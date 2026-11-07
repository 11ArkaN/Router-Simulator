// Two real threads exchange fixed frame slots and return handles. The producer
// overwrites its original immediately, exposing publication or ownership bugs.

#include "router/protocol_packet_channel.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

void protocol_packet_channel_tests() {
  using Channel = router::protocol::PacketChannel<4U>;
  auto channel = std::make_unique<Channel>();
  if (channel->release(0U)) throw std::runtime_error("Protocol channel released an unborrowed slot");
  std::atomic_bool valid{true};
  constexpr std::uint64_t count = 1024U;
  std::thread consumer([&] {
    for (std::uint64_t index = 0U; index < count; ++index) {
      bool found{};
      const auto query_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
      do {
        static_cast<void>(channel->consumer_any_ready([&](const Channel::Metadata &metadata,
            const router::packet::Frame &queued) noexcept {
          const auto queued_length = metadata.interface_id % 2U ? 60U : router::packet::maximum_frame_octets;
          if (metadata.interface_id < index || queued.size() != queued_length ||
              !std::all_of(queued.view().begin(), queued.view().end(),
                  [&](auto byte) { return byte == static_cast<std::uint8_t>(metadata.interface_id); }))
            valid.store(false, std::memory_order_relaxed);
          found = found || metadata.interface_id == index;
          return false;
        }));
        if (!found && std::chrono::steady_clock::now() >= query_deadline) {
          valid.store(false, std::memory_order_relaxed);
          break;
        }
        if (!found) std::this_thread::yield();
      } while (!found);
      std::optional<Channel::Borrowed> packet;
      while (!(packet = channel->try_receive())) std::this_thread::yield();
      const auto length = index % 2U ? 60U : router::packet::maximum_frame_octets;
      if (packet->metadata.interface_id != index || packet->metadata.device.generation != 7U ||
          packet->metadata.physical_port_ordinal != index % 32U || packet->frame->size() != length ||
          !std::all_of(packet->frame->view().begin(), packet->frame->view().end(),
                       [index](auto octet) { return octet == static_cast<std::uint8_t>(index); }))
        valid.store(false, std::memory_order_relaxed);
      if (!channel->release(packet->handle) || channel->release(packet->handle))
        valid.store(false, std::memory_order_relaxed);
    }
  });
  router::packet::Frame frame{};
  for (std::uint64_t index = 0U; index < count; ++index) {
    frame.length = static_cast<std::uint16_t>(index % 2U ? 60U : router::packet::maximum_frame_octets);
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, static_cast<std::uint8_t>(index));
    const Channel::Metadata metadata{{0U, 7U}, index, static_cast<std::uint16_t>(index % 32U)};
    while (!channel->try_send(metadata, frame)) std::this_thread::yield();
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, std::uint8_t{});
  }
  consumer.join();
  frame.length = static_cast<std::uint16_t>(frame.bytes.size() + 1U);
  if (channel->try_send({}, frame)) throw std::runtime_error("Protocol channel accepted an oversized frame view");
  if (!valid.load(std::memory_order_relaxed) || channel->producer_available() != 4U ||
      channel->try_receive() || channel->release(4U))
    throw std::runtime_error("Shared protocol channel violated FIFO frame publication or slot return");
  // A head captured before a concurrent publication bounds the scan even
  // though the producer may append more frames while its callback runs.
  auto snapshot = std::make_unique<Channel>();
  frame.length = 60U;
  std::fill_n(frame.bytes.begin(), frame.length, std::uint8_t{1U});
  if (!snapshot->try_send({{0U, 7U}, 1U}, frame)) throw std::runtime_error("Snapshot setup failed");
  std::atomic_bool entered{}, published{};
  std::size_t visited{};
  std::thread observer([&] {
    static_cast<void>(snapshot->consumer_any_ready([&](const Channel::Metadata &metadata,
        const router::packet::Frame &queued) noexcept {
      ++visited;
      entered.store(true, std::memory_order_release);
      while (!published.load(std::memory_order_acquire)) std::this_thread::yield();
      if (metadata.interface_id != 1U || queued.view().front() != 1U)
        valid.store(false, std::memory_order_relaxed);
      return false;
    }));
  });
  const auto snapshot_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (!entered.load(std::memory_order_acquire)) {
    if (std::chrono::steady_clock::now() >= snapshot_deadline) {
      published.store(true, std::memory_order_release);
      observer.join();
      throw std::runtime_error("Published snapshot did not visit its first frame");
    }
    std::this_thread::yield();
  }
  std::fill_n(frame.bytes.begin(), frame.length, std::uint8_t{2U});
  const bool appended = snapshot->try_send({{0U, 7U}, 2U}, frame);
  published.store(true, std::memory_order_release);
  observer.join();
  if (!appended || visited != 1U || !valid.load(std::memory_order_relaxed) || snapshot->producer_available() != 2U)
    throw std::runtime_error("Ready snapshot changed ownership or included a later publication");
  if (!snapshot->consumer_any_ready([](const Channel::Metadata &metadata, const router::packet::Frame &queued) noexcept {
      return metadata.interface_id == 2U && queued.view().front() == 2U;
    })) throw std::runtime_error("Next ready snapshot lost the concurrent publication");
  for (std::uint64_t expected = 1U; expected <= 2U; ++expected) {
    const auto retained = snapshot->try_receive();
    if (!retained || retained->metadata.interface_id != expected || !snapshot->release(retained->handle))
      throw std::runtime_error("Ready snapshot consumed or reordered a frame");
  }
  if (snapshot->consumer_any_ready([](const auto &, const auto &) noexcept { return true; }))
    throw std::runtime_error("Returned frames remained visible to a ready snapshot");

}
