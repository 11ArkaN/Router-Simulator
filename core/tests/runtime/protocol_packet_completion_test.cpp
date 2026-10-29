// Completion-enabled channels retain producer credits until the actual egress
// result is consumed. Two real threads verify result/frame publication through
// the reverse SPSC ring without copying a second packet into that ring.

#include "router/protocol_packet_channel.hpp"

#include <algorithm>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>

void protocol_packet_completion_tests() {
  using Channel = router::protocol::PacketChannel<4U, true>;
  auto channel = std::make_unique<Channel>();
  router::packet::Frame frame{};
  frame.length = 60U;
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, static_cast<std::uint8_t>(index));
    if (!channel->try_send({{0U, 7U}, index, 0U, index + 100U}, frame))
      throw std::runtime_error("Protocol completion channel refused a reserved slot");
  }
  if (channel->try_send({}, frame) || channel->producer_available() != 0U)
    throw std::runtime_error("Protocol completion channel exceeded its frame capacity");
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    const auto packet = channel->try_receive();
    if (!packet || !channel->release(packet->handle, index % 2U != 0U) || channel->release(packet->handle, true))
      throw std::runtime_error("Protocol completion channel lost a release or accepted a duplicate result");
  }
  if (channel->producer_available() != 0U || channel->try_send({}, frame))
    throw std::runtime_error("Protocol completion channel reclaimed unconsumed results");
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    const auto result = channel->try_completion();
    if (!result || result->metadata.interface_id != index || result->metadata.configuration_generation != index + 100U ||
        result->enqueued != (index % 2U != 0U) ||
        result->frame->view().front() != static_cast<std::uint8_t>(index))
      throw std::runtime_error("Protocol completion did not preserve its immutable frame and result");
  }
  if (channel->try_completion() || channel->producer_available() != 4U || channel->release(4U, false))
    throw std::runtime_error("Protocol completion ownership did not return exactly once");

  std::atomic_bool valid{true};
  constexpr std::uint64_t count = 1024U;
  std::thread consumer([&] {
    for (std::uint64_t index = 0U; index < count; ++index) {
      std::optional<Channel::Borrowed> packet;
      while (!(packet = channel->try_receive())) std::this_thread::yield();
      if (packet->metadata.interface_id != index || packet->metadata.configuration_generation != index + 100U ||
          packet->frame->view().front() != static_cast<std::uint8_t>(index))
        valid.store(false, std::memory_order_relaxed);
      if (!channel->release(packet->handle, index % 3U != 0U)) valid.store(false, std::memory_order_relaxed);
    }
  });
  std::uint64_t completed{};
  const auto drain = [&] {
    while (const auto result = channel->try_completion()) {
      if (result->metadata.interface_id != completed || result->metadata.configuration_generation != completed + 100U ||
          result->enqueued != (completed % 3U != 0U) ||
          result->frame->size() != 60U || !std::all_of(result->frame->view().begin(), result->frame->view().end(),
              [completed](auto byte) { return byte == static_cast<std::uint8_t>(completed); }))
        valid.store(false, std::memory_order_relaxed);
      ++completed;
    }
  };
  for (std::uint64_t index = 0U; index < count; ++index) {
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, static_cast<std::uint8_t>(index));
    while (!channel->try_send({{0U, 7U}, index, 0U, index + 100U}, frame)) { drain(); std::this_thread::yield(); }
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, std::uint8_t{});
    drain();
  }
  while (completed != count) { drain(); std::this_thread::yield(); }
  consumer.join();
  if (!valid.load(std::memory_order_relaxed) || channel->producer_available() != 4U)
    throw std::runtime_error("Protocol completion SPSC publication violated frame/result ownership");
}
