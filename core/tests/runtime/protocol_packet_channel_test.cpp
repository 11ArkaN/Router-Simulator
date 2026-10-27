// Two real threads exchange fixed frame slots and return handles. The producer
// overwrites its original immediately, exposing publication or ownership bugs.

#include "router/protocol_packet_channel.hpp"

#include <algorithm>
#include <atomic>
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
}
