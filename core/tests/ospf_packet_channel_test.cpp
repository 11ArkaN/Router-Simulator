// Packet channel tests protect FIFO frame ownership, bounded backpressure and
// exact slot return without allocating or sharing mutable packet pointers.

#include "router/ospf_packet_channel.hpp"

#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_packet_channel_tests() {
  router::ospf::PacketChannel<2U> channel;
  router::packet::Frame first{};
  first.length = 2U;
  first.bytes[0U] = 0xaaU;
  first.bytes[1U] = 0x01U;
  auto second = first;
  second.bytes[1U] = 0x02U;
  auto third = first;
  third.bytes[1U] = 0x03U;
  const router::ospf::PacketChannel<2U>::Metadata metadata{
      .device = {.index = 1U, .generation = 2U},
      .interface_id = 44U,
      .physical_port_ordinal = 7U};

  require(channel.try_send(metadata, first) &&
              channel.try_send(metadata, second) &&
              !channel.try_send(metadata, third),
          "OSPF packet channel did not apply bounded backpressure");
  const auto received_first = channel.try_receive();
  require(received_first && received_first->frame &&
              received_first->frame->bytes[1U] == 0x01U &&
              received_first->metadata.interface_id == 44U &&
              channel.release(received_first->handle),
          "OSPF packet channel lost first FIFO frame or metadata");
  require(channel.producer_available() == 1U &&
              channel.try_send(metadata, third),
          "returned OSPF packet slot was not reusable");
  const auto received_second = channel.try_receive();
  const auto received_third = channel.try_receive();
  require(received_second && received_third &&
              received_second->frame->bytes[1U] == 0x02U &&
              received_third->frame->bytes[1U] == 0x03U &&
              channel.release(received_second->handle) &&
              channel.release(received_third->handle) &&
              channel.producer_available() == 2U,
          "OSPF channel violated FIFO ordering or exact ownership return");
}
