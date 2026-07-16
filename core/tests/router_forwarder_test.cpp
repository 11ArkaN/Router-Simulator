// Router forwarder tests drive only encoded frames through two local ports.
// They verify per-hop ARP, TTL, checksum and ICMP without topology shortcuts.

#include "router/router_forwarder.hpp"

#include <memory>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  // The module runner retains the first packet-path contract failure.
  if (!condition)
    throw std::runtime_error(message);
}

struct Emitted {
  std::uint16_t port{};
  router::packet::Frame frame{};
};

bool collect(void *context, std::uint16_t port,
             const router::packet::Frame &frame) {
  // Test storage copies wire bytes because the sink contract does not permit a
  // caller to retain the forwarder's temporary frame reference.
  static_cast<std::vector<Emitted> *>(context)->push_back({port, frame});
  return true;
}

} // namespace

void router_forwarder_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;
  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac router_a{0x02, 0, 0, 0, 1, 1};
  const packet::Mac router_b{0x02, 0, 0, 0, 1, 2};
  const packet::Mac host_a{0x02, 0, 0, 0, 0, 1};
  const packet::Mac host_b{0x02, 0, 0, 0, 0, 2};
  require(forwarder->configure_port({true, true, 0, 1514, 0x0a000001U,
                                     0x0a000000U, 10'000, 24, router_a}) &&
              forwarder->configure_port({true, true, 1, 600, 0x0a000101U,
                                         0x0a000100U, 10'000, 24, router_b}),
          "forwarder rejected valid routed ports");
  RouteTable rib;
  const std::array connected{
      ConnectedInput{true, true, 0x0a000000U, 0, 24},
      ConnectedInput{true, true, 0x0a000100U, 1, 24}};
  require(rib.rebuild(connected, std::span<const StaticInput>{}) &&
              forwarder->program_fib(rib.compile(1)),
          "forwarder rejected connected FIB");

  std::vector<Emitted> emitted;
  const auto echo = packet::icmp_echo(host_a, router_a, {10, 0, 0, 2},
                                      {10, 0, 1, 2}, false, 1);
  forwarder->receive(0, echo, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 1 &&
              packet::parse_arp(emitted[0].frame)->operation == 1 &&
              forwarder->pending_frames() == 1,
          "unresolved next hop did not emit one encoded ARP request");

  const auto arp_reply = packet::arp_reply(host_b, {10, 0, 1, 2}, router_b,
                                           {10, 0, 1, 1});
  forwarder->receive(1, arp_reply, &emitted, collect);
  require(emitted.size() == 2 && emitted[1].port == 1 &&
              forwarder->pending_frames() == 0 &&
              forwarder->arp_entries() == 1,
          "ARP reply did not release the pending transit frame");
  const auto routed_ip = packet::parse_ipv4(emitted[1].frame);
  const auto routed_eth = packet::parse_ethernet(emitted[1].frame);
  require(routed_ip && routed_eth && routed_ip->ttl == 63 &&
              routed_eth->source == router_b &&
              routed_eth->destination == host_b,
          "transit hop did not rewrite Ethernet and decrement TTL once");

  // Learn the reverse source only through an ARP request received on port 0.
  const auto reverse_arp =
      packet::arp_request(host_a, {10, 0, 0, 2}, {10, 0, 0, 1});
  forwarder->receive(0, reverse_arp, &emitted, collect);
  emitted.clear();
  auto ttl_one = echo;
  // Mutate TTL and its header checksum to create a valid received datagram.
  ttl_one.bytes[22] = 1;
  ttl_one.bytes[24] = 0;
  ttl_one.bytes[25] = 0;
  const auto header_checksum = packet::checksum(
      ttl_one.view().subspan(14, 20));
  ttl_one.bytes[24] = static_cast<std::uint8_t>(header_checksum >> 8);
  ttl_one.bytes[25] = static_cast<std::uint8_t>(header_checksum);
  forwarder->receive(0, ttl_one, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "TTL expiry did not return an encoded frame on the reverse route");
  const auto error_ip = packet::parse_ipv4(emitted[0].frame);
  const auto error_icmp = packet::parse_icmp(emitted[0].frame);
  require(error_ip && error_icmp && error_ip->source == packet::Ipv4{10, 0, 0, 1} &&
              error_ip->destination == packet::Ipv4{10, 0, 0, 2} &&
              error_icmp->type == 11 && error_icmp->code == 0,
          "TTL expiry did not produce a valid ICMP Time Exceeded message");

  emitted.clear();
  const auto fragmentable = packet::icmp_echo(
      host_a, router_a, {10, 0, 0, 2}, {10, 0, 1, 2}, false, 2, 64, 1000,
      false);
  forwarder->receive(0, fragmentable, &emitted, collect);
  require(emitted.size() == 2 && emitted[0].port == 1 &&
              emitted[1].port == 1,
          "oversized non-DF datagram did not emit every IPv4 fragment");
  const auto first_fragment = packet::parse_ipv4(emitted[0].frame);
  const auto final_fragment = packet::parse_ipv4(emitted[1].frame);
  require(first_fragment && final_fragment && first_fragment->more_fragments &&
              !final_fragment->more_fragments &&
              final_fragment->fragment_offset != 0U,
          "forwarded fragments carry invalid IPv4 offset or MF fields");

  emitted.clear();
  const auto oversized = packet::icmp_echo(
      host_a, router_a, {10, 0, 0, 2}, {10, 0, 1, 2}, false, 2, 64, 1000,
      true);
  forwarder->receive(0, oversized, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "DF packet above egress MTU did not return an ICMP error");
  const auto mtu_error = packet::parse_icmp(emitted[0].frame);
  require(mtu_error && mtu_error->type == 3 && mtu_error->code == 4,
          "DF packet did not produce ICMP Fragmentation Needed");

  emitted.clear();
  auto nested_error = *packet::icmp_time_exceeded(
      echo, host_a, router_a, {10, 0, 0, 2}, {10, 0, 1, 2});
  nested_error.bytes[22] = 1;
  nested_error.bytes[24] = 0;
  nested_error.bytes[25] = 0;
  const auto nested_checksum = packet::checksum(
      nested_error.view().subspan(14, 20));
  nested_error.bytes[24] = static_cast<std::uint8_t>(nested_checksum >> 8);
  nested_error.bytes[25] = static_cast<std::uint8_t>(nested_checksum);
  forwarder->receive(0, nested_error, &emitted, collect);
  require(emitted.empty(),
          "router generated an ICMP error in response to an ICMP error");

  const auto checkpoint_now = RouterForwarder::Clock::now();
  // Checkpoint images are cold-path heap values. Keeping three complete FIB
  // images on the deliberately small Wasm test stack would test stack size,
  // not restore semantics used by the heap-owned runtime supervisor.
  auto checkpoint = std::make_unique<RouterForwarderCheckpoint>(
      forwarder->checkpoint(checkpoint_now));
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, checkpoint_now) &&
              restored->arp_entries() == forwarder->arp_entries() &&
              restored->forwarded_frames() == forwarder->forwarded_frames() &&
              restored->dropped_frames() == forwarder->dropped_frames(),
          "forwarder checkpoint did not restore owner-local state");
  auto invalid = std::make_unique<RouterForwarderCheckpoint>(*checkpoint);
  invalid->ports.front().ordinal =
      static_cast<std::uint16_t>(device_catalog::maximum_ports_per_router);
  const auto forwarded_before_invalid = restored->forwarded_frames();
  require(!restored->restore(*invalid, checkpoint_now) &&
              restored->forwarded_frames() == forwarded_before_invalid,
          "invalid forwarder checkpoint partially changed live state");
}
