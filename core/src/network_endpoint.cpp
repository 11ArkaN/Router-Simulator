// Endpoint ARP and ICMP implementation. RFC 826 sender merge and RFC 1122
// next-hop choice occur only from local configuration and received packet
// bytes.

#include "network_endpoint.hpp"

#include "router/routing.hpp"

#include <algorithm>

namespace router::network_detail {
namespace {

constexpr packet::Mac no_mac{};

// Converts configured endpoint bytes to the route helper's network-order key.
std::uint32_t to_u32(packet::Ipv4 address) noexcept {
  return routing::ipv4(address[0], address[1], address[2], address[3]);
}

// Converts the selected next hop back to packet bytes for ARP encoding.
packet::Ipv4 to_ipv4(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24),
          static_cast<std::uint8_t>(value >> 16),
          static_cast<std::uint8_t>(value >> 8),
          static_cast<std::uint8_t>(value)};
}

// Rejects an all-zero sender MAC before it can enter the neighbor cache.
bool is_zero(packet::Mac value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](auto byte) { return byte == 0; });
}

// Appends into the bounded response batch. Encoders never allocate a hidden
// overflow vector when one received frame produces multiple replies.
void append(EndpointFrames &result, const packet::Frame &frame) noexcept {
  if (result.count < result.frames.size())
    result.frames[result.count++] = frame;
}

} // namespace

void EndpointStack::configure(
    const NetworkEndpointConfiguration &configuration) noexcept {
  // Replacement is a neighbor-generation boundary. Old gateway state cannot
  // survive an address, prefix, MAC or gateway edit.
  mac_ = configuration.endpoint_mac;
  address_ = configuration.endpoint_address;
  prefix_length_ = configuration.endpoint_prefix_length;
  gateway_ = configuration.endpoint_gateway;
  clear_neighbor();
}

EndpointFrames EndpointStack::begin_echo(packet::Ipv4 destination,
                                         std::uint16_t sequence) noexcept {
  // Host next-hop selection occurs before ARP. A cached exact mapping releases
  // the packet immediately; otherwise the encoded IP frame remains pending.
  EndpointFrames result;
  auto request =
      packet::icmp_echo(mac_, no_mac, address_, destination, false, sequence);
  const auto next_hop =
      to_ipv4(routing::host_next_hop({.source = to_u32(address_),
                                      .prefix_length = prefix_length_,
                                      .destination = to_u32(destination),
                                      .gateway = to_u32(gateway_)}));
  if (neighbor_address_ == next_hop && neighbor_mac_) {
    packet::rewrite_ethernet(request, mac_, *neighbor_mac_);
    append(result, request);
    result.start_echo_clock = true;
    return result;
  }
  neighbor_address_.reset();
  neighbor_mac_.reset();
  pending_ = request;
  pending_next_hop_ = next_hop;
  append(result, packet::arp_request(mac_, address_, next_hop));
  return result;
}

EndpointFrames EndpointStack::receive(const packet::Frame &frame,
                                      std::uint16_t expected_sequence,
                                      bool probe_source) noexcept {
  // The endpoint accepts only frames addressed to its MAC or broadcast, then
  // handles ARP and ICMP strictly from decoded bytes.
  EndpointFrames result;
  const auto ethernet = packet::parse_ethernet(frame);
  if (!ethernet || !packet::ethernet_for_local(ethernet->destination, mac_))
    return result;
  if (ethernet->ether_type == 0x0806) {
    const auto arp = packet::parse_arp(frame);
    if (!arp || arp->target_ip != address_)
      return result;
    // RFC 826 merges sender mapping before examining the operation. Releasing a
    // pending frame still requires the exact protocol address requested.
    if (!is_zero(arp->sender_mac)) {
      neighbor_address_ = arp->sender_ip;
      neighbor_mac_ = arp->sender_mac;
    }
    if (arp->operation == 1) {
      append(result, packet::arp_reply(mac_, address_, arp->sender_mac,
                                       arp->sender_ip));
    }
    if (pending_ && pending_next_hop_ == arp->sender_ip) {
      auto pending = *pending_;
      pending_.reset();
      pending_next_hop_.reset();
      packet::rewrite_ethernet(pending, mac_, arp->sender_mac);
      append(result, pending);
      result.start_echo_clock = true;
    }
    return result;
  }
  if (ethernet->ether_type != 0x0800)
    return result;
  const auto ip = packet::parse_ipv4(frame);
  const auto icmp = packet::parse_icmp(frame);
  if (!ip || !icmp || ip->destination != address_)
    return result;
  if (icmp->type == 8) {
    const auto reply = packet::icmp_echo_reply(frame, mac_, ethernet->source);
    if (reply)
      append(result, *reply);
  } else if (probe_source && icmp->type == 0 &&
             icmp->sequence == expected_sequence) {
    result.echo_reply = true;
  } else if (probe_source && icmp->type == 11) {
    result.ttl_expired = true;
  }
  return result;
}

void EndpointStack::clear_neighbor() noexcept {
  // Clearing also discards the unresolved packet because it belongs to the old
  // address or link generation and cannot be forwarded safely later.
  neighbor_address_.reset();
  neighbor_mac_.reset();
  pending_.reset();
  pending_next_hop_.reset();
}

void EndpointStack::restore_router_neighbor(packet::Ipv4 address,
                                            packet::Mac mac) noexcept {
  // Checkpoint restore installs only a completed exact mapping, never pending
  // packet storage or an outstanding request flag.
  clear_neighbor();
  neighbor_address_ = address;
  neighbor_mac_ = mac;
}

} // namespace router::network_detail
