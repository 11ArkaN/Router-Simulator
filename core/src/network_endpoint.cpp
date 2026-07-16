// Endpoint ARP and ICMP implementation. RFC 826 sender merge and RFC 1122
// next-hop choice occur only from local configuration and received packet
// bytes.

#include "network_endpoint.hpp"

#include "router/multi_device_routing.hpp"

#include <algorithm>

namespace router::network_detail {
namespace {

namespace routing = router::lab::routing;

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
  if (result.count < result.frames.size()) {
    packet::copy_frame(result.frames[result.count], frame);
    ++result.count;
  }
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
  mtu_ = configuration.endpoint_mtu;
  clear_neighbor();
}

EndpointFrames EndpointStack::begin_echo(packet::Ipv4 destination,
                                         std::uint16_t sequence,
                                         std::size_t payload_octets,
                                         bool dont_fragment) noexcept {
  // Host next-hop selection occurs before ARP. A cached exact mapping releases
  // the packet immediately; otherwise the encoded IP frame remains pending.
  EndpointFrames result;
  auto request =
      packet::icmp_echo(mac_, no_mac, address_, destination, false, sequence,
                        64, payload_octets, dont_fragment);
  std::array<packet::Frame, EndpointFrames::maximum_pending_fragments> packets{};
  std::size_t packet_count = 1U;
  packet::copy_frame(packets[0], request);
  const auto ip = packet::parse_ipv4(request);
  if (!ip)
    return result;
  if (ip->total_length > mtu_) {
    if (dont_fragment) {
      result.mtu_exceeded = true;
      return result;
    }
    const auto fragments = packet::fragment_ipv4(request, mtu_);
    if (!fragments || fragments->count > packets.size()) {
      result.mtu_exceeded = true;
      return result;
    }
    packet_count = fragments->count;
    for (std::size_t index = 0; index < packet_count; ++index)
      packet::copy_frame(packets[index], fragments->frames[index]);
  }
  const auto next_hop =
      to_ipv4(routing::host_next_hop({.source = to_u32(address_),
                                      .prefix_length = prefix_length_,
                                      .destination = to_u32(destination),
                                      .gateway = to_u32(gateway_)}));
  if (neighbor_address_ == next_hop && neighbor_mac_) {
    for (std::size_t index = 0; index < packet_count; ++index) {
      packet::rewrite_ethernet(packets[index], mac_, *neighbor_mac_);
      append(result, packets[index]);
    }
    result.start_echo_clock = true;
    return result;
  }
  neighbor_address_.reset();
  neighbor_mac_.reset();
  for (std::size_t index = 0; index < packet_count; ++index)
    packet::copy_frame(pending_frames_[index], packets[index]);
  pending_count_ = static_cast<std::uint8_t>(packet_count);
  pending_next_hop_ = next_hop;
  append(result, packet::arp_request(mac_, address_, next_hop));
  return result;
}

std::optional<packet::Frame>
EndpointStack::reassemble(const packet::Frame &fragment,
                          const packet::Ipv4View &ip) noexcept {
  // RFC 791 offsets are relative to the IPv4 payload. The full-duplex link
  // preserves FIFO order, but the offset is still validated so malformed or
  // overlapping fragments cannot overwrite accepted bytes.
  const auto payload = static_cast<std::size_t>(ip.total_length - ip.header_length);
  const auto offset = static_cast<std::size_t>(ip.fragment_offset) * 8U;
  const bool first = offset == 0U;
  if (first) {
    reassembly_ = {};
    reassembly_.active = true;
    reassembly_.source = ip.source;
    reassembly_.destination = ip.destination;
    reassembly_.identification = ip.identification;
    std::copy_n(fragment.bytes.begin(), 14U + ip.header_length,
                reassembly_.frame.bytes.begin());
  }
  if (!reassembly_.active || reassembly_.source != ip.source ||
      reassembly_.destination != ip.destination ||
      reassembly_.identification != ip.identification ||
      offset != reassembly_.payload_octets ||
      14U + ip.header_length + offset + payload >
          reassembly_.frame.bytes.size()) {
    reassembly_ = {};
    return std::nullopt;
  }
  std::copy_n(fragment.bytes.begin() + 14U + ip.header_length, payload,
              reassembly_.frame.bytes.begin() + 14U + ip.header_length + offset);
  reassembly_.payload_octets =
      static_cast<std::uint16_t>(reassembly_.payload_octets + payload);
  // A partial datagram is also checkpointable wire state. Keeping length at
  // zero made a valid in-progress reassembly indistinguishable from an empty
  // frame during structural validation. Padding is deliberately omitted here:
  // this buffer represents the accumulated IP datagram, not one wire fragment.
  reassembly_.frame.length = static_cast<std::uint16_t>(
      14U + ip.header_length + reassembly_.payload_octets);
  if (ip.more_fragments)
    return std::nullopt;

  packet::Frame complete;
  packet::copy_frame(complete, reassembly_.frame);
  const auto total = static_cast<std::uint16_t>(
      ip.header_length + reassembly_.payload_octets);
  complete.bytes[16] = static_cast<std::uint8_t>(total >> 8);
  complete.bytes[17] = static_cast<std::uint8_t>(total);
  complete.bytes[20] = 0;
  complete.bytes[21] = 0;
  complete.bytes[24] = 0;
  complete.bytes[25] = 0;
  const auto header_checksum = packet::checksum(std::span<const std::uint8_t>(
      complete.bytes.data() + 14U, ip.header_length));
  complete.bytes[24] = static_cast<std::uint8_t>(header_checksum >> 8);
  complete.bytes[25] = static_cast<std::uint8_t>(header_checksum);
  complete.length = static_cast<std::uint16_t>(14U + total);
  while (complete.length < 60U)
    complete.bytes[complete.length++] = 0;
  reassembly_ = {};
  return complete;
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
    if (pending_count_ && pending_next_hop_ == arp->sender_ip) {
      const auto count = pending_count_;
      pending_count_ = 0;
      pending_next_hop_.reset();
      for (std::size_t index = 0; index < count; ++index) {
        packet::Frame pending;
        packet::copy_frame(pending, pending_frames_[index]);
        packet::rewrite_ethernet(pending, mac_, arp->sender_mac);
        append(result, pending);
      }
      result.start_echo_clock = true;
    }
    return result;
  }
  if (ethernet->ether_type != 0x0800)
    return result;
  auto ip = packet::parse_ipv4(frame);
  if (!ip || ip->destination != address_)
    return result;
  std::optional<packet::Frame> complete;
  const packet::Frame *datagram = &frame;
  if (ip->fragment_offset || ip->more_fragments) {
    complete = reassemble(frame, *ip);
    if (!complete)
      return result;
    datagram = &*complete;
    ip = packet::parse_ipv4(*datagram);
  }
  const auto complete_ethernet = packet::parse_ethernet(*datagram);
  const auto icmp = packet::parse_icmp(*datagram);
  if (!ip || !icmp || ip->destination != address_)
    return result;
  if (icmp->type == 8) {
    const auto reply = packet::icmp_echo_reply(
        *datagram, mac_, complete_ethernet ? complete_ethernet->source
                                          : ethernet->source);
    if (reply)
      append(result, *reply);
  } else if (probe_source && icmp->type == 0 &&
             icmp->sequence == expected_sequence) {
    result.echo_reply = true;
  } else if (probe_source && icmp->type == 11) {
    result.ttl_expired = true;
  } else if (probe_source && icmp->type == 3 && icmp->code == 4) {
    result.mtu_exceeded = true;
  }
  return result;
}

void EndpointStack::clear_neighbor() noexcept {
  // Clearing also discards the unresolved packet because it belongs to the old
  // address or link generation and cannot be forwarded safely later.
  neighbor_address_.reset();
  neighbor_mac_.reset();
  pending_count_ = 0;
  pending_next_hop_.reset();
  reassembly_ = {};
}

void EndpointStack::restore_router_neighbor(packet::Ipv4 address,
                                            packet::Mac mac) noexcept {
  // Checkpoint restore installs only a completed exact mapping, never pending
  // packet storage or an outstanding request flag.
  clear_neighbor();
  neighbor_address_ = address;
  neighbor_mac_ = mac;
}

void EndpointStack::checkpoint(NetworkCheckpointState &state) const {
  auto &output = state.endpoint;
  output.neighbor_valid = neighbor_address_.has_value() && neighbor_mac_.has_value();
  if (output.neighbor_valid) {
    output.neighbor_address = *neighbor_address_;
    output.neighbor_mac = *neighbor_mac_;
  }
  output.pending_next_hop_valid =
      pending_count_ && pending_next_hop_.has_value();
  if (output.pending_next_hop_valid) {
    output.pending_next_hop = *pending_next_hop_;
    for (std::size_t index = 0; index < pending_count_; ++index)
      state.frames.push_back({.stage = NetworkFrameStage::endpoint_pending,
                              .direction = 0,
                              .next_hop = *pending_next_hop_,
                              .frame = pending_frames_[index]});
  }
  output.reassembly_active = reassembly_.active;
  if (reassembly_.active) {
    output.reassembly_source = reassembly_.source;
    output.reassembly_destination = reassembly_.destination;
    output.reassembly_identification = reassembly_.identification;
    output.reassembly_payload_octets = reassembly_.payload_octets;
    state.frames.push_back({.stage = NetworkFrameStage::endpoint_reassembly,
                            .direction = 0,
                            .frame = reassembly_.frame});
  }
}

bool EndpointStack::restore(const NetworkCheckpointState &state) noexcept {
  const auto &input = state.endpoint;
  std::array<const NetworkStoredFrame *,
             EndpointFrames::maximum_pending_fragments> pending_frames{};
  std::size_t pending_count{};
  const NetworkStoredFrame *reassembly_frame{};
  for (const auto &stored : state.frames) {
    if (stored.direction != 0)
      continue;
    if (stored.stage == NetworkFrameStage::endpoint_pending) {
      if (pending_count == pending_frames.size())
        return false;
      pending_frames[pending_count++] = &stored;
    } else if (stored.stage == NetworkFrameStage::endpoint_reassembly) {
      if (reassembly_frame)
        return false;
      reassembly_frame = &stored;
    }
  }
  if (input.pending_next_hop_valid != (pending_count != 0U) ||
      input.reassembly_active != (reassembly_frame != nullptr) ||
      std::any_of(pending_frames.begin(),
                  pending_frames.begin() + pending_count,
                  [](const auto *frame) {
                    return !frame->frame.length ||
                           frame->frame.length > frame->frame.bytes.size();
                  }) ||
      (reassembly_frame &&
       (reassembly_frame->frame.length < 34U ||
        reassembly_frame->frame.length > reassembly_frame->frame.bytes.size() ||
        reassembly_frame->frame.length !=
            34U + input.reassembly_payload_octets ||
        input.reassembly_payload_octets >
            reassembly_frame->frame.bytes.size() - 34U)))
    return false;

  clear_neighbor();
  if (input.neighbor_valid) {
    neighbor_address_ = input.neighbor_address;
    neighbor_mac_ = input.neighbor_mac;
  }
  if (pending_count) {
    for (std::size_t index = 0; index < pending_count; ++index)
      pending_frames_[index] = pending_frames[index]->frame;
    pending_count_ = static_cast<std::uint8_t>(pending_count);
    pending_next_hop_ = input.pending_next_hop;
  }
  if (reassembly_frame) {
    reassembly_ = {.active = true,
                   .source = input.reassembly_source,
                   .destination = input.reassembly_destination,
                   .identification = input.reassembly_identification,
                   .payload_octets = input.reassembly_payload_octets,
                   .frame = reassembly_frame->frame};
  }
  return true;
}

} // namespace router::network_detail
