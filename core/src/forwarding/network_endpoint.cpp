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

bool ipv4_broadcast_for_interface(packet::Ipv4 destination,
                                  packet::Ipv4 address,
                                  std::uint8_t prefix_length) noexcept {
  if (destination == packet::Ipv4{255U, 255U, 255U, 255U})
    return true;
  // RFC 3021 /31 and host-route /32 prefixes have no directed broadcast.
  // For ordinary prefixes, derive the value from configured prefix bits
  // rather than reviving obsolete classful network boundaries.
  if (prefix_length >= 31U)
    return false;
  const auto mask = routing::prefix_mask(prefix_length);
  return to_u32(destination) == ((to_u32(address) & mask) | ~mask);
}

bool valid_icmpv4_error_destination(packet::Ipv4 address) noexcept {
  // RFC 1122 forbids sending ICMP errors to unspecified, limited-broadcast or
  // multicast sources. A unicast packet delivered to this exact host address
  // cannot itself be a directed-broadcast request in the current endpoint model.
  return address != packet::Ipv4{} &&
         address != packet::Ipv4{255U, 255U, 255U, 255U} &&
         (address[0U] & 0xf0U) != 0xe0U;
}

bool matches_ipv4_probe_quote(std::span<const std::uint8_t> quote,
                              const packet::Frame &probe) noexcept {
  const auto sent = packet::parse_ipv4(probe);
  // RFC 792 supplies at least the original IPv4 header plus eight data
  // octets. A shorter quote cannot identify a transport or ICMP operation and
  // must not modify path state. A longer quote is compared in full.
  if (!sent || quote.size() < static_cast<std::size_t>(sent->header_length) +
                                  8U ||
      quote.size() > sent->total_length)
    return false;
  return std::equal(quote.begin(), quote.end(),
                    probe.bytes.begin() + packet::ethernet_header_octets);
}

std::optional<transport::Ipv6NetworkErrorKind>
ipv6_network_error_kind(std::uint8_t type, std::uint8_t code) noexcept {
  // RFC 4443 assigns code zero to PTB, codes zero and one to Time Exceeded,
  // and codes zero through two to Parameter Problem. Destination Unreachable
  // has subsequently gained additional IANA codes, so its code remains data
  // for the socket rather than being frozen to the original RFC range here.
  switch (type) {
  case packet::icmpv6_destination_unreachable_type:
    return transport::Ipv6NetworkErrorKind::destination_unreachable;
  case packet::icmpv6_packet_too_big_type:
    return code == 0U
               ? std::optional{
                     transport::Ipv6NetworkErrorKind::packet_too_big}
               : std::nullopt;
  case packet::icmpv6_time_exceeded_type:
    return code <= 1U
               ? std::optional{
                     transport::Ipv6NetworkErrorKind::time_exceeded}
               : std::nullopt;
  case packet::icmpv6_parameter_problem_type:
    return code <= 2U
               ? std::optional{
                     transport::Ipv6NetworkErrorKind::parameter_problem}
               : std::nullopt;
  default:
    return type < packet::icmpv6_informational_type_boundary
               ? std::optional{transport::Ipv6NetworkErrorKind::unknown}
               : std::nullopt;
  }
}

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(bytes[offset] << 8U) |
         bytes[offset + 1U];
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

// Appends into the bounded response batch. Encoders never allocate a hidden
// overflow vector when one received frame produces multiple replies.
bool append(EndpointFrames &result, const packet::Frame &frame) noexcept {
  if (result.count < result.frames.size() &&
      result.count < result.storage.size()) {
    auto &owned = result.storage[result.count];
    packet::copy_frame(owned, frame);
    result.frames[result.count].value = &owned;
    ++result.count;
    return true;
  }
  return false;
}

// Packetizes one locally originated IPv4 datagram into caller-owned frame
// slots. The caller chooses storage appropriate to its operation, while this
// shared path enforces the configured IP MTU and all-or-nothing capacity before
// publishing the first fragment. `count` is both the initial append position
// and the resulting position. On failure it is restored to its input value.
bool packetize_ipv4_source(std::span<packet::Frame> output,
                           std::size_t &count,
                           const packet::Frame &datagram,
                           std::uint16_t mtu) noexcept {
  const auto ip = packet::parse_ipv4(datagram);
  if (!ip || count > output.size())
    return false;
  if (ip->total_length <= mtu) {
    if (count == output.size())
      return false;
    packet::copy_frame(output[count++], datagram);
    return true;
  }
  if (ip->dont_fragment)
    return false;

  const auto required = packet::ipv4_fragment_count(datagram.view(), mtu);
  if (!required || *required > output.size() - count)
    return false;
  const auto initial = count;
  struct Collector {
    std::span<packet::Frame> frames;
    std::size_t *count{};
  } collector{output, &count};
  const auto collect = [](void *opaque,
                          const packet::Frame &fragment) noexcept {
    auto &target = *static_cast<Collector *>(opaque);
    if (*target.count >= target.frames.size())
      return false;
    packet::copy_frame(target.frames[(*target.count)++], fragment);
    return true;
  };
  const auto emitted = packet::fragment_ipv4_datagram(
      datagram.view(), mtu, &collector, collect);
  if (!emitted || *emitted != *required || count - initial != *required) {
    count = initial;
    return false;
  }
  return true;
}

packet::Ipv6 derive_link_local(
    packet::Mac mac, bool ipv6_enabled,
    const host::Ipv6InterfaceIdentifierConfiguration &identifier,
    std::uint64_t interface_id, std::uint32_t dad_counter) noexcept {
  if (!ipv6_enabled)
    return {};
  if (identifier.mode != host::InterfaceIdentifierMode::stable_opaque)
    return ip::link_local_from_mac(mac);
  packet::Ipv6 link_local_network{};
  link_local_network[0] = 0xfeU;
  link_local_network[1] = 0x80U;
  const ip::Ipv6Prefix link_local_prefix{
      .network = link_local_network, .length = 64U};
  const auto iid = host::stable_opaque_interface_identifier(
      link_local_prefix, interface_id,
      std::span<const std::uint8_t>{identifier.network_id}
          .first(identifier.network_id_octets),
      dad_counter, identifier.stable_secret);
  auto address = ip::mask(link_local_prefix.network, 64U);
  std::copy(iid.begin(), iid.end(), address.begin() + 8U);
  return address;
}

bool has_reserved_interface_identifier(const packet::Ipv6 &address) noexcept {
  host::StableInterfaceIdentifier iid{};
  std::copy(address.end() - static_cast<std::ptrdiff_t>(iid.size()),
            address.end(), iid.begin());
  return host::is_reserved_ipv6_interface_identifier(iid);
}

EndpointUdpSendStatus
endpoint_udp_error(transport::UdpSendStatus status) noexcept {
  // UDP owns socket and tuple validation, while this endpoint owns routing and
  // packetization. Preserve distinct failures across that boundary so a caller
  // never retries a protocol-length error as if it were transient backpressure.
  switch (status) {
  case transport::UdpSendStatus::invalid_socket:
  case transport::UdpSendStatus::wrong_family:
    return EndpointUdpSendStatus::invalid_socket;
  case transport::UdpSendStatus::message_too_large:
    return EndpointUdpSendStatus::message_too_large;
  case transport::UdpSendStatus::buffer_too_small:
    return EndpointUdpSendStatus::resource_exhausted;
  default:
    return EndpointUdpSendStatus::invalid_destination;
  }
}

} // namespace

EndpointStack::EndpointStack()
    : tcp_(std::make_unique<transport::tcp::TcpEndpoint>(
          crypto::Sha256Digest{})),
      ip_datagram_scratch_(
          packet::maximum_ethernet_ipv6_datagram_octets),
      frame_arena_(std::make_unique<FrameArena>()) {}

EndpointFrames EndpointStack::make_frame_result() noexcept {
  EndpointFrames result;
  if (frame_arena_)
    result.storage = frame_arena_->output;
  return result;
}

packet::Ipv6 EndpointStack::derive_ipv6_link_local(
    std::uint32_t dad_counter) const noexcept {
  return derive_link_local(mac_, ipv6_enabled_, ipv6_identifier_,
                           interface_id_, dad_counter);
}

bool EndpointStack::configure(
    const NetworkEndpointConfiguration &configuration) noexcept {
  const auto stable_secret_present = std::any_of(
      configuration.endpoint_ipv6_identifier.stable_secret.begin(),
      configuration.endpoint_ipv6_identifier.stable_secret.end(),
      [](std::uint8_t value) { return value != 0U; });
  const auto transport_secret_present = std::any_of(
      configuration.endpoint_transport_secret.begin(),
      configuration.endpoint_transport_secret.end(),
      [](std::uint8_t value) { return value != 0U; });
  if (!transport_secret_present || configuration.endpoint_prefix_length > 32U ||
      configuration.endpoint_mtu < device_catalog::minimum_host_ipv4_mtu ||
      configuration.endpoint_mtu > device_catalog::maximum_network_mtu ||
      (configuration.endpoint_ipv6_autoconfiguration &&
       (!configuration.endpoint_interface_id ||
        configuration.endpoint_mtu < packet::ipv6_minimum_link_mtu ||
        configuration.endpoint_ipv6_identifier.network_id_octets >
            configuration.endpoint_ipv6_identifier.network_id.size() ||
        configuration.endpoint_ipv6_identifier.mode >
            host::InterfaceIdentifierMode::stable_opaque ||
        (configuration.endpoint_ipv6_identifier.mode ==
             host::InterfaceIdentifierMode::stable_opaque &&
         !stable_secret_present))))
    return false;
  std::unique_ptr<transport::tcp::TcpEndpoint> configured_tcp;
  try {
    configured_tcp = std::make_unique<transport::tcp::TcpEndpoint>(
        configuration.endpoint_transport_secret);
  } catch (const std::bad_alloc &) {
    return false;
  }
  if (!configured_tcp->valid())
    return false;
  std::uint32_t initial_dad_counter{};
  auto initial_link_local = derive_link_local(
      configuration.endpoint_mac,
      configuration.endpoint_ipv6_autoconfiguration,
      configuration.endpoint_ipv6_identifier,
      configuration.endpoint_interface_id, initial_dad_counter);
  if (configuration.endpoint_ipv6_autoconfiguration &&
      configuration.endpoint_ipv6_identifier.mode ==
          host::InterfaceIdentifierMode::stable_opaque) {
    while (has_reserved_interface_identifier(initial_link_local)) {
      if (initial_dad_counter >=
          device_catalog::ipv6_stable_iid_dad_retries)
        return false;
      ++initial_dad_counter;
      initial_link_local = derive_link_local(
          configuration.endpoint_mac, true,
          configuration.endpoint_ipv6_identifier,
          configuration.endpoint_interface_id, initial_dad_counter);
    }
  }

  // Replacement is a neighbor-generation boundary. Old gateway state cannot
  // survive an address, prefix, MAC or gateway edit.
  mac_ = configuration.endpoint_mac;
  address_ = configuration.endpoint_address;
  prefix_length_ = configuration.endpoint_prefix_length;
  gateway_ = configuration.endpoint_gateway;
  dhcpv4_address_owned_ = false;
  dhcpv4_probe_candidate_ = {};
  dhcpv4_probe_conflict_ = false;
  mtu_ = configuration.endpoint_mtu;
  interface_id_ = configuration.endpoint_interface_id;
  ipv6_enabled_ = configuration.endpoint_ipv6_autoconfiguration;
  ipv6_identifier_ = configuration.endpoint_ipv6_identifier;
  ipv6_link_local_dad_counter_ = initial_dad_counter;
  ipv6_link_local_generation_exhausted_ = false;
  ipv6_link_local_ = initial_link_local;
  // Configuration replacement creates a new logical interface generation.
  // Re-seeding discards memberships and report timers from the prior identity.
  mld_listener_ = lab::MldListener{interface_id_ ? interface_id_ : 1U};
  ipv4_reassembly_.discard_all();
  ipv4_path_mtu_.clear();
  ipv6_reassembly_.discard_all();
  ipv6_path_mtu_.clear();
  udp_ = transport::UdpEndpoint{};
  ike_udp_ = ikev2::UdpService{};
  tcp_ = std::move(configured_tcp);
  next_ipv4_identification_ = 1U;
  next_ipv6_fragment_identification_ = 1U;
  mld_system_groups_ = {};
  mld_system_group_count_ = 0U;
  clear_neighbor();
  set_link_state(link_operational_);
  return true;
}

void EndpointStack::set_link_state(bool operational,
                                   Clock::time_point now) noexcept {
  // Every attachment generation starts with empty learned state. Reusing an RA
  // or neighbor from the previous cable would create connectivity that did not
  // arrive through the new physical link.
  link_operational_ = operational;
  clear_neighbor();
  // A link generation owns its learned IPv6 mappings just as it owns its ARP
  // mapping. Retaining a Redirect or neighbor from the previous cable would
  // bypass both Router Discovery and ND on the replacement attachment.
  ipv6_neighbors_.remove_interface(interface_id_);
  ipv6_destinations_.remove_port(ethernet_port_ordinal);
  ipv6_path_mtu_.remove_interface(interface_id_);
  ipv4_path_mtu_.remove_interface(interface_id_);
  // Fragments from a previous physical attachment cannot be combined with
  // bytes received after carrier restoration. Bound UDP sockets remain local
  // application state, while incomplete IP-layer input is link-generation data.
  ipv4_reassembly_.discard_all();
  ipv6_reassembly_.discard_all();
  ipv6_dad_ = {};
  router_solicitation_active_ = false;
  router_solicitation_deadline_ = Clock::time_point::max();
  router_solicitations_sent_ = 0U;
  if (!ipv6_enabled_) {
    mld_listener_.set_link_state(false, false, now);
    return;
  }
  std::array<std::uint8_t,
             host::Ipv6HostAutoconfiguration::
                 ethernet_interface_identifier_octets>
      iid{};
  std::copy(ipv6_link_local_.end() - static_cast<std::ptrdiff_t>(iid.size()),
            ipv6_link_local_.end(), iid.begin());
  // Modified EUI-64 is recomputed from the active link-local address because
  // it is a link-layer property. Stable mode retains the caller-owned secret
  // and network tuple copied by configure.
  auto identifier = ipv6_identifier_;
  identifier.modified_eui64 = iid;
  if (!ipv6_autoconfiguration_.configure(interface_id_, identifier, mtu_) ||
      !operational) {
    mld_listener_.set_link_state(false, false, now);
    return;
  }
  // RFC 3590 requires the solicited-node Report before DAD begins, using the
  // unspecified source because the link-local address is still tentative.
  static_cast<void>(
      mld_listener_.join(ip::solicited_node_multicast(ipv6_link_local_), now));
  mld_listener_.set_link_state(true, false, now);
  static_cast<void>(ipv6_dad_.configure(
      interface_id_, ethernet_port_ordinal, ipv6_link_local_,
      device_catalog::ipv6_dad_transmits,
      lab::ipv6_interface_initial_delay(
          interface_id_, ipv6_link_local_, now,
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              device_catalog::ipv6_dad_max_initial_delay)),
      now));
  router_solicitation_active_ = true;
  router_solicitation_deadline_ =
      now + lab::ipv6_interface_initial_delay(
                interface_id_, ipv6_link_local_, now,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    device_catalog::ipv6_rs_max_initial_delay));
}

EndpointUdpSendResult EndpointStack::send_udp_ipv6(
    transport::UdpSocketHandle handle, packet::Ipv6 destination,
    std::uint16_t destination_port, std::span<const std::uint8_t> payload,
    void *sink_context, packet::Ipv6FragmentSink sink,
    Clock::time_point now, packet::Ipv6FragmentAdmission admission) noexcept {
  if (!ipv6_enabled_ || !link_operational_)
    return {.status = EndpointUdpSendStatus::link_down};
  if (!sink || ip::is_unspecified(destination) || destination_port == 0U)
    return {.status = EndpointUdpSendStatus::invalid_destination};
  const auto binding = udp_.local_binding(handle);
  if (!binding || binding->family != transport::IpFamily::ipv6)
    return {.status = EndpointUdpSendStatus::invalid_socket};

  // Expire lifetimes before source selection so a valid-but-expired SLAAC
  // address cannot originate one final datagram between maintenance turns.
  ipv6_autoconfiguration_.expire(now);
  std::array<ip::Ipv6SourceCandidate,
             device_catalog::ipv6_slaac_addresses_per_host_interface + 1U>
      candidates{};
  std::size_t candidate_count{};
  if (ipv6_dad_.preferred(interface_id_, ipv6_link_local_))
    candidates[candidate_count++] = {
        .address = ipv6_link_local_,
        .interface_id = interface_id_,
        .prefix_length = 64U,
        .preferred = true};
  for (const auto &address : ipv6_autoconfiguration_.addresses()) {
    if (!address.occupied ||
        address.state == host::AutoconfigAddressState::tentative)
      continue;
    candidates[candidate_count++] = {
        .address = address.address,
        .interface_id = interface_id_,
        .prefix_length = address.prefix.length,
        .preferred =
            address.state == host::AutoconfigAddressState::preferred};
  }

  std::optional<packet::Ipv6> source;
  if (!ip::is_unspecified(binding->ipv6)) {
    const auto assigned = std::find_if(
        candidates.begin(),
        candidates.begin() + static_cast<std::ptrdiff_t>(candidate_count),
        [&](const auto &candidate) {
          return candidate.address == binding->ipv6;
        });
    if (assigned != candidates.begin() +
                        static_cast<std::ptrdiff_t>(candidate_count))
      source = assigned->address;
  } else {
    const auto selected = ip::select_ipv6_source(
        std::span<const ip::Ipv6SourceCandidate>{candidates}.first(
            candidate_count),
        {.destination = destination,
         .outgoing_interface_id = interface_id_,
         .prefer_temporary = false});
    if (selected)
      source = candidates[*selected].address;
  }
  if (!source)
    return {.status = EndpointUdpSendStatus::no_source_address};

  packet::Mac destination_mac{};
  if (ip::is_multicast(destination)) {
    destination_mac = packet::ipv6_multicast_mac(destination);
  } else {
    const auto routed = route_first_hop(destination, now);
    if (!routed)
      return {.status = EndpointUdpSendStatus::no_route};
    const auto next_hop = ipv6_destinations_.current_next_hop(
        ethernet_port_ordinal, destination, *routed);
    const auto resolution =
        ipv6_neighbors_.resolve(interface_id_, next_hop, now);
    if (resolution.status == lab::Ipv6ResolutionStatus::table_full)
      return {.status = EndpointUdpSendStatus::resource_exhausted};
    if (resolution.status == lab::Ipv6ResolutionStatus::pending)
      return {.status = EndpointUdpSendStatus::neighbor_resolution_pending};
    if (resolution.status ==
        lab::Ipv6ResolutionStatus::solicitation_required) {
      const auto solicitation = packet::nd::neighbor_solicitation(
          mac_, ipv6_link_local_, next_hop);
      if (admission && !admission(sink_context, 1U))
        return {.status = EndpointUdpSendStatus::output_backpressure};
      if (!sink(sink_context, solicitation))
        return {.status = EndpointUdpSendStatus::output_backpressure};
      return {.status =
                  EndpointUdpSendStatus::neighbor_resolution_started,
              .emitted_frames = 1U};
    }
    destination_mac = resolution.mac;
  }

  // UDP writes directly behind the future IPv6 header. The generic packet
  // encoder then fills the Ethernet and IPv6 prefix in the same owner-local
  // byte arena. Source and destination ranges for the UDP copy are identical,
  // so this introduces no second 65 KiB transport scratch allocation.
  auto udp_storage = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
      packet::ethernet_header_octets + packet::ipv6_header_octets);
  const auto encoded_udp = udp_.encode_ipv6(
      handle, *source, destination, interface_id_, destination_port, payload,
      udp_storage);
  if (encoded_udp.status != transport::UdpSendStatus::encoded)
    return {.status = endpoint_udp_error(encoded_udp.status)};
  const auto datagram = packet::encode_ipv6_ethernet_datagram(
      ip_datagram_scratch_, mac_, destination_mac, *source, destination,
      packet::ipv6_next_header_udp,
      static_cast<std::uint8_t>(
          ipv6_autoconfiguration_.current_hop_limit()),
      udp_storage.first(encoded_udp.datagram_octets));
  if (!datagram)
    return {.status = EndpointUdpSendStatus::resource_exhausted};

  const auto first_hop_mtu = ipv6_autoconfiguration_.effective_mtu();
  const auto path_mtu = ipv6_path_mtu_.estimate(destination, interface_id_,
                                                 first_hop_mtu);
  const auto ip_octets = *datagram - packet::ethernet_header_octets;
  if (ip_octets <= path_mtu) {
    packet::Frame frame;
    std::copy_n(ip_datagram_scratch_.begin(), *datagram,
                frame.bytes.begin());
    frame.length = static_cast<std::uint16_t>(*datagram);
    if (admission && !admission(sink_context, 1U))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    if (!sink(sink_context, frame))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    return {.status = EndpointUdpSendStatus::sent, .emitted_frames = 1U};
  }

  const auto required = packet::ipv6_fragment_count(
      std::span<const std::uint8_t>{ip_datagram_scratch_}.first(*datagram),
      static_cast<std::uint16_t>(path_mtu));
  if (!required || (admission && !admission(sink_context, *required)))
    return {.status = EndpointUdpSendStatus::output_backpressure};
  // Identification advances only after the complete local batch has been
  // admitted. A blocked send therefore cannot consume identifier space or
  // publish a prefix that a later retry would duplicate.
  const auto identification = next_ipv6_fragment_identification_++;
  const auto fragment_count = packet::fragment_ipv6_datagram(
      std::span<const std::uint8_t>{ip_datagram_scratch_}.first(*datagram),
      static_cast<std::uint16_t>(path_mtu), identification, sink_context,
      sink);
  if (!fragment_count)
    return {.status = EndpointUdpSendStatus::output_backpressure};
  return {.status = EndpointUdpSendStatus::sent,
          .emitted_frames = *fragment_count};
}

EndpointUdpSendResult EndpointStack::send_udp_ipv4(
    transport::UdpSocketHandle handle, packet::Ipv4 destination,
    std::uint16_t destination_port, std::span<const std::uint8_t> payload,
    void *sink_context, packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission, bool checksum_enabled) noexcept {
  if (!link_operational_)
    return {.status = EndpointUdpSendStatus::link_down};
  if (!sink || destination == packet::Ipv4{} || destination_port == 0U)
    return {.status = EndpointUdpSendStatus::invalid_destination};
  const auto binding = udp_.local_binding(handle);
  if (!binding || binding->family != transport::IpFamily::ipv4)
    return {.status = EndpointUdpSendStatus::invalid_socket};
  const bool broadcast =
      ipv4_broadcast_for_interface(destination, address_, prefix_length_);
  // RFC 2131 address acquisition is the one ordinary UDP use of source
  // 0.0.0.0. A wildcard-bound, broadcast-enabled socket may use it only for
  // the limited broadcast destination. Directed broadcast and unicast still
  // require a configured interface source and therefore cannot bypass host
  // routing or ARP through this exception.
  const bool acquiring_address =
      address_ == packet::Ipv4{} &&
      destination == packet::Ipv4{255U, 255U, 255U, 255U} &&
      binding->ipv4 == packet::Ipv4{} && binding->ipv4_broadcast;
  if ((!acquiring_address && address_ == packet::Ipv4{}) ||
      (binding->ipv4 != packet::Ipv4{} && binding->ipv4 != address_))
    return {.status = EndpointUdpSendStatus::no_source_address};
  if (broadcast && !binding->ipv4_broadcast)
    return {.status = EndpointUdpSendStatus::invalid_destination};
  constexpr packet::Mac ethernet_broadcast{0xffU, 0xffU, 0xffU,
                                            0xffU, 0xffU, 0xffU};
  packet::Mac destination_mac = ethernet_broadcast;
  packet::Ipv4 next_hop{};
  if (!broadcast) {
    const auto next_hop_value = routing::host_next_hop(
        {.source = to_u32(address_),
         .prefix_length = prefix_length_,
         .destination = to_u32(destination),
         .gateway = to_u32(gateway_)});
    if (next_hop_value == 0U)
      return {.status = EndpointUdpSendStatus::no_route};
    next_hop = to_ipv4(next_hop_value);
  }
  if (!broadcast && (neighbor_address_ != next_hop || !neighbor_mac_)) {
    // A large application datagram is not hidden in a tiny pending-frame
    // array. ARP crosses the real link, then the application owner retries the
    // unchanged payload after observing neighbor-resolution progress.
    const bool request_already_pending = pending_next_hop_ == next_hop;
    neighbor_address_.reset();
    neighbor_mac_.reset();
    pending_count_ = 0U;
    if (request_already_pending)
      return {.status = EndpointUdpSendStatus::neighbor_resolution_pending};
    pending_next_hop_.reset();
    if (admission && !admission(sink_context, 1U))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    const auto request = packet::arp_request(mac_, address_, next_hop);
    if (!sink(sink_context, request))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    pending_next_hop_ = next_hop;
    return {.status = EndpointUdpSendStatus::neighbor_resolution_started,
            .emitted_frames = 1U};
  }
  if (!broadcast)
    destination_mac = *neighbor_mac_;

  return encode_udp_ipv4_to_mac(
      handle, address_, destination, destination_mac, destination_port,
      payload, sink_context, sink, admission, checksum_enabled);
}

bool EndpointStack::install_dhcpv4_lease(
    packet::Ipv4 address, std::uint8_t prefix_length,
    packet::Ipv4 gateway) noexcept {
  if (address == packet::Ipv4{} || prefix_length == 0U ||
      prefix_length > 32U || (!dhcpv4_address_owned_ &&
                              address_ != packet::Ipv4{}))
    return false;
  address_ = address;
  prefix_length_ = prefix_length;
  gateway_ = gateway;
  dhcpv4_address_owned_ = true;
  clear_neighbor();
  return true;
}

bool EndpointStack::restore_dhcpv4_lease_ownership(
    packet::Ipv4 address, std::uint8_t prefix_length,
    packet::Ipv4 gateway) noexcept {
  if (address == packet::Ipv4{} || prefix_length == 0U ||
      prefix_length > 32U || address_ != address ||
      prefix_length_ != prefix_length || gateway_ != gateway)
    return false;
  dhcpv4_address_owned_ = true;
  return true;
}

void EndpointStack::remove_dhcpv4_lease() noexcept {
  if (!dhcpv4_address_owned_)
    return;
  address_ = {};
  prefix_length_ = 0U;
  gateway_ = {};
  dhcpv4_address_owned_ = false;
  clear_neighbor();
}

bool EndpointStack::arm_dhcpv4_address_probe(
    packet::Ipv4 candidate) noexcept {
  if (candidate == packet::Ipv4{} || dhcpv4_address_owned_ ||
      address_ != packet::Ipv4{})
    return false;
  dhcpv4_probe_candidate_ = candidate;
  dhcpv4_probe_conflict_ = false;
  return true;
}

void EndpointStack::disarm_dhcpv4_address_probe() noexcept {
  dhcpv4_probe_candidate_ = {};
  dhcpv4_probe_conflict_ = false;
}

bool EndpointStack::send_dhcpv4_address_probe(
    void *sink_context, packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission) noexcept {
  if (!link_operational_ || !sink ||
      dhcpv4_probe_candidate_ == packet::Ipv4{})
    return false;
  if (admission && !admission(sink_context, 1U))
    return false;
  // packet::arp_request accepts an explicit sender protocol address. Zero is
  // intentional here and prevents other nodes from learning the candidate
  // before conflict detection has completed.
  return sink(sink_context,
              packet::arp_request(mac_, {}, dhcpv4_probe_candidate_));
}

EndpointUdpSendResult EndpointStack::send_udp_ipv4_direct_l2(
    transport::UdpSocketHandle handle, packet::Ipv4 destination,
    packet::Mac destination_mac, std::uint16_t destination_port,
    std::span<const std::uint8_t> payload, void *sink_context,
    packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission, bool checksum_enabled) noexcept {
  if (!link_operational_ || !sink)
    return {.status = EndpointUdpSendStatus::link_down};
  const auto binding = udp_.local_binding(handle);
  if (!binding || binding->family != transport::IpFamily::ipv4)
    return {.status = EndpointUdpSendStatus::invalid_socket};
  if (address_ == packet::Ipv4{} ||
      destination == packet::Ipv4{} || destination_port == 0U ||
      is_zero(destination_mac) ||
      (destination_mac[0U] & 1U) != 0U ||
      (binding->ipv4 != packet::Ipv4{} && binding->ipv4 != address_))
    return {.status = EndpointUdpSendStatus::invalid_destination};
  return encode_udp_ipv4_to_mac(
      handle, address_, destination, destination_mac, destination_port,
      payload, sink_context, sink, admission, checksum_enabled);
}

EndpointUdpSendResult EndpointStack::encode_udp_ipv4_to_mac(
    transport::UdpSocketHandle handle, packet::Ipv4 source,
    packet::Ipv4 destination, packet::Mac destination_mac,
    std::uint16_t destination_port, std::span<const std::uint8_t> payload,
    void *sink_context, packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission, bool checksum_enabled) noexcept {
  // UDP occupies bytes immediately following the fixed source IPv4 header.
  // The one owner-local arena then becomes a complete datagram image that can
  // be copied once or streamed as fragments without a 9 KiB Frame ceiling.
  auto udp_storage = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
      packet::ethernet_header_octets + 20U);
  const auto encoded_udp = udp_.encode_ipv4(
      handle, source, destination, interface_id_, destination_port, payload,
      udp_storage, checksum_enabled);
  if (encoded_udp.status != transport::UdpSendStatus::encoded)
    return {.status = endpoint_udp_error(encoded_udp.status)};
  const auto identification = next_ipv4_identification_;
  const auto datagram = packet::encode_ipv4_ethernet_datagram(
      ip_datagram_scratch_, mac_, destination_mac, source, destination, 17U,
      device_catalog::default_ip_hop_limit, identification,
      udp_storage.first(encoded_udp.datagram_octets), false);
  if (!datagram)
    return {.status = EndpointUdpSendStatus::resource_exhausted};

  const auto ip_octets = *datagram - packet::ethernet_header_octets;
  if (ip_octets <= mtu_) {
    if (admission && !admission(sink_context, 1U))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    packet::Frame frame;
    std::copy_n(ip_datagram_scratch_.begin(), *datagram, frame.bytes.begin());
    frame.length = static_cast<std::uint16_t>(*datagram);
    if (!sink(sink_context, frame))
      return {.status = EndpointUdpSendStatus::output_backpressure};
    // RFC 6864 permits any ID for an atomic datagram. Advancing uniformly keeps
    // a simple per-source sequence and avoids an immediate collision if path
    // MTU changes between two sends.
    ++next_ipv4_identification_;
    return {.status = EndpointUdpSendStatus::sent, .emitted_frames = 1U};
  }

  const auto required = packet::ipv4_fragment_count(
      std::span<const std::uint8_t>{ip_datagram_scratch_}.first(*datagram),
      mtu_);
  if (!required || (admission && !admission(sink_context, *required)))
    return {.status = EndpointUdpSendStatus::output_backpressure};
  const auto emitted = packet::fragment_ipv4_datagram(
      std::span<const std::uint8_t>{ip_datagram_scratch_}.first(*datagram),
      mtu_, sink_context, sink);
  if (!emitted)
    return {.status = EndpointUdpSendStatus::output_backpressure};
  ++next_ipv4_identification_;
  return {.status = EndpointUdpSendStatus::sent,
          .emitted_frames = *emitted};
}

EndpointTcpSendResult EndpointStack::connect_tcp(
    transport::tcp::EndpointBinding binding,
    transport::tcp::EndpointRemote remote,
    transport::tcp::SocketResources resources,
    Clock::time_point now) noexcept {
  EndpointTcpSendResult result;
  if (!tcp_)
    return result;
  if (!link_operational_) {
    result.status = EndpointTcpSendStatus::link_down;
    return result;
  }

  if (binding.family == transport::IpFamily::ipv4) {
    if (address_ == packet::Ipv4{}) {
      result.status = EndpointTcpSendStatus::no_source_address;
      return result;
    }
    if (binding.ipv4 == packet::Ipv4{})
      binding.ipv4 = address_;
    if (binding.ipv4 != address_) {
      result.status = EndpointTcpSendStatus::no_source_address;
      return result;
    }
    binding.interface_id = interface_id_;
    // A SYN is far smaller than any useful upward PMTU candidate and cannot
    // prove that a larger datagram crosses the path. Established TCP starts
    // from the confirmed estimate and learns decreases from authenticated
    // code 4 quotations.
    const auto path_mtu =
        ipv4_path_mtu_.estimate(remote.ipv4, interface_id_, mtu_);
    auto output = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
        packet::ethernet_header_octets + 20U);
    auto prepared = tcp_->prepare_connect(
        binding, remote, path_mtu - 20U, output,
        resources, now);
    return prepare_tcp_output(prepared, binding, remote, now);
  }

  if (!ipv6_enabled_) {
    result.status = EndpointTcpSendStatus::no_source_address;
    return result;
  }
  ipv6_autoconfiguration_.expire(now);
  if (ip::is_unspecified(binding.ipv6)) {
    std::array<ip::Ipv6SourceCandidate,
               device_catalog::ipv6_slaac_addresses_per_host_interface + 1U>
        candidates{};
    std::size_t candidate_count{};
    if (ipv6_dad_.preferred(interface_id_, ipv6_link_local_))
      candidates[candidate_count++] = {.address = ipv6_link_local_,
                                       .interface_id = interface_id_,
                                       .prefix_length = 64U,
                                       .preferred = true};
    for (const auto &address : ipv6_autoconfiguration_.addresses()) {
      if (!address.occupied ||
          address.state == host::AutoconfigAddressState::tentative)
        continue;
      candidates[candidate_count++] = {
          .address = address.address,
          .interface_id = interface_id_,
          .prefix_length = address.prefix.length,
          .preferred =
              address.state == host::AutoconfigAddressState::preferred};
    }
    const auto selected = ip::select_ipv6_source(
        std::span<const ip::Ipv6SourceCandidate>{candidates}.first(
            candidate_count),
        {.destination = remote.ipv6,
         .outgoing_interface_id = interface_id_,
         .prefer_temporary = false});
    if (!selected) {
      result.status = EndpointTcpSendStatus::no_source_address;
      return result;
    }
    binding.ipv6 = candidates[*selected].address;
  }
  binding.interface_id = interface_id_;
  const auto path_mtu = ipv6_path_mtu_.estimate(
      remote.ipv6, interface_id_, ipv6_autoconfiguration_.effective_mtu());
  auto output = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
      packet::ethernet_header_octets + packet::ipv6_header_octets);
  auto prepared = tcp_->prepare_connect(
      binding, remote, path_mtu - packet::ipv6_header_octets, output,
      resources, now);
  return prepare_tcp_output(prepared, binding, remote, now);
}

EndpointTcpSendResult EndpointStack::send_tcp(
    transport::tcp::EndpointSocketHandle socket, bool pushed,
    Clock::time_point now) noexcept {
  if (!tcp_)
    return {};
  const auto binding = tcp_->local_binding(socket);
  const auto remote = tcp_->remote_endpoint(socket);
  if (!binding || !remote)
    return {};
  const auto header = binding->family == transport::IpFamily::ipv4
                          ? 20U
                          : packet::ipv6_header_octets;
  auto output = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
      packet::ethernet_header_octets + header);
  return prepare_tcp_output(tcp_->prepare_data(socket, output, pushed, now),
                            *binding, *remote, now);
}

EndpointTcpSendResult EndpointStack::close_tcp(
    transport::tcp::EndpointSocketHandle socket, Clock::time_point now) noexcept {
  if (!tcp_)
    return {};
  const auto binding = tcp_->local_binding(socket);
  const auto remote = tcp_->remote_endpoint(socket);
  if (!binding || !remote)
    return {};
  const auto header = binding->family == transport::IpFamily::ipv4
                          ? 20U
                          : packet::ipv6_header_octets;
  auto output = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
      packet::ethernet_header_octets + header);
  return prepare_tcp_output(tcp_->prepare_close(socket, output, now), *binding,
                            *remote, now);
}

EndpointTcpSendResult EndpointStack::prepare_tcp_output(
    transport::tcp::EndpointPrepareResult prepared,
    transport::tcp::EndpointBinding binding,
    transport::tcp::EndpointRemote remote, Clock::time_point now) noexcept {
  EndpointTcpSendResult result{.status = EndpointTcpSendStatus::invalid_socket,
                               .socket = prepared.segment.socket,
                               .frame = {},
                               .emitted = false};
  const auto discard_prepared = [&]() noexcept {
    if (!prepared.segment.endpoint_token)
      return;
    static_cast<void>(tcp_->discard(prepared.segment));
    // Discarding a staged active-open SYN releases its newly allocated socket.
    // Do not leak that now-stale generation to an application retry owner.
    if (!tcp_->local_binding(prepared.segment.socket))
      result.socket.reset();
  };
  if (!prepared.segment.emit) {
    result.status =
        prepared.status == transport::tcp::EndpointPrepareStatus::state_changed
            ? EndpointTcpSendStatus::state_changed
            : prepared.status == transport::tcp::EndpointPrepareStatus::no_action
                  ? EndpointTcpSendStatus::no_action
                  : EndpointTcpSendStatus::transport_error;
    return result;
  }
  if (!link_operational_) {
    discard_prepared();
    result.status = EndpointTcpSendStatus::link_down;
    return result;
  }

  packet::Mac destination_mac{};
  if (binding.family == transport::IpFamily::ipv4) {
    const auto next_hop_value = routing::host_next_hop(
        {.source = to_u32(binding.ipv4),
         .prefix_length = prefix_length_,
         .destination = to_u32(remote.ipv4),
         .gateway = to_u32(gateway_)});
    if (next_hop_value == 0U) {
      discard_prepared();
      result.status = EndpointTcpSendStatus::no_route;
      return result;
    }
    const auto next_hop = to_ipv4(next_hop_value);
    if (neighbor_address_ != next_hop || !neighbor_mac_) {
      const bool pending = pending_next_hop_ == next_hop;
      discard_prepared();
      if (pending) {
        result.status = EndpointTcpSendStatus::neighbor_resolution_pending;
        return result;
      }
      result.frame = packet::arp_request(mac_, binding.ipv4, next_hop);
      result.emitted = true;
      pending_next_hop_ = next_hop;
      result.status = EndpointTcpSendStatus::neighbor_resolution_started;
      return result;
    }
    destination_mac = *neighbor_mac_;
    auto tcp_bytes = std::span<const std::uint8_t>{ip_datagram_scratch_}.subspan(
        packet::ethernet_header_octets + 20U, prepared.segment.octets);
    const auto encoded = packet::encode_ipv4_ethernet_datagram(
        ip_datagram_scratch_, mac_, destination_mac, binding.ipv4,
        remote.ipv4, packet::ipv6_next_header_tcp,
        device_catalog::default_ip_hop_limit, next_ipv4_identification_,
        tcp_bytes, true);
    if (!encoded || *encoded > result.frame.bytes.size()) {
      discard_prepared();
      result.status = EndpointTcpSendStatus::resource_exhausted;
      return result;
    }
    std::copy_n(ip_datagram_scratch_.begin(), *encoded,
                result.frame.bytes.begin());
    result.frame.length = static_cast<std::uint16_t>(*encoded);
    result.emitted = true;
    ++next_ipv4_identification_;
  } else {
    const auto routed = route_first_hop(remote.ipv6, now);
    if (!routed) {
      discard_prepared();
      result.status = EndpointTcpSendStatus::no_route;
      return result;
    }
    const auto next_hop = ipv6_destinations_.current_next_hop(
        ethernet_port_ordinal, remote.ipv6, *routed);
    const auto resolution =
        ipv6_neighbors_.resolve(interface_id_, next_hop, now);
    if (resolution.status != lab::Ipv6ResolutionStatus::resolved) {
      discard_prepared();
      if (resolution.status == lab::Ipv6ResolutionStatus::solicitation_required) {
        result.frame = packet::nd::neighbor_solicitation(
            mac_, ipv6_link_local_, next_hop);
        result.emitted = true;
        result.status = EndpointTcpSendStatus::neighbor_resolution_started;
      } else if (resolution.status == lab::Ipv6ResolutionStatus::pending) {
        result.status = EndpointTcpSendStatus::neighbor_resolution_pending;
      } else {
        result.status = EndpointTcpSendStatus::resource_exhausted;
      }
      return result;
    }
    destination_mac = resolution.mac;
    auto tcp_bytes = std::span<const std::uint8_t>{ip_datagram_scratch_}.subspan(
        packet::ethernet_header_octets + packet::ipv6_header_octets,
        prepared.segment.octets);
    const auto encoded = packet::encode_ipv6_ethernet_datagram(
        ip_datagram_scratch_, mac_, destination_mac, binding.ipv6, remote.ipv6,
        packet::ipv6_next_header_tcp,
        static_cast<std::uint8_t>(
            ipv6_autoconfiguration_.current_hop_limit()),
        tcp_bytes);
    if (!encoded || *encoded > result.frame.bytes.size()) {
      discard_prepared();
      result.status = EndpointTcpSendStatus::resource_exhausted;
      return result;
    }
    std::copy_n(ip_datagram_scratch_.begin(), *encoded,
                result.frame.bytes.begin());
    result.frame.length = static_cast<std::uint16_t>(*encoded);
    result.emitted = true;
  }

  if (prepared.segment.endpoint_token && !tcp_->commit(prepared.segment, now)) {
    // The frame has not left this method yet, so a failed state commit can
    // still retract the complete batch without exposing wire/state mismatch.
    result.frame.length = 0U;
    result.emitted = false;
    result.status = EndpointTcpSendStatus::transport_error;
    return result;
  }
  result.status = EndpointTcpSendStatus::sent;
  return result;
}

void EndpointStack::schedule_slaac_dad(Clock::time_point now) noexcept {
  for (const auto &entry : ipv6_autoconfiguration_.addresses()) {
    if (!entry.occupied ||
        entry.state != host::AutoconfigAddressState::tentative ||
        ipv6_dad_.find(interface_id_, entry.address))
      continue;
    // Every tentative unicast address joins its solicited-node group before
    // emitting NS. MLD snooping can otherwise hide a genuine duplicate.
    static_cast<void>(mld_listener_.join(
        ip::solicited_node_multicast(entry.address), now));
    static_cast<void>(ipv6_dad_.configure(
        interface_id_, ethernet_port_ordinal, entry.address,
        device_catalog::ipv6_dad_transmits,
        lab::ipv6_interface_initial_delay(
            interface_id_, entry.address, now,
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                device_catalog::ipv6_dad_max_initial_delay)),
        now));
  }
}

void EndpointStack::synchronize_mld_memberships(Clock::time_point now) noexcept {
  // Multiple unicast addresses can map to one solicited-node group. A group is
  // left only when neither the link-local address nor any live SLAAC address
  // still derives that group, preventing an address expiry from breaking DAD
  // or ND for another address sharing the low-order 24 bits.
  std::array<packet::Ipv6,
             device_catalog::ipv6_slaac_addresses_per_host_interface + 1U>
      desired{};
  std::size_t desired_count{};
  desired[desired_count++] = ip::solicited_node_multicast(ipv6_link_local_);
  for (const auto &entry : ipv6_autoconfiguration_.addresses()) {
    if (!entry.occupied)
      continue;
    const auto group = ip::solicited_node_multicast(entry.address);
    if (std::find(desired.begin(), desired.begin() + desired_count, group) ==
        desired.begin() + desired_count)
      desired[desired_count++] = group;
  }
  for (std::size_t index = 0; index < desired_count; ++index)
    static_cast<void>(mld_listener_.join(desired[index], now));
  for (std::size_t index = 0; index < mld_system_group_count_; ++index)
    if (std::find(desired.begin(), desired.begin() + desired_count,
                  mld_system_groups_[index]) == desired.begin() + desired_count)
      static_cast<void>(mld_listener_.leave(mld_system_groups_[index], now));
  std::copy_n(desired.begin(), desired_count, mld_system_groups_.begin());
  mld_system_group_count_ = static_cast<std::uint8_t>(desired_count);
}

std::optional<packet::Ipv6> EndpointStack::route_first_hop(
    const packet::Ipv6 &destination, Clock::time_point now) const noexcept {
  // A link-local unicast address is on the attached link by construction and
  // is never advertised in a Prefix Information option. Requiring an RA
  // prefix here made standards-compliant DHCPv6 peers unreachable before any
  // router had advertised a global prefix.
  if (ip::is_link_local(destination))
    return destination;
  // RFC 4861 section 5.2 first applies the Prefix List. Redirect-learned
  // on-link status lives in the Destination Cache, not in this base decision,
  // so only RA-derived live on-link prefixes are consulted here.
  for (const auto &prefix : ipv6_autoconfiguration_.on_link_prefixes())
    if (prefix.occupied && prefix.expires > now &&
        ip::contains(prefix.prefix, destination))
      return destination;

  const host::DefaultRouterEntry *selected{};
  for (const auto &router : ipv6_autoconfiguration_.default_routers()) {
    if (!router.occupied || router.expires <= now)
      continue;
    if (!selected || router.preference > selected->preference ||
        (router.preference == selected->preference &&
         router.address < selected->address))
      selected = &router;
  }
  // Router Preference is authoritative before the tie breaker. The address
  // order only makes an otherwise implementation-defined equal-preference
  // choice stable until the Destination Cache begins pinning real traffic.
  return selected ? std::optional<packet::Ipv6>{selected->address}
                  : std::nullopt;
}

EndpointFrames EndpointStack::service_maintenance(Clock::time_point now) noexcept {
  auto result = make_frame_result();
  // IPv4 reassembly expiry must continue on an IPv4-only host and therefore
  // occurs before the IPv6 capability guard. One owner-affine deadline avoids
  // a global scheduler while keeping both families live under low traffic.
  expire_ipv4_reassembly(result, now);

  // TCP deadlines are per connection and use the same monotonic owner turn as
  // ND and reassembly. At most one connection is serviced here so a large
  // socket table cannot starve physical RX work; the worker immediately sees
  // another due deadline and schedules the next bounded turn.
  if (tcp_ && result.count < result.frames.size()) {
    const auto socket = tcp_->earliest_deadline_socket();
    const auto deadline = socket ? tcp_->next_deadline(*socket) : std::nullopt;
    const auto binding = socket ? tcp_->local_binding(*socket) : std::nullopt;
    const auto remote = socket ? tcp_->remote_endpoint(*socket) : std::nullopt;
    if (socket && deadline && *deadline <= now && binding && remote) {
      const auto header = binding->family == transport::IpFamily::ipv4
                              ? 20U
                              : packet::ipv6_header_octets;
      auto output = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
          packet::ethernet_header_octets + header);
      const auto transmitted = prepare_tcp_output(
          tcp_->prepare_deadline(*socket, output, now), *binding, *remote, now);
      if (transmitted.emitted)
        append(result, transmitted.frame);
    }
  }
  if (!ipv6_enabled_ || !link_operational_)
    return result;
  ipv6_autoconfiguration_.expire(now);
  synchronize_mld_memberships(now);
  std::array<lab::Ipv6DadAction,
             device_catalog::host_ipv6_work_budget_actions>
      actions{};
  const auto count = ipv6_dad_.poll(now, actions);
  for (std::size_t index = 0; index < count; ++index)
    append(result, packet::nd::neighbor_solicitation(
                       mac_, {}, actions[index].target, true));

  // poll may complete DAD without producing a packet after the final quiet
  // interval. Mirror those transitions into the SLAAC repository before source
  // selection or upper-layer delivery observes the address.
  for (const auto &entry : ipv6_autoconfiguration_.addresses()) {
    if (!entry.occupied ||
        entry.state != host::AutoconfigAddressState::tentative)
      continue;
    const auto dad = ipv6_dad_.find(interface_id_, entry.address);
    if (dad && dad->state == lab::Ipv6DadState::preferred)
      static_cast<void>(
          ipv6_autoconfiguration_.confirm_dad(entry.address, false, now));
    else if (dad && dad->state == lab::Ipv6DadState::duplicate) {
      // confirm_dad may replace the address in place under RFC 7217. Capture
      // the old key first, then free its DAD slot so successive conflicts do
      // not consume the bounded table permanently.
      const auto duplicate_address = entry.address;
      static_cast<void>(
          ipv6_autoconfiguration_.confirm_dad(duplicate_address, true, now));
      ipv6_dad_.remove(interface_id_, duplicate_address);
    }
  }
  // A regenerated RFC 7217 entry remains tentative and has no DAD table key.
  // Scheduling here starts its encoded NS exchange on the next due deadline.
  schedule_slaac_dad(now);

  if (const auto link_local_dad =
          ipv6_dad_.find(interface_id_, ipv6_link_local_);
      link_local_dad &&
      link_local_dad->state == lab::Ipv6DadState::duplicate &&
      ipv6_identifier_.mode ==
          host::InterfaceIdentifierMode::stable_opaque &&
      !ipv6_link_local_generation_exhausted_ &&
      ipv6_link_local_dad_counter_ <
          device_catalog::ipv6_stable_iid_dad_retries) {
    const auto duplicate_address = ipv6_link_local_;
    auto next_counter = ipv6_link_local_dad_counter_;
    packet::Ipv6 next_address{};
    bool acceptable{};
    while (next_counter < device_catalog::ipv6_stable_iid_dad_retries) {
      ++next_counter;
      next_address = derive_ipv6_link_local(next_counter);
      if (!has_reserved_interface_identifier(next_address)) {
        acceptable = true;
        break;
      }
    }
    if (!acceptable) {
      // The current duplicate remains visible as the failed address. The flag
      // prevents an owner turn from repeatedly hashing the exhausted range.
      ipv6_link_local_generation_exhausted_ = true;
    } else {
      ipv6_link_local_dad_counter_ = next_counter;
      ipv6_link_local_ = next_address;
      ipv6_dad_.remove(interface_id_, duplicate_address);

      // RFC 7217 IDGEN_DELAY is profile-generated and intentionally distinct
      // from the initial random DAD spread. Retrying immediately could create
      // a tight packet loop between nodes that selected the same opaque tuple.
      static_cast<void>(mld_listener_.join(
          ip::solicited_node_multicast(ipv6_link_local_), now));
      static_cast<void>(ipv6_dad_.configure(
          interface_id_, ethernet_port_ordinal, ipv6_link_local_,
          device_catalog::ipv6_dad_transmits,
          lab::ipv6_interface_initial_delay(
              interface_id_, ipv6_link_local_, now,
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  device_catalog::ipv6_stable_iid_dad_retry_delay)),
          now));
      synchronize_mld_memberships(now);
    }
  }

  const bool link_local_preferred =
      ipv6_dad_.preferred(interface_id_, ipv6_link_local_);
  mld_listener_.set_link_state(true, link_local_preferred, now);

  // Neighbor Cache timers are owner-local. A due probe is encoded into an
  // ordinary frame and returned to NetworkPlane; no cache action can invoke a
  // peer or a link directly. There are no pending IPv6 application packets to
  // fail yet, so resolution_failed only retires the cache state.
  std::array<lab::Ipv6NeighborAction,
             device_catalog::host_ipv6_work_budget_actions>
      neighbor_actions{};
  const auto neighbor_capacity = result.frames.size() - result.count;
  const auto neighbor_count = ipv6_neighbors_.poll(
      now, std::span<lab::Ipv6NeighborAction>{neighbor_actions}.first(
               neighbor_capacity));
  for (std::size_t index = 0;
       index < neighbor_count && result.count < result.frames.size(); ++index) {
    const auto &action = neighbor_actions[index];
    if (action.kind == lab::Ipv6NeighborActionKind::multicast_solicitation)
      append(result, packet::nd::neighbor_solicitation(
                         mac_, ipv6_link_local_, action.address));
    else if (action.kind ==
             lab::Ipv6NeighborActionKind::unicast_solicitation)
      append(result, packet::nd::neighbor_unicast_probe(
                         mac_, action.mac, ipv6_link_local_, action.address));
  }

  // MLD report actions are encoded here but still returned as ordinary frames
  // to NetworkPlane. No listener state is passed directly to a router.
  std::array<lab::MldListenerAction,
             device_catalog::mld_work_budget_actions>
      mld_actions{};
  const auto mld_capacity = result.frames.size() - result.count;
  const auto mld_count = mld_listener_.poll(
      now, std::span<lab::MldListenerAction>{mld_actions}.first(mld_capacity));
  const auto mld_source =
      link_local_preferred ? ipv6_link_local_ : packet::Ipv6{};
  for (std::size_t index = 0;
       index < mld_count && result.count < result.frames.size(); ++index) {
    const auto &action = mld_actions[index];
    if (action.version_one) {
      const auto frame = packet::mld::version_one_message(
          mac_, mld_source,
          action.done ? packet::mld::version_one_done_type
                      : packet::mld::version_one_report_type,
          action.multicast_address);
      if (frame)
        append(result, *frame);
      continue;
    }
    const packet::mld::ReportRecord record{
        .type = action.record_type,
        .multicast_address = action.multicast_address,
        .sources = std::span<const packet::Ipv6>{action.sources.data(),
                                                 action.source_count}};
    const auto frame = packet::mld::version_two_report(
        mac_, mld_source, std::span<const packet::mld::ReportRecord>{&record, 1U});
    if (frame)
      append(result, *frame);
  }

  if (router_solicitation_active_ &&
      router_solicitation_deadline_ <= now &&
      result.count < result.frames.size()) {
    const auto source =
        ipv6_dad_.preferred(interface_id_, ipv6_link_local_)
                            ? ipv6_link_local_
                            : packet::Ipv6{};
    append(result, packet::nd::router_solicitation(mac_, source));
    ++router_solicitations_sent_;
    if (router_solicitations_sent_ >=
        device_catalog::ipv6_rs_max_solicitations) {
      router_solicitation_active_ = false;
      router_solicitation_deadline_ = Clock::time_point::max();
    } else {
      router_solicitation_deadline_ = now + device_catalog::ipv6_rs_interval;
    }
  }
  return result;
}

std::optional<EndpointStack::Clock::time_point>
EndpointStack::next_maintenance_deadline() const noexcept {
  std::optional<Clock::time_point> result = ipv4_reassembly_.next_deadline();
  const auto dad = ipv6_dad_.next_deadline();
  if (dad && (!result || *dad < *result))
    result = dad;
  const auto autoconfiguration = ipv6_autoconfiguration_.next_deadline();
  if (autoconfiguration && (!result || *autoconfiguration < *result))
    result = autoconfiguration;
  if (router_solicitation_active_ &&
      (!result || router_solicitation_deadline_ < *result))
    result = router_solicitation_deadline_;
  const auto mld = mld_listener_.next_deadline();
  if (mld && (!result || *mld < *result))
    result = mld;
  const auto neighbor = ipv6_neighbors_.next_deadline();
  if (neighbor && (!result || *neighbor < *result))
    result = neighbor;
  if (tcp_) {
    const auto socket = tcp_->earliest_deadline_socket();
    const auto tcp_deadline =
        socket ? tcp_->next_deadline(*socket) : std::nullopt;
    if (tcp_deadline && (!result || *tcp_deadline < *result))
      result = tcp_deadline;
  }
  return result;
}

EndpointFrames EndpointStack::begin_echo(packet::Ipv4 destination,
                                         std::uint16_t sequence,
                                         std::size_t payload_octets,
                                         bool dont_fragment,
                                         Clock::time_point now) noexcept {
  // Host next-hop selection occurs before ARP. A cached exact mapping releases
  // the packet immediately; otherwise the encoded IP frame remains pending.
  auto result = make_frame_result();
  auto request =
      packet::icmp_echo(mac_, no_mac, address_, destination, false, sequence,
                        64, payload_octets, dont_fragment);
  std::size_t packet_count{};
  // The shared source packetizer derives the complete fragment count before
  // writing. DF or an impossible MTU therefore fails without leaving a prefix
  // in the pending ARP generation. The endpoint arena is used directly so the
  // maximum 31-fragment command does not consume a forwarding pthread stack.
  const auto request_ip = packet::parse_ipv4(request);
  const auto effective_mtu =
      dont_fragment && request_ip
          ? ipv4_path_mtu_.begin_probe(destination, interface_id_, mtu_,
                                       request_ip->total_length, now)
          : static_cast<std::uint32_t>(mtu_);
  if (!packetize_ipv4_source(frame_arena_->pending, packet_count, request,
                             static_cast<std::uint16_t>(effective_mtu))) {
    result.mtu_exceeded = true;
    return result;
  }
  ipv4_probe_valid_ = dont_fragment && packet_count == 1U;
  ipv4_probe_destination_ = ipv4_probe_valid_ ? destination : packet::Ipv4{};
  if (ipv4_probe_valid_)
    packet::copy_frame(frame_arena_->ipv4_probe,
                       frame_arena_->pending[0U]);
  const auto next_hop =
      to_ipv4(routing::host_next_hop({.source = to_u32(address_),
                                      .prefix_length = prefix_length_,
                                      .destination = to_u32(destination),
                                      .gateway = to_u32(gateway_)}));
  if (neighbor_address_ == next_hop && neighbor_mac_) {
    for (std::size_t index = 0; index < packet_count; ++index) {
      packet::rewrite_ethernet(frame_arena_->pending[index], mac_,
                               *neighbor_mac_);
      append(result, frame_arena_->pending[index]);
    }
    result.start_echo_clock = true;
    return result;
  }
  neighbor_address_.reset();
  neighbor_mac_.reset();
  pending_count_ = static_cast<std::uint8_t>(packet_count);
  pending_next_hop_ = next_hop;
  append(result, packet::arp_request(mac_, address_, next_hop));
  return result;
}

EndpointFrames EndpointStack::receive(const packet::Frame &frame,
                                      std::uint16_t expected_sequence,
                                      bool probe_source,
                                      Clock::time_point now) noexcept {
  // Unicast and IPv4 broadcast use the shared Ethernet filter. IPv6 multicast
  // additionally requires an exact protocol-to-MAC mapping and membership in
  // a group owned by this interface.
  auto result = make_frame_result();
  // A packet arriving on the same owner turn as a reassembly deadline cannot
  // revive expired state. Drain due entries first, then process the new frame.
  expire_ipv4_reassembly(result, now);
  const auto ethernet = packet::parse_ethernet(frame);
  if (!ethernet)
    return result;
  std::optional<packet::Ipv6View> ipv6;
  bool layer_two_local =
      packet::ethernet_for_local(ethernet->destination, mac_);
  if (ethernet->ether_type == packet::ethernet_type_ipv6 && ipv6_enabled_) {
    ipv6 = packet::parse_ipv6(frame);
    layer_two_local =
        ethernet->destination == mac_ ||
        (ipv6 && ip::is_multicast(ipv6->destination) &&
         mld_listener_.joined(ipv6->destination) &&
         ethernet->destination ==
             packet::ipv6_multicast_mac(ipv6->destination));
  }
  if (!layer_two_local)
    return result;

  if (ethernet->ether_type == packet::ethernet_type_ipv6 && ipv6_enabled_) {
    if (!ipv6)
      return result;
    const auto local_address = [&](const packet::Ipv6 &address) {
      if (address == ipv6_link_local_)
        return ipv6_dad_.preferred(interface_id_, address);
      return std::any_of(
          ipv6_autoconfiguration_.addresses().begin(),
          ipv6_autoconfiguration_.addresses().end(),
          [&](const auto &entry) {
            return entry.occupied && entry.address == address &&
                   entry.state != host::AutoconfigAddressState::tentative;
          });
    };
    if (const auto query = packet::mld::parse_query(frame)) {
      mld_listener_.observe_query(*query, now);
      return result;
    }
    if (const auto report = packet::mld::parse_version_one(frame);
        report && report->type == packet::mld::version_one_report_type) {
      mld_listener_.observe_version_one_report(report->multicast_address);
      return result;
    }
    if (const auto advertisement =
            packet::nd::parse_router_advertisement(frame)) {
      static_cast<void>(
          ipv6_autoconfiguration_.process(*advertisement, false, now));
      if (advertisement->source_link_layer)
        static_cast<void>(ipv6_neighbors_.learn_stale(
            interface_id_, advertisement->source,
            *advertisement->source_link_layer, true, now));
      schedule_slaac_dad(now);
      // A valid RA satisfies the discovery attempt even when it advertises a
      // zero router lifetime. Prefix and DNS options remain independently useful.
      router_solicitation_active_ = false;
      router_solicitation_deadline_ = Clock::time_point::max();
      return result;
    }
    if (const auto solicitation =
            packet::nd::parse_neighbor_solicitation(frame)) {
      static_cast<void>(
          ipv6_dad_.observe_conflict(interface_id_,
                                     solicitation->target));
      if (!solicitation->duplicate_address_detection &&
          solicitation->source_link_layer)
        static_cast<void>(ipv6_neighbors_.learn_stale(
            interface_id_, solicitation->source,
            *solicitation->source_link_layer, false, now));
      const bool target_is_local =
          ipv6_dad_.preferred(interface_id_,
                              solicitation->target);
      if (target_is_local) {
        const auto destination = solicitation->duplicate_address_detection
                                     ? packet::nd::all_nodes_multicast
                                     : solicitation->source;
        const auto destination_mac =
            solicitation->duplicate_address_detection
                ? packet::ipv6_multicast_mac(
                      packet::nd::all_nodes_multicast)
                : ethernet->source;
        append(result, packet::nd::neighbor_advertisement(
                           mac_, destination_mac, solicitation->target,
                           destination, solicitation->target, false,
                           !solicitation->duplicate_address_detection, true));
      }
      return result;
    }
    if (const auto advertisement =
            packet::nd::parse_neighbor_advertisement(frame)) {
      static_cast<void>(
          ipv6_dad_.observe_conflict(interface_id_,
                                     advertisement->target));
      static_cast<void>(ipv6_neighbors_.receive_advertisement(
          interface_id_, advertisement->target,
          advertisement->target_link_layer, advertisement->solicited,
          advertisement->override_flag, advertisement->router, false,
          std::chrono::milliseconds{
              ipv6_autoconfiguration_.reachable_time_milliseconds()},
          now));
      return result;
    }
    if (const auto redirect = packet::nd::parse_redirect(frame)) {
      if (!local_address(redirect->receiver))
        return result;
      ipv6_autoconfiguration_.expire(now);
      const auto route = route_first_hop(redirect->destination, now);
      if (!route)
        return result;
      const auto current = ipv6_destinations_.current_next_hop(
          ethernet_port_ordinal, redirect->destination, *route);
      if (!ipv6_destinations_.accept_redirect(
              ethernet_port_ordinal, *redirect, current, *route))
        return result;
      // RFC 4861 section 8.3 requires a TLLA learned from Redirect to enter
      // STALE. A router target is identified by Target != Destination; the
      // on-link case cannot infer that flag and therefore uses false.
      if (redirect->target_link_layer)
        static_cast<void>(ipv6_neighbors_.learn_stale(
            interface_id_, redirect->target,
            *redirect->target_link_layer,
            redirect->target != redirect->destination, now));
      return result;
    }
    // Upper-layer multicast is local only when the interface's MLD filter
    // accepts both the group and source. The Ethernet check above proves the
    // MAC mapping, but treating only unicast addresses as local here used to
    // discard valid DHCPv6, DNS and application multicast after that check.
    const bool upper_layer_local =
        local_address(ipv6->destination) ||
        (ip::is_multicast(ipv6->destination) &&
         mld_listener_.accepts(ipv6->destination, ipv6->source));
    if (!upper_layer_local)
      return result;

    // Reassembly belongs only to the destination endpoint. Each fragment has
    // already crossed the link and passed the local L2/L3 destination checks.
    // The completed view may exceed Frame and is consumed before the next table
    // operation invalidates its owner-borrowed storage.
    std::span<const std::uint8_t> local_packet = frame.view();
    std::optional<packet::Frame> small_reassembled;
    std::optional<packet::Ipv6View> delivered_ipv6 = ipv6;
    if (ipv6->fragment) {
      const auto reassembled = ipv6_reassembly_.accept(frame, now);
      if (reassembled.status == packet::Ipv6ReassemblyStatus::incomplete)
        return result;
      if ((reassembled.status != packet::Ipv6ReassemblyStatus::complete &&
           reassembled.status != packet::Ipv6ReassemblyStatus::atomic) ||
          reassembled.packet.empty())
        return result;
      local_packet = reassembled.packet;
      delivered_ipv6 = packet::parse_ipv6(local_packet);
      if (!delivered_ipv6)
        return result;
      if (local_packet.size() <= packet::maximum_frame_octets) {
        small_reassembled.emplace();
        std::copy(local_packet.begin(), local_packet.end(),
                  small_reassembled->bytes.begin());
        small_reassembled->length =
            static_cast<std::uint16_t>(local_packet.size());
      }
    }

    // AH payload is intentionally opaque until an IPsec SA verifies its ICV.
    // The host has still received the encoded frame through its real link and
    // capture path, but it must not let an attacker select UDP, TCP, ICMPv6,
    // DHCPv6 or DNS merely by writing AH.NextHeader.
    if (delivered_ipv6->authentication_header_present)
      return result;

    const auto icmp = packet::parse_icmpv6(local_packet);
    // RFC 6980 prohibits every traditional ND message in a Fragment Header,
    // including an atomic fragment. Detection after complete reassembly also
    // covers a non-first fragment that arrived before its identifying first
    // fragment without retaining a protocol-specific partial exception.
    if (ipv6->fragment && icmp &&
        icmp->type >= packet::nd::router_solicitation_type &&
        icmp->type <= packet::nd::redirect_type)
      return result;
    if (icmp) {
      const auto error_kind = ipv6_network_error_kind(icmp->type, icmp->code);
      const auto quoted = error_kind ? packet::parse_ipv6_quote(icmp->data)
                                     : std::nullopt;
      if (quoted && local_address(quoted->source) &&
          !ip::is_multicast(quoted->destination)) {
        const auto offset =
            static_cast<std::size_t>(quoted->upper_layer_offset);
        const auto local_port = read_u16(icmp->data, offset);
        const auto remote_port = read_u16(icmp->data, offset + 2U);
        bool accepted{};
        if (quoted->upper_layer_protocol == packet::ipv6_next_header_udp) {
          accepted = udp_.report_ipv6_error(
              quoted->source, quoted->destination, interface_id_, local_port,
              remote_port, *error_kind, icmp->type, icmp->code,
              icmp->parameter);
        } else if (quoted->upper_layer_protocol ==
                       packet::ipv6_next_header_tcp &&
                   tcp_) {
          const auto sequence = read_u32(icmp->data, offset + 4U);
          accepted = tcp_->report_ipv6_error(
              quoted->source, quoted->destination, interface_id_, local_port,
              remote_port, sequence, *error_kind, icmp->type, icmp->code,
              icmp->parameter);
        }
        if (accepted && *error_kind ==
                            transport::Ipv6NetworkErrorKind::packet_too_big) {
          const auto first_hop_mtu = std::max<std::uint32_t>(
              ipv6_autoconfiguration_.effective_mtu(),
              packet::ipv6_minimum_link_mtu);
          const auto update = ipv6_path_mtu_.update(
              quoted->destination, interface_id_, icmp->parameter,
              first_hop_mtu, now);
          if (tcp_ && (update == ip::PathMtuUpdate::decreased ||
                       update == ip::PathMtuUpdate::unchanged)) {
            const auto path_mtu = ipv6_path_mtu_.estimate(
                quoted->destination, interface_id_, first_hop_mtu);
            static_cast<void>(tcp_->reduce_ipv6_path_mtu_for_path(
                quoted->destination, interface_id_,
                path_mtu - packet::ipv6_header_octets));
          }
        }
        // ICMPv6 errors are consumed by their transport owner and must never
        // fall through to UDP/TCP payload ingestion as if the quote were the
        // outer packet's application data.
        return result;
      }
    }
    if (delivered_ipv6->upper_layer_protocol ==
        packet::ipv6_next_header_udp) {
      const auto packet_end =
          static_cast<std::size_t>(packet::ethernet_header_octets) +
          packet::ipv6_header_octets + delivered_ipv6->payload_length;
      const auto upper_offset =
          static_cast<std::size_t>(delivered_ipv6->upper_layer_offset);
      if (upper_offset <= packet_end)
        static_cast<void>(udp_.ingest_ipv6(
            local_packet.subspan(upper_offset, packet_end - upper_offset),
            delivered_ipv6->source, delivered_ipv6->destination,
            interface_id_, ethernet->source));
      return result;
    }
    if (delivered_ipv6->upper_layer_protocol ==
            packet::ipv6_next_header_tcp &&
        tcp_) {
      const auto packet_end =
          static_cast<std::size_t>(packet::ethernet_header_octets) +
          packet::ipv6_header_octets + delivered_ipv6->payload_length;
      const auto upper_offset =
          static_cast<std::size_t>(delivered_ipv6->upper_layer_offset);
      if (upper_offset > packet_end)
        return result;

      // The connection policy receives the IP-layer maximum transport
      // message, including the TCP header. It is derived from this interface's
      // effective IPv6 MTU instead of a fixed Ethernet MSS. The endpoint never
      // advertises bytes which its own source packetizer could not place in
      // one IPv6 packet without a Fragment Header.
      const auto effective_mtu =
          std::max<std::uint32_t>(ipv6_autoconfiguration_.effective_mtu(),
                                  packet::ipv6_minimum_link_mtu);
      const auto maximum_transport_message =
          effective_mtu - packet::ipv6_header_octets;
      auto tcp_storage = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
          packet::ethernet_header_octets + packet::ipv6_header_octets);
      const auto prepared = tcp_->ingest_ipv6(
          local_packet.subspan(upper_offset, packet_end - upper_offset),
          delivered_ipv6->source, delivered_ipv6->destination, interface_id_,
          maximum_transport_message, tcp_storage, now);
      if (!prepared.segment.emit)
        return result;

      // A response to an accepted unicast segment returns to the exact L2
      // sender that delivered it. Routers therefore remain the next hop for
      // off-link peers and no neighbor entry is manufactured from an IP tuple.
      const auto encoded = packet::encode_ipv6_ethernet_datagram(
          ip_datagram_scratch_, mac_, ethernet->source,
          delivered_ipv6->destination, delivered_ipv6->source,
          packet::ipv6_next_header_tcp,
          static_cast<std::uint8_t>(
              ipv6_autoconfiguration_.current_hop_limit()),
          tcp_storage.first(prepared.segment.octets));
      packet::Frame response;
      const bool admitted =
          encoded && *encoded <= response.bytes.size() &&
          ([&] {
            std::copy_n(ip_datagram_scratch_.begin(), *encoded,
                        response.bytes.begin());
            response.length = static_cast<std::uint16_t>(*encoded);
            return append(result, response);
          })();
      if (prepared.segment.endpoint_token != 0U) {
        // Stateful output is transactional. A full lower batch must not move
        // SND.NXT, start an RTO or consume a FIN merely because encoding was
        // attempted. Stateless RST responses intentionally have no token.
        if (admitted)
          static_cast<void>(tcp_->commit(prepared.segment, now));
        else
          static_cast<void>(tcp_->discard(prepared.segment));
      }
      return result;
    }
    if (icmp && icmp->type == packet::icmpv6_echo_request_type &&
        icmp->code == 0U && (!ipv6->fragment || small_reassembled)) {
      // Current echo encoding consumes a Frame. Full-size UDP already uses the
      // span path above; a future full-size ICMP sender will stream fragments
      // through the same source packetizer rather than truncate to this bound.
      const auto *echo_frame = small_reassembled ? &*small_reassembled : &frame;
      const auto reply = packet::icmpv6_echo_reply(*echo_frame, mac_,
                                                   ethernet->source);
      if (reply)
        append(result, *reply);
    }
    return result;
  }

  if (ethernet->ether_type == packet::ethernet_type_arp) {
    const auto arp = packet::parse_arp(frame);
    if (!arp)
      return result;
    if (dhcpv4_probe_candidate_ != packet::Ipv4{} &&
        arp->sender_mac != mac_ &&
        (arp->sender_ip == dhcpv4_probe_candidate_ ||
         (arp->sender_ip == packet::Ipv4{} &&
          arp->target_ip == dhcpv4_probe_candidate_)))
      dhcpv4_probe_conflict_ = true;
    if (arp->target_ip != address_)
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
    if (pending_next_hop_ == arp->sender_ip) {
      const auto count = pending_count_;
      pending_count_ = 0;
      pending_next_hop_.reset();
      for (std::size_t index = 0; index < count; ++index) {
        packet::Frame pending;
        packet::copy_frame(pending, frame_arena_->pending[index]);
        packet::rewrite_ethernet(pending, mac_, arp->sender_mac);
        append(result, pending);
      }
      result.start_echo_clock = count != 0U;
    }
    return result;
  }
  if (ethernet->ether_type != packet::ethernet_type_ipv4)
    return result;
  auto ip = packet::parse_ipv4(frame);
  const bool broadcast = ip && ipv4_broadcast_for_interface(
                                   ip->destination, address_, prefix_length_);
  const auto pre_address_unicast =
      [&](std::span<const std::uint8_t> packet_bytes,
          const packet::Ipv4View &candidate) {
        // RFC 2131 permits direct L2 delivery to yiaddr before the interface
        // installs that address. Ethernet filtering above has already proved
        // the frame belongs to this NIC. UDP socket authority then narrows the
        // exception to the configured acquisition client and exact port.
        if (address_ != packet::Ipv4{} || candidate.protocol != 17U ||
            candidate.fragment_offset || candidate.more_fragments)
          return false;
        const auto upper_offset =
            packet::ethernet_header_octets +
            static_cast<std::size_t>(candidate.header_length);
        const auto packet_end =
            packet::ethernet_header_octets +
            static_cast<std::size_t>(candidate.total_length);
        if (upper_offset > packet_end || packet_end > packet_bytes.size())
          return false;
        const auto datagram = packet::udp::parse_ipv4(
            packet_bytes.subspan(upper_offset, packet_end - upper_offset),
            candidate.source, candidate.destination);
        return datagram &&
               udp_.accepts_ipv4_unconfigured_unicast(
                   interface_id_, datagram->destination_port);
      };
  if (!ip ||
      (ip->destination != address_ && !broadcast &&
       !pre_address_unicast(frame.view(), *ip)))
    return result;
  std::span<const std::uint8_t> local_packet = frame.view();
  std::optional<packet::Frame> small_reassembled;
  if (ip->fragment_offset || ip->more_fragments) {
    const auto reassembled = ipv4_reassembly_.accept(frame, now);
    if (reassembled.status == packet::Ipv4ReassemblyStatus::incomplete)
      return result;
    if (reassembled.status != packet::Ipv4ReassemblyStatus::complete ||
        reassembled.packet.empty())
      return result;
    local_packet = reassembled.packet;
    ip = packet::parse_ipv4(local_packet);
    if (!ip)
      return result;
    if (local_packet.size() <= packet::maximum_frame_octets) {
      small_reassembled.emplace();
      std::copy(local_packet.begin(), local_packet.end(),
                small_reassembled->bytes.begin());
      small_reassembled->length =
          static_cast<std::uint16_t>(local_packet.size());
    }
  }
  const bool reassembled_broadcast =
      ip && ipv4_broadcast_for_interface(ip->destination, address_,
                                         prefix_length_);
  if (!ip ||
      (ip->destination != address_ && !reassembled_broadcast &&
       !pre_address_unicast(local_packet, *ip)))
    return result;
  if (ip->protocol == 17U) {
    const auto upper_offset = packet::ethernet_header_octets +
                              static_cast<std::size_t>(ip->header_length);
    const auto packet_end = packet::ethernet_header_octets +
                            static_cast<std::size_t>(ip->total_length);
    if (upper_offset > packet_end)
      return result;
    const auto delivered = udp_.ingest_ipv4(
        local_packet.subspan(upper_offset, packet_end - upper_offset),
        ip->source, ip->destination, interface_id_, ethernet->source);
    if (delivered == transport::UdpIngressStatus::no_socket && !broadcast &&
        valid_icmpv4_error_destination(ip->source)) {
      const auto invoking_ethernet = packet::parse_ethernet(local_packet);
      if (invoking_ethernet) {
        const auto error = packet::icmp_port_unreachable(
            local_packet, mac_, invoking_ethernet->source, address_, ip->source);
        if (error)
          append(result, *error);
      }
    }
    return result;
  }
  if (ip->protocol == packet::ipv6_next_header_tcp && tcp_ && !broadcast) {
    const auto upper_offset = packet::ethernet_header_octets +
                              static_cast<std::size_t>(ip->header_length);
    const auto packet_end = packet::ethernet_header_octets +
                            static_cast<std::size_t>(ip->total_length);
    if (upper_offset > packet_end || mtu_ <= ip->header_length)
      return result;

    // IPv4 options in a received packet do not reduce the local interface's
    // advertised MSS. This stack originates the fixed 20-octet header used by
    // its source packetizer, so MMS_R follows the configured MTU minus that
    // locally generated header.
    const auto maximum_transport_message =
        static_cast<std::uint32_t>(mtu_ - 20U);
    auto tcp_storage = std::span<std::uint8_t>{ip_datagram_scratch_}.subspan(
        packet::ethernet_header_octets + 20U);
    const auto prepared = tcp_->ingest_ipv4(
        local_packet.subspan(upper_offset, packet_end - upper_offset),
        ip->source, ip->destination, interface_id_, maximum_transport_message,
        tcp_storage, now);
    if (!prepared.segment.emit)
      return result;

    const auto encoded = packet::encode_ipv4_ethernet_datagram(
        ip_datagram_scratch_, mac_, ethernet->source, ip->destination,
        ip->source, packet::ipv6_next_header_tcp,
        device_catalog::default_ip_hop_limit, next_ipv4_identification_,
        tcp_storage.first(prepared.segment.octets), true);
    packet::Frame response;
    const bool admitted =
        encoded && *encoded <= response.bytes.size() &&
        ([&] {
          std::copy_n(ip_datagram_scratch_.begin(), *encoded,
                      response.bytes.begin());
          response.length = static_cast<std::uint16_t>(*encoded);
          return append(result, response);
        })();
    if (admitted)
      ++next_ipv4_identification_;
    if (prepared.segment.endpoint_token != 0U) {
      if (admitted)
        static_cast<void>(tcp_->commit(prepared.segment, now));
      else
        static_cast<void>(tcp_->discard(prepared.segment));
    }
    return result;
  }

  // Current ICMP codecs own a Frame value. Small reassemblies retain that path;
  // a larger ICMP datagram is not truncated merely to force it through. Full
  // span-based ICMP echo belongs to the later ICMP payload-size slice.
  const packet::Frame *datagram = small_reassembled ? &*small_reassembled
                                                     : &frame;
  if (local_packet.size() > packet::maximum_frame_octets)
    return result;
  const auto complete_ethernet = packet::parse_ethernet(*datagram);
  const auto icmp = packet::parse_icmp(*datagram);
  if (!icmp)
    return result;
  if (icmp->type == 8 && !broadcast) {
    const auto reply = packet::icmp_echo_reply(
        *datagram, mac_, complete_ethernet ? complete_ethernet->source
                                          : ethernet->source);
    if (reply) {
      // Echo Reply is a new source datagram and obeys this endpoint's own MTU.
      // A large reassembled request must not make the host emit one oversized
      // Ethernet frame merely because the reply bytes fit in the core Frame
      // arena. Capacity is checked for the entire fragment batch first.
      std::size_t output_count = result.count;
      const auto initial_output_count = output_count;
      if (packetize_ipv4_source(result.storage, output_count, *reply, mtu_)) {
        for (auto index = initial_output_count; index < output_count; ++index)
          result.frames[index].value = &result.storage[index];
        result.count = static_cast<std::uint8_t>(output_count);
      } else {
        result.mtu_exceeded = true;
      }
    }
  } else if (probe_source && icmp->type == 0 &&
             icmp->sequence == expected_sequence) {
    result.echo_reply = true;
    // Success promotes an upward test only when the reply came from the exact
    // retained destination. A guessed sequence from another source cannot
    // change path state.
    if (ipv4_probe_valid_ && ip->source == ipv4_probe_destination_)
      static_cast<void>(ipv4_path_mtu_.confirm_probe(
          ipv4_probe_destination_, interface_id_, now));
    ipv4_probe_valid_ = false;
  } else if (probe_source && icmp->type == 11) {
    result.ttl_expired = true;
  } else if (icmp->type == 3 && icmp->code == 4) {
    // ICMP is not authenticated cryptographically. Exact quotation matching
    // prevents a sender that merely guesses the destination and Echo sequence
    // from lowering the cache. The endpoint still confirms that its route key
    // has not changed since the probe was emitted.
    if (probe_source && ipv4_probe_valid_ &&
        matches_ipv4_probe_quote(icmp->data, frame_arena_->ipv4_probe)) {
      const auto quoted = packet::parse_ipv4(frame_arena_->ipv4_probe);
      const auto current_next_hop = to_ipv4(routing::host_next_hop(
          {.source = to_u32(address_),
           .prefix_length = prefix_length_,
           .destination = to_u32(ipv4_probe_destination_),
           .gateway = to_u32(gateway_)}));
      if (quoted && current_next_hop != packet::Ipv4{}) {
        const auto update = ipv4_path_mtu_.update(
            ipv4_probe_destination_, interface_id_,
            icmp->parameter & 0xffffU, quoted->total_length, mtu_, now);
        result.mtu_exceeded =
            update == ip::Ipv4PathMtuUpdate::decreased ||
            update == ip::Ipv4PathMtuUpdate::unchanged;
      }
    }
    // TCP quotes normally carry only the IPv4 header and the first eight TCP
    // octets. The live tuple plus an unacknowledged transmitted sequence is
    // therefore the strongest association available in the mandated quote.
    // It is checked before the shared path cache or TCB is modified.
    const auto quoted_ip = packet::parse_ipv4_quote(icmp->data);
    if (quoted_ip && quoted_ip->protocol == packet::ipv6_next_header_tcp &&
        quoted_ip->source == address_ && quoted_ip->dont_fragment &&
        quoted_ip->fragment_offset == 0U && !quoted_ip->more_fragments) {
      const auto tcp_offset =
          static_cast<std::size_t>(quoted_ip->header_length);
      const auto local_port = static_cast<std::uint16_t>(
          icmp->data[tcp_offset] << 8U | icmp->data[tcp_offset + 1U]);
      const auto remote_port = static_cast<std::uint16_t>(
          icmp->data[tcp_offset + 2U] << 8U |
          icmp->data[tcp_offset + 3U]);
      const auto sequence =
          static_cast<std::uint32_t>(icmp->data[tcp_offset + 4U]) << 24U |
          static_cast<std::uint32_t>(icmp->data[tcp_offset + 5U]) << 16U |
          static_cast<std::uint32_t>(icmp->data[tcp_offset + 6U]) << 8U |
          icmp->data[tcp_offset + 7U];
      if (tcp_->recognizes_ipv4_transmission(
              address_, quoted_ip->destination, interface_id_, local_port,
              remote_port, sequence)) {
        const auto update = ipv4_path_mtu_.update(
            quoted_ip->destination, interface_id_,
            icmp->parameter & 0xffffU, quoted_ip->total_length, mtu_, now);
        if (update == ip::Ipv4PathMtuUpdate::decreased ||
            update == ip::Ipv4PathMtuUpdate::unchanged) {
          const auto path_mtu = ipv4_path_mtu_.estimate(
              quoted_ip->destination, interface_id_, mtu_);
          static_cast<void>(tcp_->reduce_ipv4_path_mtu(
              address_, quoted_ip->destination, interface_id_, local_port,
              remote_port, sequence, path_mtu - 20U));
        }
      }
    }
  }
  return result;
}

void EndpointStack::expire_ipv4_reassembly(EndpointFrames &result,
                                           Clock::time_point now) noexcept {
  packet::Frame first_fragment;
  while (result.count < result.frames.size() &&
         ipv4_reassembly_.take_expired(first_fragment, now)) {
    // RFC 1122 suppresses the timeout message when fragment zero never
    // arrived. The empty value still means the expired slot was reclaimed.
    if (!first_fragment.length || !link_operational_)
      continue;
    const auto ip = packet::parse_ipv4(first_fragment);
    const auto ethernet = packet::parse_ethernet(first_fragment);
    if (!ip || !ethernet)
      continue;
    const auto error = packet::icmp_reassembly_time_exceeded(
        first_fragment, mac_, ethernet->source, address_, ip->source);
    if (error)
      append(result, *error);
  }
}

void EndpointStack::clear_neighbor() noexcept {
  // Clearing also discards the unresolved packet because it belongs to the old
  // address or link generation and cannot be forwarded safely later.
  neighbor_address_.reset();
  neighbor_mac_.reset();
  pending_count_ = 0;
  pending_next_hop_.reset();
  ipv4_reassembly_.discard_all();
}

void EndpointStack::restore_router_neighbor(packet::Ipv4 address,
                                            packet::Mac mac) noexcept {
  // Checkpoint restore installs only a completed exact mapping, never pending
  // packet storage or an outstanding request flag.
  clear_neighbor();
  neighbor_address_ = address;
  neighbor_mac_ = mac;
}

void EndpointStack::checkpoint(NetworkCheckpointState &state,
                               Clock::time_point now) const {
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
      state.frames.push_back({.next_hop = *pending_next_hop_,
                              .frame = frame_arena_->pending[index]});
  }
  output.next_ipv4_identification = next_ipv4_identification_;
  state.ipv4_reassembly = ipv4_reassembly_.checkpoint(now);
  state.ipv4_path_mtu = ipv4_path_mtu_.checkpoint(now);
  output.ipv4_probe_valid = ipv4_probe_valid_;
  if (ipv4_probe_valid_) {
    output.ipv4_probe_destination = ipv4_probe_destination_;
    output.ipv4_probe_packet = frame_arena_->ipv4_probe;
  }
  state.udp = udp_.checkpoint();
  state.ike_udp = ike_udp_.checkpoint();
  state.tcp = tcp_ ? tcp_->checkpoint(now) : std::nullopt;
  if (ipv6_enabled_) {
    // Each deadline is made relative to the same captured steady-clock sample.
    // Mixing Clock::now calls here would lengthen later fields by serialization
    // time and could reorder two protocol actions that were originally equal.
    state.ipv6.autoconfiguration = ipv6_autoconfiguration_.checkpoint(now);
    state.ipv6.dad = ipv6_dad_.checkpoint(now);
    state.ipv6.neighbors = ipv6_neighbors_.checkpoint(now);
    state.ipv6.destinations = ipv6_destinations_.checkpoint();
    state.ipv6.path_mtu = ipv6_path_mtu_.checkpoint(now);
    state.ipv6.mld = mld_listener_.checkpoint(now);
    state.ipv6_reassembly = ipv6_reassembly_.checkpoint(now);
    state.ipv6.link_local_dad_counter = ipv6_link_local_dad_counter_;
    state.ipv6.next_fragment_identification =
        next_ipv6_fragment_identification_;
    state.ipv6.link_local_generation_exhausted =
        ipv6_link_local_generation_exhausted_;
    state.ipv6.router_solicitations_sent = router_solicitations_sent_;
    state.ipv6.router_solicitation_active = router_solicitation_active_;
    if (router_solicitation_active_) {
      const auto remaining = router_solicitation_deadline_ > now
                                 ? router_solicitation_deadline_ - now
                                 : Clock::duration::zero();
      state.ipv6.router_solicitation_remaining_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
              .count();
    }
  }
}

bool EndpointStack::restore(const NetworkCheckpointState &state,
                            Clock::time_point now) noexcept {
  if (!state.tcp)
    return false;
  std::unique_ptr<transport::tcp::TcpEndpoint> restored_tcp;
  try {
    restored_tcp = std::make_unique<transport::tcp::TcpEndpoint>(
        state.tcp->isn.secret, now);
  } catch (const std::bad_alloc &) {
    return false;
  }
  if (!restored_tcp->restore(*state.tcp, now))
    return false;
  const auto &input = state.endpoint;
  std::array<const NetworkStoredFrame *,
             EndpointFrames::maximum_pending_fragments> pending_frames{};
  std::size_t pending_count{};
  for (const auto &stored : state.frames) {
    if (pending_count == pending_frames.size())
      return false;
    pending_frames[pending_count++] = &stored;
  }
  const auto maximum_router_solicitation_delay = std::max(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          device_catalog::ipv6_rs_interval),
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          device_catalog::ipv6_rs_max_initial_delay));
  const bool ipv6_checkpoint_valid =
      !ipv6_enabled_
          ? state.ipv6.dad.empty() &&
                state.ipv6.neighbors.empty() &&
                state.ipv6.destinations.empty() &&
                state.ipv6.path_mtu.empty() &&
                state.ipv6.autoconfiguration.interface_id == 0U &&
                state.ipv6.mld.groups.empty() &&
                state.ipv6.mld.random_state == 0U &&
                state.ipv6.link_local_dad_counter == 0U &&
                state.ipv6.next_fragment_identification == 1U &&
                !state.ipv6.link_local_generation_exhausted &&
                !state.ipv6.mld.version_one_compatibility &&
                !state.ipv6.mld.link_operational &&
                !state.ipv6.mld.link_local_preferred &&
                !state.ipv6.router_solicitation_active &&
                state.ipv6.router_solicitations_sent == 0U &&
                state.ipv6.router_solicitation_remaining_nanoseconds == 0
          : host::Ipv6HostAutoconfiguration::validate_checkpoint(
                state.ipv6.autoconfiguration) &&
                state.ipv6.autoconfiguration.interface_id == interface_id_ &&
                lab::Ipv6DadTable::validate_checkpoint(state.ipv6.dad) &&
                std::all_of(state.ipv6.dad.begin(), state.ipv6.dad.end(),
                            [&](const auto &entry) {
                              // A host has one logical interface and one
                              // physical Ethernet attachment. Both identities
                              // must survive restore together.
                              return entry.interface_id == interface_id_ &&
                                     entry.port_ordinal ==
                                         ethernet_port_ordinal;
                            }) &&
                lab::Ipv6NeighborCache::validate_checkpoint(
                    state.ipv6.neighbors) &&
                std::all_of(state.ipv6.neighbors.begin(),
                            state.ipv6.neighbors.end(),
                            [&](const auto &entry) {
                              // A host owns one IP interface. Accepting a
                              // foreign scope would make a restored link-local
                              // neighbor unreachable while appearing valid.
                              return entry.interface_id == interface_id_;
                            }) &&
                lab::Ipv6DestinationCache::validate_checkpoint(
                    state.ipv6.destinations) &&
                ip::Ipv6PathMtuCache::validate_checkpoint(
                    state.ipv6.path_mtu) &&
                lab::MldListener::validate_checkpoint(state.ipv6.mld) &&
                state.ipv6.link_local_dad_counter <=
                    device_catalog::ipv6_stable_iid_dad_retries &&
                (ipv6_identifier_.mode ==
                         host::InterfaceIdentifierMode::stable_opaque ||
                 (state.ipv6.link_local_dad_counter == 0U &&
                  !state.ipv6.link_local_generation_exhausted)) &&
                state.ipv6.router_solicitations_sent <=
                    device_catalog::ipv6_rs_max_solicitations &&
                (!state.ipv6.router_solicitation_active ||
                 (link_operational_ &&
                  state.ipv6.router_solicitations_sent <
                      device_catalog::ipv6_rs_max_solicitations &&
                  state.ipv6.router_solicitation_remaining_nanoseconds >= 0 &&
                  state.ipv6.router_solicitation_remaining_nanoseconds <=
                      maximum_router_solicitation_delay.count()));
  if (!ipv6_checkpoint_valid ||
      !transport::UdpEndpoint::validate_checkpoint(state.udp) ||
      !ikev2::UdpService::validate_checkpoint(state.ike_udp, state.udp) ||
      !packet::Ipv6ReassemblyTable::validate_checkpoint(
          state.ipv6_reassembly) ||
      !packet::Ipv4ReassemblyTable::validate_checkpoint(
          state.ipv4_reassembly) ||
      !ip::Ipv4PathMtuCache::validate_checkpoint(state.ipv4_path_mtu) ||
      std::any_of(state.ipv4_path_mtu.begin(), state.ipv4_path_mtu.end(),
                  [&](const auto &entry) {
                    // A host endpoint has exactly one stable IP interface.
                    // A foreign PMTU scope could otherwise constrain traffic
                    // for an interface that this owner cannot route through.
                    return entry.interface_id != interface_id_;
                  }) ||
      std::any_of(state.ipv6.path_mtu.begin(), state.ipv6.path_mtu.end(),
                  [&](const auto &entry) {
                    // Apply the same ownership rule to the IPv6 destination
                    // cache image before any protocol owner is mutated.
                    return entry.interface_id != interface_id_;
                  }) ||
      (input.ipv4_probe_valid &&
       (input.ipv4_probe_destination == packet::Ipv4{} ||
        !packet::parse_ipv4(input.ipv4_probe_packet) ||
        packet::parse_ipv4(input.ipv4_probe_packet)->destination !=
            input.ipv4_probe_destination ||
        !packet::parse_ipv4(input.ipv4_probe_packet)->dont_fragment)) ||
      (!input.ipv4_probe_valid &&
       (input.ipv4_probe_destination != packet::Ipv4{} ||
        input.ipv4_probe_packet.length != 0U)) ||
      (!ipv6_enabled_ && !state.ipv6_reassembly.empty()) ||
      input.pending_next_hop_valid != (pending_count != 0U) ||
      (input.pending_next_hop_valid &&
       input.pending_next_hop == packet::Ipv4{}) ||
      std::any_of(pending_frames.begin(),
                  pending_frames.begin() + pending_count,
                  [&](const auto *frame) {
                    // One unresolved ARP generation owns the entire fragment
                    // batch. Mixing next hops would release packets on the
                    // MAC learned for a different neighbor after restore.
                    const auto ipv4 = packet::parse_ipv4(frame->frame);
                    return frame->next_hop != input.pending_next_hop ||
                           !ipv4 || ipv4->source != address_ ||
                           !frame->frame.length ||
                           frame->frame.length > frame->frame.bytes.size();
                  }))
    return false;

  const auto restored_link_local =
      derive_ipv6_link_local(state.ipv6.link_local_dad_counter);
  const auto restored_link_local_dad =
      std::find_if(state.ipv6.dad.begin(), state.ipv6.dad.end(),
                   [&](const auto &entry) {
                     return entry.port_ordinal == ethernet_port_ordinal &&
                            entry.address == restored_link_local;
                   });
  // An operational IPv6 interface always owns one DAD record for its current
  // link-local address, including the terminal duplicate state after retry
  // exhaustion. A down interface owns none because set_link_state discarded
  // that generation before the checkpoint was taken.
  if (ipv6_enabled_ &&
      ((link_operational_ && restored_link_local_dad == state.ipv6.dad.end()) ||
       (!link_operational_ && restored_link_local_dad != state.ipv6.dad.end())))
    return false;
  if (state.ipv6.link_local_generation_exhausted &&
      (restored_link_local_dad == state.ipv6.dad.end() ||
       restored_link_local_dad->state != lab::Ipv6DadState::duplicate))
    return false;

  clear_neighbor();
  if (input.neighbor_valid) {
    neighbor_address_ = input.neighbor_address;
    neighbor_mac_ = input.neighbor_mac;
  }
  if (pending_count) {
    for (std::size_t index = 0; index < pending_count; ++index)
      frame_arena_->pending[index] = pending_frames[index]->frame;
    pending_count_ = static_cast<std::uint8_t>(pending_count);
    pending_next_hop_ = input.pending_next_hop;
  }
  if (!ipv4_reassembly_.restore(state.ipv4_reassembly, now))
    return false;
  if (!ipv4_path_mtu_.restore(state.ipv4_path_mtu, now))
    return false;
  next_ipv4_identification_ = input.next_ipv4_identification;
  ipv4_probe_valid_ = input.ipv4_probe_valid;
  ipv4_probe_destination_ = input.ipv4_probe_destination;
  if (ipv4_probe_valid_)
    frame_arena_->ipv4_probe = input.ipv4_probe_packet;
  if (ipv6_enabled_) {
    // Both owners have already validated their images. Their restore methods
    // repeat validation to keep each reusable component safe in isolation.
    if (!ipv6_autoconfiguration_.restore(state.ipv6.autoconfiguration, now) ||
        !ipv6_dad_.restore(state.ipv6.dad, now) ||
        !ipv6_neighbors_.restore(state.ipv6.neighbors, now) ||
        !ipv6_destinations_.restore(state.ipv6.destinations) ||
        !ipv6_path_mtu_.restore(state.ipv6.path_mtu, now) ||
        !mld_listener_.restore(state.ipv6.mld, now) ||
        !ipv6_reassembly_.restore(state.ipv6_reassembly, now))
      return false;
    ipv6_link_local_dad_counter_ = state.ipv6.link_local_dad_counter;
    next_ipv6_fragment_identification_ =
        state.ipv6.next_fragment_identification;
    ipv6_link_local_generation_exhausted_ =
        state.ipv6.link_local_generation_exhausted;
    ipv6_link_local_ = restored_link_local;
    // This array is only an ownership aid for removing stale system groups.
    // Rebuild it from restored address intent rather than persisting duplicate
    // membership state beside the authoritative MLD checkpoint.
    mld_system_group_count_ = 0U;
    synchronize_mld_memberships(now);
    router_solicitations_sent_ = state.ipv6.router_solicitations_sent;
    router_solicitation_active_ = state.ipv6.router_solicitation_active;
    router_solicitation_deadline_ =
        router_solicitation_active_
            ? now + std::chrono::nanoseconds{
                        state.ipv6
                            .router_solicitation_remaining_nanoseconds}
            : Clock::time_point::max();
  }
  if (!udp_.restore(state.udp))
    return false;
  if (!ike_udp_.restore(state.ike_udp, udp_))
    return false;
  tcp_ = std::move(restored_tcp);
  return true;
}

} // namespace router::network_detail
