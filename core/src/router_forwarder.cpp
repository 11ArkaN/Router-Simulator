// Per-router Ethernet dual-stack forwarding implementation. ARP and Neighbor
// Discovery knowledge is learned only from validated received frames on one
// local port. No forwarding decision inspects the editor topology.

#include "router/router_forwarder.hpp"

#include "router/ipv6_extension.hpp"
#include "router/ipv6_source_selection.hpp"
#include "router/sha256.hpp"
#include "router/udp_packet.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <new>
#include <utility>

namespace router::lab {
namespace {

std::uint32_t to_u32(packet::Ipv4 address) noexcept {
  // Packet fields remain byte arrays in network order. The RIB uses an integer
  // only as a comparison key, so this conversion performs no host-endian load.
  return static_cast<std::uint32_t>(address[0]) << 24 |
         static_cast<std::uint32_t>(address[1]) << 16 |
         static_cast<std::uint32_t>(address[2]) << 8 | address[3];
}

packet::Ipv4 to_ipv4(std::uint32_t address) noexcept {
  // Shifts define the wire byte order explicitly and avoid aliasing a uint32_t
  // through a byte pointer on Wasm and native hosts.
  return {static_cast<std::uint8_t>(address >> 24),
          static_cast<std::uint8_t>(address >> 16),
          static_cast<std::uint8_t>(address >> 8),
          static_cast<std::uint8_t>(address)};
}

std::uint64_t ecmp_hash_bytes(std::span<const std::uint8_t> bytes,
                              std::uint64_t seed) noexcept {
  // Nokia documents the default unicast hash inputs as both IP addresses and
  // the path index as hash modulo ECMP width, but does not publish the ASIC
  // mixing function. FNV-1a is the release-profiled deterministic mixer here.
  // It gives stable per-flow behavior without pretending to reproduce an
  // undocumented forwarding-chip bucket assignment.
  constexpr std::uint64_t prime{1099511628211ULL};
  for (const auto byte : bytes) {
    seed ^= byte;
    seed *= prime;
  }
  return seed;
}

std::uint64_t ipv4_ecmp_hash(const packet::Ipv4View &packet) noexcept {
  constexpr std::uint64_t offset{14695981039346656037ULL};
  return ecmp_hash_bytes(packet.destination,
                         ecmp_hash_bytes(packet.source, offset));
}

std::uint64_t ipv6_ecmp_hash(const packet::Ipv6View &packet) noexcept {
  constexpr std::uint64_t offset{14695981039346656037ULL};
  return ecmp_hash_bytes(packet.destination,
                         ecmp_hash_bytes(packet.source, offset));
}

bool usable_sender_mac(packet::Mac mac) noexcept {
  // Reject group, broadcast and all-zero addresses before ARP learning. The
  // local-admin bit is valid and therefore intentionally not rejected.
  return (mac[0] & 1U) == 0U &&
         std::any_of(mac.begin(), mac.end(),
                     [](auto byte) { return byte != 0; });
}

bool directed_broadcast(const ForwardPort &port,
                        std::uint32_t destination) noexcept {
  if (!port.configured || !port.ipv4_configured || port.prefix_length >= 31U)
    return false;
  const auto host_mask = ~routing::prefix_mask(port.prefix_length);
  return destination == (port.network | host_mask);
}

constexpr packet::Mac unresolved_mac{};

std::optional<transport::Ipv6NetworkErrorKind>
ipv6_transport_error_kind(std::uint8_t type, std::uint8_t code) noexcept {
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

std::uint16_t read_network_u16(std::span<const std::uint8_t> bytes,
                               std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(bytes[offset] << 8U) |
         bytes[offset + 1U];
}

std::chrono::milliseconds arp_retry_interval(const ForwardPort &port) noexcept {
  // The MD and classic leaves use deciseconds. Converting at the forwarding
  // boundary keeps parser units out of every pending-adjacency operation.
  return std::chrono::milliseconds{
      static_cast<std::int64_t>(port.arp_retry_deciseconds) * 100};
}

void write_dhcpv6_u16(std::span<std::uint8_t> output, std::size_t offset,
                      std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write_dhcpv6_u32(std::span<std::uint8_t> output, std::size_t offset,
                      std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

bool append_dhcpv6_nested(std::span<std::uint8_t> output, std::size_t &position,
                          packet::dhcpv6::OptionCode code,
                          std::span<const std::uint8_t> body) noexcept {
  // A nested IA option uses the same four-octet TLV grammar as a top-level
  // option, but Writer intentionally owns only complete DHCP messages.
  if (body.size() > std::numeric_limits<std::uint16_t>::max() ||
      position > output.size() || body.size() + 4U > output.size() - position)
    return false;
  write_dhcpv6_u16(output, position, static_cast<std::uint16_t>(code));
  write_dhcpv6_u16(output, position + 2U,
                   static_cast<std::uint16_t>(body.size()));
  std::copy(body.begin(), body.end(), output.begin() + position + 4U);
  position += 4U + body.size();
  return true;
}

std::uint32_t
dhcpv6_remaining_seconds(RouterForwarder::Clock::time_point deadline,
                         RouterForwarder::Clock::time_point now) noexcept {
  if (deadline == RouterForwarder::Clock::time_point::max())
    return std::numeric_limits<std::uint32_t>::max();
  if (deadline <= now)
    return 0U;
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(deadline - now);
  return static_cast<std::uint32_t>(std::min<std::int64_t>(
      seconds.count(), std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t
dhcpv6_release_transaction_id(const dhcpv6::RelayLeaseRecord &lease,
                              RouterForwarder::Clock::time_point now) noexcept {
  // RFC 9915 section 16.1 recommends a transaction ID that an off-path peer
  // cannot easily predict. The lease identities, exact owner-local monotonic
  // instant and stable scoped key are hashed rather than truncated directly.
  // A newly learned lease changes at least its server/client tuple or clear
  // instant, while the 24-bit result stays in the wire-defined domain.
  crypto::Sha256 hash;
  hash.update(std::span<const std::uint8_t>{lease.client.duid}.first(
      lease.client.duid_octets));
  hash.update(std::span<const std::uint8_t>{lease.server.duid}.first(
      lease.server.duid_octets));
  hash.update(lease.value);
  std::array<std::uint8_t, 20U> context{};
  const auto instant =
      static_cast<std::uint64_t>(now.time_since_epoch().count());
  for (std::size_t index = 0; index < 8U; ++index)
    context[index] = static_cast<std::uint8_t>(instant >> (index * 8U));
  for (std::size_t index = 0; index < 8U; ++index)
    context[8U + index] =
        static_cast<std::uint8_t>(lease.interface_id >> (index * 8U));
  write_dhcpv6_u32(context, 16U, lease.client.iaid);
  hash.update(context);
  const auto digest = hash.finish();
  return (static_cast<std::uint32_t>(digest[0]) << 16U) |
         (static_cast<std::uint32_t>(digest[1]) << 8U) | digest[2];
}

bool valid_icmpv6_direction(
    const Icmpv6DirectionStatistics &statistics) noexcept {
  // Each displayed message-type bucket is mutually exclusive and therefore
  // cannot collectively exceed Total. Errors are included in Total by RFC
  // 4293, while Discarded is an independent attempted-generation outcome.
  const std::array categories{statistics.destination_unreachable,
                              statistics.redirects,
                              statistics.time_exceeded,
                              statistics.packet_too_big,
                              statistics.echo_request,
                              statistics.echo_reply,
                              statistics.router_solicitation,
                              statistics.router_advertisement,
                              statistics.neighbor_solicitation,
                              statistics.neighbor_advertisement,
                              statistics.parameter_problem};
  if (statistics.errors > statistics.total ||
      std::any_of(categories.begin(), categories.end(),
                  [&](auto value) { return value > statistics.total; }))
    return false;
  // Once Total saturates, independent type counters may continue saturating
  // and their mathematical sum can exceed uint64_t. Before that point checked
  // addition detects a forged checkpoint without rejecting valid saturation.
  if (statistics.total == std::numeric_limits<std::uint64_t>::max())
    return true;
  std::uint64_t categorized{};
  for (const auto value : categories) {
    if (value > statistics.total - categorized)
      return false;
    categorized += value;
  }
  return categorized <= statistics.total;
}

bool valid_icmpv4_direction(
    const Icmpv4DirectionStatistics &statistics) noexcept {
  // Every displayed Type bucket is mutually exclusive. Error messages are
  // already included in Total, so no category may exceed that authority and
  // the checked sum cannot exceed it before saturation.
  const std::array categories{statistics.destination_unreachable,
                              statistics.redirects,
                              statistics.echo_request,
                              statistics.echo_reply,
                              statistics.time_exceeded,
                              statistics.source_quench,
                              statistics.timestamp_request,
                              statistics.timestamp_reply,
                              statistics.address_mask_request,
                              statistics.address_mask_reply,
                              statistics.parameter_problem};
  if (statistics.errors > statistics.total ||
      std::any_of(categories.begin(), categories.end(),
                  [&](auto value) { return value > statistics.total; }))
    return false;
  if (statistics.total == std::numeric_limits<std::uint64_t>::max())
    return true;
  std::uint64_t categorized{};
  for (const auto value : categories) {
    if (value > statistics.total - categorized)
      return false;
    categorized += value;
  }
  return categorized <= statistics.total;
}

bool valid_icmpv4_statistics(const Icmpv4Statistics &statistics) noexcept {
  return valid_icmpv4_direction(statistics.received) &&
         valid_icmpv4_direction(statistics.sent);
}

bool valid_icmpv6_statistics(const Icmpv6Statistics &statistics) noexcept {
  return valid_icmpv6_direction(statistics.received) &&
         valid_icmpv6_direction(statistics.sent) &&
         statistics.received.discarded == 0U;
}

bool address_scope_selected(Ipv6UnsolicitedLearning selection,
                            const packet::Ipv6 &address) noexcept {
  // SR OS uses the same global, link-local and both vocabulary for unsolicited
  // learning and proactive refresh. The helper accepts a wire address rather
  // than CLI text, so scope is decided at the forwarding owner after parsing.
  if (selection == Ipv6UnsolicitedLearning::both)
    return true;
  return ip::is_link_local(address)
             ? selection == Ipv6UnsolicitedLearning::link_local
             : selection == Ipv6UnsolicitedLearning::global;
}

bool valid_ipv6_neighbor_policy(const ForwardPort &port) noexcept {
  // The limits are generated from the pinned 26.7 release profile. Arithmetic
  // is widened even though today's maximum is 3,600 seconds, keeping this
  // boundary safe if a future release increases it.
  const auto reachable =
      static_cast<std::uint64_t>(port.nd_reachable_time_milliseconds);
  const auto minimum_reachable =
      static_cast<std::uint64_t>(
          device_catalog::nd_minimum_reachable_time_seconds) *
      1000U;
  const auto maximum_reachable =
      static_cast<std::uint64_t>(
          device_catalog::nd_maximum_reachable_time_seconds) *
      1000U;
  if (reachable < minimum_reachable || reachable > maximum_reachable ||
      port.nd_stale_time_seconds <
          device_catalog::nd_minimum_stale_time_seconds ||
      port.nd_stale_time_seconds >
          device_catalog::nd_maximum_stale_time_seconds ||
      port.ipv6_unsolicited_learning > Ipv6UnsolicitedLearning::both ||
      port.ipv6_proactive_refresh > Ipv6UnsolicitedLearning::both ||
      port.ipv6_neighbor_limit > device_catalog::nd_maximum_neighbor_limit ||
      port.ipv6_neighbor_limit_threshold_percent > 100U)
    return false;

  // When the limit leaf is absent, the remaining fields have one canonical
  // representation. A checkpoint cannot hide dormant policy that becomes
  // active after an unrelated boolean flip.
  return port.ipv6_neighbor_limit_configured ||
         (port.ipv6_neighbor_limit == 0U &&
          !port.ipv6_neighbor_limit_log_only &&
          port.ipv6_neighbor_limit_threshold_percent ==
              device_catalog::nd_default_neighbor_limit_threshold_percent);
}

std::vector<dhcpv6::RelayLeasePolicy>
relay_lease_policies(std::span<const dhcpv6::RelayInterfaceConfig> interfaces) {
  // Translation stays at the owner boundary. The packet relay configuration
  // remains the canonical control projection, while the lease repository sees
  // only fields that affect snooped operational state. Building a complete
  // generation prevents a successful interface edit from accidentally
  // dropping the policies of other relay interfaces on the same router.
  std::vector<dhcpv6::RelayLeasePolicy> result;
  result.reserve(interfaces.size());
  for (const auto &interface : interfaces)
    result.push_back(
        {.interface_id = interface.interface_id,
         .physical_port_ordinal = interface.physical_port_ordinal,
         .client_prefix = interface.client_prefix,
         .maximum_leases = interface.lease_population_limit,
         .neighbor_resolution = interface.neighbor_resolution,
         .route_non_temporary = interface.route_non_temporary,
         .route_temporary = interface.route_temporary,
         .route_delegated_prefix = interface.route_delegated_prefix,
         .route_prefix_exclude = interface.route_prefix_exclude});
  return result;
}

std::uint64_t
ipv6_reachable_seed(const ForwardPort &port,
                    RouterForwarder::Clock::time_point now) noexcept {
  // RFC 4861 section 2.1 warns that an interface identifier alone is not a
  // sufficient PRNG seed. Mix the router-owned MAC, both configured IPv6
  // identities, physical ordinal and the monotonic activation instant. This
  // generator is scheduling entropy, not key material, so FNV-1a is suitable.
  std::uint64_t value{1469598103934665603ULL};
  const auto mix = [&](std::uint8_t byte) {
    value ^= byte;
    value *= 1099511628211ULL;
  };
  for (const auto byte : port.mac)
    mix(byte);
  for (const auto byte : port.ipv6_address)
    mix(byte);
  for (const auto byte : port.ipv6_link_local)
    mix(byte);
  mix(static_cast<std::uint8_t>(port.ordinal));
  mix(static_cast<std::uint8_t>(port.ordinal >> 8U));
  auto instant = static_cast<std::uint64_t>(now.time_since_epoch().count());
  for (unsigned shift = 0U; shift < 64U; shift += 8U)
    mix(static_cast<std::uint8_t>(instant >> shift));
  return value ? value : 1U;
}

} // namespace

void RouterForwarder::refresh_ipv6_reachable_time(
    std::uint16_t port_ordinal, Clock::time_point now) noexcept {
  auto &state = ipv6_reachable_times_[port_ordinal];
  // xorshift64* supplies a full-period scheduling stream from the nonzero
  // interface seed. It is compact, allocation-free and entirely owner-local.
  state.random_state ^= state.random_state >> 12U;
  state.random_state ^= state.random_state << 25U;
  state.random_state ^= state.random_state >> 27U;
  const auto sample = state.random_state * 0x2545f4914f6cdd1dULL;

  // RFC 4861 section 10 defines the closed 0.5 through 1.5 range. Mapping the
  // high 32 sample bits into base+1 millisecond slots avoids floating point
  // differences between native builds and WebAssembly checkpoints.
  const auto lower = state.base_milliseconds / 2U;
  const auto slots = static_cast<std::uint64_t>(state.base_milliseconds) + 1U;
  const auto offset = ((sample >> 32U) * slots) >> 32U;
  state.effective_milliseconds = lower + static_cast<std::uint32_t>(offset);
  state.refresh_deadline =
      now + device_catalog::nd_reachable_time_recalculation;
}

void RouterForwarder::configure_ipv6_reachable_time(
    const ForwardPort &port, const ForwardPort &previous,
    Clock::time_point now) noexcept {
  auto &state = ipv6_reachable_times_[port.ordinal];
  if (!port.ipv6_configured) {
    state = {};
    return;
  }
  // Unrelated control leaves do not perturb the protocol random stream. A new
  // interface identity or BaseReachableTime starts a distinct RFC variable.
  if (state.valid && previous.configured && previous.ipv6_configured &&
      previous.mac == port.mac &&
      previous.ipv6_link_local == port.ipv6_link_local &&
      state.base_milliseconds == port.nd_reachable_time_milliseconds)
    return;
  state = {.random_state = ipv6_reachable_seed(port, now),
           .base_milliseconds = port.nd_reachable_time_milliseconds,
           .valid = true};
  refresh_ipv6_reachable_time(port.ordinal, now);
}

std::chrono::milliseconds
RouterForwarder::ipv6_reachable_time(std::uint16_t port_ordinal,
                                     Clock::time_point now) noexcept {
  auto &state = ipv6_reachable_times_[port_ordinal];
  // Packet receive can be the first owner turn after a long browser-idle
  // interval. Refresh lazily as well as in maintenance so a confirmation can
  // never reuse an expired interface ReachableTime sample.
  if (state.valid && state.refresh_deadline <= now)
    refresh_ipv6_reachable_time(port_ordinal, now);
  return std::chrono::milliseconds{state.effective_milliseconds};
}

bool RouterForwarder::configure_port(const ForwardPort &input) noexcept {
  // Validation occurs before indexing the fixed arena. An invalid management
  // transaction cannot disturb the previously installed forwarding projection.
  if (input.ordinal >= ports_.size() ||
      (input.ipv4_configured && input.prefix_length > 32U) ||
      input.arp_timeout_seconds > device_catalog::arp_timeout_maximum_seconds ||
      input.arp_retry_deciseconds <
          device_catalog::arp_retry_minimum_deciseconds ||
      input.arp_retry_deciseconds >
          device_catalog::arp_retry_maximum_deciseconds ||
      input.icmp_redirect_maximum <
          device_catalog::icmp_redirect_minimum_maximum ||
      input.icmp_redirect_maximum >
          device_catalog::icmp_redirect_maximum_maximum ||
      input.icmp_redirect_interval_seconds <
          device_catalog::icmp_redirect_minimum_interval.count() ||
      input.icmp_redirect_interval_seconds >
          device_catalog::icmp_redirect_maximum_interval.count() ||
      input.mtu < device_catalog::minimum_network_mtu ||
      input.mtu > device_catalog::maximum_network_mtu || !input.speed_mbps ||
      input.icmp6_redirect_maximum <
          device_catalog::icmp6_redirect_minimum_maximum ||
      input.icmp6_redirect_maximum >
          device_catalog::icmp6_redirect_maximum_maximum ||
      input.icmp6_redirect_interval_seconds <
          device_catalog::icmp6_redirect_minimum_interval.count() ||
      input.icmp6_redirect_interval_seconds >
          device_catalog::icmp6_redirect_maximum_interval.count() ||
      !valid_ipv6_neighbor_policy(input) ||
      (input.ipv6_configured &&
       (input.mtu < packet::ipv6_minimum_ethernet_mtu ||
        input.ipv6_prefix_length > ip::ipv6_address_bits ||
        ip::is_unspecified(input.ipv6_address) ||
        ip::is_multicast(input.ipv6_address) ||
        !ip::is_link_local(input.ipv6_link_local))))
    return false;
  // Network is canonicalized at the forwarding boundary. Control may keep the
  // configured host address separately, while lookup sees one unambiguous key.
  const auto previous = ports_[input.ordinal];
  auto value = input;
  if (value.ipv4_configured)
    value.network &= routing::prefix_mask(value.prefix_length);
  if (value.ipv6_configured)
    value.ipv6_network = ip::mask(value.ipv6_address, value.ipv6_prefix_length);

  // Prepare the compatibility address generation before changing any port,
  // DAD, neighbor or PMTU state. Vector allocation is a cold control-plane
  // operation and may fail; keeping it before publication makes configure_port
  // genuinely atomic under Wasm memory pressure.
  RouterIpv6AddressTable next_address_table;
  try {
    std::vector<RouterIpv6Address> addresses;
    addresses.reserve(native_ipv6_addresses_.records().size() + 1U);
    std::optional<RouterIpv6Address> previous_primary;
    for (const auto &record : native_ipv6_addresses_.records()) {
      const bool same_interface =
          record.interface_id == physical_interface_id(value.ordinal);
      if (same_interface && !value.ipv6_configured)
        continue;
      if (same_interface && previous.ipv6_configured &&
          record.address == previous.ipv6_address)
        previous_primary = record;
      else
        addresses.push_back(record);
    }
    if (value.ipv6_configured) {
      auto selected = RouterIpv6Address{
          .address = value.ipv6_address,
          .network = value.ipv6_network,
          .interface_id = physical_interface_id(value.ordinal),
          .primary_preference = 0U,
          .port_ordinal = value.ordinal,
          .prefix_length = value.ipv6_prefix_length};
      if (previous_primary) {
        selected.primary_preference = previous_primary->primary_preference;
        selected.tag = previous_primary->tag;
        selected.duplicate_address_detection =
            previous_primary->duplicate_address_detection;
        selected.tag_configured = previous_primary->tag_configured;
      }
      addresses.push_back(selected);
    }
    if (next_address_table.program(addresses) !=
        RouterIpv6AddressProgramStatus::accepted)
      return false;
  } catch (const std::bad_alloc &) {
    return false;
  }

  ports_[value.ordinal] = value;
  configure_ipv6_reachable_time(value, previous, Clock::now());
  if (!previous.configured ||
      previous.icmp_redirects_enabled != value.icmp_redirects_enabled ||
      previous.icmp_redirect_maximum != value.icmp_redirect_maximum ||
      previous.icmp_redirect_interval_seconds !=
          value.icmp_redirect_interval_seconds)
    ipv4_redirect_limiters_[value.ordinal] = {};
  if (!previous.configured ||
      previous.icmp6_redirects_enabled != value.icmp6_redirects_enabled ||
      previous.icmp6_redirect_maximum != value.icmp6_redirect_maximum ||
      previous.icmp6_redirect_interval_seconds !=
          value.icmp6_redirect_interval_seconds)
    ipv6_redirect_limiters_[value.ordinal] = {};
  const bool path_identity_changed =
      previous.configured &&
      (previous.mtu != value.mtu || previous.mac != value.mac ||
       previous.ipv4_configured != value.ipv4_configured ||
       previous.address != value.address ||
       previous.prefix_length != value.prefix_length ||
       previous.ipv6_address != value.ipv6_address ||
       previous.ipv6_link_local != value.ipv6_link_local);
  if (path_identity_changed) {
    ipv4_path_mtu_.remove_interface(physical_interface_id(value.ordinal));
    ipv6_path_mtu_.remove_interface(physical_interface_id(value.ordinal));
    if (ipv4_probe_valid_ && ipv4_probe_port_ordinal_ == value.ordinal)
      ipv4_probe_valid_ = false;
    if (ipv6_probe_valid_ && ipv6_probe_port_ordinal_ == value.ordinal) {
      ipv6_probe_valid_ = false;
      ipv6_probe_packet_count_ = 0U;
    }
  }
  const bool dad_identity_changed =
      !previous.configured || !previous.ipv6_configured ||
      previous.ipv6_address != value.ipv6_address ||
      previous.ipv6_link_local != value.ipv6_link_local;
  if (!value.ipv6_configured || !value.operational || dad_identity_changed)
    ipv6_dad_.remove_interface(physical_interface_id(value.ordinal));
  if (previous.ipv6_configured && !value.ipv6_configured) {
    // Every neighbor entry is scoped to this IPv6 interface. Keeping either a
    // dynamic or configured entry after the address-family child is removed
    // would allow a later interface generation to inherit stale adjacency.
    ipv6_neighbors_.remove_interface(physical_interface_id(value.ordinal));
    ipv6_path_mtu_.remove_interface(physical_interface_id(value.ordinal));
  }
  if (value.ipv6_configured && value.operational) {
    const auto now = Clock::now();
    // A control-only leaf change, including Redirect rate configuration, must
    // not restart DAD for an unchanged address generation. Reconfigure the DAD
    // owner only when identity changed or no record survived link activation.
    if (dad_identity_changed ||
        !ipv6_dad_.find(physical_interface_id(value.ordinal),
                        value.ipv6_link_local))
      static_cast<void>(ipv6_dad_.configure(
          physical_interface_id(value.ordinal), value.ordinal,
          value.ipv6_link_local, device_catalog::ipv6_dad_transmits,
          ipv6_interface_initial_delay(
              physical_interface_id(value.ordinal), value.ipv6_link_local, now,
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  device_catalog::ipv6_dad_max_initial_delay)),
          now));
    begin_global_dad_if_ready(value, now);
  }
  // The address generation was validated before any operational state changed.
  // Moving a standard-allocator vector only exchanges ownership metadata and
  // therefore cannot fail after the DAD and neighbor publication above.
  native_ipv6_addresses_ = std::move(next_address_table);
  return true;
}

RouterIpv6AddressProgramStatus RouterForwarder::program_ipv6_addresses(
    std::span<const RouterIpv6Address> addresses,
    Clock::time_point now) noexcept {
  RouterIpv6AddressTable candidate;
  const auto status = candidate.program(addresses);
  if (status != RouterIpv6AddressProgramStatus::accepted)
    return status;

  // A valid value record is not sufficient to establish hardware ownership.
  // Cross-check stable interface identity and configured carrier before any
  // DAD or selected-primary state is touched.
  for (const auto &address : candidate.records()) {
    if (address.port_ordinal >= ports_.size() ||
        !ports_[address.port_ordinal].configured ||
        physical_interface_id(address.port_ordinal) != address.interface_id)
      return RouterIpv6AddressProgramStatus::invalid_record;
  }

  // DAD contains a profile-sized fixed arena. Keep its transaction on the heap
  // so a legal maximum-port router cannot exhaust the 1 MiB Wasm thread stack.
  std::unique_ptr<Ipv6DadTable> candidate_dad;
  try {
    candidate_dad = std::make_unique<Ipv6DadTable>(ipv6_dad_);
  } catch (const std::bad_alloc &) {
    return RouterIpv6AddressProgramStatus::resource_exhausted;
  }
  for (const auto &old : native_ipv6_addresses_.records())
    if (!candidate.find(old.interface_id, old.address))
      candidate_dad->remove(old.interface_id, old.address);
  for (const auto &address : candidate.records()) {
    const auto &port = ports_[address.port_ordinal];
    if (!port.operational ||
        !candidate_dad->preferred(address.interface_id, port.ipv6_link_local) ||
        candidate_dad->find(address.interface_id, address.address))
      continue;
    const auto transmits = address.duplicate_address_detection
                               ? device_catalog::ipv6_dad_transmits
                               : std::uint8_t{0U};
    if (!candidate_dad->configure(
            address.interface_id, address.port_ordinal, address.address,
            transmits,
            transmits == 0U
                ? std::chrono::nanoseconds::zero()
                : ipv6_interface_initial_delay(
                      address.interface_id, address.address, now,
                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                          device_catalog::ipv6_dad_max_initial_delay)),
            now))
      return RouterIpv6AddressProgramStatus::too_many_addresses;
  }

  // Port fields remain an immutable selected-primary cache for code that also
  // needs MAC, MTU and carrier. The address table is the only complete source
  // of configured native addresses and owns every secondary address.
  for (auto &port : ports_) {
    if (!port.configured)
      continue;
    const auto interface_id = physical_interface_id(port.ordinal);
    const auto *primary = candidate.primary(interface_id);
    port.ipv6_configured = primary != nullptr;
    if (primary) {
      port.ipv6_address = primary->address;
      port.ipv6_network = primary->network;
      port.ipv6_prefix_length = primary->prefix_length;
    } else {
      port.ipv6_address = {};
      port.ipv6_network = {};
      port.ipv6_prefix_length = 0U;
      candidate_dad->remove_interface(interface_id);
    }
  }
  native_ipv6_addresses_ = std::move(candidate);
  ipv6_dad_ = *candidate_dad;
  return RouterIpv6AddressProgramStatus::accepted;
}

service::SapProgramStatus RouterForwarder::program_sap_generation(
    std::span<const service::SapAttachment> attachments,
    std::span<const service::ServiceIpv6Interface> interfaces) noexcept {
  // Cross-check physical ownership before asking the table to allocate and
  // sort a candidate. A SAP on an absent inventory port must never become a
  // packet classifier merely because its ordinal fits the generated arena.
  for (const auto &attachment : attachments) {
    const auto ordinal = attachment.sap.port.ordinal;
    if (ordinal >= ports_.size() || !ports_[ordinal].configured)
      return service::SapProgramStatus::invalid_attachment;
  }
  for (const auto &interface : interfaces)
    if (interface.physical_port_ordinal >= ports_.size() ||
        !ports_[interface.physical_port_ordinal].configured)
      return service::SapProgramStatus::invalid_interface;
  try {
    auto candidate_table = std::make_unique<service::SapForwardingTable>();
    const auto status = candidate_table->replace(attachments, interfaces);
    if (status != service::SapProgramStatus::accepted)
      return status;
    auto candidate_dad = std::make_unique<Ipv6DadTable>(ipv6_dad_);

    // Only identity and operational withdrawal invalidate RFC 4007 state.
    // Changing a timer, Redirect rate or admission threshold on the same L3
    // interface must not restart DAD or discard a reachable neighbor. MTU is
    // handled separately because it invalidates PMTU without changing address
    // ownership.
    const auto identity_changed = [](const auto &old,
                                     const auto *replacement) noexcept {
      return !replacement ||
             old.physical_port_ordinal != replacement->physical_port_ordinal ||
             old.mac != replacement->mac ||
             old.address != replacement->address ||
             old.network != replacement->network ||
             old.link_local != replacement->link_local ||
             old.prefix_length != replacement->prefix_length ||
             old.configured != replacement->configured ||
             (old.operational && !replacement->operational);
    };

    // Remove a deleted or changed interface only from the private DAD image.
    // An unchanged projection retains its probe progress and duplicate state.
    for (const auto &old : sap_forwarding_.interfaces()) {
      const auto replacement =
          candidate_table->find_interface(old.interface_id);
      if (identity_changed(old, replacement))
        candidate_dad->remove_interface(old.interface_id);
    }
    const auto now = Clock::now();
    for (const auto &interface : interfaces) {
      const auto *physical = port(interface.physical_port_ordinal);
      if (!interface.operational || !physical || !physical->operational)
        continue;
      const auto initial_delay = [&](const packet::Ipv6 &address) {
        return ipv6_interface_initial_delay(
            interface.interface_id, address, now,
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                device_catalog::ipv6_dad_max_initial_delay));
      };
      if ((!candidate_dad->find(interface.interface_id, interface.link_local) &&
           !candidate_dad->configure(
               interface.interface_id, interface.physical_port_ordinal,
               interface.link_local, device_catalog::ipv6_dad_transmits,
               initial_delay(interface.link_local), now)) ||
          (!candidate_dad->find(interface.interface_id, interface.address) &&
           !candidate_dad->configure(
               interface.interface_id, interface.physical_port_ordinal,
               interface.address, device_catalog::ipv6_dad_transmits,
               initial_delay(interface.address), now)))
        return service::SapProgramStatus::resource_exhausted;
    }
    // Validation and every fallible DAD insertion have completed. Operational
    // state can now be withdrawn without risking a partial configuration
    // commit. These owner-local removals are allocation-free and ensure that a
    // checkpoint never contains ND, PMTU or queued frames keyed by an obsolete
    // service-interface generation.
    for (const auto &old : sap_forwarding_.interfaces()) {
      const auto replacement =
          candidate_table->find_interface(old.interface_id);
      const bool changed = identity_changed(old, replacement);
      if (changed) {
        ipv6_neighbors_.remove_interface(old.interface_id);
        for (auto &pending : pending_)
          if (pending.valid && pending.ipv6 &&
              pending.interface_id == old.interface_id) {
            pending = {};
            drop(ForwardDrop::port_down);
          }
        if (ipv6_probe_valid_ && ipv6_probe_interface_id_ == old.interface_id) {
          ipv6_probe_valid_ = false;
          ipv6_probe_packet_count_ = 0U;
        }
      }
      if (changed || (replacement && old.mtu != replacement->mtu))
        ipv6_path_mtu_.remove_interface(old.interface_id);
    }

    // Both moves are non-throwing vector and fixed-arena ownership transfers.
    // No packet turn can run between them because this forwarding shard is the
    // sole caller and processes one command to completion.
    sap_forwarding_ = std::move(*candidate_table);
    ipv6_dad_ = std::move(*candidate_dad);
    return service::SapProgramStatus::accepted;
  } catch (const std::bad_alloc &) {
    return service::SapProgramStatus::resource_exhausted;
  }
}

dhcpv6::RelayConfigStatus RouterForwarder::configure_dhcpv6_relay(
    dhcpv6::RelayInterfaceConfig configuration) noexcept {
  if (configuration.interface_id == 0U)
    return dhcpv6::RelayConfigStatus::invalid_interface;
  const auto logical_interface_id = configuration.interface_id;
  const auto physical_port_ordinal = configuration.physical_port_ordinal;
  auto configured_interface =
      ipv6_interface(logical_interface_id, physical_port_ordinal);
  if (!configured_interface) {
    // The compatibility API creates its logical relay identity and child in
    // one transaction, so that identity cannot be found in the old relay
    // generation yet. Falling back here is limited to the explicitly supplied
    // physical port and still requires a configured native IPv6 interface.
    // Packet processing never performs this fallback after publication.
    const auto *physical = port(physical_port_ordinal);
    if (physical && physical->ipv6_configured)
      configured_interface = *physical;
  }
  const auto *configured_port =
      configured_interface ? &*configured_interface : nullptr;
  if (!configured_port || !configured_port->ipv6_configured)
    return dhcpv6::RelayConfigStatus::invalid_interface;

  // Validate a complete replacement before binding transport. This preserves
  // the previous relay and socket if an opaque Interface-Id or server list is
  // invalid, matching candidate transaction atomicity.
  auto replacement = dhcpv6::RelayAgent{};
  auto replacement_leases = dhcpv6::RelayLeaseRepository{};
  auto replacement_routes = dhcpv6::RelayRouteRepository{};
  try {
    replacement = dhcpv6_relay_;
    replacement_leases = dhcpv6_relay_leases_;
    replacement_routes = dhcpv6_relay_routes_;
    const auto status = replacement.replace_interface(std::move(configuration));
    if (status != dhcpv6::RelayConfigStatus::accepted)
      return status;
    const auto policies = relay_lease_policies(replacement.interfaces());
    if (!replacement_leases.configure(policies))
      return dhcpv6::RelayConfigStatus::resource_exhausted;
    if (!replacement_routes.configure(replacement.interfaces()) ||
        !replacement_routes.rebuild(replacement_leases.leases(),
                                    replacement.interfaces()))
      return dhcpv6::RelayConfigStatus::resource_exhausted;
    std::size_t neighbor_capacity{};
    std::size_t lease_capacity{};
    for (const auto &policy : policies)
      if (policy.neighbor_resolution)
        neighbor_capacity += policy.maximum_leases;
    for (const auto &policy : policies)
      lease_capacity += policy.maximum_leases;
    const auto bounded_neighbor_capacity = std::min(
        neighbor_capacity, device_catalog::ipv6_neighbor_entries_per_router);
    dhcpv6_neighbor_edits_.reserve(bounded_neighbor_capacity * 2U);
    dhcpv6_clear_scratch_.reserve(lease_capacity);
  } catch (const std::bad_alloc &) {
    return dhcpv6::RelayConfigStatus::resource_exhausted;
  }

  auto socket = dhcpv6_relay_socket_;
  if (!socket) {
    socket = udp_.bind({.family = transport::IpFamily::ipv6,
                        .interface_id = 0U,
                        .port = packet::dhcpv6::server_port});
    if (!socket)
      return dhcpv6::RelayConfigStatus::transport_unavailable;
  }
  // The full IES publisher has already created DAD for a service interface.
  // The compatibility API reaches the same logical view by borrowing its
  // native port values. In both cases this guard only fills missing DAD rows;
  // it never aliases the logical scope back to the physical port identity.
  const auto now = Clock::now();
  const bool had_link_local =
      ipv6_dad_.find(logical_interface_id, configured_port->ipv6_link_local)
          .has_value();
  if (!had_link_local &&
      !ipv6_dad_.configure(
          logical_interface_id, physical_port_ordinal,
          configured_port->ipv6_link_local, device_catalog::ipv6_dad_transmits,
          ipv6_interface_initial_delay(
              logical_interface_id, configured_port->ipv6_link_local, now,
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  device_catalog::ipv6_dad_max_initial_delay)),
          now))
    return dhcpv6::RelayConfigStatus::resource_exhausted;
  const bool had_global =
      ipv6_dad_.find(logical_interface_id, configured_port->ipv6_address)
          .has_value();
  if (!had_global &&
      !ipv6_dad_.configure(
          logical_interface_id, physical_port_ordinal,
          configured_port->ipv6_address, device_catalog::ipv6_dad_transmits,
          ipv6_interface_initial_delay(
              logical_interface_id, configured_port->ipv6_address, now,
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  device_catalog::ipv6_dad_max_initial_delay)),
          now)) {
    if (!had_link_local)
      ipv6_dad_.remove(logical_interface_id, configured_port->ipv6_link_local);
    return dhcpv6::RelayConfigStatus::resource_exhausted;
  }
  dhcpv6_relay_ = std::move(replacement);
  dhcpv6_relay_leases_ = std::move(replacement_leases);
  dhcpv6_relay_routes_ = std::move(replacement_routes);
  dhcpv6_relay_socket_ = socket;
  return dhcpv6::RelayConfigStatus::accepted;
}

bool RouterForwarder::remove_dhcpv6_relay(
    std::uint64_t logical_interface_id) noexcept {
  dhcpv6::RelayAgent replacement_relay;
  dhcpv6::RelayLeaseRepository replacement_leases;
  dhcpv6::RelayRouteRepository replacement_routes;
  try {
    // Stage the complete relay and lease generations first. An allocator
    // failure therefore leaves live protocol forwarding and derived state
    // untouched instead of removing only half of an IES child.
    replacement_relay = dhcpv6_relay_;
    replacement_leases = dhcpv6_relay_leases_;
    if (!replacement_relay.remove_interface(logical_interface_id))
      return false;
    const auto staged_removals =
        replacement_leases.prepare_remove_interface(logical_interface_id);
    if (!staged_removals.empty() && !replacement_leases.commit_prepared())
      return false;
    const auto policies = relay_lease_policies(replacement_relay.interfaces());
    if (!replacement_leases.configure(policies))
      return false;
    if (!replacement_routes.configure(replacement_relay.interfaces()) ||
        !replacement_routes.rebuild(replacement_leases.leases(),
                                    replacement_relay.interfaces()))
      return false;
  } catch (const std::bad_alloc &) {
    return false;
  }
  const auto removals =
      dhcpv6_relay_leases_.prepare_remove_interface(logical_interface_id);
  for (const auto &mutation : removals) {
    const auto &lease = mutation.record;
    if (lease.has_client_mac &&
        (lease.protocol == dhcpv6::RelayLeaseProtocol::non_temporary ||
         lease.protocol == dhcpv6::RelayLeaseProtocol::temporary))
      static_cast<void>(
          ipv6_neighbors_.clear_dynamic(logical_interface_id, lease.value));
  }
  dhcpv6_relay_ = std::move(replacement_relay);
  dhcpv6_relay_leases_ = std::move(replacement_leases);
  dhcpv6_relay_routes_ = std::move(replacement_routes);
  if (!sap_forwarding_.find_interface(logical_interface_id)) {
    // Only the compatibility API couples relay and interface lifecycle. A
    // real IES interface remains routable after its relay child is deleted,
    // so its DAD, Neighbor Cache, PMTU and queued packets stay with the SAP
    // generation owner.
    ipv6_dad_.remove_interface(logical_interface_id);
    ipv6_neighbors_.remove_interface(logical_interface_id);
    ipv6_path_mtu_.remove_interface(logical_interface_id);
    for (auto &entry : pending_)
      if (entry.valid && entry.ipv6 &&
          entry.interface_id == logical_interface_id)
        entry = {};
  }
  if (dhcpv6_relay_.interface_count() == 0U && dhcpv6_relay_socket_) {
    static_cast<void>(udp_.close(*dhcpv6_relay_socket_));
    dhcpv6_relay_socket_.reset();
  }
  return true;
}

bool RouterForwarder::clear_dhcpv6_relay_leases(
    const dhcpv6::RelayLeaseClearFilter &filter, bool no_dhcp_release,
    void *context, EgressSink sink, EgressAdmission admission,
    Clock::time_point now) noexcept {
  const auto selected = dhcpv6_relay_leases_.prepare_clear(filter);
  if (selected.empty())
    return dhcpv6_relay_.interface(filter.interface_id) != nullptr;

  // The clear command must retain the lease identities after their live rows
  // are removed. Configuration and restore pre-reserve this vector to the
  // admitted lease capacity; refusing an unexpected short arena is safer than
  // partially withdrawing a batch inside a noexcept shard command.
  if (selected.size() > dhcpv6_clear_scratch_.capacity()) {
    dhcpv6_relay_leases_.discard_prepared();
    return false;
  }
  dhcpv6_clear_scratch_.assign(selected.size(), {});
  std::transform(selected.begin(), selected.end(),
                 dhcpv6_clear_scratch_.begin(),
                 [](const auto &mutation) { return mutation.record; });

  if (!dhcpv6_relay_routes_.prepare(selected, dhcpv6_relay_.interfaces())) {
    dhcpv6_relay_leases_.discard_prepared();
    return false;
  }
  dhcpv6_neighbor_edits_.clear();
  for (const auto &mutation : selected) {
    const auto &lease = mutation.record;
    const auto *relay = dhcpv6_relay_.interface(lease.interface_id);
    const bool address_lease =
        lease.protocol == dhcpv6::RelayLeaseProtocol::non_temporary ||
        lease.protocol == dhcpv6::RelayLeaseProtocol::temporary;
    if (relay && relay->neighbor_resolution && address_lease &&
        lease.has_client_mac && ip::contains(relay->client_prefix, lease.value))
      dhcpv6_neighbor_edits_.push_back(
          {.kind = Ipv6NeighborBatchKind::remove_dynamic,
           .interface_id = lease.interface_id,
           .address = lease.value});
  }
  if (!ipv6_neighbors_.apply_batch(dhcpv6_neighbor_edits_, now) ||
      !dhcpv6_relay_routes_.commit_prepared() ||
      !dhcpv6_relay_leases_.commit_prepared()) {
    // Route and lease commit are allocation-free after their prepare phases.
    // Reaching this branch is an invariant failure; no success is reported.
    dhcpv6_relay_routes_.discard_prepared();
    dhcpv6_relay_leases_.discard_prepared();
    return false;
  }

  constexpr auto release_threshold = std::chrono::minutes{5};
  for (const auto &lease : dhcpv6_clear_scratch_) {
    if (no_dhcp_release || (lease.valid_until != Clock::time_point::max() &&
                            lease.valid_until - now < release_threshold))
      continue;
    const auto *relay = dhcpv6_relay_.interface(lease.interface_id);
    if (!relay)
      continue;

    auto writer = packet::dhcpv6::begin_client_server(
        dhcpv6_relay_scratch_,
        static_cast<std::uint8_t>(packet::dhcpv6::MessageType::release),
        dhcpv6_release_transaction_id(lease, now));
    const auto client_duid =
        std::span<const std::uint8_t>{lease.client.duid}.first(
            lease.client.duid_octets);
    const auto server_duid =
        std::span<const std::uint8_t>{lease.server.duid}.first(
            lease.server.duid_octets);
    constexpr std::array<std::uint8_t, 2U> initial_elapsed_time{};
    if (!writer ||
        !writer->append(static_cast<std::uint16_t>(
                            packet::dhcpv6::OptionCode::client_identifier),
                        client_duid) ||
        !writer->append(static_cast<std::uint16_t>(
                            packet::dhcpv6::OptionCode::server_identifier),
                        server_duid) ||
        !writer->append(static_cast<std::uint16_t>(
                            packet::dhcpv6::OptionCode::elapsed_time),
                        initial_elapsed_time)) {
      drop(ForwardDrop::malformed);
      continue;
    }

    std::array<std::uint8_t, 64U> resource{};
    std::optional<std::size_t> resource_octets;
    packet::dhcpv6::OptionCode resource_code;
    const auto preferred = dhcpv6_remaining_seconds(lease.preferred_until, now);
    const auto valid = dhcpv6_remaining_seconds(lease.valid_until, now);
    if (lease.protocol == dhcpv6::RelayLeaseProtocol::delegated_prefix) {
      resource_code = packet::dhcpv6::OptionCode::ia_prefix;
      resource_octets = packet::dhcpv6::encode_ia_prefix(
          resource, lease.value, lease.prefix_length, preferred, valid);
    } else {
      resource_code = packet::dhcpv6::OptionCode::ia_address;
      resource_octets = packet::dhcpv6::encode_ia_address(resource, lease.value,
                                                          preferred, valid);
    }
    std::array<std::uint8_t, 96U> association{};
    const bool temporary =
        lease.protocol == dhcpv6::RelayLeaseProtocol::temporary;
    const std::size_t association_header = temporary ? 4U : 12U;
    write_dhcpv6_u32(association, 0U, lease.client.iaid);
    if (!temporary) {
      // T1 and T2 are client scheduling fields. They are zero in this
      // operator-generated Release; the server keys the selected resource
      // from the nested IA value and ignores client lifetime hints.
      write_dhcpv6_u32(association, 4U, 0U);
      write_dhcpv6_u32(association, 8U, 0U);
    }
    auto association_octets = association_header;
    if (!resource_octets ||
        !append_dhcpv6_nested(
            association, association_octets, resource_code,
            std::span<const std::uint8_t>{resource}.first(*resource_octets))) {
      drop(ForwardDrop::malformed);
      continue;
    }
    const auto association_code =
        lease.protocol == dhcpv6::RelayLeaseProtocol::delegated_prefix
            ? packet::dhcpv6::OptionCode::ia_pd
        : temporary ? packet::dhcpv6::OptionCode::ia_ta
                    : packet::dhcpv6::OptionCode::ia_na;
    if (!writer->append(static_cast<std::uint16_t>(association_code),
                        std::span<const std::uint8_t>{association}.first(
                            association_octets))) {
      drop(ForwardDrop::malformed);
      continue;
    }

    const auto encapsulated = dhcpv6::encapsulate_relay_forward(
        writer->view(), lease.peer_address, relay->link_address,
        relay->relay_interface_id, dhcpv6_release_relay_scratch_);
    if (encapsulated.status != dhcpv6::RelayStatus::forwarded) {
      drop(ForwardDrop::malformed);
      continue;
    }
    const dhcpv6::RelayDecision decision{
        .status = dhcpv6::RelayDecisionStatus::forward_upstream,
        .payload_octets = encapsulated.message_octets,
        .source_address = relay->source_address,
        .has_source_address = relay->has_source_address,
        .source_port = packet::dhcpv6::server_port,
        .destination_port = packet::dhcpv6::server_port};
    const dhcpv6::RelayDestination destination{
        .address = lease.server_address,
        .scope_interface_id = ip::is_link_local(lease.server_address)
                                  ? lease.server_scope_interface_id
                                  : 0U};
    // The operator state is already gone, matching Nokia's clear semantics.
    // Release delivery is best effort: route, ND and queue failures remain
    // visible as ordinary forwarding drops rather than resurrecting a lease.
    static_cast<void>(originate_dhcpv6_relay(
        decision, destination,
        std::span<const std::uint8_t>{dhcpv6_release_relay_scratch_}.first(
            encapsulated.message_octets),
        context, sink, admission, now));
  }
  dhcpv6_clear_scratch_.clear();
  return true;
}

void RouterForwarder::remove_port(std::uint16_t ordinal) noexcept {
  if (ordinal >= ports_.size())
    return;
  // A physical removal withdraws all service relays sharing that port. Find
  // one stable scalar at a time because removal invalidates vector iterators.
  // This noexcept hardware path performs no allocation under memory pressure.
  for (;;) {
    std::uint64_t attached{};
    for (const auto &relay : dhcpv6_relay_.interfaces())
      if (relay.physical_port_ordinal == ordinal) {
        attached = relay.interface_id;
        break;
      }
    if (attached == 0U)
      break;
    static_cast<void>(remove_dhcpv6_relay(attached));
  }
  // A physical removal invalidates every SAP on that port in the same owner
  // turn. Leaving the classifier alive would let a later reused ordinal inherit
  // another card generation's customer attachment.
  sap_forwarding_.remove_physical_port(ordinal);
  native_ipv6_addresses_.remove_physical_port(ordinal);
  ports_[ordinal] = {};
  ipv6_reachable_times_[ordinal] = {};
  ipv6_redirect_limiters_[ordinal] = {};
  ipv4_redirect_limiters_[ordinal] = {};
  // Interface statistics cease to exist with the interface. Global counters
  // remain monotonic until an explicit SR OS clear global/all operation.
  icmpv6_interface_statistics_[ordinal] = {};
  icmpv4_interface_statistics_[ordinal] = {};
  icmpv6_transmit_times_[ordinal] = {};
  // Removing physical inventory invalidates local adjacencies and queued work.
  // It never rewrites another port or another router's state.
  for (auto &entry : adjacencies_)
    if (entry.valid && entry.port_ordinal == ordinal)
      entry = {};
  ipv6_neighbors_.remove_interface(physical_interface_id(ordinal));
  ipv6_dad_.remove_physical_port(ordinal);
  ipv6_router_advertisements_.remove(ordinal);
  ipv4_path_mtu_.remove_interface(physical_interface_id(ordinal));
  ipv6_path_mtu_.remove_interface(physical_interface_id(ordinal));
  if (ipv4_probe_valid_ && ipv4_probe_port_ordinal_ == ordinal)
    ipv4_probe_valid_ = false;
  if (ipv6_probe_valid_ && ipv6_probe_port_ordinal_ == ordinal) {
    ipv6_probe_valid_ = false;
    ipv6_probe_packet_count_ = 0U;
  }
  std::erase_if(mld_interfaces_, [&](const auto &entry) {
    return entry.intent.port_ordinal == ordinal;
  });
  for (auto &entry : pending_)
    if (entry.valid && entry.port_ordinal == ordinal) {
      entry = {};
      drop(ForwardDrop::port_down);
    }
}

bool RouterForwarder::configure_router_advertisement(
    std::uint16_t port_ordinal, bool enabled,
    const packet::nd::RouterAdvertisementConfig &config,
    Clock::time_point now) noexcept {
  const auto *target = port(port_ordinal);
  // Control intent is accepted while DAD or carrier convergence is pending.
  // The timer activates only after forwarding-owned link-local state becomes
  // preferred, so no tentative address can source an advertisement.
  if (!target || !target->ipv6_configured)
    return false;
  return ipv6_router_advertisements_.configure(
      port_ordinal, enabled, config, now,
      target->operational &&
          ipv6_dad_.preferred(physical_interface_id(port_ordinal),
                              target->ipv6_link_local));
}

bool RouterForwarder::remove_router_advertisement(
    std::uint16_t port_ordinal) noexcept {
  // An absent port ordinal is rejected rather than interpreted as an
  // idempotent success. Control can consequently distinguish stale inventory
  // coordinates from a removal that reached the intended forwarding owner.
  if (port_ordinal >= ports_.size())
    return false;
  ipv6_router_advertisements_.remove(port_ordinal);
  return true;
}

bool RouterForwarder::install_static_ipv6_neighbor(std::uint16_t port_ordinal,
                                                   const packet::Ipv6 &address,
                                                   packet::Mac mac) noexcept {
  const auto *target = port(port_ordinal);
  // A configured neighbor belongs to an IPv6 interface, not merely to an
  // inventory port. Reject multicast and unspecified keys before they can
  // consume the bounded cache or influence next-hop resolution.
  if (!target || !target->ipv6_configured || ip::is_unspecified(address) ||
      ip::is_multicast(address))
    return false;
  return ipv6_neighbors_.install_static(physical_interface_id(port_ordinal),
                                        address, mac);
}

bool RouterForwarder::remove_static_ipv6_neighbor(
    std::uint16_t port_ordinal, const packet::Ipv6 &address) noexcept {
  const auto *target = port(port_ordinal);
  if (!target || !target->ipv6_configured || ip::is_unspecified(address) ||
      ip::is_multicast(address))
    return false;
  return ipv6_neighbors_.remove_static(physical_interface_id(port_ordinal),
                                       address);
}

bool RouterForwarder::install_static_ipv4_neighbor(std::uint16_t port_ordinal,
                                                   std::uint32_t address,
                                                   packet::Mac mac) noexcept {
  const auto *target_port = port(port_ordinal);
  if (!target_port || !target_port->ipv4_configured || address == 0U ||
      address == 0xffffffffU || !usable_sender_mac(mac))
    return false;

  // SR OS accepts a static ARP only on the attached network. The prefix
  // comparison also rejects the interface's subnet-directed broadcast and,
  // for ordinary prefixes, its network identifier as unusable neighbor keys.
  const auto prefix_length = target_port->prefix_length;
  const auto mask = prefix_length == 0U
                        ? 0U
                        : std::numeric_limits<std::uint32_t>::max()
                              << (32U - prefix_length);
  const auto network = target_port->address & mask;
  const auto directed_broadcast = network | ~mask;
  const bool has_broadcast_addresses = prefix_length <= 30U;
  if ((address & mask) != network ||
      (has_broadcast_addresses &&
       (address == network || address == directed_broadcast)) ||
      address == target_port->address)
    return false;

  Adjacency *free_slot{};
  for (auto &entry : adjacencies_) {
    if (entry.valid && entry.port_ordinal == port_ordinal &&
        entry.address == address) {
      // The documented replacement rule applies equally when the previous
      // row was dynamically learned or an older configured MAC.
      entry = {.valid = true,
               .port_ordinal = port_ordinal,
               .address = address,
               .mac = mac,
               .expires = Clock::time_point::max(),
               .aging_disabled = true,
               .configured_static = true};
      return true;
    }
    if (!entry.valid && !free_slot)
      free_slot = &entry;
  }
  if (!free_slot)
    return false;
  *free_slot = {.valid = true,
                .port_ordinal = port_ordinal,
                .address = address,
                .mac = mac,
                .expires = Clock::time_point::max(),
                .aging_disabled = true,
                .configured_static = true};
  return true;
}

bool RouterForwarder::remove_static_ipv4_neighbor(
    std::uint16_t port_ordinal, std::uint32_t address) noexcept {
  const auto *target_port = port(port_ordinal);
  if (!target_port || !target_port->ipv4_configured || address == 0U ||
      address == 0xffffffffU)
    return false;
  for (auto &entry : adjacencies_)
    if (entry.valid && entry.configured_static &&
        entry.port_ordinal == port_ordinal && entry.address == address) {
      entry = {};
      return true;
    }
  return false;
}

bool RouterForwarder::clear_dynamic_ipv4_neighbors(
    std::optional<std::uint16_t> port_ordinal,
    std::optional<std::uint32_t> address) noexcept {
  if (port_ordinal &&
      (!port(*port_ordinal) || !port(*port_ordinal)->ipv4_configured))
    return false;
  if (address && (*address == 0U || *address == 0xffffffffU))
    return false;

  // Operational clear affects only learned state. A configured mapping is
  // removed by its configuration command, never by `clear router arp`.
  for (auto &entry : adjacencies_)
    if (entry.valid && !entry.configured_static &&
        (!port_ordinal || entry.port_ordinal == *port_ordinal) &&
        (!address || entry.address == *address))
      entry = {};
  return true;
}

bool RouterForwarder::clear_dynamic_ipv6_neighbors(
    std::optional<std::uint16_t> port_ordinal,
    std::optional<packet::Ipv6> address) noexcept {
  if (port_ordinal &&
      (!port(*port_ordinal) || !port(*port_ordinal)->ipv6_configured))
    return false;
  if (address && (ip::is_unspecified(*address) || ip::is_multicast(*address)))
    return false;
  // SR OS reset commands are idempotent. A valid selector that currently
  // matches no dynamic entry is still accepted, while malformed addresses and
  // interfaces without IPv6 are rejected above. The cache count is therefore
  // deliberately not converted into command success.
  const auto interface_id =
      port_ordinal
          ? std::optional<std::uint64_t>{physical_interface_id(*port_ordinal)}
          : std::nullopt;
  static_cast<void>(ipv6_neighbors_.clear_dynamic(interface_id, address));
  return true;
}

RouterForwarder::MldPortState *
RouterForwarder::mld(std::uint16_t port_ordinal) noexcept {
  const auto found = std::find_if(
      mld_interfaces_.begin(), mld_interfaces_.end(), [&](const auto &entry) {
        return entry.intent.port_ordinal == port_ordinal;
      });
  return found == mld_interfaces_.end() ? nullptr : &*found;
}

const RouterForwarder::MldPortState *
RouterForwarder::mld(std::uint16_t port_ordinal) const noexcept {
  const auto found = std::find_if(
      mld_interfaces_.begin(), mld_interfaces_.end(), [&](const auto &entry) {
        return entry.intent.port_ordinal == port_ordinal;
      });
  return found == mld_interfaces_.end() ? nullptr : &*found;
}

bool RouterForwarder::configure_mld_interface(
    const MldRouterConfiguration &configuration,
    Clock::time_point now) noexcept {
  const auto *target = port(configuration.port_ordinal);
  if (!target || !target->ipv6_configured ||
      configuration.link_local_address != target->ipv6_link_local)
    return false;
  auto *state = mld(configuration.port_ordinal);
  if (!state) {
    if (mld_interfaces_.size() == device_catalog::maximum_ports_per_router)
      return false;
    mld_interfaces_.emplace_back();
    state = &mld_interfaces_.back();
  }
  const bool ready = configuration.enabled && target->operational &&
                     ipv6_dad_.preferred(physical_interface_id(target->ordinal),
                                         target->ipv6_link_local);
  auto effective = configuration;
  effective.enabled = ready;
  // MldRouterInterface validates the entire tuple before mutation. The intent
  // is replaced only after its effective protocol projection is accepted.
  if (!state->protocol.configure(effective, now))
    return false;
  state->intent = configuration;
  state->running = ready;
  return true;
}

bool RouterForwarder::remove_mld_interface(
    std::uint16_t port_ordinal) noexcept {
  const auto found = std::find_if(
      mld_interfaces_.begin(), mld_interfaces_.end(), [&](const auto &entry) {
        return entry.intent.port_ordinal == port_ordinal;
      });
  if (found == mld_interfaces_.end())
    return false;
  mld_interfaces_.erase(found);
  return true;
}

bool RouterForwarder::clear_mld_database(
    std::uint16_t port_ordinal,
    const std::optional<packet::Ipv6> &group) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  state->protocol.clear_database(group);
  return true;
}

void RouterForwarder::clear_mld_database_all() noexcept {
  // One forwarding-owner turn clears every interface. This avoids a partial
  // router-wide clear if a bounded mailbox fills between per-interface RPCs.
  for (auto &state : mld_interfaces_)
    state.protocol.clear_database();
}

bool RouterForwarder::clear_mld_version(std::uint16_t port_ordinal) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  state->protocol.clear_older_host_compatibility();
  return true;
}

bool RouterForwarder::clear_mld_statistics(
    std::uint16_t port_ordinal) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  // Clearing statistics cannot disturb learned listeners, querier timers or
  // static configuration. The protocol owner replaces only its counter set.
  state->protocol.clear_statistics();
  return true;
}

void RouterForwarder::clear_mld_statistics_all() noexcept {
  for (auto &state : mld_interfaces_)
    state.protocol.clear_statistics();
}

bool RouterForwarder::edit_mld_static(std::uint16_t port_ordinal,
                                      MldStaticOperation operation,
                                      const packet::Ipv6 &group,
                                      const packet::Ipv6 &source) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  // One enum crosses the shard boundary, but each branch still invokes the
  // protocol owner's typed operation. This keeps CLI semantics out of the
  // forwarding module and prevents a boolean tuple from becoming ambiguous.
  switch (operation) {
  case MldStaticOperation::create_group:
    return state->protocol.configure_static_group(group);
  case MldStaticOperation::add_starg:
    return state->protocol.configure_static_starg(group);
  case MldStaticOperation::add_source:
    return state->protocol.configure_static_source(group, source);
  case MldStaticOperation::remove_group:
    return state->protocol.remove_static_group(group);
  case MldStaticOperation::remove_starg:
    return state->protocol.remove_static_starg(group);
  case MldStaticOperation::remove_source:
    return state->protocol.remove_static_source(group, source);
  }
  return false;
}

bool RouterForwarder::program_mld_ssm_translation(
    std::uint16_t port_ordinal, MldSsmProgramOperation operation,
    const MldSsmTranslation &translation,
    std::uint32_t expected_entries) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;

  switch (operation) {
  case MldSsmProgramOperation::begin:
    // One effective interface program cannot create more simultaneous (S,G)
    // pairs than the generated router owner can represent. The control owner
    // retains its candidate if this cold-path allocation cannot be staged.
    if (state->translation_staging ||
        expected_entries >
            device_catalog::mld_router_group_sources_per_interface)
      return false;
    try {
      state->staged_translations.clear();
      state->staged_translations.reserve(expected_entries);
      state->translation_scratch.reserve(std::min<std::size_t>(
          expected_entries, device_catalog::mld_router_sources_per_group));
    } catch (...) {
      state->staged_translations.clear();
      return false;
    }
    state->staged_expected_entries = expected_entries;
    state->translation_staging = true;
    return true;
  case MldSsmProgramOperation::add:
    if (!state->translation_staging ||
        state->staged_translations.size() >= state->staged_expected_entries ||
        !ip::is_multicast(translation.start) ||
        !ip::is_multicast(translation.end) ||
        translation.end < translation.start ||
        ip::is_unspecified(translation.source) ||
        ip::is_multicast(translation.source) ||
        std::find(state->staged_translations.begin(),
                  state->staged_translations.end(),
                  translation) != state->staged_translations.end())
      return false;
    try {
      state->staged_translations.push_back(translation);
    } catch (...) {
      return false;
    }
    return true;
  case MldSsmProgramOperation::commit:
    if (!state->translation_staging ||
        state->staged_translations.size() != state->staged_expected_entries)
      return false;
    state->translations.swap(state->staged_translations);
    state->staged_translations.clear();
    state->staged_expected_entries = 0U;
    state->translation_staging = false;
    return true;
  case MldSsmProgramOperation::abort:
    if (!state->translation_staging)
      return false;
    state->staged_translations.clear();
    state->staged_expected_entries = 0U;
    state->translation_staging = false;
    return true;
  }
  return false;
}

bool RouterForwarder::replace_mld_import_policy(
    std::uint16_t port_ordinal,
    std::span<const mld::ImportPolicyEntry> entries,
    mld::ImportPolicyAction default_action) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  // ImportPolicyProgram constructs and validates a replacement before
  // publishing it. The scratch reservation is also staged before the active
  // program changes, so a memory failure cannot leave policy and packet-path
  // capacity from different generations.
  try {
    std::vector<packet::Ipv6> scratch;
    scratch.reserve(device_catalog::mld_router_sources_per_group);
    if (!state->import_policy.replace(entries, default_action))
      return false;
    state->policy_source_scratch.swap(scratch);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RouterForwarder::program_mld_import_policy(
    std::uint16_t port_ordinal, mld::ImportPolicyProgramOperation operation,
    const mld::ImportPolicyEntry &entry,
    mld::ImportPolicyAction default_action,
    std::uint32_t expected_entries) noexcept {
  auto *state = mld(port_ordinal);
  if (!state)
    return false;
  switch (operation) {
  case mld::ImportPolicyProgramOperation::begin:
    if (state->import_policy_staging)
      return false;
    try {
      state->staged_import_policy.clear();
      state->staged_import_policy.reserve(expected_entries);
    } catch (const std::bad_alloc &) {
      return false;
    }
    state->staged_policy_expected_entries = expected_entries;
    state->staged_import_policy_default_action = default_action;
    state->import_policy_staging = true;
    return true;
  case mld::ImportPolicyProgramOperation::add:
    if (!state->import_policy_staging ||
        state->staged_import_policy.size() >=
            state->staged_policy_expected_entries)
      return false;
    try {
      state->staged_import_policy.push_back(entry);
    } catch (const std::bad_alloc &) {
      return false;
    }
    return true;
  case mld::ImportPolicyProgramOperation::commit:
    if (!state->import_policy_staging ||
        state->staged_import_policy.size() !=
            state->staged_policy_expected_entries)
      return false;
    // replace validates into a private vector before publication. Keeping the
    // staging generation alive until it succeeds lets the caller issue abort
    // after malformed policy or allocation failure without losing the active
    // generation.
    if (!replace_mld_import_policy(port_ordinal, state->staged_import_policy,
                                   state->staged_import_policy_default_action))
      return false;
    state->staged_import_policy.clear();
    state->staged_policy_expected_entries = 0U;
    state->import_policy_staging = false;
    return true;
  case mld::ImportPolicyProgramOperation::abort:
    if (!state->import_policy_staging)
      return false;
    state->staged_import_policy.clear();
    state->staged_policy_expected_entries = 0U;
    state->import_policy_staging = false;
    return true;
  }
  return false;
}

bool RouterForwarder::accepts_ipv6_multicast(
    const ForwardPort &port_value,
    const packet::Ipv6 &destination) const noexcept {
  if (destination == packet::nd::all_nodes_multicast ||
      destination == packet::nd::all_routers_multicast)
    return true;
  // The supplied view may represent either a native port or a SAP-backed
  // routed service. Its selected global and link-local addresses therefore
  // define the two mandatory solicited-node memberships without consulting a
  // physical-port cache. Guarding the test with ipv6_configured prevents an
  // IPv4-only interface from accidentally joining ff02::1:ff00:0 for its
  // all-zero placeholder addresses.
  if (port_value.ipv6_configured &&
      (destination ==
           ip::solicited_node_multicast(port_value.ipv6_link_local) ||
       destination == ip::solicited_node_multicast(port_value.ipv6_address)))
    return true;
  // Every tentative and assigned unicast address joins its own solicited-node
  // group. Checking only the primary cache would discard DAD and ordinary NS
  // traffic for every secondary address before the ND decoder could see it.
  const auto interface_id = physical_interface_id(port_value.ordinal);
  for (const auto &address : native_ipv6_addresses_.records())
    if (address.interface_id == interface_id &&
        destination == ip::solicited_node_multicast(address.address))
      return true;
  if (destination == packet::dhcpv6::all_relay_agents_and_servers &&
      dhcpv6_relay_.unique_on_physical_port(port_value.ordinal))
    return true;
  // An enabled multicast-router interface must receive MLDv1 Reports sent to
  // the reported group as well as MLDv2 Reports sent to ff02::16. The strict
  // ICMPv6 decoder below decides whether the accepted Ethernet multicast is a
  // control message; accepting it here does not install a multicast route.
  const auto *state = mld(port_value.ordinal);
  return state && state->running && ip::is_multicast(destination);
}

std::size_t
RouterForwarder::mld_group_count(std::uint16_t port_ordinal) const noexcept {
  const auto *state = mld(port_ordinal);
  return state && state->running ? state->protocol.group_count() : 0U;
}

RouterForwarderCheckpoint
RouterForwarder::checkpoint(Clock::time_point now) const {
  RouterForwarderCheckpoint state;
  checkpoint(state, now);
  return state;
}

void RouterForwarder::checkpoint(RouterForwarderCheckpoint &state,
                                 Clock::time_point now) const {
  // Replacement semantics make reused heap storage safe: a prior, larger
  // checkpoint cannot leave trailing records that are no longer live.
  state = {};
  state.ports.reserve(ports_.size());
  for (const auto &port : ports_)
    if (port.configured)
      state.ports.push_back(port);
  const auto native_addresses = native_ipv6_addresses_.records();
  state.native_ipv6_addresses.assign(native_addresses.begin(),
                                     native_addresses.end());
  // The returned checkpoint owns its copy. No pointer into the immutable live
  // classifier may escape the forwarding shard or outlive this owner turn.
  const auto published_saps = sap_forwarding_.attachments();
  state.sap_attachments.assign(published_saps.begin(), published_saps.end());
  const auto published_interfaces = sap_forwarding_.interfaces();
  state.service_ipv6_interfaces.assign(published_interfaces.begin(),
                                       published_interfaces.end());
  state.fib = fib_;
  state.ipv6_fib = ipv6_fib_;
  state.ipv6_neighbors = ipv6_neighbors_.checkpoint(now);
  state.ipv6_dad = ipv6_dad_.checkpoint(now);
  state.ipv6_router_advertisements =
      ipv6_router_advertisements_.checkpoint(now);
  state.ipv6_path_mtu = ipv6_path_mtu_.checkpoint(now);
  state.ipv4_path_mtu = ipv4_path_mtu_.checkpoint(now);
  state.ipv4_reassembly = ipv4_reassembly_.checkpoint(now);
  state.ipv6_reassembly = ipv6_reassembly_.checkpoint(now);
  state.udp = udp_.checkpoint();
  state.ike_udp = ike_udp_.checkpoint();
  state.dhcpv6_relay_interfaces = dhcpv6_relay_.interfaces();
  state.dhcpv6_relay_leases = dhcpv6_relay_leases_.checkpoint(now);
  state.dhcpv6_relay_routes = dhcpv6_relay_routes_.checkpoint();
  state.dhcpv6_relay_socket = dhcpv6_relay_socket_;
  state.icmpv4_global_statistics = icmpv4_global_statistics_;
  state.icmpv4_interface_statistics.reserve(state.ports.size());
  for (const auto &configured : state.ports)
    state.icmpv4_interface_statistics.push_back(
        {.port_ordinal = configured.ordinal,
         .statistics = icmpv4_interface_statistics_[configured.ordinal]});
  state.icmpv6_global_statistics = icmpv6_global_statistics_;
  state.icmpv6_interface_statistics.reserve(state.ports.size());
  for (const auto &configured : state.ports) {
    const auto &times = icmpv6_transmit_times_[configured.ordinal];
    // A negative portable duration denotes "never". Zero is reserved for an
    // event in the current owner turn and must not be conflated with absence.
    const auto ago = [now](bool present, Clock::time_point value) {
      if (!present)
        return std::int64_t{-1};
      const auto elapsed = now > value ? now - value : Clock::duration::zero();
      return std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed)
          .count();
    };
    state.icmpv6_interface_statistics.push_back(
        {.port_ordinal = configured.ordinal,
         .statistics = icmpv6_interface_statistics_[configured.ordinal],
         .router_advertisement_last_sent_ago_nanoseconds =
             ago(times.has_router_advertisement, times.router_advertisement),
         .neighbor_solicitation_last_sent_ago_nanoseconds =
             ago(times.has_neighbor_solicitation, times.neighbor_solicitation),
         .neighbor_advertisement_last_sent_ago_nanoseconds = ago(
             times.has_neighbor_advertisement, times.neighbor_advertisement)});
  }
  state.mld_interfaces.reserve(mld_interfaces_.size());
  for (const auto &entry : mld_interfaces_)
    state.mld_interfaces.push_back({.intent = entry.intent,
                                    .protocol = entry.protocol.checkpoint(now),
                                    .ssm_translations = entry.translations,
                                    .import_policy =
                                        entry.import_policy.checkpoint(),
                                    .running = entry.running});
  state.ipv6_redirect_limiters.reserve(ports_.size());
  for (std::size_t ordinal = 0; ordinal < ports_.size(); ++ordinal) {
    const auto &limiter = ipv6_redirect_limiters_[ordinal];
    if (!limiter.active)
      continue;
    const auto remaining = limiter.window_end > now ? limiter.window_end - now
                                                    : Clock::duration::zero();
    state.ipv6_redirect_limiters.push_back(
        {.port_ordinal = static_cast<std::uint16_t>(ordinal),
         .sent = limiter.sent,
         .remaining_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                 .count()});
  }
  state.ipv4_redirect_limiters.reserve(ports_.size());
  for (std::size_t ordinal = 0; ordinal < ports_.size(); ++ordinal) {
    const auto &limiter = ipv4_redirect_limiters_[ordinal];
    if (!limiter.active)
      continue;
    const auto remaining = limiter.window_end > now ? limiter.window_end - now
                                                    : Clock::duration::zero();
    state.ipv4_redirect_limiters.push_back(
        {.port_ordinal = static_cast<std::uint16_t>(ordinal),
         .sent = limiter.sent,
         .remaining_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                 .count()});
  }
  state.ipv6_reachable_times.reserve(state.ports.size());
  for (std::size_t ordinal = 0; ordinal < ipv6_reachable_times_.size();
       ++ordinal) {
    const auto &entry = ipv6_reachable_times_[ordinal];
    if (!entry.valid)
      continue;
    // Cold tests and imported state can supply an explicit anchor slightly
    // earlier than the configure turn. Clamp to one full refresh period so a
    // process-local steady-clock mismatch cannot manufacture extra lifetime.
    const auto raw_remaining = entry.refresh_deadline > now
                                   ? entry.refresh_deadline - now
                                   : Clock::duration::zero();
    const auto remaining = std::min(
        raw_remaining, std::chrono::duration_cast<Clock::duration>(
                           device_catalog::nd_reachable_time_recalculation));
    state.ipv6_reachable_times.push_back(
        {.port_ordinal = static_cast<std::uint16_t>(ordinal),
         .base_milliseconds = entry.base_milliseconds,
         .effective_milliseconds = entry.effective_milliseconds,
         .random_state = entry.random_state,
         .remaining_refresh_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                 .count()});
  }
  if (ipv6_probe_valid_) {
    state.ipv6_probe_packets.reserve(ipv6_probe_packet_count_);
    for (std::size_t index = 0; index < ipv6_probe_packet_count_; ++index)
      state.ipv6_probe_packets.push_back(ipv6_probe_packets_[index]);
  }
  state.adjacencies.reserve(arp_entries());
  for (const auto &entry : adjacencies_) {
    if (!entry.valid)
      continue;
    const auto remaining = !entry.aging_disabled && entry.expires > now
                               ? entry.expires - now
                               : Clock::duration::zero();
    state.adjacencies.push_back(
        {.port_ordinal = entry.port_ordinal,
         .address = entry.address,
         .mac = entry.mac,
         .remaining_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                 .count(),
         .aging_disabled = entry.aging_disabled,
         .configured_static = entry.configured_static});
  }
  state.pending.reserve(pending_frames());
  for (const auto &entry : pending_)
    if (entry.valid) {
      const auto retry_remaining = !entry.ipv6 && entry.arp_retry_deadline > now
                                       ? entry.arp_retry_deadline - now
                                       : Clock::duration::zero();
      state.pending.push_back(
          {.transit = entry.transit,
           .ipv6 = entry.ipv6,
           .interface_id = entry.interface_id,
           .port_ordinal = entry.port_ordinal,
           .next_hop = entry.next_hop,
           .next_hop_ipv6 = entry.next_hop_ipv6,
           .frame = entry.frame,
           .ipv6_source_mtu = entry.ipv6_source_mtu,
           .arp_retry_remaining_nanoseconds =
               std::chrono::duration_cast<std::chrono::nanoseconds>(
                   retry_remaining)
                   .count()});
    }
  state.forwarded_frames = forwarded_frames_;
  state.dropped_frames = dropped_frames_;
  state.last_drop = last_drop_;
  state.echo_reply_sequence = echo_reply_sequence_;
  state.echo_reply_valid = echo_reply_valid_;
  state.echo_request_destination = echo_request_destination_;
  state.echo_request_age_nanoseconds =
      echo_request_valid_ && now >= echo_request_sent_at_
          ? static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now - echo_request_sent_at_)
                    .count())
          : 0U;
  state.echo_reply_rtt_nanoseconds = static_cast<std::uint64_t>(
      std::max<std::int64_t>(0, echo_reply_rtt_.count()));
  state.echo_request_sequence = echo_request_sequence_;
  state.echo_request_valid = echo_request_valid_;
  state.ipv6_echo_reply_sequence = ipv6_echo_reply_sequence_;
  state.ipv6_echo_reply_valid = ipv6_echo_reply_valid_;
  state.ipv6_probe_age_nanoseconds =
      ipv6_probe_valid_ && now >= ipv6_probe_sent_at_
          ? static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    now - ipv6_probe_sent_at_)
                    .count())
          : 0U;
  state.ipv6_echo_reply_rtt_nanoseconds = static_cast<std::uint64_t>(
      std::max<std::int64_t>(0, ipv6_echo_reply_rtt_.count()));
  state.ipv6_echo_error_parameter = ipv6_echo_error_parameter_;
  state.ipv6_echo_error_sequence = ipv6_echo_error_sequence_;
  state.ipv6_echo_error_type = ipv6_echo_error_type_;
  state.ipv6_echo_error_code = ipv6_echo_error_code_;
  state.ipv6_echo_error_valid = ipv6_echo_error_valid_;
  state.ipv6_probe_destination = ipv6_probe_destination_;
  state.ipv6_fragment_identification = ipv6_fragment_identification_;
  state.ipv6_probe_interface_id = ipv6_probe_interface_id_;
  state.ipv6_probe_port_ordinal = ipv6_probe_port_ordinal_;
  state.ipv6_probe_sequence = ipv6_probe_sequence_;
  state.mld_service_cursor = mld_service_cursor_;
  state.ipv6_probe_valid = ipv6_probe_valid_;
  state.ipv4_probe_valid = ipv4_probe_valid_;
  if (ipv4_probe_valid_) {
    state.ipv4_probe_packet = ipv4_probe_packet_;
    state.ipv4_probe_destination = ipv4_probe_destination_;
    state.ipv4_probe_interface_id = ipv4_probe_interface_id_;
    state.ipv4_probe_port_ordinal = ipv4_probe_port_ordinal_;
  }
}

bool RouterForwarder::validate_checkpoint(
    const RouterForwarderCheckpoint &state) noexcept {
  // Validate every index, count and frame before clearing the live arrays.
  // The second installation phase contains no allocation and cannot fail.
  if (state.ports.size() > device_catalog::maximum_ports_per_router ||
      state.native_ipv6_addresses.size() > RouterIpv6AddressTable::capacity ||
      state.adjacencies.size() > device_catalog::arp_entries_per_router ||
      state.ipv6_neighbors.size() >
          device_catalog::ipv6_neighbor_entries_per_router ||
      state.ipv6_dad.size() > Ipv6DadTable::capacity ||
      state.ipv6_router_advertisements.size() >
          Ipv6RouterAdvertisementTable::capacity ||
      state.ipv6_probe_packets.size() >
          packet::Ipv6FragmentBatch::maximum_fragment_count ||
      state.ipv4_reassembly.size() >
          device_catalog::ipv4_reassembly_entries_per_endpoint ||
      state.ipv6_reassembly.size() >
          device_catalog::ipv6_reassembly_entries_per_endpoint ||
      state.mld_interfaces.size() > device_catalog::maximum_ports_per_router ||
      state.dhcpv6_relay_interfaces.size() >
          device_catalog::maximum_ports_per_router ||
      state.ipv6_redirect_limiters.size() >
          device_catalog::maximum_ports_per_router ||
      state.ipv4_redirect_limiters.size() >
          device_catalog::maximum_ports_per_router ||
      state.ipv6_reachable_times.size() >
          device_catalog::maximum_ports_per_router ||
      state.pending.size() > device_catalog::pending_l3_frames_per_router ||
      state.fib.count > state.fib.routes.size() ||
      state.ipv6_fib.count > state.ipv6_fib.routes.size() ||
      state.last_drop < ForwardDrop::none ||
      state.last_drop > ForwardDrop::blackhole ||
      state.mld_service_cursor > state.mld_interfaces.size())
    return false;
  service::SapForwardingTable sap_validation;
  if (sap_validation.replace(state.sap_attachments,
                             state.service_ipv6_interfaces) !=
      service::SapProgramStatus::accepted)
    return false;
  if (!transport::UdpEndpoint::validate_checkpoint(state.udp) ||
      !ikev2::UdpService::validate_checkpoint(state.ike_udp, state.udp) ||
      state.dhcpv6_relay_interfaces.empty() != !state.dhcpv6_relay_socket)
    return false;
  if (state.dhcpv6_relay_socket) {
    const auto handle = *state.dhcpv6_relay_socket;
    if (handle.index >= state.udp.sockets.size())
      return false;
    const auto &socket = state.udp.sockets[handle.index];
    if (!socket.occupied || socket.generation != handle.generation ||
        socket.binding.family != transport::IpFamily::ipv6 ||
        socket.binding.port != packet::dhcpv6::server_port ||
        socket.binding.interface_id != 0U ||
        !ip::is_unspecified(socket.binding.ipv6))
      return false;
  }
  try {
    dhcpv6::RelayAgent relay_validation;
    dhcpv6::RelayLeaseRepository lease_validation;
    dhcpv6::RelayRouteRepository route_validation;
    if (!relay_validation.restore(state.dhcpv6_relay_interfaces))
      return false;
    const auto policies = relay_lease_policies(state.dhcpv6_relay_interfaces);
    if (!lease_validation.restore(policies, state.dhcpv6_relay_leases))
      return false;
    if (!route_validation.restore(state.dhcpv6_relay_interfaces,
                                  lease_validation.leases(),
                                  state.dhcpv6_relay_routes))
      return false;
  } catch (...) {
    return false;
  }
  // A syntactically valid SAP still cannot refer to an absent physical port.
  // Validate this relation against the same checkpoint image, not live state.
  for (const auto &attachment : state.sap_attachments) {
    const auto found = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const auto &configured) {
          return configured.ordinal == attachment.sap.port.ordinal;
        });
    if (found == state.ports.end())
      return false;
  }
  if (!valid_icmpv4_statistics(state.icmpv4_global_statistics))
    return false;
  if (state.icmpv4_interface_statistics.size() >
      device_catalog::maximum_ports_per_router)
    return false;
  std::array<bool, device_catalog::maximum_ports_per_router>
      seen_icmpv4_statistics{};
  for (const auto &entry : state.icmpv4_interface_statistics)
    if (entry.port_ordinal >= seen_icmpv4_statistics.size() ||
        seen_icmpv4_statistics[entry.port_ordinal] ||
        !valid_icmpv4_statistics(entry.statistics))
      return false;
    else
      seen_icmpv4_statistics[entry.port_ordinal] = true;
  if (!valid_icmpv6_statistics(state.icmpv6_global_statistics))
    return false;
  if (state.icmpv6_interface_statistics.size() >
      device_catalog::maximum_ports_per_router)
    return false;
  std::array<bool, device_catalog::maximum_ports_per_router>
      seen_icmpv6_statistics{};
  for (const auto &entry : state.icmpv6_interface_statistics)
    if (entry.port_ordinal >= seen_icmpv6_statistics.size() ||
        seen_icmpv6_statistics[entry.port_ordinal] ||
        !valid_icmpv6_statistics(entry.statistics) ||
        entry.router_advertisement_last_sent_ago_nanoseconds < -1 ||
        entry.neighbor_solicitation_last_sent_ago_nanoseconds < -1 ||
        entry.neighbor_advertisement_last_sent_ago_nanoseconds < -1)
      return false;
    else
      seen_icmpv6_statistics[entry.port_ordinal] = true;
  std::array<bool, device_catalog::maximum_ports_per_router> seen_ports{};
  for (const auto &port : state.ports) {
    if (!port.configured || port.ordinal >= seen_ports.size() ||
        seen_ports[port.ordinal] ||
        (port.ipv4_configured && port.prefix_length > 32U) ||
        port.arp_timeout_seconds >
            device_catalog::arp_timeout_maximum_seconds ||
        port.arp_retry_deciseconds <
            device_catalog::arp_retry_minimum_deciseconds ||
        port.arp_retry_deciseconds >
            device_catalog::arp_retry_maximum_deciseconds ||
        !valid_ipv6_neighbor_policy(port) ||
        port.mtu < device_catalog::minimum_network_mtu ||
        port.mtu > device_catalog::maximum_network_mtu || !port.speed_mbps ||
        (port.ipv6_configured &&
         (port.mtu < packet::ipv6_minimum_ethernet_mtu ||
          port.ipv6_prefix_length > ip::ipv6_address_bits ||
          ip::is_unspecified(port.ipv6_address) ||
          ip::is_multicast(port.ipv6_address) ||
          !ip::is_link_local(port.ipv6_link_local))) ||
        port.icmp6_redirect_maximum <
            device_catalog::icmp6_redirect_minimum_maximum ||
        port.icmp6_redirect_maximum >
            device_catalog::icmp6_redirect_maximum_maximum ||
        port.icmp6_redirect_interval_seconds <
            device_catalog::icmp6_redirect_minimum_interval.count() ||
        port.icmp6_redirect_interval_seconds >
            device_catalog::icmp6_redirect_maximum_interval.count())
      return false;
    seen_ports[port.ordinal] = true;
  }
  for (std::size_t index = 0U; index < state.fib.count; ++index) {
    const auto &route = state.fib.routes[index];
    const bool canonical =
        route.prefix_length <= 32U &&
        route.network ==
            (route.network & routing::prefix_mask(route.prefix_length));
    const bool valid_local = route.local_system && route.prefix_length == 32U &&
                             route.next_hop == 0U && route.port_ordinal == 0U;
    const bool valid_egress = !route.local_system &&
                              route.port_ordinal < seen_ports.size() &&
                              seen_ports[route.port_ordinal];
    // A restored system route is the sole FIB entry allowed without a port.
    // Conversely, a physical route cannot cite an absent ordinal or smuggle a
    // local discriminator into a non-/32 prefix.
    if (!canonical || (!valid_local && !valid_egress))
      return false;
  }
  RouterIpv6AddressTable native_addresses;
  if (native_addresses.program(state.native_ipv6_addresses) !=
      RouterIpv6AddressProgramStatus::accepted)
    return false;
  for (const auto &address : native_addresses.records()) {
    if (address.port_ordinal >= seen_ports.size() ||
        !seen_ports[address.port_ordinal] ||
        address.interface_id != physical_interface_id(address.port_ordinal))
      return false;
    const auto configured_port = std::find_if(
        state.ports.begin(), state.ports.end(),
        [&](const auto &port) { return port.ordinal == address.port_ordinal; });
    if (configured_port == state.ports.end() ||
        !configured_port->ipv6_configured)
      return false;
  }
  // The compact port projection must equal the primary selected from the full
  // generation. A mismatch would make routing and local delivery disagree
  // immediately after restore even though each record is valid in isolation.
  for (const auto &port : state.ports) {
    const auto *primary =
        native_addresses.primary(physical_interface_id(port.ordinal));
    if (port.ipv6_configured != (primary != nullptr) ||
        (primary && (port.ipv6_address != primary->address ||
                     port.ipv6_network != primary->network ||
                     port.ipv6_prefix_length != primary->prefix_length)))
      return false;
  }
  const auto interface_port =
      [&](std::uint64_t interface_id) -> std::optional<std::uint16_t> {
    if (const auto native = physical_port_from_interface_id(interface_id))
      return native;
    const auto service =
        std::find_if(state.sap_attachments.begin(), state.sap_attachments.end(),
                     [&](const auto &attachment) {
                       return attachment.logical_interface_id == interface_id;
                     });
    if (service != state.sap_attachments.end())
      return service->sap.port.ordinal;
    const auto relay = std::find_if(
        state.dhcpv6_relay_interfaces.begin(),
        state.dhcpv6_relay_interfaces.end(), [&](const auto &configuration) {
          return configuration.interface_id == interface_id;
        });
    // An untagged relay projection predates full IES attachment programming
    // but is still an explicit control-owned logical interface. Its stored
    // physical coordinate is therefore a valid scope relation, not inference.
    return relay == state.dhcpv6_relay_interfaces.end()
               ? std::nullopt
               : std::optional<std::uint16_t>{relay->physical_port_ordinal};
  };
  for (const auto &configuration : state.dhcpv6_relay_interfaces) {
    if (configuration.interface_id == 0U ||
        configuration.physical_port_ordinal >= seen_ports.size())
      return false;
    const auto ordinal =
        static_cast<std::size_t>(configuration.physical_port_ordinal);
    const auto configured_port = std::find_if(
        state.ports.begin(), state.ports.end(),
        [&](const auto &candidate) { return candidate.ordinal == ordinal; });
    const auto service_interface = std::find_if(
        state.service_ipv6_interfaces.begin(),
        state.service_ipv6_interfaces.end(), [&](const auto &candidate) {
          return candidate.interface_id == configuration.interface_id;
        });
    const bool valid_service_interface =
        service_interface != state.service_ipv6_interfaces.end() &&
        service_interface->configured &&
        service_interface->physical_port_ordinal == ordinal;
    const bool valid_legacy_interface =
        service_interface == state.service_ipv6_interfaces.end() &&
        configured_port != state.ports.end() &&
        configured_port->ipv6_configured;
    // A regular relay is an IES-interface child. The access port owns carrier,
    // while the service interface owns IPv6 addresses. Only the legacy
    // compatibility API is permitted to borrow a native port address.
    if (!seen_ports[ordinal] || configured_port == state.ports.end() ||
        (!valid_service_interface && !valid_legacy_interface))
      return false;
  }
  // A statistics row exists for every configured interface and never for a
  // vacant inventory ordinal. This prevents restoring counters onto a future
  // interface that happens to reuse the same dense coordinate.
  if (state.icmpv4_interface_statistics.size() != state.ports.size() ||
      state.icmpv6_interface_statistics.size() != state.ports.size())
    return false;
  for (std::size_t ordinal = 0; ordinal < seen_ports.size(); ++ordinal)
    if (seen_ports[ordinal] != seen_icmpv4_statistics[ordinal] ||
        seen_ports[ordinal] != seen_icmpv6_statistics[ordinal])
      return false;
  for (const auto &entry : state.adjacencies)
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] || !usable_sender_mac(entry.mac) ||
        entry.remaining_nanoseconds < 0 ||
        (entry.aging_disabled && entry.remaining_nanoseconds != 0) ||
        (entry.configured_static && !entry.aging_disabled) ||
        (!entry.aging_disabled &&
         entry.remaining_nanoseconds >
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 std::chrono::seconds{
                     device_catalog::arp_timeout_maximum_seconds})
                 .count()))
      return false;
  if (!Ipv6NeighborCache::validate_checkpoint(state.ipv6_neighbors))
    return false;
  for (const auto &entry : state.ipv6_neighbors) {
    const auto physical_port = interface_port(entry.interface_id);
    // A scoped cache row must resolve through either a native routed port or
    // the published SAP generation. Merely fitting in an integer range cannot
    // make an orphaned service identity operational after restore.
    if (!physical_port || *physical_port >= seen_ports.size() ||
        !seen_ports[*physical_port])
      return false;
  }
  if (!Ipv6DadTable::validate_checkpoint(state.ipv6_dad))
    return false;
  if (!Ipv6RouterAdvertisementTable::validate_checkpoint(
          state.ipv6_router_advertisements))
    return false;
  if (!ip::Ipv6PathMtuCache::validate_checkpoint(state.ipv6_path_mtu))
    return false;
  if (!ip::Ipv4PathMtuCache::validate_checkpoint(state.ipv4_path_mtu))
    return false;
  if (!packet::Ipv4ReassemblyTable::validate_checkpoint(state.ipv4_reassembly))
    return false;
  if (!packet::Ipv6ReassemblyTable::validate_checkpoint(state.ipv6_reassembly))
    return false;
  for (const auto &entry : state.ipv6_dad) {
    const auto physical_port = interface_port(entry.interface_id);
    const auto configured_port = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const ForwardPort &port) {
          return port.ordinal == entry.port_ordinal;
        });
    bool configured_address{};
    if (const auto native =
            physical_port_from_interface_id(entry.interface_id)) {
      // A native interface obtains both its IPv6 identity and carrier from the
      // physical projection. Requiring an exact address relation prevents an
      // otherwise well-formed DAD row from attaching to the wrong native port.
      configured_address = *native == entry.port_ordinal &&
                           configured_port != state.ports.end() &&
                           configured_port->ipv6_configured &&
                           (native_addresses.find(entry.interface_id,
                                                  entry.address) != nullptr ||
                            entry.address == configured_port->ipv6_link_local);
    } else if (const auto service = std::find_if(
                   state.service_ipv6_interfaces.begin(),
                   state.service_ipv6_interfaces.end(),
                   [&](const auto &value) {
                     return value.interface_id == entry.interface_id;
                   });
               service != state.service_ipv6_interfaces.end()) {
      // An IES address is owned by the routed service interface. Its physical
      // access port supplies carrier only and is correctly allowed to have no
      // native IPv6 address at all.
      configured_address =
          service->configured &&
          service->physical_port_ordinal == entry.port_ordinal &&
          (entry.address == service->address ||
           entry.address == service->link_local);
    } else if (const auto relay = std::find_if(
                   state.dhcpv6_relay_interfaces.begin(),
                   state.dhcpv6_relay_interfaces.end(),
                   [&](const auto &value) {
                     return value.interface_id == entry.interface_id;
                   });
               relay != state.dhcpv6_relay_interfaces.end()) {
      // The legacy untagged relay projection borrows addresses from its native
      // port until the complete IES owner replaces this compatibility path.
      configured_address = relay->physical_port_ordinal == entry.port_ordinal &&
                           configured_port != state.ports.end() &&
                           configured_port->ipv6_configured &&
                           (entry.address == configured_port->ipv6_address ||
                            entry.address == configured_port->ipv6_link_local);
    }
    if (!physical_port || *physical_port != entry.port_ordinal ||
        entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] ||
        configured_port == state.ports.end() || !configured_address)
      return false;
  }
  for (const auto &entry : state.ipv6_path_mtu) {
    const auto physical_port = interface_port(entry.interface_id);
    if (!physical_port || !seen_ports[*physical_port])
      return false;
  }
  for (const auto &entry : state.ipv4_path_mtu) {
    const auto physical_port = interface_port(entry.interface_id);
    if (!physical_port || !seen_ports[*physical_port])
      return false;
  }
  if (state.ipv6_echo_error_valid &&
      (state.ipv6_echo_error_type >=
           packet::icmpv6_informational_type_boundary ||
       (state.ipv6_echo_reply_valid &&
        state.ipv6_echo_reply_sequence ==
            state.ipv6_echo_error_sequence)))
    return false;
  if (state.ipv4_probe_valid) {
    const auto physical_port = interface_port(state.ipv4_probe_interface_id);
    const auto parsed = packet::parse_ipv4(state.ipv4_probe_packet);
    if (!physical_port || *physical_port != state.ipv4_probe_port_ordinal ||
        state.ipv4_probe_port_ordinal >= seen_ports.size() ||
        !seen_ports[state.ipv4_probe_port_ordinal] || !parsed ||
        !parsed->dont_fragment ||
        parsed->destination != state.ipv4_probe_destination)
      return false;
  } else if (state.ipv4_probe_packet.length != 0U ||
             state.ipv4_probe_destination != packet::Ipv4{} ||
             state.ipv4_probe_interface_id != 0U ||
             state.ipv4_probe_port_ordinal != 0U) {
    return false;
  }
  if (state.ipv6_probe_valid != !state.ipv6_probe_packets.empty())
    return false;
  if (state.ipv6_probe_valid) {
    const auto physical_port = interface_port(state.ipv6_probe_interface_id);
    if (!physical_port || *physical_port != state.ipv6_probe_port_ordinal ||
        state.ipv6_probe_port_ordinal >= seen_ports.size() ||
        !seen_ports[state.ipv6_probe_port_ordinal] ||
        ip::is_unspecified(state.ipv6_probe_destination))
      return false;
    for (const auto &frame : state.ipv6_probe_packets) {
      const auto parsed = packet::parse_ipv6(frame);
      if (!parsed || parsed->destination != state.ipv6_probe_destination)
        return false;
    }
  }
  for (const auto &entry : state.pending) {
    const auto physical_port =
        entry.ipv6 ? interface_port(entry.interface_id)
                   : std::optional<std::uint16_t>{entry.port_ordinal};
    if (!physical_port || *physical_port != entry.port_ordinal ||
        entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] ||
        (!entry.ipv6 && entry.interface_id != 0U) ||
        (!entry.ipv6 && !entry.next_hop) ||
        entry.arp_retry_remaining_nanoseconds < 0 ||
        (entry.ipv6 && entry.arp_retry_remaining_nanoseconds != 0) ||
        (!entry.ipv6 &&
         entry.arp_retry_remaining_nanoseconds >
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 std::chrono::milliseconds{
                     static_cast<std::int64_t>(
                         device_catalog::arp_retry_maximum_deciseconds) *
                     100})
                 .count()) ||
        (entry.ipv6 && (ip::is_unspecified(entry.next_hop_ipv6) ||
                        ip::is_multicast(entry.next_hop_ipv6))) ||
        (!entry.ipv6 && entry.ipv6_source_mtu != 0U) ||
        (entry.ipv6 && entry.ipv6_source_mtu != 0U &&
         entry.ipv6_source_mtu < packet::ipv6_minimum_link_mtu) ||
        !entry.frame.size() || entry.frame.size() > entry.frame.bytes.size())
      return false;
  }
  std::array<bool, device_catalog::maximum_ports_per_router> seen_mld{};
  for (const auto &entry : state.mld_interfaces) {
    const auto ordinal = entry.intent.port_ordinal;
    if (!entry.intent.enabled || ordinal >= seen_ports.size() ||
        !seen_ports[ordinal] || seen_mld[ordinal] ||
        !MldRouterInterface::validate_checkpoint(entry.protocol) ||
        entry.running != entry.protocol.configuration.enabled ||
        entry.intent.port_ordinal !=
            entry.protocol.configuration.port_ordinal ||
        entry.intent.version != entry.protocol.configuration.version ||
        entry.intent.link_local_address !=
            entry.protocol.configuration.link_local_address ||
        entry.intent.query_interval !=
            entry.protocol.configuration.query_interval ||
        entry.intent.query_response_interval !=
            entry.protocol.configuration.query_response_interval ||
        entry.intent.last_listener_query_interval !=
            entry.protocol.configuration.last_listener_query_interval ||
        entry.intent.robustness_variable !=
            entry.protocol.configuration.robustness_variable)
      return false;
    if (entry.ssm_translations.size() >
        device_catalog::mld_router_group_sources_per_interface)
      return false;
    mld::ImportPolicyProgram policy_validator;
    if (!policy_validator.restore(entry.import_policy))
      return false;
    for (std::size_t index = 0; index < entry.ssm_translations.size();
         ++index) {
      const auto &translation = entry.ssm_translations[index];
      if (!ip::is_multicast(translation.start) ||
          !ip::is_multicast(translation.end) ||
          translation.end < translation.start ||
          ip::is_unspecified(translation.source) ||
          ip::is_multicast(translation.source) ||
          std::find(entry.ssm_translations.begin(),
                    entry.ssm_translations.begin() +
                        static_cast<std::ptrdiff_t>(index),
                    translation) != entry.ssm_translations.begin() +
                                        static_cast<std::ptrdiff_t>(index))
        return false;
    }
    const auto configured_port = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const auto &port_value) {
          return port_value.ordinal == ordinal && port_value.ipv6_configured &&
                 port_value.ipv6_link_local == entry.intent.link_local_address;
        });
    if (configured_port == state.ports.end())
      return false;
    seen_mld[ordinal] = true;
  }
  std::array<bool, device_catalog::maximum_ports_per_router> seen_redirect{};
  for (const auto &entry : state.ipv6_redirect_limiters) {
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] || seen_redirect[entry.port_ordinal] ||
        entry.remaining_nanoseconds < 0)
      return false;
    const auto configured = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const auto &port_value) {
          return port_value.ordinal == entry.port_ordinal;
        });
    if (configured == state.ports.end() ||
        entry.sent > configured->icmp6_redirect_maximum ||
        entry.remaining_nanoseconds >
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::seconds{
                    configured->icmp6_redirect_interval_seconds})
                .count())
      return false;
    seen_redirect[entry.port_ordinal] = true;
  }
  std::array<bool, device_catalog::maximum_ports_per_router>
      seen_ipv4_redirect{};
  for (const auto &entry : state.ipv4_redirect_limiters) {
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] ||
        seen_ipv4_redirect[entry.port_ordinal] ||
        entry.remaining_nanoseconds < 0)
      return false;
    const auto configured = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const auto &port_value) {
          return port_value.ordinal == entry.port_ordinal &&
                 port_value.ipv4_configured;
        });
    if (configured == state.ports.end() ||
        entry.sent > configured->icmp_redirect_maximum ||
        entry.remaining_nanoseconds >
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::seconds{
                    configured->icmp_redirect_interval_seconds})
                .count())
      return false;
    seen_ipv4_redirect[entry.port_ordinal] = true;
  }
  std::array<bool, device_catalog::maximum_ports_per_router> seen_reachable{};
  for (const auto &entry : state.ipv6_reachable_times) {
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] || seen_reachable[entry.port_ordinal] ||
        !entry.random_state || entry.remaining_refresh_nanoseconds < 0)
      return false;
    const auto configured = std::find_if(
        state.ports.begin(), state.ports.end(), [&](const auto &port_value) {
          return port_value.ordinal == entry.port_ordinal &&
                 port_value.ipv6_configured;
        });
    if (configured == state.ports.end() ||
        entry.base_milliseconds != configured->nd_reachable_time_milliseconds ||
        entry.effective_milliseconds < entry.base_milliseconds / 2U ||
        entry.effective_milliseconds >
            entry.base_milliseconds + entry.base_milliseconds / 2U ||
        entry.remaining_refresh_nanoseconds >
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                device_catalog::nd_reachable_time_recalculation)
                .count())
      return false;
    seen_reachable[entry.port_ordinal] = true;
  }
  // Every configured IPv6 port owns exactly one independent ReachableTime
  // variable. Missing state would silently fall back to zero on a solicited
  // advertisement, while surplus state could later attach to a reused port.
  for (const auto &configured : state.ports)
    if (configured.ipv6_configured != seen_reachable[configured.ordinal])
      return false;
  return true;
}

bool RouterForwarder::restore(const RouterForwarderCheckpoint &state,
                              Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;

  transport::UdpEndpoint restored_udp;
  ikev2::UdpService restored_ike_udp;
  dhcpv6::RelayAgent restored_relay;
  dhcpv6::RelayLeaseRepository restored_relay_leases;
  dhcpv6::RelayRouteRepository restored_relay_routes;
  service::SapForwardingTable restored_saps;
  std::vector<dhcpv6::RelayLeaseRecord> restored_clear_scratch;
  std::vector<Ipv6NeighborBatchEdit> restored_neighbor_edits;
  try {
    if (!restored_udp.restore(state.udp) ||
        !restored_ike_udp.restore(state.ike_udp, restored_udp) ||
        !restored_relay.restore(state.dhcpv6_relay_interfaces) ||
        !restored_relay_leases.restore(
            relay_lease_policies(state.dhcpv6_relay_interfaces),
            state.dhcpv6_relay_leases, now) ||
        !restored_relay_routes.restore(state.dhcpv6_relay_interfaces,
                                       restored_relay_leases.leases(),
                                       state.dhcpv6_relay_routes) ||
        restored_saps.replace(state.sap_attachments,
                              state.service_ipv6_interfaces) !=
            service::SapProgramStatus::accepted)
      return false;
    std::size_t lease_capacity{};
    std::size_t neighbor_capacity{};
    for (const auto &policy :
         relay_lease_policies(state.dhcpv6_relay_interfaces)) {
      lease_capacity += policy.maximum_leases;
      if (policy.neighbor_resolution)
        neighbor_capacity += policy.maximum_leases;
    }
    restored_clear_scratch.reserve(lease_capacity);
    restored_neighbor_edits.reserve(
        std::min(neighbor_capacity,
                 device_catalog::ipv6_neighbor_entries_per_router) *
        2U);
  } catch (...) {
    return false;
  }

  ports_.fill({});
  ipv6_redirect_limiters_.fill({});
  ipv4_redirect_limiters_.fill({});
  ipv6_reachable_times_.fill({});
  adjacencies_.fill({});
  pending_.fill({});
  icmpv4_global_statistics_ = state.icmpv4_global_statistics;
  icmpv4_interface_statistics_.fill({});
  icmpv6_global_statistics_ = state.icmpv6_global_statistics;
  icmpv6_interface_statistics_.fill({});
  icmpv6_transmit_times_.fill({});
  for (const auto &port : state.ports)
    ports_[port.ordinal] = port;
  // validate_checkpoint already proved this generation and its primary cache
  // consistent, so publication cannot fail in the mutation phase.
  static_cast<void>(
      native_ipv6_addresses_.program(state.native_ipv6_addresses));
  // Publication occurs only after all fallible restore work above succeeded.
  // Moving the fully indexed table cannot expose a half-restored generation.
  sap_forwarding_ = std::move(restored_saps);
  for (const auto &entry : state.icmpv6_interface_statistics) {
    icmpv6_interface_statistics_[entry.port_ordinal] = entry.statistics;
    auto &times = icmpv6_transmit_times_[entry.port_ordinal];
    // Rebase portable elapsed durations onto this process's monotonic epoch.
    // The validation above guarantees that every present duration is >= 0.
    const auto restore_time = [now](std::int64_t elapsed) {
      return now - std::chrono::nanoseconds{elapsed};
    };
    if (entry.router_advertisement_last_sent_ago_nanoseconds >= 0) {
      times.has_router_advertisement = true;
      times.router_advertisement =
          restore_time(entry.router_advertisement_last_sent_ago_nanoseconds);
    }
    if (entry.neighbor_solicitation_last_sent_ago_nanoseconds >= 0) {
      times.has_neighbor_solicitation = true;
      times.neighbor_solicitation =
          restore_time(entry.neighbor_solicitation_last_sent_ago_nanoseconds);
    }
    if (entry.neighbor_advertisement_last_sent_ago_nanoseconds >= 0) {
      times.has_neighbor_advertisement = true;
      times.neighbor_advertisement =
          restore_time(entry.neighbor_advertisement_last_sent_ago_nanoseconds);
    }
  }
  for (const auto &entry : state.icmpv4_interface_statistics)
    icmpv4_interface_statistics_[entry.port_ordinal] = entry.statistics;
  fib_ = state.fib;
  ipv6_fib_ = state.ipv6_fib;
  // Router-level validation has already checked port scope. The cache repeats
  // its own state-machine validation so it remains safe when used by a host or
  // another future owner outside RouterForwarder.
  if (!ipv6_neighbors_.restore(state.ipv6_neighbors, now))
    return false;
  if (!ipv6_dad_.restore(state.ipv6_dad, now))
    return false;
  if (!ipv6_router_advertisements_.restore(state.ipv6_router_advertisements,
                                           now))
    return false;
  if (!ipv6_path_mtu_.restore(state.ipv6_path_mtu, now))
    return false;
  if (!ipv4_path_mtu_.restore(state.ipv4_path_mtu, now))
    return false;
  if (!ipv4_reassembly_.restore(state.ipv4_reassembly, now))
    return false;
  if (!ipv6_reassembly_.restore(state.ipv6_reassembly, now))
    return false;
  std::vector<MldPortState> restored_mld;
  restored_mld.reserve(state.mld_interfaces.size());
  for (const auto &entry : state.mld_interfaces) {
    restored_mld.emplace_back();
    auto &target = restored_mld.back();
    target.intent = entry.intent;
    target.running = entry.running;
    try {
      target.translations = entry.ssm_translations;
      target.translation_scratch.reserve(
          std::min<std::size_t>(target.translations.size(),
                                device_catalog::mld_router_sources_per_group));
      target.policy_source_scratch.reserve(
          device_catalog::mld_router_sources_per_group);
    } catch (...) {
      return false;
    }
    if (!target.import_policy.restore(entry.import_policy))
      return false;
    if (!target.protocol.restore(entry.protocol, now))
      return false;
  }
  mld_interfaces_.swap(restored_mld);
  mld_service_cursor_ = state.mld_service_cursor;
  for (const auto &entry : state.ipv6_redirect_limiters)
    ipv6_redirect_limiters_[entry.port_ordinal] = {
        .window_end =
            now + std::chrono::nanoseconds{entry.remaining_nanoseconds},
        .sent = entry.sent,
        .active = true};
  for (const auto &entry : state.ipv4_redirect_limiters)
    ipv4_redirect_limiters_[entry.port_ordinal] = {
        .window_end =
            now + std::chrono::nanoseconds{entry.remaining_nanoseconds},
        .sent = entry.sent,
        .active = true};
  for (const auto &entry : state.ipv6_reachable_times)
    ipv6_reachable_times_[entry.port_ordinal] = {
        .refresh_deadline =
            now + std::chrono::nanoseconds{entry.remaining_refresh_nanoseconds},
        .random_state = entry.random_state,
        .base_milliseconds = entry.base_milliseconds,
        .effective_milliseconds = entry.effective_milliseconds,
        .valid = true};
  for (std::size_t index = 0; index < state.adjacencies.size(); ++index) {
    const auto &source = state.adjacencies[index];
    adjacencies_[index] = {
        .valid = true,
        .port_ordinal = source.port_ordinal,
        .address = source.address,
        .mac = source.mac,
        .expires =
            source.aging_disabled
                ? Clock::time_point::max()
                : now + std::chrono::nanoseconds{source.remaining_nanoseconds},
        .aging_disabled = source.aging_disabled,
        .configured_static = source.configured_static};
  }
  for (std::size_t index = 0; index < state.pending.size(); ++index) {
    const auto &source = state.pending[index];
    pending_[index] = {
        .valid = true,
        .transit = source.transit,
        .ipv6 = source.ipv6,
        .interface_id = source.interface_id,
        .port_ordinal = source.port_ordinal,
        .next_hop = source.next_hop,
        .next_hop_ipv6 = source.next_hop_ipv6,
        .frame = source.frame,
        .ipv6_source_mtu = source.ipv6_source_mtu,
        .arp_retry_deadline =
            source.ipv6 ? Clock::time_point::max()
                        : now + std::chrono::nanoseconds{
                                    source.arp_retry_remaining_nanoseconds}};
  }
  forwarded_frames_ = state.forwarded_frames;
  dropped_frames_ = state.dropped_frames;
  last_drop_ = state.last_drop;
  echo_reply_sequence_ = state.echo_reply_sequence;
  echo_reply_valid_ = state.echo_reply_valid;
  echo_request_destination_ = state.echo_request_destination;
  echo_request_sent_at_ =
      now - std::chrono::nanoseconds{static_cast<std::int64_t>(
                state.echo_request_age_nanoseconds)};
  echo_reply_rtt_ = std::chrono::nanoseconds{static_cast<std::int64_t>(
      state.echo_reply_rtt_nanoseconds)};
  echo_request_sequence_ = state.echo_request_sequence;
  echo_request_valid_ = state.echo_request_valid;
  ipv6_echo_reply_sequence_ = state.ipv6_echo_reply_sequence;
  ipv6_echo_reply_valid_ = state.ipv6_echo_reply_valid;
  ipv6_probe_sent_at_ =
      now - std::chrono::nanoseconds{static_cast<std::int64_t>(
                state.ipv6_probe_age_nanoseconds)};
  ipv6_echo_reply_rtt_ = std::chrono::nanoseconds{static_cast<std::int64_t>(
      state.ipv6_echo_reply_rtt_nanoseconds)};
  ipv6_echo_error_parameter_ = state.ipv6_echo_error_parameter;
  ipv6_echo_error_sequence_ = state.ipv6_echo_error_sequence;
  ipv6_echo_error_type_ = state.ipv6_echo_error_type;
  ipv6_echo_error_code_ = state.ipv6_echo_error_code;
  ipv6_echo_error_valid_ = state.ipv6_echo_error_valid;
  ipv6_probe_packets_.fill({});
  ipv6_probe_packet_count_ =
      static_cast<std::uint8_t>(state.ipv6_probe_packets.size());
  for (std::size_t index = 0; index < state.ipv6_probe_packets.size(); ++index)
    ipv6_probe_packets_[index] = state.ipv6_probe_packets[index];
  ipv6_probe_destination_ = state.ipv6_probe_destination;
  ipv6_fragment_identification_ = state.ipv6_fragment_identification;
  ipv6_probe_interface_id_ = state.ipv6_probe_interface_id;
  ipv6_probe_port_ordinal_ = state.ipv6_probe_port_ordinal;
  ipv6_probe_sequence_ = state.ipv6_probe_sequence;
  ipv6_probe_valid_ = state.ipv6_probe_valid;
  ipv4_probe_valid_ = state.ipv4_probe_valid;
  ipv4_probe_packet_ = state.ipv4_probe_packet;
  ipv4_probe_destination_ = state.ipv4_probe_destination;
  ipv4_probe_interface_id_ = state.ipv4_probe_interface_id;
  ipv4_probe_port_ordinal_ = state.ipv4_probe_port_ordinal;
  udp_ = std::move(restored_udp);
  ike_udp_ = std::move(restored_ike_udp);
  dhcpv6_relay_ = std::move(restored_relay);
  dhcpv6_relay_leases_ = std::move(restored_relay_leases);
  dhcpv6_relay_routes_ = std::move(restored_relay_routes);
  dhcpv6_clear_scratch_.swap(restored_clear_scratch);
  dhcpv6_neighbor_edits_.swap(restored_neighbor_edits);
  dhcpv6_relay_socket_ = state.dhcpv6_relay_socket;
  return true;
}

bool RouterForwarder::program_fib(const routing::FibProgram &program) noexcept {
  // Equal generation is idempotent. Older generations are stale shard messages
  // and cannot replace forwarding state selected later by control.
  if (program.generation < fib_.generation ||
      program.count > program.routes.size())
    return false;
  if (program.generation == fib_.generation && fib_.generation) {
    // Reusing a generation with different bytes would make stale-message
    // ordering ambiguous. Accept only an exact idempotent replay.
    if (program.count != fib_.count ||
        !std::equal(program.routes.begin(),
                    program.routes.begin() + program.count, fib_.routes.begin(),
                    [](const auto &left, const auto &right) {
                      return left.network == right.network &&
                             left.next_hop == right.next_hop &&
                             left.port_ordinal == right.port_ordinal &&
                             left.prefix_length == right.prefix_length &&
                             left.preference == right.preference &&
                             left.metric == right.metric &&
                             left.source == right.source &&
                             left.local_system == right.local_system;
                    }))
      return false;
    return true;
  }
  fib_ = program;
  return true;
}

bool RouterForwarder::program_ipv6_fib(
    const routing::Ipv6FibProgram &program) noexcept {
  if (program.generation < ipv6_fib_.generation ||
      program.count > program.routes.size())
    return false;
  if (program.generation == ipv6_fib_.generation && ipv6_fib_.generation) {
    if (program.count != ipv6_fib_.count ||
        !std::equal(
            program.routes.begin(), program.routes.begin() + program.count,
            ipv6_fib_.routes.begin(), [](const auto &left, const auto &right) {
              return left.network == right.network &&
                     left.next_hop == right.next_hop &&
                     left.interface_id == right.interface_id &&
                     left.physical_port_ordinal ==
                         right.physical_port_ordinal &&
                     left.prefix_length == right.prefix_length &&
                     left.preference == right.preference &&
                     left.metric == right.metric &&
                     left.source == right.source;
            }))
      return false;
    return true;
  }
  ipv6_fib_ = program;
  return true;
}

bool RouterForwarder::originate_echo(std::uint32_t destination,
                                     std::uint16_t sequence, void *context,
                                     EgressSink sink, Clock::time_point now,
                                     std::uint16_t payload_octets,
                                     bool dont_fragment) noexcept {
  routing::Route route;
  // Source selection follows the same local FIB used by transit packets. This
  // prevents a CLI ping from gaining an out-of-band route through the lab
  // graph.
  if (!routing::lookup(fib_, destination, route)) {
    drop(ForwardDrop::no_route);
    return false;
  }
  if (route.local_system) {
    // A ping to the router's own system address terminates in the local IPv4
    // stack. No Ethernet frame, ARP request, fake port or fabric event exists
    // for this path. Publishing the same sequence is the observable result the
    // asynchronous CLI operation would receive from its local ICMP endpoint.
    // RFC 4293 global counters describe messages the entity attempts to send
    // and receives, not only Ethernet transmissions. Account for the logical
    // request and reply globally while deliberately leaving every physical
    // interface scope untouched.
    count_icmpv4_message(icmpv4_global_statistics_.sent, 8U);
    count_icmpv4_message(icmpv4_global_statistics_.received, 0U);
    echo_reply_sequence_ = sequence;
    echo_reply_valid_ = true;
    echo_reply_rtt_ = std::chrono::nanoseconds::zero();
    echo_request_valid_ = false;
    return true;
  }
  const auto *egress = port(route.port_ordinal);
  if (!egress || !egress->operational || !egress->ipv4_configured) {
    drop(ForwardDrop::port_down);
    return false;
  }
  // Source address and MAC come from the locally selected egress interface.
  // The router does not ask another device or the topology graph for a source.
  auto request = packet::icmp_echo(
      egress->mac, unresolved_mac, to_ipv4(egress->address),
      to_ipv4(destination), false, sequence,
      device_catalog::default_ip_hop_limit, payload_octets, dont_fragment);
  echo_reply_valid_ = false;
  // Start the RTT clock before ARP or egress queuing. A real ping observes
  // neighbor-resolution delay on its first probe, but never observes how late
  // the terminal happens to poll the already received reply.
  echo_request_destination_ = to_ipv4(destination);
  echo_request_sequence_ = sequence;
  echo_request_sent_at_ = now;
  echo_reply_rtt_ = std::chrono::nanoseconds::zero();
  echo_request_valid_ = true;
  // The message has entered the local ICMP output path even when ARP must
  // queue it before Ethernet transmission. RFC counter semantics account for
  // this generation once, not again when adjacency resolution releases it.
  count_sent_icmpv4(egress->ordinal, request);
  const auto request_ip = packet::parse_ipv4(request);
  if (!request_ip) {
    ipv4_probe_valid_ = false;
    drop(ForwardDrop::malformed);
    return false;
  }
  const auto interface_id = physical_interface_id(egress->ordinal);
  if (dont_fragment) {
    const auto first_hop_mtu = static_cast<std::uint32_t>(
        egress->mtu - packet::ethernet_header_octets);
    const auto path_mtu = ipv4_path_mtu_.begin_probe(
        to_ipv4(destination), interface_id, first_hop_mtu,
        request_ip->total_length, now);
    if (request_ip->total_length > path_mtu) {
      // The local IP layer reports EMSGSIZE semantics without emitting a
      // packet already known to exceed the path. No synthetic ICMP error is
      // generated because no router received an invoking datagram.
      ipv4_probe_valid_ = false;
      drop(ForwardDrop::mtu_exceeded);
      return false;
    }
    packet::copy_frame(ipv4_probe_packet_, request);
    ipv4_probe_destination_ = to_ipv4(destination);
    ipv4_probe_interface_id_ = interface_id;
    ipv4_probe_port_ordinal_ = egress->ordinal;
    ipv4_probe_valid_ = true;
  } else {
    ipv4_probe_valid_ = false;
  }
  const auto forwarded_before = forwarded_frames_;
  const auto pending_before = pending_frames();
  send(request, destination, false, context, sink, now);
  const bool accepted = forwarded_frames_ != forwarded_before ||
                        pending_frames() > pending_before;
  if (!accepted)
    echo_request_valid_ = false;
  if (!accepted)
    ipv4_probe_valid_ = false;
  return accepted;
}

bool RouterForwarder::originate_ipv6_echo(
    const packet::Ipv6 &destination, std::uint16_t sequence, void *context,
    EgressSink sink, Clock::time_point now,
    std::uint16_t payload_octets) noexcept {
  // Local delivery is an IPv6-layer decision, not a shortened physical path.
  // RFC 4291 assigns every configured unicast address to this node, while RFC
  // 4862 prevents a tentative or duplicate address from accepting traffic.
  // Check every forwarding-owned address generation before FIB lookup so a
  // ping to this router cannot incorrectly start Neighbor Discovery for its
  // own address. This mirrors the local-system IPv4 path without inventing an
  // Ethernet frame, a peer or a zero-length link.
  bool preferred_local_destination{};
  if (const auto *native = native_ipv6_addresses_.owner(destination))
    preferred_local_destination =
        ipv6_dad_.preferred(native->interface_id, destination);
  if (!preferred_local_destination)
    for (const auto &candidate : ports_) {
      if (!candidate.configured || !candidate.operational ||
          !candidate.ipv6_configured ||
          candidate.ipv6_link_local != destination)
        continue;
      preferred_local_destination = ipv6_dad_.preferred(
          physical_interface_id(candidate.ordinal), destination);
      if (preferred_local_destination)
        break;
    }
  if (!preferred_local_destination)
    for (const auto &candidate : sap_forwarding_.interfaces()) {
      if (!candidate.configured || !candidate.operational ||
          (candidate.address != destination &&
           candidate.link_local != destination))
        continue;
      preferred_local_destination =
          ipv6_dad_.preferred(candidate.interface_id, destination);
      if (preferred_local_destination)
        break;
    }
  if (preferred_local_destination) {
    // RFC 4293 global ICMPv6 counters observe both locally generated messages.
    // Per-interface counters do not change because neither message crossed an
    // interface. Publishing the correlated result directly also avoids adding
    // scheduler latency to an exchange that never leaves the IPv6 endpoint.
    count_icmpv6_message(icmpv6_global_statistics_.sent,
                         packet::icmpv6_echo_request_type);
    count_icmpv6_message(icmpv6_global_statistics_.received,
                         packet::icmpv6_echo_reply_type);
    ipv6_probe_valid_ = false;
    ipv6_probe_packet_count_ = 0U;
    ipv6_echo_reply_sequence_ = sequence;
    ipv6_echo_reply_rtt_ = std::chrono::nanoseconds::zero();
    ipv6_echo_reply_valid_ = true;
    ipv6_echo_error_valid_ = false;
    return true;
  }

  routing::Ipv6Route route;
  bool blackhole{};
  if (!lookup_ipv6_route(destination, route, blackhole)) {
    drop(ForwardDrop::no_route);
    return false;
  }
  if (blackhole) {
    drop(ForwardDrop::blackhole);
    return false;
  }
  const auto egress_view =
      ipv6_interface(route.interface_id, route.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured) {
    drop(ForwardDrop::port_down);
    return false;
  }
  std::array<ip::Ipv6SourceCandidate,
             device_catalog::network_interface_ip_addresses + 1U>
      candidates{};
  std::size_t candidate_count{};
  for (const auto &address : native_ipv6_addresses_.records())
    if (address.interface_id == route.interface_id &&
        ipv6_dad_.preferred(address.interface_id, address.address))
      candidates[candidate_count++] = {.address = address.address,
                                       .interface_id = address.interface_id,
                                       .prefix_length = address.prefix_length,
                                       .preferred = true};
  if (ipv6_dad_.preferred(route.interface_id, egress->ipv6_link_local))
    candidates[candidate_count++] = {.address = egress->ipv6_link_local,
                                     .interface_id = route.interface_id,
                                     .prefix_length = 64U,
                                     .preferred = true};
  const auto selected_source = ip::select_ipv6_source(
      std::span<const ip::Ipv6SourceCandidate>{candidates}.first(
          candidate_count),
      {.destination = destination,
       .outgoing_interface_id = route.interface_id,
       .prefer_temporary = false});
  if (!selected_source) {
    // Tentative and duplicate addresses never become source candidates. This
    // also makes a link-local destination fail when no preferred scoped source
    // exists on the selected outgoing interface.
    drop(ForwardDrop::port_down);
    return false;
  }
  auto request = packet::icmpv6_echo(
      egress->mac, unresolved_mac, candidates[*selected_source].address,
      destination, false, sequence, device_catalog::default_ip_hop_limit,
      payload_octets);
  const auto request_ip = packet::parse_ipv6(request);
  if (!request_ip) {
    drop(ForwardDrop::malformed);
    return false;
  }
  // RFC 4293 counts the ICMP generation attempt once, independent of whether
  // IPv6 later emits one packet, fragments it, queues it for ND, or rejects it.
  count_sent_icmpv6(egress->ordinal, request);
  const auto first_hop_mtu =
      static_cast<std::uint32_t>(egress->mtu - packet::ethernet_header_octets);
  const auto packet_octets =
      packet::ipv6_header_octets +
      static_cast<std::uint32_t>(request_ip->payload_length);
  const auto path_mtu = ipv6_path_mtu_.begin_probe(
      destination, route.interface_id, first_hop_mtu, packet_octets, now);

  // Retain the exact IP packets handed to ND and the link owner. A later PTB
  // must quote one of these byte prefixes before it is allowed to reduce PMTU.
  ipv6_probe_destination_ = destination;
  ipv6_probe_interface_id_ = route.interface_id;
  ipv6_probe_port_ordinal_ = egress->ordinal;
  ipv6_probe_sequence_ = sequence;
  ipv6_probe_packet_count_ = 0U;
  ipv6_probe_valid_ = true;
  ipv6_probe_sent_at_ = now;
  ipv6_echo_reply_rtt_ = std::chrono::nanoseconds::zero();
  ipv6_echo_reply_valid_ = false;
  ipv6_echo_error_valid_ = false;
  const auto forwarded_before = forwarded_frames_;
  const auto pending_before = pending_frames();
  if (packet_octets > path_mtu) {
    const auto fragments =
        packet::fragment_ipv6(request, static_cast<std::uint16_t>(path_mtu),
                              ipv6_fragment_identification_++);
    if (!fragments) {
      ipv6_probe_valid_ = false;
      drop(ForwardDrop::mtu_exceeded);
      return false;
    }
    for (std::size_t index = 0; index < fragments->count; ++index) {
      const auto emitted_before_fragment = forwarded_frames_;
      const auto pending_before_fragment = pending_frames();
      send_ipv6(fragments->frames[index], destination, false, context, sink,
                now, path_mtu);
      if (forwarded_frames_ != emitted_before_fragment ||
          pending_frames() > pending_before_fragment) {
        packet::copy_frame(ipv6_probe_packets_[ipv6_probe_packet_count_],
                           fragments->frames[index]);
        ++ipv6_probe_packet_count_;
      }
    }
  } else {
    const auto emitted_before_request = forwarded_frames_;
    const auto pending_before_request = pending_frames();
    send_ipv6(request, destination, false, context, sink, now, path_mtu);
    if (forwarded_frames_ != emitted_before_request ||
        pending_frames() > pending_before_request) {
      packet::copy_frame(ipv6_probe_packets_[0], request);
      ipv6_probe_packet_count_ = 1U;
    }
  }
  if (!ipv6_probe_packet_count_)
    ipv6_probe_valid_ = false;
  return forwarded_frames_ != forwarded_before ||
         pending_frames() > pending_before;
}

const ForwardPort *RouterForwarder::port(std::uint16_t ordinal) const noexcept {
  return ordinal < ports_.size() && ports_[ordinal].configured
             ? &ports_[ordinal]
             : nullptr;
}

ForwardPort *RouterForwarder::port(std::uint16_t ordinal) noexcept {
  return ordinal < ports_.size() && ports_[ordinal].configured
             ? &ports_[ordinal]
             : nullptr;
}

bool RouterForwarder::ipv6_neighbor_admission_allowed(
    const ForwardPort &egress, std::uint64_t interface_id,
    const packet::Ipv6 &address) const noexcept {
  // Updating an existing entry never consumes another resource and must remain
  // possible at the configured ceiling. This also lets a solicited NA complete
  // an INCOMPLETE entry after the administrator reduces the limit.
  if (ipv6_neighbors_.find(interface_id, address))
    return true;
  if (!egress.ipv6_neighbor_limit_configured ||
      egress.ipv6_neighbor_limit_log_only)
    return true;
  return ipv6_neighbors_.dynamic_size(interface_id) <
         egress.ipv6_neighbor_limit;
}

Ipv6Resolution RouterForwarder::resolve_ipv6_neighbor(
    const ForwardPort &egress, std::uint64_t interface_id,
    const packet::Ipv6 &address, Clock::time_point now) noexcept {
  // A hard limit rejects only creation. Returning table_full reuses the
  // bounded pending-frame failure path and never pretends that a Neighbor
  // Solicitation was placed on the wire.
  if (!ipv6_neighbor_admission_allowed(egress, interface_id, address))
    return {.status = Ipv6ResolutionStatus::table_full};
  return ipv6_neighbors_.resolve(
      interface_id, address, now,
      std::chrono::seconds{egress.nd_stale_time_seconds},
      address_scope_selected(egress.ipv6_proactive_refresh, address));
}

std::optional<Icmpv6Statistics> RouterForwarder::icmpv6_interface_statistics(
    std::uint16_t port_ordinal) const noexcept {
  if (!port(port_ordinal))
    return std::nullopt;
  return icmpv6_interface_statistics_[port_ordinal];
}

std::optional<Icmpv4Statistics> RouterForwarder::icmpv4_interface_statistics(
    std::uint16_t port_ordinal) const noexcept {
  if (!port(port_ordinal))
    return std::nullopt;
  return icmpv4_interface_statistics_[port_ordinal];
}

void RouterForwarder::clear_icmpv4_statistics_all() noexcept {
  // Global and interface scopes are cleared during one forwarding-owner turn.
  // No received frame can be counted in one scope between those two writes.
  icmpv4_global_statistics_ = {};
  icmpv4_interface_statistics_.fill({});
}

void RouterForwarder::clear_icmpv4_global_statistics() noexcept {
  icmpv4_global_statistics_ = {};
}

bool RouterForwarder::clear_icmpv4_interface_statistics(
    std::uint16_t port_ordinal) noexcept {
  if (!port(port_ordinal))
    return false;
  icmpv4_interface_statistics_[port_ordinal] = {};
  return true;
}

void RouterForwarder::clear_icmpv6_statistics_all() noexcept {
  // `all` is one owner turn, so a packet can never land between clearing the
  // global copy and the corresponding interface copy.
  icmpv6_global_statistics_ = {};
  icmpv6_interface_statistics_.fill({});
  icmpv6_transmit_times_.fill({});
}

void RouterForwarder::clear_icmpv6_global_statistics() noexcept {
  icmpv6_global_statistics_ = {};
}

bool RouterForwarder::clear_icmpv6_interface_statistics(
    std::uint16_t port_ordinal) noexcept {
  if (!port(port_ordinal))
    return false;
  icmpv6_interface_statistics_[port_ordinal] = {};
  icmpv6_transmit_times_[port_ordinal] = {};
  return true;
}

namespace {

void clear_router_advertisement_direction(
    Icmpv6DirectionStatistics &statistics) noexcept {
  // The classic RA report is a dedicated ND counter group. Clearing it does
  // not erase Echo, Redirect, MLD or error accounting maintained by ICMPv6.
  statistics.router_solicitation = 0U;
  statistics.router_advertisement = 0U;
  statistics.neighbor_solicitation = 0U;
  statistics.neighbor_advertisement = 0U;
}

} // namespace

void RouterForwarder::count_received_icmpv4(
    std::uint16_t port_ordinal, std::span<const std::uint8_t> packet_bytes,
    const packet::Ipv4View &ipv4) noexcept {
  if (port_ordinal >= icmpv4_interface_statistics_.size())
    return;
  auto &global = icmpv4_global_statistics_.received;
  auto &interface = icmpv4_interface_statistics_[port_ordinal].received;
  if (const auto icmp = packet::parse_icmp(packet_bytes)) {
    count_icmpv4_message(global, icmp->type);
    count_icmpv4_message(interface, icmp->type);
    return;
  }
  // The caller invokes this only after local IPv4 delivery and destination
  // reassembly. A remaining protocol-1 failure is therefore an ICMP checksum
  // or length error, not an IP-layer discard that would be absent from ICMP.
  if (ipv4.protocol == 1U) {
    count_icmpv4_error(global);
    count_icmpv4_error(interface);
  }
}

void RouterForwarder::count_sent_icmpv4(std::uint16_t port_ordinal,
                                        const packet::Frame &frame) noexcept {
  if (port_ordinal >= icmpv4_interface_statistics_.size())
    return;
  const auto icmp = packet::parse_icmp(frame);
  if (!icmp) {
    // A locally encoded ICMP packet that fails its own parser is a generation
    // error. It is accounted without assigning a fabricated message Type.
    count_icmpv4_error(icmpv4_global_statistics_.sent);
    count_icmpv4_error(icmpv4_interface_statistics_[port_ordinal].sent);
    return;
  }
  count_icmpv4_message(icmpv4_global_statistics_.sent, icmp->type);
  count_icmpv4_message(icmpv4_interface_statistics_[port_ordinal].sent,
                       icmp->type);
}

void RouterForwarder::clear_router_advertisement_statistics_all() noexcept {
  for (std::size_t ordinal = 0; ordinal < ports_.size(); ++ordinal) {
    if (!ports_[ordinal].configured)
      continue;
    auto &statistics = icmpv6_interface_statistics_[ordinal];
    clear_router_advertisement_direction(statistics.received);
    clear_router_advertisement_direction(statistics.sent);
    icmpv6_transmit_times_[ordinal] = {};
  }
}

bool RouterForwarder::clear_router_advertisement_interface_statistics(
    std::uint16_t port_ordinal) noexcept {
  if (!port(port_ordinal))
    return false;
  auto &statistics = icmpv6_interface_statistics_[port_ordinal];
  clear_router_advertisement_direction(statistics.received);
  clear_router_advertisement_direction(statistics.sent);
  icmpv6_transmit_times_[port_ordinal] = {};
  return true;
}

void RouterForwarder::count_received_icmpv6(
    std::uint16_t port_ordinal, std::span<const std::uint8_t> packet_bytes,
    const packet::Ipv6View &ipv6) noexcept {
  if (port_ordinal >= icmpv6_interface_statistics_.size())
    return;
  auto &global = icmpv6_global_statistics_.received;
  auto &interface = icmpv6_interface_statistics_[port_ordinal].received;
  if (const auto icmp = packet::parse_icmpv6(packet_bytes)) {
    count_icmpv6_message(global, icmp->type);
    count_icmpv6_message(interface, icmp->type);
    return;
  }
  // The caller invokes this only after IPv6 extension processing reaches the
  // ICMPv6 upper layer and endpoint reassembly is complete. A remaining parse
  // failure is therefore an ICMP-specific bad length or checksum from RFC 4293.
  if (ipv6.upper_layer_protocol == packet::ipv6_next_header_icmpv6) {
    count_icmpv6_error(global);
    count_icmpv6_error(interface);
  }
}

void RouterForwarder::count_sent_icmpv6(std::uint16_t port_ordinal,
                                        const packet::Frame &frame) noexcept {
  if (port_ordinal >= icmpv6_interface_statistics_.size())
    return;
  const auto icmp = packet::parse_icmpv6(frame);
  if (!icmp) {
    // A locally built message that fails its own parser is an internal ICMP
    // generation error. Count the attempt and error without inventing a type.
    count_icmpv6_error(icmpv6_global_statistics_.sent);
    count_icmpv6_error(icmpv6_interface_statistics_[port_ordinal].sent);
    return;
  }
  count_icmpv6_message(icmpv6_global_statistics_.sent, icmp->type);
  count_icmpv6_message(icmpv6_interface_statistics_[port_ordinal].sent,
                       icmp->type);
  auto &times = icmpv6_transmit_times_[port_ordinal];
  const auto now = Clock::now();
  // Only timestamps visible in the release's RA operational report are kept.
  // This costs three time_points per physical coordinate and no hot-path map.
  switch (icmp->type) {
  case packet::nd::router_advertisement_type:
    times.router_advertisement = now;
    times.has_router_advertisement = true;
    break;
  case packet::nd::neighbor_solicitation_type:
    times.neighbor_solicitation = now;
    times.has_neighbor_solicitation = true;
    break;
  case packet::nd::neighbor_advertisement_type:
    times.neighbor_advertisement = now;
    times.has_neighbor_advertisement = true;
    break;
  default:
    break;
  }
}

void RouterForwarder::count_discarded_icmpv6(
    std::uint16_t port_ordinal) noexcept {
  if (port_ordinal >= icmpv6_interface_statistics_.size())
    return;
  count_icmpv6_discard(icmpv6_global_statistics_.sent);
  count_icmpv6_discard(icmpv6_interface_statistics_[port_ordinal].sent);
}

RouterForwarder::Adjacency *
RouterForwarder::find_adjacency(std::uint16_t port_ordinal,
                                std::uint32_t address,
                                Clock::time_point now) noexcept {
  for (auto &entry : adjacencies_) {
    // Port is part of the key because equal protocol addresses on separate
    // interfaces cannot share one link-layer mapping.
    if (!entry.valid || entry.port_ordinal != port_ordinal ||
        entry.address != address)
      continue;
    if (!entry.aging_disabled && entry.expires <= now) {
      entry = {};
      return nullptr;
    }
    return &entry;
  }
  return nullptr;
}

void RouterForwarder::learn(std::uint16_t port_ordinal, std::uint32_t address,
                            packet::Mac mac, Clock::time_point now) noexcept {
  if (!usable_sender_mac(mac))
    return;
  Adjacency *target{};
  // Prefer an exact existing key, otherwise remember the first free slot. The
  // scan never evicts an unrelated live neighbor behind the user's back.
  for (auto &entry : adjacencies_) {
    if (entry.valid && entry.port_ordinal == port_ordinal &&
        entry.address == address) {
      // An observed ARP frame cannot rewrite administrator-owned state. The
      // configured row remains authoritative until its own delete command.
      if (entry.configured_static)
        return;
      target = &entry;
      break;
    }
    if (!entry.valid && !target)
      target = &entry;
  }
  if (!target)
    return;
  const auto *ingress = port(port_ordinal);
  if (!ingress || !ingress->ipv4_configured)
    return;
  // Source: ietf.arp.rfc826 and nokia.sros.26_7.arp.aging. A learned sender
  // mapping refreshes this interface's effective lifetime. Zero disables
  // aging and is represented explicitly instead of using an arithmetic
  // duration large enough to overflow a steady-clock time point.
  const bool aging_disabled = ingress->arp_timeout_seconds == 0U;
  *target = {.valid = true,
             .port_ordinal = port_ordinal,
             .address = address,
             .mac = mac,
             .expires =
                 aging_disabled
                     ? Clock::time_point::max()
                     : now + std::chrono::seconds{ingress->arp_timeout_seconds},
             .aging_disabled = aging_disabled};
}

bool RouterForwarder::emit(std::uint16_t port_ordinal,
                           const packet::Frame &frame, void *context,
                           EgressSink sink) noexcept {
  // The sink is the only legal forwarding-to-link boundary. Failure is a real
  // queue drop and cannot fall back to calling the receiver directly.
  if (!sink || !sink(context, port_ordinal, frame)) {
    drop(ForwardDrop::egress_queue_full);
    return false;
  }
  ++forwarded_frames_;
  return true;
}

bool RouterForwarder::lookup_ipv6_route(const packet::Ipv6 &destination,
                                        routing::Ipv6Route &selected,
                                        bool &blackhole,
                                        std::uint64_t flow_hash) const noexcept {
  routing::Ipv6Route configured;
  dhcpv6::RelayRoute populated;
  const bool have_configured =
      routing::lookup(ipv6_fib_, destination, configured, flow_hash);
  const bool have_populated =
      dhcpv6_relay_routes_.lookup(destination, populated);
  if (!have_configured && !have_populated)
    return false;
  // Longest-prefix selection precedes protocol preference. When lengths are
  // equal, keep the configured RIB selection. SR OS documents Direct as
  // preference 0 and Static as 5, while no sourced configurable preference is
  // exposed for relay-populated DHCPv6 routes in this interface context.
  if (have_configured && (!have_populated || configured.prefix_length >=
                                                 populated.prefix_length)) {
    selected = configured;
    blackhole = false;
    return true;
  }
  selected = {.network = populated.network,
              .next_hop = populated.next_hop,
              .interface_id = populated.interface_id,
              .physical_port_ordinal = populated.physical_port_ordinal,
              .prefix_length = populated.prefix_length};
  blackhole = populated.blackhole;
  return true;
}

std::optional<ForwardPort> RouterForwarder::ipv6_interface(
    std::uint64_t interface_id,
    std::uint16_t physical_port_ordinal) const noexcept {
  const auto *physical = port(physical_port_ordinal);
  if (!physical)
    return std::nullopt;
  if (const auto native = physical_port_from_interface_id(interface_id)) {
    return native && *native == physical_port_ordinal
               ? std::optional<ForwardPort>{*physical}
               : std::nullopt;
  }
  const auto *service = sap_forwarding_.find_interface(interface_id);
  if (!service) {
    // The relay API predates the complete IES generation publisher and still
    // permits one untagged logical relay interface to borrow the L3 values of
    // its physical port. Keep that compatibility projection explicit here so
    // a Relay-reply selected by its opaque Interface-Id does not get rejected
    // merely because no SAP generation owns it yet. The relay configuration
    // remains the authority for the logical-to-physical relationship, while
    // the physical port remains the authority for address, MTU and carrier.
    const auto *relay = dhcpv6_relay_.interface(interface_id);
    if (!relay || relay->physical_port_ordinal != physical_port_ordinal)
      return std::nullopt;
    return *physical;
  }
  if (service->physical_port_ordinal != physical_port_ordinal)
    return std::nullopt;
  // ForwardPort is the existing allocation-free protocol view. Overlay only
  // routed-interface state while retaining speed and carrier from hardware.
  auto view = *physical;
  view.configured = service->configured;
  view.operational = physical->operational && service->operational;
  view.mtu =
      static_cast<std::uint16_t>(service->mtu + packet::ethernet_header_octets);
  view.mac = service->mac;
  view.ipv6_configured = service->configured;
  view.ipv6_address = service->address;
  view.ipv6_network = service->network;
  view.ipv6_link_local = service->link_local;
  view.ipv6_prefix_length = service->prefix_length;
  view.nd_reachable_time_milliseconds = service->nd_reachable_time_milliseconds;
  view.nd_stale_time_seconds = service->nd_stale_time_seconds;
  view.ipv6_unsolicited_learning = service->unsolicited_learning;
  view.ipv6_proactive_refresh = service->proactive_refresh;
  view.ipv6_neighbor_limit = service->neighbor_limit;
  view.ipv6_neighbor_limit_threshold_percent =
      service->neighbor_limit_threshold_percent;
  view.ipv6_neighbor_limit_configured = service->neighbor_limit_configured;
  view.ipv6_neighbor_limit_log_only = service->neighbor_limit_log_only;
  view.icmp6_redirect_maximum = service->redirect_maximum;
  view.icmp6_redirect_interval_seconds = service->redirect_interval_seconds;
  view.icmp6_redirects_enabled = service->redirects_enabled;
  view.ipv4_configured = false;
  return view;
}

bool RouterForwarder::emit_ipv6_interface(std::uint64_t interface_id,
                                          std::uint16_t port_ordinal,
                                          const packet::Frame &frame,
                                          void *context,
                                          EgressSink sink) noexcept {
  if (physical_port_from_interface_id(interface_id))
    return emit(port_ordinal, frame, context, sink);
  if (!sap_forwarding_.find_interface(interface_id)) {
    // A relay-only logical interface is intentionally untagged. Validate the
    // stored physical attachment before emitting so an arbitrary low-domain
    // identifier can never bypass SAP classification or escape on a caller
    // supplied port.
    const auto *relay = dhcpv6_relay_.interface(interface_id);
    if (!relay || relay->physical_port_ordinal != port_ordinal) {
      drop(ForwardDrop::malformed);
      return false;
    }
    return emit(port_ordinal, frame, context, sink);
  }
  packet::Frame wire;
  // Default service marking is zero until the QoS owner supplies a retained
  // ingress or configured egress marking. SAP identity and VLAN bytes are
  // still exact and never inferred from the topology editor.
  if (!sap_forwarding_.egress(interface_id, frame, {}, wire)) {
    drop(ForwardDrop::malformed);
    return false;
  }
  return emit(port_ordinal, wire, context, sink);
}

void RouterForwarder::send_resolved(const packet::Frame &input,
                                    const ForwardPort &egress,
                                    packet::Mac destination_mac, bool transit,
                                    void *context, EgressSink sink,
                                    Clock::time_point now) noexcept {
  packet::Frame frame;
  packet::copy_frame(frame, input);
  // Input remains the untouched received datagram for ICMP quotation. The
  // bounded working copy may change L2 bytes, TTL, checksum and fragmentation.
  if (transit) {
    // route_ipv4 decrements TTL exactly once and recalculates the IPv4
    // checksum.
    if (!packet::route_ipv4_into(frame, input, egress.mac, destination_mac)) {
      drop(ForwardDrop::malformed);
      return;
    }
  } else {
    packet::rewrite_ethernet(frame, egress.mac, destination_mac);
  }

  auto ip = packet::parse_ipv4(frame);
  if (!ip) {
    drop(ForwardDrop::malformed);
    return;
  }
  // SR OS Ethernet MTU includes the 14-octet untagged MAC header. Fragmentation
  // receives the actual maximum IPv4 length for this egress port.
  const auto ip_mtu =
      static_cast<std::uint16_t>(egress.mtu - packet::ethernet_header_octets);
  if (ip->total_length <= ip_mtu) {
    static_cast<void>(emit(egress.ordinal, frame, context, sink));
    return;
  }
  if (ip->dont_fragment) {
    drop(ForwardDrop::mtu_exceeded);
    // RFC 1191 requires code 4 and the next-hop IP MTU. Quote the received
    // datagram before TTL decrement, then route the new error independently.
    if (transit) {
      const auto original_ip = packet::parse_ipv4(input);
      if (original_ip && may_send_icmp_error(input, *original_ip))
        send_fragmentation_needed(input, *original_ip, ip_mtu, context, sink,
                                  now);
    }
    return;
  }
  struct FragmentEgress {
    RouterForwarder *owner{};
    std::uint16_t port{};
    void *sink_context{};
    EgressSink sink{};
    std::size_t admitted{};
  } fragment_egress{this, egress.ordinal, context, sink};
  const auto emit_fragment = [](void *opaque,
                                const packet::Frame &fragment) noexcept {
    auto &target = *static_cast<FragmentEgress *>(opaque);
    if (!target.owner->emit(target.port, fragment, target.sink_context,
                            target.sink))
      return false;
    ++target.admitted;
    return true;
  };
  // A router may refragment an incoming fragment and must apply the IPv4
  // option copied flag when header shapes differ. Streaming avoids imposing a
  // hidden fragment-count ceiling on a legal 65,535-octet datagram. Each
  // emitted fragment independently enters the egress queue, so later
  // congestion may legitimately drop a suffix after earlier admissions.
  const auto fragments = packet::fragment_ipv4_forwarded(
      frame, ip_mtu, &fragment_egress, emit_fragment);
  if (!fragments && fragment_egress.admitted == 0U)
    drop(ForwardDrop::mtu_exceeded);
}

bool RouterForwarder::send_resolved_ipv6(
    const packet::Frame &input, const ForwardPort &egress,
    std::uint64_t interface_id, packet::Mac destination_mac, bool transit,
    void *context, EgressSink sink, Clock::time_point now,
    std::uint32_t local_source_mtu) noexcept {
  packet::Frame frame;
  if (transit) {
    if (!packet::route_ipv6_into(frame, input, egress.mac, destination_mac)) {
      drop(ForwardDrop::malformed);
      return false;
    }
  } else {
    packet::copy_frame(frame, input);
    packet::rewrite_ethernet(frame, egress.mac, destination_mac);
  }
  const auto ipv6 = packet::parse_ipv6(frame);
  if (!ipv6) {
    drop(ForwardDrop::malformed);
    return false;
  }
  // The modeled network-port MTU includes the untagged Ethernet header. IPv6
  // compares its fixed header plus declared payload against the remaining L3
  // size. Padding is not part of this comparison.
  const auto ip_mtu =
      static_cast<std::uint32_t>(egress.mtu - packet::ethernet_header_octets);
  const auto effective_mtu = transit
                                 ? ip_mtu
                             : local_source_mtu != 0U
                                 ? std::min(local_source_mtu, ip_mtu)
                                 : ipv6_path_mtu_.estimate(
                                       ipv6->destination, interface_id, ip_mtu);
  const auto packet_octets = packet::ipv6_header_octets +
                             static_cast<std::uint32_t>(ipv6->payload_length);
  if (packet_octets > effective_mtu) {
    // RFC 8200 prohibits router fragmentation. The original received packet,
    // before Hop Limit decrement, is quoted in Packet Too Big.
    if (transit) {
      drop(ForwardDrop::mtu_exceeded);
      if (may_send_ipv6_icmp_error(input, *ipv6, true))
        send_ipv6_packet_too_big(input, *ipv6, ip_mtu, context, sink, now);
      return false;
    }
    // Packetization is shared by every local producer, not only CLI ping.
    // Echo replies and future UDP or TCP senders therefore cannot bypass a
    // learned PMTU or depend on a command-specific fragmentation shortcut.
    const auto fragments =
        packet::fragment_ipv6(frame, static_cast<std::uint16_t>(effective_mtu),
                              ipv6_fragment_identification_++);
    if (!fragments) {
      drop(ForwardDrop::mtu_exceeded);
      return false;
    }
    for (std::size_t index = 0; index < fragments->count; ++index)
      if (!emit_ipv6_interface(interface_id, egress.ordinal,
                               fragments->frames[index], context, sink))
        return false;
    return true;
  }
  return emit_ipv6_interface(interface_id, egress.ordinal, frame, context,
                             sink);
}

bool RouterForwarder::send_ipv6(packet::Frame frame,
                                const packet::Ipv6 &destination, bool transit,
                                void *context, EgressSink sink,
                                Clock::time_point now,
                                std::uint32_t local_source_mtu) noexcept {
  routing::Ipv6Route route;
  bool blackhole{};
  const auto parsed_for_hash = packet::parse_ipv6(frame);
  const auto flow_hash = parsed_for_hash ? ipv6_ecmp_hash(*parsed_for_hash) : 0U;
  if (!lookup_ipv6_route(destination, route, blackhole, flow_hash)) {
    drop(ForwardDrop::no_route);
    return false;
  }
  if (blackhole) {
    drop(ForwardDrop::blackhole);
    return false;
  }
  const auto egress_view =
      ipv6_interface(route.interface_id, route.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured) {
    drop(ForwardDrop::port_down);
    return false;
  }
  // Neighbor Solicitation uses this link-local source. Until link-local DAD
  // succeeds, no ordinary IPv6 packet may leave the routed interface.
  if (!ipv6_dad_.preferred(route.interface_id, egress->ipv6_link_local)) {
    drop(ForwardDrop::port_down);
    return false;
  }
  const auto next_hop =
      ip::is_unspecified(route.next_hop) ? destination : route.next_hop;
  const auto resolution =
      resolve_ipv6_neighbor(*egress, route.interface_id, next_hop, now);
  if (resolution.status == Ipv6ResolutionStatus::resolved) {
    return send_resolved_ipv6(frame, *egress, route.interface_id,
                              resolution.mac, transit, context, sink, now,
                              local_source_mtu);
  }
  if (resolution.status == Ipv6ResolutionStatus::table_full) {
    drop(ForwardDrop::neighbor_pending_full);
    return false;
  }

  Pending *free{};
  for (auto &entry : pending_)
    if (!entry.valid) {
      free = &entry;
      break;
    }
  if (!free) {
    drop(ForwardDrop::neighbor_pending_full);
    return false;
  }
  free->valid = true;
  free->transit = transit;
  free->ipv6 = true;
  free->interface_id = route.interface_id;
  free->port_ordinal = route.physical_port_ordinal;
  free->next_hop_ipv6 = next_hop;
  free->ipv6_source_mtu = transit ? 0U : local_source_mtu;
  packet::copy_frame(free->frame, frame);

  if (resolution.status == Ipv6ResolutionStatus::solicitation_required) {
    const auto request = packet::nd::neighbor_solicitation(
        egress->mac, egress->ipv6_link_local, next_hop);
    count_sent_icmpv6(egress->ordinal, request);
    if (!emit_ipv6_interface(route.interface_id, egress->ordinal, request,
                             context, sink))
      *free = {};
    else
      return true;
  }
  return resolution.status == Ipv6ResolutionStatus::pending;
}

void RouterForwarder::send(packet::Frame frame, std::uint32_t destination,
                           bool transit, void *context, EgressSink sink,
                           Clock::time_point now) noexcept {
  routing::Route route;
  const auto parsed_for_hash = packet::parse_ipv4(frame);
  const auto flow_hash = parsed_for_hash ? ipv4_ecmp_hash(*parsed_for_hash) : 0U;
  if (!routing::lookup(fib_, destination, route, flow_hash)) {
    // A transit failure is observable on the wire. Locally originated traffic
    // reports failure to its local caller and must not recursively send an
    // ICMP error to itself.
    if (transit) {
      if (const auto original = packet::parse_ipv4(frame))
        send_network_unreachable(frame, *original, context, sink, now);
    }
    drop(ForwardDrop::no_route);
    return;
  }
  if (route.local_system) {
    // send() is an egress routine and therefore cannot manufacture a physical
    // path for a local FIB termination. Current local producers enter through
    // their protocol owner before this point. Treat reaching this guard as a
    // consumed local packet, not a port-down failure against ordinal zero.
    const auto icmp = packet::parse_icmp(frame);
    if (icmp && icmp->type == 0U && icmp->code == 0U &&
        echo_request_valid_ && icmp->sequence == echo_request_sequence_) {
      echo_reply_sequence_ = icmp->sequence;
      echo_reply_valid_ = true;
      echo_reply_rtt_ = std::chrono::nanoseconds::zero();
      echo_request_valid_ = false;
    }
    return;
  }
  const auto *egress = port(route.port_ordinal);
  if (!egress || !egress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto next_hop = route.next_hop ? route.next_hop : destination;
  // A connected route resolves the destination itself. A static route resolves
  // its configured protocol next-hop and never asks topology for a neighbor
  // MAC.
  if (auto *adjacency = find_adjacency(route.port_ordinal, next_hop, now)) {
    send_resolved(frame, *egress, adjacency->mac, transit, context, sink, now);
    return;
  }

  bool request_in_progress{};
  auto retry_deadline = Clock::time_point::max();
  Pending *free{};
  for (auto &entry : pending_) {
    if (entry.valid && entry.port_ordinal == route.port_ordinal &&
        !entry.ipv6 && entry.next_hop == next_hop) {
      request_in_progress = true;
      retry_deadline = entry.arp_retry_deadline;
    }
    if (!entry.valid && !free)
      free = &entry;
  }
  if (!free) {
    drop(ForwardDrop::arp_pending_full);
    return;
  }
  free->valid = true;
  free->transit = transit;
  free->port_ordinal = route.port_ordinal;
  free->next_hop = next_hop;
  free->arp_retry_deadline =
      request_in_progress ? retry_deadline : now + arp_retry_interval(*egress);
  packet::copy_frame(free->frame, frame);
  // Only the first pending frame for an exact adjacency emits a request.
  // Following frames wait in their bounded router-owned queue.
  if (!request_in_progress) {
    const auto request = packet::arp_request(
        egress->mac, to_ipv4(egress->address), to_ipv4(next_hop));
    if (!emit(egress->ordinal, request, context, sink)) {
      // Admission failure means the first request never entered the port
      // queue. Keeping this frame would advertise a pending operation whose
      // first retry starts only after five seconds, so reject it atomically.
      *free = {};
    }
  }
}

void RouterForwarder::flush_pending(std::uint16_t port_ordinal,
                                    std::uint32_t address, packet::Mac mac,
                                    void *context, EgressSink sink,
                                    Clock::time_point now) noexcept {
  const auto *egress = port(port_ordinal);
  if (!egress || !egress->operational)
    return;
  for (auto &entry : pending_) {
    // Only exact port and next-hop matches are released. An ARP reply received
    // elsewhere cannot unlock traffic on another physical adjacency.
    if (!entry.valid || entry.port_ordinal != port_ordinal ||
        entry.next_hop != address)
      continue;
    // Clear ownership before egress callback. A callback-triggered failure or
    // reentrant status query cannot observe the same pending frame twice.
    const auto frame = entry.frame;
    const auto transit = entry.transit;
    entry = {};
    send_resolved(frame, *egress, mac, transit, context, sink, now);
  }
}

void RouterForwarder::flush_pending_ipv6(std::uint64_t interface_id,
                                         std::uint16_t port_ordinal,
                                         const packet::Ipv6 &address,
                                         packet::Mac mac, void *context,
                                         EgressSink sink,
                                         Clock::time_point now) noexcept {
  const auto *egress = port(port_ordinal);
  if (!egress || !egress->operational || !egress->ipv6_configured)
    return;
  for (auto &entry : pending_) {
    if (!entry.valid || !entry.ipv6 || entry.interface_id != interface_id ||
        entry.port_ordinal != port_ordinal || entry.next_hop_ipv6 != address)
      continue;
    const auto frame = entry.frame;
    const auto transit = entry.transit;
    const auto local_source_mtu = entry.ipv6_source_mtu;
    entry = {};
    send_resolved_ipv6(frame, *egress, interface_id, mac, transit, context,
                       sink, now, local_source_mtu);
  }
}

void RouterForwarder::send_time_exceeded(const packet::Frame &original,
                                         const packet::Ipv4View &ip,
                                         void *context, EgressSink sink,
                                         Clock::time_point now) noexcept {
  if (!may_send_icmp_error(original, ip))
    return;
  routing::Route reverse;
  // The return path is independently looked up. Symmetry is never inferred
  // from the ingress port because static routing may be asymmetric.
  if (!routing::lookup(fib_, to_u32(ip.source), reverse)) {
    drop(ForwardDrop::no_route);
    return;
  }
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto error =
      packet::icmp_time_exceeded(original, egress->mac, unresolved_mac,
                                 to_ipv4(egress->address), ip.source);
  if (!error) {
    drop(ForwardDrop::malformed);
    return;
  }
  count_sent_icmpv4(egress->ordinal, *error);
  send(*error, to_u32(ip.source), false, context, sink, now);
}

void RouterForwarder::send_network_unreachable(const packet::Frame &original,
                                               const packet::Ipv4View &ip,
                                               void *context, EgressSink sink,
                                               Clock::time_point now) noexcept {
  if (!may_send_icmp_error(original, ip))
    return;
  routing::Route reverse;
  // RFC 1812 requires the diagnostic, but it still needs an ordinary return
  // route. The ingress port is not a substitute because routing can be
  // asymmetric and accepting that shortcut would be hidden topology magic.
  if (!routing::lookup(fib_, to_u32(ip.source), reverse) ||
      reverse.local_system)
    return;
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational || !egress->ipv4_configured)
    return;
  const auto error =
      packet::icmp_network_unreachable(original, egress->mac, unresolved_mac,
                                       to_ipv4(egress->address), ip.source);
  if (error) {
    count_sent_icmpv4(egress->ordinal, *error);
    send(*error, to_u32(ip.source), false, context, sink, now);
  }
}

void RouterForwarder::send_local_destination_unreachable(
    std::span<const std::uint8_t> original, const packet::Ipv4View &ip,
    std::uint8_t code, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  if (!may_send_icmp_error(original, ip))
    return;
  routing::Route reverse;
  if (!routing::lookup(fib_, to_u32(ip.source), reverse) ||
      reverse.local_system)
    return;
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational || !egress->ipv4_configured)
    return;

  // RFC 1812 distinguishes an unknown IP Protocol from a known UDP protocol
  // with no receiving socket. Keeping code choice at the local dispatcher
  // prevents the packet codec from inventing transport state.
  const auto error =
      code == 2U ? packet::icmp_protocol_unreachable(
                       original, egress->mac, unresolved_mac,
                       to_ipv4(egress->address), ip.source)
      : code == 3U
          ? packet::icmp_port_unreachable(original, egress->mac, unresolved_mac,
                                          to_ipv4(egress->address), ip.source)
          : std::optional<packet::Frame>{};
  if (error) {
    count_sent_icmpv4(egress->ordinal, *error);
    send(*error, to_u32(ip.source), false, context, sink, now);
  }
}

void RouterForwarder::send_reassembly_time_exceeded(
    const packet::Frame &first_fragment, const packet::Ipv4View &ip,
    void *context, EgressSink sink, Clock::time_point now) noexcept {
  if (!may_send_icmp_error(first_fragment, ip))
    return;
  routing::Route reverse;
  if (!routing::lookup(fib_, to_u32(ip.source), reverse) ||
      reverse.local_system)
    return;
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational || !egress->ipv4_configured)
    return;
  const auto error = packet::icmp_reassembly_time_exceeded(
      first_fragment, egress->mac, unresolved_mac, to_ipv4(egress->address),
      ip.source);
  if (error) {
    count_sent_icmpv4(egress->ordinal, *error);
    send(*error, to_u32(ip.source), false, context, sink, now);
  }
}

void RouterForwarder::send_fragmentation_needed(
    const packet::Frame &original, const packet::Ipv4View &ip,
    std::uint16_t next_hop_mtu, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  routing::Route reverse;
  if (!routing::lookup(fib_, to_u32(ip.source), reverse))
    return;
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational)
    return;
  const auto error = packet::icmp_fragmentation_needed(
      original, egress->mac, unresolved_mac, to_ipv4(egress->address),
      ip.source, next_hop_mtu);
  if (error) {
    count_sent_icmpv4(egress->ordinal, *error);
    send(*error, to_u32(ip.source), false, context, sink, now);
  }
}

void RouterForwarder::send_ipv6_time_exceeded(const packet::Frame &original,
                                              const packet::Ipv6View &ipv6,
                                              void *context, EgressSink sink,
                                              Clock::time_point now) noexcept {
  if (!may_send_ipv6_icmp_error(original, ipv6, false))
    return;
  routing::Ipv6Route reverse;
  bool blackhole{};
  if (!lookup_ipv6_route(ipv6.source, reverse, blackhole) || blackhole) {
    drop(ForwardDrop::no_route);
    return;
  }
  const auto egress_view =
      ipv6_interface(reverse.interface_id, reverse.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto source = ip::is_link_local(ipv6.source) ? egress->ipv6_link_local
                                                     : egress->ipv6_address;
  const auto error = packet::icmpv6_time_exceeded(
      original, egress->mac, unresolved_mac, source, ipv6.source);
  if (!error) {
    drop(ForwardDrop::malformed);
    return;
  }
  count_sent_icmpv6(egress->ordinal, *error);
  send_ipv6(*error, ipv6.source, false, context, sink, now);
}

void RouterForwarder::send_ipv6_packet_too_big(const packet::Frame &original,
                                               const packet::Ipv6View &ipv6,
                                               std::uint32_t next_hop_mtu,
                                               void *context, EgressSink sink,
                                               Clock::time_point now) noexcept {
  if (!may_send_ipv6_icmp_error(original, ipv6, true))
    return;
  routing::Ipv6Route reverse;
  bool blackhole{};
  if (!lookup_ipv6_route(ipv6.source, reverse, blackhole) || blackhole)
    return;
  const auto egress_view =
      ipv6_interface(reverse.interface_id, reverse.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured)
    return;
  const auto source = ip::is_link_local(ipv6.source) ? egress->ipv6_link_local
                                                     : egress->ipv6_address;
  const auto error = packet::icmpv6_packet_too_big(
      original, egress->mac, unresolved_mac, source, ipv6.source, next_hop_mtu);
  if (error) {
    count_sent_icmpv6(egress->ordinal, *error);
    send_ipv6(*error, ipv6.source, false, context, sink, now);
  }
}

void RouterForwarder::send_ipv6_destination_unreachable(
    const packet::Frame &original, const packet::Ipv6View &ipv6,
    std::uint8_t code, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  send_ipv6_destination_unreachable(original.view(), ipv6, code, context, sink,
                                    now);
}

void RouterForwarder::send_ipv6_destination_unreachable(
    std::span<const std::uint8_t> original, const packet::Ipv6View &ipv6,
    std::uint8_t code, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  if (!may_send_ipv6_icmp_error(original, ipv6, false))
    return;
  routing::Ipv6Route reverse;
  bool blackhole{};
  if (!lookup_ipv6_route(ipv6.source, reverse, blackhole) || blackhole)
    return;
  const auto egress_view =
      ipv6_interface(reverse.interface_id, reverse.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured)
    return;
  const auto source = ip::is_link_local(ipv6.source) ? egress->ipv6_link_local
                                                     : egress->ipv6_address;
  const auto error = packet::icmpv6_destination_unreachable(
      original, egress->mac, unresolved_mac, source, ipv6.source, code);
  if (error) {
    count_sent_icmpv6(egress->ordinal, *error);
    send_ipv6(*error, ipv6.source, false, context, sink, now);
  }
}

void RouterForwarder::send_ipv6_parameter_problem(
    const packet::Frame &original, const packet::Ipv6View &ipv6,
    std::uint8_t code, std::uint32_t pointer, bool allow_multicast_destination,
    void *context, EgressSink sink, Clock::time_point now) noexcept {
  if (!may_send_ipv6_icmp_error(original, ipv6, allow_multicast_destination))
    return;
  routing::Ipv6Route reverse;
  bool blackhole{};
  if (!lookup_ipv6_route(ipv6.source, reverse, blackhole) || blackhole)
    return;
  const auto egress_view =
      ipv6_interface(reverse.interface_id, reverse.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured)
    return;
  const auto source = ip::is_link_local(ipv6.source) ? egress->ipv6_link_local
                                                     : egress->ipv6_address;
  const auto error =
      packet::icmpv6_parameter_problem(original, egress->mac, unresolved_mac,
                                       source, ipv6.source, code, pointer);
  if (error) {
    count_sent_icmpv6(egress->ordinal, *error);
    send_ipv6(*error, ipv6.source, false, context, sink, now);
  }
}

bool RouterForwarder::accept_ipv6_packet_too_big(
    const packet::Icmpv6View &icmp, Clock::time_point now) noexcept {
  // The quote starts at the invoking IPv6 header. Require at least that fixed
  // header, then compare every received quote octet against packets retained
  // from the local source. A matching address or sequence alone is insufficient
  // because an off-path sender could guess both values.
  if (!ipv6_probe_valid_ || icmp.type != packet::icmpv6_packet_too_big_type ||
      icmp.code != 0U || !matches_ipv6_probe_quote(icmp.data))
    return false;

  // Re-resolve the current path before changing its cache. Configuration may
  // have moved the destination since the quoted packet was sent, in which case
  // the old PTB cannot constrain the new interface path.
  routing::Ipv6Route route;
  bool blackhole{};
  if (!lookup_ipv6_route(ipv6_probe_destination_, route, blackhole) ||
      blackhole || route.interface_id != ipv6_probe_interface_id_ ||
      route.physical_port_ordinal != ipv6_probe_port_ordinal_)
    return false;
  const auto egress_view =
      ipv6_interface(route.interface_id, route.physical_port_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured)
    return false;
  const auto first_hop_mtu =
      static_cast<std::uint32_t>(egress->mtu - packet::ethernet_header_octets);
  const auto update =
      ipv6_path_mtu_.update(ipv6_probe_destination_, route.interface_id,
                            icmp.parameter, first_hop_mtu, now);
  return update == ip::PathMtuUpdate::decreased ||
         update == ip::PathMtuUpdate::unchanged;
}

bool RouterForwarder::matches_ipv6_probe_quote(
    std::span<const std::uint8_t> quote) const noexcept {
  if (!ipv6_probe_valid_ || quote.size() < packet::ipv6_header_octets)
    return false;
  for (std::size_t index = 0; index < ipv6_probe_packet_count_; ++index) {
    const auto &sent = ipv6_probe_packets_[index];
    const auto sent_ipv6 = packet::parse_ipv6(sent);
    if (!sent_ipv6)
      continue;
    const auto sent_ip_octets =
        packet::ipv6_header_octets +
        static_cast<std::size_t>(sent_ipv6->payload_length);
    if (quote.size() <= sent_ip_octets &&
        std::equal(quote.begin(), quote.end(),
                   sent.bytes.begin() + packet::ethernet_header_octets)) {
      return true;
    }
  }
  return false;
}

std::uint64_t
RouterForwarder::echo_outcome(std::uint16_t sequence) const noexcept {
  if (!received_echo_reply(sequence))
    return 0U;
  const auto nanoseconds = static_cast<std::uint64_t>(std::max<std::int64_t>(
      0, echo_reply_rtt_.count()));
  // Fifty-six payload bits cover more than two years at nanosecond precision,
  // comfortably beyond the release-profile ping timeout.
  return 1U | nanoseconds << 8U;
}

std::uint64_t
RouterForwarder::ipv6_echo_outcome(std::uint16_t sequence) const noexcept {
  if (received_ipv6_echo_reply(sequence)) {
    const auto nanoseconds = static_cast<std::uint64_t>(
        std::max<std::int64_t>(0, ipv6_echo_reply_rtt_.count()));
    return 1U | nanoseconds << 8U;
  }
  if (!ipv6_echo_error_valid_ || ipv6_echo_error_sequence_ != sequence)
    return 0U;
  return 2U | static_cast<std::uint64_t>(ipv6_echo_error_type_) << 8U |
         static_cast<std::uint64_t>(ipv6_echo_error_code_) << 16U |
         static_cast<std::uint64_t>(ipv6_echo_error_parameter_) << 24U;
}

bool RouterForwarder::accept_ipv4_fragmentation_needed(
    const packet::IcmpView &icmp, Clock::time_point now) noexcept {
  if (!ipv4_probe_valid_ || icmp.type != 3U || icmp.code != 4U)
    return false;
  const auto sent = packet::parse_ipv4(ipv4_probe_packet_);
  if (!sent || !sent->dont_fragment ||
      icmp.data.size() < static_cast<std::size_t>(sent->header_length) + 8U ||
      icmp.data.size() > sent->total_length ||
      !std::equal(icmp.data.begin(), icmp.data.end(),
                  ipv4_probe_packet_.bytes.begin() +
                      packet::ethernet_header_octets))
    return false;

  // A route change gives the same destination a new path key. The old ICMP
  // report is valid evidence about the old packet but not about the new path,
  // so both the logical interface and physical port must still agree.
  routing::Route route;
  if (!routing::lookup(fib_, to_u32(ipv4_probe_destination_), route) ||
      route.local_system || route.port_ordinal != ipv4_probe_port_ordinal_ ||
      physical_interface_id(route.port_ordinal) != ipv4_probe_interface_id_)
    return false;
  const auto *egress = port(route.port_ordinal);
  if (!egress || !egress->operational || !egress->ipv4_configured)
    return false;
  const auto first_hop_mtu =
      static_cast<std::uint32_t>(egress->mtu - packet::ethernet_header_octets);
  const auto update = ipv4_path_mtu_.update(
      ipv4_probe_destination_, ipv4_probe_interface_id_,
      icmp.parameter & 0xffffU, sent->total_length, first_hop_mtu, now);
  return update == ip::Ipv4PathMtuUpdate::decreased ||
         update == ip::Ipv4PathMtuUpdate::unchanged;
}

bool RouterForwarder::may_send_icmp_error(
    const packet::Frame &original, const packet::Ipv4View &ip) const noexcept {
  return may_send_icmp_error(original.view(), ip);
}

bool RouterForwarder::may_send_icmp_error(
    std::span<const std::uint8_t> original,
    const packet::Ipv4View &ip) const noexcept {
  const auto source = to_u32(ip.source);
  const auto destination = to_u32(ip.destination);
  const auto multicast = [](std::uint32_t address) {
    return (address & 0xf0000000U) == 0xe0000000U;
  };
  // Source: ietf.ipv4.router_requirements.rfc1812. Errors are suppressed for
  // invalid sources, multicast, limited broadcast and non-initial fragments.
  if (!source || source == 0xffffffffU || multicast(source) ||
      destination == 0xffffffffU || multicast(destination) ||
      ip.fragment_offset != 0U)
    return false;
  for (const auto &candidate : ports_) {
    // Directed broadcast depends on each configured prefix, not only the
    // limited broadcast constant. /31 and /32 do not define this broadcast.
    if (!candidate.configured || candidate.prefix_length >= 31U)
      continue;
    const auto broadcast =
        candidate.network | ~routing::prefix_mask(candidate.prefix_length);
    if (destination == broadcast)
      return false;
  }
  if (ip.protocol != 1U)
    return true;

  // A reassembly timeout sees fragment zero rather than a complete ICMP
  // message. Its checksum cannot be validated until all fragments arrive, but
  // RFC 1812 still forbids replying to an ICMP error. Fragment zero necessarily
  // carries the ICMP header, so its type is sufficient for this suppression
  // decision. Complete datagrams continue through the checksum-validating
  // parser. A truncated fragment is malformed and cannot trigger an error.
  std::uint8_t icmp_type{};
  if (ip.more_fragments) {
    const auto offset = static_cast<std::size_t>(
        packet::ethernet_header_octets + ip.header_length);
    if (ip.total_length < static_cast<std::uint16_t>(ip.header_length + 8U) ||
        offset >= original.size())
      return false;
    icmp_type = original[offset];
  } else {
    const auto icmp = packet::parse_icmp(original);
    if (!icmp)
      return false;
    icmp_type = icmp->type;
  }
  // ICMP informational messages may receive errors. ICMP error types may not
  // recursively trigger another error and form a network feedback loop.
  return icmp_type != 3U && icmp_type != 4U && icmp_type != 5U &&
         icmp_type != 11U && icmp_type != 12U;
}

bool RouterForwarder::may_send_ipv6_icmp_error(
    const packet::Frame &original, const packet::Ipv6View &ipv6,
    bool allow_multicast_destination) const noexcept {
  return may_send_ipv6_icmp_error(original.view(), ipv6,
                                  allow_multicast_destination);
}

bool RouterForwarder::may_send_ipv6_icmp_error(
    std::span<const std::uint8_t> original, const packet::Ipv6View &ipv6,
    bool allow_multicast_destination) const noexcept {
  // RFC 4443 suppresses errors for unspecified or multicast sources and for
  // non-initial fragments. Multicast destinations suppress ordinary errors,
  // with Packet Too Big being an explicit exception required for PMTUD.
  if (ip::is_unspecified(ipv6.source) || ip::is_multicast(ipv6.source) ||
      (ipv6.fragment && ipv6.fragment->offset != 0U) ||
      (ip::is_multicast(ipv6.destination) && !allow_multicast_destination))
    return false;
  if (ipv6.upper_layer_protocol != packet::ipv6_next_header_icmpv6)
    return true;
  const auto icmp = packet::parse_icmpv6(original);
  if (!icmp)
    return false;
  // ICMPv6 informational types have the high bit set. Error types 0 through
  // 127 must never recursively generate another ICMPv6 error.
  return icmp->type >= packet::icmpv6_informational_type_boundary;
}

void RouterForwarder::maybe_send_ipv4_redirect(
    const ForwardPort &ingress, const packet::EthernetView &ethernet,
    const packet::Ipv4View &ipv4, const routing::Route &route,
    const packet::Frame &invoking_packet, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  if (!ingress.icmp_redirects_enabled || !ingress.ipv4_configured ||
      !ingress.operational || route.local_system ||
      route.port_ordinal != ingress.ordinal ||
      !usable_sender_mac(ethernet.source) ||
      packet::ipv4_has_source_route(invoking_packet, ipv4))
    return;

  const auto source = to_u32(ipv4.source);
  const auto target =
      route.next_hop ? route.next_hop : to_u32(ipv4.destination);
  const auto mask = routing::prefix_mask(ingress.prefix_length);
  // Both addresses must be neighbors on this logical subnet. Merely sharing
  // the physical port is insufficient when multiple logical networks later
  // use the same attachment or when malformed control state is injected.
  if ((source & mask) != ingress.network ||
      (target & mask) != ingress.network || source == target)
    return;

  auto &limiter = ipv4_redirect_limiters_[ingress.ordinal];
  const auto interval =
      std::chrono::seconds{ingress.icmp_redirect_interval_seconds};
  if (!limiter.active || now >= limiter.window_end) {
    limiter.active = true;
    limiter.sent = 0U;
    limiter.window_end = now + interval;
  }
  if (limiter.sent >= ingress.icmp_redirect_maximum) {
    // `show router icmp` has no IPv4 Sent Discarded field. The rate-limited
    // control message therefore remains absent from sent message counters,
    // while the independently forwarded invoking datagram is not a drop.
    return;
  }

  const auto redirect = packet::icmp_host_redirect(
      invoking_packet, ingress.mac, ethernet.source, to_ipv4(ingress.address),
      ipv4.source, to_ipv4(target));
  if (!redirect)
    return;
  count_sent_icmpv4(ingress.ordinal, *redirect);
  if (emit(ingress.ordinal, *redirect, context, sink))
    ++limiter.sent;
}

void RouterForwarder::maybe_send_ipv6_redirect(
    const ForwardPort &ingress, const packet::EthernetView &ethernet,
    const packet::Ipv6View &ipv6, const routing::Ipv6Route &route,
    const packet::Frame &invoking_packet, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  if (!ingress.icmp6_redirects_enabled || !ingress.ipv6_configured ||
      !ingress.operational || route.physical_port_ordinal != ingress.ordinal ||
      ip::is_unspecified(ipv6.source) || ip::is_multicast(ipv6.source) ||
      ip::is_multicast(ipv6.destination) ||
      !usable_sender_mac(ethernet.source) ||
      !ipv6_dad_.preferred(route.interface_id, ingress.ipv6_link_local))
    return;

  const ip::Ipv6Prefix ingress_prefix{.network = ingress.ipv6_network,
                                      .length = ingress.ipv6_prefix_length};
  // RFC 4861 requires the invoking source to identify a neighbor. A global
  // source is a neighbor only when the receiving interface's connected prefix
  // contains it; a link-local source is scoped to this link by definition.
  if (!ip::is_link_local(ipv6.source) &&
      !ip::contains(ingress_prefix, ipv6.source))
    return;

  const auto target =
      ip::is_unspecified(route.next_hop) ? ipv6.destination : route.next_hop;
  // A better router is named by link-local address. A directly connected host
  // is named by the destination itself. Rejecting any third form prevents a
  // malformed control projection from emitting a Redirect a host must ignore.
  if (target != ipv6.destination && !ip::is_link_local(target))
    return;

  auto &limiter = ipv6_redirect_limiters_[ingress.ordinal];
  const auto interval =
      std::chrono::seconds{ingress.icmp6_redirect_interval_seconds};
  if (!limiter.active || now >= limiter.window_end) {
    limiter.active = true;
    limiter.sent = 0U;
    limiter.window_end = now + interval;
  }
  if (limiter.sent >= ingress.icmp6_redirect_maximum) {
    // Nokia defines Sent Discarded as messages rejected by the configured
    // interface ICMPv6 rate. It is not a generic forwarding drop counter.
    count_discarded_icmpv6(ingress.ordinal);
    return;
  }

  std::optional<packet::Mac> target_mac;
  // The Target Link-Layer Address option must come from the Neighbor Cache of
  // the interface on which the redirected destination or better next hop is
  // reachable. The route carries that logical L3 identity independently from
  // its physical egress port. Looking up by the port namespace would miss a
  // neighbor learned on an IES service interface attached to the same wire and
  // could also select an entry belonging to another SAP on that port.
  if (const auto neighbor = ipv6_neighbors_.find(route.interface_id, target))
    target_mac = neighbor->mac;
  const auto redirect = packet::nd::redirect(
      ingress.mac, ethernet.source, ingress.ipv6_link_local, ipv6.source,
      target, ipv6.destination, target_mac, invoking_packet);
  // A failed encoder or full egress ring means no Redirect was sent and must
  // not consume the configured rate allowance. The transit packet has already
  // followed its independent forwarding outcome.
  if (redirect) {
    count_sent_icmpv6(ingress.ordinal, *redirect);
    if (emit_ipv6_interface(route.interface_id, ingress.ordinal, *redirect,
                            context, sink))
      ++limiter.sent;
  }
}

void RouterForwarder::service_dhcpv6_relay(std::uint16_t ingress_port,
                                           std::uint64_t ingress_interface_id,
                                           void *context, EgressSink sink,
                                           EgressAdmission admission,
                                           Clock::time_point now) noexcept {
  if (!dhcpv6_relay_socket_)
    return;
  const auto received =
      udp_.receive(*dhcpv6_relay_socket_, dhcpv6_receive_scratch_);
  if (received.status != transport::UdpReceiveStatus::delivered)
    return;
  const auto payload =
      std::span<const std::uint8_t>{dhcpv6_receive_scratch_}.first(
          received.metadata.payload_octets);
  // A Relay-reply returns through a server-facing routed interface and uses
  // its encapsulated Interface-Id to select the client-facing service. Client
  // messages and nested Relay-forward packets instead require the UDP ingress
  // identity to name the configured logical relay on this physical port.
  const auto message = packet::dhcpv6::parse(payload);
  const bool relay_reply =
      message && message->type == static_cast<std::uint8_t>(
                                      packet::dhcpv6::MessageType::relay_reply);
  if (received.metadata.interface_id != ingress_interface_id ||
      (!relay_reply && [&] {
        const auto *relay_interface =
            dhcpv6_relay_.interface(ingress_interface_id);
        return !relay_interface ||
               relay_interface->physical_port_ordinal != ingress_port;
      }())) {
    drop(ForwardDrop::malformed);
    return;
  }
  if (message && !message->relay && !relay_reply) {
    // Correlation is captured from the direct client-facing Ethernet frame.
    // The DUID remains opaque by RFC 9915 and is never decoded into a MAC.
    // Failure only disables neighbor derivation for this transaction; the
    // stateless relay decision still processes the valid DHCP message.
    static_cast<void>(dhcpv6_relay_leases_.observe_client(
        ingress_interface_id, received.metadata.source_ipv6,
        received.metadata.source_mac, payload, now));
  }
  const auto decision = dhcpv6_relay_.decide(
      {.ingress_interface_id = received.metadata.interface_id,
       .source = received.metadata.source_ipv6,
       .destination = received.metadata.destination_ipv6,
       .source_port = received.metadata.source_port,
       .destination_port = received.metadata.destination_port,
       .payload = payload},
      dhcpv6_relay_scratch_);
  const auto relayed =
      std::span<const std::uint8_t>{dhcpv6_relay_scratch_}.first(
          decision.payload_octets);
  if (decision.status == dhcpv6::RelayDecisionStatus::forward_upstream) {
    // RFC 9915 sends a copy to every configured destination. Each copy is a
    // separately encoded UDP and IPv6 packet and therefore performs its own
    // route lookup, source selection, ND and queue admission.
    for (const auto &destination : decision.upstream_destinations)
      static_cast<void>(originate_dhcpv6_relay(decision, destination, relayed,
                                               context, sink, admission, now));
  } else if (decision.status ==
             dhcpv6::RelayDecisionStatus::forward_downstream) {
    const auto inner = packet::dhcpv6::parse(relayed);
    const bool binding_reply =
        inner && !inner->relay &&
        inner->type ==
            static_cast<std::uint8_t>(packet::dhcpv6::MessageType::reply);
    const auto *binding_interface =
        dhcpv6_relay_.interface(decision.egress_interface_id);
    if (binding_reply && binding_interface &&
        binding_interface->lease_population_limit != 0U) {
      const auto plan = dhcpv6_relay_leases_.prepare_reply(
          decision.egress_interface_id, decision.destination,
          received.metadata.source_ipv6, received.metadata.interface_id,
          relayed, now);
      if (plan.status == dhcpv6::RelayLeaseReplyStatus::lease_limit_exceeded) {
        // SR OS discards subsequent Reply messages when lease-populate has
        // reached its configured maximum. Forwarding the packet while refusing
        // only the operational row would expose behavior the device does not.
        drop(ForwardDrop::dhcpv6_lease_limit);
        return;
      }
      if (plan.status != dhcpv6::RelayLeaseReplyStatus::accepted) {
        drop(plan.status == dhcpv6::RelayLeaseReplyStatus::resource_exhausted
                 ? ForwardDrop::dhcpv6_lease_state_full
                 : ForwardDrop::malformed);
        return;
      }
      if (!plan.mutations.empty() &&
          !dhcpv6_relay_routes_.prepare(plan.mutations,
                                        dhcpv6_relay_.interfaces())) {
        dhcpv6_relay_leases_.discard_prepared();
        drop(ForwardDrop::dhcpv6_lease_state_full);
        return;
      }

      dhcpv6_neighbor_edits_.clear();
      const auto *relay_interface = binding_interface;
      const auto egress_view =
          relay_interface
              ? ipv6_interface(relay_interface->interface_id,
                               relay_interface->physical_port_ordinal)
              : std::nullopt;
      std::size_t projected_dynamic =
          relay_interface
              ? ipv6_neighbors_.dynamic_size(relay_interface->interface_id)
              : 0U;
      for (const auto &mutation : plan.mutations) {
        const auto &lease = mutation.record;
        const bool address_lease =
            lease.protocol == dhcpv6::RelayLeaseProtocol::non_temporary ||
            lease.protocol == dhcpv6::RelayLeaseProtocol::temporary;
        if (!relay_interface || !egress_view ||
            !relay_interface->neighbor_resolution || !address_lease ||
            !lease.has_client_mac ||
            !ip::contains(relay_interface->client_prefix, lease.value))
          continue;
        if (dhcpv6_neighbor_edits_.size() ==
            dhcpv6_neighbor_edits_.capacity()) {
          dhcpv6_relay_leases_.discard_prepared();
          dhcpv6_relay_routes_.discard_prepared();
          drop(ForwardDrop::dhcpv6_lease_state_full);
          return;
        }
        const auto existing =
            ipv6_neighbors_.find(relay_interface->interface_id, lease.value);
        if (mutation.kind == dhcpv6::RelayLeaseMutationKind::remove) {
          if (existing && !existing->is_static && projected_dynamic != 0U)
            --projected_dynamic;
          dhcpv6_neighbor_edits_.push_back(
              {.kind = Ipv6NeighborBatchKind::remove_dynamic,
               .interface_id = relay_interface->interface_id,
               .address = lease.value});
        } else {
          if (!existing)
            ++projected_dynamic;
          dhcpv6_neighbor_edits_.push_back(
              {.kind = Ipv6NeighborBatchKind::learn_stale,
               .interface_id = relay_interface->interface_id,
               .address = lease.value,
               .mac = lease.client_mac,
               .stale_time =
                   std::chrono::seconds{egress_view->nd_stale_time_seconds},
               .proactive_refresh = address_scope_selected(
                   egress_view->ipv6_proactive_refresh, lease.value)});
        }
      }
      if (relay_interface && egress_view &&
          egress_view->ipv6_neighbor_limit_configured &&
          !egress_view->ipv6_neighbor_limit_log_only &&
          projected_dynamic > egress_view->ipv6_neighbor_limit) {
        dhcpv6_relay_leases_.discard_prepared();
        dhcpv6_relay_routes_.discard_prepared();
        drop(ForwardDrop::dhcpv6_lease_state_full);
        return;
      }
      if (!ipv6_neighbors_.apply_batch(dhcpv6_neighbor_edits_, now)) {
        dhcpv6_relay_leases_.discard_prepared();
        dhcpv6_relay_routes_.discard_prepared();
        drop(ForwardDrop::dhcpv6_lease_state_full);
        return;
      }
      if (!plan.mutations.empty() &&
          (!dhcpv6_relay_routes_.commit_prepared() ||
           !dhcpv6_relay_leases_.commit_prepared())) {
        // All failure modes were preflighted. Reaching this branch indicates
        // an owner invariant violation, so do not forward a Reply whose
        // derived lease generation could not be published completely.
        drop(ForwardDrop::dhcpv6_lease_state_full);
        return;
      }
      if (plan.mutations.empty())
        dhcpv6_relay_leases_.discard_prepared();
    }
    static_cast<void>(originate_dhcpv6_relay(
        decision,
        {.address = decision.destination,
         .scope_interface_id = decision.egress_interface_id},
        relayed, context, sink, admission, now));
  }
  // Every other decision is a protocol discard. It generates neither an ICMP
  // port error nor a successful no-op because UDP 547 is owned by the relay
  // application and RFC 9915 defines malformed and hop-limit discards locally.
}

bool RouterForwarder::originate_dhcpv6_relay(
    const dhcpv6::RelayDecision &decision,
    const dhcpv6::RelayDestination &destination,
    std::span<const std::uint8_t> payload, void *context, EgressSink sink,
    EgressAdmission admission, Clock::time_point now) noexcept {
  if (!dhcpv6_relay_socket_ || !sink ||
      decision.source_port != packet::dhcpv6::server_port ||
      decision.destination_port == 0U ||
      ip::is_unspecified(destination.address)) {
    drop(ForwardDrop::malformed);
    return false;
  }

  std::uint16_t egress_ordinal{};
  std::uint64_t egress_interface_id{};
  packet::Ipv6 next_hop{};
  if (destination.scope_interface_id != 0U) {
    const auto *scoped =
        dhcpv6_relay_.interface(destination.scope_interface_id);
    if (!scoped) {
      drop(ForwardDrop::no_route);
      return false;
    }
    egress_ordinal = scoped->physical_port_ordinal;
    egress_interface_id = scoped->interface_id;
    next_hop = destination.address;
  } else {
    routing::Ipv6Route route;
    bool blackhole{};
    if (!lookup_ipv6_route(destination.address, route, blackhole)) {
      drop(ForwardDrop::no_route);
      return false;
    }
    if (blackhole) {
      drop(ForwardDrop::blackhole);
      return false;
    }
    egress_ordinal = route.physical_port_ordinal;
    egress_interface_id = route.interface_id;
    next_hop = ip::is_unspecified(route.next_hop) ? destination.address
                                                  : route.next_hop;
  }
  const auto egress_view = ipv6_interface(egress_interface_id, egress_ordinal);
  const auto *egress = egress_view ? &*egress_view : nullptr;
  if (!egress || !egress->operational || !egress->ipv6_configured ||
      !ipv6_dad_.preferred(egress_interface_id, egress->ipv6_link_local)) {
    drop(ForwardDrop::port_down);
    return false;
  }

  // Router source selection uses the same RFC 6724 mechanism as a host. The
  // egress interface contributes its preferred global and link-local
  // addresses; no topology lookup or remote address object participates.
  packet::Ipv6 source{};
  if (decision.has_source_address) {
    bool source_is_preferred{};
    // SR OS permits an explicit relay source that is not attached to the
    // server-facing egress. It must still be a configured, preferred local
    // address. Searching owner-local interface projections preserves that
    // distinction without consulting topology or accepting an arbitrary
    // spoofed address from CLI configuration.
    if (const auto *native =
            native_ipv6_addresses_.owner(decision.source_address))
      source_is_preferred =
          ipv6_dad_.preferred(native->interface_id, native->address);
    if (!source_is_preferred)
      for (const auto &candidate : ports_) {
        const auto candidate_interface =
            physical_interface_id(candidate.ordinal);
        if (candidate.configured && candidate.ipv6_configured &&
            candidate.ipv6_link_local == decision.source_address &&
            ipv6_dad_.preferred(candidate_interface, decision.source_address)) {
          source_is_preferred = true;
          break;
        }
      }
    if (!source_is_preferred)
      for (const auto &candidate : sap_forwarding_.interfaces())
        if (candidate.configured &&
            (candidate.address == decision.source_address ||
             candidate.link_local == decision.source_address) &&
            ipv6_dad_.preferred(candidate.interface_id,
                                decision.source_address)) {
          source_is_preferred = true;
          break;
        }
    if (!source_is_preferred) {
      drop(ForwardDrop::port_down);
      return false;
    }
    source = decision.source_address;
  } else {
    std::array<ip::Ipv6SourceCandidate,
               device_catalog::network_interface_ip_addresses + 1U>
        candidates{};
    std::size_t candidate_count{};
    for (const auto &address : native_ipv6_addresses_.records())
      if (address.interface_id == egress_interface_id &&
          ipv6_dad_.preferred(address.interface_id, address.address))
        candidates[candidate_count++] = {.address = address.address,
                                         .interface_id = address.interface_id,
                                         .prefix_length = address.prefix_length,
                                         .preferred = true};
    candidates[candidate_count++] = {.address = egress->ipv6_link_local,
                                     .interface_id = egress_interface_id,
                                     .prefix_length = 64U,
                                     .preferred = true};
    const auto selected = ip::select_ipv6_source(
        std::span<const ip::Ipv6SourceCandidate>{candidates}.first(
            candidate_count),
        {.destination = destination.address,
         .outgoing_interface_id = egress_interface_id,
         .prefer_temporary = false});
    if (!selected) {
      drop(ForwardDrop::port_down);
      return false;
    }
    source = candidates[*selected].address;
  }

  packet::Mac destination_mac{};
  Ipv6Resolution resolution{.status = Ipv6ResolutionStatus::resolved};
  if (ip::is_multicast(destination.address)) {
    destination_mac = packet::ipv6_multicast_mac(destination.address);
  } else {
    resolution =
        resolve_ipv6_neighbor(*egress, egress_interface_id, next_hop, now);
    if (resolution.status == Ipv6ResolutionStatus::table_full) {
      drop(ForwardDrop::neighbor_pending_full);
      return false;
    }
    destination_mac = resolution.mac;
  }

  auto udp_storage =
      std::span<std::uint8_t>{ipv6_udp_datagram_scratch_}.subspan(
          packet::ethernet_header_octets + packet::ipv6_header_octets);
  const auto encoded_udp = udp_.encode_ipv6(
      *dhcpv6_relay_socket_, source, destination.address, egress_interface_id,
      decision.destination_port, payload, udp_storage);
  if (encoded_udp.status != transport::UdpSendStatus::encoded) {
    drop(ForwardDrop::malformed);
    return false;
  }
  const auto hop_limit = dhcpv6::relay_hop_limit_override(destination.address)
                             .value_or(device_catalog::default_ip_hop_limit);
  const auto datagram_octets = packet::encode_ipv6_ethernet_datagram(
      ipv6_udp_datagram_scratch_, egress->mac, destination_mac, source,
      destination.address, packet::ipv6_next_header_udp, hop_limit,
      udp_storage.first(encoded_udp.datagram_octets));
  if (!datagram_octets) {
    drop(ForwardDrop::malformed);
    return false;
  }

  const auto first_hop_mtu =
      static_cast<std::uint16_t>(egress->mtu - packet::ethernet_header_octets);
  const auto path_mtu = static_cast<std::uint16_t>(ipv6_path_mtu_.estimate(
      destination.address, egress_interface_id, first_hop_mtu));
  const auto ip_octets = *datagram_octets - packet::ethernet_header_octets;
  const bool fragmented = ip_octets > path_mtu;
  std::size_t frame_count{1U};
  if (fragmented) {
    const auto required = packet::ipv6_fragment_count(
        std::span<const std::uint8_t>{ipv6_udp_datagram_scratch_}.first(
            *datagram_octets),
        path_mtu);
    if (!required || *required > packet::maximum_ipv6_datagram_fragments) {
      drop(ForwardDrop::mtu_exceeded);
      return false;
    }
    frame_count = *required;
  }

  if (ip::is_multicast(destination.address) ||
      resolution.status == Ipv6ResolutionStatus::resolved) {
    if (admission && !admission(context, egress->ordinal, frame_count)) {
      drop(ForwardDrop::egress_queue_full);
      return false;
    }
    if (!fragmented) {
      packet::Frame frame;
      std::copy_n(ipv6_udp_datagram_scratch_.begin(), *datagram_octets,
                  frame.bytes.begin());
      frame.length = static_cast<std::uint16_t>(*datagram_octets);
      return send_resolved_ipv6(frame, *egress, egress_interface_id,
                                destination_mac, false, context, sink, now);
    }
    struct ResolvedFragmentContext {
      RouterForwarder *owner{};
      const ForwardPort *egress{};
      std::uint64_t interface_id{};
      packet::Mac destination_mac{};
      void *sink_context{};
      EgressSink sink{};
      Clock::time_point now{};
    } fragment_context{
        this, egress, egress_interface_id, destination_mac, context, sink, now};
    const auto fragment_sink =
        +[](void *opaque, const packet::Frame &frame) noexcept {
          auto &value = *static_cast<ResolvedFragmentContext *>(opaque);
          return value.owner->send_resolved_ipv6(
              frame, *value.egress, value.interface_id, value.destination_mac,
              false, value.sink_context, value.sink, value.now);
        };
    const auto identification = ipv6_fragment_identification_++;
    const auto emitted = packet::fragment_ipv6_datagram(
        std::span<const std::uint8_t>{ipv6_udp_datagram_scratch_}.first(
            *datagram_octets),
        path_mtu, identification, &fragment_context, fragment_sink);
    if (!emitted || *emitted != frame_count) {
      drop(ForwardDrop::egress_queue_full);
      return false;
    }
    return true;
  }

  const auto available_pending = static_cast<std::size_t>(
      std::count_if(pending_.begin(), pending_.end(),
                    [](const auto &entry) { return !entry.valid; }));
  if (available_pending < frame_count) {
    drop(ForwardDrop::neighbor_pending_full);
    return false;
  }
  if (resolution.status == Ipv6ResolutionStatus::solicitation_required &&
      admission && !admission(context, egress->ordinal, 1U)) {
    drop(ForwardDrop::egress_queue_full);
    return false;
  }

  std::array<Pending *, packet::maximum_ipv6_datagram_fragments> inserted{};
  std::size_t inserted_count{};
  const auto retain = [&](const packet::Frame &frame) noexcept {
    const auto free =
        std::find_if(pending_.begin(), pending_.end(),
                     [](const auto &entry) { return !entry.valid; });
    if (free == pending_.end() || inserted_count == inserted.size())
      return false;
    *free = {.valid = true,
             .transit = false,
             .ipv6 = true,
             // Pending frames are released only by an NA learned in this
             // logical L3 scope. The physical port is insufficient because
             // several IES SAPs can share the same wire without sharing an
             // IPv6 Neighbor Cache or an Interface-Id return path.
             .interface_id = egress_interface_id,
             .port_ordinal = egress->ordinal,
             .next_hop_ipv6 = next_hop};
    packet::copy_frame(free->frame, frame);
    inserted[inserted_count++] = &*free;
    return true;
  };
  bool retained{};
  if (!fragmented) {
    packet::Frame frame;
    std::copy_n(ipv6_udp_datagram_scratch_.begin(), *datagram_octets,
                frame.bytes.begin());
    frame.length = static_cast<std::uint16_t>(*datagram_octets);
    retained = retain(frame);
  } else {
    struct PendingFragmentContext {
      const decltype(retain) *append{};
    } fragment_context{&retain};
    const auto pending_sink =
        +[](void *opaque, const packet::Frame &frame) noexcept {
          const auto &value = *static_cast<PendingFragmentContext *>(opaque);
          return (*value.append)(frame);
        };
    const auto identification = ipv6_fragment_identification_++;
    const auto count = packet::fragment_ipv6_datagram(
        std::span<const std::uint8_t>{ipv6_udp_datagram_scratch_}.first(
            *datagram_octets),
        path_mtu, identification, &fragment_context, pending_sink);
    retained = count && *count == frame_count;
  }
  if (!retained) {
    for (std::size_t index = 0; index < inserted_count; ++index)
      *inserted[index] = {};
    drop(ForwardDrop::neighbor_pending_full);
    return false;
  }
  if (resolution.status == Ipv6ResolutionStatus::solicitation_required) {
    const auto request = packet::nd::neighbor_solicitation(
        egress->mac, egress->ipv6_link_local, next_hop);
    count_sent_icmpv6(egress->ordinal, request);
    if (!emit_ipv6_interface(egress_interface_id, egress->ordinal, request,
                             context, sink)) {
      for (std::size_t index = 0; index < inserted_count; ++index)
        *inserted[index] = {};
      return false;
    }
  }
  return true;
}

void RouterForwarder::receive(std::uint16_t ingress_port,
                              const packet::Frame &wire_frame, void *context,
                              EgressSink sink, Clock::time_point now,
                              void *punt_context, PuntObserver punt_observer,
                              EgressAdmission admission) noexcept {
  const auto *physical_ingress = port(ingress_port);
  if (!physical_ingress || !physical_ingress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  packet::Frame service_frame;
  const auto classified =
      sap_forwarding_.ingress(ingress_port, wire_frame, service_frame);
  std::optional<ForwardPort> service_ingress;
  std::uint64_t ingress_ipv6_interface_id{};
  const packet::Frame *selected_frame = &wire_frame;
  if (classified.status == service::SapIngressStatus::matched) {
    service_ingress =
        ipv6_interface(classified.logical_interface_id, ingress_port);
    if (!service_ingress) {
      drop(ForwardDrop::malformed);
      return;
    }
    ingress_ipv6_interface_id = classified.logical_interface_id;
    selected_frame = &service_frame;
  } else if (sap_forwarding_.has_physical_port(ingress_port)) {
    // Once a port has a service classifier, an unknown or malformed tag stack
    // cannot fall through into the native routed interface. That would leak a
    // customer frame across service ownership boundaries.
    drop(classified.status == service::SapIngressStatus::malformed
             ? ForwardDrop::malformed
             : ForwardDrop::not_for_router);
    return;
  } else {
    // Untagged native packets retain the physical routed-interface scope.
    // DHCPv6 relay is an application on that interface, not an L2 classifier:
    // letting its opaque Interface-Id replace this value would move ND, ICMPv6
    // and transit traffic into a different RFC 4007 zone. The UDP dispatcher
    // below selects the relay identity only after validating port 547 and the
    // DHCPv6 message kind.
    ingress_ipv6_interface_id = physical_interface_id(ingress_port);
  }
  const auto *ingress = service_ingress ? &*service_ingress : physical_ingress;
  const auto &frame = *selected_frame;
  const auto ethernet = packet::parse_ethernet(frame);
  if (!ethernet) {
    drop(ForwardDrop::malformed);
    return;
  }
  std::optional<packet::Ipv6View> ipv6;
  bool layer_two_local =
      packet::ethernet_for_local(ethernet->destination, ingress->mac);
  if (ethernet->ether_type == 0x86dd) {
    ipv6 = packet::parse_ipv6(frame);
    // IPv6 has no broadcast. A multicast frame is accepted only when the
    // destination MAC matches the IPv6 mapping and this router joined the
    // destination group on the receiving interface.
    layer_two_local = ethernet->destination == ingress->mac ||
                      (ipv6 && ip::is_multicast(ipv6->destination) &&
                       ethernet->destination ==
                           packet::ipv6_multicast_mac(ipv6->destination) &&
                       accepts_ipv6_multicast(*ingress, ipv6->destination));
  }
  if (!layer_two_local) {
    drop(ForwardDrop::not_for_router);
    return;
  }

  if (ethernet->ether_type == 0x0806) {
    const auto arp = packet::parse_arp(frame);
    if (!arp) {
      drop(ForwardDrop::malformed);
      return;
    }
    // ARP is terminated by the router adjacency process rather than forwarded
    // as IPv4. The observer receives the original encoded ingress frame and is
    // diagnostics-only, so capture failure cannot alter neighbor learning.
    if (punt_observer)
      punt_observer(punt_context, ingress_port, frame);
    // An IPv6-only routed interface has no local ARP protocol instance. It
    // consumes an L2-addressed ARP frame without learning or replying from the
    // all-zero placeholder used by the family-independent port projection.
    if (!ingress->ipv4_configured)
      return;
    const auto sender = to_u32(arp->sender_ip);
    // RFC 826 merges the sender before examining request versus reply. Pending
    // release therefore precedes the optional reply to a request for us.
    learn(ingress_port, sender, arp->sender_mac, now);
    flush_pending(ingress_port, sender, arp->sender_mac, context, sink, now);
    if (arp->operation == 1U && to_u32(arp->target_ip) == ingress->address) {
      const auto reply =
          packet::arp_reply(ingress->mac, to_ipv4(ingress->address),
                            arp->sender_mac, arp->sender_ip);
      static_cast<void>(emit(ingress_port, reply, context, sink));
    }
    return;
  }
  if (ethernet->ether_type == 0x86dd) {
    if (!ipv6) {
      drop(ForwardDrop::malformed);
      return;
    }

    // Resolve the complete native address generation before extension-header
    // policy is evaluated. Secondary addresses are local endpoints too; using
    // only ForwardPort's selected-primary cache would misclassify their Hop-by-
    // Hop unknown-option handling and omit their received ICMPv6 counters.
    const auto *native_owner = native_ipv6_addresses_.owner(ipv6->destination);
    const bool native_destination_local =
        native_owner &&
        ipv6_dad_.preferred(native_owner->interface_id, native_owner->address);
    const bool ipv6_destination_local =
        ip::is_multicast(ipv6->destination) || native_destination_local ||
        (service_ingress &&
         ((ingress->ipv6_address == ipv6->destination &&
           ipv6_dad_.preferred(ingress_ipv6_interface_id,
                               ingress->ipv6_address)) ||
          (ingress->ipv6_link_local == ipv6->destination &&
           ipv6_dad_.preferred(ingress_ipv6_interface_id,
                               ingress->ipv6_link_local)))) ||
        std::any_of(ports_.begin(), ports_.end(), [&](const auto &candidate) {
          return candidate.configured && candidate.ipv6_configured &&
                 ((candidate.ipv6_address == ipv6->destination &&
                   ipv6_dad_.preferred(physical_interface_id(candidate.ordinal),
                                       candidate.ipv6_address)) ||
                  (candidate.ipv6_link_local == ipv6->destination &&
                   ipv6_dad_.preferred(physical_interface_id(candidate.ordinal),
                                       candidate.ipv6_link_local)));
        });
    const auto extension_result = packet::validate_ipv6_extensions(
        frame, *ipv6, ipv6_destination_local, false);
    if (extension_result.action != packet::Ipv6ExtensionAction::accept) {
      if (extension_result.action ==
          packet::Ipv6ExtensionAction::parameter_problem)
        send_ipv6_parameter_problem(
            frame, *ipv6, extension_result.code, extension_result.pointer,
            extension_result.allow_multicast_response, context, sink, now);
      drop(ForwardDrop::malformed);
      return;
    }

    // Count only messages delivered to this router's ICMPv6 layer. Transit
    // traffic is not a local receive. Non-atomic fragments wait for endpoint
    // reassembly so one original message contributes exactly one counter.
    const bool complete_icmpv6 =
        !ipv6->authentication_header_present &&
        ipv6->upper_layer_protocol == packet::ipv6_next_header_icmpv6 &&
        (!ipv6->fragment ||
         (ipv6->fragment->offset == 0U && !ipv6->fragment->more_fragments));
    if (ipv6_destination_local && complete_icmpv6)
      count_received_icmpv6(ingress_port, frame.view(), *ipv6);

    // MLD is consumed only by an explicitly configured router interface. All
    // state enters through validated frame bytes; no host membership object or
    // topology edge is visible to this forwarding owner.
    auto *mld_state = mld(ingress_port);
    const bool require_mld_router_alert =
        !mld_state || mld_state->intent.router_alert_check;
    const auto reject_mld_scope = [&](const packet::Ipv6 &group) {
      if (!mld_state || !ip::is_multicast(group))
        return false;
      const auto scope = static_cast<std::uint8_t>(group[1U] & 0x0fU);
      // RFC 4291 assigns scope 1 to the originating node only. Values 0, 3
      // and 15 are reserved. SR OS exposes distinct packet counters for these
      // two cases, and neither can create a link listener membership.
      if (scope == 1U) {
        mld_state->protocol.count_receive(MldReceiveStatistic::local_scope);
        mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
        return true;
      }
      if (scope == 0U || scope == 3U || scope == 15U) {
        mld_state->protocol.count_receive(MldReceiveStatistic::reserved_scope);
        mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
        return true;
      }
      return false;
    };
    const auto translated_sources = [&](const packet::Ipv6 &group)
        -> std::optional<std::span<const packet::Ipv6>> {
      if (!mld_state || mld_state->translations.empty())
        return std::span<const packet::Ipv6>{};
      auto &scratch = mld_state->translation_scratch;
      scratch.clear();
      for (const auto &entry : mld_state->translations) {
        if (group < entry.start || entry.end < group ||
            std::find(scratch.begin(), scratch.end(), entry.source) !=
                scratch.end())
          continue;
        // One group cannot exceed the generated router source-state capacity.
        // Returning nullopt rejects the entire Report and records explicit
        // resource exhaustion instead of learning a truncated translation.
        if (scratch.size() == device_catalog::mld_router_sources_per_group)
          return std::nullopt;
        scratch.push_back(entry.source);
      }
      return std::span<const packet::Ipv6>{scratch};
    };
    const auto policy_accepts = [&](const packet::Ipv6 &group,
                                    const std::optional<packet::Ipv6> &source) {
      const auto action =
          mld_state ? mld_state->import_policy.evaluate(group, source)
                    : mld::ImportPolicyAction::accept;
      if (!mld_state || action == mld::ImportPolicyAction::accept ||
          action == mld::ImportPolicyAction::next_policy)
        return true;
      // Nokia reports policy drops separately from malformed and resource
      // failures. Count both the policy reason and the aggregate dropped
      // packet because no listener transition will be presented to the local
      // MLD state-machine owner.
      mld_state->protocol.count_receive(MldReceiveStatistic::policy_drop);
      mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
      return false;
    };
    if (const auto query =
            packet::mld::parse_query(frame, require_mld_router_alert)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      if (mld_state) {
        mld_state->protocol.count_receive(MldReceiveStatistic::query);
        // A version-1 interface does not run the version-2 state machine.
        // The packet remains a valid MLD Query for statistics, but its v2
        // controls cannot alter the v1 compatibility state.
        if (mld_state->intent.version == 1U && query->version_two) {
          mld_state->protocol.count_receive(MldReceiveStatistic::wrong_version);
          return;
        }
        if (!ip::is_unspecified(query->multicast_address) &&
            reject_mld_scope(query->multicast_address))
          return;
      }
      if (mld_state && mld_state->running) {
        std::array<packet::Ipv6, device_catalog::mld_sources_per_group>
            sources{};
        bool valid_sources = true;
        for (std::size_t index = 0; index < query->source_count; ++index) {
          const auto source = packet::mld::query_source(frame, *query, index);
          if (!source) {
            valid_sources = false;
            break;
          }
          sources[index] = *source;
        }
        if (valid_sources)
          mld_state->protocol.observe_query(
              *query,
              std::span<const packet::Ipv6>{sources.data(),
                                            query->source_count},
              now);
      }
      return;
    }
    if (const auto version_one =
            packet::mld::parse_version_one(frame, require_mld_router_alert)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      if (mld_state)
        mld_state->protocol.count_receive(
            version_one->type == packet::mld::version_one_report_type
                ? MldReceiveStatistic::report_v1
                : MldReceiveStatistic::done);
      if (reject_mld_scope(version_one->multicast_address))
        return;
      if (mld_state && mld_state->running) {
        const auto sources =
            version_one->type == packet::mld::version_one_report_type
                ? translated_sources(version_one->multicast_address)
                : std::optional<std::span<const packet::Ipv6>>{
                      std::span<const packet::Ipv6>{}};
        if (!sources) {
          mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
          drop(ForwardDrop::mld_resource_full);
          return;
        }
        // A Done must always be allowed to age existing receiver state. An
        // import policy controls admission of reports, not cleanup, otherwise
        // changing a policy could strand a membership until its full timer
        // expired. For a translated Report each generated (S,G) is evaluated
        // independently and the bounded pre-reserved scratch carries only the
        // accepted source set to the listener owner.
        std::span<const packet::Ipv6> admitted_sources = *sources;
        if (version_one->type == packet::mld::version_one_report_type) {
          if (sources->empty()) {
            if (!policy_accepts(version_one->multicast_address, std::nullopt))
              return;
          } else {
            auto &scratch = mld_state->policy_source_scratch;
            scratch.clear();
            for (const auto &source : *sources)
              if (const auto action = mld_state->import_policy.evaluate(
                      version_one->multicast_address, source);
                  action == mld::ImportPolicyAction::accept ||
                  action == mld::ImportPolicyAction::next_policy)
                scratch.push_back(source);
            if (scratch.empty()) {
              mld_state->protocol.count_receive(
                  MldReceiveStatistic::policy_drop);
              mld_state->protocol.count_receive(
                  MldReceiveStatistic::packet_drop);
              return;
            }
            admitted_sources = scratch;
          }
        }
        const bool translated = !admitted_sources.empty();
        const bool accepted =
            translated
                ? mld_state->protocol.observe_translated_version_one_report(
                      *version_one, admitted_sources, now)
                : mld_state->protocol.observe_version_one(*version_one, now);
        if (!accepted)
          mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
        if (!accepted)
          drop(ForwardDrop::mld_resource_full);
      }
      return;
    }
    if (const auto report = packet::mld::parse_version_two_report(
            frame, require_mld_router_alert)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      if (mld_state) {
        mld_state->protocol.count_receive(MldReceiveStatistic::report_v2);
        if (mld_state->intent.version == 1U) {
          mld_state->protocol.count_receive(MldReceiveStatistic::wrong_version);
          return;
        }
      }
      // RFC 3590 requires a multicast router to discard unspecified-source
      // Reports. Snooping bridges may still consume the same frame elsewhere.
      if (!mld_state || !mld_state->running ||
          !ip::is_link_local(report->source))
        return;
      // A v2 report can carry several records but scope statistics count the
      // packet, not records. Scan the already bounded record list first and
      // stop after assigning the single applicable counter.
      for (std::size_t index = 0; index < report->record_count; ++index) {
        const auto record = packet::mld::report_record(frame, *report, index);
        if (!record) {
          mld_state->protocol.count_receive(MldReceiveStatistic::bad_encoding);
          return;
        }
        if (reject_mld_scope(record->multicast_address))
          return;
      }
      for (std::size_t record_index = 0; record_index < report->record_count;
           ++record_index) {
        const auto record =
            packet::mld::report_record(frame, *report, record_index);
        if (!record) {
          drop(ForwardDrop::malformed);
          return;
        }
        std::array<packet::Ipv6, device_catalog::mld_sources_per_group>
            sources{};
        for (std::size_t source_index = 0; source_index < record->source_count;
             ++source_index) {
          const auto source =
              packet::mld::record_source(frame, *record, source_index);
          if (!source) {
            drop(ForwardDrop::malformed);
            return;
          }
          sources[source_index] = *source;
        }
        auto effective_record = *record;
        std::span<const packet::Ipv6> effective_sources{sources.data(),
                                                         record->source_count};
        const bool star_report =
            record->source_count == 0U &&
            (record->type == packet::mld::RecordType::mode_is_exclude ||
             record->type == packet::mld::RecordType::change_to_exclude);
        if (star_report) {
          const auto translated = translated_sources(record->multicast_address);
          if (!translated) {
            mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
            drop(ForwardDrop::mld_resource_full);
            return;
          }
          if (!translated->empty()) {
            effective_record.type = packet::mld::RecordType::mode_is_include;
            effective_record.source_count =
                static_cast<std::uint16_t>(translated->size());
            effective_sources = *translated;
          }
        }
        // Policy filtering happens after SSM translation because the Nokia
        // policy sees the effective source-address carried into multicast
        // admission. Source-less (*,G) records are evaluated once. A record
        // with source tuples keeps only accepted tuples, and a fully rejected
        // tuple set is discarded rather than reinterpreted as an empty INCLUDE
        // or EXCLUDE transition with different RFC 3810 meaning.
        if (effective_sources.empty()) {
          if (!policy_accepts(effective_record.multicast_address, std::nullopt))
            continue;
        } else {
          auto &scratch = mld_state->policy_source_scratch;
          scratch.clear();
          for (const auto &source : effective_sources)
            if (const auto action = mld_state->import_policy.evaluate(
                    effective_record.multicast_address, source);
                action == mld::ImportPolicyAction::accept ||
                action == mld::ImportPolicyAction::next_policy)
              scratch.push_back(source);
          if (scratch.empty()) {
            mld_state->protocol.count_receive(
                MldReceiveStatistic::policy_drop);
            mld_state->protocol.count_receive(
                MldReceiveStatistic::packet_drop);
            continue;
          }
          effective_record.source_count =
              static_cast<std::uint16_t>(scratch.size());
          effective_sources = scratch;
        }
        if (!mld_state->protocol.observe_record(effective_record,
                                                effective_sources, now)) {
          mld_state->protocol.count_receive(MldReceiveStatistic::packet_drop);
          drop(ForwardDrop::mld_resource_full);
          return;
        }
      }
      return;
    }

    // Strict decoders above distinguish valid MLD from malformed messages.
    // The diagnostic pass classifies only rejected bytes and cannot create a
    // protocol view, which keeps statistics from becoming an acceptance path.
    const auto mld_rejection =
        packet::mld::diagnose_rejection(frame, require_mld_router_alert);
    if (mld_rejection != packet::mld::RejectionReason::not_mld) {
      if (mld_state) {
        using enum packet::mld::RejectionReason;
        const auto counter = [&] {
          switch (mld_rejection) {
          case bad_length:
            return MldReceiveStatistic::bad_length;
          case bad_checksum:
            return MldReceiveStatistic::bad_checksum;
          case unknown_type:
            return MldReceiveStatistic::unknown_type;
          case bad_receive_interface:
            return MldReceiveStatistic::bad_receive_interface;
          case non_local_source:
            return MldReceiveStatistic::non_local;
          case no_router_alert:
            return MldReceiveStatistic::no_router_alert;
          case bad_encoding:
            return MldReceiveStatistic::bad_encoding;
          case not_mld:
            break;
          }
          return MldReceiveStatistic::bad_encoding;
        }();
        mld_state->protocol.count_receive(counter);
      }
      drop(ForwardDrop::malformed);
      return;
    }

    if (const auto router_solicitation =
            packet::nd::parse_router_solicitation(frame)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      // Learning from an RS is permitted only when it carries a validated
      // source and SLLA option. The sender mapping comes from received bytes,
      // never from topology metadata or a direct host reference.
      if (router_solicitation->source_link_layer &&
          !ip::is_unspecified(router_solicitation->source) &&
          usable_sender_mac(*router_solicitation->source_link_layer) &&
          ipv6_neighbor_admission_allowed(*ingress, ingress_ipv6_interface_id,
                                          router_solicitation->source))
        static_cast<void>(ipv6_neighbors_.learn_stale(
            ingress_ipv6_interface_id, router_solicitation->source,
            *router_solicitation->source_link_layer, false, now,
            std::chrono::seconds{ingress->nd_stale_time_seconds},
            address_scope_selected(ingress->ipv6_proactive_refresh,
                                   router_solicitation->source)));
      ipv6_router_advertisements_.observe_solicitation(ingress_port, now);
      return;
    }

    if (const auto solicitation =
            packet::nd::parse_neighbor_solicitation(frame)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      if (solicitation->source_link_layer &&
          usable_sender_mac(*solicitation->source_link_layer) &&
          ipv6_neighbor_admission_allowed(*ingress, ingress_ipv6_interface_id,
                                          solicitation->source)) {
        static_cast<void>(ipv6_neighbors_.learn_stale(
            ingress_ipv6_interface_id, solicitation->source,
            *solicitation->source_link_layer, false, now,
            std::chrono::seconds{ingress->nd_stale_time_seconds},
            address_scope_selected(ingress->ipv6_proactive_refresh,
                                   solicitation->source)));
      }
      if (solicitation->duplicate_address_detection)
        static_cast<void>(ipv6_dad_.observe_conflict(ingress_ipv6_interface_id,
                                                     solicitation->target));
      const bool target_is_local =
          ingress->ipv6_configured &&
          ((solicitation->target == ingress->ipv6_address) ||
           (native_ipv6_addresses_.find(ingress_ipv6_interface_id,
                                        solicitation->target) != nullptr) ||
           solicitation->target == ingress->ipv6_link_local) &&
          ipv6_dad_.preferred(ingress_ipv6_interface_id, solicitation->target);
      if (target_is_local) {
        const auto destination = solicitation->duplicate_address_detection
                                     ? packet::nd::all_nodes_multicast
                                     : solicitation->source;
        const auto destination_mac =
            solicitation->duplicate_address_detection
                ? packet::ipv6_multicast_mac(packet::nd::all_nodes_multicast)
                : ethernet->source;
        const auto reply = packet::nd::neighbor_advertisement(
            ingress->mac, destination_mac, solicitation->target, destination,
            solicitation->target, true,
            !solicitation->duplicate_address_detection, true);
        count_sent_icmpv6(ingress_port, reply);
        static_cast<void>(emit_ipv6_interface(
            ingress_ipv6_interface_id, ingress_port, reply, context, sink));
      }
      return;
    }

    if (const auto advertisement =
            packet::nd::parse_neighbor_advertisement(frame)) {
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      static_cast<void>(ipv6_dad_.observe_conflict(ingress_ipv6_interface_id,
                                                   advertisement->target));
      // nd_reachable_time_milliseconds is the configured base. The effective
      // RFC 4861 interface variable is randomized and checkpointed separately.
      const auto reachable_time = ipv6_reachable_time(ingress->ordinal, now);
      const bool known_neighbor =
          ipv6_neighbors_.find(ingress_ipv6_interface_id, advertisement->target)
              .has_value();
      const bool learn_unsolicited =
          !known_neighbor &&
          address_scope_selected(ingress->ipv6_unsolicited_learning,
                                 advertisement->target) &&
          ipv6_neighbor_admission_allowed(*ingress, ingress_ipv6_interface_id,
                                          advertisement->target);
      if (ipv6_neighbors_.receive_advertisement(
              ingress_ipv6_interface_id, advertisement->target,
              advertisement->target_link_layer, advertisement->solicited,
              advertisement->override_flag, advertisement->router,
              learn_unsolicited, reachable_time, now,
              std::chrono::seconds{ingress->nd_stale_time_seconds},
              address_scope_selected(ingress->ipv6_proactive_refresh,
                                     advertisement->target))) {
        const auto resolved = resolve_ipv6_neighbor(
            *ingress, ingress_ipv6_interface_id, advertisement->target, now);
        if (resolved.status == Ipv6ResolutionStatus::resolved)
          flush_pending_ipv6(ingress_ipv6_interface_id, ingress_port,
                             advertisement->target, resolved.mac, context, sink,
                             now);
      }
      return;
    }

    // NS and NA are link-local control messages, never transit traffic. If a
    // generic ICMPv6 parse can identify the type but the strict ND decoder
    // rejected Hop Limit, code, option length or address rules, RFC 4861
    // requires silent discard. Forwarding such a packet would let malformed
    // neighbor information escape its originating link.
    if (const auto icmp = packet::parse_icmpv6(frame);
        icmp && (icmp->type == packet::nd::neighbor_solicitation_type ||
                 icmp->type == packet::nd::neighbor_advertisement_type ||
                 icmp->type == packet::nd::router_solicitation_type ||
                 icmp->type == packet::nd::router_advertisement_type)) {
      drop(ForwardDrop::malformed);
      return;
    }

    const auto local =
        std::find_if(ports_.begin(), ports_.end(), [&](const auto &candidate) {
          const auto candidate_interface =
              physical_interface_id(candidate.ordinal);
          const bool global = native_owner &&
                              native_owner->port_ordinal == candidate.ordinal &&
                              ipv6_dad_.preferred(native_owner->interface_id,
                                                  native_owner->address);
          // Link-local unicast is meaningful only in the ingress zone. Do not
          // accept an equal byte value owned by a different physical link.
          const bool link_local =
              candidate.ordinal == ingress_port &&
              candidate.ipv6_link_local == ipv6->destination &&
              ipv6_dad_.preferred(candidate_interface,
                                  candidate.ipv6_link_local);
          return candidate.configured && candidate.ipv6_configured &&
                 (global || link_local);
        });
    const bool ingress_service_local =
        service_ingress && ((ingress->ipv6_address == ipv6->destination &&
                             ipv6_dad_.preferred(ingress_ipv6_interface_id,
                                                 ingress->ipv6_address)) ||
                            (ingress->ipv6_link_local == ipv6->destination &&
                             ipv6_dad_.preferred(ingress_ipv6_interface_id,
                                                 ingress->ipv6_link_local)));
    const bool relay_multicast_local =
        ipv6->destination == packet::dhcpv6::all_relay_agents_and_servers &&
        dhcpv6_relay_.unique_on_physical_port(ingress_port);
    if (local != ports_.end() || ingress_service_local ||
        relay_multicast_local) {
      // Multicast delivery belongs to the ingress interface. Unicast may target
      // another local address, so it retains the address-owning port for source
      // MAC and interface counters.
      const auto *local_port =
          ingress_service_local ? ingress
                                : (local != ports_.end() ? &*local : ingress);
      if (punt_observer)
        punt_observer(punt_context, ingress_port, frame);
      // Fragment state belongs to this local IPv6 endpoint. Transit fragments
      // never enter this table. Atomic fragments are normalized independently,
      // while incomplete, overlapping or exhausted datagrams produce no upper-
      // layer delivery and cannot leak partially accepted bytes.
      const packet::Frame *local_frame = &frame;
      std::optional<packet::Frame> reassembled;
      std::span<const std::uint8_t> local_packet = frame.view();
      std::optional<packet::Ipv6View> local_ipv6 = ipv6;
      if (ipv6->fragment) {
        const bool non_atomic_fragment =
            ipv6->fragment->offset != 0U || ipv6->fragment->more_fragments;
        auto result = ipv6_reassembly_.accept(frame, now);
        if (result.status == packet::Ipv6ReassemblyStatus::incomplete)
          return;
        if ((result.status != packet::Ipv6ReassemblyStatus::complete &&
             result.status != packet::Ipv6ReassemblyStatus::atomic) ||
            result.packet.empty()) {
          drop(result.status == packet::Ipv6ReassemblyStatus::resource_exhausted
                   ? ForwardDrop::reassembly_full
                   : ForwardDrop::malformed);
          return;
        }
        local_packet = result.packet;
        local_ipv6 = packet::parse_ipv6(local_packet);
        if (!local_ipv6) {
          drop(ForwardDrop::malformed);
          return;
        }
        // Existing ICMP error and echo encoders consume Frame because their
        // output normally fits one profile MTU. Preserve that path only when
        // the reassembled packet is representable. Full-size UDP delivery uses
        // local_packet directly and is not narrowed to a physical frame.
        if (local_packet.size() <= packet::maximum_frame_octets) {
          reassembled.emplace();
          std::copy(local_packet.begin(), local_packet.end(),
                    reassembled->bytes.begin());
          reassembled->length = static_cast<std::uint16_t>(local_packet.size());
          local_frame = &*reassembled;
        } else {
          local_frame = nullptr;
        }
        if (non_atomic_fragment && !local_ipv6->authentication_header_present &&
            local_ipv6->upper_layer_protocol == packet::ipv6_next_header_icmpv6)
          count_received_icmpv6(ingress_port, local_packet, *local_ipv6);
      }
      // The router has no IPsec SA subsystem in this milestone. AH remains a
      // valid opaque local payload, not permission to dispatch its unverified
      // inner Next Header into ICMPv6, UDP or DHCPv6 processing.
      if (local_ipv6->authentication_header_present)
        return;
      const auto icmp = packet::parse_icmpv6(local_packet);
      if (icmp && icmp->type == packet::icmpv6_echo_request_type &&
          icmp->code == 0U && local_frame) {
        const auto reply = packet::icmpv6_echo_reply(
            *local_frame, local_port->mac, unresolved_mac);
        if (reply) {
          count_sent_icmpv6(local_port->ordinal, *reply);
          send_ipv6(*reply, local_ipv6->source, false, context, sink, now);
        }
      } else if (icmp && icmp->type == packet::icmpv6_echo_reply_type &&
                 icmp->code == 0U) {
        // A reply belongs to this CLI operation only when the active retained
        // probe generation matches both its sequence and remote source.
        if (!ipv6_probe_valid_ || icmp->sequence != ipv6_probe_sequence_ ||
            local_ipv6->source != ipv6_probe_destination_)
          return;
        ipv6_echo_reply_sequence_ = icmp->sequence;
        ipv6_echo_reply_valid_ = true;
        ipv6_echo_reply_rtt_ = now >= ipv6_probe_sent_at_
                                   ? std::chrono::duration_cast<
                                         std::chrono::nanoseconds>(
                                         now - ipv6_probe_sent_at_)
                                   : std::chrono::nanoseconds::zero();
        // Only the retained source generation can confirm an upward PMTU
        // experiment. Destination and interface are checked again here so a
        // reply after route replacement cannot publish evidence for a new path.
        if (ipv6_probe_valid_ && icmp->sequence == ipv6_probe_sequence_ &&
            local_ipv6->source == ipv6_probe_destination_) {
          routing::Ipv6Route reply_route;
          bool reply_blackhole{};
          if (lookup_ipv6_route(ipv6_probe_destination_, reply_route,
                                reply_blackhole) &&
              !reply_blackhole &&
              reply_route.interface_id == ipv6_probe_interface_id_ &&
              reply_route.physical_port_ordinal == ipv6_probe_port_ordinal_)
            static_cast<void>(ipv6_path_mtu_.confirm_probe(
                ipv6_probe_destination_, ipv6_probe_interface_id_, now));
        }
        ipv6_probe_valid_ = false;
      } else if (icmp && ipv6_transport_error_kind(icmp->type, icmp->code)) {
        const auto kind = *ipv6_transport_error_kind(icmp->type, icmp->code);
        // The CLI Echo owner retains complete packet bytes and therefore uses
        // stronger byte-for-byte correlation before transport matching. A
        // route change may prevent a PTB cache edit, but it does not erase the
        // real error outcome for the exact probe already sent.
        if (matches_ipv6_probe_quote(icmp->data)) {
          if (kind == transport::Ipv6NetworkErrorKind::packet_too_big)
            static_cast<void>(accept_ipv6_packet_too_big(*icmp, now));
          ipv6_echo_error_parameter_ = icmp->parameter;
          ipv6_echo_error_sequence_ = ipv6_probe_sequence_;
          ipv6_echo_error_type_ = icmp->type;
          ipv6_echo_error_code_ = icmp->code;
          ipv6_echo_error_valid_ = true;
          ipv6_probe_valid_ = false;
        } else {
          const auto quoted = packet::parse_ipv6_quote(icmp->data);
          routing::Ipv6Route route;
          bool blackhole{};
          if (quoted && quoted->upper_layer_protocol ==
                            packet::ipv6_next_header_udp &&
              lookup_ipv6_route(quoted->destination, route, blackhole) &&
              !blackhole) {
            const auto offset =
                static_cast<std::size_t>(quoted->upper_layer_offset);
            const auto local_port = read_network_u16(icmp->data, offset);
            const auto remote_port =
                read_network_u16(icmp->data, offset + 2U);
            const bool accepted = udp_.report_ipv6_error(
                quoted->source, quoted->destination, route.interface_id,
                local_port, remote_port, kind, icmp->type, icmp->code,
                icmp->parameter);
            if (accepted &&
                kind == transport::Ipv6NetworkErrorKind::packet_too_big) {
              const auto egress = ipv6_interface(
                  route.interface_id, route.physical_port_ordinal);
              if (egress && egress->operational && egress->ipv6_configured)
                static_cast<void>(ipv6_path_mtu_.update(
                    quoted->destination, route.interface_id, icmp->parameter,
                    static_cast<std::uint32_t>(
                        egress->mtu - packet::ethernet_header_octets),
                    now));
            }
          }
        }
      } else if (local_ipv6->upper_layer_protocol ==
                 packet::ipv6_next_header_udp) {
        const auto packet_end =
            static_cast<std::size_t>(packet::ethernet_header_octets) +
            packet::ipv6_header_octets + local_ipv6->payload_length;
        const auto upper_offset =
            static_cast<std::size_t>(local_ipv6->upper_layer_offset);
        const auto udp = upper_offset <= packet_end
                             ? packet::udp::parse_ipv6(
                                   local_packet.subspan(
                                       upper_offset, packet_end - upper_offset),
                                   local_ipv6->source, local_ipv6->destination)
                             : std::optional<packet::udp::View>{};
        if (udp) {
          const auto udp_bytes =
              local_packet.subspan(upper_offset, packet_end - upper_offset);
          auto udp_ingress_interface_id = ingress_ipv6_interface_id;
          if (!service_ingress &&
              udp->destination_port == packet::dhcpv6::server_port) {
            // A direct client message or nested Relay-forward received on the
            // compatibility untagged API belongs to that relay's configured
            // logical scope. Relay-reply is different: its Interface-Id option
            // chooses the downstream interface after authenticated wire
            // parsing, so its server-facing ingress keeps the physical zone.
            const auto dhcpv6_message = packet::dhcpv6::parse(udp->payload);
            const bool relay_reply =
                dhcpv6_message &&
                dhcpv6_message->type ==
                    static_cast<std::uint8_t>(
                        packet::dhcpv6::MessageType::relay_reply);
            if (dhcpv6_message && !relay_reply)
              if (const auto *relay =
                      dhcpv6_relay_.unique_on_physical_port(ingress_port))
                udp_ingress_interface_id = relay->interface_id;
          }
          const auto ingress_status = udp_.ingest_ipv6(
              udp_bytes, local_ipv6->source, local_ipv6->destination,
              udp_ingress_interface_id, ethernet->source);
          if (ingress_status == transport::UdpIngressStatus::delivered) {
            service_dhcpv6_relay(ingress_port, udp_ingress_interface_id,
                                 context, sink, admission, now);
          } else if (ingress_status == transport::UdpIngressStatus::no_socket) {
            // RFC 4443 section 3.1 assigns code 4 only when no local socket
            // owns the exact tuple. Application discard is not a closed port.
            send_ipv6_destination_unreachable(
                local_packet, *local_ipv6,
                packet::icmpv6_destination_port_unreachable_code, context, sink,
                now);
          } else if (ingress_status ==
                     transport::UdpIngressStatus::queue_full) {
            drop(ForwardDrop::udp_queue_full);
          } else {
            drop(ForwardDrop::malformed);
          }
        } else {
          // RFC 8200 requires a non-zero valid UDP checksum for IPv6. A bad
          // datagram is silently discarded and cannot provoke an error that
          // would amplify corrupt traffic.
          drop(ForwardDrop::malformed);
        }
      } else if (local_frame &&
                 local_ipv6->upper_layer_protocol !=
                     packet::ipv6_next_header_icmpv6 &&
                 local_ipv6->upper_layer_protocol !=
                     packet::ipv6_next_header_esp &&
                 local_ipv6->upper_layer_protocol !=
                     packet::ipv6_next_header_none) {
        // The local protocol dispatcher currently recognizes ICMPv6 plus the
        // opaque ESP and No Next Header terminal values. Every other value is
        // unknown to this node and must identify the exact preceding Next
        // Header field rather than being silently treated as a successful
        // no-op.
        send_ipv6_parameter_problem(
            *local_frame, *local_ipv6,
            packet::icmpv6_parameter_unknown_next_header_code,
            static_cast<std::uint32_t>(
                local_ipv6->upper_layer_next_header_offset -
                packet::ethernet_header_octets),
            false, context, sink, now);
      }
      return;
    }

    if (ipv6->hop_limit <= 1U) {
      send_ipv6_time_exceeded(frame, *ipv6, context, sink, now);
      return;
    }
    routing::Ipv6Route destination_route;
    bool blackhole{};
    if (!lookup_ipv6_route(ipv6->destination, destination_route, blackhole)) {
      // RFC 4443 code zero reports that no route can be selected. The error
      // still follows an independently resolved reverse path through ND.
      drop(ForwardDrop::no_route);
      send_ipv6_destination_unreachable(
          frame, *ipv6, packet::icmpv6_destination_no_route_code, context, sink,
          now);
      return;
    }
    if (blackhole) {
      // A configured Prefix Exclude is a silent discard route. Generating an
      // ICMP error would defeat the administrator-selected blackhole and may
      // reveal excluded downstream addressing.
      drop(ForwardDrop::blackhole);
      return;
    }
    if (send_ipv6(frame, ipv6->destination, true, context, sink, now))
      maybe_send_ipv6_redirect(*ingress, *ethernet, *ipv6, destination_route,
                               frame, context, sink, now);
    return;
  }
  if (ethernet->ether_type != 0x0800) {
    drop(ForwardDrop::malformed);
    return;
  }
  auto ip = packet::parse_ipv4(frame);
  if (!ip) {
    drop(ForwardDrop::malformed);
    return;
  }

  const auto destination = to_u32(ip->destination);
  const auto local = std::find_if(
      ports_.begin(), ports_.end(), [destination](const auto &candidate) {
        return candidate.configured && candidate.ipv4_configured &&
               candidate.address == destination;
      });
  routing::Route destination_route;
  const bool local_system =
      routing::lookup(fib_, destination, destination_route) &&
      destination_route.local_system &&
      destination_route.prefix_length == 32U &&
      destination_route.network == destination;
  const bool ingress_broadcast =
      ingress->ipv4_configured && destination == 0xffffffffU;
  const bool any_directed_broadcast = std::any_of(
      ports_.begin(), ports_.end(), [destination](const auto &candidate) {
        return directed_broadcast(candidate, destination);
      });
  // RFC 2644 changes both receipt and forwarding of network-directed
  // broadcasts to disabled by default. No project configuration enables that
  // optional behavior, so every directed broadcast is discarded before ARP.
  if (any_directed_broadcast) {
    drop(ForwardDrop::directed_broadcast_disabled);
    return;
  }
  if (local != ports_.end() || local_system || ingress_broadcast) {
    // Locally addressed IPv4 leaves the transit pipeline for the CPM protocol
    // stack. Capture observes bytes before an ICMP reply or session state is
    // generated, preserving the actual received packet.
    if (punt_observer)
      punt_observer(punt_context, ingress_port, frame);
    std::span<const std::uint8_t> local_packet = frame.view();
    const packet::Frame *local_frame = &frame;
    std::optional<packet::Frame> reassembled;
    if (ip->fragment_offset != 0U || ip->more_fragments) {
      // RFC 1812 section 5.2.1 requires reassembly only after the local
      // delivery decision. Transit fragments never enter this destination
      // table and continue independently through ordinary FIB forwarding.
      const auto result = ipv4_reassembly_.accept(frame, now);
      if (result.status == packet::Ipv4ReassemblyStatus::incomplete)
        return;
      if (result.status != packet::Ipv4ReassemblyStatus::complete ||
          result.packet.empty()) {
        drop(result.status == packet::Ipv4ReassemblyStatus::resource_exhausted
                 ? ForwardDrop::reassembly_full
                 : ForwardDrop::malformed);
        return;
      }
      local_packet = result.packet;
      ip = packet::parse_ipv4(local_packet);
      if (!ip) {
        drop(ForwardDrop::malformed);
        return;
      }
      if (local_packet.size() <= packet::maximum_frame_octets) {
        reassembled.emplace();
        std::copy(local_packet.begin(), local_packet.end(),
                  reassembled->bytes.begin());
        reassembled->length = static_cast<std::uint16_t>(local_packet.size());
        local_frame = &*reassembled;
      } else {
        // UDP and ICMP errors consume spans, but the current Echo Reply codec
        // produces one bounded Frame. The large datagram is never truncated.
        local_frame = nullptr;
      }
    }

    // Local delivery terminates forwarding. ICMP and UDP are dispatched from
    // the complete reassembled bytes, while unsupported protocols return the
    // precise RFC 792 diagnostic through the normal reverse FIB and ARP path.
    if (ip->protocol == 1U)
      count_received_icmpv4(ingress_port, local_packet, *ip);
    const auto icmp = packet::parse_icmp(local_packet);
    if (icmp && icmp->type == 8U && icmp->code == 0U && local_frame &&
        !ingress_broadcast) {
      // The reply is locally originated with TTL 64, then routed toward the
      // remote source through this router's own FIB and ARP state.
      // The system interface has no MAC. The reply builder needs a temporary
      // Ethernet source only to construct the frame; send_resolved replaces it
      // with the real reverse-path egress MAC before bytes leave the router.
      const auto local_mac = local != ports_.end() ? local->mac : ingress->mac;
      const auto reply =
          packet::icmp_echo_reply(*local_frame, local_mac, unresolved_mac);
      if (reply) {
        // Sent counters belong to the actual reverse egress interface, which
        // can differ from ingress under asymmetric static routing.
        routing::Route reverse;
        if (routing::lookup(fib_, to_u32(ip->source), reverse) &&
            !reverse.local_system) {
          if (const auto *reply_egress = port(reverse.port_ordinal);
              reply_egress && reply_egress->operational)
            count_sent_icmpv4(reply_egress->ordinal, *reply);
        }
        send(*reply, to_u32(ip->source), false, context, sink, now);
      }
    } else if (icmp && icmp->type == 0U && icmp->code == 0U &&
               !ingress_broadcast) {
      // Echo success is derived only from a received encoded reply addressed to
      // one local interface. The asynchronous command owner polls this value.
      // Sequence and source jointly identify the active request generation.
      // Accepting any local Echo Reply would let unrelated traffic complete a
      // CLI ping after the 16-bit sequence space wraps.
      if (!echo_request_valid_ ||
          icmp->sequence != echo_request_sequence_ ||
          ip->source != echo_request_destination_)
        return;
      echo_reply_sequence_ = icmp->sequence;
      echo_reply_valid_ = true;
      echo_reply_rtt_ = now >= echo_request_sent_at_
                            ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                                  now - echo_request_sent_at_)
                            : std::chrono::nanoseconds::zero();
      echo_request_valid_ = false;
      if (ipv4_probe_valid_ && ip->source == ipv4_probe_destination_)
        static_cast<void>(ipv4_path_mtu_.confirm_probe(
            ipv4_probe_destination_, ipv4_probe_interface_id_, now));
      ipv4_probe_valid_ = false;
    } else if (icmp && icmp->type == 3U && icmp->code == 4U &&
               !ingress_broadcast) {
      // Receipt alone is not success. The PMTU owner changes only when the
      // quoted bytes and current route both match the retained local probe.
      static_cast<void>(accept_ipv4_fragmentation_needed(*icmp, now));
    } else if (ip->protocol == 17U) {
      const auto upper_offset = packet::ethernet_header_octets +
                                static_cast<std::size_t>(ip->header_length);
      const auto packet_end = packet::ethernet_header_octets +
                              static_cast<std::size_t>(ip->total_length);
      if (upper_offset > packet_end) {
        drop(ForwardDrop::malformed);
        return;
      }
      const auto interface_id =
          local != ports_.end() ? physical_interface_id(local->ordinal)
          : ingress_broadcast   ? physical_interface_id(ingress->ordinal)
                                : 0U;
      const auto status = udp_.ingest_ipv4(
          local_packet.subspan(upper_offset, packet_end - upper_offset),
          ip->source, ip->destination, interface_id);
      if (status == transport::UdpIngressStatus::no_socket)
        send_local_destination_unreachable(local_packet, *ip, 3U, context, sink,
                                           now);
      else if (status == transport::UdpIngressStatus::queue_full)
        drop(ForwardDrop::udp_queue_full);
      else if (status == transport::UdpIngressStatus::malformed)
        drop(ForwardDrop::malformed);
    } else if (ip->protocol != 1U && ip->protocol != 50U &&
               ip->protocol != 51U) {
      // ESP and AH are owned by IPsec policy and fail closed when no matching
      // SA accepts them. Every other unowned Protocol value is observable as
      // Destination Unreachable code 2 at the final destination.
      send_local_destination_unreachable(local_packet, *ip, 2U, context, sink,
                                         now);
    }
    return;
  }

  if (ip->ttl <= 1U) {
    // TTL is evaluated before route_ipv4 can decrement it. The original header
    // is available for the required ICMP quotation.
    send_time_exceeded(frame, *ip, context, sink, now);
    return;
  }
  routing::Route redirect_route;
  if (routing::lookup(fib_, destination, redirect_route))
    maybe_send_ipv4_redirect(*ingress, *ethernet, *ip, redirect_route, frame,
                             context, sink, now);
  send(frame, destination, true, context, sink, now);
}

void RouterForwarder::expire(Clock::time_point now) noexcept {
  // Aging is local maintenance work. It does not schedule a global event or
  // advance time, and it touches no pending frame until a new resolution
  // starts.
  for (auto &entry : adjacencies_)
    if (entry.valid && !entry.aging_disabled && entry.expires <= now)
      entry = {};
}

void RouterForwarder::service_ipv4_maintenance(void *context, EgressSink sink,
                                               Clock::time_point now) noexcept {
  expire(now);

  // Configuration reaches the forwarding owner without an egress sink, so a
  // newly installed static mapping releases already buffered packets on the
  // next ordinary maintenance turn. No cross-device shortcut is involved:
  // every released frame still traverses the port queue and physical link.
  for (const auto &entry : adjacencies_)
    if (entry.valid && entry.configured_static)
      flush_pending(entry.port_ordinal, entry.address, entry.mac, context, sink,
                    now);

  // Reassembly deadlines belong to the local IPv4 endpoint on this same
  // forwarding owner. Fragment zero is retained by the table specifically so
  // timeout can quote received bytes in ICMP Time Exceeded code 1. An entry
  // without fragment zero is reclaimed silently as required by RFC 1122.
  packet::Frame first_fragment;
  while (ipv4_reassembly_.take_expired(first_fragment, now)) {
    if (!first_fragment.length)
      continue;
    const auto ip = packet::parse_ipv4(first_fragment);
    if (ip)
      send_reassembly_time_exceeded(first_fragment, *ip, context, sink, now);
  }

  for (std::size_t index = 0U; index < pending_.size(); ++index) {
    auto &leader = pending_[index];
    if (!leader.valid || leader.ipv6 || leader.arp_retry_deadline > now)
      continue;

    // The lowest occupied slot for an exact (port, next-hop) key owns this
    // retry turn. Every follower receives the same next deadline so a later
    // slot cannot emit a duplicate request during this or the next scan.
    const bool earlier_owner = std::any_of(
        pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(index),
        [&](const auto &candidate) {
          return candidate.valid && !candidate.ipv6 &&
                 candidate.port_ordinal == leader.port_ordinal &&
                 candidate.next_hop == leader.next_hop;
        });
    if (earlier_owner)
      continue;
    const auto *egress = port(leader.port_ordinal);

    // An administratively or operationally down interface cannot transmit an
    // ARP request, but leaving an expired deadline in the pending table would
    // make the owning worker wake continuously. Advance the whole resolution
    // group first, then decide whether this retry can be put on the wire. The
    // configured port remains the timer authority while it is down, exactly as
    // it remains the owner of the unresolved adjacency state.
    const auto retry_interval =
        egress ? arp_retry_interval(*egress)
               : std::chrono::milliseconds{
                     device_catalog::dynamic_arp_retry_deciseconds * 100U};
    const auto deadline = now + retry_interval;
    for (auto &candidate : pending_)
      if (candidate.valid && !candidate.ipv6 &&
          candidate.port_ordinal == leader.port_ordinal &&
          candidate.next_hop == leader.next_hop)
        candidate.arp_retry_deadline = deadline;

    if (!egress || !egress->operational || !egress->ipv4_configured)
      continue;

    const auto request = packet::arp_request(
        egress->mac, to_ipv4(egress->address), to_ipv4(leader.next_hop));
    static_cast<void>(emit(egress->ordinal, request, context, sink));
  }
}

std::optional<RouterForwarder::Clock::time_point>
RouterForwarder::next_ipv4_deadline() const noexcept {
  auto next = ipv4_reassembly_.next_deadline();
  for (const auto &entry : adjacencies_)
    if (entry.valid && !entry.aging_disabled &&
        (!next || entry.expires < *next))
      next = entry.expires;
  for (const auto &entry : pending_)
    if (entry.valid && !entry.ipv6 &&
        (!next || entry.arp_retry_deadline < *next))
      next = entry.arp_retry_deadline;
  return next;
}

void RouterForwarder::begin_global_dad_if_ready(
    const ForwardPort &target, Clock::time_point now) noexcept {
  if (!target.configured || !target.operational || !target.ipv6_configured ||
      !ipv6_dad_.preferred(physical_interface_id(target.ordinal),
                           target.ipv6_link_local))
    return;
  const auto interface_id = physical_interface_id(target.ordinal);
  for (const auto &address : native_ipv6_addresses_.records()) {
    if (address.interface_id != interface_id ||
        ipv6_dad_.find(interface_id, address.address))
      continue;
    const auto transmits = address.duplicate_address_detection
                               ? device_catalog::ipv6_dad_transmits
                               : std::uint8_t{0U};
    static_cast<void>(ipv6_dad_.configure(
        interface_id, target.ordinal, address.address, transmits,
        transmits == 0U
            ? std::chrono::nanoseconds::zero()
            : ipv6_interface_initial_delay(
                  interface_id, address.address, now,
                  std::chrono::duration_cast<std::chrono::nanoseconds>(
                      device_catalog::ipv6_dad_max_initial_delay)),
        now));
  }
}

void RouterForwarder::service_ipv6_maintenance(void *context, EgressSink sink,
                                               Clock::time_point now) noexcept {
  const auto expired = dhcpv6_relay_leases_.prepare_expiry(now);
  if (!expired.empty()) {
    if (!dhcpv6_relay_routes_.prepare(expired, dhcpv6_relay_.interfaces())) {
      dhcpv6_relay_leases_.discard_prepared();
      drop(ForwardDrop::dhcpv6_lease_state_full);
      return;
    }
    dhcpv6_neighbor_edits_.clear();
    for (const auto &mutation : expired) {
      const auto &lease = mutation.record;
      const auto *relay = dhcpv6_relay_.interface(lease.interface_id);
      const bool address_lease =
          lease.protocol == dhcpv6::RelayLeaseProtocol::non_temporary ||
          lease.protocol == dhcpv6::RelayLeaseProtocol::temporary;
      if (!relay || !relay->neighbor_resolution || !address_lease ||
          !lease.has_client_mac ||
          !ip::contains(relay->client_prefix, lease.value))
        continue;
      // Expiry can only remove existing state and therefore requires neither
      // heap growth nor eviction. The scratch capacity was reserved from the
      // same lease policy that admitted this record.
      dhcpv6_neighbor_edits_.push_back(
          {.kind = Ipv6NeighborBatchKind::remove_dynamic,
           .interface_id = lease.interface_id,
           .address = lease.value});
    }
    if (ipv6_neighbors_.apply_batch(dhcpv6_neighbor_edits_, now)) {
      static_cast<void>(dhcpv6_relay_routes_.commit_prepared());
      static_cast<void>(dhcpv6_relay_leases_.commit_prepared());
    } else {
      dhcpv6_relay_routes_.discard_prepared();
      drop(ForwardDrop::dhcpv6_lease_state_full);
    }
  }
  // ReachableTime is periodically re-sampled per interface even if no Router
  // Advertisement changes the base value. This is owner-local maintenance,
  // not a scheduled global network event.
  for (std::size_t ordinal = 0; ordinal < ipv6_reachable_times_.size();
       ++ordinal) {
    auto &state = ipv6_reachable_times_[ordinal];
    if (state.valid && state.refresh_deadline <= now)
      refresh_ipv6_reachable_time(static_cast<std::uint16_t>(ordinal), now);
  }
  // Reassembly expiry is ordinary owner-local maintenance. No callback or
  // global event is created when an incomplete datagram times out.
  ipv6_reassembly_.expire(now);
  std::array<Ipv6DadAction, device_catalog::nd_work_budget_actions>
      dad_actions{};
  const auto dad_count = ipv6_dad_.poll(now, dad_actions);
  for (std::size_t index = 0; index < dad_count; ++index) {
    const auto &action = dad_actions[index];
    // DAD is scoped to a routed interface, not merely to the carrier port.
    // A SAP-backed IES interface therefore needs its own MAC and VLAN envelope
    // even though the final transmitter is the same physical port.
    const auto egress_view =
        ipv6_interface(action.interface_id, action.port_ordinal);
    const auto *egress = egress_view ? &*egress_view : nullptr;
    if (!egress || !egress->operational || !egress->ipv6_configured) {
      drop(ForwardDrop::port_down);
      continue;
    }
    const auto solicitation =
        packet::nd::neighbor_solicitation(egress->mac, {}, action.target, true);
    count_sent_icmpv6(action.port_ordinal, solicitation);
    static_cast<void>(emit_ipv6_interface(
        action.interface_id, action.port_ordinal, solicitation, context, sink));
  }
  // Link-local DAD completes before the configured global address begins DAD.
  // This ordering is local interface state, not a global scheduled event.
  for (const auto &candidate : ports_)
    begin_global_dad_if_ready(candidate, now);
  for (auto &state : mld_interfaces_) {
    const auto *candidate = port(state.intent.port_ordinal);
    const bool ready =
        state.intent.enabled && candidate && candidate->operational &&
        candidate->ipv6_configured &&
        ipv6_dad_.preferred(physical_interface_id(candidate->ordinal),
                            candidate->ipv6_link_local);
    if (ready == state.running && (!ready || state.intent.link_local_address ==
                                                 candidate->ipv6_link_local))
      continue;
    auto effective = state.intent;
    effective.enabled = ready;
    if (candidate)
      effective.link_local_address = candidate->ipv6_link_local;
    if (!state.protocol.configure(effective, now)) {
      drop(ForwardDrop::malformed);
      continue;
    }
    if (candidate)
      state.intent.link_local_address = candidate->ipv6_link_local;
    state.running = ready;
  }

  // Router Query generation has one generated per-turn budget shared by all
  // configured interfaces. A round-robin cursor prevents a busy low ordinal
  // from starving later ports while avoiding one physical worker per port.
  std::size_t mld_budget = device_catalog::mld_work_budget_actions;
  if (!mld_interfaces_.empty()) {
    auto cursor =
        static_cast<std::size_t>(mld_service_cursor_) % mld_interfaces_.size();
    std::size_t visited{};
    while (visited < mld_interfaces_.size() && mld_budget) {
      auto &state = mld_interfaces_[cursor];
      if (state.running) {
        std::array<MldRouterAction, device_catalog::mld_work_budget_actions>
            mld_actions{};
        const auto count = state.protocol.poll(
            now, std::span<MldRouterAction>{mld_actions}.first(mld_budget));
        const auto *egress = port(state.intent.port_ordinal);
        if (egress && egress->operational) {
          for (std::size_t index = 0; index < count; ++index) {
            const auto &action = mld_actions[index];
            std::optional<packet::Frame> query;
            if (action.version_one) {
              query = packet::mld::version_one_message(
                  egress->mac, egress->ipv6_link_local, packet::mld::query_type,
                  action.multicast_address, action.maximum_response_delay);
            } else {
              query = packet::mld::version_two_query(
                  egress->mac, egress->ipv6_link_local,
                  action.multicast_address, action.maximum_response_delay,
                  action.robustness_variable, action.suppress_router_processing,
                  action.query_interval,
                  std::span<const packet::Ipv6>{action.sources.data(),
                                                action.source_count});
            }
            if (!query) {
              drop(ForwardDrop::malformed);
              continue;
            }
            count_sent_icmpv6(egress->ordinal, *query);
            static_cast<void>(emit(egress->ordinal, *query, context, sink));
          }
        }
        mld_budget -= count;
      }
      cursor = (cursor + 1U) % mld_interfaces_.size();
      ++visited;
    }
    mld_service_cursor_ = static_cast<std::uint16_t>(cursor);
  } else {
    mld_service_cursor_ = 0U;
  }
  for (const auto &candidate : ports_)
    if (candidate.configured)
      ipv6_router_advertisements_.set_link_ready(
          candidate.ordinal,
          candidate.operational && candidate.ipv6_configured &&
              ipv6_dad_.preferred(physical_interface_id(candidate.ordinal),
                                  candidate.ipv6_link_local),
          now);

  std::array<RouterAdvertisementAction, device_catalog::nd_work_budget_actions>
      advertisement_actions{};
  const auto advertisement_count =
      ipv6_router_advertisements_.poll(now, advertisement_actions);
  for (std::size_t index = 0; index < advertisement_count; ++index) {
    const auto &action = advertisement_actions[index];
    const auto *egress = port(action.port_ordinal);
    if (!egress || !egress->operational || !egress->ipv6_configured ||
        !ipv6_dad_.preferred(physical_interface_id(egress->ordinal),
                             egress->ipv6_link_local)) {
      drop(ForwardDrop::port_down);
      continue;
    }
    const auto advertisement = packet::nd::router_advertisement(
        egress->mac, egress->ipv6_link_local, packet::nd::all_nodes_multicast,
        action.config);
    if (!advertisement) {
      drop(ForwardDrop::malformed);
      continue;
    }
    count_sent_icmpv6(egress->ordinal, *advertisement);
    static_cast<void>(emit(egress->ordinal, *advertisement, context, sink));
  }

  std::array<Ipv6NeighborAction, device_catalog::nd_work_budget_actions>
      actions{};
  const auto count = ipv6_neighbors_.poll(now, actions);
  for (std::size_t index = 0; index < count; ++index) {
    const auto &action = actions[index];
    auto physical_port = physical_port_from_interface_id(action.interface_id);
    if (!physical_port)
      if (const auto *service =
              sap_forwarding_.find_interface(action.interface_id))
        physical_port = service->physical_port_ordinal;
    const auto egress_view =
        physical_port ? ipv6_interface(action.interface_id, *physical_port)
                      : std::optional<ForwardPort>{};
    const auto *egress = egress_view ? &*egress_view : nullptr;
    if (!egress || !egress->operational || !egress->ipv6_configured) {
      drop(ForwardDrop::port_down);
      continue;
    }
    if (action.kind == Ipv6NeighborActionKind::resolution_failed) {
      // Every queued datagram waiting for this exact scoped next hop is
      // discarded explicitly. Other ports may use the same link-local address
      // and must retain their independent resolution state.
      for (auto &pending : pending_)
        if (pending.valid && pending.ipv6 &&
            pending.interface_id == action.interface_id &&
            pending.port_ordinal == *physical_port &&
            pending.next_hop_ipv6 == action.address) {
          pending = {};
          drop(ForwardDrop::neighbor_unreachable);
        }
      continue;
    }
    const auto request =
        action.kind == Ipv6NeighborActionKind::multicast_solicitation
            ? packet::nd::neighbor_solicitation(
                  egress->mac, egress->ipv6_link_local, action.address)
            : packet::nd::neighbor_unicast_probe(egress->mac, action.mac,
                                                 egress->ipv6_link_local,
                                                 action.address);
    count_sent_icmpv6(egress->ordinal, request);
    static_cast<void>(emit_ipv6_interface(action.interface_id, egress->ordinal,
                                          request, context, sink));
  }
}

std::optional<RouterForwarder::Clock::time_point>
RouterForwarder::next_ipv6_deadline() const noexcept {
  const auto dad = ipv6_dad_.next_deadline();
  const auto neighbor = ipv6_neighbors_.next_deadline();
  const auto advertisement = ipv6_router_advertisements_.next_deadline();
  const auto reassembly = ipv6_reassembly_.next_deadline();
  const auto relay_lease = dhcpv6_relay_leases_.next_deadline();
  std::optional<Clock::time_point> result = dad;
  if (neighbor && (!result || *neighbor < *result))
    result = neighbor;
  if (advertisement && (!result || *advertisement < *result))
    result = advertisement;
  if (reassembly && (!result || *reassembly < *result))
    result = reassembly;
  if (relay_lease && (!result || *relay_lease < *result))
    result = relay_lease;
  for (const auto &state : ipv6_reachable_times_)
    if (state.valid && (!result || state.refresh_deadline < *result))
      result = state.refresh_deadline;
  for (const auto &state : mld_interfaces_) {
    const auto deadline =
        state.running ? state.protocol.next_deadline() : std::nullopt;
    if (deadline && (!result || *deadline < *result))
      result = deadline;
  }
  return result;
}

void RouterForwarder::drop(ForwardDrop reason) noexcept {
  // Counters record every rejected frame while last_drop retains the most
  // recent diagnostic for an operational projection.
  ++dropped_frames_;
  last_drop_ = reason;
}

std::size_t RouterForwarder::arp_entries() const noexcept {
  return static_cast<std::size_t>(
      std::count_if(adjacencies_.begin(), adjacencies_.end(),
                    [](const auto &entry) { return entry.valid; }));
}

std::size_t RouterForwarder::pending_frames() const noexcept {
  return static_cast<std::size_t>(
      std::count_if(pending_.begin(), pending_.end(),
                    [](const auto &entry) { return entry.valid; }));
}

} // namespace router::lab
