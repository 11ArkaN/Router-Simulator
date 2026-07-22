// Stateless RFC 9915 relay encapsulation and decapsulation. The relay copies
// complete DHCP message bytes into or out of Relay Message options and leaves
// UDP, IPv6 routing, interface lookup and packet transmission to their owners.

#pragma once

#include "router/dhcpv6_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv6 {

enum class RelayStatus : std::uint8_t {
  forwarded,
  malformed,
  wrong_direction,
  hop_count_exceeded,
  output_too_small
};

struct RelayForwardResult {
  RelayStatus status{RelayStatus::malformed};
  std::size_t message_octets{};
};

// received_source is copied to peer-address. A directly received client
// message uses hop-count zero and configured_link_address. A nested
// Relay-forward increments hop-count and uses an unspecified link-address when
// its IP source itself identifies a globally scoped upstream relay.
[[nodiscard]] RelayForwardResult encapsulate_relay_forward(
    std::span<const std::uint8_t> message, packet::Ipv6 received_source,
    packet::Ipv6 configured_link_address,
    std::span<const std::uint8_t> interface_id,
    std::span<std::uint8_t> output) noexcept;

struct RelayReplyView {
  packet::Ipv6 link_address{};
  packet::Ipv6 peer_address{};
  std::span<const std::uint8_t> interface_id{};
  std::span<const std::uint8_t> message{};
  bool has_interface_id{};
};

// The returned message aliases the received Relay-reply and must be emitted
// byte-for-byte. Duplicate Relay Message or Interface-Id options are rejected
// because they make the egress link or payload ambiguous.
[[nodiscard]] std::optional<RelayReplyView>
decapsulate_relay_reply(std::span<const std::uint8_t> message) noexcept;

// A server reverses one Relay-forward layer by preserving its hop count,
// link-address and peer-address, copying Interface-Id when present, and
// replacing Relay Message with the response for the next downstream relay.
// Repeated calls reconstruct a nested return path without retained relay
// state or direct calls to another emulated device.
[[nodiscard]] RelayForwardResult encapsulate_relay_reply(
    std::span<const std::uint8_t> relay_forward,
    std::span<const std::uint8_t> response,
    std::span<std::uint8_t> output) noexcept;

// A server destination may be link-local, so its stable egress interface is
// carried beside the address. A zero interface identifier means that ordinary
// IPv6 route lookup selects the egress interface. The value never names a
// device object and cannot bypass FIB, ND, port queues or the encoded fabric.
struct RelayDestination {
  packet::Ipv6 address{};
  std::uint64_t scope_interface_id{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayDestination &, const RelayDestination &) noexcept =
      default;
};

enum class RelayUpstreamPolicy : std::uint8_t {
  // RFC 9915 section 19 uses ff05::1:3 when an otherwise enabled generic relay
  // has no explicit destination list.
  protocol_default,
  // SR OS service interfaces require at least one configured server. Keeping
  // this policy explicit prevents generic RFC behavior from leaking into the
  // vendor profile.
  explicit_servers_required
};

struct RelayInterfaceConfig {
  // The identifier is stable across inventory rebuilds and checkpoints. It is
  // also the egress selector returned for Relay-reply, never an array offset.
  std::uint64_t interface_id{};
  // Physical transmission identity is deliberately separate. Several tagged
  // service interfaces can share this port while retaining independent relay,
  // ND and transport state under interface_id.
  std::uint16_t physical_port_ordinal{};
  packet::Ipv6 link_address{};
  // A configured relay source is an explicit local IPv6 address, not the
  // client link-address and not necessarily an address on the routed server
  // egress. has_source_address preserves the difference between an absent
  // command and the all-zero IPv6 value, which is never a valid configured
  // source but remains useful in fixed shared-memory records.
  packet::Ipv6 source_address{};
  bool has_source_address{};
  // RFC 9915 defines Interface-Id as an opaque option-length value. A vector is
  // intentional on this configuration path so the packet path does not impose
  // Nokia's 32-character limit for only one of SR OS's supported encodings.
  std::vector<std::uint8_t> relay_interface_id{};
  std::array<RelayDestination,
             device_catalog::dhcpv6_relay_servers_per_interface>
      servers{};
  std::size_t server_count{};
  RelayUpstreamPolicy upstream_policy{RelayUpstreamPolicy::protocol_default};
  // These leaves are operational DHCP snooping policy, not packet encoding
  // shortcuts. client_prefix defines where a learned IA_NA or IA_TA address
  // may become an on-link Neighbor Cache entry. A zero maximum disables lease
  // population and all derived state while leaving stateless relay forwarding
  // active for generic RFC use.
  ip::Ipv6Prefix client_prefix{};
  std::uint16_t lease_population_limit{};
  bool neighbor_resolution{};
  bool route_non_temporary{};
  bool route_temporary{};
  bool route_delegated_prefix{};
  bool route_prefix_exclude{};

  // Configuration generations are immutable values once published to the
  // forwarding owner. Structural equality lets checkpoint and reconciliation
  // code detect a genuinely unchanged program without comparing allocator
  // addresses or reimplementing field order at every call site.
  [[nodiscard]] friend bool
  operator==(const RelayInterfaceConfig &,
             const RelayInterfaceConfig &) = default;
};

enum class RelayConfigStatus : std::uint8_t {
  accepted,
  invalid_interface,
  invalid_link_address,
  interface_id_too_long,
  too_many_servers,
  invalid_server,
  duplicate_server,
  duplicate_return_key,
  resource_exhausted,
  transport_unavailable
};

struct ReceivedRelayDatagram {
  std::uint64_t ingress_interface_id{};
  packet::Ipv6 source{};
  packet::Ipv6 destination{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::span<const std::uint8_t> payload{};
};

enum class RelayDecisionStatus : std::uint8_t {
  forward_upstream,
  forward_downstream,
  not_configured,
  no_upstream_server,
  malformed,
  wrong_ports,
  wrong_destination,
  hop_count_exceeded,
  return_path_not_found,
  return_path_ambiguous,
  output_too_small
};

struct RelayDecision {
  RelayDecisionStatus status{RelayDecisionStatus::malformed};
  std::size_t payload_octets{};
  std::uint64_t egress_interface_id{};
  packet::Ipv6 destination{};
  // Only an upstream decision inherits the interface's configured source.
  // Downstream replies use ordinary egress source selection, normally the
  // client-facing link-local address required for the local link.
  packet::Ipv6 source_address{};
  bool has_source_address{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  // Upstream destinations alias immutable agent configuration. Downstream
  // decisions use destination and leave this span empty.
  std::span<const RelayDestination> upstream_destinations{};
};

[[nodiscard]] constexpr std::optional<std::uint8_t>
relay_hop_limit_override(const packet::Ipv6 &destination) noexcept {
  // RFC 9915 specifies an override only for relay-to-server multicast. Unicast
  // and downstream traffic retain the IPv6 owner's configured default.
  return ip::is_multicast(destination)
             ? std::optional{packet::dhcpv6::relay_multicast_hop_limit}
             : std::nullopt;
}

class RelayAgent final {
public:
  // Configuration replacement is a control-owner operation. Packet owners may
  // call decide() only while the owning shard guarantees that the vector is
  // not being replaced concurrently.
  [[nodiscard]] RelayConfigStatus
  replace_interface(RelayInterfaceConfig config);
  [[nodiscard]] bool remove_interface(std::uint64_t interface_id) noexcept;
  void clear() noexcept;

  // decide() never sends a packet and never retains received spans. It writes
  // one complete DHCPv6 payload into caller-owned storage and returns routing
  // intent. The transport owner must encode UDP, perform source selection and
  // submit every resulting IPv6 fragment through FIB, ND and port queues.
  [[nodiscard]] RelayDecision
  decide(const ReceivedRelayDatagram &received,
         std::span<std::uint8_t> output) const noexcept;

  [[nodiscard]] std::size_t interface_count() const noexcept {
    return interfaces_.size();
  }
  [[nodiscard]] bool configured(std::uint64_t interface_id) const noexcept {
    return find_ingress(interface_id) != nullptr;
  }
  // Scoped addresses and downstream replies carry a stable logical identity.
  // Callers resolve it through this immutable owner lookup, never through
  // ordinal arithmetic or a topology-global interface table.
  [[nodiscard]] const RelayInterfaceConfig *
  interface(std::uint64_t interface_id) const noexcept {
    return find_ingress(interface_id);
  }
  // Untagged physical ingress can select a relay only when exactly one logical
  // relay attachment owns that wire port. Multiple SAPs require the classifier
  // to supply their logical identity and are intentionally ambiguous here.
  [[nodiscard]] const RelayInterfaceConfig *
  unique_on_physical_port(std::uint16_t physical_port_ordinal) const noexcept;
  [[nodiscard]] const std::vector<RelayInterfaceConfig> &
  interfaces() const noexcept {
    return interfaces_;
  }
  // Restore uses the same validation path as live configuration and swaps only
  // after every interface has been accepted. A malformed checkpoint therefore
  // cannot leave a partially replaced return-path table.
  [[nodiscard]] bool
  restore(const std::vector<RelayInterfaceConfig> &interfaces);

private:
  [[nodiscard]] const RelayInterfaceConfig *
  find_ingress(std::uint64_t interface_id) const noexcept;

  std::vector<RelayInterfaceConfig> interfaces_{};
};

} // namespace router::dhcpv6
