// DHCPv6 relay lease-state owner. It snoops only validated DHCPv6 wire
// messages, enforces the configured per-interface SR OS lease limit before a
// Reply is forwarded, and publishes value-only route and neighbor intentions.
// It never mutates a RIB, FIB, Neighbor Cache, port or link directly.

#pragma once

#include "router/dhcpv6_lease.hpp"
#include "router/ip_address.hpp"
#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv6 {

enum class RelayLeaseProtocol : std::uint8_t {
  non_temporary,
  temporary,
  delegated_prefix
};

struct RelayLeasePolicy {
  // Stable logical and physical identities are both retained because a
  // dynamic route resolves in an RFC 4007 zone before it reaches a wire port.
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  ip::Ipv6Prefix client_prefix{};
  std::uint16_t maximum_leases{};
  bool neighbor_resolution{};
  bool route_non_temporary{};
  bool route_temporary{};
  bool route_delegated_prefix{};
  bool route_prefix_exclude{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayLeasePolicy &, const RelayLeasePolicy &) noexcept =
      default;
};

struct RelayClientObservation {
  // DUID is opaque by RFC 9915. No attempt is made to derive a MAC from its
  // type because future and enterprise DUID forms remain legal.
  ClientIdentity client{};
  packet::Ipv6 peer_address{};
  packet::Mac source_mac{};
  std::uint64_t interface_id{};
  std::uint32_t transaction_id{};
  std::chrono::steady_clock::time_point expires_at{};
};

struct RelayServerIdentity {
  // RFC 9915 treats Server Identifier as an opaque DUID exactly like Client
  // Identifier. The relay retains the bytes needed to generate a later
  // operator-requested Release without interpreting a hardware address.
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint16_t duid_octets{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayServerIdentity &, const RelayServerIdentity &) noexcept =
      default;
};

struct RelayLeaseRecord {
  ClientIdentity client{};
  RelayServerIdentity server{};
  packet::Ipv6 value{};
  packet::Ipv6 peer_address{};
  packet::Ipv6 server_address{};
  packet::Mac client_mac{};
  packet::Ipv6 excluded_prefix{};
  std::uint64_t interface_id{};
  // A link-local server source requires the RFC 4007 ingress zone when an
  // operator-generated Release later returns to it. Global server addresses
  // retain the field for validation but use ordinary FIB lookup.
  std::uint64_t server_scope_interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t prefix_length{128U};
  std::uint8_t excluded_prefix_length{};
  RelayLeaseProtocol protocol{RelayLeaseProtocol::non_temporary};
  std::chrono::steady_clock::time_point preferred_until{};
  std::chrono::steady_clock::time_point valid_until{};
  bool has_client_mac{};
  bool has_excluded_prefix{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayLeaseRecord &, const RelayLeaseRecord &) noexcept =
      default;
};

enum class RelayLeaseMutationKind : std::uint8_t { install, remove };

struct RelayLeaseMutation {
  // A mutation is consumed by the route and adjacency owners after the relay
  // repository has proved the whole Reply fits. An install replaces the same
  // lease key; a remove withdraws every derived operational object.
  RelayLeaseMutationKind kind{RelayLeaseMutationKind::install};
  RelayLeaseRecord record{};
};

enum class RelayLeaseReplyStatus : std::uint8_t {
  accepted,
  disabled,
  malformed,
  wrong_message_type,
  lease_limit_exceeded,
  resource_exhausted,
  no_prepared_reply
};

struct RelayLeaseReplyPlan {
  RelayLeaseReplyStatus status{RelayLeaseReplyStatus::malformed};
  std::span<const RelayLeaseMutation> mutations{};
};

struct RelayLeaseClearFilter {
  // The forwarding owner receives a stable service-interface identity from
  // control. Optional address and MAC selectors implement the exact SR OS
  // clear forms without exposing service names or SAP strings to packet code.
  std::uint64_t interface_id{};
  ip::Ipv6Prefix prefix{};
  packet::Mac mac{};
  bool prefix_specific{};
  bool mac_specific{};
};

struct RelayLeaseCheckpoint {
  ClientIdentity client{};
  RelayServerIdentity server{};
  packet::Ipv6 value{};
  packet::Ipv6 peer_address{};
  packet::Ipv6 server_address{};
  packet::Mac client_mac{};
  packet::Ipv6 excluded_prefix{};
  std::uint64_t interface_id{};
  std::uint64_t server_scope_interface_id{};
  std::int64_t preferred_remaining_nanoseconds{};
  std::int64_t valid_remaining_nanoseconds{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t prefix_length{128U};
  std::uint8_t excluded_prefix_length{};
  RelayLeaseProtocol protocol{RelayLeaseProtocol::non_temporary};
  bool has_client_mac{};
  bool has_excluded_prefix{};
};

class RelayLeaseRepository final {
public:
  using Clock = std::chrono::steady_clock;

  // Policy replacement allocates all capacity on the configuration path.
  // Packet processing can then prepare and commit a maximum-size legal Reply
  // without heap growth. Existing leases outside the replacement policy are
  // rejected rather than silently discarded; the caller must explicitly
  // drain them first and publish their withdrawals.
  [[nodiscard]] bool
  configure(std::span<const RelayLeasePolicy> policies) noexcept;

  // Direct client observations correlate a Reply with the actual Ethernet
  // source without interpreting DUID bytes. Nested Relay-forward messages are
  // not passed here because their source MAC belongs to another relay.
  [[nodiscard]] bool observe_client(
      std::uint64_t interface_id, packet::Ipv6 peer_address,
      packet::Mac source_mac, std::span<const std::uint8_t> message,
      Clock::time_point now = Clock::now()) noexcept;

  // prepare_reply performs all parsing, duplicate checks and capacity checks
  // without mutating live lease state. The returned span aliases repository
  // scratch and remains valid only until the next non-const method call.
  [[nodiscard]] RelayLeaseReplyPlan prepare_reply(
      std::uint64_t interface_id, packet::Ipv6 peer_address,
      packet::Ipv6 server_address,
      std::uint64_t server_scope_interface_id,
      std::span<const std::uint8_t> message,
      Clock::time_point now = Clock::now()) noexcept;

  // Commit is separate so the forwarding owner can first prove that every
  // downstream frame and every route event fits its bounded egress ring. A
  // failed admission therefore leaves both lease state and packet output
  // unchanged.
  [[nodiscard]] bool commit_prepared() noexcept;
  void discard_prepared() noexcept;

  // Expiry is also two-phase. The caller publishes all returned withdrawals
  // before committing them, preserving the same overload contract as Reply.
  [[nodiscard]] std::span<const RelayLeaseMutation>
  prepare_expiry(Clock::time_point now = Clock::now()) noexcept;

  // Configuration removal must withdraw every derived object before the
  // policy disappears. This prepares those removals without changing the
  // repository, allowing the caller to reserve its output channels first.
  [[nodiscard]] std::span<const RelayLeaseMutation>
  prepare_remove_interface(std::uint64_t interface_id) noexcept;

  // Operator clear uses the same two-phase withdrawal contract as expiry.
  // A filter that matches no live row is a successful empty operation, which
  // agrees with an idempotent operational clear and does not invent state.
  [[nodiscard]] std::span<const RelayLeaseMutation>
  prepare_clear(const RelayLeaseClearFilter &filter) noexcept;

  [[nodiscard]] std::span<const RelayLeaseRecord> leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] std::size_t lease_count(std::uint64_t interface_id) const
      noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] std::vector<RelayLeaseCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(
      std::span<const RelayLeasePolicy> policies,
      std::span<const RelayLeaseCheckpoint> state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  enum class PreparedKind : std::uint8_t {
    none,
    reply,
    expiry,
    operator_clear
  };

  [[nodiscard]] const RelayLeasePolicy *
  policy(std::uint64_t interface_id) const noexcept;
  [[nodiscard]] const RelayClientObservation *observation(
      std::uint64_t interface_id, std::uint32_t transaction_id,
      const ClientIdentity &client, packet::Ipv6 peer_address,
      Clock::time_point now) const noexcept;
  [[nodiscard]] static bool same_client(const ClientIdentity &left,
                                        const ClientIdentity &right) noexcept;
  [[nodiscard]] static bool same_lease_key(const RelayLeaseRecord &left,
                                           const RelayLeaseRecord &right)
      noexcept;
  void remove_expired_observations(Clock::time_point now) noexcept;

  std::vector<RelayLeasePolicy> policies_;
  std::vector<RelayClientObservation> observations_;
  std::vector<RelayLeaseRecord> leases_;
  std::vector<RelayLeaseMutation> prepared_;
  PreparedKind prepared_kind_{PreparedKind::none};
};

} // namespace router::dhcpv6
