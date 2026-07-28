// RFC 9915 DHCPv6 server message owner. One service shard owns each Server,
// its lease repository and configuration. The API accepts and emits DHCPv6
// wire bytes only; UDP, IPv6, relay traversal and link delivery remain owned
// by the endpoint packet path and cannot be bypassed by this module.

#pragma once

#include "router/dhcpv6_lease.hpp"
#include "router/dhcpv6_relay.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv6 {

struct ServerConfiguration {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint16_t duid_octets{};
  std::uint8_t preference{};
  std::uint8_t address_pool_index{};
  std::uint8_t prefix_pool_index{};
  std::uint32_t information_refresh_time_seconds{
      packet::dhcpv6::information_refresh_default_seconds};
  bool rapid_commit{};
  // Nokia SR OS disables DHCPv6 Leasequery until the administrator explicitly
  // enables `lease-query` / `allow-lease-query`. This policy is separate from
  // codec support so disabled queries can receive the RFC 5007 NotAllowed
  // response without changing any lease state.
  bool lease_query{};
  // RFC 3646 defines an ordered list without a protocol count field. A vector
  // preserves administrator order and avoids inventing an unrelated ceiling.
  // The eventual response is bounded only by the ordinary UDP length field.
  std::vector<packet::Ipv6> dns_recursive_servers;
  // Empty values retain the RFC defaults. Present values are returned only
  // when the matching control option was requested by the client.
  std::optional<std::uint32_t> solicit_maximum_retransmission_seconds;
  std::optional<std::uint32_t> information_maximum_retransmission_seconds;
};

enum class ServerProcessStatus : std::uint8_t {
  response,
  discarded,
  malformed,
  output_too_small,
  unsupported_relay,
  not_configured
};

struct ServerProcessResult {
  ServerProcessStatus status{ServerProcessStatus::discarded};
  std::size_t message_octets{};
};

// These counters are owned by the same control-plane shard as Server. They
// count complete DHCPv6 messages at the server boundary, not UDP fragments or
// retransmission intentions. A relayed client message increments both the
// Relay-forward counter and the innermost client-message counter because SR OS
// exposes transport and message activity independently.
struct ServerStatistics {
  std::uint64_t rx_solicit{};
  std::uint64_t rx_request{};
  std::uint64_t rx_confirm{};
  std::uint64_t rx_renew{};
  std::uint64_t rx_rebind{};
  std::uint64_t rx_release{};
  std::uint64_t rx_decline{};
  std::uint64_t rx_information_request{};
  std::uint64_t rx_relay_forward{};
  std::uint64_t rx_leasequery{};
  std::uint64_t tx_advertise{};
  std::uint64_t tx_reply{};
  std::uint64_t tx_reconfigure{};
  std::uint64_t tx_relay_reply{};
  std::uint64_t tx_leasequery_reply{};
  std::uint64_t dropped_bad_packet{};
  std::uint64_t dropped_not_allowed{};
  std::uint64_t dropped_resource_exhausted{};
};

struct ServerCheckpoint {
  ServerConfiguration configuration{};
  std::vector<LeasePool> address_pools;
  std::vector<LeasePool> prefix_pools;
  std::vector<LeaseCheckpoint> leases;
  std::vector<FailoverBindingCheckpoint> failover_bindings;
  ServerStatistics statistics{};
  std::int64_t decline_hold_seconds{};
  bool configured{};
};

class Server final {
public:
  using Clock = LeaseRepository::Clock;

  Server();

  // Configuration replacement is atomic. All pools must share T1 and T2 so
  // one response containing multiple IA types obeys RFC 9915 section 18.1.
  // A false result leaves the previous server and lease database untouched.
  [[nodiscard]] bool configure(
      const ServerConfiguration &configuration,
      std::span<const LeasePool> address_pools,
      std::span<const LeasePool> prefix_pools,
      std::chrono::seconds decline_hold_time) noexcept;

  // Preconditions: input is exactly one UDP payload received on server port
  // 547, and output may contain any legal UDP payload up to 65535 octets.
  // Postcondition: `response` returns a freshly generated message whose
  // lifetimes reflect `now`; responses are never cached across retransmits.
  [[nodiscard]] ServerProcessResult process(
      std::span<const std::uint8_t> input, std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now(),
      const crypto::Sha256Digest &direct_link_identity = {},
      packet::Ipv6 direct_client_address = {}) noexcept;

  [[nodiscard]] const LeaseRepository &leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] LeaseRepository &leases() noexcept { return leases_; }
  [[nodiscard]] const ServerStatistics &statistics() const noexcept {
    return statistics_;
  }
  void clear_statistics() noexcept { statistics_ = {}; }
  [[nodiscard]] ServerCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const ServerCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const ServerCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  // Selection is link-aware before allocation. This prevents vector order
  // from deciding which subnet serves a relayed request when several pools
  // are configured in one Base server.
  [[nodiscard]] std::optional<std::size_t>
  pool_for(LeaseKind kind,
           const crypto::Sha256Digest &link_identity) const noexcept;
  [[nodiscard]] ServerProcessResult process_impl(
      std::span<const std::uint8_t> input, std::span<std::uint8_t> output,
      Clock::time_point now,
      std::uint8_t relay_depth,
      const crypto::Sha256Digest &link_identity,
      packet::Ipv6 client_address) noexcept;

  ServerConfiguration configuration_{};
  std::vector<LeasePool> address_pools_;
  std::vector<LeasePool> prefix_pools_;
  std::chrono::seconds decline_hold_time_{};
  LeaseRepository leases_{};
  // Two eagerly allocated full-message buffers allow arbitrary legal DHCPv6
  // messages to traverse nested relays without per-packet heap allocation.
  // The buffers alternate while each Relay-reply layer is reconstructed.
  std::vector<std::uint8_t> relay_scratch_a_;
  std::vector<std::uint8_t> relay_scratch_b_;
  // OPTION_CLIENT_DATA may contain every live IAADDR and IAPREFIX for one
  // DUID. A reusable maximum-wire-size buffer avoids per-query heap work and
  // remains independent of the two buffers used for relay nesting.
  std::vector<std::uint8_t> leasequery_scratch_;
  ServerStatistics statistics_{};
  bool configured_{};
};

} // namespace router::dhcpv6
