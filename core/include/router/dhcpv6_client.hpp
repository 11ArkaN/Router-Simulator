// RFC 9915 DHCPv6 client owner. One endpoint service shard mutates an
// instance. It produces and consumes DHCPv6 UDP payloads, while UDP sockets,
// IPv6 source selection, Neighbor Discovery and link transmission stay below
// this contract and remain the only path to another simulated device.

#pragma once

#include "router/dhcpv6_lease.hpp"
#include "router/dhcpv6_retransmission.hpp"
#include "router/sha256.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv6 {

struct RequestedIdentityAssociation {
  std::uint32_t iaid{};
  LeaseKind kind{LeaseKind::non_temporary};
};

struct ClientConfiguration {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint16_t duid_octets{};
  // Multiple IA_NA and IA_PD instances are allowed by RFC 9915. A vector
  // avoids inventing a count below the message wire limit.
  std::vector<RequestedIdentityAssociation> identity_associations;
  std::vector<std::uint16_t> requested_options;
  // Generated once by the project owner and retained per interface. This
  // secret never enters a packet; it keys transaction ID derivation so an
  // observer cannot predict a later exchange from earlier 24-bit values.
  crypto::Sha256Digest transaction_secret{};
  bool rapid_commit{};
};

enum class ClientState : std::uint8_t {
  stopped,
  soliciting,
  requesting,
  bound,
  renewing,
  rebinding,
  confirming,
  releasing,
  declining,
  information_requesting,
  information_bound,
  failed
};

struct ClientLease {
  packet::Ipv6 value{};
  Retransmission::Clock::time_point preferred_until{};
  Retransmission::Clock::time_point valid_until{};
  Retransmission::Clock::time_point renew_at{};
  Retransmission::Clock::time_point rebind_at{};
  std::uint32_t iaid{};
  std::uint8_t prefix_length{128U};
  LeaseKind kind{LeaseKind::non_temporary};
};

struct ClientLeaseCheckpoint {
  packet::Ipv6 value{};
  std::int64_t preferred_remaining_nanoseconds{};
  std::int64_t valid_remaining_nanoseconds{};
  std::int64_t renew_remaining_nanoseconds{};
  std::int64_t rebind_remaining_nanoseconds{};
  std::uint32_t iaid{};
  std::uint8_t prefix_length{128U};
  LeaseKind kind{LeaseKind::non_temporary};
};

struct ClientOfferCheckpoint {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> server{};
  std::uint16_t server_octets{};
  std::uint8_t preference{};
  std::vector<ClientLeaseCheckpoint> leases;
  bool present{};
};

struct ClientCheckpoint {
  ClientConfiguration configuration{};
  RetransmissionCheckpoint retransmission{};
  ClientOfferCheckpoint offer{};
  std::vector<ClientLeaseCheckpoint> leases;
  // Operation leases are already unusable at the interface while Release or
  // Decline is on the wire. Keeping their exact IA grouping separately lets
  // retransmissions rebuild the message without resurrecting an address.
  std::vector<ClientLeaseCheckpoint> operation_leases;
  std::vector<packet::Ipv6> dns_servers;
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> server{};
  std::uint16_t server_octets{};
  std::uint32_t random_state{};
  std::uint64_t transaction_counter{};
  std::uint32_t solicit_maximum_retransmission_seconds{
      packet::dhcpv6::maximum_retransmission_default_seconds};
  std::uint32_t information_maximum_retransmission_seconds{
      packet::dhcpv6::maximum_retransmission_default_seconds};
  // RFC 9915 section 18.2.9 recommends retaining an Advertise override only
  // when every server that supplied that option agreed. These fields preserve
  // an in-progress discovery consensus across checkpoint restore.
  std::uint32_t advertise_solicit_maximum_seconds{};
  std::uint32_t advertise_information_maximum_seconds{};
  std::uint64_t rate_limit_tokens_scaled{};
  std::int64_t information_refresh_remaining_nanoseconds{};
  ClientState state{ClientState::stopped};
  bool confirm_not_on_link_received{};
  bool rate_limit_initialized{};
  bool advertise_solicit_maximum_seen{};
  bool advertise_solicit_maximum_conflict{};
  bool advertise_information_maximum_seen{};
  bool advertise_information_maximum_conflict{};
};

enum class ClientPollStatus : std::uint8_t {
  idle,
  transmit,
  output_too_small,
  failed
};

struct ClientPollResult {
  ClientPollStatus status{ClientPollStatus::idle};
  std::size_t message_octets{};
};

enum class ClientIngestStatus : std::uint8_t {
  accepted,
  ignored,
  malformed,
  transaction_mismatch,
  identity_mismatch
};

class Client final {
public:
  using Clock = Retransmission::Clock;

  Client();

  // Configuration replacement is atomic and allowed only while stopped.
  // Duplicated (kind, IAID) tuples are rejected because responses would be
  // ambiguous to their independent per-IA state machines.
  [[nodiscard]] bool configure(const ClientConfiguration &configuration);

  // Start creates the Solicit exchange but honors SOL_MAX_DELAY. The caller
  // obtains actual wire data from poll only when the monotonic deadline is
  // ready. transaction_id must be a 24-bit value and seed must be nonzero.
  [[nodiscard]] bool start(std::uint32_t transaction_id, std::uint32_t seed,
                           Clock::time_point now = Clock::now()) noexcept;
  // Production callers use the keyed overload. Both transaction ID and
  // retransmission jitter seed are derived from the persisted interface
  // secret, so no UI or runtime layer invents protocol randomness.
  [[nodiscard]] bool start(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool start_information_request(
      std::uint32_t transaction_id, std::uint32_t seed,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool start_information_request(
      Clock::time_point now = Clock::now()) noexcept;

  // Confirm is legal only for a bound client with address leases and no
  // delegated prefix. The operation retains last-known lifetimes when no
  // server responds, exactly as RFC 9915 section 18.2.3 recommends.
  [[nodiscard]] bool
  start_confirm(Clock::time_point now = Clock::now());

  // Release removes selected leases from the usable set before the first
  // packet can be emitted. Decline has the same safety property and rejects
  // prefixes because DHCPv6 never uses Decline for prefix delegation.
  [[nodiscard]] bool
  start_release(std::span<const packet::Ipv6> values,
                Clock::time_point now = Clock::now());
  [[nodiscard]] bool
  start_decline(std::span<const packet::Ipv6> addresses,
                Clock::time_point now = Clock::now());
  void stop() noexcept;

  [[nodiscard]] ClientPollResult
  poll(std::span<std::uint8_t> output,
       Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ClientIngestStatus
  ingest(std::span<const std::uint8_t> input,
         Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] ClientState state() const noexcept { return state_; }
  [[nodiscard]] std::span<const ClientLease> leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] std::span<const packet::Ipv6> dns_servers() const noexcept {
    return dns_servers_;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] ClientCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const ClientCheckpoint &checkpoint);
  [[nodiscard]] bool
  restore(const ClientCheckpoint &checkpoint,
          Clock::time_point now = Clock::now());

private:
  struct Offer {
    std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> server{};
    std::uint16_t server_octets{};
    std::uint8_t preference{};
    std::vector<ClientLease> leases;
    bool present{};
  };

  [[nodiscard]] std::uint32_t next_transaction_id() noexcept;
  [[nodiscard]] bool begin_exchange(ExchangeKind kind, ClientState state,
                                    Clock::time_point now) noexcept;
  [[nodiscard]] ClientPollResult build(std::span<std::uint8_t> output,
                                       Clock::time_point now) noexcept;
  [[nodiscard]] bool select_offer(Clock::time_point now) noexcept;
  [[nodiscard]] std::uint64_t
  rate_tokens_at(Clock::time_point now) const noexcept;
  [[nodiscard]] bool consume_rate_token(Clock::time_point now) noexcept;

  ClientConfiguration configuration_{};
  Retransmission retransmission_{};
  Offer offer_{};
  std::vector<ClientLease> leases_;
  std::vector<ClientLease> operation_leases_;
  std::vector<packet::Ipv6> dns_servers_;
  std::vector<std::uint8_t> oro_bytes_;
  std::vector<std::uint8_t> information_oro_bytes_;
  std::vector<std::uint8_t> ia_scratch_;
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> server_{};
  std::uint16_t server_octets_{};
  std::uint32_t random_state_{};
  // Only this client owner increments the counter. Saving it in checkpoints
  // prevents a resumed project from repeating the same keyed ID sequence.
  std::uint64_t transaction_counter_{};
  // These interface-scoped values survive individual exchanges. Servers can
  // change them only through validated RFC 9915 options 82 and 83.
  std::uint32_t solicit_maximum_retransmission_seconds_{
      packet::dhcpv6::maximum_retransmission_default_seconds};
  std::uint32_t information_maximum_retransmission_seconds_{
      packet::dhcpv6::maximum_retransmission_default_seconds};
  std::uint32_t advertise_solicit_maximum_seconds_{};
  std::uint32_t advertise_information_maximum_seconds_{};
  // One Client instance belongs to one interface, satisfying RFC 9915's
  // per-interface token-bucket requirement without any global coordinator.
  std::uint64_t rate_limit_tokens_scaled_{};
  Clock::time_point rate_limit_refilled_at_{};
  bool rate_limit_initialized_{};
  bool advertise_solicit_maximum_seen_{};
  bool advertise_solicit_maximum_conflict_{};
  bool advertise_information_maximum_seen_{};
  bool advertise_information_maximum_conflict_{};
  Clock::time_point information_refresh_at_{};
  ClientState state_{ClientState::stopped};
  bool confirm_not_on_link_received_{};
};

} // namespace router::dhcpv6
