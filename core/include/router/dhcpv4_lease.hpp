// DHCPv4 lease repository and allocation policy. One server control-plane
// shard owns each repository. The repository serializes every reservation,
// offer and binding mutation and has no dependency on sockets, forwarding or
// management presentation.

#pragma once

#include "router/dhcpv4_failover.hpp"
#include "router/dhcpv4_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv4 {

inline constexpr std::size_t maximum_client_identifier_octets = 255U;

struct ClientKey {
  // Option 61 can occupy one complete DHCPv4 option. When it is absent, the
  // server stores htype followed by exactly hlen bytes from chaddr. The boolean
  // prevents the two namespaces from colliding.
  std::array<std::uint8_t, maximum_client_identifier_octets> bytes{};
  std::uint16_t octets{};
  bool option_61{};
};

[[nodiscard]] bool equal_client_key(const ClientKey &left,
                                    const ClientKey &right) noexcept;
[[nodiscard]] std::optional<ClientKey>
client_key(const packet::dhcpv4::MessageView &message) noexcept;

struct AllocationScope {
  std::uint32_t server_instance{};
  std::uint32_t routing_context{};
  std::uint64_t link_identity{};
};

struct ClientHardwareIdentity {
  std::array<std::uint8_t, 16U> address{};
  std::uint8_t type{};
  std::uint8_t length{};
};

struct Pool {
  std::uint16_t id{};
  AllocationScope scope{};
  packet::Ipv4 first{};
  packet::Ipv4 last{};
  packet::Ipv4 subnet_mask{};
  packet::Ipv4 router{};
  // The legacy lease_seconds field is the effective value used by dedicated
  // host programs. Named SR OS pools additionally provide lower and upper
  // policy bounds plus their own OFFER retention interval.
  std::uint32_t lease_seconds{};
  std::uint32_t minimum_lease_seconds{};
  std::uint32_t maximum_lease_seconds{};
  std::uint32_t offer_seconds{};
  std::uint32_t maximum_declined{
      device_catalog::dhcpv4_maximum_declined_default};
  std::uint32_t renewal_seconds{};
  std::uint32_t rebinding_seconds{};
  bool enabled{};
};

struct Reservation {
  AllocationScope scope{};
  ClientKey client{};
  packet::Ipv4 address{};
};

struct ExcludedRange {
  // Exclusions are allocation policy, not synthetic leases. Keeping them in a
  // separate ordered set prevents a configured exclusion from consuming a
  // lease slot or appearing in operational lease output.
  AllocationScope scope{};
  packet::Ipv4 first{};
  packet::Ipv4 last{};
};

enum class BindingState : std::uint8_t {
  pending_offer,
  active,
  expired,
  released,
  declined,
  conflict,
  reserved,
};

// SR OS exposes operational lease states that are slightly wider than the
// RFC 2131 repository states because some values belong to subscriber and
// failover features. The filter retains the release vocabulary at the
// management boundary while matches() below maps only states that this owner
// can actually hold. Unsupported state values therefore select an empty set,
// which is the correct result of an operational clear rather than a fake
// mutation.
enum class OperationalLeaseState : std::uint8_t {
  any,
  offered,
  stable,
  force_renew_pending,
  remove_pending,
  held,
  internal,
  internal_orphan,
  internal_offered,
  internal_held,
  sticky,
};

struct LeaseClearFilter {
  packet::Ipv4 address{};
  std::uint8_t prefix_length{32U};
  OperationalLeaseState state{OperationalLeaseState::any};
  bool address_specific{};
};

struct Lease {
  AllocationScope scope{};
  ClientKey client{};
  // Option 61 may be unrelated to Ethernet. Retaining the original BOOTP
  // hardware tuple is therefore required for a real direct FORCERENEW.
  ClientHardwareIdentity hardware{};
  // RFC 4388 requires the server to retain the most recent complete Relay
  // Agent Information value and the time of the last client interaction.
  // A fixed byte array keeps the binding repository bounded and avoids an
  // allocation when each DHCPREQUEST refreshes an existing binding.
  std::array<std::uint8_t, 255U> relay_agent_information{};
  std::uint16_t relay_agent_information_octets{};
  packet::Ipv4 address{};
  std::uint32_t transaction_id{};
  std::chrono::steady_clock::time_point offered_until{};
  std::chrono::steady_clock::time_point active_until{};
  std::chrono::steady_clock::time_point last_client_transaction{};
  // Leasequery time filters apply to the binding transition, not merely to a
  // client packet. Expiry is therefore recorded even when no datagram caused
  // it. revision is an owner-local Active Leasequery cursor and is never sent
  // as a protocol value.
  std::chrono::steady_clock::time_point last_state_change{};
  std::uint32_t lease_seconds{};
  std::uint64_t decline_sequence{};
  std::uint64_t revision{};
  // Failover timestamps are protocol absolute seconds, not local scheduling
  // deadlines. They are compared before applying a partner update and survive
  // checkpoint restore without being rebased to another steady-clock epoch.
  std::uint32_t failover_state_started_absolute{};
  std::uint32_t failover_partner_expiration_absolute{};
  failover::BindingStatus failover_status{failover::BindingStatus::free};
  BindingState state{BindingState::expired};
  bool sticky{};
  bool failover_managed{};
};

struct LeaseCheckpoint {
  AllocationScope scope{};
  ClientKey client{};
  ClientHardwareIdentity hardware{};
  std::array<std::uint8_t, 255U> relay_agent_information{};
  std::uint16_t relay_agent_information_octets{};
  packet::Ipv4 address{};
  std::uint32_t transaction_id{};
  std::int64_t offer_remaining_nanoseconds{};
  std::int64_t active_remaining_nanoseconds{};
  std::int64_t last_client_transaction_elapsed_nanoseconds{};
  std::int64_t last_state_change_elapsed_nanoseconds{};
  std::uint32_t lease_seconds{};
  std::uint64_t decline_sequence{};
  std::uint64_t revision{};
  std::uint32_t failover_state_started_absolute{};
  std::uint32_t failover_partner_expiration_absolute{};
  failover::BindingStatus failover_status{failover::BindingStatus::free};
  BindingState state{BindingState::expired};
  bool sticky{};
  bool failover_managed{};
};

struct LeaseRepositoryCheckpoint {
  std::vector<Pool> pools;
  std::vector<Reservation> reservations;
  std::vector<ExcludedRange> exclusions;
  std::vector<LeaseCheckpoint> leases;
  std::int64_t offer_hold_nanoseconds{};
  std::int64_t decline_hold_nanoseconds{};
  std::uint64_t next_decline_sequence{1U};
  std::uint64_t next_revision{1U};
};

enum class AllocateStatus : std::uint8_t {
  offered,
  reused,
  exhausted,
  unknown_scope,
  ambiguous_scope,
  invalid_request,
  resource_exhausted,
};

enum class PartnerUpdateStatus : std::uint8_t {
  applied,
  duplicate,
  unknown_address,
  ambiguous_address,
  invalid_update,
  resource_exhausted,
};

struct AllocateResult {
  AllocateStatus status{AllocateStatus::invalid_request};
  packet::Ipv4 address{};
  std::uint16_t pool_id{};
  std::uint32_t lease_seconds{};
};

class LeaseRepository final {
public:
  using Clock = std::chrono::steady_clock;

  LeaseRepository();

  // Replacement validates all ranges and overlapping enabled scopes before
  // changing the live repository. Existing bindings outside the replacement
  // pool set remain historical but are never offered again.
  [[nodiscard]] bool configure(std::span<const Pool> pools,
                               std::span<const Reservation> reservations,
                               std::chrono::seconds offer_hold,
                               std::chrono::seconds decline_hold,
                               std::span<const ExcludedRange> exclusions = {});

  // offer performs the exact policy order: reservation, active lease, sticky
  // lease, requested address and deterministic first-free. The one owner makes
  // candidate selection and PENDING-OFFER creation one atomic operation.
  [[nodiscard]] AllocateResult
  offer(const AllocationScope &scope, const ClientKey &client,
        std::uint32_t transaction_id,
        std::optional<packet::Ipv4> requested_address,
        Clock::time_point now = Clock::now(),
        std::optional<std::uint32_t>
            requested_lease_seconds = std::nullopt,
        ClientHardwareIdentity hardware = {},
        std::span<const std::uint8_t> relay_agent_information = {});

  // commit accepts only an address reserved by the same client transaction or
  // a still-valid existing binding. This prevents an ACK from claiming an
  // address that another transaction acquired after an expired offer.
  [[nodiscard]] bool commit(const AllocationScope &scope,
                            const ClientKey &client,
                            std::uint32_t transaction_id,
                            packet::Ipv4 address,
                            Clock::time_point now = Clock::now(),
                            std::optional<std::uint32_t>
                                requested_lease_seconds = std::nullopt,
                            ClientHardwareIdentity hardware = {},
                            std::span<const std::uint8_t>
                                relay_agent_information = {});
  [[nodiscard]] bool release(const AllocationScope &scope,
                             const ClientKey &client,
                             packet::Ipv4 address,
                             Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool decline(const AllocationScope &scope,
                             const ClientKey &client,
                             packet::Ipv4 address,
                             Clock::time_point now = Clock::now()) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] LeaseRepositoryCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool
  restore(const LeaseRepositoryCheckpoint &state,
          Clock::time_point now = Clock::now());

  [[nodiscard]] std::span<const Lease> leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] std::span<const Pool> pools() const noexcept { return pools_; }
  [[nodiscard]] std::uint64_t current_revision() const noexcept {
    return next_revision_ - 1U;
  }
  [[nodiscard]] const Pool *pool_for(const AllocationScope &scope,
                                     packet::Ipv4 address) const noexcept;
  [[nodiscard]] const Lease *lease_for(const AllocationScope &scope,
                                       const ClientKey &client) const noexcept;
  [[nodiscard]] const Lease *
  active_lease_at(packet::Ipv4 address,
                  Clock::time_point now = Clock::now()) noexcept;
  // Operational clear is an owner-affine mutation. It removes every matching
  // binding in one erase pass after expiring stale timers, so observers never
  // see a partially cleared selection. An empty selection is a valid clear.
  [[nodiscard]] std::size_t
  clear(const LeaseClearFilter &filter,
        Clock::time_point now = Clock::now()) noexcept;
  // The failover session calls this only after authenticating and decoding one
  // BNDUPD. The repository is the sole lease mutation owner, so a successful
  // return is the exact commit point after which BNDACK may be transmitted.
  [[nodiscard]] PartnerUpdateStatus apply_partner_update(
      const failover::BindingUpdateView &update,
      std::uint32_t absolute_now,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] PartnerUpdateStatus apply_partner_updates(
      std::span<const failover::BindingUpdateView> updates,
      std::uint32_t absolute_now,
      Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] bool address_available(const Pool &pool,
                                       packet::Ipv4 address,
                                       const ClientKey &client,
                                       Clock::time_point now) const noexcept;
  [[nodiscard]] std::optional<packet::Ipv4>
  first_available(const Pool &pool, const ClientKey &client,
                  Clock::time_point now) const noexcept;
  [[nodiscard]] Lease *binding(const AllocationScope &scope,
                               const ClientKey &client) noexcept;
  [[nodiscard]] const Reservation *
  reservation(const AllocationScope &scope,
              const ClientKey &client) const noexcept;
  // Only the repository owner advances this sequence. Exhaustion is not
  // practically reachable within a runtime, but saturating preserves strict
  // ordering instead of wrapping an active subscriber behind older records.
  void record_change(Lease &lease, Clock::time_point now) noexcept;

  std::vector<Pool> pools_;
  std::vector<Reservation> reservations_;
  std::vector<ExcludedRange> exclusions_;
  std::vector<Lease> leases_;
  std::chrono::seconds offer_hold_{60};
  std::chrono::seconds decline_hold_{3600};
  std::uint64_t next_decline_sequence_{1U};
  std::uint64_t next_revision_{1U};
};

} // namespace router::dhcpv4
