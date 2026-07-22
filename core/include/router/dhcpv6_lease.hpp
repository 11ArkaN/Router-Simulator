// DHCPv6 server lease repository and administrator-defined allocation pools.
// One service shard owns an instance. It allocates only local values, never
// sends packets and never reads host, router, topology or UI state directly.

#pragma once

#include "router/dhcpv6_packet.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"
#include "router/sha256.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::dhcpv6 {

enum class LeaseKind : std::uint8_t { non_temporary, temporary, prefix };

struct LeasePool {
  // For address pools, prefix.length defines the address allocation prefix.
  // For prefix pools, delegated_length selects each child prefix carved from
  // prefix. An allocation secret makes the default address policy resistant
  // to client enumeration, as recommended by RFC 9915 section 13.1.
  ip::Ipv6Prefix prefix{};
  crypto::Sha256Digest allocation_secret{};
  std::uint32_t preferred_lifetime_seconds{};
  std::uint32_t valid_lifetime_seconds{};
  std::uint32_t t1_seconds{};
  std::uint32_t t2_seconds{};
  std::uint8_t delegated_length{};
};

struct ClientIdentity {
  // DUID bytes are compared only across duid_octets. The unused fixed-array
  // tail is initialized to zero by every decoder, making default value
  // equality safe for immutable checkpoint and mutation records.
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint16_t duid_octets{};
  std::uint32_t iaid{};
  LeaseKind kind{LeaseKind::non_temporary};

  [[nodiscard]] friend constexpr bool
  operator==(const ClientIdentity &, const ClientIdentity &) noexcept =
      default;
};

enum class LeaseStatus : std::uint8_t {
  assigned,
  renewed,
  invalid_client,
  invalid_pool,
  no_binding,
  released,
  declined,
  no_addresses_available,
  no_prefixes_available
};

struct LeaseResult {
  LeaseStatus status{LeaseStatus::invalid_client};
  packet::Ipv6 value{};
  std::uint32_t preferred_lifetime_seconds{};
  std::uint32_t valid_lifetime_seconds{};
  std::uint32_t t1_seconds{};
  std::uint32_t t2_seconds{};
  std::uint8_t prefix_length{128U};
};

struct LeaseCheckpoint {
  ClientIdentity client{};
  packet::Ipv6 value{};
  std::int64_t preferred_remaining_nanoseconds{};
  std::int64_t valid_remaining_nanoseconds{};
  std::int64_t declined_remaining_nanoseconds{};
  std::uint16_t pool_index{};
  std::uint8_t prefix_length{128U};
  bool declined{};
};

class LeaseRepository final {
public:
  using Clock = std::chrono::steady_clock;

  // Configuration replacement is atomic. Every prefix must be canonical,
  // every secret nonzero and T1 <= T2 <= valid lifetime. Address and delegated
  // prefix pools are separate administrator policies and may share an
  // aggregate without sharing lease ownership.
  [[nodiscard]] bool configure(
      std::span<const LeasePool> address_pools,
      std::span<const LeasePool> prefix_pools,
      std::chrono::seconds decline_hold_time) noexcept;

  [[nodiscard]] LeaseResult assign(
      const ClientIdentity &client, std::size_t pool_index,
      Clock::time_point now = Clock::now()) noexcept;
  // Advertise may describe an available value, but RFC 9915's four-message
  // exchange does not commit that value until Request. Preview performs the
  // same secret-derived collision walk as assign without mutating repository
  // state, so merely receiving Solicit cannot consume a lease.
  [[nodiscard]] LeaseResult preview(
      const ClientIdentity &client, std::size_t pool_index,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] LeaseResult renew(
      const ClientIdentity &client,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] LeaseStatus release(const ClientIdentity &client) noexcept;
  [[nodiscard]] LeaseStatus decline(
      const ClientIdentity &client,
      Clock::time_point now = Clock::now()) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::size_t active_leases() const noexcept;
  [[nodiscard]] std::size_t declined_values() const noexcept;
  // Confirm and relay policy check whether a client-supplied value belongs to
  // any pool configured for the link. This does not require or create a
  // binding because Confirm validates location, not lease ownership.
  [[nodiscard]] bool has_address_policy() const noexcept {
    return address_pool_count_ != 0U;
  }
  [[nodiscard]] bool appropriate_address(packet::Ipv6 address) const noexcept;
  [[nodiscard]] std::vector<LeaseCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool validate_checkpoint(
      std::span<const LeaseCheckpoint> state) const noexcept;
  [[nodiscard]] bool restore(
      std::span<const LeaseCheckpoint> state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Lease {
    ClientIdentity client{};
    packet::Ipv6 value{};
    Clock::time_point preferred_until{};
    Clock::time_point valid_until{};
    Clock::time_point declined_until{};
    std::uint16_t pool_index{};
    std::uint8_t prefix_length{128U};
    bool occupied{};
    bool declined{};
  };

  [[nodiscard]] static bool valid_client(
      const ClientIdentity &client) noexcept;
  [[nodiscard]] static bool same_client(
      const ClientIdentity &left, const ClientIdentity &right) noexcept;
  [[nodiscard]] Lease *find(const ClientIdentity &client) noexcept;
  [[nodiscard]] const Lease *find(const ClientIdentity &client) const noexcept;
  [[nodiscard]] LeaseResult result(const Lease &lease,
                                   Clock::time_point now,
                                   LeaseStatus status) const noexcept;
  [[nodiscard]] packet::Ipv6 candidate(
      const LeasePool &pool, const ClientIdentity &client,
      std::uint32_t attempt) const noexcept;
  [[nodiscard]] bool value_in_use(LeaseKind kind, packet::Ipv6 value,
                                  std::uint8_t prefix_length) const noexcept;

  std::array<LeasePool, device_catalog::dhcpv6_address_pools_per_server>
      address_pools_{};
  std::array<LeasePool, device_catalog::dhcpv6_prefix_pools_per_server>
      prefix_pools_{};
  std::array<Lease, device_catalog::dhcpv6_leases_per_server> leases_{};
  std::chrono::seconds decline_hold_time_{};
  std::uint8_t address_pool_count_{};
  std::uint8_t prefix_pool_count_{};
};

} // namespace router::dhcpv6
