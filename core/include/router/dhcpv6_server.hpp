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

struct ServerCheckpoint {
  ServerConfiguration configuration{};
  std::vector<LeasePool> address_pools;
  std::vector<LeasePool> prefix_pools;
  std::vector<LeaseCheckpoint> leases;
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
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] const LeaseRepository &leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] LeaseRepository &leases() noexcept { return leases_; }
  [[nodiscard]] ServerCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const ServerCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const ServerCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] ServerProcessResult process_impl(
      std::span<const std::uint8_t> input, std::span<std::uint8_t> output,
      Clock::time_point now,
      std::uint8_t relay_depth) noexcept;

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
  bool configured_{};
};

} // namespace router::dhcpv6
