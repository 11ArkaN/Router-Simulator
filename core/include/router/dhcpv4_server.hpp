// RFC 2131 DHCPv4 server transaction owner. One control-plane shard owns the
// server and its LeaseRepository. Inputs and outputs are complete UDP payloads;
// the caller remains responsible for broadcast, direct L2 or routed delivery.

#pragma once

#include "router/dhcpv4_lease.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::dhcpv4 {

struct ServerConfiguration {
  std::uint32_t server_instance{};
  std::uint32_t routing_context{};
  packet::Ipv4 server_identifier{};
  std::vector<packet::Ipv4> domain_name_servers;
  std::chrono::seconds offer_hold{60};
  std::chrono::seconds decline_hold{3600};
  bool authoritative{true};
  bool force_renews{};
};

struct ServerStatistics {
  std::uint64_t rx_discover{};
  std::uint64_t rx_request{};
  std::uint64_t rx_release{};
  std::uint64_t rx_decline{};
  std::uint64_t rx_inform{};
  std::uint64_t rx_lease_query{};
  std::uint64_t tx_offer{};
  std::uint64_t tx_acknowledgement{};
  std::uint64_t tx_negative_acknowledgement{};
  std::uint64_t tx_force_renew{};
  std::uint64_t tx_lease_active{};
  std::uint64_t tx_lease_unassigned{};
  std::uint64_t tx_lease_unknown{};
  std::uint64_t dropped_bad_packet{};
  std::uint64_t dropped_unknown_scope{};
  std::uint64_t dropped_address_unavailable{};
  std::uint64_t dropped_resource_exhausted{};
};

enum class ServerProcessStatus : std::uint8_t {
  response,
  discarded,
  malformed,
  unknown_scope,
  resource_exhausted,
  output_too_small,
  not_configured,
};

struct ServerProcessResult {
  ServerProcessStatus status{ServerProcessStatus::discarded};
  std::size_t message_octets{};
  // Broadcast selection is part of DHCPv4 semantics and cannot be inferred
  // later from only the response bytes after ciaddr and flags were rewritten.
  bool limited_broadcast{};
  bool direct_client_l2{};
};

struct ServerCheckpoint {
  ServerConfiguration configuration;
  LeaseRepositoryCheckpoint leases;
  ServerStatistics statistics;
  bool configured{};
};

enum class ForceRenewStatus : std::uint8_t {
  encoded,
  disabled,
  lease_not_found,
  unsupported_hardware,
  output_too_small,
  delivery_failed,
  not_configured,
};

struct ForceRenewResult {
  ForceRenewStatus status{ForceRenewStatus::not_configured};
  packet::Ipv4 destination{};
  packet::Mac destination_mac{};
  std::uint64_t link_identity{};
  std::size_t message_octets{};
};

class Server final {
public:
  using Clock = LeaseRepository::Clock;

  Server() = default;

  [[nodiscard]] bool configure(
      const ServerConfiguration &configuration,
      std::span<const Pool> pools,
      std::span<const Reservation> reservations,
      std::span<const ExcludedRange> exclusions = {});

  // link_identity is derived by the relay or receiving interface owner after
  // trust validation. It is never inferred from pool storage order.
  [[nodiscard]] ServerProcessResult
  process(std::span<const std::uint8_t> input,
          std::span<std::uint8_t> output, std::uint64_t link_identity,
          Clock::time_point now = Clock::now());

  // A multihomed router chooses the identifier reachable from this request's
  // ingress according to RFC 2131 section 4.1. accepted_identifiers contains
  // every local address that may legitimately identify the same server.
  [[nodiscard]] ServerProcessResult
  process(std::span<const std::uint8_t> input,
          std::span<std::uint8_t> output, std::uint64_t link_identity,
          packet::Ipv4 response_server_identifier,
          std::span<const packet::Ipv4> accepted_identifiers,
          Clock::time_point now = Clock::now());

  [[nodiscard]] const LeaseRepository &leases() const noexcept {
    return leases_;
  }
  [[nodiscard]] LeaseRepository &leases() noexcept { return leases_; }
  [[nodiscard]] const ServerStatistics &statistics() const noexcept {
    return statistics_;
  }
  void clear_statistics() noexcept { statistics_ = {}; }
  [[nodiscard]] ForceRenewResult
  force_renew(packet::Ipv4 address, packet::Ipv4 server_identifier,
              std::span<std::uint8_t> output,
               Clock::time_point now = Clock::now());
  // Encoding is not transmission. The forwarding owner calls this only after
  // the complete UDP datagram was admitted to the real egress path.
  void note_force_renew_sent() noexcept { ++statistics_.tx_force_renew; }
  [[nodiscard]] ServerCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(const ServerCheckpoint &state,
                             Clock::time_point now = Clock::now());

private:
  [[nodiscard]] ServerProcessResult
  response(const packet::dhcpv4::MessageView &request,
           packet::dhcpv4::MessageType response_type,
           packet::Ipv4 offered_address, const Pool *pool,
           const ClientKey &client, std::uint32_t lease_seconds,
           packet::Ipv4 server_identifier,
           std::span<std::uint8_t> output) const;
  [[nodiscard]] ServerProcessResult
  lease_query_response(const packet::dhcpv4::MessageView &request,
                       std::span<std::uint8_t> output,
                       Clock::time_point now);

  ServerConfiguration configuration_{};
  LeaseRepository leases_{};
  ServerStatistics statistics_{};
  bool configured_{};
};

} // namespace router::dhcpv4
