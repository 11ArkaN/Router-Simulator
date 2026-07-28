// DHCPv6 application owner attached to one forwarding-owned EndpointStack.
// It owns client/server protocol state, UDP socket handles and application
// backpressure bytes. All traffic crosses EndpointStack as encoded UDP over
// IPv6; this module has no fabric, registry, UI or peer-device reference.

#pragma once

#include "forwarding/network_endpoint.hpp"
#include "router/dhcpv6_client.hpp"
#include "router/dhcpv6_server.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::network_detail {

} // namespace router::network_detail

namespace router::lab {
struct HostDhcpv6ServiceCheckpoint;
}

namespace router::network_detail {

class Dhcpv6EndpointService final {
public:
  using Clock = EndpointStack::Clock;

  // Replacement validates the complete protocol owner before touching the
  // existing socket. On success the new client starts immediately using its
  // persisted transaction secret and the real monotonic clock.
  [[nodiscard]] bool configure_client(
      const dhcpv6::ClientConfiguration &configuration,
      bool information_only, EndpointStack &endpoint,
      Clock::time_point now = Clock::now());
  [[nodiscard]] bool configure_server(
      const dhcpv6::ServerConfiguration &configuration,
      std::span<const dhcpv6::LeasePool> address_pools,
      std::span<const dhcpv6::LeasePool> prefix_pools,
      std::chrono::seconds decline_hold_time, EndpointStack &endpoint,
      Clock::time_point now = Clock::now());
  void remove_client(EndpointStack &endpoint) noexcept;
  void remove_server(EndpointStack &endpoint,
                     Clock::time_point now = Clock::now()) noexcept;

  // service drains bounded UDP work, advances local protocol deadlines and
  // submits generated frames through the caller's ordinary endpoint sink.
  // A returned deadline is owner-local and only wakes this forwarding shard.
  [[nodiscard]] std::optional<Clock::time_point> service(
      EndpointStack &endpoint, void *sink_context,
      packet::Ipv6FragmentSink sink,
      packet::Ipv6FragmentAdmission admission,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] lab::HostDhcpv6ServiceCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(
      const lab::HostDhcpv6ServiceCheckpoint &state, EndpointStack &endpoint,
      Clock::time_point now = Clock::now());

  [[nodiscard]] bool client_configured() const noexcept {
    return static_cast<bool>(client_);
  }
  [[nodiscard]] bool server_configured() const noexcept {
    return static_cast<bool>(server_);
  }
  [[nodiscard]] std::size_t client_lease_count() const noexcept {
    return client_ ? client_->leases().size() : 0U;
  }
  [[nodiscard]] bool client_bootstrap_complete() const noexcept {
    if (!client_)
      return false;
    // Stateful BOF completes with at least one IA value. Information-request
    // has no lease by design and is complete only after a valid Reply moved
    // the RFC 9915 client into INFORMATION-BOUND.
    return !client_->leases().empty() ||
           client_->state() == dhcpv6::ClientState::information_bound;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept {
    return client_ && !client_pending_.active ? client_->next_deadline()
                                               : std::nullopt;
  }

private:
  struct PendingDatagram {
    packet::Ipv6 destination{};
    std::uint16_t destination_port{};
    std::size_t octets{};
    bool active{};
  };

  [[nodiscard]] bool try_send(
      EndpointStack &endpoint, transport::UdpSocketHandle socket,
      PendingDatagram &pending, std::span<const std::uint8_t> bytes,
      void *sink_context, packet::Ipv6FragmentSink sink,
      packet::Ipv6FragmentAdmission admission,
      Clock::time_point now) noexcept;

  std::unique_ptr<dhcpv6::Client> client_;
  std::unique_ptr<dhcpv6::Server> server_;
  std::optional<transport::UdpSocketHandle> client_socket_;
  std::optional<transport::UdpSocketHandle> server_socket_;
  std::vector<std::uint8_t> client_wire_;
  std::vector<std::uint8_t> server_request_;
  std::vector<std::uint8_t> server_response_;
  PendingDatagram client_pending_{};
  PendingDatagram server_pending_{};
};

} // namespace router::network_detail
