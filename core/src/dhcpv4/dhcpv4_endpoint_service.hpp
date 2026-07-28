// DHCPv4 application owner attached to one forwarding-owned EndpointStack.
// It owns client or server protocol state, UDP handles and pending application
// bytes. All traffic crosses EndpointStack as encoded IPv4 and UDP frames.

#pragma once

#include "forwarding/network_endpoint.hpp"
#include "router/dhcpv4_client.hpp"
#include "router/dhcpv4_server.hpp"

#include <algorithm>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::network_detail {

} // namespace router::network_detail

namespace router::lab {
struct HostDhcpv4ServiceCheckpoint;
}

namespace router::network_detail {

class Dhcpv4EndpointService final {
public:
  using Clock = EndpointStack::Clock;

  [[nodiscard]] bool configure_client(
      const dhcpv4::ClientConfiguration &configuration,
      EndpointStack &endpoint, Clock::time_point now = Clock::now());
  [[nodiscard]] bool configure_server(
      const dhcpv4::ServerConfiguration &configuration,
      std::span<const dhcpv4::Pool> pools,
      std::span<const dhcpv4::Reservation> reservations,
      std::span<const dhcpv4::ExcludedRange> exclusions,
      EndpointStack &endpoint);
  void remove_client(EndpointStack &endpoint) noexcept;
  void remove_server(EndpointStack &endpoint) noexcept;

  [[nodiscard]] std::optional<Clock::time_point> service(
      EndpointStack &endpoint, void *sink_context,
      packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] lab::HostDhcpv4ServiceCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(
      const lab::HostDhcpv4ServiceCheckpoint &state, EndpointStack &endpoint,
      Clock::time_point now = Clock::now());

  [[nodiscard]] bool client_configured() const noexcept {
    return static_cast<bool>(client_);
  }
  [[nodiscard]] bool server_configured() const noexcept {
    return static_cast<bool>(server_);
  }
  [[nodiscard]] std::optional<Clock::time_point>
  next_deadline() const noexcept {
    // A retained datagram is retried when endpoint maintenance or queue
    // admission wakes the shard. Only the client state machine contributes an
    // independent real-time deadline.
    if (!client_ || client_pending_.active)
      return std::nullopt;
    const auto client_deadline = client_->next_deadline();
    if (!probe_.active)
      return client_deadline;
    return client_deadline ? std::min(*client_deadline, probe_.next_action)
                           : std::optional{probe_.next_action};
  }
  [[nodiscard]] std::size_t client_lease_count() const noexcept {
    return client_ && client_->lease() ? 1U : 0U;
  }
  [[nodiscard]] std::optional<dhcpv4::ClientStatus>
  client_status(Clock::time_point now = Clock::now()) const noexcept {
    return client_ ? std::optional{client_->status(now)} : std::nullopt;
  }
  [[nodiscard]] bool client_bootstrap_complete() const noexcept {
    // RFC 2131 has no separate information-only completion state. BOF has
    // completed only after address probing accepted a bound lease.
    return client_ && client_->lease().has_value();
  }

private:
  enum class Delivery : std::uint8_t {
    routed,
    limited_broadcast,
    direct_client_l2,
  };

  struct PendingDatagram {
    packet::Ipv4 destination{};
    packet::Mac destination_mac{};
    std::uint16_t destination_port{};
    std::size_t octets{};
    Delivery delivery{Delivery::routed};
    bool active{};
  };

  struct AddressProbe {
    packet::Ipv4 candidate{};
    Clock::time_point next_action{};
    std::uint8_t probes_sent{};
    bool active{};
  };

  [[nodiscard]] bool try_send(
      EndpointStack &endpoint, transport::UdpSocketHandle socket,
      PendingDatagram &pending, std::span<const std::uint8_t> bytes,
      void *sink_context, packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission) noexcept;
  [[nodiscard]] bool synchronize_lease(EndpointStack &endpoint) noexcept;

  std::unique_ptr<dhcpv4::Client> client_;
  std::unique_ptr<dhcpv4::Server> server_;
  std::optional<transport::UdpSocketHandle> client_socket_;
  std::optional<transport::UdpSocketHandle> server_socket_;
  std::vector<std::uint8_t> client_wire_;
  std::vector<std::uint8_t> server_request_;
  std::vector<std::uint8_t> server_response_;
  PendingDatagram client_pending_{};
  PendingDatagram server_pending_{};
  // The endpoint observes ARP frames, while this application owner controls
  // RFC 5227 timing. Three probes and the final two-second quiet period are
  // checkpointed with the client transaction.
  AddressProbe probe_{};
  packet::Ipv4 installed_address_{};
};

} // namespace router::network_detail
