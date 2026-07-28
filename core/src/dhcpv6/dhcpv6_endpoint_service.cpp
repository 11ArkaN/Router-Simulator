// Runtime integration for DHCPv6 application owners. The service retains a
// datagram while Neighbor Discovery or an egress ring applies backpressure,
// so an application exchange is never replaced by a direct peer invocation.

#include "dhcpv6_endpoint_service.hpp"

#include "router/generated_device_catalog.hpp"
#include "router/interface_identity.hpp"
#include "router/network_plane.hpp"

#include <algorithm>
#include <utility>

namespace router::network_detail {

lab::HostDhcpv6ServiceCheckpoint
Dhcpv6EndpointService::checkpoint(Clock::time_point now) const {
  lab::HostDhcpv6ServiceCheckpoint state;
  if (client_)
    state.client = client_->checkpoint(now);
  if (server_)
    state.server = server_->checkpoint(now);
  state.client_socket = client_socket_;
  state.server_socket = server_socket_;
  state.client_pending.destination = client_pending_.destination;
  state.client_pending.destination_port = client_pending_.destination_port;
  state.client_pending.active = client_pending_.active;
  if (client_pending_.active)
    state.client_pending.payload.assign(
        client_wire_.begin(),
        client_wire_.begin() +
            static_cast<std::ptrdiff_t>(client_pending_.octets));
  state.server_pending.destination = server_pending_.destination;
  state.server_pending.destination_port = server_pending_.destination_port;
  state.server_pending.active = server_pending_.active;
  if (server_pending_.active)
    state.server_pending.payload.assign(
        server_response_.begin(),
        server_response_.begin() +
            static_cast<std::ptrdiff_t>(server_pending_.octets));
  return state;
}

bool Dhcpv6EndpointService::restore(
    const lab::HostDhcpv6ServiceCheckpoint &state, EndpointStack &endpoint,
    Clock::time_point now) {
  if (state.client.has_value() != state.client_socket.has_value() ||
      state.server.has_value() != state.server_socket.has_value() ||
      (state.client_socket && !endpoint.valid_udp(*state.client_socket)) ||
      (state.server_socket && !endpoint.valid_udp(*state.server_socket)) ||
      state.client_pending.active != !state.client_pending.payload.empty() ||
      state.server_pending.active != !state.server_pending.payload.empty() ||
      state.client_pending.payload.size() >
          packet::dhcpv6::maximum_message_octets ||
      state.server_pending.payload.size() >
          packet::dhcpv6::maximum_message_octets ||
      (state.client_pending.active &&
       (state.client_pending.destination_port == 0U ||
        ip::is_unspecified(state.client_pending.destination))) ||
      (state.server_pending.active &&
       (state.server_pending.destination_port == 0U ||
        ip::is_unspecified(state.server_pending.destination))))
    return false;
  auto client = std::unique_ptr<dhcpv6::Client>{};
  auto server = std::unique_ptr<dhcpv6::Server>{};
  if (state.client) {
    client = std::make_unique<dhcpv6::Client>();
    if (!client->restore(*state.client, now))
      return false;
  }
  if (state.server) {
    server = std::make_unique<dhcpv6::Server>();
    if (!server->restore(*state.server, now))
      return false;
  }
  std::vector<std::uint8_t> client_wire;
  std::vector<std::uint8_t> server_request;
  std::vector<std::uint8_t> server_response;
  if (client)
    client_wire.resize(packet::dhcpv6::maximum_message_octets);
  if (server) {
    server_request.resize(packet::dhcpv6::maximum_message_octets);
    server_response.resize(packet::dhcpv6::maximum_message_octets);
  }
  std::copy(state.client_pending.payload.begin(),
            state.client_pending.payload.end(), client_wire.begin());
  std::copy(state.server_pending.payload.begin(),
            state.server_pending.payload.end(), server_response.begin());
  client_ = std::move(client);
  server_ = std::move(server);
  client_socket_ = state.client_socket;
  server_socket_ = state.server_socket;
  client_wire_ = std::move(client_wire);
  server_request_ = std::move(server_request);
  server_response_ = std::move(server_response);
  client_pending_ = {.destination = state.client_pending.destination,
                     .destination_port =
                         state.client_pending.destination_port,
                     .octets = state.client_pending.payload.size(),
                     .active = state.client_pending.active};
  server_pending_ = {.destination = state.server_pending.destination,
                     .destination_port =
                         state.server_pending.destination_port,
                     .octets = state.server_pending.payload.size(),
                     .active = state.server_pending.active};
  return true;
}

bool Dhcpv6EndpointService::configure_client(
    const dhcpv6::ClientConfiguration &configuration, bool information_only,
    EndpointStack &endpoint, Clock::time_point now) {
  auto staged = std::make_unique<dhcpv6::Client>();
  if (!staged->configure(configuration) ||
      !(information_only ? staged->start_information_request(now)
                         : staged->start(now)))
    return false;
  auto socket = client_socket_;
  if (!socket) {
    socket = endpoint.bind_udp(
        {.family = transport::IpFamily::ipv6,
         .interface_id = endpoint.interface_id(),
         .port = packet::dhcpv6::client_port});
    if (!socket)
      return false;
  }
  try {
    std::vector<std::uint8_t> wire(packet::dhcpv6::maximum_message_octets);
    client_wire_ = std::move(wire);
  } catch (...) {
    if (!client_socket_)
      static_cast<void>(endpoint.close_udp(*socket));
    return false;
  }
  client_ = std::move(staged);
  client_socket_ = socket;
  client_pending_ = {};
  return true;
}

bool Dhcpv6EndpointService::configure_server(
    const dhcpv6::ServerConfiguration &configuration,
    std::span<const dhcpv6::LeasePool> address_pools,
    std::span<const dhcpv6::LeasePool> prefix_pools,
    std::chrono::seconds decline_hold_time, EndpointStack &endpoint,
    Clock::time_point now) {
  auto staged = std::make_unique<dhcpv6::Server>();
  if (!staged->configure(configuration, address_pools, prefix_pools,
                         decline_hold_time))
    return false;
  auto socket = server_socket_;
  if (!socket) {
    socket = endpoint.bind_udp(
        {.family = transport::IpFamily::ipv6,
         .interface_id = endpoint.interface_id(),
         .port = packet::dhcpv6::server_port});
    if (!socket || !endpoint.join_ipv6_multicast(
                       packet::dhcpv6::all_relay_agents_and_servers, now)) {
      if (socket)
        static_cast<void>(endpoint.close_udp(*socket));
      return false;
    }
  }
  try {
    std::vector<std::uint8_t> request(
        packet::dhcpv6::maximum_message_octets);
    std::vector<std::uint8_t> response(
        packet::dhcpv6::maximum_message_octets);
    server_request_ = std::move(request);
    server_response_ = std::move(response);
  } catch (...) {
    if (!server_socket_) {
      static_cast<void>(endpoint.leave_ipv6_multicast(
          packet::dhcpv6::all_relay_agents_and_servers, now));
      static_cast<void>(endpoint.close_udp(*socket));
    }
    return false;
  }
  server_ = std::move(staged);
  server_socket_ = socket;
  server_pending_ = {};
  return true;
}

void Dhcpv6EndpointService::remove_client(EndpointStack &endpoint) noexcept {
  if (client_socket_)
    static_cast<void>(endpoint.close_udp(*client_socket_));
  client_socket_.reset();
  client_.reset();
  std::vector<std::uint8_t>{}.swap(client_wire_);
  client_pending_ = {};
}

void Dhcpv6EndpointService::remove_server(EndpointStack &endpoint,
                                          Clock::time_point now) noexcept {
  static_cast<void>(endpoint.leave_ipv6_multicast(
      packet::dhcpv6::all_relay_agents_and_servers, now));
  if (server_socket_)
    static_cast<void>(endpoint.close_udp(*server_socket_));
  server_socket_.reset();
  server_.reset();
  std::vector<std::uint8_t>{}.swap(server_request_);
  std::vector<std::uint8_t>{}.swap(server_response_);
  server_pending_ = {};
}

bool Dhcpv6EndpointService::try_send(
    EndpointStack &endpoint, transport::UdpSocketHandle socket,
    PendingDatagram &pending, std::span<const std::uint8_t> bytes,
    void *sink_context, packet::Ipv6FragmentSink sink,
    packet::Ipv6FragmentAdmission admission,
    Clock::time_point now) noexcept {
  if (!pending.active)
    return true;
  const auto sent = endpoint.send_udp_ipv6(
      socket, pending.destination, pending.destination_port,
      bytes.first(pending.octets), sink_context, sink, now, admission);
  if (sent.status == EndpointUdpSendStatus::sent) {
    pending = {};
    return true;
  }
  // Neighbor resolution and bounded egress pressure are transient. Retaining
  // the exact UDP payload is the application-side equivalent of an OS socket
  // send buffer; the exchange owner is not polled for a replacement packet.
  const bool transient =
      sent.status == EndpointUdpSendStatus::neighbor_resolution_started ||
      sent.status == EndpointUdpSendStatus::neighbor_resolution_pending ||
      sent.status == EndpointUdpSendStatus::output_backpressure ||
      sent.status == EndpointUdpSendStatus::link_down ||
      sent.status == EndpointUdpSendStatus::no_source_address ||
      sent.status == EndpointUdpSendStatus::no_route ||
      sent.status == EndpointUdpSendStatus::resource_exhausted;
  if (!transient)
    pending = {};
  return transient;
}

std::optional<Dhcpv6EndpointService::Clock::time_point>
Dhcpv6EndpointService::service(EndpointStack &endpoint, void *sink_context,
                               packet::Ipv6FragmentSink sink,
                               packet::Ipv6FragmentAdmission admission,
                               Clock::time_point now) noexcept {
  std::optional<Clock::time_point> next;
  if (client_ && client_socket_) {
    for (std::size_t work = 0;
         work < device_catalog::host_application_work_budget_datagrams;
         ++work) {
      const auto received = endpoint.receive_udp(*client_socket_, client_wire_);
      if (received.status != transport::UdpReceiveStatus::delivered)
        break;
      static_cast<void>(client_->ingest(
          std::span<const std::uint8_t>{client_wire_}.first(
              received.metadata.payload_octets),
          now));
    }
    if (client_pending_.active)
      static_cast<void>(try_send(endpoint, *client_socket_, client_pending_,
                                 client_wire_, sink_context, sink, admission,
                                 now));
    if (!client_pending_.active) {
      const auto polled = client_->poll(client_wire_, now);
      if (polled.status == dhcpv6::ClientPollStatus::transmit) {
        client_pending_ = {
            .destination = packet::dhcpv6::all_relay_agents_and_servers,
            .destination_port = packet::dhcpv6::server_port,
            .octets = polled.message_octets,
            .active = true};
        static_cast<void>(try_send(endpoint, *client_socket_, client_pending_,
                                   client_wire_, sink_context, sink, admission,
                                   now));
      }
    }
    // Pending bytes are woken by endpoint Neighbor Discovery deadlines, link
    // state commands or SPSC egress-space notifications. Returning `now`
    // would convert ordinary backpressure into a forwarding-thread spin.
    if (!client_pending_.active)
      next = client_->next_deadline();
  }

  if (server_ && server_socket_) {
    if (server_pending_.active)
      static_cast<void>(try_send(endpoint, *server_socket_, server_pending_,
                                 server_response_, sink_context, sink,
                                 admission, now));
    if (!server_pending_.active) {
      const auto received =
          endpoint.receive_udp(*server_socket_, server_request_);
      if (received.status == transport::UdpReceiveStatus::delivered) {
        // Direct clients are scoped by the endpoint's stable logical
        // interface identity. Encoding it in network byte order before
        // hashing gives the lease repository the same fixed-size link key
        // used for relay link-address and Interface-ID tuples.
        const auto link_identity =
            lab::dhcpv6_link_identity(endpoint.interface_id());
        const auto processed = server_->process(
            std::span<const std::uint8_t>{server_request_}.first(
                received.metadata.payload_octets),
            server_response_, now, link_identity);
        if (processed.status == dhcpv6::ServerProcessStatus::response) {
          server_pending_ = {
              .destination = received.metadata.source_ipv6,
              .destination_port = received.metadata.source_port,
              .octets = processed.message_octets,
              .active = true};
          static_cast<void>(try_send(endpoint, *server_socket_,
                                     server_pending_, server_response_,
                                     sink_context, sink, admission, now));
        }
      }
    }
  }
  return next;
}

} // namespace router::network_detail
