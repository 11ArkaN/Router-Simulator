// DHCPv4 runtime integration. Application backpressure retains one exact
// datagram and retries it through the same endpoint. A pending send never
// causes the protocol state machine to manufacture a replacement transaction.

#include "dhcpv4_endpoint_service.hpp"

#include "router/network_plane.hpp"

#include <algorithm>
#include <utility>

namespace router::network_detail {
namespace {

[[nodiscard]] std::optional<std::uint8_t>
prefix_length(packet::Ipv4 mask) noexcept {
  std::uint32_t value =
      (static_cast<std::uint32_t>(mask[0U]) << 24U) |
      (static_cast<std::uint32_t>(mask[1U]) << 16U) |
      (static_cast<std::uint32_t>(mask[2U]) << 8U) | mask[3U];
  bool zero_seen = false;
  std::uint8_t length = 0U;
  for (std::uint8_t bit = 0U; bit < 32U; ++bit) {
    const bool set = (value & (0x80000000U >> bit)) != 0U;
    if (!set)
      zero_seen = true;
    else if (zero_seen)
      return std::nullopt;
    else
      ++length;
  }
  return length == 0U ? std::nullopt : std::optional{length};
}

} // namespace

lab::HostDhcpv4ServiceCheckpoint
Dhcpv4EndpointService::checkpoint(Clock::time_point now) const {
  lab::HostDhcpv4ServiceCheckpoint state;
  if (client_)
    state.client = client_->checkpoint(now);
  if (server_)
    state.server = server_->checkpoint(now);
  state.client_socket = client_socket_;
  state.server_socket = server_socket_;
  const auto save_pending =
      [](const PendingDatagram &pending,
         std::span<const std::uint8_t> bytes,
         lab::HostDhcpv4PendingCheckpoint &target) {
        target.destination = pending.destination;
        target.destination_mac = pending.destination_mac;
        target.destination_port = pending.destination_port;
        target.delivery = static_cast<std::uint8_t>(pending.delivery);
        target.active = pending.active;
        if (pending.active)
          target.payload.assign(
              bytes.begin(),
              bytes.begin() + static_cast<std::ptrdiff_t>(pending.octets));
      };
  save_pending(client_pending_, client_wire_, state.client_pending);
  save_pending(server_pending_, server_response_, state.server_pending);
  state.probe = {
      .candidate = probe_.candidate,
      .next_action_remaining_nanoseconds =
          probe_.active
              ? std::max<std::int64_t>(
                    0, std::chrono::duration_cast<std::chrono::nanoseconds>(
                           probe_.next_action - now)
                           .count())
              : 0,
      .probes_sent = probe_.probes_sent,
      .active = probe_.active};
  state.installed_address = installed_address_;
  return state;
}

bool Dhcpv4EndpointService::restore(
    const lab::HostDhcpv4ServiceCheckpoint &state, EndpointStack &endpoint,
    Clock::time_point now) {
  const auto valid_pending = [](const auto &pending) {
    if (pending.active != !pending.payload.empty() ||
        pending.payload.size() > packet::dhcpv4::maximum_message_octets ||
        pending.delivery >
            static_cast<std::uint8_t>(Delivery::direct_client_l2))
      return false;
    if (!pending.active)
      return true;
    if (pending.destination_port == 0U ||
        pending.destination == packet::Ipv4{})
      return false;
    if (pending.delivery ==
            static_cast<std::uint8_t>(Delivery::direct_client_l2) &&
        (pending.destination_mac == packet::Mac{} ||
         (pending.destination_mac[0U] & 1U) != 0U))
      return false;
    return true;
  };
  if (state.client.has_value() != state.client_socket.has_value() ||
      state.server.has_value() != state.server_socket.has_value() ||
      (state.client_socket && !endpoint.valid_udp(*state.client_socket)) ||
      (state.server_socket && !endpoint.valid_udp(*state.server_socket)) ||
      !valid_pending(state.client_pending) ||
      !valid_pending(state.server_pending) ||
      state.probe.next_action_remaining_nanoseconds < 0 ||
      state.probe.probes_sent > 3U ||
      (state.probe.active !=
       (state.probe.candidate != packet::Ipv4{})) ||
      (state.probe.active &&
       (!state.client ||
        state.client->state != dhcpv4::ClientState::checking)))
    return false;

  auto client = std::unique_ptr<dhcpv4::Client>{};
  auto server = std::unique_ptr<dhcpv4::Server>{};
  try {
    if (state.client) {
      client = std::make_unique<dhcpv4::Client>();
      if (!client->restore(*state.client, now))
        return false;
    }
    if (state.server) {
      server = std::make_unique<dhcpv4::Server>();
      if (!server->restore(*state.server, now))
        return false;
    }
  } catch (...) {
    return false;
  }

  std::vector<std::uint8_t> client_wire;
  std::vector<std::uint8_t> server_request;
  std::vector<std::uint8_t> server_response;
  try {
    if (client)
      client_wire.resize(packet::dhcpv4::maximum_message_octets);
    if (server) {
      server_request.resize(packet::dhcpv4::maximum_message_octets);
      server_response.resize(packet::dhcpv4::maximum_message_octets);
    }
  } catch (...) {
    return false;
  }
  std::ranges::copy(state.client_pending.payload, client_wire.begin());
  std::ranges::copy(state.server_pending.payload, server_response.begin());

  client_ = std::move(client);
  server_ = std::move(server);
  client_socket_ = state.client_socket;
  server_socket_ = state.server_socket;
  client_wire_ = std::move(client_wire);
  server_request_ = std::move(server_request);
  server_response_ = std::move(server_response);
  const auto load_pending = [](const auto &saved) {
    return PendingDatagram{
        .destination = saved.destination,
        .destination_mac = saved.destination_mac,
        .destination_port = saved.destination_port,
        .octets = saved.payload.size(),
        .delivery = static_cast<Delivery>(saved.delivery),
        .active = saved.active};
  };
  client_pending_ = load_pending(state.client_pending);
  server_pending_ = load_pending(state.server_pending);
  probe_ = {
      .candidate = state.probe.candidate,
      .next_action =
          now + std::chrono::nanoseconds{
                    state.probe.next_action_remaining_nanoseconds},
      .probes_sent = state.probe.probes_sent,
      .active = state.probe.active};
  installed_address_ = state.installed_address;

  // EndpointStack was restored before this application owner. Reasserting the
  // identical lease marks the address as DHCP-owned without altering its ARP,
  // UDP or transport checkpoint state.
  if (client_ && client_->lease()) {
    const auto prefix = prefix_length(client_->lease()->subnet_mask);
    if (!prefix || client_->lease()->address != installed_address_ ||
        !endpoint.restore_dhcpv4_lease_ownership(
            client_->lease()->address, *prefix, client_->lease()->router))
      return false;
  } else if (installed_address_ != packet::Ipv4{}) {
    return false;
  }
  if (probe_.active &&
      !endpoint.arm_dhcpv4_address_probe(probe_.candidate))
    return false;
  return true;
}

bool Dhcpv4EndpointService::configure_client(
    const dhcpv4::ClientConfiguration &configuration,
    EndpointStack &endpoint, Clock::time_point now) {
  auto staged = std::make_unique<dhcpv4::Client>();
  if (!staged->configure(configuration) || !staged->start(now))
    return false;
  auto socket = client_socket_;
  if (!socket) {
    socket = endpoint.bind_udp(
        {.family = transport::IpFamily::ipv4,
         .interface_id = endpoint.interface_id(),
         .port = packet::dhcpv4::client_port,
         .ipv4_broadcast = true,
         // RFC 2131 section 4.1 permits a server to unicast DHCPOFFER and
         // DHCPACK directly to the client's hardware address and yiaddr before
         // the client configures that address. Only this acquisition socket
         // receives that narrow pre-address delivery authority.
         .ipv4_unconfigured_unicast = true});
    if (!socket)
      return false;
  }
  try {
    std::vector<std::uint8_t> wire(
        packet::dhcpv4::maximum_message_octets);
    client_wire_ = std::move(wire);
  } catch (...) {
    if (!client_socket_)
      static_cast<void>(endpoint.close_udp(*socket));
    return false;
  }
  endpoint.remove_dhcpv4_lease();
  installed_address_ = {};
  client_ = std::move(staged);
  client_socket_ = socket;
  client_pending_ = {};
  probe_ = {};
  endpoint.disarm_dhcpv4_address_probe();
  return true;
}

bool Dhcpv4EndpointService::configure_server(
    const dhcpv4::ServerConfiguration &configuration,
    std::span<const dhcpv4::Pool> pools,
    std::span<const dhcpv4::Reservation> reservations,
    std::span<const dhcpv4::ExcludedRange> exclusions,
    EndpointStack &endpoint) {
  auto staged = std::make_unique<dhcpv4::Server>();
  if (!staged->configure(configuration, pools, reservations, exclusions))
    return false;
  auto socket = server_socket_;
  if (!socket) {
    socket = endpoint.bind_udp(
        {.family = transport::IpFamily::ipv4,
         .interface_id = endpoint.interface_id(),
         .port = packet::dhcpv4::server_port,
         .ipv4_broadcast = true});
    if (!socket)
      return false;
  }
  try {
    std::vector<std::uint8_t> request(
        packet::dhcpv4::maximum_message_octets);
    std::vector<std::uint8_t> response(
        packet::dhcpv4::maximum_message_octets);
    server_request_ = std::move(request);
    server_response_ = std::move(response);
  } catch (...) {
    if (!server_socket_)
      static_cast<void>(endpoint.close_udp(*socket));
    return false;
  }
  server_ = std::move(staged);
  server_socket_ = socket;
  server_pending_ = {};
  return true;
}

void Dhcpv4EndpointService::remove_client(
    EndpointStack &endpoint) noexcept {
  endpoint.remove_dhcpv4_lease();
  if (client_socket_)
    static_cast<void>(endpoint.close_udp(*client_socket_));
  client_socket_.reset();
  client_.reset();
  std::vector<std::uint8_t>{}.swap(client_wire_);
  client_pending_ = {};
  probe_ = {};
  endpoint.disarm_dhcpv4_address_probe();
  installed_address_ = {};
}

void Dhcpv4EndpointService::remove_server(
    EndpointStack &endpoint) noexcept {
  if (server_socket_)
    static_cast<void>(endpoint.close_udp(*server_socket_));
  server_socket_.reset();
  server_.reset();
  std::vector<std::uint8_t>{}.swap(server_request_);
  std::vector<std::uint8_t>{}.swap(server_response_);
  server_pending_ = {};
}

bool Dhcpv4EndpointService::try_send(
    EndpointStack &endpoint, transport::UdpSocketHandle socket,
    PendingDatagram &pending, std::span<const std::uint8_t> bytes,
    void *sink_context, packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission) noexcept {
  if (!pending.active)
    return true;
  EndpointUdpSendResult sent;
  if (pending.delivery == Delivery::direct_client_l2) {
    sent = endpoint.send_udp_ipv4_direct_l2(
        socket, pending.destination, pending.destination_mac,
        pending.destination_port, bytes.first(pending.octets), sink_context,
        sink, admission);
  } else {
    sent = endpoint.send_udp_ipv4(
        socket, pending.destination, pending.destination_port,
        bytes.first(pending.octets), sink_context, sink, admission);
  }
  if (sent.status == EndpointUdpSendStatus::sent) {
    pending = {};
    return true;
  }
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

bool Dhcpv4EndpointService::synchronize_lease(
    EndpointStack &endpoint) noexcept {
  if (!client_ || !client_->lease()) {
    if (installed_address_ != packet::Ipv4{}) {
      endpoint.remove_dhcpv4_lease();
      installed_address_ = {};
    }
    return true;
  }
  const auto &lease = *client_->lease();
  if (lease.address == installed_address_)
    return true;
  const auto prefix = prefix_length(lease.subnet_mask);
  if (!prefix ||
      !endpoint.install_dhcpv4_lease(lease.address, *prefix, lease.router))
    return false;
  installed_address_ = lease.address;
  return true;
}

std::optional<Dhcpv4EndpointService::Clock::time_point>
Dhcpv4EndpointService::service(
    EndpointStack &endpoint, void *sink_context,
    packet::Ipv4FragmentSink sink,
    packet::Ipv4FragmentAdmission admission,
    Clock::time_point now) noexcept {
  if (client_ && client_socket_) {
    for (std::size_t work = 0U;
         work < device_catalog::host_application_work_budget_datagrams;
         ++work) {
      const auto received =
          endpoint.receive_udp(*client_socket_, client_wire_);
      if (received.status != transport::UdpReceiveStatus::delivered)
        break;
      static_cast<void>(client_->ingest(
          std::span<const std::uint8_t>{client_wire_}.first(
              received.metadata.payload_octets),
          now));
    }

    if (client_->state() == dhcpv4::ClientState::checking &&
        client_->pending_lease() && !probe_.active) {
      // The ACKed address remains absent from EndpointStack throughout the
      // probe sequence, so neither ARP replies nor ordinary IP delivery can
      // accidentally advertise ownership before conflict detection completes.
      probe_ = {
          .candidate = client_->pending_lease()->address,
          .next_action = now + client_->address_probe_initial_delay(),
          .probes_sent = 0U,
          .active = endpoint.arm_dhcpv4_address_probe(
              client_->pending_lease()->address)};
      if (!probe_.active)
        return std::nullopt;
    }
    if (probe_.active && endpoint.dhcpv4_address_conflict()) {
      endpoint.disarm_dhcpv4_address_probe();
      probe_ = {};
      if (!client_->address_probe_conflicted(now))
        return std::nullopt;
    } else if (probe_.active && now >= probe_.next_action) {
      if (probe_.probes_sent < 3U) {
        if (endpoint.send_dhcpv4_address_probe(
                sink_context, sink, admission)) {
          ++probe_.probes_sent;
          probe_.next_action =
              probe_.probes_sent < 3U
                  ? now + client_->address_probe_interval()
                  : now + std::chrono::seconds{2};
        }
      } else {
        endpoint.disarm_dhcpv4_address_probe();
        probe_ = {};
        if (!client_->address_probe_succeeded(now))
          return std::nullopt;
      }
    }
    if (!synchronize_lease(endpoint))
      return std::nullopt;
    if (client_pending_.active)
      static_cast<void>(try_send(endpoint, *client_socket_, client_pending_,
                                 client_wire_, sink_context, sink, admission));
    if (!client_pending_.active) {
      const auto polled = client_->poll(client_wire_, now);
      if (polled.status ==
              dhcpv4::ClientPollStatus::transmit_limited_broadcast ||
          polled.status == dhcpv4::ClientPollStatus::transmit_unicast) {
        client_pending_ = {
            .destination =
                polled.status ==
                        dhcpv4::ClientPollStatus::transmit_limited_broadcast
                    ? packet::Ipv4{255U, 255U, 255U, 255U}
                    : polled.destination,
            .destination_port = packet::dhcpv4::server_port,
            .octets = polled.message_octets,
            .delivery =
                polled.status ==
                        dhcpv4::ClientPollStatus::transmit_limited_broadcast
                    ? Delivery::limited_broadcast
                    : Delivery::routed,
            .active = true,
        };
        static_cast<void>(try_send(endpoint, *client_socket_,
                                   client_pending_, client_wire_,
                                   sink_context, sink, admission));
      }
    }
  }

  if (server_ && server_socket_) {
    if (server_pending_.active)
      static_cast<void>(try_send(endpoint, *server_socket_, server_pending_,
                                 server_response_, sink_context, sink,
                                 admission));
    if (!server_pending_.active) {
      const auto received =
          endpoint.receive_udp(*server_socket_, server_request_);
      if (received.status == transport::UdpReceiveStatus::delivered) {
        const auto request = packet::dhcpv4::parse(
            std::span<const std::uint8_t>{server_request_}.first(
                received.metadata.payload_octets));
        if (request) {
          const auto processed = server_->process(
              std::span<const std::uint8_t>{server_request_}.first(
                  received.metadata.payload_octets),
              server_response_,
              received.metadata.interface_id,
              now);
          if (processed.status == dhcpv4::ServerProcessStatus::response) {
            const bool relayed =
                request->gateway_address != packet::Ipv4{};
            server_pending_ = {
                .destination =
                    relayed ? request->gateway_address
                            : (processed.limited_broadcast
                                   ? packet::Ipv4{255U, 255U, 255U, 255U}
                                   : (processed.direct_client_l2
                                          ? request->your_address
                                          : request->client_address)),
                .destination_mac = received.metadata.source_mac,
                .destination_port =
                    relayed ? packet::dhcpv4::server_port
                            : packet::dhcpv4::client_port,
                .octets = processed.message_octets,
                .delivery =
                    relayed
                        ? Delivery::routed
                        : (processed.direct_client_l2
                               ? Delivery::direct_client_l2
                               : (processed.limited_broadcast
                                      ? Delivery::limited_broadcast
                                      : Delivery::routed)),
                .active = true,
            };
            // yiaddr belongs to the encoded response, not the request. Use it
            // as the direct L2 IP destination after parsing the response.
            if (!relayed && processed.direct_client_l2) {
              const auto response = packet::dhcpv4::parse(
                  std::span<const std::uint8_t>{server_response_}.first(
                      processed.message_octets));
              if (response)
                server_pending_.destination = response->your_address;
            }
            static_cast<void>(try_send(
                endpoint, *server_socket_, server_pending_,
                server_response_, sink_context, sink, admission));
          }
        }
      }
    }
  }

  if (!client_ || client_pending_.active)
    return std::nullopt;
  const auto client_deadline = client_->next_deadline();
  if (!probe_.active)
    return client_deadline;
  return client_deadline ? std::min(*client_deadline, probe_.next_action)
                         : std::optional{probe_.next_action};
}

} // namespace router::network_detail
