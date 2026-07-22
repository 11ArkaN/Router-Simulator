// IKEv2 UDP socket lifecycle and RFC 3948 payload classification. This file
// performs no IKE state transition. Its callback boundary stays inside the
// same forwarding owner and receives only bytes delivered by UdpEndpoint.

#include "router/ikev2_udp_service.hpp"

#include "router/ip_address.hpp"
#include "router/udp_packet.hpp"

#include <algorithm>

namespace router::ikev2 {
namespace {

transport::UdpBinding binding(transport::IpFamily family,
                              bool encapsulated) noexcept {
  return {.family = family,
          .ipv4 = {},
          .ipv6 = {},
          .interface_id = 0U,
          .port = encapsulated ? ipsec::nat_t::encapsulated_port
                               : ipsec::nat_t::ike_port};
}

bool is_expected_binding(const transport::UdpBinding &actual,
                         transport::IpFamily family,
                         bool encapsulated) noexcept {
  const bool wildcard = family == transport::IpFamily::ipv4
                            ? std::all_of(actual.ipv4.begin(), actual.ipv4.end(),
                                          [](auto octet) { return octet == 0U; })
                            : ip::is_unspecified(actual.ipv6);
  return actual.family == family && actual.interface_id == 0U && wildcard &&
         !actual.ipv4_broadcast &&
         actual.port == (encapsulated ? ipsec::nat_t::encapsulated_port
                                      : ipsec::nat_t::ike_port);
}

} // namespace

UdpService::UdpService()
    : receive_buffer_(packet::udp::maximum_datagram_octets) {}

std::size_t UdpService::socket_index(transport::IpFamily family,
                                     bool encapsulated) noexcept {
  return (family == transport::IpFamily::ipv6 ? 2U : 0U) +
         (encapsulated ? 1U : 0U);
}

bool UdpService::configure(transport::UdpEndpoint &endpoint) noexcept {
  if (configured_ || receive_buffer_.size() !=
                         packet::udp::maximum_datagram_octets)
    return false;
  std::size_t bound{};
  for (const auto family :
       {transport::IpFamily::ipv4, transport::IpFamily::ipv6}) {
    for (const bool encapsulated : {false, true}) {
      const auto handle = endpoint.bind(binding(family, encapsulated));
      if (!handle) {
        for (std::size_t index = 0U; index < bound; ++index)
          static_cast<void>(endpoint.close(sockets_[index]));
        sockets_.fill({});
        return false;
      }
      sockets_[socket_index(family, encapsulated)] = *handle;
      ++bound;
    }
  }
  configured_ = true;
  return true;
}

void UdpService::remove(transport::UdpEndpoint &endpoint) noexcept {
  if (!configured_)
    return;
  for (const auto handle : sockets_)
    static_cast<void>(endpoint.close(handle));
  sockets_.fill({});
  configured_ = false;
}

UdpServiceResult UdpService::service_one(
    transport::UdpEndpoint &endpoint, void *context,
    UdpInboundHandler handler) noexcept {
  if (!configured_ || !handler)
    return UdpServiceResult::transport_error;
  for (std::size_t index = 0U; index < sockets_.size(); ++index) {
    const auto received = endpoint.receive(sockets_[index], receive_buffer_);
    if (received.status == transport::UdpReceiveStatus::empty)
      continue;
    if (received.status != transport::UdpReceiveStatus::delivered)
      return UdpServiceResult::transport_error;
    auto bytes = std::span<const std::uint8_t>{receive_buffer_}.first(
        received.metadata.payload_octets);
    UdpInboundKind kind{UdpInboundKind::ike};
    const bool encapsulated = (index & 1U) != 0U;
    if (encapsulated) {
      const auto classified = ipsec::nat_t::classify(bytes);
      if (classified.kind == ipsec::nat_t::PayloadKind::invalid)
        return UdpServiceResult::malformed;
      bytes = classified.bytes;
      if (classified.kind == ipsec::nat_t::PayloadKind::esp)
        kind = UdpInboundKind::esp;
      else if (classified.kind == ipsec::nat_t::PayloadKind::nat_keepalive)
        kind = UdpInboundKind::nat_keepalive;
    }
    return handler(context,
                   {.metadata = received.metadata, .kind = kind, .bytes = bytes})
               ? UdpServiceResult::delivered
               : UdpServiceResult::handler_rejected;
  }
  return UdpServiceResult::empty;
}

std::optional<transport::UdpSocketHandle>
UdpService::socket(transport::IpFamily family,
                   bool encapsulated) const noexcept {
  return configured_
             ? std::optional{sockets_[socket_index(family, encapsulated)]}
             : std::nullopt;
}

UdpServiceCheckpoint UdpService::checkpoint() const noexcept {
  return {.sockets = sockets_, .configured = configured_};
}

bool UdpService::validate_checkpoint(
    const UdpServiceCheckpoint &state,
    const transport::UdpEndpointCheckpoint &udp_state) noexcept {
  if (!state.configured)
    return std::all_of(state.sockets.begin(), state.sockets.end(),
                       [](const auto handle) {
                         return handle.index == 0U && handle.generation == 0U;
                       });
  for (const auto family :
       {transport::IpFamily::ipv4, transport::IpFamily::ipv6})
    for (const bool encapsulated : {false, true}) {
      const auto handle = state.sockets[socket_index(family, encapsulated)];
      if (handle.index >= udp_state.sockets.size())
        return false;
      const auto &saved = udp_state.sockets[handle.index];
      if (!saved.occupied || saved.generation != handle.generation ||
          !is_expected_binding(saved.binding, family, encapsulated))
        return false;
    }
  return true;
}

bool UdpService::restore(const UdpServiceCheckpoint &state,
                         const transport::UdpEndpoint &endpoint) noexcept {
  if (!state.configured) {
    sockets_.fill({});
    configured_ = false;
    return true;
  }
  for (const auto family :
       {transport::IpFamily::ipv4, transport::IpFamily::ipv6})
    for (const bool encapsulated : {false, true}) {
      const auto handle = state.sockets[socket_index(family, encapsulated)];
      const auto actual = endpoint.local_binding(handle);
      if (!actual || !is_expected_binding(*actual, family, encapsulated))
        return false;
    }
  sockets_ = state.sockets;
  configured_ = true;
  return true;
}

} // namespace router::ikev2
