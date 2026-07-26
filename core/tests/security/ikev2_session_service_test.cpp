// Session dispatcher tests prove SPI and role selection, independent Message ID
// directions, duplicate response tokens and non-authenticating NAT keepalive
// handling over received IKE bytes.

#include "router/ikev2_session_service.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

std::array<std::uint8_t, router::ikev2::header_octets>
message(const router::ikev2::Header &header) {
  std::array<std::uint8_t, router::ikev2::header_octets> bytes{};
  if (!router::ikev2::encode_header(header, bytes))
    throw std::runtime_error("IKE session fixture header failed");
  return bytes;
}

} // namespace

void ikev2_session_service_tests() {
  using namespace router::ikev2;
  using namespace std::chrono_literals;
  SessionService service{
      {.maximum_sessions = 2U,
       .maximum_payloads_per_message = 8U,
       .retransmission = {.initial = 500ms,
                          .maximum = 4s,
                          .maximum_retransmissions = 3U}}};
  if (!service.valid())
    throw std::runtime_error("IKE session service allocation failed");
  auto session = std::make_unique<Sa>(
      7U, Role::initiator,
      SaConfiguration{.maximum_child_sas = 2U,
                      .liveness = {.idle_interval = 30s,
                                   .maximum_unanswered_requests = 2U}});
  const auto now = Sa::Clock::time_point{10s};
  if (session->begin_initial_exchange(11U, now) !=
          SaTransitionResult::applied ||
      session->complete_initial_exchange(22U, {.key_set_handle = 33U}, now) !=
          SaTransitionResult::applied ||
      session->complete_authentication(AuthenticationStatus::ok, now) !=
          SaTransitionResult::applied ||
      !service.add(std::move(session)))
    throw std::runtime_error("IKE session service could not own an SA");

  Header peer_request{.initiator_spi = 11U,
                      .responder_spi = 22U,
                      .first_payload = 0U,
                      .major_version = 2U,
                      .minor_version = 0U,
                      .exchange_type = static_cast<std::uint8_t>(
                          ExchangeType::informational),
                      .initiator = false,
                      .higher_version_supported = false,
                      .response = false,
                      .message_id = 0U,
                      .length = header_octets};
  auto request_bytes = message(peer_request);
  UdpInboundDatagram request{.metadata = {},
                             .kind = UdpInboundKind::ike,
                             .bytes = request_bytes};
  const auto request_dispatch = service.receive(request);
  if (request_dispatch.kind !=
          InboundDispatchKind::session_request_candidate ||
      request_dispatch.ike_sa_id != 7U ||
      service.receive(request).kind !=
          InboundDispatchKind::session_request_candidate ||
      service.commit_authenticated(7U, request_dispatch.header, now).kind !=
          AuthenticatedDispatchKind::session_request ||
      !service.cache_response(7U, 0U, 900U) ||
      service.receive(request).kind !=
          InboundDispatchKind::session_request_candidate ||
      service.commit_authenticated(7U, request_dispatch.header, now).kind !=
          AuthenticatedDispatchKind::duplicate_request)
    throw std::runtime_error("IKE inbound Message ID cache failed");

  if (service.start_request(7U, 4U, 901U, now) !=
      RequestStartResult::started)
    throw std::runtime_error("IKE outbound Message ID did not start");
  auto peer_response = peer_request;
  peer_response.response = true;
  peer_response.message_id = 4U;
  auto response_bytes = message(peer_response);
  const auto response_dispatch = service.receive(
      {.metadata = {}, .kind = UdpInboundKind::ike, .bytes = response_bytes});
  if (response_dispatch.kind !=
          InboundDispatchKind::session_response_candidate ||
      service.receive({.metadata = {},
                       .kind = UdpInboundKind::ike,
                       .bytes = response_bytes})
              .kind != InboundDispatchKind::session_response_candidate ||
      service.commit_authenticated(7U, response_dispatch.header, now).kind !=
          AuthenticatedDispatchKind::session_response)
    throw std::runtime_error("IKE response did not match outbound Message ID");
  if (service.start_request(7U, 5U, 902U, now) !=
      RequestStartResult::started)
    throw std::runtime_error("IKE request before checkpoint did not start");

  auto role_mismatch = peer_request;
  role_mismatch.initiator = true;
  auto role_bytes = message(role_mismatch);
  if (service.receive({.metadata = {},
                       .kind = UdpInboundKind::ike,
                       .bytes = role_bytes}).kind !=
      InboundDispatchKind::role_mismatch)
    throw std::runtime_error("IKE sender role mismatch was accepted");
  if (service.receive({.metadata = {},
                       .kind = UdpInboundKind::nat_keepalive,
                       .bytes = {}}).kind !=
          InboundDispatchKind::nat_keepalive ||
      service.receive({.metadata = {},
                       .kind = UdpInboundKind::esp,
                       .bytes = {}}).kind !=
          InboundDispatchKind::esp_for_ipsec)
    throw std::runtime_error("IKE UDP non-IKE classification changed");

  Header initial{.initiator_spi = 44U,
                 .responder_spi = 0U,
                 .first_payload = 0U,
                 .major_version = 2U,
                 .minor_version = 0U,
                 .exchange_type =
                     static_cast<std::uint8_t>(ExchangeType::ike_sa_init),
                 .initiator = true,
                 .higher_version_supported = false,
                 .response = false,
                 .message_id = 0U,
                 .length = header_octets};
  const auto initial_bytes = message(initial);
  if (service.receive({.metadata = {},
                       .kind = UdpInboundKind::ike,
                       .bytes = initial_bytes})
          .kind != InboundDispatchKind::new_ike_sa_init)
    throw std::runtime_error("unassociated IKE_SA_INIT was not dispatched");

  const auto saved = service.checkpoint(now + 100ms);
  SessionService restored{
      {.maximum_sessions = 2U,
       .maximum_payloads_per_message = 8U,
       .retransmission = {.initial = 500ms,
                          .maximum = 4s,
                          .maximum_retransmissions = 3U}}};
  if (!saved || !restored.restore(*saved, now + 10s) ||
      restored.size() != 1U ||
      restored.commit_authenticated(7U, request_dispatch.header, now + 10s)
              .kind != AuthenticatedDispatchKind::duplicate_request)
    throw std::runtime_error("IKE session checkpoint lost response cache");
  if (restored.poll_request(7U, now + 10399ms).action !=
          RequestTimerAction::none ||
      restored.poll_request(7U, now + 10400ms).action !=
          RequestTimerAction::retransmit)
    throw std::runtime_error("IKE session checkpoint changed retransmit time");

  auto duplicate = *saved;
  duplicate.sessions.push_back(duplicate.sessions.front());
  if (restored.restore(duplicate, now + 10s) || restored.size() != 1U ||
      restored.commit_authenticated(7U, request_dispatch.header, now + 10s)
              .kind != AuthenticatedDispatchKind::duplicate_request)
    throw std::runtime_error("invalid IKE checkpoint partially replaced state");
}
