// IKE UDP dispatch and directional Message ID validation. Structural parse
// failure, unknown SPIs and role mismatch are terminal for this datagram and
// never update liveness, replay or CHILD state.

#include "router/ikev2_session_service.hpp"

#include <algorithm>

namespace router::ikev2 {

SessionService::SessionService(
    SessionServiceConfiguration configuration) noexcept
    : configuration_(configuration) {
  if (configuration.maximum_sessions == 0U ||
      configuration.maximum_payloads_per_message == 0U)
    return;
  try {
    sessions_.reserve(configuration.maximum_sessions);
    payload_scratch_.resize(configuration.maximum_payloads_per_message);
    valid_ = true;
  } catch (...) {
    sessions_.clear();
    payload_scratch_.clear();
  }
}

bool SessionService::add(std::unique_ptr<Sa> session) noexcept {
  if (!valid_ || !session || session->id() == 0U ||
      sessions_.size() >= configuration_.maximum_sessions ||
      std::any_of(sessions_.begin(), sessions_.end(), [&](const auto &record) {
        return record.sa->id() == session->id() ||
               (record.sa->spis().initiator == session->spis().initiator &&
                record.sa->spis().responder == session->spis().responder &&
                session->spis().initiator != 0U);
      }))
    return false;
  try {
    sessions_.emplace_back(std::move(session), configuration_.retransmission);
    return true;
  } catch (...) {
    return false;
  }
}

bool SessionService::remove(std::uint64_t ike_sa_id) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  if (found == sessions_.end())
    return false;
  sessions_.erase(found);
  return true;
}

Sa *SessionService::find(std::uint64_t ike_sa_id) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  return found == sessions_.end() ? nullptr : found->sa.get();
}

RequestStartResult SessionService::start_request(
    std::uint64_t ike_sa_id, std::uint32_t message_id,
    std::uint64_t packet_token, RequestTracker::Clock::time_point now) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  return found == sessions_.end()
             ? RequestStartResult::invalid_token
             : found->requests.start(message_id, packet_token, now);
}

RequestTimerResult SessionService::poll_request(
    std::uint64_t ike_sa_id, RequestTracker::Clock::time_point now) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  return found == sessions_.end() ? RequestTimerResult{}
                                  : found->requests.poll(now);
}

LivenessAction SessionService::poll_liveness(
    std::uint64_t ike_sa_id, Sa::Clock::time_point now) noexcept {
  auto *session = find(ike_sa_id);
  return session ? session->poll_liveness(now) : LivenessAction::none;
}

bool SessionService::cache_response(std::uint64_t ike_sa_id,
                                    std::uint32_t message_id,
                                    std::uint64_t packet_token) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  return found != sessions_.end() &&
         found->responses.cache_response(message_id, packet_token);
}

InboundDispatch
SessionService::receive(const UdpInboundDatagram &datagram) noexcept {
  if (!valid_)
    return {.kind = InboundDispatchKind::resource_exhausted,
            .header = {},
            .payloads = {},
            .ike_sa_id = 0U,
            .cached_response_token = 0U};
  if (datagram.kind == UdpInboundKind::nat_keepalive)
    return {.kind = InboundDispatchKind::nat_keepalive,
            .header = {},
            .payloads = {},
            .ike_sa_id = 0U,
            .cached_response_token = 0U};
  if (datagram.kind == UdpInboundKind::esp)
    return {.kind = InboundDispatchKind::esp_for_ipsec,
            .header = {},
            .payloads = {},
            .ike_sa_id = 0U,
            .cached_response_token = 0U};
  const auto parsed = parse(datagram.bytes, payload_scratch_);
  if (parsed.status == ParseStatus::payload_capacity_exhausted)
    return {.kind = InboundDispatchKind::resource_exhausted,
            .header = {},
            .payloads = {},
            .ike_sa_id = 0U,
            .cached_response_token = 0U};
  if (parsed.status != ParseStatus::ok)
    return {.kind = InboundDispatchKind::malformed,
            .header = {},
            .payloads = {},
            .ike_sa_id = 0U,
            .cached_response_token = 0U};
  const auto payloads = std::span<const PayloadView>{payload_scratch_}.first(
      parsed.payload_count);
  if (!parsed.header.response &&
      parsed.header.exchange_type ==
          static_cast<std::uint8_t>(ExchangeType::ike_sa_init) &&
      parsed.header.responder_spi == 0U && parsed.header.message_id == 0U)
    return {.kind = InboundDispatchKind::new_ike_sa_init,
            .header = parsed.header,
            .payloads = payloads};

  const auto found = std::find_if(
      sessions_.begin(), sessions_.end(), [&](const auto &record) {
        const auto spis = record.sa->spis();
        return spis.initiator == parsed.header.initiator_spi &&
               spis.responder == parsed.header.responder_spi;
      });
  if (found == sessions_.end())
    return {.kind = InboundDispatchKind::unknown_session,
            .header = parsed.header,
            .payloads = payloads};
  // The inbound sender is the opposite endpoint. The I bit states whether that
  // sender was the original IKE initiator, independent of request direction.
  const bool peer_is_original_initiator = found->sa->role() == Role::responder;
  if (parsed.header.initiator != peer_is_original_initiator)
    return {.kind = InboundDispatchKind::role_mismatch,
            .header = parsed.header,
            .payloads = payloads,
            .ike_sa_id = found->sa->id()};
  if (parsed.header.response) {
    return {.kind = InboundDispatchKind::session_response_candidate,
            .header = parsed.header,
            .payloads = payloads,
            .ike_sa_id = found->sa->id()};
  }
  return {.kind = InboundDispatchKind::session_request_candidate,
          .header = parsed.header,
          .payloads = payloads,
          .ike_sa_id = found->sa->id()};
}

AuthenticatedDispatch SessionService::commit_authenticated(
    std::uint64_t ike_sa_id, const Header &header,
    Sa::Clock::time_point now) noexcept {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(),
                                  [ike_sa_id](const auto &record) {
                                    return record.sa->id() == ike_sa_id;
                                  });
  if (found == sessions_.end())
    return {.kind = AuthenticatedDispatchKind::unknown_session,
            .cached_response_token = 0U};
  const auto spis = found->sa->spis();
  if (header.initiator_spi != spis.initiator ||
      header.responder_spi != spis.responder)
    return {.kind = AuthenticatedDispatchKind::unknown_session,
            .cached_response_token = 0U};
  const bool peer_is_original_initiator = found->sa->role() == Role::responder;
  if (header.initiator != peer_is_original_initiator)
    return {.kind = AuthenticatedDispatchKind::role_mismatch,
            .cached_response_token = 0U};

  if (header.response) {
    if (found->requests.receive_response(header.message_id) !=
        ResponseResult::matched)
      return {.kind = AuthenticatedDispatchKind::message_id_rejected,
              .cached_response_token = 0U};
    if (found->sa->note_authenticated_activity(now) !=
        SaTransitionResult::applied)
      return {.kind = AuthenticatedDispatchKind::invalid_state,
              .cached_response_token = 0U};
    return {.kind = AuthenticatedDispatchKind::session_response,
            .cached_response_token = 0U};
  }

  const auto decision = found->responses.receive(header.message_id);
  if (decision.result == InboundRequestResult::outside_window)
    return {.kind = AuthenticatedDispatchKind::message_id_rejected,
            .cached_response_token = 0U};
  if (found->sa->note_authenticated_activity(now) !=
      SaTransitionResult::applied)
    return {.kind = AuthenticatedDispatchKind::invalid_state,
            .cached_response_token = 0U};
  if (decision.result == InboundRequestResult::duplicate_with_cached_response)
    return {.kind = AuthenticatedDispatchKind::duplicate_request,
            .cached_response_token = decision.response_token};
  if (decision.result == InboundRequestResult::duplicate_response_not_ready)
    return {.kind = AuthenticatedDispatchKind::message_id_rejected,
            .cached_response_token = 0U};
  return {.kind = AuthenticatedDispatchKind::session_request,
          .cached_response_token = 0U};
}

std::optional<SessionServiceCheckpoint> SessionService::checkpoint(
    RequestTracker::Clock::time_point now) const noexcept {
  if (!valid_)
    return std::nullopt;
  SessionServiceCheckpoint image;
  try {
    image.sessions.reserve(sessions_.size());
    for (const auto &record : sessions_) {
      const auto sa = record.sa->checkpoint(now);
      if (!sa)
        return std::nullopt;
      image.sessions.push_back({.sa = *sa,
                                .request = record.requests.checkpoint(now),
                                .response = record.responses.checkpoint()});
    }
  } catch (...) {
    return std::nullopt;
  }
  return image;
}

bool SessionService::restore(const SessionServiceCheckpoint &checkpoint,
                             RequestTracker::Clock::time_point now) noexcept {
  if (!valid_ || checkpoint.sessions.size() > configuration_.maximum_sessions)
    return false;

  std::vector<SessionRecord> replacement;
  try {
    replacement.reserve(configuration_.maximum_sessions);
    for (const auto &saved : checkpoint.sessions) {
      // IDs identify the local owner while the SPI pair identifies the IKE SA
      // on the wire. Either collision would make later dispatch ambiguous.
      if (saved.sa.id == 0U ||
          std::any_of(replacement.begin(), replacement.end(),
                      [&](const auto &existing) {
                        const auto spis = existing.sa->spis();
                        return existing.sa->id() == saved.sa.id ||
                               (saved.sa.spis.initiator != 0U &&
                                spis.initiator == saved.sa.spis.initiator &&
                                spis.responder == saved.sa.spis.responder);
                      }))
        return false;
      auto sa = std::make_unique<Sa>(saved.sa.id, saved.sa.role,
                                     saved.sa.configuration);
      if (!sa->restore(saved.sa, now))
        return false;
      replacement.emplace_back(std::move(sa), configuration_.retransmission);
      auto &record = replacement.back();
      if (!record.requests.restore(saved.request, now) ||
          !record.responses.restore(saved.response))
        return false;
    }
  } catch (...) {
    return false;
  }
  sessions_.swap(replacement);
  return true;
}

} // namespace router::ikev2
