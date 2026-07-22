// Control-owner IKE message dispatcher. It consumes only datagrams delivered
// by the local UDP service, maps authenticated-SA coordinates, and applies
// directional Message ID rules. Cryptographic payload processing remains with
// the selected session and no peer or topology object is reachable here.

#pragma once

#include "router/ikev2_exchange.hpp"
#include "router/ikev2_packet.hpp"
#include "router/ikev2_sa.hpp"
#include "router/ikev2_udp_service.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::ikev2 {

struct SessionServiceConfiguration {
  std::size_t maximum_sessions{};
  std::size_t maximum_payloads_per_message{};
  RetransmissionPolicy retransmission{};
};

enum class InboundDispatchKind : std::uint8_t {
  new_ike_sa_init,
  session_request_candidate,
  session_response_candidate,
  nat_keepalive,
  esp_for_ipsec,
  malformed,
  unknown_session,
  role_mismatch,
  message_id_rejected,
  resource_exhausted
};

struct InboundDispatch {
  InboundDispatchKind kind{InboundDispatchKind::malformed};
  Header header{};
  std::span<const PayloadView> payloads;
  std::uint64_t ike_sa_id{};
  std::uint64_t cached_response_token{};
};

enum class AuthenticatedDispatchKind : std::uint8_t {
  session_request,
  session_response,
  duplicate_request,
  unknown_session,
  role_mismatch,
  message_id_rejected,
  invalid_state
};

struct AuthenticatedDispatch {
  AuthenticatedDispatchKind kind{AuthenticatedDispatchKind::invalid_state};
  std::uint64_t cached_response_token{};
};

struct SessionRecordCheckpoint {
  // The three records form one ownership unit. Restoring only the SA would
  // lose the outstanding request and could reuse a Message ID while the peer
  // still treats the earlier exchange as active.
  SaCheckpoint sa;
  RequestCheckpoint request;
  ResponderCheckpoint response;
};

struct SessionServiceCheckpoint {
  std::vector<SessionRecordCheckpoint> sessions;
};

class SessionService final {
public:
  explicit SessionService(SessionServiceConfiguration configuration) noexcept;

  // Session ownership moves into this control shard. Duplicate IDs or SPI
  // pairs are rejected before ownership changes.
  [[nodiscard]] bool add(std::unique_ptr<Sa> session) noexcept;
  [[nodiscard]] bool remove(std::uint64_t ike_sa_id) noexcept;
  [[nodiscard]] Sa *find(std::uint64_t ike_sa_id) noexcept;
  [[nodiscard]] RequestStartResult start_request(
      std::uint64_t ike_sa_id, std::uint32_t message_id,
      std::uint64_t packet_token,
      RequestTracker::Clock::time_point now = RequestTracker::Clock::now())
      noexcept;
  [[nodiscard]] RequestTimerResult poll_request(
      std::uint64_t ike_sa_id,
      RequestTracker::Clock::time_point now = RequestTracker::Clock::now())
      noexcept;
  [[nodiscard]] LivenessAction poll_liveness(
      std::uint64_t ike_sa_id,
      Sa::Clock::time_point now = Sa::Clock::now()) noexcept;
  [[nodiscard]] bool cache_response(std::uint64_t ike_sa_id,
                                    std::uint32_t message_id,
                                    std::uint64_t packet_token) noexcept;

  // Returned payload views borrow the UDP receive buffer and remain valid only
  // until the next service turn for that endpoint.
  [[nodiscard]] InboundDispatch
  receive(const UdpInboundDatagram &datagram) noexcept;
  // The encrypted-payload owner calls this only after AEAD or integrity
  // verification succeeds for the exact message. Keeping this mutation out of
  // receive() prevents forged SPIs and Message IDs from consuming windows.
  [[nodiscard]] AuthenticatedDispatch commit_authenticated(
      std::uint64_t ike_sa_id, const Header &header,
      Sa::Clock::time_point now = Sa::Clock::now()) noexcept;

  // Relative monotonic deadlines make the image portable across browser
  // restarts. Restore builds and validates a replacement collection first, so
  // malformed project data cannot partially replace live control-plane state.
  [[nodiscard]] std::optional<SessionServiceCheckpoint>
  checkpoint(RequestTracker::Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const SessionServiceCheckpoint &checkpoint,
                             RequestTracker::Clock::time_point now) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return sessions_.size(); }
  [[nodiscard]] bool valid() const noexcept { return valid_; }

private:
  struct SessionRecord {
    SessionRecord(std::unique_ptr<Sa> value,
                  RetransmissionPolicy policy) noexcept
        : sa(std::move(value)), requests(policy) {}

    std::unique_ptr<Sa> sa;
    RequestTracker requests;
    ResponderMessageIds responses;
  };

  SessionServiceConfiguration configuration_{};
  std::vector<SessionRecord> sessions_;
  std::vector<PayloadView> payload_scratch_;
  bool valid_{};
};

} // namespace router::ikev2
