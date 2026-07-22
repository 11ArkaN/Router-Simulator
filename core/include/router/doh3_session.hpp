// DNS-over-HTTPS service semantics over an HTTP/3 session. The service owns
// the configured URI, request validation and response interpretation. Its
// HTTP/3 owner retains QUIC, TLS, QPACK and all encoded UDP datagrams.

#pragma once

#include "router/doh_message.hpp"
#include "router/http3_session.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::doh3 {

using Method = doh::Method;

enum class Failure : std::uint8_t {
  none,
  invalid_configuration,
  http3_failure,
  resource_exhausted
};

enum class RequestStatus : std::uint8_t {
  valid,
  malformed_http,
  wrong_endpoint,
  unsupported_media_type,
  malformed_dns_message
};

struct Configuration {
  std::string authority;
  std::string path;
};

struct SubmitOutcome {
  http3::SubmitResult result{http3::SubmitResult::invalid_message};
  std::int64_t stream_id{-1};
};

struct Request {
  std::int64_t stream_id{};
  RequestStatus status{RequestStatus::malformed_http};
  Method method{Method::post};
  std::vector<std::uint8_t> dns_message;
};

struct Response {
  std::int64_t stream_id{};
  std::uint16_t http_status{};
  std::uint32_t age_seconds{};
  std::vector<std::uint8_t> dns_message;
};

class Session final {
public:
  // Preconditions: HTTP/3 is established with h3 ALPN and the configured
  // path is an absolute path without a query component. The session takes
  // sole ownership of the transport and stays on its service shard.
  [[nodiscard]] static std::optional<Session>
  create(http3::Session http_session, Configuration configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  // A successful result allocates one client-initiated request stream. GET
  // uses canonical unpadded base64url; POST carries the DNS wire message as
  // the body. Resource failures never produce a partially visible request.
  [[nodiscard]] SubmitOutcome
  submit_query(Method method,
               std::span<const std::uint8_t> dns_message) noexcept;
  [[nodiscard]] http3::SubmitResult
  submit_response(std::int64_t stream_id,
                  std::span<const std::uint8_t> dns_message,
                  std::uint32_t freshness_seconds) noexcept;
  [[nodiscard]] http3::SubmitResult
  submit_error(std::int64_t stream_id, std::uint16_t status) noexcept;

  [[nodiscard]] http3::State
  progress(quic::RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::optional<Request> take_request() noexcept;
  [[nodiscard]] std::optional<Response> take_response() noexcept;

  // These methods preserve the QUIC datagram boundary. A caller must pass the
  // returned bytes through modeled UDP, IP, interface queues and a link before
  // calling ingest_datagram on the peer.
  [[nodiscard]] quic::Failure
  ingest_datagram(const quic::Path &path,
                  std::span<const std::uint8_t> datagram,
                  quic::RuntimeClock::time_point received_at) noexcept;
  [[nodiscard]] std::size_t
  take_datagram(std::span<std::uint8_t> output, quic::Path &path,
                quic::RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::optional<quic::RuntimeClock::time_point>
  next_expiry() const noexcept;
  [[nodiscard]] quic::Failure
  handle_expiry(quic::RuntimeClock::time_point now) noexcept;

  [[nodiscard]] http3::Role role() const noexcept;
  [[nodiscard]] http3::State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::doh3
