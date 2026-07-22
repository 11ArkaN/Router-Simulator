// DNS-over-HTTPS over HTTP/2. One logical service shard owns TLS, HTTP/2 and
// DoH request semantics. Only TLSCiphertext crosses the public transport edge,
// where modeled TCP, IP, adjacency, interface and link owners carry it.

#pragma once

#include "router/doh_message.hpp"
#include "router/http2_session.hpp"
#include "router/tls_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::doh2 {

using Method = doh::Method;

enum class State : std::uint8_t {
  handshaking,
  established,
  draining,
  closed,
  failed
};

enum class Failure : std::uint8_t {
  none,
  tls_failure,
  alpn_mismatch,
  http2_failure,
  resource_exhausted
};

enum class RequestStatus : std::uint8_t {
  valid,
  malformed_http,
  wrong_endpoint,
  unsupported_media_type,
  malformed_dns_message,
  stream_error
};

struct Configuration {
  std::string authority;
  std::string path;
  // The staging buffer is a resource-profile input. It must hold one legal
  // default HTTP/2 frame so neither TLS nor HTTP/2 can deadlock on a peer that
  // uses the mandatory RFC 9113 receive size.
  std::size_t plaintext_staging_octets{};
};

struct Request {
  std::int32_t stream_id{};
  RequestStatus status{RequestStatus::malformed_http};
  Method method{Method::post};
  std::vector<std::uint8_t> dns_message;
};

struct Response {
  std::int32_t stream_id{};
  bool complete{};
  std::uint16_t http_status{};
  std::uint32_t age_seconds{};
  std::vector<std::uint8_t> dns_message;
};

class Session final {
public:
  [[nodiscard]] static std::optional<Session>
  create(tls::Engine tls_engine, http2::Session http2_session,
         Configuration configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  // RFC 8484 servers must implement both methods, so the client exposes both
  // and the server parser accepts both. POST carries DNS in the body. GET uses
  // unpadded base64url in the configured URI template's dns parameter.
  [[nodiscard]] http2::SubmitOutcome
  submit_query(Method method,
               std::span<const std::uint8_t> dns_message) noexcept;
  [[nodiscard]] http2::SubmitResult
  submit_response(std::int32_t stream_id,
                  std::span<const std::uint8_t> dns_message,
                  std::uint32_t freshness_seconds) noexcept;
  [[nodiscard]] http2::SubmitResult
  submit_error(std::int32_t stream_id, std::uint16_t status) noexcept;

  [[nodiscard]] State progress() noexcept;
  [[nodiscard]] std::size_t
  ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept;
  [[nodiscard]] std::size_t
  take_ciphertext(std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] std::size_t pending_ciphertext() const noexcept;

  [[nodiscard]] std::optional<Request> take_request() noexcept;
  [[nodiscard]] std::optional<Response> take_response() noexcept;
  [[nodiscard]] http2::Role role() const noexcept;
  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::doh2
