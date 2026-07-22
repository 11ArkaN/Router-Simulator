// Socket-free HTTP/2 connection owner. One logical service shard owns each
// Session, its nghttp2 compression state, stream map and bounded application
// queues. The caller moves serialized bytes through modeled TLS and TCP. This
// module cannot create a host socket or call another emulated device directly.

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::http2 {

// RFC 9113 Section 4.2 requires every peer to accept the default 16,384-octet
// frame payload plus its 9-octet frame header. Callers may choose a larger
// transport buffer, but a smaller value could deadlock a conforming peer.
inline constexpr std::size_t minimum_serialized_frame_octets = 16393U;

enum class Role : std::uint8_t { client, server };

enum class State : std::uint8_t { open, draining, closed, failed };

enum class Failure : std::uint8_t {
  none,
  invalid_configuration,
  protocol_error,
  resource_exhausted
};

enum class SubmitResult : std::uint8_t {
  applied,
  invalid_role,
  invalid_message,
  stream_unavailable,
  resource_exhausted,
  protocol_error
};

struct HeaderField {
  std::string name;
  std::string value;
};

struct Message {
  std::int32_t stream_id{};
  bool request{};
  bool complete{};
  std::uint32_t error_code{};
  std::vector<HeaderField> headers;
  std::vector<std::uint8_t> body;
  std::vector<HeaderField> trailers;
};

struct SubmitOutcome {
  SubmitResult result{SubmitResult::invalid_message};
  std::int32_t stream_id{-1};
};

struct Configuration {
  // These are resource-profile inputs, not protocol constants. They bound
  // application retention while nghttp2 independently enforces wire limits,
  // stream states, flow control and HPACK correctness.
  std::uint32_t max_concurrent_streams{};
  std::size_t max_header_octets{};
  std::size_t max_message_body_octets{};
  std::size_t max_buffered_output_octets{};
  std::size_t max_completed_messages{};
  bool accept_server_push{};
};

class Session final {
public:
  // create submits the mandatory local SETTINGS preface. The returned object
  // is ready to produce serialized bytes immediately. Configuration values
  // must be nonzero and output capacity must accept a legal default frame.
  [[nodiscard]] static std::optional<Session>
  create(Role role, const Configuration &configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  // The client request headers must contain the RFC 9113 pseudo-fields. The
  // server response headers must contain :status. nghttp2 validates ordering,
  // connection-specific fields and HTTP message semantics before encoding.
  [[nodiscard]] SubmitOutcome
  submit_request(std::span<const HeaderField> headers,
                 std::span<const std::uint8_t> body) noexcept;
  [[nodiscard]] SubmitResult
  submit_response(std::int32_t stream_id,
                  std::span<const HeaderField> headers,
                  std::span<const std::uint8_t> body) noexcept;

  // ingest_bytes returns only the prefix consumed by nghttp2. The modeled TLS
  // owner retains any suffix and retries it after application backpressure is
  // relieved. A protocol failure closes the connection instead of discarding
  // bytes and pretending the exchange succeeded.
  [[nodiscard]] std::size_t
  ingest_bytes(std::span<const std::uint8_t> bytes) noexcept;

  // take_bytes drains one stable serialized prefix at a time. nghttp2's memory
  // pointer is copied before another library call can invalidate it. The
  // configured bound turns an oversized retained chunk into an explicit
  // resource failure rather than an unbounded allocation.
  [[nodiscard]] std::size_t
  take_bytes(std::span<std::uint8_t> output) noexcept;

  // Completed request or response messages preserve stream ordering. Stream
  // errors are delivered with complete=false and their RFC 9113 error code.
  [[nodiscard]] std::optional<Message> take_message() noexcept;

  [[nodiscard]] bool wants_read() const noexcept;
  [[nodiscard]] bool wants_write() const noexcept;
  [[nodiscard]] std::size_t pending_output_octets() const noexcept;
  [[nodiscard]] std::size_t active_streams() const noexcept;
  [[nodiscard]] Role role() const noexcept;
  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;
  [[nodiscard]] int provider_error() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::http2
