// Socket-free HTTP/3 and QPACK session over one emulator QUIC connection. The
// session owns nghttp3 state, bounded request and response storage, and three
// mandatory local unidirectional streams. It cannot send a datagram except by
// asking its owned QUIC connection to encode one for modeled UDP.

#pragma once

#include "router/quic_connection.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::http3 {

enum class Role : std::uint8_t { client, server };
enum class State : std::uint8_t { established, closing, closed, failed };
enum class Failure : std::uint8_t {
  none,
  invalid_configuration,
  quic_failure,
  protocol_error,
  resource_exhausted
};
enum class SubmitResult : std::uint8_t {
  applied,
  wrong_role,
  invalid_message,
  stream_limit,
  resource_exhausted,
  session_closed
};

struct HeaderField {
  std::string name;
  std::string value;
};

struct Message {
  std::int64_t stream_id{};
  std::vector<HeaderField> headers;
  std::vector<std::uint8_t> body;
  std::vector<HeaderField> trailers;
};

struct Configuration {
  std::size_t max_field_section_octets{};
  std::size_t max_body_octets{};
  std::size_t max_completed_messages{};
  std::size_t max_staged_output_octets{};
  std::size_t qpack_dynamic_table_octets{};
  std::size_t qpack_blocked_streams{};
  std::uint64_t max_remote_bidirectional_streams{};
};

class Session final {
public:
  // QUIC must already be established with h3 ALPN. Delaying HTTP/3 setup until
  // that point prevents application bytes from becoming accidental 0-RTT.
  [[nodiscard]] static std::optional<Session>
  create(quic::Connection connection, Role role,
         const Configuration &configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  [[nodiscard]] SubmitResult
  submit_request(std::span<const HeaderField> headers,
                 std::span<const std::uint8_t> body,
                 std::int64_t &stream_id) noexcept;
  [[nodiscard]] SubmitResult
  submit_response(std::int64_t stream_id,
                  std::span<const HeaderField> headers,
                  std::span<const std::uint8_t> body) noexcept;

  // One progress turn processes one ACK event, one received stream chunk and
  // one nghttp3 output batch. All work is ready now at the supplied monotonic
  // timestamp. The method neither waits nor creates a simulated deadline.
  [[nodiscard]] State progress(quic::RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::optional<Message> take_message() noexcept;

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

  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;
  [[nodiscard]] Role role() const noexcept;
  [[nodiscard]] const quic::Connection &transport() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::http3
