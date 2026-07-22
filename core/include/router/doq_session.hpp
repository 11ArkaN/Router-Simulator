// DNS over Dedicated QUIC application mapping. Session owns one socket-free
// QUIC connection and per-stream DNS framing state. Network access remains the
// caller's modeled UDP path, and no query can bypass a QUIC STREAM frame.

#pragma once

#include "router/quic_connection.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::doq {

inline constexpr std::uint16_t default_server_port = 853U;
inline constexpr std::uint64_t no_error = 0x0U;
inline constexpr std::uint64_t internal_error = 0x1U;
inline constexpr std::uint64_t protocol_error = 0x2U;
inline constexpr std::uint64_t request_cancelled = 0x3U;
inline constexpr std::uint64_t excessive_load = 0x4U;
inline constexpr std::uint64_t unspecified_error = 0x5U;

enum class Role : std::uint8_t { client, server };
enum class State : std::uint8_t {
  handshaking,
  established,
  closing,
  closed,
  failed
};
enum class Failure : std::uint8_t {
  none,
  quic_failure,
  alpn_mismatch,
  forbidden_port,
  malformed_dns_message,
  resource_exhausted,
  unexpected_stream
};
enum class SubmitResult : std::uint8_t {
  applied,
  not_established,
  invalid_message,
  stream_limit,
  resource_exhausted,
  wrong_role,
  duplicate_response
};

struct Transaction {
  std::int64_t stream_id{};
  std::vector<std::uint8_t> dns_message;
};

struct Configuration {
  Role role{Role::client};
  // DoQ itself always supports the full two-octet DNS message space. This
  // controls only how many completed application transactions can wait for
  // their owner and therefore does not create a smaller wire-size limit.
  std::size_t max_completed_transactions{};
  std::size_t max_incomplete_streams{};
};

class Session final {
public:
  [[nodiscard]] static std::optional<Session>
  create(quic::Connection connection,
         const Configuration &configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  [[nodiscard]] SubmitResult
  submit_query(std::span<const std::uint8_t> dns_message,
               std::int64_t &stream_id) noexcept;
  [[nodiscard]] SubmitResult
  submit_response(std::int64_t stream_id,
                  std::span<const std::uint8_t> dns_message) noexcept;
  [[nodiscard]] SubmitResult cancel(std::int64_t stream_id) noexcept;

  // progress consumes at most one received QUIC stream chunk. This bounded
  // budget prevents one busy resolver connection from monopolizing a service
  // shard while preserving concurrent out-of-order transactions.
  [[nodiscard]] State progress() noexcept;
  [[nodiscard]] std::optional<Transaction> take_transaction() noexcept;

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
  [[nodiscard]] const quic::Connection &transport() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::doq
