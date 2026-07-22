// DNS-over-TLS application stream. One logical service shard owns the TLS
// engine, DNS length framing and both bounded message queues. Ciphertext enters
// and leaves only through modeled TCP. No API in this module can use a host
// socket, browser resolver or direct peer reference.

#pragma once

#include "router/tls_engine.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::dot {

enum class State : std::uint8_t {
  handshaking,
  established,
  closing,
  closed,
  failed
};

enum class Failure : std::uint8_t {
  none,
  tls_failure,
  malformed_dns_message,
  resource_exhausted
};

enum class QueueResult : std::uint8_t {
  queued,
  invalid_message,
  queue_full,
  session_closed
};

struct Configuration {
  // RFC 7858 keeps RFC 1035's unsigned two-octet message length. The caller
  // selects a resource-profile ceiling no larger than that wire maximum.
  std::size_t max_dns_message_octets{};
  std::size_t max_queued_outgoing_messages{};
  std::size_t max_queued_incoming_messages{};
};

class Session final {
public:
  // The caller constructs a client or server TLS engine from the selected
  // release profile and PKI objects. Session takes exclusive ownership and
  // never retains borrowed certificate or configuration views.
  [[nodiscard]] static std::optional<Session>
  create(tls::Engine engine, const Configuration &configuration) noexcept;

  Session(Session &&) noexcept;
  Session &operator=(Session &&) noexcept;
  Session(const Session &) = delete;
  Session &operator=(const Session &) = delete;
  ~Session();

  // queue_message copies one complete DNS wire message and prepends its
  // network-order length. Multiple queued queries are pipelined on one TLS
  // session and responses can be returned in a different order by DNS ID.
  [[nodiscard]] QueueResult
  queue_message(std::span<const std::uint8_t> message) noexcept;

  // progress performs a bounded amount of handshake, framing, encryption and
  // decryption work available now. It does not wait, advance a virtual clock
  // or create a future event. The service owner calls it again after TCP I/O.
  [[nodiscard]] State progress() noexcept;

  [[nodiscard]] std::size_t
  ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept;
  [[nodiscard]] std::size_t
  take_ciphertext(std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] std::size_t pending_ciphertext() const noexcept;

  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  take_message() noexcept;
  [[nodiscard]] std::size_t queued_outgoing_messages() const noexcept;
  [[nodiscard]] std::size_t queued_incoming_messages() const noexcept;
  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;
  [[nodiscard]] tls::Failure tls_failure() const noexcept;

private:
  struct Impl;
  explicit Session(std::unique_ptr<Impl> implementation) noexcept;
  std::unique_ptr<Impl> implementation_;
};

} // namespace router::dot
