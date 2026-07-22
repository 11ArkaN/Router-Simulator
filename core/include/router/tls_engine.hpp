// Socket-free TLS 1.3 record and handshake engine. One logical service shard
// owns each Engine, its SSL state and both bounded memory BIO directions. The
// caller moves encrypted bytes between this object and modeled TCP. This
// module never creates a host socket, accesses the DOM or schedules time.

#pragma once

#include "router/pki_store.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::tls {

// RFC 8446 limits TLSCiphertext.content to 2^14 + 256 octets. A smaller BIO
// can deadlock on one legal record, so this is a protocol-derived minimum and
// not an application connection ceiling.
inline constexpr std::size_t minimum_transport_buffer_octets = 16640U;

enum class State : std::uint8_t {
  handshaking,
  established,
  closing,
  closed,
  failed
};

enum class Failure : std::uint8_t {
  none,
  invalid_configuration,
  certificate_rejected,
  protocol_error,
  peer_closed,
  resource_exhausted
};

enum class PeerAuthentication : std::uint8_t {
  // Required uses only project-supplied trust anchors. Disabled represents
  // the documented SR OS client profile behavior when no trust-anchor-profile
  // is configured. It never falls through to a browser or host trust store.
  required,
  disabled
};

struct Tls13PolicyView {
  // All spans are borrowed only during Engine construction. OpenSSL copies
  // the colon-separated policy into SSL_CTX, so the configuration owner can
  // release the resolved vectors after a successful factory call.
  std::span<const std::string_view> cipher_suites;
  std::span<const std::string_view> groups;
  std::span<const std::string_view> signatures;
};

struct PeerIdentity {
  std::string hostname;
  std::optional<std::array<std::uint8_t, 4U>> ipv4_address;
  std::optional<std::array<std::uint8_t, 16U>> ipv6_address;
};

struct ClientConfiguration {
  pki::OpenIdentity *identity{};
  std::span<const std::vector<std::uint8_t>> trust_anchors_der;
  PeerIdentity peer;
  PeerAuthentication peer_authentication{PeerAuthentication::required};
  const Tls13PolicyView *policy{};
  std::uint64_t wall_clock_seconds{};
  std::size_t transport_buffer_octets{};
  // RFC 7301 protocol identifiers are opaque non-empty byte strings of at
  // most 255 octets. The order is the client's descending preference.
  std::span<const std::string_view> alpn_protocols;
};

struct ServerConfiguration {
  pki::OpenIdentity *identity{};
  std::span<const std::vector<std::uint8_t>> trust_anchors_der;
  const Tls13PolicyView *policy{};
  std::uint64_t wall_clock_seconds{};
  std::size_t transport_buffer_octets{};
  bool require_client_certificate{};
  // The server list is its preference order. If configured, absence of a
  // common protocol fails the handshake with no_application_protocol.
  std::span<const std::string_view> alpn_protocols;
};

class Engine final {
public:
  // Factories borrow identity only while configuring SSL_CTX. OpenSSL retains
  // the required certificate and key references, so the caller may close the
  // OpenIdentity after a successful return. Trust anchors are parsed and
  // copied into the context during the same call.
  [[nodiscard]] static std::optional<Engine>
  client(const ClientConfiguration &configuration) noexcept;
  [[nodiscard]] static std::optional<Engine>
  server(const ServerConfiguration &configuration) noexcept;

  Engine(Engine &&) noexcept;
  Engine &operator=(Engine &&) noexcept;
  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;
  ~Engine();

  // ingest_ciphertext writes only bytes accepted by the inbound BIO and
  // returns that count. A short result is transport backpressure, not packet
  // loss. The caller retains and retries the remaining TCP stream bytes.
  [[nodiscard]] std::size_t
  ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept;

  // take_ciphertext drains bytes produced by handshake, alerts or protected
  // application records. Those bytes must be queued on the modeled TCP socket
  // in exactly this order.
  [[nodiscard]] std::size_t
  take_ciphertext(std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] std::size_t pending_ciphertext() const noexcept;

  // progress executes only work possible with bytes available now. WANT_READ
  // and WANT_WRITE retain the current state and never create a timer or busy
  // loop. TCP and the service shard decide when to call again.
  [[nodiscard]] State progress() noexcept;
  [[nodiscard]] std::size_t
  write_plaintext(std::span<const std::uint8_t> bytes) noexcept;
  [[nodiscard]] std::size_t
  read_plaintext(std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] State shutdown() noexcept;

  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;
  [[nodiscard]] long provider_error() const noexcept;
  [[nodiscard]] std::string negotiated_cipher() const;
  [[nodiscard]] std::string negotiated_alpn() const;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  peer_certificate_der() const noexcept;

private:
  struct Impl;
  explicit Engine(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

} // namespace router::tls
