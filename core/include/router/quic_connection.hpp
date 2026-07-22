// Socket-free QUIC v1 connection owner. One logical service shard owns every
// Connection and drives it with monotonic deadlines plus UDP datagrams carried
// by the emulator. The module never creates a system socket and never owns an
// Ethernet, IP or UDP route around the modeled packet path.

#pragma once

#include "router/ip_address.hpp"
#include "router/pki_store.hpp"
#include "router/tls_engine.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::quic {

using RuntimeClock = std::chrono::steady_clock;

// RFC 9000 section 14.1 requires every UDP datagram carrying an Initial packet
// to be at least 1200 bytes. This is a protocol floor, not a connection limit.
inline constexpr std::size_t minimum_initial_datagram_octets = 1200U;

enum class AddressFamily : std::uint8_t { ipv4, ipv6 };

struct EndpointAddress {
  AddressFamily family{AddressFamily::ipv6};
  std::array<std::uint8_t, 16U> bytes{};
  std::uint16_t port{};

  [[nodiscard]] static EndpointAddress
  ipv4(const ip::Ipv4 &address, std::uint16_t port) noexcept;
  [[nodiscard]] static EndpointAddress
  ipv6(const ip::Ipv6 &address, std::uint16_t port) noexcept;
  [[nodiscard]] friend constexpr bool
  operator==(const EndpointAddress &, const EndpointAddress &) noexcept =
      default;
};

struct Path {
  EndpointAddress local;
  EndpointAddress remote;

  [[nodiscard]] friend constexpr bool
  operator==(const Path &, const Path &) noexcept = default;
};

enum class State : std::uint8_t {
  handshaking,
  established,
  closing,
  draining,
  closed,
  failed
};

enum class Failure : std::uint8_t {
  none,
  invalid_configuration,
  certificate_rejected,
  protocol_error,
  resource_exhausted,
  flow_control_blocked,
  stream_limit_blocked,
  peer_closed
};

enum class CongestionControl : std::uint8_t { reno, cubic, bbr2 };

struct TransportConfiguration {
  // These values are advertised QUIC flow-control and stream limits. They are
  // explicit profile inputs because an application must reserve enough memory
  // for every byte it tells its peer it can receive.
  std::uint64_t connection_receive_window{};
  std::uint64_t stream_receive_window{};
  std::uint64_t max_bidirectional_streams{};
  std::uint64_t max_unidirectional_streams{};
  std::uint64_t max_idle_timeout_milliseconds{};
  std::size_t max_udp_payload_octets{};
  std::size_t max_buffered_receive_octets{};
  std::size_t max_buffered_send_octets{};
  std::size_t max_pending_transport_events{};
  CongestionControl congestion_control{CongestionControl::cubic};
  bool allow_active_migration{};
  // Privacy-sensitive applications such as DoQ can request fixed-size QUIC
  // packets without imposing that bandwidth cost on unrelated HTTP/3 users.
  bool pad_stream_datagrams{};
};

struct ClientConfiguration {
  Path initial_path;
  TransportConfiguration transport;
  pki::OpenIdentity *identity{};
  std::span<const std::vector<std::uint8_t>> trust_anchors_der;
  tls::PeerIdentity peer;
  tls::PeerAuthentication peer_authentication{
      tls::PeerAuthentication::required};
  const tls::Tls13PolicyView *tls_policy{};
  std::uint64_t wall_clock_seconds{};
  std::span<const std::string_view> alpn_protocols;
};

struct ServerConfiguration {
  Path initial_path;
  TransportConfiguration transport;
  pki::OpenIdentity *identity{};
  std::span<const std::vector<std::uint8_t>> trust_anchors_der;
  const tls::Tls13PolicyView *tls_policy{};
  std::uint64_t wall_clock_seconds{};
  std::span<const std::string_view> alpn_protocols;
  bool require_client_certificate{};
  // RFC 9000 stateless reset tokens must be unpredictable. The server owner
  // supplies a project-persisted secret so tokens remain stable across
  // ordinary connection creation and are never derived from a hardcoded key.
  std::span<const std::uint8_t> stateless_reset_secret;
};

struct ReceivedStreamChunk {
  std::int64_t stream_id{};
  std::uint64_t offset{};
  std::vector<std::uint8_t> bytes;
  bool fin{};
};

struct Statistics {
  std::uint64_t packets_sent{};
  std::uint64_t packets_received{};
  std::uint64_t packets_lost{};
  std::uint64_t bytes_in_flight{};
  std::uint64_t congestion_window{};
  std::chrono::nanoseconds smoothed_rtt{};
};

struct AcknowledgedStreamRange {
  std::int64_t stream_id{};
  std::uint64_t offset{};
  std::uint64_t octets{};
};

class Connection final {
public:
  // Client construction creates connection IDs with OpenSSL's CSPRNG and
  // immediately makes the first Initial packet eligible for take_datagram.
  [[nodiscard]] static std::optional<Connection>
  client(const ClientConfiguration &configuration,
         RuntimeClock::time_point now) noexcept;

  // A QUIC server needs the original destination and client source connection
  // IDs from the first Initial packet. The factory decodes and consumes that
  // datagram atomically so no caller can mismatch those identities.
  [[nodiscard]] static std::optional<Connection>
  server(const ServerConfiguration &configuration,
         std::span<const std::uint8_t> first_initial_datagram,
         RuntimeClock::time_point received_at) noexcept;

  Connection(Connection &&) noexcept;
  Connection &operator=(Connection &&) noexcept;
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;
  ~Connection();

  // ingest_datagram accepts exactly one modeled UDP payload. The path is part
  // of every call so ngtcp2 can enforce address validation and migration rules
  // instead of assuming that a connection's five-tuple never changes.
  [[nodiscard]] Failure
  ingest_datagram(const Path &path, std::span<const std::uint8_t> datagram,
                  RuntimeClock::time_point received_at) noexcept;

  // take_datagram emits at most one UDP payload and reports its actual path.
  // A zero return means there is nothing sendable now. The output buffer must
  // hold transport.max_udp_payload_octets to avoid truncating a legal packet.
  [[nodiscard]] std::size_t
  take_datagram(std::span<std::uint8_t> output, Path &path,
                RuntimeClock::time_point now) noexcept;

  // Timer ownership remains local to the connection. The service shard waits
  // for this deadline and invokes handle_expiry; there is no global event heap
  // and no synthetic advancement of RuntimeClock.
  [[nodiscard]] std::optional<RuntimeClock::time_point> next_expiry() const
      noexcept;
  [[nodiscard]] Failure
  handle_expiry(RuntimeClock::time_point now) noexcept;

  [[nodiscard]] std::optional<std::int64_t>
  open_bidirectional_stream() noexcept;
  [[nodiscard]] std::optional<std::int64_t>
  open_unidirectional_stream() noexcept;
  [[nodiscard]] Failure
  send_stream(std::int64_t stream_id, std::span<const std::uint8_t> bytes,
              bool fin) noexcept;
  [[nodiscard]] Failure reset_stream(std::int64_t stream_id,
                                     std::uint64_t application_error) noexcept;
  [[nodiscard]] Failure stop_sending(std::int64_t stream_id,
                                     std::uint64_t application_error) noexcept;
  [[nodiscard]] Failure
  close_application(std::uint64_t application_error) noexcept;
  [[nodiscard]] std::optional<ReceivedStreamChunk>
  take_received_stream() noexcept;
  [[nodiscard]] Failure consume_received_stream(
      std::int64_t stream_id, std::size_t octets) noexcept;
  [[nodiscard]] std::optional<AcknowledgedStreamRange>
  take_acknowledged_stream() noexcept;

  [[nodiscard]] State state() const noexcept;
  [[nodiscard]] Failure failure() const noexcept;
  [[nodiscard]] std::string negotiated_alpn() const;
  [[nodiscard]] Path current_path() const noexcept;
  [[nodiscard]] Statistics statistics() const noexcept;

private:
  struct Impl;
  explicit Connection(std::unique_ptr<Impl> impl) noexcept;
  std::unique_ptr<Impl> impl_;
};

} // namespace router::quic
