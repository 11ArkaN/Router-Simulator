// Forwarding-owned TCP socket table for one emulated endpoint. It maps local
// listeners and concrete four-tuples to transactional Connection owners. The
// API consumes and produces encoded TCP bytes only and never calls host sockets.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/tcp_connection.hpp"
#include "router/tcp_isn.hpp"
#include "router/udp_transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace router::transport::tcp {

struct EndpointSocketHandle {
  std::uint32_t index{};
  std::uint32_t generation{};

  [[nodiscard]] friend constexpr bool
  operator==(const EndpointSocketHandle &,
             const EndpointSocketHandle &) noexcept = default;
};

struct EndpointBinding {
  transport::IpFamily family{transport::IpFamily::ipv6};
  packet::Ipv4 ipv4{};
  packet::Ipv6 ipv6{};
  std::uint64_t interface_id{};
  // Zero requests a port from the generated IANA dynamic/private range. TCP
  // and UDP intentionally retain separate port namespaces.
  std::uint16_t port{};

  [[nodiscard]] bool operator==(const EndpointBinding &) const noexcept = default;
};

struct EndpointRemote {
  packet::Ipv4 ipv4{};
  packet::Ipv6 ipv6{};
  std::uint16_t port{};
};

struct SocketResources {
  // These are initial socket-memory resources, not application message limits.
  // A short write reports flow-control backpressure to the application owner.
  std::size_t send_buffer_bytes{
      device_catalog::tcp_send_buffer_default_bytes};
  std::size_t receive_buffer_bytes{
      device_catalog::tcp_receive_buffer_default_bytes};
  std::size_t transmission_records{
      device_catalog::tcp_transmission_records_default};
  std::size_t sack_ranges{device_catalog::tcp_sack_ranges_default};

  [[nodiscard]] bool operator==(const SocketResources &) const noexcept = default;
};

struct EndpointSocketCheckpoint {
  EndpointBinding binding{};
  SocketResources resources{};
  std::optional<ConnectionCheckpoint> connection;
  std::vector<EndpointSocketHandle> accepted;
  std::optional<std::uint32_t> listener_index;
  // One fixed-size advisory error mirrors a socket SO_ERROR slot. It belongs
  // only to connected sockets and cannot turn hostile ICMP traffic into an
  // unbounded checkpoint or runtime queue.
  std::optional<transport::Ipv6NetworkError> network_error;
  std::size_t backlog{};
  std::uint32_t generation{1U};
  bool occupied{};
  bool listener{};
  bool queued_for_accept{};
};

struct EndpointCheckpoint {
  IsnCheckpoint isn{};
  std::vector<EndpointSocketCheckpoint> sockets;
  std::uint16_t ephemeral_cursor{device_catalog::tcp_ephemeral_port_first};
  std::uint64_t next_endpoint_token{1U};
};

enum class EndpointPrepareStatus : std::uint8_t {
  prepared,
  no_action,
  state_changed,
  stateless_response,
  malformed_segment,
  no_socket,
  invalid_socket,
  invalid_binding,
  tuple_conflict,
  backlog_full,
  resource_exhausted,
  connection_error,
  pending_transmission
};

struct PreparedEndpointSegment {
  EndpointSocketHandle socket{};
  std::uint64_t endpoint_token{};
  std::size_t octets{};
  ControlEvent event{ControlEvent::none};
  bool emit{};

  [[nodiscard]] explicit operator bool() const noexcept {
    return endpoint_token != 0U;
  }
};

struct EndpointPrepareResult {
  EndpointPrepareStatus status{EndpointPrepareStatus::no_action};
  PreparedEndpointSegment segment{};
};

class TcpEndpoint final {
public:
  using Clock = std::chrono::steady_clock;

  explicit TcpEndpoint(crypto::Sha256Digest secret,
                       Clock::time_point now = Clock::now()) noexcept;
  ~TcpEndpoint();
  TcpEndpoint(const TcpEndpoint &) = delete;
  TcpEndpoint &operator=(const TcpEndpoint &) = delete;

  [[nodiscard]] bool valid() const noexcept;

  // backlog is an explicit application resource just as it is for a kernel
  // listen socket. No hidden child-count ceiling exists in the transport.
  [[nodiscard]] std::optional<EndpointSocketHandle> listen(
      EndpointBinding binding,
      std::size_t backlog = device_catalog::tcp_listen_backlog_default,
      SocketResources resources = {}) noexcept;
  [[nodiscard]] std::optional<EndpointSocketHandle>
  accept(EndpointSocketHandle listener) noexcept;

  // Active open returns a staged SYN. The caller commits it only after the IP
  // packet and lower queue accept the encoded segment.
  [[nodiscard]] EndpointPrepareResult prepare_connect(
      EndpointBinding binding, EndpointRemote remote,
      std::uint32_t maximum_transport_message,
      std::span<std::uint8_t> output, SocketResources resources = {},
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] EndpointPrepareResult ingest_ipv4(
      std::span<const std::uint8_t> segment, packet::Ipv4 source,
      packet::Ipv4 destination, std::uint64_t interface_id,
      std::uint32_t maximum_transport_message,
      std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointPrepareResult ingest_ipv6(
      std::span<const std::uint8_t> segment, packet::Ipv6 source,
      packet::Ipv6 destination, std::uint64_t interface_id,
      std::uint32_t maximum_transport_message,
      std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::size_t write(
      EndpointSocketHandle socket, std::span<const std::uint8_t> bytes,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::size_t read(
      EndpointSocketHandle socket, std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointPrepareResult prepare_data(
      EndpointSocketHandle socket, std::span<std::uint8_t> output,
      bool pushed, Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointPrepareResult prepare_close(
      EndpointSocketHandle socket, std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointPrepareResult prepare_deadline(
      EndpointSocketHandle socket, std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] bool commit(const PreparedEndpointSegment &prepared,
                            Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool discard(const PreparedEndpointSegment &prepared) noexcept;
  [[nodiscard]] bool close(EndpointSocketHandle socket) noexcept;

  [[nodiscard]] std::optional<State>
  state(EndpointSocketHandle socket) const noexcept;
  [[nodiscard]] std::optional<Clock::time_point>
  next_deadline(EndpointSocketHandle socket) const noexcept;
  // Returns the connection owning the earliest local deadline. The endpoint
  // shard uses the copied handle to select the IP family before asking that
  // connection to stage output. Equal deadlines retain stable socket order.
  [[nodiscard]] std::optional<EndpointSocketHandle>
  earliest_deadline_socket() const noexcept;
  [[nodiscard]] std::optional<EndpointBinding>
  local_binding(EndpointSocketHandle socket) const noexcept;
  // The remote tuple is read-only routing metadata for the endpoint IP owner.
  // Exposing a copied value avoids duplicating connection state in that owner
  // and cannot be used to communicate directly with the peer endpoint.
  [[nodiscard]] std::optional<EndpointRemote>
  remote_endpoint(EndpointSocketHandle socket) const noexcept;
  // The IP owner calls these only after parsing a valid ICMP quotation. The
  // tuple selects one connection and the sequence must still belong to an
  // admitted, unacknowledged transmission before its packetization limit can
  // change.
  [[nodiscard]] bool recognizes_ipv4_transmission(
      packet::Ipv4 local, packet::Ipv4 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      std::uint32_t sequence) const noexcept;
  [[nodiscard]] bool reduce_ipv4_path_mtu(
      packet::Ipv4 local, packet::Ipv4 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      std::uint32_t sequence,
      std::uint32_t maximum_transport_message) noexcept;
  [[nodiscard]] bool recognizes_ipv6_transmission(
      packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      std::uint32_t sequence) const noexcept;
  [[nodiscard]] bool reduce_ipv6_path_mtu(
      packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      std::uint32_t sequence,
      std::uint32_t maximum_transport_message) noexcept;
  // RFC 8201 path notification is broader than the invoking packet. A PTB
  // quoted from UDP must still reduce every TCP packetization instance using
  // the same destination and routed interface.
  [[nodiscard]] std::size_t reduce_ipv6_path_mtu_for_path(
      packet::Ipv6 remote, std::uint64_t interface_id,
      std::uint32_t maximum_transport_message) noexcept;
  [[nodiscard]] bool report_ipv6_error(
      packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      std::uint32_t sequence, transport::Ipv6NetworkErrorKind kind,
      std::uint8_t type, std::uint8_t code,
      std::uint32_t parameter) noexcept;
  [[nodiscard]] std::optional<transport::Ipv6NetworkError>
  take_network_error(EndpointSocketHandle socket) noexcept;
  [[nodiscard]] std::optional<EndpointCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const noexcept;
  [[nodiscard]] bool restore(const EndpointCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  struct Socket;
  struct OwnedConnection;

  [[nodiscard]] Socket *socket(EndpointSocketHandle handle) noexcept;
  [[nodiscard]] const Socket *socket(EndpointSocketHandle handle) const noexcept;
  [[nodiscard]] std::optional<std::uint16_t>
  ephemeral_port(const EndpointBinding &binding) noexcept;
  [[nodiscard]] bool binding_valid(const EndpointBinding &binding,
                                   bool listener) const noexcept;
  [[nodiscard]] bool resources_valid(const SocketResources &resources) const noexcept;
  [[nodiscard]] std::optional<EndpointSocketHandle>
  allocate_connection(const ConnectionTuple &tuple,
                      const EndpointBinding &binding,
                      const SocketResources &resources,
                      std::uint32_t maximum_transport_message,
                      std::optional<std::uint32_t> listener_index,
                      Clock::time_point now) noexcept;
  [[nodiscard]] EndpointPrepareResult stage(
      EndpointSocketHandle socket, const ConnectionPrepareResult &prepared,
      bool newly_created) noexcept;
  [[nodiscard]] EndpointPrepareResult prepare_for_socket(
      EndpointSocketHandle socket, const ConnectionPrepareResult &prepared,
      bool newly_created, Clock::time_point now) noexcept;
  [[nodiscard]] EndpointPrepareResult ingest(
      transport::IpFamily family, std::span<const std::uint8_t> segment,
      packet::Ipv4 source_ipv4, packet::Ipv4 destination_ipv4,
      packet::Ipv6 source_ipv6, packet::Ipv6 destination_ipv6,
      std::uint64_t interface_id, std::uint32_t maximum_transport_message,
      std::span<std::uint8_t> output, Clock::time_point now) noexcept;
  void enqueue_accepted(Socket &child) noexcept;
  void release(std::uint32_t index) noexcept;

  crypto::Sha256Digest secret_{};
  InitialSequenceGenerator isn_;
  std::vector<std::unique_ptr<Socket>> sockets_;
  std::uint16_t ephemeral_cursor_{device_catalog::tcp_ephemeral_port_first};
  std::uint64_t next_endpoint_token_{1U};
};

} // namespace router::transport::tcp
