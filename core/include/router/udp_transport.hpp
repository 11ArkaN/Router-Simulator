// Forwarding-owned dual-stack UDP socket table and receive queues. A transport
// instance belongs to one endpoint shard. It consumes validated wire datagrams,
// stores payload bytes in a bounded block pool and never calls host networking.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/udp_packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::transport {

enum class IpFamily : std::uint8_t { ipv4, ipv6 };

struct UdpSocketHandle {
  std::uint32_t index{};
  std::uint32_t generation{};

  [[nodiscard]] friend constexpr bool
  operator==(const UdpSocketHandle &, const UdpSocketHandle &) noexcept =
      default;
};

struct UdpBinding {
  IpFamily family{IpFamily::ipv6};
  packet::Ipv4 ipv4{};
  packet::Ipv6 ipv6{};
  // Zero is the wildcard interface. A link-local IPv6 address requires an
  // explicit stable interface ID because its numeric bytes are not globally
  // meaningful without an RFC 4007 zone.
  std::uint64_t interface_id{};
  // Port zero requests allocation from the generated local ephemeral range.
  std::uint16_t port{};
  // This is the modeled SO_BROADCAST permission for IPv4 transmission. It is
  // persisted with the socket because silently enabling broadcast on restore
  // would widen an application's network authority.
  bool ipv4_broadcast{};
  // Address acquisition may receive a link-layer unicast whose IPv4
  // destination is the offered address before the interface owns it. This
  // receive-only authority is separate from SO_BROADCAST and must be requested
  // explicitly by the protocol that owns the socket.
  bool ipv4_unconfigured_unicast{};
};

enum class UdpIngressStatus : std::uint8_t {
  delivered,
  malformed,
  no_socket,
  queue_full
};

enum class UdpReceiveStatus : std::uint8_t {
  delivered,
  empty,
  invalid_socket,
  buffer_too_small
};

enum class UdpSendStatus : std::uint8_t {
  encoded,
  invalid_socket,
  wrong_family,
  invalid_source,
  invalid_destination,
  address_not_available,
  interface_mismatch,
  message_too_large,
  buffer_too_small
};

enum class Ipv6NetworkErrorKind : std::uint8_t {
  destination_unreachable,
  packet_too_big,
  time_exceeded,
  parameter_problem,
  unknown
};

[[nodiscard]] constexpr bool ipv6_network_error_kind_matches(
    Ipv6NetworkErrorKind kind, std::uint8_t type) noexcept {
  // Raw type is retained for future IANA assignments. Known wire values must
  // never be relabeled through a corrupt checkpoint or an internal caller.
  switch (type) {
  case packet::icmpv6_destination_unreachable_type:
    return kind == Ipv6NetworkErrorKind::destination_unreachable;
  case packet::icmpv6_packet_too_big_type:
    return kind == Ipv6NetworkErrorKind::packet_too_big;
  case packet::icmpv6_time_exceeded_type:
    return kind == Ipv6NetworkErrorKind::time_exceeded;
  case packet::icmpv6_parameter_problem_type:
    return kind == Ipv6NetworkErrorKind::parameter_problem;
  default:
    return type < packet::icmpv6_informational_type_boundary &&
           kind == Ipv6NetworkErrorKind::unknown;
  }
}

struct Ipv6NetworkError {
  packet::Ipv6 remote{};
  std::uint64_t interface_id{};
  std::uint32_t parameter{};
  std::uint16_t remote_port{};
  std::uint8_t type{};
  std::uint8_t code{};
  Ipv6NetworkErrorKind kind{Ipv6NetworkErrorKind::destination_unreachable};
};

struct UdpIpv6Transmission {
  packet::Ipv6 local{};
  packet::Ipv6 remote{};
  std::uint64_t interface_id{};
  std::uint16_t remote_port{};
};

struct UdpSendResult {
  UdpSendStatus status{UdpSendStatus::invalid_socket};
  std::size_t datagram_octets{};
};

struct UdpDatagramMetadata {
  IpFamily family{IpFamily::ipv6};
  packet::Ipv4 source_ipv4{};
  packet::Ipv4 destination_ipv4{};
  packet::Ipv6 source_ipv6{};
  packet::Ipv6 destination_ipv6{};
  // Link identity accompanies received IPv6 data only when the IP owner had
  // an Ethernet source. DHCPv6 relay lease population must correlate a DUID
  // with the actual adjacent client and must never infer a MAC from DUID bytes.
  packet::Mac source_mac{};
  std::uint64_t interface_id{};
  std::uint32_t payload_octets{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
};

struct UdpReceiveResult {
  UdpReceiveStatus status{UdpReceiveStatus::empty};
  UdpDatagramMetadata metadata{};
};

struct UdpQueuedDatagramCheckpoint {
  UdpDatagramMetadata metadata{};
  std::vector<std::uint8_t> payload;
};

struct UdpSocketCheckpoint {
  UdpBinding binding{};
  std::vector<UdpQueuedDatagramCheckpoint> datagrams;
  // ICMP is advisory and may be lost. Retaining the most recent IPv6 send is
  // sufficient to reject errors for a tuple this socket never emitted, while
  // a single SO_ERROR-style slot prevents untrusted ICMP from growing memory.
  std::optional<UdpIpv6Transmission> last_ipv6_transmission;
  std::optional<Ipv6NetworkError> network_error;
  std::uint32_t generation{1U};
  bool occupied{};
};

struct UdpEndpointCheckpoint {
  // Every slot generation is persisted, including free slots, so a stale
  // pre-checkpoint handle cannot become valid after restore and slot reuse.
  // Socket slots grow with actual bind operations. Receive payload and
  // datagram repositories remain explicit memory resources, but an idle UDP
  // endpoint no longer preallocates or exposes an arbitrary socket-count cap.
  std::vector<UdpSocketCheckpoint> sockets;
  std::uint16_t ephemeral_cursor{device_catalog::udp_ephemeral_port_first};
};

class UdpEndpoint final {
public:
  // Runtime budgeting needs the exact persistent heap allocation made by
  // every endpoint. The block link is stored beside payload bytes, so counting
  // only the configured receive payload would understate sixteen eager host
  // arenas. This value excludes vector control words already present in
  // sizeof(UdpEndpoint).
  static constexpr std::size_t payload_arena_allocation_bytes =
      (device_catalog::udp_receive_buffer_bytes_per_endpoint /
       device_catalog::udp_receive_block_bytes) *
      (device_catalog::udp_receive_block_bytes + sizeof(std::uint16_t));

  UdpEndpoint();

  // Bind rejects an overlapping wildcard or exact local tuple. This initial
  // contract intentionally exposes no successful reuse no-op. A later
  // multicast reuse policy can extend the binding record without weakening
  // uniqueness for DHCPv6 and DNS sockets.
  [[nodiscard]] std::optional<UdpSocketHandle>
  bind(const UdpBinding &binding) noexcept;
  [[nodiscard]] bool close(UdpSocketHandle handle) noexcept;
  [[nodiscard]] std::optional<std::uint16_t>
  local_port(UdpSocketHandle handle) const noexcept;
  [[nodiscard]] std::optional<UdpBinding>
  local_binding(UdpSocketHandle handle) const noexcept;

  // Input bytes are exactly one UDP datagram extracted from a complete IP
  // packet. Codec checksum and length validation happens before demultiplexing,
  // so malformed input cannot consume queue descriptors or payload blocks.
  [[nodiscard]] UdpIngressStatus ingest_ipv4(
      std::span<const std::uint8_t> datagram, packet::Ipv4 source,
      packet::Ipv4 destination, std::uint64_t interface_id,
      packet::Mac source_mac = {}) noexcept;
  // Ethernet filtering remains the IP owner's responsibility. This query only
  // proves that an occupied IPv4 socket granted pre-address unicast authority
  // for the exact interface and destination port.
  [[nodiscard]] bool accepts_ipv4_unconfigured_unicast(
      std::uint64_t interface_id,
      std::uint16_t destination_port) const noexcept;
  [[nodiscard]] UdpIngressStatus ingest_ipv6(
      std::span<const std::uint8_t> datagram, packet::Ipv6 source,
      packet::Ipv6 destination, std::uint64_t interface_id,
      packet::Mac source_mac = {}) noexcept;

  // If output is too small, the datagram remains at the queue head and the
  // required payload length is returned in metadata. Successful receive copies
  // only application payload, then returns every descriptor and block to this
  // same endpoint owner's free lists.
  [[nodiscard]] UdpReceiveResult
  receive(UdpSocketHandle handle, std::span<std::uint8_t> output) noexcept;
  // The IP owner selects a valid source address and supplies the outgoing
  // interface. UDP verifies that choice against the local bind, then writes a
  // complete datagram into caller-owned storage. No link MTU is accepted here:
  // a legal 65535-octet datagram remains legal and the originating IP layer
  // decides whether it requires fragments.
  [[nodiscard]] UdpSendResult encode_ipv6(
      UdpSocketHandle handle, packet::Ipv6 source, packet::Ipv6 destination,
      std::uint64_t interface_id, std::uint16_t destination_port,
      std::span<const std::uint8_t> payload,
      std::span<std::uint8_t> output) noexcept;
  // IPv4 permits a zero checksum on the wire, so callers may explicitly
  // disable it for protocols that require that legacy behavior. The default
  // computes the checksum. The IP owner still owns routing, source validity,
  // fragmentation and any smaller MTU discovered for the selected path.
  [[nodiscard]] UdpSendResult encode_ipv4(
      UdpSocketHandle handle, packet::Ipv4 source, packet::Ipv4 destination,
      std::uint64_t interface_id, std::uint16_t destination_port,
      std::span<const std::uint8_t> payload,
      std::span<std::uint8_t> output,
      bool checksum_enabled = true) const noexcept;
  [[nodiscard]] std::size_t queued(UdpSocketHandle handle) const noexcept;
  // report_ipv6_error accepts only the exact most recent emitted tuple. The
  // caller must already have validated the outer ICMPv6 checksum and quote.
  [[nodiscard]] bool report_ipv6_error(
      packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
      std::uint16_t local_port, std::uint16_t remote_port,
      Ipv6NetworkErrorKind kind, std::uint8_t type, std::uint8_t code,
      std::uint32_t parameter) noexcept;
  [[nodiscard]] std::optional<Ipv6NetworkError>
  take_network_error(UdpSocketHandle handle) noexcept;
  [[nodiscard]] std::size_t free_payload_octets() const noexcept;
  [[nodiscard]] UdpEndpointCheckpoint checkpoint() const;
  [[nodiscard]] static bool
  validate_checkpoint(const UdpEndpointCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const UdpEndpointCheckpoint &state) noexcept;

private:
  static constexpr std::uint16_t invalid_index = 0xffffU;
  static constexpr std::size_t block_count =
      device_catalog::udp_receive_buffer_bytes_per_endpoint /
      device_catalog::udp_receive_block_bytes;

  struct Socket {
    UdpBinding binding{};
    std::uint16_t queue_head{invalid_index};
    std::uint16_t queue_tail{invalid_index};
    std::uint16_t queued{};
    std::optional<UdpIpv6Transmission> last_ipv6_transmission;
    std::optional<Ipv6NetworkError> network_error;
    std::uint32_t generation{1U};
    bool occupied{};
  };

  struct Datagram {
    UdpDatagramMetadata metadata{};
    std::uint16_t first_block{invalid_index};
    std::uint16_t next{invalid_index};
    std::uint16_t block_count{};
    bool occupied{};
  };

  struct Block {
    std::array<std::uint8_t, device_catalog::udp_receive_block_bytes> bytes{};
    std::uint16_t next{invalid_index};
  };

  static_assert(sizeof(Block) ==
                    device_catalog::udp_receive_block_bytes +
                        sizeof(std::uint16_t),
                "UDP block padding changed the generated memory budget");

  [[nodiscard]] Socket *socket(UdpSocketHandle handle) noexcept;
  [[nodiscard]] const Socket *socket(UdpSocketHandle handle) const noexcept;
  [[nodiscard]] Socket *select(IpFamily family, packet::Ipv4 destination_ipv4,
                               packet::Ipv6 destination_ipv6,
                               std::uint16_t destination_port,
                               std::uint64_t interface_id) noexcept;
  [[nodiscard]] UdpIngressStatus enqueue(
      Socket &socket, const UdpDatagramMetadata &metadata,
      std::span<const std::uint8_t> payload) noexcept;
  void release_datagram(std::uint16_t index) noexcept;
  [[nodiscard]] std::optional<std::uint16_t>
  ephemeral_port(IpFamily family, std::uint64_t interface_id,
                 packet::Ipv4 ipv4, packet::Ipv6 ipv6) noexcept;

  std::vector<Socket> sockets_;
  std::array<Datagram, device_catalog::udp_queued_datagrams_per_endpoint>
      datagrams_{};
  // The one-megabyte payload arena is heap-backed so constructing an endpoint
  // in a Wasm call frame cannot overflow the generated stack budget.
  std::vector<Block> blocks_;
  std::uint16_t free_datagram_head_{invalid_index};
  std::uint16_t free_block_head_{invalid_index};
  std::uint16_t free_blocks_{};
  std::uint16_t ephemeral_cursor_{device_catalog::udp_ephemeral_port_first};
};

} // namespace router::transport
