// Forwarding-owned endpoint IPv4 and ARP stack. It consumes encoded frames and
// returns encoded frames plus probe observations. It cannot inspect router FIB,
// router adjacencies, link queues or another endpoint's mutable state.

#pragma once

#include "router/endpoint_protocol.hpp"
#include "router/ipv4_path_mtu.hpp"
#include "router/ipv6_dad.hpp"
#include "router/ipv6_destination_cache.hpp"
#include "router/ipv6_host_autoconfiguration.hpp"
#include "router/ipv6_fragmentation.hpp"
#include "router/ipv6_neighbor_cache.hpp"
#include "router/ipv6_path_mtu.hpp"
#include "router/ipv6_source_selection.hpp"
#include "router/ikev2_udp_service.hpp"
#include "router/mld_listener.hpp"
#include "router/udp_transport.hpp"
#include "router/tcp_endpoint.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <memory>
#include <span>
#include <vector>

namespace router::network_detail {

struct EndpointFrames {
  // Result slots cover the largest release-valid Echo batch at the minimum
  // legal IPv4 MTU. The slots are references into the endpoint owner's
  // preallocated arena, not 9 KiB values copied through a pthread stack.
  // Callers must consume them synchronously before invoking that endpoint
  // again. This matches shard affinity: only the owning forwarding turn may
  // call the stack, and the link boundary copies every admitted frame.
  // The release command accepts a payload up to 1472 octets independently of
  // the project's host MTU. The endpoint must therefore retain every fragment
  // of the largest legal command at the smallest legal IPv4 MTU, rather than
  // sizing this queue from the much smaller default request.
  static constexpr std::size_t maximum_pending_fragments =
      maximum_endpoint_pending_ipv4_fragments;
  static constexpr std::size_t maximum_result_frames =
      maximum_pending_fragments + 1U >
              device_catalog::host_ipv6_work_budget_actions
          ? maximum_pending_fragments + 1U
          : device_catalog::host_ipv6_work_budget_actions;
  struct FrameReference {
    const packet::Frame *value{};

    // Implicit read-only conversion preserves the existing packet-codec call
    // shape while making it impossible for consumers to mutate owner storage.
    operator const packet::Frame &() const noexcept { return *value; }
  };
  std::array<FrameReference, maximum_result_frames> frames{};
  // Internal writable storage is carried only so allocation-free helpers can
  // publish the referenced values. Consumers use `frames` and `count` only.
  std::span<packet::Frame> storage{};
  std::uint8_t count{};
  bool start_echo_clock{};
  bool echo_reply{};
  // The IPv4 header belongs to the received Echo Reply, so forwarding records
  // its actual remaining TTL rather than substituting the endpoint default.
  // It is meaningful only when echo_reply is true.
  std::uint8_t echo_reply_ttl{};
  bool ttl_expired{};
  bool mtu_exceeded{};
};

enum class EndpointUdpSendStatus : std::uint8_t {
  sent,
  link_down,
  invalid_socket,
  invalid_destination,
  no_source_address,
  no_route,
  neighbor_resolution_started,
  neighbor_resolution_pending,
  resource_exhausted,
  message_too_large,
  output_backpressure
};

struct EndpointUdpSendResult {
  EndpointUdpSendStatus status{EndpointUdpSendStatus::invalid_socket};
  std::size_t emitted_frames{};
};

enum class EndpointTcpSendStatus : std::uint8_t {
  sent,
  state_changed,
  no_action,
  link_down,
  invalid_socket,
  invalid_destination,
  no_source_address,
  no_route,
  neighbor_resolution_started,
  neighbor_resolution_pending,
  resource_exhausted,
  output_backpressure,
  transport_error
};

struct EndpointTcpSendResult {
  EndpointTcpSendStatus status{EndpointTcpSendStatus::invalid_socket};
  std::optional<transport::tcp::EndpointSocketHandle> socket;
  // A prepared TCP segment always fits one path-MTU-sized IP packet. Keeping
  // one frame here avoids nesting the large maintenance batch on the Wasm
  // stack for every send or timer operation.
  packet::Frame frame;
  bool emitted{};
};

class EndpointStack final {
public:
  using Clock = std::chrono::steady_clock;
  // One scratch byte image holds either a complete ordinary IPv4 or IPv6
  // datagram. It is reused synchronously by this endpoint owner and is never
  // retained by the link or exposed through a checkpoint.
  static constexpr std::size_t outbound_scratch_allocation_bytes =
      packet::maximum_ethernet_ipv6_datagram_octets;

  EndpointStack();
  // configure replaces endpoint identity and clears neighbors when values
  // change. The configuration value is copied and may be discarded by caller.
  [[nodiscard]] bool
  configure(const NetworkEndpointConfiguration &configuration) noexcept;
  // begin_echo either emits ARP or ICMP and retains the complete bounded
  // fragment generation while address resolution is pending. Returned frame
  // references remain valid only until the next call on this endpoint owner.
  [[nodiscard]] EndpointFrames begin_echo(packet::Ipv4 destination,
                                          std::uint16_t sequence,
                                          std::size_t payload_octets =
                                              device_catalog::default_ping_payload_octets,
                                          bool dont_fragment = false,
                                          Clock::time_point now =
                                              Clock::now()) noexcept;
  // receive parses encoded Ethernet. Malformed or unrelated packets produce an
  // empty result and cannot mutate another endpoint or the router adjacency.
  [[nodiscard]] EndpointFrames receive(const packet::Frame &frame,
                                       std::uint16_t expected_sequence,
                                       bool probe_source,
                                       Clock::time_point now = Clock::now()) noexcept;
  // Endpoint-owner maintenance expires both IP families and emits protocol
  // packets only when their link preconditions hold. Returned frames still
  // cross NetworkPlane's forwarding-to-fabric ring.
  [[nodiscard]] EndpointFrames
  service_maintenance(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point>
  next_maintenance_deadline() const noexcept;
  void set_link_state(bool operational,
                      Clock::time_point now = Clock::now()) noexcept;
  // Link loss clears only this endpoint's learned router neighbor.
  void clear_neighbor() noexcept;
  // Checkpoint restore installs a previously validated exact protocol address.
  void restore_router_neighbor(packet::Ipv4 address, packet::Mac mac) noexcept;
  // Structural checkpoint methods run only on forwarding. They persist local
  // protocol values and encoded frames, never references into another owner.
  void checkpoint(NetworkCheckpointState &state,
                  Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(
      const NetworkCheckpointState &state,
      Clock::time_point now = Clock::now()) noexcept;

  // Identity accessors expose immutable values copied during configure.
  [[nodiscard]] packet::Ipv4 address() const noexcept { return address_; }
  [[nodiscard]] packet::Mac mac() const noexcept { return mac_; }
  [[nodiscard]] std::uint8_t prefix_length() const noexcept {
    return prefix_length_;
  }
  [[nodiscard]] packet::Ipv4 gateway() const noexcept { return gateway_; }
  // The DHCPv4 client owner installs and removes only its acquired address.
  // Project static configuration uses configure and cannot be overwritten by
  // this API unless the endpoint was explicitly created for dynamic IPv4.
  [[nodiscard]] bool install_dhcpv4_lease(packet::Ipv4 address,
                                          std::uint8_t prefix_length,
                                          packet::Ipv4 gateway) noexcept;
  // Restore may reclaim an already restored address only when every identity
  // field matches the validated client lease. Live acquisition continues to
  // use install_dhcpv4_lease and cannot take over a static address.
  [[nodiscard]] bool restore_dhcpv4_lease_ownership(
      packet::Ipv4 address, std::uint8_t prefix_length,
      packet::Ipv4 gateway) noexcept;
  void remove_dhcpv4_lease() noexcept;
  // RFC 5227 probing is armed by the DHCP owner before it emits any ARP
  // Probe. The endpoint observes every ARP frame on the local link because
  // only this forwarding owner can compare encoded traffic with its own MAC.
  [[nodiscard]] bool
  arm_dhcpv4_address_probe(packet::Ipv4 candidate) noexcept;
  void disarm_dhcpv4_address_probe() noexcept;
  [[nodiscard]] bool dhcpv4_address_conflict() const noexcept {
    return dhcpv4_probe_conflict_;
  }
  // One call emits exactly one RFC 5227 ARP Probe with sender IP 0.0.0.0.
  // Timing and retry count remain owned by Dhcpv4EndpointService.
  [[nodiscard]] bool send_dhcpv4_address_probe(
      void *sink_context, packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission = nullptr) noexcept;
  [[nodiscard]] std::uint16_t mtu() const noexcept { return mtu_; }
  [[nodiscard]] bool ipv6_enabled() const noexcept { return ipv6_enabled_; }
  [[nodiscard]] std::uint64_t interface_id() const noexcept {
    return interface_id_;
  }
  [[nodiscard]] packet::Ipv6 ipv6_link_local() const noexcept {
    return ipv6_link_local_;
  }
  [[nodiscard]] const host::Ipv6HostAutoconfiguration &
  ipv6_autoconfiguration() const noexcept {
    return ipv6_autoconfiguration_;
  }
  [[nodiscard]] std::optional<transport::UdpSocketHandle>
  bind_udp(const transport::UdpBinding &binding) noexcept {
    return udp_.bind(binding);
  }
  [[nodiscard]] bool close_udp(transport::UdpSocketHandle handle) noexcept {
    return udp_.close(handle);
  }
  [[nodiscard]] bool valid_udp(transport::UdpSocketHandle handle) const noexcept {
    return udp_.local_binding(handle).has_value();
  }
  // Multicast reception is a separate IPv6 interface operation, not a side
  // effect of UDP bind. DHCPv6 servers join ff02::1:2 through this API so the
  // Ethernet filter and MLD owner observe the same intent.
  [[nodiscard]] bool join_ipv6_multicast(
      const packet::Ipv6 &group,
      Clock::time_point now = Clock::now()) noexcept {
    return ipv6_enabled_ && mld_listener_.join(group, now);
  }
  [[nodiscard]] bool leave_ipv6_multicast(
      const packet::Ipv6 &group,
      Clock::time_point now = Clock::now()) noexcept {
    return ipv6_enabled_ && mld_listener_.leave(group, now);
  }
  [[nodiscard]] transport::UdpReceiveResult
  receive_udp(transport::UdpSocketHandle handle,
              std::span<std::uint8_t> output) noexcept {
    return udp_.receive(handle, output);
  }
  // Applications consume the fixed advisory slot explicitly, matching the
  // read-and-clear semantics of SO_ERROR without exposing transport internals.
  [[nodiscard]] std::optional<transport::Ipv6NetworkError>
  take_udp_network_error(transport::UdpSocketHandle handle) noexcept {
    return udp_.take_network_error(handle);
  }
  [[nodiscard]] bool configure_ike_udp() noexcept {
    return ike_udp_.configure(udp_);
  }
  void remove_ike_udp() noexcept { ike_udp_.remove(udp_); }
  [[nodiscard]] ikev2::UdpServiceResult service_ike_udp(
      void *context, ikev2::UdpInboundHandler handler) noexcept {
    return ike_udp_.service_one(udp_, context, handler);
  }
  [[nodiscard]] std::optional<transport::UdpSocketHandle>
  ike_udp_socket(transport::IpFamily family,
                 bool encapsulated) const noexcept {
    return ike_udp_.socket(family, encapsulated);
  }
  [[nodiscard]] EndpointUdpSendResult send_udp_ipv6(
      transport::UdpSocketHandle handle, packet::Ipv6 destination,
      std::uint16_t destination_port, std::span<const std::uint8_t> payload,
      void *sink_context, packet::Ipv6FragmentSink sink,
      Clock::time_point now = Clock::now(),
      packet::Ipv6FragmentAdmission admission = nullptr) noexcept;
  // IPv4 UDP uses the same application payload domain as RFC 768 permits for
  // IPv4, then performs host routing, ARP and source fragmentation. The sink
  // receives only encoded Frames and must belong to this endpoint's egress.
  [[nodiscard]] EndpointUdpSendResult send_udp_ipv4(
      transport::UdpSocketHandle handle, packet::Ipv4 destination,
      std::uint16_t destination_port, std::span<const std::uint8_t> payload,
      void *sink_context, packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission = nullptr,
      bool checksum_enabled = true) noexcept;
  // DHCPv4 servers may deliver OFFER and ACK directly to chaddr before the
  // client can answer ARP. The caller must supply the received client MAC and
  // this method still emits a normal encoded IPv4 and UDP frame through the
  // same admission and fragment path.
  [[nodiscard]] EndpointUdpSendResult send_udp_ipv4_direct_l2(
      transport::UdpSocketHandle handle, packet::Ipv4 destination,
      packet::Mac destination_mac, std::uint16_t destination_port,
      std::span<const std::uint8_t> payload, void *sink_context,
      packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission = nullptr,
      bool checksum_enabled = true) noexcept;
  [[nodiscard]] std::optional<transport::tcp::EndpointSocketHandle>
  listen_tcp(const transport::tcp::EndpointBinding &binding,
             std::size_t backlog =
                 device_catalog::tcp_listen_backlog_default,
             transport::tcp::SocketResources resources = {}) noexcept {
    return tcp_ ? tcp_->listen(binding, backlog, resources) : std::nullopt;
  }
  [[nodiscard]] std::optional<transport::tcp::EndpointSocketHandle>
  accept_tcp(transport::tcp::EndpointSocketHandle listener) noexcept {
    return tcp_ ? tcp_->accept(listener) : std::nullopt;
  }
  [[nodiscard]] std::size_t
  write_tcp(transport::tcp::EndpointSocketHandle socket,
            std::span<const std::uint8_t> bytes,
            Clock::time_point now = Clock::now()) noexcept {
    return tcp_ ? tcp_->write(socket, bytes, now) : 0U;
  }
  [[nodiscard]] std::size_t
  read_tcp(transport::tcp::EndpointSocketHandle socket,
           std::span<std::uint8_t> output,
           Clock::time_point now = Clock::now()) noexcept {
    return tcp_ ? tcp_->read(socket, output, now) : 0U;
  }
  [[nodiscard]] std::optional<transport::tcp::State>
  tcp_state(transport::tcp::EndpointSocketHandle socket) const noexcept {
    return tcp_ ? tcp_->state(socket) : std::nullopt;
  }
  [[nodiscard]] bool
  valid_tcp(transport::tcp::EndpointSocketHandle socket) const noexcept {
    // Listeners intentionally have no connection state, so validity must use
    // the generation-checked local binding rather than tcp_state().
    return tcp_ && tcp_->local_binding(socket).has_value();
  }
  [[nodiscard]] std::optional<transport::Ipv6NetworkError>
  take_tcp_network_error(
      transport::tcp::EndpointSocketHandle socket) noexcept {
    return tcp_ ? tcp_->take_network_error(socket) : std::nullopt;
  }
  [[nodiscard]] EndpointTcpSendResult connect_tcp(
      transport::tcp::EndpointBinding binding,
      transport::tcp::EndpointRemote remote,
      transport::tcp::SocketResources resources = {},
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointTcpSendResult send_tcp(
      transport::tcp::EndpointSocketHandle socket, bool pushed = true,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] EndpointTcpSendResult close_tcp(
      transport::tcp::EndpointSocketHandle socket,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool destroy_tcp(
      transport::tcp::EndpointSocketHandle socket) noexcept {
    // Listener teardown and whole-service destruction have no peer tuple from
    // which close_tcp could construct FIN. TcpEndpoint::close invalidates the
    // generation and releases accepted children atomically. Ordinary connected
    // application shutdown must continue to use close_tcp and encoded FIN.
    return tcp_ && tcp_->close(socket);
  }

private:
  struct FrameArena {
    // Output is overwritten at the start of each synchronous owner call.
    // Pending is independent because an ARP reply must copy and rewrite a
    // retained generation into output without destroying checkpoint state
    // before the complete batch has been published.
    std::array<packet::Frame, EndpointFrames::maximum_result_frames> output{};
    std::array<packet::Frame, EndpointFrames::maximum_pending_fragments>
        pending{};
    // Only a DF datagram can elicit the RFC 1191 signal. One endpoint exposes
    // one active CLI probe owner, so retaining its exact packet is sufficient
    // and avoids a second maximum-fragment arena per host.
    packet::Frame ipv4_probe{};
  };

  [[nodiscard]] EndpointFrames make_frame_result() noexcept;
  [[nodiscard]] EndpointUdpSendResult encode_udp_ipv4_to_mac(
      transport::UdpSocketHandle handle, packet::Ipv4 source,
      packet::Ipv4 destination, packet::Mac destination_mac,
      std::uint16_t destination_port, std::span<const std::uint8_t> payload,
      void *sink_context, packet::Ipv4FragmentSink sink,
      packet::Ipv4FragmentAdmission admission,
      bool checksum_enabled) noexcept;
  // A host node currently owns one Ethernet attachment. Naming its local DAD
  // coordinate avoids scattering a numeric sentinel and makes a future
  // multi-interface host change local to this owner contract.
  static constexpr std::uint16_t ethernet_port_ordinal = 0U;
  packet::Mac mac_{};
  packet::Ipv4 address_{};
  // Zero is deliberately unusable until configure installs the project prefix.
  // A protocol-specific /30 default here would make an unconfigured endpoint
  // appear valid and couple the reusable stack to the first sample topology.
  std::uint8_t prefix_length_{};
  packet::Ipv4 gateway_{};
  std::uint16_t mtu_{device_catalog::default_host_ipv4_mtu};
  std::uint64_t interface_id_{};
  packet::Ipv6 ipv6_link_local_{};
  host::Ipv6InterfaceIdentifierConfiguration ipv6_identifier_{};
  // Only the forwarding-owned endpoint mutates this RFC 7217 tuple member.
  // Link flaps preserve it, while configure creates a new identity generation
  // and resets it. The generated retry bound prevents an unbounded collision
  // loop from monopolizing the shard.
  std::uint32_t ipv6_link_local_dad_counter_{};
  bool ipv6_link_local_generation_exhausted_{};
  host::Ipv6HostAutoconfiguration ipv6_autoconfiguration_{};
  lab::Ipv6DadTable ipv6_dad_{};
  // The host owns its own Neighbor and Destination caches. They are not
  // aliases of the attached router's tables: every mapping must be learned
  // from an encoded RA, NS, NA or Redirect received through this endpoint.
  lab::Ipv6NeighborCache ipv6_neighbors_{};
  lab::Ipv6DestinationCache ipv6_destinations_{};
  ip::Ipv6PathMtuCache ipv6_path_mtu_{};
  ip::Ipv4PathMtuCache ipv4_path_mtu_{};
  // Fragment state and UDP queues terminate at this host owner. Router transit
  // forwarding never touches them and every accepted byte first crossed the
  // fabric as a Frame.
  packet::Ipv4ReassemblyTable ipv4_reassembly_{};
  packet::Ipv6ReassemblyTable ipv6_reassembly_{};
  transport::UdpEndpoint udp_{};
  // IKE socket handles borrow only this endpoint's UDP owner. Checkpoint
  // validation couples their generations to the serialized socket table.
  ikev2::UdpService ike_udp_{};
  // TCP allocates socket arenas lazily. The unique owner permits configure to
  // stage a new entropy domain and publish it only after validation succeeds.
  std::unique_ptr<transport::tcp::TcpEndpoint> tcp_;
  std::vector<std::uint8_t> ip_datagram_scratch_;
  std::uint16_t next_ipv4_identification_{1U};
  // Identification is scoped to this source endpoint. A monotonically
  // increasing 32-bit value satisfies RFC 8200's recent-datagram uniqueness
  // requirement and survives checkpoint restore so reuse cannot occur merely
  // because a project was reloaded.
  std::uint32_t next_ipv6_fragment_identification_{1U};
  // MLD owns multicast reception state and report timers. The Ethernet receive
  // filter asks this owner instead of reconstructing memberships from address
  // repositories, which also permits future UDP sockets to join real groups.
  lab::MldListener mld_listener_{};
  std::array<packet::Ipv6,
             device_catalog::ipv6_slaac_addresses_per_host_interface + 1U>
      mld_system_groups_{};
  std::uint8_t mld_system_group_count_{};
  Clock::time_point router_solicitation_deadline_{Clock::time_point::max()};
  std::uint8_t router_solicitations_sent_{};
  bool ipv6_enabled_{};
  bool link_operational_{};
  bool router_solicitation_active_{};
  bool dhcpv4_address_owned_{};
  packet::Ipv4 dhcpv4_probe_candidate_{};
  bool dhcpv4_probe_conflict_{};
  std::optional<packet::Ipv4> neighbor_address_;
  std::optional<packet::Mac> neighbor_mac_;
  // Allocated once with the endpoint, never on a packet turn. The unique owner
  // keeps large frame storage out of the WebAssembly stack and outside shared
  // mutable memory while retaining deterministic bounds.
  std::unique_ptr<FrameArena> frame_arena_;
  std::uint8_t pending_count_{};
  std::optional<packet::Ipv4> pending_next_hop_;
  packet::Ipv4 ipv4_probe_destination_{};
  bool ipv4_probe_valid_{};
  [[nodiscard]] packet::Ipv6
  derive_ipv6_link_local(std::uint32_t dad_counter) const noexcept;
  void schedule_slaac_dad(Clock::time_point now) noexcept;
  void synchronize_mld_memberships(Clock::time_point now) noexcept;
  // Ordinary RFC 4861 next-hop determination runs before applying Redirect
  // advice. On-link prefixes return the destination; otherwise the best live
  // Default Router preference is selected deterministically for this owner.
  [[nodiscard]] std::optional<packet::Ipv6>
  route_first_hop(const packet::Ipv6 &destination,
                  Clock::time_point now) const noexcept;
  // Drains fixed-timeout IPv4 reassembly entries and appends the RFC 1122
  // code-one errors for entries that had received fragment zero.
  void expire_ipv4_reassembly(EndpointFrames &result,
                              Clock::time_point now) noexcept;
  [[nodiscard]] EndpointTcpSendResult prepare_tcp_output(
      transport::tcp::EndpointPrepareResult prepared,
      transport::tcp::EndpointBinding binding,
      transport::tcp::EndpointRemote remote,
      Clock::time_point now) noexcept;
};

} // namespace router::network_detail
