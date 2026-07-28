// Forwarding-shard dual-stack pipeline for one router. It owns installed FIBs,
// port projections, ARP and ND state, unresolved-frame storage and forwarding
// counters. Every egress result remains an encoded Ethernet frame.

#pragma once

#include "router/dhcpv4_failover.hpp"
#include "router/dhcpv4_relay.hpp"
#include "router/dhcpv4_leasequery.hpp"
#include "router/dhcpv4_server.hpp"
#include "router/dhcpv6_failover.hpp"
#include "router/dhcpv6_relay.hpp"
#include "router/dhcpv6_relay_lease.hpp"
#include "router/dhcpv6_relay_route.hpp"
#include "router/dhcpv6_server.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/icmpv4_statistics.hpp"
#include "router/icmpv6_statistics.hpp"
#include "router/ikev2_udp_service.hpp"
#include "router/interface_identity.hpp"
#include "router/ipv4_path_mtu.hpp"
#include "router/ipv4_reassembly.hpp"
#include "router/ipv6_dad.hpp"
#include "router/ipv6_fragmentation.hpp"
#include "router/ipv6_neighbor_cache.hpp"
#include "router/ipv6_path_mtu.hpp"
#include "router/ipv6_router_advertisement.hpp"
#include "router/mld_router.hpp"
#include "router/mld_import_policy.hpp"
#include "router/multi_device_routing.hpp"
#include "router/neighbor_discovery_packet.hpp"
#include "router/packet.hpp"
#include "router/ospf_packet.hpp"
#include "router/router_ipv6_address_table.hpp"
#include "router/sap_forwarding.hpp"
#include "router/tcp_endpoint.hpp"
#include "router/udp_transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::lab {

enum class ForwardDrop : std::uint8_t {
  none,
  malformed,
  not_for_router,
  no_route,
  port_down,
  arp_pending_full,
  neighbor_pending_full,
  neighbor_unreachable,
  egress_queue_full,
  reassembly_full,
  mtu_exceeded,
  // RFC 2644 makes receipt and forwarding of a network-directed broadcast a
  // disabled policy by default. Keeping that outcome distinct from malformed
  // input prevents operational counters from blaming valid wire bytes.
  directed_broadcast_disabled,
  mld_resource_full,
  udp_queue_full,
  dhcpv6_lease_limit,
  dhcpv6_lease_state_full,
  blackhole,
  transit_disabled
};

struct ForwardPort {
  bool configured{};
  bool operational{};
  std::uint16_t ordinal{};
  std::uint16_t mtu{device_catalog::default_network_mtu};
  std::uint32_t address{};
  std::uint32_t network{};
  std::uint32_t speed_mbps{};
  std::uint8_t prefix_length{};
  packet::Mac mac{};
  // ARP timers are effective per-interface control projections. The
  // forwarding owner consumes them without consulting CLI or candidate state.
  std::uint32_t arp_timeout_seconds{
      static_cast<std::uint32_t>(device_catalog::dynamic_arp_timeout.count())};
  std::uint16_t arp_retry_deciseconds{
      device_catalog::dynamic_arp_retry_deciseconds};
  // IPv4 Redirect generation is enabled by default on an SR OS router
  // interface and has its own fixed-window rate limiter. These are effective
  // values projected by the control owner, not hardcoded packet-path policy.
  std::uint16_t icmp_redirect_maximum{
      device_catalog::icmp_redirect_default_maximum};
  std::uint16_t icmp_redirect_interval_seconds{static_cast<std::uint16_t>(
      device_catalog::icmp_redirect_default_interval.count())};
  bool icmp_redirects_enabled{true};
  // IPv6 state is projected from the same routed interface. Link-local is
  // stored separately because it has a distinct prefix and source-selection
  // role while still sharing the physical port and MAC.
  bool ipv6_configured{};
  packet::Ipv6 ipv6_address{};
  packet::Ipv6 ipv6_network{};
  packet::Ipv6 ipv6_link_local{};
  std::uint8_t ipv6_prefix_length{};
  std::uint32_t nd_reachable_time_milliseconds{static_cast<std::uint32_t>(
      device_catalog::nd_base_reachable_time.count())};
  std::uint32_t nd_stale_time_seconds{
      device_catalog::nd_default_stale_time_seconds};
  Ipv6UnsolicitedLearning ipv6_unsolicited_learning{
      Ipv6UnsolicitedLearning::none};
  Ipv6UnsolicitedLearning ipv6_proactive_refresh{Ipv6UnsolicitedLearning::none};
  // Absence is distinct from a configured zero. Zero disables all new
  // dynamic learning, while an absent limit permits entries up to the selected
  // hardware resource profile. log-only records the threshold without
  // enforcing admission, as documented by SR OS.
  std::uint32_t ipv6_neighbor_limit{};
  std::uint8_t ipv6_neighbor_limit_threshold_percent{
      device_catalog::nd_default_neighbor_limit_threshold_percent};
  bool ipv6_neighbor_limit_configured{};
  bool ipv6_neighbor_limit_log_only{};
  // SR OS enables ICMPv6 Redirect generation with a release-defined rate on
  // an IPv6 router interface. The values travel with the control projection,
  // while the forwarding owner keeps the mutable rate window separately.
  std::uint16_t icmp6_redirect_maximum{
      device_catalog::icmp6_redirect_default_maximum};
  std::uint16_t icmp6_redirect_interval_seconds{static_cast<std::uint16_t>(
      device_catalog::icmp6_redirect_default_interval.count())};
  bool icmp6_redirects_enabled{true};
  // Existing aggregate callers model IPv4 interfaces and therefore retain a
  // true default. IPv6-only control projections set this false explicitly so
  // ARP and local IPv4 delivery cannot activate from an all-zero address.
  bool ipv4_configured{true};
};

struct ForwarderAdjacencyCheckpoint {
  // Relative lifetime is clamped at zero during export. Restore anchors it to
  // the destination worker's current steady clock and never persists epochs.
  std::uint16_t port_ordinal{};
  std::uint32_t address{};
  packet::Mac mac{};
  std::int64_t remaining_nanoseconds{};
  // Disabled aging is not represented as an infinite serialized duration.
  // The explicit bit keeps the checkpoint independent of steady-clock epochs.
  bool aging_disabled{};
  // A configured static entry and a dynamic entry with ARP aging disabled
  // both have an infinite lifetime, but operational commands and clear
  // semantics must distinguish their provenance after restore.
  bool configured_static{};
};

struct ForwarderPendingCheckpoint {
  // Pending packets retain exact encoded bytes and whether TTL processing has
  // already begun. No PacketPool handle crosses the checkpoint boundary.
  bool transit{};
  bool ipv6{};
  std::uint64_t interface_id{};
  std::uint16_t port_ordinal{};
  std::uint32_t next_hop{};
  packet::Ipv6 next_hop_ipv6{};
  packet::Frame frame{};
  // Non-zero only for one locally originated RFC 8201 experiment. Persisting
  // it keeps an ND-delayed probe distinct from ordinary traffic after restore.
  std::uint32_t ipv6_source_mtu{};
  // IPv4 unresolved frames share one retry deadline per exact adjacency.
  // IPv6 uses NUD-owned timers and therefore stores zero in this field.
  std::int64_t arp_retry_remaining_nanoseconds{};
};

struct RouterMldInterfaceCheckpoint {
  // Intent remains present while DAD or carrier keeps the protocol stopped.
  // The nested protocol image is meaningful only when running is true.
  MldRouterConfiguration intent{};
  MldRouterCheckpoint protocol{};
  // This is the effective rule set after interface-level override resolution.
  // Candidate-only staging is never checkpointed because a control command is
  // acknowledged only after commit or abort completes on this owner.
  std::vector<MldSsmTranslation> ssm_translations;
  mld::ImportPolicyCheckpoint import_policy;
  bool running{};
};

struct Ipv6RedirectLimiterCheckpoint {
  // The active fixed window uses a relative remaining duration because a
  // steady_clock epoch cannot cross a process or browser reload boundary.
  std::uint16_t port_ordinal{};
  std::uint16_t sent{};
  std::int64_t remaining_nanoseconds{};
};

struct Ipv4RedirectLimiterCheckpoint {
  // The limiter is forwarding-owned and uses one window per physical ingress
  // interface. Relative duration makes restore independent of clock epochs.
  std::uint16_t port_ordinal{};
  std::uint16_t sent{};
  std::int64_t remaining_nanoseconds{};
};

struct Ipv6ReachableTimeCheckpoint {
  // RFC 4861 ReachableTime is an interface variable, not a fresh sample for
  // every neighbor. The forwarding owner persists both its PRNG continuation
  // and its refresh deadline so restore cannot synchronize all interfaces.
  std::uint16_t port_ordinal{};
  std::uint32_t base_milliseconds{};
  std::uint32_t effective_milliseconds{};
  std::uint64_t random_state{};
  std::int64_t remaining_refresh_nanoseconds{};
};

struct Icmpv4InterfaceStatisticsCheckpoint {
  // Only configured physical ports are serialized. The stable ordinal binds
  // the counter set to hardware inventory without persisting a native pointer
  // or allocating the profile maximum for a sparsely equipped chassis.
  std::uint16_t port_ordinal{};
  Icmpv4Statistics statistics{};
};

struct Icmpv6InterfaceStatisticsCheckpoint {
  // Ordinal binds the value to generated physical inventory. The checkpoint
  // vector contains configured ports only, avoiding an 800-entry value on the
  // Wasm stack for a router that may have only two live interfaces.
  std::uint16_t port_ordinal{};
  Icmpv6Statistics statistics{};
  // SR OS `show router rtr-advertisement` reports the elapsed time since the
  // last transmitted RA, NS and NA. Negative means that the interface has not
  // transmitted that message since the counters were created or cleared.
  // Relative durations are portable across steady-clock epochs.
  std::int64_t router_advertisement_last_sent_ago_nanoseconds{-1};
  std::int64_t neighbor_solicitation_last_sent_ago_nanoseconds{-1};
  std::int64_t neighbor_advertisement_last_sent_ago_nanoseconds{-1};
};

struct InterfaceTrafficStatistics {
  // The router forwarding shard is the sole writer. Packet and octet counters
  // advance only after an operational ingress accepts a wire frame or an
  // egress sink accepts it into the physical link queue. This keeps rejected
  // queue admissions out of transmitted traffic while preserving them in the
  // router drop counters.
  std::uint64_t ingress_packets{};
  std::uint64_t ingress_octets{};
  std::uint64_t egress_packets{};
  std::uint64_t egress_octets{};
};

struct RouterForwarderCheckpoint {
  // A dedicated multihomed server uses this owner for shared local routes and
  // sockets while keeping host forwarding disabled. Router instances retain
  // the default enabled value.
  bool transit_forwarding_enabled{true};
  std::vector<ForwardPort> ports;
  // Native addresses are independent children of a routed interface. Keeping
  // the complete generation separate from the selected-primary port cache is
  // required for secondary-address DAD and exact checkpoint continuation.
  std::vector<RouterIpv6Address> native_ipv6_addresses;
  // SAP attachments are forwarding state, not editor state. Checkpointing the
  // published generation preserves exact physical tag classification and the
  // stable logical interface identities used by upper-layer state.
  std::vector<service::SapAttachment> sap_attachments;
  std::vector<service::ServiceIpv6Interface> service_ipv6_interfaces;
  routing::FibProgram fib{};
  routing::Ipv6FibProgram ipv6_fib{};
  // Route age is an operational duration, not a wall-clock timestamp. The
  // forwarding owner records installation time per selected path and exports
  // elapsed whole seconds so checkpoint restore remains independent of the
  // host steady-clock epoch.
  std::vector<std::uint32_t> ipv4_route_ages_seconds;
  std::vector<std::uint32_t> ipv6_route_ages_seconds;
  std::vector<ForwarderAdjacencyCheckpoint> adjacencies;
  std::vector<Ipv6NeighborCheckpoint> ipv6_neighbors;
  std::vector<Ipv6DadCheckpoint> ipv6_dad;
  std::vector<Ipv6RouterAdvertisementCheckpoint> ipv6_router_advertisements;
  std::vector<ip::Ipv6PathMtuCheckpoint> ipv6_path_mtu;
  std::vector<ip::Ipv4PathMtuCheckpoint> ipv4_path_mtu;
  // A router is an IPv4 destination for its own interface addresses. Its
  // reassembly state is independent from every host endpoint and from transit
  // fragments, which are never inserted here.
  std::vector<packet::Ipv4ReassemblyCheckpoint> ipv4_reassembly;
  std::vector<packet::Ipv6ReassemblyCheckpoint> ipv6_reassembly;
  std::vector<RouterMldInterfaceCheckpoint> mld_interfaces;
  std::vector<Ipv6RedirectLimiterCheckpoint> ipv6_redirect_limiters;
  std::vector<Ipv4RedirectLimiterCheckpoint> ipv4_redirect_limiters;
  std::vector<Ipv6ReachableTimeCheckpoint> ipv6_reachable_times;
  // Router-local UDP belongs to this forwarding owner. Relay configuration is
  // stateless protocol intent, while queued datagrams and socket generations
  // are transport state and must be restored together.
  transport::UdpEndpointCheckpoint udp{};
  // Router-local TCP terminates only configured control-plane services. The
  // endpoint checkpoint retains TCP sequence, retransmission and receive
  // queues, while each application session below retains framing progress.
  std::optional<transport::tcp::EndpointCheckpoint> tcp;
  std::optional<transport::tcp::EndpointSocketHandle>
      dhcpv4_leasequery_listener;
  struct Dhcpv4LeasequerySession {
    transport::tcp::EndpointSocketHandle socket{};
    dhcpv4::leasequery::StreamDecoderCheckpoint decoder{};
    std::optional<dhcpv4::leasequery::RequestView> request;
    packet::Ipv4 local{};
    packet::Ipv4 remote{};
    std::string server_name;
    std::size_t lease_cursor{};
    std::size_t pool_cursor{};
    std::uint32_t address_cursor{};
    std::uint64_t revision_cursor{};
    std::uint64_t scan_revision_target{};
    std::int64_t data_remaining_nanoseconds{};
    std::int64_t keepalive_remaining_nanoseconds{};
    bool first_reply{true};
    bool catch_up_complete{};
    bool done{};
  };
  std::vector<Dhcpv4LeasequerySession> dhcpv4_leasequery_sessions;
  ikev2::UdpServiceCheckpoint ike_udp{};
  std::vector<dhcpv4::RelayInterfaceConfiguration> dhcpv4_relay_interfaces;
  struct Dhcpv4Server {
    // The list key is management identity. Protocol state remains the
    // server-owned checkpoint and contains no CLI path or presentation data.
    std::string name;
    dhcpv4::ServerCheckpoint protocol;
  };
  std::vector<Dhcpv4Server> dhcpv4_servers;
  struct Dhcpv6Server {
    // The Base list name is management identity only. The protocol checkpoint
    // owns configuration, pools, bindings and relative lease deadlines.
    std::string name;
    dhcpv6::ServerCheckpoint protocol;
  };
  std::vector<Dhcpv6Server> dhcpv6_servers;
  std::optional<transport::UdpSocketHandle> dhcpv4_relay_socket;
  std::vector<dhcpv6::RelayInterfaceConfig> dhcpv6_relay_interfaces;
  std::vector<dhcpv6::RelayLeaseCheckpoint> dhcpv6_relay_leases;
  std::vector<dhcpv6::RelayRouteCheckpoint> dhcpv6_relay_routes;
  std::optional<transport::UdpSocketHandle> dhcpv6_relay_socket;
  // IPv4 and IPv6 keep independent global and per-interface counters because
  // SR OS exposes and clears the two protocols separately. Mutable dense arrays
  // remain in the forwarding owner; this portable form stores configured rows.
  Icmpv4Statistics icmpv4_global_statistics{};
  std::vector<Icmpv4InterfaceStatisticsCheckpoint> icmpv4_interface_statistics;
  Icmpv6Statistics icmpv6_global_statistics{};
  std::vector<Icmpv6InterfaceStatisticsCheckpoint> icmpv6_interface_statistics;
  std::vector<InterfaceTrafficStatistics> interface_traffic_statistics;
  // Packet Too Big is trusted only when its quote matches one of these exact
  // locally transmitted IP packets. Frames are bounded by one source packet's
  // RFC 8200 fragment batch and preserve no pointer into live packet storage.
  std::vector<packet::Frame> ipv6_probe_packets;
  packet::Frame ipv4_probe_packet{};
  std::vector<ForwarderPendingCheckpoint> pending;
  std::uint64_t forwarded_frames{};
  std::uint64_t dropped_frames{};
  ForwardDrop last_drop{ForwardDrop::none};
  std::uint16_t echo_reply_sequence{};
  bool echo_reply_valid{};
  // Echo RTT is captured by the forwarding owner at packet receipt. The
  // terminal may observe that result much later, so checkpointing both the
  // request age and completed RTT prevents UI polling latency from becoming
  // simulated wire latency after restore.
  packet::Ipv4 echo_request_destination{};
  std::uint64_t echo_request_age_nanoseconds{};
  std::uint64_t echo_reply_rtt_nanoseconds{};
  // The received IPv4 TTL is packet evidence, not a display default. Keeping
  // it beside the correlated reply lets a restored CLI operation render the
  // same SR OS detail line that it would have rendered before checkpointing.
  std::uint8_t echo_reply_ttl{};
  std::uint16_t echo_request_sequence{};
  bool echo_request_valid{};
  std::uint16_t ipv6_echo_reply_sequence{};
  bool ipv6_echo_reply_valid{};
  std::uint64_t ipv6_probe_age_nanoseconds{};
  std::uint64_t ipv6_echo_reply_rtt_nanoseconds{};
  // IPv6 reports the received Hop Limit in the same `ttl=` output field used
  // by SR OS. This value therefore comes from the decoded reply header.
  std::uint8_t ipv6_echo_reply_hop_limit{};
  std::uint32_t ipv6_echo_error_parameter{};
  std::uint16_t ipv6_echo_error_sequence{};
  std::uint8_t ipv6_echo_error_type{};
  std::uint8_t ipv6_echo_error_code{};
  bool ipv6_echo_error_valid{};
  packet::Ipv6 ipv6_probe_destination{};
  packet::Ipv4 ipv4_probe_destination{};
  std::uint32_t ipv6_fragment_identification{};
  std::uint64_t ipv6_probe_interface_id{};
  std::uint64_t ipv4_probe_interface_id{};
  std::uint16_t ipv6_probe_port_ordinal{};
  // The reply must match the exact active Echo generation, not merely its
  // source address. This field is persisted beside retained packet evidence.
  std::uint16_t ipv6_probe_sequence{};
  std::uint16_t ipv4_probe_port_ordinal{};
  std::uint16_t mld_service_cursor{};
  bool ipv6_probe_valid{};
  bool ipv4_probe_valid{};
};

struct Dhcpv4FailoverTransportConfiguration {
  // server_name selects the local Base lease repository. local and partner are
  // wire endpoints and are resolved by normal IPv4 routing, never by topology
  // graph inspection.
  std::string server_name;
  packet::Ipv4 local{};
  packet::Ipv4 partner{};
  dhcpv4::failover::Configuration relationship{};
  dhcpv4::failover::NegotiationParameters negotiation{};
  // Reopening a failed application relationship is a deployment policy, not
  // a TCP retransmission timer. Requiring it explicitly prevents the runtime
  // from inventing a vendor default and gives maintenance a finite deadline.
  std::chrono::seconds reconnect_delay{};
  // draft-ietf-dhc-failover-12 section 11.1 authenticates every application
  // message with HMAC-MD5 when a shared secret is configured. The relationship
  // owner retains the secret; it never enters packet telemetry or CLI output.
  std::vector<std::uint8_t> shared_secret;
  bool secured_transport{};
};

struct Dhcpv6FailoverTransportConfiguration {
  std::string server_name;
  packet::Ipv6 local{};
  packet::Ipv6 partner{};
  dhcpv6::failover::Configuration relationship{};
  std::uint16_t connect_flags{};
  std::chrono::seconds reconnect_delay{};
};

class RouterForwarder final {
public:
  using Clock = std::chrono::steady_clock;
  explicit RouterForwarder(crypto::Sha256Digest transport_secret = {},
                           Clock::time_point now = Clock::now()) noexcept;
  // Producer: this forwarding owner. Consumer: forwarding-to-link bounded
  // queue. false applies explicit tail drop without a direct delivery fallback.
  using EgressSink = bool (*)(void *context, std::uint16_t port_ordinal,
                              const packet::Frame &frame);
  // Producer: this forwarding owner. Consumer: the selected link egress ring.
  // The callback reserves no slots; it proves that one owner can publish the
  // complete source fragment batch without a partial-datagram tail drop.
  using EgressAdmission = bool (*)(void *context, std::uint16_t port_ordinal,
                                   std::size_t frames);
  using PuntObserver = void (*)(void *context, std::uint16_t ingress_port,
                                const packet::Frame &frame);

  [[nodiscard]] bool configure_port(const ForwardPort &port) noexcept;
  // OSPF multicast is local only on explicitly configured protocol
  // interfaces. Programming this bitset lets forwarding punt protocol 89
  // without parsing or borrowing the protocol datastore.
  [[nodiscard]] bool configure_ospf_punt(std::uint16_t port_ordinal,
                                         bool version_two,
                                         bool version_three) noexcept;
  // The OSPF shard returns a complete local Ethernet/IP image. Multicast is
  // emitted on the configured physical interface; unicast re-enters ordinary
  // FIB and neighbor resolution so no protocol daemon learns a peer MAC.
  [[nodiscard]] bool originate_ospf(
      std::uint16_t port_ordinal, const packet::Frame &frame, void *context,
      EgressSink sink, Clock::time_point now = Clock::now()) noexcept;
  // Producer: forwarding-shard command handler. Consumer: the same shard's
  // packet path. A complete generation is copied, validated and committed in
  // one owner turn; failure leaves address, DAD and port-primary state intact.
  [[nodiscard]] RouterIpv6AddressProgramStatus
  program_ipv6_addresses(std::span<const RouterIpv6Address> addresses,
                         Clock::time_point now = Clock::now()) noexcept;
  void remove_port(std::uint16_t ordinal) noexcept;
  [[nodiscard]] bool program_fib(const routing::FibProgram &program) noexcept;
  [[nodiscard]] bool
  program_ipv6_fib(const routing::Ipv6FibProgram &program) noexcept;
  // A complete generation is validated against currently configured physical
  // ports and then published atomically. Partial SAP programming is forbidden
  // because a packet turn must observe either the old or new service graph.
  [[nodiscard]] service::SapProgramStatus program_sap_generation(
      std::span<const service::SapAttachment> attachments,
      std::span<const service::ServiceIpv6Interface> interfaces = {}) noexcept;
  // Static neighbor configuration is installed only by this forwarding owner.
  // The caller resolves the textual interface to a physical ordinal, while
  // the cache retains the IPv6 and MAC wire values. A static entry bypasses
  // NUD and cannot be overwritten by received Neighbor Advertisements.
  [[nodiscard]] bool install_static_ipv6_neighbor(std::uint16_t port_ordinal,
                                                  const packet::Ipv6 &address,
                                                  packet::Mac mac) noexcept;
  [[nodiscard]] bool
  remove_static_ipv6_neighbor(std::uint16_t port_ordinal,
                              const packet::Ipv6 &address) noexcept;
  // Static IPv4 adjacency is owned by the forwarding shard. Installation
  // atomically replaces a dynamic mapping for the same interface and address;
  // removal never invents a dynamic replacement or emits an ARP frame.
  [[nodiscard]] bool install_static_ipv4_neighbor(std::uint16_t port_ordinal,
                                                  std::uint32_t address,
                                                  packet::Mac mac) noexcept;
  [[nodiscard]] bool
  remove_static_ipv4_neighbor(std::uint16_t port_ordinal,
                              std::uint32_t address) noexcept;
  // Dynamic IPv4 ARP cleanup is an owner-affine operational mutation. A
  // selector may constrain the physical interface, the protocol address, or
  // both. Configured state and unresolved packet queues are not deleted.
  [[nodiscard]] bool clear_dynamic_ipv4_neighbors(
      std::optional<std::uint16_t> port_ordinal = std::nullopt,
      std::optional<std::uint32_t> address = std::nullopt) noexcept;
  // Dynamic clear deliberately preserves configured entries. This mirrors
  // the management distinction between operational cache cleanup and deleting
  // persistent interface configuration.
  [[nodiscard]] bool clear_dynamic_ipv6_neighbors(
      std::optional<std::uint16_t> port_ordinal = std::nullopt,
      std::optional<packet::Ipv6> address = std::nullopt) noexcept;
  [[nodiscard]] bool configure_router_advertisement(
      std::uint16_t port_ordinal, bool enabled,
      const packet::nd::RouterAdvertisementConfig &config,
      Clock::time_point now = Clock::now()) noexcept;
  // Removing an IPv6 interface must erase the timer entry rather than merely
  // disable transmission. That distinction keeps checkpoints and later port
  // reuse free from stale configuration owned by the forwarding shard.
  [[nodiscard]] bool
  remove_router_advertisement(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool
  configure_mld_interface(const MldRouterConfiguration &configuration,
                          Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool remove_mld_interface(std::uint16_t port_ordinal) noexcept;
  // DHCPv4 relay is disabled until a complete interface policy is installed.
  // The forwarding owner validates giaddr uniqueness and binds one wildcard
  // UDP 67 socket only after the replacement generation is fully accepted.
  [[nodiscard]] bool configure_dhcpv4_relay(
      dhcpv4::RelayInterfaceConfiguration configuration) noexcept;
  [[nodiscard]] bool
  remove_dhcpv4_relay(std::uint64_t logical_interface_id) noexcept;
  // Base local servers and relays share UDP 67 on one routing instance. The
  // forwarding owner performs one wildcard demultiplex and dispatches the
  // complete wire payload to the matching protocol owner.
  [[nodiscard]] bool configure_dhcpv4_server(
      std::string name, const dhcpv4::ServerConfiguration &configuration,
      std::span<const dhcpv4::Pool> pools,
      std::span<const dhcpv4::Reservation> reservations,
      std::span<const dhcpv4::ExcludedRange> exclusions = {}) noexcept;
  [[nodiscard]] bool
  remove_dhcpv4_server(std::string_view name) noexcept;
  // Base DHCPv6 servers share the wildcard UDP 547 socket with relay agents.
  // A complete staged protocol instance replaces the named server atomically.
  [[nodiscard]] bool configure_dhcpv6_server(
      std::string name, const dhcpv6::ServerConfiguration &configuration,
      std::span<const dhcpv6::LeasePool> address_pools,
      std::span<const dhcpv6::LeasePool> prefix_pools,
      std::chrono::seconds decline_hold_time) noexcept;
  [[nodiscard]] bool
  remove_dhcpv6_server(std::string_view name) noexcept;
  // Failover configuration is an emulator capability, not Nokia MCS. These
  // methods install only local relationship intent. All partner information
  // subsequently crosses an encoded TCP/647 connection.
  [[nodiscard]] bool configure_dhcpv4_failover(
      Dhcpv4FailoverTransportConfiguration configuration,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  remove_dhcpv4_failover(std::string_view relationship_name) noexcept;
  // Administrative PARTNER-DOWN is a documented failover state transition,
  // not a direct mutation of the partner endpoint. The request is accepted
  // only while the relationship state machine permits it.
  [[nodiscard]] bool request_dhcpv4_failover_partner_down(
      std::string_view relationship_name,
      std::uint32_t absolute_now,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool configure_dhcpv6_failover(
      Dhcpv6FailoverTransportConfiguration configuration,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  remove_dhcpv6_failover(std::string_view relationship_name) noexcept;
  [[nodiscard]] bool request_dhcpv6_failover_partner_down(
      std::string_view relationship_name,
      std::uint32_t absolute_now,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  clear_dhcpv6_server_leases(
      std::string_view name, const dhcpv6::LeaseClearFilter &filter,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  clear_dhcpv6_server_statistics(std::string_view name) noexcept;
  // Operational mutations execute on the same forwarding owner as packet
  // processing. Clear never races an OFFER/ACK transition, and force-renew
  // emits through the ordinary UDP, IPv4, ARP and link queues.
  [[nodiscard]] bool
  clear_dhcpv4_server_statistics(std::string_view name) noexcept;
  [[nodiscard]] bool
  clear_dhcpv4_server_leases(
      std::string_view name, const dhcpv4::LeaseClearFilter &filter,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] dhcpv4::ForceRenewStatus send_dhcpv4_force_renew(
      std::string_view name, packet::Ipv4 address, void *context,
      EgressSink sink, EgressAdmission admission,
      Clock::time_point now = Clock::now()) noexcept;
  // A regular SR OS relay is projected from an IES or VPRN service interface.
  // The forwarding owner receives only resolved port identity and wire policy,
  // never CLI context objects or editor nodes.
  [[nodiscard]] dhcpv6::RelayConfigStatus
  configure_dhcpv6_relay(dhcpv6::RelayInterfaceConfig configuration) noexcept;
  [[nodiscard]] bool
  remove_dhcpv6_relay(std::uint64_t logical_interface_id) noexcept;
  // SR OS operational clear removes selected populated state and, unless the
  // caller requested no-dhcp-release or fewer than five minutes remain,
  // emits an RFC 9915 Release through ordinary IPv6 forwarding.
  [[nodiscard]] bool
  clear_dhcpv6_relay_leases(const dhcpv6::RelayLeaseClearFilter &filter,
                            bool no_dhcp_release, void *context,
                            EgressSink sink, EgressAdmission admission,
                            Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool configure_ike_udp() noexcept {
    return ike_udp_.configure(udp_);
  }
  void remove_ike_udp() noexcept { ike_udp_.remove(udp_); }
  [[nodiscard]] ikev2::UdpServiceResult
  service_ike_udp(void *context, ikev2::UdpInboundHandler handler) noexcept {
    return ike_udp_.service_one(udp_, context, handler);
  }
  [[nodiscard]] std::optional<transport::UdpSocketHandle>
  ike_udp_socket(transport::IpFamily family, bool encapsulated) const noexcept {
    return ike_udp_.socket(family, encapsulated);
  }
  // These methods must run on the forwarding owner. Control supplies the
  // selected physical ordinal, while the optional group remains an IPv6 wire
  // value and is never resolved through the UI topology graph.
  [[nodiscard]] bool clear_mld_database(
      std::uint16_t port_ordinal,
      const std::optional<packet::Ipv6> &group = std::nullopt) noexcept;
  void clear_mld_database_all() noexcept;
  [[nodiscard]] bool clear_mld_version(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool clear_mld_statistics(std::uint16_t port_ordinal) noexcept;
  void clear_mld_statistics_all() noexcept;
  [[nodiscard]] bool edit_mld_static(std::uint16_t port_ordinal,
                                     MldStaticOperation operation,
                                     const packet::Ipv6 &group,
                                     const packet::Ipv6 &source = {}) noexcept;
  [[nodiscard]] bool
  program_mld_ssm_translation(std::uint16_t port_ordinal,
                              MldSsmProgramOperation operation,
                              const MldSsmTranslation &translation = {},
                              std::uint32_t expected_entries = 0U) noexcept;
  // The forwarding owner publishes a complete compiled import program in one
  // turn. Cross-shard callers stream entries into their own bounded staging
  // transaction before invoking this method.
  [[nodiscard]] bool replace_mld_import_policy(
      std::uint16_t port_ordinal,
      std::span<const mld::ImportPolicyEntry> entries,
      mld::ImportPolicyAction default_action) noexcept;
  [[nodiscard]] bool program_mld_import_policy(
      std::uint16_t port_ordinal,
      mld::ImportPolicyProgramOperation operation,
      const mld::ImportPolicyEntry &entry = {},
      mld::ImportPolicyAction default_action =
          mld::ImportPolicyAction::accept,
      std::uint32_t expected_entries = 0U) noexcept;
  [[nodiscard]] bool originate_echo(std::uint32_t destination,
                                    std::uint16_t sequence, void *context,
                                    EgressSink sink,
                                    Clock::time_point now = Clock::now(),
                                    std::uint16_t payload_octets = 56,
                                    bool dont_fragment = false) noexcept;
  [[nodiscard]] bool
  originate_ipv6_echo(const packet::Ipv6 &destination, std::uint16_t sequence,
                      void *context, EgressSink sink,
                      Clock::time_point now = Clock::now(),
                      std::uint16_t payload_octets = 56) noexcept;
  void receive(std::uint16_t ingress_port, const packet::Frame &frame,
               void *context, EgressSink sink,
               Clock::time_point now = Clock::now(),
               void *punt_context = nullptr,
               PuntObserver punt_observer = nullptr,
               EgressAdmission admission = nullptr) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;
  // IPv4 maintenance retries unresolved ARP requests using the release
  // default. It runs on the same forwarding owner as pending-frame state and
  // emits only encoded requests through the ordinary egress sink.
  void service_ipv4_maintenance(void *context, EgressSink sink,
                                Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point>
  next_ipv4_deadline() const noexcept;
  void service_ipv6_maintenance(void *context, EgressSink sink,
                                Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point>
  next_ipv6_deadline() const noexcept;

  // These cold-path operations require forwarding-shard affinity and a
  // quiesced owner turn. checkpoint returns values only. restore validates the
  // complete image before changing any live field and retains no input memory.
  [[nodiscard]] RouterForwarderCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  // Callers that already own durable storage can avoid a second large return
  // slot on the bounded Wasm stack. The output is replaced completely and
  // retains no references into forwarding-owned arenas.
  void checkpoint(RouterForwarderCheckpoint &output,
                  Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const RouterForwarderCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const RouterForwarderCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::uint64_t forwarded_frames() const noexcept {
    return forwarded_frames_;
  }
  [[nodiscard]] std::uint64_t dropped_frames() const noexcept {
    return dropped_frames_;
  }
  [[nodiscard]] ForwardDrop last_drop() const noexcept { return last_drop_; }
  void set_transit_forwarding(bool enabled) noexcept {
    transit_forwarding_enabled_ = enabled;
  }
  [[nodiscard]] bool transit_forwarding() const noexcept {
    return transit_forwarding_enabled_;
  }
  [[nodiscard]] std::size_t arp_entries() const noexcept;
  [[nodiscard]] std::size_t pending_frames() const noexcept;
  [[nodiscard]] bool
  received_echo_reply(std::uint16_t sequence) const noexcept {
    return echo_reply_valid_ && echo_reply_sequence_ == sequence;
  }
  // Low byte 1 denotes a correlated IPv4 Echo Reply. The next byte carries
  // the received IP TTL and the upper 48 bits carry the forwarding-owner RTT
  // in nanoseconds. The compact value crosses the existing owner-affine query
  // ring without sharing forwarding state with the CLI worker.
  [[nodiscard]] std::uint64_t
  echo_outcome(std::uint16_t sequence) const noexcept;
  [[nodiscard]] bool
  received_ipv6_echo_reply(std::uint16_t sequence) const noexcept {
    return ipv6_echo_reply_valid_ && ipv6_echo_reply_sequence_ == sequence;
  }
  // Low byte 1 denotes Reply, followed by Hop Limit and a 48-bit nanosecond
  // RTT. Low byte 2 denotes an error, followed by type, code and the 32-bit
  // message parameter. Zero means no outcome for this sequence. The packed
  // scalar crosses the existing SPSC query without a pointer or an additional
  // mutable result owner.
  [[nodiscard]] std::uint64_t
  ipv6_echo_outcome(std::uint16_t sequence) const noexcept;
  [[nodiscard]] std::size_t ipv6_neighbor_entries() const noexcept {
    return ipv6_neighbors_.size();
  }
  [[nodiscard]] std::optional<Ipv6DadSnapshot>
  ipv6_address_state(std::uint16_t port_ordinal,
                     const packet::Ipv6 &address) const noexcept {
    return ipv6_dad_.find(physical_interface_id(port_ordinal), address);
  }
  [[nodiscard]] std::size_t
  mld_group_count(std::uint16_t port_ordinal) const noexcept;
  // These owner-affine operations are exposed through the network command
  // ring. Callers receive values, never mutable references into forwarding.
  [[nodiscard]] const Icmpv4Statistics &
  icmpv4_global_statistics() const noexcept {
    return icmpv4_global_statistics_;
  }
  [[nodiscard]] std::optional<Icmpv4Statistics>
  icmpv4_interface_statistics(std::uint16_t port_ordinal) const noexcept;
  void clear_icmpv4_statistics_all() noexcept;
  void clear_icmpv4_global_statistics() noexcept;
  [[nodiscard]] bool
  clear_icmpv4_interface_statistics(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] const Icmpv6Statistics &
  icmpv6_global_statistics() const noexcept {
    return icmpv6_global_statistics_;
  }
  [[nodiscard]] std::optional<Icmpv6Statistics>
  icmpv6_interface_statistics(std::uint16_t port_ordinal) const noexcept;
  void clear_icmpv6_statistics_all() noexcept;
  void clear_icmpv6_global_statistics() noexcept;
  [[nodiscard]] bool
  clear_icmpv6_interface_statistics(std::uint16_t port_ordinal) noexcept;
  // These commands clear only the six ND counters displayed by SR OS router
  // advertisement reporting. Echo and ICMPv6 error counters remain intact.
  void clear_router_advertisement_statistics_all() noexcept;
  [[nodiscard]] bool clear_router_advertisement_interface_statistics(
      std::uint16_t port_ordinal) noexcept;

private:
  struct Dhcpv4ServerState;
  struct Adjacency {
    bool valid{};
    std::uint16_t port_ordinal{};
    std::uint32_t address{};
    packet::Mac mac{};
    Clock::time_point expires{};
    bool aging_disabled{};
    bool configured_static{};
  };

  struct Pending {
    // The original IPv4 frame is retained until ARP resolves. Transit frames
    // have not yet decremented TTL, ensuring one decrement at actual
    // forwarding.
    bool valid{};
    bool transit{};
    bool ipv6{};
    // IPv6 pending ownership follows the RFC 4007 interface zone. The physical
    // ordinal is retained separately for the eventual link queue operation.
    std::uint64_t interface_id{};
    std::uint16_t port_ordinal{};
    std::uint32_t next_hop{};
    packet::Ipv6 next_hop_ipv6{};
    packet::Frame frame{};
    // This override belongs to the retained packet, not to the shared cache.
    // It lets one upward probe survive ND without raising concurrent traffic.
    std::uint32_t ipv6_source_mtu{};
    // All frames waiting for the same IPv4 next hop carry the same deadline.
    // This avoids a second allocation-backed resolution table while the owner
    // emits exactly one request for that adjacency at each interval.
    Clock::time_point arp_retry_deadline{Clock::time_point::max()};
  };

  struct Ipv6ReachableTimeState {
    // One forwarding shard is the sole writer. No atomic is needed because
    // configuration, packet receive, maintenance and checkpoint operations
    // are serialized by that owner's command loop.
    Clock::time_point refresh_deadline{Clock::time_point::max()};
    std::uint64_t random_state{};
    std::uint32_t base_milliseconds{};
    std::uint32_t effective_milliseconds{};
    bool valid{};
  };

  struct Icmpv6TransmitTimes {
    // The forwarding shard is the sole writer. Presence bits are separate
    // from time_point because steady_clock's minimum value is not guaranteed
    // to be outside the host implementation's representable runtime epoch.
    Clock::time_point router_advertisement{};
    Clock::time_point neighbor_solicitation{};
    Clock::time_point neighbor_advertisement{};
    bool has_router_advertisement{};
    bool has_neighbor_solicitation{};
    bool has_neighbor_advertisement{};
  };

  [[nodiscard]] const ForwardPort *port(std::uint16_t ordinal) const noexcept;
  [[nodiscard]] ForwardPort *port(std::uint16_t ordinal) noexcept;
  // All IPv6 next-hop users pass through this policy boundary. Keeping
  // admission, vendor aging and scope-selective proactive refresh here stops
  // DHCPv6, locally originated traffic and transit forwarding from silently
  // acquiring different Neighbor Discovery behavior.
  [[nodiscard]] Ipv6Resolution
  resolve_ipv6_neighbor(const ForwardPort &port, std::uint64_t interface_id,
                        const packet::Ipv6 &address,
                        Clock::time_point now) noexcept;
  [[nodiscard]] bool
  ipv6_neighbor_admission_allowed(const ForwardPort &port,
                                  std::uint64_t interface_id,
                                  const packet::Ipv6 &address) const noexcept;
  void configure_ipv6_reachable_time(const ForwardPort &port,
                                     const ForwardPort &previous,
                                     Clock::time_point now) noexcept;
  void refresh_ipv6_reachable_time(std::uint16_t port_ordinal,
                                   Clock::time_point now) noexcept;
  [[nodiscard]] std::chrono::milliseconds
  ipv6_reachable_time(std::uint16_t port_ordinal,
                      Clock::time_point now) noexcept;
  [[nodiscard]] Adjacency *find_adjacency(std::uint16_t port_ordinal,
                                          std::uint32_t address,
                                          Clock::time_point now) noexcept;
  void learn(std::uint16_t port_ordinal, std::uint32_t address, packet::Mac mac,
             Clock::time_point now) noexcept;
  void flush_pending(std::uint16_t port_ordinal, std::uint32_t address,
                     packet::Mac mac, void *context, EgressSink sink,
                     Clock::time_point now) noexcept;
  [[nodiscard]] bool
  send(packet::Frame frame, std::uint32_t destination, bool transit,
       void *context, EgressSink sink, Clock::time_point now) noexcept;
  // OSPF already selected its outgoing protocol interface. Link-local IPv6
  // destinations are zone-scoped, and equal connected IPv4 prefixes may also
  // exist on several ports, so these paths must not repeat a global FIB lookup.
  // They still use the ordinary ARP and ND owners and bounded pending queues.
  [[nodiscard]] bool send_ospf_ipv4_unicast(
      const ForwardPort &egress, packet::Frame frame,
      std::uint32_t destination, void *context, EgressSink sink,
      Clock::time_point now) noexcept;
  [[nodiscard]] bool send_ospf_ipv6_unicast(
      const ForwardPort &egress, packet::Frame frame,
      const packet::Ipv6 &destination, void *context, EgressSink sink,
      Clock::time_point now) noexcept;
  [[nodiscard]] bool
  send_resolved(const packet::Frame &input, const ForwardPort &egress,
                packet::Mac destination_mac, bool transit, void *context,
                EgressSink sink, Clock::time_point now) noexcept;
  bool send_ipv6(packet::Frame frame, const packet::Ipv6 &destination,
                 bool transit, void *context, EgressSink sink,
                 Clock::time_point now,
                 std::uint32_t local_source_mtu = 0U) noexcept;
  bool send_resolved_ipv6(const packet::Frame &input, const ForwardPort &egress,
                          std::uint64_t interface_id,
                          packet::Mac destination_mac, bool transit,
                          void *context, EgressSink sink,
                          Clock::time_point now,
                          std::uint32_t local_source_mtu = 0U) noexcept;
  void flush_pending_ipv6(std::uint64_t interface_id,
                          std::uint16_t port_ordinal,
                          const packet::Ipv6 &address, packet::Mac mac,
                          void *context, EgressSink sink,
                          Clock::time_point now) noexcept;
  void send_time_exceeded(const packet::Frame &original,
                          const packet::Ipv4View &ip, void *context,
                          EgressSink sink, Clock::time_point now) noexcept;
  void send_network_unreachable(const packet::Frame &original,
                                const packet::Ipv4View &ip, void *context,
                                EgressSink sink,
                                Clock::time_point now) noexcept;
  void send_local_destination_unreachable(
      std::span<const std::uint8_t> original, const packet::Ipv4View &ip,
      std::uint8_t code, void *context, EgressSink sink,
      Clock::time_point now) noexcept;
  void send_reassembly_time_exceeded(const packet::Frame &first_fragment,
                                     const packet::Ipv4View &ip, void *context,
                                     EgressSink sink,
                                     Clock::time_point now) noexcept;
  void send_fragmentation_needed(const packet::Frame &original,
                                 const packet::Ipv4View &ip,
                                 std::uint16_t next_hop_mtu, void *context,
                                 EgressSink sink,
                                 Clock::time_point now) noexcept;
  void send_ipv6_time_exceeded(const packet::Frame &original,
                               const packet::Ipv6View &ip, void *context,
                               EgressSink sink, Clock::time_point now) noexcept;
  void send_ipv6_packet_too_big(const packet::Frame &original,
                                const packet::Ipv6View &ip,
                                std::uint32_t next_hop_mtu, void *context,
                                EgressSink sink,
                                Clock::time_point now) noexcept;
  void send_ipv6_destination_unreachable(const packet::Frame &original,
                                         const packet::Ipv6View &ip,
                                         std::uint8_t code, void *context,
                                         EgressSink sink,
                                         Clock::time_point now) noexcept;
  void send_ipv6_destination_unreachable(std::span<const std::uint8_t> original,
                                         const packet::Ipv6View &ip,
                                         std::uint8_t code, void *context,
                                         EgressSink sink,
                                         Clock::time_point now) noexcept;
  void send_ipv6_parameter_problem(const packet::Frame &original,
                                   const packet::Ipv6View &ip,
                                   std::uint8_t code, std::uint32_t pointer,
                                   bool allow_multicast_destination,
                                   void *context, EgressSink sink,
                                   Clock::time_point now) noexcept;
  [[nodiscard]] bool
  may_send_icmp_error(const packet::Frame &original,
                      const packet::Ipv4View &ip) const noexcept;
  [[nodiscard]] bool
  may_send_icmp_error(std::span<const std::uint8_t> original,
                      const packet::Ipv4View &ip) const noexcept;
  [[nodiscard]] bool
  may_send_ipv6_icmp_error(const packet::Frame &original,
                           const packet::Ipv6View &ip,
                           bool allow_multicast_destination) const noexcept;
  [[nodiscard]] bool
  may_send_ipv6_icmp_error(std::span<const std::uint8_t> original,
                           const packet::Ipv6View &ip,
                           bool allow_multicast_destination) const noexcept;
  [[nodiscard]] bool emit(std::uint16_t port_ordinal,
                          const packet::Frame &frame, void *context,
                          EgressSink sink) noexcept;
  // Selects an operational primary ECMP member before consulting the LFA
  // table. This is forwarding-owner logic because only this shard owns current
  // carrier and hardware state.
  [[nodiscard]] bool lookup_ipv4_route(std::uint32_t destination,
                                       routing::Route &selected,
                                       std::uint64_t flow_hash = 0U) const
      noexcept;
  // Lookup combines the configured RIB projection with DHCPv6 protocol routes.
  // Longest prefix is evaluated across both owners. An equal prefix keeps the
  // configured route because direct and static routes have better documented
  // SR OS preference than dynamically populated DHCP routes.
  [[nodiscard]] bool lookup_ipv6_route(const packet::Ipv6 &destination,
                                       routing::Ipv6Route &selected,
                                       bool &blackhole,
                                       std::uint64_t flow_hash = 0U) const
      noexcept;
  [[nodiscard]] bool emit_ipv6_interface(std::uint64_t interface_id,
                                         std::uint16_t port_ordinal,
                                         const packet::Frame &frame,
                                         void *context,
                                         EgressSink sink) noexcept;
  [[nodiscard]] std::optional<ForwardPort>
  ipv6_interface(std::uint64_t interface_id,
                 std::uint16_t physical_port_ordinal) const noexcept;
  void drop(ForwardDrop reason) noexcept;
  void begin_global_dad_if_ready(const ForwardPort &port,
                                 Clock::time_point now) noexcept;
  // A PTB is applied only after comparing every quoted octet with a packet
  // emitted by the local source. This closes the blind cache-poisoning path
  // prohibited by RFC 8201 section 5.2.
  [[nodiscard]] bool accept_ipv6_packet_too_big(const packet::Icmpv6View &icmp,
                                                 Clock::time_point now) noexcept;
  [[nodiscard]] bool
  matches_ipv6_probe_quote(std::span<const std::uint8_t> quote) const noexcept;
  // IPv4 accepts a Type 3 Code 4 report only when its quote matches the exact
  // locally emitted DF packet and the destination still resolves to the same
  // physical interface path.
  [[nodiscard]] bool
  accept_ipv4_fragmentation_needed(const packet::IcmpView &icmp,
                                   Clock::time_point now) noexcept;
  [[nodiscard]] bool
  accepts_ipv6_multicast(const ForwardPort &port,
                         const packet::Ipv6 &destination) const noexcept;
  // A system address has no data-link attachment and therefore cannot enter
  // RFC 4862 Duplicate Address Detection. Physical addresses remain owned by
  // the DAD table. Keeping this distinction behind one predicate prevents
  // local delivery and source selection from treating an absent DAD record as
  // a tentative loopback address.
  [[nodiscard]] bool
  ipv6_address_preferred(std::uint64_t interface_id,
                         const packet::Ipv6 &address) const noexcept;
  void maybe_send_ipv6_redirect(const ForwardPort &ingress,
                                const packet::EthernetView &ethernet,
                                const packet::Ipv6View &ipv6,
                                const routing::Ipv6Route &route,
                                const packet::Frame &invoking_packet,
                                void *context, EgressSink sink,
                                Clock::time_point now) noexcept;
  void maybe_send_ipv4_redirect(const ForwardPort &ingress,
                                const packet::EthernetView &ethernet,
                                const packet::Ipv4View &ipv4,
                                const routing::Route &route,
                                const packet::Frame &invoking_packet,
                                void *context, EgressSink sink,
                                Clock::time_point now) noexcept;
  void count_received_icmpv4(std::uint16_t port_ordinal,
                             std::span<const std::uint8_t> packet,
                             const packet::Ipv4View &ipv4) noexcept;
  void count_sent_icmpv4(std::uint16_t port_ordinal,
                         const packet::Frame &frame) noexcept;
  void count_received_icmpv6(std::uint16_t port_ordinal,
                             std::span<const std::uint8_t> packet,
                             const packet::Ipv6View &ipv6) noexcept;
  void count_sent_icmpv6(std::uint16_t port_ordinal,
                         const packet::Frame &frame) noexcept;
  void count_discarded_icmpv6(std::uint16_t port_ordinal) noexcept;
  void service_dhcpv4_relay(std::uint16_t ingress_port,
                            std::uint64_t ingress_interface_id, void *context,
                            EgressSink sink, EgressAdmission admission,
                            Clock::time_point now) noexcept;
  void service_dhcpv4_leasequery(void *context, EgressSink sink,
                                 Clock::time_point now) noexcept;
  void service_dhcp_failover(void *context, EgressSink sink,
                             Clock::time_point now) noexcept;
  [[nodiscard]] bool emit_tcp(
      const transport::tcp::PreparedEndpointSegment &prepared,
      transport::tcp::EndpointSocketHandle socket, void *context,
      EgressSink sink, Clock::time_point now) noexcept;
  [[nodiscard]] Dhcpv4ServerState *
  dhcpv4_leasequery_server(std::string_view name) noexcept;
  [[nodiscard]] bool originate_dhcpv4_relay(
      const dhcpv4::RelayInterfaceConfiguration &relay,
      packet::Ipv4 source, packet::Ipv4 destination,
      packet::Mac destination_mac, std::uint16_t destination_port,
      std::span<const std::uint8_t> payload, bool direct_link, void *context,
      EgressSink sink, EgressAdmission admission,
      Clock::time_point now) noexcept;
  void service_dhcpv6_relay(std::uint16_t ingress_port,
                            std::uint64_t ingress_interface_id, void *context,
                            EgressSink sink, EgressAdmission admission,
                            Clock::time_point now) noexcept;
  [[nodiscard]] bool
  originate_dhcpv6_relay(const dhcpv6::RelayDecision &decision,
                         const dhcpv6::RelayDestination &destination,
                         std::span<const std::uint8_t> payload, void *context,
                         EgressSink sink, EgressAdmission admission,
                         Clock::time_point now) noexcept;

  struct MldPortState {
    MldRouterConfiguration intent{};
    MldRouterInterface protocol{};
    // The forwarding shard owns both vectors. `translations` remains visible
    // to packet processing while a control transaction builds `staged`; commit
    // swaps them in one owner turn and therefore exposes no partial program.
    std::vector<MldSsmTranslation> translations;
    std::vector<MldSsmTranslation> staged_translations;
    std::vector<packet::Ipv6> translation_scratch;
    mld::ImportPolicyProgram import_policy;
    std::vector<mld::ImportPolicyEntry> staged_import_policy;
    std::vector<packet::Ipv6> policy_source_scratch;
    std::uint32_t staged_expected_entries{};
    std::uint32_t staged_policy_expected_entries{};
    mld::ImportPolicyAction staged_import_policy_default_action{
        mld::ImportPolicyAction::accept};
    bool translation_staging{};
    bool import_policy_staging{};
    bool running{};
  };
  [[nodiscard]] MldPortState *mld(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] const MldPortState *
  mld(std::uint16_t port_ordinal) const noexcept;

  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports_{};
  RouterIpv6AddressTable native_ipv6_addresses_{};
  // The forwarding shard is the sole mutable owner. Packet turns perform only
  // allocation-free lookups; the control shard replaces complete generations.
  service::SapForwardingTable sap_forwarding_{};
  struct Ipv6RedirectLimiter {
    Clock::time_point window_end{Clock::time_point::min()};
    std::uint16_t sent{};
    bool active{};
  };
  // Port ordinal is a dense generated coordinate, so the limiter needs no map
  // allocation or cross-owner lookup on the transit packet path.
  std::array<Ipv6RedirectLimiter, device_catalog::maximum_ports_per_router>
      ipv6_redirect_limiters_{};
  // IPv4 and IPv6 use the same fixed-window mechanism but remain independent
  // protocol resources. A burst in one family cannot consume the other
  // family's documented interface allowance.
  std::array<Ipv6RedirectLimiter, device_catalog::maximum_ports_per_router>
      ipv4_redirect_limiters_{};
  // Only this forwarding shard mutates these values. No atomics are required,
  // and checkpoint/query commands run between packet turns on the same owner.
  Icmpv4Statistics icmpv4_global_statistics_{};
  std::array<Icmpv4Statistics, device_catalog::maximum_ports_per_router>
      icmpv4_interface_statistics_{};
  Icmpv6Statistics icmpv6_global_statistics_{};
  std::array<Icmpv6Statistics, device_catalog::maximum_ports_per_router>
      icmpv6_interface_statistics_{};
  std::array<InterfaceTrafficStatistics,
             device_catalog::maximum_ports_per_router>
      interface_traffic_statistics_{};
  std::array<Icmpv6TransmitTimes, device_catalog::maximum_ports_per_router>
      icmpv6_transmit_times_{};
  std::array<Ipv6ReachableTimeState, device_catalog::maximum_ports_per_router>
      ipv6_reachable_times_{};
  routing::FibProgram fib_{};
  routing::Ipv6FibProgram ipv6_fib_{};
  std::array<Clock::time_point,
             device_catalog::maximum_fib_routes_per_router>
      ipv4_route_installed_at_{};
  std::array<Clock::time_point,
             device_catalog::maximum_fib_routes_per_router>
      ipv6_route_installed_at_{};
  std::array<bool, device_catalog::maximum_ports_per_router> ospf_v2_punt_{};
  std::array<bool, device_catalog::maximum_ports_per_router> ospf_v3_punt_{};
  std::array<Adjacency, device_catalog::arp_entries_per_router> adjacencies_{};
  // Both families share the same unresolved-frame arena, matching a physical
  // buffer resource and preventing a second 75 MiB worst-case frame envelope
  // allocation across sixteen routers.
  std::array<Pending, device_catalog::pending_l3_frames_per_router> pending_{};
  Ipv6NeighborCache ipv6_neighbors_{};
  Ipv6DadTable ipv6_dad_{};
  Ipv6RouterAdvertisementTable ipv6_router_advertisements_{};
  ip::Ipv6PathMtuCache ipv6_path_mtu_{};
  ip::Ipv4PathMtuCache ipv4_path_mtu_{};
  packet::Ipv4ReassemblyTable ipv4_reassembly_{};
  packet::Ipv6ReassemblyTable ipv6_reassembly_{};
  // Only explicitly configured MLD interfaces allocate router group state.
  // The vector is bounded by the selected chassis port count and is touched on
  // control packets and maintenance turns, never by unicast FIB lookup.
  std::vector<MldPortState> mld_interfaces_{};
  std::uint16_t mld_service_cursor_{};
  std::array<packet::Frame, packet::Ipv6FragmentBatch::maximum_fragment_count>
      ipv6_probe_packets_{};
  packet::Frame ipv4_probe_packet_{};
  std::uint64_t forwarded_frames_{};
  std::uint64_t dropped_frames_{};
  ForwardDrop last_drop_{ForwardDrop::none};
  bool transit_forwarding_enabled_{true};
  std::uint16_t echo_reply_sequence_{};
  bool echo_reply_valid_{};
  packet::Ipv4 echo_request_destination_{};
  Clock::time_point echo_request_sent_at_{};
  std::chrono::nanoseconds echo_reply_rtt_{};
  std::uint8_t echo_reply_ttl_{};
  std::uint16_t echo_request_sequence_{};
  bool echo_request_valid_{};
  std::uint16_t ipv6_echo_reply_sequence_{};
  bool ipv6_echo_reply_valid_{};
  Clock::time_point ipv6_probe_sent_at_{};
  std::chrono::nanoseconds ipv6_echo_reply_rtt_{};
  std::uint8_t ipv6_echo_reply_hop_limit_{};
  std::uint32_t ipv6_echo_error_parameter_{};
  std::uint16_t ipv6_echo_error_sequence_{};
  std::uint8_t ipv6_echo_error_type_{};
  std::uint8_t ipv6_echo_error_code_{};
  bool ipv6_echo_error_valid_{};
  packet::Ipv6 ipv6_probe_destination_{};
  packet::Ipv4 ipv4_probe_destination_{};
  std::uint32_t ipv6_fragment_identification_{1U};
  std::uint64_t ipv6_probe_interface_id_{};
  std::uint64_t ipv4_probe_interface_id_{};
  std::uint16_t ipv6_probe_port_ordinal_{};
  std::uint16_t ipv6_probe_sequence_{};
  std::uint16_t ipv4_probe_port_ordinal_{};
  std::uint8_t ipv6_probe_packet_count_{};
  bool ipv6_probe_valid_{};
  bool ipv4_probe_valid_{};
  // One wildcard UDP 547 socket receives all configured relay interfaces. The
  // ingress interface remains in datagram metadata, so one socket does not
  // collapse RFC 4007 scope or Interface-Id return routing.
  transport::UdpEndpoint udp_{};
  // TCP is allocated with per-router entropy at device admission. It remains
  // transport-only: DHCP Leasequery and failover sessions own framing and
  // protocol state but never reach into TCP sequence or retransmission data.
  std::unique_ptr<transport::tcp::TcpEndpoint> tcp_{};
  // RFC 6926 assigns Bulk Leasequery to TCP port 67. One wildcard listener is
  // shared by Base server instances because the accepted connection retains
  // its concrete local address and therefore selects the correct owner.
  std::optional<transport::tcp::EndpointSocketHandle>
      dhcpv4_leasequery_listener_{};
  struct Dhcpv4LeasequerySession {
    transport::tcp::EndpointSocketHandle socket{};
    std::unique_ptr<dhcpv4::leasequery::StreamDecoder> decoder;
    std::optional<dhcpv4::leasequery::RequestView> request;
    packet::Ipv4 local{};
    packet::Ipv4 remote{};
    std::string server_name;
    std::size_t lease_cursor{};
    std::size_t pool_cursor{};
    std::uint32_t address_cursor{};
    std::uint64_t revision_cursor{};
    // Active Leasequery takes a finite repository revision snapshot for each
    // scan. New mutations that arrive while the scan is being streamed remain
    // above this target and are delivered during the next scan, so no update
    // can be skipped by advancing the acknowledged cursor too early.
    std::uint64_t scan_revision_target{};
    Clock::time_point data_deadline{};
    Clock::time_point keepalive_deadline{};
    bool first_reply{true};
    bool catch_up_complete{};
    bool done{};
  };
  // Producer and consumer are the same forwarding owner. Capacity comes from
  // the release profile. Overflow is a TCP refusal at listen backlog admission,
  // never an unbounded application allocation.
  std::vector<Dhcpv4LeasequerySession> dhcpv4_leasequery_sessions_{};
  struct Dhcpv4FailoverSession {
    Dhcpv4FailoverTransportConfiguration configuration;
    dhcpv4::failover::Session protocol;
    std::unique_ptr<dhcpv4::failover::StreamDecoder> decoder;
    std::optional<transport::tcp::EndpointSocketHandle> socket;
    std::vector<std::uint8_t> output;
    // Full synchronization owns an immutable repository image until the peer
    // acknowledges every BNDUPD. Serial transmission is deliberately valid
    // even when the negotiated window is larger and avoids ambiguous partial
    // progress after a reconnect.
    std::vector<dhcpv4::LeaseCheckpoint> synchronization_leases;
    std::size_t output_offset{};
    std::size_t synchronization_cursor{};
    std::uint32_t synchronization_request_transaction_id{};
    std::uint32_t synchronization_binding_transaction_id{};
    Clock::time_point reconnect_at{};
    bool transport_started{};
  };
  struct Dhcpv6FailoverSession {
    Dhcpv6FailoverTransportConfiguration configuration;
    dhcpv6::failover::Session protocol;
    std::unique_ptr<dhcpv6::failover::StreamDecoder> decoder;
    std::optional<transport::tcp::EndpointSocketHandle> socket;
    std::vector<std::uint8_t> message;
    std::vector<std::uint8_t> output;
    std::vector<dhcpv6::LeaseCheckpoint> synchronization_leases;
    std::size_t output_offset{};
    std::size_t synchronization_cursor{};
    std::uint32_t synchronization_request_transaction_id{};
    std::uint32_t synchronization_binding_transaction_id{};
    Clock::time_point reconnect_at{};
    bool transport_started{};
  };
  // One listener per IP family is shared by all relationship names. An
  // accepted tuple is matched by local address, peer address and secondary
  // role before any CONNECT bytes are dispatched.
  std::optional<transport::tcp::EndpointSocketHandle>
      dhcpv4_failover_listener_{};
  std::optional<transport::tcp::EndpointSocketHandle>
      dhcpv6_failover_listener_{};
  std::vector<Dhcpv4FailoverSession> dhcpv4_failover_sessions_{};
  std::vector<Dhcpv6FailoverSession> dhcpv6_failover_sessions_{};
  std::array<std::uint8_t, packet::maximum_frame_octets>
      tcp_segment_scratch_{};
  std::array<std::uint8_t, packet::maximum_frame_octets>
      tcp_datagram_scratch_{};
  ikev2::UdpService ike_udp_{};
  struct Dhcpv4RelayInterfaceState {
    dhcpv4::RelayInterfaceConfiguration configuration;
    dhcpv4::RelayAgent agent;
  };
  // The vector is mutated only by forwarding-owner configuration commands.
  // Packet turns perform linear lookup across the profile-bounded interface
  // count, which avoids a second mutable giaddr index and atomicity hazards.
  std::vector<Dhcpv4RelayInterfaceState> dhcpv4_relays_{};
  struct Dhcpv4ServerState {
    std::string name;
    dhcpv4::ServerConfiguration configuration;
    dhcpv4::Server protocol;
  };
  // One forwarding shard owns every Base server instance. Configuration
  // replacement is staged before vector mutation, and packet turns never hold
  // an iterator across a control command.
  std::vector<Dhcpv4ServerState> dhcpv4_servers_{};
  std::optional<transport::UdpSocketHandle> dhcpv4_relay_socket_{};
  // DHCPv4 relay arenas are allocated only while at least one interface is
  // configured. RouterForwarder is instantiated for every possible router,
  // so embedding three 64 KiB arrays would reserve megabytes for labs that do
  // not use DHCP and would push the fixed shared Wasm heap toward its limit.
  std::vector<std::uint8_t> dhcpv4_receive_scratch_{};
  std::vector<std::uint8_t> dhcpv4_relay_scratch_{};
  std::vector<std::uint8_t> ipv4_udp_datagram_scratch_{};
  std::uint16_t dhcpv4_identification_{1U};
  dhcpv6::RelayAgent dhcpv6_relay_{};
  struct Dhcpv6ServerState {
    std::string name;
    dhcpv6::Server protocol;
  };
  std::vector<Dhcpv6ServerState> dhcpv6_servers_{};
  // The forwarding shard is the only writer. It derives state exclusively
  // from received DHCPv6 wire messages and emits route/neighbor intentions;
  // it never reaches into another router or the editor topology.
  dhcpv6::RelayLeaseRepository dhcpv6_relay_leases_{};
  dhcpv6::RelayRouteRepository dhcpv6_relay_routes_{};
  // Configuration reserves this cold-path vector to the sum of enabled lease
  // policies. One Reply then stages every Neighbor Cache edit without heap
  // growth before the cache's atomic batch preflight.
  std::vector<Ipv6NeighborBatchEdit> dhcpv6_neighbor_edits_{};
  // Operator clear copies selected rows before committing their removal.
  // Capacity is reserved with relay policy so the owner never removes half a
  // batch because a later Release description allocation failed.
  std::vector<dhcpv6::RelayLeaseRecord> dhcpv6_clear_scratch_{};
  std::optional<transport::UdpSocketHandle> dhcpv6_relay_socket_{};
  // Scratch is forwarding-owner local and reused serially. It admits the full
  // ordinary UDP payload domain; link MTU is handled later by source
  // fragmentation and never narrows application message validity.
  std::array<std::uint8_t, packet::dhcpv6::maximum_message_octets>
      dhcpv6_receive_scratch_{};
  std::array<std::uint8_t, packet::dhcpv6::maximum_message_octets>
      dhcpv6_relay_scratch_{};
  // Release construction needs simultaneous inner client and outer relay
  // payloads. A distinct owner-local arena prevents one encoder from
  // overwriting bytes still borrowed by the next stage.
  std::array<std::uint8_t, packet::dhcpv6::maximum_message_octets>
      dhcpv6_release_relay_scratch_{};
  std::array<std::uint8_t, packet::maximum_ethernet_ipv6_datagram_octets>
      ipv6_udp_datagram_scratch_{};
};

} // namespace router::lab
