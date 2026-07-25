// Forwarding and link-shard aggregate for the multi-device runtime. Control
// submits complete value commands. This owner never reads configuration,
// hardware inventory, CLI sessions, project strings or the topology registry.

#pragma once

#include "router/capture_store.hpp"
#include "router/dhcpv6_client.hpp"
#include "router/dhcpv6_server.hpp"
#include "router/dns_endpoint_checkpoint.hpp"
#include "router/endpoint_protocol.hpp"
#include "router/ethernet_switch.hpp"
#include "router/lab_registry.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/multi_device_routing.hpp"
#include "router/ospf_control_worker.hpp"
#include "router/ospf_process.hpp"
#include "router/packet.hpp"
#include "router/router_forwarder.hpp"
#include "router/route_policy.hpp"
#include "router/udp_transport.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <type_traits>
#include <vector>

namespace router::lab {

struct NetworkLinkProgram {
  // Control resolves textual topology and hardware compatibility before this
  // value crosses the shard boundary. NetworkPlane receives compact live ports.
  LinkHandle link;
  PortHandle first;
  PortHandle second;
  std::uint64_t bits_per_second{};
  std::chrono::nanoseconds propagation{};
  bool carrier{};
};

struct HostNetworkProgram {
  HostHandle host;
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
  std::uint64_t interface_id{};
  bool ipv6_autoconfiguration{};
  host::Ipv6InterfaceIdentifierConfiguration ipv6_identifier{};
  crypto::Sha256Digest transport_secret{};
};

struct RoutePolicyProgram {
  // Control publishes unresolved static intent together with the selected
  // ECMP width. The network route owner combines this intent with connected
  // routes from the base FIB and complete OSPF generations. Keeping indirect
  // statics here is essential because a route unresolved before OSPF
  // convergence may become active after a learned next-hop route appears.
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router>
      ipv4_statics{};
  std::array<routing::Ipv6StaticInput,
             device_catalog::maximum_static_routes_per_router>
      ipv6_statics{};
  std::uint16_t maximum_ecmp_paths{1U};
};

struct RouterAdvertisementProgram {
  // Control resolves the interface name to a stable physical ordinal before
  // crossing the shard boundary. Forwarding copies the complete option set.
  DeviceHandle device{};
  packet::nd::RouterAdvertisementConfig config{};
  std::uint16_t port_ordinal{};
  bool enabled{};
};

struct MldInterfaceProgram {
  DeviceHandle device{};
  MldRouterConfiguration configuration{};
};

struct StaticIpv6NeighborProgram {
  // Producer: serialized control owner. Consumer: the selected router's
  // forwarding shard. Port identity is already resolved, and the record is a
  // self-contained value so no configuration pointer crosses shared memory.
  DeviceHandle device{};
  packet::Ipv6 address{};
  packet::Mac mac{};
  std::uint16_t port_ordinal{};
};

struct StaticIpv4NeighborProgram {
  // Producer: serialized control owner. Consumer: the selected router's
  // forwarding shard. The fixed value contains no pointer and is safe to copy
  // through the bounded SPSC control queue.
  DeviceHandle device{};
  std::uint32_t address{};
  packet::Mac mac{};
  std::uint16_t port_ordinal{};
};

struct OspfProcessProgram {
  // The canonical configuration owner compiles one fixed area record before
  // crossing the control-to-network SPSC boundary. These values describe
  // protocol intent only. The OSPF pthread remains the sole owner of LSAs,
  // ABR decisions, timers and calculated routes.
  DeviceHandle device{};
  std::uint32_t router_id{};
  std::uint32_t area_id{};
  std::uint32_t initial_dd_sequence{};
  std::uint32_t maximum_interfaces{};
  std::uint32_t default_metric{};
  std::uint32_t router_preference{};
  std::uint32_t external_preference{};
  std::uint32_t spf_initial_wait_milliseconds{};
  std::uint32_t spf_second_wait_milliseconds{};
  std::uint32_t spf_maximum_wait_milliseconds{};
  std::uint32_t lsa_initial_wait_milliseconds{};
  std::uint32_t lsa_second_wait_milliseconds{};
  std::uint32_t lsa_maximum_wait_milliseconds{};
  ospf::AreaType area_type{ospf::AreaType::normal};
  std::uint8_t version{};
  std::uint8_t instance_id{};
  bool summaries{true};
  bool nssa_translate_always{};
  bool asbr{};
  bool graceful_restart_helper{};
  bool loopfree_alternates{};
  bool overload{};
};

struct OspfInterfaceProgram {
  OspfProcessProgram process{};
  ospf::ProcessInterfaceConfiguration interface{};
};

struct OspfAuthenticationProgram {
  // Producer: serialized configuration owner. Consumers: network transaction
  // staging and the dedicated OSPF pthread. Each message carries one bounded
  // secret record by value, so no vault pointer or vector storage crosses an
  // SPSC ring. The owner scrubs its copy after installing the generation.
  OspfProcessProgram process{};
  ospf::ProcessAuthentication authentication{};
  std::uint32_t interface_id{};
  bool receive{true};
  bool send{};
};

struct OspfNbmaNeighborProgram {
  // The configuration owner resolves the enclosing process and interface.
  // This fixed record crosses both SPSC transactions by value. The OSPF
  // pthread remains the sole owner of peer timers and learned Router IDs.
  OspfProcessProgram process{};
  std::uint32_t interface_id{};
  ospf::ProcessNbmaNeighborConfiguration neighbor{};
};

struct OspfVirtualLinkProgram {
  // The process identity always names area 0. The transit area and remote ABR
  // remain semantic configuration until the OSPF owner resolves them through
  // that area's LSDB and SPF tree.
  OspfProcessProgram process{};
  ospf::ProcessVirtualLinkConfiguration link{};
};

struct OspfAreaRangeProgram {
  // Producer: canonical router configuration. Consumers: network transaction
  // staging and the OSPF owner. The fixed prefix is copied by value; no
  // std::vector storage or configuration pointer crosses either SPSC ring.
  OspfProcessProgram process{};
  ip::IpPrefix prefix{};
  std::uint32_t advertised_metric{};
  bool has_advertised_metric{};
  bool advertise{true};
};

struct OspfExternalRouteProgram {
  // Policy evaluation happens in the serialized configuration owner. The
  // dedicated OSPF pthread receives only an accepted semantic advertisement,
  // assigns its local sequence and Link State ID, and emits real LSA bytes.
  OspfProcessProgram process{};
  routing::PolicyCandidate source{};
  ospf::CoordinatorAdvertisement advertisement{};
};

struct OspfRouteDiagnostics {
  // This projection reports only the last complete generation accepted by the
  // route owner. It does not expose mutable daemon vectors or fabricate
  // neighbor state from configured intent.
  std::uint64_t generation{};
  std::uint32_t ipv4_candidates{};
  std::uint32_t ipv6_candidates{};
};

struct OspfOperationalQuery {
  // Producer: serialized control owner. Consumer: OSPF control pthread through
  // the network owner. Ordinals select one row in the generation observed by
  // this synchronous command and have no meaning after the result is copied.
  ospf::ControlCommandKind kind{ospf::ControlCommandKind::query_process};
  std::uint32_t process_ordinal{};
  std::uint32_t interface_ordinal{};
  std::uint32_t interface_id{};
  std::uint32_t row_ordinal{};
  std::uint32_t neighbor_router_id{};
  std::uint8_t version{};
  std::uint8_t instance_id{};
};

static_assert(std::is_trivially_copyable_v<OspfOperationalQuery>);

// Variable-length relay policy is divided into fixed, trivially-copyable
// records before it crosses a shared-memory queue. The chunk size controls
// only control-plane copying cost. It is not an Interface-Id length limit:
// configure_dhcpv6_relay streams every octet allowed by the DHCPv6 option's
// 16-bit length field.
inline constexpr std::size_t dhcpv6_relay_program_chunk_octets = 256U;

struct Dhcpv6RelayBegin {
  // Producer: the caller that owns service configuration. Consumer: the
  // forwarding shard that owns RouterForwarder. Commit is accepted only when
  // both declared counts have arrived in FIFO order.
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  packet::Ipv6 link_address{};
  packet::Ipv6 source_address{};
  ip::Ipv6Prefix client_prefix{};
  std::uint32_t expected_interface_id_octets{};
  std::uint16_t expected_servers{};
  std::uint16_t lease_population_limit{};
  bool has_source_address{};
  bool neighbor_resolution{};
  bool route_non_temporary{};
  bool route_temporary{};
  bool route_delegated_prefix{};
  bool route_prefix_exclude{};
  dhcpv6::RelayUpstreamPolicy upstream_policy{
      dhcpv6::RelayUpstreamPolicy::protocol_default};
};

struct Dhcpv6RelayInterfaceIdChunk {
  // octets beyond size are zero-filled and ignored. A bounded value record
  // avoids sharing a std::vector data pointer between Wasm pthread owners.
  std::array<std::uint8_t, dhcpv6_relay_program_chunk_octets> octets{};
  std::uint16_t size{};
};

struct Dhcpv6RelayLeaseClearProgram {
  // Producer: control owner after resolving service, SAP and CLI selectors.
  // Consumer: exactly one RouterForwarder owner. The fixed value contains no
  // strings, pointers or topology references and selects only live lease rows.
  dhcpv6::RelayLeaseClearFilter filter{};
  bool no_dhcp_release{};
};

struct SapGenerationBegin {
  // Both counts are declared before any item crosses the owner boundary. The
  // receiver reserves once and publishes only after the exact related sets
  // arrive, preventing a SAP and its routed interface from diverging.
  std::uint32_t expected_attachments{};
  std::uint32_t expected_interfaces{};
};

struct Ipv6AddressGenerationBegin {
  // A complete native address generation is declared before value records
  // cross either SPSC boundary. Both lower owners reserve once and reject
  // incomplete Commit without exposing a partially changed interface.
  std::uint32_t expected_addresses{};
};

struct HostDhcpv6ClientProgram {
  HostHandle host{};
  dhcpv6::ClientConfiguration configuration{};
  bool information_only{};
};

struct HostDhcpv6ServerProgram {
  HostHandle host{};
  dhcpv6::ServerConfiguration configuration{};
  std::vector<dhcpv6::LeasePool> address_pools;
  std::vector<dhcpv6::LeasePool> prefix_pools;
  std::chrono::seconds decline_hold_time{};
};

struct HostDnsResolverProgram {
  HostHandle host{};
  crypto::Sha256Digest identifier_secret{};
  std::vector<dns::RootHint> root_hints;
  // Empty anchors select a non-validating iterative resolver. Non-empty
  // anchors are complete DNSKEY records and enable validation from exactly
  // those project-owned roots. No Internet or host trust store is consulted.
  std::vector<dns::ZoneRecord> trust_anchors;
  dnssec::Nsec3IterationPolicy nsec3_policy{};
  bool serve_clients{};
};

struct HostDnsAuthoritativeProgram {
  HostHandle host{};
  // Zone checkpoints are configuration values here, not operational restore
  // images. Reusing the canonical origin and record representation prevents a
  // second, drifting DNS schema at the control/forwarding boundary.
  std::vector<dns::ZoneCheckpoint> zones;
};

struct HostDnsSigningKeyProgram {
  // This is a generation request, never private key material. The forwarding
  // owner invokes the selected OpenSSL provider and retains the resulting key
  // inside ZoneKeyStore. Schedule values are absolute POSIX seconds because
  // RFC 7583 lifecycle events must remain meaningful across checkpoints.
  dnssec::KeySchedule schedule{};
  dnssec::SigningKeyGeneration generation{};
  dnssec::KeyRole role{dnssec::KeyRole::zone_signing};
  std::uint8_t algorithm{};
};

struct HostDnsSignedZoneProgram {
  dns::ZoneCheckpoint zone;
  std::vector<HostDnsSigningKeyProgram> keys;
  dnssec::ManagedZoneSigningPolicy policy{};
};

struct HostDnsSignedAuthoritativeProgram {
  HostHandle host{};
  std::vector<HostDnsSignedZoneProgram> zones;
  // One wall-clock sample is used for every key state and RRSIG in the
  // transaction. A configuration generation cannot straddle a second and
  // accidentally publish different rollover states for adjacent zones.
  std::uint64_t wall_now{};
};

struct HostDhcpv6PendingCheckpoint {
  packet::Ipv6 destination{};
  std::vector<std::uint8_t> payload;
  std::uint16_t destination_port{};
  bool active{};
};

struct HostDhcpv6ServiceCheckpoint {
  std::optional<dhcpv6::ClientCheckpoint> client;
  std::optional<dhcpv6::ServerCheckpoint> server;
  std::optional<transport::UdpSocketHandle> client_socket;
  std::optional<transport::UdpSocketHandle> server_socket;
  HostDhcpv6PendingCheckpoint client_pending;
  HostDhcpv6PendingCheckpoint server_pending;
};

enum class CapturePointKind : std::uint8_t {
  link_direction,
  router_ingress,
  router_egress,
  cpm_punt
};

struct CapturePointProgram {
  CapturePointId id{};
  CapturePointKind kind{};
  LinkHandle link{};
  NodeHandle node{};
  std::uint16_t port_ordinal{0xffffU};
  std::uint8_t link_endpoint{};
  bool selected{};
  std::uint16_t name_size{};
  std::array<char, device_catalog::capture_point_name_bytes> name{};
};

struct NetworkRouterCheckpoint {
  DeviceHandle device{};
  RouterForwarderCheckpoint forwarding;
};

struct NetworkHostCheckpoint {
  HostHandle host{};
  NetworkCheckpointState endpoint;
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
  std::uint64_t interface_id{};
  std::uint16_t expected_sequence{};
  bool configured{};
  bool link_signal{};
  bool ping_pending{};
  bool ping_reply{};
  bool ipv6_autoconfiguration{};
  std::optional<HostDhcpv6ServiceCheckpoint> dhcpv6;
  std::optional<dns::EndpointServiceCheckpoint> dns;
};

struct NetworkPlaneCheckpoint {
  // Sparse vectors contain only live generations. Fabric and capture values
  // retain queue bytes and selected diagnostic locations independently.
  std::vector<NetworkRouterCheckpoint> routers;
  std::vector<NetworkHostCheckpoint> hosts;
  struct Switch {
    SwitchHandle handle{};
    std::uint16_t profile_index{};
    EthernetSwitchCheckpoint forwarding;
  };
  std::vector<Switch> switches;
  MultiDeviceFabricCheckpoint fabric;
  CaptureStoreCheckpoint capture;
  // The OSPF pthread contributes one detached owner snapshot. It contains no
  // pointer into live process state and stores all deadlines as durations
  // relative to the same checkpoint instant used by forwarding and fabric.
  ospf::ControlWorkerCheckpoint ospf;
  std::vector<CapturePointProgram> capture_points;
  std::uint64_t capture_dropped{};
  // Transfer rings exist only between physical runtime owners. Their loss
  // counters are persisted so checkpoint restore cannot make overload vanish
  // from operational telemetry.
  std::uint64_t ingress_ring_dropped{};
  std::uint64_t egress_ring_dropped{};
  std::uint64_t missing_binding_dropped{};
};

class NetworkPlane final {
public:
  using Clock = std::chrono::steady_clock;

  explicit NetworkPlane(
      std::size_t logical_cpus = std::thread::hardware_concurrency());
  ~NetworkPlane();
  NetworkPlane(const NetworkPlane &) = delete;
  NetworkPlane &operator=(const NetworkPlane &) = delete;

  // Device lifecycle commands are generation-checked. Removing an old handle
  // cannot erase a forwarding instance created later in the same bounded slot.
  [[nodiscard]] bool add_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool remove_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool add_host(HostHandle host) noexcept;
  [[nodiscard]] bool remove_host(HostHandle host) noexcept;
  // profile_index addresses the immutable generated switch catalog included in
  // the runtime protocol hash. No UI-created port count or default crosses
  // this boundary.
  [[nodiscard]] bool add_switch(SwitchHandle handle,
                                std::uint16_t profile_index) noexcept;
  [[nodiscard]] bool remove_switch(SwitchHandle handle) noexcept;
  [[nodiscard]] bool configure_switch_port(
      SwitchHandle handle, std::uint16_t port,
      const SwitchPortConfiguration &configuration) noexcept;

  // Port and FIB programs replace complete owner-local projections. Neither
  // method retains a control pointer after the call or future mailbox turn.
  [[nodiscard]] bool configure_port(DeviceHandle device,
                                    const ForwardPort &port) noexcept;
  [[nodiscard]] bool remove_port(DeviceHandle device,
                                 std::uint16_t ordinal) noexcept;
  [[nodiscard]] bool
  add_ospf_process(const OspfProcessProgram &program) noexcept;
  [[nodiscard]] bool
  remove_ospf_process(const OspfProcessProgram &program) noexcept;
  [[nodiscard]] bool
  add_ospf_interface(const OspfInterfaceProgram &program) noexcept;
  [[nodiscard]] bool
  remove_ospf_interface(const OspfInterfaceProgram &program) noexcept;
  // Replaces the complete OSPF projection for one router. Processes and
  // interfaces are staged on the protocol owner before forwarding is paused;
  // Commit and the derived per-port punt mask are then published as one
  // quiesced transaction. No caller-owned span is retained.
  [[nodiscard]] bool replace_ospf_generation(
      DeviceHandle device, std::span<const OspfProcessProgram> processes,
      std::span<const OspfInterfaceProgram> interfaces,
      std::span<const OspfAuthenticationProgram> authentications,
      std::span<const OspfNbmaNeighborProgram> nbma_neighbors,
      std::span<const OspfVirtualLinkProgram> virtual_links,
      std::span<const OspfAreaRangeProgram> ranges,
      std::span<const OspfExternalRouteProgram> external_routes = {}) noexcept;
  [[nodiscard]] bool
  program_route_policy(DeviceHandle device,
                       const RoutePolicyProgram &policy) noexcept;
  [[nodiscard]] std::optional<OspfRouteDiagnostics>
  ospf_route_diagnostics(DeviceHandle device) const noexcept;
  [[nodiscard]] std::optional<ospf::ControlResult>
  query_ospf(DeviceHandle device,
             const OspfOperationalQuery &query) noexcept;
  [[nodiscard]] bool program_fib(DeviceHandle device,
                                 const routing::FibProgram &fib) noexcept;
  [[nodiscard]] bool
  program_ipv6_fib(DeviceHandle device,
                   const routing::Ipv6FibProgram &fib) noexcept;
  [[nodiscard]] bool program_ipv6_address_generation(
      DeviceHandle device,
      std::span<const RouterIpv6Address> addresses) noexcept;
  [[nodiscard]] bool program_sap_generation(
      DeviceHandle device, std::span<const service::SapAttachment> attachments,
      std::span<const service::ServiceIpv6Interface> interfaces = {}) noexcept;
  [[nodiscard]] bool install_static_ipv6_neighbor(
      const StaticIpv6NeighborProgram &program) noexcept;
  [[nodiscard]] bool
  remove_static_ipv6_neighbor(DeviceHandle device, std::uint16_t port_ordinal,
                              const packet::Ipv6 &address) noexcept;
  [[nodiscard]] bool install_static_ipv4_neighbor(
      const StaticIpv4NeighborProgram &program) noexcept;
  [[nodiscard]] bool
  remove_static_ipv4_neighbor(DeviceHandle device, std::uint16_t port_ordinal,
                              std::uint32_t address) noexcept;
  [[nodiscard]] bool clear_dynamic_ipv4_neighbors(
      DeviceHandle device,
      std::optional<std::uint16_t> port_ordinal = std::nullopt,
      std::optional<std::uint32_t> address = std::nullopt) noexcept;
  [[nodiscard]] bool clear_dynamic_ipv6_neighbors(
      DeviceHandle device,
      std::optional<std::uint16_t> port_ordinal = std::nullopt,
      std::optional<packet::Ipv6> address = std::nullopt) noexcept;
  [[nodiscard]] bool configure_router_advertisement(
      const RouterAdvertisementProgram &program) noexcept;
  [[nodiscard]] bool
  remove_router_advertisement(DeviceHandle device,
                              std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool
  configure_mld_interface(const MldInterfaceProgram &program) noexcept;
  [[nodiscard]] bool remove_mld_interface(DeviceHandle device,
                                          std::uint16_t port_ordinal) noexcept;
  // A complete replacement is streamed and committed atomically on the
  // forwarding owner. Failure aborts staging and preserves the previously
  // active relay policy and UDP socket.
  [[nodiscard]] bool configure_dhcpv6_relay(
      DeviceHandle device,
      const dhcpv6::RelayInterfaceConfig &configuration) noexcept;
  [[nodiscard]] bool
  remove_dhcpv6_relay(DeviceHandle device,
                      std::uint64_t logical_interface_id) noexcept;
  [[nodiscard]] bool clear_dhcpv6_relay_leases(
      DeviceHandle device,
      const Dhcpv6RelayLeaseClearProgram &program) noexcept;
  [[nodiscard]] bool clear_mld_database(
      DeviceHandle device, std::uint16_t port_ordinal,
      const std::optional<packet::Ipv6> &group = std::nullopt) noexcept;
  [[nodiscard]] bool clear_mld_database_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool clear_mld_version(DeviceHandle device,
                                       std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool clear_mld_statistics(DeviceHandle device,
                                          std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool clear_mld_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool edit_mld_static(DeviceHandle device,
                                     std::uint16_t port_ordinal,
                                     MldStaticOperation operation,
                                     const packet::Ipv6 &group,
                                     const packet::Ipv6 &source = {}) noexcept;
  [[nodiscard]] bool
  program_mld_ssm_translation(DeviceHandle device, std::uint16_t port_ordinal,
                              MldSsmProgramOperation operation,
                              const MldSsmTranslation &translation = {},
                              std::uint32_t expected_entries = 0U) noexcept;
  [[nodiscard]] bool program_mld_import_policy(
      DeviceHandle device, std::uint16_t port_ordinal,
      mld::ImportPolicyProgramOperation operation,
      const mld::ImportPolicyEntry &entry = {},
      mld::ImportPolicyAction default_action = mld::ImportPolicyAction::accept,
      std::uint32_t expected_entries = 0U) noexcept;
  [[nodiscard]] bool clear_icmpv4_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv4_global_statistics(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv4_interface_statistics(DeviceHandle device,
                                    std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool clear_icmpv6_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv6_global_statistics(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv6_interface_statistics(DeviceHandle device,
                                    std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool
  clear_router_advertisement_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool clear_router_advertisement_interface_statistics(
      DeviceHandle device, std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] bool configure_host(const HostNetworkProgram &program) noexcept;
  // The network owner receives project entropy through a dedicated erasing
  // SPSC channel. It retains one copy solely for managed DNSSEC checkpoint
  // seal and restore; no packet, telemetry or generic command exposes it.
  [[nodiscard]] bool initialize_signing_vault(
      std::span<const std::uint8_t> wrapping_key,
      const crypto::Sha256Digest &project_context_digest) noexcept;
  // Variable-length DHCP policy is streamed through fixed value messages and
  // committed on one forwarding owner. No vector storage or pointer crosses
  // the SPSC boundary, and a failed transaction keeps the live service.
  [[nodiscard]] bool
  configure_host_dhcpv6_client(const HostDhcpv6ClientProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv6_client(HostHandle host) noexcept;
  [[nodiscard]] bool
  configure_host_dhcpv6_server(const HostDhcpv6ServerProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv6_server(HostHandle host) noexcept;
  [[nodiscard]] std::optional<std::size_t>
  host_dhcpv6_client_lease_count(HostHandle host) noexcept;
  [[nodiscard]] bool
  configure_host_dns_resolver(const HostDnsResolverProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dns_resolver(HostHandle host) noexcept;
  [[nodiscard]] bool configure_host_dns_authoritative(
      const HostDnsAuthoritativeProgram &program) noexcept;
  [[nodiscard]] bool configure_host_dns_signed_authoritative(
      const HostDnsSignedAuthoritativeProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dns_authoritative(HostHandle host) noexcept;
  [[nodiscard]] std::optional<dns::TransactionHandle>
  start_host_dns_query(HostHandle host, const packet::dns::Question &question,
                       Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<dns::ResolutionResult>
  host_dns_result(HostHandle host, dns::TransactionHandle transaction);
  [[nodiscard]] bool
  release_host_dns_query(HostHandle host,
                         dns::TransactionHandle transaction) noexcept;

  // A link program is atomic for both directions. Failure leaves the prior
  // generation untouched, so control can report the rejected transaction.
  [[nodiscard]] bool configure_link(const NetworkLinkProgram &program) noexcept;
  [[nodiscard]] bool remove_link(LinkHandle link) noexcept;
  [[nodiscard]] bool
  configure_capture_point(const CapturePointProgram &program) noexcept;
  void prepare_capture();
  [[nodiscard]] bool clear_capture() noexcept;
  [[nodiscard]] std::span<const std::uint8_t> prepared_capture() const noexcept;
  [[nodiscard]] std::size_t captured_frames() const noexcept;
  [[nodiscard]] std::uint64_t capture_dropped() const noexcept;
  // Includes medium queue loss and all explicit cross-shard transfer losses.
  // It excludes capture loss because observation must not affect network
  // forwarding counters.
  [[nodiscard]] std::uint64_t dropped_packets() const noexcept;
  [[nodiscard]] std::optional<NetworkPlaneCheckpoint>
  checkpoint(Clock::time_point now = Clock::now());
  [[nodiscard]] std::optional<RouterForwarderCheckpoint>
  router_checkpoint(DeviceHandle device, Clock::time_point now = Clock::now());
  [[nodiscard]] bool restore(const NetworkPlaneCheckpoint &state,
                             Clock::time_point now = Clock::now());

  // Ping starts an asynchronous protocol operation. Completion becomes true
  // only after an encoded reply returns through the physical packet path.
  [[nodiscard]] bool start_router_ping(DeviceHandle device,
                                       std::uint32_t destination,
                                       std::uint16_t sequence,
                                       Clock::time_point now,
                                       std::uint16_t payload_octets = 56,
                                       bool dont_fragment = false) noexcept;
  [[nodiscard]] bool
  start_router_ipv6_ping(DeviceHandle device, const packet::Ipv6 &destination,
                         std::uint16_t sequence, Clock::time_point now,
                         std::uint16_t payload_octets = 56) noexcept;
  [[nodiscard]] bool start_host_ping(HostHandle host, packet::Ipv4 destination,
                                     std::uint16_t sequence) noexcept;
  [[nodiscard]] bool router_ping_reply(DeviceHandle device,
                                       std::uint16_t sequence) noexcept;
  [[nodiscard]] std::uint64_t
  router_ping_outcome(DeviceHandle device, std::uint16_t sequence) noexcept;
  [[nodiscard]] bool router_ipv6_ping_reply(DeviceHandle device,
                                            std::uint16_t sequence) noexcept;
  [[nodiscard]] std::uint64_t
  router_ipv6_ping_outcome(DeviceHandle device,
                           std::uint16_t sequence) noexcept;
  [[nodiscard]] bool host_ping_reply(HostHandle host,
                                     std::uint16_t sequence) noexcept;

  // pump runs one bounded forwarding and medium turn at steady-clock now. It
  // never advances a virtual clock and never executes work from a global heap.
  void pump(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::size_t active_links() const noexcept;

  // The outer link worker installs a wake callback so forwarding egress can
  // interrupt its deadline wait without polling. Callback lifetime is bounded
  // by NetworkPlaneWorker, which clears it only after all forwarding owners
  // have joined during NetworkPlane destruction.
  void set_link_wakeup(void *context, void (*wakeup)(void *)) noexcept;
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept;
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept;
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept;
  // The OSPF owner exists at NetworkPlane construction, before any router or
  // CLI command. Zero means its run loop has not published startup yet.
  [[nodiscard]] std::uint64_t ospf_owner_thread_id() const noexcept;

private:
  // PIMPL keeps the large fixed arenas and internal endpoint stack out of every
  // control translation unit. The object is still allocated once at startup.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace router::lab
