// Owner-local OSPF instance process. One control shard owns every object in
// this module. It accepts validated IP payloads, advances interface and
// neighbor state machines, owns the LSDB and produces encoded OSPF packets.
// Forwarding remains responsible for IP, Ethernet, adjacency and link queues.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ospf_configuration.hpp"
#include "router/ospf_database_exchange.hpp"
#include "router/ospf_interface.hpp"
#include "router/ospf_lsa_builder.hpp"
#include "router/ospf_route_calculator.hpp"
#include "router/ospf_spf.hpp"
#include "router/ospf_topology.hpp"
#include "router/packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <type_traits>
#include <vector>

namespace router::ospf {

// Passive loopback interfaces participate in LSA origination but own no
// Ethernet port and can never send or receive a protocol frame. The maximum
// uint16 value is outside every generated physical-port ordinal domain.
inline constexpr std::uint16_t no_physical_port =
    std::numeric_limits<std::uint16_t>::max();

enum class PacketDestination : std::uint8_t {
  all_spf_routers,
  all_dr_routers,
  neighbor_unicast
};

struct ProcessInterfaceConfiguration {
  InterfaceConfiguration protocol{};
  ip::Ipv4 ipv4_source{};
  ip::Ipv6 ipv6_source{};
  ip::Ipv6 ipv6_prefix{};
  packet::Mac source_mac{};
  std::uint16_t physical_port_ordinal{};
  // metric is the operational value advertised on the wire. Candidate cost
  // zero is resolved before this boundary from the instance reference
  // bandwidth and the physical port's configured speed.
  std::uint16_t metric{};
  std::uint16_t retransmit_interval_seconds{};
  std::uint16_t transmit_delay_seconds{};
  std::uint8_t prefix_length{};
  // A nonzero value identifies the configured peer of a virtual link. The
  // physical port remains the real transit-area egress selected by SPF, while
  // this Router ID demultiplexes multiple backbone virtual adjacencies that
  // may arrive through that same port.
  std::uint32_t virtual_neighbor_router_id{};
  // Virtual links always transmit unicast. OSPFv2 stores the peer's transit
  // interface address in the first four bytes; OSPFv3 stores the global-scope
  // LA prefix learned from the peer's transit-area Intra-Area-Prefix-LSA.
  ip::IpAddress virtual_neighbor_address{};
  bool operator==(const ProcessInterfaceConfiguration &) const = default;
};

struct VirtualLinkResolution {
  // This value is a read-only projection of one completed transit-area SPF
  // generation. The backbone owner copies it when materializing its virtual
  // interface and never retains references into topology or LSDB storage.
  ip::IpAddress local_address{};
  ip::IpAddress remote_address{};
  packet::Mac source_mac{};
  std::uint32_t local_physical_interface_id{};
  std::uint32_t remote_router_id{};
  std::uint32_t cost{};
  std::uint16_t physical_port_ordinal{};
  std::uint16_t interface_mtu{};
  bool remote_address_known{};
};

struct ProcessNbmaNeighborConfiguration {
  // The canonical configuration owner resolves the address family before the
  // record crosses the control ring. The OSPF owner retains only this value,
  // the source-advertised Router ID learned from a Hello, and its local poll
  // deadline. No editor edge or remote router object is consulted.
  ip::IpAddress address{};
  std::uint16_t poll_interval_seconds{};
  std::uint8_t priority{};
};

struct ProcessVirtualLinkConfiguration {
  // The management owner allocates a router-unique logical Interface ID.
  // Transit SPF supplies the changing physical transport and metric later.
  std::uint32_t interface_id{};
  std::uint32_t transit_area_id{};
  std::uint32_t remote_router_id{};
  std::uint16_t hello_interval_seconds{};
  std::uint16_t dead_interval_seconds{};
  std::uint16_t retransmit_interval_seconds{};
  std::uint16_t transmit_delay_seconds{};
  std::uint32_t options{};
  AuthenticationMode authentication{AuthenticationMode::none};
  bool admin_enabled{};
};

struct ProcessAuthentication {
  // The management owner opens SecretVault only long enough to prepare the
  // selected key. This buffer is private to the protocol shard, never enters
  // telemetry, and is cleansed when replaced or when the process is destroyed.
  // Nokia protected key input can exceed 64 octets. The bounded 128-octet
  // storage admits the documented keychain domain while retaining a trivially
  // copyable control-ring value and avoiding heap-backed secret material.
  std::array<std::uint8_t, 128U> key{};
  std::uint64_t initial_sequence{};
  // Checkpoints persist only this opaque SecretVault identity and purpose.
  // The management owner reopens and injects key bytes before operational
  // state reaches ControlWorker. The protocol owner never dereferences it.
  std::uint64_t secret_handle{};
  std::uint16_t key_size{};
  // OSPFv2 consumes the low eight bits as Key ID. OSPFv3 carries the complete
  // 16-bit Security Association ID, so validation rejects values that cannot
  // be represented by the selected protocol version.
  std::uint16_t key_id{};
  KeychainAlgorithm algorithm{KeychainAlgorithm::password};
  std::uint8_t secret_kind{};
  // RFC 4302 AH and RFC 7166 Authentication Trailer use different packet
  // envelopes even when both ultimately invoke HMAC. This discriminator
  // prevents an IPsec SA from being encoded as an OSPF authentication trailer
  // merely because the key algorithm happens to match.
  bool ipsec_ah{};
  // Keychain wall-clock lifetimes are configuration semantics, not simulated
  // time. The protocol owner evaluates them when it sends or authenticates a
  // packet, so rollover takes effect without republishing configuration or
  // introducing a polling task. Direct interface keys leave timed false.
  std::int64_t begin_utc_seconds{};
  std::optional<std::int64_t> end_utc_seconds;
  std::uint32_t tolerance_seconds{};
  bool timed{};
  bool operator==(const ProcessAuthentication &) const = default;
};

struct ProcessInterfaceSnapshot {
  // This value crosses only the synchronous control query channel. It is a
  // copy of one owner-local interface generation and contains no pointer into
  // the protocol process, so the next timer or packet turn cannot invalidate
  // management output already being formatted.
  ProcessInterfaceConfiguration configuration{};
  InterfaceState state{InterfaceState::down};
  std::uint32_t designated_router{};
  std::uint32_t backup_designated_router{};
  std::uint32_t neighbor_count{};
};

struct ProcessNeighborSnapshot {
  // The neighbor FSM row and its received transport address are copied
  // together. Management must never infer a neighbor address from editor
  // topology or another router's interface configuration.
  NeighborRuntime runtime{};
  ip::Ipv4 ipv4_address{};
  ip::Ipv6 ipv6_address{};
  // Exchange diagnostics remain owner-produced values. They let integration
  // tests distinguish a missing Ethernet observation from an OSPF DD state
  // machine failure without reading or exposing the mutable exchange object.
  std::uint32_t dd_sequence{};
  std::uint32_t local_interface_id{};
  std::uint32_t retransmission_queue_length{};
  std::uint32_t request_queue_length{};
  std::uint32_t up_time_seconds{};
  std::uint32_t time_before_dead_seconds{};
  std::uint32_t last_event_seconds_ago{};
  std::uint32_t last_restart_seconds_ago{};
  std::uint32_t graceful_restart_helper_age_seconds{};
  bool negotiation_complete{};
  bool database_description_pending{};
  bool local_master{};
  bool graceful_restart_helper{};
};

static_assert(std::is_trivially_copyable_v<ProcessInterfaceSnapshot>);
static_assert(std::is_trivially_copyable_v<ProcessNeighborSnapshot>);

struct ProcessOutput {
  // The process writes one complete OSPF packet. The forwarding owner wraps
  // exactly `size` octets in the address-family envelope selected by version.
  // The fixed storage is a queue payload bound, not an OSPF wire limitation.
  std::array<std::uint8_t, packet::maximum_frame_octets> bytes{};
  ip::Ipv4 ipv4_destination{};
  ip::Ipv6 ipv6_destination{};
  ip::Ipv4 ipv4_source{};
  ip::Ipv6 ipv6_source{};
  packet::Mac source_mac{};
  std::uint32_t neighbor_router_id{};
  std::uint32_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint16_t size{};
  PacketDestination destination{PacketDestination::all_spf_routers};
  // Multicast OSPF is link-local and therefore leaves with one remaining
  // hop. A virtual adjacency is routed through its transit area, so its
  // unicast envelope uses the release-profile IP default instead. Keeping
  // the value on the output preserves the process owner's knowledge of the
  // logical interface and keeps the forwarding bridge policy-free.
  std::uint8_t hop_limit{1U};
  std::uint8_t version{};
};

enum class ReceiveStatus : std::uint8_t {
  accepted,
  ignored,
  interface_not_found,
  malformed,
  version_mismatch,
  checksum_failure,
  authentication_failure,
  rejected_hello,
  neighbor_not_found,
  invalid_neighbor_state,
  resource_exhausted
};

enum class RouteRecalculationStatus : std::uint8_t {
  never_run,
  succeeded,
  topology_rejected,
  spf_rejected,
  route_derivation_rejected,
  egress_interface_missing,
  allocation_failed
};

enum class RunReadyStatus : std::uint8_t {
  succeeded,
  output_budget_exhausted,
  deadline_budget_exhausted,
  local_origination_rejected,
  route_recalculation_rejected,
  hello_encoding_rejected,
  acknowledgment_encoding_rejected,
  database_description_encoding_rejected,
  update_encoding_rejected,
  request_encoding_rejected
};

enum class LocalOriginationStatus : std::uint8_t {
  succeeded,
  router_encoding_rejected,
  router_install_rejected,
  router_flood_rejected,
  network_encoding_rejected,
  network_install_rejected,
  network_flood_rejected,
  prefix_encoding_rejected,
  prefix_install_rejected,
  prefix_flood_rejected,
  link_encoding_rejected,
  link_install_rejected,
  link_flood_rejected,
  router_information_encoding_rejected,
  router_information_install_rejected,
  router_information_flood_rejected,
  sequence_exhausted,
  allocation_failed
};

enum class CoordinatorAdvertisementKind : std::uint8_t {
  inter_area_prefix,
  inter_area_router,
  translated_external,
  // Local redistribution in an NSSA originates a Type 7, while Type 5 stays
  // AS-scoped. A separate semantic kind makes that flooding boundary explicit.
  nssa_external
};

struct CoordinatorAdvertisement {
  // The ABR coordinator supplies protocol semantics, never prebuilt bytes.
  // InstanceProcess assigns and retains the local Link State ID and sequence,
  // encodes the correct version-specific LSA and floods it through ordinary
  // adjacency retransmission state.
  ip::IpPrefix prefix{};
  std::uint32_t destination_router_id{};
  std::uint32_t metric{};
  std::uint32_t internal_metric{};
  std::uint32_t forwarding_address_v4{};
  ip::Ipv6 forwarding_address_v6{};
  std::uint32_t tag{};
  std::uint32_t source_link_state_id{};
  CoordinatorAdvertisementKind kind{
      CoordinatorAdvertisementKind::inter_area_prefix};
  bool type_two{};
  bool ipv4_forwarding_address{};

  [[nodiscard]] friend bool
  operator==(const CoordinatorAdvertisement &,
             const CoordinatorAdvertisement &) noexcept = default;
};

struct NeighborExchangeCheckpoint {
  NeighborDatabaseExchangeCheckpoint database;
  std::uint32_t router_id{};
  std::uint32_t dd_sequence{};
  std::size_t summary_cursor{};
  std::size_t request_cursor{};
  std::size_t update_cursor{};
  std::chrono::milliseconds dd_retransmit_remaining{};
  std::chrono::milliseconds request_retransmit_remaining{};
  std::chrono::milliseconds update_retransmit_remaining{};
  ip::Ipv4 ipv4_address{};
  ip::Ipv6 ipv6_address{};
  std::array<std::uint64_t, 5U> authentication_sequences{};
  std::array<bool, 5U> authentication_sequence_seen{};
  std::chrono::milliseconds helper_remaining{};
  std::chrono::milliseconds helper_elapsed{};
  bool local_master{};
  bool negotiation_complete{};
  bool pending_database_description{};
  bool pending_request{};
  bool pending_update{};
  bool pending_acknowledgment{};
  bool peer_more{};
  bool sent_more{};
  bool complete_after_reply{};
  bool helper_active{};
  bool helper_was_designated_router{};
};

struct ProcessInterfaceCheckpoint {
  struct NbmaPeer {
    ProcessNbmaNeighborConfiguration configuration{};
    std::chrono::milliseconds hello_remaining{};
    std::uint32_t router_id{};
  };

  ProcessInterfaceConfiguration configuration;
  InterfaceRuntimeCheckpoint runtime;
  std::vector<NeighborExchangeCheckpoint> exchanges;
  std::vector<NbmaPeer> nbma_peers;
  std::optional<ProcessAuthentication> send_authentication;
  std::vector<ProcessAuthentication> receive_authentications;
  std::uint64_t authentication_sequence{};
  std::uint16_t authentication_send_key_id{};
  std::uint32_t ipsec_replay_sequence{};
  std::int32_t network_lsa_sequence{initial_sequence_number};
  std::int32_t network_prefix_lsa_sequence{initial_sequence_number};
  std::int32_t link_lsa_sequence{initial_sequence_number};
  bool authentication_required{};
  bool ipsec_replay_sequence_seen{};
  bool network_lsa_originated{};
  bool network_sequence_at_max{};
  bool network_prefix_sequence_at_max{};
  bool link_sequence_at_max{};
  bool network_sequence_wrap_pending{};
  bool network_prefix_sequence_wrap_pending{};
  bool link_sequence_wrap_pending{};
};

struct PendingFightBackCheckpoint {
  LsaKey key;
  std::vector<std::uint8_t> bytes;
};

struct CoordinatorLsaCheckpoint {
  CoordinatorAdvertisement advertisement{};
  LsaKey key{};
  std::int32_t sequence{initial_sequence_number};
  bool withdrawing{};
  bool sequence_at_max{};
  bool sequence_wrap_pending{};
};

struct InstanceProcessCheckpoint {
  LinkStateDatabaseCheckpoint database;
  std::vector<ProcessInterfaceCheckpoint> interfaces;
  std::vector<PendingFightBackCheckpoint> pending_fight_backs;
  std::vector<LsaKey> pending_sequence_wraps;
  std::vector<CoordinatorLsaCheckpoint> coordinator_lsas;
  std::vector<ip::Ipv6> virtual_endpoint_addresses;
  std::vector<CoordinatorAdvertisement>
      pending_coordinator_advertisements;
  std::chrono::milliseconds last_local_origination_age{};
  std::chrono::milliseconds local_origination_remaining{};
  std::chrono::milliseconds spf_remaining{};
  std::chrono::milliseconds last_spf_started_age{};
  std::chrono::milliseconds current_lsa_delay{};
  std::chrono::milliseconds current_spf_delay{};
  std::uint64_t route_generation{};
  std::uint32_t next_dd_sequence{};
  std::uint32_t next_coordinator_link_state_id{};
  std::int32_t router_lsa_sequence{initial_sequence_number};
  std::int32_t prefix_lsa_sequence{initial_sequence_number};
  std::int32_t router_information_lsa_sequence{initial_sequence_number};
  RouteRecalculationStatus route_recalculation_status{
      RouteRecalculationStatus::never_run};
  RunReadyStatus run_ready_status{RunReadyStatus::succeeded};
  LocalOriginationStatus local_origination_status{
      LocalOriginationStatus::succeeded};
  InstallResult local_origination_install_result{
      InstallResult::installed};
  bool coordinator_reconcile_pending{};
  bool router_sequence_at_max{};
  bool prefix_sequence_at_max{};
  bool router_information_sequence_at_max{};
  bool router_sequence_wrap_pending{};
  bool prefix_sequence_wrap_pending{};
  bool router_information_sequence_wrap_pending{};
  bool area_border_router{};
  bool autonomous_system_boundary_router{};
  bool virtual_link_endpoint{};
  bool overload{};
  bool graceful_restart_helper{};
  bool loop_free_alternates{};
};

class InstanceProcess final {
public:
  // initial_dd_sequence is supplied by the process supervisor from its secure
  // per-instance sequence source. Requiring it explicitly prevents a constant
  // or editor-derived sequence from entering Database Description exchange.
  InstanceProcess(std::uint32_t router_id, std::uint32_t area_id,
                  std::uint8_t version, std::uint8_t instance_id,
                  std::uint32_t initial_dd_sequence,
                  std::size_t maximum_interfaces,
                  std::size_t maximum_neighbors_per_interface,
                  std::size_t maximum_lsas,
                  std::chrono::milliseconds lsa_initial_wait =
                      device_catalog::ospf_lsa_initial_wait,
                  std::chrono::milliseconds lsa_second_wait =
                      device_catalog::ospf_lsa_second_wait,
                  std::chrono::milliseconds lsa_maximum_wait =
                      device_catalog::ospf_lsa_maximum_wait,
                  std::chrono::milliseconds spf_initial_wait =
                      device_catalog::ospf_spf_initial_wait,
                  std::chrono::milliseconds spf_second_wait =
                      device_catalog::ospf_spf_second_wait,
                  std::chrono::milliseconds spf_maximum_wait =
                      device_catalog::ospf_spf_maximum_wait);
  ~InstanceProcess();

  [[nodiscard]] bool add_interface(
      const ProcessInterfaceConfiguration &configuration,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool set_interface_authentication(
      std::uint32_t interface_id,
      const std::optional<ProcessAuthentication> &send_authentication,
      std::span<const ProcessAuthentication> receive_authentications = {})
      noexcept;
  [[nodiscard]] bool add_nbma_neighbor(
      std::uint32_t interface_id,
      const ProcessNbmaNeighborConfiguration &configuration,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool remove_interface(
      std::uint32_t interface_id, RuntimeClock::time_point now) noexcept;
  // Replaces one dynamically resolved virtual interface. A transport or cost
  // change intentionally resets its adjacency because packets in the prior
  // retransmission generation were bound to a different transit SPF result.
  [[nodiscard]] bool replace_virtual_interface(
      const ProcessInterfaceConfiguration &configuration,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool remove_virtual_interface(
      std::uint32_t interface_id,
      RuntimeClock::time_point now) noexcept;

  // Replaces this area's ABR-owned LSA set. New and changed advertisements
  // receive monotonically newer sequence numbers. Removed advertisements are
  // prematurely aged and reliably flooded before their owner state is
  // discarded. The method is called only by the OSPF pthread after comparing
  // all areas of one router and instance.
  [[nodiscard]] bool reconcile_coordinator_advertisements(
      std::span<const CoordinatorAdvertisement> advertisements,
      RuntimeClock::time_point now) noexcept;
  // ABR and ASBR bits are derived by the owner from running area and export
  // state, never accepted from a packet or UI. A changed role schedules a
  // normal paced Router-LSA replacement.
  void set_router_roles(bool area_border_router,
                        bool autonomous_system_boundary_router,
                        bool virtual_link_endpoint, bool overload,
                        RuntimeClock::time_point now) noexcept;
  // Preferences are RIB policy and never alter the on-wire SPF metric.
  // Updating them affects only subsequently published complete generations.
  void set_route_preferences(std::uint32_t router_preference,
                             std::uint32_t external_preference) noexcept;
  // Enabling or disabling local LFA changes only the complete route
  // generation. It does not alter LSAs, neighbor state or SPF primary costs.
  void set_loop_free_alternates(bool enabled,
                                RuntimeClock::time_point now) noexcept;
  void set_graceful_restart_helper(bool enabled) noexcept {
    graceful_restart_helper_ = enabled;
  }

  // receive_packet consumes an OSPF packet after forwarding validated TTL,
  // Hop Limit, source scope and destination ownership. This owner repeats the
  // version checksum and protocol compatibility checks before changing state.
  [[nodiscard]] ReceiveStatus receive_packet(
      std::uint32_t interface_id, std::span<const std::uint8_t> ospf_packet,
      const ip::Ipv6 &ipv6_source, const ip::Ipv6 &ipv6_destination,
      RuntimeClock::time_point now) noexcept;
  // IPsec transport authentication is verified over the complete IPv6 packet
  // before its OSPF payload reaches the ordinary decoder. These methods stay
  // on the process owner so keys and replay state never cross into forwarding.
  [[nodiscard]] std::optional<std::span<const std::uint8_t>>
  protect_ipv6_ipsec_packet(
      std::uint32_t interface_id, const ip::Ipv6 &source,
      const ip::Ipv6 &destination, std::uint8_t hop_limit,
      std::span<const std::uint8_t> ospf_packet,
      std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] bool
  ipsec_authentication_configured(
      std::uint32_t interface_id) const noexcept;
  [[nodiscard]] ReceiveStatus receive_ipv6_ipsec_packet(
      std::uint32_t interface_id,
      std::span<const std::uint8_t> ipv6_packet,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] ReceiveStatus receive_ipv4_packet(
      std::uint32_t interface_id, std::span<const std::uint8_t> ospf_packet,
      const ip::Ipv4 &ipv4_source, const ip::Ipv4 &ipv4_destination,
      RuntimeClock::time_point now) noexcept;
  // Operational reset is executed by the sole protocol owner. A zero filter
  // means every matching row, while nonzero identities constrain the reset
  // without exposing mutable neighbor objects to management code.
  [[nodiscard]] std::size_t reset_neighbors(
      std::uint32_t interface_id, std::uint32_t neighbor_router_id,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool reset_database(
      RuntimeClock::time_point now) noexcept;

  // run_ready writes at most output.size() packets. false means ready work
  // remains and the shard must run another budgeted turn without sleeping.
  [[nodiscard]] bool run_ready(RuntimeClock::time_point now,
                               std::span<ProcessOutput> output,
                               std::size_t &written) noexcept;
  [[nodiscard]] std::optional<RuntimeClock::time_point>
  next_deadline() const noexcept;

  [[nodiscard]] const LinkStateDatabase &database() const noexcept {
    return database_;
  }
  // The returned span belongs to this process owner and remains valid only
  // until its next successful SPF publication. Cross-shard publication must
  // copy the complete generation into its bounded route message.
  [[nodiscard]] std::span<const CalculatedRoute> routes() const noexcept {
    return route_calculator_.routes();
  }
  [[nodiscard]] std::uint64_t route_generation() const noexcept {
    return route_generation_;
  }
  [[nodiscard]] RouteRecalculationStatus
  route_recalculation_status() const noexcept {
    return route_recalculation_status_;
  }
  [[nodiscard]] RunReadyStatus run_ready_status() const noexcept {
    return run_ready_status_;
  }
  [[nodiscard]] LocalOriginationStatus
  local_origination_status() const noexcept {
    return local_origination_status_;
  }
  [[nodiscard]] InstallResult
  local_origination_install_result() const noexcept {
    return local_origination_install_result_;
  }
  [[nodiscard]] std::span<const lab::routing::DynamicInput>
  ipv4_route_inputs() const noexcept {
    return ipv4_route_inputs_;
  }
  [[nodiscard]] std::span<const lab::routing::Ipv6DynamicInput>
  ipv6_route_inputs() const noexcept {
    return ipv6_route_inputs_;
  }
  [[nodiscard]] std::optional<NeighborState>
  neighbor_state(std::uint32_t interface_id,
                 std::uint32_t neighbor_router_id) const noexcept;
  [[nodiscard]] std::optional<InterfaceState>
  interface_state(std::uint32_t interface_id) const noexcept;
  [[nodiscard]] std::optional<std::uint32_t>
  designated_router(std::uint32_t interface_id) const noexcept;
  [[nodiscard]] std::optional<std::uint32_t>
  interface_id_for_port(std::uint16_t physical_port_ordinal) const noexcept;
  // Virtual-link receive demultiplexing uses both the real ingress port and
  // the packet Router ID, as required by RFC 2328 section 15 and RFC 5340
  // section 4.2.2. A physical interface is preferred only when its process
  // area already matches the packet area selected by ControlWorker.
  [[nodiscard]] std::optional<std::uint32_t>
  interface_id_for_packet(std::uint16_t physical_port_ordinal,
                          std::uint32_t source_router_id) const noexcept;
  // Resolves a configured endpoint solely from this transit area's accepted
  // LSDB and published SPF tree. Absence means the endpoint is unreachable or
  // its standards-required transport address cannot yet be discovered.
  [[nodiscard]] std::optional<VirtualLinkResolution>
  resolve_virtual_link(std::uint32_t remote_router_id) const noexcept;
  // OSPFv3 advertises one global-scope LA /128 while at least one configured
  // virtual link traverses this area. Replacement is owner-local and schedules
  // normal paced origination only when the semantic address set changes.
  [[nodiscard]] bool set_virtual_endpoint_addresses(
      std::span<const ip::Ipv6> addresses,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::size_t interface_count() const noexcept {
    return interfaces_.size();
  }
  // These query methods are called only on the OSPF owner pthread. They copy
  // immutable projections into value records and never lend references to
  // interface, neighbor or exchange state across the ownership boundary.
  [[nodiscard]] std::optional<ProcessInterfaceSnapshot>
  interface_snapshot(std::size_t index) const noexcept;
  [[nodiscard]] std::optional<ProcessNeighborSnapshot>
  neighbor_snapshot(std::size_t interface_index,
                    std::size_t neighbor_index) const noexcept;
  [[nodiscard]] std::uint32_t router_id() const noexcept {
    return router_id_;
  }
  [[nodiscard]] InstanceProcessCheckpoint
  checkpoint(RuntimeClock::time_point now) const;
  // Restore is transactional at the process boundary. The caller constructs a
  // fresh process with the checkpoint's immutable configuration before this
  // method stages and validates every bounded operational repository.
  [[nodiscard]] bool restore(const InstanceProcessCheckpoint &checkpoint,
                             RuntimeClock::time_point now) noexcept;

private:
  struct NeighborExchange {
    NeighborDatabaseExchange database;
    std::uint32_t router_id{};
    std::uint32_t dd_sequence{};
    std::size_t summary_cursor{};
    std::size_t request_cursor{};
    std::size_t update_cursor{};
    RuntimeClock::time_point dd_retransmit_deadline{};
    RuntimeClock::time_point request_retransmit_deadline{};
    RuntimeClock::time_point update_retransmit_deadline{};
    ip::Ipv4 ipv4_address{};
    ip::Ipv6 ipv6_address{};
    // RFC 2328 replay protection is maintained independently for each packet
    // type because control prioritization can reorder different OSPF classes.
    // RFC 7166 uses a 64-bit sequence while OSPFv2 uses 32 bits. One widened
    // representation preserves both wire domains and keeps replay comparison
    // identical after authentication succeeds.
    std::array<std::uint64_t, 5U> authentication_sequences{};
    std::array<bool, 5U> authentication_sequence_seen{};
    bool local_master{};
    bool negotiation_complete{};
    bool pending_database_description{};
    bool pending_request{};
    bool pending_update{};
    bool pending_acknowledgment{};
    bool peer_more{};
    bool sent_more{};
    bool complete_after_reply{};
    // RFC 3623 helper state is per adjacency and per segment. The neighbor may
    // restart its FSM while the helper continues to advertise the preserved
    // Full relationship until this steady-clock deadline.
    RuntimeClock::time_point helper_deadline{};
    RuntimeClock::time_point helper_started_at{};
    bool helper_active{};
    bool helper_was_designated_router{};

    NeighborExchange(std::uint32_t id, std::size_t maximum_lsas)
        : database(maximum_lsas, maximum_lsas, maximum_lsas, maximum_lsas),
          router_id(id) {}
  };

  struct InterfaceOwner {
    struct NbmaPeer {
      ProcessNbmaNeighborConfiguration configuration{};
      RuntimeClock::time_point hello_deadline{};
      // Router ID becomes known only from an authenticated, compatible Hello.
      // Keeping address and Router ID separate follows RFC 2328 section 10:
      // NBMA configuration identifies a transport peer, while the packet
      // identifies the OSPF neighbor.
      std::uint32_t router_id{};
    };

    ProcessInterfaceConfiguration configuration;
    InterfaceRuntime runtime;
    std::vector<NeighborExchange> exchanges;
    std::vector<NbmaPeer> nbma_peers;
    // The selected send key is singular, while a rollover window can make
    // several keyed receive entries valid at once. The protocol pthread owns
    // both containers and scrubs every fixed key buffer before replacement or
    // destruction. A packet selects receive material only by its wire Key ID.
    std::optional<ProcessAuthentication> send_authentication;
    std::vector<ProcessAuthentication> receive_authentications;
    std::uint64_t authentication_sequence{};
    std::uint16_t authentication_send_key_id{};
    bool authentication_required{};
    // AH anti-replay is per inbound SA, not per OSPF packet type. A separate
    // sequence owner is therefore required from the RFC 7166 and RFC 5709
    // replay arrays held by each neighbor exchange.
    std::uint32_t ipsec_replay_sequence{};
    bool ipsec_replay_sequence_seen{};
    // Election reconciliation is owner-local scratch storage. It is sized once
    // with the same neighbor bound as the FSM repository so a Hello or
    // WaitTimer never allocates while changing adjacency eligibility.
    std::vector<NeighborReconciliation> reconciliation;
    // Each DR-owned Network-LSA is an independent self-originated sequence.
    // The flag distinguishes "never originated" from "lost DR role and must
    // flush the previous instance at MaxAge".
    std::int32_t network_lsa_sequence{initial_sequence_number};
    std::int32_t network_prefix_lsa_sequence{initial_sequence_number};
    std::int32_t link_lsa_sequence{initial_sequence_number};
    bool network_lsa_originated{};
    bool network_sequence_at_max{};
    bool network_prefix_sequence_at_max{};
    bool link_sequence_at_max{};
    bool network_sequence_wrap_pending{};
    bool network_prefix_sequence_wrap_pending{};
    bool link_sequence_wrap_pending{};

    InterfaceOwner(const ProcessInterfaceConfiguration &value,
                   std::size_t maximum_neighbors,
                   RuntimeClock::time_point now)
        : configuration(value),
          runtime(value.protocol, maximum_neighbors, now),
          reconciliation(maximum_neighbors) {
      exchanges.reserve(maximum_neighbors);
      nbma_peers.reserve(maximum_neighbors);
      receive_authentications.reserve(64U);
    }
  };

  struct PendingFightBack {
    // A received self-originated generation is retained only until the
    // MinLSInterval-controlled owner turn. Keeping complete encoded bytes is
    // necessary for the MaxSequenceNumber flush: reconstructing unknown or
    // no-longer-originated LSA bodies would invent protocol data.
    LsaKey key;
    std::vector<std::uint8_t> bytes;
  };

  struct CoordinatorLsaState {
    CoordinatorAdvertisement advertisement{};
    LsaKey key{};
    std::int32_t sequence{initial_sequence_number};
    bool withdrawing{};
    bool sequence_at_max{};
    bool sequence_wrap_pending{};
  };

  [[nodiscard]] InterfaceOwner *
  interface(std::uint32_t interface_id) noexcept;
  [[nodiscard]] NeighborExchange *
  exchange(InterfaceOwner &owner, std::uint32_t router_id,
           bool create) noexcept;
  [[nodiscard]] bool advertised_full(
      const InterfaceOwner &owner, std::uint32_t router_id,
      RuntimeClock::time_point now) const noexcept;
  void terminate_grace_helpers(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool emit_hello(InterfaceOwner &owner,
                                ProcessOutput &output) noexcept;
  [[nodiscard]] bool emit_nbma_hello(
      InterfaceOwner &owner, const InterfaceOwner::NbmaPeer &peer,
      ProcessOutput &output) noexcept;
  [[nodiscard]] bool emit_database_description(
      InterfaceOwner &owner, NeighborExchange &neighbor,
      ProcessOutput &output, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool emit_link_state_request(
      InterfaceOwner &owner, NeighborExchange &neighbor,
      ProcessOutput &output, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool emit_link_state_update(
      InterfaceOwner &owner, NeighborExchange &neighbor,
      ProcessOutput &output, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool emit_link_state_acknowledgment(
      InterfaceOwner &owner, NeighborExchange &neighbor,
      ProcessOutput &output) noexcept;
  [[nodiscard]] bool encode_output(
      InterfaceOwner &owner, NeighborExchange *neighbor,
      packet::ospf::PacketType type, std::span<const std::uint8_t> body,
      ProcessOutput &output,
      const ip::IpAddress *explicit_unicast = nullptr) noexcept;
  [[nodiscard]] ReceiveStatus receive_validated(
      InterfaceOwner &owner, const packet::ospf::PacketView &packet,
      const ip::Ipv4 &ipv4_source, const ip::Ipv6 &ipv6_source,
      RuntimeClock::time_point now,
      bool outer_ipsec_verified = false) noexcept;
  // Apply every side effect emitted by one Neighbor FSM transition. Keeping
  // this in one owner method prevents Hello, WaitTimer and expiry paths from
  // initializing Database Description exchange differently.
  [[nodiscard]] bool apply_neighbor_actions(
      InterfaceOwner &owner, std::uint32_t router_id,
      NeighborAction actions, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool reconcile_interface_adjacencies(
      InterfaceOwner &owner, InterfaceAction actions,
      RuntimeClock::time_point now) noexcept;
  void schedule_local_origination(RuntimeClock::time_point now) noexcept;
  void schedule_spf(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool
  originate_local_lsas(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool recalculate_routes(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool append_route_input(
      const CalculatedRoute &route, const CalculatedNextHop &next_hop,
      bool loop_free_alternate,
      std::vector<lab::routing::DynamicInput> &ipv4,
      std::vector<lab::routing::Ipv6DynamicInput> &ipv6) const noexcept;
  [[nodiscard]] bool flood_record(const LsaRecord &record,
                                  RuntimeClock::time_point now,
                                  std::optional<std::uint32_t>
                                      link_interface = std::nullopt) noexcept;
  // Database aging is an owner-local maintenance turn. It never scans or
  // mutates another process and it never creates a global timer: next_deadline
  // derives the earliest refresh or MaxAge point from this instance's records.
  [[nodiscard]] bool
  maintain_database(RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool
  max_age_removal_safe(const LsaKey &key) const noexcept;
  [[nodiscard]] std::optional<RuntimeClock::time_point>
  database_deadline() const noexcept;
  [[nodiscard]] bool queue_fight_back(
      std::span<const std::uint8_t> encoded_lsa,
      const packet::ospf::LsaHeaderView &header,
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool apply_pending_fight_backs(
      RuntimeClock::time_point now, bool &wrap_started) noexcept;
  [[nodiscard]] bool set_self_sequence(
      const LsaKey &key, std::int32_t sequence,
      bool wrap_pending) noexcept;
  [[nodiscard]] bool self_sequence_supported(
      const LsaKey &key) const noexcept;
  void complete_sequence_wrap(const LsaKey &key,
                              RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool start_sequence_wrap(
      const LsaKey &key, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool flush_exhausted_sequences(
      RuntimeClock::time_point now, bool &wrap_started) noexcept;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  encode_coordinator_lsa(const CoordinatorLsaState &state,
                         std::uint16_t age) const noexcept;
  [[nodiscard]] bool apply_coordinator_advertisements(
      RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::uint32_t
  allocate_coordinator_link_state_id(
      const CoordinatorAdvertisement &advertisement) noexcept;

  LinkStateDatabase database_;
  TopologyBuilder topology_;
  SpfCalculator spf_;
  RouteCalculator route_calculator_;
  std::vector<lab::routing::DynamicInput> ipv4_route_inputs_;
  std::vector<lab::routing::Ipv6DynamicInput> ipv6_route_inputs_;
  std::vector<InterfaceOwner> interfaces_;
  std::vector<PendingFightBack> pending_fight_backs_;
  std::vector<LsaKey> pending_sequence_wraps_;
  std::vector<CoordinatorLsaState> coordinator_lsas_;
  std::vector<ip::Ipv6> virtual_endpoint_addresses_;
  // The coordinator replaces this complete semantic set. It is consumed only
  // at the MinLSInterval-controlled local-origination deadline, preventing
  // rapid SPF changes from bypassing RFC 2328 section 12.4 origination pacing.
  std::vector<CoordinatorAdvertisement> pending_coordinator_advertisements_;
  bool coordinator_reconcile_pending_{};
  std::uint32_t router_id_{};
  std::uint32_t area_id_{};
  std::uint32_t next_dd_sequence_{};
  std::uint32_t next_coordinator_link_state_id_{1U};
  std::int32_t router_lsa_sequence_{initial_sequence_number};
  std::int32_t prefix_lsa_sequence_{initial_sequence_number};
  std::int32_t router_information_lsa_sequence_{
      initial_sequence_number};
  bool router_sequence_at_max_{};
  bool prefix_sequence_at_max_{};
  bool router_information_sequence_at_max_{};
  bool router_sequence_wrap_pending_{};
  bool prefix_sequence_wrap_pending_{};
  bool router_information_sequence_wrap_pending_{};
  bool area_border_router_{};
  bool autonomous_system_boundary_router_{};
  bool virtual_link_endpoint_{};
  bool overload_{};
  bool graceful_restart_helper_{};
  bool loop_free_alternates_{};
  std::uint32_t router_preference_{
      device_catalog::ospf_router_preference};
  std::uint32_t external_preference_{
      device_catalog::ospf_external_preference};
  RuntimeClock::time_point last_local_origination_{};
  RuntimeClock::time_point local_origination_deadline_{};
  RuntimeClock::time_point spf_deadline_{};
  RuntimeClock::time_point last_spf_started_{};
  std::chrono::milliseconds current_lsa_delay_{
      device_catalog::ospf_lsa_initial_wait};
  std::chrono::milliseconds current_spf_delay_{
      device_catalog::ospf_spf_initial_wait};
  // These six values are copied from the validated release-specific instance
  // configuration. Keeping them beside the adaptive current delays lets each
  // process apply its own SR OS timer policy without consulting configuration
  // state owned by the management shard.
  std::chrono::milliseconds lsa_initial_wait_{
      device_catalog::ospf_lsa_initial_wait};
  std::chrono::milliseconds lsa_second_wait_{
      device_catalog::ospf_lsa_second_wait};
  std::chrono::milliseconds lsa_maximum_wait_{
      device_catalog::ospf_lsa_maximum_wait};
  std::chrono::milliseconds spf_initial_wait_{
      device_catalog::ospf_spf_initial_wait};
  std::chrono::milliseconds spf_second_wait_{
      device_catalog::ospf_spf_second_wait};
  std::chrono::milliseconds spf_maximum_wait_{
      device_catalog::ospf_spf_maximum_wait};
  std::uint64_t route_generation_{};
  // The process owner records only the failed ownership boundary, never an
  // implementation string. Operational CLI can explain why the last complete
  // route generation was retained without exposing mutable SPF or LSDB data.
  RouteRecalculationStatus route_recalculation_status_{
      RouteRecalculationStatus::never_run};
  RunReadyStatus run_ready_status_{RunReadyStatus::succeeded};
  LocalOriginationStatus local_origination_status_{
      LocalOriginationStatus::succeeded};
  InstallResult local_origination_install_result_{
      InstallResult::installed};
  std::size_t maximum_interfaces_{};
  std::size_t maximum_neighbors_per_interface_{};
  std::size_t maximum_lsas_{};
  std::uint8_t version_{};
  std::uint8_t instance_id_{};
};

} // namespace router::ospf
