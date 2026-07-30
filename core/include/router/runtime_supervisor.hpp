// Multi-device laboratory lifecycle facade. The control shard is the sole
// caller of mutating methods. It coordinates registries, live hardware and the
// link-owned fabric without exposing mutable device pointers to UI code.

#pragma once

#include "router/bof_autoconfigure.hpp"
#include "router/dhcpv4_configuration.hpp"
#include "router/dhcpv6_configuration.hpp"
#include "router/ipsec_configuration.hpp"
#include "router/lab_registry.hpp"
#include "router/network_plane_worker.hpp"
#include "router/router_hardware_inventory.hpp"
#include "router/route_policy.hpp"
#include "router/secret_vault.hpp"
#include "router/session_workflows.hpp"
#include "router/tls_profile.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab {

// These are YANG leaf-presence bits, not ICMPv6 wire flags. Explicit values
// form part of the portable checkpoint contract and may only be extended with
// a corresponding schema update.
enum class RouterAdvertisementLeaf : std::uint16_t {
  admin_state = 1U << 0U,
  current_hop_limit = 1U << 1U,
  managed_configuration = 1U << 2U,
  other_configuration = 1U << 3U,
  maximum_interval = 1U << 4U,
  minimum_interval = 1U << 5U,
  mtu = 1U << 6U,
  preference = 1U << 7U,
  reachable_time = 1U << 8U,
  retransmit_time = 1U << 9U,
  router_lifetime = 1U << 10U,
};

enum class RouterAdvertisementPrefixLeaf : std::uint8_t {
  autonomous = 1U << 0U,
  on_link = 1U << 1U,
  preferred_lifetime = 1U << 2U,
  valid_lifetime = 1U << 3U,
};

inline constexpr std::uint16_t router_advertisement_leaf_presence_mask{
    (1U << 11U) - 1U};
inline constexpr std::uint8_t router_advertisement_prefix_leaf_presence_mask{
    (1U << 4U) - 1U};

struct RouterAdvertisementIntent {
  packet::nd::RouterAdvertisementConfig config{};
  bool configured{};
  bool enabled{};
};

struct MldInterfaceIntent {
  // Control stores the complete resolved program because the forwarding shard
  // must be reconstructible after hardware, carrier or checkpoint changes.
  // port_ordinal and link_local_address are derived from the selected routed
  // interface by RuntimeSupervisor and are never accepted from CLI text.
  MldRouterConfiguration configuration{};
  std::vector<MldSsmTranslation> ssm_translations;
  // This is the effective compiled generation for this interface. Named
  // policy definitions and attachment names remain with LabRuntime; the
  // supervisor needs only the value program required to rebuild forwarding.
  mld::ImportPolicyCheckpoint import_policy;
  bool configured{};
};

struct MldGlobalIntent {
  // This is user configuration from the SR OS router MLD context. Interface
  // owners inherit these values unless a documented interface override is
  // present. No address or hardware ordinal belongs to the global context.
  std::chrono::seconds query_interval{device_catalog::mld_query_interval};
  std::chrono::milliseconds query_response_interval{
      device_catalog::mld_query_response_interval};
  std::chrono::milliseconds last_listener_query_interval{
      device_catalog::mld_last_listener_query_interval};
  std::uint8_t robustness_variable{device_catalog::mld_robustness_variable};
  // Each tuple is one YANG source list entry below an inclusive group range.
  // An interface with no local tuples inherits this protocol-level program;
  // any local tuple set replaces it as documented by Nokia.
  std::vector<MldSsmTranslation> ssm_translations;
  bool configured{};
  bool enabled{};
  // Explicit-leaf markers distinguish an inherited/default value from a
  // value the operator actually entered. That distinction is required for
  // faithful MD compare output and for classic "no" commands: deleting an
  // absent leaf must fail instead of reporting a successful no-op.
  bool query_interval_configured{};
  bool query_response_interval_configured{};
  bool last_listener_query_interval_configured{};
  bool robustness_variable_configured{};
  [[nodiscard]] bool valid() const noexcept {
    // SR OS exposes whole seconds, while the wire codec stores millisecond
    // Max Response values. Exact second divisibility rejects checkpoint data
    // that no supported CLI command could have produced.
    return (!enabled || configured) &&
           (configured || (!query_interval_configured &&
                           !query_response_interval_configured &&
                           !last_listener_query_interval_configured &&
                           !robustness_variable_configured)) &&
           query_interval >=
               std::chrono::seconds{
                   device_catalog::mld_minimum_query_interval_seconds} &&
           query_interval <=
               std::chrono::seconds{
                   device_catalog::mld_maximum_query_interval_seconds} &&
           query_response_interval >=
               std::chrono::seconds{
                   device_catalog::
                       mld_minimum_query_response_interval_seconds} &&
           query_response_interval <=
               std::chrono::seconds{
                   device_catalog::
                       mld_maximum_query_response_interval_seconds} &&
           query_response_interval < query_interval &&
           query_response_interval % std::chrono::seconds{1} ==
               std::chrono::milliseconds::zero() &&
           last_listener_query_interval >=
               std::chrono::seconds{
                   device_catalog::
                       mld_minimum_last_listener_query_interval_seconds} &&
           last_listener_query_interval <=
               std::chrono::seconds{
                   device_catalog::
                       mld_maximum_last_listener_query_interval_seconds} &&
           last_listener_query_interval % std::chrono::seconds{1} ==
               std::chrono::milliseconds::zero() &&
           robustness_variable >=
               device_catalog::mld_minimum_robustness_variable &&
           robustness_variable <=
               device_catalog::mld_maximum_robustness_variable;
  }
  bool operator==(const MldGlobalIntent &) const = default;
};

struct MldPolicyPrefixListIntent {
  std::string name;
  // policy-options is shared by IPv4 and IPv6 consumers. MLD compiles only
  // IPv6 rows from this canonical dual-stack list while preserving every row
  // for CLI editing, candidate comparison and checkpoint reconstruction.
  std::vector<ip::IpPrefix> prefixes;
  bool operator==(const MldPolicyPrefixListIntent &) const = default;
};

struct MldImportPolicyEntryIntent {
  std::uint32_t number{};
  std::string group_prefix_list;
  std::optional<packet::Ipv6> source_address;
  std::string source_prefix_list;
  mld::ImportPolicyAction action{mld::ImportPolicyAction::next_entry};
  bool action_configured{};
  bool protocol_mld{};
  // policy-options is a router-wide datastore. These route attributes share
  // the same ordered entry as multicast matches, while each consumer compiles
  // only the leaves meaningful to that protocol. This prevents OSPF export
  // from inventing a second policy namespace with divergent commit semantics.
  std::string route_prefix_list;
  std::optional<routing::RouteSource> route_source;
  std::optional<std::uint8_t> protocol_instance;
  std::optional<std::uint32_t> route_tag;
  std::optional<std::uint32_t> set_metric;
  std::optional<routing::OspfPathType> set_metric_type;
  std::optional<std::uint32_t> set_route_tag;
  bool operator==(const MldImportPolicyEntryIntent &) const = default;
};

struct MldNamedImportPolicyIntent {
  // These are canonical policy-options leaves, not the expanded forwarding
  // program. Keeping prefix-list references intact preserves candidate edits,
  // compare output and exact leafref validation.
  std::string name;
  std::vector<MldImportPolicyEntryIntent> entries;
  mld::ImportPolicyAction default_action{mld::ImportPolicyAction::accept};
  bool default_action_configured{};
  bool operator==(const MldNamedImportPolicyIntent &) const = default;
};

struct RouterControlCheckpoint {
  DeviceHandle device{};
  std::uint16_t maximum_ecmp_paths{1U};
  std::array<routing::ConnectedInput, routing::maximum_ipv4_connected_inputs>
      connected{};
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router>
      statics{};
  std::array<routing::Ipv6ConnectedInput,
             device_catalog::maximum_ports_per_router>
      ipv6_connected{};
  std::vector<RouterIpv6Address> native_ipv6_addresses{};
  std::vector<routing::Ipv6ConnectedInput> native_ipv6_connected{};
  std::array<routing::Ipv6StaticInput,
             device_catalog::maximum_static_routes_per_router>
      ipv6_statics{};
  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports{};
  std::array<bool, device_catalog::maximum_ports_per_router> interface_admin{};
  // A service-only Ethernet port has no native router interface but must still
  // exist in forwarding for SAP classification and physical carrier. This bit
  // separates that ownership from interface_admin and survives checkpoints.
  std::array<bool, device_catalog::maximum_ports_per_router> ies_port_owned{};
  std::array<RouterAdvertisementIntent,
             device_catalog::maximum_ports_per_router>
      router_advertisements{};
  std::array<MldInterfaceIntent, device_catalog::maximum_ports_per_router>
      mld_interfaces{};
  // Checkpoints store only configured relay children. Keeping 800 optional
  // vector-bearing objects per router made a second coherent checkpoint grow
  // shared Wasm memory even when no DHCP relay existed. The relay carries its
  // physical ordinal, so a sparse vector is lossless and bounded by the same
  // generated per-router port capacity.
  std::vector<dhcpv4::RelayInterfaceConfiguration> dhcpv4_relays{};
  // Service configuration remains control-owned even when hardware removes
  // the current forwarding object. Optional presence distinguishes an absent
  // DHCPv6 relay child from an empty but invalid server list.
  std::vector<dhcpv6::RelayInterfaceConfig> dhcpv6_relays{};
  // The complete IES graph remains under the serialized control owner. The
  // forwarding checkpoint stores only its immutable packet-path projection;
  // retaining intent here is what allows later card reconciliation and CLI
  // rendering without reverse-engineering configuration from operational
  // tables.
  service::Configuration ies_configuration{};
  std::vector<service::SapAttachment> ies_sap_attachments{};
  std::vector<service::ServiceIpv6Interface> ies_ipv6_interfaces{};
  std::vector<routing::Ipv6ConnectedInput> ies_ipv6_connected{};
  std::vector<dhcpv6::RelayInterfaceConfig> ies_dhcpv6_relays{};
  routing::FibProgram selected_rib{};
  routing::Ipv6FibProgram selected_ipv6_rib{};
  std::uint64_t fib_generation{};
  std::uint64_t ipv6_fib_generation{};
};

// These records preserve control-facade configuration that is not needed by
// the forwarding shard but is still part of a self-contained laboratory.
// RuntimeSupervisor deliberately does not mutate them during restore. The
// LabRuntime owner validates their handles against the restored registries and
// publishes them only after the supervisor completes its atomic state swap.
struct PortablePortIntentCheckpoint {
  std::string id;
  bool admin_enabled{};
  std::uint16_t mtu{};
  std::uint32_t speed_mbps{};
  std::string description;
};

struct PortableMldStaticGroupIntentCheckpoint {
  // The portable record stores configuration only. Dynamic listener timers
  // remain in RouterForwarderCheckpoint and are never merged into intent.
  // Range keys are retained instead of serializing only expanded groups.
  // This is required for an exact candidate reconstruction and keeps the
  // control-plane intent independent from forwarding's concrete membership.
  packet::Ipv6 multicast_address{};
  packet::Ipv6 range_end{};
  packet::Ipv6 range_step{};
  std::vector<packet::Ipv6> sources;
  bool starg{};
  bool range{};
};

struct PortableStaticIpv6NeighborIntentCheckpoint {
  // Stable interface ownership is supplied by the enclosing record. The pair
  // exactly represents the YANG list key and mandatory MAC leaf.
  packet::Ipv6 address{};
  packet::Mac mac{};
};

struct PortableStaticIpv4NeighborIntentCheckpoint {
  // Interface ownership is supplied by the enclosing intent. Address is the
  // list key and MAC is the sole mutable leaf of this compact checkpoint row.
  std::uint32_t address{};
  packet::Mac mac{};
};

struct PortableIpv6AddressIntentCheckpoint {
  packet::Ipv6 address{};
  std::uint32_t primary_preference{};
  std::uint32_t tag{};
  std::uint8_t prefix_length{};
  bool duplicate_address_detection{true};
  bool eui64{};
  packet::Mac eui64_source_mac{};
  bool tag_configured{};
};

struct PortableInterfaceIntentCheckpoint {
  std::string name;
  std::string port_id;
  packet::Mac mac{};
  std::uint32_t address{};
  std::uint8_t prefix_length{};
  // Effective values and explicit leaf presence are both portable. This keeps
  // MD delete and classic no behavior exact after a checkpoint restore.
  std::uint32_t arp_timeout_seconds{
      static_cast<std::uint32_t>(device_catalog::dynamic_arp_timeout.count())};
  std::uint16_t arp_retry_deciseconds{
      device_catalog::dynamic_arp_retry_deciseconds};
  bool arp_timeout_configured{};
  bool arp_retry_configured{};
  std::uint16_t icmp_redirect_maximum{
      device_catalog::icmp_redirect_default_maximum};
  std::uint16_t icmp_redirect_interval_seconds{static_cast<std::uint16_t>(
      device_catalog::icmp_redirect_default_interval.count())};
  bool icmp_redirects_enabled{true};
  bool icmp_redirect_admin_configured{};
  bool icmp_redirect_maximum_configured{};
  bool icmp_redirect_interval_configured{};
  std::vector<PortableStaticIpv4NeighborIntentCheckpoint> static_ipv4_neighbors;
  packet::Ipv6 ipv6_address{};
  packet::Ipv6 ipv6_link_local{};
  packet::nd::RouterAdvertisementConfig router_advertisement{};
  std::uint8_t ipv6_prefix_length{};
  bool admin_enabled{};
  bool port_configured{};
  bool address_configured{};
  bool ipv6_address_configured{};
  std::vector<PortableIpv6AddressIntentCheckpoint> ipv6_addresses;
  Ipv6UnsolicitedLearning ipv6_unsolicited_learning{
      Ipv6UnsolicitedLearning::none};
  bool ipv6_unsolicited_learning_configured{};
  std::uint32_t ipv6_nd_reachable_time_seconds{};
  std::uint32_t ipv6_nd_stale_time_seconds{};
  Ipv6UnsolicitedLearning ipv6_proactive_refresh{Ipv6UnsolicitedLearning::none};
  std::uint32_t ipv6_neighbor_limit{};
  std::uint8_t ipv6_neighbor_limit_threshold_percent{
      device_catalog::nd_default_neighbor_limit_threshold_percent};
  bool ipv6_nd_reachable_time_configured{};
  bool ipv6_nd_stale_time_configured{};
  bool ipv6_proactive_refresh_configured{};
  bool ipv6_neighbor_limit_configured{};
  bool ipv6_neighbor_limit_log_only{};
  bool ipv6_neighbor_limit_log_only_configured{};
  bool ipv6_neighbor_limit_threshold_configured{};
  std::vector<PortableStaticIpv6NeighborIntentCheckpoint> static_ipv6_neighbors;
  bool router_advertisement_configured{};
  bool router_advertisement_enabled{};
  // Portable control intent preserves MD leaf presence separately from wire
  // values. This metadata never crosses into forwarding ownership.
  std::uint16_t router_advertisement_leaf_presence{};
  std::array<std::uint8_t, device_catalog::ipv6_ra_prefixes_per_interface>
      router_advertisement_prefix_leaf_presence{};
  bool router_advertisement_rdnss_lifetime_configured{};
  bool router_advertisement_include_dns{true};
  bool router_advertisement_include_dns_configured{};
  // Defaulted MD leaves retain explicit presence so delete semantics and
  // candidate comparison survive reload even when their effective value is
  // identical to the release default.
  std::uint16_t icmp6_redirect_maximum{
      device_catalog::icmp6_redirect_default_maximum};
  std::uint16_t icmp6_redirect_interval_seconds{static_cast<std::uint16_t>(
      device_catalog::icmp6_redirect_default_interval.count())};
  bool icmp6_redirects_enabled{true};
  bool icmp6_redirect_admin_configured{};
  bool icmp6_redirect_maximum_configured{};
  bool icmp6_redirect_interval_configured{};
  std::uint8_t mld_version{device_catalog::mld_default_version};
  std::chrono::seconds mld_query_interval{};
  std::chrono::milliseconds mld_query_response_interval{};
  std::chrono::milliseconds mld_last_listener_query_interval{};
  std::uint8_t mld_robustness_variable{};
  // Portable intent retains both the scalar and explicit leaf presence. This
  // preserves MD delete and classic no semantics across a checkpoint without
  // conflating an absent leaf with an invalid user-entered zero.
  std::uint32_t mld_maximum_number_groups{};
  std::uint32_t mld_maximum_number_group_sources{};
  std::uint32_t mld_maximum_number_sources{};
  bool mld_router_alert_check{true};
  bool mld_configured{};
  bool mld_enabled{};
  bool mld_version_configured{};
  bool mld_query_interval_configured{};
  bool mld_query_response_interval_configured{};
  bool mld_last_listener_query_interval_configured{};
  bool mld_robustness_variable_configured{};
  bool mld_maximum_number_groups_configured{};
  bool mld_maximum_number_group_sources_configured{};
  bool mld_maximum_number_sources_configured{};
  bool mld_router_alert_check_configured{};
  std::string mld_import_policy;
  std::vector<MldSsmTranslation> mld_ssm_translations;
  std::vector<PortableMldStaticGroupIntentCheckpoint> mld_static_groups;
  std::optional<dhcpv4::RelayConfiguration> dhcpv4_relay;
  // The named DHCPv6 server attachment is management intent. Forwarding
  // receives only its resolved stable link digest and never a CLI list key.
  std::string dhcpv6_local_server;
};

struct PortableStaticRouteIntentCheckpoint {
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
  bool indirect{};
};

struct PortableIpv6StaticRouteIntentCheckpoint {
  // A link-local next hop is meaningful only inside one link zone. Persisting
  // the stable port key rather than a current ordinal lets inventory rebuild
  // validate and resolve the zone again during import.
  packet::Ipv6 network{};
  packet::Ipv6 next_hop{};
  std::string outgoing_port_id;
  std::uint8_t prefix_length{};
  bool indirect{};
};

struct PortableFacilityAlarmCheckpoint {
  // Facility alarm history belongs to the management facade. The forwarding
  // and hardware owners publish facts that can raise or clear alarms, but they
  // must not own CLI indexes, civil timestamps or cleared-history wrapping.
  std::string key;
  std::string code;
  std::string severity;
  std::string resource;
  std::string detail;
  std::uint64_t index{};
  std::uint64_t raised_at_epoch_ms{};
  std::uint64_t cleared_at_epoch_ms{};
  bool masked{};
};

struct PortableMdaConfigurationCheckpoint {
  std::string provisioned;
  bool admin_enabled{};
};

struct PortableCardConfigurationCheckpoint {
  std::string provisioned;
  bool admin_enabled{};
  std::array<PortableMdaConfigurationCheckpoint,
             device_catalog::maximum_mda_slots_per_card>
      mdas;
};

struct PortableConfigurationCheckpoint {
  std::string system_name;
  std::uint16_t maximum_ecmp_paths{1U};
  MldGlobalIntent mld;
  std::vector<MldPolicyPrefixListIntent> mld_prefix_lists;
  std::vector<MldNamedImportPolicyIntent> mld_import_policies;
  // Router-wide RDNSS is inherited during control-plane compilation. The
  // forwarding checkpoint contains only each already compiled interface RA.
  packet::nd::RdnssInformation router_advertisement_rdnss{};
  std::uint32_t router_advertisement_rdnss_lifetime_seconds{
      device_catalog::ra_infinite_lifetime};
  bool router_advertisement_rdnss_lifetime_configured{};
  std::uint32_t ipv6_nd_reachable_time_seconds{
      device_catalog::nd_default_reachable_time_seconds};
  std::uint32_t ipv6_nd_stale_time_seconds{
      device_catalog::nd_default_stale_time_seconds};
  bool ipv6_nd_reachable_time_configured{};
  bool ipv6_nd_stale_time_configured{};
  tls_profile::Configuration tls;
  ipsec::configuration::Configuration ipsec;
  // Service intent is portable control state. Forwarding checkpoints retain
  // only the compiled SAP and logical-interface generation, which is not
  // sufficient to reconstruct customer ownership or CLI presence semantics.
  service::Configuration ies;
  bof::AutoconfigureIntent bof_autoconfigure;
  dhcpv4::configuration::RouterConfiguration dhcpv4_servers;
  dhcpv6::configuration::RouterConfiguration dhcpv6_servers;
  ospf::RouterConfiguration ospf;
  std::array<PortableCardConfigurationCheckpoint,
             device_catalog::maximum_card_slots>
      cards;
  std::vector<PortablePortIntentCheckpoint> ports;
  std::vector<PortableInterfaceIntentCheckpoint> interfaces;
  std::vector<PortableStaticRouteIntentCheckpoint> routes;
  std::vector<PortableIpv6StaticRouteIntentCheckpoint> ipv6_routes;
};

struct PortableRouterIntentCheckpoint {
  DeviceHandle device{};
  std::uint16_t maximum_ecmp_paths{1U};
  std::vector<PortablePortIntentCheckpoint> ports;
  std::vector<PortableInterfaceIntentCheckpoint> interfaces;
  std::vector<PortableStaticRouteIntentCheckpoint> routes;
  std::vector<PortableIpv6StaticRouteIntentCheckpoint> ipv6_routes;
  MldGlobalIntent mld;
  std::vector<MldPolicyPrefixListIntent> mld_prefix_lists;
  std::vector<MldNamedImportPolicyIntent> mld_import_policies;
  packet::nd::RdnssInformation router_advertisement_rdnss{};
  std::uint32_t router_advertisement_rdnss_lifetime_seconds{
      device_catalog::ra_infinite_lifetime};
  bool router_advertisement_rdnss_lifetime_configured{};
  std::uint32_t ipv6_nd_reachable_time_seconds{
      device_catalog::nd_default_reachable_time_seconds};
  std::uint32_t ipv6_nd_stale_time_seconds{
      device_catalog::nd_default_stale_time_seconds};
  bool ipv6_nd_reachable_time_configured{};
  bool ipv6_nd_stale_time_configured{};
  tls_profile::Configuration tls;
  ipsec::configuration::Configuration ipsec;
  service::Configuration ies;
  bof::AutoconfigureIntent bof_autoconfigure;
  dhcpv4::configuration::RouterConfiguration dhcpv4_servers;
  dhcpv6::configuration::RouterConfiguration dhcpv6_servers;
  ospf::RouterConfiguration ospf;
  PortableConfigurationCheckpoint global_candidate;
  bool global_candidate_initialized{};
  std::array<bool, device_catalog::maximum_ports_per_router>
      port_seen_operational{};
  std::vector<PortableFacilityAlarmCheckpoint> active_facility_alarms;
  std::vector<PortableFacilityAlarmCheckpoint> cleared_facility_alarms;
  std::uint64_t next_facility_alarm_index{1U};
  bool cleared_facility_alarms_wrapped{};
};

struct PortableSessionCandidateCheckpoint {
  SessionHandle session{};
  PortableConfigurationCheckpoint candidate;
  bool initialized{};
  PortableConfigurationCheckpoint classic_policy_candidate;
  bool classic_policy_edit_active{};
  std::uint32_t ping_destination{};
  packet::Ipv6 ping_destination_ipv6{};
  std::uint16_t ping_sequence{};
  std::uint16_t ping_payload_octets{
      device_catalog::default_ping_payload_octets};
  std::uint32_t ping_requested{};
  std::uint32_t ping_sent{};
  std::uint32_t ping_received{};
  // These four integers are the complete sufficient statistics for the
  // population standard deviation printed by SR OS. They keep a live ping
  // exactly resumable without storing an unbounded vector of samples.
  std::uint64_t ping_rtt_min_microseconds{};
  std::uint64_t ping_rtt_max_microseconds{};
  std::uint64_t ping_rtt_sum_microseconds{};
  std::uint64_t ping_rtt_squared_sum_microseconds{};
  std::uint64_t ping_next_send_ns{};
  std::uint64_t ping_reply_deadline_ns{};
  bool ping_dont_fragment{};
  bool ping_ipv6{};
  bool ping_waiting{};
  bool ping_active{};
  bool ping_cancel_requested{};
};

struct PortableHostIntentCheckpoint {
  HostHandle host{};
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{};
  std::uint64_t interface_id{};
  bool configured{};
  bool ipv6_autoconfiguration{};
  host::Ipv6InterfaceIdentifierConfiguration ipv6_identifier{};
  crypto::Sha256Digest transport_secret{};
};

struct PortableCaptureIntentCheckpoint {
  CapturePointId id{};
  CapturePointKind kind{};
  std::string object_id;
  std::string port_id;
  std::uint8_t direction{};
  bool selected{};
};

struct RuntimeSupervisorCheckpoint {
  DeviceRegistryCheckpoint devices;
  HostRegistryCheckpoint hosts;
  SwitchRegistryCheckpoint switches;
  TopologyRegistryCheckpoint topology;
  SessionRegistryCheckpoint sessions;
  std::vector<RouterHardwareCheckpoint> hardware;
  std::vector<RouterControlCheckpoint> control;
  SessionWorkflowsCheckpoint workflows;
  NetworkPlaneCheckpoint network;
  std::uint64_t next_network_command_id{};
  std::vector<PortableRouterIntentCheckpoint> portable_routers;
  std::vector<PortableSessionCandidateCheckpoint> portable_session_candidates;
  std::vector<PortableHostIntentCheckpoint> portable_hosts;
  std::vector<PortableCaptureIntentCheckpoint> portable_capture_points;
  // Only authenticated ciphertext crosses the ABI. The wrapping key remains
  // browser-vault material and is intentionally absent from this structure.
  vault::Checkpoint secret_vault;
};

namespace checkpoint_validation {

// Preconditions: both programs passed their binary decoder and use the same
// generation. Postcondition: true means every connected/static route rebuilt
// by the control owner remains selected and every additional row has an OSPF
// owner. The function does not mutate either checkpoint image.
[[nodiscard]] bool base_fib_preserved(
    const routing::FibProgram &base,
    const routing::FibProgram &selected) noexcept;
[[nodiscard]] bool base_fib_preserved(
    const routing::Ipv6FibProgram &base,
    const routing::Ipv6FibProgram &selected) noexcept;

} // namespace checkpoint_validation

class RuntimeSupervisor final {
public:
  RuntimeSupervisor();
  ~RuntimeSupervisor();
  RuntimeSupervisor(const RuntimeSupervisor &) = delete;
  RuntimeSupervisor &operator=(const RuntimeSupervisor &) = delete;

  // DNSSEC private keys are generated and retained by the network owner, but
  // their checkpoint ciphertext must remain bound to the same project secret
  // as the control-owned credential vault. The key crosses the pthread
  // boundary once through a dedicated securely-erased SPSC payload ring. The
  // digest is the fixed-size AAD namespace derived from the project context.
  [[nodiscard]] bool initialize_signing_vault(
      std::span<const std::uint8_t> wrapping_key,
      const crypto::Sha256Digest &project_context_digest) noexcept;

  [[nodiscard]] std::optional<DeviceHandle>
  create_router(std::string_view node_id, std::string_view profile_id,
                std::string_view system_name);
  [[nodiscard]] std::optional<DeviceHandle>
  create_dhcp_server(std::string_view node_id, std::string_view profile_id,
                     std::string_view name);
  [[nodiscard]] std::optional<HostHandle> create_host(std::string_view node_id,
                                                      std::string_view name);
  [[nodiscard]] std::optional<SwitchHandle>
  create_switch(std::string_view node_id, std::string_view profile_id,
                std::string_view name);
  [[nodiscard]] bool delete_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool delete_host(HostHandle host) noexcept;
  [[nodiscard]] bool delete_switch(SwitchHandle handle) noexcept;
  [[nodiscard]] bool set_host_name(HostHandle host, std::string_view name);
  [[nodiscard]] bool set_switch_name(SwitchHandle handle,
                                     std::string_view name);
  [[nodiscard]] bool configure_switch_port(
      SwitchHandle handle, std::uint16_t port,
      std::uint32_t speed_mbps, std::uint16_t mtu,
      bool admin_enabled) noexcept;
  [[nodiscard]] bool set_system_name(DeviceHandle device,
                                     std::string_view system_name);

  [[nodiscard]] std::optional<SessionHandle>
  create_session(DeviceHandle device, std::string_view session_id);
  [[nodiscard]] bool close_session(SessionHandle session) noexcept;
  // Engine choice is terminal session state persisted by the registry. It has
  // no effect on router configuration and is updated only after the CLI state
  // machine accepts an actual // command.
  [[nodiscard]] bool set_cli_session(SessionHandle session,
                                     const CliSession &state) noexcept;
  [[nodiscard]] SessionWorkflowResult
  enter_session_mode(SessionHandle session, CandidateMode mode) noexcept;
  [[nodiscard]] SessionWorkflowResult leave_session_mode(SessionHandle session,
                                                         bool discard) noexcept;
  [[nodiscard]] SessionWorkflowResult
  transition_session_mode(SessionHandle session, CandidateMode target,
                          bool discard) noexcept;
  [[nodiscard]] SessionWorkflowResult
  record_session_edit(SessionHandle session, std::uint64_t key) noexcept;
  [[nodiscard]] SessionWorkflowResult
  commit_session(SessionHandle session) noexcept;
  [[nodiscard]] SessionWorkflowResult
  discard_session(SessionHandle session) noexcept;
  [[nodiscard]] SessionWorkflowResult
  authorize_classic_write(DeviceHandle device) const noexcept;
  [[nodiscard]] SessionWorkflowResult classic_write(DeviceHandle device,
                                                    std::uint64_t key) noexcept;
  [[nodiscard]] bool global_candidate_dirty(DeviceHandle device) const noexcept;
  [[nodiscard]] std::optional<SessionWorkflowStatus>
  session_status(SessionHandle session) const noexcept;

  [[nodiscard]] HardwareEditResult set_card(DeviceHandle device,
                                            std::uint16_t slot,
                                            std::string_view provisioned,
                                            std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult
  set_mda(DeviceHandle device, std::uint16_t card, std::uint16_t mda,
          std::string_view provisioned, std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult set_card_admin(DeviceHandle device,
                                                  std::uint16_t slot,
                                                  bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult set_mda_admin(DeviceHandle device,
                                                 std::uint16_t card,
                                                 std::uint16_t mda,
                                                 bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult
  configure_port(DeviceHandle device, std::string_view port_id,
                 bool admin_enabled, std::uint16_t mtu,
                 std::uint32_t speed_mbps) noexcept;

  [[nodiscard]] std::optional<LinkHandle>
  create_link(std::string_view link_id, const LinkEndpoint &first,
              const LinkEndpoint &second, std::chrono::nanoseconds propagation,
              bool admin_enabled = true,
              std::uint32_t configured_speed_mbps = 0U) noexcept;
  [[nodiscard]] bool delete_link(LinkHandle link) noexcept;
  [[nodiscard]] bool set_link_admin(LinkHandle link, bool enabled) noexcept;
  [[nodiscard]] bool
  set_link_properties(LinkHandle link, bool enabled,
                      std::chrono::nanoseconds propagation,
                      std::uint32_t configured_speed_mbps = 0U) noexcept;
  [[nodiscard]] bool configure_interface(
      DeviceHandle device, std::string_view port_id, packet::Mac mac,
      std::uint32_t address, std::uint8_t prefix_length, bool admin_enabled,
      std::uint32_t arp_timeout_seconds = static_cast<std::uint32_t>(
          device_catalog::dynamic_arp_timeout.count()),
      std::uint16_t arp_retry_deciseconds =
          device_catalog::dynamic_arp_retry_deciseconds) noexcept;
  // The system interface is a router-owned local /32. These operations never
  // resolve a hardware coordinate and never emit a port-programming command.
  // The control shard owns the configured and administrative leaves, while a
  // generated immutable FIB projection is the only value sent to forwarding.
  [[nodiscard]] bool configure_system_interface(DeviceHandle device,
                                                std::uint32_t address,
                                                bool admin_enabled) noexcept;
  [[nodiscard]] bool remove_system_interface(DeviceHandle device) noexcept;
  // The caller supplies one complete loopback-address generation. Control
  // validates, derives the local /128 routes and publishes the forwarding
  // address table atomically. Empty input removes the IPv6 system interface.
  [[nodiscard]] bool configure_system_ipv6_addresses(
      DeviceHandle device, std::span<const RouterIpv6Address> addresses,
      bool admin_enabled) noexcept;
  [[nodiscard]] bool configure_ipv6_interface(
      DeviceHandle device, std::string_view port_id, packet::Mac mac,
      const packet::Ipv6 &address, std::uint8_t prefix_length,
      const packet::Ipv6 &link_local, bool admin_enabled) noexcept;
  [[nodiscard]] bool configure_ipv6_address(
      DeviceHandle device, std::string_view port_id,
      const packet::Ipv6 &address, std::uint8_t prefix_length,
      std::uint32_t primary_preference, bool duplicate_address_detection = true,
      std::optional<std::uint32_t> tag = std::nullopt) noexcept;
  [[nodiscard]] bool remove_ipv6_address(DeviceHandle device,
                                         std::string_view port_id,
                                         const packet::Ipv6 &address) noexcept;
  [[nodiscard]] bool remove_ipv6_interface(DeviceHandle device,
                                           std::string_view port_id) noexcept;
  [[nodiscard]] bool
  configure_ipv6_redirects(DeviceHandle device, std::string_view port_id,
                           bool enabled, std::uint16_t maximum,
                           std::uint16_t interval_seconds) noexcept;
  [[nodiscard]] bool
  configure_ipv4_redirects(DeviceHandle device, std::string_view port_id,
                           bool enabled, std::uint16_t maximum,
                           std::uint16_t interval_seconds) noexcept;
  [[nodiscard]] bool configure_ipv6_neighbor_policy(
      DeviceHandle device, std::string_view port_id,
      std::uint32_t reachable_time_seconds, std::uint32_t stale_time_seconds,
      Ipv6UnsolicitedLearning unsolicited_learning,
      Ipv6UnsolicitedLearning proactive_refresh, bool limit_configured,
      std::uint32_t limit, bool limit_log_only,
      std::uint8_t limit_threshold_percent) noexcept;
  [[nodiscard]] bool configure_router_advertisement(
      DeviceHandle device, std::string_view port_id, bool enabled,
      const packet::nd::RouterAdvertisementConfig &config) noexcept;
  [[nodiscard]] bool
  remove_router_advertisement(DeviceHandle device,
                              std::string_view port_id) noexcept;
  [[nodiscard]] bool
  configure_mld_interface(DeviceHandle device, std::string_view port_id,
                          const MldRouterConfiguration &configuration) noexcept;
  [[nodiscard]] bool remove_mld_interface(DeviceHandle device,
                                          std::string_view port_id) noexcept;
  // Publishes one complete, already resolved OSPF generation. Stable CLI
  // interface names are converted to physical ordinals before this boundary;
  // the fixed records then cross the control-to-network SPSC transaction.
  [[nodiscard]] bool configure_ospf_generation(
      DeviceHandle device, std::span<const OspfProcessProgram> processes,
      std::span<const OspfInterfaceProgram> interfaces,
      std::span<const OspfAuthenticationProgram> authentications,
      std::span<const OspfNbmaNeighborProgram> nbma_neighbors,
      std::span<const OspfVirtualLinkProgram> virtual_links,
      std::span<const OspfAreaRangeProgram> ranges,
      std::span<const OspfExternalRouteProgram> external_routes = {}) noexcept;
  // Returns one immutable row copied by the dedicated OSPF owner during this
  // synchronous control turn. An absent optional means a stale device,
  // malformed selector or failed owner handoff; `present=false` inside a
  // successful result means the requested ordinal is past the current table.
  [[nodiscard]] std::optional<ospf::ControlResult>
  query_ospf(DeviceHandle device,
             const OspfOperationalQuery &query) noexcept;
  // Replaces the complete customer, access-port, IES, interface, SAP and
  // DHCPv6 relay graph. Validation and forwarding publication are atomic from
  // the caller's perspective: false leaves the previous committed generation
  // active on both control and forwarding owners.
  [[nodiscard]] bool
  configure_ies_services(DeviceHandle device,
                         const service::Configuration &configuration) noexcept;
  // DHCPv6 relay configuration originates in the service configuration owner,
  // but its UDP socket, return-path lookup and counters belong to the selected
  // router forwarding shard. This method resolves the stable hardware port,
  // validates that IPv6 is operationally configured there, and streams the
  // complete variable-length policy through the control-to-network SPSC ring.
  // No span, vector pointer or mutable service object crosses the shard
  // boundary. A false result leaves the prior forwarding generation active.
  [[nodiscard]] bool configure_dhcpv4_relay(
      DeviceHandle device, std::string_view port_id,
      const dhcpv4::RelayInterfaceConfiguration &configuration) noexcept;
  [[nodiscard]] bool remove_dhcpv4_relay(DeviceHandle device,
                                         std::string_view port_id) noexcept;
  [[nodiscard]] bool configure_router_dhcpv4_server(
      const RouterDhcpv4ServerProgram &program) noexcept;
  [[nodiscard]] bool configure_router_bof_management(
      const RouterBofManagementProgram &program) noexcept;
  [[nodiscard]] bool configure_router_bof_dhcpv4_client(
      const RouterBofDhcpv4ClientProgram &program) noexcept;
  [[nodiscard]] bool remove_router_bof_dhcpv4_client(
      DeviceHandle device) noexcept;
  [[nodiscard]] bool configure_router_bof_dhcpv6_client(
      const RouterBofDhcpv6ClientProgram &program) noexcept;
  [[nodiscard]] bool remove_router_bof_dhcpv6_client(
      DeviceHandle device) noexcept;
  [[nodiscard]] bool remove_router_dhcpv4_server(
      DeviceHandle device, std::string_view name) noexcept;
  [[nodiscard]] bool configure_router_dhcpv6_server(
      const RouterDhcpv6ServerProgram &program) noexcept;
  [[nodiscard]] bool remove_router_dhcpv6_server(
      DeviceHandle device, std::string_view name) noexcept;
  [[nodiscard]] bool clear_router_dhcpv6_server_leases(
      DeviceHandle device, std::string_view name,
      const dhcpv6::LeaseClearFilter &filter) noexcept;
  [[nodiscard]] bool clear_router_dhcpv6_server_statistics(
      DeviceHandle device, std::string_view name) noexcept;
  [[nodiscard]] bool clear_router_dhcpv4_server_statistics(
      DeviceHandle device, std::string_view name) noexcept;
  [[nodiscard]] bool clear_router_dhcpv4_server_leases(
      DeviceHandle device, std::string_view name,
      const dhcpv4::LeaseClearFilter &filter) noexcept;
  [[nodiscard]] dhcpv4::ForceRenewStatus send_router_dhcpv4_force_renew(
      DeviceHandle device, std::string_view name,
      packet::Ipv4 address) noexcept;
  [[nodiscard]] bool configure_dhcpv6_relay(
      DeviceHandle device, std::string_view port_id,
      const dhcpv6::RelayInterfaceConfig &configuration) noexcept;
  // The facade resolves the named attachment in control-owned state. The
  // forwarding command carries its retained logical interface ID, not a value
  // reconstructed from the physical port ordinal.
  [[nodiscard]] bool remove_dhcpv6_relay(DeviceHandle device,
                                         std::string_view port_id) noexcept;
  [[nodiscard]] bool clear_dhcpv6_relay_leases(
      DeviceHandle device,
      const Dhcpv6RelayLeaseClearProgram &program) noexcept;
  [[nodiscard]] bool clear_mld_database(
      DeviceHandle device, std::string_view port_id,
      const std::optional<packet::Ipv6> &group = std::nullopt) noexcept;
  [[nodiscard]] bool clear_mld_database_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool clear_icmpv4_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv4_global_statistics(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv4_interface_statistics(DeviceHandle device,
                                    std::string_view port_id) noexcept;
  [[nodiscard]] bool clear_icmpv6_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv6_global_statistics(DeviceHandle device) noexcept;
  [[nodiscard]] bool
  clear_icmpv6_interface_statistics(DeviceHandle device,
                                    std::string_view port_id) noexcept;
  [[nodiscard]] bool
  clear_router_advertisement_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool clear_router_advertisement_interface_statistics(
      DeviceHandle device, std::string_view port_id) noexcept;
  [[nodiscard]] bool clear_mld_version(DeviceHandle device,
                                       std::string_view port_id) noexcept;
  [[nodiscard]] bool clear_mld_statistics(DeviceHandle device,
                                          std::string_view port_id) noexcept;
  [[nodiscard]] bool clear_mld_statistics_all(DeviceHandle device) noexcept;
  [[nodiscard]] bool edit_mld_static(DeviceHandle device,
                                     std::string_view port_id,
                                     MldStaticOperation operation,
                                     const packet::Ipv6 &group,
                                     const packet::Ipv6 &source = {}) noexcept;
  [[nodiscard]] bool replace_mld_ssm_translations(
      DeviceHandle device, std::string_view port_id,
      std::span<const MldSsmTranslation> translations) noexcept;
  [[nodiscard]] bool
  replace_mld_import_policy(DeviceHandle device, std::string_view port_id,
                            std::span<const mld::ImportPolicyEntry> entries,
                            mld::ImportPolicyAction default_action) noexcept;
  [[nodiscard]] bool remove_interface(DeviceHandle device,
                                      std::string_view port_id) noexcept;
  [[nodiscard]] bool add_static_route(DeviceHandle device,
                                      std::uint32_t network,
                                      std::uint8_t prefix_length,
                                      std::uint32_t next_hop,
                                      bool indirect = false) noexcept;
  [[nodiscard]] bool remove_static_route(DeviceHandle device,
                                         std::uint32_t network,
                                         std::uint8_t prefix_length,
                                         std::optional<std::uint32_t> next_hop =
                                             std::nullopt,
                                         std::optional<bool> indirect =
                                             std::nullopt) noexcept;
  [[nodiscard]] bool configure_ecmp(DeviceHandle device,
                                    std::uint16_t maximum_paths) noexcept;
  [[nodiscard]] bool
  add_ipv6_static_route(DeviceHandle device, const packet::Ipv6 &network,
                        std::uint8_t prefix_length,
                        const packet::Ipv6 &next_hop,
                        std::string_view outgoing_port_id = {},
                        bool indirect = false) noexcept;
  [[nodiscard]] bool
  remove_ipv6_static_route(DeviceHandle device, const packet::Ipv6 &network,
                           std::uint8_t prefix_length,
                           std::optional<packet::Ipv6> next_hop = std::nullopt,
                           std::optional<bool> indirect = std::nullopt) noexcept;
  // Static neighbor edits resolve the stable hardware port key before crossing
  // the shared command ring. The forwarding shard remains the sole owner of
  // operational NUD state and configured adjacency lookup.
  [[nodiscard]] bool install_static_ipv6_neighbor(DeviceHandle device,
                                                  std::string_view port_id,
                                                  const packet::Ipv6 &address,
                                                  packet::Mac mac) noexcept;
  [[nodiscard]] bool
  remove_static_ipv6_neighbor(DeviceHandle device, std::string_view port_id,
                              const packet::Ipv6 &address) noexcept;
  [[nodiscard]] bool install_static_ipv4_neighbor(DeviceHandle device,
                                                  std::string_view port_id,
                                                  std::uint32_t address,
                                                  packet::Mac mac) noexcept;
  [[nodiscard]] bool
  remove_static_ipv4_neighbor(DeviceHandle device, std::string_view port_id,
                              std::uint32_t address) noexcept;
  [[nodiscard]] bool clear_dynamic_ipv4_neighbors(
      DeviceHandle device,
      std::optional<std::string_view> port_id = std::nullopt,
      std::optional<std::uint32_t> address = std::nullopt) noexcept;
  [[nodiscard]] bool clear_dynamic_ipv6_neighbors(
      DeviceHandle device,
      std::optional<std::string_view> port_id = std::nullopt,
      std::optional<packet::Ipv6> address = std::nullopt) noexcept;
  [[nodiscard]] bool start_router_ping(DeviceHandle device,
                                       std::uint32_t destination,
                                       std::uint16_t sequence,
                                       std::uint16_t payload_octets = 56,
                                       bool dont_fragment = false) noexcept;
  [[nodiscard]] bool router_ping_reply(DeviceHandle device,
                                       std::uint16_t sequence) noexcept;
  [[nodiscard]] std::uint64_t
  router_ping_outcome(DeviceHandle device, std::uint16_t sequence) noexcept;
  [[nodiscard]] bool
  start_router_ipv6_ping(DeviceHandle device, const packet::Ipv6 &destination,
                         std::uint16_t sequence,
                         std::uint16_t payload_octets = 56) noexcept;
  [[nodiscard]] bool router_ipv6_ping_reply(DeviceHandle device,
                                            std::uint16_t sequence) noexcept;
  [[nodiscard]] std::uint64_t
  router_ipv6_ping_outcome(DeviceHandle device,
                           std::uint16_t sequence) noexcept;
  [[nodiscard]] bool configure_host(
      HostHandle host, packet::Mac mac, packet::Ipv4 address,
      std::uint8_t prefix_length, packet::Ipv4 gateway, std::uint16_t mtu,
      std::uint64_t interface_id, bool ipv6_autoconfiguration,
      const host::Ipv6InterfaceIdentifierConfiguration &ipv6_identifier,
      crypto::Sha256Digest transport_secret) noexcept;
  [[nodiscard]] bool
  configure_host_dhcpv4_client(const HostDhcpv4ClientProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv4_client(HostHandle host) noexcept;
  [[nodiscard]] bool
  configure_host_dhcpv4_server(const HostDhcpv4ServerProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv4_server(HostHandle host) noexcept;
  [[nodiscard]] std::optional<std::size_t>
  host_dhcpv4_client_lease_count(HostHandle host) noexcept;
  [[nodiscard]] std::optional<dhcpv4::ClientStatus>
  host_dhcpv4_client_status(HostHandle host) noexcept;
  [[nodiscard]] bool
  configure_host_dhcpv6_client(const HostDhcpv6ClientProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv6_client(HostHandle host) noexcept;
  [[nodiscard]] bool
  configure_host_dhcpv6_server(const HostDhcpv6ServerProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dhcpv6_server(HostHandle host) noexcept;
  [[nodiscard]] std::optional<std::size_t>
  host_dhcpv6_client_lease_count(HostHandle host) noexcept;
  // DNS programs are streamed through the control-to-network SPSC boundary.
  // Each commit is all-or-nothing, and signed programs carry only key
  // generation requests. Provider private material never returns to control.
  [[nodiscard]] bool
  configure_host_dns_resolver(const HostDnsResolverProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dns_resolver(HostHandle host) noexcept;
  [[nodiscard]] bool configure_host_dns_authoritative(
      const HostDnsAuthoritativeProgram &program) noexcept;
  [[nodiscard]] bool configure_host_dns_signed_authoritative(
      const HostDnsSignedAuthoritativeProgram &program) noexcept;
  [[nodiscard]] bool remove_host_dns_authoritative(HostHandle host) noexcept;
  [[nodiscard]] bool start_host_ping(HostHandle host, packet::Ipv4 destination,
                                     std::uint16_t sequence) noexcept;
  [[nodiscard]] bool host_ping_reply(HostHandle host,
                                     std::uint16_t sequence) noexcept;
  [[nodiscard]] std::uint64_t
  host_ping_outcome(HostHandle host, std::uint16_t sequence) noexcept;

  [[nodiscard]] RouterHardwareInventory *hardware(DeviceHandle device) noexcept;
  [[nodiscard]] const RouterHardwareInventory *
  hardware(DeviceHandle device) const noexcept;
  [[nodiscard]] const DeviceRegistry &devices() const noexcept {
    return devices_;
  }
  [[nodiscard]] const HostRegistry &hosts() const noexcept { return hosts_; }
  [[nodiscard]] const SwitchRegistry &switches() const noexcept {
    return switches_;
  }
  [[nodiscard]] const TopologyRegistry &topology() const noexcept {
    return topology_;
  }
  [[nodiscard]] const SessionRegistry &sessions() const noexcept {
    return sessions_;
  }
  [[nodiscard]] std::size_t active_links() noexcept;
  [[nodiscard]] bool
  configure_capture_point(const CapturePointProgram &program) noexcept;
  [[nodiscard]] std::span<const std::uint8_t> prepare_capture() noexcept;
  [[nodiscard]] bool clear_capture() noexcept;
  [[nodiscard]] std::size_t captured_frames() noexcept;
  [[nodiscard]] std::uint64_t capture_dropped() noexcept;
  [[nodiscard]] std::uint64_t dropped_packets() noexcept;
  [[nodiscard]] std::optional<RouterForwarderCheckpoint>
  router_operational_state(DeviceHandle device) noexcept;
  [[nodiscard]] std::uint64_t network_thread_id() const noexcept {
    return network_worker_ ? network_worker_->owner_thread_id() : 0U;
  }
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept {
    return network_worker_ ? network_worker_->forwarding_owner_count() : 0U;
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept {
    return network_worker_ ? network_worker_->forwarding_owner_thread_id(index)
                           : 0U;
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept {
    return network_worker_ ? network_worker_->forwarding_owner_turns(index)
                           : 0U;
  }
  [[nodiscard]] std::uint64_t ospf_owner_thread_id() const noexcept {
    return network_worker_ ? network_worker_->ospf_owner_thread_id() : 0U;
  }
  [[nodiscard]] std::unique_ptr<RuntimeSupervisorCheckpoint> checkpoint();
  [[nodiscard]] bool restore(RuntimeSupervisorCheckpoint state);

private:
  struct ResolvedEndpoint {
    PortHandle handle;
    RouterHardwareInventory *router{};
    RouterPortState *router_port{};
    const device_catalog::EthernetSwitchProfile *switch_profile{};
    const SwitchPortIntent *switch_port_intent{};
    std::uint16_t switch_port{};
    bool host{};
  };
  struct RouterNetworkState;

  [[nodiscard]] std::optional<ResolvedEndpoint>
  resolve(const LinkEndpoint &endpoint) noexcept;
  // Router and dedicated-server roles share physical inventory and the
  // multiport network engine. This private admission path is the only place
  // allowed to select the immutable role and its transit-forwarding policy.
  [[nodiscard]] std::optional<DeviceHandle>
  create_network_device(std::string_view node_id, std::string_view profile_id,
                        std::string_view name,
                        device_catalog::DeviceRole expected_role);
  void deactivate(LinkHandle link) noexcept;
  void reconcile(LinkHandle link) noexcept;
  void reconcile(NodeHandle node) noexcept;
  void refresh_router(DeviceHandle device) noexcept;
  void rebuild_routes(DeviceHandle device) noexcept;
  // Internal replay already owns the stable coordinate ordinal. Keeping this
  // entry point ordinal-based avoids serializing a hardware path to text only
  // for the public API to parse it back during card reconciliation.
  [[nodiscard]] bool
  program_dhcpv4_relay(
      DeviceHandle device, std::uint16_t port_ordinal,
      const dhcpv4::RelayInterfaceConfiguration &configuration) noexcept;
  [[nodiscard]] bool
  program_dhcpv6_relay(DeviceHandle device, std::uint16_t port_ordinal,
                       const dhcpv6::RelayInterfaceConfig &configuration,
                       bool retain_legacy_port_intent = true) noexcept;
  [[nodiscard]] bool program_sap_generation(
      DeviceHandle device, std::span<const service::SapAttachment> attachments,
      std::span<const service::ServiceIpv6Interface> interfaces) noexcept;
  [[nodiscard]] bool program_ipv6_address_generation(
      DeviceHandle device,
      std::span<const RouterIpv6Address> addresses) noexcept;
  [[nodiscard]] NetworkCommand &prepare(NetworkCommandKind kind) noexcept;
  [[nodiscard]] std::optional<NetworkResult>
  dispatch(NetworkCommand &command) noexcept;

  DeviceRegistry devices_;
  HostRegistry hosts_;
  SwitchRegistry switches_;
  TopologyRegistry topology_;
  SessionRegistry sessions_;
  SessionWorkflowController session_workflows_;
  std::array<std::optional<RouterHardwareInventory>,
             device_catalog::maximum_routers>
      hardware_{};
  std::array<std::unique_ptr<RouterNetworkState>,
             device_catalog::maximum_routers>
      router_network_{};
  // Channels are allocated before their worker and outlive it. Control is the
  // only command producer and result consumer; the network pthread owns the
  // reverse endpoints plus every mutable packet and fabric structure.
  // One persistent producer scratch value avoids placing a complete maximum
  // FIB payload on the small control pthread stack for every configuration
  // command. Synchronous dispatch guarantees it is never concurrently reused.
  std::unique_ptr<NetworkCommand> network_command_;
  std::unique_ptr<NetworkPlaneChannels> network_channels_;
  std::unique_ptr<NetworkPlaneWorker> network_worker_;
  std::uint64_t next_network_command_id_{1};
};

} // namespace router::lab
