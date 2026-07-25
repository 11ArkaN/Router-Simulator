// Browser-facing multi-router control facade. One Worker owns this object and
// is the only caller of mutating methods. RuntimeSupervisor remains the owner
// of device, forwarding and fabric state; this layer owns portable names and
// configuration text that have no place in the packet path.

#pragma once

#include "router/control_projection_worker.hpp"
#include "router/device.hpp"
#include "router/generated_profile.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/runtime_supervisor.hpp"
#include "router/secret_vault.hpp"
#include "router/telemetry.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab {

class LabRuntime final {
public:
  LabRuntime();
  ~LabRuntime() = default;
  LabRuntime(const LabRuntime &) = delete;
  LabRuntime &operator=(const LabRuntime &) = delete;

  // Protocol 3 accepts one complete netstring message. The first field is a
  // generated operation identity and all remaining fields are operation data.
  // The returned string is borrowed until the next command on this owner.
  [[nodiscard]] std::string_view command(std::string_view message);

  // Capture and checkpoint exports are immutable until their next prepare.
  // Callers copy them into a transferable JavaScript buffer before issuing
  // another operation that could replace the backing vector.
  [[nodiscard]] std::span<const std::uint8_t> prepare_capture() noexcept;
  [[nodiscard]] bool clear_capture() noexcept;
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_capture() const noexcept {
    return capture_bytes_;
  }
  [[nodiscard]] std::span<const std::uint8_t> export_checkpoint();
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_checkpoint() const noexcept {
    return checkpoint_bytes_;
  }
  [[nodiscard]] bool import_checkpoint(std::span<const std::uint8_t> bytes);

  // The browser storage owner unwraps one project key and supplies it before
  // project commands or checkpoint import. The key is copied into the vault,
  // and the caller must erase its transient Wasm input immediately afterward.
  [[nodiscard]] bool initialize_secret_vault(
      std::span<const std::uint8_t> wrapping_key,
      std::span<const std::uint8_t> project_context) noexcept;

  [[nodiscard]] const TelemetryPageV6 &telemetry_page() const noexcept {
    return telemetry_;
  }

  // Called only by the serialized browser Worker owner at the generated
  // display cadence. It copies bounded runtime projections into the shared
  // seqlock page and never advances a device timer or network queue.
  void refresh_telemetry() noexcept { publish_telemetry(); }

private:
  struct PortIntent {
    std::string id;
    bool admin_enabled{};
    std::uint16_t mtu{device_catalog::default_network_mtu};
    std::uint32_t speed_mbps{};
    std::string description;
    bool operator==(const PortIntent &) const = default;
  };

  struct MldStaticGroupIntent {
    // A single-group entry has range=false and only multicast_address is a
    // list key. A group-range retains all three YANG keys so configuration,
    // checkpoint and show output do not lose the operator's range expression
    // after the forwarding owner expands it into concrete (*,G)/(S,G) rows.
    packet::Ipv6 multicast_address{};
    packet::Ipv6 range_end{};
    packet::Ipv6 range_step{};
    std::vector<packet::Ipv6> sources;
    bool starg{};
    bool range{};
    bool operator==(const MldStaticGroupIntent &) const = default;
  };

  struct StaticIpv6NeighborIntent {
    // Configuration is keyed by address inside one interface. MAC is the only
    // mutable leaf in the 26.7.R1 YANG list and is replaced atomically.
    packet::Ipv6 address{};
    packet::Mac mac{};
    bool operator==(const StaticIpv6NeighborIntent &) const = default;
  };

  struct StaticIpv4NeighborIntent {
    // SR OS keys this list by IPv4 address inside one Base router interface.
    // Re-entering the key replaces its MAC without disturbing other ARP rows.
    std::uint32_t address{};
    packet::Mac mac{};
    bool operator==(const StaticIpv4NeighborIntent &) const = default;
  };

  struct Ipv6AddressIntent {
    // The address is the list key. Prefix length, DAD policy, primary
    // preference and tag are independent SR OS leaves and therefore survive
    // edits to one another without recreating unrelated addresses.
    packet::Ipv6 address{};
    std::uint32_t primary_preference{};
    std::uint32_t tag{};
    std::uint8_t prefix_length{};
    bool duplicate_address_detection{true};
    // The configured key remains the supplied prefix address. Forwarding gets
    // the MAC-derived address, so a hardware change can be staged atomically
    // without destroying the immutable operator intent.
    bool eui64{};
    // Captured when eui-64 becomes true. SR OS keeps a chassis-derived IID
    // stable if an Ethernet port is attached later.
    packet::Mac eui64_source_mac{};
    bool tag_configured{};
    bool operator==(const Ipv6AddressIntent &) const = default;
  };

  struct RouterAdvertisementDnsIntent {
    // Router-level DNS options are inherited only by interfaces that have
    // include-dns enabled and no interface-local DNS option leaves. Keeping
    // this control-plane value separate from the wire configuration prevents
    // inheritance metadata from crossing into the forwarding shard.
    packet::nd::RdnssInformation rdnss{};
    std::uint32_t rdnss_lifetime_seconds{device_catalog::ra_infinite_lifetime};
    bool rdnss_lifetime_configured{};
    bool operator==(const RouterAdvertisementDnsIntent &) const = default;
  };

  struct InterfaceIntent {
    std::string name;
    std::string port_id;
    packet::Mac mac{};
    std::uint32_t address{};
    std::uint8_t prefix_length{};
    // These are effective Base interface values. Presence remains separate so
    // delete/no can restore the release default even when the configured value
    // happens to equal that default.
    std::uint32_t arp_timeout_seconds{static_cast<std::uint32_t>(
        device_catalog::dynamic_arp_timeout.count())};
    std::uint16_t arp_retry_deciseconds{
        device_catalog::dynamic_arp_retry_deciseconds};
    bool arp_timeout_configured{};
    bool arp_retry_configured{};
    // IPv4 ICMP children exist only while the interface owns an IPv4 address.
    // Effective defaults and explicit presence are both required for MD
    // candidate delete semantics and immediate classic `no redirects`.
    std::uint16_t icmp_redirect_maximum{
        device_catalog::icmp_redirect_default_maximum};
    std::uint16_t icmp_redirect_interval_seconds{static_cast<std::uint16_t>(
        device_catalog::icmp_redirect_default_interval.count())};
    bool icmp_redirects_enabled{true};
    bool icmp_redirect_admin_configured{};
    bool icmp_redirect_maximum_configured{};
    bool icmp_redirect_interval_configured{};
    std::vector<StaticIpv4NeighborIntent> static_ipv4_neighbors;
    packet::Ipv6 ipv6_address{};
    packet::Ipv6 ipv6_link_local{};
    packet::nd::RouterAdvertisementConfig router_advertisement{};
    std::uint8_t ipv6_prefix_length{};
    bool admin_enabled{};
    bool port_configured{};
    bool address_configured{};
    bool ipv6_address_configured{};
    std::vector<Ipv6AddressIntent> ipv6_addresses;
    Ipv6UnsolicitedLearning ipv6_unsolicited_learning{
        Ipv6UnsolicitedLearning::none};
    bool ipv6_unsolicited_learning_configured{};
    // Interface leaves override router IPv6 Neighbor Discovery defaults.
    // Presence is recorded independently because deleting a leaf restores
    // inheritance, which is different from assigning the current default.
    std::uint32_t ipv6_nd_reachable_time_seconds{};
    std::uint32_t ipv6_nd_stale_time_seconds{};
    Ipv6UnsolicitedLearning ipv6_proactive_refresh{
        Ipv6UnsolicitedLearning::none};
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
    std::vector<StaticIpv6NeighborIntent> static_ipv6_neighbors;
    bool router_advertisement_configured{};
    bool router_advertisement_enabled{};
    // MD-CLI distinguishes an absent defaulted leaf from a leaf explicitly
    // configured to its default value. The forwarding shard needs only the
    // effective RouterAdvertisementConfig, so this compact presence bitmap
    // remains exclusively in control-plane intent. Bit meanings are declared
    // next to the command application code, which is the sole mutator.
    std::uint16_t router_advertisement_leaf_presence{};
    // Prefix list entries are stored densely in RouterAdvertisementConfig.
    // Each parallel byte follows the same index and records presence of the
    // four defaulted prefix children: autonomous, on-link, preferred-lifetime
    // and valid-lifetime. List compaction must move both arrays together.
    std::array<std::uint8_t, device_catalog::ipv6_ra_prefixes_per_interface>
        router_advertisement_prefix_leaf_presence{};
    // The interface container overrides router-wide DNS options when either a
    // server or lifetime leaf exists. include-dns has its own defaulted leaf
    // because disabling advertisement must not erase the configured list.
    bool router_advertisement_rdnss_lifetime_configured{};
    bool router_advertisement_include_dns{true};
    bool router_advertisement_include_dns_configured{};
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
    // These values are meaningful only when their matching presence marker is
    // true. A configured value can never be zero because SR OS uses absence,
    // rather than zero, to express an unlimited interface admission policy.
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
    // Empty means no policy attachment and therefore accept all reports. The
    // referenced policy definition is router-owned and resolved at commit.
    std::string mld_import_policy;
    // Interface-local SSM translation is an override set, not an additive
    // extension of the router-level program. An empty vector therefore means
    // inheritance and is distinct from a fabricated empty override context.
    std::vector<MldSsmTranslation> mld_ssm_translations;
    std::vector<MldStaticGroupIntent> mld_static_groups;
    bool operator==(const InterfaceIntent &) const = default;
  };

  struct StaticRouteIntent {
    std::uint32_t network{};
    std::uint32_t next_hop{};
    std::uint8_t prefix_length{};
    bool indirect{};
    bool operator==(const StaticRouteIntent &) const = default;
  };

  struct Ipv6StaticRouteIntent {
    packet::Ipv6 network{};
    packet::Ipv6 next_hop{};
    std::string outgoing_port_id;
    std::uint8_t prefix_length{};
    bool indirect{};
    bool operator==(const Ipv6StaticRouteIntent &) const = default;
  };

  struct MdaConfigurationIntent {
    std::string provisioned;
    bool admin_enabled{};
    bool operator==(const MdaConfigurationIntent &) const = default;
  };

  struct CardConfigurationIntent {
    std::string provisioned;
    bool admin_enabled{};
    std::array<MdaConfigurationIntent,
               device_catalog::maximum_mda_slots_per_card>
        mdas;
    bool operator==(const CardConfigurationIntent &) const = default;
  };

  // A candidate is a value snapshot of configurable router intent. Equipped
  // hardware, carrier, queues and counters are deliberately excluded because
  // those are operational state and must never be replaced by a CLI commit.
  struct ConfigurationIntent {
    std::string system_name;
    std::uint16_t maximum_ecmp_paths{1U};
    MldGlobalIntent mld;
    std::vector<MldPolicyPrefixListIntent> mld_prefix_lists;
    std::vector<MldNamedImportPolicyIntent> mld_import_policies;
    RouterAdvertisementDnsIntent router_advertisement_dns;
    // Router-level ND timers are inherited by every IPv6 interface without an
    // explicit override. Explicit presence is required for MD delete and
    // classic no semantics even when the value equals the release default.
    std::uint32_t ipv6_nd_reachable_time_seconds{
        device_catalog::nd_default_reachable_time_seconds};
    std::uint32_t ipv6_nd_stale_time_seconds{
        device_catalog::nd_default_stale_time_seconds};
    bool ipv6_nd_reachable_time_configured{};
    bool ipv6_nd_stale_time_configured{};
    // Candidate and running datastores retain only configuration references.
    // Decrypted private keys and live SSL contexts remain service-shard state
    // and can never be copied by commit, compare or discard.
    tls_profile::Configuration tls;
    ipsec::configuration::Configuration ipsec;
    service::Configuration ies;
    ospf::RouterConfiguration ospf;
    std::array<CardConfigurationIntent, device_catalog::maximum_card_slots>
        cards;
    std::vector<PortIntent> ports;
    std::vector<InterfaceIntent> interfaces;
    std::vector<StaticRouteIntent> routes;
    std::vector<Ipv6StaticRouteIntent> ipv6_routes;
    bool operator==(const ConfigurationIntent &) const = default;
  };

  struct RouterIntent {
    DeviceHandle handle{};
    std::string node_id;
    std::string system_name;
    std::string profile_id;
    std::uint16_t maximum_ecmp_paths{1U};
    std::vector<PortIntent> ports;
    std::vector<InterfaceIntent> interfaces;
    std::vector<StaticRouteIntent> routes;
    std::vector<Ipv6StaticRouteIntent> ipv6_routes;
    MldGlobalIntent mld;
    std::vector<MldPolicyPrefixListIntent> mld_prefix_lists;
    std::vector<MldNamedImportPolicyIntent> mld_import_policies;
    RouterAdvertisementDnsIntent router_advertisement_dns;
    std::uint32_t ipv6_nd_reachable_time_seconds{
        device_catalog::nd_default_reachable_time_seconds};
    std::uint32_t ipv6_nd_stale_time_seconds{
        device_catalog::nd_default_stale_time_seconds};
    bool ipv6_nd_reachable_time_configured{};
    bool ipv6_nd_stale_time_configured{};
    tls_profile::Configuration tls;
    ipsec::configuration::Configuration ipsec;
    service::Configuration ies;
    ospf::RouterConfiguration ospf;
    ConfigurationIntent global_candidate;
    bool global_candidate_initialized{};
  };

  struct HostIntent {
    HostHandle handle{};
    std::string node_id;
    std::string name;
    packet::Mac mac{};
    packet::Ipv4 address{};
    packet::Ipv4 gateway{};
    std::uint8_t prefix_length{};
    std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
    std::uint64_t interface_id{};
    bool configured{};
    bool ipv6_autoconfiguration{};
    host::Ipv6InterfaceIdentifierConfiguration ipv6_identifier{};
    crypto::Sha256Digest transport_secret{};
  };

  struct SwitchIntent {
    SwitchHandle handle{};
    std::string node_id;
    std::string name;
    std::string profile_id;
    std::vector<SwitchPortIntent> ports;
  };

  struct SessionIntent {
    SessionHandle handle{};
    std::string session_id;
    // Navigation, prompt markers and engine selection belong to the terminal
    // session, not to the selected router or React. The dynamic router state
    // remains in RouterIntent and RuntimeSupervisor, so this object cannot
    // become a hidden single-router datastore.
    CliSession cli{};
    ConfigurationIntent private_candidate;
    bool private_candidate_initialized{};
    // Classic route-policy editing is transactional even though ordinary
    // classic configuration is immediate. This session-owned snapshot exists
    // only between policy-options begin and commit/abort.
    ConfigurationIntent classic_policy_candidate;
    bool classic_policy_edit_active{};
    struct PingOperation {
      std::uint32_t destination{};
      packet::Ipv6 destination_ipv6{};
      std::uint16_t sequence{};
      std::uint16_t payload_octets{device_catalog::default_ping_payload_octets};
      std::uint32_t requested{profile::default_ping_count};
      std::uint32_t sent{};
      std::uint32_t received{};
      // SR OS prints aggregate round-trip statistics after successful probes.
      // Microseconds preserve the documented three-decimal millisecond
      // precision while keeping the bounded maximum count and five-second
      // timeout safe in 64-bit sums, including the sum of squares.
      std::uint64_t rtt_min_microseconds{};
      std::uint64_t rtt_max_microseconds{};
      std::uint64_t rtt_sum_microseconds{};
      std::uint64_t rtt_squared_sum_microseconds{};
      bool dont_fragment{};
      bool ipv6{};
      bool waiting{};
      bool active{};
      bool cancel_requested{};
      std::chrono::steady_clock::time_point next_send{};
      std::chrono::steady_clock::time_point sent_at{};
      std::chrono::steady_clock::time_point reply_deadline{};
    } ping;
  };

  struct CaptureIntent {
    // The facade retains portable location keys so repeated UI toggles reuse
    // one PCAPNG interface identity. The forwarding owner receives only the
    // bounded numeric ID and resolved generation-bearing handles.
    CapturePointId id{};
    CapturePointKind kind{};
    std::string object_id;
    std::string port_id;
    std::uint8_t direction{};
    bool selected{};
  };

  [[nodiscard]] RouterIntent *router(std::string_view id) noexcept;
  [[nodiscard]] const RouterIntent *router(std::string_view id) const noexcept;
  [[nodiscard]] HostIntent *host(std::string_view id) noexcept;
  [[nodiscard]] SwitchIntent *ethernet_switch(std::string_view id) noexcept;
  [[nodiscard]] SessionIntent *session(std::string_view id) noexcept;
  [[nodiscard]] const SessionIntent *
  session(std::string_view id) const noexcept;

  [[nodiscard]] bool create_router(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  replace_router_configuration(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_host(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_switch(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  configure_switch_port(std::span<const std::string_view> fields);
  [[nodiscard]] bool set_card(std::span<const std::string_view> fields);
  [[nodiscard]] bool set_mda(std::span<const std::string_view> fields);
  [[nodiscard]] bool configure_port(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  configure_interface(std::span<const std::string_view> fields);
  [[nodiscard]] bool delete_interface(std::span<const std::string_view> fields);
  [[nodiscard]] bool add_static_route(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  delete_static_route(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_link(std::span<const std::string_view> fields);
  [[nodiscard]] bool configure_host(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  replace_host_dhcpv6(std::span<const std::string_view> fields);
  [[nodiscard]] bool replace_host_dns(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  replace_capture_selection(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_session(std::span<const std::string_view> fields);
  [[nodiscard]] std::string session_state(std::string_view session_id) const;
  [[nodiscard]] std::string execute_session(std::string_view session_id,
                                            std::string_view input);
  [[nodiscard]] std::string poll_session(std::string_view session_id);
  [[nodiscard]] std::string complete_session(std::string_view session_id,
                                             std::string_view input,
                                             std::string_view trigger) const;
  [[nodiscard]] ConfigurationIntent
  running_configuration(const RouterIntent &router) const;
  [[nodiscard]] PortableConfigurationCheckpoint
  portable_configuration(const ConfigurationIntent &value) const;
  [[nodiscard]] bool apply_configuration(RouterIntent &router,
                                         const ConfigurationIntent &value);
  [[nodiscard]] static packet::nd::RouterAdvertisementConfig
  effective_router_advertisement(const RouterAdvertisementDnsIntent &router_dns,
                                 const InterfaceIntent &interface) noexcept;
  [[nodiscard]] bool
  configure_capture(std::span<const std::string_view> fields);
  [[nodiscard]] std::string snapshot();
  void publish_telemetry() noexcept;
  void fail(std::string_view reason);
  void succeed(std::string_view value = "ok");

  RuntimeSupervisor supervisor_;
  // This control-owner repository stores only authenticated ciphertext at
  // rest. Router configuration and protocol shards use opaque 64-bit handles.
  std::optional<vault::SecretVault> secret_vault_;
  std::vector<RouterIntent> routers_;
  std::vector<HostIntent> hosts_;
  std::vector<SwitchIntent> switches_;
  std::vector<SessionIntent> sessions_;
  std::vector<CaptureIntent> capture_intents_;
  // Monotonic within one live runtime. Deselected intent rows are erased, but
  // their numeric identity is not reused inside the current PCAPNG section.
  CapturePointId next_capture_id_{};
  // Present only for the generated high-CPU policy. Declaring it after the
  // supervisor makes it join before the network owners during destruction.
  std::unique_ptr<ControlProjectionWorker> secondary_control_;
  std::uint64_t next_projection_id_{1};
  TelemetryPageV6 telemetry_{};
  std::vector<std::uint8_t> capture_bytes_;
  std::vector<std::uint8_t> checkpoint_bytes_;
  std::string response_;
};

} // namespace router::lab
