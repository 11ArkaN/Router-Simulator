// Canonical control-owned OSPF configuration shared by MD-CLI, classic CLI,
// persistence and the protocol process. It contains intent only: no neighbor,
// LSDB, timer, route or forwarding state can enter this datastore.

#pragma once

#include "router/ip_address.hpp"
#include "router/ospf_fsm.hpp"
#include "router/ospf_keychain.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace router::ospf {

enum class AddressFamily : std::uint8_t {
  ipv4,
  ipv6,
  ipv4_over_ospfv3
};

enum class AreaType : std::uint8_t {
  normal,
  stub,
  totally_stub,
  nssa
};

enum class AuthenticationMode : std::uint8_t {
  none,
  simple_password,
  message_digest,
  keychain,
  authentication_trailer,
  ipsec_security_association
};

struct AreaRangeConfiguration {
  ip::IpPrefix prefix{};
  std::optional<std::uint32_t> advertised_metric{};
  bool advertise{true};
  bool operator==(const AreaRangeConfiguration &) const = default;
};

struct NbmaNeighborConfiguration {
  ip::IpAddress address{};
  std::uint8_t priority{};
  std::uint16_t poll_interval_seconds{};
  bool operator==(const NbmaNeighborConfiguration &) const = default;
};

struct InterfaceConfigurationIntent {
  std::string interface_name{};
  std::string keychain{};
  // SR OS permits one bidirectional SA name or distinct inbound and outbound
  // names. Storing the directions separately avoids silently treating an
  // inbound-only association as usable for transmission. The CLI maps the
  // bidirectional form to equal names in both fields.
  std::string ipsec_sa_inbound{};
  std::string ipsec_sa_outbound{};
  // Direct OSPFv2 credentials are purpose-bound SecretVault handles. Key ID
  // is used by message-digest authentication and remains zero for the
  // fixed-width simple-password field. Plaintext never enters configuration.
  vault::SecretHandle authentication_secret{};
  std::uint8_t authentication_key_id{};
  std::uint32_t cost{};
  std::uint16_t hello_interval_seconds{};
  std::uint16_t dead_interval_seconds{};
  std::uint16_t retransmit_interval_seconds{};
  std::uint16_t transmit_delay_seconds{};
  std::uint8_t priority{};
  // SR OS 26.7 derives the default from the bound physical medium. Every
  // routed physical interface currently exposed by the hardware catalog is
  // Ethernet, and an interface whose physical type is still unknown also
  // defaults to broadcast. SONET support must introduce its own derived
  // point-to-point default rather than changing this Ethernet intent.
  NetworkType network_type{NetworkType::broadcast};
  AuthenticationMode authentication{AuthenticationMode::none};
  bool passive{};
  bool mtu_mismatch_ignore{};
  bool admin_enabled{};
  std::vector<NbmaNeighborConfiguration> nbma_neighbors{};
  bool operator==(const InterfaceConfigurationIntent &) const = default;
};

struct VirtualLinkConfiguration {
  std::uint32_t transit_area_id{};
  std::uint32_t remote_router_id{};
  std::uint16_t hello_interval_seconds{};
  std::uint16_t dead_interval_seconds{};
  std::uint16_t retransmit_interval_seconds{};
  std::uint16_t transmit_delay_seconds{};
  AuthenticationMode authentication{AuthenticationMode::none};
  std::string keychain{};
  // Virtual links use the same direction-specific OSPF3 authentication
  // contract as physical interfaces. The eventual packet still traverses the
  // resolved transit interface and is never delivered directly to the peer.
  std::string ipsec_sa_inbound{};
  std::string ipsec_sa_outbound{};
  vault::SecretHandle authentication_secret{};
  std::uint8_t authentication_key_id{};
  bool admin_enabled{};
  bool operator==(const VirtualLinkConfiguration &) const = default;
};

struct AreaConfiguration {
  std::uint32_t area_id{};
  AreaType type{AreaType::normal};
  // Nokia SR OS 26.7 documents metric 1 as the default route metric generated
  // by an ABR into a stub area.
  std::uint32_t default_metric{1U};
  bool summaries{true};
  bool nssa_translate_always{};
  std::vector<AreaRangeConfiguration> ranges{};
  std::vector<InterfaceConfigurationIntent> interfaces{};
  std::vector<VirtualLinkConfiguration> virtual_links{};
  bool operator==(const AreaConfiguration &) const = default;
};

struct InstanceConfiguration {
  std::string export_policy{};
  std::optional<std::uint32_t> configured_router_id{};
  // The ASBR presence container gates all RTM export. OSPFv2 trace-path uses
  // one domain bit to prevent redistribution loops between protocol instances;
  // absence is distinct from the documented numeric domain values.
  std::optional<std::uint8_t> asbr_trace_path_domain_id{};
  // SR OS stores reference-bandwidth in kb/s. Keeping the source unit here
  // avoids rounding high-speed port values before the auto-cost division.
  std::uint64_t reference_bandwidth_kbps{};
  std::uint32_t router_preference{};
  std::uint32_t external_preference{};
  std::uint32_t spf_initial_wait_milliseconds{};
  std::uint32_t spf_second_wait_milliseconds{};
  std::uint32_t spf_maximum_wait_milliseconds{};
  std::uint32_t lsa_initial_wait_milliseconds{};
  std::uint32_t lsa_second_wait_milliseconds{};
  std::uint32_t lsa_maximum_wait_milliseconds{};
  std::uint8_t instance_id{};
  AddressFamily address_family{AddressFamily::ipv4};
  bool asbr{};
  bool graceful_restart_helper{};
  // Local LFA is operator-controlled in SR OS. Keeping the switch in the
  // canonical instance intent prevents a CLI command from becoming a no-op
  // and lets the SPF owner decide whether alternate next hops are published.
  bool loopfree_alternates{};
  bool overload{};
  bool admin_enabled{};
  std::vector<AreaConfiguration> areas{};
  bool operator==(const InstanceConfiguration &) const = default;
};

struct RouterConfiguration {
  // System keychains are stored alongside the OSPF intent in this bounded
  // vertical slice because OSPF is their first consumer. Secret bytes remain
  // in SecretVault and only authenticated handles enter this value model.
  std::vector<KeychainConfiguration> keychains{};
  std::vector<InstanceConfiguration> instances{};
  bool operator==(const RouterConfiguration &) const = default;
};

enum class ConfigurationStatus : std::uint8_t {
  valid,
  duplicate_instance,
  duplicate_area,
  duplicate_interface,
  invalid_instance,
  invalid_area,
  invalid_timer,
  invalid_reference
};

// Defaults are read from the generated release profile. Instance zero is not
// implied by this factory: the caller supplies the exact version-visible ID.
[[nodiscard]] InstanceConfiguration
default_instance(AddressFamily family, std::uint8_t instance_id);
[[nodiscard]] ConfigurationStatus
validate(const RouterConfiguration &configuration,
         bool allow_incomplete = false) noexcept;

} // namespace router::ospf
