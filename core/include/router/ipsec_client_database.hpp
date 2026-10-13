// Control-owned SR OS IPsec client database and RADIUS policy intent. This
// value module stores operator intent only: client match criteria, tunnel
// setup references, address-assignment sources and RADIUS policy selection.
// Tunnel negotiation, RADIUS packet exchange and AAA server state remain in
// their protocol owners. Secret values are opaque vault handles, never
// plaintext. Cross-list leafrefs (ts-list, tunnel-template, certificate and
// trust-anchor profiles) resolve against the sibling IPsec stores at edit
// time. References without a local owner (DHCP servers and pools, private
// services, router instances, AAA server policies, PKI objects) validate
// structurally here and resolve when their owner connects them.
// Dependency direction is CLI and checkpoint code -> this value model -> the
// sibling IPsec value modules for reference checks, never the reverse.

#pragma once

#include "router/ipsec_credentials_configuration.hpp"
#include "router/ipsec_tunnel_configuration.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace router::ipsec::configuration {

inline constexpr std::size_t maximum_client_databases = 1'000U;
inline constexpr std::uint32_t maximum_client_id = 8'000U;
inline constexpr std::size_t maximum_radius_accounting_policies = 100U;
inline constexpr std::size_t maximum_radius_authentication_policies = 100U;

enum class ClientAction : std::uint8_t { accept, reject };

enum class ClientIdiKind : std::uint8_t {
  none,
  any,
  ipv4_prefix,
  ipv4_prefix_any,
  ipv6_prefix,
  ipv6_prefix_any,
  fqdn,
  fqdn_suffix,
  rfc822,
  rfc822_suffix,
  regexp
};

enum class ClientPeerKind : std::uint8_t {
  none,
  ip_prefix,
  ipv4_only,
  ipv6_only
};

enum class ClientStringKind : std::uint8_t {
  none,
  fqdn,
  fqdn_suffix,
  rfc822,
  rfc822_suffix,
  regexp
};

enum class PskFormat : std::uint8_t { hexadecimal, hash, hash2, custom };

struct ClientIdiCriterion {
  ClientIdiKind kind{ClientIdiKind::none};
  // Prefix storage covers the ipv4-prefix and ipv6-prefix arms. The any arms
  // and the boolean MD spellings select the kind without storing an address.
  std::string prefix{};
  // String storage covers the fqdn, fqdn-suffix, rfc822, rfc822-suffix and
  // regexp arms together with the classic string-type spelling.
  ClientStringKind string_kind{ClientStringKind::none};
  std::string string_value{};

  bool operator==(const ClientIdiCriterion &) const = default;
};

struct ClientPeerCriterion {
  ClientPeerKind kind{ClientPeerKind::none};
  std::string prefix{};

  bool operator==(const ClientPeerCriterion &) const = default;
};

struct ClientLocalV4 {
  std::string router_instance{};
  std::string dhcp_server{};
  std::string pool{};
  std::string secondary_pool{};

  bool operator==(const ClientLocalV4 &) const = default;
};

struct ClientLocalV6 {
  std::string router_instance{};
  std::string dhcp_server{};
  std::string pool{};

  bool operator==(const ClientLocalV6 &) const = default;
};

struct ClientLocalAssignment {
  ClientLocalV4 ipv4{};
  ClientLocalV6 ipv6{};
  bool configured{};

  bool operator==(const ClientLocalAssignment &) const = default;
};

struct ClientCertificate {
  std::string certificate_profile{};
  std::string trust_anchor_profile{};
  RevocationResult default_result{RevocationResult::revoked};
  RevocationMethod primary_method{RevocationMethod::crl};
  RevocationMethod secondary_method{RevocationMethod::none};
  bool default_result_configured{};
  bool methods_configured{};

  bool operator==(const ClientCertificate &) const = default;
};

struct ClientEntry {
  std::uint32_t id{};
  std::string client_name{};
  std::string private_interface{};
  std::string private_service{};
  std::string ts_list{};
  std::uint16_t tunnel_template{};
  ClientAction action{ClientAction::accept};
  // Zero means no credential is configured. A nonzero handle seals the
  // hexadecimal pre-shared key in the vault; classic hash, hash2 and custom
  // spellings select an imported protected form instead of clear input.
  std::uint64_t psk_handle{};
  PskFormat psk_format{PskFormat::hexadecimal};
  bool psk_configured{};
  ClientIdiCriterion idi{};
  ClientPeerCriterion peer{};
  ClientLocalAssignment local{};
  ClientCertificate certificate{};
  bool admin_enabled{};
  bool admin_state_configured{};
  bool action_configured{};
  bool tunnel_template_configured{};

  bool operator==(const ClientEntry &) const = default;
};

struct ClientDatabase {
  std::string name;
  std::string description{};
  bool match_idi{};
  bool match_idi_configured{};
  bool match_peer_ip_prefix{};
  bool match_peer_configured{};
  std::vector<ClientEntry> clients{};
  bool admin_enabled{};
  bool admin_state_configured{};

  bool operator==(const ClientDatabase &) const = default;
};

struct RadiusIncludeAccounting {
  bool acct_stats{};
  bool called_station_id{};
  bool calling_station_id{};
  bool framed_ip_addr{};
  bool framed_ipv6_prefix{};
  bool nas_identifier{};
  bool nas_ip_addr{};
  bool nas_port_id{};

  bool operator==(const RadiusIncludeAccounting &) const = default;
};

struct RadiusIncludeAuthentication {
  bool called_station_id{};
  bool calling_station_id{};
  bool client_cert_subject_key_id{};
  bool nas_identifier{};
  bool nas_ip_addr{};
  bool nas_port_id{};

  bool operator==(const RadiusIncludeAuthentication &) const = default;
};

struct RadiusAccountingPolicy {
  std::string name;
  std::string radius_server_policy{};
  std::uint32_t update_value_minutes{10U};
  std::uint16_t update_jitter_seconds{};
  RadiusIncludeAccounting include_{};
  bool update_value_configured{};
  bool update_jitter_configured{};

  bool operator==(const RadiusAccountingPolicy &) const = default;
};

struct RadiusAuthenticationPolicy {
  std::string name;
  std::string radius_server_policy{};
  // Zero means no password is configured. A nonzero handle seals the
  // authentication password in the vault, never in configuration state.
  std::uint64_t password_handle{};
  bool password_configured{};
  RadiusIncludeAuthentication include_{};

  bool operator==(const RadiusAuthenticationPolicy &) const = default;
};

[[nodiscard]] inline bool valid_client_string_kind(ClientStringKind kind) noexcept {
  return kind == ClientStringKind::fqdn ||
         kind == ClientStringKind::fqdn_suffix ||
         kind == ClientStringKind::rfc822 ||
         kind == ClientStringKind::rfc822_suffix ||
         kind == ClientStringKind::regexp;
}

[[nodiscard]] inline bool valid_client_entry(const ClientEntry &entry) noexcept {
  if (!entry.id || entry.id > maximum_client_id ||
      entry.client_name.size() > 32U ||
      entry.private_interface.size() > 32U ||
      entry.private_service.size() > 32U || entry.ts_list.size() > 32U ||
      (entry.tunnel_template_configured && !entry.tunnel_template) ||
      (entry.action != ClientAction::accept &&
       entry.action != ClientAction::reject))
    return false;
  const auto idi_kind = entry.idi.kind;
  if (idi_kind != ClientIdiKind::none && idi_kind != ClientIdiKind::any &&
      idi_kind != ClientIdiKind::ipv4_prefix &&
      idi_kind != ClientIdiKind::ipv4_prefix_any &&
      idi_kind != ClientIdiKind::ipv6_prefix &&
      idi_kind != ClientIdiKind::ipv6_prefix_any &&
      idi_kind != ClientIdiKind::fqdn &&
      idi_kind != ClientIdiKind::fqdn_suffix &&
      idi_kind != ClientIdiKind::rfc822 &&
      idi_kind != ClientIdiKind::rfc822_suffix &&
      idi_kind != ClientIdiKind::regexp)
    return false;
  if ((idi_kind == ClientIdiKind::ipv4_prefix ||
       idi_kind == ClientIdiKind::ipv6_prefix) &&
      entry.idi.prefix.empty())
    return false;
  if ((idi_kind == ClientIdiKind::fqdn ||
       idi_kind == ClientIdiKind::fqdn_suffix ||
       idi_kind == ClientIdiKind::rfc822 ||
       idi_kind == ClientIdiKind::rfc822_suffix ||
       idi_kind == ClientIdiKind::regexp) &&
      (!valid_client_string_kind(entry.idi.string_kind) ||
       entry.idi.string_value.size() > 255U))
    return false;
  if (entry.peer.kind != ClientPeerKind::none &&
      entry.peer.kind != ClientPeerKind::ip_prefix &&
      entry.peer.kind != ClientPeerKind::ipv4_only &&
      entry.peer.kind != ClientPeerKind::ipv6_only)
    return false;
  if (entry.peer.kind == ClientPeerKind::ip_prefix && entry.peer.prefix.empty())
    return false;
  const auto &local_v4 = entry.local.ipv4;
  const auto &local_v6 = entry.local.ipv6;
  if (local_v4.router_instance.size() > 32U ||
      local_v4.dhcp_server.size() > 32U || local_v4.pool.size() > 32U ||
      local_v4.secondary_pool.size() > 32U ||
      local_v6.router_instance.size() > 32U ||
      local_v6.dhcp_server.size() > 32U || local_v6.pool.size() > 32U)
    return false;
  const auto &cert = entry.certificate;
  if (cert.certificate_profile.size() > 32U ||
      cert.trust_anchor_profile.size() > 32U ||
      (cert.default_result != RevocationResult::revoked &&
       cert.default_result != RevocationResult::good))
    return false;
  const auto valid_method = [](RevocationMethod method) noexcept {
    return method == RevocationMethod::none ||
           method == RevocationMethod::crl || method == RevocationMethod::ocsp;
  };
  if (!valid_method(cert.primary_method) || !valid_method(cert.secondary_method))
    return false;
  return true;
}

[[nodiscard]] inline bool
validate_client_databases(const std::vector<ClientDatabase> &databases,
                          bool allow_incomplete = false) noexcept {
  if (!unique_named_items(databases, maximum_client_databases))
    return false;
  for (const auto &database : databases) {
    if (database.description.size() > 80U ||
        database.clients.size() > maximum_client_id)
      return false;
    for (std::size_t index = 0U; index < database.clients.size(); ++index) {
      const auto &entry = database.clients[index];
      // A sealed handle is required for a configured secret in running
      // state. Sealing can fail while a candidate is still being assembled,
      // so incomplete validation tolerates the missing handle exactly like
      // the sibling PPK validator does.
      if (!valid_client_entry(entry) ||
          (!allow_incomplete && entry.psk_configured && !entry.psk_handle))
        return false;
      if (std::any_of(database.clients.begin(),
                      database.clients.begin() + index,
                      [&](const auto &other) { return other.id == entry.id; }))
        return false;
    }
  }
  return true;
}

[[nodiscard]] inline bool validate_radius_accounting_policies(
    const std::vector<RadiusAccountingPolicy> &policies) noexcept {
  if (!unique_named_items(policies, maximum_radius_accounting_policies))
    return false;
  for (const auto &policy : policies) {
    if (policy.radius_server_policy.size() > 32U ||
        (policy.update_value_configured &&
         policy.update_value_minutes != 0U &&
         (policy.update_value_minutes < 5U ||
          policy.update_value_minutes > 259200U)) ||
        (policy.update_jitter_configured &&
         policy.update_jitter_seconds > 3600U))
      return false;
  }
  return true;
}

[[nodiscard]] inline bool validate_radius_authentication_policies(
    const std::vector<RadiusAuthenticationPolicy> &policies) noexcept {
  if (!unique_named_items(policies, maximum_radius_authentication_policies))
    return false;
  for (const auto &policy : policies) {
    if (policy.radius_server_policy.size() > 32U ||
        (policy.password_configured && !policy.password_handle))
      return false;
  }
  return true;
}

} // namespace router::ipsec::configuration
