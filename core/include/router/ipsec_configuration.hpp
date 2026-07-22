// Control-owned IPsec configuration corresponding to the SR OS /configure/ipsec
// transform lists. The model stores operator intent only. Live IKE SAs, CHILD
// SAs, keys, replay windows and counters remain in their protocol owners.
// Dependency direction is CLI and checkpoint code -> this value model -> no
// runtime, forwarding, browser or cryptographic implementation dependency.

#pragma once

#include "router/generated_profile.hpp"
#include "router/ipsec_credentials_configuration.hpp"
#include "router/ipsec_traffic_selector_configuration.hpp"
#include "router/ipsec_tunnel_configuration.hpp"

#include <algorithm>
#include <cstdint>
#include <string_view>
#include <vector>

namespace router::ipsec::configuration {

// Only suites implemented by the cryptographic packet path are representable.
// This prevents a documented but weak SR OS keyword from becoming a successful
// configuration no-op. Additional suites require codec, source and test work
// before they can be added to these enums and to the generated CLI grammar.
enum class AesGcmKeySize : std::uint16_t {
  aes128 = 128U,
  aes192 = 192U,
  aes256 = 256U
};

enum class DiffieHellmanGroup : std::uint16_t { ecp256 = 19U };

struct IkeTransform {
  std::uint16_t id{};
  DiffieHellmanGroup dh_group{DiffieHellmanGroup::ecp256};
  AesGcmKeySize encryption{AesGcmKeySize::aes128};
  std::uint32_t lifetime_seconds{86'400U};

  // IKE AES-GCM requires a separate PRF but no independent integrity transform.
  // Presence flags preserve the MD datastore distinction between an explicitly
  // configured default and an inherited/defaulted leaf removed with delete.
  bool dh_group_configured{};
  bool authentication_encryption_configured{};
  bool encryption_configured{};
  bool prf_sha256_configured{};
  bool lifetime_configured{};

  bool operator==(const IkeTransform &) const = default;
};

struct IpsecTransform {
  std::uint16_t id{};
  AesGcmKeySize encryption{AesGcmKeySize::aes128};
  DiffieHellmanGroup pfs_group{DiffieHellmanGroup::ecp256};
  std::uint32_t lifetime_seconds{};
  bool authentication_encryption_configured{};
  bool encryption_configured{};
  bool extended_sequence_number{true};
  bool extended_sequence_number_configured{};
  bool lifetime_configured{};
  bool pfs_enabled{};
  bool pfs_group_configured{};

  bool operator==(const IpsecTransform &) const = default;
};

enum class AuthenticationMethod : std::uint8_t { psk, certificate, symmetric };

struct IkePolicy {
  std::uint16_t id{};
  std::string description;
  std::vector<std::uint16_t> ike_transforms;
  AuthenticationMethod peer_authentication{AuthenticationMethod::psk};
  AuthenticationMethod own_authentication{AuthenticationMethod::symmetric};
  std::uint32_t ipsec_lifetime_seconds{3'600U};
  std::uint16_t fragmentation_mtu{1'500U};
  std::uint8_t fragmentation_reassembly_timeout_seconds{2U};
  std::uint16_t dpd_interval_seconds{30U};
  std::uint8_t dpd_max_retries{3U};
  std::uint16_t nat_keepalive_interval_seconds{};
  // These presence bits are separate from child leaf presence. In MD-CLI the
  // three containers can exist with default-valued children, while classic
  // CLI creates or removes each container with one compound command. Losing
  // that distinction during checkpointing changes both `info` output and live
  // IKE behavior after restore.
  bool fragmentation_configured{};
  bool dpd_configured{};
  bool nat_traversal_configured{};
  bool ike_version2_configured{};
  bool peer_authentication_configured{};
  bool own_authentication_configured{};
  bool ipsec_lifetime_configured{};
  bool fragmentation_mtu_configured{};
  bool fragmentation_reassembly_timeout_configured{};
  bool dpd_interval_configured{};
  bool dpd_max_retries_configured{};
  bool dpd_reply_only{};
  bool dpd_reply_only_configured{};
  bool nat_force{};
  bool nat_force_configured{};
  bool nat_force_keepalive{true};
  bool nat_force_keepalive_configured{};
  bool nat_keepalive_interval_configured{};

  bool operator==(const IkePolicy &) const = default;
};

enum class StaticSaAuthentication : std::uint8_t { md5, sha1 };
enum class StaticSaKeyFormat : std::uint8_t {
  encrypted_leaf,
  ascii,
  hexadecimal
};
enum class StaticSaDirection : std::uint8_t {
  inbound,
  outbound,
  bidirectional
};

struct StaticSa {
  std::string name;
  std::string description;
  // Classic SR OS documents SHA-1 as the manual-SA authentication default.
  // Presence remains separate because a default algorithm without key
  // material cannot activate an SA and must never create a usable SAD entry.
  StaticSaAuthentication authentication{StaticSaAuthentication::sha1};
  StaticSaKeyFormat authentication_key_format{StaticSaKeyFormat::encrypted_leaf};
  StaticSaDirection direction{StaticSaDirection::bidirectional};
  SecurityProtocol protocol{SecurityProtocol::esp};
  // The common vault authenticates this purpose separately from IKE PSKs and
  // PPKs. The configuration graph retains no plaintext or protected CLI token.
  std::uint64_t authentication_key_handle{};
  std::uint32_t spi{};
  bool authentication_container_configured{};
  bool authentication_configured{};
  bool direction_configured{};
  bool protocol_configured{};
  bool spi_configured{};

  bool operator==(const StaticSa &) const = default;
};

struct Configuration {
  // Vector capacities are validated against generated release limits before a
  // mutation is committed. Values are snapshots copied by candidate workflows;
  // no pointer into either vector crosses a control-shard message boundary.
  std::vector<IkeTransform> ike_transforms;
  std::vector<IpsecTransform> ipsec_transforms;
  std::vector<IkePolicy> ike_policies;
  std::vector<StaticSa> static_sas;
  std::vector<CertificateProfile> certificate_profiles;
  std::vector<TrustAnchorProfile> trust_anchor_profiles;
  std::vector<PpkList> ppk_lists;
  std::vector<TrafficSelectorList> traffic_selector_lists;
  std::vector<TransportModeProfile> transport_mode_profiles;
  std::vector<TunnelTemplate> tunnel_templates;

  bool operator==(const Configuration &) const = default;
};

[[nodiscard]] inline IkeTransform *find_ike(Configuration &state,
                                            std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ike_transforms.begin(),
                                  state.ike_transforms.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ike_transforms.end() ? nullptr : &*found;
}

[[nodiscard]] inline IkePolicy *find_policy(Configuration &state,
                                            std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ike_policies.begin(),
                                  state.ike_policies.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ike_policies.end() ? nullptr : &*found;
}

[[nodiscard]] inline const IkePolicy *
find_policy(const Configuration &state, std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ike_policies.begin(),
                                  state.ike_policies.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ike_policies.end() ? nullptr : &*found;
}

[[nodiscard]] inline const IkeTransform *
find_ike(const Configuration &state, std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ike_transforms.begin(),
                                  state.ike_transforms.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ike_transforms.end() ? nullptr : &*found;
}

[[nodiscard]] inline IpsecTransform *find_ipsec(Configuration &state,
                                                std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ipsec_transforms.begin(),
                                  state.ipsec_transforms.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ipsec_transforms.end() ? nullptr : &*found;
}

[[nodiscard]] inline const IpsecTransform *
find_ipsec(const Configuration &state, std::uint16_t id) noexcept {
  const auto found = std::find_if(state.ipsec_transforms.begin(),
                                  state.ipsec_transforms.end(),
                                  [id](const auto &item) { return item.id == id; });
  return found == state.ipsec_transforms.end() ? nullptr : &*found;
}

[[nodiscard]] constexpr std::string_view
encryption_name(AesGcmKeySize value) noexcept {
  switch (value) {
  case AesGcmKeySize::aes128:
    return "aes128-gcm16";
  case AesGcmKeySize::aes192:
    return "aes192-gcm16";
  case AesGcmKeySize::aes256:
    return "aes256-gcm16";
  }
  return {};
}

// Returns true only for a canonical, reference-complete configuration. This
// validates persisted or externally reconstructed state; interactive candidate
// editing may temporarily contain an unreferenced or partially specified list
// entry exactly as SR OS does before commit.
[[nodiscard]] inline bool validate(const Configuration &state,
                                   bool allow_incomplete = false) noexcept {
  if (state.ike_transforms.size() > profile::maximum_ike_transforms ||
      state.ipsec_transforms.size() > profile::maximum_ipsec_transforms ||
      state.ike_policies.size() > profile::maximum_ike_policies ||
      !unique_named_items(state.static_sas, profile::maximum_static_sas) ||
      !validate_certificate_profiles(state.certificate_profiles,
                                     allow_incomplete) ||
      !validate_trust_anchor_profiles(state.trust_anchor_profiles) ||
      !validate_ppk_lists(state.ppk_lists, allow_incomplete) ||
      !validate_traffic_selector_lists(state.traffic_selector_lists,
                                       allow_incomplete) ||
      !validate_transport_profiles(state.transport_mode_profiles) ||
      !validate_tunnel_templates(state.tunnel_templates))
    return false;
  for (const auto &association : state.static_sas) {
    const bool valid_authentication =
        association.authentication == StaticSaAuthentication::md5 ||
        association.authentication == StaticSaAuthentication::sha1;
    const bool valid_direction =
        association.direction == StaticSaDirection::inbound ||
        association.direction == StaticSaDirection::outbound ||
        association.direction == StaticSaDirection::bidirectional;
    const bool valid_protocol = association.protocol == SecurityProtocol::ah ||
                                association.protocol == SecurityProtocol::esp;
    const bool valid_key_format =
        association.authentication_key_format ==
            StaticSaKeyFormat::encrypted_leaf ||
        association.authentication_key_format == StaticSaKeyFormat::ascii ||
        association.authentication_key_format ==
            StaticSaKeyFormat::hexadecimal;
    if (association.description.size() > 32U ||
        (!association.description.empty() &&
         std::all_of(association.description.begin(),
                     association.description.end(),
                     [](char character) { return character == ' '; })) ||
        !valid_authentication || !valid_key_format || !valid_direction ||
        !valid_protocol ||
        ((association.authentication_configured ||
          association.authentication_key_handle) &&
         !association.authentication_container_configured) ||
        (association.authentication_container_configured &&
         (!association.authentication_configured ||
          !association.authentication_key_handle) && !allow_incomplete) ||
        (association.spi_configured &&
         (association.spi < 256U || association.spi > 16'383U)) ||
        (!association.spi_configured && association.spi != 0U))
      return false;
  }
  const auto unique_ids = [](const auto &items, std::size_t maximum) {
    for (std::size_t left = 0; left < items.size(); ++left) {
      if (!items[left].id || items[left].id > maximum)
        return false;
      for (std::size_t right = left + 1U; right < items.size(); ++right)
        if (items[left].id == items[right].id)
          return false;
    }
    return true;
  };
  if (!unique_ids(state.ike_transforms, profile::maximum_ike_transforms) ||
      !unique_ids(state.ipsec_transforms, profile::maximum_ipsec_transforms) ||
      !unique_ids(state.ike_policies, profile::maximum_ike_policies))
    return false;
  for (const auto &transform : state.ike_transforms) {
    // The implemented release profile intentionally exposes only the ECP-256
    // group and authenticated AES-GCM suites that have a real packet path.
    if (transform.dh_group != DiffieHellmanGroup::ecp256 ||
        (transform.encryption != AesGcmKeySize::aes128 &&
         transform.encryption != AesGcmKeySize::aes256) ||
        transform.lifetime_seconds < 1'200U ||
        transform.lifetime_seconds > 31'536'000U)
      return false;
  }
  for (const auto &transform : state.ipsec_transforms) {
    if (transform.pfs_group != DiffieHellmanGroup::ecp256 ||
        (transform.encryption != AesGcmKeySize::aes128 &&
         transform.encryption != AesGcmKeySize::aes192 &&
         transform.encryption != AesGcmKeySize::aes256) ||
        (transform.lifetime_configured &&
         (transform.lifetime_seconds < 1'200U ||
          transform.lifetime_seconds > 31'536'000U)))
      return false;
  }
  for (const auto &policy : state.ike_policies) {
    if (policy.description.size() > 80U ||
        (!policy.description.empty() &&
         std::all_of(policy.description.begin(), policy.description.end(),
                     [](char character) { return character == ' '; })) ||
        policy.ike_transforms.size() > 4U ||
        policy.peer_authentication != AuthenticationMethod::psk ||
        policy.own_authentication != AuthenticationMethod::symmetric ||
        policy.ipsec_lifetime_seconds < 1'200U ||
        policy.ipsec_lifetime_seconds > 31'536'000U ||
        policy.fragmentation_mtu < 512U || policy.fragmentation_mtu > 9'000U ||
        policy.fragmentation_reassembly_timeout_seconds < 1U ||
        policy.fragmentation_reassembly_timeout_seconds > 5U ||
        policy.dpd_interval_seconds < 10U ||
        policy.dpd_interval_seconds > 300U || policy.dpd_max_retries < 2U ||
        policy.dpd_max_retries > 5U ||
        ((policy.fragmentation_mtu_configured ||
          policy.fragmentation_reassembly_timeout_configured) &&
         !policy.fragmentation_configured) ||
        ((policy.dpd_interval_configured ||
          policy.dpd_max_retries_configured ||
          policy.dpd_reply_only_configured) &&
         !policy.dpd_configured) ||
        ((policy.nat_force_configured ||
          policy.nat_force_keepalive_configured ||
          policy.nat_keepalive_interval_configured) &&
         !policy.nat_traversal_configured) ||
        (policy.nat_keepalive_interval_configured &&
         (policy.nat_keepalive_interval_seconds < 120U ||
          policy.nat_keepalive_interval_seconds > 600U)))
      return false;
    for (std::size_t index = 0; index < policy.ike_transforms.size(); ++index) {
      if (!find_ike(state, policy.ike_transforms[index]))
        return false;
      if (std::find(policy.ike_transforms.begin(),
                    policy.ike_transforms.begin() + index,
                    policy.ike_transforms[index]) !=
          policy.ike_transforms.begin() + index)
        return false;
    }
  }
  const auto valid_transform_refs = [&](const auto &references) {
    for (std::size_t index = 0; index < references.size(); ++index) {
      if (!find_ipsec(state, references[index]) ||
          std::find(references.begin(), references.begin() + index,
                    references[index]) != references.begin() + index)
        return false;
    }
    return true;
  };
  for (const auto &transport : state.transport_mode_profiles) {
    const auto *ppk_list = transport.dynamic.ppk_list.empty()
                               ? nullptr
                               : find_named(state.ppk_lists,
                                            transport.dynamic.ppk_list);
    const bool ppk_id_exists =
        transport.dynamic.ppk_id.empty() ||
        (ppk_list && std::any_of(ppk_list->entries.begin(),
                                ppk_list->entries.end(), [&](const auto &entry) {
                                  return entry.id == transport.dynamic.ppk_id;
                                }));
    if ((transport.dynamic.ike_policy &&
         !find_policy(state, transport.dynamic.ike_policy)) ||
        !valid_transform_refs(transport.dynamic.ipsec_transforms) ||
        (!transport.dynamic.certificate_profile.empty() &&
         !find_named(state.certificate_profiles,
                     transport.dynamic.certificate_profile)) ||
        (!transport.dynamic.trust_anchor_profile.empty() &&
         !find_named(state.trust_anchor_profiles,
                     transport.dynamic.trust_anchor_profile)) ||
        (!transport.dynamic.ppk_list.empty() && !ppk_list) || !ppk_id_exists)
      return false;
  }
  for (const auto &tunnel : state.tunnel_templates)
    if (!valid_transform_refs(tunnel.ipsec_transforms) ||
        (!tunnel.ppk_list.empty() &&
         !find_named(state.ppk_lists, tunnel.ppk_list)))
      return false;
  return true;
}

} // namespace router::ipsec::configuration
