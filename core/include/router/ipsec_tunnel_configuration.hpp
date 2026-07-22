// SR OS IPsec transport-profile and tunnel-template intent. The control shard
// owns these values. IKE consumes immutable references for negotiation and the
// forwarding shard consumes compiled parameters for encapsulation, PMTU and
// replay handling. Live tunnel state and counters are deliberately excluded.

#pragma once

#include "router/generated_profile.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router::ipsec::configuration {

enum class IdentityType : std::uint8_t { automatic, fqdn, ipv4, ipv6 };
enum class RevocationResult : std::uint8_t { revoked, good };
enum class RevocationMethod : std::uint8_t { none, crl, ocsp };
enum class ServiceProviderReverseRoute : std::uint8_t {
  none,
  use_security_policy
};

struct DynamicKeyExchange {
  std::uint16_t ike_policy{};
  std::vector<std::uint16_t> ipsec_transforms;
  std::string certificate_profile;
  std::string trust_anchor_profile;
  std::string ppk_list;
  std::string ppk_id;
  // The secret owner returns an opaque handle after sealing a CLI value. The
  // plaintext and protected CLI spelling never enter candidate checkpoints.
  std::uint64_t pre_shared_key_handle{};
  std::string identity;
  IdentityType identity_type{IdentityType::automatic};
  RevocationResult default_revocation_result{RevocationResult::revoked};
  RevocationMethod primary_revocation_method{RevocationMethod::crl};
  RevocationMethod secondary_revocation_method{RevocationMethod::none};
  bool auto_establish{};
  bool auto_establish_configured{};
  bool default_revocation_result_configured{};
  bool primary_revocation_method_configured{};
  bool secondary_revocation_method_configured{};

  bool operator==(const DynamicKeyExchange &) const = default;
};

struct TransportModeProfile {
  std::string name;
  std::string description;
  DynamicKeyExchange dynamic;
  std::uint16_t replay_window{};
  std::uint8_t maximum_esp_history_records{};
  std::uint8_t maximum_ike_history_records{};
  bool replay_window_configured{};
  bool maximum_esp_history_records_configured{};
  bool maximum_ike_history_records_configured{};

  bool operator==(const TransportModeProfile &) const = default;
};

struct RateLimit {
  // The SR OS model expresses both tunnel ICMP rate intervals in whole
  // seconds. Persisting that native unit avoids lossy or ambiguous conversion
  // when a live rate limiter is reconstructed from a checkpoint.
  std::uint8_t interval_seconds{10U};
  std::uint16_t message_count{100U};
  bool enabled{true};
  bool enabled_configured{};
  bool interval_configured{};
  bool message_count_configured{};

  bool operator==(const RateLimit &) const = default;
};

struct TunnelTemplate {
  std::uint16_t id{};
  std::string description;
  std::vector<std::uint16_t> ipsec_transforms;
  std::string ppk_list;
  std::uint16_t encapsulated_ip_mtu{};
  std::uint16_t ip_mtu{};
  std::uint16_t replay_window{};
  std::uint16_t pmtu_discovery_aging_seconds{900U};
  std::uint16_t private_tcp_mss_adjust{};
  std::uint16_t public_tcp_mss_adjust{};
  std::uint16_t reverse_route_metric{};
  std::uint8_t reverse_route_preference{};
  ServiceProviderReverseRoute service_provider_reverse_route{
      ServiceProviderReverseRoute::none};
  RateLimit ipv4_fragmentation_required;
  RateLimit ipv6_packet_too_big;
  bool clear_df_bit{};
  bool clear_df_bit_configured{};
  bool copy_traffic_class_upon_decapsulation{};
  bool copy_traffic_class_configured{};
  bool ignore_default_route{};
  bool ignore_default_route_configured{};
  bool encapsulated_ip_mtu_configured{};
  bool ip_mtu_configured{};
  bool replay_window_configured{};
  bool pmtu_discovery_aging_configured{};
  bool private_tcp_mss_adjust_configured{};
  bool propagate_pmtu_v4{};
  bool propagate_pmtu_v4_configured{};
  bool propagate_pmtu_v6{};
  bool propagate_pmtu_v6_configured{};
  bool public_tcp_mss_adjust_configured{};
  bool public_tcp_mss_auto{};
  bool reverse_route_metric_configured{};
  bool reverse_route_preference_configured{};
  bool service_provider_reverse_route_configured{};

  bool operator==(const TunnelTemplate &) const = default;
};

template <typename Item>
[[nodiscard]] inline Item *find_named(std::vector<Item> &items,
                                      std::string_view name) noexcept {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [name](const auto &item) {
                                    return item.name == name;
                                  });
  return found == items.end() ? nullptr : &*found;
}

template <typename Item>
[[nodiscard]] inline const Item *find_named(const std::vector<Item> &items,
                                            std::string_view name) noexcept {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [name](const auto &item) {
                                    return item.name == name;
                                  });
  return found == items.end() ? nullptr : &*found;
}

[[nodiscard]] inline TunnelTemplate *
find_tunnel_template(std::vector<TunnelTemplate> &items,
                     std::uint16_t id) noexcept {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [id](const auto &item) {
                                    return item.id == id;
                                  });
  return found == items.end() ? nullptr : &*found;
}

[[nodiscard]] inline bool valid_replay_window(std::uint16_t value) noexcept {
  return value == 32U || value == 64U || value == 128U || value == 256U ||
         value == 512U;
}

[[nodiscard]] inline bool validate_rate_limit(const RateLimit &rate) noexcept {
  return rate.interval_seconds >= 1U && rate.interval_seconds <= 60U &&
         rate.message_count >= 10U &&
         rate.message_count <= 1'000U;
}

[[nodiscard]] inline bool validate_transport_profiles(
    const std::vector<TransportModeProfile> &profiles) noexcept {
  for (std::size_t index = 0; index < profiles.size(); ++index) {
    const auto &profile = profiles[index];
    // Check enum domains explicitly because checkpoint decoding reads their
    // underlying bytes. A cast alone cannot prove that a persisted byte names
    // an SR OS value, and accepting an out-of-domain value would defer a
    // malformed credential policy until IKE authentication is already active.
    const bool valid_identity =
        profile.dynamic.identity_type == IdentityType::automatic ||
        profile.dynamic.identity_type == IdentityType::fqdn ||
        profile.dynamic.identity_type == IdentityType::ipv4 ||
        profile.dynamic.identity_type == IdentityType::ipv6;
    const bool valid_result =
        profile.dynamic.default_revocation_result == RevocationResult::revoked ||
        profile.dynamic.default_revocation_result == RevocationResult::good;
    const auto valid_method = [](RevocationMethod method) noexcept {
      return method == RevocationMethod::none || method == RevocationMethod::crl ||
             method == RevocationMethod::ocsp;
    };
    if (!valid_identity || !valid_result ||
        !valid_method(profile.dynamic.primary_revocation_method) ||
        !valid_method(profile.dynamic.secondary_revocation_method) ||
        profile.name.empty() || profile.name.size() > 32U ||
        profile.description.size() > 80U ||
        profile.dynamic.ipsec_transforms.size() > 4U ||
        profile.dynamic.certificate_profile.size() > 32U ||
        profile.dynamic.trust_anchor_profile.size() > 32U ||
        profile.dynamic.ppk_list.size() > 32U ||
        profile.dynamic.ppk_id.size() > 64U ||
        profile.dynamic.identity.size() > 255U ||
        (profile.replay_window_configured &&
         !valid_replay_window(profile.replay_window)) ||
        (profile.maximum_esp_history_records_configured &&
         (profile.maximum_esp_history_records < 1U ||
          profile.maximum_esp_history_records > 48U)) ||
        (profile.maximum_ike_history_records_configured &&
         (profile.maximum_ike_history_records < 1U ||
          profile.maximum_ike_history_records > 3U)) ||
        std::any_of(profiles.begin(), profiles.begin() + index,
                    [&](const auto &other) {
                      return other.name == profile.name;
                    }))
      return false;
  }
  return true;
}

[[nodiscard]] inline bool validate_tunnel_templates(
    const std::vector<TunnelTemplate> &templates) noexcept {
  if (templates.size() > profile::maximum_tunnel_templates)
    return false;
  for (std::size_t index = 0; index < templates.size(); ++index) {
    const auto &item = templates[index];
    const bool valid_reverse_route =
        item.service_provider_reverse_route ==
            ServiceProviderReverseRoute::none ||
        item.service_provider_reverse_route ==
            ServiceProviderReverseRoute::use_security_policy;
    if (!item.id || item.id > profile::maximum_tunnel_templates ||
        !valid_reverse_route || item.description.size() > 80U ||
        item.ipsec_transforms.size() > 4U ||
        item.ppk_list.size() > 32U ||
        (item.encapsulated_ip_mtu_configured &&
         (item.encapsulated_ip_mtu < 512U ||
          item.encapsulated_ip_mtu > 9'000U)) ||
        (item.ip_mtu_configured &&
         (item.ip_mtu < 512U || item.ip_mtu > 9'000U)) ||
        (item.replay_window_configured &&
         !valid_replay_window(item.replay_window)) ||
        (item.pmtu_discovery_aging_seconds < 900U ||
         item.pmtu_discovery_aging_seconds > 3'600U) ||
        (item.private_tcp_mss_adjust_configured &&
         (item.private_tcp_mss_adjust < 512U ||
          item.private_tcp_mss_adjust > 9'000U)) ||
        (item.public_tcp_mss_adjust_configured &&
         !item.public_tcp_mss_auto &&
         (item.public_tcp_mss_adjust < 512U ||
          item.public_tcp_mss_adjust > 9'000U)) ||
        !validate_rate_limit(item.ipv4_fragmentation_required) ||
        !validate_rate_limit(item.ipv6_packet_too_big) ||
        std::any_of(templates.begin(), templates.begin() + index,
                    [&](const auto &other) { return other.id == item.id; }))
      return false;
  }
  return true;
}

} // namespace router::ipsec::configuration
