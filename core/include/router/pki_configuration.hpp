// Control-owned SR OS public-key infrastructure configuration. This value
// module stores operator intent for CA profiles, common-name lists and EST
// profiles. Enrollment operations, CMP exchanges, CRL fetching and OCSP
// transactions remain in their protocol owners; configuring an EST profile
// never starts enrollment. Certificate and key file leaves are references
// resolved by the file owner, validated here by shape only. Cross-list
// leafrefs from TLS and IPsec configurations into CA profiles and common-name
// lists resolve at terminal-edit and commit time in the runtime owner, which
// sees every subtree at once.
// Dependency direction is CLI and checkpoint code -> this value model. The
// module depends on nothing outside generated limits.

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace router::pki {

inline constexpr std::size_t maximum_ca_profiles = 128U;
inline constexpr std::size_t maximum_common_name_lists = 64U;
inline constexpr std::size_t maximum_common_names_per_list = 128U;
inline constexpr std::size_t maximum_est_profiles = 128U;

enum class RevocationCheck : std::uint8_t { crl, crl_optional };

enum class CommonNameType : std::uint8_t { ip_address, domain_name };

enum class EstServerAddressKind : std::uint8_t { none, ipv4, ipv6, fqdn };

struct CaProfile {
  std::string name;
  std::string description{};
  std::string certificate_file{};
  std::string crl_file{};
  RevocationCheck revocation_check{RevocationCheck::crl};
  bool admin_enabled{};
  bool admin_state_configured{};
  bool revocation_check_configured{};

  bool operator==(const CaProfile &) const = default;
};

struct CommonNameEntry {
  std::uint32_t index{};
  CommonNameType type{CommonNameType::domain_name};
  std::string value{};

  bool operator==(const CommonNameEntry &) const = default;
};

struct CommonNameList {
  std::string name;
  std::vector<CommonNameEntry> entries{};

  bool operator==(const CommonNameList &) const = default;
};

struct EstServerPath {
  std::string cacerts{};
  std::string simple_enroll{};
  std::string simple_reenroll{};

  bool operator==(const EstServerPath &) const = default;
};

struct EstServer {
  std::uint16_t port{443U};
  EstServerAddressKind address_kind{EstServerAddressKind::none};
  std::string address{};
  EstServerPath path{};
  bool port_configured{};

  bool operator==(const EstServer &) const = default;
};

struct EstHttpAuthentication {
  std::string username{};
  // Zero means no password is configured. A nonzero handle seals the EST
  // HTTP password in the vault, never in configuration state.
  std::uint64_t password_handle{};
  bool password_configured{};

  bool operator==(const EstHttpAuthentication &) const = default;
};

struct EstProfile {
  std::string name;
  std::string transmission_profile{};
  std::string client_tls_profile{};
  bool check_id_kp_cmcra_only{};
  bool check_id_kp_cmcra_only_configured{};
  EstServer server{};
  EstHttpAuthentication http_authentication{};

  bool operator==(const EstProfile &) const = default;
};

struct Configuration {
  std::vector<CaProfile> ca_profiles{};
  std::vector<CommonNameList> common_name_lists{};
  std::vector<EstProfile> est_profiles{};

  bool operator==(const Configuration &) const = default;
};

[[nodiscard]] inline bool valid_named_key(std::string_view value,
                                          std::size_t maximum) noexcept {
  return !value.empty() && value.size() <= maximum &&
         std::any_of(value.begin(), value.end(),
                     [](char character) { return character != ' '; });
}

[[nodiscard]] inline bool valid_pki_filename(std::string_view value) noexcept {
  // Checkpoint images bypass grammar validation, so the model repeats the
  // filename constraint: no URL or path separators of either flavor.
  return valid_named_key(value, 95U) &&
         value.find_first_of(":/\\") == std::string_view::npos;
}

[[nodiscard]] inline bool valid_ca_profile(const CaProfile &profile) noexcept {
  if (profile.description.size() > 80U ||
      (!profile.certificate_file.empty() &&
       !valid_pki_filename(profile.certificate_file)) ||
      (!profile.crl_file.empty() && !valid_pki_filename(profile.crl_file)) ||
      (profile.revocation_check != RevocationCheck::crl &&
       profile.revocation_check != RevocationCheck::crl_optional))
    return false;
  return true;
}

[[nodiscard]] inline bool
valid_common_name_list(const CommonNameList &list,
                       bool allow_incomplete = false) noexcept {
  if (list.entries.size() > maximum_common_names_per_list)
    return false;
  for (std::size_t index = 0U; index < list.entries.size(); ++index) {
    const auto &entry = list.entries[index];
    // The type and value leaves are mandatory in running state. A candidate
    // entry under construction may carry the key with one leaf still missing;
    // commit and classic apply still require the complete record.
    if (!entry.index || entry.index > maximum_common_names_per_list ||
        (entry.type != CommonNameType::ip_address &&
         entry.type != CommonNameType::domain_name) ||
        (!allow_incomplete &&
         (entry.value.empty() || entry.value.size() > 255U)) ||
        (allow_incomplete && entry.value.size() > 255U) ||
        std::any_of(list.entries.begin(), list.entries.begin() + index,
                    [&](const auto &other) { return other.index == entry.index; }))
      return false;
  }
  return true;
}

[[nodiscard]] inline bool valid_est_profile(const EstProfile &profile) noexcept {
  if (profile.transmission_profile.size() > 32U ||
      profile.client_tls_profile.size() > 32U ||
      profile.server.path.cacerts.size() > 255U ||
      profile.server.path.simple_enroll.size() > 255U ||
      profile.server.path.simple_reenroll.size() > 255U ||
      profile.http_authentication.username.size() > 32U ||
      profile.server.port == 0U)
    return false;
  // An address kind without an address (or vice versa) is malformed in both
  // engines. A profile without any server address stays configurable; tunnel
  // setup reports an explicit error instead of using it.
  if (profile.server.address_kind == EstServerAddressKind::none)
    return profile.server.address.empty();
  return !profile.server.address.empty() &&
         profile.server.address.size() <= 255U;
}

[[nodiscard]] inline bool validate(const Configuration &state,
                                   bool allow_incomplete = false) noexcept {
  static_cast<void>(allow_incomplete);
  if (state.ca_profiles.size() > maximum_ca_profiles ||
      state.common_name_lists.size() > maximum_common_name_lists ||
      state.est_profiles.size() > maximum_est_profiles)
    return false;
  const auto unique_names = [](const auto &items) {
    for (std::size_t index = 0U; index < items.size(); ++index) {
      if (!valid_named_key(items[index].name, 32U) ||
          std::any_of(items.begin(), items.begin() + index,
                      [&](const auto &other) {
                        return other.name == items[index].name;
                      }))
        return false;
    }
    return true;
  };
  if (!unique_names(state.ca_profiles) ||
      !unique_names(state.common_name_lists) ||
      !unique_names(state.est_profiles))
    return false;
  for (const auto &profile : state.ca_profiles) {
    if (!valid_ca_profile(profile))
      return false;
  }
  for (const auto &list : state.common_name_lists) {
    if (!valid_common_name_list(list, allow_incomplete))
      return false;
  }
  for (const auto &profile : state.est_profiles) {
    if (!valid_est_profile(profile))
      return false;
  }
  return true;
}
[[nodiscard]] inline const CaProfile *
find_ca_profile(const Configuration &state, std::string_view name) noexcept {
  const auto found =
      std::find_if(state.ca_profiles.begin(), state.ca_profiles.end(),
                   [name](const auto &profile) { return profile.name == name; });
  return found == state.ca_profiles.end() ? nullptr : &*found;
}

template <typename Item>
[[nodiscard]] inline Item *find_named(std::vector<Item> &items,
                                     std::string_view name) noexcept {
  const auto found =
      std::find_if(items.begin(), items.end(),
                   [name](const auto &item) { return item.name == name; });
  return found == items.end() ? nullptr : &*found;
}

template <typename Item>
[[nodiscard]] inline const Item *
find_named(const std::vector<Item> &items, std::string_view name) noexcept {
  const auto found =
      std::find_if(items.begin(), items.end(),
                   [name](const auto &item) { return item.name == name; });
  return found == items.end() ? nullptr : &*found;
}

[[nodiscard]] inline const CommonNameList *
find_common_name_list(const Configuration &state,
                      std::string_view name) noexcept {
  const auto found = std::find_if(
      state.common_name_lists.begin(), state.common_name_lists.end(),
      [name](const auto &list) { return list.name == name; });
  return found == state.common_name_lists.end() ? nullptr : &*found;
}

} // namespace router::pki
