// Control-owned SR OS IPsec certificate, trust-anchor and PPK intent. This
// value module owns no provider objects and never stores plaintext secrets.
// PKI and IKE owners resolve immutable filenames, CA-profile references and
// opaque secret handles only after the complete candidate passes validation.

#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace router::ipsec::configuration {

inline constexpr std::size_t maximum_certificate_profiles = 10'200U;
inline constexpr std::size_t maximum_certificate_entries = 8U;
inline constexpr std::size_t maximum_send_chain_profiles = 7U;
inline constexpr std::size_t maximum_trust_anchor_profiles = 10'128U;
inline constexpr std::size_t maximum_trust_anchors = 8U;
inline constexpr std::size_t maximum_ppk_lists = 128U;
inline constexpr std::size_t maximum_ppks_per_list = 128U;

enum class RsaSignature : std::uint8_t { pkcs1, pss };

struct CertificateProfileEntry {
  std::uint8_t id{};
  std::string certificate_file;
  std::string private_key_file;
  std::string compare_chain_include;
  std::vector<std::string> send_chain_ca_profiles;
  RsaSignature rsa_signature{RsaSignature::pkcs1};
  bool rsa_signature_configured{};

  bool operator==(const CertificateProfileEntry &) const = default;
};

struct CertificateProfile {
  std::string name;
  std::vector<CertificateProfileEntry> entries;
  bool enabled{};
  bool admin_state_configured{};

  bool operator==(const CertificateProfile &) const = default;
};

struct TrustAnchorProfile {
  std::string name;
  std::vector<std::string> ca_profiles;

  bool operator==(const TrustAnchorProfile &) const = default;
};

enum class PpkValueFormat : std::uint8_t { ascii, hexadecimal };

struct PpkEntry {
  std::string id;
  // The vault owner maps this stable handle to authenticated encrypted bytes.
  // Zero means that the mandatory value choice is absent in a private
  // candidate and can never be compiled into an active IKE policy.
  std::uint64_t secret_handle{};
  PpkValueFormat format{PpkValueFormat::ascii};

  bool operator==(const PpkEntry &) const = default;
};

struct PpkList {
  std::string name;
  std::vector<PpkEntry> entries;

  bool operator==(const PpkList &) const = default;
};

[[nodiscard]] inline bool valid_named_key(std::string_view value,
                                          std::size_t maximum) noexcept {
  return !value.empty() && value.size() <= maximum &&
         std::any_of(value.begin(), value.end(),
                     [](char character) { return character != ' '; });
}

[[nodiscard]] inline bool valid_pki_filename(std::string_view value) noexcept {
  return valid_named_key(value, 95U) &&
         value.find_first_of(":/") == std::string_view::npos;
}

template <typename Item>
[[nodiscard]] inline bool unique_named_items(const std::vector<Item> &items,
                                             std::size_t maximum) noexcept {
  if (items.size() > maximum)
    return false;
  for (std::size_t index = 0U; index < items.size(); ++index)
    if (!valid_named_key(items[index].name, 32U) ||
        std::any_of(items.begin(), items.begin() + index,
                    [&](const auto &other) {
                      return other.name == items[index].name;
                    }))
      return false;
  return true;
}

[[nodiscard]] inline bool validate_certificate_profiles(
    const std::vector<CertificateProfile> &profiles,
    bool allow_incomplete = false) noexcept {
  if (!unique_named_items(profiles, maximum_certificate_profiles))
    return false;
  for (const auto &profile : profiles) {
    if (profile.entries.size() > maximum_certificate_entries)
      return false;
    for (std::size_t index = 0U; index < profile.entries.size(); ++index) {
      const auto &entry = profile.entries[index];
      const bool valid_signature = entry.rsa_signature == RsaSignature::pkcs1 ||
                                   entry.rsa_signature == RsaSignature::pss;
      if (!entry.id || entry.id > maximum_certificate_entries ||
          !valid_signature ||
          std::any_of(profile.entries.begin(), profile.entries.begin() + index,
                      [&](const auto &other) { return other.id == entry.id; }) ||
          (!entry.certificate_file.empty() &&
           !valid_pki_filename(entry.certificate_file)) ||
          (!entry.private_key_file.empty() &&
           !valid_pki_filename(entry.private_key_file)) ||
          (!entry.compare_chain_include.empty() &&
           !valid_named_key(entry.compare_chain_include, 32U)) ||
          entry.send_chain_ca_profiles.size() > maximum_send_chain_profiles)
        return false;
      for (std::size_t ca = 0U; ca < entry.send_chain_ca_profiles.size(); ++ca)
        if (!valid_named_key(entry.send_chain_ca_profiles[ca], 32U) ||
            std::find(entry.send_chain_ca_profiles.begin(),
                      entry.send_chain_ca_profiles.begin() + ca,
                      entry.send_chain_ca_profiles[ca]) !=
                entry.send_chain_ca_profiles.begin() + ca)
          return false;
      // An enabled profile must contain at least one complete certificate and
      // private-key pair. Disabled profiles and private candidates may retain
      // partial entries without exposing them to IKE authentication.
      if (!allow_incomplete && profile.enabled &&
          (entry.certificate_file.empty() || entry.private_key_file.empty()))
        return false;
    }
    if (!allow_incomplete && profile.enabled && profile.entries.empty())
      return false;
  }
  return true;
}

[[nodiscard]] inline bool validate_trust_anchor_profiles(
    const std::vector<TrustAnchorProfile> &profiles) noexcept {
  if (!unique_named_items(profiles, maximum_trust_anchor_profiles))
    return false;
  for (const auto &profile : profiles) {
    if (profile.ca_profiles.size() > maximum_trust_anchors)
      return false;
    for (std::size_t index = 0U; index < profile.ca_profiles.size(); ++index)
      if (!valid_named_key(profile.ca_profiles[index], 32U) ||
          std::find(profile.ca_profiles.begin(),
                    profile.ca_profiles.begin() + index,
                    profile.ca_profiles[index]) !=
              profile.ca_profiles.begin() + index)
        return false;
  }
  return true;
}

[[nodiscard]] inline bool validate_ppk_lists(const std::vector<PpkList> &lists,
                                             bool allow_incomplete = false)
    noexcept {
  if (!unique_named_items(lists, maximum_ppk_lists))
    return false;
  for (const auto &list : lists) {
    if (list.entries.size() > maximum_ppks_per_list)
      return false;
    for (std::size_t index = 0U; index < list.entries.size(); ++index) {
      const auto &entry = list.entries[index];
      if (!valid_named_key(entry.id, 64U) ||
          (!allow_incomplete && !entry.secret_handle) ||
          (entry.format != PpkValueFormat::ascii &&
           entry.format != PpkValueFormat::hexadecimal) ||
          std::any_of(list.entries.begin(), list.entries.begin() + index,
                      [&](const auto &other) { return other.id == entry.id; }))
        return false;
    }
  }
  return true;
}

} // namespace router::ipsec::configuration
