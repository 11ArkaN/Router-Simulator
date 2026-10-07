// Control-owned SR OS public-key infrastructure configuration. This value
// module stores operator intent for CA profiles (with OCSP, CMPv2 and
// automatic CRL update subtrees), common-name lists, EST profiles,
// certificate update profiles and certificate auto-update entries, plus the
// top-level display, import, chain-depth and expiration-warning leaves.
// Enrollment operations, CMP exchanges, CRL fetching and OCSP
// transactions remain in their protocol owners; configuring a profile
// never starts enrollment. Certificate and key file leaves are references
// resolved by the file owner, validated here by shape only. Cross-list
// leafrefs from TLS and IPsec configurations into CA profiles and common-name
// lists, and from update profiles into CA and EST profiles, resolve at
// terminal-edit and commit time in the runtime owner, which
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
// YANG caps the CMPv2 initial-authentication key list at 128 entries, the
// automatic CRL update URL list at eight entries, and each update family at
// 256 entries. The classic reference confirms the eight-URL bound.
inline constexpr std::size_t maximum_cmp_keys = 128U;
inline constexpr std::size_t maximum_crl_url_entries = 8U;
inline constexpr std::size_t maximum_certificate_update_profiles = 256U;
inline constexpr std::size_t maximum_certificate_auto_updates = 256U;
inline constexpr std::uint32_t automatic_crl_default_period_seconds = 86400U;
inline constexpr std::uint32_t automatic_crl_default_pre_update_seconds = 3600U;
inline constexpr std::uint32_t automatic_crl_default_retry_seconds = 3600U;
inline constexpr std::uint32_t update_default_retry_seconds = 3600U;
inline constexpr std::uint32_t update_default_before_expiry_seconds = 86400U;

enum class RevocationCheck : std::uint8_t { crl, crl_optional };

enum class CommonNameType : std::uint8_t { ip_address, domain_name };

enum class EstServerAddressKind : std::uint8_t { none, ipv4, ipv6, fqdn };

enum class CertificateDisplayFormat : std::uint8_t { ascii, utf8 };

enum class ImportedFormat : std::uint8_t { any, secure };

enum class OcspServiceKind : std::uint8_t { none, id, name };

enum class CmpResponseSigningKind : std::uint8_t { cert, use_extra_cert };

enum class CmpRecipientKind : std::uint8_t { ca_subject, subject };

enum class HttpVersion : std::uint8_t { v10, v11 };

enum class CmpUrlTransportKind : std::uint8_t {
  none,
  service_id,
  service_name,
  transmission_profile
};

enum class HashAlgorithm : std::uint8_t {
  md5,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512
};

enum class UpdateProtocol : std::uint8_t { cmpv2, est };

enum class KeyGenerationKind : std::uint8_t {
  same_as_existing,
  rsa,
  dsa,
  ecdsa
};

enum class EcdsaCurve : std::uint8_t { secp256r1, secp384r1, secp521r1 };

enum class UpdateScheduleKind : std::uint8_t { before_expiry, after_issue };

enum class AutoCrlScheduleKind : std::uint8_t {
  next_update_based,
  periodic
};

struct OcspConfiguration {
  std::string responder_url{};
  OcspServiceKind service_kind{OcspServiceKind::none};
  // Base-router selection uses identifier zero; service identifiers otherwise
  // span 1 through 2147483647 per the classic reference.
  std::uint32_t service_id{};
  std::string service_name{};
  std::string transmission_profile{};

  bool operator==(const OcspConfiguration &) const = default;
};

struct CmpKey {
  std::string reference{};
  // Zero means no password is configured. A nonzero handle seals the CMPv2
  // initial-authentication key in the vault, never in configuration state.
  std::uint64_t password_handle{};
  bool password_configured{};

  bool operator==(const CmpKey &) const = default;
};

struct Cmpv2Configuration {
  bool always_set_sender_for_ir{};
  bool always_set_sender_for_ir_configured{};
  bool same_recipient_nonce_for_poll_request{};
  bool same_recipient_nonce_for_poll_request_configured{};
  std::string signing_cert_subject{};
  CmpResponseSigningKind response_signing{CmpResponseSigningKind::cert};
  std::string response_signing_cert{};
  bool response_signing_configured{};
  CmpRecipientKind recipient{CmpRecipientKind::ca_subject};
  std::string recipient_subject{};
  bool recipient_configured{};
  bool accept_unprotected_error{};
  bool accept_unprotected_error_configured{};
  bool accept_unprotected_pkiconf{};
  bool accept_unprotected_pkiconf_configured{};
  std::uint32_t http_response_timeout_seconds{30U};
  bool http_response_timeout_configured{};
  HttpVersion http_version{HttpVersion::v11};
  bool http_version_configured{};
  std::string url_string{};
  CmpUrlTransportKind url_transport{CmpUrlTransportKind::none};
  std::uint32_t url_service_id{};
  std::string url_service_name{};
  std::string url_transmission_profile{};
  std::vector<CmpKey> keys{};

  bool operator==(const Cmpv2Configuration &) const = default;
};

struct CrlUrlEntry {
  std::uint32_t entry_id{};
  std::string url{};
  std::string transmission_profile{};

  bool operator==(const CrlUrlEntry &) const = default;
};

struct AutoCrlUpdate {
  // Presence container: entering the context creates it, `no auto-crl-update`
  // removes it. The shutdown leaf is the classic spelling of admin-state.
  bool present{};
  bool admin_enabled{};
  bool admin_state_configured{};
  std::uint32_t periodic_update_seconds{automatic_crl_default_period_seconds};
  bool periodic_update_configured{};
  std::uint32_t pre_update_seconds{automatic_crl_default_pre_update_seconds};
  bool pre_update_configured{};
  std::uint32_t retry_seconds{automatic_crl_default_retry_seconds};
  bool retry_configured{};
  AutoCrlScheduleKind schedule{AutoCrlScheduleKind::next_update_based};
  bool schedule_configured{};
  std::vector<CrlUrlEntry> urls{};

  bool operator==(const AutoCrlUpdate &) const = default;
};

struct CaProfile {
  std::string name;
  std::string description{};
  std::string certificate_file{};
  std::string crl_file{};
  RevocationCheck revocation_check{RevocationCheck::crl};
  bool admin_enabled{};
  bool admin_state_configured{};
  bool revocation_check_configured{};
  OcspConfiguration ocsp{};
  Cmpv2Configuration cmpv2{};
  AutoCrlUpdate auto_crl_update{};

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

struct CertificateUpdateProfile {
  std::string name;
  HashAlgorithm hash_algorithm{HashAlgorithm::sha256};
  bool hash_algorithm_configured{};
  std::uint32_t retry_seconds{update_default_retry_seconds};
  bool retry_configured{};
  UpdateProtocol protocol{UpdateProtocol::cmpv2};
  std::string protocol_profile{};
  bool protocol_configured{};
  KeyGenerationKind key_generation{KeyGenerationKind::same_as_existing};
  std::uint32_t key_size_bits{2048U};
  EcdsaCurve curve{EcdsaCurve::secp256r1};
  UpdateScheduleKind schedule{UpdateScheduleKind::before_expiry};
  std::uint32_t schedule_seconds{update_default_before_expiry_seconds};

  bool operator==(const CertificateUpdateProfile &) const = default;
};

struct CertificateAutoUpdate {
  std::string certificate_file{};
  std::string key_file{};
  std::string profile{};

  bool operator==(const CertificateAutoUpdate &) const = default;
};

struct ExpirationWarning {
  bool hours_configured{};
  std::int32_t hours{};
  bool repeat_configured{};
  std::int32_t repeat_hours{};

  bool operator==(const ExpirationWarning &) const = default;
};

struct Configuration {
  CertificateDisplayFormat display_format{CertificateDisplayFormat::ascii};
  bool display_format_configured{};
  bool dynamic_ca{};
  bool dynamic_ca_configured{};
  ImportedFormat imported_format{ImportedFormat::any};
  bool imported_format_configured{};
  std::uint32_t maximum_cert_chain_depth{7U};
  bool maximum_cert_chain_depth_configured{};
  ExpirationWarning certificate_expiration_warning{};
  ExpirationWarning crl_expiration_warning{};
  std::vector<CaProfile> ca_profiles{};
  std::vector<CommonNameList> common_name_lists{};
  std::vector<EstProfile> est_profiles{};
  std::vector<CertificateUpdateProfile> update_profiles{};
  std::vector<CertificateAutoUpdate> auto_updates{};

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

[[nodiscard]] inline bool valid_pki_url(std::string_view value) noexcept {
  // Shape-only URL check shared by OCSP, CMPv2 and CRL update locations:
  // the YANG 180-octet bound, at least one non-space character, no
  // whitespace. Scheme and host resolution belong to the protocol owner.
  if (value.empty() || value.size() > 180U)
    return false;
  return std::any_of(value.begin(), value.end(),
                     [](char character) { return character != ' '; }) &&
         std::none_of(value.begin(), value.end(), [](char character) {
           return character == ' ' || character == '\t' || character == '\n' ||
                  character == '\r';
         });
}

[[nodiscard]] inline bool valid_dn_subject(std::string_view value) noexcept {
  // Distinguished-name attribute strings carry their own separators, so only
  // the YANG 1..256 bound applies here.
  return !value.empty() && value.size() <= 256U;
}

[[nodiscard]] inline bool
valid_ocsp_configuration(const OcspConfiguration &ocsp) noexcept {
  if ((!ocsp.responder_url.empty() && !valid_pki_url(ocsp.responder_url)) ||
      (ocsp.service_kind == OcspServiceKind::id &&
       ocsp.service_id > 2147483647U) ||
      (ocsp.service_kind == OcspServiceKind::name &&
       !valid_named_key(ocsp.service_name, 64U)) ||
      (ocsp.service_kind == OcspServiceKind::none &&
       (!ocsp.service_name.empty() || ocsp.service_id != 0U)) ||
      ocsp.transmission_profile.size() > 32U)
    return false;
  return true;
}

[[nodiscard]] inline bool
valid_cmpv2_configuration(const Cmpv2Configuration &cmpv2) noexcept {
  if ((!cmpv2.signing_cert_subject.empty() &&
       !valid_dn_subject(cmpv2.signing_cert_subject)) ||
      (cmpv2.response_signing == CmpResponseSigningKind::cert &&
       !cmpv2.response_signing_cert.empty() &&
       !valid_pki_filename(cmpv2.response_signing_cert)) ||
      (cmpv2.response_signing == CmpResponseSigningKind::use_extra_cert &&
       !cmpv2.response_signing_cert.empty()) ||
      (cmpv2.recipient == CmpRecipientKind::subject &&
       !valid_dn_subject(cmpv2.recipient_subject)) ||
      (cmpv2.recipient == CmpRecipientKind::ca_subject &&
       !cmpv2.recipient_subject.empty()) ||
      (cmpv2.http_response_timeout_seconds < 1U ||
       cmpv2.http_response_timeout_seconds > 3600U) ||
      (!cmpv2.url_string.empty() && !valid_pki_url(cmpv2.url_string)) ||
      (cmpv2.url_transport == CmpUrlTransportKind::service_id &&
       cmpv2.url_service_id > 2147483647U) ||
      (cmpv2.url_transport == CmpUrlTransportKind::service_name &&
       !valid_named_key(cmpv2.url_service_name, 64U)) ||
      (cmpv2.url_transport == CmpUrlTransportKind::transmission_profile &&
       (cmpv2.url_transmission_profile.empty() ||
        cmpv2.url_transmission_profile.size() > 32U)) ||
      (cmpv2.url_transport == CmpUrlTransportKind::none &&
       (!cmpv2.url_service_name.empty() ||
        !cmpv2.url_transmission_profile.empty() ||
        cmpv2.url_service_id != 0U)) ||
      cmpv2.keys.size() > maximum_cmp_keys)
    return false;
  for (std::size_t index = 0U; index < cmpv2.keys.size(); ++index) {
    const auto &key = cmpv2.keys[index];
    if (!valid_named_key(key.reference, 64U) ||
        std::any_of(cmpv2.keys.begin(), cmpv2.keys.begin() + index,
                    [&](const auto &other) {
                      return other.reference == key.reference;
                    }))
      return false;
  }
  return true;
}

[[nodiscard]] inline bool
valid_auto_crl_update(const AutoCrlUpdate &update) noexcept {
  if ((update.periodic_update_seconds < 3600U ||
       update.periodic_update_seconds > 31622400U) ||
      update.pre_update_seconds > 31622400U ||
      update.retry_seconds > 31622400U ||
      update.urls.size() > maximum_crl_url_entries)
    return false;
  for (std::size_t index = 0U; index < update.urls.size(); ++index) {
    const auto &entry = update.urls[index];
    // A pristine shell (classic `url-entry <id> create` before any leaf) is
    // inert and stays valid in candidate and running state; once either leaf
    // is set the full location shape applies.
    if (entry.entry_id < 1U || entry.entry_id > 8U ||
        std::any_of(update.urls.begin(), update.urls.begin() + index,
                    [&](const auto &other) {
                      return other.entry_id == entry.entry_id;
                    }))
      return false;
    if (entry.url.empty() && entry.transmission_profile.empty())
      continue;
    // The CRL location must carry a path after the host per the
    // http-url-path-loose shape; the fetch itself is a protocol-owner task.
    if (!valid_pki_url(entry.url) ||
        entry.url.find('/') == std::string_view::npos ||
        entry.transmission_profile.size() > 32U)
      return false;
  }
  return true;
}

[[nodiscard]] inline bool valid_ca_profile(const CaProfile &profile) noexcept {
  if (profile.description.size() > 80U ||
      (!profile.certificate_file.empty() &&
       !valid_pki_filename(profile.certificate_file)) ||
      (!profile.crl_file.empty() && !valid_pki_filename(profile.crl_file)) ||
      (profile.revocation_check != RevocationCheck::crl &&
       profile.revocation_check != RevocationCheck::crl_optional) ||
      !valid_ocsp_configuration(profile.ocsp) ||
      !valid_cmpv2_configuration(profile.cmpv2) ||
      (profile.auto_crl_update.present &&
       !valid_auto_crl_update(profile.auto_crl_update)))
    return false;
  return true;
}

[[nodiscard]] inline bool
valid_update_profile(const CertificateUpdateProfile &profile) noexcept {
  if ((profile.retry_seconds < 60U || profile.retry_seconds > 36000U) ||
      ((profile.key_generation == KeyGenerationKind::rsa ||
        profile.key_generation == KeyGenerationKind::dsa) &&
       (profile.key_size_bits < 512U || profile.key_size_bits > 8192U)) ||
      profile.protocol_profile.size() > 32U ||
      (profile.schedule == UpdateScheduleKind::before_expiry &&
       (profile.schedule_seconds < 3600U ||
        profile.schedule_seconds > 157680000U)) ||
      (profile.schedule == UpdateScheduleKind::after_issue &&
       (profile.schedule_seconds < 864000U ||
        profile.schedule_seconds > 157680000U)))
    return false;
  return true;
}

[[nodiscard]] inline bool
valid_auto_update(const CertificateAutoUpdate &entry) noexcept {
  // The certificate filename keys the entry; the key file and the update
  // profile it points at are set together by each engine's compound command.
  return valid_pki_filename(entry.certificate_file) &&
         (entry.key_file.empty() || valid_pki_filename(entry.key_file)) &&
         (entry.profile.empty() || valid_named_key(entry.profile, 32U));
}

[[nodiscard]] inline bool
valid_expiration_warning(const ExpirationWarning &warning) noexcept {
  return (!warning.hours_configured ||
          (warning.hours >= 0 && warning.hours <= 8760)) &&
         (!warning.repeat_configured ||
          (warning.repeat_hours >= 0 && warning.repeat_hours <= 8760));
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
      state.est_profiles.size() > maximum_est_profiles ||
      state.update_profiles.size() > maximum_certificate_update_profiles ||
      state.auto_updates.size() > maximum_certificate_auto_updates ||
      state.maximum_cert_chain_depth < 1U ||
      state.maximum_cert_chain_depth > 7U ||
      !valid_expiration_warning(state.certificate_expiration_warning) ||
      !valid_expiration_warning(state.crl_expiration_warning))
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
      !unique_names(state.est_profiles) ||
      !unique_names(state.update_profiles))
    return false;
  for (std::size_t index = 0U; index < state.auto_updates.size(); ++index) {
    const auto &entry = state.auto_updates[index];
    if (!valid_pki_filename(entry.certificate_file) ||
        std::any_of(state.auto_updates.begin(),
                    state.auto_updates.begin() + index,
                    [&](const auto &other) {
                      return other.certificate_file == entry.certificate_file;
                    }))
      return false;
  }
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
  for (const auto &profile : state.update_profiles) {
    if (!valid_named_key(profile.name, 32U) || !valid_update_profile(profile))
      return false;
  }
  for (const auto &entry : state.auto_updates) {
    if (!valid_auto_update(entry))
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
