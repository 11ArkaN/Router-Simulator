// Atomic implementation of the SR OS PKI ca-profile, common-name-list and
// est-profile commands represented by the generated CLI schema. Both terminal
// syntaxes update one intent model while retaining their own commit semantics.

#include "pki_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab::pki_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  Integer parsed{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (text.empty() || result.ec != std::errc{} ||
      result.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::string_view argument_text(const cli_detail::ParsedCommand &command,
                               TokenKind kind) noexcept {
  const auto value = cli_detail::argument(command, kind);
  return value ? cli_detail::unquote(*value) : std::string_view{};
}

template <typename Value>
bool configure(Value &target, bool &presence, Value value) {
  if (presence && target == value)
    return false;
  target = value;
  presence = true;
  return true;
}

template <typename Value>
bool remove(Value &target, bool &presence, Value default_value) {
  if (!presence)
    return false;
  target = default_value;
  presence = false;
  return true;
}

bool assign_description(std::string &target, std::string_view value) {
  if (value.empty() || value.size() > 80U ||
      std::all_of(value.begin(), value.end(),
                  [](char character) { return character == ' '; }) ||
      target == value)
    return false;
  target.assign(value);
  return true;
}

std::optional<std::uint32_t> seconds_argument(
    const cli_detail::ParsedCommand &command, TokenKind kind) noexcept {
  const auto text = argument_text(command, kind);
  std::uint32_t value{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || result.ec != std::errc{} ||
      result.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

bool seal_password(SecretSink *secrets, std::string_view text,
                   SecretKind kind, std::uint64_t &handle, bool &configured) {
  if (text.empty() || text.size() > 166U)
    return false;
  auto bytes = std::vector<std::uint8_t>{text.begin(), text.end()};
  const auto sealed =
      secrets ? secrets->seal(kind, bytes) : std::optional<std::uint64_t>{};
  std::fill(bytes.begin(), bytes.end(), std::uint8_t{});
  if (!sealed)
    return false;
  if (configured && handle == *sealed)
    return false;
  handle = *sealed;
  configured = true;
  return true;
}

bool edit_ocsp(pki::OcspConfiguration &ocsp, CommandId id,
               const cli_detail::ParsedCommand &command, bool md,
               bool &silent_absent) {
  using enum CommandId;
  if (id == md_pki_ocsp_url) {
    const auto text = argument_text(command, TokenKind::pki_url);
    if (!pki::valid_pki_url(text) || ocsp.responder_url == text)
      return false;
    ocsp.responder_url.assign(text);
    return true;
  }
  if (id == md_delete_pki_ocsp_url) {
    const bool changed = !ocsp.responder_url.empty();
    ocsp.responder_url.clear();
    silent_absent = !changed;
    return changed;
  }
  if (id == classic_pki_ocsp_url) {
    const auto text = argument_text(command, TokenKind::pki_url);
    if (!pki::valid_pki_url(text) || ocsp.responder_url == text)
      return false;
    ocsp.responder_url.assign(text);
    return true;
  }
  if (id == classic_pki_ocsp_no_url) {
    if (ocsp.responder_url.empty())
      return false;
    ocsp.responder_url.clear();
    return true;
  }
  if (id == md_pki_ocsp_service) {
    const auto text = argument_text(command, TokenKind::pki_service_name);
    if (!pki::valid_named_key(text, 64U))
      return false;
    if (ocsp.service_kind == pki::OcspServiceKind::name &&
        ocsp.service_name == text)
      return false;
    ocsp.service_kind = pki::OcspServiceKind::name;
    ocsp.service_name.assign(text);
    ocsp.service_id = 0U;
    return true;
  }
  if (id == md_delete_pki_ocsp_service) {
    const bool changed = ocsp.service_kind != pki::OcspServiceKind::none;
    ocsp.service_kind = pki::OcspServiceKind::none;
    ocsp.service_name.clear();
    ocsp.service_id = 0U;
    silent_absent = !changed;
    return changed;
  }
  if (id == classic_pki_ocsp_service_id) {
    // Base-router selection uses identifier zero; service identifiers
    // otherwise span 1 through 2147483647 per the classic reference.
    const auto value = seconds_argument(command, TokenKind::pki_service_id);
    if (!value || *value > 2147483647U)
      return false;
    if (ocsp.service_kind == pki::OcspServiceKind::id &&
        ocsp.service_id == *value)
      return false;
    ocsp.service_kind = pki::OcspServiceKind::id;
    ocsp.service_id = *value;
    ocsp.service_name.clear();
    return true;
  }
  if (id == classic_pki_ocsp_service_name) {
    const auto text = argument_text(command, TokenKind::pki_service_name);
    if (!pki::valid_named_key(text, 64U))
      return false;
    if (ocsp.service_kind == pki::OcspServiceKind::name &&
        ocsp.service_name == text)
      return false;
    ocsp.service_kind = pki::OcspServiceKind::name;
    ocsp.service_name.assign(text);
    ocsp.service_id = 0U;
    return true;
  }
  if (id == classic_pki_ocsp_no_service) {
    if (ocsp.service_kind == pki::OcspServiceKind::none)
      return false;
    ocsp.service_kind = pki::OcspServiceKind::none;
    ocsp.service_name.clear();
    ocsp.service_id = 0U;
    return true;
  }
  if (id == md_pki_ocsp_transmission ||
      id == classic_pki_ocsp_transmission) {
    const auto text =
        argument_text(command, TokenKind::pki_transmission_profile);
    if (text.empty() || text.size() > 32U || ocsp.transmission_profile == text)
      return false;
    ocsp.transmission_profile.assign(text);
    return true;
  }
  if (id == md_delete_pki_ocsp_transmission ||
      id == classic_pki_ocsp_no_transmission) {
    if (ocsp.transmission_profile.empty()) {
      silent_absent = md;
      return false;
    }
    ocsp.transmission_profile.clear();
    return true;
  }
  return false;
}

bool edit_cmpv2(pki::Cmpv2Configuration &cmpv2, CommandId id,
                const cli_detail::ParsedCommand &command, bool md,
                SecretSink *secrets, bool &silent_absent) {
  using enum CommandId;
  if (id == md_pki_cmp_always_sender || id == classic_pki_cmp_sender) {
    const auto text = md ? argument_text(command, TokenKind::boolean)
                         : std::string_view{};
    // MD carries an explicit boolean; classic uses a presence flag where
    // bare means true and `no` means false.
    if (md && text != "true" && text != "false")
      return false;
    return configure(cmpv2.always_set_sender_for_ir,
                     cmpv2.always_set_sender_for_ir_configured,
                     md ? text == "true" : true);
  }
  if (id == md_delete_pki_cmp_sender || id == classic_pki_cmp_no_sender) {
    const bool changed =
        remove(cmpv2.always_set_sender_for_ir,
               cmpv2.always_set_sender_for_ir_configured, false);
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_same_nonce) {
    const auto text = argument_text(command, TokenKind::boolean);
    if (text != "true" && text != "false")
      return false;
    return configure(cmpv2.same_recipient_nonce_for_poll_request,
                     cmpv2.same_recipient_nonce_for_poll_request_configured,
                     text == "true");
  }
  if (id == classic_pki_cmp_nonce) {
    return configure(cmpv2.same_recipient_nonce_for_poll_request,
                     cmpv2.same_recipient_nonce_for_poll_request_configured,
                     true);
  }
  if (id == md_delete_pki_cmp_nonce || id == classic_pki_cmp_no_nonce) {
    const bool changed = remove(cmpv2.same_recipient_nonce_for_poll_request,
                                cmpv2.same_recipient_nonce_for_poll_request_configured,
                                false);
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_signing_subject) {
    const auto text = argument_text(command, TokenKind::pki_dn_string);
    if (!pki::valid_dn_subject(text) || cmpv2.signing_cert_subject == text)
      return false;
    cmpv2.signing_cert_subject.assign(text);
    return true;
  }
  if (id == md_delete_pki_cmp_signing) {
    const bool changed = !cmpv2.signing_cert_subject.empty();
    cmpv2.signing_cert_subject.clear();
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_response_extracert) {
    if (cmpv2.response_signing ==
            pki::CmpResponseSigningKind::use_extra_cert &&
        cmpv2.response_signing_configured)
      return false;
    cmpv2.response_signing = pki::CmpResponseSigningKind::use_extra_cert;
    cmpv2.response_signing_configured = true;
    cmpv2.response_signing_cert.clear();
    return true;
  }
  if (id == md_delete_pki_cmp_extracert) {
    const bool changed =
        cmpv2.response_signing_configured &&
        cmpv2.response_signing == pki::CmpResponseSigningKind::use_extra_cert;
    cmpv2.response_signing = pki::CmpResponseSigningKind::cert;
    cmpv2.response_signing_configured = false;
    cmpv2.response_signing_cert.clear();
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_response_cert ||
      id == classic_pki_cmp_response_cert) {
    const auto text = argument_text(command, TokenKind::pki_file_name);
    if (!pki::valid_pki_filename(text))
      return false;
    if (cmpv2.response_signing == pki::CmpResponseSigningKind::cert &&
        cmpv2.response_signing_configured &&
        cmpv2.response_signing_cert == text)
      return false;
    cmpv2.response_signing = pki::CmpResponseSigningKind::cert;
    cmpv2.response_signing_configured = true;
    cmpv2.response_signing_cert.assign(text);
    return true;
  }
  if (id == md_delete_pki_cmp_response ||
      id == classic_pki_cmp_no_response_cert) {
    const bool changed = cmpv2.response_signing_configured &&
                         cmpv2.response_signing ==
                             pki::CmpResponseSigningKind::cert;
    cmpv2.response_signing = pki::CmpResponseSigningKind::cert;
    cmpv2.response_signing_configured = false;
    cmpv2.response_signing_cert.clear();
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_use_ca_subject) {
    if (cmpv2.recipient == pki::CmpRecipientKind::ca_subject &&
        cmpv2.recipient_configured)
      return false;
    cmpv2.recipient = pki::CmpRecipientKind::ca_subject;
    cmpv2.recipient_configured = true;
    cmpv2.recipient_subject.clear();
    return true;
  }
  if (id == md_delete_pki_cmp_casubject) {
    const bool changed =
        cmpv2.recipient_configured &&
        cmpv2.recipient == pki::CmpRecipientKind::ca_subject;
    cmpv2.recipient = pki::CmpRecipientKind::ca_subject;
    cmpv2.recipient_configured = false;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_recipient_subject) {
    const auto text = argument_text(command, TokenKind::pki_dn_string);
    if (!pki::valid_dn_subject(text))
      return false;
    if (cmpv2.recipient == pki::CmpRecipientKind::subject &&
        cmpv2.recipient_configured && cmpv2.recipient_subject == text)
      return false;
    cmpv2.recipient = pki::CmpRecipientKind::subject;
    cmpv2.recipient_configured = true;
    cmpv2.recipient_subject.assign(text);
    return true;
  }
  if (id == md_delete_pki_cmp_recipient) {
    const bool changed =
        cmpv2.recipient_configured &&
        cmpv2.recipient == pki::CmpRecipientKind::subject;
    cmpv2.recipient = pki::CmpRecipientKind::ca_subject;
    cmpv2.recipient_configured = false;
    cmpv2.recipient_subject.clear();
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_accept_error || id == classic_pki_cmp_accept_error) {
    const auto text = md ? argument_text(command, TokenKind::boolean)
                         : std::string_view{};
    if (md && text != "true" && text != "false")
      return false;
    return configure(cmpv2.accept_unprotected_error,
                     cmpv2.accept_unprotected_error_configured,
                     md ? text == "true" : true);
  }
  if (id == md_delete_pki_cmp_error || id == classic_pki_cmp_no_accept_error) {
    const bool changed =
        remove(cmpv2.accept_unprotected_error,
               cmpv2.accept_unprotected_error_configured, false);
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_accept_pkiconf ||
      id == classic_pki_cmp_accept_pkiconf) {
    const auto text = md ? argument_text(command, TokenKind::boolean)
                         : std::string_view{};
    if (md && text != "true" && text != "false")
      return false;
    return configure(cmpv2.accept_unprotected_pkiconf,
                     cmpv2.accept_unprotected_pkiconf_configured,
                     md ? text == "true" : true);
  }
  if (id == md_delete_pki_cmp_pkiconf ||
      id == classic_pki_cmp_no_accept_pkiconf) {
    const bool changed =
        remove(cmpv2.accept_unprotected_pkiconf,
               cmpv2.accept_unprotected_pkiconf_configured, false);
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_http_timeout) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 1U || *value > 3600U)
      return false;
    if (cmpv2.http_response_timeout_configured &&
        cmpv2.http_response_timeout_seconds == *value)
      return false;
    cmpv2.http_response_timeout_seconds = *value;
    cmpv2.http_response_timeout_configured = true;
    return true;
  }
  if (id == md_delete_pki_cmp_timeout) {
    const bool changed = remove(cmpv2.http_response_timeout_seconds,
                                cmpv2.http_response_timeout_configured, 30U);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_http_v10 || id == md_pki_cmp_http_v11) {
    const auto version = id == md_pki_cmp_http_v10 ? pki::HttpVersion::v10
                                                   : pki::HttpVersion::v11;
    if (cmpv2.http_version_configured && cmpv2.http_version == version)
      return false;
    cmpv2.http_version = version;
    cmpv2.http_version_configured = true;
    return true;
  }
  if (id == md_delete_pki_cmp_version) {
    const bool changed = remove(cmpv2.http_version,
                                cmpv2.http_version_configured,
                                pki::HttpVersion::v11);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_url_string || id == classic_pki_cmp_url) {
    const auto text = argument_text(command, TokenKind::pki_url);
    if (!pki::valid_pki_url(text) || cmpv2.url_string == text)
      return false;
    cmpv2.url_string.assign(text);
    return true;
  }
  if (id == classic_pki_cmp_url_service_id) {
    const auto url = argument_text(command, TokenKind::pki_url);
    const auto service = seconds_argument(command, TokenKind::pki_service_id);
    if (!pki::valid_pki_url(url) || !service || *service > 2147483647U)
      return false;
    bool changed = false;
    if (cmpv2.url_string != url) {
      cmpv2.url_string.assign(url);
      changed = true;
    }
    if (cmpv2.url_transport != pki::CmpUrlTransportKind::service_id ||
        cmpv2.url_service_id != *service) {
      cmpv2.url_transport = pki::CmpUrlTransportKind::service_id;
      cmpv2.url_service_id = *service;
      cmpv2.url_service_name.clear();
      cmpv2.url_transmission_profile.clear();
      changed = true;
    }
    return changed;
  }
  if (id == classic_pki_cmp_url_service_name) {
    const auto url = argument_text(command, TokenKind::pki_url);
    const auto service = argument_text(command, TokenKind::pki_service_name);
    if (!pki::valid_pki_url(url) || !pki::valid_named_key(service, 64U))
      return false;
    bool changed = false;
    if (cmpv2.url_string != url) {
      cmpv2.url_string.assign(url);
      changed = true;
    }
    if (cmpv2.url_transport != pki::CmpUrlTransportKind::service_name ||
        cmpv2.url_service_name != service) {
      cmpv2.url_transport = pki::CmpUrlTransportKind::service_name;
      cmpv2.url_service_name.assign(service);
      cmpv2.url_service_id = 0U;
      cmpv2.url_transmission_profile.clear();
      changed = true;
    }
    return changed;
  }
  if (id == md_delete_pki_cmp_url || id == classic_pki_cmp_no_url) {
    const bool changed = !cmpv2.url_string.empty() ||
                         cmpv2.url_transport !=
                             pki::CmpUrlTransportKind::none;
    cmpv2.url_string.clear();
    cmpv2.url_transport = pki::CmpUrlTransportKind::none;
    cmpv2.url_service_id = 0U;
    cmpv2.url_service_name.clear();
    cmpv2.url_transmission_profile.clear();
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_cmp_url_service) {
    const auto text = argument_text(command, TokenKind::pki_service_name);
    if (!pki::valid_named_key(text, 64U))
      return false;
    if (cmpv2.url_transport == pki::CmpUrlTransportKind::service_name &&
        cmpv2.url_service_name == text)
      return false;
    cmpv2.url_transport = pki::CmpUrlTransportKind::service_name;
    cmpv2.url_service_name.assign(text);
    cmpv2.url_service_id = 0U;
    cmpv2.url_transmission_profile.clear();
    return true;
  }
  if (id == md_delete_pki_cmp_url_service) {
    const bool changed =
        cmpv2.url_transport == pki::CmpUrlTransportKind::service_name;
    if (changed) {
      cmpv2.url_transport = pki::CmpUrlTransportKind::none;
      cmpv2.url_service_name.clear();
      cmpv2.url_service_id = 0U;
    }
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_url_transmission) {
    const auto text =
        argument_text(command, TokenKind::pki_transmission_profile);
    if (text.empty() || text.size() > 32U)
      return false;
    if (cmpv2.url_transport ==
            pki::CmpUrlTransportKind::transmission_profile &&
        cmpv2.url_transmission_profile == text)
      return false;
    cmpv2.url_transport = pki::CmpUrlTransportKind::transmission_profile;
    cmpv2.url_transmission_profile.assign(text);
    cmpv2.url_service_id = 0U;
    cmpv2.url_service_name.clear();
    return true;
  }
  if (id == md_delete_pki_cmp_url_transmission) {
    const bool changed =
        cmpv2.url_transport == pki::CmpUrlTransportKind::transmission_profile;
    if (changed) {
      cmpv2.url_transport = pki::CmpUrlTransportKind::none;
      cmpv2.url_transmission_profile.clear();
    }
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_cmp_key_password || id == classic_pki_cmp_key) {
    // MD addresses the key by reference and seals the password; classic
    // carries the password first and the reference after its keyword.
    const auto ref = md ? argument_text(command, TokenKind::pki_cmp_key_ref)
                        : argument_text(command, TokenKind::pki_cmp_key_ref);
    const auto text = argument_text(command, TokenKind::radius_password);
    if (!pki::valid_named_key(ref, 64U))
      return false;
    const auto found_key = std::find_if(
        cmpv2.keys.begin(), cmpv2.keys.end(),
        [&](const auto &key) { return key.reference == ref; });
    auto *key = found_key == cmpv2.keys.end() ? nullptr : &*found_key;
    if (!key) {
      if (cmpv2.keys.size() >= pki::maximum_cmp_keys)
        return false;
      cmpv2.keys.push_back(pki::CmpKey{.reference = std::string{ref}});
      key = &cmpv2.keys.back();
    }
    std::uint64_t handle = key->password_handle;
    bool configured = key->password_configured;
    if (!seal_password(secrets, text, SecretKind::cmp_key_password, handle,
                       configured))
      return false;
    key->password_handle = handle;
    key->password_configured = configured;
    return true;
  }
  if (id == md_delete_pki_cmp_key || id == classic_pki_cmp_no_key) {
    const auto ref = argument_text(command, TokenKind::pki_cmp_key_ref);
    const auto found =
        std::find_if(cmpv2.keys.begin(), cmpv2.keys.end(),
                     [&](const auto &key) { return key.reference == ref; });
    if (found == cmpv2.keys.end()) {
      silent_absent = md;
      return false;
    }
    cmpv2.keys.erase(found);
    return true;
  }
  return false;
}

bool sum_classic_interval(const cli_detail::ParsedCommand &command,
                          std::uint32_t &total) noexcept {
  // Classic days/hrs/min/sec components sum with an overflow guard, on the
  // same pattern as the DHCP timer editors. Any subset may be present.
  total = 0U;
  const auto add = [&](TokenKind kind, unsigned long long factor) {
    const auto text = argument_text(command, kind);
    if (text.empty())
      return true;
    unsigned long long part{};
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), part);
    if (text.empty() || result.ec != std::errc{} ||
        result.ptr != text.data() + text.size())
      return false;
    const auto scaled = part * factor;
    if (scaled > 31622400ULL || total > 31622400U - scaled)
      return false;
    total += static_cast<std::uint32_t>(scaled);
    return true;
  };
  return add(TokenKind::dhcp_time_days, 86400ULL) &&
         add(TokenKind::dhcp_time_hours, 3600ULL) &&
         add(TokenKind::dhcp_time_minutes, 60ULL) &&
         add(TokenKind::dhcp_time_seconds, 1ULL);
}

bool edit_auto_crl(pki::AutoCrlUpdate &update, CommandId id,
                   const cli_detail::ParsedCommand &command, bool md,
                   bool &silent_absent) {
  using enum CommandId;
  if (id == md_pki_crl_admin_enable || id == classic_pki_crl_no_shutdown) {
    update.present = true;
    return configure(update.admin_enabled, update.admin_state_configured,
                     true);
  }
  if (id == md_pki_crl_admin_disable || id == classic_pki_crl_shutdown) {
    update.present = true;
    return configure(update.admin_enabled, update.admin_state_configured,
                     false);
  }
  if (id == md_delete_pki_crl_admin) {
    const bool changed = remove(update.admin_enabled,
                                update.admin_state_configured, false);
    silent_absent = !changed;
    return changed;
  }
  if (id == classic_pki_crl_create) {
    if (update.present)
      return false;
    update.present = true;
    return true;
  }
  if (id == md_pki_crl_periodic) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 3600U || *value > 31622400U)
      return false;
    update.present = true;
    if (update.periodic_update_configured &&
        update.periodic_update_seconds == *value)
      return false;
    update.periodic_update_seconds = *value;
    update.periodic_update_configured = true;
    return true;
  }
  if (id == md_delete_pki_crl_periodic) {
    const bool changed =
        remove(update.periodic_update_seconds,
               update.periodic_update_configured,
               pki::automatic_crl_default_period_seconds);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_crl_preupdate) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value > 31622400U)
      return false;
    update.present = true;
    if (update.pre_update_configured && update.pre_update_seconds == *value)
      return false;
    update.pre_update_seconds = *value;
    update.pre_update_configured = true;
    return true;
  }
  if (id == md_delete_pki_crl_preupdate) {
    const bool changed =
        remove(update.pre_update_seconds, update.pre_update_configured,
               pki::automatic_crl_default_pre_update_seconds);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_crl_retry || id == classic_pki_crl_retry) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value > 31622400U)
      return false;
    update.present = true;
    if (update.retry_configured && update.retry_seconds == *value)
      return false;
    update.retry_seconds = *value;
    update.retry_configured = true;
    return true;
  }
  if (id == md_delete_pki_crl_retry || id == classic_pki_crl_no_retry) {
    const bool changed =
        remove(update.retry_seconds, update.retry_configured,
               pki::automatic_crl_default_retry_seconds);
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_crl_schedule_next ||
      id == classic_pki_crl_schedule_next) {
    update.present = true;
    if (update.schedule_configured &&
        update.schedule == pki::AutoCrlScheduleKind::next_update_based)
      return false;
    update.schedule = pki::AutoCrlScheduleKind::next_update_based;
    update.schedule_configured = true;
    return true;
  }
  if (id == md_pki_crl_schedule_periodic ||
      id == classic_pki_crl_schedule_periodic) {
    update.present = true;
    if (update.schedule_configured &&
        update.schedule == pki::AutoCrlScheduleKind::periodic)
      return false;
    update.schedule = pki::AutoCrlScheduleKind::periodic;
    update.schedule_configured = true;
    return true;
  }
  if (id == md_delete_pki_crl_schedule) {
    const bool changed =
        remove(update.schedule, update.schedule_configured,
               pki::AutoCrlScheduleKind::next_update_based);
    silent_absent = !changed;
    return changed;
  }
  // Classic periodic intervals arrive as day/hour/minute/second components
  // that sum to one duration. Every non-empty subset is its own schema row
  // but converges here; the range matches the MD single-value leaf.
  switch (id) {
  case CommandId::classic_pki_crl_periodic_days:
  case CommandId::classic_pki_crl_periodic_hours:
  case CommandId::classic_pki_crl_periodic_days_hours:
  case CommandId::classic_pki_crl_periodic_minutes:
  case CommandId::classic_pki_crl_periodic_days_minutes:
  case CommandId::classic_pki_crl_periodic_hours_minutes:
  case CommandId::classic_pki_crl_periodic_days_hours_minutes:
  case CommandId::classic_pki_crl_periodic_seconds:
  case CommandId::classic_pki_crl_periodic_days_seconds:
  case CommandId::classic_pki_crl_periodic_hours_seconds:
  case CommandId::classic_pki_crl_periodic_days_hours_seconds:
  case CommandId::classic_pki_crl_periodic_minutes_seconds:
  case CommandId::classic_pki_crl_periodic_days_minutes_seconds:
  case CommandId::classic_pki_crl_periodic_hours_minutes_seconds:
  case CommandId::classic_pki_crl_periodic_days_hours_minutes_seconds: {
    std::uint32_t total{};
    if (!sum_classic_interval(command, total) || total < 3600U ||
        total > 31622400U)
      return false;
    update.present = true;
    if (update.periodic_update_configured &&
        update.periodic_update_seconds == total)
      return false;
    update.periodic_update_seconds = total;
    update.periodic_update_configured = true;
    return true;
  }
  default:
    break;
  }
  if (id == md_pki_crl_url || id == classic_pki_crl_entry_url) {
    const auto entry_id = seconds_argument(command, TokenKind::pki_crl_entry_id);
    const auto text = argument_text(command, TokenKind::pki_url);
    if (!entry_id || *entry_id < 1U || *entry_id > 8U ||
        !pki::valid_pki_url(text) ||
        text.find('/') == std::string_view::npos)
      return false;
    update.present = true;
    auto *entry = [&]() -> pki::CrlUrlEntry * {
      const auto found = std::find_if(
          update.urls.begin(), update.urls.end(),
          [&](const auto &item) { return item.entry_id == *entry_id; });
      if (found != update.urls.end())
        return &*found;
      if (update.urls.size() >= pki::maximum_crl_url_entries)
        return nullptr;
      update.urls.push_back(pki::CrlUrlEntry{.entry_id = *entry_id});
      return &update.urls.back();
    }();
    if (!entry || entry->url == text)
      return false;
    entry->url.assign(text);
    return true;
  }
  if (id == md_pki_crl_transmission) {
    const auto entry_id = seconds_argument(command, TokenKind::pki_crl_entry_id);
    const auto text =
        argument_text(command, TokenKind::pki_transmission_profile);
    if (!entry_id || *entry_id < 1U || *entry_id > 8U || text.empty() ||
        text.size() > 32U)
      return false;
    update.present = true;
    auto *entry = [&]() -> pki::CrlUrlEntry * {
      const auto found = std::find_if(
          update.urls.begin(), update.urls.end(),
          [&](const auto &item) { return item.entry_id == *entry_id; });
      if (found != update.urls.end())
        return &*found;
      if (update.urls.size() >= pki::maximum_crl_url_entries)
        return nullptr;
      update.urls.push_back(pki::CrlUrlEntry{.entry_id = *entry_id});
      return &update.urls.back();
    }();
    if (!entry || entry->transmission_profile == text)
      return false;
    entry->transmission_profile.assign(text);
    return true;
  }
  if (id == md_delete_pki_crl_entry_url ||
      id == classic_pki_crl_entry_no_url) {
    const auto entry_id = seconds_argument(command, TokenKind::pki_crl_entry_id);
    if (!entry_id)
      return false;
    const auto found = std::find_if(
        update.urls.begin(), update.urls.end(),
        [&](const auto &item) { return item.entry_id == *entry_id; });
    if (found == update.urls.end() || found->url.empty()) {
      silent_absent = md;
      return false;
    }
    found->url.clear();
    return true;
  }
  if (id == md_delete_pki_crl_entry_transmission) {
    const auto entry_id = seconds_argument(command, TokenKind::pki_crl_entry_id);
    if (!entry_id)
      return false;
    const auto found = std::find_if(
        update.urls.begin(), update.urls.end(),
        [&](const auto &item) { return item.entry_id == *entry_id; });
    if (found == update.urls.end() || found->transmission_profile.empty()) {
      silent_absent = true;
      return false;
    }
    found->transmission_profile.clear();
    return true;
  }
  if (id == md_delete_pki_crl_entry || id == classic_pki_crl_entry_remove ||
      id == classic_pki_crl_entry_create) {
    // Entry creation is implicit when MD addresses a child; classic create
    // materializes the entry shell. Both removals drop the whole entry.
    if (id == classic_pki_crl_entry_create) {
      const auto entry_id =
          seconds_argument(command, TokenKind::pki_crl_entry_id);
      if (!entry_id || *entry_id < 1U || *entry_id > 8U)
        return false;
      const auto exists = std::any_of(
          update.urls.begin(), update.urls.end(),
          [&](const auto &item) { return item.entry_id == *entry_id; });
      if (exists)
        return false;
      if (update.urls.size() >= pki::maximum_crl_url_entries)
        return false;
      update.present = true;
      update.urls.push_back(pki::CrlUrlEntry{.entry_id = *entry_id});
      return true;
    }
    const auto entry_id = seconds_argument(command, TokenKind::pki_crl_entry_id);
    if (!entry_id)
      return false;
    const auto found = std::find_if(
        update.urls.begin(), update.urls.end(),
        [&](const auto &item) { return item.entry_id == *entry_id; });
    if (found == update.urls.end()) {
      silent_absent = id == md_delete_pki_crl_entry;
      return false;
    }
    update.urls.erase(found);
    return true;
  }
  return false;
}

bool edit_update_profile(pki::CertificateUpdateProfile &profile, CommandId id,
                         const cli_detail::ParsedCommand &command, bool md,
                         bool &silent_absent) {
  using enum CommandId;
  static_cast<void>(md);
  if (id == md_pki_update_hash_md5 || id == md_pki_update_hash_sha1 ||
      id == md_pki_update_hash_sha224 || id == md_pki_update_hash_sha256 ||
      id == md_pki_update_hash_sha384 || id == md_pki_update_hash_sha512) {
    const auto algorithm =
        id == md_pki_update_hash_md5       ? pki::HashAlgorithm::md5
        : id == md_pki_update_hash_sha1    ? pki::HashAlgorithm::sha1
        : id == md_pki_update_hash_sha224  ? pki::HashAlgorithm::sha224
        : id == md_pki_update_hash_sha256  ? pki::HashAlgorithm::sha256
        : id == md_pki_update_hash_sha384  ? pki::HashAlgorithm::sha384
                                           : pki::HashAlgorithm::sha512;
    if (profile.hash_algorithm_configured && profile.hash_algorithm == algorithm)
      return false;
    profile.hash_algorithm = algorithm;
    profile.hash_algorithm_configured = true;
    return true;
  }
  if (id == md_delete_pki_update_hash) {
    const bool changed = remove(profile.hash_algorithm,
                                profile.hash_algorithm_configured,
                                pki::HashAlgorithm::sha256);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_update_retry || id == classic_pki_update_retry) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 60U || *value > 36000U)
      return false;
    if (profile.retry_configured && profile.retry_seconds == *value)
      return false;
    profile.retry_seconds = *value;
    profile.retry_configured = true;
    return true;
  }
  if (id == md_delete_pki_update_retry) {
    const bool changed =
        remove(profile.retry_seconds, profile.retry_configured,
               pki::update_default_retry_seconds);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_update_cmpv2) {
    const auto text = argument_text(command, TokenKind::pki_ca_profile_name);
    if (!pki::valid_named_key(text, 32U))
      return false;
    if (profile.protocol_configured &&
        profile.protocol == pki::UpdateProtocol::cmpv2 &&
        profile.protocol_profile == text)
      return false;
    profile.protocol = pki::UpdateProtocol::cmpv2;
    profile.protocol_profile.assign(text);
    profile.protocol_configured = true;
    return true;
  }
  if (id == md_delete_pki_update_protocol) {
    const bool changed = profile.protocol_configured &&
                         profile.protocol == pki::UpdateProtocol::cmpv2;
    profile.protocol = pki::UpdateProtocol::cmpv2;
    profile.protocol_profile.clear();
    profile.protocol_configured = false;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_update_est) {
    const auto text = argument_text(command, TokenKind::pki_est_profile_name);
    if (!pki::valid_named_key(text, 32U))
      return false;
    if (profile.protocol_configured &&
        profile.protocol == pki::UpdateProtocol::est &&
        profile.protocol_profile == text)
      return false;
    profile.protocol = pki::UpdateProtocol::est;
    profile.protocol_profile.assign(text);
    profile.protocol_configured = true;
    return true;
  }
  if (id == md_delete_pki_update_est) {
    const bool changed = profile.protocol_configured &&
                         profile.protocol == pki::UpdateProtocol::est;
    profile.protocol = pki::UpdateProtocol::cmpv2;
    profile.protocol_profile.clear();
    profile.protocol_configured = false;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_update_samekey || id == classic_pki_update_samekey) {
    if (profile.key_generation == pki::KeyGenerationKind::same_as_existing)
      return false;
    profile.key_generation = pki::KeyGenerationKind::same_as_existing;
    profile.key_size_bits = 2048U;
    profile.curve = pki::EcdsaCurve::secp256r1;
    return true;
  }
  if (id == md_pki_update_rsa) {
    if (profile.key_generation == pki::KeyGenerationKind::rsa)
      return false;
    profile.key_generation = pki::KeyGenerationKind::rsa;
    profile.key_size_bits = 2048U;
    return true;
  }
  if (id == md_pki_update_rsa_size || id == classic_pki_update_rsa) {
    const auto value = seconds_argument(command, TokenKind::pki_key_size);
    if (!value || *value < 512U || *value > 8192U)
      return false;
    if (profile.key_generation == pki::KeyGenerationKind::rsa &&
        profile.key_size_bits == *value)
      return false;
    profile.key_generation = pki::KeyGenerationKind::rsa;
    profile.key_size_bits = *value;
    return true;
  }
  if (id == md_pki_update_dsa) {
    if (profile.key_generation == pki::KeyGenerationKind::dsa)
      return false;
    profile.key_generation = pki::KeyGenerationKind::dsa;
    profile.key_size_bits = 2048U;
    return true;
  }
  if (id == md_pki_update_dsa_size || id == classic_pki_update_dsa) {
    const auto value = seconds_argument(command, TokenKind::pki_key_size);
    if (!value || *value < 512U || *value > 8192U)
      return false;
    if (profile.key_generation == pki::KeyGenerationKind::dsa &&
        profile.key_size_bits == *value)
      return false;
    profile.key_generation = pki::KeyGenerationKind::dsa;
    profile.key_size_bits = *value;
    return true;
  }
  if (id == md_pki_update_ecdsa) {
    if (profile.key_generation == pki::KeyGenerationKind::ecdsa)
      return false;
    profile.key_generation = pki::KeyGenerationKind::ecdsa;
    profile.curve = pki::EcdsaCurve::secp256r1;
    return true;
  }
  if (id == md_pki_update_curve_256 || id == classic_pki_update_ecdsa_256) {
    if (profile.key_generation == pki::KeyGenerationKind::ecdsa &&
        profile.curve == pki::EcdsaCurve::secp256r1)
      return false;
    profile.key_generation = pki::KeyGenerationKind::ecdsa;
    profile.curve = pki::EcdsaCurve::secp256r1;
    return true;
  }
  if (id == md_pki_update_curve_384 || id == classic_pki_update_ecdsa_384) {
    if (profile.key_generation == pki::KeyGenerationKind::ecdsa &&
        profile.curve == pki::EcdsaCurve::secp384r1)
      return false;
    profile.key_generation = pki::KeyGenerationKind::ecdsa;
    profile.curve = pki::EcdsaCurve::secp384r1;
    return true;
  }
  if (id == md_pki_update_curve_521 || id == classic_pki_update_ecdsa_521) {
    if (profile.key_generation == pki::KeyGenerationKind::ecdsa &&
        profile.curve == pki::EcdsaCurve::secp521r1)
      return false;
    profile.key_generation = pki::KeyGenerationKind::ecdsa;
    profile.curve = pki::EcdsaCurve::secp521r1;
    return true;
  }
  if (id == md_delete_pki_update_keygen) {
    const bool changed =
        profile.key_generation != pki::KeyGenerationKind::same_as_existing;
    profile.key_generation = pki::KeyGenerationKind::same_as_existing;
    profile.key_size_bits = 2048U;
    profile.curve = pki::EcdsaCurve::secp256r1;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_delete_pki_update_rsa || id == md_delete_pki_update_dsa ||
      id == md_delete_pki_update_ecdsa) {
    const auto kind = id == md_delete_pki_update_rsa
                          ? pki::KeyGenerationKind::rsa
                      : id == md_delete_pki_update_dsa
                          ? pki::KeyGenerationKind::dsa
                          : pki::KeyGenerationKind::ecdsa;
    const bool changed = profile.key_generation == kind;
    if (changed) {
      profile.key_generation = pki::KeyGenerationKind::same_as_existing;
      profile.key_size_bits = 2048U;
      profile.curve = pki::EcdsaCurve::secp256r1;
    }
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_update_before) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 3600U || *value > 157680000U)
      return false;
    if (profile.schedule == pki::UpdateScheduleKind::before_expiry &&
        profile.schedule_seconds == *value)
      return false;
    profile.schedule = pki::UpdateScheduleKind::before_expiry;
    profile.schedule_seconds = *value;
    return true;
  }
  if (id == md_pki_update_after) {
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 864000U || *value > 157680000U)
      return false;
    if (profile.schedule == pki::UpdateScheduleKind::after_issue &&
        profile.schedule_seconds == *value)
      return false;
    profile.schedule = pki::UpdateScheduleKind::after_issue;
    profile.schedule_seconds = *value;
    return true;
  }
  if (id == classic_pki_update_schedule) {
    // Classic carries one schedule time; the documented default matches the
    // before-expiry default, so the single leaf maps to that schedule kind.
    const auto value = seconds_argument(command, TokenKind::pki_seconds);
    if (!value || *value < 3600U || *value > 157680000U)
      return false;
    if (profile.schedule == pki::UpdateScheduleKind::before_expiry &&
        profile.schedule_seconds == *value)
      return false;
    profile.schedule = pki::UpdateScheduleKind::before_expiry;
    profile.schedule_seconds = *value;
    return true;
  }
  if (id == md_delete_pki_update_schedule ||
      id == md_delete_pki_update_after) {
    const bool changed =
        profile.schedule != pki::UpdateScheduleKind::before_expiry ||
        profile.schedule_seconds != pki::update_default_before_expiry_seconds;
    profile.schedule = pki::UpdateScheduleKind::before_expiry;
    profile.schedule_seconds = pki::update_default_before_expiry_seconds;
    silent_absent = !changed;
    return changed;
  }
  return false;
}

bool edit_top_level(pki::Configuration &state, CommandId id,
                    const cli_detail::ParsedCommand &command, bool md,
                    bool &silent_absent) {
  using enum CommandId;
  if (id == md_pki_display_ascii || id == classic_pki_display_ascii) {
    if (state.display_format_configured &&
        state.display_format == pki::CertificateDisplayFormat::ascii)
      return false;
    state.display_format = pki::CertificateDisplayFormat::ascii;
    state.display_format_configured = true;
    return true;
  }
  if (id == md_pki_display_utf8 || id == classic_pki_display_utf8) {
    if (state.display_format_configured &&
        state.display_format == pki::CertificateDisplayFormat::utf8)
      return false;
    state.display_format = pki::CertificateDisplayFormat::utf8;
    state.display_format_configured = true;
    return true;
  }
  if (id == md_delete_pki_display) {
    const bool changed = remove(state.display_format,
                                state.display_format_configured,
                                pki::CertificateDisplayFormat::ascii);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_dynamic_ca) {
    const auto text = argument_text(command, TokenKind::boolean);
    if (text != "true" && text != "false")
      return false;
    return configure(state.dynamic_ca, state.dynamic_ca_configured,
                     text == "true");
  }
  if (id == md_delete_pki_dynamic) {
    const bool changed =
        remove(state.dynamic_ca, state.dynamic_ca_configured, false);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_imported_any || id == classic_pki_imported_any) {
    if (state.imported_format_configured &&
        state.imported_format == pki::ImportedFormat::any)
      return false;
    state.imported_format = pki::ImportedFormat::any;
    state.imported_format_configured = true;
    return true;
  }
  if (id == md_pki_imported_secure || id == classic_pki_imported_secure) {
    if (state.imported_format_configured &&
        state.imported_format == pki::ImportedFormat::secure)
      return false;
    state.imported_format = pki::ImportedFormat::secure;
    state.imported_format_configured = true;
    return true;
  }
  if (id == md_delete_pki_imported) {
    const bool changed = remove(state.imported_format,
                                state.imported_format_configured,
                                pki::ImportedFormat::any);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_chain_depth || id == classic_pki_chain_depth) {
    const auto value = seconds_argument(command, TokenKind::pki_chain_depth);
    if (!value || *value < 1U || *value > 7U)
      return false;
    if (state.maximum_cert_chain_depth_configured &&
        state.maximum_cert_chain_depth == *value)
      return false;
    state.maximum_cert_chain_depth = *value;
    state.maximum_cert_chain_depth_configured = true;
    return true;
  }
  if (id == md_delete_pki_chain_depth || id == classic_pki_no_chain_depth) {
    const bool changed =
        remove(state.maximum_cert_chain_depth,
               state.maximum_cert_chain_depth_configured, 7U);
    silent_absent = !changed && md;
    return changed;
  }
  const auto edit_warning = [&](pki::ExpirationWarning &warning, bool hours_leaf) {
    const auto value = seconds_argument(command, TokenKind::pki_warning_hours);
    if (!value || *value > 8760U)
      return false;
    if (hours_leaf) {
      if (warning.hours_configured && warning.hours == static_cast<std::int32_t>(*value))
        return false;
      warning.hours = static_cast<std::int32_t>(*value);
      warning.hours_configured = true;
      return true;
    }
    if (warning.repeat_configured &&
        warning.repeat_hours == static_cast<std::int32_t>(*value))
      return false;
    warning.repeat_hours = static_cast<std::int32_t>(*value);
    warning.repeat_configured = true;
    return true;
  };
  if (id == md_pki_cert_warn_hours)
    return edit_warning(state.certificate_expiration_warning, true);
  if (id == md_pki_cert_warn_repeat)
    return edit_warning(state.certificate_expiration_warning, false);
  if (id == md_pki_crl_warn_hours)
    return edit_warning(state.crl_expiration_warning, true);
  if (id == md_pki_crl_warn_repeat)
    return edit_warning(state.crl_expiration_warning, false);
  if (id == classic_pki_cert_warn || id == classic_pki_crl_warn) {
    // Classic carries hours alone in the single-value row; the repeat
    // variant is its own row below.
    const auto value = seconds_argument(command, TokenKind::pki_warning_hours);
    if (!value || *value > 8760U)
      return false;
    auto &warning = id == classic_pki_cert_warn
                        ? state.certificate_expiration_warning
                        : state.crl_expiration_warning;
    if (warning.hours_configured &&
        warning.hours == static_cast<std::int32_t>(*value))
      return false;
    warning.hours = static_cast<std::int32_t>(*value);
    warning.hours_configured = true;
    return true;
  }
  if (id == classic_pki_cert_warn_repeat || id == classic_pki_crl_warn_repeat) {
    const auto hours = seconds_argument(command, TokenKind::pki_warning_hours);
    const auto repeat =
        seconds_argument(command, TokenKind::pki_warning_repeat);
    if (!hours || *hours > 8760U || !repeat || *repeat > 8760U)
      return false;
    auto &warning = id == classic_pki_cert_warn_repeat
                        ? state.certificate_expiration_warning
                        : state.crl_expiration_warning;
    if (warning.hours_configured &&
        warning.hours == static_cast<std::int32_t>(*hours) &&
        warning.repeat_configured &&
        warning.repeat_hours == static_cast<std::int32_t>(*repeat))
      return false;
    warning.hours = static_cast<std::int32_t>(*hours);
    warning.hours_configured = true;
    warning.repeat_hours = static_cast<std::int32_t>(*repeat);
    warning.repeat_configured = true;
    return true;
  }
  if (id == classic_pki_no_cert_warn || id == classic_pki_no_crl_warn) {
    auto &warning = id == classic_pki_no_cert_warn
                        ? state.certificate_expiration_warning
                        : state.crl_expiration_warning;
    const bool changed =
        warning.hours_configured || warning.repeat_configured;
    warning.hours_configured = false;
    warning.repeat_configured = false;
    warning.hours = 0;
    warning.repeat_hours = 0;
    return changed;
  }
  if (id == md_delete_pki_cert_warn_hours) {
    const bool changed = state.certificate_expiration_warning.hours_configured;
    state.certificate_expiration_warning.hours_configured = false;
    state.certificate_expiration_warning.hours = 0;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_delete_pki_cert_warn_repeat) {
    const bool changed = state.certificate_expiration_warning.repeat_configured;
    state.certificate_expiration_warning.repeat_configured = false;
    state.certificate_expiration_warning.repeat_hours = 0;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_delete_pki_crl_warn_hours) {
    const bool changed = state.crl_expiration_warning.hours_configured;
    state.crl_expiration_warning.hours_configured = false;
    state.crl_expiration_warning.hours = 0;
    silent_absent = !changed;
    return changed;
  }
  if (id == md_delete_pki_crl_warn_repeat) {
    const bool changed = state.crl_expiration_warning.repeat_configured;
    state.crl_expiration_warning.repeat_configured = false;
    state.crl_expiration_warning.repeat_hours = 0;
    silent_absent = !changed;
    return changed;
  }
  return false;
}

bool edit_auto_update(pki::Configuration &state, pki::CertificateAutoUpdate &entry,
                      CommandId id, const cli_detail::ParsedCommand &command,
                      bool md, bool &silent_absent) {
  using enum CommandId;
  static_cast<void>(state);
  static_cast<void>(md);
  if (id == md_pki_autoupdate_key || id == classic_pki_autoupdate_key) {
    const auto kind = md ? TokenKind::pki_key_file : TokenKind::pki_key_file;
    const auto text = argument_text(command, kind);
    if (!pki::valid_pki_filename(text) || entry.key_file == text)
      return false;
    entry.key_file.assign(text);
    return true;
  }
  if (id == md_pki_autoupdate_profile) {
    const auto text = argument_text(command, TokenKind::pki_update_profile_name);
    if (!pki::valid_named_key(text, 32U) || entry.profile == text)
      return false;
    entry.profile.assign(text);
    return true;
  }
  if (id == md_delete_pki_autoupdate_key) {
    if (entry.key_file.empty()) {
      silent_absent = true;
      return false;
    }
    entry.key_file.clear();
    return true;
  }
  if (id == md_delete_pki_autoupdate_profile) {
    if (entry.profile.empty()) {
      silent_absent = true;
      return false;
    }
    entry.profile.clear();
    return true;
  }
  return false;
}

template <typename Item>
Item *materialize_named(std::vector<Item> &items, std::string_view name,
                        std::size_t maximum) {
  if (auto *existing = pki::find_named(items, name))
    return existing;
  if (name.empty() || name.size() > 32U || items.size() >= maximum)
    return nullptr;
  Item item;
  item.name = name;
  items.push_back(std::move(item));
  return &items.back();
}

bool edit_ca_profile(pki::CaProfile &profile, CommandId id,
                     const cli_detail::ParsedCommand &command, bool md,
                     SecretSink *secrets, bool &silent_absent) {
  using enum CommandId;
  if (id == md_pki_ca_admin_enable || id == classic_pki_ca_no_shutdown)
    return configure(profile.admin_enabled, profile.admin_state_configured,
                     true);
  if (id == md_pki_ca_admin_disable || id == classic_pki_ca_shutdown)
    return configure(profile.admin_enabled, profile.admin_state_configured,
                     false);
  if (id == md_delete_pki_ca_admin) {
    const bool changed = remove(profile.admin_enabled,
                                profile.admin_state_configured, false);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_ca_description || id == classic_pki_ca_description) {
    const auto text = argument_text(command, TokenKind::description);
    return assign_description(profile.description, text);
  }
  if (id == md_delete_pki_ca_description ||
      id == classic_pki_ca_no_description) {
    const bool changed = !profile.description.empty();
    profile.description.clear();
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_ca_cert_file || id == classic_pki_ca_cert_file) {
    const auto text = argument_text(command, TokenKind::pki_file_name);
    const bool valid =
        !text.empty() && pki::valid_pki_filename(text) &&
        profile.certificate_file != text;
    if (valid)
      profile.certificate_file.assign(text);
    return valid;
  }
  if (id == md_delete_pki_ca_cert_file || id == classic_pki_ca_no_cert_file) {
    const bool changed = !profile.certificate_file.empty();
    profile.certificate_file.clear();
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_ca_crl_file || id == classic_pki_ca_crl_file) {
    const auto text = argument_text(command, TokenKind::pki_file_name);
    const bool valid = !text.empty() && pki::valid_pki_filename(text) &&
                       profile.crl_file != text;
    if (valid)
      profile.crl_file.assign(text);
    return valid;
  }
  if (id == md_delete_pki_ca_crl_file || id == classic_pki_ca_no_crl_file) {
    const bool changed = !profile.crl_file.empty();
    profile.crl_file.clear();
    silent_absent = !changed && md;
    return changed;
  }
  if (id == md_pki_ca_revocation_crl || id == md_pki_ca_revocation_optional ||
      id == classic_pki_ca_revocation_crl ||
      id == classic_pki_ca_revocation_optional) {
    return configure(profile.revocation_check,
                     profile.revocation_check_configured,
                     id == md_pki_ca_revocation_optional ||
                                 id == classic_pki_ca_revocation_optional
                         ? pki::RevocationCheck::crl_optional
                         : pki::RevocationCheck::crl);
  }
  if (id == md_delete_pki_ca_revocation ||
      id == classic_pki_ca_no_revocation) {
    const bool changed =
        remove(profile.revocation_check, profile.revocation_check_configured,
               pki::RevocationCheck::crl);
    silent_absent = !changed && md;
    return changed;
  }
  // OCSP, CMPv2 and automatic CRL update subtrees hang under the CA profile.
  // Each subtree owns its leaves; the container presence for auto-crl-update
  // is raised when any child edit succeeds.
  if (id == md_pki_ocsp_url || id == md_delete_pki_ocsp_url ||
      id == classic_pki_ocsp_url || id == classic_pki_ocsp_no_url ||
      id == md_pki_ocsp_service || id == md_delete_pki_ocsp_service ||
      id == classic_pki_ocsp_service_id ||
      id == classic_pki_ocsp_service_name ||
      id == classic_pki_ocsp_no_service || id == md_pki_ocsp_transmission ||
      id == md_delete_pki_ocsp_transmission ||
      id == classic_pki_ocsp_transmission ||
      id == classic_pki_ocsp_no_transmission) {
    return edit_ocsp(profile.ocsp, id, command, md, silent_absent);
  }
  if (id == md_pki_cmp_always_sender || id == md_delete_pki_cmp_sender ||
      id == classic_pki_cmp_sender || id == classic_pki_cmp_no_sender ||
      id == md_pki_cmp_same_nonce || id == md_delete_pki_cmp_nonce ||
      id == classic_pki_cmp_nonce || id == classic_pki_cmp_no_nonce ||
      id == md_pki_cmp_signing_subject || id == md_delete_pki_cmp_signing ||
      id == md_pki_cmp_response_extracert ||
      id == md_delete_pki_cmp_extracert || id == md_pki_cmp_response_cert ||
      id == md_delete_pki_cmp_response ||
      id == classic_pki_cmp_response_cert ||
      id == classic_pki_cmp_no_response_cert ||
      id == md_pki_cmp_use_ca_subject || id == md_delete_pki_cmp_casubject ||
      id == md_pki_cmp_recipient_subject ||
      id == md_delete_pki_cmp_recipient || id == md_pki_cmp_accept_error ||
      id == md_delete_pki_cmp_error || id == classic_pki_cmp_accept_error ||
      id == classic_pki_cmp_no_accept_error ||
      id == md_pki_cmp_accept_pkiconf || id == md_delete_pki_cmp_pkiconf ||
      id == classic_pki_cmp_accept_pkiconf ||
      id == classic_pki_cmp_no_accept_pkiconf ||
      id == md_pki_cmp_http_timeout || id == md_delete_pki_cmp_timeout ||
      id == md_pki_cmp_http_v10 || id == md_pki_cmp_http_v11 ||
      id == md_delete_pki_cmp_version || id == md_pki_cmp_url_string ||
      id == md_delete_pki_cmp_url || id == classic_pki_cmp_url ||
      id == classic_pki_cmp_url_service_id ||
      id == classic_pki_cmp_url_service_name ||
      id == classic_pki_cmp_no_url || id == md_pki_cmp_url_service ||
      id == md_delete_pki_cmp_url_service ||
      id == md_pki_cmp_url_transmission ||
      id == md_delete_pki_cmp_url_transmission ||
      id == md_pki_cmp_key_password || id == md_delete_pki_cmp_key ||
      id == classic_pki_cmp_key || id == classic_pki_cmp_no_key) {
    return edit_cmpv2(profile.cmpv2, id, command, md, secrets, silent_absent);
  }
  if (id == md_pki_crl_admin_enable || id == md_pki_crl_admin_disable ||
      id == md_delete_pki_crl_admin || id == classic_pki_crl_no_shutdown ||
      id == classic_pki_crl_shutdown || id == classic_pki_crl_create ||
      id == md_pki_crl_periodic || id == md_delete_pki_crl_periodic ||
      id == md_pki_crl_preupdate || id == md_delete_pki_crl_preupdate ||
      id == md_pki_crl_retry || id == md_delete_pki_crl_retry ||
      id == classic_pki_crl_retry || id == classic_pki_crl_no_retry ||
      id == md_pki_crl_schedule_next || id == md_pki_crl_schedule_periodic ||
      id == md_delete_pki_crl_schedule ||
      id == classic_pki_crl_schedule_next ||
      id == classic_pki_crl_schedule_periodic ||
      id == classic_pki_crl_periodic_days ||
      id == classic_pki_crl_periodic_hours ||
      id == classic_pki_crl_periodic_days_hours ||
      id == classic_pki_crl_periodic_minutes ||
      id == classic_pki_crl_periodic_days_minutes ||
      id == classic_pki_crl_periodic_hours_minutes ||
      id == classic_pki_crl_periodic_days_hours_minutes ||
      id == classic_pki_crl_periodic_seconds ||
      id == classic_pki_crl_periodic_days_seconds ||
      id == classic_pki_crl_periodic_hours_seconds ||
      id == classic_pki_crl_periodic_days_hours_seconds ||
      id == classic_pki_crl_periodic_minutes_seconds ||
      id == classic_pki_crl_periodic_days_minutes_seconds ||
      id == classic_pki_crl_periodic_hours_minutes_seconds ||
      id == classic_pki_crl_periodic_days_hours_minutes_seconds ||
      id == md_pki_crl_url || id == md_pki_crl_transmission ||
      id == md_delete_pki_crl_entry_url ||
      id == md_delete_pki_crl_entry_transmission ||
      id == md_delete_pki_crl_entry || id == classic_pki_crl_entry_create ||
      id == classic_pki_crl_entry_remove || id == classic_pki_crl_entry_url ||
      id == classic_pki_crl_entry_no_url) {
    const bool changed =
        edit_auto_crl(profile.auto_crl_update, id, command, md, silent_absent);
    // Addressing any auto-crl-update child creates the presence container.
    // A failed edit rolls back through the caller snapshot, so raising
    // presence on success never leaks a phantom container.
    if (changed && !profile.auto_crl_update.present &&
        id != md_delete_pki_crl_update &&
        id != classic_pki_crl_remove)
      profile.auto_crl_update.present = true;
    return changed;
  }
  if (id == md_delete_pki_crl_update || id == classic_pki_crl_remove) {
    if (!profile.auto_crl_update.present) {
      silent_absent = id == md_delete_pki_crl_update;
      return false;
    }
    profile.auto_crl_update = pki::AutoCrlUpdate{};
    return true;
  }
  return false;
}

bool edit_common_name_list(pki::Configuration &state,
                           pki::CommonNameList &list, CommandId id,
                           const cli_detail::ParsedCommand &command, bool md,
                           bool &silent_absent) {
  using enum CommandId;
  static_cast<void>(state);
  const auto index_text = argument_text(command, TokenKind::pki_cn_index);
  const auto index = decimal<std::uint32_t>(index_text);
  if (id == md_delete_pki_cn_list || id == classic_pki_cn_list_remove) {
    // Handled by the caller, which owns the list vector. Reaching here
    // means a logic defect, never a silent success.
    return false;
  }
  if (!index || *index < 1U || *index > pki::maximum_common_names_per_list)
    return false;
  const auto numeric = *index;
  // MD-CLI removals never materialize their entries: resolving with find
  // keeps the absent-entry silent path free of phantom records.
  const bool md_removal_for_entry =
      md && command.spec && cli_detail::removal_command(*command.spec);
  auto *entry = [&]() -> pki::CommonNameEntry * {
    const auto found =
        std::find_if(list.entries.begin(), list.entries.end(),
                     [&](const auto &item) { return item.index == numeric; });
    if (found != list.entries.end())
      return &*found;
    // The classic compound command carries type and value together and
    // creates the entry directly. Removals never materialize.
    if ((!md && id != classic_pki_cn_ip && id != classic_pki_cn_domain) ||
        md_removal_for_entry)
      return nullptr;
    list.entries.push_back(pki::CommonNameEntry{.index = numeric});
    return &list.entries.back();
  }();
  if (id == classic_pki_cn_remove || id == md_delete_pki_cn) {
    if (!entry) {
      silent_absent = md;
      return false;
    }
    list.entries.erase(
        std::remove_if(list.entries.begin(), list.entries.end(),
                       [&](const auto &item) { return item.index == numeric; }),
        list.entries.end());
    return true;
  }
  if (!entry)
    return false;
  if (id == md_pki_cn_type_ip || id == md_pki_cn_type_domain ||
      id == classic_pki_cn_ip || id == classic_pki_cn_domain) {
    // Classic carries type and value in one compound command; MD addresses
    // one leaf per command. Both converge on the same entry record.
    const auto type = id == md_pki_cn_type_domain ||
                              id == classic_pki_cn_domain
                          ? pki::CommonNameType::domain_name
                          : pki::CommonNameType::ip_address;
    std::string value = entry->value;
    if (id == classic_pki_cn_ip || id == classic_pki_cn_domain) {
      const auto text = argument_text(command, TokenKind::pki_cn_value);
      if (text.empty() || text.size() > 255U)
        return false;
      value.assign(text);
    }
    if (entry->type == type && entry->value == value)
      return false;
    entry->type = type;
    entry->value = std::move(value);
    return true;
  }
  if (id == md_pki_cn_value) {
    const auto text = argument_text(command, TokenKind::pki_cn_value);
    if (text.empty() || text.size() > 255U || entry->value == text)
      return false;
    entry->value.assign(text);
    return true;
  }
  return false;
}

bool edit_est_profile(pki::Configuration &state, pki::EstProfile &profile,
                      CommandId id, const cli_detail::ParsedCommand &command,
                      bool md, SecretSink *secrets, bool &silent_absent) {
  using enum CommandId;
  static_cast<void>(state);
  if (id == md_pki_est_transmission) {
    const auto text = argument_text(command, TokenKind::pki_transmission_profile);
    if (text.empty() || text.size() > 32U || profile.transmission_profile == text)
      return false;
    profile.transmission_profile.assign(text);
    return true;
  }
  if (id == md_delete_pki_est_transmission) {
    if (profile.transmission_profile.empty()) {
      silent_absent = true;
      return false;
    }
    profile.transmission_profile.clear();
    return true;
  }
  if (id == md_pki_est_client_tls || id == classic_pki_est_client_tls) {
    const auto text =
        argument_text(command, TokenKind::tls_client_profile_name);
    if (text.empty() || text.size() > 32U || profile.client_tls_profile == text)
      return false;
    profile.client_tls_profile.assign(text);
    return true;
  }
  if (id == md_delete_pki_est_client_tls ||
      id == classic_pki_est_no_client_tls) {
    if (profile.client_tls_profile.empty()) {
      silent_absent = md;
      return false;
    }
    profile.client_tls_profile.clear();
    return true;
  }
  if (id == md_pki_est_check_id) {
    const auto text = argument_text(command, TokenKind::boolean);
    if (text != "true" && text != "false")
      return false;
    return configure(profile.check_id_kp_cmcra_only,
                     profile.check_id_kp_cmcra_only_configured,
                     text == "true");
  }
  if (id == md_delete_pki_est_check_id) {
    const bool changed =
        remove(profile.check_id_kp_cmcra_only,
               profile.check_id_kp_cmcra_only_configured, false);
    silent_absent = !changed;
    return changed;
  }
  if (id == md_pki_est_server_port) {
    const auto value = decimal<unsigned>(argument_text(command, TokenKind::pki_server_port));
    if (!value || *value < 1U || *value > 65535U ||
        (profile.server.port_configured &&
         profile.server.port == *value))
      return false;
    profile.server.port = static_cast<std::uint16_t>(*value);
    profile.server.port_configured = true;
    return true;
  }
  if (id == md_delete_pki_est_server_port) {
    if (!profile.server.port_configured && profile.server.port == 443U) {
      silent_absent = true;
      return false;
    }
    profile.server.port = 443U;
    profile.server.port_configured = false;
    return true;
  }
  if (id == md_pki_est_server_ipv4 || id == md_pki_est_server_ipv6 ||
      id == md_pki_est_server_fqdn) {
    const auto kind = id == md_pki_est_server_ipv4
                          ? pki::EstServerAddressKind::ipv4
                      : id == md_pki_est_server_ipv6
                          ? pki::EstServerAddressKind::ipv6
                          : pki::EstServerAddressKind::fqdn;
    const auto text = argument_text(
        command, id == md_pki_est_server_ipv4 ? TokenKind::ipv4
                : id == md_pki_est_server_ipv6 ? TokenKind::ipv6
                                               : TokenKind::pki_fqdn);
    if (text.empty() || text.size() > 255U)
      return false;
    if (profile.server.address_kind == kind && profile.server.address == text)
      return false;
    profile.server.address_kind = kind;
    profile.server.address.assign(text);
    return true;
  }
  if (id == md_delete_pki_est_server_address) {
    if (profile.server.address_kind == pki::EstServerAddressKind::none) {
      silent_absent = true;
      return false;
    }
    profile.server.address_kind = pki::EstServerAddressKind::none;
    profile.server.address.clear();
    return true;
  }
  const auto server_path = [&](TokenKind kind, std::string &leaf) {
    const auto text = argument_text(command, kind);
    if (text.empty() || text.size() > 255U || text.front() != '/' ||
        leaf == text)
      return false;
    leaf.assign(text);
    return true;
  };
  if (id == md_pki_est_path_cacerts)
    return server_path(TokenKind::pki_path, profile.server.path.cacerts);
  if (id == md_pki_est_path_simpleenroll)
    return server_path(TokenKind::pki_path, profile.server.path.simple_enroll);
  if (id == md_pki_est_path_simplereenroll)
    return server_path(TokenKind::pki_path,
                       profile.server.path.simple_reenroll);
  if (id == md_delete_pki_est_path_cacerts ||
      id == md_delete_pki_est_path_simpleenroll ||
      id == md_delete_pki_est_path_simplereenroll) {
    auto &leaf = id == md_delete_pki_est_path_cacerts
                     ? profile.server.path.cacerts
                 : id == md_delete_pki_est_path_simpleenroll
                     ? profile.server.path.simple_enroll
                     : profile.server.path.simple_reenroll;
    if (leaf.empty()) {
      silent_absent = true;
      return false;
    }
    leaf.clear();
    return true;
  }
  if (id == md_pki_est_http_username || id == classic_pki_est_http_username) {
    const auto text = argument_text(command, TokenKind::pki_username);
    if (text.empty() || text.size() > 32U ||
        profile.http_authentication.username == text)
      return false;
    profile.http_authentication.username.assign(text);
    return true;
  }
  if (id == md_delete_pki_est_http_username ||
      id == classic_pki_est_http_no_username) {
    if (profile.http_authentication.username.empty()) {
      silent_absent = md;
      return false;
    }
    profile.http_authentication.username.clear();
    return true;
  }
  if (id == md_pki_est_http_password ||
      id == classic_pki_est_http_password) {
    const auto text = argument_text(command, TokenKind::radius_password);
    if (text.empty() || text.size() > 166U)
      return false;
    auto bytes = std::vector<std::uint8_t>{text.begin(), text.end()};
    const auto handle =
        secrets ? secrets->seal(SecretKind::est_http_password, bytes)
                : std::nullopt;
    std::fill(bytes.begin(), bytes.end(), std::uint8_t{});
    if (!handle)
      return false;
    if (profile.http_authentication.password_handle == *handle &&
        profile.http_authentication.password_configured)
      return false;
    profile.http_authentication.password_handle = *handle;
    profile.http_authentication.password_configured = true;
    return true;
  }
  if (id == md_delete_pki_est_http_password ||
      id == classic_pki_est_http_no_password) {
    if (!profile.http_authentication.password_configured) {
      silent_absent = md;
      return false;
    }
    profile.http_authentication.password_handle = 0U;
    profile.http_authentication.password_configured = false;
    return true;
  }
  return false;
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  // Schema-driven ownership never drifts when rows are reordered: the source
  // record owns every PKI command and the engine mask owns the syntax.
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [id](const auto &command) {
        const auto root = command.tokens[0].display;
        return command.id == id && (command.engine_mask & 1U) != 0U &&
               command.source_id == "nokia.sros.26_7.pki.configuration" &&
               (root == "configure" || root == "delete");
      });
}

bool is_classic_command(CommandId id) noexcept {
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [id](const auto &command) {
        return command.id == id && (command.engine_mask & 2U) != 0U &&
               command.source_id == "nokia.sros.26_7.pki.configuration" &&
               command.tokens[0].display == "configure";
      });
}

EditResult edit(pki::Configuration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine,
                SecretSink *secrets) {
  const auto id = command.spec->id;
  const bool recognized =
      engine == CliEngine::md ? is_md_command(id) : is_classic_command(id);
  if (!recognized)
    return {};
  const bool md = engine == CliEngine::md;
  const auto before = configuration;
  bool changed{};
  bool silent_absent{};
  bool selected{};
  std::string instance{"/system/security/pki"};
  const auto ca_name = argument_text(command, TokenKind::pki_ca_profile_name);
  const auto cn_list_name =
      argument_text(command, TokenKind::pki_common_name_list_name);
  const auto est_name = argument_text(command, TokenKind::pki_est_profile_name);
  const auto update_name =
      argument_text(command, TokenKind::pki_update_profile_name);
  const auto auto_cert =
      argument_text(command, TokenKind::pki_file_name);
  const auto auto_key = argument_text(command, TokenKind::pki_key_file);
  using enum CommandId;

  // Top-level leaves carry no list key. They are selected when none of the
  // list names is present.
  const bool top_level =
      ca_name.empty() && cn_list_name.empty() && est_name.empty() &&
      update_name.empty() && auto_cert.empty() && auto_key.empty() &&
      (id == md_pki_display_ascii || id == md_pki_display_utf8 ||
       id == classic_pki_display_ascii || id == classic_pki_display_utf8 ||
       id == md_delete_pki_display || id == md_pki_dynamic_ca ||
       id == md_delete_pki_dynamic || id == md_pki_imported_any ||
       id == md_pki_imported_secure || id == classic_pki_imported_any ||
       id == classic_pki_imported_secure || id == md_delete_pki_imported ||
       id == md_pki_chain_depth || id == md_delete_pki_chain_depth ||
       id == classic_pki_chain_depth || id == classic_pki_no_chain_depth ||
       id == md_pki_cert_warn_hours || id == md_pki_cert_warn_repeat ||
       id == md_pki_crl_warn_hours || id == md_pki_crl_warn_repeat ||
       id == classic_pki_cert_warn || id == classic_pki_cert_warn_repeat ||
       id == classic_pki_crl_warn || id == classic_pki_crl_warn_repeat ||
       id == classic_pki_no_cert_warn || id == classic_pki_no_crl_warn ||
       id == md_delete_pki_cert_warn_hours ||
       id == md_delete_pki_cert_warn_repeat ||
       id == md_delete_pki_crl_warn_hours ||
       id == md_delete_pki_crl_warn_repeat);
  // Branch selection is by command identity, never by bare name presence:
  // value leaves (cert-file, response-signing-cert) carry pki_file_name
  // values that must not route into the auto-update branch, and the update
  // cmpv2 row carries both an update name and a referenced CA name.
  const bool is_update_command =
      id == md_pki_update_hash_md5 || id == md_pki_update_hash_sha1 ||
      id == md_pki_update_hash_sha224 || id == md_pki_update_hash_sha256 ||
      id == md_pki_update_hash_sha384 || id == md_pki_update_hash_sha512 ||
      id == md_delete_pki_update_hash || id == md_pki_update_retry ||
      id == classic_pki_update_retry || id == md_delete_pki_update_retry ||
      id == md_pki_update_cmpv2 || id == md_delete_pki_update_protocol ||
      id == md_pki_update_est || id == md_delete_pki_update_est ||
      id == md_pki_update_samekey || id == classic_pki_update_samekey ||
      id == md_pki_update_rsa || id == md_pki_update_rsa_size ||
      id == classic_pki_update_rsa || id == md_pki_update_dsa ||
      id == md_pki_update_dsa_size || id == classic_pki_update_dsa ||
      id == md_pki_update_ecdsa || id == md_pki_update_curve_256 ||
      id == md_pki_update_curve_384 || id == md_pki_update_curve_521 ||
      id == classic_pki_update_ecdsa_256 ||
      id == classic_pki_update_ecdsa_384 ||
      id == classic_pki_update_ecdsa_521 ||
      id == md_delete_pki_update_keygen || id == md_delete_pki_update_rsa ||
      id == md_delete_pki_update_dsa || id == md_delete_pki_update_ecdsa ||
      id == md_pki_update_before || id == md_pki_update_after ||
      id == classic_pki_update_schedule ||
      id == md_delete_pki_update_schedule ||
      id == md_delete_pki_update_after || id == md_delete_pki_update ||
      id == classic_pki_update_remove || id == classic_pki_update_create;
  const bool is_autoupdate_command =
      id == md_pki_autoupdate_key || id == md_pki_autoupdate_profile ||
      id == md_delete_pki_autoupdate || id == md_delete_pki_autoupdate_key ||
      id == md_delete_pki_autoupdate_profile ||
      id == classic_pki_autoupdate_create ||
      id == classic_pki_autoupdate_remove || id == classic_pki_autoupdate_key;
  if (top_level) {
    changed = edit_top_level(configuration, id, command, md, silent_absent);
  } else if (is_update_command) {
    instance += "/certificate-update-profile/" + std::string{update_name};
    const bool md_removal =
        md && command.spec && cli_detail::removal_command(*command.spec);
    auto *profile =
        md && !md_removal
            ? materialize_named(configuration.update_profiles, update_name,
                                pki::maximum_certificate_update_profiles)
            : pki::find_named(configuration.update_profiles, update_name);
    if (id == md_delete_pki_update || id == classic_pki_update_remove) {
      const auto found = std::find_if(
          configuration.update_profiles.begin(),
          configuration.update_profiles.end(),
          [&](const auto &item) { return item.name == update_name; });
      if (found != configuration.update_profiles.end()) {
        configuration.update_profiles.erase(found);
        changed = true;
      } else {
        silent_absent = id == md_delete_pki_update;
      }
    } else if (id == classic_pki_update_create) {
      const bool existed = pki::find_named(before.update_profiles, update_name);
      if (!profile)
        profile = materialize_named(configuration.update_profiles, update_name,
                                    pki::maximum_certificate_update_profiles);
      changed = profile && !existed;
      selected = profile && existed;
    } else if (profile) {
      changed =
          edit_update_profile(*profile, id, command, md, silent_absent);
    } else if (md_removal) {
      silent_absent = true;
    }
  } else if (is_autoupdate_command) {
    // Certificate auto-update entries are keyed by certificate file. The
    // key-file row carries both the entry key and the key file; other rows
    // address the entry through the certificate file alone.
    const std::string_view key =
        !auto_cert.empty() ? auto_cert : std::string_view{};
    if (!key.empty())
      instance += "/certificate-auto-update/" + std::string{key};
    const bool md_removal =
        md && command.spec && cli_detail::removal_command(*command.spec);
    auto *entry = [&]() -> pki::CertificateAutoUpdate * {
      const auto found = std::find_if(
          configuration.auto_updates.begin(), configuration.auto_updates.end(),
          [&](const auto &item) { return item.certificate_file == key; });
      if (found != configuration.auto_updates.end())
        return &*found;
      if (key.empty() || md_removal)
        return nullptr;
      if (!pki::valid_pki_filename(key) ||
          configuration.auto_updates.size() >=
              pki::maximum_certificate_auto_updates)
        return nullptr;
      // Classic materializes only through create; MD materializes when
      // addressing a child leaf.
      if (!md && id != classic_pki_autoupdate_create)
        return nullptr;
      configuration.auto_updates.push_back(
          pki::CertificateAutoUpdate{.certificate_file = std::string{key}});
      return &configuration.auto_updates.back();
    }();
    if (id == md_delete_pki_autoupdate || id == classic_pki_autoupdate_remove) {
      const auto found = std::find_if(
          configuration.auto_updates.begin(), configuration.auto_updates.end(),
          [&](const auto &item) { return item.certificate_file == key; });
      if (found != configuration.auto_updates.end()) {
        configuration.auto_updates.erase(found);
        changed = true;
      } else {
        silent_absent = id == md_delete_pki_autoupdate;
      }
    } else if (id == classic_pki_autoupdate_create) {
      const bool existed = std::any_of(
          before.auto_updates.begin(), before.auto_updates.end(),
          [&](const auto &item) { return item.certificate_file == key; });
      changed = entry && !existed;
      selected = entry && existed;
    } else if (entry) {
      changed = edit_auto_update(configuration, *entry, id, command, md,
                                 silent_absent);
    } else if (md_removal) {
      silent_absent = true;
    }
  } else if (!ca_name.empty() && cn_list_name.empty() && est_name.empty()) {
    instance += "/ca-profile/" + std::string{ca_name};
    const bool md_removal =
        md && command.spec && cli_detail::removal_command(*command.spec);
    auto *profile =
        md && !md_removal
            ? materialize_named(configuration.ca_profiles, ca_name,
                                pki::maximum_ca_profiles)
            : pki::find_named(configuration.ca_profiles, ca_name);
    if (id == md_delete_pki_ca || id == classic_pki_ca_remove) {
      const auto found = std::find_if(
          configuration.ca_profiles.begin(), configuration.ca_profiles.end(),
          [&](const auto &item) { return item.name == ca_name; });
      if (found != configuration.ca_profiles.end()) {
        configuration.ca_profiles.erase(found);
        changed = true;
      } else {
        silent_absent = id == md_delete_pki_ca;
      }
    } else if (id == classic_pki_ca_create) {
      const bool existed = pki::find_named(before.ca_profiles, ca_name);
      if (!profile)
        profile = materialize_named(configuration.ca_profiles, ca_name,
                                    pki::maximum_ca_profiles);
      changed = profile && !existed;
      selected = profile && existed;
    } else if (profile) {
      changed = edit_ca_profile(*profile, id, command, md, secrets, silent_absent);
    } else if (md_removal) {
      silent_absent = true;
    }
  } else if (!cn_list_name.empty() && ca_name.empty() && est_name.empty()) {
    instance += "/common-name-list/" + std::string{cn_list_name};
    const bool md_removal =
        md && command.spec && cli_detail::removal_command(*command.spec);
    auto *list =
        md && !md_removal
            ? materialize_named(configuration.common_name_lists, cn_list_name,
                                pki::maximum_common_name_lists)
            : pki::find_named(configuration.common_name_lists, cn_list_name);
    if (id == md_delete_pki_cn_list || id == classic_pki_cn_list_remove) {
      const auto found = std::find_if(
          configuration.common_name_lists.begin(),
          configuration.common_name_lists.end(),
          [&](const auto &item) { return item.name == cn_list_name; });
      if (found != configuration.common_name_lists.end()) {
        configuration.common_name_lists.erase(found);
        changed = true;
      } else {
        silent_absent = id == md_delete_pki_cn_list;
      }
    } else if (id == classic_pki_cn_list_create) {
      const bool existed = pki::find_named(before.common_name_lists,
                                           cn_list_name);
      if (!list)
        list = materialize_named(configuration.common_name_lists,
                                 cn_list_name,
                                 pki::maximum_common_name_lists);
      changed = list && !existed;
      selected = list && existed;
    } else if (list) {
      changed = edit_common_name_list(configuration, *list, id, command, md,
                                       silent_absent);
    } else if (md_removal) {
      silent_absent = true;
    }
  } else if (!est_name.empty() && ca_name.empty() && cn_list_name.empty()) {
    instance += "/est-profile/" + std::string{est_name};
    const bool md_removal =
        md && command.spec && cli_detail::removal_command(*command.spec);
    auto *profile =
        md && !md_removal
            ? materialize_named(configuration.est_profiles, est_name,
                                pki::maximum_est_profiles)
            : pki::find_named(configuration.est_profiles, est_name);
    if (id == md_delete_pki_est || id == classic_pki_est_remove) {
      const auto found = std::find_if(
          configuration.est_profiles.begin(), configuration.est_profiles.end(),
          [&](const auto &item) { return item.name == est_name; });
      if (found != configuration.est_profiles.end()) {
        configuration.est_profiles.erase(found);
        changed = true;
      } else {
        silent_absent = id == md_delete_pki_est;
      }
    } else if (id == classic_pki_est_create) {
      const bool existed =
          pki::find_named(before.est_profiles, est_name);
      if (!profile)
        profile = materialize_named(configuration.est_profiles, est_name,
                                    pki::maximum_est_profiles);
      changed = profile && !existed;
      selected = profile && existed;
    } else if (profile) {
      changed = edit_est_profile(configuration, *profile, id, command, md,
                                  secrets, silent_absent);
    } else if (md_removal) {
      silent_absent = true;
    }
  }

  if (!changed)
    configuration = before;
  const bool valid = changed || silent_absent || selected;
  if (valid && changed && !pki::validate(configuration, md)) {
    configuration = before;
    return {.recognized = true,
            .valid = false,
            .changed = false,
            .instance = std::move(instance)};
  }
  return {.recognized = true,
          .valid = valid,
          .changed = changed,
          .instance = std::move(instance)};
}

} // namespace router::lab::pki_cli
