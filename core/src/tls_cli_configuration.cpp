// Implementation of generated MD-CLI and classic CLI TLS configuration
// semantics. Named-object creation differs by engine, while every leaf edits
// the same control-owned release model and is validated atomically.

#include "tls_cli_configuration.hpp"

#include "cli_internal.hpp"

#include <algorithm>
#include <optional>
#include <string_view>

namespace router::lab::tls_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;
using tls_profile::AlgorithmList;
using tls_profile::CertificateEntry;
using tls_profile::CertificateProfile;
using tls_profile::ClientProfile;
using tls_profile::Configuration;
using tls_profile::ProtocolVersion;
using tls_profile::RevocationMethod;
using tls_profile::ServerProfile;
using tls_profile::StatusResult;
using tls_profile::TrustAnchorProfile;

template <typename Item>
Item *named(std::vector<Item> &items, std::string_view name) {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [name](const Item &item) {
                                    return item.name == name;
                                  });
  return found == items.end() ? nullptr : &*found;
}

template <typename Item>
bool create_named(std::vector<Item> &items, std::string_view name) {
  // Classic `create` must create a new list instance. Treating an existing
  // instance as success would violate both SR OS intent and the project-wide
  // prohibition on successful no-op compatibility commands.
  if (named(items, name))
    return false;
  Item item{};
  item.name.assign(name);
  items.push_back(std::move(item));
  return true;
}

template <typename Item>
bool erase_named(std::vector<Item> &items, std::string_view name) {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [name](const Item &item) {
                                    return item.name == name;
                                  });
  if (found == items.end())
    return false;
  items.erase(found);
  return true;
}

template <typename Item>
Item *md_named(std::vector<Item> &items, std::string_view name) {
  // Entering or assigning a leaf below an MD named-item materializes that list
  // entry in candidate configuration. Classic requires its explicit `create`
  // row and therefore never calls this helper for a missing parent.
  if (auto *item = named(items, name))
    return item;
  Item item{};
  item.name.assign(name);
  items.push_back(std::move(item));
  return &items.back();
}

std::string_view value(const cli_detail::ParsedCommand &command,
                       TokenKind kind) {
  const auto raw = cli_detail::argument(command, kind);
  return raw ? cli_detail::unquote(*raw) : std::string_view{};
}

std::optional<std::uint8_t>
index(const cli_detail::ParsedCommand &command) {
  // Certificate entries and negotiation entries use different release
  // ranges, but both are stored as one-byte keys after schema validation.
  // Read whichever generated parameter is present without conflating their
  // help or acceptance ranges in the parser.
  auto text = value(command, TokenKind::tls_certificate_entry_index);
  if (text.empty())
    text = value(command, TokenKind::tls_algorithm_index);
  unsigned parsed{};
  if (text.empty())
    return std::nullopt;
  for (const auto byte : text) {
    if (byte < '0' || byte > '9')
      return std::nullopt;
    parsed = parsed * 10U + static_cast<unsigned>(byte - '0');
    if (parsed > device_catalog::tls_algorithm_index_maximum)
      return std::nullopt;
  }
  return parsed >= device_catalog::tls_algorithm_index_minimum
             ? std::optional<std::uint8_t>{static_cast<std::uint8_t>(parsed)}
             : std::nullopt;
}

template <typename Entry>
bool assign(std::string Entry::*member, Entry &entry, std::string_view text) {
  if (text.empty() || entry.*member == text)
    return false;
  entry.*member = text;
  return true;
}

template <typename Entry>
bool clear(std::string Entry::*member, Entry &entry) {
  if ((entry.*member).empty())
    return false;
  (entry.*member).clear();
  return true;
}

template <typename Value>
bool set_distinct(Value &destination, Value next) {
  if (destination == next)
    return false;
  destination = std::move(next);
  return true;
}

template <typename Value>
bool configure_leaf(Value &destination, bool &configured, Value next) {
  // A configured default is observable configuration, not a no-op. Preserve
  // that distinction so `delete` removes the leaf and `info` can later render
  // exactly what the operator entered instead of only the effective value.
  if (configured && destination == next)
    return false;
  destination = std::move(next);
  configured = true;
  return true;
}

template <typename Value>
bool delete_leaf(Value &destination, bool &configured, Value default_value) {
  // Deleting an absent leaf is a rejected no-op. Reset both the effective
  // scalar and its presence in one operation to keep candidate snapshots
  // self-contained and deterministic across checkpoint restore.
  if (!configured)
    return false;
  destination = std::move(default_value);
  configured = false;
  return true;
}

bool add_unique(std::vector<std::string> &items, std::string_view value) {
  if (value.empty() || std::find(items.begin(), items.end(), value) != items.end())
    return false;
  items.emplace_back(value);
  return true;
}

bool erase_value(std::vector<std::string> &items, std::string_view value) {
  const auto found = std::find(items.begin(), items.end(), value);
  if (found == items.end())
    return false;
  items.erase(found);
  return true;
}

CertificateEntry *certificate_entry(CertificateProfile &profile,
                                    std::uint8_t id, bool create) {
  const auto found = std::find_if(profile.entries.begin(), profile.entries.end(),
                                  [id](const auto &entry) {
                                    return entry.id == id;
                                  });
  if (found != profile.entries.end())
    return &*found;
  if (!create || id > device_catalog::tls_maximum_cert_entries_per_profile)
    return nullptr;
  CertificateEntry entry{};
  entry.id = id;
  profile.entries.push_back(std::move(entry));
  return &profile.entries.back();
}

bool edit_algorithm(AlgorithmList &list, std::uint8_t id,
                    std::string_view name, bool remove) {
  const auto found = std::find_if(list.entries.begin(), list.entries.end(),
                                  [id](const auto &entry) {
                                    return entry.index == id;
                                  });
  if (remove) {
    if (found == list.entries.end())
      return false;
    list.entries.erase(found);
    return true;
  }
  if (name.empty())
    return false;
  if (found == list.entries.end()) {
    list.entries.push_back({.index = id, .name = std::string{name}});
    return true;
  }
  return set_distinct(found->name, std::string{name});
}

ProtocolVersion protocol(CommandId id) {
  using enum CommandId;
  switch (id) {
  case md_tls_client_protocol_13:
  case md_tls_server_protocol_13:
  case classic_tls_client_protocol_13:
  case classic_tls_server_protocol_13:
    return ProtocolVersion::tls13;
  case md_tls_client_protocol_all:
  case md_tls_server_protocol_all:
  case classic_tls_client_protocol_all:
  case classic_tls_server_protocol_all:
    return ProtocolVersion::all;
  default:
    return ProtocolVersion::tls12;
  }
}

RevocationMethod revocation(CommandId id) {
  using enum CommandId;
  switch (id) {
  case md_tls_client_primary_ocsp:
  case md_tls_client_secondary_ocsp:
  case md_tls_server_primary_ocsp:
  case md_tls_server_secondary_ocsp:
  case classic_tls_client_primary_ocsp:
  case classic_tls_client_secondary_ocsp:
  case classic_tls_server_primary_ocsp:
  case classic_tls_server_secondary_ocsp:
    return RevocationMethod::ocsp;
  case md_tls_client_secondary_none:
  case md_tls_server_secondary_none:
  case classic_tls_client_secondary_none:
  case classic_tls_server_secondary_none:
    return RevocationMethod::none;
  default:
    return RevocationMethod::crl;
  }
}

template <typename Profile>
bool edit_common_profile(Profile &profile, CommandId id,
                         const cli_detail::ParsedCommand &command) {
  using enum CommandId;
  switch (id) {
  case md_tls_client_profile_enable:
  case md_tls_server_profile_enable:
  case classic_tls_client_profile_no_shutdown:
  case classic_tls_server_profile_no_shutdown:
    return configure_leaf(profile.admin_enabled, profile.admin_configured,
                          true);
  case md_tls_client_profile_disable:
  case md_tls_server_profile_disable:
  case classic_tls_client_profile_shutdown:
  case classic_tls_server_profile_shutdown:
    return configure_leaf(profile.admin_enabled, profile.admin_configured,
                          false);
  case md_delete_tls_client_profile_admin:
  case md_delete_tls_server_profile_admin:
    return delete_leaf(profile.admin_enabled, profile.admin_configured, false);
  case md_tls_client_cert_profile:
  case md_tls_server_cert_profile:
  case classic_tls_client_cert_profile:
  case classic_tls_server_cert_profile:
    return assign(&Profile::certificate_profile, profile,
                  value(command, TokenKind::tls_cert_profile_name));
  case md_delete_tls_client_cert_profile:
  case md_delete_tls_server_cert_profile:
  case classic_tls_client_no_cert_profile:
  case classic_tls_server_no_cert_profile:
    return clear(&Profile::certificate_profile, profile);
  case md_tls_client_protocol_12:
  case md_tls_client_protocol_13:
  case md_tls_client_protocol_all:
  case md_tls_server_protocol_12:
  case md_tls_server_protocol_13:
  case md_tls_server_protocol_all:
  case classic_tls_client_protocol_12:
  case classic_tls_client_protocol_13:
  case classic_tls_client_protocol_all:
  case classic_tls_server_protocol_12:
  case classic_tls_server_protocol_13:
  case classic_tls_server_protocol_all:
    return configure_leaf(profile.protocol_version,
                          profile.protocol_version_configured, protocol(id));
  case md_delete_tls_client_protocol:
  case md_delete_tls_server_protocol:
  case classic_tls_client_no_protocol:
  case classic_tls_server_no_protocol:
    return delete_leaf(profile.protocol_version,
                       profile.protocol_version_configured,
                       ProtocolVersion::tls12);
  case md_tls_client_status_good:
  case md_tls_server_status_good:
  case classic_tls_client_status_good:
  case classic_tls_server_status_good:
    return configure_leaf(
        profile.status_verification.default_result,
        profile.status_verification.default_result_configured,
        StatusResult::good);
  case md_tls_client_status_revoked:
  case md_tls_server_status_revoked:
  case classic_tls_client_status_revoked:
  case classic_tls_server_status_revoked:
    return configure_leaf(
        profile.status_verification.default_result,
        profile.status_verification.default_result_configured,
        StatusResult::revoked);
  case md_delete_tls_client_status:
  case md_delete_tls_server_status:
  case classic_tls_client_no_status:
  case classic_tls_server_no_status:
    return delete_leaf(
        profile.status_verification.default_result,
        profile.status_verification.default_result_configured,
        StatusResult::revoked);
  case md_tls_client_primary_crl:
  case md_tls_client_primary_ocsp:
  case md_tls_server_primary_crl:
  case md_tls_server_primary_ocsp:
  case classic_tls_client_primary_crl:
  case classic_tls_client_primary_ocsp:
  case classic_tls_server_primary_crl:
  case classic_tls_server_primary_ocsp:
    return configure_leaf(profile.status_verification.primary,
                          profile.status_verification.primary_configured,
                          revocation(id));
  case md_delete_tls_client_primary:
  case md_delete_tls_server_primary:
  case classic_tls_client_no_primary:
  case classic_tls_server_no_primary:
    return delete_leaf(profile.status_verification.primary,
                       profile.status_verification.primary_configured,
                       RevocationMethod::crl);
  case md_tls_client_secondary_none:
  case md_tls_client_secondary_crl:
  case md_tls_client_secondary_ocsp:
  case md_tls_server_secondary_none:
  case md_tls_server_secondary_crl:
  case md_tls_server_secondary_ocsp:
  case classic_tls_client_secondary_none:
  case classic_tls_client_secondary_crl:
  case classic_tls_client_secondary_ocsp:
  case classic_tls_server_secondary_none:
  case classic_tls_server_secondary_crl:
  case classic_tls_server_secondary_ocsp:
    return configure_leaf(profile.status_verification.secondary,
                          profile.status_verification.secondary_configured,
                          revocation(id));
  case md_delete_tls_client_secondary:
  case md_delete_tls_server_secondary:
  case classic_tls_client_no_secondary:
  case classic_tls_server_no_secondary:
    return delete_leaf(profile.status_verification.secondary,
                       profile.status_verification.secondary_configured,
                       RevocationMethod::none);
  default:
    return false;
  }
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  static_assert(md_tls_use_pqc_only < md_delete_tls_server_secondary);
  return id >= md_tls_use_pqc_only && id <= md_delete_tls_server_secondary;
}

bool is_classic_command(CommandId id) noexcept {
  using enum CommandId;
  static_assert(classic_tls_use_pqc_only < classic_tls_server_no_secondary);
  return id >= classic_tls_use_pqc_only &&
         id <= classic_tls_server_no_secondary;
}

EditResult edit(Configuration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine) {
  const auto id = command.spec->id;
  const bool recognized = engine == CliEngine::md ? is_md_command(id)
                                                   : is_classic_command(id);
  if (!recognized)
    return {};

  const auto before = configuration;
  bool changed{};
  std::string instance{"/system/security/tls"};
  const auto key = [&](TokenKind kind) {
    const auto result = value(command, kind);
    if (!result.empty()) {
      instance.push_back('/');
      instance.append(result);
    }
    return result;
  };
  const bool md = engine == CliEngine::md;
  using enum CommandId;

  if (id == md_tls_use_pqc_only || id == classic_tls_use_pqc_only) {
    const bool enabled = id == classic_tls_use_pqc_only ||
                         value(command, TokenKind::boolean) == "true";
    changed = configure_leaf(configuration.use_pqc_only,
                             configuration.use_pqc_only_configured, enabled);
  }
  else if (id == md_delete_tls_use_pqc_only ||
           id == classic_tls_no_use_pqc_only)
    changed = delete_leaf(configuration.use_pqc_only,
                          configuration.use_pqc_only_configured, false);
  else if (const auto certificate_profile_name =
               key(TokenKind::tls_cert_profile_name);
           !certificate_profile_name.empty() &&
           (id == classic_tls_cert_profile_create ||
            id == md_delete_tls_cert_profile ||
            id == classic_tls_cert_profile_remove ||
            id == md_tls_cert_profile_enable ||
            id == md_delete_tls_cert_profile_admin ||
            id == classic_tls_cert_profile_no_shutdown ||
            id == md_tls_cert_profile_disable ||
            id == classic_tls_cert_profile_shutdown ||
            id == md_tls_cert_entry_certificate ||
            id == classic_tls_cert_entry_certificate ||
            id == md_delete_tls_cert_entry_certificate ||
            id == classic_tls_cert_entry_no_certificate ||
            id == md_tls_cert_entry_key ||
            id == classic_tls_cert_entry_key ||
            id == md_delete_tls_cert_entry_key ||
            id == classic_tls_cert_entry_no_key ||
            id == md_tls_cert_entry_ca ||
            id == classic_tls_cert_entry_ca ||
            id == md_delete_tls_cert_entry_ca ||
            id == classic_tls_cert_entry_no_ca)) {
    if (id == classic_tls_cert_profile_create)
      changed = create_named(configuration.certificate_profiles,
                             certificate_profile_name);
    else if (id == md_delete_tls_cert_profile ||
             id == classic_tls_cert_profile_remove)
      changed = erase_named(configuration.certificate_profiles,
                            certificate_profile_name);
    else {
      auto *profile =
          md ? md_named(configuration.certificate_profiles,
                        certificate_profile_name)
             : named(configuration.certificate_profiles,
                     certificate_profile_name);
      if (profile && (id == md_tls_cert_profile_enable ||
                      id == classic_tls_cert_profile_no_shutdown))
        changed = configure_leaf(profile->admin_enabled,
                                 profile->admin_configured, true);
      else if (profile && (id == md_tls_cert_profile_disable ||
                           id == classic_tls_cert_profile_shutdown))
        changed = configure_leaf(profile->admin_enabled,
                                 profile->admin_configured, false);
      else if (profile && id == md_delete_tls_cert_profile_admin)
        changed = delete_leaf(profile->admin_enabled,
                              profile->admin_configured, false);
      else if (profile) {
        const auto entry_id = index(command);
        auto *entry = entry_id ? certificate_entry(*profile, *entry_id, true)
                               : nullptr;
        if (entry && (id == md_tls_cert_entry_certificate ||
                      id == classic_tls_cert_entry_certificate))
          changed = assign(&CertificateEntry::certificate_file, *entry,
                           value(command, TokenKind::tls_certificate_file));
        else if (entry && (id == md_delete_tls_cert_entry_certificate ||
                           id == classic_tls_cert_entry_no_certificate))
          changed = clear(&CertificateEntry::certificate_file, *entry);
        else if (entry && (id == md_tls_cert_entry_key ||
                           id == classic_tls_cert_entry_key))
          changed = assign(&CertificateEntry::key_file, *entry,
                           value(command, TokenKind::tls_key_file));
        else if (entry && (id == md_delete_tls_cert_entry_key ||
                           id == classic_tls_cert_entry_no_key))
          changed = clear(&CertificateEntry::key_file, *entry);
        else if (entry && (id == md_tls_cert_entry_ca ||
                           id == classic_tls_cert_entry_ca))
          changed = add_unique(entry->send_chain_ca_profiles,
                               value(command, TokenKind::tls_ca_profile_name));
        else if (entry && (id == md_delete_tls_cert_entry_ca ||
                           id == classic_tls_cert_entry_no_ca))
          changed = erase_value(
              entry->send_chain_ca_profiles,
              value(command, TokenKind::tls_ca_profile_name));
      }
    }
  } else if (const auto trust_anchor_profile_name =
                 key(TokenKind::tls_trust_anchor_profile_name);
             !trust_anchor_profile_name.empty() &&
             (id == md_tls_trust_anchor ||
              id == md_delete_tls_trust_anchor ||
              id == md_delete_tls_trust_anchor_profile ||
              id == classic_tls_trust_anchor_profile_create ||
              id == classic_tls_trust_anchor_profile_remove ||
              id == classic_tls_trust_anchor ||
              id == classic_tls_no_trust_anchor)) {
    if (id == classic_tls_trust_anchor_profile_create)
      changed = create_named(configuration.trust_anchor_profiles,
                             trust_anchor_profile_name);
    else if (id == md_delete_tls_trust_anchor_profile ||
             id == classic_tls_trust_anchor_profile_remove)
      changed = erase_named(configuration.trust_anchor_profiles,
                            trust_anchor_profile_name);
    else {
      auto *profile =
          md ? md_named(configuration.trust_anchor_profiles,
                        trust_anchor_profile_name)
             : named(configuration.trust_anchor_profiles,
                     trust_anchor_profile_name);
      if (profile && (id == md_tls_trust_anchor ||
                      id == classic_tls_trust_anchor))
        changed = add_unique(profile->ca_profiles,
                             value(command, TokenKind::tls_ca_profile_name));
      else if (profile)
        changed = erase_value(
            profile->ca_profiles,
            value(command, TokenKind::tls_ca_profile_name));
    }
  } else {
    // Algorithm collections share identical list-key semantics. Selecting the
    // collection from the generated parameter kind keeps client and server
    // namespaces independent without copying six editing implementations.
    auto edit_list = [&](auto &lists, TokenKind list_kind,
                         TokenKind algorithm_kind, CommandId create_id,
                         CommandId remove_list_id, CommandId remove_entry_id) {
      const auto name = key(list_kind);
      if (name.empty())
        return false;
      if (id == create_id)
        return create_named(lists, name);
      if (id == remove_list_id)
        return erase_named(lists, name);
      auto *list = md ? md_named(lists, name) : named(lists, name);
      const auto entry_id = index(command);
      return list && entry_id &&
             edit_algorithm(*list, *entry_id, value(command, algorithm_kind),
                            id == remove_entry_id);
    };
    if (value(command, TokenKind::tls_client_cipher_list_name).size() &&
        (index(command) || id == md_delete_tls_client_cipher_list ||
         id == classic_tls_client_cipher_list_create ||
         id == classic_tls_client_cipher_list_remove))
      changed = edit_list(configuration.client_cipher_lists,
                          TokenKind::tls_client_cipher_list_name,
                          TokenKind::tls_cipher_name,
                          classic_tls_client_cipher_list_create,
                          md ? md_delete_tls_client_cipher_list
                             : classic_tls_client_cipher_list_remove,
                          md ? md_delete_tls_client_cipher
                             : classic_tls_no_client_cipher);
    else if (value(command, TokenKind::tls_client_group_list_name).size() &&
             (index(command) || id == md_delete_tls_client_group_list ||
              id == classic_tls_client_group_list_create ||
              id == classic_tls_client_group_list_remove))
      changed = edit_list(configuration.client_group_lists,
                          TokenKind::tls_client_group_list_name,
                          TokenKind::tls_group_name,
                          classic_tls_client_group_list_create,
                          md ? md_delete_tls_client_group_list
                             : classic_tls_client_group_list_remove,
                          md ? md_delete_tls_client_group
                             : classic_tls_no_client_group);
    else if (value(command, TokenKind::tls_client_signature_list_name).size() &&
             (index(command) || id == md_delete_tls_client_signature_list ||
              id == classic_tls_client_signature_list_create ||
              id == classic_tls_client_signature_list_remove))
      changed = edit_list(configuration.client_signature_lists,
                          TokenKind::tls_client_signature_list_name,
                          TokenKind::tls_signature_name,
                          classic_tls_client_signature_list_create,
                          md ? md_delete_tls_client_signature_list
                             : classic_tls_client_signature_list_remove,
                          md ? md_delete_tls_client_signature
                             : classic_tls_no_client_signature);
    else if (value(command, TokenKind::tls_server_cipher_list_name).size() &&
             (index(command) || id == md_delete_tls_server_cipher_list ||
              id == classic_tls_server_cipher_list_create ||
              id == classic_tls_server_cipher_list_remove))
      changed = edit_list(configuration.server_cipher_lists,
                          TokenKind::tls_server_cipher_list_name,
                          TokenKind::tls_cipher_name,
                          classic_tls_server_cipher_list_create,
                          md ? md_delete_tls_server_cipher_list
                             : classic_tls_server_cipher_list_remove,
                          md ? md_delete_tls_server_cipher
                             : classic_tls_no_server_cipher);
    else if (value(command, TokenKind::tls_server_group_list_name).size() &&
             (index(command) || id == md_delete_tls_server_group_list ||
              id == classic_tls_server_group_list_create ||
              id == classic_tls_server_group_list_remove))
      changed = edit_list(configuration.server_group_lists,
                          TokenKind::tls_server_group_list_name,
                          TokenKind::tls_group_name,
                          classic_tls_server_group_list_create,
                          md ? md_delete_tls_server_group_list
                             : classic_tls_server_group_list_remove,
                          md ? md_delete_tls_server_group
                             : classic_tls_no_server_group);
    else if (value(command, TokenKind::tls_server_signature_list_name).size() &&
             (index(command) || id == md_delete_tls_server_signature_list ||
              id == classic_tls_server_signature_list_create ||
              id == classic_tls_server_signature_list_remove))
      changed = edit_list(configuration.server_signature_lists,
                          TokenKind::tls_server_signature_list_name,
                          TokenKind::tls_signature_name,
                          classic_tls_server_signature_list_create,
                          md ? md_delete_tls_server_signature_list
                             : classic_tls_server_signature_list_remove,
                          md ? md_delete_tls_server_signature
                             : classic_tls_no_server_signature);
    else if (const auto client_profile_name =
                 key(TokenKind::tls_client_profile_name);
             !client_profile_name.empty()) {
      if (id == classic_tls_client_profile_create)
        changed = create_named(configuration.client_profiles,
                               client_profile_name);
      else if (id == md_delete_tls_client_profile ||
               id == classic_tls_client_profile_remove)
        changed = erase_named(configuration.client_profiles,
                              client_profile_name);
      else {
        auto *profile =
            md ? md_named(configuration.client_profiles, client_profile_name)
               : named(configuration.client_profiles, client_profile_name);
        if (profile && (id == md_tls_client_cipher_list ||
                        id == classic_tls_client_cipher_list))
          changed = assign(&ClientProfile::cipher_list, *profile,
                           value(command,
                                 TokenKind::tls_client_cipher_list_name));
        else if (profile && (id == md_delete_tls_client_cipher_list_ref ||
                             id == classic_tls_client_no_cipher_list))
          changed = clear(&ClientProfile::cipher_list, *profile);
        else if (profile && (id == md_tls_client_group_list ||
                             id == classic_tls_client_group_list))
          changed = assign(&ClientProfile::group_list, *profile,
                           value(command,
                                 TokenKind::tls_client_group_list_name));
        else if (profile && (id == md_delete_tls_client_group_list_ref ||
                             id == classic_tls_client_no_group_list))
          changed = clear(&ClientProfile::group_list, *profile);
        else if (profile && (id == md_tls_client_signature_list ||
                             id == classic_tls_client_signature_list))
          changed = assign(&ClientProfile::signature_list, *profile,
                           value(command,
                                 TokenKind::tls_client_signature_list_name));
        else if (profile &&
                 (id == md_delete_tls_client_signature_list_ref ||
                  id == classic_tls_client_no_signature_list))
          changed = clear(&ClientProfile::signature_list, *profile);
        else if (profile && (id == md_tls_client_trust_anchor ||
                             id == classic_tls_client_trust_anchor))
          changed = assign(
              &ClientProfile::trust_anchor_profile, *profile,
              value(command, TokenKind::tls_trust_anchor_profile_name));
        else if (profile && (id == md_delete_tls_client_trust_anchor ||
                             id == classic_tls_client_no_trust_anchor))
          changed = clear(&ClientProfile::trust_anchor_profile, *profile);
        else if (profile)
          changed = edit_common_profile(*profile, id, command);
      }
    } else if (const auto server_profile_name =
                   key(TokenKind::tls_server_profile_name);
               !server_profile_name.empty()) {
      if (id == classic_tls_server_profile_create)
        changed = create_named(configuration.server_profiles,
                               server_profile_name);
      else if (id == md_delete_tls_server_profile ||
               id == classic_tls_server_profile_remove)
        changed = erase_named(configuration.server_profiles,
                              server_profile_name);
      else {
        auto *profile =
            md ? md_named(configuration.server_profiles, server_profile_name)
               : named(configuration.server_profiles, server_profile_name);
        if (profile && (id == md_tls_server_cipher_list ||
                        id == classic_tls_server_cipher_list))
          changed = assign(&ServerProfile::cipher_list, *profile,
                           value(command,
                                 TokenKind::tls_server_cipher_list_name));
        else if (profile && (id == md_delete_tls_server_cipher_list_ref ||
                             id == classic_tls_server_no_cipher_list))
          changed = clear(&ServerProfile::cipher_list, *profile);
        else if (profile && (id == md_tls_server_group_list ||
                             id == classic_tls_server_group_list))
          changed = assign(&ServerProfile::group_list, *profile,
                           value(command,
                                 TokenKind::tls_server_group_list_name));
        else if (profile && (id == md_delete_tls_server_group_list_ref ||
                             id == classic_tls_server_no_group_list))
          changed = clear(&ServerProfile::group_list, *profile);
        else if (profile && (id == md_tls_server_signature_list ||
                             id == classic_tls_server_signature_list))
          changed = assign(&ServerProfile::signature_list, *profile,
                           value(command,
                                 TokenKind::tls_server_signature_list_name));
        else if (profile &&
                 (id == md_delete_tls_server_signature_list_ref ||
                  id == classic_tls_server_no_signature_list))
          changed = clear(&ServerProfile::signature_list, *profile);
        else if (profile && (id == md_tls_server_trust_anchor ||
                             id == classic_tls_server_trust_anchor))
          changed = assign(
              &ServerProfile::client_trust_anchor_profile, *profile,
              value(command, TokenKind::tls_trust_anchor_profile_name));
        else if (profile && (id == md_delete_tls_server_trust_anchor ||
                             id == classic_tls_server_no_trust_anchor))
          changed = clear(&ServerProfile::client_trust_anchor_profile,
                          *profile);
        else if (profile && (id == md_tls_server_common_name ||
                             id == classic_tls_server_common_name))
          changed = assign(
              &ServerProfile::client_common_name_list, *profile,
              value(command, TokenKind::tls_common_name_list_name));
        else if (profile && (id == md_delete_tls_server_common_name ||
                             id == classic_tls_server_no_common_name))
          changed = clear(&ServerProfile::client_common_name_list, *profile);
        else if (profile)
          changed = edit_common_profile(*profile, id, command);
      }
    }
  }

  // Cross-reference and PQC rules are validated after the complete atomic
  // edit. A rejected command cannot leave a half-created list entry behind.
  if (!changed || tls_profile::validate(configuration)) {
    configuration = before;
    changed = false;
  }
  return {.recognized = true,
          .changed = changed,
          .instance = std::move(instance)};
}

} // namespace router::lab::tls_cli
