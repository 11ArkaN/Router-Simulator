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
                     bool &silent_absent) {
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
  using enum CommandId;

  if (!ca_name.empty() && cn_list_name.empty() && est_name.empty()) {
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
      changed = edit_ca_profile(*profile, id, command, md, silent_absent);
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
