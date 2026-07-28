// SR OS 26.7.R1 BOF DHCP autoconfiguration edits. The BOF is a separate
// model-driven configuration region, so this editor deliberately exposes no
// classic alias and never inserts a fictitious configure prefix.

#include "bof_cli_configuration.hpp"

#include "cli_internal.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <string_view>

namespace router::lab::bof_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;

std::optional<std::string_view>
argument_of(const cli_detail::ParsedCommand &command, TokenKind kind) noexcept {
  if (!command.spec)
    return std::nullopt;
  for (std::size_t index{}; index < command.spec->token_count; ++index)
    if (command.spec->tokens[index].kind == kind)
      return command.tokens[index];
  return std::nullopt;
}

bool parse_boolean(std::string_view text, bool &value) noexcept {
  if (text == "true") {
    value = true;
    return true;
  }
  if (text == "false") {
    value = false;
    return true;
  }
  return false;
}

std::optional<std::uint16_t> timeout(std::string_view text) noexcept {
  unsigned value{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || result.ec != std::errc{} ||
      result.ptr != text.data() + text.size() || value < 1U ||
      value > 65'535U)
    return std::nullopt;
  return static_cast<std::uint16_t>(value);
}

bool hexadecimal(std::string_view text) noexcept {
  return !text.empty() &&
         std::all_of(text.begin(), text.end(), [](const char byte) {
           return (byte >= '0' && byte <= '9') ||
                  (byte >= 'a' && byte <= 'f') ||
                  (byte >= 'A' && byte <= 'F');
         });
}

struct ClientId {
  std::string value;
  bool hexadecimal{};
};

std::optional<ClientId> client_id(std::string_view raw,
                                  std::size_t string_maximum,
                                  std::size_t hexadecimal_maximum) {
  // Nokia distinguishes a quoted character string from unquoted hexadecimal
  // bytes. Preserve the user's lexical value without quotes because the BOF
  // owner later encodes it according to the selected form.
  const bool quoted = raw.size() >= 2U && raw.front() == '"' &&
                      raw.back() == '"';
  const auto value = cli_detail::unquote(raw);
  if (quoted)
    return !value.empty() && value.size() <= string_maximum
               ? std::optional<ClientId>{{std::string{value}, false}}
               : std::nullopt;
  const auto digits = value.starts_with("0x") ? value.substr(2U)
                                               : std::string_view{};
  return value.size() >= 3U && value.size() <= hexadecimal_maximum &&
                 !digits.empty() && hexadecimal(digits)
             ? std::optional<ClientId>{{std::string{value}, true}}
             : std::nullopt;
}

bool fresh_secret(crypto::Sha256Digest &secret,
                  EntropySource *entropy) noexcept {
  return entropy && entropy->fill(secret);
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  switch (id) {
  case md_bof_ipv4_dhcp:
  case md_bof_ipv4_client_id:
  case md_bof_ipv4_include_user_class:
  case md_bof_ipv4_timeout:
  case md_delete_bof_ipv4_dhcp:
  case md_delete_bof_ipv4_client_id:
  case md_delete_bof_ipv4_include_user_class:
  case md_delete_bof_ipv4_timeout:
  case md_bof_ipv6_dhcp:
  case md_bof_ipv6_client_id:
  case md_bof_ipv6_client_type_enterprise:
  case md_bof_ipv6_client_type_link_local:
  case md_bof_ipv6_include_user_class:
  case md_bof_ipv6_timeout:
  case md_delete_bof_ipv6_dhcp:
  case md_delete_bof_ipv6_client_id:
  case md_delete_bof_ipv6_client_type:
  case md_delete_bof_ipv6_include_user_class:
  case md_delete_bof_ipv6_timeout:
    return true;
  default:
    return false;
  }
}

EditResult edit(bof::AutoconfigureIntent &configuration,
                const cli_detail::ParsedCommand &command,
                EntropySource *entropy) {
  if (!command.spec || !is_md_command(command.spec->id))
    return {};

  using enum CommandId;
  const auto id = command.spec->id;
  const bool ipv6_command =
      id == md_bof_ipv6_dhcp || id == md_bof_ipv6_client_id ||
      id == md_bof_ipv6_client_type_enterprise ||
      id == md_bof_ipv6_client_type_link_local ||
      id == md_bof_ipv6_include_user_class || id == md_bof_ipv6_timeout ||
      id == md_delete_bof_ipv6_dhcp || id == md_delete_bof_ipv6_client_id ||
      id == md_delete_bof_ipv6_client_type ||
      id == md_delete_bof_ipv6_include_user_class ||
      id == md_delete_bof_ipv6_timeout;
  auto staged = configuration;
  bool valid = true;
  bool identity_changed = false;

  if (id == md_bof_ipv4_dhcp) {
    staged.ipv4.enabled = true;
    identity_changed = true;
  } else if (id == md_delete_bof_ipv4_dhcp) {
    staged.ipv4 = {};
    staged.ipv4_transaction_secret = {};
  } else if (id == md_bof_ipv4_client_id) {
    const auto raw = argument_of(command, TokenKind::bof_client_id);
    const auto value = raw ? client_id(*raw, 127U, 256U) : std::nullopt;
    valid = value.has_value();
    if (valid) {
      staged.ipv4.client_id = value->value;
      staged.ipv4.client_id_hex = value->hexadecimal;
      identity_changed = true;
    }
  } else if (id == md_delete_bof_ipv4_client_id) {
    staged.ipv4.client_id.clear();
    staged.ipv4.client_id_hex = false;
    identity_changed = staged.ipv4.enabled;
  } else if (id == md_bof_ipv4_include_user_class) {
    const auto value = argument_of(command, TokenKind::boolean);
    valid = value && parse_boolean(*value, staged.ipv4.include_user_class);
  } else if (id == md_delete_bof_ipv4_include_user_class) {
    staged.ipv4.include_user_class = false;
  } else if (id == md_bof_ipv4_timeout) {
    const auto raw = argument_of(command, TokenKind::bof_timeout_seconds);
    const auto value = raw ? timeout(*raw) : std::nullopt;
    valid = value.has_value();
    if (valid)
      staged.ipv4.timeout_seconds = *value;
  } else if (id == md_delete_bof_ipv4_timeout) {
    staged.ipv4.timeout_seconds = 30U;
  } else if (id == md_bof_ipv6_dhcp) {
    staged.ipv6.enabled = true;
    identity_changed = true;
  } else if (id == md_delete_bof_ipv6_dhcp) {
    staged.ipv6 = {};
    staged.ipv6_transaction_secret = {};
  } else if (id == md_bof_ipv6_client_id) {
    const auto raw = argument_of(command, TokenKind::bof_client_id);
    const auto value = raw ? client_id(*raw, 124U, 250U) : std::nullopt;
    valid = value.has_value();
    if (valid) {
      staged.ipv6.client_id = value->value;
      staged.ipv6.client_id_hex = value->hexadecimal;
      identity_changed = true;
    }
  } else if (id == md_delete_bof_ipv6_client_id) {
    staged.ipv6.client_id.clear();
    staged.ipv6.client_id_hex = false;
    identity_changed = staged.ipv6.enabled;
  } else if (id == md_bof_ipv6_client_type_enterprise ||
             id == md_bof_ipv6_client_type_link_local) {
    staged.ipv6.client_type =
        id == md_bof_ipv6_client_type_enterprise
            ? bof::Dhcpv6ClientType::duid_enterprise
            : bof::Dhcpv6ClientType::duid_link_local;
    identity_changed = staged.ipv6.enabled;
  } else if (id == md_delete_bof_ipv6_client_type) {
    staged.ipv6.client_type = bof::Dhcpv6ClientType::duid_enterprise;
    identity_changed = staged.ipv6.enabled;
  } else if (id == md_bof_ipv6_include_user_class) {
    const auto value = argument_of(command, TokenKind::boolean);
    valid = value && parse_boolean(*value, staged.ipv6.include_user_class);
  } else if (id == md_delete_bof_ipv6_include_user_class) {
    staged.ipv6.include_user_class = false;
  } else if (id == md_bof_ipv6_timeout) {
    const auto raw = argument_of(command, TokenKind::bof_timeout_seconds);
    const auto value = raw ? timeout(*raw) : std::nullopt;
    valid = value.has_value();
    if (valid)
      staged.ipv6.timeout_seconds = *value;
  } else if (id == md_delete_bof_ipv6_timeout) {
    staged.ipv6.timeout_seconds = 30U;
  }

  if (valid && identity_changed) {
    auto &secret = ipv6_command ? staged.ipv6_transaction_secret
                                : staged.ipv4_transaction_secret;
    valid = fresh_secret(secret, entropy);
  }
  valid = valid && bof::valid(staged);
  if (!valid)
    return {.recognized = true, .valid = false};

  const bool changed = staged != configuration;
  configuration = std::move(staged);
  return {.recognized = true,
          .valid = true,
          .changed = changed,
          .instance = ipv6_command ? "/bof/auto-configure/ipv6/dhcp"
                                   : "/bof/auto-configure/ipv4/dhcp"};
}

} // namespace router::lab::bof_cli
