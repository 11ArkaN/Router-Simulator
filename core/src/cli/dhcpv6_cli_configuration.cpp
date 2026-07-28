// SR OS 26.7.R1 DHCPv6 local-server CLI edits. Named lists are resolved by
// their actual keys and every edit is validated against the canonical model
// before it replaces the caller-owned candidate or running configuration.

#include "dhcpv6_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <ranges>
#include <string_view>

namespace router::lab::dhcpv6_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;
using dhcpv6::configuration::Pool;
using dhcpv6::configuration::Prefix;
using dhcpv6::configuration::RouterConfiguration;
using dhcpv6::configuration::Server;

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  Integer value{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || result.ec != std::errc{} ||
      result.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::optional<std::string_view>
argument_at(const cli_detail::ParsedCommand &command, TokenKind kind,
            std::size_t occurrence = 0U) noexcept {
  if (!command.spec)
    return std::nullopt;
  std::size_t seen{};
  for (std::size_t index{}; index < command.spec->token_count; ++index) {
    if (command.spec->tokens[index].kind != kind)
      continue;
    if (seen++ == occurrence)
      return cli_detail::unquote(command.tokens[index]);
  }
  return std::nullopt;
}

std::optional<ip::Ipv6Prefix> ipv6_prefix(std::string_view text) noexcept {
  const auto parsed = ip::parse_ip_prefix(text);
  if (!parsed || parsed->network.family != ip::AddressFamily::ipv6)
    return std::nullopt;
  packet::Ipv6 network{};
  std::ranges::copy(parsed->network.bytes, network.begin());
  return ip::Ipv6Prefix{.network = ip::mask(network, parsed->length),
                        .length = parsed->length};
}

bool boolean(const cli_detail::ParsedCommand &command, bool &value) noexcept {
  const auto text = argument_at(command, TokenKind::boolean);
  if (!text)
    return false;
  if (*text == "true") {
    value = true;
    return true;
  }
  if (*text == "false") {
    value = false;
    return true;
  }
  return false;
}

Server *server_by_name(RouterConfiguration &configuration,
                       std::string_view name) noexcept {
  const auto found =
      std::ranges::find(configuration.servers, name, &Server::name);
  return found == configuration.servers.end() ? nullptr : &*found;
}

bool generate_duid_uuid(Server &server, EntropySource *entropy) noexcept {
  // RFC 6355 encodes DUID-UUID as type 4 followed by a 128-bit UUID. Setting
  // the RFC 4122 version and variant bits keeps the generated payload a valid
  // UUID while retaining 122 bits of platform entropy.
  if (!entropy)
    return false;
  server.duid.fill(0U);
  server.duid[0U] = 0U;
  server.duid[1U] = 4U;
  if (!entropy->fill(std::span<std::uint8_t>{server.duid}.subspan(2U, 16U)))
    return false;
  server.duid[8U] =
      static_cast<std::uint8_t>((server.duid[8U] & 0x0fU) | 0x40U);
  server.duid[10U] =
      static_cast<std::uint8_t>((server.duid[10U] & 0x3fU) | 0x80U);
  server.duid_octets = 18U;
  return true;
}

Server *ensure_server(RouterConfiguration &configuration,
                      std::string_view name, EntropySource *entropy) {
  if (auto *existing = server_by_name(configuration, name))
    return existing;
  if (name.empty() || name.size() > 32U ||
      configuration.servers.size() >=
          device_catalog::dhcpv6_servers_per_router)
    return nullptr;

  std::uint32_t instance_id{1U};
  while (std::ranges::any_of(
      configuration.servers, [instance_id](const Server &candidate) {
        return candidate.instance_id == instance_id;
      }))
    ++instance_id;

  Server staged{};
  staged.instance_id = instance_id;
  staged.name.assign(name);
  if (!generate_duid_uuid(staged, entropy))
    return nullptr;
  configuration.servers.push_back(std::move(staged));
  return &configuration.servers.back();
}

Pool *pool_by_name(Server &server, std::string_view name) noexcept {
  const auto found = std::ranges::find(server.pools, name, &Pool::name);
  return found == server.pools.end() ? nullptr : &*found;
}

Pool *ensure_pool(Server &server, std::string_view name) {
  if (auto *existing = pool_by_name(server, name))
    return existing;
  if (name.empty() || name.size() > 32U ||
      server.pools.size() >=
          device_catalog::dhcpv6_address_pools_per_server +
              device_catalog::dhcpv6_prefix_pools_per_server)
    return nullptr;
  Pool staged{};
  staged.name.assign(name);
  server.pools.push_back(std::move(staged));
  return &server.pools.back();
}

Prefix *prefix_by_key(Pool &pool, const ip::Ipv6Prefix &key) noexcept {
  const auto found =
      std::ranges::find(pool.prefixes, key, &Prefix::aggregate);
  return found == pool.prefixes.end() ? nullptr : &*found;
}

Prefix *ensure_prefix(Server &server, Pool &pool, const ip::Ipv6Prefix &key,
                      EntropySource *entropy) {
  if (auto *existing = prefix_by_key(pool, key))
    return existing;
  if (!entropy ||
      pool.prefixes.size() >=
          device_catalog::dhcpv6_address_pools_per_server +
              device_catalog::dhcpv6_prefix_pools_per_server)
    return nullptr;

  std::uint64_t scope{1U};
  const auto scope_exists = [&](std::uint64_t value) {
    return std::ranges::any_of(server.pools, [&](const Pool &candidate_pool) {
      return std::ranges::any_of(
          candidate_pool.prefixes, [&](const Prefix &candidate) {
            return candidate.allocation_scope_id == value;
          });
    });
  };
  while (scope_exists(scope))
    ++scope;

  Prefix staged{.allocation_scope_id = scope, .aggregate = key};
  if (!entropy->fill(staged.allocation_secret))
    return nullptr;
  pool.prefixes.push_back(std::move(staged));
  return &pool.prefixes.back();
}

bool deletes_server(CommandId id) noexcept {
  return id == CommandId::md_delete_dhcpv6_server ||
         id == CommandId::classic_dhcpv6_server_remove;
}

bool deletes_pool(CommandId id) noexcept {
  return id == CommandId::md_delete_dhcpv6_pool ||
         id == CommandId::classic_dhcpv6_pool_remove;
}

bool deletes_prefix(CommandId id) noexcept {
  return id == CommandId::md_delete_dhcpv6_prefix ||
         id == CommandId::classic_dhcpv6_prefix_remove;
}

std::string instance_path(std::string_view server, std::string_view pool = {},
                          std::string_view prefix = {}) {
  std::string result{"/router/Base/dhcp-server/dhcpv6/"};
  result.append(server);
  if (!pool.empty()) {
    result.append("/pool/");
    result.append(pool);
  }
  if (!prefix.empty()) {
    result.append("/prefix/");
    result.append(prefix);
  }
  return result;
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= md_dhcpv6_server_enable &&
         id <= md_delete_dhcpv6_prefix_rebind_time;
}

bool is_classic_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= classic_dhcpv6_server_shutdown &&
         id <= classic_dhcpv6_prefix_no_rebind_time;
}

EditResult edit(RouterConfiguration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine,
                EntropySource *entropy) {
  const auto id = command.spec ? command.spec->id : CommandId{};
  const bool recognized = engine == CliEngine::md ? is_md_command(id)
                                                  : is_classic_command(id);
  if (!recognized)
    return {};

  const auto server_name = argument_at(command, TokenKind::dhcp_server_name);
  const auto pool_name = argument_at(command, TokenKind::dhcp_pool_name);
  const auto prefix_text = argument_at(command, TokenKind::ipv6_prefix);
  const auto prefix_key =
      prefix_text ? ipv6_prefix(*prefix_text)
                  : std::optional<ip::Ipv6Prefix>{};
  if (!server_name || (pool_name && pool_name->empty()) ||
      (prefix_text && !prefix_key))
    return {.recognized = true};

  auto next = configuration;
  auto *server = server_by_name(next, *server_name);
  if (!server && !deletes_server(id))
    server = ensure_server(next, *server_name, entropy);
  if (!server)
    return {.recognized = true};

  auto *pool =
      pool_name ? pool_by_name(*server, *pool_name) : nullptr;
  if (pool_name && !pool && !deletes_pool(id))
    pool = ensure_pool(*server, *pool_name);
  if (pool_name && !pool)
    return {.recognized = true};

  auto *prefix =
      pool && prefix_key ? prefix_by_key(*pool, *prefix_key) : nullptr;
  if (pool && prefix_key && !prefix && !deletes_prefix(id))
    prefix = ensure_prefix(*server, *pool, *prefix_key, entropy);
  if (prefix_key && !prefix)
    return {.recognized = true};

  bool accepted = true;
  const auto set_lifetime = [&](TokenKind kind, std::uint32_t minimum,
                                std::uint32_t maximum,
                                std::uint32_t &target) {
    const auto text = argument_at(command, kind);
    const auto value =
        text ? decimal<std::uint32_t>(*text) : std::nullopt;
    if (!value || *value < minimum || *value > maximum)
      return false;
    target = *value;
    return true;
  };

  using enum CommandId;
  switch (id) {
  case md_dhcpv6_server_enable:
  case classic_dhcpv6_server_no_shutdown:
    server->admin_enabled = true;
    server->admin_state_configured = true;
    break;
  case md_dhcpv6_server_disable:
  case classic_dhcpv6_server_shutdown:
    server->admin_enabled = false;
    server->admin_state_configured = true;
    break;
  case md_dhcpv6_server_description:
  case classic_dhcpv6_server_description: {
    const auto value = argument_at(command, TokenKind::description);
    accepted = value && !value->empty() && value->size() <= 80U;
    if (accepted)
      server->description.assign(*value);
    break;
  }
  case md_delete_dhcpv6_server_description:
  case classic_dhcpv6_server_no_description:
    server->description.clear();
    break;
  case md_dhcpv6_server_ignore_rapid_commit: {
    bool ignored{};
    accepted = boolean(command, ignored);
    if (accepted)
      server->rapid_commit = !ignored;
    if (accepted)
      server->rapid_commit_configured = true;
    break;
  }
  case classic_dhcpv6_server_ignore_rapid_commit:
    server->rapid_commit = false;
    server->rapid_commit_configured = true;
    break;
  case md_delete_dhcpv6_server_ignore_rapid_commit:
  case classic_dhcpv6_server_no_ignore_rapid_commit:
    server->rapid_commit = true;
    server->rapid_commit_configured = false;
    break;
  case md_dhcpv6_server_lease_query:
    accepted = boolean(command, server->lease_query);
    if (accepted)
      server->lease_query_configured = true;
    break;
  case classic_dhcpv6_server_lease_query:
    server->lease_query = true;
    server->lease_query_configured = true;
    break;
  case md_delete_dhcpv6_server_lease_query:
  case classic_dhcpv6_server_no_lease_query:
    server->lease_query = false;
    server->lease_query_configured = false;
    break;
  case md_delete_dhcpv6_server:
  case classic_dhcpv6_server_remove:
    next.servers.erase(
        std::ranges::find(next.servers, *server_name, &Server::name));
    break;
  case md_dhcpv6_default_preferred_lifetime:
  case classic_dhcpv6_default_preferred_lifetime:
    accepted = set_lifetime(TokenKind::dhcpv6_lifetime_seconds, 300U,
                            315446399U,
                            server->default_preferred_lifetime_seconds);
    if (accepted)
      server->default_preferred_lifetime_configured = true;
    break;
  case md_dhcpv6_default_valid_lifetime:
  case classic_dhcpv6_default_valid_lifetime:
    accepted = set_lifetime(TokenKind::dhcpv6_lifetime_seconds, 300U,
                            315446399U,
                            server->default_valid_lifetime_seconds);
    if (accepted)
      server->default_valid_lifetime_configured = true;
    break;
  case md_dhcpv6_default_renew_time:
  case classic_dhcpv6_default_renew_time:
    accepted = set_lifetime(TokenKind::dhcpv6_timer_seconds, 0U, 604800U,
                            server->default_renewal_time_seconds);
    if (accepted)
      server->default_renewal_time_configured = true;
    break;
  case md_dhcpv6_default_rebind_time:
  case classic_dhcpv6_default_rebind_time:
    accepted = set_lifetime(TokenKind::dhcpv6_timer_seconds, 0U, 1209600U,
                            server->default_rebinding_time_seconds);
    if (accepted)
      server->default_rebinding_time_configured = true;
    break;
  case md_delete_dhcpv6_default_preferred_lifetime:
  case classic_dhcpv6_default_no_preferred_lifetime:
    server->default_preferred_lifetime_seconds = 3600U;
    server->default_preferred_lifetime_configured = false;
    break;
  case md_delete_dhcpv6_default_valid_lifetime:
  case classic_dhcpv6_default_no_valid_lifetime:
    server->default_valid_lifetime_seconds = 86400U;
    server->default_valid_lifetime_configured = false;
    break;
  case md_delete_dhcpv6_default_renew_time:
  case classic_dhcpv6_default_no_renew_time:
    server->default_renewal_time_seconds = 1800U;
    server->default_renewal_time_configured = false;
    break;
  case md_delete_dhcpv6_default_rebind_time:
  case classic_dhcpv6_default_no_rebind_time:
    server->default_rebinding_time_seconds = 2880U;
    server->default_rebinding_time_configured = false;
    break;
  case md_dhcpv6_pool_description:
  case classic_dhcpv6_pool_description: {
    const auto value = argument_at(command, TokenKind::description);
    accepted = pool && value && !value->empty() && value->size() <= 80U;
    if (accepted)
      pool->description.assign(*value);
    break;
  }
  case md_delete_dhcpv6_pool_description:
  case classic_dhcpv6_pool_no_description:
    accepted = pool != nullptr;
    if (accepted)
      pool->description.clear();
    break;
  case md_delete_dhcpv6_pool:
  case classic_dhcpv6_pool_remove: {
    const auto found =
        std::ranges::find(server->pools, *pool_name, &Pool::name);
    accepted = found != server->pools.end();
    if (accepted)
      server->pools.erase(found);
    break;
  }
  case md_dhcpv6_pool_delegated_length:
  case classic_dhcpv6_pool_delegated_length: {
    const auto text =
        argument_at(command, TokenKind::dhcpv6_delegated_length);
    const auto value =
        text ? decimal<std::uint8_t>(*text) : std::nullopt;
    accepted = pool && value && *value >= 48U && *value <= 127U;
    if (accepted)
      pool->delegated_length = *value;
    if (accepted)
      pool->delegated_length_configured = true;
    break;
  }
  case md_dhcpv6_pool_delegated_minimum: {
    const auto text =
        argument_at(command, TokenKind::dhcpv6_delegated_length);
    const auto value =
        text ? decimal<std::uint8_t>(*text) : std::nullopt;
    accepted = pool && value && *value >= 48U && *value <= 127U;
    if (accepted)
      pool->minimum_delegated_length = *value;
    if (accepted)
      pool->minimum_delegated_length_configured = true;
    break;
  }
  case md_dhcpv6_pool_delegated_maximum: {
    const auto text =
        argument_at(command, TokenKind::dhcpv6_delegated_length);
    const auto value =
        text ? decimal<std::uint8_t>(*text) : std::nullopt;
    accepted = pool && value && *value >= 48U && *value <= 127U;
    if (accepted)
      pool->maximum_delegated_length = *value;
    if (accepted)
      pool->maximum_delegated_length_configured = true;
    break;
  }
  case classic_dhcpv6_pool_delegated_range: {
    const auto length_text =
        argument_at(command, TokenKind::dhcpv6_delegated_length, 0U);
    const auto minimum_text =
        argument_at(command, TokenKind::dhcpv6_delegated_length, 1U);
    const auto maximum_text =
        argument_at(command, TokenKind::dhcpv6_delegated_length, 2U);
    const auto length =
        length_text ? decimal<std::uint8_t>(*length_text) : std::nullopt;
    const auto minimum =
        minimum_text ? decimal<std::uint8_t>(*minimum_text) : std::nullopt;
    const auto maximum =
        maximum_text ? decimal<std::uint8_t>(*maximum_text) : std::nullopt;
    accepted = pool && length && minimum && maximum &&
               *minimum >= 48U && *maximum <= 127U &&
               *minimum <= *length && *length <= *maximum;
    if (accepted) {
      pool->delegated_length = *length;
      pool->minimum_delegated_length = *minimum;
      pool->maximum_delegated_length = *maximum;
      pool->delegated_length_configured = true;
      pool->minimum_delegated_length_configured = true;
      pool->maximum_delegated_length_configured = true;
    }
    break;
  }
  case md_delete_dhcpv6_pool_delegated_length:
    pool->delegated_length = 64U;
    pool->delegated_length_configured = false;
    break;
  case md_delete_dhcpv6_pool_delegated_minimum:
    pool->minimum_delegated_length = 48U;
    pool->minimum_delegated_length_configured = false;
    break;
  case md_delete_dhcpv6_pool_delegated_maximum:
    pool->maximum_delegated_length = 64U;
    pool->maximum_delegated_length_configured = false;
    break;
  case classic_dhcpv6_pool_no_delegated_length:
    pool->delegated_length = 64U;
    pool->minimum_delegated_length = 48U;
    pool->maximum_delegated_length = 64U;
    pool->delegated_length_configured = false;
    pool->minimum_delegated_length_configured = false;
    pool->maximum_delegated_length_configured = false;
    break;
  case classic_dhcpv6_prefix_default:
  case classic_dhcpv6_prefix_both:
    prefix->delegated_prefix = true;
    prefix->wan_host = true;
    prefix->delegated_prefix_configured =
        id == classic_dhcpv6_prefix_both;
    prefix->wan_host_configured = id == classic_dhcpv6_prefix_both;
    break;
  case classic_dhcpv6_prefix_pd:
    prefix->delegated_prefix = true;
    prefix->wan_host = false;
    prefix->delegated_prefix_configured = true;
    prefix->wan_host_configured = true;
    break;
  case classic_dhcpv6_prefix_wan_host:
    prefix->delegated_prefix = false;
    prefix->wan_host = true;
    prefix->delegated_prefix_configured = true;
    prefix->wan_host_configured = true;
    break;
  case md_dhcpv6_prefix_pd:
    accepted = prefix && boolean(command, prefix->delegated_prefix);
    if (accepted)
      prefix->delegated_prefix_configured = true;
    break;
  case md_dhcpv6_prefix_wan_host:
    accepted = prefix && boolean(command, prefix->wan_host);
    if (accepted)
      prefix->wan_host_configured = true;
    break;
  case md_dhcpv6_prefix_drain:
    accepted = prefix && boolean(command, prefix->drain);
    if (accepted)
      prefix->drain_configured = true;
    break;
  case classic_dhcpv6_prefix_drain:
    prefix->drain = true;
    prefix->drain_configured = true;
    break;
  case md_delete_dhcpv6_prefix_drain:
  case classic_dhcpv6_prefix_no_drain:
    prefix->drain = false;
    prefix->drain_configured = false;
    break;
  case md_delete_dhcpv6_prefix_pd:
    prefix->delegated_prefix = true;
    prefix->delegated_prefix_configured = false;
    break;
  case md_delete_dhcpv6_prefix_wan_host:
    prefix->wan_host = true;
    prefix->wan_host_configured = false;
    break;
  case md_delete_dhcpv6_prefix:
  case classic_dhcpv6_prefix_remove: {
    const auto found =
        std::ranges::find(pool->prefixes, *prefix_key, &Prefix::aggregate);
    accepted = found != pool->prefixes.end();
    if (accepted)
      pool->prefixes.erase(found);
    break;
  }
  case md_dhcpv6_prefix_preferred_lifetime:
  case classic_dhcpv6_prefix_preferred_lifetime:
    accepted = prefix &&
               set_lifetime(TokenKind::dhcpv6_lifetime_seconds, 300U,
                            315446399U,
                            prefix->preferred_lifetime_seconds);
    if (accepted)
      prefix->preferred_lifetime_configured = true;
    break;
  case md_dhcpv6_prefix_valid_lifetime:
  case classic_dhcpv6_prefix_valid_lifetime:
    accepted = prefix &&
               set_lifetime(TokenKind::dhcpv6_lifetime_seconds, 300U,
                            315446399U, prefix->valid_lifetime_seconds);
    if (accepted)
      prefix->valid_lifetime_configured = true;
    break;
  case md_dhcpv6_prefix_renew_time:
  case classic_dhcpv6_prefix_renew_time:
    accepted = prefix &&
               set_lifetime(TokenKind::dhcpv6_timer_seconds, 0U, 604800U,
                            prefix->renewal_time_seconds);
    if (accepted)
      prefix->renewal_time_configured = true;
    break;
  case md_dhcpv6_prefix_rebind_time:
  case classic_dhcpv6_prefix_rebind_time:
    accepted = prefix &&
               set_lifetime(TokenKind::dhcpv6_timer_seconds, 0U, 1209600U,
                            prefix->rebinding_time_seconds);
    if (accepted)
      prefix->rebinding_time_configured = true;
    break;
  case md_delete_dhcpv6_prefix_preferred_lifetime:
  case classic_dhcpv6_prefix_no_preferred_lifetime:
    prefix->preferred_lifetime_configured = false;
    prefix->preferred_lifetime_seconds = 0U;
    break;
  case md_delete_dhcpv6_prefix_valid_lifetime:
  case classic_dhcpv6_prefix_no_valid_lifetime:
    prefix->valid_lifetime_configured = false;
    prefix->valid_lifetime_seconds = 0U;
    break;
  case md_delete_dhcpv6_prefix_renew_time:
  case classic_dhcpv6_prefix_no_renew_time:
    prefix->renewal_time_configured = false;
    prefix->renewal_time_seconds = 0U;
    break;
  case md_delete_dhcpv6_prefix_rebind_time:
  case classic_dhcpv6_prefix_no_rebind_time:
    prefix->rebinding_time_configured = false;
    prefix->rebinding_time_seconds = 0U;
    break;
  default:
    return {.recognized = true};
  }

  if (!accepted ||
      dhcpv6::configuration::validate(next, true) !=
          dhcpv6::configuration::Status::valid)
    return {.recognized = true};
  const bool changed = next != configuration;
  if (changed)
    configuration = std::move(next);
  return {.recognized = true,
          .valid = true,
          .changed = changed,
          .instance = instance_path(
              *server_name, pool_name ? *pool_name : std::string_view{},
              prefix_text ? *prefix_text : std::string_view{})};
}

} // namespace router::lab::dhcpv6_cli
