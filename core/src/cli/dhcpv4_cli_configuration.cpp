// SR OS 26.7.R1 DHCPv4 local-server CLI edits. List objects are selected by
// their operator-visible keys, never by vector position. A temporary model is
// validated before publication so malformed ranges cannot partially alter a
// running server or an MD candidate.

#include "dhcpv4_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <string_view>

namespace router::lab::dhcpv4_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;
using dhcpv4::configuration::AddressRange;
using dhcpv4::configuration::ExcludedRange;
using dhcpv4::configuration::FailoverControlType;
using dhcpv4::configuration::Pool;
using dhcpv4::configuration::RouterConfiguration;
using dhcpv4::configuration::Server;
using dhcpv4::configuration::Subnet;

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  // from_chars is locale independent and rejects suffixes. This matters for
  // time leaves because accepting `60s` where SR OS expects `60` would make
  // transcript behavior differ even if the internal duration were identical.
  Integer parsed{};
  const auto converted =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (text.empty() || converted.ec != std::errc{} ||
      converted.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::optional<std::string_view>
argument_at(const cli_detail::ParsedCommand &command, TokenKind kind,
            std::size_t occurrence = 0U) noexcept {
  // A DHCP range has two IPv4 operands. Walking the generated token metadata
  // keeps that ordering authoritative and avoids parsing command text twice.
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

std::optional<packet::Ipv4> ipv4(std::string_view text) noexcept {
  const auto parsed = ip::parse_ip_address(text);
  if (!parsed || parsed->family != ip::AddressFamily::ipv4)
    return std::nullopt;
  return packet::Ipv4{parsed->bytes[0U], parsed->bytes[1U],
                      parsed->bytes[2U], parsed->bytes[3U]};
}

struct Prefix {
  packet::Ipv4 network{};
  std::uint8_t length{};
};

std::optional<Prefix> ipv4_prefix(std::string_view text) noexcept {
  const auto parsed = ip::parse_ip_prefix(text);
  if (!parsed || parsed->network.family != ip::AddressFamily::ipv4)
    return std::nullopt;
  return Prefix{.network = {parsed->network.bytes[0U],
                            parsed->network.bytes[1U],
                            parsed->network.bytes[2U],
                            parsed->network.bytes[3U]},
                .length = parsed->length};
}

Server *server_by_name(RouterConfiguration &configuration,
                       std::string_view name) noexcept {
  const auto found = std::ranges::find(configuration.servers, name,
                                       &Server::name);
  return found == configuration.servers.end() ? nullptr : &*found;
}

Server *ensure_server(RouterConfiguration &configuration,
                      std::string_view name) {
  if (auto *existing = server_by_name(configuration, name))
    return existing;
  if (name.empty() ||
      name.size() > device_catalog::dhcpv4_server_name_bytes ||
      configuration.servers.size() >=
          device_catalog::dhcpv4_servers_per_router)
    return nullptr;
  std::uint32_t instance_id{1U};
  while (std::ranges::any_of(configuration.servers,
                             [instance_id](const Server &server) {
                               return server.instance_id == instance_id;
                             }))
    ++instance_id;
  // SR OS list creation does not imply `admin-state enable`. The generated
  // defaults therefore leave a newly addressed server administratively down.
  configuration.servers.push_back(
      {.instance_id = instance_id, .name = std::string{name}});
  return &configuration.servers.back();
}

Pool *pool_by_name(Server &server, std::string_view name) noexcept {
  const auto found = std::ranges::find(server.pools, name, &Pool::name);
  return found == server.pools.end() ? nullptr : &*found;
}

Pool *ensure_pool(Server &server, std::string_view name) {
  if (auto *existing = pool_by_name(server, name))
    return existing;
  if (name.empty() ||
      name.size() > device_catalog::dhcpv4_server_name_bytes ||
      server.pools.size() >= device_catalog::dhcpv4_pools_per_server)
    return nullptr;
  server.pools.push_back({.name = std::string{name}});
  return &server.pools.back();
}

Subnet *subnet_by_key(Pool &pool, const Prefix &key) noexcept {
  const auto found = std::find_if(
      pool.subnets.begin(), pool.subnets.end(), [&](const Subnet &subnet) {
        return subnet.network == key.network &&
               subnet.prefix_length == key.length;
      });
  return found == pool.subnets.end() ? nullptr : &*found;
}

Subnet *ensure_subnet(Server &server, Pool &pool, const Prefix &key) {
  if (auto *existing = subnet_by_key(pool, key))
    return existing;
  std::uint64_t scope_id{1U};
  const auto scope_exists = [&](std::uint64_t candidate) {
    return std::ranges::any_of(server.pools, [&](const Pool &candidate_pool) {
      return std::ranges::any_of(
          candidate_pool.subnets, [&](const Subnet &subnet) {
            return subnet.allocation_scope_id == candidate;
          });
    });
  };
  while (scope_exists(scope_id))
    ++scope_id;
  pool.subnets.push_back({.allocation_scope_id = scope_id,
                          .network = key.network,
                          .prefix_length = key.length});
  return &pool.subnets.back();
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

std::string instance_path(std::string_view server,
                          std::string_view pool = {},
                          std::string_view subnet = {}) {
  std::string result{"/router/Base/dhcp-server/dhcpv4/"};
  result.append(server);
  if (!pool.empty()) {
    result.append("/pool/");
    result.append(pool);
  }
  if (!subnet.empty()) {
    result.append("/subnet/");
    result.append(subnet);
  }
  return result;
}

bool erase_range(Subnet &subnet, packet::Ipv4 first, packet::Ipv4 last) {
  const auto found = std::find_if(
      subnet.address_ranges.begin(), subnet.address_ranges.end(),
      [&](const AddressRange &range) {
        return range.first == first && range.last == last;
      });
  if (found == subnet.address_ranges.end())
    return false;
  subnet.address_ranges.erase(found);
  return true;
}

bool erase_exclusion(Subnet &subnet, packet::Ipv4 first, packet::Ipv4 last) {
  const auto found = std::find_if(
      subnet.excluded_ranges.begin(), subnet.excluded_ranges.end(),
      [&](const ExcludedRange &range) {
        return range.first == first && range.last == last;
      });
  if (found == subnet.excluded_ranges.end())
    return false;
  subnet.excluded_ranges.erase(found);
  return true;
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= md_dhcpv4_server_enable &&
         id <= md_delete_dhcpv4_exclude_range;
}

bool is_classic_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= classic_dhcpv4_server_shutdown &&
         id <= classic_dhcpv4_exclude_range_no;
}

EditResult edit(RouterConfiguration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine) {
  const auto id = command.spec ? command.spec->id : CommandId{};
  const bool recognized = engine == CliEngine::md ? is_md_command(id)
                                                  : is_classic_command(id);
  if (!recognized)
    return {};

  const auto server_name = argument_at(command, TokenKind::dhcp_server_name);
  const auto pool_name = argument_at(command, TokenKind::dhcp_pool_name);
  const auto subnet_text = argument_at(command, TokenKind::ipv4_prefix);
  const auto subnet_key =
      subnet_text ? ipv4_prefix(*subnet_text) : std::optional<Prefix>{};
  if (!server_name || (pool_name && pool_name->empty()) ||
      (subnet_text && !subnet_key))
    return {.recognized = true};

  auto next = configuration;
  auto *server = ensure_server(next, *server_name);
  if (!server)
    return {.recognized = true};
  auto *pool = pool_name ? ensure_pool(*server, *pool_name) : nullptr;
  if (pool_name && !pool)
    return {.recognized = true};
  auto *subnet =
      pool && subnet_key
          ? ensure_subnet(*server, *pool, *subnet_key)
          : nullptr;
  if (subnet_key && !subnet)
    return {.recognized = true};

  bool accepted = true;
  using enum CommandId;
  switch (id) {
  case md_dhcpv4_server_enable:
  case classic_dhcpv4_server_no_shutdown:
    server->admin_enabled = true;
    break;
  case md_dhcpv4_server_disable:
  case classic_dhcpv4_server_shutdown:
    server->admin_enabled = false;
    break;
  case md_dhcpv4_server_description:
  case classic_dhcpv4_server_description: {
    const auto value = argument_at(command, TokenKind::description);
    accepted = value && value->size() <=
                            device_catalog::dhcpv4_description_bytes;
    if (accepted)
      server->description.assign(*value);
    break;
  }
  case md_delete_dhcpv4_server_description:
  case classic_dhcpv4_server_no_description:
    server->description.clear();
    break;
  case md_dhcpv4_server_force_renews:
    accepted = boolean(command, server->force_renews);
    break;
  case classic_dhcpv4_server_force_renews:
    server->force_renews = true;
    break;
  case md_delete_dhcpv4_server_force_renews:
  case classic_dhcpv4_server_no_force_renews:
    server->force_renews = false;
    break;
  case md_delete_dhcpv4_server:
  case classic_dhcpv4_server_remove:
    next.servers.erase(std::ranges::find(next.servers, *server_name,
                                         &Server::name));
    break;
  case md_dhcpv4_pool_description:
  case classic_dhcpv4_pool_description: {
    const auto value = argument_at(command, TokenKind::description);
    accepted = pool && value &&
               value->size() <= device_catalog::dhcpv4_description_bytes;
    if (accepted)
      pool->description.assign(*value);
    break;
  }
  case md_delete_dhcpv4_pool_description:
  case classic_dhcpv4_pool_no_description:
    accepted = pool != nullptr;
    if (accepted)
      pool->description.clear();
    break;
  case md_dhcpv4_pool_min_lease:
  case classic_dhcpv4_pool_min_lease: {
    const auto value = argument_at(command, TokenKind::dhcp_lease_seconds);
    const auto seconds =
        value ? decimal<std::uint32_t>(*value) : std::nullopt;
    accepted = pool && seconds;
    if (accepted)
      pool->minimum_lease_seconds = *seconds;
    break;
  }
  case md_dhcpv4_pool_max_lease:
  case classic_dhcpv4_pool_max_lease: {
    const auto value = argument_at(command, TokenKind::dhcp_lease_seconds);
    const auto seconds =
        value ? decimal<std::uint32_t>(*value) : std::nullopt;
    accepted = pool && seconds;
    if (accepted)
      pool->maximum_lease_seconds = *seconds;
    break;
  }
  case md_dhcpv4_pool_offer_time:
  case classic_dhcpv4_pool_offer_time: {
    const auto value = argument_at(command, TokenKind::dhcp_offer_seconds);
    const auto seconds =
        value ? decimal<std::uint32_t>(*value) : std::nullopt;
    accepted = pool && seconds;
    if (accepted)
      pool->offer_seconds = *seconds;
    break;
  }
  case md_delete_dhcpv4_pool_min_lease:
  case classic_dhcpv4_pool_no_min_lease:
    accepted = pool != nullptr;
    if (accepted)
      pool->minimum_lease_seconds =
          device_catalog::dhcpv4_minimum_lease_time_seconds;
    break;
  case md_delete_dhcpv4_pool_max_lease:
  case classic_dhcpv4_pool_no_max_lease:
    accepted = pool != nullptr;
    if (accepted)
      pool->maximum_lease_seconds =
          device_catalog::dhcpv4_maximum_lease_time_seconds;
    break;
  case md_delete_dhcpv4_pool_offer_time:
  case classic_dhcpv4_pool_no_offer_time:
    accepted = pool != nullptr;
    if (accepted)
      pool->offer_seconds = device_catalog::dhcpv4_offer_time_seconds;
    break;
  case md_dhcpv4_pool_nak:
    accepted = pool && boolean(command, pool->nak_non_matching_subnet);
    break;
  case classic_dhcpv4_pool_nak:
    accepted = pool != nullptr;
    if (accepted)
      pool->nak_non_matching_subnet = true;
    break;
  case md_delete_dhcpv4_pool_nak:
  case classic_dhcpv4_pool_no_nak:
    accepted = pool != nullptr;
    if (accepted)
      pool->nak_non_matching_subnet = false;
    break;
  case md_delete_dhcpv4_pool:
  case classic_dhcpv4_pool_remove: {
    const auto found = pool_name
                           ? std::ranges::find(server->pools, *pool_name,
                                               &Pool::name)
                           : server->pools.end();
    accepted = found != server->pools.end();
    if (accepted)
      server->pools.erase(found);
    break;
  }
  case md_dhcpv4_subnet_drain:
    accepted = subnet && boolean(command, subnet->drain);
    break;
  case classic_dhcpv4_subnet_drain:
    accepted = subnet != nullptr;
    if (accepted)
      subnet->drain = true;
    break;
  case md_delete_dhcpv4_subnet_drain:
  case classic_dhcpv4_subnet_no_drain:
    accepted = subnet != nullptr;
    if (accepted)
      subnet->drain = false;
    break;
  case md_dhcpv4_subnet_maximum_declined:
  case classic_dhcpv4_subnet_maximum_declined: {
    const auto value =
        argument_at(command, TokenKind::dhcp_maximum_declined);
    const auto maximum =
        value ? decimal<std::uint32_t>(*value) : std::nullopt;
    accepted = subnet && maximum;
    if (accepted)
      subnet->maximum_declined = *maximum;
    break;
  }
  case md_delete_dhcpv4_subnet_maximum_declined:
  case classic_dhcpv4_subnet_no_maximum_declined:
    accepted = subnet != nullptr;
    if (accepted)
      subnet->maximum_declined =
          device_catalog::dhcpv4_maximum_declined_default;
    break;
  case md_delete_dhcpv4_subnet:
  case classic_dhcpv4_subnet_remove: {
    accepted = pool && subnet_key;
    if (accepted) {
      const auto found = std::find_if(
          pool->subnets.begin(), pool->subnets.end(),
          [&](const Subnet &value) {
            return value.network == subnet_key->network &&
                   value.prefix_length == subnet_key->length;
          });
      accepted = found != pool->subnets.end();
      if (accepted)
        pool->subnets.erase(found);
    }
    break;
  }
  case md_dhcpv4_range_local:
  case md_dhcpv4_range_remote:
  case classic_dhcpv4_range_local:
  case classic_dhcpv4_range_remote: {
    const auto first_text = argument_at(command, TokenKind::ipv4, 0U);
    const auto last_text = argument_at(command, TokenKind::ipv4, 1U);
    const auto first = first_text ? ipv4(*first_text) : std::nullopt;
    const auto last = last_text ? ipv4(*last_text) : std::nullopt;
    accepted = subnet && first && last;
    if (accepted) {
      const auto existing = std::find_if(
          subnet->address_ranges.begin(), subnet->address_ranges.end(),
          [&](const AddressRange &range) {
            return range.first == *first && range.last == *last;
          });
      const auto control =
          id == md_dhcpv4_range_remote ||
                  id == classic_dhcpv4_range_remote
              ? FailoverControlType::remote
              : FailoverControlType::local;
      if (existing == subnet->address_ranges.end())
        subnet->address_ranges.push_back(
            {.first = *first, .last = *last, .failover_control = control});
      else
        existing->failover_control = control;
    }
    break;
  }
  case md_delete_dhcpv4_range:
  case classic_dhcpv4_range_no: {
    const auto first_text = argument_at(command, TokenKind::ipv4, 0U);
    const auto last_text = argument_at(command, TokenKind::ipv4, 1U);
    const auto first = first_text ? ipv4(*first_text) : std::nullopt;
    const auto last = last_text ? ipv4(*last_text) : std::nullopt;
    accepted = subnet && first && last &&
               erase_range(*subnet, *first, *last);
    break;
  }
  case md_dhcpv4_exclude_range:
  case classic_dhcpv4_exclude_range: {
    const auto first_text = argument_at(command, TokenKind::ipv4, 0U);
    const auto last_text = argument_at(command, TokenKind::ipv4, 1U);
    const auto first = first_text ? ipv4(*first_text) : std::nullopt;
    const auto last = last_text ? ipv4(*last_text) : std::nullopt;
    accepted = subnet && first && last;
    if (accepted) {
      const auto exists = std::ranges::any_of(
          subnet->excluded_ranges, [&](const ExcludedRange &range) {
            return range.first == *first && range.last == *last;
          });
      if (!exists)
        subnet->excluded_ranges.push_back(
            {.first = *first, .last = *last});
    }
    break;
  }
  case md_delete_dhcpv4_exclude_range:
  case classic_dhcpv4_exclude_range_no: {
    const auto first_text = argument_at(command, TokenKind::ipv4, 0U);
    const auto last_text = argument_at(command, TokenKind::ipv4, 1U);
    const auto first = first_text ? ipv4(*first_text) : std::nullopt;
    const auto last = last_text ? ipv4(*last_text) : std::nullopt;
    accepted = subnet && first && last &&
               erase_exclusion(*subnet, *first, *last);
    break;
  }
  default:
    return {.recognized = true};
  }

  if (!accepted ||
      dhcpv4::configuration::validate(next, true) !=
          dhcpv4::configuration::Status::valid)
    return {.recognized = true};
  const bool changed = next != configuration;
  if (changed)
    configuration = std::move(next);
  return {.recognized = true,
          .valid = true,
          .changed = changed,
          .instance = instance_path(
              *server_name, pool_name ? *pool_name : std::string_view{},
              subnet_text ? *subnet_text : std::string_view{})};
}

} // namespace router::lab::dhcpv4_cli
