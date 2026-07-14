// Atomic project parser and data-plane projection. This module has no mailbox,
// thread, capture, checkpoint or UI dependency.

#include "router/project_configuration.hpp"

#include "router/routing.hpp"

#include <algorithm>
#include <charconv>
#include <optional>
#include <string_view>

namespace router::project {
namespace {

std::optional<packet::Ipv4> parse_ipv4(std::string_view text) {
  packet::Ipv4 result{};
  for (std::size_t index = 0; index < result.size(); ++index) {
    const auto separator = text.find('.');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed =
        std::from_chars(token.data(), token.data() + token.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() ||
        value > 255) {
      return std::nullopt;
    }
    result[index] = static_cast<std::uint8_t>(value);
    if (index + 1 == result.size()) {
      if (separator != std::string_view::npos)
        return std::nullopt;
    } else {
      if (separator == std::string_view::npos)
        return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

std::optional<packet::Mac> parse_mac(std::string_view text) {
  packet::Mac result{};
  for (std::size_t index = 0; index < result.size(); ++index) {
    const auto separator = text.find(':');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed =
        std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (token.size() != 2 || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size() || value > 255)
      return std::nullopt;
    result[index] = static_cast<std::uint8_t>(value);
    if (index + 1 == result.size()) {
      if (separator != std::string_view::npos)
        return std::nullopt;
    } else {
      if (separator == std::string_view::npos)
        return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

template <std::size_t N>
std::optional<std::array<std::string_view, N>>
fields(const std::string &command) {
  std::array<std::string_view, N> result{};
  std::string_view remaining{command};
  for (auto &field : result) {
    const auto separator = remaining.find('|');
    field = remaining.substr(0, separator);
    if (separator == std::string_view::npos) {
      remaining = {};
    } else {
      remaining.remove_prefix(separator + 1);
    }
  }
  if (!remaining.empty())
    return std::nullopt;
  return result;
}

} // namespace

ParseResult parse_hosts(const ProjectState &current,
                        const std::string &command) {
  constexpr auto count = ProjectState::endpoint_count;
  const auto values = fields<1 + count * 3>(command);
  if (!values || (*values)[0] != "project:hosts") {
    return {.error = "ERROR: invalid atomic host configuration command"};
  }
  ProjectState next = current;
  const auto valid_unicast = [](const packet::Ipv4 &candidate) {
    return candidate != packet::Ipv4{} && candidate[0] != 0 &&
           candidate[0] != 127 && candidate[0] < 224;
  };
  for (std::size_t index = 0; index < count; ++index) {
    const auto base = 1U + index * 3U;
    const auto mac = parse_mac((*values)[base]);
    const auto slash = (*values)[base + 1].find('/');
    if (slash == std::string_view::npos) {
      return {.error = "ERROR: host address requires a prefix length"};
    }
    const auto address = parse_ipv4((*values)[base + 1].substr(0, slash));
    const auto gateway = parse_ipv4((*values)[base + 2]);
    unsigned prefix{};
    const auto prefix_text = (*values)[base + 1].substr(slash + 1);
    const auto prefix_result = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (!mac || !address || !gateway || prefix_result.ec != std::errc{} ||
        prefix_result.ptr != prefix_text.data() + prefix_text.size() ||
        prefix > 32) {
      return {.error =
                  "ERROR: invalid host MAC, IPv4 address, prefix, or gateway"};
    }
    const auto mask = routing::prefix_mask(static_cast<std::uint8_t>(prefix));
    const auto address_value = routing::ipv4((*address)[0], (*address)[1],
                                             (*address)[2], (*address)[3]);
    const auto gateway_value = routing::ipv4((*gateway)[0], (*gateway)[1],
                                             (*gateway)[2], (*gateway)[3]);
    const auto host_bits = ~mask;
    const auto address_host = address_value & host_bits;
    const auto gateway_host = gateway_value & host_bits;
    const auto invalid_mac = std::all_of(mac->begin(), mac->end(),
                                         [](auto byte) { return byte == 0; }) ||
                             ((*mac)[0] & 1U);
    // Sources: RFC 1122 host addressing and IEEE 802.3 individual MAC bit.
    // The exact JavaScript command is revalidated here because callers may
    // bypass TypeScript and invoke the Wasm ABI directly.
    if ((address_value & mask) != (gateway_value & mask) ||
        *address == *gateway || !valid_unicast(*address) ||
        !valid_unicast(*gateway) || invalid_mac ||
        (prefix <= 30 && (address_host == 0 || address_host == host_bits ||
                          gateway_host == 0 || gateway_host == host_bits)) ||
        std::find(profile::router_macs.begin(), profile::router_macs.end(),
                  *mac) != profile::router_macs.end() ||
        std::find(profile::router_addresses.begin(),
                  profile::router_addresses.end(),
                  *address) != profile::router_addresses.end()) {
      return {.error = "ERROR: invalid or conflicting host identity, prefix, "
                       "or gateway"};
    }
    next.hosts[index] = {*mac, *address, static_cast<std::uint8_t>(prefix),
                         *gateway};
  }
  for (std::size_t left = 0; left < count; ++left) {
    for (std::size_t right = left + 1; right < count; ++right) {
      if (next.hosts[left].mac == next.hosts[right].mac ||
          next.hosts[left].address == next.hosts[right].address) {
        return {.error = "ERROR: host endpoint identities must be unique"};
      }
    }
  }
  return {.success = true, .state = next, .error = {}};
}

ParseResult parse_links(const ProjectState &current,
                        const std::string &command) {
  constexpr auto count = ProjectState::endpoint_count;
  const auto values = fields<1 + count>(command);
  if (!values || (*values)[0] != "project:links") {
    return {.error = "ERROR: invalid atomic link configuration command"};
  }
  ProjectState next = current;
  for (std::size_t index = 0; index < count; ++index) {
    std::uint64_t delay{};
    const auto value = (*values)[index + 1];
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), delay);
    // ECMA Number.MAX_SAFE_INTEGER is the interchange limit. It is not a
    // physical circuit limit and preserves exact nanoseconds through JSON.
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size() ||
        delay > 9007199254740991ULL) {
      return {.error = "ERROR: link propagation must be an exact non-negative "
                       "integer in ns"};
    }
    next.links[index].propagation = std::chrono::nanoseconds(delay);
  }
  return {.success = true, .state = next, .error = {}};
}

NetworkConfiguration
network_configuration(const DeviceConfiguration &running,
                      const ProjectState &project) noexcept {
  NetworkConfiguration result;
  for (std::size_t endpoint = 0; endpoint < project.links.size(); ++endpoint) {
    const auto &link = project.links[endpoint];
    const auto interface =
        std::find_if(running.interfaces.begin(),
                     running.interfaces.begin() + running.interface_count,
                     [&link](const auto &item) {
                       return item.valid && item.port_index == link.router_port;
                     });
    const bool routed =
        interface != running.interfaces.begin() + running.interface_count;
    const auto &host = project.hosts[endpoint];
    result.endpoints[endpoint] = {
        .connected = link.connected && routed,
        .router_port = link.router_port,
        .endpoint_mac = host.mac,
        .endpoint_address = host.address,
        .endpoint_prefix_length = host.prefix_length,
        .endpoint_gateway = host.gateway,
        .router_mac = routed ? interface->mac : packet::Mac{},
        .router_address = routed ? interface->ipv4 : packet::Ipv4{},
        .propagation = link.propagation};
  }
  return result;
}

} // namespace router::project
