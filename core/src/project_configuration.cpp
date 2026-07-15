// Atomic project parser and data-plane projection. This module has no mailbox,
// thread, capture, checkpoint or UI dependency.

#include "router/project_configuration.hpp"

#include "router/generated_runtime_protocol.hpp"
#include "router/routing.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

namespace router::project {
namespace {

std::optional<packet::Ipv4> parse_ipv4(std::string_view text) {
  // Parse directly into the packet representation. This avoids temporary
  // strings, locale-sensitive conversion and platform socket dependencies.
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
  // Exactly two hexadecimal digits per octet keep project input canonical and
  // prevent native and browser builds from accepting different shorthand.
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
  // Host and link messages predate arbitrary user text and have a fixed field
  // count. Their compact delimiter format remains safe because those fields
  // contain only validated numeric addresses and identifiers.
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

std::optional<std::vector<std::string_view>>
netstrings(std::string_view command, std::string_view prefix,
           std::size_t maximum_fields) {
  // Running configuration contains names and descriptions that may include
  // any delimiter. Byte lengths preserve those values across UTF-8 Wasm input
  // without escaping or teaching the browser CLI grammar.
  if (!command.starts_with(prefix))
    return std::nullopt;
  command.remove_prefix(prefix.size());
  std::vector<std::string_view> result;
  result.reserve(1U + profile::port_count * 4U + profile::endpoint_count * 4U);
  while (!command.empty()) {
    // A bounded field count prevents a stream of zero-length netstrings from
    // causing unbounded vector growth before structural validation.
    if (result.size() == maximum_fields)
      return std::nullopt;
    const auto colon = command.find(':');
    if (colon == std::string_view::npos)
      return std::nullopt;
    std::size_t length{};
    const auto length_text = command.substr(0, colon);
    const auto parsed = std::from_chars(
        length_text.data(), length_text.data() + length_text.size(), length);
    if (length_text.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != length_text.data() + length_text.size())
      return std::nullopt;
    command.remove_prefix(colon + 1U);
    if (length > command.size())
      return std::nullopt;
    result.push_back(command.substr(0, length));
    command.remove_prefix(length);
    // The canonical netstring grammar is [len]:[string], including the comma
    // for an empty string. Requiring it keeps concatenated fields synchronized
    // and makes the C++ decoder match the browser encoder byte for byte.
    if (command.empty() || command.front() != ',')
      return std::nullopt;
    command.remove_prefix(1U);
  }
  return result;
}

template <typename Integer>
std::optional<Integer> integer(std::string_view text) {
  // from_chars is allocation-free and rejects trailing data. Callers add the
  // semantic range required by the particular configuration leaf.
  Integer value{};
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (text.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != text.data() + text.size())
    return std::nullopt;
  return value;
}

template <std::size_t Size>
bool copy_text(std::array<char, Size> &destination, std::string_view value) {
  // Fixed storage is part of the shared device ABI. Reject truncation instead
  // of silently producing a system name or description the user did not set.
  if (value.size() >= destination.size())
    return false;
  destination.fill('\0');
  std::memcpy(destination.data(), value.data(), value.size());
  return true;
}

} // namespace

ParseResult parse_hosts(const ProjectState &current,
                        const std::string &command) {
  // Work on a complete copy. The caller publishes it only after both endpoints
  // pass validation, so an address swap has no transient duplicate state.
  constexpr auto count = ProjectState::endpoint_count;
  const auto values = fields<1 + count * 3>(command);
  constexpr std::string_view operation = runtime_protocol::project_hosts;
  const auto operation_name = operation.substr(0, operation.size() - 1U);
  if (!values || (*values)[0] != operation_name) {
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
    // Pairwise comparison is bounded by the profile endpoint count and avoids
    // allocating a set for a two-endpoint transaction.
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
  // Both link directions are parsed before publishing. A malformed second
  // delay therefore cannot leave only one side changed.
  constexpr auto count = ProjectState::endpoint_count;
  const auto values = fields<1 + count>(command);
  constexpr std::string_view operation = runtime_protocol::project_links;
  const auto operation_name = operation.substr(0, operation.size() - 1U);
  if (!values || (*values)[0] != operation_name) {
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

RunningParseResult parse_running(const DeviceConfiguration &current,
                                 const std::string &command) {
  constexpr std::string_view prefix = runtime_protocol::project_running;
  // Four scalar counts and headers surround bounded port, interface and route
  // arrays. The parser never needs to accept more fields than this capacity.
  const auto maximum_fields = 4U + current.ports.size() * 4U +
                              current.interfaces.size() * 2U +
                              current.static_routes.size() * 2U;
  const auto values = netstrings(command, prefix, maximum_fields);
  if (!values)
    return {.error = "ERROR: invalid atomic running configuration"};
  std::size_t cursor{};
  // The cursor owns the only traversal state. Each field is consumed exactly
  // once, and the final equality check rejects hidden trailing values.
  const auto take = [&]() -> std::optional<std::string_view> {
    if (cursor == values->size())
      return std::nullopt;
    return (*values)[cursor++];
  };

  DeviceConfiguration next = current;
  // Copying the bounded configuration first preserves provisioning and other
  // device-owned leaves that are outside the portable project transaction.
  const auto system_name = take();
  const auto port_count_text = take();
  const auto port_count =
      port_count_text ? integer<std::size_t>(*port_count_text) : std::nullopt;
  if (!system_name || !port_count || *port_count != profile::port_count ||
      !copy_text(next.system_name, *system_name))
    return {.error = "ERROR: invalid running system or port configuration"};

  for (std::size_t index = 0; index < *port_count; ++index) {
    // Port order and identifiers must match the hardware profile. The project
    // can change leaves, but it cannot invent inventory through this API.
    const auto id = take();
    const auto admin = take();
    const auto mtu_text = take();
    const auto description = take();
    const auto mtu = mtu_text ? integer<unsigned>(*mtu_text) : std::nullopt;
    if (!id || !admin || !mtu || !description ||
        *id != profile::port_ids[index] ||
        (*admin != "up" && *admin != "down") ||
        *mtu < profile::minimum_port_mtu || *mtu > profile::maximum_port_mtu ||
        !copy_text(next.ports[index].description, *description)) {
      return {.error = "ERROR: invalid running port configuration"};
    }
    next.ports[index].admin_enabled = *admin == "up";
    next.ports[index].mtu = static_cast<std::uint16_t>(*mtu);
  }

  const auto interface_count_text = take();
  const auto interface_count = interface_count_text
                                   ? integer<std::size_t>(*interface_count_text)
                                   : std::nullopt;
  if (!interface_count || *interface_count != next.interface_count)
    return {.error = "ERROR: invalid running interface configuration"};
  // Interfaces are profile-backed in this milestone. Restore only their
  // mutable administrative state and reject renamed or reordered entries.
  for (std::size_t index = 0; index < *interface_count; ++index) {
    const auto name = take();
    const auto admin = take();
    if (!name || !admin || *name != next.interfaces[index].name ||
        (*admin != "up" && *admin != "down")) {
      return {.error = "ERROR: invalid running interface configuration"};
    }
    next.interfaces[index].admin_enabled = *admin == "up";
  }

  const auto route_count_text = take();
  const auto route_count =
      route_count_text ? integer<std::size_t>(*route_count_text) : std::nullopt;
  if (!route_count || *route_count > next.static_routes.size())
    return {.error = "ERROR: invalid running route configuration"};
  // Clear the fixed route table in the local copy so routes omitted from the
  // imported project cannot survive from the previous running datastore.
  next.static_routes = {};
  for (std::size_t index = 0; index < *route_count; ++index) {
    const auto route_prefix = take();
    const auto next_hop_text = take();
    if (!route_prefix || !next_hop_text)
      return {.error = "ERROR: invalid running route configuration"};
    const auto slash = route_prefix->find('/');
    const auto network = slash == std::string_view::npos
                             ? std::nullopt
                             : parse_ipv4(route_prefix->substr(0, slash));
    const auto prefix_length =
        slash == std::string_view::npos
            ? std::nullopt
            : integer<unsigned>(route_prefix->substr(slash + 1U));
    const auto next_hop = parse_ipv4(*next_hop_text);
    if (!network || !prefix_length || *prefix_length > 32 || !next_hop)
      return {.error = "ERROR: invalid running route configuration"};
    const auto network_value = routing::ipv4((*network)[0], (*network)[1],
                                             (*network)[2], (*network)[3]);
    const auto mask =
        routing::prefix_mask(static_cast<std::uint8_t>(*prefix_length));
    // Static route prefixes are stored canonically. Host bits in the network
    // field would make show output and route matching disagree.
    if ((network_value & mask) != network_value)
      return {.error = "ERROR: invalid running route configuration"};
    next.static_routes[index] = {
        .valid = true,
        .network = network_value,
        .next_hop = routing::ipv4((*next_hop)[0], (*next_hop)[1],
                                  (*next_hop)[2], (*next_hop)[3]),
        .prefix_length = static_cast<std::uint8_t>(*prefix_length)};
  }
  if (cursor != values->size())
    return {.error = "ERROR: excess running configuration fields"};
  // Returning the complete value transfers no ownership. Runtime control is
  // the only component allowed to publish it as running configuration.
  return {.success = true, .configuration = next, .error = {}};
}

NetworkConfiguration
network_configuration(const DeviceConfiguration &running,
                      const ProjectState &project) noexcept {
  // This is a pure projection from control state into a forwarding job. It
  // does not mutate interfaces, links or the forwarding owner directly.
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
    // A physical link becomes usable by IP forwarding only when a configured
    // router interface owns its port. Administrative and hardware state are
    // applied later by their respective owners.
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
