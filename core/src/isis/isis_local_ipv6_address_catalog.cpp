// Address assignment gates select local IPv6 reachability and owned LSP232
// units. The instance control writer mutates readiness only; configured address
// candidates remain immutable until cold generation replacement.
#include "router/isis_local_ipv6_address_catalog.hpp"
#include "router/generated_device_catalog.hpp"
#include <algorithm>
#include <tuple>
namespace router::isis {
namespace {
auto key(const LocalIpv6Address &value) noexcept { return std::tie(value.interface_id, value.address); }
bool valid_source(const LocalIpv6Address &value) noexcept {
  return value.interface_id && value.prefix_length <= 128U &&
      (!value.physical_port || *value.physical_port < device_catalog::maximum_ports_per_router) &&
      !ip::is_unspecified(value.address) && !ip::is_multicast(value.address);
}
std::array<std::uint8_t, 18U> metadata(const ip::Ipv6 &address) noexcept {
  std::array<std::uint8_t, 18U> value{232U, 16U};
  std::copy(address.begin(), address.end(), value.begin() + 2U);
  return value;
}
}
std::optional<LocalIpv6AddressCatalog> prepare_local_ipv6_address_catalog(
    std::span<const LocalIpv6Address> sources, std::size_t maximum_addresses) {
  if (sources.size() > maximum_addresses) return {};
  LocalIpv6AddressCatalog result;
  result.units.reserve(sources.size());
  for (const auto &source : sources) {
    if (!valid_source(source)) return {};
    result.units.push_back({source, metadata(source.address)});
  }
  std::sort(result.units.begin(), result.units.end(), [](const auto &a, const auto &b) {
    return key(a.source) < key(b.source);
  });
  if (!valid_local_ipv6_address_catalog(result)) return {};
  return result;
}
bool valid_local_ipv6_address_catalog(const LocalIpv6AddressCatalog &catalog) noexcept {
  if (catalog.version != 1U) return false;
  for (std::size_t index{}; index < catalog.units.size(); ++index) {
    const auto &unit = catalog.units[index];
    if (!valid_source(unit.source) || unit.metadata != metadata(unit.source.address) ||
        (index && key(catalog.units[index - 1U].source) >= key(unit.source))) return false;
  }
  return true;
}
bool valid_local_ipv6_address_catalog(const LocalIpv6AddressCatalog &catalog,
    const LocalPrefixCatalogProgram &prefixes) noexcept {
  if (!valid_local_ipv6_address_catalog(catalog) || !valid_local_prefix_catalog(prefixes)) return false;
  for (const auto &unit : catalog.units) {
    const auto &source = unit.source;
    const auto found = std::lower_bound(prefixes.interfaces.begin(), prefixes.interfaces.end(), source.interface_id,
        [](const auto &candidate, auto id) { return candidate.interface_id < id; });
    if (found == prefixes.interfaces.end() || found->interface_id != source.interface_id ||
        found->physical_port != source.physical_port) return false;
  }
  for (const auto &unit : prefixes.units) if (unit.prefix.network.family == ip::AddressFamily::ipv6)
    for (const auto owner : unit.owners) {
      const bool candidate = std::any_of(catalog.units.begin(), catalog.units.end(), [&](const auto &address) {
        const auto &source = address.source;
        return source.interface_id == owner && !ip::is_link_local(source.address) &&
            source.prefix_length == unit.prefix.length &&
            ip::mask(ip::IpAddress{ip::AddressFamily::ipv6, source.address}, source.prefix_length) == unit.prefix.network;
      });
      if (!candidate) return false;
    }
  return true;
}
bool set_local_ipv6_address_ready(LocalIpv6AddressCatalog &catalog, std::uint64_t interface_id,
    std::uint16_t port, const ip::Ipv6 &address, bool preferred) noexcept {
  const auto found = std::lower_bound(catalog.units.begin(), catalog.units.end(),
      std::tie(interface_id, address), [](const auto &unit, const auto &selected) {
        return key(unit.source) < selected;
      });
  if (found == catalog.units.end() || found->source.interface_id != interface_id ||
      found->source.address != address || found->source.physical_port != port ||
      found->source.preferred == preferred) return false;
  found->source.preferred = preferred;
  return true;
}
bool clear_local_ipv6_port(LocalIpv6AddressCatalog &catalog, std::uint16_t port) noexcept {
  bool changed{};
  for (auto &unit : catalog.units) if (unit.source.physical_port == port && unit.source.preferred) {
    unit.source.preferred = false; changed = true;
  }
  return changed;
}
bool local_ipv6_prefix_available(const LocalIpv6AddressCatalog &catalog, std::uint64_t interface_id,
    const ip::IpPrefix &prefix) noexcept {
  if (prefix.network.family != ip::AddressFamily::ipv6) return false;
  return std::any_of(catalog.units.begin(), catalog.units.end(), [&](const auto &unit) {
    const auto &source = unit.source;
    return source.interface_id == interface_id && source.preferred &&
        !ip::is_link_local(source.address) && source.prefix_length == prefix.length &&
        ip::mask(ip::IpAddress{ip::AddressFamily::ipv6, source.address}, source.prefix_length) == prefix.network;
  });
}
bool local_ipv6_link_local_available(const LocalIpv6AddressCatalog &catalog, std::uint64_t interface_id) noexcept {
  return std::any_of(catalog.units.begin(), catalog.units.end(), [&](const auto &unit) {
    return unit.source.interface_id == interface_id && unit.source.preferred && ip::is_link_local(unit.source.address);
  });
}
bool local_ipv6_hello_available(const LocalIpv6AddressCatalog &catalog, std::uint64_t interface_id,
    std::span<const packet::Ipv6> candidates) noexcept {
  return !candidates.empty() && std::all_of(candidates.begin(), candidates.end(), [&](const auto &address) {
    return ip::is_link_local(address) && std::any_of(catalog.units.begin(), catalog.units.end(), [&](const auto &unit) {
      return unit.source.interface_id == interface_id && unit.source.address == address && unit.source.preferred;
    });
  });
}
bool append_local_af_prefixes(OriginFragmentWorkspace &workspace, const LocalPrefixCatalogProgram &prefixes,
    const LocalIpv6AddressCatalog &addresses, std::size_t level, bool all_possible) noexcept {
  const auto available = [](const void *context, std::uint64_t id, const ip::IpPrefix &prefix) noexcept {
    return prefix.network.family == ip::AddressFamily::ipv4 ||
        local_ipv6_prefix_available(*static_cast<const LocalIpv6AddressCatalog *>(context), id, prefix);
  };
  return append_local_prefix_catalog(workspace, prefixes, level, all_possible, {&addresses, available});
}
bool append_local_ipv6_addresses(OriginFragmentWorkspace &workspace, const LocalIpv6AddressCatalog &catalog,
    const LocalPrefixCatalogProgram &prefixes, bool all_possible) noexcept {
  const auto active = [&](const auto &unit) {
    const auto &source = unit.source;
    if (ip::is_link_local(source.address)) return false;
    const auto interface = std::lower_bound(prefixes.interfaces.begin(), prefixes.interfaces.end(), source.interface_id,
        [](const auto &candidate, auto id) { return candidate.interface_id < id; });
    return interface != prefixes.interfaces.end() && interface->interface_id == source.interface_id &&
        (all_possible || (source.preferred && interface->available));
  };
  for (std::size_t index{}; index < catalog.units.size(); ++index) {
    const auto &unit = catalog.units[index];
    if (!active(unit)) continue;
    bool duplicate{};
    for (std::size_t previous{}; previous < index && !duplicate; ++previous)
      duplicate = catalog.units[previous].source.address == unit.source.address && active(catalog.units[previous]);
    if (!duplicate && !workspace.add_options({4U, index + 1U}, unit.metadata, {}, false)) return false;
  }
  return true;
}
}
