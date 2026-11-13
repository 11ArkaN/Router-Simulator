// Cold canonical policy selects every possible local prefix before publication.
// The configuration owner supplies source and binding storage. Generic catalog
// consumers retain owned semantic bytes and never depend on this compiler.
#include "router/isis_local_prefix_catalog_program.hpp"
#include <algorithm>
#include <array>
namespace router::isis {
namespace {
bool eligible(const InstanceIntent &intent, const InterfaceIntent &attached,
    const LocalPrefixSource &source, std::size_t level) noexcept {
  const auto resolved = resolve_interface(intent, attached);
  return resolved.admin_enabled && resolved.level[level].enabled &&
      (!intent.advertise_passive_only.value_or(configuration_profile::advertise_passive_only_default) ||
       source.inherently_passive || resolved.level[level].passive);
}
}
LocalPrefixCatalogResult prepare_local_prefix_catalog(const InstanceIntent &intent,
    std::span<const LocalPrefixSource> sources, std::span<const LocalPrefixInterface> bindings,
    std::array<std::size_t, 2U> maximum_prefixes) {
  using Status = LocalPrefixCatalogStatus;
  const auto fail = [](Status status) { return LocalPrefixCatalogResult{status, {}}; };
  if (bindings.size() != sources.size())
    return fail(Status::invalid_context);
  // A down port must not hide invalid content or a future capacity overflow.
  // The complete cold superset is compiled first, then availability gates it.
  std::vector<LocalPrefixSource> complete(sources.begin(), sources.end());
  for (std::size_t index{}; index < bindings.size(); ++index) {
    if (!bindings[index].interface_id || bindings[index].available != sources[index].available)
      return fail(Status::invalid_context);
    complete[index].available = true;
  }
  const auto selected = prepare_local_prefix_program(intent, complete, maximum_prefixes);
  switch (selected.status) {
  case LocalPrefixProgramStatus::prepared: break;
  case LocalPrefixProgramStatus::inactive: return fail(Status::inactive);
  case LocalPrefixProgramStatus::conflicting_prefix: return fail(Status::conflicting_prefix);
  case LocalPrefixProgramStatus::capacity: return fail(Status::capacity);
  case LocalPrefixProgramStatus::unsupported_topology: return fail(Status::unsupported_topology);
  case LocalPrefixProgramStatus::invalid_context: return fail(Status::invalid_context);
  }
  LocalPrefixCatalogProgram program;
  program.interfaces.assign(bindings.begin(), bindings.end());
  std::sort(program.interfaces.begin(), program.interfaces.end(),
      [](const auto &a, const auto &b) { return a.interface_id < b.interface_id; });
  for (std::size_t level{}; level < selected.levels.size(); ++level)
    for (auto prefix : selected.levels[level]) {
      const bool wide = resolve_instance_level(intent, level).wide_metrics_only;
      if (wide || prefix.prefix.network.family == ip::AddressFamily::ipv6) prefix.narrow.reset();
      else if (!prefix.narrow) {
        if (prefix.metric > 63U) return fail(Status::unresolved_narrow_metric);
        prefix.narrow = static_cast<std::uint8_t>(prefix.metric);
      }
      std::array<std::uint8_t, 514U> bytes{};
      packet::isis::TlvWriter writer(bytes);
      if (!encode_root_prefix(writer, prefix)) return fail(Status::invalid_context);
      LocalPrefixCatalogUnit unit{static_cast<std::uint8_t>(level), prefix.prefix,
          {writer.bytes().begin(), writer.bytes().end()}, {}};
      for (std::size_t index{}; index < sources.size(); ++index) {
        const auto attached = std::find_if(intent.interfaces.begin(), intent.interfaces.end(),
            [&](const auto &entry) { return entry.name == sources[index].interface_name; });
        if (attached == intent.interfaces.end() || !eligible(intent, *attached, sources[index], level)) continue;
        if (std::any_of(sources[index].levels[level].begin(), sources[index].levels[level].end(),
            [&](const auto &value) { return value.prefix == prefix.prefix; }))
          unit.owners.push_back(bindings[index].interface_id);
      }
      std::sort(unit.owners.begin(), unit.owners.end());
      program.units.push_back(std::move(unit));
    }
  if (!valid_local_prefix_catalog(program)) return fail(Status::invalid_context);
  return {Status::prepared, std::move(program)};
}
LocalIpPrefixCatalogResult prepare_local_ip_prefix_catalog(const InstanceIntent &intent,
    std::span<const LocalIpPrefixSource> input, std::array<std::size_t, 2U> maximum_prefixes) {
  using Status = LocalPrefixCatalogStatus;
  const auto fail = [](Status status) { return LocalIpPrefixCatalogResult{status, {}, {}, {}}; };
  std::vector<std::array<std::vector<RootPrefix>, 2U>> storage(input.size());
  std::vector<LocalPrefixSource> sources; sources.reserve(input.size());
  std::vector<LocalPrefixInterface> bindings; bindings.reserve(input.size());
  LocalIpPrefixCatalogResult result;
  for (std::size_t index{}; index < input.size(); ++index) {
    const auto &source = input[index];
    for (auto &level : storage[index]) level.reserve(source.addresses.size());
    for (const auto &address : source.addresses) {
      const auto family = address.address.family;
      if ((family != ip::AddressFamily::ipv4 && family != ip::AddressFamily::ipv6) ||
          address.prefix_length > ip::address_bits(family)) return fail(Status::invalid_context);
      const bool ipv6 = family == ip::AddressFamily::ipv6;
      if (!ipv6 && std::any_of(address.address.bytes.begin() + 4U, address.address.bytes.end(),
          [](auto byte) { return byte != 0U; })) return fail(Status::invalid_context);
      if (ipv6 && ip::is_link_local(address.address.bytes)) continue;
      const ip::IpPrefix prefix{ip::mask(address.address, address.prefix_length), address.prefix_length};
      for (std::size_t level{}; level < 2U; ++level)
        storage[index][level].push_back({prefix, address.metrics[level], {}});
      if (ipv6) result.ipv6_addresses.push_back(address.address.bytes);
      else {
        packet::Ipv4 value; std::copy_n(address.address.bytes.begin(), value.size(), value.begin());
        result.ipv4_addresses.push_back(value);
      }
    }
    sources.push_back({source.interface_name, {storage[index][0U], storage[index][1U]},
        source.binding.available, !source.binding.physical_port});
    bindings.push_back(source.binding);
  }
  auto prepared = prepare_local_prefix_catalog(intent, sources, bindings, maximum_prefixes);
  if (prepared.status != Status::prepared) return fail(prepared.status);
  const auto unique = [](auto &addresses) {
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
  };
  unique(result.ipv4_addresses); unique(result.ipv6_addresses);
  result.status = Status::prepared; result.program = std::move(prepared.program);
  return result;
}
LocalIpv4PrefixCatalogResult prepare_local_ipv4_prefix_catalog(const InstanceIntent &intent,
    std::span<const LocalIpv4PrefixSource> input, std::array<std::size_t, 2U> maximum_prefixes) {
  using Status = LocalPrefixCatalogStatus;
  const auto fail = [](Status status) { return LocalIpv4PrefixCatalogResult{status, {}, {}}; };
  std::vector<LocalIpPrefixAddress> storage(input.size());
  std::vector<LocalIpPrefixSource> sources; sources.reserve(input.size());
  for (std::size_t index{}; index < input.size(); ++index) {
    const auto &source = input[index];
    const auto attached = std::find_if(intent.interfaces.begin(), intent.interfaces.end(),
        [&](const auto &entry) { return entry.name == source.interface_name; });
    if (attached == intent.interfaces.end() || !source.address_configured || source.prefix_length > 32U ||
        source.system == source.binding.physical_port.has_value() || (source.system && source.prefix_length != 32U))
      return fail(Status::invalid_context);
    storage[index].address.bytes[0U] = static_cast<std::uint8_t>(source.address >> 24U);
    storage[index].address.bytes[1U] = static_cast<std::uint8_t>(source.address >> 16U);
    storage[index].address.bytes[2U] = static_cast<std::uint8_t>(source.address >> 8U);
    storage[index].address.bytes[3U] = static_cast<std::uint8_t>(source.address);
    storage[index].prefix_length = source.prefix_length;
    const auto resolved = resolve_interface(intent, *attached);
    for (std::size_t level{}; level < 2U; ++level) {
      if (source.system && resolved.level[level].enabled &&
          (attached->level[level].metric || intent.level[level].default_metric))
        return fail(Status::unresolved_system_metric);
      storage[index].metrics[level] = source.system ? 0U : resolved.level[level].metric;
    }
    sources.push_back({source.interface_name, source.binding, std::span{&storage[index], 1U}});
  }
  auto prepared = prepare_local_ip_prefix_catalog(intent, sources, maximum_prefixes);
  if (prepared.status != Status::prepared) return fail(prepared.status);
  return {Status::prepared, std::move(prepared.program), std::move(prepared.ipv4_addresses)};
}
}
