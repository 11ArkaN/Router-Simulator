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
LocalIpv4PrefixCatalogResult prepare_local_ipv4_prefix_catalog(const InstanceIntent &intent,
    std::span<const LocalIpv4PrefixSource> input, std::array<std::size_t, 2U> maximum_prefixes) {
  using Status = LocalPrefixCatalogStatus;
  const auto fail = [](Status status) { return LocalIpv4PrefixCatalogResult{status, {}, {}}; };
  std::vector<std::array<RootPrefix, 2U>> storage(input.size());
  std::vector<LocalPrefixSource> sources; sources.reserve(input.size());
  std::vector<LocalPrefixInterface> bindings; bindings.reserve(input.size());
  std::vector<packet::Ipv4> addresses; addresses.reserve(input.size());
  for (std::size_t index{}; index < input.size(); ++index) {
    const auto &source = input[index];
    const auto attached = std::find_if(intent.interfaces.begin(), intent.interfaces.end(),
        [&](const auto &entry) { return entry.name == source.interface_name; });
    if (attached == intent.interfaces.end() || !source.address_configured || source.prefix_length > 32U ||
        source.system == source.binding.physical_port.has_value() || (source.system && source.prefix_length != 32U))
      return fail(Status::invalid_context);
    const packet::Ipv4 address{static_cast<std::uint8_t>(source.address >> 24U),
        static_cast<std::uint8_t>(source.address >> 16U), static_cast<std::uint8_t>(source.address >> 8U),
        static_cast<std::uint8_t>(source.address)};
    addresses.push_back(address);
    ip::IpAddress value; std::copy(address.begin(), address.end(), value.bytes.begin());
    const ip::IpPrefix prefix{ip::mask(value, source.prefix_length), source.prefix_length};
    const auto resolved = resolve_interface(intent, *attached);
    for (std::size_t level{}; level < 2U; ++level) {
      if (source.system && resolved.level[level].enabled &&
          (attached->level[level].metric || intent.level[level].default_metric))
        return fail(Status::unresolved_system_metric);
      storage[index][level] = {prefix, source.system ? 0U : resolved.level[level].metric, {}};
    }
    sources.push_back({source.interface_name, {std::span{&storage[index][0U], 1U},
        std::span{&storage[index][1U], 1U}}, source.binding.available, source.system});
    bindings.push_back(source.binding);
  }
  auto prepared = prepare_local_prefix_catalog(intent, sources, bindings, maximum_prefixes);
  if (prepared.status != Status::prepared) return fail(prepared.status);
  std::sort(addresses.begin(), addresses.end());
  addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
  return {Status::prepared, std::move(prepared.program), std::move(addresses)};
}
}
