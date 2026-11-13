// Canonical administrative and passive policy filters local AF projections.
// The caller owns source storage and publication; this module borrows only
// within one cold transaction and cannot observe another router.
#include "router/isis_local_prefix_program.hpp"
#include <algorithm>
#include <tuple>
namespace router::isis {
namespace {
auto key(const RootPrefix &value) noexcept {
  return std::tie(value.prefix.network.family, value.prefix.network.bytes, value.prefix.length);
}
bool identical(const RootPrefix &left, const RootPrefix &right) noexcept {
  return left.metric == right.metric && left.narrow == right.narrow &&
      left.external_ipv6 == right.external_ipv6 &&
      std::equal(left.attributes.begin(), left.attributes.end(), right.attributes.begin(), right.attributes.end());
}
}
LocalPrefixProgramResult prepare_local_prefix_program(const InstanceIntent &intent,
    std::span<const LocalPrefixSource> sources, std::array<std::size_t, 2U> maximum_prefixes) {
  using Status = LocalPrefixProgramStatus;
  const auto fail = [](Status status) { return LocalPrefixProgramResult{status, {}}; };
  if (!intent.admin_enabled.value_or(configuration_profile::instance_admin_enabled_default)) return fail(Status::inactive);
  if (intent.ipv6_routing == ConfiguredIpv6Routing::multi_topology) return fail(Status::unsupported_topology);
  if (sources.size() != intent.interfaces.size() || !maximum_prefixes[0U] || !maximum_prefixes[1U])
    return fail(Status::invalid_context);
  const bool passive_only = intent.advertise_passive_only.value_or(configuration_profile::advertise_passive_only_default);
  const bool ipv4 = intent.ipv4_routing.value_or(configuration_profile::ipv4_routing_default);
  const bool ipv6 = intent.ipv6_routing == ConfiguredIpv6Routing::native;
  LocalPrefixProgramResult result{Status::prepared, {}};
  // One bounded cold allocation per level. Identical duplicates do not spend
  // another output slot, so admission counts distinct advertised prefixes.
  for (std::size_t level{}; level < 2U; ++level) {
    std::size_t capacity{};
    for (const auto &source : sources)
      capacity += std::min(source.levels[level].size(), maximum_prefixes[level] - capacity);
    result.levels[level].reserve(capacity);
  }
  for (std::size_t ordinal{}; ordinal < sources.size(); ++ordinal) {
    const auto &source = sources[ordinal];
    if (std::any_of(sources.begin(), sources.begin() + ordinal,
        [&](const auto &prior) { return prior.interface_name == source.interface_name; })) return fail(Status::invalid_context);
    const auto attached = std::find_if(intent.interfaces.begin(), intent.interfaces.end(),
        [&](const auto &entry) { return entry.name == source.interface_name; });
    if (attached == intent.interfaces.end()) return fail(Status::invalid_context);
    const auto resolved = resolve_interface(intent, *attached);
    if (!source.available || !resolved.admin_enabled) continue;
    for (std::size_t level{}; level < 2U; ++level) {
      if (!resolved.level[level].enabled ||
          (passive_only && !source.inherently_passive && !resolved.level[level].passive)) continue;
      auto &output = result.levels[level];
      for (const auto &prefix : source.levels[level]) {
        const auto family = prefix.prefix.network.family;
        if (family != ip::AddressFamily::ipv4 && family != ip::AddressFamily::ipv6) return fail(Status::invalid_context);
        if ((family == ip::AddressFamily::ipv4 && !ipv4) || (family == ip::AddressFamily::ipv6 && !ipv6)) continue;
        if (prefix.prefix.length > ip::address_bits(family) ||
            ip::mask(prefix.prefix.network, prefix.prefix.length) != prefix.prefix.network ||
            (family == ip::AddressFamily::ipv6 && ip::is_link_local(prefix.prefix.network.bytes)))
          return fail(Status::invalid_context);
        const auto position = std::lower_bound(output.begin(), output.end(), prefix,
            [](const auto &left, const auto &right) { return key(left) < key(right); });
        if (position != output.end() && key(*position) == key(prefix)) {
          if (!identical(*position, prefix)) return fail(Status::conflicting_prefix);
          continue;
        }
        if (output.size() == maximum_prefixes[level]) return fail(Status::capacity);
        output.insert(position, prefix);
      }
    }
  }
  return result;
}
}
