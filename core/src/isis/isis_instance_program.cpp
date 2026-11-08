// Canonical values become detached update, origin and route policy programs.
// The router configuration owner supplies bounded local-only input projections.
#include "router/isis_instance_program.hpp"
#include <algorithm>
namespace router::isis {
InstanceProgramResult prepare_instance_program(const InstanceIntent &intent,
    const InstanceProgramContext &context) {
  namespace defaults = configuration_profile;
  using Status = InstanceProgramStatus;
  const auto fail = [](Status status) { return InstanceProgramResult{status, {}}; };
  if (!intent.admin_enabled.value_or(defaults::instance_admin_enabled_default)) return fail(Status::inactive);
  if (intent.instance) return fail(Status::unsupported_instance);
  if (intent.ipv6_routing == ConfiguredIpv6Routing::multi_topology) return fail(Status::unsupported_topology);
  const auto local = resolve_configured_system_id(intent, context.identity);
  if (!local) return fail(Status::unresolved_identity);
  if (!context.maximum_areas || context.maximum_areas > defaults::area_addresses_maximum ||
      intent.areas.size() > context.maximum_areas || !context.maximum_circuits ||
      context.resource_retry.count() <= 0 ||
      context.minimum_generation_interval.count() <= 0) return fail(Status::invalid_context);
  UpdateInstanceProgram program;
  program.local = *local; program.maximum_areas = context.maximum_areas;
  program.maximum_circuits = context.maximum_circuits; program.transmission = context.transmission;
  program.origination.emplace();
  auto &origin = *program.origination;
  origin.resource_retry = context.resource_retry; origin.content.random = context.random;
  origin.neighbors.emplace(); origin.broadcast_neighbors.emplace();
  const bool ipv4 = intent.ipv4_routing.value_or(defaults::ipv4_routing_default);
  const bool ipv6 = intent.ipv6_routing.value_or(ConfiguredIpv6Routing::disabled) == ConfiguredIpv6Routing::native;
  const auto lifetime = intent.lsp_lifetime_seconds.value_or(defaults::lsp_lifetime_seconds_default);
  const auto mtu = intent.lsp_mtu_octets.value_or(defaults::lsp_mtu_octets_default);
  const auto mask = static_cast<std::uint8_t>(intent.levels.value_or(ConfiguredLevels::both));
  for (std::size_t level{}; level < 2U; ++level) {
    const auto resolved = resolve_instance_level(intent, level);
    if (!resolved.enabled) continue;
    if (resolved.lsp_mtu_octets != mtu) return fail(Status::unresolved_mtu);
    if (!context.fragments[level] || context.fragments[level] > context.levels[level].database.records ||
        context.transmission.maximum_pdu_octets < mtu || context.levels[level].receive_pdu_octets < mtu)
      return fail(Status::capacity);
    program.levels[level] = context.levels[level];
    program.levels[level]->maximum_age = lifetime;
    origin.content.levels[level] = LocalLspLevelProgram{lifetime, mtu,
        context.minimum_generation_interval, std::chrono::microseconds{std::chrono::seconds{lifetime}} / 2};
    std::vector<RootPrefix> prefixes;
    for (const auto &prefix : context.prefixes[level]) {
      const bool v6 = prefix.prefix.network.family == ip::AddressFamily::ipv6;
      if ((v6 && !ipv6) || (!v6 && !ipv4)) continue;
      auto selected = prefix;
      if (resolved.wide_metrics_only || v6) selected.narrow.reset();
      else if (!selected.narrow) {
        if (selected.metric > 63U) return fail(Status::unresolved_narrow_metric);
        selected.narrow = static_cast<std::uint8_t>(selected.metric);
      }
      prefixes.push_back(selected);
    }
    RootContentInput root;
    root.local = *local; root.level = static_cast<std::uint8_t>(level); root.flags = mask == 1U ? 1U : 3U;
    root.ipv4 = ipv4; root.ipv6 = ipv6; root.areas = intent.areas; root.hostname = context.hostname;
    if (ipv4) root.ipv4_addresses = context.ipv4_addresses;
    if (ipv6) root.ipv6_addresses = context.ipv6_addresses;
    root.prefixes = prefixes;
    auto content = prepare_root_content(root, mtu - packet::isis::lsp_header_octets, context.fragments[level]);
    if (content.status != RootContentStatus::prepared)
      return fail(content.status == RootContentStatus::capacity ? Status::capacity : Status::invalid_content);
    for (auto &record : content.records) origin.content.records.push_back(std::move(record));
    for (std::size_t family{}; family < program.routing.size(); ++family) {
      if ((family ? !ipv6 : !ipv4) || !context.routing[family]) continue;
      if (!program.routing[family]) program.routing[family] = context.routing[family];
      auto &preference = program.routing[family]->preferences[level];
      if (resolved.preference) preference.internal = *resolved.preference;
      if (resolved.external_preference) preference.external = *resolved.external_preference;
    }
  }
  for (std::size_t index{}; index < context.interfaces.size(); ++index) {
    const auto &binding = context.interfaces[index];
    if (!binding.interface_id || std::any_of(context.interfaces.begin(), context.interfaces.begin() + index,
        [&](const auto &other) { return binding.interface_id == other.interface_id || binding.name == other.name; }))
      return fail(Status::invalid_context);
    const auto attached = std::find_if(intent.interfaces.begin(), intent.interfaces.end(),
        [&](const auto &entry) { return entry.name == binding.name; });
    if (attached == intent.interfaces.end()) return fail(Status::invalid_context);
    const auto resolved = resolve_interface(intent, *attached, binding.default_type);
    if (!resolved.admin_enabled || !binding.operational || binding.loopback) continue;
    if (!resolved.type) return fail(Status::unresolved_media);
    std::array<std::optional<P2pOriginMetric>, 2U> metrics;
    for (std::size_t level{}; level < metrics.size(); ++level) {
      if (!resolved.level[level].enabled || resolved.level[level].passive) continue;
      const auto metric = resolved.level[level].metric;
      std::optional<std::uint8_t> narrow;
      if (!resolve_instance_level(intent, level).wide_metrics_only) {
        if (metric > 63U) return fail(Status::unresolved_narrow_metric);
        narrow = static_cast<std::uint8_t>(metric);
      }
      metrics[level] = P2pOriginMetric{metric, narrow};
    }
    if (!metrics[0U] && !metrics[1U]) continue;
    // The circuit budget counts live transport bindings, not configured
    // passive, loopback or inactive interface entries retained in the datastore.
    if (origin.neighbors->size() + origin.broadcast_neighbors->size() == context.maximum_circuits)
      return fail(Status::capacity);
    if (*resolved.type == ConfiguredInterfaceType::point_to_point)
      origin.neighbors->push_back({binding.interface_id, metrics});
    else {
      if (!binding.circuit || !binding.maximum_neighbors) return fail(Status::invalid_context);
      origin.broadcast_neighbors->push_back({binding.interface_id, binding.circuit, binding.maximum_neighbors, metrics});
    }
  }
  // Admission uses sorted local keys and never discovers topology here.
  const auto ordered = [](const auto &a, const auto &b) { return a.interface_id < b.interface_id; };
  std::sort(origin.neighbors->begin(), origin.neighbors->end(), ordered);
  std::sort(origin.broadcast_neighbors->begin(), origin.broadcast_neighbors->end(), ordered);
  return {Status::prepared, std::move(program)};
}
}
