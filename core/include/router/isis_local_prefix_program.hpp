// The local configuration owner selects prefix projections before LSP admission.
// This cold module reads canonical intent and local AF values only. It owns no
// interface, peer, route, protocol timer or shared mutable state.
#pragma once
#include "router/isis_configuration_resolution.hpp"
#include "router/isis_root_content.hpp"
namespace router::isis {
struct LocalPrefixSource {
  std::string_view interface_name;
  // AF ownership already resolved address validity, availability and metrics.
  // A source without an eligible local address supplies empty spans. A local
  // loopback owner may explicitly identify an inherently passive source.
  std::array<std::span<const RootPrefix>, 2U> levels;
  bool available{}, inherently_passive{};
};
enum class LocalPrefixProgramStatus : std::uint8_t {
  prepared, inactive, invalid_context, conflicting_prefix, capacity, unsupported_topology
};
struct LocalPrefixProgramResult {
  LocalPrefixProgramStatus status{LocalPrefixProgramStatus::invalid_context};
  std::array<std::vector<RootPrefix>, 2U> levels;
};
// Preconditions: validated canonical intent, one distinct source per configured
// interface, and explicit per-level prefix budgets. Caller and callee stay on
// the serialized configuration shard. May allocate and throw. Result owns prefix
// values; attribute spans remain borrowed until prepare_instance_program copies
// their bytes. Input storage must outlive that composition, never publication.
// Applies enabled levels, interface administration, AF selection and the pinned
// passive-only policy. Metrics and availability remain AF-owner decisions.
// Success returns sorted unique prefixes. Identical duplicates coalesce;
// conflicting fixed fields refuse instead of inventing export precedence.
// Failure returns no partial result and changes no input. No clock or I/O.
[[nodiscard]] LocalPrefixProgramResult prepare_local_prefix_program(const InstanceIntent &,
    std::span<const LocalPrefixSource>, std::array<std::size_t, 2U> maximum_prefixes);
}
