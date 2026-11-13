// The serialized CLI owner renders immutable IS-IS operational projections.
// Local interface names remain caller-owned during formatting. This module
// reads accepted protocol values and never queries or mutates a live owner.
#pragma once
#include "router/isis_operational.hpp"
namespace router::lab::isis_cli {
struct InterfaceName { std::uint64_t identity{}; std::string_view name; };
// Valid version-one projection and distinct local interface bindings required.
// Returned text owns all storage. Missing names, invalid states or malformed
// accepted attributes refuse. Formatting may allocate on the CLI shard.
[[nodiscard]] std::optional<std::string> adjacency_table(const isis::AdjacencyQuery &,
    std::span<const InterfaceName>);
}
