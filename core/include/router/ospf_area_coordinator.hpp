// Owner-local OSPF ABR and NSSA coordination. The dedicated OSPF pthread is
// the sole caller and state owner. The module compares immutable per-area LSDB
// and SPF results, then returns semantic advertisements for each destination
// area. It never installs routes, edits another router or reads editor links.

#pragma once

#include "router/ospf_configuration.hpp"
#include "router/ospf_process.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ospf {

struct AreaCoordinationView {
  std::span<const CalculatedRoute> routes{};
  std::span<const LsaRecord> database{};
  std::span<const AreaRangeConfiguration> ranges{};
  std::uint32_t area_id{};
  std::uint32_t default_metric{1U};
  AreaType type{AreaType::normal};
  bool summaries{true};
  bool nssa_translate_always{};
};

struct AreaCoordinationResult {
  // Result index corresponds exactly to the input area index. A caller may
  // therefore reconcile each process without a map lookup or unstable pointer.
  std::vector<std::vector<CoordinatorAdvertisement>> advertisements;
  bool area_border_router{};
  bool autonomous_system_boundary_router{};
};

// All views must belong to one router, OSPF version and protocol instance.
// A missing backbone means the router is not an ABR and produces empty sets.
// Allocation failure or malformed source LSA returns nullopt without changing
// any process generation.
[[nodiscard]] std::optional<AreaCoordinationResult>
coordinate_areas(std::span<const AreaCoordinationView> areas,
                 std::uint32_t local_router_id, std::uint8_t version,
                 bool ipv4_address_family) noexcept;

} // namespace router::ospf
