// OSPF route calculation over one owner-local LSDB and its published SPF tree.
// This module maps topology vertices and prefix-bearing LSAs into complete
// route candidates. It never reads editor topology, another router, RIB or FIB.

#pragma once

#include "router/ip_address.hpp"
#include "router/multi_device_routing.hpp"
#include "router/ospf_spf.hpp"
#include "router/ospf_topology.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace router::ospf {

struct CalculatedNextHop {
  FirstHop topology{};
  // OSPFv3 resolves the neighbor's scoped link-local address from its Link-LSA.
  // OSPFv2 leaves this zero and uses topology.version_two_next_hop.
  ip::Ipv6 version_three_link_local{};
};

struct CalculatedRoute {
  ip::Ipv6 version_three_network{};
  std::vector<CalculatedNextHop> next_hops;
  // Repair next hops satisfy the RFC 5286 loop-free inequality but are not
  // members of the equal-cost primary set. RIB publication labels them so the
  // forwarding owner can activate them only after primary egress failure.
  std::vector<CalculatedNextHop> loop_free_alternates;
  std::uint32_t version_two_network{};
  std::uint32_t metric{};
  std::uint32_t internal_metric{};
  std::uint32_t advertising_router{};
  std::uint32_t area_id{};
  std::uint32_t tag{};
  lab::routing::OspfPathType path_type{
      lab::routing::OspfPathType::intra_area};
  std::uint8_t prefix_length{};
  bool version_three{};
  bool ipv4_address_family{};
  // The LSDB vertex that resolves this destination. It remains internal to
  // route calculation and gives the LFA pass a real graph destination for
  // intra-area, inter-area and external routes.
  std::uint32_t topology_vertex{std::numeric_limits<std::uint32_t>::max()};
};

class RouteCalculator final {
public:
  RouteCalculator(std::size_t maximum_routes,
                  std::size_t maximum_equal_cost_next_hops);

  // recalculate publishes only a complete generation. False leaves the last
  // successful route set visible and reports malformed LSAs, missing required
  // topology references or capacity exhaustion to the instance owner.
  [[nodiscard]] bool
  recalculate(std::span<const LsaRecord> records, std::uint8_t version,
              std::uint32_t area_id, bool ipv4_address_family,
              const TopologyGraphView &graph,
              const SpfCalculator &spf,
              bool calculate_loop_free_alternates = false) noexcept;

  [[nodiscard]] std::span<const CalculatedRoute> routes() const noexcept {
    return published_;
  }

private:
  std::vector<CalculatedRoute> published_;
  std::size_t maximum_routes_{};
  std::size_t maximum_equal_cost_next_hops_{};
};

} // namespace router::ospf
