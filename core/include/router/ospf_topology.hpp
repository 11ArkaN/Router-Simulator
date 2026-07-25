// Translation from one area LSDB into the indexed graph consumed by OSPF SPF.
// The translator owns reusable vectors but no LSDB. It derives vertices,
// reciprocal arcs and forwarding first-hop tokens only from encoded LSAs.

#pragma once

#include "router/ospf_lsdb.hpp"
#include "router/ospf_spf.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ospf {

enum class TopologyVertexKind : std::uint8_t {
  router,
  transit_network
};

struct TopologyVertexKey {
  TopologyVertexKind kind{TopologyVertexKind::router};
  std::uint32_t id{};
  std::uint32_t advertising_router{};

  [[nodiscard]] friend bool
  operator==(const TopologyVertexKey &,
             const TopologyVertexKey &) noexcept = default;
};

struct FirstHop {
  std::uint32_t neighbor_router_id{};
  // OSPFv2 obtains the forwarding address from the neighbor's reciprocal
  // Router-LSA link_data. OSPFv3 leaves this zero because the scoped
  // link-local address is learned from the neighbor's Link-LSA.
  std::uint32_t version_two_next_hop{};
  // OSPFv3 identifies the neighbor's Link-LSA with this Interface ID. OSPFv2
  // leaves it zero because its Router-LSA already carries the IPv4 next hop.
  std::uint32_t neighbor_interface{};
  // OSPFv2 retains the root's local address as an interface resolver token.
  // OSPFv3 stores the numeric Interface ID. Keeping this separate from the
  // neighbor address prevents a shared-address-family shortcut.
  std::uint32_t local_interface{};

  [[nodiscard]] friend bool operator==(const FirstHop &,
                                       const FirstHop &) noexcept = default;
};

struct TopologyGraphView {
  std::span<const TopologyVertexKey> keys{};
  std::span<const SpfVertex> vertices{};
  std::span<const SpfEdge> edges{};
  std::span<const FirstHop> first_hops{};
  std::uint32_t root_vertex{};
};

class TopologyBuilder final {
public:
  TopologyBuilder(std::size_t maximum_vertices, std::size_t maximum_edges);

  // false preserves the previous published graph. Capacity values come from
  // the active protocol resource profile and malformed or non-reciprocal LSAs
  // never create an invented reachability arc.
  [[nodiscard]] bool build(std::span<const LsaRecord> records,
                           std::uint8_t version,
                           std::uint32_t root_router_id) noexcept;

  [[nodiscard]] TopologyGraphView graph() const noexcept;

private:
  struct TemporaryEdge;

  std::vector<TopologyVertexKey> keys_;
  std::vector<SpfVertex> vertices_;
  std::vector<SpfEdge> edges_;
  std::vector<FirstHop> first_hops_;
  std::size_t maximum_vertices_{};
  std::size_t maximum_edges_{};
  std::uint32_t root_vertex_{};
};

} // namespace router::ospf
