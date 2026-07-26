// Topology tests prove that Dijkstra consumes reciprocal Router-LSAs from one
// LSDB and that removing the reverse description removes reachability.

#include "router/ospf_topology.hpp"

#include "router/ospf_lsdb.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::array<std::uint8_t, 36U>
router_lsa(std::uint32_t router, std::uint32_t neighbor,
           std::uint32_t local_address, std::uint16_t cost) {
  std::array<std::uint8_t, 36U> bytes{};
  write16(bytes, 0U, 1U);
  bytes[3U] = 1U;
  write32(bytes, 4U, router);
  write32(bytes, 8U, router);
  write32(bytes, 12U, 0x80000001U);
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  write16(bytes, 22U, 1U);
  write32(bytes, 24U, neighbor);
  write32(bytes, 28U, local_address);
  bytes[32U] = 1U;
  write16(bytes, 34U, cost);
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("topology LSA checksum failed");
  return bytes;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_topology_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::now();
  LinkStateDatabase database{4U};
  const auto first = router_lsa(0x01010101U, 0x02020202U, 0x0a000001U, 10U);
  const auto second = router_lsa(0x02020202U, 0x01010101U, 0x0a000002U, 10U);
  require(database.install(first, router::packet::ospf::version_two, now,
                           0x01010101U, false) == InstallResult::installed &&
              database.install(second, router::packet::ospf::version_two, now,
                               0x01010101U, true) ==
                  InstallResult::installed,
          "reciprocal Router-LSAs did not enter test LSDB");

  TopologyBuilder builder{8U, 16U};
  require(builder.build(database.records(), router::packet::ospf::version_two,
                        0x01010101U),
          "reciprocal LSDB did not build an SPF graph");
  const auto graph = builder.graph();
  SpfCalculator spf{8U, 32U};
  require(graph.keys.size() == 2U && graph.first_hops.size() == 1U &&
              graph.first_hops[0].version_two_next_hop == 0x0a000002U &&
              graph.first_hops[0].local_interface == 0x0a000001U &&
              spf.calculate(graph.root_vertex, graph.vertices, graph.edges,
                            static_cast<std::uint16_t>(
                                graph.first_hops.size())) &&
              spf.cost(1U) == 10U && spf.first_hop_count(1U) == 1U,
          "SPF did not derive cost and first hop from reciprocal LSAs");

  LinkStateDatabase one_way{2U};
  require(one_way.install(first, router::packet::ospf::version_two, now,
                          0x01010101U, false) == InstallResult::installed &&
              builder.build(one_way.records(),
                            router::packet::ospf::version_two, 0x01010101U),
          "one-way LSDB could not build its local vertex");
  const auto one_way_graph = builder.graph();
  require(one_way_graph.edges.empty(),
          "one-way Router-LSA invented bidirectional reachability");
}
