// Route-calculation tests prove that a remote stub prefix uses the reciprocal
// neighbor address, accumulated SPF cost and advertised stub cost. No test
// topology object or direct peer state is available to the calculator.

#include "router/ospf_route_calculator.hpp"

#include "router/ospf_lsdb.hpp"

#include <algorithm>
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

std::array<std::uint8_t, 48U>
router_lsa(std::uint32_t router, std::uint32_t neighbor,
           std::uint32_t local_address, std::uint32_t stub_network,
           std::uint16_t link_cost, std::uint16_t stub_cost) {
  std::array<std::uint8_t, 48U> bytes{};
  write16(bytes, 0U, 1U);
  bytes[3U] = 1U;
  write32(bytes, 4U, router);
  write32(bytes, 8U, router);
  write32(bytes, 12U, 0x80000001U);
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  write16(bytes, 22U, 2U);
  write32(bytes, 24U, neighbor);
  write32(bytes, 28U, local_address);
  bytes[32U] = 1U;
  write16(bytes, 34U, link_cost);
  write32(bytes, 36U, stub_network);
  write32(bytes, 40U, 0xffffff00U);
  bytes[44U] = 3U;
  write16(bytes, 46U, stub_cost);
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("route fixture checksum failed");
  return bytes;
}

// Three-router LFA fixtures need two point-to-point adjacencies and one stub
// prefix in one Router-LSA. Keeping the bytes explicit exercises the production
// LSA parser and prevents the test from handing a synthetic graph to SPF.
std::array<std::uint8_t, 60U>
triangle_router_lsa(std::uint32_t router, std::uint32_t first_neighbor,
                    std::uint32_t first_local_address,
                    std::uint16_t first_cost,
                    std::uint32_t second_neighbor,
                    std::uint32_t second_local_address,
                    std::uint16_t second_cost,
                    std::uint32_t stub_network,
                    std::uint16_t stub_cost) {
  std::array<std::uint8_t, 60U> bytes{};
  write16(bytes, 0U, 1U);
  bytes[3U] = 1U;
  write32(bytes, 4U, router);
  write32(bytes, 8U, router);
  write32(bytes, 12U, 0x80000001U);
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  write16(bytes, 22U, 3U);
  const auto point_to_point = [&](std::size_t offset,
                                  std::uint32_t neighbor,
                                  std::uint32_t local_address,
                                  std::uint16_t cost) {
    write32(bytes, offset, neighbor);
    write32(bytes, offset + 4U, local_address);
    bytes[offset + 8U] = 1U;
    write16(bytes, offset + 10U, cost);
  };
  point_to_point(24U, first_neighbor, first_local_address, first_cost);
  point_to_point(36U, second_neighbor, second_local_address, second_cost);
  write32(bytes, 48U, stub_network);
  write32(bytes, 52U, 0xffffff00U);
  bytes[56U] = 3U;
  write16(bytes, 58U, stub_cost);
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("triangle LFA fixture checksum failed");
  return bytes;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_route_calculator_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::now();
  constexpr std::uint32_t root = 0x01010101U;
  constexpr std::uint32_t neighbor = 0x02020202U;
  LinkStateDatabase database{4U};
  const auto first =
      router_lsa(root, neighbor, 0x0a000001U, 0xc0000200U, 10U, 1U);
  const auto second =
      router_lsa(neighbor, root, 0x0a000002U, 0xc6336400U, 10U, 5U);
  require(database.install(first, router::packet::ospf::version_two, now,
                           root, false) == InstallResult::installed &&
              database.install(second,
                               router::packet::ospf::version_two, now,
                               root, true) == InstallResult::installed,
          "route fixture did not enter LSDB");

  TopologyBuilder topology{8U, 16U};
  require(topology.build(database.records(),
                         router::packet::ospf::version_two, root),
          "route fixture did not build topology");
  const auto graph = topology.graph();
  SpfCalculator spf{8U, 32U};
  require(spf.calculate(graph.root_vertex, graph.vertices, graph.edges,
                        static_cast<std::uint16_t>(
                            graph.first_hops.size())),
          "route fixture SPF failed");

  RouteCalculator calculator{16U, 4U};
  require(calculator.recalculate(
              database.records(), router::packet::ospf::version_two, 0U,
              false, graph, spf),
          "route generation rejected valid LSDB");
  const auto routes = calculator.routes();
  const auto remote =
      std::find_if(routes.begin(), routes.end(), [](const auto &route) {
        return route.version_two_network == 0xc6336400U &&
               route.prefix_length == 24U;
      });
  require(remote != routes.end() && remote->metric == 15U &&
              remote->path_type ==
                  router::lab::routing::OspfPathType::intra_area &&
              remote->next_hops.size() == 1U &&
              remote->next_hops[0].topology.version_two_next_hop ==
                  0x0a000002U &&
              remote->next_hops[0].topology.local_interface ==
                  0x0a000001U,
          "remote prefix did not use real SPF cost and reciprocal next hop");

  // R1 reaches the destination through R2. R3 has a strictly loop-free path
  // through R2 because D(R3,D)=15 is less than D(R3,R1)+D(R1,D)=35.
  // The repair must be derived from the three encoded Router-LSAs and remain
  // separate from the primary next-hop set.
  constexpr std::uint32_t alternate = 0x03030303U;
  LinkStateDatabase triangle_database{6U};
  const auto root_lsa = triangle_router_lsa(
      root, neighbor, 0x0a000001U, 10U, alternate, 0x0a000101U, 30U,
      0xcb007100U, 1U);
  const auto primary_lsa = triangle_router_lsa(
      neighbor, root, 0x0a000002U, 10U, alternate, 0x0a000201U, 10U,
      0xc6336400U, 5U);
  const auto alternate_lsa = triangle_router_lsa(
      alternate, root, 0x0a000102U, 30U, neighbor, 0x0a000202U, 10U,
      0xcb007200U, 1U);
  require(
      triangle_database.install(root_lsa,
                                router::packet::ospf::version_two, now,
                                root, false) == InstallResult::installed &&
          triangle_database.install(primary_lsa,
                                    router::packet::ospf::version_two, now,
                                    root, true) ==
              InstallResult::installed &&
          triangle_database.install(alternate_lsa,
                                    router::packet::ospf::version_two, now,
                                    root, true) ==
              InstallResult::installed,
      "triangle LFA fixture did not enter LSDB");
  TopologyBuilder triangle_topology{12U, 32U};
  require(triangle_topology.build(triangle_database.records(),
                                  router::packet::ospf::version_two, root),
          "triangle LFA topology was rejected");
  const auto triangle_graph = triangle_topology.graph();
  SpfCalculator triangle_spf{12U, 48U};
  require(triangle_spf.calculate(
              triangle_graph.root_vertex, triangle_graph.vertices,
              triangle_graph.edges,
              static_cast<std::uint16_t>(
                  triangle_graph.first_hops.size())),
          "triangle LFA SPF failed");
  RouteCalculator protected_calculator{24U, 4U};
  require(protected_calculator.recalculate(
              triangle_database.records(),
              router::packet::ospf::version_two, 0U, false,
              triangle_graph, triangle_spf, true),
          "LFA route generation rejected a synchronized triangle LSDB");
  const auto protected_routes = protected_calculator.routes();
  const auto protected_remote = std::find_if(
      protected_routes.begin(), protected_routes.end(), [](const auto &route) {
        return route.version_two_network == 0xc6336400U &&
               route.prefix_length == 24U;
      });
  require(protected_remote != protected_routes.end() &&
              protected_remote->next_hops.size() == 1U &&
              protected_remote->next_hops.front()
                      .topology.neighbor_router_id == neighbor &&
              protected_remote->loop_free_alternates.size() == 1U &&
              protected_remote->loop_free_alternates.front()
                      .topology.neighbor_router_id == alternate,
          "RFC 5286 inequality did not produce the expected repair next hop");
}
