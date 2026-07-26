// RFC 2328 sections 16.1 through 16.4 and RFC 5340 section 4.8 route
// derivation. Dijkstra results are consumed as immutable input and all route
// comparison happens before one complete vector replaces the prior generation.

#include "router/ospf_route_calculator.hpp"

#include "router/ospf_lsa.hpp"
#include "router/ospf_packet.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <new>
#include <queue>
#include <tuple>

namespace router::ospf {
namespace {

using lab::routing::OspfPathType;

[[nodiscard]] std::optional<std::uint8_t>
prefix_length(std::uint32_t mask) noexcept {
  const auto length =
      static_cast<std::uint8_t>(std::countl_one(mask));
  const auto expected =
      length == 0U ? 0U : 0xffffffffU << (32U - length);
  return mask == expected ? std::optional{length} : std::nullopt;
}

[[nodiscard]] std::uint8_t rank(OspfPathType type) noexcept {
  switch (type) {
  case OspfPathType::intra_area:
    return 0U;
  case OspfPathType::inter_area:
    return 1U;
  case OspfPathType::external_type_1:
  case OspfPathType::nssa_type_1:
    return 2U;
  case OspfPathType::external_type_2:
  case OspfPathType::nssa_type_2:
    return 3U;
  case OspfPathType::none:
    return std::numeric_limits<std::uint8_t>::max();
  }
  return std::numeric_limits<std::uint8_t>::max();
}

[[nodiscard]] bool same_prefix(const CalculatedRoute &left,
                               const CalculatedRoute &right) noexcept {
  return left.version_three == right.version_three &&
         left.ipv4_address_family == right.ipv4_address_family &&
         left.prefix_length == right.prefix_length &&
         (left.version_three
              ? left.version_three_network == right.version_three_network
              : left.version_two_network == right.version_two_network);
}

[[nodiscard]] bool better(const CalculatedRoute &left,
                          const CalculatedRoute &right) noexcept {
  if (rank(left.path_type) != rank(right.path_type))
    return rank(left.path_type) < rank(right.path_type);
  const bool left_type_two =
      left.path_type == OspfPathType::external_type_2 ||
      left.path_type == OspfPathType::nssa_type_2;
  if (left_type_two && left.metric != right.metric)
    return left.metric < right.metric;
  if (left_type_two && left.internal_metric != right.internal_metric)
    return left.internal_metric < right.internal_metric;
  if (!left_type_two && left.metric != right.metric)
    return left.metric < right.metric;
  return std::tie(left.advertising_router, left.area_id) <
         std::tie(right.advertising_router, right.area_id);
}

[[nodiscard]] bool equal_cost(const CalculatedRoute &left,
                              const CalculatedRoute &right) noexcept {
  return rank(left.path_type) == rank(right.path_type) &&
         left.metric == right.metric &&
         left.internal_metric == right.internal_metric;
}

[[nodiscard]] bool prefix_contains(const ip::Ipv6 &network,
                                   std::uint8_t length,
                                   const ip::Ipv6 &address) noexcept {
  // Both OSPFv3 IPv6 and RFC 5838 IPv4-AF values use the same canonical
  // sixteen-octet container. IPv4 occupies its first four octets, so the same
  // bit-exact test applies without inventing an IPv4-mapped address format.
  return ip::mask(address, length) == network;
}

[[nodiscard]] std::optional<std::size_t>
vertex_for_router(const TopologyGraphView &graph,
                  std::uint32_t router_id) noexcept {
  for (std::size_t index{}; index < graph.keys.size(); ++index)
    if (graph.keys[index].kind == TopologyVertexKind::router &&
        graph.keys[index].id == router_id)
      return index;
  return std::nullopt;
}

[[nodiscard]] std::optional<std::size_t>
vertex_for_network(const TopologyGraphView &graph, std::uint32_t id,
                   std::uint32_t advertiser) noexcept {
  for (std::size_t index{}; index < graph.keys.size(); ++index)
    if (graph.keys[index].kind == TopologyVertexKind::transit_network &&
        graph.keys[index].id == id &&
        graph.keys[index].advertising_router == advertiser)
      return index;
  return std::nullopt;
}

[[nodiscard]] std::optional<ip::Ipv6>
link_local_for(std::span<const LsaRecord> records,
               const FirstHop &hop, bool ipv4_address_family) noexcept {
  for (const auto &record : records) {
    const auto header =
        packet::ospf::lsa_header(record.bytes, packet::ospf::version_three);
    if (!header || (header->type & 0x1fffU) != 8U ||
        header->advertising_router != hop.neighbor_router_id ||
        header->link_state_id != hop.neighbor_interface)
      continue;
    const auto link = packet::ospf::lsa::parse_version_three_link(
        record.bytes, ipv4_address_family);
    if (link)
      return link->link_local_address;
  }
  return std::nullopt;
}

[[nodiscard]] bool set_hops(CalculatedRoute &route,
                            std::span<const LsaRecord> records,
                            const TopologyGraphView &graph,
                            const SpfCalculator &spf,
                            std::size_t vertex) {
  const auto count = spf.first_hop_count(vertex);
  if (count == 0U)
    return vertex == graph.root_vertex;
  route.next_hops.reserve(count);
  for (std::size_t ordinal{}; ordinal < count; ++ordinal) {
    const auto token = spf.first_hop(vertex, ordinal);
    if (!token || *token >= graph.first_hops.size())
      return false;
    CalculatedNextHop next{.topology = graph.first_hops[*token]};
    if (route.version_three) {
      const auto address =
          link_local_for(records, next.topology,
                         route.ipv4_address_family);
      if (!address)
        return false;
      next.version_three_link_local = *address;
    } else if (next.topology.version_two_next_hop == 0U) {
      return false;
    }
    route.next_hops.push_back(next);
  }
  return true;
}

[[nodiscard]] bool calculate_loop_free_alternates(
    std::span<const LsaRecord> records, const TopologyGraphView &graph,
    const SpfCalculator &spf, std::vector<CalculatedRoute> &routes,
    std::size_t maximum_equal_cost_next_hops) {
  using DistanceCandidate = std::pair<std::uint32_t, std::uint32_t>;
  if (graph.root_vertex >= graph.vertices.size())
    return false;

  // RFC 5286 section 3.1 requires distances from each directly connected
  // neighbor, not another shortest-path run rooted at S with the first edge
  // removed. Running Dijkstra on this router's synchronized area graph yields
  // D(N,D) and D(N,S) without consulting another router or editor topology.
  for (const auto &first_hop : graph.first_hops) {
    const auto neighbor =
        vertex_for_router(graph, first_hop.neighbor_router_id);
    if (!neighbor)
      return false;
    std::vector<std::uint32_t> distances(
        graph.vertices.size(), ls_infinity);
    std::priority_queue<DistanceCandidate,
                        std::vector<DistanceCandidate>,
                        std::greater<>>
        pending;
    distances[*neighbor] = 0U;
    pending.emplace(0U, static_cast<std::uint32_t>(*neighbor));
    while (!pending.empty()) {
      const auto [distance, vertex] = pending.top();
      pending.pop();
      if (distance != distances[vertex])
        continue;
      const auto &source = graph.vertices[vertex];
      for (const auto &edge :
           graph.edges.subspan(source.first_edge, source.edge_count)) {
        if (distance >= ls_infinity - edge.cost)
          continue;
        const auto candidate = distance + edge.cost;
        if (candidate >= distances[edge.target_vertex])
          continue;
        distances[edge.target_vertex] = candidate;
        pending.emplace(candidate, edge.target_vertex);
      }
    }

    for (auto &route : routes) {
      if (route.topology_vertex >= graph.vertices.size() ||
          route.next_hops.empty() ||
          route.loop_free_alternates.size() >=
              maximum_equal_cost_next_hops)
        continue;
      const auto root_distance = spf.cost(route.topology_vertex);
      const auto neighbor_to_destination =
          distances[route.topology_vertex];
      const auto neighbor_to_source = distances[graph.root_vertex];
      if (!root_distance ||
          neighbor_to_destination >= ls_infinity ||
          neighbor_to_source >= ls_infinity)
        continue;

      const bool primary =
          std::any_of(route.next_hops.begin(), route.next_hops.end(),
                      [&](const auto &hop) {
                        return hop.topology == first_hop;
                      });
      // A primary next hop cannot simultaneously be its own repair path. The
      // strict inequality is copied directly from RFC 5286 section 3.1 and is
      // evaluated in 64 bits to avoid overflow near LSInfinity.
      if (primary ||
          static_cast<std::uint64_t>(neighbor_to_destination) >=
              static_cast<std::uint64_t>(neighbor_to_source) +
                  *root_distance)
        continue;

      CalculatedNextHop alternate{.topology = first_hop};
      if (route.version_three) {
        const auto link_local =
            link_local_for(records, first_hop,
                           route.ipv4_address_family);
        if (!link_local)
          return false;
        alternate.version_three_link_local = *link_local;
      } else if (first_hop.version_two_next_hop == 0U) {
        return false;
      }
      route.loop_free_alternates.push_back(alternate);
    }
  }

  const auto less = [](const CalculatedNextHop &left,
                       const CalculatedNextHop &right) noexcept {
    return std::tie(left.topology.neighbor_router_id,
                    left.topology.local_interface,
                    left.topology.neighbor_interface,
                    left.topology.version_two_next_hop) <
           std::tie(right.topology.neighbor_router_id,
                    right.topology.local_interface,
                    right.topology.neighbor_interface,
                    right.topology.version_two_next_hop);
  };
  for (auto &route : routes)
    std::sort(route.loop_free_alternates.begin(),
              route.loop_free_alternates.end(), less);
  return true;
}

[[nodiscard]] bool add_candidate(std::vector<CalculatedRoute> &routes,
                                 CalculatedRoute candidate,
                                 std::size_t maximum_routes,
                                 std::size_t maximum_equal_cost_next_hops) {
  const auto hop_less = [](const CalculatedNextHop &left,
                           const CalculatedNextHop &right) noexcept {
    return std::tie(left.topology.neighbor_router_id,
                    left.topology.local_interface,
                    left.topology.neighbor_interface,
                    left.topology.version_two_next_hop) <
           std::tie(right.topology.neighbor_router_id,
                    right.topology.local_interface,
                    right.topology.neighbor_interface,
                    right.topology.version_two_next_hop);
  };
  std::sort(candidate.next_hops.begin(), candidate.next_hops.end(), hop_less);
  if (candidate.next_hops.size() > maximum_equal_cost_next_hops)
    candidate.next_hops.resize(maximum_equal_cost_next_hops);
  const auto existing =
      std::find_if(routes.begin(), routes.end(), [&](const auto &route) {
        return same_prefix(route, candidate);
      });
  if (existing == routes.end()) {
    if (routes.size() == maximum_routes)
      return false;
    routes.push_back(std::move(candidate));
    return true;
  }
  if (better(candidate, *existing)) {
    *existing = std::move(candidate);
    return true;
  }
  if (!better(*existing, candidate) && equal_cost(*existing, candidate)) {
    for (const auto &hop : candidate.next_hops)
      if (std::find_if(existing->next_hops.begin(),
                       existing->next_hops.end(), [&](const auto &current) {
            return current.topology == hop.topology;
          }) == existing->next_hops.end())
        if (existing->next_hops.size() < maximum_equal_cost_next_hops)
          existing->next_hops.push_back(hop);
    std::sort(existing->next_hops.begin(), existing->next_hops.end(),
              hop_less);
  }
  return true;
}

} // namespace

RouteCalculator::RouteCalculator(
    std::size_t maximum_routes,
    std::size_t maximum_equal_cost_next_hops)
    : maximum_routes_(maximum_routes),
      maximum_equal_cost_next_hops_(maximum_equal_cost_next_hops) {
  published_.reserve(maximum_routes_);
}

bool RouteCalculator::recalculate(
    std::span<const LsaRecord> records, std::uint8_t version,
    std::uint32_t area_id, bool ipv4_address_family,
    const TopologyGraphView &graph, const SpfCalculator &spf,
    bool calculate_lfa) noexcept {
  if ((version != packet::ospf::version_two &&
       version != packet::ospf::version_three) ||
      graph.keys.size() != spf.vertex_count() || maximum_routes_ == 0U ||
      maximum_equal_cost_next_hops_ == 0U)
    return false;
  try {
    std::vector<CalculatedRoute> routes;
    routes.reserve(maximum_routes_);

    // Intra-area destinations are calculated before externals because a
    // non-zero forwarding address must resolve through an intra/inter-area
    // route, never recursively through another external route.
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function =
          version == packet::ospf::version_two
              ? header->type
              : static_cast<std::uint16_t>(header->type & 0x1fffU);
      if (version == packet::ospf::version_two && function == 1U) {
        const auto view =
            packet::ospf::lsa::parse_version_two_router(record.bytes);
        const auto vertex =
            vertex_for_router(graph, header->advertising_router);
        if (!view || !vertex || !spf.reachable(*vertex))
          continue;
        std::size_t offset{};
        for (std::size_t index{}; index < view->link_count; ++index) {
          const auto link =
              packet::ospf::lsa::version_two_router_link(*view, offset);
          if (!link)
            return false;
          offset = link->next_offset;
          if (link->type !=
              packet::ospf::lsa::RouterLinkType::stub_network)
            continue;
          const auto length = prefix_length(link->link_data);
          const auto base = spf.cost(*vertex);
          if (!length || !base)
            return false;
          CalculatedRoute route{
              .next_hops = {},
              .loop_free_alternates = {},
              .version_two_network = link->link_id & link->link_data,
              .metric = *base + link->metric,
              .internal_metric = *base + link->metric,
              .advertising_router = header->advertising_router,
              .area_id = area_id,
              .path_type = OspfPathType::intra_area,
              .prefix_length = *length,
              .topology_vertex =
                  static_cast<std::uint32_t>(*vertex)};
          if (!set_hops(route, records, graph, spf, *vertex) ||
              !add_candidate(routes, std::move(route), maximum_routes_,
                             maximum_equal_cost_next_hops_))
            return false;
        }
      } else if (version == packet::ospf::version_two && function == 2U) {
        const auto view =
            packet::ospf::lsa::parse_version_two_network(record.bytes);
        const auto vertex = vertex_for_network(
            graph, header->link_state_id, header->advertising_router);
        const auto length = view ? prefix_length(view->network_mask)
                                 : std::nullopt;
        const auto cost = vertex ? spf.cost(*vertex) : std::nullopt;
        if (!view || !length || !cost)
          continue;
        if (spf.first_hop_count(*vertex) == 0U) {
          // A directly attached transit network is already an authoritative
          // connected RIB input. Its root-to-network SPF arc deliberately has
          // no forwarding next hop. Do not turn that absence into a failed
          // dynamic generation or publish a duplicate OSPF route.
          continue;
        }
        CalculatedRoute route{
            .next_hops = {},
            .loop_free_alternates = {},
            .version_two_network =
                header->link_state_id & view->network_mask,
            .metric = *cost,
            .internal_metric = *cost,
            .advertising_router = header->advertising_router,
            .area_id = area_id,
            .path_type = OspfPathType::intra_area,
            .prefix_length = *length,
            .topology_vertex =
                static_cast<std::uint32_t>(*vertex)};
        if (!set_hops(route, records, graph, spf, *vertex) ||
            !add_candidate(routes, std::move(route), maximum_routes_,
                           maximum_equal_cost_next_hops_))
          return false;
      } else if (version == packet::ospf::version_two && function == 3U) {
        const auto summary =
            packet::ospf::lsa::parse_version_two_summary(record.bytes);
        const auto vertex =
            vertex_for_router(graph, header->advertising_router);
        const auto length =
            summary ? prefix_length(summary->network_mask) : std::nullopt;
        const auto cost = vertex ? spf.cost(*vertex) : std::nullopt;
        if (!summary || !length || !cost)
          continue;
        CalculatedRoute route{
            .next_hops = {},
            .loop_free_alternates = {},
            .version_two_network =
                header->link_state_id & summary->network_mask,
            .metric = *cost + summary->metric,
            .internal_metric = *cost,
            .advertising_router = header->advertising_router,
            .area_id = area_id,
            .path_type = OspfPathType::inter_area,
            .prefix_length = *length,
            .topology_vertex =
                static_cast<std::uint32_t>(*vertex)};
        if (!set_hops(route, records, graph, spf, *vertex) ||
            !add_candidate(routes, std::move(route), maximum_routes_,
                           maximum_equal_cost_next_hops_))
          return false;
      } else if (version == packet::ospf::version_three &&
                 function == 9U) {
        const auto prefix =
            packet::ospf::lsa::parse_version_three_intra_area_prefix(
                record.bytes);
        if (!prefix)
          return false;
        std::optional<std::size_t> vertex;
        if ((prefix->referenced_lsa_type & 0x1fffU) == 1U)
          vertex = vertex_for_router(
              graph, prefix->referenced_advertising_router);
        else if ((prefix->referenced_lsa_type & 0x1fffU) == 2U)
          vertex = vertex_for_network(
              graph, prefix->referenced_link_state_id,
              prefix->referenced_advertising_router);
        const auto base = vertex ? spf.cost(*vertex) : std::nullopt;
        if (!vertex || !base)
          continue;
        if ((prefix->referenced_lsa_type & 0x1fffU) == 2U &&
            spf.first_hop_count(*vertex) == 0U) {
          // OSPFv3 separates the transit prefix from Network-LSA topology, but
          // the local segment is still owned by connected routing and has no
          // link-local next hop. Only remote transit prefixes become OSPF3 RIB
          // candidates.
          continue;
        }
        std::size_t offset{};
        for (std::size_t index{}; index < prefix->prefix_count; ++index) {
          const auto item = packet::ospf::lsa::version_three_prefix(
              prefix->prefixes, offset, true);
          const auto network =
              item ? packet::ospf::lsa::expand_prefix(*item) : std::nullopt;
          if (!item || !network)
            return false;
          offset = item->next_offset;
          CalculatedRoute route{
              .version_three_network = *network,
              .next_hops = {},
              .loop_free_alternates = {},
              .metric = *base + item->metric,
              .internal_metric = *base + item->metric,
              .advertising_router = header->advertising_router,
              .area_id = area_id,
              .path_type = OspfPathType::intra_area,
              .prefix_length = item->length,
              .version_three = true,
              .ipv4_address_family = ipv4_address_family,
              .topology_vertex =
                  static_cast<std::uint32_t>(*vertex)};
          if (!set_hops(route, records, graph, spf, *vertex) ||
              !add_candidate(routes, std::move(route), maximum_routes_,
                             maximum_equal_cost_next_hops_))
            return false;
        }
      } else if (version == packet::ospf::version_three &&
                 function == 3U) {
        const auto item =
            packet::ospf::lsa::parse_version_three_inter_area_prefix(
                record.bytes);
        const auto network =
            item ? packet::ospf::lsa::expand_prefix(item->prefix)
                 : std::nullopt;
        const auto vertex =
            vertex_for_router(graph, header->advertising_router);
        const auto base = vertex ? spf.cost(*vertex) : std::nullopt;
        if (!item || !network || !vertex || !base)
          continue;
        CalculatedRoute route{
            .version_three_network = *network,
            .next_hops = {},
            .loop_free_alternates = {},
            .metric = *base + item->metric,
            .internal_metric = *base,
            .advertising_router = header->advertising_router,
            .area_id = area_id,
            .path_type = OspfPathType::inter_area,
            .prefix_length = item->prefix.length,
            .version_three = true,
            .ipv4_address_family = ipv4_address_family,
            .topology_vertex =
                static_cast<std::uint32_t>(*vertex)};
        if (!set_hops(route, records, graph, spf, *vertex) ||
            !add_candidate(routes, std::move(route), maximum_routes_,
                           maximum_equal_cost_next_hops_))
          return false;
      }
    }

    struct InterAreaAsbr {
      std::vector<CalculatedNextHop> next_hops;
      std::uint32_t router_id{};
      std::uint32_t metric{};
      std::uint32_t advertising_router{};
      std::uint32_t topology_vertex{};
    };
    std::vector<InterAreaAsbr> inter_area_asbrs;
    inter_area_asbrs.reserve(maximum_routes_);
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function =
          version == packet::ospf::version_two
              ? header->type
              : static_cast<std::uint16_t>(header->type & 0x1fffU);
      if (function != 4U)
        continue;
      const auto abr =
          vertex_for_router(graph, header->advertising_router);
      const auto abr_cost = abr ? spf.cost(*abr) : std::nullopt;
      if (!abr || !abr_cost)
        continue;
      std::uint32_t asbr{};
      std::uint32_t advertised_metric{};
      if (version == packet::ospf::version_two) {
        const auto body =
            packet::ospf::lsa::parse_version_two_summary(record.bytes);
        if (!body || !body->autonomous_system_boundary_router)
          return false;
        asbr = header->link_state_id;
        advertised_metric = body->metric;
      } else {
        const auto body =
            packet::ospf::lsa::parse_version_three_inter_area_router(
                record.bytes);
        if (!body)
          return false;
        asbr = body->destination_router_id;
        advertised_metric = body->metric;
      }
      InterAreaAsbr candidate{
          .next_hops = {},
          .router_id = asbr,
          .metric = *abr_cost + advertised_metric,
          .advertising_router = header->advertising_router,
          .topology_vertex = static_cast<std::uint32_t>(*abr)};
      CalculatedRoute hop_source{.next_hops = {},
                                 .loop_free_alternates = {},
                                 .version_three =
                                     version ==
                                     packet::ospf::version_three,
                                 .ipv4_address_family =
                                     ipv4_address_family};
      if (!set_hops(hop_source, records, graph, spf, *abr))
        return false;
      candidate.next_hops = std::move(hop_source.next_hops);
      const auto existing = std::find_if(
          inter_area_asbrs.begin(), inter_area_asbrs.end(),
          [asbr](const auto &item) { return item.router_id == asbr; });
      if (existing == inter_area_asbrs.end()) {
        if (inter_area_asbrs.size() == maximum_routes_)
          return false;
        inter_area_asbrs.push_back(std::move(candidate));
      } else if (std::tie(candidate.metric,
                          candidate.advertising_router) <
                 std::tie(existing->metric,
                          existing->advertising_router)) {
        *existing = std::move(candidate);
      } else if (candidate.metric == existing->metric) {
        for (const auto &hop : candidate.next_hops)
          if (std::find_if(
                  existing->next_hops.begin(),
                  existing->next_hops.end(),
                  [&](const auto &current) {
                    return current.topology == hop.topology;
                  }) == existing->next_hops.end() &&
              existing->next_hops.size() <
                  maximum_equal_cost_next_hops_)
            existing->next_hops.push_back(hop);
      }
    }

    // External and NSSA destinations are evaluated only after internal routes
    // exist. A forwarding address is resolved by longest internal match;
    // otherwise reachability and next hops are inherited from the ASBR.
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function =
          version == packet::ospf::version_two
              ? header->type
              : static_cast<std::uint16_t>(header->type & 0x1fffU);
      const bool external =
          version == packet::ospf::version_two
              ? function == 5U || function == 7U
              : function == 5U || function == 7U;
      if (!external)
        continue;
      const auto asbr =
          vertex_for_router(graph, header->advertising_router);
      const auto inter_area_asbr = std::find_if(
          inter_area_asbrs.begin(), inter_area_asbrs.end(),
          [&](const auto &item) {
            return item.router_id == header->advertising_router;
          });
      const auto asbr_cost =
          asbr ? spf.cost(*asbr)
               : inter_area_asbr != inter_area_asbrs.end()
                     ? std::optional<std::uint32_t>{
                           inter_area_asbr->metric}
                     : std::nullopt;
      if (!asbr_cost)
        continue;

      if (version == packet::ospf::version_two) {
        const auto item =
            packet::ospf::lsa::parse_version_two_external(record.bytes);
        const auto length =
            item ? prefix_length(item->network_mask) : std::nullopt;
        if (!item || !length)
          return false;
        CalculatedRoute route{
            .next_hops = {},
            .loop_free_alternates = {},
            .version_two_network =
                header->link_state_id & item->network_mask,
            .metric = item->type_two_metric
                          ? item->metric
                          : *asbr_cost + item->metric,
            .internal_metric = *asbr_cost,
            .advertising_router = header->advertising_router,
            .area_id = area_id,
            .tag = item->route_tag,
            .path_type =
                function == 7U
                    ? (item->type_two_metric
                           ? OspfPathType::nssa_type_2
                           : OspfPathType::nssa_type_1)
                    : (item->type_two_metric
                           ? OspfPathType::external_type_2
                           : OspfPathType::external_type_1),
            .prefix_length = *length};
        if (item->forwarding_address != 0U) {
          const CalculatedRoute *resolution{};
          for (const auto &candidate : routes)
            if (!candidate.version_three &&
                rank(candidate.path_type) <=
                    rank(OspfPathType::inter_area) &&
                (item->forwarding_address &
                 lab::routing::prefix_mask(candidate.prefix_length)) ==
                    candidate.version_two_network &&
                (!resolution ||
                 candidate.prefix_length > resolution->prefix_length))
              resolution = &candidate;
          if (!resolution)
            continue;
          route.internal_metric = resolution->metric;
          route.metric = item->type_two_metric
                             ? item->metric
                             : resolution->metric + item->metric;
          route.next_hops = resolution->next_hops;
          route.topology_vertex = resolution->topology_vertex;
        } else if (asbr) {
          if (!set_hops(route, records, graph, spf, *asbr))
            return false;
          route.topology_vertex = static_cast<std::uint32_t>(*asbr);
        } else {
          route.next_hops = inter_area_asbr->next_hops;
          route.topology_vertex = inter_area_asbr->topology_vertex;
        }
        if (!add_candidate(routes, std::move(route), maximum_routes_,
                           maximum_equal_cost_next_hops_))
          return false;
      } else {
        const auto item =
            packet::ospf::lsa::parse_version_three_external(
                record.bytes, ipv4_address_family);
        const auto network =
            item ? packet::ospf::lsa::expand_prefix(item->prefix)
                 : std::nullopt;
        if (!item || !network)
          return false;
        CalculatedRoute route{
            .version_three_network = *network,
            .next_hops = {},
            .loop_free_alternates = {},
            .metric = item->type_two_metric
                          ? item->metric
                          : *asbr_cost + item->metric,
            .internal_metric = *asbr_cost,
            .advertising_router = header->advertising_router,
            .area_id = area_id,
            .tag = item->route_tag.value_or(0U),
            .path_type =
                function == 7U
                    ? (item->type_two_metric
                           ? OspfPathType::nssa_type_2
                           : OspfPathType::nssa_type_1)
                    : (item->type_two_metric
                           ? OspfPathType::external_type_2
                           : OspfPathType::external_type_1),
            .prefix_length = item->prefix.length,
            .version_three = true,
            .ipv4_address_family = ipv4_address_family};
        if (!item->forwarding_address.empty()) {
          ip::Ipv6 forwarding{};
          std::copy(item->forwarding_address.begin(),
                    item->forwarding_address.end(), forwarding.begin());
          const CalculatedRoute *resolution{};
          for (const auto &candidate : routes)
            if (candidate.version_three &&
                candidate.ipv4_address_family == ipv4_address_family &&
                rank(candidate.path_type) <= rank(OspfPathType::inter_area) &&
                prefix_contains(candidate.version_three_network,
                                candidate.prefix_length, forwarding) &&
                (!resolution ||
                 candidate.prefix_length > resolution->prefix_length))
              resolution = &candidate;
          // RFC 5340 section 4.8.3 requires a reachable non-external
          // forwarding address. Falling back to the ASBR would install a route
          // that a conforming router must omit.
          if (!resolution)
            continue;
          route.internal_metric = resolution->metric;
          route.metric = item->type_two_metric
                             ? item->metric
                             : resolution->metric + item->metric;
          route.next_hops = resolution->next_hops;
          route.topology_vertex = resolution->topology_vertex;
        } else if (asbr) {
          if (!set_hops(route, records, graph, spf, *asbr))
            return false;
          route.topology_vertex = static_cast<std::uint32_t>(*asbr);
        } else {
          route.next_hops = inter_area_asbr->next_hops;
          route.topology_vertex = inter_area_asbr->topology_vertex;
        }
        if (!add_candidate(routes, std::move(route), maximum_routes_,
                           maximum_equal_cost_next_hops_))
          return false;
      }
    }
    if (calculate_lfa &&
        !calculate_loop_free_alternates(
            records, graph, spf, routes,
            maximum_equal_cost_next_hops_))
      return false;
    published_ = std::move(routes);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
