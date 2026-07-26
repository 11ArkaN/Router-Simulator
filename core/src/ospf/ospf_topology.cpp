// RFC 2328 section 16.1 and RFC 5340 section 4.8 topology construction. Every
// candidate arc requires the corresponding reverse description before it can
// enter SPF, matching the standards' bidirectional-link check.

#include "router/ospf_topology.hpp"

#include "router/ospf_lsa.hpp"

#include <algorithm>
#include <new>
#include <tuple>

namespace router::ospf {
namespace {

using packet::ospf::lsa::RouterLinkType;

[[nodiscard]] bool key_less(const TopologyVertexKey &left,
                            const TopologyVertexKey &right) noexcept {
  return std::tie(left.kind, left.id, left.advertising_router) <
         std::tie(right.kind, right.id, right.advertising_router);
}

[[nodiscard]] bool hop_less(const FirstHop &left,
                            const FirstHop &right) noexcept {
  return std::tie(left.neighbor_router_id, left.version_two_next_hop,
                  left.neighbor_interface, left.local_interface) <
         std::tie(right.neighbor_router_id, right.version_two_next_hop,
                  right.neighbor_interface, right.local_interface);
}

} // namespace

struct TopologyBuilder::TemporaryEdge {
  TopologyVertexKey from;
  TopologyVertexKey to;
  std::optional<FirstHop> first_hop;
  std::uint32_t cost{};
};

TopologyBuilder::TopologyBuilder(std::size_t maximum_vertices,
                                 std::size_t maximum_edges)
    : maximum_vertices_(maximum_vertices), maximum_edges_(maximum_edges) {
  keys_.reserve(maximum_vertices_);
  vertices_.reserve(maximum_vertices_);
  edges_.reserve(maximum_edges_);
  first_hops_.reserve(device_catalog::maximum_ecmp_paths);
}

bool TopologyBuilder::build(std::span<const LsaRecord> records,
                            std::uint8_t version,
                            std::uint32_t root_router_id) noexcept {
  if (version != packet::ospf::version_two &&
      version != packet::ospf::version_three)
    return false;
  try {
    std::vector<TopologyVertexKey> keys;
    std::vector<TemporaryEdge> temporary;
    std::vector<FirstHop> hops;
    keys.reserve(std::min(maximum_vertices_, records.size()));
    temporary.reserve(maximum_edges_);
    hops.reserve(device_catalog::maximum_ecmp_paths);

    const auto add_key = [&](TopologyVertexKey key) {
      if (std::find(keys.begin(), keys.end(), key) == keys.end())
        keys.push_back(key);
    };

    // The first pass establishes stable vertices. Prefix LSAs do not describe
    // graph nodes and are intentionally excluded from this topology phase.
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function = version == packet::ospf::version_two
                                ? header->type
                                : header->type & 0x1fffU;
      if (function == 1U)
        add_key({.kind = TopologyVertexKind::router,
                 .id = header->advertising_router});
      else if (function == 2U)
        add_key({.kind = TopologyVertexKind::transit_network,
                 .id = header->link_state_id,
                 .advertising_router = header->advertising_router});
    }
    if (keys.empty() || keys.size() > maximum_vertices_)
      return false;
    std::sort(keys.begin(), keys.end(), key_less);

    const auto router_key = [](std::uint32_t router_id) {
      return TopologyVertexKey{.kind = TopologyVertexKind::router,
                               .id = router_id};
    };
    const auto find_router_record =
        [&](std::uint32_t router_id) -> const LsaRecord * {
      const auto found = std::find_if(records.begin(), records.end(),
                                      [&](const auto &record) {
        const auto header =
            packet::ospf::lsa_header(record.bytes, version);
        return header &&
               (version == packet::ospf::version_two
                    ? header->type == 1U
                    : (header->type & 0x1fffU) == 1U) &&
               header->advertising_router == router_id;
      });
      return found == records.end() ? nullptr : &*found;
    };
    const auto find_network_key =
        [&](std::uint32_t id,
            std::optional<std::uint32_t> advertiser)
        -> std::optional<TopologyVertexKey> {
      const auto found = std::find_if(keys.begin(), keys.end(),
                                      [&](const auto &key) {
        return key.kind == TopologyVertexKind::transit_network &&
               key.id == id &&
               (!advertiser || key.advertising_router == *advertiser);
      });
      return found == keys.end() ? std::nullopt
                                 : std::optional<TopologyVertexKey>{*found};
    };

    const auto v2_router_has_link =
        [&](std::uint32_t router_id, RouterLinkType type,
            std::uint32_t target) {
      const auto *record = find_router_record(router_id);
      const auto view =
          record ? packet::ospf::lsa::parse_version_two_router(record->bytes)
                 : std::nullopt;
      if (!view)
        return false;
      std::size_t offset{};
      for (std::size_t index{}; index < view->link_count; ++index) {
        const auto link =
            packet::ospf::lsa::version_two_router_link(*view, offset);
        if (!link)
          return false;
        offset = link->next_offset;
        if (link->type == type && link->link_id == target)
          return true;
      }
      return false;
    };
    const auto v3_router_has_link =
        [&](std::uint32_t router_id, RouterLinkType type,
            std::uint32_t neighbor_router,
            std::uint32_t neighbor_interface) {
      const auto *record = find_router_record(router_id);
      const auto view =
          record ? packet::ospf::lsa::parse_version_three_router(record->bytes)
                 : std::nullopt;
      if (!view)
        return false;
      const auto count = view->links.size() / 16U;
      for (std::size_t index{}; index < count; ++index) {
        const auto link =
            packet::ospf::lsa::version_three_router_link(*view, index);
        if (link && link->type == type &&
            link->neighbor_router_id == neighbor_router &&
            (type != RouterLinkType::transit_network ||
             link->neighbor_interface_id == neighbor_interface))
          return true;
      }
      return false;
    };

    const auto append = [&](TemporaryEdge edge) {
      if (temporary.size() == maximum_edges_)
        return false;
      if (edge.first_hop &&
          std::find(hops.begin(), hops.end(), *edge.first_hop) == hops.end()) {
        if (hops.size() == device_catalog::maximum_ecmp_paths)
          return false;
        hops.push_back(*edge.first_hop);
      }
      temporary.push_back(std::move(edge));
      return true;
    };

    // Router arcs carry configured outgoing cost. Stub links are prefixes and
    // are attached after SPF rather than represented as graph vertices.
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function = version == packet::ospf::version_two
                                ? header->type
                                : header->type & 0x1fffU;
      if (function != 1U)
        continue;
      const auto from = router_key(header->advertising_router);
      if (version == packet::ospf::version_two) {
        const auto view =
            packet::ospf::lsa::parse_version_two_router(record.bytes);
        if (!view)
          return false;
        std::size_t offset{};
        for (std::size_t index{}; index < view->link_count; ++index) {
          const auto link =
              packet::ospf::lsa::version_two_router_link(*view, offset);
          if (!link)
            return false;
          offset = link->next_offset;
          if (link->type == RouterLinkType::stub_network)
            continue;
          if (link->type == RouterLinkType::point_to_point ||
              link->type == RouterLinkType::virtual_link) {
            if (!v2_router_has_link(link->link_id, link->type,
                                    header->advertising_router))
              continue;
            std::optional<FirstHop> hop;
            if (header->advertising_router == root_router_id) {
              // RFC 2328 section 12.4.1 makes link_data the advertising
              // router's own interface address. Forwarding needs the address
              // in the neighbor's reciprocal link, not the root address.
              const auto *neighbor = find_router_record(link->link_id);
              const auto neighbor_view =
                  neighbor ? packet::ospf::lsa::parse_version_two_router(
                                 neighbor->bytes)
                           : std::nullopt;
              std::size_t neighbor_offset{};
              if (neighbor_view)
                for (std::size_t neighbor_index{};
                     neighbor_index < neighbor_view->link_count;
                     ++neighbor_index) {
                  const auto reverse =
                      packet::ospf::lsa::version_two_router_link(
                          *neighbor_view, neighbor_offset);
                  if (!reverse)
                    break;
                  neighbor_offset = reverse->next_offset;
                  if (reverse->type == link->type &&
                      reverse->link_id == root_router_id) {
                    hop = FirstHop{.neighbor_router_id = link->link_id,
                                   .version_two_next_hop = reverse->link_data,
                                   .local_interface = link->link_data};
                    break;
                  }
                }
            }
            if (!append({.from = from,
                         .to = router_key(link->link_id),
                         .first_hop = hop,
                         .cost = link->metric}))
              return false;
          } else {
            const auto network = find_network_key(link->link_id, std::nullopt);
            if (!network)
              continue;
            const auto network_record =
                std::find_if(records.begin(), records.end(),
                             [&](const auto &candidate) {
              const auto candidate_header =
                  packet::ospf::lsa_header(candidate.bytes, version);
              if (!candidate_header ||
                  candidate_header->link_state_id != network->id ||
                  candidate_header->advertising_router !=
                      network->advertising_router)
                return false;
              const auto view =
                  packet::ospf::lsa::parse_version_two_network(candidate.bytes);
              if (!view)
                return false;
              for (std::size_t attached{};
                   attached < view->attached_routers.size() / 4U; ++attached)
                if (packet::ospf::lsa::attached_router(*view, attached) ==
                    header->advertising_router)
                  return true;
              return false;
            });
            if (network_record != records.end() &&
                !append({.from = from,
                         .to = *network,
                         .first_hop = std::nullopt,
                         .cost = link->metric}))
              return false;
          }
        }
      } else {
        const auto view =
            packet::ospf::lsa::parse_version_three_router(record.bytes);
        if (!view)
          return false;
        for (std::size_t index{}; index < view->links.size() / 16U; ++index) {
          const auto link =
              packet::ospf::lsa::version_three_router_link(*view, index);
          if (!link)
            return false;
          if (link->type == RouterLinkType::point_to_point ||
              link->type == RouterLinkType::virtual_link) {
            if (!v3_router_has_link(link->neighbor_router_id, link->type,
                                    header->advertising_router,
                                    link->interface_id))
              continue;
            const auto hop =
                header->advertising_router == root_router_id
                    ? std::optional<FirstHop>{{
                          .neighbor_router_id = link->neighbor_router_id,
                          .neighbor_interface =
                              link->neighbor_interface_id,
                          .local_interface = link->interface_id}}
                    : std::nullopt;
            if (!append({.from = from,
                         .to = router_key(link->neighbor_router_id),
                         .first_hop = hop,
                         .cost = link->metric}))
              return false;
          } else if (link->type == RouterLinkType::transit_network) {
            const auto network = find_network_key(
                link->neighbor_interface_id, link->neighbor_router_id);
            if (network &&
                !append({.from = from,
                         .to = *network,
                         .first_hop = std::nullopt,
                         .cost = link->metric}))
              return false;
          }
        }
      }
    }

    // Network-to-router arcs cost zero. Reciprocity is checked against the
    // attached router's transit link before the arc is admitted.
    for (const auto &record : records) {
      const auto header = packet::ospf::lsa_header(record.bytes, version);
      if (!header)
        return false;
      const auto function = version == packet::ospf::version_two
                                ? header->type
                                : header->type & 0x1fffU;
      if (function != 2U)
        continue;
      const auto network =
          find_network_key(header->link_state_id,
                           header->advertising_router);
      if (!network)
        return false;
      if (version == packet::ospf::version_two) {
        const auto view =
            packet::ospf::lsa::parse_version_two_network(record.bytes);
        if (!view)
          return false;
        for (std::size_t index{};
             index < view->attached_routers.size() / 4U; ++index) {
          const auto router =
              packet::ospf::lsa::attached_router(*view, index);
          if (!router ||
              !v2_router_has_link(*router, RouterLinkType::transit_network,
                                  header->link_state_id))
            continue;
          std::optional<FirstHop> hop;
          if (*router != root_router_id &&
              v2_router_has_link(root_router_id,
                                 RouterLinkType::transit_network,
                                 header->link_state_id)) {
            const auto *root = find_router_record(root_router_id);
            const auto root_view =
                root ? packet::ospf::lsa::parse_version_two_router(root->bytes)
                     : std::nullopt;
            std::size_t offset{};
            if (root_view)
              for (std::size_t link_index{};
                   link_index < root_view->link_count; ++link_index) {
                const auto link =
                    packet::ospf::lsa::version_two_router_link(*root_view,
                                                                offset);
                if (!link)
                  break;
                offset = link->next_offset;
                if (link->type == RouterLinkType::transit_network &&
                    link->link_id == header->link_state_id) {
                  // The attached router's matching link_data is its address
                  // on this transit network. The root's link_data remains the
                  // local interface token used to select egress.
                  const auto *neighbor = find_router_record(*router);
                  const auto neighbor_view =
                      neighbor ? packet::ospf::lsa::parse_version_two_router(
                                     neighbor->bytes)
                               : std::nullopt;
                  std::size_t neighbor_offset{};
                  if (neighbor_view)
                    for (std::size_t neighbor_index{};
                         neighbor_index < neighbor_view->link_count;
                         ++neighbor_index) {
                      const auto neighbor_link =
                          packet::ospf::lsa::version_two_router_link(
                              *neighbor_view, neighbor_offset);
                      if (!neighbor_link)
                        break;
                      neighbor_offset = neighbor_link->next_offset;
                      if (neighbor_link->type ==
                              RouterLinkType::transit_network &&
                          neighbor_link->link_id ==
                              header->link_state_id) {
                        hop = FirstHop{
                            .neighbor_router_id = *router,
                            .version_two_next_hop =
                                neighbor_link->link_data,
                            .local_interface = link->link_data};
                        break;
                      }
                    }
                  break;
                }
              }
          }
          if (!append({.from = *network,
                       .to = router_key(*router),
                       .first_hop = hop,
                       .cost = 0U}))
            return false;
        }
      } else {
        const auto view =
            packet::ospf::lsa::parse_version_three_network(record.bytes);
        if (!view)
          return false;
        for (std::size_t index{};
             index < view->attached_routers.size() / 4U; ++index) {
          const auto router =
              packet::ospf::lsa::attached_router(*view, index);
          if (!router ||
              !v3_router_has_link(*router, RouterLinkType::transit_network,
                                  header->advertising_router,
                                  header->link_state_id))
            continue;
          std::optional<FirstHop> hop;
          if (*router != root_router_id) {
            // RFC 5340 section 4.8.1 represents a transit network by the DR's
            // Router ID and Interface ID. When the root is attached to that
            // network, the forwarding first hop appears only on the zero-cost
            // network-to-router arc. Keeping it here avoids incorrectly
            // resolving the neighbor from editor geometry or an IPv6 address
            // that is absent from Router-LSAs.
            const auto *root = find_router_record(root_router_id);
            const auto root_view =
                root ? packet::ospf::lsa::parse_version_three_router(
                           root->bytes)
                     : std::nullopt;
            if (root_view)
              for (std::size_t root_index{};
                   root_index < root_view->links.size() / 16U;
                   ++root_index) {
                const auto root_link =
                    packet::ospf::lsa::version_three_router_link(*root_view,
                                                                  root_index);
                if (root_link &&
                    root_link->type == RouterLinkType::transit_network &&
                    root_link->neighbor_router_id ==
                        header->advertising_router &&
                    root_link->neighbor_interface_id ==
                        header->link_state_id) {
                  hop = FirstHop{.neighbor_router_id = *router,
                                 .neighbor_interface =
                                     root_link->neighbor_interface_id,
                                 .local_interface =
                                     root_link->interface_id};
                  break;
                }
              }
          }
          if (!append({.from = *network,
                       .to = router_key(*router),
                       .first_hop = hop,
                       .cost = 0U}))
            return false;
        }
      }
    }

    const auto root =
        std::find(keys.begin(), keys.end(), router_key(root_router_id));
    if (root == keys.end())
      return false;
    const auto root_index =
        static_cast<std::uint32_t>(root - keys.begin());
    std::sort(hops.begin(), hops.end(), hop_less);
    std::sort(temporary.begin(), temporary.end(),
              [](const auto &left, const auto &right) {
      return key_less(left.from, right.from) ||
             (!key_less(right.from, left.from) &&
              (key_less(left.to, right.to) ||
               (!key_less(right.to, left.to) && left.cost < right.cost)));
    });

    std::vector<SpfVertex> vertices(keys.size());
    std::vector<SpfEdge> edges;
    edges.reserve(temporary.size());
    for (std::size_t vertex_index{}; vertex_index < keys.size();
         ++vertex_index) {
      auto &vertex = vertices[vertex_index];
      vertex.first_edge = static_cast<std::uint32_t>(edges.size());
      for (const auto &edge : temporary) {
        if (edge.from != keys[vertex_index])
          continue;
        const auto target = std::lower_bound(keys.begin(), keys.end(),
                                             edge.to, key_less);
        if (target == keys.end() || *target != edge.to)
          continue;
        std::uint16_t token = no_first_hop;
        if (edge.first_hop) {
          const auto found =
              std::lower_bound(hops.begin(), hops.end(), *edge.first_hop,
                               hop_less);
          if (found == hops.end() || *found != *edge.first_hop)
            return false;
          token = static_cast<std::uint16_t>(found - hops.begin());
        }
        edges.push_back(
            {.target_vertex = static_cast<std::uint32_t>(target - keys.begin()),
             .cost = edge.cost,
             .first_hop = token});
      }
      vertex.edge_count =
          static_cast<std::uint32_t>(edges.size() - vertex.first_edge);
    }

    // Publish the complete translation only after all references and resource
    // bounds have been validated.
    keys_ = std::move(keys);
    vertices_ = std::move(vertices);
    edges_ = std::move(edges);
    first_hops_ = std::move(hops);
    root_vertex_ = root_index;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

TopologyGraphView TopologyBuilder::graph() const noexcept {
  return {.keys = keys_,
          .vertices = vertices_,
          .edges = edges_,
          .first_hops = first_hops_,
          .root_vertex = root_vertex_};
}

} // namespace router::ospf
