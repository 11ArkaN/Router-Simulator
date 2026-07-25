// OSPF shortest-path-first workspace. The calculator owns only reusable
// scratch and one immutable published result. An OSPF process translates its
// own LSDB into this indexed graph, invokes Dijkstra, and maps the result back
// to prefixes. The calculator has no topology-editor, packet, RIB or device
// registry dependency and cannot inspect another router's LSDB.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ospf {

inline constexpr std::uint32_t ls_infinity = 0x00ffffffU;
inline constexpr std::uint16_t no_first_hop = 0xffffU;
inline constexpr std::size_t first_hop_word_count =
    (device_catalog::maximum_ecmp_paths + 63U) / 64U;

struct SpfVertex {
  // Edges for one vertex occupy one contiguous subspan. LSDB translation sorts
  // vertices and edges before calculation, providing O(V + E log V) behavior
  // without an allocation-heavy map in the SPF hot path.
  std::uint32_t first_edge{};
  std::uint32_t edge_count{};
};

struct SpfEdge {
  std::uint32_t target_vertex{};
  std::uint32_t cost{};
  // A token identifies a distinct forwarding next hop in a caller-owned,
  // deterministically sorted catalog. no_first_hop is used for graph arcs such
  // as root-router to transit-network where the next router is learned by a
  // subsequent zero-cost network arc.
  std::uint16_t first_hop{no_first_hop};
};

class SpfCalculator final {
public:
  // max_pending_candidates is an emulator resource bound. It must be derived
  // from the active profile and sized for repeated equal-cost propagation.
  // Construction allocates both generations once. calculate performs no heap
  // allocation and returns false without replacing the published generation
  // if input or workspace capacity is invalid.
  SpfCalculator(std::size_t maximum_vertices,
                std::size_t maximum_pending_candidates);

  [[nodiscard]] bool
  calculate(std::uint32_t root_vertex, std::span<const SpfVertex> vertices,
            std::span<const SpfEdge> edges,
            std::uint16_t first_hop_count) noexcept;

  [[nodiscard]] std::size_t vertex_count() const noexcept {
    return published_count_;
  }
  [[nodiscard]] bool reachable(std::size_t vertex) const noexcept;
  [[nodiscard]] std::optional<std::uint32_t>
  cost(std::size_t vertex) const noexcept;
  [[nodiscard]] std::size_t
  first_hop_count(std::size_t vertex) const noexcept;
  [[nodiscard]] std::optional<std::uint16_t>
  first_hop(std::size_t vertex, std::size_t ordinal) const noexcept;

private:
  using FirstHopBits =
      std::array<std::uint64_t, first_hop_word_count>;

  struct VertexState {
    FirstHopBits first_hops{};
    std::uint32_t distance{ls_infinity};
    // Every path-set expansion increments revision. Heap entries carry the
    // revision they observed, allowing stale equal-distance work to be skipped
    // without a global visited bit that would break zero-cost network arcs.
    std::uint32_t revision{};
  };

  struct Candidate {
    std::uint32_t distance{};
    std::uint32_t vertex{};
    std::uint32_t revision{};
  };

  std::vector<VertexState> published_;
  std::vector<VertexState> scratch_;
  std::vector<Candidate> candidates_;
  std::size_t maximum_vertices_{};
  std::size_t maximum_pending_candidates_{};
  std::size_t published_count_{};
  std::uint16_t published_first_hop_count_{};
};

} // namespace router::ospf
