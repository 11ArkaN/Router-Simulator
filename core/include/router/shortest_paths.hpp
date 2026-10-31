// Bounded indexed shortest paths shared by routing protocols. One control
// owner owns scratch and the published generation. Protocol owners translate
// their local LSDB and supply metric arithmetic explicitly. This mechanism
// depends only on value types and cannot inspect topology or peer state.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::routing {

inline constexpr std::uint32_t unreachable_distance = 0xffffffffU;

struct DistancePolicy {
  std::uint32_t maximum_distance{};
  std::uint32_t maximum_edge{};
  bool saturate{};
  bool settle_once{};
};
inline constexpr std::uint16_t no_first_hop = 0xffffU;
inline constexpr std::size_t first_hop_word_count =
    (device_catalog::maximum_ecmp_paths + 63U) / 64U;

struct SpfVertex {
  // Edges for one vertex occupy one contiguous subspan. LSDB translation sorts
  // vertices and edges before calculation, providing O(V + E log V) behavior
  // without an allocation-heavy map in the SPF hot path.
  std::uint32_t first_edge{};
  std::uint32_t edge_count{};
  // Smaller values win equal-distance selection. The IS-IS translator gives
  // pseudonodes precedence over routers as required by ISO 10589 C.2.7.
  std::uint8_t tie_priority{};
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

class ShortestPaths {
public:
  // max_pending_candidates is an emulator resource bound. It must be derived
  // from the active profile and sized for repeated equal-cost propagation.
  // Policy requires a finite maximum below unreachable_distance and an edge
  // maximum no larger than that distance, otherwise throws invalid_argument.
  // Overflow either discards a path or saturates at the inclusive finite cap.
  // settle_once closes a selected vertex permanently; its translator must
  // supply the protocol's equal-distance priority. Other policies retain
  // revision-driven propagation through equal-distance graph arcs.
  // Construction allocates both generations once. calculate performs no heap
  // allocation and returns false without replacing the published generation
  // if input or workspace capacity is invalid.
  ShortestPaths(std::size_t maximum_vertices,
                std::size_t maximum_pending_candidates, DistancePolicy policy);

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
    std::uint32_t distance{unreachable_distance};
    // Every path-set expansion increments revision. Heap entries carry the
    // revision they observed, allowing stale equal-distance work to be skipped
    // without a global visited bit that would break zero-cost network arcs.
    std::uint32_t revision{};
    bool settled{};
  };

  struct Candidate {
    std::uint32_t distance{};
    std::uint32_t vertex{};
    std::uint32_t revision{};
  };

  std::vector<VertexState> published_;
  std::vector<VertexState> scratch_;
  std::vector<Candidate> candidates_;
  DistancePolicy policy_;
  std::size_t maximum_vertices_{};
  std::size_t maximum_pending_candidates_{};
  std::size_t published_count_{};
  std::uint16_t published_first_hop_count_{};
};

} // namespace router::routing
