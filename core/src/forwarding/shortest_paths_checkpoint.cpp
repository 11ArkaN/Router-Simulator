// Published shortest-path results belong to one protocol calculation owner.
// Transfers omit relaxation scratch and preserve exact reachable/token results.
// Validation precedes replacement and never allocates during restore.

#include "router/shortest_paths.hpp"

namespace router::routing {
ShortestPathsCheckpoint ShortestPaths::checkpoint() const {
  ShortestPathsCheckpoint result{1U, policy_, maximum_vertices_, maximum_pending_candidates_, published_first_hop_count_, {}};
  result.vertices.reserve(published_count_);
  for (std::size_t index{}; index < published_count_; ++index)
    result.vertices.push_back({published_[index].distance, published_[index].first_hops});
  return result;
}
bool ShortestPaths::restore(const ShortestPathsCheckpoint &saved) noexcept {
  if (saved.version != 1U || saved.policy != policy_ || saved.maximum_vertices != maximum_vertices_ ||
      saved.maximum_pending_candidates != maximum_pending_candidates_ || saved.vertices.size() > maximum_vertices_ ||
      saved.first_hop_count > maximum_first_hops || (saved.vertices.empty() && saved.first_hop_count)) return false;
  bool root{};
  for (const auto &vertex : saved.vertices) {
    if (vertex.distance != unreachable_distance && vertex.distance > policy_.maximum_distance) return false;
    root = root || vertex.distance == 0U;
    for (std::size_t word{}; word < vertex.first_hops.size(); ++word) {
      const auto first = word * 64U;
      const auto count = saved.first_hop_count > first ? saved.first_hop_count - first : 0U;
      const auto allowed = count >= 64U ? ~std::uint64_t{} : (std::uint64_t{1U} << count) - 1U;
      if ((vertex.first_hops[word] & ~allowed) ||
          (vertex.distance == unreachable_distance && vertex.first_hops[word])) return false;
    }
  }
  if (!saved.vertices.empty() && !root) return false;
  // Construction reserves maximum_vertices in both generations; trivial
  // value initialization below cannot allocate or throw after validation.
  published_.resize(saved.vertices.size());
  for (std::size_t index{}; index < saved.vertices.size(); ++index)
    published_[index] = {saved.vertices[index].first_hops, saved.vertices[index].distance, 0U, false};
  published_count_ = saved.vertices.size();
  published_first_hop_count_ = saved.first_hop_count;
  return true;
}
} // namespace router::routing
