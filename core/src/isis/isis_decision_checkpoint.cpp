// A decision restores its last published identity, distance and prefix set.
// Scratch translation is rebuilt at the next ordinary calculation. Restoring
// never reads a newer LSDB or changes a route publication generation.

#include "router/isis_p2p_decision.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>

namespace router::isis {
DecisionCheckpoint P2pRouteDecision::checkpoint() const {
  DecisionCheckpoint result{1U, configuration_, identities_, calculator_.checkpoint(), {}};
  // A successful missing-root decision clears the identity projection while
  // leaving old calculator scratch inaccessible. Do not transfer those bytes.
  if (identities_.empty()) {
    result.paths.vertices.clear();
    result.paths.first_hop_count = 0U;
  }
  if (prefixes_) result.prefixes = prefixes_->checkpoint();
  return result;
}
std::unique_ptr<P2pRouteDecision> P2pRouteDecision::restore_checkpoint(const DecisionCheckpoint &saved,
    DecisionConfiguration expected) noexcept {
  if (saved.version != 1U || saved.configuration != expected || saved.identities.size() > expected.nodes ||
      saved.identities.size() != saved.paths.vertices.size() || saved.prefixes.has_value() != expected.prefixes.has_value())
    return nullptr;
  for (std::size_t index{1U}; index < saved.identities.size(); ++index)
    if (saved.identities[index - 1U] >= saved.identities[index]) return nullptr;
  if (saved.prefixes) for (const auto &prefix : saved.prefixes->entries) {
    packet::isis::LanId id{};
    std::copy_n(prefix.origin.begin(), id.size(), id.begin());
    if (!std::binary_search(saved.identities.begin(), saved.identities.end(), id)) return nullptr;
  }
  try {
    auto result = std::make_unique<P2pRouteDecision>(expected.nodes, expected.links, expected.pending,
        expected.distance, expected.prefixes);
    if (!result->calculator_.restore(saved.paths) || (saved.prefixes && !result->prefixes_->restore(*saved.prefixes)))
      return nullptr;
    result->identities_.assign(saved.identities.begin(), saved.identities.end());
    return result;
  } catch (const std::bad_alloc &) { return nullptr; }
    catch (const std::invalid_argument &) { return nullptr; }
    catch (const std::length_error &) { return nullptr; }
}
} // namespace router::isis
