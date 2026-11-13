// ISO 10589 7.3.8, 7.3.10 and 8.4.5 couple pseudonode generation to the
// local DIS role. Current-set membership and counters stay with LocalLspSet;
// encoded output and purge completion remain with the instance update owner.

#include "router/isis_lan_origination.hpp"

#include <algorithm>

namespace router::isis {
LocalContentResult synchronize_lan_pseudonode(LocalLspSet &current,
    std::size_t level, packet::isis::LspId id, std::uint8_t flags, bool designated,
    std::span<const packet::isis::SystemId> peers, bool narrow,
    std::span<std::uint8_t> scratch, RuntimeClock::time_point now) noexcept {
  if (level > 1U || !id[6U]) return LocalContentResult::invalid;
  if (!current.sequence(level, id)) return LocalContentResult::missing;
  if (!designated) return current.withdraw(level, id);
  const auto required = lan_pseudonode_option_octets(peers.size(), narrow);
  if (!required || scratch.size() < *required) return LocalContentResult::capacity;
  packet::isis::SystemId local{};
  std::copy_n(id.begin(), local.size(), local.begin());
  packet::isis::TlvWriter writer(scratch);
  if (!append_lan_pseudonode_neighbors(writer, local, peers, narrow)) return LocalContentResult::invalid;
  return current.replace(level, id, flags, writer.bytes(), now);
}
} // namespace router::isis
