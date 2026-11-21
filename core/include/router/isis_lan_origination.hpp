// The instance control owner applies its local DIS selection to reserved
// pseudonode content. This adapter owns no mutable state; dependencies point
// to same-shard local generation and allocation-free neighbor composition.

#pragma once

#include "router/isis_local_lsp_set.hpp"
#include "router/isis_neighbor_origination.hpp"

namespace router::isis {
// Same instance shard. The caller supplies the actual local DIS role and
// sorted unique Up peer system IDs, excluding the system portion of id.
// id must select an already reserved pseudonode record; no record is created.
// Non-DIS withdraws it for ordinary MaxAge purge through LocalLspSet::service.
// DIS replaces neighbor content, retaining its publication counter. Changes
// remain deferred to service, including minimum spacing and authentication.
// Scratch is exclusive and may not alias peers or retained local content.
// Invalid level/ID/peers returns invalid, missing reservation returns missing,
// and insufficient scratch or reserved content returns capacity. All failures
// preserve current content. No allocation, remote state or borrowed retention.
[[nodiscard]] LocalContentResult synchronize_lan_pseudonode(LocalLspSet &current,
    std::size_t level, packet::isis::LspId id, std::uint8_t flags, bool designated,
    std::span<const packet::isis::SystemId> peers, bool narrow,
    std::span<std::uint8_t> scratch, RuntimeClock::time_point now) noexcept;
} // namespace router::isis
