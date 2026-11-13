// Quiescent channel coordinators validate fixed-slot ownership as pure values.
// Live producers/consumers retain their separate mutable state. This helper
// reads only a detached image and depends solely on standard value containers.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <type_traits>

namespace router::protocol::checkpoint {
enum class SlotRole : std::uint8_t { unassigned, available, ready, borrowed, returned, editing };

// Any coordinator may validate a detached image; no live channel is accessed.
// Every slot must occur exactly once. Stack scratch is one byte per bounded
// slot, never a payload. Borrowed/editing catalogs are ascending; FIFO and free
// stack order are retained verbatim. Invalid extents/duplicates return nullopt.
// return_handle must not throw or retain its argument. No allocation occurs.
template <std::size_t Capacity, typename Returns, typename Projection>
[[nodiscard]] std::optional<std::array<SlotRole, Capacity>> partition(
    std::span<const std::uint32_t> available, std::span<const std::uint32_t> ready,
    std::span<const std::uint32_t> borrowed, const Returns &returned,
    std::span<const std::uint32_t> editing, Projection return_handle) noexcept {
  static_assert(std::is_nothrow_invocable_r_v<std::uint32_t, Projection, const typename Returns::value_type &>);
  if (available.size() > Capacity || ready.size() > Capacity || borrowed.size() > Capacity ||
      returned.size() > Capacity || editing.size() > Capacity) return std::nullopt;
  std::array<SlotRole, Capacity> roles{};
  const auto claim = [&](std::uint32_t handle, SlotRole role) noexcept {
    if (handle >= Capacity || roles[handle] != SlotRole::unassigned) return false;
    roles[handle] = role;
    return true;
  };
  for (const auto handle : available) if (!claim(handle, SlotRole::available)) return std::nullopt;
  for (const auto handle : ready) if (!claim(handle, SlotRole::ready)) return std::nullopt;
  for (std::size_t index{}; index < borrowed.size(); ++index)
    if (!claim(borrowed[index], SlotRole::borrowed) || (index && borrowed[index - 1U] >= borrowed[index])) return std::nullopt;
  for (const auto &value : returned) if (!claim(return_handle(value), SlotRole::returned)) return std::nullopt;
  for (std::size_t index{}; index < editing.size(); ++index)
    if (!claim(editing[index], SlotRole::editing) || (index && editing[index - 1U] >= editing[index])) return std::nullopt;
  for (const auto role : roles) if (role == SlotRole::unassigned) return std::nullopt;
  return roles;
}
} // namespace router::protocol::checkpoint
