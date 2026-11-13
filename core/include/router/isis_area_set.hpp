// The instance control shard owns its effective area set and manual-address
// rejection history. Inputs are revision-fenced local L1 decisions; no circuit,
// peer registry, editor state or cross-shard mutable storage is consulted.
// Source: iso.10589.2002.area_addresses
#pragma once
#include "router/isis_area_attachment.hpp"
#include <string_view>
#include <vector>
namespace router::isis {
// Same-owner canonical sorted set to one complete Area Addresses option.
// Empty input omits the option. Output borrows caller scratch; nullopt rejects
// invalid framing or capacity. No allocation or retained view escapes.
[[nodiscard]] std::optional<std::size_t> encode_area_set_options(
    std::span<const NeighborArea>, std::span<std::uint8_t>) noexcept;
// Read-only semantic comparison for composed LSP metadata. Canonical expected
// order is significant; malformed, duplicate or extra Area Addresses refuse.
[[nodiscard]] bool area_set_options_match(std::span<const std::uint8_t>,
    std::span<const NeighborArea>) noexcept;
struct ManualAreaDropped {
  NeighborArea area;
  static constexpr std::string_view specific_problem = "ISIS.manualAddressDroppedFromArea";
  static constexpr std::string_view probable_cause = "NLM.configurationOrCustomisationError";
  static constexpr std::string_view severity = "Major";
  static constexpr bool significant = false;
};
struct AreaSetObserver {
  void *context{};
  void (*dropped)(void *, const ManualAreaDropped &) noexcept{};
};
struct AreaSetCheckpoint {
  std::uint32_t version{1U};
  std::uint8_t maximum{};
  std::vector<NeighborArea> manual, effective;
  std::vector<std::uint8_t> rejected;
  std::uint32_t manual_addresses_dropped{};
};
struct AreaSetResult { bool valid{}, changed{}; std::size_t events{}; };
class AreaAddressSet final {
public:
  // Cold construction copies a unique canonical manual set of at most maximum
  // addresses, then sorts it numerically. Zero capacity or malformed values
  // throw invalid_argument; allocation failure propagates. The manual identity
  // is immutable for this owner. Initial effective addresses are the manual set.
  AreaAddressSet(std::uint8_t maximum, std::span<const NeighborArea> manual);
  AreaAddressSet(const AreaAddressSet &) = delete;
  AreaAddressSet &operator=(const AreaAddressSet &) = delete;
  // Sole instance shard, complete matching family-independent L1 SPF required.
  // No allocation. Invalid input preserves all owned state and emits nothing.
  // Only a manual address observed in the union and rejected by truncation
  // generates an event. Reinstatement rearms it without a Cleared event.
  // The counter follows yang:counter32 modulo 2^32. Observer borrows each event
  // only for the synchronous callback and must not reenter or mutate this owner.
  [[nodiscard]] AreaSetResult recompute(const LinkStateDatabase &, const P2pRouteDecision &,
      RuntimeClock::time_point, AreaSetObserver = {}) noexcept;
  [[nodiscard]] std::span<const NeighborArea> manual() const noexcept { return manual_; }
  [[nodiscard]] std::span<const NeighborArea> effective() const noexcept { return effective_; }
  // Same identity recovery discards foreign evidence and reinstates manual
  // addresses. The occurrence counter survives; no Cleared event is emitted.
  void reset_to_manual() noexcept;
  [[nodiscard]] std::uint32_t manual_addresses_dropped() const noexcept { return dropped_; }
  // Quiescent same-owner value copy; may allocate. Restore requires the exact
  // admitted manual identity and capacity, validates before allocation-free
  // replacement and never synthesizes notifications. Refusal preserves state.
  [[nodiscard]] AreaSetCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const AreaSetCheckpoint &) noexcept;
private:
  std::uint8_t maximum_{};
  std::vector<NeighborArea> manual_, effective_;
  std::vector<std::uint8_t> rejected_;
  std::uint32_t dropped_{};
};
}
