// One local content owner assigns intact semantic TLV units to LSP numbers.
// Only derived packing scratch lives here; sequence, authentication, LSDB and
// flooding belong to their existing owners. No received state enters this API.
#pragma once
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::isis {
struct FragmentUnitId {
  std::uint64_t domain{}, object{};
  constexpr FragmentUnitId() = default;
  constexpr FragmentUnitId(std::uint64_t object_id) : object(object_id) {}
  constexpr FragmentUnitId(std::uint64_t domain_id, std::uint64_t object_id) : domain(domain_id), object(object_id) {}
  auto operator<=>(const FragmentUnitId &) const = default;
};
struct FragmentUnit {
  // Stable producer-defined identity, ordered by domain then object. Domains
  // separate metadata from interface/peer keys without truncating their IDs.
  // A unit consists of one or more complete TLVs which must stay together.
  FragmentUnitId identity{};
  std::span<const std::uint8_t> tlv;
  std::optional<std::uint8_t> previous_fragment;
  bool root_only{};
};
struct FragmentOptions {
  std::span<std::uint8_t> storage;
  std::size_t size{};
};
enum class FragmentPlanStatus : std::uint8_t { planned, malformed, capacity };
class FragmentPlanner final {
public:
  // Cold control-shard construction reserves at most maximum_units assignments.
  // No shared memory, callbacks or protocol state. Allocation failure throws.
  explicit FragmentPlanner(std::size_t maximum_units);
  // Same-owner synchronous planning, no allocation. semantic_octets is the
  // originating PDU limit after fixed header, IID and authentication overhead.
  // fragment_count is 1..256. Input units contain complete, nonempty framed TLV streams;
  // authentication/IID options are forbidden and Area Addresses are root-only.
  // Pseudonodes cannot contain Area Addresses. Inputs/output never alias scratch.
  // Success writes one LSP number per input; failure leaves output unchanged.
  // Existing placement is retained while it fits, then lowest free space is
  // reused. If that layout cannot fit, bounded dense packing may relocate
  // units. Relocation requires atomic SRM publication by the caller.
  [[nodiscard]] FragmentPlanStatus plan(std::span<const FragmentUnit> units,
      std::size_t semantic_octets, std::size_t fragment_count, bool pseudonode,
      std::span<std::uint8_t> output) noexcept;
  // Same ownership and framing rules as plan(). Produces semantic option
  // streams in caller-reserved fragment buffers, before IID/authentication.
  // Input bytes and output buffers are mutually disjoint. Buffer count selects
  // the fragment limit. Every size and byte remains unchanged on refusal;
  // success clears unused fragments and copies only complete semantic units.
  [[nodiscard]] FragmentPlanStatus compose(std::span<const FragmentUnit> units,
      std::size_t semantic_octets, bool pseudonode, std::span<FragmentOptions> fragments) noexcept;
private:
  [[nodiscard]] FragmentPlanStatus prepare(std::span<const FragmentUnit> units,
      std::size_t semantic_octets, std::size_t fragment_count, bool pseudonode) noexcept;
  [[nodiscard]] FragmentPlanStatus dense(std::span<const FragmentUnit> units,
      std::size_t semantic_octets, std::size_t fragment_count) noexcept;
  const std::size_t maximum_units_;
  std::vector<std::uint16_t> assignments_;
  std::vector<std::size_t> order_;
};
}
