// The router RIB owner retains two protocol candidate sets in one bounded
// arena. Dependencies are value and capacity definitions only. No protocol
// owner or forwarding shard may borrow mutable storage from this owner.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <algorithm>
#include <span>
#include <new>
#include <type_traits>
#include <vector>

namespace router::routing {
template <typename Entry> class RouteInputStore final {
  static_assert(std::is_nothrow_default_constructible_v<Entry> &&
      std::is_nothrow_copy_assignable_v<Entry> && std::is_nothrow_move_assignable_v<Entry> &&
      std::is_nothrow_move_constructible_v<Entry> && std::is_nothrow_destructible_v<Entry>);
public:
  // Empty admission allocates no candidate storage. The RIB owner prepares
  // variable protocol storage before a fallible installation transaction.
  // Failure preserves both value sets; successful preparation may invalidate
  // old views but never publishes a route. Growth remains bounded by one
  // generated ceiling and uses the runtime's normal checked heap growth.
  [[nodiscard]] bool prepare_first(std::size_t count) noexcept {
    const auto others = entries_.size() - first_count_;
    return count <= device_catalog::maximum_dynamic_routes_per_router - others && reserve(count + others);
  }
  [[nodiscard]] bool prepare_second(std::size_t count) noexcept {
    return count <= device_catalog::maximum_dynamic_routes_per_router - first_count_ && reserve(first_count_ + count);
  }
  [[nodiscard]] std::span<const Entry> first() const noexcept {
    return std::span<const Entry>{entries_}.first(first_count_);
  }
  [[nodiscard]] std::span<const Entry> second() const noexcept {
    return std::span<const Entry>{entries_}.subspan(first_count_);
  }
  // Serialized RIB owner only. Input must not alias this arena; the caller
  // normally retains an immutable received publication until the call ends.
  // Preparation before installation guarantees replacement cannot allocate.
  // Refusal preserves both sets. Success copies the complete replacement,
  // preserves the other set and invalidates previously borrowed views.
  [[nodiscard]] bool replace_first(std::span<const Entry> input) noexcept {
    const auto others = entries_.size() - first_count_;
    if (!prepare_first(input.size())) return false;
    const auto total = input.size() + others;
    if (input.size() > first_count_) {
      entries_.resize(total);
      std::move_backward(entries_.begin() + first_count_, entries_.begin() + first_count_ + others,
          entries_.end());
    } else if (input.size() < first_count_) {
      std::move(entries_.begin() + first_count_, entries_.end(), entries_.begin() + input.size());
      entries_.resize(total);
    }
    std::copy(input.begin(), input.end(), entries_.begin());
    first_count_ = input.size();
    return true;
  }
  [[nodiscard]] bool replace_second(std::span<const Entry> input) noexcept {
    if (!prepare_second(input.size())) return false;
    entries_.resize(first_count_ + input.size());
    std::copy(input.begin(), input.end(), entries_.begin() + first_count_);
    return true;
  }
private:
  [[nodiscard]] bool reserve(std::size_t required) noexcept {
    if (required <= entries_.capacity()) return true;
    if (required > entries_.max_size()) return false;
    auto capacity = std::max<std::size_t>(1U, entries_.capacity());
    while (capacity < required) capacity = std::min(capacity * 2U,
        device_catalog::maximum_dynamic_routes_per_router);
    try { entries_.reserve(capacity); }
    catch (const std::bad_alloc &) { return false; }
    return true;
  }
  std::vector<Entry> entries_;
  std::size_t first_count_{};
};
} // namespace router::routing
