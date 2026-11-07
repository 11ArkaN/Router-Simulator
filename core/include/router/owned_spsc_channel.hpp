// Local control values move between one producer and one consumer. Each
// owner accesses a slot only during its lease. The two SPSC rings carry fixed
// handles; no pointer or container representation crosses a ring.

#pragma once

#include "router/spsc_ring.hpp"
#include "router/channel_checkpoint_partition.hpp"

#include <limits>
#include <memory>
#include <optional>
#include <utility>
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace router::protocol {

template <typename Value, std::size_t Capacity, bool WithCompletions = false> class OwnedSpscChannel final {
  static_assert(Capacity > 0U && Capacity <= std::numeric_limits<std::uint32_t>::max());
  static_assert(std::is_nothrow_default_constructible_v<Value> && std::is_nothrow_move_assignable_v<Value> &&
      std::is_nothrow_destructible_v<Value>);
public:
  using Handle = std::uint32_t;
  struct Lease { Handle handle{}; Value *value{}; };
  struct Completion { const Value *value{}; };
  struct SlotCheckpoint {
    Handle handle{};
    Value value;
    // A decoder can construct an empty owned slot directly in heap storage;
    // it must validate the completed partition before publishing any owner.
    SlotCheckpoint() noexcept : handle{}, value{} {}
    // Direct in-vector construction keeps even profile-sized values off stack.
    SlotCheckpoint(Handle slot, const Value &source) : handle(slot), value(source) {}
  };
  struct Checkpoint {
    std::uint32_t version{1U};
    std::uint64_t barrier_epoch{};
    std::size_t capacity{Capacity};
    bool with_completions{WithCompletions};
    std::vector<Handle> available, ready, borrowed, returned, editing;
    std::vector<SlotCheckpoint> occupied;
  };
  class PreparedRestore final {
    friend class OwnedSpscChannel;
    explicit PreparedRestore(const Checkpoint &saved) : saved_(saved) {}
    Checkpoint saved_;
    bool ready_{true};
  public:
    PreparedRestore(const PreparedRestore &) = delete;
    PreparedRestore &operator=(const PreparedRestore &) = delete;
  };

  OwnedSpscChannel() noexcept : available_count_(Capacity) {
    for (std::size_t index{}; index < Capacity; ++index)
      available_[index] = static_cast<Handle>(Capacity - index - 1U);
  }
  // Producer reserves exclusive edit ownership until publish or cancel.
  // Full applies backpressure without changing configuration. Reclamation
  // destroys consumed values only after acquiring their returned handles.
  [[nodiscard]] std::optional<Lease> acquire() noexcept {
    Handle handle{};
    if constexpr (!WithCompletions) while (returned_.try_pop(handle)) {
      reset(handle);
      available_[available_count_++] = handle;
    }
    if (!available_count_) return std::nullopt;
    handle = available_[--available_count_];
    if constexpr (WithCompletions) reset(handle);
    editing_[handle] = true;
    return Lease{handle, &values_[handle]};
  }
  // Producer release-publishes all value-owned allocations. Its lease ends
  // on success; it cannot inspect or modify that value until a later acquire.
  [[nodiscard]] bool publish(Handle handle) noexcept {
    if (handle >= Capacity || !editing_[handle] || !ready_.try_push(handle)) return false;
    editing_[handle] = false;
    return true;
  }
  // Producer cancels an unpublished edit, destroying its owned allocations.
  [[nodiscard]] bool cancel(Handle handle) noexcept {
    if (handle >= Capacity || !editing_[handle]) return false;
    reset(handle);
    editing_[handle] = false;
    available_[available_count_++] = handle;
    return true;
  }
  // Consumer acquire-observes exclusive mutable ownership. It may move fields
  // into its state before release. Values own their data; external borrowed
  // references cannot outlive publication or create another mutable owner.
  [[nodiscard]] std::optional<Lease> receive() noexcept {
    Handle handle{};
    if (!ready_.try_pop(handle)) return std::nullopt;
    borrowed_[handle] = true;
    return Lease{handle, &values_[handle]};
  }
  // Consumer release-publishes the return before producer reuse. Sensitive
  // plaintext must be erased before this call. Duplicate/unknown returns
  // reject without corrupting credits. Nothing may access the released lease.
  [[nodiscard]] bool release(Handle handle) noexcept {
    if (handle >= Capacity || !borrowed_[handle] || !returned_.try_push(handle)) return false;
    borrowed_[handle] = false;
    return true;
  }
  // Completion-enabled producer consumes the consumer's final value before
  // recovering its credit. No acquire can silently discard this result. The
  // read-only view expires at the next acquire; copy required receipt fields
  // before that call. Consumer writes become visible through return acquire.
  [[nodiscard]] std::optional<Completion> completion() noexcept requires WithCompletions {
    Handle handle{};
    if (!returned_.try_pop(handle)) return std::nullopt;
    available_[available_count_++] = handle;
    return Completion{&values_[handle]};
  }
  [[nodiscard]] bool empty() const noexcept { return ready_.empty(); }

  // Quiescent coordinator only after both live owners release-acknowledge the
  // enclosing barrier. No ring entry is consumed. Values are copy-constructed
  // directly in heap storage; large payloads never become stack temporaries.
  // Capture can throw allocation/value-copy or internal-invariant errors.
  // The enclosing codec must protect any secret-bearing value before storage.
  [[nodiscard]] Checkpoint checkpoint_quiescent(std::uint64_t barrier_epoch) const
      requires std::is_copy_constructible_v<Value> {
    if (!barrier_epoch) throw std::invalid_argument("Owned channel checkpoint requires a barrier epoch");
    if (available_count_ > Capacity) throw std::logic_error("Owned channel free count corrupted");
    Checkpoint result;
    result.barrier_epoch = barrier_epoch;
    result.available.assign(available_.begin(), available_.begin() + static_cast<std::ptrdiff_t>(available_count_));
    result.ready = ready_.checkpoint_quiescent();
    result.returned = returned_.checkpoint_quiescent();
    std::array<bool, Capacity> free{};
    for (const auto handle : result.available) {
      if (handle >= Capacity || free[handle]) throw std::logic_error("Owned channel free handles corrupted");
      free[handle] = true;
    }
    result.occupied.reserve(Capacity - available_count_);
    for (std::size_t index{}; index < Capacity; ++index) {
      const auto handle = static_cast<Handle>(index);
      if (borrowed_[index]) result.borrowed.push_back(handle);
      if (editing_[index]) result.editing.push_back(handle);
      if (!free[index]) result.occupied.emplace_back(handle, values_[index]);
    }
    if (!valid_checkpoint(result, barrier_epoch)) throw std::logic_error("Owned channel ownership corrupted");
    return result;
  }
  // Detached-image validation only, with bounded handle scratch and no owner
  // access or allocation. Value-specific semantics belong to the enclosing
  // contract. Editing is a fifth role distinct from free and published slots.
  [[nodiscard]] static bool valid_checkpoint(const Checkpoint &saved, std::uint64_t expected_epoch) noexcept {
    if (!expected_epoch || saved.version != 1U || saved.barrier_epoch != expected_epoch || saved.capacity != Capacity ||
        saved.with_completions != WithCompletions || saved.available.size() > Capacity ||
        saved.occupied.size() != Capacity - saved.available.size()) return false;
    const auto roles = checkpoint::partition<Capacity>(saved.available, saved.ready, saved.borrowed, saved.returned,
        saved.editing, [](Handle value) noexcept { return value; });
    if (!roles) return false;
    for (std::size_t index{}; index < saved.occupied.size(); ++index) {
      const auto handle = saved.occupied[index].handle;
      if (handle >= Capacity || (*roles)[handle] == checkpoint::SlotRole::available ||
          (index && saved.occupied[index - 1U].handle >= handle)) return false;
    }
    return true;
  }
  // Preparation reads only a detached image and may run before live quiescence.
  // It owns all copied values before commit. Refusal returns null on invalid
  // ownership or any allocation/value-copy failure, without touching the live
  // channel. Prepare every dependent channel before the first global commit.
  [[nodiscard]] static std::unique_ptr<PreparedRestore> prepare_restore(const Checkpoint &saved,
      std::uint64_t expected_epoch) noexcept requires std::is_copy_constructible_v<Value> {
    if (!valid_checkpoint(saved, expected_epoch)) return nullptr;
    try { return std::unique_ptr<PreparedRestore>{new PreparedRestore(saved)}; }
    catch (...) { return nullptr; }
  }
  // Same coordinator after both owners acknowledge quiescence. All old views
  // expire. Commit uses nothrow value moves and existing ring/slot capacity,
  // consumes this preparation once and performs no heap allocation. Refusal
  // precedes mutation. Resume must release-publish the complete owner graph.
  [[nodiscard]] bool commit_quiescent(PreparedRestore &prepared, std::uint64_t expected_epoch) noexcept {
    if (!prepared.ready_ || !valid_checkpoint(prepared.saved_, expected_epoch)) return false;
    auto &saved = prepared.saved_;
    for (const auto handle : saved.available) reset(handle);
    for (auto &slot : saved.occupied) values_[slot.handle] = std::move(slot.value);
    editing_.fill(false);
    borrowed_.fill(false);
    for (const auto handle : saved.editing) editing_[handle] = true;
    for (const auto handle : saved.borrowed) borrowed_[handle] = true;
    std::copy(saved.available.begin(), saved.available.end(), available_.begin());
    available_count_ = saved.available.size();
    static_cast<void>(ready_.restore_quiescent(saved.ready));
    static_cast<void>(returned_.restore_quiescent(saved.returned));
    prepared.ready_ = false;
    return true;
  }
  // Coordinator only, after restoration and before producer resume. Rebinds an
  // already reserved edit without acquiring another credit. The producer keeps
  // its ordinary edit lease until publish/cancel. Other handles return null.
  [[nodiscard]] Value *editing_value_quiescent(Handle handle) noexcept {
    return handle < Capacity && editing_[handle] ? &values_[handle] : nullptr;
  }
  // Coordinator only, after restoration and before consumer resume. Rebinds
  // the consumer's existing borrowed projection without another lease. Views
  // follow ordinary consumer lease rules; other handles return null.
  [[nodiscard]] const Value *borrowed_value_quiescent(Handle handle) const noexcept {
    return handle < Capacity && borrowed_[handle] ? &values_[handle] : nullptr;
  }
  [[nodiscard]] Value *borrowed_value_quiescent(Handle handle) noexcept {
    return handle < Capacity && borrowed_[handle] ? &values_[handle] : nullptr;
  }

private:
  void reset(Handle handle) noexcept {
    // Route generations can exceed a protocol stack's entire budget. Destroy
    // and reconstruct in their fixed slot instead of materializing Value{} as
    // a large temporary. Release/acquire ownership already ended every peer view.
    std::destroy_at(&values_[handle]);
    std::construct_at(&values_[handle]);
  }
  std::array<Value, Capacity> values_{};
  // Capacity usable FIFO entries plus one sentinel per ring. Roles reverse
  // for returned_. Both directions use release/acquire publication. Overflow
  // rejects work and never overwrites a live control value.
  SpscRing<Handle, Capacity + 1U> ready_;
  SpscRing<Handle, Capacity + 1U> returned_;
  std::array<Handle, Capacity> available_{};
  std::size_t available_count_{};
  std::array<bool, Capacity> editing_{}; // producer only
  std::array<bool, Capacity> borrowed_{}; // consumer only
};

} // namespace router::protocol
