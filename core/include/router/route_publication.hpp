// Receipt-enabled local route publication from one protocol owner to one RIB
// owner. Fixed slots carry generations; a returned result acknowledges actual
// installation or explicit refusal. No ring contains a pointer or route table.

#pragma once

#include "router/owned_spsc_channel.hpp"
#include "router/route_generation.hpp"

namespace router::routing {
enum class RouteInstallStatus : std::uint8_t { pending, installed, stale, invalid, capacity, selection_failed, forwarding_failed };
struct RouteInstallReceipt {
  lab::DeviceHandle device{};
  std::uint64_t generation{};
  RouteInstallStatus status{RouteInstallStatus::pending};
};
template <std::size_t Capacity> class RoutePublicationChannel final {
  struct Publication { RouteGeneration routes; RouteInstallStatus status{RouteInstallStatus::pending}; };
  using Channel = protocol::OwnedSpscChannel<Publication, Capacity, true>;
public:
  using Handle = typename Channel::Handle;
  using Checkpoint = typename Channel::Checkpoint;
  class PreparedRestore final {
    friend class RoutePublicationChannel;
    explicit PreparedRestore(std::unique_ptr<typename Channel::PreparedRestore> value) noexcept : channel_(std::move(value)) {}
    std::unique_ptr<typename Channel::PreparedRestore> channel_;
  public:
    PreparedRestore(const PreparedRestore &) = delete;
    PreparedRestore &operator=(const PreparedRestore &) = delete;
  };
  struct Writable { Handle handle{}; RouteGeneration *generation{}; };
  struct Borrowed { Handle handle{}; const RouteGeneration *generation{}; };
  // Exactly one protocol producer and one RIB consumer per channel. FIFO in
  // both directions, Capacity usable slots, release/acquire publication. Full
  // applies backpressure until the producer consumes an installation result.
  // All route storage is fixed and normally heap-owned by the channel aggregate.
  [[nodiscard]] std::optional<Writable> try_acquire() noexcept {
    const auto lease = channel_.acquire();
    return lease ? std::optional{Writable{lease->handle, &lease->value->routes}} : std::nullopt;
  }
  [[nodiscard]] bool publish(Handle handle) noexcept { return channel_.publish(handle); }
  [[nodiscard]] bool cancel(Handle handle) noexcept { return channel_.cancel(handle); }
  [[nodiscard]] std::optional<Borrowed> try_receive() noexcept {
    const auto lease = channel_.receive();
    if (!lease) return std::nullopt;
    borrowed_[lease->handle] = lease->value;
    return Borrowed{lease->handle, &lease->value->routes};
  }
  // Consumer only, after validating the complete generation and finishing the
  // real RIB/FIB transaction. Installed must never mean transfer-ring enqueue.
  // Expected identity guards delayed results across slot reuse. Unknown,
  // duplicate, mismatched or pending completion rejects without credit return.
  // Success ends the consumer's borrowed view and cannot be repeated.
  [[nodiscard]] bool complete(Handle handle, lab::DeviceHandle expected_device,
      std::uint64_t expected_generation, RouteInstallStatus status) noexcept {
    if (handle >= Capacity || !borrowed_[handle] || status == RouteInstallStatus::pending ||
        status > RouteInstallStatus::forwarding_failed) return false;
    auto &publication = *borrowed_[handle];
    if (publication.routes.device != expected_device || publication.routes.generation != expected_generation) return false;
    publication.status = status;
    if (!channel_.release(handle)) return false;
    borrowed_[handle] = nullptr;
    return true;
  }
  // Producer only. Copy the small final result before making the slot reusable;
  // no borrowed route view escapes and no result can be silently reclaimed.
  [[nodiscard]] std::optional<RouteInstallReceipt> try_completion() noexcept {
    const auto result = channel_.completion();
    return result ? std::optional{RouteInstallReceipt{result->value->routes.device,
        result->value->routes.generation, result->value->status}} : std::nullopt;
  }
  // Same quiescent coordinator after protocol and RIB owners acknowledge the
  // barrier. Capture owns exact generations/results, may throw on allocation
  // or a corrupt pointer projection, and consumes no installation receipt.
  [[nodiscard]] Checkpoint checkpoint_quiescent(std::uint64_t barrier_epoch) const {
    auto result = channel_.checkpoint_quiescent(barrier_epoch);
    for (std::size_t index{}; index < Capacity; ++index)
      if (borrowed_[index] != channel_.borrowed_value_quiescent(static_cast<Handle>(index)))
        throw std::logic_error("Route checkpoint borrowed projection corrupted");
    if (!valid_checkpoint(result, barrier_epoch)) throw std::logic_error("Route checkpoint result state corrupted");
    return result;
  }
  // Validates transfer/result state, not RIB installation admissibility. A
  // queued invalid route generation must still receive its ordinary refusal
  // after resume rather than being installed or silently discarded by capture.
  [[nodiscard]] static bool valid_checkpoint(const Checkpoint &saved, std::uint64_t expected_epoch) noexcept {
    if (!Channel::valid_checkpoint(saved, expected_epoch)) return false;
    std::array<bool, Capacity> returned{};
    for (const auto handle : saved.returned) returned[handle] = true;
    for (const auto &slot : saved.occupied)
      if (slot.value.status > RouteInstallStatus::forwarding_failed ||
          returned[slot.handle] == (slot.value.status == RouteInstallStatus::pending)) return false;
    return true;
  }
  // Detached preparation stages every allocation before any channel commit.
  // Invalid result state or failed value copy returns null without mutation.
  [[nodiscard]] static std::unique_ptr<PreparedRestore> prepare_restore(const Checkpoint &saved,
      std::uint64_t expected_epoch) noexcept {
    if (!valid_checkpoint(saved, expected_epoch)) return nullptr;
    auto prepared = Channel::prepare_restore(saved, expected_epoch);
    if (!prepared) return nullptr;
    try { return std::unique_ptr<PreparedRestore>{new PreparedRestore(std::move(prepared))}; }
    catch (...) { return nullptr; }
  }
  // Both owners remain quiescent. One allocation-free commit restores exact
  // values/credits and rebinds consumer pointers into the new slot storage.
  // Stale/consumed preparation refuses before changing this projection.
  [[nodiscard]] bool commit_quiescent(PreparedRestore &prepared, std::uint64_t expected_epoch) noexcept {
    if (!prepared.channel_ || !channel_.commit_quiescent(*prepared.channel_, expected_epoch)) return false;
    for (std::size_t index{}; index < Capacity; ++index)
      borrowed_[index] = channel_.borrowed_value_quiescent(static_cast<Handle>(index));
    return true;
  }
  // Quiescent coordinator only. Rebind an already reserved producer edit after
  // restore, before producer resume. No acquisition or credit change occurs.
  [[nodiscard]] RouteGeneration *editing_generation_quiescent(Handle handle) noexcept {
    auto *publication = channel_.editing_value_quiescent(handle);
    return publication ? &publication->routes : nullptr;
  }
private:
  Channel channel_;
  std::array<Publication *, Capacity> borrowed_{}; // consumer only
};
using RoutePublication = RoutePublicationChannel<2U>;
} // namespace router::routing
