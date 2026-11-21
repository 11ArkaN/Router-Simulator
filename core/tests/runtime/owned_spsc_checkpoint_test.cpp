// Detached staging preserves five ownership roles and prepares every value
// before commit. Large fixed payloads exceed the default stack deliberately;
// capture and restore must construct them directly in their heap destinations.

#include "router/owned_spsc_channel.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>
#include <vector>

void owned_spsc_checkpoint_tests() {
  using Channel = router::protocol::OwnedSpscChannel<std::vector<std::uint64_t>, 6U, true>;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("Owned channel checkpoint invariant at " + std::to_string(where.line()));
  };
  auto source = std::make_unique<Channel>();
  for (std::uint64_t value{}; value < 4U; ++value) {
    const auto lease = source->acquire();
    require(lease.has_value());
    lease->value->assign(3U, value);
    require(source->publish(lease->handle));
  }
  const auto first = source->receive();
  require(first && source->release(first->handle));
  auto held = source->receive();
  require(held.has_value());
  const auto held_handle = held->handle;
  held.reset();
  const auto edit = source->acquire();
  require(edit.has_value());
  edit->value->assign(2U, 99U);
  const auto edit_handle = edit->handle;
  const auto saved = source->checkpoint_quiescent(91U);
  require(saved.available.size() == 1U && saved.ready.size() == 2U && saved.borrowed.size() == 1U &&
      saved.returned.size() == 1U && saved.editing.size() == 1U && saved.occupied.size() == 5U);
  auto restored = std::make_unique<Channel>();
  auto detached = saved;
  auto prepared = Channel::prepare_restore(detached, 91U);
  detached.occupied[0U].value[0U] = 999U; // Prepared values must own a complete independent copy.
  require(prepared && !restored->commit_quiescent(*prepared, 92U));
  source.reset();
  require(restored->commit_quiescent(*prepared, 91U) && !restored->commit_quiescent(*prepared, 91U));
  require(restored->borrowed_value_quiescent(held_handle) && *restored->borrowed_value_quiescent(held_handle) ==
      std::vector<std::uint64_t>(3U, 1U) && !restored->borrowed_value_quiescent(edit_handle));
  for (unsigned invalid{}; invalid < 10U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: ++bad.barrier_epoch; break;
      case 2U: ++bad.capacity; break;
      case 3U: bad.with_completions = false; break;
      case 4U: bad.editing[0U] = bad.borrowed[0U]; break;
      case 5U: bad.returned[0U] = 6U; break;
      case 6U: bad.ready.clear(); break;
      case 7U: bad.occupied.pop_back(); break;
      case 8U: bad.occupied[1U].handle = bad.occupied[0U].handle; break;
      default: bad.available[0U] = bad.editing[0U]; break;
    }
    require(!Channel::valid_checkpoint(bad, 91U) && !Channel::prepare_restore(bad, 91U));
  }
  auto *continued_edit = restored->editing_value_quiescent(edit_handle);
  require(continued_edit && *continued_edit == std::vector<std::uint64_t>(2U, 99U));
  continued_edit->push_back(100U);
  require(restored->publish(edit_handle) && !restored->editing_value_quiescent(edit_handle));
  const auto receipt = restored->completion();
  require(receipt && *receipt->value == std::vector<std::uint64_t>(3U, 0U));
  const auto reused = restored->acquire();
  require(reused && reused->handle == saved.returned[0U] && reused->value->empty() && restored->cancel(reused->handle));
  require(restored->release(held_handle));
  for (std::uint64_t expected{2U}; expected < 4U; ++expected) {
    const auto value = restored->receive();
    require(value && *value->value == std::vector<std::uint64_t>(3U, expected) && restored->release(value->handle));
  }
  const auto edited = restored->receive();
  require(edited && *edited->value == std::vector<std::uint64_t>{99U, 99U, 100U} && restored->release(edited->handle));
  for (std::uint64_t expected{1U}; expected < 4U; ++expected) {
    const auto value = restored->completion();
    require(value && *value->value == std::vector<std::uint64_t>(3U, expected));
  }
  const auto edited_result = restored->completion();
  require(edited_result && *edited_result->value == std::vector<std::uint64_t>{99U, 99U, 100U});
  require(!restored->receive() && !restored->completion() && restored->checkpoint_quiescent(92U).occupied.empty());

  using Ingress = router::protocol::OwnedSpscChannel<std::vector<std::uint64_t>, 1U>;
  auto incoming = std::make_unique<Ingress>();
  const auto payload = incoming->acquire();
  require(payload.has_value());
  payload->value->assign(4U, 17U);
  require(incoming->publish(payload->handle));
  const auto consumed = incoming->receive();
  require(consumed && incoming->release(consumed->handle));
  auto cold = Ingress::prepare_restore(incoming->checkpoint_quiescent(93U), 93U);
  incoming.reset(); incoming = std::make_unique<Ingress>();
  require(cold && incoming->commit_quiescent(*cold, 93U));
  const auto next = incoming->acquire();
  require(next && next->value->empty() && incoming->cancel(next->handle));

  struct Large { std::array<std::uint8_t, 2U * 1024U * 1024U> bytes{}; };
  using LargeChannel = router::protocol::OwnedSpscChannel<Large, 1U, true>;
  auto large = std::make_unique<LargeChannel>();
  const auto large_edit = large->acquire();
  require(large_edit.has_value());
  large_edit->value->bytes.front() = 7U;
  large_edit->value->bytes.back() = 11U;
  require(large->publish(large_edit->handle));
  auto large_saved = large->checkpoint_quiescent(94U);
  auto large_prepared = LargeChannel::prepare_restore(large_saved, 94U);
  require(large_prepared != nullptr);
  large.reset(); large = std::make_unique<LargeChannel>();
  require(large->commit_quiescent(*large_prepared, 94U));
  const auto large_result = large->receive();
  require(large_result && large_result->value->bytes.front() == 7U && large_result->value->bytes.back() == 11U &&
      large->release(large_result->handle) && large->completion().has_value());
  struct FailingCopy {
    bool reject{};
    FailingCopy() noexcept = default;
    FailingCopy(const FailingCopy &other) : reject(other.reject) {
      if (reject) throw std::runtime_error("Injected cold-copy failure");
    }
    FailingCopy(FailingCopy &&) noexcept = default;
    FailingCopy &operator=(FailingCopy &&) noexcept = default;
  };
  using FailingChannel = router::protocol::OwnedSpscChannel<FailingCopy, 1U>;
  FailingChannel failure;
  const auto failure_edit = failure.acquire();
  require(failure_edit.has_value());
  auto failing_saved = failure.checkpoint_quiescent(95U);
  failing_saved.occupied[0U].value.reject = true;
  require(!FailingChannel::prepare_restore(failing_saved, 95U) &&
      failure.editing_value_quiescent(failure_edit->handle) &&
      !failure.editing_value_quiescent(failure_edit->handle)->reject && failure.cancel(failure_edit->handle));

}
