// Allocator-owner concurrency and failure tests. The fake changes only its
// reported extent, allowing exact step and epoch assertions without reserving
// hundreds of MiB in every native test process.

#include "router/runtime_memory_growth.hpp"

#include <cstddef>
#include <stdexcept>
#include <thread>

namespace {
struct FakeMemory {
  std::size_t size{};
  std::size_t calls{};
  bool fail{};
};

bool resize_fake(std::size_t target, std::size_t &actual,
                 void *context) noexcept {
  auto &memory = *static_cast<FakeMemory *>(context);
  ++memory.calls;
  if (memory.fail)
    return false;
  memory.size = target;
  actual = memory.size;
  return true;
}
} // namespace

void runtime_memory_growth_tests() {
  using router::lab::MemoryReserveResult;
  using router::lab::RuntimeMemoryGrowth;

  constexpr std::size_t mebibyte = 1024U * 1024U;
  FakeMemory memory{320U * mebibyte};
  RuntimeMemoryGrowth owner(memory.size, 1024U * mebibyte, 64U * mebibyte,
                            resize_fake, &memory);

  // A request just beyond the baseline commits exactly one configured step,
  // while a larger request performs repeated steps rather than one geometric
  // over-allocation hidden inside the owner.
  if (owner.reserve(320U * mebibyte + 1U) != MemoryReserveResult::grown ||
      owner.size() != 384U * mebibyte || owner.epoch() != 1U ||
      memory.calls != 1U)
    throw std::runtime_error("memory owner did not publish one linear step");
  if (owner.reserve(500U * mebibyte) != MemoryReserveResult::grown ||
      owner.size() != 512U * mebibyte || owner.epoch() != 3U ||
      memory.calls != 3U)
    throw std::runtime_error("memory owner skipped a linear growth generation");

  // The checkpoint phase rejects growth without invoking the platform. Packet
  // owners are not represented here because they continue independently and
  // have no dependency on this control-only coordinator.
  if (!owner.begin_checkpoint() ||
      owner.reserve(513U * mebibyte) !=
          MemoryReserveResult::checkpoint_active ||
      memory.calls != 3U)
    throw std::runtime_error("checkpoint admitted a concurrent memory grow");
  owner.end_checkpoint();

  // Calls from another pthread are rejected before touching the callback. A
  // protocol shard therefore cannot silently become a second allocator owner.
  MemoryReserveResult foreign_result{MemoryReserveResult::unchanged};
  std::thread foreign([&] {
    foreign_result = owner.reserve(513U * mebibyte);
  });
  foreign.join();
  if (foreign_result != MemoryReserveResult::owner_violation ||
      memory.calls != 3U)
    throw std::runtime_error("foreign pthread requested shared memory growth");

  memory.fail = true;
  if (owner.reserve(513U * mebibyte) != MemoryReserveResult::growth_failed ||
      owner.size() != 512U * mebibyte || owner.epoch() != 3U)
    throw std::runtime_error("failed memory growth changed the published extent");
  if (owner.reserve(1024U * mebibyte + 1U) !=
      MemoryReserveResult::maximum_exceeded)
    throw std::runtime_error("memory owner accepted a request above 1 GiB");
}
