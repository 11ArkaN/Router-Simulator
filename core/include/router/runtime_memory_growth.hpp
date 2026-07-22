// Shared WebAssembly memory growth coordinator. The browser runtime Worker is
// the sole allocator owner. Protocol and forwarding pthreads keep using their
// startup-sized arenas and may not call this contract. A checkpoint lease and
// a growth transaction are mutually exclusive without stopping packet owners.

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace router::lab {

enum class MemoryReserveResult : std::uint8_t {
  unchanged,
  grown,
  owner_violation,
  checkpoint_active,
  maximum_exceeded,
  growth_failed,
  invalid_observation,
};

// The callback is deliberately a function pointer instead of std::function.
// Growing memory must never allocate the wrapper that is responsible for
// obtaining more memory. On Wasm it calls emscripten_resize_heap; native tests
// use a deterministic fake with the same target/result contract.
using MemoryResizeFunction = bool (*)(std::size_t requested_size,
                                      std::size_t &resulting_size,
                                      void *context) noexcept;

class RuntimeMemoryGrowth final {
public:
  // initial_size is the actual current WebAssembly extent, not merely the
  // profile default. This matters for test binaries whose initial memory is
  // intentionally larger than the production runtime's 320 MiB baseline.
  RuntimeMemoryGrowth(std::size_t initial_size, std::size_t maximum_size,
                      std::size_t linear_step,
                      MemoryResizeFunction resize_function,
                      void *resize_context) noexcept;

  RuntimeMemoryGrowth(const RuntimeMemoryGrowth &) = delete;
  RuntimeMemoryGrowth &operator=(const RuntimeMemoryGrowth &) = delete;

  // Only the constructing thread may request pages. The operation grows one
  // configured linear step per callback, publishes an epoch after every
  // successful step, and never changes emulator state when the final request
  // cannot be satisfied.
  [[nodiscard]] MemoryReserveResult reserve(std::size_t minimum_size) noexcept;

  // A lease prevents a page request from starting while a checkpoint value
  // graph is being prepared. It does not pause any protocol deadline, packet
  // ring, forwarding owner or link owner.
  [[nodiscard]] bool begin_checkpoint() noexcept;
  void end_checkpoint() noexcept;

  // The owner calls observe after operations that may allocate through the C
  // runtime. This keeps JavaScript safe even if the standard allocator used
  // already committed pages while servicing an owner-affine operation.
  [[nodiscard]] MemoryReserveResult
  observe_owner_allocation(std::size_t actual_size) noexcept;

  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::uint32_t epoch() const noexcept;
  [[nodiscard]] bool growth_in_progress() const noexcept;

private:
  enum class Phase : std::uint8_t { idle, growing, checkpoint };

  [[nodiscard]] bool is_owner() const noexcept;
  [[nodiscard]] MemoryReserveResult
  publish_size(std::size_t actual_size) noexcept;

  const std::thread::id owner_;
  const std::size_t maximum_size_;
  const std::size_t linear_step_;
  const MemoryResizeFunction resize_function_;
  void *const resize_context_;
  std::atomic<std::size_t> size_;
  std::atomic<std::uint32_t> epoch_{};
  std::atomic<Phase> phase_{Phase::idle};
};

} // namespace router::lab
