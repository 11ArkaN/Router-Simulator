// A logical LAN interface owns independently scheduled L1/L2 circuits on one
// control shard. Effective configuration moves into those owners once; shared
// identity is immutable and no received neighbor data enters cold admission.

#pragma once

#include "router/isis_lan_circuit.hpp"

namespace router::isis {
struct LanCircuitProgram {
  std::array<std::optional<LanCircuitConfiguration>, 2U> levels;
  bool operator==(const LanCircuitProgram &) const = default;
};
class LanCircuitPair final {
public:
  // At least one resolved level and explicit L1/L2 update groups are required.
  // All levels share interface/instance identity, local addresses, NLPIDs and
  // area data. Per-level priority and Hello timing remain independent. Circuit
  // IDs are nonzero and each present level has a positive neighbor budget.
  // Invalid input/allocation throws before this aggregate can be published.
  LanCircuitPair(LanCircuitProgram program, std::uint64_t random_state,
      LanCircuit::Clock::time_point now);
  LanCircuitPair(const LanCircuitPair &) = delete;
  LanCircuitPair &operator=(const LanCircuitPair &) = delete;
  LanCircuitPair(LanCircuitPair &&) noexcept = default;
  LanCircuitPair &operator=(LanCircuitPair &&) noexcept = default;
  // Same owner only. Borrow lasts until a move or destruction. An absent or
  // invalid level returns nullptr; zero selects L1, one L2. No allocation.
  [[nodiscard]] LanCircuit *at(std::size_t level) noexcept;
  [[nodiscard]] const LanCircuit *at(std::size_t level) const noexcept;
  // Nonempty construction guarantees this reference. No mutable config escapes.
  [[nodiscard]] const LanCircuitConfiguration &common() const noexcept;
  [[nodiscard]] Levels levels() const noexcept;
  // Compare complete effective values without copying or resetting live state.
  [[nodiscard]] bool matches(const LanCircuitProgram &program) const noexcept;
private:
  std::array<std::optional<LanCircuit>, 2U> circuits_;
};
} // namespace router::isis
