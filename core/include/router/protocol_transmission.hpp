// One protocol owner tracks one outstanding transmission class on one circuit.
// Tickets correlate actual egress receipts without retaining frames or keys.
// This local state is never mutated by forwarding or another control shard.

#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>

namespace router::protocol {
class TransmissionWindow final {
public:
  // Epoch and ticket high-water marks are nonzero checkpoint-owned values.
  // Invalid construction throws before publication. No allocation occurs.
  explicit TransmissionWindow(std::uint64_t epoch, std::uint64_t next_ticket = 1U)
      : epoch_(epoch), next_ticket_(next_ticket) {
    if (!epoch || !next_ticket) throw std::invalid_argument("Protocol transmission identity cannot be zero");
  }
  TransmissionWindow(const TransmissionWindow &) = delete;
  TransmissionWindow &operator=(const TransmissionWindow &) = delete;
  TransmissionWindow(TransmissionWindow &&) noexcept = default;
  TransmissionWindow &operator=(TransmissionWindow &&) noexcept = default;
  // Reserves exactly one ticket. Pending work or exhausted ticket space rejects
  // without mutation; the caller must report exhaustion and stop this class.
  [[nodiscard]] std::optional<std::uint64_t> begin() noexcept {
    if (pending_ || next_ticket_ == std::numeric_limits<std::uint64_t>::max()) return std::nullopt;
    pending_ = next_ticket_++;
    return pending_;
  }
  // Accept only the exact current reservation. The caller applies protocol
  // effects after true, using the receipt's actual enqueue result separately.
  [[nodiscard]] bool complete(std::uint64_t epoch, std::uint64_t ticket) noexcept {
    if (epoch != epoch_ || !pending_ || ticket != pending_) return false;
    pending_ = 0U;
    return true;
  }
  // Operational cancellation, such as losing DIS role, preserves ticket
  // progression even when the configuration epoch does not change.
  void cancel() noexcept { pending_ = 0U; }
  // Configuration replacement requires a strictly newer epoch. Old receipts
  // remain invalid even if their original frame bytes equal new output.
  [[nodiscard]] bool replace(std::uint64_t epoch) noexcept {
    if (epoch <= epoch_) return false;
    epoch_ = epoch;
    cancel();
    return true;
  }
  [[nodiscard]] std::uint64_t epoch() const noexcept { return epoch_; }
  [[nodiscard]] std::uint64_t next_ticket() const noexcept { return next_ticket_; }
  [[nodiscard]] bool pending() const noexcept { return pending_ != 0U; }
private:
  std::uint64_t epoch_{};
  std::uint64_t next_ticket_{};
  std::uint64_t pending_{};
};
} // namespace router::protocol
