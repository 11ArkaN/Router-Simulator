// IPsec sequence allocation and inbound anti-replay window. One SAD owner calls
// these objects, so no atomics are required. Inbound check() never mutates the
// window because RFC 4302 and RFC 4303 require integrity verification before a
// packet can advance replay state. commit() is called only after authentication.

#pragma once

#include <cstdint>
#include <optional>

namespace router::ipsec {

enum class ReplayStatus : std::uint8_t {
  admissible,
  zero_sequence,
  duplicate,
  too_old,
  invalid_window,
  sequence_space_exhausted
};

struct ReplayCandidate {
  ReplayStatus status{ReplayStatus::invalid_window};
  // For ESN this is the reconstructed 64-bit value. The received packet carries
  // only low32 on the wire; high32 is also authenticated as specified by the
  // selected integrity or AEAD construction.
  std::uint64_t sequence{};
};

class ReplayWindow final {
public:
  // Width 1 through 64 is represented by one word. Wider release-specific
  // windows can later replace the bitmap without changing check/commit.
  explicit ReplayWindow(std::uint8_t width = 64U,
                        bool extended_sequence_numbers = false) noexcept;

  [[nodiscard]] ReplayCandidate check(std::uint32_t received_low) const noexcept;
  [[nodiscard]] bool commit(std::uint64_t authenticated_sequence) noexcept;

  [[nodiscard]] std::uint64_t highest() const noexcept { return highest_; }
  [[nodiscard]] std::uint64_t bitmap() const noexcept { return bitmap_; }
  [[nodiscard]] std::uint8_t width() const noexcept { return width_; }
  [[nodiscard]] bool extended() const noexcept { return extended_; }

  // Restore validates the serialized invariant before changing live state.
  // Bits outside the configured window are forbidden because they could mark a
  // future valid packet as a replay after checkpoint reconstruction.
  [[nodiscard]] bool restore(std::uint64_t highest,
                             std::uint64_t bitmap) noexcept;

private:
  [[nodiscard]] std::optional<std::uint64_t>
  reconstruct(std::uint32_t received_low) const noexcept;
  [[nodiscard]] std::uint64_t active_mask() const noexcept;

  std::uint64_t highest_{};
  std::uint64_t bitmap_{};
  std::uint8_t width_{};
  bool extended_{};
};

class OutboundSequence final {
public:
  explicit OutboundSequence(bool extended_sequence_numbers = false) noexcept
      : extended_(extended_sequence_numbers) {}

  // next() returns the complete sequence used by integrity processing. The low
  // word is encoded in AH or ESP. nullopt is a hard-SA-expiry signal and must
  // never cause a counter wrap or cleartext fallback.
  [[nodiscard]] std::optional<std::uint64_t> next() noexcept;
  [[nodiscard]] std::uint64_t current() const noexcept { return current_; }
  [[nodiscard]] bool extended() const noexcept { return extended_; }
  [[nodiscard]] bool restore(std::uint64_t current) noexcept;

private:
  std::uint64_t current_{};
  bool extended_{};
};

} // namespace router::ipsec
