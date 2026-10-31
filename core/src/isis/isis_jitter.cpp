// Uniform bounded jitter uses rejection sampling to avoid modulo bias. Each
// process supplies an independently seeded xorshift64* state and retains it.
// Source: iso.10589.2002.periodic_jitter

#include "router/isis_jitter.hpp"

namespace router::isis {

std::optional<std::chrono::microseconds> jittered_interval(
    std::chrono::microseconds base, std::uint64_t &state) noexcept {
  if (base.count() <= 0 || !state) return std::nullopt;
  // Architectural Jitter is 25%. Inclusive endpoints use one additional
  // integer sample; sub-four-microsecond periods retain their single value.
  const auto bound = static_cast<std::uint64_t>(base.count() / 4) + 1U;
  const auto threshold = (std::uint64_t{} - bound) % bound;
  std::uint64_t sample{};
  do {
    state ^= state >> 12U;
    state ^= state << 25U;
    state ^= state >> 27U;
    sample = state * 0x2545f4914f6cdd1dULL;
  } while (sample < threshold);
  return std::chrono::microseconds{base.count() - static_cast<std::int64_t>(sample % bound)};
}

} // namespace router::isis
