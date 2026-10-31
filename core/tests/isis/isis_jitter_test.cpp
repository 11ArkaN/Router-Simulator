// Fixed seeds make timer distribution checks repeatable. Fixtures verify the
// normative range and continued draws rather than matching PRNG internals.

#include "router/isis_jitter.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_jitter_tests() {
  using namespace std::chrono_literals;
  std::uint64_t state = 0x123456789abcdef1ULL;
  const auto saved = state;
  require(!router::isis::jittered_interval(0us, state) && state == saved &&
            !router::isis::jittered_interval(-1us, state) && state == saved,
          "IS-IS invalid timer base changed PRNG state");
  std::uint64_t zero{};
  require(!router::isis::jittered_interval(1s, zero) && !zero, "IS-IS accepted an unseeded periodic timer");
  for (const auto base : {1000us, 5'000'000us, 10'000'000us, 1'200'000'000us}) {
    std::array<unsigned, 4U> bins{};
    const auto width = base.count() / 4;
    for (unsigned draw = 0U; draw < 20'000U; ++draw) {
      const auto before = state;
      const auto period = router::isis::jittered_interval(base, state);
      require(period && state != before && *period <= base && period->count() >= base.count() - width,
              "IS-IS periodic timer escaped the 25 percent reduction range");
      const auto bin = std::min<std::size_t>(3U,
          static_cast<std::size_t>((base.count() - period->count()) * 4 / (width + 1)));
      ++bins[bin];
    }
    require(std::all_of(bins.begin(), bins.end(), [](auto count) { return count > 4500U && count < 5500U; }),
            "IS-IS periodic timer draws are not distributed across the jitter range");
  }
  auto continuation = state;
  const auto first = router::isis::jittered_interval(10s, state);
  require(first == router::isis::jittered_interval(10s, continuation) && state == continuation,
          "IS-IS PRNG continuation did not reproduce its next timer draw");
}
