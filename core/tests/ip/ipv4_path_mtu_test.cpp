// IPv4 PMTU conformance tests cover modern and old-router reports, per-path
// scope, conservative upward probing, resource exhaustion and exact checkpoint
// continuation. Packet quotation authentication belongs to endpoint tests.

#include "router/ipv4_path_mtu.hpp"

#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ipv4_path_mtu_tests() {
  using namespace std::chrono_literals;
  using router::ip::Ipv4PathMtuCache;
  using router::ip::Ipv4PathMtuUpdate;

  const router::packet::Ipv4 destination{198U, 51U, 100U, 7U};
  const auto now = Ipv4PathMtuCache::Clock::now();
  Ipv4PathMtuCache cache;
  require(cache.estimate(destination, 11U, 1'500U) == 1'500U,
          "first-hop MTU is the initial IPv4 PMTU");
  require(cache.update(destination, 11U, 1'280U, 1'500U, 1'500U, now) ==
              Ipv4PathMtuUpdate::decreased &&
              cache.estimate(destination, 11U, 1'500U) == 1'280U,
          "a validated modern report lowers only its path");
  require(cache.estimate(destination, 12U, 1'500U) == 1'500U,
          "interface identity is part of the IPv4 path key");
  require(cache.update(destination, 11U, 1'400U, 1'500U, 1'500U, now) ==
              Ipv4PathMtuUpdate::unchanged,
          "network input cannot raise a learned PMTU");
  require(cache.update(destination, 11U, 67U, 1'500U, 1'500U, now) ==
              Ipv4PathMtuUpdate::invalid_report,
          "IPv4 PMTU never falls below the RFC 791 floor");

  const router::packet::Ipv4 legacy_destination{203U, 0U, 113U, 9U};
  require(cache.update(legacy_destination, 11U, 0U, 1'500U, 1'500U, now) ==
              Ipv4PathMtuUpdate::decreased &&
              cache.estimate(legacy_destination, 11U, 1'500U) == 1'492U,
          "zero Next-Hop MTU selects the next lower RFC 1191 plateau");
  require(cache.begin_probe(destination, 11U, 1'500U, 1'500U,
                            now + 599s) == 1'280U,
          "a PMTU cannot increase before the recommended ten minutes");
  require(cache.begin_probe(destination, 11U, 1'500U, 100U, now + 600s) ==
              1'280U,
          "a short packet cannot prove a larger IPv4 path MTU");
  require(cache.begin_probe(destination, 11U, 1'500U, 1'500U,
                            now + 600s) == 1'492U &&
              cache.estimate(destination, 11U, 1'500U) == 1'280U &&
              cache.begin_probe(destination, 11U, 1'500U, 1'500U,
                                now + 601s) == 1'280U,
          "an unconfirmed upward probe leaked into ordinary traffic");
  require(cache.confirm_probe(destination, 11U, now + 602s) &&
              cache.estimate(destination, 11U, 1'500U) == 1'492U &&
              !cache.confirm_probe(destination, 11U, now + 603s),
          "an exact success did not publish one upward PMTU result");

  const auto checkpoint = cache.checkpoint(now + 603s);
  Ipv4PathMtuCache restored;
  require(restored.restore(checkpoint, now + 1'000s) &&
              restored.estimate(destination, 11U, 1'500U) == 1'492U,
          "checkpoint preserves PMTU and relative probe progress");
  auto duplicate = checkpoint;
  duplicate.push_back(duplicate.front());
  require(!Ipv4PathMtuCache::validate_checkpoint(duplicate),
          "duplicate path keys cannot depend on restore order");

  Ipv4PathMtuCache full;
  for (std::size_t index = 0;
       index < router::device_catalog::ipv4_pmtu_entries_per_endpoint;
       ++index) {
    const router::packet::Ipv4 address{
        10U, static_cast<std::uint8_t>(index >> 8U),
        static_cast<std::uint8_t>(index), 1U};
    require(full.update(address, 1U, 1'280U, 1'500U, 1'500U, now) ==
                Ipv4PathMtuUpdate::decreased,
            "every generated IPv4 PMTU slot is usable");
  }
  require(full.update({192U, 0U, 2U, 1U}, 1U, 1'280U, 1'500U, 1'500U,
                      now) == Ipv4PathMtuUpdate::resource_exhausted,
          "full PMTU storage reports overload instead of allocating");
}
