// PMTU tests exercise reduction-only network input, correlated upward probes,
// minimum-MTU attack resistance, path keys and bounded-resource exhaustion.

#include "router/ipv6_path_mtu.hpp"

#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ipv6_path_mtu_tests() {
  using namespace router::ip;
  const auto parsed = parse_ipv6("2001:db8::1");
  require(parsed.has_value(), "PMTU fixture address is invalid");
  constexpr std::uint64_t interface_id = 11U;
  constexpr std::uint32_t first_hop_mtu = 9'000U;
  const auto now = Ipv6PathMtuCache::Clock::now();
  Ipv6PathMtuCache cache;
  require(cache.estimate(*parsed, interface_id, first_hop_mtu) ==
              first_hop_mtu &&
              cache.update(*parsed, interface_id, 1'500U, first_hop_mtu,
                           now) == PathMtuUpdate::decreased &&
              cache.estimate(*parsed, interface_id, first_hop_mtu) == 1'500U,
          "PTB did not reduce the destination PMTU");
  require(cache.update(*parsed, interface_id, 2'000U, first_hop_mtu, now) ==
              PathMtuUpdate::unchanged &&
              cache.estimate(*parsed, interface_id, first_hop_mtu) == 1'500U,
          "larger PTB improperly raised a PMTU estimate");
  require(cache.update(*parsed, interface_id, 1'279U, first_hop_mtu, now) ==
              PathMtuUpdate::invalid_report &&
              cache.begin_probe(*parsed, interface_id, first_hop_mtu,
                                first_hop_mtu,
                                now + std::chrono::minutes{5}) == 1'500U &&
              cache.begin_probe(
                  *parsed, interface_id, first_hop_mtu, 1'400U,
                  now + router::device_catalog::ipv6_pmtu_probe_interval) ==
                  1'500U &&
              cache.begin_probe(
                  *parsed, interface_id, first_hop_mtu, 2'000U,
                  now + router::device_catalog::ipv6_pmtu_probe_interval) ==
                  2'000U &&
              cache.estimate(*parsed, interface_id, first_hop_mtu) == 1'500U,
          "PMTU minimum or generated probe interval was ignored");
  require(cache.confirm_probe(
              *parsed, interface_id,
              now + router::device_catalog::ipv6_pmtu_probe_interval +
                  std::chrono::seconds{1}) &&
              cache.estimate(*parsed, interface_id, first_hop_mtu) == 2'000U &&
              !cache.confirm_probe(*parsed, interface_id, now),
          "a correlated successful IPv6 probe did not publish its size once");
  require(cache.estimate(*parsed, interface_id + 1U, first_hop_mtu) ==
              first_hop_mtu,
          "PMTU entry leaked across interface identities");

  cache.clear();
  for (std::size_t index = 0;
       index < router::device_catalog::ipv6_pmtu_entries_per_endpoint;
       ++index) {
    auto destination = *parsed;
    destination[14] = static_cast<std::uint8_t>(index >> 8U);
    destination[15] = static_cast<std::uint8_t>(index);
    require(cache.update(destination, interface_id, 1'500U, first_hop_mtu,
                         now) == PathMtuUpdate::decreased,
            "PMTU cache exhausted before its generated capacity");
  }
  auto overflow = *parsed;
  overflow[13] = 1U;
  require(cache.update(overflow, interface_id, 1'500U, first_hop_mtu, now) ==
              PathMtuUpdate::resource_exhausted,
          "full PMTU cache silently evicted an active path");
  cache.remove_interface(interface_id);
  require(cache.size() == 0U, "interface removal retained PMTU entries");

  const auto restored_now = now + std::chrono::seconds{1};
  require(cache.update(*parsed, interface_id, 1'400U, 1'500U, now) ==
              PathMtuUpdate::decreased,
          "checkpoint fixture could not install a PMTU entry");
  const auto checkpoint = cache.checkpoint(restored_now);
  Ipv6PathMtuCache restored;
  require(restored.restore(checkpoint, restored_now) &&
              restored.estimate(*parsed, interface_id, 1'500U) == 1'400U &&
              restored.begin_probe(*parsed, interface_id, 1'500U, 1'500U,
                                   restored_now) == 1'400U,
          "PMTU checkpoint did not preserve estimate and deadline");
  auto duplicate = checkpoint;
  duplicate.push_back(checkpoint.front());
  require(!Ipv6PathMtuCache::validate_checkpoint(duplicate),
          "duplicate PMTU checkpoint key was accepted");
}
