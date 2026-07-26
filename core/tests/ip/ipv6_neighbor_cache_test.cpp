// Neighbor Cache tests exercise RFC 4861 state transitions against explicit
// steady-clock points. They validate emitted actions instead of depending on a
// sleeping thread or simulated global time.

#include "router/ipv6_neighbor_cache.hpp"

#include <array>
#include <memory>
#include <stdexcept>

void ipv6_neighbor_cache_tests() {
  using namespace router::lab;
  using Clock = Ipv6NeighborCache::Clock;
  const auto neighbor = router::ip::parse_ipv6("2001:db8:1::2");
  if (!neighbor)
    throw std::runtime_error("Neighbor Cache test address setup failed");
  const router::packet::Mac first_mac{0x02, 0, 0, 0, 0, 2};
  const router::packet::Mac second_mac{0x02, 0, 0, 0, 0, 3};
  const auto start = Clock::time_point{} + std::chrono::seconds(10);
  auto cache = std::make_unique<Ipv6NeighborCache>();

  const auto initial = cache->resolve(4, *neighbor, start);
  if (initial.status != Ipv6ResolutionStatus::solicitation_required ||
      cache->size() != 1) {
    throw std::runtime_error("Neighbor resolution did not start INCOMPLETE");
  }
  const auto pending = cache->resolve(4, *neighbor, start);
  if (pending.status != Ipv6ResolutionStatus::pending) {
    throw std::runtime_error("INCOMPLETE neighbor was used for forwarding");
  }

  // An output-capacity failure must leave the retransmission deadline due.
  // The next owner turn can then emit the action without losing a solicitation.
  if (cache->poll(start + router::device_catalog::nd_retrans_timer,
                  std::span<Ipv6NeighborAction>{}) != 0 ||
      cache->next_deadline() !=
          start + router::device_catalog::nd_retrans_timer) {
    throw std::runtime_error("ND action backpressure lost a due probe");
  }

  std::array<Ipv6NeighborAction, 4> actions{};
  const auto retry_count = cache->poll(
      start + router::device_catalog::nd_retrans_timer, actions);
  if (retry_count != 1 ||
      actions[0].kind != Ipv6NeighborActionKind::multicast_solicitation) {
    throw std::runtime_error("INCOMPLETE neighbor did not retransmit NS");
  }

  const auto advertisement_time =
      start + router::device_catalog::nd_retrans_timer * 2;
  if (!cache->receive_advertisement(
          4, *neighbor, first_mac, true, true, true,
          false,
          router::device_catalog::nd_base_reachable_time,
          advertisement_time)) {
    throw std::runtime_error("Solicited NA did not resolve neighbor");
  }
  const auto resolved = cache->resolve(4, *neighbor, advertisement_time);
  const auto reachable = cache->find(4, *neighbor);
  if (resolved.status != Ipv6ResolutionStatus::resolved ||
      resolved.mac != first_mac || !reachable ||
      reachable->state != Ipv6NeighborState::reachable ||
      !reachable->is_router) {
    throw std::runtime_error("Resolved neighbor did not become REACHABLE");
  }

  // A conflicting NA with Override clear cannot replace the MAC. It changes a
  // REACHABLE entry to STALE so ordinary NUD can verify the cached mapping.
  if (!cache->receive_advertisement(
          4, *neighbor, second_mac, false, false, true,
          false,
          router::device_catalog::nd_base_reachable_time,
          advertisement_time) ||
      !cache->find(4, *neighbor) ||
      cache->find(4, *neighbor)->mac != first_mac ||
      cache->find(4, *neighbor)->state != Ipv6NeighborState::stale) {
    throw std::runtime_error("NA Override semantics changed neighbor MAC");
  }

  // Using STALE data is allowed immediately and starts DELAY. When DELAY
  // expires, the owner emits a unicast probe to the cached link-layer address.
  const auto delayed = cache->resolve(4, *neighbor, advertisement_time);
  if (delayed.status != Ipv6ResolutionStatus::resolved ||
      cache->find(4, *neighbor)->state != Ipv6NeighborState::delay) {
    throw std::runtime_error("STALE neighbor did not enter DELAY on use");
  }
  const auto probe_count = cache->poll(
      advertisement_time + router::device_catalog::nd_delay_first_probe,
      actions);
  if (probe_count != 1 ||
      actions[0].kind != Ipv6NeighborActionKind::unicast_solicitation ||
      actions[0].mac != first_mac ||
      cache->find(4, *neighbor)->state != Ipv6NeighborState::probe) {
    throw std::runtime_error("DELAY neighbor did not begin unicast probing");
  }

  if (!cache->confirm_reachability(
          4, *neighbor, router::device_catalog::nd_base_reachable_time,
          advertisement_time +
              router::device_catalog::nd_delay_first_probe)) {
    throw std::runtime_error("Upper-layer confirmation was ignored");
  }
  if (cache->find(4, *neighbor)->state != Ipv6NeighborState::reachable) {
    throw std::runtime_error("Confirmed neighbor did not return REACHABLE");
  }

  // A checkpoint stores duration, not a steady-clock epoch. Restoring at a
  // different base must preserve state and schedule expiry relative to that
  // new owner clock.
  const auto checkpoint = cache->checkpoint(
      advertisement_time + router::device_catalog::nd_delay_first_probe);
  auto restored = std::make_unique<Ipv6NeighborCache>();
  const auto restore_time = start + std::chrono::hours(2);
  if (!Ipv6NeighborCache::validate_checkpoint(checkpoint) ||
      !restored->restore(checkpoint, restore_time) ||
      restored->size() != cache->size() ||
      !restored->find(4, *neighbor) ||
      restored->find(4, *neighbor)->state !=
          Ipv6NeighborState::reachable) {
    throw std::runtime_error("Neighbor Cache checkpoint lost live NUD state");
  }

  auto invalid_checkpoint = checkpoint;
  invalid_checkpoint.front().state = Ipv6NeighborState::stale;
  invalid_checkpoint.front().has_deadline = false;
  if (Ipv6NeighborCache::validate_checkpoint(invalid_checkpoint) ||
      restored->restore(invalid_checkpoint, restore_time)) {
    throw std::runtime_error("Invalid NUD timer shape passed checkpoint validation");
  }

  const auto learned = router::ip::parse_ipv6("2001:db8:1::3");
  if (!learned ||
      !cache->learn_stale(4, *learned, second_mac, false, start) ||
      cache->find(4, *learned)->state != Ipv6NeighborState::stale) {
    throw std::runtime_error("Validated ND option did not create STALE entry");
  }

  // The cache is a second validation boundary below the ND decoder. A future
  // caller must not be able to install an unusable all-zero or multicast MAC
  // even if it bypasses packet-option validation by mistake.
  const router::packet::Mac zero_mac{};
  const router::packet::Mac multicast_mac{0x33, 0x33, 0, 0, 0, 1};
  if (cache->learn_stale(4U, *learned, zero_mac, false, start) ||
      cache->learn_stale(4U, *learned, multicast_mac, false, start))
    throw std::runtime_error("neighbor cache accepted an unusable MAC");

  const auto configured = router::ip::parse_ipv6("2001:db8:1::44");
  auto configured_cache = std::make_unique<Ipv6NeighborCache>();
  if (!configured ||
      !configured_cache->install_static(4U, *configured, first_mac))
    throw std::runtime_error("static IPv6 neighbor could not be installed");
  const auto static_resolution =
      configured_cache->resolve(4U, *configured, start);
  const auto static_snapshot = configured_cache->find(4U, *configured);
  if (static_resolution.status != Ipv6ResolutionStatus::resolved ||
      static_resolution.mac != first_mac || !static_snapshot ||
      !static_snapshot->is_static || configured_cache->poll(
          start + std::chrono::hours{24}, actions) != 0U)
    throw std::runtime_error("static IPv6 neighbor entered NUD");
  if (!configured_cache->receive_advertisement(
          4U, *configured, second_mac, true, true, false,
          false,
          router::device_catalog::nd_base_reachable_time, start) ||
      configured_cache->find(4U, *configured)->mac != first_mac)
    throw std::runtime_error("received NA replaced static IPv6 intent");

  // An unknown NA follows RFC 4861 by default. Explicit SR OS interface
  // policy may create the same mapping as STALE, never REACHABLE, because no
  // local solicitation established bidirectional reachability.
  auto policy_cache = std::make_unique<Ipv6NeighborCache>();
  if (policy_cache->receive_advertisement(
          4U, *learned, second_mac, true, true, false, false,
          router::device_catalog::nd_base_reachable_time, start) ||
      policy_cache->find(4U, *learned) ||
      !policy_cache->receive_advertisement(
          4U, *learned, second_mac, true, true, false, true,
          router::device_catalog::nd_base_reachable_time, start) ||
      !policy_cache->find(4U, *learned) ||
      policy_cache->find(4U, *learned)->state !=
          Ipv6NeighborState::stale)
    throw std::runtime_error(
        "unsolicited NA learning did not honor explicit policy");

  // SR OS stale-time is an operational lifetime beyond RFC 4861 NUD. Without
  // proactive refresh its expiry removes the dynamic mapping. Static entries
  // and unrelated interfaces are intentionally outside this timer.
  if (policy_cache->poll(
          start + std::chrono::seconds{
                      router::device_catalog::nd_default_stale_time_seconds},
          actions) != 0U || policy_cache->find(4U, *learned))
    throw std::runtime_error("ordinary STALE entry did not age out");

  // Scope selection is decided by RouterForwarder. Once selected, the cache
  // stores the effective policy with the entry and emits a unicast NUD probe
  // at expiry. A checkpoint must retain both values because it can be restored
  // before control replays interface intent.
  auto proactive_cache = std::make_unique<Ipv6NeighborCache>();
  const auto proactive_stale = std::chrono::seconds{60};
  if (!proactive_cache->learn_stale(4U, *learned, second_mac, false,
                                    start, proactive_stale, true) ||
      proactive_cache->dynamic_size(4U) != 1U ||
      proactive_cache->dynamic_size(5U) != 0U)
    throw std::runtime_error("proactive STALE policy was not installed");
  const auto proactive_checkpoint = proactive_cache->checkpoint(start);
  if (proactive_checkpoint.size() != 1U ||
      proactive_checkpoint.front().stale_time_seconds != 60U ||
      !proactive_checkpoint.front().proactive_refresh)
    throw std::runtime_error("checkpoint lost proactive STALE policy");
  if (proactive_cache->poll(start + proactive_stale, actions) != 1U ||
      actions[0].kind != Ipv6NeighborActionKind::unicast_solicitation ||
      actions[0].address != *learned || actions[0].mac != second_mac ||
      !proactive_cache->find(4U, *learned) ||
      proactive_cache->find(4U, *learned)->state !=
          Ipv6NeighborState::probe)
    throw std::runtime_error("proactive STALE expiry did not probe neighbor");
  const auto static_checkpoint = configured_cache->checkpoint(start);
  auto static_restored = std::make_unique<Ipv6NeighborCache>();
  if (!static_restored->restore(static_checkpoint, restore_time) ||
      !static_restored->find(4U, *configured) ||
      !static_restored->find(4U, *configured)->is_static)
    throw std::runtime_error("checkpoint lost static IPv6 neighbor intent");
  static_cast<void>(configured_cache->learn_stale(4U, *learned, second_mac,
                                                  false, start));
  if (configured_cache->clear_dynamic(4U, *learned) != 1U ||
      configured_cache->clear_dynamic(4U, *learned) != 0U)
    throw std::runtime_error("scoped dynamic clear returned the wrong count");
  if (!configured_cache->find(4U, *configured) ||
      configured_cache->find(4U, *learned))
    throw std::runtime_error("dynamic clear removed a static IPv6 neighbor");
  if (!configured_cache->remove_static(4U, *configured) ||
      configured_cache->remove_static(4U, *configured))
    throw std::runtime_error("static IPv6 neighbor removal was not exact");

  // A fresh cache with no advertisements exhausts MaxMulticastSolicit and
  // produces one explicit failure action before deleting the entry.
  auto failing = std::make_unique<Ipv6NeighborCache>();
  static_cast<void>(failing->resolve(5, *neighbor, start));
  auto deadline = start + router::device_catalog::nd_retrans_timer;
  for (std::uint8_t sent = 1;
       sent < router::device_catalog::nd_max_multicast_solicit; ++sent) {
    if (failing->poll(deadline, actions) != 1 ||
        actions[0].kind !=
            Ipv6NeighborActionKind::multicast_solicitation) {
      throw std::runtime_error("ND multicast retry count is incorrect");
    }
    deadline += router::device_catalog::nd_retrans_timer;
  }
  if (failing->poll(deadline, actions) != 1 ||
      actions[0].kind != Ipv6NeighborActionKind::resolution_failed ||
      failing->size() != 0) {
    throw std::runtime_error("ND resolution exhaustion was not reported");
  }
}
