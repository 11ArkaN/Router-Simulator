// P2P owner tests keep ISO adjacency and RFC 5303 state distinct and verify
// that rejected wire projections cannot extend an accepted holding deadline.

#include "router/isis_p2p_adjacency.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
router::packet::isis::TlvView option(std::array<std::uint8_t, 17U> &storage,
                                    const router::isis::ThreeWayOption &value) {
  router::packet::isis::TlvWriter writer(storage);
  require(router::isis::encode_three_way(writer, value), "IS-IS P2P option fixture failed");
  router::packet::isis::TlvCursor cursor(writer.bytes());
  return *cursor.next();
}
}

void isis_p2p_adjacency_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = PointToPointAdjacency::Clock::time_point{100s};
  const SystemId system_a{1U, 2U, 3U, 4U, 5U, 6U};
  const SystemId system_b{1U, 2U, 3U, 4U, 5U, 7U};
  const router::packet::Mac mac_a{2U, 0U, 0U, 0U, 0U, 1U};
  const router::packet::Mac mac_b{2U, 0U, 0U, 0U, 0U, 2U};
  const P2pLocal local_a{system_a, 1001U, 3U, Levels::both, true};
  const P2pLocal local_b{system_b, 1002U, 9U, Levels::both, true};
  PointToPointAdjacency a(local_a);
  PointToPointAdjacency b(local_b);
  HelloView hello_a{system_a, 30U, 3U, 3U, 0U, {}};
  HelloView hello_b{system_b, 30U, 3U, 9U, 0U, {}};
  std::array<std::uint8_t, 17U> encoded{};
  require(!a.ready() && !a.deadline() && a.outbound_three_way().state == ThreeWayState::down,
          "IS-IS P2P did not start Down without a peer");
  auto result = a.receive(hello_b, mac_b, true, true, option(encoded, b.outbound_three_way()), now);
  require(result.outcome == P2pOutcome::initializing && result.holding_refreshed && !a.ready() &&
            a.snapshot().present && !a.snapshot().iso_up && a.deadline() == now + 30s &&
            a.outbound_three_way().neighbor_system == system_b &&
            a.outbound_three_way().neighbor_circuit == 1002U,
          "IS-IS first three-way Hello incorrectly raised ISO adjacency");
  PointToPointAdjacency restored_a(local_a);
  const auto rebased = PointToPointAdjacency::Clock::time_point{9000s};
  const auto initializing_saved = a.checkpoint(now + 500ms);
  require(restored_a.restore(initializing_saved, rebased) && !restored_a.ready() &&
      restored_a.deadline() == rebased + 29500ms, "IS-IS initializing checkpoint lost fractional holding time");
  result = b.receive(hello_a, mac_a, true, true, option(encoded, a.outbound_three_way()), now);
  require(result.outcome == P2pOutcome::up && b.ready() && result.forwarding_readiness_changed,
          "IS-IS peer did not recognize its echoed three-way identity");
  result = a.receive(hello_b, mac_b, true, true, option(encoded, b.outbound_three_way()), now);
  require(result.outcome == P2pOutcome::up && a.ready(), "IS-IS three-way handshake did not converge");
  require(restored_a.receive(hello_b, mac_b, true, true, option(encoded, b.outbound_three_way()), rebased).outcome ==
      P2pOutcome::up && restored_a.ready(), "IS-IS restored initializing handshake did not converge");
  const auto accepted_saved = a.checkpoint(now + 1500ms);
  require(restored_a.restore(accepted_saved, rebased), "IS-IS Up checkpoint refused");
  for (unsigned invalid{}; invalid < 10U; ++invalid) {
    auto bad = accepted_saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: ++bad.local.extended_circuit; break;
      case 2U: bad.state.usage = Levels::none; break;
      case 3U: bad.state.three_way = static_cast<ThreeWayState>(3U); break;
      case 4U: bad.state.three_way = ThreeWayState::down; break;
      case 5U: bad.state.iso_up = false; break;
      case 6U: bad.state.present = false; break;
      case 7U: bad.holding_nanoseconds.reset(); break;
      case 8U: bad.holding_nanoseconds = 65535000000001LL; break;
      default: bad.state.uses_three_way = false; break;
    }
    require(!restored_a.restore(bad, rebased) && restored_a.ready() &&
        restored_a.deadline() == rebased + 28500ms, "IS-IS malformed P2P checkpoint mutated live state");
  }
  require(!restored_a.restore(accepted_saved, PointToPointAdjacency::Clock::time_point::max()),
      "IS-IS P2P holding restore overflow accepted");
  require(restored_a.expire(rebased + 28499ms).outcome == P2pOutcome::discarded &&
      restored_a.expire(rebased + 28500ms).reason == P2pReason::holding_expired,
      "IS-IS restored holding expiry changed");
  require(restored_a.restore(a.checkpoint(now + 31s), rebased) &&
      restored_a.expire(rebased).reason == P2pReason::holding_expired, "IS-IS due holding time resurrected");
  const auto empty_saved = restored_a.checkpoint(rebased);
  require(restored_a.restore(empty_saved, rebased) && !restored_a.deadline(), "IS-IS empty P2P restore failed");
  const auto holding = a.deadline();
  auto wrong = b.outbound_three_way();
  wrong.neighbor_circuit = 999U;
  result = a.receive(hello_b, mac_b, true, true, option(encoded, wrong), now + 20s);
  require(result.outcome == P2pOutcome::discarded && !result.holding_refreshed && a.deadline() == holding && a.ready(),
          "IS-IS mismatched echoed circuit refreshed or changed the adjacency");
  auto stranger = hello_b;
  ++stranger.source.back();
  result = a.receive(stranger, mac_b, true, true, option(encoded, b.outbound_three_way()), now + 25s);
  require(result.reason == P2pReason::different_lan_neighbor && a.deadline() == holding,
          "IS-IS P2P-over-LAN accepted a second neighbor");
  require(a.expire(now + 29s).outcome == P2pOutcome::discarded &&
            a.expire(now + 30s).reason == P2pReason::holding_expired && !a.snapshot().present && !a.ready(),
          "IS-IS rejected Hellos postponed holding expiry");

  // An Initialize action emits no ISO Down event, while three-way readiness
  // is withheld until the neighbor confirms the new handshake.
  wrong = {ThreeWayState::down, 1001U, std::nullopt, std::nullopt};
  result = b.receive(hello_a, mac_a, true, true, option(encoded, wrong), now + 1s);
  require(result.outcome == P2pOutcome::initializing && b.snapshot().iso_up && !b.ready() &&
            result.forwarding_readiness_changed, "IS-IS conflated Initialize with ISO Down or usable Up");
  require(b.circuit_down().reason == P2pReason::circuit_down && !b.snapshot().present &&
            b.circuit_down().outcome == P2pOutcome::discarded,
          "IS-IS circuit-down did not delete exactly one adjacency");

  auto physical = local_a;
  physical.over_lan = false;
  PointToPointAdjacency legacy(physical);
  result = legacy.receive(hello_b, mac_b, true, true, std::nullopt, now);
  require(result.outcome == P2pOutcome::up && legacy.ready() &&
            legacy.snapshot().negotiated_circuit == p2p_circuit_id(system_a, 3U, system_b, 9U),
          "IS-IS legacy adjacency did not negotiate its ISO circuit ID");
  auto changed = hello_b;
  changed.local_circuit_id = 10U;
  result = legacy.receive(changed, mac_b, true, true, std::nullopt, now + 1s);
  require(result.reason == P2pReason::identity_changed && !legacy.snapshot().present,
          "IS-IS legacy circuit identity change retained its adjacency");
  require(legacy.receive(hello_b, mac_b, true, false, std::nullopt, now).reason == P2pReason::maximum_area_mismatch &&
            !legacy.snapshot().present, "IS-IS maximum-area mismatch created adjacency state");
  result = legacy.receive(hello_b, mac_b, false, true, std::nullopt, now);
  require(result.outcome == P2pOutcome::up && legacy.snapshot().usage == Levels::level2,
          "IS-IS nonmatching areas did not restrict P2P usage to Level 2");
  static_cast<void>(legacy.circuit_down());
  auto zero = hello_b;
  zero.holding_seconds = 0U;
  require(legacy.receive(zero, mac_b, true, true, std::nullopt, now).outcome == P2pOutcome::up &&
            legacy.deadline() == now && legacy.expire(now).outcome == P2pOutcome::down,
          "IS-IS zero holding time lost ordered Up and expiration events");
  PointToPointAdjacency initializing(local_a);
  require(initializing.receive(hello_b, mac_b, true, true,
              option(encoded, {ThreeWayState::down, 1002U, std::nullopt, std::nullopt}), now).outcome == P2pOutcome::initializing &&
            initializing.expire(now + 30s).outcome == P2pOutcome::down,
          "IS-IS initializing adjacency survived holding expiry");
  PointToPointAdjacency near_limit(local_a);
  require(near_limit.receive(hello_b, mac_b, true, true, std::nullopt,
      PointToPointAdjacency::Clock::time_point::max() - 1s).holding_refreshed &&
      near_limit.deadline() == PointToPointAdjacency::Clock::time_point::max(), "IS-IS P2P holding clock wrapped");

}
