// LAN state tests verify two-way MAC reporting, independent holding state and
// non-mutating rejection. Capacity decisions use the ISO priority/MAC order.

#include "router/isis_adjacency.hpp"
#include "router/isis_lan_adjacency.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
router::packet::isis::PduView hello(std::array<std::uint8_t, 512U> &output,
    const router::packet::isis::HelloInput &input, std::span<const router::packet::Mac> neighbors,
    bool malformed_neighbors = false) {
  using namespace router::packet::isis;
  std::array<std::uint8_t, 256U> options{};
  TlvWriter writer(options);
  const std::array<std::uint8_t, 3U> area{0x49U, 0U, 1U};
  const std::array<std::span<const std::uint8_t>, 1U> areas{area};
  const std::array<std::uint8_t, 1U> protocols{ipv4_nlpid};
  require(encode_area_addresses(writer, areas) && writer.append(129U, protocols), "IS-IS LAN options fixture failed");
  if (malformed_neighbors) {
    const std::array<std::uint8_t, 1U> partial{1U};
    require(writer.append(6U, partial), "IS-IS LAN malformed fixture failed");
  } else require(encode_fixed_addresses<6U>(writer, 6U, neighbors), "IS-IS LAN neighbor fixture failed");
  const auto encoded = encode_hello(output, input, writer.bytes());
  DecodeError error{};
  require(encoded.has_value(), "IS-IS LAN Hello fixture failed");
  const auto pdu = parse(*encoded, error);
  require(pdu.has_value(), "IS-IS LAN Hello fixture did not parse");
  return *pdu;
}
}

void isis_lan_adjacency_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = LanAdjacency::Clock::time_point{100s};
  const SystemId peer{1U, 2U, 3U, 4U, 5U, 6U};
  const router::packet::Mac peer_mac{2U, 0U, 0U, 0U, 0U, 1U};
  const router::packet::Mac local_mac{2U, 0U, 0U, 0U, 0U, 2U};
  const std::array<router::packet::Mac, 1U> local{local_mac};
  LanAdjacency neighbor(PduType::lan_hello_l1, peer, peer_mac, local_mac);
  HelloInput input{PduType::lan_hello_l1, peer, 3U, 3U, 0U, 64U, {9U, 8U, 7U, 6U, 5U, 4U, 3U}};
  std::array<std::uint8_t, 512U> wire{};
  auto update = neighbor.receive(hello(wire, input, {}), peer_mac, now);
  require(update.outcome == LanOutcome::initializing && update.holding_refreshed &&
            neighbor.snapshot().present && neighbor.snapshot().priority == 64U && neighbor.deadline() == now + 3s,
          "IS-IS LAN initial Hello did not create an initializing neighbor");
  update = neighbor.receive(hello(wire, input, local), peer_mac, now + 1s);
  require(update.outcome == LanOutcome::up && neighbor.snapshot().state == LanState::up &&
            neighbor.snapshot().advertised_lan == input.designated_id,
          "IS-IS LAN did not recognize two-way MAC reporting or changed reported DIS");
  input.priority = 127U;
  input.designated_id.back() = 99U;
  update = neighbor.receive(hello(wire, input, local), peer_mac, now + 1500ms);
  require(update.outcome == LanOutcome::accepted && neighbor.snapshot().priority == 127U &&
            neighbor.snapshot().advertised_lan.back() == 99U,
          "IS-IS LAN did not refresh priority and advertised LAN identity");
  update = neighbor.receive(hello(wire, input, {}), peer_mac, now + 2s);
  require(update.outcome == LanOutcome::down && update.reason == LanReason::one_way &&
            neighbor.snapshot().present && neighbor.snapshot().state == LanState::initializing &&
            neighbor.deadline() == now + 5s,
          "IS-IS LAN one-way loss deleted rather than initialized its adjacency");
  const auto deadline = neighbor.deadline();
  update = neighbor.receive(hello(wire, input, local, true), peer_mac, now + 4s);
  require(update.reason == LanReason::malformed && !update.holding_refreshed && neighbor.deadline() == deadline,
          "IS-IS LAN malformed neighbor list refreshed the holding timer");
  auto other = input;
  ++other.source.back();
  update = neighbor.receive(hello(wire, other, local), peer_mac, now + 4s);
  require(update.reason == LanReason::different_peer && neighbor.deadline() == deadline,
          "IS-IS LAN changed the identity of a live neighbor record");
  require(neighbor.expire(now + 4999ms).outcome == LanOutcome::discarded &&
            neighbor.expire(now + 5s).reason == LanReason::holding_expired && !neighbor.snapshot().present,
          "IS-IS LAN initializing neighbor survived its holding deadline");
  other = input;
  other.type = PduType::lan_hello_l2;
  require(neighbor.receive(hello(wire, other, local), peer_mac, now + 6s).reason == LanReason::malformed &&
            !neighbor.deadline(), "IS-IS LAN accepted another level into the same record");
  require(neighbor.receive(hello(wire, input, local), peer_mac, now + 6s).outcome == LanOutcome::up &&
            neighbor.circuit_down().reason == LanReason::circuit_down && !neighbor.snapshot().present,
          "IS-IS LAN circuit-down failed to delete its neighbor");

  std::array<LanCandidate, 2U> candidates{{{peer_mac, 10U}, {local_mac, 90U}}};
  auto incoming = local_mac;
  ++incoming.back();
  auto eviction = select_lan_eviction(candidates, {incoming, 100U});
  require(eviction.action == LanAdmission::evict_existing && eviction.victim == 0U,
          "IS-IS LAN capacity did not choose the lowest-priority existing neighbor");
  require(select_lan_eviction(candidates, {incoming, 0U}).action == LanAdmission::reject_new,
          "IS-IS LAN capacity admitted a new lowest-priority neighbor");
  candidates[0U].priority = 90U;
  eviction = select_lan_eviction(candidates, {incoming, 90U});
  require(eviction.action == LanAdmission::evict_existing && eviction.victim == 0U,
          "IS-IS LAN equal-priority capacity tie did not use the lowest MAC");
  incoming.back() = 0U;
  require(select_lan_eviction(candidates, {incoming, 90U}).action == LanAdmission::reject_new &&
            select_lan_eviction(candidates, {peer_mac, 90U}).action == LanAdmission::invalid &&
            select_lan_eviction(candidates, {incoming, 128U}).action == LanAdmission::invalid,
          "IS-IS LAN capacity accepted a duplicate, invalid priority or lowest-MAC newcomer");
}
