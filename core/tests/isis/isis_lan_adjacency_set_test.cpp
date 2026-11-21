// Bounded LAN admission tests verify area ownership, complete Down-before-Up
// eviction, malformed-update atomicity and expiry of Initializing neighbors.

#include "router/isis_lan_adjacency_set.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
struct Recorded {
  router::isis::LanEventCause cause{};
  router::isis::LanOutcome outcome{};
  router::packet::Mac before{};
  router::packet::Mac after{};
  std::size_t old_areas{};
  std::size_t new_areas{};
  std::uint8_t old_suffix{};
  std::uint8_t new_suffix{};
};
struct Trace {
  router::isis::LanAdjacencySet *set{};
  router::packet::Mac incoming{};
  std::array<Recorded, 32U> events{};
  std::size_t count{};
  bool ordered{true};
};
void observe(void *opaque, const router::isis::LanPeerEvent &event) noexcept {
  auto &trace = *static_cast<Trace *>(opaque);
  if (event.cause == router::isis::LanEventCause::capacity_evicted)
    trace.ordered = trace.ordered && !trace.set->find(event.before.adjacency.mac) &&
                    !trace.set->find(trace.incoming) && !event.after.adjacency.present;
  if (trace.count >= trace.events.size()) { trace.ordered = false; return; }
  trace.events[trace.count++] = {event.cause, event.transition.outcome,
      event.before.adjacency.mac, event.after.adjacency.mac,
      event.before.areas.size(), event.after.areas.size(),
      event.before.areas.empty() ? std::uint8_t{} : event.before.areas.front().view().back(),
      event.after.areas.empty() ? std::uint8_t{} : event.after.areas.front().view().back()};
}
router::packet::isis::PduView hello(std::array<std::uint8_t, 512U> &wire,
    router::packet::isis::HelloInput header, const router::packet::Mac &local,
    std::uint8_t area_suffix, std::size_t area_count = 1U, bool two_way = false,
    bool malformed_area = false, std::span<const std::uint8_t> extra = {}) {
  using namespace router::packet::isis;
  std::array<std::uint8_t, 256U> options{};
  TlvWriter writer(options);
  const std::array<std::uint8_t, 3U> area{0x49U, 0U, area_suffix};
  const std::array<std::span<const std::uint8_t>, 3U> areas{area, area, area};
  if (malformed_area) {
    const std::array<std::uint8_t, 1U> invalid{0U};
    require(writer.append(1U, invalid), "IS-IS malformed retained-area fixture failed");
  } else require(encode_area_addresses(writer, std::span(areas).first(area_count)), "IS-IS retained-area fixture failed");
  const std::array<router::packet::Mac, 1U> neighbor{local};
  require(encode_fixed_addresses<6U>(writer, 6U, two_way ? std::span(neighbor) : std::span(neighbor).first(0U)),
          "IS-IS retained-neighbor fixture failed");
  TlvCursor additional(extra);
  while (const auto option = additional.next())
    require(writer.append(option->code, option->value), "IS-IS LAN extra option fixture failed");
  require(additional.valid(), "IS-IS LAN extra framing fixture failed");
  const auto encoded = encode_hello(wire, header, writer.bytes());
  DecodeError error{};
  const auto pdu = encoded ? parse(*encoded, error) : std::nullopt;
  require(pdu.has_value(), "IS-IS LAN set fixture did not parse");
  return *pdu;
}
}

void isis_lan_adjacency_set_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto now = LanAdjacencySet::Clock::time_point{100s};
  const router::packet::Mac local{2U, 0U, 0U, 0U, 0U, 100U};
  const router::packet::Mac first{2U, 0U, 0U, 0U, 0U, 1U};
  const router::packet::Mac second{2U, 0U, 0U, 0U, 0U, 2U};
  const router::packet::Mac third{2U, 0U, 0U, 0U, 0U, 3U};
  LanAdjacencySet set(PduType::lan_hello_l1, local, {2U, 2U}, 512U);
  Trace trace{&set, third};
  HelloInput input{PduType::lan_hello_l1, {1U, 2U, 3U, 4U, 5U, 1U}, 3U, 3U, 0U, 10U};
  std::array<std::uint8_t, 512U> wire{};
  require(set.receive(hello(wire, input, local, 1U), first, now, &trace, observe) == LanSetResult::accepted,
          "IS-IS LAN set did not retain an Initializing neighbor");
  wire.fill(0U);
  require(set.find(first) && set.find(first)->areas.front().view().back() == 1U &&
            set.find(first)->adjacency.state == LanState::initializing,
          "IS-IS LAN set borrowed received area storage after return");
  input.source.back() = 2U;
  require(set.receive(hello(wire, input, local, 2U), second, now, &trace, observe) == LanSetResult::accepted,
          "IS-IS LAN set did not fill its second reserved slot");
  const auto saved_set = set.checkpoint(now + 500ms);
  const auto rebased = LanAdjacencySet::Clock::time_point{9000s};
  auto restored_set = LanAdjacencySet::restore_checkpoint(saved_set, PduType::lan_hello_l1, local, {2U, 2U}, 512U, rebased);
  require(restored_set && restored_set->size() == 2U && restored_set->deadline() == rebased + 2500ms &&
      restored_set->find(first)->areas.front().view().back() == 1U &&
      restored_set->find(second)->areas.front().view().back() == 2U, "IS-IS LAN set restore lost owned areas or holding time");
  for (unsigned invalid{}; invalid < 11U; ++invalid) {
    auto bad = saved_set;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: bad.type = PduType::lan_hello_l2; break;
      case 2U: ++bad.local[0U]; break;
      case 3U: ++bad.limits.neighbors; break;
      case 4U: ++bad.maximum_attribute_octets; break;
      case 5U: bad.peers.push_back(bad.peers.front()); break;
      case 6U: bad.peers[1U] = bad.peers[0U]; break;
      case 7U: bad.peers[0U].attributes = {10U, 1U, 7U}; break;
      case 8U: bad.peers[0U].attributes = {1U, 1U, 0U}; break;
      case 9U: bad.peers[0U].adjacency.state.present = false; break;
      default: bad.peers[0U].adjacency.holding_nanoseconds.reset(); break;
    }
    require(!LanAdjacencySet::restore_checkpoint(bad, PduType::lan_hello_l1, local, {2U, 2U}, 512U, rebased) &&
        restored_set->size() == 2U && trace.count == 2U, "IS-IS bad LAN set transfer mutated live state or emitted events");
  }
  Trace resumed_trace{restored_set.get(), third};
  require(!restored_set->expire_one(rebased + 2499ms, &resumed_trace, observe) &&
      restored_set->expire_one(rebased + 2500ms, &resumed_trace, observe) && resumed_trace.events[0U].before == first &&
      resumed_trace.events[0U].old_suffix == 1U && restored_set->expire_one(rebased + 2500ms, &resumed_trace, observe) &&
      !restored_set->size(), "IS-IS restored LAN set expiration lost ordering or old attributes");
  require(restored_set->receive(hello(wire, input, local, 7U, 2U, true), second, rebased + 3s,
      &resumed_trace, observe) == LanSetResult::accepted && restored_set->find(second)->areas.size() == 2U,
      "IS-IS restored LAN set lost future admission capacity");
  input.source.back() = 3U;
  require(set.receive(hello(wire, input, local, 3U, 1U, true), third, now + 1s, &trace, observe) == LanSetResult::accepted &&
            !set.find(first) && set.find(second) && set.find(third) && trace.ordered && trace.count == 4U &&
            trace.events[2U].cause == LanEventCause::capacity_evicted && trace.events[2U].outcome == LanOutcome::down &&
            trace.events[2U].before == first && trace.events[2U].old_suffix == 1U &&
            trace.events[3U].outcome == LanOutcome::up && trace.events[3U].after == third,
          "IS-IS LAN capacity did not complete lowest-MAC Initializing eviction before admitting Up");
  input.priority = 0U;
  input.source.back() = 4U;
  const router::packet::Mac fourth{2U, 0U, 0U, 0U, 0U, 4U};
  require(set.receive(hello(wire, input, local, 4U), fourth, now + 1s, &trace, observe) == LanSetResult::capacity_refused &&
            set.size() == 2U && trace.count == 4U, "IS-IS LAN admitted the new lowest-priority candidate");
  input.priority = 10U;
  input.source.back() = 2U;
  require(set.receive(hello(wire, input, local, 9U, 2U, true), second, now + 1s, &trace, observe) == LanSetResult::accepted &&
            set.find(second)->areas.size() == 2U && trace.events[4U].old_suffix == 2U &&
            trace.events[4U].new_suffix == 9U && trace.events[4U].outcome == LanOutcome::up,
          "IS-IS LAN did not expose old/new owned areas during an accepted update");
  const auto accepted_events = trace.count;
  require(set.receive(hello(wire, input, local, 8U, 1U, true, true), second, now + 2s, &trace, observe) == LanSetResult::malformed &&
            set.receive(hello(wire, input, local, 8U, 3U, true), second, now + 2s, &trace, observe) == LanSetResult::capacity_refused &&
            set.find(second)->areas.front().view().back() == 9U && trace.count == accepted_events && set.deadline() == now + 4s,
          "IS-IS LAN rejected area retention modified a peer or emitted an event");
  input.source.back() = 99U;
  require(set.receive(hello(wire, input, local, 7U, 1U, true), second, now + 2s, &trace, observe) == LanSetResult::discarded &&
            trace.count == accepted_events, "IS-IS LAN reused an existing MAC for a different system ID");
  require(!set.expire_one(now + 3999ms, &trace, observe) && set.expire_one(now + 4s, &trace, observe) &&
            set.expire_one(now + 4s, &trace, observe) && !set.expire_one(now + 4s, &trace, observe) &&
            set.size() == 0U && trace.events[accepted_events].cause == LanEventCause::expired,
          "IS-IS LAN rejected Hellos refreshed a holding deadline or expiry exceeded one record per call");
  input.source.back() = 1U;
  require(set.receive(hello(wire, input, local, 1U), first, now + 5s, &trace, observe) == LanSetResult::accepted &&
            set.expire_one(now + 8s, &trace, observe) && trace.events[trace.count - 1U].outcome == LanOutcome::down,
          "IS-IS LAN Initializing holding expiry did not emit Down");
  require(set.receive(hello(wire, input, local, 1U), first, now + 9s, &trace, observe) == LanSetResult::accepted &&
            !set.circuit_down(&trace, nullptr) && set.size() == 1U &&
            set.circuit_down(&trace, observe) && set.size() == 0U &&
            trace.events[trace.count - 1U].cause == LanEventCause::circuit_down,
          "IS-IS LAN circuit shutdown lost its owned Down event");
  require(set.receive(hello(wire, input, local, 1U), first, now, &trace, nullptr) == LanSetResult::missing_observer &&
            set.size() == 0U, "IS-IS LAN accepted a state change without an event consumer");
  LanAdjacencySet other_level(PduType::lan_hello_l2, local, {1U, 2U}, 512U);
  Trace other_trace{&other_level};
  require(other_level.receive(hello(wire, input, local, 1U), first, now, &other_trace, observe) == LanSetResult::discarded,
          "IS-IS LAN set mixed L1 and L2 peers");
  input.type = PduType::lan_hello_l2;
  require(other_level.receive(hello(wire, input, local, 1U), first, now, &other_trace, observe) == LanSetResult::accepted &&
            other_level.size() == 1U && set.size() == 0U,
          "IS-IS LAN level collections shared mutable neighbor state");
  require(other_level.receive(hello(wire, input, local, 2U, 1U, true), first, now + 1s, &other_trace, observe) == LanSetResult::accepted &&
            other_trace.events[1U].outcome == LanOutcome::up &&
            other_level.receive(hello(wire, input, local, 3U), first, now + 2s, &other_trace, observe) == LanSetResult::accepted &&
            other_trace.events[2U].outcome == LanOutcome::down && other_trace.events[2U].cause == LanEventCause::received &&
            other_level.find(first)->adjacency.state == LanState::initializing &&
            other_level.find(first)->areas.front().view().back() == 3U && other_level.deadline() == now + 5s &&
            other_level.at(0U) && !other_level.at(1U),
          "IS-IS LAN one-way Down deleted its retained Init record, areas or holding deadline");
  // Retained non-secret options survive receive-buffer reuse. Invalid address
  // widths and exhausted byte budgets cannot extend a holding deadline.
  LanAdjacencySet retained(PduType::lan_hello_l2, local, {1U, 2U}, 32U);
  Trace retained_trace{&retained};
  std::array<std::uint8_t, 64U> option_bytes{};
  TlvWriter option_writer(option_bytes);
  const std::array<std::uint8_t, 1U> protocol{ipv4_nlpid};
  const std::array<router::packet::Ipv4, 1U> addresses{{{203U, 0U, 113U, 7U}}};
  const std::array<std::uint8_t, 2U> secret{1U, 99U};
  require(option_writer.append(129U, protocol) && encode_fixed_addresses<4U>(option_writer, 132U, addresses) &&
      option_writer.append(10U, secret), "IS-IS retained option fixture failed");
  require(retained.receive(hello(wire, input, local, 1U, 1U, true, false, option_writer.bytes()),
      first, now, &retained_trace, observe) == LanSetResult::accepted,
      "IS-IS LAN did not retain IP attributes");
  wire.fill(0U);
  const auto owned = retained.find(first);
  require(owned && owned->type == PduType::lan_hello_l2 && owned->attributes.size() == 15U,
      "IS-IS LAN retained secret options or lost selected attributes");
  TlvCursor retained_options(owned->attributes);
  bool found_ip{};
  while (const auto option = retained_options.next()) {
    require(option->code != 10U && option->code != 6U, "IS-IS LAN retained secret or transient neighbor option");
    if (option->code == 132U) found_ip = option->value.back() == 7U;
  }
  require(found_ip && retained_options.valid(), "IS-IS LAN borrowed IP bytes from receive storage");
  const auto deadline = retained.deadline();
  TlvWriter invalid_writer(option_bytes);
  const std::array<std::uint8_t, 1U> invalid_address{1U};
  require(invalid_writer.append(132U, invalid_address), "IS-IS malformed address fixture failed");
  require(retained.receive(hello(wire, input, local, 2U, 1U, true, false, invalid_writer.bytes()),
      first, now + 1s, &retained_trace, observe) == LanSetResult::malformed && retained.deadline() == deadline &&
      retained.find(first)->attributes.size() == 15U && retained_trace.count == 1U,
      "IS-IS LAN malformed IP option mutated accepted attributes or timer");
  TlvWriter oversized(option_bytes);
  const std::array<std::uint8_t, 30U> protocols{};
  require(oversized.append(129U, protocols), "IS-IS oversized retained option fixture failed");
  require(retained.receive(hello(wire, input, local, 2U, 1U, true, false, oversized.bytes()),
      first, now + 1s, &retained_trace, observe) == LanSetResult::capacity_refused &&
      retained.deadline() == deadline && retained_trace.count == 1U,
      "IS-IS LAN attribute budget refusal refreshed a deadline");

  TlvWriter invalid_mt(option_bytes);
  require(invalid_mt.append(229U, invalid_address), "IS-IS malformed MT fixture failed");
  require(retained.receive(hello(wire, input, local, 2U, 1U, true, false, invalid_mt.bytes()),
      first, now + 1s, &retained_trace, observe) == LanSetResult::malformed && retained.deadline() == deadline,
      "IS-IS LAN malformed MT refreshed a deadline");
  TlvWriter invalid_v6(option_bytes);
  require(invalid_v6.append(232U, invalid_address), "IS-IS malformed IPv6 fixture failed");
  require(retained.receive(hello(wire, input, local, 2U, 1U, true, false, invalid_v6.bytes()),
      first, now + 1s, &retained_trace, observe) == LanSetResult::malformed && retained.deadline() == deadline,
      "IS-IS LAN malformed IPv6 refreshed a deadline");
  // Lack of common MT does not prevent ISO LAN adjacency formation.
  TlvWriter mt_only(option_bytes);
  const std::array<std::uint8_t, 2U> topology_two{0U, 2U};
  require(mt_only.append(229U, topology_two), "IS-IS MT-only fixture failed");
  require(retained.receive(hello(wire, input, local, 2U, 1U, true, false, mt_only.bytes()),
      first, now + 1s, &retained_trace, observe) == LanSetResult::accepted &&
      retained.find(first)->adjacency.state == LanState::up && retained.deadline() == now + 4s,
      "IS-IS LAN incorrectly required common MT0 for adjacency formation");

}
