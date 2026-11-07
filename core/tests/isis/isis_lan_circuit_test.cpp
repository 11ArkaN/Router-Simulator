// Three LAN circuit owners discover each other only through encoded Hellos,
// physical queues and a learning bridge. Injected owner-local deadlines prove
// election delay, two-way admission and DIS replacement after carrier loss.

#include "router/isis_lan_circuit.hpp"
#include "router/isis_instance_update.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_lan_origination.hpp"
#include "router/isis_p2p_decision.hpp"
#include "router/ethernet_switch.hpp"
#include "router/multi_device_fabric.hpp"

#include <memory>
#include <algorithm>
#include <source_location>
#include <stdexcept>

namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS LAN circuit owner invariant failed at line " +
      std::to_string(location.line()));
}
LanCircuitConfiguration configuration(std::uint8_t id) {
  LanCircuitConfiguration result;
  result.mac = {2U, 0U, 0U, 0U, 0U, id};
  result.local = {{1U, 2U, 3U, 4U, 5U, id}, result.mac, 64U, id};
  result.levels = Levels::both;
  result.type = packet::isis::PduType::lan_hello_l1;
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area;
  area.bytes[0U] = 0x49U;
  area.bytes[2U] = 1U;
  area.length = 3U;
  result.areas.push_back(area);
  result.protocols = {packet::isis::ipv4_nlpid};
  result.ipv4_addresses.push_back({192U, 0U, 2U, id});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = result.designated_holding_seconds = 3U;
  result.hello_interval = result.designated_hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.peer_attribute_octets = 512U;
  result.limits = {4U, 3U};
  return result;
}
struct Events {
  unsigned up{}, down{}, changes{};
  bool old_areas{true}, update_ok{true};
  LanCircuit *circuit{};
  InstanceUpdateProcess *update{};
  LocalLspSet *origin{};
  packet::isis::LspId root{}, pseudonode{};
  std::vector<std::uint8_t> base;
  RuntimeClock::time_point now{};
};
void synchronize(Events &events) noexcept {
  if (!events.update) return;
  std::array<packet::Mac, 4U> peers{};
  std::array<packet::isis::SystemId, 4U> systems{};
  std::size_t count{}, accepted_count{};
  for (std::size_t index{}; index < events.circuit->neighbors().size(); ++index) {
    const auto neighbor = events.circuit->neighbors().at(index)->adjacency;
    peers[accepted_count++] = neighbor.mac;
    if (neighbor.state == LanState::up) {
      systems[count++] = neighbor.system;
    }
  }
  const auto selected = events.circuit->designated();
  const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
  events.update_ok = events.update_ok && events.update->lan(0U, 7U, 0U,
      std::span(peers).first(accepted_count), count && selected && selected->local, observer) == UpdateStatus::applied;
  if (!events.origin) return;
  const auto accepted = [](LocalContentResult result) {
    return result == LocalContentResult::changed || result == LocalContentResult::unchanged;
  };
  auto system_peers = std::span(systems).first(count);
  std::sort(system_peers.begin(), system_peers.end());
  const auto unique_end = std::unique(system_peers.begin(), system_peers.end());
  std::array<std::uint8_t, 256U> options{};
  events.update_ok = events.update_ok && accepted(synchronize_lan_pseudonode(*events.origin,
      0U, events.pseudonode, 3U, count && selected && selected->local,
      std::span<const packet::isis::SystemId>(system_peers.begin(), unique_end), true, options, events.now));
  packet::isis::TlvWriter writer(options);
  packet::isis::TlvCursor base(events.base);
  while (const auto option = base.next()) events.update_ok = events.update_ok && writer.append(option->code, option->value);
  if (selected) events.update_ok = events.update_ok && append_lan_origin_neighbor(writer, selected->lan, {10U, 10U});
  events.update_ok = events.update_ok && base.valid() && accepted(events.origin->replace(0U,
      events.root, 3U, writer.bytes(), events.now));
}
void peer(void *opaque, const LanPeerEvent &value) noexcept {
  auto &events = *static_cast<Events *>(opaque);
  if (value.transition.outcome == LanOutcome::up) ++events.up;
  if (value.transition.outcome == LanOutcome::down) {
    ++events.down;
    events.old_areas = events.old_areas && !value.before.areas.empty();
  }
  synchronize(events);
}
void designated(void *opaque, const std::optional<DisSelection> &,
    const std::optional<DisSelection> &) noexcept {
  auto &events = *static_cast<Events *>(opaque);
  ++events.changes;
  synchronize(events);
}
struct Context {
  std::array<std::unique_ptr<LanCircuit>, 3U> circuits;
  std::array<Events, 3U> events;
  lab::EthernetSwitch &bridge;
  LanCircuit::Clock::time_point now;
  std::size_t active{3U};
  std::array<std::unique_ptr<InstanceUpdateProcess>, 3U> updates{};
  std::array<std::unique_ptr<LocalLspSet>, 3U> origins{};
  LanCircuitObserver observer(std::size_t index) { return {&events[index], peer, designated}; }
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
  auto &context = *static_cast<Context *>(opaque);
  if (delivery.destination.node.kind == lab::NodeKind::ethernet_switch) {
    require(!context.bridge.ingress(delivery.destination.ordinal, delivery.frame, context.now).malformed);
  } else if (delivery.destination.node.index < context.active) {
    const auto index = delivery.destination.node.index;
    context.events[index].now = context.now;
    packet::isis::EthernetDecodeError error{};
    const auto wire = packet::isis::parse_ethernet_pdu(delivery.frame.view(), error);
    require(wire.has_value());
    if (wire->pdu.type == packet::isis::PduType::lan_hello_l1)
      require(context.circuits[index]->receive(delivery.frame, std::nullopt, context.now,
          context.observer(index)) == LanCircuitReceive::accepted);
    else {
      const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
      const auto received = context.updates[index]->receive(0U, 7U, delivery.frame, {}, context.now, observer);
      const bool suppressed = wire->pdu.type == packet::isis::PduType::psnp_l1 &&
          !context.updates[index]->outputs(0U, 0U)->reservations.designated;
      require(suppressed ? received.snp.database.status == SnpBatchStatus::discarded :
          received.status == UpdateStatus::applied);
    }
    require(context.events[index].update_ok);
  }
}
}

void isis_lan_circuit_tests() {
  auto pool = std::make_unique<PacketPool>();
  lab::EthernetSwitch bridge(device_catalog::ethernet_switch_profiles[0U], *pool);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const auto start = LanCircuit::Clock::time_point{100s};
  auto invalid_groups = configuration(1U);
  invalid_groups.update_destinations = std::array<packet::Mac, 2U>{
      packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}, invalid_groups.hello_destination};
  bool groups_rejected{};
  try { LanCircuit invalid(std::move(invalid_groups), 1U, start); }
  catch (const std::invalid_argument &) { groups_rejected = true; }
  require(groups_rejected);

  Context context{{}, {}, bridge, start};
  auto scratch = std::make_unique<PduScratch>();
  for (std::uint16_t index{}; index < 3U; ++index) {
    context.circuits[index] = std::make_unique<LanCircuit>(
        configuration(static_cast<std::uint8_t>(index + 1U)), index + 123U, start);
    const auto local = configuration(static_cast<std::uint8_t>(index + 1U));
    const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
        1200U, 60s, 60s, false, false, false, PurgeRules::registry_6233};
    const UpdateCircuitConfiguration binding{7U, Levels::level1, false,
        packet::isis::InstanceFormat::standard, 0U,
        {local.hello_destination, local.hello_destination}, true, 4U};
    context.updates[index] = std::make_unique<InstanceUpdateProcess>(local.local.system, 3U,
        std::array<std::optional<UpdateLevelConfiguration>, 2U>{level, {}}, std::array{binding},
        UpdateInstanceSelector{packet::isis::InstanceFormat::standard, 0U});
    context.events[index].circuit = context.circuits[index].get();
    context.events[index].update = context.updates[index].get();
    auto &events = context.events[index];
    std::copy(local.local.system.begin(), local.local.system.end(), events.root.begin());
    events.pseudonode = events.root;
    events.pseudonode[6U] = local.local.circuit;
    events.base = {1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 1U, packet::isis::ipv4_nlpid};
    LocalLspProgram origin;
    origin.levels[0U] = LocalLspLevelProgram{1200U, 256U, 1s, 40s};
    origin.random = index + 19U;
    origin.records = {{0U, events.root, 3U, events.base}, {0U, events.pseudonode, 3U, {}, false}};
    context.origins[index] = std::make_unique<LocalLspSet>(local.local.system, 3U,
        UpdateInstanceSelector{packet::isis::InstanceFormat::standard, 0U}, std::move(origin), start);
    events.origin = context.origins[index].get();
    events.now = start;
    require(bridge.configure_port(index, {1000U, 1514U, true, true}));
    require(fabric->configure({index, 1U}, {lab::node(lab::DeviceHandle{index, 1U}), 0U, 1U},
        {lab::node(lab::SwitchHandle{0U, 1U}), index, 1U}, 1'000'000'000U, 100ns, true));
  }
  const auto flush = [&] {
    for (unsigned flight{}; flight < 3U; ++flight) {
      fabric->pump_transmit(context.now);
      context.now += 1ms;
      fabric->pump_delivery(&context, delivered, context.now);
    }
    for (std::uint16_t index{}; index < context.active; ++index) {
      while (const auto frame = bridge.dequeue(index)) {
        require(fabric->enqueue({index, 1U}, 1U, *frame->frame) == lab::MultiDeviceFabric::DropReason::none);
        bridge.release(frame->handle);
      }
    }
    for (unsigned flight{}; flight < 3U; ++flight) {
      fabric->pump_transmit(context.now);
      context.now += 1ms;
      fabric->pump_delivery(&context, delivered, context.now);
    }
  };
  const auto flood = [&] {
    for (std::uint16_t index{}; index < context.active; ++index) {
      const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
      std::size_t work{4U};
      require(!context.origins[index]->service(*context.updates[index], {}, context.now,
          *scratch, observer, work).blocked);
      auto output = context.updates[index]->outputs(0U, 0U);
      if (!output) continue;
      const auto local = configuration(static_cast<std::uint8_t>(index + 1U));
      const auto &database = context.updates[index]->level(0U)->database();
      for (std::size_t record{}; record < database.size(); ++record) {
        const auto stored = database.database().at(record, context.now);
        require(stored.has_value());
        if (!database.flags(stored->header.id, 0U)->srm) continue;
        packet::Frame frame;
        const auto sent = output->reservations.lsp.prepare(stored->header.id, local.mac,
            local.hello_destination, 1492U, 1U, frame, *scratch, context.now);
        require(sent.status == LspEmissionStatus::encoded);
        const bool admitted = fabric->enqueue({index, 1U}, 0U, frame) == lab::MultiDeviceFabric::DropReason::none;
        require(admitted && output->reservations.lsp.complete(output->synchronization_epoch,
            sent.ticket, admitted, context.now).accepted && !database.flags(stored->header.id, 0U)->srm);
      }
    }
    flush();
  };
  const auto round = [&](LanCircuit::Clock::time_point now) {
    context.now = now;
    for (std::uint16_t index{}; index < context.active; ++index) {
      context.events[index].now = now;
      packet::Frame frame;
      require(context.circuits[index]->hello(frame, std::nullopt, *scratch, now,
          context.observer(index)) == HelloBuildResult::encoded);
      const bool admitted = fabric->enqueue({index, 1U}, 0U, frame) == lab::MultiDeviceFabric::DropReason::none;
      require(admitted && context.circuits[index]->complete_hello(admitted, now));
    }
    flush();
    flood();
  };
  const auto check_routes = [&](std::size_t index, bool converged = false) {
    std::array<P2pSpfSeed, 4U> seeds{};
    std::size_t count{};
    const auto selected = context.circuits[index]->designated();
    require(selected.has_value());
    std::optional<std::uint16_t> dis_token;
    for (std::size_t peer{}; peer < context.circuits[index]->neighbors().size(); ++peer) {
      const auto neighbor = context.circuits[index]->neighbors().at(peer)->adjacency;
      if (neighbor.state != LanState::up) continue;
      seeds[count] = {neighbor.system, 10U, static_cast<std::uint16_t>(count)};
      if (neighbor.system == selected->system) dis_token = static_cast<std::uint16_t>(count);
      ++count;
    }
    const std::array lans{LanSpfCircuit{101U, selected->lan, 10U, dis_token}};
    packet::isis::LanId local{};
    std::copy_n(context.events[index].root.begin(), local.size(), local.begin());
    P2pRouteDecision decision(8U, 32U, 64U, MetricStyle::wide);
    const auto status = decision.calculate(context.updates[index]->level(0U)->database().database(),
        {local, 0U, packet::isis::ipv4_nlpid, GraphMetricStyle::wide}, std::span(seeds).first(count),
        static_cast<std::uint16_t>(count), context.now, lans);
    if (status != DecisionStatus::applied)
      throw std::runtime_error("IS-IS LAN decision router " + std::to_string(index) + " status " +
          std::to_string(static_cast<unsigned>(status)) + " DIS " + std::to_string(selected->system.back()) +
          " pseudonode " + std::to_string(selected->lan.back()) + " token " +
          (dis_token ? std::to_string(*dis_token) : "local") + " peers " + std::to_string(count));
    for (std::size_t peer{}; peer < count; ++peer) {
      packet::isis::LanId id{};
      std::copy(seeds[peer].peer.begin(), seeds[peer].peer.end(), id.begin());
      require(decision.cost(id) == 10U && decision.first_hop_count(id) == 1U && decision.first_hop(id, 0U) == peer);
    }
    require(decision.cost(local) == 0U && !decision.first_hop_count(local));
    if (context.active == 2U) {
      packet::isis::LanId retired{};
      std::copy_n(context.events[2U].root.begin(), retired.size(), retired.begin());
      // Before the next Hello, R2 still sees R1's old root-to-PN link and
      // legitimately computes a transient path through R1. Only new encoded
      // R1 content can remove that path from R2's independent database.
      if (converged || index == 0U) require(!decision.cost(retired));
      else require(decision.cost(retired) == 20U);
    }
  };
  round(start);
  for (std::size_t index{}; index < context.circuits.size(); ++index) {
    const auto &circuit = context.circuits[index];
    require(circuit->neighbors().size() == 2U && !circuit->designated() && !context.events[index].up);
    // The first Hello creates Initializing adjacencies. ISO update acceptance
    // uses same-level SNPA membership, while SPF and pseudonodes still use Up.
    require(circuit->neighbors().at(0U)->adjacency.state == LanState::initializing &&
        context.updates[index]->level(0U)->database().size() == 3U &&
        context.updates[index]->outputs(0U, 0U)->synchronization_epoch == 1U &&
        !context.origins[index]->contains(0U, context.events[index].pseudonode));
  }
  round(start + 1s);
  for (std::size_t index{}; index < 3U; ++index)
    require(context.events[index].up == 2U && !context.circuits[index]->designated());
  auto stranger_configuration = configuration(4U);
  stranger_configuration.mac = configuration(3U).mac;
  stranger_configuration.local.mac = stranger_configuration.mac;
  stranger_configuration.protocols = {packet::isis::ipv6_nlpid};
  LanCircuit stranger(std::move(stranger_configuration), 444U, start + 1500ms);
  Events stranger_events;
  packet::Frame stranger_frame;
  const LanCircuitObserver stranger_observer{&stranger_events, peer, designated};
  require(stranger.hello(stranger_frame, std::nullopt, *scratch, start + 1500ms,
      stranger_observer) == HelloBuildResult::encoded);
  require(context.circuits[0U]->receive(stranger_frame, std::nullopt, start + 1500ms,
      context.observer(0U)) == LanCircuitReceive::discarded &&
      context.circuits[0U]->neighbors().find(configuration(3U).mac)->adjacency.system.back() == 3U &&
      context.events[0U].down == 0U);
  round(start + 2s);
  for (std::size_t index{}; index < 3U; ++index) {
    const auto selected = context.circuits[index]->designated();
    require(selected && selected->system.back() == 3U && selected->local == (index == 2U));
    const auto pseudonode = context.updates[index]->level(0U)->database().database().find(
        context.events[2U].pseudonode, context.now);
    require(pseudonode && lsp_link_counts(pseudonode->pdu.tlvs) == std::optional{LspLinkCounts{3U, 3U}} &&
        context.updates[index]->level(0U)->database().size() == 4U &&
        context.origins[index]->contains(0U, context.events[index].pseudonode) == (index == 2U));
    check_routes(index);
  }
  {
    const auto local = configuration(1U);
    LspContents contents;
    contents.header = {packet::isis::PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U}, 1200U, 1U, 3U};
    contents.maximum_pdu_octets = 1492U;
    const LevelObserver observer{nullptr, +[](void *, const LevelEvent &) noexcept {}};
    auto output = context.updates[0U]->outputs(0U, 0U);
    packet::Frame frame;
    for (std::size_t index{}; index < 3U; ++index) {
      require(context.updates[index]->level(0U)->database().size() == 4U &&
          !context.updates[index]->level(0U)->database().flags(contents.header.id, 0U)->ssn);
      require(context.updates[index]->outputs(0U, 0U)->reservations.designated == (index == 2U));
    }
    contents.header.id.back() = 7U;
    contents.header.remaining_seconds = 0U;
    const auto purge = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(purge.status == LspBuildStatus::encoded && context.updates[0U]->originate(0U,
        purge.bytes, context.now, OriginPurgeReason::initiated, observer).install == LspInstallResult::installed);
    const auto sent_purge = output->reservations.lsp.prepare(contents.header.id, local.mac,
        local.hello_destination, 1492U, 1U, frame, *scratch, context.now);
    require(sent_purge.status == LspEmissionStatus::encoded &&
        fabric->enqueue({0U, 1U}, 0U, frame) == lab::MultiDeviceFabric::DropReason::none &&
        output->reservations.lsp.complete(output->synchronization_epoch,
            sent_purge.ticket, true, context.now).accepted);
    flush();
    for (std::uint16_t index{1U}; index < 3U; ++index) {
      require(context.updates[index]->level(0U)->database().size() == 4U &&
          context.updates[index]->level(0U)->transient_acknowledgements() == 1U);
      auto acknowledgement = context.updates[index]->outputs(0U, 0U);
      SnpContents snp;
      const auto peer_local = configuration(static_cast<std::uint8_t>(index + 1U));
      snp.header.type = packet::isis::PduType::psnp_l1;
      snp.header.source = peer_local.local.system;
      snp.source = peer_local.mac;
      snp.destination = peer_local.hello_destination;
      snp.maximum_pdu_octets = 1492U;
      const auto ack = acknowledgement->reservations.snp.prepare(SnpEmission::transient_acknowledgement,
          snp, acknowledgement->reservations.designated, frame, *scratch, context.now);
      require(ack.status == SnpExchangeStatus::encoded &&
          context.updates[index]->level(0U)->transient_acknowledgements() == 1U);
      const bool ack_admitted = fabric->enqueue({index, 1U}, 0U, frame) == lab::MultiDeviceFabric::DropReason::none;
      require(ack_admitted && acknowledgement->reservations.snp.complete(acknowledgement->synchronization_epoch,
          ack.ticket, ack_admitted, context.now).accepted &&
          !context.updates[index]->level(0U)->transient_acknowledgements());
    }
    flush();
  }
  require(context.circuits[2U]->down(context.observer(2U)) &&
      context.events[2U].down == 2U && context.events[2U].old_areas &&
      context.events[2U].update_ok && !context.updates[2U]->outputs(0U, 0U));
  flood();
  require(!context.origins[2U]->contains(0U, context.events[2U].pseudonode) &&
      context.updates[2U]->level(0U)->database().database().find(context.events[2U].pseudonode,
          context.now)->purge_installed);
  context.active = 2U;
  require(fabric->set_carrier({2U, 1U}, false) && bridge.configure_port(2U, {1000U, 1514U, true, false}));
  round(start + 3s);
  round(start + 4s);
  context.now = start + 5s + 10ms;
  for (std::size_t index{}; index < 2U; ++index) {
    context.events[index].now = context.now;
    context.circuits[index]->service(start + 5s + 10ms, 4U, context.observer(index));
    const auto selected = context.circuits[index]->designated();
    require(selected && selected->system.back() == 2U && selected->local == (index == 1U) &&
        context.circuits[index]->neighbors().size() == 1U && context.events[index].down == 1U &&
        context.events[index].old_areas);
    require(context.events[index].update_ok && context.updates[index]->outputs(0U, 0U)->reservations.designated ==
        (index == 1U) && context.updates[index]->outputs(0U, 0U)->synchronization_epoch == 1U);
  }
  flood();
  for (std::size_t index{}; index < 2U; ++index) {
    const auto pseudonode = context.updates[index]->level(0U)->database().database().find(
        context.events[1U].pseudonode, context.now);
    require(pseudonode && pseudonode->header.sequence == 1U &&
        lsp_link_counts(pseudonode->pdu.tlvs) == std::optional{LspLinkCounts{2U, 2U}});
    const auto root = context.updates[index]->level(0U)->database().database().find(context.events[index].root, context.now);
    require(root.has_value());
    packet::isis::TlvCursor options(root->pdu.tlvs);
    bool points_to_new_dis{};
    while (const auto option = options.next()) if (option->code == 22U) {
      packet::isis::ExtendedNeighborCursor links(*option);
      const auto link = links.next();
      points_to_new_dis = points_to_new_dis || (link && link->id == context.circuits[index]->designated()->lan &&
          link->metric == 10U);
    }
    require(options.valid() && points_to_new_dis);
    check_routes(index);
  }
  // The new DIS advertises its own LAN ID only in its following Hello.
  round(start + 6s);
  for (std::size_t index{}; index < 2U; ++index) {
    const auto selected = context.circuits[index]->designated();
    require(selected && std::equal(selected->lan.begin(), selected->lan.end(),
        context.events[1U].pseudonode.begin()));
    check_routes(index, true);
  }
}
