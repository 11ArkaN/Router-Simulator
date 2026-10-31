// Authenticated local circuit events activate independent L1/L2 update owners.
// Hello, LSP and SNP bytes cross physical queues. Repeated adjacency activation
// cancels old reservations while retaining the transport configuration epoch.

#include "router/isis_instance_update.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/multi_device_fabric.hpp"

#include <algorithm>
#include <source_location>
#include <stdexcept>
#include <string>
#include <limits>
#include <vector>

namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS instance update invariant failed at " + std::to_string(location.line()));
}
P2pCircuitConfiguration hello_configuration(std::uint8_t id) {
  P2pCircuitConfiguration result;
  result.local = {{1U, 2U, 3U, 4U, 5U, id}, id, id, Levels::both, true};
  result.mac = {2U, 0U, 0U, 0U, 0U, id};
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area;
  area.bytes = {0x49U, 0U, 1U};
  area.length = 3U;
  result.areas.push_back(area);
  result.protocols.push_back(ipv4_nlpid);
  result.ipv4_addresses.push_back({192U, 0U, 2U, id});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = 3U;
  result.hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.peer_attribute_octets = 512U;
  return result;
}
std::array<std::optional<UpdateLevelConfiguration>, 2U> level_configuration() {
  const UpdateLevelConfiguration value{{8U, 8192U}, 8U, 128U, 1492U, 1200U, 60s, 60s, true, true, true, PurgeRules::registry_6233};
  return {value, value};
}
struct Endpoint {
  PointToPointCircuit circuit;
  InstanceUpdateProcess update;
  LevelObserver observer;
  UpdateStatus event_status{UpdateStatus::applied};
  UpdateReceiveResult received{};
  unsigned circuit_changes{};
  Endpoint(std::uint8_t id, RuntimeClock::time_point now, std::uint64_t initial_epoch = 41U)
      : circuit(hello_configuration(id), id, now),
        update(circuit.configuration().local.system, 3U, level_configuration(),
            std::array{UpdateCircuitConfiguration{7U, Levels::both, false, InstanceFormat::standard, 0U,
                {circuit.configuration().hello_destination, circuit.configuration().hello_destination}}}, {InstanceFormat::standard, 0U}, 2U, initial_epoch),
        observer{this, +[](void *opaque, const LevelEvent &value) noexcept {
          if (value.kind == LevelEventKind::circuit_changed) ++static_cast<Endpoint *>(opaque)->circuit_changes;
        }} {}
};
void event(void *opaque, const P2pCircuitEvent &value) noexcept {
  auto &endpoint = *static_cast<Endpoint *>(opaque);
  endpoint.event_status = endpoint.update.p2p(0U, 7U, value, endpoint.observer);
}
struct Context {
  std::array<Endpoint *, 2U> endpoints;
  AuthenticationKey key;
  RuntimeClock::time_point now;
  bool accept_local_copies{};
  bool accept_retired_purges{};
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
  auto &context = *static_cast<Context *>(opaque);
  auto &endpoint = *context.endpoints[delivery.destination.node.index];
  EthernetDecodeError error{};
  const auto decoded = parse_ethernet_pdu(delivery.frame.view(), error);
  require(decoded.has_value());
  if (decoded->pdu.type == PduType::point_to_point_hello) {
    require(endpoint.circuit.receive(delivery.frame, std::nullopt, context.now, &endpoint, event) ==
        CircuitReceive::accepted);
    require(endpoint.event_status == UpdateStatus::applied);
  } else {
    endpoint.received = endpoint.update.receive(0U, 7U, delivery.frame, context.key,
        context.now, endpoint.observer);
    if (context.accept_local_copies && endpoint.received.status == UpdateStatus::self_originated) {
      if (context.accept_retired_purges && !endpoint.received.local_lsp->remaining_seconds)
        endpoint.received = endpoint.update.receive_retired_local_purge(0U, 7U, delivery.frame, context.key,
            context.now, endpoint.observer);
      else endpoint.received = endpoint.update.receive_local_copy(0U, 7U, delivery.frame, context.key,
          context.now, endpoint.observer);
    }
  }
}
}

void isis_instance_update_tests() {
  auto now = RuntimeClock::time_point{100s};
  Endpoint a(1U, now), b(2U, now);
  require(a.update.maximum_synchronization_epoch() == 41U && b.update.maximum_synchronization_epoch() == 41U);
  const auto destination_for_admission = a.circuit.configuration().hello_destination;
  const UpdateCircuitConfiguration admission_configuration{7U, Levels::both, false,
      InstanceFormat::standard, 0U, {destination_for_admission, destination_for_admission}};
  auto failing_levels = level_configuration();
  failing_levels[1U]->snp_entry_capacity = std::numeric_limits<std::size_t>::max();
  InstanceUpdateProcess failing(a.circuit.configuration().local.system, 3U, failing_levels, {}, {InstanceFormat::standard, 0U}, 1U);
  for (unsigned attempt{}; attempt < 2U; ++attempt) {
    const auto refused = failing.admit_circuit(admission_configuration);
    require(refused.status == UpdateStatus::level_refused &&
        refused.level_status == LevelStatus::invalid_configuration && !refused.index);
    require(!failing.level(0U)->database().circuit_state(0U) &&
        !failing.level(1U)->database().circuit_state(0U));
  }
  InstanceUpdateProcess rollback(a.circuit.configuration().local.system, 3U, level_configuration(), {}, {InstanceFormat::standard, 0U}, 1U);
  auto first_admission = rollback.admit_circuit(admission_configuration);
  auto delayed_admission = first_admission;
  require(first_admission.appended && rollback.cancel_circuit_admission(first_admission));
  require(!rollback.cancel_circuit_admission(first_admission));
  auto second_admission = rollback.admit_circuit(admission_configuration);
  require(second_admission.appended && !rollback.cancel_circuit_admission(delayed_admission));
  require(rollback.cancel_circuit_admission(second_admission));
  auto reusable = rollback.admit_circuit(admission_configuration);
  require(rollback.release_circuit(0U, 7U) == UpdateStatus::applied);
  auto next_configuration = admission_configuration;
  next_configuration.configuration_epoch = 8U;
  auto temporary = rollback.admit_circuit(next_configuration);
  require(!temporary.appended && !rollback.cancel_circuit_admission(reusable));
  auto delayed_temporary = temporary;
  require(rollback.cancel_circuit_admission(temporary));
  auto retried = rollback.admit_circuit(next_configuration);
  require(retried.status == UpdateStatus::applied && !rollback.cancel_circuit_admission(delayed_temporary));
  require(rollback.cancel_circuit_admission(retried));
  auto unresolved_levels = level_configuration();
  unresolved_levels[0U]->purge_rules = PurgeRules::unspecified;
  bool unresolved_rejected{};
  try {
    InstanceUpdateProcess unresolved(a.circuit.configuration().local.system, 3U, unresolved_levels,
        {}, {InstanceFormat::standard, 0U}, 1U);
  } catch (const std::invalid_argument &) { unresolved_rejected = true; }
  require(unresolved_rejected);
  auto wrong_selector = admission_configuration;
  wrong_selector.wire_instance = 1U;
  require(a.update.admit_circuit(wrong_selector).status == UpdateStatus::invalid_configuration);
  auto invalid = admission_configuration;
  invalid.format = static_cast<InstanceFormat>(255U);
  require(a.update.admit_circuit(invalid).status == UpdateStatus::invalid_configuration);
  const std::array<std::uint8_t, 6U> secret{1U, 2U, 3U, 4U, 5U, 6U};
  const AuthenticationKey key{AuthenticationMethod::hmac_sha256, 7U, secret};
  Context context{{&a, &b}, key, now};
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(lab::DeviceHandle{0U, 1U}), 0U, 1U},
      {lab::node(lab::DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true));
  auto scratch = std::make_unique<PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  const auto transmit = [&](std::uint8_t direction) {
    require(fabric->enqueue(link, direction, *frame) == lab::MultiDeviceFabric::DropReason::none);
    fabric->pump_transmit(context.now);
    context.now += 1ms;
    fabric->pump_delivery(&context, delivered, context.now);
  };
  const auto round = [&] {
    for (std::uint8_t index{}; index < 2U; ++index) {
      auto &endpoint = *context.endpoints[index];
      const auto built = endpoint.circuit.hello(*frame, std::nullopt, *scratch, context.now);
      if (!built) continue;
      require(*built == HelloBuildResult::encoded);
      transmit(index);
      require(endpoint.circuit.complete_hello(true, context.now));
    }
    context.now += 1s;
  };
  require(!a.update.outputs(0U, 0U) && !b.update.outputs(0U, 1U));
  for (unsigned index{}; index < 6U; ++index) round();
  require(a.circuit.adjacency().iso_up && b.circuit.adjacency().iso_up);
  require(a.update.outputs(0U, 0U)->synchronization_epoch == 41U &&
      a.update.outputs(0U, 1U)->synchronization_epoch == 41U);
  const auto source = a.circuit.configuration().mac;
  const auto destination = a.circuit.configuration().hello_destination;
  std::array<std::uint8_t, 128U> semantic{};
  TlvWriter writer(semantic);
  const std::array<std::uint8_t, 3U> area{0x49U, 0U, 1U};
  const std::array<std::span<const std::uint8_t>, 1U> areas{area};
  require(encode_area_addresses(writer, areas));
  const std::array<std::uint8_t, 1U> protocol{ipv4_nlpid};
  require(writer.append(129U, protocol));
  LspContents contents;
  contents.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U}, 1200U, 1U, 3U};
  contents.options = writer.bytes();
  contents.authentication = key;
  contents.maximum_pdu_octets = 1492U;
  for (std::size_t level{}; level < 2U; ++level) {
    contents.header.type = level ? PduType::lsp_l2 : PduType::lsp_l1;
    const auto built = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded && a.update.originate(level, built.bytes,
        context.now, OriginPurgeReason::none, a.observer).install == LspInstallResult::installed);
    auto output = a.update.outputs(0U, level);
    const auto sent = output->reservations.lsp.prepare(contents.header.id, source, destination,
        1492U, 1U, *frame, *scratch, context.now);
    require(sent.status == LspEmissionStatus::encoded);
    transmit(0U);
    require(b.received.status == UpdateStatus::applied && b.received.level == level &&
        b.update.level(level)->database().size() == 1U);
    require(output->reservations.lsp.complete(output->synchronization_epoch, sent.ticket,
        true, context.now).accepted);
    require(a.update.level(level)->database().flags(contents.header.id, 0U)->srm &&
        b.update.level(level)->database().flags(contents.header.id, 0U)->ssn);
    auto acknowledgement = b.update.outputs(0U, level);
    SnpContents snp;
    snp.header.type = level ? PduType::psnp_l2 : PduType::psnp_l1;
    snp.header.source = b.circuit.configuration().local.system;
    snp.source = b.circuit.configuration().mac;
    snp.destination = destination;
    snp.authentication = key;
    snp.maximum_pdu_octets = 1492U;
    const auto ack = acknowledgement->reservations.snp.prepare(SnpEmission::partial,
        snp, false, *frame, *scratch, context.now);
    require(ack.status == SnpExchangeStatus::encoded);
    transmit(1U);
    require(a.received.status == UpdateStatus::applied && !a.update.level(level)->database().flags(
        contents.header.id, 0U)->srm);
    require(acknowledgement->reservations.snp.complete(acknowledgement->synchronization_epoch,
        ack.ticket, true, context.now).accepted);
    const auto live_options = contents.options;
    contents.header.id.back() = 7U;
    contents.header.remaining_seconds = 0U;
    contents.header.sequence = 29U;
    contents.options = {};
    const auto purge = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(purge.status == LspBuildStatus::encoded && a.update.originate(level, purge.bytes,
        context.now, OriginPurgeReason::initiated, a.observer).install == LspInstallResult::installed);
    const auto purged = output->reservations.lsp.prepare(contents.header.id, source, destination,
        1492U, 1U, *frame, *scratch, context.now);
    require(purged.status == LspEmissionStatus::encoded);
    transmit(0U);
    require(b.received.status == UpdateStatus::applied && b.update.level(level)->database().size() == 1U &&
        b.update.level(level)->transient_acknowledgements() == 1U);
    require(output->reservations.lsp.complete(output->synchronization_epoch, purged.ticket,
        true, context.now).accepted);
    const auto purge_ack = acknowledgement->reservations.snp.prepare(SnpEmission::transient_acknowledgement,
        snp, false, *frame, *scratch, context.now);
    require(purge_ack.status == SnpExchangeStatus::encoded);
    transmit(1U);
    require(a.received.status == UpdateStatus::applied &&
        !a.update.level(level)->database().flags(contents.header.id, 0U)->srm);
    require(acknowledgement->reservations.snp.complete(acknowledgement->synchronization_epoch,
        purge_ack.ticket, true, context.now).accepted && !b.update.level(level)->transient_acknowledgements());
    contents.header.id.back() = 0U;
    contents.header.remaining_seconds = 1200U;
    contents.header.sequence = 1U;
    contents.options = live_options;
  }
  const auto candidate = [&] {
    const auto built = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded && ethernet_pdu_into(*frame, source,
        destination, built.bytes));
    transmit(0U);
    return b.received;
  };
  contents.header.type = PduType::lsp_l1;
  contents.header.sequence = 2U;
  const std::array<std::uint8_t, 3U> wrong_secret{4U, 5U, 6U};
  contents.authentication = AuthenticationKey{AuthenticationMethod::hmac_sha256, 7U, wrong_secret};
  require(candidate().status == UpdateStatus::authentication);
  require(b.update.level(0U)->database().database().find(contents.header.id, context.now)->header.sequence == 1U);
  contents.authentication = key;
  contents.header.maximum_area_addresses = 4U;
  require(candidate().status == UpdateStatus::maximum_areas);
  contents.header.type = PduType::lsp_l2;
  require(candidate().status == UpdateStatus::applied);
  // ISO 7.3.15 requires a same-level adjacency on a logical P2P circuit. Its
  // broadcast-only SNPA lookup is not added to P2P-over-LAN acceptance.
  frame->bytes[11U] = 9U;
  transmit(0U);
  require(b.received.status == UpdateStatus::applied);
  contents.header.type = PduType::lsp_l1;
  contents.header.maximum_area_addresses = 3U;
  const std::array<std::uint16_t, 1U> topology{0U};
  contents.instance = PduInstanceOption{InstanceFormat::standard, 7U, topology};
  require(candidate().status == UpdateStatus::instance);
  EthernetDecodeError wrong_envelope{};
  const auto wrong_instance_pdu = parse_ethernet_pdu(frame->view(), wrong_envelope);
  require(wrong_instance_pdu && a.update.originate(0U, wrong_instance_pdu->pdu.bytes, context.now,
      OriginPurgeReason::none, a.observer).status == LevelStatus::invalid_configuration);
  contents.instance.reset();
  contents.header.id[5U] = 2U;
  contents.options = {};
  const auto local = candidate();
  require(local.status == UpdateStatus::self_originated && local.local_lsp &&
      local.local_lsp->id == contents.header.id && b.update.level(0U)->database().size() == 1U);
  constexpr auto prefix = packet::ethernet_header_octets + packet::llc_ui_header_octets;
  frame->bytes[prefix + lsp_checksum_offset] = 0U;
  frame->bytes[prefix + lsp_checksum_offset + 1U] = 0U;
  transmit(0U);
  require(b.received.status == UpdateStatus::self_originated &&
      b.received.local_lsp->remaining_seconds == 0U);
  SnpContents complete;
  complete.header.type = PduType::csnp_l1;
  complete.header.source = a.circuit.configuration().local.system;
  complete.source = source;
  complete.destination = destination;
  complete.authentication = key;
  complete.maximum_pdu_octets = 1492U;
  SnpTransmission old;
  std::uint64_t old_epoch{};
  {
    const auto output = a.update.outputs(0U, 0U);
    old = output->reservations.snp.prepare(SnpEmission::complete, complete, false,
        *frame, *scratch, context.now);
    require(old.status == SnpExchangeStatus::encoded);
    old_epoch = output->synchronization_epoch;
  }
  const auto admitted = a.update.admit_circuit(admission_configuration);
  require(admitted.status == UpdateStatus::applied && admitted.index == 1U &&
      !a.update.outputs(1U, 0U) && !a.update.outputs(1U, 1U));
  require(a.update.admit_circuit(admission_configuration).status == UpdateStatus::capacity);
  {
    const auto retained = a.update.outputs(0U, 0U);
    require(retained->reservations.snp.complete(old_epoch, old.ticket, false, context.now).accepted);
    old = retained->reservations.snp.prepare(SnpEmission::complete, complete, false,
        *frame, *scratch, context.now);
    require(old.status == SnpExchangeStatus::encoded);
  }
  require(a.circuit.down(&a, event) && a.event_status == UpdateStatus::applied &&
      !a.update.outputs(0U, 0U) && !a.update.outputs(0U, 1U));
  require(a.circuit.up(context.now));
  for (unsigned index{}; index < 6U; ++index) round();
  const auto output = a.update.outputs(0U, 0U);
  require(output && output->synchronization_epoch == old_epoch + 1U &&
      !output->reservations.snp.complete(old_epoch, old.ticket, true, context.now).accepted);
  require(a.update.level(0U)->database().size() == 2U && a.update.level(1U)->database().size() == 2U);
  require(a.update.receive(0U, 6U, *frame, key, context.now, a.observer).status ==
      UpdateStatus::stale_configuration);
  const auto changes = a.circuit_changes;
  const auto synchronization_epoch = a.update.outputs(0U, 0U)->synchronization_epoch;
  require(b.circuit.down(&b, event) && b.circuit.up(context.now));
  const auto restarted = b.circuit.hello(*frame, std::nullopt, *scratch, context.now);
  require(restarted && *restarted == HelloBuildResult::encoded);
  transmit(1U);
  require(b.circuit.complete_hello(true, context.now));
  require(a.circuit.adjacency().iso_up && a.circuit.adjacency().three_way == ThreeWayState::initializing &&
      a.update.outputs(0U, 0U) && a.circuit_changes == changes);
  for (unsigned index{}; index < 6U; ++index) round();
  require(a.circuit.adjacency().three_way == ThreeWayState::up && a.circuit_changes == changes + 2U &&
      a.update.outputs(0U, 0U)->synchronization_epoch == synchronization_epoch);
  require(a.update.maximum_synchronization_epoch() == synchronization_epoch);
  // An accepted same-system Hello may update its SNPA without inventing an
  // ISO Down. The update owner must follow the circuit's accepted projection.
  context.now += 1s;
  const auto moved = b.circuit.hello(*frame, std::nullopt, *scratch, context.now);
  require(moved && *moved == HelloBuildResult::encoded);
  frame->bytes[11U] = 9U;
  transmit(1U);
  require(b.circuit.complete_hello(true, context.now) && a.event_status == UpdateStatus::applied &&
      a.circuit.adjacency().neighbor_mac[5U] == 9U && a.update.outputs(0U, 0U));
  require(a.update.release_circuit(0U, 7U) == UpdateStatus::invalid_event);
  require(a.update.release_circuit(1U, 6U) == UpdateStatus::stale_configuration);
  require(a.update.release_circuit(1U, 7U) == UpdateStatus::applied);
  require(a.update.release_circuit(1U, 7U) == UpdateStatus::invalid_circuit);
  require(a.update.admit_circuit(admission_configuration).status == UpdateStatus::stale_configuration);
  auto replacement_configuration = admission_configuration;
  replacement_configuration.configuration_epoch = 8U;
  const auto reused = a.update.admit_circuit(replacement_configuration);
  require(reused.status == UpdateStatus::applied && reused.index == 1U &&
      a.update.level(0U)->database().size() == 2U && !a.update.outputs(1U, 0U));
  const auto retired_epoch = a.update.maximum_synchronization_epoch();
  require(a.circuit.down(&a, event));
  require(a.update.release_circuit(0U, 7U) == UpdateStatus::applied);
  require(a.update.p2p(0U, 7U, {}, a.observer) == UpdateStatus::invalid_circuit);
  require(a.update.receive(0U, 7U, *frame, key, context.now, a.observer).status == UpdateStatus::invalid_circuit);
  const auto rebound = a.update.admit_circuit(replacement_configuration);
  require(rebound.status == UpdateStatus::applied && rebound.index == 0U);
  P2pCircuitEvent rebound_up{};
  rebound_up.after = b.circuit.adjacency();
  rebound_up.transition.outcome = P2pOutcome::up;
  require(a.update.p2p(0U, 7U, rebound_up, a.observer) == UpdateStatus::stale_configuration);
  require(a.update.p2p(0U, 8U, rebound_up, a.observer) == UpdateStatus::applied);
  require(a.update.outputs(0U, 0U)->synchronization_epoch == retired_epoch + 1U &&
      a.update.level(0U)->database().size() == 2U);
  Endpoint successor(1U, context.now, retired_epoch + 1U);
  context.endpoints[0U] = &successor;
  for (unsigned index{}; index < 6U; ++index) round();
  auto successor_output = successor.update.outputs(0U, 0U);
  require(successor_output && successor_output->synchronization_epoch == retired_epoch + 1U &&
      successor.update.maximum_synchronization_epoch() == retired_epoch + 1U);
  const auto first_after_restart = successor_output->reservations.snp.prepare(SnpEmission::complete,
      complete, false, *frame, *scratch, context.now);
  require(first_after_restart.status == SnpExchangeStatus::encoded && first_after_restart.ticket == 1U &&
      !successor_output->reservations.snp.complete(retired_epoch, first_after_restart.ticket, true, context.now).accepted);
  transmit(0U);
  require(successor_output->reservations.snp.complete(successor_output->synchronization_epoch,
      first_after_restart.ticket, true, context.now).accepted);
  Endpoint c(3U, context.now), d(4U, context.now);
  context.endpoints = {&c, &d};
  for (unsigned index{}; index < 6U; ++index) round();
  LspContents owned;
  owned.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 3U, 0U, 0U}, 1200U, 1U, 3U};
  owned.authentication = key;
  owned.maximum_pdu_octets = 1492U;
  owned.options = writer.bytes();
  auto built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && c.update.originate(0U, built.bytes,
      context.now, OriginPurgeReason::none, c.observer).install == LspInstallResult::installed);
  auto c_output = c.update.outputs(0U, 0U);
  auto sent = c_output->reservations.lsp.prepare(owned.header.id, c.circuit.configuration().mac,
      destination, 1492U, 1U, *frame, *scratch, context.now);
  require(sent.status == LspEmissionStatus::encoded);
  transmit(0U);
  require(c_output->reservations.lsp.complete(c_output->synchronization_epoch, sent.ticket, true, context.now).accepted);
  require(d.received.status == UpdateStatus::applied);
  owned.header.remaining_seconds = 0U;
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && ethernet_pdu_into(*frame,
      c.circuit.configuration().mac, destination, built.bytes));
  transmit(0U);
  require(d.received.status == UpdateStatus::purge_options &&
      d.update.level(0U)->database().database().find(owned.header.id, context.now)->header.remaining_seconds != 0U);
  const std::array<std::uint8_t, 3U> extension{201U, 1U, 0xa5U};
  owned.options = extension;
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && ethernet_pdu_into(*frame,
      c.circuit.configuration().mac, destination, built.bytes));
  transmit(0U);
  require(d.received.status == UpdateStatus::purge_options);
  std::array<std::uint8_t, 64U> purge_options{};
  TlvWriter purge_writer(purge_options);
  require(purge_writer.append(201U, std::span(extension).subspan(2U)) &&
      encode_purge_originator(purge_writer, {c.circuit.configuration().local.system, std::nullopt}));
  owned.options = purge_writer.bytes();
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded);
  const std::vector<std::uint8_t> retained_purge(built.bytes.begin(), built.bytes.end());
  require(c.update.originate(0U, built.bytes, context.now, OriginPurgeReason::initiated,
      c.observer).install == LspInstallResult::installed);
  sent = c_output->reservations.lsp.prepare(owned.header.id, c.circuit.configuration().mac,
      destination, 1492U, 1U, *frame, *scratch, context.now);
  require(sent.status == LspEmissionStatus::encoded);
  transmit(0U);
  require(c_output->reservations.lsp.complete(c_output->synchronization_epoch, sent.ticket, true, context.now).accepted);
  const auto received_purge = d.update.level(0U)->database().database().find(owned.header.id, context.now);
  require(d.received.status == UpdateStatus::applied && received_purge && received_purge->purge_installed &&
      std::equal(received_purge->pdu.bytes.begin(), received_purge->pdu.bytes.end(), retained_purge.begin(), retained_purge.end()));
  require(d.circuit.down(&d, event) && d.circuit.up(context.now));
  for (unsigned index{}; index < 6U; ++index) round();
  auto d_output = d.update.outputs(0U, 0U);
  sent = d_output->reservations.lsp.prepare(owned.header.id, d.circuit.configuration().mac,
      destination, 1492U, 1U, *frame, *scratch, context.now);
  EthernetDecodeError envelope{};
  const auto forwarded = parse_ethernet_pdu(frame->view(), envelope);
  require(sent.status == LspEmissionStatus::encoded && forwarded &&
      std::equal(forwarded->pdu.bytes.begin(), forwarded->pdu.bytes.end(), retained_purge.begin(), retained_purge.end()));
  transmit(1U);
  require(d_output->reservations.lsp.complete(d_output->synchronization_epoch, sent.ticket, true, context.now).accepted);
  // A sender must not generate live POI. A receiver still retains and floods
  // the LSP, ignoring the misplaced TLV under RFC 8918 rather than rejecting it.
  owned.header.remaining_seconds = 1200U;
  owned.header.sequence = 2U;
  require(build_lsp_pdu(owned, scratch->options, scratch->pdu).status == LspBuildStatus::options);
  TlvWriter raw_options(scratch->options);
  TlvCursor raw_cursor(owned.options);
  while (const auto option = raw_cursor.next()) require(raw_options.append(option->code, option->value));
  require(append_authentication(raw_options, key));
  const auto raw_live = encode_lsp(scratch->pdu, owned.header, raw_options.bytes());
  require(raw_live && finalize_authentication(std::span(scratch->pdu).first(raw_live->size()), key,
      c.circuit.configuration().local.system) == AuthenticationError::none);
  require(ethernet_pdu_into(*frame, c.circuit.configuration().mac, destination, *raw_live));
  transmit(0U);
  require(d.received.status == UpdateStatus::applied &&
      d.update.level(0U)->database().database().find(owned.header.id, context.now)->header.sequence == 2U);

  const auto expires_at = context.now + 1200s;
  const auto before_expiration = d.update.level(0U)->database().database().find(owned.header.id, context.now);
  const auto foreign_checksum = before_expiration->header.checksum;
  const auto allocation = d.update.level(0U)->database().database().allocated_octets();
  const auto retained_address = before_expiration->pdu.bytes.data();
  const auto expiry = d.update.next_database_deadline();
  require(expiry && expiry->level == 0U && expiry->deadline.kind == LspDeadlineKind::finalize_expiration &&
      expiry->deadline.at == expires_at);
  require(d.update.finalize_expiration(0U, owned.header.id, {true, key}, expires_at - 1s,
      scratch->options, scratch->pdu, d.observer).status == UpdateStatus::inactive);
  require(d.circuit.expire(expires_at, &d, event));
  require(d.update.finalize_expiration(0U, owned.header.id, {true, std::nullopt}, expires_at + 10s,
      scratch->options, scratch->pdu, d.observer).status == UpdateStatus::authentication);
  require(!d.update.level(0U)->database().database().find(owned.header.id, expires_at + 10s)->purge_installed);
  const auto finalized = d.update.finalize_expiration(0U, owned.header.id, {true, key}, expires_at + 10s,
      scratch->options, scratch->pdu, d.observer);
  require(finalized.status == UpdateStatus::applied && finalized.origin.install == LspInstallResult::installed);
  const auto expired = d.update.level(0U)->database().database().find(owned.header.id, expires_at + 10s);
  require(expired && expired->purge_installed && expired->header.checksum == foreign_checksum &&
      expired->pdu.bytes.data() == retained_address &&
      d.update.level(0U)->database().database().allocated_octets() == allocation &&
      verify_authentication(expired->pdu.bytes, key) == AuthenticationError::none);
  TlvCursor expired_options(expired->pdu.tlvs);
  const auto expired_poi = expired_options.next();
  require(expired_poi && decode_purge_originator(*expired_poi)->originator == d.circuit.configuration().local.system &&
      expired_options.next()->code == 10U && !expired_options.next() && expired_options.valid());
  require(!valid_lsp_checksum(expired->pdu) && ethernet_pdu_into(*frame,
      d.circuit.configuration().mac, destination, expired->pdu.bytes));
  transmit(1U);
  require(c.received.status == UpdateStatus::self_originated &&
      c.received.local_lsp->remaining_seconds == 0U && c.received.local_lsp->checksum == foreign_checksum);
  const auto retire = d.update.next_database_deadline();
  require(retire && retire->deadline.kind == LspDeadlineKind::retire_purge && retire->deadline.at == expires_at + 60s);
  require(!d.update.retire_purge(0U, owned.header.id, expires_at + 59s, d.observer) &&
      d.update.retire_purge(0U, owned.header.id, expires_at + 60s, d.observer) && !d.update.next_database_deadline());

  Endpoint e(5U, context.now), f(6U, context.now);
  context.endpoints = {&e, &f};
  context.accept_local_copies = true;
  for (unsigned index{}; index < 6U; ++index) round();
  owned.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 5U, 0U, 0U}, 1200U, 5U, 3U};
  owned.options = writer.bytes();
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && e.update.originate(0U, built.bytes,
      context.now, OriginPurgeReason::none, e.observer).install == LspInstallResult::installed);
  const auto copy = [&] {
    const auto pdu = build_lsp_pdu(owned, scratch->options, scratch->pdu);
    require(pdu.status == LspBuildStatus::encoded && ethernet_pdu_into(*frame,
        f.circuit.configuration().mac, destination, pdu.bytes));
    transmit(1U);
  };
  copy();
  const auto flags = [&] { return e.update.level(0U)->database().flags(owned.header.id, 0U); };
  require(e.received.status == UpdateStatus::applied && flags()->ssn && !flags()->srm);
  owned.header.sequence = 4U;
  copy();
  require(e.received.status == UpdateStatus::applied && flags()->srm && !flags()->ssn);
  owned.header.sequence = 6U;
  copy();
  require(e.received.status == UpdateStatus::self_originated &&
      e.update.level(0U)->database().database().find(owned.header.id, context.now)->header.sequence == 5U);
  owned.header.sequence = 5U;
  owned.header.flags = 7U;
  copy();
  require(e.received.status == UpdateStatus::self_originated);
  owned.header.flags = 3U;
  owned.header.remaining_seconds = 0U;
  owned.options = {};
  copy();
  require(e.received.status == UpdateStatus::self_originated &&
      !e.update.level(0U)->database().database().find(owned.header.id, context.now)->purge_installed);
  owned.header.id.back() = 1U;
  copy();
  require(e.received.status == UpdateStatus::applied && e.update.level(0U)->transient_acknowledgements() == 1U &&
      !e.update.level(0U)->database().database().find(owned.header.id, context.now));
  const auto zero_sequence = parse_ethernet_pdu(frame->view(), envelope);
  require(zero_sequence.has_value());
  std::fill_n(frame->bytes.begin() + prefix + 20U, 4U, std::uint8_t{});
  require(finalize_authentication(std::span(frame->bytes).subspan(prefix, zero_sequence->pdu.bytes.size()),
      key, e.circuit.configuration().local.system) == AuthenticationError::none);
  transmit(1U);
  require(e.received.status == UpdateStatus::malformed && e.update.level(0U)->transient_acknowledgements() == 1U);

  owned.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 5U, 0U, 2U}, 1200U, 20U, 3U};
  owned.options = writer.bytes();
  copy();
  require(e.received.status == UpdateStatus::self_originated && e.received.local_lsp);
  const auto unknown_live = *e.received.local_lsp;
  require(e.update.purge_unknown_source(0U, unknown_live, 3U, {true, std::nullopt}, context.now,
      scratch->options, scratch->pdu, e.observer).status == UpdateStatus::authentication);
  require(!e.update.level(0U)->database().database().find(unknown_live.id, context.now));
  require(e.update.purge_unknown_source(0U, unknown_live, 3U, {true, key}, context.now,
      scratch->options, scratch->pdu, e.observer).origin.install == LspInstallResult::installed);
  auto unknown_purge = e.update.level(0U)->database().database().find(unknown_live.id, context.now);
  require(unknown_purge && unknown_purge->purge_installed && unknown_purge->header.sequence == 20U &&
      verify_authentication(unknown_purge->pdu.bytes, key) == AuthenticationError::none);
  owned.header.sequence = 21U;
  copy();
  require(e.received.status == UpdateStatus::self_originated && e.received.local_lsp);
  require(e.update.purge_unknown_source(0U, *e.received.local_lsp, 3U, {true, key}, context.now,
      scratch->options, scratch->pdu, e.observer).origin.install == LspInstallResult::installed);
  unknown_purge = e.update.level(0U)->database().database().find(unknown_live.id, context.now);
  require(unknown_purge->header.sequence == 21U && unknown_purge->purge_installed);

  owned.header.id.back() = 3U;
  owned.header.sequence = 7U;
  owned.header.remaining_seconds = 2U;
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && e.update.originate(0U, built.bytes, context.now,
      OriginPurgeReason::none, e.observer).install == LspInstallResult::installed);
  for (unsigned index{}; index < 2U; ++index) round();
  owned.header.remaining_seconds = 1200U;
  // An expired cached body does not establish current generated-set
  // membership. This incarnation is handled by the unknown-source owner.
  context.accept_local_copies = false;
  copy();
  require(e.received.status == UpdateStatus::self_originated && e.received.local_lsp);
  const auto initiated_at = context.now;
  require(e.update.purge_unknown_source(0U, *e.received.local_lsp, 3U, {true, key}, initiated_at,
      scratch->options, scratch->pdu, e.observer).origin.install == LspInstallResult::installed);
  const auto initiated_id = owned.header.id;
  context.accept_local_copies = true;

  owned.header.id.back() = 5U;
  owned.header.sequence = 50U;
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && e.update.originate(0U, built.bytes, context.now,
      OriginPurgeReason::none, e.observer).install == LspInstallResult::installed);
  owned.header.sequence = 40U;
  context.accept_local_copies = false;
  copy();
  require(e.received.status == UpdateStatus::self_originated && e.received.local_lsp);
  require(e.update.purge_unknown_source(0U, *e.received.local_lsp, 3U, {true, key}, context.now,
      scratch->options, scratch->pdu, e.observer).origin.install == LspInstallResult::installed);
  const auto newer_unknown = e.update.level(0U)->database().database().find(owned.header.id, context.now);
  require(newer_unknown && newer_unknown->purge_installed && newer_unknown->header.sequence == 50U);
  context.accept_local_copies = true;

  owned.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 3U, 3U};
  copy();
  require(e.received.status == UpdateStatus::applied);
  const auto foreign_before = e.update.level(0U)->database().database().find(owned.header.id, context.now);
  const auto before_checksum = foreign_before->header.checksum;
  const auto *before_address = foreign_before->pdu.bytes.data();
  owned.header.flags = 7U;
  copy();
  require(e.received.lsp.database.install == LspInstallResult::confusion);
  const auto conflicting_frame = parse_ethernet_pdu(frame->view(), envelope);
  const auto conflicting_header = lsp(conflicting_frame->pdu);
  require(conflicting_header && conflicting_header->checksum != before_checksum);
  const auto confused_at = context.now;
  require(e.update.finalize_confusion(0U, *conflicting_header, {true, std::nullopt}, confused_at,
      scratch->options, scratch->pdu, e.observer).status == UpdateStatus::authentication);
  require(e.update.finalize_confusion(0U, *conflicting_header, {true, key}, confused_at,
      scratch->options, scratch->pdu, e.observer).origin.install == LspInstallResult::installed);
  const auto confusion_purge = e.update.level(0U)->database().database().find(owned.header.id, confused_at);
  require(confusion_purge && confusion_purge->purge_installed && confusion_purge->header.checksum == before_checksum &&
      confusion_purge->pdu.bytes.data() == before_address &&
      verify_authentication(confusion_purge->pdu.bytes, key) == AuthenticationError::none);
  const auto confused_id = owned.header.id;
  require(e.update.receive_retired_local_purge(0U, 7U, *frame, key, context.now, e.observer).status == UpdateStatus::invalid_event);
  owned.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 5U, 0U, 4U}, 1200U, 8U, 3U};
  built = build_lsp_pdu(owned, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded && e.update.originate(0U, built.bytes, context.now,
      OriginPurgeReason::none, e.observer).install == LspInstallResult::installed);
  owned.header.remaining_seconds = 0U;
  owned.options = {};
  copy();
  require(e.received.status == UpdateStatus::self_originated &&
      !e.update.level(0U)->database().database().find(owned.header.id, context.now)->purge_installed);
  context.accept_retired_purges = true;
  copy();
  const auto retired_at = context.now;
  require(e.received.status == UpdateStatus::applied &&
      e.update.level(0U)->database().database().find(owned.header.id, retired_at)->purge_installed);
  require(!e.update.retire_purge(0U, confused_id, confused_at + 59s, e.observer) &&
      !e.update.retire_purge(0U, owned.header.id, retired_at + 59s, e.observer) &&
      e.update.retire_purge(0U, confused_id, confused_at + 60s, e.observer) &&
      e.update.retire_purge(0U, owned.header.id, retired_at + 60s, e.observer));
  require(!e.update.retire_purge(0U, initiated_id, initiated_at + 1199s, e.observer) &&
      e.update.retire_purge(0U, initiated_id, initiated_at + 1200s, e.observer));

}

void isis_expiration_notification_tests() {
  const auto now = RuntimeClock::time_point{100s};
  const SystemId local{1U, 2U, 3U, 4U, 5U, 1U};
  const LspId id{1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U};
  const UpdateLevelConfiguration level{{4U, 4096U}, 0U, 0U, 1492U,
      1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
  InstanceUpdateProcess update(local, 3U, {level, std::nullopt}, {}, {InstanceFormat::standard, 0U});
  struct Events { unsigned changed{}, refreshed{}; } events;
  const LevelObserver observer{&events, +[](void *opaque, const LevelEvent &event) noexcept {
    auto &values = *static_cast<Events *>(opaque);
    if (event.kind == LevelEventKind::database_changed) ++values.changed;
    if (event.kind == LevelEventKind::database_refreshed) ++values.refreshed;
  }};
  auto scratch = std::make_unique<PduScratch>();
  const std::array<std::uint8_t, 3U> options{129U, 1U, ipv4_nlpid};
  LspContents content;
  content.header = {PduType::lsp_l1, id, 2U, 1U, 1U};
  content.options = options;
  content.maximum_pdu_octets = 1492U;
  auto encoded = build_lsp_pdu(content, scratch->options, scratch->pdu);
  require(encoded.status == LspBuildStatus::encoded && update.originate(0U, encoded.bytes, now,
      OriginPurgeReason::none, observer).install == LspInstallResult::installed && events.changed == 1U);
  const auto view = [&](RuntimeClock::time_point time) { return update.level(0U)->database().database().find(id, time); };
  const std::vector<std::uint8_t> original(view(now)->pdu.bytes.begin(), view(now)->pdu.bytes.end());
  auto missing = id;
  missing.back() = 1U;
  require(!update.notify_expiration(0U, id, now + 1s, observer) &&
      !update.notify_expiration(2U, id, now + 2s, observer) &&
      !update.notify_expiration(0U, missing, now + 2s, observer) &&
      !update.notify_expiration(0U, id, now + 2s, {}) && !view(now + 2s)->expiration_notified);
  require(update.notify_expiration(0U, id, now + 2s, observer) && events.changed == 2U &&
      view(now + 2s)->expiration_notified && !view(now + 2s)->purge_installed &&
      std::ranges::equal(original, view(now + 2s)->pdu.bytes));
  require(!update.notify_expiration(0U, id, now + 3s, observer) && events.changed == 2U);
  const auto refused = update.finalize_expiration(0U, id, {true, std::nullopt}, now + 3s,
      scratch->options, scratch->pdu, observer);
  require(refused.status == UpdateStatus::authentication && events.changed == 2U && !events.refreshed &&
      view(now + 3s)->expiration_notified && !view(now + 3s)->purge_installed &&
      std::ranges::equal(original, view(now + 3s)->pdu.bytes));
  const auto finalized = update.finalize_expiration(0U, id, {}, now + 10s, scratch->options, scratch->pdu, observer);
  require(finalized.status == UpdateStatus::applied && finalized.origin.install == LspInstallResult::installed &&
      events.changed == 2U && events.refreshed == 1U && view(now + 10s)->purge_installed);
  const auto retained = update.next_database_deadline();
  require(retained && retained->deadline.kind == LspDeadlineKind::retire_purge && retained->deadline.at == now + 62s);
  content.header.sequence = 2U;
  content.header.remaining_seconds = 1200U;
  encoded = build_lsp_pdu(content, scratch->options, scratch->pdu);
  require(encoded.status == LspBuildStatus::encoded && update.originate(0U, encoded.bytes, now + 11s,
      OriginPurgeReason::none, observer).install == LspInstallResult::installed && events.changed == 3U &&
      !view(now + 11s)->expiration_notified && !update.notify_expiration(0U, id, now + 12s, observer));
  require(update.notify_expiration(0U, id, now + 1211s, observer) && events.changed == 4U);
}
