// Authenticated local circuit events activate independent L1/L2 update owners.
// Hello, LSP and SNP bytes cross physical queues. Repeated adjacency activation
// cancels old reservations while retaining the transport configuration epoch.

#include "router/isis_instance_update.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/multi_device_fabric.hpp"

#include <source_location>
#include <stdexcept>
#include <string>
#include <limits>

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
  const UpdateLevelConfiguration value{{8U, 8192U}, 8U, 128U, 1492U, 1200U, 60s, 60s, true, true, true};
  return {value, value};
}
struct Endpoint {
  PointToPointCircuit circuit;
  InstanceUpdateProcess update;
  LevelObserver observer;
  UpdateStatus event_status{UpdateStatus::applied};
  UpdateReceiveResult received{};
  unsigned circuit_changes{};
  Endpoint(std::uint8_t id, RuntimeClock::time_point now)
      : circuit(hello_configuration(id), id, now),
        update(circuit.configuration().local.system, 3U, level_configuration(),
            std::array{UpdateCircuitConfiguration{7U, Levels::both, false, InstanceFormat::standard, 0U,
                {circuit.configuration().hello_destination, circuit.configuration().hello_destination}}}, 2U),
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
  } else endpoint.received = endpoint.update.receive(0U, 7U, delivery.frame, context.key,
      context.now, endpoint.observer);
}
}

void isis_instance_update_tests() {
  auto now = RuntimeClock::time_point{100s};
  Endpoint a(1U, now), b(2U, now);
  const auto destination_for_admission = a.circuit.configuration().hello_destination;
  const UpdateCircuitConfiguration admission_configuration{7U, Levels::both, false,
      InstanceFormat::standard, 0U, {destination_for_admission, destination_for_admission}};
  auto failing_levels = level_configuration();
  failing_levels[1U]->snp_entry_capacity = std::numeric_limits<std::size_t>::max();
  InstanceUpdateProcess failing(a.circuit.configuration().local.system, 3U, failing_levels, {}, 1U);
  for (unsigned attempt{}; attempt < 2U; ++attempt) {
    const auto refused = failing.admit_circuit(admission_configuration);
    require(refused.status == UpdateStatus::level_refused &&
        refused.level_status == LevelStatus::invalid_configuration && !refused.index);
    require(!failing.level(0U)->database().circuit_state(0U) &&
        !failing.level(1U)->database().circuit_state(0U));
  }
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
  require(a.update.outputs(0U, 0U)->synchronization_epoch == 1U &&
      a.update.outputs(0U, 1U)->synchronization_epoch == 1U);
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
  contents.instance.reset();
  contents.header.id[5U] = 2U;
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
  // An accepted same-system Hello may update its SNPA without inventing an
  // ISO Down. The update owner must follow the circuit's accepted projection.
  context.now += 1s;
  const auto moved = b.circuit.hello(*frame, std::nullopt, *scratch, context.now);
  require(moved && *moved == HelloBuildResult::encoded);
  frame->bytes[11U] = 9U;
  transmit(1U);
  require(b.circuit.complete_hello(true, context.now) && a.event_status == UpdateStatus::applied &&
      a.circuit.adjacency().neighbor_mac[5U] == 9U && a.update.outputs(0U, 0U));
}
