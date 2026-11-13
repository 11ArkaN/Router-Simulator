// Three independent control-owned instances learn area state only from encoded
// frames through two physical links. The test owns transport and copied query
// values, and checks L2 metadata, transition history and detached restoration.
#include "router/isis_control_checkpoint.hpp"
#include "router/isis_instance_program.hpp"
#include "router/isis_ethernet.hpp"
#include "router/multi_device_fabric.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS computed area owner invariant at " + std::to_string(where.line()));
}
}
void isis_area_set_control_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 4U);
  std::uint64_t serial{};
  const auto command = [&](ControlCommand request) {
    request.id = ++serial;
    const auto until = RuntimeClock::now() + 4s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == serial); return result;
  };
  const std::array<NeighborArea, 5U> area{*parse_configured_area("49.0001"), *parse_configured_area("49.0002"),
      *parse_configured_area("49.0003"), *parse_configured_area("49.0004"), *parse_configured_area("49.0005")};
  const std::array<CircuitIdentity, 4U> identities{{
      {{0U, 1U}, 1U, 7U, 0U, 0U}, {{0U, 1U}, 2U, 7U, 1U, 0U},
      {{1U, 1U}, 1U, 7U, 0U, 0U}, {{2U, 1U}, 1U, 7U, 0U, 0U}}};
  const std::array<std::size_t, 3U> first{0U, 2U, 3U}, counts{2U, 1U, 1U};
  std::array<packet::isis::LspId, 3U> roots{};
  for (std::size_t index{}; index < first.size(); ++index) {
    const auto identity = identities[first[index]];
    ControlCommand add; add.kind = ControlCommandKind::register_device; add.identity = identity;
    require(command(add).error == ControlError::none);
    InstanceIntent intent; intent.admin_enabled = true;
    intent.levels = index == 1U ? ConfiguredLevels::level1 : ConfiguredLevels::both;
    intent.system_id = packet::isis::SystemId{1U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(index + 1U)};
    std::copy(intent.system_id->begin(), intent.system_id->end(), roots[index].begin());
    intent.areas = index == 0U ? std::vector<NeighborArea>{area[1U], area[2U], area[3U]} :
        index == 1U ? std::vector<NeighborArea>{area[0U], area[1U], area[2U]} : std::vector<NeighborArea>{area[4U]};
    for (auto &level : intent.level) { level.present = true; level.wide_metrics_only = true; }
    std::vector<InstanceOriginInterface> interfaces;
    for (std::size_t port{}; port < counts[index]; ++port) {
      InterfaceIntent edge;
      edge.name = port ? "right" : "edge";
      edge.type = ConfiguredInterfaceType::point_to_point;
      edge.levels = index == 2U || port ? ConfiguredLevels::level2 : ConfiguredLevels::level1;
      intent.interfaces.push_back(edge);
      interfaces.push_back({port ? "right" : "edge", identities[first[index] + port].interface_id,
          {}, static_cast<std::uint8_t>(port + 1U), 0U, false});
    }
    const UpdateLevelConfiguration level{{16U, 32768U}, 16U, 128U, 1492U,
        1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
    InstanceProgramContext context;
    context.maximum_areas = 3U; context.maximum_circuits = counts[index];
    context.levels = {level, level}; context.fragments = {2U, 2U};
    context.transmission = {1U, 1U, 5U, 100ms, 10U, 1492U, 1U};
    context.minimum_generation_interval = 10ms; context.resource_retry = 100ms;
    context.random = index + 1U; context.interfaces = interfaces;
    context.hierarchy_decision = P2pDecisionProgram{8U, 32U, 64U, {}, {}};
    intent.spf_wait = {10U, 10U, 10U};
    auto prepared = prepare_instance_program(intent, context);
    require(prepared.status == InstanceProgramStatus::prepared && prepared.program->origination->automatic_area_set);
    add = {}; add.kind = ControlCommandKind::add_update_instance; add.identity = identity; add.update = std::move(prepared.program);
    require(command(std::move(add)).error == ControlError::none);
    for (std::size_t port{}; port < counts[index]; ++port) {
      add = {}; add.kind = ControlCommandKind::add_p2p_circuit; add.identity = identities[first[index] + port];
      const auto usage = index == 2U || port ? Levels::level2 : Levels::level1;
      auto &hello = add.configuration;
      hello.local = {*intent.system_id, static_cast<std::uint32_t>(port + 1U), static_cast<std::uint8_t>(port + 1U), usage, true};
      hello.mac = {2U, 0U, 0U, 0U, static_cast<std::uint8_t>(index + 1U), static_cast<std::uint8_t>(port + 1U)};
      hello.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
      hello.areas = intent.areas; hello.protocols = {packet::isis::ipv4_nlpid};
      hello.maximum_area_addresses = 3U; hello.holding_seconds = 3U; hello.hello_interval = 1s;
      hello.maximum_pdu_octets = 1492U; hello.peer_attribute_octets = 512U; add.random_state = index + port + 1U;
      require(command(std::move(add)).error == ControlError::none);
    }
  }
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const auto link = [&](std::size_t index, bool carrier) {
    return fabric->configure({static_cast<std::uint16_t>(index), 1U},
        {lab::node(identities[index].device), static_cast<std::uint16_t>(index), 1U},
        {lab::node(identities[index + 2U].device), 0U, 1U}, 1'000'000'000U, 100ns, carrier);
  };
  require(link(0U, true) && link(1U, true));
  std::array<NeighborArea, 3U> expected{area[0U], area[1U], area[2U]};
  const std::array<NeighborArea, 3U> manual{area[1U], area[2U], area[3U]};
  bool wire_area{}, manual_hello{}, manual_lsp{};
  std::uint32_t sequence_floor{}, latest_sequence{};
  struct Delivery { ControlChannels &channels; ControlWorker &worker; const decltype(identities) &identities; std::uint64_t discarded{}; } delivery{*channels, *worker, identities};
  const auto pump = [&] {
    while (const auto frame = channels->egress[0U].try_receive()) {
      packet::isis::EthernetDecodeError error{};
      const auto decoded = packet::isis::parse_ethernet_pdu(frame->frame->view(), error);
      require(decoded.has_value());
      if (frame->metadata.device.index == 0U) {
        if (decoded->pdu.type == packet::isis::PduType::point_to_point_hello)
          manual_hello = manual_hello || area_set_options_match(decoded->pdu.tlvs, manual);
        if (const auto header = packet::isis::lsp(decoded->pdu); header && header->id == roots[0U] && header->remaining_seconds) {
          require(packet::isis::valid_lsp_checksum(decoded->pdu));
          if (decoded->pdu.type == packet::isis::PduType::lsp_l1)
            manual_lsp = manual_lsp || area_set_options_match(decoded->pdu.tlvs, manual);
          if (decoded->pdu.type == packet::isis::PduType::lsp_l2) {
            latest_sequence = std::max(latest_sequence, header->sequence);
            wire_area = wire_area || (header->sequence > sequence_floor && area_set_options_match(decoded->pdu.tlvs, expected));
          }
        }
      }
      const auto cable = frame->metadata.device.index == 2U ||
          (frame->metadata.device.index == 0U && frame->metadata.physical_port_ordinal == 1U) ? 1U : 0U;
      const auto direction = static_cast<std::uint8_t>(frame->metadata.device.index ? 1U : 0U);
      const bool accepted = fabric->enqueue({static_cast<std::uint16_t>(cable), 1U}, direction, *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, frame->metadata, accepted)); worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&delivery, +[](void *opaque, const lab::MultiDeviceFabric::Delivery &frame) {
      auto &state = *static_cast<Delivery *>(opaque);
      const auto found = std::find_if(state.identities.begin(), state.identities.end(), [&](const auto &identity) {
        return identity.device.index == frame.destination.node.index && identity.physical_port_ordinal == frame.destination.ordinal;
      });
      require(found != state.identities.end());
      // Transport overflow is explicit Ethernet loss, recovered by protocol
      // Hellos and synchronization rather than direct peer-state delivery.
      if (!state.channels.ingress[0U].try_send({found->device, found->interface_id,
          found->physical_port_ordinal, found->configuration_generation}, frame.frame)) ++state.discarded;
      state.worker.notify();
    });
  };
  const auto query = [&] {
    ControlCommand request; request.kind = ControlCommandKind::query_update_instance; request.identity = identities[0U];
    return command(request);
  };
  const auto converge = [&](std::uint32_t occurrences) {
    const auto until = RuntimeClock::now() + 8s;
    for (;;) {
      pump(); const auto state = query();
      require(state.error == ControlError::none && state.update_status == UpdateStatus::applied);
      if (state.areas && state.areas->count == expected.size() &&
          std::ranges::equal(std::span{state.areas->effective}.first(state.areas->count), expected) &&
          state.areas->manual_addresses_dropped == occurrences && wire_area) {
        require(state.areas->last_drop && state.areas->last_drop->area == area[3U]); break;
      }
      require(RuntimeClock::now() < until); std::this_thread::yield();
    }
  };
  converge(1U);
  require(manual_hello && manual_lsp);
  // Reinstatement changes the L2 composite without a Cleared occurrence.
  sequence_floor = latest_sequence; wire_area = false; expected = manual;
  require(link(0U, false));
  for (const auto ordinal : {0U, 2U}) {
    ControlCommand down; down.kind = ControlCommandKind::set_circuit_carrier; down.identity = identities[ordinal]; down.carrier = false;
    require(command(down).error == ControlError::none);
  }
  converge(1U);
  // Reconnecting the L1 peer drops the same address a second time.
  sequence_floor = latest_sequence; wire_area = false; expected = {area[0U], area[1U], area[2U]};
  require(link(0U, true));
  for (const auto ordinal : {0U, 2U}) {
    ControlCommand up; up.kind = ControlCommandKind::set_circuit_carrier; up.identity = identities[ordinal]; up.carrier = true;
    require(command(up).error == ControlError::none);
  }
  converge(2U);
  const auto settled_until = RuntimeClock::now() + 4s;
  for (;;) {
    pump();
    ControlCommand begin; begin.kind = ControlCommandKind::begin_checkpoint_barrier;
    const auto barrier = command(begin); require(barrier.error == ControlError::none);
    ControlWorkerCheckpoint image;
    ControlCommand capture; capture.kind = ControlCommandKind::capture_checkpoint;
    capture.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
    capture.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
    capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&image);
    require(command(capture).error == ControlError::none);
    const auto &saved = image.devices[0U].instances[0U];
    bool settled = true;
    for (std::size_t level{}; level < 2U; ++level)
      settled = settled && !saved.local_roots_dirty[level] && saved.decision_status[level] == DecisionStatus::applied &&
          saved.consumed_decision_revision[level] == saved.decision_revisions[level];
    if (settled) {
      require(saved.areas && saved.areas->manual_addresses_dropped == 2U && saved.last_area_drop);
      ControlCommand restore; restore.kind = ControlCommandKind::prepare_checkpoint_restore;
      restore.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
      restore.checkpoint_source_epoch = image.barrier_epoch;
      restore.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
      restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&image);
      require(command(restore).error == ControlError::none);
      auto abort = restore; abort.kind = ControlCommandKind::abort_checkpoint_restore;
      require(command(abort).error == ControlError::none);
      const auto refuses = [&](auto corrupt) {
        auto changed = image;
        corrupt(changed.devices[0U].instances[0U]);
        auto request = restore; request.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&changed);
        require(command(request).error == ControlError::invalid_argument);
      };
      refuses([](auto &owner) { owner.areas.reset(); });
      refuses([](auto &owner) { owner.last_area_drop.reset(); });
      refuses([](auto &owner) { owner.areas->rejected.back() = 0U; });
      refuses([&](auto &owner) { owner.last_area_drop->area = area[4U]; });
      refuses([&](auto &owner) {
        owner.areas->effective.assign(manual.begin(), manual.end());
        std::fill(owner.areas->rejected.begin(), owner.areas->rejected.end(), 0U);
        std::array<std::uint8_t, 257U> bytes{};
        const auto size = encode_area_set_options(manual, bytes); require(size.has_value());
        for (auto &entry : owner.local->entries)
          if (entry.content.level == 1U && !entry.content.id[6U] && !entry.content.id[7U]) {
            packet::isis::TlvCursor options(entry.content.options);
            while (const auto option = options.next()) if (option->code == 1U) {
              require(option->value.size() + 2U == *size);
              const auto offset = static_cast<std::size_t>(option->value.data() - entry.content.options.data()) - 2U;
              std::copy_n(bytes.begin(), *size, entry.content.options.begin() + offset);
            }
          }
      });
    }
    ControlCommand end; end.kind = ControlCommandKind::end_checkpoint_barrier;
    end.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
    require(command(end).error == ControlError::none);
    if (settled) break;
    require(RuntimeClock::now() < settled_until); std::this_thread::yield();
  }
}
