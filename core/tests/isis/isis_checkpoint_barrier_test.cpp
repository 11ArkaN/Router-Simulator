// The real protocol pthread stops timers and both packet directions at a
// command-result barrier. The test owns the other channel endpoints, inspects
// only after acknowledgement and never reads the worker's mutable registry.

#include "router/isis_control_worker.hpp"
#include "router/isis_control_checkpoint.hpp"
#include "router/isis_runtime_checkpoint.hpp"
#include "router/isis_checkpoint_codec.hpp"
#include "router/isis_lsp_builder.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_checkpoint_barrier_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS checkpoint barrier invariant at " + std::to_string(where.line()));
  };
  const auto configuration = [](std::uint8_t id) {
    P2pCircuitConfiguration value;
    value.local = {{1U, 2U, 3U, 4U, 5U, id}, id, id, Levels::both, true};
    value.mac = {2U, 0U, 0U, 0U, 0U, id};
    value.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
    NeighborArea area;
    area.length = 3U; area.bytes[0U] = 0x49U; area.bytes[2U] = 1U;
    value.areas.push_back(area);
    value.protocols = {packet::isis::ipv4_nlpid};
    value.ipv4_addresses.push_back({192U, 0U, 2U, id});
    value.maximum_area_addresses = 3U;
    value.holding_seconds = 3U;
    value.hello_interval = 20ms;
    value.maximum_pdu_octets = 1492U;
    value.peer_attribute_octets = 512U;
    return value;
  };
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 2U);
  std::uint64_t next_id{};
  const auto command = [&](ControlCommand value) {
    value.id = ++next_id;
    const auto until = RuntimeClock::now() + 3s;
    while (!worker->submit(std::move(value))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == next_id && result.thread_identity);
    return result;
  };
  ControlCommand begin;
  begin.kind = ControlCommandKind::begin_checkpoint_barrier;
  const auto empty_barrier = command(begin);
  require(empty_barrier.error == ControlError::none && empty_barrier.checkpoint_barrier_epoch);
  require(command(begin).error == ControlError::checkpoint_barrier_pending);
  const CircuitIdentity identity{{0U, 1U}, 1U, 7U, 0U, 0U};
  ControlCommand registration;
  registration.kind = ControlCommandKind::register_device;
  registration.identity = identity;
  require(command(registration).error == ControlError::checkpoint_barrier_pending);
  ControlCommand end;
  end.kind = ControlCommandKind::end_checkpoint_barrier;
  end.checkpoint_barrier_epoch = empty_barrier.checkpoint_barrier_epoch + 1U;
  require(command(end).error == ControlError::stale_checkpoint_barrier);
  end.checkpoint_barrier_epoch = empty_barrier.checkpoint_barrier_epoch;
  require(command(end).error == ControlError::none && command(end).error == ControlError::stale_checkpoint_barrier);
  require(command(registration).error == ControlError::none);
  ControlCommand add;
  add.kind = ControlCommandKind::add_p2p_circuit;
  add.identity = identity;
  add.configuration = configuration(1U);
  add.random_state = 11U;
  require(command(add).error == ControlError::none);
  auto scratch = std::make_unique<PduScratch>();
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 8U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  UpdateInstanceProgram program;
  program.local = configuration(1U).local.system;
  program.maximum_areas = 3U;
  program.levels = {level, level};
  program.maximum_circuits = 2U;
  program.spf_delay = SpfDelayPolicy{10s, 1s, 1s};
  program.transmission = {1U, 1U, 10U, 10ms, 4U, 1492U, 1U};
  ControlCommand add_instance;
  add_instance.kind = ControlCommandKind::add_update_instance;
  add_instance.identity = identity;
  add_instance.update = program;
  require(command(add_instance).error == ControlError::none);
  LspContents content;
  content.header = {packet::isis::PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U}, 1200U, 1U, 3U};
  const std::array<std::uint8_t, 9U> root_options{1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 1U, packet::isis::ipv4_nlpid};
  content.options = root_options;
  content.maximum_pdu_octets = 1492U;
  const auto built = build_lsp_pdu(content, scratch->options, scratch->pdu);
  require(built.status == LspBuildStatus::encoded);
  ControlCommand originate;
  originate.kind = ControlCommandKind::originate_lsp;
  originate.identity = identity;
  originate.local_lsp.assign(built.bytes.begin(), built.bytes.end());
  require(command(originate).error == ControlError::none);
  ControlWorkerCheckpoint captured;
  captured.version = 9U;
  ControlCommand capture;
  capture.kind = ControlCommandKind::capture_checkpoint;
  capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&captured);
  require(command(capture).error == ControlError::stale_checkpoint_barrier && captured.version == 9U);
  const auto until = RuntimeClock::now() + 3s;
  while (!channels->egress[0U].consumer_pending()) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
  const auto outgoing = channels->egress[0U].try_receive();
  require(outgoing.has_value());
  const auto barrier = command(begin);
  require(barrier.error == ControlError::none && barrier.checkpoint_barrier_epoch > empty_barrier.checkpoint_barrier_epoch);
  require(channels->egress[0U].release(outgoing->handle, outgoing->metadata, true));
  PointToPointCircuit peer(configuration(2U), 19U, RuntimeClock::now());
  auto incoming = std::make_unique<packet::Frame>();
  require(peer.hello(*incoming, {}, *scratch, RuntimeClock::now()) == HelloBuildResult::encoded);
  require(channels->ingress[0U].try_send({identity.device, identity.interface_id, 0U, 7U}, *incoming));
  worker->notify();
  const auto ingress = channels->ingress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch);
  const auto egress = channels->egress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch);
  require(ingress.ready.size() == 1U && egress.returned.size() == 1U);
  capture.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds = -1;
  require(command(capture).error == ControlError::invalid_argument && captured.version == 9U);
  // Use the owner's acknowledged sample, independently of the caller clock.
  // Negative and future explicit anchors still fail the strict owner checks.
  capture.checkpoint_now_nanoseconds = RuntimeClock::time_point::max().time_since_epoch().count();
  require(command(capture).error == ControlError::invalid_argument && captured.version == 9U);
  capture.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
  require(command(capture).error == ControlError::none && captured.version == 3U &&
      captured.barrier_epoch == barrier.checkpoint_barrier_epoch && captured.active_circuits == 1U &&
      captured.devices.size() == 1U && captured.devices[0U].circuits.size() == 1U &&
      captured.devices[0U].instances.size() == 1U);
  const auto &instance_image = captured.devices[0U].instances[0U];
  require(instance_image.spf[0U] && instance_image.spf[1U] && !instance_image.spf[0U]->pending_nanoseconds);
  require(instance_image.process && instance_image.process->levels[0U] && instance_image.process->levels[1U] &&
      instance_image.process->levels[0U]->database.database.records.size() == 1U &&
      instance_image.process->levels[0U]->database.database.records[0U].bytes == originate.local_lsp);
  const auto &circuit_image = captured.devices[0U].circuits[0U];
  require(circuit_image.update_slot == 0U && circuit_image.egress && circuit_image.transmission.pending &&
      std::get<P2pCircuitCheckpoint>(circuit_image.medium).hello.pending);
  lab::IsisRuntimeCheckpoint joined;
  joined.control = captured;
  joined.ingress.push_back(ingress);
  joined.egress.push_back(egress);
  joined.routes = channels->routes->checkpoint_quiescent(captured.barrier_epoch);
  joined.ports.push_back({identity, {lab::node(identity.device), identity.physical_port_ordinal, 1U}});
  require(lab::valid_isis_runtime_links(joined));
  std::array<std::uint8_t, 32U> checkpoint_key{}, checkpoint_binding{};
  checkpoint_key.fill(0x53U); checkpoint_binding.fill(0x87U);
  auto checkpoint_vault = vault::SecretVault::create(checkpoint_key, std::array<std::uint8_t, 3U>{'l', 'a', 'b'}, 1U);
  require(checkpoint_vault.has_value());
  const auto encoded_initial = lab::isis_checkpoint::encode(joined, *checkpoint_vault, checkpoint_binding);
  require(encoded_initial.has_value());
  auto decoded_initial = lab::isis_checkpoint::decode(*encoded_initial, *checkpoint_vault, checkpoint_binding);
  require(decoded_initial && decoded_initial->control.devices[0U].instances[0U].process->levels[0U]->database.database.records[0U].bytes == originate.local_lsp);
  const auto transport_refuses = [&](auto corrupt) {
    auto malformed = joined;
    corrupt(malformed);
    require(!lab::valid_isis_runtime_links(malformed));
  };
  transport_refuses([](auto &value) { ++value.egress[0U].barrier_epoch; });
  transport_refuses([](auto &value) { ++value.egress[0U].occupied[0U].metadata.transmission_id; });
  transport_refuses([](auto &value) { value.egress[0U].occupied[0U].bytes[0U] = 0U;
    value.egress[0U].occupied[0U].bytes[14U] = 0U; });
  transport_refuses([](auto &value) { value.egress[0U].occupied[0U].bytes[0U] ^= 1U; });
  transport_refuses([](auto &value) { value.egress[0U].occupied[0U].bytes[6U] ^= 1U; });
  transport_refuses([](auto &value) { value.ports[0U].port.generation = 0U; });
  transport_refuses([](auto &value) { value.ports.clear(); });
  auto invalid_capture = capture;
  invalid_capture.checkpoint_transfer = 0U;
  require(command(invalid_capture).error == ControlError::invalid_argument && captured.active_circuits == 1U);
  invalid_capture = capture;
  ++invalid_capture.checkpoint_barrier_epoch;
  require(command(invalid_capture).error == ControlError::stale_checkpoint_barrier && captured.devices.size() == 1U);

  ControlCommand restore;
  restore.kind = ControlCommandKind::prepare_checkpoint_restore;
  restore.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  restore.checkpoint_source_epoch = captured.barrier_epoch;
  restore.checkpoint_now_nanoseconds = capture.checkpoint_now_nanoseconds;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&captured);
  auto invalid_image = captured;
  invalid_image.devices[0U].circuits[0U].transmission.pending = 0U;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&invalid_image);
  require(command(restore).error == ControlError::invalid_argument);
  // A refused candidate must preserve the live pending Hello and exact LSDB.
  ControlWorkerCheckpoint after_refusal;
  auto inspect = capture;
  inspect.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&after_refusal);
  require(command(inspect).error == ControlError::none &&
      after_refusal.devices[0U].circuits[0U].transmission.pending == circuit_image.transmission.pending &&
      after_refusal.devices[0U].instances[0U].process->levels[0U]->database.database.records[0U].bytes == originate.local_lsp);
  const auto refuses = [&](auto corrupt) {
    auto malformed = captured;
    corrupt(malformed);
    auto request = restore;
    request.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&malformed);
    require(command(request).error == ControlError::invalid_argument);
  };
  refuses([](auto &image) { ++image.version; });
  refuses([](auto &image) { image.devices[0U].instances[0U].spf[0U].reset(); });
  refuses([](auto &image) { image.devices[0U].instances[0U].spf[0U]->next_hold = 3s; });
  refuses([](auto &image) { ++image.barrier_epoch; });
  refuses([](auto &image) { ++image.forwarding_shards; });
  refuses([](auto &image) { ++image.active_circuits; });
  refuses([](auto &image) { image.devices.push_back(image.devices[0U]); });
  refuses([](auto &image) { image.devices[0U].instance_order[0U] = 1U; });
  refuses([](auto &image) { image.devices[0U].circuits[0U].update_slot = 99U; });
  refuses([](auto &image) { image.devices[0U].circuits[0U].egress.reset(); });
  refuses([](auto &image) { image.devices[0U].circuits[0U].egress->random = 0U; });
  refuses([](auto &image) { image.devices[0U].circuits[0U].egress->credits = 99U; });
  refuses([](auto &image) { image.devices[0U].circuits[0U].egress->pacing.kind = static_cast<checkpoint_time::DeadlineKind>(99U); });
  refuses([](auto &image) { image.devices[0U].instances[0U].process->configuration.local[0U] ^= 1U; });
  refuses([](auto &image) { image.devices[0U].instances[0U].decision_status[0U] = static_cast<DecisionStatus>(99U); });
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&decoded_initial->control);
  require(command(restore).error == ControlError::none);
  require(command(restore).error == ControlError::generation_pending);
  end.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  require(command(end).error == ControlError::generation_pending);
  require(command(inspect).error == ControlError::generation_pending);
  ControlCommand commit_restore = restore;
  commit_restore.kind = ControlCommandKind::commit_checkpoint_restore;
  ++commit_restore.checkpoint_source_epoch;
  require(command(commit_restore).error == ControlError::stale_checkpoint_barrier);
  commit_restore.checkpoint_source_epoch = restore.checkpoint_source_epoch;
  require(command(commit_restore).error == ControlError::none);
  require(command(commit_restore).error == ControlError::stale_checkpoint_barrier);
  require(command(inspect).error == ControlError::none && after_refusal.devices[0U].circuits[0U].egress &&
      after_refusal.devices[0U].circuits[0U].transmission.pending == circuit_image.transmission.pending &&
      after_refusal.devices[0U].instances[0U].process->levels[0U]->database.database.records[0U].bytes == originate.local_lsp);
  // Preparation owns all copies. Aborting discards them without replacing the
  // registry, and does not release the enclosing transport barrier.
  require(command(restore).error == ControlError::none);
  ControlCommand abort_restore = restore;
  abort_restore.kind = ControlCommandKind::abort_checkpoint_restore;
  require(command(abort_restore).error == ControlError::none && command(inspect).error == ControlError::none);

  std::this_thread::sleep_for(60ms); // Three Hello periods must remain unserviced inside the barrier.
  ControlCommand query;
  query.kind = ControlCommandKind::query_worker;
  const auto paused = command(query);
  require(paused.error == ControlError::none && paused.checkpoint_barrier_epoch == barrier.checkpoint_barrier_epoch);
  const auto ingress_after = channels->ingress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch);
  const auto egress_after = channels->egress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch);
  require(ingress_after.ready == ingress.ready && egress_after.ready == egress.ready &&
      egress_after.returned.size() == egress.returned.size() &&
      egress_after.occupied[0U].bytes == egress.occupied[0U].bytes);
  ControlCommand circuit_query;
  circuit_query.kind = ControlCommandKind::query_circuit;
  circuit_query.identity = identity;
  require(command(circuit_query).error == ControlError::checkpoint_barrier_pending);
  end.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  require(command(end).error == ControlError::none);
  ControlResult live;
  do { live = command(circuit_query); require(RuntimeClock::now() < until); }
  while (!live.counters.received || !live.counters.hello_enqueued);
  require(live.error == ControlError::none && live.adjacency.present && live.counters.hello_enqueued >= 1U);
  ControlCommand prepare;
  prepare.kind = ControlCommandKind::prepare_generation;
  prepare.identity = identity;
  prepare.circuits.push_back({identity, configuration(1U), 11U});
  require(command(prepare).error == ControlError::none && command(begin).error == ControlError::generation_pending);
  ControlCommand abort;
  abort.kind = ControlCommandKind::abort_generation;
  abort.identity = identity;
  require(command(abort).error == ControlError::none);
  begin.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  require(command(begin).error == ControlError::invalid_argument);
  begin.checkpoint_barrier_epoch = 0U;
  const auto final_barrier = command(begin);
  require(final_barrier.error == ControlError::none && final_barrier.checkpoint_barrier_epoch == barrier.checkpoint_barrier_epoch + 1U);
  end.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  require(command(end).error == ControlError::stale_checkpoint_barrier);
  end.checkpoint_barrier_epoch = final_barrier.checkpoint_barrier_epoch;
  require(command(end).error == ControlError::none);
  ControlCommand remove;
  remove.kind = ControlCommandKind::remove_circuit;
  remove.identity = identity;
  require(command(remove).error == ControlError::none);
  ControlCommand add_lan;
  add_lan.kind = ControlCommandKind::add_lan_circuit;
  add_lan.identity = identity;
  add_lan.identity.configuration_generation = 8U;
  add_lan.random_state = 23U;
  add_lan.broadcast.emplace();
  const auto common = configuration(1U);
  const std::array groups{packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U},
      packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}};
  for (std::size_t level_index{}; level_index < 2U; ++level_index) {
    LanCircuitConfiguration entry;
    static_cast<CircuitHelloConfiguration &>(entry) = common;
    entry.local = {common.local.system, common.mac, 64U, 2U};
    entry.levels = Levels::both;
    entry.type = level_index ? packet::isis::PduType::lan_hello_l2 : packet::isis::PduType::lan_hello_l1;
    entry.hello_destination = groups[level_index];
    entry.update_destinations = groups;
    entry.designated_hello_interval = 10ms;
    entry.designated_holding_seconds = 3U;
    entry.limits = {4U, 3U};
    add_lan.broadcast->levels[level_index] = std::move(entry);
  }
  add_lan.update_transmission = program.transmission;
  add_lan.update_transmission->broadcast = BroadcastTransmissionProgram{10ms, 10ms};
  require(command(add_lan).error == ControlError::none);
  const auto lan_barrier = command(begin);
  require(lan_barrier.error == ControlError::none);
  capture.checkpoint_barrier_epoch = lan_barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds = lan_barrier.checkpoint_anchor_nanoseconds;
  require(command(capture).error == ControlError::none && captured.devices[0U].circuits.size() == 1U &&
      std::holds_alternative<LanPairCheckpoint>(captured.devices[0U].circuits[0U].medium));
  restore.checkpoint_barrier_epoch = lan_barrier.checkpoint_barrier_epoch;
  restore.checkpoint_source_epoch = captured.barrier_epoch;
  restore.checkpoint_now_nanoseconds = capture.checkpoint_now_nanoseconds;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&captured);
  require(command(restore).error == ControlError::none);
  commit_restore = restore;
  commit_restore.kind = ControlCommandKind::commit_checkpoint_restore;
  require(command(commit_restore).error == ControlError::none);
  inspect = capture;
  inspect.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&after_refusal);
  require(command(inspect).error == ControlError::none &&
      after_refusal.devices[0U].circuits[0U].definition.identity.configuration_generation == 8U &&
      after_refusal.devices[0U].circuits[0U].egress->broadcast_scan.has_value());
  joined.control = after_refusal;
  joined.ingress[0U] = channels->ingress[0U].checkpoint_quiescent(captured.barrier_epoch);
  joined.egress[0U] = channels->egress[0U].checkpoint_quiescent(captured.barrier_epoch);
  joined.routes = channels->routes->checkpoint_quiescent(captured.barrier_epoch);
  joined.ports[0U].identity = add_lan.identity;
  require(lab::valid_isis_runtime_links(joined)); // Old canceled P2P wire remains legal deferred work.
  const auto encoded_lan = lab::isis_checkpoint::encode(joined, *checkpoint_vault, checkpoint_binding);
  require(encoded_lan.has_value());
  auto decoded_lan = lab::isis_checkpoint::decode(*encoded_lan, *checkpoint_vault, checkpoint_binding);
  require(decoded_lan != nullptr);
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&decoded_lan->control);
  require(command(restore).error == ControlError::none);
  commit_restore = restore;
  commit_restore.kind = ControlCommandKind::commit_checkpoint_restore;
  require(command(commit_restore).error == ControlError::none);
  worker->stop(); // Shutdown must join even while protocol service is quiescent.
  require(!worker->thread_id() && !worker->submit(ControlCommand{}));
}
