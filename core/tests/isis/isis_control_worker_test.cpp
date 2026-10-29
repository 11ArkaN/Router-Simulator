// The actual IS-IS pthread exchanges encoded Hellos through SPSC channels and
// the physical fabric. The test thread owns forwarding and link state only.
// Generation rejection and removal are observed through immutable results.

#include "router/isis_control_worker.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/network_plane.hpp"

#include <memory>
#include <algorithm>
#include <stdexcept>
#include <source_location>
#include <string>

namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS control worker transport invariant failed at " + std::to_string(location.line()));
}
P2pCircuitConfiguration configuration(std::uint8_t id) {
  P2pCircuitConfiguration result;
  result.local = {{1U, 2U, 3U, 4U, 5U, id}, id, id, Levels::both, true};
  result.mac = {2U, 0U, 0U, 0U, 0U, id};
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area;
  area.bytes[0U] = 0x49U;
  area.bytes[2U] = 1U;
  area.length = 3U;
  result.areas.push_back(area);
  result.protocols.push_back(packet::isis::ipv4_nlpid);
  result.ipv4_addresses.push_back({192U, 0U, 2U, id});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = 3U;
  result.hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.peer_attribute_octets = 512U;
  return result;
}
struct DeliveryContext {
  ControlChannels &channels;
  ControlWorker &worker;
  packet::Frame last;
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &value) {
  auto &context = *static_cast<DeliveryContext *>(opaque);
  const auto index = value.destination.node.index;
  require(context.channels.ingress[0U].try_send(
      {{index, 1U}, index + 1U, 0U, 7U}, value.frame));
  packet::copy_frame(context.last, value.frame);
  context.worker.notify();
}
}

void isis_control_worker_tests() {
  auto channels = std::make_unique<ControlChannels>();
  struct Wakeups { std::atomic_uint64_t count{}; std::atomic_bool invalid{}; } wakeups;
  channels->egress_context = &wakeups;
  channels->egress_wakeup = +[](void *opaque, std::size_t shard) {
    auto &state = *static_cast<Wakeups *>(opaque);
    if (shard != 0U) state.invalid.store(true, std::memory_order_relaxed);
    state.count.fetch_add(1U, std::memory_order_release);
  };
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 2U);
  std::uint64_t next_id{};
  const auto command = [&](ControlCommand value) {
    value.id = ++next_id;
    const auto deadline = PointToPointCircuit::Clock::now() + 3s;
    while (!worker->submit(std::move(value))) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    ControlResult result;
    while (!worker->read(result)) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    require(result.id == next_id && result.thread_identity != 0U);
    return result;
  };
  std::array<CircuitIdentity, 2U> identities{{
      {{0U, 1U}, 1U, 7U, 0U, 0U}, {{1U, 1U}, 2U, 7U, 0U, 0U}}};
  for (std::uint8_t index{}; index < 2U; ++index) {
    ControlCommand registration;
    registration.kind = ControlCommandKind::register_device;
    registration.identity = identities[index];
    require(command(std::move(registration)).error == ControlError::none);
    ControlCommand add;
    add.kind = ControlCommandKind::add_p2p_circuit;
    add.identity = identities[index];
    add.configuration = configuration(static_cast<std::uint8_t>(index + 1U));
    add.random_state = index + 11U;
    require(command(std::move(add)).error == ControlError::none);
  }
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle cable{0U, 1U};
  require(fabric->configure(cable, {lab::node(identities[0U].device), 0U, 1U},
      {lab::node(identities[1U].device), 0U, 1U}, 1'000'000'000U, 100ns, true));
  DeliveryContext context{*channels, *worker, {}};
  const auto query = [&](std::size_t index) {
    ControlCommand value;
    value.kind = ControlCommandKind::query_circuit;
    value.identity = identities[index];
    return command(std::move(value));
  };
  const auto deadline = PointToPointCircuit::Clock::now() + 4s;
  for (;;) {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const auto index = frame->metadata.device.index;
      require(frame->metadata.transmission_class == static_cast<std::uint8_t>(packet::isis::PduType::point_to_point_hello));
      const bool accepted = fabric->enqueue(cable, static_cast<std::uint8_t>(index),
          *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, accepted) && accepted);
      worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&context, delivered);
    if (query(0U).adjacency.iso_up && query(1U).adjacency.iso_up) break;
    require(PointToPointCircuit::Clock::now() < deadline);
    std::this_thread::yield();
  }
  const auto before = query(0U);
  require(before.counters.adjacency_up == 1U && before.counters.hello_enqueued >= 2U);
  require(wakeups.count.load(std::memory_order_acquire) >= 4U && !wakeups.invalid.load(std::memory_order_relaxed));
  // Build a valid peer Hello with an old epoch. It must never reach the FSM.
  PointToPointCircuit peer(configuration(2U), 777U, PointToPointCircuit::Clock::now());
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame stale;
  require(peer.hello(stale, std::nullopt, *scratch,
      PointToPointCircuit::Clock::now()) == HelloBuildResult::encoded);
  require(channels->ingress[0U].try_send({identities[0U].device, 1U, 0U, 6U}, stale));
  worker->notify();
  ControlResult after;
  do {
    after = query(0U);
    require(PointToPointCircuit::Clock::now() < deadline);
  } while (!after.counters.stale_ingress);
  require(after.holding_deadline_nanoseconds == before.holding_deadline_nanoseconds &&
      after.counters.received == before.counters.received);
  ControlCommand remove;
  remove.kind = ControlCommandKind::remove_circuit;
  remove.identity = identities[0U];
  remove.identity.configuration_generation = 6U;
  require(command(std::move(remove)).error == ControlError::stale_configuration);
  std::optional<protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>::Borrowed> delayed;
  const auto receipt_deadline = PointToPointCircuit::Clock::now() + 4s;
  while (!delayed) {
    if (const auto frame = channels->egress[0U].try_receive()) {
      if (frame->metadata.device == identities[0U].device) delayed = frame;
      else {
        require(channels->egress[0U].release(frame->handle, true));
        worker->notify();
      }
    }
    require(PointToPointCircuit::Clock::now() < receipt_deadline);
    std::this_thread::yield();
  }
  remove = {};
  remove.kind = ControlCommandKind::remove_circuit;
  remove.identity = identities[0U];
  const auto removed = command(std::move(remove));
  require(removed.error == ControlError::none && removed.active_circuits == 1U &&
      query(0U).error == ControlError::not_found);
  ControlCommand reused;
  reused.kind = ControlCommandKind::add_p2p_circuit;
  reused.identity = identities[0U];
  reused.configuration = configuration(1U);
  reused.random_state = 444U;
  require(command(std::move(reused)).error == ControlError::stale_configuration);
  identities[0U].configuration_generation = 8U;
  ControlCommand replacement;
  replacement.kind = ControlCommandKind::add_p2p_circuit;
  replacement.identity = identities[0U];
  replacement.configuration = configuration(1U);
  replacement.random_state = 444U;
  require(command(std::move(replacement)).error == ControlError::none);
  require(channels->egress[0U].release(delayed->handle, true));
  worker->notify();
  for (;;) {
    const auto current = query(0U);
    if (current.counters.stale_completion) {
      require(current.counters.hello_enqueued == 0U && current.hello_pending);
      break;
    }
    require(PointToPointCircuit::Clock::now() < receipt_deadline);
  }
  remove = {};
  remove.kind = ControlCommandKind::remove_circuit;
  remove.identity = identities[0U];
  require(command(std::move(remove)).error == ControlError::none);
  const auto backpressure_deadline = PointToPointCircuit::Clock::now() + 4s;
  for (;;) {
    while (const auto frame = channels->egress[0U].try_receive()) {
      require(channels->egress[0U].release(frame->handle, true));
      worker->notify();
    }
    if (!query(1U).hello_pending) break;
    require(PointToPointCircuit::Clock::now() < backpressure_deadline);
  }
  // Saturate the result ring without reading it. One result remains pending;
  // packet work must continue while later control commands apply backpressure.
  for (std::size_t index{}; index < device_catalog::network_result_ring_entries + 2U; ++index) {
    ControlCommand value;
    value.id = ++next_id;
    while (!worker->submit(std::move(value))) {
      require(PointToPointCircuit::Clock::now() < backpressure_deadline);
      std::this_thread::yield();
    }
  }
  for (;;) {
    const auto frame = channels->egress[0U].try_receive();
    if (frame) {
      require(frame->metadata.device == identities[1U].device &&
          channels->egress[0U].release(frame->handle, false));
      worker->notify();
      break;
    }
    require(PointToPointCircuit::Clock::now() < backpressure_deadline);
    std::this_thread::yield();
  }
}

void isis_control_generation_tests() {
  auto channels = std::make_unique<ControlChannels>();
  ControlWorker worker(*channels, 1U, 3U);
  std::uint64_t id{};
  const auto command = [&](ControlCommand value) {
    value.id = ++id;
    const auto deadline = PointToPointCircuit::Clock::now() + 3s;
    while (!worker.submit(std::move(value))) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    ControlResult result;
    while (!worker.read(result)) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    require(result.id == id);
    return result;
  };
  const CircuitIdentity first{{0U, 1U}, 1U, 7U, 0U, 0U};
  const CircuitIdentity second{{0U, 1U}, 2U, 3U, 1U, 0U};
  const auto operation = [&](ControlCommandKind kind, CircuitIdentity identity) {
    ControlCommand value;
    value.kind = kind;
    value.identity = identity;
    return command(std::move(value));
  };
  require(operation(ControlCommandKind::register_device, first).error == ControlError::none);
  ControlCommand add;
  add.kind = ControlCommandKind::add_p2p_circuit;
  add.identity = first;
  add.configuration = configuration(1U);
  add.random_state = 11U;
  require(command(std::move(add)).error == ControlError::none);
  const auto query = [&](CircuitIdentity identity) { return operation(ControlCommandKind::query_circuit, identity); };
  const auto prepare = [&](std::vector<CircuitDefinition> definitions) {
    ControlCommand value;
    value.kind = ControlCommandKind::prepare_generation;
    value.identity = first;
    value.circuits = std::move(definitions);
    return command(std::move(value));
  };
  const CircuitDefinition retained{first, configuration(1U), 123U};
  const CircuitDefinition added{second, configuration(2U), 456U};
  auto invalid = added;
  invalid.configuration.maximum_area_addresses = 0U;
  require(prepare({retained, invalid}).error == ControlError::construction_failed &&
      query(first).error == ControlError::none && query(second).error == ControlError::not_found);
  require(operation(ControlCommandKind::commit_generation, first).error == ControlError::not_found);
  require(prepare({retained, added}).error == ControlError::none &&
      query(first).active_circuits == 1U && query(second).error == ControlError::not_found);
  require(operation(ControlCommandKind::remove_circuit, first).error == ControlError::generation_pending);
  auto other_device = first;
  other_device.device.index = 1U;
  require(operation(ControlCommandKind::commit_generation, other_device).error == ControlError::stale_device);
  require(operation(ControlCommandKind::abort_generation, first).error == ControlError::none &&
      query(first).active_circuits == 1U);
  require(prepare({added, retained}).error == ControlError::invalid_argument);
  auto alias = retained;
  alias.identity.instance = 1U;
  require(prepare({retained, alias}).error == ControlError::already_exists);
  auto changed = retained;
  changed.configuration.hello_interval = 2s;
  require(prepare({changed}).error == ControlError::stale_configuration && query(first).active_circuits == 1U);
  require(prepare({retained, added}).error == ControlError::none);
  const auto before = query(first);
  require(before.hello_pending && operation(ControlCommandKind::commit_generation, first).active_circuits == 2U);
  const auto after = query(first);
  require(after.error == ControlError::none && after.hello_pending &&
      after.counters.hello_enqueued == before.counters.hello_enqueued && query(second).error == ControlError::none);
  auto proposed = retained;
  proposed.identity.configuration_generation = 8U;
  require(prepare({proposed, added}).error == ControlError::none &&
      operation(ControlCommandKind::abort_generation, first).error == ControlError::none);
  auto third = added;
  third.identity.interface_id = 3U;
  third.identity.physical_port_ordinal = 2U;
  third.identity.configuration_generation = 1U;
  third.configuration = configuration(3U);
  require(prepare({retained, added, third}).error == ControlError::none &&
      operation(ControlCommandKind::abort_generation, first).error == ControlError::none);
  using Egress = protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>;
  std::optional<Egress::Borrowed> delayed;
  // Keep a real borrowed slot through replacement. It remains the old epoch's
  // immutable output even after the live circuit is atomically replaced.
  const auto borrow_deadline = PointToPointCircuit::Clock::now() + 3s;
  while (!delayed) {
    delayed = channels->egress[0U].try_receive();
    require(PointToPointCircuit::Clock::now() < borrow_deadline);
    if (!delayed) std::this_thread::yield();
  }
  require(delayed->metadata.interface_id == first.interface_id && delayed->metadata.configuration_generation == 7U);
  changed = retained;
  changed.identity.configuration_generation = 8U;
  changed.configuration.hello_interval = 2s;
  require(prepare({changed, added}).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, first).error == ControlError::none);
  require(query(first).error == ControlError::stale_configuration && query(second).error == ControlError::none);
  require(channels->egress[0U].release(delayed->handle, delayed->metadata, true));
  worker.notify();
  const auto receipt_deadline = PointToPointCircuit::Clock::now() + 3s;
  for (;;) {
    const auto current = query(changed.identity);
    require(current.error == ControlError::none && current.counters.hello_enqueued == 0U);
    if (current.counters.stale_completion) break;
    require(PointToPointCircuit::Clock::now() < receipt_deadline);
  }
  require(prepare({}).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, first).active_circuits == 0U &&
      query(changed.identity).error == ControlError::not_found && query(second).error == ControlError::not_found);
  require(prepare({changed}).error == ControlError::stale_configuration);
  third.identity.configuration_generation = 9U;
  require(prepare({third}).error == ControlError::none &&
      operation(ControlCommandKind::abort_generation, first).error == ControlError::none &&
      prepare({third}).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, first).error == ControlError::none);
  require(operation(ControlCommandKind::remove_device, first).error == ControlError::none &&
      operation(ControlCommandKind::register_device, first).error == ControlError::none &&
      prepare({third}).error == ControlError::stale_configuration);
  third.identity.configuration_generation = 10U;
  require(prepare({third}).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, first).error == ControlError::none &&
      prepare({}).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, first).error == ControlError::none &&
      operation(ControlCommandKind::remove_device, first).error == ControlError::none &&
      operation(ControlCommandKind::register_device, first).error == ControlError::none &&
      prepare({third}).error == ControlError::stale_configuration);
  require(operation(ControlCommandKind::remove_device, first).error == ControlError::none);
  auto fresh = retained;
  fresh.identity.device.generation = 2U;
  require(operation(ControlCommandKind::register_device, fresh.identity).error == ControlError::none);
  ControlCommand fresh_generation;
  fresh_generation.kind = ControlCommandKind::prepare_generation;
  fresh_generation.identity = fresh.identity;
  fresh_generation.circuits.push_back(fresh);
  require(command(std::move(fresh_generation)).error == ControlError::none &&
      operation(ControlCommandKind::commit_generation, fresh.identity).error == ControlError::none &&
      query(fresh.identity).error == ControlError::none && query(first).error == ControlError::stale_device);
}

void isis_network_plane_tests() {
  for (const auto logical_cpus : {4U, 8U}) {
    auto plane = std::make_unique<lab::NetworkPlane>(logical_cpus);
    const std::array devices{lab::DeviceHandle{0U, 1U}, lab::DeviceHandle{1U, 1U}};
    std::array<lab::IsisP2pCircuitProgram, 2U> programs;
    for (std::uint8_t index{}; index < devices.size(); ++index) {
      crypto::Sha256Digest secret{};
      secret.fill(static_cast<std::uint8_t>(index + 1U));
      require(plane->add_router(devices[index], secret));
      auto &program = programs[index];
      program.circuit = {{devices[index], 1U, 7U, 0U, 0U}, configuration(static_cast<std::uint8_t>(index + 1U)), index + 11U};
      program.port = {lab::node(devices[index]), 0U, 1U};
      lab::ForwardPort port;
      port.configured = port.operational = true;
      port.ordinal = 0U;
      port.mtu = 1514U;
      port.speed_mbps = 1000U;
      port.mac = program.circuit.configuration.mac;
      port.ipv4_configured = false;
      require(plane->configure_port(devices[index], port));
    }
    lab::NetworkLinkProgram cable{{0U, 1U}, programs[0U].port, programs[1U].port, 1'000'000'000U, 100ns, false};
    require(plane->configure_link(cable));
    auto initial = plane->checkpoint();
    require(initial.has_value());
    lab::CapturePointProgram capture;
    capture.id = 55U;
    capture.kind = lab::CapturePointKind::router_egress;
    capture.node = lab::node(devices[0U]);
    capture.port_ordinal = 0U;
    capture.selected = true;
    constexpr std::string_view capture_name{"isis-wire"};
    capture.name_size = static_cast<std::uint16_t>(capture_name.size());
    std::copy(capture_name.begin(), capture_name.end(), capture.name.begin());
    require(plane->configure_capture_point(capture));
    const auto publish = [&](std::size_t index) {
      return plane->replace_isis_p2p_generation(devices[index], std::span{&programs[index], 1U});
    };
    const auto query = [&](std::size_t index) {
      const auto value = plane->query_isis_circuit(programs[index].circuit.identity);
      require(value && value->error == ControlError::none);
      return *value;
    };
    auto rejected_first = programs[0U];
    rejected_first.port.ordinal = rejected_first.circuit.identity.physical_port_ordinal = 1U;
    require(!plane->replace_isis_p2p_generation(devices[0U], std::span{&rejected_first, 1U}) &&
        !plane->query_isis_circuit(programs[0U].circuit.identity) && plane->checkpoint());
    require(publish(0U) && publish(1U));
    const auto refusal_deadline = lab::NetworkPlane::Clock::now() + 3s;
    for (;;) {
      plane->pump(lab::NetworkPlane::Clock::now());
      const auto state = query(0U);
      require(state.counters.hello_enqueued == 0U);
      if (state.counters.hello_refused && plane->captured_frames()) break;
      require(lab::NetworkPlane::Clock::now() < refusal_deadline);
      std::this_thread::yield();
    }
    require(!plane->checkpoint() && !plane->restore(*initial) && !plane->remove_port(devices[0U], 0U));
    cable.carrier = true;
    require(plane->configure_link(cable));
    const auto converge = [&] {
      const auto deadline = lab::NetworkPlane::Clock::now() + 6s;
      for (;;) {
        const auto first_state = query(0U);
        const auto second_state = query(1U);
        if (first_state.adjacency.iso_up && second_state.adjacency.iso_up &&
            first_state.counters.hello_enqueued >= 2U && second_state.counters.hello_enqueued >= 2U) break;
        plane->pump(lab::NetworkPlane::Clock::now());
        require(lab::NetworkPlane::Clock::now() < deadline);
        std::this_thread::yield();
      }
    };
    converge();
    const auto retained = query(0U);
    require(publish(0U) && query(0U).adjacency.iso_up && query(0U).counters.adjacency_up == retained.counters.adjacency_up);
    auto invalid = programs[0U];
    invalid.port.ordinal = invalid.circuit.identity.physical_port_ordinal = 1U;
    invalid.circuit.identity.configuration_generation = 8U;
    require(!plane->replace_isis_p2p_generation(devices[0U], std::span{&invalid, 1U}) && query(0U).adjacency.iso_up);
    // Hardware generation changes while old protocol output may be queued.
    // The link owner must refuse it even though node, ordinal and MAC still match.
    require(plane->remove_link(cable.link));
    cable.link.generation = 2U;
    cable.first.generation = cable.second.generation = 2U;
    require(plane->configure_link(cable));
    const auto before_replacement = query(0U);
    const auto stale_deadline = lab::NetworkPlane::Clock::now() + 3s;
    for (;;) {
      plane->pump(lab::NetworkPlane::Clock::now());
      const auto current = query(0U);
      if (current.counters.hello_refused > before_replacement.counters.hello_refused) break;
      require(lab::NetworkPlane::Clock::now() < stale_deadline);
      std::this_thread::yield();
    }
    // A previously admitted frame may return its legitimate receipt after the
    // link replacement. Once refusal of an old physical generation is observed,
    // its subsequent retry must not gain an enqueue success on the new hardware.
    const auto refused = query(0U);
    const auto retry_deadline = lab::NetworkPlane::Clock::now() + 3s;
    while (query(0U).counters.hello_refused == refused.counters.hello_refused) {
      plane->pump(lab::NetworkPlane::Clock::now());
      require(query(0U).counters.hello_enqueued == refused.counters.hello_enqueued &&
          lab::NetworkPlane::Clock::now() < retry_deadline);
      std::this_thread::yield();
    }
    for (std::size_t index{}; index < programs.size(); ++index) {
      programs[index].port.generation = 2U;
      require(!publish(index));
      programs[index].circuit.identity.configuration_generation = 8U;
      require(publish(index));
    }
    converge();
    require(plane->replace_isis_p2p_generation(devices[0U], {}) && !plane->query_isis_circuit(programs[0U].circuit.identity));
    require(!publish(0U) && !plane->query_isis_circuit(programs[0U].circuit.identity));
    programs[0U].circuit.identity.configuration_generation = 9U;
    require(publish(0U) && plane->replace_isis_p2p_generation(devices[0U], {}));
    require(plane->remove_router(devices[1U]) && plane->checkpoint() && plane->restore(*initial));
  }
}

void isis_network_plane_instance_tests() {
  auto plane = std::make_unique<lab::NetworkPlane>(8U);
  std::array<std::array<lab::IsisP2pCircuitProgram, 2U>, 2U> programs;
  for (std::uint16_t device_index{}; device_index < programs.size(); ++device_index) {
    const lab::DeviceHandle device{device_index, 1U};
    crypto::Sha256Digest secret{};
    secret.fill(static_cast<std::uint8_t>(device_index + 1U));
    require(plane->add_router(device, secret));
    for (std::uint8_t instance{}; instance < 2U; ++instance) {
      auto &program = programs[device_index][instance];
      auto effective = configuration(static_cast<std::uint8_t>(device_index + 1U));
      effective.instance_format = packet::isis::InstanceFormat::standard;
      effective.emit_instance = true;
      effective.wire_instance = static_cast<std::uint16_t>(instance + 1U);
      effective.instance_topologies = {0U};
      // RFC 8202 uses AllL1MI-ISs for nonzero-IID P2P-over-LAN Hellos.
      effective.hello_destination = {1U, 0U, 0x5eU, 0x90U, 0U, 2U};
      program.circuit = {{device, 1U, 7U, 0U, static_cast<std::uint8_t>(instance + 1U)},
          std::move(effective), device_index * 2U + instance + 11U};
      program.port = {lab::node(device), 0U, 1U};
    }
    lab::ForwardPort port;
    port.configured = port.operational = true;
    port.ordinal = 0U;
    port.mtu = 1514U;
    port.speed_mbps = 1000U;
    port.mac = programs[device_index][0U].circuit.configuration.mac;
    port.ipv4_configured = false;
    require(plane->configure_port(device, port));
  }
  require(plane->configure_link({{0U, 1U}, programs[0U][0U].port, programs[1U][0U].port,
      1'000'000'000U, 100ns, true}));
  const auto publish = [&](std::size_t index, bool first_instance) {
    const auto values = std::span{programs[index]};
    return plane->replace_isis_p2p_generation(programs[index][0U].circuit.identity.device,
        first_instance ? values : values.subspan(1U));
  };
  const auto query = [&](std::size_t device, std::size_t instance) {
    const auto value = plane->query_isis_circuit(programs[device][instance].circuit.identity);
    require(value.has_value());
    return *value;
  };
  const auto converge = [&] {
    const auto deadline = lab::NetworkPlane::Clock::now() + 6s;
    for (;;) {
      bool ready = true;
      for (std::size_t device{}; device < 2U; ++device)
        for (std::size_t instance{}; instance < 2U; ++instance) {
          const auto value = query(device, instance);
          ready = ready && value.error == ControlError::none && value.adjacency.iso_up;
        }
      if (ready) break;
      plane->pump(lab::NetworkPlane::Clock::now());
      require(lab::NetworkPlane::Clock::now() < deadline);
      std::this_thread::yield();
    }
  };
  require(publish(0U, true) && publish(1U, true));
  converge();
  require(publish(1U, false) && query(1U, 0U).error == ControlError::not_found);
  const auto deadline = lab::NetworkPlane::Clock::now() + 5s;
  while (query(0U, 0U).adjacency.iso_up) {
    plane->pump(lab::NetworkPlane::Clock::now());
    require(lab::NetworkPlane::Clock::now() < deadline);
    std::this_thread::yield();
  }
  require(query(0U, 1U).adjacency.iso_up && query(1U, 1U).adjacency.iso_up &&
      query(0U, 1U).counters.adjacency_up == 1U && query(1U, 1U).counters.adjacency_up == 1U);
  programs[1U][0U].circuit.identity.configuration_generation = 8U;
  require(publish(1U, true));
  converge();
  require(query(0U, 0U).counters.adjacency_up == 2U && query(1U, 0U).counters.adjacency_up == 1U &&
      query(0U, 1U).counters.adjacency_up == 1U && query(1U, 1U).counters.adjacency_up == 1U);
}

void isis_network_plane_scale_tests() {
  for (const auto logical_cpus : {4U, 16U}) {
    auto plane = std::make_unique<lab::NetworkPlane>(logical_cpus);
    std::array<std::array<lab::IsisP2pCircuitProgram, 2U>, 16U> programs;
    std::array<lab::NetworkLinkProgram, 16U> cables;
    for (std::uint16_t index{}; index < programs.size(); ++index) {
      const lab::DeviceHandle device{index, 1U};
      crypto::Sha256Digest secret{};
      secret.fill(static_cast<std::uint8_t>(index + 1U));
      require(plane->add_router(device, secret));
      for (std::uint16_t ordinal{}; ordinal < 2U; ++ordinal) {
        auto &program = programs[index][ordinal];
        auto effective = configuration(static_cast<std::uint8_t>(index + 1U));
        effective.local.extended_circuit = ordinal + 1U;
        effective.local.local_circuit = static_cast<std::uint8_t>(ordinal + 1U);
        effective.mac = {2U, 0U, 0U, static_cast<std::uint8_t>(index), static_cast<std::uint8_t>(ordinal), 1U};
        program.circuit = {{device, ordinal + 1U, 7U, ordinal, 0U}, std::move(effective), index * 2U + ordinal + 11U};
        program.port = {lab::node(device), ordinal, 1U};
        lab::ForwardPort port;
        port.configured = port.operational = true;
        port.ordinal = ordinal;
        port.mtu = 1514U;
        port.speed_mbps = 1000U;
        port.mac = program.circuit.configuration.mac;
        port.ipv4_configured = false;
        require(plane->configure_port(device, port));
      }
    }
    for (std::uint16_t index{}; index < cables.size(); ++index) {
      cables[index] = {{index, 1U}, programs[index][1U].port, programs[(index + 1U) % programs.size()][0U].port,
          1'000'000'000U, 100ns, true};
      require(plane->configure_link(cables[index]));
    }
    for (std::size_t index{}; index < programs.size(); ++index)
      require(plane->replace_isis_p2p_generation(programs[index][0U].circuit.identity.device, programs[index]));
    const auto query = [&](std::size_t device, std::size_t ordinal) {
      const auto value = plane->query_isis_circuit(programs[device][ordinal].circuit.identity);
      require(value && value->error == ControlError::none);
      return *value;
    };
    const auto converge = [&] {
      const auto deadline = lab::NetworkPlane::Clock::now() + 8s;
      for (;;) {
        bool ready = true;
        for (std::size_t index{}; index < programs.size(); ++index)
          for (std::size_t ordinal{}; ordinal < 2U; ++ordinal) {
            const auto state = query(index, ordinal);
            ready = ready && state.adjacency.iso_up && state.counters.hello_enqueued >= 2U;
          }
        if (ready) break;
        plane->pump(lab::NetworkPlane::Clock::now());
        require(lab::NetworkPlane::Clock::now() < deadline);
        std::this_thread::yield();
      }
    };
    converge();
    cables[0U].carrier = false;
    require(plane->configure_link(cables[0U]));
    const auto down_deadline = lab::NetworkPlane::Clock::now() + 5s;
    while (query(0U, 1U).adjacency.iso_up || query(1U, 0U).adjacency.iso_up) {
      plane->pump(lab::NetworkPlane::Clock::now());
      require(lab::NetworkPlane::Clock::now() < down_deadline);
      std::this_thread::yield();
    }
    for (std::size_t index{}; index < programs.size(); ++index)
      for (std::size_t ordinal{}; ordinal < 2U; ++ordinal)
        if (!((index == 0U && ordinal == 1U) || (index == 1U && ordinal == 0U))) {
          const auto state = query(index, ordinal);
          require(state.adjacency.iso_up && state.counters.adjacency_up == 1U);
        }
    cables[0U].carrier = true;
    require(plane->configure_link(cables[0U]));
    converge();
    require(query(0U, 1U).counters.adjacency_up == 2U && query(1U, 0U).counters.adjacency_up == 2U);
    for (const auto &router : programs)
      require(plane->replace_isis_p2p_generation(router[0U].circuit.identity.device, {}));
    require(plane->checkpoint().has_value());
  }
}

void isis_control_worker_scale_tests() {
  // Thirty-two circuits deliberately exceed one ring's frame credits. Real
  // exhausted frame credits and possible ingress loss recover through Hellos.
  auto channels = std::make_unique<ControlChannels>();
  static_assert(sizeof(ControlChannels) <= 1024U * 1024U,
      "IS-IS channels exceed their share of the fixed network reserve");
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 32U);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  std::uint64_t next_id{};
  const auto deadline = PointToPointCircuit::Clock::now() + 8s;
  const auto command = [&](ControlCommand value) {
    value.id = ++next_id;
    while (!worker->submit(std::move(value))) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    ControlResult result;
    while (!worker->read(result)) {
      require(PointToPointCircuit::Clock::now() < deadline);
      std::this_thread::yield();
    }
    require(result.id == next_id && result.error == ControlError::none);
    return result;
  };
  for (std::uint16_t router{}; router < 16U; ++router) {
    ControlCommand registration;
    registration.kind = ControlCommandKind::register_device;
    registration.identity.device = {router, 1U};
    static_cast<void>(command(std::move(registration)));
    for (std::uint16_t port{}; port < 2U; ++port) {
      ControlCommand add;
      add.kind = ControlCommandKind::add_p2p_circuit;
      add.identity = {{router, 1U}, port + 1U, 7U, port, 0U};
      add.configuration = configuration(static_cast<std::uint8_t>(router + 1U));
      add.configuration.local.extended_circuit = port + 1U;
      add.configuration.local.local_circuit = static_cast<std::uint8_t>(port + 1U);
      add.random_state = router * 2U + port + 1U;
      static_cast<void>(command(std::move(add)));
    }
  }
  for (std::uint16_t port{}; port < 2U; ++port)
    for (std::uint16_t pair{}; pair < 8U; ++pair)
      require(fabric->configure({static_cast<std::uint16_t>(port * 8U + pair), 1U},
          {lab::node(lab::DeviceHandle{static_cast<std::uint16_t>(pair * 2U), 1U}), port, 1U},
          {lab::node(lab::DeviceHandle{static_cast<std::uint16_t>(pair * 2U + 1U), 1U}), port, 1U},
          1'000'000'000U, 100ns, true));
  const auto query = [&](std::uint16_t router, std::uint16_t port) {
    ControlCommand value;
    value.kind = ControlCommandKind::query_circuit;
    value.identity = {{router, 1U}, port + 1U, 7U, port, 0U};
    return command(std::move(value));
  };
  using Borrowed = protocol::PacketChannel<device_catalog::isis_packet_ring_frames, true>::Borrowed;
  std::array<Borrowed, device_catalog::isis_packet_ring_frames> held;
  std::size_t held_count{};
  while (held_count < held.size()) {
    if (const auto frame = channels->egress[0U].try_receive()) held[held_count++] = *frame;
    require(PointToPointCircuit::Clock::now() < deadline);
    std::this_thread::yield();
  }
  require(!channels->egress[0U].try_receive());
  std::size_t pending{};
  for (std::uint16_t router{}; router < 16U; ++router)
    for (std::uint16_t port{}; port < 2U; ++port)
      pending += query(router, port).hello_pending;
  require(pending == held.size());
  struct Context { ControlChannels &channels; ControlWorker &worker; } context{*channels, *worker};
  const auto deliver = [](void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
    auto &state = *static_cast<Context *>(opaque);
    const auto port = delivery.destination.ordinal;
    static_cast<void>(state.channels.ingress[0U].try_send(
        {{delivery.destination.node.index, 1U}, port + 1U, port, 7U}, delivery.frame));
    state.worker.notify();
  };
  for (const auto &frame : held) {
    const auto router = frame.metadata.device.index;
    const auto port = frame.metadata.physical_port_ordinal;
    const lab::LinkHandle link{static_cast<std::uint16_t>(port * 8U + router / 2U), 1U};
    const bool accepted = fabric->enqueue(link, static_cast<std::uint8_t>(router % 2U),
        *frame.frame) == lab::MultiDeviceFabric::DropReason::none;
    require(channels->egress[0U].release(frame.handle, accepted));
    worker->notify();
  }
  for (;;) {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const auto router = frame->metadata.device.index;
      const auto port = frame->metadata.physical_port_ordinal;
      const lab::LinkHandle link{static_cast<std::uint16_t>(port * 8U + router / 2U), 1U};
      const bool accepted = fabric->enqueue(link, static_cast<std::uint8_t>(router % 2U),
          *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, accepted));
      worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&context, deliver);
    bool all_up{true};
    for (std::uint16_t router{}; router < 16U; ++router)
      for (std::uint16_t port{}; port < 2U; ++port)
        all_up = query(router, port).adjacency.iso_up && all_up;
    if (all_up) break;
    require(PointToPointCircuit::Clock::now() < deadline);
    std::this_thread::yield();
  }
}
