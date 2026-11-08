// The actual IS-IS pthread exchanges encoded Hellos through SPSC channels and
// the physical fabric. The test thread owns forwarding and link state only.
// Generation rejection and removal are observed through immutable results.

#include "router/isis_control_worker.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/isis_root_content.hpp"
#include "router/isis_rib_input.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/network_plane.hpp"

#include <memory>
#include <limits>
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
// Direct heap construction gives the large optional return its final storage
// before capture. Long-lived test frames then retain only an owning pointer.
std::unique_ptr<lab::RouterForwarderCheckpoint> heap_router_checkpoint(lab::NetworkPlane &plane,
    lab::DeviceHandle device, RuntimeClock::time_point now) {
  using Image = std::optional<lab::RouterForwarderCheckpoint>;
  auto image = std::unique_ptr<Image>{new Image(plane.router_checkpoint(device, now))};
  return *image ? std::make_unique<lab::RouterForwarderCheckpoint>(std::move(**image)) : nullptr;
}
struct DeliveryContext {
  ControlChannels &channels;
  ControlWorker &worker;
  packet::Frame last;
  std::array<std::uint64_t, 2U> epochs{7U, 7U};
  std::array<std::array<bool, 2U>, 2U> neighbor_roots{};
};
void delivered(void *opaque, const lab::MultiDeviceFabric::Delivery &value) {
  auto &context = *static_cast<DeliveryContext *>(opaque);
  const auto index = value.destination.node.index;
  require(context.channels.ingress[0U].try_send(
      {{index, 1U}, index + 1U, 0U, context.epochs[index]}, value.frame));
  packet::isis::EthernetDecodeError error;
  const auto decoded = packet::isis::parse_ethernet_pdu(value.frame.view(), error);
  const auto header = decoded ? packet::isis::lsp(decoded->pdu) : std::nullopt;
  if (header && header->remaining_seconds && !header->id[6U] && !header->id[7U] &&
      header->id[5U] >= 1U && header->id[5U] <= 2U) {
    const auto sender = static_cast<std::size_t>(header->id[5U] - 1U);
    const packet::isis::LanId expected{1U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(2U - sender), 0U};
    bool narrow{}, wide{};
    packet::isis::TlvCursor options(decoded->pdu.tlvs);
    while (const auto option = options.next()) {
      if (option->code == 2U) {
        packet::isis::NarrowNeighborCursor links(*option);
        while (const auto entry = links.next())
          narrow = narrow || (entry->id == expected && entry->metrics.metric == 10U);
      } else if (option->code == 22U) {
        packet::isis::ExtendedNeighborCursor links(*option);
        while (const auto entry = links.next())
          wide = wide || (entry->id == expected && entry->metric == 10U);
      }
    }
    const auto level = decoded->pdu.type == packet::isis::PduType::lsp_l2 ? 1U : 0U;
    context.neighbor_roots[sender][level] = context.neighbor_roots[sender][level] || (narrow && wide && options.valid());
  }
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
  ControlCommand next_hop_query;
  next_hop_query.kind = ControlCommandKind::query_circuit;
  next_hop_query.identity = identities[0U];
  next_hop_query.level = 1U;
  next_hop_query.selected_next_hop = *ip::parse_ip_address("192.0.2.2");
  const auto binding = command(next_hop_query);
  require(binding.error == ControlError::none && binding.bound_next_hop &&
      binding.bound_next_hop->interface.interface_id == 1U &&
      binding.bound_next_hop->interface.configuration_generation == 7U &&
      binding.bound_next_hop->interface.physical_port_ordinal == 0U &&
      binding.bound_next_hop->address == *next_hop_query.selected_next_hop &&
      binding.bound_next_hop->peer == configuration(2U).local.system);
  next_hop_query.selected_next_hop = *ip::parse_ip_address("192.0.2.1");
  require(command(next_hop_query).error == ControlError::not_found);
  next_hop_query.identity.configuration_generation = 6U;
  require(command(next_hop_query).error == ControlError::stale_configuration);
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
    auto refused_image = plane->checkpoint();
    require(refused_image && refused_image->isis && !plane->remove_port(devices[0U], 0U));
    require(plane->restore(*refused_image));
    require(query(0U).counters.hello_refused >= 1U);
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
    const auto connected_image = plane->checkpoint();
    require(connected_image && connected_image->isis && plane->restore(*connected_image));
    require(query(0U).adjacency.iso_up && query(1U).adjacency.iso_up);
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

void isis_control_update_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 4U);
  std::uint64_t next_id{};
  const auto command = [&](ControlCommand value) {
    value.id = ++next_id;
    const auto deadline = RuntimeClock::now() + 4s;
    while (!worker->submit(std::move(value))) {
      require(RuntimeClock::now() < deadline);
      std::this_thread::yield();
    }
    ControlResult result;
    while (!worker->read(result)) {
      require(RuntimeClock::now() < deadline);
      std::this_thread::yield();
    }
    require(result.id == next_id);
    return result;
  };
  std::array<CircuitIdentity, 2U> identities{{
      {{0U, 1U}, 1U, 7U, 0U, 0U}, {{1U, 1U}, 2U, 7U, 0U, 0U}}};
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
      1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
  const auto add_instance = [&](std::size_t index) {
    ControlCommand value;
    value.kind = ControlCommandKind::add_update_instance;
    value.identity = identities[index];
    value.update = UpdateInstanceProgram{configuration(static_cast<std::uint8_t>(index + 1U)).local.system,
        3U, {level, level}, 2U, {1U, 5U, 5U, 1s, 10U, 1492U, 1U}};
    return command(std::move(value));
  };
  const auto query = [&](std::size_t index, bool instance) {
    ControlCommand value;
    value.kind = instance ? ControlCommandKind::query_update_instance : ControlCommandKind::query_circuit;
    value.identity = identities[index];
    return command(std::move(value));
  };
  for (std::uint8_t index{}; index < 2U; ++index) {
    ControlCommand value;
    value.kind = ControlCommandKind::register_device;
    value.identity = identities[index];
    require(command(std::move(value)).error == ControlError::none);
    require(add_instance(index).error == ControlError::none);
    value = {};
    value.kind = ControlCommandKind::add_p2p_circuit;
    value.identity = identities[index];
    value.configuration = configuration(static_cast<std::uint8_t>(index + 1U));
    value.random_state = index + 1U;
    require(command(std::move(value)).error == ControlError::none);
  }
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(identities[0U].device), 0U, 1U},
      {lab::node(identities[1U].device), 0U, 1U}, 1'000'000'000U, 100ns, true));
  DeliveryContext context{*channels, *worker, {}};
  bool refused_lsp{};
  const auto pump = [&] {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const bool lsp = frame->metadata.transmission_class == static_cast<std::uint8_t>(packet::isis::PduType::lsp_l1) ||
          frame->metadata.transmission_class == static_cast<std::uint8_t>(packet::isis::PduType::lsp_l2);
      const bool refuse = lsp && frame->metadata.device.index == 1U && !refused_lsp;
      if (refuse) refused_lsp = true;
      if (frame->metadata.transmission_class != static_cast<std::uint8_t>(packet::isis::PduType::point_to_point_hello))
        require(frame->metadata.protocol_epoch != 0U);
      const bool accepted = !refuse && frame->metadata.physical_port_ordinal == 0U && fabric->enqueue(link, static_cast<std::uint8_t>(frame->metadata.device.index),
          *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, frame->metadata, accepted));
      worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&context, delivered);
  };
  const auto deadline = RuntimeClock::now() + 4s;
  while (!query(0U, false).adjacency.iso_up || !query(1U, false).adjacency.iso_up) {
    pump();
    require(RuntimeClock::now() < deadline);
  }
  require(query(0U, true).update_status == UpdateStatus::applied);
  auto scratch = std::make_unique<PduScratch>();
  LspContents contents;
  contents.header = {packet::isis::PduType::lsp_l1,
      {1U, 2U, 3U, 4U, 5U, 2U, 0U, 0U}, 1200U, 1U, 3U};
  const std::array<std::uint8_t, 9U> semantic{1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 1U, packet::isis::ipv4_nlpid};
  contents.options = semantic;
  contents.maximum_pdu_octets = 1492U;
  for (std::uint8_t selected{}; selected < 2U; ++selected) {
    contents.header.type = selected ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
    const auto built = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded);
    ControlCommand originate;
    originate.kind = ControlCommandKind::originate_lsp;
    originate.identity = identities[1U];
    originate.level = selected;
    originate.local_lsp.assign(built.bytes.begin(), built.bytes.end());
    const auto originated = command(std::move(originate));
    require(originated.error == ControlError::none && originated.origin.install == LspInstallResult::installed);
    while (query(0U, true).retained_lsps[selected] != 1U) {
      pump();
      require(RuntimeClock::now() < deadline);
    }
  }
  while (query(1U, false).flood_requests != std::array<std::size_t, 2U>{} ||
      query(0U, false).snp_requests != std::array<std::size_t, 2U>{}) {
    pump();
    require(RuntimeClock::now() < deadline);
  }
  require(refused_lsp && query(1U, false).counters.lsp_refused >= 1U &&
      query(1U, false).counters.lsp_enqueued >= 2U && query(0U, false).counters.snp_enqueued >= 2U);
  require(query(0U, false).counters.update_received >= 2U &&
      query(0U, false).counters.last_update == UpdateStatus::applied);
  for (const bool wrong_system : {true, false}) {
    ControlCommand invalid;
    invalid.kind = ControlCommandKind::add_p2p_circuit;
    invalid.identity = {identities[0U].device, 3U, 8U, 1U, 0U};
    invalid.configuration = configuration(wrong_system ? 2U : 1U);
    invalid.random_state = 17U;
    require(command(std::move(invalid)).error == (wrong_system ? ControlError::invalid_argument : ControlError::already_exists));
    require(query(0U, true).retained_lsps == std::array<std::size_t, 2U>{1U, 1U});
  }
  CircuitDefinition original{identities[0U], configuration(1U), 1U};
  CircuitDefinition added = original;
  added.identity.interface_id = 3U;
  added.identity.configuration_generation = 8U;
  added.identity.physical_port_ordinal = 1U;
  added.configuration.local.extended_circuit = 2U;
  added.configuration.local.local_circuit = 2U;
  added.configuration.mac[5U] = 3U;
  const auto generation = [&](ControlCommandKind kind, bool second) {
    ControlCommand value;
    value.kind = kind;
    value.identity.device = identities[0U].device;
    if (kind == ControlCommandKind::prepare_generation) {
      value.circuits.push_back(original);
      if (second) value.circuits.push_back(added);
    }
    return command(std::move(value));
  };
  const auto before_generation = query(0U, false);
  require(generation(ControlCommandKind::prepare_generation, true).error == ControlError::none);
  require(query(0U, true).retained_lsps == std::array<std::size_t, 2U>{1U, 1U});
  require(generation(ControlCommandKind::abort_generation, false).error == ControlError::none);
  require(generation(ControlCommandKind::prepare_generation, true).error == ControlError::none);
  require(generation(ControlCommandKind::commit_generation, false).error == ControlError::none);
  require(query(0U, false).adjacency.iso_up &&
      query(0U, false).counters.adjacency_up == before_generation.counters.adjacency_up &&
      query(0U, true).retained_lsps == std::array<std::size_t, 2U>{1U, 1U});
  ControlCommand retire_added;
  retire_added.kind = ControlCommandKind::remove_circuit;
  retire_added.identity = added.identity;
  require(command(std::move(retire_added)).error == ControlError::none);
  original.identity.configuration_generation = 9U;
  original.configuration.holding_seconds = 4U;
  require(generation(ControlCommandKind::prepare_generation, false).error == ControlError::none);
  require(generation(ControlCommandKind::commit_generation, false).error == ControlError::none);
  identities[0U] = original.identity;
  context.epochs[0U] = original.identity.configuration_generation;
  require(query(0U, true).retained_lsps == std::array<std::size_t, 2U>{1U, 1U});
  const auto recovery_deadline = RuntimeClock::now() + 4s;
  while (!query(0U, false).adjacency.iso_up || !query(1U, false).adjacency.iso_up) {
    pump();
    require(RuntimeClock::now() < recovery_deadline);
  }
  ControlCommand remove;
  remove.kind = ControlCommandKind::remove_update_instance;
  remove.identity = identities[0U];
  const auto epoch = query(0U, true).update_epoch;
  require(command(std::move(remove)).error == ControlError::none &&
      query(0U, true).error == ControlError::not_found && !query(0U, false).adjacency.iso_up);
  require(add_instance(0U).error == ControlError::none && query(0U, true).update_epoch > epoch &&
      query(0U, true).retained_lsps == std::array<std::size_t, 2U>{});
}

void isis_control_origination_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 4U);
  std::uint64_t next_id{};
  const CircuitIdentity identity{{0U, 1U}, 1U, 7U, 0U, 0U};
  const auto command = [&](ControlCommand request) {
    request.id = ++next_id;
    const auto until = RuntimeClock::now() + 4s;
    while (!worker->submit(std::move(request))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == next_id);
    return result;
  };
  ControlCommand request;
  request.kind = ControlCommandKind::register_device;
  request.identity = identity;
  require(command(std::move(request)).error == ControlError::none);
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
      1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
  UpdateInstanceProgram program{configuration(1U).local.system, 3U, {level, level}, 2U,
      {1U, 5U, 5U, 1s, 10U, 1492U, 1U}};
  program.origination.emplace();
  program.origination->resource_retry = 100ms;
  program.decision = P2pDecisionProgram{8U, 32U, 64U, packet::isis::ipv4_nlpid, PrefixCollectionBudget{8U, 64U}};
  program.origination->neighbors = std::vector<P2pOriginInterface>{{1U, {P2pOriginMetric{10U, 10U}, P2pOriginMetric{10U, 10U}}}};
  auto &local = program.origination->content;
  local.random = 17U;
  local.levels = {LocalLspLevelProgram{1200U, 1492U, 10ms, 1s}, LocalLspLevelProgram{1200U, 1492U, 10ms, 1s}};
  const packet::isis::LspId root{1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U};
  std::vector<std::uint8_t> options{1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 2U,
      packet::isis::ipv4_nlpid, packet::isis::ipv6_nlpid};
  const auto test_prefix = *ip::parse_ip_prefix("198.51.100.0/24");
  std::array<std::uint8_t, 32U> prefix_bytes{};
  packet::isis::TlvWriter prefix_writer(prefix_bytes);
  require(packet::isis::encode_extended_prefix(prefix_writer, {test_prefix, 5U, false, false, false, {}}));
  options.insert(options.end(), prefix_writer.bytes().begin(), prefix_writer.bytes().end());
  local.records = {{0U, root, 3U, options}, {1U, root, 3U, options}};
  auto reserved_fragment = root;
  reserved_fragment.back() = 1U;
  local.records.push_back({0U, reserved_fragment, 3U, {8U, 0U}, false});
  const auto refuse_program = [&](UpdateInstanceProgram invalid, ControlError expected) {
    ControlCommand add;
    add.kind = ControlCommandKind::add_update_instance;
    add.identity = identity;
    add.update = std::move(invalid);
    require(command(std::move(add)).error == expected);
  };
  auto invalid = program;
  invalid.decision->protocol.reset();
  refuse_program(std::move(invalid), ControlError::invalid_argument);
  invalid = program;
  invalid.decision->protocol = 0xeeU;
  refuse_program(std::move(invalid), ControlError::invalid_argument);
  invalid = program;
  invalid.origination->neighbors->push_back(invalid.origination->neighbors->front());
  refuse_program(std::move(invalid), ControlError::invalid_argument);
  invalid = program;
  invalid.origination->content.records[0U].options = {22U, 0U};
  refuse_program(std::move(invalid), ControlError::invalid_argument);
  invalid = program;
  invalid.origination->content.levels[0U]->maximum_pdu_octets = 27U + 9U;
  refuse_program(std::move(invalid), ControlError::capacity);
  request = {};
  request.kind = ControlCommandKind::add_update_instance;
  request.identity = identity;
  request.update = program;
  require(command(std::move(request)).error == ControlError::none);
  const auto query = [&] {
    ControlCommand value;
    value.kind = ControlCommandKind::query_update_instance;
    value.identity = identity;
    return command(std::move(value));
  };
  const auto initial = query();
  require(initial.retained_lsps == std::array<std::size_t, 2U>{1U, 1U} &&
      initial.local_root_sequences == std::array<std::uint32_t, 2U>{1U, 1U});
  require(initial.local_root_links[0U] == std::optional{LspLinkCounts{}} &&
      initial.local_root_links[1U] == std::optional{LspLinkCounts{}});
  const auto until = RuntimeClock::now() + 3s;
  for (;;) {
    const auto state = query();
    require(state.update_status == UpdateStatus::applied);
    if (state.local_root_sequences[0U] >= 2U && state.local_root_sequences[1U] >= 2U &&
        state.database_validations[0U] && state.database_validations[1U]) {
      require(state.decision_revisions[0U] == initial.decision_revisions[0U] + state.database_validations[0U] &&
          state.decision_revisions[1U] == initial.decision_revisions[1U] + state.database_validations[1U]);
      break;
    }
    require(RuntimeClock::now() < until);
    std::this_thread::yield();
  }
  const CircuitIdentity peer{{1U, 1U}, 2U, 7U, 0U, 0U};
  request = {};
  request.kind = ControlCommandKind::register_device;
  request.identity = peer;
  require(command(std::move(request)).error == ControlError::none);
  program.local = configuration(2U).local.system;
  program.origination->neighbors->front().interface_id = 2U;
  for (auto &content : program.origination->content.records) content.id[5U] = 2U;
  request = {};
  request.kind = ControlCommandKind::add_update_instance;
  request.identity = peer;
  request.update = program;
  require(command(std::move(request)).error == ControlError::none);
  request = {};
  request.kind = ControlCommandKind::add_p2p_circuit;
  request.identity = identity;
  request.identity.interface_id = 99U;
  request.configuration = configuration(1U);
  request.random_state = 1U;
  require(command(std::move(request)).error == ControlError::invalid_argument);
  request = {};
  request.kind = ControlCommandKind::add_p2p_circuit;
  request.identity = identity;
  request.configuration = configuration(1U);
  request.configuration.topologies = {{2U, false, false}};
  request.random_state = 1U;
  require(command(std::move(request)).error == ControlError::invalid_argument);
  for (std::uint8_t index{}; index < 2U; ++index) {
    request = {};
    request.kind = ControlCommandKind::add_p2p_circuit;
    request.identity = index ? peer : identity;
    request.configuration = configuration(static_cast<std::uint8_t>(index + 1U));
    request.configuration.protocols.push_back(packet::isis::ipv6_nlpid);
    request.configuration.ipv6_addresses.push_back(*ip::parse_ipv6(index ? "fe80::2" : "fe80::1"));
    request.random_state = index + 1U;
    require(command(std::move(request)).error == ControlError::none);
  }
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(identity.device), 0U, 1U}, {lab::node(peer.device), 0U, 1U},
      1'000'000'000U, 100ns, true));
  DeliveryContext context{*channels, *worker, {}};
  const auto synchronized_by = RuntimeClock::now() + 4s;
  bool advertise_peer_ipv4{true};
  auto altered_hello = std::make_unique<packet::Frame>();
  const auto pump = [&] {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const packet::Frame *transmitted = frame->frame;
      if (!advertise_peer_ipv4 && frame->metadata.device.index == 1U) {
        packet::isis::EthernetDecodeError error{};
        const auto decoded = packet::isis::parse_ethernet_pdu(frame->frame->view(), error);
        if (decoded && decoded->pdu.type == packet::isis::PduType::point_to_point_hello) {
          packet::copy_frame(*altered_hello, *frame->frame);
          packet::isis::TlvCursor attributes(decoded->pdu.tlvs);
          while (const auto option = attributes.next()) if (option->code == 129U)
            for (std::size_t protocol{}; protocol < option->value.size(); ++protocol)
              if (option->value[protocol] == packet::isis::ipv4_nlpid) {
                const auto offset = static_cast<std::size_t>(option->value.data() - frame->frame->bytes.data());
                altered_hello->bytes[offset + protocol] = 0xeeU;
              }
          require(attributes.valid());
          transmitted = altered_hello.get();
        }
      }
      const bool accepted = fabric->enqueue(link, static_cast<std::uint8_t>(frame->metadata.device.index),
          *transmitted) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, frame->metadata, accepted));
      worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&context, delivered);
  };
  for (;;) {
    pump();
    request = {};
    request.kind = ControlCommandKind::query_update_instance;
    request.identity = peer;
    const auto remote = command(std::move(request));
    const auto own = query();
    const auto linked = [](const auto &state) {
      return state.local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}} &&
          state.local_root_links[1U] == std::optional{LspLinkCounts{1U, 1U}};
    };
    if (own.retained_lsps == std::array<std::size_t, 2U>{2U, 2U} &&
        remote.retained_lsps == std::array<std::size_t, 2U>{2U, 2U} && linked(own) && linked(remote) &&
        context.neighbor_roots[0U][0U] && context.neighbor_roots[0U][1U] &&
        context.neighbor_roots[1U][0U] && context.neighbor_roots[1U][1U]) break;
    require(RuntimeClock::now() < synchronized_by);
    std::this_thread::yield();
  }
  const auto decision_by = RuntimeClock::now() + 3s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    auto remote_root = root;
    remote_root[5U] = 2U;
    selected.selected_lsp = remote_root;
    selected.selected_prefix = test_prefix;
    const auto state = command(std::move(selected));
    require(state.error == ControlError::none);
    if (state.selected_cost[0U] == 10U && state.selected_cost[1U] == 10U) {
      require(state.decision_runs[0U] && state.decision_runs[1U] &&
          state.prefix_advertisements == std::array<std::size_t, 2U>{2U, 2U} &&
          state.selected_prefix_distance[0U] == PrefixDistance{0U, 15U, 0U} &&
          state.selected_prefix_distance[1U] == PrefixDistance{1U, 15U, 0U});
      break;
    }
    require(RuntimeClock::now() < decision_by);
  }
  // Losing only IPv4 NLPID on a dual-stack wire must not remove ISO Up, but
  // the IPv4 decision can no longer seed this link from the peer's LSP alone.
  const auto family_epoch = query().update_epoch;
  advertise_peer_ipv4 = false;
  const auto family_lost_by = RuntimeClock::now() + 4s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    auto remote_root = root;
    remote_root[5U] = 2U;
    selected.selected_lsp = remote_root;
    selected.selected_prefix = test_prefix;
    const auto state = command(std::move(selected));
    if (state.prefix_advertisements == std::array<std::size_t, 2U>{2U, 2U} &&
        !state.selected_cost[0U] && !state.selected_cost[1U]) {
      require(!state.selected_prefix_distance[0U] && !state.selected_prefix_distance[1U] &&
          state.update_epoch == family_epoch);
      ControlCommand circuit;
      circuit.kind = ControlCommandKind::query_circuit;
      circuit.identity = identity;
      require(command(std::move(circuit)).adjacency.iso_up);
      break;
    }
    require(RuntimeClock::now() < family_lost_by);
  }
  advertise_peer_ipv4 = true;
  const auto family_restored_by = RuntimeClock::now() + 4s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    auto remote_root = root;
    remote_root[5U] = 2U;
    selected.selected_lsp = remote_root;
    selected.selected_prefix = test_prefix;
    const auto state = command(std::move(selected));
    if (state.selected_prefix_distance[0U] == PrefixDistance{0U, 15U, 0U} &&
        state.selected_prefix_distance[1U] == PrefixDistance{1U, 15U, 0U}) {
      require(state.update_epoch == family_epoch);
      break;
    }
    require(RuntimeClock::now() < family_restored_by);
  }
  const auto lost_by = RuntimeClock::now() + 5s;
  for (;;) {
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    auto remote_root = root;
    remote_root[5U] = 2U;
    selected.selected_lsp = remote_root;
    selected.selected_prefix = test_prefix;
    const auto state = command(std::move(selected));
    require(state.error == ControlError::none);
    if (state.local_root_links[0U] == std::optional{LspLinkCounts{}} &&
        state.local_root_links[1U] == std::optional{LspLinkCounts{}} &&
        state.decision_status[0U] == DecisionStatus::applied && state.decision_status[1U] == DecisionStatus::applied &&
        !state.selected_cost[0U] && !state.selected_cost[1U] &&
        !state.selected_prefix_distance[0U] && !state.selected_prefix_distance[1U]) break;
    require(RuntimeClock::now() < lost_by);
    std::this_thread::yield();
  }
  const auto restored_decision_by = RuntimeClock::now() + 5s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    auto remote_root = root;
    remote_root[5U] = 2U;
    selected.selected_lsp = remote_root;
    selected.selected_prefix = test_prefix;
    const auto state = command(std::move(selected));
    require(state.error == ControlError::none);
    if (state.selected_cost[0U] == 10U && state.selected_cost[1U] == 10U) {
      require(state.selected_prefix_distance[0U] == PrefixDistance{0U, 15U, 0U} &&
          state.selected_prefix_distance[1U] == PrefixDistance{1U, 15U, 0U});
      break;
    }
    require(RuntimeClock::now() < restored_decision_by);
  }
  auto scratch = std::make_unique<PduScratch>();
  auto replay = std::make_unique<packet::Frame>();
  // An earlier incarnation can advertise a higher sequence but cannot replace
  // this owner's semantic content. The response must exceed its sequence and
  // traverse the same physical transport as ordinary refresh output.
  LspContents finite_replay;
  finite_replay.header = {packet::isis::PduType::lsp_l1, root, 1200U, 1000U, 7U};
  finite_replay.options = options;
  finite_replay.maximum_pdu_octets = 1492U;
  const auto finite_encoded = build_lsp_pdu(finite_replay, scratch->options, scratch->pdu);
  require(finite_encoded.status == LspBuildStatus::encoded && packet::isis::ethernet_pdu_into(*replay,
      configuration(2U).mac, configuration(1U).hello_destination, finite_encoded.bytes));
  require(fabric->enqueue(link, 1U, *replay) == lab::MultiDeviceFabric::DropReason::none);
  const auto fought_back_by = RuntimeClock::now() + 3s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    selected.level = 0U;
    selected.selected_lsp = root;
    const auto response = command(std::move(selected));
    require(response.error == ControlError::none && response.update_status == UpdateStatus::applied);
    if (response.selected_lsp && response.selected_lsp->sequence > 1000U) {
      require(response.selected_lsp->flags == 3U && response.selected_lsp->remaining_seconds > 0U);
      break;
    }
    require(RuntimeClock::now() < fought_back_by);
    std::this_thread::yield();
  }
  // A local ID outside the current semantic set is purged with its observed
  // sequence, even when this incarnation never retained that fragment.
  auto unknown = root;
  unknown.back() = 1U;
  finite_replay.header.id = unknown;
  finite_replay.header.sequence = 77U;
  const auto unknown_encoded = build_lsp_pdu(finite_replay, scratch->options, scratch->pdu);
  require(unknown_encoded.status == LspBuildStatus::encoded && packet::isis::ethernet_pdu_into(*replay,
      configuration(2U).mac, configuration(1U).hello_destination, unknown_encoded.bytes));
  require(fabric->enqueue(link, 1U, *replay) == lab::MultiDeviceFabric::DropReason::none);
  const auto purged_by = RuntimeClock::now() + 3s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    selected.level = 0U;
    selected.selected_lsp = unknown;
    const auto response = command(std::move(selected));
    require(response.error == ControlError::none || response.error == ControlError::not_found);
    if (response.selected_lsp) {
      require(response.selected_lsp->sequence == 77U && !response.selected_lsp->remaining_seconds);
      break;
    }
    require(RuntimeClock::now() < purged_by);
    std::this_thread::yield();
  }
  request = {};
  request.kind = ControlCommandKind::replace_local_content;
  request.identity = identity;
  request.local_content = LocalLspContent{0U, unknown, 3U, {8U, 0U}};
  require(command(std::move(request)).error == ControlError::none);
  const auto reactivated_by = RuntimeClock::now() + 3s;
  for (;;) {
    pump();
    ControlCommand selected;
    selected.kind = ControlCommandKind::query_update_instance;
    selected.identity = identity;
    selected.selected_lsp = unknown;
    const auto response = command(std::move(selected));
    require(response.error == ControlError::none && response.selected_lsp);
    if (response.selected_lsp->remaining_seconds) {
      require(response.selected_lsp->sequence >= 78U);
      break;
    }
    require(RuntimeClock::now() < reactivated_by);
  }
  LspContents old_incarnation;
  old_incarnation.header = {packet::isis::PduType::lsp_l1, root, 1200U,
      std::numeric_limits<std::uint32_t>::max(), 3U};
  old_incarnation.options = options;
  old_incarnation.maximum_pdu_octets = 1492U;
  const auto encoded = build_lsp_pdu(old_incarnation, scratch->options, scratch->pdu);
  require(encoded.status == LspBuildStatus::encoded && packet::isis::ethernet_pdu_into(*replay,
      configuration(2U).mac, configuration(1U).hello_destination, encoded.bytes));
  require(fabric->enqueue(link, 1U, *replay) == lab::MultiDeviceFabric::DropReason::none);
  const auto stopped_by = RuntimeClock::now() + 3s;
  while (query().update_status != UpdateStatus::sequence_exhausted) {
    pump();
    require(RuntimeClock::now() < stopped_by);
  }
  const auto recovery_query = [&] {
    ControlCommand value;
    value.kind = ControlCommandKind::query_sequence_recovery;
    value.identity = identity;
    return command(std::move(value));
  };
  require(recovery_query().sequence_recovery_pending);
  for (const auto operation : {ControlCommandKind::prepare_generation, ControlCommandKind::commit_generation,
      ControlCommandKind::remove_update_instance}) {
    request = {};
    request.kind = operation;
    request.identity = identity;
    require(command(std::move(request)).error == ControlError::none);
  }
  program.local = configuration(1U).local.system;
  program.origination->neighbors->front().interface_id = 1U;
  for (auto &content : program.origination->content.records) content.id[5U] = 1U;
  request = {};
  request.kind = ControlCommandKind::add_update_instance;
  request.identity = identity;
  request.update = program;
  require(command(std::move(request)).error == ControlError::sequence_cooldown && recovery_query().sequence_recovery_pending);
}

void isis_network_plane_update_tests() {
  for (const auto logical_cpus : {4U, 8U}) {
    auto plane = std::make_unique<lab::NetworkPlane>(logical_cpus);
    const std::array devices{lab::DeviceHandle{0U, 1U}, lab::DeviceHandle{1U, 1U}};
    std::array<lab::IsisP2pCircuitProgram, 2U> circuits;
    const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
        1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
    std::array<UpdateInstanceProgram, 2U> instances;
    for (std::uint8_t index{}; index < devices.size(); ++index) {
      crypto::Sha256Digest secret{};
      secret.fill(static_cast<std::uint8_t>(index + 1U));
      require(plane->add_router(devices[index], secret));
      auto &circuit = circuits[index];
      circuit.circuit = {{devices[index], 1U, 7U, 0U, 0U}, configuration(static_cast<std::uint8_t>(index + 1U)), index + 1U};
      // RFC 5309 permits AllISs for logical P2P Hello while update levels
      // retain separate explicit AllL1ISs and AllL2ISs groups.
      circuit.circuit.configuration.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 9U};
      circuit.circuit.configuration.update_destinations = std::array<packet::Mac, 2U>{
          packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U},
          packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}};
      circuit.port = {lab::node(devices[index]), 0U, 1U};
      lab::ForwardPort port;
      port.configured = port.operational = true;
      port.ordinal = 0U;
      port.mtu = 1514U;
      port.speed_mbps = 1000U;
      port.mac = circuit.circuit.configuration.mac;
      require(plane->configure_port(devices[index], port));
      instances[index] = {circuit.circuit.configuration.local.system, 3U, {level, level},
          1U, {1U, 5U, 5U, 1s, 10U, 1492U, 1U}};
    }
    // Both instance policies suppress LSPs. The explicit per-interface policy
    // enables their real wire output, so ignoring it prevents synchronization.
    for (std::size_t index{}; index < devices.size(); ++index) {
      circuits[index].circuit.update_transmission = instances[index].transmission;
      instances[index].transmission.pacing_burst = 0U;
    }
    const lab::NetworkLinkProgram link{{0U, 1U}, circuits[0U].port, circuits[1U].port,
        1'000'000'000U, 100ns, true};
    require(plane->configure_link(link));
    auto initial = plane->checkpoint();
    require(initial.has_value());
    auto unsupported = instances[0U];
    unsupported.levels[0U]->authenticate_lsp = true;
    require(!plane->add_isis_update_instance(devices[0U], 0U, unsupported) && plane->checkpoint());
    unsupported = instances[0U];
    unsupported.transmission.partial_seconds = 0U;
    require(!plane->add_isis_update_instance(devices[0U], 0U, unsupported) && plane->checkpoint());
    unsupported = instances[0U];
    unsupported.wire_instance = 1U;
    require(!plane->add_isis_update_instance(devices[0U], 1U, unsupported) && plane->checkpoint());
    for (std::size_t index{}; index < devices.size(); ++index) {
      require(plane->add_isis_update_instance(devices[index], 0U, instances[index]));
      const auto cold = plane->checkpoint();
      require(cold && cold->isis && plane->restore(*cold));
      require(plane->query_isis_update_instance(devices[index], 0U)->error == ControlError::none);
      require(plane->replace_isis_p2p_generation(devices[index], std::span{&circuits[index], 1U}));
    }
    const auto query = [&](std::size_t index) {
      const auto result = plane->query_isis_circuit(circuits[index].circuit.identity);
      require(result && result->error == ControlError::none);
      return *result;
    };
    const auto deadline = RuntimeClock::now() + 6s;
    while (!query(0U).adjacency.iso_up || !query(1U).adjacency.iso_up) {
      plane->pump();
      require(RuntimeClock::now() < deadline);
    }
    {
      // Exercise the consumer contract with complete, copied protocol values.
      // SPF and accepted-Hello binding are verified in their separate fixtures.
      using Install = ::router::routing::RouteInstallStatus;
      auto base4 = std::make_unique<lab::routing::FibProgram>();
      auto base6 = std::make_unique<lab::routing::Ipv6FibProgram>();
      base4->generation = base6->generation = 1U;
      base4->count = base6->count = 1U;
      base4->routes[0U] = {.network = 0xc0000200U, .port_ordinal = 0U, .prefix_length = 24U};
      base6->routes[0U] = {.network = *ip::parse_ipv6("2001:db8:12::"), .interface_id = 1U,
          .physical_port_ordinal = 0U, .prefix_length = 64U};
      lab::RoutePolicyProgram policy;
      require(plane->program_route_policy(devices[0U], policy) &&
          plane->program_fib(devices[0U], *base4) && plane->program_ipv6_fib(devices[0U], *base6));
      auto publication = std::make_unique<::router::routing::RouteGeneration>();
      publication->device = devices[0U];
      publication->generation = 1U;
      PrefixRouteCandidate route;
      route.destination = *ip::parse_ip_prefix("198.51.100.0/24");
      route.distance = {0U, 20U, 0U};
      route.next_hop = {{1U, 7U, 0U}, {}, *ip::parse_ip_address("192.0.2.2"), 1U};
      const auto first4 = make_ipv4_rib_input(route, 0U, 15U);
      route.destination = *ip::parse_ip_prefix("2001:db8:100::/64");
      route.next_hop.address = *ip::parse_ip_address("fe80::2");
      const auto first6 = make_ipv6_rib_input(route, 0U, 15U);
      require(first4 && first6);
      publication->ipv4[0U] = *first4;
      publication->ipv6[0U] = *first6;
      publication->ipv4_count = publication->ipv6_count = 1U;
      require(plane->program_isis_routes(*publication) == Install::installed &&
          plane->program_isis_routes(*publication) == Install::stale);
      auto selected = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
      require(selected && selected->fib.count == 2U && selected->ipv6_fib.count == 2U);
      const auto learned4 = std::find_if(selected->fib.routes.begin(), selected->fib.routes.begin() + selected->fib.count,
          [](const auto &entry) { return entry.source == lab::routing::RouteSource::isis; });
      require(learned4 != selected->fib.routes.begin() + selected->fib.count && learned4->interface_generation == 7U);
      publication->generation = 2U;
      publication->ipv4[0U].metric = 21U;
      publication->ipv6[0U].interface_generation = 6U;
      const auto old4 = selected->fib.generation, old6 = selected->ipv6_fib.generation;
      require(plane->program_isis_routes(*publication) == Install::invalid);
      selected = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
      require(selected && selected->fib.generation == old4 && selected->ipv6_fib.generation == old6);
      require(!plane->replace_isis_p2p_generation(devices[0U], {}));
      publication->ipv6[0U].interface_generation = 7U;
      require(plane->program_isis_routes(*publication) == Install::installed);
      // A failed second-family selection returns no installed key.
      base6->routes[0U].prefix_length = 129U;
      require(!plane->program_ipv6_fib(devices[0U], *base6));
      publication->generation = 3U;
      publication->ipv4[0U].metric = 22U;
      selected = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
      const auto retained4 = selected->fib.generation, retained6 = selected->ipv6_fib.generation;
      require(plane->program_isis_routes(*publication) == Install::selection_failed);
      selected = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
      require(selected && selected->fib.generation == retained4 && selected->ipv6_fib.generation == retained6);
      base6->routes[0U].prefix_length = 64U;
      base6->generation = retained6 + 1U;
      require(plane->program_ipv6_fib(devices[0U], *base6));
      require(plane->program_isis_routes(*publication) == Install::installed);
      publication->generation = 4U;
      publication->ipv4_count = publication->ipv6_count = 0U;
      require(plane->program_isis_routes(*publication) == Install::installed);
      selected = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
      require(selected && selected->fib.count == 1U && selected->ipv6_fib.count == 1U &&
          selected->fib.routes[0U].source == lab::routing::RouteSource::connected &&
          selected->ipv6_fib.routes[0U].source == lab::routing::RouteSource::connected);
    }
    auto changed_policy = circuits[0U];
    changed_policy.circuit.update_transmission->pacing_burst = 1U;
    require(!plane->replace_isis_generation(devices[0U], std::span{&changed_policy, 1U}) && query(0U).adjacency.iso_up);
    changed_policy.circuit.identity.configuration_generation = 8U;
    changed_policy.circuit.update_transmission->partial_seconds = 0U;
    require(!plane->replace_isis_generation(devices[0U], std::span{&changed_policy, 1U}) && query(0U).adjacency.iso_up);
    auto scratch = std::make_unique<PduScratch>();
    LspContents contents;
    contents.header = {packet::isis::PduType::lsp_l1,
        {1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U}, 1200U, 1U, 3U};
    const std::array<std::uint8_t, 9U> semantic{1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 1U, packet::isis::ipv4_nlpid};
    contents.options = semantic;
    contents.maximum_pdu_octets = 1492U;
    for (std::uint8_t selected{}; selected < 2U; ++selected) {
      contents.header.type = selected ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
      const auto pdu = build_lsp_pdu(contents, scratch->options, scratch->pdu);
      require(pdu.status == LspBuildStatus::encoded);
      const auto result = plane->originate_isis_lsp(devices[0U], 0U, selected, pdu.bytes);
      require(result && result->error == ControlError::none && result->origin.install == LspInstallResult::installed);
    }
    for (;;) {
      const auto peer = plane->query_isis_update_instance(devices[1U], 0U);
      require(peer && peer->error == ControlError::none && peer->update_status == UpdateStatus::applied);
      if (peer->retained_lsps == std::array<std::size_t, 2U>{1U, 1U} &&
          query(0U).flood_requests == std::array<std::size_t, 2U>{} &&
          query(1U).snp_requests == std::array<std::size_t, 2U>{}) break;
      plane->pump();
      require(RuntimeClock::now() < deadline);
    }
    require(query(0U).counters.lsp_enqueued >= 2U && query(1U).counters.snp_enqueued >= 2U);
    for (std::uint8_t queried_level{}; queried_level < 2U; ++queried_level) {
      const auto retained = plane->query_isis_lsp(devices[1U], 0U, queried_level, contents.header.id);
      require(retained && retained->error == ControlError::none && retained->selected_lsp &&
          retained->selected_lsp->id == contents.header.id && retained->selected_lsp->sequence == 1U &&
          retained->selected_lsp->remaining_seconds > 0U && retained->selected_lsp->remaining_seconds <= 1200U);
    }
    auto missing_id = contents.header.id;
    missing_id.back() = 0xffU;
    const auto missing = plane->query_isis_lsp(devices[1U], 0U, 0U, missing_id);
    const auto invalid_level = plane->query_isis_lsp(devices[1U], 0U, 2U, contents.header.id);
    require(missing && missing->error == ControlError::not_found && !missing->selected_lsp &&
        invalid_level && invalid_level->error == ControlError::invalid_argument && !invalid_level->selected_lsp);
    // Remaining Lifetime is an aged wire value, not a reduced configured
    // MaxAge. Both owner-loop placements must finalize this near-expiry copy.
    contents.header.type = packet::isis::PduType::lsp_l1;
    contents.header.sequence = 2U;
    contents.header.remaining_seconds = 2U;
    const auto near_expiry = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(near_expiry.status == LspBuildStatus::encoded);
    const auto installed = plane->originate_isis_lsp(devices[0U], 0U, 0U, near_expiry.bytes);
    require(installed && installed->error == ControlError::none);
    const auto expiration_deadline = RuntimeClock::now() + 5s;
    for (;;) {
      const auto local = plane->query_isis_update_instance(devices[0U], 0U);
      const auto peer = plane->query_isis_update_instance(devices[1U], 0U);
      require(local && peer && local->update_status == UpdateStatus::applied && peer->update_status == UpdateStatus::applied);
      if (local->retained_purges[0U] == 1U && peer->retained_purges[0U] == 1U) break;
      plane->pump();
      require(RuntimeClock::now() < expiration_deadline);
    }
    const auto epoch = plane->query_isis_update_instance(devices[0U], 0U)->update_epoch;
    for (std::size_t index{}; index < devices.size(); ++index) {
      require(plane->replace_isis_p2p_generation(devices[index], {}));
      const auto retained = plane->query_isis_update_instance(devices[index], 0U);
      require(retained && retained->retained_lsps == std::array<std::size_t, 2U>{1U, 1U});
    }
    const auto retired = plane->checkpoint();
    require(retired.has_value());
    require(retired->isis.has_value());
    require(plane->restore(*retired));
    require(plane->query_isis_update_instance(devices[0U], 0U)->update_epoch == epoch);
    for (const auto device : devices) require(plane->remove_isis_update_instance(device, 0U));
    require(plane->checkpoint().has_value());
    require(plane->add_isis_update_instance(devices[0U], 0U, instances[0U]));
    require(plane->query_isis_update_instance(devices[0U], 0U)->update_epoch > epoch);
    require(plane->remove_isis_update_instance(devices[0U], 0U));
    for (std::size_t index{}; index < devices.size(); ++index) {
      auto &automatic = instances[index];
      automatic.origination.emplace();
      automatic.origination->resource_retry = 100ms;
      automatic.origination->neighbors = std::vector<P2pOriginInterface>{{circuits[index].circuit.identity.interface_id,
          {P2pOriginMetric{10U, 10U}, P2pOriginMetric{10U, 10U}}}};
      auto &local = automatic.origination->content;
      local.random = index + 1U;
      local.levels = {LocalLspLevelProgram{1200U, 1492U, 10ms, 1s},
          LocalLspLevelProgram{1200U, 1492U, 10ms, 1s}};
      packet::isis::LspId root{};
      std::copy(automatic.local.begin(), automatic.local.end(), root.begin());
      const std::vector<std::uint8_t> options(semantic.begin(), semantic.end());
      local.records = {{0U, root, 3U, options}, {1U, root, 3U, options}};
      root.back() = 1U;
      local.records.push_back({0U, root, 3U, {8U, 0U}, false});
      circuits[index].circuit.identity.configuration_generation = 8U;
      require(plane->add_isis_update_instance(devices[index], 0U, automatic));
      require(plane->replace_isis_p2p_generation(devices[index], std::span{&circuits[index], 1U}));
    }
    const auto automatic_deadline = RuntimeClock::now() + 6s;
    for (;;) {
      plane->pump();
      const auto left = plane->query_isis_update_instance(devices[0U], 0U);
      const auto right = plane->query_isis_update_instance(devices[1U], 0U);
      require(left && right && left->update_status == UpdateStatus::applied && right->update_status == UpdateStatus::applied);
      if (left->retained_lsps == std::array<std::size_t, 2U>{2U, 2U} &&
          right->retained_lsps == std::array<std::size_t, 2U>{2U, 2U} &&
          left->local_root_sequences[0U] >= 2U && right->local_root_sequences[1U] >= 2U &&
          left->local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}} &&
          left->local_root_links[1U] == std::optional{LspLinkCounts{1U, 1U}} &&
          right->local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}} &&
          right->local_root_links[1U] == std::optional{LspLinkCounts{1U, 1U}}) break;
      require(RuntimeClock::now() < automatic_deadline);
    }
    require(plane->replace_isis_p2p_generation(devices[0U], {}));
    const auto down_by = RuntimeClock::now() + 3s;
    for (;;) {
      plane->pump();
      const auto state = plane->query_isis_update_instance(devices[0U], 0U);
      require(state && state->update_status == UpdateStatus::applied);
      if (state->local_root_links[0U] == std::optional{LspLinkCounts{}} &&
          state->local_root_links[1U] == std::optional{LspLinkCounts{}}) break;
      require(RuntimeClock::now() < down_by);
    }
    circuits[0U].circuit.identity.configuration_generation = 9U;
    require(plane->replace_isis_p2p_generation(devices[0U], std::span{&circuits[0U], 1U}));
    const auto restored_by = RuntimeClock::now() + 6s;
    for (;;) {
      plane->pump();
      const auto state = plane->query_isis_update_instance(devices[0U], 0U);
      require(state && state->update_status == UpdateStatus::applied);
      if (state->local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}} &&
          state->local_root_links[1U] == std::optional{LspLinkCounts{1U, 1U}}) break;
      require(RuntimeClock::now() < restored_by);
    }
    packet::isis::LspId fragment{};
    std::copy(instances[0U].local.begin(), instances[0U].local.end(), fragment.begin());
    fragment.back() = 1U;
    const auto await_fragment = [&](std::uint32_t sequence, bool live) {
      const auto until = RuntimeClock::now() + 3s;
      for (;;) {
        plane->pump();
        const auto peer = plane->query_isis_lsp(devices[1U], 0U, 0U, fragment);
        require(peer && (peer->error == ControlError::none || peer->error == ControlError::not_found));
        if (peer->selected_lsp && peer->selected_lsp->sequence >= sequence &&
            static_cast<bool>(peer->selected_lsp->remaining_seconds) == live) break;
        require(RuntimeClock::now() < until);
      }
    };
    const auto activated = plane->replace_isis_local_lsp(devices[0U], 0U, {0U, fragment, 3U, {8U, 0U}});
    require(activated && activated->error == ControlError::none && activated->local_content_result == LocalContentResult::changed);
    await_fragment(1U, true);
    const auto withdrawn = plane->withdraw_isis_local_lsp(devices[0U], 0U, 0U, fragment);
    require(withdrawn && withdrawn->error == ControlError::none && withdrawn->local_content_result == LocalContentResult::changed);
    const auto repeated = plane->withdraw_isis_local_lsp(devices[0U], 0U, 0U, fragment);
    require(repeated && repeated->error == ControlError::none && repeated->local_content_result == LocalContentResult::unchanged);
    await_fragment(1U, false);
    const auto reactivated = plane->replace_isis_local_lsp(devices[0U], 0U, {0U, fragment, 3U, {8U, 0U}});
    require(reactivated && reactivated->error == ControlError::none);
    await_fragment(2U, true);
    const auto malformed = plane->replace_isis_local_lsp(devices[0U], 0U, {0U, fragment, 3U, {13U, 0U}});
    require(malformed && malformed->error == ControlError::invalid_argument);
    fragment.back() = 0U;
    const auto root_refusal = plane->withdraw_isis_local_lsp(devices[0U], 0U, 0U, fragment);
    require(root_refusal && root_refusal->error == ControlError::invalid_argument);
    const auto unchanged_root = plane->replace_isis_local_lsp(devices[0U], 0U,
        {0U, fragment, 3U, std::vector<std::uint8_t>(semantic.begin(), semantic.end())});
    require(unchanged_root && unchanged_root->error == ControlError::none &&
        unchanged_root->local_content_result == LocalContentResult::unchanged);
    const auto injected_links = plane->replace_isis_local_lsp(devices[0U], 0U, {0U, fragment, 3U, {22U, 0U}});
    require(injected_links && injected_links->error == ControlError::invalid_argument);
    auto edited_options = std::vector<std::uint8_t>(semantic.begin(), semantic.end());
    edited_options.insert(edited_options.end(), {250U, 1U, 7U});
    const auto edited_root = plane->replace_isis_local_lsp(devices[0U], 0U, {0U, fragment, 3U, edited_options});
    require(edited_root && edited_root->error == ControlError::none &&
        edited_root->local_content_result == LocalContentResult::changed);
    const auto root_sequence = plane->query_isis_update_instance(devices[0U], 0U)->local_root_sequences[0U];
    const auto edited_by = RuntimeClock::now() + 3s;
    for (;;) {
      plane->pump();
      const auto state = plane->query_isis_update_instance(devices[0U], 0U);
      require(state && state->update_status == UpdateStatus::applied);
      if (state->local_root_sequences[0U] > root_sequence &&
          state->local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}}) break;
      require(RuntimeClock::now() < edited_by);
    }
    const auto raw_refusal = plane->originate_isis_lsp(devices[0U], 0U, 0U, near_expiry.bytes);
    require(raw_refusal && raw_refusal->error == ControlError::update_refused);
    for (const auto device : devices) {
      require(plane->replace_isis_p2p_generation(device, {}));
      require(plane->remove_isis_update_instance(device, 0U));
    }
    require(plane->checkpoint().has_value());
    require(plane->remove_router(devices[0U]) && plane->checkpoint() && plane->restore(*initial));
  }
}

void isis_network_plane_route_publication_tests() {
  using Install = ::router::routing::RouteInstallStatus;
  using Source = lab::routing::RouteSource;
  constexpr auto interface = lab::physical_interface_id(0U);
  for (const auto cpus : {1U, 8U}) {
    auto plane = std::make_unique<lab::NetworkPlane>(cpus);
    const std::array devices{lab::DeviceHandle{0U, 1U}, lab::DeviceHandle{1U, 1U}};
    std::array<lab::IsisP2pCircuitProgram, 2U> circuits;
    std::array<UpdateInstanceProgram, 2U> programs;
    const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U,
        1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
    for (std::size_t index{}; index < devices.size(); ++index) {
      crypto::Sha256Digest secret{};
      secret.fill(static_cast<std::uint8_t>(index + 1U));
      require(plane->add_router(devices[index], secret));
      auto hello = configuration(static_cast<std::uint8_t>(index + 1U));
      // RFC 1195 4.4 requires forwarding to a physically adjacent router
      // even when its IPv4 address belongs to a different logical subnet.
      if (index) hello.ipv4_addresses[0U] = {198U, 51U, 100U, 2U};
      hello.protocols.push_back(packet::isis::ipv6_nlpid);
      hello.ipv6_addresses.push_back(*ip::parse_ipv6(index ? "fe80::2" : "fe80::1"));
      circuits[index] = {{{devices[index], interface, 7U, 0U, 0U}, hello, index + 1U},
          {lab::node(devices[index]), 0U, 1U}};
      lab::ForwardPort port;
      port.configured = port.operational = true;
      port.ordinal = 0U;
      port.mtu = 1514U;
      port.address = index ? 0xc6336402U : 0xc0000201U;
      port.network = index ? 0xc6336400U : 0xc0000200U;
      port.prefix_length = 24U;
      port.speed_mbps = 1000U;
      port.mac = hello.mac;
      port.ipv6_configured = true;
      port.ipv6_address = *ip::parse_ipv6(index ? "2001:db8:12::2" : "2001:db8:12::1");
      port.ipv6_network = *ip::parse_ipv6("2001:db8:12::");
      port.ipv6_link_local = hello.ipv6_addresses.front();
      port.ipv6_prefix_length = 64U;
      require(plane->configure_port(devices[index], port));
      auto base4 = std::make_unique<lab::routing::FibProgram>();
      auto base6 = std::make_unique<lab::routing::Ipv6FibProgram>();
      base4->generation = base6->generation = 1U;
      base4->count = base6->count = 1U;
      base4->routes[0U] = {.network = port.network, .port_ordinal = 0U, .prefix_length = 24U};
      base6->routes[0U] = {.network = port.ipv6_network, .interface_id = interface,
          .physical_port_ordinal = 0U, .prefix_length = 64U};
      lab::RoutePolicyProgram policy;
      require(plane->program_route_policy(devices[index], policy) && plane->program_fib(devices[index], *base4) &&
          plane->program_ipv6_fib(devices[index], *base6));
      auto &program = programs[index];
      program = {hello.local.system, 3U, {level, level}, 1U, {1U, 5U, 5U, 1s, 10U, 1492U, 1U}};
      program.origination.emplace();
      program.origination->resource_retry = 100ms;
      program.origination->neighbors = std::vector<P2pOriginInterface>{{interface,
          {P2pOriginMetric{10U, 10U}, P2pOriginMetric{10U, 10U}}}};
      auto &local = program.origination->content;
      local.random = index + 1U;
      local.levels = {LocalLspLevelProgram{1200U, 1492U, 10ms, 1s}, LocalLspLevelProgram{1200U, 1492U, 10ms, 1s}};
      const std::array prefixes{
          RootPrefix{*ip::parse_ip_prefix(index ? "198.51.100.2/32" : "192.0.2.1/32"), 5U, {}},
          RootPrefix{*ip::parse_ip_prefix(index ? "2001:db8:12::2/128" : "2001:db8:12::1/128"), 7U, {}}};
      const std::array<packet::Ipv6, 1U> global_ipv6{port.ipv6_address};
      RootContentInput root;
      root.local = program.local; root.flags = 3U; root.ipv4 = root.ipv6 = true;
      root.areas = hello.areas; root.prefixes = prefixes;
      root.ipv4_addresses = hello.ipv4_addresses; root.ipv6_addresses = global_ipv6;
      root.hostname = index ? "R2" : "R1";
      for (std::size_t selected{}; selected < 2U; ++selected) {
        root.level = static_cast<std::uint8_t>(selected);
        auto prepared = prepare_root_content(root, 1492U - packet::isis::lsp_header_octets, 1U);
        require(prepared.status == RootContentStatus::prepared);
        for (auto &record : prepared.records) local.records.push_back(std::move(record));
      }
      for (std::size_t family{}; family < program.routing.size(); ++family) {
        program.routing[family].emplace();
        auto &route = *program.routing[family];
        route.calculation = {8U, 16U, 32U,
            family ? packet::isis::ipv6_nlpid : packet::isis::ipv4_nlpid, PrefixCollectionBudget{8U, 128U}};
        route.preferences = {P2pRouteFamilyProgram::Preference{15U, 160U}, P2pRouteFamilyProgram::Preference{18U, 165U}};
      }
    }
    require(plane->configure_link({{0U, 1U}, circuits[0U].port, circuits[1U].port, 1'000'000'000U, 100ns, true}));
    auto invalid = programs[0U];
    invalid.routing[0U]->preferences[0U].internal = 0U;
    require(!plane->add_isis_update_instance(devices[0U], 0U, invalid));
    invalid = programs[0U];
    invalid.routing[1U]->calculation.protocol = packet::isis::ipv4_nlpid;
    require(!plane->add_isis_update_instance(devices[0U], 0U, invalid));
    std::array<std::uint64_t, 2U> generations{};
    for (unsigned cycle{}; cycle < 2U; ++cycle) {
      for (std::size_t index{}; index < devices.size(); ++index) {
        circuits[index].circuit.identity.configuration_generation = 7U + cycle;
        require(plane->add_isis_update_instance(devices[index], 0U, programs[index]) &&
            plane->replace_isis_p2p_generation(devices[index], std::span{&circuits[index], 1U}));
      }
      const auto converged = RuntimeClock::now() + 8s;
      for (;;) {
        plane->pump();
        bool ready = true;
        for (std::size_t index{}; index < devices.size(); ++index) {
          const auto state = plane->query_isis_update_instance(devices[index], 0U);
          const auto selected = heap_router_checkpoint(*plane, devices[index], RuntimeClock::now());
          require(state && state->error == ControlError::none && selected);
          ready = ready && state->route_install_status == Install::installed && state->route_installed_generation > generations[index];
          const auto address = *ip::parse_ipv6(index ? "2001:db8:12::2" : "2001:db8:12::1");
          ready = ready && std::any_of(selected->ipv6_dad.begin(), selected->ipv6_dad.end(),
              [&](const auto &dad) { return dad.interface_id == interface && dad.address == address &&
                  dad.state == lab::Ipv6DadState::preferred; });
          ready = ready && std::any_of(selected->fib.routes.begin(), selected->fib.routes.begin() + selected->fib.count,
              [&](const auto &route) { return route.source == Source::isis && route.metric == 15U &&
                  route.interface_generation == 7U + cycle && route.next_hop == (index ? 0xc0000201U : 0xc6336402U); });
          ready = ready && std::any_of(selected->ipv6_fib.routes.begin(), selected->ipv6_fib.routes.begin() + selected->ipv6_fib.count,
              [&](const auto &route) { return route.source == Source::isis && route.metric == 17U &&
                  route.interface_generation == 7U + cycle && route.interface_id == interface; });
        }
        if (ready) break;
        require(RuntimeClock::now() < converged);
      }
      // Back-to-back owner snapshots can resume before the forwarding pthread
      // reaches its wait. A published pause receipt must already be armed so
      // that an early resume is retained rather than overwritten afterwards.
      for (std::size_t sample{}; sample < 128U; ++sample) {
        const auto state = heap_router_checkpoint(*plane, devices[sample % devices.size()], RuntimeClock::now());
        require(state && state->fib.count == 2U && state->ipv6_fib.count == 2U);
      }
      // Real ARP and ND resolve the bound peer; encoded requests and replies
      // traverse the configured physical link in both owner layouts.
      const auto ping_by = RuntimeClock::now() + 5s;
      bool sent4{}, sent6{};
      while (!sent4 || !sent6 || !plane->router_ping_reply(devices[0U], 71U) ||
          !plane->router_ipv6_ping_reply(devices[0U], 72U)) {
        plane->pump();
        if (!sent4) sent4 = plane->start_router_ping(devices[0U], 0xc6336402U, 71U, RuntimeClock::now());
        if (!sent6) sent6 = plane->start_router_ipv6_ping(devices[0U], *ip::parse_ipv6("2001:db8:12::2"), 72U, RuntimeClock::now());
        if (RuntimeClock::now() >= ping_by) {
          const auto state = heap_router_checkpoint(*plane, devices[0U], RuntimeClock::now());
          throw std::runtime_error("IS-IS forwarding timeout CPUs=" + std::to_string(cpus) +
              " cycle=" + std::to_string(cycle) + " sent4=" + std::to_string(sent4) + " sent6=" + std::to_string(sent6) +
              " reply4=" + std::to_string(plane->router_ping_reply(devices[0U], 71U)) +
              " reply6=" + std::to_string(plane->router_ipv6_ping_reply(devices[0U], 72U)) +
              " drop=" + std::to_string(state ? static_cast<unsigned>(state->last_drop) : 255U));
        }
      }
      for (std::size_t index{}; index < devices.size(); ++index) {
        generations[index] = plane->query_isis_update_instance(devices[index], 0U)->route_installed_generation;
        const std::array<std::uint8_t, 1U> missing{1U};
        require(!plane->replace_isis_generation(devices[index], std::span{&circuits[index], 1U}, {}, missing));
        const auto unchanged = heap_router_checkpoint(*plane, devices[index], RuntimeClock::now());
        require(unchanged && unchanged->fib.count == 2U && unchanged->ipv6_fib.count == 2U &&
            plane->query_isis_update_instance(devices[index], 0U)->error == ControlError::none);
        const std::array<std::uint8_t, 1U> retired{0U};
        require(plane->replace_isis_generation(devices[index], {}, {}, retired));
      }
      // The synchronous retirement receipt already covers both FIB families;
      // no pump or asynchronous withdrawal retry is needed before inspection.
      for (const auto device : devices) {
        const auto selected = heap_router_checkpoint(*plane, device, RuntimeClock::now());
        require(selected && selected->fib.count == 1U && selected->ipv6_fib.count == 1U &&
            selected->fib.routes[0U].source == Source::connected && selected->ipv6_fib.routes[0U].source == Source::connected);
      }
    }
  }
}

void isis_network_plane_lan_tests() {
  constexpr auto interface = lab::physical_interface_id(0U);
  for (const auto cpus : {1U, 8U}) {
    auto plane = std::make_unique<lab::NetworkPlane>(cpus);
    const std::array devices{lab::DeviceHandle{0U, 1U}, lab::DeviceHandle{1U, 1U}};
    const std::array groups{packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U},
        packet::Mac{1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}};
    std::array<lab::IsisCircuitProgram, 2U> programs;
    for (std::uint8_t index{}; index < 2U; ++index) {
      crypto::Sha256Digest secret{};
      secret.fill(static_cast<std::uint8_t>(index + 11U));
      require(plane->add_router(devices[index], secret));
      auto &program = programs[index];
      program.circuit.identity = {devices[index], interface, 7U, 0U, 0U};
      program.circuit.random_state = index + 51U;
      program.circuit.broadcast.emplace();
      const auto common = configuration(static_cast<std::uint8_t>(index + 1U));
      for (std::size_t level{}; level < 2U; ++level) {
        LanCircuitConfiguration entry;
        static_cast<CircuitHelloConfiguration &>(entry) = common;
        entry.local = {common.local.system, common.mac,
            level ? static_cast<std::uint8_t>(index ? 20U : 100U) : std::uint8_t{64U}, 1U};
        entry.levels = Levels::both;
        entry.type = level ? packet::isis::PduType::lan_hello_l2 : packet::isis::PduType::lan_hello_l1;
        entry.hello_destination = groups[level];
        entry.update_destinations = groups;
        entry.designated_hello_interval = 1s;
        entry.designated_holding_seconds = 3U;
        entry.limits = {4U, 3U};
        if (index) entry.ipv4_addresses[0U] = {198U, 51U, 100U, 2U};
        entry.protocols.push_back(packet::isis::ipv6_nlpid);
        entry.ipv6_addresses.push_back(*ip::parse_ipv6(index ? "fe80::2" : "fe80::1"));
        program.circuit.broadcast->levels[level] = std::move(entry);
      }
      program.port = {lab::node(devices[index]), 0U, 1U};
      lab::ForwardPort port;
      port.configured = port.operational = true;
      port.ordinal = 0U;
      port.mtu = 1514U;
      port.speed_mbps = 1000U;
      port.mac = common.mac;
      port.address = index ? 0xc6336402U : 0xc0000201U;
      port.network = index ? 0xc6336400U : 0xc0000200U;
      port.prefix_length = 24U;
      port.ipv6_configured = true;
      port.ipv6_address = *ip::parse_ipv6(index ? "2001:db8:22::2" : "2001:db8:12::1");
      port.ipv6_network = *ip::parse_ipv6(index ? "2001:db8:22::" : "2001:db8:12::");
      port.ipv6_link_local = *ip::parse_ipv6(index ? "fe80::2" : "fe80::1");
      port.ipv6_prefix_length = 64U;
      require(plane->configure_port(devices[index], port));
      auto base4 = std::make_unique<lab::routing::FibProgram>();
      auto base6 = std::make_unique<lab::routing::Ipv6FibProgram>();
      base4->generation = base6->generation = 1U;
      base4->count = base6->count = 1U;
      base4->routes[0U] = {.network = port.network, .port_ordinal = 0U, .prefix_length = 24U};
      base6->routes[0U] = {.network = port.ipv6_network, .interface_id = interface,
          .physical_port_ordinal = 0U, .prefix_length = 64U};
      lab::RoutePolicyProgram policy;
      require(plane->program_route_policy(devices[index], policy) && plane->program_fib(devices[index], *base4) &&
          plane->program_ipv6_fib(devices[index], *base6));
    }
    require(plane->configure_link({{0U, 1U}, programs[0U].port, programs[1U].port,
        1'000'000'000U, 100ns, true}));
    const auto original_programs = programs;
    const auto initial = plane->checkpoint();
    require(initial.has_value());
    for (std::size_t index{}; index < 2U; ++index)
      require(plane->replace_isis_generation(devices[index], std::span{&programs[index], 1U}));
    const auto query = [&](std::size_t index) {
      const auto result = plane->query_isis_circuit(programs[index].circuit.identity);
      require(result && result->error == ControlError::none && result->broadcast_circuit && !result->adjacency.present);
      return *result;
    };
    const auto wait = [&](auto ready, std::source_location location = std::source_location::current()) {
      const auto until = RuntimeClock::now() + 8s;
      while (!ready()) {
        plane->pump();
        if (RuntimeClock::now() < until) continue;
        std::string detail;
        for (std::size_t router{}; router < devices.size(); ++router) {
          const auto state = plane->query_isis_update_instance(devices[router], 0U);
          const auto circuit = query(router);
          detail += " router=" + std::to_string(router) + " up=" + std::to_string(circuit.lan_up[0U]) + "," +
              std::to_string(circuit.lan_up[1U]) + " lsp=" + std::to_string(circuit.counters.lsp_enqueued) +
              " snp=" + std::to_string(circuit.counters.snp_enqueued);
          if (state) for (std::size_t level_index{}; level_index < 2U; ++level_index) {
            detail += " level=" + std::to_string(level_index) + " records=" + std::to_string(state->retained_lsps[level_index]) +
                " purges=" + std::to_string(state->retained_purges[level_index]);
            if (state->local_root_links[level_index]) detail += " root=" +
                std::to_string(state->local_root_links[level_index]->narrow) + "," + std::to_string(state->local_root_links[level_index]->wide);
          }
        }
        throw std::runtime_error("IS-IS LAN convergence failed at " + std::to_string(location.line()) + detail);
      }
    };
    wait([&] {
      const auto a = query(0U), b = query(1U);
      return a.lan_up == std::array<std::size_t, 2U>{1U, 1U} && b.lan_up == a.lan_up &&
          a.designated[0U] && a.designated[1U] && b.designated[0U] && b.designated[1U];
    });
    for (std::size_t index{}; index < 2U; ++index) {
      const auto result = query(index);
      require(result.lan_neighbors == std::array<std::size_t, 2U>{1U, 1U} &&
          result.designated[0U]->system.back() == 2U && result.designated[1U]->system.back() == 1U &&
          result.designated[0U]->local == (index == 1U) && result.designated[1U]->local == (index == 0U) &&
          result.counters.hello_enqueued >= 2U && result.counters.designated_changes >= 2U &&
          result.holding_deadline_nanoseconds > 0 && result.thread_identity);
    }
    const auto peer = configuration(2U).mac;
    const auto bound4 = plane->query_isis_lan_next_hop(programs[0U].circuit.identity, 1U, peer,
        *ip::parse_ip_address("198.51.100.2"));
    const auto bound6 = plane->query_isis_lan_next_hop(programs[0U].circuit.identity, 2U, peer,
        *ip::parse_ip_address("fe80::2"));
    require(bound4 && bound6 && bound4->bound_next_hop && bound6->bound_next_hop &&
        bound4->bound_next_hop->peer.back() == 2U && bound6->bound_next_hop->level == 2U &&
        bound6->bound_next_hop->interface == NextHopInterface{interface, 7U, 0U});
    const auto absent = plane->query_isis_lan_next_hop(programs[0U].circuit.identity, 2U, peer,
        *ip::parse_ip_address("fe80::99"));
    require(absent && absent->error == ControlError::not_found && !absent->bound_next_hop);
    const auto elected = plane->checkpoint();
    require(elected && elected->isis && plane->restore(*elected));
    // RuntimeSupervisor owns base intent and republishes it after the network
    // owner commits. This direct network fixture performs the same handoff.
    const auto restore_base = [&] {
      for (const auto &router : initial->routers) {
        lab::RoutePolicyProgram policy;
        require(plane->program_route_policy(router.device, policy) &&
            plane->program_fib(router.device, router.forwarding.fib) &&
            plane->program_ipv6_fib(router.device, router.forwarding.ipv6_fib));
      }
    };
    restore_base();
    require(query(0U).lan_up[0U] == 1U && query(0U).lan_up[1U] == 1U);
    const auto restored_binding = plane->query_isis_lan_next_hop(programs[0U].circuit.identity, 1U, peer,
        *ip::parse_ip_address("198.51.100.2"));
    require(restored_binding && restored_binding->bound_next_hop == bound4->bound_next_hop);
    auto invalid = programs[0U];
    invalid.circuit.broadcast->levels[0U]->local.priority = 10U;
    require(!plane->replace_isis_generation(devices[0U], std::span{&invalid, 1U}) && query(0U).lan_up[0U] == 1U);
    invalid.circuit.identity.configuration_generation = 8U;
    invalid.circuit.broadcast->levels[1U]->local.system.back() = 3U;
    require(!plane->replace_isis_generation(devices[0U], std::span{&invalid, 1U}) && query(0U).lan_up[1U] == 1U);
    const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 128U, 1492U, 1200U, 60s, 60s,
        false, false, false, PurgeRules::registry_6233};
    const UpdateInstanceProgram update{programs[0U].circuit.broadcast->levels[0U]->local.system,
        3U, {level, level}, 1U, {1U, 5U, 5U, 1s, 10U, 1492U, 1U}};
    require(!plane->add_isis_update_instance(devices[0U], 0U, update) && query(0U).lan_up[0U] == 1U);
    for (std::size_t index{}; index < devices.size(); ++index) {
      auto active_update = update;
      active_update.local = programs[index].circuit.broadcast->levels[0U]->local.system;
      active_update.transmission.broadcast = BroadcastTransmissionProgram{20ms, 20ms};
      require(plane->add_isis_update_instance(devices[index], 0U, active_update));
    }
    auto lan_scratch = std::make_unique<PduScratch>();
    LspContents lan_content;
    lan_content.header = {packet::isis::PduType::lsp_l1,
        {1U, 2U, 3U, 4U, 5U, 1U, 0U, 0U}, 1200U, 1U, 3U};
    const std::array<std::uint8_t, 10U> lan_options{1U, 4U, 3U, 0x49U, 0U, 1U,
        129U, 2U, packet::isis::ipv4_nlpid, packet::isis::ipv6_nlpid};
    lan_content.options = lan_options;
    lan_content.maximum_pdu_octets = 1492U;
    for (std::uint8_t level_index{}; level_index < 2U; ++level_index) {
      lan_content.header.type = level_index ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1;
      const auto encoded = build_lsp_pdu(lan_content, lan_scratch->options, lan_scratch->pdu);
      require(encoded.status == LspBuildStatus::encoded);
      const auto result = plane->originate_isis_lsp(devices[0U], 0U, level_index, encoded.bytes);
      require(result && result->error == ControlError::none);
    }
    wait([&] {
      const auto remote = plane->query_isis_update_instance(devices[1U], 0U);
      require(remote && remote->update_status == UpdateStatus::applied);
      return remote->retained_lsps == std::array<std::size_t, 2U>{1U, 1U} &&
          query(0U).flood_requests == std::array<std::size_t, 2U>{} &&
          query(0U).counters.lsp_enqueued >= 2U && query(0U).counters.snp_enqueued && query(1U).counters.snp_enqueued;
    });
    for (std::uint8_t level_index{}; level_index < 2U; ++level_index) {
      const auto retained = plane->query_isis_lsp(devices[1U], 0U, level_index, lan_content.header.id);
      require(retained && retained->selected_lsp && retained->selected_lsp->sequence == 1U);
    }
    const auto retired_identity = programs[0U].circuit.identity;
    programs[0U].circuit.identity.configuration_generation = 8U;
    programs[0U].circuit.broadcast->levels[0U]->limits.neighbors = 6U;
    require(plane->replace_isis_generation(devices[0U], std::span{&programs[0U], 1U}));
    const auto stale = plane->query_isis_circuit(retired_identity);
    require(stale && stale->error == ControlError::stale_configuration);
    wait([&] { return query(0U).lan_up == std::array<std::size_t, 2U>{1U, 1U} && query(1U).lan_up[1U] == 1U; });
    programs[0U].circuit.identity.configuration_generation = 9U;
    programs[0U].circuit.broadcast->levels[1U].reset();
    programs[0U].circuit.broadcast->levels[0U]->levels = Levels::level1;
    require(plane->replace_isis_generation(devices[0U], std::span{&programs[0U], 1U}));
    wait([&] { return query(0U).lan_up == std::array<std::size_t, 2U>{1U, 0U} &&
        query(1U).lan_up == std::array<std::size_t, 2U>{1U, 0U}; });
    require(!query(0U).designated[1U] && !query(1U).designated[1U]);
    for (const auto device : devices) {
      require(plane->replace_isis_generation(device, {}));
      require(plane->remove_isis_update_instance(device, 0U));
    }
    // Distinct standard IIDs share their level multicast groups on one LAN
    // interface. Collision admission must read the selected medium's selector.
    std::array multiple{programs[0U], programs[0U]};
    for (std::size_t index{}; index < multiple.size(); ++index) {
      auto &entry = multiple[index].circuit;
      entry.identity.instance = static_cast<std::uint8_t>(index + 1U);
      entry.identity.configuration_generation = 10U;
      auto &hello_level = *entry.broadcast->levels[0U];
      hello_level.instance_format = packet::isis::InstanceFormat::standard;
      hello_level.emit_instance = true;
      hello_level.wire_instance = static_cast<std::uint16_t>(index + 1U);
      hello_level.instance_topologies = {0U};
      hello_level.hello_destination = {1U, 0U, 0x5eU, 0x90U, 0U, 2U};
      hello_level.update_destinations = std::array{hello_level.hello_destination,
          packet::Mac{1U, 0U, 0x5eU, 0x90U, 0U, 3U}};
    }
    require(plane->replace_isis_generation(devices[0U], multiple));
    for (const auto &entry : multiple) {
      const auto result = plane->query_isis_circuit(entry.circuit.identity);
      require(result && result->error == ControlError::none && result->broadcast_circuit);
    }
    auto collision = multiple;
    for (auto &entry : collision) entry.circuit.identity.configuration_generation = 11U;
    collision[1U].circuit.broadcast->levels[0U]->wire_instance = 1U;
    require(!plane->replace_isis_generation(devices[0U], collision));
    for (const auto &entry : multiple) {
      const auto result = plane->query_isis_circuit(entry.circuit.identity);
      require(result && result->error == ControlError::none && result->broadcast_circuit);
    }
    require(plane->replace_isis_generation(devices[0U], {}));
    programs = original_programs;
    std::array<UpdateInstanceProgram, 2U> automatic_programs;
    for (std::size_t index{}; index < devices.size(); ++index) {
      auto automatic = update;
      automatic.local = programs[index].circuit.broadcast->levels[0U]->local.system;
      automatic.transmission.broadcast = BroadcastTransmissionProgram{20ms, 20ms};
      automatic.origination.emplace();
      automatic.origination->resource_retry = 100ms;
      automatic.origination->broadcast_neighbors = std::vector<LanOriginInterface>{{interface, 1U, 6U,
          {P2pOriginMetric{10U, 10U}, P2pOriginMetric{10U, 10U}}}};
      auto &content = automatic.origination->content;
      content.random = index + 1U;
      content.levels = {LocalLspLevelProgram{1200U, 1492U, 10ms, 600s},
          LocalLspLevelProgram{1200U, 1492U, 10ms, 600s}};
      packet::isis::LspId root_id{};
      std::copy(automatic.local.begin(), automatic.local.end(), root_id.begin());
      content.records = {{0U, root_id, 3U, {lan_options.begin(), lan_options.end()}},
          {1U, root_id, 3U, {lan_options.begin(), lan_options.end()}}};
      automatic_programs[index] = automatic;
      require(plane->add_isis_update_instance(devices[index], 0U, automatic));
      programs[index].circuit.identity.configuration_generation = 11U;
      require(plane->replace_isis_generation(devices[index], std::span{&programs[index], 1U}));
    }
    wait([&] {
      for (const auto device : devices) {
        const auto state = plane->query_isis_update_instance(device, 0U);
        require(state && state->update_status == UpdateStatus::applied);
        if (state->retained_lsps != std::array<std::size_t, 2U>{3U, 3U} ||
            state->local_root_links[0U] != std::optional{LspLinkCounts{1U, 1U}} ||
            state->local_root_links[1U] != std::optional{LspLinkCounts{1U, 1U}}) return false;
      }
      return true;
    });
    packet::isis::LspId first_pseudonode{1U, 2U, 3U, 4U, 5U, 2U, 1U, 0U};
    packet::isis::LspId second_pseudonode{1U, 2U, 3U, 4U, 5U, 1U, 1U, 0U};
    const auto first = plane->query_isis_lsp(devices[0U], 0U, 0U, first_pseudonode);
    const auto level_two = plane->query_isis_lsp(devices[1U], 0U, 1U, second_pseudonode);
    require(first && level_two && first->selected_lsp && level_two->selected_lsp &&
        first->selected_lsp_links == std::optional{LspLinkCounts{2U, 2U}} &&
        level_two->selected_lsp_links == std::optional{LspLinkCounts{2U, 2U}});
    const auto first_sequence = first->selected_lsp->sequence;
    // Replacing root prefix/attribute intent must retain learned LAN edges.
    const auto &base_root = automatic_programs[0U].origination->content.records[0U];
    auto edited_options = base_root.options;
    edited_options.insert(edited_options.end(), {250U, 1U, 7U});
    const auto root_before_edit = plane->query_isis_update_instance(devices[0U], 0U)->local_root_sequences[0U];
    const auto edited_root = plane->replace_isis_local_lsp(devices[0U], 0U,
        {0U, base_root.id, base_root.flags, edited_options});
    require(edited_root && edited_root->error == ControlError::none &&
        edited_root->local_content_result == LocalContentResult::changed);
    wait([&] {
      const auto state = plane->query_isis_update_instance(devices[0U], 0U);
      require(state && state->update_status == UpdateStatus::applied);
      return state->local_root_sequences[0U] > root_before_edit &&
          state->local_root_links[0U] == std::optional{LspLinkCounts{1U, 1U}};
    });
    programs[1U].circuit.identity.configuration_generation = 12U;
    programs[1U].circuit.broadcast->levels[0U]->local.priority = 0U;
    require(plane->replace_isis_generation(devices[1U], std::span{&programs[1U], 1U}));
    wait([&] {
      const auto old = plane->query_isis_lsp(devices[0U], 0U, 0U, first_pseudonode);
      const auto current = plane->query_isis_lsp(devices[1U], 0U, 0U, second_pseudonode);
      return old && current && old->selected_lsp && current->selected_lsp &&
          !old->selected_lsp->remaining_seconds && current->selected_lsp->remaining_seconds &&
          current->selected_lsp_links == std::optional{LspLinkCounts{2U, 2U}};
    });
    programs[1U].circuit.identity.configuration_generation = 13U;
    programs[1U].circuit.broadcast->levels[0U]->local.priority = 127U;
    require(plane->replace_isis_generation(devices[1U], std::span{&programs[1U], 1U}));
    wait([&] {
      const auto renewed = plane->query_isis_lsp(devices[0U], 0U, 0U, first_pseudonode);
      const auto retired = plane->query_isis_lsp(devices[1U], 0U, 0U, second_pseudonode);
      return renewed && retired && renewed->selected_lsp && retired->selected_lsp &&
          renewed->selected_lsp->remaining_seconds && renewed->selected_lsp->sequence > first_sequence &&
          renewed->selected_lsp_links == std::optional{LspLinkCounts{2U, 2U}} && !retired->selected_lsp->remaining_seconds;
    });
    // The former DIS update owner is unavailable and cannot send its own
    // withdrawal. Its Hello owner continues, so the new DIS must purge the
    // cached foreign pseudonode itself after the priority transition.
    require(plane->remove_isis_update_instance(devices[1U], 0U));
    const auto abandoned = plane->query_isis_lsp(devices[0U], 0U, 0U, first_pseudonode);
    require(abandoned && abandoned->selected_lsp && abandoned->selected_lsp->remaining_seconds);
    programs[1U].circuit.identity.configuration_generation = 14U;
    programs[1U].circuit.broadcast->levels[0U]->local.priority = 0U;
    require(plane->replace_isis_generation(devices[1U], std::span{&programs[1U], 1U}));
    wait([&] {
      const auto old = plane->query_isis_lsp(devices[0U], 0U, 0U, first_pseudonode);
      const auto current = plane->query_isis_lsp(devices[0U], 0U, 0U, second_pseudonode);
      return old && current && old->selected_lsp && current->selected_lsp &&
          !old->selected_lsp->remaining_seconds && current->selected_lsp->remaining_seconds &&
          old->selected_lsp->sequence == abandoned->selected_lsp->sequence &&
          old->selected_lsp->checksum == abandoned->selected_lsp->checksum;
    });
    for (const auto device : devices) require(plane->replace_isis_generation(device, {}));
    require(plane->remove_isis_update_instance(devices[0U], 0U));
    for (std::size_t index{}; index < devices.size(); ++index) {
      auto &routed = automatic_programs[index];
      std::array<std::uint8_t, 256U> prefix_storage{};
      packet::isis::TlvWriter writer(prefix_storage);
      const std::array<std::uint8_t, 4U> area{3U, 0x49U, 0U, 1U};
      const std::array protocols{packet::isis::ipv4_nlpid, packet::isis::ipv6_nlpid};
      require(writer.append(1U, area) && writer.append(129U, protocols) &&
          packet::isis::encode_extended_prefix(writer,
              {.prefix = *ip::parse_ip_prefix(index ? "198.51.100.2/32" : "192.0.2.1/32"), .metric = 5U, .sub_tlvs = {}}) &&
          packet::isis::encode_extended_prefix(writer,
              {.prefix = *ip::parse_ip_prefix(index ? "2001:db8:22::2/128" : "2001:db8:12::1/128"), .metric = 7U, .sub_tlvs = {}}));
      for (auto &record : routed.origination->content.records)
        record.options.assign(writer.bytes().begin(), writer.bytes().end());
      for (std::size_t family{}; family < routed.routing.size(); ++family) {
        routed.routing[family].emplace();
        routed.routing[family]->calculation = {16U, 32U, 128U,
            family ? packet::isis::ipv6_nlpid : packet::isis::ipv4_nlpid, PrefixCollectionBudget{8U, 128U}};
        routed.routing[family]->preferences = {P2pRouteFamilyProgram::Preference{15U, 160U},
            P2pRouteFamilyProgram::Preference{18U, 165U}};
      }
      programs[index].circuit.identity.configuration_generation = 15U;
      require(plane->add_isis_update_instance(devices[index], 0U, routed) &&
          plane->replace_isis_generation(devices[index], std::span{&programs[index], 1U}));
    }
    wait([&] {
      for (const auto device : devices) {
        const auto state = plane->query_isis_update_instance(device, 0U);
        const auto snapshot = heap_router_checkpoint(*plane, device, RuntimeClock::now());
        require(state && state->update_status == UpdateStatus::applied && snapshot);
        if (state->route_install_status != routing::RouteInstallStatus::installed ||
            snapshot->fib.count != 2U || snapshot->ipv6_fib.count != 2U ||
            std::none_of(snapshot->fib.routes.begin(), snapshot->fib.routes.begin() + snapshot->fib.count,
                [](const auto &route) { return route.source == lab::routing::RouteSource::isis && route.metric == 15U &&
                    route.interface_generation == 15U; }) ||
            std::none_of(snapshot->ipv6_fib.routes.begin(), snapshot->ipv6_fib.routes.begin() + snapshot->ipv6_fib.count,
                [](const auto &route) { return route.source == lab::routing::RouteSource::isis && route.metric == 17U &&
                    route.interface_generation == 15U && route.interface_id == interface; })) return false;
      }
      return true;
    });
    const auto routed_checkpoint = plane->checkpoint();
    require(routed_checkpoint && routed_checkpoint->isis && routed_checkpoint->isis->installed.size() == 2U);
    require(plane->restore(*routed_checkpoint));
    restore_base();
    for (const auto device : devices) {
      const auto restored_routes = heap_router_checkpoint(*plane, device, RuntimeClock::now());
      require(restored_routes && restored_routes->fib.count == 2U && restored_routes->ipv6_fib.count == 2U);
    }
    bool sent4{}, sent6{};
    const auto replies_by = RuntimeClock::now() + 5s;
    while (!sent4 || !sent6 || !plane->router_ping_reply(devices[0U], 771U) ||
        !plane->router_ipv6_ping_reply(devices[0U], 772U)) {
      plane->pump();
      if (!sent4) sent4 = plane->start_router_ping(devices[0U], 0xc6336402U, 771U, RuntimeClock::now());
      if (!sent6) sent6 = plane->start_router_ipv6_ping(devices[0U], *ip::parse_ipv6("2001:db8:22::2"), 772U, RuntimeClock::now());
      require(RuntimeClock::now() < replies_by);
    }
    for (const auto device : devices) require(plane->remove_isis_update_instance(device, 0U));
    const auto withdrawn_by = RuntimeClock::now() + 5s;
    for (const auto device : devices) {
      while (!plane->replace_isis_generation(device, {})) {
        plane->pump(); require(RuntimeClock::now() < withdrawn_by);
      }
      const auto snapshot = heap_router_checkpoint(*plane, device, RuntimeClock::now());
      require(snapshot && snapshot->fib.count == 1U && snapshot->ipv6_fib.count == 1U &&
          snapshot->fib.routes[0U].source == lab::routing::RouteSource::connected &&
          snapshot->ipv6_fib.routes[0U].source == lab::routing::RouteSource::connected);
    }
    require(plane->checkpoint().has_value() && plane->restore(*initial));
  }
}
