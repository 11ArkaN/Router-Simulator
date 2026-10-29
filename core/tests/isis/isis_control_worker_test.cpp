// The actual IS-IS pthread exchanges encoded Hellos through SPSC channels and
// the physical fabric. The test thread owns forwarding and link state only.
// Generation rejection and removal are observed through immutable results.

#include "router/isis_control_worker.hpp"
#include "router/multi_device_fabric.hpp"

#include <memory>
#include <stdexcept>

namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS control worker transport invariant failed");
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
