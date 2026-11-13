// Two real control-owned routers exchange encoded L2 frames through a physical
// fabric. The test thread owns only transport and observes copied LSP headers;
// attachment never reads another router's configuration or runtime state.
#include "router/isis_control_worker.hpp"
#include "router/isis_instance_program.hpp"
#include "router/multi_device_fabric.hpp"
#include <memory>
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS area attachment owner invariant at " + std::to_string(where.line()));
}
}
void isis_area_attachment_control_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 4U);
  std::uint64_t serial{};
  const auto command = [&](ControlCommand value) {
    value.id = ++serial; const auto until = RuntimeClock::now() + 4s;
    while (!worker->submit(std::move(value))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == serial); return result;
  };
  const std::array<CircuitIdentity, 2U> identities{{{{0U, 1U}, 1U, 7U, 0U, 0U}, {{1U, 1U}, 2U, 7U, 0U, 0U}}};
  std::array<packet::isis::LspId, 2U> roots{};
  for (std::size_t index{}; index < identities.size(); ++index) {
    ControlCommand add; add.kind = ControlCommandKind::register_device; add.identity = identities[index];
    require(command(std::move(add)).error == ControlError::none);
    InstanceIntent intent; intent.admin_enabled = true;
    intent.system_id = packet::isis::SystemId{1U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(index + 1U)};
    std::copy(intent.system_id->begin(), intent.system_id->end(), roots[index].begin());
    intent.areas = {*parse_configured_area(index ? "49.0002" : "49.0001")};
    intent.suppress_attached_bit = index != 0U;
    for (auto &level : intent.level) { level.present = true; level.wide_metrics_only = true; }
    InterfaceIntent edge; edge.name = "edge"; edge.type = ConfiguredInterfaceType::point_to_point;
    edge.levels = ConfiguredLevels::level2; intent.interfaces.push_back(edge);
    const std::array interfaces{InstanceOriginInterface{"edge", identities[index].interface_id, {}, 1U, 0U, false}};
    const UpdateLevelConfiguration level{{16U, 32768U}, 16U, 128U, 1492U,
        1200U, 60s, 60s, false, false, false, PurgeRules::iso_10589};
    InstanceProgramContext context; context.maximum_areas = 3U; context.maximum_circuits = 1U;
    context.levels = {level, level}; context.fragments = {2U, 2U};
    context.transmission = {1U, 1U, 5U, 100ms, 10U, 1492U, 1U};
    context.minimum_generation_interval = 10ms; context.resource_retry = 100ms;
    context.random = index + 1U; context.interfaces = interfaces;
    context.hierarchy_decision = P2pDecisionProgram{8U, 32U, 64U, {}, {}};
    intent.spf_wait = {10U, 10U, 10U};
    auto prepared = prepare_instance_program(intent, context);
    require(prepared.status == InstanceProgramStatus::prepared);
    add = {}; add.kind = ControlCommandKind::add_update_instance; add.identity = identities[index];
    add.update = std::move(prepared.program);
    require(command(std::move(add)).error == ControlError::none);
    add = {}; add.kind = ControlCommandKind::add_p2p_circuit; add.identity = identities[index];
    auto &hello = add.configuration;
    hello.local = {*intent.system_id, static_cast<std::uint32_t>(index + 1U), static_cast<std::uint8_t>(index + 1U), Levels::level2, true};
    hello.mac = {2U, 0U, 0U, 0U, 0U, static_cast<std::uint8_t>(index + 1U)};
    hello.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
    hello.areas = intent.areas; hello.protocols = {packet::isis::ipv4_nlpid};
    hello.maximum_area_addresses = 3U; hello.holding_seconds = 3U; hello.hello_interval = 1s;
    hello.maximum_pdu_octets = 1492U; hello.peer_attribute_octets = 512U; add.random_state = index + 1U;
    require(command(std::move(add)).error == ControlError::none);
  }
  auto fabric = std::make_unique<lab::MultiDeviceFabric>(); const lab::LinkHandle link{0U, 1U};
  require(fabric->configure(link, {lab::node(identities[0U].device), 0U, 1U},
      {lab::node(identities[1U].device), 0U, 1U}, 1'000'000'000U, 100ns, true));
  struct Transport { ControlChannels &channels; ControlWorker &worker; const decltype(identities) &identities; } transport{*channels, *worker, identities};
  const auto pump = [&] {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const bool accepted = fabric->enqueue(link, static_cast<std::uint8_t>(frame->metadata.device.index), *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, frame->metadata, accepted)); worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&transport, +[](void *opaque, const lab::MultiDeviceFabric::Delivery &delivery) {
      auto &value = *static_cast<Transport *>(opaque); const auto &identity = value.identities[delivery.destination.node.index];
      require(value.channels.ingress[0U].try_send({identity.device, identity.interface_id, 0U, identity.configuration_generation}, delivery.frame));
      value.worker.notify();
    });
  };
  const auto query = [&](std::size_t index) {
    ControlCommand value; value.kind = ControlCommandKind::query_update_instance; value.identity = identities[index];
    value.selected_lsp = roots[index]; value.level = 0U; return command(std::move(value));
  };
  const auto until = RuntimeClock::now() + 5s;
  for (;;) {
    pump(); const auto first = query(0U); const auto second = query(1U);
    require(first.update_status == UpdateStatus::applied && second.update_status == UpdateStatus::applied);
    if (first.selected_lsp && (first.selected_lsp->flags & 8U)) {
      require(second.selected_lsp && !(second.selected_lsp->flags & 8U)); break;
    }
    require(RuntimeClock::now() < until); std::this_thread::yield();
  }
  for (const auto &identity : identities) {
    ControlCommand down; down.kind = ControlCommandKind::set_circuit_carrier; down.identity = identity; down.carrier = false;
    require(command(std::move(down)).error == ControlError::none);
  }
  const auto withdrawn = RuntimeClock::now() + 3s;
  for (;;) {
    pump(); const auto first = query(0U);
    if (first.selected_lsp && !(first.selected_lsp->flags & 8U)) break;
    require(RuntimeClock::now() < withdrawn); std::this_thread::yield();
  }
}
