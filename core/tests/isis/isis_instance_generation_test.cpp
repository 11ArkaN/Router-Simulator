// Real control-owner transactions keep new databases and circuits invisible
// until commit. Cancellation and invalid siblings must preserve live owners.
#include "router/isis_control_worker.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_interface_program.hpp"
#include "router/isis_root_content.hpp"
#include "router/network_plane.hpp"
#include <memory>
#include <stdexcept>
#include <source_location>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS instance generation invariant at " + std::to_string(location.line()));
}
UpdateInstanceProgram instance() {
  const UpdateLevelConfiguration level{{8U, 8192U}, 8U, 16U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  UpdateInstanceProgram result{{1U, 2U, 3U, 4U, 5U, 6U}, 3U, {level, std::nullopt}, 2U,
      {1U, 1U, 10U, 1s, 10U, 1492U, 1U}};
  result.origination.emplace();
  result.origination->resource_retry = 100ms;
  auto &content = result.origination->content;
  content.random = 123U;
  content.levels[0U] = LocalLspLevelProgram{1200U, 1492U, 1s, 600s};
  const std::array areas{*parse_configured_area("49.0001")};
  RootContentInput root;
  root.local = result.local; root.flags = 1U; root.ipv4 = true; root.areas = areas;
  root.hostname = "R1";
  auto prepared = prepare_root_content(root, 1492U - packet::isis::lsp_header_octets, 8U);
  require(prepared.status == RootContentStatus::prepared);
  content.records = std::move(prepared.records);
  return result;
}
UpdateInstanceProgram restarted_instance() {
  auto program = instance();
  program.levels[0U]->maximum_age = 1100U;
  program.origination->content.levels[0U]->maximum_age = 1100U;
  program.origination->content.levels[0U]->refresh_interval = 550s;
  return program;
}
CircuitDefinition circuit() {
  InstanceIntent intent; intent.admin_enabled = true; intent.levels = ConfiguredLevels::level1;
  intent.system_id = instance().local; intent.areas = {*parse_configured_area("49.0001")};
  InterfaceIntent interface; interface.name = "edge"; interface.type = ConfiguredInterfaceType::point_to_point;
  const std::array<std::uint8_t, 1U> protocols{packet::isis::ipv4_nlpid};
  InterfaceProgramContext context;
  context.interface_name = interface.name; context.identity = {{0U, 1U}, 1U, 1U, 0U, 0U};
  context.mac = {2U, 0U, 0U, 0U, 0U, 1U};
  context.destinations = {{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U},
      {{{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U}, {1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}}}};
  context.extended_circuit = 1U; context.local_circuit = 1U; context.maximum_areas = 3U;
  context.maximum_pdu_octets = 1492U; context.peer_attribute_octets = 512U;
  context.random = 123U; context.protocols = protocols; context.operational = true;
  auto prepared = prepare_interface_program(intent, interface, context);
  require(prepared.status == InterfaceProgramStatus::prepared && prepared.circuit.has_value());
  return std::move(*prepared.circuit);
}
}
void isis_instance_generation_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 8U);
  std::uint64_t next{};
  const auto send = [&](ControlCommand value) {
    value.id = ++next;
    const auto deadline = RuntimeClock::now() + 3s;
    while (!worker->submit(std::move(value))) { require(RuntimeClock::now() < deadline); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < deadline); std::this_thread::yield(); }
    require(result.id == next);
    return result;
  };
  const auto scoped = [](ControlCommandKind kind) { ControlCommand command; command.kind = kind; command.identity.device = {0U, 1U}; return command; };
  require(send(scoped(ControlCommandKind::register_device)).error == ControlError::none);
  auto prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.new_instances.push_back({0U, instance()});
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::query_update_instance)).error == ControlError::not_found);
  auto query = scoped(ControlCommandKind::query_circuit); query.identity = circuit().identity;
  require(send(query).error == ControlError::not_found);
  require(send(scoped(ControlCommandKind::abort_generation)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::query_update_instance)).error == ControlError::not_found);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.new_instances.push_back({0U, instance()});
  prepare.new_instances.push_back({0U, instance()});
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  require(send(scoped(ControlCommandKind::query_update_instance)).error == ControlError::not_found);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.new_instances.push_back({0U, instance()});
  prepare.circuits.push_back(circuit());
  prepare.circuits.back().configuration.local.system[0U] = 9U;
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  require(send(scoped(ControlCommandKind::query_update_instance)).error == ControlError::not_found);
  prepare = scoped(ControlCommandKind::prepare_generation);
  auto refreshing = instance();
  refreshing.origination->content.levels[0U]->minimum_interval = 10ms;
  refreshing.origination->content.levels[0U]->refresh_interval = 200ms;
  prepare.new_instances.push_back({0U, std::move(refreshing)});
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::query_update_instance)).error == ControlError::none);
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.new_instances.push_back({0U, instance()});
  require(send(std::move(prepare)).error == ControlError::already_exists);
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.circuits.push_back(circuit());
  prepare.new_instances.push_back({1U, instance()});
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  query = scoped(ControlCommandKind::query_update_instance); query.identity.instance = 1U;
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {1U, 1U};
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U};
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {1U};
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(query).error == ControlError::none);
  require(send(scoped(ControlCommandKind::abort_generation)).error == ControlError::none);
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {1U};
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  require(send(query).error == ControlError::not_found);
  query = scoped(ControlCommandKind::query_update_instance);
  require(send(query).error == ControlError::none);
  query = scoped(ControlCommandKind::query_circuit); query.identity = circuit().identity;
  require(send(query).error == ControlError::none);
  const auto old_instance = send(scoped(ControlCommandKind::query_update_instance));
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.new_instances.push_back({0U, restarted_instance(), true});
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U};
  prepare.new_instances.push_back({0U, restarted_instance()});
  require(send(std::move(prepare)).error == ControlError::invalid_argument);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U}; prepare.new_instances.push_back({0U, restarted_instance(), true});
  prepare.circuits.push_back(circuit());
  require(send(std::move(prepare)).error == ControlError::stale_configuration);
  auto restarted_circuit = circuit(); restarted_circuit.identity.configuration_generation = 2U;
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U}; prepare.new_instances.push_back({0U, restarted_instance(), true});
  prepare.circuits.push_back(restarted_circuit);
  require(send(std::move(prepare)).error == ControlError::none);
  const auto leased_sequences = send(scoped(ControlCommandKind::query_update_instance)).local_root_sequences;
  std::this_thread::sleep_for(300ms);
  require(send(scoped(ControlCommandKind::query_update_instance)).local_root_sequences == leased_sequences);
  require(send(scoped(ControlCommandKind::abort_generation)).error == ControlError::none);
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U}; prepare.new_instances.push_back({0U, restarted_instance(), true});
  prepare.circuits.push_back(restarted_circuit);
  require(send(std::move(prepare)).error == ControlError::none);
  const auto replaced_sequence = send(scoped(ControlCommandKind::query_update_instance)).local_root_sequences[0U];
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  const auto restarted = send(scoped(ControlCommandKind::query_update_instance));
  require(restarted.error == ControlError::none && restarted.update_epoch > old_instance.update_epoch &&
      restarted.local_root_sequences[0U] == replaced_sequence + 1U);
  query.identity = restarted_circuit.identity;
  require(send(query).error == ControlError::none);
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {0U};
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(query).error == ControlError::none);
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  require(send(query).error == ControlError::not_found);
  worker->stop(); worker.reset();
  channels = std::make_unique<ControlChannels>();
  worker = std::make_unique<ControlWorker>(*channels, 1U, 8U);
  require(send(scoped(ControlCommandKind::register_device)).error == ControlError::none);
  for (std::size_t index{}; index <= device_catalog::isis_instance_last; ++index) {
    auto add = scoped(ControlCommandKind::add_update_instance);
    add.identity.instance = static_cast<std::uint8_t>(index); add.update = instance();
    require(send(std::move(add)).error == ControlError::none);
  }
  prepare = scoped(ControlCommandKind::prepare_generation);
  prepare.retired_instances = {device_catalog::isis_instance_last};
  prepare.new_instances.push_back({device_catalog::isis_instance_last, restarted_instance(), true});
  require(send(std::move(prepare)).error == ControlError::none);
  require(send(scoped(ControlCommandKind::commit_generation)).error == ControlError::none);
  query = scoped(ControlCommandKind::query_update_instance); query.identity.instance = device_catalog::isis_instance_last;
  require(send(query).local_root_sequences[0U] == 2U);
  require(send(scoped(ControlCommandKind::query_update_instance)).local_root_sequences[0U] == 1U);
  worker->stop(); worker.reset(); channels.reset();

  auto plane = std::make_unique<lab::NetworkPlane>();
  const lab::DeviceHandle device{0U, 1U};
  crypto::Sha256Digest secret{}; secret.fill(7U);
  require(plane->add_router(device, secret));
  lab::ForwardPort port;
  port.configured = port.operational = true;
  port.ordinal = 0U; port.mtu = 1514U; port.speed_mbps = 1000U;
  port.mac = circuit().configuration.mac;
  require(plane->configure_port(device, port));
  const std::array additions{NewUpdateInstance{0U, instance()}};
  std::array bindings{lab::IsisCircuitProgram{circuit(), {lab::node(device), 0U, 1U}}};
  bindings[0U].circuit.configuration.local.system[0U] = 9U;
  require(!plane->replace_isis_generation(device, bindings, additions));
  require(!plane->query_isis_update_instance(device, 0U));
  bindings[0U].circuit = circuit();
  require(plane->replace_isis_generation(device, bindings, additions));
  const auto installed = plane->query_isis_update_instance(device, 0U);
  require(installed && installed->error == ControlError::none && installed->local_root_sequences[0U] == 1U);
  require(plane->query_isis_circuit(bindings[0U].circuit.identity)->error == ControlError::none);
  bindings[0U].circuit.identity.configuration_generation = 2U;
  const std::array replacement{NewUpdateInstance{0U, restarted_instance(), true}};
  const std::array<std::uint8_t, 1U> retired{0U};
  require(plane->replace_isis_generation(device, bindings, replacement, retired));
  require(plane->query_isis_update_instance(device, 0U)->local_root_sequences[0U] == 2U &&
      plane->query_isis_circuit(bindings[0U].circuit.identity)->error == ControlError::none);
  const std::array empty_instance{NewUpdateInstance{1U, instance()}};
  require(plane->replace_isis_generation(device, {}, empty_instance));
  require(plane->query_isis_update_instance(device, 0U)->error == ControlError::none);
  require(plane->query_isis_update_instance(device, 1U)->error == ControlError::none);
  require(plane->remove_isis_update_instance(device, 0U));
  require(plane->query_isis_update_instance(device, 1U)->error == ControlError::none);
  require(plane->remove_isis_update_instance(device, 1U));
  require(plane->remove_router(device));
}
