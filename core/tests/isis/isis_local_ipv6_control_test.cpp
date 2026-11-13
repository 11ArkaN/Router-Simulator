// A real IS-IS pthread composes address-gated roots and preserves them through
// protected joined checkpoints. The test owns channel consumer endpoints and
// inspects protocol values only under an acknowledged control barrier.
#include "router/isis_control_worker.hpp"
#include "router/isis_control_checkpoint.hpp"
#include "router/isis_checkpoint_codec.hpp"
#include "router/isis_local_prefix_catalog_program.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS IPv6 control root invariant at " + std::to_string(at.line()));
}
}
void isis_local_ipv6_control_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 1U);
  const CircuitIdentity identity{{0U, 1U}, 70001U, 9U, 0U, 0U};
  std::uint64_t next{};
  const auto send = [&](ControlCommand command) {
    command.id = ++next;
    const auto until = RuntimeClock::now() + 3s;
    while (!worker->submit(std::move(command))) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == next && result.thread_identity); return result;
  };
  ControlCommand command; command.identity = identity; command.kind = ControlCommandKind::register_device;
  require(send(command).error == ControlError::none);
  InstanceIntent intent; intent.admin_enabled = true; intent.ipv4_routing = false;
  intent.ipv6_routing = ConfiguredIpv6Routing::native; intent.levels = ConfiguredLevels::level2;
  intent.level[1U].wide_metrics_only = true;
  InterfaceIntent attached; attached.name = "passive"; attached.passive = true; intent.interfaces.push_back(attached);
  const auto address = *ip::parse_ipv6("2001:db8:12::1");
  const std::array prefix{RootPrefix{*ip::parse_ip_prefix("2001:db8:12::/64"), 20U, {}}};
  const std::array sources{LocalPrefixSource{"passive", {std::span<const RootPrefix>{}, prefix}, true, false}};
  const std::array bindings{LocalPrefixInterface{identity.interface_id, std::uint16_t{0U}, true}};
  auto prefixes = prepare_local_prefix_catalog(intent, sources, bindings, {1U, 1U});
  require(prefixes.program.has_value());
  const std::array candidates{LocalIpv6Address{identity.interface_id, std::uint16_t{0U}, address, 64U, true}};
  auto addresses = prepare_local_ipv6_address_catalog(candidates, 1U); require(addresses.has_value());
  UpdateInstanceProgram program; program.local = {1U, 2U, 3U, 4U, 5U, 6U};
  program.maximum_areas = 3U; program.maximum_circuits = 1U;
  program.levels[1U] = UpdateLevelConfiguration{{8U, 8192U}, 8U, 8U, 1492U, 1200U, 60s, 60s,
      false, false, false, PurgeRules::iso_10589};
  program.transmission = {1U, 1U, 10U, 10ms, 4U, 1492U, 1U};
  program.origination.emplace();
  auto &origin = *program.origination; origin.resource_retry = 100ms; origin.content.random = 1U;
  origin.content.levels[1U] = LocalLspLevelProgram{1200U, 1492U, 10ms, 600s};
  packet::isis::LspId root{}; std::copy(program.local.begin(), program.local.end(), root.begin());
  origin.content.records.push_back({1U, root, 3U, {129U, 1U, packet::isis::ipv6_nlpid}, true});
  origin.prefixes = std::move(prefixes.program); origin.ipv6_addresses = std::move(addresses);
  command.kind = ControlCommandKind::add_update_instance; command.update = program;
  require(send(command).error == ControlError::none);
  command.update.reset(); command.kind = ControlCommandKind::query_update_instance;
  const auto wait_sequence = [&](std::uint32_t previous) {
    const auto until = RuntimeClock::now() + 3s;
    for (;;) {
      const auto result = send(command); require(result.error == ControlError::none);
      if (result.local_root_sequences[1U] > previous) return result.local_root_sequences[1U];
      require(RuntimeClock::now() < until); std::this_thread::yield();
    }
  };
  const auto first_sequence = wait_sequence(0U);
  ControlCommand begin; begin.kind = ControlCommandKind::begin_checkpoint_barrier;
  const auto barrier = send(begin); require(barrier.error == ControlError::none);
  auto joined = std::make_unique<lab::IsisRuntimeCheckpoint>();
  ControlCommand capture; capture.kind = ControlCommandKind::capture_checkpoint;
  capture.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
  capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&joined->control);
  require(send(capture).error == ControlError::none);
  joined->ingress.push_back(channels->ingress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch));
  joined->egress.push_back(channels->egress[0U].checkpoint_quiescent(barrier.checkpoint_barrier_epoch));
  joined->routes = channels->routes->checkpoint_quiescent(barrier.checkpoint_barrier_epoch);
  require(lab::valid_isis_runtime_links(*joined));
  std::array<std::uint8_t, 32U> key{}, binding{}; key.fill(0x59U); binding.fill(0x97U);
  auto vault = vault::SecretVault::create(key, std::array<std::uint8_t, 3U>{'l', 'a', 'b'}, 1U);
  require(vault.has_value());
  const auto encoded = lab::isis_checkpoint::encode(*joined, *vault, binding); require(encoded.has_value());
  auto decoded = lab::isis_checkpoint::decode(*encoded, *vault, binding); require(decoded != nullptr);
  auto &image = decoded->control.devices.front().instances.front();
  require(image.configuration.origination->ipv6_addresses == program.origination->ipv6_addresses);
  bool metadata{}, reachable{};
  for (const auto &entry : image.local->entries) if (entry.content.active) {
    packet::isis::TlvCursor options(entry.content.options);
    while (const auto option = options.next()) { metadata = metadata || option->code == 232U; reachable = reachable || option->code == 236U; }
    require(options.valid());
  }
  require(metadata && reachable);
  ControlCommand restore; restore.kind = ControlCommandKind::prepare_checkpoint_restore;
  restore.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch;
  restore.checkpoint_source_epoch = decoded->control.barrier_epoch;
  restore.checkpoint_now_nanoseconds = barrier.checkpoint_anchor_nanoseconds;
  restore.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(&decoded->control);
  image.configuration.origination->ipv6_addresses->units.front().metadata[0U] = 0U;
  require(send(restore).error == ControlError::invalid_argument);
  image.configuration.origination->ipv6_addresses->units.front().metadata[0U] = 232U;
  require(send(restore).error == ControlError::none);
  restore.kind = ControlCommandKind::commit_checkpoint_restore; require(send(restore).error == ControlError::none);
  ControlCommand end; end.kind = ControlCommandKind::end_checkpoint_barrier;
  end.checkpoint_barrier_epoch = barrier.checkpoint_barrier_epoch; require(send(end).error == ControlError::none);
  ControlCommand carrier; carrier.kind = ControlCommandKind::set_local_port_carrier; carrier.identity = identity;
  carrier.carrier = false; require(send(carrier).error == ControlError::none);
  const auto withdrawn_sequence = wait_sequence(first_sequence);
  carrier.carrier = true; require(send(carrier).error == ControlError::none);
  const auto recovered_barrier = send(begin); require(recovered_barrier.error == ControlError::none);
  auto recovered = std::make_unique<ControlWorkerCheckpoint>();
  capture.checkpoint_barrier_epoch = recovered_barrier.checkpoint_barrier_epoch;
  capture.checkpoint_now_nanoseconds = recovered_barrier.checkpoint_anchor_nanoseconds;
  capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(recovered.get());
  require(send(capture).error == ControlError::none);
  const auto &recovered_instance = recovered->devices.front().instances.front();
  require(recovered_instance.configuration.origination->prefixes->interfaces.front().available &&
      !recovered_instance.configuration.origination->ipv6_addresses->units.front().source.preferred);
  for (const auto &entry : recovered_instance.local->entries) if (entry.content.active) {
    packet::isis::TlvCursor options(entry.content.options);
    while (const auto option = options.next()) require(option->code != 232U && option->code != 236U);
    require(options.valid());
  }
  end.checkpoint_barrier_epoch = recovered_barrier.checkpoint_barrier_epoch;
  require(send(end).error == ControlError::none);
  ControlCommand readiness; readiness.kind = ControlCommandKind::set_local_ipv6_readiness;
  readiness.identity = identity;
  readiness.local_ipv6_readiness = lab::Ipv6ReadinessChange{1U, identity.device, 9U,
      {identity.interface_id, 0U, address}, true};
  readiness.local_ipv6_readiness->version = 0U; require(send(readiness).error == ControlError::invalid_argument);
  readiness.local_ipv6_readiness->version = 1U;
  ++readiness.local_ipv6_readiness->source.interface_id; require(send(readiness).error == ControlError::not_found);
  --readiness.local_ipv6_readiness->source.interface_id;
  require(send(readiness).error == ControlError::none);
  const auto reassigned_sequence = wait_sequence(withdrawn_sequence);
  require(send(readiness).error == ControlError::none);
  require(send(command).local_root_sequences[1U] == reassigned_sequence);
}
