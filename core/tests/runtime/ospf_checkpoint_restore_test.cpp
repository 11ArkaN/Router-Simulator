// The existing OSPF owner participates in the network restore transaction with
// allocation before publication. Prepared state freezes protocol service; abort
// retains live owners and matching commit consumes the candidate exactly once.

#include "router/ospf_control_worker.hpp"

#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void ospf_checkpoint_restore_tests() {
  using namespace router;
  using namespace router::ospf;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("OSPF restore preparation invariant at " + std::to_string(where.line()));
  };
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U);
  std::uint64_t next_id{};
  const auto command = [&](ControlCommand value) {
    value.id = ++next_id;
    const auto until = RuntimeClock::now() + 3s;
    while (!worker->submit(value)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < until); std::this_thread::yield(); }
    require(result.id == value.id);
    return result;
  };
  ControlCommand add;
  add.kind = ControlCommandKind::add_process;
  add.process = {{0U, 1U}, 0U, packet::ospf::version_two, 0U};
  add.router_id = 0x0a000001U;
  add.maximum_interfaces = 1U;
  add.initial_dd_sequence = 7U;
  add.router_preference = 10U;
  add.external_preference = 150U;
  add.spf_initial_wait_milliseconds = add.lsa_initial_wait_milliseconds = 1U;
  add.spf_second_wait_milliseconds = add.lsa_second_wait_milliseconds = 2U;
  add.spf_maximum_wait_milliseconds = add.lsa_maximum_wait_milliseconds = 3U;
  require(command(add).success);
  ControlCommand add_interface;
  add_interface.kind = ControlCommandKind::add_interface;
  add_interface.process = add.process;
  add_interface.interface = {
      .protocol = {.router_id = add.router_id, .area_id = 0U, .interface_id = 7U, .network_mask = 0xffffffffU,
          .options = 2U, .hello_interval_seconds = 10U, .dead_interval_seconds = 40U, .interface_mtu = 1500U,
          .router_priority = 1U, .version = packet::ospf::version_two, .instance_id = 0U,
          .network_type = NetworkType::point_to_point, .passive = true, .enabled = true},
      .ipv4_source = {10U, 0U, 0U, 1U}, .source_mac = {2U, 0U, 0U, 0U, 0U, 1U},
      .physical_port_ordinal = no_physical_port, .metric = 0U,
      .retransmit_interval_seconds = 5U, .transmit_delay_seconds = 1U, .prefix_length = 32U};
  require(command(add_interface).success);
  ControlCommand ready_query;
  ready_query.kind = ControlCommandKind::query_process;
  ready_query.process = add.process;
  const auto ready_until = RuntimeClock::now() + 3s;
  for (;;) {
    const auto ready = command(ready_query);
    if (ready.present && ready.lsa_count && ready.route_status == RouteRecalculationStatus::succeeded) break;
    require(RuntimeClock::now() < ready_until);
    std::this_thread::yield();
  }

  auto source = std::make_unique<ControlWorkerCheckpoint>();
  ControlCommand capture;
  capture.kind = ControlCommandKind::checkpoint;
  capture.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(source.get());
  capture.operation_now_nanoseconds = RuntimeClock::now().time_since_epoch().count();
  require(command(capture).success && source->processes.size() == 1U);
  ControlCommand remove;
  remove.kind = ControlCommandKind::remove_process;
  remove.process = add.process;
  require(command(remove).success);
  ControlCommand query;
  query.kind = ControlCommandKind::query_process;
  query.process = add.process;
  require(command(query).success && !command(query).present);
  ControlCommand prepare;
  prepare.kind = ControlCommandKind::prepare_checkpoint_restore;
  prepare.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(source.get());
  prepare.operation_now_nanoseconds = RuntimeClock::now().time_since_epoch().count();
  require(!command(prepare).success);
  prepare.checkpoint_transaction = 41U;
  auto malformed = std::make_unique<ControlWorkerCheckpoint>(*source);
  malformed->processes[0U].definition.router_id = 0U;
  auto rejected = prepare;
  rejected.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(malformed.get());
  require(!command(rejected).success && !command(query).present);
  require(command(prepare).success);
  require(!command(prepare).success);
  require(!command(query).success && !command(add).success && !command(capture).success);
  auto packet = std::make_unique<packet::Frame>();
  packet->length = 60U;
  require(channels->ingress[0U].try_send({add.process.device, 7U, 0U}, *packet));
  worker->notify();
  const auto queued = channels->ingress[0U].checkpoint_quiescent(41U);
  require(queued.ready.size() == 1U);
  ControlCommand commit = prepare;
  commit.kind = ControlCommandKind::commit_checkpoint_restore;
  commit.checkpoint_transaction = 42U;
  require(!command(commit).success);
  ControlCommand abort = commit;
  abort.kind = ControlCommandKind::abort_checkpoint_restore;
  require(!command(abort).success);
  std::this_thread::sleep_for(25ms);
  require(channels->ingress[0U].checkpoint_quiescent(41U).ready == queued.ready);
  abort.checkpoint_transaction = 41U;
  require(command(abort).success && !command(abort).success);
  const auto until = RuntimeClock::now() + 3s;
  while (channels->ingress[0U].producer_available() != device_catalog::ospf_packet_ring_frames) {
    require(RuntimeClock::now() < until); std::this_thread::yield();
  }
  require(!command(query).present && source->processes.size() == 1U);
  prepare.checkpoint_transaction = 42U;
  prepare.operation_now_nanoseconds = RuntimeClock::now().time_since_epoch().count();
  require(command(prepare).success && command(commit).success && !command(commit).success);
  const auto restored = command(query);
  require(restored.success && restored.present && restored.router_id == add.router_id);
  // Existing synchronous callers keep their one-command restore behavior.
  auto legacy = prepare;
  legacy.kind = ControlCommandKind::restore_checkpoint;
  require(command(legacy).success && command(query).present);
  prepare.checkpoint_transaction = 43U;
  require(command(prepare).success);
  worker->stop();
  require(!worker->thread_id());
}
