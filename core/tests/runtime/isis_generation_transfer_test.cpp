// The real network pthread consumes moved IS-IS generations. Version refusal,
// full backpressure and malformed commands must preserve credits and owners.
#include "router/network_plane_worker.hpp"
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <source_location>
namespace {
using namespace router;
using namespace router::lab;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) { if (!value) throw std::runtime_error("IS-IS generation transfer invariant at " + std::to_string(location.line())); }
NetworkIsisGeneration generation() {
  const isis::UpdateLevelConfiguration level{{8U, 8192U}, 8U, 16U, 1492U, 1200U, 60s, 60s,
      false, false, false, isis::PurgeRules::iso_10589};
  isis::UpdateInstanceProgram program{{1U, 2U, 3U, 4U, 5U, 6U}, 3U, {level, std::nullopt}, 2U,
      {1U, 1U, 10U, 1s, 10U, 1492U, 1U}};
  NetworkIsisGeneration result;
  result.device = {0U, 1U};
  result.new_instances.push_back({0U, std::move(program)});
  return result;
}
}
void isis_generation_transfer_tests() {
  auto channels = std::make_unique<NetworkPlaneChannels>();
  auto worker = std::make_unique<NetworkPlaneWorker>(*channels);
  auto command = std::make_unique<NetworkCommand>();
  command->kind = NetworkCommandKind::admit_isis_generation;
  command->device = {0U, 1U};
  command->version = network_plane_message_version - 1U;
  auto value = generation();
  require(!worker->submit_isis_generation(*command, std::move(value)) && value.new_instances.size() == 1U);
  command->version = network_plane_message_version;
  constexpr auto queued = std::min(device_catalog::isis_control_generation_slots, device_catalog::network_command_ring_entries - 1U);
  for (std::size_t index{}; index < queued; ++index) {
    command->id = index + 1U;
    auto pending = generation();
    require(worker->submit_isis_generation(*command, std::move(pending)));
  }
  command->id = queued + 1U;
  require(!worker->submit_isis_generation(*command, std::move(value)) && value.new_instances.size() == 1U);
  worker->start();
  const auto receive = [&](std::uint64_t id, bool success) {
    NetworkResult result;
    const auto deadline = NetworkPlane::Clock::now() + 5s;
    while (!worker->read(result)) { require(NetworkPlane::Clock::now() < deadline); std::this_thread::yield(); }
    require(result.version == network_plane_message_version && result.id == id && result.success == success);
  };
  for (std::size_t index{}; index < queued; ++index) receive(index + 1U, false);
  require(worker->submit_isis_generation(*command, std::move(value)));
  receive(command->id, false);
  command->kind = NetworkCommandKind::add_router;
  command->id++;
  command->router_transport_secret.fill(7U);
  require(worker->submit(*command)); receive(command->id, true);
  command->router_transport_secret.fill(0U);
  command->kind = NetworkCommandKind::admit_isis_generation;
  command->id++;
  value = generation();
  require(worker->submit_isis_generation(*command, std::move(value))); receive(command->id, true);
  // A fixed command alone has no owned payload and must fail explicitly.
  command->id++;
  require(worker->submit(*command)); receive(command->id, false);
  command->kind = NetworkCommandKind::prepare_checkpoint;
  command->id++;
  require(worker->submit(*command)); receive(command->id, true);
  const auto *checkpoint = worker->prepared_checkpoint();
  require(checkpoint && checkpoint->isis && checkpoint->isis->control.devices.size() == 1U &&
      checkpoint->isis->control.devices[0U].instances.size() == 1U &&
      checkpoint->isis->control.devices[0U].instances[0U].instance == 0U);
  command->kind = NetworkCommandKind::admit_isis_generation;
  command->id++;
  NetworkIsisGeneration retirement;
  retirement.device = command->device;
  retirement.retired_instances = {0U};
  require(worker->submit_isis_generation(*command, std::move(retirement))); receive(command->id, true);
  command->kind = NetworkCommandKind::prepare_checkpoint;
  command->id++;
  require(worker->submit(*command)); receive(command->id, true);
  checkpoint = worker->prepared_checkpoint();
  require(checkpoint && (!checkpoint->isis || std::all_of(checkpoint->isis->control.devices.begin(),
      checkpoint->isis->control.devices.end(), [](const auto &device) { return device.instances.empty(); })));
}
