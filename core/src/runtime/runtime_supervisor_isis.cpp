// Serialized control transfers IS-IS generation ownership to the network
// pthread. Mutable protocol and forwarding state remain on their own owners.
#include "runtime_supervisor_internal.hpp"
#include <limits>
namespace router::lab {
std::shared_ptr<const isis::AdjacencyQuery> RuntimeSupervisor::isis_adjacencies(DeviceHandle device,
    std::uint8_t instance, std::uint32_t maximum_rows, std::uint32_t maximum_attribute_octets) noexcept {
  if (!devices_.get(device) || instance > device_catalog::isis_instance_last || !maximum_rows || !maximum_attribute_octets)
    return nullptr;
  auto &command = prepare(NetworkCommandKind::prepare_isis_adjacencies);
  command.device = device; command.isis_query = {instance, maximum_rows, maximum_attribute_octets};
  const auto result = dispatch(command);
  return result && result->success ? network_worker_->prepared_isis_adjacencies() : nullptr;
}
bool RuntimeSupervisor::admit_isis_generation(NetworkIsisGeneration &&generation) noexcept {
  if (!devices_.get(generation.device) || next_network_command_id_ == std::numeric_limits<std::uint64_t>::max()) return false;
  auto &command = prepare(NetworkCommandKind::admit_isis_generation);
  command.device = generation.device;
  command.id = next_network_command_id_++;
  if (!network_worker_->submit_isis_generation(command, std::move(generation))) return false;
  NetworkResult result;
  while (!network_worker_->read(result)) std::this_thread::yield();
  return result.version == network_plane_message_version && result.id == command.id &&
      result.kind == command.kind && result.success;
}
}
