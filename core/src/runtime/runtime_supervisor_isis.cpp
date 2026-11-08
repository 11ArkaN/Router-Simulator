// Serialized control transfers IS-IS generation ownership to the network
// pthread. Mutable protocol and forwarding state remain on their own owners.
#include "runtime_supervisor_internal.hpp"
#include <limits>
namespace router::lab {
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
