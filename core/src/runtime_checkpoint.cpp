// Checkpoint orchestration at shard quiescence. The codec owns format details;
// Runtime only establishes barriers and republishes restored value programs.

#include "router/runtime.hpp"

#include "router/checkpoint.hpp"
#include "router/project_configuration.hpp"

namespace router {

std::span<const std::uint8_t> Runtime::encode_checkpoint_on_control() {
  const auto barrier =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::checkpoint_barrier});
  if (!barrier.success)
    return {};
  state_.operational.arp = {};
  for (const auto &entry : barrier.arp) {
    if (entry.valid) {
      state_.operational.arp[entry.port_index] = {.valid = true,
                                                  .address = entry.address,
                                                  .mac = entry.mac,
                                                  .port_index =
                                                      entry.port_index};
    }
  }
  prepared_checkpoint_ = checkpoint::encode(state_, session_, fib_generation_,
                                            std::chrono::steady_clock::now());
  return prepared_checkpoint_;
}

bool Runtime::decode_checkpoint_on_control(
    std::span<const std::uint8_t> bytes) {
  auto image = checkpoint::decode(bytes);
  if (!image)
    return false;
  const auto now = std::chrono::steady_clock::now();
  if (image->device.hardware.card.lifecycle ==
      EquipmentLifecycle::initializing) {
    image->device.hardware.card.deadline =
        now + std::chrono::nanoseconds(image->card_remaining_ns);
  }
  if (image->device.hardware.mda.lifecycle ==
      EquipmentLifecycle::initializing) {
    image->device.hardware.mda.deadline =
        now + std::chrono::nanoseconds(image->mda_remaining_ns);
  }

  const auto network = project::network_configuration(
      image->device.configuration.running, image->device.project);
  const auto configured =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::configure_network,
                      .network = network});
  if (!configured.success)
    return false;

  std::array<NetworkArpEntry, profile::port_count> restored{};
  for (std::size_t index = 0; index < restored.size(); ++index) {
    const auto &entry = image->device.operational.arp[index];
    restored[index] = {.valid = entry.valid,
                       .address = entry.address,
                       .mac = entry.mac,
                       .port_index = entry.port_index};
  }
  const auto adjacency =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::restore_adjacencies,
                      .restored_arp = restored});
  if (!adjacency.success)
    return false;

  state_ = image->device;
  session_ = image->session;
  fib_generation_ = image->fib_generation;
  const auto hardware_result = hardware::reconcile(
      state_.configuration.running, state_.hardware, state_.operational, now);
  hardware_deadline_ = hardware_result.next_deadline;
  // Force publication even for an empty table. The imported hardware may have
  // withdrawn every route while forwarding still owns the pre-import program.
  reconcile_fib(true);
  publish_telemetry();
  return true;
}

} // namespace router
