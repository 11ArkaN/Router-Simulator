// Checkpoint orchestration at shard quiescence. The codec owns format details;
// Runtime only establishes barriers and republishes restored value programs.

#include "router/runtime.hpp"

#include "router/checkpoint.hpp"
#include "router/project_configuration.hpp"

namespace router {

std::span<const std::uint8_t> Runtime::encode_checkpoint_on_control() {
  // The forwarding barrier returns adjacency after every earlier job. Control
  // then encodes one cross-owner consistent structural image.
  const auto barrier =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::checkpoint_barrier});
  if (!barrier.success)
    return {};
  state_.operational.arp = {};
  const auto projection_time = std::chrono::steady_clock::now();
  for (const auto &entry : barrier.arp) {
    if (entry.valid) {
      state_.operational.arp[entry.port_index] = {
          .valid = true,
          .address = entry.address,
          .mac = entry.mac,
          .port_index = entry.port_index,
          .expires_at =
              projection_time + std::chrono::seconds{entry.remaining_seconds}};
    }
  }
  prepared_checkpoint_ = checkpoint::encode(state_, session_, fib_generation_,
                                            std::chrono::steady_clock::now());
  return prepared_checkpoint_;
}

bool Runtime::decode_checkpoint_on_control(
    std::span<const std::uint8_t> bytes) {
  // Decode completes into private storage, so incompatible input cannot mutate
  // any live owner before the whole image is validated.
  const auto now = std::chrono::steady_clock::now();
  auto image = checkpoint::decode(bytes, now);
  if (!image)
    return false;
  // Remaining initialization durations are rebased to this process clock.
  // Absolute steady-clock timestamps are never portable across sessions.
  for (std::size_t card_index = 0;
       card_index < image->device.hardware.cards.size(); ++card_index) {
    auto &card = image->device.hardware.cards[card_index];
    if (card.equipment.lifecycle == EquipmentLifecycle::initializing) {
      card.equipment.deadline =
          now + std::chrono::nanoseconds(image->card_remaining_ns[card_index]);
    }
    for (std::size_t mda_index = 0; mda_index < card.mdas.size(); ++mda_index) {
      auto &mda = card.mdas[mda_index];
      const auto flat = card_index * profile::mda_slots_per_card + mda_index;
      if (mda.equipment.lifecycle == EquipmentLifecycle::initializing) {
        mda.equipment.deadline =
            now + std::chrono::nanoseconds(image->mda_remaining_ns[flat]);
      }
    }
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
  // Only completed adjacency values cross restore. Pending packets, pool
  // handles and request flags deliberately do not exist in the checkpoint.
  for (std::size_t index = 0; index < restored.size(); ++index) {
    const auto &entry = image->device.operational.arp[index];
    const auto remaining_seconds =
        entry.valid && entry.expires_at > now
            ? static_cast<std::uint32_t>(
                  std::chrono::duration_cast<std::chrono::seconds>(
                      entry.expires_at - now + std::chrono::milliseconds{999})
                      .count())
            : 0U;
    restored[index] = {.valid = entry.valid && remaining_seconds != 0,
                       .address = entry.address,
                       .mac = entry.mac,
                       .port_index = entry.port_index,
                       .remaining_seconds = remaining_seconds};
    if (entry.valid && remaining_seconds == 0)
      image->device.operational.arp[index] = {};
  }
  const auto adjacency =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::restore_adjacencies,
                      .restored_arp = restored});
  if (!adjacency.success)
    return false;

  state_ = image->device;
  // Publish control-owned aggregates only after forwarding accepted both the
  // topology generation and adjacency value projection.
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
