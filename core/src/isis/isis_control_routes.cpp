// The IS-IS pthread builds complete local route generations from its own
// accepted Hellos and revision-fenced decisions. The network owner alone installs
// them and returns an explicit receipt. No remote router state is accessible.

// Source: project.isis.route_publication

#include "router/isis_control_worker.hpp"
#include "router/isis_rib_input.hpp"
#include "router/isis_attached_default.hpp"

#include <algorithm>
#include <limits>

namespace router::isis {

ControlWorker::InterlevelOwners ControlWorker::interlevel_owners(const DeviceState &device) noexcept {
  InterlevelOwners result{};
  for (std::size_t index{}; index < device.instances.size(); ++index) {
    const auto &instance = device.instances[index];
    if (!instance) continue;
    auto &owner = result[index];
    owner.admission = instance->admission_epoch; owner.entity = instance->entity_epoch;
    if (!device.active || !instance->admin_enabled || !instance->process ||
        instance->status != UpdateStatus::applied || !instance->configuration.origination ||
        !instance->configuration.origination->automatic_area_attachment) continue;
    for (std::size_t family{}; family < instance->configuration.routing.size(); ++family)
      if (instance->configuration.routing[family]) owner.families |= static_cast<std::uint8_t>(1U << family);
  }
  return result;
}
void ControlWorker::reconcile_interlevel(DeviceState &device) noexcept {
  if (!device.interlevel) return;
  const auto owners = interlevel_owners(device);
  const auto result = device.interlevel->reconcile(owners);
  if (result.status == InterlevelApplyStatus::invalid) std::terminate();
  for (std::size_t index{}; index < device.instances.size(); ++index)
    if (result.dirty[index] && device.instances[index]) device.instances[index]->local_roots_dirty[1U] = true;
}
void ControlWorker::complete_selections() noexcept {
  // At most the channel's two credits per turn, even if the producer refills
  // returned slots concurrently. Protocol deadlines retain bounded service.
  for (std::size_t budget{}; budget < 2U; ++budget) {
    const auto lease = channels_.selections->receive();
    if (!lease) break;
    const auto &selection = *lease->value;
    if (selection.identity.device.index < devices_.size()) {
      auto &device = devices_[selection.identity.device.index];
      if (device.interlevel && device.handle == selection.identity.device) {
        const auto owners = interlevel_owners(device);
        const auto result = device.interlevel->accept(selection,device.configuration_epoch,owners);
        for (std::size_t index{}; index < device.instances.size(); ++index)
          if (result.dirty[index] && device.instances[index]) device.instances[index]->local_roots_dirty[1U] = true;
      }
    }
    if (!channels_.selections->release(lease->handle)) std::terminate();
    if (channels_.route_wakeup) channels_.route_wakeup(channels_.route_wakeup_context);
  }
}

void ControlWorker::complete_routes(RuntimeClock::time_point now) noexcept {
  while (const auto receipt = channels_.routes->try_completion()) {
    if (receipt->device.index >= devices_.size()) continue;
    auto &device = devices_[receipt->device.index];
    if (device.handle != receipt->device || device.route_pending != receipt->generation) continue;
    if (device.interlevel) {
      const bool accepted = receipt->status == ::router::routing::RouteInstallStatus::installed
          ? device.interlevel->confirm_routes(receipt->generation) : device.interlevel->refuse_routes(receipt->generation);
      if (!accepted) std::terminate();
    }
    device.route_pending = 0U;
    device.route_status = receipt->status;
    if (receipt->status == ::router::routing::RouteInstallStatus::installed) {
      device.route_installed = receipt->generation;
      device.installed_routes = device.pending_routes;
      device.route_retry_at = {};
    } else device.route_retry_at = now + device.route_retry;
  }
}

RuntimeClock::time_point ControlWorker::service_routes(DeviceState &device,
    RuntimeClock::time_point now) noexcept {
  using Status = ::router::routing::RouteInstallStatus;
  const auto never = RuntimeClock::time_point::max();
  if (!device.active || device.route_pending || (device.interlevel && !device.interlevel->can_publish_routes())) return never;
  reconcile_interlevel(device);
  RouteStamps current{};
  bool enabled{};
  auto retry = std::chrono::milliseconds::max();
  for (std::size_t index{}; index < device.instances.size(); ++index) {
    const auto &instance = device.instances[index];
    if (!instance || !instance->admin_enabled) continue;
    std::uint8_t families{}, ignored{};
    for (std::size_t family{}; family < instance->configuration.routing.size(); ++family)
      if (instance->configuration.routing[family]) {
        families |= static_cast<std::uint8_t>(1U << family);
        if (instance->configuration.routing[family]->ignore_attached_bit) ignored |= static_cast<std::uint8_t>(1U << family);
      }
    if (!families) continue;
    enabled = true;
    retry = std::min(retry, instance->configuration.origination->resource_retry);
    current[index] = {instance->process ? instance->process->maximum_synchronization_epoch() : device.update_fences[index],
        instance->decision_revisions, instance->status, families, ignored};
  }
  if (enabled) device.route_retry = retry;
  if ((!enabled && !device.route_generation) || current == device.installed_routes) return never;
  if (device.route_retry_at > now) return device.route_retry_at;
  const auto refuse = [&](Status status) {
    device.route_status = status;
    device.route_retry_at = now + device.route_retry;
    return device.route_retry_at;
  };
  // Every enabled family and level belongs to this exact local revision. A
  // failed calculation preserves the installed generation and retries only
  // at the explicitly configured emulator resource-recovery period.
  for (auto &instance : device.instances) if (instance && instance->admin_enabled && instance->status == UpdateStatus::applied) {
    for (auto &family : instance->route_families)
      for (std::size_t level{}; level < family.decisions.size(); ++level) {
        if (!family.decisions[level]) continue;
        if (family.consumed[level] != instance->decision_revisions[level]) return instance->decision_deadline(now);
        if (family.status[level] != DecisionStatus::applied) {
          if (device.route_status == Status::selection_failed && instance->decision_revisions[level]) {
            family.consumed[level] = 0U;
            device.route_status = Status::pending;
            return now;
          }
          return refuse(Status::selection_failed);
        }
      }
  }
  if (device.route_generation == std::numeric_limits<std::uint64_t>::max()) {
    device.route_status = Status::stale;
    return never;
  }
  const auto lease = channels_.routes->try_acquire();
  // A completion notifies this owner; a full ring must not busy-spin.
  if (!lease) return never;
  auto &output = *lease->generation;
  output.device = device.handle;
  output.generation = device.route_generation + 1U;
  output.ipv4_count = output.ipv6_count = 0U;
  if (device.interlevel && !device.interlevel->begin_routes(output.generation)) std::terminate();
  auto *templates = device.interlevel ? device.interlevel->building_templates() : nullptr;
  Status failure = Status::pending;
  for (std::size_t index{}; index < device.instances.size() && failure == Status::pending; ++index) {
    const auto &instance = device.instances[index];
    if (!instance || !instance->admin_enabled || instance->status != UpdateStatus::applied) continue;
    for (std::size_t family{}; family < instance->configuration.routing.size() && failure == Status::pending; ++family) {
      const auto &program = instance->configuration.routing[family];
      if (!program) continue;
      for (std::size_t level{}; level < 2U && failure == Status::pending; ++level) {
        const auto &decision = instance->route_families[family].decisions[level];
        if (!decision) continue;
        const auto &bindings = instance->route_families[family].bindings[level];
        std::size_t last_advertisement = std::numeric_limits<std::size_t>::max();
        auto template_index = InterlevelTemplates::no_template;
        const auto append_mapped = [&](const PrefixRouteCandidate &candidate, std::uint32_t mapped_template) {
          if (templates && templates->map_candidate(family,mapped_template) != InterlevelTemplateStatus::applied) {
            failure = Status::capacity; return false;
          }
          const auto preference = candidate.external ? program->preferences[level].external : program->preferences[level].internal;
          if (family) {
            if (output.ipv6_count == output.ipv6.size()) { failure = Status::capacity; return false; }
            const auto mapped = make_ipv6_rib_input(candidate, static_cast<std::uint8_t>(index), preference);
            if (!mapped) { failure = Status::invalid; return false; }
            output.ipv6[output.ipv6_count++] = *mapped;
          } else {
            if (output.ipv4_count == output.ipv4.size()) { failure = Status::capacity; return false; }
            const auto mapped = make_ipv4_rib_input(candidate, static_cast<std::uint8_t>(index), preference);
            if (!mapped) { failure = Status::invalid; return false; }
            output.ipv4[output.ipv4_count++] = *mapped;
          }
          return true;
        };
        const auto append = [&](std::size_t, const PrefixRouteCandidate &candidate, std::size_t advertisement) {
          if (templates && advertisement != last_advertisement) {
            template_index = InterlevelTemplates::no_template;
            if (!level && instance->configuration.origination->automatic_area_attachment) {
              const auto copied = templates->append(decision->prefixes()[advertisement],candidate.distance,
                  {static_cast<std::uint8_t>(index),instance->admission_epoch,instance->entity_epoch},
                  decision->prefix_attributes(advertisement));
              if (copied.status == InterlevelTemplateStatus::invalid || copied.status == InterlevelTemplateStatus::capacity) {
                failure = copied.status == InterlevelTemplateStatus::capacity ? Status::capacity : Status::invalid;
                return false;
              }
              template_index = copied.index;
            }
            last_advertisement = advertisement;
          }
          return append_mapped(candidate,template_index);
        };
        const auto collected = visit_prefix_routes(*decision, std::span{bindings}, append);
        if (collected.status != PrefixRoutesStatus::applied && failure == Status::pending)
          failure = collected.status == PrefixRoutesStatus::capacity ? Status::capacity : Status::invalid;
        if (!level && failure == Status::pending) {
          const auto attached = visit_attached_default_routes(instance->process->level(0U)->database().database(),
              *decision, std::span{bindings}, {family ? ip::AddressFamily::ipv6 : ip::AddressFamily::ipv4,
                  0U, program->ignore_attached_bit}, now,
              [&](std::size_t, const PrefixRouteCandidate &candidate) {
                return append_mapped(candidate,InterlevelTemplates::no_template);
              });
          if (attached.status != PrefixRoutesStatus::applied && failure == Status::pending)
            failure = attached.status == PrefixRoutesStatus::capacity ? Status::capacity : Status::invalid;
        }
      }
    }
  }
  if (failure != Status::pending) {
    if (device.interlevel && !device.interlevel->abort_build()) std::terminate();
    if (!channels_.routes->cancel(lease->handle)) std::terminate();
    return refuse(failure);
  }
  const auto generation = output.generation;
  if (device.interlevel && !device.interlevel->route_published(generation)) std::terminate();
  if (!channels_.routes->publish(lease->handle)) std::terminate();
  device.route_generation = generation;
  device.route_pending = generation;
  device.pending_routes = current;
  device.route_status = Status::pending;
  if (channels_.route_wakeup) channels_.route_wakeup(channels_.route_wakeup_context);
  return never;
}
} // namespace router::isis
