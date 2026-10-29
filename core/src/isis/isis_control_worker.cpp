// Control command ownership, circuit timers and encoded frame handoff for the
// dedicated IS-IS pthread. No topology-editor or other router state is read.
// Device and configuration generations guard every ingress and completion.

#include "router/isis_control_worker.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>

namespace router::isis {
namespace {
bool same_circuit(const CircuitIdentity &left, const CircuitIdentity &right) noexcept {
  return left.device == right.device && left.interface_id == right.interface_id && left.instance == right.instance;
}
}

ControlWorker::ControlWorker(ControlChannels &channels, std::size_t forwarding_shards,
    std::size_t maximum_circuits)
    : channels_(channels), forwarding_shards_(forwarding_shards), maximum_circuits_(maximum_circuits) {
  if (!forwarding_shards || forwarding_shards > channels_.ingress.size() || !maximum_circuits)
    throw std::invalid_argument("Invalid IS-IS control worker resources");
  thread_ = std::thread([this] { run(); });
}

ControlWorker::~ControlWorker() {
  stop_.store(true, std::memory_order_release);
  notify();
  if (thread_.joinable()) thread_.join();
}

bool ControlWorker::submit(ControlCommand &&command) noexcept {
  const auto lease = commands_.acquire();
  if (!lease) return false;
  *lease->value = std::move(command);
  if (!commands_.publish(lease->handle)) {
    command = std::move(*lease->value);
    static_cast<void>(commands_.cancel(lease->handle));
    return false;
  }
  notify();
  return true;
}

bool ControlWorker::read(ControlResult &result) noexcept {
  const bool consumed = results_.try_pop(result);
  if (consumed) notify();
  return consumed;
}

void ControlWorker::notify() noexcept {
  work_.store(true, std::memory_order_release);
  { std::lock_guard lock(wait_mutex_); }
  wait_condition_.notify_one();
}

void ControlWorker::event(void *context, const P2pCircuitEvent &value) noexcept {
  auto &owned = *static_cast<OwnedCircuit *>(context);
  if (value.transition.forwarding_readiness_changed && value.after.iso_up) ++owned.counters.adjacency_up;
  if (value.transition.outcome == P2pOutcome::down) ++owned.counters.adjacency_down;
}

ControlResult ControlWorker::apply(ControlCommand &command) noexcept {
  ControlResult result;
  result.id = command.id;
  result.thread_identity = identity_.load(std::memory_order_relaxed);
  result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
  if (command.kind == ControlCommandKind::shutdown) {
    stop_.store(true, std::memory_order_release);
    return result;
  }
  if (command.kind == ControlCommandKind::query_worker) return result;
  const auto handle = command.identity.device;
  if (!handle.generation || handle.index >= devices_.size()) { result.error = ControlError::invalid_argument; return result; }
  auto &device = devices_[handle.index];
  if (command.kind == ControlCommandKind::register_device) {
    if (device.active) result.error = device.handle == handle ? ControlError::already_exists : ControlError::stale_device;
    else { device.handle = handle; device.active = true; }
    return result;
  }
  if (!device.active || device.handle != handle) { result.error = ControlError::stale_device; return result; }
  if (command.kind == ControlCommandKind::remove_device) {
    for (auto &owned : device.circuits) static_cast<void>(owned.circuit.down(&owned, event));
    active_circuits_ -= device.circuits.size();
    device.circuits.clear();
    device.active = false;
    result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    return result;
  }
  auto found = std::find_if(device.circuits.begin(), device.circuits.end(),
      [&](const auto &owned) { return same_circuit(owned.identity, command.identity); });
  if (command.kind == ControlCommandKind::add_p2p_circuit) {
    if (found != device.circuits.end()) result.error = ControlError::already_exists;
    else if (!command.identity.interface_id || !command.identity.configuration_generation ||
        command.identity.instance > device_catalog::isis_instance_last ||
        command.identity.physical_port_ordinal >= device_catalog::maximum_ports_per_router)
      result.error = ControlError::invalid_argument;
    else if (command.configuration.receive_authentication || command.configuration.transmit_authentication)
      result.error = ControlError::unsupported_authentication;
    else if (std::any_of(device.circuits.begin(), device.circuits.end(), [&](const auto &other) {
      return other.identity.interface_id == command.identity.interface_id &&
          (other.identity.configuration_generation != command.identity.configuration_generation ||
           (other.wire_instance == command.configuration.wire_instance &&
            other.destination == command.configuration.hello_destination));
    })) result.error = ControlError::already_exists;
    else if (active_circuits_ >= maximum_circuits_) result.error = ControlError::capacity;
    else try {
      device.circuits.emplace_back(command, PointToPointCircuit::Clock::now());
      ++active_circuits_;
      result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    } catch (const std::bad_alloc &) { result.error = ControlError::capacity; }
      catch (const std::exception &) { result.error = ControlError::construction_failed; }
    return result;
  }
  if (found == device.circuits.end()) { result.error = ControlError::not_found; return result; }
  if (found->identity.configuration_generation != command.identity.configuration_generation) {
    result.error = ControlError::stale_configuration;
    return result;
  }
  if (command.kind == ControlCommandKind::remove_circuit) {
    static_cast<void>(found->circuit.down(&*found, event));
    device.circuits.erase(found);
    --active_circuits_;
    result.active_circuits = static_cast<std::uint32_t>(active_circuits_);
    return result;
  }
  if (command.kind != ControlCommandKind::query_circuit) { result.error = ControlError::invalid_argument; return result; }
  result.adjacency = found->circuit.adjacency();
  result.counters = found->counters;
  result.hello_pending = found->circuit.hello_pending();
  const auto holding = found->circuit.holding_deadline();
  if (holding) result.holding_deadline_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(holding->time_since_epoch()).count();
  return result;
}

void ControlWorker::receive(
    const protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::Borrowed &packet,
    PointToPointCircuit::Clock::time_point now) noexcept {
  const auto handle = packet.metadata.device;
  if (handle.index >= devices_.size()) return;
  auto &device = devices_[handle.index];
  if (!device.active || device.handle != handle) return;
  packet::isis::EthernetDecodeError decode{};
  const auto wire = packet::isis::parse_ethernet_pdu(packet.frame->view(), decode);
  if (!wire) return;
  for (auto &owned : device.circuits) {
    if (owned.identity.interface_id != packet.metadata.interface_id ||
        owned.identity.physical_port_ordinal != packet.metadata.physical_port_ordinal) continue;
    packet::isis::InstanceError error{};
    const auto selection = packet::isis::select_instance(wire->pdu, owned.format, owned.physical_point_to_point, error);
    if (wire->ethernet.destination != owned.destination || !selection || selection->instance != owned.wire_instance) continue;
    if (owned.identity.configuration_generation != packet.metadata.configuration_generation) {
      ++owned.counters.stale_ingress;
      continue;
    }
    const auto received = owned.circuit.receive(*packet.frame, std::nullopt, now, &owned, event);
    if (received == CircuitReceive::instance) continue;
    ++owned.counters.received;
    if (received != CircuitReceive::accepted) ++owned.counters.discarded;
  }
}

void ControlWorker::run() noexcept {
  const auto hash = static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));
  identity_.store(hash ? hash : 1U, std::memory_order_release);
  std::optional<ControlResult> pending_result;
  while (!stop_.load(std::memory_order_acquire)) {
    work_.store(false, std::memory_order_release);
    if (pending_result && results_.try_push(*pending_result)) pending_result.reset();
    auto command_budget = device_catalog::network_command_work_budget;
    while (!pending_result && command_budget--) {
      const auto command = commands_.receive();
      if (!command) break;
      const auto result = apply(*command->value);
      static_cast<void>(commands_.release(command->handle));
      if (!results_.try_push(result)) pending_result = result;
      if (stop_.load(std::memory_order_acquire)) break;
    }
    if (stop_.load(std::memory_order_acquire)) break;
    const auto now = PointToPointCircuit::Clock::now();
    for (std::size_t shard{}; shard < forwarding_shards_; ++shard) {
      auto budget = device_catalog::isis_work_budget_packets;
      while (budget--) {
        const auto completion = channels_.egress[shard].try_completion();
        if (!completion) break;
        const auto handle = completion->metadata.device;
        if (handle.index >= devices_.size()) continue;
        auto &device = devices_[handle.index];
        if (!device.active || device.handle != handle) continue;
        packet::isis::EthernetDecodeError decode{};
        const auto wire = packet::isis::parse_ethernet_pdu(completion->frame->view(), decode);
        if (!wire || wire->pdu.type != packet::isis::PduType::point_to_point_hello) continue;
        for (auto &owned : device.circuits) if (owned.identity.interface_id == completion->metadata.interface_id &&
            owned.identity.physical_port_ordinal == completion->metadata.physical_port_ordinal) {
          packet::isis::InstanceError error{};
          const auto selection = packet::isis::select_instance(wire->pdu, owned.format, owned.physical_point_to_point, error);
          if (wire->ethernet.destination != owned.destination || !selection || selection->instance != owned.wire_instance) continue;
          if (owned.identity.configuration_generation != completion->metadata.configuration_generation) {
            ++owned.counters.stale_completion;
            continue;
          }
          if (owned.circuit.complete_hello(completion->enqueued, now)) {
            if (completion->enqueued) ++owned.counters.hello_enqueued;
            else ++owned.counters.hello_refused;
          }
        }
      }
      budget = device_catalog::isis_work_budget_packets;
      while (budget--) {
        const auto packet = channels_.ingress[shard].try_receive();
        if (!packet) break;
        receive(*packet, now);
        static_cast<void>(channels_.ingress[shard].release(packet->handle));
      }
    }
    auto deadline = PointToPointCircuit::Clock::time_point::max();
    auto transmit_budget = device_catalog::isis_work_budget_packets;
    for (std::size_t offset{}; offset < devices_.size(); ++offset) {
      auto &device = devices_[(first_device_ + offset) % devices_.size()];
      for (std::size_t ordinal{}; ordinal < device.circuits.size(); ++ordinal) {
        auto &owned = device.circuits[(device.first_circuit + ordinal) % device.circuits.size()];
        static_cast<void>(owned.circuit.expire(now, &owned, event));
        const auto shard = owned.identity.device.index % forwarding_shards_;
        auto &channel = channels_.egress[shard];
        if (transmit_budget && channel.producer_available()) {
          const auto built = owned.circuit.hello(output_, std::nullopt, scratch_, now);
          if (built) --transmit_budget;
          if (built && *built == HelloBuildResult::encoded) {
            const bool published = channel.try_send({owned.identity.device, owned.identity.interface_id,
                owned.identity.physical_port_ordinal, owned.identity.configuration_generation}, output_);
            if (!published) static_cast<void>(owned.circuit.complete_hello(false, now));
            else if (channels_.egress_wakeup) channels_.egress_wakeup(channels_.egress_context);
          }
        }
        const auto next = owned.circuit.deadline();
        // A ready circuit with no channel credit waits for its completion
        // notification. Its holding deadline still participates in expiry.
        if (next > now || channel.producer_available()) deadline = std::min(deadline, next);
        else if (const auto holding = owned.circuit.holding_deadline()) deadline = std::min(deadline, *holding);
      }
      if (!device.circuits.empty()) device.first_circuit = (device.first_circuit + 1U) % device.circuits.size();
    }
    first_device_ = (first_device_ + 1U) % devices_.size();
    std::unique_lock lock(wait_mutex_);
    const auto ready = [&] {
      return stop_.load(std::memory_order_acquire) || work_.load(std::memory_order_acquire) ||
          (!pending_result && !commands_.empty());
    };
    if (deadline == PointToPointCircuit::Clock::time_point::max()) wait_condition_.wait(lock, ready);
    else static_cast<void>(wait_condition_.wait_until(lock, deadline, ready));
  }
}

} // namespace router::isis
