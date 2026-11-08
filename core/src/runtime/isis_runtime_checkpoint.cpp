// Cross-owner IS-IS checkpoint validation belongs to the quiescent network
// coordinator. It joins owned packet and protocol projections without reading a
// live router, consuming a queue, replaying wire or recomputing a decision.

#include "router/isis_runtime_checkpoint.hpp"
#include "router/isis_ethernet.hpp"

#include <algorithm>

namespace router::lab {
namespace {
using Slot = IsisCheckpointEgress::SlotCheckpoint;
const Slot *pending_frame(const IsisRuntimeCheckpoint &saved, const isis::CircuitDefinition &definition,
    packet::isis::PduType type, const protocol::TransmissionWindowCheckpoint &window, std::uint64_t protocol_epoch) noexcept {
  const auto &identity = definition.identity;
  if (!window.pending || identity.device.index >= device_catalog::maximum_routers) return nullptr;
  const auto shard = identity.device.index % saved.control.forwarding_shards;
  const IsisCheckpointEgress::Metadata expected{identity.device, identity.interface_id, identity.physical_port_ordinal,
      identity.configuration_generation, window.pending, static_cast<std::uint8_t>(type), identity.instance, protocol_epoch};
  const Slot *result{};
  for (const auto &slot : saved.egress[shard].occupied) if (slot.metadata == expected) {
    if (result) return nullptr;
    result = &slot;
  }
  if (!result) return nullptr;
  packet::isis::EthernetDecodeError error{};
  const auto wire = packet::isis::parse_ethernet_pdu(result->bytes, error);
  const auto *common = isis::circuit_hello_configuration(definition.configuration, definition.broadcast);
  if (!wire || !common || wire->pdu.type != type || wire->ethernet.source != common->mac ||
      wire->ethernet.destination != common->destinations().select(type) ||
      wire->pdu.maximum_area_addresses != common->maximum_area_addresses) return nullptr;
  packet::isis::InstanceError instance_error{};
  const auto selected = packet::isis::select_instance(wire->pdu,
      common->instance_format.value_or(packet::isis::InstanceFormat::standard),
      !definition.broadcast && definition.configuration.physical_point_to_point, instance_error);
  if (!selected || selected->instance != common->wire_instance) return nullptr;
  if (const auto hello = packet::isis::hello(wire->pdu)) {
    auto local = definition.configuration.local.system;
    if (definition.broadcast) {
      const auto &level = definition.broadcast->levels[type == packet::isis::PduType::lan_hello_l2 ? 1U : 0U];
      if (!level) return nullptr;
      local = level->local.system;
    }
    if (hello->source != local) return nullptr;
  }
  return result;
}
template <typename Entry> bool installed_candidate(const Entry &entry,
    const IsisRuntimeCheckpoint &saved, DeviceHandle device) noexcept {
  constexpr bool ipv6 = std::is_same_v<Entry, routing::Ipv6DynamicInput>;
  if (!entry.configured || !entry.operational || entry.source != routing::RouteSource::isis ||
      !entry.preference || entry.preference > 255U || !entry.interface_id || !entry.interface_generation ||
      entry.protocol_instance > device_catalog::isis_instance_last ||
      !routing::valid_route_path(entry.source, entry.ospf_path_type, entry.isis_path_type, entry.isis_rank, ipv6)) return false;
  if constexpr (ipv6) {
    if (entry.prefix_length > 128U || ip::mask(entry.network, entry.prefix_length) != entry.network || !ip::is_link_local(entry.next_hop)) return false;
  } else {
    const auto first = entry.next_hop >> 24U;
    if (entry.prefix_length > 32U || (entry.network & routing::prefix_mask(entry.prefix_length)) != entry.network ||
        !first || first == 127U || first >= 224U) return false;
  }
  return std::any_of(saved.ports.begin(), saved.ports.end(), [&](const auto &port) {
    const auto &identity = port.identity;
    const auto ordinal = [&] { if constexpr (ipv6) return entry.physical_port_ordinal; else return entry.port_ordinal; }();
    return identity.device == device && identity.instance == entry.protocol_instance &&
        identity.interface_id == entry.interface_id && identity.configuration_generation == entry.interface_generation &&
        identity.physical_port_ordinal == ordinal;
  });
}
bool pending_snp(const Slot &slot, const isis::SnpExchangeCheckpoint &saved,
    const packet::isis::SystemId &local) noexcept {
  packet::isis::EthernetDecodeError error{};
  const auto wire = packet::isis::parse_ethernet_pdu(slot.bytes, error);
  const auto header = wire ? packet::isis::snp(wire->pdu) : std::nullopt;
  if (!header || header->source != local || header->source_circuit_id) return false;
  if (saved.pending_emission == isis::SnpEmission::complete &&
      (header->first != saved.complete.first || header->last != saved.complete.pending_last)) return false;
  packet::isis::SnpEntryCursor entries(wire->pdu.tlvs);
  for (const auto &expected : saved.entries) if (entries.next() != expected) return false;
  return !entries.next() && entries.valid();
}
}
bool valid_isis_runtime_links(const IsisRuntimeCheckpoint &saved) noexcept {
  const auto &control = saved.control;
  const auto cohort = control.barrier_epoch;
  const auto shards = control.forwarding_shards;
  if (saved.version != 1U || control.version != 2U || !cohort || !shards ||
      shards > device_catalog::high_forwarding_shards || saved.ingress.size() != shards || saved.egress.size() != shards ||
      (!saved.forwarding.empty() && saved.forwarding.size() != shards) ||
      (saved.forwarding.empty() && shards != 1U) ||
      !::router::routing::RoutePublication::valid_checkpoint(saved.routes, cohort) || !saved.routes.editing.empty() ||
      saved.ports.size() != control.active_circuits || saved.installed.size() > device_catalog::maximum_routers) return false;
  for (std::size_t shard{}; shard < shards; ++shard) {
    if (!protocol::PacketChannel<device_catalog::isis_packet_ring_frames>::valid_checkpoint(saved.ingress[shard], cohort) ||
        !saved.ingress[shard].borrowed.empty() || !IsisCheckpointEgress::valid_checkpoint(saved.egress[shard], cohort)) return false;
    if (saved.forwarding.empty()) {
      if (!saved.egress[shard].borrowed.empty()) return false;
    } else if (!valid_forward_transfers(saved.forwarding[shard], saved.egress[shard], shard, shards, cohort)) return false;
  }
  std::optional<std::uint16_t> previous_installed;
  for (const auto &installed : saved.installed) {
    if (!installed.device || installed.device.index >= device_catalog::maximum_routers || !installed.generation ||
        (previous_installed && installed.device.index <= *previous_installed) ||
        installed.ipv4.size() > device_catalog::maximum_dynamic_routes_per_router ||
        installed.ipv6.size() > device_catalog::maximum_dynamic_routes_per_router) return false;
    previous_installed = installed.device.index;
    const auto owner = std::find_if(control.devices.begin(), control.devices.end(),
        [&](const auto &value) { return value.handle == installed.device; });
    if (owner == control.devices.end()) return false;
    bool acknowledged = owner->route_installed == installed.generation;
    // The serialized network consumer also admits explicit complete generations
    // before a protocol publisher is enabled. That accepted high water belongs
    // to RIB even though no producer receipt or route stamp exists yet.
    if (!owner->route_generation && !owner->route_pending && !owner->route_installed &&
        std::all_of(owner->instances.begin(), owner->instances.end(), [](const auto &instance) {
          return std::none_of(instance.configuration.routing.begin(), instance.configuration.routing.end(),
              [](const auto &family) { return family.has_value(); });
        })) acknowledged = true;
    if (!acknowledged && owner->route_pending == installed.generation) {
      for (const auto &slot : saved.routes.occupied)
        if (slot.value.routes.device == installed.device && slot.value.routes.generation == installed.generation &&
            slot.value.status == ::router::routing::RouteInstallStatus::installed &&
            std::find(saved.routes.returned.begin(), saved.routes.returned.end(), slot.handle) != saved.routes.returned.end()) acknowledged = true;
    }
    if (!acknowledged || !std::all_of(installed.ipv4.begin(), installed.ipv4.end(),
        [&](const auto &entry) { return installed_candidate(entry, saved, installed.device); }) ||
        !std::all_of(installed.ipv6.begin(), installed.ipv6.end(),
        [&](const auto &entry) { return installed_candidate(entry, saved, installed.device); })) return false;
  }
  std::size_t circuits{};
  for (const auto &device : control.devices) {
    for (const auto &circuit : device.circuits) {
      ++circuits;
      const auto &identity = circuit.definition.identity;
      const auto port = std::find_if(saved.ports.begin(), saved.ports.end(), [&](const auto &value) { return value.identity == identity; });
      if (port == saved.ports.end() || port->port.node != node(identity.device) ||
          port->port.ordinal != identity.physical_port_ordinal || !port->port.generation ||
          std::count_if(saved.ports.begin(), saved.ports.end(), [&](const auto &value) { return value.identity == identity; }) != 1) return false;
      const bool broadcast = circuit.definition.broadcast.has_value();
      if (circuit.transmission.pending && (broadcast || !pending_frame(saved, circuit.definition,
          packet::isis::PduType::point_to_point_hello, circuit.transmission, 0U))) return false;
      for (std::size_t level{}; level < 2U; ++level) {
        if (circuit.lan_transmissions[level].pending && (!broadcast || !pending_frame(saved, circuit.definition,
            level ? packet::isis::PduType::lan_hello_l2 : packet::isis::PduType::lan_hello_l1,
            circuit.lan_transmissions[level], 0U))) return false;
      }
      if (!circuit.update_slot) continue;
      const auto instance = std::find_if(device.instances.begin(), device.instances.end(), [&](const auto &value) { return value.instance == identity.instance; });
      if (instance == device.instances.end()) return false;
      if (!instance->process) continue;
      const auto &process = *instance->process;
      for (std::size_t level{}; level < 2U; ++level) {
        if (!process.levels[level]) continue;
        const auto &level_image = *process.levels[level];
        if (*circuit.update_slot >= level_image.circuits.size()) return false;
        const auto &output = level_image.circuits[*circuit.update_slot];
        if (output.lsp.transmission.pending) {
          const auto *frame = pending_frame(saved, circuit.definition, level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1,
              output.lsp.transmission, output.lsp.transmission.epoch);
          if (!frame || !output.lsp.pending || !circuit.egress) return false;
          packet::isis::EthernetDecodeError error{};
          const auto wire = packet::isis::parse_ethernet_pdu(frame->bytes, error);
          const auto header = wire ? packet::isis::lsp(wire->pdu) : std::nullopt;
          const auto &pending = *output.lsp.pending;
          const auto decrement = std::max<std::uint16_t>(1U, circuit.egress->program.transit_seconds);
          if (!header || header->id != pending.id || header->sequence != pending.sequence || header->checksum != pending.checksum ||
              header->flags != pending.flags || (pending.remaining_seconds && pending.remaining_seconds <= decrement) ||
              header->remaining_seconds != (pending.remaining_seconds ? pending.remaining_seconds - decrement : 0U)) return false;
        }
        if (output.snp.transmission.pending) {
          if (!output.snp.pending_emission) return false;
          const bool complete = output.snp.pending_emission == isis::SnpEmission::complete;
          const auto type = complete ? (level ? packet::isis::PduType::csnp_l2 : packet::isis::PduType::csnp_l1) :
              (level ? packet::isis::PduType::psnp_l2 : packet::isis::PduType::psnp_l1);
          const auto *frame = pending_frame(saved, circuit.definition, type, output.snp.transmission, output.snp.transmission.epoch);
          if (!frame || !pending_snp(*frame, output.snp, instance->configuration.local)) return false;
        }
      }
    }
    if (device.active && device.route_installed && std::none_of(saved.installed.begin(), saved.installed.end(),
        [&](const auto &value) { return value.device == device.handle; })) return false;
    if (device.route_pending && std::count_if(saved.routes.occupied.begin(), saved.routes.occupied.end(), [&](const auto &slot) {
      return slot.value.routes.device == device.handle && slot.value.routes.generation == device.route_pending;
    }) != 1) return false;
  }
  return circuits == control.active_circuits;
}
} // namespace router::lab
