// Canonical IS-IS checkpoint field order, owned by the versioned codec.
// These explicit borrowed tuples serve encoding and decoding synchronously.
// They contain no pointers in the image and never escape the archive call.
// Structured bindings also reject a changed flat record field count at compile
// time. Inherited circuit records explicitly visit their common base first.

#pragma once

#include "router/isis_runtime_checkpoint.hpp"
#include <tuple>
#include <type_traits>
#include <utility>

namespace router::lab::isis_checkpoint::detail {
template <typename T> requires std::is_same_v<std::remove_const_t<T>, protocol::FrameExpiryCheckpoint>
auto members(T &v) noexcept { auto &[offset, prepaid_transit_seconds, holding_nanoseconds] = v;
  return std::tie(offset, prepaid_transit_seconds, holding_nanoseconds); }
using Ingress = protocol::PacketChannel<device_catalog::isis_packet_ring_frames>;
using IngressImage = Ingress::Checkpoint;
using EgressImage = IsisCheckpointEgress::Checkpoint;
using IngressSlot = Ingress::SlotCheckpoint;
using EgressSlot = IsisCheckpointEgress::SlotCheckpoint;
using IngressMetadata = Ingress::Metadata;
using EgressMetadata = IsisCheckpointEgress::Metadata;
using IngressReturn = Ingress::ReturnCheckpoint;
using EgressReturn = IsisCheckpointEgress::ReturnCheckpoint;
using RouteImage = ::router::routing::RoutePublication::Checkpoint;
using RouteSlot = typename decltype(std::declval<RouteImage>().occupied)::value_type;
using RouteValue = decltype(std::declval<RouteSlot>().value);
template <typename Base, typename T> auto &base(T &value) noexcept {
  return static_cast<std::conditional_t<std::is_const_v<T>, const Base, Base> &>(value);
}
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::DisLocal>
auto members(T &v) noexcept { [[maybe_unused]] auto &[system, mac, priority, circuit] = v; return std::tie(v.system, v.mac, v.priority, v.circuit); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::DisSelection>
auto members(T &v) noexcept { [[maybe_unused]] auto &[system, mac, lan, local] = v; return std::tie(v.system, v.mac, v.lan, v.local); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::BroadcastScanCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, interval, periodic_nanoseconds, last_sent_nanoseconds, random, pending] = v; return std::tie(v.version, v.interval, v.periodic_nanoseconds, v.last_sent_nanoseconds, v.random, v.pending); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::checkpoint_time::DeadlineCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[kind, nanoseconds] = v; return std::tie(v.kind, v.nanoseconds); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::CircuitHelloConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[mac, hello_destination, areas, protocols, ipv4_addresses, ipv6_addresses, topologies, instance_format, wire_instance, instance_topologies, emit_instance, padding, receive_authentication, transmit_authentication, strict_adjacency_check, maximum_area_addresses, holding_seconds, hello_interval, maximum_pdu_octets, peer_attribute_octets, update_destinations, ipv6_addresses_ready] = v; return std::tie(v.mac, v.hello_destination, v.areas, v.protocols, v.ipv4_addresses, v.ipv6_addresses, v.topologies, v.instance_format, v.wire_instance, v.instance_topologies, v.emit_instance, v.padding, v.receive_authentication, v.transmit_authentication, v.strict_adjacency_check, v.maximum_area_addresses, v.holding_seconds, v.hello_interval, v.maximum_pdu_octets, v.peer_attribute_octets, v.update_destinations, v.ipv6_addresses_ready); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlCircuitCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[definition, medium, transmission, lan_transmissions, counters, update_slot, queued_lsp, previous_dis, egress] = v; return std::tie(v.definition, v.medium, v.transmission, v.lan_transmissions, v.counters, v.update_slot, v.queued_lsp, v.previous_dis, v.egress); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlCircuitCheckpoint::PreviousDis>
auto members(T &v) noexcept { [[maybe_unused]] auto &[remote, fragment, retry] = v; return std::tie(v.remote, v.fragment, v.retry); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlDeviceCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, active, retired_epoch_floor, circuits, instances, gates, update_fences, instance_order, first_instance, first_circuit, installed_routes, pending_routes, route_generation, route_installed, route_pending, route_status, route_retry_at, route_retry] = v; return std::tie(v.handle, v.active, v.retired_epoch_floor, v.circuits, v.instances, v.gates, v.update_fences, v.instance_order, v.first_instance, v.first_circuit, v.installed_routes, v.pending_routes, v.route_generation, v.route_installed, v.route_pending, v.route_status, v.route_retry_at, v.route_retry); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlDeviceCheckpoint::Gate>
auto members(T &v) noexcept { [[maybe_unused]] auto &[instance, state] = v; return std::tie(v.instance, v.state); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlEgressCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[program, retries, epochs, revision, partial, complete, complete_periodic, lsp, earliest, complete_started, transient_first, designated, scan, remaining, pacing, csnp_ready, credits, random, broadcast_scan, lan_active, synchronize, lan_lsp, lan_csnp] = v; return std::tie(v.program, v.retries, v.epochs, v.revision, v.partial, v.complete, v.complete_periodic, v.lsp, v.earliest, v.complete_started, v.transient_first, v.designated, v.scan, v.remaining, v.pacing, v.csnp_ready, v.credits, v.random, v.broadcast_scan, v.lan_active, v.synchronize, v.lan_lsp, v.lan_csnp); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlEgressCheckpoint::Retry>
auto members(T &v) noexcept { [[maybe_unused]] auto &[header, level, at] = v; return std::tie(v.header, v.level, v.at); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlEgressCheckpoint::Reservation>
auto members(T &v) noexcept { [[maybe_unused]] auto &[level, epoch, ticket] = v; return std::tie(v.level, v.epoch, v.ticket); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlFamilyCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[decisions, consumed, status, bindings] = v; return std::tie(v.decisions, v.consumed, v.status, v.bindings); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlInstanceCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[instance, configuration, process, local, decisions, consumed_decision_revision, decision_runs, decision_status, families, local_roots_dirty, first_root_level, validation, database_validations, decision_revisions, revision, expiration_revision, expiration_blocked, corrupted_lsp, status, spf, admin_enabled] = v; return std::tie(v.instance, v.configuration, v.process, v.local, v.decisions, v.consumed_decision_revision, v.decision_runs, v.decision_status, v.families, v.local_roots_dirty, v.first_root_level, v.validation, v.database_validations, v.decision_revisions, v.revision, v.expiration_revision, v.expiration_blocked, v.corrupted_lsp, v.status, v.spf, v.admin_enabled); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlWorkerCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, barrier_epoch, forwarding_shards, maximum_circuits, active_circuits, first_device, devices] = v; return std::tie(v.version, v.barrier_epoch, v.forwarding_shards, v.maximum_circuits, v.active_circuits, v.first_device, v.devices); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::BroadcastTransmissionProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[lsp_scan_interval, csnp_separation] = v; return std::tie(v.lsp_scan_interval, v.csnp_separation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::CircuitCounters>
auto members(T &v) noexcept { [[maybe_unused]] auto &[received, discarded, stale_ingress, stale_completion, hello_enqueued, hello_refused, adjacency_up, adjacency_down, transmission_exhausted, update_received, update_discarded, last_update, lsp_enqueued, lsp_refused, snp_enqueued, snp_refused, lsp_too_large, purge_pending, designated_changes] = v; return std::tie(v.received, v.discarded, v.stale_ingress, v.stale_completion, v.hello_enqueued, v.hello_refused, v.adjacency_up, v.adjacency_down, v.transmission_exhausted, v.update_received, v.update_discarded, v.last_update, v.lsp_enqueued, v.lsp_refused, v.snp_enqueued, v.snp_refused, v.lsp_too_large, v.purge_pending, v.designated_changes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::CircuitDefinition>
auto members(T &v) noexcept { [[maybe_unused]] auto &[identity, configuration, random_state, broadcast, update_transmission, carrier] = v; return std::tie(v.identity, v.configuration, v.random_state, v.broadcast, v.update_transmission, v.carrier); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::CircuitIdentity>
auto members(T &v) noexcept { [[maybe_unused]] auto &[device, interface_id, configuration_generation, physical_port_ordinal, instance] = v; return std::tie(v.device, v.interface_id, v.configuration_generation, v.physical_port_ordinal, v.instance); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanOriginInterface>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface_id, circuit, maximum_neighbors, levels] = v; return std::tie(v.interface_id, v.circuit, v.maximum_neighbors, v.levels); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalPrefixInterface>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface_id, physical_port, available] = v; return std::tie(v.interface_id, v.physical_port, v.available); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalPrefixCatalogUnit>
auto members(T &v) noexcept { [[maybe_unused]] auto &[level, prefix, options, owners] = v; return std::tie(v.level, v.prefix, v.options, v.owners); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalPrefixCatalogProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, interfaces, units] = v; return std::tie(v.version, v.interfaces, v.units); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalIpv6Address>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface_id, physical_port, address, prefix_length, preferred] = v; return std::tie(v.interface_id, v.physical_port, v.address, v.prefix_length, v.preferred); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalIpv6AddressUnit>
auto members(T &v) noexcept { [[maybe_unused]] auto &[source, metadata] = v; return std::tie(v.source, v.metadata); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalIpv6AddressCatalog>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, units] = v; return std::tie(v.version, v.units); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalOriginProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[content, neighbors, resource_retry, broadcast_neighbors, prefixes, ipv6_addresses, automatic_area_attachment, suppress_attached_bit] = v; return std::tie(v.content, v.neighbors, v.resource_retry, v.broadcast_neighbors, v.prefixes, v.ipv6_addresses, v.automatic_area_attachment, v.suppress_attached_bit); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::SpfDelayPolicy>
auto members(T &v) noexcept { [[maybe_unused]] auto &[maximum_delay, initial_delay, second_delay] = v; return std::tie(v.maximum, v.initial, v.second); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::SpfThrottleCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, policy, next_hold, last_run_nanoseconds, pending_nanoseconds] = v; return std::tie(v.version, v.policy, v.next_hold, v.last_run_nanoseconds, v.pending_nanoseconds); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pDecisionProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[nodes, links, pending, protocol, prefixes] = v; return std::tie(v.nodes, v.links, v.pending, v.protocol, v.prefixes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pRouteFamilyProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[calculation, preferences, ignore_attached_bit] = v; return std::tie(v.calculation, v.preferences, v.ignore_attached_bit); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pRouteFamilyProgram::Preference>
auto members(T &v) noexcept { [[maybe_unused]] auto &[internal, external] = v; return std::tie(v.internal, v.external); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::UpdateInstanceProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[local, maximum_areas, levels, maximum_circuits, transmission, wire_instance, format, origination, decision, routing, spf_delay] = v; return std::tie(v.local, v.maximum_areas, v.levels, v.maximum_circuits, v.transmission, v.wire_instance, v.format, v.origination, v.decision, v.routing, v.spf_delay); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::UpdateTransmissionProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[partial_seconds, retransmit_seconds, complete_seconds, pacing_period, pacing_burst, maximum_pdu_octets, transit_seconds, broadcast] = v; return std::tie(v.partial_seconds, v.retransmit_seconds, v.complete_seconds, v.pacing_period, v.pacing_burst, v.maximum_pdu_octets, v.transit_seconds, v.broadcast); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::CompleteSnpSequenceCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, first, pending_last, active, pending, repeat] = v; return std::tie(v.version, v.first, v.pending_last, v.active, v.pending, v.repeat); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::DatabaseValidationCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, interval, random, due_nanoseconds, cursor, scanning, corrupted] = v; return std::tie(v.version, v.interval, v.random, v.due_nanoseconds, v.cursor, v.scanning, v.corrupted); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::FloodCircuit>
auto members(T &v) noexcept { [[maybe_unused]] auto &[broadcast, eligible, srm, ssn] = v; return std::tie(v.broadcast, v.eligible, v.srm, v.ssn); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::HelloScheduleCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, interval, periodic_nanoseconds, last_sent_nanoseconds, random, broadcast, designated, sent, dirty, pending] = v; return std::tie(v.version, v.interval, v.periodic_nanoseconds, v.last_sent_nanoseconds, v.random, v.broadcast, v.designated, v.sent, v.dirty, v.pending); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::InstanceCircuitCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[configuration, synchronization_epochs, activated, configured, admission_pending, admission_ticket, active, peer, lan_peers] = v; return std::tie(v.configuration, v.synchronization_epochs, v.activated, v.configured, v.admission_pending, v.admission_ticket, v.active, v.peer, v.lan_peers); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::InstanceUpdateCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, configuration, levels, circuits, admission_counter] = v; return std::tie(v.version, v.configuration, v.levels, v.circuits, v.admission_counter); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::InstanceUpdateConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[local, maximum_areas, levels, selector, maximum_circuits, initial_synchronization_epoch] = v; return std::tie(v.local, v.maximum_areas, v.levels, v.selector, v.maximum_circuits, v.initial_synchronization_epoch); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::UpdateCircuitConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[configuration_epoch, levels, physical_point_to_point, format, wire_instance, destinations, broadcast, neighbor_capacity] = v; return std::tie(v.configuration_epoch, v.levels, v.physical_point_to_point, v.format, v.wire_instance, v.destinations, v.broadcast, v.neighbor_capacity); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::UpdateInstanceSelector>
auto members(T &v) noexcept { [[maybe_unused]] auto &[format, wire_instance] = v; return std::tie(v.format, v.wire_instance); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::UpdateLevelConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[database, acknowledgement_capacity, snp_entry_capacity, receive_pdu_octets, maximum_age, purge_retention, waiting_time, authenticate_lsp, authenticate_csnp, authenticate_psnp, purge_rules] = v; return std::tie(v.database, v.acknowledgement_capacity, v.snp_entry_capacity, v.receive_pdu_octets, v.maximum_age, v.purge_retention, v.waiting_time, v.authenticate_lsp, v.authenticate_csnp, v.authenticate_psnp, v.purge_rules); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanAdjacencyCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, type, peer, peer_mac, local_mac, state, holding_nanoseconds] = v; return std::tie(v.version, v.type, v.peer, v.peer_mac, v.local_mac, v.state, v.holding_nanoseconds); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanSnapshot>
auto members(T &v) noexcept { [[maybe_unused]] auto &[system, mac, advertised_lan, priority, state, present] = v; return std::tie(v.system, v.mac, v.advertised_lan, v.priority, v.state, v.present); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanPeerCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[adjacency, attributes] = v; return std::tie(v.adjacency, v.attributes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanSetCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, type, local, limits, maximum_attribute_octets, peers] = v; return std::tie(v.version, v.type, v.local, v.limits, v.maximum_attribute_octets, v.peers); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanSetLimits>
auto members(T &v) noexcept { [[maybe_unused]] auto &[neighbors, areas_per_neighbor] = v; return std::tie(v.neighbors, v.areas_per_neighbor); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanCircuitCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, configuration, neighbors, hello, election_nanoseconds, designated, advertised_lan, election_started, operational] = v; return std::tie(v.version, v.configuration, v.neighbors, v.hello, v.election_nanoseconds, v.designated, v.advertised_lan, v.election_started, v.operational); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanCircuitConfiguration>
auto members(T &v) noexcept { return std::tie(base<router::isis::CircuitHelloConfiguration>(v), v.local, v.levels, v.type, v.limits, v.designated_hello_interval, v.designated_holding_seconds); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanCircuitProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[levels] = v; return std::tie(v.levels); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LanPairCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, levels] = v; return std::tie(v.version, v.levels); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelDatabaseCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, database, maximum_circuits, circuits, records] = v; return std::tie(v.version, v.database, v.maximum_circuits, v.circuits, v.records); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelFloodRecordCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[id, circuits, placeholder] = v; return std::tie(v.id, v.circuits, v.placeholder); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelCircuitCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[configuration, eligible, designated, activated, snp, lsp] = v; return std::tie(v.configuration, v.eligible, v.designated, v.activated, v.snp, v.lsp); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelCircuitConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[broadcast, epoch] = v; return std::tie(v.broadcast, v.epoch); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelProcessCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, configuration, database, acknowledgements, circuits, waiting_nanoseconds, waiting, waiting_timer_expired] = v; return std::tie(v.version, v.configuration, v.database, v.acknowledgements, v.circuits, v.waiting_nanoseconds, v.waiting, v.waiting_timer_expired); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LevelProcessConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[level, database, acknowledgement_capacity, maximum_age, purge_retention, waiting_time, maximum_circuits] = v; return std::tie(v.level, v.database, v.acknowledgement_capacity, v.maximum_age, v.purge_retention, v.waiting_time, v.maximum_circuits); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalLspContent>
auto members(T &v) noexcept { [[maybe_unused]] auto &[level, id, flags, options, active] = v; return std::tie(v.level, v.id, v.flags, v.options, v.active); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalLspEntryCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[content, generation, last_error, retirement_pending, retirement_blocked] = v; return std::tie(v.content, v.generation, v.last_error, v.retirement_pending, v.retirement_blocked); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalLspLevelProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[maximum_age, maximum_pdu_octets, minimum_interval, refresh_interval] = v; return std::tie(v.maximum_age, v.maximum_pdu_octets, v.minimum_interval, v.refresh_interval); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalLspProgram>
auto members(T &v) noexcept { [[maybe_unused]] auto &[levels, records, random] = v; return std::tie(v.levels, v.records, v.random); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LocalLspSetCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, local, maximum_areas, selector, levels, waiting_overload, entries, first, terminal] = v; return std::tie(v.version, v.local, v.maximum_areas, v.selector, v.levels, v.waiting_overload, v.entries, v.first, v.terminal); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LsdbCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, type, limits, records] = v; return std::tie(v.version, v.type, v.limits, v.records); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LspRecordCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[bytes, allocation, age_nanoseconds, retirement_nanoseconds, expiration_notified] = v; return std::tie(v.bytes, v.allocation, v.age_nanoseconds, v.retirement_nanoseconds, v.expiration_notified); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LspExchangeCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, database_type, circuit, transmission, pending] = v; return std::tie(v.version, v.database_type, v.circuit, v.transmission, v.pending); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LspGeneration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[status, sequence, ticket] = v; return std::tie(v.status, v.sequence, v.ticket); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LspGenerationCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, minimum, refresh, random, tickets, committed, observed, refresh_nanoseconds, changed_nanoseconds, hold_nanoseconds, pending, dirty, changed_during_pending, blocked, stopped] = v; return std::tie(v.version, v.minimum, v.refresh, v.random, v.tickets, v.committed, v.observed, v.refresh_nanoseconds, v.changed_nanoseconds, v.hold_nanoseconds, v.pending, v.dirty, v.changed_during_pending, v.blocked, v.stopped); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::packet::isis::TopologyComponent>
auto members(T &v) noexcept { [[maybe_unused]] auto &[id, overloaded, attached] = v; return std::tie(v.id, v.overloaded, v.attached); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::NeighborArea>
auto members(T &v) noexcept { [[maybe_unused]] auto &[bytes, length] = v; return std::tie(v.bytes, v.length); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pOriginInterface>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface_id, levels] = v; return std::tie(v.interface_id, v.levels); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pOriginMetric>
auto members(T &v) noexcept { [[maybe_unused]] auto &[wide, narrow] = v; return std::tie(v.wide, v.narrow); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::AdjacencyNextHop>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface, peer, address, level] = v; return std::tie(v.interface, v.peer, v.address, v.level); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::NextHopInterface>
auto members(T &v) noexcept { [[maybe_unused]] auto &[interface_id, configuration_generation, physical_port_ordinal] = v; return std::tie(v.interface_id, v.configuration_generation, v.physical_port_ordinal); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pAdjacencyCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, local, state, holding_nanoseconds] = v; return std::tie(v.version, v.local, v.state, v.holding_nanoseconds); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pLocal>
auto members(T &v) noexcept { [[maybe_unused]] auto &[system, extended_circuit, local_circuit, levels, over_lan] = v; return std::tie(v.system, v.extended_circuit, v.local_circuit, v.levels, v.over_lan); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pSnapshot>
auto members(T &v) noexcept { [[maybe_unused]] auto &[neighbor_system, neighbor_mac, negotiated_circuit, neighbor_extended_circuit, usage, three_way, present, iso_up, uses_three_way] = v; return std::tie(v.neighbor_system, v.neighbor_mac, v.negotiated_circuit, v.neighbor_extended_circuit, v.usage, v.three_way, v.present, v.iso_up, v.uses_three_way); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pCircuitCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, configuration, adjacency, hello, peer_attributes, operational] = v; return std::tie(v.version, v.configuration, v.adjacency, v.hello, v.peer_attributes, v.operational); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::P2pCircuitConfiguration>
auto members(T &v) noexcept { return std::tie(base<router::isis::CircuitHelloConfiguration>(v), v.local, v.physical_point_to_point); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::DecisionCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, configuration, identities, paths, prefixes] = v; return std::tie(v.version, v.configuration, v.identities, v.paths, v.prefixes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::DecisionConfiguration>
auto members(T &v) noexcept { [[maybe_unused]] auto &[nodes, links, pending, distance, prefixes] = v; return std::tie(v.nodes, v.links, v.pending, v.distance, v.prefixes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::packet::isis::LspView>
auto members(T &v) noexcept { [[maybe_unused]] auto &[id, remaining_seconds, sequence, checksum, flags] = v; return std::tie(v.id, v.remaining_seconds, v.sequence, v.checksum, v.flags); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::packet::isis::SnpEntry>
auto members(T &v) noexcept { [[maybe_unused]] auto &[remaining_seconds, id, sequence, checksum] = v; return std::tie(v.remaining_seconds, v.id, v.sequence, v.checksum); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::PrefixAdvertisement>
auto members(T &v) noexcept { [[maybe_unused]] auto &[origin, prefix, metric, level, down, external, attributes_offset, attributes_size] = v; return std::tie(v.origin, v.prefix, v.metric, v.level, v.down, v.external, v.attributes_offset, v.attributes_size); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::PrefixCollectionBudget>
auto members(T &v) noexcept { [[maybe_unused]] auto &[records, attributes] = v; return std::tie(v.records, v.attributes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::PrefixSetCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, budget, entries, attributes, ignored] = v; return std::tie(v.version, v.budget, v.entries, v.attributes, v.ignored); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::IsisRuntimeCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, control, ingress, egress, routes, forwarding, ports, installed] = v; return std::tie(v.version, v.control, v.ingress, v.egress, v.routes, v.forwarding, v.ports, v.installed); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::IsisTransportPortCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[identity, port] = v; return std::tie(v.identity, v.port); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::SequenceRecoveryCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, cooldown, resource_retry, due_nanoseconds, disabled, saturated] = v; return std::tie(v.version, v.cooldown, v.resource_retry, v.due_nanoseconds, v.disabled, v.saturated); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::SnpExchangeCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, database_type, circuit, entry_capacity, transmission, complete, pending_emission, partial_cursor, acknowledgement_cursor, pending_cursor, entries, acknowledgements] = v; return std::tie(v.version, v.database_type, v.circuit, v.entry_capacity, v.transmission, v.complete, v.pending_emission, v.partial_cursor, v.acknowledgement_cursor, v.pending_cursor, v.entries, v.acknowledgements); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::TransientAcknowledgement>
auto members(T &v) noexcept { [[maybe_unused]] auto &[entry, ticket] = v; return std::tie(v.entry, v.ticket); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::TransientAcknowledgementCheckpointEntry>
auto members(T &v) noexcept { [[maybe_unused]] auto &[circuit, acknowledgement] = v; return std::tie(v.circuit, v.acknowledgement); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::TransientAcknowledgementsCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, capacity, next_ticket, entries] = v; return std::tie(v.version, v.capacity, v.next_ticket, v.entries); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::routing::DistancePolicy>
auto members(T &v) noexcept { [[maybe_unused]] auto &[maximum_distance, maximum_edge, saturate, settle_once] = v; return std::tie(v.maximum_distance, v.maximum_edge, v.saturate, v.settle_once); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::routing::ShortestPathCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[distance, first_hops] = v; return std::tie(v.distance, v.first_hops); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::routing::ShortestPathsCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, policy, maximum_vertices, maximum_pending_candidates, first_hop_count, vertices] = v; return std::tie(v.version, v.policy, v.maximum_vertices, v.maximum_pending_candidates, v.first_hop_count, v.vertices); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::routing::DynamicInput>
auto members(T &v) noexcept { [[maybe_unused]] auto &[configured, operational, network, next_hop, port_ordinal, preference, metric, prefix_length, source, ospf_path_type, internal_metric, area_id, tag, protocol_instance, loop_free_alternate, interface_id, isis_path_type, isis_rank, interface_generation] = v; return std::tie(v.configured, v.operational, v.network, v.next_hop, v.port_ordinal, v.preference, v.metric, v.prefix_length, v.source, v.ospf_path_type, v.internal_metric, v.area_id, v.tag, v.protocol_instance, v.loop_free_alternate, v.interface_id, v.isis_path_type, v.isis_rank, v.interface_generation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::routing::Ipv6DynamicInput>
auto members(T &v) noexcept { [[maybe_unused]] auto &[configured, operational, network, next_hop, interface_id, physical_port_ordinal, preference, metric, prefix_length, source, ospf_path_type, internal_metric, area_id, tag, protocol_instance, loop_free_alternate, isis_path_type, isis_rank, interface_generation] = v; return std::tie(v.configured, v.operational, v.network, v.next_hop, v.interface_id, v.physical_port_ordinal, v.preference, v.metric, v.prefix_length, v.source, v.ospf_path_type, v.internal_metric, v.area_id, v.tag, v.protocol_instance, v.loop_free_alternate, v.isis_path_type, v.isis_rank, v.interface_generation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::ip::IpAddress>
auto members(T &v) noexcept { [[maybe_unused]] auto &[family, bytes] = v; return std::tie(v.family, v.bytes); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::ip::IpPrefix>
auto members(T &v) noexcept { [[maybe_unused]] auto &[network, length] = v; return std::tie(v.network, v.length); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::ForwardShardTransferCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, barrier_epoch, egress, receipts, retained_receipt] = v; return std::tie(v.version, v.barrier_epoch, v.egress, v.receipts, v.retained_receipt); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::ForwardTransferCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[kind, source, ordinal, expected_port, isis_receipt, bytes, expiry] = v; return std::tie(v.kind, v.source, v.ordinal, v.expected_port, v.isis_receipt, v.bytes, v.expiry); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::IsisLinkReceiptCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, metadata, enqueued] = v; return std::tie(v.handle, v.metadata, v.enqueued); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::LsdbLimits>
auto members(T &v) noexcept { [[maybe_unused]] auto &[records, allocated_pdu_octets, minimum_pdu_allocation] = v; return std::tie(v.records, v.allocated_pdu_octets, v.minimum_pdu_allocation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::protocol::TransmissionWindowCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, epoch, next_ticket, pending] = v; return std::tie(v.version, v.epoch, v.next_ticket, v.pending); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::DeviceHandle>
auto members(T &v) noexcept { [[maybe_unused]] auto &[index, generation] = v; return std::tie(v.index, v.generation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::NodeHandle>
auto members(T &v) noexcept { [[maybe_unused]] auto &[kind, index, generation] = v; return std::tie(v.kind, v.index, v.generation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::PortHandle>
auto members(T &v) noexcept { [[maybe_unused]] auto &[node, ordinal, generation] = v; return std::tie(v.node, v.ordinal, v.generation); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, IngressImage>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, barrier_epoch, capacity, with_completions, available, ready, borrowed, returned, occupied] = v; return std::tie(v.version, v.barrier_epoch, v.capacity, v.with_completions, v.available, v.ready, v.borrowed, v.returned, v.occupied); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, EgressImage>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, barrier_epoch, capacity, with_completions, available, ready, borrowed, returned, occupied] = v; return std::tie(v.version, v.barrier_epoch, v.capacity, v.with_completions, v.available, v.ready, v.borrowed, v.returned, v.occupied); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, IngressSlot>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, metadata, bytes, expiry] = v; return std::tie(v.handle, v.metadata, v.bytes, v.expiry); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, EgressSlot>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, metadata, bytes, expiry] = v; return std::tie(v.handle, v.metadata, v.bytes, v.expiry); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, IngressMetadata>
auto members(T &v) noexcept { [[maybe_unused]] auto &[device, interface_id, physical_port_ordinal, configuration_generation, transmission_id, transmission_class, instance_id, protocol_epoch] = v; return std::tie(v.device, v.interface_id, v.physical_port_ordinal, v.configuration_generation, v.transmission_id, v.transmission_class, v.instance_id, v.protocol_epoch); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, EgressMetadata>
auto members(T &v) noexcept { [[maybe_unused]] auto &[device, interface_id, physical_port_ordinal, configuration_generation, transmission_id, transmission_class, instance_id, protocol_epoch] = v; return std::tie(v.device, v.interface_id, v.physical_port_ordinal, v.configuration_generation, v.transmission_id, v.transmission_class, v.instance_id, v.protocol_epoch); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, IngressReturn>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, enqueued] = v; return std::tie(v.handle, v.enqueued); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, EgressReturn>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, enqueued] = v; return std::tie(v.handle, v.enqueued); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, RouteImage>
auto members(T &v) noexcept { [[maybe_unused]] auto &[version, barrier_epoch, capacity, with_completions, available, ready, borrowed, returned, editing, occupied] = v; return std::tie(v.version, v.barrier_epoch, v.capacity, v.with_completions, v.available, v.ready, v.borrowed, v.returned, v.editing, v.occupied); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, RouteSlot>
auto members(T &v) noexcept { [[maybe_unused]] auto &[handle, value] = v; return std::tie(v.handle, v.value); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, RouteValue>
auto members(T &v) noexcept { [[maybe_unused]] auto &[routes, status] = v; return std::tie(v.routes, v.status); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::isis::ControlRouteStamp>
auto members(T &v) noexcept { [[maybe_unused]] auto &[epoch, decision, status, families, ignored_attached_families] = v; return std::tie(v.epoch, v.decision, v.status, v.families, v.ignored_attached_families); }
template <typename T> requires std::is_same_v<std::remove_const_t<T>, router::lab::IsisInstalledRoutesCheckpoint>
auto members(T &v) noexcept { [[maybe_unused]] auto &[device, generation, ipv4, ipv6] = v; return std::tie(v.device, v.generation, v.ipv4, v.ipv6); }
} // namespace router::lab::isis_checkpoint::detail
