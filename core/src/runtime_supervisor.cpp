// Control-shard implementation of multi-device lifecycle and carrier
// reconciliation. Packet parsing and protocol state do not belong here.

#include "router/runtime_supervisor.hpp"

#include "router/multi_device_routing.hpp"

#include <algorithm>
#include <new>
#include <thread>

namespace router::lab {

struct RuntimeSupervisor::RouterNetworkState {
  // Control owns interface and RIB inputs. The forwarding object owns only its
  // installed value projections, adjacency table and packet queues.
  routing::RouteTable rib;
  std::array<routing::ConnectedInput, device_catalog::maximum_ports_per_router>
      connected{};
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router>
      statics{};
  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports{};
  std::array<bool, device_catalog::maximum_ports_per_router> interface_admin{};
  std::uint64_t fib_generation{};
};

RuntimeSupervisor::RuntimeSupervisor()
    : session_workflows_(sessions_),
      network_command_(std::make_unique<NetworkCommand>()),
      network_channels_(std::make_unique<NetworkPlaneChannels>()),
      network_worker_(
          std::make_unique<NetworkPlaneWorker>(*network_channels_)) {
  // Construction publishes no default router, host or link. The packet arena
  // exists early so later node creation never changes shared-memory layout.
  network_worker_->start();
}

RuntimeSupervisor::~RuntimeSupervisor() {
  // Joining before channel destruction guarantees that the network owner can
  // no longer publish into shared storage during supervisor teardown.
  network_worker_->stop();
}

std::optional<SessionHandle> RuntimeSupervisor::create_session(
    DeviceHandle device, std::string_view session_id) {
  const auto *record = devices_.get(device);
  // Quiescing closes admission before link and arena teardown begins. A new
  // terminal can never revive a router whose generation is being removed.
  return record && !record->quiescing ? sessions_.create(device, session_id)
                                      : std::nullopt;
}

bool RuntimeSupervisor::close_session(SessionHandle session) noexcept {
  return session_workflows_.close(session);
}

bool RuntimeSupervisor::set_cli_session(SessionHandle session,
                                        const CliSession &state) noexcept {
  auto *record = sessions_.get(session);
  if (!record || record->closing)
    return false;
  record->cli = state;
  return true;
}

SessionWorkflowResult RuntimeSupervisor::enter_session_mode(
    SessionHandle session, CandidateMode mode) noexcept {
  return session_workflows_.enter(session, mode);
}

SessionWorkflowResult RuntimeSupervisor::leave_session_mode(
    SessionHandle session, bool discard) noexcept {
  return session_workflows_.leave(session, discard);
}

SessionWorkflowResult RuntimeSupervisor::transition_session_mode(
    SessionHandle session, CandidateMode target, bool discard) noexcept {
  return session_workflows_.transition(session, target, discard);
}

SessionWorkflowResult RuntimeSupervisor::record_session_edit(
    SessionHandle session, std::uint64_t key) noexcept {
  return session_workflows_.record_edit(session, key);
}

SessionWorkflowResult
RuntimeSupervisor::commit_session(SessionHandle session) noexcept {
  return session_workflows_.commit(session);
}

SessionWorkflowResult
RuntimeSupervisor::discard_session(SessionHandle session) noexcept {
  return session_workflows_.discard(session);
}

SessionWorkflowResult RuntimeSupervisor::authorize_classic_write(
    DeviceHandle device) const noexcept {
  return devices_.get(device)
             ? session_workflows_.authorize_classic_write(device)
             : SessionWorkflowResult::invalid_session;
}

SessionWorkflowResult RuntimeSupervisor::classic_write(
    DeviceHandle device, std::uint64_t key) noexcept {
  return devices_.get(device) ? session_workflows_.classic_write(device, key)
                              : SessionWorkflowResult::invalid_session;
}

bool RuntimeSupervisor::global_candidate_dirty(
    DeviceHandle device) const noexcept {
  // A stale device handle cannot identify a candidate belonging to a newer
  // router that reused the same compact registry slot.
  return devices_.get(device) &&
         session_workflows_.global_candidate_dirty(device);
}

std::optional<SessionWorkflowStatus>
RuntimeSupervisor::session_status(SessionHandle session) const noexcept {
  return session_workflows_.status(session);
}

std::optional<NetworkResult>
RuntimeSupervisor::dispatch(NetworkCommand &command) noexcept {
  // RuntimeSupervisor is confined to one control shard, making command IDs and
  // the producer side of this SPSC ring single-writer without another lock.
  command.id = next_network_command_id_++;
  if (!network_worker_->submit(command))
    return std::nullopt;

  NetworkResult result;
  while (!network_worker_->read(result)) {
    // This wait occurs on the control worker, never the browser UI thread. A
    // yield lets the network pthread consume the command without burning a
    // full core while the bounded response travels back.
    std::this_thread::yield();
  }
  // Synchronous dispatch permits exactly one outstanding command. Any other
  // identity indicates corrupted ordering and cannot be treated as success.
  if (result.version != network_plane_message_version ||
      result.id != command.id || result.kind != command.kind)
    return std::nullopt;
  return result;
}

NetworkCommand &
RuntimeSupervisor::prepare(NetworkCommandKind kind) noexcept {
  // Assignment resets every inactive payload field in the persistent arena.
  // This keeps stale handles or FIB bytes from accidentally accompanying a
  // later command if the message schema grows another handler.
  *network_command_ = {};
  network_command_->kind = kind;
  return *network_command_;
}

std::optional<DeviceHandle> RuntimeSupervisor::create_router(
    std::string_view node_id, std::string_view profile_id,
    std::string_view system_name) {
  // Cross-kind identity is checked before DeviceRegistry reserves a slot.
  if (hosts_.find(node_id))
    return std::nullopt;
  const auto handle = devices_.create(node_id, profile_id, system_name);
  if (!handle)
    return std::nullopt;
  const auto *record = devices_.get(*handle);
  // Construct inventory in the matching compact slot before publishing the
  // handle back to the command caller.
  hardware_[handle->index].emplace(*handle, *record->profile);
  router_network_[handle->index] = std::make_unique<RouterNetworkState>();
  auto &add = prepare(NetworkCommandKind::add_router);
  add.device = *handle;
  const auto admitted = dispatch(add);
  if (!admitted || !admitted->success) {
    // Cross-owner admission is transactional. A failed network allocation is
    // rolled back before the caller can observe a half-created router.
    router_network_[handle->index].reset();
    hardware_[handle->index].reset();
    static_cast<void>(devices_.erase(*handle));
    return std::nullopt;
  }
  return handle;
}

std::optional<HostHandle> RuntimeSupervisor::create_host(
    std::string_view node_id, std::string_view name) {
  // The reciprocal check makes stable identity unique regardless of node kind.
  if (devices_.find(node_id))
    return std::nullopt;
  const auto handle = hosts_.create(node_id, name);
  std::optional<NetworkResult> admitted;
  if (handle) {
    auto &add = prepare(NetworkCommandKind::add_host);
    add.host = *handle;
    admitted = dispatch(add);
  }
  if (handle && (!admitted || !admitted->success)) {
    // Host protocol ownership is admitted with the identity or not at all.
    static_cast<void>(hosts_.erase(*handle));
    return std::nullopt;
  }
  return handle;
}

bool RuntimeSupervisor::set_system_name(DeviceHandle device,
                                         std::string_view system_name) {
  auto *record = devices_.get(device);
  if (!record || system_name.empty() || system_name.size() > 64U)
    return false;
  // Build the replacement before touching the registry-owned string. A failed
  // allocation leaves the prompt identity and checkpoint record unchanged.
  std::string replacement{system_name};
  record->system_name.swap(replacement);
  return true;
}

bool RuntimeSupervisor::set_host_name(HostHandle host,
                                      std::string_view name) {
  auto *record = hosts_.get(host);
  if (!record || name.empty() || name.size() > 64U)
    return false;
  // Host display identity is control-plane configuration. Stable NodeId and
  // HostHandle remain unchanged, so queued frames and link endpoints continue
  // to target the same protocol stack after a rename.
  try {
    record->name.assign(name);
    return true;
  } catch (...) {
    return false;
  }
}

RouterHardwareInventory *
RuntimeSupervisor::hardware(DeviceHandle device) noexcept {
  // Registry validation prevents a stale handle from accessing replacement
  // inventory that happens to occupy the same compact array slot.
  if (!devices_.get(device) || device.index >= hardware_.size() ||
      !hardware_[device.index])
    return nullptr;
  return &*hardware_[device.index];
}

const RouterHardwareInventory *
RuntimeSupervisor::hardware(DeviceHandle device) const noexcept {
  if (!devices_.get(device) || device.index >= hardware_.size() ||
      !hardware_[device.index])
    return nullptr;
  return &*hardware_[device.index];
}

std::optional<RuntimeSupervisor::ResolvedEndpoint>
RuntimeSupervisor::resolve(const LinkEndpoint &endpoint) noexcept {
  if (endpoint.node.kind == NodeKind::router) {
    const DeviceHandle device{endpoint.node.index, endpoint.node.generation};
    auto *inventory = hardware(device);
    if (!inventory)
      return std::nullopt;
    const auto port_handle = inventory->handle(endpoint.port_id);
    auto *port = inventory->find(endpoint.port_id);
    if (!port_handle || !port || !port->present)
      return std::nullopt;
    return ResolvedEndpoint{*port_handle, inventory, port, false};
  }
  const HostHandle host{endpoint.node.index, endpoint.node.generation};
  if (!hosts_.get(host) || endpoint.port_id != "eth0")
    return std::nullopt;
  return ResolvedEndpoint{PortHandle{node(host), 0, 1}, nullptr, nullptr, true};
}

void RuntimeSupervisor::deactivate(LinkHandle link) noexcept {
  auto *record = topology_.get(link);
  if (record) {
    // Operational state is withdrawn before the forwarding removal request.
    // A concurrent snapshot can therefore never advertise carrier for a link
    // whose endpoint identities are already being invalidated.
    record->carrier = false;
    record->speed_mbps = 0U;
    for (const auto &endpoint : record->endpoints) {
      // Resolve current inventory rather than trusting endpoints retained by a
      // fabric generation that hardware replacement may already have invalidated.
      const auto current = resolve(endpoint);
      if (current && current->router)
        static_cast<void>(current->router->set_link_signal(current->handle,
                                                           false));
    }
  }
  // NetworkPlane validates the complete generation. An absent live binding is
  // expected for retained topology whose hardware has never produced carrier.
  auto &remove = prepare(NetworkCommandKind::remove_link);
  remove.link = link;
  static_cast<void>(dispatch(remove));
  if (record) {
    // Carrier withdrawal changes only the RIB of routers incident to this link.
    // Each rebuild still consumes local interface state rather than graph data.
    for (const auto &endpoint : record->endpoints)
      if (endpoint.node.kind == NodeKind::router)
        refresh_router({endpoint.node.index, endpoint.node.generation});
  }
}

void RuntimeSupervisor::reconcile(LinkHandle link) noexcept {
  auto *record = topology_.get(link);
  if (!record)
    return;
  deactivate(link);
  const auto first = resolve(record->endpoints[0]);
  const auto second = resolve(record->endpoints[1]);
  // Missing equipment is not a topology error. Leave the cable record intact
  // and wait for a later hardware edit to make both live endpoints resolvable.
  if (!first || !second)
    return;

  std::uint32_t speed_mbps{};
  if (first->router_port && second->router_port) {
    // Selected rates must match. The runtime does not fabricate a negotiation
    // result outside the two configured port capabilities.
    if (first->router_port->speed_mbps != second->router_port->speed_mbps)
      return;
    speed_mbps = first->router_port->speed_mbps;
  } else if (first->router_port) {
    // A project host is a protocol endpoint, not a claimed NIC hardware model.
    // On a router-host link it adopts the one physical peer's rate.
    speed_mbps = first->router_port->speed_mbps;
  } else if (second->router_port) {
    speed_mbps = second->router_port->speed_mbps;
  } else {
    // Project format 3 supplies no host-host rate source. Carrier stays down
    // instead of using a hidden default.
    return;
  }
  auto &configure = prepare(NetworkCommandKind::configure_link);
  configure.link_program = {
      link, first->handle, second->handle,
      static_cast<std::uint64_t>(speed_mbps) * 1'000'000ULL,
      std::chrono::nanoseconds{record->propagation_ns},
      record->admin_enabled};
  const auto configured = speed_mbps ? dispatch(configure) : std::nullopt;
  if (!configured || !configured->success)
    return;

  // A compatible medium retains its negotiated/configured rate even when the
  // cable is administratively disabled. Carrier represents signal presence,
  // so it additionally follows the link administrative state.
  record->speed_mbps = speed_mbps;
  record->carrier = record->admin_enabled;

  // Physical signal follows endpoint compatibility and cable administration.
  // Router port administration remains a separate operational-state gate.
  if (first->router)
    static_cast<void>(first->router->set_link_signal(first->handle,
                                                     record->admin_enabled));
  if (second->router)
    static_cast<void>(second->router->set_link_signal(second->handle,
                                                      record->admin_enabled));
  if (first->handle.node.kind == NodeKind::router)
    refresh_router({first->handle.node.index, first->handle.node.generation});
  if (second->handle.node.kind == NodeKind::router)
    refresh_router({second->handle.node.index, second->handle.node.generation});
}

void RuntimeSupervisor::reconcile(NodeHandle node_handle) noexcept {
  const auto links = topology_.attached(node_handle);
  // The handle snapshot is bounded and remains valid for this serialized owner
  // turn. Reconciliation itself does not add or remove topology records.
  for (std::size_t index = 0; index < links.count; ++index)
    reconcile(links.handles[index]);
}

HardwareEditResult RuntimeSupervisor::set_card(
    DeviceHandle device, std::uint16_t slot, std::string_view provisioned,
    std::string_view equipped) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_card(slot, provisioned, equipped);
  // A rejected edit cannot flap working links. Reconciliation runs only after
  // the hardware aggregate accepted and atomically rebuilt its inventory.
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::set_mda(
    DeviceHandle device, std::uint16_t card, std::uint16_t mda,
    std::string_view provisioned, std::string_view equipped) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_mda(card, mda, provisioned, equipped);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::set_card_admin(
    DeviceHandle device, std::uint16_t slot, bool enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_card_admin(slot, enabled);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::set_mda_admin(
    DeviceHandle device, std::uint16_t card, std::uint16_t mda,
    bool enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_mda_admin(card, mda, enabled);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::configure_port(
    DeviceHandle device, std::string_view port_id, bool admin_enabled,
    std::uint16_t mtu, std::uint32_t speed_mbps) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result =
      inventory->configure_port(port_id, admin_enabled, mtu, speed_mbps);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

std::optional<LinkHandle> RuntimeSupervisor::create_link(
    std::string_view link_id, const LinkEndpoint &first,
    const LinkEndpoint &second, std::chrono::nanoseconds propagation,
    bool admin_enabled) noexcept {
  // Node identity must exist, while absent port hardware is valid retained link
  // intent and will reconcile when compatible inventory appears.
  const auto exists = [this](NodeHandle handle) {
    return handle.kind == NodeKind::router
               ? devices_.get({handle.index, handle.generation}) != nullptr
               : hosts_.get({handle.index, handle.generation}) != nullptr;
  };
  if (!exists(first.node) || !exists(second.node) || propagation.count() < 0)
    return std::nullopt;
  const auto link = topology_.create(
      link_id, first, second,
      static_cast<std::uint64_t>(propagation.count()));
  if (!link)
    return std::nullopt;
  topology_.get(*link)->admin_enabled = admin_enabled;
  reconcile(*link);
  return link;
}

bool RuntimeSupervisor::delete_link(LinkHandle link) noexcept {
  if (!topology_.get(link))
    return false;
  deactivate(link);
  return topology_.erase(link);
}

bool RuntimeSupervisor::set_link_admin(LinkHandle link, bool enabled) noexcept {
  auto *record = topology_.get(link);
  if (!record)
    return false;
  record->admin_enabled = enabled;
  reconcile(link);
  return true;
}

bool RuntimeSupervisor::set_link_properties(
    LinkHandle link, bool enabled,
    std::chrono::nanoseconds propagation) noexcept {
  auto *record = topology_.get(link);
  if (!record || propagation.count() < 0)
    return false;
  // TopologyRegistry is the sole owner of portable link intent. Reconciliation
  // reprograms both physical directions and their local propagation deadlines
  // from this one accepted value, never from an editor-side timer.
  record->admin_enabled = enabled;
  record->propagation_ns =
      static_cast<std::uint64_t>(propagation.count());
  reconcile(link);
  return true;
}

bool RuntimeSupervisor::configure_interface(
    DeviceHandle device, std::string_view port_id, packet::Mac mac,
    std::uint32_t address, std::uint8_t prefix_length,
    bool admin_enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U)
    return false;
  const auto ordinal_value = inventory->coordinate_ordinal(port_id);
  const auto *physical = inventory->find(port_id);
  if (!ordinal_value || !physical || !physical->speed_mbps)
    return false;
  auto &network = *router_network_[device.index];
  const auto ordinal = *ordinal_value;
  // The interface key is the stable physical ordinal. Removing its MDA leaves
  // control intent in this slot while forwarding operational state becomes down.
  network.ports[ordinal] = {
      .configured = true,
      .operational = false,
      .ordinal = ordinal,
      .mtu = physical->mtu,
      .address = address,
      .network = address & routing::prefix_mask(prefix_length),
      .speed_mbps = physical->speed_mbps,
      .prefix_length = prefix_length,
      .mac = mac};
  network.interface_admin[ordinal] = admin_enabled;
  network.connected[ordinal] = {
      .configured = true,
      .operational = false,
      .network = address & routing::prefix_mask(prefix_length),
      .port_ordinal = ordinal,
      .prefix_length = prefix_length};
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::remove_interface(DeviceHandle device,
                                         std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.ports[*ordinal].configured)
    return false;

  // Clear control-owned RIB input before withdrawing the forwarding port. The
  // next FIB generation therefore cannot retain a connected route that points
  // at an interface whose ARP and pending queues are about to be destroyed.
  state.ports[*ordinal] = {};
  state.interface_admin[*ordinal] = false;
  state.connected[*ordinal] = {};
  rebuild_routes(device);
  auto &remove = prepare(NetworkCommandKind::remove_port);
  remove.device = device;
  remove.port.ordinal = *ordinal;
  const auto result = dispatch(remove);
  return result && result->success;
}

bool RuntimeSupervisor::add_static_route(DeviceHandle device,
                                         std::uint32_t network,
                                         std::uint8_t prefix_length,
                                         std::uint32_t next_hop) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U || !next_hop)
    return false;
  auto &state = *router_network_[device.index];
  routing::StaticInput *target{};
  const auto canonical = network & routing::prefix_mask(prefix_length);
  for (auto &entry : state.statics) {
    if (entry.configured && entry.network == canonical &&
        entry.prefix_length == prefix_length) {
      target = &entry;
      break;
    }
    if (!entry.configured && !target)
      target = &entry;
  }
  if (!target)
    // Exhaustion is explicit. No oldest route is evicted to make the command
    // appear successful.
    return false;
  *target = {.configured = true,
             .network = canonical,
             .next_hop = next_hop,
             .prefix_length = prefix_length};
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::remove_static_route(DeviceHandle device,
                                            std::uint32_t network,
                                            std::uint8_t prefix_length) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U)
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = network & routing::prefix_mask(prefix_length);
  const auto found = std::find_if(
      state.statics.begin(), state.statics.end(), [&](const auto &entry) {
        return entry.configured && entry.network == canonical &&
               entry.prefix_length == prefix_length;
      });
  if (found == state.statics.end())
    return false;
  *found = {};
  rebuild_routes(device);
  return true;
}

void RuntimeSupervisor::refresh_router(DeviceHandle device) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return;
  auto &state = *router_network_[device.index];
  for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
    if (!state.ports[ordinal].configured)
      continue;
    const auto *physical = inventory->at(static_cast<std::uint16_t>(ordinal));
    const bool operational = physical && physical->present &&
                             physical->configuration_compatible &&
                             physical->hierarchy_enabled &&
                             physical->admin_enabled && physical->link_signal &&
                             state.interface_admin[ordinal];
    state.ports[ordinal].operational = operational;
    if (physical) {
      state.ports[ordinal].mtu = physical->mtu;
      state.ports[ordinal].speed_mbps = physical->speed_mbps;
    }
    state.connected[ordinal].operational = operational;
    // Forwarding receives the complete port projection even when down. This
    // preserves address and MTU configuration without granting packet passage.
    auto &configure = prepare(NetworkCommandKind::configure_port);
    configure.device = device;
    configure.port = state.ports[ordinal];
    static_cast<void>(dispatch(configure));
  }
  rebuild_routes(device);
}

void RuntimeSupervisor::rebuild_routes(DeviceHandle device) noexcept {
  if (device.index >= router_network_.size() ||
      !router_network_[device.index])
    return;
  auto &state = *router_network_[device.index];
  const bool changed = state.rib.rebuild(state.connected, state.statics);
  if (!state.rib.last_rebuild_valid())
    return;
  if (changed || !state.fib_generation) {
    // Generation advances only for an installed selection. Rejected rebuilds
    // leave both control RIB and forwarding FIB on their previous generation.
    ++state.fib_generation;
    auto &program = prepare(NetworkCommandKind::program_fib);
    program.device = device;
    program.fib = state.rib.compile(state.fib_generation);
    static_cast<void>(dispatch(program));
  }
}

bool RuntimeSupervisor::start_router_ping(
    DeviceHandle device, std::uint32_t destination,
    std::uint16_t sequence, std::uint16_t payload_octets,
    bool dont_fragment) noexcept {
  if (!devices_.get(device))
    return false;
  auto &command = prepare(NetworkCommandKind::router_ping);
  command.device = device;
  command.destination = destination;
  command.sequence = sequence;
  command.payload_octets = payload_octets;
  command.dont_fragment = dont_fragment;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::router_ping_reply(DeviceHandle device,
                                          std::uint16_t sequence) noexcept {
  if (!devices_.get(device))
    return false;
  auto &command = prepare(NetworkCommandKind::router_ping_status);
  command.device = device;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success && result->value != 0;
}

bool RuntimeSupervisor::configure_host(HostHandle host, packet::Mac mac,
                                       packet::Ipv4 address,
                                       std::uint8_t prefix_length,
                                       packet::Ipv4 gateway,
                                       std::uint16_t mtu) noexcept {
  if (!hosts_.get(host) || prefix_length > 32U ||
      mtu < device_catalog::minimum_host_ipv4_mtu ||
      mtu > device_catalog::maximum_network_mtu)
    return false;
  // HostNetworkProgram crosses the same value boundary as router port and FIB
  // projections. Control never receives a pointer to endpoint ARP state.
  auto &command = prepare(NetworkCommandKind::configure_host);
  command.host_program = {host, mac, address, gateway, prefix_length, mtu};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::start_host_ping(HostHandle host,
                                        packet::Ipv4 destination,
                                        std::uint16_t sequence) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::host_ping);
  command.host = host;
  command.host_destination = destination;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::host_ping_reply(HostHandle host,
                                        std::uint16_t sequence) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::host_ping_status);
  command.host = host;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success && result->value != 0;
}

bool RuntimeSupervisor::delete_router(DeviceHandle device) noexcept {
  auto *record = devices_.get(device);
  if (!record)
    return false;
  // Quiescing is visible before dependent deletion. New session work can be
  // rejected while already accepted work follows the explicit drain policy.
  record->quiescing = true;
  const auto links = topology_.attached(node(device));
  static_cast<void>(session_workflows_.close_device(device));
  for (std::size_t index = 0; index < links.count; ++index)
    // delete_link drains fabric ownership and clears both endpoint signals
    // before TopologyRegistry invalidates the handle generation.
    static_cast<void>(delete_link(links.handles[index]));
  // Network-owned queues and protocol state are destroyed before the control
  // generation is advanced, so no live packet can target a released handle.
  auto &remove = prepare(NetworkCommandKind::remove_router);
  remove.device = device;
  const auto removed = dispatch(remove);
  if (!removed || !removed->success)
    return false;
  hardware_[device.index].reset();
  router_network_[device.index].reset();
  return devices_.erase(device);
}

bool RuntimeSupervisor::delete_host(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  const auto links = topology_.attached(node(host));
  for (std::size_t index = 0; index < links.count; ++index)
    static_cast<void>(delete_link(links.handles[index]));
  auto &remove = prepare(NetworkCommandKind::remove_host);
  remove.host = host;
  const auto removed = dispatch(remove);
  if (!removed || !removed->success)
    return false;
  return hosts_.erase(host);
}

std::size_t RuntimeSupervisor::active_links() noexcept {
  auto &query = prepare(NetworkCommandKind::active_link_count);
  const auto result = dispatch(query);
  // A failed health query cannot safely invent a stale physical link count.
  return result && result->success ? static_cast<std::size_t>(result->value) : 0;
}

bool RuntimeSupervisor::configure_capture_point(
    const CapturePointProgram &program) noexcept {
  auto &command = prepare(NetworkCommandKind::configure_capture_point);
  command.capture_program = program;
  const auto result = dispatch(command);
  return result && result->success;
}

std::span<const std::uint8_t>
RuntimeSupervisor::prepare_capture() noexcept {
  auto &command = prepare(NetworkCommandKind::prepare_capture);
  const auto result = dispatch(command);
  if (!result || !result->success ||
      result->value != network_worker_->prepared_capture().size())
    return {};
  // Response-ring acquire ordering publishes the completed byte vector. The
  // bridge must copy it before issuing another prepare command.
  return network_worker_->prepared_capture();
}

std::size_t RuntimeSupervisor::captured_frames() noexcept {
  auto &command = prepare(NetworkCommandKind::capture_frame_count);
  const auto result = dispatch(command);
  return result && result->success ? static_cast<std::size_t>(result->value) : 0;
}

std::uint64_t RuntimeSupervisor::capture_dropped() noexcept {
  auto &command = prepare(NetworkCommandKind::capture_drop_count);
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0;
}

std::uint64_t RuntimeSupervisor::dropped_packets() noexcept {
  // The link owner combines its medium and cross-shard counters. Control reads
  // one scalar response and never samples forwarding-owned atomics directly.
  auto &command = prepare(NetworkCommandKind::packet_drop_count);
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0;
}

std::optional<RouterForwarderCheckpoint>
RuntimeSupervisor::router_operational_state(DeviceHandle device) noexcept {
  if (!devices_.get(device))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::prepare_router_checkpoint);
  command.device = device;
  const auto result = dispatch(command);
  const auto *prepared = network_worker_->prepared_router_checkpoint();
  if (!result || !result->success || !prepared)
    return std::nullopt;
  // Acquire on the result ring publishes the immutable prepared value. Copying
  // now releases the worker-owned buffer for the next show request without
  // exposing forwarding pointers or taking the 32 MiB capture checkpoint.
  try {
    return *prepared;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

std::unique_ptr<RuntimeSupervisorCheckpoint>
RuntimeSupervisor::checkpoint() {
  auto &barrier = prepare(NetworkCommandKind::prepare_checkpoint);
  const auto result = dispatch(barrier);
  if (!result || !result->success)
    return nullptr;
  auto network = network_worker_->take_prepared_checkpoint();
  if (!network)
    return nullptr;
  try {
    auto state = std::make_unique<RuntimeSupervisorCheckpoint>();
    state->devices = devices_.checkpoint();
    state->hosts = hosts_.checkpoint();
    state->topology = topology_.checkpoint();
    state->sessions = sessions_.checkpoint();
    state->workflows = session_workflows_.checkpoint();
    state->hardware.reserve(state->devices.entries.size());
    state->control.reserve(state->devices.entries.size());
    for (const auto &device : state->devices.entries) {
      const auto *inventory = hardware(device.handle);
      const auto *control = device.handle.index < router_network_.size()
                                ? router_network_[device.handle.index].get()
                                : nullptr;
      if (!inventory || !control)
        return nullptr;
      state->hardware.emplace_back();
      inventory->checkpoint(state->hardware.back());
      RouterControlCheckpoint router;
      router.device = device.handle;
      router.connected = control->connected;
      router.statics = control->statics;
      router.ports = control->ports;
      router.interface_admin = control->interface_admin;
      router.fib_generation = control->fib_generation;
      router.selected_rib = control->rib.compile(control->fib_generation);
      state->control.push_back(std::move(router));
    }
    state->network = std::move(*network);
    state->next_network_command_id = next_network_command_id_;
    return state;
  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

bool RuntimeSupervisor::restore(RuntimeSupervisorCheckpoint state) {
  try {
    auto devices = std::make_unique<DeviceRegistry>();
    auto hosts = std::make_unique<HostRegistry>();
    auto topology = std::make_unique<TopologyRegistry>();
    auto sessions = std::make_unique<SessionRegistry>();
    if (!devices->restore(state.devices) || !hosts->restore(state.hosts) ||
        !topology->restore(state.topology) ||
        !sessions->restore(state.sessions))
      return false;
    for (const auto &device : state.devices.entries)
      if (hosts->find(device.node_id))
        return false;
    for (const auto &session : state.sessions.entries)
      if (!devices->get(session.record.device))
        return false;
    for (const auto &link : state.topology.entries)
      for (const auto &endpoint : link.record.endpoints) {
        const bool exists = endpoint.node.kind == NodeKind::router
                                ? devices->get({endpoint.node.index,
                                                endpoint.node.generation}) !=
                                      nullptr
                                : hosts->get({endpoint.node.index,
                                              endpoint.node.generation}) !=
                                      nullptr;
        if (!exists)
          return false;
      }

    auto hardware = std::make_unique<decltype(hardware_)>();
    auto control = std::make_unique<decltype(router_network_)>();
    std::array<bool, device_catalog::maximum_routers> hardware_seen{};
    std::array<bool, device_catalog::maximum_routers> control_seen{};
    for (const auto &source : state.hardware) {
      const auto *device = devices->get(source.device);
      if (!device || source.device.index >= hardware_seen.size() ||
          hardware_seen[source.device.index] ||
          source.profile_id != device->profile->id)
        return false;
      auto restored = std::make_unique<RouterHardwareInventory>();
      if (!restored->restore(source))
        return false;
      (*hardware)[source.device.index] = std::move(*restored);
      hardware_seen[source.device.index] = true;
    }
    const auto same_fib = [](const routing::FibProgram &left,
                             const routing::FibProgram &right) {
      return left.generation == right.generation && left.count == right.count &&
             std::equal(left.routes.begin(), left.routes.begin() + left.count,
                        right.routes.begin(), [](const auto &a, const auto &b) {
                          return a.network == b.network &&
                                 a.next_hop == b.next_hop &&
                                 a.port_ordinal == b.port_ordinal &&
                                 a.prefix_length == b.prefix_length;
                        });
    };
    for (const auto &source : state.control) {
      if (!devices->get(source.device) ||
          source.device.index >= control_seen.size() ||
          control_seen[source.device.index] ||
          source.selected_rib.generation != source.fib_generation ||
          source.selected_rib.count > source.selected_rib.routes.size())
        return false;
      auto restored = std::make_unique<RouterNetworkState>();
      restored->connected = source.connected;
      restored->statics = source.statics;
      restored->ports = source.ports;
      restored->interface_admin = source.interface_admin;
      restored->fib_generation = source.fib_generation;
      static_cast<void>(restored->rib.rebuild(restored->connected,
                                              restored->statics));
      if (!restored->rib.last_rebuild_valid() ||
          !same_fib(restored->rib.compile(source.fib_generation),
                    source.selected_rib))
        return false;
      RouterForwarderCheckpoint forwarding_validation;
      forwarding_validation.fib = source.selected_rib;
      for (const auto &port : source.ports)
        if (port.configured)
          forwarding_validation.ports.push_back(port);
      if (!RouterForwarder::validate_checkpoint(forwarding_validation))
        return false;
      (*control)[source.device.index] = std::move(restored);
      control_seen[source.device.index] = true;
    }
    for (const auto &device : state.devices.entries)
      if (!hardware_seen[device.handle.index] ||
          !control_seen[device.handle.index])
        return false;

    if (state.network.routers.size() != state.devices.entries.size() ||
        state.network.hosts.size() != state.hosts.entries.size())
      return false;
    for (const auto &router : state.network.routers)
      if (!devices->get(router.device))
        return false;
    for (const auto &host : state.network.hosts)
      if (!hosts->get(host.host))
        return false;
    for (const auto &workflow : state.workflows.routers)
      if (!devices->get(workflow.device))
        return false;

    SessionWorkflowController workflows{*sessions};
    if (!workflows.restore(state.workflows) ||
        !network_worker_->stage_restore(std::move(state.network)))
      return false;
    auto &restore_command = prepare(NetworkCommandKind::restore_checkpoint);
    const auto network_result = dispatch(restore_command);
    if (!network_result || !network_result->success) {
      network_worker_->cancel_staged_restore();
      return false;
    }

    // All allocating and fallible work completed before this commit. Registry
    // object addresses stay stable, preserving the workflow controller's
    // reference to sessions_ while their validated contents are replaced.
    devices_ = std::move(*devices);
    hosts_ = std::move(*hosts);
    topology_ = std::move(*topology);
    sessions_ = std::move(*sessions);
    for (std::size_t index = 0; index < hardware_.size(); ++index) {
      hardware_[index] = std::move((*hardware)[index]);
      router_network_[index] = std::move((*control)[index]);
    }
    session_workflows_.swap_state(workflows);
    next_network_command_id_ =
        std::max(next_network_command_id_, state.next_network_command_id);
    return true;
  } catch (const std::bad_alloc &) {
    network_worker_->cancel_staged_restore();
    return false;
  }
}

} // namespace router::lab
