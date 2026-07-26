// Control-shard lifecycle, topology and carrier reconciliation. RuntimeSupervisor
// owns mutable registries; dependencies point only toward device and network layers.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

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

std::optional<SessionHandle>
RuntimeSupervisor::create_session(DeviceHandle device,
                                  std::string_view session_id) {
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

SessionWorkflowResult
RuntimeSupervisor::enter_session_mode(SessionHandle session,
                                      CandidateMode mode) noexcept {
  return session_workflows_.enter(session, mode);
}

SessionWorkflowResult
RuntimeSupervisor::leave_session_mode(SessionHandle session,
                                      bool discard) noexcept {
  return session_workflows_.leave(session, discard);
}

SessionWorkflowResult RuntimeSupervisor::transition_session_mode(
    SessionHandle session, CandidateMode target, bool discard) noexcept {
  return session_workflows_.transition(session, target, discard);
}

SessionWorkflowResult
RuntimeSupervisor::record_session_edit(SessionHandle session,
                                       std::uint64_t key) noexcept {
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

SessionWorkflowResult
RuntimeSupervisor::authorize_classic_write(DeviceHandle device) const noexcept {
  return devices_.get(device)
             ? session_workflows_.authorize_classic_write(device)
             : SessionWorkflowResult::invalid_session;
}

SessionWorkflowResult
RuntimeSupervisor::classic_write(DeviceHandle device,
                                 std::uint64_t key) noexcept {
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
  const auto id = command.id;
  const auto kind = command.kind;
  const bool sensitive =
      kind == NetworkCommandKind::add_ospf_authentication;
  if (!network_worker_->submit(command)) {
    if (sensitive)
      spsc_secure_clear(command);
    return std::nullopt;
  }
  if (sensitive)
    spsc_secure_clear(command);

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
      result.id != id || result.kind != kind)
    return std::nullopt;
  return result;
}

bool RuntimeSupervisor::initialize_signing_vault(
    std::span<const std::uint8_t> wrapping_key,
    const crypto::Sha256Digest &project_context_digest) noexcept {
  if (wrapping_key.size() !=
      NetworkSigningVaultInitialize{}.wrapping_key.size())
    return false;

  NetworkSigningVaultInitialize payload;
  std::copy(wrapping_key.begin(), wrapping_key.end(),
            payload.wrapping_key.begin());
  payload.project_context_digest = project_context_digest;

  auto &command = prepare(NetworkCommandKind::initialize_signing_vault);
  command.id = next_network_command_id_++;
  if (!network_worker_->submit_signing_vault(command, payload)) {
    // The producer-local copy is sensitive too. Clear it on every exit path;
    // secure clearing of the shared slot is the network consumer's duty.
    spsc_secure_clear(payload);
    return false;
  }
  spsc_secure_clear(payload);

  NetworkResult result;
  while (!network_worker_->read(result)) {
    // This synchronous control-shard wait mirrors ordinary dispatch. It never
    // blocks the browser UI thread and preserves the single-outstanding-command
    // ordering contract without a second response queue.
    std::this_thread::yield();
  }
  return result.version == network_plane_message_version &&
         result.id == command.id && result.kind == command.kind &&
         result.success;
}

NetworkCommand &RuntimeSupervisor::prepare(NetworkCommandKind kind) noexcept {
  // Assignment resets every inactive payload field in the persistent arena.
  // This keeps stale handles or FIB bytes from accidentally accompanying a
  // later command if the message schema grows another handler.
  *network_command_ = {};
  network_command_->kind = kind;
  return *network_command_;
}

std::optional<DeviceHandle>
RuntimeSupervisor::create_router(std::string_view node_id,
                                 std::string_view profile_id,
                                 std::string_view system_name) {
  // Cross-kind identity is checked before DeviceRegistry reserves a slot.
  if (hosts_.find(node_id) || switches_.find(node_id))
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

std::optional<HostHandle>
RuntimeSupervisor::create_host(std::string_view node_id,
                               std::string_view name) {
  // The reciprocal check makes stable identity unique regardless of node kind.
  if (devices_.find(node_id) || switches_.find(node_id))
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

std::optional<SwitchHandle>
RuntimeSupervisor::create_switch(std::string_view node_id,
                                 std::string_view profile_id,
                                 std::string_view name) {
  if (devices_.find(node_id) || hosts_.find(node_id))
    return std::nullopt;
  const auto profile_index =
      device_catalog::ethernet_switch_profile_index(profile_id);
  if (!profile_index)
    return std::nullopt;
  const auto handle = switches_.create(node_id, profile_id, name);
  if (!handle)
    return std::nullopt;
  auto &add = prepare(NetworkCommandKind::add_switch);
  add.ethernet_switch = *handle;
  add.switch_profile_index = *profile_index;
  const auto admitted = dispatch(add);
  if (!admitted || !admitted->success) {
    static_cast<void>(switches_.erase(*handle));
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

bool RuntimeSupervisor::set_host_name(HostHandle host, std::string_view name) {
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

bool RuntimeSupervisor::set_switch_name(SwitchHandle handle,
                                        std::string_view name) {
  auto *record = switches_.get(handle);
  if (!record || name.empty() || name.size() > 64U)
    return false;
  try {
    record->name.assign(name);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::configure_switch_port(
    SwitchHandle handle, std::uint16_t port, std::uint32_t speed_mbps,
    std::uint16_t mtu, bool admin_enabled) noexcept {
  const auto *record = switches_.get(handle);
  if (!record || port >= record->profile->port_count)
    return false;
  auto &command = prepare(NetworkCommandKind::configure_switch_port);
  command.ethernet_switch = handle;
  command.switch_port = port;
  command.switch_port_configuration = {
      .speed_mbps = speed_mbps,
      .mtu = mtu,
      .admin_enabled = admin_enabled,
      // Carrier remains network-owner state and is ignored by the edit.
      .carrier = false};
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  auto *mutable_record = switches_.get(handle);
  mutable_record->ports[port] = {
      .speed_mbps = speed_mbps,
      .mtu = mtu,
      .admin_enabled = admin_enabled};
  // Rate or administration changes can make an existing cable compatible or
  // incompatible. Reconciliation derives carrier again from both endpoints.
  reconcile(node(handle));
  return true;
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
    return ResolvedEndpoint{
        .handle = *port_handle,
        .router = inventory,
        .router_port = port};
  }
  if (endpoint.node.kind == NodeKind::host) {
    const HostHandle host{endpoint.node.index, endpoint.node.generation};
    if (!hosts_.get(host) || endpoint.port_id != "eth0")
      return std::nullopt;
    return ResolvedEndpoint{
        .handle = PortHandle{node(host), 0, 1}, .host = true};
  }
  if (endpoint.node.kind != NodeKind::ethernet_switch)
    return std::nullopt;
  const SwitchHandle handle{endpoint.node.index, endpoint.node.generation};
  const auto *record = switches_.get(handle);
  std::uint16_t displayed_port{};
  const auto parsed =
      std::from_chars(endpoint.port_id.data(),
                      endpoint.port_id.data() + endpoint.port_id.size(),
                      displayed_port);
  // User-facing switch ports are numbered one through profile.port_count.
  // Compact runtime ordinals remain zero-based and are never accepted as
  // textual port zero.
  if (!record || parsed.ec != std::errc{} ||
      parsed.ptr != endpoint.port_id.data() + endpoint.port_id.size() ||
      displayed_port == 0U || displayed_port > record->profile->port_count)
    return std::nullopt;
  const auto ordinal = static_cast<std::uint16_t>(displayed_port - 1U);
  return ResolvedEndpoint{
      .handle = PortHandle{node(handle), ordinal, 1U},
      .switch_profile = record->profile,
      .switch_port_intent = &record->ports[ordinal],
      .switch_port = ordinal};
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
      // fabric generation that hardware replacement may already have
      // invalidated.
      const auto current = resolve(endpoint);
      if (current && current->router)
        static_cast<void>(
            current->router->set_link_signal(current->handle, false));
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
  const auto physical_speed = [](const ResolvedEndpoint &endpoint) {
    if (endpoint.router_port)
      return endpoint.router_port->speed_mbps;
    if (endpoint.switch_port_intent)
      return endpoint.switch_port_intent->speed_mbps;
    return std::uint32_t{};
  };
  const auto first_speed = physical_speed(*first);
  const auto second_speed = physical_speed(*second);
  if (first_speed && second_speed) {
    // Selected rates must match. The runtime does not fabricate a negotiation
    // result outside the two configured port capabilities.
    if (first_speed != second_speed)
      return;
    speed_mbps = first_speed;
  } else if (first_speed) {
    // A project host is a protocol endpoint, not a claimed NIC hardware model.
    // On a host-to-profiled-device link it adopts the physical peer's rate.
    speed_mbps = first_speed;
  } else if (second_speed) {
    speed_mbps = second_speed;
  } else {
    // Host endpoints have no hardware profile from which IEEE autonegotiation
    // capabilities can be derived. A direct cable therefore needs explicit
    // project intent and never receives a fabricated default.
    speed_mbps = record->configured_speed_mbps;
  }
  // Explicit media intent also constrains catalog-backed router links. A
  // mismatch represents incompatible physical configuration and must not be
  // repaired by silently replacing either administrator-selected rate.
  if (record->configured_speed_mbps &&
      record->configured_speed_mbps != speed_mbps)
    return;
  auto &configure = prepare(NetworkCommandKind::configure_link);
  configure.link_program = {link,
                            first->handle,
                            second->handle,
                            static_cast<std::uint64_t>(speed_mbps) *
                                1'000'000ULL,
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
    static_cast<void>(
        first->router->set_link_signal(first->handle, record->admin_enabled));
  if (second->router)
    static_cast<void>(
        second->router->set_link_signal(second->handle, record->admin_enabled));
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

HardwareEditResult
RuntimeSupervisor::set_card(DeviceHandle device, std::uint16_t slot,
                            std::string_view provisioned,
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

HardwareEditResult
RuntimeSupervisor::set_mda(DeviceHandle device, std::uint16_t card,
                           std::uint16_t mda, std::string_view provisioned,
                           std::string_view equipped) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_mda(card, mda, provisioned, equipped);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::set_card_admin(DeviceHandle device,
                                                     std::uint16_t slot,
                                                     bool enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_card_admin(slot, enabled);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult RuntimeSupervisor::set_mda_admin(DeviceHandle device,
                                                    std::uint16_t card,
                                                    std::uint16_t mda,
                                                    bool enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory)
    return HardwareEditResult::invalid_slot;
  const auto result = inventory->set_mda_admin(card, mda, enabled);
  if (result == HardwareEditResult::applied)
    reconcile(node(device));
  return result;
}

HardwareEditResult
RuntimeSupervisor::configure_port(DeviceHandle device, std::string_view port_id,
                                  bool admin_enabled, std::uint16_t mtu,
                                  std::uint32_t speed_mbps) noexcept {
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
    bool admin_enabled, std::uint32_t configured_speed_mbps) noexcept {
  // Node identity must exist, while absent port hardware is valid retained link
  // intent and will reconcile when compatible inventory appears.
  const auto exists = [this](NodeHandle handle) {
    switch (handle.kind) {
    case NodeKind::router:
      return devices_.get({handle.index, handle.generation}) != nullptr;
    case NodeKind::host:
      return hosts_.get({handle.index, handle.generation}) != nullptr;
    case NodeKind::ethernet_switch:
      return switches_.get({handle.index, handle.generation}) != nullptr;
    }
    return false;
  };
  if (!exists(first.node) || !exists(second.node) || propagation.count() < 0)
    return std::nullopt;

  if (first.node.kind == NodeKind::ethernet_switch &&
      second.node.kind == NodeKind::ethernet_switch) {
    // The initial bridge profile has no spanning-tree process. IEEE 802.1Q
    // transparent forwarding would therefore circulate broadcasts forever
    // when switch-to-switch links close a cycle. Reject exactly that physical
    // L2 condition while still permitting arbitrary routed cycles between
    // router nodes.
    std::array<bool, device_catalog::maximum_switches> visited{};
    std::array<bool, device_catalog::maximum_switches> queued{};
    std::array<NodeHandle, device_catalog::maximum_switches> pending{};
    std::size_t pending_size{1U};
    pending[0] = first.node;
    queued[first.node.index] = true;
    const auto current = topology_.checkpoint();
    while (pending_size) {
      const auto candidate = pending[--pending_size];
      if (candidate.index >= visited.size() || visited[candidate.index])
        continue;
      if (candidate == second.node)
        return std::nullopt;
      visited[candidate.index] = true;
      for (const auto &entry : current.entries) {
        const auto &left = entry.record.endpoints[0].node;
        const auto &right = entry.record.endpoints[1].node;
        if (left.kind != NodeKind::ethernet_switch ||
            right.kind != NodeKind::ethernet_switch)
          continue;
        const auto neighbor =
            left == candidate ? std::optional{right}
            : right == candidate ? std::optional{left}
                                 : std::nullopt;
        if (neighbor && neighbor->index < visited.size() &&
            !queued[neighbor->index]) {
          // Each live switch generation enters the bounded stack once, so its
          // capacity is proven by maximum_switches rather than handled by a
          // lossy overflow branch.
          queued[neighbor->index] = true;
          pending[pending_size++] = *neighbor;
        }
      }
    }
  }
  const auto link = topology_.create(
      link_id, first, second, static_cast<std::uint64_t>(propagation.count()),
      configured_speed_mbps);
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
    LinkHandle link, bool enabled, std::chrono::nanoseconds propagation,
    std::uint32_t configured_speed_mbps) noexcept {
  auto *record = topology_.get(link);
  if (!record || propagation.count() < 0)
    return false;
  // TopologyRegistry is the sole owner of portable link intent. Reconciliation
  // reprograms both physical directions and their local propagation deadlines
  // from this one accepted value, never from an editor-side timer.
  record->admin_enabled = enabled;
  record->propagation_ns = static_cast<std::uint64_t>(propagation.count());
  // Zero means that physical router ports negotiate from their catalog-backed
  // selected rates. A nonzero value is retained as administrator intent and
  // reconciliation refuses carrier when it conflicts with either endpoint.
  record->configured_speed_mbps = configured_speed_mbps;
  reconcile(link);
  return true;
}

} // namespace router::lab
