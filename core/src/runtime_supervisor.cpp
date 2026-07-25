// Control-shard implementation of multi-device lifecycle and carrier
// reconciliation. Packet parsing and protocol state do not belong here.

#include "router/runtime_supervisor.hpp"

#include "router/multi_device_routing.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <new>
#include <thread>

namespace router::lab {

struct RuntimeSupervisor::RouterNetworkState {
  // Control owns interface and RIB inputs. The forwarding object owns only its
  // installed value projections, adjacency table and packet queues.
  routing::RouteTable rib;
  std::array<routing::ConnectedInput, routing::maximum_ipv4_connected_inputs>
      connected{};
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router>
      statics{};
  routing::Ipv6RouteTable ipv6_rib;
  std::array<routing::Ipv6ConnectedInput,
             device_catalog::maximum_ports_per_router>
      ipv6_connected{};
  // Native secondary addresses are cold control intent. The separate derived
  // connected vector is rebuilt transactionally and passed to the RIB without
  // making the forwarding shard inspect mutable configuration memory.
  std::vector<RouterIpv6Address> native_ipv6_addresses{};
  std::vector<routing::Ipv6ConnectedInput> native_ipv6_connected{};
  std::array<routing::Ipv6StaticInput,
             device_catalog::maximum_static_routes_per_router>
      ipv6_statics{};
  // One is the SR OS default and represents disabled path sharing. Control is
  // the sole owner; forwarding receives only the resulting immutable groups.
  std::uint16_t maximum_ecmp_paths{1U};
  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports{};
  std::array<bool, device_catalog::maximum_ports_per_router> interface_admin{};
  std::array<bool, device_catalog::maximum_ports_per_router> ies_port_owned{};
  std::array<RouterAdvertisementIntent,
             device_catalog::maximum_ports_per_router>
      router_advertisements{};
  std::array<MldInterfaceIntent, device_catalog::maximum_ports_per_router>
      mld_interfaces{};
  // Control retains committed relay intent independently of the forwarding
  // socket. Card removal may destroy the latter while the former must be
  // available for exact reprovisioning when hardware returns.
  std::array<std::optional<dhcpv6::RelayInterfaceConfig>,
             device_catalog::maximum_ports_per_router>
      dhcpv6_relays{};
  // These vectors are cold-path, control-owned configuration generations.
  // Packet owners receive only complete immutable projections through the
  // SPSC command stream, never pointers into these allocations.
  service::Configuration ies_configuration{};
  std::vector<service::SapAttachment> ies_sap_attachments{};
  std::vector<service::ServiceIpv6Interface> ies_ipv6_interfaces{};
  std::vector<routing::Ipv6ConnectedInput> ies_ipv6_connected{};
  std::vector<dhcpv6::RelayInterfaceConfig> ies_dhcpv6_relays{};
  std::uint64_t fib_generation{};
  std::uint64_t ipv6_fib_generation{};
};

namespace {

bool build_native_ipv6_connected(
    std::span<const RouterIpv6Address> addresses,
    std::span<const ForwardPort> ports,
    bool system_operational,
    std::vector<routing::Ipv6ConnectedInput> &output) noexcept {
  try {
    std::vector<routing::Ipv6ConnectedInput> candidate;
    candidate.reserve(addresses.size());
    for (const auto &address : addresses) {
      const bool system = address.interface_id == system_interface_id;
      if (system ? address.port_ordinal != system_interface_port_ordinal
                 : address.port_ordinal >= ports.size())
        return false;
      // Multiple addresses in one subnet install one connected prefix. Local
      // address ownership remains per-address in RouterIpv6AddressTable, while
      // duplicating the connected FIB entry would create ambiguous show output
      // without adding any forwarding reachability.
      const auto duplicate = std::find_if(
          candidate.begin(), candidate.end(), [&](const auto &entry) {
            return entry.interface_id == address.interface_id &&
                   entry.network == address.network &&
                   entry.prefix_length == address.prefix_length;
          });
      if (duplicate != candidate.end())
        continue;
      candidate.push_back(
          {.configured = true,
           .operational =
               system ? system_operational
                      : ports[address.port_ordinal].operational,
           .network = address.network,
           .interface_id = address.interface_id,
           .physical_port_ordinal = address.port_ordinal,
           .prefix_length = address.prefix_length});
    }
    output.swap(candidate);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace

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

bool RuntimeSupervisor::configure_interface(
    DeviceHandle device, std::string_view port_id, packet::Mac mac,
    std::uint32_t address, std::uint8_t prefix_length, bool admin_enabled,
    std::uint32_t arp_timeout_seconds,
    std::uint16_t arp_retry_deciseconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U ||
      arp_timeout_seconds > device_catalog::arp_timeout_maximum_seconds ||
      arp_retry_deciseconds < device_catalog::arp_retry_minimum_deciseconds ||
      arp_retry_deciseconds > device_catalog::arp_retry_maximum_deciseconds)
    return false;
  const auto ordinal_value = inventory->coordinate_ordinal(port_id);
  const auto *physical = inventory->find(port_id);
  if (!ordinal_value || !physical || !physical->speed_mbps)
    return false;
  auto &network = *router_network_[device.index];
  const auto ordinal = *ordinal_value;
  // The interface key is the stable physical ordinal. Removing its MDA leaves
  // control intent in this slot while forwarding operational state becomes
  // down. IPv4 and IPv6 are leaves of one routed interface. Updating one family
  // must preserve the other family's addresses and ND state projection.
  auto &port = network.ports[ordinal];
  port.configured = true;
  port.operational = false;
  port.ordinal = ordinal;
  port.mtu = physical->mtu;
  port.address = address;
  port.network = address & routing::prefix_mask(prefix_length);
  port.speed_mbps = physical->speed_mbps;
  port.prefix_length = prefix_length;
  port.mac = mac;
  port.arp_timeout_seconds = arp_timeout_seconds;
  port.arp_retry_deciseconds = arp_retry_deciseconds;
  port.ipv4_configured = true;
  network.interface_admin[ordinal] = admin_enabled;
  network.connected[ordinal] = {.configured = true,
                                .operational = false,
                                .network = address &
                                           routing::prefix_mask(prefix_length),
                                .port_ordinal = ordinal,
                                .prefix_length = prefix_length};
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_system_interface(
    DeviceHandle device, std::uint32_t address, bool admin_enabled) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  // Zero, multicast and the limited broadcast value cannot identify a local
  // unicast endpoint. The /32 length is structural in this API, so callers
  // cannot accidentally create a connected subnet without a physical medium.
  const bool multicast = (address & 0xf0000000U) == 0xe0000000U;
  if (!address || address == 0xffffffffU || multicast)
    return false;

  auto &state = *router_network_[device.index];
  auto &system = state.connected[routing::system_ipv4_connected_index];
  system = {.configured = true,
            .operational = admin_enabled,
            .network = address,
            // The ordinal is deliberately meaningless for a local route. The
            // local_system discriminator prevents every consumer from using it.
            .port_ordinal = 0U,
            .prefix_length = 32U,
            .local_system = true};
  rebuild_routes(device);
  return state.rib.last_rebuild_valid();
}

bool RuntimeSupervisor::remove_system_interface(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &state = *router_network_[device.index];
  auto &system = state.connected[routing::system_ipv4_connected_index];
  if (!system.configured || !system.local_system)
    return false;
  system = {};
  rebuild_routes(device);
  return state.rib.last_rebuild_valid();
}

bool RuntimeSupervisor::configure_system_ipv6_addresses(
    DeviceHandle device, std::span<const RouterIpv6Address> addresses,
    bool admin_enabled) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      addresses.size() > device_catalog::network_interface_ip_addresses)
    return false;
  if (std::any_of(addresses.begin(), addresses.end(), [](const auto &entry) {
        return entry.interface_id != system_interface_id ||
               entry.port_ordinal != system_interface_port_ordinal ||
               entry.prefix_length != ip::ipv6_address_bits ||
               ip::is_unspecified(entry.address) ||
               ip::is_multicast(entry.address) ||
               entry.network != entry.address;
      }))
    return false;

  auto &state = *router_network_[device.index];
  try {
    auto candidate_addresses = state.native_ipv6_addresses;
    std::erase_if(candidate_addresses, [](const auto &entry) {
      return entry.interface_id == system_interface_id;
    });
    candidate_addresses.insert(candidate_addresses.end(), addresses.begin(),
                               addresses.end());

    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    if (!build_native_ipv6_connected(candidate_addresses, state.ports,
                                     admin_enabled, candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected,
        {}, state.maximum_ecmp_paths));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate_addresses))
      return false;

    state.native_ipv6_addresses.swap(candidate_addresses);
    state.native_ipv6_connected.swap(candidate_connected);
    rebuild_routes(device);
    return state.ipv6_rib.last_rebuild_valid();
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::configure_ipv6_interface(
    DeviceHandle device, std::string_view port_id, packet::Mac mac,
    const packet::Ipv6 &address, std::uint8_t prefix_length,
    const packet::Ipv6 &link_local, bool admin_enabled) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(address) || ip::is_multicast(address) ||
      !ip::is_link_local(link_local))
    return false;
  const auto ordinal_value = inventory->coordinate_ordinal(port_id);
  const auto *physical = inventory->find(port_id);
  if (!ordinal_value || !physical || !physical->speed_mbps ||
      physical->mtu < packet::ipv6_minimum_ethernet_mtu)
    return false;

  auto &network = *router_network_[device.index];
  const auto ordinal = *ordinal_value;
  auto candidate_port = network.ports[ordinal];
  const bool previously_configured = candidate_port.configured;
  if (!previously_configured)
    candidate_port.ipv4_configured = false;
  candidate_port.configured = true;
  candidate_port.operational = false;
  candidate_port.ordinal = ordinal;
  candidate_port.mtu = physical->mtu;
  candidate_port.speed_mbps = physical->speed_mbps;
  candidate_port.mac = mac;
  candidate_port.ipv6_configured = true;
  candidate_port.ipv6_address = address;
  candidate_port.ipv6_network = ip::mask(address, prefix_length);
  candidate_port.ipv6_link_local = link_local;
  candidate_port.ipv6_prefix_length = prefix_length;
  const routing::Ipv6ConnectedInput selected_connected{
      .configured = true,
      .operational = false,
      .network = candidate_port.ipv6_network,
      .interface_id = physical_interface_id(ordinal),
      .physical_port_ordinal = ordinal,
      .prefix_length = prefix_length};
  try {
    auto candidate_addresses = network.native_ipv6_addresses;
    candidate_addresses.erase(
        std::remove_if(candidate_addresses.begin(), candidate_addresses.end(),
                       [&](const auto &configured) {
                         return configured.interface_id ==
                                physical_interface_id(ordinal);
                       }),
        candidate_addresses.end());
    candidate_addresses.push_back(
        {.address = address,
         .network = candidate_port.ipv6_network,
         .interface_id = physical_interface_id(ordinal),
         .primary_preference = 0U,
         .port_ordinal = ordinal,
         .prefix_length = prefix_length});
    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        network.native_ipv6_connected.begin(),
        network.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate_addresses, network.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    for (auto &connected : candidate_connected)
      if (connected.interface_id == physical_interface_id(ordinal))
        connected.operational = false;

    // Allocation and derivation are complete. Publish all control-owned
    // fields together before reconciliation emits the forwarding generation.
    network.ports[ordinal] = candidate_port;
    network.interface_admin[ordinal] = admin_enabled;
    network.ipv6_connected[ordinal] = selected_connected;
    network.native_ipv6_addresses.swap(candidate_addresses);
    network.native_ipv6_connected.swap(candidate_connected);
  } catch (const std::bad_alloc &) {
    return false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_address(
    DeviceHandle device, std::string_view port_id, const packet::Ipv6 &address,
    std::uint8_t prefix_length, std::uint32_t primary_preference,
    bool duplicate_address_detection,
    std::optional<std::uint32_t> tag) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(address) || ip::is_multicast(address) ||
      ip::is_link_local(address))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  const auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  try {
    auto candidate_addresses = state.native_ipv6_addresses;
    auto existing = std::find_if(
        candidate_addresses.begin(), candidate_addresses.end(),
        [&](const auto &configured) { return configured.address == address; });
    if (existing != candidate_addresses.end() &&
        existing->interface_id != physical_interface_id(*ordinal))
      return false;
    const auto on_interface = static_cast<std::size_t>(std::count_if(
        candidate_addresses.begin(), candidate_addresses.end(),
        [&](const auto &configured) {
          return configured.interface_id == physical_interface_id(*ordinal);
        }));
    // The documented sixteen-address ceiling is shared with IPv4. Updating an
    // existing record consumes no resource; a new IPv6 record accounts for the
    // native IPv4 address already present on the same routed interface.
    if (existing == candidate_addresses.end() &&
        on_interface + (port.ipv4_configured ? 1U : 0U) >=
            device_catalog::network_interface_ip_addresses)
      return false;
    const RouterIpv6Address replacement{
        .address = address,
        .network = ip::mask(address, prefix_length),
        .interface_id = physical_interface_id(*ordinal),
        .primary_preference = primary_preference,
        .tag = tag.value_or(0U),
        .port_ordinal = *ordinal,
        .prefix_length = prefix_length,
        .duplicate_address_detection = duplicate_address_detection,
        .tag_configured = tag.has_value()};
    if (existing == candidate_addresses.end())
      candidate_addresses.push_back(replacement);
    else
      *existing = replacement;

    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        state.native_ipv6_connected.begin(),
        state.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate_addresses, state.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate_addresses))
      return false;
    state.native_ipv6_addresses.swap(candidate_addresses);
    state.native_ipv6_connected.swap(candidate_connected);

    // The lowest preference cache is updated only after the complete address
    // generation is live. A leaf edit can never expose a port primary that the
    // forwarding table rejected.
    const RouterIpv6Address *primary{};
    for (const auto &configured : state.native_ipv6_addresses)
      if (configured.interface_id == physical_interface_id(*ordinal) &&
          (!primary ||
           configured.primary_preference < primary->primary_preference ||
           (configured.primary_preference == primary->primary_preference &&
            configured.address < primary->address)))
        primary = &configured;
    if (primary) {
      state.ports[*ordinal].ipv6_address = primary->address;
      state.ports[*ordinal].ipv6_network = primary->network;
      state.ports[*ordinal].ipv6_prefix_length = primary->prefix_length;
    }
    rebuild_routes(device);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::remove_ipv6_address(
    DeviceHandle device, std::string_view port_id,
    const packet::Ipv6 &address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  try {
    auto candidate = state.native_ipv6_addresses;
    const auto removed = std::erase_if(candidate, [&](const auto &configured) {
      return configured.interface_id == physical_interface_id(*ordinal) &&
             configured.address == address;
    });
    if (removed != 1U || std::none_of(candidate.begin(), candidate.end(),
                                      [&](const auto &value) {
                                        return value.interface_id ==
                                               physical_interface_id(*ordinal);
                                      }))
      return false;
    std::vector<routing::Ipv6ConnectedInput> candidate_connected;
    const bool system_operational = std::any_of(
        state.native_ipv6_connected.begin(),
        state.native_ipv6_connected.end(), [](const auto &entry) {
          return entry.interface_id == system_interface_id &&
                 entry.operational;
        });
    if (!build_native_ipv6_connected(candidate, state.ports,
                                     system_operational,
                                     candidate_connected))
      return false;
    auto candidate_rib = std::unique_ptr<routing::Ipv6RouteTable>{
        new (std::nothrow) routing::Ipv6RouteTable{}};
    if (!candidate_rib)
      return false;
    static_cast<void>(candidate_rib->rebuild(
        candidate_connected, state.ipv6_statics, state.ies_ipv6_connected));
    if (!candidate_rib->last_rebuild_valid() ||
        !program_ipv6_address_generation(device, candidate))
      return false;
    state.native_ipv6_addresses.swap(candidate);
    state.native_ipv6_connected.swap(candidate_connected);
    const auto *primary = [&]() -> const RouterIpv6Address * {
      const RouterIpv6Address *selected{};
      for (const auto &configured : state.native_ipv6_addresses)
        if (configured.interface_id == physical_interface_id(*ordinal) &&
            (!selected ||
             configured.primary_preference < selected->primary_preference ||
             (configured.primary_preference == selected->primary_preference &&
              configured.address < selected->address)))
          selected = &configured;
      return selected;
    }();
    state.ports[*ordinal].ipv6_address = primary->address;
    state.ports[*ordinal].ipv6_network = primary->network;
    state.ports[*ordinal].ipv6_prefix_length = primary->prefix_length;
    rebuild_routes(device);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool RuntimeSupervisor::remove_ipv6_interface(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // RA is an IPv6-interface child. Remove the forwarding-owned timer before
  // clearing the address family so no advertisement can be emitted between
  // the two owner turns. Failure leaves every control-owned field unchanged.
  if (state.router_advertisements[*ordinal].configured) {
    auto &remove_ra = prepare(NetworkCommandKind::remove_router_advertisement);
    remove_ra.device = device;
    remove_ra.port.ordinal = *ordinal;
    const auto result = dispatch(remove_ra);
    if (!result || !result->success)
      return false;
    state.router_advertisements[*ordinal] = {};
  }
  // MLD is also bound to the routed IPv6 interface, but it is a distinct
  // protocol context in SR OS. Withdraw it explicitly before its source
  // link-local address disappears. This prevents a final Query from being
  // emitted with an address that control has already removed.
  if (state.mld_interfaces[*ordinal].configured) {
    auto &remove_mld = prepare(NetworkCommandKind::remove_mld_interface);
    remove_mld.device = device;
    remove_mld.port.ordinal = *ordinal;
    const auto result = dispatch(remove_mld);
    if (!result || !result->success)
      return false;
    state.mld_interfaces[*ordinal] = {};
  }
  if (state.dhcpv6_relays[*ordinal] && !remove_dhcpv6_relay(device, port_id))
    return false;
  port.ipv6_configured = false;
  port.ipv6_address = {};
  port.ipv6_network = {};
  port.ipv6_link_local = {};
  port.ipv6_prefix_length = 0;
  port.ipv6_unsolicited_learning = Ipv6UnsolicitedLearning::none;
  port.nd_reachable_time_milliseconds = static_cast<std::uint32_t>(
      device_catalog::nd_base_reachable_time.count());
  port.nd_stale_time_seconds = device_catalog::nd_default_stale_time_seconds;
  port.ipv6_proactive_refresh = Ipv6UnsolicitedLearning::none;
  port.ipv6_neighbor_limit = 0U;
  port.ipv6_neighbor_limit_threshold_percent =
      device_catalog::nd_default_neighbor_limit_threshold_percent;
  port.ipv6_neighbor_limit_configured = false;
  port.ipv6_neighbor_limit_log_only = false;
  state.ipv6_connected[*ordinal] = {};
  std::erase_if(state.native_ipv6_addresses, [&](const auto &configured) {
    return configured.interface_id == physical_interface_id(*ordinal);
  });
  std::erase_if(state.native_ipv6_connected, [&](const auto &configured) {
    return configured.interface_id == physical_interface_id(*ordinal);
  });
  if (!port.ipv4_configured && !state.ies_port_owned[*ordinal]) {
    port = {};
    state.interface_admin[*ordinal] = false;
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = *ordinal;
    const auto result = dispatch(remove);
    rebuild_routes(device);
    return result && result->success;
  }
  if (!port.ipv4_configured) {
    // Removing the final native address family must not remove a physical
    // access port still owned by IES. A service interface carries its own MAC,
    // so retaining the former native source MAC here would create an identity
    // that no longer exists in configuration.
    port.mac = {};
    state.interface_admin[*ordinal] = false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_redirects(
    DeviceHandle device, std::string_view port_id, bool enabled,
    std::uint16_t maximum, std::uint16_t interval_seconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      maximum < device_catalog::icmp6_redirect_minimum_maximum ||
      maximum > device_catalog::icmp6_redirect_maximum_maximum ||
      interval_seconds <
          device_catalog::icmp6_redirect_minimum_interval.count() ||
      interval_seconds >
          device_catalog::icmp6_redirect_maximum_interval.count())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // The control owner changes the complete tuple before one refresh command.
  // RouterForwarder validates it again and resets only the affected port's
  // rate window, while an unchanged IPv6 identity keeps its completed DAD.
  port.icmp6_redirects_enabled = enabled;
  port.icmp6_redirect_maximum = maximum;
  port.icmp6_redirect_interval_seconds = interval_seconds;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv4_redirects(
    DeviceHandle device, std::string_view port_id, bool enabled,
    std::uint16_t maximum, std::uint16_t interval_seconds) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      maximum < device_catalog::icmp_redirect_minimum_maximum ||
      maximum > device_catalog::icmp_redirect_maximum_maximum ||
      interval_seconds <
          device_catalog::icmp_redirect_minimum_interval.count() ||
      interval_seconds > device_catalog::icmp_redirect_maximum_interval.count())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // The complete policy tuple crosses the existing whole-port projection.
  // No separate mutable limiter state is exposed to the control shard.
  port.icmp_redirects_enabled = enabled;
  port.icmp_redirect_maximum = maximum;
  port.icmp_redirect_interval_seconds = interval_seconds;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_ipv6_neighbor_policy(
    DeviceHandle device, std::string_view port_id,
    std::uint32_t reachable_time_seconds, std::uint32_t stale_time_seconds,
    Ipv6UnsolicitedLearning unsolicited_learning,
    Ipv6UnsolicitedLearning proactive_refresh, bool limit_configured,
    std::uint32_t limit, bool limit_log_only,
    std::uint8_t limit_threshold_percent) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      reachable_time_seconds <
          device_catalog::nd_minimum_reachable_time_seconds ||
      reachable_time_seconds >
          device_catalog::nd_maximum_reachable_time_seconds ||
      stale_time_seconds < device_catalog::nd_minimum_stale_time_seconds ||
      stale_time_seconds > device_catalog::nd_maximum_stale_time_seconds ||
      unsolicited_learning > Ipv6UnsolicitedLearning::both ||
      proactive_refresh > Ipv6UnsolicitedLearning::both ||
      limit > device_catalog::nd_maximum_neighbor_limit ||
      limit_threshold_percent > 100U ||
      (!limit_configured &&
       (limit != 0U || limit_log_only ||
        limit_threshold_percent !=
            device_catalog::nd_default_neighbor_limit_threshold_percent)))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;
  // The complete policy tuple is replaced before one forwarding refresh.
  // Packet processing can therefore see either the old or new settings but
  // never a reachable timer paired with stale limit metadata from another
  // configuration generation.
  port.nd_reachable_time_milliseconds = reachable_time_seconds * 1000U;
  port.nd_stale_time_seconds = stale_time_seconds;
  port.ipv6_unsolicited_learning = unsolicited_learning;
  port.ipv6_proactive_refresh = proactive_refresh;
  port.ipv6_neighbor_limit_configured = limit_configured;
  port.ipv6_neighbor_limit = limit;
  port.ipv6_neighbor_limit_log_only = limit_log_only;
  port.ipv6_neighbor_limit_threshold_percent = limit_threshold_percent;
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::configure_router_advertisement(
    DeviceHandle device, std::string_view port_id, bool enabled,
    const packet::nd::RouterAdvertisementConfig &config) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.ports[*ordinal].configured ||
      !state.ports[*ordinal].ipv6_configured)
    return false;

  // Forwarding validates wire fields and interval relationships before the
  // control owner publishes intent. A rejected command leaves the prior
  // configuration untouched in both owners.
  auto &command = prepare(NetworkCommandKind::configure_router_advertisement);
  command.device = device;
  command.fib = RouterAdvertisementProgram{.device = device,
                                           .config = config,
                                           .port_ordinal = *ordinal,
                                           .enabled = enabled};
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.router_advertisements[*ordinal] = {
      .config = config, .configured = true, .enabled = enabled};
  return true;
}

bool RuntimeSupervisor::remove_router_advertisement(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.router_advertisements[*ordinal].configured)
    return false;

  // The forwarding owner acknowledges removal before control drops its copy.
  // This ordering makes a failed transaction observable and checkpoint-safe.
  auto &command = prepare(NetworkCommandKind::remove_router_advertisement);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.router_advertisements[*ordinal] = {};
  return true;
}

bool RuntimeSupervisor::configure_mld_interface(
    DeviceHandle device, std::string_view port_id,
    const MldRouterConfiguration &configuration) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  const auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv6_configured ||
      !ip::is_link_local(port.ipv6_link_local))
    return false;

  // Interface identity is owned by the inventory and IPv6 interface owners.
  // Replace both derived fields so a caller cannot aim MLD at another port or
  // advertise a fabricated Querier address. Timer, version and admin intent
  // remain caller supplied and are validated by MldRouterInterface.
  auto resolved = configuration;
  resolved.port_ordinal = *ordinal;
  resolved.link_local_address = port.ipv6_link_local;
  auto &command = prepare(NetworkCommandKind::configure_mld_interface);
  command.device = device;
  command.fib =
      MldInterfaceProgram{.device = device, .configuration = resolved};
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.mld_interfaces[*ordinal] = {.configuration = resolved,
                                    .ssm_translations = {},
                                    .import_policy = {},
                                    .configured = true};
  return true;
}

bool RuntimeSupervisor::configure_ospf_generation(
    DeviceHandle device, std::span<const OspfProcessProgram> processes,
    std::span<const OspfInterfaceProgram> interfaces,
    std::span<const OspfAuthenticationProgram> authentications,
    std::span<const OspfNbmaNeighborProgram> nbma_neighbors,
    std::span<const OspfVirtualLinkProgram> virtual_links,
    std::span<const OspfAreaRangeProgram> ranges,
    std::span<const OspfExternalRouteProgram> external_routes) noexcept {
  if (!devices_.get(device) ||
      processes.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max() ||
      authentications.size() > std::numeric_limits<std::uint32_t>::max() ||
      nbma_neighbors.size() > std::numeric_limits<std::uint32_t>::max() ||
      virtual_links.size() > std::numeric_limits<std::uint32_t>::max() ||
      ranges.size() > std::numeric_limits<std::uint32_t>::max() ||
      external_routes.size() > std::numeric_limits<std::uint32_t>::max())
    return false;

  auto &begin = prepare(NetworkCommandKind::begin_ospf_generation);
  begin.device = device;
  begin.fib = NetworkOspfGenerationBegin{
      .expected_processes =
          static_cast<std::uint32_t>(processes.size()),
      .expected_interfaces =
          static_cast<std::uint32_t>(interfaces.size()),
      .expected_authentications =
          static_cast<std::uint32_t>(authentications.size()),
      .expected_nbma_neighbors =
          static_cast<std::uint32_t>(nbma_neighbors.size()),
      .expected_virtual_links =
          static_cast<std::uint32_t>(virtual_links.size()),
      .expected_ranges =
          static_cast<std::uint32_t>(ranges.size()),
      .expected_external_routes =
          static_cast<std::uint32_t>(external_routes.size())};
  auto result = dispatch(begin);
  for (const auto &process : processes) {
    if (!result || !result->success || process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_process);
    add.device = device;
    add.fib = process;
    result = dispatch(add);
  }
  for (const auto &interface : interfaces) {
    if (!result || !result->success ||
        interface.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_interface);
    add.device = device;
    add.fib = interface;
    result = dispatch(add);
  }
  for (const auto &authentication : authentications) {
    if (!result || !result->success ||
        authentication.process.device != device)
      break;
    auto &add =
        prepare(NetworkCommandKind::add_ospf_authentication);
    add.device = device;
    add.fib = authentication;
    result = dispatch(add);
  }
  for (const auto &neighbor : nbma_neighbors) {
    if (!result || !result->success ||
        neighbor.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_nbma_neighbor);
    add.device = device;
    add.fib = neighbor;
    result = dispatch(add);
  }
  for (const auto &virtual_link : virtual_links) {
    if (!result || !result->success ||
        virtual_link.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_virtual_link);
    add.device = device;
    add.fib = virtual_link;
    result = dispatch(add);
  }
  for (const auto &range : ranges) {
    if (!result || !result->success ||
        range.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_area_range);
    add.device = device;
    add.fib = range;
    result = dispatch(add);
  }
  for (const auto &external : external_routes) {
    if (!result || !result->success ||
        external.process.device != device)
      break;
    auto &add = prepare(NetworkCommandKind::add_ospf_external_route);
    add.device = device;
    add.fib = external;
    result = dispatch(add);
  }
  if (result && result->success) {
    auto &commit = prepare(NetworkCommandKind::commit_ospf_generation);
    commit.device = device;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }

  // Abort is idempotent and never touches the active generation. The result is
  // deliberately ignored because the original rejected transaction is the
  // caller-visible failure.
  auto &abort = prepare(NetworkCommandKind::abort_ospf_generation);
  abort.device = device;
  static_cast<void>(dispatch(abort));
  return false;
}

std::optional<ospf::ControlResult>
RuntimeSupervisor::query_ospf(
    DeviceHandle device, const OspfOperationalQuery &query) noexcept {
  if (!devices_.get(device))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::query_ospf);
  command.device = device;
  command.fib = query;
  const auto result = dispatch(command);
  return result && result->success
             ? std::optional<ospf::ControlResult>{result->ospf}
             : std::nullopt;
}

bool RuntimeSupervisor::remove_mld_interface(
    DeviceHandle device, std::string_view port_id) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &state = *router_network_[device.index];
  if (!state.mld_interfaces[*ordinal].configured)
    return false;

  // Acknowledgement precedes intent removal, preserving an exact rollback
  // point when the bounded cross-shard command cannot be accepted.
  auto &command = prepare(NetworkCommandKind::remove_mld_interface);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  state.mld_interfaces[*ordinal] = {};
  return true;
}

bool RuntimeSupervisor::program_sap_generation(
    DeviceHandle device, std::span<const service::SapAttachment> attachments,
    std::span<const service::ServiceIpv6Interface> interfaces) noexcept {
  if (!devices_.get(device) ||
      attachments.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max())
    return false;

  // Begin declares both cardinalities before one value is copied. The network
  // worker reserves its private staging vectors once, acknowledges each SPSC
  // record in order, and publishes only when Commit observes both exact sets.
  auto &begin = prepare(NetworkCommandKind::begin_sap_generation);
  begin.device = device;
  begin.fib = SapGenerationBegin{
      .expected_attachments = static_cast<std::uint32_t>(attachments.size()),
      .expected_interfaces = static_cast<std::uint32_t>(interfaces.size())};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;

  for (const auto &attachment : attachments) {
    auto &command = prepare(NetworkCommandKind::add_sap_attachment);
    command.device = device;
    command.fib = attachment;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_sap_generation;
  }
  for (const auto &interface : interfaces) {
    auto &command = prepare(NetworkCommandKind::add_service_ipv6_interface);
    command.device = device;
    command.fib = interface;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_sap_generation;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_sap_generation);
    command.device = device;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }

abort_sap_generation: {
  // Abort is idempotent after a failed Commit and is mandatory after a
  // rejected value record. A later candidate can never inherit a prefix of
  // this generation from the network owner's private staging storage.
  auto &command = prepare(NetworkCommandKind::abort_sap_generation);
  command.device = device;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::program_ipv6_address_generation(
    DeviceHandle device,
    std::span<const RouterIpv6Address> addresses) noexcept {
  if (!device || addresses.size() > RouterIpv6AddressTable::capacity)
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_ipv6_address_generation);
  begin.device = device;
  begin.fib =
      Ipv6AddressGenerationBegin{static_cast<std::uint32_t>(addresses.size())};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &address : addresses) {
    auto &add = prepare(NetworkCommandKind::add_ipv6_interface_address);
    add.device = device;
    add.fib = address;
    result = dispatch(add);
    if (!result || !result->success)
      goto abort_ipv6_addresses;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_ipv6_address_generation);
    commit.device = device;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }

abort_ipv6_addresses: {
  // Abort is safe after a failed Commit. Both lower owners treat it as a
  // terminal cleanup and never retain a prefix for a later generation.
  auto &abort = prepare(NetworkCommandKind::abort_ipv6_address_generation);
  abort.device = device;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::configure_ies_services(
    DeviceHandle device, const service::Configuration &configuration) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      service::validate(configuration) != service::ValidationError::none)
    return false;
  auto &state = *router_network_[device.index];

  service::Configuration candidate_configuration;
  auto candidate_ports = state.ports;
  std::array<bool, device_catalog::maximum_ports_per_router>
      candidate_port_ownership{};
  std::vector<service::SapAttachment> candidate_attachments;
  std::vector<service::ServiceIpv6Interface> candidate_interfaces;
  std::vector<routing::Ipv6ConnectedInput> candidate_connected;
  std::vector<dhcpv6::RelayInterfaceConfig> candidate_relays;
  try {
    candidate_configuration = configuration;
    std::size_t interface_count{};
    for (const auto &service : configuration.ies_services)
      interface_count += service.interfaces.size();
    candidate_attachments.reserve(interface_count);
    candidate_interfaces.reserve(interface_count);
    candidate_connected.reserve(interface_count);
    candidate_relays.reserve(interface_count);

    // Configuration stores both visible card/MDA/port coordinates and the
    // dense runtime ordinal. Validate their relation against this router's
    // hardware owner before allowing either identity to reach forwarding.
    for (const auto &port_configuration : configuration.ports) {
      const auto ordinal = port_configuration.coordinate.ordinal;
      const auto *hardware_port = inventory->at(ordinal);
      if (!hardware_port ||
          hardware_port->card_slot != port_configuration.coordinate.card ||
          hardware_port->mda_slot != port_configuration.coordinate.mda ||
          hardware_port->port_number != port_configuration.coordinate.port)
        return false;

      // Port configuration and a routed interface are separate SR OS
      // objects. An access port therefore needs a forwarding projection even
      // when it has no native IPv4 or IPv6 child. Keep the physical object
      // address-free and let the SAP generation supply each logical L3 MAC
      // and address. This prevents one arbitrary SAP from becoming a fake
      // native interface on a port that can host several tagged services.
      if (!hardware_port->present)
        continue;
      candidate_port_ownership[ordinal] = true;
      auto &candidate_port = candidate_ports[ordinal];
      if (!candidate_port.configured) {
        candidate_port = {};
        candidate_port.configured = true;
        candidate_port.ipv4_configured = false;
        candidate_port.ordinal = ordinal;
      }
      candidate_port.mtu = hardware_port->mtu;
      candidate_port.speed_mbps = hardware_port->speed_mbps;
      candidate_port.operational =
          hardware_port->configuration_compatible &&
          hardware_port->hierarchy_enabled && hardware_port->admin_enabled &&
          hardware_port->link_signal &&
          (state.interface_admin[ordinal] || candidate_port_ownership[ordinal]);
    }

    // Retiring service ownership must not remove a native routed interface.
    // Conversely, a port that existed solely for an old IES generation is
    // cleared in the candidate control image after the new SAP generation has
    // stopped referencing it.
    for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal)
      if (state.ies_port_owned[ordinal] && !candidate_port_ownership[ordinal] &&
          !candidate_ports[ordinal].ipv4_configured &&
          !candidate_ports[ordinal].ipv6_configured)
        candidate_ports[ordinal] = {};

    const auto configured_local_source = [&](const packet::Ipv6 &address) {
      for (const auto &service : configuration.ies_services)
        for (const auto &interface : service.interfaces)
          if (interface.address_configured &&
              (interface.address == address || interface.link_local == address))
            return true;
      for (const auto &port : state.ports)
        if (port.configured && port.ipv6_configured &&
            (port.ipv6_address == address || port.ipv6_link_local == address))
          return true;
      return false;
    };

    for (const auto &ies : configuration.ies_services) {
      for (const auto &interface : ies.interfaces) {
        // Classic CLI permits creation of an IP interface before its SAP.
        // Such intent is real running configuration but owns no forwarding
        // classifier or physical port until the attachment is configured.
        if (interface.sap.port.card == 0U && interface.sap.port.mda == 0U &&
            interface.sap.port.port == 0U)
          continue;
        const auto ordinal = interface.sap.port.ordinal;
        if (ordinal >= state.ports.size())
          return false;
        const auto port_configuration =
            std::find_if(configuration.ports.begin(), configuration.ports.end(),
                         [&](const auto &port) {
                           return port.coordinate == interface.sap.port;
                         });
        if (port_configuration == configuration.ports.end())
          return false;

        // Intent on an unequipped card remains in candidate_configuration but
        // cannot become a live SAP classifier. refresh_router republishes the
        // same retained graph after the physical owner reports the port again.
        const auto &physical = candidate_ports[ordinal];
        if (!candidate_port_ownership[ordinal] || !physical.configured)
          continue;
        candidate_attachments.push_back(
            {.logical_interface_id = interface.logical_id,
             .sap = interface.sap,
             .outer_tpid = port_configuration->outer_tpid,
             .inner_tpid = static_cast<std::uint16_t>(
                 interface.sap.encapsulation ==
                         service::EthernetEncapsulation::qinq
                     ? packet::ethernet_type_customer_vlan
                     : 0U)});
        const bool operational = interface.address_configured &&
                                 ies.admin_enabled && interface.admin_enabled &&
                                 physical.operational;
        candidate_interfaces.push_back(
            {.interface_id = interface.logical_id,
             .physical_port_ordinal = ordinal,
             .mtu = interface.ip_mtu,
             .mac = interface.mac,
             .address = interface.address,
             .network =
                 interface.address_configured
                     ? ip::mask(interface.address, interface.prefix_length)
                     : packet::Ipv6{},
             .link_local = interface.link_local,
             .prefix_length = interface.prefix_length,
             .nd_reachable_time_milliseconds =
                 device_catalog::nd_default_reachable_time_seconds * 1000U,
             .nd_stale_time_seconds =
                 device_catalog::nd_default_stale_time_seconds,
             .neighbor_limit_threshold_percent =
                 device_catalog::nd_default_neighbor_limit_threshold_percent,
             .redirect_maximum = device_catalog::icmp6_redirect_default_maximum,
             .redirect_interval_seconds = static_cast<std::uint16_t>(
                 device_catalog::icmp6_redirect_default_interval.count()),
             .redirects_enabled = true,
             .configured = interface.address_configured,
             .operational = operational});
        if (interface.address_configured)
          candidate_connected.push_back(
              {.configured = true,
               .operational = operational,
               .network = ip::mask(interface.address, interface.prefix_length),
               .interface_id = interface.logical_id,
               .physical_port_ordinal = ordinal,
               .prefix_length = interface.prefix_length});

        const auto &relay_intent = interface.dhcpv6_relay;
        if (!relay_intent.configured || !relay_intent.admin_enabled ||
            relay_intent.servers.empty() || !operational)
          continue;
        const auto interface_id =
            service::relay_interface_id(configuration, ies, interface);
        if (!interface_id ||
            (relay_intent.source_address &&
             !configured_local_source(*relay_intent.source_address)))
          return false;
        dhcpv6::RelayInterfaceConfig relay{
            .interface_id = interface.logical_id,
            .physical_port_ordinal = ordinal,
            .link_address =
                relay_intent.link_address.value_or(interface.address),
            .source_address =
                relay_intent.source_address.value_or(packet::Ipv6{}),
            .has_source_address = relay_intent.source_address.has_value(),
            .relay_interface_id = std::move(*interface_id),
            .server_count = relay_intent.servers.size(),
            .upstream_policy =
                dhcpv6::RelayUpstreamPolicy::explicit_servers_required,
            .client_prefix = {.network = ip::mask(interface.address,
                                                  interface.prefix_length),
                              .length = interface.prefix_length},
            .lease_population_limit = relay_intent.lease_population_limit,
            .neighbor_resolution = relay_intent.neighbor_resolution,
            .route_non_temporary = relay_intent.route_populate_na,
            .route_temporary = relay_intent.route_populate_ta,
            .route_delegated_prefix = relay_intent.route_populate_pd,
            .route_prefix_exclude = relay_intent.route_populate_pd_exclude};
        std::copy(relay_intent.servers.begin(), relay_intent.servers.end(),
                  relay.servers.begin());
        candidate_relays.push_back(std::move(relay));
      }
    }

    // Route admission is checked before any forwarding publication. This
    // prevents a valid SAP generation from becoming live when the combined
    // native, service and static RIB would exceed its profiled capacity.
    auto candidate_rib = std::make_unique<routing::Ipv6RouteTable>();
    static_cast<void>(candidate_rib->rebuild(
        state.native_ipv6_connected, state.ipv6_statics, candidate_connected));
    if (!candidate_rib->last_rebuild_valid())
      return false;
  } catch (const std::bad_alloc &) {
    return false;
  }

  // Publish every physical prerequisite before the atomic SAP generation.
  // Old service-only ports remain installed until after that generation is
  // replaced, so no live classifier ever points at a removed physical port.
  std::array<bool, device_catalog::maximum_ports_per_router>
      candidate_port_published{};
  for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal) {
    if (!candidate_ports[ordinal].configured ||
        (!candidate_port_ownership[ordinal] && !state.ies_port_owned[ordinal]))
      continue;
    auto &configure = prepare(NetworkCommandKind::configure_port);
    configure.device = device;
    configure.port = candidate_ports[ordinal];
    const auto result = dispatch(configure);
    if (!result || !result->success) {
      // Only earlier records were accepted. Restore those exact records in
      // reverse ownership order before reporting a failed transaction.
      for (std::size_t rollback_ordinal = 0;
           rollback_ordinal < candidate_port_published.size();
           ++rollback_ordinal) {
        if (!candidate_port_published[rollback_ordinal])
          continue;
        auto &restore = prepare(state.ports[rollback_ordinal].configured
                                    ? NetworkCommandKind::configure_port
                                    : NetworkCommandKind::remove_port);
        restore.device = device;
        restore.port = state.ports[rollback_ordinal].configured
                           ? state.ports[rollback_ordinal]
                           : ForwardPort{.ordinal = static_cast<std::uint16_t>(
                                             rollback_ordinal)};
        static_cast<void>(dispatch(restore));
      }
      return false;
    }
    candidate_port_published[ordinal] = true;
  }

  const auto rollback = [&]() noexcept {
    // Remove every candidate relay first while its candidate SAP still owns
    // the logical interface. Then restore the prior SAP generation and its
    // complete relay set. Each operation is best effort because the caller
    // already receives failure, but no successful candidate state is retained
    // intentionally.
    for (const auto &relay : candidate_relays) {
      auto &remove = prepare(NetworkCommandKind::remove_dhcpv6_relay);
      remove.device = device;
      remove.logical_interface_id = relay.interface_id;
      static_cast<void>(dispatch(remove));
    }
    // Restore old configured physical records first because the old SAP
    // generation is validated against them. Candidate-only ports deliberately
    // remain until that old generation has displaced every candidate SAP.
    for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
      if (!candidate_port_published[ordinal] ||
          !state.ports[ordinal].configured)
        continue;
      auto &restore = prepare(NetworkCommandKind::configure_port);
      restore.device = device;
      restore.port = state.ports[ordinal];
      static_cast<void>(dispatch(restore));
    }
    static_cast<void>(program_sap_generation(device, state.ies_sap_attachments,
                                             state.ies_ipv6_interfaces));
    for (std::size_t ordinal = 0; ordinal < state.ports.size(); ++ordinal) {
      if (!candidate_port_published[ordinal] || state.ports[ordinal].configured)
        continue;
      auto &remove = prepare(NetworkCommandKind::remove_port);
      remove.device = device;
      remove.port.ordinal = static_cast<std::uint16_t>(ordinal);
      static_cast<void>(dispatch(remove));
    }
    for (const auto &relay : state.ies_dhcpv6_relays)
      static_cast<void>(program_dhcpv6_relay(
          device, relay.physical_port_ordinal, relay, false));
  };

  if (!program_sap_generation(device, candidate_attachments,
                              candidate_interfaces)) {
    rollback();
    return false;
  }
  for (const auto &relay : candidate_relays)
    if (!program_dhcpv6_relay(device, relay.physical_port_ordinal, relay,
                              false)) {
      rollback();
      return false;
    }
  for (const auto &old : state.ies_dhcpv6_relays) {
    const auto retained =
        std::find_if(candidate_relays.begin(), candidate_relays.end(),
                     [&](const auto &relay) {
                       return relay.interface_id == old.interface_id;
                     });
    if (retained != candidate_relays.end())
      continue;
    auto &remove = prepare(NetworkCommandKind::remove_dhcpv6_relay);
    remove.device = device;
    remove.logical_interface_id = old.interface_id;
    const auto result = dispatch(remove);
    if (!result || !result->success) {
      rollback();
      return false;
    }
  }

  for (std::size_t ordinal = 0; ordinal < candidate_ports.size(); ++ordinal) {
    if (!state.ies_port_owned[ordinal] || candidate_port_ownership[ordinal] ||
        candidate_ports[ordinal].configured)
      continue;
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = static_cast<std::uint16_t>(ordinal);
    const auto result = dispatch(remove);
    if (!result || !result->success) {
      rollback();
      return false;
    }
  }

  // Every move publishes a fully built cold-path value without allocation.
  // The forwarding owner has already acknowledged the corresponding packet
  // generation, so control can now make it the source for CLI and checkpoint.
  state.ies_configuration = std::move(candidate_configuration);
  state.ports = candidate_ports;
  state.ies_port_owned = candidate_port_ownership;
  state.ies_sap_attachments = std::move(candidate_attachments);
  state.ies_ipv6_interfaces = std::move(candidate_interfaces);
  state.ies_ipv6_connected = std::move(candidate_connected);
  state.ies_dhcpv6_relays = std::move(candidate_relays);
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::configure_dhcpv6_relay(
    DeviceHandle device, std::string_view port_id,
    const dhcpv6::RelayInterfaceConfig &configuration) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  return ordinal && program_dhcpv6_relay(device, *ordinal, configuration);
}

bool RuntimeSupervisor::program_dhcpv6_relay(
    DeviceHandle device, std::uint16_t port_ordinal,
    const dhcpv6::RelayInterfaceConfig &configuration,
    bool retain_legacy_port_intent) noexcept {
  if (device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      port_ordinal >= router_network_[device.index]->ports.size())
    return false;
  const auto &port = router_network_[device.index]->ports[port_ordinal];
  if ((retain_legacy_port_intent &&
       (!port.configured || !port.ipv6_configured)) ||
      configuration.interface_id == 0U ||
      configuration.relay_interface_id.size() >
          std::numeric_limits<std::uint16_t>::max() ||
      configuration.server_count > configuration.servers.size())
    return false;

  // A full IES transaction publishes its candidate physical port and SAP
  // generation before the relay child, while the old control generation stays
  // visible until every forwarding command succeeds. In that path the
  // forwarding owner validates the just-published logical interface. Requiring
  // the old control port here would break transaction atomicity and force a
  // fake native IPv6 child onto a service-only access port.

  // Copy the value before touching the forwarding owner. If allocation fails,
  // the old generation remains active on both owners. Once commit succeeds,
  // moving this staged value into the fixed control slot cannot allocate.
  auto staged = std::optional<dhcpv6::RelayInterfaceConfig>{};
  try {
    staged = configuration;
    // Hardware resolution is authoritative. A caller cannot route the relay
    // through a different physical port by embedding a conflicting ordinal.
    staged->physical_port_ordinal = port_ordinal;
  } catch (const std::bad_alloc &) {
    return false;
  }

  // The begin record declares the complete generation before any variable
  // data is accepted. Every following command is synchronously acknowledged,
  // so failure can abort without publishing a prefix of Interface-Id or a
  // partial server list. The forwarding owner swaps generations only at
  // commit after the declared counts match exactly.
  auto &begin_command = prepare(NetworkCommandKind::begin_dhcpv6_relay);
  begin_command.device = device;
  begin_command.fib = Dhcpv6RelayBegin{
      .interface_id = configuration.interface_id,
      .physical_port_ordinal = port_ordinal,
      .link_address = configuration.link_address,
      .source_address = configuration.source_address,
      .client_prefix = configuration.client_prefix,
      .expected_interface_id_octets =
          static_cast<std::uint32_t>(configuration.relay_interface_id.size()),
      .expected_servers =
          static_cast<std::uint16_t>(configuration.server_count),
      .lease_population_limit = configuration.lease_population_limit,
      .has_source_address = configuration.has_source_address,
      .neighbor_resolution = configuration.neighbor_resolution,
      .route_non_temporary = configuration.route_non_temporary,
      .route_temporary = configuration.route_temporary,
      .route_delegated_prefix = configuration.route_delegated_prefix,
      .route_prefix_exclude = configuration.route_prefix_exclude,
      .upstream_policy = configuration.upstream_policy};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;

  for (std::size_t offset = 0; offset < configuration.relay_interface_id.size();
       offset += dhcpv6_relay_program_chunk_octets) {
    Dhcpv6RelayInterfaceIdChunk chunk;
    chunk.size = static_cast<std::uint16_t>(
        std::min(dhcpv6_relay_program_chunk_octets,
                 configuration.relay_interface_id.size() - offset));
    std::copy_n(configuration.relay_interface_id.begin() + offset, chunk.size,
                chunk.octets.begin());
    auto &command = prepare(NetworkCommandKind::add_dhcpv6_relay_interface_id);
    command.device = device;
    command.fib = chunk;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_relay;
  }
  for (std::size_t index = 0; index < configuration.server_count; ++index) {
    auto &command = prepare(NetworkCommandKind::add_dhcpv6_relay_server);
    command.device = device;
    command.fib = configuration.servers[index];
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_relay;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_dhcpv6_relay);
    command.device = device;
    result = dispatch(command);
    if (result && result->success) {
      if (!retain_legacy_port_intent)
        return true;
      auto &state = *router_network_[device.index];
      state.dhcpv6_relays[port_ordinal] = std::move(staged);
      // Regular relay is an IES-interface child, not an independent port
      // protocol. Publish the same stable logical identity to the RIB so ND,
      // PMTU, UDP metadata and Relay-reply all use one RFC 4007 zone.
      state.ipv6_connected[port_ordinal].interface_id =
          configuration.interface_id;
      rebuild_routes(device);
      return true;
    }
  }

abort_relay: {
  // Abort is idempotent after a rejected commit. Keeping it on all failure
  // paths also protects future workers that retain a rejected generation for
  // diagnostics instead of discarding it inside commit handling.
  auto &command = prepare(NetworkCommandKind::abort_dhcpv6_relay);
  command.device = device;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_dhcpv6_relay(DeviceHandle device,
                                            std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->ports[*ordinal].ipv6_configured ||
      !router_network_[device.index]->dhcpv6_relays[*ordinal])
    return false;
  auto &command = prepare(NetworkCommandKind::remove_dhcpv6_relay);
  command.device = device;
  command.logical_interface_id =
      router_network_[device.index]->dhcpv6_relays[*ordinal]->interface_id;
  const auto result = dispatch(command);
  if (!result || !result->success)
    return false;
  router_network_[device.index]->dhcpv6_relays[*ordinal].reset();
  // The current native-interface API has no remaining service object after
  // relay removal. Restore its collision-free native identity. Full IES
  // ownership keeps the service ID independently when only its relay child is
  // removed.
  router_network_[device.index]->ipv6_connected[*ordinal].interface_id =
      physical_interface_id(*ordinal);
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::clear_dhcpv6_relay_leases(
    DeviceHandle device, const Dhcpv6RelayLeaseClearProgram &program) noexcept {
  if (!device || program.filter.interface_id == 0U ||
      device.index >= router_network_.size() || !router_network_[device.index])
    return false;
  const auto &state = *router_network_[device.index];
  const auto owns_interface = [&](const auto &relay) {
    return relay.interface_id == program.filter.interface_id;
  };
  const bool configured =
      std::any_of(state.ies_dhcpv6_relays.begin(),
                  state.ies_dhcpv6_relays.end(), owns_interface) ||
      std::any_of(
          state.dhcpv6_relays.begin(), state.dhcpv6_relays.end(),
          [&](const auto &relay) { return relay && owns_interface(*relay); });
  if (!configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_dhcpv6_relay_leases);
  command.device = device;
  command.fib = program;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_database(
    DeviceHandle device, std::string_view port_id,
    const std::optional<packet::Ipv6> &group) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // The group selector is validated before crossing the shard boundary. An
  // all-interface clear is intentionally performed by LabRuntime as one
  // command per configured interface, preserving each interface owner.
  if (group && !ip::is_multicast(*group))
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_database);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = group.value_or(packet::Ipv6{});
  command.mld_group_specific = group.has_value();
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_database_all(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_database_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv4_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_global_statistics(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv4_global_statistics);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv4_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_icmpv4_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv6_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_global_statistics(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command = prepare(NetworkCommandKind::clear_icmpv6_global_statistics);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_icmpv6_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_icmpv6_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_router_advertisement_statistics_all(
    DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  auto &command =
      prepare(NetworkCommandKind::clear_router_advertisement_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_router_advertisement_interface_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal || !router_network_[device.index]->ports[*ordinal].configured)
    return false;
  auto &command = prepare(
      NetworkCommandKind::clear_router_advertisement_interface_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_version(DeviceHandle device,
                                          std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_version);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_statistics(
    DeviceHandle device, std::string_view port_id) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  auto &command = prepare(NetworkCommandKind::clear_mld_statistics);
  command.device = device;
  command.port.ordinal = *ordinal;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_mld_statistics_all(DeviceHandle device) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  // A router-wide clear is one bounded mailbox command. A sequence of
  // per-interface requests could otherwise stop halfway when the ring fills.
  auto &command = prepare(NetworkCommandKind::clear_mld_statistics_all);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::edit_mld_static(DeviceHandle device,
                                        std::string_view port_id,
                                        MldStaticOperation operation,
                                        const packet::Ipv6 &group,
                                        const packet::Ipv6 &source) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;
  if (!ip::is_multicast(group))
    return false;
  const bool needs_source = operation == MldStaticOperation::add_source ||
                            operation == MldStaticOperation::remove_source;
  if (needs_source && (ip::is_unspecified(source) || ip::is_multicast(source)))
    return false;
  auto &command = prepare(NetworkCommandKind::edit_mld_static);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = group;
  command.ipv6_source = source;
  command.mld_static_operation = operation;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::replace_mld_ssm_translations(
    DeviceHandle device, std::string_view port_id,
    std::span<const MldSsmTranslation> translations) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      translations.size() >
          device_catalog::mld_router_group_sources_per_interface)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // Validate the complete value program before opening forwarding staging.
  // This keeps malformed or duplicate candidate state on the control owner and
  // guarantees that every accepted add in the transaction has one meaning.
  for (std::size_t index = 0; index < translations.size(); ++index) {
    const auto &entry = translations[index];
    if (!ip::is_multicast(entry.start) || !ip::is_multicast(entry.end) ||
        entry.end < entry.start || ip::is_unspecified(entry.source) ||
        ip::is_multicast(entry.source) ||
        std::find(translations.begin(),
                  translations.begin() + static_cast<std::ptrdiff_t>(index),
                  entry) !=
            translations.begin() + static_cast<std::ptrdiff_t>(index))
      return false;
  }
  std::vector<MldSsmTranslation> control_program;
  try {
    control_program.assign(translations.begin(), translations.end());
  } catch (...) {
    return false;
  }

  const auto submit = [&](MldSsmProgramOperation operation,
                          const MldSsmTranslation &entry = {}) {
    auto &command = prepare(NetworkCommandKind::program_mld_ssm_translation);
    command.device = device;
    command.port.ordinal = *ordinal;
    command.mld_ssm_operation = operation;
    command.mld_ssm_translation = entry;
    command.mld_ssm_expected_entries =
        operation == MldSsmProgramOperation::begin
            ? static_cast<std::uint32_t>(translations.size())
            : 0U;
    const auto result = dispatch(command);
    return result && result->success;
  };

  if (!submit(MldSsmProgramOperation::begin))
    return false;
  for (const auto &entry : translations) {
    if (submit(MldSsmProgramOperation::add, entry))
      continue;
    static_cast<void>(submit(MldSsmProgramOperation::abort));
    return false;
  }
  if (!submit(MldSsmProgramOperation::commit)) {
    static_cast<void>(submit(MldSsmProgramOperation::abort));
    return false;
  }

  // Control updates its checkpointable projection only after forwarding has
  // atomically published the complete generation.
  router_network_[device.index]->mld_interfaces[*ordinal].ssm_translations.swap(
      control_program);
  return true;
}

bool RuntimeSupervisor::replace_mld_import_policy(
    DeviceHandle device, std::string_view port_id,
    std::span<const mld::ImportPolicyEntry> entries,
    mld::ImportPolicyAction default_action) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] ||
      entries.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal ||
      !router_network_[device.index]->mld_interfaces[*ordinal].configured)
    return false;

  // Compile into detached control memory first. This validates canonical
  // prefixes, numeric ordering and terminal action before opening forwarding
  // staging. It also creates the exact checkpoint projection that will be
  // published only after the network owner acknowledges commit.
  mld::ImportPolicyProgram validator;
  if (!validator.replace(entries, default_action))
    return false;
  mld::ImportPolicyCheckpoint control_program;
  try {
    control_program = validator.checkpoint();
  } catch (const std::bad_alloc &) {
    return false;
  }

  const auto submit = [&](mld::ImportPolicyProgramOperation operation,
                          const mld::ImportPolicyEntry &entry = {}) {
    auto &command = prepare(NetworkCommandKind::program_mld_import_policy);
    command.device = device;
    command.port.ordinal = *ordinal;
    command.mld_import_policy_operation = operation;
    command.mld_import_policy_entry = entry;
    command.mld_import_policy_default_action = default_action;
    command.mld_import_policy_expected_entries =
        operation == mld::ImportPolicyProgramOperation::begin
            ? static_cast<std::uint32_t>(entries.size())
            : 0U;
    const auto result = dispatch(command);
    return result && result->success;
  };

  if (!submit(mld::ImportPolicyProgramOperation::begin))
    return false;
  for (const auto &entry : entries) {
    if (submit(mld::ImportPolicyProgramOperation::add, entry))
      continue;
    static_cast<void>(submit(mld::ImportPolicyProgramOperation::abort));
    return false;
  }
  if (!submit(mld::ImportPolicyProgramOperation::commit)) {
    static_cast<void>(submit(mld::ImportPolicyProgramOperation::abort));
    return false;
  }

  router_network_[device.index]->mld_interfaces[*ordinal].import_policy =
      std::move(control_program);
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
  auto &port = state.ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // IPv4 and IPv6 are leaves on one routed interface. Removing the IPv4 leaf
  // must not tear down IPv6, DAD, ND or RA state. The physical forwarding port
  // is withdrawn only after the final configured address family is removed.
  port.ipv4_configured = false;
  port.address = 0U;
  port.network = 0U;
  port.prefix_length = 0U;
  state.connected[*ordinal] = {};
  if (!port.ipv6_configured && !state.ies_port_owned[*ordinal]) {
    port = {};
    state.interface_admin[*ordinal] = false;
    state.ipv6_connected[*ordinal] = {};
    rebuild_routes(device);
    auto &remove = prepare(NetworkCommandKind::remove_port);
    remove.device = device;
    remove.port.ordinal = *ordinal;
    const auto result = dispatch(remove);
    return result && result->success;
  }
  if (!port.ipv6_configured) {
    // SAP lookup, not the physical access-port projection, supplies the source
    // identity for service traffic. Keep only carrier, MTU and line rate when
    // the native IPv4 child was the final native address family.
    port.mac = {};
    state.interface_admin[*ordinal] = false;
  }
  refresh_router(device);
  return true;
}

bool RuntimeSupervisor::add_static_route(DeviceHandle device,
                                         std::uint32_t network,
                                         std::uint8_t prefix_length,
                                         std::uint32_t next_hop,
                                         bool indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U || !next_hop)
    return false;
  auto &state = *router_network_[device.index];
  routing::StaticInput *target{};
  const auto canonical = network & routing::prefix_mask(prefix_length);
  for (auto &entry : state.statics) {
    if (entry.configured && entry.network == canonical &&
        entry.prefix_length == prefix_length &&
        entry.next_hop == next_hop && entry.indirect == indirect) {
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
             .prefix_length = prefix_length,
             .indirect = indirect};
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::remove_static_route(
    DeviceHandle device, std::uint32_t network,
    std::uint8_t prefix_length, std::optional<std::uint32_t> next_hop,
    std::optional<bool> indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > 32U)
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = network & routing::prefix_mask(prefix_length);
  bool removed{};
  for (auto &entry : state.statics) {
    if (!entry.configured || entry.network != canonical ||
        entry.prefix_length != prefix_length ||
        (next_hop && entry.next_hop != *next_hop) ||
        (indirect && entry.indirect != *indirect))
      continue;
    entry = {};
    removed = true;
  }
  if (!removed)
    return false;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::configure_ecmp(DeviceHandle device,
                                       std::uint16_t maximum_paths) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || maximum_paths == 0U ||
      maximum_paths > device_catalog::maximum_ecmp_paths)
    return false;
  auto &state = *router_network_[device.index];
  if (state.maximum_ecmp_paths == maximum_paths)
    return true;
  state.maximum_ecmp_paths = maximum_paths;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::add_ipv6_static_route(
    DeviceHandle device, const packet::Ipv6 &network,
    std::uint8_t prefix_length, const packet::Ipv6 &next_hop,
    std::string_view outgoing_port_id, bool indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(next_hop) || ip::is_multicast(next_hop))
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = ip::mask(network, prefix_length);
  std::optional<std::uint16_t> outgoing_port;
  if (!outgoing_port_id.empty()) {
    const auto *inventory = hardware(device);
    if (!inventory)
      return false;
    outgoing_port = inventory->coordinate_ordinal(outgoing_port_id);
    if (!outgoing_port)
      return false;
  }
  // An indirect address is a routing-table key, not a scoped adjacency. A
  // link-local address cannot be resolved without a zone, while attaching a
  // physical port would turn the command into direct next-hop semantics.
  if ((indirect && (ip::is_link_local(next_hop) || outgoing_port)) ||
      (!indirect && ip::is_link_local(next_hop) && !outgoing_port))
    return false;

  routing::Ipv6StaticInput *target{};
  for (auto &entry : state.ipv6_statics) {
    if (entry.configured && entry.network == canonical &&
        entry.prefix_length == prefix_length && entry.next_hop == next_hop &&
        entry.indirect == indirect) {
      target = &entry;
      break;
    }
    if (!entry.configured && !target)
      target = &entry;
  }
  if (!target)
    return false;
  *target = {.configured = true,
             .indirect = indirect,
             .outgoing_interface_set = outgoing_port.has_value(),
             .network = canonical,
             .next_hop = next_hop,
             .outgoing_interface_id =
                 outgoing_port ? physical_interface_id(*outgoing_port) : 0U,
             .prefix_length = prefix_length};
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::remove_ipv6_static_route(
    DeviceHandle device, const packet::Ipv6 &network,
    std::uint8_t prefix_length, std::optional<packet::Ipv6> next_hop,
    std::optional<bool> indirect) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index] || prefix_length > ip::ipv6_address_bits)
    return false;
  auto &state = *router_network_[device.index];
  const auto canonical = ip::mask(network, prefix_length);
  bool removed{};
  for (auto &entry : state.ipv6_statics) {
    if (!entry.configured || entry.network != canonical ||
        entry.prefix_length != prefix_length ||
        (next_hop && entry.next_hop != *next_hop) ||
        (indirect && entry.indirect != *indirect))
      continue;
    entry = {};
    removed = true;
  }
  if (!removed)
    return false;
  rebuild_routes(device);
  return true;
}

bool RuntimeSupervisor::install_static_ipv6_neighbor(
    DeviceHandle device, std::string_view port_id, const packet::Ipv6 &address,
    packet::Mac mac) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || ip::is_unspecified(address) ||
      ip::is_multicast(address))
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  const auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv6_configured)
    return false;

  // Forwarding validates the MAC and owns capacity. Control publishes no
  // parallel cache copy, so a rejected full-cache installation cannot appear
  // in management intent until LabRuntime commits the acknowledged change.
  auto &command = prepare(NetworkCommandKind::install_static_ipv6_neighbor);
  command.device = device;
  command.fib = StaticIpv6NeighborProgram{.device = device,
                                          .address = address,
                                          .mac = mac,
                                          .port_ordinal = *ordinal};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::remove_static_ipv6_neighbor(
    DeviceHandle device, std::string_view port_id,
    const packet::Ipv6 &address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &command = prepare(NetworkCommandKind::remove_static_ipv6_neighbor);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.ipv6_destination = address;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::install_static_ipv4_neighbor(DeviceHandle device,
                                                     std::string_view port_id,
                                                     std::uint32_t address,
                                                     packet::Mac mac) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index] || address == 0U || address == 0xffffffffU)
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  const auto &port = router_network_[device.index]->ports[*ordinal];
  if (!port.configured || !port.ipv4_configured)
    return false;

  // The forwarding owner performs the final on-link and capacity validation.
  // Intent is committed only after this bounded command is acknowledged.
  auto &command = prepare(NetworkCommandKind::install_static_ipv4_neighbor);
  command.device = device;
  command.fib = StaticIpv4NeighborProgram{.device = device,
                                          .address = address,
                                          .mac = mac,
                                          .port_ordinal = *ordinal};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::remove_static_ipv4_neighbor(
    DeviceHandle device, std::string_view port_id,
    std::uint32_t address) noexcept {
  auto *inventory = hardware(device);
  if (!inventory || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  const auto ordinal = inventory->coordinate_ordinal(port_id);
  if (!ordinal)
    return false;
  auto &command = prepare(NetworkCommandKind::remove_static_ipv4_neighbor);
  command.device = device;
  command.port.ordinal = *ordinal;
  command.destination = address;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_dynamic_ipv6_neighbors(
    DeviceHandle device, std::optional<std::string_view> port_id,
    std::optional<packet::Ipv6> address) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  std::optional<std::uint16_t> ordinal;
  if (port_id) {
    auto *inventory = hardware(device);
    if (!inventory)
      return false;
    ordinal = inventory->coordinate_ordinal(*port_id);
    if (!ordinal)
      return false;
  }
  auto &command = prepare(NetworkCommandKind::clear_dynamic_ipv6_neighbors);
  command.device = device;
  command.port.ordinal = ordinal.value_or(0U);
  command.ipv6_destination = address.value_or(packet::Ipv6{});
  command.ipv6_neighbor_interface_specific = ordinal.has_value();
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::clear_dynamic_ipv4_neighbors(
    DeviceHandle device, std::optional<std::string_view> port_id,
    std::optional<std::uint32_t> address) noexcept {
  if (!devices_.get(device) || device.index >= router_network_.size() ||
      !router_network_[device.index])
    return false;
  std::optional<std::uint16_t> ordinal;
  if (port_id) {
    auto *inventory = hardware(device);
    if (!inventory)
      return false;
    ordinal = inventory->coordinate_ordinal(*port_id);
    if (!ordinal)
      return false;
  }
  auto &command = prepare(NetworkCommandKind::clear_dynamic_ipv4_neighbors);
  command.device = device;
  command.port.ordinal = ordinal.value_or(0U);
  command.destination = address.value_or(0U);
  command.ipv4_neighbor_interface_specific = ordinal.has_value();
  const auto result = dispatch(command);
  return result && result->success;
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
    const bool operational =
        physical && physical->present && physical->configuration_compatible &&
        physical->hierarchy_enabled && physical->admin_enabled &&
        physical->link_signal &&
        (state.interface_admin[ordinal] || state.ies_port_owned[ordinal]);
    state.ports[ordinal].operational = operational;
    if (physical) {
      state.ports[ordinal].mtu = physical->mtu;
      state.ports[ordinal].speed_mbps = physical->speed_mbps;
    }
    state.connected[ordinal].operational = operational;
    state.ipv6_connected[ordinal].operational =
        operational && state.ports[ordinal].ipv6_configured;
    for (auto &connected : state.native_ipv6_connected)
      if (connected.physical_port_ordinal == ordinal)
        connected.operational =
            operational && state.ports[ordinal].ipv6_configured;
    // Forwarding receives the complete port projection even when down. This
    // preserves address and MTU configuration without granting packet passage.
    auto &configure = prepare(NetworkCommandKind::configure_port);
    configure.device = device;
    configure.port = state.ports[ordinal];
    static_cast<void>(dispatch(configure));
    const auto &advertisement = state.router_advertisements[ordinal];
    if (advertisement.configured) {
      auto &ra = prepare(NetworkCommandKind::configure_router_advertisement);
      ra.device = device;
      ra.fib = RouterAdvertisementProgram{
          .device = device,
          .config = advertisement.config,
          .port_ordinal = static_cast<std::uint16_t>(ordinal),
          .enabled = advertisement.enabled};
      static_cast<void>(dispatch(ra));
    }
    const auto &mld = state.mld_interfaces[ordinal];
    if (mld.configured) {
      // Re-resolve fields that originate outside the MLD configuration tree.
      // Hardware replacement may preserve the stable ordinal while an IPv6
      // address edit changes the local Querier address.
      auto configuration = mld.configuration;
      configuration.port_ordinal = static_cast<std::uint16_t>(ordinal);
      configuration.link_local_address = state.ports[ordinal].ipv6_link_local;
      auto &program = prepare(NetworkCommandKind::configure_mld_interface);
      program.device = device;
      program.fib =
          MldInterfaceProgram{.device = device, .configuration = configuration};
      const auto result = dispatch(program);
      if (result && result->success) {
        state.mld_interfaces[ordinal].configuration = configuration;
        // configure_mld_interface recreates the forwarding-owned protocol
        // object. Reinstall the last committed SSM program before this refresh
        // can be considered complete. The begin/add/commit sequence keeps the
        // previous generation visible until every range-source tuple arrives.
        const auto &translations = mld.ssm_translations;
        const auto submit = [&](MldSsmProgramOperation operation,
                                const MldSsmTranslation &entry = {}) {
          auto &translation =
              prepare(NetworkCommandKind::program_mld_ssm_translation);
          translation.device = device;
          translation.port.ordinal = static_cast<std::uint16_t>(ordinal);
          translation.mld_ssm_operation = operation;
          translation.mld_ssm_translation = entry;
          translation.mld_ssm_expected_entries =
              operation == MldSsmProgramOperation::begin
                  ? static_cast<std::uint32_t>(translations.size())
                  : 0U;
          const auto programmed = dispatch(translation);
          return programmed && programmed->success;
        };
        bool complete = submit(MldSsmProgramOperation::begin);
        for (const auto &translation : translations)
          complete =
              complete && submit(MldSsmProgramOperation::add, translation);
        complete = complete && submit(MldSsmProgramOperation::commit);
        if (!complete)
          static_cast<void>(submit(MldSsmProgramOperation::abort));

        // Reconfiguration constructs a new forwarding MLD owner, so the
        // effective policy generation must follow the same rebuild path as SSM
        // translation. The named policy remains a LabRuntime concern; this
        // transaction restores only its already resolved value program.
        const auto &policy = mld.import_policy;
        const auto submit_policy =
            [&](mld::ImportPolicyProgramOperation operation,
                const mld::ImportPolicyEntry &entry = {}) {
              auto &policy_command =
                  prepare(NetworkCommandKind::program_mld_import_policy);
              policy_command.device = device;
              policy_command.port.ordinal = static_cast<std::uint16_t>(ordinal);
              policy_command.mld_import_policy_operation = operation;
              policy_command.mld_import_policy_entry = entry;
              policy_command.mld_import_policy_default_action =
                  policy.default_action;
              policy_command.mld_import_policy_expected_entries =
                  operation == mld::ImportPolicyProgramOperation::begin
                      ? static_cast<std::uint32_t>(policy.entries.size())
                      : 0U;
              const auto programmed = dispatch(policy_command);
              return programmed && programmed->success;
            };
        bool policy_complete =
            submit_policy(mld::ImportPolicyProgramOperation::begin);
        for (const auto &entry : policy.entries)
          policy_complete =
              policy_complete &&
              submit_policy(mld::ImportPolicyProgramOperation::add, entry);
        policy_complete =
            policy_complete &&
            submit_policy(mld::ImportPolicyProgramOperation::commit);
        if (!policy_complete)
          static_cast<void>(
              submit_policy(mld::ImportPolicyProgramOperation::abort));
      }
    }
    if (state.dhcpv6_relays[ordinal]) {
      // A forwarding port can disappear with a card while committed service
      // intent remains. Reinstall the complete relay generation only after
      // IPv6 and its UDP/FIB prerequisites have been republished.
      static_cast<void>(
          program_dhcpv6_relay(device, static_cast<std::uint16_t>(ordinal),
                               *state.dhcpv6_relays[ordinal]));
    }
  }
  // configure_port carries only the selected-primary compatibility cache.
  // Republish the full generation after all physical projections so secondary
  // addresses cannot disappear during card, link or admin reconciliation.
  static_cast<void>(
      program_ipv6_address_generation(device, state.native_ipv6_addresses));
  if (!state.ies_configuration.ports.empty() ||
      !state.ies_configuration.ies_services.empty()) {
    // Rebuild the entire service generation after all physical port views are
    // current. The call retains configured intent for absent equipment while
    // publishing classifiers only for ports that presently exist.
    static_cast<void>(configure_ies_services(device, state.ies_configuration));
  }
  rebuild_routes(device);
}

void RuntimeSupervisor::rebuild_routes(DeviceHandle device) noexcept {
  if (device.index >= router_network_.size() || !router_network_[device.index])
    return;
  auto &state = *router_network_[device.index];
  // Publish unresolved static intent before either base FIB. The network
  // route-manager is the sole owner that can later resolve an indirect static
  // next hop through an OSPF route without asking control to poll protocol
  // state or letting OSPF bypass RIB selection.
  auto &policy_command = prepare(NetworkCommandKind::program_route_policy);
  policy_command.device = device;
  policy_command.fib =
      RoutePolicyProgram{.ipv4_statics = state.statics,
                         .ipv6_statics = state.ipv6_statics,
                         .maximum_ecmp_paths = state.maximum_ecmp_paths};
  const auto policy_result = dispatch(policy_command);
  if (!policy_result || !policy_result->success)
    return;
  const bool changed = state.rib.rebuild(state.connected, state.statics, {},
                                         state.maximum_ecmp_paths);
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
  const bool ipv6_changed =
      state.ipv6_rib.rebuild(state.native_ipv6_connected, state.ipv6_statics,
                             state.ies_ipv6_connected, {},
                             state.maximum_ecmp_paths);
  if (!state.ipv6_rib.last_rebuild_valid())
    return;
  if (ipv6_changed || !state.ipv6_fib_generation) {
    ++state.ipv6_fib_generation;
    auto &program = prepare(NetworkCommandKind::program_ipv6_fib);
    program.device = device;
    program.fib = state.ipv6_rib.compile(state.ipv6_fib_generation);
    static_cast<void>(dispatch(program));
  }
}

bool RuntimeSupervisor::start_router_ping(DeviceHandle device,
                                          std::uint32_t destination,
                                          std::uint16_t sequence,
                                          std::uint16_t payload_octets,
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
  return (router_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
RuntimeSupervisor::router_ping_outcome(DeviceHandle device,
                                       std::uint16_t sequence) noexcept {
  if (!devices_.get(device))
    return 0U;
  auto &command = prepare(NetworkCommandKind::router_ping_status);
  command.device = device;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0U;
}

bool RuntimeSupervisor::start_router_ipv6_ping(
    DeviceHandle device, const packet::Ipv6 &destination,
    std::uint16_t sequence, std::uint16_t payload_octets) noexcept {
  if (!devices_.get(device) || ip::is_unspecified(destination) ||
      ip::is_multicast(destination))
    return false;
  auto &command = prepare(NetworkCommandKind::router_ipv6_ping);
  command.device = device;
  command.ipv6_destination = destination;
  command.sequence = sequence;
  command.payload_octets = payload_octets;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::router_ipv6_ping_reply(
    DeviceHandle device, std::uint16_t sequence) noexcept {
  return (router_ipv6_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
RuntimeSupervisor::router_ipv6_ping_outcome(DeviceHandle device,
                                            std::uint16_t sequence) noexcept {
  if (!devices_.get(device))
    return 0U;
  auto &command = prepare(NetworkCommandKind::router_ipv6_ping_status);
  command.device = device;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0U;
}

bool RuntimeSupervisor::configure_host(
    HostHandle host, packet::Mac mac, packet::Ipv4 address,
    std::uint8_t prefix_length, packet::Ipv4 gateway, std::uint16_t mtu,
    std::uint64_t interface_id, bool ipv6_autoconfiguration,
    const host::Ipv6InterfaceIdentifierConfiguration &ipv6_identifier,
    crypto::Sha256Digest transport_secret) noexcept {
  const bool transport_secret_present =
      std::any_of(transport_secret.begin(), transport_secret.end(),
                  [](std::uint8_t value) { return value != 0U; });
  if (!hosts_.get(host) || prefix_length > 32U ||
      mtu < device_catalog::minimum_host_ipv4_mtu ||
      mtu > device_catalog::maximum_network_mtu || !transport_secret_present ||
      (ipv6_autoconfiguration &&
       (!interface_id || mtu < packet::ipv6_minimum_link_mtu)))
    return false;
  // HostNetworkProgram crosses the same value boundary as router port and FIB
  // projections. Control never receives a pointer to endpoint ARP state.
  auto &command = prepare(NetworkCommandKind::configure_host);
  command.host_program = {host,
                          mac,
                          address,
                          gateway,
                          prefix_length,
                          mtu,
                          interface_id,
                          ipv6_autoconfiguration,
                          ipv6_identifier,
                          transport_secret};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dhcpv6_client(
    const HostDhcpv6ClientProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.configuration.identity_associations.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.requested_options.size() >
          std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv6_client);
  begin_command.host = program.host;
  begin_command.fib = NetworkDhcpv6ClientBegin{
      .duid = program.configuration.duid,
      .transaction_secret = program.configuration.transaction_secret,
      .expected_associations = static_cast<std::uint32_t>(
          program.configuration.identity_associations.size()),
      .expected_options = static_cast<std::uint32_t>(
          program.configuration.requested_options.size()),
      .duid_octets = program.configuration.duid_octets,
      .rapid_commit = program.configuration.rapid_commit,
      .information_only = program.information_only};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  for (const auto &association : program.configuration.identity_associations) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_client_ia);
    command.host = program.host;
    command.fib =
        NetworkDhcpv6ClientAssociation{association.iaid, association.kind};
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_client;
  }
  for (const auto option : program.configuration.requested_options) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_client_option);
    command.host = program.host;
    command.dhcpv6_option_code = option;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_client;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_host_dhcpv6_client);
    command.host = program.host;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }
abort_client: {
  auto &command = prepare(NetworkCommandKind::abort_host_dhcpv6_client);
  command.host = program.host;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv6_client(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv6_client);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dhcpv6_server(
    const HostDhcpv6ServerProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.decline_hold_time < std::chrono::seconds::zero() ||
      program.configuration.dns_recursive_servers.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.address_pools.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.prefix_pools.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto &configuration = program.configuration;
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv6_server);
  begin_command.host = program.host;
  begin_command.fib = NetworkDhcpv6ServerBegin{
      .duid = configuration.duid,
      .decline_hold_seconds =
          static_cast<std::uint64_t>(program.decline_hold_time.count()),
      .expected_dns_servers = static_cast<std::uint32_t>(
          configuration.dns_recursive_servers.size()),
      .expected_address_pools =
          static_cast<std::uint32_t>(program.address_pools.size()),
      .expected_prefix_pools =
          static_cast<std::uint32_t>(program.prefix_pools.size()),
      .information_refresh_time_seconds =
          configuration.information_refresh_time_seconds,
      .solicit_maximum_retransmission_seconds =
          configuration.solicit_maximum_retransmission_seconds.value_or(0U),
      .information_maximum_retransmission_seconds =
          configuration.information_maximum_retransmission_seconds.value_or(0U),
      .duid_octets = configuration.duid_octets,
      .preference = configuration.preference,
      .address_pool_index = configuration.address_pool_index,
      .prefix_pool_index = configuration.prefix_pool_index,
      .rapid_commit = configuration.rapid_commit,
      .has_solicit_maximum_retransmission =
          configuration.solicit_maximum_retransmission_seconds.has_value(),
      .has_information_maximum_retransmission =
          configuration.information_maximum_retransmission_seconds.has_value()};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  for (const auto &dns : configuration.dns_recursive_servers) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_server_dns);
    command.host = program.host;
    command.ipv6_destination = dns;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  for (const auto &pool : program.address_pools) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv6_server_address_pool);
    command.host = program.host;
    command.fib = pool;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  for (const auto &pool : program.prefix_pools) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv6_server_prefix_pool);
    command.host = program.host;
    command.fib = pool;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_host_dhcpv6_server);
    command.host = program.host;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }
abort_server: {
  auto &command = prepare(NetworkCommandKind::abort_host_dhcpv6_server);
  command.host = program.host;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv6_server(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv6_server);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

std::optional<std::size_t>
RuntimeSupervisor::host_dhcpv6_client_lease_count(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::host_dhcpv6_client_status);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success ? std::optional<std::size_t>{result->value}
                                   : std::nullopt;
}

bool RuntimeSupervisor::configure_host_dns_resolver(
    const HostDnsResolverProgram &program) noexcept {
  if (!hosts_.get(program.host) || program.root_hints.empty() ||
      program.root_hints.size() > std::numeric_limits<std::uint32_t>::max() ||
      program.trust_anchors.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_resolver);
  begin.host = program.host;
  begin.fib = NetworkDnsResolverBegin{
      .identifier_secret = program.identifier_secret,
      .expected_root_hints =
          static_cast<std::uint32_t>(program.root_hints.size()),
      .expected_trust_anchors =
          static_cast<std::uint32_t>(program.trust_anchors.size()),
      .maximum_nsec3_iterations = program.nsec3_policy.maximum,
      .serve_clients = program.serve_clients};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &hint : program.root_hints) {
    if (hint.addresses.empty() ||
        hint.addresses.size() > std::numeric_limits<std::uint32_t>::max())
      goto abort_resolver;
    auto &root = prepare(NetworkCommandKind::begin_host_dns_root_hint);
    root.host = program.host;
    root.fib = NetworkDnsRootHintBegin{
        .server_name = hint.server_name,
        .expected_addresses =
            static_cast<std::uint32_t>(hint.addresses.size())};
    result = dispatch(root);
    if (!result || !result->success)
      goto abort_resolver;
    for (const auto &address : hint.addresses) {
      auto &add = prepare(NetworkCommandKind::add_host_dns_root_address);
      add.host = program.host;
      add.fib = address;
      result = dispatch(add);
      if (!result || !result->success)
        goto abort_resolver;
    }
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_root_hint);
    commit.host = program.host;
    result = dispatch(commit);
    if (!result || !result->success)
      goto abort_resolver;
  }
  for (const auto &anchor : program.trust_anchors) {
    if (anchor.type != packet::dns::type_dnskey || !anchor.record_class ||
        anchor.rdata.empty() ||
        anchor.rdata.size() > std::numeric_limits<std::uint16_t>::max())
      goto abort_resolver;
    auto &anchor_begin =
        prepare(NetworkCommandKind::begin_host_dns_trust_anchor);
    anchor_begin.host = program.host;
    anchor_begin.fib = NetworkDnsTrustAnchorBegin{
        .owner = anchor.owner,
        .ttl = anchor.ttl,
        .expected_rdata_octets =
            static_cast<std::uint32_t>(anchor.rdata.size()),
        .record_class = anchor.record_class};
    result = dispatch(anchor_begin);
    if (!result || !result->success)
      goto abort_resolver;
    for (std::size_t offset{}; offset < anchor.rdata.size();
         offset += network_dns_chunk_octets) {
      NetworkDnsRdataChunk chunk;
      chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
          chunk.octets.size(), anchor.rdata.size() - offset));
      std::copy_n(anchor.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                  chunk.size, chunk.octets.begin());
      auto &add = prepare(NetworkCommandKind::add_host_dns_trust_anchor_rdata);
      add.host = program.host;
      add.fib = chunk;
      result = dispatch(add);
      if (!result || !result->success)
        goto abort_resolver;
    }
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_trust_anchor);
    commit.host = program.host;
    result = dispatch(commit);
    if (!result || !result->success)
      goto abort_resolver;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_resolver);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_resolver: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_resolver);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dns_resolver(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dns_resolver);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dns_authoritative(
    const HostDnsAuthoritativeProgram &program) noexcept {
  if (!hosts_.get(program.host) || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_authoritative);
  begin.host = program.host;
  begin.fib = NetworkDnsAuthoritativeBegin{
      .wall_now = 0U,
      .expected_zones = static_cast<std::uint32_t>(program.zones.size()),
      .managed_signing = false};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &zone : program.zones) {
    if (zone.records.empty() ||
        zone.records.size() > std::numeric_limits<std::uint32_t>::max())
      goto abort_authoritative;
    auto &zone_begin = prepare(NetworkCommandKind::begin_host_dns_zone);
    zone_begin.host = program.host;
    zone_begin.fib = NetworkDnsZoneBegin{
        .origin = zone.origin,
        .policy = {},
        .expected_records = static_cast<std::uint32_t>(zone.records.size()),
        .expected_keys = 0U};
    result = dispatch(zone_begin);
    if (!result || !result->success)
      goto abort_authoritative;
    for (const auto &record : zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        goto abort_authoritative;
      auto &record_begin = prepare(NetworkCommandKind::begin_host_dns_record);
      record_begin.host = program.host;
      record_begin.fib = NetworkDnsRecordBegin{
          .owner = record.owner,
          .ttl = record.ttl,
          .expected_rdata_octets =
              static_cast<std::uint32_t>(record.rdata.size()),
          .type = record.type,
          .record_class = record.record_class};
      result = dispatch(record_begin);
      if (!result || !result->success)
        goto abort_authoritative;
      for (std::size_t offset{}; offset < record.rdata.size();
           offset += network_dns_chunk_octets) {
        NetworkDnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        auto &add = prepare(NetworkCommandKind::add_host_dns_rdata);
        add.host = program.host;
        add.fib = chunk;
        result = dispatch(add);
        if (!result || !result->success)
          goto abort_authoritative;
      }
      auto &commit = prepare(NetworkCommandKind::commit_host_dns_record);
      commit.host = program.host;
      result = dispatch(commit);
      if (!result || !result->success)
        goto abort_authoritative;
    }
    auto &zone_commit = prepare(NetworkCommandKind::commit_host_dns_zone);
    zone_commit.host = program.host;
    result = dispatch(zone_commit);
    if (!result || !result->success)
      goto abort_authoritative;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_authoritative);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_authoritative: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_authoritative);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::configure_host_dns_signed_authoritative(
    const HostDnsSignedAuthoritativeProgram &program) noexcept {
  if (!hosts_.get(program.host) || !program.wall_now || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_authoritative);
  begin.host = program.host;
  begin.fib = NetworkDnsAuthoritativeBegin{
      .wall_now = program.wall_now,
      .expected_zones = static_cast<std::uint32_t>(program.zones.size()),
      .managed_signing = true};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &zone : program.zones) {
    if (zone.zone.records.empty() || zone.keys.empty() ||
        zone.zone.records.size() > std::numeric_limits<std::uint32_t>::max() ||
        zone.keys.size() > std::numeric_limits<std::uint32_t>::max() ||
        !dnssec::valid_managed_zone_policy(zone.policy))
      goto abort_signed;
    auto &zone_begin = prepare(NetworkCommandKind::begin_host_dns_zone);
    zone_begin.host = program.host;
    zone_begin.fib = NetworkDnsZoneBegin{
        .origin = zone.zone.origin,
        .policy = zone.policy,
        .expected_records =
            static_cast<std::uint32_t>(zone.zone.records.size()),
        .expected_keys = static_cast<std::uint32_t>(zone.keys.size())};
    result = dispatch(zone_begin);
    if (!result || !result->success)
      goto abort_signed;
    for (const auto &key : zone.keys) {
      auto &add_key = prepare(NetworkCommandKind::add_host_dns_signing_key);
      add_key.host = program.host;
      add_key.fib = NetworkDnsSigningKeyDefinition{.schedule = key.schedule,
                                                   .generation = key.generation,
                                                   .role = key.role,
                                                   .algorithm = key.algorithm};
      result = dispatch(add_key);
      if (!result || !result->success)
        goto abort_signed;
    }
    for (const auto &record : zone.zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        goto abort_signed;
      auto &record_begin = prepare(NetworkCommandKind::begin_host_dns_record);
      record_begin.host = program.host;
      record_begin.fib = NetworkDnsRecordBegin{
          .owner = record.owner,
          .ttl = record.ttl,
          .expected_rdata_octets =
              static_cast<std::uint32_t>(record.rdata.size()),
          .type = record.type,
          .record_class = record.record_class};
      result = dispatch(record_begin);
      if (!result || !result->success)
        goto abort_signed;
      for (std::size_t offset{}; offset < record.rdata.size();
           offset += network_dns_chunk_octets) {
        NetworkDnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        auto &add = prepare(NetworkCommandKind::add_host_dns_rdata);
        add.host = program.host;
        add.fib = chunk;
        result = dispatch(add);
        if (!result || !result->success)
          goto abort_signed;
      }
      auto &record_commit = prepare(NetworkCommandKind::commit_host_dns_record);
      record_commit.host = program.host;
      result = dispatch(record_commit);
      if (!result || !result->success)
        goto abort_signed;
    }
    auto &zone_commit = prepare(NetworkCommandKind::commit_host_dns_zone);
    zone_commit.host = program.host;
    result = dispatch(zone_commit);
    if (!result || !result->success)
      goto abort_signed;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_authoritative);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_signed: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_authoritative);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dns_authoritative(
    HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dns_authoritative);
  command.host = host;
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

bool RuntimeSupervisor::delete_switch(SwitchHandle handle) noexcept {
  if (!switches_.get(handle))
    return false;
  const auto links = topology_.attached(node(handle));
  for (std::size_t index{}; index < links.count; ++index)
    static_cast<void>(delete_link(links.handles[index]));
  auto &remove = prepare(NetworkCommandKind::remove_switch);
  remove.ethernet_switch = handle;
  const auto removed = dispatch(remove);
  return removed && removed->success && switches_.erase(handle);
}

std::size_t RuntimeSupervisor::active_links() noexcept {
  auto &query = prepare(NetworkCommandKind::active_link_count);
  const auto result = dispatch(query);
  // A failed health query cannot safely invent a stale physical link count.
  return result && result->success ? static_cast<std::size_t>(result->value)
                                   : 0;
}

bool RuntimeSupervisor::configure_capture_point(
    const CapturePointProgram &program) noexcept {
  auto &command = prepare(NetworkCommandKind::configure_capture_point);
  command.capture_program = program;
  const auto result = dispatch(command);
  return result && result->success;
}

std::span<const std::uint8_t> RuntimeSupervisor::prepare_capture() noexcept {
  auto &command = prepare(NetworkCommandKind::prepare_capture);
  const auto result = dispatch(command);
  if (!result || !result->success ||
      result->value != network_worker_->prepared_capture().size())
    return {};
  // Response-ring acquire ordering publishes the completed byte vector. The
  // bridge must copy it before issuing another prepare command.
  return network_worker_->prepared_capture();
}

bool RuntimeSupervisor::clear_capture() noexcept {
  auto &command = prepare(NetworkCommandKind::clear_capture);
  const auto result = dispatch(command);
  return result && result->success;
}

std::size_t RuntimeSupervisor::captured_frames() noexcept {
  auto &command = prepare(NetworkCommandKind::capture_frame_count);
  const auto result = dispatch(command);
  return result && result->success ? static_cast<std::size_t>(result->value)
                                   : 0;
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
  // exposing forwarding pointers or serializing unrelated capture metadata.
  try {
    return *prepared;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

std::unique_ptr<RuntimeSupervisorCheckpoint> RuntimeSupervisor::checkpoint() {
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
    state->switches = switches_.checkpoint();
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
      // RouterControlCheckpoint contains full fixed-capacity route and RA
      // projections. Construct it directly in the reserved heap vector so the
      // one MiB Wasm stack never receives a second temporary copy.
      state->control.emplace_back();
      auto &router = state->control.back();
      router.device = device.handle;
      router.maximum_ecmp_paths = control->maximum_ecmp_paths;
      router.connected = control->connected;
      router.statics = control->statics;
      router.ipv6_connected = control->ipv6_connected;
      router.native_ipv6_addresses = control->native_ipv6_addresses;
      router.native_ipv6_connected = control->native_ipv6_connected;
      router.ipv6_statics = control->ipv6_statics;
      router.ports = control->ports;
      router.interface_admin = control->interface_admin;
      router.ies_port_owned = control->ies_port_owned;
      router.router_advertisements = control->router_advertisements;
      router.mld_interfaces = control->mld_interfaces;
      router.dhcpv6_relays = control->dhcpv6_relays;
      router.ies_configuration = control->ies_configuration;
      router.ies_sap_attachments = control->ies_sap_attachments;
      router.ies_ipv6_interfaces = control->ies_ipv6_interfaces;
      router.ies_ipv6_connected = control->ies_ipv6_connected;
      router.ies_dhcpv6_relays = control->ies_dhcpv6_relays;
      router.fib_generation = control->fib_generation;
      router.selected_rib = control->rib.compile(control->fib_generation);
      router.ipv6_fib_generation = control->ipv6_fib_generation;
      router.selected_ipv6_rib =
          control->ipv6_rib.compile(control->ipv6_fib_generation);
    }
    state->network = std::move(*network);
    state->next_network_command_id = next_network_command_id_;
    return state;
  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

bool checkpoint_validation::base_fib_preserved(
    const routing::FibProgram &base,
    const routing::FibProgram &selected) noexcept {
      // The route manager checkpoint owns connected and static intent. OSPF
      // routes are owned and validated by the network-plane checkpoint below,
      // so rebuilding only the base RIB cannot legitimately be byte-equal to
      // a selected FIB that contains converged dynamic routes. Require every
      // independently rebuilt base route and permit only typed OSPF additions.
      if (base.generation != selected.generation ||
          base.count > selected.count)
        return false;
      const auto equal_route = [](const auto &a, const auto &b) {
        return a.network == b.network && a.next_hop == b.next_hop &&
               a.port_ordinal == b.port_ordinal &&
               a.prefix_length == b.prefix_length &&
               a.preference == b.preference && a.metric == b.metric &&
               a.source == b.source && a.local_system == b.local_system;
      };
      const auto selected_end =
          selected.routes.begin() + selected.count;
      for (auto route = base.routes.begin();
           route != base.routes.begin() + base.count; ++route)
        if (std::find_if(selected.routes.begin(), selected_end,
                         [&](const auto &candidate) {
                           return equal_route(*route, candidate);
                         }) == selected_end)
          return false;
      return std::all_of(
          selected.routes.begin(), selected_end, [&](const auto &route) {
            return route.source == routing::RouteSource::ospf ||
                   route.source == routing::RouteSource::ospf3 ||
                   std::find_if(base.routes.begin(),
                                base.routes.begin() + base.count,
                                [&](const auto &candidate) {
                                  return equal_route(route, candidate);
                                }) != base.routes.begin() + base.count;
          });
}

bool checkpoint_validation::base_fib_preserved(
    const routing::Ipv6FibProgram &base,
    const routing::Ipv6FibProgram &selected) noexcept {
      // IPv6 follows the same ownership split as IPv4. The exact saved FIB is
      // later checked by RouterForwarder and NetworkWorker restore; this check
      // proves that protocol routes did not replace required local intent.
      if (base.generation != selected.generation ||
          base.count > selected.count)
        return false;
      const auto equal_route = [](const auto &a, const auto &b) {
        return a.network == b.network && a.next_hop == b.next_hop &&
               a.interface_id == b.interface_id &&
               a.physical_port_ordinal == b.physical_port_ordinal &&
               a.prefix_length == b.prefix_length &&
               a.preference == b.preference && a.metric == b.metric &&
               a.source == b.source;
      };
      const auto selected_end =
          selected.routes.begin() + selected.count;
      for (auto route = base.routes.begin();
           route != base.routes.begin() + base.count; ++route)
        if (std::find_if(selected.routes.begin(), selected_end,
                         [&](const auto &candidate) {
                           return equal_route(*route, candidate);
                         }) == selected_end)
          return false;
      return std::all_of(
          selected.routes.begin(), selected_end, [&](const auto &route) {
            return route.source == routing::RouteSource::ospf ||
                   route.source == routing::RouteSource::ospf3 ||
                   std::find_if(base.routes.begin(),
                                base.routes.begin() + base.count,
                                [&](const auto &candidate) {
                                  return equal_route(route, candidate);
                                }) != base.routes.begin() + base.count;
          });
}

bool RuntimeSupervisor::restore(RuntimeSupervisorCheckpoint state) {
  try {
    auto devices = std::make_unique<DeviceRegistry>();
    auto hosts = std::make_unique<HostRegistry>();
    auto switches = std::make_unique<SwitchRegistry>();
    auto topology = std::make_unique<TopologyRegistry>();
    auto sessions = std::make_unique<SessionRegistry>();
    if (!devices->restore(state.devices) || !hosts->restore(state.hosts) ||
        !switches->restore(state.switches) ||
        !topology->restore(state.topology) ||
        !sessions->restore(state.sessions))
      return false;
    for (const auto &device : state.devices.entries)
      if (hosts->find(device.node_id) || switches->find(device.node_id))
        return false;
    for (const auto &host : state.hosts.entries)
      if (switches->find(host.node_id))
        return false;
    for (const auto &session : state.sessions.entries)
      if (!devices->get(session.record.device))
        return false;
    for (const auto &link : state.topology.entries)
      for (const auto &endpoint : link.record.endpoints) {
        bool exists{};
        if (endpoint.node.kind == NodeKind::router)
          exists = devices->get(
                       {endpoint.node.index, endpoint.node.generation}) !=
                   nullptr;
        else if (endpoint.node.kind == NodeKind::host)
          exists =
              hosts->get({endpoint.node.index, endpoint.node.generation}) !=
              nullptr;
        else if (endpoint.node.kind == NodeKind::ethernet_switch)
          exists = switches->get(
                       {endpoint.node.index, endpoint.node.generation}) !=
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
    for (const auto &source : state.control) {
      if (!devices->get(source.device) ||
          source.device.index >= control_seen.size() ||
          control_seen[source.device.index] ||
          source.selected_rib.generation != source.fib_generation ||
          source.selected_rib.count > source.selected_rib.routes.size() ||
          source.selected_ipv6_rib.generation != source.ipv6_fib_generation ||
          source.selected_ipv6_rib.count >
              source.selected_ipv6_rib.routes.size() ||
          source.maximum_ecmp_paths == 0U ||
          source.maximum_ecmp_paths > device_catalog::maximum_ecmp_paths)
        return false;
      auto restored = std::make_unique<RouterNetworkState>();
      restored->connected = source.connected;
      restored->statics = source.statics;
      restored->ipv6_connected = source.ipv6_connected;
      restored->native_ipv6_addresses = source.native_ipv6_addresses;
      restored->native_ipv6_connected = source.native_ipv6_connected;
      restored->ipv6_statics = source.ipv6_statics;
      restored->maximum_ecmp_paths = source.maximum_ecmp_paths;
      restored->ports = source.ports;
      restored->interface_admin = source.interface_admin;
      restored->ies_port_owned = source.ies_port_owned;
      restored->router_advertisements = source.router_advertisements;
      restored->mld_interfaces = source.mld_interfaces;
      restored->dhcpv6_relays = source.dhcpv6_relays;
      restored->ies_configuration = source.ies_configuration;
      restored->ies_sap_attachments = source.ies_sap_attachments;
      restored->ies_ipv6_interfaces = source.ies_ipv6_interfaces;
      restored->ies_ipv6_connected = source.ies_ipv6_connected;
      restored->ies_dhcpv6_relays = source.ies_dhcpv6_relays;
      restored->fib_generation = source.fib_generation;
      restored->ipv6_fib_generation = source.ipv6_fib_generation;
      service::SapForwardingTable service_validation;
      dhcpv6::RelayAgent service_relay_validation;
      if (service::validate(source.ies_configuration) !=
              service::ValidationError::none ||
          service_validation.replace(source.ies_sap_attachments,
                                     source.ies_ipv6_interfaces) !=
              service::SapProgramStatus::accepted ||
          !service_relay_validation.restore(source.ies_dhcpv6_relays))
        return false;
      for (std::size_t ordinal = 0; ordinal < source.ies_port_owned.size();
           ++ordinal) {
        if (!source.ies_port_owned[ordinal])
          continue;
        // A serialized forwarding owner must be backed by both the physical
        // projection and the service configuration object that created it.
        // Otherwise removing a native interface after restore could preserve
        // an orphan port indefinitely.
        if (!source.ports[ordinal].configured ||
            std::none_of(source.ies_configuration.ports.begin(),
                         source.ies_configuration.ports.end(),
                         [ordinal](const auto &port) {
                           return port.coordinate.ordinal == ordinal;
                         }))
          return false;
      }
      auto advertisement_validation =
          std::make_unique<Ipv6RouterAdvertisementTable>();
      for (std::size_t ordinal = 0;
           ordinal < source.router_advertisements.size(); ++ordinal) {
        const auto &advertisement = source.router_advertisements[ordinal];
        if (!advertisement.configured) {
          if (advertisement.enabled)
            return false;
          continue;
        }
        if (!source.ports[ordinal].configured ||
            !source.ports[ordinal].ipv6_configured ||
            !advertisement_validation->configure(
                static_cast<std::uint16_t>(ordinal), false,
                advertisement.config))
          return false;
      }
      for (std::size_t ordinal = 0; ordinal < source.mld_interfaces.size();
           ++ordinal) {
        const auto &mld = source.mld_interfaces[ordinal];
        if (!mld.configured)
          continue;
        const auto &port = source.ports[ordinal];
        if (!port.configured || !port.ipv6_configured ||
            mld.configuration.port_ordinal != ordinal ||
            mld.configuration.link_local_address != port.ipv6_link_local ||
            !MldRouterInterface{}.configure(mld.configuration))
          return false;
        if (mld.ssm_translations.size() >
            device_catalog::mld_router_group_sources_per_interface)
          return false;
        for (std::size_t index = 0; index < mld.ssm_translations.size();
             ++index) {
          const auto &translation = mld.ssm_translations[index];
          if (!ip::is_multicast(translation.start) ||
              !ip::is_multicast(translation.end) ||
              translation.end < translation.start ||
              ip::is_unspecified(translation.source) ||
              ip::is_multicast(translation.source) ||
              std::find(mld.ssm_translations.begin(),
                        mld.ssm_translations.begin() +
                            static_cast<std::ptrdiff_t>(index),
                        translation) != mld.ssm_translations.begin() +
                                            static_cast<std::ptrdiff_t>(index))
            return false;
        }
      }
      std::vector<dhcpv6::RelayInterfaceConfig> relay_validation_values;
      for (std::size_t ordinal = 0; ordinal < source.dhcpv6_relays.size();
           ++ordinal) {
        if (!source.dhcpv6_relays[ordinal])
          continue;
        const auto &port = source.ports[ordinal];
        const auto &relay = *source.dhcpv6_relays[ordinal];
        if (!port.configured || !port.ipv6_configured ||
            relay.interface_id == 0U || relay.physical_port_ordinal != ordinal)
          return false;
        relay_validation_values.push_back(relay);
      }
      dhcpv6::RelayAgent relay_validation;
      if (!relay_validation.restore(relay_validation_values))
        return false;
      static_cast<void>(
          restored->rib.rebuild(restored->connected, restored->statics, {},
                                restored->maximum_ecmp_paths));
      if (!restored->rib.last_rebuild_valid() ||
          !checkpoint_validation::base_fib_preserved(
              restored->rib.compile(source.fib_generation),
              source.selected_rib))
        return false;
      static_cast<void>(restored->ipv6_rib.rebuild(
          restored->native_ipv6_connected, restored->ipv6_statics,
          restored->ies_ipv6_connected, {},
          restored->maximum_ecmp_paths));
      if (!restored->ipv6_rib.last_rebuild_valid() ||
          !checkpoint_validation::base_fib_preserved(
              restored->ipv6_rib.compile(source.ipv6_fib_generation),
              source.selected_ipv6_rib))
        return false;
      RouterForwarderCheckpoint forwarding_validation;
      forwarding_validation.fib = source.selected_rib;
      forwarding_validation.ipv6_fib = source.selected_ipv6_rib;
      // Route age vectors are members of the selected FIB generation. The
      // control-only validator has no operational installation history, so a
      // zero age is the sole truthful synthetic value for every selected row.
      forwarding_validation.ipv4_route_ages_seconds.assign(
          forwarding_validation.fib.count, 0U);
      forwarding_validation.ipv6_route_ages_seconds.assign(
          forwarding_validation.ipv6_fib.count, 0U);
      forwarding_validation.sap_attachments = source.ies_sap_attachments;
      forwarding_validation.service_ipv6_interfaces =
          source.ies_ipv6_interfaces;
      forwarding_validation.native_ipv6_addresses =
          source.native_ipv6_addresses;
      for (const auto &port : source.ports)
        if (port.configured) {
          forwarding_validation.ports.push_back(port);
          // Validation uses a minimal synthetic forwarding image rather than
          // the live network checkpoint. Every configured interface still
          // requires independent zero-valued ICMPv4 and ICMPv6 rows because
          // restore rejects counters detached from physical inventory.
          forwarding_validation.icmpv4_interface_statistics.push_back(
              {.port_ordinal = port.ordinal});
          forwarding_validation.icmpv6_interface_statistics.push_back(
              {.port_ordinal = port.ordinal});
          if (port.ipv6_configured) {
            // The synthetic image validates control intent only, but the
            // forwarding checkpoint contract also requires one operational
            // ReachableTime variable per IPv6 interface. Use a canonical
            // in-range sample and nonzero continuation state. Live random
            // state is validated separately in state.network below.
            forwarding_validation.ipv6_reachable_times.push_back(
                {.port_ordinal = port.ordinal,
                 .base_milliseconds = port.nd_reachable_time_milliseconds,
                 .effective_milliseconds = port.nd_reachable_time_milliseconds,
                 .random_state = 1U,
                 .remaining_refresh_nanoseconds = 0});
          }
        }
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
        state.network.hosts.size() != state.hosts.entries.size() ||
        state.network.switches.size() != state.switches.entries.size())
      return false;
    for (const auto &router : state.network.routers) {
      if (!devices->get(router.device) ||
          router.device.index >= control->size() ||
          !(*control)[router.device.index])
        return false;
      const auto &intent = *(*control)[router.device.index];
      if (router.forwarding.sap_attachments != intent.ies_sap_attachments)
        return false;
      if (router.forwarding.service_ipv6_interfaces !=
          intent.ies_ipv6_interfaces)
        return false;
      // Control preserves operator insertion order because that order is part
      // of configuration presentation. The forwarding owner deliberately
      // canonicalizes the same generation by interface, primary preference and
      // address for contiguous packet-path lookup. Comparing the two vectors
      // byte-for-byte therefore rejects a valid multi-interface router merely
      // because the owners use different orderings. Reuse the forwarding
      // table's atomic validator and canonicalizer before comparing values, so
      // malformed records are still rejected without requiring identical
      // presentation order across ownership domains.
      RouterIpv6AddressTable canonical_addresses;
      if (canonical_addresses.program(intent.native_ipv6_addresses) !=
              RouterIpv6AddressProgramStatus::accepted ||
          router.forwarding.native_ipv6_addresses.size() !=
              canonical_addresses.records().size() ||
          !std::equal(router.forwarding.native_ipv6_addresses.begin(),
                      router.forwarding.native_ipv6_addresses.end(),
                      canonical_addresses.records().begin()))
        return false;
      for (const auto &relay : intent.ies_dhcpv6_relays)
        if (std::find(router.forwarding.dhcpv6_relay_interfaces.begin(),
                      router.forwarding.dhcpv6_relay_interfaces.end(),
                      relay) == router.forwarding.dhcpv6_relay_interfaces.end())
          return false;
    }
    for (const auto &host : state.network.hosts)
      if (!hosts->get(host.host))
        return false;
    for (const auto &saved : state.network.switches) {
      const auto *record = switches->get(saved.handle);
      const auto profile_index =
          record ? device_catalog::ethernet_switch_profile_index(
                       record->profile->id)
                 : std::nullopt;
      if (!record || !profile_index ||
          *profile_index != saved.profile_index ||
          saved.forwarding.ports.size() != record->ports.size())
        return false;
      for (std::size_t port{}; port < record->ports.size(); ++port) {
        const auto &intent = record->ports[port];
        const auto &operational =
            saved.forwarding.ports[port].configuration;
        if (!saved.forwarding.ports[port].configured ||
            intent.speed_mbps != operational.speed_mbps ||
            intent.mtu != operational.mtu ||
            intent.admin_enabled != operational.admin_enabled)
          return false;
      }
    }
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

    // NetworkPlane intentionally reconstructs route managers without a second
    // checkpoint copy of control-owned policy, connected routes or static
    // intent. Republish those already validated values now. The restored OSPF
    // owner independently republishes its LSDB-derived generation; whichever
    // arrives first is retained, and the second input triggers one complete
    // RIB selection. Without this handoff, a browser reload could restore a
    // Full adjacency and 34 calculated routes while leaving the manager
    // permanently unconfigured and the forwarding table empty.
    //
    // Network restore above is the owner commit point. Every command below is
    // infallible for the validated, preallocated records staged in `control`;
    // failure is therefore an internal invariant violation, just like a
    // post-swap forwarder restore failure inside NetworkPlane.
    for (const auto &device : state.devices.entries) {
      const auto &router = (*control)[device.handle.index];
      if (!router)
        std::terminate();
      auto &policy = prepare(NetworkCommandKind::program_route_policy);
      policy.device = device.handle;
      policy.fib =
          RoutePolicyProgram{.ipv4_statics = router->statics,
                             .ipv6_statics = router->ipv6_statics,
                             .maximum_ecmp_paths =
                                 router->maximum_ecmp_paths};
      const auto policy_result = dispatch(policy);
      if (!policy_result || !policy_result->success)
        std::terminate();

      auto &ipv4 = prepare(NetworkCommandKind::program_fib);
      ipv4.device = device.handle;
      ipv4.fib = router->rib.compile(router->fib_generation);
      const auto ipv4_result = dispatch(ipv4);
      if (!ipv4_result || !ipv4_result->success)
        std::terminate();

      auto &ipv6 = prepare(NetworkCommandKind::program_ipv6_fib);
      ipv6.device = device.handle;
      ipv6.fib =
          router->ipv6_rib.compile(router->ipv6_fib_generation);
      const auto ipv6_result = dispatch(ipv6);
      if (!ipv6_result || !ipv6_result->success)
        std::terminate();
    }

    // All allocating and fallible work completed before this commit. Registry
    // object addresses stay stable, preserving the workflow controller's
    // reference to sessions_ while their validated contents are replaced.
    devices_ = std::move(*devices);
    hosts_ = std::move(*hosts);
    switches_ = std::move(*switches);
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
