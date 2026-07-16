// Multi-device laboratory lifecycle facade. The control shard is the sole
// caller of mutating methods. It coordinates registries, live hardware and the
// link-owned fabric without exposing mutable device pointers to UI code.

#pragma once

#include "router/lab_registry.hpp"
#include "router/network_plane_worker.hpp"
#include "router/router_hardware_inventory.hpp"
#include "router/session_workflows.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab {

struct RouterControlCheckpoint {
  DeviceHandle device{};
  std::array<routing::ConnectedInput,
             device_catalog::maximum_ports_per_router> connected{};
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router> statics{};
  std::array<ForwardPort,
             device_catalog::maximum_ports_per_router> ports{};
  std::array<bool,
             device_catalog::maximum_ports_per_router> interface_admin{};
  routing::FibProgram selected_rib{};
  std::uint64_t fib_generation{};
};

// These records preserve control-facade configuration that is not needed by
// the forwarding shard but is still part of a self-contained laboratory.
// RuntimeSupervisor deliberately does not mutate them during restore. The
// LabRuntime owner validates their handles against the restored registries and
// publishes them only after the supervisor completes its atomic state swap.
struct PortablePortIntentCheckpoint {
  std::string id;
  bool admin_enabled{};
  std::uint16_t mtu{};
  std::uint32_t speed_mbps{};
  std::string description;
};

struct PortableInterfaceIntentCheckpoint {
  std::string name;
  std::string port_id;
  packet::Mac mac{};
  std::uint32_t address{};
  std::uint8_t prefix_length{};
  bool admin_enabled{};
  bool port_configured{};
  bool address_configured{};
};

struct PortableStaticRouteIntentCheckpoint {
  std::uint32_t network{};
  std::uint32_t next_hop{};
  std::uint8_t prefix_length{};
};

struct PortableMdaConfigurationCheckpoint {
  std::string provisioned;
  bool admin_enabled{};
};

struct PortableCardConfigurationCheckpoint {
  std::string provisioned;
  bool admin_enabled{};
  std::array<PortableMdaConfigurationCheckpoint,
             device_catalog::maximum_mda_slots_per_card> mdas;
};

struct PortableConfigurationCheckpoint {
  std::string system_name;
  std::array<PortableCardConfigurationCheckpoint,
             device_catalog::maximum_card_slots> cards;
  std::vector<PortablePortIntentCheckpoint> ports;
  std::vector<PortableInterfaceIntentCheckpoint> interfaces;
  std::vector<PortableStaticRouteIntentCheckpoint> routes;
};

struct PortableRouterIntentCheckpoint {
  DeviceHandle device{};
  std::vector<PortablePortIntentCheckpoint> ports;
  std::vector<PortableInterfaceIntentCheckpoint> interfaces;
  std::vector<PortableStaticRouteIntentCheckpoint> routes;
  PortableConfigurationCheckpoint global_candidate;
  bool global_candidate_initialized{};
};

struct PortableSessionCandidateCheckpoint {
  SessionHandle session{};
  PortableConfigurationCheckpoint candidate;
  bool initialized{};
  std::uint32_t ping_destination{};
  std::uint16_t ping_sequence{};
  std::uint16_t ping_payload_octets{56};
  std::uint32_t ping_requested{};
  std::uint32_t ping_sent{};
  std::uint32_t ping_received{};
  std::uint64_t ping_next_send_ns{};
  std::uint64_t ping_reply_deadline_ns{};
  bool ping_dont_fragment{};
  bool ping_waiting{};
  bool ping_active{};
  bool ping_cancel_requested{};
};

struct PortableHostIntentCheckpoint {
  HostHandle host{};
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{};
  bool configured{};
};

struct PortableCaptureIntentCheckpoint {
  CapturePointId id{};
  CapturePointKind kind{};
  std::string object_id;
  std::string port_id;
  std::uint8_t direction{};
  bool selected{};
};

struct RuntimeSupervisorCheckpoint {
  DeviceRegistryCheckpoint devices;
  HostRegistryCheckpoint hosts;
  TopologyRegistryCheckpoint topology;
  SessionRegistryCheckpoint sessions;
  std::vector<RouterHardwareCheckpoint> hardware;
  std::vector<RouterControlCheckpoint> control;
  SessionWorkflowsCheckpoint workflows;
  NetworkPlaneCheckpoint network;
  std::uint64_t next_network_command_id{};
  std::vector<PortableRouterIntentCheckpoint> portable_routers;
  std::vector<PortableSessionCandidateCheckpoint> portable_session_candidates;
  std::vector<PortableHostIntentCheckpoint> portable_hosts;
  std::vector<PortableCaptureIntentCheckpoint> portable_capture_points;
};

class RuntimeSupervisor final {
public:
  RuntimeSupervisor();
  ~RuntimeSupervisor();
  RuntimeSupervisor(const RuntimeSupervisor &) = delete;
  RuntimeSupervisor &operator=(const RuntimeSupervisor &) = delete;

  [[nodiscard]] std::optional<DeviceHandle>
  create_router(std::string_view node_id, std::string_view profile_id,
                std::string_view system_name);
  [[nodiscard]] std::optional<HostHandle>
  create_host(std::string_view node_id, std::string_view name);
  [[nodiscard]] bool delete_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool delete_host(HostHandle host) noexcept;
  [[nodiscard]] bool set_host_name(HostHandle host,
                                   std::string_view name);
  [[nodiscard]] bool set_system_name(DeviceHandle device,
                                     std::string_view system_name);

  [[nodiscard]] std::optional<SessionHandle>
  create_session(DeviceHandle device, std::string_view session_id);
  [[nodiscard]] bool close_session(SessionHandle session) noexcept;
  // Engine choice is terminal session state persisted by the registry. It has
  // no effect on router configuration and is updated only after the CLI state
  // machine accepts an actual // command.
  [[nodiscard]] bool set_cli_session(SessionHandle session,
                                     const CliSession &state) noexcept;
  [[nodiscard]] SessionWorkflowResult
  enter_session_mode(SessionHandle session, CandidateMode mode) noexcept;
  [[nodiscard]] SessionWorkflowResult
  leave_session_mode(SessionHandle session, bool discard) noexcept;
  [[nodiscard]] SessionWorkflowResult
  transition_session_mode(SessionHandle session, CandidateMode target,
                          bool discard) noexcept;
  [[nodiscard]] SessionWorkflowResult
  record_session_edit(SessionHandle session, std::uint64_t key) noexcept;
  [[nodiscard]] SessionWorkflowResult
  commit_session(SessionHandle session) noexcept;
  [[nodiscard]] SessionWorkflowResult
  discard_session(SessionHandle session) noexcept;
  [[nodiscard]] SessionWorkflowResult
  authorize_classic_write(DeviceHandle device) const noexcept;
  [[nodiscard]] SessionWorkflowResult
  classic_write(DeviceHandle device, std::uint64_t key) noexcept;
  [[nodiscard]] bool
  global_candidate_dirty(DeviceHandle device) const noexcept;
  [[nodiscard]] std::optional<SessionWorkflowStatus>
  session_status(SessionHandle session) const noexcept;

  [[nodiscard]] HardwareEditResult
  set_card(DeviceHandle device, std::uint16_t slot,
           std::string_view provisioned, std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult
  set_mda(DeviceHandle device, std::uint16_t card, std::uint16_t mda,
          std::string_view provisioned, std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult
  set_card_admin(DeviceHandle device, std::uint16_t slot,
                 bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult
  set_mda_admin(DeviceHandle device, std::uint16_t card, std::uint16_t mda,
                bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult
  configure_port(DeviceHandle device, std::string_view port_id,
                 bool admin_enabled, std::uint16_t mtu,
                 std::uint32_t speed_mbps) noexcept;

  [[nodiscard]] std::optional<LinkHandle>
  create_link(std::string_view link_id, const LinkEndpoint &first,
              const LinkEndpoint &second,
              std::chrono::nanoseconds propagation,
              bool admin_enabled = true) noexcept;
  [[nodiscard]] bool delete_link(LinkHandle link) noexcept;
  [[nodiscard]] bool set_link_admin(LinkHandle link, bool enabled) noexcept;
  [[nodiscard]] bool set_link_properties(
      LinkHandle link, bool enabled,
      std::chrono::nanoseconds propagation) noexcept;
  [[nodiscard]] bool configure_interface(DeviceHandle device,
                                         std::string_view port_id,
                                         packet::Mac mac,
                                         std::uint32_t address,
                                         std::uint8_t prefix_length,
                                         bool admin_enabled) noexcept;
  [[nodiscard]] bool remove_interface(DeviceHandle device,
                                      std::string_view port_id) noexcept;
  [[nodiscard]] bool add_static_route(DeviceHandle device,
                                      std::uint32_t network,
                                      std::uint8_t prefix_length,
                                      std::uint32_t next_hop) noexcept;
  [[nodiscard]] bool remove_static_route(DeviceHandle device,
                                         std::uint32_t network,
                                         std::uint8_t prefix_length) noexcept;
  [[nodiscard]] bool start_router_ping(DeviceHandle device,
                                       std::uint32_t destination,
                                       std::uint16_t sequence,
                                       std::uint16_t payload_octets = 56,
                                       bool dont_fragment = false) noexcept;
  [[nodiscard]] bool router_ping_reply(DeviceHandle device,
                                       std::uint16_t sequence) noexcept;
  [[nodiscard]] bool configure_host(HostHandle host, packet::Mac mac,
                                    packet::Ipv4 address,
                                    std::uint8_t prefix_length,
                                    packet::Ipv4 gateway,
                                    std::uint16_t mtu) noexcept;
  [[nodiscard]] bool start_host_ping(
      HostHandle host, packet::Ipv4 destination, std::uint16_t sequence) noexcept;
  [[nodiscard]] bool host_ping_reply(HostHandle host,
                                     std::uint16_t sequence) noexcept;

  [[nodiscard]] RouterHardwareInventory *hardware(DeviceHandle device) noexcept;
  [[nodiscard]] const RouterHardwareInventory *
  hardware(DeviceHandle device) const noexcept;
  [[nodiscard]] const DeviceRegistry &devices() const noexcept {
    return devices_;
  }
  [[nodiscard]] const HostRegistry &hosts() const noexcept { return hosts_; }
  [[nodiscard]] const TopologyRegistry &topology() const noexcept {
    return topology_;
  }
  [[nodiscard]] const SessionRegistry &sessions() const noexcept {
    return sessions_;
  }
  [[nodiscard]] std::size_t active_links() noexcept;
  [[nodiscard]] bool
  configure_capture_point(const CapturePointProgram &program) noexcept;
  [[nodiscard]] std::span<const std::uint8_t> prepare_capture() noexcept;
  [[nodiscard]] std::size_t captured_frames() noexcept;
  [[nodiscard]] std::uint64_t capture_dropped() noexcept;
  [[nodiscard]] std::uint64_t dropped_packets() noexcept;
  [[nodiscard]] std::optional<RouterForwarderCheckpoint>
  router_operational_state(DeviceHandle device) noexcept;
  [[nodiscard]] std::uint64_t network_thread_id() const noexcept {
    return network_worker_ ? network_worker_->owner_thread_id() : 0U;
  }
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept {
    return network_worker_ ? network_worker_->forwarding_owner_count() : 0U;
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept {
    return network_worker_
               ? network_worker_->forwarding_owner_thread_id(index)
               : 0U;
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept {
    return network_worker_ ? network_worker_->forwarding_owner_turns(index)
                           : 0U;
  }
  [[nodiscard]] std::unique_ptr<RuntimeSupervisorCheckpoint> checkpoint();
  [[nodiscard]] bool restore(RuntimeSupervisorCheckpoint state);

private:
  struct ResolvedEndpoint {
    PortHandle handle;
    RouterHardwareInventory *router{};
    RouterPortState *router_port{};
    bool host{};
  };
  struct RouterNetworkState;

  [[nodiscard]] std::optional<ResolvedEndpoint>
  resolve(const LinkEndpoint &endpoint) noexcept;
  void deactivate(LinkHandle link) noexcept;
  void reconcile(LinkHandle link) noexcept;
  void reconcile(NodeHandle node) noexcept;
  void refresh_router(DeviceHandle device) noexcept;
  void rebuild_routes(DeviceHandle device) noexcept;
  [[nodiscard]] NetworkCommand &
  prepare(NetworkCommandKind kind) noexcept;
  [[nodiscard]] std::optional<NetworkResult>
  dispatch(NetworkCommand &command) noexcept;

  DeviceRegistry devices_;
  HostRegistry hosts_;
  TopologyRegistry topology_;
  SessionRegistry sessions_;
  SessionWorkflowController session_workflows_;
  std::array<std::optional<RouterHardwareInventory>,
             device_catalog::maximum_routers>
      hardware_{};
  std::array<std::unique_ptr<RouterNetworkState>,
             device_catalog::maximum_routers>
      router_network_{};
  // Channels are allocated before their worker and outlive it. Control is the
  // only command producer and result consumer; the network pthread owns the
  // reverse endpoints plus every mutable packet and fabric structure.
  // One persistent producer scratch value avoids placing a complete maximum
  // FIB payload on the small control pthread stack for every configuration
  // command. Synchronous dispatch guarantees it is never concurrently reused.
  std::unique_ptr<NetworkCommand> network_command_;
  std::unique_ptr<NetworkPlaneChannels> network_channels_;
  std::unique_ptr<NetworkPlaneWorker> network_worker_;
  std::uint64_t next_network_command_id_{1};
};

} // namespace router::lab
