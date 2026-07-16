// Browser-facing multi-router control facade. One Worker owns this object and
// is the only caller of mutating methods. RuntimeSupervisor remains the owner
// of device, forwarding and fabric state; this layer owns portable names and
// configuration text that have no place in the packet path.

#pragma once

#include "router/lab_checkpoint.hpp"
#include "router/control_projection_worker.hpp"
#include "router/device.hpp"
#include "router/runtime_supervisor.hpp"
#include "router/telemetry.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::lab {

class LabRuntime final {
public:
  LabRuntime();
  ~LabRuntime() = default;
  LabRuntime(const LabRuntime &) = delete;
  LabRuntime &operator=(const LabRuntime &) = delete;

  // Protocol 3 accepts one complete netstring message. The first field is a
  // generated operation identity and all remaining fields are operation data.
  // The returned string is borrowed until the next command on this owner.
  [[nodiscard]] std::string_view command(std::string_view message);

  // Capture and checkpoint exports are immutable until their next prepare.
  // Callers copy them into a transferable JavaScript buffer before issuing
  // another operation that could replace the backing vector.
  [[nodiscard]] std::span<const std::uint8_t> prepare_capture() noexcept;
  [[nodiscard]] std::span<const std::uint8_t> prepared_capture() const noexcept {
    return capture_bytes_;
  }
  [[nodiscard]] std::span<const std::uint8_t> export_checkpoint();
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_checkpoint() const noexcept {
    return checkpoint_bytes_;
  }
  [[nodiscard]] bool import_checkpoint(std::span<const std::uint8_t> bytes);

  [[nodiscard]] const TelemetryPageV5 &telemetry_page() const noexcept {
    return telemetry_;
  }

  // Called only by the serialized browser Worker owner at the generated
  // display cadence. It copies bounded runtime projections into the shared
  // seqlock page and never advances a device timer or network queue.
  void refresh_telemetry() noexcept { publish_telemetry(); }

private:
  struct PortIntent {
    std::string id;
    bool admin_enabled{};
    std::uint16_t mtu{device_catalog::default_network_mtu};
    std::uint32_t speed_mbps{};
    std::string description;
    bool operator==(const PortIntent &) const = default;
  };

  struct InterfaceIntent {
    std::string name;
    std::string port_id;
    packet::Mac mac{};
    std::uint32_t address{};
    std::uint8_t prefix_length{};
    bool admin_enabled{};
    bool port_configured{};
    bool address_configured{};
    bool operator==(const InterfaceIntent &) const = default;
  };

  struct StaticRouteIntent {
    std::uint32_t network{};
    std::uint32_t next_hop{};
    std::uint8_t prefix_length{};
    bool operator==(const StaticRouteIntent &) const = default;
  };

  struct MdaConfigurationIntent {
    std::string provisioned;
    bool admin_enabled{};
    bool operator==(const MdaConfigurationIntent &) const = default;
  };

  struct CardConfigurationIntent {
    std::string provisioned;
    bool admin_enabled{};
    std::array<MdaConfigurationIntent,
               device_catalog::maximum_mda_slots_per_card> mdas;
    bool operator==(const CardConfigurationIntent &) const = default;
  };

  // A candidate is a value snapshot of configurable router intent. Equipped
  // hardware, carrier, queues and counters are deliberately excluded because
  // those are operational state and must never be replaced by a CLI commit.
  struct ConfigurationIntent {
    std::string system_name;
    std::array<CardConfigurationIntent,
               device_catalog::maximum_card_slots> cards;
    std::vector<PortIntent> ports;
    std::vector<InterfaceIntent> interfaces;
    std::vector<StaticRouteIntent> routes;
    bool operator==(const ConfigurationIntent &) const = default;
  };

  struct RouterIntent {
    DeviceHandle handle{};
    std::string node_id;
    std::string system_name;
    std::string profile_id;
    std::vector<PortIntent> ports;
    std::vector<InterfaceIntent> interfaces;
    std::vector<StaticRouteIntent> routes;
    ConfigurationIntent global_candidate;
    bool global_candidate_initialized{};
  };

  struct HostIntent {
    HostHandle handle{};
    std::string node_id;
    std::string name;
    packet::Mac mac{};
    packet::Ipv4 address{};
    packet::Ipv4 gateway{};
    std::uint8_t prefix_length{};
    std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
    bool configured{};
  };

  struct SessionIntent {
    SessionHandle handle{};
    std::string session_id;
    // Navigation, prompt markers and engine selection belong to the terminal
    // session, not to the selected router or React. The dynamic router state
    // remains in RouterIntent and RuntimeSupervisor, so this object cannot
    // become a hidden single-router datastore.
    CliSession cli{};
    ConfigurationIntent private_candidate;
    bool private_candidate_initialized{};
    struct PingOperation {
      std::uint32_t destination{};
      std::uint16_t sequence{};
      std::uint16_t payload_octets{56};
      std::uint32_t requested{5};
      std::uint32_t sent{};
      std::uint32_t received{};
      bool dont_fragment{};
      bool waiting{};
      bool active{};
      bool cancel_requested{};
      std::chrono::steady_clock::time_point next_send{};
      std::chrono::steady_clock::time_point sent_at{};
      std::chrono::steady_clock::time_point reply_deadline{};
    } ping;
  };

  struct CaptureIntent {
    // The facade retains portable location keys so repeated UI toggles reuse
    // one PCAPNG interface identity. The forwarding owner receives only the
    // bounded numeric ID and resolved generation-bearing handles.
    CapturePointId id{};
    CapturePointKind kind{};
    std::string object_id;
    std::string port_id;
    std::uint8_t direction{};
    bool selected{};
  };

  [[nodiscard]] RouterIntent *router(std::string_view id) noexcept;
  [[nodiscard]] const RouterIntent *router(std::string_view id) const noexcept;
  [[nodiscard]] HostIntent *host(std::string_view id) noexcept;
  [[nodiscard]] SessionIntent *session(std::string_view id) noexcept;
  [[nodiscard]] const SessionIntent *session(std::string_view id) const noexcept;

  [[nodiscard]] bool create_router(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  replace_router_configuration(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_host(std::span<const std::string_view> fields);
  [[nodiscard]] bool set_card(std::span<const std::string_view> fields);
  [[nodiscard]] bool set_mda(std::span<const std::string_view> fields);
  [[nodiscard]] bool configure_port(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  configure_interface(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  delete_interface(std::span<const std::string_view> fields);
  [[nodiscard]] bool add_static_route(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  delete_static_route(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_link(std::span<const std::string_view> fields);
  [[nodiscard]] bool configure_host(std::span<const std::string_view> fields);
  [[nodiscard]] bool
  replace_capture_selection(std::span<const std::string_view> fields);
  [[nodiscard]] bool create_session(std::span<const std::string_view> fields);
  [[nodiscard]] std::string session_state(std::string_view session_id) const;
  [[nodiscard]] std::string execute_session(std::string_view session_id,
                                            std::string_view input);
  [[nodiscard]] std::string poll_session(std::string_view session_id);
  [[nodiscard]] std::string
  complete_session(std::string_view session_id, std::string_view input,
                   std::string_view trigger) const;
  [[nodiscard]] ConfigurationIntent running_configuration(
      const RouterIntent &router) const;
  [[nodiscard]] PortableConfigurationCheckpoint portable_configuration(
      const ConfigurationIntent &value) const;
  [[nodiscard]] bool apply_configuration(RouterIntent &router,
                                         const ConfigurationIntent &value);
  [[nodiscard]] bool
  configure_capture(std::span<const std::string_view> fields);
  [[nodiscard]] std::string snapshot();
  void publish_telemetry() noexcept;
  void fail(std::string_view reason);
  void succeed(std::string_view value = "ok");

  RuntimeSupervisor supervisor_;
  std::vector<RouterIntent> routers_;
  std::vector<HostIntent> hosts_;
  std::vector<SessionIntent> sessions_;
  std::vector<CaptureIntent> capture_intents_;
  // Present only for the generated high-CPU policy. Declaring it after the
  // supervisor makes it join before the network owners during destruction.
  std::unique_ptr<ControlProjectionWorker> secondary_control_;
  std::uint64_t next_projection_id_{1};
  TelemetryPageV5 telemetry_{};
  std::vector<std::uint8_t> capture_bytes_;
  std::vector<std::uint8_t> checkpoint_bytes_;
  std::string response_;
};

} // namespace router::lab
