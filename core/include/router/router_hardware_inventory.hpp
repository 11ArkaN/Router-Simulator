// Control-owned dynamic hardware inventory for one router. It derives live
// Ethernet ports only from release catalog compatibility and matching physical
// equipment. Topology, routing and UI receive value projections or handles.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/lab_registry.hpp"
#include "router/packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <string>

namespace router::lab {

enum class HardwareEditResult : std::uint8_t {
  applied,
  invalid_slot,
  fixed_hardware,
  unsupported_type,
  incompatible_children
};

struct RouterPortState {
  // Port configuration survives hardware removal. present and generation
  // describe live inventory, while admin, speed and MTU are running intent.
  bool present{};
  // Running port configuration can outlive equipment. When replacement MDA
  // capabilities do not admit the retained speed, inventory remains present
  // but no live PortHandle is issued and carrier reconciliation stays down.
  bool configuration_compatible{true};
  bool hierarchy_enabled{};
  bool admin_enabled{};
  bool link_signal{};
  std::uint16_t generation{1};
  std::uint16_t card_slot{};
  std::uint16_t mda_slot{};
  std::uint16_t port_number{};
  std::uint16_t mtu{device_catalog::default_network_mtu};
  std::uint32_t speed_mbps{};
};

struct RouterMdaCheckpoint {
  std::string provisioned;
  std::string equipped;
  bool admin_enabled{};
};

struct RouterCardCheckpoint {
  std::string provisioned;
  std::string equipped;
  bool admin_enabled{};
  std::array<RouterMdaCheckpoint,
             device_catalog::maximum_mda_slots_per_card> mdas;
};

struct RouterHardwareCheckpoint {
  DeviceHandle device{};
  std::string profile_id;
  std::array<RouterCardCheckpoint,
             device_catalog::maximum_card_slots> cards;
  std::array<RouterPortState,
             device_catalog::maximum_ports_per_router> ports;
};

class RouterHardwareInventory final {
public:
  RouterHardwareInventory() = default;
  RouterHardwareInventory(DeviceHandle device,
                          const device_catalog::DeviceProfile &profile) noexcept;

  // Empty type means absent. Provisioned and equipped identities are distinct
  // so valid mismatch alarms can be represented without inventing live ports.
  [[nodiscard]] HardwareEditResult
  set_card(std::uint16_t slot, std::string_view provisioned,
           std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult
  set_mda(std::uint16_t card_slot, std::uint16_t mda_slot,
          std::string_view provisioned, std::string_view equipped) noexcept;
  [[nodiscard]] HardwareEditResult
  set_card_admin(std::uint16_t slot, bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult
  set_mda_admin(std::uint16_t card_slot, std::uint16_t mda_slot,
                bool enabled) noexcept;
  [[nodiscard]] HardwareEditResult
  configure_port(std::string_view port_id, bool admin_enabled,
                 std::uint16_t mtu, std::uint32_t speed_mbps) noexcept;

  [[nodiscard]] RouterPortState *find(std::string_view port_id) noexcept;
  [[nodiscard]] const RouterPortState *
  find(std::string_view port_id) const noexcept;
  [[nodiscard]] std::optional<PortHandle>
  handle(std::string_view port_id) const noexcept;
  // Returns the fixed coordinate ordinal for any port that can exist on this
  // chassis, even while its card or MDA is absent. Configuration uses this
  // identity; live packet delivery still requires handle().
  [[nodiscard]] std::optional<std::uint16_t>
  coordinate_ordinal(std::string_view port_id) const noexcept;
  [[nodiscard]] std::optional<packet::Mac>
  physical_mac(std::string_view port_id) const noexcept;
  [[nodiscard]] bool set_link_signal(PortHandle port, bool present) noexcept;
  [[nodiscard]] RouterPortState *at(std::uint16_t ordinal) noexcept;
  [[nodiscard]] const RouterPortState *at(std::uint16_t ordinal) const noexcept;
  [[nodiscard]] std::size_t present_ports() const noexcept {
    return present_ports_;
  }
  [[nodiscard]] const device_catalog::DeviceProfile *profile() const noexcept {
    return profile_;
  }
  void checkpoint(RouterHardwareCheckpoint &state) const;
  [[nodiscard]] bool restore(const RouterHardwareCheckpoint &state);

private:
  struct MdaSlot {
    std::string_view provisioned;
    std::string_view equipped;
    bool admin_enabled{};
  };

  struct CardSlot {
    std::string_view provisioned;
    std::string_view equipped;
    bool admin_enabled{};
    std::array<MdaSlot, device_catalog::maximum_mda_slots_per_card> mdas{};
  };

  [[nodiscard]] static std::optional<std::size_t>
  ordinal(std::uint16_t card, std::uint16_t mda,
          std::uint16_t port) noexcept;
  [[nodiscard]] const device_catalog::CardProfile *
  supported_card(std::string_view type) const noexcept;
  void rebuild_ports() noexcept;
  void invalidate_mda_ports(std::uint16_t card, std::uint16_t mda) noexcept;
  void set_presence(std::array<bool, device_catalog::maximum_ports_per_router>
                        &next_presence,
                    std::uint16_t card, std::uint16_t mda,
                    const device_catalog::MdaProfile &profile) noexcept;

  DeviceHandle device_{};
  const device_catalog::DeviceProfile *profile_{};
  std::array<CardSlot, device_catalog::maximum_card_slots> cards_{};
  std::array<RouterPortState, device_catalog::maximum_ports_per_router> ports_{};
  std::size_t present_ports_{};
};

} // namespace router::lab
