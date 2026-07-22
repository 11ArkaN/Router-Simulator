// Stable router-local IP interface identity contract. Control and forwarding
// use these values to scope RIB, FIB, Neighbor Discovery, PMTU and transports
// without treating a physical port ordinal as an IP interface. This primitive
// depends only on the generated hardware capacity and owns no mutable state.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <cstdint>
#include <optional>

namespace router::lab {

// Control-allocated service interface IDs occupy the positive low domain used
// by the SR OS service model. The high bit is reserved for native routed-port
// interfaces, making the two sources collision-free without a central table.
inline constexpr std::uint64_t physical_interface_namespace{1ULL << 63U};

[[nodiscard]] constexpr std::uint64_t
physical_interface_id(std::uint16_t port_ordinal) noexcept {
  return physical_interface_namespace | port_ordinal;
}

[[nodiscard]] constexpr std::optional<std::uint16_t>
physical_port_from_interface_id(std::uint64_t interface_id) noexcept {
  if ((interface_id & physical_interface_namespace) == 0U)
    return std::nullopt;
  const auto ordinal = interface_id & ~physical_interface_namespace;
  if (ordinal >= device_catalog::maximum_ports_per_router)
    return std::nullopt;
  return static_cast<std::uint16_t>(ordinal);
}

[[nodiscard]] constexpr bool
is_service_interface_id(std::uint64_t interface_id) noexcept {
  return interface_id != 0U &&
         (interface_id & physical_interface_namespace) == 0U;
}

} // namespace router::lab
