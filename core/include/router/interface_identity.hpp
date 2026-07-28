// Stable router-local IP interface identity contract. Control and forwarding
// use these values to scope RIB, FIB, Neighbor Discovery, PMTU and transports
// without treating a physical port ordinal as an IP interface. This primitive
// depends only on the generated hardware capacity and owns no mutable state.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/sha256.hpp"

#include <array>
#include <cstdint>
#include <optional>

namespace router::lab {

// Control-allocated service interface IDs occupy the positive low domain used
// by the SR OS service model. The high bit is reserved for native routed-port
// interfaces, making the two sources collision-free without a central table.
inline constexpr std::uint64_t physical_interface_namespace{1ULL << 63U};
// Relay-only DHCP allocation links are protocol scopes rather than IP
// interfaces. Bit 62 keeps them disjoint from both low-domain IES identities
// and high-domain physical identities without registering fake interfaces.
inline constexpr std::uint64_t dhcpv4_allocation_scope_namespace{1ULL << 62U};

[[nodiscard]] constexpr std::uint64_t
dhcpv4_allocation_scope_id(std::uint32_t server_instance,
                           std::uint64_t local_scope) noexcept {
  // The generated server ceiling is far below 2^16. Packing the stable server
  // instance and subnet key makes collision detection arithmetic and portable
  // instead of relying on a process-specific hash.
  return dhcpv4_allocation_scope_namespace |
         (static_cast<std::uint64_t>(server_instance) << 32U) |
         (local_scope & 0xffffffffULL);
}

// The system loopback belongs to the native-interface namespace but has no
// hardware ordinal.  Reserve the first value immediately after the complete
// generated port domain.  This keeps it collision-free with physical and
// service interfaces without a global allocator or a fabricated port zero.
inline constexpr std::uint16_t system_interface_port_ordinal{
    device_catalog::maximum_ports_per_router};
inline constexpr std::uint64_t system_interface_id{
    physical_interface_namespace | system_interface_port_ordinal};

[[nodiscard]] constexpr std::uint64_t
physical_interface_id(std::uint16_t port_ordinal) noexcept {
  return physical_interface_namespace | port_ordinal;
}

[[nodiscard]] inline crypto::Sha256Digest
dhcpv6_link_identity(std::uint64_t interface_id) noexcept {
  // Network byte order gives every owner the same stable RFC link key without
  // exposing native endianness through checkpoints or allocation HMAC input.
  std::array<std::uint8_t, 8U> bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[bytes.size() - 1U - index] =
        static_cast<std::uint8_t>(interface_id >> (index * 8U));
  return crypto::sha256(bytes);
}

[[nodiscard]] constexpr std::uint32_t
ospf_physical_interface_id(std::uint16_t port_ordinal) noexcept {
  // RFC 5340 sections 3.1.2 and 4.2 require a nonzero, router-local Interface
  // ID that stays unchanged while the interface remains operational. The
  // immutable hardware ordinal already has exactly that ownership and
  // lifetime. Converting its zero-based storage index to the positive wire
  // domain is therefore the router's actual allocation policy, not a topology
  // editor value or an SR OS hardware-limit claim.
  return static_cast<std::uint32_t>(port_ordinal) + 1U;
}

[[nodiscard]] constexpr std::uint32_t
ospf_virtual_interface_id(std::uint32_t virtual_ordinal) noexcept {
  // Virtual interfaces share the RFC 5340 router-local Interface ID domain,
  // but have no hardware ordinal. Allocate them immediately after the complete
  // generated physical-port domain so adding or removing a card cannot collide
  // with an already valid physical Interface ID.
  return static_cast<std::uint32_t>(
             device_catalog::maximum_ports_per_router) +
         1U + virtual_ordinal;
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
