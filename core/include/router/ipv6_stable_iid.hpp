// RFC 7217 stable opaque IPv6 interface identifier generation. The caller
// owns the secret, stable interface identity, optional network identity and
// persisted DAD counter. This module only derives an IID and cannot generate,
// reveal, store or rotate the secret on its own.

#pragma once

#include "router/ip_address.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace router::host {

inline constexpr std::size_t stable_iid_secret_octets = 32U;
using StableIidSecret = std::array<std::uint8_t, stable_iid_secret_octets>;
using StableInterfaceIdentifier = std::array<std::uint8_t, 8U>;

enum class InterfaceIdentifierMode : std::uint8_t {
  modified_eui64,
  stable_opaque
};

// Preconditions: prefix is canonical, interface_id is nonzero, secret contains
// at least one nonzero byte, and network_id is a stable caller-defined byte
// identity. Postcondition: identical tuples return identical IIDs without
// retaining any input. The DAD counter is interpreted as an unsigned integer
// and must be incremented by the address owner after each detected conflict.
[[nodiscard]] StableInterfaceIdentifier stable_opaque_interface_identifier(
    const ip::Ipv6Prefix &prefix, std::uint64_t interface_id,
    std::span<const std::uint8_t> network_id, std::uint32_t dad_counter,
    const StableIidSecret &secret) noexcept;

// RFC 7217 section 5 recommends rejecting IIDs from the live IANA reserved
// registry before configuring a tentative address. Keeping this predicate in
// the derivation module gives link-local and SLAAC owners one byte-order-safe
// interpretation of the registry ranges without coupling either owner to I/O.
[[nodiscard]] bool is_reserved_ipv6_interface_identifier(
    const StableInterfaceIdentifier &identifier) noexcept;

} // namespace router::host
