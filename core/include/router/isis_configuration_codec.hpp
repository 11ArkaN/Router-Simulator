// Portable IS-IS intent encoding belongs to the persistence coordinator.
// Detached values cross this boundary; no live protocol state or pointer does.
#pragma once
#include "router/isis_configuration.hpp"
#include <memory>
#include <span>
namespace router::isis::configuration_codec {
// Version 2 appends six optional wait-timer leaves to each instance. Version 1
// remains readable with absent timer leaves. Both use little-endian integers
// and canonical one-byte bools,
// presence-prefixed optional leaves, uint32 vector counts and uint16 UTF-8 byte
// lengths. Limits are coordinator allocation guards, not SR OS platform limits.
// Failure returns empty without changing input. Success owns all returned bytes.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode(
    const RouterConfiguration &, std::size_t maximum_image_bytes) noexcept;
// Decode validates the complete model and rejects trailing bytes before returning
// detached ownership. A cumulative allocation budget is charged before reserve.
// Input storage need only outlive this synchronous call; refusal changes no owner.
[[nodiscard]] std::unique_ptr<RouterConfiguration> decode(
    std::span<const std::uint8_t>, std::size_t maximum_allocation_bytes) noexcept;
}
