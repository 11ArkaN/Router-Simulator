// RFC 7296 NAT detection hash construction for IPv4 and IPv6 endpoints. The
// IKE SA owner compares the received notify value with this fixed-size result;
// this primitive owns no endpoint state and performs no address migration.

#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace router::ikev2 {

using NatDetectionHash = std::array<std::uint8_t, 20U>;

enum class NatDetectionStatus : std::uint8_t {
  ok,
  invalid_address,
  provider_failure
};

[[nodiscard]] NatDetectionStatus compute_nat_detection_hash(
    std::uint64_t initiator_spi, std::uint64_t responder_spi,
    std::span<const std::uint8_t> ip_address, std::uint16_t port,
    NatDetectionHash &output) noexcept;

[[nodiscard]] bool equal_nat_detection_hash(
    const NatDetectionHash &expected,
    std::span<const std::uint8_t> received) noexcept;

} // namespace router::ikev2
