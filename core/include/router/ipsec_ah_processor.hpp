// Forwarding-owner AH processing composed from SAD, replay, lifetime,
// canonicalization and protected HMAC engine ownership. No Next Header or
// payload is returned until integrity and selectors both succeed.

#pragma once

#include "router/ipsec_integrity.hpp"
#include "router/ipsec_sad.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ipsec {

using AhEngineLookup = integrity::HmacSha256128Engine *(*)(
    void *context, std::uint64_t handle) noexcept;
using AhInboundSelectorValidator = bool (*)(
    void *context, std::uint32_t policy_id, std::uint8_t next_header,
    std::span<const std::uint8_t> payload) noexcept;

struct AhProcessorDependencies {
  void *engine_context{};
  AhEngineLookup find_engine{};
  void *selector_context{};
  AhInboundSelectorValidator validate_inbound_selector{};
};

enum class AhProcessStatus : std::uint8_t {
  ok,
  invalid_argument,
  unsupported_header_chain,
  unknown_sa,
  wrong_sa_direction,
  replay_rejected,
  lifetime_expired,
  sequence_exhausted,
  output_too_small,
  crypto_failure,
  authentication_failed,
  selector_mismatch
};

struct AhProtectResult {
  AhProcessStatus status{AhProcessStatus::invalid_argument};
  std::size_t packet_octets{};
  bool soft_lifetime_reached{};
  bool hard_lifetime_reached{};
};

struct AhVerifyResult {
  AhProcessStatus status{AhProcessStatus::invalid_argument};
  std::size_t payload_offset{};
  std::size_t payload_octets{};
  std::uint8_t next_header{};
  bool soft_lifetime_reached{};
  bool hard_lifetime_reached{};
};

// packet_template already contains an aligned AH header at the supported base
// header offset. This owner writes SPI, Sequence and ICV after reserving the SAD
// sequence. canonical_scratch must be at least the complete packet size.
[[nodiscard]] AhProtectResult protect_ah(
    Sad &sad, std::uint64_t outbound_sa_id,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet_template,
    std::chrono::steady_clock::time_point now, std::span<std::uint8_t> output,
    std::span<std::uint8_t> canonical_scratch) noexcept;

[[nodiscard]] AhVerifyResult verify_ah(
    Sad &sad, const Address &outer_destination, const Address &outer_source,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> canonical_scratch) noexcept;

} // namespace router::ipsec
