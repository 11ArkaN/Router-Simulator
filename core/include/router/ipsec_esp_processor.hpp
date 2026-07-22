// Forwarding-owner ESP processing that composes SAD lookup, sequence allocation,
// anti-replay, AES-GCM, lifetimes and post-decryption selector validation. The
// key provider is a narrow shard-local callback and never exposes key bytes.

#pragma once

#include "router/ipsec_esp_gcm.hpp"
#include "router/ipsec_sad.hpp"

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <span>

namespace router::ipsec {

using EspEngineLookup = esp_gcm::Engine *(*)(void *context,
                                              std::uint64_t handle) noexcept;
using InboundSelectorValidator = bool (*)(
    void *context, std::uint32_t policy_id, std::uint8_t next_header,
    std::span<const std::uint8_t> plaintext) noexcept;

struct EspProcessorDependencies {
  void *engine_context{};
  EspEngineLookup find_engine{};
  void *selector_context{};
  InboundSelectorValidator validate_inbound_selector{};
};

enum class EspProcessStatus : std::uint8_t {
  ok,
  invalid_argument,
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

struct EspProtectResult {
  EspProcessStatus status{EspProcessStatus::invalid_argument};
  std::size_t packet_octets{};
  bool soft_lifetime_reached{};
  bool hard_lifetime_reached{};
};

struct EspUnprotectResult {
  EspProcessStatus status{EspProcessStatus::invalid_argument};
  std::size_t plaintext_octets{};
  std::uint8_t next_header{};
  bool soft_lifetime_reached{};
  bool hard_lifetime_reached{};
};

[[nodiscard]] EspProtectResult protect_esp(
    Sad &sad, std::uint64_t outbound_sa_id,
    const EspProcessorDependencies &dependencies, std::uint8_t next_header,
    std::span<const std::uint8_t> plaintext,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> output) noexcept;

[[nodiscard]] EspUnprotectResult unprotect_esp(
    Sad &sad, const Address &outer_destination, const Address &outer_source,
    const EspProcessorDependencies &dependencies,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> plaintext_output) noexcept;

} // namespace router::ipsec
