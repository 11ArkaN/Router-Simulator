// RFC 9293 clock-driven, secret-keyed initial sequence number generator.
// One endpoint owner retains the secret and clock continuity state. The PRF
// consumes only connection tuples and never reads topology or peer state.

#pragma once

#include "router/packet.hpp"
#include "router/sha256.hpp"

#include <chrono>
#include <cstdint>

namespace router::transport::tcp {

struct IsnCheckpoint {
  crypto::Sha256Digest secret{};
  std::uint32_t clock_quanta{};
};

class InitialSequenceGenerator final {
public:
  using Clock = std::chrono::steady_clock;

  explicit InitialSequenceGenerator(
      crypto::Sha256Digest secret,
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] bool valid() const noexcept;
  [[nodiscard]] std::uint32_t generate(
      packet::Ipv4 local_address, std::uint16_t local_port,
      packet::Ipv4 remote_address, std::uint16_t remote_port,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::uint32_t generate(
      packet::Ipv6 local_address, std::uint16_t local_port,
      packet::Ipv6 remote_address, std::uint16_t remote_port,
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] IsnCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] static bool
  validate_checkpoint(const IsnCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const IsnCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] std::uint32_t clock_value(Clock::time_point now) noexcept;
  [[nodiscard]] std::uint32_t derive(
      std::uint8_t family, std::span<const std::uint8_t> local_address,
      std::uint16_t local_port,
      std::span<const std::uint8_t> remote_address,
      std::uint16_t remote_port, Clock::time_point now) noexcept;

  crypto::Sha256Digest secret_{};
  Clock::time_point origin_{};
  std::uint32_t base_quanta_{};
  std::uint32_t last_quanta_{};
};

} // namespace router::transport::tcp
