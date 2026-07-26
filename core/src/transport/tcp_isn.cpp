// RFC 9293 section 3.4.1 ISN=M+F(tuple,secret). M advances every four real
// monotonic microseconds. HMAC-SHA-256 supplies the external-unpredictability
// property without allocating or exporting the endpoint-owned secret.

#include "router/tcp_isn.hpp"

#include <algorithm>
#include <array>

namespace router::transport::tcp {
namespace {

[[nodiscard]] std::array<std::uint8_t, 2U>
port_bytes(std::uint16_t port) noexcept {
  return {static_cast<std::uint8_t>(port >> 8U),
          static_cast<std::uint8_t>(port)};
}

} // namespace

InitialSequenceGenerator::InitialSequenceGenerator(
    crypto::Sha256Digest secret, Clock::time_point now) noexcept
    : secret_(secret), origin_(now) {}

bool InitialSequenceGenerator::valid() const noexcept {
  // An all-zero value is the portable representation of missing entropy in a
  // project or checkpoint. It must never silently become a public PRF key.
  return std::any_of(secret_.begin(), secret_.end(),
                     [](std::uint8_t byte) { return byte != 0U; });
}

std::uint32_t
InitialSequenceGenerator::clock_value(Clock::time_point now) noexcept {
  if (now <= origin_)
    return last_quanta_;
  const auto elapsed = now - origin_;
  const auto quanta = std::chrono::duration_cast<std::chrono::microseconds>(
                          elapsed).count() /
                      4;
  // Unsigned addition intentionally follows TCP's modulo-2^32 sequence space.
  const auto current = base_quanta_ + static_cast<std::uint32_t>(quanta);
  // Elapsed monotonic time can legitimately wrap the 32-bit M value roughly
  // every 4.77 hours. Assigning the modulo result is correct; treating M as a
  // serial comparison here would freeze it for half of every wrap cycle.
  last_quanta_ = current;
  return last_quanta_;
}

std::uint32_t InitialSequenceGenerator::derive(
    std::uint8_t family, std::span<const std::uint8_t> local_address,
    std::uint16_t local_port, std::span<const std::uint8_t> remote_address,
    std::uint16_t remote_port, Clock::time_point now) noexcept {
  const std::array<std::uint8_t, 1U> family_bytes{family};
  const auto local_port_bytes = port_bytes(local_port);
  const auto remote_port_bytes = port_bytes(remote_port);
  const std::array<std::span<const std::uint8_t>, 5U> tuple{
      family_bytes, local_address, local_port_bytes, remote_address,
      remote_port_bytes};
  const auto digest = crypto::hmac_sha256(secret_, tuple);
  const auto function = (static_cast<std::uint32_t>(digest[0]) << 24U) |
                        (static_cast<std::uint32_t>(digest[1]) << 16U) |
                        (static_cast<std::uint32_t>(digest[2]) << 8U) |
                        digest[3];
  return clock_value(now) + function;
}

std::uint32_t InitialSequenceGenerator::generate(
    packet::Ipv4 local_address, std::uint16_t local_port,
    packet::Ipv4 remote_address, std::uint16_t remote_port,
    Clock::time_point now) noexcept {
  return derive(4U, local_address, local_port, remote_address, remote_port, now);
}

std::uint32_t InitialSequenceGenerator::generate(
    packet::Ipv6 local_address, std::uint16_t local_port,
    packet::Ipv6 remote_address, std::uint16_t remote_port,
    Clock::time_point now) noexcept {
  return derive(6U, local_address, local_port, remote_address, remote_port, now);
}

IsnCheckpoint
InitialSequenceGenerator::checkpoint(Clock::time_point now) noexcept {
  return {.secret = secret_, .clock_quanta = clock_value(now)};
}

bool InitialSequenceGenerator::validate_checkpoint(
    const IsnCheckpoint &state) noexcept {
  return std::any_of(state.secret.begin(), state.secret.end(),
                     [](std::uint8_t byte) { return byte != 0U; });
}

bool InitialSequenceGenerator::restore(const IsnCheckpoint &state,
                                       Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  secret_ = state.secret;
  origin_ = now;
  base_quanta_ = state.clock_quanta;
  last_quanta_ = state.clock_quanta;
  return true;
}

} // namespace router::transport::tcp
