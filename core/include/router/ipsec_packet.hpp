// Allocation-free AH and ESP structural packet views shared by IPv4 and IPv6.
// Parsing validates only fields that are safe before SAD lookup. Authentication,
// replay commitment, decryption and selector checks belong to the IPsec owner.
// No inner Next Header value is actionable until that owner reports success.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::ipsec {

inline constexpr std::uint8_t ip_protocol_esp = 50U;
inline constexpr std::uint8_t ip_protocol_ah = 51U;

struct AhView {
  std::uint8_t next_header{};
  std::uint32_t spi{};
  std::uint32_t sequence_low{};
  // The ICV length is determined from AH Payload Len after the twelve-octet
  // fixed portion. The selected SA must separately validate its exact length.
  std::span<const std::uint8_t> icv;
  std::size_t header_length{};
};

struct EspView {
  std::uint32_t spi{};
  std::uint32_t sequence_low{};
  // The SA algorithm owns IV, ciphertext, padding, trailer and ICV boundaries.
  // Exposing one opaque remainder prevents a generic parser from guessing them.
  std::span<const std::uint8_t> protected_payload;
};

// AH header length depends on the enclosing address family because IPv6
// requires eight-octet alignment while IPv4 requires four-octet alignment.
[[nodiscard]] std::optional<AhView>
parse_ah(std::span<const std::uint8_t> packet, bool enclosing_ipv6) noexcept;
[[nodiscard]] std::optional<EspView>
parse_esp(std::span<const std::uint8_t> packet) noexcept;

} // namespace router::ipsec
