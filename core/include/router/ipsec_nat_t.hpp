// UDP encapsulation discriminator for IKEv2 and ESP NAT traversal. The codec
// owns no UDP socket, NAT state or timer. UDP port 4500 payloads arrive from the
// emulator transport and leave as bounded views or encoded bytes for that same
// owner to route through the normal packet path.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ipsec::nat_t {

inline constexpr std::uint16_t ike_port = 500U;
inline constexpr std::uint16_t encapsulated_port = 4500U;

enum class PayloadKind : std::uint8_t {
  invalid,
  ike,
  esp,
  nat_keepalive
};

struct PayloadView {
  PayloadKind kind{PayloadKind::invalid};
  std::span<const std::uint8_t> bytes;
};

// RFC 3948 reserves a four-zero Non-ESP Marker for IKE on UDP 4500. A nonzero
// first word is an ESP SPI. One 0xff octet is the NAT keepalive convention.
[[nodiscard]] PayloadView
classify(std::span<const std::uint8_t> udp_payload) noexcept;

[[nodiscard]] std::size_t
encode_ike(std::span<const std::uint8_t> ike_message,
           std::span<std::uint8_t> output) noexcept;
[[nodiscard]] std::size_t
encode_esp(std::span<const std::uint8_t> esp_packet,
           std::span<std::uint8_t> output) noexcept;
[[nodiscard]] std::size_t
encode_keepalive(std::span<std::uint8_t> output) noexcept;

} // namespace router::ipsec::nat_t
