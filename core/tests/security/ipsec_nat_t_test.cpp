// NAT traversal tests verify the exact UDP 4500 discriminator. IKE, ESP and
// keepalive bytes remain separate, and zero SPI cannot enter the ESP path.

#include "router/ipsec_nat_t.hpp"

#include <array>
#include <stdexcept>

void ipsec_nat_t_tests() {
  using namespace router::ipsec::nat_t;
  const std::array<std::uint8_t, 5> ike{1U, 2U, 3U, 4U, 5U};
  std::array<std::uint8_t, 32> wire{};
  const auto ike_octets = encode_ike(ike, wire);
  const auto ike_view = classify(
      std::span<const std::uint8_t>{wire}.first(ike_octets));
  if (ike_octets != 9U || ike_view.kind != PayloadKind::ike ||
      ike_view.bytes.size() != ike.size() || ike_view.bytes[0] != 1U)
    throw std::runtime_error("NAT-T Non-ESP Marker handling failed");

  const std::array<std::uint8_t, 10> esp{
      0x10U, 0x20U, 0x30U, 0x40U, 0U, 0U, 0U, 1U, 0xaaU, 0xbbU};
  const auto esp_octets = encode_esp(esp, wire);
  const auto esp_view = classify(
      std::span<const std::uint8_t>{wire}.first(esp_octets));
  if (esp_octets != esp.size() || esp_view.kind != PayloadKind::esp ||
      esp_view.bytes.size() != esp.size())
    throw std::runtime_error("NAT-T ESP discriminator failed");

  if (encode_keepalive(wire) != 1U ||
      classify(std::span<const std::uint8_t>{wire}.first(1U)).kind !=
          PayloadKind::nat_keepalive ||
      classify(std::array<std::uint8_t, 3>{0U, 0U, 0U}).kind !=
          PayloadKind::invalid ||
      encode_esp(std::array<std::uint8_t, 8>{}, wire) != 0U)
    throw std::runtime_error("NAT-T invalid or keepalive payload handling failed");
}
