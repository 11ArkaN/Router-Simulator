// RFC 3948 UDP-encapsulated ESP and Non-ESP Marker processing. Classification
// is intentionally exact so a zero SPI cannot be reinterpreted as ESP and an
// undersized marker cannot reach the IKE parser.

#include "router/ipsec_nat_t.hpp"

#include <algorithm>

namespace router::ipsec::nat_t {

PayloadView classify(std::span<const std::uint8_t> udp_payload) noexcept {
  if (udp_payload.size() == 1U && udp_payload[0] == 0xffU)
    return {.kind = PayloadKind::nat_keepalive, .bytes = {}};
  if (udp_payload.size() < 4U)
    return {};
  const auto marker = static_cast<std::uint32_t>(udp_payload[0]) << 24U |
                      static_cast<std::uint32_t>(udp_payload[1]) << 16U |
                      static_cast<std::uint32_t>(udp_payload[2]) << 8U |
                      udp_payload[3];
  if (marker == 0U) {
    if (udp_payload.size() == 4U)
      return {};
    return {.kind = PayloadKind::ike, .bytes = udp_payload.subspan(4U)};
  }
  // ESP contains no marker. Preserve SPI as the first four bytes for SAD lookup.
  return {.kind = PayloadKind::esp, .bytes = udp_payload};
}

std::size_t encode_ike(std::span<const std::uint8_t> ike_message,
                       std::span<std::uint8_t> output) noexcept {
  if (ike_message.empty() || output.size() < ike_message.size() + 4U)
    return 0U;
  std::fill_n(output.begin(), 4U, std::uint8_t{0});
  std::copy(ike_message.begin(), ike_message.end(), output.begin() + 4);
  return ike_message.size() + 4U;
}

std::size_t encode_esp(std::span<const std::uint8_t> esp_packet,
                       std::span<std::uint8_t> output) noexcept {
  if (esp_packet.size() < 8U || output.size() < esp_packet.size() ||
      std::all_of(esp_packet.begin(), esp_packet.begin() + 4,
                  [](std::uint8_t byte) { return byte == 0U; }))
    return 0U;
  std::copy(esp_packet.begin(), esp_packet.end(), output.begin());
  return esp_packet.size();
}

std::size_t encode_keepalive(std::span<std::uint8_t> output) noexcept {
  if (output.empty())
    return 0U;
  output[0] = 0xffU;
  return 1U;
}

} // namespace router::ipsec::nat_t
