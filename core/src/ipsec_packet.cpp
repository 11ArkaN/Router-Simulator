// RFC 4302 and RFC 4303 fixed-header parsers. These routines intentionally do
// not return plaintext, verify ICVs or mutate replay windows. Their only job is
// to produce a bounded SAD lookup key without reading beyond received bytes.

#include "router/ipsec_packet.hpp"

namespace router::ipsec {
namespace {

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

} // namespace

std::optional<AhView> parse_ah(std::span<const std::uint8_t> packet,
                               bool enclosing_ipv6) noexcept {
  if (packet.size() < 12U)
    return std::nullopt;
  const auto length =
      (static_cast<std::size_t>(packet[1]) + 2U) * 4U;
  const auto alignment = enclosing_ipv6 ? 8U : 4U;
  if (length < 12U || length > packet.size() || length % alignment != 0U ||
      packet[2] != 0U || packet[3] != 0U)
    return std::nullopt;
  const auto spi = read_u32(packet, 4U);
  // RFC 4302 reserves SPI zero for local implementation-specific use and
  // forbids it on the wire. Reject it before any table lookup or audit label.
  if (spi == 0U)
    return std::nullopt;
  return AhView{.next_header = packet[0],
                .spi = spi,
                .sequence_low = read_u32(packet, 8U),
                .icv = packet.subspan(12U, length - 12U),
                .header_length = length};
}

std::optional<EspView>
parse_esp(std::span<const std::uint8_t> packet) noexcept {
  if (packet.size() < 8U)
    return std::nullopt;
  const auto spi = read_u32(packet, 0U);
  // The same zero-SPI rule applies to ESP. Values 1 through 255 are reserved by
  // IANA but remain structurally parseable because a receiver may use future
  // assignments; the release-specific SAD decides whether a matching SA exists.
  if (spi == 0U)
    return std::nullopt;
  return EspView{.spi = spi,
                 .sequence_low = read_u32(packet, 4U),
                 .protected_payload = packet.subspan(8U)};
}

} // namespace router::ipsec
