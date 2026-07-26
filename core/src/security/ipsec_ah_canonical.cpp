// Base-header AH normalization. Field offsets come directly from RFC 791,
// RFC 8200 and RFC 4302 section 3.3.3.1. Mutable fields remain present as zero
// bytes so alignment and authenticated packet length cannot change in transit.

#include "router/ipsec_ah_canonical.hpp"

#include "router/ipsec_integrity.hpp"

#include <algorithm>

namespace router::ipsec::ah {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(bytes[offset]) << 8U |
         bytes[offset + 1U];
}

CanonicalResult canonicalize_ah(
    std::span<const std::uint8_t> packet, std::size_t ah_offset,
    bool ipv6, std::span<std::uint8_t> output) noexcept {
  const auto parsed = parse_ah(packet.subspan(ah_offset), ipv6);
  if (!parsed)
    return {.status = CanonicalStatus::malformed};
  const auto expected_icv_region =
      integrity::hmac_sha256_128_icv_octets + (ipv6 ? 4U : 0U);
  // A 128-bit ICV makes the IPv4 AH 28 octets. IPv6 requires AH to be aligned
  // to eight octets, so four explicit zero padding octets follow that ICV.
  if (parsed->icv.size() != expected_icv_region)
    return {.status = CanonicalStatus::unsupported_icv_length};
  if (output.size() < packet.size())
    return {.status = CanonicalStatus::output_too_small};
  std::copy(packet.begin(), packet.end(), output.begin());
  std::fill_n(output.begin() + static_cast<std::ptrdiff_t>(ah_offset + 12U),
              parsed->icv.size(), std::uint8_t{0});
  auto canonical_view = *parsed;
  canonical_view.icv = std::span<const std::uint8_t>{output}.subspan(
      ah_offset + 12U, parsed->icv.size());
  return {.status = CanonicalStatus::ok,
          .packet_octets = packet.size(),
          .ah = canonical_view};
}

} // namespace

CanonicalResult canonicalize_ipv4(std::span<const std::uint8_t> packet,
                                  std::span<std::uint8_t> output) noexcept {
  if (packet.size() < 20U || (packet[0U] >> 4U) != 4U)
    return {.status = CanonicalStatus::malformed};
  const auto header_octets = static_cast<std::size_t>(packet[0U] & 0x0fU) * 4U;
  if (header_octets < 20U || header_octets > packet.size() ||
      read_u16(packet, 2U) != packet.size())
    return {.status = CanonicalStatus::malformed};
  // Appendix A option mutability is intentionally not approximated. Until all
  // enabled option kinds are classified, a non-base header cannot be secured.
  if (header_octets != 20U || packet[9U] != ip_protocol_ah)
    return {.status = CanonicalStatus::unsupported_header_chain};
  const auto flags_and_offset = read_u16(packet, 6U);
  if ((flags_and_offset & 0x3fffU) != 0U)
    return {.status = CanonicalStatus::fragmented};
  const auto result = canonicalize_ah(packet, header_octets, false, output);
  if (result.status != CanonicalStatus::ok)
    return result;
  // DSCP+ECN, Flags+Fragment Offset, TTL and Header Checksum are mutable and
  // unpredictable. Version, IHL, length, ID, protocol and addresses remain.
  output[1U] = 0U;
  output[6U] = 0U;
  output[7U] = 0U;
  output[8U] = 0U;
  output[10U] = 0U;
  output[11U] = 0U;
  return result;
}

CanonicalResult canonicalize_ipv6(std::span<const std::uint8_t> packet,
                                  std::span<std::uint8_t> output) noexcept {
  if (packet.size() < 40U || (packet[0U] >> 4U) != 6U ||
      static_cast<std::size_t>(read_u16(packet, 4U)) + 40U != packet.size())
    return {.status = CanonicalStatus::malformed};
  // AH after Hop-by-Hop, Destination or Routing headers requires option and
  // predictable-destination processing. Reject that chain until implemented.
  if (packet[6U] != ip_protocol_ah)
    return {.status = CanonicalStatus::unsupported_header_chain};
  const auto result = canonicalize_ah(packet, 40U, true, output);
  if (result.status != CanonicalStatus::ok)
    return result;
  // Preserve the high version nibble and clear Traffic Class, Flow Label and
  // Hop Limit exactly as RFC 4302 specifies for AHv2 compatibility.
  output[0U] = static_cast<std::uint8_t>(output[0U] & 0xf0U);
  output[1U] = 0U;
  output[2U] = 0U;
  output[3U] = 0U;
  output[7U] = 0U;
  return result;
}

} // namespace router::ipsec::ah
