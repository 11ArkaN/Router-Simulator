// RFC 7296 sections 3.1 and 3.2 IKE header and generic payload parsing. Exact
// datagram length and reserved-bit checks prevent two parsers from seeing
// different messages, while unknown payload types remain available to the IKE
// state owner for critical-bit processing.

#include "router/ikev2_packet.hpp"

#include <limits>

namespace router::ikev2 {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(bytes[offset] << 8U) |
         bytes[offset + 1U];
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint64_t>(read_u32(bytes, offset)) << 32U |
         read_u32(bytes, offset + 4U);
}

void put_u16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void put_u32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

void put_u64(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint64_t value) noexcept {
  put_u32(bytes, offset, static_cast<std::uint32_t>(value >> 32U));
  put_u32(bytes, offset + 4U, static_cast<std::uint32_t>(value));
}

bool header_semantics_valid(const Header &header) noexcept {
  if (header.initiator_spi == 0U || header.major_version != 2U ||
      header.length < header_octets)
    return false;
  // The responder SPI is zero only in an IKE_SA_INIT request. A response or any
  // later exchange without it cannot identify the responder-owned IKE SA.
  if (header.responder_spi == 0U &&
      (header.response ||
       header.exchange_type !=
           static_cast<std::uint8_t>(ExchangeType::ike_sa_init)))
    return false;
  return true;
}

PayloadChainParseResult parse_chain(
    std::uint8_t first_payload, std::span<const std::uint8_t> encoded,
    std::span<PayloadView> payloads, std::size_t reported_offset_base) noexcept {
  std::size_t offset{};
  std::size_t count{};
  auto type = first_payload;
  while (type != static_cast<std::uint8_t>(PayloadType::none)) {
    if (offset + generic_payload_header_octets > encoded.size())
      return {.status = ParseStatus::truncated_payload,
              .payload_count = count};
    if (count == payloads.size())
      return {.status = ParseStatus::payload_capacity_exhausted,
              .payload_count = count};
    const auto length = read_u16(encoded, offset + 2U);
    if (length < generic_payload_header_octets ||
        offset + length > encoded.size())
      return {.status = ParseStatus::invalid_payload_length,
              .payload_count = count};
    const auto flags = encoded[offset + 1U];
    if ((flags & 0x7fU) != 0U)
      return {.status = ParseStatus::invalid_flags, .payload_count = count};
    const auto next = encoded[offset];
    payloads[count++] = {
        .type = type,
        .next_payload = next,
        .critical = (flags & 0x80U) != 0U,
        .body = encoded.subspan(offset + generic_payload_header_octets,
                                length - generic_payload_header_octets),
        .offset = reported_offset_base + offset};
    offset += length;

    // RFC 7296 section 3.14 and RFC 7383 section 2.5 overload the generic
    // Next Payload octet: for SK and SKF it identifies encrypted plaintext.
    // Following it in the outer datagram would parse ciphertext as headers.
    const bool protected_container =
        type == static_cast<std::uint8_t>(PayloadType::encrypted) ||
        type == static_cast<std::uint8_t>(PayloadType::encrypted_fragment);
    if (protected_container) {
      type = static_cast<std::uint8_t>(PayloadType::none);
      break;
    }
    type = next;
  }
  if (offset != encoded.size())
    return {.status = ParseStatus::trailing_payload_type,
            .payload_count = count};
  return {.status = ParseStatus::ok, .payload_count = count};
}

} // namespace

ParseResult parse(std::span<const std::uint8_t> datagram,
                  std::span<PayloadView> payloads) noexcept {
  if (datagram.size() < header_octets)
    return {.status = ParseStatus::truncated_header};
  Header header{.initiator_spi = read_u64(datagram, 0U),
                .responder_spi = read_u64(datagram, 8U),
                .first_payload = datagram[16U],
                .major_version =
                    static_cast<std::uint8_t>(datagram[17U] >> 4U),
                .minor_version =
                    static_cast<std::uint8_t>(datagram[17U] & 0x0fU),
                .exchange_type = datagram[18U],
                .initiator = (datagram[19U] & 0x08U) != 0U,
                .higher_version_supported = (datagram[19U] & 0x10U) != 0U,
                .response = (datagram[19U] & 0x20U) != 0U,
                .message_id = read_u32(datagram, 20U),
                .length = read_u32(datagram, 24U)};
  if (header.length != datagram.size())
    return {.status = ParseStatus::invalid_length, .header = header};
  if (header.major_version != 2U)
    return {.status = ParseStatus::invalid_version, .header = header};
  // Bits outside I, V and R are reserved and MUST be zero. Treating them as
  // extensions would make authenticated transcript interpretation ambiguous.
  if ((datagram[19U] & 0xc7U) != 0U)
    return {.status = ParseStatus::invalid_flags, .header = header};
  if (!header_semantics_valid(header))
    return {.status = ParseStatus::invalid_spi, .header = header};

  const auto chain = parse_chain(
      header.first_payload, datagram.subspan(header_octets), payloads,
      header_octets);
  return {.status = chain.status,
          .header = header,
          .payload_count = chain.payload_count};
}

PayloadChainParseResult parse_payload_chain(
    std::uint8_t first_payload,
    std::span<const std::uint8_t> encoded_payloads,
    std::span<PayloadView> payloads) noexcept {
  return parse_chain(first_payload, encoded_payloads, payloads, 0U);
}

bool encode_header(const Header &header,
                   std::span<std::uint8_t> output) noexcept {
  if (output.size() < header_octets || header.length > output.size() ||
      !header_semantics_valid(header))
    return false;
  put_u64(output, 0U, header.initiator_spi);
  put_u64(output, 8U, header.responder_spi);
  output[16U] = header.first_payload;
  output[17U] = static_cast<std::uint8_t>((header.major_version << 4U) |
                                          header.minor_version);
  output[18U] = header.exchange_type;
  output[19U] = static_cast<std::uint8_t>(
      (header.initiator ? 0x08U : 0U) |
      (header.higher_version_supported ? 0x10U : 0U) |
      (header.response ? 0x20U : 0U));
  put_u32(output, 20U, header.message_id);
  put_u32(output, 24U, header.length);
  return true;
}

std::size_t encode_payload(std::uint8_t next_payload, bool critical,
                           std::span<const std::uint8_t> body,
                           std::span<std::uint8_t> output) noexcept {
  const auto total = generic_payload_header_octets + body.size();
  if (!encode_payload_header(next_payload, critical, total, output))
    return 0U;
  for (std::size_t index = 0U; index < body.size(); ++index)
    output[generic_payload_header_octets + index] = body[index];
  return total;
}

bool encode_payload_header(std::uint8_t next_payload, bool critical,
                           std::size_t payload_octets,
                           std::span<std::uint8_t> output) noexcept {
  if (payload_octets < generic_payload_header_octets ||
      payload_octets > std::numeric_limits<std::uint16_t>::max() ||
      output.size() < generic_payload_header_octets)
    return false;
  output[0] = next_payload;
  output[1] = critical ? 0x80U : 0U;
  put_u16(output, 2U, static_cast<std::uint16_t>(payload_octets));
  return true;
}

} // namespace router::ikev2
