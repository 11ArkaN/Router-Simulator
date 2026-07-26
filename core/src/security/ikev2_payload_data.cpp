// Strict RFC 7296 and RFC 7383 payload-body validation. Exact-length checks
// prevent the IKE SA owner from authenticating one interpretation while later
// state code consumes another. All output spans point into the immutable input
// datagram and therefore remain valid only while that datagram is owned.

#include "router/ikev2_payload_data.hpp"

#include <limits>

namespace router::ikev2 {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) << 8U | bytes[offset + 1U]);
}

bool reserved_zero(std::span<const std::uint8_t> body,
                   std::size_t first) noexcept {
  return body[first] == 0U && body[first + 1U] == 0U &&
         body[first + 2U] == 0U;
}

bool sa_protocol(std::uint8_t protocol) noexcept {
  // RFC 7296 section 3.3 assigns 1 to IKE, 2 to AH and 3 to ESP. Protocol zero
  // is legal only for notifications that are not associated with an SA.
  return protocol >= 1U && protocol <= 3U;
}

} // namespace

BodyParseStatus parse_key_exchange(std::span<const std::uint8_t> body,
                                   KeyExchangeView &view) noexcept {
  if (body.size() < 4U)
    return BodyParseStatus::truncated;
  if (body[2U] != 0U || body[3U] != 0U)
    return BodyParseStatus::invalid_reserved;
  if (read_u16(body, 0U) == 0U || body.size() == 4U)
    return BodyParseStatus::invalid_value;
  view = {.group = read_u16(body, 0U), .data = body.subspan(4U)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_nonce(std::span<const std::uint8_t> body,
                            std::span<const std::uint8_t> &nonce) noexcept {
  if (body.size() < 16U || body.size() > 256U)
    return BodyParseStatus::invalid_length;
  nonce = body;
  return BodyParseStatus::ok;
}

BodyParseStatus parse_notify(std::span<const std::uint8_t> body,
                             NotifyView &view) noexcept {
  if (body.size() < 4U)
    return BodyParseStatus::truncated;
  const auto protocol = body[0U];
  const auto spi_size = body[1U];
  if ((protocol != 0U && !sa_protocol(protocol)) ||
      (protocol == 0U && spi_size != 0U))
    return BodyParseStatus::invalid_protocol;
  if (body.size() < 4U + spi_size)
    return BodyParseStatus::invalid_length;
  view = {.protocol_id = protocol,
          .message_type = read_u16(body, 2U),
          .spi = body.subspan(4U, spi_size),
          .data = body.subspan(4U + spi_size)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_delete(std::span<const std::uint8_t> body,
                             DeleteView &view) noexcept {
  if (body.size() < 4U)
    return BodyParseStatus::truncated;
  const auto protocol = body[0U];
  const auto spi_size = body[1U];
  const auto count = read_u16(body, 2U);
  if (!sa_protocol(protocol))
    return BodyParseStatus::invalid_protocol;
  // Deleting the IKE SA names no SPI because its two SPIs are already in the
  // IKE header. AH and ESP deletes carry one or more 32-bit inbound SPIs.
  if ((protocol == 1U && (spi_size != 0U || count != 0U)) ||
      (protocol != 1U && (spi_size != 4U || count == 0U)))
    return BodyParseStatus::invalid_count;
  const auto encoded_spi_octets =
      static_cast<std::size_t>(count) * static_cast<std::size_t>(spi_size);
  if (body.size() != 4U + encoded_spi_octets)
    return BodyParseStatus::invalid_length;
  view = {.protocol_id = protocol,
          .spi_count = count,
          .encoded_spis = body.subspan(4U)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_identification(std::span<const std::uint8_t> body,
                                     IdentificationView &view) noexcept {
  if (body.size() < 4U)
    return BodyParseStatus::truncated;
  if (!reserved_zero(body, 1U))
    return BodyParseStatus::invalid_reserved;
  if (body[0U] == 0U || body.size() == 4U)
    return BodyParseStatus::invalid_value;
  view = {.type = body[0U], .data = body.subspan(4U)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_authentication(std::span<const std::uint8_t> body,
                                     AuthenticationView &view) noexcept {
  if (body.size() < 4U)
    return BodyParseStatus::truncated;
  if (!reserved_zero(body, 1U))
    return BodyParseStatus::invalid_reserved;
  if (body[0U] == 0U || body.size() == 4U)
    return BodyParseStatus::invalid_value;
  view = {.method = body[0U], .data = body.subspan(4U)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_digital_signature_authentication(
    const AuthenticationView &authentication,
    DigitalSignatureView &view) noexcept {
  if (authentication.method != digital_signature_authentication_method)
    return BodyParseStatus::invalid_value;
  if (authentication.data.size() < 3U)
    return BodyParseStatus::truncated;
  const auto algorithm_octets = authentication.data[0U];
  if (algorithm_octets == 0U ||
      static_cast<std::size_t>(algorithm_octets) + 1U >=
          authentication.data.size())
    return BodyParseStatus::invalid_length;
  view = {.algorithm_identifier_der =
              authentication.data.subspan(1U, algorithm_octets),
          .signature = authentication.data.subspan(1U + algorithm_octets)};
  return BodyParseStatus::ok;
}

BodyParseStatus parse_signature_hash_algorithms(
    const NotifyView &notification, std::span<std::uint16_t> algorithms,
    std::size_t &algorithm_count) noexcept {
  algorithm_count = 0U;
  if (notification.protocol_id != 0U || !notification.spi.empty() ||
      notification.message_type != signature_hash_algorithms_notify)
    return BodyParseStatus::invalid_value;
  if (notification.data.empty() || (notification.data.size() % 2U) != 0U)
    return BodyParseStatus::invalid_length;
  const auto count = notification.data.size() / 2U;
  if (count > algorithms.size())
    return BodyParseStatus::capacity_exhausted;
  for (std::size_t index = 0U; index < count; ++index) {
    const auto value = read_u16(notification.data, index * 2U);
    // Zero is reserved. Future and private-use values remain visible for
    // profile negotiation rather than being guessed as unsupported here.
    if (value == 0U)
      return BodyParseStatus::invalid_value;
    algorithms[index] = value;
  }
  algorithm_count = count;
  return BodyParseStatus::ok;
}

std::size_t encode_signature_hash_algorithms(
    std::span<const std::uint16_t> algorithms,
    std::span<std::uint8_t> output) noexcept {
  if (algorithms.empty() ||
      algorithms.size() > std::numeric_limits<std::size_t>::max() / 2U ||
      output.size() < algorithms.size() * 2U)
    return 0U;
  for (std::size_t index = 0U; index < algorithms.size(); ++index) {
    if (algorithms[index] == 0U)
      return 0U;
    output[index * 2U] = static_cast<std::uint8_t>(algorithms[index] >> 8U);
    output[index * 2U + 1U] = static_cast<std::uint8_t>(algorithms[index]);
  }
  return algorithms.size() * 2U;
}

std::size_t encode_digital_signature_authentication(
    std::span<const std::uint8_t> algorithm_identifier_der,
    std::span<const std::uint8_t> signature,
    std::span<std::uint8_t> output) noexcept {
  if (algorithm_identifier_der.empty() ||
      algorithm_identifier_der.size() > 255U || signature.empty() ||
      output.size() < 1U + algorithm_identifier_der.size() + signature.size())
    return 0U;
  output[0U] = static_cast<std::uint8_t>(algorithm_identifier_der.size());
  for (std::size_t index = 0U; index < algorithm_identifier_der.size(); ++index)
    output[1U + index] = algorithm_identifier_der[index];
  for (std::size_t index = 0U; index < signature.size(); ++index)
    output[1U + algorithm_identifier_der.size() + index] = signature[index];
  return 1U + algorithm_identifier_der.size() + signature.size();
}

ConfigurationParseResult parse_configuration(
    std::span<const std::uint8_t> body,
    std::span<ConfigurationAttributeView> attributes) noexcept {
  if (body.size() < 4U)
    return {.status = BodyParseStatus::truncated};
  if (!reserved_zero(body, 1U) || body[0U] < 1U || body[0U] > 4U)
    return {.status = body[0U] < 1U || body[0U] > 4U
                          ? BodyParseStatus::invalid_value
                          : BodyParseStatus::invalid_reserved};
  std::size_t offset{4U};
  std::size_t count{};
  while (offset < body.size()) {
    if (body.size() - offset < 4U)
      return {.status = BodyParseStatus::invalid_length,
              .configuration_type = body[0U],
              .attribute_count = count};
    if (count == attributes.size())
      return {.status = BodyParseStatus::capacity_exhausted,
              .configuration_type = body[0U],
              .attribute_count = count};
    const auto length = read_u16(body, offset + 2U);
    if (length > body.size() - offset - 4U)
      return {.status = BodyParseStatus::invalid_length,
              .configuration_type = body[0U],
              .attribute_count = count};
    const auto encoded_type = read_u16(body, offset);
    if ((encoded_type & 0x8000U) != 0U)
      return {.status = BodyParseStatus::invalid_reserved,
              .configuration_type = body[0U],
              .attribute_count = count};
    attributes[count++] = {.type = encoded_type,
                           .value = body.subspan(offset + 4U, length)};
    offset += 4U + length;
  }
  return {.status = BodyParseStatus::ok,
          .configuration_type = body[0U],
          .attribute_count = count};
}

BodyParseStatus
parse_encrypted_fragment(std::span<const std::uint8_t> body,
                         EncryptedFragmentView &view) noexcept {
  if (body.size() < 5U)
    return BodyParseStatus::truncated;
  const auto number = read_u16(body, 0U);
  const auto total = read_u16(body, 2U);
  if (number == 0U || total == 0U || number > total)
    return BodyParseStatus::invalid_count;
  view = {.number = number,
          .total = total,
          .encrypted_data = body.subspan(4U)};
  return BodyParseStatus::ok;
}

} // namespace router::ikev2
