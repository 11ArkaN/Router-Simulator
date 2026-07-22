// IKEv2 codec tests cover exact RFC 7296 header bytes, bounded payload chains,
// zero-responder-SPI rules and malformed lengths without requiring an IKE SA.

#include "router/ikev2_packet.hpp"

#include <array>
#include <stdexcept>

void ikev2_packet_tests() {
  using namespace router::ikev2;
  const std::array<std::uint8_t, 4> sa_body{0U, 0U, 0U, 0U};
  const std::array<std::uint8_t, 3> nonce_body{1U, 2U, 3U};
  std::array<std::uint8_t, 64> datagram{};
  const auto sa_octets = encode_payload(
      static_cast<std::uint8_t>(PayloadType::nonce), false, sa_body,
      std::span<std::uint8_t>{datagram}.subspan(header_octets));
  const auto nonce_octets = encode_payload(
      static_cast<std::uint8_t>(PayloadType::none), false, nonce_body,
      std::span<std::uint8_t>{datagram}.subspan(header_octets + sa_octets));
  const auto total = header_octets + sa_octets + nonce_octets;
  Header request{.initiator_spi = 0x0102030405060708ULL,
                 .responder_spi = 0U,
                 .first_payload = static_cast<std::uint8_t>(
                     PayloadType::security_association),
                 .major_version = 2U,
                 .minor_version = 0U,
                 .exchange_type =
                     static_cast<std::uint8_t>(ExchangeType::ike_sa_init),
                 .initiator = true,
                 .higher_version_supported = false,
                 .response = false,
                 .message_id = 0U,
                 .length = static_cast<std::uint32_t>(total)};
  if (!encode_header(request, datagram))
    throw std::runtime_error("IKEv2 header encoding rejected valid request");

  std::array<PayloadView, 4> payloads{};
  const auto parsed = parse(
      std::span<const std::uint8_t>{datagram}.first(total), payloads);
  if (parsed.status != ParseStatus::ok || parsed.payload_count != 2U ||
      parsed.header.initiator_spi != request.initiator_spi ||
      parsed.header.responder_spi != 0U || !parsed.header.initiator ||
      parsed.header.response || payloads[0].type != 33U ||
      payloads[0].next_payload != 40U || payloads[0].body.size() != 4U ||
      payloads[1].type != 40U || payloads[1].body.size() != 3U)
    throw std::runtime_error("IKEv2 payload chain did not round trip");

  // A bounded caller must receive explicit overload rather than a silently
  // truncated chain, because the omitted payload may carry authentication data.
  std::array<PayloadView, 1> one_payload{};
  if (parse(std::span<const std::uint8_t>{datagram}.first(total), one_payload)
          .status != ParseStatus::payload_capacity_exhausted)
    throw std::runtime_error("IKEv2 payload capacity was silently truncated");

  auto malformed = datagram;
  malformed[27U] = static_cast<std::uint8_t>(total - 1U);
  if (parse(std::span<const std::uint8_t>{malformed}.first(total), payloads)
          .status != ParseStatus::invalid_length)
    throw std::runtime_error("IKEv2 mismatched message length was accepted");
  malformed = datagram;
  malformed[19U] |= 0x01U;
  if (parse(std::span<const std::uint8_t>{malformed}.first(total), payloads)
          .status != ParseStatus::invalid_flags)
    throw std::runtime_error("IKEv2 reserved header flag was accepted");

  // Zero responder SPI is valid only for an IKE_SA_INIT request. Reusing the
  // same header as IKE_AUTH must fail before a state lookup is attempted.
  malformed = datagram;
  malformed[18U] = static_cast<std::uint8_t>(ExchangeType::ike_auth);
  if (parse(std::span<const std::uint8_t>{malformed}.first(total), payloads)
          .status != ParseStatus::invalid_spi)
    throw std::runtime_error("IKE_AUTH with zero responder SPI was accepted");

  malformed = datagram;
  malformed[header_octets + 2U] = 0U;
  malformed[header_octets + 3U] = 3U;
  if (parse(std::span<const std::uint8_t>{malformed}.first(total), payloads)
          .status != ParseStatus::invalid_payload_length)
    throw std::runtime_error("short IKEv2 generic payload was accepted");

  // An SK Next Payload value identifies the first decrypted payload. It must
  // not make the outer parser walk beyond the encrypted container.
  std::array<std::uint8_t, 37U> encrypted_message{};
  Header encrypted_header{.initiator_spi = 1U,
                          .responder_spi = 2U,
                          .first_payload = static_cast<std::uint8_t>(
                              PayloadType::encrypted),
                          .major_version = 2U,
                          .minor_version = 0U,
                          .exchange_type = static_cast<std::uint8_t>(
                              ExchangeType::informational),
                          .initiator = true,
                          .higher_version_supported = false,
                          .response = false,
                          .message_id = 1U,
                          .length = static_cast<std::uint32_t>(
                              encrypted_message.size())};
  if (!encode_header(encrypted_header, encrypted_message) ||
      encode_payload(static_cast<std::uint8_t>(PayloadType::notify), false,
                     std::array<std::uint8_t, 5U>{},
                     std::span{encrypted_message}.subspan(header_octets)) != 9U)
    throw std::runtime_error("IKEv2 encrypted fixture encoding failed");
  std::array<PayloadView, 2U> encrypted_views{};
  const auto encrypted_parsed = parse(encrypted_message, encrypted_views);
  if (encrypted_parsed.status != ParseStatus::ok ||
      encrypted_parsed.payload_count != 1U ||
      encrypted_views[0].type !=
          static_cast<std::uint8_t>(PayloadType::encrypted) ||
      encrypted_views[0].next_payload !=
          static_cast<std::uint8_t>(PayloadType::notify))
    throw std::runtime_error("IKEv2 encrypted outer chain was misparsed");

  const std::array<std::uint8_t, 5U> inner_body{1U, 2U, 3U, 4U, 5U};
  std::array<std::uint8_t, 9U> inner_encoded{};
  if (encode_payload(0U, false, inner_body, inner_encoded) !=
          inner_encoded.size() ||
      parse_payload_chain(static_cast<std::uint8_t>(PayloadType::notify),
                          inner_encoded, encrypted_views)
              .status != ParseStatus::ok ||
      encrypted_views[0].body.size() != inner_body.size())
    throw std::runtime_error("IKEv2 decrypted payload chain parsing failed");
}
