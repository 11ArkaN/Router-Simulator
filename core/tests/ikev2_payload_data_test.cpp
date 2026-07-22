// IKEv2 payload-body tests cover each fixed prefix, exact nested length and the
// RFC 7383 fragment numbering rules before any state-machine side effect.

#include "router/ikev2_payload_data.hpp"

#include <array>
#include <stdexcept>

void ikev2_payload_data_tests() {
  using namespace router::ikev2;

  const std::array<std::uint8_t, 8U> ke{0U, 14U, 0U, 0U,
                                        1U, 2U, 3U, 4U};
  KeyExchangeView key_exchange{};
  if (parse_key_exchange(ke, key_exchange) != BodyParseStatus::ok ||
      key_exchange.group != 14U || key_exchange.data.size() != 4U)
    throw std::runtime_error("IKEv2 KE payload parsing failed");
  auto invalid_ke = ke;
  invalid_ke[2U] = 1U;
  if (parse_key_exchange(invalid_ke, key_exchange) !=
      BodyParseStatus::invalid_reserved)
    throw std::runtime_error("IKEv2 KE reserved field was accepted");

  const std::array<std::uint8_t, 16U> nonce_bytes{};
  std::span<const std::uint8_t> nonce;
  if (parse_nonce(nonce_bytes, nonce) != BodyParseStatus::ok ||
      nonce.size() != nonce_bytes.size())
    throw std::runtime_error("IKEv2 minimum nonce was rejected");
  if (parse_nonce(std::span{nonce_bytes}.first(15U), nonce) !=
      BodyParseStatus::invalid_length)
    throw std::runtime_error("undersized IKEv2 nonce was accepted");

  const std::array<std::uint8_t, 10U> notify{3U, 4U, 0x40U, 0x09U,
                                             0U, 0U, 1U, 2U, 9U, 8U};
  NotifyView notification{};
  if (parse_notify(notify, notification) != BodyParseStatus::ok ||
      notification.protocol_id != 3U || notification.spi.size() != 4U ||
      notification.data.size() != 2U)
    throw std::runtime_error("IKEv2 Notify payload parsing failed");

  const std::array<std::uint8_t, 12U> deletion{
      3U, 4U, 0U, 2U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 2U};
  DeleteView delete_view{};
  if (parse_delete(deletion, delete_view) != BodyParseStatus::ok ||
      delete_view.spi_count != 2U || delete_view.encoded_spis.size() != 8U)
    throw std::runtime_error("IKEv2 Delete payload parsing failed");
  const std::array<std::uint8_t, 4U> ike_delete{1U, 0U, 0U, 0U};
  if (parse_delete(ike_delete, delete_view) != BodyParseStatus::ok)
    throw std::runtime_error("IKEv2 IKE SA Delete payload was rejected");

  const std::array<std::uint8_t, 8U> identity{1U, 0U, 0U, 0U,
                                              10U, 0U, 0U, 1U};
  IdentificationView identification{};
  if (parse_identification(identity, identification) != BodyParseStatus::ok ||
      identification.type != 1U || identification.data.size() != 4U)
    throw std::runtime_error("IKEv2 Identification payload parsing failed");
  AuthenticationView authentication{};
  if (parse_authentication(identity, authentication) != BodyParseStatus::ok ||
      authentication.method != 1U)
    throw std::runtime_error("IKEv2 Authentication payload parsing failed");

  const std::array<std::uint16_t, 2U> hashes{
      static_cast<std::uint16_t>(SignatureHashAlgorithm::sha2_256),
      static_cast<std::uint16_t>(SignatureHashAlgorithm::sha2_512)};
  std::array<std::uint8_t, 8U> hash_notify{};
  hash_notify[2U] = static_cast<std::uint8_t>(
      signature_hash_algorithms_notify >> 8U);
  hash_notify[3U] =
      static_cast<std::uint8_t>(signature_hash_algorithms_notify);
  if (encode_signature_hash_algorithms(hashes,
                                       std::span{hash_notify}.subspan(4U)) !=
      4U ||
      parse_notify(hash_notify, notification) != BodyParseStatus::ok)
    throw std::runtime_error("IKEv2 signature hash Notify encoding failed");
  std::array<std::uint16_t, 4U> decoded_hashes{};
  std::size_t decoded_hash_count{};
  if (parse_signature_hash_algorithms(notification, decoded_hashes,
                                      decoded_hash_count) !=
          BodyParseStatus::ok ||
      decoded_hash_count != hashes.size() || decoded_hashes[0U] != hashes[0U] ||
      decoded_hashes[1U] != hashes[1U])
    throw std::runtime_error("IKEv2 signature hash Notify parsing failed");

  const std::array<std::uint8_t, 15U> rsa_sha256_identifier{
      0x30U, 0x0dU, 0x06U, 0x09U, 0x2aU, 0x86U, 0x48U, 0x86U,
      0xf7U, 0x0dU, 0x01U, 0x01U, 0x0bU, 0x05U, 0x00U};
  const std::array<std::uint8_t, 4U> signature{1U, 2U, 3U, 4U};
  std::array<std::uint8_t, 24U> signature_auth{};
  signature_auth[0U] = digital_signature_authentication_method;
  if (encode_digital_signature_authentication(
          rsa_sha256_identifier, signature,
          std::span{signature_auth}.subspan(4U)) != 20U ||
      parse_authentication(signature_auth, authentication) !=
          BodyParseStatus::ok)
    throw std::runtime_error("IKEv2 digital signature AUTH encoding failed");
  DigitalSignatureView signature_view{};
  if (parse_digital_signature_authentication(authentication, signature_view) !=
          BodyParseStatus::ok ||
      signature_view.algorithm_identifier_der.size() !=
          rsa_sha256_identifier.size() ||
      signature_view.signature.size() != signature.size())
    throw std::runtime_error("IKEv2 digital signature AUTH parsing failed");

  const std::array<std::uint8_t, 12U> configuration{
      1U, 0U, 0U, 0U, 0U, 8U, 0U, 4U, 10U, 0U, 0U, 1U};
  std::array<ConfigurationAttributeView, 2U> attributes{};
  const auto parsed_configuration =
      parse_configuration(configuration, attributes);
  if (parsed_configuration.status != BodyParseStatus::ok ||
      parsed_configuration.configuration_type != 1U ||
      parsed_configuration.attribute_count != 1U ||
      attributes[0U].type != 8U || attributes[0U].value.size() != 4U)
    throw std::runtime_error("IKEv2 Configuration payload parsing failed");

  const std::array<std::uint8_t, 7U> fragment{0U, 1U, 0U, 2U, 7U, 8U, 9U};
  EncryptedFragmentView fragment_view{};
  if (parse_encrypted_fragment(fragment, fragment_view) !=
          BodyParseStatus::ok ||
      fragment_view.number != 1U || fragment_view.total != 2U ||
      fragment_view.encrypted_data.size() != 3U)
    throw std::runtime_error("IKEv2 Encrypted Fragment parsing failed");
  auto invalid_fragment = fragment;
  invalid_fragment[1U] = 3U;
  if (parse_encrypted_fragment(invalid_fragment, fragment_view) !=
      BodyParseStatus::invalid_count)
    throw std::runtime_error("invalid IKEv2 fragment numbering was accepted");
}
