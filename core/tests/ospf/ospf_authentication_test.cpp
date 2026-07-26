// OSPF authentication tests use a digest calculated independently with
// Node.js OpenSSL. They cover RFC 5709 key normalization, Apad placement,
// Packet Length exclusion, digest verification and tamper rejection.

#include "router/ospf_authentication.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <stdexcept>

namespace {

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_authentication_tests() {
  using namespace router;
  std::array<std::uint8_t, 20U> hello{};
  write32(hello, 0U, 0xffffff00U);
  write16(hello, 4U, 10U);
  hello[6U] = 2U;
  hello[7U] = 1U;
  write32(hello, 8U, 40U);

  constexpr std::array<std::uint8_t, 19U> key{
      's', 't', 'a', 'n', 'd', 'a', 'r', 'd', 's', '-',
      'b', 'a', 's', 'e', 'd', '-', 'k', 'e', 'y'};
  constexpr std::array<std::uint8_t, 32U> expected_digest{
      0xb2U, 0xd6U, 0xd8U, 0xbbU, 0xd5U, 0xcfU, 0xb6U, 0xbcU,
      0x8dU, 0xe0U, 0x97U, 0xf9U, 0x86U, 0xe1U, 0x56U, 0xd1U,
      0xb4U, 0x8cU, 0x06U, 0xbeU, 0xb3U, 0x7bU, 0xeeU, 0xf3U,
      0x24U, 0x02U, 0x7cU, 0x10U, 0x9fU, 0x76U, 0x43U, 0x73U};

  std::array<std::uint8_t, 128U> storage{};
  const auto encoded = ospf::authentication::encode_v2_hmac_sha256(
      storage, packet::ospf::PacketType::hello, 0x01010101U, 0U, 7U,
      0x01020304U, key, hello);
  const auto decoded =
      encoded ? packet::ospf::parse_packet(*encoded) : std::nullopt;
  require(encoded && decoded &&
              encoded->size() == 24U + hello.size() +
                                     expected_digest.size() &&
              decoded->authentication_data.size() ==
                  expected_digest.size() &&
              std::equal(decoded->authentication_data.begin(),
                         decoded->authentication_data.end(),
                         expected_digest.begin()) &&
              ospf::authentication::v2_key_id(*decoded) == 7U &&
              ospf::authentication::v2_sequence_number(*decoded) ==
                  0x01020304U &&
              ospf::authentication::verify_v2_hmac_sha256(*decoded, key),
          "RFC 5709 HMAC-SHA-256 encoding disagreed with independent vector");

  storage[24U + 4U] ^= 1U;
  const auto tampered = packet::ospf::parse_packet(
      std::span<const std::uint8_t>{storage.data(), encoded->size()});
  require(tampered &&
              !ospf::authentication::verify_v2_hmac_sha256(*tampered, key),
          "OSPFv2 HMAC accepted a modified Hello payload");

  // These fixtures were generated independently with Node's OpenSSL provider.
  // MD5 follows RFC 2328 D.4.3 packet || padded-key hashing. SHA-1 follows the
  // RFC 5709 key normalization and Apad procedure used by the SR OS keychain
  // hmac-sha-1 algorithm.
  constexpr std::array<std::uint8_t, 16U> expected_md5{
      0xeaU, 0xc4U, 0xddU, 0xcbU, 0x95U, 0x66U, 0xefU, 0xc2U,
      0x24U, 0x62U, 0x26U, 0x26U, 0xe2U, 0x85U, 0x72U, 0xf3U};
  constexpr std::array<std::uint8_t, 20U> expected_sha1{
      0xf4U, 0x4aU, 0x02U, 0x11U, 0xd1U, 0x8dU, 0x86U, 0xfbU,
      0x5fU, 0xe7U, 0x8dU, 0x54U, 0x51U, 0x08U, 0xe9U, 0x6cU,
      0x3cU, 0xb6U, 0xdaU, 0xffU};
  constexpr std::array<std::uint8_t, 7U> md5_key{
      'm', 'd', '5', '-', 'k', 'e', 'y'};
  constexpr std::array<std::uint8_t, 17U> sha1_key{
      's', 'h', 'a', '1', '-', 'k', 'e', 'y', 'c',
      'h', 'a', 'i', 'n', '-', 'k', 'e', 'y'};
  const auto verify_algorithm =
      [&](ospf::authentication::V2CryptographicAlgorithm algorithm,
          std::uint8_t key_id, std::span<const std::uint8_t> algorithm_key,
          std::span<const std::uint8_t> expected) {
        std::fill(storage.begin(), storage.end(), std::uint8_t{0U});
        const auto wire = ospf::authentication::encode_v2_cryptographic(
            storage, packet::ospf::PacketType::hello, 0x01010101U, 0U,
            key_id, 0x01020304U, algorithm, algorithm_key, hello);
        const auto view =
            wire ? packet::ospf::parse_packet(*wire) : std::nullopt;
        require(wire && view &&
                    std::equal(view->authentication_data.begin(),
                               view->authentication_data.end(),
                               expected.begin(), expected.end()) &&
                    ospf::authentication::verify_v2_cryptographic(
                        *view, algorithm, algorithm_key),
                "OSPFv2 keyed digest disagreed with independent vector");
      };
  verify_algorithm(
      ospf::authentication::V2CryptographicAlgorithm::message_digest_md5,
      9U, md5_key, expected_md5);
  verify_algorithm(
      ospf::authentication::V2CryptographicAlgorithm::hmac_sha1,
      11U, sha1_key, expected_sha1);

  // This OSPFv3 fixture was calculated independently with Node.js OpenSSL
  // from the RFC 7166 Authentication Trailer layout. It verifies the AT bit,
  // zero checksum, 16-bit SA ID, 64-bit sequence, IPv6-source Apad seed and
  // the IANA OSPFv3 Cryptographic Protocol ID appended to the key.
  constexpr ip::Ipv6 ipv6_source{
      0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
      0U,    0U,    0U, 0U, 0U, 0U, 0U, 1U};
  constexpr std::array<std::uint8_t, 11U> v3_key{
      'v', '3', '-', 'a', 'u', 't', 'h', '-', 'k', 'e', 'y'};
  constexpr std::array<std::uint8_t, 32U> expected_v3_digest{
      0x37U, 0x6cU, 0x21U, 0x8dU, 0x63U, 0xcfU, 0xe0U, 0x12U,
      0x8aU, 0xa7U, 0xa7U, 0x1cU, 0xbfU, 0x55U, 0xfeU, 0xa3U,
      0xf3U, 0x19U, 0xb4U, 0xfcU, 0x49U, 0xfaU, 0xdcU, 0xefU,
      0xf3U, 0xf3U, 0x45U, 0xbfU, 0x70U, 0x00U, 0xb4U, 0x1dU};
  std::array<std::uint8_t, 20U> v3_hello{};
  write16(v3_hello, 4U, 10U);
  write16(v3_hello, 8U, 1U);
  write16(v3_hello, 10U, 40U);
  const auto v3_wire =
      ospf::authentication::encode_v3_authentication_trailer(
          storage, packet::ospf::PacketType::hello, 0x01010101U, 0U, 0U,
          ipv6_source, 42U, 0x0102030405060708ULL,
          ospf::authentication::V3CryptographicAlgorithm::hmac_sha256,
          v3_key, v3_hello);
  const auto v3_view =
      v3_wire ? packet::ospf::parse_packet(*v3_wire) : std::nullopt;
  require(v3_wire && v3_view &&
              v3_view->packet[12U] == 0U &&
              v3_view->packet[13U] == 0U &&
              (v3_view->packet[
                   packet::ospf::version_three_header_octets + 6U] &
               0x04U) != 0U &&
              ospf::authentication::v3_security_association_id(*v3_view) ==
                  42U &&
              ospf::authentication::v3_sequence_number(*v3_view) ==
                  0x0102030405060708ULL &&
              std::equal(v3_view->authentication_data.begin(),
                         v3_view->authentication_data.end(),
                         expected_v3_digest.begin()) &&
              ospf::authentication::verify_v3_authentication_trailer(
                  *v3_view, ipv6_source,
                  ospf::authentication::V3CryptographicAlgorithm::hmac_sha256,
                  v3_key),
          "RFC 7166 Authentication Trailer disagreed with independent vector");
  storage[16U] ^= 1U;
  const auto modified_v3 = packet::ospf::parse_packet(
      std::span<const std::uint8_t>{storage.data(), v3_wire->size()});
  require(modified_v3 &&
              !ospf::authentication::verify_v3_authentication_trailer(
                  *modified_v3, ipv6_source,
                  ospf::authentication::V3CryptographicAlgorithm::hmac_sha256,
                  v3_key),
          "OSPFv3 Authentication Trailer accepted modified payload");

  // RFC 4302 AH protects the IPv6 envelope separately from the OSPFv3
  // checksum. The round trip checks the exact 24-octet AH layout, SPI,
  // sequence and 96-bit ICV truncation. Hop Limit is mutable and therefore
  // changes without invalidating the ICV, while an OSPF payload change must
  // fail authentication.
  constexpr ip::Ipv6 ipv6_destination{
      0xffU, 0x02U, 0U, 0U, 0U, 0U, 0U, 0U,
      0U,    0U,    0U, 0U, 0U, 0U, 0U, 5U};
  std::array<std::uint8_t, 128U> plain_storage{};
  const auto plain_v3 = packet::ospf::encode_version_three(
      plain_storage, packet::ospf::PacketType::hello, 0x01010101U, 0U,
      0U, ipv6_source, ipv6_destination, v3_hello);
  std::array<std::uint8_t, 256U> ah_storage{};
  const auto ah_wire = plain_v3
      ? ospf::authentication::encode_ipv6_ipsec_ah(
            ah_storage, ipv6_source, ipv6_destination, 1U, 4096U, 7U,
            ospf::authentication::IpsecAhAlgorithm::hmac_sha1_96,
            sha1_key, *plain_v3)
      : std::nullopt;
  const auto verified_ah = ah_wire
      ? ospf::authentication::verify_ipv6_ipsec_ah(
            *ah_wire,
            ospf::authentication::IpsecAhAlgorithm::hmac_sha1_96,
            sha1_key)
      : std::nullopt;
  require(ah_wire && verified_ah && (*ah_wire)[6U] == 51U &&
              (*ah_wire)[40U] == packet::ospf::ip_protocol &&
              (*ah_wire)[41U] == 4U && verified_ah->spi == 4096U &&
              verified_ah->sequence_number == 7U &&
              std::equal(verified_ah->ospf_packet.begin(),
                         verified_ah->ospf_packet.end(),
                         plain_v3->begin(), plain_v3->end()),
          "OSPFv3 IPsec AH packet did not round-trip");
  ah_storage[7U] = 64U;
  require(ospf::authentication::verify_ipv6_ipsec_ah(
              std::span<const std::uint8_t>{ah_storage}.first(
                  ah_wire->size()),
              ospf::authentication::IpsecAhAlgorithm::hmac_sha1_96,
              sha1_key)
              .has_value(),
          "AH verification treated mutable IPv6 Hop Limit as immutable");
  ah_storage[ah_wire->size() - 1U] ^= 1U;
  require(!ospf::authentication::verify_ipv6_ipsec_ah(
               std::span<const std::uint8_t>{ah_storage}.first(
                   ah_wire->size()),
               ospf::authentication::IpsecAhAlgorithm::hmac_sha1_96,
               sha1_key),
          "AH verification accepted modified OSPF payload");
}
