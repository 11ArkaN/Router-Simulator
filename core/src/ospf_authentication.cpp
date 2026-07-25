// RFC 5709 OSPFv2 HMAC-SHA-256 authentication. Fixed storage and segmented
// hashing keep the protocol shard allocation-free and avoid a second packet
// copy during normal transmission.

#include "router/ospf_authentication.hpp"

#include "router/packet.hpp"
#include "router/sha256.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace router::ospf::authentication {
namespace {

constexpr std::size_t packet_length_offset = 2U;
constexpr std::size_t checksum_offset = 12U;
constexpr std::size_t authentication_type_offset = 14U;
constexpr std::size_t key_id_offset = 18U;
constexpr std::size_t digest_length_offset = 19U;
constexpr std::size_t sequence_offset = 20U;
constexpr std::size_t sha256_digest_octets = crypto::sha256_digest_octets;
constexpr std::size_t sha1_digest_octets = 20U;
constexpr std::size_t md5_digest_octets = 16U;
constexpr std::size_t maximum_digest_octets = sha256_digest_octets;
constexpr std::size_t ipv6_header_octets = 40U;
constexpr std::size_t ah_fixed_header_octets = 12U;
constexpr std::size_t ah_icv_octets = 12U;
constexpr std::size_t ah_header_octets =
    ah_fixed_header_octets + ah_icv_octets;
constexpr std::uint8_t ipv6_next_header_ah = 51U;
constexpr std::array<std::uint8_t, 4U> apad_word{
    0x87U, 0x8fU, 0xe1U, 0xf3U};

void write_apad(std::span<std::uint8_t> destination) noexcept;

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

void write64(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint64_t value) noexcept {
  write32(bytes, offset, static_cast<std::uint32_t>(value >> 32U));
  write32(bytes, offset + 4U, static_cast<std::uint32_t>(value));
}

std::uint16_t read16(std::span<const std::uint8_t> bytes,
                     std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) << 8U |
      bytes[offset + 1U]);
}

std::uint32_t read32(std::span<const std::uint8_t> bytes,
                     std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

std::array<std::uint8_t, sha256_digest_octets>
normalized_sha256_key(std::span<const std::uint8_t> key) noexcept {
  // RFC 5709 section 3.3 defines Ko as exactly L octets, unlike generic
  // RFC 2104 normalization which hashes only keys longer than the compression
  // block. The distinction matters for keys between 33 and 64 octets.
  std::array<std::uint8_t, sha256_digest_octets> normalized{};
  if (key.size() > normalized.size()) {
    const auto digest = crypto::sha256(key);
    std::copy(digest.begin(), digest.end(), normalized.begin());
  } else {
    std::copy(key.begin(), key.end(), normalized.begin());
  }
  return normalized;
}

std::size_t digest_size(V2CryptographicAlgorithm algorithm) noexcept {
  switch (algorithm) {
  case V2CryptographicAlgorithm::message_digest_md5:
    return md5_digest_octets;
  case V2CryptographicAlgorithm::hmac_sha1:
    return sha1_digest_octets;
  case V2CryptographicAlgorithm::hmac_sha256:
    return sha256_digest_octets;
  }
  return 0U;
}

const EVP_MD *digest_provider(V2CryptographicAlgorithm algorithm) noexcept {
  return algorithm == V2CryptographicAlgorithm::message_digest_md5
             ? EVP_md5()
         : algorithm == V2CryptographicAlgorithm::hmac_sha1
             ? EVP_sha1()
             : EVP_sha256();
}

bool provider_digest(
    const EVP_MD *algorithm,
    std::span<const std::span<const std::uint8_t>> segments,
    std::span<std::uint8_t> output) noexcept {
  // OSPF control packets are paced and never form the forwarding hot path.
  // EVP keeps MD5 and SHA-1 provider policy in OpenSSL instead of duplicating
  // legacy digest implementations. The context exists only for one bounded
  // packet and is released before this owner turn can process another packet.
  auto *context = EVP_MD_CTX_new();
  if (!context)
    return false;
  bool valid = EVP_DigestInit_ex(context, algorithm, nullptr) == 1;
  for (const auto segment : segments)
    valid = valid &&
            EVP_DigestUpdate(context, segment.data(), segment.size()) == 1;
  unsigned written{};
  valid = valid &&
          EVP_DigestFinal_ex(context, output.data(), &written) == 1 &&
          written == output.size();
  EVP_MD_CTX_free(context);
  return valid;
}

bool hmac_rfc5709(
    V2CryptographicAlgorithm algorithm, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> message,
    std::span<std::uint8_t> output) noexcept {
  constexpr std::size_t compression_block_octets = 64U;
  const auto length = digest_size(algorithm);
  if (!length || length > maximum_digest_octets || output.size() != length)
    return false;
  if (algorithm == V2CryptographicAlgorithm::hmac_sha256) {
    const auto normalized = normalized_sha256_key(key);
    const std::array segments{message};
    const auto digest = crypto::hmac_sha256(normalized, segments);
    std::copy(digest.begin(), digest.end(), output.begin());
    return true;
  }

  std::array<std::uint8_t, maximum_digest_octets> normalized{};
  if (key.size() > length) {
    const std::array segments{key};
    if (!provider_digest(digest_provider(algorithm), segments,
                         std::span<std::uint8_t>{normalized}.first(length)))
      return false;
  } else {
    std::copy(key.begin(), key.end(), normalized.begin());
  }
  std::array<std::uint8_t, compression_block_octets> inner_pad{};
  std::array<std::uint8_t, compression_block_octets> outer_pad{};
  for (std::size_t index{}; index < compression_block_octets; ++index) {
    const auto value =
        index < length ? normalized[index] : std::uint8_t{0U};
    inner_pad[index] = static_cast<std::uint8_t>(value ^ 0x36U);
    outer_pad[index] = static_cast<std::uint8_t>(value ^ 0x5cU);
  }
  std::array<std::uint8_t, maximum_digest_octets> inner_digest{};
  const std::array inner_segments{
      std::span<const std::uint8_t>{inner_pad}, message};
  if (!provider_digest(
          digest_provider(algorithm), inner_segments,
          std::span<std::uint8_t>{inner_digest}.first(length)))
    return false;
  const std::array outer_segments{
      std::span<const std::uint8_t>{outer_pad},
      std::span<const std::uint8_t>{inner_digest}.first(length)};
  return provider_digest(digest_provider(algorithm), outer_segments, output);
}

bool calculate_digest(
    V2CryptographicAlgorithm algorithm, std::span<const std::uint8_t> key,
    std::span<std::uint8_t> wire, std::size_t protocol_octets,
    std::span<std::uint8_t> output) noexcept {
  if (algorithm == V2CryptographicAlgorithm::message_digest_md5) {
    // RFC 2328 D.4.3 defines a sixteen-octet MD5 key appended to the OSPF
    // packet and overwritten by the resulting digest. A shorter configured
    // key is zero-padded; longer material is outside the protocol key domain.
    if (key.size() > md5_digest_octets ||
        output.size() != md5_digest_octets)
      return false;
    std::fill(output.begin(), output.end(), std::uint8_t{0U});
    std::copy(key.begin(), key.end(), output.begin());
    const std::array segments{
        std::span<const std::uint8_t>{wire.data(),
                                     protocol_octets + output.size()}};
    std::array<std::uint8_t, md5_digest_octets> digest{};
    if (!provider_digest(EVP_md5(), segments, digest))
      return false;
    std::copy(digest.begin(), digest.end(), output.begin());
    OPENSSL_cleanse(digest.data(), digest.size());
    return true;
  }

  write_apad(output);
  return hmac_rfc5709(
      algorithm, key,
      std::span<const std::uint8_t>{wire.data(),
                                   protocol_octets + output.size()},
      output);
}

void write_apad(std::span<std::uint8_t> destination) noexcept {
  for (std::size_t index{}; index < destination.size(); ++index)
    destination[index] = apad_word[index % apad_word.size()];
}

bool constant_time_equal(std::span<const std::uint8_t> left,
                         std::span<const std::uint8_t> right) noexcept {
  if (left.size() != right.size())
    return false;
  std::uint8_t difference{};
  for (std::size_t index{}; index < left.size(); ++index)
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  return difference == 0U;
}

} // namespace

std::optional<std::span<const std::uint8_t>>
encode_ipv6_ipsec_ah(
    std::span<std::uint8_t> output, const ip::Ipv6 &source,
    const ip::Ipv6 &destination, std::uint8_t hop_limit, std::uint32_t spi,
    std::uint32_t sequence_number, IpsecAhAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> ospf_packet) noexcept {
  const auto payload_octets = ah_header_octets + ospf_packet.size();
  const auto packet_octets = ipv6_header_octets + payload_octets;
  if (key.empty() || spi == 0U || sequence_number == 0U ||
      payload_octets > std::numeric_limits<std::uint16_t>::max() ||
      packet_octets > output.size())
    return std::nullopt;

  auto wire = output.first(packet_octets);
  std::fill(wire.begin(), wire.end(), std::uint8_t{0U});
  wire[0U] = 0x60U;
  write16(wire, 4U, static_cast<std::uint16_t>(payload_octets));
  wire[6U] = ipv6_next_header_ah;
  wire[7U] = hop_limit;
  std::copy(source.begin(), source.end(), wire.begin() + 8U);
  std::copy(destination.begin(), destination.end(), wire.begin() + 24U);

  const auto ah = ipv6_header_octets;
  wire[ah] = packet::ospf::ip_protocol;
  // RFC 4302 Payload Len counts 32-bit words minus two. A 24-octet AH
  // therefore carries the value four.
  wire[ah + 1U] =
      static_cast<std::uint8_t>(ah_header_octets / 4U - 2U);
  write32(wire, ah + 4U, spi);
  write32(wire, ah + 8U, sequence_number);
  std::copy(ospf_packet.begin(), ospf_packet.end(),
            wire.begin() + ah + ah_header_octets);

  // Hop Limit is mutable in transit and is zero for ICV calculation. OSPF
  // link-local packets normally remain at one, but canonicalization must still
  // follow RFC 4302 rather than relying on that operational fact.
  const auto retained_hop_limit = wire[7U];
  wire[7U] = 0U;
  std::array<std::uint8_t, sha1_digest_octets> digest{};
  const auto hmac_algorithm =
      algorithm == IpsecAhAlgorithm::hmac_md5_96
          ? V2CryptographicAlgorithm::message_digest_md5
          : V2CryptographicAlgorithm::hmac_sha1;
  const auto digest_octets =
      algorithm == IpsecAhAlgorithm::hmac_md5_96
          ? md5_digest_octets
          : sha1_digest_octets;
  const bool valid = hmac_rfc5709(
      hmac_algorithm, key, wire,
      std::span<std::uint8_t>{digest}.first(digest_octets));
  wire[7U] = retained_hop_limit;
  if (!valid) {
    OPENSSL_cleanse(digest.data(), digest.size());
    return std::nullopt;
  }
  std::copy_n(digest.begin(), ah_icv_octets,
              wire.begin() + ah + ah_fixed_header_octets);
  OPENSSL_cleanse(digest.data(), digest.size());
  return wire;
}

std::optional<VerifiedIpsecAh>
verify_ipv6_ipsec_ah(std::span<const std::uint8_t> ipv6_packet,
                     IpsecAhAlgorithm algorithm,
                     std::span<const std::uint8_t> key) noexcept {
  if (key.empty() ||
      ipv6_packet.size() < ipv6_header_octets + ah_header_octets ||
      (ipv6_packet[0U] >> 4U) != 6U ||
      ipv6_packet[6U] != ipv6_next_header_ah)
    return std::nullopt;
  const auto payload_octets = read16(ipv6_packet, 4U);
  if (payload_octets != ipv6_packet.size() - ipv6_header_octets)
    return std::nullopt;
  const auto ah = ipv6_header_octets;
  const auto encoded_ah_octets =
      (static_cast<std::size_t>(ipv6_packet[ah + 1U]) + 2U) * 4U;
  if (ipv6_packet[ah] != packet::ospf::ip_protocol ||
      encoded_ah_octets != ah_header_octets)
    return std::nullopt;
  const auto spi = read32(ipv6_packet, ah + 4U);
  const auto sequence = read32(ipv6_packet, ah + 8U);
  if (spi == 0U || sequence == 0U)
    return std::nullopt;

  // The frame pool bounds this copy to one maximum Ethernet frame. Verification
  // cannot modify shared capture bytes, so a private canonical image is the
  // safe alternative to lending mutable access across shard ownership.
  std::array<std::uint8_t, packet::maximum_frame_octets> canonical{};
  if (ipv6_packet.size() > canonical.size())
    return std::nullopt;
  std::copy(ipv6_packet.begin(), ipv6_packet.end(), canonical.begin());
  canonical[7U] = 0U;
  std::array<std::uint8_t, ah_icv_octets> received{};
  std::copy_n(canonical.begin() + ah + ah_fixed_header_octets,
              received.size(), received.begin());
  std::fill_n(canonical.begin() + ah + ah_fixed_header_octets,
              ah_icv_octets, std::uint8_t{0U});

  std::array<std::uint8_t, sha1_digest_octets> digest{};
  const auto hmac_algorithm =
      algorithm == IpsecAhAlgorithm::hmac_md5_96
          ? V2CryptographicAlgorithm::message_digest_md5
          : V2CryptographicAlgorithm::hmac_sha1;
  const auto digest_octets =
      algorithm == IpsecAhAlgorithm::hmac_md5_96
          ? md5_digest_octets
          : sha1_digest_octets;
  const bool calculated = hmac_rfc5709(
      hmac_algorithm, key,
      std::span<const std::uint8_t>{canonical}.first(ipv6_packet.size()),
      std::span<std::uint8_t>{digest}.first(digest_octets));
  const bool authentic =
      calculated &&
      constant_time_equal(received,
                          std::span<const std::uint8_t>{digest}.first(
                              ah_icv_octets));
  OPENSSL_cleanse(canonical.data(), canonical.size());
  OPENSSL_cleanse(digest.data(), digest.size());
  if (!authentic)
    return std::nullopt;
  return VerifiedIpsecAh{
      .ospf_packet =
          ipv6_packet.subspan(ipv6_header_octets + ah_header_octets),
      .spi = spi,
      .sequence_number = sequence};
}

std::optional<std::span<const std::uint8_t>>
encode_v2_cryptographic(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t key_id,
    std::uint32_t sequence_number, V2CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept {
  const auto digest_octets = digest_size(algorithm);
  const auto protocol_octets =
      packet::ospf::version_two_header_octets + payload.size();
  const auto wire_octets = protocol_octets + digest_octets;
  if (key.empty() || wire_octets > output.size() ||
      protocol_octets > std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;

  auto wire = output.first(wire_octets);
  std::fill(wire.begin(), wire.end(), std::uint8_t{0U});
  wire[0U] = packet::ospf::version_two;
  wire[1U] = static_cast<std::uint8_t>(type);
  write16(wire, packet_length_offset,
          static_cast<std::uint16_t>(protocol_octets));
  write32(wire, 4U, router_id);
  write32(wire, 8U, area_id);
  write16(wire, checksum_offset, 0U);
  write16(wire, authentication_type_offset,
          static_cast<std::uint16_t>(
              packet::ospf::AuthenticationType::cryptographic));
  wire[key_id_offset] = key_id;
  wire[digest_length_offset] =
      static_cast<std::uint8_t>(digest_octets);
  write32(wire, sequence_offset, sequence_number);
  std::copy(payload.begin(), payload.end(),
            wire.begin() + packet::ospf::version_two_header_octets);

  auto trailer = wire.subspan(protocol_octets, digest_octets);
  if (!calculate_digest(algorithm, key, wire, protocol_octets, trailer))
    return std::nullopt;
  return std::span<const std::uint8_t>{wire};
}

bool verify_v2_cryptographic(const packet::ospf::PacketView &packet,
                             V2CryptographicAlgorithm algorithm,
                             std::span<const std::uint8_t> key) noexcept {
  const auto digest_octets = digest_size(algorithm);
  if (key.empty() ||
      packet.version != packet::ospf::version_two ||
      packet.authentication_type != static_cast<std::uint16_t>(
          packet::ospf::AuthenticationType::cryptographic) ||
      packet.authentication_data.size() != digest_octets ||
      packet.authentication[3U] != digest_octets ||
      packet.packet.size() + digest_octets >
          packet::maximum_frame_octets)
    return false;

  std::array<std::uint8_t, packet::maximum_frame_octets> scratch{};
  std::copy(packet.packet.begin(), packet.packet.end(), scratch.begin());
  auto trailer = std::span<std::uint8_t>{scratch}.subspan(
      packet.packet.size(), digest_octets);
  if (!calculate_digest(algorithm, key, scratch, packet.packet.size(),
                        trailer))
    return false;
  return constant_time_equal(trailer, packet.authentication_data);
}

std::optional<std::span<const std::uint8_t>>
encode_v3_authentication_trailer(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t instance_id,
    const ip::Ipv6 &source, std::uint16_t security_association_id,
    std::uint64_t sequence_number, V3CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept {
  constexpr std::size_t fixed_trailer_octets = 16U;
  const auto mapped =
      algorithm == V3CryptographicAlgorithm::hmac_sha1
          ? V2CryptographicAlgorithm::hmac_sha1
          : V2CryptographicAlgorithm::hmac_sha256;
  const auto digest_octets = digest_size(mapped);
  const auto protocol_octets =
      packet::ospf::version_three_header_octets + payload.size();
  const auto trailer_octets = fixed_trailer_octets + digest_octets;
  if (key.empty() || key.size() + 2U > 130U ||
      protocol_octets > std::numeric_limits<std::uint16_t>::max() ||
      protocol_octets + trailer_octets > output.size())
    return std::nullopt;

  auto wire = output.first(protocol_octets + trailer_octets);
  std::fill(wire.begin(), wire.end(), std::uint8_t{0U});
  wire[0U] = packet::ospf::version_three;
  wire[1U] = static_cast<std::uint8_t>(type);
  write16(wire, packet_length_offset,
          static_cast<std::uint16_t>(protocol_octets));
  write32(wire, 4U, router_id);
  write32(wire, 8U, area_id);
  // RFC 7166 requires a zero OSPFv3 checksum when generating an AT. The
  // Authentication Trailer supplies integrity for the packet and source.
  write16(wire, checksum_offset, 0U);
  wire[14U] = instance_id;
  std::copy(payload.begin(), payload.end(),
            wire.begin() + packet::ospf::version_three_header_octets);
  if (type == packet::ospf::PacketType::hello && payload.size() >= 8U)
    wire[packet::ospf::version_three_header_octets + 6U] |= 0x04U;
  else if (type == packet::ospf::PacketType::database_description &&
           payload.size() >= 4U)
    wire[packet::ospf::version_three_header_octets + 2U] |= 0x04U;

  auto trailer = wire.subspan(protocol_octets, trailer_octets);
  write16(trailer, 0U, 1U);
  write16(trailer, 2U, static_cast<std::uint16_t>(trailer_octets));
  write16(trailer, 4U, 0U);
  write16(trailer, 6U, security_association_id);
  write64(trailer, 8U, sequence_number);
  auto authentication_data = trailer.subspan(fixed_trailer_octets);
  std::copy(source.begin(), source.end(), authentication_data.begin());
  for (std::size_t index = source.size();
       index < authentication_data.size(); ++index)
    authentication_data[index] =
        apad_word[(index - source.size()) % apad_word.size()];

  // IANA assigns Cryptographic Protocol ID 1 to OSPFv3. Appending its
  // network-order representation to K creates Ks and prevents cross-protocol
  // replay when an operator reuses key material.
  std::array<std::uint8_t, 130U> protocol_key{};
  std::copy(key.begin(), key.end(), protocol_key.begin());
  protocol_key[key.size() + 1U] = 1U;
  const bool valid = hmac_rfc5709(
      mapped,
      std::span<const std::uint8_t>{protocol_key}.first(key.size() + 2U),
      wire, authentication_data);
  OPENSSL_cleanse(protocol_key.data(), protocol_key.size());
  return valid ? std::optional<std::span<const std::uint8_t>>{
                     std::span<const std::uint8_t>{wire}}
               : std::nullopt;
}

bool verify_v3_authentication_trailer(
    const packet::ospf::PacketView &packet, const ip::Ipv6 &source,
    V3CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key) noexcept {
  constexpr std::size_t fixed_trailer_octets = 16U;
  const auto mapped =
      algorithm == V3CryptographicAlgorithm::hmac_sha1
          ? V2CryptographicAlgorithm::hmac_sha1
          : V2CryptographicAlgorithm::hmac_sha256;
  const auto digest_octets = digest_size(mapped);
  if (packet.version != packet::ospf::version_three || key.empty() ||
      key.size() + 2U > 130U ||
      packet.authentication_trailer.size() !=
          fixed_trailer_octets + digest_octets ||
      packet.authentication_data.size() != digest_octets ||
      read16(packet.authentication_trailer, 0U) != 1U ||
      read16(packet.authentication_trailer, 2U) !=
          packet.authentication_trailer.size())
    return false;
  const auto total = packet.packet.size() +
                     packet.link_local_signaling_data.size() +
                     packet.authentication_trailer.size();
  if (total > packet::maximum_frame_octets)
    return false;
  std::array<std::uint8_t, packet::maximum_frame_octets> scratch{};
  std::size_t offset{};
  auto append = [&](std::span<const std::uint8_t> bytes) {
    std::copy(bytes.begin(), bytes.end(), scratch.begin() + offset);
    offset += bytes.size();
  };
  append(packet.packet);
  append(packet.link_local_signaling_data);
  append(packet.authentication_trailer);
  auto authentication_data =
      std::span<std::uint8_t>{scratch}.subspan(
          total - digest_octets, digest_octets);
  std::copy(source.begin(), source.end(), authentication_data.begin());
  for (std::size_t index = source.size();
       index < authentication_data.size(); ++index)
    authentication_data[index] =
        apad_word[(index - source.size()) % apad_word.size()];
  std::array<std::uint8_t, 130U> protocol_key{};
  std::copy(key.begin(), key.end(), protocol_key.begin());
  protocol_key[key.size() + 1U] = 1U;
  const bool calculated = hmac_rfc5709(
      mapped,
      std::span<const std::uint8_t>{protocol_key}.first(key.size() + 2U),
      std::span<const std::uint8_t>{scratch}.first(total),
      authentication_data);
  OPENSSL_cleanse(protocol_key.data(), protocol_key.size());
  return calculated &&
         constant_time_equal(authentication_data,
                             packet.authentication_data);
}

std::uint16_t v3_security_association_id(
    const packet::ospf::PacketView &packet) noexcept {
  return packet.authentication_trailer.size() >= 8U
             ? read16(packet.authentication_trailer, 6U)
             : 0U;
}

std::uint64_t
v3_sequence_number(const packet::ospf::PacketView &packet) noexcept {
  return packet.authentication_trailer.size() >= 16U
             ? static_cast<std::uint64_t>(
                   read32(packet.authentication_trailer, 8U))
                       << 32U |
                   read32(packet.authentication_trailer, 12U)
             : 0U;
}

std::optional<std::span<const std::uint8_t>>
encode_v2_hmac_sha256(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t key_id,
    std::uint32_t sequence_number, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept {
  return encode_v2_cryptographic(
      output, type, router_id, area_id, key_id, sequence_number,
      V2CryptographicAlgorithm::hmac_sha256, key, payload);
}

bool verify_v2_hmac_sha256(const packet::ospf::PacketView &packet,
                           std::span<const std::uint8_t> key) noexcept {
  return verify_v2_cryptographic(
      packet, V2CryptographicAlgorithm::hmac_sha256, key);
}

std::uint8_t
v2_key_id(const packet::ospf::PacketView &packet) noexcept {
  return packet.authentication[2U];
}

std::uint32_t
v2_sequence_number(const packet::ospf::PacketView &packet) noexcept {
  return static_cast<std::uint32_t>(packet.authentication[4U]) << 24U |
         static_cast<std::uint32_t>(packet.authentication[5U]) << 16U |
         static_cast<std::uint32_t>(packet.authentication[6U]) << 8U |
         static_cast<std::uint32_t>(packet.authentication[7U]);
}

} // namespace router::ospf::authentication
