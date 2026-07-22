// RFC 4034 and RFC 5155 DNSSEC record conversion. Multi-octet integers are
// always network order, embedded names are never compressed, and type bitmap
// windows are canonicalized before publication.
// Source: ietf.dnssec.records.rfc4034
// Source: ietf.dnssec.nsec3.rfc5155
// Source: ietf.dnssec.ds_sha256.rfc4509

#include "router/dnssec_record.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::dnssec {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(input[offset]) << 8U) |
      input[offset + 1U]);
}

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(input[offset]) << 24U) |
         (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
         input[offset + 3U];
}

void append_u16(std::vector<std::uint8_t> &output,
                std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t> &output,
                std::uint32_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 24U));
  output.push_back(static_cast<std::uint8_t>(value >> 16U));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

bool valid_name(const packet::dns::Name &name) noexcept {
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

packet::dns::Name canonical_name(packet::dns::Name name) noexcept {
  std::size_t offset{};
  while (offset < name.octets && name.wire[offset] != 0U) {
    const auto length = name.wire[offset++];
    for (std::size_t index = 0U; index < length; ++index) {
      auto &octet = name.wire[offset + index];
      if (octet >= 'A' && octet <= 'Z')
        octet = static_cast<std::uint8_t>(octet + ('a' - 'A'));
    }
    offset += length;
  }
  return name;
}

bool encode_type_bitmap(std::span<const std::uint16_t> types,
                        std::vector<std::uint8_t> &output,
                        bool allow_empty = false) {
  if (types.empty())
    return allow_empty;
  std::vector<std::uint16_t> ordered{types.begin(), types.end()};
  std::sort(ordered.begin(), ordered.end());
  if (std::adjacent_find(ordered.begin(), ordered.end()) != ordered.end())
    return false;

  std::vector<std::uint8_t> encoded;
  for (std::size_t begin = 0U; begin < ordered.size();) {
    const auto window = static_cast<std::uint8_t>(ordered[begin] >> 8U);
    std::size_t end = begin;
    std::uint8_t highest{};
    while (end < ordered.size() && (ordered[end] >> 8U) == window) {
      highest = static_cast<std::uint8_t>(ordered[end]);
      ++end;
    }
    const auto bitmap_octets = static_cast<std::uint8_t>(highest / 8U + 1U);
    encoded.push_back(window);
    encoded.push_back(bitmap_octets);
    const auto bitmap_offset = encoded.size();
    encoded.resize(encoded.size() + bitmap_octets, 0U);
    for (std::size_t index = begin; index < end; ++index) {
      const auto low = static_cast<std::uint8_t>(ordered[index]);
      encoded[bitmap_offset + low / 8U] |=
          static_cast<std::uint8_t>(0x80U >> (low % 8U));
    }
    begin = end;
  }
  output.insert(output.end(), encoded.begin(), encoded.end());
  return true;
}

std::optional<std::vector<std::uint16_t>>
decode_type_bitmap(std::span<const std::uint8_t> input,
                   bool allow_empty = false) {
  std::vector<std::uint16_t> types;
  std::size_t offset{};
  std::optional<std::uint8_t> previous_window;
  while (offset < input.size()) {
    if (input.size() - offset < 2U)
      return std::nullopt;
    const auto window = input[offset++];
    const auto length = input[offset++];
    if (length == 0U || length > 32U || input.size() - offset < length ||
        (previous_window && window <= *previous_window) ||
        input[offset + length - 1U] == 0U)
      return std::nullopt;
    for (std::size_t octet = 0U; octet < length; ++octet)
      for (std::uint8_t bit = 0U; bit < 8U; ++bit)
        if ((input[offset + octet] & (0x80U >> bit)) != 0U)
          types.push_back(static_cast<std::uint16_t>(
              (static_cast<std::uint16_t>(window) << 8U) |
              static_cast<std::uint16_t>(octet * 8U + bit)));
    offset += length;
    previous_window = window;
  }
  return types.empty() && !allow_empty ? std::nullopt
                       : std::optional{std::move(types)};
}

bool publish(std::vector<std::uint8_t> staged,
             std::vector<std::uint8_t> &output) {
  if (staged.size() > std::numeric_limits<std::uint16_t>::max())
    return false;
  output = std::move(staged);
  return true;
}

} // namespace

bool encode_dnskey(const Dnskey &value,
                   std::vector<std::uint8_t> &output) noexcept {
  if (value.protocol != dnskey_protocol || value.public_key.empty())
    return false;
  try {
    std::vector<std::uint8_t> staged;
    staged.reserve(4U + value.public_key.size());
    append_u16(staged, value.flags);
    staged.push_back(value.protocol);
    staged.push_back(value.algorithm);
    staged.insert(staged.end(), value.public_key.begin(), value.public_key.end());
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Dnskey>
decode_dnskey(std::span<const std::uint8_t> rdata) noexcept {
  if (rdata.size() < 5U || rdata[2U] != dnskey_protocol)
    return std::nullopt;
  try {
    return Dnskey{.flags = read_u16(rdata, 0U),
                  .protocol = rdata[2U],
                  .algorithm = rdata[3U],
                  .public_key = std::vector<std::uint8_t>(
                      rdata.begin() + 4, rdata.end())};
  } catch (...) {
    return std::nullopt;
  }
}

bool encode_ds(const Ds &value, std::vector<std::uint8_t> &output) noexcept {
  if (value.digest.empty())
    return false;
  try {
    std::vector<std::uint8_t> staged;
    staged.reserve(4U + value.digest.size());
    append_u16(staged, value.key_tag);
    staged.push_back(value.algorithm);
    staged.push_back(value.digest_type);
    staged.insert(staged.end(), value.digest.begin(), value.digest.end());
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Ds> decode_ds(std::span<const std::uint8_t> rdata) noexcept {
  if (rdata.size() < 5U)
    return std::nullopt;
  try {
    return Ds{.key_tag = read_u16(rdata, 0U),
              .algorithm = rdata[2U],
              .digest_type = rdata[3U],
              .digest = std::vector<std::uint8_t>(
                  rdata.begin() + 4, rdata.end())};
  } catch (...) {
    return std::nullopt;
  }
}

bool encode_rrsig(const Rrsig &value,
                  std::vector<std::uint8_t> &output) noexcept {
  if (!valid_name(value.signer_name) || value.signature.empty())
    return false;
  try {
    std::vector<std::uint8_t> staged;
    staged.reserve(18U + value.signer_name.octets + value.signature.size());
    append_u16(staged, value.type_covered);
    staged.push_back(value.algorithm);
    staged.push_back(value.labels);
    append_u32(staged, value.original_ttl);
    append_u32(staged, value.signature_expiration);
    append_u32(staged, value.signature_inception);
    append_u16(staged, value.key_tag);
    const auto signer = canonical_name(value.signer_name);
    staged.insert(staged.end(), signer.wire.begin(),
                  signer.wire.begin() + signer.octets);
    staged.insert(staged.end(), value.signature.begin(), value.signature.end());
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Rrsig>
decode_rrsig(std::span<const std::uint8_t> rdata) noexcept {
  if (rdata.size() < 20U)
    return std::nullopt;
  packet::dns::Name signer;
  const auto name_octets = packet::dns::parse_name(rdata, 18U, signer);
  if (!name_octets || 18U + *name_octets >= rdata.size())
    return std::nullopt;
  try {
    return Rrsig{.type_covered = read_u16(rdata, 0U),
                 .algorithm = rdata[2U],
                 .labels = rdata[3U],
                 .original_ttl = read_u32(rdata, 4U),
                 .signature_expiration = read_u32(rdata, 8U),
                 .signature_inception = read_u32(rdata, 12U),
                 .key_tag = read_u16(rdata, 16U),
                 .signer_name = canonical_name(signer),
                 .signature = std::vector<std::uint8_t>(
                     rdata.begin() + static_cast<std::ptrdiff_t>(
                                         18U + *name_octets),
                     rdata.end())};
  } catch (...) {
    return std::nullopt;
  }
}

bool encode_nsec(const Nsec &value,
                 std::vector<std::uint8_t> &output) noexcept {
  if (!valid_name(value.next_domain))
    return false;
  try {
    std::vector<std::uint8_t> staged;
    // RFC 6840 section 5.1 corrects RFC 4034: unlike an RRSIG signer name,
    // NSEC Next Domain is not lowercased in canonical RDATA. Preserve its
    // uncompressed wire case exactly while canonicalizing only the bitmap.
    staged.insert(staged.end(), value.next_domain.wire.begin(),
                  value.next_domain.wire.begin() + value.next_domain.octets);
    if (!encode_type_bitmap(value.types, staged))
      return false;
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Nsec> decode_nsec(std::span<const std::uint8_t> rdata) noexcept {
  packet::dns::Name next;
  const auto name_octets = packet::dns::parse_name(rdata, 0U, next);
  if (!name_octets || *name_octets >= rdata.size())
    return std::nullopt;
  const auto types = decode_type_bitmap(rdata.subspan(*name_octets));
  return types ? std::optional<Nsec>{
                     Nsec{.next_domain = next,
                          .types = std::move(*types)}}
               : std::nullopt;
}

bool encode_nsec3(const Nsec3 &value,
                  std::vector<std::uint8_t> &output) noexcept {
  if (value.salt.size() > 255U || value.next_hashed_owner.empty() ||
      value.next_hashed_owner.size() > 255U)
    return false;
  try {
    std::vector<std::uint8_t> staged{
        value.hash_algorithm, value.flags,
        static_cast<std::uint8_t>(value.iterations >> 8U),
        static_cast<std::uint8_t>(value.iterations),
        static_cast<std::uint8_t>(value.salt.size())};
    staged.insert(staged.end(), value.salt.begin(), value.salt.end());
    staged.push_back(
        static_cast<std::uint8_t>(value.next_hashed_owner.size()));
    staged.insert(staged.end(), value.next_hashed_owner.begin(),
                  value.next_hashed_owner.end());
    if (!encode_type_bitmap(value.types, staged, true))
      return false;
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Nsec3> decode_nsec3(
    std::span<const std::uint8_t> rdata) noexcept {
  if (rdata.size() < 7U)
    return std::nullopt;
  const auto salt_length = rdata[4U];
  if (rdata.size() < 6U + salt_length)
    return std::nullopt;
  const auto hash_length = rdata[5U + salt_length];
  const auto bitmap_offset = 6U + salt_length + hash_length;
  if (hash_length == 0U || bitmap_offset > rdata.size())
    return std::nullopt;
  const auto types = decode_type_bitmap(rdata.subspan(bitmap_offset), true);
  if (!types)
    return std::nullopt;
  try {
    return Nsec3{
        .hash_algorithm = rdata[0U],
        .flags = rdata[1U],
        .iterations = read_u16(rdata, 2U),
        .salt = std::vector<std::uint8_t>(
            rdata.begin() + 5,
            rdata.begin() + static_cast<std::ptrdiff_t>(5U + salt_length)),
        .next_hashed_owner = std::vector<std::uint8_t>(
            rdata.begin() + static_cast<std::ptrdiff_t>(6U + salt_length),
            rdata.begin() + static_cast<std::ptrdiff_t>(bitmap_offset)),
        .types = std::move(*types)};
  } catch (...) {
    return std::nullopt;
  }
}

bool encode_nsec3param(const Nsec3param &value,
                       std::vector<std::uint8_t> &output) noexcept {
  if (value.flags != 0U || value.salt.size() > 255U)
    return false;
  try {
    std::vector<std::uint8_t> staged{
        value.hash_algorithm, value.flags,
        static_cast<std::uint8_t>(value.iterations >> 8U),
        static_cast<std::uint8_t>(value.iterations),
        static_cast<std::uint8_t>(value.salt.size())};
    staged.insert(staged.end(), value.salt.begin(), value.salt.end());
    return publish(std::move(staged), output);
  } catch (...) {
    return false;
  }
}

std::optional<Nsec3param>
decode_nsec3param(std::span<const std::uint8_t> rdata) noexcept {
  if (rdata.size() < 5U || rdata[1U] != 0U ||
      rdata.size() != 5U + rdata[4U])
    return std::nullopt;
  try {
    return Nsec3param{.hash_algorithm = rdata[0U],
                      .flags = rdata[1U],
                      .iterations = read_u16(rdata, 2U),
                      .salt = std::vector<std::uint8_t>(
                          rdata.begin() + 5, rdata.end())};
  } catch (...) {
    return std::nullopt;
  }
}

std::uint16_t key_tag(
    std::span<const std::uint8_t> dnskey_rdata) noexcept {
  std::uint32_t accumulator{};
  for (std::size_t index = 0U; index < dnskey_rdata.size(); ++index)
    accumulator += (index & 1U) != 0U
                       ? dnskey_rdata[index]
                       : static_cast<std::uint32_t>(dnskey_rdata[index]) << 8U;
  accumulator += (accumulator >> 16U) & 0xffffU;
  return static_cast<std::uint16_t>(accumulator);
}

std::optional<Ds>
make_ds_sha256(const packet::dns::Name &owner,
               std::span<const std::uint8_t> dnskey_rdata) noexcept {
  if (!valid_name(owner))
    return std::nullopt;
  const auto key = decode_dnskey(dnskey_rdata);
  if (!key)
    return std::nullopt;
  const auto canonical_owner = canonical_name(owner);
  crypto::Sha256 hash;
  hash.update(canonical_owner.view());
  hash.update(dnskey_rdata);
  const auto digest = hash.finish();
  return Ds{.key_tag = key_tag(dnskey_rdata),
            .algorithm = key->algorithm,
            .digest_type = ds_digest_sha256,
            .digest = std::vector<std::uint8_t>(digest.begin(), digest.end())};
}

} // namespace router::dnssec
