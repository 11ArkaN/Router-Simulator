// IS-IS fixed-header encoding and bounded TLV framing. Mutable storage belongs
// exclusively to the caller. No adjacency, LSDB, configuration or runtime
// dependency is permitted in this wire-format layer.

#include "router/isis_packet.hpp"
#include "router/iso_checksum.hpp"

#include <algorithm>
#include <cstring>

namespace router::packet::isis {
namespace {

[[nodiscard]] bool is_hello(PduType type) noexcept {
  return type == PduType::lan_hello_l1 || type == PduType::lan_hello_l2 ||
         type == PduType::point_to_point_hello;
}

[[nodiscard]] bool is_lsp(PduType type) noexcept {
  return type == PduType::lsp_l1 || type == PduType::lsp_l2;
}

[[nodiscard]] bool is_csnp(PduType type) noexcept {
  return type == PduType::csnp_l1 || type == PduType::csnp_l2;
}

[[nodiscard]] std::size_t header_length(PduType type) noexcept {
  switch (type) {
  case PduType::lan_hello_l1:
  case PduType::lan_hello_l2: return lan_hello_header_octets;
  case PduType::point_to_point_hello: return point_to_point_hello_header_octets;
  case PduType::lsp_l1:
  case PduType::lsp_l2: return lsp_header_octets;
  case PduType::csnp_l1:
  case PduType::csnp_l2: return csnp_header_octets;
  case PduType::psnp_l1:
  case PduType::psnp_l2: return psnp_header_octets;
  }
  return 0U;
}

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                 std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U |
                                    bytes[offset + 1U]);
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  for (std::size_t i = 0U; i < 4U; ++i)
    bytes[offset + i] = static_cast<std::uint8_t>(value >> (24U - i * 8U));
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                  std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

[[nodiscard]] bool framed(std::span<const std::uint8_t> bytes) noexcept {
  TlvCursor cursor(bytes);
  while (cursor.next()) { /* validate every envelope, preserving unknown codes */ }
  return cursor.valid();
}

[[nodiscard]] bool fits(std::span<std::uint8_t> output, std::size_t header,
                        std::span<const std::uint8_t> tlvs,
                        std::uint8_t maximum_areas) noexcept {
  return header != 0U && tlvs.size() <= 65535U - header &&
         output.size() >= header + tlvs.size() && maximum_areas != 255U && framed(tlvs);
}

void initialize(std::span<std::uint8_t> output, PduType type,
                std::uint8_t maximum_areas,
                std::span<const std::uint8_t> tlvs) noexcept {
  const auto header = header_length(type);
  // Moving first permits callers to append into the same bounded buffer and
  // avoids corrupting source TLVs when their input overlaps the future header.
  if (!tlvs.empty())
    std::memmove(output.data() + header, tlvs.data(), tlvs.size());
  std::fill_n(output.begin(), header, std::uint8_t{});
  output[0U] = discriminator;
  output[1U] = static_cast<std::uint8_t>(header);
  output[2U] = 1U;
  output[3U] = 0U; // ISO 10589: zero encodes a six-octet system ID.
  output[4U] = static_cast<std::uint8_t>(type);
  output[5U] = 1U;
  output[7U] = maximum_areas;
  write16(output, is_hello(type) ? 17U : 8U,
          static_cast<std::uint16_t>(header + tlvs.size()));
}

} // namespace

std::optional<TlvView> TlvCursor::next() noexcept {
  if (remaining_.empty())
    return std::nullopt;
  if (remaining_.size() < 2U || remaining_[1U] > remaining_.size() - 2U) {
    valid_ = false;
    remaining_ = {};
    return std::nullopt;
  }
  const auto length = remaining_[1U];
  const TlvView result{remaining_[0U], remaining_.subspan(2U, length)};
  remaining_ = remaining_.subspan(2U + length);
  return result;
}

bool TlvWriter::append(std::uint8_t code, std::span<const std::uint8_t> value) noexcept {
  if (value.size() > 255U || output_.size() - length_ < value.size() + 2U)
    return false;
  if (!value.empty())
    std::memmove(output_.data() + length_ + 2U, value.data(), value.size());
  output_[length_] = code;
  output_[length_ + 1U] = static_cast<std::uint8_t>(value.size());
  length_ += value.size() + 2U;
  return true;
}

bool TlvWriter::pad_to(std::size_t target) noexcept {
  if (target <= length_)
    return true;
  const auto gap = target - length_;
  const auto required = gap == 1U ? 2U : gap;
  if (output_.size() - length_ < required)
    return false;
  auto remaining = required;
  while (remaining != 0U) {
    auto chunk = std::min<std::size_t>(remaining, 257U);
    if (remaining - chunk == 1U)
      --chunk;
    output_[length_] = 8U;
    output_[length_ + 1U] = static_cast<std::uint8_t>(chunk - 2U);
    std::fill_n(output_.begin() + static_cast<std::ptrdiff_t>(length_ + 2U), chunk - 2U,
                std::uint8_t{});
    length_ += chunk;
    remaining -= chunk;
  }
  return true;
}

std::optional<SnpEntry> snp_entry(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() != snp_entry_octets)
    return std::nullopt;
  SnpEntry result;
  result.remaining_seconds = read16(bytes, 0U);
  std::copy_n(bytes.begin() + 2U, result.id.size(), result.id.begin());
  result.sequence = read32(bytes, 10U);
  result.checksum = read16(bytes, 14U);
  return result;
}

bool encode_snp_entry(std::span<std::uint8_t> output, const SnpEntry &entry) noexcept {
  if (output.size() < snp_entry_octets)
    return false;
  write16(output, 0U, entry.remaining_seconds);
  std::copy(entry.id.begin(), entry.id.end(), output.begin() + 2U);
  write32(output, 10U, entry.sequence);
  write16(output, 14U, entry.checksum);
  return true;
}

std::optional<PduView> parse(std::span<const std::uint8_t> bytes,
                             DecodeError &error) noexcept {
  error = DecodeError::none;
  const auto reject = [&error](DecodeError reason) -> std::optional<PduView> {
    error = reason;
    return std::nullopt;
  };
  if (bytes.size() < common_header_octets)
    return reject(DecodeError::truncated);
  if (bytes[0U] != discriminator)
    return reject(DecodeError::discriminator);
  if (bytes[2U] != 1U || bytes[5U] != 1U)
    return reject(DecodeError::version);
  const auto type = static_cast<PduType>(bytes[4U] & 0x1fU);
  const auto header = header_length(type);
  if (header == 0U)
    return reject(DecodeError::pdu_type);
  if (bytes[3U] != 0U && bytes[3U] != 6U)
    return reject(bytes[3U] <= 8U || bytes[3U] == 255U
                      ? DecodeError::unsupported_id_length : DecodeError::invalid_id_length);
  if (bytes[1U] != header)
    return reject(DecodeError::header_length);
  if (bytes.size() < header)
    return reject(DecodeError::truncated);
  const auto length = read16(bytes, is_hello(type) ? 17U : 8U);
  if (length < header || length > bytes.size())
    return reject(DecodeError::pdu_length);
  const auto tlvs = bytes.subspan(header, length - header);
  if (!framed(tlvs))
    return reject(DecodeError::tlv_length);
  return PduView{type, static_cast<std::uint8_t>(bytes[7U] == 0U ? 3U : bytes[7U]),
                 bytes.first(length), tlvs};
}

std::optional<HelloView> hello(const PduView &pdu) noexcept {
  if (!is_hello(pdu.type) || pdu.bytes.size() < header_length(pdu.type))
    return std::nullopt;
  HelloView result;
  std::copy_n(pdu.bytes.begin() + 9U, result.source.size(), result.source.begin());
  result.holding_seconds = read16(pdu.bytes, 15U);
  result.circuit_type = pdu.bytes[8U] & 3U;
  if (pdu.type == PduType::point_to_point_hello)
    result.local_circuit_id = pdu.bytes[19U];
  else {
    result.priority = pdu.bytes[19U] & 0x7fU;
    std::copy_n(pdu.bytes.begin() + 20U, result.designated_id.size(), result.designated_id.begin());
  }
  return result;
}

std::optional<LspView> lsp(const PduView &pdu) noexcept {
  if (!is_lsp(pdu.type) || pdu.bytes.size() < lsp_header_octets)
    return std::nullopt;
  LspView result;
  std::copy_n(pdu.bytes.begin() + 12U, result.id.size(), result.id.begin());
  result.remaining_seconds = read16(pdu.bytes, 10U);
  result.sequence = read32(pdu.bytes, 20U);
  result.checksum = read16(pdu.bytes, 24U);
  result.flags = pdu.bytes[26U];
  return result;
}

std::optional<SnpView> snp(const PduView &pdu) noexcept {
  if ((!is_csnp(pdu.type) && pdu.type != PduType::psnp_l1 && pdu.type != PduType::psnp_l2) ||
      pdu.bytes.size() < header_length(pdu.type))
    return std::nullopt;
  SnpView result;
  std::copy_n(pdu.bytes.begin() + 10U, result.source.size(), result.source.begin());
  result.source_circuit_id = pdu.bytes[16U];
  if (is_csnp(pdu.type)) {
    std::copy_n(pdu.bytes.begin() + 17U, result.first.size(), result.first.begin());
    std::copy_n(pdu.bytes.begin() + 25U, result.last.size(), result.last.begin());
  }
  return result;
}

std::optional<std::span<const std::uint8_t>>
encode_hello(std::span<std::uint8_t> output, const HelloInput &input,
             std::span<const std::uint8_t> tlvs) noexcept {
  if (!is_hello(input.type) || input.circuit_type == 0U || input.circuit_type > 3U ||
      (input.type == PduType::lan_hello_l1 && input.circuit_type == 2U) ||
      (input.type == PduType::lan_hello_l2 && input.circuit_type == 1U) ||
      input.priority > 127U || !fits(output, header_length(input.type), tlvs, input.maximum_area_addresses))
    return std::nullopt;
  initialize(output, input.type, input.maximum_area_addresses, tlvs);
  output[8U] = input.circuit_type;
  std::copy(input.source.begin(), input.source.end(), output.begin() + 9U);
  write16(output, 15U, input.holding_seconds);
  if (input.type == PduType::point_to_point_hello)
    output[19U] = input.local_circuit_id;
  else {
    output[19U] = input.priority;
    std::copy(input.designated_id.begin(), input.designated_id.end(), output.begin() + 20U);
  }
  return std::span<const std::uint8_t>(output.data(), header_length(input.type) + tlvs.size());
}

std::optional<std::span<const std::uint8_t>>
encode_lsp(std::span<std::uint8_t> output, const LspInput &input,
           std::span<const std::uint8_t> tlvs) noexcept {
  const auto system_type = input.flags & 3U;
  if (!is_lsp(input.type) || input.sequence == 0U ||
      (system_type != 1U && system_type != 3U) ||
      (input.type == PduType::lsp_l2 && system_type != 3U) ||
      !fits(output, lsp_header_octets, tlvs, input.maximum_area_addresses))
    return std::nullopt;
  // ISO 10589 7.3.11 seeds from the configured ID before writing the packet,
  // protecting against originating an LSP under an accidentally altered ID.
  const auto seed = iso::accumulate(std::span(input.id).first<6U>());
  initialize(output, input.type, input.maximum_area_addresses, tlvs);
  write16(output, 10U, input.remaining_seconds);
  std::copy(input.id.begin(), input.id.end(), output.begin() + 12U);
  write32(output, 20U, input.sequence);
  output[26U] = input.flags;
  const auto length = lsp_header_octets + tlvs.size();
  // Preflight bounds above make insert's failure conditions impossible here.
  const auto inserted = iso::insert(output.first(length).subspan(lsp_protected_offset),
                                    lsp_checksum_offset - lsp_protected_offset, 6U, seed);
  if (!inserted)
    return std::nullopt;
  return std::span<const std::uint8_t>(output.data(), length);
}

std::optional<std::span<const std::uint8_t>>
encode_snp(std::span<std::uint8_t> output, const SnpInput &input,
           std::span<const std::uint8_t> tlvs) noexcept {
  if ((!is_csnp(input.type) && input.type != PduType::psnp_l1 && input.type != PduType::psnp_l2) ||
      (is_csnp(input.type) && input.last < input.first) ||
      !fits(output, header_length(input.type), tlvs, input.maximum_area_addresses))
    return std::nullopt;
  initialize(output, input.type, input.maximum_area_addresses, tlvs);
  std::copy(input.source.begin(), input.source.end(), output.begin() + 10U);
  if (is_csnp(input.type)) {
    std::copy(input.first.begin(), input.first.end(), output.begin() + 17U);
    std::copy(input.last.begin(), input.last.end(), output.begin() + 25U);
  }
  return std::span<const std::uint8_t>(output.data(), header_length(input.type) + tlvs.size());
}

bool valid_lsp_checksum(const PduView &pdu) noexcept {
  return is_lsp(pdu.type) && pdu.bytes.size() >= lsp_header_octets &&
         iso::valid(pdu.bytes.subspan(lsp_protected_offset));
}

} // namespace router::packet::isis
