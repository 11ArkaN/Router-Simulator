// Instance TLV framing and PDU-level consistency rules. State belongs to each
// call, while packet bytes remain with their caller. Legacy and 2016 profiles
// are never inferred from length or silently substituted for one another.
// Source: ietf.isis.multi_instance.legacy_2009
// Source: ietf.isis.multi_instance.standard_2016

#include "router/isis_instance_tlv.hpp"

#include <array>

namespace router::packet::isis {
namespace {
[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U | bytes[offset + 1U]);
}
void write16(std::span<std::uint8_t> bytes, std::size_t offset, std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}
}

std::optional<std::uint16_t> InstanceTlvView::topology(std::size_t index) const noexcept {
  if (index >= topology_count()) return std::nullopt;
  return read16(encoded_topologies, index * 2U);
}

std::optional<InstanceTlvView> decode_instance_tlv(TlvView tlv, InstanceFormat format) noexcept {
  const auto size = tlv.value.size();
  if (format > InstanceFormat::standard_2016 || tlv.code != 7U || size < 2U || size > 254U || size % 2U)
    return std::nullopt;
  InstanceTlvView result{read16(tlv.value, 0U), tlv.value.subspan(2U)};
  if (format == InstanceFormat::legacy_2009)
    return size == 2U ? std::optional(result) : std::nullopt;
  if (!result.instance && !result.encoded_topologies.empty()) return std::nullopt;
  bool zero{};
  bool nonzero{};
  for (std::size_t i = 0U; i < result.topology_count(); ++i) {
    if (*result.topology(i) == 0U) zero = true;
    else nonzero = true;
  }
  if ((zero && nonzero) || (result.instance && !result.topology_count())) return std::nullopt;
  return result;
}

bool encode_instance_tlv(TlvWriter &writer, InstanceFormat format,
    std::uint16_t instance, std::span<const std::uint16_t> topologies) noexcept {
  if (format > InstanceFormat::standard_2016 || topologies.size() > 126U ||
      (format == InstanceFormat::legacy_2009 && !topologies.empty()) ||
      (format == InstanceFormat::standard_2016 &&
       ((!instance && !topologies.empty()) || (instance && topologies.empty()))))
    return false;
  bool zero{};
  bool nonzero{};
  for (const auto topology : topologies) {
    if (topology == 0U) zero = true;
    else nonzero = true;
  }
  if (zero && nonzero) return false;
  std::array<std::uint8_t, 254U> bytes{};
  write16(bytes, 0U, instance);
  for (std::size_t i = 0U; i < topologies.size(); ++i) write16(bytes, 2U + i * 2U, topologies[i]);
  return writer.append(7U, std::span(bytes).first(2U + topologies.size() * 2U));
}

std::optional<InstanceSelection> select_instance(const PduView &pdu,
    InstanceFormat format, bool physical_point_to_point, InstanceError &error) noexcept {
  error = InstanceError::none;
  if (format > InstanceFormat::standard_2016) {
    error = InstanceError::invalid_format;
    return std::nullopt;
  }
  const bool hello = pdu.type == PduType::point_to_point_hello ||
                     pdu.type == PduType::lan_hello_l1 || pdu.type == PduType::lan_hello_l2;
  InstanceSelection result;
  std::size_t options{};
  bool nonzero_topology{};
  TlvCursor cursor(pdu.tlvs);
  while (const auto tlv = cursor.next()) {
    if (tlv->code != 7U) continue;
    const auto decoded = decode_instance_tlv(*tlv, format);
    if (!decoded) { error = InstanceError::malformed_tlv; return std::nullopt; }
    ++options;
    if (options > 1U && (format == InstanceFormat::legacy_2009 || !hello)) {
      error = InstanceError::duplicate;
      return std::nullopt;
    }
    if (result.present && result.instance != decoded->instance) {
      error = InstanceError::conflicting_instance;
      return std::nullopt;
    }
    result.present = true;
    result.instance = decoded->instance;
    if (format == InstanceFormat::legacy_2009) continue;
    if (!result.instance && (!physical_point_to_point || pdu.type != PduType::point_to_point_hello)) {
      error = InstanceError::zero_instance_placement;
      return std::nullopt;
    }
    if (!hello && decoded->topology_count() != 1U) {
      error = InstanceError::topology_count;
      return std::nullopt;
    }
    for (std::size_t i = 0U; i < decoded->topology_count(); ++i) {
      if (*decoded->topology(i) == 0U) result.topology_zero = true;
      else nonzero_topology = true;
    }
  }
  if (!cursor.valid()) { error = InstanceError::malformed_tlv; return std::nullopt; }
  if (result.topology_zero && nonzero_topology) {
    error = InstanceError::mixed_zero_topology;
    return std::nullopt;
  }
  return result;
}

} // namespace router::packet::isis
