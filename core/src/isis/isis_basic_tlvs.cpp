// Stateless bounded basic TLV codecs. Callers own packet memory, advertised
// address sets and all adjacency policy. Dependencies point to wire values.
// Source: iso.10589.2002.basic_tlvs
// Source: ietf.isis.integrated.rfc1195
// Source: ietf.isis.ipv6.rfc5308

#include "router/isis_basic_tlvs.hpp"

namespace router::packet::isis {

std::optional<std::span<const std::uint8_t>> AreaAddressCursor::next() noexcept {
  if (!valid_ || remaining_.empty()) return std::nullopt;
  const auto length = remaining_[0U];
  if (length == 0U || length > maximum_area_octets || length > remaining_.size() - 1U) {
    valid_ = false;
    return std::nullopt;
  }
  const auto result = remaining_.subspan(1U, length);
  remaining_ = remaining_.subspan(1U + length);
  return result;
}

bool encode_area_addresses(TlvWriter &writer,
    std::span<const std::span<const std::uint8_t>> areas) noexcept {
  std::size_t length{};
  for (const auto area : areas) {
    if (area.empty() || area.size() > maximum_area_octets || area.size() + 1U > 255U - length)
      return false;
    length += 1U + area.size();
  }
  std::array<std::uint8_t, 255U> bytes{};
  std::size_t offset{};
  for (const auto area : areas) {
    bytes[offset++] = static_cast<std::uint8_t>(area.size());
    std::copy(area.begin(), area.end(), bytes.begin() + offset);
    offset += area.size();
  }
  return writer.append(1U, std::span(bytes).first(length));
}

bool supports_protocol(TlvView tlv, std::uint8_t nlpid) noexcept {
  return tlv.code == 129U && tlv.value.size() <= 255U &&
         std::find(tlv.value.begin(), tlv.value.end(), nlpid) != tlv.value.end();
}

bool valid_ipv6_interface_addresses(TlvView tlv, PduType pdu) noexcept {
  const bool hello = pdu == PduType::lan_hello_l1 || pdu == PduType::lan_hello_l2 ||
                     pdu == PduType::point_to_point_hello;
  const bool lsp = pdu == PduType::lsp_l1 || pdu == PduType::lsp_l2;
  if (!hello && !lsp) return false;
  FixedAddressCursor<16U> addresses(tlv, 232U);
  while (const auto address = addresses.next())
    if (ip::is_link_local(*address) != hello) return false;
  return addresses.valid();
}

} // namespace router::packet::isis
