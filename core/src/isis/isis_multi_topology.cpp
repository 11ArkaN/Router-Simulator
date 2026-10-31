// MT membership is independent of Instance-Identifier TLV 7. The 12-bit MT
// prefix wraps the shared standard reachability codecs without copying into
// a second parser. Source: ietf.isis.multi_topology.rfc5120.

#include "router/isis_multi_topology.hpp"

#include <algorithm>

namespace router::packet::isis {
namespace {
std::uint16_t topology_id(std::span<const std::uint8_t> value) noexcept {
  return static_cast<std::uint16_t>(((value[0U] & 0x0fU) << 8U) | value[1U]);
}
template <typename Entry, typename Encoder>
bool encode_wrapped(TlvWriter &writer, std::uint16_t topology, std::uint8_t code,
    const Entry &entry, Encoder encode) noexcept {
  if (!topology || topology > maximum_topology_id) return false;
  std::array<std::uint8_t, 257U> standard{};
  TlvWriter staged(standard);
  if (!encode(staged, entry) || staged.bytes().size() > 255U) return false;
  const auto body = staged.bytes().subspan(2U);
  std::array<std::uint8_t, 255U> value{};
  value[0U] = static_cast<std::uint8_t>(topology >> 8U);
  value[1U] = static_cast<std::uint8_t>(topology);
  std::copy(body.begin(), body.end(), value.begin() + 2U);
  return writer.append(code, std::span(value).first(2U + body.size()));
}
}

TopologyCursor::TopologyCursor(TlvView tlv, bool lsp_fragment_zero) noexcept
    : remaining_(tlv.value), flags_allowed_(lsp_fragment_zero),
      valid_(tlv.code == 229U && !tlv.value.empty() && tlv.value.size() <= 254U &&
             tlv.value.size() % 2U == 0U) {}

std::optional<TopologyComponent> TopologyCursor::next() noexcept {
  if (!valid_ || remaining_.empty()) return std::nullopt;
  const auto id = topology_id(remaining_);
  const bool flags = flags_allowed_ && id != 0U;
  const TopologyComponent result{id, flags && (remaining_[0U] & 0x80U) != 0U,
                                      flags && (remaining_[0U] & 0x40U) != 0U};
  remaining_ = remaining_.subspan(2U);
  return result;
}

bool encode_topologies(TlvWriter &writer, std::span<const TopologyComponent> topologies,
    bool lsp_fragment_zero) noexcept {
  if (topologies.empty() || topologies.size() > 127U) return false;
  std::array<std::uint8_t, 254U> value{};
  std::size_t offset{};
  for (const auto &topology : topologies) {
    if (topology.id > maximum_topology_id ||
        ((topology.overloaded || topology.attached) && (!lsp_fragment_zero || !topology.id))) return false;
    value[offset++] = static_cast<std::uint8_t>((topology.id >> 8U) |
        (topology.overloaded ? 0x80U : 0U) | (topology.attached ? 0x40U : 0U));
    value[offset++] = static_cast<std::uint8_t>(topology.id);
  }
  return writer.append(229U, std::span(value).first(offset));
}

std::optional<bool> supports_topology(const PduView &pdu, std::uint16_t topology) noexcept {
  if (topology > maximum_topology_id) return std::nullopt;
  const bool is_hello = pdu.type == PduType::point_to_point_hello ||
      pdu.type == PduType::lan_hello_l1 || pdu.type == PduType::lan_hello_l2;
  if (!is_hello) {
    const auto header = lsp(pdu);
    if (!header || header->id[6U] || header->id.back() != 0U) return std::nullopt;
  }
  bool advertised{};
  bool found{};
  TlvCursor options(pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code != 229U) continue;
    advertised = true;
    TopologyCursor components(*option);
    while (const auto component = components.next()) found = found || component->id == topology;
    if (!components.valid()) return std::nullopt;
  }
  return options.valid() ? std::optional(found || (!advertised && topology == 0U)) : std::nullopt;
}

std::optional<MtReachabilityView> mt_reachability(TlvView tlv) noexcept {
  const auto standard = tlv.code == 222U ? 22U : tlv.code == 235U ? 135U : tlv.code == 237U ? 236U : 0U;
  if (!standard || tlv.value.size() < 2U || tlv.value.size() > 255U) return std::nullopt;
  return MtReachabilityView{topology_id(tlv.value),
      {static_cast<std::uint8_t>(standard), tlv.value.subspan(2U)}};
}

bool encode_mt_neighbor(TlvWriter &writer, std::uint16_t topology, const ExtendedNeighbor &entry) noexcept {
  return encode_wrapped(writer, topology, 222U, entry, encode_extended_neighbor);
}

bool encode_mt_prefix(TlvWriter &writer, std::uint16_t topology, const ExtendedPrefix &entry) noexcept {
  return encode_wrapped(writer, topology,
      entry.prefix.network.family == ip::AddressFamily::ipv4 ? 235U : 237U, entry, encode_extended_prefix);
}

} // namespace router::packet::isis
