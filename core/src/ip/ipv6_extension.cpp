// RFC 8200 option action bits and Routing Header error behavior. All offsets
// are checked against the parser-validated IPv6 payload before they are read.

#include "router/ipv6_extension.hpp"

namespace router::packet {
namespace {

constexpr std::uint8_t pad1_option = 0U;
constexpr std::uint8_t padn_option = 1U;
constexpr std::uint8_t router_alert_option = 5U;
constexpr std::uint8_t router_alert_data_octets = 2U;
constexpr std::size_t ethernet_header = ethernet_header_octets;
constexpr std::size_t first_extension =
    ethernet_header_octets + ipv6_header_octets;

Ipv6ExtensionValidation parameter(std::uint8_t code,
                                  std::size_t frame_offset,
                                  bool allow_multicast = false) noexcept {
  return {.action = Ipv6ExtensionAction::parameter_problem,
          .pointer = static_cast<std::uint32_t>(frame_offset - ethernet_header),
          .code = code,
          .allow_multicast_response = allow_multicast};
}

Ipv6ExtensionValidation validate_options(const Frame &frame,
                                         std::size_t begin,
                                         std::size_t end,
                                         bool multicast_destination) noexcept {
  auto cursor = begin + 2U;
  while (cursor < end) {
    const auto type = frame[cursor];
    if (type == pad1_option) {
      ++cursor;
      continue;
    }
    if (cursor + 2U > end)
      return parameter(icmpv6_parameter_bad_header_code, cursor);
    const auto data_octets = static_cast<std::size_t>(frame[cursor + 1U]);
    if (cursor + 2U + data_octets > end)
      return parameter(icmpv6_parameter_bad_header_code, cursor + 1U);
    if (type == padn_option) {
      cursor += 2U + data_octets;
      continue;
    }
    if (type == router_alert_option) {
      if (data_octets != router_alert_data_octets)
        return parameter(icmpv6_parameter_bad_header_code, cursor + 1U);
      cursor += 2U + data_octets;
      continue;
    }

    // The top two bits are a wire-level action, not an implementation policy.
    // 00 skips, 01 silently discards, 10 always reports, and 11 reports only
    // for a unicast destination.
    switch (type >> 6U) {
    case 0U:
      cursor += 2U + data_octets;
      continue;
    case 1U:
      return {.action = Ipv6ExtensionAction::silent_discard,
              .pointer = 0U,
              .code = 0U,
              .allow_multicast_response = false};
    case 2U:
      return parameter(icmpv6_parameter_unknown_option_code, cursor, true);
    default:
      if (multicast_destination)
        return {.action = Ipv6ExtensionAction::silent_discard,
                .pointer = 0U,
                .code = 0U,
                .allow_multicast_response = false};
      return parameter(icmpv6_parameter_unknown_option_code, cursor);
    }
  }
  return {};
}

} // namespace

Ipv6ExtensionValidation validate_ipv6_extensions(
    const Frame &frame, const Ipv6View &view, bool at_destination,
    bool process_hop_by_hop) noexcept {
  const auto packet_end = first_extension + view.payload_length;
  auto current = view.next_header;
  std::size_t offset = first_extension;
  while (offset < packet_end) {
    if (current == ipv6_next_header_hop_by_hop ||
        current == ipv6_next_header_destination_options) {
      const auto length =
          (static_cast<std::size_t>(frame[offset + 1U]) + 1U) * 8U;
      const bool inspect = current == ipv6_next_header_hop_by_hop
                               ? process_hop_by_hop || at_destination
                               : at_destination;
      if (inspect) {
        const auto result = validate_options(
            frame, offset, offset + length, ip::is_multicast(view.destination));
        if (result.action != Ipv6ExtensionAction::accept)
          return result;
      }
      current = frame[offset];
      offset += length;
      continue;
    }
    if (current == ipv6_next_header_routing) {
      const auto length =
          (static_cast<std::size_t>(frame[offset + 1U]) + 1U) * 8U;
      // No Routing Type is implemented in this stage. RFC 8200 requires an
      // unknown type with Segments Left zero to be ignored, but a nonzero value
      // at its destination produces Code 0 pointing at Routing Type.
      if (at_destination && frame[offset + 3U] != 0U)
        return parameter(icmpv6_parameter_bad_header_code, offset + 2U);
      current = frame[offset];
      offset += length;
      continue;
    }
    if (current == ipv6_next_header_fragment) {
      const auto field = static_cast<std::uint16_t>(
          (frame[offset + 2U] << 8U) | frame[offset + 3U]);
      current = frame[offset];
      offset += ipv6_fragment_header_octets;
      // Non-first fragment data is not an extension chain and must not be
      // interpreted before destination reassembly.
      if (((field >> 3U) & 0x1fffU) != 0U)
        return {};
      continue;
    }
    if (current == ipv6_next_header_authentication) {
      const auto length =
          (static_cast<std::size_t>(frame[offset + 1U]) + 2U) * 4U;
      current = frame[offset];
      offset += length;
      continue;
    }
    break;
  }
  return {};
}

} // namespace router::packet
