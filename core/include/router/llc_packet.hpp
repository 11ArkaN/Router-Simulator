// Ethernet LLC UI framing, independent of the carried network protocol.
// Views borrow caller bytes; writers mutate only caller-owned fixed frames.
// No adjacency, routing, queue or runtime state belongs to this codec.

#pragma once

#include "router/packet.hpp"

namespace router::packet {

inline constexpr std::uint16_t ethernet_maximum_length = 1500U;
inline constexpr std::uint16_t ethernet_type_llc = 0x8870U;
inline constexpr std::size_t llc_ui_header_octets = 3U;

struct LlcUiView {
  EthernetView ethernet;
  std::span<const std::uint8_t> payload;
  std::uint8_t destination_sap{};
  std::uint8_t source_sap{};
  bool extended_length{};
};

struct LlcUiInput {
  Mac source{};
  Mac destination{};
  std::uint8_t destination_sap{};
  std::uint8_t source_sap{};
};

// Accepts Length <= 1500 or the IEEE 802.1AC LLC encapsulation EtherType.
// Only UI control 0x03 is supported. Ordinary Length includes LLC and excludes
// Ethernet padding; the returned payload is trimmed accordingly. Extended
// LLC has no length field and leaves any padding to the carried PDU decoder.
// Rejects truncated tags, headers and declared payloads, undefined Length/Type
// values and other EtherTypes. No allocation; usable on any owning shard.
[[nodiscard]] std::optional<LlcUiView>
parse_llc_ui(std::span<const std::uint8_t> wire) noexcept;

// Emits an untagged frame without FCS, padded to the Ethernet minimum. Selects
// ordinary Length when LLC+payload fits, otherwise 0x8870. Existing VLAN helpers
// may tag the complete frame afterward. Payload may alias the output buffer.
// Capacity failure preserves every output byte and its length. The caller
// retains output ownership and enforces the selected physical interface MTU.
[[nodiscard]] bool llc_ui_into(Frame &output, const LlcUiInput &input,
                               std::span<const std::uint8_t> payload) noexcept;

} // namespace router::packet
