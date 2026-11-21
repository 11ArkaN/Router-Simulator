// IS-IS Ethernet/LLC envelope adapter. Caller-owned wire bytes remain the only
// boundary; this module owns no port, instance, authentication or neighbor state.
// Dependencies point to the generic LLC codec and bounded IS-IS PDU codec.

#pragma once

#include "router/isis_packet.hpp"
#include "router/llc_packet.hpp"

namespace router::packet::isis {

inline constexpr std::uint8_t iso_network_sap = 0xfeU;

enum class EthernetError : std::uint8_t { none, llc_envelope, network_sap, pdu };
struct EthernetDecodeError {
  EthernetError envelope{EthernetError::none};
  DecodeError pdu{DecodeError::none};
};
struct EthernetPduView {
  EthernetView ethernet;
  PduView pdu;
};

// Requires immutable captured frame bytes without FCS. Validates Length/LLC,
// both ISO SAPs and the complete PDU envelope; trims link padding using the
// PDU's own length. MAC/instance/media acceptance, authentication and checksum
// policy belong to the receiving process. Failure populates the error value;
// returned views borrow wire until the caller returns its channel handle.
[[nodiscard]] std::optional<EthernetPduView> parse_ethernet_pdu(
    std::span<const std::uint8_t> wire, EthernetDecodeError &error) noexcept;

// Validates the PDU envelope before writing an untagged LLC UI frame. Target
// MAC selection is explicit caller policy. Capacity or malformed PDU failure
// preserves output; source PDU bytes may alias output. Padding beyond the PDU
// is discarded and Ethernet minimum padding is regenerated with zero bytes.
// Caller owns output on its shard and checks the physical port MTU afterward.
[[nodiscard]] bool ethernet_pdu_into(Frame &output, const Mac &source,
    const Mac &destination, std::span<const std::uint8_t> pdu) noexcept;

} // namespace router::packet::isis
