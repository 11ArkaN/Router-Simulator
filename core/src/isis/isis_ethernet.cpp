// IS-IS envelope composition never infers protocol state from editor topology.
// The generic LLC parser owns Length/Type interpretation, while the PDU codec
// owns NLPID, version, declared length and option boundaries.
// Sources: ieee.802_1ac.llc_encapsulation and ietf.llc.nlpid.rfc2684

#include "router/isis_ethernet.hpp"

namespace router::packet::isis {

std::optional<EthernetPduView> parse_ethernet_pdu(
    std::span<const std::uint8_t> wire, EthernetDecodeError &error) noexcept {
  error = {};
  const auto llc = parse_llc_ui(wire);
  if (!llc) { error.envelope = EthernetError::llc_envelope; return std::nullopt; }
  if (llc->destination_sap != iso_network_sap || llc->source_sap != iso_network_sap) {
    error.envelope = EthernetError::network_sap;
    return std::nullopt;
  }
  const auto pdu = parse(llc->payload, error.pdu);
  if (!pdu) { error.envelope = EthernetError::pdu; return std::nullopt; }
  return EthernetPduView{llc->ethernet, *pdu};
}

bool ethernet_pdu_into(Frame &output, const Mac &source, const Mac &destination,
    std::span<const std::uint8_t> wire) noexcept {
  DecodeError error{};
  const auto pdu = parse(wire, error);
  return pdu && llc_ui_into(output, {source, destination, iso_network_sap, iso_network_sap}, pdu->bytes);
}

} // namespace router::packet::isis
