// LLC UI codec over ordinary Ethernet Length or extended LLC EtherType.
// All writes are preflighted and only initialized frame bytes are published.
// Sources: ieee.802_1ac.llc_encapsulation and ietf.llc.nlpid.rfc2684

#include "router/llc_packet.hpp"

#include <algorithm>
#include <cstring>

namespace router::packet {

std::optional<LlcUiView> parse_llc_ui(std::span<const std::uint8_t> wire) noexcept {
  const auto ethernet = parse_ethernet(wire);
  if (!ethernet || (ethernet->ether_type > ethernet_maximum_length &&
                    ethernet->ether_type != ethernet_type_llc)) return std::nullopt;
  auto client = wire.subspan(ethernet->payload_offset);
  const bool extended = ethernet->ether_type == ethernet_type_llc;
  if (!extended) {
    if (ethernet->ether_type > client.size()) return std::nullopt;
    client = client.first(ethernet->ether_type);
  }
  if (client.size() < llc_ui_header_octets || client[2U] != 0x03U) return std::nullopt;
  return LlcUiView{*ethernet, client.subspan(llc_ui_header_octets), client[0U], client[1U], extended};
}

bool llc_ui_into(Frame &output, const LlcUiInput &input,
                 std::span<const std::uint8_t> payload) noexcept {
  constexpr auto prefix = ethernet_header_octets + llc_ui_header_octets;
  if (payload.size() > output.bytes.size() - prefix) return false;
  const auto client_length = llc_ui_header_octets + payload.size();
  const auto type = client_length <= ethernet_maximum_length ?
      static_cast<std::uint16_t>(client_length) : ethernet_type_llc;
  // Move borrowed payload before overwriting a potentially aliased header.
  if (!payload.empty()) std::memmove(output.bytes.data() + prefix, payload.data(), payload.size());
  std::copy(input.destination.begin(), input.destination.end(), output.bytes.begin());
  std::copy(input.source.begin(), input.source.end(), output.bytes.begin() + 6U);
  output.bytes[12U] = static_cast<std::uint8_t>(type >> 8U);
  output.bytes[13U] = static_cast<std::uint8_t>(type);
  output.bytes[14U] = input.destination_sap;
  output.bytes[15U] = input.source_sap;
  output.bytes[16U] = 0x03U;
  const auto actual_length = prefix + payload.size();
  const auto padded_length = std::max<std::size_t>(actual_length, ethernet_minimum_without_fcs);
  std::fill(output.bytes.begin() + actual_length, output.bytes.begin() + padded_length, std::uint8_t{});
  output.length = static_cast<std::uint16_t>(padded_length);
  return true;
}

} // namespace router::packet
