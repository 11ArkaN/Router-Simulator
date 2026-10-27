// Hello composition shares bounded TLV and Ethernet encoders. Only the final
// complete frame is copied into caller output, preserving failure atomicity.
// Sources: iso.10589.2002.basic_tlvs, ietf.isis.integrated.rfc1195,
// ietf.isis.ipv6.rfc5308, ietf.isis.three_way.rfc5303,
// ietf.isis.multi_instance.rfc8202 and ietf.isis.authentication.rfc5304

#include "router/isis_hello_builder.hpp"

#include <algorithm>

namespace router::isis {
namespace {
template <std::size_t Width>
bool append_addresses(packet::isis::TlvWriter &writer, std::uint8_t code,
    std::span<const std::array<std::uint8_t, Width>> addresses) noexcept {
  while (!addresses.empty()) {
    const auto count = std::min<std::size_t>(255U / Width, addresses.size());
    if (!packet::isis::encode_fixed_addresses<Width>(writer, code, addresses.first(count))) return false;
    addresses = addresses.subspan(count);
  }
  return true;
}
}

HelloBuildResult build_hello_frame(packet::Frame &output, const HelloContents &contents,
    HelloScratch &scratch) noexcept {
  using namespace packet::isis;
  using Result = HelloBuildResult;
  const auto type = contents.header.type;
  const bool p2p = type == PduType::point_to_point_hello;
  if (!p2p && type != PduType::lan_hello_l1 && type != PduType::lan_hello_l2) return Result::invalid_header;
  const auto fixed = p2p ? point_to_point_hello_header_octets : lan_hello_header_octets;
  if (contents.maximum_pdu_octets < fixed || contents.maximum_pdu_octets >
      packet::maximum_frame_octets - packet::ethernet_header_octets - packet::llc_ui_header_octets)
    return Result::capacity;
  if (p2p != contents.three_way.has_value() || (p2p && !contents.neighbors.empty())) return Result::three_way;
  TlvWriter writer(std::span(scratch.options).first(contents.maximum_pdu_octets - fixed));
  if (contents.instance && !encode_instance_tlv(writer, contents.instance->format,
      contents.instance->instance, contents.instance->topologies)) return Result::instance;
  if (!contents.areas.empty() && !encode_area_addresses(writer, contents.areas)) return Result::areas;
  if (!contents.protocols.empty() && !writer.append(129U, contents.protocols)) return Result::capacity;
  for (const auto &address : contents.ipv6_addresses)
    if (!ip::is_link_local(address)) return Result::addresses;
  if (!append_addresses<4U>(writer, 132U, contents.ipv4_addresses) ||
      !append_addresses<16U>(writer, 232U, contents.ipv6_addresses) ||
      !append_addresses<6U>(writer, 6U, contents.neighbors)) return Result::capacity;
  if (contents.three_way && !encode_three_way(writer, *contents.three_way)) return Result::three_way;
  if (contents.authentication && !append_authentication(writer, *contents.authentication)) return Result::authentication;
  const auto target = contents.maximum_pdu_octets - fixed;
  // ISO padding reaches at least maximum size minus one. A remaining single
  // octet cannot hold a TLV header and must not force an oversized Hello.
  if (contents.padding && writer.bytes().size() + 1U < target && !writer.pad_to(target)) return Result::capacity;
  const auto encoded = encode_hello(scratch.pdu, contents.header, writer.bytes());
  if (!encoded) return Result::invalid_header;
  if (contents.instance) {
    DecodeError decode{};
    InstanceError instance{};
    const auto pdu = parse(*encoded, decode);
    if (!pdu || !select_instance(*pdu, contents.instance->format,
        contents.physical_point_to_point, instance)) return Result::instance;
  }
  if (contents.authentication && finalize_authentication(
      std::span(scratch.pdu).first(encoded->size()), *contents.authentication,
      contents.header.source) != AuthenticationError::none) return Result::authentication;
  return ethernet_pdu_into(output, contents.source, contents.destination, *encoded) ? Result::encoded : Result::capacity;
}

} // namespace router::isis
