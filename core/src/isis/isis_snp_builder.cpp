// ISO 10589 clauses 9.10 through 9.13 SNP lists retain their total wire order
// across TLV boundaries. Only a fully encoded and authenticated PDU reaches the
// caller's frame. Sources: iso.10589.2002.snp_composition,
// ietf.isis.multi_instance.rfc8202, ietf.isis.authentication.rfc5304.

#include "router/isis_snp_builder.hpp"

#include <algorithm>

namespace router::isis {

SnpBuildResult build_snp_frame(packet::Frame &output, const SnpContents &contents,
    PduScratch &scratch) noexcept {
  using namespace packet::isis;
  using Result = SnpBuildResult;
  const auto type = contents.header.type;
  const bool complete = type == PduType::csnp_l1 || type == PduType::csnp_l2;
  if (!complete && type != PduType::psnp_l1 && type != PduType::psnp_l2) return Result::invalid_header;
  if (complete && contents.header.last < contents.header.first) return Result::invalid_header;
  const auto fixed = complete ? csnp_header_octets : psnp_header_octets;
  if (contents.maximum_pdu_octets < fixed || contents.maximum_pdu_octets >
      packet::maximum_frame_octets - packet::ethernet_header_octets - packet::llc_ui_header_octets)
    return Result::capacity;
  for (std::size_t index = 0U; index < contents.entries.size(); ++index) {
    const auto &id = contents.entries[index].id;
    if ((index && id <= contents.entries[index - 1U].id) ||
        (complete && (id < contents.header.first || id > contents.header.last))) return Result::entries;
  }
  TlvWriter writer(std::span(scratch.options).first(contents.maximum_pdu_octets - fixed));
  if (contents.instance && !encode_instance_tlv(writer, contents.instance->format,
      contents.instance->instance, contents.instance->topologies)) return Result::instance;
  auto remaining = contents.entries;
  std::array<std::uint8_t, (255U / snp_entry_octets) * snp_entry_octets> batch{};
  while (!remaining.empty()) {
    const auto count = std::min<std::size_t>(batch.size() / snp_entry_octets, remaining.size());
    for (std::size_t index = 0U; index < count; ++index)
      if (!encode_snp_entry(std::span(batch).subspan(index * snp_entry_octets, snp_entry_octets), remaining[index]))
        return Result::entries;
    if (!writer.append(9U, std::span(batch).first(count * snp_entry_octets))) return Result::capacity;
    remaining = remaining.subspan(count);
  }
  if (contents.authentication && !append_authentication(writer, *contents.authentication)) return Result::authentication;
  const auto encoded = encode_snp(scratch.pdu, contents.header, writer.bytes());
  if (!encoded) return Result::invalid_header;
  if (contents.instance) {
    DecodeError decode{};
    InstanceError instance{};
    const auto pdu = parse(*encoded, decode);
    if (!pdu || !select_instance(*pdu, contents.instance->format, false, instance)) return Result::instance;
  }
  if (contents.authentication && finalize_authentication(
      std::span(scratch.pdu).first(encoded->size()), *contents.authentication,
      contents.header.source) != AuthenticationError::none) return Result::authentication;
  return ethernet_pdu_into(output, contents.source, contents.destination, *encoded) ? Result::encoded : Result::capacity;
}

} // namespace router::isis
