// ISO 10589 9.8/9.9 header and checksum, RFC 8202 instance placement and RFC
// 5304/5310 digest composition share the existing codecs. The raw LSP budget
// is independent of a circuit dataLinkBlockSize under ISO 10589 7.3.15.

#include "router/isis_lsp_builder.hpp"

#include <algorithm>

namespace router::isis {
LspBuild build_lsp_pdu(const LspContents &contents, std::span<std::uint8_t> option_scratch,
    std::span<std::uint8_t> pdu_scratch) noexcept {
  using namespace packet::isis;
  using Status = LspBuildStatus;
  const auto maximum = contents.maximum_pdu_octets;
  if (maximum < lsp_header_octets || maximum > 65535U || pdu_scratch.size() < maximum)
    return {Status::capacity, {}};
  if (contents.header.type != PduType::lsp_l1 && contents.header.type != PduType::lsp_l2)
    return {Status::invalid_header, {}};
  TlvCursor validation(contents.options);
  while (const auto option = validation.next())
    if (option->code == 7U || option->code == 10U ||
        (option->code == 13U && contents.header.remaining_seconds)) return {Status::options, {}};
  if (!validation.valid()) return {Status::options, {}};
  TlvWriter writer(option_scratch.first(std::min(option_scratch.size(), maximum - lsp_header_octets)));
  if (contents.instance && !encode_instance_tlv(writer, contents.instance->format,
      contents.instance->instance, contents.instance->topologies)) return {Status::instance, {}};
  TlvCursor options(contents.options);
  while (const auto option = options.next())
    if (!writer.append(option->code, option->value)) return {Status::capacity, {}};
  if (contents.authentication && !append_authentication(writer, *contents.authentication))
    return {Status::authentication, {}};
  const auto encoded = encode_lsp(pdu_scratch.first(maximum), contents.header, writer.bytes());
  if (!encoded) return {Status::invalid_header, {}};
  if (contents.instance) {
    DecodeError decode{};
    InstanceError instance{};
    const auto pdu = parse(*encoded, decode);
    if (!pdu || !select_instance(*pdu, contents.instance->format, false, instance))
      return {Status::instance, {}};
  }
  if (contents.authentication) {
    SystemId originator{};
    std::copy_n(contents.header.id.begin(), originator.size(), originator.begin());
    if (finalize_authentication(pdu_scratch.first(encoded->size()), *contents.authentication,
        originator) != AuthenticationError::none) return {Status::authentication, {}};
  }
  return {Status::encoded, *encoded};
}
} // namespace router::isis
