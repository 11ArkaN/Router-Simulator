// ISO 10589 expiry keeps the original foreign header checksum while discarding
// reachability. RFC 6233 extends generation with POI and authentication options.
// All data and authentication leases remain with the same control caller.
// Source: ietf.isis.purge_options

#include "router/isis_purge_builder.hpp"

#include <algorithm>

namespace router::isis {
LspBuild build_purge_pdu(const PurgeContents &contents, std::span<std::uint8_t> option_scratch,
    std::span<std::uint8_t> pdu_scratch) noexcept {
  if (contents.rules > PurgeRules::registry_6233 ||
      (contents.rules == PurgeRules::authentication_only && contents.instance))
    return {LspBuildStatus::options, {}};
  std::array<std::uint8_t, 9U> options{};
  packet::isis::TlvWriter writer(options);
  if (contents.rules == PurgeRules::registry_6233 &&
      !encode_purge_originator(writer, {contents.generator, std::nullopt}))
    return {LspBuildStatus::options, {}};
  LspContents purge;
  purge.header = {contents.type, contents.original.id, 0U, contents.original.sequence,
      contents.original.flags, contents.maximum_areas};
  purge.options = writer.bytes();
  purge.instance = contents.instance;
  purge.authentication = contents.authentication;
  purge.maximum_pdu_octets = contents.maximum_pdu_octets;
  const auto built = build_lsp_pdu(purge, option_scratch, pdu_scratch);
  if (built.status == LspBuildStatus::encoded &&
      !std::equal(contents.generator.begin(), contents.generator.end(), contents.original.id.begin())) {
    pdu_scratch[packet::isis::lsp_checksum_offset] = static_cast<std::uint8_t>(contents.original.checksum >> 8U);
    pdu_scratch[packet::isis::lsp_checksum_offset + 1U] = static_cast<std::uint8_t>(contents.original.checksum);
  }
  return built;
}
} // namespace router::isis
