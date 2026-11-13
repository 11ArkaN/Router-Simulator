// Local LSP construction is authenticated before LSDB publication. Raw LSP
// storage can exceed physical frame capacity without enlarging packet rings;
// circuit emission must still refuse that oversized advertisement.

#include "router/isis_lsp_builder.hpp"
#include "router/isis_lsp_exchange.hpp"

#include <array>
#include <memory>
#include <stdexcept>
#include <source_location>
#include <string>
#include <vector>

void isis_lsp_builder_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS local LSP composition invariant failed at " + std::to_string(location.line()));
  };
  std::vector<std::uint8_t> options(9778U), output(9778U);
  const std::array<std::uint8_t, 5U> attributes{137U, 3U, 'r', '-', '1'};
  const std::array<std::uint16_t, 1U> topology{0U};
  const std::array<std::uint8_t, 6U> secret{1U, 2U, 3U, 4U, 5U, 6U};
  LspContents contents;
  contents.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  contents.options = attributes;
  contents.maximum_pdu_octets = 1492U;
  contents.instance = PduInstanceOption{InstanceFormat::standard, 7U, topology};
  for (const auto type : {PduType::lsp_l1, PduType::lsp_l2})
    for (const auto method : {AuthenticationMethod::password, AuthenticationMethod::hmac_md5,
        AuthenticationMethod::hmac_sha1, AuthenticationMethod::hmac_sha256})
      for (const auto lifetime : {std::uint16_t{1200U}, std::uint16_t{0U}}) {
        contents.header.type = type;
        contents.header.remaining_seconds = lifetime;
        contents.authentication = AuthenticationKey{method, 9U, secret};
        const auto result = build_lsp_pdu(contents, options, output);
        require(result.status == LspBuildStatus::encoded);
        DecodeError error{};
        const auto pdu = parse(result.bytes, error);
        require(pdu && valid_lsp_checksum(*pdu) && lsp(*pdu)->remaining_seconds == lifetime &&
            verify_authentication(result.bytes, *contents.authentication) == AuthenticationError::none);
        InstanceError selection_error{};
        const auto selection = select_instance(*pdu, InstanceFormat::standard, false, selection_error);
        require(selection && selection->instance == 7U && selection->topology_zero);
        TlvCursor cursor(pdu->tlvs);
        require(cursor.next()->code == 7U && cursor.next()->code == 137U && cursor.next()->code == 10U &&
            !cursor.next() && cursor.valid());
      }
  contents.authentication.reset();
  contents.instance.reset();
  const std::array<std::uint8_t, 3U> malformed{137U, 2U, 'r'};
  contents.options = malformed;
  require(build_lsp_pdu(contents, options, output).status == LspBuildStatus::options);
  for (const auto code : {std::uint8_t{7U}, std::uint8_t{10U}}) {
    const std::array reserved{code, std::uint8_t{0U}};
    contents.options = reserved;
    require(build_lsp_pdu(contents, options, output).status == LspBuildStatus::options);
  }
  contents.options = attributes;
  contents.header.sequence = 0U;
  require(build_lsp_pdu(contents, options, output).status == LspBuildStatus::invalid_header);
  contents.header.sequence = 1U;
  contents.maximum_pdu_octets = 65536U;
  require(build_lsp_pdu(contents, options, output).status == LspBuildStatus::capacity);
  contents.maximum_pdu_octets = 9778U;
  std::vector<std::uint8_t> large_options(9400U);
  TlvWriter padding(large_options);
  require(padding.pad_to(9400U));
  contents.options = padding.bytes();
  contents.header.remaining_seconds = 1200U;
  const auto large = build_lsp_pdu(contents, options, output);
  require(large.status == LspBuildStatus::encoded && large.bytes.size() > packet::maximum_frame_octets);
  const std::array circuits{FloodCircuit{false, true, false, false},
      FloodCircuit{true, true, false, false}};
  LevelDatabase database(PduType::lsp_l2, {1U, 9778U}, circuits);
  const auto now = RuntimeClock::time_point{100s};
  require(database.originate(large.bytes, now, 1200U, 60s) == LspInstallResult::installed);
  require(database.receive(large.bytes, 0U, now, 1200U, 60s).install == LspInstallResult::identical);
  require(database.circuit(0U, false, true, true) && database.flags(contents.header.id, 0U)->ssn);
  LspExchange exchange(database, 0U, 1U);
  auto scratch = std::make_unique<PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  require(exchange.prepare(contents.header.id, {2U, 0U, 0U, 0U, 0U, 1U},
      {1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}, 9778U, 1U, *frame, *scratch, now).status ==
      LspEmissionStatus::capacity);
  require(database.flags(contents.header.id, 0U)->srm);
  require(exchange.prepare(contents.header.id, {2U, 0U, 0U, 0U, 0U, 1U},
      {1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}, 1492U, 1U, *frame, *scratch, now).status ==
      LspEmissionStatus::too_large);
  require(!database.flags(contents.header.id, 0U)->srm && database.flags(contents.header.id, 0U)->ssn &&
      database.flags(contents.header.id, 1U)->srm && database.database().size() == 1U);
  require(exchange.prepare(contents.header.id, {2U, 0U, 0U, 0U, 0U, 1U},
      {1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}, 1492U, 1U, *frame, *scratch, now).status ==
      LspEmissionStatus::not_requested);
}
