// Encoded SNP batches validate completely before level-owned flags change.
// Fixtures cover repeated options, CSNP omissions, DIS-only LAN PSNP admission
// and bounded missing-entry requests without direct peer-state injection.

#include "router/isis_level_database.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS complete SNP receive invariant failed");
}
}

void isis_snp_receive_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const std::array circuits{FloodCircuit{false, true, false, false},
      FloodCircuit{true, true, false, false}};
  LevelDatabase database(PduType::lsp_l1, {3U, 1024U}, circuits);
  const auto now = RuntimeClock::time_point{100s};
  std::array<std::uint8_t, 512U> wire{};
  std::array<SnpEntry, 2U> reports{};
  for (std::uint8_t index{}; index < reports.size(); ++index) {
    LspInput input{PduType::lsp_l1, {static_cast<std::uint8_t>(index + 1U), 0U, 0U, 0U, 0U, 1U, 0U, 0U},
        1200U, 10U, 3U};
    const auto encoded = encode_lsp(wire, input, {});
    require(encoded && database.receive(*encoded, 0U, now, 1200U, 60s).install == LspInstallResult::installed);
    const auto header = database.database().find(input.id, now)->header;
    require(database.complete(header, 0U, true, true, now) &&
        database.complete(header, 1U, false, true, now));
    reports[index] = {1200U, input.id, header.sequence, header.checksum};
  }
  const auto make = [&](PduType type, std::span<const SnpEntry> entries, bool malformed_tail = false) {
    std::array<std::uint8_t, 256U> options{};
    TlvWriter writer(options);
    const std::array<std::uint8_t, 3U> unknown{1U, 2U, 3U};
    require(writer.append(253U, unknown));
    for (const auto &entry : entries) {
      std::array<std::uint8_t, snp_entry_octets> bytes{};
      require(encode_snp_entry(bytes, entry) && writer.append(9U, bytes));
    }
    if (malformed_tail) {
      const std::array<std::uint8_t, snp_entry_octets - 1U> partial{};
      require(writer.append(9U, partial));
    }
    SnpInput input;
    input.type = type;
    input.source = {9U, 8U, 7U, 6U, 5U, 4U};
    input.last.fill(0xffU);
    const auto encoded = encode_snp(wire, input, writer.bytes());
    DecodeError error{};
    const auto decoded = encoded ? parse(*encoded, error) : std::nullopt;
    require(decoded.has_value());
    return *decoded;
  };
  auto pdu = make(PduType::csnp_l1, std::span(reports).first(1U));
  auto result = database.receive_snp(pdu, 1U, false, now);
  require(result.status == SnpBatchStatus::accepted && !result.waiting_state && !result.confusions &&
      !database.flags(reports[0U].id, 1U)->srm && database.flags(reports[1U].id, 1U)->srm);
  auto newer = reports[0U];
  ++newer.sequence;
  pdu = make(PduType::psnp_l1, std::span(&newer, 1U), true);
  require(database.receive_snp(pdu, 0U, false, now).status == SnpBatchStatus::malformed &&
      !database.flags(newer.id, 0U)->ssn);
  const std::array reversed{reports[1U], newer};
  pdu = make(PduType::psnp_l1, reversed);
  require(database.receive_snp(pdu, 0U, false, now).status == SnpBatchStatus::malformed &&
      !database.flags(newer.id, 0U)->ssn);
  const std::array duplicate{newer, newer};
  pdu = make(PduType::psnp_l1, duplicate);
  require(database.receive_snp(pdu, 0U, false, now).status == SnpBatchStatus::malformed);
  pdu = make(PduType::psnp_l1, std::span(&newer, 1U));
  require(database.receive_snp(pdu, 1U, false, now).status == SnpBatchStatus::discarded &&
      !database.flags(newer.id, 1U)->ssn);
  require(database.receive_snp(pdu, 1U, true, now).status == SnpBatchStatus::accepted &&
      database.flags(newer.id, 1U)->ssn);
  pdu = make(PduType::psnp_l2, std::span(&newer, 1U));
  require(database.receive_snp(pdu, 0U, false, now).status == SnpBatchStatus::discarded);
  std::array additions{newer, newer, newer};
  additions[1U].id[0U] = 3U;
  additions[2U].id[0U] = 4U;
  pdu = make(PduType::csnp_l1, additions);
  result = database.receive_snp(pdu, 0U, false, now);
  require(result.status == SnpBatchStatus::accepted && result.waiting_state &&
      database.flags(newer.id, 0U)->ssn && database.flags(additions[1U].id, 0U)->ssn &&
      !database.flags(additions[2U].id, 0U) && !database.flags(additions[1U].id, 0U)->srm &&
      database.flags(reports[1U].id, 0U)->srm);
  auto confused = reports[0U];
  confused.checksum ^= 1U;
  pdu = make(PduType::psnp_l1, std::span(&confused, 1U));
  result = database.receive_snp(pdu, 0U, false, now);
  require(result.status == SnpBatchStatus::accepted && result.confusions == 1U &&
      database.database().find(confused.id, now)->header.checksum == reports[0U].checksum);
  const auto second = database.database().find(reports[1U].id, now)->header;
  require(database.complete(second, 1U, false, true, now) && !database.flags(second.id, 1U)->srm);
  SnpInput limited;
  limited.type = PduType::csnp_l1;
  limited.first = limited.last = reports[0U].id;
  const auto encoded = encode_snp(wire, limited, {});
  DecodeError error{};
  const auto decoded = encoded ? parse(*encoded, error) : std::nullopt;
  require(decoded && database.receive_snp(*decoded, 1U, false, now).status == SnpBatchStatus::accepted &&
      database.flags(reports[0U].id, 1U)->srm && !database.flags(reports[1U].id, 1U)->srm);
}
