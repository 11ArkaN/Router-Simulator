// CSNP ranges cover the complete identifier space across packet-sized batches.
// Encoded frames prove inclusive boundaries, retry after refusal, empty LSDB
// handling and progress when another periodic request arrives mid-sequence.

#include "router/isis_csnp_sequence.hpp"
#include "router/isis_snp_builder.hpp"

#include <array>
#include <memory>
#include <stdexcept>

void isis_csnp_sequence_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS complete SNP sequence invariant failed");
  };
  const std::array circuits{FloodCircuit{true, true, false, false}};
  LevelDatabase database(PduType::lsp_l1, {3U, 1024U}, circuits);
  const auto now = RuntimeClock::time_point{100s};
  LspId maximum;
  maximum.fill(0xffU);
  const std::array ids{LspId{1U, 0U, 0U, 0U, 0U, 1U, 0U, 0U},
      LspId{3U, 0U, 0U, 0U, 0U, 1U, 0U, 0U}, maximum};
  std::array<std::uint8_t, 128U> bytes{};
  for (const auto &id : ids) {
    const auto encoded = encode_lsp(bytes, {PduType::lsp_l1, id, 1200U, 1U, 3U}, {});
    require(encoded && database.originate(*encoded, now, 1200U, 60s) == LspInstallResult::installed);
  }
  CompleteSnpSequence sequence;
  std::array<SnpEntry, 1U> entries{};
  require(sequence.prepare(database, entries, now).status == CompleteSnpStatus::idle);
  sequence.request();
  require(sequence.prepare(database, {}, now).status == CompleteSnpStatus::capacity &&
      sequence.active() && !sequence.pending());
  auto batch = sequence.prepare(database, entries, now);
  require(batch.status == CompleteSnpStatus::prepared && batch.first == LspId{} && batch.count == 1U &&
      entries[0U].id == ids[0U] && batch.last == LspId{3U, 0U, 0U, 0U, 0U, 0U, 0xffU, 0xffU});
  require(sequence.prepare(database, entries, now).status == CompleteSnpStatus::pending);
  auto scratch = std::make_unique<PduScratch>();
  SnpContents contents;
  contents.header.type = PduType::csnp_l1;
  contents.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  contents.maximum_pdu_octets = 51U;
  packet::Frame frame;
  const auto encode = [&](const CompleteSnpBatch &part) {
    contents.header.first = part.first;
    contents.header.last = part.last;
    contents.entries = std::span(entries).first(part.count);
    require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::encoded);
    EthernetDecodeError error{};
    const auto decoded = parse_ethernet_pdu(frame.view(), error);
    const auto header = decoded ? snp(decoded->pdu) : std::nullopt;
    require(header && header->first == part.first && header->last == part.last);
  };
  encode(batch);
  const auto changed = encode_lsp(bytes, {PduType::lsp_l1, ids[0U], 1200U, 2U, 3U}, {});
  require(changed && database.originate(*changed, now, 1200U, 60s) == LspInstallResult::installed &&
      entries[0U].sequence == 1U && sequence.complete(false));
  batch = sequence.prepare(database, entries, now);
  require(batch.first == LspId{} && entries[0U].sequence == 2U);
  encode(batch);
  sequence.request();
  require(sequence.complete(true) && !sequence.complete(true));
  batch = sequence.prepare(database, entries, now);
  LspId before_maximum = maximum;
  before_maximum.back() = 0xfeU;
  require(batch.first == ids[1U] && batch.last == before_maximum && entries[0U].id == ids[1U]);
  encode(batch);
  require(sequence.complete(true));
  batch = sequence.prepare(database, entries, now);
  require(batch.first == maximum && batch.last == maximum && entries[0U].id == maximum);
  encode(batch);
  require(sequence.complete(true) && sequence.active());
  batch = sequence.prepare(database, entries, now);
  require(batch.first == LspId{} && entries[0U].id == ids[0U]);
  sequence.reset();
  require(!sequence.active() && !sequence.pending() && !sequence.complete(true));
  LevelDatabase empty(PduType::lsp_l1, {0U, 0U}, circuits);
  sequence.request();
  batch = sequence.prepare(empty, {}, now);
  require(batch.status == CompleteSnpStatus::prepared && !batch.count &&
      batch.first == LspId{} && batch.last == maximum);
  contents.maximum_pdu_octets = csnp_header_octets;
  encode(batch);
  require(sequence.complete(true) && !sequence.active());
}
