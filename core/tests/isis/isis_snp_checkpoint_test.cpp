// Coordinated SNP snapshots preserve range progress, cyclic requests and
// unknown-purge tickets. Encoded output before/after restore is compared while
// superseded ordinary LSP versions remain valid pending receipt projections.

#include "router/isis_snp_exchange.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
using namespace router;
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS SNP checkpoint invariant failed at " + std::to_string(at.line()));
}
LevelDatabase database() {
  const std::array circuits{FloodCircuit{false, true}, FloodCircuit{true, true}};
  return LevelDatabase(PduType::lsp_l1, {4U, 1024U, 128U}, circuits);
}
LspId id(std::uint8_t fragment) { return {1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}; }
void install(LevelDatabase &target, std::uint8_t fragment, std::uint32_t sequence,
    RuntimeClock::time_point now, bool received = false) {
  std::array<std::uint8_t, 128U> bytes{};
  const auto encoded = encode_lsp(bytes, {PduType::lsp_l1, id(fragment), 1200U, sequence, 3U}, {});
  require(encoded.has_value());
  require((received ? target.receive(*encoded, 0U, now, 1200U, 60s).install :
      target.originate(*encoded, now, 1200U, 60s)) == LspInstallResult::installed);
}
SnpContents contents(bool complete) {
  SnpContents result;
  result.header.type = complete ? PduType::csnp_l1 : PduType::psnp_l1;
  result.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  result.header.maximum_area_addresses = 3U;
  result.source = {2U, 0U, 0U, 0U, 0U, 1U};
  result.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  result.maximum_pdu_octets = (complete ? csnp_header_octets : psnp_header_octets) + 2U + snp_entry_octets;
  return result;
}
}
void isis_snp_checkpoint_tests() {
  const auto now = RuntimeClock::time_point{100s}, resumed_at = RuntimeClock::time_point{1000s};
  auto frame = std::make_unique<packet::Frame>(), replay = std::make_unique<packet::Frame>();
  auto scratch = std::make_unique<PduScratch>();
  {
    auto original_db = database(), resumed_db = database();
    install(original_db, 0U, 1U, now);
    install(original_db, 1U, 1U, now);
    require(original_db.receive_snp_entry({1200U, id(2U), 1U, 7U}, 0U, now).request_missing);
    TransientAcknowledgements original_acks(8U), resumed_acks(8U);
    SnpExchange original(original_db, original_acks, 1U, 7U, 8U);
    original.request_complete();
    const auto sent = original.prepare(SnpEmission::complete, contents(true), true, *frame, *scratch, now);
    require(sent.status == SnpExchangeStatus::encoded);
    original.request_complete();
    const auto saved = original.checkpoint();
    require(resumed_db.restore(original_db.checkpoint(now), resumed_at, 1200U));
    SnpExchange resumed(resumed_db, resumed_acks, 1U, 7U, 8U);
    require(resumed.restore(saved) && resumed.pending());
    const auto refused = [&](auto invalid) {
      require(!resumed.restore(invalid) && resumed.checkpoint().transmission.pending == saved.transmission.pending &&
          resumed.checkpoint().transmission.next_ticket == saved.transmission.next_ticket &&
          resumed.checkpoint().complete.pending_last == saved.complete.pending_last && resumed_db.flags(id(0U), 1U)->srm);
    };
    auto invalid = saved;
    invalid.version = 2U; refused(invalid);
    invalid = saved; invalid.database_type = PduType::lsp_l2; refused(invalid);
    invalid = saved; invalid.circuit = 0U; refused(invalid);
    invalid = saved; invalid.entry_capacity = 7U; refused(invalid);
    invalid = saved; invalid.transmission.epoch = 6U; refused(invalid);
    invalid = saved; invalid.transmission.next_ticket = 0U; refused(invalid);
    invalid = saved; invalid.pending_emission.reset(); refused(invalid);
    invalid = saved; invalid.complete.pending = false; refused(invalid);
    invalid = saved; invalid.pending_cursor = id(0U); refused(invalid);
    invalid = saved; invalid.entries.push_back(invalid.entries[0U]); refused(invalid);
    invalid = saved; invalid.entries[0U].id.fill(0xffU); refused(invalid);
    invalid = saved; invalid.entries[0U].sequence = 0U; refused(invalid);
    invalid = saved; invalid.entries.clear(); refused(invalid);
    require(original.complete(7U, sent.ticket, false, now).accepted &&
        resumed.complete(7U, sent.ticket, false, resumed_at).accepted);
    unsigned batches{};
    for (;;) {
      const auto left = original.prepare(SnpEmission::complete, contents(true), true, *frame, *scratch, now);
      const auto right = resumed.prepare(SnpEmission::complete, contents(true), true, *replay, *scratch, resumed_at);
      require(left.status == right.status);
      if (left.status == SnpExchangeStatus::idle) break;
      require(left.status == SnpExchangeStatus::encoded && left.ticket == right.ticket &&
          std::equal(frame->view().begin(), frame->view().end(), replay->view().begin(), replay->view().end()));
      require(original.complete(7U, left.ticket, true, now).accepted && resumed.complete(7U, right.ticket, true, resumed_at).accepted);
      require(++batches <= 6U);
    }
    require(batches == 6U && !resumed.pending());
  }
  {
    auto original_db = database(), resumed_db = database();
    install(original_db, 0U, 1U, now, true);
    require(original_db.receive_snp_entry({1200U, id(2U), 1U, 7U}, 0U, now).request_missing);
    TransientAcknowledgements original_acks(8U), resumed_acks(8U);
    SnpExchange original(original_db, original_acks, 0U, 9U, 8U);
    const auto sent = original.prepare(SnpEmission::partial, contents(false), false, *frame, *scratch, now);
    require(sent.status == SnpExchangeStatus::encoded);
    const auto saved = original.checkpoint();
    install(original_db, 0U, 2U, now);
    require(!original_db.receive_snp_entry({1200U, id(0U), 3U, 7U}, 0U, now).waiting_state);
    require(resumed_db.restore(original_db.checkpoint(now), resumed_at, 1200U));
    SnpExchange resumed(resumed_db, resumed_acks, 0U, 9U, 8U);
    require(resumed.restore(saved));
    auto invalid = saved;
    invalid.pending_cursor = id(99U);
    require(!resumed.restore(invalid) && resumed.pending());
    invalid = saved; invalid.entries.clear();
    require(!resumed.restore(invalid) && resumed.pending());
    const auto completed = resumed.complete(9U, sent.ticket, true, resumed_at);
    require(completed.accepted && completed.superseded == 1U && !completed.retired && resumed_db.flags(id(0U), 0U)->ssn);
    const auto next = resumed.prepare(SnpEmission::partial, contents(false), false, *replay, *scratch, resumed_at);
    require(next.status == SnpExchangeStatus::encoded && resumed.checkpoint().entries[0U].id == id(2U) &&
        !resumed.checkpoint().entries[0U].sequence);
    resumed.cancel();
    auto exhausted = resumed.checkpoint();
    exhausted.transmission.next_ticket = std::numeric_limits<std::uint64_t>::max();
    require(resumed.restore(exhausted));
    require(resumed.prepare(SnpEmission::partial, contents(false), false, *replay, *scratch, resumed_at).status ==
        SnpExchangeStatus::ticket_exhausted);
    const auto idle = resumed.checkpoint();
    SnpExchange idle_copy(resumed_db, resumed_acks, 0U, 9U, 8U);
    require(!idle.pending_emission && idle.entries.empty() && !idle.pending_cursor && idle_copy.restore(idle));
  }
  {
    auto original_db = database(), resumed_db = database();
    TransientAcknowledgements original_acks(8U), resumed_acks(8U), empty_acks(8U);
    SnpEntry purge{0U, id(0U), 1U, 7U};
    const auto first = original_acks.admit(0U, purge);
    auto second = purge;
    second.id = id(1U);
    require(first.status == AcknowledgementAdmission::queued && original_acks.admit(0U, second).status == AcknowledgementAdmission::queued);
    SnpExchange original(original_db, original_acks, 0U, 11U, 8U);
    const auto sent = original.prepare(SnpEmission::transient_acknowledgement, contents(false), false, *frame, *scratch, now);
    require(sent.status == SnpExchangeStatus::encoded);
    ++purge.sequence;
    require(original_acks.admit(0U, purge).status == AcknowledgementAdmission::queued);
    const auto saved = original.checkpoint();
    require(resumed_acks.restore(original_acks.checkpoint(), 2U));
    SnpExchange resumed(resumed_db, resumed_acks, 0U, 11U, 8U), missing(resumed_db, empty_acks, 0U, 11U, 8U);
    require(resumed.restore(saved) && !missing.restore(saved));
    auto invalid = saved;
    invalid.acknowledgements[0U].ticket = 99U;
    require(!resumed.restore(invalid) && resumed.pending());
    invalid = saved; ++invalid.entries[0U].sequence; invalid.acknowledgements[0U].entry = invalid.entries[0U];
    require(!resumed.restore(invalid) && resumed.pending());
    const auto completed = resumed.complete(11U, sent.ticket, true, resumed_at);
    require(completed.accepted && completed.retired == 1U && resumed_acks.size() == 2U &&
        !resumed_acks.contains(0U, saved.acknowledgements[0U]));
    const auto idle = resumed.checkpoint();
    SnpExchange idle_copy(resumed_db, resumed_acks, 0U, 11U, 8U);
    require(idle_copy.restore(idle));
    const auto next = idle_copy.prepare(SnpEmission::transient_acknowledgement, contents(false), false, *replay, *scratch, resumed_at);
    require(next.status == SnpExchangeStatus::encoded && next.ticket == saved.transmission.next_ticket &&
        idle_copy.checkpoint().entries[0U].id == id(1U));
  }
}
