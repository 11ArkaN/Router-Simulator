// Unknown purges retain only bounded acknowledgement entries. Encoded PSNP
// batches and egress completion results prove that no superseded ticket can
// erase another purge version or a different circuit's obligation.

#include "router/isis_transient_acknowledgements.hpp"
#include "router/isis_snp_builder.hpp"

#include <array>
#include <limits>
#include <memory>
#include <stdexcept>

void isis_transient_acknowledgements_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS transient acknowledgement invariant failed");
  };
  TransientAcknowledgements acknowledgements(4U);
  SnpEntry purge{0U, {1U, 0U, 0U, 0U, 0U, 1U, 0U, 0U}, 1U, 10U};
  const auto first = acknowledgements.admit(0U, purge);
  require(first.status == AcknowledgementAdmission::queued && first.ticket != 0U);
  const auto duplicate = acknowledgements.admit(0U, purge);
  require(duplicate.status == AcknowledgementAdmission::duplicate && duplicate.ticket == first.ticket);
  ++purge.sequence;
  const auto replacement = acknowledgements.admit(0U, purge);
  require(replacement.status == AcknowledgementAdmission::queued && replacement.ticket > first.ticket);
  auto second = purge;
  second.id[0U] = 2U;
  const auto next = acknowledgements.admit(0U, second);
  const auto other = acknowledgements.admit(1U, purge);
  require(next.status == AcknowledgementAdmission::queued && other.status == AcknowledgementAdmission::queued &&
      acknowledgements.size() == 4U);
  auto excess = purge;
  excess.id[0U] = 3U;
  require(acknowledgements.admit(0U, excess).status == AcknowledgementAdmission::capacity);
  excess.remaining_seconds = 1U;
  require(acknowledgements.admit(0U, excess).status == AcknowledgementAdmission::not_purge);
  std::array<TransientAcknowledgement, 4U> batch{};
  auto selected = acknowledgements.select(0U, second.id, batch);
  require(selected.count == 2U && selected.cursor == second.id && batch[0U].ticket == first.ticket &&
      batch[1U].ticket == next.ticket && batch[0U].entry.id < batch[1U].entry.id);
  require(!acknowledgements.complete(1U, first.ticket, true) &&
      acknowledgements.complete(0U, first.ticket, false) && acknowledgements.size() == 4U);
  const std::array entries{batch[0U].entry, batch[1U].entry};
  SnpContents contents;
  contents.header.type = PduType::psnp_l1;
  contents.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  contents.entries = entries;
  contents.maximum_pdu_octets = 1492U;
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame frame;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::encoded);
  EthernetDecodeError error{};
  const auto wire = parse_ethernet_pdu(frame.view(), error);
  require(wire && wire->pdu.type == PduType::psnp_l1);
  TlvCursor options(wire->pdu.tlvs);
  const auto list = options.next();
  require(list && list->code == 9U && list->value.size() == 2U * snp_entry_octets &&
      snp_entry(list->value.first(snp_entry_octets)) == entries[0U]);
  require(acknowledgements.complete(0U, first.ticket, true) &&
      !acknowledgements.complete(0U, first.ticket, true) && acknowledgements.size() == 3U);
  selected = acknowledgements.select(0U, second.id, batch);
  require(selected.count == 2U && batch[0U].ticket == replacement.ticket &&
      batch[0U].entry.sequence == purge.sequence);
  require(acknowledgements.clear_circuit(0U) == 2U && acknowledgements.size() == 1U &&
      !acknowledgements.complete(0U, replacement.ticket, true));
  selected = acknowledgements.select(1U, std::nullopt, batch);
  require(selected.count == 1U && batch[0U].ticket == other.ticket &&
      acknowledgements.complete(1U, other.ticket, true) && acknowledgements.size() == 0U);
  TransientAcknowledgements exhausted(1U, std::numeric_limits<std::uint64_t>::max());
  require(exhausted.admit(0U, purge).status == AcknowledgementAdmission::ticket_exhausted &&
      exhausted.size() == 0U);
  {
    TransientAcknowledgements original(4U, 7U), resumed(4U);
    SnpEntry old_purge{0U, {1U, 0U, 0U, 0U, 0U, 1U, 0U, 0U}, 11U, 22U};
    auto other_purge = old_purge;
    other_purge.id[0U] = 2U;
    require(original.admit(1U, old_purge).ticket == 7U && original.admit(0U, other_purge).ticket == 8U);
    ++old_purge.sequence;
    require(original.admit(1U, old_purge).ticket == 9U);
    const auto saved = original.checkpoint();
    require(resumed.restore(saved, 2U) && resumed.next_ticket() == 10U && resumed.size() == 3U);
    std::array<TransientAcknowledgement, 4U> selected_entries{};
    require(resumed.select(1U, std::nullopt, selected_entries).count == 1U && selected_entries[0U].ticket == 7U);
    require(resumed.complete(1U, 7U, false) && resumed.complete(1U, 7U, true) &&
        !resumed.complete(1U, 7U, true) && !resumed.complete(1U, 8U, true) && resumed.complete(0U, 8U, true));
    require(resumed.select(1U, std::nullopt, selected_entries).count == 1U && selected_entries[0U].ticket == 9U);
    other_purge.id[0U] = 3U;
    require(resumed.admit(0U, other_purge).ticket == 10U);
    const auto baseline = resumed.checkpoint();
    const auto refused = [&](auto invalid) {
      require(!resumed.restore(invalid, 2U));
      const auto after = resumed.checkpoint();
      require(after.next_ticket == baseline.next_ticket && after.entries.size() == baseline.entries.size());
      for (std::size_t index{}; index < after.entries.size(); ++index)
        require(after.entries[index].circuit == baseline.entries[index].circuit &&
            after.entries[index].acknowledgement.ticket == baseline.entries[index].acknowledgement.ticket &&
            after.entries[index].acknowledgement.entry == baseline.entries[index].acknowledgement.entry);
    };
    auto invalid = saved;
    invalid.version = 2U; refused(invalid);
    invalid = saved; invalid.capacity = 3U; refused(invalid);
    invalid = saved; invalid.next_ticket = 0U; refused(invalid);
    invalid = saved; invalid.entries[0U].circuit = 2U; refused(invalid);
    invalid = saved; invalid.entries[0U].acknowledgement.entry.remaining_seconds = 1U; refused(invalid);
    invalid = saved; invalid.entries[0U].acknowledgement.ticket = 0U; refused(invalid);
    invalid = saved; invalid.entries[0U].acknowledgement.ticket = saved.next_ticket; refused(invalid);
    invalid = saved; invalid.entries[0U].acknowledgement.ticket = invalid.entries[1U].acknowledgement.ticket; refused(invalid);
    invalid = saved; invalid.entries[2U].acknowledgement.entry = invalid.entries[1U].acknowledgement.entry; refused(invalid);
    invalid = saved; std::swap(invalid.entries[0U], invalid.entries[1U]); refused(invalid);
    invalid = saved; invalid.entries.push_back(saved.entries[0U]); invalid.entries.push_back(saved.entries[1U]); refused(invalid);
    require(!resumed.restore(saved, 1U) && resumed.next_ticket() == baseline.next_ticket);
    auto exhausted_state = saved;
    exhausted_state.entries.clear();
    exhausted_state.next_ticket = std::numeric_limits<std::uint64_t>::max();
    require(resumed.restore(exhausted_state, 2U) &&
        resumed.admit(0U, old_purge).status == AcknowledgementAdmission::ticket_exhausted);
  }
}
