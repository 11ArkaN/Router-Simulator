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
}
