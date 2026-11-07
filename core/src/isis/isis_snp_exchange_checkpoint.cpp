// The circuit owner restores SNP range progress and exact pending receipts.
// Its level database and transient-ack owner are restored first and outlive it.
// Queued frames stay with the transport coordinator; no key lease is retained.

#include "router/isis_snp_exchange.hpp"

#include <algorithm>
#include <utility>

namespace router::isis {
SnpExchangeCheckpoint SnpExchange::checkpoint() const {
  const bool pending = transmission_.pending();
  SnpExchangeCheckpoint result{1U, database_.type(), circuit_, entries_.size(), transmission_.checkpoint(),
      complete_.checkpoint(), pending ? pending_emission_ : std::nullopt, partial_cursor_, acknowledgement_cursor_,
      pending ? pending_cursor_ : std::nullopt, {}, {}};
  if (pending) {
    result.entries.assign(entries_.begin(), entries_.begin() + pending_count_);
    if (pending_emission_ == SnpEmission::transient_acknowledgement)
      result.acknowledgements.assign(acknowledgement_entries_.begin(), acknowledgement_entries_.begin() + pending_count_);
  }
  return result;
}

bool SnpExchange::restore(const SnpExchangeCheckpoint &saved) noexcept {
  if (saved.version != 1U || saved.database_type != database_.type() || saved.circuit != circuit_ ||
      saved.entry_capacity != entries_.size() || saved.entries.size() > entries_.size() ||
      saved.pending_emission.has_value() != (saved.transmission.pending != 0U) ||
      (saved.pending_emission && *saved.pending_emission > SnpEmission::transient_acknowledgement)) return false;
  protocol::TransmissionWindow transmission(transmission_.epoch());
  CompleteSnpSequence complete;
  if (!transmission.restore(saved.transmission) || !complete.restore(saved.complete)) return false;
  const bool full = saved.pending_emission == SnpEmission::complete;
  const bool transient = saved.pending_emission == SnpEmission::transient_acknowledgement;
  if (saved.complete.pending != full ||
      (!saved.pending_emission && (!saved.entries.empty() || saved.pending_cursor)) ||
      (full && saved.pending_cursor) ||
      (saved.pending_emission && !full && (saved.entries.empty() || !saved.pending_cursor)) ||
      saved.acknowledgements.size() != (transient ? saved.entries.size() : 0U)) return false;
  for (std::size_t index{}; index < saved.entries.size(); ++index) {
    const auto &entry = saved.entries[index];
    if ((index && saved.entries[index - 1U].id >= entry.id) ||
        (!entry.sequence && (entry.remaining_seconds || entry.checksum)) || (entry.remaining_seconds && !entry.checksum) ||
        (full && (entry.id < saved.complete.first || entry.id > saved.complete.pending_last))) return false;
    if (transient && (saved.acknowledgements[index].entry != entry ||
        !acknowledgements_.contains(circuit_, saved.acknowledgements[index]))) return false;
  }
  if (saved.pending_cursor && std::none_of(saved.entries.begin(), saved.entries.end(),
      [&](const auto &entry) { return entry.id == *saved.pending_cursor; })) return false;
  if (full && saved.entries.empty()) {
    packet::isis::LspId maximum;
    maximum.fill(0xffU);
    if (saved.complete.pending_last != maximum) return false;
  }
  transmission_ = std::move(transmission);
  complete_ = complete;
  pending_emission_ = saved.pending_emission;
  partial_cursor_ = saved.partial_cursor;
  acknowledgement_cursor_ = saved.acknowledgement_cursor;
  pending_cursor_ = saved.pending_cursor;
  pending_count_ = saved.entries.size();
  std::copy(saved.entries.begin(), saved.entries.end(), entries_.begin());
  std::copy(saved.acknowledgements.begin(), saved.acknowledgements.end(), acknowledgement_entries_.begin());
  return true;
}
} // namespace router::isis
