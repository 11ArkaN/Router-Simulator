// Circuit-local SNP output coordinates independently owned flood obligations.
// Exact transmission tickets guard operational cancellation within an unchanged
// configuration epoch. ISO 10589 7.3.15-7.3.17 govern flag and range completion.

#include "router/isis_snp_exchange.hpp"

#include <stdexcept>

namespace router::isis {
SnpExchange::SnpExchange(LevelDatabase &database, TransientAcknowledgements &acknowledgements,
    std::size_t circuit, std::uint64_t epoch, std::size_t entry_capacity)
    : database_(database), acknowledgements_(acknowledgements), circuit_(circuit),
      transmission_(epoch), entries_(entry_capacity), acknowledgement_entries_(entry_capacity) {
  if (!database.circuit_state(circuit)) throw std::invalid_argument("IS-IS SNP exchange requires a stable circuit");
}

SnpTransmission SnpExchange::prepare(SnpEmission emission, SnpContents contents,
    bool designated, packet::Frame &output, PduScratch &scratch, RuntimeClock::time_point now) noexcept {
  using namespace packet::isis;
  if (emission != SnpEmission::complete && emission != SnpEmission::partial &&
      emission != SnpEmission::transient_acknowledgement) return {SnpExchangeStatus::invalid_configuration};
  if (transmission_.pending()) return {SnpExchangeStatus::pending};
  const auto circuit = database_.circuit_state(circuit_);
  if (!circuit || !circuit->eligible) return {SnpExchangeStatus::ineligible};
  const bool is_complete = emission == SnpEmission::complete;
  if (circuit->broadcast && ((is_complete && !designated) || (!is_complete && designated)))
    return {SnpExchangeStatus::role_forbidden};
  const bool level1 = database_.type() == PduType::lsp_l1;
  const auto expected = is_complete ? (level1 ? PduType::csnp_l1 : PduType::csnp_l2)
      : (level1 ? PduType::psnp_l1 : PduType::psnp_l2);
  if (contents.header.type != expected) return {SnpExchangeStatus::invalid_configuration};
  if (is_complete) contents.header.first = contents.header.last = {};
  const auto budget = maximum_snp_entries(contents, scratch);
  if (!budget) return {SnpExchangeStatus::invalid_configuration};
  if (*budget > entries_.size()) return {SnpExchangeStatus::capacity};
  if (!is_complete && !*budget) return {SnpExchangeStatus::capacity};
  const auto available = std::span(entries_).first(*budget);
  pending_count_ = 0U;
  pending_cursor_.reset();
  if (is_complete) {
    const auto batch = complete_.prepare(database_, available, now);
    if (batch.status == CompleteSnpStatus::idle) return {};
    if (batch.status == CompleteSnpStatus::pending) return {SnpExchangeStatus::pending};
    if (batch.status == CompleteSnpStatus::inconsistent_database) return {SnpExchangeStatus::inconsistent_database};
    if (batch.status != CompleteSnpStatus::prepared) return {SnpExchangeStatus::capacity};
    contents.header.first = batch.first;
    contents.header.last = batch.last;
    pending_count_ = batch.count;
  } else if (emission == SnpEmission::partial) {
    const auto batch = database_.partial_snp(circuit_, partial_cursor_, available, now);
    pending_count_ = batch.count;
    pending_cursor_ = batch.cursor;
  } else {
    const auto batch = acknowledgements_.select(circuit_, acknowledgement_cursor_,
        std::span(acknowledgement_entries_).first(*budget));
    pending_count_ = batch.count;
    pending_cursor_ = batch.cursor;
    for (std::size_t index{}; index < batch.count; ++index) entries_[index] = acknowledgement_entries_[index].entry;
  }
  if (!is_complete && !pending_count_) return {};
  contents.entries = std::span(entries_).first(pending_count_);
  const auto composed = build_snp_frame(output, contents, scratch);
  if (composed != SnpBuildResult::encoded) {
    if (is_complete) static_cast<void>(complete_.complete(false));
    return {SnpExchangeStatus::composition_failed, 0U, composed};
  }
  const auto ticket = transmission_.begin();
  if (!ticket) {
    if (is_complete) static_cast<void>(complete_.complete(false));
    return {SnpExchangeStatus::ticket_exhausted};
  }
  pending_emission_ = emission;
  return {SnpExchangeStatus::encoded, *ticket, composed};
}

SnpCompletion SnpExchange::complete(std::uint64_t epoch, std::uint64_t ticket,
    bool enqueued, RuntimeClock::time_point now) noexcept {
  if (!pending_emission_ || !transmission_.complete(epoch, ticket)) return {};
  SnpCompletion result{true, 0U, 0U};
  if (*pending_emission_ == SnpEmission::complete) static_cast<void>(complete_.complete(enqueued));
  else {
    for (std::size_t index{}; index < pending_count_; ++index) {
      bool matched{};
      if (*pending_emission_ == SnpEmission::partial) {
        const auto &entry = entries_[index];
        matched = database_.complete({entry.id, entry.remaining_seconds, entry.sequence, entry.checksum, 0U},
            circuit_, true, enqueued, now);
      } else matched = acknowledgements_.complete(circuit_, acknowledgement_entries_[index].ticket, enqueued);
      if (!matched) ++result.superseded;
      else if (enqueued) ++result.retired;
    }
    if (enqueued) {
      if (*pending_emission_ == SnpEmission::partial) partial_cursor_ = pending_cursor_;
      else acknowledgement_cursor_ = pending_cursor_;
    }
  }
  pending_emission_.reset();
  pending_count_ = 0U;
  return result;
}

void SnpExchange::cancel() noexcept {
  transmission_.cancel();
  pending_emission_.reset();
  pending_count_ = 0U;
  complete_.reset();
}

bool SnpExchange::replace_epoch(std::uint64_t epoch) noexcept {
  if (!transmission_.replace(epoch)) return false;
  cancel();
  partial_cursor_.reset();
  acknowledgement_cursor_.reset();
  static_cast<void>(acknowledgements_.clear_circuit(circuit_));
  return true;
}
} // namespace router::isis
