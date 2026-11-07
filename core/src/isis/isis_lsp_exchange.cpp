// Encoded LSP output preserves retained bytes and commits only actual receipts.
// ISO 10589 7.3.16.3 requires holding-time and transit lifetime reduction;
// 7.3.17 distinguishes LAN enqueue completion from P2P peer acknowledgement.

#include "router/isis_lsp_exchange.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace router::isis {
LspExchange::LspExchange(LevelDatabase &database, std::size_t circuit, std::uint64_t epoch)
    : database_(database), circuit_(circuit), transmission_(epoch) {
  if (!database.circuit_state(circuit)) throw std::invalid_argument("IS-IS LSP exchange requires a stable circuit");
}

LspTransmission LspExchange::prepare(const packet::isis::LspId &id,
    const packet::Mac &source, const packet::Mac &destination,
    std::size_t maximum_pdu_octets, std::uint16_t transit_seconds,
    packet::Frame &output, PduScratch &scratch, RuntimeClock::time_point now) noexcept {
  if (transmission_.pending()) return {LspEmissionStatus::pending};
  const auto flags = database_.flags(id, circuit_);
  if (!flags || !flags->eligible) return {LspEmissionStatus::ineligible};
  if (!flags->srm) return {};
  const auto stored = database_.database().find(id, now);
  if (!stored) return {};
  const auto decrement = std::max<std::uint16_t>(1U, transit_seconds);
  if (!stored->purge_installed && stored->header.remaining_seconds <= decrement)
    return {LspEmissionStatus::purge_required};
  const auto bytes = stored->pdu.bytes;
  if (maximum_pdu_octets < packet::isis::lsp_header_octets)
    return {LspEmissionStatus::capacity};
  if (bytes.size() > maximum_pdu_octets) {
    static_cast<void>(database_.suppress_oversized(id, circuit_));
    return {LspEmissionStatus::too_large};
  }
  if (bytes.size() > scratch.pdu.size()) return {LspEmissionStatus::capacity};
  std::copy(bytes.begin(), bytes.end(), scratch.pdu.begin());
  const auto lifetime = stored->purge_installed ? std::uint16_t{} :
      static_cast<std::uint16_t>(stored->header.remaining_seconds - decrement);
  scratch.pdu[10U] = static_cast<std::uint8_t>(lifetime >> 8U);
  scratch.pdu[11U] = static_cast<std::uint8_t>(lifetime);
  if (!packet::isis::ethernet_pdu_into(output, source, destination,
      std::span(scratch.pdu).first(bytes.size()))) return {LspEmissionStatus::capacity};
  const auto ticket = transmission_.begin();
  if (!ticket) return {LspEmissionStatus::ticket_exhausted};
  pending_ = stored->header;
  return {LspEmissionStatus::encoded, *ticket};
}

LspReceipt LspExchange::complete(std::uint64_t epoch, std::uint64_t ticket,
    bool enqueued, RuntimeClock::time_point now) noexcept {
  if (!transmission_.complete(epoch, ticket)) return {};
  return {true, database_.complete(pending_, circuit_, false, enqueued, now)};
}
LspExchangeCheckpoint LspExchange::checkpoint() const noexcept {
  return {1U, database_.type(), circuit_, transmission_.checkpoint(),
      transmission_.pending() ? std::optional{pending_} : std::nullopt};
}
bool LspExchange::restore(const LspExchangeCheckpoint &saved) noexcept {
  if (saved.version != 1U || saved.database_type != database_.type() || saved.circuit != circuit_ ||
      saved.pending.has_value() != (saved.transmission.pending != 0U) ||
      (saved.pending && (!saved.pending->sequence || (saved.pending->remaining_seconds && !saved.pending->checksum))))
    return false;
  protocol::TransmissionWindow transmission(transmission_.epoch());
  if (!transmission.restore(saved.transmission)) return false;
  transmission_ = std::move(transmission);
  pending_ = saved.pending.value_or(packet::isis::LspView{});
  return true;
}
void LspExchange::cancel() noexcept { transmission_.cancel(); }
bool LspExchange::replace_epoch(std::uint64_t epoch) noexcept { return transmission_.replace(epoch); }
} // namespace router::isis
