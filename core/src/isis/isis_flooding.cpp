// ISO flood-flag transitions. The caller is the sole owner of all flags and
// commits packet admission before invoking these allocation-free operations.
// Source: iso.10589.2002.flooding

#include "router/isis_flooding.hpp"

namespace router::isis {

LspFloodResult received_lsp(std::span<FloodCircuit> circuits, std::size_t ingress,
    LspInstallResult result) noexcept {
  if (ingress >= circuits.size() || !circuits[ingress].eligible) return {};
  if (result == LspInstallResult::capacity_exhausted) return {false, false, true};
  if (result == LspInstallResult::unknown_purge) return {true, true, false};
  auto &incoming = circuits[ingress];
  if (result == LspInstallResult::installed) {
    for (std::size_t index = 0U; index < circuits.size(); ++index) {
      auto &circuit = circuits[index];
      if (!circuit.eligible) continue;
      circuit.srm = index != ingress;
      if (index != ingress) circuit.ssn = false;
    }
    if (!incoming.broadcast) incoming.ssn = true;
  } else if (result == LspInstallResult::identical) {
    incoming.srm = false;
    if (!incoming.broadcast) incoming.ssn = true;
  } else if (result == LspInstallResult::older) {
    incoming.srm = true;
    incoming.ssn = false;
  } else return {};
  return {true, false, false};
}

SnpFloodResult received_snp_entry(FloodCircuit &circuit,
    const packet::isis::SnpEntry &reported, const packet::isis::LspView *stored) noexcept {
  if (!circuit.eligible) return {};
  if (!stored) return {reported.remaining_seconds != 0U && reported.checksum != 0U &&
                       reported.sequence != 0U, false};
  if (reported.id != stored->id) return {};
  const packet::isis::LspView candidate{reported.id, reported.remaining_seconds,
                                       reported.sequence, reported.checksum, 0U};
  const auto recency = compare_lsp_headers(candidate, *stored);
  if (recency == LspRecency::confusion) return {false, true};
  if (recency == LspRecency::older) {
    circuit.ssn = false;
    // Zero-sequence placeholders never represent an advertisement to flood.
    circuit.srm = stored->sequence != 0U;
  } else if (recency == LspRecency::newer) {
    circuit.ssn = true;
    if (!circuit.broadcast) circuit.srm = false;
  } else if (!circuit.broadcast) circuit.srm = false;
  return {};
}

void omitted_from_csnp(FloodCircuit &circuit, const packet::isis::LspView &stored,
    const packet::isis::LspId &start, const packet::isis::LspId &end) noexcept {
  if (circuit.eligible && stored.sequence && stored.remaining_seconds &&
      start <= stored.id && stored.id <= end) circuit.srm = true;
}

void lsp_transmitted(FloodCircuit &circuit, bool enqueued) noexcept {
  if (enqueued && circuit.broadcast) circuit.srm = false;
}

void psnp_transmitted(FloodCircuit &circuit, bool enqueued) noexcept {
  if (enqueued) circuit.ssn = false;
}

} // namespace router::isis
