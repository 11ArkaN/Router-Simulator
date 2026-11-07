// Independent ISO 10589 flood scenarios distinguish LAN transmission from
// P2P acknowledgement and verify that rejected admission cannot acknowledge.

#include "router/isis_flooding.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_flooding_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  for (const bool broadcast : {false, true}) {
    std::array<FloodCircuit, 3U> circuits{{{broadcast, true, true, false},
                                          {false, true, false, true},
                                          {false, false, false, false}}};
    auto result = received_lsp(circuits, 0U, LspInstallResult::installed);
    require(result.accepted && !circuits[0U].srm && circuits[0U].ssn == !broadcast &&
              circuits[1U].srm && !circuits[1U].ssn && !circuits[2U].srm,
            "IS-IS new LSP flood/ack transition failed");
    result = received_lsp(circuits, 0U, LspInstallResult::older);
    require(result.accepted && circuits[0U].srm && !circuits[0U].ssn,
            "IS-IS old LSP did not schedule database copy");
    lsp_transmitted(circuits[0U], false);
    require(circuits[0U].srm, "IS-IS failed enqueue cleared retransmission");
    lsp_transmitted(circuits[0U], true);
    require(circuits[0U].srm == !broadcast, "IS-IS P2P transmission lost acknowledgement requirement");
    result = received_lsp(circuits, 0U, LspInstallResult::identical);
    require(result.accepted && !circuits[0U].srm && circuits[0U].ssn == !broadcast,
            "IS-IS duplicate LSP was not acknowledged");
    circuits[0U].ssn = true;
    psnp_transmitted(circuits[0U], false);
    require(circuits[0U].ssn, "IS-IS failed PSNP enqueue lost pending acknowledgement");
    psnp_transmitted(circuits[0U], true);
    require(!circuits[0U].ssn, "IS-IS successful PSNP retained SSN");
    for (const auto rejected : {LspInstallResult::malformed, LspInstallResult::invalid_checksum,
                               LspInstallResult::excessive_lifetime, LspInstallResult::confusion,
                               LspInstallResult::capacity_exhausted}) {
      result = received_lsp(circuits, 0U, rejected);
      require(!result.accepted && !circuits[0U].srm && !circuits[0U].ssn &&
                result.waiting_state == (rejected == LspInstallResult::capacity_exhausted),
              "IS-IS rejected LSP changed flood state");
    }
    result = received_lsp(circuits, 0U, LspInstallResult::unknown_purge);
    require(result.accepted && result.transient_acknowledgement && !circuits[0U].ssn,
            "IS-IS unknown purge requires a transient acknowledgement");

    const LspView stored{{1U, 2U, 3U, 4U, 5U, 6U, 0U, 1U}, 30U, 10U, 100U, 3U};
    SnpEntry entry{1U, stored.id, stored.sequence, stored.checksum};
    FloodCircuit circuit{broadcast, true, true, true};
    auto snp = received_snp_entry(circuit, entry, &stored);
    require(!snp.confusion && circuit.srm == broadcast && circuit.ssn,
            "IS-IS equal SNP must clear only P2P SRM");
    --entry.sequence;
    snp = received_snp_entry(circuit, entry, &stored);
    require(circuit.srm && !circuit.ssn, "IS-IS older SNP did not schedule stored LSP");
    entry.sequence += 2U;
    snp = received_snp_entry(circuit, entry, &stored);
    require(circuit.srm == broadcast && circuit.ssn, "IS-IS newer SNP did not request LSP");
    entry.sequence = stored.sequence;
    ++entry.checksum;
    snp = received_snp_entry(circuit, entry, &stored);
    require(snp.confusion && circuit.srm == broadcast && circuit.ssn,
            "IS-IS SNP checksum confusion mutated flags");
    snp = received_snp_entry(circuit, entry, nullptr);
    require(snp.request_missing, "IS-IS nonzero unknown SNP entry was not requested");
    for (unsigned zero = 0U; zero < 3U; ++zero) {
      auto absent = entry;
      if (zero == 0U) absent.remaining_seconds = 0U;
      if (zero == 1U) absent.sequence = 0U;
      if (zero == 2U) absent.checksum = 0U;
      require(!received_snp_entry(circuit, absent, nullptr).request_missing,
              "IS-IS unknown zero-valued SNP entry created a request");
    }
    circuit.srm = false;
    auto begin = stored.id;
    auto end = stored.id;
    omitted_from_csnp(circuit, stored, begin, end);
    require(circuit.srm, "IS-IS CSNP inclusive singleton range missed LSP");
    circuit.srm = false;
    ++begin.back();
    omitted_from_csnp(circuit, stored, begin, end);
    require(!circuit.srm, "IS-IS invalid CSNP range scheduled an LSP");
    auto expired = stored;
    expired.remaining_seconds = 0U;
    omitted_from_csnp(circuit, expired, stored.id, end);
    expired = stored;
    expired.sequence = 0U;
    omitted_from_csnp(circuit, expired, stored.id, end);
    require(!circuit.srm, "IS-IS omitted purge or request placeholder was flooded");
  }
  std::array<FloodCircuit, 1U> disabled{{{false, false, false, false}}};
  require(!received_lsp(disabled, 0U, LspInstallResult::installed).accepted &&
            !received_lsp(disabled, 1U, LspInstallResult::installed).accepted && !disabled[0U].srm,
          "IS-IS ineligible ingress changed flood flags");
}
