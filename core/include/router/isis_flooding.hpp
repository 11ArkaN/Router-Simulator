// IS-IS flood-flag transitions for one encoded LSP and one level/instance.
// The control shard owns the supplied circuit flags. This module allocates
// nothing and depends only on the LSDB recency and packet value contracts.

#pragma once

#include "router/isis_lsdb.hpp"

namespace router::isis {

struct FloodCircuit {
  bool broadcast{};
  bool eligible{};
  bool srm{};
  bool ssn{};
};

struct LspFloodResult {
  bool accepted{};
  bool transient_acknowledgement{};
  bool waiting_state{};
};

// Called only after accepted envelope, authentication and purge checks, and
// LSDB admission. eligible excludes external-domain circuits and circuits not
// participating at this level. Every supplied circuit belongs to the same
// linkage. Invalid ingress changes nothing. Unknown purges need a transient
// acknowledgement without inserting an LSDB record. Allocation refusal must
// enter Waiting State and must not acknowledge. No input memory is retained.
[[nodiscard]] LspFloodResult received_lsp(std::span<FloodCircuit> circuits,
    std::size_t ingress, LspInstallResult result) noexcept;

struct SnpFloodResult {
  bool request_missing{};
  bool confusion{};
  bool waiting_state{};
};

// Caller has accepted the SNP and uses effective lifetimes for local entries.
// Missing entries request only a nonzero lifetime/checksum/sequence triple.
// The owner must reserve the zero-sequence request before setting SSN for it.
// Confusion leaves flags unchanged until the owner constructs a purge or
// regenerates a self-originated LSP. Broadcast PSNP acceptance requires DIS
// status and is checked before this per-entry operation.
[[nodiscard]] SnpFloodResult received_snp_entry(FloodCircuit &circuit,
    const packet::isis::SnpEntry &reported,
    const packet::isis::LspView *stored) noexcept;

// Called for an LSDB entry omitted from an accepted CSNP. Only live, nonzero
// sequence entries inside the inclusive advertised range are advertised back.
// Existing SSN is preserved. Ranges with start > end produce no transition.
void omitted_from_csnp(FloodCircuit &circuit, const packet::isis::LspView &stored,
    const packet::isis::LspId &start, const packet::isis::LspId &end) noexcept;

// Successful physical egress commits flags. A failed enqueue leaves them set
// for retry. P2P LSPs retain SRM until peer acknowledgement; PSNP entries clear
// SSN only after the containing PDU was accepted by the outbound queue.
void lsp_transmitted(FloodCircuit &circuit, bool enqueued) noexcept;
void psnp_transmitted(FloodCircuit &circuit, bool enqueued) noexcept;

} // namespace router::isis
