// Local purge composition preserves foreign source identity and checksum. The
// control owner selects policy, original header and a borrowed authentication
// lease; no LSDB, sequence, timer or packet-queue state belongs here.

#pragma once

#include "router/isis_lsp_builder.hpp"
#include "router/isis_purge_options.hpp"

namespace router::isis {
struct PurgeContents {
  packet::isis::PduType type{};
  packet::isis::LspView original;
  std::uint8_t maximum_areas{};
  packet::isis::SystemId generator{};
  PurgeRules rules{PurgeRules::unspecified};
  std::optional<PduInstanceOption> instance;
  std::optional<AuthenticationKey> authentication;
  std::size_t maximum_pdu_octets{};
};
// Caller selected expiration, confusion or initiated purge from a validated
// header. Generates no reachability options. Registry mode inserts local POI;
// compatibility modes omit it. IID and authentication remain explicit policy.
// Foreign checksum is preserved under ISO 7.3.11 and 7.3.16.4, including zero.
// HMAC excludes checksum, so restoring it after digest construction is safe.
// Inputs and exclusive scratch are disjoint. No packet-buffer allocation or
// retention; cryptographic provider failures are explicit. Success
// borrows PDU scratch until reuse. Failure returns no bytes and may alter scratch.
[[nodiscard]] LspBuild build_purge_pdu(const PurgeContents &contents,
    std::span<std::uint8_t> option_scratch, std::span<std::uint8_t> pdu_scratch) noexcept;
} // namespace router::isis
