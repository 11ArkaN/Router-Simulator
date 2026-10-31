// Local LSP composition owns no sequence, LSDB, timer or circuit state. The
// instance control owner supplies finalized header/options and exclusive raw
// buffers; physical frame capacity is checked separately by each circuit.

#pragma once

#include "router/isis_authentication.hpp"
#include "router/isis_pdu_composition.hpp"

namespace router::isis {
struct LspContents {
  packet::isis::LspInput header;
  std::span<const std::uint8_t> options;
  std::optional<PduInstanceOption> instance;
  std::optional<AuthenticationKey> authentication;
  std::size_t maximum_pdu_octets{};
};
enum class LspBuildStatus : std::uint8_t {
  encoded, capacity, invalid_header, options, instance, authentication
};
struct LspBuild {
  LspBuildStatus status{LspBuildStatus::invalid_header};
  std::span<const std::uint8_t> bytes{};
};
// Same-owner synchronous composition. Inputs, option scratch and PDU scratch
// are disjoint; leases outlive this call only. Caller-selected capacity may
// exceed a port's Frame capacity, but never the 16-bit PDU length. Input options
// must be framed TLVs without IID or authentication, which this builder owns.
// Success borrows PDU scratch until reuse. Failure returns no bytes and may
// modify scratch. No packet-buffer allocation, network admission or sequence
// advancement. Cryptographic provider failures are reported separately.
[[nodiscard]] LspBuild build_lsp_pdu(const LspContents &contents,
    std::span<std::uint8_t> option_scratch, std::span<std::uint8_t> pdu_scratch) noexcept;
} // namespace router::isis
