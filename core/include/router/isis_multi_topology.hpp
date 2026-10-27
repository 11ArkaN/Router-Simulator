// RFC 5120 topology membership and reachability wire values. Cursors borrow
// packet bytes and own only traversal offsets. Instance IDs, adjacency state,
// LSDB retention, topology-specific SPF and forwarding remain separate owners.

#pragma once

#include "router/isis_reachability.hpp"

namespace router::packet::isis {

inline constexpr std::uint16_t maximum_topology_id = 4095U;

struct TopologyComponent {
  std::uint16_t id{};
  bool overloaded{};
  bool attached{};
  bool operator==(const TopologyComponent &) const = default;
};

class TopologyCursor final {
public:
  // lsp_fragment_zero may be true only for LSP fragment zero. O/A flags are
  // otherwise ignored, and always ignored for MT0. Reserved bits are ignored.
  // A wrong code, empty list or nonintegral component sets valid() false.
  explicit TopologyCursor(TlvView tlv, bool lsp_fragment_zero = false) noexcept;
  [[nodiscard]] std::optional<TopologyComponent> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool flags_allowed_{};
  bool valid_{};
};

// Encodes one nonempty TLV 229 with at most 127 components. Only fragment-zero
// LSPs may originate O/A flags for nonzero MTs; invalid IDs, flag placement or
// capacity preserve writer bytes. All inputs are borrowed only for the call.
[[nodiscard]] bool encode_topologies(TlvWriter &writer,
    std::span<const TopologyComponent> topologies, bool lsp_fragment_zero) noexcept;

// Requires parse() output for a Hello or fragment-zero LSP. Unions membership
// across all TLV 229 occurrences. Absence means MT0 only; explicit MT2 alone
// does not imply MT0. nullopt means invalid context, ID or option framing.
// This does not decide whether to establish or use an adjacency: LAN adjacency
// formation must remain independent of having a common MT (RFC 5120 2.2).
[[nodiscard]] std::optional<bool> supports_topology(const PduView &pdu,
                                                   std::uint16_t topology) noexcept;

struct MtReachabilityView {
  std::uint16_t topology{};
  TlvView entries;
};

// Unwraps TLV 222, 235 or 237 into a borrowed standard 22, 135 or 236 view.
// Reserved membership bits are ignored. A zero topology is returned explicitly
// and MUST cause the entire TLV to be ignored, without traversing its body.
// Other bodies are validated by the existing extended reachability cursors.
// Wrong code, oversized value or a truncated MT header returns nullopt.
[[nodiscard]] std::optional<MtReachabilityView> mt_reachability(TlvView tlv) noexcept;

// Appends one complete nonzero-MT entry, sharing the standard reachability
// encoders and their canonical-prefix/sub-TLV checks. The extra MT header
// reduces body capacity by two octets. Failure leaves writer unchanged;
// input entry sub-TLVs may alias writer storage. No allocation or retention.
[[nodiscard]] bool encode_mt_neighbor(TlvWriter &writer, std::uint16_t topology,
                                       const ExtendedNeighbor &entry) noexcept;
[[nodiscard]] bool encode_mt_prefix(TlvWriter &writer, std::uint16_t topology,
                                     const ExtendedPrefix &entry) noexcept;

} // namespace router::packet::isis
