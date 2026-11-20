// Cold root LSP composition belongs to the instance configuration owner.
// Inputs are local intent only; encoded units feed the existing fragment
// planner. No peer state, timer, sequence, LSDB or mutable shared state is owned.
#pragma once
#include "router/isis_local_lsp_set.hpp"
#include "router/isis_neighbor_attributes.hpp"
#include "router/isis_reachability.hpp"
#include <string_view>
#include <array>
namespace router::isis {
struct RootPrefix {
  ip::IpPrefix prefix;
  std::uint32_t metric{};
  // Transitional output is explicit. The caller resolves narrow metrics;
  // composition never clips a wide metric into a six-bit value.
  std::optional<std::uint8_t> narrow;
  // Borrowed complete prefix sub-TLVs, copied into owned wire records before
  // return. External IPv4 classification follows RFC 7794 X; IPv6 uses the
  // fixed reachability flag supplied separately by the originating owner.
  std::span<const std::uint8_t> attributes{};
  bool external_ipv6{};
};
// Same-owner semantic encoding into caller scratch. Requires a canonical local
// prefix and complete borrowed sub-TLVs, valid only for this call. Appends wide
// reachability and its optional narrow companion together. Failure preserves
// the writer. No allocation, state retention, publication or shard crossing.
[[nodiscard]] bool encode_root_prefix(packet::isis::TlvWriter &writer, const RootPrefix &prefix) noexcept;
struct RootContentInput {
  packet::isis::SystemId local;
  std::uint8_t level{}, flags{1U};
  bool ipv4{}, ipv6{};
  std::span<const NeighborArea> areas;
  std::span<const packet::Ipv4> ipv4_addresses;
  std::span<const packet::Ipv6> ipv6_addresses;
  // Empty omits TLV 137. Nonempty is 7-bit ASCII, at most 255 bytes; the
  // management owner performs any Unicode ToASCII conversion before admission.
  std::string_view hostname;
  // Prefixes are strictly ordered unique canonical networks. The configuration
  // owner applies local-interface, passive, aggregation and export policy first.
  std::span<const RootPrefix> prefixes;
};
enum class RootContentStatus : std::uint8_t { prepared, invalid, capacity };
struct RootContentResult {
  RootContentStatus status{RootContentStatus::invalid};
  std::vector<LocalLspContent> records;
};
// Control owner, cold preparation only. semantic_octets excludes fixed header,
// IID and authentication; fragments is 1..256 and charged to the caller's LSDB
// budget. Success owns complete TLVs in active non-pseudonode fragments, always
// including fragment zero. Area Addresses occur only in zero. Higher fragments
// carry only IS-type bits. Failure returns no records; allocation may throw.
// Inputs expire on return and must not alias internal temporary storage.
[[nodiscard]] RootContentResult prepare_root_content(const RootContentInput &input,
    std::size_t semantic_octets, std::size_t fragments);
// Cold configuration/control owner only. Input is one local program's canonical
// root metadata (TLVs 1, 129, 132, 137 and 232), with contiguous reserved root
// fragment IDs per level. Pseudonode records are preserved. Budgets are semantic
// PDU extents after framing. Empty hostname withdraws TLV 137; other values use
// the same ASCII/length contract as RootContentInput. Success retains record
// identities/flags and owns all bytes. Invalid framing, unsupported options or
// capacity returns no records and leaves input unchanged. Allocation may throw.
[[nodiscard]] RootContentResult rewrite_root_hostname(std::span<const LocalLspContent> records,
    std::string_view hostname, std::array<std::size_t,2U> semantic_octets);
}
