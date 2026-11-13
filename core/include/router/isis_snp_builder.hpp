// Complete and partial SNP composition from an owner's ordered LSDB projection.
// The control shard owns entries, authentication keys and scratch. This module
// owns no flood flags, acknowledgement state, timer or queued output frame.

#pragma once

#include "router/isis_authentication.hpp"
#include "router/isis_pdu_composition.hpp"

namespace router::isis {

struct SnpContents {
  packet::isis::SnpInput header;
  packet::Mac source{};
  packet::Mac destination{};
  std::span<const packet::isis::SnpEntry> entries;
  std::optional<PduInstanceOption> instance;
  std::optional<AuthenticationKey> authentication;
  std::size_t maximum_pdu_octets{};
};

enum class SnpBuildResult : std::uint8_t {
  encoded, invalid_header, capacity, entries, instance, authentication
};

// Call after effective instance-policy acceptance. Uses the same option
// encoders as composition to budget IID and authentication overhead, then
// accounts for whole TLV 9 headers. entries is ignored. nullopt means invalid
// header, option encoding or fixed-PDU capacity. Zero is a valid empty-CSNP
// budget. Scratch remains exclusively owned and no key view is retained.
[[nodiscard]] std::optional<std::size_t> maximum_snp_entries(
    const SnpContents &contents, PduScratch &scratch) noexcept;

// Requires a complete owner-selected batch in strictly ascending LSP-ID order;
// CSNP entries must lie inside the inclusive advertised range. The caller owns
// range partitioning and advances SRM/SSN only after actual egress succeeds.
// Entries split into whole TLV 9 options, IID precedes them and authentication
// covers the final PDU. No partial batch is emitted. Failure preserves output.
// Input/output views must be disjoint from exclusively owned scratch. Nothing
// is retained and the returned frame still must cross the egress SPSC channel.
[[nodiscard]] SnpBuildResult build_snp_frame(packet::Frame &output,
    const SnpContents &contents, PduScratch &scratch) noexcept;

} // namespace router::isis
