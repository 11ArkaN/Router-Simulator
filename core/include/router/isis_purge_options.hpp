// Purge option policy and POI wire values own no protocol state. Callers keep
// packet storage and select compatibility policy before local LSDB admission.
// Dependencies point only to bounded TLV framing and immutable registry facts.

#pragma once

#include "router/isis_packet.hpp"

namespace router::isis {
enum class PurgeRules : std::uint8_t { iso_10589, authentication_only, registry_6233, unspecified = 255U };
enum class PurgeValidation : std::uint8_t {
  accepted, prohibited_option, unknown_without_poi, malformed, invalid_policy
};
// Input is the option span of an effective zero-lifetime LSP. Compatibility is
// explicit, not inferred from the presence of an authentication TLV. No mutation
// or allocation occurs; the caller authenticates before accepting these options.
// POI presence enables unknown TLVs under RFC 6233; invalid POI value contents
// are ignored by their semantic consumer under RFC 8918, not a PDU rejection.
[[nodiscard]] PurgeValidation validate_purge_options(std::span<const std::uint8_t> options,
    PurgeRules rules) noexcept;

struct PurgeOriginator {
  packet::isis::SystemId originator{};
  std::optional<packet::isis::SystemId> received_from;
  bool operator==(const PurgeOriginator &) const = default;
};
// RFC 6232 TLV 13 carries exactly one or two six-octet system IDs. Malformed
// contents return nullopt and must be ignored without rejecting an entire LSP.
// Returned IDs are values; no packet reference or shard affinity is retained.
[[nodiscard]] std::optional<PurgeOriginator> decode_purge_originator(packet::isis::TlvView option) noexcept;
// Caller is constructing a purge, never a live LSP. Capacity refusal preserves
// the writer. No allocation; input and output may alias because staging is local.
[[nodiscard]] bool encode_purge_originator(packet::isis::TlvWriter &writer,
    const PurgeOriginator &originator) noexcept;
} // namespace router::isis
