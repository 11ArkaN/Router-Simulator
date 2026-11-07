// Registry facts produce immutable normal-TLV membership maps. The caller owns
// input data and output publication; this module has no filesystem side effects.

// Requires a version-one source lock and sorted unique octet lists. Throws
// Error on invalid metadata or permissions; success returns C++ text without
// mutating inputs or retaining references. No shard affinity or shared memory.
export function renderTlvRegistry(facts) {
  if (facts.schema_version !== 1 || !/^[a-f0-9]{64}$/.test(facts.sha256 ?? ""))
    throw new Error("Invalid IS-IS registry source lock");
  const bitmap = (values) => {
    if (!Array.isArray(values) || values.some((value, index) => !Number.isInteger(value) ||
        value < 0 || value > 255 || (index && values[index - 1] >= value)))
      throw new Error("IS-IS registry codes must be sorted unique octets");
    const words = [0n, 0n, 0n, 0n];
    for (const value of values) words[value >>> 6] |= 1n << BigInt(value & 63);
    return words.map((word) => `0x${word.toString(16).padStart(16, "0")}ULL`).join(", ");
  };
  const registered = bitmap(facts.registered);
  const allowed = bitmap(facts.purge_allowed);
  if (facts.purge_allowed.some((value) => !facts.registered.includes(value)))
    throw new Error("Purge codes must have a registered assignment");
  return `// Normal IS-IS TLV registry membership and purge permissions are immutable.
// No module owns mutable state here; consumers depend only on these wire facts.
// Source: iana.isis.tlv_purge_registry

#pragma once

#include <array>
#include <cstdint>

namespace router::packet::isis {
inline constexpr std::array<std::uint64_t, 4U> registered_tlv_codes{${registered}};
inline constexpr std::array<std::uint64_t, 4U> purge_tlv_codes{${allowed}};
} // namespace router::packet::isis
`;
}
