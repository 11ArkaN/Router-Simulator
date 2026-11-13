// Registry facts produce immutable normal-TLV membership maps. The caller owns
// input data and output publication; this module has no filesystem side effects.

// Requires a version-two source lock and sorted unique octet lists. Throws
// Error on invalid metadata or permissions; success returns C++ text without
// mutating inputs or retaining references. No shard affinity or shared memory.
export function renderTlvRegistry(facts) {
  if (facts.schema_version !== 2 || !/^[a-f0-9]{64}$/.test(facts.sha256 ?? ""))
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
  const contexts = ["neighbor", "prefix", "router_capability"];
  if (!facts.subregistries || Object.keys(facts.subregistries).sort().join() !== [...contexts].sort().join())
    throw new Error("Incomplete IS-IS multipart registry contexts");
  const membership = (name, source) => {
    if (!/^[a-f0-9]{64}$/.test(source.sha256 ?? "") ||
        !source.source_url?.startsWith("https://www.iana.org/assignments/isis-tlv-codepoints/"))
      throw new Error("Invalid IS-IS multipart registry source");
    const assigned = bitmap(source.registered);
    const yes = bitmap(source.multipart_allowed), no = bitmap(source.multipart_disallowed);
    if ([...source.multipart_allowed, ...source.multipart_disallowed].some((code) => !source.registered.includes(code)) ||
        source.multipart_allowed.some((code) => source.multipart_disallowed.includes(code)))
      throw new Error("Invalid IS-IS multipart registry permission");
    return (name === "tlv" ? "" : `inline constexpr std::array<std::uint64_t, 4U> ${name}_registered_codes{${assigned}};\n`) +
      `inline constexpr std::array<std::uint64_t, 4U> ${name}_multipart_codes{${yes}};\n` +
      `inline constexpr std::array<std::uint64_t, 4U> ${name}_nonmultipart_codes{${no}};`;
  };
  const multipart = [membership("tlv", facts), ...contexts.map((name) => membership(name, facts.subregistries[name]))];
  return `// IS-IS registry membership, purge and multipart permissions are immutable.
// No module owns mutable state here; consumers depend only on these wire facts.
// Source: iana.isis.tlv_purge_registry

#pragma once

#include <array>
#include <cstdint>

namespace router::packet::isis {
inline constexpr std::array<std::uint64_t, 4U> registered_tlv_codes{${registered}};
inline constexpr std::array<std::uint64_t, 4U> purge_tlv_codes{${allowed}};
${multipart.join("\n")}
enum class MultipartContext : std::uint8_t { tlv, neighbor, prefix, router_capability };
enum class MultipartApplicability : std::uint8_t { unknown, allowed, disallowed };
// Context is a registry namespace, not a peer capability. Unassigned or blank
// registry permission remains unknown; it must not become a prohibition.
[[nodiscard]] constexpr MultipartApplicability multipart_applicability(MultipartContext context, std::uint8_t code) noexcept {
  const auto bit = std::uint64_t{1U} << (code & 63U);
  const auto word = code >> 6U;
  const auto select = [&](const auto &yes, const auto &no) {
    return yes[word] & bit ? MultipartApplicability::allowed :
        no[word] & bit ? MultipartApplicability::disallowed : MultipartApplicability::unknown;
  };
  switch (context) {
    case MultipartContext::tlv: return select(tlv_multipart_codes, tlv_nonmultipart_codes);
${contexts.map((name) => `    case MultipartContext::${name}: return select(${name}_multipart_codes, ${name}_nonmultipart_codes);`).join("\n")}
  }
  return MultipartApplicability::unknown;
}
} // namespace router::packet::isis
`;
}
