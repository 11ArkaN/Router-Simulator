// IS-IS registry membership, purge and multipart permissions are immutable.
// No module owns mutable state here; consumers depend only on these wire facts.
// Source: iana.isis.tlv_purge_registry

#pragma once

#include <array>
#include <cstdint>

namespace router::packet::isis {
inline constexpr std::array<std::uint64_t, 4U> registered_tlv_codes{0x000004003fffffffULL, 0xc000000000000004ULL, 0x00030002007bfeffULL, 0x080d7b20c0080000ULL};
inline constexpr std::array<std::uint64_t, 4U> purge_tlv_codes{0x000000000000a480ULL, 0x0000000000000000ULL, 0x0000000000000200ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> tlv_multipart_codes{0x000000000ef00080ULL, 0x0000000000000000ULL, 0x000000000079e480ULL, 0x08047800c0000000ULL};
inline constexpr std::array<std::uint64_t, 4U> tlv_nonmultipart_codes{0x00000400310fff7eULL, 0xc000000000000004ULL, 0x0003000200021a7fULL, 0x0009032000080000ULL};
inline constexpr std::array<std::uint64_t, 4U> neighbor_registered_codes{0x0001ffffffffff58ULL, 0x0000000000000000ULL, 0x0000000200000000ULL, 0xfc00000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> neighbor_multipart_codes{0x00001e0048218000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> neighbor_nonmultipart_codes{0x0001e1ffb7de7f58ULL, 0x0000000000000000ULL, 0x0000000200000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> prefix_registered_codes{0x000000010000187eULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> prefix_multipart_codes{0x0000000100000026ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> prefix_nonmultipart_codes{0x0000000000001858ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> router_capability_registered_codes{0x000000007fffffffULL, 0x0000000000000000ULL, 0x0000000200000000ULL, 0x0400000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> router_capability_multipart_codes{0x000000000087c758ULL, 0x0000000000000000ULL, 0x0000000200000000ULL, 0x0000000000000000ULL};
inline constexpr std::array<std::uint64_t, 4U> router_capability_nonmultipart_codes{0x000000007f7838a6ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0400000000000000ULL};
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
    case MultipartContext::neighbor: return select(neighbor_multipart_codes, neighbor_nonmultipart_codes);
    case MultipartContext::prefix: return select(prefix_multipart_codes, prefix_nonmultipart_codes);
    case MultipartContext::router_capability: return select(router_capability_multipart_codes, router_capability_nonmultipart_codes);
  }
  return MultipartApplicability::unknown;
}
} // namespace router::packet::isis
