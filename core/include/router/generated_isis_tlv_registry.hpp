// Normal IS-IS TLV registry membership and purge permissions are immutable.
// No module owns mutable state here; consumers depend only on these wire facts.
// Source: iana.isis.tlv_purge_registry

#pragma once

#include <array>
#include <cstdint>

namespace router::packet::isis {
inline constexpr std::array<std::uint64_t, 4U> registered_tlv_codes{0x000004001bffffffULL, 0xc000000000000004ULL, 0x00030002007bfeffULL, 0x080d7b20c0080000ULL};
inline constexpr std::array<std::uint64_t, 4U> purge_tlv_codes{0x000000000000a480ULL, 0x0000000000000000ULL, 0x0000000000000200ULL, 0x0000000000000000ULL};
} // namespace router::packet::isis
