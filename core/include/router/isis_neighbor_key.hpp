// A received extended-neighbor object's identifiers are immutable wire values.
// The caller owns input and output; normalization owns traversal scratch only
// and depends on packet framing and address values, never a live adjacency.
#pragma once
#include "router/isis_reachability.hpp"
namespace router::packet::isis {
inline constexpr std::size_t maximum_neighbor_key_octets = 255U - 11U;
// RFC 9885 keys include all present link identifiers, not the default metric.
// IPv4/IPv6 address identifiers form unordered sets. RFC 5307 duplicate type-4
// identifiers are all ignored; invalid individual values are ignored under
// RFC 8918. IPv6 link-local identifiers are prohibited by RFC 6119.
// No allocation or shard affinity. Input is one neighbor's at-most-244-octet
// sub-TLV extent. Success returns initialized output length, including zero for
// no identifiers. Framing, extent or capacity refusal returns nullopt and keeps
// output unchanged. Staging permits overlap; no borrowed view escapes the call.
[[nodiscard]] std::optional<std::size_t> normalize_neighbor_key(
    std::span<const std::uint8_t> attributes, std::span<std::uint8_t> output) noexcept;
}
