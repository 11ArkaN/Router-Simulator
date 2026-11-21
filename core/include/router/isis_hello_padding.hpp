// Stateless SR OS Hello padding decisions. The circuit owner supplies its own
// adjacency projection; no peer lookup, timer or mutable state belongs here.
#pragma once
#include "router/isis_three_way.hpp"
#include <string_view>
namespace router::isis {
enum class HelloPadding : std::uint8_t { adaptive=1U, loose=2U, strict=3U, none=4U };
// Pinned YANG enum spellings shared by intent editors and renderers. Parsing
// is exact and retains no view. Formatting invalid values returns an empty view;
// all valid outputs reference immutable static storage on the calling shard.
[[nodiscard]] std::optional<HelloPadding> parse_hello_padding(std::string_view) noexcept;
[[nodiscard]] std::string_view format_hello_padding(HelloPadding) noexcept;
// Same circuit control shard. Absence of a neighbor is represented by Down
// with legacy=false. A legacy peer has no three-way state. An unresolved loose
// legacy combination or invalid enum returns nullopt and must not be silently
// interpreted as unpadded. Adaptive follows the release-specific requirement
// to continue padding when the peer lacks TLV 240. No input is retained.
[[nodiscard]] std::optional<bool> p2p_hello_padding(HelloPadding,
    ThreeWayState, bool legacy) noexcept;
// Same LAN circuit owner. any_up is computed from this level's actual local
// adjacency set. Both adaptive and loose stop when any adjacency is Up.
// Invalid modes return nullopt; output owns no memory or state.
[[nodiscard]] std::optional<bool> lan_hello_padding(HelloPadding, bool any_up) noexcept;
}
