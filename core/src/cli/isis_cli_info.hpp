// Read-only IS-IS CLI projection. The session owner supplies canonical intent;
// this module owns formatting only and cannot change a datastore or protocol.
#pragma once
#include "router/isis_configuration.hpp"
#include <span>
namespace router::lab::isis_cli {
// Validated intent only. Returned MD tree owns its storage. Caller selects the
// present working context and applies the separately sourced classic spelling.
[[nodiscard]] std::string md_tree(const isis::RouterConfiguration &, bool detail);
// Validated running/candidate intent, on the serialized session owner. The
// returned hierarchical delta owns all bytes and includes changed keyed paths,
// scalar before/after values and leaf-list additions/removals. No mutation or
// inferred default values; an equal semantic tree returns an empty string.
[[nodiscard]] std::string md_compare(const isis::RouterConfiguration &running,
    const isis::RouterConfiguration &candidate);
struct ClassicTimerBlock { std::string command; std::size_t lines{}; };
// Canonical MD timer body, excluding its opening line. Converts one complete
// direct-child block to the documented compound classic command. The result
// owns text and counts consumed lines including the closing brace. Invalid
// group, framing, duplicate leaf or number refuses without consuming input.
// Formatting may allocate; caller and input share serialized session affinity.
[[nodiscard]] std::optional<ClassicTimerBlock> classic_timer_block(std::string_view group,
    std::span<const std::string> body);
// Source-bound leaf rewrite inside an IS-IS context. Containers remain owned
// by the shared CLI renderer. Unknown leaves retain their original spelling.
[[nodiscard]] std::string classic_leaf(std::string_view);
}
