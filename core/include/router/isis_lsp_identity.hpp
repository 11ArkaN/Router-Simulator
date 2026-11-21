// Operational LSP identities use the pinned YANG hexadecimal spelling. This
// pure conversion owns no protocol state and depends only on wire value types.
#pragma once
#include "router/isis_packet.hpp"
#include <optional>
#include <string>
#include <string_view>
namespace router::isis {
// Any fixed-width ID is representable, including the YANG zero default. The
// returned string belongs to the caller; allocation failure may propagate.
[[nodiscard]] std::string format_lsp_id(const packet::isis::LspId &);
// Exact XXXX.XXXX.XXXX.XX-XX spelling, case-insensitive hexadecimal. Failure
// retains no input view and changes no state. No owner or shard is required.
[[nodiscard]] std::optional<packet::isis::LspId> parse_lsp_id(std::string_view) noexcept;
}
