// Cold basic LSP option rendering belongs to the serialized CLI owner.
// Input bytes are caller-owned, non-secret TLVs; no protocol owner is retained.
#pragma once
#include <optional>
#include <span>
#include <string>
#include <cstdint>
namespace router::isis { struct HostnameOperational; }
namespace router::lab::isis_cli {
// Input must exclude authentication values before crossing the owner boundary.
// Returns owned text for supported, well-formed basic options. Malformed or
// unsupported content refuses the whole projection. Allocation may throw.
// Names, when supplied, must be a sorted unique validated protocol catalog.
[[nodiscard]] std::optional<std::string> basic_lsp_options(std::span<const std::uint8_t>,
    std::span<const isis::HostnameOperational> names={});
}
