// Whole-laboratory checkpoint ABI 6. The codec serializes only explicit value
// fields in little-endian order. Runtime pointers, padding, pthread identities
// and steady-clock epochs never cross this boundary.

#pragma once

#include "router/runtime_supervisor.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace router::lab::checkpoint_v6 {

inline constexpr std::uint32_t abi = 6;
inline constexpr std::uint64_t schema_hash =
    device_catalog::checkpoint_schema_hash;

[[nodiscard]] std::vector<std::uint8_t>
encode(const RuntimeSupervisorCheckpoint &state);
[[nodiscard]] std::unique_ptr<RuntimeSupervisorCheckpoint>
decode(std::span<const std::uint8_t> bytes);

} // namespace router::lab::checkpoint_v6
