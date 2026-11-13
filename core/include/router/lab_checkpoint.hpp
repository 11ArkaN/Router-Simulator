// Whole-laboratory checkpoint ABI 17. The codec serializes only explicit value
// fields in little-endian order. Runtime pointers, padding, pthread identities
// and steady-clock epochs never cross this boundary.

#pragma once

#include "router/runtime_supervisor.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace router::lab::checkpoint_v17 {

inline constexpr std::uint32_t abi = profile::checkpoint_abi;
static_assert(abi == 17U, "Checkpoint codec and selected profile ABI must agree");
inline constexpr std::uint64_t schema_hash =
    device_catalog::checkpoint_schema_hash;

[[nodiscard]] std::vector<std::uint8_t>
encode(const RuntimeSupervisorCheckpoint &state, const vault::SecretVault *protector = nullptr);
[[nodiscard]] std::unique_ptr<RuntimeSupervisorCheckpoint>
decode(std::span<const std::uint8_t> bytes, const vault::SecretVault *protector = nullptr);

} // namespace router::lab::checkpoint_v17
