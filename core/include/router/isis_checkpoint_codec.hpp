// Protected IS-IS checkpoint encoding belongs to the persistence coordinator.
// Only explicit owned values cross the versioned binary boundary. The codec
// depends on protocol transfer contracts and the project vault, never live shards.

#pragma once

#include "router/isis_runtime_checkpoint.hpp"
#include "router/secret_vault.hpp"

namespace router::lab::isis_checkpoint {
// Caller holds a detached joined image. Binding is the 32-byte SHA-256 of the
// enclosing structural checkpoint prefix. All integer fields and counts use
// little-endian 64-bit values; booleans use one canonical octet and byte arrays
// retain their exact octets. No size_t representation, padding or pointer leaks.
// Refusal returns nullopt and changes neither the input nor vault. Temporary
// serialized plaintext is cleansed before return. Payload uses the initial Wasm
// memory bound, independently of the stable credential record capacity.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> encode(const IsisRuntimeCheckpoint &state,
    const vault::SecretVault &vault, std::span<const std::uint8_t> binding) noexcept;
// Authentication precedes parsing and allocation of decoded records. Lengths
// consume a cumulative allocation budget before reserve; narrow integers,
// noncanonical booleans, unknown variants, trailing bytes and transport mismatch
// refuse. Child owner preparation must still validate protocol state and policy
// before publication. A returned value owns every byte and retains no vault lease.
[[nodiscard]] std::unique_ptr<IsisRuntimeCheckpoint> decode(std::span<const std::uint8_t> sealed,
    const vault::SecretVault &vault, std::span<const std::uint8_t> binding) noexcept;
} // namespace router::lab::isis_checkpoint
