// Stateful DNSSEC zone-key owner. One DNS service shard mutates this store.
// Private material remains inside ManagedKey providers and checkpoints contain
// only authenticated encrypted blobs plus public lifecycle metadata.

#pragma once

#include "router/dnssec_key_lifecycle.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

struct ZoneKeyCheckpoint {
  std::uint64_t id{};
  KeyRole role{KeyRole::zone_signing};
  KeySchedule schedule{};
  std::uint8_t algorithm{};
  std::vector<std::uint8_t> public_key;
  std::vector<std::uint8_t> sealed_private_key;
};

struct ZoneKeyStoreCheckpoint {
  std::uint64_t next_id{1U};
  std::vector<ZoneKeyCheckpoint> keys;
};

enum class ZoneKeyMutation : std::uint8_t {
  applied,
  duplicate,
  not_found,
  invalid_key,
  resource_exhausted
};

class ZoneKeyStore final {
public:
  // add assigns a stable non-zero identifier and consumes the key only after
  // duplicate checks and vector reservation succeed.
  [[nodiscard]] std::pair<ZoneKeyMutation, std::uint64_t>
  add(ManagedKey key) noexcept;
  [[nodiscard]] ZoneKeyMutation remove(std::uint64_t id) noexcept;

  [[nodiscard]] std::vector<const ManagedKey *> active(KeyRole role,
                                                       std::uint64_t now) const;
  [[nodiscard]] std::optional<std::vector<dns::ZoneRecord>>
  published_dnskeys(const packet::dns::Name &zone, std::uint32_t ttl,
                    std::uint64_t now) const noexcept;

  // Only publication, activation, retirement and removal alter the records
  // emitted by sign_zone_snapshot. ready_at and dead_at are operational key
  // states, but neither changes the DNSKEY RRset nor the set of signing keys.
  // The DNS service owner uses this projection to wake at the first material
  // transition without exposing mutable Entry storage or polling every key.
  [[nodiscard]] std::optional<std::uint64_t>
  next_signing_material_transition(std::uint64_t now) const noexcept;

  // vault_context should bind at least project and zone identity. Metadata is
  // appended internally so changing an ID, role, schedule or algorithm makes
  // decryption fail. An all-zero wrapping key is treated as absent entropy.
  [[nodiscard]] std::optional<ZoneKeyStoreCheckpoint>
  checkpoint(std::span<const std::uint8_t> wrapping_key,
             std::span<const std::uint8_t> vault_context) const noexcept;
  [[nodiscard]] static std::optional<ZoneKeyStore>
  restore(const ZoneKeyStoreCheckpoint &state,
          std::span<const std::uint8_t> wrapping_key,
          std::span<const std::uint8_t> vault_context) noexcept;

private:
  struct Entry {
    std::uint64_t id{};
    ManagedKey key;
  };

  std::vector<Entry> keys_;
  std::uint64_t next_id_{1U};
};

} // namespace router::dnssec
