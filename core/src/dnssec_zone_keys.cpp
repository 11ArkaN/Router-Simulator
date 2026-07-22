// DNSSEC zone key ownership and encrypted checkpoint binding. Lifecycle
// metadata is authenticated alongside the sealed provider key, preventing a
// checkpoint editor from changing a ZSK into a KSK or altering activation time.
// Source: ietf.dnssec.key_timing.rfc7583
// Source: nist.project_key_vault.aes_gcm

#include "router/dnssec_zone_keys.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::dnssec {
namespace {

void append_u64(std::vector<std::uint8_t> &bytes, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    bytes.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::vector<std::uint8_t> binding(std::span<const std::uint8_t> context,
                                  const ZoneKeyCheckpoint &key) {
  std::vector<std::uint8_t> bytes{context.begin(), context.end()};
  bytes.reserve(bytes.size() + 8U * 7U + 2U);
  append_u64(bytes, key.id);
  bytes.push_back(static_cast<std::uint8_t>(key.role));
  bytes.push_back(key.algorithm);
  append_u64(bytes, key.schedule.publish_at);
  append_u64(bytes, key.schedule.ready_at);
  append_u64(bytes, key.schedule.activate_at);
  append_u64(bytes, key.schedule.retire_at);
  append_u64(bytes, key.schedule.dead_at);
  append_u64(bytes, key.schedule.remove_at);
  return bytes;
}

bool has_entropy(std::span<const std::uint8_t> key) noexcept {
  return key.size() == 32U &&
         std::ranges::any_of(key, [](const auto byte) { return byte != 0U; });
}

bool same_public_key(const ManagedKey &left, const ManagedKey &right) noexcept {
  return left.key().algorithm() == right.key().algorithm() &&
         std::ranges::equal(left.key().public_key(), right.key().public_key());
}

} // namespace

std::pair<ZoneKeyMutation, std::uint64_t>
ZoneKeyStore::add(ManagedKey key) noexcept {
  if (key.key().public_key().empty())
    return {ZoneKeyMutation::invalid_key, 0U};
  if (std::ranges::any_of(keys_, [&](const auto &existing) {
        return same_public_key(existing.key, key);
      }))
    return {ZoneKeyMutation::duplicate, 0U};
  try {
    keys_.reserve(keys_.size() + 1U);
    auto id = next_id_++;
    if (id == 0U) {
      // Wrap cannot silently reuse an identity because it is part of AEAD AAD.
      // Search is linear only on the practically unreachable wrap path.
      id = 1U;
      while (std::ranges::any_of(
          keys_, [&](const auto &entry) { return entry.id == id; }))
        ++id;
      next_id_ = id + 1U;
    }
    keys_.push_back({.id = id, .key = std::move(key)});
    return {ZoneKeyMutation::applied, id};
  } catch (...) {
    return {ZoneKeyMutation::resource_exhausted, 0U};
  }
}

ZoneKeyMutation ZoneKeyStore::remove(std::uint64_t id) noexcept {
  const auto found = std::ranges::find(keys_, id, &Entry::id);
  if (found == keys_.end())
    return ZoneKeyMutation::not_found;
  keys_.erase(found);
  return ZoneKeyMutation::applied;
}

std::vector<const ManagedKey *> ZoneKeyStore::active(KeyRole role,
                                                     std::uint64_t now) const {
  std::vector<const ManagedKey *> result;
  result.reserve(keys_.size());
  for (const auto &entry : keys_)
    if (entry.key.role() == role && entry.key.signs(now))
      result.push_back(&entry.key);
  return result;
}

std::optional<std::vector<dns::ZoneRecord>>
ZoneKeyStore::published_dnskeys(const packet::dns::Name &zone,
                                std::uint32_t ttl,
                                std::uint64_t now) const noexcept {
  try {
    std::vector<dns::ZoneRecord> result;
    result.reserve(keys_.size());
    for (const auto &entry : keys_) {
      if (!entry.key.published(now))
        continue;
      const auto record =
          make_dnskey_record(zone, ttl, entry.key.key(), entry.key.role());
      if (!record)
        return std::nullopt;
      result.push_back(*record);
    }
    return result;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::uint64_t> ZoneKeyStore::next_signing_material_transition(
    std::uint64_t now) const noexcept {
  std::optional<std::uint64_t> earliest;
  for (const auto &entry : keys_) {
    const auto &schedule = entry.key.schedule();
    // These four boundaries are the complete set observed by published() and
    // signs(). Keeping the selection next to those predicates makes it much
    // harder to add a lifecycle state later without also updating wakeups.
    const std::array material_boundaries{
        schedule.publish_at, schedule.activate_at, schedule.retire_at,
        schedule.remove_at};
    for (const auto boundary : material_boundaries)
      if (boundary > now && (!earliest || boundary < *earliest))
        earliest = boundary;
  }
  return earliest;
}

std::optional<ZoneKeyStoreCheckpoint> ZoneKeyStore::checkpoint(
    std::span<const std::uint8_t> wrapping_key,
    std::span<const std::uint8_t> vault_context) const noexcept {
  if (!has_entropy(wrapping_key))
    return std::nullopt;
  try {
    ZoneKeyStoreCheckpoint state{.next_id = next_id_, .keys = {}};
    state.keys.reserve(keys_.size());
    for (const auto &entry : keys_) {
      ZoneKeyCheckpoint saved{
          .id = entry.id,
          .role = entry.key.role(),
          .schedule = entry.key.schedule(),
          .algorithm = entry.key.key().algorithm(),
          .public_key = {entry.key.key().public_key().begin(),
                         entry.key.key().public_key().end()},
          .sealed_private_key = {}};
      const auto aad = binding(vault_context, saved);
      if (!entry.key.key().seal(wrapping_key, aad, saved.sealed_private_key))
        return std::nullopt;
      state.keys.push_back(std::move(saved));
    }
    return state;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<ZoneKeyStore>
ZoneKeyStore::restore(const ZoneKeyStoreCheckpoint &state,
                      std::span<const std::uint8_t> wrapping_key,
                      std::span<const std::uint8_t> vault_context) noexcept {
  if (!has_entropy(wrapping_key) || state.next_id == 0U)
    return std::nullopt;
  try {
    ZoneKeyStore candidate;
    candidate.next_id_ = state.next_id;
    candidate.keys_.reserve(state.keys.size());
    for (const auto &saved : state.keys) {
      if (saved.id == 0U || !valid_schedule(saved.schedule) ||
          saved.public_key.empty() || saved.sealed_private_key.empty() ||
          std::ranges::any_of(candidate.keys_, [&](const auto &existing) {
            return existing.id == saved.id;
          }))
        return std::nullopt;
      const auto aad = binding(vault_context, saved);
      auto key =
          unseal_signing_key(saved.sealed_private_key, wrapping_key, aad);
      if (!key || key->algorithm() != saved.algorithm ||
          !std::ranges::equal(key->public_key(), saved.public_key))
        return std::nullopt;
      auto managed =
          ManagedKey::create(saved.role, saved.schedule, std::move(key));
      if (!managed)
        return std::nullopt;
      candidate.keys_.push_back({.id = saved.id, .key = std::move(*managed)});
    }
    return candidate;
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace router::dnssec
