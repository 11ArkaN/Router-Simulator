// Live DNSSEC signed-zone owner. One DNS service shard owns unsigned input,
// private-key lifecycle, the currently published immutable record generation
// and its monotonic visit deadline. The owner never sends DNS packets and it
// exposes records only by const reference to the authoritative DNS service.

#pragma once

#include "router/dnssec_signed_zone.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

// RFC 6781 sections 4.4.1 and 4.4.2 distinguish the signature validity,
// refresh and re-sign periods. All durations are explicit operator policy.
// There are deliberately no defaults because zone TTLs and operational
// recovery objectives determine safe values.
struct SignatureRefreshPolicy {
  std::uint32_t validity_seconds{};
  std::uint32_t refresh_seconds{};
  std::uint32_t resign_seconds{};
  std::uint32_t inception_offset_seconds{};
};

struct ManagedZoneSigningPolicy {
  std::uint32_t dnskey_ttl{};
  std::uint32_t denial_ttl{};
  DenialMode denial_mode{DenialMode::nsec};
  SignatureRefreshPolicy timing{};
};

[[nodiscard]] bool
valid_signature_refresh_policy(const SignatureRefreshPolicy &policy) noexcept;
[[nodiscard]] bool
valid_managed_zone_policy(const ManagedZoneSigningPolicy &policy) noexcept;

enum class SignedZoneRefreshResult : std::uint8_t {
  not_due,
  visited_without_change,
  generation_replaced,
  signing_failed,
  wall_clock_regressed
};

struct SignedZoneStatistics {
  std::uint64_t generation{};
  std::uint64_t successful_refreshes{};
  std::uint64_t failed_refreshes{};
  std::uint64_t last_success_wall_seconds{};
  std::uint64_t signature_expiration_wall_seconds{};
};

struct SignedZoneOwnerCheckpoint {
  packet::dns::Name origin;
  std::vector<dns::ZoneRecord> unsigned_records;
  ZoneKeyStoreCheckpoint keys;
  ManagedZoneSigningPolicy policy{};
  SignedZoneStatistics statistics{};
  std::int64_t next_visit_remaining_nanoseconds{};
};

class SignedZoneOwner final {
public:
  using Clock = std::chrono::steady_clock;

  // create consumes the key store and publishes a generation only after every
  // RRset, denial record and active rollover key has been signed. wall_now is
  // Unix time for RRSIG fields; steady_now controls only the local wakeup.
  [[nodiscard]] static std::optional<SignedZoneOwner>
  create(packet::dns::Name origin,
         std::vector<dns::ZoneRecord> unsigned_records, ZoneKeyStore keys,
         const ManagedZoneSigningPolicy &policy, std::uint64_t wall_now,
         Clock::time_point steady_now = Clock::now(),
         const DigestCalculator *digests = nullptr) noexcept;

  SignedZoneOwner(SignedZoneOwner &&) noexcept = default;
  SignedZoneOwner &operator=(SignedZoneOwner &&) noexcept = default;
  SignedZoneOwner(const SignedZoneOwner &) = delete;
  SignedZoneOwner &operator=(const SignedZoneOwner &) = delete;

  // poll performs at most one complete signing attempt. Failure retains the
  // previous generation and schedules the next bounded retry, preventing a
  // bad key transition or provider failure from creating a busy loop.
  [[nodiscard]] SignedZoneRefreshResult
  poll(std::uint64_t wall_now, Clock::time_point steady_now = Clock::now(),
       const DigestCalculator *digests = nullptr) noexcept;

  // A source-zone edit is transactional. New data becomes visible only when
  // a complete signed generation can replace the old one atomically.
  [[nodiscard]] SignedZoneRefreshResult
  replace_unsigned_records(std::vector<dns::ZoneRecord> records,
                           std::uint64_t wall_now,
                           Clock::time_point steady_now = Clock::now(),
                           const DigestCalculator *digests = nullptr) noexcept;

  [[nodiscard]] const packet::dns::Name &origin() const noexcept {
    return served_zone_.origin();
  }
  [[nodiscard]] const std::vector<dns::ZoneRecord> &records() const noexcept {
    return served_zone_.records();
  }
  [[nodiscard]] const dns::Zone &zone() const noexcept { return served_zone_; }
  [[nodiscard]] const SignedZoneStatistics &statistics() const noexcept {
    return statistics_;
  }
  [[nodiscard]] Clock::time_point next_deadline() const noexcept {
    return next_visit_;
  }

  // Private keys are sealed with caller-owned project entropy. Restore always
  // rebuilds and signs a fresh generation before returning, so edited or stale
  // generated DNSSEC records are never trusted from the checkpoint image.
  [[nodiscard]] std::optional<SignedZoneOwnerCheckpoint>
  checkpoint(std::span<const std::uint8_t> wrapping_key,
             std::span<const std::uint8_t> vault_context,
             Clock::time_point steady_now = Clock::now()) const noexcept;
  [[nodiscard]] static std::optional<SignedZoneOwner>
  restore(const SignedZoneOwnerCheckpoint &state,
          std::span<const std::uint8_t> wrapping_key,
          std::span<const std::uint8_t> vault_context, std::uint64_t wall_now,
          Clock::time_point steady_now = Clock::now(),
          const DigestCalculator *digests = nullptr) noexcept;

private:
  SignedZoneOwner(packet::dns::Name origin,
                  std::vector<dns::ZoneRecord> unsigned_records,
                  ZoneKeyStore keys, ManagedZoneSigningPolicy policy) noexcept;

  [[nodiscard]] std::optional<std::vector<dns::ZoneRecord>>
  sign_generation(std::span<const dns::ZoneRecord> records,
                  std::uint64_t wall_now,
                  const DigestCalculator *digests) const noexcept;
  [[nodiscard]] bool
  key_material_changed(std::uint64_t wall_now) const noexcept;
  void schedule_next_visit(Clock::time_point steady_now,
                           std::uint64_t wall_now) noexcept;
  [[nodiscard]] bool publish(std::vector<dns::ZoneRecord> records,
                             std::uint64_t wall_now) noexcept;

  // Zone is the serving generation itself. Keeping lookup storage in the
  // owner removes a second copy and makes signed generation replacement and
  // authoritative visibility the same transaction.
  dns::Zone served_zone_;
  std::vector<dns::ZoneRecord> unsigned_records_;
  ZoneKeyStore keys_;
  ManagedZoneSigningPolicy policy_{};
  SignedZoneStatistics statistics_{};
  std::uint64_t last_observed_wall_seconds_{};
  Clock::time_point next_visit_{};
};

} // namespace router::dnssec
