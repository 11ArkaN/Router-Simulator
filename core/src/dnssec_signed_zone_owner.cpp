// RFC 6781 signed-zone maintenance. Absolute Unix seconds are used only for
// RRSIG inception and expiration, while steady_clock owns wakeups. This split
// prevents host clock corrections from changing packet or timer progression.
// Source: ietf.dnssec.records.rfc4034
// Source: ietf.dnssec.operations.rfc6781

#include "router/dnssec_signed_zone_owner.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::dnssec {
namespace {

constexpr std::uint64_t serial_half_range = std::uint64_t{1U} << 31U;

SignedZoneOwner::Clock::time_point
deadline_after(SignedZoneOwner::Clock::time_point now,
               std::uint64_t seconds) noexcept {
  const auto delay =
      std::chrono::duration_cast<SignedZoneOwner::Clock::duration>(
          std::chrono::seconds{seconds});
  if (SignedZoneOwner::Clock::time_point::max() - now < delay)
    return SignedZoneOwner::Clock::time_point::max();
  return now + delay;
}

std::int64_t
remaining_nanoseconds(SignedZoneOwner::Clock::time_point deadline,
                      SignedZoneOwner::Clock::time_point now) noexcept {
  if (deadline <= now)
    return 0;
  return std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
      .count();
}

std::vector<std::uint8_t> zone_vault_context(std::span<const std::uint8_t> base,
                                             const packet::dns::Name &origin) {
  // The canonical wire name, including its root label, prevents a sealed key
  // checkpoint copied between two zones in one project from authenticating
  // under the destination owner. The prefix separates this domain from other
  // users that may append their own data to the same project context.
  constexpr std::array<std::uint8_t, 5U> domain{'d', 'n', 's', 's', 'z'};
  std::vector<std::uint8_t> result;
  result.reserve(base.size() + domain.size() + origin.octets);
  result.insert(result.end(), base.begin(), base.end());
  result.insert(result.end(), domain.begin(), domain.end());
  result.insert(result.end(), origin.wire.begin(),
                origin.wire.begin() + origin.octets);
  return result;
}

} // namespace

bool valid_signature_refresh_policy(
    const SignatureRefreshPolicy &policy) noexcept {
  // RFC 6781 section 4.4.2 requires Re-Sign Period < Refresh Period. Keeping
  // the complete inception-to-expiration span below the RFC 1982 half-range
  // makes every RRSIG time comparison unambiguous across uint32 wraparound.
  return policy.validity_seconds != 0U && policy.refresh_seconds != 0U &&
         policy.resign_seconds != 0U &&
         policy.resign_seconds < policy.refresh_seconds &&
         policy.refresh_seconds < policy.validity_seconds &&
         static_cast<std::uint64_t>(policy.validity_seconds) +
                 policy.inception_offset_seconds <
             serial_half_range;
}

bool valid_managed_zone_policy(
    const ManagedZoneSigningPolicy &policy) noexcept {
  return policy.dnskey_ttl != 0U && policy.denial_ttl != 0U &&
         policy.denial_mode <= DenialMode::nsec3_opt_out &&
         valid_signature_refresh_policy(policy.timing);
}

SignedZoneOwner::SignedZoneOwner(packet::dns::Name origin,
                                 std::vector<dns::ZoneRecord> unsigned_records,
                                 ZoneKeyStore keys,
                                 ManagedZoneSigningPolicy policy) noexcept
    : served_zone_(std::move(origin)),
      unsigned_records_(std::move(unsigned_records)), keys_(std::move(keys)),
      policy_(policy) {}

std::optional<SignedZoneOwner> SignedZoneOwner::create(
    packet::dns::Name origin, std::vector<dns::ZoneRecord> unsigned_records,
    ZoneKeyStore keys, const ManagedZoneSigningPolicy &policy,
    std::uint64_t wall_now, Clock::time_point steady_now,
    const DigestCalculator *digests) noexcept {
  if (!valid_managed_zone_policy(policy) || unsigned_records.empty() ||
      wall_now < policy.timing.inception_offset_seconds ||
      wall_now > std::numeric_limits<std::uint64_t>::max() -
                     policy.timing.validity_seconds)
    return std::nullopt;
  try {
    SignedZoneOwner candidate{std::move(origin), std::move(unsigned_records),
                              std::move(keys), policy};
    auto signed_records = candidate.sign_generation(candidate.unsigned_records_,
                                                    wall_now, digests);
    if (!signed_records)
      return std::nullopt;
    if (!candidate.publish(std::move(*signed_records), wall_now))
      return std::nullopt;
    candidate.schedule_next_visit(steady_now, wall_now);
    return candidate;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::vector<dns::ZoneRecord>> SignedZoneOwner::sign_generation(
    std::span<const dns::ZoneRecord> records, std::uint64_t wall_now,
    const DigestCalculator *digests) const noexcept {
  if (wall_now < policy_.timing.inception_offset_seconds ||
      wall_now > std::numeric_limits<std::uint64_t>::max() -
                     policy_.timing.validity_seconds)
    return std::nullopt;
  // RFC 4034 encodes these absolute fields modulo 2^32. Policy validation
  // keeps their separation below 2^31, which is the RFC 1982 comparison limit.
  const auto inception = static_cast<std::uint32_t>(
      wall_now - policy_.timing.inception_offset_seconds);
  const auto expiration =
      static_cast<std::uint32_t>(wall_now + policy_.timing.validity_seconds);
  return sign_zone_snapshot(served_zone_.origin(), records, keys_, wall_now,
                            {.dnskey_ttl = policy_.dnskey_ttl,
                             .denial_ttl = policy_.denial_ttl,
                             .signature_inception = inception,
                             .signature_expiration = expiration,
                             .denial_mode = policy_.denial_mode},
                            digests);
}

bool SignedZoneOwner::key_material_changed(
    std::uint64_t wall_now) const noexcept {
  const auto transition = keys_.next_signing_material_transition(
      statistics_.last_success_wall_seconds);
  return transition && *transition <= wall_now;
}

void SignedZoneOwner::schedule_next_visit(Clock::time_point steady_now,
                                          std::uint64_t wall_now) noexcept {
  std::uint64_t delay = policy_.timing.resign_seconds;
  if (const auto transition = keys_.next_signing_material_transition(wall_now))
    delay = std::min(delay, *transition - wall_now);
  next_visit_ = deadline_after(steady_now, delay);
}

bool SignedZoneOwner::publish(std::vector<dns::ZoneRecord> records,
                              std::uint64_t wall_now) noexcept {
  if (!served_zone_.replace(std::move(records)))
    return false;
  if (statistics_.generation != std::numeric_limits<std::uint64_t>::max())
    ++statistics_.generation;
  if (statistics_.successful_refreshes !=
      std::numeric_limits<std::uint64_t>::max())
    ++statistics_.successful_refreshes;
  statistics_.last_success_wall_seconds = wall_now;
  statistics_.signature_expiration_wall_seconds =
      wall_now + policy_.timing.validity_seconds;
  last_observed_wall_seconds_ = wall_now;
  return true;
}

SignedZoneRefreshResult
SignedZoneOwner::poll(std::uint64_t wall_now, Clock::time_point steady_now,
                      const DigestCalculator *digests) noexcept {
  if (steady_now < next_visit_)
    return SignedZoneRefreshResult::not_due;
  if (wall_now < last_observed_wall_seconds_) {
    // A backwards civil-clock step must never manufacture signatures whose
    // inception unexpectedly precedes the previously published generation.
    // Retaining the old generation is safer and the bounded visit loop retries.
    last_observed_wall_seconds_ = wall_now;
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::wall_clock_regressed;
  }
  last_observed_wall_seconds_ = wall_now;
  const auto remaining =
      statistics_.signature_expiration_wall_seconds > wall_now
          ? statistics_.signature_expiration_wall_seconds - wall_now
          : 0U;
  if (!key_material_changed(wall_now) &&
      remaining > policy_.timing.refresh_seconds) {
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::visited_without_change;
  }

  auto replacement = sign_generation(unsigned_records_, wall_now, digests);
  if (!replacement) {
    if (statistics_.failed_refreshes !=
        std::numeric_limits<std::uint64_t>::max())
      ++statistics_.failed_refreshes;
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::signing_failed;
  }
  if (!publish(std::move(*replacement), wall_now)) {
    if (statistics_.failed_refreshes !=
        std::numeric_limits<std::uint64_t>::max())
      ++statistics_.failed_refreshes;
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::signing_failed;
  }
  schedule_next_visit(steady_now, wall_now);
  return SignedZoneRefreshResult::generation_replaced;
}

SignedZoneRefreshResult SignedZoneOwner::replace_unsigned_records(
    std::vector<dns::ZoneRecord> records, std::uint64_t wall_now,
    Clock::time_point steady_now, const DigestCalculator *digests) noexcept {
  if (records.empty() || wall_now < last_observed_wall_seconds_)
    return wall_now < last_observed_wall_seconds_
               ? SignedZoneRefreshResult::wall_clock_regressed
               : SignedZoneRefreshResult::signing_failed;
  auto replacement = sign_generation(records, wall_now, digests);
  if (!replacement) {
    if (statistics_.failed_refreshes !=
        std::numeric_limits<std::uint64_t>::max())
      ++statistics_.failed_refreshes;
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::signing_failed;
  }
  if (!publish(std::move(*replacement), wall_now)) {
    if (statistics_.failed_refreshes !=
        std::numeric_limits<std::uint64_t>::max())
      ++statistics_.failed_refreshes;
    schedule_next_visit(steady_now, wall_now);
    return SignedZoneRefreshResult::signing_failed;
  }
  unsigned_records_ = std::move(records);
  schedule_next_visit(steady_now, wall_now);
  return SignedZoneRefreshResult::generation_replaced;
}

std::optional<SignedZoneOwnerCheckpoint>
SignedZoneOwner::checkpoint(std::span<const std::uint8_t> wrapping_key,
                            std::span<const std::uint8_t> vault_context,
                            Clock::time_point steady_now) const noexcept {
  try {
    const auto bound_context = zone_vault_context(vault_context, origin());
    auto key_state = keys_.checkpoint(wrapping_key, bound_context);
    if (!key_state)
      return std::nullopt;
    return SignedZoneOwnerCheckpoint{
        .origin = served_zone_.origin(),
        .unsigned_records = unsigned_records_,
        .keys = std::move(*key_state),
        .policy = policy_,
        .statistics = statistics_,
        .next_visit_remaining_nanoseconds =
            remaining_nanoseconds(next_visit_, steady_now)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<SignedZoneOwner>
SignedZoneOwner::restore(const SignedZoneOwnerCheckpoint &state,
                         std::span<const std::uint8_t> wrapping_key,
                         std::span<const std::uint8_t> vault_context,
                         std::uint64_t wall_now, Clock::time_point steady_now,
                         const DigestCalculator *digests) noexcept {
  if (!valid_managed_zone_policy(state.policy) ||
      state.unsigned_records.empty() || state.statistics.generation == 0U ||
      state.next_visit_remaining_nanoseconds < 0)
    return std::nullopt;
  std::vector<std::uint8_t> bound_context;
  try {
    bound_context = zone_vault_context(vault_context, state.origin);
  } catch (...) {
    return std::nullopt;
  }
  auto keys = ZoneKeyStore::restore(state.keys, wrapping_key, bound_context);
  if (!keys)
    return std::nullopt;
  auto candidate =
      create(state.origin, state.unsigned_records, std::move(*keys),
             state.policy, wall_now, steady_now, digests);
  if (!candidate)
    return std::nullopt;

  // Restore signs a fresh generation rather than trusting serialized RRSIG
  // bytes. Preserve monotonic counters, then account for this new successful
  // generation without allowing arithmetic wrap to reuse an old identity.
  candidate->statistics_.generation =
      state.statistics.generation == std::numeric_limits<std::uint64_t>::max()
          ? state.statistics.generation
          : state.statistics.generation + 1U;
  candidate->statistics_.successful_refreshes =
      state.statistics.successful_refreshes ==
              std::numeric_limits<std::uint64_t>::max()
          ? state.statistics.successful_refreshes
          : state.statistics.successful_refreshes + 1U;
  candidate->statistics_.failed_refreshes = state.statistics.failed_refreshes;

  const auto restored_delay =
      std::chrono::nanoseconds{state.next_visit_remaining_nanoseconds};
  const auto restored_deadline =
      Clock::time_point::max() - steady_now < restored_delay
          ? Clock::time_point::max()
          : steady_now + restored_delay;
  candidate->next_visit_ = std::min(candidate->next_visit_, restored_deadline);
  return candidate;
}

} // namespace router::dnssec
