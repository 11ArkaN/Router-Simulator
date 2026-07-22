// Signed-zone owner tests cover RFC 6781 visit and refresh timing, key
// lifecycle wakeups, transactional signing failure and encrypted restore.

#include "router/dnssec_signed_zone_owner.hpp"

#include "router/dnssec_record.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

router::packet::dns::Name owner_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("signed-zone owner fixture name is malformed");
  return *parsed;
}

std::vector<std::uint8_t> owner_name_wire(const char *text) {
  const auto value = owner_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

std::vector<router::dns::ZoneRecord> owner_records() {
  const auto origin = owner_name("example.");
  std::vector<std::uint8_t> soa = owner_name_wire("ns.example.");
  const auto mailbox = owner_name_wire("hostmaster.example.");
  soa.insert(soa.end(), mailbox.begin(), mailbox.end());
  soa.resize(soa.size() + 20U, 0U);
  return {{.owner = origin,
           .type = router::packet::dns::type_soa,
           .record_class = router::packet::dns::internet_class,
           .ttl = 300U,
           .rdata = std::move(soa)},
          {.owner = origin,
           .type = router::packet::dns::type_ns,
           .record_class = router::packet::dns::internet_class,
           .ttl = 300U,
           .rdata = owner_name_wire("ns.example.")},
          {.owner = owner_name("www.example."),
           .type = router::packet::dns::type_aaaa,
           .record_class = router::packet::dns::internet_class,
           .ttl = 60U,
           .rdata = std::vector<std::uint8_t>(16U, 0x20U)}};
}

router::dnssec::ZoneKeyStore
owner_keys(std::uint64_t retire_at = 3000U,
           std::optional<std::uint64_t> second_zsk_activation = std::nullopt) {
  using namespace router::dnssec;
  const KeySchedule active{.publish_at = 900U,
                           .ready_at = 900U,
                           .activate_at = 900U,
                           .retire_at = retire_at,
                           .dead_at = retire_at + 100U,
                           .remove_at = retire_at + 200U};
  ZoneKeyStore keys;
  auto ksk = ManagedKey::create(KeyRole::key_signing, active,
                                generate_signing_key(15U));
  auto zsk = ManagedKey::create(KeyRole::zone_signing, active,
                                generate_signing_key(15U));
  if (!ksk || !zsk ||
      keys.add(std::move(*ksk)).first != ZoneKeyMutation::applied ||
      keys.add(std::move(*zsk)).first != ZoneKeyMutation::applied)
    throw std::runtime_error("signed-zone owner fixture keys failed");
  if (second_zsk_activation) {
    const auto transition = *second_zsk_activation;
    const KeySchedule rollover{.publish_at = transition,
                               .ready_at = transition,
                               .activate_at = transition,
                               .retire_at = retire_at + 500U,
                               .dead_at = retire_at + 600U,
                               .remove_at = retire_at + 700U};
    auto replacement = ManagedKey::create(KeyRole::zone_signing, rollover,
                                          generate_signing_key(15U));
    if (!replacement ||
        keys.add(std::move(*replacement)).first != ZoneKeyMutation::applied)
      throw std::runtime_error("signed-zone rollover fixture key failed");
  }
  return keys;
}

std::size_t
covered_aaaa_signatures(std::span<const router::dns::ZoneRecord> records) {
  return static_cast<std::size_t>(
      std::ranges::count_if(records, [](const auto &record) {
        const auto signature = record.type == router::packet::dns::type_rrsig
                                   ? router::dnssec::decode_rrsig(record.rdata)
                                   : std::nullopt;
        return signature &&
               signature->type_covered == router::packet::dns::type_aaaa;
      }));
}

bool same_records(std::span<const router::dns::ZoneRecord> left,
                  std::span<const router::dns::ZoneRecord> right) {
  return left.size() == right.size() &&
         std::ranges::equal(left, right, [](const auto &a, const auto &b) {
           return router::packet::dns::equal_case_insensitive(a.owner,
                                                              b.owner) &&
                  a.type == b.type && a.record_class == b.record_class &&
                  a.ttl == b.ttl && a.rdata == b.rdata;
         });
}

} // namespace

void dnssec_signed_zone_owner_tests() {
  using namespace router::dnssec;
  using Clock = SignedZoneOwner::Clock;
  const ManagedZoneSigningPolicy policy{
      .dnskey_ttl = 300U,
      .denial_ttl = 60U,
      .denial_mode = DenialMode::nsec,
      .timing = {.validity_seconds = 1000U,
                 .refresh_seconds = 300U,
                 .resign_seconds = 100U,
                 .inception_offset_seconds = 5U}};
  if (!valid_managed_zone_policy(policy))
    throw std::runtime_error("valid signed-zone timing policy was rejected");
  auto invalid = policy;
  invalid.timing.resign_seconds = invalid.timing.refresh_seconds;
  if (valid_managed_zone_policy(invalid))
    throw std::runtime_error("non-strict DNSSEC re-sign period was accepted");

  const auto start = Clock::time_point{} + std::chrono::seconds{10};
  auto owner =
      SignedZoneOwner::create(owner_name("example."), owner_records(),
                              owner_keys(3000U, 1020U), policy, 1000U, start);
  if (!owner || owner->statistics().generation != 1U ||
      covered_aaaa_signatures(owner->records()) != 1U ||
      owner->next_deadline() != start + std::chrono::seconds{20})
    throw std::runtime_error("initial signed-zone generation or wakeup failed");

  if (owner->poll(1019U, start + std::chrono::seconds{19}) !=
          SignedZoneRefreshResult::not_due ||
      owner->poll(1020U, start + std::chrono::seconds{20}) !=
          SignedZoneRefreshResult::generation_replaced ||
      owner->statistics().generation != 2U ||
      covered_aaaa_signatures(owner->records()) != 2U)
    throw std::runtime_error(
        "DNSSEC key activation did not replace generation");

  if (owner->poll(1120U, start + std::chrono::seconds{120}) !=
          SignedZoneRefreshResult::visited_without_change ||
      owner->poll(1720U, start + std::chrono::seconds{220}) !=
          SignedZoneRefreshResult::generation_replaced ||
      owner->statistics().signature_expiration_wall_seconds != 2720U)
    throw std::runtime_error("DNSSEC refresh-period maintenance is wrong");

  // Retirement leaves no active ZSK. The old signed generation must remain
  // byte-for-byte intact while the failed attempt and bounded retry are
  // reported, rather than publishing a partially signed zone.
  auto failing =
      SignedZoneOwner::create(owner_name("example."), owner_records(),
                              owner_keys(1020U), policy, 1000U, start);
  if (!failing)
    throw std::runtime_error("signed-zone failure fixture was not created");
  const auto previous = failing->records();
  if (failing->poll(1020U, start + std::chrono::seconds{20}) !=
          SignedZoneRefreshResult::signing_failed ||
      !same_records(failing->records(), previous) ||
      failing->statistics().failed_refreshes != 1U ||
      failing->next_deadline() != start + std::chrono::seconds{120})
    throw std::runtime_error("failed DNSSEC refresh changed live generation");

  std::array<std::uint8_t, 32U> wrapping_key{};
  wrapping_key.fill(0x71U);
  const std::array<std::uint8_t, 12U> context{'p', 'r', 'o', 'j', 'e', 'c',
                                              't', '/', 'z', 'o', 'n', 'e'};
  const auto saved = owner->checkpoint(wrapping_key, context,
                                       start + std::chrono::seconds{221});
  auto restored =
      saved ? SignedZoneOwner::restore(*saved, wrapping_key, context, 1721U,
                                       start + std::chrono::seconds{500})
            : std::nullopt;
  if (!restored ||
      restored->statistics().generation !=
          owner->statistics().generation + 1U ||
      restored->statistics().last_success_wall_seconds != 1721U ||
      covered_aaaa_signatures(restored->records()) != 2U)
    throw std::runtime_error("signed-zone encrypted restore failed");

  auto edited = *saved;
  edited.policy.timing.resign_seconds = edited.policy.timing.refresh_seconds;
  if (SignedZoneOwner::restore(edited, wrapping_key, context, 1721U, start))
    throw std::runtime_error("signed-zone restore accepted invalid timing");
}
