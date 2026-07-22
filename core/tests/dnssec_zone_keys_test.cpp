// Zone-key owner tests cover stable identities, lifecycle filtering, encrypted
// checkpoint round trips and authenticated rejection of edited metadata.

#include "router/dnssec_zone_keys.hpp"

#include <array>
#include <stdexcept>

void dnssec_zone_keys_tests() {
  using namespace router::dnssec;

  const KeySchedule schedule{.publish_at = 100U,
                             .ready_at = 150U,
                             .activate_at = 200U,
                             .retire_at = 400U,
                             .dead_at = 500U,
                             .remove_at = 600U};
  auto managed = ManagedKey::create(KeyRole::zone_signing, schedule,
                                    generate_signing_key(15U));
  if (!managed)
    throw std::runtime_error("zone key store fixture key failed");
  ZoneKeyStore store;
  const auto [mutation, id] = store.add(std::move(*managed));
  if (mutation != ZoneKeyMutation::applied || id == 0U ||
      store.active(KeyRole::zone_signing, 199U).size() != 0U ||
      store.active(KeyRole::zone_signing, 200U).size() != 1U)
    throw std::runtime_error("zone key store lifecycle filtering failed");

  const auto zone = router::packet::dns::name_from_text("example.");
  const auto published =
      zone ? store.published_dnskeys(*zone, 3600U, 300U) : std::nullopt;
  if (!published || published->size() != 1U)
    throw std::runtime_error("zone key store did not publish DNSKEY");

  std::array<std::uint8_t, 32U> wrapping_key{};
  wrapping_key.fill(0x6dU);
  const std::array<std::uint8_t, 7U> context{'p', 'r', 'o', 'j', 'e', 'c', 't'};
  const auto checkpoint = store.checkpoint(wrapping_key, context);
  const auto restored =
      checkpoint ? ZoneKeyStore::restore(*checkpoint, wrapping_key, context)
                 : std::nullopt;
  if (!restored || restored->active(KeyRole::zone_signing, 300U).size() != 1U)
    throw std::runtime_error("zone key store checkpoint did not restore");

  // A signer wakeup is required only when published() or signs() can change.
  // ready_at=150 and dead_at=500 are deliberately absent from the expected
  // sequence because they do not alter emitted DNSKEY or RRSIG material.
  if (store.next_signing_material_transition(99U) != 100U ||
      store.next_signing_material_transition(100U) != 200U ||
      store.next_signing_material_transition(200U) != 400U ||
      store.next_signing_material_transition(400U) != 600U ||
      store.next_signing_material_transition(600U))
    throw std::runtime_error("zone key material transition projection failed");

  auto edited = *checkpoint;
  edited.keys.front().schedule.activate_at += 1U;
  if (ZoneKeyStore::restore(edited, wrapping_key, context))
    throw std::runtime_error(
        "zone key store accepted edited lifecycle metadata");
  if (store.remove(id) != ZoneKeyMutation::applied ||
      store.remove(id) != ZoneKeyMutation::not_found)
    throw std::runtime_error("zone key store removal result is wrong");
}
