// Deterministic SR OS keychain validity and rollover selection. Calendar text
// parsing belongs to CLI management; the protocol consumes normalized UTC
// seconds so DST and locale cannot alter a running adjacency.

#include "router/ospf_keychain.hpp"

#include <algorithm>
#include <limits>

namespace router::ospf {
namespace {

bool valid_for_send(const KeychainEntry &entry,
                    std::int64_t now) noexcept {
  // SR OS selects the newest key whose begin time has passed. OSPF is one of
  // the documented special consumers that continues using the last valid
  // key after all entries expire instead of reverting to unauthenticated
  // traffic. Therefore an end time does not disqualify the newest previously
  // active send key here.
  return entry.admin_enabled && entry.secret != 0U &&
         now >= entry.begin_utc_seconds;
}

std::int64_t saturating_subtract(std::int64_t value,
                                 std::uint32_t delta) noexcept {
  const auto minimum = std::numeric_limits<std::int64_t>::min();
  const auto signed_delta = static_cast<std::int64_t>(delta);
  return value < minimum + signed_delta ? minimum : value - signed_delta;
}

std::int64_t saturating_add(std::int64_t value,
                            std::uint32_t delta) noexcept {
  const auto maximum = std::numeric_limits<std::int64_t>::max();
  const auto signed_delta = static_cast<std::int64_t>(delta);
  return value > maximum - signed_delta ? maximum : value + signed_delta;
}

bool valid_for_receive(const KeychainConfiguration &keychain,
                       const KeychainEntry &entry,
                       std::int64_t now) noexcept {
  if (!entry.admin_enabled || entry.secret == 0U ||
      now < saturating_subtract(entry.begin_utc_seconds,
                                entry.tolerance_seconds))
    return false;
  std::optional<std::int64_t> replacement_begin;
  for (const auto &candidate : keychain.bidirectional) {
    if (!candidate.admin_enabled ||
        candidate.begin_utc_seconds <= entry.begin_utc_seconds)
      continue;
    if (!replacement_begin ||
        candidate.begin_utc_seconds < *replacement_begin)
      replacement_begin = candidate.begin_utc_seconds;
  }
  // A receive key overlaps on both sides of its activation boundary. When it
  // is the newest entry, OSPF retains it as the last valid key just as it does
  // for transmission.
  return !replacement_begin ||
         now < saturating_add(*replacement_begin,
                              entry.tolerance_seconds);
}

} // namespace

KeychainStatus validate(const KeychainConfiguration &keychain,
                        bool allow_incomplete) noexcept {
  if (keychain.name.empty() || keychain.name.size() > 32U)
    return KeychainStatus::invalid_name;
  for (std::size_t index{}; index < keychain.bidirectional.size(); ++index) {
    const auto &entry = keychain.bidirectional[index];
    // The release command range is 0 through 63. uint8_t represents the wire
    // Key ID, while this explicit check preserves the narrower platform limit.
    if (entry.id > 63U ||
        (!allow_incomplete &&
         (!entry.secret_configured || !entry.algorithm_configured ||
          entry.secret == 0U)) ||
        (entry.secret_configured && entry.secret == 0U))
      return KeychainStatus::invalid_entry;
    if (entry.end_utc_seconds &&
        *entry.end_utc_seconds <= entry.begin_utc_seconds)
      return KeychainStatus::invalid_window;
    for (std::size_t prior{}; prior < index; ++prior)
      if (keychain.bidirectional[prior].id == entry.id)
        return KeychainStatus::duplicate_entry;
  }
  return KeychainStatus::valid;
}

const KeychainEntry *
select_send_key(const KeychainConfiguration &keychain,
                std::int64_t now_utc_seconds) noexcept {
  if (!keychain.admin_enabled ||
      validate(keychain) != KeychainStatus::valid)
    return nullptr;
  const KeychainEntry *selected{};
  for (const auto &entry : keychain.bidirectional) {
    if (!valid_for_send(entry, now_utc_seconds))
      continue;
    // "Youngest" is the latest begin time. Entry ID is only a stable
    // deterministic tie-break when two configuration rows begin together.
    if (!selected ||
        entry.begin_utc_seconds > selected->begin_utc_seconds ||
        (entry.begin_utc_seconds == selected->begin_utc_seconds &&
         entry.id > selected->id))
      selected = &entry;
  }
  return selected;
}

const KeychainEntry *
select_receive_key(const KeychainConfiguration &keychain,
                   std::uint8_t key_id,
                   std::int64_t now_utc_seconds) noexcept {
  if (!keychain.admin_enabled ||
      validate(keychain) != KeychainStatus::valid)
    return nullptr;
  const auto found = std::find_if(
      keychain.bidirectional.begin(), keychain.bidirectional.end(),
      [key_id](const auto &entry) { return entry.id == key_id; });
  return found != keychain.bidirectional.end() &&
                 valid_for_receive(keychain, *found, now_utc_seconds)
             ? &*found
             : nullptr;
}

} // namespace router::ospf
