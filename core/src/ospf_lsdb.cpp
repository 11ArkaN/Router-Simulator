// RFC 2328 and RFC 5340 LSA validation, recency comparison and LSDB ownership.
// The repository has no timer thread. Its owner supplies steady-clock values
// from the control shard and decides when a safely flooded MaxAge LSA is erased.

#include "router/ospf_lsdb.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/ospf_lsa.hpp"

#include <algorithm>
#include <new>

namespace router::ospf {
namespace {

[[nodiscard]] bool known_version_three_type(
    std::uint16_t type) noexcept {
  using namespace packet::ospf::lsa;
  switch (type) {
  case version_three_router_type:
  case version_three_network_type:
  case version_three_inter_area_prefix_type:
  case version_three_inter_area_router_type:
  case version_three_external_type:
  case version_three_nssa_type:
  case version_three_link_type:
  case version_three_intra_area_prefix_type:
    return true;
  default:
    return false;
  }
}

[[nodiscard]] bool known_version_two_type(
    std::uint16_t type) noexcept {
  // Base OSPFv2 defines 1 through 5 and 7. RFC 5250 adds link, area and
  // AS-scoped opaque types 9 through 11. Unsupported MOSPF and obsolete
  // external-attribute types are discarded instead of being assigned an
  // invented body or flooding behavior.
  return (type >= 1U && type <= 5U) || type == 7U ||
         (type >= 9U && type <= 11U);
}

[[nodiscard]] FloodingScope scope_for(std::uint16_t type,
                                      std::uint8_t version) noexcept {
  if (version == packet::ospf::version_two) {
    // OSPFv2 Type 9 is link-local opaque, Type 11 is AS-scoped opaque, and
    // Type 5 external LSAs are AS-scoped. All remaining supported base types
    // are area-scoped, including NSSA Type 7.
    if (type == 9U)
      return FloodingScope::link;
    if (type == 5U || type == 11U)
      return FloodingScope::autonomous_system;
    return FloodingScope::area;
  }
  // RFC 5340 section 2.9 says an unknown type with U=0 is treated as
  // link-local regardless of its encoded S2/S1 bits. U=1 preserves the
  // encoded scope so extensions can be stored and flooded without their body
  // being understood.
  if (!known_version_three_type(type) && (type & 0x8000U) == 0U)
    return FloodingScope::link;
  switch ((type >> 13U) & 0x03U) {
  case 0U:
    return FloodingScope::link;
  case 1U:
    return FloodingScope::area;
  case 2U:
    return FloodingScope::autonomous_system;
  case 3U:
    // Installation rejects reserved scope before constructing the key.
    return FloodingScope::link;
  }
  return FloodingScope::link;
}

} // namespace

LsaKey lsa_key(const packet::ospf::LsaHeaderView &header) noexcept {
  return {.link_state_id = header.link_state_id,
          .advertising_router = header.advertising_router,
          .type = header.type,
          .scope = scope_for(header.type, header.version)};
}

LsaRecency compare_lsa_headers(
    const packet::ospf::LsaHeaderView &candidate,
    const packet::ospf::LsaHeaderView &current) noexcept {
  if (candidate.sequence_number != current.sequence_number)
    return candidate.sequence_number > current.sequence_number
               ? LsaRecency::newer
               : LsaRecency::older;
  if (candidate.checksum != current.checksum)
    return candidate.checksum > current.checksum ? LsaRecency::newer
                                                 : LsaRecency::older;
  if (candidate.age_seconds == max_age_seconds &&
      current.age_seconds != max_age_seconds)
    return LsaRecency::newer;
  if (current.age_seconds == max_age_seconds &&
      candidate.age_seconds != max_age_seconds)
    return LsaRecency::older;
  const auto difference =
      candidate.age_seconds > current.age_seconds
          ? candidate.age_seconds - current.age_seconds
          : current.age_seconds - candidate.age_seconds;
  if (difference > max_age_difference_seconds)
    return candidate.age_seconds < current.age_seconds
               ? LsaRecency::newer
               : LsaRecency::older;
  return LsaRecency::identical;
}

namespace {

[[nodiscard]] bool valid_sequence(std::int32_t sequence) noexcept {
  // 0x80000000 is reserved. Signed comparison then naturally orders the
  // InitialSequenceNumber through MaxSequenceNumber interval.
  return static_cast<std::uint32_t>(sequence) != 0x80000000U;
}

} // namespace

std::uint16_t LsaRecord::age(RuntimeClock::time_point now) const noexcept {
  if (now <= installed_at)
    return age_at_install;
  const auto elapsed =
      std::chrono::duration_cast<std::chrono::seconds>(now - installed_at)
          .count();
  const auto total = static_cast<std::uint64_t>(age_at_install) +
                     static_cast<std::uint64_t>(elapsed);
  return static_cast<std::uint16_t>(
      std::min<std::uint64_t>(total, max_age_seconds));
}

bool verify_lsa_checksum(std::span<const std::uint8_t> lsa) noexcept {
  if (lsa.size() < packet::ospf::lsa_header_octets)
    return false;
  std::uint32_t c0{};
  std::uint32_t c1{};
  for (std::size_t index = 2U; index < lsa.size(); ++index) {
    c0 = (c0 + lsa[index]) % 255U;
    c1 = (c1 + c0) % 255U;
  }
  return c0 == 0U && c1 == 0U;
}

bool update_lsa_checksum(std::span<std::uint8_t> lsa) noexcept {
  constexpr std::size_t checksum_offset = 16U;
  if (lsa.size() < packet::ospf::lsa_header_octets)
    return false;
  lsa[checksum_offset] = 0U;
  lsa[checksum_offset + 1U] = 0U;
  std::int32_t c0{};
  std::int32_t c1{};
  for (std::size_t index = 2U; index < lsa.size(); ++index) {
    c0 = (c0 + lsa[index]) % 255;
    c1 = (c1 + c0) % 255;
  }
  // RFC 905 section 3 applies signed modular arithmetic here. `size()` is an
  // unsigned type, so allowing it to participate directly converts a
  // negative intermediate to size_t before `% 255`. That changed X by one for
  // valid LSAs whose C1 exceeded the length-weighted C0, including an OSPFv3
  // Router-LSA as soon as it gained its first point-to-point link.
  const auto checksum_distance = static_cast<std::int32_t>(
      lsa.size() - checksum_offset - 1U);
  auto x =
      (checksum_distance * c0 - c1) % static_cast<std::int32_t>(255);
  if (x <= 0)
    x += 255;
  auto y = 510 - c0 - x;
  if (y > 255)
    y -= 255;
  lsa[checksum_offset] = static_cast<std::uint8_t>(x);
  lsa[checksum_offset + 1U] = static_cast<std::uint8_t>(y);
  return verify_lsa_checksum(lsa);
}

LinkStateDatabase::LinkStateDatabase(std::size_t maximum_records)
    : maximum_records_(maximum_records) {
  records_.reserve(maximum_records_);
}

const LsaRecord *LinkStateDatabase::find(const LsaKey &key) const noexcept {
  const auto found =
      std::find_if(records_.begin(), records_.end(),
                   [&](const auto &record) { return record.key == key; });
  return found == records_.end() ? nullptr : &*found;
}

LsaRecord *LinkStateDatabase::find(const LsaKey &key) noexcept {
  return const_cast<LsaRecord *>(
      std::as_const(*this).find(key));
}

bool LinkStateDatabase::erase(const LsaKey &key) noexcept {
  const auto found =
      std::find_if(records_.begin(), records_.end(),
                   [&](const auto &record) { return record.key == key; });
  if (found == records_.end())
    return false;
  records_.erase(found);
  return true;
}

bool LinkStateDatabase::premature_age(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  auto *record = find(key);
  if (!record || record->bytes.size() < packet::ospf::lsa_header_octets)
    return false;

  // LS age is the only LSA field that may change without recomputing the
  // checksum. Resetting the time anchor makes every later age() sample stable
  // at MaxAge even if the host clock advances by days.
  record->bytes[0U] =
      static_cast<std::uint8_t>(max_age_seconds >> 8U);
  record->bytes[1U] = static_cast<std::uint8_t>(max_age_seconds);
  record->installed_at = now;
  record->age_at_install = max_age_seconds;
  record->max_age_flooded = false;
  return true;
}

bool LinkStateDatabase::mark_max_age_flooded(
    const LsaKey &key) noexcept {
  auto *record = find(key);
  if (!record || record->age_at_install != max_age_seconds)
    return false;
  record->max_age_flooded = true;
  return true;
}

bool LinkStateDatabase::verify_checksum_at(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  auto *record = find(key);
  if (!record || !verify_lsa_checksum(record->bytes))
    return false;
  record->last_checksum_check_age = record->age(now);
  return true;
}

InstallResult LinkStateDatabase::install(
    std::span<const std::uint8_t> encoded_lsa, std::uint8_t version,
    RuntimeClock::time_point now, std::uint32_t local_router_id,
    bool received_from_neighbor) noexcept {
  const auto header = packet::ospf::lsa_header(encoded_lsa, version);
  if (!header || header->length != encoded_lsa.size() ||
      header->age_seconds > max_age_seconds ||
      !valid_sequence(header->sequence_number) ||
      !verify_lsa_checksum(encoded_lsa))
    return InstallResult::malformed;
  if (version == packet::ospf::version_two &&
      !known_version_two_type(header->type))
    return InstallResult::ignored;
  if (version == packet::ospf::version_three &&
      ((header->type >> 13U) & 0x03U) == 0x03U)
    return InstallResult::ignored;

  const LsaKey key{.link_state_id = header->link_state_id,
                   .advertising_router = header->advertising_router,
                   .type = header->type,
                   .scope = scope_for(header->type, version)};
  auto *current = find(key);
  if (current) {
    auto current_header =
        packet::ospf::lsa_header(current->bytes, version);
    if (!current_header)
      return InstallResult::malformed;
    current_header->age_seconds = current->age(now);
    const auto order = compare_lsa_headers(*header, *current_header);
    if (order == LsaRecency::older)
      return InstallResult::older;
    if (order == LsaRecency::identical)
      return InstallResult::identical;
    // A reflected self-originated LSA requires a fight-back only when it is
    // newer than the owner's installed generation. Treating an identical
    // multicast copy as a collision causes endless sequence increments on
    // broadcast links where the originator legitimately hears its own flood.
    if (received_from_neighbor &&
        header->advertising_router == local_router_id)
      return InstallResult::fight_back_required;
    // MinLSArrival protects the receive path from repeated newer instances.
    // Local origination is governed by MinLSInterval in the process owner and
    // must not be rejected a second time by a receiver-side timer.
    if (received_from_neighbor && now > current->installed_at &&
        now - current->installed_at <
            device_catalog::ospf_min_ls_arrival)
      return InstallResult::too_soon;
  } else if (records_.size() == maximum_records_) {
    return InstallResult::capacity_exhausted;
  } else if (received_from_neighbor &&
             header->advertising_router == local_router_id) {
    // The local router no longer has this LSA. Section 13.4 still requires a
    // self-originated response so the stale advertisement can be flushed.
    return InstallResult::fight_back_required;
  }

  try {
    std::vector<std::uint8_t> bytes{encoded_lsa.begin(), encoded_lsa.end()};
    LsaRecord replacement{.key = key,
                          .bytes = std::move(bytes),
                          .installed_at = now,
                          .age_at_install = header->age_seconds,
                          .last_checksum_check_age =
                              header->age_seconds,
                          .max_age_flooded = false};
    if (current)
      *current = std::move(replacement);
    else
      records_.push_back(std::move(replacement));
    return InstallResult::installed;
  } catch (const std::bad_alloc &) {
    return InstallResult::capacity_exhausted;
  }
}

LinkStateDatabaseCheckpoint
LinkStateDatabase::checkpoint(RuntimeClock::time_point now) const {
  LinkStateDatabaseCheckpoint result;
  result.records.reserve(records_.size());
  for (const auto &record : records_)
    result.records.push_back(
        {.key = record.key,
         .bytes = record.bytes,
         .effective_age = record.age(now),
         .last_checksum_check_age = record.last_checksum_check_age,
         .max_age_flooded = record.max_age_flooded});
  return result;
}

bool LinkStateDatabase::restore(
    const LinkStateDatabaseCheckpoint &checkpoint, std::uint8_t version,
    RuntimeClock::time_point now) noexcept {
  if (checkpoint.records.size() > maximum_records_)
    return false;
  try {
    std::vector<LsaRecord> staged;
    staged.reserve(maximum_records_);
    for (const auto &saved : checkpoint.records) {
      const auto header = packet::ospf::lsa_header(saved.bytes, version);
      if (!header || header->length != saved.bytes.size() ||
          lsa_key(*header) != saved.key ||
          saved.effective_age > max_age_seconds ||
          saved.last_checksum_check_age > saved.effective_age ||
          !verify_lsa_checksum(saved.bytes) ||
          std::any_of(staged.begin(), staged.end(), [&](const auto &entry) {
            return entry.key == saved.key;
          }))
        return false;
      staged.push_back(
          {.key = saved.key,
           .bytes = saved.bytes,
           .installed_at = now,
           .age_at_install = saved.effective_age,
           .last_checksum_check_age = saved.last_checksum_check_age,
           .max_age_flooded = saved.max_age_flooded});
    }
    records_.swap(staged);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
