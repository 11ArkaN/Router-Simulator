// RFC 1034 and RFC 2308 DNS cache implementation. Expirations use the host
// monotonic clock and are serialized as relative durations. Wall-clock jumps
// and browser suspension therefore cannot manufacture additional TTL life.

#include "router/dns_cache.hpp"

#include <algorithm>
#include <limits>
#include <new>

namespace router::dns {
namespace {

using Clock = ResolverCache::Clock;
constexpr std::uint32_t maximum_cache_ttl = 0x7fffffffU;

bool valid_name(const packet::dns::Name &name) noexcept {
  if (name.octets == 0U || name.octets > name.wire.size())
    return false;
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

Clock::time_point expiration(Clock::time_point now, std::uint32_t ttl) noexcept {
  return now + std::chrono::seconds{ttl};
}

std::uint32_t remaining_ttl(Clock::time_point expires,
                            Clock::time_point now) noexcept {
  if (expires <= now)
    return 0U;
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(expires - now).count();
  return static_cast<std::uint32_t>(std::min<std::int64_t>(
      seconds, std::numeric_limits<std::uint32_t>::max()));
}

bool same_name(const packet::dns::Name &left,
               const packet::dns::Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool is_subdomain(const packet::dns::Name &name,
                  const packet::dns::Name &ancestor) noexcept {
  std::size_t offset{};
  while (offset < name.octets) {
    packet::dns::Name suffix;
    suffix.octets = static_cast<std::uint16_t>(name.octets - offset);
    std::copy_n(name.wire.begin() + static_cast<std::ptrdiff_t>(offset),
                suffix.octets, suffix.wire.begin());
    if (same_name(suffix, ancestor))
      return true;
    if (name.wire[offset] == 0U)
      break;
    offset += 1U + name.wire[offset];
  }
  return false;
}

} // namespace

struct ResolverCache::Record {
  packet::dns::Name owner;
  std::vector<std::uint8_t> rdata;
  Clock::time_point expires{};
  std::uint64_t use_generation{};
  std::uint16_t type{};
  std::uint16_t record_class{};
  std::uint32_t original_ttl{};
  CacheSecurity security{CacheSecurity::indeterminate};
};

struct ResolverCache::Negative {
  packet::dns::Name name;
  Record soa;
  Clock::time_point expires{};
  std::uint64_t use_generation{};
  std::uint16_t type{};
  std::uint16_t record_class{};
  NegativeKind kind{NegativeKind::none};
  CacheSecurity security{CacheSecurity::indeterminate};
};

ResolverCache::ResolverCache(std::size_t capacity_bytes) noexcept
    : capacity_bytes_(capacity_bytes) {}

// These special members stay out of the header because Record and Negative
// are private implementation types. This preserves the narrow public ABI while
// allowing standard vectors to destroy and move complete element types here.
ResolverCache::~ResolverCache() = default;
ResolverCache::ResolverCache(ResolverCache &&) noexcept = default;
ResolverCache &ResolverCache::operator=(ResolverCache &&) noexcept = default;

std::uint64_t ResolverCache::next_use() noexcept {
  auto result = next_use_generation_++;
  if (result != 0U)
    return result;
  // Wrap is practically unreachable, but resetting all generations preserves
  // a strict total order instead of allowing zero to look older than live data.
  std::uint64_t generation{1U};
  for (auto &record : records_)
    record.use_generation = generation++;
  for (auto &entry : negative_)
    entry.use_generation = generation++;
  next_use_generation_ = generation + 1U;
  return generation;
}

void ResolverCache::recalculate_used() noexcept {
  used_bytes_ = 0U;
  for (const auto &record : records_)
    used_bytes_ += sizeof(Record) + record.rdata.size();
  for (const auto &entry : negative_)
    used_bytes_ += sizeof(Negative) + entry.soa.rdata.size();
}

void ResolverCache::enforce_capacity() noexcept {
  recalculate_used();
  while (used_bytes_ > capacity_bytes_ &&
         (!records_.empty() || !negative_.empty())) {
    const auto positive = std::min_element(
        records_.begin(), records_.end(), [](const auto &left, const auto &right) {
          return left.use_generation < right.use_generation;
        });
    const auto negative = std::min_element(
        negative_.begin(), negative_.end(), [](const auto &left, const auto &right) {
          return left.use_generation < right.use_generation;
        });
    const bool remove_positive =
        negative == negative_.end() ||
        (positive != records_.end() &&
         positive->use_generation <= negative->use_generation);
    if (remove_positive)
      records_.erase(positive);
    else
      negative_.erase(negative);
    recalculate_used();
  }
}

bool ResolverCache::insert_positive(
    std::span<const packet::dns::RecordData> records,
    Clock::time_point now, CacheSecurity security) noexcept {
  if (capacity_bytes_ == 0U || security > CacheSecurity::secure)
    return false;
  try {
    std::vector<Record> additions;
    additions.reserve(records.size());
    for (const auto &record : records) {
      if (!valid_name(record.owner) || record.type == 0U ||
          record.record_class == 0U || record.ttl > maximum_cache_ttl ||
          record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        return false;
      if (record.ttl == 0U)
        continue;
      additions.push_back({.owner = record.owner,
                           .rdata = {record.rdata.begin(), record.rdata.end()},
                           .expires = expiration(now, record.ttl),
                           .use_generation = 0U,
                           .type = record.type,
                           .record_class = record.record_class,
                           .original_ttl = record.ttl,
                           .security = security});
    }
    records_.reserve(records_.size() + additions.size());
    // All potentially throwing allocations completed before the live cache is
    // touched. Generation allocation and replacement below are non-throwing,
    // so an allocation failure cannot leave half of an RRset installed.
    for (auto &addition : additions)
      addition.use_generation = next_use();
    for (const auto &addition : additions)
      std::erase_if(records_, [&](const auto &existing) {
        return existing.type == addition.type &&
               existing.record_class == addition.record_class &&
               same_name(existing.owner, addition.owner);
      });
    for (const auto &addition : additions)
      std::erase_if(negative_, [&](const auto &existing) {
        // A newly validated positive RRset proves that the owner exists and
        // supersedes both an NXDOMAIN entry and NODATA for this exact type.
        return existing.record_class == addition.record_class &&
               ((existing.kind == NegativeKind::name_error &&
                 is_subdomain(addition.owner, existing.name)) ||
                (same_name(existing.name, addition.owner) &&
                 existing.type == addition.type));
      });
    for (auto &addition : additions)
      records_.push_back(std::move(addition));
    enforce_capacity();
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool ResolverCache::insert_negative(
    const packet::dns::Name &name, std::uint16_t type,
    std::uint16_t record_class, NegativeKind kind,
    const packet::dns::RecordData &soa, Clock::time_point now,
    CacheSecurity security) noexcept {
  if (capacity_bytes_ == 0U || !valid_name(name) ||
      kind == NegativeKind::none ||
      security > CacheSecurity::secure ||
      record_class == 0U || soa.type != packet::dns::type_soa ||
      soa.ttl == 0U || soa.ttl > maximum_cache_ttl ||
      soa.record_class != record_class || !valid_name(soa.owner) ||
      soa.rdata.size() > std::numeric_limits<std::uint16_t>::max() ||
      (kind == NegativeKind::no_data && type == 0U))
    return false;
  try {
    Negative addition{
        .name = name,
        .soa = {.owner = soa.owner,
                .rdata = {soa.rdata.begin(), soa.rdata.end()},
                .expires = expiration(now, soa.ttl),
                .use_generation = 0U,
                .type = soa.type,
                .record_class = soa.record_class,
                .original_ttl = soa.ttl,
                .security = security},
        .expires = expiration(now, soa.ttl),
        .use_generation = 0U,
        .type = static_cast<std::uint16_t>(
            kind == NegativeKind::name_error ? 0U : type),
        .record_class = record_class,
        .kind = kind,
        .security = security};
    negative_.reserve(negative_.size() + 1U);
    addition.soa.use_generation = next_use();
    addition.use_generation = next_use();
    std::erase_if(negative_, [&](const auto &existing) {
      return same_name(existing.name, name) &&
             existing.record_class == record_class &&
             (kind == NegativeKind::name_error ||
              existing.kind == NegativeKind::name_error ||
              existing.type == type);
    });
    negative_.push_back(std::move(addition));
    enforce_capacity();
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

CacheLookup ResolverCache::lookup(const packet::dns::Name &name,
                                  std::uint16_t type,
                                  std::uint16_t record_class,
                                  Clock::time_point now) {
  expire(now);
  CacheLookup result;
  for (auto &record : records_) {
    if (record.type != type || record.record_class != record_class ||
        !same_name(record.owner, name))
      continue;
    record.use_generation = next_use();
    result.records.push_back({.owner = record.owner,
                              .type = record.type,
                              .record_class = record.record_class,
                              .ttl = remaining_ttl(record.expires, now),
                              .rdata = record.rdata});
    // A valid RRset is replaced atomically, so all values for this lookup key
    // carry one status. Preserve a defensive downgrade if a corrupt internal
    // state ever violates that invariant instead of overstating AD security.
    if (result.records.size() == 1U)
      result.security = record.security;
    else if (result.security != record.security)
      result.security = CacheSecurity::indeterminate;
  }
  if (!result.records.empty())
    return result;
  for (auto &entry : negative_) {
    const bool key_matches =
        entry.record_class == record_class &&
        ((entry.kind == NegativeKind::name_error &&
          is_subdomain(name, entry.name)) ||
         (same_name(entry.name, name) && entry.type == type));
    if (!key_matches)
      continue;
    entry.use_generation = next_use();
    result.negative = entry.kind;
    result.security = entry.security;
    result.rcode = entry.kind == NegativeKind::name_error
                       ? packet::dns::Rcode::name_error
                       : packet::dns::Rcode::no_error;
    result.authorities.push_back(
        {.owner = entry.soa.owner,
         .type = entry.soa.type,
         .record_class = entry.soa.record_class,
         .ttl = remaining_ttl(entry.expires, now),
         .rdata = entry.soa.rdata});
    break;
  }
  return result;
}

void ResolverCache::expire(Clock::time_point now) noexcept {
  std::erase_if(records_, [&](const auto &record) {
    return record.expires <= now;
  });
  std::erase_if(negative_, [&](const auto &entry) {
    return entry.expires <= now;
  });
  recalculate_used();
}

CacheCheckpoint ResolverCache::checkpoint(Clock::time_point now) const {
  CacheCheckpoint state{.records = {},
                        .negative = {},
                        .next_use_generation = next_use_generation_,
                        .capacity_bytes = capacity_bytes_};
  state.records.reserve(records_.size());
  for (const auto &record : records_) {
    if (record.expires <= now)
      continue;
    state.records.push_back(
        {.owner = record.owner,
         .rdata = record.rdata,
         .remaining_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 record.expires - now)
                 .count(),
         .use_generation = record.use_generation,
         .type = record.type,
         .record_class = record.record_class,
         .original_ttl = record.original_ttl,
         .security = record.security});
  }
  state.negative.reserve(negative_.size());
  for (const auto &entry : negative_) {
    if (entry.expires <= now)
      continue;
    const auto remaining =
        std::chrono::duration_cast<std::chrono::nanoseconds>(entry.expires - now)
            .count();
    state.negative.push_back(
        {.name = entry.name,
         .soa = {.owner = entry.soa.owner,
                 .rdata = entry.soa.rdata,
                 .remaining_nanoseconds = remaining,
                 .use_generation = entry.soa.use_generation,
                 .type = entry.soa.type,
                 .record_class = entry.soa.record_class,
                 .original_ttl = entry.soa.original_ttl,
                 .security = entry.soa.security},
         .remaining_nanoseconds = remaining,
         .use_generation = entry.use_generation,
         .type = entry.type,
         .record_class = entry.record_class,
         .kind = entry.kind,
         .security = entry.security});
  }
  return state;
}

bool ResolverCache::restore(const CacheCheckpoint &state,
                            Clock::time_point now) noexcept {
  if (state.capacity_bytes == 0U ||
      state.capacity_bytes > std::numeric_limits<std::size_t>::max() ||
      state.next_use_generation == 0U)
    return false;
  try {
    ResolverCache candidate{static_cast<std::size_t>(state.capacity_bytes)};
    candidate.next_use_generation_ = state.next_use_generation;
    std::uint64_t greatest_generation{};
    candidate.records_.reserve(state.records.size());
    for (const auto &record : state.records) {
      const auto maximum_life = std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::seconds{record.original_ttl}).count();
      if (!valid_name(record.owner) || record.remaining_nanoseconds <= 0 ||
          record.remaining_nanoseconds > maximum_life || record.type == 0U ||
          record.record_class == 0U || record.original_ttl == 0U ||
          record.original_ttl > maximum_cache_ttl ||
          record.use_generation == 0U ||
          record.security > CacheSecurity::secure)
        return false;
      for (const auto &existing : candidate.records_) {
        if (existing.type == record.type &&
            existing.record_class == record.record_class &&
            same_name(existing.owner, record.owner))
          return false;
      }
      greatest_generation = std::max(greatest_generation, record.use_generation);
      candidate.records_.push_back(
          {.owner = record.owner,
           .rdata = record.rdata,
           .expires = now +
                      std::chrono::nanoseconds{record.remaining_nanoseconds},
           .use_generation = record.use_generation,
           .type = record.type,
           .record_class = record.record_class,
           .original_ttl = record.original_ttl,
           .security = record.security});
    }
    candidate.negative_.reserve(state.negative.size());
    for (const auto &entry : state.negative) {
      const auto maximum_life = std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::seconds{entry.soa.original_ttl}).count();
      if (!valid_name(entry.name) || !valid_name(entry.soa.owner) ||
          entry.remaining_nanoseconds <= 0 ||
          entry.remaining_nanoseconds > maximum_life ||
          entry.kind == NegativeKind::none || entry.record_class == 0U ||
          entry.use_generation == 0U || entry.soa.use_generation == 0U ||
          entry.soa.type != packet::dns::type_soa ||
          entry.soa.record_class != entry.record_class ||
          entry.soa.original_ttl == 0U ||
          entry.soa.original_ttl > maximum_cache_ttl ||
          entry.soa.security > CacheSecurity::secure ||
          entry.security > CacheSecurity::secure ||
          entry.soa.security != entry.security ||
          (entry.kind == NegativeKind::name_error && entry.type != 0U) ||
          (entry.kind == NegativeKind::no_data && entry.type == 0U))
        return false;
      for (const auto &existing : candidate.negative_) {
        if (same_name(existing.name, entry.name) &&
            existing.record_class == entry.record_class &&
            existing.type == entry.type)
          return false;
      }
      greatest_generation = std::max(
          greatest_generation,
          std::max(entry.use_generation, entry.soa.use_generation));
      const auto expires =
          now + std::chrono::nanoseconds{entry.remaining_nanoseconds};
      candidate.negative_.push_back(
          {.name = entry.name,
           .soa = {.owner = entry.soa.owner,
                   .rdata = entry.soa.rdata,
                   .expires = expires,
                   .use_generation = entry.soa.use_generation,
                   .type = entry.soa.type,
                   .record_class = entry.soa.record_class,
                   .original_ttl = entry.soa.original_ttl,
                   .security = entry.soa.security},
           .expires = expires,
           .use_generation = entry.use_generation,
           .type = entry.type,
           .record_class = entry.record_class,
           .kind = entry.kind,
           .security = entry.security});
    }
    candidate.recalculate_used();
    // A checkpoint is an exact state transfer, not an import hint. Silent LRU
    // eviction here would make restore succeed with observably different DNS
    // contents, so oversized or generation-inconsistent images are rejected.
    if (candidate.used_bytes_ > candidate.capacity_bytes_ ||
        candidate.next_use_generation_ <= greatest_generation)
      return false;
    *this = std::move(candidate);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::dns
