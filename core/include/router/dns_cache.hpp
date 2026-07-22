// Resolver-owned DNS positive and negative cache. One service shard mutates
// entries and monotonic TTLs. The cache stores canonical DNS values only and
// has no access to UDP, TCP, topology or another resolver instance.

#pragma once

#include "router/dns_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::dns {

enum class NegativeKind : std::uint8_t { none, name_error, no_data };

// RFC 4035 security status is retained with cached data. Bogus is omitted on
// purpose because failed validation must never produce a reusable cache entry.
enum class CacheSecurity : std::uint8_t { indeterminate, insecure, secure };

struct CacheRecordCheckpoint {
  packet::dns::Name owner;
  std::vector<std::uint8_t> rdata;
  std::int64_t remaining_nanoseconds{};
  std::uint64_t use_generation{};
  std::uint16_t type{};
  std::uint16_t record_class{};
  std::uint32_t original_ttl{};
  CacheSecurity security{CacheSecurity::indeterminate};
};

struct NegativeCacheCheckpoint {
  packet::dns::Name name;
  CacheRecordCheckpoint soa;
  std::int64_t remaining_nanoseconds{};
  std::uint64_t use_generation{};
  std::uint16_t type{};
  std::uint16_t record_class{};
  NegativeKind kind{NegativeKind::none};
  CacheSecurity security{CacheSecurity::indeterminate};
};

struct CacheCheckpoint {
  std::vector<CacheRecordCheckpoint> records;
  std::vector<NegativeCacheCheckpoint> negative;
  std::uint64_t next_use_generation{1U};
  std::uint64_t capacity_bytes{};
};

struct CacheLookup {
  packet::dns::Rcode rcode{packet::dns::Rcode::no_error};
  std::vector<packet::dns::RecordData> records;
  std::vector<packet::dns::RecordData> authorities;
  NegativeKind negative{NegativeKind::none};
  CacheSecurity security{CacheSecurity::indeterminate};
};

class ResolverCache final {
public:
  using Clock = std::chrono::steady_clock;

  explicit ResolverCache(
      std::size_t capacity_bytes =
          device_catalog::dns_cache_default_bytes) noexcept;
  ~ResolverCache();
  ResolverCache(ResolverCache &&) noexcept;
  ResolverCache &operator=(ResolverCache &&) noexcept;
  ResolverCache(const ResolverCache &) = delete;
  ResolverCache &operator=(const ResolverCache &) = delete;

  [[nodiscard]] bool insert_positive(
      std::span<const packet::dns::RecordData> records,
      Clock::time_point now = Clock::now(),
      CacheSecurity security = CacheSecurity::indeterminate) noexcept;
  [[nodiscard]] bool insert_negative(
      const packet::dns::Name &name, std::uint16_t type,
      std::uint16_t record_class, NegativeKind kind,
      const packet::dns::RecordData &soa,
      Clock::time_point now = Clock::now(),
      CacheSecurity security = CacheSecurity::indeterminate) noexcept;

  // lookup updates LRU ownership and reports remaining whole-second TTLs. A
  // miss has no records and NegativeKind::none.
  [[nodiscard]] CacheLookup lookup(
      const packet::dns::Name &name, std::uint16_t type,
      std::uint16_t record_class,
      Clock::time_point now = Clock::now());
  void expire(Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] CacheCheckpoint checkpoint(
      Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(const CacheCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::size_t used_bytes() const noexcept { return used_bytes_; }

private:
  struct Record;
  struct Negative;
  [[nodiscard]] std::uint64_t next_use() noexcept;
  void enforce_capacity() noexcept;
  void recalculate_used() noexcept;

  std::vector<Record> records_;
  std::vector<Negative> negative_;
  std::size_t capacity_bytes_{};
  std::size_t used_bytes_{};
  std::uint64_t next_use_generation_{1U};
};

} // namespace router::dns
