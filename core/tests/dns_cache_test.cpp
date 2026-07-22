// Resolver cache tests cover TTL ageing, distinct RFC 2308 negative keys,
// resource-pressure eviction and exact checkpoint transfer. Test timestamps
// are monotonic values, so the suite never waits for wall-clock time.

#include "router/dns_cache.hpp"

#include <array>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

router::packet::dns::Name cache_name(const char *text) {
  const auto value = router::packet::dns::name_from_text(text);
  if (!value)
    throw std::runtime_error("DNS cache fixture name is invalid");
  return *value;
}

} // namespace

void dns_cache_tests() {
  using namespace std::chrono_literals;
  using namespace router;
  using namespace router::packet::dns;

  const auto epoch = dns::ResolverCache::Clock::time_point{10s};
  const auto owner = cache_name("www.example.test.");
  const std::array<std::uint8_t, 4U> address{192U, 0U, 2U, 1U};
  const RecordData record{.owner = owner,
                          .type = type_a,
                          .record_class = internet_class,
                          .ttl = 60U,
                          .rdata = address};

  dns::ResolverCache cache;
  if (!cache.insert_positive(std::span{&record, 1U}, epoch,
                             dns::CacheSecurity::secure))
    throw std::runtime_error("DNS positive cache insertion failed");
  const auto positive = cache.lookup(owner, type_a, internet_class, epoch + 1s);
  if (positive.records.size() != 1U || positive.records.front().ttl != 59U ||
      positive.records.front().rdata.size() != address.size() ||
      positive.security != dns::CacheSecurity::secure)
    throw std::runtime_error("DNS positive TTL did not age monotonically");
  if (!cache.lookup(owner, type_a, internet_class, epoch + 61s).records.empty())
    throw std::runtime_error("expired positive DNS data remained visible");

  // The cache API receives the already RFC 2308-limited SOA TTL from response
  // processing. Canonical SOA bytes stay opaque here because cache ownership
  // must not reinterpret authoritative zone data.
  const std::array<std::uint8_t, 22U> soa_bytes{};
  const RecordData soa{.owner = cache_name("example.test."),
                       .type = type_soa,
                       .record_class = internet_class,
                       .ttl = 30U,
                       .rdata = soa_bytes};
  if (!cache.insert_negative(owner, type_a, internet_class,
                             dns::NegativeKind::name_error, soa, epoch,
                             dns::CacheSecurity::secure))
    throw std::runtime_error("DNS NXDOMAIN cache insertion failed");
  const auto name_error =
      cache.lookup(owner, type_aaaa, internet_class, epoch + 1s);
  if (name_error.negative != dns::NegativeKind::name_error ||
      name_error.rcode != Rcode::name_error ||
      name_error.authorities.front().ttl != 29U ||
      name_error.security != dns::CacheSecurity::secure)
    throw std::runtime_error("NXDOMAIN was not keyed by name and class");
  const auto descendant = cache.lookup(cache_name("child.www.example.test."),
                                       type_a, internet_class, epoch + 1s);
  if (descendant.negative != dns::NegativeKind::name_error)
    throw std::runtime_error("cached NXDOMAIN did not deny its subtree");

  if (!cache.insert_negative(owner, type_aaaa, internet_class,
                             dns::NegativeKind::no_data, soa, epoch))
    throw std::runtime_error("DNS NODATA cache insertion failed");
  if (cache.lookup(owner, type_a, internet_class, epoch + 1s).negative !=
          dns::NegativeKind::none ||
      cache.lookup(owner, type_aaaa, internet_class, epoch + 1s).negative !=
          dns::NegativeKind::no_data)
    throw std::runtime_error("NODATA was not keyed by name, type and class");

  // Derive a capacity that is one octet too small for two records. This tests
  // policy without baking a compiler-specific sizeof(Record) into the suite.
  dns::ResolverCache measured;
  const auto other = cache_name("other.example.test.");
  const RecordData second{.owner = other,
                          .type = type_a,
                          .record_class = internet_class,
                          .ttl = 60U,
                          .rdata = address};
  const std::array pair{record, second};
  if (!measured.insert_positive(pair, epoch) || measured.used_bytes() < 2U)
    throw std::runtime_error("DNS cache resource accounting failed");
  dns::ResolverCache bounded{measured.used_bytes() - 1U};
  if (!bounded.insert_positive(std::span{&record, 1U}, epoch) ||
      !bounded.insert_positive(std::span{&second, 1U}, epoch + 1s))
    throw std::runtime_error("bounded DNS cache insertion failed");
  if (!bounded.lookup(owner, type_a, internet_class, epoch + 2s).records.empty() ||
      bounded.lookup(other, type_a, internet_class, epoch + 2s).records.empty())
    throw std::runtime_error("DNS cache did not evict the least-recent entry");

  dns::ResolverCache source;
  if (!source.insert_positive(std::span{&record, 1U}, epoch,
                              dns::CacheSecurity::secure))
    throw std::runtime_error("DNS checkpoint source insertion failed");
  const auto checkpoint = source.checkpoint(epoch + 5s);
  dns::ResolverCache restored;
  if (!restored.restore(checkpoint, epoch + 100s))
    throw std::runtime_error("DNS cache checkpoint restore failed");
  const auto transferred =
      restored.lookup(owner, type_a, internet_class, epoch + 101s);
  if (transferred.records.size() != 1U ||
      transferred.records.front().ttl != 54U ||
      transferred.security != dns::CacheSecurity::secure)
    throw std::runtime_error("DNS checkpoint extended or shortened TTL life");

  auto corrupt = checkpoint;
  corrupt.records.front().remaining_nanoseconds = -1;
  if (restored.restore(corrupt, epoch + 200s) ||
      restored.lookup(owner, type_a, internet_class, epoch + 101s)
          .records.empty())
    throw std::runtime_error("corrupt DNS checkpoint changed live cache state");
}
