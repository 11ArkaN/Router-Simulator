// Authoritative DNS zone repository and answer selection. One service shard
// owns each Zone. Lookup returns record views borrowing immutable zone storage;
// it never sends a packet or calls another server directly.

#pragma once

#include "router/dns_packet.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace router::dns {

struct ZoneRecord {
  packet::dns::Name owner;
  std::uint16_t type{};
  std::uint16_t record_class{packet::dns::internet_class};
  std::uint32_t ttl{};
  std::vector<std::uint8_t> rdata;
};

struct AuthoritativeAnswer {
  packet::dns::Rcode rcode{packet::dns::Rcode::no_error};
  std::vector<packet::dns::RecordData> answers;
  std::vector<packet::dns::RecordData> authorities;
  std::vector<packet::dns::RecordData> additionals;
  // Synthesized DNAME CNAME targets need response-owned storage because no
  // backing ZoneRecord exists for them. RecordData views remain valid for the
  // lifetime of this answer and are never retained by the Zone.
  std::vector<std::vector<std::uint8_t>> synthesized_rdata;
  bool authoritative{};
  bool referral{};
};

class Zone final {
public:
  explicit Zone(packet::dns::Name origin) noexcept;

  // Replacement validates the complete detached record set before swapping
  // storage. A rejected import leaves the serving generation unchanged.
  [[nodiscard]] bool replace(std::vector<ZoneRecord> records) noexcept;
  [[nodiscard]] AuthoritativeAnswer
  answer(const packet::dns::Question &question) const;

  [[nodiscard]] const packet::dns::Name &origin() const noexcept {
    return origin_;
  }
  [[nodiscard]] const std::vector<ZoneRecord> &records() const noexcept {
    return records_;
  }

private:
  [[nodiscard]] packet::dns::RecordData
  view(const ZoneRecord &record) const noexcept;
  void negative_soa(AuthoritativeAnswer &answer) const;

  packet::dns::Name origin_;
  std::vector<ZoneRecord> records_;
};

[[nodiscard]] bool is_subdomain(const packet::dns::Name &name,
                                const packet::dns::Name &ancestor) noexcept;

} // namespace router::dns
