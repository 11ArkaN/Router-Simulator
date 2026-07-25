// LSDB tests cover Fletcher checksum generation, recency, MinLSArrival,
// MaxAge preference, self-originated fight-back and bounded atomic storage.

#include "router/ospf_lsdb.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::array<std::uint8_t, 24U>
lsa(std::uint16_t age, std::int32_t sequence, std::uint32_t advertiser,
    std::uint8_t body_value = 1U) {
  std::array<std::uint8_t, 24U> bytes{};
  write16(bytes, 0U, age);
  bytes[2U] = 0x02U;
  bytes[3U] = 1U;
  write32(bytes, 4U, 0x0a000001U);
  write32(bytes, 8U, advertiser);
  write32(bytes, 12U, static_cast<std::uint32_t>(sequence));
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  bytes[20U] = body_value;
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("test LSA checksum generation failed");
  return bytes;
}

std::array<std::uint8_t, 24U>
version_three_lsa(std::uint16_t type, std::uint32_t advertiser) {
  std::array<std::uint8_t, 24U> bytes{};
  write16(bytes, 0U, 0U);
  write16(bytes, 2U, type);
  write32(bytes, 4U, 0x0a000001U);
  write32(bytes, 8U, advertiser);
  write32(bytes, 12U,
          static_cast<std::uint32_t>(
              router::ospf::initial_sequence_number));
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  bytes[20U] = 0x5aU;
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error(
        "test OSPFv3 LSA checksum generation failed");
  return bytes;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_lsdb_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  LinkStateDatabase database{2U};
  auto first = lsa(10U, initial_sequence_number, 0x01010101U);
  require(verify_lsa_checksum(first) &&
              database.install(first, router::packet::ospf::version_two, now,
                               0x02020202U, true) ==
                  InstallResult::installed,
          "valid LSA was not installed");

  auto newer = lsa(10U, initial_sequence_number + 1, 0x01010101U);
  require(database.install(newer, router::packet::ospf::version_two,
                           now + std::chrono::milliseconds{500U}, 0x02020202U,
                           true) == InstallResult::too_soon &&
              database.install(newer, router::packet::ospf::version_two,
                               now + std::chrono::seconds{1U}, 0x02020202U,
                               true) == InstallResult::installed,
          "MinLSArrival did not defer only the early newer instance");

  auto older = lsa(10U, initial_sequence_number, 0x01010101U);
  require(database.install(older, router::packet::ospf::version_two,
                           now + std::chrono::seconds{2U}, 0x02020202U,
                           true) == InstallResult::older,
          "older LSA replaced a newer database instance");

  auto flush = lsa(max_age_seconds, initial_sequence_number + 1,
                   0x01010101U);
  require(database.install(flush, router::packet::ospf::version_two,
                           now + std::chrono::seconds{2U}, 0x02020202U,
                           true) == InstallResult::installed,
          "MaxAge instance did not supersede an equal-sequence LSA");

  auto reflected = lsa(1U, initial_sequence_number, 0x02020202U);
  require(database.install(reflected, router::packet::ospf::version_two,
                           now + std::chrono::seconds{3U}, 0x02020202U,
                           true) == InstallResult::fight_back_required,
          "reflected self-originated LSA did not request fight-back");

  LinkStateDatabase self_database{2U};
  require(self_database.install(
              reflected, router::packet::ospf::version_two,
              now + std::chrono::seconds{3U}, 0x02020202U, false) ==
              InstallResult::installed &&
              self_database.install(
                  reflected, router::packet::ospf::version_two,
                  now + std::chrono::seconds{4U}, 0x02020202U, true) ==
                  InstallResult::identical,
          "an identical reflected self-originated multicast copy caused a "
          "false fight-back");
  auto reflected_newer =
      lsa(1U, initial_sequence_number + 1, 0x02020202U);
  require(self_database.install(
              reflected_newer, router::packet::ospf::version_two,
              now + std::chrono::seconds{4U}, 0x02020202U, true) ==
              InstallResult::fight_back_required,
          "a newer reflected self-originated LSA did not request fight-back");

  const auto reflected_key =
      lsa_key(*router::packet::ospf::lsa_header(
          reflected, router::packet::ospf::version_two));
  require(self_database.verify_checksum_at(
              reflected_key,
              now + std::chrono::seconds{
                        checksum_check_age_seconds + 5U}) &&
              self_database.find(reflected_key) &&
              self_database.find(reflected_key)
                      ->last_checksum_check_age >=
                  checksum_check_age_seconds,
          "periodic CheckAge validation did not advance its owner marker");
  auto *check_age_record = self_database.find(reflected_key);
  require(check_age_record != nullptr,
          "CheckAge corruption fixture lost its LSA");
  check_age_record->bytes[20U] ^= 0x01U;
  require(!self_database.verify_checksum_at(
              reflected_key,
              now + std::chrono::seconds{
                        checksum_check_age_seconds * 2U + 5U}),
          "CheckAge accepted a corrupted LSDB record");
  check_age_record->bytes[20U] ^= 0x01U;
  require(self_database.premature_age(
              reflected_key, now + std::chrono::seconds{5U}) &&
              self_database.find(reflected_key) &&
              self_database.find(reflected_key)->age(
                  now + std::chrono::hours{2U}) == max_age_seconds &&
              !self_database.find(reflected_key)->max_age_flooded &&
              self_database.mark_max_age_flooded(reflected_key) &&
              self_database.find(reflected_key)->max_age_flooded,
          "premature aging did not preserve an explicit reliable-flood "
          "lifecycle");

  LinkStateDatabase unknown_database{4U};
  auto unknown_u0 = version_three_lsa(0x2123U, 0x03030303U);
  auto unknown_u1 = version_three_lsa(0xa123U, 0x04040404U);
  auto reserved_scope =
      version_three_lsa(0xe123U, 0x05050505U);
  require(
      unknown_database.install(
          unknown_u0, router::packet::ospf::version_three, now,
          0x01010101U, true) == InstallResult::installed &&
          unknown_database.records().front().key.scope ==
              FloodingScope::link,
      "unknown OSPFv3 U=0 LSA did not fall back to link-local scope");
  require(
      unknown_database.install(
          unknown_u1, router::packet::ospf::version_three, now,
          0x01010101U, true) == InstallResult::installed &&
          unknown_database.records().back().key.scope ==
              FloodingScope::area,
      "unknown OSPFv3 U=1 LSA did not retain its encoded area scope");
  require(unknown_database.install(
              reserved_scope, router::packet::ospf::version_three,
              now, 0x01010101U, true) == InstallResult::ignored &&
              unknown_database.records().size() == 2U,
          "reserved OSPFv3 flooding scope entered the LSDB");

  auto corrupt = reflected;
  corrupt[20U] ^= 0xffU;
  require(database.install(corrupt, router::packet::ospf::version_two,
                           now + std::chrono::seconds{3U}, 0x03030303U,
                           true) == InstallResult::malformed,
          "corrupt LSA checksum entered the LSDB");
}
