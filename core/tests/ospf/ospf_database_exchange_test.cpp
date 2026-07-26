// Neighbor database exchange tests cover summary generation, request
// deduplication, Loading completion inputs and exact retransmission ACKs.

#include "router/ospf_database_exchange.hpp"

#include <algorithm>
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

std::array<std::uint8_t, 24U> lsa(
    std::int32_t sequence, std::uint8_t type = 1U) {
  std::array<std::uint8_t, 24U> bytes{};
  bytes[3U] = type;
  write32(bytes, 4U, 1U);
  write32(bytes, 8U, 0x01010101U);
  write32(bytes, 12U, static_cast<std::uint32_t>(sequence));
  write16(bytes, 18U, static_cast<std::uint16_t>(bytes.size()));
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("exchange LSA checksum failed");
  return bytes;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_database_exchange_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::now();
  LinkStateDatabase database{4U};
  const auto current = lsa(initial_sequence_number);
  require(database.install(current, router::packet::ospf::version_two, now,
                           0x02020202U, true) == InstallResult::installed,
          "exchange fixture did not enter LSDB");
  NeighborDatabaseExchange exchange{4U, 4U, 4U, 4U};
  require(exchange.begin(database.records(),
                         router::packet::ospf::version_two, now) &&
              exchange.summaries().size() == 1U,
          "database summary generation failed");

  // RFC 2328 section 15 excludes AS-external-LSAs from both flooding and
  // database summaries over virtual adjacencies. Exercise the exchange
  // owner's scope filter independently of the process packet scheduler.
  const auto external = lsa(initial_sequence_number, 5U);
  require(database.install(external, router::packet::ospf::version_two, now,
                           0x02020202U, true) ==
              InstallResult::installed &&
              exchange.begin(database.records(),
                             router::packet::ospf::version_two, now,
                             false) &&
              exchange.summaries().size() == 1U,
          "virtual exchange summarized an AS-external-LSA");

  const auto external_newer = lsa(initial_sequence_number + 1, 5U);
  std::array<std::uint8_t, router::packet::ospf::lsa_header_octets>
      external_header{};
  std::copy_n(external_newer.begin(), external_header.size(),
              external_header.begin());
  router::packet::ospf::DatabaseDescriptionView external_description{};
  external_description.lsa_headers = external_header;
  external_description.version = router::packet::ospf::version_two;
  require(exchange.process_database_description(
              external_description, database, now) &&
              exchange.requests().empty(),
          "virtual exchange requested an AS-external-LSA");

  // Restore an ordinary exchange before testing request and acknowledgment
  // mechanics below. begin deliberately clears all neighbor-local lists.
  require(exchange.begin(database.records(),
                         router::packet::ospf::version_two, now),
          "ordinary exchange restart failed");

  auto newer = lsa(initial_sequence_number + 1);
  const auto newer_header = router::packet::ospf::lsa_header(
      newer, router::packet::ospf::version_two);
  require(newer_header.has_value(), "newer exchange header was malformed");
  std::array<std::uint8_t, router::packet::ospf::lsa_header_octets>
      dd_header{};
  std::copy_n(newer.begin(), dd_header.size(), dd_header.begin());
  router::packet::ospf::DatabaseDescriptionView description{};
  description.lsa_headers = dd_header;
  description.version = router::packet::ospf::version_two;
  require(exchange.process_database_description(description, database, now) &&
              exchange.process_database_description(description, database,
                                                    now) &&
              exchange.requests().size() == 1U,
          "newer DD header did not create one deduplicated request");
  exchange.received_lsa(*newer_header, InstallResult::installed);
  require(exchange.requests().empty(),
          "received requested LSA did not complete request");
  require(exchange.process_database_description(description, database, now) &&
              exchange.requests().size() == 1U,
          "fight-back request fixture did not restore the requested identity");
  exchange.received_lsa(*newer_header,
                        InstallResult::fight_back_required);
  require(exchange.requests().empty(),
          "received self-originated LSA did not complete its request");

  require(exchange.queue_retransmission(database.records()[0U],
                                        router::packet::ospf::version_two,
                                        now) &&
              exchange.retransmissions().size() == 1U,
          "LSA did not enter retransmission list");
  auto wrong_ack = *exchange.summaries().begin();
  ++wrong_ack.sequence_number;
  require(!exchange.acknowledge(wrong_ack) &&
              exchange.acknowledge(*exchange.summaries().begin()) &&
              exchange.retransmissions().empty(),
          "acknowledgment cleared the wrong LSA generation");
}
