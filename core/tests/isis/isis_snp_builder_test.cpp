// SNP batches cross TLV boundaries without losing ordered entries. Full-frame
// tests exercise instance selection, authentication and atomic batch refusal.

#include "router/isis_snp_builder.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_snp_builder_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  auto scratch = std::make_unique<PduScratch>();
  packet::Frame frame{};
  std::array<SnpEntry, 33U> entries{};
  for (std::size_t index = 0U; index < entries.size(); ++index)
    entries[index] = {static_cast<std::uint16_t>(100U + index),
      {1U, 2U, 3U, 4U, 5U, 6U, 0U, static_cast<std::uint8_t>(index)},
      static_cast<std::uint32_t>(1000U + index), static_cast<std::uint16_t>(2000U + index)};
  // Requests and purge acknowledgements share the same wire list and must not
  // be silently discarded by a generic builder's sequence/lifetime validation.
  entries[7U].remaining_seconds = 0U;
  entries[7U].sequence = 0U;
  entries[7U].checksum = 0U;
  const std::array<std::uint16_t, 1U> topologies{0U};
  const std::array<std::uint8_t, 6U> key{1U, 2U, 3U, 4U, 5U, 6U};
  SnpContents contents;
  contents.header.source = {9U, 8U, 7U, 6U, 5U, 4U};
  contents.header.first = entries.front().id;
  contents.header.last = entries.back().id;
  contents.source = {2U, 0U, 0U, 0U, 0U, 1U};
  contents.destination = {1U, 0U, 0x5eU, 0x90U, 0U, 2U};
  contents.entries = entries;
  contents.instance = PduInstanceOption{InstanceFormat::standard, 7U, topologies};
  contents.authentication = AuthenticationKey{AuthenticationMethod::hmac_sha256, 5U, key};
  contents.maximum_pdu_octets = 1492U;
  for (const auto type : {PduType::csnp_l1, PduType::csnp_l2, PduType::psnp_l1, PduType::psnp_l2}) {
    contents.header.type = type;
    require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::encoded,
            "IS-IS authenticated SNP batch construction failed");
    EthernetDecodeError error{};
    const auto decoded = parse_ethernet_pdu(frame.view(), error);
    require(decoded && decoded->pdu.type == type &&
              verify_authentication(decoded->pdu.bytes, *contents.authentication) == AuthenticationError::none,
            "IS-IS SNP authentication did not cover the complete batch");
    const auto header = snp(decoded->pdu);
    require(header && header->source == contents.header.source && header->source_circuit_id == 0U,
            "IS-IS SNP did not use the originating system with zero circuit ID");
    TlvCursor cursor(decoded->pdu.tlvs);
    const auto first = cursor.next();
    require(first && first->code == 7U, "IS-IS SNP IID did not precede other options");
    InstanceError instance{};
    const auto selected = select_instance(decoded->pdu, InstanceFormat::standard, false, instance);
    require(selected && selected->instance == 7U && selected->topology_zero,
            "IS-IS SNP instance selection failed");
    std::size_t count{};
    unsigned options{};
    while (const auto tlv = cursor.next()) {
      if (tlv->code != 9U) continue;
      ++options;
      require(tlv->value.size() % snp_entry_octets == 0U && tlv->value.size() <= 240U,
              "IS-IS SNP split an entry across TLV boundaries");
      for (std::size_t offset = 0U; offset < tlv->value.size(); offset += snp_entry_octets) {
        const auto entry = snp_entry(tlv->value.subspan(offset, snp_entry_octets));
        require(count < entries.size() && entry == entries[count], "IS-IS SNP lost wire order or entry fields");
        ++count;
      }
    }
    require(cursor.valid() && count == entries.size() && options == 3U,
            "IS-IS SNP did not emit every selected entry exactly once");
    auto damaged = frame;
    damaged.bytes[damaged.length - 1U] ^= 1U;
    const auto changed = parse_ethernet_pdu(damaged.view(), error);
    require(changed && verify_authentication(changed->pdu.bytes, *contents.authentication) == AuthenticationError::mismatch,
            "IS-IS SNP mutation was not detected by authentication");
  }
  const auto saved = frame;
  const auto unchanged = [&] { return frame.length == saved.length && frame.bytes == saved.bytes; };
  contents.maximum_pdu_octets = 100U;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::capacity && unchanged(),
          "IS-IS SNP capacity failure emitted a partial acknowledgement batch");
  contents.maximum_pdu_octets = 1492U;
  std::swap(entries[15U], entries[16U]);
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::entries && unchanged(),
          "IS-IS SNP accepted out-of-order entries across a TLV boundary");
  std::swap(entries[15U], entries[16U]);
  entries[16U].id = entries[15U].id;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::entries && unchanged(),
          "IS-IS SNP accepted duplicate LSP identifiers");
  entries[16U].id.back() = 16U;
  contents.header.type = PduType::csnp_l1;
  contents.header.first.back() = 1U;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::entries && unchanged(),
          "IS-IS CSNP advertised an entry outside its inclusive range");
  contents.header.first = entries.front().id;
  contents.header.last = {};
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::invalid_header && unchanged(),
          "IS-IS CSNP accepted a reversed range");
  contents.header.last = entries.back().id;
  const std::array<std::uint16_t, 2U> multiple{1U, 2U};
  contents.instance->topologies = multiple;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::instance && unchanged(),
          "IS-IS SNP accepted more than one instance-specific topology");
  contents.instance.reset();
  contents.authentication.reset();
  contents.entries = {};
  contents.maximum_pdu_octets = csnp_header_octets;
  require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::encoded,
          "IS-IS empty CSNP range could not synchronize an empty database");
  EthernetDecodeError error{};
  const auto empty = parse_ethernet_pdu(frame.view(), error);
  require(empty && empty->pdu.bytes.size() == csnp_header_octets && empty->pdu.tlvs.empty(),
          "IS-IS empty CSNP contained synthetic entries or protocol padding");
  for (const auto type : {PduType::csnp_l1, PduType::csnp_l2, PduType::psnp_l1, PduType::psnp_l2})
    for (const bool with_instance : {false, true})
      for (const bool with_authentication : {false, true})
        for (const std::size_t mtu : {51U, 100U, 1492U}) {
          contents.header.type = type;
          contents.header.first = {};
          contents.header.last.fill(0xffU);
          contents.maximum_pdu_octets = mtu;
          contents.entries = {};
          contents.instance = with_instance
              ? std::optional(PduInstanceOption{InstanceFormat::standard, 7U, topologies}) : std::nullopt;
          contents.authentication = with_authentication
              ? std::optional(AuthenticationKey{AuthenticationMethod::hmac_sha256, 5U, key}) : std::nullopt;
          const auto budget = maximum_snp_entries(contents, *scratch);
          if (!budget) {
            require(build_snp_frame(frame, contents, *scratch) != SnpBuildResult::encoded,
                "IS-IS SNP budget rejected a viable fixed header and options");
            continue;
          }
          std::vector<SnpEntry> selected(*budget + 1U);
          for (std::size_t index{}; index < selected.size(); ++index) {
            selected[index].id[0U] = 1U;
            selected[index].id[6U] = static_cast<std::uint8_t>(index >> 8U);
            selected[index].id[7U] = static_cast<std::uint8_t>(index & 0xffU);
            selected[index].sequence = selected[index].checksum = 1U;
          }
          contents.entries = std::span(selected).first(*budget);
          require(build_snp_frame(frame, contents, *scratch) == SnpBuildResult::encoded,
              "IS-IS exact SNP budget did not fit its encoded packet");
          const auto before = frame;
          contents.entries = selected;
          const auto oversized = build_snp_frame(frame, contents, *scratch);
          require((oversized == SnpBuildResult::capacity || oversized == SnpBuildResult::authentication) &&
              frame.bytes == before.bytes && frame.length == before.length,
              "IS-IS SNP budget admitted one excess entry or changed output on refusal");
        }
}
