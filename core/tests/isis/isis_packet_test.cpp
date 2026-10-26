// IS-IS envelope conformance fixtures. Tests own byte buffers and compare wire
// positions to ISO 10589 clause 9, including malformed and reserved-bit input.

#include "router/isis_packet.hpp"
#include "router/iso_checksum.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
}

void isis_packet_tests() {
  using namespace router::packet::isis;
  std::array<std::uint8_t, 512U> storage{};
  const SystemId source{0U, 1U, 2U, 3U, 4U, 5U};
  const std::array<std::uint8_t, 7U> tlvs{1U, 3U, 2U, 0x49U, 0U, 8U, 0U};
  const HelloInput hello{.type = PduType::point_to_point_hello, .source = source,
    .holding_seconds = 30U, .circuit_type = 3U, .local_circuit_id = 7U};
  auto encoded = encode_hello(storage, hello, tlvs);
  const std::array<std::uint8_t, 27U> expected{
    0x83U, 20U, 1U, 0U, 17U, 1U, 0U, 3U, 3U,
    0U, 1U, 2U, 3U, 4U, 5U, 0U, 30U, 0U, 27U, 7U,
    1U, 3U, 2U, 0x49U, 0U, 8U, 0U};
  require(encoded && std::equal(encoded->begin(), encoded->end(), expected.begin(), expected.end()),
           "IS-IS P2P Hello fixed wire fixture mismatch");
  DecodeError error{};
  auto parsed = parse(*encoded, error);
  require(parsed && error == DecodeError::none && parsed->tlvs.size() == tlvs.size(),
           "IS-IS P2P Hello envelope rejected");
  const auto hello_body = router::packet::isis::hello(*parsed);
  require(hello_body && hello_body->source == source && hello_body->holding_seconds == 30U &&
            hello_body->circuit_type == 3U && hello_body->local_circuit_id == 7U,
           "IS-IS P2P Hello body projection mismatch");
  storage[3U] = 6U;
  storage[4U] |= 0xe0U;
  storage[6U] = 0xffU;
  storage[7U] = 0U;
  parsed = parse(std::span(storage).first(expected.size() + 5U), error);
  require(parsed && parsed->bytes.size() == expected.size() && parsed->maximum_area_addresses == 3U,
           "IS-IS reserved receive bits, ID shorthand or link padding mishandled");

  for (const auto type : {PduType::lan_hello_l1, PduType::lan_hello_l2}) {
    auto lan = hello;
    lan.type = type;
    lan.priority = 127U;
    lan.designated_id = {1U, 2U, 3U, 4U, 5U, 6U, 9U};
    encoded = encode_hello(storage, lan, tlvs);
    require(encoded && (*encoded)[1U] == 27U && (*encoded)[19U] == 127U && (*encoded)[26U] == 9U,
             "IS-IS LAN Hello wire positions mismatch");
    require(parse(*encoded, error).has_value(), "IS-IS LAN Hello parse failed");
  }

  for (const auto type : {PduType::lsp_l1, PduType::lsp_l2}) {
    const LspInput lsp{.type = type, .id = {0U, 1U, 2U, 3U, 4U, 5U, 0U, 2U},
      .remaining_seconds = 1200U, .sequence = 0x01020304U, .flags = 3U};
    encoded = encode_lsp(storage, lsp, tlvs);
    require(encoded && (*encoded)[8U] == 0U && (*encoded)[9U] == 34U &&
              (*encoded)[10U] == 4U && (*encoded)[11U] == 0xb0U &&
              (*encoded)[20U] == 1U && (*encoded)[23U] == 4U,
             "IS-IS LSP wire positions mismatch");
    parsed = parse(*encoded, error);
    require(parsed && valid_lsp_checksum(*parsed), "IS-IS LSP checksum invalid");
    const auto body = router::packet::isis::lsp(*parsed);
    require(body && body->id == lsp.id && body->sequence == lsp.sequence &&
              body->remaining_seconds == lsp.remaining_seconds && body->flags == lsp.flags,
             "IS-IS LSP body projection mismatch");
    storage[10U] = 0U;
    storage[11U] = 1U;
    require(valid_lsp_checksum(*parsed), "IS-IS aging changed checksum protected region");
    storage[13U] ^= 1U;
    require(!valid_lsp_checksum(*parsed), "IS-IS checksum failed to detect source-ID corruption");
  }

  for (const auto type : {PduType::csnp_l1, PduType::csnp_l2, PduType::psnp_l1, PduType::psnp_l2}) {
    SnpInput snp{.type = type, .source = source};
    snp.last.fill(0xffU);
    encoded = encode_snp(storage, snp, {});
    const bool complete = type == PduType::csnp_l1 || type == PduType::csnp_l2;
    require(encoded && encoded->size() == (complete ? 33U : 17U) && (*encoded)[16U] == 0U,
             "IS-IS SNP fixed header or source circuit ID mismatch");
    require(parse(*encoded, error).has_value(), "IS-IS SNP parse failed");
    if (complete)
      require((*encoded)[17U] == 0U && (*encoded)[32U] == 0xffU, "IS-IS CSNP range mismatch");
  }

  encoded = encode_hello(storage, hello, tlvs);
  require(encoded.has_value(), "IS-IS negative fixture setup failed");
  const auto original = storage;
  for (std::size_t length = 0U; length < encoded->size(); ++length)
    require(!parse(std::span(storage).first(length), error), "IS-IS truncated PDU accepted");
  for (const auto field : {0U, 2U, 5U}) {
    storage = original;
    storage[field] ^= 1U;
    require(!parse(std::span(storage).first(27U), error), "IS-IS bad protocol/version accepted");
  }
  storage = original;
  storage[3U] = 5U;
  require(!parse(std::span(storage).first(27U), error) && error == DecodeError::unsupported_id_length,
           "IS-IS legal foreign ID length not distinguished");
  storage[3U] = 9U;
  require(!parse(std::span(storage).first(27U), error) && error == DecodeError::invalid_id_length,
           "IS-IS illegal ID length accepted");
  storage = original;
  storage[21U] = 255U;
  require(!parse(std::span(storage).first(27U), error) && error == DecodeError::tlv_length,
           "IS-IS overflowing TLV accepted");

  storage.fill(0xa5U);
  const auto untouched = storage;
  require(!encode_hello(std::span(storage).first(10U), hello, tlvs) && storage == untouched,
           "IS-IS short-output failure changed storage");
  const std::array<std::uint8_t, 1U> partial_tlv{8U};
  require(!encode_hello(storage, hello, partial_tlv) && storage == untouched,
           "IS-IS malformed-TLV failure changed storage");
  std::copy(tlvs.begin(), tlvs.end(), storage.begin());
  encoded = encode_hello(storage, hello, std::span(storage).first(tlvs.size()));
  require(encoded && std::equal(encoded->begin(), encoded->end(), expected.begin(), expected.end()),
           "IS-IS overlapping TLV input corrupted");

  // A foreign/unknown zero-length TLV is legal framing and must survive as
  // received. Its interpretation belongs to the protocol extension owner.
  const std::array<std::uint8_t, 5U> unknown{250U, 0U, 251U, 1U, 42U};
  encoded = encode_hello(storage, hello, unknown);
  parsed = parse(*encoded, error);
  TlvCursor cursor(parsed->tlvs);
  require(cursor.next()->value.empty() && cursor.next()->value[0U] == 42U &&
            !cursor.next() && cursor.valid(), "IS-IS unknown TLV was lost or rewritten");

  std::array<std::uint8_t, 32U> checksum{};
  for (std::size_t i = 0U; i < checksum.size(); ++i)
    checksum[i] = static_cast<std::uint8_t>(i * 7U);
  require(router::packet::iso::insert(checksum, 12U) && router::packet::iso::valid(checksum),
           "ISO checksum signed arithmetic failed");
  const auto saved = checksum;
  require(!router::packet::iso::insert(checksum, 31U) && checksum == saved,
           "ISO checksum invalid-bound failure changed bytes");

  const SnpEntry entry{1200U, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 1U}, 0x12345678U, 0xabcdU};
  const std::array<std::uint8_t, 16U> entry_fixture{
    4U, 0xb0U, 1U, 2U, 3U, 4U, 5U, 6U, 0U, 1U, 0x12U, 0x34U, 0x56U, 0x78U, 0xabU, 0xcdU};
  require(snp_entry(entry_fixture) == entry, "IS-IS SNP entry fixture decode mismatch");
  require(encode_snp_entry(storage, entry) &&
            std::equal(entry_fixture.begin(), entry_fixture.end(), storage.begin()),
           "IS-IS SNP entry fixture encode mismatch");
  require(!snp_entry(std::span(entry_fixture).first(15U)), "IS-IS short SNP entry accepted");
  for (const std::size_t target : {1U, 2U, 255U, 256U, 257U, 258U, 511U}) {
    TlvWriter writer(storage);
    require(writer.pad_to(target) && writer.bytes().size() >= target,
             "IS-IS Hello padding could not cover target");
    TlvCursor padding(writer.bytes());
    while (const auto option = padding.next())
      require(option->code == 8U, "IS-IS Hello padding emitted another option");
    require(padding.valid(), "IS-IS Hello padding left a one-byte TLV fragment");
  }
  storage.fill(0xa5U);
  TlvWriter short_writer(std::span(storage).first(1U));
  require(!short_writer.pad_to(1U) && storage == untouched && short_writer.bytes().empty(),
           "IS-IS padding capacity failure mutated bytes");
}
