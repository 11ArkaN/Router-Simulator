// Wire fixtures for basic area, neighbor, NLPID and interface-address options.
// Test-owned storage covers truncation and ownership-preserving failed writes.

#include "router/isis_basic_tlvs.hpp"

#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_basic_tlvs_tests() {
  using namespace router::packet::isis;
  const std::array<std::uint8_t, 6U> fixture{1U, 0x49U, 3U, 0x49U, 0U, 1U};
  AreaAddressCursor areas({1U, fixture});
  const auto first = areas.next();
  const auto second = areas.next();
  require(first && first->size() == 1U && (*first)[0U] == 0x49U && second &&
            second->size() == 3U && (*second)[2U] == 1U && !areas.next() && areas.valid(),
          "IS-IS area list fixture failed");
  std::array<std::uint8_t, 257U> output{};
  TlvWriter writer(output);
  const std::array<std::span<const std::uint8_t>, 2U> entries{*first, *second};
  require(encode_area_addresses(writer, entries) && writer.bytes()[0U] == 1U &&
            writer.bytes()[1U] == fixture.size() &&
            std::equal(fixture.begin(), fixture.end(), writer.bytes().begin() + 2U),
          "IS-IS area list encoding mismatch");
  for (const auto length : {1U, 3U, 4U, 5U}) {
    AreaAddressCursor truncated({1U, std::span(fixture).first(length)});
    while (truncated.next()) {}
    require(!truncated.valid(), "IS-IS accepted truncated area list");
  }
  for (const auto length : {0U, 14U, 255U}) {
    const std::array<std::uint8_t, 1U> invalid{static_cast<std::uint8_t>(length)};
    AreaAddressCursor cursor({1U, invalid});
    require(!cursor.next() && !cursor.valid(), "IS-IS accepted invalid area length");
  }
  const std::array<std::array<std::uint8_t, 6U>, 2U> macs{{
    {2U, 0U, 0U, 0U, 0U, 1U}, {2U, 0U, 0U, 0U, 0U, 2U}}};
  TlvWriter mac_writer(output);
  require(encode_fixed_addresses<6U>(mac_writer, 6U, macs), "IS-IS LAN list encoding failed");
  TlvCursor tlvs(mac_writer.bytes());
  FixedAddressCursor<6U> neighbors(*tlvs.next(), 6U);
  require(neighbors.next() == macs[0U] && neighbors.next() == macs[1U] &&
            !neighbors.next() && neighbors.valid(), "IS-IS LAN list fixture failed");
  FixedAddressCursor<6U> partial({6U, std::span(fixture).first<5U>()}, 6U);
  require(!partial.next() && !partial.valid(), "IS-IS accepted partial LAN address");
  const std::array<std::uint8_t, 3U> protocols{ipv4_nlpid, 0x42U, ipv6_nlpid};
  require(supports_protocol({129U, protocols}, ipv4_nlpid) &&
            supports_protocol({129U, protocols}, ipv6_nlpid) &&
            !supports_protocol({129U, protocols}, 0x81U) &&
            !supports_protocol({128U, protocols}, ipv4_nlpid), "IS-IS NLPID membership failed");
  std::array<std::uint8_t, 16U> address{0xfeU, 0x80U};
  require(valid_ipv6_interface_addresses({232U, address}, PduType::point_to_point_hello) &&
            !valid_ipv6_interface_addresses({232U, address}, PduType::lsp_l1),
          "IS-IS link-local IPv6 address placement failed");
  address[0U] = 0x20U;
  address[1U] = 1U;
  require(valid_ipv6_interface_addresses({232U, address}, PduType::lsp_l2) &&
            !valid_ipv6_interface_addresses({232U, address}, PduType::lan_hello_l2) &&
            !valid_ipv6_interface_addresses({232U, address}, PduType::psnp_l2) &&
            !valid_ipv6_interface_addresses({232U, std::span(address).first(15U)}, PduType::lsp_l1),
          "IS-IS non-link-local IPv6 address placement failed");
  std::array<std::uint8_t, 4U> short_output{0xaaU, 0xaaU, 0xaaU, 0xaaU};
  const auto unchanged = short_output;
  TlvWriter bounded(short_output);
  require(!encode_area_addresses(bounded, entries) && short_output == unchanged,
          "IS-IS short area writer mutated output");
}
