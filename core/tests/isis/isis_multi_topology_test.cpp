// Independent MT option fixtures verify reserved-bit handling, membership
// unions and the separate reachability envelope. Standard cursors consume the
// same borrowed bodies, preserving canonical-prefix and sub-TLV checks.

#include "router/isis_multi_topology.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_multi_topology_tests() {
  using namespace router::packet::isis;
  const std::array<std::uint8_t, 6U> membership{0xf0U, 0U, 0xf0U, 2U, 0x3fU, 0xffU};
  TopologyCursor hello({229U, membership});
  require(hello.next() == TopologyComponent{0U, false, false} &&
            hello.next() == TopologyComponent{2U, false, false} &&
            hello.next() == TopologyComponent{4095U, false, false} && !hello.next() && hello.valid(),
          "IS-IS MT Hello interpreted reserved or LSP-only flags");
  TopologyCursor fragment_zero({229U, membership}, true);
  require(fragment_zero.next() == TopologyComponent{0U, false, false} &&
            fragment_zero.next() == TopologyComponent{2U, true, true} &&
            fragment_zero.next() == TopologyComponent{4095U, false, false},
          "IS-IS MT fragment-zero flag interpretation failed");
  for (const auto size : {0U, 1U, 3U, 5U}) {
    TopologyCursor invalid({229U, std::span(membership).first(size)});
    require(!invalid.next() && !invalid.valid(), "IS-IS MT accepted an empty or partial component");
  }
  std::array<std::uint8_t, 1024U> options{};
  TlvWriter writer(options);
  const std::array<TopologyComponent, 2U> both{{{0U}, {2U, true, true}}};
  require(encode_topologies(writer, both, true) && writer.bytes().size() == 6U &&
            writer.bytes()[4U] == 0xc0U && writer.bytes()[5U] == 2U,
          "IS-IS MT encoder did not clear reserved membership bits");
  const auto saved = options;
  const auto length = writer.bytes().size();
  require(!encode_topologies(writer, both, false) && options == saved && writer.bytes().size() == length,
          "IS-IS MT originated LSP flags in a Hello or changed rejected output");
  const std::array<TopologyComponent, 1U> invalid_id{{{4096U}}};
  const std::array<TopologyComponent, 1U> invalid_zero{{{0U, true, false}}};
  require(!encode_topologies(writer, invalid_id, true) && !encode_topologies(writer, invalid_zero, true) &&
            options == saved, "IS-IS MT accepted an oversized ID or MT0 overload flag");
  std::array<TopologyComponent, 128U> many{};
  for (std::size_t index = 0U; index < many.size(); ++index) many[index].id = static_cast<std::uint16_t>(index);
  std::array<std::uint8_t, 256U> full{};
  TlvWriter full_writer(full);
  require(!encode_topologies(full_writer, many, false) && full_writer.bytes().empty() &&
            encode_topologies(full_writer, std::span(many).first(127U), false) && full_writer.bytes().size() == 256U,
          "IS-IS MT option component-count boundary failed");

  std::array<std::uint8_t, 1024U> wire{};
  HelloInput header{PduType::point_to_point_hello, {1U, 2U, 3U, 4U, 5U, 6U}, 27U, 3U, 1U};
  DecodeError error{};
  auto encoded = encode_hello(wire, header, {});
  auto pdu = parse(*encoded, error);
  require(pdu && supports_topology(*pdu, 0U) == true && supports_topology(*pdu, 2U) == false,
          "IS-IS legacy Hello did not imply MT0 only");
  TlvWriter only_mt2(options);
  const std::array<TopologyComponent, 1U> mt2{{{2U}}};
  const std::array<TopologyComponent, 1U> mt0{{{0U}}};
  require(encode_topologies(only_mt2, mt2, false), "IS-IS MT2 fixture encoding failed");
  encoded = encode_hello(wire, header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(supports_topology(*pdu, 0U) == false && supports_topology(*pdu, 2U) == true,
          "IS-IS explicit MT2 incorrectly implied MT0");
  require(encode_topologies(only_mt2, mt0, false) && encode_topologies(only_mt2, mt2, false),
          "IS-IS repeated MT fixture encoding failed");
  encoded = encode_hello(wire, header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(supports_topology(*pdu, 0U) == true && supports_topology(*pdu, 2U) == true &&
            !supports_topology(*pdu, 4096U), "IS-IS MT membership did not union repeated options");
  LspInput lsp_header{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  encoded = encode_lsp(wire, lsp_header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(supports_topology(*pdu, 2U) == true, "IS-IS MT fragment-zero membership failed");
  lsp_header.id[6U] = 1U;
  encoded = encode_lsp(wire, lsp_header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(!supports_topology(*pdu, 2U), "IS-IS MT interpreted router membership on a shared pseudonode");
  lsp_header.id[6U] = 0U;
  lsp_header.id.back() = 1U;
  encoded = encode_lsp(wire, lsp_header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(!supports_topology(*pdu, 2U), "IS-IS MT interpreted membership outside LSP fragment zero");
  SnpInput snp_header{PduType::psnp_l1, header.source};
  encoded = encode_snp(wire, snp_header, only_mt2.bytes());
  pdu = parse(*encoded, error);
  require(!supports_topology(*pdu, 2U), "IS-IS MT interpreted membership in an SNP");

  // MT2 plus the RFC 5305 /25 prefix with deliberately nonzero unused bits.
  const std::array<std::uint8_t, 11U> ipv4{0xf0U, 2U, 0U, 0U, 0U, 10U, 0x99U, 192U, 0U, 2U, 0xffU};
  const auto four = mt_reachability({235U, ipv4});
  require(four && four->topology == 2U && four->entries.code == 135U,
          "IS-IS MT IPv4 did not ignore reserved membership bits");
  ExtendedPrefixCursor prefix_cursor(four->entries);
  const auto prefix = prefix_cursor.next();
  require(prefix && prefix->down && prefix->prefix.length == 25U &&
            prefix->prefix.network.bytes[3U] == 128U && !prefix_cursor.next() && prefix_cursor.valid(),
          "IS-IS MT IPv4 did not share standard prefix validation");
  TlvWriter prefix_writer(options);
  require(encode_mt_prefix(prefix_writer, 2U, *prefix), "IS-IS MT IPv4 prefix encoding failed");
  TlvCursor outer(prefix_writer.bytes());
  const auto wrapped = outer.next();
  require(wrapped && wrapped->code == 235U && wrapped->value[0U] == 0U &&
            wrapped->value[1U] == 2U && wrapped->value.back() == 128U,
          "IS-IS MT IPv4 did not originate a canonical prefix or cleared flags");
  const auto before = options;
  const auto before_length = prefix_writer.bytes().size();
  require(!encode_mt_prefix(prefix_writer, 0U, *prefix) && !encode_mt_prefix(prefix_writer, 4096U, *prefix) &&
            options == before && prefix_writer.bytes().size() == before_length,
          "IS-IS MT prefix invalid ID changed output");
  const std::array<std::uint8_t, 3U> ignored{0xf0U, 0U, 0xffU};
  const auto zero = mt_reachability({237U, ignored});
  require(zero && zero->topology == 0U && zero->entries.value.size() == 1U,
          "IS-IS zero-MT reachability was not exposed for whole-option ignoring");
  require(!mt_reachability({222U, std::span(ignored).first(1U)}) && !mt_reachability({22U, ignored}),
          "IS-IS MT accepted a truncated or unrelated reachability envelope");

  const std::array<std::uint8_t, 4U> sub_tlvs{250U, 2U, 0xabU, 0xcdU};
  const ExtendedNeighbor neighbor{{1U, 2U, 3U, 4U, 5U, 6U, 0U}, 100U, sub_tlvs};
  TlvWriter neighbor_writer(options);
  require(encode_mt_neighbor(neighbor_writer, 2U, neighbor), "IS-IS MT neighbor encoding failed");
  TlvCursor neighbor_outer(neighbor_writer.bytes());
  const auto neighbor_view = mt_reachability(*neighbor_outer.next());
  ExtendedNeighborCursor neighbors(neighbor_view->entries);
  const auto decoded_neighbor = neighbors.next();
  require(neighbor_view->topology == 2U && decoded_neighbor && decoded_neighbor->id == neighbor.id &&
            decoded_neighbor->metric == 100U && std::ranges::equal(decoded_neighbor->sub_tlvs, sub_tlvs) &&
            !neighbors.next() && neighbors.valid(), "IS-IS MT neighbor fields or sub-TLVs changed");
  auto ipv6 = *prefix;
  ipv6.prefix = {};
  ipv6.prefix.network.family = router::ip::AddressFamily::ipv6;
  ipv6.prefix.network.bytes[0U] = 0x20U;
  ipv6.prefix.network.bytes[1U] = 1U;
  ipv6.prefix.length = 64U;
  ipv6.external = true;
  ipv6.sub_tlvs_present = true;
  ipv6.sub_tlvs = sub_tlvs;
  TlvWriter ipv6_writer(options);
  require(encode_mt_prefix(ipv6_writer, 2U, ipv6), "IS-IS MT IPv6 encoding failed");
  TlvCursor ipv6_outer(ipv6_writer.bytes());
  const auto ipv6_view = mt_reachability(*ipv6_outer.next());
  ExtendedPrefixCursor ipv6_cursor(ipv6_view->entries);
  const auto decoded_ipv6 = ipv6_cursor.next();
  require(ipv6_view->entries.code == 236U && decoded_ipv6 && decoded_ipv6->prefix == ipv6.prefix &&
            decoded_ipv6->down && decoded_ipv6->external &&
            std::ranges::equal(decoded_ipv6->sub_tlvs, sub_tlvs) && !ipv6_cursor.next() && ipv6_cursor.valid(),
          "IS-IS MT IPv6 flags, prefix or sub-TLVs changed");
  std::array<std::uint8_t, 244U> maximum_sub_tlvs{};
  maximum_sub_tlvs[0U] = 250U;
  maximum_sub_tlvs[1U] = 240U;
  auto large_neighbor = neighbor;
  large_neighbor.sub_tlvs = std::span(maximum_sub_tlvs).first(242U);
  std::array<std::uint8_t, 257U> maximum_option{};
  TlvWriter maximum_writer(maximum_option);
  require(encode_mt_neighbor(maximum_writer, 2U, large_neighbor) && maximum_writer.bytes().size() == 257U &&
            maximum_writer.bytes()[1U] == 255U, "IS-IS MT reduced reachability capacity boundary failed");
  const auto maximum_saved = maximum_option;
  maximum_sub_tlvs[1U] = 242U;
  large_neighbor.sub_tlvs = maximum_sub_tlvs;
  require(!encode_mt_neighbor(maximum_writer, 2U, large_neighbor) && maximum_option == maximum_saved,
          "IS-IS MT header overflow changed the previous batch");
  std::array<std::uint8_t, 16U> too_small{};
  too_small.fill(0xa5U);
  const auto small_saved = too_small;
  TlvWriter small_writer(too_small);
  require(!encode_mt_neighbor(small_writer, 2U, neighbor) && small_writer.bytes().empty() && too_small == small_saved,
          "IS-IS MT failed to preserve output on capacity refusal");
}
