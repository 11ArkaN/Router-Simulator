// Independent RFC wire fixtures and malformed-entry boundaries. Test-owned
// packets exercise borrowed traversal without a runtime or shared state.

#include "router/isis_reachability.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
}

void isis_reachability_tests() {
  using namespace router::packet::isis;
  using router::ip::AddressFamily;
  const std::array<std::uint8_t, 15U> neighbor{
    1U, 2U, 3U, 4U, 5U, 6U, 7U, 0x12U, 0x34U, 0x56U, 4U, 250U, 2U, 0xabU, 0xcdU};
  ExtendedNeighborCursor neighbors({22U, neighbor});
  const auto link = neighbors.next();
  require(link && link->id == LanId{1U, 2U, 3U, 4U, 5U, 6U, 7U} &&
            link->metric == 0x123456U && link->sub_tlvs.size() == 4U &&
            !neighbors.next() && neighbors.valid(), "IS-IS extended neighbor fixture failed");
  std::array<std::uint8_t, 512U> output{};
  TlvWriter links(output);
  require(encode_extended_neighbor(links, *link) && links.bytes()[0U] == 22U &&
            links.bytes()[1U] == neighbor.size() &&
            std::equal(neighbor.begin(), neighbor.end(), links.bytes().begin() + 2U),
          "IS-IS extended neighbor encoding mismatch");
  for (std::size_t length = 1U; length < neighbor.size(); ++length) {
    ExtendedNeighborCursor truncated({22U, std::span(neighbor).first(length)});
    require(!truncated.next() && !truncated.valid() && !truncated.next(),
            "IS-IS accepted truncated extended neighbor");
  }

  // /25 deliberately sets unused low bits: receive must mask, not reject.
  const std::array<std::uint8_t, 9U> ipv4{0U, 0U, 0U, 10U, 0x99U, 192U, 0U, 2U, 0xffU};
  ExtendedPrefixCursor ipv4_cursor({135U, ipv4});
  auto prefix = ipv4_cursor.next();
  require(prefix && prefix->down && !prefix->external && prefix->metric == 10U &&
            prefix->prefix.length == 25U && prefix->prefix.network.bytes[3U] == 128U &&
            !ipv4_cursor.next() && ipv4_cursor.valid(), "IS-IS IPv4 fixture failed");
  TlvWriter prefixes(output);
  require(encode_extended_prefix(prefixes, *prefix) && prefixes.bytes()[0U] == 135U &&
            prefixes.bytes()[10U] == 128U, "IS-IS IPv4 canonical encoding failed");

  const std::array<std::uint8_t, 18U> ipv6{0xfeU, 0U, 0U, 0U, 0xffU, 64U,
    0x20U, 1U, 0x0dU, 0xb8U, 0U, 1U, 0U, 2U, 3U, 251U, 1U, 42U};
  ExtendedPrefixCursor ipv6_cursor({236U, ipv6});
  const auto six = ipv6_cursor.next();
  require(six && six->prefix.network.family == AddressFamily::ipv6 && six->down && six->external &&
            six->sub_tlvs_present && six->sub_tlvs.size() == 3U &&
            six->metric == maximum_path_metric && !ipv6_cursor.next() && ipv6_cursor.valid(),
          "IS-IS IPv6 fixture failed");
  TlvWriter six_writer(output);
  require(encode_extended_prefix(six_writer, *six) && six_writer.bytes()[6U] == 0xe0U,
          "IS-IS IPv6 reserved output bits were not cleared");
  for (std::size_t length = 1U; length < ipv6.size(); ++length) {
    ExtendedPrefixCursor truncated({236U, std::span(ipv6).first(length)});
    require(!truncated.next() && !truncated.valid(), "IS-IS accepted truncated IPv6 prefix");
  }
  for (const auto family : {AddressFamily::ipv4, AddressFamily::ipv6}) {
    const auto maximum = family == AddressFamily::ipv4 ? 32U : 128U;
    for (unsigned length = 0U; length <= maximum; ++length) {
      ExtendedPrefix entry;
      entry.prefix.network.family = family;
      entry.prefix.length = static_cast<std::uint8_t>(length);
      entry.prefix.network.bytes[0U] = length >= 8U ? 0x20U : 0U;
      TlvWriter writer(output);
      require(encode_extended_prefix(writer, entry), "IS-IS prefix length encoding failed");
      TlvCursor tlvs(writer.bytes());
      ExtendedPrefixCursor reader(*tlvs.next());
      const auto decoded = reader.next();
      require(decoded && decoded->prefix == entry.prefix && !reader.next() && reader.valid(),
              "IS-IS prefix length boundary failed");
    }
  }
  auto invalid = *six;
  invalid.prefix.network.bytes[0U] = 0xfeU;
  invalid.prefix.network.bytes[1U] = 0x80U;
  TlvWriter rejected(output);
  require(!encode_extended_prefix(rejected, invalid) && rejected.bytes().empty(),
          "IS-IS originated link-local IPv6 reachability");
  invalid = *prefix;
  invalid.external = true;
  require(!encode_extended_prefix(rejected, invalid), "IS-IS encoded nonexistent IPv4 external flag");
  invalid.external = false;
  invalid.prefix.network.bytes[3U] = 129U;
  require(!encode_extended_prefix(rejected, invalid), "IS-IS encoded noncanonical prefix");
  auto bad_link = *link;
  bad_link.metric = maximum_link_metric + 1U;
  require(!encode_extended_neighbor(rejected, bad_link), "IS-IS truncated a 25-bit link metric");
  const std::array<std::uint8_t, 2U> malformed_sub{1U, 1U};
  bad_link = *link;
  bad_link.sub_tlvs = malformed_sub;
  require(!encode_extended_neighbor(rejected, bad_link), "IS-IS emitted malformed sub-TLV");
  auto bad_wire = neighbor;
  bad_wire[12U] = 3U;
  ExtendedNeighborCursor malformed({22U, bad_wire});
  require(!malformed.next() && !malformed.valid(), "IS-IS accepted malformed nested length");
  auto bad_prefix = ipv6;
  bad_prefix[5U] = 129U;
  ExtendedPrefixCursor oversized({236U, bad_prefix});
  require(!oversized.next() && !oversized.valid(), "IS-IS accepted IPv6 length above 128");
  std::array<std::uint8_t, 10U> short_output{};
  short_output.fill(0xaaU);
  const auto unchanged = short_output;
  TlvWriter bounded(short_output);
  require(!encode_extended_neighbor(bounded, *link) && short_output == unchanged,
          "IS-IS capacity failure mutated output");
  require(path_metric_sum(10U, 20U) == 30U &&
            path_metric_sum(maximum_path_metric - 1U, 2U) == maximum_path_metric &&
            path_metric_sum(0xffffffffU, 1U) == maximum_path_metric &&
            path_metric_sum(0U, maximum_path_metric) == maximum_path_metric,
          "IS-IS path metric saturation failed");
}
