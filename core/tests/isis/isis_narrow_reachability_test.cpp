// Original reachability fixtures distinguish reachability origin from metric
// type and preserve address masks. Each test owns its packet buffers.

#include "router/isis_narrow_reachability.hpp"

#include <algorithm>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_narrow_reachability_tests() {
  using namespace router::packet::isis;
  const std::array<std::uint8_t, 12U> neighbor{0U, 10U, 0x80U, 5U, 0xbfU,
    1U, 2U, 3U, 4U, 5U, 6U, 7U};
  NarrowNeighborCursor cursor({2U, neighbor});
  const auto entry = cursor.next();
  require(entry && entry->metrics.metric == 10U && !entry->metrics.external_metric &&
            !entry->metrics.delay && entry->metrics.expense == 5U && !entry->metrics.error &&
            entry->id == LanId{1U, 2U, 3U, 4U, 5U, 6U, 7U} && !entry->virtual_link &&
            !cursor.next() && cursor.valid(), "IS-IS narrow neighbor fixture failed");
  std::array<std::uint8_t, 64U> output{};
  TlvWriter writer(output);
  require(encode_narrow_neighbor(writer, *entry) && writer.bytes()[0U] == 2U &&
            writer.bytes()[1U] == 12U && writer.bytes()[6U] == 0x80U,
          "IS-IS narrow neighbor encoding failed");
  const std::array<std::uint8_t, 12U> ipv4{0xcaU, 0x7fU, 0xffU, 0x40U,
    192U, 0U, 2U, 1U, 255U, 0U, 255U, 0U};
  NarrowIpv4Cursor prefixes({130U, ipv4});
  auto prefix = prefixes.next();
  require(prefix && prefix->metrics.metric == 10U && prefix->metrics.external_metric &&
            prefix->external_reachability && prefix->down && prefix->metrics.delay == 63U &&
            !prefix->metrics.expense && prefix->metrics.error == 0U &&
            prefix->address == router::ip::Ipv4{192U, 0U, 2U, 1U} &&
            prefix->mask == router::ip::Ipv4{255U, 0U, 255U, 0U} &&
            !prefixes.next() && prefixes.valid(), "IS-IS narrow IPv4 fixture failed");
  TlvWriter prefix_writer(output);
  require(encode_narrow_ipv4(prefix_writer, *prefix) && prefix_writer.bytes()[0U] == 130U &&
            prefix_writer.bytes()[2U] == 0xcaU && prefix_writer.bytes()[3U] == 63U &&
            prefix_writer.bytes()[4U] == 0x80U && prefix_writer.bytes()[5U] == 0U,
          "IS-IS narrow IPv4 reserved output bits failed");
  prefix->external_reachability = false;
  TlvWriter rejected(output);
  require(!encode_narrow_ipv4(rejected, *prefix) && rejected.bytes().empty(),
          "IS-IS internal narrow reachability used external metrics");
  prefix->metrics.external_metric = false;
  require(encode_narrow_ipv4(rejected, *prefix) && rejected.bytes()[0U] == 128U,
          "IS-IS internal narrow reachability encoding failed");
  prefix->down = false;
  TlvWriter upward(output);
  require(encode_narrow_ipv4(upward, *prefix) && upward.bytes()[2U] == 10U,
          "IS-IS narrow prefix did not clear the up/down bit");
  prefix->metrics.delay = std::uint8_t{64U};
  const auto saved = output;
  require(!encode_narrow_ipv4(rejected, *prefix) && output == saved,
          "IS-IS narrow metric overflow mutated output");
  for (std::size_t length = 0U; length < neighbor.size(); ++length) {
    NarrowNeighborCursor truncated({2U, std::span(neighbor).first(length)});
    require(truncated.valid() == (length == 1U) && !truncated.next(),
            "IS-IS narrow neighbor length validation failed");
    NarrowIpv4Cursor short_prefix({128U, std::span(ipv4).first(length)});
    require(short_prefix.valid() == (length == 0U) && !short_prefix.next(),
            "IS-IS narrow IPv4 length validation failed");
  }
  auto virtual_neighbor = *entry;
  virtual_neighbor.virtual_link = true;
  TlvWriter virtual_writer(output);
  require(encode_narrow_neighbor(virtual_writer, virtual_neighbor), "IS-IS virtual flag encoding failed");
  TlvCursor tlvs(virtual_writer.bytes());
  NarrowNeighborCursor virtual_cursor(*tlvs.next());
  require(virtual_cursor.next()->virtual_link, "IS-IS virtual flag projection failed");
}
