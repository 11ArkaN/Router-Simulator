// Source fragmentation and destination reassembly tests use real ICMPv6 bytes.
// Reverse ordering, overlap and atomic collision cases exercise state rather
// than comparing only the fragment header encoder.

#include "router/ipv6_fragmentation.hpp"
#include "router/udp_packet.hpp"

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::ip::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("fragmentation fixture address is invalid");
  return *parsed;
}

bool collect_fragment(void *opaque,
                      const router::packet::Frame &fragment) noexcept {
  auto &frames = *static_cast<std::vector<router::packet::Frame> *>(opaque);
  frames.push_back(fragment);
  return true;
}

} // namespace

void ipv6_fragmentation_tests() {
  using namespace router::packet;
  const Mac source_mac{0x02, 0, 0, 0, 0, 1};
  const Mac destination_mac{0x02, 0, 0, 0, 0, 2};
  const auto original = icmpv6_echo(source_mac, destination_mac,
                                    address("2001:db8::1"),
                                    address("2001:db8::2"), false, 77U, 64U,
                                    3'000U);
  const auto fragments = fragment_ipv6(original, ipv6_minimum_link_mtu,
                                       0x12345678U);
  require(fragments && fragments->count == 3U,
          "IPv6 source did not create the expected MTU-bounded fragments");
  for (std::size_t index = 0; index < fragments->count; ++index) {
    const auto parsed = parse_ipv6(fragments->frames[index]);
    require(parsed && parsed->fragment &&
                parsed->fragment->identification == 0x12345678U &&
                ipv6_header_octets + parsed->payload_length <=
                    ipv6_minimum_link_mtu &&
                parsed->fragment->more_fragments ==
                    (index + 1U < fragments->count),
            "IPv6 fragment carried invalid offset, size or M state");
  }

  Ipv6ReassemblyTable table;
  Ipv6ReassemblyResult result;
  for (std::size_t index = fragments->count; index-- > 0U;)
    result = table.accept(fragments->frames[index]);
  require(result.status == Ipv6ReassemblyStatus::complete &&
              !result.packet.empty() &&
              result.packet.size() == original.size() &&
              std::equal(
                  result.packet.begin() + ethernet_header_octets,
                  result.packet.end(),
                  original.view().begin() + ethernet_header_octets),
          "out-of-order IPv6 fragments did not restore original IP bytes");

  Ipv6ReassemblyTable overlap;
  require(overlap.accept(fragments->frames[0]).status ==
              Ipv6ReassemblyStatus::incomplete &&
              overlap.accept(fragments->frames[0]).status ==
                  Ipv6ReassemblyStatus::overlap &&
              overlap.active() == 0U,
          "overlapping IPv6 fragment did not discard the entire datagram");

  // Convert a first fragment into an atomic fragment with the same tuple and
  // identification as an active normal datagram. RFC 6946 requires isolation.
  Ipv6ReassemblyTable atomic_table;
  require(atomic_table.accept(fragments->frames[1]).status ==
              Ipv6ReassemblyStatus::incomplete,
          "normal fragment did not create reassembly state");
  auto atomic = fragments->frames[0];
  const auto atomic_view = parse_ipv6(atomic);
  require(atomic_view && atomic_view->fragment,
          "fixture fragment header was unavailable");
  atomic.bytes[atomic_view->fragment_header_offset + 2U] = 0U;
  atomic.bytes[atomic_view->fragment_header_offset + 3U] = 0U;
  const auto atomic_result = atomic_table.accept(atomic);
  require(atomic_result.status == Ipv6ReassemblyStatus::atomic &&
              !atomic_result.packet.empty() && atomic_table.active() == 1U,
          "atomic fragment interfered with normal reassembly state");

  // Persist an out-of-order final fragment. Restore must retain both its byte
  // range and the gap before it, then complete only after the missing ranges
  // arrive rather than treating a payload count as contiguous coverage.
  const auto checkpoint_now = Ipv6ReassemblyTable::Clock::now();
  Ipv6ReassemblyTable partial;
  require(partial.accept(fragments->frames[2], checkpoint_now).status ==
              Ipv6ReassemblyStatus::incomplete,
          "checkpoint fixture did not retain its final fragment");
  const auto checkpoint = partial.checkpoint(checkpoint_now);
  Ipv6ReassemblyTable restored;
  require(checkpoint.size() == 1U &&
              restored.restore(checkpoint, checkpoint_now) &&
              restored.accept(fragments->frames[1], checkpoint_now).status ==
                  Ipv6ReassemblyStatus::incomplete,
          "IPv6 reassembly checkpoint lost an out-of-order gap");
  const auto restored_result =
      restored.accept(fragments->frames[0], checkpoint_now);
  require(restored_result.status == Ipv6ReassemblyStatus::complete &&
              !restored_result.packet.empty() && restored.active() == 0U,
          "restored IPv6 fragments did not complete the original datagram");
  auto duplicate = checkpoint;
  duplicate.push_back(checkpoint.front());
  require(!Ipv6ReassemblyTable::validate_checkpoint(duplicate),
          "duplicate IPv6 reassembly tuple survived validation");

  // A legal UDP datagram is an IP-layer object, not one Ethernet frame. This
  // fixture exercises the complete ordinary 16-bit UDP and IPv6 payload range
  // through fifty-plus encoded fragments and reverse-order destination
  // reassembly. It guards against reintroducing a profile-MTU transport cap.
  const auto large_source = address("2001:db8:1::1");
  const auto large_destination = address("2001:db8:1::2");
  std::vector<std::uint8_t> large(
      maximum_ethernet_ipv6_datagram_octets, 0U);
  std::copy(destination_mac.begin(), destination_mac.end(), large.begin());
  std::copy(source_mac.begin(), source_mac.end(), large.begin() + 6U);
  large[12] = 0x86U;
  large[13] = 0xddU;
  large[14] = 0x60U;
  large[18] = 0xffU;
  large[19] = 0xffU;
  large[20] = ipv6_next_header_udp;
  large[21] = 64U;
  std::copy(large_source.begin(), large_source.end(), large.begin() + 22U);
  std::copy(large_destination.begin(), large_destination.end(),
            large.begin() + 38U);
  std::vector<std::uint8_t> payload(udp::maximum_payload_octets, 0x5aU);
  const auto udp_length = udp::encode_ipv6(
      std::span<std::uint8_t>{large}.subspan(54U), large_source,
      large_destination, 49152U, 547U, payload);
  require(udp_length && *udp_length == udp::maximum_datagram_octets,
          "full ordinary UDP fixture could not be encoded");
  std::vector<Frame> large_fragments;
  const auto large_count = fragment_ipv6_datagram(
      large, ipv6_minimum_link_mtu, 0xaabbccddU, &large_fragments,
      collect_fragment);
  require(large_count && *large_count == large_fragments.size() &&
              *large_count > Ipv6FragmentBatch::maximum_fragment_count,
          "streaming source fragmentation retained the one-frame ceiling");
  Ipv6ReassemblyTable large_table;
  Ipv6ReassemblyResult large_result;
  for (std::size_t index = large_fragments.size(); index-- > 0U;)
    large_result = large_table.accept(large_fragments[index]);
  const auto large_ipv6 = parse_ipv6(large_result.packet);
  require(large_result.status == Ipv6ReassemblyStatus::complete &&
              large_result.packet.size() == large.size() && large_ipv6 &&
              large_ipv6->upper_layer_protocol == ipv6_next_header_udp,
          "full ordinary IPv6 payload was not reassembled");
  const auto parsed_udp = udp::parse_ipv6(
      large_result.packet.subspan(large_ipv6->upper_layer_offset,
                                  udp::maximum_datagram_octets),
      large_ipv6->source, large_ipv6->destination);
  require(parsed_udp && parsed_udp->source_port == 49152U &&
              parsed_udp->destination_port == 547U &&
              parsed_udp->payload.size() == udp::maximum_payload_octets &&
              parsed_udp->payload.front() == 0x5aU &&
              parsed_udp->payload.back() == 0x5aU,
          "reassembled full-size UDP bytes failed checksum or demultiplexing");
}
