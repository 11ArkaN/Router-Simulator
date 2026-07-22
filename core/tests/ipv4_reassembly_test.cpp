// IPv4 reassembly tests cover out-of-order delivery, overlap precedence,
// timeout, bounded admission and exact checkpoint continuation from wire data.

#include "router/ipv4_reassembly.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

using namespace router::packet;

bool collect(void *context, const Frame &fragment) noexcept {
  static_cast<std::vector<Frame> *>(context)->push_back(fragment);
  return true;
}

std::vector<Frame> make_fragments(std::uint16_t identification,
                                  std::uint8_t fill) {
  const Mac source_mac{0x02, 0, 0, 0, 0, 1};
  const Mac destination_mac{0x02, 0, 0, 0, 0, 2};
  const Ipv4 source{192, 0, 2, 1};
  const Ipv4 destination{192, 0, 2, 2};
  std::vector<std::uint8_t> payload(4000U, fill);
  std::vector<std::uint8_t> datagram(maximum_ethernet_ipv4_datagram_octets);
  const auto encoded = encode_ipv4_ethernet_datagram(
      datagram, source_mac, destination_mac, source, destination, 17U, 64U,
      identification, payload, false);
  if (!encoded)
    throw std::runtime_error("IPv4 reassembly fixture encoding failed");
  std::vector<Frame> fragments;
  const auto count = fragment_ipv4_datagram(
      std::span<const std::uint8_t>{datagram.data(), *encoded}, 576U,
      &fragments, collect);
  if (!count || *count != fragments.size() || fragments.size() < 3U)
    throw std::runtime_error("IPv4 reassembly fixture fragmentation failed");
  return fragments;
}

} // namespace

void ipv4_reassembly_tests() {
  using Clock = Ipv4ReassemblyTable::Clock;
  const auto now = Clock::time_point{std::chrono::seconds{100}};
  auto fragments = make_fragments(0x1234U, 0x41U);

  Ipv4ReassemblyTable table;
  // Fragment zero is deliberately followed by a later duplicate whose first
  // payload byte differs. RFC 791's copy procedure gives the later bytes
  // precedence, while receipt tracking must not count the duplicate twice.
  if (table.accept(fragments.front(), now).status !=
      Ipv4ReassemblyStatus::incomplete)
    throw std::runtime_error("IPv4 first fragment was not retained");
  auto replacement = fragments.front();
  replacement.bytes[34U] = 0x5aU;
  if (table.accept(replacement, now).status !=
      Ipv4ReassemblyStatus::incomplete)
    throw std::runtime_error("IPv4 overlapping retransmission was rejected");

  Ipv4ReassemblyResult completed;
  for (std::size_t index = fragments.size(); index-- > 1U;) {
    completed = table.accept(fragments[index], now);
    if (index > 1U && completed.status != Ipv4ReassemblyStatus::incomplete)
      throw std::runtime_error("IPv4 gap was mistaken for completion");
  }
  const auto complete_view = parse_ipv4(completed.packet);
  if (completed.status != Ipv4ReassemblyStatus::complete || !complete_view ||
      complete_view->fragment_offset != 0U || complete_view->more_fragments ||
      complete_view->total_length != 4020U ||
      completed.packet[34U] != 0x5aU || completed.packet.back() != 0x41U ||
      table.active() != 0U) {
    throw std::runtime_error(
        "IPv4 out-of-order reassembly changed bytes or header state");
  }

  // A structural checkpoint contains both bytes and the receipt bitmap. After
  // restore, an out-of-order suffix cannot turn an unreceived gap into data.
  fragments = make_fragments(0x2345U, 0x62U);
  if (table.accept(fragments[1U], now).status !=
      Ipv4ReassemblyStatus::incomplete)
    throw std::runtime_error("IPv4 middle fragment was not retained");
  const auto saved = table.checkpoint(now + std::chrono::seconds{1});
  Ipv4ReassemblyTable restored;
  if (saved.size() != 1U ||
      !restored.restore(saved, now + std::chrono::seconds{5}))
    throw std::runtime_error("IPv4 reassembly checkpoint did not restore");
  for (std::size_t index = fragments.size(); index-- > 0U;) {
    if (index == 1U)
      continue;
    completed = restored.accept(fragments[index], now +
                                                      std::chrono::seconds{6});
  }
  if (completed.status != Ipv4ReassemblyStatus::complete ||
      completed.packet[34U] != 0x62U)
    throw std::runtime_error(
        "IPv4 restored receipt bitmap lost the incomplete datagram");

  // Capacity exhaustion is explicit and timeout uses the profile's fixed RFC
  // 1122 interval. The owner does not evict a live datagram to admit an attack.
  Ipv4ReassemblyTable bounded;
  for (std::size_t slot = 0U;
       slot < router::device_catalog::ipv4_reassembly_entries_per_endpoint;
       ++slot) {
    auto candidate = make_fragments(static_cast<std::uint16_t>(0x3000U + slot),
                                    static_cast<std::uint8_t>(slot));
    if (bounded.accept(candidate.front(), now).status !=
        Ipv4ReassemblyStatus::incomplete)
      throw std::runtime_error("IPv4 reassembly table filled too early");
  }
  auto overflow = make_fragments(0x4000U, 0xeeU);
  if (bounded.accept(overflow.front(), now).status !=
      Ipv4ReassemblyStatus::resource_exhausted)
    throw std::runtime_error("IPv4 reassembly capacity was not enforced");
  Frame expired;
  std::size_t expired_count{};
  while (bounded.take_expired(
      expired, now + router::device_catalog::ipv4_reassembly_timeout))
    ++expired_count;
  if (expired_count !=
          router::device_catalog::ipv4_reassembly_entries_per_endpoint ||
      bounded.active() != 0U || bounded.next_deadline())
    throw std::runtime_error("IPv4 fixed reassembly timeout did not expire");
}
