// RFC 8200 source fragmentation and destination-only reassembly. One endpoint
// owner mutates each table. Runtime payload arenas are allocated at owner
// construction, while every inter-device unit remains an encoded Frame.

#include "router/ipv6_fragmentation.hpp"

#include <algorithm>
#include <utility>

namespace router::packet {
namespace {

constexpr std::size_t ipv6_offset = ethernet_header_octets;
constexpr std::size_t fixed_payload_length_offset = ipv6_offset + 4U;
constexpr std::size_t fixed_next_header_offset = ipv6_offset + 6U;
constexpr std::size_t first_extension_offset =
    ethernet_header_octets + ipv6_header_octets;

void write16(Frame &frame, std::size_t offset, std::uint16_t value) noexcept {
  frame.bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  frame.bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(Frame &frame, std::size_t offset, std::uint32_t value) noexcept {
  frame.bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  frame.bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  frame.bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  frame.bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

struct FragmentInsertion {
  std::size_t offset{};
  std::size_t previous_next_header_offset{};
  std::uint8_t fragment_next_header{};
};

struct FragmentLayout {
  FragmentInsertion insertion{};
  std::size_t packet_end{};
  std::size_t unfragmentable_ip_size{};
  std::size_t per_fragment{};
  std::size_t fragmentable_size{};
  std::size_t count{};
};

[[nodiscard]] std::optional<FragmentInsertion>
insertion_point(std::span<const std::uint8_t> packet,
                std::size_t packet_end) noexcept {
  auto current = packet[fixed_next_header_offset];
  std::size_t offset = first_extension_offset;
  std::size_t previous = fixed_next_header_offset;
  bool routing_seen{};
  for (;;) {
    // RFC 8200 section 4.5 keeps Hop-by-Hop and Routing headers in the
    // Unfragmentable Part. Destination Options stays there only when it is
    // processed by nodes named in a following Routing header.
    if (current != ipv6_next_header_hop_by_hop &&
        current != ipv6_next_header_routing &&
        current != ipv6_next_header_destination_options)
      return FragmentInsertion{offset, previous, current};
    if (offset + 2U > packet_end)
      return std::nullopt;
    const auto length =
        (static_cast<std::size_t>(packet[offset + 1U]) + 1U) * 8U;
    if (offset + length > packet_end)
      return std::nullopt;
    if (current == ipv6_next_header_destination_options) {
      const auto following = packet[offset];
      if (following != ipv6_next_header_routing || routing_seen)
        return FragmentInsertion{offset, previous, current};
    }
    if (current == ipv6_next_header_routing)
      routing_seen = true;
    previous = offset;
    current = packet[offset];
    offset += length;
  }
}

[[nodiscard]] std::optional<FragmentLayout>
fragment_layout(std::span<const std::uint8_t> packet,
                std::uint16_t mtu) noexcept {
  const auto view = parse_ipv6(packet);
  if (!view || view->fragment || mtu < ipv6_minimum_link_mtu)
    return std::nullopt;
  const auto original_ip_size =
      ipv6_header_octets + static_cast<std::size_t>(view->payload_length);
  if (original_ip_size <= mtu)
    return std::nullopt;
  const auto packet_end = ethernet_header_octets + original_ip_size;
  const auto insertion = insertion_point(packet, packet_end);
  if (!insertion)
    return std::nullopt;
  const auto unfragmentable_ip_size =
      insertion->offset - ethernet_header_octets;
  if (mtu <= unfragmentable_ip_size + ipv6_fragment_header_octets)
    return std::nullopt;
  const auto per_fragment =
      (static_cast<std::size_t>(mtu) - unfragmentable_ip_size -
       ipv6_fragment_header_octets) &
      ~std::size_t{ipv6_fragment_offset_unit_octets - 1U};
  const auto fragmentable_size = packet_end - insertion->offset;
  if (!per_fragment || !fragmentable_size)
    return std::nullopt;
  return FragmentLayout{
      .insertion = *insertion,
      .packet_end = packet_end,
      .unfragmentable_ip_size = unfragmentable_ip_size,
      .per_fragment = per_fragment,
      .fragmentable_size = fragmentable_size,
      .count = (fragmentable_size + per_fragment - 1U) / per_fragment};
}

struct BatchSinkContext {
  Ipv6FragmentBatch *batch{};
};

bool append_to_batch(void *opaque, const Frame &fragment) noexcept {
  auto &context = *static_cast<BatchSinkContext *>(opaque);
  if (context.batch->count >= context.batch->frames.size())
    return false;
  copy_frame(context.batch->frames[context.batch->count], fragment);
  ++context.batch->count;
  return true;
}

[[nodiscard]] bool bitmap_bit(std::span<const std::uint8_t> bitmap,
                              std::size_t index) noexcept {
  return (bitmap[index / 8U] & static_cast<std::uint8_t>(1U << (index % 8U))) !=
         0U;
}

void set_bitmap_bit(std::span<std::uint8_t> bitmap,
                    std::size_t index) noexcept {
  bitmap[index / 8U] |= static_cast<std::uint8_t>(1U << (index % 8U));
}

} // namespace

std::optional<std::size_t>
ipv6_fragment_count(std::span<const std::uint8_t> packet,
                    std::uint16_t mtu) noexcept {
  const auto layout = fragment_layout(packet, mtu);
  return layout ? std::optional<std::size_t>{layout->count} : std::nullopt;
}

std::optional<std::size_t> fragment_ipv6_datagram(
    std::span<const std::uint8_t> packet, std::uint16_t mtu,
    std::uint32_t identification, void *context,
    Ipv6FragmentSink sink) noexcept {
  if (!sink)
    return std::nullopt;
  const auto layout = fragment_layout(packet, mtu);
  if (!layout)
    return std::nullopt;

  std::size_t count{};
  for (std::size_t offset = 0; offset < layout->fragmentable_size;
       offset += layout->per_fragment) {
    const auto copied = std::min(layout->per_fragment,
                                 layout->fragmentable_size - offset);
    Frame fragment;
    std::copy_n(packet.begin(), layout->insertion.offset,
                fragment.bytes.begin());
    fragment.bytes[layout->insertion.previous_next_header_offset] =
        ipv6_next_header_fragment;
    auto cursor = layout->insertion.offset;
    fragment.bytes[cursor++] = layout->insertion.fragment_next_header;
    fragment.bytes[cursor++] = 0U;
    const auto field = static_cast<std::uint16_t>(
        ((offset / ipv6_fragment_offset_unit_octets) << 3U) |
        (offset + copied < layout->fragmentable_size ? 1U : 0U));
    write16(fragment, cursor, field);
    cursor += 2U;
    write32(fragment, cursor, identification);
    cursor += 4U;
    std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(
                                   layout->insertion.offset + offset),
                copied, fragment.bytes.begin() +
                            static_cast<std::ptrdiff_t>(cursor));
    cursor += copied;
    write16(fragment, fixed_payload_length_offset,
            static_cast<std::uint16_t>(
                layout->insertion.offset - first_extension_offset +
                ipv6_fragment_header_octets + copied));
    fragment.length = static_cast<std::uint16_t>(cursor);
    while (fragment.length < ethernet_minimum_without_fcs)
      fragment.bytes[fragment.length++] = 0U;
    // The sink owns queue admission. Stopping immediately on refusal preserves
    // fragment order and prevents a later suffix from crossing the link alone.
    if (!sink(context, fragment))
      return std::nullopt;
    ++count;
  }
  return count;
}

std::optional<Ipv6FragmentBatch>
fragment_ipv6(const Frame &packet, std::uint16_t mtu,
              std::uint32_t identification) noexcept {
  Ipv6FragmentBatch batch;
  BatchSinkContext context{.batch = &batch};
  const auto count = fragment_ipv6_datagram(
      packet.view(), mtu, identification, &context, append_to_batch);
  if (!count || *count != batch.count)
    return std::nullopt;
  return batch;
}

Ipv6ReassemblyTable::Ipv6ReassemblyTable()
    : completed_(maximum_ethernet_ipv6_datagram_octets) {
  // Allocation occurs once at endpoint-owner creation, never in accept(). The
  // generated table capacity remains the admission bound under fragment flood.
  for (auto &entry : entries_)
    entry.fragmentable.resize(maximum_ipv6_payload_octets);
}

void Ipv6ReassemblyTable::clear(Entry &entry) noexcept {
  // Preserve vector capacity and its stable allocation. Only metadata and the
  // acceptance bitmap define live state; stale payload bytes are unreachable.
  entry.source = {};
  entry.destination = {};
  entry.first_fragment.length = 0U;
  entry.received.reset();
  entry.expires = {};
  entry.identification = 0U;
  entry.fragment_header_offset = 0U;
  entry.previous_next_header_offset = 0U;
  entry.extent = 0U;
  entry.final_size = 0U;
  entry.fragment_next_header = 0U;
  entry.occupied = false;
  entry.have_first = false;
  entry.have_last = false;
}

Ipv6ReassemblyTable::Entry *Ipv6ReassemblyTable::find(
    const Ipv6View &view) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.source == view.source &&
        entry.destination == view.destination && view.fragment &&
        entry.identification == view.fragment->identification)
      return &entry;
  return nullptr;
}

Ipv6ReassemblyTable::Entry *Ipv6ReassemblyTable::allocate(
    const Ipv6View &view, Clock::time_point now) noexcept {
  for (auto &entry : entries_)
    if (!entry.occupied) {
      clear(entry);
      entry.occupied = true;
      entry.source = view.source;
      entry.destination = view.destination;
      entry.identification = view.fragment->identification;
      entry.expires = now + device_catalog::ipv6_reassembly_timeout;
      return &entry;
    }
  return nullptr;
}

std::span<const std::uint8_t>
Ipv6ReassemblyTable::assemble(const Entry &entry) noexcept {
  if (!entry.have_first || !entry.have_last || !entry.final_size)
    return {};
  const auto unfragmentable_payload =
      entry.fragment_header_offset - first_extension_offset;
  const auto reassembled_payload = unfragmentable_payload + entry.final_size;
  const auto packet_end = first_extension_offset + reassembled_payload;
  if (reassembled_payload > maximum_ipv6_payload_octets ||
      packet_end > completed_.size())
    return {};
  std::copy_n(entry.first_fragment.bytes.begin(),
              entry.fragment_header_offset, completed_.begin());
  completed_[entry.previous_next_header_offset] = entry.fragment_next_header;
  std::copy_n(entry.fragmentable.begin(), entry.final_size,
              completed_.begin() + entry.fragment_header_offset);
  write16(std::span<std::uint8_t>{completed_}, fixed_payload_length_offset,
          static_cast<std::uint16_t>(reassembled_payload));
  auto length = packet_end;
  while (length < ethernet_minimum_without_fcs)
    completed_[length++] = 0U;
  return {completed_.data(), length};
}

Ipv6ReassemblyResult Ipv6ReassemblyTable::accept(
    const Frame &fragment, Clock::time_point now) noexcept {
  expire(now);
  const auto view = parse_ipv6(fragment);
  if (!view)
    return {.status = Ipv6ReassemblyStatus::malformed};
  if (!view->fragment)
    return {.status = Ipv6ReassemblyStatus::not_fragment};
  const auto packet_end = first_extension_offset + view->payload_length;

  if (view->fragment->offset == 0U && !view->fragment->more_fragments) {
    // RFC 6946 requires an atomic fragment to bypass matching normal state.
    // Normalize it into the table-owned completion buffer independently.
    const auto header = static_cast<std::size_t>(view->fragment_header_offset);
    if (!header || header + ipv6_fragment_header_octets > packet_end)
      return {.status = Ipv6ReassemblyStatus::malformed};
    std::copy_n(fragment.bytes.begin(), header, completed_.begin());
    std::copy(fragment.bytes.begin() + header + ipv6_fragment_header_octets,
              fragment.bytes.begin() + packet_end,
              completed_.begin() + header);
    completed_[view->fragment_previous_next_header_offset] = fragment[header];
    write16(std::span<std::uint8_t>{completed_}, fixed_payload_length_offset,
            static_cast<std::uint16_t>(view->payload_length -
                                       ipv6_fragment_header_octets));
    auto length = packet_end - ipv6_fragment_header_octets;
    while (length < ethernet_minimum_without_fcs)
      completed_[length++] = 0U;
    return {.status = Ipv6ReassemblyStatus::atomic,
            .packet = {completed_.data(), length}};
  }

  const auto data_start =
      static_cast<std::size_t>(view->fragment_header_offset) +
      ipv6_fragment_header_octets;
  if (data_start > packet_end)
    return {.status = Ipv6ReassemblyStatus::malformed};
  const auto data_size = packet_end - data_start;
  const auto offset = static_cast<std::size_t>(view->fragment->offset) *
                      ipv6_fragment_offset_unit_octets;
  const auto unfragmentable_payload =
      static_cast<std::size_t>(view->fragment_header_offset) -
      first_extension_offset;
  if (!data_size ||
      (view->fragment->more_fragments &&
       data_size % ipv6_fragment_offset_unit_octets != 0U) ||
      offset + data_size > maximum_ipv6_payload_octets ||
      unfragmentable_payload + offset + data_size >
          maximum_ipv6_payload_octets)
    return {.status = Ipv6ReassemblyStatus::malformed};

  auto *entry = find(*view);
  if (!entry)
    entry = allocate(*view, now);
  if (!entry)
    return {.status = Ipv6ReassemblyStatus::resource_exhausted};
  if (entry->fragment_header_offset &&
      (entry->fragment_header_offset != view->fragment_header_offset ||
       entry->fragment_next_header !=
           fragment[view->fragment_header_offset])) {
    clear(*entry);
    return {.status = Ipv6ReassemblyStatus::malformed};
  }
  entry->fragment_header_offset = view->fragment_header_offset;
  entry->previous_next_header_offset =
      view->fragment_previous_next_header_offset;
  entry->fragment_next_header = fragment[view->fragment_header_offset];

  // RFC 5722 rejects the entire datagram on the first overlapping byte. The
  // same rule covers a fragment that extends beyond an already known last end.
  bool overlaps{};
  for (std::size_t index = offset; index < offset + data_size; ++index)
    if (entry->received.test(index)) {
      overlaps = true;
      break;
    }
  if ((entry->have_last && offset + data_size > entry->final_size) ||
      overlaps) {
    clear(*entry);
    return {.status = Ipv6ReassemblyStatus::overlap};
  }
  std::copy_n(fragment.bytes.begin() + data_start, data_size,
              entry->fragmentable.begin() + offset);
  for (std::size_t index = offset; index < offset + data_size; ++index)
    entry->received.set(index);
  entry->extent = static_cast<std::uint32_t>(
      std::max<std::size_t>(entry->extent, offset + data_size));
  if (offset == 0U) {
    copy_frame(entry->first_fragment, fragment);
    entry->have_first = true;
  }
  if (!view->fragment->more_fragments) {
    const auto final_size = offset + data_size;
    if ((entry->have_last && entry->final_size != final_size) ||
        entry->extent > final_size) {
      clear(*entry);
      return {.status = Ipv6ReassemblyStatus::malformed};
    }
    entry->have_last = true;
    entry->final_size = static_cast<std::uint16_t>(final_size);
  }
  if (!entry->have_first || !entry->have_last)
    return {.status = Ipv6ReassemblyStatus::incomplete};
  for (std::size_t index = 0; index < entry->final_size; ++index)
    if (!entry->received.test(index))
      return {.status = Ipv6ReassemblyStatus::incomplete};
  const auto packet = assemble(*entry);
  clear(*entry);
  return {.status = packet.empty() ? Ipv6ReassemblyStatus::malformed
                                   : Ipv6ReassemblyStatus::complete,
          .packet = packet};
}

void Ipv6ReassemblyTable::expire(Clock::time_point now) noexcept {
  for (auto &entry : entries_)
    if (entry.occupied && entry.expires <= now)
      clear(entry);
}

void Ipv6ReassemblyTable::discard_all() noexcept {
  // Link replacement and interface reconfiguration invalidate every tuple but
  // retain the preallocated payload arenas for the next attachment generation.
  for (auto &entry : entries_)
    clear(entry);
}

std::optional<Ipv6ReassemblyTable::Clock::time_point>
Ipv6ReassemblyTable::next_deadline() const noexcept {
  std::optional<Clock::time_point> result;
  for (const auto &entry : entries_)
    if (entry.occupied && (!result || entry.expires < *result))
      result = entry.expires;
  return result;
}

std::size_t Ipv6ReassemblyTable::active() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const auto &entry) { return entry.occupied; }));
}

std::vector<Ipv6ReassemblyCheckpoint>
Ipv6ReassemblyTable::checkpoint(Clock::time_point now) const {
  std::vector<Ipv6ReassemblyCheckpoint> state;
  state.reserve(active());
  for (const auto &entry : entries_) {
    if (!entry.occupied)
      continue;
    Ipv6ReassemblyCheckpoint saved{
        .source = entry.source,
        .destination = entry.destination,
        .first_fragment = entry.first_fragment,
        .fragmentable = {},
        .received = {},
        .remaining_nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     entry.expires > now
                                         ? entry.expires - now
                                         : Clock::duration::zero())
                                     .count(),
        .identification = entry.identification,
        .fragment_header_offset = entry.fragment_header_offset,
        .previous_next_header_offset = entry.previous_next_header_offset,
        .final_size = entry.final_size,
        .fragment_next_header = entry.fragment_next_header,
        .have_first = entry.have_first,
        .have_last = entry.have_last};
    saved.fragmentable.assign(entry.fragmentable.begin(),
                              entry.fragmentable.begin() + entry.extent);
    saved.received.assign((entry.extent + 7U) / 8U, 0U);
    for (std::size_t index = 0; index < entry.extent; ++index)
      if (entry.received.test(index))
        set_bitmap_bit(saved.received, index);
    state.push_back(std::move(saved));
  }
  return state;
}

bool Ipv6ReassemblyTable::validate_checkpoint(
    const std::vector<Ipv6ReassemblyCheckpoint> &state) noexcept {
  if (state.size() > device_catalog::ipv6_reassembly_entries_per_endpoint)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &entry = state[index];
    const auto extent = entry.fragmentable.size();
    if (entry.remaining_nanoseconds < 0 || !extent ||
        extent > maximum_ipv6_payload_octets ||
        entry.received.size() != (extent + 7U) / 8U ||
        entry.fragment_header_offset < first_extension_offset ||
        entry.fragment_header_offset >= maximum_frame_octets ||
        entry.previous_next_header_offset >= maximum_frame_octets ||
        entry.final_size > extent ||
        entry.have_last != (entry.final_size != 0U))
      return false;
    // Unused high bits must remain zero so one serialized state has one
    // canonical meaning and cannot smuggle accepted bytes beyond its extent.
    if ((extent % 8U) != 0U &&
        (entry.received.back() &
         static_cast<std::uint8_t>(0xffU << (extent % 8U))) != 0U)
      return false;
    if (entry.have_first) {
      const auto first = parse_ipv6(entry.first_fragment);
      if (!first || !first->fragment || first->source != entry.source ||
          first->destination != entry.destination ||
          first->fragment->identification != entry.identification ||
          first->fragment->offset != 0U ||
          first->fragment_header_offset != entry.fragment_header_offset)
        return false;
    } else if (entry.first_fragment.length)
      return false;
    if (entry.have_last)
      for (std::size_t octet = entry.final_size; octet < extent; ++octet)
        if (bitmap_bit(entry.received, octet))
          return false;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (state[previous].source == entry.source &&
          state[previous].destination == entry.destination &&
          state[previous].identification == entry.identification)
        return false;
  }
  return true;
}

bool Ipv6ReassemblyTable::restore(
    const std::vector<Ipv6ReassemblyCheckpoint> &state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  for (auto &entry : entries_)
    clear(entry);
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &saved = state[index];
    auto &entry = entries_[index];
    entry.source = saved.source;
    entry.destination = saved.destination;
    entry.first_fragment = saved.first_fragment;
    std::copy(saved.fragmentable.begin(), saved.fragmentable.end(),
              entry.fragmentable.begin());
    for (std::size_t octet = 0; octet < saved.fragmentable.size(); ++octet)
      entry.received.set(octet, bitmap_bit(saved.received, octet));
    entry.expires =
        now + std::chrono::nanoseconds(saved.remaining_nanoseconds);
    entry.identification = saved.identification;
    entry.fragment_header_offset = saved.fragment_header_offset;
    entry.previous_next_header_offset = saved.previous_next_header_offset;
    entry.extent = static_cast<std::uint32_t>(saved.fragmentable.size());
    entry.final_size = saved.final_size;
    entry.fragment_next_header = saved.fragment_next_header;
    entry.occupied = true;
    entry.have_first = saved.have_first;
    entry.have_last = saved.have_last;
  }
  return true;
}

} // namespace router::packet
