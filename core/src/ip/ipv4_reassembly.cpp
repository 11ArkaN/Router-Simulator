// IPv4 destination reassembly following RFC 791 and RFC 1122. The table is a
// single-owner protocol repository and cannot send frames or inspect topology.

#include "router/ipv4_reassembly.hpp"

#include <algorithm>

namespace router::packet {
namespace {

constexpr std::size_t ipv4_offset = ethernet_header_octets;

[[nodiscard]] bool bitmap_bit(std::span<const std::uint8_t> bitmap,
                              std::size_t index) noexcept {
  return (bitmap[index / 8U] &
          static_cast<std::uint8_t>(1U << (index % 8U))) != 0U;
}

void set_bitmap_bit(std::span<std::uint8_t> bitmap,
                    std::size_t index) noexcept {
  bitmap[index / 8U] |= static_cast<std::uint8_t>(1U << (index % 8U));
}

} // namespace

Ipv4ReassemblyTable::Ipv4ReassemblyTable()
    : entries_(device_catalog::ipv4_reassembly_entries_per_endpoint),
      completed_(maximum_ethernet_ipv4_datagram_octets) {
  // Stable allocations keep a fragment flood from turning into allocator
  // traffic. Profile capacity, not available host memory, is admission policy.
  for (auto &entry : entries_)
    entry.payload.resize(maximum_payload_octets);
}

void Ipv4ReassemblyTable::clear(Entry &entry) noexcept {
  // Payload capacity is retained. occupied and the receipt bitmap are the only
  // authorities that make stale bytes reachable after a slot is released.
  entry.source = {};
  entry.destination = {};
  entry.first_fragment.length = 0U;
  entry.received.reset();
  entry.expires = {};
  entry.extent = 0U;
  entry.identification = 0U;
  entry.final_size = 0U;
  entry.protocol = 0U;
  entry.occupied = false;
  entry.have_first = false;
  entry.have_last = false;
}

Ipv4ReassemblyTable::Entry *
Ipv4ReassemblyTable::find(const Ipv4View &view) noexcept {
  // RFC 791's reassembly key contains source, destination, protocol and ID.
  // Interface ownership is implicit because one table belongs to one endpoint.
  for (auto &entry : entries_)
    if (entry.occupied && entry.source == view.source &&
        entry.destination == view.destination &&
        entry.protocol == view.protocol &&
        entry.identification == view.identification)
      return &entry;
  return nullptr;
}

Ipv4ReassemblyTable::Entry *
Ipv4ReassemblyTable::allocate(const Ipv4View &view,
                              Clock::time_point now) noexcept {
  for (auto &entry : entries_)
    if (!entry.occupied) {
      clear(entry);
      entry.occupied = true;
      entry.source = view.source;
      entry.destination = view.destination;
      entry.protocol = view.protocol;
      entry.identification = view.identification;
      entry.expires = now + device_catalog::ipv4_reassembly_timeout;
      return &entry;
    }
  return nullptr;
}

std::span<const std::uint8_t>
Ipv4ReassemblyTable::assemble(const Entry &entry) noexcept {
  if (!entry.have_first || !entry.have_last || entry.final_size == 0U)
    return {};
  const auto first = parse_ipv4(entry.first_fragment);
  if (!first)
    return {};
  const auto header_length = static_cast<std::size_t>(first->header_length);
  const auto total_length = header_length + entry.final_size;
  if (total_length > maximum_ipv4_datagram_octets)
    return {};

  // Options from fragment zero form the reassembled header. Fragment bits are
  // cleared, Total Length and checksum are regenerated, and Ethernet padding
  // is retained only when the resulting packet is shorter than 60 octets.
  std::copy_n(entry.first_fragment.bytes.begin(),
              ethernet_header_octets + header_length, completed_.begin());
  std::copy_n(entry.payload.begin(), entry.final_size,
              completed_.begin() + ethernet_header_octets + header_length);
  completed_[16U] = static_cast<std::uint8_t>(total_length >> 8U);
  completed_[17U] = static_cast<std::uint8_t>(total_length);
  completed_[20U] = 0U;
  completed_[21U] = 0U;
  completed_[24U] = 0U;
  completed_[25U] = 0U;
  const auto header_checksum = checksum(std::span<const std::uint8_t>{
      completed_.data() + ipv4_offset, header_length});
  completed_[24U] = static_cast<std::uint8_t>(header_checksum >> 8U);
  completed_[25U] = static_cast<std::uint8_t>(header_checksum);
  auto captured_length = ethernet_header_octets + total_length;
  while (captured_length < ethernet_minimum_without_fcs)
    completed_[captured_length++] = 0U;
  return {completed_.data(), captured_length};
}

Ipv4ReassemblyResult Ipv4ReassemblyTable::accept(
    const Frame &fragment, Clock::time_point now) noexcept {
  const auto view = parse_ipv4(fragment);
  if (!view)
    return {.status = Ipv4ReassemblyStatus::malformed};
  if (view->fragment_offset == 0U && !view->more_fragments)
    return {.status = Ipv4ReassemblyStatus::not_fragment};

  const auto header_length = static_cast<std::size_t>(view->header_length);
  const auto data_size =
      static_cast<std::size_t>(view->total_length - view->header_length);
  const auto offset = static_cast<std::size_t>(view->fragment_offset) * 8U;
  if (data_size == 0U ||
      (view->more_fragments && data_size % 8U != 0U) ||
      offset + data_size > maximum_payload_octets)
    return {.status = Ipv4ReassemblyStatus::malformed};

  auto *entry = find(*view);
  if (!entry)
    entry = allocate(*view, now);
  if (!entry)
    return {.status = Ipv4ReassemblyStatus::resource_exhausted};

  // RFC 791's example procedure copies newly received bytes at their stated
  // offsets. Consequently a later overlapping fragment replaces prior bytes.
  // This is not reused by IPv6, whose RFC 5722 rule discards the whole packet.
  std::copy_n(fragment.bytes.begin() + ipv4_offset + header_length, data_size,
              entry->payload.begin() + static_cast<std::ptrdiff_t>(offset));
  for (std::size_t index = offset; index < offset + data_size; ++index)
    entry->received.set(index);
  entry->extent = static_cast<std::uint32_t>(
      std::max<std::size_t>(entry->extent, offset + data_size));
  if (offset == 0U) {
    copy_frame(entry->first_fragment, fragment);
    entry->have_first = true;
  }
  if (!view->more_fragments) {
    entry->final_size = static_cast<std::uint16_t>(offset + data_size);
    entry->have_last = true;
  }

  if (!entry->have_first || !entry->have_last)
    return {.status = Ipv4ReassemblyStatus::incomplete};
  for (std::size_t index = 0U; index < entry->final_size; ++index)
    if (!entry->received.test(index))
      return {.status = Ipv4ReassemblyStatus::incomplete};

  const auto completed = assemble(*entry);
  clear(*entry);
  if (completed.empty())
    return {.status = Ipv4ReassemblyStatus::malformed};
  return {.status = Ipv4ReassemblyStatus::complete, .packet = completed};
}

bool Ipv4ReassemblyTable::take_expired(Frame &first_fragment,
                                       Clock::time_point now) noexcept {
  first_fragment.length = 0U;
  // RFC 1122 recommends a fixed 60 to 120 second timer rather than deriving it
  // from TTL. Returning fragment zero transfers only the evidence needed by
  // EndpointStack to encode the required ICMP error through its normal egress.
  for (auto &entry : entries_)
    if (entry.occupied && entry.expires <= now) {
      if (entry.have_first)
        copy_frame(first_fragment, entry.first_fragment);
      clear(entry);
      return true;
    }
  return false;
}

void Ipv4ReassemblyTable::discard_all() noexcept {
  for (auto &entry : entries_)
    clear(entry);
}

std::optional<Ipv4ReassemblyTable::Clock::time_point>
Ipv4ReassemblyTable::next_deadline() const noexcept {
  std::optional<Clock::time_point> earliest;
  for (const auto &entry : entries_)
    if (entry.occupied && (!earliest || entry.expires < *earliest))
      earliest = entry.expires;
  return earliest;
}

std::size_t Ipv4ReassemblyTable::active() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      entries_.begin(), entries_.end(),
      [](const Entry &entry) { return entry.occupied; }));
}

std::vector<Ipv4ReassemblyCheckpoint>
Ipv4ReassemblyTable::checkpoint(Clock::time_point now) const {
  std::vector<Ipv4ReassemblyCheckpoint> result;
  result.reserve(active());
  for (const auto &entry : entries_) {
    if (!entry.occupied || entry.expires <= now)
      continue;
    Ipv4ReassemblyCheckpoint saved{
        .source = entry.source,
        .destination = entry.destination,
        .first_fragment = entry.first_fragment,
        .payload = std::vector<std::uint8_t>(entry.payload.begin(),
                                             entry.payload.begin() + entry.extent),
        .received = std::vector<std::uint8_t>((entry.extent + 7U) / 8U),
        .remaining_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                entry.expires - now).count(),
        .identification = entry.identification,
        .final_size = entry.final_size,
        .protocol = entry.protocol,
        .have_first = entry.have_first,
        .have_last = entry.have_last};
    for (std::size_t index = 0U; index < entry.extent; ++index)
      if (entry.received.test(index))
        set_bitmap_bit(saved.received, index);
    result.push_back(std::move(saved));
  }
  return result;
}

bool Ipv4ReassemblyTable::validate_checkpoint(
    const std::vector<Ipv4ReassemblyCheckpoint> &state) noexcept {
  if (state.size() > device_catalog::ipv4_reassembly_entries_per_endpoint)
    return false;
  for (std::size_t outer = 0U; outer < state.size(); ++outer) {
    const auto &entry = state[outer];
    if (entry.payload.empty() || entry.payload.size() > maximum_payload_octets ||
        entry.received.size() != (entry.payload.size() + 7U) / 8U ||
        entry.remaining_nanoseconds <= 0 ||
        entry.remaining_nanoseconds >
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                device_catalog::ipv4_reassembly_timeout).count() ||
        (entry.have_first && !parse_ipv4(entry.first_fragment)) ||
        (!entry.have_first && entry.first_fragment.length != 0U) ||
        (entry.have_last &&
         (entry.final_size == 0U || entry.final_size > entry.payload.size())) ||
        (!entry.have_last && entry.final_size != 0U))
      return false;
    for (std::size_t inner = 0U; inner < outer; ++inner)
      if (state[inner].source == entry.source &&
          state[inner].destination == entry.destination &&
          state[inner].protocol == entry.protocol &&
          state[inner].identification == entry.identification)
        return false;
    for (std::size_t index = entry.payload.size();
         index < entry.received.size() * 8U; ++index)
      if (bitmap_bit(entry.received, index))
        return false;
  }
  return true;
}

bool Ipv4ReassemblyTable::restore(
    const std::vector<Ipv4ReassemblyCheckpoint> &state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  discard_all();
  for (std::size_t slot = 0U; slot < state.size(); ++slot) {
    const auto &saved = state[slot];
    auto &entry = entries_[slot];
    entry.occupied = true;
    entry.source = saved.source;
    entry.destination = saved.destination;
    entry.first_fragment = saved.first_fragment;
    std::copy(saved.payload.begin(), saved.payload.end(), entry.payload.begin());
    for (std::size_t index = 0U; index < saved.payload.size(); ++index)
      if (bitmap_bit(saved.received, index))
        entry.received.set(index);
    entry.expires = now + std::chrono::nanoseconds{
                              saved.remaining_nanoseconds};
    entry.extent = static_cast<std::uint32_t>(saved.payload.size());
    entry.identification = saved.identification;
    entry.final_size = saved.final_size;
    entry.protocol = saved.protocol;
    entry.have_first = saved.have_first;
    entry.have_last = saved.have_last;
  }
  return true;
}

} // namespace router::packet
