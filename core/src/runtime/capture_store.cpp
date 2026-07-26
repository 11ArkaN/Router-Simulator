// Incremental PCAPNG encoding owned exclusively by the forwarding shard.
// Sources: draft-ietf-opsawg-pcapng-05 sections 4.1, 4.2, 4.3 and 4.6;
// IANA LINKTYPE registry entry 1 for Ethernet.

#include "router/capture_store.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <new>

namespace router {
namespace {

constexpr std::uint32_t section_header_block = 0x0a0d0d0aU;
constexpr std::uint32_t interface_description_block = 1U;
constexpr std::uint32_t interface_statistics_block = 5U;
constexpr std::uint32_t enhanced_packet_block = 6U;
constexpr std::uint16_t linktype_ethernet = 1U;

void put16(std::vector<std::uint8_t> &out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value));
  out.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void put32(std::vector<std::uint8_t> &out, std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8)
    out.push_back(static_cast<std::uint8_t>(value >> shift));
}

void put64(std::vector<std::uint8_t> &out, std::uint64_t value) {
  put32(out, static_cast<std::uint32_t>(value));
  put32(out, static_cast<std::uint32_t>(value >> 32U));
}

std::uint64_t wall_timestamp_us() {
  // PCAPNG timestamps are wall-clock values. Packet timestamps already arrive
  // from the runtime conversion; statistics use the same Unix microsecond unit.
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

CaptureStore::CaptureStore() { append_section_header(); }

CaptureStore::Point *CaptureStore::find_point(CapturePointId id) noexcept {
  const auto found = std::lower_bound(
      points_.begin(), points_.end(), id,
      [](const Point &point, CapturePointId candidate) {
        return point.id < candidate;
      });
  return found != points_.end() && found->id == id ? &*found : nullptr;
}

const CaptureStore::Point *
CaptureStore::find_point(CapturePointId id) const noexcept {
  const auto found = std::lower_bound(
      points_.begin(), points_.end(), id,
      [](const Point &point, CapturePointId candidate) {
        return point.id < candidate;
      });
  return found != points_.end() && found->id == id ? &*found : nullptr;
}

void CaptureStore::append_section_header() {
  put32(stream_, section_header_block);
  put32(stream_, 28U);
  put32(stream_, 0x1a2b3c4dU);
  put16(stream_, 1U);
  put16(stream_, 0U);
  put32(stream_, 0xffffffffU);
  put32(stream_, 0xffffffffU);
  put32(stream_, 28U);
}

bool CaptureStore::describe(Point &point) {
  if (point.described)
    return true;
  const auto start = stream_.size();
  try {
    const auto length = point.name.size();
    const auto padded = (length + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(28U + padded);
    put32(stream_, interface_description_block);
    put32(stream_, total);
    put16(stream_, linktype_ethernet);
    put16(stream_, 0U);
    put32(stream_, static_cast<std::uint32_t>(packet::maximum_frame_octets));
    put16(stream_, 2U); // if_name
    put16(stream_, static_cast<std::uint16_t>(length));
    stream_.insert(stream_.end(), point.name.begin(), point.name.end());
    stream_.resize(stream_.size() + padded - length, 0U);
    put16(stream_, 0U);
    put16(stream_, 0U);
    put32(stream_, total);
    point.described = true;
    return true;
  } catch (const std::bad_alloc &) {
    // vector growth provides the strong guarantee per operation, but a block
    // spans several operations. Roll back the already appended prefix so the
    // persisted PCAPNG never ends with a malformed partial block.
    stream_.resize(start);
    return false;
  }
}

bool CaptureStore::configure_point(CapturePointId id, std::string_view name) {
  if (name.empty() || name.size() > device_catalog::capture_point_name_bytes ||
      name.size() > std::numeric_limits<std::uint16_t>::max())
    return false;
  try {
    auto found = std::lower_bound(
        points_.begin(), points_.end(), id,
        [](const Point &point, CapturePointId candidate) {
          return point.id < candidate;
        });
    if (found != points_.end() && found->id == id && found->name == name) {
      const auto was_active = found->active;
      found->active = true;
      if (describe(*found))
        return true;
      found->active = was_active;
      return false;
    }

    const auto replacing = found != points_.end() && found->id == id;
    if (next_pcap_interface_ == std::numeric_limits<std::uint32_t>::max())
      return false;
    if (!replacing && points_.size() == points_.capacity()) {
      // Preserve geometric vector growth. Reserving exactly one extra entry
      // would turn repeated point activation into quadratic control-plane work.
      if (points_.size() == points_.max_size())
        return false;
      const auto required = points_.size() + 1U;
      const auto doubled = points_.size() <= points_.max_size() / 2U
                               ? points_.size() * 2U
                               : points_.max_size();
      points_.reserve(std::max(required, std::max<std::size_t>(1U, doubled)));
      found = std::lower_bound(
          points_.begin(), points_.end(), id,
          [](const Point &point, CapturePointId candidate) {
            return point.id < candidate;
          });
    }

    // Construct the replacement metadata before mutating the ordered set.
    // This keeps a failed string allocation from leaving a sparse or unnamed
    // entry behind. The IDB is emitted before committing the point, so success
    // always means decoders have the metadata needed for the first packet.
    Point candidate{};
    candidate.id = id;
    candidate.name.assign(name);
    candidate.pcap_interface = next_pcap_interface_;
    candidate.active = true;
    if (replacing)
      append_statistics(*found, wall_timestamp_us());
    if (!describe(candidate))
      return false;

    if (replacing)
      *found = std::move(candidate);
    else
      points_.insert(found, std::move(candidate));
    ++next_pcap_interface_;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool CaptureStore::deactivate_point(CapturePointId id) noexcept {
  auto found = std::lower_bound(
      points_.begin(), points_.end(), id,
      [](const Point &point, CapturePointId candidate) {
        return point.id < candidate;
      });
  if (found == points_.end() || found->id != id)
    return false;
  auto &point = *found;
  point.active = false;
  // Close the interface's accounting before releasing its metadata. The IDB,
  // packets and final ISB already live in stream_, so no historic point slot
  // must remain resident merely to keep the exported file self-describing.
  try {
    append_statistics(point, wall_timestamp_us());
  } catch (const std::bad_alloc &) {
    ++point.dropped;
  }
  points_.erase(found);
  return true;
}

bool CaptureStore::point_active(CapturePointId id) const noexcept {
  const auto *point = find_point(id);
  return point && point->active;
}

bool CaptureStore::append_packet(Point &point, const packet::Frame &frame,
                                 std::uint64_t timestamp_us) {
  if (!describe(point))
    return false;
  const auto start = stream_.size();
  try {
    const auto padded = (frame.size() + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(32U + padded);
    put32(stream_, enhanced_packet_block);
    put32(stream_, total);
    put32(stream_, point.pcap_interface);
    put32(stream_, static_cast<std::uint32_t>(timestamp_us >> 32U));
    put32(stream_, static_cast<std::uint32_t>(timestamp_us));
    put32(stream_, frame.length);
    put32(stream_, frame.length);
    stream_.insert(stream_.end(), frame.view().begin(), frame.view().end());
    stream_.resize(stream_.size() + padded - frame.size(), 0U);
    put32(stream_, total);
    return true;
  } catch (const std::bad_alloc &) {
    stream_.resize(start);
    return false;
  }
}

bool CaptureStore::record(CapturePointId id, const packet::Frame &frame,
                          std::uint64_t timestamp_us) {
  auto *point = find_point(id);
  if (!point || !point->active)
    return false;
  if (!append_packet(*point, frame, timestamp_us)) {
    ++point->dropped;
    return false;
  }
  ++point->received;
  ++record_count_;
  return true;
}

void CaptureStore::append_statistics(Point &point,
                                     std::uint64_t timestamp_us) {
  // ISB option 4 is ifrecv and option 5 is ifdrop. Repeated ISBs are valid
  // snapshots; consumers use the latest counters for each interface.
  constexpr std::uint32_t total = 52U;
  const auto start = stream_.size();
  try {
    put32(stream_, interface_statistics_block);
    put32(stream_, total);
    put32(stream_, point.pcap_interface);
    put32(stream_, static_cast<std::uint32_t>(timestamp_us >> 32U));
    put32(stream_, static_cast<std::uint32_t>(timestamp_us));
    put16(stream_, 4U);
    put16(stream_, 8U);
    // isb_ifrecv counts observations presented to capture, including packets
    // later lost by capture resources. isb_ifdrop reports that lost subset.
    const auto observed = point.dropped >
                                  std::numeric_limits<std::uint64_t>::max() -
                                      point.received
                              ? std::numeric_limits<std::uint64_t>::max()
                              : point.received + point.dropped;
    put64(stream_, observed);
    put16(stream_, 5U);
    put16(stream_, 8U);
    put64(stream_, point.dropped);
    put16(stream_, 0U);
    put16(stream_, 0U);
    put32(stream_, total);
    point.reported_received = point.received;
    point.reported_dropped = point.dropped;
  } catch (...) {
    stream_.resize(start);
    throw;
  }
}

void CaptureStore::encode() {
  try {
    const auto now = wall_timestamp_us();
    for (auto &point : points_)
      if (describe(point) &&
          (point.received != point.reported_received ||
           point.dropped != point.reported_dropped))
        append_statistics(point, now);
    prepared_.clear();
    prepared_.swap(stream_);
  } catch (const std::bad_alloc &) {
    // Existing packet blocks remain intact. A later drain can retry statistics;
    // export must never discard already captured bytes after allocation failure.
    prepared_.clear();
  }
}

bool CaptureStore::clear_session() noexcept {
  // Build a complete replacement section before touching the live encoder.
  // This provides an all-or-nothing reset if the browser is under memory
  // pressure: either every active point has a valid IDB, or the old capture
  // remains available for a later drain/export attempt.
  try {
    CaptureStore replacement;
    replacement.points_.reserve(points_.size());
    for (const auto &point : points_) {
      if (!replacement.configure_point(point.id, point.name))
        return false;
      auto *fresh = replacement.find_point(point.id);
      fresh->active = point.active;
    }
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

CaptureStoreCheckpoint CaptureStore::checkpoint() const {
  CaptureStoreCheckpoint state;
  for (const auto &point : points_)
    state.points.push_back(
        {point.id, point.name, point.active, point.received, point.dropped});
  return state;
}

bool CaptureStore::validate_checkpoint(const CaptureStoreCheckpoint &state) noexcept {
  CapturePointId previous{};
  bool first = true;
  for (const auto &point : state.points) {
    if ((!first && point.id <= previous) || point.name.empty() ||
        point.name.size() > device_catalog::capture_point_name_bytes)
      return false;
    previous = point.id;
    first = false;
  }
  return true;
}

bool CaptureStore::restore(const CaptureStoreCheckpoint &state) {
  if (!validate_checkpoint(state))
    return false;
  try {
    CaptureStore replacement;
    for (const auto &saved : state.points) {
      if (!replacement.configure_point(saved.id, saved.name))
        return false;
      auto *point = replacement.find_point(saved.id);
      point->active = saved.active;
      point->received = saved.received;
      point->dropped = saved.dropped;
      replacement.record_count_ += static_cast<std::size_t>(std::min<
          std::uint64_t>(saved.received,
                        std::numeric_limits<std::size_t>::max() -
                            replacement.record_count_));
    }
    *this = std::move(replacement);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router
