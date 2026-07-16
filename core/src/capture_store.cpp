// PCAPNG storage implementation. The forwarding shard owns both vectors, and
// reserve at construction prevents capture growth from reallocating packet
// data.

#include "router/capture_store.hpp"

#include <array>
#include <limits>
#include <new>
#include <string>

namespace router {

// Reserve the complete bounded record arena before packet observation starts.
CaptureStore::CaptureStore() {
  records_.reserve(capacity);
}

bool CaptureStore::configure_point(CapturePointId id,
                                   std::string_view name) {
  if (id >= points_.size() || name.empty() ||
      name.size() > device_catalog::capture_point_name_bytes ||
      name.size() > std::numeric_limits<std::uint16_t>::max())
    return false;
  auto &point = points_[id];
  // Name replacement supports a router system-name edit without changing the
  // stable capture identity referenced by retained records.
  point.name.assign(name);
  point.configured = true;
  point.active = true;
  return true;
}

bool CaptureStore::deactivate_point(CapturePointId id) noexcept {
  if (id >= points_.size() || !points_[id].configured)
    return false;
  points_[id].active = false;
  return true;
}

bool CaptureStore::point_active(CapturePointId id) const noexcept {
  return id < points_.size() && points_[id].configured && points_[id].active;
}

bool CaptureStore::record(CapturePointId capture_point,
                          const packet::Frame &frame,
                          std::uint64_t timestamp_us) {
  // Capacity exhaustion is explicit tail drop. Existing records remain stable
  // and forwarding never blocks on capture memory.
  if (!point_active(capture_point) || records_.size() == capacity)
    return false;
  records_.emplace_back();
  auto &record = records_.back();
  record.timestamp_us = timestamp_us;
  record.capture_point = capture_point;
  packet::copy_frame(record.frame, frame);
  return true;
}

CaptureStoreCheckpoint CaptureStore::checkpoint() const {
  CaptureStoreCheckpoint state;
  for (std::size_t id = 0; id < points_.size(); ++id) {
    const auto &point = points_[id];
    if (point.configured)
      state.points.push_back(
          {static_cast<CapturePointId>(id), point.name, point.active});
  }
  state.records.reserve(records_.size());
  for (const auto &record : records_)
    state.records.push_back(
        {record.timestamp_us, record.capture_point, record.frame});
  return state;
}

bool CaptureStore::validate_checkpoint(
    const CaptureStoreCheckpoint &state) noexcept {
  if (state.points.size() > device_catalog::selected_capture_points ||
      state.records.size() > capacity)
    return false;
  std::array<bool, device_catalog::selected_capture_points> configured{};
  for (const auto &point : state.points) {
    if (point.id >= configured.size() || configured[point.id] ||
        point.name.empty() ||
        point.name.size() > device_catalog::capture_point_name_bytes)
      return false;
    configured[point.id] = true;
  }
  for (const auto &record : state.records)
    if (record.capture_point >= configured.size() ||
        !configured[record.capture_point] || !record.frame.size() ||
        record.frame.size() > record.frame.bytes.size())
      return false;
  return true;
}

bool CaptureStore::restore(const CaptureStoreCheckpoint &state) {
  if (!validate_checkpoint(state))
    return false;

  // Temporary ownership gives allocation failure normal exception semantics:
  // the caller receives failure while the active diagnostic store is intact.
  try {
    CaptureStore replacement;
    for (const auto &point : state.points) {
      if (!replacement.configure_point(point.id, point.name))
        return false;
      if (!point.active)
        static_cast<void>(replacement.deactivate_point(point.id));
    }
    for (const auto &record : state.records) {
      // Restore retains records for deactivated points. Configure them briefly
      // during insertion, then return the exact checkpoint active bit below.
      if (!replacement.points_[record.capture_point].active)
        replacement.points_[record.capture_point].active = true;
      if (!replacement.record(record.capture_point, record.frame,
                              record.timestamp_us))
        return false;
    }
    for (const auto &point : state.points)
      replacement.points_[point.id].active = point.active;
    points_.swap(replacement.points_);
    records_.swap(replacement.records_);
    prepared_.clear();
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void CaptureStore::encode() {
  // Source: ietf.pcapng.draft_ietf_opsawg_05. Each modeled capture point owns
  // an IDB, so EPB interface IDs preserve the physical observation point.
  std::size_t size = 28U;
  for (const auto &point : points_) {
    if (!point.configured)
      continue;
    const auto length = point.name.size();
    size += 28U + ((length + 3U) & ~std::size_t{3U});
  }
  for (const auto &record : records_) {
    size += 32U + ((record.frame.size() + 3U) & ~std::size_t{3U});
  }
  prepared_.clear();
  prepared_.reserve(size);
  const auto put16 = [this](std::uint16_t value) {
    // PCAPNG fields are emitted little-endian independently of host byte order.
    prepared_.push_back(static_cast<std::uint8_t>(value));
    prepared_.push_back(static_cast<std::uint8_t>(value >> 8));
  };
  const auto put32 = [this](std::uint32_t value) {
    // Shifted byte output avoids unaligned integer stores into vector storage.
    for (int shift = 0; shift < 32; shift += 8) {
      prepared_.push_back(static_cast<std::uint8_t>(value >> shift));
    }
  };
  put32(0x0a0d0d0aU);
  put32(28);
  put32(0x1a2b3c4dU);
  put16(1);
  put16(0);
  put32(0xffffffffU);
  put32(0xffffffffU);
  put32(28);
  std::array<std::uint32_t, device_catalog::selected_capture_points>
      pcap_interfaces{};
  pcap_interfaces.fill(std::numeric_limits<std::uint32_t>::max());
  std::uint32_t interface_index{};
  for (std::size_t point_id = 0; point_id < points_.size(); ++point_id) {
    const auto &point = points_[point_id];
    if (!point.configured)
      continue;
    // IDBs are compact in the exported file even when the stable CapturePointId
    // space contains gaps left by removed topology objects.
    pcap_interfaces[point_id] = interface_index++;
    const auto length = point.name.size();
    const auto padded = (length + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(28U + padded);
    put32(1);
    put32(total);
    put16(1);
    put16(0);
    put32(static_cast<std::uint32_t>(packet::maximum_frame_octets));
    put16(2);
    put16(static_cast<std::uint16_t>(length));
    prepared_.insert(prepared_.end(), point.name.begin(), point.name.end());
    prepared_.resize(prepared_.size() + padded - length, 0);
    put16(0);
    put16(0);
    put32(total);
  }
  for (const auto &record : records_) {
    // Enhanced Packet Blocks preserve captured length, original frame length,
    // microsecond timestamp and observation interface without packet parsing.
    const auto padded = (record.frame.size() + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(32U + padded);
    put32(6);
    put32(total);
    // Every record was admitted only for a configured point, so this mapping
    // cannot contain the invalid sentinel unless memory ownership was broken.
    put32(pcap_interfaces[record.capture_point]);
    put32(static_cast<std::uint32_t>(record.timestamp_us >> 32));
    put32(static_cast<std::uint32_t>(record.timestamp_us));
    put32(record.frame.length);
    put32(record.frame.length);
    prepared_.insert(prepared_.end(), record.frame.view().begin(),
                     record.frame.view().end());
    prepared_.resize(prepared_.size() + padded - record.frame.size(), 0);
    put32(total);
  }
}

} // namespace router
