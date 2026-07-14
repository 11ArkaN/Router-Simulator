// PCAPNG storage implementation. The forwarding shard owns both vectors, and
// reserve at construction prevents capture growth from reallocating packet
// data.

#include "router/capture_store.hpp"

#include "router/generated_profile.hpp"

#include <string>

namespace router {

CaptureStore::CaptureStore() { records_.reserve(capacity); }

bool CaptureStore::record(std::uint8_t interface_id, const packet::Frame &frame,
                          std::uint64_t timestamp_us) {
  if (records_.size() == capacity)
    return false;
  records_.push_back({timestamp_us, interface_id, frame});
  return true;
}

void CaptureStore::encode() {
  // Source: ietf.pcapng.draft_ietf_opsawg_05. Each modeled capture point owns
  // an IDB, so EPB interface IDs preserve the physical observation point.
  std::size_t size = 28U;
  for (const auto *name : profile::capture_interface_names) {
    const auto length = std::char_traits<char>::length(name);
    size += 28U + ((length + 3U) & ~std::size_t{3U});
  }
  for (const auto &record : records_) {
    size += 32U + ((record.frame.size() + 3U) & ~std::size_t{3U});
  }
  prepared_.clear();
  prepared_.reserve(size);
  const auto put16 = [this](std::uint16_t value) {
    prepared_.push_back(static_cast<std::uint8_t>(value));
    prepared_.push_back(static_cast<std::uint8_t>(value >> 8));
  };
  const auto put32 = [this](std::uint32_t value) {
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
  for (const auto *name : profile::capture_interface_names) {
    const auto length = std::char_traits<char>::length(name);
    const auto padded = (length + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(28U + padded);
    put32(1);
    put32(total);
    put16(1);
    put16(0);
    put32(1514);
    put16(2);
    put16(static_cast<std::uint16_t>(length));
    prepared_.insert(prepared_.end(), name, name + length);
    prepared_.resize(prepared_.size() + padded - length, 0);
    put16(0);
    put16(0);
    put32(total);
  }
  for (const auto &record : records_) {
    const auto padded = (record.frame.size() + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(32U + padded);
    put32(6);
    put32(total);
    put32(record.interface_id);
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
