// ISO 10589 clause 9.8 and RFC 1195 section 5.3 narrow entry codecs. All state
// is cursor-local; packet storage and subsequent protocol decisions are owned
// by callers. Unsupported optional metrics retain absence rather than a cost.
// Source: iso.10589.2002.narrow_reachability
// Source: ietf.isis.narrow_ipv4.rfc1195
// Source: ietf.isis.domain_wide.rfc5302

#include "router/isis_narrow_reachability.hpp"

#include <algorithm>

namespace router::packet::isis {
namespace {
[[nodiscard]] NarrowMetrics metrics(std::span<const std::uint8_t> bytes) noexcept {
  const auto optional = [](std::uint8_t byte) -> std::optional<std::uint8_t> {
    return (byte & 0x80U) != 0U ? std::nullopt :
        std::optional<std::uint8_t>(static_cast<std::uint8_t>(byte & 0x3fU));
  };
  return {static_cast<std::uint8_t>(bytes[0U] & 0x3fU), (bytes[0U] & 0x40U) != 0U,
          optional(bytes[1U]), optional(bytes[2U]), optional(bytes[3U])};
}

[[nodiscard]] bool valid(const NarrowMetrics &value) noexcept {
  return value.metric <= 63U && (!value.delay || *value.delay <= 63U) &&
         (!value.expense || *value.expense <= 63U) && (!value.error || *value.error <= 63U);
}

void write_metrics(std::span<std::uint8_t> output, const NarrowMetrics &value) noexcept {
  output[0U] = static_cast<std::uint8_t>(value.metric | (value.external_metric ? 0x40U : 0U));
  output[1U] = value.delay.value_or(0x80U);
  output[2U] = value.expense.value_or(0x80U);
  output[3U] = value.error.value_or(0x80U);
}
}

NarrowNeighborCursor::NarrowNeighborCursor(TlvView tlv) noexcept {
  valid_ = tlv.code == 2U && !tlv.value.empty() && tlv.value.size() <= 255U &&
           (tlv.value.size() - 1U) % 11U == 0U && tlv.value[0U] <= 1U;
  if (valid_) {
    virtual_link_ = tlv.value[0U] == 1U;
    remaining_ = tlv.value.subspan(1U);
  }
}

std::optional<NarrowNeighbor> NarrowNeighborCursor::next() noexcept {
  if (!valid_ || remaining_.empty()) return std::nullopt;
  NarrowNeighbor result{metrics(remaining_), {}, virtual_link_};
  std::copy_n(remaining_.begin() + 4U, result.id.size(), result.id.begin());
  remaining_ = remaining_.subspan(11U);
  return result;
}

NarrowIpv4Cursor::NarrowIpv4Cursor(TlvView tlv) noexcept
    : remaining_(tlv.value), external_(tlv.code == 130U),
      valid_((tlv.code == 128U || tlv.code == 130U) && tlv.value.size() <= 255U &&
             tlv.value.size() % 12U == 0U) {}

std::optional<NarrowIpv4> NarrowIpv4Cursor::next() noexcept {
  if (!valid_ || remaining_.empty()) return std::nullopt;
  NarrowIpv4 result{metrics(remaining_), {}, {}, external_, (remaining_[0U] & 0x80U) != 0U};
  std::copy_n(remaining_.begin() + 4U, result.address.size(), result.address.begin());
  std::copy_n(remaining_.begin() + 8U, result.mask.size(), result.mask.begin());
  remaining_ = remaining_.subspan(12U);
  return result;
}

bool encode_narrow_neighbor(TlvWriter &writer, const NarrowNeighbor &entry) noexcept {
  if (!valid(entry.metrics) || entry.metrics.external_metric) return false;
  std::array<std::uint8_t, 12U> bytes{};
  bytes[0U] = entry.virtual_link ? 1U : 0U;
  write_metrics(std::span(bytes).subspan(1U), entry.metrics);
  std::copy(entry.id.begin(), entry.id.end(), bytes.begin() + 5U);
  return writer.append(2U, bytes);
}

bool encode_narrow_ipv4(TlvWriter &writer, const NarrowIpv4 &entry) noexcept {
  if (!valid(entry.metrics) || (!entry.external_reachability && entry.metrics.external_metric))
    return false;
  std::array<std::uint8_t, 12U> bytes{};
  write_metrics(bytes, entry.metrics);
  if (entry.down) bytes[0U] |= 0x80U;
  std::copy(entry.address.begin(), entry.address.end(), bytes.begin() + 4U);
  std::copy(entry.mask.begin(), entry.mask.end(), bytes.begin() + 8U);
  return writer.append(entry.external_reachability ? 130U : 128U, bytes);
}

} // namespace router::packet::isis
