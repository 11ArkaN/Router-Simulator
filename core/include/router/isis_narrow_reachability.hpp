// Original six-bit IS-IS reachability values. Cursors borrow immutable TLV
// bytes and own only traversal state; retained LSDB and routing state belong
// to their protocol owners. Dependencies point only to packet/IP values.

#pragma once

#include "router/isis_packet.hpp"
#include "router/ip_address.hpp"

namespace router::packet::isis {

struct NarrowMetrics {
  std::uint8_t metric{};
  bool external_metric{};
  std::optional<std::uint8_t> delay;
  std::optional<std::uint8_t> expense;
  std::optional<std::uint8_t> error;
};

struct NarrowNeighbor {
  NarrowMetrics metrics{};
  LanId id{};
  bool virtual_link{};
};

struct NarrowIpv4 {
  NarrowMetrics metrics{};
  ip::Ipv4 address{};
  ip::Ipv4 mask{};
  bool external_reachability{};
  bool down{}; // RFC 5302 reassigns the default metric's high bit for IP only.
};

// The complete TLV must have an integral entry count. Wrong codes, missing
// virtual flag or partial entries set valid() false before traversal. Values
// are copied, never retained by the cursor. No allocation or shard affinity.
class NarrowNeighborCursor final {
public:
  explicit NarrowNeighborCursor(TlvView tlv) noexcept;
  [[nodiscard]] std::optional<NarrowNeighbor> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool virtual_link_{};
  bool valid_{};
};

class NarrowIpv4Cursor final {
public:
  explicit NarrowIpv4Cursor(TlvView tlv) noexcept;
  [[nodiscard]] std::optional<NarrowIpv4> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool external_{};
  bool valid_{};
};

// Each call appends one complete TLV. Metrics must fit six bits; IS neighbors
// and internal IPv4 reachability require internal metrics. Failure leaves the
// destination unchanged. Address/mask bytes are preserved, including received
// noncontiguous masks allowed by RFC 1195. Route eligibility is a separate check.
[[nodiscard]] bool encode_narrow_neighbor(TlvWriter &writer, const NarrowNeighbor &entry) noexcept;
[[nodiscard]] bool encode_narrow_ipv4(TlvWriter &writer, const NarrowIpv4 &entry) noexcept;

} // namespace router::packet::isis
