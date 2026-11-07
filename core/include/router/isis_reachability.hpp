// RFC 5305 and RFC 5308 reachability wire values. Cursors own only traversal
// state and borrow packet memory; the LSDB owns retained advertisements.
// Dependencies point to packet and IP values, with no runtime or CLI coupling.

#pragma once

#include "router/ip_address.hpp"
#include "router/isis_packet.hpp"

namespace router::packet::isis {

inline constexpr std::uint32_t maximum_link_metric = 0x00ffffffU;
inline constexpr std::uint32_t maximum_path_metric = 0xfe000000U;

// RFC 5305 section 3 excludes maximum-link-metric edges from normal SPF.
// Section 4 saturates path sums; prefix metrics above the maximum are unusable.
[[nodiscard]] constexpr std::uint32_t
path_metric_sum(std::uint32_t left, std::uint32_t right) noexcept {
  return left >= maximum_path_metric || right >= maximum_path_metric - left
             ? maximum_path_metric : left + right;
}

struct ExtendedNeighbor {
  LanId id{};
  std::uint32_t metric{};
  std::span<const std::uint8_t> sub_tlvs;
};

struct ExtendedPrefix {
  ip::IpPrefix prefix{};
  std::uint32_t metric{};
  bool down{};
  bool external{}; // RFC 5308 IPv6 flag; TLV 135 has no external flag.
  bool sub_tlvs_present{};
  std::span<const std::uint8_t> sub_tlvs;
};

// Construct with one complete TLV 22, 135 or 236. A wrong code or malformed
// entry makes valid() false permanently; exhaustion preserves true. next()
// returns value identifiers and bounded borrowed sub-TLVs. Unknown sub-TLVs
// remain available unchanged. No allocation, retention or shard affinity.
class ExtendedNeighborCursor final {
public:
  explicit ExtendedNeighborCursor(TlvView tlv) noexcept;
  [[nodiscard]] std::optional<ExtendedNeighbor> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool valid_{};
};

class ExtendedPrefixCursor final {
public:
  explicit ExtendedPrefixCursor(TlvView tlv) noexcept;
  [[nodiscard]] std::optional<ExtendedPrefix> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  ip::AddressFamily family_{ip::AddressFamily::ipv4};
  bool valid_{};
};

// Append one entry in a complete TLV. LSDB packing may combine entries later.
// Invalid values, noncanonical prefixes, malformed nested framing or capacity
// failure leave the writer unchanged. Inputs may borrow writer storage because
// the complete value is staged before append. IPv6 link-local prefixes are not
// originated. SPF eligibility and leakage policy belong to the routing owner.
[[nodiscard]] bool encode_extended_neighbor(TlvWriter &writer,
                                             const ExtendedNeighbor &entry) noexcept;
[[nodiscard]] bool encode_extended_prefix(TlvWriter &writer,
                                           const ExtendedPrefix &entry) noexcept;

} // namespace router::packet::isis
