// ISO area and LAN-neighbor lists and integrated IS-IS address advertisements.
// Views borrow caller bytes; cursors own only offsets. No protocol acceptance,
// timer, routing or configuration state belongs to this wire-value module.

#pragma once

#include "router/isis_packet.hpp"
#include "router/ip_address.hpp"

#include <algorithm>

namespace router::packet::isis {

inline constexpr std::uint8_t ipv4_nlpid = 0xccU;
inline constexpr std::uint8_t ipv6_nlpid = 0x8eU;
inline constexpr std::size_t maximum_area_octets = 13U;

class AreaAddressCursor final {
public:
  explicit AreaAddressCursor(TlvView tlv) noexcept
      : remaining_(tlv.value), valid_(tlv.code == 1U && tlv.value.size() <= 255U) {}
  // Each address is length-prefixed, nonempty and at most 13 octets in this
  // six-octet ID profile. Truncation or invalid length is a sticky failure.
  [[nodiscard]] std::optional<std::span<const std::uint8_t>> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool valid_{};
};

// Fixed-width values are copied out without alignment or object-lifetime casts.
// The entire outer value must have an integral entry count before traversal.
// The caller supplies the required TLV code; address-placement rules remain
// with the process owner. The template owns no storage beyond its cursor.
template <std::size_t Width> class FixedAddressCursor final {
  static_assert(Width > 0U && Width <= 255U);
public:
  explicit FixedAddressCursor(TlvView tlv, std::uint8_t expected_code) noexcept
      : remaining_(tlv.value), valid_(tlv.code == expected_code &&
          tlv.value.size() <= 255U && tlv.value.size() % Width == 0U) {}
  [[nodiscard]] std::optional<std::array<std::uint8_t, Width>> next() noexcept {
    if (!valid_ || remaining_.empty()) return std::nullopt;
    std::array<std::uint8_t, Width> value{};
    std::copy_n(remaining_.begin(), Width, value.begin());
    remaining_ = remaining_.subspan(Width);
    return value;
  }
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  bool valid_{};
};

// Append one complete area-list TLV, or leave the writer unchanged on any
// invalid area or capacity failure. Storage may alias the writer's destination.
// No allocation or shard affinity; area-count policy belongs to configuration.
[[nodiscard]] bool encode_area_addresses(TlvWriter &writer,
    std::span<const std::span<const std::uint8_t>> areas) noexcept;

// Encodes fixed-width TLV values using bounded staging, permitting aliased
// inputs. Empty lists are represented explicitly as zero-length TLVs. Width
// and code are selected by typed protocol call sites, never inferred from data.
template <std::size_t Width>
[[nodiscard]] bool encode_fixed_addresses(TlvWriter &writer, std::uint8_t code,
    std::span<const std::array<std::uint8_t, Width>> addresses) noexcept {
  static_assert(Width > 0U && Width <= 255U);
  if (addresses.size() > 255U / Width) return false;
  std::array<std::uint8_t, 255U> bytes{};
  std::size_t offset{};
  for (const auto &address : addresses) {
    std::copy(address.begin(), address.end(), bytes.begin() + offset);
    offset += Width;
  }
  return writer.append(code, std::span(bytes).first(offset));
}

// RFC 1195 and RFC 5308 protocol declarations. Unknown NLPIDs remain legal;
// false means malformed framing or absence, not a peer capability decision.
[[nodiscard]] bool supports_protocol(TlvView tlv, std::uint8_t nlpid) noexcept;

// RFC 5308 section 3: Hello address TLVs contain only link-local addresses;
// LSP address TLVs contain only non-link-local addresses. Other PDU families
// do not carry this option. This checks placement without creating a route.
[[nodiscard]] bool valid_ipv6_interface_addresses(TlvView tlv, PduType pdu) noexcept;

} // namespace router::packet::isis
