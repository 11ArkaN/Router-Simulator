// Prefix sub-TLV wire values for administrative tags and origin attributes.
// Cursors own traversal only and borrow prefix bytes from their caller. Routing,
// policy decisions, source-ID consistency and leakage remain instance-owned.

#pragma once

#include "router/isis_reachability.hpp"

namespace router::packet::isis {
struct AdministrativeTag {
  std::uint64_t value{};
  bool wide{};
};
class AdministrativeTagCursor final {
public:
  // Requires one prefix sub-TLV 1 or 2. A nonempty integral list is mandatory.
  // Zero is preserved as a wire value; policy treats it as no tag (RFC 5130).
  // Input outlives traversal. No allocation or retained owner reference.
  explicit AdministrativeTagCursor(TlvView option) noexcept;
  [[nodiscard]] std::optional<AdministrativeTag> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
private:
  std::span<const std::uint8_t> remaining_;
  std::uint8_t width_{};
  bool valid_{};
};
// Append one complete nonempty list, preserving caller order. The maximum is
// 63 32-bit or 31 64-bit values. Invalid count or capacity preserves writer.
// Zero remains representable; prefix policy owns omission of no-tag values.
[[nodiscard]] bool encode_administrative_tags(TlvWriter &writer, std::span<const std::uint32_t> tags) noexcept;
[[nodiscard]] bool encode_administrative_tags(TlvWriter &writer, std::span<const std::uint64_t> tags) noexcept;
struct PrefixAttributeFlags {
  bool external{}, readvertised{}, node{};
  bool operator==(const PrefixAttributeFlags &) const = default;
};
// Sub-TLV 4 uses X/R/N in the first octet. Missing bits are zero, unknown bits
// are ignored, X is ignored for IPv6 and N is ignored for non-host prefixes.
// Invalid code, context or oversized value returns nullopt. No borrowed result.
[[nodiscard]] std::optional<PrefixAttributeFlags> prefix_attribute_flags(TlvView option,
    const ip::IpPrefix &prefix) noexcept;
// Canonical one-octet generation zeros undefined bits. Refuses N on non-host
// prefixes and X on IPv6; IPv6 externality belongs in the fixed reachability
// header. Refusal preserves writer bytes/cursor. Caller supplies the context.
[[nodiscard]] bool encode_prefix_attribute_flags(TlvWriter &writer, const ip::IpPrefix &prefix,
    PrefixAttributeFlags flags) noexcept;
// Sub-TLV 11 is IPv4 and 12 is IPv6, independent of the advertised prefix's
// family. Same-owner generation must agree with the corresponding TE Router
// ID when present; this codec owns neither originating identity nor LSDB state.
[[nodiscard]] std::optional<ip::IpAddress> prefix_source_router_id(TlvView option) noexcept;
[[nodiscard]] bool encode_prefix_source_router_id(TlvWriter &writer, const ip::IpAddress &address) noexcept;
} // namespace router::packet::isis
