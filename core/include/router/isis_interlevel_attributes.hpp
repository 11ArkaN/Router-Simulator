// The instance control owner canonicalizes one copied prefix attribute set
// before interlevel origination. This allocation-free adapter owns no routing
// state and depends only on wire codecs; policy and source identity stay outside.
// Source: ietf.isis.selected_interlevel_export
#pragma once
#include "router/isis_prefix_attributes.hpp"
namespace router::isis {
enum class InterlevelAttributeStatus : std::uint8_t { applied, invalid, capacity };
struct InterlevelAttributeResult {
  InterlevelAttributeStatus status{InterlevelAttributeStatus::invalid};
  std::size_t octets{};
};
// Same control owner, immutable complete joined sub-TLV input, disjoint output.
// Canonicalizes flags with R set, preserves valid X/N, first valid source IDs,
// and all valid tags in their original order. Long tag lists are split at whole
// tag boundaries so every sub-TLV fits an independent reachability part.
// Unknown and invalid individual attributes
// are ignored. Malformed framing or insufficient capacity preserves output.
// No allocation; output can exceed one reachability part. The caller must encode
// RFC 9885 parts without truncation. TE-ID consistency belongs to origin policy.
[[nodiscard]] InterlevelAttributeResult prepare_interlevel_attributes(const ip::IpPrefix &,
    std::span<const std::uint8_t>, std::span<std::uint8_t>) noexcept;
// A control-local cursor borrows canonical attributes until exhausted. Every
// returned complete TLV borrows cursor scratch until next(); no part splits a
// sub-TLV. Construction validates the entire input before exposing any part.
class InterlevelPrefixParts final {
public:
  explicit InterlevelPrefixParts(packet::isis::ExtendedPrefix) noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] std::optional<std::span<const std::uint8_t>> next() noexcept;
private:
  packet::isis::ExtendedPrefix prefix_;
  std::span<const std::uint8_t> remaining_;
  std::array<std::uint8_t, 257U> bytes_{};
  std::size_t capacity_{};
  bool valid_{}, first_{true};
};
}
