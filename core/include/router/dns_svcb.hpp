// Allocation-free SVCB and HTTPS RDATA decoder. The caller owns canonical
// RDATA bytes and fixed parameter storage. This module validates record wire
// structure but leaves scheme-specific compatibility decisions to DDR, HTTP
// or another service mapping owner.

#pragma once

#include "router/dns_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace router::packet::dns::svcb {

inline constexpr std::uint16_t key_mandatory = 0U;
inline constexpr std::uint16_t key_alpn = 1U;
inline constexpr std::uint16_t key_no_default_alpn = 2U;
inline constexpr std::uint16_t key_port = 3U;
inline constexpr std::uint16_t key_ipv4hint = 4U;
inline constexpr std::uint16_t key_ech = 5U;
inline constexpr std::uint16_t key_ipv6hint = 6U;
inline constexpr std::uint16_t key_dohpath = 7U;

struct Parameter {
  std::uint16_t key{};
  std::span<const std::uint8_t> value;
};

struct RecordView {
  std::uint16_t priority{};
  Name target;
  std::span<const Parameter> parameters;

  [[nodiscard]] bool alias_mode() const noexcept { return priority == 0U; }
};

// Preconditions: rdata is canonical module-owned SVCB or HTTPS RDATA and
// parameter_storage outlives the returned view. The parser rejects compressed
// TargetName, non-increasing keys, truncated values and malformed formats for
// every base key it recognizes. No allocation or mutation outside storage is
// performed.
[[nodiscard]] std::optional<RecordView>
parse(std::span<const std::uint8_t> rdata,
      std::span<Parameter> parameter_storage) noexcept;

[[nodiscard]] const Parameter *find(const RecordView &record,
                                    std::uint16_t key) noexcept;

// Visits opaque ALPN identifiers without converting them to C strings. The
// callback returns false to stop. A false return from this function means the
// ALPN value itself was malformed, not merely that the visitor stopped.
template <typename Visitor>
[[nodiscard]] bool visit_alpn(std::span<const std::uint8_t> value,
                              Visitor visitor) noexcept {
  if (value.empty())
    return false;
  std::size_t offset{};
  while (offset < value.size()) {
    const auto length = static_cast<std::size_t>(value[offset++]);
    if (length == 0U || length > value.size() - offset)
      return false;
    if (!visitor(value.subspan(offset, length)))
      return true;
    offset += length;
  }
  return offset == value.size();
}

} // namespace router::packet::dns::svcb
