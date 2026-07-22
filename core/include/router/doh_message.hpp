// HTTP-version-independent DNS-over-HTTPS wire semantics. This module owns
// only DNS message validation and the RFC 8484 GET representation. HTTP/2,
// HTTP/3, TLS and QUIC remain owned by their transport adapters.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::doh {

inline constexpr std::string_view dns_media_type{"application/dns-message"};

enum class Method : std::uint8_t { get, post };

// The DNS wire limit is checked here before an HTTP adapter copies a body.
// Postcondition: true means the span contains at least a DNS header and no
// more than the DNS codec's supported maximum message size.
[[nodiscard]] bool
valid_dns_message(std::span<const std::uint8_t> message) noexcept;

// RFC 8484 uses unpadded base64url for the GET dns query parameter. Encoding
// may allocate and therefore reports failure with nullopt instead of allowing
// an exception to cross a transport-owner boundary.
[[nodiscard]] std::optional<std::string>
encode_query_parameter(std::span<const std::uint8_t> message) noexcept;

// Non-canonical trailing bits, padding and the ordinary base64 alphabet are
// rejected. The returned buffer is owned by the caller.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
decode_query_parameter(std::string_view value) noexcept;

} // namespace router::doh
