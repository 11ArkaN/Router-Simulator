// Canonical binary codec for one TCP endpoint checkpoint. This module owns
// only serialization and never mutates a live socket table. The enclosing lab
// checkpoint stores the returned byte image as one length-delimited ABI field.

#pragma once

#include "router/tcp_endpoint.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::transport::tcp::checkpoint {

// Encoding rejects values whose vector sizes cannot be represented by the
// portable 32-bit length fields. No native pointer, size_t width, padding or
// steady-clock epoch enters the image.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
encode(const EndpointCheckpoint &state) noexcept;

// Decoding consumes the complete image and constructs detached value state.
// TcpEndpoint::restore performs semantic and cross-field validation before
// publishing it to a forwarding owner.
[[nodiscard]] std::optional<EndpointCheckpoint>
decode(std::span<const std::uint8_t> bytes) noexcept;

} // namespace router::transport::tcp::checkpoint
