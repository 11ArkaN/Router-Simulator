// Normative IS-IS prefix distance and class ordering as immutable values.
// No state is owned. The instance owner supplies a completed origin distance;
// policy, administrative preferences and forwarding remain outside this module.

// Source: ietf.isis.prefix_distance

#pragma once

#include "router/isis_spf.hpp"

#include <compare>

namespace router::isis {
struct PrefixPath {
  ip::AddressFamily family{ip::AddressFamily::ipv4};
  MetricStyle style{MetricStyle::wide};
  std::uint8_t level{};
  bool down{}, external_route{}, external_metric{};
  std::uint32_t advertised_metric{}, origin_distance{};
};
struct PrefixDistance {
  std::uint8_t rank{};
  std::uint32_t metric{}, internal_metric{};
  auto operator<=>(const PrefixDistance &) const = default;
};
// Requires the distance to an eligible reachable originating IS, not a guessed
// editor path. nullopt excludes invalid contexts, prohibited narrow metric type,
// over-maximum advertised metrics and overflowing narrow sums. Wide sums saturate.
// Ordering applies to equal destination prefixes inside one IS-IS calculation,
// before global administrative preference. External route type alone does not
// change this ordering. IPv4 ignores L2 down as recommended by RFC 5302 3.3;
// IPv6 retains all four mandatory classes from RFC 5308 5. No allocation/affinity.
[[nodiscard]] inline std::optional<PrefixDistance> prefix_distance(const PrefixPath &path) noexcept {
  const bool ipv6 = path.family == ip::AddressFamily::ipv6;
  if ((path.family != ip::AddressFamily::ipv4 && !ipv6) || path.style > MetricStyle::wide ||
      (path.level != 1U && path.level != 2U) || (ipv6 && path.style != MetricStyle::wide)) return std::nullopt;
  std::uint8_t rank = ipv6 ? static_cast<std::uint8_t>(path.level == 1U ? (path.down ? 3U : 0U) : (path.down ? 2U : 1U))
      : static_cast<std::uint8_t>(path.level == 2U ? 1U : (path.down ? 2U : 0U));
  if (path.style == MetricStyle::narrow) {
    if (path.advertised_metric > 63U || path.origin_distance > 1023U ||
        (path.external_metric && !path.external_route)) return std::nullopt;
    if (path.external_metric)
      return PrefixDistance{static_cast<std::uint8_t>(rank + 3U), path.advertised_metric, path.origin_distance};
    if (path.advertised_metric > 1023U - path.origin_distance) return std::nullopt;
    return PrefixDistance{rank, path.origin_distance + path.advertised_metric, 0U};
  }
  if (path.external_metric || path.advertised_metric > packet::isis::maximum_path_metric ||
      path.origin_distance > packet::isis::maximum_path_metric) return std::nullopt;
  return PrefixDistance{rank, packet::isis::path_metric_sum(path.origin_distance, path.advertised_metric), 0U};
}
} // namespace router::isis
