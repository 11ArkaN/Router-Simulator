// Independent wire identifiers form deterministic neighbor object keys.
// Caller-owned buffers verify ordering, malformed values and atomic refusal.
#include "router/isis_neighbor_key.hpp"
#include <algorithm>
#include <source_location>
#include <stdexcept>
#include <string>
namespace {
using namespace router;
using namespace router::packet::isis;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS neighbor key invariant at " + std::to_string(where.line()));
}
}
void isis_neighbor_key_tests() {
  std::array<std::uint8_t, maximum_neighbor_key_octets> first{}, second{}, output{}, ordered{};
  const std::array<std::uint8_t, 4U> a{192U, 0U, 2U, 1U}, b{192U, 0U, 2U, 2U};
  const auto global = *ip::parse_ipv6("2001:db8::1"), local = *ip::parse_ipv6("fe80::1");
  const std::array<std::uint8_t, 8U> ids{0U, 0U, 0U, 1U, 0U, 0U, 0U, 2U};
  TlvWriter one(first), two(second);
  require(one.append(8U, b) && one.append(6U, b) && one.append(6U, a) && one.append(6U, a) &&
      one.append(12U, global) && one.append(4U, ids) && one.append(18U, a));
  require(two.append(4U, ids) && two.append(12U, global) && two.append(6U, a) && two.append(6U, b) && two.append(8U, b));
  const auto size = normalize_neighbor_key(one.bytes(), output), sorted = normalize_neighbor_key(two.bytes(), ordered);
  require(size && sorted && *size == *sorted && *size == 46U &&
      std::equal(output.begin(), output.begin() + *size, ordered.begin()));
  // Canonical staging remains safe even when the destination overlaps input.
  const auto alias = normalize_neighbor_key(one.bytes(), first);
  require(alias == size && std::equal(first.begin(), first.begin() + *alias, ordered.begin()));
  // Duplicate type 4 is ignored in full, rather than choosing one conflicting ID.
  TlvWriter duplicates(first);
  require(duplicates.append(4U, ids) && duplicates.append(4U, ids) && duplicates.append(6U, a));
  const auto reduced = normalize_neighbor_key(duplicates.bytes(), output);
  require(reduced == 6U && output[0U] == 6U && output[1U] == 4U);
  TlvWriter invalid(first);
  require(invalid.append(4U, std::span{ids}.first(7U)) && invalid.append(6U, std::span{a}.first(3U)) &&
      invalid.append(12U, local) && invalid.append(13U, local) && invalid.append(8U, b));
  require(normalize_neighbor_key(invalid.bytes(), output) == 6U && output[0U] == 8U);
  output.fill(0xaaU);
  const auto before = output;
  require(!normalize_neighbor_key(two.bytes(), std::span{output}.first(5U)) && output == before);
  const std::array<std::uint8_t, 3U> truncated{6U, 4U, 1U};
  require(!normalize_neighbor_key(truncated, output) && output == before);
  std::array<std::uint8_t, maximum_neighbor_key_octets + 1U> oversized{};
  require(!normalize_neighbor_key(oversized, output) && output == before);
  require(normalize_neighbor_key({}, {}) == 0U);
}
