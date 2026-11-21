// SR OS strict adjacency policy compares configured IPv4/IPv6 families.
// Circuit owners supply immutable local NLPIDs and retained validated Hello
// attributes. No peer, timer, packet or mutable shared state is owned here.
#pragma once
#include "router/isis_basic_tlvs.hpp"
namespace router::isis {
[[nodiscard]] inline std::uint8_t address_family_mask(std::span<const std::uint8_t> protocols) noexcept {
  std::uint8_t result{};
  for (const auto value : protocols) {
    if (value == packet::isis::ipv4_nlpid) result |= 1U;
    if (value == packet::isis::ipv6_nlpid) result |= 2U;
  }
  return result;
}
// Same-owner borrowed TLVs. Malformed input refuses without state mutation.
[[nodiscard]] inline std::optional<std::uint8_t> peer_address_family_mask(
    std::span<const std::uint8_t> attributes) noexcept {
  packet::isis::TlvCursor cursor(attributes);
  std::uint8_t result{};
  while (const auto option = cursor.next())
    if (option->code == 129U) result |= address_family_mask(option->value);
  return cursor.valid() ? std::optional{result} : std::nullopt;
}
}
