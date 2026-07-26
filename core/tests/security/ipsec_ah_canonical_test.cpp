// AH canonicalization tests prove every mutable base-header field is zero,
// immutable bytes survive, ICV bytes are cleared and unsupported header chains
// or fragments fail closed before integrity verification.

#include "router/ipsec_ah_canonical.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void ipsec_ah_canonical_tests() {
  using namespace router::ipsec;
  // IPv4 total length is 48: 20 base + 28 AH with a 16-octet ICV.
  std::array<std::uint8_t, 48U> ipv4{};
  ipv4[0U] = 0x45U;
  ipv4[1U] = 0xabU;
  ipv4[2U] = 0U;
  ipv4[3U] = 48U;
  ipv4[4U] = 0x12U;
  ipv4[5U] = 0x34U;
  ipv4[6U] = 0x40U;
  ipv4[8U] = 64U;
  ipv4[9U] = ip_protocol_ah;
  ipv4[10U] = 0xaaU;
  ipv4[11U] = 0xbbU;
  ipv4[12U] = 192U;
  ipv4[15U] = 1U;
  ipv4[16U] = 192U;
  ipv4[19U] = 2U;
  ipv4[20U] = 6U;
  ipv4[21U] = 5U;
  ipv4[24U] = 0x10U;
  ipv4[27U] = 1U;
  ipv4[31U] = 1U;
  std::fill(ipv4.begin() + 32, ipv4.end(), std::uint8_t{0x5aU});
  std::array<std::uint8_t, ipv4.size()> canonical4{};
  const auto result4 = ah::canonicalize_ipv4(ipv4, canonical4);
  if (result4.status != ah::CanonicalStatus::ok || canonical4[0U] != 0x45U ||
      canonical4[4U] != 0x12U || canonical4[9U] != ip_protocol_ah ||
      canonical4[1U] != 0U || canonical4[6U] != 0U ||
      canonical4[8U] != 0U || canonical4[10U] != 0U ||
      std::any_of(canonical4.begin() + 32, canonical4.end(),
                  [](auto byte) { return byte != 0U; }))
    throw std::runtime_error("IPv4 AH canonicalization failed");
  auto fragmented = ipv4;
  fragmented[7U] = 1U;
  if (ah::canonicalize_ipv4(fragmented, canonical4).status !=
      ah::CanonicalStatus::fragmented)
    throw std::runtime_error("fragmented IPv4 reached AH integrity input");

  std::array<std::uint8_t, 72U> ipv6{};
  ipv6[0U] = 0x6aU;
  ipv6[1U] = 0xbcU;
  ipv6[2U] = 0xdeU;
  ipv6[3U] = 0xf0U;
  ipv6[5U] = 32U;
  ipv6[6U] = ip_protocol_ah;
  ipv6[7U] = 32U;
  ipv6[8U] = 0x20U;
  ipv6[24U] = 0x20U;
  ipv6[40U] = 6U;
  ipv6[41U] = 6U;
  ipv6[44U] = 0x10U;
  ipv6[47U] = 2U;
  ipv6[51U] = 1U;
  std::fill(ipv6.begin() + 52, ipv6.begin() + 68,
            std::uint8_t{0xa5U});
  std::array<std::uint8_t, ipv6.size()> canonical6{};
  const auto result6 = ah::canonicalize_ipv6(ipv6, canonical6);
  if (result6.status != ah::CanonicalStatus::ok || canonical6[0U] != 0x60U ||
      canonical6[4U] != 0U || canonical6[5U] != 32U ||
      canonical6[6U] != ip_protocol_ah || canonical6[7U] != 0U ||
      canonical6[8U] != 0x20U ||
      std::any_of(canonical6.begin() + 52, canonical6.end(),
                  [](auto byte) { return byte != 0U; }))
    throw std::runtime_error("IPv6 AH canonicalization failed");
  auto extension = ipv6;
  extension[6U] = 0U;
  if (ah::canonicalize_ipv6(extension, canonical6).status !=
      ah::CanonicalStatus::unsupported_header_chain)
    throw std::runtime_error("unsupported IPv6 AH chain was guessed");
}
