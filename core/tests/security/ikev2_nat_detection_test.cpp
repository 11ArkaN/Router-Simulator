// NAT detection tests cover the exact network byte order for IPv6 and reject
// address lengths that cannot occur in an IKE endpoint tuple.

#include "router/ikev2_nat_detection.hpp"

#include <array>
#include <stdexcept>

void ikev2_nat_detection_tests() {
  using namespace router::ikev2;
  const std::array<std::uint8_t, 16U> address{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U,    0U,    0U,    0U, 0U, 0U, 1U};
  const NatDetectionHash expected{
      0x64U, 0x5eU, 0xfdU, 0xf3U, 0xa4U, 0xd4U, 0x73U,
      0x67U, 0x9cU, 0x6aU, 0x65U, 0x30U, 0xabU, 0xefU,
      0xd3U, 0xb7U, 0x1dU, 0x8cU, 0x18U, 0xafU};
  NatDetectionHash actual{};
  if (compute_nat_detection_hash(0x0102030405060708ULL,
                                 0x1112131415161718ULL, address, 500U,
                                 actual) != NatDetectionStatus::ok ||
      actual != expected || !equal_nat_detection_hash(expected, actual))
    throw std::runtime_error("IKEv2 NAT detection hash mismatch");
  if (compute_nat_detection_hash(1U, 2U,
                                 std::span{address}.first(8U), 500U,
                                 actual) !=
      NatDetectionStatus::invalid_address)
    throw std::runtime_error("invalid NAT detection address was accepted");
}
