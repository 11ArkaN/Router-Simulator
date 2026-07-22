// RFC 7296 section 2.23 SHA-1 over SPIi, SPIr, IP address and network-order
// port. SHA-1 is retained only because the wire protocol mandates it here; it
// is not used as an authentication or key-derivation algorithm.

#include "router/ikev2_nat_detection.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>

namespace router::ikev2 {
namespace {

void write_u64(std::span<std::uint8_t> output, std::size_t offset,
               std::uint64_t value) noexcept {
  for (std::size_t index = 0U; index < 8U; ++index)
    output[offset + index] =
        static_cast<std::uint8_t>(value >> ((7U - index) * 8U));
}

} // namespace

NatDetectionStatus compute_nat_detection_hash(
    std::uint64_t initiator_spi, std::uint64_t responder_spi,
    std::span<const std::uint8_t> ip_address, std::uint16_t port,
    NatDetectionHash &output) noexcept {
  if (ip_address.size() != 4U && ip_address.size() != 16U)
    return NatDetectionStatus::invalid_address;
  std::array<std::uint8_t, 34U> input{};
  write_u64(input, 0U, initiator_spi);
  write_u64(input, 8U, responder_spi);
  std::copy(ip_address.begin(), ip_address.end(), input.begin() + 16U);
  const auto port_offset = 16U + ip_address.size();
  input[port_offset] = static_cast<std::uint8_t>(port >> 8U);
  input[port_offset + 1U] = static_cast<std::uint8_t>(port);
  unsigned int digest_octets{};
  if (EVP_Digest(input.data(), port_offset + 2U, output.data(), &digest_octets,
                 EVP_sha1(), nullptr) != 1 ||
      digest_octets != output.size()) {
    output.fill(0U);
    return NatDetectionStatus::provider_failure;
  }
  return NatDetectionStatus::ok;
}

bool equal_nat_detection_hash(const NatDetectionHash &expected,
                              std::span<const std::uint8_t> received) noexcept {
  if (received.size() != expected.size())
    return false;
  std::uint8_t difference{};
  for (std::size_t index = 0U; index < expected.size(); ++index)
    difference = static_cast<std::uint8_t>(difference |
                                           (expected[index] ^ received[index]));
  return difference == 0U;
}

} // namespace router::ikev2
