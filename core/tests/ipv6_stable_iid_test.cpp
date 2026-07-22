// Independent cryptographic and RFC 7217 identity tests. Published SHA and
// HMAC vectors detect errors in the PRF itself before stable-IID assertions can
// accidentally bless two matching defects in tuple construction and hashing.

#include "router/ipv6_stable_iid.hpp"
#include "router/sha256.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string_view>

namespace {

template <std::size_t Size>
std::array<std::uint8_t, Size> hexadecimal(std::string_view text) {
  if (text.size() != Size * 2U)
    throw std::runtime_error("invalid fixed hexadecimal test vector length");
  const auto digit = [](char value) -> std::uint8_t {
    if (value >= '0' && value <= '9')
      return static_cast<std::uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f')
      return static_cast<std::uint8_t>(value - 'a' + 10);
    throw std::runtime_error("invalid hexadecimal test vector digit");
  };
  std::array<std::uint8_t, Size> result{};
  for (std::size_t index = 0; index < Size; ++index)
    result[index] = static_cast<std::uint8_t>(
        (digit(text[index * 2U]) << 4U) | digit(text[index * 2U + 1U]));
  return result;
}

void require(bool condition, const char *reason) {
  if (!condition)
    throw std::runtime_error(reason);
}

} // namespace

void ipv6_stable_iid_tests() {
  using namespace router;
  constexpr std::array<std::uint8_t, 3U> abc{'a', 'b', 'c'};
  require(crypto::sha256(abc) ==
              hexadecimal<32U>(
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9c"
                  "b410ff61f20015ad"),
          "SHA-256 failed the FIPS 180-4 abc vector");

  // RFC 4231 test case 1 proves key normalization, both pads and the nested
  // digest. Splitting the ASCII message also verifies that segment boundaries
  // do not alter the authenticated byte stream.
  std::array<std::uint8_t, 20U> hmac_key{};
  hmac_key.fill(0x0bU);
  constexpr std::array<std::uint8_t, 3U> hi{'H', 'i', ' '};
  constexpr std::array<std::uint8_t, 5U> there{'T', 'h', 'e', 'r', 'e'};
  const std::array<std::span<const std::uint8_t>, 2U> hmac_message{hi, there};
  require(crypto::hmac_sha256(hmac_key, hmac_message) ==
              hexadecimal<32U>(
                  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da7"
                  "26e9376c2e32cff7"),
          "HMAC-SHA-256 failed RFC 4231 test case 1");

  host::StableIidSecret secret{};
  for (std::size_t index = 0; index < secret.size(); ++index)
    secret[index] = static_cast<std::uint8_t>(index);
  const auto prefix = ip::Ipv6Prefix{
      .network = hexadecimal<16U>("20010db8000100000000000000000000"),
      .length = 64U};
  constexpr std::array<std::uint8_t, 10U> network_id{
      'l', 'a', 'b', '-', 'l', 'i', 'n', 'k', '-', '7'};
  const auto first = host::stable_opaque_interface_identifier(
      prefix, 42U, network_id, 0U, secret);
  require(first == hexadecimal<8U>("13add05f1d8538fb"),
          "RFC 7217 tuple did not match the independent HMAC fixture");
  require(first == host::stable_opaque_interface_identifier(
                       prefix, 42U, network_id, 0U, secret),
          "stable IID changed for an identical subnet and interface tuple");

  const auto other_prefix = ip::Ipv6Prefix{
      .network = hexadecimal<16U>("20010db8000200000000000000000000"),
      .length = 64U};
  require(first != host::stable_opaque_interface_identifier(
                       other_prefix, 42U, network_id, 0U, secret) &&
              first != host::stable_opaque_interface_identifier(
                           prefix, 42U, network_id, 1U, secret),
          "prefix or DAD counter failed to separate stable opaque IIDs");

  // The live IANA registry combines the original RFC 5453 assignments with
  // the complete IANA Ethernet block. Exercise both inclusive boundaries and
  // their immediate neighbors so a future byte-order or range merge error
  // cannot reserve too few or too many opaque identifiers.
  require(host::is_reserved_ipv6_interface_identifier(
              hexadecimal<8U>("0000000000000000")) &&
              host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("02005efffe000000")) &&
              host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("02005efffeffffff")) &&
              host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("fdffffffffffff80")) &&
              host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("fdffffffffffffff")),
          "IANA reserved IID boundary was accepted");
  require(!host::is_reserved_ipv6_interface_identifier(
              hexadecimal<8U>("0000000000000001")) &&
              !host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("02005efffdffffff")) &&
              !host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("02005effff000000")) &&
              !host::is_reserved_ipv6_interface_identifier(
                  hexadecimal<8U>("fdffffffffffff7f")),
          "non-reserved IID adjacent to an IANA range was rejected");
}
