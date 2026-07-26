// RFC 7217 section 5 tuple encoding and HMAC-SHA-256 PRF selection. RFC 7217
// deliberately leaves the PRF and parameter encoding implementation-defined.
// This encoding is versioned by the checkpoint/project contracts and uses
// fixed-width length fields so distinct tuples cannot concatenate ambiguously.

#include "router/ipv6_stable_iid.hpp"

#include "router/sha256.hpp"

#include <algorithm>

namespace router::host {
namespace {

template <typename Integer, std::size_t Size>
std::array<std::uint8_t, Size> big_endian(Integer value) noexcept {
  std::array<std::uint8_t, Size> result{};
  for (std::size_t index = 0; index < Size; ++index)
    result[Size - 1U - index] =
        static_cast<std::uint8_t>(value >> (index * 8U));
  return result;
}

} // namespace

StableInterfaceIdentifier stable_opaque_interface_identifier(
    const ip::Ipv6Prefix &prefix, std::uint64_t interface_id,
    std::span<const std::uint8_t> network_id, std::uint32_t dad_counter,
    const StableIidSecret &secret) noexcept {
  // Canonicalize defensively even though the public precondition asks the
  // caller to do so. This makes host identity stable when a valid prefix was
  // constructed directly rather than through the text parser.
  const auto network = ip::mask(prefix.network, prefix.length);
  const std::array<std::uint8_t, 1U> prefix_length{prefix.length};
  const auto encoded_interface = big_endian<std::uint64_t, 8U>(interface_id);
  const auto encoded_network_length =
      big_endian<std::uint64_t, 8U>(network_id.size());
  const auto encoded_dad_counter =
      big_endian<std::uint32_t, 4U>(dad_counter);
  const std::array<std::span<const std::uint8_t>, 6U> tuple{
      std::span<const std::uint8_t>{network},
      std::span<const std::uint8_t>{prefix_length},
      std::span<const std::uint8_t>{encoded_interface},
      std::span<const std::uint8_t>{encoded_network_length}, network_id,
      std::span<const std::uint8_t>{encoded_dad_counter}};
  const auto rid = crypto::hmac_sha256(secret, tuple);

  StableInterfaceIdentifier iid{};
  // RFC 7217 takes the least significant bits of the RID and treats every IID
  // bit as opaque under RFC 7136. Therefore the final eight network-order
  // digest octets are copied unchanged, including the traditional u/g bits.
  std::copy(rid.end() - static_cast<std::ptrdiff_t>(iid.size()), rid.end(),
            iid.begin());
  return iid;
}

bool is_reserved_ipv6_interface_identifier(
    const StableInterfaceIdentifier &identifier) noexcept {
  // Registry values are written as network-order 64-bit IIDs. Decode them
  // explicitly instead of relying on host endianness so the native Windows
  // and Wasm builds make the same acceptance decision.
  std::uint64_t value{};
  for (const auto octet : identifier)
    value = (value << 8U) | octet;

  constexpr std::uint64_t subnet_router_anycast = 0x0000000000000000ULL;
  constexpr std::uint64_t iana_ethernet_first = 0x02005efffe000000ULL;
  constexpr std::uint64_t iana_ethernet_last = 0x02005efffeffffffULL;
  constexpr std::uint64_t reserved_anycast_first = 0xfdffffffffffff80ULL;
  constexpr std::uint64_t reserved_anycast_last = 0xfdffffffffffffffULL;
  return value == subnet_router_anycast ||
         (value >= iana_ethernet_first && value <= iana_ethernet_last) ||
         (value >= reserved_anycast_first && value <= reserved_anycast_last);
}

} // namespace router::host
