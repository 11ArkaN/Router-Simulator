// OSPF packet-authentication primitives. This module owns wire construction
// and digest verification only. Key selection, rollover windows, sequence
// persistence and failure counters belong to the control-plane process.

#pragma once

#include "router/ospf_packet.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace router::ospf::authentication {

enum class V2CryptographicAlgorithm : std::uint8_t {
  message_digest_md5,
  hmac_sha1,
  hmac_sha256
};

enum class V3CryptographicAlgorithm : std::uint8_t {
  hmac_sha1,
  hmac_sha256
};

enum class IpsecAhAlgorithm : std::uint8_t {
  hmac_md5_96,
  hmac_sha1_96
};

struct VerifiedIpsecAh {
  std::span<const std::uint8_t> ospf_packet;
  std::uint32_t spi{};
  std::uint32_t sequence_number{};
};

// The algorithm-neutral entry point implements every cryptographic algorithm
// exposed by the SR OS OSPF keychain profile. Packet Length always excludes
// the appended digest, while the returned wire span includes it.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_v2_cryptographic(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t key_id,
    std::uint32_t sequence_number, V2CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept;

[[nodiscard]] bool
verify_v2_cryptographic(const packet::ospf::PacketView &packet,
                        V2CryptographicAlgorithm algorithm,
                        std::span<const std::uint8_t> key) noexcept;

// RFC 7166 protects the IPv6 source through Apad and appends the complete
// sixteen-octet AT header plus digest outside the OSPFv3 Packet Length.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_v3_authentication_trailer(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t instance_id,
    const ip::Ipv6 &source, std::uint16_t security_association_id,
    std::uint64_t sequence_number, V3CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept;

[[nodiscard]] bool verify_v3_authentication_trailer(
    const packet::ospf::PacketView &packet, const ip::Ipv6 &source,
    V3CryptographicAlgorithm algorithm,
    std::span<const std::uint8_t> key) noexcept;
[[nodiscard]] std::uint16_t
v3_security_association_id(
    const packet::ospf::PacketView &packet) noexcept;
[[nodiscard]] std::uint64_t
v3_sequence_number(const packet::ospf::PacketView &packet) noexcept;

// RFC 4302 transport-mode AH protects the complete IPv6 packet and leaves the
// OSPF packet as the AH payload. The supported SR OS manual-SA algorithms use
// the 96-bit truncation defined by RFC 2403 and RFC 2404. Extension headers are
// deliberately not accepted here: OSPF emits none, and silently
// canonicalizing an unknown mutable option would invalidate authentication.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_ipv6_ipsec_ah(
    std::span<std::uint8_t> output, const ip::Ipv6 &source,
    const ip::Ipv6 &destination, std::uint8_t hop_limit, std::uint32_t spi,
    std::uint32_t sequence_number, IpsecAhAlgorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> ospf_packet) noexcept;

[[nodiscard]] std::optional<VerifiedIpsecAh>
verify_ipv6_ipsec_ah(std::span<const std::uint8_t> ipv6_packet,
                     IpsecAhAlgorithm algorithm,
                     std::span<const std::uint8_t> key) noexcept;

// RFC 5709 requires the full 32-octet SHA-256 output. The OSPF Packet Length
// excludes those octets while the returned span includes them for IP framing.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_v2_hmac_sha256(
    std::span<std::uint8_t> output, packet::ospf::PacketType type,
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t key_id,
    std::uint32_t sequence_number, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> payload) noexcept;

// Verification does not update replay state. The process must compare and
// commit the sequence number only after this function authenticates the bytes.
[[nodiscard]] bool
verify_v2_hmac_sha256(const packet::ospf::PacketView &packet,
                      std::span<const std::uint8_t> key) noexcept;

[[nodiscard]] std::uint8_t
v2_key_id(const packet::ospf::PacketView &packet) noexcept;
[[nodiscard]] std::uint32_t
v2_sequence_number(const packet::ospf::PacketView &packet) noexcept;

} // namespace router::ospf::authentication
