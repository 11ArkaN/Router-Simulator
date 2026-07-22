// DNSSEC RDATA codecs and algorithm-independent derivations. This module owns
// no keys, trust anchors, clock or resolver state. It converts only canonical
// wire values, allowing the signer and validator owners to remain separate.

#pragma once

#include "router/dns_packet.hpp"
#include "router/sha256.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dnssec {

inline constexpr std::uint8_t dnskey_protocol = 3U;
inline constexpr std::uint16_t dnskey_zone_flag = 0x0100U;
inline constexpr std::uint16_t dnskey_secure_entry_point_flag = 0x0001U;
inline constexpr std::uint8_t ds_digest_sha256 = 2U;

struct Dnskey {
  std::uint16_t flags{};
  std::uint8_t protocol{dnskey_protocol};
  std::uint8_t algorithm{};
  std::vector<std::uint8_t> public_key;
};

struct Ds {
  std::uint16_t key_tag{};
  std::uint8_t algorithm{};
  std::uint8_t digest_type{};
  std::vector<std::uint8_t> digest;
};

struct Rrsig {
  std::uint16_t type_covered{};
  std::uint8_t algorithm{};
  std::uint8_t labels{};
  std::uint32_t original_ttl{};
  std::uint32_t signature_expiration{};
  std::uint32_t signature_inception{};
  std::uint16_t key_tag{};
  packet::dns::Name signer_name;
  std::vector<std::uint8_t> signature;
};

struct Nsec {
  packet::dns::Name next_domain;
  std::vector<std::uint16_t> types;
};

struct Nsec3 {
  std::uint8_t hash_algorithm{};
  std::uint8_t flags{};
  std::uint16_t iterations{};
  std::vector<std::uint8_t> salt;
  std::vector<std::uint8_t> next_hashed_owner;
  std::vector<std::uint16_t> types;
};

struct Nsec3param {
  std::uint8_t hash_algorithm{};
  std::uint8_t flags{};
  std::uint16_t iterations{};
  std::vector<std::uint8_t> salt;
};

// Encoders return false without publishing partial bytes. Callers own both the
// value and output vector. DNS RDLENGTH remains the final 65,535-octet bound.
[[nodiscard]] bool encode_dnskey(const Dnskey &value,
                                 std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Dnskey>
decode_dnskey(std::span<const std::uint8_t> rdata) noexcept;
[[nodiscard]] bool encode_ds(const Ds &value,
                             std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Ds>
decode_ds(std::span<const std::uint8_t> rdata) noexcept;
[[nodiscard]] bool encode_rrsig(const Rrsig &value,
                                std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Rrsig>
decode_rrsig(std::span<const std::uint8_t> rdata) noexcept;
[[nodiscard]] bool encode_nsec(const Nsec &value,
                               std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Nsec>
decode_nsec(std::span<const std::uint8_t> rdata) noexcept;
[[nodiscard]] bool encode_nsec3(const Nsec3 &value,
                                std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Nsec3>
decode_nsec3(std::span<const std::uint8_t> rdata) noexcept;
[[nodiscard]] bool encode_nsec3param(
    const Nsec3param &value, std::vector<std::uint8_t> &output) noexcept;
[[nodiscard]] std::optional<Nsec3param>
decode_nsec3param(std::span<const std::uint8_t> rdata) noexcept;

// RFC 4034 Appendix B calculates over the complete DNSKEY RDATA. The caller
// therefore cannot accidentally omit flags, protocol or algorithm bytes.
[[nodiscard]] std::uint16_t
key_tag(std::span<const std::uint8_t> dnskey_rdata) noexcept;

// RFC 4509 digest type 2 hashes canonical owner name followed by DNSKEY RDATA.
// The returned DS owns its digest; input case does not affect the result.
[[nodiscard]] std::optional<Ds>
make_ds_sha256(const packet::dns::Name &owner,
               std::span<const std::uint8_t> dnskey_rdata) noexcept;

} // namespace router::dnssec
