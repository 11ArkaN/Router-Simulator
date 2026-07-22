// Generated from profiles/dnssec/iana-2026-01-13.yaml. Do not edit.
// Registry policy and compiled crypto support share this single wire-number map.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace router::dnssec::policy {

enum class Recommendation : std::uint8_t { must_not, not_recommended, may, recommended, must };
enum class CryptoBackend : std::uint8_t { none, rsa_sha256, ecdsa_p256_sha256, ed25519 };
enum class DigestBackend : std::uint8_t { none, sha1, sha256, sha384 };

struct Algorithm {
  std::uint8_t number;
  std::string_view mnemonic;
  Recommendation use_signing;
  Recommendation use_validation;
  Recommendation implement_signing;
  Recommendation implement_validation;
  CryptoBackend backend;
};

struct Digest {
  std::uint8_t number;
  std::string_view name;
  Recommendation use_delegation;
  Recommendation use_validation;
  Recommendation implement_delegation;
  Recommendation implement_validation;
  DigestBackend backend;
};

inline constexpr std::string_view registry_date = "2026-01-13";
inline constexpr std::string_view algorithm_registry_url = "https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml";
inline constexpr std::string_view digest_registry_url = "https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml";
inline constexpr std::array<Algorithm, 16> algorithms{{
    {1U, "RSAMD5", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, CryptoBackend::none},
    {3U, "DSA", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, CryptoBackend::none},
    {5U, "RSASHA1", Recommendation::not_recommended, Recommendation::recommended, Recommendation::not_recommended, Recommendation::must, CryptoBackend::none},
    {6U, "DSA-NSEC3-SHA1", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, CryptoBackend::none},
    {7U, "RSASHA1-NSEC3-SHA1", Recommendation::not_recommended, Recommendation::recommended, Recommendation::not_recommended, Recommendation::must, CryptoBackend::none},
    {8U, "RSASHA256", Recommendation::recommended, Recommendation::recommended, Recommendation::must, Recommendation::must, CryptoBackend::rsa_sha256},
    {10U, "RSASHA512", Recommendation::not_recommended, Recommendation::recommended, Recommendation::not_recommended, Recommendation::must, CryptoBackend::none},
    {12U, "ECC-GOST", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, CryptoBackend::none},
    {13U, "ECDSAP256SHA256", Recommendation::recommended, Recommendation::recommended, Recommendation::must, Recommendation::must, CryptoBackend::ecdsa_p256_sha256},
    {14U, "ECDSAP384SHA384", Recommendation::may, Recommendation::recommended, Recommendation::may, Recommendation::recommended, CryptoBackend::none},
    {15U, "ED25519", Recommendation::recommended, Recommendation::recommended, Recommendation::recommended, Recommendation::recommended, CryptoBackend::ed25519},
    {16U, "ED448", Recommendation::may, Recommendation::recommended, Recommendation::may, Recommendation::recommended, CryptoBackend::none},
    {17U, "SM2SM3", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, CryptoBackend::none},
    {23U, "ECC-GOST12", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, CryptoBackend::none},
    {253U, "PRIVATEDNS", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, CryptoBackend::none},
    {254U, "PRIVATEOID", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, CryptoBackend::none}
}};
inline constexpr std::array<Digest, 7> digests{{
    {0U, "Reserved", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, DigestBackend::none},
    {1U, "SHA-1", Recommendation::must_not, Recommendation::recommended, Recommendation::must_not, Recommendation::must, DigestBackend::sha1},
    {2U, "SHA-256", Recommendation::recommended, Recommendation::recommended, Recommendation::must, Recommendation::must, DigestBackend::sha256},
    {3U, "GOST-R-34.11-94", Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, Recommendation::must_not, DigestBackend::none},
    {4U, "SHA-384", Recommendation::may, Recommendation::recommended, Recommendation::may, Recommendation::recommended, DigestBackend::sha384},
    {5U, "GOST-R-34.11-2012", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, DigestBackend::none},
    {6U, "SM3", Recommendation::may, Recommendation::may, Recommendation::may, Recommendation::may, DigestBackend::none}
}};

[[nodiscard]] constexpr std::optional<Algorithm> algorithm(std::uint8_t number) noexcept {
  for (const auto &entry : algorithms) if (entry.number == number) return entry;
  return std::nullopt;
}

[[nodiscard]] constexpr std::optional<Digest> digest(std::uint8_t number) noexcept {
  for (const auto &entry : digests) if (entry.number == number) return entry;
  return std::nullopt;
}

} // namespace router::dnssec::policy
