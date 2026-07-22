// IKEv2 HMAC-SHA-256 PRF and PRF+ key expansion. The IKE SA owner supplies all
// key material and destination storage. This primitive owns no persistent key,
// allocates no memory and is safe to invoke only with non-overlapping output.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

enum class KdfStatus : std::uint8_t {
  ok,
  invalid_argument,
  output_too_large
};

// Negotiated PRF_HMAC_SHA2_256 over a segmented message. output must contain
// exactly one 32-octet digest. Segments preserve wire order without flattening.
[[nodiscard]] KdfStatus prf_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> message,
    std::span<std::uint8_t> output) noexcept;

// RFC 7296 section 2.13 PRF+. HMAC-SHA-256 emits 32 octets per iteration and
// the one-octet iteration counter limits one expansion to 255 digest blocks.
[[nodiscard]] KdfStatus
prf_plus_sha256(std::span<const std::uint8_t> key,
                std::span<const std::span<const std::uint8_t>> seed,
                std::span<std::uint8_t> output) noexcept;

// RFC 7296 section 2.14 SKEYSEED for a freshly negotiated IKE SA.
[[nodiscard]] KdfStatus derive_skeyseed_sha256(
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::span<const std::uint8_t> shared_secret,
    std::span<std::uint8_t> output) noexcept;

struct IkeSaKeyLengths {
  std::size_t sk_d{};
  std::size_t sk_ai{};
  std::size_t sk_ar{};
  std::size_t sk_ei{};
  std::size_t sk_er{};
  std::size_t sk_pi{};
  std::size_t sk_pr{};
};

struct IkeSaKeyViews {
  std::span<std::uint8_t> sk_d;
  std::span<std::uint8_t> sk_ai;
  std::span<std::uint8_t> sk_ar;
  std::span<std::uint8_t> sk_ei;
  std::span<std::uint8_t> sk_er;
  std::span<std::uint8_t> sk_pi;
  std::span<std::uint8_t> sk_pr;
};

// RFC 7296 section 2.14 expands a negotiated SKEYSEED into directional IKE SA
// keys. Lengths come from the selected transform catalog, including zero-length
// SK_a keys for AEAD. storage is partitioned into the returned non-owning views.
[[nodiscard]] KdfStatus derive_ike_sa_keys_sha256(
    std::span<const std::uint8_t> skeyseed,
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::uint64_t initiator_spi, std::uint64_t responder_spi,
    const IkeSaKeyLengths &lengths, std::span<std::uint8_t> storage,
    IkeSaKeyViews &views) noexcept;

// RFC 7296 section 2.17 CHILD SA KEYMAT. new_shared_secret is empty unless the
// CREATE_CHILD_SA exchange negotiated PFS.
[[nodiscard]] KdfStatus derive_child_sa_keymat_sha256(
    std::span<const std::uint8_t> sk_d,
    std::span<const std::uint8_t> new_shared_secret,
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::span<std::uint8_t> output) noexcept;

} // namespace router::ikev2
