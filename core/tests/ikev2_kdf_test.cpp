// KDF tests use independent HMAC-SHA-256 bytes generated from the RFC 7296 PRF+
// construction and verify truncation across the T1 to T2 boundary.

#include "router/ikev2_kdf.hpp"

#include <array>
#include <stdexcept>

namespace {

std::uint8_t hex(char digit) {
  return static_cast<std::uint8_t>(digit <= '9' ? digit - '0'
                                                : digit - 'a' + 10);
}

template <std::size_t Octets>
std::array<std::uint8_t, Octets> decode(const char (&text)[Octets * 2U + 1U]) {
  std::array<std::uint8_t, Octets> result{};
  for (std::size_t index = 0U; index < Octets; ++index)
    result[index] = static_cast<std::uint8_t>(
        hex(text[index * 2U]) << 4U | hex(text[index * 2U + 1U]));
  return result;
}

} // namespace

void ikev2_kdf_tests() {
  using namespace router::ikev2;
  std::array<std::uint8_t, 20U> key{};
  key.fill(0x0bU);
  const std::array<std::uint8_t, 8U> seed{'H', 'i', ' ', 'T',
                                          'h', 'e', 'r', 'e'};
  const std::array seed_segments{std::span<const std::uint8_t>{seed}};
  std::array<std::uint8_t, 48U> expanded{};
  const auto expected = decode<48U>(
      "b9bdc08988b4c2b75aa93e596ac84205fa2ddde1bf7a2572067b00e14b237732"
      "830509981ad2f94a8c32a47daa2255b6");
  if (prf_plus_sha256(key, seed_segments, expanded) != KdfStatus::ok ||
      expanded != expected)
    throw std::runtime_error("IKEv2 PRF+ derivation mismatch");

  std::array<std::uint8_t, 16U> initiator_nonce{};
  std::array<std::uint8_t, 16U> responder_nonce{};
  initiator_nonce.fill(1U);
  responder_nonce.fill(2U);
  const std::array<std::uint8_t, 6U> secret{'s', 'h', 'a', 'r', 'e', 'd'};
  std::array<std::uint8_t, 32U> skeyseed{};
  const auto expected_skeyseed = decode<32U>(
      "0c90e9a47837025a7c45cb313f95a2734955f82faffa255e733143e7a3757ac0");
  if (derive_skeyseed_sha256(initiator_nonce, responder_nonce, secret,
                             skeyseed) != KdfStatus::ok ||
      skeyseed != expected_skeyseed)
    throw std::runtime_error("IKEv2 SKEYSEED derivation mismatch");

  const IkeSaKeyLengths lengths{.sk_d = 32U,
                                .sk_ai = 0U,
                                .sk_ar = 0U,
                                .sk_ei = 20U,
                                .sk_er = 20U,
                                .sk_pi = 32U,
                                .sk_pr = 32U};
  std::array<std::uint8_t, 136U> key_storage{};
  IkeSaKeyViews views{};
  if (derive_ike_sa_keys_sha256(skeyseed, initiator_nonce, responder_nonce,
                                0x0102030405060708ULL,
                                0x1112131415161718ULL, lengths, key_storage,
                                views) != KdfStatus::ok ||
      views.sk_d.size() != 32U || !views.sk_ai.empty() ||
      views.sk_ei.size() != 20U || views.sk_pr.size() != 32U ||
      views.sk_d.data() != key_storage.data() ||
      views.sk_ei.data() != key_storage.data() + 32U)
    throw std::runtime_error("IKEv2 directional key partition failed");

  std::array<std::uint8_t, 40U> child_keymat{};
  if (derive_child_sa_keymat_sha256(views.sk_d, {}, initiator_nonce,
                                    responder_nonce, child_keymat) !=
      KdfStatus::ok)
    throw std::runtime_error("IKEv2 CHILD SA KEYMAT derivation failed");

  std::array<std::uint8_t, 8161U> excessive{};
  if (prf_plus_sha256(key, seed_segments, excessive) !=
      KdfStatus::output_too_large)
    throw std::runtime_error("IKEv2 PRF+ counter exhaustion was accepted");
}
