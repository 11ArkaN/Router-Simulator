// RFC 7296 sections 2.13 and 2.14 key derivation over the portable repository
// HMAC-SHA-256 primitive. Segment-based hashing avoids temporary concatenation
// of nonces, SPIs and previous PRF blocks on the control plane.

#include "router/ikev2_kdf.hpp"

#include "router/sha256.hpp"

#include <algorithm>
#include <array>

namespace router::ikev2 {
namespace {

class StreamingHmac final {
public:
  explicit StreamingHmac(std::span<const std::uint8_t> key) noexcept {
    constexpr std::size_t block_octets{64U};
    std::array<std::uint8_t, block_octets> normalized_key{};
    if (key.size() > block_octets) {
      const auto digest = router::crypto::sha256(key);
      std::copy(digest.begin(), digest.end(), normalized_key.begin());
    } else {
      std::copy(key.begin(), key.end(), normalized_key.begin());
    }

    for (std::size_t index = 0U; index < block_octets; ++index) {
      inner_pad_[index] =
          static_cast<std::uint8_t>(normalized_key[index] ^ 0x36U);
      outer_pad_[index] =
          static_cast<std::uint8_t>(normalized_key[index] ^ 0x5cU);
    }
    inner_.update(inner_pad_);
    std::fill(normalized_key.begin(), normalized_key.end(), std::uint8_t{0});
  }

  void update(std::span<const std::uint8_t> bytes) noexcept {
    inner_.update(bytes);
  }

  [[nodiscard]] router::crypto::Sha256Digest finish() noexcept {
    auto inner_digest = inner_.finish();
    router::crypto::Sha256 outer;
    outer.update(outer_pad_);
    outer.update(inner_digest);
    std::fill(inner_digest.begin(), inner_digest.end(), std::uint8_t{0});
    auto result = outer.finish();
    std::fill(inner_pad_.begin(), inner_pad_.end(), std::uint8_t{0});
    std::fill(outer_pad_.begin(), outer_pad_.end(), std::uint8_t{0});
    return result;
  }

private:
  router::crypto::Sha256 inner_{};
  std::array<std::uint8_t, 64U> inner_pad_{};
  std::array<std::uint8_t, 64U> outer_pad_{};
};

} // namespace

KdfStatus prf_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> message,
    std::span<std::uint8_t> output) noexcept {
  if (key.empty() || output.size() != router::crypto::sha256_digest_octets)
    return KdfStatus::invalid_argument;
  StreamingHmac hmac{key};
  for (const auto segment : message)
    hmac.update(segment);
  auto digest = hmac.finish();
  std::copy(digest.begin(), digest.end(), output.begin());
  std::fill(digest.begin(), digest.end(), std::uint8_t{0});
  return KdfStatus::ok;
}

KdfStatus prf_plus_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> seed,
    std::span<std::uint8_t> output) noexcept {
  constexpr auto digest_octets = router::crypto::sha256_digest_octets;
  constexpr auto maximum_octets = digest_octets * 255U;
  if (key.empty())
    return KdfStatus::invalid_argument;
  if (output.size() > maximum_octets)
    return KdfStatus::output_too_large;

  router::crypto::Sha256Digest previous{};
  std::size_t produced{};
  std::uint8_t iteration{1U};
  while (produced < output.size()) {
    // T1 omits T0. Later rounds prefix the complete previous digest exactly as
    // required by PRF+(K, S) = T1 | T2 | ... .
    const std::span<const std::uint8_t> counter{&iteration, 1U};
    StreamingHmac hmac{key};
    if (iteration != 1U)
      hmac.update(previous);
    for (const auto segment : seed)
      hmac.update(segment);
    hmac.update(counter);
    auto block = hmac.finish();
    const auto copied = std::min(digest_octets, output.size() - produced);
    std::copy_n(block.begin(), copied, output.begin() + produced);
    previous = block;
    std::fill(block.begin(), block.end(), std::uint8_t{0});
    produced += copied;
    ++iteration;
  }
  // The portable digest arrays are values rather than provider objects. Clear
  // the chaining value before returning so it is not retained on this stack.
  std::fill(previous.begin(), previous.end(), std::uint8_t{0});
  return KdfStatus::ok;
}

KdfStatus derive_skeyseed_sha256(
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::span<const std::uint8_t> shared_secret,
    std::span<std::uint8_t> output) noexcept {
  if (initiator_nonce.size() < 16U || initiator_nonce.size() > 256U ||
      responder_nonce.size() < 16U || responder_nonce.size() > 256U ||
      shared_secret.empty() ||
      output.size() != router::crypto::sha256_digest_octets)
    return KdfStatus::invalid_argument;
  // HMAC's key is Ni | Nr, so build at most 512 bytes in fixed control-plane
  // storage. This is bounded by the protocol nonce limit, not topology size.
  std::array<std::uint8_t, 512U> combined_nonce{};
  std::copy(initiator_nonce.begin(), initiator_nonce.end(),
            combined_nonce.begin());
  std::copy(responder_nonce.begin(), responder_nonce.end(),
            combined_nonce.begin() + initiator_nonce.size());
  const std::array secret_segments{shared_secret};
  auto digest = router::crypto::hmac_sha256(
      std::span{combined_nonce}.first(initiator_nonce.size() +
                                      responder_nonce.size()),
      secret_segments);
  std::copy(digest.begin(), digest.end(), output.begin());
  std::fill(digest.begin(), digest.end(), std::uint8_t{0});
  std::fill(combined_nonce.begin(), combined_nonce.end(), std::uint8_t{0});
  return KdfStatus::ok;
}

KdfStatus derive_ike_sa_keys_sha256(
    std::span<const std::uint8_t> skeyseed,
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::uint64_t initiator_spi, std::uint64_t responder_spi,
    const IkeSaKeyLengths &lengths, std::span<std::uint8_t> storage,
    IkeSaKeyViews &views) noexcept {
  if (skeyseed.empty() || initiator_nonce.empty() || responder_nonce.empty())
    return KdfStatus::invalid_argument;
  const std::array requested{lengths.sk_d,  lengths.sk_ai, lengths.sk_ar,
                             lengths.sk_ei, lengths.sk_er, lengths.sk_pi,
                             lengths.sk_pr};
  std::size_t required{};
  for (const auto length : requested) {
    if (length > storage.size() - required)
      return KdfStatus::invalid_argument;
    required += length;
  }
  std::array<std::uint8_t, 16U> encoded_spis{};
  for (std::size_t index = 0U; index < 8U; ++index) {
    encoded_spis[index] = static_cast<std::uint8_t>(
        initiator_spi >> ((7U - index) * 8U));
    encoded_spis[8U + index] = static_cast<std::uint8_t>(
        responder_spi >> ((7U - index) * 8U));
  }
  const std::array seed{initiator_nonce, responder_nonce,
                        std::span<const std::uint8_t>{encoded_spis}};
  if (prf_plus_sha256(skeyseed, seed, storage.first(required)) != KdfStatus::ok)
    return KdfStatus::output_too_large;
  std::size_t offset{};
  const auto take = [&storage, &offset](std::size_t length) {
    auto result = storage.subspan(offset, length);
    offset += length;
    return result;
  };
  views = {.sk_d = take(lengths.sk_d),
           .sk_ai = take(lengths.sk_ai),
           .sk_ar = take(lengths.sk_ar),
           .sk_ei = take(lengths.sk_ei),
           .sk_er = take(lengths.sk_er),
           .sk_pi = take(lengths.sk_pi),
           .sk_pr = take(lengths.sk_pr)};
  return KdfStatus::ok;
}

KdfStatus derive_child_sa_keymat_sha256(
    std::span<const std::uint8_t> sk_d,
    std::span<const std::uint8_t> new_shared_secret,
    std::span<const std::uint8_t> initiator_nonce,
    std::span<const std::uint8_t> responder_nonce,
    std::span<std::uint8_t> output) noexcept {
  if (sk_d.empty() || initiator_nonce.empty() || responder_nonce.empty())
    return KdfStatus::invalid_argument;
  const std::array seed{new_shared_secret, initiator_nonce, responder_nonce};
  return prf_plus_sha256(sk_d, seed, output);
}

} // namespace router::ikev2
