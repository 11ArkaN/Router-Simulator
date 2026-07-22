// Portable FIPS 180-4 SHA-256 and RFC 2104 HMAC implementation. The code uses
// fixed-size stack storage so packet and identity owners do not allocate or
// call an operating-system cryptographic service. This primitive is deliberately
// small and independently vector-tested before a protocol may consume it.

#include "router/sha256.hpp"

#include <algorithm>

namespace router::crypto {
namespace {

constexpr std::array<std::uint32_t, 64U> round_constants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::uint32_t rotate_right(std::uint32_t value,
                                     unsigned shift) noexcept {
  return (value >> shift) | (value << (32U - shift));
}

std::uint32_t read_big_endian(const std::uint8_t *input) noexcept {
  return (static_cast<std::uint32_t>(input[0]) << 24U) |
         (static_cast<std::uint32_t>(input[1]) << 16U) |
         (static_cast<std::uint32_t>(input[2]) << 8U) |
         static_cast<std::uint32_t>(input[3]);
}

void write_big_endian(std::uint8_t *output, std::uint32_t value) noexcept {
  output[0] = static_cast<std::uint8_t>(value >> 24U);
  output[1] = static_cast<std::uint8_t>(value >> 16U);
  output[2] = static_cast<std::uint8_t>(value >> 8U);
  output[3] = static_cast<std::uint8_t>(value);
}

} // namespace

Sha256::Sha256() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
             0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Sha256::compress(const std::uint8_t *block) noexcept {
  std::array<std::uint32_t, 64U> schedule{};
  for (std::size_t index = 0; index < 16U; ++index)
    schedule[index] = read_big_endian(block + index * 4U);
  for (std::size_t index = 16U; index < schedule.size(); ++index) {
    // FIPS 180-4 section 6.2.2 expands each block independently. Keeping the
    // schedule local prevents one context from exposing mutable work memory to
    // another thread even when callers hash concurrently on separate owners.
    const auto s0 = rotate_right(schedule[index - 15U], 7U) ^
                    rotate_right(schedule[index - 15U], 18U) ^
                    (schedule[index - 15U] >> 3U);
    const auto s1 = rotate_right(schedule[index - 2U], 17U) ^
                    rotate_right(schedule[index - 2U], 19U) ^
                    (schedule[index - 2U] >> 10U);
    schedule[index] = schedule[index - 16U] + s0 + schedule[index - 7U] + s1;
  }

  auto a = state_[0];
  auto b = state_[1];
  auto c = state_[2];
  auto d = state_[3];
  auto e = state_[4];
  auto f = state_[5];
  auto g = state_[6];
  auto h = state_[7];
  for (std::size_t index = 0; index < schedule.size(); ++index) {
    const auto upper_sigma_one = rotate_right(e, 6U) ^ rotate_right(e, 11U) ^
                                 rotate_right(e, 25U);
    const auto choose = (e & f) ^ (~e & g);
    const auto temporary_one = h + upper_sigma_one + choose +
                               round_constants[index] + schedule[index];
    const auto upper_sigma_zero = rotate_right(a, 2U) ^ rotate_right(a, 13U) ^
                                  rotate_right(a, 22U);
    const auto majority = (a & b) ^ (a & c) ^ (b & c);
    const auto temporary_two = upper_sigma_zero + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary_one;
    d = c;
    c = b;
    b = a;
    a = temporary_one + temporary_two;
  }
  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> input) noexcept {
  // The algorithm's length field is modulo 2^64 bits. Unsigned arithmetic
  // gives that specified behavior without a signed overflow branch.
  total_octets_ += static_cast<std::uint64_t>(input.size());
  while (!input.empty()) {
    const auto copied = std::min(block_.size() - block_octets_, input.size());
    std::copy_n(input.begin(), copied, block_.begin() + block_octets_);
    block_octets_ += copied;
    input = input.subspan(copied);
    if (block_octets_ == block_.size()) {
      compress(block_.data());
      block_octets_ = 0U;
    }
  }
}

Sha256Digest Sha256::finish() noexcept {
  const auto message_bits = total_octets_ * 8U;
  block_[block_octets_++] = 0x80U;
  // The final eight octets hold the message length. A block with fewer than
  // eight remaining octets must be compressed before the zero padding and
  // length are written into a fresh block.
  if (block_octets_ > 56U) {
    std::fill(block_.begin() + block_octets_, block_.end(), std::uint8_t{0});
    compress(block_.data());
    block_octets_ = 0U;
  }
  std::fill(block_.begin() + block_octets_, block_.begin() + 56U,
            std::uint8_t{0});
  for (std::size_t index = 0; index < 8U; ++index)
    block_[63U - index] =
        static_cast<std::uint8_t>(message_bits >> (index * 8U));
  compress(block_.data());

  Sha256Digest digest{};
  for (std::size_t index = 0; index < state_.size(); ++index)
    write_big_endian(digest.data() + index * 4U, state_[index]);
  return digest;
}

Sha256Digest sha256(std::span<const std::uint8_t> input) noexcept {
  Sha256 context;
  context.update(input);
  return context.finish();
}

Sha256Digest hmac_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::span<const std::uint8_t>> message) noexcept {
  constexpr std::size_t block_octets = 64U;
  std::array<std::uint8_t, block_octets> normalized_key{};
  if (key.size() > normalized_key.size()) {
    // RFC 2104 hashes keys longer than the compression block once, then pads
    // that digest with zeros. Shorter keys are copied directly and padded.
    const auto digest = sha256(key);
    std::copy(digest.begin(), digest.end(), normalized_key.begin());
  } else {
    std::copy(key.begin(), key.end(), normalized_key.begin());
  }

  std::array<std::uint8_t, block_octets> inner_pad{};
  std::array<std::uint8_t, block_octets> outer_pad{};
  for (std::size_t index = 0; index < normalized_key.size(); ++index) {
    inner_pad[index] = static_cast<std::uint8_t>(normalized_key[index] ^ 0x36U);
    outer_pad[index] = static_cast<std::uint8_t>(normalized_key[index] ^ 0x5cU);
  }
  Sha256 inner;
  inner.update(inner_pad);
  for (const auto segment : message)
    inner.update(segment);
  const auto inner_digest = inner.finish();
  Sha256 outer;
  outer.update(outer_pad);
  outer.update(inner_digest);
  return outer.finish();
}

} // namespace router::crypto
