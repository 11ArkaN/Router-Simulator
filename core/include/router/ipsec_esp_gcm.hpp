// OpenSSL-backed RFC 4106 ESP AES-GCM transform. One forwarding security owner
// owns an Engine and calls it serially; the reusable provider context is not
// thread-safe and never crosses a shard. Inputs and outputs are caller-owned
// packet-pool spans. No system socket, random host I/O or topology access exists.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace router::ipsec::esp_gcm {

struct KeyMaterial {
  // RFC 4106 permits 128-, 192- and 256-bit AES keys followed by a four-octet
  // salt in IKE KEYMAT. Only key_octets bytes are consumed from key.
  std::array<std::uint8_t, 32> key{};
  std::uint8_t key_octets{};
  std::array<std::uint8_t, 4> salt{};
};

enum class Status : std::uint8_t {
  ok,
  invalid_argument,
  output_too_small,
  provider_failure,
  authentication_failed,
  invalid_padding
};

struct ProtectResult {
  Status status{Status::invalid_argument};
  std::size_t packet_octets{};
};

struct UnprotectResult {
  Status status{Status::invalid_argument};
  std::size_t plaintext_octets{};
  std::uint8_t next_header{};
  std::uint32_t spi{};
};

class Engine final {
public:
  [[nodiscard]] static std::unique_ptr<Engine>
  create(const KeyMaterial &material) noexcept;
  ~Engine();

  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;

  // protect writes one complete ESP packet beginning with SPI and Sequence.
  // sequence is the already reserved SAD counter and therefore also provides a
  // unique eight-octet explicit IV for this key. A failed call consumes no
  // additional counter because allocation remains the SAD owner's decision.
  [[nodiscard]] ProtectResult
  protect(std::uint32_t spi, std::uint64_t sequence, bool esn,
          std::uint8_t next_header, std::span<const std::uint8_t> plaintext,
          std::span<std::uint8_t> output) noexcept;

  // unprotect authenticates SPI, sequence, IV, ciphertext and trailer before
  // returning plaintext length. On every failure, written output bytes are
  // cleansed and no upper-layer protocol is returned.
  [[nodiscard]] UnprotectResult
  unprotect(std::uint64_t reconstructed_sequence, bool esn,
            std::span<const std::uint8_t> packet,
            std::span<std::uint8_t> plaintext_output) noexcept;

private:
  Engine(void *context, const KeyMaterial &material) noexcept;
  [[nodiscard]] const void *cipher() const noexcept;

  void *context_{};
  KeyMaterial material_{};
};

} // namespace router::ipsec::esp_gcm
