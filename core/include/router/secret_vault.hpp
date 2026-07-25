// Authenticated project-secret storage. One control/service owner mutates a
// SecretVault. Configuration, telemetry and packet-path objects retain only
// stable handles, while plaintext exists only inside a short-lived
// OpenedSecret on the owning shard. The module depends on the cryptographic
// provider but has no runtime, CLI, DOM, storage or network dependency.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::vault {

using SecretHandle = std::uint64_t;

// Kind is authenticated metadata, not a display label. It prevents a valid
// ciphertext saved for one protocol purpose from being opened as another type
// of key after a malformed checkpoint or programming error changes a handle.
enum class SecretKind : std::uint8_t {
  ipsec_ppk_ascii = 1U,
  ipsec_ppk_hexadecimal = 2U,
  ike_pre_shared_key = 3U,
  pki_private_key = 4U,
  dnssec_private_key = 5U,
  host_transport_entropy = 6U,
  stable_ipv6_interface_identifier = 7U,
  dhcpv6_transaction_entropy = 8U,
  dhcpv6_allocation_entropy = 9U,
  ipsec_static_authentication_key = 10U,
  ospf_authentication_key = 11U
};

struct SealedRecord {
  SecretHandle handle{};
  SecretKind kind{};
  // The blob contains a versioned header, a fresh 96-bit GCM nonce, ciphertext
  // and a full 128-bit tag. Its header and the fields above are all AAD-bound.
  std::vector<std::uint8_t> sealed;
  bool operator==(const SealedRecord &) const = default;
};

struct Checkpoint {
  // next_handle is monotonic and never rewound by erasure. Consequently a
  // stale configuration handle cannot become valid for a later secret.
  SecretHandle next_handle{1U};
  std::vector<SealedRecord> records;
  bool operator==(const Checkpoint &) const = default;
};

enum class Result : std::uint8_t {
  applied,
  not_found,
  wrong_kind,
  invalid_argument,
  resource_exhausted,
  authentication_failed,
  cryptographic_failure
};

class OpenedSecret final {
public:
  OpenedSecret(OpenedSecret &&other) noexcept;
  OpenedSecret &operator=(OpenedSecret &&other) noexcept;
  OpenedSecret(const OpenedSecret &) = delete;
  OpenedSecret &operator=(const OpenedSecret &) = delete;
  ~OpenedSecret();

  // The returned view is valid only until this owner is destroyed or moved.
  // Callers must consume it synchronously and must not cache, log or serialize
  // the pointer or bytes. Destruction uses the provider erasure barrier.
  [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept {
    return plaintext_;
  }

private:
  explicit OpenedSecret(std::vector<std::uint8_t> plaintext) noexcept;
  void cleanse() noexcept;

  std::vector<std::uint8_t> plaintext_;
  friend class SecretVault;
};

class SecretVault final {
public:
  // wrapping_key must contain exactly 32 nonzero project-random bytes. Context
  // must identify the project and vault role. capacity is a profile resource
  // bound and therefore an overload decision, not a wire-protocol limit.
  [[nodiscard]] static std::optional<SecretVault>
  create(std::span<const std::uint8_t> wrapping_key,
         std::span<const std::uint8_t> context,
         std::size_t capacity) noexcept;
  [[nodiscard]] static std::optional<SecretVault>
  restore(const Checkpoint &checkpoint,
          std::span<const std::uint8_t> wrapping_key,
          std::span<const std::uint8_t> context,
          std::size_t capacity) noexcept;

  // Builds an authenticated detached replacement with this vault's key and
  // context. Runtime checkpoint import can therefore validate all records
  // before atomically swapping any live laboratory state.
  [[nodiscard]] std::optional<SecretVault>
  stage_restore(const Checkpoint &checkpoint) const noexcept;

  SecretVault(SecretVault &&other) noexcept;
  SecretVault &operator=(SecretVault &&other) noexcept;
  SecretVault(const SecretVault &) = delete;
  SecretVault &operator=(const SecretVault &) = delete;
  ~SecretVault();

  // seal is atomic: the record becomes visible only after AES-GCM has
  // completed. Equal kind and plaintext reuse the existing handle, avoiding
  // unreachable encrypted records when an operator repeats a command.
  [[nodiscard]] std::pair<Result, SecretHandle>
  seal(SecretKind kind, std::span<const std::uint8_t> plaintext) noexcept;

  // open authenticates the complete record before returning any plaintext.
  // A wrong kind is distinguished from corruption without attempting to use
  // the bytes under a different protocol contract.
  [[nodiscard]] std::pair<Result, std::optional<OpenedSecret>>
  open(SecretHandle handle, SecretKind expected_kind) const noexcept;

  // Erasure and pruning affect encrypted records only. Callers must first
  // collect handles from running configuration, every candidate and active
  // protocol state so a still-referenced credential is never removed.
  [[nodiscard]] Result erase(SecretHandle handle) noexcept;
  void prune(std::span<const SecretHandle> live_handles) noexcept;

  // rewrap authenticates every old record and stages every new ciphertext
  // before changing the active key. Failure leaves the original vault intact.
  [[nodiscard]] Result
  rewrap(std::span<const std::uint8_t> wrapping_key,
         std::span<const std::uint8_t> context) noexcept;

  [[nodiscard]] bool contains(SecretHandle handle,
                              SecretKind kind) const noexcept;
  [[nodiscard]] const Checkpoint &checkpoint() const noexcept { return state_; }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

private:
  SecretVault(std::array<std::uint8_t, 32U> wrapping_key,
              std::vector<std::uint8_t> context, std::size_t capacity,
              Checkpoint state) noexcept;
  void cleanse_key() noexcept;

  std::array<std::uint8_t, 32U> wrapping_key_{};
  std::vector<std::uint8_t> context_;
  std::size_t capacity_{};
  Checkpoint state_{};
};

} // namespace router::vault
