// IPsec Security Association Database metadata and lookup ownership. One
// forwarding security shard owns each Sad and all mutable sequence, replay,
// lifetime and counter state inside it. Cryptographic key bytes remain in the
// separate protected key owner and are referenced only by an opaque handle.

#pragma once

#include "router/ipsec_policy.hpp"
#include "router/ipsec_replay.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router::ipsec {

enum class EncryptionAlgorithm : std::uint16_t {
  none,
  aes_gcm_16_128,
  aes_gcm_16_192,
  aes_gcm_16_256
};

enum class IntegrityAlgorithm : std::uint16_t {
  none,
  hmac_sha256_128,
  hmac_sha384_192,
  hmac_sha512_256,
  aes_xcbc_96
};

struct SaIdentifier {
  std::uint32_t spi{};
  SecurityProtocol protocol{SecurityProtocol::esp};
  // RFC 4303 permits SPI-only, SPI+destination and
  // SPI+destination+source lookup. A source match without a destination match
  // is invalid because it cannot occur in the required longest-identifier order.
  std::optional<Address> destination;
  std::optional<Address> source;
};

struct SaLifetime {
  std::uint64_t soft_bytes{};
  std::uint64_t hard_bytes{};
  std::uint64_t soft_packets{};
  std::uint64_t hard_packets{};
  std::chrono::seconds soft_time{};
  std::chrono::seconds hard_time{};
};

struct SaCounters {
  std::uint64_t packets{};
  std::uint64_t bytes{};
  std::uint64_t replay_drops{};
  std::uint64_t integrity_drops{};
  std::uint64_t selector_drops{};
};

struct SecurityAssociation {
  std::uint64_t id{};
  SaIdentifier inbound_identifier{};
  Mode mode{Mode::transport};
  EncryptionAlgorithm encryption{EncryptionAlgorithm::none};
  IntegrityAlgorithm integrity{IntegrityAlgorithm::none};
  // The key owner validates that this handle refers to material compatible with
  // the selected algorithm before installation. Zero never names key material.
  std::uint64_t crypto_material_handle{};
  std::uint32_t policy_id{};
  std::optional<Address> tunnel_source;
  std::optional<Address> tunnel_destination;
  SaLifetime lifetime{};
  std::chrono::steady_clock::time_point created_at{};
  ReplayWindow replay{};
  OutboundSequence outbound_sequence{};
  SaCounters counters{};
  bool outbound{};
};

enum class SaInstallResult : std::uint8_t {
  installed,
  replaced,
  invalid,
  identifier_conflict,
  capacity_exhausted
};

struct SaPairInstallResult {
  SaInstallResult inbound{SaInstallResult::invalid};
  SaInstallResult outbound{SaInstallResult::invalid};
  bool committed{};
};

struct SadAssociationCheckpoint {
  // created_at and mutable sequence repositories are normalized into the
  // explicit portable fields below. All other metadata is a canonical value.
  SecurityAssociation association{};
  std::int64_t created_age_nanoseconds{};
  std::uint64_t replay_highest{};
  std::uint64_t replay_bitmap{};
  std::uint64_t outbound_sequence{};
};

struct SadCheckpoint {
  std::size_t capacity{};
  std::vector<SadAssociationCheckpoint> associations;
};

enum class SaPairEraseResult : std::uint8_t {
  erased,
  invalid,
  missing,
  not_a_pair
};

class Sad final {
public:
  explicit Sad(std::size_t capacity);

  [[nodiscard]] SaInstallResult
  install(const SecurityAssociation &association) noexcept;
  // IKE creates CHILD SAs as an inbound/outbound pair. The forwarding owner
  // installs both or restores the previous SAD byte-for-byte, preventing a
  // one-directional half-SA after conflict or resource exhaustion.
  [[nodiscard]] SaPairInstallResult
  install_pair(const SecurityAssociation &inbound,
               const SecurityAssociation &outbound) noexcept;
  // A CHILD SA is unusable if only one direction survives. Deletion therefore
  // validates both identities before mutating the vector and erases the pair
  // in one forwarding-owner turn. A missing member leaves the SAD unchanged.
  [[nodiscard]] SaPairEraseResult
  erase_pair(std::uint64_t inbound_id, std::uint64_t outbound_id) noexcept;
  [[nodiscard]] bool erase(std::uint64_t id) noexcept;

  // Returned pointers are shard-local borrows and remain valid only until the
  // next install or erase. The one-owner rule forbids storing them in messages.
  [[nodiscard]] SecurityAssociation *
  find_inbound(SecurityProtocol protocol, std::uint32_t spi,
               const Address &destination,
               const Address &source) noexcept;
  [[nodiscard]] SecurityAssociation *find_outbound(std::uint64_t id) noexcept;
  // An ordered SPD protect entry names a policy, while IKE chooses the actual
  // outbound SA. During rekey there may briefly be two associations for that
  // policy. The newest creation time wins and the old SA remains available for
  // inbound overlap until the control owner completes make-before-break.
  [[nodiscard]] SecurityAssociation *
  find_outbound_for_policy(std::uint32_t policy_id,
                           SecurityProtocol protocol) noexcept;
  [[nodiscard]] const SecurityAssociation *find(std::uint64_t id) const noexcept;

  [[nodiscard]] std::optional<SadCheckpoint>
  checkpoint(std::chrono::steady_clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const SadCheckpoint &state,
                             std::chrono::steady_clock::time_point now) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }

private:
  std::size_t capacity_{};
  std::vector<SecurityAssociation> entries_;
};

} // namespace router::ipsec
