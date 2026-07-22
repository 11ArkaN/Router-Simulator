// Control-shard IKE SA and CHILD SA lifecycle owner. It never mutates the
// forwarding SAD directly. Complete unidirectional SA values cross the shard
// boundary in one install request and become active here only after an atomic
// forwarding acknowledgement.

#pragma once

#include "router/ikev2_authentication.hpp"
#include "router/ipsec_sad.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ikev2 {

enum class Role : std::uint8_t { initiator, responder };
enum class SaState : std::uint8_t {
  created,
  initial_exchange,
  authenticating,
  established,
  deleting,
  closed,
  failed
};

struct SaSpis {
  std::uint64_t initiator{};
  std::uint64_t responder{};
};

struct DerivedKeysEvidence {
  // The protected key owner creates this nonzero handle only after successful
  // DH, SKEYSEED and directional key derivation. No key byte crosses this API.
  std::uint64_t key_set_handle{};
};

struct LivenessPolicy {
  std::chrono::seconds idle_interval{};
  std::uint8_t maximum_unanswered_requests{};
};

struct SaConfiguration {
  std::size_t maximum_child_sas{};
  LivenessPolicy liveness{};
};

enum class SaTransitionResult : std::uint8_t {
  applied,
  invalid_state,
  invalid_value,
  capacity_exhausted,
  request_pending,
  request_mismatch,
  forwarding_rejected
};

struct ChildSaInstallRequest {
  std::uint64_t request_id{};
  std::uint64_t ike_sa_id{};
  std::uint64_t child_sa_id{};
  // Nonzero only for CREATE_CHILD_SA rekey. The old pair remains active until
  // this new pair is acknowledged by the forwarding owner.
  std::uint64_t replaces_child_sa_id{};
  ipsec::SecurityAssociation inbound;
  ipsec::SecurityAssociation outbound;
};

enum class ChildSaState : std::uint8_t { active, retiring };

enum class RekeyCollisionLoser : std::uint8_t {
  local_exchange,
  peer_exchange,
  indeterminate
};

// RFC 7296 section 2.8.1 selects the redundant exchange containing the
// lexicographically lowest of all four nonces. An empty nonce or exact minimum
// tie is invalid exchange evidence and cannot safely select an SA for deletion.
[[nodiscard]] RekeyCollisionLoser resolve_rekey_collision(
    std::span<const std::uint8_t> local_initiator_nonce,
    std::span<const std::uint8_t> local_responder_nonce,
    std::span<const std::uint8_t> peer_initiator_nonce,
    std::span<const std::uint8_t> peer_responder_nonce) noexcept;

struct ChildSaBinding {
  std::uint64_t child_sa_id{};
  std::uint64_t inbound_sa_id{};
  std::uint64_t outbound_sa_id{};
  std::chrono::steady_clock::time_point installed_at{};
  ChildSaState state{ChildSaState::active};
};

struct ChildSaRemoveRequest {
  std::uint64_t request_id{};
  std::uint64_t ike_sa_id{};
  std::uint64_t child_sa_id{};
  std::uint64_t inbound_sa_id{};
  std::uint64_t outbound_sa_id{};
};

struct ChildSaCheckpoint {
  std::uint64_t child_sa_id{};
  std::uint64_t inbound_sa_id{};
  std::uint64_t outbound_sa_id{};
  std::int64_t installed_age_nanoseconds{};
  ChildSaState state{ChildSaState::active};
};

struct SaCheckpoint {
  std::uint64_t id{};
  Role role{Role::initiator};
  SaConfiguration configuration{};
  SaState state{SaState::created};
  SaSpis spis{};
  // This is a vault/provider reference. The provider checkpoint validates that
  // it can reconstruct the referenced secret before this owner is restored.
  std::uint64_t key_set_handle{};
  std::uint64_t next_request_id{};
  std::optional<ChildSaInstallRequest> pending_child_install;
  std::optional<ChildSaRemoveRequest> pending_child_remove;
  ChildSaState pending_remove_previous_state{ChildSaState::active};
  std::vector<ChildSaCheckpoint> child_sas;
  bool has_liveness_deadline{};
  std::int64_t liveness_remaining_nanoseconds{};
  std::uint8_t unanswered_liveness_requests{};
};

enum class LivenessAction : std::uint8_t {
  none,
  send_empty_informational,
  delete_ike_sa
};

class Sa final {
public:
  using Clock = std::chrono::steady_clock;

  Sa(std::uint64_t id, Role role, SaConfiguration configuration);

  [[nodiscard]] SaTransitionResult
  begin_initial_exchange(std::uint64_t initiator_spi,
                         Clock::time_point now) noexcept;
  [[nodiscard]] SaTransitionResult
  complete_initial_exchange(std::uint64_t responder_spi,
                            DerivedKeysEvidence keys,
                            Clock::time_point now) noexcept;
  [[nodiscard]] SaTransitionResult
  complete_authentication(AuthenticationStatus authentication,
                          Clock::time_point now) noexcept;

  [[nodiscard]] std::optional<ChildSaInstallRequest> begin_child_install(
      std::uint64_t child_sa_id,
      const ipsec::SecurityAssociation &inbound,
      const ipsec::SecurityAssociation &outbound) noexcept;
  // Rekey is make-before-break: successful installation exposes the new pair
  // and marks the replaced binding retiring, but never deletes it implicitly.
  [[nodiscard]] std::optional<ChildSaInstallRequest> begin_child_rekey(
      std::uint64_t replaced_child_sa_id, std::uint64_t new_child_sa_id,
      const ipsec::SecurityAssociation &inbound,
      const ipsec::SecurityAssociation &outbound) noexcept;
  [[nodiscard]] SaTransitionResult complete_child_install(
      std::uint64_t request_id,
      const ipsec::SaPairInstallResult &forwarding_result,
      Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<ChildSaRemoveRequest>
  begin_child_delete(std::uint64_t child_sa_id) noexcept;
  [[nodiscard]] SaTransitionResult complete_child_delete(
      std::uint64_t request_id,
      ipsec::SaPairEraseResult forwarding_result) noexcept;
  // IKE SA deletion first blocks new CHILD creation, then drains every owned
  // forwarding pair through the same acknowledged delete path. Key ownership
  // is released only after no binding or transaction remains.
  [[nodiscard]] SaTransitionResult begin_ike_delete() noexcept;
  [[nodiscard]] SaTransitionResult complete_ike_delete() noexcept;

  // Authenticated IKE or ESP activity proves peer reachability and restarts
  // the local idle deadline. It does not synthesize a response or packet.
  [[nodiscard]] SaTransitionResult
  note_authenticated_activity(Clock::time_point now) noexcept;
  [[nodiscard]] LivenessAction poll_liveness(Clock::time_point now) noexcept;

  // Checkpoint time values are relative to the supplied monotonic instant.
  // Restore validates the whole replacement before changing live owner state.
  [[nodiscard]] std::optional<SaCheckpoint>
  checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const SaCheckpoint &checkpoint,
                             Clock::time_point now) noexcept;

  [[nodiscard]] SaState state() const noexcept { return state_; }
  [[nodiscard]] std::uint64_t id() const noexcept { return id_; }
  [[nodiscard]] Role role() const noexcept { return role_; }
  [[nodiscard]] SaSpis spis() const noexcept { return spis_; }
  [[nodiscard]] std::uint64_t key_set_handle() const noexcept {
    return key_set_handle_;
  }
  [[nodiscard]] std::span<const ChildSaBinding> child_sas() const noexcept {
    return child_sas_;
  }

private:
  [[nodiscard]] bool set_liveness_deadline(Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<ChildSaInstallRequest> begin_child_install_impl(
      std::uint64_t child_sa_id, std::uint64_t replaces_child_sa_id,
      const ipsec::SecurityAssociation &inbound,
      const ipsec::SecurityAssociation &outbound) noexcept;
  [[nodiscard]] std::uint64_t allocate_request_id() noexcept;

  std::uint64_t id_{};
  Role role_{Role::initiator};
  SaConfiguration configuration_{};
  SaState state_{SaState::created};
  SaSpis spis_{};
  std::uint64_t key_set_handle_{};
  std::uint64_t next_request_id_{1U};
  std::optional<ChildSaInstallRequest> pending_child_install_;
  std::optional<ChildSaRemoveRequest> pending_child_remove_;
  ChildSaState pending_remove_previous_state_{ChildSaState::active};
  std::vector<ChildSaBinding> child_sas_;
  Clock::time_point liveness_deadline_{};
  std::uint8_t unanswered_liveness_requests_{};
};

} // namespace router::ikev2
