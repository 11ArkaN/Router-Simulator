// IKE SA transition enforcement. Cryptographic success and forwarding commit
// are distinct evidence. A failed AUTH closes the state before any CHILD SA can
// be requested, and a failed forwarding transaction never creates a binding.

#include "router/ikev2_sa.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>

namespace router::ikev2 {
namespace {

bool nonce_less(std::span<const std::uint8_t> left,
                std::span<const std::uint8_t> right) noexcept {
  return std::lexicographical_compare(left.begin(), left.end(), right.begin(),
                                      right.end());
}

bool same_configuration(const SaConfiguration &left,
                        const SaConfiguration &right) noexcept {
  return left.maximum_child_sas == right.maximum_child_sas &&
         left.liveness.idle_interval == right.liveness.idle_interval &&
         left.liveness.maximum_unanswered_requests ==
             right.liveness.maximum_unanswered_requests;
}

std::optional<Sa::Clock::duration>
checked_duration(std::int64_t nanoseconds) noexcept {
  if (nanoseconds < 0)
    return std::nullopt;
  const auto source = std::chrono::nanoseconds{nanoseconds};
  const auto converted = std::chrono::duration_cast<Sa::Clock::duration>(source);
  if (std::chrono::duration_cast<std::chrono::nanoseconds>(converted) != source)
    return std::nullopt;
  return converted;
}

std::optional<Sa::Clock::time_point>
checked_add(Sa::Clock::time_point now, std::int64_t nanoseconds) noexcept {
  const auto duration = checked_duration(nanoseconds);
  if (!duration || now.time_since_epoch() > Sa::Clock::duration::max() - *duration)
    return std::nullopt;
  return now + *duration;
}

} // namespace

RekeyCollisionLoser resolve_rekey_collision(
    std::span<const std::uint8_t> local_initiator_nonce,
    std::span<const std::uint8_t> local_responder_nonce,
    std::span<const std::uint8_t> peer_initiator_nonce,
    std::span<const std::uint8_t> peer_responder_nonce) noexcept {
  const std::array nonces{local_initiator_nonce, local_responder_nonce,
                          peer_initiator_nonce, peer_responder_nonce};
  if (std::any_of(nonces.begin(), nonces.end(),
                  [](const auto nonce) { return nonce.empty(); }))
    return RekeyCollisionLoser::indeterminate;
  std::size_t lowest{};
  for (std::size_t index = 1U; index < nonces.size(); ++index)
    if (nonce_less(nonces[index], nonces[lowest]))
      lowest = index;
  // An exact duplicate minimum gives no RFC-defined unique loser. Fail closed
  // instead of letting each endpoint make a potentially different choice.
  for (std::size_t index = 0U; index < nonces.size(); ++index)
    if (index != lowest && nonces[index].size() == nonces[lowest].size() &&
        std::equal(nonces[index].begin(), nonces[index].end(),
                   nonces[lowest].begin()))
      return RekeyCollisionLoser::indeterminate;
  return lowest < 2U ? RekeyCollisionLoser::local_exchange
                     : RekeyCollisionLoser::peer_exchange;
}

Sa::Sa(std::uint64_t id, Role role, SaConfiguration configuration)
    : id_(id), role_(role), configuration_(configuration) {
  try {
    // One extra binding is intentional rekey headroom. RFC 7296 requires the
    // replacement CHILD SA to exist before the old pair is deleted. Keeping
    // this allocation out of the commit callback also preserves its noexcept
    // cross-shard acknowledgement contract.
    if (configuration.maximum_child_sas ==
        std::numeric_limits<std::size_t>::max())
      throw std::bad_alloc{};
    child_sas_.reserve(configuration.maximum_child_sas + 1U);
  } catch (...) {
    configuration_.maximum_child_sas = 0U;
  }
  if (id_ == 0U || configuration_.liveness.idle_interval <=
                       std::chrono::seconds::zero() ||
      configuration_.liveness.maximum_unanswered_requests == 0U)
    state_ = SaState::failed;
}

std::uint64_t Sa::allocate_request_id() noexcept {
  if (next_request_id_ == 0U)
    return 0U;
  const auto result = next_request_id_;
  next_request_id_ = result == std::numeric_limits<std::uint64_t>::max()
                         ? 0U
                         : result + 1U;
  return result;
}

bool Sa::set_liveness_deadline(Clock::time_point now) noexcept {
  const auto maximum_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(Clock::duration::max());
  if (configuration_.liveness.idle_interval > maximum_seconds)
    return false;
  const auto delay = std::chrono::duration_cast<Clock::duration>(
      configuration_.liveness.idle_interval);
  if (delay <= Clock::duration::zero() ||
      now.time_since_epoch() > Clock::duration::max() - delay)
    return false;
  liveness_deadline_ = now + delay;
  return true;
}

SaTransitionResult
Sa::begin_initial_exchange(std::uint64_t initiator_spi,
                           Clock::time_point now) noexcept {
  if (state_ != SaState::created)
    return SaTransitionResult::invalid_state;
  if (initiator_spi == 0U || !set_liveness_deadline(now))
    return SaTransitionResult::invalid_value;
  spis_.initiator = initiator_spi;
  spis_.responder = 0U;
  state_ = SaState::initial_exchange;
  return SaTransitionResult::applied;
}

SaTransitionResult Sa::complete_initial_exchange(
    std::uint64_t responder_spi, DerivedKeysEvidence keys,
    Clock::time_point now) noexcept {
  if (state_ != SaState::initial_exchange)
    return SaTransitionResult::invalid_state;
  if (responder_spi == 0U || keys.key_set_handle == 0U ||
      !set_liveness_deadline(now))
    return SaTransitionResult::invalid_value;
  spis_.responder = responder_spi;
  key_set_handle_ = keys.key_set_handle;
  state_ = SaState::authenticating;
  return SaTransitionResult::applied;
}

SaTransitionResult Sa::complete_authentication(
    AuthenticationStatus authentication, Clock::time_point now) noexcept {
  if (state_ != SaState::authenticating)
    return SaTransitionResult::invalid_state;
  if (authentication != AuthenticationStatus::ok) {
    state_ = SaState::failed;
    key_set_handle_ = 0U;
    return SaTransitionResult::forwarding_rejected;
  }
  if (!set_liveness_deadline(now)) {
    state_ = SaState::failed;
    key_set_handle_ = 0U;
    return SaTransitionResult::invalid_value;
  }
  unanswered_liveness_requests_ = 0U;
  state_ = SaState::established;
  return SaTransitionResult::applied;
}

std::optional<ChildSaInstallRequest> Sa::begin_child_install(
    std::uint64_t child_sa_id,
    const ipsec::SecurityAssociation &inbound,
    const ipsec::SecurityAssociation &outbound) noexcept {
  return begin_child_install_impl(child_sa_id, 0U, inbound, outbound);
}

std::optional<ChildSaInstallRequest> Sa::begin_child_rekey(
    std::uint64_t replaced_child_sa_id, std::uint64_t new_child_sa_id,
    const ipsec::SecurityAssociation &inbound,
    const ipsec::SecurityAssociation &outbound) noexcept {
  if (replaced_child_sa_id == 0U ||
      replaced_child_sa_id == new_child_sa_id)
    return std::nullopt;
  const auto replaced =
      std::find_if(child_sas_.begin(), child_sas_.end(),
                   [replaced_child_sa_id](const ChildSaBinding &binding) {
                     return binding.child_sa_id == replaced_child_sa_id &&
                            binding.state == ChildSaState::active;
                   });
  if (replaced == child_sas_.end())
    return std::nullopt;
  return begin_child_install_impl(new_child_sa_id, replaced_child_sa_id,
                                  inbound, outbound);
}

std::optional<ChildSaInstallRequest> Sa::begin_child_install_impl(
    std::uint64_t child_sa_id, std::uint64_t replaces_child_sa_id,
    const ipsec::SecurityAssociation &inbound,
    const ipsec::SecurityAssociation &outbound) noexcept {
  const bool ordinary_install = replaces_child_sa_id == 0U;
  if (state_ != SaState::established || pending_child_install_.has_value() ||
      pending_child_remove_.has_value() || child_sa_id == 0U ||
      (ordinary_install &&
       child_sas_.size() >= configuration_.maximum_child_sas) ||
      (!ordinary_install &&
       child_sas_.size() > configuration_.maximum_child_sas) ||
      std::any_of(child_sas_.begin(), child_sas_.end(),
                  [child_sa_id](const ChildSaBinding &binding) {
                    return binding.child_sa_id == child_sa_id;
                  }))
    return std::nullopt;
  if (inbound.outbound || !outbound.outbound || inbound.id == 0U ||
      outbound.id == 0U || inbound.id == outbound.id ||
      inbound.policy_id != outbound.policy_id)
    return std::nullopt;
  const auto request_id = allocate_request_id();
  if (request_id == 0U)
    return std::nullopt;
  pending_child_install_ = ChildSaInstallRequest{
      .request_id = request_id,
      .ike_sa_id = id_,
      .child_sa_id = child_sa_id,
      .replaces_child_sa_id = replaces_child_sa_id,
      .inbound = inbound,
      .outbound = outbound};
  return pending_child_install_;
}

SaTransitionResult Sa::complete_child_install(
    std::uint64_t request_id,
    const ipsec::SaPairInstallResult &forwarding_result,
    Clock::time_point now) noexcept {
  if (state_ != SaState::established)
    return SaTransitionResult::invalid_state;
  if (!pending_child_install_.has_value())
    return SaTransitionResult::request_pending;
  if (pending_child_install_->request_id != request_id)
    return SaTransitionResult::request_mismatch;
  if (!forwarding_result.committed) {
    pending_child_install_.reset();
    return SaTransitionResult::forwarding_rejected;
  }
  child_sas_.push_back(
      {.child_sa_id = pending_child_install_->child_sa_id,
       .inbound_sa_id = pending_child_install_->inbound.id,
       .outbound_sa_id = pending_child_install_->outbound.id,
       .installed_at = now,
       .state = ChildSaState::active});
  if (pending_child_install_->replaces_child_sa_id != 0U) {
    // push_back can invalidate iterators. Re-find the old binding only after
    // the replacement is durable, then mark it for an explicit DELETE flow.
    const auto replaced = std::find_if(
        child_sas_.begin(), child_sas_.end(), [&](const auto &binding) {
          return binding.child_sa_id ==
                 pending_child_install_->replaces_child_sa_id;
        });
    if (replaced != child_sas_.end())
      replaced->state = ChildSaState::retiring;
  }
  pending_child_install_.reset();
  unanswered_liveness_requests_ = 0U;
  if (!set_liveness_deadline(now))
    state_ = SaState::failed, key_set_handle_ = 0U;
  return SaTransitionResult::applied;
}

std::optional<ChildSaRemoveRequest>
Sa::begin_child_delete(std::uint64_t child_sa_id) noexcept {
  if ((state_ != SaState::established && state_ != SaState::deleting) ||
      pending_child_install_.has_value() ||
      pending_child_remove_.has_value() || child_sa_id == 0U)
    return std::nullopt;
  const auto binding =
      std::find_if(child_sas_.begin(), child_sas_.end(),
                   [child_sa_id](const ChildSaBinding &candidate) {
                     return candidate.child_sa_id == child_sa_id;
                   });
  if (binding == child_sas_.end())
    return std::nullopt;
  const auto request_id = allocate_request_id();
  if (request_id == 0U)
    return std::nullopt;
  pending_remove_previous_state_ = binding->state;
  binding->state = ChildSaState::retiring;
  pending_child_remove_ = ChildSaRemoveRequest{
      .request_id = request_id,
      .ike_sa_id = id_,
      .child_sa_id = binding->child_sa_id,
      .inbound_sa_id = binding->inbound_sa_id,
      .outbound_sa_id = binding->outbound_sa_id};
  return pending_child_remove_;
}

SaTransitionResult Sa::complete_child_delete(
    std::uint64_t request_id,
    ipsec::SaPairEraseResult forwarding_result) noexcept {
  if (state_ != SaState::established && state_ != SaState::deleting)
    return SaTransitionResult::invalid_state;
  if (!pending_child_remove_)
    return SaTransitionResult::request_pending;
  if (pending_child_remove_->request_id != request_id)
    return SaTransitionResult::request_mismatch;
  const auto child_sa_id = pending_child_remove_->child_sa_id;
  const auto binding =
      std::find_if(child_sas_.begin(), child_sas_.end(),
                   [child_sa_id](const ChildSaBinding &candidate) {
                     return candidate.child_sa_id == child_sa_id;
                   });
  if (forwarding_result != ipsec::SaPairEraseResult::erased) {
    // The pair may still carry traffic. Restore its prior operational label and
    // retain the binding so control state never claims that forwarding state
    // vanished after a rejected or partial delete.
    if (binding != child_sas_.end())
      binding->state = pending_remove_previous_state_;
    pending_child_remove_.reset();
    return SaTransitionResult::forwarding_rejected;
  }
  if (binding != child_sas_.end())
    child_sas_.erase(binding);
  pending_child_remove_.reset();
  return SaTransitionResult::applied;
}

SaTransitionResult Sa::begin_ike_delete() noexcept {
  if (state_ != SaState::established)
    return SaTransitionResult::invalid_state;
  if (pending_child_install_ || pending_child_remove_)
    return SaTransitionResult::request_pending;
  state_ = SaState::deleting;
  return SaTransitionResult::applied;
}

SaTransitionResult Sa::complete_ike_delete() noexcept {
  if (state_ != SaState::deleting)
    return SaTransitionResult::invalid_state;
  if (!child_sas_.empty() || pending_child_install_ || pending_child_remove_)
    return SaTransitionResult::request_pending;
  key_set_handle_ = 0U;
  liveness_deadline_ = {};
  unanswered_liveness_requests_ = 0U;
  state_ = SaState::closed;
  return SaTransitionResult::applied;
}

SaTransitionResult
Sa::note_authenticated_activity(Clock::time_point now) noexcept {
  if (state_ != SaState::established)
    return SaTransitionResult::invalid_state;
  if (!set_liveness_deadline(now))
    return SaTransitionResult::invalid_value;
  unanswered_liveness_requests_ = 0U;
  return SaTransitionResult::applied;
}

LivenessAction Sa::poll_liveness(Clock::time_point now) noexcept {
  if (state_ != SaState::established || now < liveness_deadline_)
    return LivenessAction::none;
  if (unanswered_liveness_requests_ >=
      configuration_.liveness.maximum_unanswered_requests) {
    state_ = SaState::deleting;
    return LivenessAction::delete_ike_sa;
  }
  if (!set_liveness_deadline(now)) {
    state_ = SaState::failed;
    key_set_handle_ = 0U;
    return LivenessAction::delete_ike_sa;
  }
  ++unanswered_liveness_requests_;
  return LivenessAction::send_empty_informational;
}

std::optional<SaCheckpoint>
Sa::checkpoint(Clock::time_point now) const noexcept {
  SaCheckpoint result{
      .id = id_,
      .role = role_,
      .configuration = configuration_,
      .state = state_,
      .spis = spis_,
      .key_set_handle = key_set_handle_,
      .next_request_id = next_request_id_,
      .pending_child_install = pending_child_install_,
      .pending_child_remove = pending_child_remove_,
      .pending_remove_previous_state = pending_remove_previous_state_,
      .child_sas = {},
      .has_liveness_deadline = state_ == SaState::initial_exchange ||
                               state_ == SaState::authenticating ||
                               state_ == SaState::established ||
                               state_ == SaState::deleting,
      .unanswered_liveness_requests = unanswered_liveness_requests_};
  try {
    result.child_sas.reserve(child_sas_.size());
    for (const auto &binding : child_sas_) {
      if (binding.installed_at > now)
        return std::nullopt;
      const auto age = std::chrono::duration_cast<std::chrono::nanoseconds>(
          now - binding.installed_at);
      if (std::chrono::duration_cast<Clock::duration>(age) !=
          now - binding.installed_at)
        return std::nullopt;
      result.child_sas.push_back(
          {.child_sa_id = binding.child_sa_id,
           .inbound_sa_id = binding.inbound_sa_id,
           .outbound_sa_id = binding.outbound_sa_id,
           .installed_age_nanoseconds = age.count(),
           .state = binding.state});
    }
  } catch (...) {
    return std::nullopt;
  }
  if (result.has_liveness_deadline) {
    const auto remaining = liveness_deadline_ > now
                               ? liveness_deadline_ - now
                               : Clock::duration::zero();
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(remaining);
    if (std::chrono::duration_cast<Clock::duration>(nanoseconds) != remaining)
      return std::nullopt;
    result.liveness_remaining_nanoseconds = nanoseconds.count();
  }
  return result;
}

bool Sa::restore(const SaCheckpoint &checkpoint,
                 Clock::time_point now) noexcept {
  if (checkpoint.id != id_ || checkpoint.role != role_ ||
      !same_configuration(checkpoint.configuration, configuration_) ||
      checkpoint.state > SaState::failed ||
      checkpoint.pending_remove_previous_state > ChildSaState::retiring ||
      checkpoint.unanswered_liveness_requests >
          configuration_.liveness.maximum_unanswered_requests)
    return false;
  const bool needs_keys = checkpoint.state == SaState::authenticating ||
                          checkpoint.state == SaState::established ||
                          checkpoint.state == SaState::deleting;
  const bool needs_both_spis = needs_keys || checkpoint.state == SaState::closed;
  if ((checkpoint.state == SaState::created &&
       (checkpoint.spis.initiator != 0U || checkpoint.spis.responder != 0U)) ||
      (checkpoint.state == SaState::initial_exchange &&
       (checkpoint.spis.initiator == 0U || checkpoint.spis.responder != 0U)) ||
      (needs_both_spis &&
       (checkpoint.spis.initiator == 0U || checkpoint.spis.responder == 0U)) ||
      (needs_keys != (checkpoint.key_set_handle != 0U)) ||
      ((checkpoint.state == SaState::created ||
        checkpoint.state == SaState::closed ||
        checkpoint.state == SaState::failed) &&
       checkpoint.has_liveness_deadline) ||
      ((checkpoint.state == SaState::initial_exchange || needs_keys) &&
       checkpoint.state != SaState::closed &&
       !checkpoint.has_liveness_deadline) ||
      checkpoint.liveness_remaining_nanoseconds < 0 ||
      (checkpoint.pending_child_install && checkpoint.pending_child_remove) ||
      ((!checkpoint.child_sas.empty() || checkpoint.pending_child_install ||
        checkpoint.pending_child_remove) &&
       checkpoint.state != SaState::established &&
       checkpoint.state != SaState::deleting))
    return false;

  const auto maximum_with_rekey_headroom =
      configuration_.maximum_child_sas + 1U;
  if (checkpoint.child_sas.size() > maximum_with_rekey_headroom)
    return false;
  std::vector<ChildSaBinding> restored_children;
  try {
    restored_children.reserve(maximum_with_rekey_headroom);
    for (const auto &saved : checkpoint.child_sas) {
      if (saved.child_sa_id == 0U || saved.inbound_sa_id == 0U ||
          saved.outbound_sa_id == 0U ||
          saved.inbound_sa_id == saved.outbound_sa_id ||
          saved.state > ChildSaState::retiring)
        return false;
      if (std::any_of(restored_children.begin(), restored_children.end(),
                      [&](const auto &existing) {
                        return existing.child_sa_id == saved.child_sa_id ||
                               existing.inbound_sa_id == saved.inbound_sa_id ||
                               existing.outbound_sa_id == saved.outbound_sa_id;
                      }))
        return false;
      const auto age = checked_duration(saved.installed_age_nanoseconds);
      if (!age || now.time_since_epoch() < *age)
        return false;
      restored_children.push_back(
          {.child_sa_id = saved.child_sa_id,
           .inbound_sa_id = saved.inbound_sa_id,
           .outbound_sa_id = saved.outbound_sa_id,
           .installed_at = now - *age,
           .state = saved.state});
    }
  } catch (...) {
    return false;
  }

  if (checkpoint.pending_child_install &&
      (checkpoint.pending_child_install->request_id == 0U ||
       checkpoint.pending_child_install->ike_sa_id != id_ ||
       checkpoint.pending_child_install->child_sa_id == 0U))
    return false;
  if (checkpoint.pending_child_remove) {
    const auto &pending = *checkpoint.pending_child_remove;
    const auto binding = std::find_if(
        restored_children.begin(), restored_children.end(),
        [&](const auto &candidate) {
          return candidate.child_sa_id == pending.child_sa_id &&
                 candidate.inbound_sa_id == pending.inbound_sa_id &&
                 candidate.outbound_sa_id == pending.outbound_sa_id &&
                 candidate.state == ChildSaState::retiring;
        });
    if (pending.request_id == 0U || pending.ike_sa_id != id_ ||
        binding == restored_children.end())
      return false;
  }
  Clock::time_point restored_deadline{};
  if (checkpoint.has_liveness_deadline) {
    const auto deadline =
        checked_add(now, checkpoint.liveness_remaining_nanoseconds);
    if (!deadline)
      return false;
    restored_deadline = *deadline;
  }

  // All allocation and validation completed above. These moves and scalar
  // assignments are the only point at which the live owner changes.
  state_ = checkpoint.state;
  spis_ = checkpoint.spis;
  key_set_handle_ = checkpoint.key_set_handle;
  next_request_id_ = checkpoint.next_request_id;
  pending_child_install_ = checkpoint.pending_child_install;
  pending_child_remove_ = checkpoint.pending_child_remove;
  pending_remove_previous_state_ = checkpoint.pending_remove_previous_state;
  child_sas_ = std::move(restored_children);
  liveness_deadline_ = restored_deadline;
  unanswered_liveness_requests_ = checkpoint.unanswered_liveness_requests;
  return true;
}

} // namespace router::ikev2
