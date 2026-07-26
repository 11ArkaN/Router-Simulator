// IKE SA tests prove AUTH gating, cross-shard CHILD SA acknowledgement, failed
// install isolation and owner-local liveness deadlines.

#include "router/ikev2_sa.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

void ikev2_sa_tests() {
  using namespace router::ikev2;
  using namespace std::chrono_literals;
  const auto start = Sa::Clock::time_point{10s};
  const std::array<std::uint8_t, 2U> local_i{0x20U, 0x00U};
  const std::array<std::uint8_t, 1U> local_r{0x20U};
  const std::array<std::uint8_t, 2U> peer_i{0x30U, 0x00U};
  const std::array<std::uint8_t, 2U> peer_r{0x40U, 0x00U};
  if (resolve_rekey_collision(local_i, local_r, peer_i, peer_r) !=
          RekeyCollisionLoser::local_exchange ||
      resolve_rekey_collision(peer_i, peer_r, local_i, local_r) !=
          RekeyCollisionLoser::peer_exchange ||
      resolve_rekey_collision(local_i, local_i, peer_i, peer_r) !=
          RekeyCollisionLoser::indeterminate)
    throw std::runtime_error("RFC 7296 rekey nonce ordering failed");
  Sa sa{1U,
        Role::initiator,
        SaConfiguration{.maximum_child_sas = 2U,
                        .liveness = {.idle_interval = 30s,
                                     .maximum_unanswered_requests = 2U}}};
  if (sa.begin_initial_exchange(11U, start) != SaTransitionResult::applied ||
      sa.complete_initial_exchange(22U, {.key_set_handle = 33U}, start) !=
          SaTransitionResult::applied ||
      sa.complete_authentication(AuthenticationStatus::ok, start) !=
          SaTransitionResult::applied ||
      sa.state() != SaState::established)
    throw std::runtime_error("IKE SA establishment transition failed");

  router::ipsec::SecurityAssociation inbound{};
  inbound.id = 101U;
  inbound.inbound_identifier.spi = 0x10203040U;
  inbound.encryption =
      router::ipsec::EncryptionAlgorithm::aes_gcm_16_128;
  inbound.crypto_material_handle = 1U;
  inbound.policy_id = 7U;
  auto outbound = inbound;
  outbound.id = 102U;
  outbound.outbound = true;
  const auto request = sa.begin_child_install(9U, inbound, outbound);
  if (!request.has_value() || !sa.child_sas().empty())
    throw std::runtime_error("IKE SA exposed an uncommitted CHILD SA");
  if (sa.complete_child_install(
          request->request_id,
          {.inbound = router::ipsec::SaInstallResult::installed,
           .outbound = router::ipsec::SaInstallResult::installed,
           .committed = true},
          start) != SaTransitionResult::applied ||
      sa.child_sas().size() != 1U ||
      sa.child_sas()[0U].inbound_sa_id != 101U)
    throw std::runtime_error("IKE SA did not accept an atomic CHILD SA pair");

  auto failed_inbound = inbound;
  failed_inbound.id = 103U;
  auto failed_outbound = outbound;
  failed_outbound.id = 104U;
  const auto failed_request =
      sa.begin_child_install(10U, failed_inbound, failed_outbound);
  if (!failed_request ||
      sa.complete_child_install(failed_request->request_id, {}, start) !=
          SaTransitionResult::forwarding_rejected ||
      sa.child_sas().size() != 1U)
    throw std::runtime_error("failed CHILD SA became operational");

  // Rekey installs a fresh pair before the old one is retired. A forwarding
  // delete failure must retain the old binding because packets can still use
  // it; a later successful transaction removes only that old pair.
  auto rekey_inbound = inbound;
  rekey_inbound.id = 105U;
  rekey_inbound.inbound_identifier.spi = 0x50607080U;
  auto rekey_outbound = outbound;
  rekey_outbound.id = 106U;
  rekey_outbound.inbound_identifier.spi = 0x50607080U;
  const auto rekey =
      sa.begin_child_rekey(9U, 11U, rekey_inbound, rekey_outbound);
  if (!rekey || rekey->replaces_child_sa_id != 9U ||
      sa.complete_child_install(
          rekey->request_id,
          {.inbound = router::ipsec::SaInstallResult::installed,
           .outbound = router::ipsec::SaInstallResult::installed,
           .committed = true},
          start + 1s) != SaTransitionResult::applied ||
      sa.child_sas().size() != 2U ||
      sa.child_sas()[0U].state != ChildSaState::retiring ||
      sa.child_sas()[1U].state != ChildSaState::active)
    throw std::runtime_error("IKE CHILD SA rekey was not make-before-break");
  const auto first_delete = sa.begin_child_delete(9U);
  if (!first_delete ||
      sa.complete_child_delete(first_delete->request_id,
                               router::ipsec::SaPairEraseResult::missing) !=
          SaTransitionResult::forwarding_rejected ||
      sa.child_sas().size() != 2U ||
      sa.child_sas()[0U].state != ChildSaState::retiring)
    throw std::runtime_error("failed rekey retirement lost the old CHILD SA");
  const auto second_delete = sa.begin_child_delete(9U);
  const auto saved = sa.checkpoint(start + 2s);
  Sa restored{1U,
              Role::initiator,
              SaConfiguration{.maximum_child_sas = 2U,
                              .liveness = {.idle_interval = 30s,
                                           .maximum_unanswered_requests = 2U}}};
  const auto restore_time = Sa::Clock::time_point{100s};
  if (!second_delete || !saved || !restored.restore(*saved, restore_time) ||
      restored.complete_child_delete(
          second_delete->request_id,
          router::ipsec::SaPairEraseResult::erased) !=
          SaTransitionResult::applied ||
      restored.child_sas().size() != 1U ||
      restored.child_sas()[0U].child_sa_id != 11U ||
      restored.poll_liveness(restore_time + 28s) != LivenessAction::none ||
      restored.poll_liveness(restore_time + 29s) !=
          LivenessAction::send_empty_informational)
    throw std::runtime_error(
        "active CHILD delete or relative liveness deadline did not restore");

  auto corrupt = *saved;
  corrupt.child_sas[0U].inbound_sa_id = 0U;
  if (restored.restore(corrupt, restore_time) ||
      restored.child_sas().size() != 1U ||
      restored.child_sas()[0U].child_sa_id != 11U)
    throw std::runtime_error("invalid IKE checkpoint partially changed state");

  if (restored.begin_ike_delete() != SaTransitionResult::applied ||
      restored.complete_ike_delete() != SaTransitionResult::request_pending)
    throw std::runtime_error("IKE delete closed an SA with a live CHILD pair");
  const auto final_child_delete = restored.begin_child_delete(11U);
  if (!final_child_delete ||
      restored.complete_child_delete(
          final_child_delete->request_id,
          router::ipsec::SaPairEraseResult::erased) !=
          SaTransitionResult::applied ||
      restored.complete_ike_delete() != SaTransitionResult::applied ||
      restored.state() != SaState::closed || restored.key_set_handle() != 0U)
    throw std::runtime_error("IKE delete retained CHILD state or key ownership");

  if (sa.poll_liveness(start + 31s) !=
          LivenessAction::send_empty_informational ||
      sa.poll_liveness(start + 61s) !=
          LivenessAction::send_empty_informational ||
      sa.poll_liveness(start + 91s) != LivenessAction::delete_ike_sa ||
      sa.state() != SaState::deleting)
    throw std::runtime_error("IKE SA liveness retry policy failed");

  Sa rejected{2U,
              Role::responder,
              SaConfiguration{.maximum_child_sas = 1U,
                              .liveness = {.idle_interval = 30s,
                                           .maximum_unanswered_requests = 1U}}};
  if (rejected.begin_initial_exchange(44U, start) !=
          SaTransitionResult::applied ||
      rejected.complete_initial_exchange(55U, {.key_set_handle = 66U}, start) !=
          SaTransitionResult::applied ||
      rejected.complete_authentication(
          AuthenticationStatus::authentication_failed, start) !=
          SaTransitionResult::forwarding_rejected ||
      rejected.state() != SaState::failed ||
      rejected.begin_child_install(1U, inbound, outbound))
    throw std::runtime_error("failed IKE AUTH did not fail closed");
}
