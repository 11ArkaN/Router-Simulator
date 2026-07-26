// Executable forwarding-owner composition for RFC 4301, RFC 4302 and RFC
// 4303. Policy misses, explicit bypass and explicit discard remain distinct,
// which lets the caller apply its configured default SPD policy without ever
// treating missing CHILD SA state as permission to transmit cleartext.

#include "router/ipsec_forwarding_security.hpp"

namespace router::ipsec {

ForwardingSecurity::ForwardingSecurity(std::size_t policy_capacity,
                                       std::size_t association_capacity) noexcept
    : policy_capacity_(policy_capacity),
      association_capacity_(association_capacity), spd_(policy_capacity),
      sad_(association_capacity) {}

PolicyDecision ForwardingSecurity::decide(
    Direction direction, const PacketSelector &packet) noexcept {
  const auto policy = spd_.lookup(direction, packet);
  if (!policy)
    return {.status = PolicyDecisionStatus::no_matching_policy};
  if (policy->action == PolicyAction::bypass)
    return {.status = PolicyDecisionStatus::bypass,
            .policy_id = policy->id};
  if (policy->action == PolicyAction::discard)
    return {.status = PolicyDecisionStatus::discard,
            .policy_id = policy->id};

  auto *esp = sad_.find_outbound_for_policy(policy->id,
                                             SecurityProtocol::esp);
  auto *ah = sad_.find_outbound_for_policy(policy->id,
                                            SecurityProtocol::ah);
  if (esp && ah)
    return {.status = PolicyDecisionStatus::ambiguous_sa,
            .policy_id = policy->id};
  const auto *selected = esp ? esp : ah;
  if (!selected)
    return {.status = PolicyDecisionStatus::required_sa_unavailable,
            .policy_id = policy->id};
  return {.status = PolicyDecisionStatus::protect,
          .policy_id = policy->id,
          .outbound_sa_id = selected->id,
          .protocol = selected->inbound_identifier.protocol};
}

EspProtectResult ForwardingSecurity::protect_esp_packet(
    const PolicyDecision &decision,
    const EspProcessorDependencies &dependencies, std::uint8_t next_header,
    std::span<const std::uint8_t> plaintext,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> output) noexcept {
  if (decision.status != PolicyDecisionStatus::protect ||
      decision.protocol != SecurityProtocol::esp ||
      decision.outbound_sa_id == 0U)
    return {.status = EspProcessStatus::invalid_argument};
  return protect_esp(sad_, decision.outbound_sa_id, dependencies, next_header,
                     plaintext, now, output);
}

EspUnprotectResult ForwardingSecurity::unprotect_esp_packet(
    const Address &outer_destination, const Address &outer_source,
    const EspProcessorDependencies &dependencies,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> plaintext_output) noexcept {
  return unprotect_esp(sad_, outer_destination, outer_source, dependencies,
                       packet, now, plaintext_output);
}

AhProtectResult ForwardingSecurity::protect_ah_packet(
    const PolicyDecision &decision,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet_template,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> output,
    std::span<std::uint8_t> canonical_scratch) noexcept {
  if (decision.status != PolicyDecisionStatus::protect ||
      decision.protocol != SecurityProtocol::ah ||
      decision.outbound_sa_id == 0U)
    return {.status = AhProcessStatus::invalid_argument};
  return protect_ah(sad_, decision.outbound_sa_id, dependencies, ipv6,
                    packet_template, now, output, canonical_scratch);
}

AhVerifyResult ForwardingSecurity::verify_ah_packet(
    const Address &outer_destination, const Address &outer_source,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> canonical_scratch) noexcept {
  return verify_ah(sad_, outer_destination, outer_source, dependencies, ipv6,
                   packet, now, canonical_scratch);
}

std::optional<ForwardingSecurityCheckpoint>
ForwardingSecurity::checkpoint(
    std::chrono::steady_clock::time_point now) const noexcept {
  const auto sad = sad_.checkpoint(now);
  if (!sad)
    return std::nullopt;
  try {
    return ForwardingSecurityCheckpoint{.spd = spd_.checkpoint(),
                                        .sad = *sad};
  } catch (...) {
    return std::nullopt;
  }
}

bool ForwardingSecurity::restore(const ForwardingSecurityCheckpoint &state,
                                 std::chrono::steady_clock::time_point now) noexcept {
  if (state.spd.capacity != policy_capacity_ ||
      state.sad.capacity != association_capacity_)
    return false;
  try {
    Spd staged_spd{policy_capacity_};
    Sad staged_sad{association_capacity_};
    if (!staged_spd.restore(state.spd) || !staged_sad.restore(state.sad, now))
      return false;
    spd_ = std::move(staged_spd);
    sad_ = std::move(staged_sad);
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::ipsec
