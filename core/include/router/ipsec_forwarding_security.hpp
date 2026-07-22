// Forwarding-shard IPsec policy and association owner. This module composes
// ordered SPD selection, CHILD SA selection, AH or ESP processing and portable
// mutable state without knowing CLI nodes, router topology or secret bytes.
// The forwarding worker is the sole writer. Cryptographic engines are borrowed
// through shard-local callbacks for the duration of one packet operation.

#pragma once

#include "router/ipsec_ah_processor.hpp"
#include "router/ipsec_esp_processor.hpp"
#include "router/ipsec_policy.hpp"
#include "router/ipsec_sad.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::ipsec {

struct ForwardingSecurityCheckpoint {
  SpdCheckpoint spd;
  SadCheckpoint sad;
};

enum class PolicyDecisionStatus : std::uint8_t {
  no_matching_policy,
  bypass,
  discard,
  protect,
  required_sa_unavailable,
  ambiguous_sa
};

struct PolicyDecision {
  PolicyDecisionStatus status{PolicyDecisionStatus::no_matching_policy};
  std::uint32_t policy_id{};
  std::uint64_t outbound_sa_id{};
  SecurityProtocol protocol{SecurityProtocol::esp};
};

class ForwardingSecurity final {
public:
  // Capacities come from the selected runtime resource profile. Construction
  // performs all vector reservations so policy lookup and packet processing do
  // not allocate on the forwarding shard.
  ForwardingSecurity(std::size_t policy_capacity,
                     std::size_t association_capacity) noexcept;

  [[nodiscard]] PolicyInstallResult install_policy(
      const Policy &policy) noexcept {
    return spd_.install(policy);
  }
  [[nodiscard]] bool erase_policy(std::uint32_t id) noexcept {
    return spd_.erase(id);
  }
  [[nodiscard]] SaInstallResult install_sa(
      const SecurityAssociation &association) noexcept {
    return sad_.install(association);
  }
  [[nodiscard]] SaPairInstallResult install_child_pair(
      const SecurityAssociation &inbound,
      const SecurityAssociation &outbound) noexcept {
    return sad_.install_pair(inbound, outbound);
  }
  [[nodiscard]] SaPairEraseResult erase_child_pair(
      std::uint64_t inbound_id, std::uint64_t outbound_id) noexcept {
    return sad_.erase_pair(inbound_id, outbound_id);
  }

  // A protect rule is never converted into bypass when no matching SA exists.
  // During make-before-break the newest outbound SA for the policy is selected.
  // Two protocols for one policy are rejected as ambiguous control programming.
  [[nodiscard]] PolicyDecision decide(
      Direction direction, const PacketSelector &packet) noexcept;

  [[nodiscard]] EspProtectResult protect_esp_packet(
      const PolicyDecision &decision,
      const EspProcessorDependencies &dependencies, std::uint8_t next_header,
      std::span<const std::uint8_t> plaintext,
      std::chrono::steady_clock::time_point now,
      std::span<std::uint8_t> output) noexcept;
  [[nodiscard]] EspUnprotectResult unprotect_esp_packet(
      const Address &outer_destination, const Address &outer_source,
      const EspProcessorDependencies &dependencies,
      std::span<const std::uint8_t> packet,
      std::chrono::steady_clock::time_point now,
      std::span<std::uint8_t> plaintext_output) noexcept;

  [[nodiscard]] AhProtectResult protect_ah_packet(
      const PolicyDecision &decision,
      const AhProcessorDependencies &dependencies, bool ipv6,
      std::span<const std::uint8_t> packet_template,
      std::chrono::steady_clock::time_point now,
      std::span<std::uint8_t> output,
      std::span<std::uint8_t> canonical_scratch) noexcept;
  [[nodiscard]] AhVerifyResult verify_ah_packet(
      const Address &outer_destination, const Address &outer_source,
      const AhProcessorDependencies &dependencies, bool ipv6,
      std::span<const std::uint8_t> packet,
      std::chrono::steady_clock::time_point now,
      std::span<std::uint8_t> canonical_scratch) noexcept;

  // Restore validates both databases in detached owners. If either side is
  // malformed, the current SPD and SAD remain byte-for-byte operational.
  [[nodiscard]] std::optional<ForwardingSecurityCheckpoint>
  checkpoint(std::chrono::steady_clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const ForwardingSecurityCheckpoint &state,
                             std::chrono::steady_clock::time_point now) noexcept;

  [[nodiscard]] std::size_t policy_count() const noexcept {
    return spd_.size();
  }
  [[nodiscard]] std::size_t association_count() const noexcept {
    return sad_.size();
  }

private:
  std::size_t policy_capacity_{};
  std::size_t association_capacity_{};
  Spd spd_;
  Sad sad_;
};

} // namespace router::ipsec
