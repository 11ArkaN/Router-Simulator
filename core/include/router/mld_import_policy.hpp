// Compiled MLD import-policy program. The forwarding shard owns one immutable
// instance per configured MLD interface. Control supplies a complete ordered
// generation, and packet processing performs allocation-free group/source
// evaluation before the listener database owner sees a membership report.

#pragma once

#include "router/ip_address.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::mld {

// nokia-conf-policy-options.yang defines policy-statement names as
// named-item-64. Classic CLI narrows accepted text to 32 characters at its
// parser boundary, while the canonical datastore must retain the MD width.
inline constexpr std::size_t maximum_policy_name_octets = 64U;

enum class ImportPolicyAction : std::uint8_t {
  accept,
  reject,
  // Classic SR OS exposes both drop and reject. Both deny an MLD report, but
  // retaining the configured spelling is required for faithful persistence,
  // candidate compare and future policy consumers where their route-property
  // semantics differ.
  drop,
  // SR OS route-policy next-entry continues with the next numeric entry. It
  // is distinct from accept so a broad logging or classification rule cannot
  // accidentally terminate evaluation.
  next_entry,
  // An MLD interface has one import-policy reference in 26.7.R1. Reaching the
  // next policy therefore exits this policy chain and falls through to the
  // protocol default, which accepts the report.
  next_policy
};

// A complete policy can exceed one bounded SPSC command slot. Control streams
// one generation with this transaction protocol. Only commit publishes it, so
// packet processing never observes a prefix of a policy after ring pressure or
// a failed command.
enum class ImportPolicyProgramOperation : std::uint8_t {
  begin,
  add,
  commit,
  abort
};

struct ImportPolicyEntry {
  // Numeric entries are evaluated in ascending order. Duplicate identifiers
  // are rejected during generation replacement instead of relying on vector
  // order that could differ between CLI engines.
  std::uint32_t number{};
  // One route-policy entry can reference prefix lists containing many values.
  // Compilation expands their Cartesian match set while preserving one
  // operator-visible entry number. term orders those private expansion rows.
  std::uint32_t term{};
  std::optional<ip::Ipv6Prefix> group;
  std::optional<ip::Ipv6Prefix> source;
  ImportPolicyAction action{ImportPolicyAction::next_entry};
  bool protocol_mld{};

  [[nodiscard]] friend bool
  operator==(const ImportPolicyEntry &,
             const ImportPolicyEntry &) noexcept = default;
};

struct ImportPolicyCheckpoint {
  std::vector<ImportPolicyEntry> entries;
  ImportPolicyAction default_action{ImportPolicyAction::accept};
  [[nodiscard]] friend bool
  operator==(const ImportPolicyCheckpoint &,
             const ImportPolicyCheckpoint &) noexcept = default;
};

class ImportPolicyProgram final {
public:
  // replace validates the entire generation before publishing it. Failure
  // leaves the previous program active, which is required for atomic MD commit
  // and immediate classic CLI semantics across a forwarding-shard boundary.
  [[nodiscard]] bool
  replace(std::span<const ImportPolicyEntry> entries,
          ImportPolicyAction default_action) noexcept;

  // A source-less membership, such as MLDv1 (*,G), cannot match an entry with
  // a source-address criterion. The optional therefore carries protocol
  // meaning and is not represented by the unspecified IPv6 address.
  [[nodiscard]] ImportPolicyAction
  evaluate(const ip::Ipv6 &group,
           const std::optional<ip::Ipv6> &source = std::nullopt) const noexcept;

  [[nodiscard]] const std::vector<ImportPolicyEntry> &entries() const noexcept {
    return entries_;
  }
  [[nodiscard]] ImportPolicyAction default_action() const noexcept {
    return default_action_;
  }

  [[nodiscard]] ImportPolicyCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const ImportPolicyCheckpoint &state) noexcept;

private:
  [[nodiscard]] static bool
  valid(std::span<const ImportPolicyEntry> entries,
        ImportPolicyAction default_action) noexcept;

  std::vector<ImportPolicyEntry> entries_;
  ImportPolicyAction default_action_{ImportPolicyAction::accept};
};

} // namespace router::mld
