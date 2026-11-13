// Effective IS-IS values are derived by the router configuration owner before
// protocol admission. This pure projection owns no live timers or shared state.
#pragma once
#include "router/isis_configuration.hpp"
#include <chrono>
namespace router::isis {
enum class WaitTimerKind : std::uint8_t { spf, lsp };
struct ResolvedWaitTimer {
  std::chrono::milliseconds maximum, initial, second;
  bool operator==(const ResolvedWaitTimer &) const = default;
};
// Pure local projection. Absence uses pinned YANG defaults; explicit values
// must fit their own leaf ranges. Classic timer granularity rounds down without
// mutating intent or inventing relationships between independently typed leaves.
// Zero effective durations are valid after rounding. Invalid kind/range refuses.
// This function owns no timer, clock, allocation or adaptive scheduling state.
[[nodiscard]] std::optional<ResolvedWaitTimer> resolve_wait_timer(WaitTimerKind,
    const WaitTimerIntent &) noexcept;
struct ResolvedInstanceLevel {
  bool enabled{}, wide_metrics_only{};
  std::uint32_t default_metric{};
  // The level leaf has its own YANG default. Global instance MTU is a
  // separate setting and cannot silently replace this datastore value.
  std::uint16_t lsp_mtu_octets{};
  // YANG supplies ranges but no level-dependent preference defaults. The
  // enclosing source-backed platform resolver must provide absent values.
  std::optional<std::uint8_t> preference, external_preference;
  bool operator==(const ResolvedInstanceLevel &) const = default;
};
struct ResolvedInterfaceLevel {
  bool enabled{}, passive{};
  std::uint32_t metric{};
  std::uint16_t hello_interval_seconds{};
  std::uint8_t hello_multiplier{}, priority{};
  // Preserve the full configured product. Selecting a wire holding-time
  // normalization is a separate source-backed policy, never integer truncation.
  std::uint32_t nominal_holding_seconds{};
  bool operator==(const ResolvedInterfaceLevel &) const = default;
};
struct ResolvedHelloTiming {
  std::chrono::microseconds interval;
  // RFC 4444 rounds the transmitted seconds upward. Keep the full product;
  // wire overflow still requires an explicit platform policy at admission.
  std::uint32_t holding_seconds{};
  bool operator==(const ResolvedHelloTiming &) const = default;
};
// Pure control-owner projection from validated level values. designated is
// true only for the actual local LAN DIS, never a P2P circuit. The result owns
// no storage. Sub-microsecond timer fractions truncate to the runtime resolution;
// holding seconds round upward independently. No wire integer is narrowed here.
[[nodiscard]] ResolvedHelloTiming resolve_hello_timing(const ResolvedInterfaceLevel &, bool designated) noexcept;
struct ResolvedP2pHello {
  bool enabled{};
  std::uint16_t hello_interval_seconds{};
  std::uint8_t hello_multiplier{};
  std::uint32_t nominal_holding_seconds{};
  bool operator==(const ResolvedP2pHello &) const = default;
};
struct ResolvedInterface {
  bool admin_enabled{};
  std::optional<ConfiguredInterfaceType> type;
  std::uint16_t csnp_interval_seconds{}, retransmit_interval_seconds{},
      lsp_pacing_interval_milliseconds{};
  std::array<ResolvedInterfaceLevel, 2U> level;
  // SR OS uses interface level-1 Hello parameters on P2P regardless of operational
  // level. The common enabled gate is the complete interface level mask.
  // Absence means media type still needs resolution, or this is broadcast.
  std::optional<ResolvedP2pHello> point_to_point;
  bool operator==(const ResolvedInterface &) const = default;
};
// Preconditions: validated intent and level < 2. Results borrow no storage.
// Root shutdown does not erase inherited values or per-level presence. The
// runtime applies administrative gating separately from circuit level masks.
[[nodiscard]] ResolvedInstanceLevel resolve_instance_level(const InstanceIntent &, std::size_t level) noexcept;
// default_type is resolved by the local media owner; absence preserves unknown media.
[[nodiscard]] ResolvedInterface resolve_interface(const InstanceIntent &, const InterfaceIntent &,
    std::optional<ConfiguredInterfaceType> default_type = {}) noexcept;
// Lifecycle selection belongs to the configuration owner before preparation.
// Null means an absent list entry. Non-null entries share one instance key.
// Inputs must be validated; no state changes,
// allocations or protocol calls occur. Active changes to restart-marked leaves
// require an entity restart even when all existing circuits could be retained.
enum class InstanceTransition : std::uint8_t {
  unchanged, inactive_edit, activate, deactivate, restart, reconfigure
};
[[nodiscard]] InstanceTransition instance_transition(const InstanceIntent *before,
    const InstanceIntent *after, const IdentityContext &before_identity,
    const IdentityContext &after_identity) noexcept;

}
