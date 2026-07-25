// Pure OSPF interface and neighbor finite-state machines. This module owns no
// timers, packets or LSDB storage. A per-instance control owner supplies one
// event at a time, applies the returned actions atomically and then stores the
// returned state. Keeping transition logic pure makes every RFC table row
// testable without a virtual production clock or hidden cross-router state.

#pragma once

#include <cstdint>
#include <span>

namespace router::ospf {

enum class NetworkType : std::uint8_t {
  point_to_point,
  broadcast,
  non_broadcast,
  point_to_multipoint,
  virtual_link
};

enum class InterfaceState : std::uint8_t {
  down,
  loopback,
  waiting,
  point_to_point,
  dr_other,
  backup,
  designated
};

enum class InterfaceEvent : std::uint8_t {
  interface_up,
  wait_timer,
  backup_seen,
  neighbor_change,
  loop_indication,
  unloop_indication,
  interface_down
};

enum class InterfaceAction : std::uint16_t {
  none = 0U,
  start_hello_timer = 1U << 0U,
  start_wait_timer = 1U << 1U,
  stop_timers = 1U << 2U,
  send_hello = 1U << 3U,
  elect_dr_bdr = 1U << 4U,
  reset_interface = 1U << 5U,
  originate_router_lsa = 1U << 6U,
  originate_network_lsa = 1U << 7U
};

[[nodiscard]] constexpr InterfaceAction
operator|(InterfaceAction left, InterfaceAction right) noexcept {
  return static_cast<InterfaceAction>(static_cast<std::uint16_t>(left) |
                                      static_cast<std::uint16_t>(right));
}

[[nodiscard]] constexpr bool has_action(InterfaceAction actions,
                                        InterfaceAction action) noexcept {
  return (static_cast<std::uint16_t>(actions) &
          static_cast<std::uint16_t>(action)) != 0U;
}

struct InterfaceTransition {
  InterfaceState state{InterfaceState::down};
  InterfaceAction actions{InterfaceAction::none};
};

// interface_transition implements RFC 2328 section 9.3 before DR election.
// Election events request elect_dr_bdr rather than reading neighbor state
// through a global registry. The interface owner performs the election from
// its own neighbor repository and applies election_state afterward.
[[nodiscard]] InterfaceTransition interface_transition(
    InterfaceState current, InterfaceEvent event, NetworkType network_type,
    std::uint8_t router_priority) noexcept;

struct ElectionRouter {
  // election_identity is the value carried in the Hello DR and BDR fields.
  // OSPFv2 uses the interface's IPv4 address while OSPFv3 uses the Router ID.
  // Keeping it separate from router_id prevents the shared election algorithm
  // from silently applying OSPFv3 wire semantics to OSPFv2.
  std::uint32_t election_identity{};
  // declared_dr and declared_bdr are the sender's most recently accepted Hello
  // values. A zero value means that role was not declared.
  std::uint32_t router_id{};
  std::uint32_t declared_dr{};
  std::uint32_t declared_bdr{};
  std::uint8_t priority{};
  bool two_way_or_greater{};
  bool local{};
};

struct DrBdrElection {
  std::uint32_t designated_router{};
  std::uint32_t backup_designated_router{};
  InterfaceState local_state{InterfaceState::dr_other};
};

// The input includes the local router and all neighbors known on exactly one
// broadcast or NBMA interface. Ineligible routers are ignored. The two-pass
// calculation accounts for a local role change as required by RFC 2328
// section 9.4 and never uses input order as a tie-break.
[[nodiscard]] DrBdrElection
elect_dr_bdr(std::span<const ElectionRouter> routers) noexcept;

enum class NeighborState : std::uint8_t {
  down,
  attempt,
  init,
  two_way,
  exstart,
  exchange,
  loading,
  full
};

enum class NeighborEvent : std::uint8_t {
  start,
  hello_received,
  two_way_received,
  negotiation_done,
  exchange_done,
  bad_link_state_request,
  loading_done,
  adjacency_ok,
  sequence_number_mismatch,
  one_way_received,
  kill_neighbor,
  inactivity_timer,
  lower_layer_down
};

enum class NeighborAction : std::uint16_t {
  none = 0U,
  send_hello = 1U << 0U,
  reset_inactivity_timer = 1U << 1U,
  stop_inactivity_timer = 1U << 2U,
  clear_adjacency = 1U << 3U,
  begin_database_exchange = 1U << 4U,
  start_sending_requests = 1U << 5U,
  notify_interface = 1U << 6U,
  delete_neighbor = 1U << 7U
};

[[nodiscard]] constexpr NeighborAction
operator|(NeighborAction left, NeighborAction right) noexcept {
  return static_cast<NeighborAction>(static_cast<std::uint16_t>(left) |
                                     static_cast<std::uint16_t>(right));
}

[[nodiscard]] constexpr bool has_action(NeighborAction actions,
                                        NeighborAction action) noexcept {
  return (static_cast<std::uint16_t>(actions) &
          static_cast<std::uint16_t>(action)) != 0U;
}

struct NeighborTransition {
  NeighborState state{NeighborState::down};
  NeighborAction actions{NeighborAction::none};
};

// adjacency_required is calculated by the local interface owner from network
// type and current DR and BDR roles. requests_pending is sampled only for the
// ExchangeDone event. Passing these values explicitly prevents the FSM from
// borrowing mutable interface or LSDB containers.
[[nodiscard]] NeighborTransition neighbor_transition(
    NeighborState current, NeighborEvent event, bool adjacency_required,
    bool requests_pending) noexcept;

} // namespace router::ospf
