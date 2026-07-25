// RFC 2328 sections 9.3, 9.4 and 10.3 finite-state behavior. OSPFv3 retains
// these fundamental state machines through RFC 5340 section 4, so one pure
// implementation serves both protocol versions.

#include "router/ospf_fsm.hpp"

#include <algorithm>

namespace router::ospf {
namespace {

constexpr InterfaceAction interface_reset_actions =
    InterfaceAction::stop_timers | InterfaceAction::reset_interface |
    InterfaceAction::originate_router_lsa;

constexpr NeighborAction adjacency_reset_actions =
    NeighborAction::clear_adjacency |
    NeighborAction::begin_database_exchange;

bool is_multi_access(NetworkType type) noexcept {
  return type == NetworkType::broadcast ||
         type == NetworkType::non_broadcast;
}

bool better(const ElectionRouter *candidate,
            const ElectionRouter *current) noexcept {
  if (candidate == nullptr)
    return false;
  if (current == nullptr)
    return true;
  return candidate->priority > current->priority ||
         (candidate->priority == current->priority &&
          candidate->router_id > current->router_id);
}

bool eligible(const ElectionRouter &router) noexcept {
  // The local router participates before it can be represented as its own
  // neighbor. Remote routers require 2-Way or greater, exactly matching the
  // election candidate set.
  return router.priority != 0U &&
         (router.local || router.two_way_or_greater);
}

struct ElectionPair {
  const ElectionRouter *designated{};
  const ElectionRouter *backup{};
};

ElectionPair one_election(std::span<const ElectionRouter> routers) noexcept {
  const ElectionRouter *declared_backup{};
  const ElectionRouter *fallback_backup{};
  const ElectionRouter *declared_designated{};

  for (const auto &router : routers) {
    if (!eligible(router))
      continue;
    const bool declares_dr =
        router.declared_dr == router.election_identity;
    const bool declares_bdr =
        router.declared_bdr == router.election_identity;
    if (declares_dr) {
      if (better(&router, declared_designated))
        declared_designated = &router;
      // A router declaring itself DR is excluded from both BDR candidate
      // passes even if a stale Hello also contains itself as BDR.
      continue;
    }
    if (better(&router, fallback_backup))
      fallback_backup = &router;
    if (declares_bdr && better(&router, declared_backup))
      declared_backup = &router;
  }
  const auto *backup = declared_backup ? declared_backup : fallback_backup;
  const auto *designated =
      declared_designated ? declared_designated : backup;
  return {.designated = designated, .backup = backup};
}

NeighborTransition down_neighbor(NeighborAction extra) noexcept {
  return {.state = NeighborState::down,
          .actions = NeighborAction::stop_inactivity_timer |
                     NeighborAction::clear_adjacency |
                     NeighborAction::notify_interface | extra};
}

} // namespace

InterfaceTransition interface_transition(
    InterfaceState current, InterfaceEvent event, NetworkType network_type,
    std::uint8_t router_priority) noexcept {
  if (event == InterfaceEvent::interface_down) {
    return {.state = InterfaceState::down,
            .actions = interface_reset_actions};
  }
  if (event == InterfaceEvent::loop_indication) {
    return {.state = InterfaceState::loopback,
            .actions = interface_reset_actions};
  }
  if (current == InterfaceState::loopback) {
    if (event == InterfaceEvent::unloop_indication)
      return {.state = InterfaceState::down,
              .actions = InterfaceAction::originate_router_lsa};
    return {.state = current};
  }
  if (current == InterfaceState::down) {
    if (event != InterfaceEvent::interface_up)
      return {.state = current};
    if (!is_multi_access(network_type)) {
      return {.state = InterfaceState::point_to_point,
              .actions = InterfaceAction::start_hello_timer |
                         InterfaceAction::send_hello |
                         InterfaceAction::originate_router_lsa};
    }
    if (router_priority == 0U) {
      return {.state = InterfaceState::dr_other,
              .actions = InterfaceAction::start_hello_timer |
                         InterfaceAction::send_hello |
                         InterfaceAction::originate_router_lsa};
    }
    return {.state = InterfaceState::waiting,
            .actions = InterfaceAction::start_hello_timer |
                       InterfaceAction::start_wait_timer |
                       InterfaceAction::send_hello |
                       InterfaceAction::originate_router_lsa};
  }

  if (!is_multi_access(network_type))
    return {.state = current};

  if (current == InterfaceState::waiting) {
    if (event == InterfaceEvent::wait_timer ||
        event == InterfaceEvent::backup_seen) {
      return {.state = current,
              .actions = InterfaceAction::elect_dr_bdr};
    }
    // NeighborChange during Waiting does not terminate the WaitTimer. The
    // BackupSeen event is raised separately when a Hello reveals a DR or BDR.
    return {.state = current};
  }

  if ((current == InterfaceState::dr_other ||
       current == InterfaceState::backup ||
       current == InterfaceState::designated) &&
      event == InterfaceEvent::neighbor_change) {
    return {.state = current,
            .actions = InterfaceAction::elect_dr_bdr};
  }
  return {.state = current};
}

DrBdrElection elect_dr_bdr(
    std::span<const ElectionRouter> routers) noexcept {
  auto first = one_election(routers);
  const ElectionRouter *local{};
  for (const auto &router : routers) {
    if (router.local) {
      local = &router;
      break;
    }
  }
  if (local == nullptr || !eligible(*local)) {
    return {.designated_router =
                first.designated
                    ? first.designated->election_identity
                    : 0U,
            .backup_designated_router =
                first.backup ? first.backup->election_identity : 0U,
            .local_state = InterfaceState::dr_other};
  }

  const auto previous_local_role =
      local->declared_dr == local->election_identity
          ? InterfaceState::designated
          : (local->declared_bdr == local->election_identity
                 ? InterfaceState::backup
                 : InterfaceState::dr_other);
  const auto first_local_role =
      first.designated == local
          ? InterfaceState::designated
          : (first.backup == local ? InterfaceState::backup
                                   : InterfaceState::dr_other);

  // RFC 2328 repeats the election when this router's role changes. Build one
  // bounded local projection with its new declarations rather than modifying
  // the caller-owned Hello repository.
  if (first_local_role != previous_local_role) {
    // An OSPF interface cannot have more candidate routers than the neighbor
    // repository limit, but this pure primitive must not allocate an
    // unbounded copy. Recompute the second pass by substituting the local
    // declarations while scanning candidates.
    const ElectionRouter *declared_backup{};
    const ElectionRouter *fallback_backup{};
    const ElectionRouter *declared_designated{};
    for (const auto &source : routers) {
      auto router = source;
      if (router.local) {
        router.declared_dr =
            first_local_role == InterfaceState::designated
                ? router.election_identity
                : 0U;
        router.declared_bdr =
            first_local_role == InterfaceState::backup
                ? router.election_identity
                : 0U;
      }
      if (!eligible(router))
        continue;
      const bool declares_dr =
          router.declared_dr == router.election_identity;
      const bool declares_bdr =
          router.declared_bdr == router.election_identity;
      // Candidate pointers cannot refer to the loop-local copy. Preserve the
      // source address after evaluating declarations from the projected copy.
      if (declares_dr) {
        if (better(&source, declared_designated))
          declared_designated = &source;
        continue;
      }
      if (better(&source, fallback_backup))
        fallback_backup = &source;
      if (declares_bdr && better(&source, declared_backup))
        declared_backup = &source;
    }
    first.backup =
        declared_backup ? declared_backup : fallback_backup;
    first.designated =
        declared_designated ? declared_designated : first.backup;
  }

  return {
      .designated_router =
          first.designated ? first.designated->election_identity : 0U,
      .backup_designated_router =
          first.backup ? first.backup->election_identity : 0U,
      .local_state =
          first.designated == local
              ? InterfaceState::designated
              : (first.backup == local ? InterfaceState::backup
                                       : InterfaceState::dr_other)};
}

NeighborTransition neighbor_transition(
    NeighborState current, NeighborEvent event, bool adjacency_required,
    bool requests_pending) noexcept {
  if (event == NeighborEvent::kill_neighbor ||
      event == NeighborEvent::inactivity_timer ||
      event == NeighborEvent::lower_layer_down) {
    return down_neighbor(event == NeighborEvent::kill_neighbor
                             ? NeighborAction::delete_neighbor
                             : NeighborAction::none);
  }

  if (event == NeighborEvent::hello_received) {
    if (current == NeighborState::down ||
        current == NeighborState::attempt) {
      return {.state = NeighborState::init,
              .actions = NeighborAction::reset_inactivity_timer |
                         NeighborAction::notify_interface};
    }
    return {.state = current,
            .actions = NeighborAction::reset_inactivity_timer};
  }

  if (current == NeighborState::down) {
    if (event == NeighborEvent::start) {
      return {.state = NeighborState::attempt,
              .actions = NeighborAction::send_hello |
                         NeighborAction::reset_inactivity_timer};
    }
    return {.state = current};
  }

  if (event == NeighborEvent::one_way_received &&
      current >= NeighborState::two_way) {
    return {.state = NeighborState::init,
            .actions = NeighborAction::clear_adjacency |
                       NeighborAction::notify_interface};
  }

  if (event == NeighborEvent::sequence_number_mismatch ||
      event == NeighborEvent::bad_link_state_request) {
    if (current >= NeighborState::exchange) {
      return {.state = NeighborState::exstart,
              .actions = adjacency_reset_actions};
    }
    return {.state = current};
  }

  switch (current) {
  case NeighborState::attempt:
  case NeighborState::init:
    if (event == NeighborEvent::two_way_received) {
      return adjacency_required
                 ? NeighborTransition{
                       .state = NeighborState::exstart,
                       .actions = NeighborAction::begin_database_exchange |
                                  NeighborAction::notify_interface}
                 : NeighborTransition{
                       .state = NeighborState::two_way,
                       .actions = NeighborAction::notify_interface};
    }
    break;
  case NeighborState::two_way:
    if (event == NeighborEvent::adjacency_ok && adjacency_required) {
      return {.state = NeighborState::exstart,
              .actions = NeighborAction::begin_database_exchange};
    }
    break;
  case NeighborState::exstart:
    if (event == NeighborEvent::negotiation_done)
      return {.state = NeighborState::exchange};
    if (event == NeighborEvent::adjacency_ok && !adjacency_required)
      return {.state = NeighborState::two_way,
              .actions = NeighborAction::clear_adjacency};
    break;
  case NeighborState::exchange:
    if (event == NeighborEvent::exchange_done) {
      return requests_pending
                 ? NeighborTransition{
                       .state = NeighborState::loading,
                       .actions = NeighborAction::start_sending_requests}
                 : NeighborTransition{.state = NeighborState::full,
                                      .actions =
                                          NeighborAction::notify_interface};
    }
    if (event == NeighborEvent::adjacency_ok && !adjacency_required) {
      return {.state = NeighborState::two_way,
              .actions = NeighborAction::clear_adjacency};
    }
    break;
  case NeighborState::loading:
    if (event == NeighborEvent::loading_done)
      return {.state = NeighborState::full,
              .actions = NeighborAction::notify_interface};
    if (event == NeighborEvent::adjacency_ok && !adjacency_required) {
      return {.state = NeighborState::two_way,
              .actions = NeighborAction::clear_adjacency};
    }
    break;
  case NeighborState::full:
    if (event == NeighborEvent::adjacency_ok && !adjacency_required) {
      return {.state = NeighborState::two_way,
              .actions = NeighborAction::clear_adjacency |
                         NeighborAction::notify_interface};
    }
    break;
  case NeighborState::down:
    break;
  }
  return {.state = current};
}

} // namespace router::ospf
