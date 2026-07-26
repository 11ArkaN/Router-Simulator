// Table-oriented OSPF FSM tests cover interface startup, DR and BDR
// non-preemption, adjacency formation, database synchronization failures and
// teardown. They exercise pure transitions without replacing production time
// with a user-visible simulation clock.

#include "router/ospf_fsm.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_fsm_tests() {
  using namespace router::ospf;

  const auto point_to_point = interface_transition(
      InterfaceState::down, InterfaceEvent::interface_up,
      NetworkType::point_to_point, 1U);
  require(point_to_point.state == InterfaceState::point_to_point &&
              has_action(point_to_point.actions,
                         InterfaceAction::start_hello_timer) &&
              has_action(point_to_point.actions, InterfaceAction::send_hello) &&
              !has_action(point_to_point.actions,
                          InterfaceAction::start_wait_timer),
          "OSPF point-to-point interface startup is incorrect");

  const auto broadcast = interface_transition(
      InterfaceState::down, InterfaceEvent::interface_up,
      NetworkType::broadcast, 1U);
  require(broadcast.state == InterfaceState::waiting &&
              has_action(broadcast.actions,
                         InterfaceAction::start_wait_timer),
          "eligible OSPF broadcast interface did not enter Waiting");
  const auto ineligible = interface_transition(
      InterfaceState::down, InterfaceEvent::interface_up,
      NetworkType::broadcast, 0U);
  require(ineligible.state == InterfaceState::dr_other &&
              !has_action(ineligible.actions,
                          InterfaceAction::start_wait_timer),
          "priority-zero OSPF interface participated in DR waiting");
  const auto waiting_change = interface_transition(
      InterfaceState::waiting, InterfaceEvent::neighbor_change,
      NetworkType::broadcast, 1U);
  const auto wait_expired = interface_transition(
      InterfaceState::waiting, InterfaceEvent::wait_timer,
      NetworkType::broadcast, 1U);
  require(waiting_change.state == InterfaceState::waiting &&
              waiting_change.actions == InterfaceAction::none &&
              has_action(wait_expired.actions,
                         InterfaceAction::elect_dr_bdr),
          "OSPF WaitTimer and NeighborChange semantics diverged");

  const std::array stable_election{
      ElectionRouter{.election_identity = 101U,
                     .router_id = 1U,
                     .declared_dr = 0U,
                     .declared_bdr = 0U,
                     .priority = 1U,
                     .two_way_or_greater = true,
                     .local = true},
      ElectionRouter{.election_identity = 102U,
                     .router_id = 2U,
                     .declared_dr = 0U,
                     .declared_bdr = 102U,
                     .priority = 1U,
                     .two_way_or_greater = true},
      ElectionRouter{.election_identity = 103U,
                     .router_id = 3U,
                     .declared_dr = 103U,
                     .declared_bdr = 0U,
                     .priority = 1U,
                     .two_way_or_greater = true},
      // A later router with a higher ID cannot preempt already declared roles.
      ElectionRouter{.election_identity = 104U,
                     .router_id = 4U,
                     .declared_dr = 0U,
                     .declared_bdr = 0U,
                     .priority = 1U,
                     .two_way_or_greater = true}};
  const auto elected = elect_dr_bdr(stable_election);
  require(elected.designated_router == 103U &&
              elected.backup_designated_router == 102U &&
              elected.local_state == InterfaceState::dr_other,
          "OSPF DR or BDR election became preemptive");

  const std::array local_wins{
      ElectionRouter{.election_identity = 110U,
                     .router_id = 10U,
                     .priority = 100U,
                     .two_way_or_greater = true,
                     .local = true},
      ElectionRouter{.election_identity = 120U,
                     .router_id = 20U,
                     .priority = 1U,
                     .two_way_or_greater = true}};
  const auto local_election = elect_dr_bdr(local_wins);
  require(local_election.designated_router == 110U &&
              local_election.local_state == InterfaceState::designated,
          "OSPF election did not repeat after the local role changed");

  auto neighbor = neighbor_transition(
      NeighborState::down, NeighborEvent::hello_received, true, false);
  require(neighbor.state == NeighborState::init &&
              has_action(neighbor.actions,
                         NeighborAction::reset_inactivity_timer),
          "OSPF Hello did not create an Init neighbor");
  neighbor = neighbor_transition(neighbor.state,
                                 NeighborEvent::two_way_received, true, false);
  require(neighbor.state == NeighborState::exstart &&
              has_action(neighbor.actions,
                         NeighborAction::begin_database_exchange),
          "OSPF required adjacency did not enter ExStart");
  neighbor = neighbor_transition(neighbor.state,
                                 NeighborEvent::negotiation_done, true, false);
  require(neighbor.state == NeighborState::exchange,
          "OSPF DD negotiation did not enter Exchange");
  neighbor = neighbor_transition(neighbor.state,
                                 NeighborEvent::exchange_done, true, true);
  require(neighbor.state == NeighborState::loading &&
              has_action(neighbor.actions,
                         NeighborAction::start_sending_requests),
          "OSPF outstanding requests did not enter Loading");
  neighbor = neighbor_transition(neighbor.state,
                                 NeighborEvent::loading_done, true, false);
  require(neighbor.state == NeighborState::full &&
              has_action(neighbor.actions, NeighborAction::notify_interface),
          "OSPF completed request list did not enter Full");

  const auto mismatch = neighbor_transition(
      NeighborState::full, NeighborEvent::sequence_number_mismatch, true,
      false);
  require(mismatch.state == NeighborState::exstart &&
              has_action(mismatch.actions,
                         NeighborAction::clear_adjacency) &&
              has_action(mismatch.actions,
                         NeighborAction::begin_database_exchange),
          "OSPF sequence mismatch did not restart database exchange");
  const auto no_longer_adjacent = neighbor_transition(
      NeighborState::full, NeighborEvent::adjacency_ok, false, false);
  require(no_longer_adjacent.state == NeighborState::two_way &&
              has_action(no_longer_adjacent.actions,
                         NeighborAction::clear_adjacency),
          "OSPF DR role change retained an unnecessary adjacency");
  const auto one_way = neighbor_transition(
      NeighborState::exchange, NeighborEvent::one_way_received, true, false);
  require(one_way.state == NeighborState::init &&
              has_action(one_way.actions,
                         NeighborAction::clear_adjacency),
          "OSPF one-way Hello did not tear down adjacency state");
  const auto expired = neighbor_transition(
      NeighborState::full, NeighborEvent::inactivity_timer, true, false);
  require(expired.state == NeighborState::down &&
              has_action(expired.actions,
                         NeighborAction::stop_inactivity_timer) &&
              has_action(expired.actions,
                         NeighborAction::notify_interface),
          "OSPF inactivity expiry did not remove the neighbor");
}
