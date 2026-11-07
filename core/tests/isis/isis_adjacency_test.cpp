// Independent fixtures transcribe ISO 10589 tables 5 through 8 in printed
// row/column order. DIS tests cover preemption, startup guards and MAC ties.

#include "router/isis_adjacency.hpp"

#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void isis_adjacency_tests() {
  using namespace router::isis;
  using L = Levels;
  using A = P2pAction;
  using R = AdjacencyReason;
  const std::array<L, 3U> rows{L::level1, L::level2, L::both};
  const std::array<L, 4U> columns{L::none, L::level1, L::both, L::level2};
  const std::array<std::array<A, 2U>, 3U> table5{{
    {A::up, A::accept}, {A::reject, A::down}, {A::up, A::accept}}};
  const std::array<std::array<A, 4U>, 3U> table6{{
    {A::up, A::accept, A::down, A::down},
    {A::up, A::down, A::down, A::accept},
    {A::up, A::down, A::accept, A::down}}};
  const std::array<std::array<A, 3U>, 3U> table7{{
    {A::reject, A::down, A::down}, {A::up, A::down, A::accept}, {A::up, A::down, A::accept}}};
  const std::array<std::array<A, 4U>, 3U> table8{{
    {A::reject, A::down, A::down, A::down},
    {A::up, A::down, A::down, A::accept},
    {A::up, A::down, A::down, A::accept}}};
  const std::array<L, 3U> columns7{L::none, L::both, L::level2};
  for (std::size_t row = 0U; row < rows.size(); ++row) {
    for (std::size_t column = 0U; column < 2U; ++column) {
      const auto decision = p2p_hello_decision(L::level1, rows[row], columns[column], true, true);
      require(decision.action == table5[row][column], "IS-IS ISO table 5 mismatch");
      require(decision.usage == (rows[row] == L::level2 ? L::none : L::level1),
              "IS-IS ISO table 5 usage mismatch");
    }
    for (std::size_t column = 0U; column < columns.size(); ++column) {
      const auto decision = p2p_hello_decision(L::both, rows[row], columns[column], true, true);
      require(decision.action == table6[row][column], "IS-IS ISO table 6 mismatch");
      require(decision.usage == (decision.action == A::down ? L::none : rows[row]),
              "IS-IS ISO table 6 usage mismatch");
      for (const auto local : {L::both, L::level2}) {
        const auto unmatched = p2p_hello_decision(local, rows[row], columns[column], false, false);
        require(unmatched.action == table8[row][column], "IS-IS ISO table 8 mismatch");
        const bool area_reason = row == 0U ? column < 2U : row == 2U && column == 2U;
        const auto reason = unmatched.action == A::up || unmatched.action == A::accept ? R::none :
            area_reason ? R::area_mismatch : R::wrong_system;
        require(unmatched.reason == reason, "IS-IS ISO table 8 event reason mismatch");
      }
    }
    for (std::size_t column = 0U; column < columns7.size(); ++column) {
      const auto decision = p2p_hello_decision(L::level2, rows[row], columns7[column], true, true);
      require(decision.action == table7[row][column], "IS-IS ISO table 7 mismatch");
      require(decision.usage == (decision.action == A::up || decision.action == A::accept ? L::level2 : L::none),
              "IS-IS ISO table 7 usage mismatch");
    }
    require(p2p_hello_decision(L::level1, rows[row], L::none, false, true).action == A::reject &&
              p2p_hello_decision(L::level1, rows[row], L::level1, false, true).reason == R::area_mismatch,
            "IS-IS L1 unmatched area rejection failed");
  }
  require(p2p_hello_decision(L::both, L::both, L::both, true, false).action == A::discard &&
            p2p_hello_decision(L::both, L::none, L::both, true, true).usage == L::both,
          "IS-IS P2P invalid input changed adjacency usage");
  const router::packet::isis::SystemId first{1U, 2U, 3U, 4U, 5U, 6U};
  auto second = first;
  second.back() = 7U;
  require(p2p_circuit_id(first, 1U, second, 2U).back() == 2U &&
            p2p_circuit_id(second, 2U, first, 1U).back() == 2U &&
            p2p_circuit_id(first, 1U, first, 2U).back() == 1U,
          "IS-IS P2P circuit-ID negotiation mismatch");
  const DisLocal local{first, {2U, 0U, 0U, 0U, 0U, 1U}, 64U, 9U};
  std::array<DisNeighbor, 2U> neighbors{{
    {second, {2U, 0U, 0U, 0U, 0U, 2U}, {9U, 8U, 7U, 6U, 5U, 4U, 3U}, 64U, true},
    {second, {2U, 0U, 0U, 0U, 0U, 3U}, {}, 127U, false}}};
  require(!select_dis(local, neighbors, false, true) && !select_dis(local, neighbors, true, false),
          "IS-IS DIS declared before startup/receiver guards");
  auto winner = select_dis(local, neighbors, true, true);
  require(winner && !winner->local && winner->mac == neighbors[0U].mac &&
            winner->lan == neighbors[0U].advertised_lan,
          "IS-IS DIS MAC tie or remote LAN-ID selection failed");
  neighbors[0U].priority = 63U;
  winner = select_dis(local, neighbors, true, true);
  require(winner && winner->local && winner->lan.back() == local.circuit,
          "IS-IS DIS local priority preemption failed");
  auto zero_priority = local;
  zero_priority.priority = 0U;
  neighbors[0U].priority = 0U;
  winner = select_dis(zero_priority, neighbors, true, true);
  require(winner && !winner->local, "IS-IS DIS incorrectly excluded priority zero");
}
