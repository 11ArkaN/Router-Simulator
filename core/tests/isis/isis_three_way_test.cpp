// RFC 5303 option and transition-table fixtures. Test-owned values cover every
// table cell, legacy fallback, identity rejection and optional-field boundaries.

#include "router/isis_three_way.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
}

void isis_three_way_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  const SystemId local{1U, 2U, 3U, 4U, 5U, 6U};
  constexpr std::uint32_t circuit = 0x11223344U;
  std::array<std::uint8_t, 32U> bytes{};
  TlvWriter writer(bytes);
  require(encode_three_way(writer, {ThreeWayState::initializing, 0xaabbccddU, local, circuit}),
           "IS-IS three-way option encoding failed");
  const std::array<std::uint8_t, 17U> fixture{240U, 15U, 1U, 0xaaU, 0xbbU, 0xccU, 0xddU,
    1U, 2U, 3U, 4U, 5U, 6U, 0x11U, 0x22U, 0x33U, 0x44U};
  require(std::equal(writer.bytes().begin(), writer.bytes().end(), fixture.begin(), fixture.end()),
           "IS-IS three-way wire fixture mismatch");
  TlvCursor cursor(writer.bytes());
  auto wire = cursor.next();
  const auto decoded = decode_three_way(*wire);
  require(decoded && decoded->local_circuit == 0xaabbccddU && decoded->neighbor_system == local &&
            decoded->neighbor_circuit == circuit, "IS-IS three-way identity projection mismatch");

  using State = ThreeWayState;
  using Action = ThreeWayAction;
  // Fixture order follows the printed RFC table: Down, Initializing, Up.
  const std::array<State, 3U> states{State::down, State::initializing, State::up};
  const std::array<std::array<Action, 3U>, 3U> expected{{
    {Action::initialize, Action::up, Action::down},
    {Action::initialize, Action::up, Action::up},
    {Action::initialize, Action::accept, Action::accept}}};
  for (std::size_t row = 0U; row < states.size(); ++row) {
    for (std::size_t col = 0U; col < states.size(); ++col) {
      bytes[2U] = static_cast<std::uint8_t>(states[col]);
      const auto decision = three_way_receive(states[row], local, circuit, true, wire);
      require(decision.action == expected[row][col], "IS-IS three-way transition table mismatch");
      if (decision.action == Action::initialize)
        require(decision.next_state == State::initializing, "IS-IS three-way Initialize state mismatch");
      if (decision.action == Action::up)
        require(decision.next_state == State::up, "IS-IS three-way Up state mismatch");
    }
  }
  bytes[2U] = 1U;
  bytes[7U] ^= 1U;
  require(three_way_receive(State::up, local, circuit, true, wire).action == Action::discard,
           "IS-IS three-way accepted another neighbor system");
  bytes[7U] ^= 1U;
  bytes[16U] ^= 1U;
  require(three_way_receive(State::up, local, circuit, true, wire).action == Action::discard,
           "IS-IS three-way accepted another neighbor circuit");
  bytes[16U] ^= 1U;
  bytes[2U] = 3U;
  require(three_way_receive(State::up, local, circuit, true, wire).action == Action::discard,
           "IS-IS invalid three-way state accepted");
  require(three_way_receive(State::down, local, circuit, true, std::nullopt).action == Action::legacy,
           "IS-IS three-way legacy fallback missing");
  require(three_way_receive(State::up, local, circuit, false, std::nullopt).action == Action::discard,
           "IS-IS three-way bypassed base ISO rejection");
  for (std::size_t length = 0U; length <= 16U; ++length) {
    bytes[2U] = 2U;
    const auto option = decode_three_way({240U, std::span(bytes).subspan(2U, length)});
    require(option.has_value() == (length == 1U || length == 5U || length == 11U || length == 15U),
             "IS-IS three-way accepted a partial optional field");
  }
  TlvWriter invalid(bytes);
  require(!encode_three_way(invalid, {State::up, {}, local, circuit}) && invalid.bytes().empty(),
           "IS-IS three-way emitted fields with missing predecessor");
}
