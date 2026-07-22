// RFC 7383 tests cover out-of-order arrival, exact duplicates, conflicting
// duplicates, profile capacities and timeout disposal of retained plaintext.

#include "router/ikev2_fragmentation.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

void ikev2_fragmentation_tests() {
  using namespace router::ikev2;
  using namespace std::chrono_literals;
  FragmentAssembler assembler{4U, 32U, 2s};
  const FragmentSetKey key{.initiator_spi = 1U,
                           .responder_spi = 2U,
                           .message_id = 3U,
                           .response = false};
  const auto now = FragmentAssembler::Clock::time_point{100s};
  std::array<std::uint8_t, 32U> output{};
  const std::array<std::uint8_t, 2U> second{3U, 4U};
  if (assembler.accept(key, 2U, 2U, 0U, second, now, output).status !=
      FragmentAcceptStatus::stored)
    throw std::runtime_error("out-of-order IKEv2 fragment was rejected");
  if (assembler.accept(key, 2U, 2U, 0U, second, now, output).status !=
      FragmentAcceptStatus::duplicate)
    throw std::runtime_error("exact IKEv2 fragment duplicate was rejected");
  const std::array<std::uint8_t, 2U> first{1U, 2U};
  const auto completed = assembler.accept(key, 1U, 2U, 33U, first, now, output);
  if (completed.status != FragmentAcceptStatus::complete ||
      completed.assembled_octets != 4U || completed.first_payload != 33U ||
      output[0U] != 1U || output[1U] != 2U || output[2U] != 3U ||
      output[3U] != 4U || assembler.active())
    throw std::runtime_error("IKEv2 fragment reassembly order failed");

  if (assembler.accept(key, 1U, 2U, 33U, first, now, output).status !=
      FragmentAcceptStatus::stored)
    throw std::runtime_error("IKEv2 fragment set restart failed");
  const std::array<std::uint8_t, 2U> conflict{9U, 9U};
  if (assembler.accept(key, 1U, 2U, 33U, conflict, now, output).status !=
          FragmentAcceptStatus::conflicting_duplicate ||
      assembler.active())
    throw std::runtime_error("conflicting IKEv2 duplicate was retained");

  if (assembler.accept(key, 1U, 2U, 33U, first, now, output).status !=
      FragmentAcceptStatus::stored)
    throw std::runtime_error("IKEv2 timeout test setup failed");
  if (assembler.accept(key, 2U, 2U, 0U, second, now + 2s, output).status !=
          FragmentAcceptStatus::expired ||
      assembler.active())
    throw std::runtime_error("expired IKEv2 fragment set survived");

  if (assembler.accept(key, 1U, 5U, 33U, first, now, output).status !=
      FragmentAcceptStatus::invalid)
    throw std::runtime_error("profile fragment capacity was ignored");
}
