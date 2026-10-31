// Three-way option 240 framing and RFC 5303 3.2 state table. State and timer
// ownership remains in the caller's adjacency process. Verified errata 2587
// and 2588 correct the referenced ISO 10589:2002 section numbers.

#include "router/isis_three_way.hpp"

#include <algorithm>

namespace router::isis {
namespace {
constexpr std::uint8_t option_code = 240U;

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                  std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  for (std::size_t i = 0U; i < 4U; ++i)
    bytes[offset + i] = static_cast<std::uint8_t>(value >> (24U - i * 8U));
}
}

std::optional<ThreeWayOption>
decode_three_way(const packet::isis::TlvView &tlv) noexcept {
  const auto size = tlv.value.size();
  if (tlv.code != option_code || (size != 1U && size != 5U && size != 11U && size != 15U) ||
      tlv.value[0U] > static_cast<std::uint8_t>(ThreeWayState::down))
    return std::nullopt;
  ThreeWayOption result;
  result.state = static_cast<ThreeWayState>(tlv.value[0U]);
  if (size >= 5U)
    result.local_circuit = read32(tlv.value, 1U);
  if (size >= 11U) {
    packet::isis::SystemId system{};
    std::copy_n(tlv.value.begin() + 5U, system.size(), system.begin());
    result.neighbor_system = system;
  }
  if (size == 15U)
    result.neighbor_circuit = read32(tlv.value, 11U);
  return result;
}

bool encode_three_way(packet::isis::TlvWriter &writer,
                       const ThreeWayOption &option) noexcept {
  if (option.state > ThreeWayState::down ||
      (option.neighbor_system && !option.local_circuit) ||
      (option.neighbor_circuit && !option.neighbor_system))
    return false;
  std::array<std::uint8_t, 15U> bytes{};
  bytes[0U] = static_cast<std::uint8_t>(option.state);
  std::size_t length = 1U;
  if (option.local_circuit) {
    write32(bytes, 1U, *option.local_circuit);
    length = 5U;
  }
  if (option.neighbor_system) {
    std::copy(option.neighbor_system->begin(), option.neighbor_system->end(), bytes.begin() + 5U);
    length = 11U;
  }
  if (option.neighbor_circuit) {
    write32(bytes, 11U, *option.neighbor_circuit);
    length = 15U;
  }
  return writer.append(option_code, std::span(bytes).first(length));
}

ThreeWayDecision
three_way_receive(ThreeWayState current, const packet::isis::SystemId &local_system,
                  std::uint32_t local_circuit, bool iso_accepted,
                  std::optional<packet::isis::TlvView> option) noexcept {
  const auto discard = ThreeWayDecision{ThreeWayAction::discard, current};
  if (!iso_accepted || current > ThreeWayState::down)
    return discard;
  if (!option)
    return {ThreeWayAction::legacy, current};
  const auto decoded = decode_three_way(*option);
  if (!decoded || (decoded->neighbor_system && *decoded->neighbor_system != local_system) ||
      (decoded->neighbor_circuit && *decoded->neighbor_circuit != local_circuit))
    return discard;
  // Source: ietf.isis.three_way.rfc5303. Rows and columns use the encoded enum
  // order Up, Initializing, Down. The ISO adjacency state is not overwritten
  // with this table's three-way state, even when Initialize emits no event.
  using Action = ThreeWayAction;
  constexpr std::array<std::array<Action, 3U>, 3U> actions{{
    {Action::accept, Action::accept, Action::initialize},
    {Action::up, Action::up, Action::initialize},
    {Action::down, Action::up, Action::initialize}}};
  const auto action = actions[static_cast<std::size_t>(current)][static_cast<std::size_t>(decoded->state)];
  switch (action) {
  case Action::initialize: return {action, ThreeWayState::initializing};
  case Action::up: return {action, ThreeWayState::up};
  case Action::down: return {action, ThreeWayState::down};
  default: return {action, current};
  }
}

} // namespace router::isis
