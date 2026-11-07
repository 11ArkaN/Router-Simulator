// Cold LAN admission checks one logical identity before constructing either
// level. Each contained circuit remains its neighbor/timer/DIS state owner.
// No update database, runtime queue or foreign device is read here.

#include "router/isis_lan_circuit_pair.hpp"

#include <stdexcept>
#include <utility>

namespace router::isis {
namespace {
bool same_identity(const LanCircuitConfiguration &a, const LanCircuitConfiguration &b) noexcept {
  return a.local.system == b.local.system && a.local.mac == b.local.mac && a.local.circuit == b.local.circuit &&
      a.mac == b.mac && a.areas == b.areas && a.protocols == b.protocols &&
      a.ipv4_addresses == b.ipv4_addresses && a.ipv6_addresses == b.ipv6_addresses &&
      a.maximum_area_addresses == b.maximum_area_addresses && a.maximum_pdu_octets == b.maximum_pdu_octets &&
      a.instance_format == b.instance_format && a.wire_instance == b.wire_instance && a.emit_instance == b.emit_instance &&
      a.instance_topologies == b.instance_topologies && a.update_destinations == b.update_destinations;
}
}
LanCircuitPair::LanCircuitPair(LanCircuitProgram program, std::uint64_t seed,
    LanCircuit::Clock::time_point now) {
  const auto mask = static_cast<Levels>((program.levels[0U] ? 1U : 0U) | (program.levels[1U] ? 2U : 0U));
  if (mask == Levels::none || !seed) throw std::invalid_argument("Empty or unseeded IS-IS LAN program");
  const auto &common = program.levels[0U] ? *program.levels[0U] : *program.levels[1U];
  for (std::size_t level{}; level < program.levels.size(); ++level) if (program.levels[level]) {
    const auto &entry = *program.levels[level];
    const auto expected = level ? packet::isis::PduType::lan_hello_l2 : packet::isis::PduType::lan_hello_l1;
    if (entry.type != expected || entry.levels != mask || !entry.local.circuit || !entry.limits.neighbors ||
        !entry.update_destinations || !same_identity(common, entry))
      throw std::invalid_argument("Inconsistent IS-IS LAN level identity");
  }
  for (std::size_t level{}; level < program.levels.size(); ++level) if (program.levels[level]) {
    auto level_seed = seed ^ static_cast<std::uint64_t>(level + 1U);
    if (!level_seed) level_seed = seed;
    circuits_[level].emplace(std::move(*program.levels[level]), level_seed, now);
  }
}
LanCircuit *LanCircuitPair::at(std::size_t level) noexcept {
  return level < circuits_.size() && circuits_[level] ? &*circuits_[level] : nullptr;
}
const LanCircuit *LanCircuitPair::at(std::size_t level) const noexcept {
  return level < circuits_.size() && circuits_[level] ? &*circuits_[level] : nullptr;
}
const LanCircuitConfiguration &LanCircuitPair::common() const noexcept {
  return (circuits_[0U] ? *circuits_[0U] : *circuits_[1U]).configuration();
}
Levels LanCircuitPair::levels() const noexcept {
  return static_cast<Levels>((circuits_[0U] ? 1U : 0U) | (circuits_[1U] ? 2U : 0U));
}
bool LanCircuitPair::matches(const LanCircuitProgram &program) const noexcept {
  for (std::size_t level{}; level < circuits_.size(); ++level)
    if (circuits_[level].has_value() != program.levels[level].has_value() ||
        (circuits_[level] && circuits_[level]->configuration() != *program.levels[level])) return false;
  return true;
}
} // namespace router::isis
