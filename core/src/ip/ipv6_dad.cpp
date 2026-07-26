// RFC 4862 Duplicate Address Detection state transitions. Timers use the host
// monotonic clock and remain local to the forwarding owner.

#include "router/ipv6_dad.hpp"

#include <algorithm>

namespace router::lab {

std::chrono::nanoseconds ipv6_interface_initial_delay(
    std::uint64_t scope_id, const ip::Ipv6 &address,
    std::chrono::steady_clock::time_point now,
    std::chrono::nanoseconds maximum) noexcept {
  // FNV-1a is used only to spread deadlines inside the RFC-defined random
  // window. It is not a security primitive or an IID generator. Including the
  // local scope, address and current steady-clock sample prevents synchronized
  // NS bursts without shared PRNG state between forwarding owners.
  constexpr std::uint64_t fnv_offset_basis = 1469598103934665603ULL;
  constexpr std::uint64_t fnv_prime = 1099511628211ULL;
  std::uint64_t mixed = fnv_offset_basis;
  for (const auto byte : address) {
    mixed ^= byte;
    mixed *= fnv_prime;
  }
  mixed ^= scope_id;
  mixed *= fnv_prime;
  mixed ^= static_cast<std::uint64_t>(now.time_since_epoch().count());
  return maximum.count() == 0
             ? std::chrono::nanoseconds::zero()
             : std::chrono::nanoseconds{static_cast<std::int64_t>(
                   mixed % (static_cast<std::uint64_t>(maximum.count()) +
                            1U))};
}

Ipv6DadTable::Entry *Ipv6DadTable::entry(
    std::uint64_t interface_id, const ip::Ipv6 &address) noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(),
                                  [&](const Entry &candidate) {
                                    return candidate.valid &&
                                           candidate.interface_id ==
                                               interface_id &&
                                           candidate.address == address;
                                  });
  return found == entries_.end() ? nullptr : &*found;
}

const Ipv6DadTable::Entry *Ipv6DadTable::entry(
    std::uint64_t interface_id, const ip::Ipv6 &address) const noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(),
                                  [&](const Entry &candidate) {
                                    return candidate.valid &&
                                           candidate.interface_id ==
                                               interface_id &&
                                           candidate.address == address;
                                  });
  return found == entries_.end() ? nullptr : &*found;
}

bool Ipv6DadTable::configure(
    std::uint64_t interface_id, std::uint16_t port_ordinal,
    const ip::Ipv6 &address,
    std::uint8_t transmit_limit, std::chrono::nanoseconds initial_delay,
    Clock::time_point now) noexcept {
  if (interface_id == 0U ||
      port_ordinal >= device_catalog::maximum_ports_per_router ||
      ip::is_unspecified(address) || ip::is_multicast(address) ||
      initial_delay < std::chrono::nanoseconds::zero())
    return false;
  if (entry(interface_id, address))
    return true;
  const auto available = std::find_if(entries_.begin(), entries_.end(),
                                      [](const Entry &candidate) {
                                        return !candidate.valid;
                                      });
  if (available == entries_.end())
    return false;
  *available = {.valid = true,
                .interface_id = interface_id,
                .port_ordinal = port_ordinal,
                .address = address,
                .state = transmit_limit ? Ipv6DadState::tentative
                                        : Ipv6DadState::preferred,
                .transmit_limit = transmit_limit,
                .deadline = transmit_limit ? now + initial_delay
                                           : Clock::time_point::max()};
  return true;
}

void Ipv6DadTable::remove(std::uint64_t interface_id,
                          const ip::Ipv6 &address) noexcept {
  if (auto *candidate = entry(interface_id, address))
    *candidate = {};
}

void Ipv6DadTable::remove_interface(std::uint64_t interface_id) noexcept {
  for (auto &candidate : entries_)
    if (candidate.valid && candidate.interface_id == interface_id)
      candidate = {};
}

void Ipv6DadTable::remove_physical_port(
    std::uint16_t port_ordinal) noexcept {
  // Hardware removal invalidates every logical service attached to the wire.
  // This physical lifecycle operation is intentionally separate from an L3
  // interface deletion, which must not disturb sibling SAPs on the same port.
  for (auto &candidate : entries_)
    if (candidate.valid && candidate.port_ordinal == port_ordinal)
      candidate = {};
}

bool Ipv6DadTable::observe_conflict(std::uint64_t interface_id,
                                    const ip::Ipv6 &target) noexcept {
  auto *candidate = entry(interface_id, target);
  if (!candidate || candidate->state != Ipv6DadState::tentative)
    return false;
  candidate->state = Ipv6DadState::duplicate;
  candidate->deadline = Clock::time_point::max();
  return true;
}

bool Ipv6DadTable::preferred(std::uint64_t interface_id,
                             const ip::Ipv6 &address) const noexcept {
  const auto *candidate = entry(interface_id, address);
  return candidate && candidate->state == Ipv6DadState::preferred;
}

std::optional<Ipv6DadSnapshot>
Ipv6DadTable::find(std::uint64_t interface_id,
                   const ip::Ipv6 &address) const noexcept {
  const auto *candidate = entry(interface_id, address);
  if (!candidate)
    return std::nullopt;
  return Ipv6DadSnapshot{.interface_id = candidate->interface_id,
                         .address = candidate->address,
                         .state = candidate->state,
                         .probes_sent = candidate->probes_sent};
}

std::size_t Ipv6DadTable::poll(
    Clock::time_point now, std::span<Ipv6DadAction> output) noexcept {
  std::size_t written{};
  for (auto &candidate : entries_) {
    if (!candidate.valid || candidate.state != Ipv6DadState::tentative ||
        candidate.deadline > now)
      continue;
    if (candidate.probes_sent >= candidate.transmit_limit) {
      // DAD succeeds only after one complete RetransTimer interval following
      // the last NS, leaving time for a conflicting NA to return on the link.
      candidate.state = Ipv6DadState::preferred;
      candidate.deadline = Clock::time_point::max();
      continue;
    }
    if (written == output.size())
      break;
    output[written++] = {.interface_id = candidate.interface_id,
                         .port_ordinal = candidate.port_ordinal,
                         .target = candidate.address};
    ++candidate.probes_sent;
    candidate.deadline = now + device_catalog::nd_retrans_timer;
  }
  return written;
}

std::optional<Ipv6DadTable::Clock::time_point>
Ipv6DadTable::next_deadline() const noexcept {
  auto result = Clock::time_point::max();
  for (const auto &candidate : entries_)
    if (candidate.valid && candidate.deadline < result)
      result = candidate.deadline;
  return result == Clock::time_point::max()
             ? std::nullopt
             : std::optional<Clock::time_point>{result};
}

std::vector<Ipv6DadCheckpoint>
Ipv6DadTable::checkpoint(Clock::time_point now) const {
  std::vector<Ipv6DadCheckpoint> result;
  for (const auto &candidate : entries_) {
    if (!candidate.valid)
      continue;
    const bool has_deadline = candidate.deadline != Clock::time_point::max();
    const auto remaining = has_deadline && candidate.deadline > now
                               ? candidate.deadline - now
                               : Clock::duration::zero();
    result.push_back({
        .interface_id = candidate.interface_id,
        .port_ordinal = candidate.port_ordinal,
        .address = candidate.address,
        .state = candidate.state,
        .probes_sent = candidate.probes_sent,
        .transmit_limit = candidate.transmit_limit,
        .has_deadline = has_deadline,
        .remaining_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                .count()});
  }
  return result;
}

bool Ipv6DadTable::validate_checkpoint(
    std::span<const Ipv6DadCheckpoint> state) noexcept {
  if (state.size() > capacity)
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &candidate = state[index];
    const bool tentative = candidate.state == Ipv6DadState::tentative;
    if (candidate.interface_id == 0U ||
        candidate.port_ordinal >=
            device_catalog::maximum_ports_per_router ||
        ip::is_unspecified(candidate.address) ||
        ip::is_multicast(candidate.address) ||
        candidate.state > Ipv6DadState::duplicate ||
        candidate.remaining_nanoseconds < 0 ||
        (tentative != candidate.has_deadline) ||
        candidate.probes_sent > candidate.transmit_limit ||
        (candidate.state == Ipv6DadState::preferred &&
         candidate.probes_sent < candidate.transmit_limit))
      return false;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (state[previous].interface_id == candidate.interface_id &&
          state[previous].address == candidate.address)
        return false;
  }
  return true;
}

bool Ipv6DadTable::restore(std::span<const Ipv6DadCheckpoint> state,
                           Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  entries_.fill({});
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &source = state[index];
    entries_[index] = {
        .valid = true,
        .interface_id = source.interface_id,
        .port_ordinal = source.port_ordinal,
        .address = source.address,
        .state = source.state,
        .probes_sent = source.probes_sent,
        .transmit_limit = source.transmit_limit,
        .deadline = source.has_deadline
                        ? now + std::chrono::nanoseconds(
                                    source.remaining_nanoseconds)
                        : Clock::time_point::max()};
  }
  return true;
}

} // namespace router::lab
