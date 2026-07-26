// IEEE 802.1D forwarding implementation. Decisions use destination MAC and
// locally learned FDB state only. The switch cannot inspect IP, OSPF state,
// router registries or editor links to infer a destination.

#include "router/ethernet_switch.hpp"

#include <algorithm>
#include <new>

namespace router::lab {
namespace {

[[nodiscard]] packet::Mac mac_at(const packet::Frame &frame,
                                 std::size_t offset) noexcept {
  packet::Mac result{};
  std::copy_n(frame.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              result.size(), result.begin());
  return result;
}

[[nodiscard]] bool group_address(const packet::Mac &address) noexcept {
  return (address[0] & 0x01U) != 0U;
}

} // namespace

EthernetSwitch::EthernetSwitch(
    const device_catalog::EthernetSwitchProfile &profile,
    PacketPool &pool)
    : profile_(profile), pool_(pool) {
  // Construction is outside the packet path. Reserving exact profile bounds
  // prevents source learning from allocating after the switch starts.
  ports_.resize(profile_.port_count);
  fdb_.reserve(profile_.fdb_entries);
}

EthernetSwitch::~EthernetSwitch() {
  // Destruction occurs on the owner shard after forwarding stops. Returning
  // every queued reference keeps the shared packet pool balanced across
  // project replacement and failed restore.
  for (auto &port : ports_) {
    PacketHandle handle{};
    while (port.egress.try_pop(handle))
      pool_.release(handle);
  }
}

bool EthernetSwitch::active(std::uint16_t port) const noexcept {
  return port < ports_.size() &&
         ports_[port].configured &&
         ports_[port].configuration.admin_enabled &&
         ports_[port].configuration.carrier;
}

void EthernetSwitch::flush_port(std::uint16_t port) noexcept {
  std::erase_if(fdb_, [port](const auto &entry) {
    return entry.port == port;
  });
}

bool EthernetSwitch::configure_port(
    std::uint16_t port,
    const SwitchPortConfiguration &configuration) noexcept {
  const auto supported_speed =
      std::find(profile_.supported_speeds_mbps.begin(),
                profile_.supported_speeds_mbps.begin() +
                    profile_.speed_count,
                configuration.speed_mbps) !=
      profile_.supported_speeds_mbps.begin() + profile_.speed_count;
  if (port >= ports_.size() || !supported_speed ||
      configuration.mtu < profile_.minimum_mtu ||
      configuration.mtu > profile_.maximum_mtu)
    return false;
  const bool was_active = active(port);
  ports_[port].configuration = configuration;
  ports_[port].configured = true;
  if (was_active && !active(port)) {
    flush_port(port);
    PacketHandle handle{};
    while (ports_[port].egress.try_pop(handle))
      pool_.release(handle);
  }
  return true;
}

std::optional<SwitchPortConfiguration>
EthernetSwitch::port_configuration(std::uint16_t port) const noexcept {
  if (port >= ports_.size() || !ports_[port].configured)
    return std::nullopt;
  return ports_[port].configuration;
}

SwitchForwardResult EthernetSwitch::ingress(
    std::uint16_t port, const packet::Frame &frame,
    Clock::time_point now) noexcept {
  SwitchForwardResult result{};
  if (!active(port) || frame.size() < packet::ethernet_header_octets ||
      frame.size() > ports_[port].configuration.mtu) {
    result.malformed = frame.size() < packet::ethernet_header_octets;
    return result;
  }
  const auto destination = mac_at(frame, 0U);
  const auto source = mac_at(frame, 6U);

  // IEEE bridges learn only individual source addresses. A station movement
  // atomically replaces its old port and refreshes the same aging deadline.
  if (!group_address(source)) {
    auto learned = std::find_if(fdb_.begin(), fdb_.end(),
                                [&](const auto &entry) {
      return entry.address == source;
    });
    if (learned != fdb_.end()) {
      learned->port = port;
      learned->expires = now + profile_.fdb_aging;
      result.learned_source = true;
    } else if (fdb_.size() < profile_.fdb_entries) {
      try {
        fdb_.push_back({.address = source,
                        .expires = now + profile_.fdb_aging,
                        .port = port});
        result.learned_source = true;
      } catch (const std::bad_alloc &) {
        // Learning failure does not discard a valid frame. It remains an
        // unknown-source frame and follows ordinary destination forwarding.
      }
    }
  }

  std::array<std::uint16_t, device_catalog::maximum_switch_ports> egresses{};
  std::size_t egress_count{};
  bool filtered_to_ingress{};
  if (!group_address(destination)) {
    const auto known = std::find_if(
        fdb_.begin(), fdb_.end(),
        [&](const auto &entry) { return entry.address == destination; });
    if (known != fdb_.end() && active(known->port)) {
      // IEEE 802.1D filtering discards a frame whose learned destination is
      // behind the ingress port. Treating zero selected egresses as "unknown"
      // here would incorrectly flood it back across the broadcast domain.
      filtered_to_ingress = known->port == port;
      if (!filtered_to_ingress)
        egresses[egress_count++] = known->port;
    }
  }
  // A group address or absent active unicast destination floods to every
  // other active port in the one profile-defined broadcast domain.
  if (group_address(destination) ||
      (egress_count == 0U && !filtered_to_ingress))
    for (std::uint16_t candidate{};
         candidate < ports_.size(); ++candidate)
      if (candidate != port && active(candidate))
        egresses[egress_count++] = candidate;

  if (egress_count == 0U)
    return result;
  const auto handle = pool_.allocate(frame);
  if (!handle) {
    result.congested_egresses =
        static_cast<std::uint16_t>(egress_count);
    return result;
  }

  bool first_reference = true;
  for (std::size_t index{}; index < egress_count; ++index) {
    const auto egress = egresses[index];
    // Every queue admits at most the profile's configured depth even though
    // the generated container is sized for the largest switch profile.
    if (ports_[egress].egress.size() >= profile_.queue_frames_per_port) {
      ++result.congested_egresses;
      continue;
    }
    if (!first_reference && !pool_.retain(*handle)) {
      ++result.congested_egresses;
      continue;
    }
    if (!ports_[egress].egress.try_push(*handle)) {
      if (!first_reference)
        pool_.release(*handle);
      ++result.congested_egresses;
      continue;
    }
    first_reference = false;
    ++result.admitted_egresses;
  }
  if (first_reference)
    pool_.release(*handle);
  return result;
}

std::optional<EthernetSwitch::BorrowedFrame>
EthernetSwitch::dequeue(std::uint16_t port) noexcept {
  if (port >= ports_.size())
    return std::nullopt;
  PacketHandle handle{};
  if (!ports_[port].egress.try_pop(handle))
    return std::nullopt;
  return BorrowedFrame{.handle = handle, .frame = &pool_.get(handle)};
}

void EthernetSwitch::age(Clock::time_point now) noexcept {
  std::erase_if(fdb_, [now](const auto &entry) {
    return entry.expires <= now;
  });
}

std::optional<EthernetSwitch::Clock::time_point>
EthernetSwitch::next_deadline() const noexcept {
  if (fdb_.empty())
    return std::nullopt;
  return std::min_element(
             fdb_.begin(), fdb_.end(),
             [](const auto &left, const auto &right) {
               return left.expires < right.expires;
             })
      ->expires;
}

EthernetSwitchCheckpoint
EthernetSwitch::checkpoint(Clock::time_point now) const {
  EthernetSwitchCheckpoint state;
  state.ports.reserve(ports_.size());
  state.fdb.reserve(fdb_.size());
  for (const auto &port : ports_)
    state.ports.push_back(
        {.configuration = port.configuration,
         .configured = port.configured});
  for (const auto &entry : fdb_)
    state.fdb.push_back(
        {.address = entry.address,
         .remaining_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 entry.expires > now ? entry.expires - now
                                     : Clock::duration::zero())
                 .count(),
         .port = entry.port});
  for (std::size_t port{}; port < ports_.size(); ++port)
    for (std::size_t offset{}; offset < ports_[port].egress.size(); ++offset) {
      PacketHandle handle{};
      if (ports_[port].egress.copy_at(offset, handle))
        state.egress.push_back(
            {.frame = pool_.get(handle),
             .port = static_cast<std::uint16_t>(port)});
    }
  return state;
}

bool EthernetSwitch::validate_checkpoint(
    const device_catalog::EthernetSwitchProfile &profile,
    const EthernetSwitchCheckpoint &state) noexcept {
  if (state.ports.size() != profile.port_count ||
      state.fdb.size() > profile.fdb_entries)
    return false;
  std::array<std::size_t, device_catalog::maximum_switch_ports>
      queued_per_port{};
  for (std::size_t port{}; port < state.ports.size(); ++port) {
    const auto &configuration = state.ports[port].configuration;
    if (!state.ports[port].configured) {
      if (configuration != SwitchPortConfiguration{})
        return false;
      continue;
    }
    const auto supported_speed =
        std::find(profile.supported_speeds_mbps.begin(),
                  profile.supported_speeds_mbps.begin() +
                      profile.speed_count,
                  configuration.speed_mbps) !=
        profile.supported_speeds_mbps.begin() + profile.speed_count;
    if (!supported_speed || configuration.mtu < profile.minimum_mtu ||
        configuration.mtu > profile.maximum_mtu)
      return false;
  }
  for (const auto &entry : state.fdb)
    if (entry.port >= profile.port_count ||
        entry.remaining_nanoseconds < 0 ||
        !state.ports[entry.port].configured ||
        !state.ports[entry.port].configuration.admin_enabled ||
        !state.ports[entry.port].configuration.carrier ||
        group_address(entry.address) ||
        std::count_if(state.fdb.begin(), state.fdb.end(),
                      [&](const auto &other) {
                        return other.address == entry.address;
                      }) != 1)
      return false;
  for (const auto &entry : state.egress) {
    if (entry.port >= profile.port_count ||
        entry.frame.size() < packet::ethernet_header_octets ||
        !state.ports[entry.port].configured ||
        entry.frame.size() >
            state.ports[entry.port].configuration.mtu ||
        ++queued_per_port[entry.port] > profile.queue_frames_per_port)
      return false;
  }
  return true;
}

bool EthernetSwitch::restore(const EthernetSwitchCheckpoint &state,
                             Clock::time_point now) noexcept {
  if (!validate_checkpoint(profile_, state))
    return false;
  std::size_t currently_queued{};
  for (const auto &port : ports_)
    currently_queued += port.egress.size();
  if (state.egress.size() > pool_.available() + currently_queued)
    return false;

  // All validation and the packet-pool capacity proof precede mutation. At the
  // barrier no other owner can allocate between the proof and replacement.
  for (auto &port : ports_) {
    PacketHandle handle{};
    while (port.egress.try_pop(handle))
      pool_.release(handle);
  }
  fdb_.clear();
  for (std::size_t port{}; port < ports_.size(); ++port) {
    ports_[port].configuration = state.ports[port].configuration;
    ports_[port].configured = state.ports[port].configured;
  }
  for (const auto &entry : state.fdb)
    fdb_.push_back(
        {.address = entry.address,
         .expires = now +
                    std::chrono::nanoseconds{entry.remaining_nanoseconds},
         .port = entry.port});
  for (const auto &entry : state.egress) {
    const auto handle = pool_.allocate(entry.frame);
    // The capacity proof above makes failure an ownership invariant violation.
    // Preserve noexcept behavior by returning false, while the caller rejects
    // the complete outer checkpoint rather than publishing this switch.
    if (!handle || !ports_[entry.port].egress.try_push(*handle)) {
      if (handle)
        pool_.release(*handle);
      return false;
    }
  }
  return true;
}

} // namespace router::lab
