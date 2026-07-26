// OSPF Hello compatibility, neighbor liveness and owner-local deadline logic.
// This module never sends to a peer directly. Encoded output is passed to the
// forwarding shard, which supplies IP, Ethernet, queue and link processing.

#include "router/ospf_interface.hpp"

#include <algorithm>
#include <limits>
#include <new>

namespace router::ospf {
namespace {

void write16(std::span<std::uint8_t> output, std::size_t offset,
             std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write24(std::span<std::uint8_t> output, std::size_t offset,
             std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 2U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> output, std::size_t offset,
             std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

void record_neighbor_event(NeighborRuntime &neighbor, NeighborEvent event,
                           const NeighborTransition &transition,
                           RuntimeClock::time_point now) noexcept {
  // One helper owns all management accounting for the RFC 2328 neighbor FSM.
  // Keeping accounting beside the accepted transition prevents show output
  // from guessing counters from the current state and makes every event path
  // use identical restart semantics.
  const auto previous = neighbor.state;
  ++neighbor.event_count;
  neighbor.last_event_at = now;
  if (event == NeighborEvent::bad_link_state_request)
    ++neighbor.bad_link_state_requests;
  if (event == NeighborEvent::sequence_number_mismatch)
    ++neighbor.bad_sequence_numbers;
  if ((event == NeighborEvent::one_way_received ||
       event == NeighborEvent::inactivity_timer ||
       event == NeighborEvent::lower_layer_down) &&
      previous >= NeighborState::exstart)
    ++neighbor.bad_neighbor_states;
  if (transition.state != previous)
    neighbor.state_since = now;
  if (transition.state == NeighborState::exstart &&
      previous >= NeighborState::exstart) {
    ++neighbor.restart_count;
    neighbor.last_restart_at = now;
  }
  neighbor.state = transition.state;
}

} // namespace

InterfaceRuntime::InterfaceRuntime(InterfaceConfiguration configuration,
                                   std::size_t maximum_neighbors,
                                   RuntimeClock::time_point now)
    : configuration_(configuration), maximum_neighbors_(maximum_neighbors) {
  neighbors_.reserve(maximum_neighbors_);
  if (!validate_configuration(configuration_))
    return;
  if (!configuration_.enabled)
    return;
  const auto transition =
      interface_transition(InterfaceState::down,
                           InterfaceEvent::interface_up,
                           configuration_.network_type,
                           configuration_.router_priority);
  state_ = transition.state;
  // An NBMA interface cannot use AllSPFRouters. Its configured transport
  // peers own independent Hello and PollInterval deadlines in InstanceProcess,
  // while this FSM still owns election and neighbor inactivity timers.
  if (!configuration_.passive &&
      configuration_.network_type != NetworkType::non_broadcast)
    hello_deadline_ = now;
  if (has_action(transition.actions, InterfaceAction::start_wait_timer))
    wait_deadline_ =
        now + std::chrono::seconds{configuration_.dead_interval_seconds};
}

bool InterfaceRuntime::validate_configuration(
    const InterfaceConfiguration &configuration) noexcept {
  return (configuration.version == packet::ospf::version_two ||
          configuration.version == packet::ospf::version_three) &&
         configuration.router_id != 0U &&
         configuration.hello_interval_seconds != 0U &&
         configuration.dead_interval_seconds != 0U &&
         configuration.dead_interval_seconds >
             configuration.hello_interval_seconds &&
         configuration.interface_mtu != 0U &&
         (configuration.version == packet::ospf::version_three ||
          configuration.instance_id == 0U);
}

bool InterfaceRuntime::adjacency_required(
    const NeighborRuntime &neighbor) const noexcept {
  if (configuration_.network_type == NetworkType::point_to_point ||
      configuration_.network_type == NetworkType::point_to_multipoint ||
      configuration_.network_type == NetworkType::virtual_link)
    return true;
  return state_ == InterfaceState::designated ||
         state_ == InterfaceState::backup ||
         neighbor.election_identity == designated_router_ ||
         neighbor.election_identity == backup_designated_router_;
}

HelloResult InterfaceRuntime::receive_hello(
    const packet::ospf::PacketView &packet,
    std::uint32_t neighbor_election_identity,
    RuntimeClock::time_point now) noexcept {
  HelloResult result{};
  if (!configuration_.enabled || configuration_.passive ||
      state_ == InterfaceState::down ||
      state_ == InterfaceState::loopback) {
    result.disposition = HelloDisposition::interface_down;
    return result;
  }
  if (packet.router_id == configuration_.router_id ||
      neighbor_election_identity == 0U) {
    result.disposition = HelloDisposition::self;
    return result;
  }
  if (packet.area_id != configuration_.area_id) {
    result.disposition = HelloDisposition::area_mismatch;
    return result;
  }
  if (packet.version != configuration_.version ||
      (packet.version == packet::ospf::version_three &&
       packet.instance_id != configuration_.instance_id)) {
    result.disposition = HelloDisposition::instance_mismatch;
    return result;
  }
  const auto hello = packet::ospf::parse_hello(packet);
  if (!hello) {
    result.disposition = HelloDisposition::malformed;
    return result;
  }
  if (hello->hello_interval_seconds !=
          configuration_.hello_interval_seconds ||
      hello->dead_interval_seconds !=
          configuration_.dead_interval_seconds) {
    result.disposition = HelloDisposition::timer_mismatch;
    return result;
  }
  if (packet.version == packet::ospf::version_two &&
      hello->network_mask != configuration_.network_mask &&
      configuration_.network_type != NetworkType::point_to_point &&
      configuration_.network_type != NetworkType::virtual_link) {
    result.disposition = HelloDisposition::network_mask_mismatch;
    return result;
  }
  // The E-bit must agree for ordinary, stub and NSSA area compatibility. Other
  // optional capability bits may differ and are negotiated by later packet
  // processing rather than causing a simulator-wide exact-options check.
  if ((hello->options &
       packet::ospf::option_external_routing_capability) !=
      (configuration_.options &
       packet::ospf::option_external_routing_capability)) {
    result.disposition = HelloDisposition::options_mismatch;
    return result;
  }
  if (packet.version == packet::ospf::version_three &&
      configuration_.instance_id != 0U &&
      (configuration_.options & packet::ospf::option_address_family) != 0U &&
      (hello->options & packet::ospf::option_address_family) == 0U) {
    // RFC 5838 section 2.4 requires a non-base AF-capable instance to discard
    // Hellos without the AF bit. Instance zero is the explicit compatibility
    // exception and therefore never reaches this rejection branch.
    result.disposition = HelloDisposition::options_mismatch;
    return result;
  }

  auto found = std::find_if(neighbors_.begin(), neighbors_.end(),
                            [&](const auto &neighbor) {
    return neighbor.router_id == packet.router_id;
  });
  if (found == neighbors_.end()) {
    if (neighbors_.size() == maximum_neighbors_) {
      result.disposition = HelloDisposition::neighbor_capacity_exhausted;
      return result;
    }
    try {
      neighbors_.push_back(NeighborRuntime{.router_id = packet.router_id,
                                           .state_since = now});
      found = std::prev(neighbors_.end());
    } catch (const std::bad_alloc &) {
      result.disposition = HelloDisposition::neighbor_capacity_exhausted;
      return result;
    }
  }

  const auto previous_priority = found->priority;
  const auto previous_designated = found->designated_router;
  const auto previous_backup = found->backup_designated_router;
  const bool first_hello = found->state == NeighborState::down;

  // Store the value from the accepted wire packet before advancing the FSM.
  // Deriving it from our port ordinal would describe the wrong router and
  // produces a Router-LSA that cannot be joined to the peer's link tuple.
  if (packet.version == packet::ospf::version_three)
    found->interface_id = hello->interface_id;
  found->election_identity = neighbor_election_identity;
  found->priority = hello->router_priority;
  found->designated_router = hello->designated_router;
  found->backup_designated_router = hello->backup_designated_router;
  found->options = hello->options;
  if (state_ == InterfaceState::waiting) {
    // The Hello DR and BDR fields contain an IPv4 interface address in OSPFv2
    // and a Router ID in OSPFv3. Compare against the version-normalized wire
    // identity, never packet.router_id unconditionally.
    const bool sender_is_backup =
        hello->backup_designated_router == neighbor_election_identity;
    const bool sender_is_only_designated =
        hello->designated_router == neighbor_election_identity &&
        hello->backup_designated_router == 0U;
    result.backup_seen = sender_is_backup || sender_is_only_designated;
  }
  found->inactivity_deadline =
      now + std::chrono::seconds{configuration_.dead_interval_seconds};
  auto transition = neighbor_transition(
      found->state, NeighborEvent::hello_received,
      adjacency_required(*found), false);
  record_neighbor_event(*found, NeighborEvent::hello_received, transition,
                        now);
  result.actions = transition.actions;

  bool seen_self{};
  for (std::size_t index{}; index < hello->neighbors.size() / 4U; ++index)
    if (packet::ospf::hello_neighbor(*hello, index) ==
        configuration_.router_id) {
      seen_self = true;
      break;
    }
  transition = neighbor_transition(
      found->state,
      seen_self ? NeighborEvent::two_way_received
                : NeighborEvent::one_way_received,
      adjacency_required(*found), false);
  record_neighbor_event(
      *found,
      seen_self ? NeighborEvent::two_way_received
                : NeighborEvent::one_way_received,
      transition, now);
  result.actions = result.actions | transition.actions;
  if (!first_hello &&
      (previous_priority != found->priority ||
       previous_designated != found->designated_router ||
       previous_backup != found->backup_designated_router)) {
    // RFC 2328 sections 9.2 and 10.5 require NeighborChange when an accepted
    // Hello changes priority or the neighbor's DR/BDR declarations. Merely
    // resetting the inactivity timer leaves every DROther with the election
    // result it computed before the elected DR announced the final BDR.
    result.actions =
        result.actions | NeighborAction::notify_interface;
  }
  result.disposition = HelloDisposition::accepted;
  result.state = found->state;
  result.neighbor_router_id = found->router_id;
  return result;
}

bool InterfaceRuntime::process_deadlines(RuntimeClock::time_point now,
                                         std::span<ExpiredNeighbor> output,
                                         std::size_t &written) noexcept {
  written = 0U;
  for (auto &neighbor : neighbors_) {
    if (neighbor.state == NeighborState::down ||
        neighbor.inactivity_deadline > now)
      continue;
    if (written == output.size())
      return false;
    const auto transition =
        neighbor_transition(neighbor.state,
                            NeighborEvent::inactivity_timer,
                            adjacency_required(neighbor), false);
    record_neighbor_event(neighbor, NeighborEvent::inactivity_timer,
                          transition, now);
    neighbor.inactivity_deadline = {};
    output[written++] = {.router_id = neighbor.router_id,
                         .actions = transition.actions};
  }
  return true;
}

bool InterfaceRuntime::defer_inactivity(
    std::uint32_t router_id,
    RuntimeClock::time_point deadline) noexcept {
  const auto found = std::find_if(
      neighbors_.begin(), neighbors_.end(),
      [router_id](const auto &neighbor) {
        return neighbor.router_id == router_id;
      });
  if (found == neighbors_.end() ||
      found->state == NeighborState::down ||
      deadline == RuntimeClock::time_point{})
    return false;
  if (found->inactivity_deadline < deadline)
    found->inactivity_deadline = deadline;
  return true;
}

InterfaceAction InterfaceRuntime::process_interface_deadline(
    RuntimeClock::time_point now) noexcept {
  if (state_ != InterfaceState::waiting ||
      wait_deadline_ == RuntimeClock::time_point{} ||
      wait_deadline_ > now)
    return InterfaceAction::none;
  wait_deadline_ = {};
  const auto transition =
      interface_transition(state_, InterfaceEvent::wait_timer,
                           configuration_.network_type,
                           configuration_.router_priority);
  return apply_election(transition.actions);
}

InterfaceAction
InterfaceRuntime::neighbor_change(bool backup_seen) noexcept {
  if (configuration_.network_type != NetworkType::broadcast &&
      configuration_.network_type != NetworkType::non_broadcast)
    return InterfaceAction::none;
  const auto transition = interface_transition(
      state_,
      backup_seen ? InterfaceEvent::backup_seen
                  : InterfaceEvent::neighbor_change,
      configuration_.network_type, configuration_.router_priority);
  if (backup_seen)
    wait_deadline_ = {};
  return apply_election(transition.actions);
}

InterfaceAction
InterfaceRuntime::apply_election(InterfaceAction requested) noexcept {
  if (!has_action(requested, InterfaceAction::elect_dr_bdr))
    return requested;

  const auto old_state = state_;
  const auto old_designated = designated_router_;
  const auto old_backup = backup_designated_router_;
  static_cast<void>(elect());
  const bool changed = old_state != state_ ||
                       old_designated != designated_router_ ||
                       old_backup != backup_designated_router_;
  if (!changed)
    return requested;

  // A changed local role or selected transit router changes the local
  // Router-LSA. A Network-LSA must be originated or flushed whenever this
  // router enters or leaves DR state. The process owner performs the actual
  // MinLSInterval-controlled origination after it reconciles adjacencies.
  requested = requested | InterfaceAction::originate_router_lsa;
  if (old_state == InterfaceState::designated ||
      state_ == InterfaceState::designated)
    requested = requested | InterfaceAction::originate_network_lsa;
  return requested;
}

bool InterfaceRuntime::reconcile_adjacencies(
    std::span<NeighborReconciliation> output,
    std::size_t &written) noexcept {
  written = 0U;
  // The operation is deliberately all-or-nothing. Partially reconciling a
  // broadcast segment would expose an election generation in which some
  // neighbors use the old DR/BDR result and others use the new one.
  if (output.size() < neighbors_.size())
    return false;
  const auto now = RuntimeClock::now();
  for (auto &neighbor : neighbors_) {
    const auto transition =
        neighbor_transition(neighbor.state, NeighborEvent::adjacency_ok,
                            adjacency_required(neighbor), false);
    record_neighbor_event(neighbor, NeighborEvent::adjacency_ok, transition,
                          now);
    if (transition.actions == NeighborAction::none)
      continue;
    output[written++] = {.router_id = neighbor.router_id,
                         .actions = transition.actions};
  }
  return true;
}

std::optional<RuntimeClock::time_point>
InterfaceRuntime::next_deadline() const noexcept {
  std::optional<RuntimeClock::time_point> result;
  if (configuration_.enabled && !configuration_.passive &&
      configuration_.network_type != NetworkType::non_broadcast)
    result = hello_deadline_;
  if (state_ == InterfaceState::waiting &&
      wait_deadline_ != RuntimeClock::time_point{} &&
      (!result || wait_deadline_ < *result))
    result = wait_deadline_;
  for (const auto &neighbor : neighbors_) {
    if (neighbor.state == NeighborState::down)
      continue;
    if (!result || neighbor.inactivity_deadline < *result)
      result = neighbor.inactivity_deadline;
  }
  return result;
}

bool InterfaceRuntime::hello_due(RuntimeClock::time_point now) const noexcept {
  return configuration_.enabled && !configuration_.passive &&
         configuration_.network_type != NetworkType::non_broadcast &&
         state_ != InterfaceState::down &&
         state_ != InterfaceState::loopback && hello_deadline_ <= now;
}

void InterfaceRuntime::hello_sent(RuntimeClock::time_point now) noexcept {
  hello_deadline_ =
      now + std::chrono::seconds{configuration_.hello_interval_seconds};
}

std::optional<std::span<const std::uint8_t>>
InterfaceRuntime::encode_hello_payload(
    std::span<std::uint8_t> output) const noexcept {
  constexpr std::size_t fixed_octets = 20U;
  const auto advertised_neighbors = static_cast<std::size_t>(std::count_if(
      neighbors_.begin(), neighbors_.end(), [](const auto &neighbor) {
        return neighbor.state != NeighborState::down &&
               neighbor.state != NeighborState::attempt;
      }));
  const auto required = fixed_octets + advertised_neighbors * 4U;
  if (!configuration_.enabled || configuration_.passive ||
      output.size() < required ||
      advertised_neighbors >
          (std::numeric_limits<std::uint16_t>::max() - fixed_octets) / 4U)
    return std::nullopt;
  auto payload = output.first(required);
  std::fill(payload.begin(), payload.end(), std::uint8_t{0U});
  if (configuration_.version == packet::ospf::version_two) {
    write32(payload, 0U, configuration_.network_mask);
    write16(payload, 4U, configuration_.hello_interval_seconds);
    payload[6U] = static_cast<std::uint8_t>(configuration_.options);
    payload[7U] = configuration_.router_priority;
    write32(payload, 8U, configuration_.dead_interval_seconds);
  } else {
    write32(payload, 0U, configuration_.interface_id);
    payload[4U] = configuration_.router_priority;
    write24(payload, 5U, configuration_.options);
    write16(payload, 8U, configuration_.hello_interval_seconds);
    write16(payload, 10U, configuration_.dead_interval_seconds);
  }
  write32(payload, 12U, designated_router_);
  write32(payload, 16U, backup_designated_router_);
  std::size_t output_index{};
  for (const auto &neighbor : neighbors_)
    if (neighbor.state != NeighborState::down &&
        neighbor.state != NeighborState::attempt)
      write32(payload, fixed_octets + output_index++ * 4U,
              neighbor.router_id);
  return std::span<const std::uint8_t>{payload};
}

std::optional<NeighborTransition>
InterfaceRuntime::apply_neighbor_event(std::uint32_t router_id,
                                       NeighborEvent event,
                                       bool requests_pending) noexcept {
  const auto found =
      std::find_if(neighbors_.begin(), neighbors_.end(),
                   [router_id](const auto &neighbor) {
                     return neighbor.router_id == router_id;
                   });
  if (found == neighbors_.end())
    return std::nullopt;
  const auto transition =
      neighbor_transition(found->state, event, adjacency_required(*found),
                          requests_pending);
  record_neighbor_event(*found, event, transition, RuntimeClock::now());
  if (has_action(transition.actions, NeighborAction::stop_inactivity_timer))
    found->inactivity_deadline = {};
  return transition;
}

bool InterfaceRuntime::erase_neighbor(std::uint32_t router_id) noexcept {
  const auto found =
      std::find_if(neighbors_.begin(), neighbors_.end(),
                   [router_id](const auto &neighbor) {
                     return neighbor.router_id == router_id;
                   });
  if (found == neighbors_.end())
    return false;
  neighbors_.erase(found);
  return true;
}

DrBdrElection InterfaceRuntime::elect() noexcept {
  // One local row plus the bounded neighbor repository is allocated only when
  // an election event occurs. It remains control-plane work and never enters
  // the packet path or a shared-memory structure.
  std::vector<ElectionRouter> candidates;
  try {
    candidates.reserve(neighbors_.size() + 1U);
    candidates.push_back(
        {.election_identity =
             configuration_.version == packet::ospf::version_two
                 ? configuration_.local_election_identity
                 : configuration_.router_id,
         .router_id = configuration_.router_id,
         .declared_dr = designated_router_,
         .declared_bdr = backup_designated_router_,
         .priority = configuration_.router_priority,
         .two_way_or_greater = true,
         .local = true});
    for (const auto &neighbor : neighbors_)
      candidates.push_back(
          {.election_identity = neighbor.election_identity,
           .router_id = neighbor.router_id,
           .declared_dr = neighbor.designated_router,
           .declared_bdr = neighbor.backup_designated_router,
           .priority = neighbor.priority,
           .two_way_or_greater = neighbor.state >= NeighborState::two_way,
           .local = false});
  } catch (const std::bad_alloc &) {
    // Keeping the prior roles is safer than publishing an election over a
    // truncated candidate set. The next neighbor event or WaitTimer retry can
    // run the complete election after memory pressure subsides.
    return {.designated_router = designated_router_,
            .backup_designated_router = backup_designated_router_,
            .local_state = state_};
  }
  const auto result = elect_dr_bdr(candidates);
  set_election_result(result);
  return result;
}

InterfaceRuntimeCheckpoint
InterfaceRuntime::checkpoint(RuntimeClock::time_point now) const {
  const auto remaining = [now](RuntimeClock::time_point deadline) {
    if (deadline == RuntimeClock::time_point{} || deadline <= now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
  };
  const auto elapsed = [now](RuntimeClock::time_point point) {
    if (point == RuntimeClock::time_point{} || point > now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - point);
  };
  InterfaceRuntimeCheckpoint result{
      .configuration = configuration_,
      .neighbors = neighbors_,
      .hello_remaining = remaining(hello_deadline_),
      .wait_remaining = remaining(wait_deadline_),
      .state = state_,
      .designated_router = designated_router_,
      .backup_designated_router = backup_designated_router_};
  // Absolute steady-clock epochs are process-local and meaningless after a
  // restore. Reuse the field as an exact remaining duration in milliseconds
  // inside the detached checkpoint value.
  for (auto &neighbor : result.neighbors) {
    const auto duration = remaining(neighbor.inactivity_deadline);
    neighbor.inactivity_deadline =
        RuntimeClock::time_point{duration};
    neighbor.state_since = RuntimeClock::time_point{
        elapsed(neighbor.state_since)};
    neighbor.last_event_at = RuntimeClock::time_point{
        elapsed(neighbor.last_event_at)};
    neighbor.last_restart_at = RuntimeClock::time_point{
        elapsed(neighbor.last_restart_at)};
  }
  return result;
}

bool InterfaceRuntime::restore(
    const InterfaceRuntimeCheckpoint &checkpoint,
    RuntimeClock::time_point now) noexcept {
  if (checkpoint.configuration != configuration_ ||
      checkpoint.neighbors.size() > maximum_neighbors_ ||
      checkpoint.hello_remaining < std::chrono::milliseconds{} ||
      checkpoint.wait_remaining < std::chrono::milliseconds{})
    return false;
  try {
    auto staged = checkpoint.neighbors;
    for (std::size_t index{}; index < staged.size(); ++index) {
      auto &neighbor = staged[index];
      const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              neighbor.inactivity_deadline.time_since_epoch());
      const auto state_elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              neighbor.state_since.time_since_epoch());
      const auto event_elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              neighbor.last_event_at.time_since_epoch());
      const auto restart_elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              neighbor.last_restart_at.time_since_epoch());
      if (remaining < std::chrono::milliseconds{} ||
          state_elapsed < std::chrono::milliseconds{} ||
          event_elapsed < std::chrono::milliseconds{} ||
          restart_elapsed < std::chrono::milliseconds{} ||
          neighbor.router_id == 0U ||
          std::any_of(staged.begin(), staged.begin() +
                                         static_cast<std::ptrdiff_t>(index),
                      [&](const auto &prior) {
                        return prior.router_id == neighbor.router_id;
                      }))
        return false;
      neighbor.inactivity_deadline =
          remaining == std::chrono::milliseconds{}
              ? RuntimeClock::time_point{}
              : now + remaining;
      neighbor.state_since =
          state_elapsed == std::chrono::milliseconds{}
              ? RuntimeClock::time_point{}
              : now - state_elapsed;
      neighbor.last_event_at =
          event_elapsed == std::chrono::milliseconds{}
              ? RuntimeClock::time_point{}
              : now - event_elapsed;
      neighbor.last_restart_at =
          restart_elapsed == std::chrono::milliseconds{}
              ? RuntimeClock::time_point{}
              : now - restart_elapsed;
    }
    neighbors_.swap(staged);
    hello_deadline_ =
        checkpoint.hello_remaining == std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now + checkpoint.hello_remaining;
    wait_deadline_ =
        checkpoint.wait_remaining == std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now + checkpoint.wait_remaining;
    state_ = checkpoint.state;
    designated_router_ = checkpoint.designated_router;
    backup_designated_router_ = checkpoint.backup_designated_router;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
