// OSPF neighbor exchange, LSDB maintenance and route recalculation.
// InstanceProcess owns database state; forwarding and topology remain external.

#include "ospf_process_internal.hpp"

namespace router::ospf {

InstanceProcess::NeighborExchange *
InstanceProcess::exchange(InterfaceOwner &owner, std::uint32_t router_id,
                          bool create) noexcept {
  const auto found = std::find_if(
      owner.exchanges.begin(), owner.exchanges.end(),
      [&](const auto &candidate) { return candidate.router_id == router_id; });
  if (found != owner.exchanges.end())
    return &*found;
  if (!create ||
      owner.exchanges.size() == maximum_neighbors_per_interface_)
    return nullptr;
  try {
    owner.exchanges.emplace_back(router_id, maximum_lsas_);
    return &owner.exchanges.back();
  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

bool InstanceProcess::advertised_full(
    const InterfaceOwner &owner, std::uint32_t router_id,
    RuntimeClock::time_point now) const noexcept {
  const auto runtime = std::find_if(
      owner.runtime.neighbors().begin(),
      owner.runtime.neighbors().end(),
      [router_id](const auto &neighbor) {
        return neighbor.router_id == router_id;
      });
  if (runtime != owner.runtime.neighbors().end() &&
      runtime->state == NeighborState::full)
    return true;
  const auto control = std::find_if(
      owner.exchanges.begin(), owner.exchanges.end(),
      [router_id](const auto &neighbor) {
        return neighbor.router_id == router_id;
      });
  return control != owner.exchanges.end() && control->helper_active &&
         control->helper_deadline > now;
}

void InstanceProcess::terminate_grace_helpers(
    RuntimeClock::time_point now) noexcept {
  bool changed{};
  for (auto &owner : interfaces_)
    for (auto &neighbor : owner.exchanges)
      if (neighbor.helper_active) {
        neighbor.helper_active = false;
        neighbor.helper_deadline = {};
        neighbor.helper_was_designated_router = false;
        changed = true;
      }
  // RFC 3623 section 3.2 requires the router and, when applicable, network LSA
  // to be reoriginated after strict topology checking terminates helper mode.
  if (changed)
    schedule_local_origination(now);
}

void InstanceProcess::schedule_local_origination(
    RuntimeClock::time_point now) noexcept {
  // RFC 2328 MinLSInterval is the absolute lower bound. SR OS additionally
  // applies its sourced lsa-generate initial, second and doubling waits.
  // Startup has no previous generation and can originate immediately.
  auto requested = now;
  if (last_local_origination_ != RuntimeClock::time_point{}) {
    const auto minimum =
        last_local_origination_ +
        device_catalog::ospf_min_lsa_interval;
    if (now - last_local_origination_ >= current_lsa_delay_) {
      // A quiet interval resets the adaptive hold-down and permits the
      // topology change to use only the RFC minimum that has already elapsed.
      current_lsa_delay_ = lsa_initial_wait_;
      requested = std::max(now, minimum);
    } else {
      requested = std::max(
          minimum, last_local_origination_ + current_lsa_delay_);
      current_lsa_delay_ =
          current_lsa_delay_ == lsa_initial_wait_
              ? lsa_second_wait_
              : std::min(current_lsa_delay_ * 2,
                         lsa_maximum_wait_);
    }
  }
  if (local_origination_deadline_ == RuntimeClock::time_point{} ||
      requested < local_origination_deadline_)
    local_origination_deadline_ = requested;
}

void InstanceProcess::schedule_spf(RuntimeClock::time_point now) noexcept {
  // SR OS exposes initial, second and maximum SPF waits. After the second
  // calculation, each failure inside the active hold-down doubles the
  // previous wait. Adding a constant here would converge increasingly slowly
  // and contradict the release command reference.
  if (last_spf_started_ == RuntimeClock::time_point{} ||
      now - last_spf_started_ >= spf_maximum_wait_)
    current_spf_delay_ = spf_initial_wait_;
  else
    current_spf_delay_ =
        current_spf_delay_ == spf_initial_wait_
            ? spf_second_wait_
            : std::min(current_spf_delay_ * 2,
                       spf_maximum_wait_);
  const auto requested = now + current_spf_delay_;
  if (spf_deadline_ == RuntimeClock::time_point{} ||
      requested < spf_deadline_)
    spf_deadline_ = requested;
}

bool InstanceProcess::self_sequence_supported(
    const LsaKey &key) const noexcept {
  using namespace packet::ospf::lsa;
  if (key.advertising_router != router_id_)
    return false;
  const auto router_type =
      version_ == packet::ospf::version_two
          ? version_two_router_type
          : version_three_router_type;
  if (key.type == router_type)
    return true;
  const auto router_information_type =
      version_ == packet::ospf::version_two
          ? version_two_area_opaque_type
          : version_three_router_information_type;
  const auto router_information_id =
      version_ == packet::ospf::version_two
          ? static_cast<std::uint32_t>(
                version_two_router_information_opaque_type)
                << 24U
          : 0U;
  if (key.type == router_information_type &&
      key.link_state_id == router_information_id)
    return true;
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_intra_area_prefix_type) {
    if (key.link_state_id == 0U)
      return true;
    return std::any_of(
        interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
          return owner.configuration.protocol.interface_id ==
                 key.link_state_id;
        });
  }
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_link_type)
    return std::any_of(
        interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
          return owner.configuration.protocol.interface_id ==
                 key.link_state_id;
        });
  if (std::any_of(coordinator_lsas_.begin(), coordinator_lsas_.end(),
                  [&](const auto &state) { return state.key == key; }))
    return true;
  if (key.type != version_two_network_type &&
      key.type != version_three_network_type)
    return false;
  return std::any_of(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return version_ == packet::ospf::version_two
                   ? owner.configuration.protocol.local_election_identity ==
                         key.link_state_id
                   : owner.configuration.protocol.interface_id ==
                         key.link_state_id;
      });
}

bool InstanceProcess::set_self_sequence(
    const LsaKey &key, std::int32_t sequence,
    bool wrap_pending) noexcept {
  using namespace packet::ospf::lsa;
  auto update = [&](std::int32_t &value, bool &at_max,
                    bool &pending) {
    // A completed wrap is the only legal sequence reset. Ordinary fight-back
    // can only raise the next generation, never move it backwards.
    value = pending && !wrap_pending ? sequence
                                    : std::max(value, sequence);
    at_max = false;
    pending = wrap_pending;
    return true;
  };
  const auto router_type =
      version_ == packet::ospf::version_two
          ? version_two_router_type
          : version_three_router_type;
  if (key.type == router_type)
    return update(router_lsa_sequence_, router_sequence_at_max_,
                  router_sequence_wrap_pending_);
  const auto router_information_type =
      version_ == packet::ospf::version_two
          ? version_two_area_opaque_type
          : version_three_router_information_type;
  const auto router_information_id =
      version_ == packet::ospf::version_two
          ? static_cast<std::uint32_t>(
                version_two_router_information_opaque_type)
                << 24U
          : 0U;
  if (key.type == router_information_type &&
      key.link_state_id == router_information_id)
    return update(router_information_lsa_sequence_,
                  router_information_sequence_at_max_,
                  router_information_sequence_wrap_pending_);
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_intra_area_prefix_type &&
      key.link_state_id == 0U)
    return update(prefix_lsa_sequence_, prefix_sequence_at_max_,
                  prefix_sequence_wrap_pending_);
  for (auto &owner : interfaces_) {
    const auto interface_identity =
        version_ == packet::ospf::version_two
            ? owner.configuration.protocol.local_election_identity
            : owner.configuration.protocol.interface_id;
    if (key.type == (version_ == packet::ospf::version_two
                         ? version_two_network_type
                         : version_three_network_type) &&
        key.link_state_id == interface_identity)
      return update(owner.network_lsa_sequence,
                    owner.network_sequence_at_max,
                    owner.network_sequence_wrap_pending);
    if (version_ == packet::ospf::version_three &&
        key.type == version_three_intra_area_prefix_type &&
        key.link_state_id ==
            owner.configuration.protocol.interface_id)
      return update(owner.network_prefix_lsa_sequence,
                    owner.network_prefix_sequence_at_max,
                    owner.network_prefix_sequence_wrap_pending);
    if (version_ == packet::ospf::version_three &&
        key.type == version_three_link_type &&
        key.link_state_id ==
            owner.configuration.protocol.interface_id)
      return update(owner.link_lsa_sequence,
                    owner.link_sequence_at_max,
                    owner.link_sequence_wrap_pending);
  }
  const auto coordinator = std::find_if(
      coordinator_lsas_.begin(), coordinator_lsas_.end(),
      [&](const auto &state) { return state.key == key; });
  if (coordinator != coordinator_lsas_.end())
    return update(coordinator->sequence,
                  coordinator->sequence_at_max,
                  coordinator->sequence_wrap_pending);
  return false;
}

bool InstanceProcess::queue_fight_back(
    std::span<const std::uint8_t> encoded_lsa,
    const packet::ospf::LsaHeaderView &header,
    RuntimeClock::time_point now) noexcept {
  const auto key = lsa_key(header);
  const auto found = std::find_if(
      pending_fight_backs_.begin(), pending_fight_backs_.end(),
      [&](const auto &pending) { return pending.key == key; });
  try {
    if (found != pending_fight_backs_.end()) {
      const auto queued =
          packet::ospf::lsa_header(found->bytes, version_);
      if (queued &&
          compare_lsa_headers(header, *queued) != LsaRecency::newer)
        return true;
      found->bytes.assign(encoded_lsa.begin(), encoded_lsa.end());
    } else {
      if (pending_fight_backs_.size() == maximum_lsas_)
        return false;
      PendingFightBack pending{.key = key, .bytes = {}};
      pending.bytes.assign(encoded_lsa.begin(), encoded_lsa.end());
      pending_fight_backs_.push_back(std::move(pending));
    }
    // Fight-back is a self-origination and therefore shares MinLSInterval
    // with topology-driven local LSA changes. The pending wire image remains
    // owner-local until that deadline.
    schedule_local_origination(now);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::apply_pending_fight_backs(
    RuntimeClock::time_point now, bool &wrap_started) noexcept {
  wrap_started = false;
  for (auto &pending : pending_fight_backs_) {
    auto header = packet::ospf::lsa_header(pending.bytes, version_);
    if (!header)
      return false;
    const auto *current = database_.find(pending.key);
    if (current) {
      auto current_header =
          packet::ospf::lsa_header(current->bytes, version_);
      if (!current_header)
        return false;
      current_header->age_seconds = current->age(now);
      if (compare_lsa_headers(*header, *current_header) !=
          LsaRecency::newer)
        continue;
    }

    const bool supported = self_sequence_supported(pending.key);
    if (supported &&
        header->sequence_number != maximum_sequence_number) {
      if (!set_self_sequence(pending.key,
                             header->sequence_number + 1, false))
        return false;
      continue;
    }

    // An unsupported self-originated LSA describes state this router no
    // longer originates and is flushed at the received sequence. A supported
    // MaxSequenceNumber collision follows the same flush, then waits for
    // reliable removal before restarting at InitialSequenceNumber.
    pending.bytes[0U] =
        static_cast<std::uint8_t>(max_age_seconds >> 8U);
    pending.bytes[1U] = static_cast<std::uint8_t>(max_age_seconds);
    const auto installed = database_.install(
        pending.bytes, version_, now, router_id_, false);
    if (installed != InstallResult::installed &&
        installed != InstallResult::identical)
      return false;
    if (!database_.premature_age(pending.key, now))
      return false;
    const auto *flush = database_.find(pending.key);
    if (!flush || !flood_record(*flush, now))
      return false;

    if (!supported)
      continue;
    if (!set_self_sequence(pending.key, initial_sequence_number,
                           true))
      return false;
    if (std::find(pending_sequence_wraps_.begin(),
                  pending_sequence_wraps_.end(),
                  pending.key) == pending_sequence_wraps_.end())
      pending_sequence_wraps_.push_back(pending.key);
    wrap_started = true;
  }
  pending_fight_backs_.clear();
  return true;
}

void InstanceProcess::complete_sequence_wrap(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  const auto pending = std::find(pending_sequence_wraps_.begin(),
                                 pending_sequence_wraps_.end(), key);
  if (pending == pending_sequence_wraps_.end())
    return;
  if (set_self_sequence(key, initial_sequence_number, false)) {
    pending_sequence_wraps_.erase(pending);
    // Restart only after the MaxAge generation is absent from this LSDB and
    // every adjacency retransmission list. This is the sequence-wrap ordering
    // required by RFC 2328 sections 12.1.6 and 14.1.
    schedule_local_origination(now);
  }
}

bool InstanceProcess::start_sequence_wrap(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  if (!database_.premature_age(key, now))
    return false;
  const auto *flush = database_.find(key);
  if (!flush || !flood_record(*flush, now) ||
      !set_self_sequence(key, initial_sequence_number, true))
    return false;
  if (std::find(pending_sequence_wraps_.begin(),
                pending_sequence_wraps_.end(),
                key) == pending_sequence_wraps_.end())
    pending_sequence_wraps_.push_back(key);
  return true;
}

bool InstanceProcess::flush_exhausted_sequences(
    RuntimeClock::time_point now, bool &wrap_started) noexcept {
  using namespace packet::ospf::lsa;
  wrap_started = false;
  if (router_sequence_at_max_) {
    const LsaKey key{
        .link_state_id =
            version_ == packet::ospf::version_two ? router_id_ : 0U,
        .advertising_router = router_id_,
        .type = version_ == packet::ospf::version_two
                    ? version_two_router_type
                    : version_three_router_type,
        .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  if (version_ == packet::ospf::version_three &&
      prefix_sequence_at_max_) {
    const LsaKey key{.link_state_id = 0U,
                     .advertising_router = router_id_,
                     .type = version_three_intra_area_prefix_type,
                     .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  if (router_information_sequence_at_max_) {
    const LsaKey key{
        .link_state_id =
            version_ == packet::ospf::version_two
                ? static_cast<std::uint32_t>(
                      version_two_router_information_opaque_type)
                      << 24U
                : 0U,
        .advertising_router = router_id_,
        .type = version_ == packet::ospf::version_two
                    ? version_two_area_opaque_type
                    : version_three_router_information_type,
        .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  for (auto &owner : interfaces_) {
    const auto interface_id =
        owner.configuration.protocol.interface_id;
    const auto network_id =
        version_ == packet::ospf::version_two
            ? owner.configuration.protocol.local_election_identity
            : interface_id;
    if (owner.network_sequence_at_max) {
      const LsaKey key{
          .link_state_id = network_id,
          .advertising_router = router_id_,
          .type = version_ == packet::ospf::version_two
                      ? version_two_network_type
                      : version_three_network_type,
          .scope = FloodingScope::area};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
    if (version_ == packet::ospf::version_three &&
        owner.network_prefix_sequence_at_max) {
      const LsaKey key{.link_state_id = interface_id,
                       .advertising_router = router_id_,
                       .type = version_three_intra_area_prefix_type,
                       .scope = FloodingScope::area};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
    if (version_ == packet::ospf::version_three &&
        owner.link_sequence_at_max) {
      const LsaKey key{.link_state_id = interface_id,
                       .advertising_router = router_id_,
                       .type = version_three_link_type,
                       .scope = FloodingScope::link};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
  }
  for (auto &state : coordinator_lsas_) {
    if (!state.sequence_at_max)
      continue;
    if (!start_sequence_wrap(state.key, now))
      return false;
    wrap_started = true;
  }
  return true;
}

bool InstanceProcess::flood_record(const LsaRecord &record,
                                   RuntimeClock::time_point now,
                                   std::optional<std::uint32_t>
                                       link_interface) noexcept {
  // Every eligible Full adjacency receives the same immutable LSDB instance.
  // Queueing a key and generation does not copy or synthesize a neighbor LSA.
  for (auto &owner : interfaces_) {
    if (link_interface &&
        owner.configuration.protocol.interface_id != *link_interface)
      continue;
    for (auto &candidate : owner.exchanges) {
      // RFC 2328 section 15 and RFC 5340 section 4.7 forbid AS-scope
      // flooding over virtual adjacencies. The filter lives beside reliable
      // queueing so originations, refreshes and MaxAge flushes all obey it.
      if (owner.configuration.protocol.network_type ==
              NetworkType::virtual_link &&
          record.key.scope == FloodingScope::autonomous_system)
        continue;
      const auto neighbor = std::find_if(
          owner.runtime.neighbors().begin(), owner.runtime.neighbors().end(),
          [&](const auto &item) {
            return item.router_id == candidate.router_id;
          });
      if (neighbor == owner.runtime.neighbors().end() ||
          !advertised_full(owner, candidate.router_id, now))
        continue;
      if (!candidate.database.queue_retransmission(record, version_, now))
        return false;
      candidate.pending_update = true;
      candidate.update_retransmit_deadline = now;
    }
  }
  if (record.age(now) == max_age_seconds &&
      !database_.mark_max_age_flooded(record.key))
    return false;
  return true;
}

bool InstanceProcess::max_age_removal_safe(
    const LsaKey &key) const noexcept {
  for (const auto &owner : interfaces_) {
    // RFC 2328 section 14 keeps every MaxAge LSA while any neighbor is still
    // synchronizing its database. Such a neighbor may need the flush even if
    // this particular key is not yet visible on its retransmission list.
    if (std::any_of(owner.runtime.neighbors().begin(),
                    owner.runtime.neighbors().end(),
                    [](const auto &neighbor) {
                      return neighbor.state == NeighborState::exchange ||
                             neighbor.state == NeighborState::loading;
                    }))
      return false;
    if (std::any_of(owner.exchanges.begin(), owner.exchanges.end(),
                    [&](const auto &neighbor) {
                      return neighbor.database.retransmits(key);
                    }))
      return false;
  }
  return true;
}

bool InstanceProcess::maintain_database(
    RuntimeClock::time_point now) noexcept {
  bool topology_changed{};
  std::size_t index{};
  while (index < database_.records().size()) {
    const auto &sample = database_.records()[index];
    const auto key = sample.key;
    const auto age = sample.age(now);
    const bool self_originated =
        key.advertising_router == router_id_;
    const auto next_checksum_age = static_cast<std::uint16_t>(
        (sample.last_checksum_check_age /
             checksum_check_age_seconds +
         1U) *
        checksum_check_age_seconds);
    if (age < max_age_seconds &&
        next_checksum_age <= max_age_seconds &&
        age >= next_checksum_age &&
        !database_.verify_checksum_at(key, now))
      return false;

    // RFC 2328 section 12.4 refreshes reachable self-originated LSAs at
    // LSRefreshTime. The existing MinLSInterval scheduler collapses records
    // that became due in the same owner turn into one coherent local
    // generation without bypassing the five-second origination guard.
    if (self_originated &&
        age >= device_catalog::ospf_lsa_refresh.count() &&
        age < max_age_seconds)
      schedule_local_origination(now);

    if (age == max_age_seconds && !sample.max_age_flooded) {
      // Freeze the encoded record at MaxAge before queueing it. LSU emission
      // still adds interface transmit delay with a MaxAge clamp, while the
      // LSDB checksum remains valid because LS age is excluded.
      if (!database_.premature_age(key, now))
        return false;
      const auto *flush = database_.find(key);
      if (!flush || !flood_record(*flush, now))
        return false;
      topology_changed = true;
    }

    const auto *current = database_.find(key);
    if (current && current->age(now) == max_age_seconds &&
        current->max_age_flooded && max_age_removal_safe(key)) {
      // erase() compacts the bounded vector, so retain the same index and
      // inspect the record that moved into this slot. No iterator or pointer
      // survives the mutation.
      if (!database_.erase(key))
        return false;
      complete_sequence_wrap(key, now);
      const auto coordinator = std::find_if(
          coordinator_lsas_.begin(), coordinator_lsas_.end(),
          [&](const auto &state) { return state.key == key; });
      if (coordinator != coordinator_lsas_.end() &&
          coordinator->withdrawing &&
          !coordinator->sequence_wrap_pending)
        coordinator_lsas_.erase(coordinator);
      topology_changed = true;
      continue;
    }
    ++index;
  }
  if (topology_changed)
    schedule_spf(now);
  return true;
}

std::optional<RuntimeClock::time_point>
InstanceProcess::database_deadline() const noexcept {
  std::optional<RuntimeClock::time_point> earliest;
  const auto retain_earlier = [&](RuntimeClock::time_point candidate) {
    if (!earliest || candidate < *earliest)
      earliest = candidate;
  };
  for (const auto &record : database_.records()) {
    if (record.age_at_install == max_age_seconds) {
      // An unflooded MaxAge record is immediately ready. A flooded one wakes
      // on an ACK or neighbor-state event instead of spinning continuously.
      if (!record.max_age_flooded)
        retain_earlier(record.installed_at);
      continue;
    }
    const auto next_checksum_age = static_cast<std::uint16_t>(
        (record.last_checksum_check_age /
             checksum_check_age_seconds +
         1U) *
        checksum_check_age_seconds);
    if (next_checksum_age <= max_age_seconds)
      retain_earlier(
          record.installed_at +
          std::chrono::seconds{
              next_checksum_age - record.age_at_install});
    if (record.key.advertising_router == router_id_ &&
        record.age_at_install <
            device_catalog::ospf_lsa_refresh.count())
      retain_earlier(
          record.installed_at +
          (device_catalog::ospf_lsa_refresh -
           std::chrono::seconds{record.age_at_install}));
    retain_earlier(
        record.installed_at +
        (device_catalog::ospf_lsa_max_age -
         std::chrono::seconds{record.age_at_install}));
  }
  return earliest;
}

bool InstanceProcess::append_route_input(
    const CalculatedRoute &route, const CalculatedNextHop &next_hop,
    bool loop_free_alternate,
    std::vector<lab::routing::DynamicInput> &ipv4,
    std::vector<lab::routing::Ipv6DynamicInput> &ipv6) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &item) {
        if (route.version_three)
          return item.configuration.protocol.interface_id ==
                 next_hop.topology.local_interface;
        const auto &address = item.configuration.ipv4_source;
        const auto encoded =
            static_cast<std::uint32_t>(address[0U]) << 24U |
            static_cast<std::uint32_t>(address[1U]) << 16U |
            static_cast<std::uint32_t>(address[2U]) << 8U | address[3U];
        return encoded == next_hop.topology.local_interface;
      });
  if (owner == interfaces_.end() ||
      owner->configuration.physical_port_ordinal == no_physical_port)
    return false;

  const bool external =
      route.path_type == lab::routing::OspfPathType::external_type_1 ||
      route.path_type == lab::routing::OspfPathType::external_type_2 ||
      route.path_type == lab::routing::OspfPathType::nssa_type_1 ||
      route.path_type == lab::routing::OspfPathType::nssa_type_2;
  const auto preference = static_cast<std::uint16_t>(
      external ? external_preference_ : router_preference_);
  try {
    if (!route.version_three) {
      ipv4.push_back(
          {.configured = true,
           .operational = true,
           .network = route.version_two_network,
           .next_hop = next_hop.topology.version_two_next_hop,
           .port_ordinal = owner->configuration.physical_port_ordinal,
           .preference = preference,
           .metric = route.metric,
           .prefix_length = route.prefix_length,
           .source = lab::routing::RouteSource::ospf,
           .ospf_path_type = route.path_type,
           .internal_metric = route.internal_metric,
           .area_id = route.area_id,
           .tag = route.tag,
           .protocol_instance = instance_id_,
           .loop_free_alternate = loop_free_alternate});
      return true;
    }
    if (!route.ipv4_address_family) {
      // The OSPFv3 Interface ID is a 32-bit router-local value carried on the
      // wire by RFC 5340. It is not the forwarding interface identity. Native
      // IPv6 RIB, ND, PMTU and source-address selection share the disjoint
      // 64-bit identity defined by interface_identity.hpp. Publishing the wire
      // ID here made the route visible in OSPF show output while the FIB could
      // not associate its link-local next hop with the physical interface.
      ipv6.push_back(
          {.configured = true,
           .operational = true,
           .network = route.version_three_network,
           .next_hop = next_hop.version_three_link_local,
           .interface_id = lab::physical_interface_id(
               owner->configuration.physical_port_ordinal),
           .physical_port_ordinal =
               owner->configuration.physical_port_ordinal,
           .preference = preference,
           .metric = route.metric,
           .prefix_length = route.prefix_length,
           .source = lab::routing::RouteSource::ospf3,
           .ospf_path_type = route.path_type,
           .internal_metric = route.internal_metric,
           .area_id = route.area_id,
           .tag = route.tag,
           .protocol_instance = instance_id_,
           .loop_free_alternate = loop_free_alternate});
      return true;
    }

    // RFC 5838 section 2.5 places the IPv4 Direct Interface Address in the
    // first 32 bits of the Link-LSA address field and requires the remaining
    // 96 bits to be zero. The parser has already enforced that representation.
    const auto &encoded = next_hop.version_three_link_local;
    const auto network =
        static_cast<std::uint32_t>(route.version_three_network[0U]) << 24U |
        static_cast<std::uint32_t>(route.version_three_network[1U]) << 16U |
        static_cast<std::uint32_t>(route.version_three_network[2U]) << 8U |
        route.version_three_network[3U];
    const auto forwarding =
        static_cast<std::uint32_t>(encoded[0U]) << 24U |
        static_cast<std::uint32_t>(encoded[1U]) << 16U |
        static_cast<std::uint32_t>(encoded[2U]) << 8U | encoded[3U];
    ipv4.push_back(
        {.configured = true,
         .operational = true,
         .network = network,
         .next_hop = forwarding,
         .port_ordinal = owner->configuration.physical_port_ordinal,
         .preference = preference,
         .metric = route.metric,
         .prefix_length = route.prefix_length,
         .source = lab::routing::RouteSource::ospf3,
         .ospf_path_type = route.path_type,
         .internal_metric = route.internal_metric,
         .area_id = route.area_id,
         .tag = route.tag,
         .protocol_instance = instance_id_,
         .loop_free_alternate = loop_free_alternate});
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::recalculate_routes(
    RuntimeClock::time_point now) noexcept {
  if (!topology_.build(database_.records(), version_, router_id_)) {
    route_recalculation_status_ =
        RouteRecalculationStatus::topology_rejected;
    return false;
  }
  const auto graph = topology_.graph();
  if (!spf_.calculate(graph.root_vertex, graph.vertices, graph.edges,
                      static_cast<std::uint16_t>(graph.first_hops.size()))) {
    route_recalculation_status_ = RouteRecalculationStatus::spf_rejected;
    return false;
  }
  const bool ipv4_address_family =
      version_ == packet::ospf::version_three &&
      instance_id_ >= device_catalog::ospf_v3_ipv4_instance_first;
  if (!route_calculator_.recalculate(database_.records(), version_, area_id_,
                                     ipv4_address_family, graph, spf_,
                                     loop_free_alternates_)) {
    route_recalculation_status_ =
        RouteRecalculationStatus::route_derivation_rejected;
    return false;
  }

  try {
    std::vector<lab::routing::DynamicInput> ipv4;
    std::vector<lab::routing::Ipv6DynamicInput> ipv6;
    for (const auto &route : route_calculator_.routes()) {
      // Connected prefixes are already authoritative RIB inputs. OSPF
      // publishes only routes that have a real first hop; retaining the local
      // zero-hop copies would create duplicate protocol ownership.
      for (const auto &next_hop : route.next_hops)
        if (!append_route_input(route, next_hop, false, ipv4, ipv6)) {
          route_recalculation_status_ =
              RouteRecalculationStatus::egress_interface_missing;
          return false;
        }
      for (const auto &next_hop : route.loop_free_alternates)
        if (!append_route_input(route, next_hop, true, ipv4, ipv6)) {
          route_recalculation_status_ =
              RouteRecalculationStatus::egress_interface_missing;
          return false;
        }
    }
    ipv4_route_inputs_.swap(ipv4);
    ipv6_route_inputs_.swap(ipv6);
  } catch (const std::bad_alloc &) {
    route_recalculation_status_ =
        RouteRecalculationStatus::allocation_failed;
    return false;
  }
  ++route_generation_;
  last_spf_started_ = now;
  spf_deadline_ = {};
  route_recalculation_status_ = RouteRecalculationStatus::succeeded;
  return true;
}

} // namespace router::ospf
