// DHCPv4 allocation and binding transitions. Address arithmetic is performed
// in host-order integers only inside this owner, while public packet addresses
// remain canonical network-order byte arrays.

#include "router/dhcpv4_lease.hpp"

#include <algorithm>
#include <limits>

namespace router::dhcpv4 {
namespace {

[[nodiscard]] std::uint32_t integer(const packet::Ipv4 &address) noexcept {
  return (static_cast<std::uint32_t>(address[0U]) << 24U) |
         (static_cast<std::uint32_t>(address[1U]) << 16U) |
         (static_cast<std::uint32_t>(address[2U]) << 8U) | address[3U];
}

[[nodiscard]] packet::Ipv4 address(std::uint32_t value) noexcept {
  return packet::Ipv4{
      static_cast<std::uint8_t>(value >> 24U),
      static_cast<std::uint8_t>(value >> 16U),
      static_cast<std::uint8_t>(value >> 8U),
      static_cast<std::uint8_t>(value),
  };
}

[[nodiscard]] bool same_scope(const AllocationScope &left,
                              const AllocationScope &right) noexcept {
  return left.server_instance == right.server_instance &&
         left.routing_context == right.routing_context &&
         left.link_identity == right.link_identity;
}

[[nodiscard]] bool contains(const Pool &pool,
                            packet::Ipv4 value) noexcept {
  const auto candidate = integer(value);
  return candidate >= integer(pool.first) && candidate <= integer(pool.last);
}

[[nodiscard]] bool valid_pool(const Pool &pool) noexcept {
  const auto minimum =
      pool.minimum_lease_seconds ? pool.minimum_lease_seconds
                                 : pool.lease_seconds;
  const auto maximum =
      pool.maximum_lease_seconds ? pool.maximum_lease_seconds
                                 : pool.lease_seconds;
  if (pool.id == 0U || integer(pool.first) > integer(pool.last) ||
      minimum == 0U || maximum == 0U || minimum > maximum)
    return false;
  // RFC 2131 requires T1 before T2 and both before lease expiry when the
  // server supplies explicit values. Zero means the server omits the option.
  if ((pool.renewal_seconds != 0U &&
       pool.renewal_seconds >= maximum) ||
      (pool.rebinding_seconds != 0U &&
       pool.rebinding_seconds >= maximum) ||
      (pool.renewal_seconds != 0U && pool.rebinding_seconds != 0U &&
       pool.renewal_seconds >= pool.rebinding_seconds))
    return false;
  return true;
}

[[nodiscard]] std::uint32_t
effective_lease(const Pool &pool,
                std::optional<std::uint32_t> requested) noexcept {
  const auto minimum =
      pool.minimum_lease_seconds ? pool.minimum_lease_seconds
                                 : pool.lease_seconds;
  const auto maximum =
      pool.maximum_lease_seconds ? pool.maximum_lease_seconds
                                 : pool.lease_seconds;
  return std::clamp(requested.value_or(maximum), minimum, maximum);
}

[[nodiscard]] std::chrono::seconds
effective_offer_hold(const Pool &pool,
                     std::chrono::seconds fallback) noexcept {
  return pool.offer_seconds
             ? std::chrono::seconds{pool.offer_seconds}
             : fallback;
}

[[nodiscard]] std::int64_t
remaining_nanoseconds(LeaseRepository::Clock::time_point deadline,
                      LeaseRepository::Clock::time_point now) noexcept {
  return std::max<std::int64_t>(
      0, std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
             .count());
}

} // namespace

bool equal_client_key(const ClientKey &left,
                      const ClientKey &right) noexcept {
  return left.option_61 == right.option_61 &&
         left.octets == right.octets &&
         std::equal(left.bytes.begin(), left.bytes.begin() + left.octets,
                    right.bytes.begin());
}

std::optional<ClientKey>
client_key(const packet::dhcpv4::MessageView &message) noexcept {
  std::array<std::uint8_t, maximum_client_identifier_octets> normalized{};
  const auto option = packet::dhcpv4::normalize_option(
      message,
      static_cast<std::uint8_t>(
          packet::dhcpv4::OptionCode::client_identifier),
      normalized);
  if (!option)
    return std::nullopt;
  if (option->occurrences != 0U) {
    // RFC 6842 treats the concatenated Option 61 value as one identifier. An
    // empty identifier has no identity semantics and is rejected.
    if (option->octets == 0U ||
        option->octets > maximum_client_identifier_octets)
      return std::nullopt;
    ClientKey result{.octets = static_cast<std::uint16_t>(option->octets),
                     .option_61 = true};
    std::copy_n(normalized.begin(), option->octets, result.bytes.begin());
    return result;
  }

  if (message.hardware_length == 0U ||
      static_cast<std::size_t>(message.hardware_length) + 1U >
          maximum_client_identifier_octets)
    return std::nullopt;
  ClientKey result{.octets = static_cast<std::uint16_t>(
                       message.hardware_length + 1U)};
  result.bytes[0U] = message.hardware_type;
  std::copy_n(message.client_hardware_address.begin(),
              message.hardware_length, result.bytes.begin() + 1U);
  return result;
}

LeaseRepository::LeaseRepository() {
  pools_.reserve(device_catalog::dhcpv4_pools_per_server);
  reservations_.reserve(device_catalog::dhcpv4_leases_per_server);
  exclusions_.reserve(device_catalog::dhcpv4_leases_per_server);
  leases_.reserve(device_catalog::dhcpv4_leases_per_server);
}

bool LeaseRepository::configure(
    std::span<const Pool> pools,
    std::span<const Reservation> reservations,
    std::chrono::seconds offer_hold,
    std::chrono::seconds decline_hold,
    std::span<const ExcludedRange> exclusions) {
  if (pools.size() > device_catalog::dhcpv4_pools_per_server ||
      reservations.size() > device_catalog::dhcpv4_leases_per_server ||
      exclusions.size() > device_catalog::dhcpv4_leases_per_server ||
      offer_hold <= std::chrono::seconds::zero() ||
      decline_hold < std::chrono::seconds::zero())
    return false;

  for (std::size_t index = 0U; index < pools.size(); ++index) {
    if (!valid_pool(pools[index]))
      return false;
    for (std::size_t other = index + 1U; other < pools.size(); ++other) {
      if (pools[index].id == pools[other].id)
        return false;
      if (!pools[index].enabled || !pools[other].enabled ||
          !same_scope(pools[index].scope, pools[other].scope))
        continue;
      // One allocation scope must not have overlapping pools because storage
      // order is not a valid protocol policy for resolving the ambiguity.
      if (integer(pools[index].first) <= integer(pools[other].last) &&
          integer(pools[other].first) <= integer(pools[index].last))
        return false;
    }
  }

  for (std::size_t index = 0U; index < reservations.size(); ++index) {
    const auto matching_pool = std::count_if(
        pools.begin(), pools.end(), [&](const Pool &pool) {
          return pool.enabled &&
                 same_scope(pool.scope, reservations[index].scope) &&
                 contains(pool, reservations[index].address);
        });
    if (reservations[index].client.octets == 0U || matching_pool != 1)
      return false;
    for (std::size_t other = index + 1U; other < reservations.size(); ++other) {
      if (same_scope(reservations[index].scope,
                     reservations[other].scope) &&
          (reservations[index].address == reservations[other].address ||
           equal_client_key(reservations[index].client,
                            reservations[other].client)))
        return false;
    }
  }

  for (std::size_t index{}; index < exclusions.size(); ++index) {
    const auto &excluded = exclusions[index];
    if (integer(excluded.first) > integer(excluded.last))
      return false;
    const auto matching_pool = std::count_if(
        pools.begin(), pools.end(), [&](const Pool &pool) {
          return pool.enabled && same_scope(pool.scope, excluded.scope) &&
                 contains(pool, excluded.first) &&
                 contains(pool, excluded.last);
        });
    if (matching_pool != 1)
      return false;
    for (std::size_t prior{}; prior < index; ++prior)
      if (same_scope(exclusions[prior].scope, excluded.scope) &&
          integer(exclusions[prior].first) <= integer(excluded.last) &&
          integer(excluded.first) <= integer(exclusions[prior].last))
        return false;
  }

  try {
    std::vector<Pool> next_pools{pools.begin(), pools.end()};
    std::vector<Reservation> next_reservations{reservations.begin(),
                                               reservations.end()};
    std::vector<ExcludedRange> next_exclusions{exclusions.begin(),
                                               exclusions.end()};
    pools_ = std::move(next_pools);
    reservations_ = std::move(next_reservations);
    exclusions_ = std::move(next_exclusions);
  } catch (...) {
    return false;
  }
  offer_hold_ = offer_hold;
  decline_hold_ = decline_hold;
  return true;
}

const Pool *LeaseRepository::pool_for(
    const AllocationScope &scope, packet::Ipv4 value) const noexcept {
  const Pool *result = nullptr;
  for (const auto &pool : pools_) {
    if (!pool.enabled || !same_scope(pool.scope, scope) ||
        !contains(pool, value))
      continue;
    if (result)
      return nullptr;
    result = &pool;
  }
  return result;
}

Lease *LeaseRepository::binding(const AllocationScope &scope,
                                const ClientKey &client) noexcept {
  const auto found = std::find_if(
      leases_.begin(), leases_.end(), [&](const Lease &lease) {
        return same_scope(lease.scope, scope) &&
               equal_client_key(lease.client, client);
      });
  return found == leases_.end() ? nullptr : &*found;
}

const Lease *LeaseRepository::lease_for(
    const AllocationScope &scope, const ClientKey &client) const noexcept {
  const auto found = std::find_if(
      leases_.begin(), leases_.end(), [&](const Lease &lease) {
        return same_scope(lease.scope, scope) &&
               equal_client_key(lease.client, client);
      });
  return found == leases_.end() ? nullptr : &*found;
}

const Reservation *LeaseRepository::reservation(
    const AllocationScope &scope, const ClientKey &client) const noexcept {
  const auto found = std::find_if(
      reservations_.begin(), reservations_.end(),
      [&](const Reservation &entry) {
        return same_scope(entry.scope, scope) &&
               equal_client_key(entry.client, client);
      });
  return found == reservations_.end() ? nullptr : &*found;
}

void LeaseRepository::record_change(Lease &lease,
                                    Clock::time_point now) noexcept {
  lease.last_state_change = now;
  lease.revision = next_revision_;
  if (next_revision_ != std::numeric_limits<std::uint64_t>::max())
    ++next_revision_;
}

bool LeaseRepository::address_available(
    const Pool &pool, packet::Ipv4 value, const ClientKey &client,
    Clock::time_point now) const noexcept {
  if (!contains(pool, value))
    return false;
  for (const auto &excluded : exclusions_)
    if (same_scope(excluded.scope, pool.scope) &&
        integer(value) >= integer(excluded.first) &&
        integer(value) <= integer(excluded.last))
      return false;
  for (const auto &entry : reservations_) {
    if (same_scope(entry.scope, pool.scope) && entry.address == value &&
        !equal_client_key(entry.client, client))
      return false;
  }
  for (const auto &lease : leases_) {
    if (!same_scope(lease.scope, pool.scope) || lease.address != value ||
        equal_client_key(lease.client, client))
      continue;
    if ((lease.state == BindingState::pending_offer &&
         lease.offered_until > now) ||
        (lease.state == BindingState::active &&
         lease.active_until > now) ||
        ((lease.state == BindingState::declined ||
          lease.state == BindingState::conflict) &&
         lease.active_until > now))
      return false;
  }
  return true;
}

std::optional<packet::Ipv4> LeaseRepository::first_available(
    const Pool &pool, const ClientKey &client,
    Clock::time_point now) const noexcept {
  const auto first = integer(pool.first);
  const auto last = integer(pool.last);
  for (auto current = first;; ++current) {
    const auto candidate = address(current);
    if (address_available(pool, candidate, client, now))
      return candidate;
    if (current == last || current == std::numeric_limits<std::uint32_t>::max())
      break;
  }
  return std::nullopt;
}

AllocateResult LeaseRepository::offer(
    const AllocationScope &scope, const ClientKey &client,
    std::uint32_t transaction_id,
    std::optional<packet::Ipv4> requested_address,
    Clock::time_point now,
    std::optional<std::uint32_t> requested_lease_seconds,
    ClientHardwareIdentity hardware,
    std::span<const std::uint8_t> relay_agent_information) {
  expire(now);
  const auto scope_exists = std::any_of(
      pools_.begin(), pools_.end(), [&](const Pool &candidate) {
        return candidate.enabled && same_scope(candidate.scope, scope);
      });
  if (!scope_exists)
    return {.status = AllocateStatus::unknown_scope};
  // RFC 2131 defines XID as an opaque 32-bit transaction value and does not
  // reserve zero. Rejecting zero would invent a protocol restriction.
  if (client.octets == 0U ||
      relay_agent_information.size() >
          Lease{}.relay_agent_information.size())
    return {.status = AllocateStatus::invalid_request};

  std::optional<packet::Ipv4> selected;
  const Pool *selected_pool = nullptr;
  if (const auto *fixed = reservation(scope, client)) {
    selected = fixed->address;
    selected_pool = pool_for(scope, *selected);
  }

  auto *existing = binding(scope, client);
  const auto select_existing = [&](packet::Ipv4 value) {
    const auto *candidate_pool = pool_for(scope, value);
    if (!candidate_pool ||
        !address_available(*candidate_pool, value, client, now))
      return false;
    selected = value;
    selected_pool = candidate_pool;
    return true;
  };
  if (!selected && existing && existing->state == BindingState::active &&
      existing->active_until > now)
    (void)select_existing(existing->address);
  if (!selected && existing && existing->sticky)
    (void)select_existing(existing->address);
  if (!selected && requested_address)
    (void)select_existing(*requested_address);

  if (!selected) {
    // Multiple non-overlapping pools can serve one link. Pool identity is
    // configuration semantics, while vector order is merely serialization
    // order, so allocation always walks increasing pool IDs.
    for (std::uint32_t next_id = 1U;
         next_id <= std::numeric_limits<std::uint16_t>::max();) {
      const Pool *candidate = nullptr;
      for (const auto &pool : pools_) {
        if (!pool.enabled || !same_scope(pool.scope, scope) ||
            pool.id < next_id ||
            (candidate && pool.id >= candidate->id))
          continue;
        candidate = &pool;
      }
      if (!candidate)
        break;
      if (const auto address = first_available(*candidate, client, now)) {
        selected = *address;
        selected_pool = candidate;
        break;
      }
      next_id = static_cast<std::uint32_t>(candidate->id) + 1U;
    }
  }
  if (!selected || !selected_pool)
    return {.status = AllocateStatus::exhausted};

  if (!existing) {
    if (leases_.size() == device_catalog::dhcpv4_leases_per_server)
      return {.status = AllocateStatus::resource_exhausted,
              .pool_id = selected_pool->id};
    try {
      leases_.push_back(Lease{.scope = scope, .client = client});
      existing = &leases_.back();
    } catch (...) {
      return {.status = AllocateStatus::resource_exhausted,
              .pool_id = selected_pool->id};
    }
  }
  existing->address = *selected;
  if (hardware.length != 0U)
    existing->hardware = hardware;
  std::ranges::copy(relay_agent_information,
                    existing->relay_agent_information.begin());
  existing->relay_agent_information_octets =
      static_cast<std::uint16_t>(relay_agent_information.size());
  existing->transaction_id = transaction_id;
  existing->lease_seconds =
      effective_lease(*selected_pool, requested_lease_seconds);
  existing->offered_until =
      now + effective_offer_hold(*selected_pool, offer_hold_);
  existing->state = BindingState::pending_offer;
  existing->last_client_transaction = now;
  record_change(*existing, now);
  return {.status = AllocateStatus::offered,
          .address = *selected,
          .pool_id = selected_pool->id,
          .lease_seconds = existing->lease_seconds};
}

bool LeaseRepository::commit(const AllocationScope &scope,
                             const ClientKey &client,
                             std::uint32_t transaction_id,
                             packet::Ipv4 value,
                             Clock::time_point now,
                             std::optional<std::uint32_t>
                                 requested_lease_seconds,
                             ClientHardwareIdentity hardware,
                             std::span<const std::uint8_t>
                                 relay_agent_information) {
  expire(now);
  if (relay_agent_information.size() >
      Lease{}.relay_agent_information.size())
    return false;
  auto *lease = binding(scope, client);
  const auto *pool = pool_for(scope, value);
  if (!lease || !pool || lease->address != value ||
      (lease->state != BindingState::active &&
       (lease->state != BindingState::pending_offer ||
        lease->transaction_id != transaction_id ||
        lease->offered_until <= now)))
    return false;
  lease->transaction_id = transaction_id;
  if (hardware.length != 0U)
    lease->hardware = hardware;
  std::ranges::copy(relay_agent_information,
                    lease->relay_agent_information.begin());
  lease->relay_agent_information_octets =
      static_cast<std::uint16_t>(relay_agent_information.size());
  if (requested_lease_seconds || lease->lease_seconds == 0U)
    lease->lease_seconds =
        effective_lease(*pool, requested_lease_seconds);
  lease->active_until = now + std::chrono::seconds{lease->lease_seconds};
  lease->state = BindingState::active;
  lease->sticky = true;
  lease->last_client_transaction = now;
  record_change(*lease, now);
  return true;
}

bool LeaseRepository::release(const AllocationScope &scope,
                              const ClientKey &client,
                              packet::Ipv4 value,
                              Clock::time_point now) noexcept {
  auto *lease = binding(scope, client);
  if (!lease || lease->address != value ||
      lease->state != BindingState::active)
    return false;
  lease->state = BindingState::released;
  lease->active_until = now;
  lease->last_client_transaction = now;
  record_change(*lease, now);
  return true;
}

bool LeaseRepository::decline(const AllocationScope &scope,
                              const ClientKey &client,
                              packet::Ipv4 value,
                              Clock::time_point now) noexcept {
  auto *lease = binding(scope, client);
  const auto *pool = pool_for(scope, value);
  if (!lease || !pool || lease->address != value)
    return false;
  lease->state = BindingState::declined;
  lease->active_until = Clock::time_point::max();
  lease->decline_sequence = next_decline_sequence_++;
  lease->sticky = false;
  lease->last_client_transaction = now;
  record_change(*lease, now);
  auto declined_count = static_cast<std::uint32_t>(std::count_if(
      leases_.begin(), leases_.end(), [&](const Lease &candidate) {
        return same_scope(candidate.scope, scope) &&
               candidate.state == BindingState::declined;
      }));
  while (declined_count > pool->maximum_declined) {
    const auto oldest = std::min_element(
        leases_.begin(), leases_.end(), [&](const Lease &left,
                                            const Lease &right) {
          const auto left_sequence =
              same_scope(left.scope, scope) &&
                      left.state == BindingState::declined
                  ? left.decline_sequence
                  : std::numeric_limits<std::uint64_t>::max();
          const auto right_sequence =
              same_scope(right.scope, scope) &&
                      right.state == BindingState::declined
                  ? right.decline_sequence
                  : std::numeric_limits<std::uint64_t>::max();
          return left_sequence < right_sequence;
        });
    if (oldest == leases_.end() ||
        oldest->state != BindingState::declined)
      break;
    oldest->state = BindingState::expired;
    oldest->active_until = now;
    oldest->decline_sequence = 0U;
    record_change(*oldest, now);
    --declined_count;
  }
  return true;
}

const Lease *LeaseRepository::active_lease_at(
    packet::Ipv4 address, Clock::time_point now) noexcept {
  expire(now);
  const auto lease = std::find_if(
      leases_.begin(), leases_.end(), [&](const Lease &candidate) {
        return candidate.address == address &&
               candidate.state == BindingState::active &&
               candidate.active_until > now;
      });
  return lease == leases_.end() ? nullptr : &*lease;
}

std::size_t LeaseRepository::clear(const LeaseClearFilter &filter,
                                   Clock::time_point now) noexcept {
  expire(now);
  const auto address_word = [](packet::Ipv4 address) noexcept {
    return static_cast<std::uint32_t>(address[0U]) << 24U |
           static_cast<std::uint32_t>(address[1U]) << 16U |
           static_cast<std::uint32_t>(address[2U]) << 8U |
           static_cast<std::uint32_t>(address[3U]);
  };
  if (filter.prefix_length > 32U)
    return 0U;
  const auto mask =
      filter.prefix_length == 0U
          ? 0U
          : std::numeric_limits<std::uint32_t>::max()
                << (32U - filter.prefix_length);
  const auto selected_network = address_word(filter.address) & mask;
  const auto state_matches = [&](const Lease &lease) noexcept {
    switch (filter.state) {
    case OperationalLeaseState::any:
      return true;
    case OperationalLeaseState::offered:
      return lease.state == BindingState::pending_offer;
    case OperationalLeaseState::stable:
      return lease.state == BindingState::active;
    case OperationalLeaseState::held:
      return lease.state == BindingState::released ||
             lease.state == BindingState::expired ||
             lease.state == BindingState::declined ||
             lease.state == BindingState::conflict;
    case OperationalLeaseState::sticky:
      return lease.sticky;
    case OperationalLeaseState::force_renew_pending:
    case OperationalLeaseState::remove_pending:
    case OperationalLeaseState::internal:
    case OperationalLeaseState::internal_orphan:
    case OperationalLeaseState::internal_offered:
    case OperationalLeaseState::internal_held:
      // These documented values belong to absent subscriber or failover
      // owners. They remain valid filters but cannot match this repository.
      return false;
    }
    return false;
  };
  const auto before = leases_.size();
  std::erase_if(leases_, [&](const Lease &lease) noexcept {
    const bool address_matches =
        !filter.address_specific ||
        (address_word(lease.address) & mask) == selected_network;
    return address_matches && state_matches(lease);
  });
  return before - leases_.size();
}

PartnerUpdateStatus LeaseRepository::apply_partner_update(
    const failover::BindingUpdateView &update,
    std::uint32_t absolute_now, Clock::time_point now) noexcept {
  // The address identifies the allocation scope only when exactly one
  // configured range contains it. Disabled remote ranges intentionally
  // participate here because they are precisely the bindings learned from a
  // partner and must not disappear merely because local allocation is barred.
  const Pool *selected_pool{};
  for (const auto &pool : pools_) {
    if (!contains(pool, update.address))
      continue;
    if (selected_pool)
      return PartnerUpdateStatus::ambiguous_address;
    selected_pool = &pool;
  }
  if (!selected_pool)
    return PartnerUpdateStatus::unknown_address;
  if (!update.start_time_of_state)
    return PartnerUpdateStatus::invalid_update;
  if (update.status == failover::BindingStatus::active &&
      (!update.lease_expiration_time ||
       !update.potential_expiration_time ||
       !update.client_last_transaction_time))
    return PartnerUpdateStatus::invalid_update;

  ClientKey key{};
  ClientHardwareIdentity hardware{};
  if (!update.client_identifier.empty()) {
    if (update.client_identifier.size() > key.bytes.size())
      return PartnerUpdateStatus::invalid_update;
    key.option_61 = true;
    key.octets =
        static_cast<std::uint16_t>(update.client_identifier.size());
    std::ranges::copy(update.client_identifier, key.bytes.begin());
  } else if (!update.client_hardware_address.empty()) {
    if (update.client_hardware_address.size() > key.bytes.size() ||
        update.client_hardware_address.size() - 1U >
            hardware.address.size())
      return PartnerUpdateStatus::invalid_update;
    key.octets = static_cast<std::uint16_t>(
        update.client_hardware_address.size());
    std::ranges::copy(update.client_hardware_address, key.bytes.begin());
    hardware.type = update.client_hardware_address.front();
    hardware.length = static_cast<std::uint8_t>(
        update.client_hardware_address.size() - 1U);
    std::ranges::copy(update.client_hardware_address.subspan(1U),
                      hardware.address.begin());
  }

  const bool requires_identity =
      update.status == failover::BindingStatus::active ||
      update.status == failover::BindingStatus::expired ||
      update.status == failover::BindingStatus::released;
  if (requires_identity && key.octets == 0U)
    return PartnerUpdateStatus::invalid_update;

  auto existing = std::find_if(
      leases_.begin(), leases_.end(), [&](const Lease &lease) {
        return lease.address == update.address &&
               same_scope(lease.scope, selected_pool->scope);
      });
  if (existing != leases_.end() && existing->failover_managed &&
      existing->failover_state_started_absolute >=
          *update.start_time_of_state)
    return PartnerUpdateStatus::duplicate;

  if (existing == leases_.end()) {
    if (leases_.size() == device_catalog::dhcpv4_leases_per_server)
      return PartnerUpdateStatus::resource_exhausted;
    try {
      leases_.push_back(
          {.scope = selected_pool->scope, .client = key,
           .address = update.address});
      existing = leases_.end() - 1;
    } catch (...) {
      return PartnerUpdateStatus::resource_exhausted;
    }
  }

  auto &lease = *existing;
  if (key.octets != 0U)
    lease.client = key;
  if (hardware.length != 0U)
    lease.hardware = hardware;
  lease.address = update.address;
  lease.failover_status = update.status;
  lease.failover_state_started_absolute = *update.start_time_of_state;
  lease.failover_partner_expiration_absolute =
      update.potential_expiration_time.value_or(0U);
  lease.failover_managed = true;
  lease.sticky = update.status == failover::BindingStatus::active;
  lease.last_client_transaction =
      update.client_last_transaction_time &&
              *update.client_last_transaction_time <= absolute_now
          ? now - std::chrono::seconds{
                      absolute_now - *update.client_last_transaction_time}
          : now;

  const auto local_deadline = [&](std::optional<std::uint32_t> absolute) {
    return !absolute || *absolute <= absolute_now
               ? now
               : now + std::chrono::seconds{*absolute - absolute_now};
  };
  switch (update.status) {
  case failover::BindingStatus::active:
    lease.state = BindingState::active;
    lease.active_until = local_deadline(update.lease_expiration_time);
    lease.lease_seconds =
        *update.lease_expiration_time > absolute_now
            ? *update.lease_expiration_time - absolute_now
            : 0U;
    break;
  case failover::BindingStatus::released:
    lease.state = BindingState::released;
    lease.active_until = now;
    break;
  case failover::BindingStatus::abandoned:
    lease.state = BindingState::conflict;
    lease.active_until = Clock::time_point::max();
    lease.sticky = false;
    break;
  case failover::BindingStatus::expired:
  case failover::BindingStatus::free:
  case failover::BindingStatus::reset:
  case failover::BindingStatus::backup:
    lease.state = BindingState::expired;
    lease.active_until = now;
    lease.sticky = false;
    break;
  }
  record_change(lease, now);
  return PartnerUpdateStatus::applied;
}

PartnerUpdateStatus LeaseRepository::apply_partner_updates(
    std::span<const failover::BindingUpdateView> updates,
    std::uint32_t absolute_now, Clock::time_point now) noexcept {
  if (updates.empty() ||
      updates.size() > device_catalog::dhcp_failover_updates_in_flight)
    return PartnerUpdateStatus::invalid_update;
  try {
    // One BNDUPD is one protocol transaction even when it carries several
    // binding groups. Staging the repository ensures a malformed later group
    // cannot leave earlier groups committed without the matching BNDACK.
    auto staged = *this;
    auto aggregate = PartnerUpdateStatus::duplicate;
    for (const auto &update : updates) {
      const auto result =
          staged.apply_partner_update(update, absolute_now, now);
      if (result != PartnerUpdateStatus::applied &&
          result != PartnerUpdateStatus::duplicate)
        return result;
      if (result == PartnerUpdateStatus::applied)
        aggregate = PartnerUpdateStatus::applied;
    }
    *this = std::move(staged);
    return aggregate;
  } catch (...) {
    return PartnerUpdateStatus::resource_exhausted;
  }
}

void LeaseRepository::expire(Clock::time_point now) noexcept {
  for (auto &lease : leases_) {
    if (lease.state == BindingState::pending_offer &&
        lease.offered_until <= now) {
      lease.state = BindingState::expired;
      record_change(lease, now);
    } else if ((lease.state == BindingState::active ||
                lease.state == BindingState::conflict) &&
               lease.active_until <= now) {
      lease.state = BindingState::expired;
      record_change(lease, now);
    }
  }
}

LeaseRepositoryCheckpoint
LeaseRepository::checkpoint(Clock::time_point now) const {
  LeaseRepositoryCheckpoint result{
      .pools = pools_,
      .reservations = reservations_,
      .exclusions = exclusions_,
      .leases = {},
      .offer_hold_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(offer_hold_)
              .count(),
      .decline_hold_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(decline_hold_)
              .count(),
      .next_decline_sequence = next_decline_sequence_,
      .next_revision = next_revision_};
  result.leases.reserve(leases_.size());
  for (const auto &lease : leases_)
    result.leases.push_back(
        {.scope = lease.scope,
         .client = lease.client,
         .hardware = lease.hardware,
         .relay_agent_information = lease.relay_agent_information,
         .relay_agent_information_octets =
             lease.relay_agent_information_octets,
         .address = lease.address,
         .transaction_id = lease.transaction_id,
         .offer_remaining_nanoseconds =
             remaining_nanoseconds(lease.offered_until, now),
         .active_remaining_nanoseconds =
             lease.state == BindingState::declined
                 ? 0
                 : remaining_nanoseconds(lease.active_until, now),
         .last_client_transaction_elapsed_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 now - lease.last_client_transaction)
                 .count(),
         .last_state_change_elapsed_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 now - lease.last_state_change)
                 .count(),
         .lease_seconds = lease.lease_seconds,
         .decline_sequence = lease.decline_sequence,
         .revision = lease.revision,
         .failover_state_started_absolute =
             lease.failover_state_started_absolute,
         .failover_partner_expiration_absolute =
             lease.failover_partner_expiration_absolute,
         .failover_status = lease.failover_status,
         .state = lease.state,
         .sticky = lease.sticky,
         .failover_managed = lease.failover_managed});
  return result;
}

bool LeaseRepository::restore(const LeaseRepositoryCheckpoint &state,
                              Clock::time_point now) {
  if (state.offer_hold_nanoseconds <= 0 ||
      state.decline_hold_nanoseconds < 0 ||
      state.next_decline_sequence == 0U ||
      state.next_revision == 0U ||
      state.leases.size() > device_catalog::dhcpv4_leases_per_server)
    return false;
  const auto offer_hold =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::nanoseconds{state.offer_hold_nanoseconds});
  const auto decline_hold =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::nanoseconds{state.decline_hold_nanoseconds});
  LeaseRepository staged;
  if (!staged.configure(state.pools, state.reservations, offer_hold,
                        decline_hold, state.exclusions))
    return false;
  try {
    staged.leases_.reserve(state.leases.size());
    for (std::size_t index{}; index < state.leases.size(); ++index) {
      const auto &saved = state.leases[index];
      if (saved.client.octets == 0U ||
          saved.client.octets > saved.client.bytes.size() ||
          saved.hardware.length > saved.hardware.address.size() ||
          saved.relay_agent_information_octets >
              saved.relay_agent_information.size() ||
          (saved.hardware.length != 0U && saved.hardware.type == 0U) ||
          saved.state > BindingState::reserved ||
          saved.offer_remaining_nanoseconds < 0 ||
          saved.active_remaining_nanoseconds < 0 ||
          saved.last_client_transaction_elapsed_nanoseconds < 0 ||
          saved.last_state_change_elapsed_nanoseconds < 0 ||
          saved.revision == 0U || saved.revision >= state.next_revision ||
          saved.failover_status > failover::BindingStatus::backup ||
          (saved.failover_managed &&
           saved.failover_state_started_absolute == 0U) ||
          std::count_if(
              staged.pools_.begin(), staged.pools_.end(),
              [&](const Pool &pool) {
                return same_scope(pool.scope, saved.scope) &&
                       contains(pool, saved.address);
              }) != 1)
        return false;
      if ((saved.state == BindingState::declined &&
           (saved.decline_sequence == 0U ||
            saved.decline_sequence >= state.next_decline_sequence)) ||
          (saved.state != BindingState::declined &&
           saved.decline_sequence != 0U))
        return false;
      if ((saved.state == BindingState::pending_offer &&
           saved.offer_remaining_nanoseconds == 0) ||
          ((saved.state == BindingState::active ||
            saved.state == BindingState::conflict) &&
           saved.active_remaining_nanoseconds == 0))
        return false;
      for (std::size_t prior{}; prior < index; ++prior) {
        const auto &other = state.leases[prior];
        if (same_scope(saved.scope, other.scope) &&
            (equal_client_key(saved.client, other.client) ||
             (saved.address == other.address &&
              ((saved.state == BindingState::pending_offer ||
                saved.state == BindingState::active ||
                saved.state == BindingState::declined ||
                saved.state == BindingState::conflict) &&
               (other.state == BindingState::pending_offer ||
                other.state == BindingState::active ||
                other.state == BindingState::declined ||
                other.state == BindingState::conflict)))))
          return false;
      }
      staged.leases_.push_back(
          {.scope = saved.scope,
           .client = saved.client,
           .hardware = saved.hardware,
           .relay_agent_information = saved.relay_agent_information,
           .relay_agent_information_octets =
               saved.relay_agent_information_octets,
           .address = saved.address,
           .transaction_id = saved.transaction_id,
           .offered_until =
               now + std::chrono::nanoseconds{
                         saved.offer_remaining_nanoseconds},
           .active_until =
               saved.state == BindingState::declined
                   ? Clock::time_point::max()
                   : now + std::chrono::nanoseconds{
                               saved.active_remaining_nanoseconds},
           .last_client_transaction =
               now - std::chrono::nanoseconds{
                         saved.last_client_transaction_elapsed_nanoseconds},
           .last_state_change =
               now - std::chrono::nanoseconds{
                         saved.last_state_change_elapsed_nanoseconds},
           .lease_seconds = saved.lease_seconds,
           .decline_sequence = saved.decline_sequence,
           .revision = saved.revision,
           .failover_state_started_absolute =
               saved.failover_state_started_absolute,
           .failover_partner_expiration_absolute =
               saved.failover_partner_expiration_absolute,
           .failover_status = saved.failover_status,
           .state = saved.state,
           .sticky = saved.sticky,
           .failover_managed = saved.failover_managed});
    }
  } catch (...) {
    return false;
  }
  staged.next_decline_sequence_ = state.next_decline_sequence;
  staged.next_revision_ = state.next_revision;
  *this = std::move(staged);
  return true;
}

} // namespace router::dhcpv4
