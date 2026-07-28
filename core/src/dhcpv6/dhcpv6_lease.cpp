// Stateful DHCPv6 allocation implementation. HMAC selects a stable secret
// starting point, then bounded linear probing guarantees that active and
// declined values are not reassigned even if two client hashes collide.

#include "router/dhcpv6_lease.hpp"

#include "router/ipv6_stable_iid.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace router::dhcpv6 {
namespace {

std::array<std::uint8_t, 4U> network_u32(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24U),
          static_cast<std::uint8_t>(value >> 16U),
          static_cast<std::uint8_t>(value >> 8U),
          static_cast<std::uint8_t>(value)};
}

bool nonzero(std::span<const std::uint8_t> bytes) noexcept {
  return std::any_of(bytes.begin(), bytes.end(),
                     [](auto byte) { return byte != 0U; });
}

std::uint64_t lower_u64(const crypto::Sha256Digest &digest) noexcept {
  std::uint64_t value{};
  for (std::size_t index = digest.size() - 8U; index < digest.size(); ++index)
    value = (value << 8U) | digest[index];
  return value;
}

LeaseRepository::Clock::time_point
lease_deadline(LeaseRepository::Clock::time_point now,
               std::uint32_t lifetime) noexcept {
  // RFC 9915 section 7.7 gives 0xffffffff a semantic value of infinity. A
  // large finite duration would eventually expire and would also overflow
  // nanosecond checkpoint arithmetic on common steady_clock ranges.
  return lifetime == std::numeric_limits<std::uint32_t>::max()
             ? LeaseRepository::Clock::time_point::max()
             : now + std::chrono::seconds{lifetime};
}

void write_suffix(packet::Ipv6 &value, std::uint8_t prefix_length,
                  std::uint64_t ordinal) noexcept {
  // The lower 64 host bits provide at least 2^64 candidates for every pool at
  // or above /64. Longer prefixes mask the ordinal to their exact finite
  // space. Shorter prefixes deliberately keep the upper host bits zero while
  // retaining a non-predictable 64-bit allocation domain.
  const auto host_bits = static_cast<std::uint8_t>(128U - prefix_length);
  if (host_bits < 64U)
    ordinal &= host_bits == 0U ? 0U : ((std::uint64_t{1U} << host_bits) - 1U);
  if (prefix_length <= 64U) {
    for (std::size_t index = 0; index < 8U; ++index)
      value[15U - index] =
          static_cast<std::uint8_t>(ordinal >> (index * 8U));
    return;
  }
  // A prefix may end in the middle of an octet. Touch only actual host bits,
  // preserving every configured prefix bit already present in the canonical
  // network value. This also leaves a /128 pool's single value unchanged.
  for (std::uint8_t target_bit = prefix_length; target_bit < 128U;
       ++target_bit) {
    const auto source_bit = static_cast<std::uint8_t>(127U - target_bit);
    const auto mask = static_cast<std::uint8_t>(1U << (7U - target_bit % 8U));
    if (((ordinal >> source_bit) & 1U) != 0U)
      value[target_bit / 8U] |= mask;
  }
}

void write_delegated_index(packet::Ipv6 &value, std::uint8_t aggregate_length,
                           std::uint8_t delegated_length,
                           std::uint64_t ordinal) noexcept {
  // Prefix pools need only the bits between the aggregate and delegated
  // lengths. Writing one bit at a time handles non-octet-aligned policies and
  // avoids native 128-bit types that differ across compiler targets.
  const auto allocation_bits =
      static_cast<std::uint8_t>(delegated_length - aggregate_length);
  if (allocation_bits < 64U)
    ordinal &= allocation_bits == 0U
                   ? 0U
                   : ((std::uint64_t{1U} << allocation_bits) - 1U);
  for (std::uint8_t offset = 0; offset < allocation_bits; ++offset) {
    const auto target_bit =
        static_cast<std::uint8_t>(aggregate_length + offset);
    const auto source_bit =
        static_cast<std::uint8_t>(allocation_bits - 1U - offset);
    const auto mask = static_cast<std::uint8_t>(1U << (7U - target_bit % 8U));
    if (((ordinal >> source_bit) & 1U) != 0U)
      value[target_bit / 8U] |= mask;
  }
}

} // namespace

bool LeaseRepository::valid_client(const ClientIdentity &client) noexcept {
  return client.duid_octets >= 3U &&
         client.duid_octets <= client.duid.size() &&
         packet::dhcpv6::valid_duid(
             std::span<const std::uint8_t>{client.duid}.first(
                 client.duid_octets));
}

bool LeaseRepository::same_client(const ClientIdentity &left,
                                  const ClientIdentity &right) noexcept {
  return left.iaid == right.iaid && left.kind == right.kind &&
         left.link_identity == right.link_identity &&
         left.duid_octets == right.duid_octets &&
         std::equal(left.duid.begin(),
                    left.duid.begin() + left.duid_octets,
                    right.duid.begin());
}

bool LeaseRepository::configure(
    std::span<const LeasePool> address_pools,
    std::span<const LeasePool> prefix_pools,
    std::chrono::seconds decline_hold_time) noexcept {
  if (address_pools.size() > address_pools_.size() ||
      prefix_pools.size() > prefix_pools_.size() ||
      decline_hold_time < std::chrono::seconds::zero())
    return false;
  const auto valid_pool = [](const LeasePool &pool, bool prefix) {
    const bool canonical =
        pool.prefix.length <= 128U &&
        ip::mask(pool.prefix.network, pool.prefix.length) ==
            pool.prefix.network;
    const bool lifetimes =
        pool.preferred_lifetime_seconds <= pool.valid_lifetime_seconds &&
        pool.t1_seconds <= pool.t2_seconds &&
        pool.t2_seconds <= pool.valid_lifetime_seconds &&
        pool.valid_lifetime_seconds != 0U;
    // Both lengths are one-octet wire values, but integer promotion makes
    // their subtraction signed. Keeping the bounded difference explicitly
    // signed matches that language rule and avoids comparing it with an
    // unsigned literal under GCC's mandatory warning set.
    const auto delegated_span = static_cast<int>(pool.delegated_length) -
                                static_cast<int>(pool.prefix.length);
    const bool shape = prefix
                           ? pool.delegated_length >= pool.prefix.length &&
                                 pool.delegated_length <= 128U &&
                                 delegated_span <= 64
                           : pool.delegated_length == 0U;
    return canonical && lifetimes && shape &&
           nonzero(pool.allocation_secret);
  };
  if (std::any_of(address_pools.begin(), address_pools.end(),
                  [&](const auto &pool) { return !valid_pool(pool, false); }) ||
      std::any_of(prefix_pools.begin(), prefix_pools.end(),
                  [&](const auto &pool) { return !valid_pool(pool, true); }))
    return false;

  address_pools_.fill({});
  prefix_pools_.fill({});
  std::copy(address_pools.begin(), address_pools.end(),
            address_pools_.begin());
  std::copy(prefix_pools.begin(), prefix_pools.end(), prefix_pools_.begin());
  address_pool_count_ = static_cast<std::uint8_t>(address_pools.size());
  prefix_pool_count_ = static_cast<std::uint8_t>(prefix_pools.size());
  decline_hold_time_ = decline_hold_time;
  // Replacing administrator pool intent invalidates every binding. Keeping a
  // lease whose value is outside the new pool would fabricate ownership that
  // no longer exists in configured server policy.
  leases_.fill({});
  return true;
}

LeaseRepository::Lease *
LeaseRepository::find(const ClientIdentity &client) noexcept {
  const auto found = std::find_if(leases_.begin(), leases_.end(),
                                  [&](const Lease &lease) {
                                    return lease.occupied && !lease.declined &&
                                           same_client(lease.client, client);
                                  });
  return found == leases_.end() ? nullptr : &*found;
}

const LeaseRepository::Lease *
LeaseRepository::find(const ClientIdentity &client) const noexcept {
  const auto found = std::find_if(leases_.begin(), leases_.end(),
                                  [&](const Lease &lease) {
                                    return lease.occupied && !lease.declined &&
                                           same_client(lease.client, client);
                                  });
  return found == leases_.end() ? nullptr : &*found;
}

packet::Ipv6 LeaseRepository::candidate(
    const LeasePool &pool, const ClientIdentity &client,
    std::uint32_t attempt) const noexcept {
  const auto iaid = network_u32(client.iaid);
  const std::array<std::uint8_t, 1U> kind{
      static_cast<std::uint8_t>(client.kind)};
  const std::array<std::span<const std::uint8_t>, 4U> message{
      std::span<const std::uint8_t>{client.duid}.first(client.duid_octets),
      client.link_identity, iaid, kind};
  const auto digest = crypto::hmac_sha256(pool.allocation_secret, message);
  auto value = pool.prefix.network;
  // A keyed start hides sequential client identity while adding the attempt
  // yields a collision-free walk until the finite pool wraps.
  const auto ordinal = lower_u64(digest) + attempt;
  if (client.kind == LeaseKind::prefix)
    write_delegated_index(value, pool.prefix.length, pool.delegated_length,
                          ordinal);
  else
    write_suffix(value, pool.prefix.length, ordinal);
  return value;
}

bool LeaseRepository::value_in_use(LeaseKind kind, packet::Ipv6 value,
                                   std::uint8_t prefix_length) const noexcept {
  return std::any_of(leases_.begin(), leases_.end(), [&](const Lease &lease) {
    if (!lease.occupied)
      return false;
    if (kind == LeaseKind::prefix || lease.client.kind == LeaseKind::prefix) {
      if (kind != LeaseKind::prefix || lease.client.kind != LeaseKind::prefix)
        return false;
      const ip::Ipv6Prefix requested{.network = value,
                                     .length = prefix_length};
      const ip::Ipv6Prefix existing{.network = lease.value,
                                    .length = lease.prefix_length};
      return ip::contains(requested, existing.network) ||
             ip::contains(existing, requested.network);
    }
    return lease.value == value;
  });
}

LeaseResult LeaseRepository::result(const Lease &lease, Clock::time_point now,
                                    LeaseStatus status) const noexcept {
  const auto remaining = [&](Clock::time_point deadline) {
    if (deadline == Clock::time_point::max())
      return std::numeric_limits<std::uint32_t>::max();
    if (deadline <= now)
      return std::uint32_t{};
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
        deadline - now);
    return seconds.count() > 0xffffffffLL
               ? std::uint32_t{0xffffffffU}
               : static_cast<std::uint32_t>(seconds.count());
  };
  const auto &pool = lease.client.kind == LeaseKind::prefix
                         ? prefix_pools_[lease.pool_index]
                         : address_pools_[lease.pool_index];
  return {.status = status,
          .value = lease.value,
          .preferred_lifetime_seconds = remaining(lease.preferred_until),
          .valid_lifetime_seconds = remaining(lease.valid_until),
          .t1_seconds = pool.t1_seconds,
          .t2_seconds = pool.t2_seconds,
          .prefix_length = lease.prefix_length};
}

LeaseResult LeaseRepository::assign(const ClientIdentity &client,
                                    std::size_t pool_index,
                                    Clock::time_point now) noexcept {
  if (!valid_client(client))
    return {.status = LeaseStatus::invalid_client};
  expire(now);
  const auto pool_count = client.kind == LeaseKind::prefix
                              ? prefix_pool_count_
                              : address_pool_count_;
  if (pool_index >= pool_count)
    return {.status = LeaseStatus::invalid_pool};
  if (auto *existing = find(client)) {
    const auto &pool = client.kind == LeaseKind::prefix
                           ? prefix_pools_[existing->pool_index]
                           : address_pools_[existing->pool_index];
    existing->preferred_until =
        lease_deadline(now, pool.preferred_lifetime_seconds);
    existing->valid_until = lease_deadline(now, pool.valid_lifetime_seconds);
    // Assignment and renewal are both client transactions for RFC 5007.
    // Preview deliberately does not touch this timestamp because Solicit
    // cannot create or refresh an authoritative binding.
    existing->last_client_transaction = now;
    return result(*existing, now, LeaseStatus::renewed);
  }
  auto available = std::find_if(leases_.begin(), leases_.end(),
                                [](const Lease &lease) {
                                  return !lease.occupied;
                                });
  if (available == leases_.end())
    return {.status = client.kind == LeaseKind::prefix
                          ? LeaseStatus::no_prefixes_available
                          : LeaseStatus::no_addresses_available};
  const auto &pool = client.kind == LeaseKind::prefix
                         ? prefix_pools_[pool_index]
                         : address_pools_[pool_index];
  const auto prefix_length = client.kind == LeaseKind::prefix
                                 ? pool.delegated_length
                                 : std::uint8_t{128U};
  for (std::uint32_t attempt = 0U; attempt <= leases_.size(); ++attempt) {
    const auto value = candidate(pool, client, attempt);
    if ((client.kind != LeaseKind::prefix &&
         host::is_reserved_ipv6_interface_identifier(
             {value[8U], value[9U], value[10U], value[11U], value[12U],
              value[13U], value[14U], value[15U]})) ||
        value_in_use(client.kind, value, prefix_length))
      continue;
    *available = {.client = client,
                  .value = value,
                  .preferred_until =
                      lease_deadline(now, pool.preferred_lifetime_seconds),
                  .valid_until =
                      lease_deadline(now, pool.valid_lifetime_seconds),
                  .last_client_transaction = now,
                  .pool_index = static_cast<std::uint16_t>(pool_index),
                  .prefix_length = prefix_length,
                  .occupied = true};
    return result(*available, now, LeaseStatus::assigned);
  }
  return {.status = client.kind == LeaseKind::prefix
                        ? LeaseStatus::no_prefixes_available
                        : LeaseStatus::no_addresses_available};
}

LeaseResult LeaseRepository::preview(const ClientIdentity &client,
                                     std::size_t pool_index,
                                     Clock::time_point now) noexcept {
  if (!valid_client(client))
    return {.status = LeaseStatus::invalid_client};
  expire(now);
  const auto pool_count = client.kind == LeaseKind::prefix
                              ? prefix_pool_count_
                              : address_pool_count_;
  if (pool_index >= pool_count)
    return {.status = LeaseStatus::invalid_pool};
  if (const auto *existing = find(client))
    return result(*existing, now, LeaseStatus::renewed);

  const auto &pool = client.kind == LeaseKind::prefix
                         ? prefix_pools_[pool_index]
                         : address_pools_[pool_index];
  const auto prefix_length = client.kind == LeaseKind::prefix
                                 ? pool.delegated_length
                                 : std::uint8_t{128U};
  // The repository descriptor count is also the maximum number of occupied
  // values that can force a collision. One additional candidate is therefore
  // sufficient to prove availability or repository exhaustion. Finite pools
  // wrap naturally and repeated candidates remain rejected by value_in_use.
  for (std::uint32_t attempt = 0U; attempt <= leases_.size(); ++attempt) {
    const auto value = candidate(pool, client, attempt);
    if ((client.kind != LeaseKind::prefix &&
         host::is_reserved_ipv6_interface_identifier(
             {value[8U], value[9U], value[10U], value[11U], value[12U],
              value[13U], value[14U], value[15U]})) ||
        value_in_use(client.kind, value, prefix_length))
      continue;
    return {.status = LeaseStatus::assigned,
            .value = value,
            .preferred_lifetime_seconds = pool.preferred_lifetime_seconds,
            .valid_lifetime_seconds = pool.valid_lifetime_seconds,
            .t1_seconds = pool.t1_seconds,
            .t2_seconds = pool.t2_seconds,
            .prefix_length = prefix_length};
  }
  return {.status = client.kind == LeaseKind::prefix
                        ? LeaseStatus::no_prefixes_available
                        : LeaseStatus::no_addresses_available};
}

LeaseResult LeaseRepository::renew(const ClientIdentity &client,
                                   Clock::time_point now) noexcept {
  if (!valid_client(client))
    return {.status = LeaseStatus::invalid_client};
  expire(now);
  auto *lease = find(client);
  if (!lease)
    return {.status = LeaseStatus::no_binding};
  return assign(client, lease->pool_index, now);
}

LeaseStatus LeaseRepository::release(const ClientIdentity &client) noexcept {
  if (!valid_client(client))
    return LeaseStatus::invalid_client;
  auto *lease = find(client);
  if (!lease)
    return LeaseStatus::no_binding;
  *lease = {};
  return LeaseStatus::released;
}

LeaseStatus LeaseRepository::decline(const ClientIdentity &client,
                                     Clock::time_point now) noexcept {
  if (!valid_client(client))
    return LeaseStatus::invalid_client;
  auto *lease = find(client);
  if (!lease)
    return LeaseStatus::no_binding;
  lease->preferred_until = {};
  lease->valid_until = {};
  lease->declined = true;
  // RFC 9915 section 18.2.7 requires a server to make a declined value
  // unavailable, but defines no universal quarantine duration. SR OS exposes
  // held DHCPv6 leases and an explicit reset operation instead of a documented
  // DHCPv6 decline timer. A zero configured duration therefore means an
  // indefinite held value, not immediate reuse.
  lease->declined_until =
      decline_hold_time_ == std::chrono::seconds::zero()
          ? Clock::time_point::max()
          : now + decline_hold_time_;
  lease->last_client_transaction = now;
  return LeaseStatus::declined;
}

void LeaseRepository::expire(Clock::time_point now) noexcept {
  for (auto &lease : leases_)
    if (lease.occupied &&
        ((lease.declined && lease.declined_until <= now) ||
         (!lease.declined && lease.valid_until <= now)))
      lease = {};
}

std::size_t LeaseRepository::active_leases() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      leases_.begin(), leases_.end(), [](const Lease &lease) {
        return lease.occupied && !lease.declined;
      }));
}

std::size_t LeaseRepository::declined_values() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      leases_.begin(), leases_.end(), [](const Lease &lease) {
        return lease.occupied && lease.declined;
      }));
}

bool LeaseRepository::appropriate_address(
    packet::Ipv6 address,
    const crypto::Sha256Digest &link_identity) const noexcept {
  return std::any_of(address_pools_.begin(),
                     address_pools_.begin() + address_pool_count_,
                     [&](const LeasePool &pool) {
                       return (!pool.link_scoped ||
                               pool.link_identity == link_identity) &&
                              ip::contains(pool.prefix, address);
                     });
}

std::vector<LeaseCheckpoint>
LeaseRepository::checkpoint(Clock::time_point now) const {
  std::vector<LeaseCheckpoint> state;
  state.reserve(active_leases() + declined_values());
  const auto remaining = [&](Clock::time_point deadline) {
    if (deadline == Clock::time_point::max())
      return std::int64_t{-1};
    const auto duration = deadline > now ? deadline - now
                                         : Clock::duration::zero();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(duration)
        .count();
  };
  const auto elapsed = [&](Clock::time_point timestamp) {
    if (timestamp == Clock::time_point{} || timestamp >= now)
      return std::int64_t{};
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               now - timestamp)
        .count();
  };
  for (const auto &lease : leases_) {
    if (!lease.occupied)
      continue;
    state.push_back({
        .client = lease.client,
        .value = lease.value,
        .last_client_address = lease.last_client_address,
        .preferred_remaining_nanoseconds =
            lease.declined ? 0 : remaining(lease.preferred_until),
        .valid_remaining_nanoseconds =
            lease.declined ? 0 : remaining(lease.valid_until),
        .declined_remaining_nanoseconds =
            lease.declined ? remaining(lease.declined_until) : 0,
        .last_client_transaction_ago_nanoseconds =
            elapsed(lease.last_client_transaction),
        .pool_index = lease.pool_index,
        .prefix_length = lease.prefix_length,
        .declined = lease.declined});
  }
  return state;
}

bool LeaseRepository::validate_checkpoint(
    std::span<const LeaseCheckpoint> state) const noexcept {
  if (state.size() > leases_.size())
    return false;
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &lease = state[index];
    const auto pool_count = lease.client.kind == LeaseKind::prefix
                                ? prefix_pool_count_
                                : address_pool_count_;
    if (!valid_client(lease.client) || lease.pool_index >= pool_count)
      return false;
    const auto expected_prefix =
        lease.client.kind == LeaseKind::prefix
            ? prefix_pools_[lease.pool_index].delegated_length
            : std::uint8_t{128U};
    if (lease.prefix_length != expected_prefix ||
        (lease.client.kind == LeaseKind::prefix
             ? !ip::contains(prefix_pools_[lease.pool_index].prefix,
                             lease.value) ||
                   ip::mask(lease.value, lease.prefix_length) != lease.value
             : !ip::contains(address_pools_[lease.pool_index].prefix,
                             lease.value)) ||
        lease.preferred_remaining_nanoseconds < -1 ||
        lease.valid_remaining_nanoseconds < -1 ||
        lease.declined_remaining_nanoseconds < -1 ||
        lease.last_client_transaction_ago_nanoseconds < 0 ||
        (lease.declined
             ? lease.preferred_remaining_nanoseconds != 0 ||
                   lease.valid_remaining_nanoseconds != 0 ||
                   lease.declined_remaining_nanoseconds == 0
             : (lease.valid_remaining_nanoseconds == -1
                    ? false
                    : lease.preferred_remaining_nanoseconds == -1 ||
                          lease.preferred_remaining_nanoseconds >
                              lease.valid_remaining_nanoseconds) ||
                   lease.valid_remaining_nanoseconds == 0 ||
                   lease.declined_remaining_nanoseconds != 0))
      return false;
    for (std::size_t previous = 0; previous < index; ++previous) {
      const auto &other = state[previous];
      if ((!lease.declined && !other.declined &&
           same_client(lease.client, other.client)) ||
          (lease.client.kind == LeaseKind::prefix &&
           other.client.kind == LeaseKind::prefix &&
           (ip::contains({.network = lease.value,
                          .length = lease.prefix_length},
                         other.value) ||
            ip::contains({.network = other.value,
                          .length = other.prefix_length},
                         lease.value))) ||
          (lease.client.kind != LeaseKind::prefix &&
           other.client.kind != LeaseKind::prefix &&
           lease.value == other.value))
        return false;
    }
  }
  return true;
}

bool LeaseRepository::restore(std::span<const LeaseCheckpoint> state,
                              Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;
  // The staged array is a cold checkpoint value. Live leases remain untouched
  // until every record has been converted back to owner-local deadlines.
  // A maximum-size DHCPv6 repository is deliberately dense. WebAssembly
  // pthreads have a fixed stack, so a cold restore must stage this arena on
  // the heap before one atomic publication instead of consuming the worker
  // stack. Allocation failure leaves the live repository unchanged.
  auto staged = std::unique_ptr<
      std::array<Lease, device_catalog::dhcpv6_leases_per_server>>{};
  try {
    staged = std::make_unique<
        std::array<Lease, device_catalog::dhcpv6_leases_per_server>>();
  } catch (...) {
    return false;
  }
  for (std::size_t index = 0; index < state.size(); ++index) {
    const auto &saved = state[index];
    (*staged)[index] = {
        .client = saved.client,
        .value = saved.value,
        .last_client_address = saved.last_client_address,
        .preferred_until =
            saved.declined
                ? Clock::time_point{}
                : saved.preferred_remaining_nanoseconds == -1
                      ? Clock::time_point::max()
                      : now + std::chrono::nanoseconds{
                                  saved.preferred_remaining_nanoseconds},
        .valid_until =
            saved.declined
                ? Clock::time_point{}
                : saved.valid_remaining_nanoseconds == -1
                      ? Clock::time_point::max()
                      : now + std::chrono::nanoseconds{
                                  saved.valid_remaining_nanoseconds},
        .declined_until =
            saved.declined
                ? saved.declined_remaining_nanoseconds == -1
                      ? Clock::time_point::max()
                      : now + std::chrono::nanoseconds{
                                  saved.declined_remaining_nanoseconds}
                : Clock::time_point{},
        .last_client_transaction =
            now - std::chrono::nanoseconds{
                      saved.last_client_transaction_ago_nanoseconds},
        .pool_index = saved.pool_index,
        .prefix_length = saved.prefix_length,
        .occupied = true,
        .declined = saved.declined};
  }
  leases_ = std::move(*staged);
  return true;
}

PartnerUpdateStatus LeaseRepository::apply_partner_updates(
    std::span<const failover::BindingUpdateView> updates,
    std::uint32_t absolute_now, Clock::time_point now) noexcept {
  if (updates.empty() ||
      updates.size() > device_catalog::dhcp_failover_updates_in_flight)
    return PartnerUpdateStatus::invalid_update;

  std::unique_ptr<LeaseRepository> staged;
  try {
    // The repository contains profile-sized fixed arenas. Staging on the heap
    // avoids exhausting a Wasm pthread stack while preserving BNDUPD atomicity.
    staged = std::make_unique<LeaseRepository>(*this);
  } catch (...) {
    return PartnerUpdateStatus::resource_exhausted;
  }

  bool changed{};
  for (const auto &update : updates) {
    const bool delegated =
        update.association ==
            failover::IdentityAssociationType::delegated_prefix ||
        update.association ==
            failover::IdentityAssociationType::unassociated_prefix;
    if ((delegated && update.prefix_length > 128U) ||
        (!delegated && update.prefix_length != 128U) ||
        update.start_time_of_state == 0U)
      return PartnerUpdateStatus::invalid_update;

    const LeasePool *selected_pool{};
    std::uint16_t selected_index{};
    const auto select_pool = [&](const auto &pools, std::size_t count) {
      for (std::size_t index{}; index < count; ++index) {
        const auto &pool = pools[index];
        const bool contains_value =
            ip::contains(pool.prefix, update.value) &&
            (!delegated || pool.delegated_length == update.prefix_length);
        if (!contains_value)
          continue;
        if (selected_pool) {
          selected_pool = nullptr;
          selected_index = std::numeric_limits<std::uint16_t>::max();
          return;
        }
        selected_pool = &pool;
        selected_index = static_cast<std::uint16_t>(index);
      }
    };
    if (delegated)
      select_pool(staged->prefix_pools_, staged->prefix_pool_count_);
    else
      select_pool(staged->address_pools_, staged->address_pool_count_);
    if (selected_index == std::numeric_limits<std::uint16_t>::max())
      return PartnerUpdateStatus::ambiguous_value;
    if (!selected_pool)
      return PartnerUpdateStatus::unknown_value;

    auto cursor = std::find_if(
        staged->failover_bindings_.begin(),
        staged->failover_bindings_.end(), [&](const auto &candidate) {
          return candidate.occupied && candidate.value == update.value &&
                 candidate.prefix_length == update.prefix_length &&
                 candidate.association == update.association;
        });
    if (cursor != staged->failover_bindings_.end() &&
        cursor->state_started_absolute >= update.start_time_of_state)
      continue;
    if (cursor == staged->failover_bindings_.end()) {
      cursor = std::find_if(staged->failover_bindings_.begin(),
                            staged->failover_bindings_.end(),
                            [](const auto &candidate) {
                              return !candidate.occupied;
                            });
      if (cursor == staged->failover_bindings_.end())
        return PartnerUpdateStatus::resource_exhausted;
    }

    const auto kind =
        delegated
            ? LeaseKind::prefix
            : update.association ==
                      failover::IdentityAssociationType::temporary
                  ? LeaseKind::temporary
                  : LeaseKind::non_temporary;
    ClientIdentity identity{.link_identity = selected_pool->link_identity,
                            .iaid = update.iaid,
                            .kind = kind};
    if (!update.client_identifier.empty()) {
      if (update.client_identifier.size() > identity.duid.size())
        return PartnerUpdateStatus::invalid_update;
      identity.duid_octets =
          static_cast<std::uint16_t>(update.client_identifier.size());
      std::ranges::copy(update.client_identifier, identity.duid.begin());
    }
    const bool active =
        update.status == failover::BindingStatus::active;
    if (active && !valid_client(identity))
      return PartnerUpdateStatus::invalid_update;

    auto lease = std::find_if(
        staged->leases_.begin(), staged->leases_.end(),
        [&](const auto &candidate) {
          return candidate.occupied && candidate.value == update.value &&
                 candidate.prefix_length == update.prefix_length;
        });
    if (active || update.status == failover::BindingStatus::abandoned) {
      if (lease == staged->leases_.end()) {
        lease = std::find_if(staged->leases_.begin(), staged->leases_.end(),
                             [](const auto &candidate) {
                               return !candidate.occupied;
                             });
        if (lease == staged->leases_.end())
          return PartnerUpdateStatus::resource_exhausted;
      }
      if (!valid_client(identity))
        return PartnerUpdateStatus::invalid_update;
      const auto deadline = [&](std::uint32_t absolute) {
        return absolute <= absolute_now
                   ? now
                   : now + std::chrono::seconds{absolute - absolute_now};
      };
      const auto preferred_absolute =
          update.base_time >
                  std::numeric_limits<std::uint32_t>::max() -
                      update.preferred_lifetime
              ? std::numeric_limits<std::uint32_t>::max()
              : update.base_time + update.preferred_lifetime;
      const auto valid_absolute =
          update.expiration_time.value_or(
              update.base_time >
                      std::numeric_limits<std::uint32_t>::max() -
                          update.valid_lifetime
                  ? std::numeric_limits<std::uint32_t>::max()
                  : update.base_time + update.valid_lifetime);
      *lease = {.client = identity,
                .value = update.value,
                .preferred_until =
                    active ? deadline(preferred_absolute)
                           : Clock::time_point{},
                .valid_until =
                    active ? deadline(valid_absolute) : Clock::time_point{},
                .declined_until =
                    active ? Clock::time_point{} : Clock::time_point::max(),
                .last_client_transaction =
                    update.client_last_transaction_time &&
                            *update.client_last_transaction_time <= absolute_now
                        ? now - std::chrono::seconds{
                                    absolute_now -
                                    *update.client_last_transaction_time}
                        : now,
                .pool_index = selected_index,
                .prefix_length = update.prefix_length,
                .occupied = true,
                .declined = !active};
    } else if (lease != staged->leases_.end()) {
      *lease = {};
    }
    *cursor = {.value = update.value,
               .association = update.association,
               .status = update.status,
               .state_started_absolute = update.start_time_of_state,
               .prefix_length = update.prefix_length,
               .occupied = true};
    changed = true;
  }

  if (!changed)
    return PartnerUpdateStatus::duplicate;
  *this = std::move(*staged);
  return PartnerUpdateStatus::applied;
}

std::vector<FailoverBindingCheckpoint>
LeaseRepository::failover_checkpoint() const {
  std::vector<FailoverBindingCheckpoint> result;
  result.reserve(std::count_if(
      failover_bindings_.begin(), failover_bindings_.end(),
      [](const auto &binding) { return binding.occupied; }));
  for (const auto &binding : failover_bindings_)
    if (binding.occupied)
      result.push_back({.value = binding.value,
                        .association = binding.association,
                        .status = binding.status,
                        .state_started_absolute =
                            binding.state_started_absolute,
                        .prefix_length = binding.prefix_length,
                        .occupied = true});
  return result;
}

bool LeaseRepository::validate_failover_checkpoint(
    std::span<const FailoverBindingCheckpoint> state) const noexcept {
  if (state.size() > failover_bindings_.size())
    return false;
  for (std::size_t index{}; index < state.size(); ++index) {
    const auto &binding = state[index];
    if (!binding.occupied || binding.state_started_absolute == 0U ||
        binding.prefix_length > 128U ||
        binding.association >
            failover::IdentityAssociationType::unassociated_prefix ||
        binding.status > failover::BindingStatus::reset)
      return false;
    for (std::size_t prior{}; prior < index; ++prior)
      if (state[prior].value == binding.value &&
          state[prior].prefix_length == binding.prefix_length &&
          state[prior].association == binding.association)
        return false;
  }
  return true;
}

bool LeaseRepository::restore_failover_checkpoint(
    std::span<const FailoverBindingCheckpoint> state) noexcept {
  if (!validate_failover_checkpoint(state))
    return false;
  failover_bindings_ = {};
  for (std::size_t index{}; index < state.size(); ++index)
    failover_bindings_[index] = {
        .value = state[index].value,
        .association = state[index].association,
        .status = state[index].status,
        .state_started_absolute = state[index].state_started_absolute,
        .prefix_length = state[index].prefix_length,
        .occupied = true};
  return true;
}

bool LeaseRepository::note_client_address(const ClientIdentity &client,
                                          packet::Ipv6 address) noexcept {
  auto *lease = find(client);
  if (!lease || ip::is_unspecified(address) || ip::is_multicast(address))
    return false;
  lease->last_client_address = address;
  return true;
}

std::size_t LeaseRepository::clear(const LeaseClearFilter &filter,
                                   Clock::time_point now) noexcept {
  if (filter.prefix_length > 128U)
    return 0U;
  expire(now);

  const auto state_of = [](const Lease &lease) noexcept {
    // Preview-only Advertise values never become bindings. An active binding
    // is therefore stable, while a declined value is held until its RFC
    // conflict hold-down expires. Other SR OS states belong to failover or
    // subscriber features and correctly match no record in this owner.
    return lease.declined ? OperationalLeaseState::held
                          : OperationalLeaseState::stable;
  };
  const auto type_of = [](const Lease &lease) noexcept {
    return lease.client.kind == LeaseKind::prefix
               ? LeaseClearFilter::Type::pd
               : LeaseClearFilter::Type::wan;
  };
  const ip::Ipv6Prefix selected{
      .network = ip::mask(filter.value, filter.prefix_length),
      .length = filter.prefix_length};

  std::size_t removed{};
  for (auto &lease : leases_) {
    if (!lease.occupied)
      continue;
    if (filter.value_specific &&
        (filter.prefix_length == 128U
             ? lease.value != filter.value
             : !ip::contains(selected, lease.value)))
      continue;
    if (filter.state && *filter.state != state_of(lease))
      continue;
    if (filter.type && *filter.type != type_of(lease))
      continue;
    lease = {};
    ++removed;
  }
  return removed;
}

} // namespace router::dhcpv6
