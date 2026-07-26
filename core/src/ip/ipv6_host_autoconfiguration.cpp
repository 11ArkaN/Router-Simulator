// RFC 4861 Router Discovery, RFC 4862 SLAAC lifetime and RFC 8106 RDNSS
// repositories for one host interface. All deadlines use the owner's steady
// clock, and every resource bound comes from the generated release catalog.

#include "router/ipv6_host_autoconfiguration.hpp"

#include <algorithm>
#include <limits>

namespace router::host {
namespace {

using Clock = Ipv6HostAutoconfiguration::Clock;

// RFC 4862 section 5.5.3 protects an existing address against an
// unauthenticated advertisement that tries to reduce its Valid Lifetime below
// two hours. This is a protocol constant, not a configurable platform limit.
constexpr auto minimum_protected_valid_lifetime = std::chrono::hours{2};
constexpr std::uint8_t ethernet_slaac_prefix_length =
    static_cast<std::uint8_t>(
        ip::ipv6_address_bits -
        Ipv6HostAutoconfiguration::ethernet_interface_identifier_octets * 8U);

Clock::time_point deadline(std::uint32_t lifetime,
                           Clock::time_point now) noexcept {
  // All-one-bits is infinity in PIO and RDNSS lifetime fields. Mapping it to
  // time_point::max avoids overflowing a finite steady-clock duration.
  return lifetime == device_catalog::ra_infinite_lifetime
             ? Clock::time_point::max()
             : now + std::chrono::seconds{lifetime};
}

RelativeIpv6Lifetime relative_lifetime(Clock::time_point value,
                                       Clock::time_point now) noexcept {
  // A non-positive finite remainder is retained as zero. The first owner turn
  // after restore removes it, matching a checkpoint taken on the exact expiry
  // boundary without manufacturing one extra clock tick of validity.
  if (value == Clock::time_point::max())
    return {.infinite = true};
  const auto remaining = value > now ? value - now : Clock::duration::zero();
  return {.remaining_nanoseconds =
              std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                  .count()};
}

Clock::time_point absolute_lifetime(const RelativeIpv6Lifetime &value,
                                    Clock::time_point now) noexcept {
  return value.infinite
             ? Clock::time_point::max()
             : now + std::chrono::nanoseconds{value.remaining_nanoseconds};
}

bool valid_relative_lifetime(const RelativeIpv6Lifetime &value) noexcept {
  // Every finite RA option uses a 32-bit seconds field with all-one-bits
  // reserved for infinity. The derived upper bound accepts every wire value
  // that can be represented by RFC 4862 or RFC 8106, without a project-local
  // one-day or one-year truncation.
  constexpr auto maximum_finite = std::chrono::seconds{
      static_cast<std::int64_t>(device_catalog::ra_infinite_lifetime) - 1};
  constexpr auto maximum_finite_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(maximum_finite)
          .count();
  return value.infinite ? value.remaining_nanoseconds == 0
                        : value.remaining_nanoseconds >= 0 &&
                              value.remaining_nanoseconds <=
                                  maximum_finite_nanoseconds;
}

bool lifetime_not_greater(const RelativeIpv6Lifetime &left,
                          const RelativeIpv6Lifetime &right) noexcept {
  if (right.infinite)
    return true;
  return !left.infinite &&
         left.remaining_nanoseconds <= right.remaining_nanoseconds;
}

template <typename Range, typename Equal>
bool has_duplicate(const Range &range, Equal equal) noexcept {
  for (auto left = range.begin(); left != range.end(); ++left)
    for (auto right = left + 1; right != range.end(); ++right)
      if (equal(*left, *right))
        return true;
  return false;
}

template <typename Entry, std::size_t Size>
Entry *free_or_earliest(std::array<Entry, Size> &entries,
                        bool &evicted) noexcept {
  const auto free = std::find_if(entries.begin(), entries.end(),
                                 [](const Entry &entry) {
                                   return !entry.occupied;
                                 });
  if (free != entries.end())
    return &*free;
  // Router and DNS repositories have standards-defined permission to retain a
  // bounded subset. The earliest-expiring entry loses the least remaining
  // information and makes the local policy deterministic.
  evicted = true;
  return &*std::min_element(entries.begin(), entries.end(),
                            [](const Entry &left, const Entry &right) {
                              return left.expires < right.expires;
                            });
}

packet::Ipv6 compose_address(
    const ip::Ipv6Prefix &prefix,
    const std::array<std::uint8_t,
                     Ipv6HostAutoconfiguration::
                         ethernet_interface_identifier_octets> &iid) noexcept {
  auto result = ip::mask(prefix.network, prefix.length);
  std::copy(iid.begin(), iid.end(),
            result.end() - static_cast<std::ptrdiff_t>(iid.size()));
  return result;
}

StableInterfaceIdentifier select_interface_identifier(
    InterfaceIdentifierMode mode,
    const StableInterfaceIdentifier &modified_eui64,
    const StableIidSecret &stable_secret,
    std::span<const std::uint8_t> network_id, std::uint64_t interface_id,
    const ip::Ipv6Prefix &prefix, std::uint32_t dad_counter) noexcept {
  // RFC 7217 varies the IID for every prefix and DAD counter. Modified EUI-64
  // intentionally remains one link-layer-derived value across prefixes.
  return mode == InterfaceIdentifierMode::stable_opaque
             ? stable_opaque_interface_identifier(
                   prefix, interface_id, network_id, dad_counter, stable_secret)
             : modified_eui64;
}

std::optional<StableInterfaceIdentifier> select_acceptable_identifier(
    InterfaceIdentifierMode mode,
    const StableInterfaceIdentifier &modified_eui64,
    const StableIidSecret &stable_secret,
    std::span<const std::uint8_t> network_id, std::uint64_t interface_id,
    const ip::Ipv6Prefix &prefix, std::uint32_t &dad_counter) noexcept {
  if (mode == InterfaceIdentifierMode::modified_eui64)
    return modified_eui64;

  // RFC 7217 says a reserved result is handled like a DAD conflict. The same
  // generated retry bound therefore limits pre-DAD rejection as well as
  // collisions observed on the wire. No unacceptable IID becomes tentative.
  for (;;) {
    const auto iid = stable_opaque_interface_identifier(
        prefix, interface_id, network_id, dad_counter, stable_secret);
    if (!is_reserved_ipv6_interface_identifier(iid))
      return iid;
    if (dad_counter >= device_catalog::ipv6_stable_iid_dad_retries)
      return std::nullopt;
    ++dad_counter;
  }
}

bool nonzero_secret(const StableIidSecret &secret) noexcept {
  return std::any_of(secret.begin(), secret.end(),
                     [](std::uint8_t value) { return value != 0U; });
}

} // namespace

bool Ipv6HostAutoconfiguration::configure(
    std::uint64_t interface_id,
    const Ipv6InterfaceIdentifierConfiguration &identifier,
    std::uint32_t link_mtu) noexcept {
  if (!interface_id || link_mtu < packet::ipv6_minimum_link_mtu ||
      identifier.network_id_octets > identifier.network_id.size() ||
      identifier.mode > InterfaceIdentifierMode::stable_opaque ||
      (identifier.mode == InterfaceIdentifierMode::stable_opaque &&
       !nonzero_secret(identifier.stable_secret)))
    return false;
  default_routers_.fill({});
  on_link_prefixes_.fill({});
  addresses_.fill({});
  rdnss_.fill({});
  interface_id_ = interface_id;
  interface_identifier_ = identifier.modified_eui64;
  stable_secret_ = identifier.stable_secret;
  network_id_ = identifier.network_id;
  network_id_octets_ = identifier.network_id_octets;
  interface_identifier_mode_ = identifier.mode;
  link_mtu_ = link_mtu;
  effective_mtu_ = link_mtu;
  current_hop_limit_ = device_catalog::default_ip_hop_limit;
  reachable_time_milliseconds_ = static_cast<std::uint32_t>(
      device_catalog::nd_base_reachable_time.count());
  retrans_timer_milliseconds_ =
      static_cast<std::uint32_t>(device_catalog::nd_retrans_timer.count());
  managed_configuration_ = false;
  other_configuration_ = false;
  next_rdnss_order_ = 1U;
  return true;
}

RouterAdvertisementApply Ipv6HostAutoconfiguration::process(
    const packet::nd::RouterAdvertisementView &advertisement,
    bool authenticated, Clock::time_point now) noexcept {
  if (!interface_id_ || !ip::is_link_local(advertisement.source))
    return RouterAdvertisementApply::invalid_interface;
  expire(now);
  bool resource_drop{};

  auto router = std::find_if(
      default_routers_.begin(), default_routers_.end(),
      [&](const auto &entry) {
        return entry.occupied && entry.address == advertisement.source;
      });
  if (!advertisement.router_lifetime_seconds) {
    if (router != default_routers_.end())
      *router = {};
  } else {
    DefaultRouterEntry *target =
        router != default_routers_.end()
            ? &*router
            : free_or_earliest(default_routers_, resource_drop);
    *target = {.address = advertisement.source,
               .expires = deadline(advertisement.router_lifetime_seconds, now),
               .preference = advertisement.preference,
               .occupied = true};
  }

  for (std::size_t index = 0; index < advertisement.prefix_count; ++index) {
    const auto &information = advertisement.prefixes[index];
    const auto canonical = ip::Ipv6Prefix{
        .network = ip::mask(information.prefix.network,
                            information.prefix.length),
        .length = information.prefix.length};
    const bool usable_prefix =
        canonical.length <= ip::ipv6_address_bits &&
        !ip::is_link_local(canonical.network) &&
        !ip::is_multicast(canonical.network);
    auto on_link = std::find_if(
        on_link_prefixes_.begin(), on_link_prefixes_.end(),
        [&](const auto &entry) {
          return entry.occupied && entry.prefix == canonical;
        });
    if (usable_prefix && information.on_link) {
      if (!information.valid_lifetime_seconds) {
        if (on_link != on_link_prefixes_.end())
          *on_link = {};
      } else {
        OnLinkPrefixEntry *target =
            on_link != on_link_prefixes_.end()
                ? &*on_link
                : free_or_earliest(on_link_prefixes_, resource_drop);
        *target = {.prefix = canonical,
                   .expires = deadline(information.valid_lifetime_seconds, now),
                   .occupied = true};
      }
    }

    // Ethernet SLAAC currently has a 64-bit interface identifier. Prefixes of
    // another length remain valid for on-link discovery but cannot form an
    // address until a link type supplies a matching IID length.
    if (!usable_prefix || !information.autonomous ||
        canonical.length != ethernet_slaac_prefix_length ||
        information.preferred_lifetime_seconds >
            information.valid_lifetime_seconds)
      continue;
    auto address = std::find_if(
        addresses_.begin(), addresses_.end(), [&](const auto &entry) {
          return entry.occupied && entry.prefix == canonical;
        });
    if (address == addresses_.end()) {
      if (!information.valid_lifetime_seconds)
        continue;
      const auto free = std::find_if(addresses_.begin(), addresses_.end(),
                                     [](const auto &entry) {
                                       return !entry.occupied;
                                     });
      if (free == addresses_.end()) {
        // Unlike RDNSS, silently evicting a still-valid address could break an
        // established transport. Ignore only the new PIO and report pressure.
        resource_drop = true;
        continue;
      }
      std::uint32_t dad_counter{};
      const auto iid = select_acceptable_identifier(
          interface_identifier_mode_, interface_identifier_, stable_secret_,
          std::span<const std::uint8_t>{network_id_}.first(network_id_octets_),
          interface_id_, canonical, dad_counter);
      if (!iid)
        continue;
      *free = {.address = compose_address(canonical, *iid),
               .prefix = canonical,
               .preferred_until =
                   deadline(information.preferred_lifetime_seconds, now),
               .valid_until =
                   deadline(information.valid_lifetime_seconds, now),
               .state = AutoconfigAddressState::tentative,
               .dad_counter = dad_counter,
               .occupied = true};
      continue;
    }

    address->preferred_until =
        deadline(information.preferred_lifetime_seconds, now);
    const auto advertised_valid = information.valid_lifetime_seconds;
    const auto remaining = address->valid_until == Clock::time_point::max()
                               ? Clock::duration::max()
                               : address->valid_until - now;
    if (authenticated ||
        advertised_valid >
            std::chrono::duration_cast<std::chrono::seconds>(
                minimum_protected_valid_lifetime)
                .count() ||
        std::chrono::seconds{advertised_valid} > remaining) {
      address->valid_until = deadline(advertised_valid, now);
    } else if (remaining > minimum_protected_valid_lifetime) {
      address->valid_until = now + minimum_protected_valid_lifetime;
    }
    if (address->state != AutoconfigAddressState::tentative)
      address->state = address->preferred_until <= now
                           ? AutoconfigAddressState::deprecated
                           : AutoconfigAddressState::preferred;
  }

  for (std::size_t index = 0; index < advertisement.rdnss.count; ++index) {
    const auto &server = advertisement.rdnss.servers[index];
    if (ip::is_unspecified(server.address) || ip::is_multicast(server.address))
      continue;
    auto existing = std::find_if(
        rdnss_.begin(), rdnss_.end(), [&](const auto &entry) {
          return entry.occupied && entry.interface_id == interface_id_ &&
                 entry.address == server.address;
        });
    if (!server.lifetime_seconds) {
      if (existing != rdnss_.end())
        *existing = {};
      continue;
    }
    RdnssEntry *target = existing != rdnss_.end()
                             ? &*existing
                             : free_or_earliest(rdnss_, resource_drop);
    *target = {.address = server.address,
               .expires = deadline(server.lifetime_seconds, now),
               .interface_id = interface_id_,
               .order = next_rdnss_order_++,
               .occupied = true};
  }

  if (advertisement.current_hop_limit)
    current_hop_limit_ = advertisement.current_hop_limit;
  if (advertisement.reachable_time_milliseconds)
    reachable_time_milliseconds_ =
        advertisement.reachable_time_milliseconds;
  if (advertisement.retrans_timer_milliseconds)
    retrans_timer_milliseconds_ =
        advertisement.retrans_timer_milliseconds;
  if (advertisement.advertised_mtu &&
      *advertisement.advertised_mtu >= packet::ipv6_minimum_link_mtu &&
      *advertisement.advertised_mtu <= link_mtu_)
    effective_mtu_ = *advertisement.advertised_mtu;
  managed_configuration_ = advertisement.managed_configuration;
  other_configuration_ = advertisement.other_configuration;
  return resource_drop ? RouterAdvertisementApply::applied_with_resource_drop
                       : RouterAdvertisementApply::applied;
}

bool Ipv6HostAutoconfiguration::confirm_dad(
    const packet::Ipv6 &address, bool duplicate,
    Clock::time_point now) noexcept {
  auto entry = std::find_if(addresses_.begin(), addresses_.end(),
                            [&](const auto &candidate) {
                              return candidate.occupied &&
                                     candidate.address == address &&
                                     candidate.state ==
                                         AutoconfigAddressState::tentative;
                            });
  if (entry == addresses_.end())
    return false;
  if (duplicate &&
      interface_identifier_mode_ == InterfaceIdentifierMode::stable_opaque &&
      entry->dad_counter < device_catalog::ipv6_stable_iid_dad_retries &&
      entry->valid_until > now) {
    // RFC 7217 section 6 forbids falling back to a MAC-derived IID. Increment
    // the persisted tuple counter and leave the replacement tentative so the
    // endpoint starts a new real DAD exchange after its bounded random delay.
    ++entry->dad_counter;
    const auto iid = select_acceptable_identifier(
        interface_identifier_mode_, interface_identifier_, stable_secret_,
        std::span<const std::uint8_t>{network_id_}.first(network_id_octets_),
        interface_id_, entry->prefix, entry->dad_counter);
    if (iid) {
      entry->address = compose_address(entry->prefix, *iid);
      return true;
    }
    // Exhausting the bounded search fails this prefix. Falling back to the
    // modified EUI-64 value would violate RFC 7217 section 6.
    *entry = {};
    return true;
  }
  if (duplicate || entry->valid_until <= now) {
    *entry = {};
    return true;
  }
  entry->state = entry->preferred_until <= now
                     ? AutoconfigAddressState::deprecated
                     : AutoconfigAddressState::preferred;
  return true;
}

void Ipv6HostAutoconfiguration::expire(Clock::time_point now) noexcept {
  for (auto &entry : default_routers_)
    if (entry.occupied && entry.expires <= now)
      entry = {};
  for (auto &entry : on_link_prefixes_)
    if (entry.occupied && entry.expires <= now)
      entry = {};
  for (auto &entry : rdnss_)
    if (entry.occupied && entry.expires <= now)
      entry = {};
  for (auto &entry : addresses_) {
    if (!entry.occupied)
      continue;
    if (entry.valid_until <= now) {
      entry = {};
      continue;
    }
    if (entry.state == AutoconfigAddressState::preferred &&
        entry.preferred_until <= now)
      entry.state = AutoconfigAddressState::deprecated;
  }
}

std::optional<Ipv6HostAutoconfiguration::Clock::time_point>
Ipv6HostAutoconfiguration::next_deadline() const noexcept {
  std::optional<Clock::time_point> result;
  const auto consider = [&](Clock::time_point value) {
    if (value != Clock::time_point::max() && (!result || value < *result))
      result = value;
  };
  for (const auto &entry : default_routers_)
    if (entry.occupied)
      consider(entry.expires);
  for (const auto &entry : on_link_prefixes_)
    if (entry.occupied)
      consider(entry.expires);
  for (const auto &entry : rdnss_)
    if (entry.occupied)
      consider(entry.expires);
  for (const auto &entry : addresses_)
    if (entry.occupied) {
      consider(entry.preferred_until);
      consider(entry.valid_until);
    }
  return result;
}

Ipv6HostAutoconfigurationCheckpoint
Ipv6HostAutoconfiguration::checkpoint(Clock::time_point now) const {
  Ipv6HostAutoconfigurationCheckpoint state;
  state.default_routers.reserve(default_routers_.size());
  for (const auto &entry : default_routers_)
    if (entry.occupied)
      state.default_routers.push_back(
          {.address = entry.address,
           .lifetime = relative_lifetime(entry.expires, now),
           .preference = entry.preference});
  state.on_link_prefixes.reserve(on_link_prefixes_.size());
  for (const auto &entry : on_link_prefixes_)
    if (entry.occupied)
      state.on_link_prefixes.push_back(
          {.prefix = entry.prefix,
           .lifetime = relative_lifetime(entry.expires, now)});
  state.addresses.reserve(addresses_.size());
  for (const auto &entry : addresses_)
    if (entry.occupied)
      state.addresses.push_back(
          {.address = entry.address,
           .prefix = entry.prefix,
           .preferred_lifetime =
               relative_lifetime(entry.preferred_until, now),
           .valid_lifetime = relative_lifetime(entry.valid_until, now),
           .state = entry.state,
           .dad_counter = entry.dad_counter});
  state.rdnss.reserve(rdnss_.size());
  for (const auto &entry : rdnss_)
    if (entry.occupied)
      state.rdnss.push_back(
          {.address = entry.address,
           .lifetime = relative_lifetime(entry.expires, now),
           .interface_id = entry.interface_id,
           .order = entry.order});
  state.interface_identifier = interface_identifier_;
  state.stable_secret = stable_secret_;
  state.network_id.assign(network_id_.begin(),
                          network_id_.begin() + network_id_octets_);
  state.interface_id = interface_id_;
  state.next_rdnss_order = next_rdnss_order_;
  state.link_mtu = link_mtu_;
  state.effective_mtu = effective_mtu_;
  state.current_hop_limit = current_hop_limit_;
  state.reachable_time_milliseconds = reachable_time_milliseconds_;
  state.retrans_timer_milliseconds = retrans_timer_milliseconds_;
  state.managed_configuration = managed_configuration_;
  state.other_configuration = other_configuration_;
  state.interface_identifier_mode = interface_identifier_mode_;
  return state;
}

bool Ipv6HostAutoconfiguration::validate_checkpoint(
    const Ipv6HostAutoconfigurationCheckpoint &state) noexcept {
  if (!state.interface_id ||
      state.link_mtu < packet::ipv6_minimum_link_mtu ||
      state.link_mtu > device_catalog::maximum_network_mtu ||
      state.effective_mtu < packet::ipv6_minimum_link_mtu ||
      state.effective_mtu > state.link_mtu ||
      state.current_hop_limit > std::numeric_limits<std::uint8_t>::max() ||
      !state.next_rdnss_order ||
      state.default_routers.size() >
          device_catalog::ipv6_default_routers_per_host_interface ||
      state.on_link_prefixes.size() >
          device_catalog::ipv6_on_link_prefixes_per_host_interface ||
      state.addresses.size() >
          device_catalog::ipv6_slaac_addresses_per_host_interface ||
      state.rdnss.size() >
          device_catalog::ipv6_rdnss_entries_per_host_interface ||
      state.network_id.size() >
          device_catalog::ipv6_stable_iid_network_id_octets ||
      state.interface_identifier_mode >
          InterfaceIdentifierMode::stable_opaque ||
      (state.interface_identifier_mode ==
           InterfaceIdentifierMode::stable_opaque &&
       !nonzero_secret(state.stable_secret)))
    return false;

  for (const auto &entry : state.default_routers)
    if (!ip::is_link_local(entry.address) ||
        !valid_relative_lifetime(entry.lifetime) ||
        entry.preference < packet::nd::RouterPreference::low ||
        entry.preference > packet::nd::RouterPreference::high)
      return false;
  if (has_duplicate(state.default_routers, [](const auto &left,
                                               const auto &right) {
        return left.address == right.address;
      }))
    return false;

  for (const auto &entry : state.on_link_prefixes)
    if (entry.prefix.length > ip::ipv6_address_bits ||
        entry.prefix.network !=
            ip::mask(entry.prefix.network, entry.prefix.length) ||
        ip::is_link_local(entry.prefix.network) ||
        ip::is_multicast(entry.prefix.network) ||
        !valid_relative_lifetime(entry.lifetime))
      return false;
  if (has_duplicate(state.on_link_prefixes, [](const auto &left,
                                                const auto &right) {
        return left.prefix == right.prefix;
      }))
    return false;

  for (const auto &entry : state.addresses) {
    const auto iid = select_interface_identifier(
        state.interface_identifier_mode, state.interface_identifier,
        state.stable_secret, state.network_id, state.interface_id, entry.prefix,
        entry.dad_counter);
    const auto expected = compose_address(entry.prefix, iid);
    if (entry.prefix.length != ethernet_slaac_prefix_length ||
        entry.address != expected ||
        (state.interface_identifier_mode ==
             InterfaceIdentifierMode::stable_opaque &&
         is_reserved_ipv6_interface_identifier(iid)) ||
        ip::is_unspecified(entry.address) ||
        ip::is_multicast(entry.address) ||
        !valid_relative_lifetime(entry.preferred_lifetime) ||
        !valid_relative_lifetime(entry.valid_lifetime) ||
        !lifetime_not_greater(entry.preferred_lifetime,
                              entry.valid_lifetime) ||
        entry.state < AutoconfigAddressState::tentative ||
        entry.state > AutoconfigAddressState::deprecated ||
        (state.interface_identifier_mode ==
             InterfaceIdentifierMode::modified_eui64 &&
         entry.dad_counter != 0U) ||
        entry.dad_counter > device_catalog::ipv6_stable_iid_dad_retries)
      return false;
  }
  if (has_duplicate(state.addresses, [](const auto &left,
                                        const auto &right) {
        return left.address == right.address || left.prefix == right.prefix;
      }))
    return false;

  std::uint64_t greatest_rdnss_order{};
  for (const auto &entry : state.rdnss) {
    if (entry.interface_id != state.interface_id || !entry.order ||
        ip::is_unspecified(entry.address) || ip::is_multicast(entry.address) ||
        !valid_relative_lifetime(entry.lifetime))
      return false;
    greatest_rdnss_order = std::max(greatest_rdnss_order, entry.order);
  }
  if (state.next_rdnss_order <= greatest_rdnss_order ||
      has_duplicate(state.rdnss, [](const auto &left, const auto &right) {
        return left.interface_id == right.interface_id &&
               left.address == right.address;
      }))
    return false;
  return true;
}

bool Ipv6HostAutoconfiguration::restore(
    const Ipv6HostAutoconfigurationCheckpoint &state,
    Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;

  // Validation above is the only failing phase. Installation below uses fixed
  // owner arrays and cannot allocate, retaining the previous live state when a
  // malformed checkpoint is rejected.
  default_routers_.fill({});
  on_link_prefixes_.fill({});
  addresses_.fill({});
  rdnss_.fill({});
  for (std::size_t index = 0; index < state.default_routers.size(); ++index) {
    const auto &source = state.default_routers[index];
    default_routers_[index] = {
        .address = source.address,
        .expires = absolute_lifetime(source.lifetime, now),
        .preference = source.preference,
        .occupied = true};
  }
  for (std::size_t index = 0; index < state.on_link_prefixes.size(); ++index) {
    const auto &source = state.on_link_prefixes[index];
    on_link_prefixes_[index] = {
        .prefix = source.prefix,
        .expires = absolute_lifetime(source.lifetime, now),
        .occupied = true};
  }
  for (std::size_t index = 0; index < state.addresses.size(); ++index) {
    const auto &source = state.addresses[index];
    addresses_[index] = {
        .address = source.address,
        .prefix = source.prefix,
        .preferred_until =
            absolute_lifetime(source.preferred_lifetime, now),
        .valid_until = absolute_lifetime(source.valid_lifetime, now),
        .state = source.state,
        .dad_counter = source.dad_counter,
        .occupied = true};
  }
  for (std::size_t index = 0; index < state.rdnss.size(); ++index) {
    const auto &source = state.rdnss[index];
    rdnss_[index] = {.address = source.address,
                     .expires = absolute_lifetime(source.lifetime, now),
                     .interface_id = source.interface_id,
                     .order = source.order,
                     .occupied = true};
  }
  interface_identifier_ = state.interface_identifier;
  stable_secret_ = state.stable_secret;
  network_id_.fill(0U);
  std::copy(state.network_id.begin(), state.network_id.end(),
            network_id_.begin());
  network_id_octets_ = static_cast<std::uint8_t>(state.network_id.size());
  interface_id_ = state.interface_id;
  next_rdnss_order_ = state.next_rdnss_order;
  link_mtu_ = state.link_mtu;
  effective_mtu_ = state.effective_mtu;
  current_hop_limit_ = state.current_hop_limit;
  reachable_time_milliseconds_ = state.reachable_time_milliseconds;
  retrans_timer_milliseconds_ = state.retrans_timer_milliseconds;
  managed_configuration_ = state.managed_configuration;
  other_configuration_ = state.other_configuration;
  interface_identifier_mode_ = state.interface_identifier_mode;
  return true;
}

} // namespace router::host
