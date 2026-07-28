// Validation for canonical Base DHCPv6 configuration. It performs no packet
// work and allocates no memory, so a candidate can be checked before replacing
// the single control-plane owner or starting an SPSC programming transaction.

#include "router/dhcpv6_configuration.hpp"

#include <algorithm>

namespace router::dhcpv6::configuration {

Status validate(const RouterConfiguration &configuration,
                bool allow_incomplete) noexcept {
  if (configuration.servers.size() >
      device_catalog::dhcpv6_servers_per_router)
    return Status::resource_exhausted;
  for (std::size_t server_index{}; server_index < configuration.servers.size();
       ++server_index) {
    const auto &server = configuration.servers[server_index];
    if (server.instance_id == 0U || server.name.empty() ||
        server.name.size() > 32U ||
        server.duid_octets > server.duid.size() ||
        (!allow_incomplete &&
         !packet::dhcpv6::valid_duid(
             std::span<const std::uint8_t>{server.duid}.first(
                 server.duid_octets))))
      return Status::invalid_name;
    if (server.description.size() > 80U)
      return Status::invalid_description;
    if (server.default_preferred_lifetime_seconds >
            server.default_valid_lifetime_seconds ||
        server.default_renewal_time_seconds >
            server.default_rebinding_time_seconds ||
        server.default_rebinding_time_seconds >
            server.default_valid_lifetime_seconds)
      return Status::invalid_lifetime;
    if (server.pools.size() >
            device_catalog::dhcpv6_address_pools_per_server +
                device_catalog::dhcpv6_prefix_pools_per_server ||
        server.dns_recursive_servers.size() >
            packet::dhcpv6::maximum_message_octets /
                packet::Ipv6{}.size())
      return Status::resource_exhausted;
    for (std::size_t prior{}; prior < server_index; ++prior)
      if (configuration.servers[prior].name == server.name ||
          configuration.servers[prior].instance_id == server.instance_id)
        return Status::duplicate_server;

    for (std::size_t pool_index{}; pool_index < server.pools.size();
         ++pool_index) {
      const auto &pool = server.pools[pool_index];
      if (pool.name.empty() || pool.name.size() > 32U)
        return Status::invalid_name;
      if (pool.description.size() > 80U)
        return Status::invalid_description;
      if (pool.minimum_delegated_length < 48U ||
          pool.maximum_delegated_length > 127U ||
          pool.minimum_delegated_length > pool.delegated_length ||
          pool.delegated_length > pool.maximum_delegated_length)
        return Status::invalid_prefix;
      for (std::size_t prior{}; prior < pool_index; ++prior)
        if (server.pools[prior].name == pool.name)
          return Status::duplicate_pool;
      if (!allow_incomplete && pool.prefixes.empty())
        return Status::invalid_prefix;
      for (std::size_t prefix_index{}; prefix_index < pool.prefixes.size();
           ++prefix_index) {
        const auto &prefix = pool.prefixes[prefix_index];
        const bool canonical =
            prefix.aggregate.length <= 128U &&
            ip::mask(prefix.aggregate.network, prefix.aggregate.length) ==
                prefix.aggregate.network;
        const auto preferred =
            prefix.preferred_lifetime_configured
                ? prefix.preferred_lifetime_seconds
                : server.default_preferred_lifetime_seconds;
        const auto valid = prefix.valid_lifetime_configured
                               ? prefix.valid_lifetime_seconds
                               : server.default_valid_lifetime_seconds;
        const auto renewal = prefix.renewal_time_configured
                                 ? prefix.renewal_time_seconds
                                 : server.default_renewal_time_seconds;
        const auto rebinding = prefix.rebinding_time_configured
                                   ? prefix.rebinding_time_seconds
                                   : server.default_rebinding_time_seconds;
        // The pool-wide minimum may be shorter than one aggregate. It is a
        // client hint policy, not a promise that every aggregate can supply
        // that length. For a /56 aggregate and a configured 48..64 policy,
        // the effective range on this aggregate is 56..64. Reject only when
        // neither the preferred nor maximum delegated length can fit inside
        // the aggregate.
        if (!canonical || prefix.aggregate.length == 0U ||
            (!prefix.wan_host && !prefix.delegated_prefix) ||
            (prefix.delegated_prefix &&
             (pool.delegated_length < prefix.aggregate.length ||
              pool.maximum_delegated_length < prefix.aggregate.length)))
          return Status::invalid_prefix;
        if (preferred > valid || renewal > rebinding || rebinding > valid)
          return Status::invalid_lifetime;
        if (std::ranges::none_of(prefix.allocation_secret,
                                 [](std::uint8_t value) {
                                   return value != 0U;
                                 }))
          return Status::missing_entropy;
        for (std::size_t prior{}; prior < prefix_index; ++prior)
          if (pool.prefixes[prior].aggregate == prefix.aggregate)
            return Status::duplicate_prefix;
      }
    }
  }
  return Status::valid;
}

} // namespace router::dhcpv6::configuration
