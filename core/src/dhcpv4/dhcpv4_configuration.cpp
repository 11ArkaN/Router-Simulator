// Validation for canonical Base-router DHCPv4 configuration. This module owns
// no runtime state and depends only on generated release data and packet value
// types. Management calls it before commit and the runtime compiler repeats the
// check before replacing a live server, forming a deliberate trust boundary.

#include "router/dhcpv4_configuration.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>

namespace router::dhcpv4::configuration {
namespace {

std::uint32_t integer(packet::Ipv4 value) noexcept {
  return (static_cast<std::uint32_t>(value[0U]) << 24U) |
         (static_cast<std::uint32_t>(value[1U]) << 16U) |
         (static_cast<std::uint32_t>(value[2U]) << 8U) |
         static_cast<std::uint32_t>(value[3U]);
}

std::uint32_t prefix_mask(std::uint8_t length) noexcept {
  // Shifting a 32-bit value by 32 is undefined. Treat /0 explicitly even
  // though SR OS local DHCP subnets require a usable unicast prefix.
  return length == 0U ? 0U : 0xffffffffU << (32U - length);
}

bool valid_name(std::string_view value) noexcept {
  return !value.empty() &&
         value.size() <= device_catalog::dhcpv4_server_name_bytes;
}

bool ranges_overlap(std::uint32_t first_a, std::uint32_t last_a,
                    std::uint32_t first_b, std::uint32_t last_b) noexcept {
  return first_a <= last_b && first_b <= last_a;
}

bool valid_option(const Option &option) noexcept {
  // Pad and End are packet framing, never configured options. An option body
  // is limited by the one-octet DHCPv4 length field after any RFC 3396
  // concatenation has been split by the encoder.
  if (option.code == 0U || option.code == 255U || option.value.size() > 255U)
    return false;
  switch (option.kind) {
  case OptionValueKind::empty:
    return option.value.empty();
  case OptionValueKind::duration:
    return option.value.size() == 4U;
  case OptionValueKind::ipv4_address:
    return !option.value.empty() && option.value.size() % 4U == 0U;
  case OptionValueKind::netbios_node_type:
    return option.value.size() == 1U;
  case OptionValueKind::ascii_string:
  case OptionValueKind::hexadecimal:
    return !option.value.empty();
  }
  return false;
}

} // namespace

Status validate(const RouterConfiguration &configuration,
                bool allow_incomplete) noexcept {
  if (configuration.servers.size() >
      device_catalog::dhcpv4_servers_per_router)
    return Status::resource_exhausted;

  for (std::size_t server_index{}; server_index < configuration.servers.size();
       ++server_index) {
    const auto &server = configuration.servers[server_index];
    if (server.instance_id == 0U || !valid_name(server.name))
      return Status::invalid_name;
    if (server.description.size() > device_catalog::dhcpv4_description_bytes)
      return Status::invalid_description;
    for (std::size_t earlier{}; earlier < server_index; ++earlier)
      if (configuration.servers[earlier].name == server.name ||
          configuration.servers[earlier].instance_id == server.instance_id)
        return Status::duplicate_server;
    if (server.pools.size() > device_catalog::dhcpv4_pools_per_server)
      return Status::resource_exhausted;

    for (std::size_t pool_index{}; pool_index < server.pools.size();
         ++pool_index) {
      const auto &pool = server.pools[pool_index];
      if (!valid_name(pool.name))
        return Status::invalid_name;
      if (pool.description.size() >
          device_catalog::dhcpv4_description_bytes)
        return Status::invalid_description;
      for (std::size_t earlier{}; earlier < pool_index; ++earlier)
        if (server.pools[earlier].name == pool.name)
          return Status::duplicate_pool;
      if (pool.minimum_lease_seconds <
              device_catalog::dhcpv4_lease_time_minimum_seconds ||
          pool.minimum_lease_seconds >
              device_catalog::dhcpv4_lease_time_maximum_seconds ||
          pool.maximum_lease_seconds <
              device_catalog::dhcpv4_lease_time_minimum_seconds ||
          pool.maximum_lease_seconds >
              device_catalog::dhcpv4_lease_time_maximum_seconds ||
          pool.minimum_lease_seconds > pool.maximum_lease_seconds)
        return Status::invalid_lease_time;
      if (pool.offer_seconds <
              device_catalog::dhcpv4_offer_time_minimum_seconds ||
          pool.offer_seconds >
              device_catalog::dhcpv4_offer_time_maximum_seconds)
        return Status::invalid_offer_time;
      if (!std::ranges::all_of(pool.options, valid_option))
        return Status::invalid_option;

      for (const auto &subnet : pool.subnets) {
        const auto network = integer(subnet.network);
        const auto mask = prefix_mask(subnet.prefix_length);
        if (subnet.allocation_scope_id == 0U ||
            subnet.allocation_scope_id >
                std::numeric_limits<std::uint32_t>::max() ||
            subnet.prefix_length == 0U || subnet.prefix_length > 32U ||
            (network & mask) != network)
          return Status::invalid_subnet;
        for (std::size_t prior_pool{}; prior_pool <= pool_index; ++prior_pool) {
          const auto &prior_subnets = server.pools[prior_pool].subnets;
          const auto limit = prior_pool == pool_index
                                 ? static_cast<std::size_t>(
                                       &subnet - pool.subnets.data())
                                 : prior_subnets.size();
          for (std::size_t prior{}; prior < limit; ++prior)
            if (prior_subnets[prior].allocation_scope_id ==
                subnet.allocation_scope_id)
              return Status::invalid_subnet;
        }
        if (!std::ranges::all_of(subnet.options, valid_option))
          return Status::invalid_option;
        if (!allow_incomplete && subnet.address_ranges.empty())
          return Status::invalid_address_range;

        for (std::size_t range_index{}; range_index < subnet.address_ranges.size();
             ++range_index) {
          const auto first = integer(subnet.address_ranges[range_index].first);
          const auto last = integer(subnet.address_ranges[range_index].last);
          if (first > last || (first & mask) != network ||
              (last & mask) != network)
            return Status::invalid_address_range;
          for (std::size_t earlier{}; earlier < range_index; ++earlier)
            if (ranges_overlap(
                    first, last,
                    integer(subnet.address_ranges[earlier].first),
                    integer(subnet.address_ranges[earlier].last)))
              return Status::overlapping_address_range;
        }

        for (std::size_t excluded_index{};
             excluded_index < subnet.excluded_ranges.size();
             ++excluded_index) {
          const auto first = integer(subnet.excluded_ranges[excluded_index].first);
          const auto last = integer(subnet.excluded_ranges[excluded_index].last);
          if (first > last || (first & mask) != network ||
              (last & mask) != network)
            return Status::invalid_excluded_range;
          const bool contained = std::ranges::any_of(
              subnet.address_ranges, [&](const AddressRange &range) {
                return integer(range.first) <= first &&
                       integer(range.last) >= last;
              });
          if (!contained)
            return Status::exclusion_outside_range;
          for (std::size_t earlier{}; earlier < excluded_index; ++earlier)
            if (ranges_overlap(
                    first, last,
                    integer(subnet.excluded_ranges[earlier].first),
                    integer(subnet.excluded_ranges[earlier].last)))
              return Status::overlapping_excluded_range;
        }
      }
    }
  }
  return Status::valid;
}

} // namespace router::dhcpv4::configuration
