// Atomic validation and publication for native router IPv6 addresses. This
// module depends only on generated resource policy and IP value primitives;
// DAD, routing and CLI owners consume its immutable records separately.

#include "router/router_ipv6_address_table.hpp"

#include <algorithm>
#include <array>
#include <new>

namespace router::lab {

RouterIpv6AddressProgramStatus RouterIpv6AddressTable::program(
    std::span<const RouterIpv6Address> records) noexcept {
  if (records.size() > capacity)
    return RouterIpv6AddressProgramStatus::too_many_addresses;

  try {
    // Copy first so every later validation and ordering pass works on private
    // memory. The current generation remains byte-for-byte intact on every
    // semantic error and on allocation failure.
    std::vector<RouterIpv6Address> next(records.begin(), records.end());

    // Validate the caller's generation before touching live bytes. Apart from
    // preventing partial updates, this ensures a malformed SPSC command cannot
    // turn an address into an implicit prefix through silent normalization.
    std::array<std::size_t, device_catalog::maximum_ports_per_router + 1U>
        per_port{};
    for (const auto &record : next) {
      const bool system = record.interface_id == system_interface_id;
      if (!record.interface_id ||
          (system
               ? record.port_ordinal != system_interface_port_ordinal
               : record.port_ordinal >=
                         device_catalog::maximum_ports_per_router ||
                     record.interface_id !=
                         physical_interface_id(record.port_ordinal)) ||
          record.prefix_length > ip::ipv6_address_bits ||
          (system && record.prefix_length != ip::ipv6_address_bits) ||
          ip::is_unspecified(record.address) ||
          ip::is_multicast(record.address) ||
          ip::is_link_local(record.address) ||
          ip::mask(record.address, record.prefix_length) != record.network)
        return RouterIpv6AddressProgramStatus::invalid_record;
      if (++per_port[record.port_ordinal] >
          device_catalog::network_interface_ip_addresses)
        return RouterIpv6AddressProgramStatus::interface_limit_exceeded;
    }

    // Sort once by wire address to make duplicate validation O(n log n) at
    // maximum hardware scale. A quadratic pair scan would turn a legal 12 800
    // address generation into more than eighty million comparisons.
    std::sort(next.begin(), next.end(), [](const auto &left,
                                           const auto &right) {
      return left.address < right.address;
    });
    if (std::adjacent_find(next.begin(), next.end(),
                           [](const auto &left, const auto &right) {
                             return left.address == right.address;
                           }) != next.end())
      return RouterIpv6AddressProgramStatus::duplicate_address;

    // The published order groups each interface and makes its selected primary
    // the first record. Packet-path lookups then scan contiguous storage without
    // allocation, locks or a second preference sort.
    std::sort(next.begin(), next.end(),
              [](const auto &left, const auto &right) {
                if (left.interface_id != right.interface_id)
                  return left.interface_id < right.interface_id;
                if (left.primary_preference != right.primary_preference)
                  return left.primary_preference < right.primary_preference;
                return left.address < right.address;
              });
    records_.swap(next);
    return RouterIpv6AddressProgramStatus::accepted;
  } catch (const std::bad_alloc &) {
    // Memory pressure is distinct from a configured scale violation. The old
    // vector remains live because allocation happened before publication.
    return RouterIpv6AddressProgramStatus::resource_exhausted;
  }
}

const RouterIpv6Address *RouterIpv6AddressTable::find(
    std::uint64_t interface_id, const packet::Ipv6 &address) const noexcept {
  const auto match = std::find_if(records().begin(), records().end(),
                                  [&](const auto &record) {
                                    return record.interface_id == interface_id &&
                                           record.address == address;
                                  });
  return match == records().end() ? nullptr : &*match;
}

const RouterIpv6Address *RouterIpv6AddressTable::owner(
    const packet::Ipv6 &address) const noexcept {
  const auto match = std::find_if(records().begin(), records().end(),
                                  [&](const auto &record) {
                                    return record.address == address;
                                  });
  return match == records().end() ? nullptr : &*match;
}

const RouterIpv6Address *RouterIpv6AddressTable::primary(
    std::uint64_t interface_id) const noexcept {
  // program() groups interfaces and orders their records by preference. The
  // first match is therefore the selected primary without another sort or a
  // packet-path allocation.
  const auto match = std::find_if(records().begin(), records().end(),
                                  [&](const auto &record) {
                                    return record.interface_id == interface_id;
                                  });
  return match == records().end() ? nullptr : &*match;
}

std::size_t RouterIpv6AddressTable::interface_count(
    std::uint64_t interface_id) const noexcept {
  return static_cast<std::size_t>(std::count_if(
      records().begin(), records().end(), [&](const auto &record) {
        return record.interface_id == interface_id;
      }));
}

void RouterIpv6AddressTable::remove_physical_port(
    std::uint16_t port_ordinal) noexcept {
  std::erase_if(records_, [&](const auto &record) {
    // The system loopback uses the sentinel immediately above the physical
    // domain and therefore survives every chassis removal.
    return record.interface_id != system_interface_id &&
           record.port_ordinal == port_ordinal;
  });
}

} // namespace router::lab
