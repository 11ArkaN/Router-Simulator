// Private control-shard state shared only by RuntimeSupervisor implementation
// units. RuntimeSupervisor remains the sole owner; dependencies point inward
// from the runtime implementation and never become part of its public API.

#pragma once

#include "router/runtime_supervisor.hpp"

#include "router/multi_device_routing.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <new>
#include <thread>

namespace router::lab {

struct RuntimeSupervisor::RouterNetworkState {
  // Control owns interface and RIB inputs. The forwarding object owns only its
  // installed value projections, adjacency table and packet queues.
  routing::RouteTable rib;
  std::array<routing::ConnectedInput, routing::maximum_ipv4_connected_inputs>
      connected{};
  std::array<routing::StaticInput,
             device_catalog::maximum_static_routes_per_router>
      statics{};
  routing::Ipv6RouteTable ipv6_rib;
  std::array<routing::Ipv6ConnectedInput,
             device_catalog::maximum_ports_per_router>
      ipv6_connected{};
  // Native secondary addresses are cold control intent. The separate derived
  // connected vector is rebuilt transactionally and passed to the RIB without
  // making the forwarding shard inspect mutable configuration memory.
  std::vector<RouterIpv6Address> native_ipv6_addresses{};
  std::vector<routing::Ipv6ConnectedInput> native_ipv6_connected{};
  std::array<routing::Ipv6StaticInput,
             device_catalog::maximum_static_routes_per_router>
      ipv6_statics{};
  // One is the SR OS default and represents disabled path sharing. Control is
  // the sole owner; forwarding receives only the resulting immutable groups.
  std::uint16_t maximum_ecmp_paths{1U};
  std::array<ForwardPort, device_catalog::maximum_ports_per_router> ports{};
  std::array<bool, device_catalog::maximum_ports_per_router> interface_admin{};
  std::array<bool, device_catalog::maximum_ports_per_router> ies_port_owned{};
  std::array<RouterAdvertisementIntent,
             device_catalog::maximum_ports_per_router>
      router_advertisements{};
  std::array<MldInterfaceIntent, device_catalog::maximum_ports_per_router>
      mld_interfaces{};
  // Native Base relay intent remains control-owned while an absent card may
  // temporarily remove its forwarding object and UDP socket.
  std::array<std::optional<dhcpv4::RelayInterfaceConfiguration>,
             device_catalog::maximum_ports_per_router>
      dhcpv4_relays{};
  // Control retains committed relay intent independently of the forwarding
  // socket. Card removal may destroy the latter while the former must be
  // available for exact reprovisioning when hardware returns.
  std::array<std::optional<dhcpv6::RelayInterfaceConfig>,
             device_catalog::maximum_ports_per_router>
      dhcpv6_relays{};
  // These vectors are cold-path, control-owned configuration generations.
  // Packet owners receive only complete immutable projections through the
  // SPSC command stream, never pointers into these allocations.
  service::Configuration ies_configuration{};
  std::vector<service::SapAttachment> ies_sap_attachments{};
  std::vector<service::ServiceIpv6Interface> ies_ipv6_interfaces{};
  std::vector<routing::Ipv6ConnectedInput> ies_ipv6_connected{};
  std::vector<dhcpv6::RelayInterfaceConfig> ies_dhcpv6_relays{};
  std::uint64_t fib_generation{};
  std::uint64_t ipv6_fib_generation{};
};

namespace {

[[maybe_unused]] bool build_native_ipv6_connected(
    std::span<const RouterIpv6Address> addresses,
    std::span<const ForwardPort> ports,
    bool system_operational,
    std::vector<routing::Ipv6ConnectedInput> &output) noexcept {
  try {
    std::vector<routing::Ipv6ConnectedInput> candidate;
    candidate.reserve(addresses.size());
    for (const auto &address : addresses) {
      const bool system = address.interface_id == system_interface_id;
      if (system ? address.port_ordinal != system_interface_port_ordinal
                 : address.port_ordinal >= ports.size())
        return false;
      // Multiple addresses in one subnet install one connected prefix. Local
      // address ownership remains per-address in RouterIpv6AddressTable, while
      // duplicating the connected FIB entry would create ambiguous show output
      // without adding any forwarding reachability.
      const auto duplicate = std::find_if(
          candidate.begin(), candidate.end(), [&](const auto &entry) {
            return entry.interface_id == address.interface_id &&
                   entry.network == address.network &&
                   entry.prefix_length == address.prefix_length;
          });
      if (duplicate != candidate.end())
        continue;
      candidate.push_back(
          {.configured = true,
           .operational =
               system ? system_operational
                      : ports[address.port_ordinal].operational,
           .network = address.network,
           .interface_id = address.interface_id,
           .physical_port_ordinal = address.port_ordinal,
           .prefix_length = address.prefix_length});
    }
    output.swap(candidate);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace

} // namespace router::lab
