// DHCPv6 relay-populated IPv6 route owner. It converts committed lease
// mutations into protocol-labelled route entries and supports atomic rebuild,
// incremental update, lookup and checkpoint without touching packet queues.

#pragma once

#include "router/dhcpv6_relay.hpp"
#include "router/dhcpv6_relay_lease.hpp"
#include "router/ip_address.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::dhcpv6 {

enum class RelayRouteProtocol : std::uint8_t {
  non_temporary,
  temporary,
  delegated_prefix,
  delegated_prefix_exclude
};

struct RelayRoute {
  ip::Ipv6 network{};
  ip::Ipv6 next_hop{};
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint8_t prefix_length{};
  RelayRouteProtocol protocol{RelayRouteProtocol::non_temporary};
  bool blackhole{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayRoute &, const RelayRoute &) noexcept = default;
};

using RelayRouteCheckpoint = RelayRoute;

class RelayRouteRepository final {
public:
  // Configuration reserves two route slots per admitted lease because an
  // IA_PD may own both its forwarding prefix and an OPTION_PD_EXCLUDE
  // blackhole. Existing routes must still resolve to a supplied interface.
  [[nodiscard]] bool configure(
      std::span<const RelayInterfaceConfig> interfaces) noexcept;

  // Rebuild is used after a policy flag changes or after checkpoint restore.
  // The old generation remains live if any lease or route exceeds the new
  // complete policy and capacity contract.
  [[nodiscard]] bool rebuild(
      std::span<const RelayLeaseRecord> leases,
      std::span<const RelayInterfaceConfig> interfaces) noexcept;

  // Incremental prepare leaves live routes untouched. The returned boolean
  // means the entire lease mutation list has a staged route generation.
  [[nodiscard]] bool prepare(
      std::span<const RelayLeaseMutation> mutations,
      std::span<const RelayInterfaceConfig> interfaces) noexcept;
  [[nodiscard]] bool commit_prepared() noexcept;
  void discard_prepared() noexcept;

  [[nodiscard]] bool lookup(const ip::Ipv6 &destination,
                            RelayRoute &selected) const noexcept;
  [[nodiscard]] std::span<const RelayRoute> routes() const noexcept {
    return routes_;
  }
  [[nodiscard]] std::vector<RelayRouteCheckpoint> checkpoint() const;
  [[nodiscard]] bool restore(
      std::span<const RelayInterfaceConfig> interfaces,
      std::span<const RelayLeaseRecord> leases,
      std::span<const RelayRouteCheckpoint> state) noexcept;

private:
  [[nodiscard]] static const RelayInterfaceConfig *policy(
      std::span<const RelayInterfaceConfig> interfaces,
      std::uint64_t interface_id) noexcept;
  [[nodiscard]] static bool append_lease_routes(
      std::vector<RelayRoute> &output, const RelayLeaseRecord &lease,
      const RelayInterfaceConfig &interface) noexcept;
  [[nodiscard]] static bool same_route_key(const RelayRoute &left,
                                           const RelayRoute &right) noexcept;

  std::vector<RelayRoute> routes_;
  std::vector<RelayRoute> staged_;
  bool prepared_{};
};

} // namespace router::dhcpv6
