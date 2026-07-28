// Canonical Base-router DHCPv6 server configuration shared by management,
// persistence and the protocol compiler. The control-plane shard owns this
// intent. Packet and forwarding modules consume only validated compiled
// copies and never interpret CLI list names or default-presence metadata.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/dhcpv6_packet.hpp"
#include "router/ip_address.hpp"
#include "router/sha256.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace router::dhcpv6::configuration {

struct Prefix {
  // allocation_scope_id is stable across list reordering and identifies a
  // relay-only link when no configured Base interface references this pool.
  std::uint64_t allocation_scope_id{};
  ip::Ipv6Prefix aggregate{};
  crypto::Sha256Digest allocation_secret{};
  // SR OS lets a single aggregate serve IA_NA/SLAAC and IA_PD at the same
  // time. Independent booleans preserve that behavior; an enum would silently
  // discard one address-assignment application when both leaves are true.
  bool wan_host{true};
  bool delegated_prefix{true};
  std::uint8_t delegated_length{64U};

  // A prefix inherits the server defaults until its corresponding configured
  // bit is set. Zero is a valid T1 or T2 value, so it cannot double as an
  // "unset" sentinel.
  std::uint32_t preferred_lifetime_seconds{};
  std::uint32_t valid_lifetime_seconds{};
  std::uint32_t renewal_time_seconds{};
  std::uint32_t rebinding_time_seconds{};
  bool preferred_lifetime_configured{};
  bool valid_lifetime_configured{};
  bool renewal_time_configured{};
  bool rebinding_time_configured{};
  bool drain{};
  bool drain_configured{};
  bool wan_host_configured{};
  bool delegated_prefix_configured{};
  bool operator==(const Prefix &) const = default;
};

struct Pool {
  std::string name;
  std::string description;
  // RFC 9915 prefix hints are constrained by the SR OS pool policy. The
  // preferred value is used when the client supplies no hint; otherwise the
  // request is clamped to the documented minimum and maximum.
  std::uint8_t delegated_length{64U};
  std::uint8_t minimum_delegated_length{48U};
  std::uint8_t maximum_delegated_length{64U};
  bool delegated_length_configured{};
  bool minimum_delegated_length_configured{};
  bool maximum_delegated_length_configured{};
  std::vector<Prefix> prefixes;
  bool operator==(const Pool &) const = default;
};

struct Server {
  // Runtime identity is persistent and independent from vector position.
  // Deleting another named instance therefore cannot transfer live bindings.
  std::uint32_t instance_id{};
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::uint16_t duid_octets{};
  std::string name;
  std::string description;
  std::vector<packet::Ipv6> dns_recursive_servers;
  std::vector<Pool> pools;
  // Defaults are taken from the SR OS 26.7.R1 router DHCPv6 tree. They are
  // stored on the server because changing a default must affect every prefix
  // that has not overridden the corresponding leaf.
  std::uint32_t default_preferred_lifetime_seconds{3600U};
  std::uint32_t default_valid_lifetime_seconds{86400U};
  std::uint32_t default_renewal_time_seconds{1800U};
  std::uint32_t default_rebinding_time_seconds{2880U};
  bool default_preferred_lifetime_configured{};
  bool default_valid_lifetime_configured{};
  bool default_renewal_time_configured{};
  bool default_rebinding_time_configured{};
  std::uint32_t information_refresh_time_seconds{
      packet::dhcpv6::information_refresh_default_seconds};
  std::uint8_t preference{};
  bool rapid_commit{true};
  bool lease_query{};
  bool admin_enabled{};
  bool rapid_commit_configured{};
  bool lease_query_configured{};
  bool admin_state_configured{};
  bool operator==(const Server &) const = default;
};

struct RouterConfiguration {
  std::vector<Server> servers;
  bool operator==(const RouterConfiguration &) const = default;
};

enum class Status : std::uint8_t {
  valid,
  duplicate_server,
  duplicate_pool,
  duplicate_prefix,
  invalid_name,
  invalid_description,
  invalid_prefix,
  invalid_lifetime,
  missing_entropy,
  resource_exhausted,
};

// allow_incomplete admits list keys in an MD candidate before their mandatory
// prefix children are entered. Running configuration must always pass with
// allow_incomplete false before any forwarding transaction begins.
[[nodiscard]] Status validate(const RouterConfiguration &configuration,
                              bool allow_incomplete = false) noexcept;

} // namespace router::dhcpv6::configuration
