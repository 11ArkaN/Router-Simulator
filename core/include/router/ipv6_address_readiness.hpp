// Local address readiness messages cross a forwarding-to-control SPSC channel.
// The forwarding AF writer produces owned values; the local protocol coordinator
// consumes them. Dependencies are address and registry identities only.
#pragma once
#include "router/ip_address.hpp"
#include "router/lab_registry.hpp"
namespace router::lab {
struct Ipv6ReadinessWatch {
  std::uint64_t interface_id{};
  std::uint16_t port_ordinal{};
  ip::Ipv6 address{};
  bool operator==(const Ipv6ReadinessWatch &) const = default;
};
// Producer: one forwarding AF writer. Consumer: the local protocol coordinator.
// The caller's bounded SPSC channel release-publishes complete value copies and
// acquire-consumes them. Full admission retains the value at the producer;
// consumers reject obsolete configuration generations. No shared pointer.
struct Ipv6ReadinessChange {
  std::uint32_t version{1U};
  DeviceHandle device{};
  std::uint64_t configuration_generation{};
  Ipv6ReadinessWatch source;
  bool preferred{};
};
}
