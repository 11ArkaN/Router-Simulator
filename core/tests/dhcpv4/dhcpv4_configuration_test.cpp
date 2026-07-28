// Canonical DHCPv4 configuration tests exercise relationships that cannot be
// validated by scalar CLI parsing. They keep both terminal engines from
// accepting an intent that the runtime compiler would interpret ambiguously.

#include "router/dhcpv4_configuration.hpp"

#include <stdexcept>
#include <utility>

namespace {

using namespace router;
using namespace router::dhcpv4::configuration;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

RouterConfiguration valid_configuration() {
  RouterConfiguration configuration;
  Server server;
  server.instance_id = 1U;
  server.name = "base-v4";
  server.admin_enabled = true;
  Pool pool;
  pool.name = "access";
  Subnet subnet;
  subnet.allocation_scope_id = 1U;
  subnet.network = {192U, 0U, 2U, 0U};
  subnet.prefix_length = 24U;
  subnet.address_ranges.push_back(
      {.first = {192U, 0U, 2U, 10U},
       .last = {192U, 0U, 2U, 200U},
       .failover_control = FailoverControlType::local});
  subnet.excluded_ranges.push_back(
      {.first = {192U, 0U, 2U, 100U},
       .last = {192U, 0U, 2U, 110U}});
  pool.subnets.push_back(std::move(subnet));
  server.pools.push_back(std::move(pool));
  configuration.servers.push_back(std::move(server));
  return configuration;
}

void validates_named_hierarchy_and_defaults() {
  const auto configuration = valid_configuration();
  require(validate(configuration) == Status::valid,
          "canonical DHCPv4 server hierarchy rejected documented defaults");
}

void rejects_ambiguous_or_ineffective_ranges() {
  auto configuration = valid_configuration();
  auto &subnet = configuration.servers.front().pools.front().subnets.front();
  subnet.address_ranges.push_back(
      {.first = {192U, 0U, 2U, 150U},
       .last = {192U, 0U, 2U, 220U},
       .failover_control = FailoverControlType::local});
  require(validate(configuration) == Status::overlapping_address_range,
          "overlapping DHCPv4 address ranges were accepted");

  configuration = valid_configuration();
  auto &excluded =
      configuration.servers.front().pools.front().subnets.front()
          .excluded_ranges.front();
  excluded.first = {192U, 0U, 2U, 201U};
  excluded.last = {192U, 0U, 2U, 210U};
  require(validate(configuration) == Status::exclusion_outside_range,
          "DHCPv4 exclusion outside every allocation range was accepted");
}

} // namespace

void dhcpv4_configuration_tests() {
  validates_named_hierarchy_and_defaults();
  rejects_ambiguous_or_ineffective_ranges();
}
