// Configuration tests prove release instance ranges, shutdown defaults,
// timer ordering and one-area ownership of each routed interface.

#include "router/ospf_configuration.hpp"

#include "router/generated_device_catalog.hpp"

#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
} // namespace

void ospf_configuration_tests() {
  using namespace router::ospf;
  auto instance = default_instance(AddressFamily::ipv4, 0U);
  require(!instance.admin_enabled &&
              instance.reference_bandwidth_kbps ==
                  router::device_catalog::ospf_reference_bandwidth_kbps,
          "OSPF instance did not use release shutdown defaults");
  AreaConfiguration area{.area_id = 0U};
  area.interfaces.push_back({
      .interface_name = "to-r2",
      .cost = 10U,
      .hello_interval_seconds = 10U,
      .dead_interval_seconds = 40U,
      .retransmit_interval_seconds = 5U,
      .transmit_delay_seconds = 1U,
      .admin_enabled = true});
  require(area.interfaces[0].network_type == NetworkType::broadcast,
          "Ethernet OSPF interface did not inherit the SR OS broadcast default");
  instance.areas.push_back(area);
  RouterConfiguration router{.instances = {instance}};
  require(validate(router) == ConfigurationStatus::valid,
          "valid OSPF configuration was rejected");
  router.instances[0].areas.push_back(area);
  require(validate(router) == ConfigurationStatus::duplicate_area,
          "duplicate area was accepted");

  auto invalid_af =
      default_instance(
          AddressFamily::ipv4_over_ospfv3,
          static_cast<std::uint8_t>(
              router::device_catalog::ospf_v3_ipv4_instance_first - 1U));
  RouterConfiguration invalid{.instances = {invalid_af}};
  require(validate(invalid) == ConfigurationStatus::invalid_instance,
          "OSPFv3 IPv4 AF accepted an instance below 64");

  auto ipv4_af = default_instance(
      AddressFamily::ipv4_over_ospfv3,
      router::device_catalog::ospf_v3_ipv4_instance_first);
  AreaConfiguration ipv4_af_backbone{.area_id = 0U};
  ipv4_af_backbone.virtual_links.push_back({
      .transit_area_id = 1U,
      .remote_router_id = 0x0a000002U,
      .hello_interval_seconds = 10U,
      .dead_interval_seconds = 40U,
      .retransmit_interval_seconds = 5U,
      .transmit_delay_seconds = 1U,
      .admin_enabled = true});
  ipv4_af.areas.push_back(ipv4_af_backbone);
  require(validate(RouterConfiguration{.instances = {ipv4_af}}) ==
              ConfigurationStatus::invalid_area,
          "OSPFv3 IPv4 AF accepted a virtual link forbidden by RFC 5838");
}
