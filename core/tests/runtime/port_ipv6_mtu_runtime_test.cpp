// The serialized supervisor owns hardware and forwarding port projections.
// This fixture checks their MTU dependency without a link or protocol shortcut.
#include "router/runtime_supervisor.hpp"
#include "router/router_hardware_inventory.hpp"
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
void port_ipv6_mtu_runtime_tests() {
  using namespace router;
  using namespace router::lab;
  const auto require=[](bool ok,const char *why) { if (!ok) throw std::runtime_error(why); };
  auto runtime=std::make_unique<RuntimeSupervisor>();
  const auto device=runtime->create_router("mtu-owner","7750-sr-1","MTU");
  require(device.has_value(),"MTU owner fixture creation failed");
  require(runtime->configure_port(*device,"1/1/1",true,9212U,100000U)==HardwareEditResult::applied,
      "MTU fixture port configuration failed");
  const auto mac=runtime->hardware(*device)->physical_mac("1/1/1");
  const auto address=*ip::parse_ipv6("2001:db8:1::1");
  const auto local=*ip::parse_ipv6("fe80::1");
  require(mac && runtime->configure_interface(*device,"1/1/1",*mac,0xc0000201U,24U,true),
      "MTU fixture IPv4 configuration failed");
  require(mac && runtime->configure_ipv6_interface(*device,"1/1/1",*mac,address,64U,local,true),
      "MTU fixture IPv6 configuration failed");
  const auto check=[&](std::uint16_t expected,bool ipv6) {
    const auto *physical=runtime->hardware(*device)->find("1/1/1");
    const auto state=runtime->router_operational_state(*device);
    require(physical && physical->mtu==expected && state,"Physical MTU projection diverged");
    const auto ordinal=runtime->hardware(*device)->coordinate_ordinal("1/1/1");
    const auto port=std::find_if(state->ports.begin(),state->ports.end(),
        [&](const auto &value) { return ordinal && value.ordinal==*ordinal && value.configured; });
    if (port==state->ports.end() || port->mtu!=expected || port->ipv6_configured!=ipv6)
      throw std::runtime_error("Forwarding MTU projection diverged: expected="+std::to_string(expected)+
          "/"+std::to_string(ipv6)+" actual="+(port==state->ports.end() ? "absent" :
          std::to_string(port->mtu)+"/"+std::to_string(port->ipv6_configured)));
  };
  check(9212U,true);
  require(runtime->configure_port(*device,"1/1/1",true,512U,100000U)==HardwareEditResult::incompatible_children,
      "IPv6-incompatible MTU was accepted by the hardware owner");
  check(9212U,true);
  require(runtime->configure_port(*device,"1/1/1",true,packet::ipv6_minimum_ethernet_mtu,100000U)==HardwareEditResult::applied,
      "IPv6 minimum Ethernet MTU was rejected");
  check(packet::ipv6_minimum_ethernet_mtu,true);
  require(runtime->remove_ipv6_interface(*device,"1/1/1"),"IPv6 parent removal failed");
  require(runtime->configure_port(*device,"1/1/1",true,512U,100000U)==HardwareEditResult::applied,
      "IPv4-only physical MTU was rejected");
  check(512U,false);
  require(!runtime->configure_ipv6_interface(*device,"1/1/1",*mac,address,64U,local,true),
      "IPv6 was enabled on an undersized physical port");
  check(512U,false);
}
