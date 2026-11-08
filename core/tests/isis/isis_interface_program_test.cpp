// Canonical intent prepares owned P2P/LAN Hello programs. Real circuit owners
// encode the result; inactive and refused inputs never produce partial programs.
#include "router/isis_interface_program.hpp"
#include <memory>
#include <stdexcept>
#include <source_location>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS interface program invariant at " + std::to_string(location.line()));
}
}
void isis_interface_program_tests() {
  InstanceIntent instance; instance.admin_enabled = true; instance.levels = ConfiguredLevels::level2;
  instance.areas = {*parse_configured_area("49.0001")};
  InterfaceIntent interface; interface.name = "edge one";
  interface.level[0U].present = interface.level[1U].present = true;
  interface.level[0U].hello_interval_seconds = std::uint16_t{2U}; interface.level[0U].hello_multiplier = std::uint8_t{2U};
  interface.level[1U].hello_interval_seconds = std::uint16_t{7U}; interface.level[1U].priority = std::uint8_t{100U};
  std::array<std::uint8_t, 1U> protocols{packet::isis::ipv4_nlpid};
  const std::array<packet::Ipv4, 1U> addresses{{{192U, 0U, 2U, 1U}}};
  InterfaceProgramContext context;
  context.interface_name = "edge one";
  context.identity = {{0U, 1U}, 1U, 1U, 0U, 0U};
  context.system_identity.fallback_router_id = 0xff000000U;
  context.default_type = ConfiguredInterfaceType::point_to_point;
  context.mac = {2U, 0U, 0U, 0U, 0U, 1U};
  context.destinations = {{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U},
      {{{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U}, {1U, 0x80U, 0xc2U, 0U, 0U, 0x15U}}}};
  context.extended_circuit = 1U; context.local_circuit = 1U; context.maximum_areas = 3U;
  context.random = 123U; context.maximum_pdu_octets = 1492U; context.peer_attribute_octets = 512U;
  context.lan_neighbors = 16U; context.protocols = protocols; context.ipv4_addresses = addresses;
  context.operational = true;
  const auto before = interface;
  auto result = prepare_interface_program(instance, interface, context);
  require(result.status == InterfaceProgramStatus::prepared && result.circuit && !result.circuit->broadcast && interface == before);
  require(result.circuit->configuration.local.levels == Levels::level2 &&
      result.circuit->configuration.local.over_lan && result.circuit->configuration.holding_seconds == 4U &&
      result.circuit->configuration.hello_interval == 2s && result.circuit->configuration.ipv4_addresses.front() == addresses.front());
  protocols[0U] = packet::isis::ipv6_nlpid;
  require(result.circuit->configuration.protocols.front() == packet::isis::ipv4_nlpid);
  protocols[0U] = packet::isis::ipv4_nlpid;
  const auto now = RuntimeClock::time_point{100s};
  PointToPointCircuit owner(result.circuit->configuration, context.random, now);
  auto scratch = std::make_unique<PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  const auto built = owner.hello(*frame, {}, *scratch, now);
  require(built && *built == HelloBuildResult::encoded);
  packet::isis::EthernetDecodeError error;
  const auto pdu = packet::isis::parse_ethernet_pdu(frame->view(), error);
  const auto hello = pdu ? packet::isis::hello(pdu->pdu) : std::nullopt;
  require(hello && hello->holding_seconds == 4U && hello->source == *resolve_configured_system_id(instance, context.system_identity));
  interface.type = ConfiguredInterfaceType::broadcast; instance.levels = ConfiguredLevels::both;
  result = prepare_interface_program(instance, interface, context);
  require(result.status == InterfaceProgramStatus::prepared && result.circuit->broadcast);
  const auto &lan = *result.circuit->broadcast;
  require(lan.levels[0U] && lan.levels[1U] && lan.levels[0U]->holding_seconds == 4U &&
      lan.levels[0U]->designated_holding_seconds == 2U && lan.levels[0U]->hello_interval == 2s &&
      lan.levels[1U]->holding_seconds == 21U && lan.levels[1U]->local.priority == 100U &&
      lan.levels[1U]->hello_destination == context.destinations.levels[1U]);
  LanCircuitPair lan_owner(lan, context.random, now);
  require(lan_owner.levels() == Levels::both);
  interface.level[0U].passive = true;
  result = prepare_interface_program(instance, interface, context);
  require(result.status == InterfaceProgramStatus::prepared && !result.circuit->broadcast->levels[0U] &&
      result.circuit->broadcast->levels[1U]->levels == Levels::level2);
  interface.type = ConfiguredInterfaceType::point_to_point;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::inactive);
  interface.level[0U].passive.reset();
  interface.level[0U].hello_interval_seconds = std::uint16_t{20000U}; interface.level[0U].hello_multiplier = std::uint8_t{100U};
  result = prepare_interface_program(instance, interface, context);
  require(result.status == InterfaceProgramStatus::unrepresentable_holding && !result.circuit);
  interface.level[0U].hello_interval_seconds = std::uint16_t{2U}; interface.level[0U].hello_multiplier = std::uint8_t{2U};
  context.system_identity = {};
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::unresolved_identity);
  context.system_identity.fallback_router_id = 0xff000000U;
  interface.type.reset(); context.default_type.reset();
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::unresolved_media);
  context.default_type = ConfiguredInterfaceType::broadcast; context.random = 0U;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::invalid_context);
  context.random = 123U; instance.instance = 1U;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::unsupported_instance);
  instance.instance = 0U; instance.ipv6_routing = ConfiguredIpv6Routing::multi_topology;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::unsupported_topology);
  instance.ipv6_routing.reset(); instance.admin_enabled = false;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::inactive);
  instance.admin_enabled = true; context.loopback = true;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::inactive);
  context.loopback = false; context.interface_name = "other";
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::invalid_context);
  context.interface_name = interface.name; context.operational = false;
  require(prepare_interface_program(instance, interface, context).status == InterfaceProgramStatus::inactive);
}
