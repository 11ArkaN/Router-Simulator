// Snapshot JSON must preserve nullable intent, enums and arbitrary interface
// names without exposing protocol state or emitting invalid escaped strings.
#include "runtime/isis_configuration_projection.hpp"
#include <sstream>
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS JSON projection invariant"); }
}
void isis_configuration_projection_tests() {
  using namespace router::isis;
  RouterConfiguration configuration;
  std::ostringstream empty;
  router::lab::isis_projection::write_json(empty, configuration);
  require(empty.str() == "{\"instances\":[]}");
  configuration.instances.emplace_back();
  auto &instance = configuration.instances.back();
  instance.instance = 127U; instance.admin_enabled = true; instance.ipv4_routing = false;
  instance.ipv6_routing = ConfiguredIpv6Routing::native; instance.levels = ConfiguredLevels::both;
  instance.router_id = 0xda700e05U;
  instance.areas.push_back(*parse_configured_area("49.00.01"));
  instance.interfaces.emplace_back();
  instance.interfaces.back().name = "edge\n\"\\";
  instance.interfaces.back().type = ConfiguredInterfaceType::point_to_point;
  instance.interfaces.back().level[0U].present = true;
  instance.interfaces.back().level[0U].passive = false;
  std::ostringstream out;
  router::lab::isis_projection::write_json(out, configuration);
  const auto text = out.str();
  require(text.find("\"instance\":127,\"adminEnabled\":true,\"ipv4Routing\":false") != std::string::npos);
  require(text.find("\"ipv6Routing\":\"native\",\"levelCapability\":\"1/2\"") != std::string::npos);
  require(text.find("\"systemId\":null,\"routerId\":\"218.112.14.5\"") != std::string::npos);
  require(text.find("\"areas\":[\"49.0001\"]") != std::string::npos);
  require(text.find("\"name\":\"edge\\u000a\\\"\\\\\"") != std::string::npos);
  require(text.find("\"type\":\"point-to-point\"") != std::string::npos);
  require(text.find("\"passive\":false") != std::string::npos);
  require(text.find('\n') == std::string::npos);
}
