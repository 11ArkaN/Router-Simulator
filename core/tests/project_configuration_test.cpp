#include "router/project_configuration.hpp"

#include "router/generated_profile.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

std::string command(const std::vector<std::string> &fields) {
  // The test encoder mirrors only the generic byte framing. It intentionally
  // knows nothing about the order or meaning of running configuration fields.
  std::string result{"project:running|"};
  for (const auto &field : fields)
    result += std::to_string(field.size()) + ':' + field;
  return result;
}

} // namespace

void project_configuration_tests() {
  router::DeviceConfiguration current;
  // Separator characters prove that framing, rather than delimiter splitting,
  // protects user-controlled names and descriptions.
  std::vector<std::string> fields{"edge|r1",
                                  std::to_string(router::profile::port_count)};
  for (std::size_t index = 0; index < router::profile::port_count; ++index) {
    fields.emplace_back(router::profile::port_ids[index]);
    fields.emplace_back(index == 0 ? "down" : "up");
    fields.emplace_back(index == 0 ? "1400" : "1500");
    fields.emplace_back(index == 0 ? "host|a" : "");
  }
  fields.emplace_back(std::to_string(current.interface_count));
  for (std::size_t index = 0; index < current.interface_count; ++index) {
    fields.emplace_back(current.interfaces[index].name);
    fields.emplace_back("up");
  }
  fields.emplace_back("1");
  fields.emplace_back("203.0.113.0/24");
  fields.emplace_back("198.51.100.2");

  const auto parsed = router::project::parse_running(current, command(fields));
  // One assertion covers the atomic value returned to runtime control. The
  // parser itself cannot mutate the supplied current configuration.
  if (!parsed.success ||
      std::string_view(parsed.configuration.system_name.data()) != "edge|r1" ||
      parsed.configuration.ports[0].admin_enabled ||
      parsed.configuration.ports[0].mtu != 1400 ||
      std::string_view(parsed.configuration.ports[0].description.data()) !=
          "host|a" ||
      !parsed.configuration.static_routes[0].valid) {
    throw std::runtime_error(
        "Atomic running configuration did not preserve structured fields");
  }
  if (router::project::parse_running(current, "project:running|9:truncated")
          .success) {
    // A declared byte length must never read beyond the received command.
    throw std::runtime_error(
        "Running configuration accepted a truncated field");
  }

  // Empty fields consume no payload bytes, so field count needs its own bound
  // independent from command byte length.
  std::vector<std::string> excessive_fields(128, "");
  if (router::project::parse_running(current, command(excessive_fields))
          .success) {
    throw std::runtime_error("Running configuration accepted excess fields");
  }
}
