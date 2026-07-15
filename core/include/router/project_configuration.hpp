// Validation and projection for persisted lab endpoint and physical link data.
// Parsing is control-owned and produces complete values before any live state
// or forwarding configuration changes.

#pragma once

#include "router/device.hpp"
#include "router/network.hpp"

#include <string>

namespace router::project {

struct ParseResult {
  bool success{};
  ProjectState state{};
  std::string error;
};

struct RunningParseResult {
  bool success{};
  DeviceConfiguration configuration{};
  std::string error;
};

// Parsers are fail-closed control-plane transactions. On failure they return
// the original value untouched together with a stable diagnostic string.
[[nodiscard]] ParseResult parse_hosts(const ProjectState &current,
                                      const std::string &command);
[[nodiscard]] ParseResult parse_links(const ProjectState &current,
                                      const std::string &command);
[[nodiscard]] RunningParseResult
parse_running(const DeviceConfiguration &current, const std::string &command);

// Preconditions: every connected project link references a profile port.
// Missing routed interface configuration disables that link in the projection
// rather than inventing router L3 identities.
[[nodiscard]] NetworkConfiguration
network_configuration(const DeviceConfiguration &running,
                      const ProjectState &project) noexcept;

} // namespace router::project
