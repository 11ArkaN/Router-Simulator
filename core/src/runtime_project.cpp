// Runtime application of atomic project updates. Parsing and validation remain
// in project_configuration; this file only coordinates control and forwarding.

#include "router/runtime.hpp"

#include "router/project_configuration.hpp"

namespace router {

std::string Runtime::configure_hosts(const std::string &text) {
  const auto parsed = project::parse_hosts(state_.project, text);
  if (!parsed.success)
    return parsed.error;
  const auto network = project::network_configuration(
      state_.configuration.running, parsed.state);
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::configure_network,
                      .network = network});
  if (!result.success)
    return "ERROR: atomic host configuration was rejected";
  state_.project = parsed.state;
  state_.operational.arp = {};
  return snapshot();
}

std::string Runtime::configure_links(const std::string &text) {
  const auto parsed = project::parse_links(state_.project, text);
  if (!parsed.success)
    return parsed.error;
  const auto network = project::network_configuration(
      state_.configuration.running, parsed.state);
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::configure_network,
                      .network = network});
  if (!result.success)
    return "ERROR: atomic link configuration was rejected";
  state_.project = parsed.state;
  state_.operational.arp = {};
  return snapshot();
}

} // namespace router
