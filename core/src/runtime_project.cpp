// Runtime application of atomic project updates. Parsing and validation remain
// in project_configuration; this file only coordinates control and forwarding.

#include "router/runtime.hpp"

#include "router/project_configuration.hpp"

namespace router {

std::string Runtime::configure_running(const std::string &text) {
  const auto parsed =
      project::parse_running(state_.configuration.running, text);
  if (!parsed.success)
    return parsed.error;

  // Publish one complete datastore, then rebuild both dependent projections.
  // The forwarding owner receives one value message, so no packet can observe
  // half of an imported interface or route set.
  const auto network =
      project::network_configuration(parsed.configuration, state_.project);
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::configure_network,
                      .network = network});
  if (!result.success)
    return "ERROR: atomic running configuration was rejected";
  state_.configuration.running = parsed.configuration;
  state_.configuration.candidate = parsed.configuration;
  session_.candidate_dirty = false;
  session_.candidate_outdated = false;
  state_.operational.arp = {};
  const auto hardware = hardware::reconcile(
      state_.configuration.running, state_.hardware, state_.operational,
      std::chrono::steady_clock::now());
  hardware_deadline_ = hardware.next_deadline;
  reconcile_fib(true);
  return snapshot();
}

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
