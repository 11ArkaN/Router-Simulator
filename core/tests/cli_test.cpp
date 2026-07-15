#include "router/cli.hpp"

#include <stdexcept>

void cli_tests() {
  router::DeviceState state;
  router::CliSession session;
  const auto ping = [](router::packet::Ipv4, std::uint32_t) {
    return std::string{};
  };
  const auto no_routes =
      router::execute_cli(state, session, "show router route-table", ping);
  if (no_routes.find("No active routes") == std::string::npos ||
      no_routes.find("[ex:/]\nA:admin@R1#") == std::string::npos) {
    throw std::runtime_error("Down hardware exposed active routes");
  }

  // A fresh lab has no line-card provisioning. Build and commit a candidate
  // first, then verify that removing the parent is another isolated candidate
  // transaction rather than relying on an implicit factory configuration.
  router::execute_cli(state, session, "configure card 1 card-type iom4-e",
                      ping);
  router::execute_cli(state, session,
                      "configure card 1 mda 1 mda-type me10-10gb-sfp+", ping);
  router::execute_cli(state, session, "commit", ping);
  if (!router::profile_card(state.configuration.running).type ||
      !router::profile_mda(state.configuration.running).type) {
    throw std::runtime_error("MD-CLI did not provision fresh hardware");
  }
  const auto candidate =
      router::execute_cli(state, session, "delete card 1", ping);
  if (router::profile_card(state.hardware).type || !session.candidate_dirty) {
    throw std::runtime_error("MD-CLI changed running state before commit");
  }
  if (candidate.find("*[ex:/]") == std::string::npos) {
    throw std::runtime_error(
        "MD-CLI candidate marker is missing from the prompt");
  }
  const auto compare = router::execute_cli(state, session, "compare", ping);
  // Deleting a parent also deletes its provisioned child in the candidate.
  // Both removals must be shown with a minus sign rather than the old output
  // that displayed every difference as an addition.
  if (compare.find("- card 1") == std::string::npos ||
      compare.find("- mda 1") == std::string::npos) {
    throw std::runtime_error(
        "MD-CLI compare did not represent candidate removals");
  }
  router::execute_cli(state, session, "commit", ping);
  if (router::profile_card(state.configuration.running).type) {
    throw std::runtime_error("MD-CLI commit did not remove provisioning");
  }

  const auto switched = router::execute_cli(state, session, "//", ping);
  if (switched.find("A:R1#") == std::string::npos) {
    throw std::runtime_error(
        "Session did not switch to the classic CLI prompt");
  }
  router::execute_cli(state, session, "configure card 1 card-type iom4-e",
                      ping);
  router::execute_cli(state, session,
                      "configure card 1 mda 1 mda-type me10-10gb-sfp+", ping);
  if (!router::profile_mda(state.configuration.running).type ||
      router::profile_mda(state.hardware).type) {
    throw std::runtime_error(
        "classic CLI provisioning changed physical equipment");
  }

  // Official engine interaction retains a dirty MD candidate across classic
  // writes. Returning to MD must show an outdated baseline and must not commit
  // that stale candidate as though no concurrent configuration change occurred.
  // Establish a clean unprovisioned running baseline through the classic
  // engine, then create a new dirty MD candidate above that baseline.
  router::execute_cli(state, session, "configure card 1 no card-type", ping);
  router::execute_cli(state, session, "//", ping);
  router::execute_cli(state, session,
                      "configure card 1 mda 1 mda-type me10-10gb-sfp+", ping);
  router::execute_cli(state, session, "configure card 1 card-type iom4-e",
                      ping);
  router::execute_cli(state, session, "//", ping);
  router::execute_cli(state, session, "configure card 1 card-type iom4-e",
                      ping);
  const auto stale_prompt = router::execute_cli(state, session, "//", ping);
  if (!session.candidate_dirty || !session.candidate_outdated ||
      !router::profile_mda(state.configuration.candidate).type ||
      stale_prompt.find("!*[ex:/]") == std::string::npos) {
    throw std::runtime_error(
        "classic CLI overwrote or hid a dirty MD candidate");
  }
  const auto stale_commit = router::execute_cli(state, session, "commit", ping);
  if (stale_commit.find("baseline is out of date") == std::string::npos) {
    throw std::runtime_error(
        "MD-CLI accepted a commit from an outdated baseline");
  }
  router::execute_cli(state, session, "discard", ping);

  // Port nodes exist only below provisioned MDA inventory. Recreate that
  // parent before testing port leaves instead of relying on implicit ports.
  router::execute_cli(state, session,
                      "configure card 1 mda 1 mda-type me10-10gb-sfp+", ping);
  router::execute_cli(state, session, "configure system name edge-r1", ping);
  router::execute_cli(state, session,
                      "configure port 1/1/1 admin-state disable", ping);
  router::execute_cli(state, session, "configure port 1/1/1 ethernet mtu 1400",
                      ping);
  router::execute_cli(state, session,
                      "configure port 1/1/1 description \"host-a\"", ping);
  router::execute_cli(state, session,
                      "configure router \"Base\" static-routes route "
                      "203.0.113.0/24 next-hop 198.51.100.2",
                      ping);
  router::execute_cli(state, session, "commit", ping);
  const auto &running = state.configuration.running;
  if (std::string_view(running.system_name.data()) != "edge-r1" ||
      running.ports[0].admin_enabled || running.ports[0].mtu != 1400 ||
      std::string_view(running.ports[0].description.data()) != "host-a" ||
      !running.static_routes[0].valid) {
    throw std::runtime_error(
        "MD-CLI canonical configuration did not commit atomically");
  }

  std::uint32_t requested_count{};
  router::packet::Ipv4 requested_destination{};
  const auto counted_ping = [&](router::packet::Ipv4 destination,
                                std::uint32_t count) {
    requested_destination = destination;
    requested_count = count;
    return std::string{"ping-result"};
  };
  const auto default_ping =
      router::execute_cli(state, session, "ping 198.51.100.2", counted_ping);
  if (requested_count != 5 ||
      requested_destination != router::packet::Ipv4{198, 51, 100, 2} ||
      default_ping.find("ping-result") == std::string::npos) {
    throw std::runtime_error("SR OS ping default count was not applied");
  }
  router::execute_cli(state, session, "ping 198.51.100.2 count 1",
                      counted_ping);
  if (requested_count != 1)
    throw std::runtime_error("Explicit ping count was ignored");

  // Completion queries the active engine schema without executing a command.
  // A context lists only its immediate children. It must never print complete
  // provisioning or ping lines that resemble a preloaded demo transcript.
  const auto root_completion = router::complete_cli(state, session, "");
  if (router::complete_cli(state, session, "show router ar") !=
          "show router arp" ||
      router::complete_cli(state, session, "show").find("port") ==
          std::string::npos ||
      root_completion.find("configure card 1") != std::string::npos ||
      root_completion.find("ping 198.51.100.2") != std::string::npos) {
    throw std::runtime_error(
        "CLI completion exposed a hardcoded command transcript");
  }

  const auto unknown = router::execute_cli(state, session, "jjj", ping);
  if (unknown.find("MGMT_CORE #2201") == std::string::npos ||
      unknown.find("milestone") != std::string::npos ||
      unknown.find("profile") != std::string::npos) {
    throw std::runtime_error("CLI leaked implementation status to the console");
  }
  const auto incomplete_ping =
      router::execute_cli(state, session, "ping", ping);
  if (incomplete_ping.find("<ipv4>") == std::string::npos ||
      incomplete_ping.find("192.0.2.2") == std::string::npos ||
      incomplete_ping.find("198.51.100.2") == std::string::npos) {
    throw std::runtime_error(
        "Incomplete ping did not show its contextual destination choices");
  }
}
