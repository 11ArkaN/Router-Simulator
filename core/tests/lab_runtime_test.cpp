// Product ABI facade tests. Messages use the same generated protocol 3 names
// and netstring framing as the browser Worker, while all network behavior still
// executes through RuntimeSupervisor and its real network pthread.

#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_runtime.hpp"
#include "router/shard_policy.hpp"

#include <chrono>
#include <initializer_list>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::string message(std::string_view operation,
                    std::initializer_list<std::string_view> fields = {}) {
  std::string result;
  const auto add = [&](std::string_view value) {
    result += std::to_string(value.size()) + ':';
    result.append(value);
    result += ',';
  };
  add(operation);
  for (const auto field : fields)
    add(field);
  return result;
}

std::string nested(std::initializer_list<std::string_view> fields) {
  // Atomic form payloads deliberately use the same byte-length framing as the
  // public operation. This fixture therefore exercises spaces and empty leaf
  // values without relying on a test-only delimiter.
  std::string result;
  for (const auto field : fields) {
    result += std::to_string(field.size()) + ':';
    result.append(field);
    result += ',';
  }
  return result;
}

void require(bool condition, const char *reason) {
  if (!condition)
    throw std::runtime_error(reason);
}

} // namespace

void lab_runtime_tests() {
  using namespace router;
  using namespace router::lab;
  LabRuntime runtime;
  auto output = runtime.command(message(lab_runtime_protocol::snapshot));
  require(output.find("\"routers\":[]") != std::string_view::npos &&
              output.find("\"hosts\":[]") != std::string_view::npos,
          "protocol 3 runtime invented a default topology");
  // Startup must expose every owner selected from the same generated policy
  // as the Emscripten pthread pool. Re-publishing is permitted while pthreads
  // enter their loops, but duplicate IDs or an idle reserved slot are not.
  const auto expected_workers =
      select_shard_policy(std::thread::hardware_concurrency()).worker_domains();
  bool owners_ready{};
  for (std::size_t attempt = 0; attempt < 200U && !owners_ready; ++attempt) {
    static_cast<void>(
        runtime.command(message(lab_runtime_protocol::snapshot)));
    const auto &telemetry = runtime.telemetry_page();
    std::set<std::uint64_t> owners;
    owners_ready = telemetry.worker_count == expected_workers;
    for (std::size_t index = 0; owners_ready && index < expected_workers;
         ++index) {
      const auto &worker = telemetry.workers[index];
      owners_ready = worker.running && worker.thread_id &&
                     owners.insert(worker.thread_id).second;
    }
    if (!owners_ready)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  require(owners_ready,
          "telemetry did not publish every distinct generated shard owner");

  output = runtime.command(message(lab_runtime_protocol::router_create,
                                   {"r1", "7750-sr-1", "R1"}));
  require(!output.starts_with("ERROR:") &&
              output.find("\"profileId\":\"7750-sr-1\"") !=
                  std::string_view::npos,
          "protocol 3 router creation failed");
  require(runtime.command(message(lab_runtime_protocol::router_create,
                                  {"r1", "7750-sr-7", "duplicate"}))
              .starts_with("ERROR:"),
          "protocol 3 accepted duplicate stable router identity");

  require(!runtime.command(message(lab_runtime_protocol::router_create,
                                   {"r7", "7750-sr-7", "R7"}))
               .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::session_create,
                                       {"r7-console", "r7", "exclusive"}))
                   .starts_with("ERROR:"),
          "profile completion fixture could not create an SR-7 session");
  const auto sr7_cards = runtime.command(message(
      lab_runtime_protocol::session_complete,
      {"r7-console", "configure card 1 card-type ", "question"}));
  require(sr7_cards.find("iom4-e") != std::string_view::npos &&
              sr7_cards.find("iom5-e") != std::string_view::npos &&
              sr7_cards.find("cpm-1") == std::string_view::npos,
          "CLI completion escaped the selected router profile catalog");
  require(!runtime.command(message(lab_runtime_protocol::session_close,
                                   {"r7-console"}))
               .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::router_delete,
                                       {"r7"}))
                   .starts_with("ERROR:"),
          "profile completion fixture did not release its router and session");

  require(!runtime.command(message(lab_runtime_protocol::port_configure,
                                   {"r1", "1/1/1", "1", "9212", "100000",
                                    "edge port"}))
               .starts_with("ERROR:"),
          "fixed-profile port configuration failed");
  require(!runtime.command(message(lab_runtime_protocol::interface_configure,
                                   {"r1", "edge", "1/1/1",
                                    "192.0.2.1/30", "1"}))
               .starts_with("ERROR:"),
          "router interface operation failed");
  require(!runtime.command(message(lab_runtime_protocol::host_create,
                                   {"host-a", "Host A"}))
               .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::host_configure,
                                       {"host-a", "02:00:00:00:aa:01",
                                        "192.0.2.2/30", "192.0.2.1", "1500"}))
                   .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::link_create,
                                       {"edge-link", "r1", "1/1/1", "host-a",
                                        "eth0", "100", "1"}))
                   .starts_with("ERROR:"),
          "protocol 3 host or physical link operation failed");
  require(!runtime.command(message(lab_runtime_protocol::link_properties_set,
                                   {"edge-link", "1", "250"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::snapshot))
                      .find("\"propagationDelayNs\":250") !=
                  std::string_view::npos,
          "protocol 3 link property edit did not reach topology ownership");
  require(!runtime.command(message(lab_runtime_protocol::static_route_add,
                                   {"r1", "203.0.113.0/24", "192.0.2.2"}))
               .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::static_route_delete,
                                       {"r1", "203.0.113.0/24"}))
                   .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::static_route_delete,
                                      {"r1", "203.0.113.0/24"}))
                  .starts_with("ERROR:"),
          "protocol 3 static route removal accepted a successful no-op");

  const auto replacement = nested({"R1", "1", "1/1/1", "1", "9212",
                                   "100000", "edge port", "1", "edge",
                                   "1/1/1", "192.0.2.1/30", "1", "0"});
  require(!runtime.command(message(
                  lab_runtime_protocol::router_configuration_replace,
                  {"r1", replacement}))
               .starts_with("ERROR:"),
          "atomic running configuration replacement was rejected");
  const std::string before_invalid{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  const auto duplicate_interface = nested(
      {"R1", "1", "1/1/1", "1", "9212", "100000", "edge port", "2",
       "edge", "1/1/1", "192.0.2.1/30", "1", "edge", "1/1/1",
       "192.0.2.1/30", "1", "0"});
  require(runtime.command(message(
                  lab_runtime_protocol::router_configuration_replace,
                  {"r1", duplicate_interface}))
                  .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::snapshot)) ==
                  before_invalid,
          "invalid atomic replacement changed part of the running datastore");

  require(!runtime.command(message(lab_runtime_protocol::session_create,
                                   {"r1-console-1", "r1", "operational"}))
               .starts_with("ERROR:"),
          "router-scoped terminal session creation failed");
  const auto state = runtime.command(message(lab_runtime_protocol::session_state,
                                             {"r1-console-1"}));
  require(state.find("A:admin@R1#") != std::string_view::npos,
          "terminal state did not use its router system name");
  const auto show = runtime.command(message(lab_runtime_protocol::session_execute,
                                            {"r1-console-1",
                                             "show system information"}));
  require(show.find("System Type            : 7750 SR-1") !=
              std::string_view::npos,
          "terminal show output ignored selected device profile");
  const auto switched = runtime.command(message(lab_runtime_protocol::session_execute,
                                                {"r1-console-1", "//"}));
  require(switched.find("A:R1#") != std::string_view::npos,
          "engine switch escaped its router terminal session");
  const auto switched_back = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "//"}));
  require(switched_back.find("A:admin@R1#") != std::string_view::npos,
          "classic to MD engine switch lost the router-owned session");
  const auto configure = runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "configure exclusive"}));
  require(configure.find("[ex:/configure]") != std::string_view::npos,
          "MD container navigation was not retained by protocol 3");
  const auto parent = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "back"}));
  require(parent.find("[/]") != std::string_view::npos,
          "MD parent navigation did not return to the root context");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "configure exclusive"}))
              .find("[ex:/configure]") != std::string_view::npos,
          "MD configuration context could not be re-entered before checkpoint");
  const std::string candidate_edit{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "system name candidate-r1"}))};
  require(candidate_edit.find("MINOR:") == std::string_view::npos,
          "exclusive MD edit rejected a valid candidate value");
  const std::string candidate_compare{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "compare"}))};
  const std::string precommit_snapshot{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  if (candidate_compare.find("candidate-r1") == std::string_view::npos ||
      precommit_snapshot.find("\"systemName\":\"R1\"") ==
          std::string_view::npos)
    throw std::runtime_error("candidate compare lost the edit: edit=" +
                             candidate_edit + " compare=" +
                             candidate_compare);
  const std::string md_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}))};
  const std::string committed_snapshot{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  if (md_commit.find("MGMT_CORE #") != std::string_view::npos ||
      committed_snapshot.find("\"systemName\":\"candidate-r1\"") ==
          std::string_view::npos)
    throw std::runtime_error(
        "exclusive MD commit did not publish its value candidate: " +
        std::string{md_commit} + " edit=" + candidate_edit +
        " compare=" + candidate_compare +
        " snapshot=" + std::string{committed_snapshot});
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "exit all"}))
                  .find("[/]") != std::string_view::npos,
          "clean exclusive workflow could not return to operational mode");

  require(!runtime.command(message(lab_runtime_protocol::session_create,
                                   {"r1-console-2", "r1", "operational"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-2", "configure read-only"}))
                      .find("[ro:/configure]") != std::string_view::npos &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-2",
                                       "system name forbidden"}))
                      .find("Operation not allowed") != std::string_view::npos,
          "read-only workflow accepted a candidate mutation");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "exit all"})));

  require(!runtime.command(message(lab_runtime_protocol::session_create,
                                   {"r1-console-3", "r1", "operational"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-2", "configure private"}))
                      .find("[pr:/configure]") != std::string_view::npos &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-3", "configure private"}))
                      .find("[pr:/configure]") != std::string_view::npos,
          "independent private MD candidates could not be opened");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-2", "system name private-first"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-3", "system name private-second"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "commit"})));
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-3", "commit"}))
                  .find("conflicts") != std::string_view::npos &&
              runtime.command(message(lab_runtime_protocol::snapshot))
                      .find("\"systemName\":\"private-first\"") !=
                  std::string_view::npos,
          "same-path private conflict overwrote a newer running value");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "exit all"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-3", "discard"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-3", "exit all"})));

  // A classic command that repeats the running value still passes through the
  // real lock and parser, but it must not publish a fictitious running
  // revision. Otherwise an untouched private candidate would immediately gain
  // the MD stale marker and fail its next commit.
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-2", "configure private"}))
                  .find("[pr:/configure]") != std::string_view::npos &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-1", "//"}))
                      .find("A:private-first#") != std::string_view::npos,
          "idempotent classic fixture could not open both terminal engines");
  const auto classic_no_op = runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "configure system name private-first"}));
  const auto private_after_no_op = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "compare"}));
  require(classic_no_op.find("Error:") == std::string_view::npos &&
              private_after_no_op.find("!(pr)") == std::string_view::npos &&
              private_after_no_op.find("![pr:") == std::string_view::npos,
          "idempotent classic write advanced the running generation");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "//"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "exit all"})));

  const std::string first_global{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "configure global"}))};
  const std::string second_global{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-2", "configure global"}))};
  require(first_global.find("CLI #2054: Entering global") !=
                  std::string::npos &&
              second_global.find("CLI #2075: Other global") !=
                  std::string::npos,
          "global sessions did not use documented entry and sharing messages");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "system name shared-global"})));
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-2", "compare"}))
                  .find("shared-global") != std::string_view::npos,
          "global candidate value was not shared between router sessions");
  const std::string denied_transition{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "edit-config exclusive"}))};
  if (denied_transition.find("MGMT_CORE #2052") == std::string::npos)
    throw std::runtime_error(
        "exclusive transition ignored another global session: " +
        denied_transition);
  const std::string global_exit{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-2", "exit all"}))};
  if (global_exit.find("CLI #2056: Exiting global") == std::string::npos ||
      global_exit.find("CLI #2057: Uncommitted changes are kept") ==
          std::string::npos)
    throw std::runtime_error(
        "global exit claimed that shared candidate changes were discarded: " +
        global_exit);
  const std::string exclusive_transition{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "edit-config exclusive"}))};
  require(exclusive_transition.find("CLI #2060: Entering exclusive") !=
                  std::string::npos &&
              exclusive_transition.find("(ex)[/configure]") !=
                  std::string::npos,
          "global candidate did not transition to an explicit exclusive session");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "discard"})));
  const std::string read_only_transition{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "edit-config read-only"}))};
  require(read_only_transition.find("CLI #2066: Entering read-only") !=
                  std::string::npos &&
              read_only_transition.find("(ro)[/configure]") !=
                  std::string::npos,
          "exclusive session did not transition to read-only mode");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "exit all"})));
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "quit-config"}))
                  .find("CLI #2067: Exiting read-only") !=
              std::string_view::npos,
          "read-only exit used another candidate mode's message");

  std::string ping_output{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1",
       "ping 192.0.2.2 count 1 size 100 do-not-fragment"}))};
  for (std::size_t attempt = 0;
       attempt < 200U && ping_output.find("pending") != std::string::npos;
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    ping_output += runtime.command(message(lab_runtime_protocol::session_poll,
                                           {"r1-console-1"}));
  }
  require(ping_output.find("108 bytes from 192.0.2.2") !=
                  std::string_view::npos &&
              ping_output.find("1 packets transmitted, 1 packets received") !=
                  std::string_view::npos,
          "asynchronous CLI ping did not return through the packet path");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "ping 192.0.2.2 count 5"})));
  require(!runtime.command(message(lab_runtime_protocol::session_cancel,
                                   {"r1-console-1"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::session_poll,
                                      {"r1-console-1"}))
                      .find("ping statistics") != std::string_view::npos,
          "out-of-band terminal cancellation did not stop active ping");
  require(!runtime.command(message(lab_runtime_protocol::interface_delete,
                                   {"r1", "edge"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::interface_delete,
                                      {"r1", "edge"}))
                  .starts_with("ERROR:"),
          "protocol 3 interface removal accepted a successful no-op");

  require(!runtime.command(message(lab_runtime_protocol::interface_configure,
                                   {"r1", "checkpoint-edge", "1/1/1",
                                    "192.0.2.1/30", "1"}))
               .starts_with("ERROR:") &&
              !runtime.command(message(lab_runtime_protocol::capture_point_set,
                                       {"router-ingress", "r1", "1/1/1",
                                        "0", "1"}))
                   .starts_with("ERROR:"),
          "portable checkpoint fixture could not be configured");
  const std::string capture_before{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  require(capture_before.find("\"kind\":\"router-ingress\"") !=
              std::string_view::npos,
          "snapshot ABI 5 omitted an active capture selection");
  const auto invalid_capture_replacement =
      nested({"1", "link-direction", "missing-link", "", "0", "1"});
  require(runtime.command(message(
                  lab_runtime_protocol::capture_selection_replace,
                  {invalid_capture_replacement}))
                  .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::snapshot)) ==
                  capture_before,
          "rejected capture replacement changed the active selection");
  const auto capture_replacement = nested(
      {"2", "router-ingress", "r1", "1/1/1", "0", "1",
       "link-direction", "edge-link", "", "0", "1"});
  const auto replaced_capture = runtime.command(message(
      lab_runtime_protocol::capture_selection_replace,
      {capture_replacement}));
  require(!replaced_capture.starts_with("ERROR:") &&
              replaced_capture.find("\"kind\":\"router-ingress\"") !=
                  std::string_view::npos &&
              replaced_capture.find("\"kind\":\"link-direction\"") !=
                  std::string_view::npos,
          "atomic capture replacement did not publish both locations");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "configure exclusive"}))
                  .find("[ex:/configure]") != std::string_view::npos,
          "checkpoint fixture could not reserve an exclusive session");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "system name checkpoint-candidate"}))
                  .find("*[ex:/configure]") != std::string_view::npos,
          "checkpoint fixture could not create a dirty value candidate");
  require(!runtime.command(message(lab_runtime_protocol::session_create,
                                   {"r1-console-4", "r1", "operational"}))
               .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-4",
                                       "ping 192.0.2.2 count 1"}))
                      .find("pending") != std::string_view::npos,
          "checkpoint fixture could not start an asynchronous operation");

  const auto checkpoint = runtime.export_checkpoint();
  require(!checkpoint.empty(), "protocol 3 checkpoint export failed");
  const std::vector<std::uint8_t> owned(checkpoint.begin(), checkpoint.end());
  LabRuntime restored;
  require(restored.import_checkpoint(owned),
          "protocol 3 checkpoint import rejected a valid value graph");
  const auto restored_snapshot =
      restored.command(message(lab_runtime_protocol::snapshot));
  require(restored_snapshot.find("\"id\":\"r1\"") !=
                  std::string_view::npos &&
              restored_snapshot.find("\"description\":\"edge port\"") !=
                  std::string_view::npos &&
              restored_snapshot.find("\"name\":\"checkpoint-edge\"") !=
                  std::string_view::npos &&
              restored.command(message(lab_runtime_protocol::session_state,
                                       {"r1-console-1"}))
                      .find("*[ex:/configure]") != std::string_view::npos &&
              restored.command(message(lab_runtime_protocol::session_execute,
                                       {"r1-console-1", "compare"}))
                      .find("checkpoint-candidate") != std::string_view::npos &&
              restored_snapshot.find("\"kind\":\"link-direction\"") !=
                  std::string_view::npos,
          "bare checkpoint lost portable router or terminal configuration");
  require(!restored.command(message(lab_runtime_protocol::capture_point_set,
                                    {"router-ingress", "r1", "1/1/1", "0",
                                     "0"}))
               .starts_with("ERROR:"),
          "checkpoint lost the stable capture location identity");
  std::string restored_ping;
  for (std::size_t attempt = 0; attempt < 200U; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    restored_ping += restored.command(message(lab_runtime_protocol::session_poll,
                                              {"r1-console-4"}));
    if (restored_ping.find("packets received") != std::string::npos)
      break;
  }
  require(restored_ping.find("1 packets transmitted, 1 packets received") !=
              std::string_view::npos,
          "checkpoint lost asynchronous ping state or relative deadlines");
}
