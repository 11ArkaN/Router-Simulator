// Product ABI facade tests. Messages use the same generated protocol 4 names
// and netstring framing as the browser Worker, while all network behavior still
// executes through RuntimeSupervisor and its real network pthread.

#include "router/generated_lab_runtime_protocol.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/lab_runtime.hpp"
#include "router/shard_policy.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <initializer_list>
#include <memory>
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

std::string nested(const std::vector<std::string> &fields) {
  // Dynamic wall-clock schedule values use the same exact framing helper as
  // literal fixtures. Keeping one codec prevents this DNSSEC test from
  // smuggling separators that production parsing would never accept.
  std::string result;
  for (const auto &field : fields) {
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

router::packet::Ipv6 ipv6_address(const char *text) {
  // Keep checkpoint assertions on parsed wire values. Comparing formatted
  // strings would accidentally test one presentation spelling instead of the
  // canonical 128-bit address retained by the runtime.
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("invalid IPv6 address fixture");
  return *parsed;
}

std::string_view capture_projection(std::string_view snapshot) {
  constexpr std::string_view prefix{"\"capturePoints\":["};
  constexpr std::string_view suffix{"],\"activeLinks\":"};
  const auto begin = snapshot.find(prefix);
  if (begin == std::string_view::npos)
    return {};
  const auto content = begin + prefix.size();
  const auto end = snapshot.find(suffix, content);
  return end == std::string_view::npos
             ? std::string_view{}
             : snapshot.substr(content, end - content);
}

} // namespace

void lab_runtime_tests() {
  using namespace router;
  using namespace router::lab;
  LabRuntime runtime;
  const std::array<std::uint8_t, 32U> project_key{
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
      0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
      0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50};
  const std::array<std::uint8_t, 19U> project_context{
      'l', 'a', 'b', '-', 'r', 'u', 'n', 't', 'i', 'm',
      'e', '/', 'v', 'a', 'u', 'l', 't', '/', '1'};
  require(runtime.initialize_secret_vault(project_key, project_context),
          "protocol runtime rejected valid project vault material");
  require(runtime.initialize_secret_vault(project_key, project_context),
          "protocol runtime rejected idempotent project vault initialization");
  auto replacement_key = project_key;
  replacement_key.front() ^= 0xffU;
  require(!runtime.initialize_secret_vault(replacement_key, project_context),
          "protocol runtime allowed a split control and DNSSEC vault key");
  auto output = runtime.command(message(lab_runtime_protocol::snapshot));
  require(output.find("\"routers\":[]") != std::string_view::npos &&
              output.find("\"hosts\":[]") != std::string_view::npos,
          "protocol 4 runtime invented a default topology");
  // Startup must expose every owner selected from the same generated policy
  // as the Emscripten pthread pool. Re-publishing is permitted while pthreads
  // enter their loops, but duplicate IDs or an idle reserved slot are not.
  const auto expected_workers =
      select_shard_policy(std::thread::hardware_concurrency()).worker_domains();
  bool owners_ready{};
  for (std::size_t attempt = 0; attempt < 200U && !owners_ready; ++attempt) {
    static_cast<void>(runtime.command(message(lab_runtime_protocol::snapshot)));
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

  output = runtime.command(
      message(lab_runtime_protocol::router_create, {"r1", "7750-sr-1", "R1"}));
  require(!output.starts_with("ERROR:") &&
              output.find("\"profileId\":\"7750-sr-1\"") !=
                  std::string_view::npos,
          "protocol 4 router creation failed");
  require(runtime
              .command(message(lab_runtime_protocol::router_create,
                               {"r1", "7750-sr-7", "duplicate"}))
              .starts_with("ERROR:"),
          "protocol 4 accepted duplicate stable router identity");

  require(!runtime.command(message(lab_runtime_protocol::router_create,
                                   {"r7", "7750-sr-7", "R7"}))
                  .starts_with("ERROR:") &&
              !runtime
                   .command(message(lab_runtime_protocol::session_create,
                                    {"r7-console", "r7", "exclusive"}))
                   .starts_with("ERROR:"),
          "profile completion fixture could not create an SR-7 session");
  const auto sr7_cards = runtime.command(
      message(lab_runtime_protocol::session_complete,
              {"r7-console", "configure card 1 card-type ", "question"}));
  require(sr7_cards.find("iom4-e") != std::string_view::npos &&
              sr7_cards.find("iom5-e") != std::string_view::npos &&
              sr7_cards.find("cpm-1") == std::string_view::npos,
          "CLI completion escaped the selected router profile catalog");
  require(
      !runtime.command(
                  message(lab_runtime_protocol::session_close, {"r7-console"}))
              .starts_with("ERROR:") &&
          !runtime.command(message(lab_runtime_protocol::router_delete, {"r7"}))
               .starts_with("ERROR:"),
      "profile completion fixture did not release its router and session");

  require(!runtime
               .command(
                   message(lab_runtime_protocol::port_configure,
                           {"r1", "1/1/1", "1", "9212", "100000", "edge port"}))
               .starts_with("ERROR:"),
          "fixed-profile port configuration failed");
  require(!runtime
               .command(message(
                   lab_runtime_protocol::interface_configure,
                   {"r1", "edge", "1/1/1", "192.0.2.1/30", "", "", "1"}))
               .starts_with("ERROR:"),
          "router interface operation failed");
  require(
      !runtime.command(message(lab_runtime_protocol::host_create,
                               {"host-a", "Host A"}))
              .starts_with("ERROR:") &&
          !runtime
               .command(message(lab_runtime_protocol::host_configure,
                                {"host-a", "02:00:00:00:aa:01", "192.0.2.2/30",
                                 "192.0.2.1", "1500", "1", "1", "stable-opaque",
                                 "000102030405060708090a0b0c0d0e0f"
                                 "101112131415161718191a1b1c1d1e1f",
                                 "edge-link",
                                 "0102030405060708090a0b0c0d0e0f10"
                                 "1112131415161718191a1b1c1d1e1f20"}))
               .starts_with("ERROR:") &&
          !runtime
               .command(message(lab_runtime_protocol::link_create,
                                {"edge-link", "r1", "1/1/1", "host-a", "eth0",
                                 "100", "1", "0"}))
               .starts_with("ERROR:") &&
          runtime.command(message(lab_runtime_protocol::snapshot))
                  .find("\"ipv6InterfaceIdentifierMode\":"
                        "\"stable-opaque\"") != std::string_view::npos,
      "protocol 4 host or physical link operation failed");
  require(!runtime.command(message(lab_runtime_protocol::link_properties_set,
                                   {"edge-link", "1", "250", "0"}))
                  .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::snapshot))
                      .find("\"propagationDelayNs\":250") !=
                  std::string_view::npos,
          "protocol 4 link property edit did not reach topology ownership");

  const auto dhcpv6 = nested(
      {"1",
       "0003000102000000aa01",
       "0101010101010101010101010101010101010101010101010101010101010101",
       "1",
       "0",
       "1",
       "7",
       "ia-na",
       "1",
       "23",
       "1",
       "0003000102000000aa02",
       "100",
       "1",
       "86400",
       "",
       "",
       "3600",
       "0",
       "0",
       "1",
       "2001:db8::53",
       "1",
       "2001:db8:100::/64",
       "0202020202020202020202020202020202020202020202020202020202020202",
       "1800",
       "3600",
       "900",
       "1440",
       "1",
       "2001:db8:200::/56",
       "0303030303030303030303030303030303030303030303030303030303030303",
       "1800",
       "3600",
       "900",
       "1440",
       "64"});
  require(!runtime.command(message(lab_runtime_protocol::host_dhcpv6_replace,
                                   {"host-a", dhcpv6}))
                  .starts_with("ERROR:") &&
              runtime
                  .command(message(lab_runtime_protocol::host_dhcpv6_replace,
                                   {"host-a", nested({"1"})}))
                  .starts_with("ERROR:"),
          "protocol 4 DHCPv6 replacement accepted a partial record or rejected "
          "complete intent");
  const auto dns_wall_now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  const std::string dns_master =
      "$ORIGIN test.\n$TTL 300\n@ IN SOA ns hostmaster "
      "( 1 3600 600 86400 60 )\n@ IN NS ns\nns IN A 192.0.2.2\n";
  const auto dns = nested(std::vector<std::string>{
      "1",
      "1111111111111111111111111111111111111111111111111111111111111111",
      "0",
      "0",
      "1",
      "ns.test.",
      "1",
      "ipv4",
      "192.0.2.2",
      "0",
      "1",
      "1",
      "1",
      "test.",
      dns_master,
      "300",
      "60",
      "nsec",
      "3600",
      "1200",
      "600",
      "60",
      "2",
      "ksk",
      "15",
      "2048",
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now + 3600U),
      std::to_string(dns_wall_now + 3660U),
      std::to_string(dns_wall_now + 3720U),
      "zsk",
      "15",
      "2048",
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now - 60U),
      std::to_string(dns_wall_now + 3600U),
      std::to_string(dns_wall_now + 3660U),
      std::to_string(dns_wall_now + 3720U)});
  require(!runtime.command(message(lab_runtime_protocol::host_dns_replace,
                                   {"host-a", dns}))
                  .starts_with("ERROR:") &&
              runtime
                  .command(message(lab_runtime_protocol::host_dns_replace,
                                   {"host-a", nested({"1"})}))
                  .starts_with("ERROR:"),
          "protocol 4 DNS replacement accepted a partial record or rejected "
          "managed signing intent");
  require(!runtime.command(message(lab_runtime_protocol::static_route_add,
                                   {"r1", "203.0.113.0/24", "192.0.2.2"}))
                  .starts_with("ERROR:") &&
              !runtime
                   .command(message(lab_runtime_protocol::static_route_delete,
                                    {"r1", "203.0.113.0/24"}))
                   .starts_with("ERROR:") &&
              runtime
                  .command(message(lab_runtime_protocol::static_route_delete,
                                   {"r1", "203.0.113.0/24"}))
                  .starts_with("ERROR:"),
          "protocol 4 static route removal accepted a successful no-op");

  const auto replacement = nested({"R1",
                                   "1",
                                   "1",
                                   "1/1/1",
                                   "1",
                                   "9212",
                                   "100000",
                                   "edge port",
                                   "1",
                                   "edge",
                                   "1/1/1",
                                   "192.0.2.1/30",
                                   "120",
                                   "25",
                                   "1",
                                   "2001:db8:1::1/64",
                                   "1",
                                   "0",
                                   "",
                                   "0",
                                   "",
                                   "1",
                                   "0",
                                   "0"});
  require(
      !runtime.command(
                  message(lab_runtime_protocol::router_configuration_replace,
                          {"r1", replacement}))
              .starts_with("ERROR:") &&
          runtime.command(message(lab_runtime_protocol::snapshot))
                  .find("\"address\":\"2001:db8:1::1/64\"") !=
              std::string_view::npos,
      "atomic running configuration replacement was rejected");
  const std::string before_invalid{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  const auto duplicate_interface = nested({"R1",
                                           "1",
                                           "1",
                                           "1/1/1",
                                           "1",
                                           "9212",
                                           "100000",
                                           "edge port",
                                           "2",
                                           "edge",
                                           "1/1/1",
                                           "192.0.2.1/30",
                                           "",
                                           "",
                                           "1",
                                           "2001:db8:1::1/64",
                                           "1",
                                           "0",
                                           "",
                                           "0",
                                           "",
                                           "1",
                                           "edge",
                                           "1/1/1",
                                           "192.0.2.1/30",
                                           "",
                                           "",
                                           "1",
                                           "2001:db8:1::1/64",
                                           "1",
                                           "0",
                                           "",
                                           "0",
                                           "",
                                           "1",
                                           "0",
                                           "0"});
  require(runtime.command(
                     message(lab_runtime_protocol::router_configuration_replace,
                             {"r1", duplicate_interface}))
                  .starts_with("ERROR:") &&
              runtime.command(message(lab_runtime_protocol::snapshot)) ==
                  before_invalid,
          "invalid atomic replacement changed part of the running datastore");

  require(!runtime
               .command(message(lab_runtime_protocol::session_create,
                                {"r1-console-1", "r1", "operational"}))
               .starts_with("ERROR:"),
          "router-scoped terminal session creation failed");
  const auto state = runtime.command(
      message(lab_runtime_protocol::session_state, {"r1-console-1"}));
  require(state.find("A:admin@R1#") != std::string_view::npos,
          "terminal state did not use its router system name");
  const auto show =
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show system information"}));
  require(show.find("System Type            : 7750 SR-1") !=
              std::string_view::npos,
          "terminal show output ignored selected device profile");
  const auto switched = runtime.command(
      message(lab_runtime_protocol::session_execute, {"r1-console-1", "//"}));
  require(switched.find("A:R1#") != std::string_view::npos,
          "engine switch escaped its router terminal session");
  const auto switched_back = runtime.command(
      message(lab_runtime_protocol::session_execute, {"r1-console-1", "//"}));
  require(switched_back.find("A:admin@R1#") != std::string_view::npos,
          "classic to MD engine switch lost the router-owned session");
  const auto configure =
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "configure exclusive"}));
  require(configure.find("[ex:/configure]") != std::string_view::npos,
          "MD container navigation was not retained by protocol 4");
  const auto parent = runtime.command(
      message(lab_runtime_protocol::session_execute, {"r1-console-1", "back"}));
  require(parent.find("[/]") != std::string_view::npos,
          "MD parent navigation did not return to the root context");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "configure exclusive"}))
                  .find("[ex:/configure]") != std::string_view::npos,
          "MD configuration context could not be re-entered before checkpoint");
  const std::string candidate_edit{
      runtime.command(message(lab_runtime_protocol::session_execute,
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
                             candidate_edit + " compare=" + candidate_compare);
  const std::string md_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}))};
  const std::string committed_snapshot{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  if (md_commit.find("MGMT_CORE #") != std::string_view::npos ||
      committed_snapshot.find("\"systemName\":\"candidate-r1\"") ==
          std::string_view::npos)
    throw std::runtime_error(
        "exclusive MD commit did not publish its value candidate: " +
        std::string{md_commit} + " edit=" + candidate_edit + " compare=" +
        candidate_compare + " snapshot=" + std::string{committed_snapshot});

  // The MD delete paths address real leaves of the same dual-stack interface.
  // Remove and restore each IPv4 prerequisite inside the candidate so the
  // running forwarding owner never observes a half-configured test fixture.
  // The later IPv6 commit then proves those leaf operations did not erase any
  // unrelated interface state.
  for (const auto command :
       {"delete router \"Base\" interface edge ipv4 primary",
        "router \"Base\" interface edge ipv4 primary address "
        "192.0.2.1 prefix-length 30",
        "delete router \"Base\" interface edge port",
        "router \"Base\" interface edge port 1/1/1",
        "router \"Base\" interface edge ipv4 neighbor-discovery timeout 0",
        "delete router \"Base\" interface edge ipv4 neighbor-discovery timeout",
        "router \"Base\" interface edge ipv4 neighbor-discovery timeout 120",
        "router \"Base\" interface edge ipv4 neighbor-discovery retry-timer 25",
        "delete router \"Base\" interface edge ipv4 neighbor-discovery "
        "retry-timer",
        "router \"Base\" interface edge ipv4 neighbor-discovery retry-timer 25",
        "router \"Base\" interface edge ipv4 neighbor-discovery "
        "static-neighbor 192.0.2.2 mac-address 02:00:00:00:00:22"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid IPv4 MD leaf edit failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  for (const auto command :
       {"router \"Base\" interface edge ipv4 neighbor-discovery timeout 65536",
        "router \"Base\" interface edge ipv4 neighbor-discovery retry-timer 0",
        "router \"Base\" interface edge ipv4 neighbor-discovery retry-timer "
        "301",
        "router \"Base\" interface edge ipv4 neighbor-discovery "
        "static-neighbor 198.51.100.2 mac-address 02:00:00:00:00:22"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") != std::string_view::npos,
            "MD admitted an ARP timer outside the 26.7.R1 YANG range");
  for (const auto command :
       {"router \"Base\" interface system port 1/1/1",
        "router \"Base\" interface system ipv4 primary address "
        "10.255.0.1 prefix-length 31"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") != std::string_view::npos,
            "MD admitted a physical port or non-/32 system interface");
  for (const auto command :
       {"router \"Base\" interface system ipv4 primary address "
        "10.255.0.1 prefix-length 32",
        "router \"Base\" interface system admin-state enable"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid system interface MD edit failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "delete router \"Base\" interface system"}))
                  .find("MINOR:") == std::string_view::npos,
          "MD could not remove the complete system-interface list entry");
  for (const auto command :
       {"router \"Base\" interface system ipv4 primary address "
        "10.255.0.1 prefix-length 32",
        "router \"Base\" interface system admin-state enable"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") == std::string_view::npos,
            "MD could not recreate the system interface after list deletion");

  // IPv4 Redirect configuration is a real child of the numbered interface,
  // not merely accepted grammar. Exercise MD leaf presence and exact release
  // ranges before the shared dual-stack commit publishes it to forwarding.
  for (const auto command :
       {"router \"Base\" interface edge icmp redirects admin-state disable",
        "router \"Base\" interface edge icmp redirects number 321",
        "router \"Base\" interface edge icmp redirects seconds 17"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid IPv4 Redirect MD edit failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  for (const auto command :
       {"router \"Base\" interface edge icmp redirects number 9",
        "router \"Base\" interface edge icmp redirects number 1001",
        "router \"Base\" interface edge icmp redirects seconds 0",
        "router \"Base\" interface edge icmp redirects seconds 61"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") != std::string_view::npos,
            "MD IPv4 Redirect edit widened a Nokia 26.7 range");

  // IPv6 management coverage exercises the generated MD paths as one value
  // transaction. The static next hop is on the configured link, and RA is not
  // published to the forwarding owner until commit accepts the complete set.
  const std::array<std::string_view, 18> ipv6_candidate_commands{
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:1::1 prefix-length 64",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:2::1 prefix-length 64",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:2::1 duplicate-address-detection false",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:2::1 primary-preference 50",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:2::1 tag 700",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:3:: prefix-length 64",
      "router \"Base\" interface edge ipv6 address "
      "2001:db8:3:: eui-64 true",
      "router \"Base\" interface edge ipv6 icmp6 redirects admin-state "
      "disable",
      "router \"Base\" interface edge ipv6 icmp6 redirects number 321",
      "router \"Base\" interface edge ipv6 icmp6 redirects seconds 17",
      "router \"Base\" ipv6 router-advertisement interface edge "
      "prefix 2001:db8:1::/64 autonomous true",
      "router \"Base\" ipv6 router-advertisement interface edge "
      "prefix 2001:db8:1::/64 on-link true",
      "router \"Base\" ipv6 router-advertisement interface edge "
      "dns-options server 2001:db8:1::53",
      "router \"Base\" ipv6 router-advertisement dns-options server "
      "2001:db8:1::54",
      "router \"Base\" ipv6 router-advertisement dns-options "
      "rdnss-lifetime 1200",
      "router \"Base\" ipv6 router-advertisement interface edge "
      "dns-options include-dns true",
      "router \"Base\" ipv6 router-advertisement interface edge "
      "admin-state enable",
      "router \"Base\" static-routes route 2001:db8:ffff::/64 "
      "route-type unicast next-hop \"2001:db8:1::2\""};
  for (const auto command : ipv6_candidate_commands) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid IPv6 MD command failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  // Route siblings share one destination key but retain independent next-hop
  // children. Indirect intent is accepted even while inactive because no
  // dynamic protocol has published a resolver for it in this fixture.
  for (const auto command : {
           "router \"Base\" ecmp 2",
           "router \"Base\" static-routes route 203.0.113.0/24 route-type "
           "unicast next-hop \"192.0.2.2\"",
           "router \"Base\" static-routes route 203.0.113.0/24 route-type "
           "unicast next-hop \"192.0.2.3\"",
           "router \"Base\" static-routes route 198.51.100.0/24 route-type "
           "unicast indirect \"10.0.0.1\"",
           "router \"Base\" static-routes route 2001:db8:dead::/64 "
           "route-type unicast indirect \"2001:db8:ffff::1\""}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error("valid MD ECMP or indirect edit failed: " +
                               std::string{command} + " output=" +
                               std::string{result});
  }
  // Configure the complete referential chain exposed by the IPsec release
  // grammar through terminal bytes. Transform objects must exist before IKE
  // policy and profile leafrefs, while traffic-selector entries remain normal
  // candidate data until the same atomic commit publishes all of them.
  const std::array<std::string_view, 22> ipsec_md_commands{
      "ipsec ike-transform 19 dh-group group-19",
      "ipsec ike-transform 19 ike-auth-algorithm auth-encryption",
      "ipsec ike-transform 19 ike-encryption-algorithm aes256-gcm16",
      "ipsec ike-transform 19 ike-prf-algorithm sha-256",
      "ipsec ipsec-transform 7 esp-auth-algorithm auth-encryption",
      "ipsec ipsec-transform 7 esp-encryption-algorithm aes192-gcm16",
      "ipsec ike-policy 4 ike-transform 19",
      "ipsec ike-policy 4 dpd interval 45",
      "ipsec ts-list protected-v6 local entry 1 address prefix 2001:db8:1::/64",
      "ipsec ts-list protected-v6 remote entry 1 address prefix "
      "2001:db8:ffff::/64",
      "ipsec ppk-list core-peers ppk peer-a value ascii primary-ppk",
      "ipsec ipsec-transport-mode-profile gre-protected key-exchange dynamic "
      "ike-policy 4",
      "ipsec ipsec-transport-mode-profile gre-protected key-exchange dynamic "
      "ppk list core-peers",
      "ipsec ipsec-transport-mode-profile gre-protected key-exchange dynamic "
      "ppk id peer-a",
      "ipsec ipsec-transport-mode-profile gre-protected key-exchange dynamic "
      "pre-shared-key primary-ike-psk",
      "ipsec tunnel-template 10 ipsec-transform 7",
      "ipsec static-sa ospf3-auth description control-plane",
      "ipsec static-sa ospf3-auth direction bidirectional",
      "ipsec static-sa ospf3-auth protocol ah",
      "ipsec static-sa ospf3-auth spi 4096",
      "ipsec static-sa ospf3-auth authentication algorithm sha1",
      "ipsec static-sa ospf3-auth authentication key protected-manual-key "
      "hash2"};
  for (const auto command : ipsec_md_commands) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid IPsec MD command failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  const auto static_sa_completion = runtime.command(
      message(lab_runtime_protocol::session_complete,
              {"r1-console-1", "ipsec static-sa ", "question"}));
  require(static_sa_completion.find("ospf3-auth") != std::string_view::npos,
          "MD static-SA completion did not read candidate list ownership");
  // Space completion operates on a line relative to the saved /configure
  // context. The runtime may prepend that path while matching root grammar,
  // but it must remove the implicit portion before returning editable text.
  // Otherwise each accepted completion contaminates the following command
  // with an extra "configure" token even though the editor cleared on Enter.
  require(runtime.command(message(lab_runtime_protocol::session_complete,
                                  {"r1-console-1", "ipsec", "space"})) ==
              "ipsec",
          "MD Space completion leaked the implicit configure context");
  const auto invalid_ra_interval = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "router \"Base\" ipv6 router-advertisement interface edge "
               "min-advertisement-interval 500"}));
  require(invalid_ra_interval.find("MGMT_CORE #2301") != std::string_view::npos,
          "MD accepted an RFC-invalid RA min/max relationship");
  // Every defaulted RA leaf must retain presence independently of its
  // effective wire value. Exercise set and delete through the terminal so the
  // test covers generated grammar, candidate ownership and default restore,
  // rather than mutating the intent structure directly.
  for (const auto command :
       {"router \"Base\" ipv6 router-advertisement interface edge "
        "current-hop-limit 17",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "managed-configuration true",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "other-stateful-configuration true",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "max-advertisement-interval 300",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "min-advertisement-interval 100",
        "router \"Base\" ipv6 router-advertisement interface edge mtu "
        "1500",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "nd-router-preference high",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "reachable-time 400",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "retransmit-time 500",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "router-lifetime 900",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 preferred-lifetime 600",
        "router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 valid-lifetime 1200"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") == std::string_view::npos,
            "MD could not configure a documented RA leaf");
  for (const auto command :
       {"delete router \"Base\" ipv6 router-advertisement interface edge "
        "admin-state",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "current-hop-limit",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "managed-configuration",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "other-stateful-configuration",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "max-advertisement-interval",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "min-advertisement-interval",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "mtu",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "nd-router-preference",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "reachable-time",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "retransmit-time",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "router-lifetime",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 autonomous",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 on-link",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 valid-lifetime",
        "delete router \"Base\" ipv6 router-advertisement interface edge "
        "prefix 2001:db8:1::/64 preferred-lifetime"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "MD could not delete RA leaf: " + std::string{command} +
          " output=" + std::string{result});
  }
  require(
      runtime
              .command(message(
                  lab_runtime_protocol::session_execute,
                  {"r1-console-1",
                   "delete router \"Base\" ipv6 router-advertisement interface "
                   "edge current-hop-limit"}))
              .find("MGMT_CORE #2301") != std::string_view::npos,
      "MD accepted deletion of an absent RA leaf");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "router \"Base\" ipv6 router-advertisement "
                                   "interface edge "
                                   "prefix 2001:db8:3::/64 autonomous false"}))
                      .find("MINOR:") == std::string_view::npos &&
              runtime
                      .command(message(
                          lab_runtime_protocol::session_execute,
                          {"r1-console-1",
                           "delete router \"Base\" ipv6 router-advertisement "
                           "interface edge prefix 2001:db8:3::/64"}))
                      .find("MINOR:") == std::string_view::npos,
          "MD could not delete a complete RA prefix list instance");
  require(
      runtime
              .command(message(
                  lab_runtime_protocol::session_execute,
                  {"r1-console-1",
                   "router \"Base\" ipv6 router-advertisement interface edge "
                   "admin-state enable"}))
              .find("MINOR:") == std::string_view::npos,
      "MD could not re-enable RA after deleting admin-state");
  // These four edges are the exact ranges published by the release YANG.
  // Test each side independently so a later generic integer parser cannot
  // silently widen either the message budget or its measurement interval.
  for (const auto command :
       {"router \"Base\" interface edge ipv6 icmp6 redirects number 9",
        "router \"Base\" interface edge ipv6 icmp6 redirects number 1001",
        "router \"Base\" interface edge ipv6 icmp6 redirects seconds 0",
        "router \"Base\" interface edge ipv6 icmp6 redirects seconds 61"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") != std::string_view::npos,
            "MD ICMPv6 Redirect configuration admitted an invalid YANG value");
  // Keep one non-default RA scalar in the candidate through commit. Earlier
  // coverage exercised every leaf and its delete form, but restoring the
  // default before commit could not detect a lost candidate-to-forwarding
  // publication. The subsequent operational report therefore verifies the
  // complete owner chain instead of only the CLI editor.
  require(
      runtime
              .command(message(
                  lab_runtime_protocol::session_execute,
                  {"r1-console-1",
                   "router \"Base\" ipv6 router-advertisement interface edge "
                   "current-hop-limit 17"}))
              .find("MINOR:") == std::string_view::npos,
      "MD could not retain a non-default RA hop limit for commit");
  const auto ipv6_compare = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "compare"}));
  require(ipv6_compare.find("2001:db8:ffff::/64") != std::string_view::npos &&
              ipv6_compare.find("~ router \"Base\" interface \"edge\"") !=
                  std::string_view::npos,
          "MD compare omitted IPv6 routing or changed interface state");
  const auto ipv6_commit = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}));
  require(ipv6_commit.find("MGMT_CORE #") == std::string_view::npos,
          "valid dual-stack MD candidate did not commit atomically");
  require(runtime.command(message(lab_runtime_protocol::snapshot))
                  .find("\"address\":\"2001:db8:3::/64\","
                        "\"duplicateAddressDetection\":true,"
                        "\"eui64\":true") != std::string_view::npos,
          "MD EUI-64 leaf did not survive committed runtime projection");
  const std::string multipath_snapshot{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  require(multipath_snapshot.find("\"maximumEcmpPaths\":2") !=
              std::string_view::npos &&
              multipath_snapshot.find("\"nextHop\":\"192.0.2.2\","
                                      "\"indirect\":false") !=
                  std::string_view::npos &&
              multipath_snapshot.find("\"nextHop\":\"192.0.2.3\","
                                      "\"indirect\":false") !=
                  std::string_view::npos &&
              multipath_snapshot.find("\"nextHop\":\"10.0.0.1\","
                                      "\"indirect\":true") !=
                  std::string_view::npos,
          "MD commit lost ECMP width, route siblings or indirect intent");

  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "exit all"}))
                  .find("[/]") != std::string_view::npos,
          "IPsec operational fixture could not leave configuration context");

  const std::string system_interfaces{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router interface"}))};
  const std::string interface_summary{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router interface summary"}))};
  const std::string chassis_report{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show chassis"}))};
  const std::string selected_port_report{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show port 1/1/1"}))};
  const std::string system_routes{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router route-table"}))};
  const std::string ipv6_routes{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router route-table ipv6"}))};
  const std::string router_advertisement_report{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "show router rtr-advertisement interface edge"}))};
  const std::string system_fib{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router fib 1"}))};
  if (chassis_report.find("Name                              : candidate-r1") ==
          std::string_view::npos ||
      chassis_report.find("Type                              : 7750 SR-1") ==
          std::string_view::npos ||
      chassis_report.find("Num of physical ports") == std::string_view::npos ||
      selected_port_report.find("Ethernet Interface") ==
          std::string_view::npos ||
      selected_port_report.find("Interface          : 1/1/1") ==
          std::string_view::npos ||
      selected_port_report.find("Physical Link      : Yes") ==
          std::string_view::npos ||
      interface_summary.find("Router Summary (Interfaces)") ==
          std::string_view::npos ||
      interface_summary.find("1         Base") == std::string_view::npos ||
      system_interfaces.find("system") == std::string_view::npos ||
      system_interfaces.find("10.255.0.1/32") == std::string_view::npos ||
      system_interfaces.find("edge") == std::string_view::npos ||
      system_interfaces.find("Up/Up") == std::string_view::npos ||
      system_interfaces.find("2001:db8:2::1/64") == std::string_view::npos ||
      system_interfaces.find("PREFERRED") == std::string_view::npos ||
      system_routes.find("10.255.0.1/32") == std::string_view::npos ||
      system_routes.find("system") == std::string_view::npos ||
      ipv6_routes.find("IPv6 Route Table (Router: Base)") ==
          std::string_view::npos ||
      ipv6_routes.find("2001:db8:1::/64") == std::string_view::npos ||
      ipv6_routes.find("2001:db8:ffff::/64") == std::string_view::npos ||
      ipv6_routes.find("2001:db8:1::2") == std::string_view::npos ||
      router_advertisement_report.find("Hop Limit            : 17") ==
          std::string_view::npos ||
      system_fib.find("10.255.0.1/32") == std::string_view::npos ||
      system_fib.find("system") == std::string_view::npos)
    throw std::runtime_error(
        "system interface was absent from operational output: interfaces=" +
        std::string{system_interfaces} + " summary=" + interface_summary +
        " chassis=" + chassis_report + " selected-port=" +
        selected_port_report + " routes=" + std::string{system_routes} +
        " ipv6-routes=" + ipv6_routes + " ra=" + router_advertisement_report +
        " fib=" + std::string{system_fib});
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "show port 5/2/10"}))
                  .find("MGMT_CORE #2301") != std::string_view::npos,
          "selected port report fabricated an unequipped physical port");
  std::string system_ping{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "ping 10.255.0.1 count 1"}))};
  for (std::size_t attempt = 0;
       attempt < 200U && system_ping.find("pending") != std::string::npos;
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    system_ping += runtime.command(
        message(lab_runtime_protocol::session_poll, {"r1-console-1"}));
  }
  require(system_ping.find("1 packets transmitted, 1 packets received") !=
              std::string_view::npos,
          "terminal ping to the system interface did not terminate locally");
  std::string repeated_system_ping{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "ping 10.255.0.1 count 1"}))};
  for (std::size_t attempt = 0;
       attempt < 200U &&
       repeated_system_ping.find("pending") != std::string::npos;
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    repeated_system_ping += runtime.command(
        message(lab_runtime_protocol::session_poll, {"r1-console-1"}));
  }
  require(system_ping.find("icmp_seq=1") != std::string_view::npos &&
              repeated_system_ping.find("icmp_seq=1") != std::string_view::npos,
          "a new terminal ping inherited the preceding operation sequence");

  // Configuration mode still permits operational troubleshooting. The
  // unqualified command must resolve from the operational root instead of
  // being prefixed with the current /configure path.
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "show router interface"}))
                  .find("Interface Table (Router: Base)") !=
              std::string_view::npos,
          "MD configuration mode hid an operational show command");

  // Operational commands are run immediately after commit so this test fails
  // if a show path accidentally reads a private candidate or fabricates a
  // profile that the running datastore does not own.
  const std::string ipsec_ts_show{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "show ipsec ts-list protected-v6 local-entry 1"}))};
  const std::string ipsec_transport_show{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "show ipsec ipsec-transport-mode-profile gre-protected"}))};
  const std::string ipsec_tunnel_show{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show ipsec tunnel-template 10"}))};
  const std::string ipsec_static_show{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show ipsec static-sa name ospf3-auth"}))};
  if (ipsec_ts_show.find("2001:db8:1::/64") == std::string_view::npos ||
      ipsec_transport_show.find("IKE Policy Id    : 4") ==
          std::string_view::npos ||
      ipsec_tunnel_show.find("10") == std::string_view::npos ||
      ipsec_tunnel_show.find("7") == std::string_view::npos ||
      ipsec_static_show.find("ospf3-auth") == std::string_view::npos ||
      ipsec_static_show.find("4096") == std::string_view::npos ||
      ipsec_static_show.find("protected-manual-key") != std::string_view::npos)
    throw std::runtime_error(
        "IPsec operational reports did not read committed router intent: ts=" +
        std::string{ipsec_ts_show} +
        " transport=" + std::string{ipsec_transport_show} +
        " tunnel=" + std::string{ipsec_tunnel_show} +
        " static=" + std::string{ipsec_static_show});
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "configure exclusive"}))
                  .find("[ex:/configure]") != std::string_view::npos,
          "IPsec operational fixture could not resume MD configuration");

  // Build a complete PQC-only TLS 1.3 client and server through the same
  // terminal byte path used by xterm. References are created before profiles
  // are enabled, matching SR OS leafref and PQC assignment validation instead
  // of relying on a test-only configuration injection.
  const std::vector<std::string_view> tls_md_commands{
      "system security tls cert-profile router-cert admin-state enable",
      "system security tls cert-profile router-cert entry 1 certificate-file "
      "router.pem",
      "system security tls cert-profile router-cert entry 1 key-file "
      "router.key",
      "system security tls cert-profile router-cert entry 1 send-chain "
      "ca-profile root-ca",
      "system security tls trust-anchor-profile lab-roots trust-anchor root-ca",
      "system security tls client-cipher-list client-ciphers tls13-cipher 1 "
      "name tls-aes256-gcm-sha384",
      "system security tls client-group-list client-groups tls13-group 1 name "
      "tls-ml-kem1024",
      "system security tls client-signature-list client-signatures "
      "tls13-signature 1 name tls-ml-dsa87",
      "system security tls client-tls-profile dns-client cipher-list "
      "client-ciphers",
      "system security tls client-tls-profile dns-client group-list "
      "client-groups",
      "system security tls client-tls-profile dns-client signature-list "
      "client-signatures",
      "system security tls client-tls-profile dns-client trust-anchor-profile "
      "lab-roots",
      "system security tls client-tls-profile dns-client protocol-version "
      "tls-version-13",
      "system security tls client-tls-profile dns-client status-verify "
      "ee-revocation secondary ocsp",
      "system security tls client-tls-profile dns-client admin-state enable",
      "system security tls server-cipher-list server-ciphers tls13-cipher 1 "
      "name tls-aes256-gcm-sha384",
      "system security tls server-group-list server-groups tls13-group 1 name "
      "tls-ml-kem1024",
      "system security tls server-signature-list server-signatures "
      "tls13-signature 1 name tls-ml-dsa87",
      "system security tls server-tls-profile dns-server cert-profile "
      "router-cert",
      "system security tls server-tls-profile dns-server cipher-list "
      "server-ciphers",
      "system security tls server-tls-profile dns-server group-list "
      "server-groups",
      "system security tls server-tls-profile dns-server signature-list "
      "server-signatures",
      "system security tls server-tls-profile dns-server protocol-version "
      "tls-version-13",
      "system security tls server-tls-profile dns-server admin-state enable",
      // These edits deliberately configure release-default values and then
      // delete their leaves. A scalar-only model would reject each delete as
      // a no-op and would lose the distinction SR OS exposes through info and
      // compare. Restore the non-default values afterward for the live policy.
      "system security tls cert-profile router-cert admin-state disable",
      "delete system security tls cert-profile router-cert admin-state",
      "system security tls cert-profile router-cert admin-state enable",
      "system security tls client-tls-profile dns-client protocol-version "
      "tls-version-12",
      "delete system security tls client-tls-profile dns-client "
      "protocol-version",
      "system security tls client-tls-profile dns-client protocol-version "
      "tls-version-13",
      "system security tls client-tls-profile dns-client status-verify "
      "default-result revoked",
      "delete system security tls client-tls-profile dns-client status-verify "
      "default-result",
      "system security tls server-tls-profile dns-server admin-state disable",
      "delete system security tls server-tls-profile dns-server admin-state",
      "system security tls server-tls-profile dns-server admin-state enable",
      "system security tls use-pqc-only false",
      "delete system security tls use-pqc-only",
      "system security tls use-pqc-only true"};
  for (const auto command : tls_md_commands) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid TLS MD command failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  const auto tls_completion = runtime.command(
      message(lab_runtime_protocol::session_complete,
              {"r1-console-1",
               "system security tls client-tls-profile dns-client cipher-list ",
               "question"}));
  if (tls_completion.find("client-ciphers") == std::string_view::npos ||
      tls_completion.find("server-ciphers") != std::string_view::npos)
    throw std::runtime_error(
        "TLS completion ignored candidate ownership or crossed list "
        "namespaces: " +
        std::string{tls_completion});
  const auto tls_compare = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "compare"}));
  require(tls_compare.find("~ system security tls") != std::string_view::npos,
          "MD compare omitted the TLS candidate subtree");
  const auto tls_commit = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}));
  require(tls_commit.find("MGMT_CORE #") == std::string_view::npos,
          "complete TLS 1.3 candidate did not commit atomically");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "exit all"}))
                  .find("[/]") != std::string_view::npos,
          "clean exclusive workflow could not return to operational mode");

  // Classic uses explicit object creation and immediate writes. Exercise a
  // second independent client profile so the test cannot pass by reusing the
  // MD-created named objects or silently treating `create` as navigation.
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:candidate-r1#") != std::string_view::npos,
          "TLS classic fixture could not switch terminal engine");
  for (const auto command :
       {"configure router interface system port 1/1/1",
        "configure router interface system address 10.255.0.1/31"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") != std::string_view::npos,
            "classic admitted a physical port or non-/32 system interface");
  for (const auto command :
       {"configure router interface system shutdown",
        "configure router interface system no address",
        "configure router interface system address 10.255.0.1/32",
        "configure router interface system no shutdown",
        "configure router no interface system",
        "configure router interface system address 10.255.0.1/32",
        "configure router interface system no shutdown"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("Error:") != std::string_view::npos)
      throw std::runtime_error("valid classic system-interface edit failed: " +
                               std::string{command} +
                               " output=" + std::string{result});
  }
  const std::vector<std::string_view> tls_classic_commands{
      "configure system security tls no use-pqc-only",
      "configure system security tls client-cipher-list classic-ciphers create",
      "configure system security tls client-cipher-list classic-ciphers "
      "tls13-cipher 5 name tls-aes256-gcm-sha384",
      "configure system security tls client-group-list classic-groups create",
      "configure system security tls client-group-list classic-groups "
      "tls13-group 5 name tls-ml-kem1024",
      "configure system security tls client-signature-list classic-signatures "
      "create",
      "configure system security tls client-signature-list classic-signatures "
      "tls13-signature 5 name tls-ml-dsa87",
      "configure system security tls client-tls-profile classic-client create",
      "configure system security tls client-tls-profile classic-client "
      "cipher-list classic-ciphers",
      "configure system security tls client-tls-profile classic-client "
      "group-list classic-groups",
      "configure system security tls client-tls-profile classic-client "
      "signature-list classic-signatures",
      "configure system security tls client-tls-profile classic-client "
      "protocol-version tls-version13",
      "configure system security tls client-tls-profile classic-client no "
      "shutdown",
      "configure system security tls use-pqc-only"};
  for (const auto command : tls_classic_commands) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("Error:") != std::string_view::npos)
      throw std::runtime_error(
          "valid TLS classic command failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  // Classic CLI edits the same router-owned canonical model immediately, but
  // retains its own create/no syntax and command semantics. Independent IDs
  // make it impossible for this path to pass by reusing the MD objects above.
  const std::array<std::string_view, 17> ipsec_classic_commands{
      "configure ipsec ike-transform 20 create",
      "configure ipsec ike-transform 20 dh-group group-19",
      "configure ipsec ike-transform 20 ike-auth-algorithm auth-encryption",
      "configure ipsec ike-transform 20 ike-encryption-algorithm aes128-gcm16",
      "configure ipsec ike-transform 20 ike-prf-algorithm sha256",
      "configure ipsec ike-policy 5 create",
      "configure ipsec ike-policy 5 ike-version 2",
      "configure ipsec ike-policy 5 ike-transform 20",
      "configure ipsec ipsec-transform 8 create",
      "configure ipsec ipsec-transform 8 esp-auth-algorithm auth-encryption",
      "configure ipsec ipsec-transform 8 esp-encryption-algorithm aes256-gcm16",
      "configure ipsec static-sa classic-manual create",
      "configure ipsec static-sa classic-manual description classic-auth",
      "configure ipsec static-sa classic-manual direction inbound",
      "configure ipsec static-sa classic-manual protocol ah",
      "configure ipsec static-sa classic-manual spi 8192",
      "configure ipsec static-sa classic-manual authentication sha1 ascii-key "
      "12345678901234567890"};
  for (const auto command : ipsec_classic_commands) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("Error:") != std::string_view::npos ||
        result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error(
          "valid IPsec classic command failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:admin@candidate-r1#") != std::string_view::npos,
          "TLS classic fixture did not return to MD-CLI");

  // Operational reports read only running intent. The configured filenames
  // are visible, but their state remains down until the PKI owner binds and
  // validates the actual objects. This prevents a show-only success path from
  // masking an unavailable private key.
  const auto tls_client_show = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show system security tls client-tls-profile"}));
  require(tls_client_show.find("dns-client") != std::string_view::npos &&
              tls_client_show.find("classic-client") != std::string_view::npos,
          "TLS client profile report omitted running MD or classic state");
  const auto tls_server_show = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "show system security tls server-tls-profile dns-server"}));
  require(tls_server_show.find("Certificate Profile Name    : router-cert") !=
                  std::string_view::npos &&
              tls_server_show.find("Oper State                  : down") !=
                  std::string_view::npos,
          "TLS server detail fabricated an operational identity or lost its "
          "reference");
  const auto tls_certificate_show = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "show system security tls cert-profile router-cert entry 1"}));
  require(tls_certificate_show.find("Cert File        : router.pem") !=
                  std::string_view::npos &&
              tls_certificate_show.find("Key File         : router.key") !=
                  std::string_view::npos,
          "TLS certificate entry report did not use running profile data");
  const auto tls_trust_associations = runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1",
       "show system security tls trust-anchor-profile lab-roots association"}));
  require(tls_trust_associations.find(
              "TLS Client Profile             dns-client") !=
              std::string_view::npos,
          "TLS trust anchor association report ignored profile leafrefs");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "show system security tls cert-profile "
                                   "router-cert entry 9"}))
                  .find("MINOR:") != std::string_view::npos,
          "TLS certificate show accepted an entry outside the release range");

  require(
      !runtime.command(message(lab_runtime_protocol::session_create,
                               {"r1-console-2", "r1", "operational"}))
              .starts_with("ERROR:") &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-2", "configure read-only"}))
                  .find("[ro:/configure]") != std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-2", "system name forbidden"}))
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
  static_cast<void>(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-2", "system name private-first"})));
  static_cast<void>(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-3", "system name private-second"})));
  const std::string first_private_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "commit"}))};
  const std::string second_private_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-3", "commit"}))};
  const std::string private_snapshot{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  if (second_private_commit.find("conflicts") == std::string_view::npos ||
      private_snapshot.find("\"systemName\":\"private-first\"") ==
          std::string_view::npos)
    throw std::runtime_error(
        "same-path private conflict overwrote a newer running value: first=" +
        first_private_commit + " second=" + second_private_commit +
        " snapshot=" + private_snapshot);
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
  const auto classic_no_op = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "configure system name private-first"}));
  const auto private_after_no_op = runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "compare"}));
  require(classic_no_op.find("Error:") == std::string_view::npos &&
              private_after_no_op.find("!(pr)") == std::string_view::npos &&
              private_after_no_op.find("![pr:") == std::string_view::npos,
          "idempotent classic write advanced the running generation");
  static_cast<void>(runtime.command(
      message(lab_runtime_protocol::session_execute, {"r1-console-1", "//"})));
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "exit all"})));

  const std::string first_global{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "configure global"}))};
  const std::string second_global{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-2", "configure global"}))};
  require(
      first_global.find("CLI #2054: Entering global") != std::string::npos &&
          second_global.find("CLI #2075: Other global") != std::string::npos,
      "global sessions did not use documented entry and sharing messages");
  static_cast<void>(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "system name shared-global"})));
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-2", "compare"}))
                  .find("shared-global") != std::string_view::npos,
          "global candidate value was not shared between router sessions");
  const std::string denied_transition{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "edit-config exclusive"}))};
  if (denied_transition.find("MGMT_CORE #2052") == std::string::npos)
    throw std::runtime_error(
        "exclusive transition ignored another global session: " +
        denied_transition);
  const std::string global_exit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-2", "exit all"}))};
  if (global_exit.find("CLI #2056: Exiting global") == std::string::npos ||
      global_exit.find("CLI #2057: Uncommitted changes are kept") ==
          std::string::npos)
    throw std::runtime_error(
        "global exit claimed that shared candidate changes were discarded: " +
        global_exit);
  const std::string exclusive_transition{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "edit-config exclusive"}))};
  require(
      exclusive_transition.find("CLI #2060: Entering exclusive") !=
              std::string::npos &&
          exclusive_transition.find("(ex)[/configure]") != std::string::npos,
      "global candidate did not transition to an explicit exclusive session");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "discard"})));
  const std::string read_only_transition{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "edit-config read-only"}))};
  require(read_only_transition.find("CLI #2066: Entering read-only") !=
                  std::string::npos &&
              read_only_transition.find("(ro)[/configure]") !=
                  std::string::npos,
          "exclusive session did not transition to read-only mode");
  static_cast<void>(runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "exit all"})));
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "quit-config"}))
                  .find("CLI #2067: Exiting read-only") !=
              std::string_view::npos,
          "read-only exit used another candidate mode's message");

  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:private-first#") != std::string_view::npos,
          "classic IPv6 fixture could not switch terminal engines");
  // Both terminal engines expose the same forwarding-owned IPv6 RIB. Running
  // this after the engine transition catches a schema entry accidentally
  // limited to MD-CLI while avoiding a second source of route truth.
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router route-table ipv6"}))
              .find("2001:db8:ffff::/64") != std::string_view::npos,
      "classic IPv6 route-table command did not expose the selected RIB");
  const auto classic_static_arp = runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "configure router interface edge static-arp 192.0.2.2 "
                       "02:00:00:00:00:22"}));
  if (classic_static_arp.find("Error:") != std::string_view::npos)
    throw std::runtime_error("classic static ARP configuration failed: " +
                             std::string{classic_static_arp});
  const std::string static_arp_report{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router static-arp 192.0.2.2"}))};
  const auto arp_report = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router arp 192.0.2.0/30"}));
  const auto arp_mac_report = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router arp mac 02:00:00:00:00:02"}));
  require(
      static_arp_report.find("192.0.2.2") != std::string_view::npos &&
          static_arp_report.find("Sta") != std::string_view::npos &&
          arp_report.find("Expiry    Type   Interface") !=
              std::string_view::npos &&
          arp_mac_report.find("ARP Table (Router: Base)") !=
              std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "show router arp summary"}))
                  .find("Dynamic ARP Entries") != std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "clear router arp interface 192.0.2.1"}))
                  .find("Error:") == std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "clear router arp all"}))
                  .find("Error:") == std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "show router static-arp"}))
                  .find("192.0.2.2") != std::string_view::npos,
      "classic ARP filtering, report columns or owner clear failed");
  const std::array<std::string_view, 27> classic_ipv6_commands{
      "configure router interface edge ipv6 address 2001:db8:1::1/64",
      "configure router interface edge ipv6 address 2001:db8:3::1/64 "
      "dad-disable primary-preference 30 tag 900",
      "configure router interface edge ipv6 address 2001:db8:4::/64 eui-64 "
      "primary-preference 40 tag 901",
      // Classic accepts both Nokia-documented IEEE delimiters. The hyphen
      // form proves this is parsed as configuration data rather than copied
      // from a canned colon-form example.
      "configure router interface edge ipv6 neighbor 2001:db8:1::2 "
      "02-00-00-00-01-02",
      "configure router interface edge ipv6 nd-learn-unsolicited both",
      "configure router ipv6 reachable-time 45",
      "configure router ipv6 stale-time 18000",
      "configure router interface edge ipv6 reachable-time 60",
      "configure router interface edge ipv6 stale-time 3600",
      "configure router interface edge ipv6 nd-proactive-refresh global",
      "configure router interface edge ipv6 neighbor-limit 1024 log-only "
      "threshold 75",
      "configure router interface edge ipv6 icmp6 no redirects",
      "configure router interface edge ipv6 icmp6 redirects",
      "configure router interface edge ipv6 icmp6 redirects 1000 60",
      // These classic forms update the same IPv4 forwarding policy
      // immediately. They are deliberately mixed into the dual-stack set to
      // catch accidental engine or address-family separation.
      "configure router interface edge icmp no redirects",
      "configure router interface edge icmp redirects",
      "configure router interface edge icmp redirects 1000 60",
      "configure router router-advertisement interface edge reachable-time "
      "400",
      "configure router static-route-entry 2001:db8:aaaa::/64 next-hop "
      "2001:db8:1::2",
      "configure router no static-route-entry 2001:db8:aaaa::/64",
      "configure router no ecmp",
      "configure router ecmp 2",
      "configure router static-route-entry 203.0.114.0/24 next-hop "
      "192.0.2.2",
      "configure router static-route-entry 203.0.114.0/24 next-hop "
      "192.0.2.3",
      "configure router static-route-entry 198.51.101.0/24 indirect "
      "10.0.0.1",
      "configure router static-route-entry 203.0.114.0/24 no next-hop "
      "192.0.2.3",
      "configure router static-route-entry 198.51.101.0/24 no indirect "
      "10.0.0.1"};
  for (const auto command : classic_ipv6_commands) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos)
      throw std::runtime_error("valid classic IPv6 command failed: " +
                               std::string{command} + " output=" + result);
  }
  require(runtime.command(message(lab_runtime_protocol::snapshot))
                  .find("\"address\":\"2001:db8:4::/64\","
                        "\"duplicateAddressDetection\":true,"
                        "\"eui64\":true") != std::string_view::npos,
          "classic EUI-64 command did not publish its effective intent");
  // Classic no forms apply immediately. Removing the IPv4 address and then
  // the physical binding must leave the independently configured IPv6 address
  // list intact. Restoring each leaf returns the fixture to its original
  // forwarding topology for the remaining packet and checkpoint tests.
  for (const auto command :
       {"configure router interface edge arp-timeout 0",
        "configure router interface edge no arp-timeout",
        "configure router interface edge arp-timeout 120",
        "configure router interface edge arp-retry-timer 25",
        "configure router interface edge no arp-retry-timer",
        "configure router interface edge arp-retry-timer 25",
        "configure router interface edge no address",
        "configure router interface edge address 192.0.2.1/30",
        "configure router interface edge no port",
        "configure router interface edge port 1/1/1"}) {
    const auto result = runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}));
    if (result.find("Error:") != std::string_view::npos)
      throw std::runtime_error(
          "valid classic IPv4 leaf edit failed: " + std::string{command} +
          " output=" + std::string{result});
  }
  const std::string ipv4_interface_detail{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router interface edge detail"}))};
  require(ipv4_interface_detail.find("If Name          : edge") !=
                  std::string::npos &&
              ipv4_interface_detail.find("ARP Timeout      : 120s") !=
                  std::string::npos &&
              ipv4_interface_detail.find("ARP Retry Timer  : 2500ms") !=
                  std::string::npos,
          "interface detail did not expose live configured ARP timers");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "show router interface missing detail"}))
                  .find("MGMT_CORE #2301") != std::string_view::npos,
          "interface detail fabricated operational state for an absent name");

  // Validate the portable representation while `edge` still exists. A later
  // protocol-4 deletion deliberately removes this interface to exercise child
  // teardown, so inspecting only the final checkpoint would test an impossible
  // state and conceal whether the MD and classic address edits were preserved.
  const auto multi_address_checkpoint = runtime.export_checkpoint();
  const std::vector<std::uint8_t> owned_multi_address_checkpoint(
      multi_address_checkpoint.begin(), multi_address_checkpoint.end());
  const auto decoded_multi_address =
      checkpoint_v6::decode(owned_multi_address_checkpoint);
  const PortableInterfaceIntentCheckpoint *multi_address_interface{};
  if (decoded_multi_address) {
    const auto device =
        std::find_if(decoded_multi_address->devices.entries.begin(),
                     decoded_multi_address->devices.entries.end(),
                     [](const auto &entry) { return entry.node_id == "r1"; });
    const auto portable_router =
        device == decoded_multi_address->devices.entries.end()
            ? decoded_multi_address->portable_routers.end()
            : std::find_if(decoded_multi_address->portable_routers.begin(),
                           decoded_multi_address->portable_routers.end(),
                           [&](const auto &entry) {
                             return entry.device == device->handle;
                           });
    if (portable_router != decoded_multi_address->portable_routers.end()) {
      const auto interface =
          std::find_if(portable_router->interfaces.begin(),
                       portable_router->interfaces.end(),
                       [](const auto &entry) { return entry.name == "edge"; });
      if (interface != portable_router->interfaces.end())
        multi_address_interface = std::addressof(*interface);
    }
  }
  const auto contains_ipv6_address = [&](const char *text,
                                         std::uint32_t preference, bool dad,
                                         std::uint32_t tag) {
    return multi_address_interface &&
           std::any_of(multi_address_interface->ipv6_addresses.begin(),
                       multi_address_interface->ipv6_addresses.end(),
                       [&](const auto &entry) {
                         return entry.address == ipv6_address(text) &&
                                entry.primary_preference == preference &&
                                entry.duplicate_address_detection == dad &&
                                entry.tag_configured && entry.tag == tag;
                       });
  };
  if (!multi_address_interface ||
      multi_address_interface->arp_timeout_seconds != 120U ||
      multi_address_interface->arp_retry_deciseconds != 25U ||
      !multi_address_interface->arp_timeout_configured ||
      !multi_address_interface->arp_retry_configured ||
      (multi_address_interface->router_advertisement_leaf_presence &
       static_cast<std::uint16_t>(RouterAdvertisementLeaf::admin_state)) ==
          0U ||
      (multi_address_interface->router_advertisement_leaf_presence &
       static_cast<std::uint16_t>(RouterAdvertisementLeaf::reachable_time)) ==
          0U ||
      multi_address_interface->ipv6_addresses.size() != 5U ||
      !contains_ipv6_address("2001:db8:2::1", 50U, false, 700U) ||
      !contains_ipv6_address("2001:db8:3::1", 30U, false, 900U) ||
      std::none_of(multi_address_interface->ipv6_addresses.begin(),
                   multi_address_interface->ipv6_addresses.end(),
                   [&](const auto &entry) {
                     return entry.address == ipv6_address("2001:db8:4::") &&
                            entry.eui64 &&
                            std::any_of(entry.eui64_source_mac.begin(),
                                        entry.eui64_source_mac.end(),
                                        [](auto byte) { return byte != 0U; });
                   })) {
    // Include the complete decoded address set so a future failure identifies
    // whether the candidate workflow, immediate classic apply, or codec lost a
    // particular leaf. This remains diagnostic evidence, not product output.
    std::string detail = decoded_multi_address ? "decoded" : "decode-failed";
    detail +=
        multi_address_interface ? ",interface-found" : ",interface-missing";
    if (multi_address_interface) {
      detail += ",addresses=" +
                std::to_string(multi_address_interface->ipv6_addresses.size());
      for (const auto &entry : multi_address_interface->ipv6_addresses)
        detail +=
            " [" + ip::format_ipv6(entry.address) + "/" +
            std::to_string(entry.prefix_length) +
            ",preference=" + std::to_string(entry.primary_preference) +
            ",dad=" + (entry.duplicate_address_detection ? "true" : "false") +
            ",tag=" +
            (entry.tag_configured ? std::to_string(entry.tag)
                                  : std::string{"absent"}) +
            "]";
    }
    throw std::runtime_error(
        "multi-address MD/classic leaves were not preserved in checkpoint "
        "intent: " +
        detail);
  }
  // A regular IES relay is configured through classic terminal bytes so the
  // lease-state reports below resolve a real service ID and logical interface.
  // No client Reply has crossed the wire yet, therefore every selector must
  // report an empty forwarding-owned table rather than a canned example row.
  for (const auto command :
       {"configure port 1/1/2 ethernet mode access",
        "configure port 1/1/2 ethernet encap-type dot1q",
        "configure service customer 10 create",
        "configure service ies 100 customer 10 create",
        "configure service ies 100 interface subscriber create",
        "configure service ies 100 interface subscriber ipv6 address "
        "2001:db8:100::1/64",
        "configure service ies 100 interface subscriber sap 1/1/2:100 "
        "create",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "server 2001:db8:ffff::1",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "lease-populate route-populate pd exclude",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "neighbor-resolution",
        "configure service ies 100 interface subscriber ipv6 dhcp6-relay "
        "no shutdown",
        "configure service ies 100 interface subscriber no shutdown",
        "configure service ies 100 no shutdown"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos)
      throw std::runtime_error("valid classic IES DHCPv6 command failed: " +
                               std::string{command} + " output=" + result);
  }
  for (const auto command :
       {"show service id 100 dhcp6 lease-state",
        "show service id 100 dhcp6 lease-state detail",
        "show service id 100 dhcp6 lease-state interface subscriber",
        "show service id 100 dhcp6 lease-state 2001:db8:100::/64",
        "show service id 100 dhcp6 lease-state mac 02:00:00:00:aa:01"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    require(
        result.find("DHCP lease states for service 100") != std::string::npos &&
            result.find("Number of lease states : 0") != std::string::npos,
        "DHCPv6 lease-state selector did not read live empty service state");
  }
  for (const auto command :
       {"clear service id 100 dhcp6 lease-state all",
        "clear service id 100 dhcp6 lease-state all no-dhcp-release",
        "clear service id 100 dhcp6 lease-state 2001:db8:100::10/128",
        "clear service id 100 dhcp6 lease-state 2001:db8:100::10/128 "
        "no-dhcp-release",
        "clear service id 100 dhcp6 lease-state mac 02:00:00:00:aa:01",
        "clear service id 100 dhcp6 lease-state mac 02:00:00:00:aa:01 "
        "no-dhcp-release",
        "clear service id 100 dhcp6 lease-state sap 1/1/2:100",
        "clear service id 100 dhcp6 lease-state sap 1/1/2:100 "
        "no-dhcp-release"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos ||
        result.find("MINOR:") != std::string::npos)
      throw std::runtime_error(
          "valid DHCPv6 lease-state clear selector was rejected: " +
          std::string{command} + " output=" + result);
  }
  // SR OS configuration setters are idempotent. Repeating an already active
  // Neighbor Discovery value must return the normal prompt instead of turning
  // an unchanged datastore into a fabricated bad-command error.
  for (const auto command :
       {"configure router ipv6 reachable-time 45",
        "configure router interface edge ipv6 nd-proactive-refresh global",
        "configure router interface edge ipv6 neighbor-limit 1024 "
        "log-only threshold 75"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    require(result.find("Error:") == std::string::npos,
            "idempotent classic IPv6 configuration was rejected");
  }
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1",
                               "configure router interface edge ipv6 neighbor "
                               "2001:db8:1::3 02:00-00:00:01:03"}))
              .find("Error: Bad command.") != std::string_view::npos,
      "classic IPv6 neighbor accepted mixed MAC delimiters");
  // Operational output is derived from the forwarding-owned cache installed
  // by the configuration commands above. Check independent selectors so a
  // future canned table or UI-side copy cannot satisfy the test accidentally.
  const std::string static_neighbors{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router neighbor static"}))};
  const std::string interface_neighbors{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router neighbor edge static"}))};
  const std::string mac_neighbors{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "show router neighbor mac 02-00-00-00-01-02 static"}))};
  if (static_neighbors.find("Neighbor Table (Router: Base)") ==
          std::string::npos ||
      static_neighbors.find("2001:db8:1::2") == std::string::npos ||
      static_neighbors.find("02:00:00:00:01:02") == std::string::npos ||
      static_neighbors.find("REACHABLE") == std::string::npos ||
      static_neighbors.find("Static") == std::string::npos ||
      interface_neighbors.find("2001:db8:1::2") == std::string::npos ||
      mac_neighbors.find("2001:db8:1::2") == std::string::npos)
    throw std::runtime_error(
        "classic IPv6 neighbor report did not project cache-owned state: "
        "static=" +
        static_neighbors + "; interface=" + interface_neighbors +
        "; mac=" + mac_neighbors);
  // Summary values must come from the same filtered forwarding projection as
  // the detailed table. Verifying both the complete and type-filtered forms
  // catches canned totals and a parser that silently ignores `static`.
  const std::string neighbor_summary{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router neighbor summary"}))};
  const std::string static_neighbor_summary{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router neighbor summary static"}))};
  require(neighbor_summary.find("Neighbor Table Summary (Router: Base)") !=
                  std::string::npos &&
              neighbor_summary.find("Static Neighbor Entries  : 1") !=
                  std::string::npos &&
              neighbor_summary.find("No. of Neighbor Entries  : 1") !=
                  std::string::npos &&
              static_neighbor_summary.find("Dynamic Neighbor Entries : 0") !=
                  std::string::npos &&
              static_neighbor_summary.find("No. of Neighbor Entries  : 1") !=
                  std::string::npos,
          "IPv6 neighbor summary did not reflect filtered cache-owned state");
  // Clearing operational state is idempotent and must never erase a static
  // mapping. The second show reaches the cache again after the clear command,
  // proving persistence rather than inspecting the prior response string.
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "clear router neighbor 2001:db8:1::2"}))
                      .find("Error:") == std::string_view::npos &&
              runtime.command(message(lab_runtime_protocol::session_execute,
                                      {"r1-console-1",
                                       "show router neighbor static"}))
                      .find("2001:db8:1::2") != std::string_view::npos,
          "classic neighbor clear deleted static configuration");
  for (const auto command :
       {"configure router interface edge ipv6 icmp6 redirects 9 1",
        "configure router interface edge ipv6 icmp6 redirects 1001 1",
        "configure router interface edge ipv6 icmp6 redirects 10 0",
        "configure router interface edge ipv6 icmp6 redirects 10 61"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error: Bad command.") != std::string_view::npos,
            "classic ICMPv6 Redirect configuration widened the release range");
  for (const auto command :
       {"configure router interface edge icmp redirects 9 1",
        "configure router interface edge icmp redirects 1001 1",
        "configure router interface edge icmp redirects 10 0",
        "configure router interface edge icmp redirects 10 61"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error: Bad command.") != std::string_view::npos,
            "classic IPv4 Redirect configuration widened the release range");
  const std::string classic_router_advertisement{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router rtr-advertisement"}))};
  const std::string classic_router_advertisement_interface{
      runtime.command(message(
          lab_runtime_protocol::session_execute,
          {"r1-console-1", "show router rtr-advertisement interface edge"}))};
  const std::string classic_router_advertisement_prefix{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "show router rtr-advertisement prefix 2001:db8:1::/64"}))};
  require(classic_router_advertisement.find("Router Advertisement") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Interface: edge") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("2001:db8:1::53") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Rdnss-lifetime") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Max Advert Interval") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Managed Config") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Reachable Time") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Link MTU") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Prefix: 2001:db8:1::/64") !=
                  std::string_view::npos &&
              classic_router_advertisement.find("Autonomous Flag") !=
                  std::string_view::npos &&
              classic_router_advertisement_interface.find(
                  "Rtr Advertisement Tx") != std::string_view::npos &&
              classic_router_advertisement_interface.find("Last Sent") !=
                  std::string_view::npos &&
              classic_router_advertisement_prefix.find(
                  "Prefix: 2001:db8:1::/64") != std::string_view::npos,
          "classic RA report omitted documented forwarding or intent fields");
  // Classic `no` forms reset only the addressed leaf. A newly created prefix
  // also inherits the SR OS Base-router defaults for Autonomous and On-link,
  // rather than the zero values of the underlying wire structure.
  for (const auto command :
       {"configure router router-advertisement interface edge "
        "current-hop-limit 17",
        "configure router router-advertisement interface edge no "
        "current-hop-limit",
        "configure router router-advertisement interface edge prefix "
        "2001:db8:2::/64 preferred-lifetime 600"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic RA leaf edit or reset failed");
  const auto defaulted_ra_prefix = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1",
               "show router rtr-advertisement prefix 2001:db8:2::/64"}));
  require(defaulted_ra_prefix.find("Autonomous Flag") !=
                  std::string_view::npos &&
              defaulted_ra_prefix.find("TRUE") != std::string_view::npos &&
              defaulted_ra_prefix.find("Hop Limit") != std::string_view::npos &&
              defaulted_ra_prefix.find(": 64") != std::string_view::npos,
          "classic RA defaults did not survive a set followed by no");
  for (const auto command :
       {"configure router router-advertisement interface edge prefix "
        "2001:db8:2::/64 no preferred-lifetime",
        "configure router router-advertisement interface edge no prefix "
        "2001:db8:2::/64",
        "configure router router-advertisement interface edge dns-options "
        "no server"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic RA list or RDNSS removal failed");
  const auto removed_ra_values = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router rtr-advertisement"}));
  require(
      removed_ra_values.find("2001:db8:2::/64") == std::string_view::npos &&
          removed_ra_values.find("2001:db8:1::53") == std::string_view::npos &&
          removed_ra_values.find("2001:db8:1::54") != std::string_view::npos,
      "classic RA removal did not activate router-level DNS inheritance");
  require(runtime
                  .command(message(
                      lab_runtime_protocol::session_execute,
                      {"r1-console-1",
                       "configure router router-advertisement interface edge "
                       "dns-options no include-dns"}))
                  .find("Error:") == std::string_view::npos,
          "classic include-dns disable failed");
  const auto excluded_ra_dns = runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "show router rtr-advertisement interface edge"}));
  require(
      excluded_ra_dns.find("2001:db8:1::54") == std::string_view::npos &&
          excluded_ra_dns.find("Include-dns") != std::string_view::npos &&
          excluded_ra_dns.find("no") != std::string_view::npos,
      "include-dns false did not suppress inherited RDNSS on the wire view");
  require(
      runtime
                  .command(message(
                      lab_runtime_protocol::session_execute,
                      {"r1-console-1",
                       "configure router router-advertisement interface edge "
                       "dns-options include-dns"}))
                  .find("Error:") == std::string_view::npos &&
          runtime.command(
                     message(lab_runtime_protocol::session_execute,
                             {"r1-console-1",
                              "show router rtr-advertisement interface edge"}))
                  .find("2001:db8:1::54") != std::string_view::npos,
      "include-dns restore did not republish inherited RDNSS state");
  for (const auto command : {"clear router router-advertisement interface edge",
                             "clear router router-advertisement all"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic RA counter clear did not reach forwarding ownership");

  // IPv4 ICMP uses the same operational owner as the packet path. Exercise
  // both terminal engines here so schema exposure, named-interface resolution,
  // forwarding-shard commands and the release-specific table all remain one
  // tested contract rather than independent parser fixtures.
  const std::string classic_icmpv4_global{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router icmp"}))};
  const std::string classic_icmpv4_interface{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router icmp interface edge"}))};
  if (classic_icmpv4_global.find("Global ICMP Stats") ==
          std::string_view::npos ||
      classic_icmpv4_global.find("Destination Unreachable") ==
          std::string_view::npos ||
      classic_icmpv4_global.find("Address Mask") == std::string_view::npos ||
      classic_icmpv4_interface.find("Interface \"edge\"") ==
          std::string_view::npos)
    throw std::runtime_error(
        "classic ICMP operational display diverged from the release layout: "
        "global=" +
        classic_icmpv4_global + " interface=" + classic_icmpv4_interface);
  for (const auto command :
       {"clear router icmp global", "clear router icmp interface edge",
        "clear router icmp all"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic ICMP clear did not reach forwarding ownership");

  const std::string classic_icmpv6_global{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router icmp6"}))};
  const std::string classic_icmpv6_interface{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router icmp6 interface edge"}))};
  require(
      classic_icmpv6_global.find("Global ICMPv6 Stats") !=
              std::string_view::npos &&
          classic_icmpv6_global.find("Parameter Problem") !=
              std::string_view::npos &&
          classic_icmpv6_global.find("Discarded") != std::string_view::npos &&
          classic_icmpv6_interface.find("Interface \"edge\"") !=
              std::string_view::npos,
      "classic ICMPv6 operational display diverged from the release layout");
  for (const auto command :
       {"clear router icmp6 global", "clear router icmp6 interface edge",
        "clear router icmp6 all"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic ICMPv6 clear did not reach forwarding ownership");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:admin@private-first#") != std::string_view::npos,
          "ICMPv6 reset fixture could not enter MD-CLI");
  for (const auto command :
       {"reset router \"Base\" neighbor address ipv6-address "
        "2001:db8:1::2",
        "reset router \"Base\" neighbor interface interface-name edge",
        "reset router \"Base\" neighbor all",
        "reset router \"Base\" icmp global",
        "reset router \"Base\" icmp interface interface-name edge",
        "reset router \"Base\" icmp all", "reset router \"Base\" icmp6 global",
        "reset router \"Base\" icmp6 interface interface-name edge",
        "reset router \"Base\" icmp6 all"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") == std::string_view::npos,
            "MD-CLI ICMP reset did not reach forwarding ownership");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:private-first#") != std::string_view::npos,
          "ICMPv6 reset fixture did not return to classic CLI");
  // MLD configuration is exercised through classic syntax before MD output
  // and clear commands. Every command reaches the same router protocol owner;
  // this is not a transcript-only parser test.
  const std::array<std::string_view, 9> classic_mld_commands{
      "configure router mld no shutdown",
      "configure router mld query-interval 126",
      "configure router mld interface edge no shutdown",
      "configure router mld interface edge version 2",
      "configure router mld interface edge robust-count 3",
      "configure router mld interface edge max-groups 16000",
      "configure router mld interface edge max-grp-sources 32000",
      "configure router mld interface edge max-sources 1000",
      "configure router mld interface edge disable-router-alert-check"};
  for (const auto command : classic_mld_commands) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos)
      throw std::runtime_error("valid classic MLD command failed: " +
                               std::string{command} + " output=" + result);
  }
  // Classic policy-options is a separate edit transaction on a classic
  // terminal. Verify the real begin and commit boundary before attaching the
  // resulting policy to MLD. Each route-policy leaf is then consumed by the
  // compiler and forwarding owner, rather than existing as parser-only state.
  for (const auto command :
       {"configure router policy-options begin",
        "configure router policy-options prefix-list MLD-GROUPS prefix "
        "192.0.2.0/24",
        "configure router policy-options prefix-list MLD-GROUPS prefix "
        "ff3e:500::/40",
        "configure router policy-options prefix-list MLD-SOURCES prefix "
        "2001:db8:1::/64",
        "configure router policy-options policy-statement MLD-IN entry 10 "
        "from group-address MLD-GROUPS",
        "configure router policy-options policy-statement MLD-IN entry 10 "
        "from source-address prefix-list MLD-SOURCES",
        "configure router policy-options policy-statement MLD-IN entry 10 "
        "from protocol mld",
        "configure router policy-options policy-statement MLD-IN entry 10 "
        "action drop",
        "configure router policy-options policy-statement MLD-IN "
        "default-action accept",
        "configure router policy-options commit",
        "configure router mld interface edge import MLD-IN"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string_view::npos ||
        result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error("valid classic MLD policy command failed: " +
                               std::string{command} + " output=" + result);
  }
  const std::string policy_detail{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router mld interface edge detail"}))};
  require(policy_detail.find("Import Policy               : MLD-IN") !=
              std::string_view::npos,
          "classic MLD import attachment was absent from operational state");
  // An aborted edit must not delete the committed policy. Re-attaching after
  // removing only the interface leaf proves that the named policy remained in
  // running state and did not leak the private delete operation.
  for (const auto command :
       {"configure router policy-options begin",
        "configure router policy-options no policy-statement MLD-IN",
        "configure router policy-options abort",
        "configure router mld interface edge no import",
        "configure router mld interface edge import MLD-IN"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    require(result.find("MINOR:") == std::string_view::npos &&
                result.find("Error:") == std::string_view::npos,
            "classic policy abort leaked state or lost the running policy");
  }
  // Static listener state is configuration, not a learned database entry.
  // Exercise both source-specific and wildcard forms through the actual
  // classic engine so the test detects parser, candidate and forwarding-owner
  // regressions together. The two forms are intentionally placed on different
  // groups because SR OS makes `source` and `starg` mutually exclusive inside
  // one static group context.
  for (const auto command :
       {"configure router mld interface edge static group ff3e::100",
        "configure router mld interface edge static group ff3e::100 "
        "source 2001:db8:1::100",
        "configure router mld interface edge static group ff3e::200",
        "configure router mld interface edge static group ff3e::200 starg",
        "configure router mld interface edge static group start ff3e::210 "
        "end ff3e::212 source 2001:db8:1::210",
        "configure router mld interface edge static group start ff3e::220 "
        "end ff3e::224 step ::2 starg"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos)
      throw std::runtime_error("valid classic static MLD command failed: " +
                               std::string{command} + " output=" + result);
  }
  // Nokia permits one protocol-level SSM map and an interface-local override.
  // Exercise both through classic CLI and inspect the exact configuration
  // projection before any packet-level test relies on the resolved program.
  for (const auto command :
       {"configure router mld ssm-translate grp-range ff3e::300 "
        "ff3e::30f source 2001:db8:1::300",
        "configure router mld interface edge ssm-translate grp-range "
        "ff3e::300 ff3e::30f source 2001:db8:1::301"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("Error:") != std::string::npos)
      throw std::runtime_error("valid classic SSM translation failed: " +
                               std::string{command} + " output=" + result);
  }
  const std::string classic_ssm_show{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router mld ssm-translate"}))};
  require(classic_ssm_show.find("MLD SSM Translate Entries") !=
                  std::string::npos &&
              classic_ssm_show.find("2001:db8:1::300") != std::string::npos &&
              classic_ssm_show.find("2001:db8:1::301") != std::string::npos &&
              classic_ssm_show.find("Interface   : edge") != std::string::npos,
          "classic SSM show omitted global or interface translation");
  require(
      runtime
              .command(message(
                  lab_runtime_protocol::session_execute,
                  {"r1-console-1",
                   "configure router mld interface edge static group ff3e::100 "
                   "starg"}))
              .find("Error:") != std::string_view::npos,
      "classic MLD accepted mutually exclusive source and starg state");
  const auto static_mld_show =
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router mld static edge"}));
  if (static_mld_show.find("ff3e::100") == std::string_view::npos ||
      static_mld_show.find("2001:db8:1::100") == std::string_view::npos ||
      static_mld_show.find("ff3e::200") == std::string_view::npos ||
      static_mld_show.find("ff3e::212") == std::string_view::npos ||
      static_mld_show.find("ff3e::224") == std::string_view::npos ||
      static_mld_show.find("*                                         edge") ==
          std::string_view::npos)
    throw std::runtime_error(
        std::string{"static MLD operational output omitted configured "
                    "memberships: "} +
        std::string{static_mld_show});
  const auto mld_show = runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router mld interface edge detail"}));
  require(mld_show.find("MLD Interfaces") != std::string_view::npos &&
              mld_show.find("edge") != std::string_view::npos &&
              mld_show.find("Robust Count                : 3") !=
                  std::string_view::npos &&
              mld_show.find("Router Alert Check          : Disabled") !=
                  std::string_view::npos &&
              mld_show.find("Max Groups Allowed          : 16000") !=
                  std::string_view::npos,
          "MLD operational output did not reflect live interface intent");
  const std::string mld_status{
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router mld status"}))};
  const std::string mld_statistics{runtime.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-1", "show router mld statistics edge"}))};
  require(mld_status.find("MLD Status") != std::string_view::npos &&
              mld_status.find("Admin State                       : Up") !=
                  std::string_view::npos &&
              mld_status.find("Query Interval                    : 126") !=
                  std::string_view::npos &&
              mld_statistics.find("MLD Interface Statistics") !=
                  std::string_view::npos &&
              mld_statistics.find("No Router Alert   : ") !=
                  std::string_view::npos &&
              mld_statistics.find("Source Group Statistics") !=
                  std::string_view::npos,
          "MLD status or statistics output diverged from the 26.7 layout");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "configure router mld query-interval 1"}))
                  .find("Error: Bad command.") != std::string_view::npos,
          "classic MLD accepted an out-of-profile query interval");
  for (const auto command :
       {"configure router mld interface edge max-groups 16001",
        "configure router mld interface edge max-grp-sources 32001",
        "configure router mld interface edge max-sources 1001"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error: Bad command.") != std::string_view::npos,
            "classic MLD admitted a value beyond its official range");
  // The no forms must remove actual configured leaves, not merely parse. A
  // second no therefore fails, after which the value is restored for the
  // checkpoint and forwarding projection tests below.
  for (const auto command :
       {"configure router mld interface edge no max-groups",
        "configure router mld interface edge no max-grp-sources",
        "configure router mld interface edge no max-sources"}) {
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic MLD no form did not remove a configured limit");
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") != std::string_view::npos,
            "classic MLD no form accepted a successful no-op");
  }
  const auto classic_no_router_alert =
      "configure router mld interface edge no disable-router-alert-check";
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", classic_no_router_alert}))
                  .find("Error:") == std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", classic_no_router_alert}))
                  .find("Error:") != std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "configure router mld interface edge "
                                   "disable-router-alert-check"}))
                  .find("Error:") == std::string_view::npos,
      "classic Router Alert no form lost leaf presence semantics");
  for (const auto command :
       {"configure router mld interface edge max-groups 16000",
        "configure router mld interface edge max-grp-sources 32000",
        "configure router mld interface edge max-sources 1000"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic MLD limit could not be restored after no form");
  for (const auto command :
       {"clear router mld database interface edge",
        "clear router mld version edge", "clear router mld statistics edge",
        "clear router mld statistics", "clear router mld database"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("MINOR:") == std::string_view::npos,
            "MLD clear command did not reach forwarding-owned state");
  // RFC 3810 clear operations remove learned host state. They must not erase
  // operator-owned static membership, which belongs to configuration and is
  // removed only by an explicit configuration command.
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", "show router mld static edge"}))
              .find("ff3e::100") != std::string_view::npos,
      "clearing the dynamic MLD database erased static configuration");
  for (const auto command :
       {"configure router mld interface edge static group ff3e::100 no "
        "source 2001:db8:1::100",
        "configure router mld interface edge static no group ff3e::100",
        "configure router mld interface edge static group ff3e::200 no "
        "starg",
        "configure router mld interface edge static no group ff3e::200",
        "configure router mld interface edge static no group start ff3e::210 "
        "end ff3e::212",
        "configure router mld interface edge static no group start ff3e::220 "
        "end ff3e::224 step ::2"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic static MLD removal did not update live configuration");
  for (const auto command :
       {"configure router mld interface edge ssm-translate grp-range "
        "ff3e::300 ff3e::30f no source 2001:db8:1::301",
        "configure router mld ssm-translate no grp-range ff3e::300 "
        "ff3e::30f"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", command}))
                    .find("Error:") == std::string_view::npos,
            "classic SSM no form did not remove committed configuration");
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "//"}))
                  .find("A:admin@private-first#") != std::string_view::npos,
          "classic IPv6 fixture could not return to MD-CLI");

  std::string ping_output{runtime.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-1", "ping 192.0.2.2 count 1 size 100 do-not-fragment"}))};
  for (std::size_t attempt = 0;
       attempt < 200U && ping_output.find("pending") != std::string::npos;
       ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    ping_output += runtime.command(
        message(lab_runtime_protocol::session_poll, {"r1-console-1"}));
  }
  require(ping_output.find("108 bytes from 192.0.2.2") !=
                  std::string_view::npos &&
              ping_output.find("1 packets transmitted, 1 packets received") !=
                  std::string_view::npos,
          "asynchronous CLI ping did not return through the packet path");
  static_cast<void>(
      runtime.command(message(lab_runtime_protocol::session_execute,
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
              runtime
                  .command(message(lab_runtime_protocol::interface_delete,
                                   {"r1", "edge"}))
                  .starts_with("ERROR:"),
          "protocol 4 interface removal accepted a successful no-op");

  require(
      !runtime.command(message(lab_runtime_protocol::interface_configure,
                               {"r1", "checkpoint-edge", "1/1/1",
                                "192.0.2.1/30", "", "", "1"}))
              .starts_with("ERROR:") &&
          !runtime
               .command(message(lab_runtime_protocol::capture_point_set,
                                {"router-ingress", "r1", "1/1/1", "0", "1"}))
               .starts_with("ERROR:"),
      "portable checkpoint fixture could not be configured");
  const std::string capture_before{
      runtime.command(message(lab_runtime_protocol::snapshot))};
  require(capture_before.find("\"kind\":\"router-ingress\"") !=
              std::string_view::npos,
          "snapshot ABI 6 omitted an active capture selection");
  const auto invalid_capture_replacement =
      nested({"1", "link-direction", "missing-link", "", "0", "1"});
  const auto capture_before_projection = capture_projection(capture_before);
  // command() returns a view into the facade response buffer. Preserve the
  // rejection before requesting another snapshot, otherwise the next command
  // legitimately reuses that buffer and the assertion reads unrelated bytes.
  const std::string rejected_capture{
      runtime.command(message(lab_runtime_protocol::capture_selection_replace,
                              {invalid_capture_replacement}))};
  const auto capture_after_rejection =
      runtime.command(message(lab_runtime_protocol::snapshot));
  // Snapshot counters and link deadlines continue changing on their owners
  // while this command runs. Transactionality concerns the capture selection,
  // so compare that projection instead of incorrectly requiring the entire
  // live snapshot to freeze byte-for-byte.
  const auto capture_after_projection =
      capture_projection(capture_after_rejection);
  if (!rejected_capture.starts_with("ERROR:") ||
      capture_before_projection.empty() ||
      capture_after_projection != capture_before_projection)
    throw std::runtime_error(
        "rejected capture replacement changed the active selection: before=" +
        std::string{capture_before_projection} +
        " after=" + std::string{capture_after_projection} +
        " response=" + std::string{rejected_capture});
  const auto capture_replacement =
      nested({"2", "router-ingress", "r1", "1/1/1", "0", "1", "link-direction",
              "edge-link", "", "0", "1"});
  const auto replaced_capture = runtime.command(message(
      lab_runtime_protocol::capture_selection_replace, {capture_replacement}));
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
  // Build a source-specific static listener through MD-CLI and commit it before
  // taking the checkpoint. This verifies that the running intent, forwarding
  // owner and portable checkpoint all describe the same membership. A later
  // uncommitted system-name edit remains in the candidate and independently
  // verifies session restoration.
  for (const auto command :
       {"router \"Base\" interface checkpoint-edge ipv6 address "
        "2001:db8:ffff::1 prefix-length 64",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery static-neighbor 2001:db8:ffff::2 "
        "mac-address 02:00:00:00:ff:02",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery learn-unsolicited link-local",
        "router \"Base\" ipv6 neighbor-discovery reachable-time 75",
        "router \"Base\" ipv6 neighbor-discovery stale-time 19000",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery reachable-time 90",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery stale-time 7200",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery proactive-refresh both",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery limit max-entries 4096",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery limit log-only true",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery limit threshold 80",
        "router \"Base\" interface checkpoint-edge ipv6 icmp6 redirects "
        "admin-state disable",
        "router \"Base\" interface checkpoint-edge ipv6 icmp6 redirects "
        "number 777",
        "router \"Base\" interface checkpoint-edge ipv6 icmp6 redirects "
        "seconds 23",
        "router \"Base\" mld admin-state enable",
        "router \"Base\" mld interface checkpoint-edge "
        "admin-state enable",
        "router \"Base\" mld interface checkpoint-edge "
        "maximum-number-groups 16000",
        "router \"Base\" mld interface checkpoint-edge "
        "maximum-number-group-sources 32000",
        "router \"Base\" mld interface checkpoint-edge "
        "maximum-number-sources 1000",
        "router \"Base\" mld interface checkpoint-edge "
        "router-alert-check false",
        "router \"Base\" mld ssm-translate group-range start "
        "ff3e::400 end ff3e::40f source 2001:db8:ffff::400",
        "router \"Base\" mld interface checkpoint-edge ssm-translate "
        "group-range start ff3e::400 end ff3e::40f source "
        "2001:db8:ffff::401",
        "router \"Base\" mld interface checkpoint-edge static "
        "group ff3e::beef",
        "router \"Base\" mld interface checkpoint-edge static "
        "group ff3e::beef source 2001:db8:ffff::2",
        "router \"Base\" mld interface checkpoint-edge static "
        "group-range start ff3e::c000 end ff3e::c004 step ::2 "
        "source 2001:db8:ffff::3"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error("MD static MLD checkpoint fixture rejected: " +
                               std::string{command} + " output=" + result);
  }
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1",
                               "router \"Base\" mld interface checkpoint-edge "
                               "maximum-number-groups 16001"}))
              .find("MINOR:") != std::string_view::npos,
      "MD MLD admitted a group limit beyond the YANG range");
  for (const auto invalid :
       {"router \"Base\" ipv6 neighbor-discovery reachable-time 29",
        "router \"Base\" ipv6 neighbor-discovery stale-time 59",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery limit max-entries 102401",
        "router \"Base\" interface checkpoint-edge ipv6 "
        "neighbor-discovery limit threshold 0"})
    require(runtime.command(message(lab_runtime_protocol::session_execute,
                                    {"r1-console-1", invalid}))
                    .find("MINOR:") != std::string_view::npos,
            "MD Neighbor Discovery admitted a value outside 26.7 YANG");
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1",
                               "router \"Base\" interface checkpoint-edge ipv6 "
                               "neighbor-discovery proactive-refresh both"}))
              .find("MINOR:") == std::string_view::npos,
      "idempotent MD Neighbor Discovery setter was rejected");
  const auto delete_md_limit =
      "delete router \"Base\" mld interface checkpoint-edge "
      "maximum-number-sources";
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", delete_md_limit}))
                  .find("MINOR:") == std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", delete_md_limit}))
                  .find("MINOR:") != std::string_view::npos &&
          runtime.command(
                     message(lab_runtime_protocol::session_execute,
                             {"r1-console-1",
                              "router \"Base\" mld interface checkpoint-edge "
                              "maximum-number-sources 1000"}))
                  .find("MINOR:") == std::string_view::npos,
      "MD MLD delete lost leaf presence or could not restore the value");
  const auto delete_md_router_alert =
      "delete router \"Base\" mld interface checkpoint-edge "
      "router-alert-check";
  require(
      runtime.command(message(lab_runtime_protocol::session_execute,
                              {"r1-console-1", delete_md_router_alert}))
                  .find("MINOR:") == std::string_view::npos &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", delete_md_router_alert}))
                  .find("MINOR:") != std::string_view::npos &&
          runtime.command(
                     message(lab_runtime_protocol::session_execute,
                             {"r1-console-1",
                              "router \"Base\" mld interface checkpoint-edge "
                              "router-alert-check false"}))
                  .find("MINOR:") == std::string_view::npos,
      "MD Router Alert delete lost explicit boolean leaf presence");
  const std::string base_checkpoint_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}))};
  if (base_checkpoint_commit.find("MINOR:") != std::string_view::npos)
    throw std::runtime_error(
        "MD static MLD checkpoint fixture could not be committed: " +
        base_checkpoint_commit);
  // Start a fresh candidate generation for the policy graph. The preceding
  // fixture intentionally touches a large cross-section of IPv6 leaves, while
  // this generation verifies policy checkpointing without conflating the
  // generated candidate-key resource test with policy semantics.
  for (const auto command :
       {"policy-options prefix-list CHECKPOINT-MLD-GROUPS prefix "
        "ff3e:d000::/52",
        "policy-options prefix-list CHECKPOINT-MLD-GROUPS prefix "
        "198.51.100.0/24",
        "policy-options prefix-list CHECKPOINT-MLD-SOURCES prefix "
        "2001:db8:ffff::/64",
        "policy-options policy-statement CHECKPOINT-MLD-IN entry 10 from "
        "group-address CHECKPOINT-MLD-GROUPS",
        "policy-options policy-statement CHECKPOINT-MLD-IN entry 10 from "
        "source-address prefix-list CHECKPOINT-MLD-SOURCES",
        "policy-options policy-statement CHECKPOINT-MLD-IN entry 10 from "
        "protocol name mld",
        "policy-options policy-statement CHECKPOINT-MLD-IN entry 10 action "
        "action-type drop",
        "policy-options policy-statement CHECKPOINT-MLD-IN default-action "
        "action-type accept",
        "router \"Base\" mld interface checkpoint-edge import-policy "
        "CHECKPOINT-MLD-IN"}) {
    const std::string result{runtime.command(message(
        lab_runtime_protocol::session_execute, {"r1-console-1", command}))};
    if (result.find("MINOR:") != std::string_view::npos)
      throw std::runtime_error("MD MLD policy checkpoint fixture rejected: " +
                               std::string{command} + " output=" + result);
  }
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1", "compare"}))
                  .find("~ policy-options") != std::string_view::npos,
          "MD compare omitted the uncommitted MLD policy object graph");
  const auto precommit_checkpoint = runtime.export_checkpoint();
  const std::vector<std::uint8_t> precommit_owned(precommit_checkpoint.begin(),
                                                  precommit_checkpoint.end());
  const auto precommit_state = checkpoint_v6::decode(precommit_owned);
  if (!precommit_state || precommit_state->portable_routers.size() != 1U ||
      !precommit_state->portable_routers.front().global_candidate_initialized)
    throw std::runtime_error(
        "checkpoint fixture could not inspect its exclusive candidate: " +
        std::to_string(precommit_owned.size()) +
        " bytes, decoded=" + (precommit_state ? "yes, " : "no, ") +
        std::to_string(
            precommit_state ? precommit_state->portable_routers.size() : 0U) +
        " portable routers, candidate=" +
        (precommit_state && !precommit_state->portable_routers.empty() &&
                 precommit_state->portable_routers.front()
                     .global_candidate_initialized
             ? "initialized"
             : "absent"));
  const auto &precommit_candidate =
      precommit_state->portable_routers.front().global_candidate;
  const auto checkpoint_policy = std::find_if(
      precommit_candidate.mld_import_policies.begin(),
      precommit_candidate.mld_import_policies.end(),
      [](const auto &policy) { return policy.name == "CHECKPOINT-MLD-IN"; });
  const auto checkpoint_prefix_list = std::find_if(
      precommit_candidate.mld_prefix_lists.begin(),
      precommit_candidate.mld_prefix_lists.end(),
      [](const auto &list) { return list.name == "CHECKPOINT-MLD-GROUPS"; });
  const auto checkpoint_interface = std::find_if(
      precommit_candidate.interfaces.begin(),
      precommit_candidate.interfaces.end(), [](const auto &interface) {
        return interface.name == "checkpoint-edge";
      });
  require(
      checkpoint_prefix_list != precommit_candidate.mld_prefix_lists.end() &&
          checkpoint_prefix_list->prefixes.size() == 2U &&
          checkpoint_prefix_list->prefixes.front().network.family ==
              ip::AddressFamily::ipv4 &&
          checkpoint_policy != precommit_candidate.mld_import_policies.end() &&
          checkpoint_policy->entries.size() == 1U &&
          checkpoint_policy->entries.front().action ==
              mld::ImportPolicyAction::drop &&
          checkpoint_interface != precommit_candidate.interfaces.end() &&
          checkpoint_interface->mld_import_policy == "CHECKPOINT-MLD-IN",
      "MD candidate checkpoint lost policy leaves before commit");
  const std::string checkpoint_commit{runtime.command(message(
      lab_runtime_protocol::session_execute, {"r1-console-1", "commit"}))};
  if (checkpoint_commit.find("MINOR:") != std::string_view::npos)
    throw std::runtime_error(
        "MD MLD policy checkpoint fixture could not be committed: " +
        checkpoint_commit);
  require(runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-1",
                                   "system name checkpoint-candidate"}))
                  .find("*[ex:/configure]") != std::string_view::npos,
          "checkpoint fixture could not create a dirty value candidate");
  require(
      !runtime.command(message(lab_runtime_protocol::session_create,
                               {"r1-console-4", "r1", "operational"}))
              .starts_with("ERROR:") &&
          runtime.command(message(lab_runtime_protocol::session_execute,
                                  {"r1-console-4", "ping 192.0.2.2 count 1"}))
                  .find("pending") != std::string_view::npos,
      "checkpoint fixture could not start an asynchronous operation");

  const auto checkpoint = runtime.export_checkpoint();
  require(!checkpoint.empty(), "protocol 4 checkpoint export failed");
  const std::vector<std::uint8_t> owned(checkpoint.begin(), checkpoint.end());
  const auto decoded_addresses = checkpoint_v6::decode(owned);
  const auto contains_plaintext = [&owned](std::string_view secret) {
    // This searches the complete portable checkpoint, not only the vault
    // record. A failure therefore also detects accidental plaintext copies in
    // CLI candidates, session history or another checkpoint subsystem.
    return std::search(owned.begin(), owned.end(), secret.begin(),
                       secret.end()) != owned.end();
  };
  require(!contains_plaintext("primary-ppk") &&
              !contains_plaintext("primary-ike-psk") &&
              !contains_plaintext("protected-manual-key") &&
              !contains_plaintext("12345678901234567890"),
          "checkpoint serialized an IPsec credential in plaintext");

  {
    LabRuntime wrong_key_runtime;
    auto wrong_key = project_key;
    wrong_key.front() ^= 0xffU;
    require(
        wrong_key_runtime.initialize_secret_vault(wrong_key, project_context),
        "negative checkpoint fixture rejected a valid alternate key");
    require(!wrong_key_runtime.import_checkpoint(owned),
            "checkpoint vault accepted ciphertext under the wrong project key");
    require(wrong_key_runtime.command(message(lab_runtime_protocol::snapshot))
                    .find("\"routers\":[]") != std::string_view::npos,
            "failed vault authentication partially replaced runtime state");
  }

  {
    // Flip a ciphertext byte through the public checkpoint codec so the test
    // does not depend on a private byte offset. The import must authenticate
    // the complete vault before restoring any router or terminal owner.
    auto tampered_state = checkpoint_v6::decode(owned);
    require(tampered_state && !tampered_state->secret_vault.records.empty() &&
                !tampered_state->secret_vault.records.front().sealed.empty(),
            "checkpoint fixture did not retain configured IPsec credentials");
    tampered_state->secret_vault.records.front().sealed.back() ^= 0x01U;
    const auto tampered = checkpoint_v6::encode(*tampered_state);
    LabRuntime tampered_runtime;
    require(
        tampered_runtime.initialize_secret_vault(project_key, project_context),
        "tamper fixture rejected valid project vault material");
    require(!tampered_runtime.import_checkpoint(tampered),
            "checkpoint vault accepted modified authenticated ciphertext");
    require(tampered_runtime.command(message(lab_runtime_protocol::snapshot))
                    .find("\"routers\":[]") != std::string_view::npos,
            "tampered checkpoint partially replaced runtime state");
  }

  LabRuntime restored;
  require(restored.initialize_secret_vault(project_key, project_context),
          "restored runtime rejected the matching project vault material");
  require(restored.import_checkpoint(owned),
          "protocol 4 checkpoint import rejected a valid value graph");
  // Snapshot is backed by LabRuntime's reusable response buffer just like
  // terminal output. Own it before issuing any session command, otherwise a
  // later response aliases and overwrites the JSON under test.
  const std::string restored_snapshot{
      restored.command(message(lab_runtime_protocol::snapshot))};
  // The saved r1-console-4 session still owns an asynchronous ping. Inspect
  // restored operational MLD state from the idle second session so session
  // busy semantics cannot hide a checkpoint defect behind a valid rejection.
  // Reusing it also respects the generated four-session router limit.
  // LabRuntime returns a view into its reusable response buffer. Own each
  // response before issuing the next command so this test observes the two
  // distinct terminal writes instead of two aliases to the latest buffer.
  const std::string restored_static_mld{restored.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-2", "show router mld static checkpoint-edge"}))};
  const std::string restored_static_neighbor{restored.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-2", "show router neighbor checkpoint-edge static"}))};
  const std::string restored_mld_detail{restored.command(message(
      lab_runtime_protocol::session_execute,
      {"r1-console-2", "show router mld interface checkpoint-edge detail"}))};
  const std::string restored_ssm{restored.command(
      message(lab_runtime_protocol::session_execute,
              {"r1-console-2", "show router mld ssm-translate"}))};
  const bool portable_state_restored =
      restored_snapshot.find("\"id\":\"r1\"") != std::string_view::npos &&
      restored_snapshot.find("\"description\":\"edge port\"") !=
          std::string_view::npos &&
      restored_snapshot.find("\"name\":\"checkpoint-edge\"") !=
          std::string_view::npos &&
      restored_snapshot.find("\"ipv6InterfaceIdentifierMode\":"
                             "\"stable-opaque\"") != std::string_view::npos &&
      restored.command(message(lab_runtime_protocol::session_state,
                               {"r1-console-1"}))
              .find("*[ex:/configure]") != std::string_view::npos &&
      restored.command(message(lab_runtime_protocol::session_execute,
                               {"r1-console-1", "compare"}))
              .find("checkpoint-candidate") != std::string_view::npos &&
      restored_static_mld.find("2001:db8:ffff::2") != std::string_view::npos &&
      restored_static_mld.find("2001:db8:ffff::3") != std::string_view::npos &&
      restored_static_mld.find("ff3e::c004") != std::string_view::npos &&
      restored_static_neighbor.find("2001:db8:ffff::2") !=
          std::string_view::npos &&
      restored_static_neighbor.find("02:00:00:00:ff:02") !=
          std::string_view::npos &&
      restored_mld_detail.find("Max Groups Allowed          : 16000") !=
          std::string_view::npos &&
      restored_mld_detail.find("Router Alert Check          : Disabled") !=
          std::string_view::npos &&
      restored_mld_detail.find(
          "Import Policy               : CHECKPOINT-MLD-IN") !=
          std::string_view::npos &&
      restored_ssm.find("2001:db8:ffff::400") != std::string::npos &&
      restored_ssm.find("2001:db8:ffff::401") != std::string::npos &&
      restored_snapshot.find("\"kind\":\"link-direction\"") !=
          std::string_view::npos;
  // Include the two human-readable operational projections in a failure.
  // Checkpoint regressions otherwise collapse into one opaque conjunction and
  // force a debugger merely to identify whether intent, terminal workflow or
  // forwarding-owner reconstruction diverged.
  if (!portable_state_restored)
    throw std::runtime_error(
        std::string{
            "bare checkpoint lost portable router or terminal configuration; "
            "static="} +
        std::string{restored_static_mld} +
        "; detail=" + std::string{restored_static_neighbor} +
        "; neighbor=" + std::string{restored_mld_detail} +
        "; ssm=" + std::string{restored_ssm} +
        "; snapshot=" + std::string{restored_snapshot});
  // The restored exclusive candidate and the restored running intent are two
  // separate portable graphs. Delete the explicit defaulted leaves once from
  // each graph. A successful second delete would prove that checkpoint import
  // collapsed presence into an effective scalar or accepted a no-op.
  const auto delete_redirect_number =
      "delete router \"Base\" interface checkpoint-edge ipv6 icmp6 "
      "redirects number";
  require(
      restored.command(message(lab_runtime_protocol::session_execute,
                               {"r1-console-1", delete_redirect_number}))
                  .find("MINOR:") == std::string_view::npos &&
          restored.command(message(lab_runtime_protocol::session_execute,
                                   {"r1-console-1", delete_redirect_number}))
                  .find("MINOR:") != std::string_view::npos &&
          restored.command(message(lab_runtime_protocol::session_execute,
                                   {"r1-console-1", "discard"}))
                  .find("MINOR:") == std::string_view::npos &&
          restored.command(message(lab_runtime_protocol::session_execute,
                                   {"r1-console-1", delete_redirect_number}))
                  .find("MINOR:") == std::string_view::npos,
      "checkpoint lost ICMPv6 Redirect leaf presence in candidate or running "
      "intent");
  require(!restored
               .command(message(lab_runtime_protocol::capture_point_set,
                                {"router-ingress", "r1", "1/1/1", "0", "0"}))
               .starts_with("ERROR:"),
          "checkpoint lost the stable capture location identity");
  std::string restored_ping;
  for (std::size_t attempt = 0; attempt < 200U; ++attempt) {
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
    restored_ping += restored.command(
        message(lab_runtime_protocol::session_poll, {"r1-console-4"}));
    if (restored_ping.find("packets received") != std::string::npos)
      break;
  }
  require(restored_ping.find("1 packets transmitted, 1 packets received") !=
              std::string_view::npos,
          "checkpoint lost asynchronous ping state or relative deadlines");
}
