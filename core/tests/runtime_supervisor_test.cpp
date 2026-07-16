// Supervisor tests verify empty startup, cross-kind identity, hardware-derived
// carrier, retained absent-port links and isolated router deletion.

#include "router/runtime_supervisor.hpp"
#include "router/lab_checkpoint.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

namespace {

void require(bool condition, const char *message) {
  // The shared runner preserves the first focused lifecycle diagnostic.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void runtime_supervisor_tests() {
  using namespace router::lab;
  // The global packet pool belongs on the heap, matching the production
  // supervisor lifetime instead of consuming a Wasm pthread stack.
  auto runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->devices().size() == 0 && runtime->hosts().size() == 0 &&
              runtime->topology().size() == 0,
          "new supervisor did not start empty");

  const auto r1 = runtime->create_router("r1", "7750-sr-1", "R1");
  const auto r2 = runtime->create_router("r2", "7750-sr-7", "R2");
  const auto h1 = runtime->create_host("h1", "Host 1");
  require(r1 && r2 && h1, "supervisor rejected valid mixed nodes");
  require(!runtime->create_host("r1", "Duplicate"),
          "supervisor accepted cross-kind duplicate identity");

  const auto router_link = runtime->create_link(
      "r1-r2", {node(*r1), "1/1/1"}, {node(*r2), "1/1/1"},
      std::chrono::nanoseconds{100});
  // Empty modular hardware retains topology but cannot create physical signal.
  require(router_link && runtime->topology().size() == 1 &&
              runtime->active_links() == 0,
          "absent hardware did not retain carrier-down link intent");
  require(runtime->set_card(*r2, 1, "iom4-e", "iom4-e") ==
              HardwareEditResult::applied &&
              runtime->set_mda(*r2, 1, 1, "me10-10gb-sfp+",
                               "me10-10gb-sfp+") ==
                  HardwareEditResult::applied,
          "supervisor rejected compatible R2 inventory");
  // R1 is 100 Gb/s and R2 is 10 Gb/s. A name-matched cable cannot hide that
  // selected rate mismatch.
  require(runtime->active_links() == 0,
          "speed mismatch produced magic carrier");

  const auto host_link = runtime->create_link(
      "r1-h1", {node(*r1), "1/1/2"}, {node(*h1), "eth0"},
      std::chrono::nanoseconds{50});
  require(host_link && runtime->active_links() == 1,
          "router-host physical link did not activate");
  require(runtime->set_link_properties(*host_link, false,
                                       std::chrono::nanoseconds{250}) &&
              runtime->topology().get(*host_link)->propagation_ns == 250U &&
              runtime->active_links() == 1,
          "link property edit deleted the object or lost propagation");
  require(runtime->delete_router(*r1) && runtime->devices().size() == 1 &&
              runtime->topology().size() == 0 &&
              runtime->active_links() == 0,
          "router deletion retained links or changed unrelated router");

  // Release the first shared packet pool before constructing the four-router
  // reference path inside the fixed 256 MiB Wasm memory budget.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  const auto a = runtime->create_router("a", "7750-sr-1", "A");
  const auto b = runtime->create_router("b", "7750-sr-1", "B");
  const auto c = runtime->create_router("c", "7750-sr-1", "C");
  const auto d = runtime->create_router("d", "7750-sr-1", "D");
  require(a && b && c && d, "four-router runtime creation failed");

  for (const auto device : {*a, *b, *c, *d}) {
    // Every used physical port is explicitly enabled. Fixed inventory alone
    // does not make a router interface operational.
    require(runtime->configure_port(
                device, "1/1/1", true,
                router::device_catalog::default_network_mtu, 100'000) ==
                HardwareEditResult::applied &&
                runtime->configure_port(
                    device, "1/1/2", true,
                    router::device_catalog::default_network_mtu, 100'000) ==
                    HardwareEditResult::applied,
            "four-router port provisioning failed");
  }
  const auto ab = runtime->create_link("a-b", {node(*a), "1/1/1"},
                                       {node(*b), "1/1/1"},
                                       std::chrono::nanoseconds{100});
  const auto bc = runtime->create_link("b-c", {node(*b), "1/1/2"},
                                       {node(*c), "1/1/1"},
                                       std::chrono::nanoseconds{100});
  const auto cd = runtime->create_link("c-d", {node(*c), "1/1/2"},
                                       {node(*d), "1/1/1"},
                                       std::chrono::nanoseconds{100});
  require(ab && bc && cd,
          "four-router physical chain creation failed");

  const auto select_wire = [&](router::CapturePointId id, LinkHandle link,
                               std::string_view name) {
    CapturePointProgram program;
    program.id = id;
    program.kind = CapturePointKind::link_direction;
    program.link = link;
    program.link_endpoint = 0;
    program.selected = true;
    program.name_size = static_cast<std::uint16_t>(name.size());
    std::copy(name.begin(), name.end(), program.name.begin());
    return runtime->configure_capture_point(program);
  };
  require(select_wire(0, *ab, "a-b/from-a") &&
              select_wire(1, *bc, "b-c/from-b") &&
              select_wire(2, *cd, "c-d/from-c"),
          "four-router wire capture selection failed");

  const router::packet::Mac mac_a{0x02, 0, 0, 0, 0x0a, 1};
  const router::packet::Mac mac_b1{0x02, 0, 0, 0, 0x0b, 1};
  const router::packet::Mac mac_b2{0x02, 0, 0, 0, 0x0b, 2};
  const router::packet::Mac mac_c1{0x02, 0, 0, 0, 0x0c, 1};
  const router::packet::Mac mac_c2{0x02, 0, 0, 0, 0x0c, 2};
  const router::packet::Mac mac_d{0x02, 0, 0, 0, 0x0d, 1};
  require(runtime->configure_interface(*a, "1/1/1", mac_a, 0x0a000c01U,
                                       30, true) &&
              runtime->configure_interface(*b, "1/1/1", mac_b1,
                                           0x0a000c02U, 30, true) &&
              runtime->configure_interface(*b, "1/1/2", mac_b2,
                                           0x0a001701U, 30, true) &&
              runtime->configure_interface(*c, "1/1/1", mac_c1,
                                           0x0a001702U, 30, true) &&
              runtime->configure_interface(*c, "1/1/2", mac_c2,
                                           0x0a002201U, 30, true) &&
              runtime->configure_interface(*d, "1/1/1", mac_d, 0x0a002202U,
                                           30, true),
          "four-router interface configuration failed");
  require(runtime->add_static_route(*a, 0x0a002200U, 30, 0x0a000c02U) &&
              runtime->add_static_route(*b, 0x0a002200U, 30, 0x0a001702U) &&
              runtime->add_static_route(*c, 0x0a000c00U, 30, 0x0a001701U) &&
              runtime->add_static_route(*d, 0x0a000c00U, 30, 0x0a002201U),
          "four-router static route configuration failed");

  require(runtime->start_router_ping(*a, 0x0a002202U, 77),
          "asynchronous four-router ping did not start");
  // The network pthread owns steady_clock and all delivery deadlines. Polling
  // observes completion only and never advances a hidden test timeline.
  for (std::size_t turn = 0;
       turn < 500 && !runtime->router_ping_reply(*a, 77); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->router_ping_reply(*a, 77),
          "four-router ping did not traverse encoded hop-by-hop forwarding");

  auto path_checkpoint = runtime->checkpoint();
  require(path_checkpoint && path_checkpoint->network.routers.size() == 4,
          "four-router forwarding checkpoint was unavailable");
  for (const auto &router : path_checkpoint->network.routers)
    require(!router.forwarding.adjacencies.empty(),
            "a physical hop completed without a learned ARP adjacency");
  std::array<bool, 3> observed_ttl{};
  for (const auto &record : path_checkpoint->network.capture.records) {
    if (record.capture_point >= observed_ttl.size())
      continue;
    const auto ipv4 = router::packet::parse_ipv4(record.frame);
    const auto icmp = router::packet::parse_icmp(record.frame);
    if (ipv4 && icmp && icmp->type == 8U && icmp->sequence == 77U)
      observed_ttl[record.capture_point] =
          ipv4->ttl == static_cast<std::uint8_t>(64U - record.capture_point);
  }
  require(std::all_of(observed_ttl.begin(), observed_ttl.end(),
                      [](bool value) { return value; }),
          "encoded IPv4 TTL was not decremented exactly once per physical hop");
  path_checkpoint.reset();

  const auto host_a = runtime->create_host("host-a", "Host A");
  const auto host_b = runtime->create_host("host-b", "Host B");
  require(host_a && host_b,
          "reference path host creation failed");
  require(runtime->create_link("host-a-a", {node(*host_a), "eth0"},
                               {node(*a), "1/1/2"},
                               std::chrono::nanoseconds{100}) &&
              runtime->create_link("d-host-b", {node(*d), "1/1/2"},
                                   {node(*host_b), "eth0"},
                                   std::chrono::nanoseconds{100}),
          "reference path host links failed");
  const router::packet::Mac edge_a{0x02, 0, 0, 0, 0x0a, 2};
  const router::packet::Mac edge_d{0x02, 0, 0, 0, 0x0d, 2};
  const router::packet::Mac endpoint_a{0x02, 0, 0, 0, 0xaa, 1};
  const router::packet::Mac endpoint_b{0x02, 0, 0, 0, 0xbb, 1};
  require(runtime->configure_interface(*a, "1/1/2", edge_a, 0xc0000201U,
                                       30, true) &&
              runtime->configure_interface(*d, "1/1/2", edge_d,
                                           0xc6336401U, 30, true) &&
              runtime->configure_host(*host_a, endpoint_a, {192, 0, 2, 2}, 30,
                                      {192, 0, 2, 1}, 1500) &&
              runtime->configure_host(*host_b, endpoint_b,
                                      {198, 51, 100, 2}, 30,
                                      {198, 51, 100, 1}, 1500),
          "reference path edge configuration failed");
  require(runtime->add_static_route(*a, 0xc6336400U, 30, 0x0a000c02U) &&
              runtime->add_static_route(*b, 0xc0000200U, 30, 0x0a000c01U) &&
              runtime->add_static_route(*b, 0xc6336400U, 30, 0x0a001702U) &&
              runtime->add_static_route(*c, 0xc0000200U, 30, 0x0a001701U) &&
              runtime->add_static_route(*c, 0xc6336400U, 30, 0x0a002202U) &&
              runtime->add_static_route(*d, 0xc0000200U, 30, 0x0a002201U),
          "reference path host routes failed");

  require(runtime->start_host_ping(*host_a, {198, 51, 100, 2}, 88),
          "Host A asynchronous ping did not start");
  for (std::size_t turn = 0;
       turn < 500 && !runtime->host_ping_reply(*host_a, 88); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->host_ping_reply(*host_a, 88),
          "Host A to four routers to Host B ping did not complete");

  const auto session = runtime->create_session(*a, "a-console-1");
  require(session &&
              runtime->enter_session_mode(
                  *session, CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied &&
              runtime->record_session_edit(*session, 0xabcU) ==
                  SessionWorkflowResult::applied,
          "supervisor checkpoint fixture could not stage a private session");
  auto checkpoint = runtime->checkpoint();
  require(checkpoint && checkpoint->devices.entries.size() == 4 &&
              checkpoint->hosts.entries.size() == 2 &&
              checkpoint->topology.entries.size() == 5 &&
              checkpoint->network.fabric.links.size() == 5,
          "supervisor barrier omitted part of the laboratory graph");
  const auto bytes = checkpoint_v5::encode(*checkpoint);
  auto decoded = checkpoint_v5::decode(bytes);
  require(decoded && bytes.size() > 64,
          "checkpoint ABI 5 did not round-trip the value graph");
  auto corrupted = bytes;
  corrupted[0] ^= 0x5aU;
  require(!checkpoint_v5::decode(corrupted),
          "checkpoint ABI 5 accepted corrupted family magic");

  // Destroying releases the only packet and capture arenas. The checkpoint
  // owns encoded values, not references into those arenas.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->restore(std::move(*decoded)) &&
              runtime->devices().get(*a) && runtime->hosts().get(*host_a) &&
              runtime->topology().size() == 5 &&
              runtime->session_status(*session)->candidate_dirty,
          "whole-lab checkpoint did not restore identities and owner state");
  require(runtime->start_host_ping(*host_a, {198, 51, 100, 2}, 89),
          "restored whole lab could not start endpoint traffic");
  for (std::size_t turn = 0;
       turn < 500 && !runtime->host_ping_reply(*host_a, 89); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->host_ping_reply(*host_a, 89),
          "restored whole lab did not preserve multi-hop forwarding state");

  // Removal is a real control-to-forwarding transaction. Repeating it must
  // fail explicitly instead of acknowledging an already absent route or
  // interface as a successful no-op.
  require(runtime->remove_static_route(*a, 0xc6336400U, 30) &&
              !runtime->remove_static_route(*a, 0xc6336400U, 30) &&
              runtime->remove_interface(*a, "1/1/1") &&
              !runtime->remove_interface(*a, "1/1/1"),
          "route or interface removal was not exact and idempotence-safe");

  auto invalid = runtime->checkpoint();
  require(static_cast<bool>(invalid),
          "supervisor could not prepare invalid-import fixture");
  invalid->devices.generations[a->index] = 0;
  require(!runtime->restore(std::move(*invalid)) &&
              runtime->devices().get(*a) && runtime->active_links() == 5,
          "failed whole-lab import partially changed the active laboratory");

  const auto before_failure = runtime->checkpoint();
  require(static_cast<bool>(before_failure),
          "failure-isolation baseline checkpoint was unavailable");
  const auto fib_generation = [](const RuntimeSupervisorCheckpoint &state,
                                 DeviceHandle device) {
    const auto found = std::find_if(state.network.routers.begin(),
                                    state.network.routers.end(),
                                    [&](const auto &router) {
                                      return router.device == device;
                                    });
    return found == state.network.routers.end()
               ? std::uint64_t{}
               : found->forwarding.fib.generation;
  };
  const auto a_before = fib_generation(*before_failure, *a);
  const auto b_before = fib_generation(*before_failure, *b);
  const auto c_before = fib_generation(*before_failure, *c);
  const auto d_before = fib_generation(*before_failure, *d);
  require(runtime->delete_link(*bc),
          "middle-link failure transaction was rejected");
  const auto after_failure = runtime->checkpoint();
  require(after_failure && fib_generation(*after_failure, *a) == a_before &&
              fib_generation(*after_failure, *d) == d_before &&
              fib_generation(*after_failure, *b) > b_before &&
              fib_generation(*after_failure, *c) > c_before,
          "middle-link failure rebuilt an unrelated router FIB");
}
