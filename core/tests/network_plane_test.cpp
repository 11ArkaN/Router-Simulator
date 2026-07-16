// Network-plane tests prove that forwarding and fabric state can run under one
// owner without registry, hardware, CLI or project access.

#include "router/network_plane.hpp"

#include <chrono>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace {

void require(bool condition, const char *message) {
  // The shared module runner preserves the first ownership-boundary failure.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void network_plane_tests() {
  using namespace router::lab;
  using namespace router::lab::routing;
  // Module tests inject future steady-clock points and therefore select the
  // generated low-CPU combined owner explicitly. Physical shard scheduling is
  // covered separately with real host time by NetworkPlaneWorker tests.
  auto plane = std::make_unique<NetworkPlane>(1);
  const DeviceHandle first{0, 1};
  const DeviceHandle second{1, 1};
  require(plane->add_router(first) && plane->add_router(second),
          "network plane rejected valid router generations");

  const router::packet::Mac first_mac{0x02, 0, 0, 0, 1, 1};
  const router::packet::Mac second_mac{0x02, 0, 0, 0, 2, 1};
  require(plane->configure_port(first, {true, true, 0, 1514, 0x0a000001U,
                                        0x0a000000U, 10'000, 30, first_mac}) &&
              plane->configure_port(second, {true, true, 0, 1514,
                                             0x0a000002U, 0x0a000000U,
                                             10'000, 30, second_mac}),
          "network plane rejected valid forwarding ports");
  RouteTable first_rib;
  RouteTable second_rib;
  const std::array first_connected{
      ConnectedInput{true, true, 0x0a000000U, 0, 30}};
  const std::array second_connected{
      ConnectedInput{true, true, 0x0a000000U, 0, 30}};
  require(first_rib.rebuild(first_connected, std::span<const StaticInput>{}) &&
              second_rib.rebuild(second_connected,
                                 std::span<const StaticInput>{}) &&
              plane->program_fib(first, first_rib.compile(1)) &&
              plane->program_fib(second, second_rib.compile(1)),
          "network plane rejected connected FIB programs");
  const LinkHandle link{0, 1};
  require(plane->configure_link({link, {node(first), 0, 1},
                                 {node(second), 0, 1}, 10'000'000'000ULL,
                                 std::chrono::nanoseconds{100}, true}),
          "network plane rejected live point-to-point link");
  const auto select = [&](router::CapturePointId id, CapturePointKind kind,
                          std::string_view name, NodeHandle capture_node,
                          std::uint16_t port, std::uint8_t endpoint) {
    CapturePointProgram program;
    program.id = id;
    program.kind = kind;
    program.link = link;
    program.node = capture_node;
    program.port_ordinal = port;
    program.link_endpoint = endpoint;
    program.selected = true;
    program.name_size = static_cast<std::uint16_t>(name.size());
    std::copy(name.begin(), name.end(), program.name.begin());
    return plane->configure_capture_point(program);
  };
  require(select(10, CapturePointKind::link_direction,
                 "link:first-second", {}, 0xffffU, 0) &&
              select(11, CapturePointKind::router_ingress,
                     "router:second/port:0/ingress", node(second), 0, 0) &&
              select(12, CapturePointKind::router_egress,
                     "router:first/port:0/egress", node(first), 0, 0) &&
              select(13, CapturePointKind::cpm_punt,
                     "router:second/cpm-punt", node(second), 0xffffU, 0),
          "network plane rejected selected capture observation points");
  const LinkHandle conflicting_link{1, 1};
  require(!plane->configure_link(
              {conflicting_link, {node(first), 0, 1},
               {node(second), 1, 1}, 10'000'000'000ULL,
               std::chrono::nanoseconds{100}, true}),
          "network plane allowed one physical port on two links");

  const auto origin = NetworkPlane::Clock::now();
  require(plane->start_router_ping(first, 0x0a000002U, 9, origin),
          "network plane did not start asynchronous ping");
  for (std::size_t turn = 1;
       turn <= 30 && !plane->router_ping_reply(first, 9); ++turn)
    plane->pump(origin + std::chrono::microseconds{turn * 10U});
  require(plane->router_ping_reply(first, 9),
          "network plane ping did not cross encoded ARP and ICMP frames");
  require(plane->captured_frames() == 8 && !plane->capture_dropped(),
          "capture taps missed or duplicated encoded ARP and ICMP frames");
  plane->prepare_capture();
  const auto capture = plane->prepared_capture();
  require(capture.size() > 28 && capture[0] == 0x0a && capture[1] == 0x0d,
          "multi-router capture did not produce a PCAPNG section");

  auto checkpoint = std::make_unique<NetworkPlaneCheckpoint>(
      plane->checkpoint(origin + std::chrono::milliseconds{1}));
  require(checkpoint->routers.size() == 2 &&
              checkpoint->fabric.links.size() == 1 &&
              checkpoint->capture.records.size() == 8 &&
              checkpoint->capture_points.size() == 4,
          "network-plane barrier omitted an owner-local checkpoint domain");
  plane.reset();
  plane = std::make_unique<NetworkPlane>(1);
  const auto restore_time = NetworkPlane::Clock::now();
  require(plane->restore(*checkpoint, restore_time) &&
              plane->active_links() == 1 && plane->captured_frames() == 8,
          "network plane failed an atomic structural restore");
  require(plane->start_router_ping(first, 0x0a000002U, 10, restore_time),
          "restored router could not use its retained FIB and adjacency");
  for (std::size_t turn = 1;
       turn <= 30 && !plane->router_ping_reply(first, 10); ++turn)
    plane->pump(restore_time + std::chrono::microseconds{turn * 10U});
  require(plane->router_ping_reply(first, 10),
          "restored packet path did not deliver encoded traffic");
  auto invalid = std::make_unique<NetworkPlaneCheckpoint>(*checkpoint);
  invalid->fabric.links.front().endpoints[0].ordinal = 0xffffU;
  const auto links_before_invalid = plane->active_links();
  require(!plane->restore(*invalid, restore_time) &&
              plane->active_links() == links_before_invalid,
          "invalid network-plane checkpoint partially changed live state");

  require(plane->remove_link(link) && plane->remove_router(second),
          "network plane rejected ordered lifecycle removal");
  // Removing the cable must clear its constant-time egress binding. A later
  // originate call can create pending ARP state but cannot reach a stale link.
  require(!plane->start_router_ping(first, 0x0a000002U, 11,
                                    NetworkPlane::Clock::now()),
          "removed link retained a hidden packet-path binding");
  require(plane->dropped_packets() > 0,
          "missing physical binding discarded a frame without a drop counter");
  const auto drop_checkpoint = plane->checkpoint();
  require(drop_checkpoint.missing_binding_dropped > 0,
          "checkpoint omitted an explicit cross-owner drop counter");
  require(!plane->program_fib(second, second_rib.compile(2)),
          "stale router generation accepted a FIB program after deletion");

  const HostHandle host_a{0, 1};
  const HostHandle host_b{1, 1};
  const router::packet::Mac host_a_mac{0x02, 0, 0, 0, 0xaa, 1};
  const router::packet::Mac host_b_mac{0x02, 0, 0, 0, 0xbb, 1};
  require(plane->add_host(host_a) && plane->add_host(host_b) &&
              plane->configure_host({host_a, host_a_mac, {192, 0, 2, 1},
                                     {192, 0, 2, 2}, 30, 68}) &&
              plane->configure_host({host_b, host_b_mac, {192, 0, 2, 2},
                                     {192, 0, 2, 1}, 30, 1500}),
          "network plane rejected valid host MTU configuration");
  const LinkHandle host_link{1, 1};
  require(plane->configure_link({host_link, {node(host_a), 0, 1},
                                 {node(host_b), 0, 1}, 10'000'000'000ULL,
                                 std::chrono::nanoseconds{0}, true}) &&
              plane->start_host_ping(host_a, {192, 0, 2, 2}, 12),
          "minimum-MTU host could not start an encoded Echo operation");
  const auto host_origin = NetworkPlane::Clock::now();
  for (std::size_t turn = 1;
       turn <= 40 && !plane->host_ping_reply(host_a, 12); ++turn)
    plane->pump(host_origin + std::chrono::microseconds{turn * 10U});
  require(plane->host_ping_reply(host_a, 12),
          "host MTU was ignored instead of fragmenting and reassembling Echo");
  const auto host_checkpoint = plane->checkpoint();
  require(host_checkpoint.hosts.size() == 2 &&
              host_checkpoint.hosts[0].mtu == 68 &&
              host_checkpoint.hosts[1].mtu == 1500,
          "host checkpoint omitted interface MTU ownership");
}
