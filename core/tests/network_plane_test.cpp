// Network-plane tests prove that forwarding and fabric state can run under one
// owner without registry, hardware, CLI or project access.

#include "router/network_plane.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <numeric>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::uint32_t capture_u32(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void require(bool condition, const char *message) {
  // The shared module runner preserves the first ownership-boundary failure.
  if (!condition)
    throw std::runtime_error(message);
}

void count_network_wakeup(void *context) noexcept {
  // The callback is intentionally payload-free. Packet bytes and metadata
  // remain owned by their SPSC ring; this counter proves only that release
  // publication wakes a potentially sleeping network owner.
  static_cast<std::atomic_size_t *>(context)->fetch_add(
      1U, std::memory_order_relaxed);
}

router::crypto::Sha256Digest transport_secret(std::uint8_t seed) {
  router::crypto::Sha256Digest result{};
  for (std::size_t index = 0U; index < result.size(); ++index)
    result[index] = static_cast<std::uint8_t>(seed + index);
  return result;
}

router::packet::dns::Name dns_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("network-plane DNS fixture name is invalid");
  return *parsed;
}

std::vector<std::uint8_t> dns_name_data(const char *text) {
  const auto value = dns_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

void append_dns_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

router::lab::NetworkPlaneCheckpoint
network_checkpoint(router::lab::NetworkPlane &plane,
                   router::lab::NetworkPlane::Clock::time_point now =
                       router::lab::NetworkPlane::Clock::now()) {
  auto saved = plane.checkpoint(now);
  if (!saved)
    throw std::runtime_error("network-plane checkpoint export failed");
  return std::move(*saved);
}

} // namespace

void network_plane_tests() {
  using namespace router;
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
  require(
      plane->configure_port(first, {true, true, 0, 1514, 0x0a000001U,
                                    0x0a000000U, 10'000, 30, first_mac}) &&
          plane->configure_port(second, {true, true, 0, 1514, 0x0a000002U,
                                         0x0a000000U, 10'000, 30, second_mac}),
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
  // One physical interface may simultaneously host OSPFv2 and OSPFv3. The
  // complete generation test catches the former bug where programming one
  // address family cleared the other family's punt bit.
  const auto ospf_interface =
      [&](std::uint8_t version, std::uint8_t instance_id,
          std::uint32_t router_id, const packet::Mac &mac,
          const packet::Ipv4 &ipv4, const packet::Ipv6 &ipv6) {
        OspfInterfaceProgram program;
        program.process = {
            .device = first,
            .router_id = router_id,
            .area_id = 0U,
            .initial_dd_sequence = router_id,
            .maximum_interfaces = 1U,
            .version = version,
            .instance_id = instance_id};
        program.interface = {
            .protocol =
                {.router_id = router_id,
                 .area_id = 0U,
                 .interface_id =
                     version == packet::ospf::version_two ? 1U : 2U,
                 .network_mask = 0xfffffffcU,
                 .options = packet::ospf::option_external_routing_capability,
                 .hello_interval_seconds = 10U,
                 .dead_interval_seconds = 40U,
                 .interface_mtu = 1514U,
                 .router_priority = 1U,
                 .version = version,
                 .instance_id = instance_id,
                 .network_type = ospf::NetworkType::point_to_point,
                 .passive = false,
                 .enabled = true},
            .ipv4_source = ipv4,
            .ipv6_source = ipv6,
            .source_mac = mac,
            .physical_port_ordinal = 0U,
            .retransmit_interval_seconds = 5U,
            .transmit_delay_seconds = 1U};
        return program;
      };
  const packet::Ipv6 first_link_local{
      0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  const auto ospfv2 =
      ospf_interface(packet::ospf::version_two, 0U, 0x0a000001U,
                     first_mac, packet::Ipv4{10U, 0U, 0U, 1U}, {});
  const auto ospfv3 =
      ospf_interface(packet::ospf::version_three, 0U, 0x0a000001U,
                     first_mac, {}, first_link_local);
  const std::array ospf_processes{ospfv2.process, ospfv3.process};
  const std::array ospf_interfaces{ospfv2, ospfv3};
  require(plane->replace_ospf_generation(first, ospf_processes,
                                         ospf_interfaces, {}, {}, {}, {}),
          "network plane rejected complete dual-stack OSPF generation");
  const auto ospf_process_query = plane->query_ospf(
      first, {.kind = ospf::ControlCommandKind::query_process,
              .process_ordinal = 0U});
  require(ospf_process_query && ospf_process_query->present &&
              ospf_process_query->process_count == 2U &&
              ospf_process_query->router_id == 0x0a000001U &&
              ospf_process_query->interface_count == 1U,
          "OSPF owner did not return its live process projection");
  const auto ospf_interface_query = plane->query_ospf(
      first, {.kind = ospf::ControlCommandKind::query_interface,
              .process_ordinal = 0U,
              .interface_ordinal = 0U});
  require(ospf_interface_query && ospf_interface_query->present &&
              ospf_interface_query->interface.configuration.protocol
                      .interface_id == 1U,
          "OSPF owner did not return its live interface projection");
  require(plane->replace_ospf_generation(first, {}, {}, {}, {}, {}, {}),
          "network plane did not atomically withdraw OSPF generation");
  // Withdrawal is ordered after the OSPF owner processed the prior generation.
  // Drain any already released Hello before creating a physical link so the
  // later capture assertions observe only their explicitly selected traffic.
  plane->pump(NetworkPlane::Clock::now());
  require(plane->configure_link({link,
                                 {node(first), 0, 1},
                                 {node(second), 0, 1},
                                 10'000'000'000ULL,
                                 std::chrono::nanoseconds{100},
                                 true}),
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
  require(select(10, CapturePointKind::link_direction, "link:first-second", {},
                 0xffffU, 0) &&
              select(11, CapturePointKind::router_ingress,
                     "router:second/port:0/ingress", node(second), 0, 0) &&
              select(12, CapturePointKind::router_egress,
                     "router:first/port:0/egress", node(first), 0, 0) &&
              select(13, CapturePointKind::cpm_punt, "router:second/cpm-punt",
                     node(second), 0xffffU, 0),
          "network plane rejected selected capture observation points");
  const LinkHandle conflicting_link{1, 1};
  require(!plane->configure_link({conflicting_link,
                                  {node(first), 0, 1},
                                  {node(second), 1, 1},
                                  10'000'000'000ULL,
                                  std::chrono::nanoseconds{100},
                                  true}),
          "network plane allowed one physical port on two links");

  const auto origin = NetworkPlane::Clock::now();
  require(plane->start_router_ping(first, 0x0a000002U, 9, origin),
          "network plane did not start asynchronous ping");
  for (std::size_t turn = 1; turn <= 30 && !plane->router_ping_reply(first, 9);
       ++turn)
    plane->pump(origin + std::chrono::microseconds{turn * 10U});
  require(plane->router_ping_reply(first, 9),
          "network plane ping did not cross encoded ARP and ICMP frames");
  require(plane->captured_frames() == 8 && !plane->capture_dropped(),
          "capture taps missed or duplicated encoded ARP and ICMP frames");
  plane->prepare_capture();
  const auto capture = plane->prepared_capture();
  require(capture.size() > 28 && capture[0] == 0x0a && capture[1] == 0x0d,
          "multi-router capture did not produce a PCAPNG section");
  std::vector<std::uint32_t> observed_interfaces;
  for (std::size_t offset = 0; offset + 12U <= capture.size();) {
    const auto length = capture_u32(capture, offset + 4U);
    require(length >= 12U && offset + length <= capture.size(),
            "network-plane capture emitted an invalid PCAPNG block");
    if (capture_u32(capture, offset) == 6U)
      observed_interfaces.push_back(capture_u32(capture, offset + 8U));
    offset += length;
  }
  require(observed_interfaces.size() >= 4U &&
              observed_interfaces[0] == 2U &&
              observed_interfaces[1] == 0U &&
              observed_interfaces[2] == 1U &&
              observed_interfaces[3] == 3U,
          "capture tap order did not follow egress, link, ingress and CPM");

  auto checkpoint = std::make_unique<NetworkPlaneCheckpoint>(
      network_checkpoint(*plane, origin + std::chrono::milliseconds{1}));
  require(checkpoint->routers.size() == 2 &&
              checkpoint->fabric.links.size() == 1 &&
              std::accumulate(checkpoint->capture.points.begin(),
                              checkpoint->capture.points.end(),
                              std::uint64_t{0},
                              [](auto total, const auto &point) {
                                return total + point.received;
                              }) == 8U &&
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
  for (std::size_t turn = 1; turn <= 30 && !plane->router_ping_reply(first, 10);
       ++turn)
    plane->pump(restore_time + std::chrono::microseconds{turn * 10U});
  require(plane->router_ping_reply(first, 10),
          "restored packet path did not deliver encoded traffic");
  // The operational clear crosses the same forwarding command boundary as
  // configuration. Removing one exact mapping must force a fresh encoded ARP
  // exchange; it must not delete the FIB route or satisfy the retry through a
  // control-plane shortcut.
  require(
      plane->clear_dynamic_ipv4_neighbors(first, std::nullopt, 0x0a000002U) &&
          plane->install_static_ipv4_neighbor({.device = first,
                                               .address = 0x0a000002U,
                                               .mac = second_mac,
                                               .port_ordinal = 0U}) &&
          // Operational clear cannot remove configuration-owned state.
          plane->clear_dynamic_ipv4_neighbors(first, std::nullopt,
                                              0x0a000002U) &&
          plane->start_router_ping(first, 0x0a000002U, 12, restore_time),
      "network plane rejected static ARP programming or exact clear");
  for (std::size_t turn = 1; turn <= 30 && !plane->router_ping_reply(first, 12);
       ++turn)
    plane->pump(restore_time + std::chrono::milliseconds{1} +
                std::chrono::microseconds{turn * 10U});
  require(plane->router_ping_reply(first, 12),
          "configured adjacency did not forward through the encoded link");
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
  const auto drop_checkpoint = network_checkpoint(*plane);
  require(drop_checkpoint.missing_binding_dropped > 0,
          "checkpoint omitted an explicit cross-owner drop counter");
  require(!plane->program_fib(second, second_rib.compile(2)),
          "stale router generation accepted a FIB program after deletion");

  // This scenario crosses every production owner used by OSPFv2: protocol
  // pthread, packet channels, forwarding, physical fabric, route-generation
  // channel, RIB selection and final FIB programming. Only encoded packets
  // cross between the two routers.
  // Exercise the production split-owner topology rather than the combined
  // single-shard test mode. Checkpoint restore must wake OSPF, drain its SPSC
  // packet channels through physical forwarding shards and reconverge without
  // a management-plane configuration touch.
  auto ospf_plane = std::make_unique<NetworkPlane>(4);
  std::atomic_size_t ospf_network_wakeups{};
  ospf_plane->set_link_wakeup(&ospf_network_wakeups,
                              count_network_wakeup);
  const DeviceHandle ospf_first{4U, 1U};
  const DeviceHandle ospf_second{5U, 1U};
  const packet::Mac ospf_first_mac{0x02U, 0U, 0U, 0U, 0x40U, 1U};
  const packet::Mac ospf_second_mac{0x02U, 0U, 0U, 0U, 0x40U, 2U};
  constexpr std::uint16_t integration_hello_seconds = 1U;
  require(
      ospf_plane->add_router(ospf_first) &&
          ospf_plane->add_router(ospf_second) &&
          ospf_plane->configure_port(
              ospf_first,
              {.configured = true,
               .operational = true,
               .ordinal = 0U,
               .mtu = 1514U,
               .address = 0xc0000201U,
               .network = 0xc0000200U,
               .speed_mbps = 10'000U,
               .prefix_length = 30U,
               .mac = ospf_first_mac}) &&
          ospf_plane->configure_port(
              ospf_second,
              {.configured = true,
               .operational = true,
               .ordinal = 0U,
               .mtu = 1514U,
               .address = 0xc0000202U,
               .network = 0xc0000200U,
               .speed_mbps = 10'000U,
               .prefix_length = 30U,
               .mac = ospf_second_mac}),
      "OSPF integration fixture rejected routers or physical ports");

  const router::lab::RoutePolicyProgram route_policy{
      .maximum_ecmp_paths = 4U};
  RouteTable ospf_first_base;
  RouteTable ospf_second_base;
  const std::array ospf_first_connected{
      ConnectedInput{true, true, 0xc0000200U, 0U, 30U},
      ConnectedInput{true, true, 0xc6336401U, 0U, 32U, true}};
  const std::array ospf_second_connected{
      ConnectedInput{true, true, 0xc0000200U, 0U, 30U},
      ConnectedInput{true, true, 0xc6336402U, 0U, 32U, true}};
  require(
      ospf_first_base.rebuild(ospf_first_connected, {}) &&
          ospf_second_base.rebuild(ospf_second_connected, {}) &&
          ospf_plane->program_route_policy(ospf_first, route_policy) &&
          ospf_plane->program_route_policy(ospf_second, route_policy) &&
          ospf_plane->program_fib(ospf_first,
                                  ospf_first_base.compile(1U)) &&
          ospf_plane->program_fib(ospf_second,
                                  ospf_second_base.compile(1U)) &&
          ospf_plane->configure_link(
              {{4U, 1U},
               {node(ospf_first), 0U, 1U},
               {node(ospf_second), 0U, 1U},
               10'000'000'000ULL,
               std::chrono::nanoseconds{100U},
               true}),
      "OSPF integration fixture rejected base RIB or physical link");
  CapturePointProgram ospf_capture;
  ospf_capture.id = 400U;
  ospf_capture.kind = CapturePointKind::link_direction;
  ospf_capture.link = {4U, 1U};
  ospf_capture.link_endpoint = 0U;
  ospf_capture.selected = true;
  constexpr std::string_view ospf_capture_name{"ospf-wire"};
  ospf_capture.name_size =
      static_cast<std::uint16_t>(ospf_capture_name.size());
  std::copy(ospf_capture_name.begin(), ospf_capture_name.end(),
            ospf_capture.name.begin());
  require(ospf_plane->configure_capture_point(ospf_capture),
          "OSPF integration fixture rejected wire capture");
  CapturePointProgram ospf_punt_capture;
  ospf_punt_capture.id = 401U;
  ospf_punt_capture.kind = CapturePointKind::cpm_punt;
  ospf_punt_capture.node = node(ospf_second);
  ospf_punt_capture.selected = true;
  constexpr std::string_view ospf_punt_name{"ospf-second-cpm"};
  ospf_punt_capture.name_size =
      static_cast<std::uint16_t>(ospf_punt_name.size());
  std::copy(ospf_punt_name.begin(), ospf_punt_name.end(),
            ospf_punt_capture.name.begin());
  require(ospf_plane->configure_capture_point(ospf_punt_capture),
          "OSPF integration fixture rejected CPM capture");

  const auto ospf_program = [&](DeviceHandle device, std::uint32_t router_id,
                                std::uint32_t physical_address,
                                std::uint32_t system_address,
                                const packet::Mac &mac) {
    OspfProcessProgram process{.device = device,
                               .router_id = router_id,
                               .area_id = 0U,
                               .initial_dd_sequence = router_id,
                               .maximum_interfaces = 2U,
                               .version = packet::ospf::version_two,
                               .instance_id = 0U};
    OspfInterfaceProgram physical{
        .process = process,
        .interface =
            {.protocol =
                 {.router_id = router_id,
                  .area_id = 0U,
                  .interface_id = 1U,
                  .network_mask = 0xfffffffcU,
                  .options = packet::ospf::option_external_routing_capability,
                  .hello_interval_seconds = integration_hello_seconds,
                  .dead_interval_seconds = 4U,
                  .interface_mtu = 1514U,
                  .router_priority = 1U,
                  .version = packet::ospf::version_two,
                  .network_type = ospf::NetworkType::point_to_point,
                  .enabled = true},
             .ipv4_source =
                 {{static_cast<std::uint8_t>(physical_address >> 24U),
                   static_cast<std::uint8_t>(physical_address >> 16U),
                   static_cast<std::uint8_t>(physical_address >> 8U),
                   static_cast<std::uint8_t>(physical_address)}},
             .source_mac = mac,
             .physical_port_ordinal = 0U,
             .metric = 10U,
             .retransmit_interval_seconds = 1U,
             .transmit_delay_seconds = 1U,
             .prefix_length = 30U}};
    auto passive = physical;
    passive.interface.protocol.interface_id = 2U;
    passive.interface.protocol.network_mask = 0xffffffffU;
    passive.interface.protocol.passive = true;
    passive.interface.ipv4_source = {
        {static_cast<std::uint8_t>(system_address >> 24U),
         static_cast<std::uint8_t>(system_address >> 16U),
         static_cast<std::uint8_t>(system_address >> 8U),
         static_cast<std::uint8_t>(system_address)}};
    passive.interface.physical_port_ordinal = ospf::no_physical_port;
    passive.interface.metric = 0U;
    passive.interface.prefix_length = 32U;
    return std::pair{process, std::array{physical, passive}};
  };
  const auto [ospf_first_process, ospf_first_interfaces] =
      ospf_program(ospf_first, 0x01010101U, 0xc0000201U, 0xc6336401U,
                   ospf_first_mac);
  const auto [ospf_second_process, ospf_second_interfaces] =
      ospf_program(ospf_second, 0x02020202U, 0xc0000202U, 0xc6336402U,
                   ospf_second_mac);
  require(
      ospf_plane->replace_ospf_generation(
          ospf_first, std::span{&ospf_first_process, 1U},
          ospf_first_interfaces, {}, {}, {}, {}) &&
          ospf_plane->replace_ospf_generation(
              ospf_second, std::span{&ospf_second_process, 1U},
              ospf_second_interfaces, {}, {}, {}, {}),
      "OSPF integration fixture rejected complete process generations");

  bool learned{};
  const auto convergence_deadline =
      std::chrono::steady_clock::now() +
      device_catalog::ospf_min_lsa_interval +
      device_catalog::ospf_spf_maximum_wait +
      std::chrono::seconds{integration_hello_seconds};
  while (!learned && std::chrono::steady_clock::now() <
                         convergence_deadline) {
    ospf_plane->pump(NetworkPlane::Clock::now());
    const auto state =
        ospf_plane->router_checkpoint(ospf_first, NetworkPlane::Clock::now());
    learned =
        state && std::any_of(
                     state->fib.routes.begin(),
                     state->fib.routes.begin() + state->fib.count,
                     [](const auto &route) {
                       return route.network == 0xc6336402U &&
                              route.prefix_length == 32U &&
                              route.source == RouteSource::ospf &&
                              route.next_hop == 0xc0000202U;
                     });
    if (!learned)
      std::this_thread::sleep_for(std::chrono::milliseconds{1U});
  }
  if (!learned) {
    ospf_plane->prepare_capture();
    const auto capture_bytes = ospf_plane->prepared_capture();
    std::array<std::size_t, 6U> packet_types{};
    std::size_t last_hello_neighbors{};
    for (std::size_t offset{}; offset + 12U <= capture_bytes.size();) {
      const auto block_length = capture_u32(capture_bytes, offset + 4U);
      if (block_length < 12U || offset + block_length > capture_bytes.size())
        break;
      if (capture_u32(capture_bytes, offset) == 6U &&
          block_length >= 28U + packet::ethernet_header_octets +
                              packet::ipv4_minimum_header_octets +
                              packet::ospf::version_two_header_octets) {
        packet::Frame frame;
        const auto captured =
            std::min<std::size_t>(capture_u32(capture_bytes, offset + 20U),
                                  frame.bytes.size());
        std::copy_n(capture_bytes.begin() +
                        static_cast<std::ptrdiff_t>(offset + 28U),
                    captured, frame.bytes.begin());
        frame.length = static_cast<std::uint16_t>(captured);
        const auto ipv4 = packet::parse_ipv4(frame);
        if (ipv4) {
          const auto payload_offset =
              packet::ethernet_header_octets + ipv4->header_length;
          const auto decoded = packet::ospf::parse_packet(
              frame.view().subspan(payload_offset));
          if (decoded) {
            const auto type = static_cast<std::size_t>(decoded->type);
            if (type < packet_types.size())
              ++packet_types[type];
            if (decoded->type == packet::ospf::PacketType::hello)
              if (const auto hello = packet::ospf::parse_hello(*decoded))
                last_hello_neighbors = hello->neighbors.size() / 4U;
          }
        }
      }
      offset += block_length;
    }
    const auto state =
        ospf_plane->router_checkpoint(ospf_first, NetworkPlane::Clock::now());
    const auto route_diagnostics =
        ospf_plane->ospf_route_diagnostics(ospf_first);
    std::string detail =
        "encoded OSPF adjacency and LSDB did not install the remote route; "
        "drops=" +
        std::to_string(ospf_plane->dropped_packets()) + " frames=" +
        std::to_string(ospf_plane->captured_frames()) + " hello=" +
        std::to_string(packet_types[1U]) + " hello-neighbors=" +
        std::to_string(last_hello_neighbors) + " dd=" +
        std::to_string(packet_types[2U]) + " lsr=" +
        std::to_string(packet_types[3U]) + " lsu=" +
        std::to_string(packet_types[4U]) + " ack=" +
        std::to_string(packet_types[5U]) + " fib=" +
        std::to_string(state ? state->fib.count : 0U) + " route-gen=" +
        std::to_string(route_diagnostics ? route_diagnostics->generation
                                         : 0U) +
        " candidates=" +
        std::to_string(route_diagnostics
                           ? route_diagnostics->ipv4_candidates
                           : 0U);
    if (state)
      for (std::size_t index{}; index < state->fib.count; ++index) {
        const auto &route = state->fib.routes[index];
        detail += " " + std::to_string(route.network) + "/" +
                  std::to_string(route.prefix_length) + " src=" +
                  std::to_string(static_cast<unsigned>(route.source)) +
                  " nh=" + std::to_string(route.next_hop);
      }
    throw std::runtime_error(detail);
  }
  const auto ospf_continuity_time = NetworkPlane::Clock::now();
  auto ospf_checkpoint =
      network_checkpoint(*ospf_plane, ospf_continuity_time);
  const auto restored_first = std::find_if(
      ospf_checkpoint.routers.begin(), ospf_checkpoint.routers.end(),
      [&](const auto &router) { return router.device == ospf_first; });
  require(restored_first != ospf_checkpoint.routers.end(),
          "OSPF checkpoint omitted its first forwarding owner");
  // Reproduce a browser reload whose persisted forwarding generation is newer
  // than the canonical configuration generation while its bytes contain only
  // the base connected RIB. The restored LSDB must republish learned routes
  // above this high-water mark. Otherwise the forwarder correctly rejects the
  // reconstructed FIB as stale and `show router ospf status` can report routes
  // while the route table remains empty.
  constexpr std::uint64_t restored_generation_floor = 10'000U;
  restored_first->forwarding.fib =
      ospf_first_base.compile(restored_generation_floor);
  // This fixture intentionally replaces the selected FIB generation inside
  // the detached checkpoint. Route ages are part of that same generation, so
  // replace them atomically instead of leaving timestamps for removed paths.
  restored_first->forwarding.ipv4_route_ages_seconds.assign(
      restored_first->forwarding.fib.count, 0U);
  require(ospf_checkpoint.ospf.processes.size() == 2U &&
              ospf_plane->restore(ospf_checkpoint,
                                  NetworkPlane::Clock::now()) &&
              ospf_plane->program_route_policy(ospf_first, route_policy) &&
              ospf_plane->program_route_policy(ospf_second, route_policy) &&
              ospf_plane->program_fib(ospf_first,
                                      ospf_first_base.compile(1U)) &&
              ospf_plane->program_fib(ospf_second,
                                      ospf_second_base.compile(1U)),
          "network checkpoint did not restore both live OSPF owners");
  const auto restored_route_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{1U};
  bool restored_remote_route{};
  while (std::chrono::steady_clock::now() < restored_route_deadline) {
    ospf_plane->pump(NetworkPlane::Clock::now());
    const auto restored =
        ospf_plane->router_checkpoint(ospf_first,
                                      NetworkPlane::Clock::now());
    if (restored &&
        std::any_of(restored->fib.routes.begin(),
                    restored->fib.routes.begin() + restored->fib.count,
                    [](const auto &route) {
                      return route.network == 0xc6336402U &&
                             route.prefix_length == 32U &&
                             route.source == RouteSource::ospf;
                    }) &&
        restored->fib.generation > restored_generation_floor) {
      restored_remote_route = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{1U});
  }
  require(restored_remote_route,
          "restored OSPF generation did not advance beyond the forwarding "
          "high-water mark");
  require(ospf_plane->start_router_ping(
              ospf_first, 0xc6336402U, 81U, NetworkPlane::Clock::now()),
          "learned OSPF route did not originate a router ping");
  const auto ping_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{1U};
  while (!ospf_plane->router_ping_reply(ospf_first, 81U) &&
         std::chrono::steady_clock::now() < ping_deadline) {
    ospf_plane->pump(NetworkPlane::Clock::now());
    std::this_thread::sleep_for(std::chrono::milliseconds{1U});
  }
  require(ospf_plane->router_ping_reply(ospf_first, 81U),
          "IPv4 data traffic did not cross the learned OSPF route");
  require(ospf_network_wakeups.load(std::memory_order_relaxed) != 0U,
          "release-published OSPF egress did not wake the network owner");

  // A restored Full adjacency can make a shallow checkpoint test pass even
  // when the replacement forwarder has lost its derived OSPF punt mask. Wait
  // beyond the four-second inactivity interval so only newly encoded and
  // delivered Hellos can keep both neighbors alive. This verifies continuity
  // across the real protocol, forwarding, fabric and peer protocol owners,
  // rather than merely observing stale serialized neighbor state.
  const auto restored_adjacency_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{5U};
  while (std::chrono::steady_clock::now() <
         restored_adjacency_deadline) {
    ospf_plane->pump(NetworkPlane::Clock::now());
    std::this_thread::sleep_for(std::chrono::milliseconds{1U});
  }
  const auto restored_first_neighbor = ospf_plane->query_ospf(
      ospf_first,
      {.kind = ospf::ControlCommandKind::query_neighbor,
       .process_ordinal = 0U,
       .interface_ordinal = 0U,
       .row_ordinal = 0U});
  const auto restored_second_neighbor = ospf_plane->query_ospf(
      ospf_second,
      {.kind = ospf::ControlCommandKind::query_neighbor,
       .process_ordinal = 0U,
       .interface_ordinal = 0U,
       .row_ordinal = 0U});
  require(restored_first_neighbor && restored_first_neighbor->present &&
              restored_first_neighbor->neighbor.runtime.state ==
                  ospf::NeighborState::full &&
              restored_second_neighbor && restored_second_neighbor->present &&
              restored_second_neighbor->neighbor.runtime.state ==
                  ospf::NeighborState::full,
          "restored forwarding owners did not sustain OSPF adjacency through "
          "post-restore Hello packets");

  const HostHandle host_a{0, 1};
  const HostHandle host_b{1, 1};
  const router::packet::Mac host_a_mac{0x02, 0, 0, 0, 0xaa, 1};
  const router::packet::Mac host_b_mac{0x02, 0, 0, 0, 0xbb, 1};
  require(
      plane->add_host(host_a) && plane->add_host(host_b) &&
          plane->configure_host({.host = host_a,
                                 .mac = host_a_mac,
                                 .address = {192, 0, 2, 1},
                                 .gateway = {192, 0, 2, 2},
                                 .prefix_length = 30,
                                 .mtu = 68,
                                 .transport_secret = transport_secret(1U)}) &&
          plane->configure_host({.host = host_b,
                                 .mac = host_b_mac,
                                 .address = {192, 0, 2, 2},
                                 .gateway = {192, 0, 2, 1},
                                 .prefix_length = 30,
                                 .mtu = 1500,
                                 .transport_secret = transport_secret(2U)}),
      "network plane rejected valid host MTU configuration");
  const LinkHandle host_link{1, 1};
  require(plane->configure_link({host_link,
                                 {node(host_a), 0, 1},
                                 {node(host_b), 0, 1},
                                 10'000'000'000ULL,
                                 std::chrono::nanoseconds{0},
                                 true}) &&
              plane->start_host_ping(host_a, {192, 0, 2, 2}, 12),
          "minimum-MTU host could not start an encoded Echo operation");
  const auto host_origin = NetworkPlane::Clock::now();
  for (std::size_t turn = 1; turn <= 40 && !plane->host_ping_reply(host_a, 12);
       ++turn)
    plane->pump(host_origin + std::chrono::microseconds{turn * 10U});
  require(plane->host_ping_reply(host_a, 12),
          "host MTU was ignored instead of fragmenting and reassembling Echo");
  const auto host_checkpoint = network_checkpoint(*plane);
  require(host_checkpoint.hosts.size() == 2 &&
              host_checkpoint.hosts[0].mtu == 68 &&
              host_checkpoint.hosts[1].mtu == 1500,
          "host checkpoint omitted interface MTU ownership");

  // Production DHCPv6 services are programmed through NetworkPlane rather
  // than invoking a peer protocol object. Both hosts first complete link-local
  // DAD, then Solicit, Advertise, Request and Reply traverse the same fabric.
  require(plane->configure_host({.host = host_a,
                                 .mac = host_a_mac,
                                 .address = {192, 0, 2, 1},
                                 .gateway = {192, 0, 2, 2},
                                 .prefix_length = 30,
                                 .mtu = 1500,
                                 .interface_id = 201U,
                                 .ipv6_autoconfiguration = true,
                                 .transport_secret = transport_secret(3U)}) &&
              plane->configure_host({.host = host_b,
                                     .mac = host_b_mac,
                                     .address = {192, 0, 2, 2},
                                     .gateway = {192, 0, 2, 1},
                                     .prefix_length = 30,
                                     .mtu = 1500,
                                     .interface_id = 202U,
                                     .ipv6_autoconfiguration = true,
                                     .transport_secret = transport_secret(4U)}),
          "network plane rejected dual-stack DHCPv6 hosts");
  HostDhcpv6ServerProgram dhcp_server{.host = host_b,
                                      .configuration = {},
                                      .address_pools = {},
                                      .prefix_pools = {},
                                      .decline_hold_time =
                                          std::chrono::hours{1}};
  constexpr std::array<std::uint8_t, 7U> server_duid{0U,    3U,    0U, 1U,
                                                     0x22U, 0x22U, 1U};
  std::copy(server_duid.begin(), server_duid.end(),
            dhcp_server.configuration.duid.begin());
  dhcp_server.configuration.duid_octets =
      static_cast<std::uint16_t>(server_duid.size());
  const auto dhcp_prefix = router::ip::parse_ipv6_prefix("2001:db8:220::/64");
  require(dhcp_prefix.has_value(), "DHCPv6 NetworkPlane pool is invalid");
  dhcp_server.address_pools.push_back({.prefix = *dhcp_prefix,
                                       .preferred_lifetime_seconds = 3600U,
                                       .valid_lifetime_seconds = 7200U,
                                       .t1_seconds = 1800U,
                                       .t2_seconds = 2880U});
  for (std::size_t index = 0;
       index < dhcp_server.address_pools.front().allocation_secret.size();
       ++index)
    dhcp_server.address_pools.front().allocation_secret[index] =
        static_cast<std::uint8_t>(index + 1U);
  HostDhcpv6ClientProgram dhcp_client{
      .host = host_a, .configuration = {}, .information_only = false};
  constexpr std::array<std::uint8_t, 7U> client_duid{0U,    3U,    0U, 1U,
                                                     0x11U, 0x11U, 1U};
  std::copy(client_duid.begin(), client_duid.end(),
            dhcp_client.configuration.duid.begin());
  dhcp_client.configuration.duid_octets =
      static_cast<std::uint16_t>(client_duid.size());
  dhcp_client.configuration.identity_associations.push_back(
      {.iaid = 0x10203040U, .kind = router::dhcpv6::LeaseKind::non_temporary});
  for (std::size_t index = 0;
       index < dhcp_client.configuration.transaction_secret.size(); ++index)
    dhcp_client.configuration.transaction_secret[index] =
        static_cast<std::uint8_t>(0xa0U + index);
  require(plane->configure_host_dhcpv6_server(dhcp_server) &&
              plane->configure_host_dhcpv6_client(dhcp_client),
          "network plane rejected transactional DHCPv6 service programs");
  const auto dhcp_origin = NetworkPlane::Clock::now();
  for (std::size_t turn = 1;
       turn <= 1'500U &&
       plane->host_dhcpv6_client_lease_count(host_a).value_or(0U) == 0U;
       ++turn)
    plane->pump(dhcp_origin + std::chrono::milliseconds{turn * 10U});
  require(
      plane->host_dhcpv6_client_lease_count(host_a).value_or(0U) == 1U,
      "production DHCPv6 exchange bypassed or failed the encoded fabric path");
  const auto dhcp_checkpoint =
      network_checkpoint(*plane, dhcp_origin + std::chrono::seconds{16});
  plane.reset();
  plane = std::make_unique<NetworkPlane>(1);
  require(plane->restore(dhcp_checkpoint, NetworkPlane::Clock::now()) &&
              plane->host_dhcpv6_client_lease_count(host_a).value_or(0U) == 1U,
          "DHCPv6 client/server owners or UDP sockets were lost on restore");

  // A separate dual-stack fixture proves the public NetworkPlane contract,
  // not only RouterForwarder internals. Resolution, Echo and Echo Reply cross
  // the real fabric as NS, NA and ICMPv6 frames owned by different routers.
  auto ipv6_plane = std::make_unique<NetworkPlane>(1);
  const DeviceHandle ipv6_first{0, 1};
  const DeviceHandle ipv6_second{1, 1};
  const auto ipv6 = [](const char *text) {
    const auto result = router::ip::parse_ipv6(text);
    if (!result)
      throw std::runtime_error("IPv6 network-plane fixture address is invalid");
    return *result;
  };
  const auto first_ipv6 = ipv6("2001:db8:20::1");
  const auto second_ipv6 = ipv6("2001:db8:20::2");
  const auto second_ipv6_secondary = ipv6("2001:db8:20::22");
  ForwardPort first_ipv6_port{.configured = true,
                              .operational = true,
                              .ordinal = 0,
                              .mtu = 1514,
                              .speed_mbps = 10'000,
                              .mac = first_mac,
                              .ipv6_configured = true,
                              .ipv6_address = first_ipv6,
                              .ipv6_link_local = ipv6("fe80::1"),
                              .ipv6_prefix_length = 64};
  ForwardPort second_ipv6_port{.configured = true,
                               .operational = true,
                               .ordinal = 0,
                               .mtu = 1514,
                               .speed_mbps = 10'000,
                               .mac = second_mac,
                               .ipv6_configured = true,
                               .ipv6_address = second_ipv6,
                               .ipv6_link_local = ipv6("fe80::2"),
                               .ipv6_prefix_length = 64};
  Ipv6RouteTable first_ipv6_rib;
  Ipv6RouteTable second_ipv6_rib;
  const std::array ipv6_connected{
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = ipv6("2001:db8:20::"),
                         .interface_id = physical_interface_id(0U),
                         .physical_port_ordinal = 0,
                         .prefix_length = 64}};
  const std::array first_ipv6_addresses{
      RouterIpv6Address{.address = first_ipv6,
                        .network = ipv6("2001:db8:20::"),
                        .interface_id = physical_interface_id(0U),
                        .port_ordinal = 0U,
                        .prefix_length = 64U}};
  const std::array second_ipv6_addresses{
      RouterIpv6Address{.address = second_ipv6,
                        .network = ipv6("2001:db8:20::"),
                        .interface_id = physical_interface_id(0U),
                        .primary_preference = 10U,
                        .port_ordinal = 0U,
                        .prefix_length = 64U},
      RouterIpv6Address{.address = second_ipv6_secondary,
                        .network = ipv6("2001:db8:20::"),
                        .interface_id = physical_interface_id(0U),
                        .primary_preference = 20U,
                        .tag = 2022U,
                        .port_ordinal = 0U,
                        .prefix_length = 64U,
                        .tag_configured = true}};
  require(
      ipv6_plane->add_router(ipv6_first) &&
          ipv6_plane->add_router(ipv6_second) &&
          ipv6_plane->configure_port(ipv6_first, first_ipv6_port) &&
          ipv6_plane->configure_port(ipv6_second, second_ipv6_port) &&
          // This public call streams an atomic address generation through
          // the forwarding-owner boundary. The Echo destination below is
          // deliberately secondary, so retaining only ForwardPort's
          // selected primary cannot accidentally satisfy the test.
          ipv6_plane->program_ipv6_address_generation(ipv6_first,
                                                      first_ipv6_addresses) &&
          ipv6_plane->program_ipv6_address_generation(ipv6_second,
                                                      second_ipv6_addresses) &&
          first_ipv6_rib.rebuild(ipv6_connected,
                                 std::span<const Ipv6StaticInput>{}) &&
          second_ipv6_rib.rebuild(ipv6_connected,
                                  std::span<const Ipv6StaticInput>{}) &&
          ipv6_plane->program_ipv6_fib(ipv6_first, first_ipv6_rib.compile(1)) &&
          ipv6_plane->program_ipv6_fib(ipv6_second, second_ipv6_rib.compile(1)),
      "network plane rejected valid IPv6 interface or FIB projection");
  const LinkHandle ipv6_link{0, 1};
  require(ipv6_plane->configure_link({ipv6_link,
                                      {node(ipv6_first), 0, 1},
                                      {node(ipv6_second), 0, 1},
                                      10'000'000'000ULL,
                                      std::chrono::nanoseconds{100},
                                      true}),
          "network plane rejected IPv6 point-to-point fabric link");
  const auto ipv6_origin = NetworkPlane::Clock::now();
  for (std::size_t turn = 1; turn <= 500; ++turn)
    ipv6_plane->pump(ipv6_origin + std::chrono::milliseconds{turn * 10U});
  const auto ipv6_ping_origin = ipv6_origin + std::chrono::seconds{5};
  require(ipv6_plane->start_router_ipv6_ping(ipv6_first, second_ipv6_secondary,
                                             41, ipv6_ping_origin),
          "network plane did not start encoded IPv6 Echo operation");
  for (std::size_t turn = 1;
       turn <= 40 && !ipv6_plane->router_ipv6_ping_reply(ipv6_first, 41);
       ++turn)
    ipv6_plane->pump(ipv6_ping_origin + std::chrono::microseconds{turn * 10U});
  require(ipv6_plane->router_ipv6_ping_reply(ipv6_first, 41),
          "IPv6 Echo did not cross encoded ND and ICMPv6 fabric traffic");
  router::packet::nd::RouterAdvertisementConfig plane_ra{};
  require(ipv6_plane->configure_router_advertisement({.device = ipv6_first,
                                                      .config = plane_ra,
                                                      .port_ordinal = 0U,
                                                      .enabled = true}) &&
              ipv6_plane->remove_router_advertisement(ipv6_first, 0U),
          "network-plane owner chain rejected explicit RA removal");
  router::dhcpv6::RelayInterfaceConfig relay_program;
  relay_program.interface_id = 7'002U;
  relay_program.link_address = first_ipv6;
  // More than two transport chunks proves that the queue granularity is not
  // exposed as a DHCPv6 Interface-Id length restriction.
  relay_program.relay_interface_id.resize(
      dhcpv6_relay_program_chunk_octets * 2U + 1U);
  for (std::size_t index = 0; index < relay_program.relay_interface_id.size();
       ++index)
    relay_program.relay_interface_id[index] =
        static_cast<std::uint8_t>((index * 37U) & 0xffU);
  relay_program.servers[0].address = second_ipv6;
  relay_program.server_count = 1U;
  relay_program.upstream_policy =
      router::dhcpv6::RelayUpstreamPolicy::explicit_servers_required;
  const std::array sap_generation{router::service::SapAttachment{
      .logical_interface_id = 7'001U,
      .sap = {.port = {.ordinal = 0U, .card = 1U, .mda = 1U, .port = 1U},
              .encapsulation = router::service::EthernetEncapsulation::dot1q,
              .outer_vlan = std::uint16_t{701U}},
      .outer_tpid = 0x8100U}};
  require(ipv6_plane->configure_dhcpv6_relay(ipv6_first, relay_program),
          "network-plane relay transaction exposed its chunk size as a "
          "protocol limit");
  require(ipv6_plane->program_sap_generation(ipv6_first, sap_generation),
          "network-plane SAP generation did not cross the forwarding owner "
          "boundary");
  const auto ipv6_checkpoint = network_checkpoint(*ipv6_plane);
  require(
      ipv6_checkpoint.routers.size() == 2 &&
          !ipv6_checkpoint.routers[0].forwarding.ipv6_neighbors.empty() &&
          !ipv6_checkpoint.routers[1].forwarding.ipv6_neighbors.empty() &&
          ipv6_checkpoint.routers[0]
                  .forwarding.dhcpv6_relay_interfaces.size() == 1U &&
          ipv6_checkpoint.routers[0]
                  .forwarding.dhcpv6_relay_interfaces[0]
                  .relay_interface_id == relay_program.relay_interface_id &&
          ipv6_checkpoint.routers[0].forwarding.sap_attachments ==
              std::vector<router::service::SapAttachment>{
                  sap_generation.begin(), sap_generation.end()} &&
          ipv6_checkpoint.routers[0]
              .forwarding.ipv6_router_advertisements.empty(),
      "network-plane checkpoint omitted forwarding-owned IPv6 or relay state");
  require(ipv6_plane->remove_dhcpv6_relay(ipv6_first, 7'002U),
          "network-plane owner chain rejected relay removal");

  // A router-to-host fixture verifies the complete Router Discovery path. The
  // host has no preinstalled IPv6 prefix, default router or DNS server. Every
  // learned value below must therefore arrive in encoded RS, RA, NS and NA
  // frames through NetworkPlane's ordinary link queues.
  auto slaac_plane = std::make_unique<NetworkPlane>(1);
  const DeviceHandle slaac_router{0, 1};
  const HostHandle slaac_host{0, 1};
  const router::packet::Mac slaac_router_mac{0x02, 0, 0, 0, 0x30, 1};
  const router::packet::Mac slaac_host_mac{0x02, 0, 0, 0, 0x30, 2};
  const auto slaac_router_address = ipv6("2001:db8:30::1");
  ForwardPort slaac_router_port{.configured = true,
                                .operational = true,
                                .ordinal = 0,
                                .mtu = 1'500,
                                .speed_mbps = 10'000,
                                .mac = slaac_router_mac,
                                .ipv6_configured = true,
                                .ipv6_address = slaac_router_address,
                                .ipv6_link_local = ipv6("fe80::30:1"),
                                .ipv6_prefix_length = 64};
  Ipv6RouteTable slaac_rib;
  const std::array slaac_connected{
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = ipv6("2001:db8:30::"),
                         .interface_id = physical_interface_id(0U),
                         .physical_port_ordinal = 0,
                         .prefix_length = 64}};
  router::packet::nd::RouterAdvertisementConfig slaac_ra{};
  slaac_ra.advertised_mtu = 1'500;
  slaac_ra.prefix_count = 1U;
  slaac_ra.prefixes[0] = {
      .prefix = {.network = ipv6("2001:db8:30::"), .length = 64U},
      .valid_lifetime_seconds = 86'400U,
      .preferred_lifetime_seconds = 14'400U,
      .on_link = true,
      .autonomous = true};
  slaac_ra.rdnss.count = 1U;
  slaac_ra.rdnss.servers[0].address = ipv6("2001:db8:30::53");
  router::host::Ipv6InterfaceIdentifierConfiguration slaac_identifier{
      .network_id_octets = 10U,
      .mode = router::host::InterfaceIdentifierMode::stable_opaque};
  for (std::size_t index = 0; index < slaac_identifier.stable_secret.size();
       ++index)
    slaac_identifier.stable_secret[index] =
        static_cast<std::uint8_t>(index + 1U);
  constexpr std::array<std::uint8_t, 10U> slaac_network_id{
      's', 'l', 'a', 'a', 'c', '-', 'l', 'i', 'n', 'k'};
  std::copy(slaac_network_id.begin(), slaac_network_id.end(),
            slaac_identifier.network_id.begin());
  require(
      slaac_plane->add_router(slaac_router) &&
          slaac_plane->add_host(slaac_host) &&
          slaac_plane->configure_port(slaac_router, slaac_router_port) &&
          slaac_rib.rebuild(slaac_connected,
                            std::span<const Ipv6StaticInput>{}) &&
          slaac_plane->program_ipv6_fib(slaac_router, slaac_rib.compile(1)) &&
          slaac_plane->configure_router_advertisement({.device = slaac_router,
                                                       .config = slaac_ra,
                                                       .port_ordinal = 0U,
                                                       .enabled = true}) &&
          slaac_plane->configure_host(
              {.host = slaac_host,
               .mac = slaac_host_mac,
               .address = {192, 0, 2, 2},
               .gateway = {192, 0, 2, 1},
               .prefix_length = 24,
               .mtu = 1'500,
               .interface_id = 1U,
               .ipv6_autoconfiguration = true,
               .ipv6_identifier = slaac_identifier,
               .transport_secret = transport_secret(5U)}),
      "network plane rejected a valid IPv6 SLAAC attachment");
  const LinkHandle slaac_link{0, 1};
  require(slaac_plane->configure_link({slaac_link,
                                       {node(slaac_router), 0, 1},
                                       {node(slaac_host), 0, 1},
                                       10'000'000'000ULL,
                                       std::chrono::nanoseconds{100},
                                       true}),
          "network plane rejected the router-to-host SLAAC link");
  const auto slaac_origin = NetworkPlane::Clock::now();
  for (std::size_t turn = 1; turn <= 3'000; ++turn)
    slaac_plane->pump(slaac_origin + std::chrono::milliseconds{turn * 10U});
  auto slaac_checkpoint =
      std::make_unique<NetworkPlaneCheckpoint>(network_checkpoint(
          *slaac_plane, slaac_origin + std::chrono::seconds{30}));
  require(
      slaac_checkpoint->hosts.size() == 1U &&
          slaac_checkpoint->hosts[0].ipv6_autoconfiguration &&
          slaac_checkpoint->hosts[0].interface_id == 1U &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.addresses.size() == 1U &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.default_routers.size() ==
              1U &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.rdnss.size() == 1U &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.addresses[0]
                  .state == router::host::AutoconfigAddressState::preferred &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.interface_identifier_mode ==
              router::host::InterfaceIdentifierMode::stable_opaque &&
          slaac_checkpoint->hosts[0]
                  .endpoint.ipv6.autoconfiguration.stable_secret ==
              slaac_identifier.stable_secret &&
          !slaac_checkpoint->hosts[0].endpoint.ipv6.mld.groups.empty() &&
          slaac_checkpoint->hosts[0].endpoint.ipv6.mld.random_state != 0U,
      "encoded RA did not create preferred SLAAC, router and RDNSS state");
  const auto slaac_host_address =
      slaac_checkpoint->hosts[0]
          .endpoint.ipv6.autoconfiguration.addresses[0]
          .address;
  const auto slaac_ping_origin = slaac_origin + std::chrono::seconds{31};
  require(slaac_plane->start_router_ipv6_ping(slaac_router, slaac_host_address,
                                              42, slaac_ping_origin),
          "router could not originate IPv6 Echo toward learned SLAAC host");
  for (std::size_t turn = 1;
       turn <= 200 && !slaac_plane->router_ipv6_ping_reply(slaac_router, 42);
       ++turn)
    slaac_plane->pump(slaac_ping_origin +
                      std::chrono::microseconds{turn * 10U});
  require(slaac_plane->router_ipv6_ping_reply(slaac_router, 42),
          "SLAAC host did not answer encoded ND and ICMPv6 traffic");

  // Restoring at a new monotonic origin must retain the learned host state and
  // exact DAD result. No synthetic RA is injected after restoration.
  slaac_checkpoint =
      std::make_unique<NetworkPlaneCheckpoint>(network_checkpoint(
          *slaac_plane, slaac_origin + std::chrono::seconds{32}));
  slaac_plane.reset();
  slaac_plane = std::make_unique<NetworkPlane>(1);
  const auto slaac_restore = NetworkPlane::Clock::now();
  require(slaac_plane->restore(*slaac_checkpoint, slaac_restore) &&
              slaac_plane->start_router_ipv6_ping(
                  slaac_router, slaac_host_address, 43, slaac_restore),
          "restored SLAAC network rejected retained host IPv6 state");
  for (std::size_t turn = 1;
       turn <= 200 && !slaac_plane->router_ipv6_ping_reply(slaac_router, 43);
       ++turn)
    slaac_plane->pump(slaac_restore + std::chrono::microseconds{turn * 10U});
  require(slaac_plane->router_ipv6_ping_reply(slaac_router, 43),
          "restored SLAAC host lost its operational IPv6 packet path");

  // Two hosts deliberately receive the same RFC 7217 tuple. Their different
  // MAC addresses cannot hide the collision because stable opaque generation
  // does not use the MAC-derived IID. Every conflict must be learned from the
  // peer's encoded DAD NS after it traverses the host-to-host fabric link.
  auto collision_plane = std::make_unique<NetworkPlane>(1);
  const HostHandle collision_first{0, 1};
  const HostHandle collision_second{1, 1};
  const auto configure_collision_host = [&](HostHandle handle,
                                            router::packet::Mac mac,
                                            router::packet::Ipv4 address) {
    return collision_plane->add_host(handle) &&
           collision_plane->configure_host(
               {.host = handle,
                .mac = mac,
                .address = address,
                .gateway = {},
                .prefix_length = 24,
                .mtu = 1'500,
                .interface_id = 99U,
                .ipv6_autoconfiguration = true,
                .ipv6_identifier = slaac_identifier,
                .transport_secret = transport_secret(
                    static_cast<std::uint8_t>(handle.index + 6U))});
  };
  require(configure_collision_host(collision_first, {0x02, 0, 0, 0, 0x40, 1},
                                   {192, 0, 2, 1}) &&
              configure_collision_host(
                  collision_second, {0x02, 0, 0, 0, 0x40, 2}, {192, 0, 2, 2}) &&
              collision_plane->configure_link({{0, 1},
                                               {node(collision_first), 0, 1},
                                               {node(collision_second), 0, 1},
                                               10'000'000'000ULL,
                                               std::chrono::nanoseconds{100},
                                               true}),
          "network plane rejected the stable-IID collision fixture");
  // RFC 4862 deliberately randomizes the first DAD transmission. The fixture
  // tests RFC 7217 collision retry exhaustion, not that unrelated random
  // spread, so normalize only the two already-created local deadlines through
  // the production checkpoint contract. Both endpoints will then emit real
  // encoded NS frames on the same owner turn. Every later regenerated address
  // receives the same IDGEN_DELAY because both peers process those frames at
  // the same monotonic instant. Direct conflict injection would hide the link,
  // packet codec and receive-path behavior that this integration test exists
  // to verify.
  const auto collision_seed_time = NetworkPlane::Clock::now();
  auto collision_seed =
      network_checkpoint(*collision_plane, collision_seed_time);
  require(collision_seed.hosts.size() == 2U,
          "collision fixture could not checkpoint both hosts");
  for (auto &host : collision_seed.hosts) {
    require(host.endpoint.ipv6.dad.size() == 1U &&
                host.endpoint.ipv6.dad[0].state == Ipv6DadState::tentative,
            "collision fixture did not begin with tentative link-local DAD");
    host.endpoint.ipv6.dad[0].has_deadline = true;
    host.endpoint.ipv6.dad[0].remaining_nanoseconds = 0;
  }
  collision_plane.reset();
  collision_plane = std::make_unique<NetworkPlane>(1);
  const auto collision_origin = NetworkPlane::Clock::now();
  require(collision_plane->restore(collision_seed, collision_origin),
          "collision fixture rejected synchronized DAD deadlines");
  // Every regenerated stable address first observes IDGEN_DELAY and then the
  // RFC 4862 DAD quiet interval. Derive the fixture horizon from the generated
  // retry count instead of assuming that all retries fit an unrelated six
  // second literal. The extra interval covers the initial address generation
  // and one link-delivery turn at the 10 ms test cadence.
  const auto collision_horizon = std::chrono::seconds{
      2U * (router::device_catalog::ipv6_stable_iid_dad_retries + 1U)};
  const auto collision_turns = static_cast<std::size_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(collision_horizon)
          .count() /
      10);
  for (std::size_t turn = 1; turn <= collision_turns; ++turn)
    collision_plane->pump(collision_origin +
                          std::chrono::milliseconds{turn * 10U});
  auto collision_checkpoint = network_checkpoint(
      *collision_plane, collision_origin + collision_horizon);
  require(collision_checkpoint.hosts.size() == 2U,
          "collision fixture lost a host checkpoint");
  for (const auto &host : collision_checkpoint.hosts) {
    require(host.endpoint.ipv6.link_local_dad_counter ==
                    router::device_catalog::ipv6_stable_iid_dad_retries &&
                host.endpoint.ipv6.dad.size() == 1U &&
                host.endpoint.ipv6.dad[0].state == Ipv6DadState::duplicate,
            "stable link-local DAD did not exhaust the generated RFC 7217 "
            "retry bound");
  }
  require(collision_checkpoint.hosts[0].endpoint.ipv6.dad[0].address ==
              collision_checkpoint.hosts[1].endpoint.ipv6.dad[0].address,
          "equal RFC 7217 tuples did not remain equal across DAD counters");

  // Checkpoint replacement must not silently restart at counter zero. Such a
  // reset would make a repeatedly colliding address oscillate forever after
  // each project save and reload.
  collision_plane.reset();
  collision_plane = std::make_unique<NetworkPlane>(1);
  const auto collision_restore = NetworkPlane::Clock::now();
  require(collision_plane->restore(collision_checkpoint, collision_restore),
          "checkpoint rejected an exhausted stable link-local DAD tuple");
  const auto restored_collision =
      network_checkpoint(*collision_plane, collision_restore);
  require(
      restored_collision.hosts.size() == 2U &&
          restored_collision.hosts[0].endpoint.ipv6.link_local_dad_counter ==
              router::device_catalog::ipv6_stable_iid_dad_retries &&
          restored_collision.hosts[1].endpoint.ipv6.link_local_dad_counter ==
              router::device_catalog::ipv6_stable_iid_dad_retries,
      "checkpoint restore reset the stable link-local DAD counter");

  // DNS configuration crosses the same value-only SPSC command path used by
  // other host services. The query then traverses ARP, IPv4, UDP and Ethernet;
  // no test callback can invoke the authoritative owner directly.
  auto dns_plane = std::make_unique<NetworkPlane>(4);
  const HostHandle dns_client{0U, 1U};
  const HostHandle dns_server{1U, 1U};
  const auto configure_dns_host = [&](HostHandle handle, packet::Mac mac,
                                      packet::Ipv4 address,
                                      std::uint8_t secret_seed) {
    return dns_plane->add_host(handle) &&
           dns_plane->configure_host(
               {.host = handle,
                .mac = mac,
                .address = address,
                .gateway = {},
                .prefix_length = 24U,
                .mtu = 1500U,
                .interface_id = 5300U + handle.index,
                .ipv6_autoconfiguration = false,
                .ipv6_identifier = {},
                .transport_secret = transport_secret(secret_seed)});
  };
  require(configure_dns_host(dns_client, {0x02U, 0U, 0U, 0U, 0x53U, 1U},
                             {192U, 0U, 2U, 10U}, 20U) &&
              configure_dns_host(dns_server, {0x02U, 0U, 0U, 0U, 0x53U, 2U},
                                 {192U, 0U, 2U, 53U}, 21U) &&
              dns_plane->configure_link({{0U, 1U},
                                         {node(dns_client), 0U, 1U},
                                         {node(dns_server), 0U, 1U},
                                         10'000'000'000ULL,
                                         std::chrono::nanoseconds{100},
                                         true}),
          "network plane rejected DNS host topology");

  auto soa = dns_name_data("ns.test.");
  const auto mailbox = dns_name_data("hostmaster.test.");
  soa.insert(soa.end(), mailbox.begin(), mailbox.end());
  append_dns_u32(soa, 1U);
  append_dns_u32(soa, 3600U);
  append_dns_u32(soa, 600U);
  append_dns_u32(soa, 86400U);
  append_dns_u32(soa, 60U);
  HostDnsAuthoritativeProgram authoritative{
      .host = dns_server,
      .zones = {{.origin = dns_name("test."),
                 .records = {{.owner = dns_name("test."),
                              .type = packet::dns::type_soa,
                              .record_class = packet::dns::internet_class,
                              .ttl = 300U,
                              .rdata = soa},
                             {.owner = dns_name("test."),
                              .type = packet::dns::type_ns,
                              .record_class = packet::dns::internet_class,
                              .ttl = 300U,
                              .rdata = dns_name_data("ns.test.")},
                             {.owner = dns_name("ns.test."),
                              .type = packet::dns::type_a,
                              .record_class = packet::dns::internet_class,
                              .ttl = 300U,
                              .rdata = {192U, 0U, 2U, 53U}},
                             {.owner = dns_name("www.test."),
                              .type = packet::dns::type_a,
                              .record_class = packet::dns::internet_class,
                              .ttl = 60U,
                              .rdata = {198U, 51U, 100U, 7U}}}}}};
  require(
      dns_plane->configure_host_dns_authoritative(authoritative) &&
          dns_plane->configure_host_dns_resolver(
              {.host = dns_client,
               .identifier_secret = transport_secret(22U),
               .root_hints = {{.server_name = dns_name("ns.test."),
                               .addresses = {{.family =
                                                  transport::IpFamily::ipv4,
                                              .ipv4 = {192U, 0U, 2U, 53U}}}}},
               .trust_anchors = {},
               .nsec3_policy = {},
               .serve_clients = false}),
      "network plane rejected staged DNS service configuration");
  const auto dns_origin = NetworkPlane::Clock::now();
  const auto dns_transaction = dns_plane->start_host_dns_query(
      dns_client,
      {.name = dns_name("www.test."),
       .type = packet::dns::type_a,
       .record_class = packet::dns::internet_class},
      dns_origin);
  require(dns_transaction.has_value(),
          "network plane did not start DNS transaction");
  std::optional<dns::ResolutionResult> dns_result;
  for (std::size_t turn = 1U; turn <= 500U && !dns_result; ++turn) {
    dns_plane->pump(dns_origin + std::chrono::microseconds{turn * 10U});
    dns_result = dns_plane->host_dns_result(dns_client, *dns_transaction);
  }
  require(dns_result && dns_result->status == dns::ResolutionStatus::success &&
              dns_result->answers.size() == 1U &&
              dns_result->answers.front().rdata ==
                  std::vector<std::uint8_t>({198U, 51U, 100U, 7U}),
          "network-plane DNS query bypassed or failed encoded packet path");
  // Managed signing uses the same streamed zone-record transaction but key
  // requests are values only. Provider-generated private keys are created on
  // the DNS owner and the checkpoint can leave that owner only as AEAD-sealed
  // ciphertext bound to this project digest.
  std::array<std::uint8_t, 32U> dnssec_vault_key{};
  dnssec_vault_key.fill(0xa6U);
  const auto dnssec_context = transport_secret(0x41U);
  const auto dnssec_wall_now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  const dnssec::KeySchedule dnssec_schedule{
      .publish_at = dnssec_wall_now - 100U,
      .ready_at = dnssec_wall_now - 100U,
      .activate_at = dnssec_wall_now - 100U,
      .retire_at = dnssec_wall_now + 5000U,
      .dead_at = dnssec_wall_now + 5100U,
      .remove_at = dnssec_wall_now + 5200U};
  const std::vector<HostDnsSigningKeyProgram> signing_keys{
      {.schedule = dnssec_schedule,
       .generation = {},
       .role = dnssec::KeyRole::key_signing,
       .algorithm = 15U},
      {.schedule = dnssec_schedule,
       .generation = {},
       .role = dnssec::KeyRole::zone_signing,
       .algorithm = 15U}};
  require(
      dns_plane->initialize_signing_vault(dnssec_vault_key, dnssec_context) &&
          dns_plane->configure_host_dns_signed_authoritative(
              {.host = dns_server,
               .zones = {{.zone = authoritative.zones.front(),
                          .keys = signing_keys,
                          .policy = {.dnskey_ttl = 300U,
                                     .denial_ttl = 60U,
                                     .denial_mode = dnssec::DenialMode::nsec,
                                     .timing = {.validity_seconds = 3600U,
                                                .refresh_seconds = 1200U,
                                                .resign_seconds = 600U,
                                                .inception_offset_seconds =
                                                    60U}}}},
               .wall_now = dnssec_wall_now}),
      "network plane rejected streamed managed DNSSEC configuration");
  const auto dns_checkpoint =
      network_checkpoint(*dns_plane, dns_origin + std::chrono::milliseconds{6});
  require(dns_checkpoint.hosts.size() == 2U &&
              std::count_if(
                  dns_checkpoint.hosts.begin(), dns_checkpoint.hosts.end(),
                  [](const auto &host) { return host.dns.has_value(); }) == 2,
          "network-plane checkpoint omitted DNS service owners");
  const auto signed_service =
      std::find_if(dns_checkpoint.hosts.begin(), dns_checkpoint.hosts.end(),
                   [&](const auto &host) { return host.host == dns_server; });
  require(signed_service != dns_checkpoint.hosts.end() && signed_service->dns &&
              signed_service->dns->zones.empty() &&
              signed_service->dns->signed_zones.size() == 1U,
          "network-plane checkpoint downgraded managed DNSSEC state");
  dns_plane.reset();
  dns_plane = std::make_unique<NetworkPlane>(4);
  require(
      dns_plane->initialize_signing_vault(dnssec_vault_key, dnssec_context) &&
          dns_plane->restore(dns_checkpoint, NetworkPlane::Clock::now()),
      "network-plane restore rejected DNS service checkpoint");

  // Three independent host links meet only inside the bridge. Successful ARP
  // resolution proves broadcast replication crossed encoded Ethernet frames
  // and did not consult the editor topology or call a peer endpoint directly.
  auto switch_plane = std::make_unique<NetworkPlane>(1);
  const SwitchHandle bridge{0U, 1U};
  const auto bridge_profile =
      device_catalog::ethernet_switch_profile_index("generic-ethernet-24");
  const std::array<HostHandle, 3> bridge_hosts{
      HostHandle{0U, 1U}, HostHandle{1U, 1U}, HostHandle{2U, 1U}};
  const std::array<packet::Mac, 3> bridge_macs{
      packet::Mac{0x02U, 0U, 0U, 0U, 0x30U, 1U},
      packet::Mac{0x02U, 0U, 0U, 0U, 0x30U, 2U},
      packet::Mac{0x02U, 0U, 0U, 0U, 0x30U, 3U}};
  require(bridge_profile &&
              switch_plane->add_switch(bridge, *bridge_profile),
          "network plane rejected generated Ethernet switch profile");
  for (std::size_t index{}; index < bridge_hosts.size(); ++index) {
    const auto last = static_cast<std::uint8_t>(index + 1U);
    require(
        switch_plane->add_host(bridge_hosts[index]) &&
            switch_plane->configure_host(
                {.host = bridge_hosts[index],
                 .mac = bridge_macs[index],
                 .address = {198U, 51U, 100U, last},
                 .gateway = {},
                 .prefix_length = 29U,
                 .mtu = 1500U,
                 .transport_secret =
                     transport_secret(static_cast<std::uint8_t>(40U + index))}),
        "network plane rejected a broadcast-domain host");
    require(
        switch_plane->configure_link(
            {{static_cast<std::uint16_t>(index), 1U},
             {node(bridge_hosts[index]), 0U, 1U},
             {node(bridge), static_cast<std::uint16_t>(index), 1U},
             10'000'000'000ULL,
             std::chrono::nanoseconds{100},
             true}),
        "network plane rejected a switch access link");
  }
  const auto bridge_origin = NetworkPlane::Clock::now();
  require(switch_plane->start_host_ping(
              bridge_hosts.front(), {198U, 51U, 100U, 3U}, 71U),
          "broadcast-domain host did not originate ping");
  for (std::size_t turn = 1U;
       turn <= 100U &&
       !switch_plane->host_ping_reply(bridge_hosts.front(), 71U);
       ++turn)
    switch_plane->pump(bridge_origin +
                       std::chrono::microseconds{turn * 10U});
  require(switch_plane->host_ping_reply(bridge_hosts.front(), 71U),
          "learning bridge did not carry encoded ARP and ICMP traffic");
  const auto bridge_checkpoint = network_checkpoint(
      *switch_plane, bridge_origin + std::chrono::milliseconds{2});
  require(bridge_checkpoint.switches.size() == 1U &&
              bridge_checkpoint.fabric.links.size() == 3U &&
              bridge_checkpoint.switches.front().forwarding.fdb.size() >= 2U,
          "network checkpoint omitted bridge identity, links or learned FDB");
  switch_plane.reset();
  switch_plane = std::make_unique<NetworkPlane>(1);
  const auto bridge_restore = NetworkPlane::Clock::now();
  require(switch_plane->restore(bridge_checkpoint, bridge_restore) &&
              switch_plane->start_host_ping(
                  bridge_hosts[1], {198U, 51U, 100U, 1U}, 72U),
          "restored bridge could not resume host traffic");
  for (std::size_t turn = 1U;
       turn <= 100U &&
       !switch_plane->host_ping_reply(bridge_hosts[1], 72U);
       ++turn)
    switch_plane->pump(bridge_restore +
                       std::chrono::microseconds{turn * 10U});
  require(switch_plane->host_ping_reply(bridge_hosts[1], 72U),
          "restored bridge did not retain a valid packet path");
}
