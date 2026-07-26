// OSPFv3 IPv4 and IPv6 address-family and database-reset cases.
// Each process owns its routes and consumes only encoded protocol packets.

#include "ospf_process_test_support.hpp"

void ospf_process_address_family_tests() {
  using namespace router;
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  std::array<ProcessOutput, 2U> output{};
  std::size_t written{};
  // RFC 5838 uses IPv6 only for the OSPFv3 control transport. The IPv4
  // unicast AF must derive the forwarding next hop from the first 32 bits of
  // the peer's Link-LSA and publish an ordinary IPv4 RIB candidate. This
  // second exchange proves that behavior between isolated process owners
  // using only encoded OSPFv3 packets.
  InstanceProcess first_ipv4_af{
      0x03030303U, 0U, router::packet::ospf::version_three,
      router::device_catalog::ospf_v3_ipv4_instance_first, 0x60708090U, 4U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess second_ipv4_af{
      0x04040404U, 0U, router::packet::ospf::version_three,
      router::device_catalog::ospf_v3_ipv4_instance_first, 0x708090a0U, 4U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto first_ipv4_af_link =
      ipv4_af_interface_configuration(0x03030303U, 0xc0000201U, 3U, 0U);
  auto second_ipv4_af_link =
      ipv4_af_interface_configuration(0x04040404U, 0xc0000202U, 4U, 0U);
  auto first_ipv4_af_system =
      ipv4_af_interface_configuration(0x03030303U, 0xcb007101U, 3U, 1U);
  first_ipv4_af_system.protocol.interface_id = 2U;
  first_ipv4_af_system.protocol.passive = true;
  first_ipv4_af_system.physical_port_ordinal = no_physical_port;
  first_ipv4_af_system.prefix_length = 32U;
  first_ipv4_af_system.metric = 0U;
  auto second_ipv4_af_system =
      ipv4_af_interface_configuration(0x04040404U, 0xcb007102U, 4U, 1U);
  second_ipv4_af_system.protocol.interface_id = 2U;
  second_ipv4_af_system.protocol.passive = true;
  second_ipv4_af_system.physical_port_ordinal = no_physical_port;
  second_ipv4_af_system.prefix_length = 32U;
  second_ipv4_af_system.metric = 0U;
  require(first_ipv4_af.add_interface(first_ipv4_af_link, now) &&
              second_ipv4_af.add_interface(second_ipv4_af_link, now) &&
              first_ipv4_af.add_interface(first_ipv4_af_system, now) &&
              second_ipv4_af.add_interface(second_ipv4_af_system, now),
          "OSPFv3 IPv4-AF rejected valid process interfaces");

  // Exchange the immediately scheduled startup Hellos before advancing to
  // the next periodic deadline. The second Hello then contains the first
  // router in its neighbor list, exactly as it would on a live point-to-point
  // link, and both owners can proceed from Init to ExStart.
  deliver_ready_v3(first_ipv4_af, second_ipv4_af, 0x03030303U, now);
  deliver_ready_v3(second_ipv4_af, first_ipv4_af, 0x04040404U, now);
  const auto ipv4_af_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (first_ipv4_af.neighbor_state(1U, 0x04040404U) !=
            NeighborState::full ||
        second_ipv4_af.neighbor_state(1U, 0x03030303U) !=
            NeighborState::full);
       ++turn) {
    deliver_ready_v3(first_ipv4_af, second_ipv4_af, 0x03030303U,
                     ipv4_af_convergence);
    deliver_ready_v3(second_ipv4_af, first_ipv4_af, 0x04040404U,
                     ipv4_af_convergence);
  }
  const auto first_ipv4_af_state =
      first_ipv4_af.neighbor_state(1U, 0x04040404U);
  const auto second_ipv4_af_state =
      second_ipv4_af.neighbor_state(1U, 0x03030303U);
  if (first_ipv4_af_state != NeighborState::full ||
      second_ipv4_af_state != NeighborState::full)
    throw std::runtime_error(
        "OSPFv3 IPv4-AF database exchange did not reach Full; first=" +
        std::to_string(first_ipv4_af_state
                           ? static_cast<unsigned>(*first_ipv4_af_state)
                           : 255U) +
        " second=" +
        std::to_string(second_ipv4_af_state
                           ? static_cast<unsigned>(*second_ipv4_af_state)
                           : 255U) +
        " first-lsdb=" +
        std::to_string(first_ipv4_af.database().records().size()) +
        " second-lsdb=" +
        std::to_string(second_ipv4_af.database().records().size()));
  deliver_ready_v3(first_ipv4_af, second_ipv4_af, 0x03030303U,
                   ipv4_af_convergence);
  deliver_ready_v3(second_ipv4_af, first_ipv4_af, 0x04040404U,
                   ipv4_af_convergence);

  const auto ipv4_af_spf =
      ipv4_af_convergence +
      router::device_catalog::ospf_spf_initial_wait +
      router::device_catalog::ospf_spf_second_wait;
  require(first_ipv4_af.run_ready(ipv4_af_spf, output, written) &&
              second_ipv4_af.run_ready(ipv4_af_spf, output, written),
          "OSPFv3 IPv4-AF rejected its sourced SPF deadline");
  const auto learned_ipv4_af = std::find_if(
      first_ipv4_af.ipv4_route_inputs().begin(),
      first_ipv4_af.ipv4_route_inputs().end(), [](const auto &route) {
        return route.network == 0xcb007102U && route.prefix_length == 32U;
      });
  require(learned_ipv4_af != first_ipv4_af.ipv4_route_inputs().end() &&
              learned_ipv4_af->source ==
                  router::lab::routing::RouteSource::ospf3 &&
              learned_ipv4_af->next_hop == 0xc0000202U &&
              learned_ipv4_af->port_ordinal == 0U,
          "OSPFv3 IPv4-AF did not publish its Link-LSA IPv4 next hop");

  // RFC 5340 keeps its 32-bit Interface ID on the protocol wire, while the
  // forwarding plane uses a separate 64-bit identity to scope ND and
  // link-local next hops. A complete encoded exchange must therefore publish
  // the peer prefix with the physical forwarding identity, never the wire ID.
  InstanceProcess first_ipv6{
      0x05050505U, 0U, router::packet::ospf::version_three,
      router::device_catalog::ospf_v3_ipv6_instance_first, 0x8090a0b0U, 4U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess second_ipv6{
      0x06060606U, 0U, router::packet::ospf::version_three,
      router::device_catalog::ospf_v3_ipv6_instance_first, 0x90a0b0c0U, 4U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  router::ip::Ipv6 first_link_prefix{
      {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 1U}};
  router::ip::Ipv6 second_link_prefix = first_link_prefix;
  auto first_ipv6_link = ipv6_interface_configuration(
      0x05050505U, first_link_prefix, 5U, 0U);
  auto second_ipv6_link = ipv6_interface_configuration(
      0x06060606U, second_link_prefix, 6U, 0U);
  router::ip::Ipv6 first_edge_prefix{
      {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 1U}};
  router::ip::Ipv6 second_edge_prefix{
      {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 2U}};
  auto first_ipv6_edge = ipv6_interface_configuration(
      0x05050505U, first_edge_prefix, 5U, 1U);
  first_ipv6_edge.protocol.interface_id = 2U;
  first_ipv6_edge.protocol.passive = true;
  first_ipv6_edge.physical_port_ordinal = no_physical_port;
  auto second_ipv6_edge = ipv6_interface_configuration(
      0x06060606U, second_edge_prefix, 6U, 1U);
  second_ipv6_edge.protocol.interface_id = 2U;
  second_ipv6_edge.protocol.passive = true;
  second_ipv6_edge.physical_port_ordinal = no_physical_port;
  require(first_ipv6.add_interface(first_ipv6_link, now) &&
              second_ipv6.add_interface(second_ipv6_link, now) &&
              first_ipv6.add_interface(first_ipv6_edge, now) &&
              second_ipv6.add_interface(second_ipv6_edge, now),
          "OSPFv3 IPv6 rejected valid process interfaces");
  deliver_ready_v3(first_ipv6, second_ipv6, 0x05050505U, now);
  deliver_ready_v3(second_ipv6, first_ipv6, 0x06060606U, now);
  const auto ipv6_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (first_ipv6.neighbor_state(1U, 0x06060606U) != NeighborState::full ||
        second_ipv6.neighbor_state(1U, 0x05050505U) != NeighborState::full);
       ++turn) {
    deliver_ready_v3(first_ipv6, second_ipv6, 0x05050505U,
                     ipv6_convergence);
    deliver_ready_v3(second_ipv6, first_ipv6, 0x06060606U,
                     ipv6_convergence);
  }
  require(first_ipv6.neighbor_state(1U, 0x06060606U) ==
                  NeighborState::full &&
              second_ipv6.neighbor_state(1U, 0x05050505U) ==
                  NeighborState::full,
          "OSPFv3 IPv6 database exchange did not reach Full");
  deliver_ready_v3(first_ipv6, second_ipv6, 0x05050505U, ipv6_convergence);
  deliver_ready_v3(second_ipv6, first_ipv6, 0x06060606U, ipv6_convergence);
  const auto ipv6_spf =
      ipv6_convergence + router::device_catalog::ospf_spf_initial_wait +
      router::device_catalog::ospf_spf_second_wait;
  require(first_ipv6.run_ready(ipv6_spf, output, written) &&
              second_ipv6.run_ready(ipv6_spf, output, written),
          "OSPFv3 IPv6 rejected its sourced SPF deadline");
  const auto learned_ipv6 = std::find_if(
      first_ipv6.ipv6_route_inputs().begin(),
      first_ipv6.ipv6_route_inputs().end(), [&](const auto &route) {
        return route.network == second_edge_prefix &&
               route.prefix_length == 64U;
      });
  require(learned_ipv6 != first_ipv6.ipv6_route_inputs().end() &&
              learned_ipv6->source ==
                  router::lab::routing::RouteSource::ospf3 &&
              learned_ipv6->next_hop == second_ipv6_link.ipv6_source &&
              learned_ipv6->interface_id ==
                  router::lab::physical_interface_id(0U) &&
              learned_ipv6->physical_port_ordinal == 0U,
          "OSPFv3 IPv6 did not preserve the scoped link-local next hop");

  // Operational clear commands must enter through the protocol owner instead
  // of editing an operational projection. Killing one selected neighbor uses
  // the normal FSM transition, which also empties exchange and retransmission
  // state. A repeated clear reports zero affected rows instead of pretending
  // that a nonexistent adjacency changed.
  require(first_ipv4_af.reset_neighbors(
              1U, 0x04040404U, ipv4_af_spf) == 1U &&
              !first_ipv4_af.neighbor_state(1U, 0x04040404U) &&
              first_ipv4_af.reset_neighbors(
                  1U, 0x04040404U, ipv4_af_spf) == 0U,
          "OSPF neighbor reset bypassed the owner-local FSM");

  // A database reset retains self-originated state and removes learned state.
  // The local Router, Link and Intra-Area-Prefix LSAs are needed to restart
  // synchronization without manufacturing a second protocol instance.
  const auto local_before_reset = static_cast<std::size_t>(std::count_if(
      second_ipv4_af.database().records().begin(),
      second_ipv4_af.database().records().end(),
      [](const auto &record) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_three);
        return header && header->advertising_router == 0x04040404U;
      }));
  require(local_before_reset != 0U &&
              second_ipv4_af.reset_database(ipv4_af_spf),
          "OSPF database reset rejected a valid owner generation");
  require(std::all_of(
              second_ipv4_af.database().records().begin(),
              second_ipv4_af.database().records().end(),
              [](const auto &record) {
                const auto header = router::packet::ospf::lsa_header(
                    record.bytes, router::packet::ospf::version_three);
                return header &&
                       header->advertising_router == 0x04040404U;
              }),
          "OSPF database reset retained a received LSA");

}
