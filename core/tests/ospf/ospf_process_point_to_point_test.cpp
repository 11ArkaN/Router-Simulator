// OSPF point-to-point adjacency, virtual-link and sequence-wrap cases.
// Each process owns its LSDB and exchanges only encoded protocol packets.

#include "ospf_process_test_support.hpp"

void ospf_process_point_to_point_tests() {
  using namespace router;
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  InstanceProcess first{
      0x01010101U, 0U, router::packet::ospf::version_two, 0U,
      0x10203040U, 4U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess second{
      0x02020202U, 0U, router::packet::ospf::version_two, 0U,
      0x50607080U, 4U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  first.set_route_preferences(15U, 160U);
  require(first.add_interface(
              interface_configuration(0x01010101U, 0xc0000201U, 0U), now) &&
              second.add_interface(
                  interface_configuration(0x02020202U, 0xc0000202U, 0U), now),
          "OSPF process rejected valid generated-profile interfaces");
  auto first_system =
      interface_configuration(0x01010101U, 0xc6336401U, 1U);
  first_system.protocol.interface_id = 2U;
  first_system.protocol.passive = true;
  first_system.physical_port_ordinal = no_physical_port;
  first_system.prefix_length = 32U;
  first_system.metric = 0U;
  auto second_system =
      interface_configuration(0x02020202U, 0xc6336402U, 1U);
  second_system.protocol.interface_id = 2U;
  second_system.protocol.passive = true;
  second_system.physical_port_ordinal = no_physical_port;
  second_system.prefix_length = 32U;
  second_system.metric = 0U;
  require(first.add_interface(first_system, now) &&
              second.add_interface(second_system, now),
          "OSPF process rejected valid passive system interfaces");

  std::array<ProcessOutput, 2U> output{};
  std::size_t written{};
  require(first.run_ready(now, output, written) && written == 1U,
          "first OSPF owner did not originate its scheduled Hello");
  const auto first_packet = router::packet::ospf::parse_packet(
      std::span<const std::uint8_t>{output[0].bytes}.first(output[0].size));
  require(first_packet &&
              router::packet::ospf::verify_version_two_checksum(*first_packet),
          "OSPF process emitted a malformed version 2 Hello");
  require(second.receive_ipv4_packet(
              1U,
              std::span<const std::uint8_t>{output[0].bytes}.first(
                  output[0].size),
              {{192U, 0U, 2U, 1U}},
              router::packet::ospf::all_spf_routers_v4,
              now) == ReceiveStatus::accepted,
          "second OSPF owner rejected an on-wire compatible Hello");

  require(second.run_ready(now, output, written) && written == 1U &&
              first.receive_ipv4_packet(
                  1U,
                  std::span<const std::uint8_t>{output[0].bytes}.first(
                      output[0].size),
                  {{192U, 0U, 2U, 2U}},
                  router::packet::ospf::all_spf_routers_v4,
                  now) == ReceiveStatus::accepted,
          "two-way Hello exchange did not traverse encoded packets");
  // Two-way reception schedules ExStart immediately. The earliest deadline
  // must therefore be ready now even though the periodic Hello itself moved
  // to its configured future interval.
  require(first.next_deadline().has_value() &&
              *first.next_deadline() <= now,
          "two-way Hello did not schedule immediate database exchange");

  // Drive only packets that each owner has scheduled at the same monotonic
  // instant. The bounded loop is a test watchdog derived from the production
  // work budget, not a protocol timer or convergence shortcut.
  const auto convergence_now =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (first.neighbor_state(1U, 0x02020202U) != NeighborState::full ||
        second.neighbor_state(1U, 0x01010101U) != NeighborState::full);
       ++turn) {
    deliver_ready(first, second, {{192U, 0U, 2U, 1U}}, convergence_now);
    deliver_ready(second, first, {{192U, 0U, 2U, 2U}}, convergence_now);
  }
  require(first.neighbor_state(1U, 0x02020202U) == NeighborState::full &&
              second.neighbor_state(1U, 0x01010101U) ==
                  NeighborState::full,
          "empty LSDB exchange did not converge both neighbors to Full");
  // Full changes each router's own point-to-point Router-LSA. Give both
  // owners their already-ready turn and deliver those newer LSAs through the
  // same packet path before evaluating the SPF throttle.
  deliver_ready(first, second, {{192U, 0U, 2U, 1U}}, convergence_now);
  deliver_ready(second, first, {{192U, 0U, 2U, 2U}}, convergence_now);

  // SPF is delayed by the release-profile throttle, never accelerated by the
  // test. Running each owner at the real configured deadline must publish the
  // remote subnet derived from its own synchronized LSDB.
  const auto spf_now =
      convergence_now + router::device_catalog::ospf_spf_initial_wait +
      router::device_catalog::ospf_spf_second_wait;
  require(first.run_ready(spf_now, output, written) &&
              second.run_ready(spf_now, output, written),
          "OSPF process rejected its sourced SPF deadline");
  const auto virtual_transport =
      first.resolve_virtual_link(0x02020202U);
  require(virtual_transport &&
              virtual_transport->remote_address_known &&
              virtual_transport->cost == 10U &&
              virtual_transport->physical_port_ordinal == 0U &&
              virtual_transport->local_address.bytes[0U] == 192U &&
              virtual_transport->local_address.bytes[3U] == 1U &&
              virtual_transport->remote_address.bytes[0U] == 192U &&
              virtual_transport->remote_address.bytes[3U] == 2U,
          "transit SPF did not derive the OSPFv2 virtual-link transport");

  // The backbone process owns a logical interface but emits through the real
  // transit-area port selected above. RFC 2328 limits TTL 1 only to link-local
  // multicast. A virtual Hello is routed unicast and must retain the
  // release-profile host TTL so the transit path may contain multiple hops.
  InstanceProcess virtual_backbone{
      0x01010101U, 0U, router::packet::ospf::version_two, 0U,
      0x30405060U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  ProcessInterfaceConfiguration virtual_interface{
      .protocol =
          {.router_id = 0x01010101U,
           .area_id = 0U,
           .interface_id = 99U,
           .network_mask = 0U,
           .options =
               router::packet::ospf::option_external_routing_capability,
           .hello_interval_seconds = 10U,
           .dead_interval_seconds = 40U,
           .interface_mtu = 576U,
           .version = router::packet::ospf::version_two,
           .network_type = NetworkType::virtual_link,
           .enabled = true},
      .ipv4_source = {{192U, 0U, 2U, 1U}},
      .source_mac = {{0x02U, 0U, 0U, 0U, 1U, 1U}},
      .physical_port_ordinal = 0U,
      .metric = 10U,
      .retransmit_interval_seconds = 5U,
      .transmit_delay_seconds = 1U,
      .virtual_neighbor_router_id = 0x02020202U,
      .virtual_neighbor_address =
          {.family = router::ip::AddressFamily::ipv4,
           .bytes = {{192U, 0U, 2U, 2U}}}};
  std::array<ProcessOutput, 2U> virtual_output{};
  std::size_t virtual_written{};
  require(
      virtual_backbone.replace_virtual_interface(virtual_interface, now) &&
          virtual_backbone.run_ready(now, virtual_output, virtual_written),
      "backbone owner rejected the resolved virtual interface");
  const auto virtual_hello = std::find_if(
      virtual_output.begin(), virtual_output.begin() + virtual_written,
      [](const auto &candidate) {
        const auto decoded = router::packet::ospf::parse_packet(
            std::span<const std::uint8_t>{candidate.bytes}.first(
                candidate.size));
        return decoded &&
               decoded->type == router::packet::ospf::PacketType::hello;
      });
  require(virtual_hello !=
                  virtual_output.begin() + virtual_written &&
              virtual_hello->destination ==
                  PacketDestination::neighbor_unicast &&
              virtual_hello->hop_limit ==
                  router::device_catalog::default_ip_hop_limit &&
              virtual_hello->ipv4_destination ==
                  router::ip::Ipv4{192U, 0U, 2U, 2U},
          "virtual Hello did not use routed unicast envelope semantics");

  // Two virtual interfaces must form an ordinary point-to-point adjacency
  // through repeated encoded unicast packets. Replacing an unchanged derived
  // transport generation between Hello intervals models the ABR coordinator
  // revisiting stable SPF output. It must preserve the neighbor FSM rather
  // than recreating the logical interface and returning it to Down.
  InstanceProcess remote_virtual_backbone{
      0x02020202U, 0U, router::packet::ospf::version_two, 0U,
      0x40506070U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto remote_virtual_interface = virtual_interface;
  remote_virtual_interface.protocol.router_id = 0x02020202U;
  remote_virtual_interface.ipv4_source = {{192U, 0U, 2U, 2U}};
  remote_virtual_interface.source_mac =
      {{0x02U, 0U, 0U, 0U, 2U, 2U}};
  remote_virtual_interface.virtual_neighbor_router_id = 0x01010101U;
  remote_virtual_interface.virtual_neighbor_address.bytes =
      {{192U, 0U, 2U, 1U}};
  require(remote_virtual_backbone.replace_virtual_interface(
              remote_virtual_interface, now),
          "remote backbone owner rejected its virtual interface");
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (virtual_backbone.neighbor_state(99U, 0x02020202U) !=
            NeighborState::full ||
        remote_virtual_backbone.neighbor_state(99U, 0x01010101U) !=
            NeighborState::full);
       ++turn) {
    const auto virtual_now =
        now + router::device_catalog::ospf_hello_interval *
                  static_cast<std::int64_t>(turn + 1U);
    require(virtual_backbone.replace_virtual_interface(
                virtual_interface, virtual_now) &&
                remote_virtual_backbone.replace_virtual_interface(
                    remote_virtual_interface, virtual_now),
            "stable virtual transport replacement reset the adjacency");
    const auto [saw_virtual_hello, advertised_remote] =
        deliver_ready_with_hello_observation(
            virtual_backbone, remote_virtual_backbone,
            {{192U, 0U, 2U, 1U}}, 0x02020202U, virtual_now);
    if (turn > 0U) {
      require(saw_virtual_hello,
              "virtual interface stopped periodic Hello transmission");
      require(advertised_remote,
              "virtual Hello omitted a known peer after one interval");
      const auto state =
          remote_virtual_backbone.neighbor_state(99U, 0x01010101U);
      if (!state || *state < NeighborState::two_way)
        throw std::runtime_error(
            "remote virtual peer did not observe a two-way Hello on turn " +
            std::to_string(turn) + ": " +
            std::to_string(state ? static_cast<unsigned>(*state) : 255U));
    }
    deliver_ready(remote_virtual_backbone, virtual_backbone,
                  {{192U, 0U, 2U, 2U}}, virtual_now);
  }
  const auto local_virtual_state =
      virtual_backbone.neighbor_state(99U, 0x02020202U);
  const auto remote_virtual_state =
      remote_virtual_backbone.neighbor_state(99U, 0x01010101U);
  if (local_virtual_state != NeighborState::full ||
      remote_virtual_state != NeighborState::full)
    throw std::runtime_error(
        "routed virtual-link packet exchange did not converge to Full: " +
        std::to_string(local_virtual_state
                           ? static_cast<unsigned>(*local_virtual_state)
                           : 255U) +
        "/" +
        std::to_string(remote_virtual_state
                           ? static_cast<unsigned>(*remote_virtual_state)
                           : 255U));
  const auto learned_by_first =
      std::find_if(first.routes().begin(), first.routes().end(),
                   [](const auto &route) {
                     return route.version_two_network == 0xc6336402U &&
                            route.prefix_length == 32U &&
                            route.path_type ==
                                router::lab::routing::OspfPathType::intra_area;
                   });
  if (learned_by_first == first.routes().end() ||
      learned_by_first->metric != 10U ||
      learned_by_first->next_hops.size() != 1U ||
      learned_by_first->next_hops.front().topology.version_two_next_hop !=
          0xc0000202U) {
    std::string detail =
        "SPF did not derive the remote IPv4 route and on-wire next hop; lsdb=" +
        std::to_string(first.database().records().size()) + " routes=" +
        std::to_string(first.routes().size()) + ":";
    for (const auto &route : first.routes())
      detail += " net=" + std::to_string(route.version_two_network) +
                "/" + std::to_string(route.prefix_length) +
                " metric=" + std::to_string(route.metric) +
                " hops=" + std::to_string(route.next_hops.size());
    for (const auto &record : first.database().records()) {
      const auto header = router::packet::ospf::lsa_header(
          record.bytes, router::packet::ospf::version_two);
      const auto router_lsa =
          router::packet::ospf::lsa::parse_version_two_router(record.bytes);
      detail += " lsa-router=" +
                std::to_string(header ? header->advertising_router : 0U) +
                " links=" +
                std::to_string(router_lsa ? router_lsa->link_count : 0U);
    }
    throw std::runtime_error(detail);
  }
  const auto published_by_first = std::find_if(
      first.ipv4_route_inputs().begin(), first.ipv4_route_inputs().end(),
      [](const auto &route) {
        return route.network == 0xc6336402U &&
               route.prefix_length == 32U;
      });
  require(published_by_first != first.ipv4_route_inputs().end() &&
              published_by_first->preference == 15U,
          "configured OSPF preference did not reach the complete RIB input");

  // A self-originated collision must be learned only from an encoded LSU.
  // Forge a newer R1 Router-LSA inside a packet sent by the established R2
  // neighbor, then wait for the real MinLSInterval deadline. R1 must originate
  // its authoritative topology at the received sequence plus one instead of
  // installing the reflected body or incrementing on every identical copy.
  const auto local_router_record = std::find_if(
      first.database().records().begin(),
      first.database().records().end(), [](const auto &record) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_two);
        return header && header->type ==
                             router::packet::ospf::lsa::
                                 version_two_router_type &&
               header->advertising_router == 0x01010101U;
      });
  const auto local_router_header =
      local_router_record != first.database().records().end()
          ? router::packet::ospf::lsa_header(
                local_router_record->bytes,
                router::packet::ospf::version_two)
          : std::nullopt;
  require(local_router_header.has_value(),
          "fight-back fixture could not find R1's Router-LSA");
  const auto reflected_sequence =
      local_router_header->sequence_number + 5;
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      reflected_storage{};
  const auto reflected_lsa =
      router::packet::ospf::lsa::encode_version_two_router_lsa(
          reflected_storage,
          {.link_state_id = 0x01010101U,
           .advertising_router = 0x01010101U,
           .sequence_number = reflected_sequence,
           .age_seconds = 0U,
           .type =
               router::packet::ospf::lsa::version_two_router_type,
           .options =
               router::packet::ospf::
                   option_external_routing_capability,
           .version = router::packet::ospf::version_two},
          {}, false, false, false);
  const std::array reflected_advertisements{
      router::packet::ospf::EncodedLsa{
          .bytes = reflected_lsa
                       ? *reflected_lsa
                       : std::span<const std::uint8_t>{}}};
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      reflected_payload_storage{};
  const auto reflected_payload =
      router::packet::ospf::encode_link_state_update_payload(
          reflected_payload_storage,
          router::packet::ospf::version_two,
          reflected_advertisements);
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      reflected_packet_storage{};
  constexpr std::array<std::uint8_t, 8U> null_authentication{};
  const auto reflected_packet =
      reflected_payload
          ? router::packet::ospf::encode_version_two(
                reflected_packet_storage,
                router::packet::ospf::PacketType::link_state_update,
                0x02020202U, 0U,
                router::packet::ospf::AuthenticationType::none,
                null_authentication, *reflected_payload)
          : std::nullopt;
  require(reflected_lsa && reflected_payload && reflected_packet &&
              first.receive_ipv4_packet(
                  1U, *reflected_packet, {{192U, 0U, 2U, 2U}},
                  router::packet::ospf::all_spf_routers_v4,
                  spf_now) == ReceiveStatus::accepted,
          "R1 rejected a valid newer self-originated collision");
  const auto fight_back_now =
      convergence_now + router::device_catalog::ospf_min_lsa_interval;
  deliver_ready(first, second, {{192U, 0U, 2U, 1U}},
                fight_back_now);
  const auto fought_back_record = std::find_if(
      first.database().records().begin(),
      first.database().records().end(), [](const auto &record) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_two);
        return header && header->type ==
                             router::packet::ospf::lsa::
                                 version_two_router_type &&
               header->advertising_router == 0x01010101U;
      });
  const auto fought_back_header =
      fought_back_record != first.database().records().end()
          ? router::packet::ospf::lsa_header(
                fought_back_record->bytes,
                router::packet::ospf::version_two)
          : std::nullopt;
  require(fought_back_header &&
              fought_back_header->sequence_number ==
                  reflected_sequence + 1,
          "self-originated collision did not produce an RFC fight-back "
          "generation");

  // MaxSequenceNumber cannot wrap directly to 0x80000001. R1 must first
  // flood the MaxAge form, retain it until R2 acknowledges that exact
  // generation, remove it only after database synchronization is safe, then
  // restart at InitialSequenceNumber after another MinLSInterval.
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      maximum_reflection_storage{};
  const auto maximum_reflection_lsa =
      router::packet::ospf::lsa::encode_version_two_router_lsa(
          maximum_reflection_storage,
          {.link_state_id = 0x01010101U,
           .advertising_router = 0x01010101U,
           .sequence_number = maximum_sequence_number,
           .age_seconds = 0U,
           .type =
               router::packet::ospf::lsa::version_two_router_type,
           .options =
               router::packet::ospf::
                   option_external_routing_capability,
           .version = router::packet::ospf::version_two},
          {}, false, false, false);
  const std::array maximum_reflection_advertisements{
      router::packet::ospf::EncodedLsa{
          .bytes = maximum_reflection_lsa
                       ? *maximum_reflection_lsa
                       : std::span<const std::uint8_t>{}}};
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      maximum_reflection_payload_storage{};
  const auto maximum_reflection_payload =
      router::packet::ospf::encode_link_state_update_payload(
          maximum_reflection_payload_storage,
          router::packet::ospf::version_two,
          maximum_reflection_advertisements);
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      maximum_reflection_packet_storage{};
  const auto maximum_reflection_packet =
      maximum_reflection_payload
          ? router::packet::ospf::encode_version_two(
                maximum_reflection_packet_storage,
                router::packet::ospf::PacketType::link_state_update,
                0x02020202U, 0U,
                router::packet::ospf::AuthenticationType::none,
                null_authentication, *maximum_reflection_payload)
          : std::nullopt;
  require(maximum_reflection_lsa && maximum_reflection_payload &&
              maximum_reflection_packet &&
              first.receive_ipv4_packet(
                  1U, *maximum_reflection_packet,
                  {{192U, 0U, 2U, 2U}},
                  router::packet::ospf::all_spf_routers_v4,
                  fight_back_now) == ReceiveStatus::accepted,
          "R1 rejected a valid MaxSequenceNumber collision");
  const auto wrap_flush_now =
      fight_back_now + router::device_catalog::ospf_min_lsa_interval;
  deliver_ready(first, second, {{192U, 0U, 2U, 1U}},
                wrap_flush_now);
  const auto maximum_record = std::find_if(
      first.database().records().begin(),
      first.database().records().end(), [](const auto &record) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_two);
        return header && header->type ==
                             router::packet::ospf::lsa::
                                 version_two_router_type &&
               header->advertising_router == 0x01010101U;
      });
  const auto maximum_header =
      maximum_record != first.database().records().end()
          ? router::packet::ospf::lsa_header(
                maximum_record->bytes,
                router::packet::ospf::version_two)
          : std::nullopt;
  require(maximum_header &&
              maximum_header->sequence_number ==
                  maximum_sequence_number &&
              maximum_record->age(wrap_flush_now) ==
                  max_age_seconds &&
              maximum_record->max_age_flooded,
          "MaxSequenceNumber collision was not retained as a reliably "
          "flooded MaxAge generation");
  deliver_ready(second, first, {{192U, 0U, 2U, 2U}},
                wrap_flush_now);
  deliver_ready(first, second, {{192U, 0U, 2U, 1U}},
                wrap_flush_now);
  const auto wrap_restart_now =
      wrap_flush_now + router::device_catalog::ospf_min_lsa_interval;
  deliver_ready(first, second, {{192U, 0U, 2U, 1U}},
                wrap_restart_now);
  const auto restarted_record = std::find_if(
      first.database().records().begin(),
      first.database().records().end(), [](const auto &record) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_two);
        return header && header->type ==
                             router::packet::ospf::lsa::
                                 version_two_router_type &&
               header->advertising_router == 0x01010101U;
      });
  const auto restarted_header =
      restarted_record != first.database().records().end()
          ? router::packet::ospf::lsa_header(
                restarted_record->bytes,
                router::packet::ospf::version_two)
          : std::nullopt;
  require(restarted_header &&
              restarted_header->sequence_number ==
                  initial_sequence_number &&
              restarted_record->age(wrap_restart_now) == 0U,
          "sequence wrap restarted before the flush completed or used the "
          "wrong InitialSequenceNumber");

}
