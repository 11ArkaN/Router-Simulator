// OSPFv2 and OSPFv3 broadcast election and adjacency cases.
// Each segment owns isolated process fixtures and encoded packet delivery.

#include "ospf_process_test_support.hpp"

void ospf_process_broadcast_tests() {
  using namespace router;
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  // Four isolated owners share one emulated broadcast segment. The first two
  // become DROther, the third becomes BDR and the highest Router ID becomes
  // DR. This topology distinguishes the normative 2-Way DROther relationship
  // from the Full adjacencies each DROther forms with both elected routers.
  InstanceProcess broadcast_one{
      0x01010101U, 0U, router::packet::ospf::version_two, 0U,
      0x11111111U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess broadcast_two{
      0x02020202U, 0U, router::packet::ospf::version_two, 0U,
      0x22222222U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess broadcast_three{
      0x03030303U, 0U, router::packet::ospf::version_two, 0U,
      0x33333333U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess broadcast_four{
      0x04040404U, 0U, router::packet::ospf::version_two, 0U,
      0x44444444U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(
      broadcast_one.add_interface(
          broadcast_interface_configuration(0x01010101U, 0x0a000001U, 0U),
          now) &&
          broadcast_two.add_interface(
              broadcast_interface_configuration(0x02020202U, 0x0a000002U,
                                                0U),
              now) &&
          broadcast_three.add_interface(
              broadcast_interface_configuration(0x03030303U, 0x0a000003U,
                                                0U),
              now) &&
          broadcast_four.add_interface(
              broadcast_interface_configuration(0x04040404U, 0x0a000004U,
                                                0U),
              now),
      "broadcast OSPF processes rejected valid interface configuration");
  std::array<BroadcastPeer, 4U> broadcast_segment{{
      {.process = &broadcast_one,
       .router_id = 0x01010101U,
       .address = {{10U, 0U, 0U, 1U}},
       .source_mac = {{0x02U, 0U, 0U, 0U, 0U, 1U}}},
      {.process = &broadcast_two,
       .router_id = 0x02020202U,
       .address = {{10U, 0U, 0U, 2U}},
       .source_mac = {{0x02U, 0U, 0U, 0U, 0U, 2U}}},
      {.process = &broadcast_three,
       .router_id = 0x03030303U,
       .address = {{10U, 0U, 0U, 3U}},
       .source_mac = {{0x02U, 0U, 0U, 0U, 0U, 3U}}},
      {.process = &broadcast_four,
       .router_id = 0x04040404U,
       .address = {{10U, 0U, 0U, 4U}},
       .source_mac = {{0x02U, 0U, 0U, 0U, 0U, 4U}}},
  }};
  for (auto &peer : broadcast_segment)
    deliver_broadcast_ready(peer, broadcast_segment, now);
  const auto broadcast_two_way =
      now + router::device_catalog::ospf_hello_interval;
  for (auto &peer : broadcast_segment)
    deliver_broadcast_ready(peer, broadcast_segment, broadcast_two_way);
  const auto broadcast_election =
      now + router::device_catalog::ospf_dead_interval;
  const auto broadcast_converged = [&] {
    for (std::size_t local{}; local < broadcast_segment.size(); ++local)
      for (std::size_t remote{}; remote < broadcast_segment.size(); ++remote) {
        if (local == remote)
          continue;
        const bool both_drother = local < 2U && remote < 2U;
        const auto expected =
            both_drother ? NeighborState::two_way : NeighborState::full;
        if (broadcast_segment[local].process->neighbor_state(
                1U, broadcast_segment[remote].router_id) != expected)
          return false;
      }
    return true;
  };
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       !broadcast_converged();
       ++turn)
    for (auto &peer : broadcast_segment)
      deliver_broadcast_ready(peer, broadcast_segment, broadcast_election);
  if (!broadcast_converged()) {
    std::string detail{
        "four-router broadcast segment did not converge DR/BDR adjacencies"};
    for (std::size_t local{}; local < broadcast_segment.size(); ++local) {
      const auto role =
          broadcast_segment[local].process->interface_state(1U);
      const auto dr =
          broadcast_segment[local].process->designated_router(1U);
      detail += " local=" + std::to_string(local + 1U) +
                " role=" +
                std::to_string(role ? static_cast<unsigned>(*role) : 255U) +
                " dr=" + std::to_string(dr.value_or(0U));
      for (std::size_t remote{}; remote < broadcast_segment.size();
           ++remote) {
        if (local == remote)
          continue;
        const auto state =
            broadcast_segment[local].process->neighbor_state(
                1U, broadcast_segment[remote].router_id);
        detail += " n" + std::to_string(remote + 1U) + "=" +
                  std::to_string(
                      state ? static_cast<unsigned>(*state) : 255U);
      }
    }
    throw std::runtime_error(detail);
  }
  require(
      broadcast_one.interface_state(1U) == InterfaceState::dr_other &&
          broadcast_two.interface_state(1U) == InterfaceState::dr_other &&
          broadcast_three.interface_state(1U) == InterfaceState::backup &&
          broadcast_four.interface_state(1U) ==
              InterfaceState::designated,
      "broadcast election selected incorrect interface roles");
  for (const auto &peer : broadcast_segment)
    require(peer.process->designated_router(1U) == 0x0a000004U,
            "OSPFv2 peers disagreed on the DR interface IPv4 identity");

  // Full transitions schedule a newer Router-LSA and the DR-owned
  // Network-LSA. The election-time Router-LSA generation already consumed
  // this owner's current origination slot, so honor RFC MinLSInterval before
  // draining the next generation and its reliable flooding.
  const auto broadcast_network_origination =
      broadcast_election + router::device_catalog::ospf_min_lsa_interval;
  for (std::size_t round{}; round < 4U; ++round)
    for (auto &peer : broadcast_segment)
      deliver_broadcast_ready(peer, broadcast_segment,
                              broadcast_network_origination);
  for (std::size_t peer_index{}; peer_index < broadcast_segment.size();
       ++peer_index) {
    const auto &peer = broadcast_segment[peer_index];
    const auto network_record = std::find_if(
        peer.process->database().records().begin(),
        peer.process->database().records().end(), [](const auto &record) {
          const auto header = router::packet::ospf::lsa_header(
              record.bytes, router::packet::ospf::version_two);
          return header && header->type ==
                               router::packet::ospf::lsa::
                                   version_two_network_type &&
                 header->link_state_id == 0x0a000004U &&
                 header->advertising_router == 0x04040404U;
        });
    const auto network =
        network_record != peer.process->database().records().end()
            ? router::packet::ospf::lsa::parse_version_two_network(
                  network_record->bytes)
            : std::nullopt;
    if (!network || network->attached_routers.size() != 16U) {
      std::string detail =
          "DR Network-LSA did not reach LSDB " +
          std::to_string(peer_index + 1U) + " records=" +
          std::to_string(peer.process->database().records().size());
      for (const auto &record : peer.process->database().records()) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_two);
        detail += " type=" +
                  std::to_string(header ? header->type : 0U) +
                  " id=" +
                  std::to_string(header ? header->link_state_id : 0U) +
                  " adv=" +
                  std::to_string(
                      header ? header->advertising_router : 0U);
      }
      throw std::runtime_error(detail);
    }
  }

  // RFC 5340 uses the same DR/BDR adjacency rules over broadcast links as
  // OSPFv2, but DD unicast is addressed to each neighbor's IPv6 link-local
  // address. Three routers are sufficient to prove that two concurrent DD
  // exchanges do not leak into one another through a shared Ethernet segment.
  InstanceProcess v3_broadcast_fourteen{
      0x0e0e0e0eU, 2U, router::packet::ospf::version_three, 0U,
      0x11121314U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess v3_broadcast_fifteen{
      0x0f0f0f0fU, 2U, router::packet::ospf::version_three, 0U,
      0x21222324U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess v3_broadcast_sixteen{
      0x10101010U, 2U, router::packet::ospf::version_three, 0U,
      0x31323334U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto v3_interface_fourteen =
      ipv6_interface_configuration(0x0e0e0e0eU, {}, 14U, 0U);
  auto v3_interface_fifteen =
      ipv6_interface_configuration(0x0f0f0f0fU, {}, 15U, 0U);
  auto v3_interface_sixteen =
      ipv6_interface_configuration(0x10101010U, {}, 16U, 0U);
  for (auto *configuration :
       {&v3_interface_fourteen, &v3_interface_fifteen,
        &v3_interface_sixteen}) {
    configuration->protocol.area_id = 2U;
    configuration->protocol.network_type = NetworkType::broadcast;
    configuration->protocol.interface_id = 1U;
  }
  v3_interface_fourteen.source_mac =
      {{0x02U, 0U, 0U, 0U, 0U, 14U}};
  v3_interface_fifteen.source_mac =
      {{0x02U, 0U, 0U, 0U, 0U, 15U}};
  v3_interface_sixteen.source_mac =
      {{0x02U, 0U, 0U, 0U, 0U, 16U}};
  require(v3_broadcast_fourteen.add_interface(v3_interface_fourteen, now) &&
              v3_broadcast_fifteen.add_interface(v3_interface_fifteen, now) &&
              v3_broadcast_sixteen.add_interface(v3_interface_sixteen, now),
          "OSPFv3 broadcast owners rejected valid shared-link interfaces");
  std::array<VersionThreeBroadcastPeer, 3U> v3_broadcast_segment{{
      {.process = &v3_broadcast_fourteen,
       .router_id = 0x0e0e0e0eU,
       .link_local = v3_interface_fourteen.ipv6_source,
       .source_mac = v3_interface_fourteen.source_mac},
      {.process = &v3_broadcast_fifteen,
       .router_id = 0x0f0f0f0fU,
       .link_local = v3_interface_fifteen.ipv6_source,
       .source_mac = v3_interface_fifteen.source_mac},
      {.process = &v3_broadcast_sixteen,
       .router_id = 0x10101010U,
       .link_local = v3_interface_sixteen.ipv6_source,
       .source_mac = v3_interface_sixteen.source_mac},
  }};
  for (auto &peer : v3_broadcast_segment)
    deliver_version_three_broadcast_ready(peer, v3_broadcast_segment, now);
  const auto v3_broadcast_two_way =
      now + router::device_catalog::ospf_hello_interval;
  for (auto &peer : v3_broadcast_segment)
    deliver_version_three_broadcast_ready(
        peer, v3_broadcast_segment, v3_broadcast_two_way);
  const auto v3_broadcast_election =
      now + router::device_catalog::ospf_dead_interval;
  const auto v3_broadcast_converged = [&] {
    for (std::size_t local{}; local < v3_broadcast_segment.size(); ++local)
      for (std::size_t remote{}; remote < v3_broadcast_segment.size();
           ++remote)
        if (local != remote &&
            v3_broadcast_segment[local].process->neighbor_state(
                1U, v3_broadcast_segment[remote].router_id) !=
                NeighborState::full)
          return false;
    return true;
  };
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       !v3_broadcast_converged();
       ++turn)
    for (auto &peer : v3_broadcast_segment)
      deliver_version_three_broadcast_ready(
          peer, v3_broadcast_segment, v3_broadcast_election);
  require(v3_broadcast_converged(),
          "three-router OSPFv3 broadcast segment remained below Full");

}
