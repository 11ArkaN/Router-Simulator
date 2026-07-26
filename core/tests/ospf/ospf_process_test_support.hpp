// Instance process tests exchange real encoded Hello packets between isolated
// owners. No neighbor object or topology fact is copied between processes.


#pragma once
#include "router/ospf_process.hpp"
#include "router/secret_vault.hpp"
#include "router/interface_identity.hpp"
#include "router/ospf_authentication.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

[[maybe_unused]] void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

[[maybe_unused]] void deliver_ready(router::ospf::InstanceProcess &source,
                   router::ospf::InstanceProcess &destination,
                   const router::ip::Ipv4 &source_address,
                   router::ospf::RuntimeClock::time_point now) {
  std::array<router::ospf::ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      output{};
  std::size_t written{};
  require(source.run_ready(now, output, written),
          "OSPF owner exceeded one generated work batch");
  for (std::size_t index{}; index < written; ++index) {
    const auto status = destination.receive_ipv4_packet(
        output[index].interface_id,
        std::span<const std::uint8_t>{output[index].bytes}.first(
            output[index].size),
        source_address, output[index].ipv4_destination, now);
    const auto decoded = router::packet::ospf::parse_packet(
        std::span<const std::uint8_t>{output[index].bytes}.first(
            output[index].size));
    if (status != router::ospf::ReceiveStatus::accepted &&
        status != router::ospf::ReceiveStatus::ignored) {
      const auto description = decoded
          ? router::packet::ospf::parse_database_description(*decoded)
          : std::nullopt;
      throw std::runtime_error(
          "peer rejected encoded OSPF packet with status " +
          std::to_string(static_cast<unsigned>(status)) + " type " +
          std::to_string(decoded ? static_cast<unsigned>(decoded->type)
                                 : 0U) + " router " +
          std::to_string(decoded ? decoded->router_id : 0U) + " seq " +
          std::to_string(description ? description->sequence_number : 0U) +
          " flags " +
          std::to_string(description
              ? (description->init ? 4U : 0U) |
                    (description->more ? 2U : 0U) |
                    (description->master ? 1U : 0U)
              : 0U));
    }
  }
}

[[maybe_unused]] std::pair<bool, bool> deliver_ready_with_hello_observation(
    router::ospf::InstanceProcess &source,
    router::ospf::InstanceProcess &destination,
    const router::ip::Ipv4 &source_address,
    std::uint32_t expected_neighbor,
    router::ospf::RuntimeClock::time_point now) {
  std::array<router::ospf::ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      output{};
  std::size_t written{};
  require(source.run_ready(now, output, written),
          "OSPF owner exceeded one observed work batch");
  bool saw_hello{};
  bool hello_advertised_neighbor{};
  for (std::size_t index{}; index < written; ++index) {
    const auto bytes =
        std::span<const std::uint8_t>{output[index].bytes}.first(
            output[index].size);
    const auto packet = router::packet::ospf::parse_packet(bytes);
    if (packet &&
        packet->type == router::packet::ospf::PacketType::hello) {
      saw_hello = true;
      const auto hello = router::packet::ospf::parse_hello(*packet);
      for (std::size_t neighbor{};
           hello && neighbor < hello->neighbors.size() / 4U; ++neighbor)
        hello_advertised_neighbor =
            hello_advertised_neighbor ||
            router::packet::ospf::hello_neighbor(*hello, neighbor) ==
                expected_neighbor;
    }
    const auto status = destination.receive_ipv4_packet(
        output[index].interface_id, bytes, source_address,
        output[index].ipv4_destination, now);
    require(status == router::ospf::ReceiveStatus::accepted ||
                status == router::ospf::ReceiveStatus::ignored,
            "peer rejected an observed OSPF packet");
  }
  return {saw_hello, hello_advertised_neighbor};
}

struct BroadcastPeer {
  router::ospf::InstanceProcess *process{};
  std::uint32_t router_id{};
  router::ip::Ipv4 address{};
  router::packet::Mac source_mac{};
};

struct VersionThreeBroadcastPeer {
  router::ospf::InstanceProcess *process{};
  std::uint32_t router_id{};
  router::ip::Ipv6 link_local{};
  router::packet::Mac source_mac{};
};

[[maybe_unused]] void deliver_version_three_broadcast_ready(
    VersionThreeBroadcastPeer &source,
    std::span<VersionThreeBroadcastPeer> segment,
    router::ospf::RuntimeClock::time_point now) {
  // The test models one Ethernet transmission per process output. Multicast
  // reaches every eligible receiver, while neighbor-unicast traffic reaches
  // only the Router ID selected by the protocol exchange owner.
  for (std::size_t batch{};
       batch < router::device_catalog::ospf_work_budget_packets; ++batch) {
    std::array<router::ospf::ProcessOutput,
               router::device_catalog::ospf_work_budget_packets>
        output{};
    std::size_t written{};
    const bool drained = source.process->run_ready(now, output, written);
    for (std::size_t index{}; index < written; ++index) {
      for (auto &destination : segment) {
        if (destination.process == source.process)
          continue;
        if (output[index].neighbor_router_id != 0U &&
            output[index].neighbor_router_id != destination.router_id)
          continue;
        if (output[index].destination ==
            router::ospf::PacketDestination::all_dr_routers) {
          const auto state =
              destination.process->interface_state(output[index].interface_id);
          if (!state ||
              (*state != router::ospf::InterfaceState::designated &&
               *state != router::ospf::InterfaceState::backup))
            continue;
        }
        const auto status = destination.process->receive_packet(
            output[index].interface_id,
            std::span<const std::uint8_t>{output[index].bytes}.first(
                output[index].size),
            source.link_local, output[index].ipv6_destination, now);
        require(status == router::ospf::ReceiveStatus::accepted ||
                    status == router::ospf::ReceiveStatus::ignored,
                "broadcast OSPFv3 peer rejected an encoded packet");
      }
    }
    if (drained)
      return;
  }
  throw std::runtime_error(
      "broadcast OSPFv3 owner did not drain within its packet budget");
}

[[maybe_unused]] void deliver_broadcast_ready(
    BroadcastPeer &source, std::span<BroadcastPeer> segment,
    router::ospf::RuntimeClock::time_point now) {
  // One process turn can fill its packet work budget while more DD or flooding
  // work remains. Drain bounded turns at the same monotonic instant, exactly
  // as the control shard would reschedule a ready owner without advancing
  // protocol time.
  for (std::size_t batch{};
       batch < router::device_catalog::ospf_work_budget_packets; ++batch) {
    std::array<router::ospf::ProcessOutput,
               router::device_catalog::ospf_work_budget_packets>
        output{};
    std::size_t written{};
    const bool drained = source.process->run_ready(now, output, written);
    for (std::size_t index{}; index < written; ++index) {
      if (output[index].destination ==
          router::ospf::PacketDestination::neighbor_unicast) {
        const auto destination = std::find_if(
            segment.begin(), segment.end(), [&](const auto &candidate) {
              return candidate.router_id ==
                     output[index].neighbor_router_id;
            });
        require(destination != segment.end(),
                "neighbor-unicast OSPF output named a router outside the "
                "attached broadcast segment");
      }
      if (output[index].destination !=
          router::ospf::PacketDestination::neighbor_unicast) {
        require(output[index].neighbor_router_id == 0U,
                "multicast OSPF output leaked a private neighbor identity");
        // One encoded multicast frame represents one transmission on the
        // shared segment. Identical copies would multiply traffic by the
        // adjacency count even though retransmission ownership is per peer.
        for (std::size_t previous{}; previous < index; ++previous)
          require(
              output[previous].destination != output[index].destination ||
                  output[previous].interface_id !=
                      output[index].interface_id ||
                  output[previous].size != output[index].size ||
                  !std::equal(
                      output[previous].bytes.begin(),
                      output[previous].bytes.begin() + output[previous].size,
                      output[index].bytes.begin()),
              "one OSPF owner turn emitted duplicate multicast frames");
      }
      for (auto &destination : segment) {
        if (destination.process == source.process)
          continue;
        if (output[index].destination ==
            router::ospf::PacketDestination::all_dr_routers) {
          const auto state = destination.process->interface_state(
              output[index].interface_id);
          if (!state ||
              (*state != router::ospf::InterfaceState::designated &&
               *state != router::ospf::InterfaceState::backup))
            continue;
        }
        // Multicast is observed by every attached router. Unicast DD, request
        // and NBMA traffic remains addressed to the peer that owns the
        // exchange state.
        if (output[index].neighbor_router_id != 0U &&
            output[index].neighbor_router_id != destination.router_id)
          continue;
        const auto status = destination.process->receive_ipv4_packet(
            output[index].interface_id,
            std::span<const std::uint8_t>{output[index].bytes}.first(
                output[index].size),
            source.address, output[index].ipv4_destination, now);
        if (status != router::ospf::ReceiveStatus::accepted &&
            status != router::ospf::ReceiveStatus::ignored)
          throw std::runtime_error(
              "broadcast peer rejected encoded OSPF packet with status " +
              std::to_string(static_cast<unsigned>(status)));
      }
    }
    if (drained)
      return;
  }
  throw std::runtime_error(
      "broadcast OSPF owner did not drain within its work-budget bound; "
      "router=" +
      std::to_string(source.router_id) + " run-stage=" +
      std::to_string(static_cast<unsigned>(
          source.process->run_ready_status())) +
      " route-stage=" +
      std::to_string(static_cast<unsigned>(
          source.process->route_recalculation_status())) +
      " origin-stage=" +
      std::to_string(static_cast<unsigned>(
          source.process->local_origination_status())));
}

[[maybe_unused]] void deliver_ready_v3(router::ospf::InstanceProcess &source,
                      router::ospf::InstanceProcess &destination,
                      std::uint32_t source_router_id,
                      router::ospf::RuntimeClock::time_point now) {
  for (std::size_t batch{};
       batch < router::device_catalog::ospf_work_budget_packets; ++batch) {
    std::array<router::ospf::ProcessOutput,
               router::device_catalog::ospf_work_budget_packets>
        output{};
    std::size_t written{};
    const bool drained = source.run_ready(now, output, written);
    for (std::size_t index{}; index < written; ++index) {
      const auto status = destination.receive_packet(
          output[index].interface_id,
          std::span<const std::uint8_t>{output[index].bytes}.first(
              output[index].size),
          output[index].ipv6_source, output[index].ipv6_destination, now);
      if (status != router::ospf::ReceiveStatus::accepted &&
          status != router::ospf::ReceiveStatus::ignored)
        throw std::runtime_error(
            "peer rejected encoded OSPFv3 IPv4-AF packet with status " +
            std::to_string(static_cast<unsigned>(status)));
    }
    if (drained)
      return;
    if (written < output.size())
    {
      router::ospf::TopologyBuilder topology{
          router::device_catalog::ospf_vertices_per_area,
          router::device_catalog::ospf_edges_per_area};
      const bool topology_valid = topology.build(
          source.database().records(),
          router::packet::ospf::version_three, source_router_id);
      router::ospf::SpfCalculator spf{
          router::device_catalog::ospf_vertices_per_area,
          router::device_catalog::ospf_edges_per_area};
      const auto graph = topology.graph();
      const bool spf_valid =
          topology_valid &&
          spf.calculate(graph.root_vertex, graph.vertices, graph.edges,
                        static_cast<std::uint16_t>(
                            graph.first_hops.size()));
      router::ospf::RouteCalculator routes{
          router::device_catalog::ospf_lsas_per_instance,
          router::device_catalog::maximum_ecmp_paths};
      const bool routes_valid =
          spf_valid &&
          routes.recalculate(source.database().records(),
                             router::packet::ospf::version_three, 0U, true,
                             graph, spf);
      std::array<std::uint8_t, router::packet::maximum_frame_octets>
          diagnostic_lsa{};
      const auto diagnostic_router_lsa =
          router::packet::ospf::lsa::encode_version_three_router_lsa(
              diagnostic_lsa,
              {.link_state_id = 0U,
               .advertising_router = source_router_id,
               .sequence_number =
                   router::ospf::initial_sequence_number + 1,
               .age_seconds = 0U,
               .type =
                   router::packet::ospf::lsa::
                       version_three_router_type,
               .options =
                   router::packet::ospf::
                       option_external_routing_capability |
                   router::packet::ospf::option_address_family |
                   router::packet::ospf::option_ospfv3_router,
               .version = router::packet::ospf::version_three},
              {}, 0U,
              router::packet::ospf::option_external_routing_capability |
                  router::packet::ospf::option_address_family |
                  router::packet::ospf::option_ospfv3_router);
      const std::array diagnostic_link{
          router::packet::ospf::lsa::VersionThreeRouterLinkInput{
              .interface_id = 1U,
              .neighbor_interface_id = 1U,
              .neighbor_router_id =
                  source_router_id == 0x03030303U ? 0x04040404U
                                                  : 0x03030303U,
              .metric = 10U,
              .type =
                  router::packet::ospf::lsa::RouterLinkType::
                      point_to_point}};
      const auto diagnostic_link_router_lsa =
          router::packet::ospf::lsa::encode_version_three_router_lsa(
              diagnostic_lsa,
              {.link_state_id = 0U,
               .advertising_router = source_router_id,
               .sequence_number =
                   router::ospf::initial_sequence_number + 1,
               .age_seconds = 0U,
               .type =
                   router::packet::ospf::lsa::
                       version_three_router_type,
               .options =
                   router::packet::ospf::
                       option_external_routing_capability |
                   router::packet::ospf::option_address_family |
                   router::packet::ospf::option_ospfv3_router,
               .version = router::packet::ospf::version_three},
              diagnostic_link, 0U,
              router::packet::ospf::option_external_routing_capability |
                  router::packet::ospf::option_address_family |
                  router::packet::ospf::option_ospfv3_router);
      const bool diagnostic_link_checksum =
          router::ospf::verify_lsa_checksum(
              std::span<const std::uint8_t>{diagnostic_lsa}.first(40U));
      std::string route_detail;
      for (const auto &route : routes.routes())
        for (const auto &hop : route.next_hops)
          route_detail +=
              " prefix=" +
              std::to_string(
                  static_cast<unsigned>(route.version_three_network[0U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(route.version_three_network[1U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(route.version_three_network[2U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(route.version_three_network[3U])) +
              "/" + std::to_string(route.prefix_length) +
              " local-if=" +
              std::to_string(hop.topology.local_interface) +
              " peer-if=" +
              std::to_string(hop.topology.neighbor_interface) +
              " next=" +
              std::to_string(
                  static_cast<unsigned>(hop.version_three_link_local[0U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(hop.version_three_link_local[1U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(hop.version_three_link_local[2U])) +
              "." +
              std::to_string(
                  static_cast<unsigned>(hop.version_three_link_local[3U]));
      for (const auto &record : source.database().records()) {
        const auto header = router::packet::ospf::lsa_header(
            record.bytes, router::packet::ospf::version_three);
        if (header && header->advertising_router == source_router_id)
          route_detail += " local-lsa=" +
                          std::to_string(header->type & 0x1fffU) +
                          ":" + std::to_string(header->sequence_number);
      }
      throw std::runtime_error(
          "OSPFv3 owner rejected ready work before filling its output "
          "budget; written=" +
          std::to_string(written) + " lsdb=" +
          std::to_string(source.database().records().size()) +
          " topology=" + std::to_string(topology_valid) +
          " spf=" + std::to_string(spf_valid) +
          " routes=" + std::to_string(routes_valid) +
          " owner-stage=" +
          std::to_string(static_cast<unsigned>(
              source.route_recalculation_status())) +
          " run-stage=" +
          std::to_string(static_cast<unsigned>(source.run_ready_status())) +
          " origin-stage=" +
          std::to_string(static_cast<unsigned>(
              source.local_origination_status())) +
          " install-result=" +
          std::to_string(static_cast<unsigned>(
              source.local_origination_install_result())) +
          " isolated-router-lsa=" +
          std::to_string(diagnostic_router_lsa.has_value()) +
          " linked-router-lsa=" +
          std::to_string(diagnostic_link_router_lsa.has_value()) +
          " linked-checksum=" +
          std::to_string(diagnostic_link_checksum) +
          " check-octets=" +
          std::to_string(
              static_cast<unsigned>(diagnostic_lsa[16U])) +
          "," +
          std::to_string(
              static_cast<unsigned>(diagnostic_lsa[17U])) +
          " body=" +
          std::to_string(
              static_cast<unsigned>(diagnostic_lsa[24U])) +
          "," +
          std::to_string(
              static_cast<unsigned>(diagnostic_lsa[26U])) +
          "," +
          std::to_string(
              static_cast<unsigned>(diagnostic_lsa[27U])) +
          route_detail);
    }
  }
  throw std::runtime_error(
      "OSPFv3 owner did not drain within the sourced work-budget bound");
}

[[maybe_unused]] router::ospf::ProcessInterfaceConfiguration
interface_configuration(std::uint32_t router_id, std::uint32_t address,
                        std::uint16_t port) {
  using namespace router::ospf;
  return {
      .protocol =
          {.router_id = router_id,
           .area_id = 0U,
           .interface_id = port + 1U,
           .network_mask = 0xffffff00U,
           .options = 0x02U,
           .hello_interval_seconds = static_cast<std::uint16_t>(
               router::device_catalog::ospf_hello_interval.count()),
           .dead_interval_seconds = static_cast<std::uint16_t>(
               router::device_catalog::ospf_dead_interval.count()),
           .interface_mtu = 1500U,
           .router_priority = 1U,
           .version = router::packet::ospf::version_two,
           .instance_id = 0U,
           .network_type = NetworkType::point_to_point,
           .passive = false,
           .enabled = true},
      .ipv4_source = {{static_cast<std::uint8_t>(address >> 24U),
                       static_cast<std::uint8_t>(address >> 16U),
                       static_cast<std::uint8_t>(address >> 8U),
                       static_cast<std::uint8_t>(address)}},
      .physical_port_ordinal = port,
      .metric = 10U,
      .retransmit_interval_seconds = static_cast<std::uint16_t>(
          router::device_catalog::ospf_retransmit_interval.count()),
      .transmit_delay_seconds = static_cast<std::uint16_t>(
          router::device_catalog::ospf_transmit_delay.count()),
      .prefix_length = 24U};
}

[[maybe_unused]] router::ospf::ProcessInterfaceConfiguration
broadcast_interface_configuration(std::uint32_t router_id,
                                  std::uint32_t address,
                                  std::uint16_t port) {
  auto value = interface_configuration(router_id, address, port);
  value.protocol.network_type = router::ospf::NetworkType::broadcast;
  value.protocol.interface_id = 1U;
  return value;
}

[[maybe_unused]] router::ospf::ProcessInterfaceConfiguration
ipv4_af_interface_configuration(std::uint32_t router_id,
                                std::uint32_t address,
                                std::uint8_t link_local_suffix,
                                std::uint16_t port) {
  using namespace router::ospf;
  auto value = interface_configuration(router_id, address, port);
  value.protocol.version = router::packet::ospf::version_three;
  value.protocol.instance_id =
      router::device_catalog::ospf_v3_ipv4_instance_first;
  value.protocol.interface_id = port + 1U;
  value.protocol.options =
      router::packet::ospf::option_external_routing_capability |
      router::packet::ospf::option_ospfv3_router |
      router::packet::ospf::option_address_family;
  value.ipv6_source = {
      {0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, link_local_suffix}};
  return value;
}

[[maybe_unused]] router::ospf::ProcessInterfaceConfiguration
ipv6_interface_configuration(std::uint32_t router_id,
                             router::ip::Ipv6 prefix,
                             std::uint8_t link_local_suffix,
                             std::uint16_t port) {
  using namespace router::ospf;
  auto value = interface_configuration(router_id, 0U, port);
  value.protocol.version = router::packet::ospf::version_three;
  value.protocol.instance_id =
      router::device_catalog::ospf_v3_ipv6_instance_first;
  value.protocol.interface_id = port + 1U;
  value.protocol.options =
      router::packet::ospf::option_external_routing_capability |
      router::packet::ospf::option_ospfv3_router |
      router::packet::ospf::option_ipv6_forwarding;
  value.ipv4_source = {};
  value.ipv6_source = {
      {0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, link_local_suffix}};
  value.ipv6_prefix = prefix;
  value.prefix_length = 64U;
  return value;
}

} // namespace
