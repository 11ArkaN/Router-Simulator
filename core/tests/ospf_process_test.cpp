// Instance process tests exchange real encoded Hello packets between isolated
// owners. No neighbor object or topology fact is copied between processes.

#include "router/ospf_process.hpp"
#include "router/secret_vault.hpp"
#include "router/interface_identity.hpp"
#include "router/ospf_authentication.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void deliver_ready(router::ospf::InstanceProcess &source,
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

std::pair<bool, bool> deliver_ready_with_hello_observation(
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

void deliver_version_three_broadcast_ready(
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

void deliver_broadcast_ready(
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

void deliver_ready_v3(router::ospf::InstanceProcess &source,
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

router::ospf::ProcessInterfaceConfiguration
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

router::ospf::ProcessInterfaceConfiguration
broadcast_interface_configuration(std::uint32_t router_id,
                                  std::uint32_t address,
                                  std::uint16_t port) {
  auto value = interface_configuration(router_id, address, port);
  value.protocol.network_type = router::ospf::NetworkType::broadcast;
  value.protocol.interface_id = 1U;
  return value;
}

router::ospf::ProcessInterfaceConfiguration
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

router::ospf::ProcessInterfaceConfiguration
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

void ospf_process_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};

  // Authentication is verified at the protocol owner before Hello semantics
  // can allocate neighbor state. These process-level cases complement the
  // byte-level RFC 5709 fixture by proving that an encoded packet traverses
  // the same receive gate used by every real adjacency.
  const auto authentication = [](KeychainAlgorithm algorithm,
                                 std::uint8_t key_id,
                                 std::string_view secret) {
    ProcessAuthentication result{
        .initial_sequence = 100U,
        .secret_handle = 1U,
        .key_id = key_id,
        .algorithm = algorithm,
        .secret_kind = static_cast<std::uint8_t>(
            router::vault::SecretKind::ospf_authentication_key),
        .begin_utc_seconds = 0,
        .end_utc_seconds = std::nullopt,
        .tolerance_seconds = 0U,
        .timed = false};
    result.key_size = static_cast<std::uint8_t>(secret.size());
    std::copy(secret.begin(), secret.end(), result.key.begin());
    return result;
  };
  const auto authenticated_hello =
      [&](KeychainAlgorithm algorithm, std::uint8_t key_id,
          std::string_view transmit_secret,
          std::string_view receive_secret) {
        InstanceProcess transmitter{
            0x11111111U, 0U, router::packet::ospf::version_two, 0U,
            0x10101010U, 1U,
            router::device_catalog::ospf_neighbors_per_interface,
            router::device_catalog::ospf_lsas_per_instance};
        InstanceProcess receiver{
            0x22222222U, 0U, router::packet::ospf::version_two, 0U,
            0x20202020U, 1U,
            router::device_catalog::ospf_neighbors_per_interface,
            router::device_catalog::ospf_lsas_per_instance};
        require(
            transmitter.add_interface(
                interface_configuration(0x11111111U, 0xc0000201U, 0U), now) &&
                receiver.add_interface(
                    interface_configuration(0x22222222U, 0xc0000202U, 0U),
                    now),
            "authenticated OSPF peers rejected their interfaces");
        const auto transmit =
            authentication(algorithm, key_id, transmit_secret);
        const auto receive =
            authentication(algorithm, key_id, receive_secret);
        require(transmitter.set_interface_authentication(1U, transmit) &&
                    receiver.set_interface_authentication(1U, receive),
                "authenticated OSPF peers rejected valid key material");
        std::array<ProcessOutput, 2U> packets{};
        std::size_t written{};
        require(transmitter.run_ready(now, packets, written) &&
                    written == 1U,
                "authenticated OSPF owner did not emit its initial Hello");
        const auto bytes =
            std::span<const std::uint8_t>{packets[0].bytes}.first(
                packets[0].size);
        const auto status = receiver.receive_ipv4_packet(
            1U, bytes, {{192U, 0U, 2U, 1U}},
            packets[0].ipv4_destination, now);
        return std::pair{status,
                         receiver.receive_ipv4_packet(
                             1U, bytes, {{192U, 0U, 2U, 1U}},
                             packets[0].ipv4_destination, now)};
      };
  const auto password_ok =
      authenticated_hello(KeychainAlgorithm::password, 0U,
                          "wirepass", "wirepass");
  require(password_ok.first == ReceiveStatus::accepted,
          "matching OSPFv2 simple passwords did not authenticate");
  const auto password_bad =
      authenticated_hello(KeychainAlgorithm::password, 0U,
                          "wirepass", "wrong");
  require(password_bad.first == ReceiveStatus::authentication_failure,
          "mismatched OSPFv2 simple passwords changed protocol state");
  const auto hmac_ok =
      authenticated_hello(KeychainAlgorithm::hmac_sha256, 17U,
                          "rfc5709-shared-key", "rfc5709-shared-key");
  require(hmac_ok.first == ReceiveStatus::accepted &&
              hmac_ok.second == ReceiveStatus::authentication_failure,
          "OSPFv2 HMAC-SHA-256 acceptance or replay protection failed");
  const auto hmac_bad =
      authenticated_hello(KeychainAlgorithm::hmac_sha256, 17U,
                          "rfc5709-shared-key", "different-key");
  require(hmac_bad.first == ReceiveStatus::authentication_failure,
          "OSPFv2 HMAC-SHA-256 accepted a mismatched key");
  require(authenticated_hello(KeychainAlgorithm::message_digest, 9U,
                              "md5-key", "md5-key")
                  .first == ReceiveStatus::accepted &&
              authenticated_hello(KeychainAlgorithm::hmac_sha1, 11U,
                                  "sha1-keychain-key",
                                  "sha1-keychain-key")
                      .first == ReceiveStatus::accepted,
          "release-supported OSPFv2 keyed algorithms did not reach Hello");

  // OSPFv3 manual-SA authentication is a transport-mode AH envelope, not an
  // OSPF Authentication Trailer. The process owns both the outgoing sequence
  // and inbound anti-replay value, so replaying the same authentic packet must
  // fail before the Hello refreshes neighbor inactivity state.
  InstanceProcess ah_transmitter{
      0x11111111U, 0U, router::packet::ospf::version_three, 0U,
      0x31313131U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess ah_receiver{
      0x22222222U, 0U, router::packet::ospf::version_three, 0U,
      0x32323232U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  const auto ah_tx_interface = ipv6_interface_configuration(
      0x11111111U,
      {{0x20U, 1U, 0x0dU, 0xb8U, 0U, 1U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}},
      1U, 0U);
  const auto ah_rx_interface = ipv6_interface_configuration(
      0x22222222U,
      {{0x20U, 1U, 0x0dU, 0xb8U, 0U, 1U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 2U}},
      2U, 0U);
  require(ah_transmitter.add_interface(ah_tx_interface, now) &&
              ah_receiver.add_interface(ah_rx_interface, now),
          "OSPFv3 AH fixture rejected its interfaces");
  ProcessAuthentication ah_key{
      .initial_sequence = 0U,
      .secret_handle = 1U,
      .key_size = 20U,
      .key_id = 4096U,
      .algorithm = KeychainAlgorithm::hmac_sha1,
      .secret_kind = static_cast<std::uint8_t>(
          router::vault::SecretKind::ipsec_static_authentication_key),
      .ipsec_ah = true,
      .begin_utc_seconds = 0,
      .end_utc_seconds = std::nullopt,
      .tolerance_seconds = 0U,
      .timed = false};
  constexpr std::string_view ah_secret = "01234567890123456789";
  std::copy(ah_secret.begin(), ah_secret.end(), ah_key.key.begin());
  require(ah_transmitter.set_interface_authentication(1U, ah_key) &&
              ah_receiver.set_interface_authentication(1U, ah_key),
          "OSPFv3 AH fixture rejected its manual SA");
  std::array<ProcessOutput, 1U> ah_outputs{};
  std::size_t ah_written{};
  require(ah_transmitter.run_ready(now, ah_outputs, ah_written) &&
              ah_written == 1U,
          "OSPFv3 AH fixture did not create an OSPF Hello");
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      ah_ipv6{};
  const auto ah_packet = ah_transmitter.protect_ipv6_ipsec_packet(
      1U, ah_outputs[0].ipv6_source,
      ah_outputs[0].ipv6_destination, ah_outputs[0].hop_limit,
      std::span<const std::uint8_t>{ah_outputs[0].bytes}.first(
          ah_outputs[0].size),
      ah_ipv6);
  require(ah_packet &&
              ah_receiver.receive_ipv6_ipsec_packet(
                  1U, *ah_packet, now) == ReceiveStatus::accepted &&
              ah_receiver.receive_ipv6_ipsec_packet(
                  1U, *ah_packet, now) ==
                  ReceiveStatus::authentication_failure,
          "OSPFv3 AH acceptance or anti-replay behavior failed");

  // Key rollover is evaluated by the protocol owner from real UTC at packet
  // creation time. Two already-active entries prove that the newest begin-time
  // wins without a configuration republish or a management polling loop.
  InstanceProcess rollover{
      0x33333333U, 0U, router::packet::ospf::version_two, 0U,
      0x30303030U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(rollover.add_interface(
              interface_configuration(0x33333333U, 0xc0000203U, 0U), now),
          "rollover fixture rejected its physical interface");
  const auto utc_now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now()
                               .time_since_epoch())
                           .count();
  auto old_key = authentication(KeychainAlgorithm::hmac_sha256, 12U,
                                "old-keychain-key");
  old_key.timed = true;
  old_key.begin_utc_seconds = utc_now - 20;
  old_key.tolerance_seconds = 300U;
  auto new_key = authentication(KeychainAlgorithm::hmac_sha256, 13U,
                                "new-keychain-key");
  new_key.timed = true;
  new_key.begin_utc_seconds = utc_now - 10;
  new_key.tolerance_seconds = 300U;
  const std::array rollover_keys{old_key, new_key};
  require(rollover.set_interface_authentication(1U, std::nullopt,
                                                rollover_keys),
          "rollover fixture rejected its complete keychain");
  std::array<ProcessOutput, 1U> rollover_packets{};
  std::size_t rollover_written{};
  require(rollover.run_ready(now, rollover_packets, rollover_written) &&
              rollover_written == 1U,
          "keychain rollover did not emit a protected Hello");
  const auto rollover_packet = router::packet::ospf::parse_packet(
      std::span<const std::uint8_t>{rollover_packets[0].bytes}.first(
          rollover_packets[0].size));
  require(rollover_packet &&
              router::ospf::authentication::v2_key_id(*rollover_packet) ==
                  new_key.key_id,
          "keychain rollover did not select the newest active send entry");

  // RFC 2328 sections 9.5.1 and C.5 require NBMA discovery to use the
  // configured neighbor table and unicast Hellos. A packet received from any
  // other transport address must not create a neighbor dynamically.
  InstanceProcess nbma_first{
      0x11111111U, 0U, router::packet::ospf::version_two, 0U,
      0x10101010U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess nbma_second{
      0x22222222U, 0U, router::packet::ospf::version_two, 0U,
      0x20202020U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto nbma_first_interface =
      interface_configuration(0x11111111U, 0xc0000201U, 0U);
  auto nbma_second_interface =
      interface_configuration(0x22222222U, 0xc0000202U, 0U);
  nbma_first_interface.protocol.network_type = NetworkType::non_broadcast;
  nbma_second_interface.protocol.network_type = NetworkType::non_broadcast;
  router::ip::IpAddress first_peer{
      .family = router::ip::AddressFamily::ipv4};
  first_peer.bytes[0U] = 192U;
  first_peer.bytes[1U] = 0U;
  first_peer.bytes[2U] = 2U;
  first_peer.bytes[3U] = 2U;
  router::ip::IpAddress second_peer{
      .family = router::ip::AddressFamily::ipv4};
  second_peer.bytes[0U] = 192U;
  second_peer.bytes[1U] = 0U;
  second_peer.bytes[2U] = 2U;
  second_peer.bytes[3U] = 1U;
  require(nbma_first.add_interface(nbma_first_interface, now) &&
              nbma_second.add_interface(nbma_second_interface, now) &&
              nbma_first.add_nbma_neighbor(
                  1U, {.address = first_peer,
                       .poll_interval_seconds = 120U,
                       .priority = 1U},
                  now) &&
              nbma_second.add_nbma_neighbor(
                  1U, {.address = second_peer,
                       .poll_interval_seconds = 120U,
                       .priority = 1U},
                  now),
          "NBMA owner rejected a valid configured peer set");
  std::array<ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      nbma_output{};
  std::size_t nbma_written{};
  require(nbma_first.run_ready(now, nbma_output, nbma_written),
          "NBMA owner rejected its initial PollInterval turn");
  const auto nbma_hello = std::find_if(
      nbma_output.begin(), nbma_output.begin() + nbma_written,
      [&](const auto &packet) {
        return packet.destination == PacketDestination::neighbor_unicast &&
               packet.ipv4_destination ==
                   router::ip::Ipv4{192U, 0U, 2U, 2U};
      });
  require(nbma_hello != nbma_output.begin() + nbma_written,
          "NBMA Hello was not unicasted to its configured transport peer");
  require(nbma_second.receive_ipv4_packet(
              1U,
              std::span<const std::uint8_t>{nbma_hello->bytes}.first(
                  nbma_hello->size),
              router::ip::Ipv4{192U, 0U, 2U, 1U},
              nbma_hello->ipv4_destination,
              now) == ReceiveStatus::accepted &&
              nbma_second.receive_ipv4_packet(
                  1U,
                  std::span<const std::uint8_t>{nbma_hello->bytes}.first(
                      nbma_hello->size),
                  router::ip::Ipv4{192U, 0U, 2U, 99U},
                  nbma_hello->ipv4_destination, now) ==
                  ReceiveStatus::neighbor_not_found,
          "NBMA receive path did not enforce the configured neighbor table");

  // LSRefreshTime is a local steady-clock deadline, not a global simulation
  // event. An isolated passive interface is sufficient to originate one
  // Router-LSA, then prove that the same owner refreshes it with a newer
  // sequence after the sourced 1800-second interval.
  InstanceProcess refresh_owner{
      0x11111111U, 0U, router::packet::ospf::version_two, 0U,
      0x01020304U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto refresh_interface =
      interface_configuration(0x11111111U, 0xcb007101U, 0U);
  refresh_interface.protocol.passive = true;
  refresh_interface.physical_port_ordinal = no_physical_port;
  refresh_interface.prefix_length = 32U;
  std::array<ProcessOutput, 2U> refresh_output{};
  std::size_t refresh_written{};
  require(refresh_owner.add_interface(refresh_interface, now) &&
              refresh_owner.run_ready(now, refresh_output,
                                      refresh_written),
          "isolated OSPF owner could not originate its initial LSDB");
  const auto initial_refresh_header =
      router::packet::ospf::lsa_header(
          refresh_owner.database().records().front().bytes,
          router::packet::ospf::version_two);
  require(initial_refresh_header &&
              initial_refresh_header->sequence_number ==
                  initial_sequence_number,
          "initial self-originated Router-LSA used the wrong sequence");
  const auto refresh_now = now + router::device_catalog::ospf_lsa_refresh;
  require(refresh_owner.next_deadline() &&
              *refresh_owner.next_deadline() <= refresh_now &&
              refresh_owner.run_ready(refresh_now, refresh_output,
                                      refresh_written),
          "LSRefreshTime did not wake the owning process");
  const auto refreshed_header =
      router::packet::ospf::lsa_header(
          refresh_owner.database().records().front().bytes,
          router::packet::ospf::version_two);
  require(refreshed_header &&
              refreshed_header->sequence_number ==
                  initial_sequence_number + 1 &&
              refresh_owner.database().records().front().age(refresh_now) ==
                  0U,
          "LSRefreshTime did not publish a younger Router-LSA generation");

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

  // Graceful-restart assistance is exercised through an actual Grace-LSA in
  // an LSU, never by editing the neighbor repository. The helper keeps an
  // already Full adjacency beyond DeadInterval and releases it precisely at
  // the remaining grace deadline.
  InstanceProcess helper{
      0x07070707U, 0U, router::packet::ospf::version_two, 0U,
      0x70707070U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess restarting{
      0x08080808U, 0U, router::packet::ospf::version_two, 0U,
      0x80808080U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  helper.set_graceful_restart_helper(true);
  require(helper.add_interface(
              interface_configuration(0x07070707U, 0xc0000207U, 0U),
              now) &&
              restarting.add_interface(
                  interface_configuration(0x08080808U, 0xc0000208U, 0U),
                  now),
          "graceful-restart peers rejected valid interfaces");
  deliver_ready(helper, restarting, {{192U, 0U, 2U, 7U}}, now);
  deliver_ready(restarting, helper, {{192U, 0U, 2U, 8U}}, now);
  const auto helper_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (helper.neighbor_state(1U, 0x08080808U) !=
            NeighborState::full ||
        restarting.neighbor_state(1U, 0x07070707U) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(helper, restarting, {{192U, 0U, 2U, 7U}},
                  helper_convergence);
    deliver_ready(restarting, helper, {{192U, 0U, 2U, 8U}},
                  helper_convergence);
  }
  require(helper.neighbor_state(1U, 0x08080808U) ==
              NeighborState::full,
          "graceful-restart fixture did not establish Full adjacency");

  std::array<std::uint8_t, 44U> grace_lsa{};
  const auto put16 = [](std::span<std::uint8_t> bytes,
                        std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value);
  };
  const auto put32 = [](std::span<std::uint8_t> bytes,
                        std::size_t offset, std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value);
  };
  put16(grace_lsa, 0U, 0U);
  grace_lsa[2U] = static_cast<std::uint8_t>(
      router::packet::ospf::option_opaque_capability);
  grace_lsa[3U] = static_cast<std::uint8_t>(
      router::packet::ospf::lsa::version_two_link_opaque_type);
  put32(grace_lsa, 4U,
        static_cast<std::uint32_t>(
            router::packet::ospf::lsa::
                version_two_grace_opaque_type)
            << 24U);
  put32(grace_lsa, 8U, 0x08080808U);
  put32(grace_lsa, 12U,
        static_cast<std::uint32_t>(initial_sequence_number));
  put16(grace_lsa, 18U,
        static_cast<std::uint16_t>(grace_lsa.size()));
  put16(grace_lsa, 20U, 1U);
  put16(grace_lsa, 22U, 4U);
  put32(grace_lsa, 24U, 120U);
  put16(grace_lsa, 28U, 2U);
  put16(grace_lsa, 30U, 1U);
  grace_lsa[32U] = static_cast<std::uint8_t>(
      router::packet::ospf::lsa::GraceRestartReason::software_restart);
  put16(grace_lsa, 36U, 3U);
  put16(grace_lsa, 38U, 4U);
  put32(grace_lsa, 40U, 0xc0000208U);
  require(update_lsa_checksum(grace_lsa),
          "Grace-LSA fixture checksum failed");
  const std::array grace_advertisements{
      router::packet::ospf::EncodedLsa{
          .bytes = grace_lsa}};
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      grace_payload_storage{};
  const auto grace_payload =
      router::packet::ospf::encode_link_state_update_payload(
          grace_payload_storage, router::packet::ospf::version_two,
          grace_advertisements);
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      grace_packet_storage{};
  constexpr std::array<std::uint8_t, 8U> grace_null_authentication{};
  const auto grace_packet =
      grace_payload
          ? router::packet::ospf::encode_version_two(
                grace_packet_storage,
                router::packet::ospf::PacketType::link_state_update,
                0x08080808U, 0U,
                router::packet::ospf::AuthenticationType::none,
                grace_null_authentication, *grace_payload)
          : std::nullopt;
  require(grace_packet &&
              helper.receive_ipv4_packet(
                  1U, *grace_packet, {{192U, 0U, 2U, 8U}},
                  router::packet::ospf::all_spf_routers_v4,
                  helper_convergence) == ReceiveStatus::accepted,
          "valid Grace-LSA did not enter helper processing");
  // Continuity restore must retain the live Full adjacency, Grace-LSA,
  // exchange repositories and remaining helper deadline. Derived routes are
  // rebuilt from the restored LSDB rather than trusted as serialized output.
  const auto helper_checkpoint = helper.checkpoint(helper_convergence);
  InstanceProcess restored_helper{
      0x07070707U, 0U, router::packet::ospf::version_two, 0U,
      0x70707070U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(restored_helper.restore(helper_checkpoint, helper_convergence) &&
              restored_helper.neighbor_state(1U, 0x08080808U) ==
                  NeighborState::full &&
              restored_helper.database().records().size() ==
                  helper.database().records().size(),
          "OSPF continuity restore lost live adjacency or LSDB state");
  std::array<ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      helper_output{};
  const auto after_dead =
      helper_convergence + std::chrono::seconds{41U};
  require(helper.run_ready(after_dead, helper_output, written) &&
              helper.neighbor_state(1U, 0x08080808U) ==
                  NeighborState::full,
          "helper released Full adjacency at ordinary DeadInterval");
  const auto after_grace =
      helper_convergence + std::chrono::seconds{121U};
  require(helper.run_ready(after_grace, helper_output, written) &&
              helper.neighbor_state(1U, 0x08080808U) !=
                  NeighborState::full,
          "helper retained adjacency after Grace-LSA expiry");
  require(restored_helper.run_ready(after_grace, helper_output, written) &&
              restored_helper.neighbor_state(1U, 0x08080808U) !=
                  NeighborState::full,
          "restored helper did not preserve the remaining grace deadline");

  // A committed configuration generation constructs a fresh process while
  // the remote router can still retain its prior Full adjacency. Exercise
  // that asymmetric restart using encoded Hellos and DD packets. The peer
  // must follow OneWayReceived or SeqNumberMismatch back through ExStart and
  // reconverge without a management-plane neighbor reset.
  InstanceProcess generation_a{
      0x0a0a0a0aU, 0U, router::packet::ospf::version_two, 0U,
      0xa0a0a0a0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess generation_b{
      0x0b0b0b0bU, 0U, router::packet::ospf::version_two, 0U,
      0xb0b0b0b0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  const auto generation_a_interface =
      interface_configuration(0x0a0a0a0aU, 0xc000020aU, 0U);
  const auto generation_b_interface =
      interface_configuration(0x0b0b0b0bU, 0xc000020bU, 0U);
  require(generation_a.add_interface(generation_a_interface, now) &&
              generation_b.add_interface(generation_b_interface, now),
          "generation-replacement fixture rejected valid interfaces");
  // The first Hello creates Init state on each side. The next periodic Hello
  // carries the learned Router ID and is what makes the relationship 2-Way.
  deliver_ready(generation_a, generation_b, {{192U, 0U, 2U, 10U}}, now);
  deliver_ready(generation_b, generation_a, {{192U, 0U, 2U, 11U}}, now);
  const auto initial_generation_convergence =
      now + router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets &&
       (generation_a.neighbor_state(1U, 0x0b0b0b0bU) !=
            NeighborState::full ||
        generation_b.neighbor_state(1U, 0x0a0a0a0aU) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(generation_a, generation_b, {{192U, 0U, 2U, 10U}},
                  initial_generation_convergence);
    deliver_ready(generation_b, generation_a, {{192U, 0U, 2U, 11U}},
                  initial_generation_convergence);
  }
  require(generation_a.neighbor_state(1U, 0x0b0b0b0bU) ==
                  NeighborState::full &&
              generation_b.neighbor_state(1U, 0x0a0a0a0aU) ==
                  NeighborState::full,
          "generation-replacement fixture did not establish Full");

  InstanceProcess replacement_a{
      0x0a0a0a0aU, 0U, router::packet::ospf::version_two, 0U,
      0xc0c0c0c0U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(replacement_a.add_interface(generation_a_interface,
                                      initial_generation_convergence),
          "fresh committed generation rejected the unchanged interface");
  // Deliver the replacement's neighbor-less first Hello while the peer still
  // owns its old Full row. This is the exact asymmetric state transition that
  // a live configuration commit creates.
  deliver_ready(replacement_a, generation_b,
                {{192U, 0U, 2U, 10U}}, initial_generation_convergence);
  const auto replacement_convergence =
      initial_generation_convergence +
      router::device_catalog::ospf_hello_interval;
  for (std::size_t turn{};
       turn < router::device_catalog::ospf_work_budget_packets * 2U &&
       (replacement_a.neighbor_state(1U, 0x0b0b0b0bU) !=
            NeighborState::full ||
       generation_b.neighbor_state(1U, 0x0a0a0a0aU) !=
            NeighborState::full);
       ++turn) {
    deliver_ready(generation_b, replacement_a,
                  {{192U, 0U, 2U, 11U}}, replacement_convergence);
    deliver_ready(replacement_a, generation_b,
                  {{192U, 0U, 2U, 10U}}, replacement_convergence);
  }
  const auto replacement_a_state =
      replacement_a.neighbor_state(1U, 0x0b0b0b0bU);
  const auto generation_b_state =
      generation_b.neighbor_state(1U, 0x0a0a0a0aU);
  if (replacement_a_state != NeighborState::full ||
      generation_b_state != NeighborState::full) {
    const auto replacement_checkpoint =
        replacement_a.checkpoint(replacement_convergence);
    const auto retained_checkpoint =
        generation_b.checkpoint(replacement_convergence);
    const auto &replacement_exchange =
        replacement_checkpoint.interfaces.front().exchanges.front();
    const auto &retained_exchange =
        retained_checkpoint.interfaces.front().exchanges.front();
    throw std::runtime_error(
        "fresh OSPF generation required a manual neighbor reset; fresh=" +
        std::to_string(replacement_a_state
                           ? static_cast<unsigned>(*replacement_a_state)
                           : 255U) +
        " retained=" +
        std::to_string(generation_b_state
                           ? static_cast<unsigned>(*generation_b_state)
                           : 255U) +
        " fresh-requests=" +
        std::to_string(replacement_exchange.database.requests.size()) +
        " fresh-pending-request=" +
        std::to_string(replacement_exchange.pending_request) +
        " fresh-request-cursor=" +
        std::to_string(replacement_exchange.request_cursor) +
        " retained-retransmissions=" +
        std::to_string(retained_exchange.database.retransmissions.size()) +
        " retained-pending-update=" +
        std::to_string(retained_exchange.pending_update));
  }
}
