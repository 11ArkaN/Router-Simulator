// Interface owner tests cover compatible and incompatible Hello processing,
// two-way adjacency, real inactivity deadlines and version-specific output.

#include "router/ospf_interface.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read32(std::span<const std::uint8_t> bytes,
                     std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_interface_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};
  InterfaceRuntime interface{
      InterfaceConfiguration{.router_id = 0x01010101U,
                             .area_id = 0U,
                             .interface_id = 7U,
                             .network_mask = 0xffffff00U,
                             .options = 0x02U,
                             .hello_interval_seconds = 10U,
                             .dead_interval_seconds = 40U,
                             .interface_mtu = 1500U,
                             .router_priority = 1U,
                             .version = router::packet::ospf::version_two,
                             .instance_id = 0U,
                             .network_type = NetworkType::point_to_point,
                             .passive = false,
                             .enabled = true},
      4U, now};
  require(interface.hello_due(now),
          "enabled OSPF interface did not schedule immediate Hello");

  std::array<std::uint8_t, 24U> payload{};
  write32(payload, 0U, 0xffffff00U);
  write16(payload, 4U, 10U);
  payload[6U] = 0x02U;
  payload[7U] = 1U;
  write32(payload, 8U, 40U);
  write32(payload, 20U, 0x01010101U);
  std::array<std::uint8_t, 8U> no_auth{};
  std::array<std::uint8_t, 64U> packet_storage{};
  const auto encoded = router::packet::ospf::encode_version_two(
      packet_storage, router::packet::ospf::PacketType::hello, 0x02020202U,
      0U, router::packet::ospf::AuthenticationType::none, no_auth, payload);
  const auto packet =
      encoded ? router::packet::ospf::parse_packet(*encoded) : std::nullopt;
  require(packet.has_value(), "test Hello packet did not parse");
  const auto accepted = interface.receive_hello(*packet, 2U, now);
  require(accepted.disposition == HelloDisposition::accepted &&
              accepted.state == NeighborState::exstart &&
              interface.neighbors().size() == 1U,
          "compatible point-to-point Hello did not start adjacency");
  std::array<std::uint8_t, 64U> hello_output{};
  const auto hello_payload = interface.encode_hello_payload(hello_output);
  require(hello_payload && hello_payload->size() == 24U,
          "Hello payload did not retain active neighbor in wire list");

  auto wrong_payload = payload;
  write16(wrong_payload, 4U, 5U);
  const auto wrong_encoded = router::packet::ospf::encode_version_two(
      packet_storage, router::packet::ospf::PacketType::hello, 0x03030303U,
      0U, router::packet::ospf::AuthenticationType::none, no_auth,
      wrong_payload);
  const auto wrong_packet =
      wrong_encoded ? router::packet::ospf::parse_packet(*wrong_encoded)
                    : std::nullopt;
  require(wrong_packet &&
              interface.receive_hello(*wrong_packet, 2U, now).disposition ==
                  HelloDisposition::timer_mismatch &&
              interface.neighbors().size() == 1U,
          "timer-mismatched Hello mutated neighbor repository");

  std::array<ExpiredNeighbor, 2U> expired{};
  std::size_t written{};
  require(interface.process_deadlines(now + std::chrono::seconds{40U},
                                      expired, written) &&
              written == 1U &&
              interface.neighbors()[0U].state == NeighborState::down,
          "real inactivity deadline did not tear down neighbor");

  const auto after_expiry = interface.encode_hello_payload(hello_output);
  require(after_expiry && after_expiry->size() == 20U,
          "Down neighbor remained in emitted Hello neighbor list");

  // OSPFv2 DR and BDR fields contain interface IPv4 addresses, while the
  // election tie-break still compares Router IDs. Use deliberately unrelated
  // values so this test cannot pass if either identity is substituted for the
  // other. A neighbor declaring itself BDR ends Waiting immediately, and the
  // resulting election must promote the existing 2-Way relationship into an
  // adjacency through the AdjacencyOk event.
  InterfaceRuntime broadcast{
      InterfaceConfiguration{
          .router_id = 0x01010101U,
          .area_id = 0U,
          .interface_id = 8U,
          .network_mask = 0xffffff00U,
          .local_election_identity = 0x0a000001U,
          .options = 0x02U,
          .hello_interval_seconds = 10U,
          .dead_interval_seconds = 40U,
          .interface_mtu = 1500U,
          .router_priority = 1U,
          .version = router::packet::ospf::version_two,
          .instance_id = 0U,
          .network_type = NetworkType::broadcast,
          .passive = false,
          .enabled = true},
      4U, now};
  auto broadcast_payload = payload;
  write32(broadcast_payload, 12U, 0U);
  write32(broadcast_payload, 16U, 0x0a000002U);
  const auto broadcast_encoded = router::packet::ospf::encode_version_two(
      packet_storage, router::packet::ospf::PacketType::hello, 0x02020202U,
      0U, router::packet::ospf::AuthenticationType::none, no_auth,
      broadcast_payload);
  const auto broadcast_packet =
      broadcast_encoded
          ? router::packet::ospf::parse_packet(*broadcast_encoded)
          : std::nullopt;
  const auto broadcast_hello =
      broadcast_packet
          ? broadcast.receive_hello(*broadcast_packet, 0x0a000002U, now)
          : HelloResult{};
  require(broadcast_hello.disposition == HelloDisposition::accepted &&
              broadcast_hello.state == NeighborState::two_way &&
              broadcast_hello.backup_seen,
          "OSPFv2 BDR declaration did not end the initial Waiting state");
  const auto election_actions =
      broadcast.neighbor_change(broadcast_hello.backup_seen);
  std::array<NeighborReconciliation, 4U> reconciled{};
  std::size_t reconciled_count{};
  require(has_action(election_actions, InterfaceAction::elect_dr_bdr) &&
              broadcast.reconcile_adjacencies(reconciled,
                                              reconciled_count) &&
              reconciled_count == 1U &&
              has_action(reconciled[0U].actions,
                         NeighborAction::begin_database_exchange) &&
              broadcast.neighbors()[0U].state == NeighborState::exstart,
          "DR/BDR election did not reconcile 2-Way adjacency eligibility");
  const auto elected_hello = broadcast.encode_hello_payload(hello_output);
  const auto designated =
      elected_hello ? read32(*elected_hello, 12U) : 0U;
  const auto backup =
      elected_hello ? read32(*elected_hello, 16U) : 0U;
  require(elected_hello && designated != 0U &&
              (designated == 0x0a000001U ||
               designated == 0x0a000002U) &&
              (backup == 0U || backup == 0x0a000001U ||
               backup == 0x0a000002U),
          "OSPFv2 Hello did not publish IPv4 election identities");

  InterfaceRuntime ipv4_af_interface{
      InterfaceConfiguration{
          .router_id = 0x01010101U,
          .area_id = 0U,
          .interface_id = 17U,
          .network_mask = 0U,
          .options = router::packet::ospf::option_external_routing_capability |
                     router::packet::ospf::option_ospfv3_router |
                     router::packet::ospf::option_address_family,
          .hello_interval_seconds = 10U,
          .dead_interval_seconds = 40U,
          .interface_mtu = 1500U,
          .router_priority = 1U,
          .version = router::packet::ospf::version_three,
          .instance_id = 64U,
          .network_type = NetworkType::point_to_point,
          .passive = false,
          .enabled = true},
      4U, now};
  std::array<std::uint8_t, 20U> ipv4_af_hello{};
  write32(ipv4_af_hello, 0U, 18U);
  ipv4_af_hello[4U] = 1U;
  ipv4_af_hello[7U] =
      static_cast<std::uint8_t>(
          router::packet::ospf::option_external_routing_capability |
          router::packet::ospf::option_ospfv3_router);
  write16(ipv4_af_hello, 8U, 10U);
  write16(ipv4_af_hello, 10U, 40U);
  const router::ip::Ipv6 source_v3{
      {0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, 2U}};
  const auto legacy_v3 = router::packet::ospf::encode_version_three(
      packet_storage, router::packet::ospf::PacketType::hello, 0x02020202U,
      0U, 64U, source_v3, router::packet::ospf::all_spf_routers_v6,
      ipv4_af_hello);
  const auto legacy_packet =
      legacy_v3 ? router::packet::ospf::parse_packet(*legacy_v3)
                : std::nullopt;
  require(legacy_packet &&
              ipv4_af_interface.receive_hello(*legacy_packet, 2U, now)
                      .disposition == HelloDisposition::options_mismatch &&
              ipv4_af_interface.neighbors().empty(),
          "OSPFv3 IPv4-AF formed adjacency without the mandatory AF bit");

  ipv4_af_hello[6U] = 0x01U;
  const auto capable_v3 = router::packet::ospf::encode_version_three(
      packet_storage, router::packet::ospf::PacketType::hello, 0x02020202U,
      0U, 64U, source_v3, router::packet::ospf::all_spf_routers_v6,
      ipv4_af_hello);
  const auto capable_packet =
      capable_v3 ? router::packet::ospf::parse_packet(*capable_v3)
                 : std::nullopt;
  require(capable_packet &&
              ipv4_af_interface.receive_hello(*capable_packet, 2U, now)
                      .disposition == HelloDisposition::accepted,
          "OSPFv3 IPv4-AF rejected a compatible AF-capable Hello");
}
