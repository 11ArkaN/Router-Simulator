// SAP forwarding tests use exact frame bytes to prove that classification is
// driven by physical port plus configured TPIDs and VIDs, that logical service
// identity is independent from port ordinal, and that failed programming is
// atomic.

#include "router/sap_forwarding.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void sap_forwarding_tests() {
  using namespace router;
  using namespace router::service;

  constexpr PhysicalPortCoordinate physical{7U, 1U, 1U, 8U};
  constexpr std::array<SapAttachment, 2U> attachments{{
      {.logical_interface_id = 0x100000001ULL,
       .sap = {physical, EthernetEncapsulation::qinq,
               std::uint16_t{200U}, std::uint16_t{300U}},
       .outer_tpid = 0x9100U,
       .inner_tpid = packet::ethernet_type_customer_vlan},
      {.logical_interface_id = 0x100000002ULL,
       .sap = {physical, EthernetEncapsulation::qinq,
               std::uint16_t{200U}, std::uint16_t{301U}},
       .outer_tpid = 0x9100U,
       .inner_tpid = packet::ethernet_type_customer_vlan}}};

  SapForwardingTable table{};
  if (table.replace(attachments) != SapProgramStatus::accepted)
    throw std::runtime_error("valid custom-TPID SAP generation was rejected");

  const auto global = ip::parse_ipv6("2001:db8:7::1");
  const auto network = ip::parse_ipv6("2001:db8:7::");
  const auto link_local = ip::parse_ipv6("fe80::7");
  if (!global || !network || !link_local)
    throw std::runtime_error("service interface fixture address is invalid");
  const std::array<ServiceIpv6Interface, 2U> interfaces{{
      {.interface_id = attachments[0].logical_interface_id,
       .physical_port_ordinal = physical.ordinal,
       .mtu = 1500U,
       .mac = {0x02U, 0U, 0U, 0U, 7U, 1U},
       .address = *global,
       .network = *network,
       .link_local = *link_local,
       .prefix_length = 64U,
       .nd_reachable_time_milliseconds = 30'000U,
       .nd_stale_time_seconds = 14'400U,
       .neighbor_limit_threshold_percent = 90U,
       .redirect_maximum = 10U,
       .redirect_interval_seconds = 1U,
       .redirects_enabled = true,
       .configured = true,
       .operational = true},
      {.interface_id = attachments[1].logical_interface_id,
       .physical_port_ordinal = physical.ordinal,
       .mtu = 1500U,
       .mac = {0x02U, 0U, 0U, 0U, 7U, 2U},
       .address = *global,
       .network = *network,
       .link_local = *link_local,
       .prefix_length = 64U,
       .nd_reachable_time_milliseconds = 30'000U,
       .nd_stale_time_seconds = 14'400U,
       .neighbor_limit_threshold_percent = 90U,
       .redirect_maximum = 10U,
       .redirect_interval_seconds = 1U,
       .redirects_enabled = true,
       .configured = true,
       .operational = true}}};
  if (table.replace(attachments, interfaces) != SapProgramStatus::accepted ||
      !table.find_interface(attachments[1].logical_interface_id) ||
      table.find_interface(attachments[1].logical_interface_id)
              ->physical_port_ordinal != physical.ordinal)
    throw std::runtime_error(
        "atomic SAP and routed-interface generation was rejected");

  auto incomplete_interfaces = interfaces;
  incomplete_interfaces[1].interface_id = 0x100000003ULL;
  if (table.replace(attachments, incomplete_interfaces) !=
          SapProgramStatus::incomplete_service_generation ||
      !table.find_interface(attachments[1].logical_interface_id))
    throw std::runtime_error(
        "incomplete service generation changed the published table");

  constexpr packet::Mac source{0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U};
  constexpr packet::Ipv4 source_ip{192U, 0U, 2U, 1U};
  constexpr packet::Ipv4 target_ip{192U, 0U, 2U, 2U};
  const auto internal = packet::arp_request(source, source_ip, target_ip);

  packet::Frame wire{};
  const SapVlanMarking transmit_marking{
      .outer_priority_code_point = 5U,
      .outer_drop_eligible = true,
      .inner_priority_code_point = 2U,
      .inner_drop_eligible = false};
  if (!table.egress(0x100000002ULL, internal, transmit_marking, wire) ||
      wire.length != internal.length + 8U || wire.bytes[12] != 0x91U ||
      wire.bytes[13] != 0x00U || wire.bytes[16] != 0x81U ||
      wire.bytes[17] != 0x00U)
    throw std::runtime_error("custom-TPID QinQ egress envelope was invalid");

  packet::Frame restored{};
  const auto classified = table.ingress(physical.ordinal, wire, restored);
  if (classified.status != SapIngressStatus::matched ||
      classified.logical_interface_id != 0x100000002ULL ||
      classified.received_marking.outer_priority_code_point != 5U ||
      !classified.received_marking.outer_drop_eligible ||
      classified.received_marking.inner_priority_code_point != 2U ||
      classified.received_marking.inner_drop_eligible ||
      restored.length != internal.length ||
      !std::equal(restored.bytes.begin(),
                  restored.bytes.begin() + restored.length,
                  internal.bytes.begin()))
    throw std::runtime_error("SAP ingress did not restore exact routed frame");

  auto unknown_vlan = wire;
  unknown_vlan.bytes[19] = 0x2fU;
  if (table.ingress(physical.ordinal, unknown_vlan, restored).status !=
      SapIngressStatus::no_match)
    throw std::runtime_error("unconfigured inner VLAN selected a service");

  auto extra_tag = wire;
  // Replacing the final ARP EtherType with another known tag marker is enough
  // to prove that a three-tag frame cannot match the configured two-tag SAP.
  extra_tag.bytes[20] = 0x81U;
  extra_tag.bytes[21] = 0x00U;
  if (table.ingress(physical.ordinal, extra_tag, restored).status !=
      SapIngressStatus::no_match)
    throw std::runtime_error("extra VLAN tag matched a shorter SAP");

  auto duplicate = attachments;
  duplicate[1].sap.inner_vlan = std::uint16_t{300U};
  if (table.replace(duplicate) != SapProgramStatus::duplicate_sap ||
      !table.find_logical(0x100000002ULL))
    throw std::runtime_error("failed SAP replacement changed live generation");

  if (table.ingress(physical.ordinal + 1U, wire, restored).status !=
      SapIngressStatus::no_match)
    throw std::runtime_error("SAP classification ignored physical ingress");
}
