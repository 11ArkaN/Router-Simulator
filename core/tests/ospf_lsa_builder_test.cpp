// LSA origination tests round-trip emitted bytes through the independent
// parsers and verify Fletcher checksums for both protocol versions.

#include "router/ospf_lsa_builder.hpp"

#include "router/ospf_lsdb.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_lsa_builder_tests() {
  using namespace router::packet::ospf;
  using namespace router::packet::ospf::lsa;
  std::array<std::uint8_t, 512U> storage{};
  const OriginationHeader v2{
      .link_state_id = 0x01010101U,
      .advertising_router = 0x01010101U,
      .sequence_number = router::ospf::initial_sequence_number,
      .type = 1U,
      .options = 0x02U,
      .version = version_two};
  const std::array links{
      VersionTwoRouterLinkInput{.link_id = 0x02020202U,
                                .link_data = 0x0a000001U,
                                .metric = 10U,
                                .type = RouterLinkType::point_to_point},
      VersionTwoRouterLinkInput{.link_id = 0xc0000200U,
                                .link_data = 0xffffff00U,
                                .metric = 5U,
                                .type = RouterLinkType::stub_network}};
  const auto router_lsa = encode_version_two_router_lsa(
      storage, v2, links, false, false, false);
  const auto parsed_router =
      router_lsa ? parse_version_two_router(*router_lsa) : std::nullopt;
  require(router_lsa && router::ospf::verify_lsa_checksum(*router_lsa) &&
              parsed_router && parsed_router->link_count == 2U,
          "OSPFv2 Router-LSA did not round-trip");

  const OriginationHeader v3{
      .link_state_id = 7U,
      .advertising_router = 0x01010101U,
      .sequence_number = router::ospf::initial_sequence_number,
      .type = 0x2008U,
      .version = version_three};
  router::ip::Ipv6 link_local{
      {0xfeU, 0x80U, 0U, 0U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}};
  router::ip::Ipv6 network{
      {0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
       0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}};
  const std::array prefixes{
      PrefixInput{.network = network, .metric = 10U, .length = 64U}};
  const auto link_lsa = encode_version_three_link_lsa(
      storage, v3, 1U, 0x13U, link_local, prefixes);
  const auto parsed_link =
      link_lsa ? parse_version_three_link(*link_lsa) : std::nullopt;
  require(link_lsa && router::ospf::verify_lsa_checksum(*link_lsa) &&
              parsed_link && parsed_link->link_local_address == link_local &&
              parsed_link->prefix_count == 1U,
          "OSPFv3 Link-LSA did not round-trip");

  const std::array version_three_links{
      VersionThreeRouterLinkInput{
          .interface_id = 1U,
          .neighbor_interface_id = 1U,
          .neighbor_router_id = 0x02020202U,
          .metric = 10U,
          .type = RouterLinkType::point_to_point}};
  const auto linked_router_lsa = encode_version_three_router_lsa(
      storage,
      {.link_state_id = 0U,
       .advertising_router = 0x01010101U,
       .sequence_number = router::ospf::initial_sequence_number + 1,
       .age_seconds = 0U,
       .type = version_three_router_type,
       .options = option_external_routing_capability |
                  option_address_family | option_ospfv3_router,
       .version = version_three},
      version_three_links, 0U,
      option_external_routing_capability | option_address_family |
          option_ospfv3_router);
  require(linked_router_lsa &&
              router::ospf::verify_lsa_checksum(*linked_router_lsa),
          "OSPFv3 Router-LSA checksum failed after adding a real link");

  // RFC 5838 section 2.5 gives the same field different address-family
  // semantics. An IPv4 AF peer advertises its Direct Interface Address in the
  // first four octets and zeroes the remaining twelve. Parsing it as ordinary
  // IPv6 must fail, while parsing it in the owning AF must return the exact
  // bytes used later for ARP next-hop resolution.
  router::ip::Ipv6 ipv4_direct_interface_address{};
  ipv4_direct_interface_address[0U] = 192U;
  ipv4_direct_interface_address[1U] = 0U;
  ipv4_direct_interface_address[2U] = 2U;
  ipv4_direct_interface_address[3U] = 9U;
  const auto ipv4_af_link_lsa = encode_version_three_link_lsa(
      storage, v3, 1U, option_address_family | option_ospfv3_router,
      ipv4_direct_interface_address, {});
  const auto parsed_ipv4_af_link =
      ipv4_af_link_lsa
          ? parse_version_three_link(*ipv4_af_link_lsa, true)
          : std::nullopt;
  require(ipv4_af_link_lsa && parsed_ipv4_af_link &&
              parsed_ipv4_af_link->link_local_address ==
                  ipv4_direct_interface_address &&
              !parse_version_three_link(*ipv4_af_link_lsa, false),
          "OSPFv3 IPv4-AF Link-LSA did not preserve its Direct Interface "
          "Address semantics");

  auto noncanonical_ipv4_af_address = ipv4_direct_interface_address;
  noncanonical_ipv4_af_address[15U] = 1U;
  const auto invalid_ipv4_af_link_lsa = encode_version_three_link_lsa(
      storage, v3, 1U, option_address_family | option_ospfv3_router,
      noncanonical_ipv4_af_address, {});
  require(invalid_ipv4_af_link_lsa &&
              !parse_version_three_link(*invalid_ipv4_af_link_lsa, true),
          "OSPFv3 IPv4-AF accepted nonzero bits outside its first 32 bits");

  const OriginationHeader inter_area_header{
      .link_state_id = 9U,
      .advertising_router = 0x01010101U,
      .sequence_number = router::ospf::initial_sequence_number,
      .type = 0x2003U,
      .version = version_three};
  const auto inter_area = encode_version_three_inter_area_prefix_lsa(
      storage, inter_area_header, 25U, prefixes.front());
  const auto parsed_inter_area =
      inter_area ? parse_version_three_inter_area_prefix(*inter_area)
                 : std::nullopt;
  require(inter_area && router::ospf::verify_lsa_checksum(*inter_area) &&
              parsed_inter_area && parsed_inter_area->metric == 25U &&
              parsed_inter_area->prefix.length == 64U,
          "OSPFv3 Inter-Area-Prefix-LSA did not round-trip");

  const OriginationHeader external_header{
      .link_state_id = 10U,
      .advertising_router = 0x01010101U,
      .sequence_number = router::ospf::initial_sequence_number,
      .type = 0x4005U,
      .version = version_three};
  const std::array<std::uint8_t, 16U> forwarding{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U,    0U,    0U,    0U,    0U, 0U, 0U, 2U};
  const auto external = encode_version_three_external_lsa(
      storage, external_header, 50U, true, prefixes.front(), forwarding,
      std::uint32_t{77U}, 0x2001U, std::uint32_t{11U});
  const auto parsed_external =
      external ? parse_version_three_external(*external, false)
               : std::nullopt;
  require(external && router::ospf::verify_lsa_checksum(*external) &&
              parsed_external && parsed_external->type_two_metric &&
              parsed_external->metric == 50U &&
              parsed_external->forwarding_address.size() == 16U &&
              parsed_external->route_tag == 77U &&
              parsed_external->referenced_link_state_id == 11U,
          "OSPFv3 AS-External-LSA did not round-trip");

  // Bits 1 and 2 advertise only the helper and stub-router capabilities that
  // this process actually implements. Bit zero remains clear because the
  // selected release scope implements helper behavior, not restarting-router
  // behavior.
  constexpr std::uint32_t capabilities = 0x60000000U;
  const auto ri_v2 = encode_router_information_lsa(
      storage,
      {.link_state_id =
           static_cast<std::uint32_t>(
               version_two_router_information_opaque_type)
           << 24U,
       .advertising_router = 0x01010101U,
       .sequence_number = router::ospf::initial_sequence_number,
       .type = version_two_area_opaque_type,
       .version = version_two},
      capabilities);
  const auto parsed_ri_v2 =
      ri_v2 ? parse_router_information_lsa(*ri_v2, version_two)
            : std::nullopt;
  require(ri_v2 && router::ospf::verify_lsa_checksum(*ri_v2) &&
              parsed_ri_v2 &&
              parsed_ri_v2->informational_capabilities.size() == 4U &&
              parsed_ri_v2->informational_capabilities[0U] == 0x60U,
          "OSPFv2 Router Information LSA did not round-trip");

  const auto ri_v3 = encode_router_information_lsa(
      storage,
      {.link_state_id = 0U,
       .advertising_router = 0x01010101U,
       .sequence_number = router::ospf::initial_sequence_number,
       .type = version_three_router_information_type,
       .version = version_three},
      capabilities);
  const auto parsed_ri_v3 =
      ri_v3 ? parse_router_information_lsa(*ri_v3, version_three)
            : std::nullopt;
  require(ri_v3 && router::ospf::verify_lsa_checksum(*ri_v3) &&
              parsed_ri_v3 &&
              parsed_ri_v3->informational_capabilities.size() == 4U &&
              parsed_ri_v3->informational_capabilities[0U] == 0x60U,
          "OSPFv3 Router Information LSA did not round-trip");
}
