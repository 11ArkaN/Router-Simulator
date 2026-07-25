// LSA body tests use byte fixtures for variable OSPFv2 router links and OSPFv3
// router, network and prefix records, including malformed trailing data.

#include "router/ospf_lsa.hpp"
#include "router/ospf_lsdb.hpp"

#include <array>
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

template <std::size_t Size>
void header(std::array<std::uint8_t, Size> &bytes, std::uint16_t type) {
  write16(bytes, 0U, 1U);
  write16(bytes, 2U, type);
  write32(bytes, 4U, 10U);
  write32(bytes, 8U, 0x01010101U);
  write32(bytes, 12U, 0x80000001U);
  write16(bytes, 18U, static_cast<std::uint16_t>(Size));
  if (!router::ospf::update_lsa_checksum(bytes))
    throw std::runtime_error("LSA fixture checksum failed");
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_lsa_tests() {
  namespace lsa = router::packet::ospf::lsa;

  std::array<std::uint8_t, 40U> router_v2{};
  router_v2[20U] = 0x03U;
  write16(router_v2, 22U, 1U);
  write32(router_v2, 24U, 0x02020202U);
  write32(router_v2, 28U, 0x0a000001U);
  router_v2[32U] = 1U;
  router_v2[33U] = 1U;
  write16(router_v2, 34U, 10U);
  router_v2[36U] = 1U;
  write16(router_v2, 38U, 20U);
  header(router_v2, 1U);
  const auto parsed_v2 = lsa::parse_version_two_router(router_v2);
  const auto link_v2 =
      parsed_v2 ? lsa::version_two_router_link(*parsed_v2, 0U) : std::nullopt;
  require(parsed_v2 && parsed_v2->area_border_router &&
              parsed_v2->autonomous_system_boundary_router && link_v2 &&
              link_v2->link_id == 0x02020202U && link_v2->metric == 10U &&
              link_v2->next_offset == 16U,
          "OSPFv2 Router-LSA link decoding failed");

  std::array<std::uint8_t, 40U> router_v3{};
  router_v3[20U] = 0x01U;
  router_v3[21U] = 0x00U;
  router_v3[22U] = 0x00U;
  router_v3[23U] = 0x13U;
  router_v3[24U] = 1U;
  write16(router_v3, 26U, 15U);
  write32(router_v3, 28U, 7U);
  write32(router_v3, 32U, 8U);
  write32(router_v3, 36U, 0x02020202U);
  header(router_v3, 0x2001U);
  const auto parsed_v3 = lsa::parse_version_three_router(router_v3);
  const auto link_v3 =
      parsed_v3 ? lsa::version_three_router_link(*parsed_v3, 0U)
                : std::nullopt;
  require(parsed_v3 && parsed_v3->options == 0x13U && link_v3 &&
              link_v3->interface_id == 7U &&
              link_v3->neighbor_interface_id == 8U &&
              link_v3->neighbor_router_id == 0x02020202U &&
              link_v3->metric == 15U,
          "OSPFv3 Router-LSA link decoding failed");

  std::array<std::uint8_t, 44U> prefix_v3{};
  write16(prefix_v3, 20U, 1U);
  write16(prefix_v3, 22U, 0x2001U);
  write32(prefix_v3, 24U, 10U);
  write32(prefix_v3, 28U, 0x01010101U);
  prefix_v3[32U] = 64U;
  prefix_v3[33U] = 0x02U;
  write16(prefix_v3, 34U, 20U);
  prefix_v3[36U] = 0x20U;
  prefix_v3[37U] = 0x01U;
  prefix_v3[38U] = 0x0dU;
  prefix_v3[39U] = 0xb8U;
  header(prefix_v3, 0x2009U);
  const auto parsed_prefix =
      lsa::parse_version_three_intra_area_prefix(prefix_v3);
  const auto prefix =
      parsed_prefix
          ? lsa::version_three_prefix(parsed_prefix->prefixes, 0U, true)
          : std::nullopt;
  const auto expanded = prefix ? lsa::expand_prefix(*prefix) : std::nullopt;
  require(parsed_prefix && prefix && prefix->metric == 20U && expanded &&
              (*expanded)[0U] == 0x20U && (*expanded)[1U] == 0x01U &&
              (*expanded)[2U] == 0x0dU && (*expanded)[3U] == 0xb8U,
          "OSPFv3 Intra-Area-Prefix-LSA decoding failed");

  std::array<std::uint8_t, 28U> summary_v2{};
  write32(summary_v2, 20U, 0xffffff00U);
  summary_v2[24U] = 0U;
  summary_v2[25U] = 0U;
  summary_v2[26U] = 0U;
  summary_v2[27U] = 50U;
  header(summary_v2, 3U);
  const auto summary = lsa::parse_version_two_summary(summary_v2);
  require(summary && summary->network_mask == 0xffffff00U &&
              summary->metric == 50U &&
              !summary->autonomous_system_boundary_router,
          "OSPFv2 Summary-LSA decoding failed");

  std::array<std::uint8_t, 36U> external_v2{};
  write32(external_v2, 20U, 0xffffff00U);
  write32(external_v2, 24U, 0x80000064U);
  write32(external_v2, 28U, 0x0a000001U);
  write32(external_v2, 32U, 65001U);
  header(external_v2, 5U);
  const auto external = lsa::parse_version_two_external(external_v2);
  require(external && external->type_two_metric &&
              external->metric == 100U &&
              external->forwarding_address == 0x0a000001U &&
              external->route_tag == 65001U,
          "OSPFv2 AS-External-LSA decoding failed");

  std::array<std::uint8_t, 56U> external_v3{};
  write32(external_v3, 20U, 0xe0000064U);
  external_v3[24U] = 64U;
  external_v3[25U] = 0U;
  write16(external_v3, 26U, 0U);
  external_v3[28U] = 0x20U;
  external_v3[29U] = 0x01U;
  external_v3[30U] = 0x0dU;
  external_v3[31U] = 0xb8U;
  external_v3[36U] = 0xfeU;
  external_v3[37U] = 0x80U;
  external_v3[51U] = 1U;
  write32(external_v3, 52U, 65002U);
  header(external_v3, 0x4005U);
  const auto parsed_external_v3 =
      lsa::parse_version_three_external(external_v3, false);
  require(parsed_external_v3 && parsed_external_v3->type_two_metric &&
              parsed_external_v3->metric == 100U &&
              parsed_external_v3->forwarding_address.size() == 16U &&
              parsed_external_v3->route_tag == 65002U,
          "OSPFv3 AS-External-LSA optional fields failed");

  // RFC 3623 Appendix A requires Grace Period and Restart Reason and requires
  // the interface address on the multi-access OSPFv2 use case. The opaque
  // identity is part of the test because accepting the same body under a
  // different Type 9 application would let an unrelated extension suppress
  // the neighbor inactivity timer.
  std::array<std::uint8_t, 44U> grace_v2{};
  write16(grace_v2, 20U, 1U);
  write16(grace_v2, 22U, 4U);
  write32(grace_v2, 24U, 120U);
  write16(grace_v2, 28U, 2U);
  write16(grace_v2, 30U, 1U);
  grace_v2[32U] = static_cast<std::uint8_t>(
      lsa::GraceRestartReason::software_reload);
  write16(grace_v2, 36U, 3U);
  write16(grace_v2, 38U, 4U);
  write32(grace_v2, 40U, 0xc0000201U);
  header(grace_v2, lsa::version_two_link_opaque_type);
  write32(grace_v2, 4U,
          static_cast<std::uint32_t>(
              lsa::version_two_grace_opaque_type)
              << 24U);
  require(router::ospf::update_lsa_checksum(grace_v2),
          "OSPFv2 Grace-LSA checksum update failed");
  const auto parsed_grace_v2 =
      lsa::parse_grace_lsa(grace_v2, router::packet::ospf::version_two);
  require(parsed_grace_v2 &&
              parsed_grace_v2->grace_period_seconds == 120U &&
              parsed_grace_v2->reason ==
                  lsa::GraceRestartReason::software_reload &&
              parsed_grace_v2->interface_address == 0xc0000201U,
          "OSPFv2 Grace-LSA required TLVs failed");

  // RFC 5187 removes the interface-address TLV and identifies the link-scoped
  // Grace-LSA with LS type 0x000b. Padding after the one-octet reason remains
  // part of the shared TLV format and must not become a second fake TLV.
  std::array<std::uint8_t, 36U> grace_v3{};
  write16(grace_v3, 20U, 1U);
  write16(grace_v3, 22U, 4U);
  write32(grace_v3, 24U, 300U);
  write16(grace_v3, 28U, 2U);
  write16(grace_v3, 30U, 1U);
  grace_v3[32U] = static_cast<std::uint8_t>(
      lsa::GraceRestartReason::redundant_control_processor);
  header(grace_v3, lsa::version_three_grace_type);
  const auto parsed_grace_v3 =
      lsa::parse_grace_lsa(grace_v3, router::packet::ospf::version_three);
  require(parsed_grace_v3 &&
              parsed_grace_v3->grace_period_seconds == 300U &&
              parsed_grace_v3->reason ==
                  lsa::GraceRestartReason::redundant_control_processor &&
              !parsed_grace_v3->interface_address,
          "OSPFv3 Grace-LSA required TLVs failed");

  auto duplicate_period = grace_v3;
  write16(duplicate_period, 28U, 1U);
  write16(duplicate_period, 30U, 4U);
  write32(duplicate_period, 32U, 10U);
  require(router::ospf::update_lsa_checksum(duplicate_period) &&
              !lsa::parse_grace_lsa(duplicate_period,
                                    router::packet::ospf::version_three),
          "Grace-LSA duplicate required TLV was accepted");

  auto malformed = router_v2;
  malformed[33U] = 2U;
  header(malformed, 1U);
  require(!lsa::parse_version_two_router(malformed),
          "truncated OSPFv2 TOS metric was accepted");
}
