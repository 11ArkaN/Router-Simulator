// ABR coordination tests use only per-area calculated routes and encoded LSAs.
// They prove backbone directionality, stub default origination, summary
// suppression and NSSA translation without exposing editor topology or
// directly installing a route in another process.

#include "router/ospf_area_coordinator.hpp"
#include "router/ospf_lsa_builder.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

router::ospf::CalculatedRoute ipv4_route(
    std::uint32_t network, std::uint8_t length, std::uint32_t metric,
    std::uint32_t area) {
  return {.next_hops = {},
          .loop_free_alternates = {},
          .version_two_network = network,
          .metric = metric,
          .internal_metric = metric,
          .area_id = area,
          .path_type =
              router::lab::routing::OspfPathType::intra_area,
          .prefix_length = length};
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

bool prefix_is(const router::ospf::CoordinatorAdvertisement &item,
               std::uint32_t network, std::uint8_t length) {
  const auto &bytes = item.prefix.network.bytes;
  const auto encoded =
      static_cast<std::uint32_t>(bytes[0U]) << 24U |
      static_cast<std::uint32_t>(bytes[1U]) << 16U |
      static_cast<std::uint32_t>(bytes[2U]) << 8U |
      bytes[3U];
  return encoded == network && item.prefix.length == length;
}

} // namespace

void ospf_area_coordinator_tests() {
  using namespace router::ospf;
  const std::array backbone_routes{
      ipv4_route(0x0a000000U, 24U, 10U, 0U)};
  const std::array area_one_routes{
      ipv4_route(0x0a010000U, 24U, 20U, 1U)};
  const std::array<AreaCoordinationView, 2U> areas{
      AreaCoordinationView{.routes = backbone_routes,
                           .area_id = 0U},
      AreaCoordinationView{.routes = area_one_routes,
                           .area_id = 1U,
                           .default_metric = 7U,
                           .type = AreaType::stub}};

  const auto coordinated =
      coordinate_areas(areas, 0x01010101U,
                       router::packet::ospf::version_two, false);
  require(coordinated && coordinated->area_border_router,
          "backbone-attached multi-area router was not an ABR");
  require(coordinated->advertisements[0U].size() == 1U &&
              prefix_is(coordinated->advertisements[0U][0U],
                        0x0a010000U, 24U),
          "non-backbone intra-area route was not summarized into area 0");
  const auto &stub = coordinated->advertisements[1U];
  require(stub.size() == 2U &&
              std::any_of(stub.begin(), stub.end(),
                          [](const auto &item) {
                            return prefix_is(item, 0U, 0U) &&
                                   item.metric == 7U;
                          }) &&
              std::any_of(stub.begin(), stub.end(),
                          [](const auto &item) {
                            return prefix_is(item, 0x0a000000U,
                                             24U);
                          }),
          "stub area did not receive default and backbone summary");

  auto totally_stub = areas;
  totally_stub[1U].type = AreaType::totally_stub;
  const auto suppressed =
      coordinate_areas(totally_stub, 0x01010101U,
                       router::packet::ospf::version_two, false);
  require(suppressed &&
              suppressed->advertisements[1U].size() == 1U &&
              prefix_is(suppressed->advertisements[1U][0U], 0U,
                        0U),
          "totally-stub area leaked a non-default summary");

  // RFC 3101 section 3.2 permits Type 7 to Type 5 translation only when the
  // originating NSSA ASBR set P and supplied a nonzero forwarding address.
  // Build the advertisement bytes with the production codec so this test also
  // fixes the exact OSPFv2 Options-bit interpretation at the ABR boundary.
  std::array<std::uint8_t, 64U> type_seven_storage{};
  const auto type_seven =
      router::packet::ospf::lsa::encode_version_two_external_lsa(
          type_seven_storage,
          {.link_state_id = 0xc0000200U,
           .advertising_router = 0x02020202U,
           .sequence_number = initial_sequence_number,
           .age_seconds = 0U,
           .type = 7U,
           .options = 0x08U,
           .version = router::packet::ospf::version_two},
          0xffffff00U, 20U, true, 0x0a010001U, 77U);
  require(type_seven.has_value(),
          "NSSA translation fixture could not encode Type 7");
  const auto type_seven_header = router::packet::ospf::lsa_header(
      *type_seven, router::packet::ospf::version_two);
  require(type_seven_header.has_value(),
          "NSSA translation fixture could not parse Type 7");
  const std::array nssa_database{
      LsaRecord{.key = lsa_key(*type_seven_header),
                .bytes = std::vector<std::uint8_t>(
                    type_seven->begin(), type_seven->end())}};
  const std::array<AreaCoordinationView, 2U> nssa_areas{
      AreaCoordinationView{.area_id = 0U},
      AreaCoordinationView{.database = nssa_database,
                           .area_id = 1U,
                           .type = AreaType::nssa,
                           .nssa_translate_always = true}};
  const auto translated =
      coordinate_areas(nssa_areas, 0x01010101U,
                       router::packet::ospf::version_two, false);
  require(translated &&
              std::any_of(
                  translated->advertisements[0U].begin(),
                  translated->advertisements[0U].end(),
                  [](const auto &item) {
                    return item.kind ==
                               CoordinatorAdvertisementKind::
                                   translated_external &&
                           prefix_is(item, 0xc0000200U, 24U) &&
                           item.metric == 20U && item.type_two &&
                           item.tag == 77U;
                  }),
          "eligible NSSA Type 7 was not translated into the backbone");

  // Changing Options would invalidate the Fletcher checksum, so re-encode
  // instead of admitting deliberately corrupt wire data to the coordinator.
  const auto no_propagate =
      router::packet::ospf::lsa::encode_version_two_external_lsa(
          type_seven_storage,
          {.link_state_id = 0xc0000200U,
           .advertising_router = 0x02020202U,
           .sequence_number = initial_sequence_number,
           .age_seconds = 0U,
           .type = 7U,
           .options = 0U,
           .version = router::packet::ospf::version_two},
          0xffffff00U, 20U, true, 0x0a010001U, 77U);
  require(no_propagate.has_value(),
          "NSSA no-propagate fixture could not encode Type 7");
  const auto no_propagate_header =
      router::packet::ospf::lsa_header(
          *no_propagate, router::packet::ospf::version_two);
  std::array no_propagate_database{
      LsaRecord{.key = lsa_key(*no_propagate_header),
                .bytes = std::vector<std::uint8_t>(
                    no_propagate->begin(), no_propagate->end())}};
  auto blocked_areas = nssa_areas;
  blocked_areas[1U].database = no_propagate_database;
  const auto blocked =
      coordinate_areas(blocked_areas, 0x01010101U,
                       router::packet::ospf::version_two, false);
  require(blocked &&
              std::none_of(
                  blocked->advertisements[0U].begin(),
                  blocked->advertisements[0U].end(),
                  [](const auto &item) {
                    return item.kind ==
                           CoordinatorAdvertisementKind::
                               translated_external;
                  }),
          "NSSA ABR translated a Type 7 with P clear");
}
