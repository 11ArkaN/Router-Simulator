// RFC 2328 sections 12.4.3, 12.4.4 and 16.2 plus RFC 3101 translator behavior
// expressed as a pure ABR decision. Wire encoding and sequence ownership stay
// in InstanceProcess, while this module decides only what each area should
// advertise from routes and LSAs actually learned by this router.

#include "router/ospf_area_coordinator.hpp"

#include "router/ospf_lsa.hpp"
#include "router/ospf_packet.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <new>

namespace router::ospf {
namespace {

using lab::routing::OspfPathType;

[[nodiscard]] bool external_path(OspfPathType type) noexcept {
  return type == OspfPathType::external_type_1 ||
         type == OspfPathType::external_type_2 ||
         type == OspfPathType::nssa_type_1 ||
         type == OspfPathType::nssa_type_2;
}

[[nodiscard]] ip::IpPrefix route_prefix(
    const CalculatedRoute &route) noexcept {
  ip::IpPrefix prefix;
  prefix.length = route.prefix_length;
  if (route.version_three) {
    prefix.network.family =
        route.ipv4_address_family ? ip::AddressFamily::ipv4
                                  : ip::AddressFamily::ipv6;
    prefix.network.bytes = route.version_three_network;
  } else {
    prefix.network.family = ip::AddressFamily::ipv4;
    prefix.network.bytes[0U] =
        static_cast<std::uint8_t>(route.version_two_network >> 24U);
    prefix.network.bytes[1U] =
        static_cast<std::uint8_t>(route.version_two_network >> 16U);
    prefix.network.bytes[2U] =
        static_cast<std::uint8_t>(route.version_two_network >> 8U);
    prefix.network.bytes[3U] =
        static_cast<std::uint8_t>(route.version_two_network);
  }
  return prefix;
}

[[nodiscard]] const AreaRangeConfiguration *
matching_range(const AreaCoordinationView &area,
               const ip::IpPrefix &prefix) noexcept {
  const AreaRangeConfiguration *selected{};
  for (const auto &range : area.ranges) {
    if (range.prefix.network.family != prefix.network.family ||
        range.prefix.length > prefix.length ||
        !ip::contains(range.prefix, prefix.network))
      continue;
    if (!selected ||
        range.prefix.length > selected->prefix.length)
      selected = &range;
  }
  return selected;
}

void retain_best(std::vector<CoordinatorAdvertisement> &output,
                 CoordinatorAdvertisement candidate) {
  const auto existing = std::find_if(
      output.begin(), output.end(), [&](const auto &current) {
        return current.kind == candidate.kind &&
               current.prefix == candidate.prefix &&
               current.destination_router_id ==
                   candidate.destination_router_id &&
               current.source_link_state_id ==
                   candidate.source_link_state_id;
      });
  if (existing == output.end()) {
    output.push_back(std::move(candidate));
    return;
  }
  // Summary LSAs carry the best cost from this ABR. Equal costs describe one
  // advertisement, not multiple local LSAs. External Type 2 compares external
  // metric first and internal metric second, matching route selection.
  const bool better =
      candidate.metric < existing->metric ||
      (candidate.metric == existing->metric &&
       candidate.internal_metric < existing->internal_metric);
  if (better)
    *existing = std::move(candidate);
}

[[nodiscard]] bool is_abr_router_lsa(
    const LsaRecord &record, std::uint8_t version,
    std::uint32_t &router_id) noexcept {
  const auto header = packet::ospf::lsa_header(record.bytes, version);
  if (!header)
    return false;
  router_id = header->advertising_router;
  if (version == packet::ospf::version_two) {
    const auto body =
        packet::ospf::lsa::parse_version_two_router(record.bytes);
    return body && body->area_border_router;
  }
  const auto body =
      packet::ospf::lsa::parse_version_three_router(record.bytes);
  // RFC 5340 Appendix A.4.2 retains the B bit at bit zero of Router-LSA flags.
  return body && (body->flags & 0x01U) != 0U;
}

[[nodiscard]] bool translate_nssa(
    const AreaCoordinationView &source,
    std::vector<CoordinatorAdvertisement> &destination,
    std::uint32_t local_router_id, std::uint8_t version,
    bool ipv4_address_family) {
  if (source.type != AreaType::nssa)
    return true;

  // RFC 3101 section 3.1 elects the highest Router ID among eligible NSSA
  // translators, unless local configuration requests always-translate.
  std::uint32_t elected = local_router_id;
  if (!source.nssa_translate_always)
    for (const auto &record : source.database) {
      std::uint32_t candidate{};
      if (is_abr_router_lsa(record, version, candidate))
        elected = std::max(elected, candidate);
    }
  if (!source.nssa_translate_always && elected != local_router_id)
    return true;

  for (const auto &record : source.database) {
    const auto header = packet::ospf::lsa_header(record.bytes, version);
    if (!header)
      return false;
    const auto function =
        version == packet::ospf::version_two
            ? header->type
            : static_cast<std::uint16_t>(header->type & 0x1fffU);
    if (function != 7U)
      continue;

    CoordinatorAdvertisement translated{
        .source_link_state_id = header->link_state_id,
        .kind = CoordinatorAdvertisementKind::translated_external};
    if (version == packet::ospf::version_two) {
      const auto body =
          packet::ospf::lsa::parse_version_two_external(record.bytes);
      if (!body)
        return false;
      const auto length =
          static_cast<std::uint8_t>(std::countl_one(body->network_mask));
      const auto expected =
          length == 0U ? 0U : 0xffffffffU << (32U - length);
      if (body->network_mask != expected)
        return false;
      translated.prefix.network.family = ip::AddressFamily::ipv4;
      const auto network = header->link_state_id & body->network_mask;
      translated.prefix.network.bytes[0U] =
          static_cast<std::uint8_t>(network >> 24U);
      translated.prefix.network.bytes[1U] =
          static_cast<std::uint8_t>(network >> 16U);
      translated.prefix.network.bytes[2U] =
          static_cast<std::uint8_t>(network >> 8U);
      translated.prefix.network.bytes[3U] =
          static_cast<std::uint8_t>(network);
      translated.prefix.length = length;
      translated.metric = body->metric;
      translated.forwarding_address_v4 =
          body->forwarding_address;
      translated.tag = body->route_tag;
      translated.type_two = body->type_two_metric;
    } else {
      const auto body =
          packet::ospf::lsa::parse_version_three_external(
              record.bytes, ipv4_address_family);
      const auto network =
          body ? packet::ospf::lsa::expand_prefix(body->prefix)
               : std::nullopt;
      if (!body || !network)
        return false;
      translated.prefix.network.family =
          ipv4_address_family ? ip::AddressFamily::ipv4
                              : ip::AddressFamily::ipv6;
      translated.prefix.network.bytes = *network;
      translated.prefix.length = body->prefix.length;
      translated.metric = body->metric;
      if (!body->forwarding_address.empty())
        std::copy(body->forwarding_address.begin(),
                  body->forwarding_address.end(),
                  translated.forwarding_address_v6.begin());
      translated.tag = body->route_tag.value_or(0U);
      translated.type_two = body->type_two_metric;
      translated.ipv4_forwarding_address = ipv4_address_family;
    }
    // RFC 3101 section 3.2 requires both the P-bit and a nonzero forwarding
    // address. OSPFv2 carries N/P in the LSA header Options octet. OSPFv3
    // carries P in the embedded PrefixOptions octet defined by RFC 5340.
    // Checking both explicitly prevents a valid local Type 7 route from being
    // incorrectly leaked into the rest of the autonomous system.
    const bool propagate =
        version == packet::ospf::version_two
            ? (header->options & 0x08U) != 0U
            : (packet::ospf::lsa::parse_version_three_external(
                   record.bytes, ipv4_address_family)
                   ->prefix.options &
               0x08U) != 0U;
    const bool translatable =
        propagate && (version == packet::ospf::version_two
            ? translated.forwarding_address_v4 != 0U
            : !ip::is_unspecified(translated.forwarding_address_v6));
    if (translatable)
      retain_best(destination, std::move(translated));
  }
  return true;
}

} // namespace

std::optional<AreaCoordinationResult>
coordinate_areas(std::span<const AreaCoordinationView> areas,
                 std::uint32_t local_router_id, std::uint8_t version,
                 bool ipv4_address_family) noexcept {
  if (local_router_id == 0U ||
      (version != packet::ospf::version_two &&
       version != packet::ospf::version_three))
    return std::nullopt;
  try {
    AreaCoordinationResult result;
    result.advertisements.resize(areas.size());
    const auto backbone = std::find_if(
        areas.begin(), areas.end(),
        [](const auto &area) { return area.area_id == 0U; });
    result.area_border_router =
        backbone != areas.end() && areas.size() > 1U;
    if (!result.area_border_router)
      return result;

    for (std::size_t destination_index{};
         destination_index < areas.size(); ++destination_index) {
      const auto &destination = areas[destination_index];
      auto &output = result.advertisements[destination_index];

      const bool stub =
          destination.type == AreaType::stub ||
          destination.type == AreaType::totally_stub;
      if (stub) {
        ip::IpPrefix default_prefix;
        default_prefix.network.family =
            version == packet::ospf::version_two ||
                    ipv4_address_family
                ? ip::AddressFamily::ipv4
                : ip::AddressFamily::ipv6;
        retain_best(
            output,
            {.prefix = default_prefix,
             .metric = destination.default_metric,
             .kind =
                 CoordinatorAdvertisementKind::inter_area_prefix});
      }

      const bool suppress_summaries =
          destination.type == AreaType::totally_stub ||
          ((destination.type == AreaType::stub ||
            destination.type == AreaType::nssa) &&
           !destination.summaries);
      if (!suppress_summaries) {
        for (const auto &source : areas) {
          if (source.area_id == destination.area_id)
            continue;
          // RFC 2328 section 16.2: non-backbone area information enters the
          // backbone, while summaries into a non-backbone area are selected
          // from the ABR's backbone calculation.
          if (destination.area_id == 0U) {
            if (source.area_id == 0U)
              continue;
          } else if (source.area_id != 0U) {
            continue;
          }
          for (const auto &route : source.routes) {
            if (external_path(route.path_type))
              continue;
            const auto exact = route_prefix(route);
            const auto *range = matching_range(source, exact);
            if (range && !range->advertise)
              continue;
            const auto advertised_prefix =
                range ? range->prefix : exact;
            const auto advertised_metric =
                range && range->advertised_metric
                    ? *range->advertised_metric
                    : route.metric;
            const auto existing = std::find_if(
                output.begin(), output.end(),
                [&](const auto &item) {
                  return item.kind ==
                             CoordinatorAdvertisementKind::
                                 inter_area_prefix &&
                         item.prefix == advertised_prefix;
                });
            if (existing != output.end() && range &&
                !range->advertised_metric) {
              // RFC 2328 section 12.4.3 uses the maximum cost of the component
              // networks for an active address range.
              existing->metric =
                  std::max(existing->metric, advertised_metric);
              continue;
            }
            retain_best(
                output,
                {.prefix = advertised_prefix,
                 .metric = advertised_metric,
                 .internal_metric = route.internal_metric,
                 .kind =
                     CoordinatorAdvertisementKind::inter_area_prefix});
          }
        }
      }

      // AS-external LSAs are not admitted into stub or NSSA areas. Each
      // normal-area process owns an independent AS-scope database projection,
      // so the coordinator copies wire semantics learned in another normal
      // area rather than sharing an LSDB pointer.
      if (destination.type == AreaType::normal) {
        for (const auto &source : areas) {
          if (source.area_id == destination.area_id)
            continue;
          for (const auto &route : source.routes) {
            if (!external_path(route.path_type))
              continue;
            // Learning an external route does not make this router an ASBR.
            // The E-bit belongs only to a router that locally redistributes
            // an accepted non-OSPF route into this instance.
            retain_best(
                output,
                {.prefix = route_prefix(route),
                 .metric =
                     route.path_type == OspfPathType::external_type_1 ||
                             route.path_type == OspfPathType::nssa_type_1
                         ? route.metric - route.internal_metric
                         : route.metric,
                 .internal_metric = route.internal_metric,
                 .tag = route.tag,
                 .kind =
                     CoordinatorAdvertisementKind::translated_external,
                 .type_two =
                     route.path_type == OspfPathType::external_type_2 ||
                     route.path_type == OspfPathType::nssa_type_2});
            retain_best(
                output,
                {.destination_router_id =
                     route.advertising_router,
                 .metric = route.internal_metric,
                 .kind =
                     CoordinatorAdvertisementKind::inter_area_router});
          }
          if (!translate_nssa(source, output, local_router_id, version,
                              ipv4_address_family))
            return std::nullopt;
        }
      }
    }
    return result;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

} // namespace router::ospf
