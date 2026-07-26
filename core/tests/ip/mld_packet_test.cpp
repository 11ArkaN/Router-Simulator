// MLD wire tests cover Router Alert framing, v1 and v2 message layouts,
// floating response codes, source vectors and strict receive constraints.

#include "router/mld_packet.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("MLD fixture address is invalid");
  return *parsed;
}

router::packet::Frame without_hop_by_hop(const router::packet::Frame &source) {
  using namespace router::packet;
  constexpr std::size_t ipv6_offset = ethernet_header_octets;
  constexpr std::size_t extension_offset =
      ethernet_header_octets + ipv6_header_octets;
  constexpr std::size_t canonical_hop_by_hop_octets = 8U;
  if (source.length < extension_offset + canonical_hop_by_hop_octets)
    throw std::runtime_error("MLD Router Alert fixture is truncated");

  // The MLD checksum covers the ICMPv6 message and IPv6 pseudo-header, not the
  // extension header. Removing only the canonical HBH header therefore keeps
  // the checksum valid while producing a standards-valid IPv6 packet that is
  // suitable for testing the SR OS compatibility knob in isolation.
  auto result = source;
  std::move(result.bytes.begin() +
                static_cast<std::ptrdiff_t>(extension_offset +
                                            canonical_hop_by_hop_octets),
            result.bytes.begin() + static_cast<std::ptrdiff_t>(result.length),
            result.bytes.begin() +
                static_cast<std::ptrdiff_t>(extension_offset));
  result.length =
      static_cast<std::uint16_t>(result.length - canonical_hop_by_hop_octets);
  result.bytes[ipv6_offset + 6U] = ipv6_next_header_icmpv6;
  const auto old_payload = static_cast<std::uint16_t>(
      (result.bytes[ipv6_offset + 4U] << 8U) | result.bytes[ipv6_offset + 5U]);
  const auto payload =
      static_cast<std::uint16_t>(old_payload - canonical_hop_by_hop_octets);
  result.bytes[ipv6_offset + 4U] = static_cast<std::uint8_t>(payload >> 8U);
  result.bytes[ipv6_offset + 5U] = static_cast<std::uint8_t>(payload);
  return result;
}

} // namespace

void mld_packet_tests() {
  using namespace router;
  using namespace router::packet;
  using namespace router::packet::mld;
  const Mac mac{0x02U, 0U, 0U, 0U, 0x38U, 0x10U};
  const auto link_local = address("fe80::3810");
  const auto group = address("ff02::1234");

  const auto general = version_one_message(mac, link_local, query_type, {},
                                           std::chrono::milliseconds{10'000});
  const auto parsed_general = general ? parse_query(*general) : std::nullopt;
  require(parsed_general && !parsed_general->version_two &&
              ip::is_unspecified(parsed_general->multicast_address) &&
              parsed_general->destination == nd::all_nodes_multicast &&
              parsed_general->maximum_response_delay ==
                  std::chrono::seconds{10},
          "MLDv1 General Query did not preserve its wire contract");

  const std::array query_sources{address("2001:db8::1"),
                                 address("2001:db8::2")};
  const auto query = version_two_query(
      mac, link_local, group, std::chrono::milliseconds{40'000}, 2U, true,
      std::chrono::seconds{130}, query_sources);
  const auto parsed_query = query ? parse_query(*query) : std::nullopt;
  require(
      parsed_query && parsed_query->version_two &&
          parsed_query->multicast_address == group &&
          parsed_query->source_count == query_sources.size() &&
          parsed_query->robustness_variable == 2U &&
          parsed_query->suppress_router_processing &&
          parsed_query->maximum_response_delay >=
              std::chrono::milliseconds{40'000} &&
          parsed_query->query_interval >= std::chrono::seconds{130} &&
          query_source(*query, *parsed_query, 0U) == query_sources[0] &&
          query_source(*query, *parsed_query, 1U) == query_sources[1] &&
          !query_source(*query, *parsed_query, 2U),
      "MLDv2 Query exponent fields or source vector were decoded incorrectly");

  const std::array report_sources{address("2001:db8:1::1"),
                                  address("2001:db8:1::2")};
  const std::array records{
      ReportRecord{.type = RecordType::mode_is_include,
                   .multicast_address = group,
                   .sources = report_sources},
      ReportRecord{.type = RecordType::change_to_exclude,
                   .multicast_address = address("ff3e::8000:1"),
                   .sources = {}}};
  const auto report = version_two_report(mac, {}, records);
  const auto parsed_report =
      report ? parse_version_two_report(*report) : std::nullopt;
  const auto first =
      parsed_report ? report_record(*report, *parsed_report, 0U) : std::nullopt;
  const auto second =
      parsed_report ? report_record(*report, *parsed_report, 1U) : std::nullopt;
  require(parsed_report && parsed_report->source == Ipv6{} &&
              parsed_report->destination == all_mldv2_routers &&
              parsed_report->record_count == records.size() && first &&
              first->type == RecordType::mode_is_include &&
              first->source_count == report_sources.size() &&
              record_source(*report, *first, 0U) == report_sources[0] &&
              record_source(*report, *first, 1U) == report_sources[1] &&
              second && second->source_count == 0U &&
              !report_record(*report, *parsed_report, 2U),
          "MLDv2 Report records were not preserved as bounded frame views");

  const auto version_one_report =
      version_one_message(mac, {}, version_one_report_type, group);
  const auto parsed_version_one = version_one_report
                                      ? parse_version_one(*version_one_report)
                                      : std::nullopt;
  require(parsed_version_one && parsed_version_one->source == Ipv6{} &&
              parsed_version_one->multicast_address == group,
          "RFC 3590 unspecified-source MLDv1 Report was rejected");

  // Each corruption targets a separate receive invariant. Recomputing no
  // checksum after mutation is intentional for the checksum case only; the
  // Hop Limit and Router Alert cases fail before any state owner sees bytes.
  auto bad_hop = *report;
  bad_hop.bytes[ethernet_header_octets + 7U] = 2U;
  require(!parse_version_two_report(bad_hop) &&
              diagnose_rejection(bad_hop) ==
                  RejectionReason::bad_receive_interface,
          "MLD accepted a packet whose Hop Limit was not one");
  auto bad_alert = *report;
  bad_alert.bytes[ethernet_header_octets + ipv6_header_octets + 4U] = 1U;
  require(!parse_version_two_report(bad_alert),
          "MLD accepted a non-MLD Router Alert value");
  const auto no_alert_report = without_hop_by_hop(*report);
  require(!parse_version_two_report(no_alert_report) &&
              parse_version_two_report(no_alert_report, false),
          "Router Alert compatibility control did not change only the "
          "receive-side option requirement");
  require(diagnose_rejection(no_alert_report) ==
              RejectionReason::no_router_alert,
          "MLD rejection diagnostics did not identify missing Router Alert");
  const auto no_alert_query = without_hop_by_hop(*query);
  require(!parse_query(no_alert_query) && parse_query(no_alert_query, false),
          "Router Alert compatibility control was not applied to MLD Query");
  const auto no_alert_v1 = without_hop_by_hop(*version_one_report);
  require(!parse_version_one(no_alert_v1) &&
              parse_version_one(no_alert_v1, false),
          "Router Alert compatibility control was not applied to MLDv1");
  auto bad_checksum = *report;
  bad_checksum.bytes[bad_checksum.length - 1U] ^= 0x01U;
  require(!parse_version_two_report(bad_checksum) &&
              diagnose_rejection(bad_checksum) == RejectionReason::bad_checksum,
          "MLD accepted a corrupted ICMPv6 checksum");
}
