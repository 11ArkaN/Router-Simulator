// RFC 2710, RFC 3590 and RFC 3810 MLD packet implementation. Every packet is
// an ordinary Ethernet and IPv6 frame and therefore cannot bypass a modeled
// port, queue, link or capture point.

#include "router/mld_packet.hpp"

#include "router/ipv6_extension.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::packet::mld {
namespace {

constexpr std::size_t ipv6_offset = ethernet_header_octets;
constexpr std::size_t hop_by_hop_offset =
    ethernet_header_octets + ipv6_header_octets;
constexpr std::size_t hop_by_hop_octets = 8U;
constexpr std::size_t mld_offset = hop_by_hop_offset + hop_by_hop_octets;
constexpr std::size_t version_one_message_octets = 24U;
constexpr std::size_t version_two_query_base_octets = 28U;
constexpr std::size_t version_two_report_base_octets = 8U;
constexpr std::size_t version_two_record_base_octets = 20U;
constexpr std::uint8_t router_alert_option = 5U;
constexpr std::uint8_t router_alert_data_octets = 2U;
constexpr std::uint16_t mld_router_alert_value = 0U;
constexpr std::uint8_t padn_option = 1U;
constexpr std::uint8_t query_suppress_mask = 0x08U;
constexpr std::uint8_t query_robustness_mask = 0x07U;

void put16(Frame &frame, std::size_t offset, std::uint16_t value) noexcept {
  frame.bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  frame.bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void put32(Frame &frame, std::size_t offset, std::uint32_t value) noexcept {
  frame.bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  frame.bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  frame.bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  frame.bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint16_t read16(const Frame &frame, std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((frame.bytes[offset] << 8U) |
                                    frame.bytes[offset + 1U]);
}

Ipv6 read_address(const Frame &frame, std::size_t offset) noexcept {
  Ipv6 result{};
  std::copy_n(frame.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              result.size(), result.begin());
  return result;
}

void write_address(Frame &frame, std::size_t offset,
                   const Ipv6 &address) noexcept {
  std::copy(address.begin(), address.end(),
            frame.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

bool valid_record_type(std::uint8_t value) noexcept {
  return value >= static_cast<std::uint8_t>(RecordType::mode_is_include) &&
         value <= static_cast<std::uint8_t>(RecordType::block_old_sources);
}

std::uint32_t decode_response_code(std::uint16_t code) noexcept {
  // RFC 3810 section 5.1.3 retains millisecond linear encoding below 32768.
  // Above that boundary the top three bits are an exponent and the low twelve
  // bits form a normalized mantissa with one implicit leading bit.
  if ((code & 0x8000U) == 0U)
    return code;
  const auto exponent = static_cast<std::uint32_t>((code >> 12U) & 0x07U);
  const auto mantissa = static_cast<std::uint32_t>(code & 0x0fffU) | 0x1000U;
  return mantissa << (exponent + 3U);
}

std::uint32_t decode_qqic(std::uint8_t code) noexcept {
  if ((code & 0x80U) == 0U)
    return code;
  const auto exponent = static_cast<std::uint32_t>((code >> 4U) & 0x07U);
  const auto mantissa = static_cast<std::uint32_t>(code & 0x0fU) | 0x10U;
  return mantissa << (exponent + 3U);
}

std::uint16_t encode_response_code(std::chrono::milliseconds value) noexcept {
  const auto requested = static_cast<std::uint64_t>(value.count());
  if (requested < 0x8000U)
    return static_cast<std::uint16_t>(requested);
  // Select the smallest floating representation that is not less than the
  // requested interval. Responding with a shorter encoded bound could violate
  // a caller's configured maximum response delay.
  for (std::uint16_t exponent = 0U; exponent <= 7U; ++exponent) {
    const auto unit = std::uint64_t{1} << (exponent + 3U);
    const auto normalized = (requested + unit - 1U) / unit;
    if (normalized <= 0x1fffU)
      return static_cast<std::uint16_t>(0x8000U | (exponent << 12U) |
                                        (normalized - 0x1000U));
  }
  return std::numeric_limits<std::uint16_t>::max();
}

std::uint8_t encode_qqic(std::chrono::seconds value) noexcept {
  const auto requested = static_cast<std::uint64_t>(value.count());
  if (requested < 0x80U)
    return static_cast<std::uint8_t>(requested);
  for (std::uint8_t exponent = 0U; exponent <= 7U; ++exponent) {
    const auto unit = std::uint64_t{1} << (exponent + 3U);
    const auto normalized = (requested + unit - 1U) / unit;
    if (normalized <= 0x1fU)
      return static_cast<std::uint8_t>(0x80U | (exponent << 4U) |
                                       (normalized - 0x10U));
  }
  return std::numeric_limits<std::uint8_t>::max();
}

bool has_mld_router_alert(const Frame &frame, const Ipv6View &ipv6) noexcept {
  if (ipv6.next_header != ipv6_next_header_hop_by_hop ||
      hop_by_hop_offset + 2U > frame.length)
    return false;
  // Hdr Ext Len counts eight-octet units after the first unit. Router Alert
  // may legally share a longer Hop-by-Hop header with other options, so the
  // decoder must not assume the canonical eight-octet layout used by our own
  // encoder.
  const auto header_octets =
      (static_cast<std::size_t>(frame.bytes[hop_by_hop_offset + 1U]) + 1U) * 8U;
  auto cursor = hop_by_hop_offset + 2U;
  const auto end = hop_by_hop_offset + header_octets;
  if (end > frame.length || end > ipv6.upper_layer_offset)
    return false;
  while (cursor < end) {
    const auto type = frame.bytes[cursor];
    if (type == 0U) {
      ++cursor;
      continue;
    }
    if (cursor + 2U > end)
      return false;
    const auto octets = frame.bytes[cursor + 1U];
    if (cursor + 2U + octets > end)
      return false;
    if (type == router_alert_option) {
      if (octets != router_alert_data_octets ||
          read16(frame, cursor + 2U) != mld_router_alert_value)
        return false;
      return true;
    }
    cursor += 2U + octets;
  }
  return false;
}

std::optional<Ipv6View> envelope(const Frame &frame,
                                 bool require_router_alert) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  if (!ipv6 || ipv6->hop_limit != 1U ||
      ipv6->upper_layer_protocol != ipv6_next_header_icmpv6 ||
      (require_router_alert && !has_mld_router_alert(frame, *ipv6)) ||
      validate_ipv6_extensions(frame, *ipv6, true, true).action !=
          Ipv6ExtensionAction::accept ||
      !parse_icmpv6(frame))
    return std::nullopt;
  return ipv6;
}

bool begin(Frame &frame, Mac source_mac, Ipv6 source, Ipv6 destination,
           std::size_t icmp_octets, std::uint8_t type) noexcept {
  const auto total = mld_offset + icmp_octets;
  if (total > frame.bytes.size() ||
      icmp_octets >
          std::numeric_limits<std::uint16_t>::max() - hop_by_hop_octets)
    return false;
  frame = {};
  const auto destination_mac = ipv6_multicast_mac(destination);
  std::copy(destination_mac.begin(), destination_mac.end(),
            frame.bytes.begin());
  std::copy(source_mac.begin(), source_mac.end(), frame.bytes.begin() + 6U);
  put16(frame, 12U, ethernet_type_ipv6);
  put32(frame, ipv6_offset, 6U << 28U);
  put16(frame, ipv6_offset + 4U,
        static_cast<std::uint16_t>(hop_by_hop_octets + icmp_octets));
  frame.bytes[ipv6_offset + 6U] = ipv6_next_header_hop_by_hop;
  frame.bytes[ipv6_offset + 7U] = 1U;
  write_address(frame, ipv6_offset + 8U, source);
  write_address(frame, ipv6_offset + 24U, destination);

  // The canonical eight-octet HBH header carries Router Alert value zero and
  // a zero-length PadN option. Its layout is taken directly from RFC 2711.
  frame.bytes[hop_by_hop_offset] = ipv6_next_header_icmpv6;
  frame.bytes[hop_by_hop_offset + 1U] = 0U;
  frame.bytes[hop_by_hop_offset + 2U] = router_alert_option;
  frame.bytes[hop_by_hop_offset + 3U] = router_alert_data_octets;
  put16(frame, hop_by_hop_offset + 4U, mld_router_alert_value);
  frame.bytes[hop_by_hop_offset + 6U] = padn_option;
  frame.bytes[hop_by_hop_offset + 7U] = 0U;
  frame.bytes[mld_offset] = type;
  frame.bytes[mld_offset + 1U] = 0U;
  put16(frame, mld_offset + 2U, 0U);
  frame.length = static_cast<std::uint16_t>(total);
  return true;
}

void finish(Frame &frame, const Ipv6 &source,
            const Ipv6 &destination) noexcept {
  const auto payload = std::span<const std::uint8_t>(
      frame.bytes.data() + mld_offset, frame.length - mld_offset);
  const auto checksum = ipv6_upper_layer_checksum(
      source, destination, ipv6_next_header_icmpv6, payload);
  put16(frame, mld_offset + 2U, checksum);
}

} // namespace

const Ipv6 all_mldv2_routers{0xffU, 0x02U, 0U, 0U, 0U, 0U, 0U, 0U,
                             0U,    0U,    0U, 0U, 0U, 0U, 0U, 0x16U};

std::optional<QueryView> parse_query(const Frame &frame,
                                     bool require_router_alert) noexcept {
  const auto ipv6 = envelope(frame, require_router_alert);
  if (!ipv6 || frame.bytes[ipv6->upper_layer_offset] != query_type ||
      !ip::is_link_local(ipv6->source))
    return std::nullopt;
  const auto extension_octets =
      ipv6->upper_layer_offset - (ipv6_offset + ipv6_header_octets);
  if (ipv6->payload_length < extension_octets + version_one_message_octets)
    return std::nullopt;
  const auto offset = ipv6->upper_layer_offset;
  const auto multicast = read_address(frame, offset + 8U);
  if (!ip::is_unspecified(multicast) && !ip::is_multicast(multicast))
    return std::nullopt;
  const auto icmp_octets =
      static_cast<std::size_t>(ipv6->payload_length - extension_octets);
  if (icmp_octets == version_one_message_octets)
    return QueryView{.source = ipv6->source,
                     .destination = ipv6->destination,
                     .multicast_address = multicast,
                     .maximum_response_delay =
                         std::chrono::milliseconds{read16(frame, offset + 4U)},
                     // MLDv1 has no encoded QQIC. RFC 3810 section 8.2.1 uses
                     // the interface Query Interval for its compatibility
                     // timer, supplied here by the selected generated profile.
                     .query_interval = device_catalog::mld_query_interval,
                     .version_two = false};
  if (icmp_octets < version_two_query_base_octets)
    return std::nullopt;
  const auto source_count = read16(frame, offset + 26U);
  if (source_count > device_catalog::mld_sources_per_group ||
      version_two_query_base_octets +
              static_cast<std::size_t>(source_count) * Ipv6{}.size() !=
          icmp_octets)
    return std::nullopt;
  const auto controls = frame.bytes[offset + 24U];
  return QueryView{
      .source = ipv6->source,
      .destination = ipv6->destination,
      .multicast_address = multicast,
      .maximum_response_delay = std::chrono::milliseconds{decode_response_code(
          read16(frame, offset + 4U))},
      .query_interval =
          std::chrono::seconds{decode_qqic(frame.bytes[offset + 25U])},
      .source_count = source_count,
      .source_offset =
          static_cast<std::uint16_t>(offset + version_two_query_base_octets),
      .robustness_variable =
          static_cast<std::uint8_t>(controls & query_robustness_mask),
      .suppress_router_processing = (controls & query_suppress_mask) != 0U,
      .version_two = true};
}

std::optional<VersionOneView>
parse_version_one(const Frame &frame, bool require_router_alert) noexcept {
  const auto ipv6 = envelope(frame, require_router_alert);
  if (!ipv6)
    return std::nullopt;
  const auto extension_octets =
      ipv6->upper_layer_offset - (ipv6_offset + ipv6_header_octets);
  if (ipv6->payload_length != extension_octets + version_one_message_octets)
    return std::nullopt;
  const auto offset = ipv6->upper_layer_offset;
  const auto type = frame.bytes[offset];
  if (type != version_one_report_type && type != version_one_done_type)
    return std::nullopt;
  if (!ip::is_link_local(ipv6->source) && !ip::is_unspecified(ipv6->source))
    return std::nullopt;
  const auto multicast = read_address(frame, offset + 8U);
  if (!ip::is_multicast(multicast))
    return std::nullopt;
  return VersionOneView{
      .source = ipv6->source,
      .destination = ipv6->destination,
      .multicast_address = multicast,
      .maximum_response_delay =
          std::chrono::milliseconds{read16(frame, offset + 4U)},
      .type = type};
}

std::optional<ReportView>
parse_version_two_report(const Frame &frame,
                         bool require_router_alert) noexcept {
  const auto ipv6 = envelope(frame, require_router_alert);
  if (!ipv6 ||
      frame.bytes[ipv6->upper_layer_offset] != version_two_report_type ||
      ipv6->destination != all_mldv2_routers ||
      (!ip::is_link_local(ipv6->source) && !ip::is_unspecified(ipv6->source)))
    return std::nullopt;
  const auto extension_octets =
      ipv6->upper_layer_offset - (ipv6_offset + ipv6_header_octets);
  if (ipv6->payload_length < extension_octets + version_two_report_base_octets)
    return std::nullopt;
  const auto offset = ipv6->upper_layer_offset;
  const auto count = read16(frame, offset + 6U);
  if (count > device_catalog::mld_records_per_report)
    return std::nullopt;
  ReportView result{.source = ipv6->source,
                    .destination = ipv6->destination,
                    .record_count = count,
                    .records_offset = static_cast<std::uint16_t>(
                        offset + version_two_report_base_octets)};
  std::size_t cursor = result.records_offset;
  const auto end = static_cast<std::size_t>(ethernet_header_octets) +
                   ipv6_header_octets + ipv6->payload_length;
  for (std::size_t index = 0; index < count; ++index) {
    if (cursor + version_two_record_base_octets > end ||
        !valid_record_type(frame.bytes[cursor]))
      return std::nullopt;
    const auto auxiliary =
        static_cast<std::size_t>(frame.bytes[cursor + 1U]) * 4U;
    const auto sources = read16(frame, cursor + 2U);
    if (sources > device_catalog::mld_sources_per_group)
      return std::nullopt;
    const auto size = version_two_record_base_octets +
                      static_cast<std::size_t>(sources) * Ipv6{}.size() +
                      auxiliary;
    if (cursor + size > end ||
        !ip::is_multicast(read_address(frame, cursor + 4U)))
      return std::nullopt;
    cursor += size;
  }
  return cursor == end ? std::optional<ReportView>{result} : std::nullopt;
}

RejectionReason diagnose_rejection(const Frame &frame,
                                   bool require_router_alert) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  if (!ipv6)
    return RejectionReason::bad_length;
  const auto packet_end = ethernet_header_octets + ipv6_header_octets +
                          static_cast<std::size_t>(ipv6->payload_length);
  const auto offset = static_cast<std::size_t>(ipv6->upper_layer_offset);
  if (ipv6->upper_layer_protocol != ipv6_next_header_icmpv6 ||
      offset >= packet_end)
    return RejectionReason::not_mld;
  const auto type = frame.bytes[offset];
  const bool known_type =
      type == query_type || type == version_one_report_type ||
      type == version_one_done_type || type == version_two_report_type;
  if (!known_type) {
    // Router Alert value zero identifies an MLD control message even when its
    // ICMPv6 type is not one of the versions understood by this release. An
    // unrelated ICMPv6 packet without that alert remains outside MLD stats.
    return ipv6->hop_limit == 1U && has_mld_router_alert(frame, *ipv6)
               ? RejectionReason::unknown_type
               : RejectionReason::not_mld;
  }
  if (offset + 8U > packet_end)
    return RejectionReason::bad_length;
  if (ipv6->hop_limit != 1U)
    return RejectionReason::bad_receive_interface;
  const auto extension = validate_ipv6_extensions(frame, *ipv6, true, true);
  if (extension.action != Ipv6ExtensionAction::accept)
    return RejectionReason::bad_encoding;
  const auto icmp = std::span<const std::uint8_t>{frame.bytes.data() + offset,
                                                  packet_end - offset};
  if (ipv6_upper_layer_checksum(ipv6->source, ipv6->destination,
                                ipv6_next_header_icmpv6, icmp) != 0U)
    return RejectionReason::bad_checksum;
  if (require_router_alert && !has_mld_router_alert(frame, *ipv6))
    return RejectionReason::no_router_alert;
  if (type == query_type && !ip::is_link_local(ipv6->source))
    return RejectionReason::non_local_source;
  if (type != query_type && !ip::is_link_local(ipv6->source) &&
      !ip::is_unspecified(ipv6->source))
    return RejectionReason::non_local_source;

  // At this point the envelope and checksum are sound. Failure of the decoder
  // is therefore a message length, reserved-field or record encoding error.
  // `bad_length` is reserved for an envelope shorter than the ICMPv6 minimum;
  // all type-specific structural failures map to the Nokia bad-encoding field.
  const bool valid =
      parse_query(frame, require_router_alert).has_value() ||
      parse_version_one(frame, require_router_alert).has_value() ||
      parse_version_two_report(frame, require_router_alert).has_value();
  return valid ? RejectionReason::unknown_type : RejectionReason::bad_encoding;
}

std::optional<RecordView> report_record(const Frame &frame,
                                        const ReportView &report,
                                        std::size_t index) noexcept {
  if (index >= report.record_count)
    return std::nullopt;
  std::size_t cursor = report.records_offset;
  for (std::size_t current = 0; current <= index; ++current) {
    if (cursor + version_two_record_base_octets > frame.length)
      return std::nullopt;
    const auto sources = read16(frame, cursor + 2U);
    const auto auxiliary =
        static_cast<std::size_t>(frame.bytes[cursor + 1U]) * 4U;
    const auto source_offset = cursor + version_two_record_base_octets;
    const auto auxiliary_offset =
        source_offset + static_cast<std::size_t>(sources) * Ipv6{}.size();
    if (auxiliary_offset + auxiliary > frame.length)
      return std::nullopt;
    if (current == index)
      return RecordView{
          .multicast_address = read_address(frame, cursor + 4U),
          .source_count = sources,
          .sources_offset = static_cast<std::uint16_t>(source_offset),
          .auxiliary_offset = static_cast<std::uint16_t>(auxiliary_offset),
          .auxiliary_octets = static_cast<std::uint16_t>(auxiliary),
          .type = static_cast<RecordType>(frame.bytes[cursor])};
    cursor = auxiliary_offset + auxiliary;
  }
  return std::nullopt;
}

std::optional<Ipv6> query_source(const Frame &frame, const QueryView &query,
                                 std::size_t index) noexcept {
  if (index >= query.source_count)
    return std::nullopt;
  const auto offset =
      static_cast<std::size_t>(query.source_offset) + index * Ipv6{}.size();
  return offset + Ipv6{}.size() <= frame.length
             ? std::optional<Ipv6>{read_address(frame, offset)}
             : std::nullopt;
}

std::optional<Ipv6> record_source(const Frame &frame, const RecordView &record,
                                  std::size_t index) noexcept {
  if (index >= record.source_count)
    return std::nullopt;
  const auto offset =
      static_cast<std::size_t>(record.sources_offset) + index * Ipv6{}.size();
  return offset + Ipv6{}.size() <= record.auxiliary_offset
             ? std::optional<Ipv6>{read_address(frame, offset)}
             : std::nullopt;
}

std::optional<Frame>
version_one_message(Mac source_mac, Ipv6 source, std::uint8_t type,
                    const Ipv6 &multicast_address,
                    std::chrono::milliseconds maximum_response_delay) noexcept {
  const bool general_query =
      type == query_type && ip::is_unspecified(multicast_address);
  if ((type != version_one_report_type && type != version_one_done_type &&
       type != query_type) ||
      (!general_query && !ip::is_multicast(multicast_address)) ||
      maximum_response_delay.count() < 0 ||
      maximum_response_delay.count() >
          std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;
  const auto destination =
      type == version_one_done_type
          ? packet::nd::all_routers_multicast
          : (general_query ? packet::nd::all_nodes_multicast
                           : multicast_address);
  Frame result;
  if (!begin(result, source_mac, source, destination,
             version_one_message_octets, type))
    return std::nullopt;
  put16(result, mld_offset + 4U,
        static_cast<std::uint16_t>(maximum_response_delay.count()));
  put16(result, mld_offset + 6U, 0U);
  write_address(result, mld_offset + 8U, multicast_address);
  finish(result, source, destination);
  return result;
}

std::optional<Frame>
version_two_report(Mac source_mac, Ipv6 source,
                   std::span<const ReportRecord> records) noexcept {
  if (records.size() > device_catalog::mld_records_per_report)
    return std::nullopt;
  std::size_t octets = version_two_report_base_octets;
  for (const auto &record : records) {
    if (!valid_record_type(static_cast<std::uint8_t>(record.type)) ||
        !ip::is_multicast(record.multicast_address) ||
        std::any_of(record.sources.begin(), record.sources.end(),
                    [](const auto &address) {
                      return ip::is_unspecified(address) ||
                             ip::is_multicast(address);
                    }) ||
        record.sources.size() > device_catalog::mld_sources_per_group ||
        record.sources.size() > (std::numeric_limits<std::size_t>::max() -
                                 octets - version_two_record_base_octets) /
                                    Ipv6{}.size())
      return std::nullopt;
    octets +=
        version_two_record_base_octets + record.sources.size() * Ipv6{}.size();
  }
  Frame result;
  if (!begin(result, source_mac, source, all_mldv2_routers, octets,
             version_two_report_type))
    return std::nullopt;
  put16(result, mld_offset + 4U, 0U);
  put16(result, mld_offset + 6U, static_cast<std::uint16_t>(records.size()));
  auto cursor = mld_offset + version_two_report_base_octets;
  for (const auto &record : records) {
    result.bytes[cursor] = static_cast<std::uint8_t>(record.type);
    result.bytes[cursor + 1U] = 0U;
    put16(result, cursor + 2U,
          static_cast<std::uint16_t>(record.sources.size()));
    write_address(result, cursor + 4U, record.multicast_address);
    cursor += version_two_record_base_octets;
    for (const auto &source_address : record.sources) {
      write_address(result, cursor, source_address);
      cursor += source_address.size();
    }
  }
  finish(result, source, all_mldv2_routers);
  return result;
}

std::optional<Frame>
version_two_query(Mac source_mac, Ipv6 source, const Ipv6 &multicast_address,
                  std::chrono::milliseconds maximum_response_delay,
                  std::uint8_t robustness_variable,
                  bool suppress_router_processing,
                  std::chrono::seconds query_interval,
                  std::span<const Ipv6> sources) noexcept {
  if (!ip::is_link_local(source) ||
      (!ip::is_unspecified(multicast_address) &&
       !ip::is_multicast(multicast_address)) ||
      robustness_variable > query_robustness_mask ||
      sources.size() > device_catalog::mld_sources_per_group ||
      maximum_response_delay.count() < 0 || query_interval.count() < 0)
    return std::nullopt;
  const auto destination = ip::is_unspecified(multicast_address)
                               ? packet::nd::all_nodes_multicast
                               : multicast_address;
  const auto octets =
      version_two_query_base_octets + sources.size() * Ipv6{}.size();
  Frame result;
  if (!begin(result, source_mac, source, destination, octets, query_type))
    return std::nullopt;
  put16(result, mld_offset + 4U, encode_response_code(maximum_response_delay));
  put16(result, mld_offset + 6U, 0U);
  write_address(result, mld_offset + 8U, multicast_address);
  result.bytes[mld_offset + 24U] = static_cast<std::uint8_t>(
      robustness_variable |
      (suppress_router_processing ? query_suppress_mask : 0U));
  result.bytes[mld_offset + 25U] = encode_qqic(query_interval);
  put16(result, mld_offset + 26U, static_cast<std::uint16_t>(sources.size()));
  auto cursor = mld_offset + version_two_query_base_octets;
  for (const auto &source_address : sources) {
    if (ip::is_multicast(source_address) || ip::is_unspecified(source_address))
      return std::nullopt;
    write_address(result, cursor, source_address);
    cursor += source_address.size();
  }
  finish(result, source, destination);
  return result;
}

} // namespace router::packet::mld
