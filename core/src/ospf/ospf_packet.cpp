// RFC 2328 and RFC 5340 OSPF packet codec. The implementation reads and writes
// network-order octets explicitly, avoiding packed structs, host alignment and
// compiler bit-field layout. No function allocates or retains caller storage.

#include "router/ospf_packet.hpp"

#include "router/packet.hpp"

#include <algorithm>
#include <limits>

namespace router::packet::ospf {
namespace {

constexpr std::size_t packet_length_offset = 2U;
constexpr std::size_t router_id_offset = 4U;
constexpr std::size_t area_id_offset = 8U;
constexpr std::size_t checksum_offset = 12U;
constexpr std::size_t version_two_authentication_type_offset = 14U;
constexpr std::size_t version_two_authentication_offset = 16U;
constexpr std::size_t version_three_instance_offset = 14U;
constexpr std::uint8_t dd_init = 0x04U;
constexpr std::uint8_t dd_more = 0x02U;
constexpr std::uint8_t dd_master = 0x01U;

std::uint16_t read16(std::span<const std::uint8_t> bytes,
                     std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) << 8U |
      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read24(std::span<const std::uint8_t> bytes,
                     std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
         static_cast<std::uint32_t>(bytes[offset + 2U]);
}

std::uint32_t read32(std::span<const std::uint8_t> bytes,
                     std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         static_cast<std::uint32_t>(bytes[offset + 3U]);
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

bool valid_packet_type(std::uint8_t value) noexcept {
  return value >= static_cast<std::uint8_t>(PacketType::hello) &&
         value <=
             static_cast<std::uint8_t>(PacketType::link_state_acknowledgment);
}

std::size_t header_octets(std::uint8_t version) noexcept {
  return version == version_two ? version_two_header_octets
                                : version_three_header_octets;
}

std::uint16_t internet_checksum_with_zero_range(
    std::span<const std::uint8_t> bytes, std::size_t zero_begin,
    std::size_t zero_end) noexcept {
  // RFC 2328 excludes the complete 64-bit Authentication field from the
  // ordinary packet checksum. Treating it as zero rather than copying a
  // temporary packet preserves the exact one's-complement arithmetic.
  std::uint32_t sum{};
  for (std::size_t index = 0U; index < bytes.size(); index += 2U) {
    const auto high =
        index >= zero_begin && index < zero_end ? 0U : bytes[index];
    const auto low_index = index + 1U;
    const auto low = low_index >= bytes.size() ||
                             (low_index >= zero_begin && low_index < zero_end)
                         ? 0U
                         : bytes[low_index];
    sum += static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(high) << 8U | low);
    while ((sum >> 16U) != 0U)
      sum = (sum & 0xffffU) + (sum >> 16U);
  }
  return static_cast<std::uint16_t>(~sum);
}

std::uint16_t version_two_checksum(
    std::span<const std::uint8_t> bytes) noexcept {
  return internet_checksum_with_zero_range(
      bytes, version_two_authentication_offset,
      version_two_authentication_offset + 8U);
}

std::uint32_t ipv6_pseudo_header_sum(const ip::Ipv6 &source,
                                     const ip::Ipv6 &destination,
                                     std::size_t length) noexcept {
  std::uint32_t sum{};
  const auto add = [&sum](std::uint16_t word) {
    sum += word;
    while ((sum >> 16U) != 0U)
      sum = (sum & 0xffffU) + (sum >> 16U);
  };
  for (std::size_t index = 0U; index < source.size(); index += 2U) {
    add(static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(source[index]) << 8U |
        source[index + 1U]));
    add(static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(destination[index]) << 8U |
        destination[index + 1U]));
  }
  add(static_cast<std::uint16_t>((length >> 16U) & 0xffffU));
  add(static_cast<std::uint16_t>(length & 0xffffU));
  add(ip_protocol);
  return sum;
}

std::uint16_t version_three_checksum(
    std::span<const std::uint8_t> bytes, const ip::Ipv6 &source,
    const ip::Ipv6 &destination) noexcept {
  // OSPFv3 uses the standard IPv6 upper-layer checksum. This local form can
  // zero the checksum field without mutating or copying caller-owned packet
  // bytes.
  std::uint32_t sum =
      ipv6_pseudo_header_sum(source, destination, bytes.size());
  for (std::size_t index = 0U; index < bytes.size(); index += 2U) {
    const auto high =
        index == checksum_offset || index == checksum_offset + 1U
            ? 0U
            : bytes[index];
    const auto low_index = index + 1U;
    const auto low =
        low_index >= bytes.size() || low_index == checksum_offset ||
                low_index == checksum_offset + 1U
            ? 0U
            : bytes[low_index];
    sum += static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(high) << 8U | low);
    while ((sum >> 16U) != 0U)
      sum = (sum & 0xffffU) + (sum >> 16U);
  }
  return static_cast<std::uint16_t>(~sum);
}

bool valid_lsa_header_sequence(const std::span<const std::uint8_t> headers,
                               std::uint8_t version) noexcept {
  if (headers.size() % lsa_header_octets != 0U)
    return false;
  for (std::size_t offset = 0U; offset < headers.size();
       offset += lsa_header_octets) {
    const auto header = lsa_header(headers.subspan(offset, lsa_header_octets),
                                   version);
    // Acknowledgment and DD packets carry only headers. The encoded Length
    // still describes the complete advertisement and must never be smaller
    // than the header itself.
    if (!header || header->length < lsa_header_octets)
      return false;
  }
  return true;
}

} // namespace

std::optional<PacketView>
parse_packet(std::span<const std::uint8_t> packet) noexcept {
  if (packet.size() < version_three_header_octets)
    return std::nullopt;
  const auto version = packet[0U];
  if (version != version_two && version != version_three)
    return std::nullopt;
  const auto common_header = header_octets(version);
  const auto length = read16(packet, packet_length_offset);
  if (length < common_header || length > packet.size() ||
      !valid_packet_type(packet[1U]))
    return std::nullopt;

  PacketView result{
      .packet = packet.first(length),
      .payload = packet.subspan(common_header,
                                length - common_header),
      .router_id = read32(packet, router_id_offset),
      .area_id = read32(packet, area_id_offset),
      .checksum = read16(packet, checksum_offset),
      .type = static_cast<PacketType>(packet[1U]),
      .version = version};
  if (version == version_two) {
    result.authentication_type =
        read16(packet, version_two_authentication_type_offset);
    if (result.authentication_type >
        static_cast<std::uint16_t>(AuthenticationType::cryptographic))
      return std::nullopt;
    std::copy_n(packet.begin() + version_two_authentication_offset,
                result.authentication.size(), result.authentication.begin());
    if (result.authentication_type ==
        static_cast<std::uint16_t>(AuthenticationType::cryptographic)) {
      // Authentication Data Length is octet 19 of the RFC 2328
      // cryptographic-authentication header. It must describe exactly the
      // suffix outside the OSPF Packet Length, otherwise verification would
      // authenticate a different byte string from the sender.
      const auto digest_octets = result.authentication[3U];
      if (digest_octets == 0U ||
          packet.size() != length + digest_octets)
        return std::nullopt;
      result.authentication_data = packet.subspan(length, digest_octets);
    } else if (packet.size() != length) {
      return std::nullopt;
    }
  } else {
    // RFC 5340 reserves the final header octet. Accepting a nonzero value
    // would turn an unknown extension into ordinary OSPFv3 state.
    if (packet[15U] != 0U)
      return std::nullopt;
    result.instance_id = packet[version_three_instance_offset];
    if (packet.size() != length) {
      auto suffix = packet.subspan(length);
      bool lls_present{};
      if (result.type == PacketType::hello && result.payload.size() >= 8U)
        lls_present =
            (read24(result.payload, 5U) &
             option_link_local_signaling) != 0U;
      else if (result.type == PacketType::database_description &&
               result.payload.size() >= 4U)
        lls_present =
            (read24(result.payload, 1U) &
             option_link_local_signaling) != 0U;
      if (lls_present) {
        // RFC 5613 section 2.2 expresses the complete LLS block length in
        // 32-bit words. The fixed header occupies one word, so zero is never
        // a valid block and arithmetic remains bounded before slicing.
        if (suffix.size() < 4U)
          return std::nullopt;
        const auto words = read16(suffix, 2U);
        const auto lls_octets = static_cast<std::size_t>(words) * 4U;
        if (words == 0U || lls_octets > suffix.size())
          return std::nullopt;
        result.link_local_signaling_data = suffix.first(lls_octets);
        suffix = suffix.subspan(lls_octets);
      }
      // RFC 7166 section 4.1 fixes the trailer prefix at sixteen octets and
      // makes Auth Data Len cover that prefix plus the digest. Requiring an
      // exact suffix prevents unauthenticated garbage after a valid digest.
      if (suffix.size() < 16U || read16(suffix, 0U) != 1U ||
          read16(suffix, 2U) != suffix.size())
        return std::nullopt;
      result.authentication_trailer = suffix;
      result.authentication_data = suffix.subspan(16U);
      if (result.authentication_data.empty())
        return std::nullopt;
    }
  }
  return result;
}

bool verify_version_two_checksum(const PacketView &packet) noexcept {
  if (packet.version != version_two)
    return false;
  if (packet.authentication_type ==
      static_cast<std::uint16_t>(AuthenticationType::cryptographic)) {
    // RFC 2328 cryptographic authentication places zero in the ordinary
    // checksum field. Digest validation is performed by the configured
    // authentication owner using the trailer outside this packet view.
    return packet.checksum == 0U;
  }
  return version_two_checksum(packet.packet) == 0U;
}

bool verify_version_three_checksum(const PacketView &packet,
                                   const ip::Ipv6 &source,
                                   const ip::Ipv6 &destination) noexcept {
  return packet.version == version_three &&
         (!packet.authentication_trailer.empty() ||
         version_three_checksum(packet.packet, source, destination) ==
             packet.checksum);
}

std::optional<std::span<const std::uint8_t>>
encode_version_two(std::span<std::uint8_t> output, PacketType type,
                   std::uint32_t router_id, std::uint32_t area_id,
                   AuthenticationType authentication_type,
                   std::span<const std::uint8_t, 8U> authentication,
                   std::span<const std::uint8_t> payload) noexcept {
  const auto length = version_two_header_octets + payload.size();
  if (length > output.size() ||
      length > std::numeric_limits<std::uint16_t>::max() ||
      authentication_type == AuthenticationType::cryptographic)
    return std::nullopt;
  auto packet = output.first(length);
  std::fill(packet.begin(), packet.end(), std::uint8_t{0U});
  packet[0U] = version_two;
  packet[1U] = static_cast<std::uint8_t>(type);
  write16(packet, packet_length_offset, static_cast<std::uint16_t>(length));
  write32(packet, router_id_offset, router_id);
  write32(packet, area_id_offset, area_id);
  write16(packet, version_two_authentication_type_offset,
          static_cast<std::uint16_t>(authentication_type));
  std::copy(authentication.begin(), authentication.end(),
            packet.begin() + version_two_authentication_offset);
  std::copy(payload.begin(), payload.end(),
            packet.begin() + version_two_header_octets);
  write16(packet, checksum_offset, version_two_checksum(packet));
  return std::span<const std::uint8_t>{packet};
}

std::optional<std::span<const std::uint8_t>>
encode_version_three(std::span<std::uint8_t> output, PacketType type,
                     std::uint32_t router_id, std::uint32_t area_id,
                     std::uint8_t instance_id, const ip::Ipv6 &source,
                     const ip::Ipv6 &destination,
                     std::span<const std::uint8_t> payload) noexcept {
  const auto length = version_three_header_octets + payload.size();
  if (length > output.size() ||
      length > std::numeric_limits<std::uint16_t>::max())
    return std::nullopt;
  auto packet = output.first(length);
  std::fill(packet.begin(), packet.end(), std::uint8_t{0U});
  packet[0U] = version_three;
  packet[1U] = static_cast<std::uint8_t>(type);
  write16(packet, packet_length_offset, static_cast<std::uint16_t>(length));
  write32(packet, router_id_offset, router_id);
  write32(packet, area_id_offset, area_id);
  packet[version_three_instance_offset] = instance_id;
  std::copy(payload.begin(), payload.end(),
            packet.begin() + version_three_header_octets);
  write16(packet, checksum_offset,
          version_three_checksum(packet, source, destination));
  return std::span<const std::uint8_t>{packet};
}

std::optional<std::span<const std::uint8_t>>
encode_database_description_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::uint16_t interface_mtu, std::uint32_t options,
    std::uint32_t sequence_number, bool init, bool more, bool master,
    std::span<const std::uint8_t> lsa_headers,
    bool ipv6_mtu_separate) noexcept {
  const auto fixed = version == version_two ? 8U : 12U;
  if ((version != version_two && version != version_three) ||
      (version == version_two && ipv6_mtu_separate) ||
      !valid_lsa_header_sequence(lsa_headers, version) ||
      fixed + lsa_headers.size() > output.size())
    return std::nullopt;
  auto payload = output.first(fixed + lsa_headers.size());
  std::fill(payload.begin(), payload.end(), std::uint8_t{0U});
  const auto flags = static_cast<std::uint8_t>(
      (init ? dd_init : 0U) | (more ? dd_more : 0U) |
      (master ? dd_master : 0U) |
      (ipv6_mtu_separate ? dd_ipv6_mtu_separate : 0U));
  if (version == version_two) {
    write16(payload, 0U, interface_mtu);
    payload[2U] = static_cast<std::uint8_t>(options);
    payload[3U] = flags;
    write32(payload, 4U, sequence_number);
  } else {
    payload[1U] = static_cast<std::uint8_t>(options >> 16U);
    payload[2U] = static_cast<std::uint8_t>(options >> 8U);
    payload[3U] = static_cast<std::uint8_t>(options);
    write16(payload, 4U, interface_mtu);
    payload[7U] = flags;
    write32(payload, 8U, sequence_number);
  }
  std::copy(lsa_headers.begin(), lsa_headers.end(),
            payload.begin() + static_cast<std::ptrdiff_t>(fixed));
  return std::span<const std::uint8_t>{payload};
}

std::optional<std::span<const std::uint8_t>>
encode_link_state_request_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const LinkStateRequestEntry> entries) noexcept {
  constexpr std::size_t entry_octets = 12U;
  if ((version != version_two && version != version_three) ||
      entries.empty() || entries.size() > output.size() / entry_octets)
    return std::nullopt;
  auto payload = output.first(entries.size() * entry_octets);
  std::fill(payload.begin(), payload.end(), std::uint8_t{0U});
  for (std::size_t index{}; index < entries.size(); ++index) {
    const auto offset = index * entry_octets;
    write32(payload, offset, entries[index].link_state_type);
    write32(payload, offset + 4U, entries[index].link_state_id);
    write32(payload, offset + 8U, entries[index].advertising_router);
  }
  return std::span<const std::uint8_t>{payload};
}

std::optional<std::span<const std::uint8_t>>
encode_link_state_update_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const EncodedLsa> advertisements) noexcept {
  if ((version != version_two && version != version_three) ||
      advertisements.empty() ||
      advertisements.size() > std::numeric_limits<std::uint32_t>::max() ||
      output.size() < 4U)
    return std::nullopt;
  std::size_t length = 4U;
  for (const auto &advertisement : advertisements) {
    const auto header = lsa_header(advertisement.bytes, version);
    if (!header || header->length != advertisement.bytes.size() ||
        advertisement.bytes.size() > output.size() - length)
      return std::nullopt;
    length += advertisement.bytes.size();
  }
  auto payload = output.first(length);
  std::fill(payload.begin(), payload.end(), std::uint8_t{0U});
  write32(payload, 0U, static_cast<std::uint32_t>(advertisements.size()));
  std::size_t offset = 4U;
  for (const auto &advertisement : advertisements) {
    std::copy(advertisement.bytes.begin(), advertisement.bytes.end(),
              payload.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += advertisement.bytes.size();
  }
  return std::span<const std::uint8_t>{payload};
}

std::optional<std::span<const std::uint8_t>>
encode_link_state_acknowledgment_payload(
    std::span<std::uint8_t> output, std::uint8_t version,
    std::span<const std::uint8_t> lsa_headers) noexcept {
  if (!valid_lsa_header_sequence(lsa_headers, version) ||
      lsa_headers.empty() || lsa_headers.size() > output.size())
    return std::nullopt;
  std::copy(lsa_headers.begin(), lsa_headers.end(), output.begin());
  return std::span<const std::uint8_t>{output.first(lsa_headers.size())};
}

std::optional<HelloView> parse_hello(const PacketView &packet) noexcept {
  if (packet.type != PacketType::hello || packet.payload.size() < 20U ||
      (packet.payload.size() - 20U) % 4U != 0U)
    return std::nullopt;
  if (packet.version == version_two) {
    return HelloView{
        .network_mask = read32(packet.payload, 0U),
        .designated_router = read32(packet.payload, 12U),
        .backup_designated_router = read32(packet.payload, 16U),
        .neighbors = packet.payload.subspan(20U),
        .dead_interval_seconds = read32(packet.payload, 8U),
        .options = packet.payload[6U],
        .hello_interval_seconds = read16(packet.payload, 4U),
        .router_priority = packet.payload[7U],
        .version = version_two};
  }
  return HelloView{
      .interface_id = read32(packet.payload, 0U),
      .designated_router = read32(packet.payload, 12U),
      .backup_designated_router = read32(packet.payload, 16U),
      .neighbors = packet.payload.subspan(20U),
      .dead_interval_seconds = read16(packet.payload, 10U),
      .options = static_cast<std::uint32_t>(packet.payload[5U]) << 16U |
                 static_cast<std::uint32_t>(packet.payload[6U]) << 8U |
                 packet.payload[7U],
      .hello_interval_seconds = read16(packet.payload, 8U),
      .router_priority = packet.payload[4U],
      .version = version_three};
}

std::optional<DatabaseDescriptionView>
parse_database_description(const PacketView &packet) noexcept {
  if (packet.type != PacketType::database_description)
    return std::nullopt;
  if (packet.version == version_two) {
    if (packet.payload.size() < 8U)
      return std::nullopt;
    const auto headers = packet.payload.subspan(8U);
    if (!valid_lsa_header_sequence(headers, version_two))
      return std::nullopt;
    const auto flags = packet.payload[3U];
    if ((flags & 0xf8U) != 0U)
      return std::nullopt;
    return DatabaseDescriptionView{
        .lsa_headers = headers,
        .options = packet.payload[2U],
        .sequence_number = read32(packet.payload, 4U),
        .interface_mtu = read16(packet.payload, 0U),
        .init = (flags & dd_init) != 0U,
        .more = (flags & dd_more) != 0U,
        .master = (flags & dd_master) != 0U,
        .ipv6_mtu_separate = false,
        .version = version_two};
  }
  if (packet.payload.size() < 12U || packet.payload[0U] != 0U ||
      packet.payload[6U] != 0U)
    return std::nullopt;
  const auto flags = packet.payload[7U];
  const auto headers = packet.payload.subspan(12U);
  // Bit 3 is the RFC 5838 M6 bit. All higher bits remain reserved and must
  // fail decoding, otherwise an unknown DD capability could silently alter
  // adjacency compatibility.
  if ((flags & 0xf0U) != 0U ||
      !valid_lsa_header_sequence(headers, version_three))
    return std::nullopt;
  return DatabaseDescriptionView{
      .lsa_headers = headers,
      .options = static_cast<std::uint32_t>(packet.payload[1U]) << 16U |
                 static_cast<std::uint32_t>(packet.payload[2U]) << 8U |
                 packet.payload[3U],
      .sequence_number = read32(packet.payload, 8U),
      .interface_mtu = read16(packet.payload, 4U),
      .init = (flags & dd_init) != 0U,
      .more = (flags & dd_more) != 0U,
      .master = (flags & dd_master) != 0U,
      .ipv6_mtu_separate =
          (flags & dd_ipv6_mtu_separate) != 0U,
      .version = version_three};
}

std::optional<LinkStateRequestView>
parse_link_state_request(const PacketView &packet) noexcept {
  if (packet.type != PacketType::link_state_request ||
      packet.payload.empty() || packet.payload.size() % 12U != 0U)
    return std::nullopt;
  return LinkStateRequestView{.entries = packet.payload,
                              .version = packet.version};
}

std::optional<LinkStateUpdateView>
parse_link_state_update(const PacketView &packet) noexcept {
  if (packet.type != PacketType::link_state_update ||
      packet.payload.size() < 4U)
    return std::nullopt;
  const auto count = read32(packet.payload, 0U);
  auto remaining = packet.payload.subspan(4U);
  for (std::uint32_t index = 0U; index < count; ++index) {
    const auto header = lsa_header(remaining, packet.version);
    if (!header || header->length > remaining.size())
      return std::nullopt;
    remaining = remaining.subspan(header->length);
  }
  if (!remaining.empty())
    return std::nullopt;
  return LinkStateUpdateView{.lsas = packet.payload.subspan(4U),
                             .advertisement_count = count,
                             .version = packet.version};
}

std::optional<LinkStateAcknowledgmentView>
parse_link_state_acknowledgment(const PacketView &packet) noexcept {
  if (packet.type != PacketType::link_state_acknowledgment ||
      packet.payload.empty() ||
      !valid_lsa_header_sequence(packet.payload, packet.version))
    return std::nullopt;
  return LinkStateAcknowledgmentView{.lsa_headers = packet.payload,
                                     .version = packet.version};
}

std::optional<std::uint32_t>
hello_neighbor(const HelloView &hello, std::size_t index) noexcept {
  if (index >= hello.neighbors.size() / 4U)
    return std::nullopt;
  return read32(hello.neighbors, index * 4U);
}

std::optional<LinkStateRequestEntry>
request_entry(const LinkStateRequestView &request,
              std::size_t index) noexcept {
  if (index >= request.entries.size() / 12U)
    return std::nullopt;
  const auto offset = index * 12U;
  const auto encoded_type = read32(request.entries, offset);
  if (request.version == version_three && (encoded_type >> 16U) != 0U)
    return std::nullopt;
  return LinkStateRequestEntry{
      .link_state_type =
          request.version == version_three ? encoded_type & 0xffffU
                                           : encoded_type,
      .link_state_id = read32(request.entries, offset + 4U),
      .advertising_router = read32(request.entries, offset + 8U)};
}

std::optional<LsaHeaderView>
lsa_header(std::span<const std::uint8_t> bytes,
           std::uint8_t version) noexcept {
  if ((version != version_two && version != version_three) ||
      bytes.size() < lsa_header_octets)
    return std::nullopt;
  const auto length = read16(bytes, 18U);
  if (length < lsa_header_octets)
    return std::nullopt;
  LsaHeaderView result{
      .link_state_id = read32(bytes, 4U),
      .advertising_router = read32(bytes, 8U),
      .sequence_number = static_cast<std::int32_t>(read32(bytes, 12U)),
      .age_seconds = read16(bytes, 0U),
      .checksum = read16(bytes, 16U),
      .length = length,
      .version = version};
  if (version == version_two) {
    result.options = bytes[2U];
    result.type = bytes[3U];
    if (result.type == 0U)
      return std::nullopt;
  } else {
    result.type = read16(bytes, 2U);
    if ((result.type & 0x1fffU) == 0U)
      return std::nullopt;
  }
  return result;
}

std::optional<std::span<const std::uint8_t>>
update_lsa(const LinkStateUpdateView &update, std::size_t index) noexcept {
  if (index >= update.advertisement_count)
    return std::nullopt;
  auto remaining = update.lsas;
  for (std::size_t current = 0U; current <= index; ++current) {
    const auto header = lsa_header(remaining, update.version);
    if (!header || header->length > remaining.size())
      return std::nullopt;
    if (current == index)
      return remaining.first(header->length);
    remaining = remaining.subspan(header->length);
  }
  return std::nullopt;
}

std::optional<LsaHeaderView> acknowledgment_header(
    const LinkStateAcknowledgmentView &acknowledgment,
    std::size_t index) noexcept {
  if (index >= acknowledgment.lsa_headers.size() / lsa_header_octets)
    return std::nullopt;
  return lsa_header(
      acknowledgment.lsa_headers.subspan(index * lsa_header_octets,
                                         lsa_header_octets),
      acknowledgment.version);
}

} // namespace router::packet::ospf
