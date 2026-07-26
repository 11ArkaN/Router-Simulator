// RFC 9915 DHCPv6 structural parsing and serialization. Semantic client,
// server and relay state machines consume these views but cannot weaken their
// bounds or reinterpret truncated option data as an absent option.

#include "router/dhcpv6_packet.hpp"

#include <algorithm>
#include <limits>

namespace router::packet::dhcpv6 {
namespace {

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
      bytes[offset + 1U]);
}

[[nodiscard]] std::uint32_t read24(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
         bytes[offset + 2U];
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
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

[[nodiscard]] bool options_well_formed(
    std::span<const std::uint8_t> bytes) noexcept {
  OptionCursor cursor{bytes};
  while (cursor.next()) {
  }
  return cursor.valid();
}

} // namespace

std::optional<OptionView> OptionCursor::next() noexcept {
  if (!valid_ || remaining_.empty())
    return std::nullopt;
  if (remaining_.size() < 4U) {
    valid_ = false;
    return std::nullopt;
  }
  const auto code = read16(remaining_, 0U);
  const auto length = read16(remaining_, 2U);
  if (remaining_.size() - 4U < length) {
    valid_ = false;
    return std::nullopt;
  }
  const auto data = remaining_.subspan(4U, length);
  remaining_ = remaining_.subspan(4U + length);
  return OptionView{.code = code, .data = data};
}

std::optional<MessageView> parse(
    std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.empty())
    return std::nullopt;
  const auto type = bytes.front();
  const auto relay = type == static_cast<std::uint8_t>(
                                  MessageType::relay_forward) ||
                     type == static_cast<std::uint8_t>(MessageType::relay_reply);
  if (relay) {
    if (bytes.size() < relay_header_octets)
      return std::nullopt;
    MessageView result{.type = type,
                       .hop_count = bytes[1U],
                       .options = bytes.subspan(relay_header_octets),
                       .relay = true};
    std::copy_n(bytes.begin() + 2U, result.link_address.size(),
                result.link_address.begin());
    std::copy_n(bytes.begin() + 18U, result.peer_address.size(),
                result.peer_address.begin());
    if (!options_well_formed(result.options))
      return std::nullopt;
    return result;
  }
  if (bytes.size() < client_server_header_octets)
    return std::nullopt;
  MessageView result{.type = type,
                     .transaction_id = read24(bytes, 1U),
                     .options = bytes.subspan(client_server_header_octets)};
  if (!options_well_formed(result.options))
    return std::nullopt;
  return result;
}

bool Writer::append(std::uint16_t code,
                    std::span<const std::uint8_t> data) noexcept {
  if (data.size() > std::numeric_limits<std::uint16_t>::max() ||
      output_.size() - position_ < 4U ||
      output_.size() - position_ - 4U < data.size())
    return false;
  write16(output_, position_, code);
  write16(output_, position_ + 2U,
          static_cast<std::uint16_t>(data.size()));
  std::copy(data.begin(), data.end(), output_.begin() + position_ + 4U);
  position_ += 4U + data.size();
  return true;
}

std::optional<Writer>
begin_client_server(std::span<std::uint8_t> output, std::uint8_t type,
                    std::uint32_t transaction_id) noexcept {
  if (output.size() < client_server_header_octets ||
      transaction_id > 0x00ffffffU ||
      type == static_cast<std::uint8_t>(MessageType::relay_forward) ||
      type == static_cast<std::uint8_t>(MessageType::relay_reply))
    return std::nullopt;
  output[0U] = type;
  output[1U] = static_cast<std::uint8_t>(transaction_id >> 16U);
  output[2U] = static_cast<std::uint8_t>(transaction_id >> 8U);
  output[3U] = static_cast<std::uint8_t>(transaction_id);
  return Writer{output, client_server_header_octets};
}

std::optional<Writer>
begin_relay(std::span<std::uint8_t> output, std::uint8_t type,
            std::uint8_t hop_count, Ipv6 link_address,
            Ipv6 peer_address) noexcept {
  if (output.size() < relay_header_octets ||
      (type != static_cast<std::uint8_t>(MessageType::relay_forward) &&
       type != static_cast<std::uint8_t>(MessageType::relay_reply)))
    return std::nullopt;
  output[0U] = type;
  output[1U] = hop_count;
  std::copy(link_address.begin(), link_address.end(), output.begin() + 2U);
  std::copy(peer_address.begin(), peer_address.end(), output.begin() + 18U);
  return Writer{output, relay_header_octets};
}

std::optional<IdentityAssociationView>
parse_ia_na_or_pd(std::span<const std::uint8_t> data) noexcept {
  if (data.size() < 12U)
    return std::nullopt;
  const auto options = data.subspan(12U);
  if (!options_well_formed(options))
    return std::nullopt;
  return IdentityAssociationView{.iaid = read32(data, 0U),
                                 .t1 = read32(data, 4U),
                                 .t2 = read32(data, 8U),
                                 .options = options};
}

std::optional<TemporaryIdentityAssociationView>
parse_ia_ta(std::span<const std::uint8_t> data) noexcept {
  if (data.size() < 4U)
    return std::nullopt;
  const auto options = data.subspan(4U);
  if (!options_well_formed(options))
    return std::nullopt;
  return TemporaryIdentityAssociationView{.iaid = read32(data, 0U),
                                          .options = options};
}

std::optional<IaAddressView>
parse_ia_address(std::span<const std::uint8_t> data) noexcept {
  if (data.size() < 24U)
    return std::nullopt;
  IaAddressView result{};
  std::copy_n(data.begin(), result.address.size(), result.address.begin());
  result.preferred_lifetime = read32(data, 16U);
  result.valid_lifetime = read32(data, 20U);
  result.options = data.subspan(24U);
  // RFC 9915 section 21.6 requires clients to discard an address whose
  // preferred lifetime exceeds its valid lifetime.
  if (result.preferred_lifetime > result.valid_lifetime ||
      !options_well_formed(result.options))
    return std::nullopt;
  return result;
}

std::optional<IaPrefixView>
parse_ia_prefix(std::span<const std::uint8_t> data) noexcept {
  if (data.size() < 25U)
    return std::nullopt;
  IaPrefixView result{.preferred_lifetime = read32(data, 0U),
                      .valid_lifetime = read32(data, 4U),
                      .prefix_length = data[8U],
                      .options = data.subspan(25U)};
  std::copy_n(data.begin() + 9U, result.prefix.size(), result.prefix.begin());
  if (result.prefix_length > 128U ||
      result.preferred_lifetime > result.valid_lifetime ||
      !options_well_formed(result.options))
    return std::nullopt;
  return result;
}

std::optional<PrefixExcludeView> parse_prefix_exclude(
    std::span<const std::uint8_t> data, const Ipv6 &delegated_prefix,
    std::uint8_t delegated_prefix_length) noexcept {
  // RFC 6603 section 4.2 permits one to sixteen subnet-id octets plus the
  // excluded prefix length. The excluded prefix must be a strict child of the
  // IAPREFIX value, so a /128 delegation cannot carry this option.
  if (data.size() < 2U || data.size() > 17U ||
      delegated_prefix_length >= 128U)
    return std::nullopt;
  const auto excluded_length = data[0U];
  if (excluded_length <= delegated_prefix_length || excluded_length > 128U)
    return std::nullopt;
  const auto subnet_bits = static_cast<std::size_t>(excluded_length -
                                                     delegated_prefix_length);
  const auto subnet_octets = (subnet_bits + 7U) / 8U;
  if (data.size() != subnet_octets + 1U)
    return std::nullopt;

  // Bits beyond the declared subnet-id length are padding and MUST be zero.
  // Rejecting non-canonical encodings prevents two byte strings from naming
  // the same black-hole route in the lease and RIB owners.
  const auto padding_bits = subnet_octets * 8U - subnet_bits;
  if (padding_bits != 0U) {
    const auto padding_mask = static_cast<std::uint8_t>(
        (std::uint16_t{1U} << padding_bits) - 1U);
    if ((data.back() & padding_mask) != 0U)
      return std::nullopt;
  }

  PrefixExcludeView result{.excluded_prefix = delegated_prefix,
                           .excluded_prefix_length = excluded_length};
  // Clear every bit outside the delegated prefix before appending the encoded
  // subnet ID. A malformed IAPREFIX with nonzero host bits therefore cannot
  // smuggle unrelated suffix data into the reconstructed route.
  for (std::size_t bit = delegated_prefix_length; bit < 128U; ++bit)
    result.excluded_prefix[bit / 8U] &=
        static_cast<std::uint8_t>(~(1U << (7U - bit % 8U)));
  for (std::size_t offset = 0; offset < subnet_bits; ++offset) {
    const auto source_mask =
        static_cast<std::uint8_t>(1U << (7U - offset % 8U));
    if ((data[1U + offset / 8U] & source_mask) == 0U)
      continue;
    const auto target_bit =
        static_cast<std::size_t>(delegated_prefix_length) + offset;
    result.excluded_prefix[target_bit / 8U] |=
        static_cast<std::uint8_t>(1U << (7U - target_bit % 8U));
  }
  return result;
}

std::optional<std::size_t> encode_ia_na_or_pd(
    std::span<std::uint8_t> output, std::uint32_t iaid, std::uint32_t t1,
    std::uint32_t t2, std::span<const std::uint8_t> options) noexcept {
  constexpr std::size_t fixed = 12U;
  if (!options_well_formed(options) || output.size() < fixed + options.size())
    return std::nullopt;
  write32(output, 0U, iaid);
  write32(output, 4U, t1);
  write32(output, 8U, t2);
  std::copy(options.begin(), options.end(), output.begin() + fixed);
  return fixed + options.size();
}

std::optional<std::size_t> encode_ia_ta(
    std::span<std::uint8_t> output, std::uint32_t iaid,
    std::span<const std::uint8_t> options) noexcept {
  constexpr std::size_t fixed = 4U;
  if (!options_well_formed(options) || output.size() < fixed + options.size())
    return std::nullopt;
  write32(output, 0U, iaid);
  std::copy(options.begin(), options.end(), output.begin() + fixed);
  return fixed + options.size();
}

std::optional<std::size_t> encode_ia_address(
    std::span<std::uint8_t> output, Ipv6 address,
    std::uint32_t preferred_lifetime, std::uint32_t valid_lifetime,
    std::span<const std::uint8_t> options) noexcept {
  constexpr std::size_t fixed = 24U;
  if (preferred_lifetime > valid_lifetime ||
      !options_well_formed(options) || output.size() < fixed + options.size())
    return std::nullopt;
  std::copy(address.begin(), address.end(), output.begin());
  write32(output, 16U, preferred_lifetime);
  write32(output, 20U, valid_lifetime);
  std::copy(options.begin(), options.end(), output.begin() + fixed);
  return fixed + options.size();
}

std::optional<std::size_t> encode_ia_prefix(
    std::span<std::uint8_t> output, Ipv6 prefix, std::uint8_t prefix_length,
    std::uint32_t preferred_lifetime, std::uint32_t valid_lifetime,
    std::span<const std::uint8_t> options) noexcept {
  constexpr std::size_t fixed = 25U;
  if (prefix_length > 128U || preferred_lifetime > valid_lifetime ||
      !options_well_formed(options) || output.size() < fixed + options.size())
    return std::nullopt;
  write32(output, 0U, preferred_lifetime);
  write32(output, 4U, valid_lifetime);
  output[8U] = prefix_length;
  std::copy(prefix.begin(), prefix.end(), output.begin() + 9U);
  std::copy(options.begin(), options.end(), output.begin() + fixed);
  return fixed + options.size();
}

std::optional<StatusCodeView>
parse_status_code(std::span<const std::uint8_t> data) noexcept {
  if (data.size() < 2U)
    return std::nullopt;
  return StatusCodeView{.code = read16(data, 0U),
                        .message = data.subspan(2U)};
}

std::optional<std::size_t> encode_status_code(
    std::span<std::uint8_t> output, std::uint16_t code,
    std::span<const std::uint8_t> message) noexcept {
  if (output.size() < 2U + message.size())
    return std::nullopt;
  write16(output, 0U, code);
  std::copy(message.begin(), message.end(), output.begin() + 2U);
  return 2U + message.size();
}

Ipv6 Ipv6AddressSequenceView::operator[](std::size_t index) const noexcept {
  Ipv6 result{};
  const auto first = bytes_.begin() + index * result.size();
  std::copy_n(first, result.size(), result.begin());
  return result;
}

std::optional<Ipv6AddressSequenceView> parse_dns_recursive_name_servers(
    std::span<const std::uint8_t> data) noexcept {
  if (data.empty() || data.size() % Ipv6{}.size() != 0U)
    return std::nullopt;
  return Ipv6AddressSequenceView{data};
}

std::size_t DomainSearchListView::size() const noexcept {
  std::size_t count{};
  std::size_t offset{};
  dns::Name ignored;
  while (offset < bytes_.size()) {
    const auto consumed =
        dns::parse_uncompressed_name(bytes_.subspan(offset), ignored);
    // The parser is the sole constructor gate. This branch guards only
    // against future internal misuse, not a recoverable wire-input state.
    if (!consumed)
      return 0U;
    offset += *consumed;
    ++count;
  }
  return count;
}

dns::Name DomainSearchListView::operator[](std::size_t index) const noexcept {
  std::size_t offset{};
  dns::Name name;
  for (std::size_t current{}; current <= index && offset < bytes_.size();
       ++current) {
    const auto consumed =
        dns::parse_uncompressed_name(bytes_.subspan(offset), name);
    if (!consumed)
      return {};
    if (current == index)
      return name;
    offset += *consumed;
  }
  return {};
}

std::optional<DomainSearchListView>
parse_domain_search_list(std::span<const std::uint8_t> data) noexcept {
  std::size_t offset{};
  dns::Name name;
  while (offset < data.size()) {
    const auto consumed =
        dns::parse_uncompressed_name(data.subspan(offset), name);
    if (!consumed)
      return std::nullopt;
    offset += *consumed;
  }
  return DomainSearchListView{data};
}

bool valid_duid(std::span<const std::uint8_t> data) noexcept {
  // The two-octet type is followed by an identifier of one through 128
  // octets. Unknown type values remain valid opaque identities.
  return data.size() >= 3U && data.size() <= maximum_duid_octets;
}

std::optional<std::size_t>
encode_duid_llt_ethernet(std::span<std::uint8_t> output, Mac address,
                         std::uint32_t seconds_since_2000) noexcept {
  constexpr std::size_t wire_octets = 2U + 2U + 4U + Mac{}.size();
  if (output.size() < wire_octets)
    return std::nullopt;
  // DUID type 1 is LLT and ARP hardware type 1 identifies Ethernet.
  write16(output, 0U, 1U);
  write16(output, 2U, 1U);
  output[4U] = static_cast<std::uint8_t>(seconds_since_2000 >> 24U);
  output[5U] = static_cast<std::uint8_t>(seconds_since_2000 >> 16U);
  output[6U] = static_cast<std::uint8_t>(seconds_since_2000 >> 8U);
  output[7U] = static_cast<std::uint8_t>(seconds_since_2000);
  std::copy(address.begin(), address.end(), output.begin() + 8U);
  return wire_octets;
}

} // namespace router::packet::dhcpv6
