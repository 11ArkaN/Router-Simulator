// RFC 4861 Neighbor Solicitation and Advertisement encoding and validation.
// Every result is a complete Ethernet frame, preserving the repository rule
// that neighbor information cannot cross devices as an in-memory object.

#include "router/neighbor_discovery_packet.hpp"

#include <algorithm>
#include <array>

namespace router::packet::nd {
namespace {

struct LinkLayerOptionResult {
  bool valid{true};
  std::optional<Mac> address{};
};

[[nodiscard]] LinkLayerOptionResult
link_layer_option(std::span<const std::uint8_t> options,
                  std::uint8_t requested_type) noexcept {
  LinkLayerOptionResult result;
  std::size_t offset{};
  while (offset < options.size()) {
    // Every ND option begins with type and a length measured in units of eight
    // octets. A zero length would never advance and is therefore a mandatory
    // discard condition rather than an unknown option to skip.
    if (offset + 2U > options.size() || options[offset + 1U] == 0U) {
      result.valid = false;
      return result;
    }
    const auto length = static_cast<std::size_t>(options[offset + 1U]) * 8U;
    if (offset + length > options.size()) {
      result.valid = false;
      return result;
    }
    if (options[offset] == requested_type) {
      // Ethernet link-layer address options are exactly one unit. Rejecting a
      // duplicate avoids choosing one of two contradictory sender identities.
      if (length != 8U || result.address) {
        result.valid = false;
        return result;
      }
      Mac address{};
      std::copy_n(options.begin() + static_cast<std::ptrdiff_t>(offset + 2U),
                  address.size(), address.begin());
      result.address = address;
    }
    offset += length;
  }
  return result;
}

void append_address(std::array<std::uint8_t, 28> &body,
                    std::size_t offset, const Ipv6 &address) noexcept {
  std::copy(address.begin(), address.end(),
            body.begin() + static_cast<std::ptrdiff_t>(offset));
}

void put16(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void put32(std::span<std::uint8_t> bytes, std::size_t offset,
           std::uint32_t value) noexcept {
  // ND integer fields use network byte order regardless of host architecture.
  // Writing each octet also keeps the codec safe on unaligned Wasm storage.
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::uint32_t get32(std::span<const std::uint8_t> bytes,
                                  std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(bytes[offset]) << 24U |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U |
         bytes[offset + 3U];
}

[[nodiscard]] std::uint8_t
preference_bits(RouterPreference preference) noexcept {
  switch (preference) {
  case RouterPreference::high:
    return 0x08U;
  case RouterPreference::low:
    return 0x18U;
  case RouterPreference::medium:
    return 0U;
  }
  return 0U;
}

[[nodiscard]] RouterPreference
parse_preference(std::uint8_t flags) noexcept {
  const auto bits = static_cast<std::uint8_t>(flags & 0x18U);
  if (bits == 0x08U)
    return RouterPreference::high;
  if (bits == 0x18U)
    return RouterPreference::low;
  // RFC 4191 reserves binary 10 and requires receivers to treat it as medium.
  // Normalization here keeps that compatibility rule out of every state owner.
  return RouterPreference::medium;
}

} // namespace

Frame neighbor_solicitation(Mac source_mac, Ipv6 source, Ipv6 target,
                            bool dad) noexcept {
  const auto destination = ip::solicited_node_multicast(target);
  const auto destination_mac = ipv6_multicast_mac(destination);
  std::array<std::uint8_t, 28> body{};
  // Bytes 0 through 3 are the reserved field following the checksum. Target
  // begins at byte 4. A normal NS appends one eight-octet SLLA option.
  append_address(body, 4, target);
  std::size_t body_length = 20U;
  if (!dad) {
    body[20] = 1; // Source Link-Layer Address
    body[21] = 1; // one eight-octet unit
    std::copy(source_mac.begin(), source_mac.end(), body.begin() + 22);
    body_length = body.size();
  }
  Frame result;
  const Ipv6 unspecified{};
  icmpv6_message_into(result, source_mac, destination_mac,
                      dad ? unspecified : source, destination, 135, 0,
                      std::span<const std::uint8_t>{body.data(), body_length},
                      255);
  return result;
}

Frame neighbor_unicast_probe(Mac source_mac, Mac destination_mac, Ipv6 source,
                             Ipv6 target) noexcept {
  // NUD PROBE sends NS directly to the cached neighbor instead of the
  // solicited-node multicast group. It still carries SLLA so the receiver can
  // update a changed sender mapping from the validated message.
  std::array<std::uint8_t, 28> body{};
  append_address(body, 4, target);
  body[20] = 1;
  body[21] = 1;
  std::copy(source_mac.begin(), source_mac.end(), body.begin() + 22);
  Frame result;
  icmpv6_message_into(result, source_mac, destination_mac, source, target, 135,
                      0, body, 255);
  return result;
}

Frame neighbor_advertisement(Mac source_mac, Mac destination_mac,
                             Ipv6 source, Ipv6 destination, Ipv6 target,
                             bool router, bool solicited,
                             bool override_flag) noexcept {
  std::array<std::uint8_t, 28> body{};
  // R, S and O occupy the three high bits of the 32-bit flags field. Remaining
  // bits are transmitted as zero and ignored on receipt.
  body[0] = static_cast<std::uint8_t>((router ? 0x80U : 0U) |
                                     (solicited ? 0x40U : 0U) |
                                     (override_flag ? 0x20U : 0U));
  append_address(body, 4, target);
  body[20] = 2; // Target Link-Layer Address
  body[21] = 1;
  std::copy(source_mac.begin(), source_mac.end(), body.begin() + 22);
  Frame result;
  icmpv6_message_into(result, source_mac, destination_mac, source, destination,
                      136, 0, body, 255);
  return result;
}

std::optional<Frame> redirect(
    Mac source_mac, Mac receiver_mac, Ipv6 source, Ipv6 receiver,
    Ipv6 target, Ipv6 destination, std::optional<Mac> target_link_layer,
    const Frame &invoking_packet) noexcept {
  const auto invoked_ipv6 = parse_ipv6(invoking_packet);
  if (!ip::is_link_local(source) || ip::is_unspecified(receiver) ||
      ip::is_multicast(receiver) || ip::is_unspecified(destination) ||
      ip::is_multicast(destination) ||
      !(ip::is_link_local(target) || target == destination) ||
      !invoked_ipv6)
    return std::nullopt;

  // RFC 4861 section 4.5 limits the complete IPv6 Redirect packet to 1280
  // octets. The fixed body includes reserved, target and destination fields.
  // Every option length is an eight-octet multiple, so the Redirected Header
  // capacity is rounded down before copying the invoking IPv6 packet.
  constexpr auto maximum_body =
      static_cast<std::size_t>(ipv6_minimum_link_mtu) - ipv6_header_octets - 4U;
  std::array<std::uint8_t, maximum_body> body{};
  std::copy(target.begin(), target.end(), body.begin() + 4);
  std::copy(destination.begin(), destination.end(), body.begin() + 20);
  auto used = std::size_t{36};
  if (target_link_layer) {
    body[used] = 2U;
    body[used + 1U] = 1U;
    std::copy(target_link_layer->begin(), target_link_layer->end(),
              body.begin() + static_cast<std::ptrdiff_t>(used + 2U));
    used += 8U;
  }

  const auto option_capacity = (body.size() - used) / 8U * 8U;
  if (option_capacity < 8U)
    return std::nullopt;
  body[used] = 4U;
  body[used + 1U] = static_cast<std::uint8_t>(option_capacity / 8U);
  const auto original_ipv6_octets = invoking_packet.view().subspan(
      ethernet_header_octets,
      std::min(invoking_packet.size() - ethernet_header_octets,
               ipv6_header_octets +
                   static_cast<std::size_t>(invoked_ipv6->payload_length)));
  const auto quoted = std::min(original_ipv6_octets.size(),
                               option_capacity - 8U);
  std::copy_n(original_ipv6_octets.begin(), quoted,
              body.begin() + static_cast<std::ptrdiff_t>(used + 8U));
  used += option_capacity;

  Frame result;
  icmpv6_message_into(result, source_mac, receiver_mac, source, receiver,
                      redirect_type, 0U,
                      std::span<const std::uint8_t>{body.data(), used},
                      required_hop_limit);
  return result.length ? std::optional<Frame>{result} : std::nullopt;
}

Frame router_solicitation(Mac source_mac, Ipv6 source) noexcept {
  // RFC 4861 section 4.1 transmits a four-octet reserved field followed by
  // options. An unspecified source is used before the host owns an address and
  // must not carry SLLA, while an addressed host includes its Ethernet identity.
  std::array<std::uint8_t, 12> body{};
  auto body_length = std::size_t{4};
  if (!ip::is_unspecified(source)) {
    body[4] = 1U;
    body[5] = 1U;
    std::copy(source_mac.begin(), source_mac.end(), body.begin() + 6);
    body_length = body.size();
  }
  Frame result;
  icmpv6_message_into(
      result, source_mac, ipv6_multicast_mac(all_routers_multicast), source,
      all_routers_multicast, router_solicitation_type, 0U,
      std::span<const std::uint8_t>{body.data(), body_length},
      required_hop_limit);
  return result;
}

std::optional<Frame>
router_advertisement(Mac source_mac, Ipv6 source, Ipv6 destination,
                     const RouterAdvertisementConfig &config) noexcept {
  // RFC 4861 requires a link-local source. A multicast response is sent only
  // to ff02::1; solicited responses may instead use the requesting host's
  // unicast address. Refusing invalid local intent prevents emitting packets a
  // conforming receiver would discard.
  if (!ip::is_link_local(source) || ip::is_unspecified(destination) ||
      (ip::is_multicast(destination) && destination != all_nodes_multicast) ||
      config.prefix_count > config.prefixes.size() ||
      config.rdnss.count > config.rdnss.servers.size() ||
      (config.advertised_mtu != 0U &&
       config.advertised_mtu < ipv6_minimum_link_mtu))
    return std::nullopt;

  // The body bound is derived from the selected physical frame profile. No RA
  // option is silently omitted to fit: capacity failure rejects the operation
  // before a partially representative advertisement reaches the wire.
  std::array<std::uint8_t, maximum_frame_octets - 58U> body{};
  auto used = std::size_t{12};
  body[0] = config.current_hop_limit;
  body[1] = static_cast<std::uint8_t>(
      (config.managed_configuration ? 0x80U : 0U) |
      (config.other_configuration ? 0x40U : 0U) |
      preference_bits(config.preference));
  put16(body, 2U, config.router_lifetime_seconds);
  put32(body, 4U, config.reachable_time_milliseconds);
  put32(body, 8U, config.retrans_timer_milliseconds);

  const auto reserve = [&](std::size_t length) noexcept {
    return used + length <= body.size();
  };
  if (config.include_source_link_layer) {
    if (!reserve(8U))
      return std::nullopt;
    body[used] = 1U;
    body[used + 1U] = 1U;
    std::copy(source_mac.begin(), source_mac.end(), body.begin() +
                                                       static_cast<std::ptrdiff_t>(used + 2U));
    used += 8U;
  }
  if (config.advertised_mtu != 0U) {
    if (!reserve(8U))
      return std::nullopt;
    body[used] = 5U;
    body[used + 1U] = 1U;
    put32(body, used + 4U, config.advertised_mtu);
    used += 8U;
  }
  for (std::size_t index = 0; index < config.prefix_count; ++index) {
    const auto &prefix = config.prefixes[index];
    if (prefix.prefix.length > ip::ipv6_address_bits ||
        ip::mask(prefix.prefix.network, prefix.prefix.length) !=
            prefix.prefix.network ||
        ip::is_link_local(prefix.prefix.network) ||
        prefix.preferred_lifetime_seconds > prefix.valid_lifetime_seconds ||
        !reserve(32U))
      return std::nullopt;
    body[used] = 3U;
    body[used + 1U] = 4U;
    body[used + 2U] = prefix.prefix.length;
    body[used + 3U] = static_cast<std::uint8_t>(
        (prefix.on_link ? 0x80U : 0U) |
        (prefix.autonomous ? 0x40U : 0U));
    put32(body, used + 4U, prefix.valid_lifetime_seconds);
    put32(body, used + 8U, prefix.preferred_lifetime_seconds);
    std::copy(prefix.prefix.network.begin(), prefix.prefix.network.end(),
              body.begin() + static_cast<std::ptrdiff_t>(used + 16U));
    used += 32U;
  }
  if (config.rdnss.count != 0U) {
    const auto option_length = 8U + 16U * config.rdnss.count;
    if (!reserve(option_length))
      return std::nullopt;
    body[used] = 25U;
    body[used + 1U] = static_cast<std::uint8_t>(1U + 2U * config.rdnss.count);
    // SR OS configures one RDNSS lifetime per advertised server set. The
    // scalar survives candidate leaf ordering even when the server list is
    // empty. Per-server lifetime fields remain populated for received options
    // and must agree when a locally configured set is encoded.
    const auto lifetime = config.rdnss_lifetime_seconds;
    put32(body, used + 4U, lifetime);
    for (std::size_t index = 0; index < config.rdnss.count; ++index) {
      const auto &server = config.rdnss.servers[index];
      if (ip::is_unspecified(server.address) ||
          ip::is_multicast(server.address))
        return std::nullopt;
      std::copy(server.address.begin(), server.address.end(),
                body.begin() + static_cast<std::ptrdiff_t>(used + 8U +
                                                            16U * index));
    }
    used += option_length;
  }

  Frame result;
  const auto destination_mac = ip::is_multicast(destination)
                                   ? ipv6_multicast_mac(destination)
                                   : Mac{};
  // A unicast RA requires a caller-supplied neighbor MAC, which this narrow
  // API intentionally does not guess. The runtime currently uses multicast
  // advertisements and can add a resolved-MAC overload with the solicited path.
  if (!ip::is_multicast(destination))
    return std::nullopt;
  icmpv6_message_into(result, source_mac, destination_mac, source, destination,
                      router_advertisement_type, 0U,
                      std::span<const std::uint8_t>{body.data(), used},
                      required_hop_limit);
  if (!result.length)
    return std::nullopt;
  return result;
}

std::optional<NeighborSolicitationView>
parse_neighbor_solicitation(const Frame &frame) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  const auto icmp = parse_icmpv6(frame);
  // RFC 6980 requires every traditional ND message carrying a Fragment Header,
  // including an atomic fragment, to be silently ignored.
  if (!ipv6 || ipv6->fragment || !icmp ||
      ipv6->hop_limit != required_hop_limit ||
      icmp->type != neighbor_solicitation_type ||
      icmp->code != 0U || icmp->data.size() < 16U)
    return std::nullopt;
  NeighborSolicitationView result{.source = ipv6->source,
                                  .destination = ipv6->destination};
  std::copy_n(icmp->data.begin(), result.target.size(), result.target.begin());
  if (ip::is_multicast(result.target))
    return std::nullopt;
  const auto option =
      link_layer_option(icmp->data.subspan(16U), 1U);
  if (!option.valid)
    return std::nullopt;
  result.source_link_layer = option.address;
  result.duplicate_address_detection = ip::is_unspecified(result.source);
  // DAD must not carry a Source Link-Layer Address option and must target the
  // solicited-node multicast address for the tentative target.
  if (result.duplicate_address_detection &&
      (result.source_link_layer ||
       result.destination != ip::solicited_node_multicast(result.target)))
    return std::nullopt;
  if (!result.duplicate_address_detection &&
      ip::is_multicast(result.destination) && !result.source_link_layer)
    return std::nullopt;
  return result;
}

std::optional<NeighborAdvertisementView>
parse_neighbor_advertisement(const Frame &frame) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  const auto icmp = parse_icmpv6(frame);
  if (!ipv6 || ipv6->fragment || !icmp ||
      ipv6->hop_limit != required_hop_limit ||
      icmp->type != neighbor_advertisement_type ||
      icmp->code != 0U || icmp->data.size() < 16U ||
      ip::is_unspecified(ipv6->source))
    return std::nullopt;
  const auto flags_offset =
      static_cast<std::size_t>(ipv6->upper_layer_offset) + 4U;
  NeighborAdvertisementView result{
      .source = ipv6->source,
      .destination = ipv6->destination,
      .router = (frame[flags_offset] & 0x80U) != 0,
      .solicited = (frame[flags_offset] & 0x40U) != 0,
      .override_flag = (frame[flags_offset] & 0x20U) != 0};
  std::copy_n(icmp->data.begin(), result.target.size(), result.target.begin());
  if (ip::is_multicast(result.target) ||
      (ip::is_multicast(result.destination) && result.solicited))
    return std::nullopt;
  const auto option =
      link_layer_option(icmp->data.subspan(16U), 2U);
  if (!option.valid)
    return std::nullopt;
  result.target_link_layer = option.address;
  return result;
}

std::optional<RedirectView> parse_redirect(const Frame &frame) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  const auto icmp = parse_icmpv6(frame);
  if (!ipv6 || ipv6->fragment || !icmp ||
      ipv6->hop_limit != required_hop_limit ||
      icmp->type != redirect_type || icmp->code != 0U ||
      !ip::is_link_local(ipv6->source) ||
      ip::is_unspecified(ipv6->destination) ||
      ip::is_multicast(ipv6->destination) || icmp->data.size() < 32U)
    return std::nullopt;

  RedirectView result{.source = ipv6->source,
                      .receiver = ipv6->destination};
  std::copy_n(icmp->data.begin(), result.target.size(),
              result.target.begin());
  std::copy_n(icmp->data.begin() + 16, result.destination.size(),
              result.destination.begin());
  if (ip::is_multicast(result.destination) ||
      ip::is_unspecified(result.destination) ||
      !(ip::is_link_local(result.target) ||
        result.target == result.destination))
    return std::nullopt;

  auto options = icmp->data.subspan(32U);
  std::size_t offset{};
  while (offset < options.size()) {
    if (offset + 2U > options.size() || options[offset + 1U] == 0U)
      return std::nullopt;
    const auto length = static_cast<std::size_t>(options[offset + 1U]) * 8U;
    if (offset + length > options.size())
      return std::nullopt;
    if (options[offset] == 2U) {
      if (length != 8U || result.target_link_layer)
        return std::nullopt;
      Mac address{};
      std::copy_n(options.begin() +
                      static_cast<std::ptrdiff_t>(offset + 2U),
                  address.size(), address.begin());
      result.target_link_layer = address;
    } else if (options[offset] == 4U) {
      // The option has six reserved octets after its type and length. A second
      // instance is ambiguous and cannot improve Destination Cache input.
      if (length < 8U || result.redirected_header_present)
        return std::nullopt;
      result.redirected_header_present = true;
    }
    offset += length;
  }
  return result;
}

std::optional<RouterSolicitationView>
parse_router_solicitation(const Frame &frame) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  const auto icmp = parse_icmpv6(frame);
  if (!ipv6 || ipv6->fragment || !icmp ||
      ipv6->hop_limit != required_hop_limit ||
      icmp->type != router_solicitation_type || icmp->code != 0U ||
      ipv6->destination != all_routers_multicast ||
      ip::is_multicast(ipv6->source))
    return std::nullopt;

  // parse_icmpv6 exposes bytes after the four-octet reserved field as data.
  // Running the common option walker validates every option length, including
  // unknown options, before any sender identity reaches the neighbor owner.
  const auto option = link_layer_option(icmp->data, 1U);
  if (!option.valid || (ip::is_unspecified(ipv6->source) && option.address))
    return std::nullopt;
  return RouterSolicitationView{.source = ipv6->source,
                                .destination = ipv6->destination,
                                .source_link_layer = option.address};
}

std::optional<RouterAdvertisementView>
parse_router_advertisement(const Frame &frame) noexcept {
  const auto ipv6 = parse_ipv6(frame);
  const auto icmp = parse_icmpv6(frame);
  if (!ipv6 || ipv6->fragment || !icmp ||
      ipv6->hop_limit != required_hop_limit ||
      icmp->type != router_advertisement_type || icmp->code != 0U ||
      !ip::is_link_local(ipv6->source) || icmp->data.size() < 8U ||
      (ip::is_multicast(ipv6->destination) &&
       ipv6->destination != all_nodes_multicast))
    return std::nullopt;

  // The first four body octets are represented by parameter in the generic
  // ICMPv6 view. The next eight data octets carry the two timer values.
  const auto flags = static_cast<std::uint8_t>(icmp->parameter >> 16U);
  RouterAdvertisementView result{
      .source = ipv6->source,
      .destination = ipv6->destination,
      .reachable_time_milliseconds = get32(icmp->data, 0U),
      .retrans_timer_milliseconds = get32(icmp->data, 4U),
      .router_lifetime_seconds =
          static_cast<std::uint16_t>(icmp->parameter),
      .current_hop_limit =
          static_cast<std::uint8_t>(icmp->parameter >> 24U),
      .preference = parse_preference(flags),
      .managed_configuration = (flags & 0x80U) != 0U,
      .other_configuration = (flags & 0x40U) != 0U};

  auto options = icmp->data.subspan(8U);
  std::size_t offset{};
  while (offset < options.size()) {
    if (offset + 2U > options.size() || options[offset + 1U] == 0U)
      return std::nullopt;
    const auto length = static_cast<std::size_t>(options[offset + 1U]) * 8U;
    if (offset + length > options.size())
      return std::nullopt;
    const auto option = options.subspan(offset, length);
    switch (option[0]) {
    case 1U: {
      // Ethernet SLLA is one eight-octet unit. A second instance is ambiguous,
      // so reject it instead of allowing option order to choose router identity.
      if (length != 8U || result.source_link_layer)
        return std::nullopt;
      Mac address{};
      std::copy_n(option.begin() + 2, address.size(), address.begin());
      result.source_link_layer = address;
      break;
    }
    case 3U: {
      if (length != 32U)
        break;
      PrefixInformation prefix{
          .prefix = {.length = option[2]},
          .valid_lifetime_seconds = get32(option, 4U),
          .preferred_lifetime_seconds = get32(option, 8U),
          .on_link = (option[3] & 0x80U) != 0U,
          .autonomous = (option[3] & 0x40U) != 0U};
      std::copy_n(option.begin() + 16, prefix.prefix.network.size(),
                  prefix.prefix.network.begin());
      // RFC 4861 receivers ignore, rather than invalidate the RA for, an
      // unusable Prefix Information option. Preserve that per-option behavior.
      if (prefix.prefix.length > ip::ipv6_address_bits ||
          prefix.preferred_lifetime_seconds > prefix.valid_lifetime_seconds ||
          ip::is_link_local(prefix.prefix.network))
        break;
      prefix.prefix.network =
          ip::mask(prefix.prefix.network, prefix.prefix.length);
      if (result.prefix_count >= result.prefixes.size())
        return std::nullopt;
      result.prefixes[result.prefix_count++] = prefix;
      break;
    }
    case 5U: {
      if (length != 8U)
        break;
      const auto mtu = get32(option, 4U);
      // An MTU below IPv6's minimum is ignored by a receiver. Keeping the RA
      // valid matches RFC 4861 option processing and avoids an all-or-nothing
      // behavior not present on real nodes.
      if (mtu >= ipv6_minimum_link_mtu)
        result.advertised_mtu = mtu;
      break;
    }
    case 25U: {
      // RFC 8106 uses an odd length of at least three units: one fixed unit
      // followed by one or more sixteen-octet IPv6 server addresses.
      if (length < 24U || (option[1] & 1U) == 0U)
        break;
      const auto lifetime = get32(option, 4U);
      const auto count = (length - 8U) / 16U;
      if (result.rdnss.count + count > result.rdnss.servers.size())
        return std::nullopt;
      for (std::size_t index = 0; index < count; ++index) {
        RdnssServer server{.lifetime_seconds = lifetime};
        std::copy_n(option.begin() + static_cast<std::ptrdiff_t>(8U +
                                                                 16U * index),
                    server.address.size(), server.address.begin());
        if (!ip::is_unspecified(server.address) &&
            !ip::is_multicast(server.address))
          result.rdnss.servers[result.rdnss.count++] = server;
      }
      break;
    }
    default:
      // Unknown options are skipped using their validated length. This is the
      // forward-compatible behavior required by the ND option format.
      break;
    }
    offset += length;
  }
  return result;
}

} // namespace router::packet::nd
