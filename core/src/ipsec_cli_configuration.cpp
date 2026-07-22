// Source-backed implementation of the /configure/ipsec transform and policy
// editors. Numeric ranges come from the SR OS 26.7.R1 IPsec command reference;
// suite availability is narrower and follows the generated implemented profile.

#include "ipsec_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <iterator>
#include <optional>
#include <utility>
#include <vector>

namespace router::lab::ipsec_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;
using ipsec::configuration::AesGcmKeySize;
using ipsec::configuration::Configuration;
using ipsec::configuration::IkePolicy;
using ipsec::configuration::IkeTransform;
using ipsec::configuration::IpsecTransform;

std::optional<unsigned> number(const cli_detail::ParsedCommand &command,
                               TokenKind kind) noexcept {
  const auto text = cli_detail::argument(command, kind);
  if (!text)
    return std::nullopt;
  unsigned value{};
  const auto parsed = std::from_chars(text->data(), text->data() + text->size(),
                                      value);
  return parsed.ec == std::errc{} && parsed.ptr == text->data() + text->size()
             ? std::optional<unsigned>{value}
             : std::nullopt;
}

std::vector<std::uint16_t>
numbers(const cli_detail::ParsedCommand &command, TokenKind kind) {
  std::vector<std::uint16_t> result;
  // Repeated leaf-list values retain their position in the matched generated
  // schema row. `argument()` intentionally returns only the first occurrence,
  // so classic compound commands collect every typed position explicitly.
  // The largest applicable SR OS list contains four values and allocation is
  // confined to this cold control-plane edit.
  result.reserve(4U);
  for (std::size_t index = 0U; index < command.token_count; ++index) {
    if (command.spec->tokens[index].kind != kind)
      continue;
    unsigned value{};
    const auto text = command.tokens[index];
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                        value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value > 65'535U)
      return {};
    result.push_back(static_cast<std::uint16_t>(value));
  }
  return result;
}

std::vector<std::string_view>
arguments(const cli_detail::ParsedCommand &command, TokenKind kind) {
  std::vector<std::string_view> result;
  result.reserve(2U);
  for (std::size_t index = 0U; index < command.token_count; ++index)
    if (command.spec->tokens[index].kind == kind)
      result.push_back(command.tokens[index]);
  return result;
}

std::optional<std::pair<ipsec::configuration::SelectorProtocol, std::uint8_t>>
selector_protocol(std::string_view value) noexcept {
  using ipsec::configuration::SelectorProtocol;
  if (value == "icmp")
    return {{SelectorProtocol::icmp, std::uint8_t{0}}};
  if (value == "tcp")
    return {{SelectorProtocol::tcp, std::uint8_t{0}}};
  if (value == "udp")
    return {{SelectorProtocol::udp, std::uint8_t{0}}};
  if (value == "icmp6")
    return {{SelectorProtocol::icmpv6, std::uint8_t{0}}};
  if (value == "sctp")
    return {{SelectorProtocol::sctp, std::uint8_t{0}}};
  if (value == "mipv6")
    return {{SelectorProtocol::ipv6_mobility, std::uint8_t{0}}};
  unsigned numeric{};
  const auto parsed =
      std::from_chars(value.data(), value.data() + value.size(), numeric);
  if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
      !numeric || numeric > 255U)
    return std::nullopt;
  const auto wire = static_cast<std::uint8_t>(numeric);
  switch (wire) {
  case 1U:
    return {{SelectorProtocol::icmp, wire}};
  case 6U:
    return {{SelectorProtocol::tcp, wire}};
  case 17U:
    return {{SelectorProtocol::udp, wire}};
  case 58U:
    return {{SelectorProtocol::icmpv6, wire}};
  case 132U:
    return {{SelectorProtocol::sctp, wire}};
  case 135U:
    return {{SelectorProtocol::ipv6_mobility, wire}};
  default:
    return {{SelectorProtocol::numeric, wire}};
  }
}

std::optional<std::uint16_t>
selector_bound(ipsec::configuration::SelectorProtocol protocol,
               std::string_view value) noexcept {
  const auto slash = value.find('/');
  if (protocol == ipsec::configuration::SelectorProtocol::icmp ||
      protocol == ipsec::configuration::SelectorProtocol::icmpv6) {
    if (slash == std::string_view::npos)
      return std::nullopt;
    unsigned type{};
    unsigned code{};
    const auto parsed_type =
        std::from_chars(value.data(), value.data() + slash, type);
    const auto parsed_code = std::from_chars(
        value.data() + slash + 1U, value.data() + value.size(), code);
    if (parsed_type.ec != std::errc{} || parsed_code.ec != std::errc{} ||
        parsed_type.ptr != value.data() + slash ||
        parsed_code.ptr != value.data() + value.size() || type > 255U ||
        code > 255U)
      return std::nullopt;
    // RFC 7296 maps the ICMP type and code into the 16-bit port selector in
    // network order. Keeping the packed canonical form lets the IKE encoder
    // consume the same value as ordinary port ranges without guessing later.
    return static_cast<std::uint16_t>((type << 8U) | code);
  }
  if (slash != std::string_view::npos)
    return std::nullopt;
  unsigned result{};
  const auto parsed =
      std::from_chars(value.data(), value.data() + value.size(), result);
  const auto maximum =
      protocol == ipsec::configuration::SelectorProtocol::ipv6_mobility
          ? 255U
          : 65'535U;
  return parsed.ec == std::errc{} &&
                 parsed.ptr == value.data() + value.size() && result <= maximum
             ? std::optional<std::uint16_t>{
                   static_cast<std::uint16_t>(result)}
             : std::nullopt;
}

bool has_literal(const cli_detail::ParsedCommand &command,
                 std::string_view literal) noexcept {
  for (std::size_t index = 0U; index < command.token_count; ++index)
    if (command.spec->tokens[index].kind == TokenKind::literal &&
        command.spec->tokens[index].display == literal)
      return true;
  return false;
}

std::optional<std::pair<ipsec::configuration::SelectorProtocol, std::uint8_t>>
command_selector_protocol(const cli_detail::ParsedCommand &command) noexcept {
  if (const auto value =
          cli_detail::argument(command, TokenKind::ipsec_protocol_id))
    return selector_protocol(*value);
  if (const auto value = cli_detail::argument(command, TokenKind::protocol_id))
    return selector_protocol(*value);
  // MD named alternatives are literals so they remain visible in completion.
  // Inspecting the generated token kind, rather than arbitrary user text,
  // prevents a traffic-selector list named `tcp` from selecting a protocol.
  constexpr std::array names{"icmp", "tcp", "udp", "icmp6", "sctp",
                             "mipv6"};
  for (const auto name : names)
    if (has_literal(command, name))
      return selector_protocol(name);
  return std::nullopt;
}

template <typename Entry>
Entry *materialize(std::vector<Entry> &entries, std::uint16_t id,
                   std::size_t maximum) {
  const auto found = std::find_if(entries.begin(), entries.end(),
                                  [id](const auto &item) { return item.id == id; });
  if (found != entries.end())
    return &*found;
  // The release limit is an instance count as well as an ID range. Checking
  // both prevents a sparse set of legal IDs from exceeding platform capacity.
  if (!id || id > maximum || entries.size() >= maximum)
    return nullptr;
  // Value-initialize every field before assigning the list key. This preserves
  // each entry type's documented defaults without relying on a partial
  // aggregate initializer whose omissions can change silently as fields grow.
  Entry entry{};
  const auto key = static_cast<decltype(entry.id)>(id);
  if (key != id)
    return nullptr;
  entry.id = key;
  entries.push_back(std::move(entry));
  return &entries.back();
}

template <typename Entry>
bool erase(std::vector<Entry> &entries, std::uint16_t id) {
  const auto found = std::find_if(entries.begin(), entries.end(),
                                  [id](const auto &item) { return item.id == id; });
  if (found == entries.end())
    return false;
  entries.erase(found);
  return true;
}

template <typename Value>
bool configure(Value &target, bool &presence, Value value) {
  // Explicitly configuring an effective default is observable intent. Only a
  // second identical assignment is a no-op and is rejected by the caller.
  if (presence && target == value)
    return false;
  target = value;
  presence = true;
  return true;
}

template <typename Value>
bool remove(Value &target, bool &presence, Value default_value) {
  if (!presence)
    return false;
  target = default_value;
  presence = false;
  return true;
}

bool configure_flag(bool &presence) noexcept {
  // Presence-only leaves have no value storage separate from their configured
  // bit. A dedicated operation avoids relying on aliasing through the generic
  // value helper and keeps identical repeated assignments observable as no-op.
  if (presence)
    return false;
  presence = true;
  return true;
}

bool remove_flag(bool &presence) noexcept {
  if (!presence)
    return false;
  presence = false;
  return true;
}

bool assign_description(std::string &target, std::string_view value) {
  // SR OS accepts 1 to 80 characters and rejects an all-space description.
  // The generated parser already preserves a quoted argument as one token;
  // validation remains here because this editor is the datastore boundary.
  if (value.empty() || value.size() > 80U ||
      std::all_of(value.begin(), value.end(), [](char character) {
        return character == ' ';
      }) ||
      target == value)
    return false;
  target.assign(value);
  return true;
}

std::optional<std::vector<std::uint8_t>>
clear_secret_bytes(std::string_view value, bool hexadecimal) {
  // Protected SR OS hash/hash2/hash3 spellings are deliberately not decoded
  // as if they were clear key material. Those formats are vendor protection
  // envelopes, not password hashes that can participate directly in IKE.
  // Accepting one without a compatible importer would create a configuration
  // that appears valid but can never authenticate a peer.
  if (value.empty() || value.find(' ') != std::string_view::npos)
    return std::nullopt;
  if (!hexadecimal) {
    if (value.size() > 64U)
      return std::nullopt;
    return std::vector<std::uint8_t>{value.begin(), value.end()};
  }

  if (value.starts_with("0x"))
    value.remove_prefix(2U);
  if (value.empty() || value.size() > 128U || value.size() % 2U)
    return std::nullopt;
  const auto nibble = [](char byte) -> std::optional<std::uint8_t> {
    if (byte >= '0' && byte <= '9')
      return static_cast<std::uint8_t>(byte - '0');
    if (byte >= 'a' && byte <= 'f')
      return static_cast<std::uint8_t>(byte - 'a' + 10);
    if (byte >= 'A' && byte <= 'F')
      return static_cast<std::uint8_t>(byte - 'A' + 10);
    return std::nullopt;
  };
  std::vector<std::uint8_t> bytes;
  bytes.reserve(value.size() / 2U);
  for (std::size_t index = 0U; index < value.size(); index += 2U) {
    const auto high = nibble(value[index]);
    const auto low = nibble(value[index + 1U]);
    if (!high || !low) {
      std::fill(bytes.begin(), bytes.end(), std::uint8_t{});
      return std::nullopt;
    }
    bytes.push_back(static_cast<std::uint8_t>((*high << 4U) | *low));
  }
  return bytes;
}

std::optional<std::uint64_t>
seal_secret(SecretSink *sink, SecretKind kind, std::string_view value,
            bool hexadecimal = false) {
  if (!sink)
    return std::nullopt;
  auto bytes = clear_secret_bytes(value, hexadecimal);
  if (!bytes)
    return std::nullopt;
  const auto handle = sink->seal(kind, *bytes);
  // The editor owns this temporary copy and cleanses its capacity before the
  // vector releases memory. SecretSink must already have encrypted or copied
  // the bytes because the span becomes invalid on return.
  std::fill(bytes->begin(), bytes->end(), std::uint8_t{});
  return handle && *handle ? handle : std::nullopt;
}

void clear_fragmentation(IkePolicy &policy) noexcept {
  policy.fragmentation_configured = false;
  policy.fragmentation_mtu = 1'500U;
  policy.fragmentation_reassembly_timeout_seconds = 2U;
  policy.fragmentation_mtu_configured = false;
  policy.fragmentation_reassembly_timeout_configured = false;
}

void clear_dpd(IkePolicy &policy) noexcept {
  policy.dpd_configured = false;
  policy.dpd_interval_seconds = 30U;
  policy.dpd_max_retries = 3U;
  policy.dpd_reply_only = false;
  policy.dpd_interval_configured = false;
  policy.dpd_max_retries_configured = false;
  policy.dpd_reply_only_configured = false;
}

void clear_nat_traversal(IkePolicy &policy) noexcept {
  policy.nat_traversal_configured = false;
  policy.nat_force = false;
  policy.nat_force_keepalive = true;
  policy.nat_keepalive_interval_seconds = 0U;
  policy.nat_force_configured = false;
  policy.nat_force_keepalive_configured = false;
  policy.nat_keepalive_interval_configured = false;
}

AesGcmKeySize encryption(CommandId id) noexcept {
  using enum CommandId;
  switch (id) {
  case md_ipsec_transform_aes192_gcm16:
  case classic_ipsec_transform_aes192_gcm16:
    return AesGcmKeySize::aes192;
  case md_ike_transform_aes256_gcm16:
  case md_ipsec_transform_aes256_gcm16:
  case classic_ike_transform_aes256_gcm16:
  case classic_ipsec_transform_aes256_gcm16:
    return AesGcmKeySize::aes256;
  default:
    return AesGcmKeySize::aes128;
  }
}

bool referenced(const Configuration &state, std::uint16_t transform) {
  return std::any_of(state.ike_policies.begin(), state.ike_policies.end(),
                     [transform](const auto &policy) {
                       return std::find(policy.ike_transforms.begin(),
                                        policy.ike_transforms.end(), transform) !=
                              policy.ike_transforms.end();
                     });
}

bool ipsec_referenced(const Configuration &state, std::uint16_t transform) {
  const auto contains = [transform](const auto &references) {
    return std::find(references.begin(), references.end(), transform) !=
           references.end();
  };
  return std::any_of(state.transport_mode_profiles.begin(),
                     state.transport_mode_profiles.end(),
                     [&](const auto &profile) {
                       return contains(profile.dynamic.ipsec_transforms);
                     }) ||
         std::any_of(state.tunnel_templates.begin(),
                     state.tunnel_templates.end(), [&](const auto &item) {
                       return contains(item.ipsec_transforms);
                     });
}

bool classic_transport_transform_command(CommandId id) noexcept {
  using enum CommandId;
  return id == classic_transport_ipsec_transform ||
         id == classic_transport_ipsec_transform_2 ||
         id == classic_transport_ipsec_transform_3 ||
         id == classic_transport_ipsec_transform_4;
}

bool classic_tunnel_transform_command(CommandId id) noexcept {
  using enum CommandId;
  return id == classic_tunnel_transform || id == classic_tunnel_transform_2 ||
         id == classic_tunnel_transform_3 || id == classic_tunnel_transform_4;
}

bool valid_ipsec_transform_list(const Configuration &state,
                                const std::vector<std::uint16_t> &references) {
  if (references.empty() || references.size() > 4U)
    return false;
  for (std::size_t index = 0U; index < references.size(); ++index)
    if (!ipsec::configuration::find_ipsec(state, references[index]) ||
        std::find(references.begin(), references.begin() + index,
                  references[index]) != references.begin() + index)
      return false;
  return true;
}

std::optional<ipsec::Address> address(std::string_view text) noexcept {
  ipsec::Address result;
  if (const auto ipv6 = ip::parse_ipv6(text)) {
    result.family = ipsec::AddressFamily::ipv6;
    result.bytes = *ipv6;
    return result;
  }
  result.family = ipsec::AddressFamily::ipv4;
  std::size_t begin{};
  for (std::size_t octet = 0; octet < 4U; ++octet) {
    const auto end = octet == 3U ? text.size() : text.find('.', begin);
    if (end == std::string_view::npos || begin == end)
      return std::nullopt;
    unsigned value{};
    const auto parsed =
        std::from_chars(text.data() + begin, text.data() + end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + end ||
        value > 255U)
      return std::nullopt;
    result.bytes[octet] = static_cast<std::uint8_t>(value);
    begin = end + 1U;
  }
  return result;
}

std::optional<ipsec::Prefix> prefix(std::string_view text) noexcept {
  const auto slash = text.find('/');
  if (slash == std::string_view::npos)
    return std::nullopt;
  const auto parsed_address = address(text.substr(0U, slash));
  unsigned length{};
  const auto length_result = std::from_chars(
      text.data() + slash + 1U, text.data() + text.size(), length);
  const auto maximum = parsed_address &&
                               parsed_address->family ==
                                   ipsec::AddressFamily::ipv6
                           ? 128U
                           : 32U;
  if (!parsed_address || length_result.ec != std::errc{} ||
      length_result.ptr != text.data() + text.size() || length > maximum)
    return std::nullopt;
  ipsec::Prefix result;
  result.network = *parsed_address;
  result.length = static_cast<std::uint8_t>(length);
  const auto whole = length / 8U;
  const auto remainder = length % 8U;
  if (remainder)
    result.network.bytes[whole] &=
        static_cast<std::uint8_t>(0xffU << (8U - remainder));
  const auto octets = result.network.family == ipsec::AddressFamily::ipv6
                          ? 16U
                          : 4U;
  for (std::size_t index = whole + (remainder ? 1U : 0U); index < octets;
       ++index)
    result.network.bytes[index] = 0U;
  return result;
}

template <typename Item>
Item *materialize_named(std::vector<Item> &items, std::string_view name,
                        std::size_t maximum) {
  if (auto *existing = ipsec::configuration::find_named(items, name))
    return existing;
  if (name.empty() || name.size() > 32U || items.size() >= maximum)
    return nullptr;
  Item item;
  item.name = name;
  items.push_back(std::move(item));
  return &items.back();
}

ipsec::configuration::TrafficSelectorEntry *materialize_selector(
    std::vector<ipsec::configuration::TrafficSelectorEntry> &entries,
    std::uint8_t id) {
  const auto found = std::find_if(entries.begin(), entries.end(),
                                  [id](const auto &item) {
                                    return item.id == id;
                                  });
  if (found != entries.end())
    return &*found;
  if (!id || id > profile::maximum_traffic_selectors_per_list ||
      entries.size() >= profile::maximum_traffic_selectors_per_list)
    return nullptr;
  entries.emplace_back();
  entries.back().id = id;
  return &entries.back();
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= md_ike_transform_dh19 && id <= md_delete_static_sa_key;
}

bool is_classic_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= classic_ike_transform_create &&
         id <= classic_static_sa_no_authentication;
}

bool is_show_command(CommandId id) noexcept {
  using enum CommandId;
  return id >= show_ipsec_static_sas &&
         id <= show_ipsec_tunnel_template_association_all;
}

EditResult edit(Configuration &state,
                const cli_detail::ParsedCommand &command, CliEngine engine,
                SecretSink *secrets) {
  const auto id = command.spec->id;
  const bool recognized = engine == CliEngine::md ? is_md_command(id)
                                                   : is_classic_command(id);
  if (!recognized)
    return {};

  const auto before = state;
  bool changed{};
  std::string instance{"/ipsec"};
  const auto ike_id = number(command, TokenKind::ike_transform_id);
  const auto ipsec_id = number(command, TokenKind::ipsec_transform_id);
  const auto policy_id = number(command, TokenKind::ike_policy_id);
  const auto certificate_name =
      cli_detail::argument(command, TokenKind::ipsec_cert_profile_name);
  const auto trust_anchor_name = cli_detail::argument(
      command, TokenKind::ipsec_trust_anchor_profile_name);
  const auto ppk_list_name =
      cli_detail::argument(command, TokenKind::ppk_list_name);
  const auto ts_name = cli_detail::argument(command, TokenKind::ts_list_name);
  const auto transport_name =
      cli_detail::argument(command, TokenKind::transport_profile_name);
  const auto tunnel_id = number(command, TokenKind::tunnel_template_id);
  const auto static_sa_name =
      cli_detail::argument(command, TokenKind::static_sa_name);
  const bool md = engine == CliEngine::md;
  using enum CommandId;

  if (static_sa_name) {
    instance += "/static-sa/" + std::string{*static_sa_name};
    auto found = std::find_if(state.static_sas.begin(), state.static_sas.end(),
                              [&](const auto &item) {
                                return item.name == *static_sa_name;
                              });
    const bool static_sa_existed = found != state.static_sas.end();
    if (id == md_delete_static_sa || id == classic_static_sa_remove) {
      if (found != state.static_sas.end()) {
        state.static_sas.erase(found);
        changed = true;
      }
    } else {
      auto *item = md ? materialize_named(state.static_sas, *static_sa_name,
                                           profile::maximum_static_sas)
                      : found == state.static_sas.end() ? nullptr : &*found;
      if (id == classic_static_sa_create) {
        if (!item)
          item = materialize_named(state.static_sas, *static_sa_name,
                                   profile::maximum_static_sas);
        changed = item && !static_sa_existed;
      } else if (item && (id == md_static_sa_description ||
                          id == classic_static_sa_description)) {
        const auto value =
            cli_detail::argument(command, TokenKind::description);
        changed = value &&
                  ipsec::configuration::valid_named_key(*value, 32U) &&
                  item->description != *value;
        if (changed)
          item->description = *value;
      } else if (item && (id == md_delete_static_sa_description ||
                          id == classic_static_sa_no_description)) {
        changed = !item->description.empty();
        if (changed)
          item->description.clear();
      } else if (item && (id == md_static_sa_direction_inbound ||
                          id == md_static_sa_direction_outbound ||
                          id == md_static_sa_direction_bidirectional ||
                          id == classic_static_sa_direction_inbound ||
                          id == classic_static_sa_direction_outbound ||
                          id == classic_static_sa_direction_bidirectional)) {
        const auto direction =
            (id == md_static_sa_direction_inbound ||
             id == classic_static_sa_direction_inbound)
                ? ipsec::configuration::StaticSaDirection::inbound
            : (id == md_static_sa_direction_outbound ||
               id == classic_static_sa_direction_outbound)
                ? ipsec::configuration::StaticSaDirection::outbound
                : ipsec::configuration::StaticSaDirection::bidirectional;
        changed = !item->direction_configured || item->direction != direction;
        item->direction = direction;
        item->direction_configured = true;
      } else if (item && (id == md_delete_static_sa_direction ||
                          id == classic_static_sa_no_direction)) {
        changed = item->direction_configured;
        item->direction =
            ipsec::configuration::StaticSaDirection::bidirectional;
        item->direction_configured = false;
      } else if (item && (id == md_static_sa_protocol_ah ||
                          id == md_static_sa_protocol_esp ||
                          id == classic_static_sa_protocol_ah ||
                          id == classic_static_sa_protocol_esp)) {
        const auto protocol =
            (id == md_static_sa_protocol_ah ||
             id == classic_static_sa_protocol_ah)
                ? ipsec::SecurityProtocol::ah
                : ipsec::SecurityProtocol::esp;
        changed = !item->protocol_configured || item->protocol != protocol;
        item->protocol = protocol;
        item->protocol_configured = true;
      } else if (item && (id == md_delete_static_sa_protocol ||
                          id == classic_static_sa_no_protocol)) {
        changed = item->protocol_configured;
        item->protocol = ipsec::SecurityProtocol::esp;
        item->protocol_configured = false;
      } else if (item &&
                 (id == md_static_sa_spi || id == classic_static_sa_spi)) {
        const auto value = number(command, TokenKind::static_sa_spi);
        changed = value && *value >= 256U && *value <= 16'383U &&
                  (!item->spi_configured || item->spi != *value);
        if (changed) {
          item->spi = *value;
          item->spi_configured = true;
        }
      } else if (item && (id == md_delete_static_sa_spi ||
                          id == classic_static_sa_no_spi)) {
        changed = item->spi_configured;
        item->spi = 0U;
        item->spi_configured = false;
      } else if (item && (id == md_static_sa_auth_md5 ||
                          id == md_static_sa_auth_sha1)) {
        const auto algorithm = id == md_static_sa_auth_sha1
                                   ? ipsec::configuration::StaticSaAuthentication::sha1
                                   : ipsec::configuration::StaticSaAuthentication::md5;
        changed = !item->authentication_container_configured ||
                  !item->authentication_configured ||
                  item->authentication != algorithm;
        item->authentication_container_configured = true;
        item->authentication_configured = true;
        item->authentication = algorithm;
      } else if (item && (id == md_delete_static_sa_authentication ||
                          id == classic_static_sa_no_authentication)) {
        changed = item->authentication_container_configured;
        item->authentication_container_configured = false;
        item->authentication_configured = false;
        item->authentication =
            ipsec::configuration::StaticSaAuthentication::sha1;
        item->authentication_key_handle = 0U;
        item->authentication_key_format =
            ipsec::configuration::StaticSaKeyFormat::encrypted_leaf;
      } else if (item && id == md_delete_static_sa_algorithm) {
        changed = item->authentication_configured;
        item->authentication_configured = false;
        item->authentication =
            ipsec::configuration::StaticSaAuthentication::sha1;
      } else if (item && id == md_delete_static_sa_key) {
        changed = item->authentication_key_handle != 0U;
        item->authentication_key_handle = 0U;
        item->authentication_key_format =
            ipsec::configuration::StaticSaKeyFormat::encrypted_leaf;
      } else if (item) {
        const auto key =
            cli_detail::argument(command, TokenKind::static_sa_key);
        const bool classic_authentication =
            id >= classic_static_sa_auth_md5_ascii &&
            id <= classic_static_sa_auth_sha1_hex_custom;
        const bool sha1 = id == classic_static_sa_auth_sha1_ascii ||
                          id == classic_static_sa_auth_sha1_hex ||
                          (id >= classic_static_sa_auth_sha1_ascii_hash &&
                           id <= classic_static_sa_auth_sha1_hex_custom);
        const bool hexadecimal =
            id == classic_static_sa_auth_md5_hex ||
            id == classic_static_sa_auth_sha1_hex ||
            (id >= classic_static_sa_auth_md5_hex_hash &&
             id <= classic_static_sa_auth_md5_hex_custom) ||
            (id >= classic_static_sa_auth_sha1_hex_hash &&
             id <= classic_static_sa_auth_sha1_hex_custom);
        const bool protected_input =
            id == md_static_sa_key_hash || id == md_static_sa_key_hash2 ||
            id == md_static_sa_key_hash3 || id == md_static_sa_key_custom ||
            (classic_authentication &&
             (has_literal(command, "hash") || has_literal(command, "hash2") ||
              has_literal(command, "hash3") || has_literal(command, "custom")));
        const auto plain_length = sha1 ? (hexadecimal ? 40U : 20U)
                                       : (hexadecimal ? 32U : 16U);
        const bool valid_plain =
            key && key->size() == plain_length &&
            (!hexadecimal ||
             std::all_of(key->begin(), key->end(), [](unsigned char value) {
               return (value >= '0' && value <= '9') ||
                      (value >= 'a' && value <= 'f') ||
                      (value >= 'A' && value <= 'F');
             }));
        const bool valid_key = key && !key->empty() && key->size() <= 110U &&
                               (protected_input || !classic_authentication ||
                                valid_plain);
        if (valid_key && secrets) {
          const auto handle = secrets->seal(
              SecretKind::static_authentication_key,
              {reinterpret_cast<const std::uint8_t *>(key->data()),
               key->size()});
          if (handle && item->authentication_key_handle != *handle) {
            item->authentication_key_handle = *handle;
            item->authentication_container_configured = true;
            item->authentication_key_format =
                protected_input || !classic_authentication
                    ? ipsec::configuration::StaticSaKeyFormat::encrypted_leaf
                : hexadecimal
                    ? ipsec::configuration::StaticSaKeyFormat::hexadecimal
                    : ipsec::configuration::StaticSaKeyFormat::ascii;
            if (classic_authentication) {
              item->authentication =
                  sha1 ? ipsec::configuration::StaticSaAuthentication::sha1
                       : ipsec::configuration::StaticSaAuthentication::md5;
              item->authentication_configured = true;
            }
            changed = true;
          }
        }
      }
    }
  } else if (ppk_list_name && !transport_name && !tunnel_id) {
    instance += "/ppk-list/" + std::string{*ppk_list_name};
    const auto ppk_id = cli_detail::argument(command, TokenKind::ppk_id);
    const bool list_referenced =
        std::any_of(state.transport_mode_profiles.begin(),
                    state.transport_mode_profiles.end(), [&](const auto &item) {
                      return item.dynamic.ppk_list == *ppk_list_name;
                    }) ||
        std::any_of(state.tunnel_templates.begin(), state.tunnel_templates.end(),
                    [&](const auto &item) {
                      return item.ppk_list == *ppk_list_name;
                    });
    if (id == md_delete_ipsec_ppk_list ||
        id == classic_ipsec_ppk_list_remove) {
      const auto found = std::find_if(
          state.ppk_lists.begin(), state.ppk_lists.end(), [&](const auto &list) {
            return list.name == *ppk_list_name;
          });
      if (!list_referenced && found != state.ppk_lists.end()) {
        state.ppk_lists.erase(found);
        changed = true;
      }
    } else {
      auto *list = md ? materialize_named(
                            state.ppk_lists, *ppk_list_name,
                            ipsec::configuration::maximum_ppk_lists)
                      : ipsec::configuration::find_named(state.ppk_lists,
                                                         *ppk_list_name);
      if (id == classic_ipsec_ppk_list_create) {
        if (!list)
          list = materialize_named(state.ppk_lists, *ppk_list_name,
                                   ipsec::configuration::maximum_ppk_lists);
        changed = list && !ipsec::configuration::find_named(
                              before.ppk_lists, *ppk_list_name);
      } else if (list && ppk_id) {
        instance += "/ppk/" + std::string{*ppk_id};
        const bool entry_referenced = std::any_of(
            state.transport_mode_profiles.begin(),
            state.transport_mode_profiles.end(), [&](const auto &item) {
              return item.dynamic.ppk_list == *ppk_list_name &&
                     item.dynamic.ppk_id == *ppk_id;
            });
        auto found = std::find_if(
            list->entries.begin(), list->entries.end(),
            [&](const auto &entry) { return entry.id == *ppk_id; });
        if (id == md_delete_ipsec_ppk || id == classic_ipsec_ppk_remove) {
          if (!entry_referenced && found != list->entries.end()) {
            list->entries.erase(found);
            changed = true;
          }
        } else {
          const bool sets_value = id == md_ipsec_ppk_ascii ||
                                  id == classic_ipsec_ppk_ascii ||
                                  id == md_ipsec_ppk_hex ||
                                  id == classic_ipsec_ppk_hex;
          if (found == list->entries.end() && sets_value &&
              list->entries.size() <
                  ipsec::configuration::maximum_ppks_per_list &&
              ipsec::configuration::valid_named_key(*ppk_id, 64U)) {
            list->entries.push_back({.id = std::string{*ppk_id}});
            found = std::prev(list->entries.end());
          }
          if (found != list->entries.end()) {
            if (id == md_delete_ipsec_ppk_value) {
              changed = found->secret_handle != 0U;
              found->secret_handle = 0U;
            } else if (id == md_ipsec_ppk_ascii ||
                       id == classic_ipsec_ppk_ascii ||
                       id == md_ipsec_ppk_hex ||
                       id == classic_ipsec_ppk_hex) {
              const bool hexadecimal = id == md_ipsec_ppk_hex ||
                                       id == classic_ipsec_ppk_hex;
              const auto kind =
                  hexadecimal ? SecretKind::ppk_hexadecimal
                              : SecretKind::ppk_ascii;
              const auto value = cli_detail::argument(
                  command, hexadecimal ? TokenKind::ppk_hex_value
                                       : TokenKind::ppk_ascii_value);
              const auto handle =
                  value ? seal_secret(secrets, kind, *value, hexadecimal)
                        : std::nullopt;
              if (handle) {
                changed = found->secret_handle != *handle ||
                          found->format !=
                              (hexadecimal
                                   ? ipsec::configuration::PpkValueFormat::
                                         hexadecimal
                                   : ipsec::configuration::PpkValueFormat::
                                         ascii);
                found->secret_handle = *handle;
                found->format = hexadecimal
                                    ? ipsec::configuration::PpkValueFormat::
                                          hexadecimal
                                    : ipsec::configuration::PpkValueFormat::
                                          ascii;
              }
            }
          }
        }
      }
    }
  } else if (certificate_name && !transport_name) {
    instance += "/cert-profile/" + std::string{*certificate_name};
    const bool referenced_by_transport = std::any_of(
        state.transport_mode_profiles.begin(),
        state.transport_mode_profiles.end(), [&](const auto &profile) {
          return profile.dynamic.certificate_profile == *certificate_name;
        });
    if (id == md_delete_ipsec_cert_profile ||
        id == classic_ipsec_cert_profile_remove) {
      const auto found = std::find_if(
          state.certificate_profiles.begin(),
          state.certificate_profiles.end(), [&](const auto &profile) {
            return profile.name == *certificate_name;
          });
      if (!referenced_by_transport && found != state.certificate_profiles.end()) {
        state.certificate_profiles.erase(found);
        changed = true;
      }
    } else {
      auto *profile = md
                          ? materialize_named(
                                state.certificate_profiles, *certificate_name,
                                ipsec::configuration::
                                    maximum_certificate_profiles)
                          : ipsec::configuration::find_named(
                                state.certificate_profiles, *certificate_name);
      if (id == classic_ipsec_cert_profile_create) {
        if (!profile)
          profile = materialize_named(
              state.certificate_profiles, *certificate_name,
              ipsec::configuration::maximum_certificate_profiles);
        changed = profile && !ipsec::configuration::find_named(
                                  before.certificate_profiles,
                                  *certificate_name);
      } else if (profile && (id == classic_ipsec_cert_shutdown ||
                             id == classic_ipsec_cert_no_shutdown)) {
        // Classic profiles are administratively shut down by default. Both
        // commands retain explicit intent, matching MD admin-state presence.
        changed = configure(profile->enabled,
                            profile->admin_state_configured,
                            id == classic_ipsec_cert_no_shutdown);
      } else
      if (profile && (id == md_ipsec_cert_admin_enable ||
                      id == md_ipsec_cert_admin_disable)) {
        changed = configure(profile->enabled, profile->admin_state_configured,
                            id == md_ipsec_cert_admin_enable);
      } else if (profile && id == md_delete_ipsec_cert_admin) {
        changed = remove(profile->enabled, profile->admin_state_configured,
                         false);
      } else if (profile) {
        const auto entry_id =
            number(command, TokenKind::ipsec_certificate_entry_id);
        if (entry_id && *entry_id >= 1U &&
            *entry_id <= ipsec::configuration::maximum_certificate_entries) {
          const auto numeric_id = static_cast<std::uint8_t>(*entry_id);
          if (id == md_delete_ipsec_cert_entry ||
              id == classic_ipsec_cert_entry_remove) {
            const auto found = std::find_if(
                profile->entries.begin(), profile->entries.end(),
                [numeric_id](const auto &entry) {
                  return entry.id == numeric_id;
                });
            if (found != profile->entries.end()) {
              profile->entries.erase(found);
              changed = true;
            }
          } else {
            auto *entry = md
                              ? materialize<ipsec::configuration::
                                                CertificateProfileEntry>(
                                    profile->entries, numeric_id,
                                    ipsec::configuration::
                                        maximum_certificate_entries)
                              : nullptr;
            if (!md) {
              const auto existing = std::find_if(
                  profile->entries.begin(), profile->entries.end(),
                  [numeric_id](const auto &candidate) {
                    return candidate.id == numeric_id;
                  });
              entry = existing == profile->entries.end() ? nullptr : &*existing;
            }
            if (id == classic_ipsec_cert_entry_create) {
              if (!entry)
                entry = materialize<ipsec::configuration::
                                        CertificateProfileEntry>(
                    profile->entries, numeric_id,
                    ipsec::configuration::maximum_certificate_entries);
              const auto *before_profile = ipsec::configuration::find_named(
                  before.certificate_profiles, *certificate_name);
              changed = entry &&
                        (!before_profile ||
                         std::none_of(before_profile->entries.begin(),
                                      before_profile->entries.end(),
                                      [numeric_id](const auto &candidate) {
                                        return candidate.id == numeric_id;
                                      }));
            } else
            if (entry) {
              const auto filename =
                  cli_detail::argument(command, TokenKind::pki_file_name);
              const auto ca_profile =
                  cli_detail::argument(command, TokenKind::ca_profile_name);
              if ((id == md_ipsec_cert_entry_cert ||
                   id == classic_ipsec_cert_entry_cert) &&
                  filename &&
                  ipsec::configuration::valid_pki_filename(*filename) &&
                  entry->certificate_file != *filename) {
                entry->certificate_file = *filename;
                changed = true;
              } else if ((id == md_ipsec_cert_entry_key ||
                          id == classic_ipsec_cert_entry_key) &&
                         filename &&
                         ipsec::configuration::valid_pki_filename(*filename) &&
                         entry->private_key_file != *filename) {
                entry->private_key_file = *filename;
                changed = true;
              } else if ((id == md_ipsec_cert_entry_compare_chain ||
                          id == classic_ipsec_cert_entry_compare) &&
                         ca_profile && entry->compare_chain_include !=
                                           *ca_profile) {
                entry->compare_chain_include = *ca_profile;
                changed = true;
              } else if (id == md_ipsec_cert_entry_rsa_pkcs1 ||
                         id == md_ipsec_cert_entry_rsa_pss ||
                         id == classic_ipsec_cert_entry_rsa_pkcs1 ||
                         id == classic_ipsec_cert_entry_rsa_pss) {
                changed = configure(
                    entry->rsa_signature, entry->rsa_signature_configured,
                    id == md_ipsec_cert_entry_rsa_pss ||
                            id == classic_ipsec_cert_entry_rsa_pss
                        ? ipsec::configuration::RsaSignature::pss
                        : ipsec::configuration::RsaSignature::pkcs1);
              } else if ((id == md_ipsec_cert_entry_send_chain ||
                          id == classic_ipsec_cert_entry_send_ca) &&
                         ca_profile &&
                         entry->send_chain_ca_profiles.size() <
                             ipsec::configuration::
                                 maximum_send_chain_profiles &&
                         std::find(entry->send_chain_ca_profiles.begin(),
                                   entry->send_chain_ca_profiles.end(),
                                   *ca_profile) ==
                             entry->send_chain_ca_profiles.end()) {
                entry->send_chain_ca_profiles.emplace_back(*ca_profile);
                changed = true;
              } else if (id == md_delete_ipsec_cert_entry_cert ||
                         id == classic_ipsec_cert_entry_no_cert) {
                changed = !entry->certificate_file.empty();
                entry->certificate_file.clear();
              } else if (id == md_delete_ipsec_cert_entry_key ||
                         id == classic_ipsec_cert_entry_no_key) {
                changed = !entry->private_key_file.empty();
                entry->private_key_file.clear();
              } else if (id == md_delete_ipsec_cert_entry_compare_chain ||
                         id == classic_ipsec_cert_entry_no_compare) {
                changed = !entry->compare_chain_include.empty();
                entry->compare_chain_include.clear();
              } else if (id == md_delete_ipsec_cert_entry_rsa) {
                changed = remove(entry->rsa_signature,
                                 entry->rsa_signature_configured,
                                 ipsec::configuration::RsaSignature::pkcs1);
              } else if ((id == md_delete_ipsec_cert_entry_send_chain ||
                          id == classic_ipsec_cert_entry_no_send_ca) &&
                         ca_profile) {
                const auto found =
                    std::find(entry->send_chain_ca_profiles.begin(),
                              entry->send_chain_ca_profiles.end(), *ca_profile);
                if (found != entry->send_chain_ca_profiles.end()) {
                  entry->send_chain_ca_profiles.erase(found);
                  changed = true;
                }
              }
            }
          }
        }
      }
    }
  } else if (trust_anchor_name && !transport_name) {
    instance += "/trust-anchor-profile/" + std::string{*trust_anchor_name};
    const bool referenced_by_transport = std::any_of(
        state.transport_mode_profiles.begin(),
        state.transport_mode_profiles.end(), [&](const auto &profile) {
          return profile.dynamic.trust_anchor_profile == *trust_anchor_name;
        });
    if (id == md_delete_ipsec_trust_anchor_profile ||
        id == classic_ipsec_trust_profile_remove) {
      const auto found = std::find_if(
          state.trust_anchor_profiles.begin(),
          state.trust_anchor_profiles.end(), [&](const auto &profile) {
            return profile.name == *trust_anchor_name;
          });
      if (!referenced_by_transport &&
          found != state.trust_anchor_profiles.end()) {
        state.trust_anchor_profiles.erase(found);
        changed = true;
      }
    } else {
      auto *profile = md
                          ? materialize_named(
                                state.trust_anchor_profiles,
                                *trust_anchor_name,
                                ipsec::configuration::
                                    maximum_trust_anchor_profiles)
                          : ipsec::configuration::find_named(
                                state.trust_anchor_profiles,
                                *trust_anchor_name);
      if (id == classic_ipsec_trust_profile_create) {
        if (!profile)
          profile = materialize_named(
              state.trust_anchor_profiles, *trust_anchor_name,
              ipsec::configuration::maximum_trust_anchor_profiles);
        changed = profile && !ipsec::configuration::find_named(
                                  before.trust_anchor_profiles,
                                  *trust_anchor_name);
      }
      const auto ca_profile =
          cli_detail::argument(command, TokenKind::ca_profile_name);
      if (profile && ca_profile &&
          (id == md_ipsec_trust_anchor ||
           id == classic_ipsec_trust_anchor) &&
          profile->ca_profiles.size() <
              ipsec::configuration::maximum_trust_anchors &&
          std::find(profile->ca_profiles.begin(), profile->ca_profiles.end(),
                    *ca_profile) == profile->ca_profiles.end()) {
        profile->ca_profiles.emplace_back(*ca_profile);
        changed = true;
      } else if (profile && ca_profile &&
                 (id == md_delete_ipsec_trust_anchor ||
                  id == classic_ipsec_no_trust_anchor)) {
        const auto found = std::find(profile->ca_profiles.begin(),
                                     profile->ca_profiles.end(), *ca_profile);
        if (found != profile->ca_profiles.end()) {
          profile->ca_profiles.erase(found);
          changed = true;
        }
      }
    }
  } else if (ike_id && !transport_name) {
    instance += "/ike-transform/" + std::to_string(*ike_id);
    if (id == md_delete_ike_transform || id == classic_ike_transform_remove) {
      // A leafref in an IKE policy makes deletion invalid. Silently leaving a
      // dangling policy would defer an avoidable failure until negotiation.
      changed = !referenced(state, static_cast<std::uint16_t>(*ike_id)) &&
                erase(state.ike_transforms,
                      static_cast<std::uint16_t>(*ike_id));
    } else if (id == classic_ike_transform_create) {
      changed = !ipsec::configuration::find_ike(
                    state, static_cast<std::uint16_t>(*ike_id)) &&
                materialize<IkeTransform>(state.ike_transforms,
                                          static_cast<std::uint16_t>(*ike_id),
                                          profile::maximum_ike_transforms);
    } else {
      auto *item = md ? materialize<IkeTransform>(
                            state.ike_transforms,
                            static_cast<std::uint16_t>(*ike_id),
                            profile::maximum_ike_transforms)
                      : ipsec::configuration::find_ike(
                            state, static_cast<std::uint16_t>(*ike_id));
      if (item) {
        if (id == md_ike_transform_dh19 || id == classic_ike_transform_dh19)
          changed = configure(item->dh_group, item->dh_group_configured,
                              ipsec::configuration::DiffieHellmanGroup::ecp256);
        else if (id == md_ike_transform_auth_encryption ||
                 id == classic_ike_transform_auth_encryption)
          changed = configure_flag(item->authentication_encryption_configured);
        else if (id == md_ike_transform_aes128_gcm16 ||
                 id == md_ike_transform_aes256_gcm16 ||
                 id == classic_ike_transform_aes128_gcm16 ||
                 id == classic_ike_transform_aes256_gcm16)
          changed = configure(item->encryption, item->encryption_configured,
                              encryption(id));
        else if (id == md_ike_transform_prf_sha256 ||
                 id == classic_ike_transform_prf_sha256)
          changed = configure_flag(item->prf_sha256_configured);
        else if (id == md_ike_transform_lifetime ||
                 id == classic_ike_transform_lifetime) {
          const auto value = number(command, TokenKind::ike_lifetime);
          changed = value && *value >= 1'200U && *value <= 31'536'000U &&
                    configure(item->lifetime_seconds, item->lifetime_configured,
                              static_cast<std::uint32_t>(*value));
        } else if (id == md_delete_ike_transform_dh ||
                   id == classic_ike_transform_no_dh)
          changed = remove(item->dh_group, item->dh_group_configured,
                           ipsec::configuration::DiffieHellmanGroup::ecp256);
        else if (id == md_delete_ike_transform_auth ||
                 id == classic_ike_transform_no_auth)
          changed = remove_flag(item->authentication_encryption_configured);
        else if (id == md_delete_ike_transform_encryption ||
                 id == classic_ike_transform_no_encryption)
          changed = remove(item->encryption, item->encryption_configured,
                           AesGcmKeySize::aes128);
        else if (id == md_delete_ike_transform_prf ||
                 id == classic_ike_transform_no_prf)
          changed = remove_flag(item->prf_sha256_configured);
        else if (id == md_delete_ike_transform_lifetime ||
                 id == classic_ike_transform_no_lifetime)
          changed = remove(item->lifetime_seconds, item->lifetime_configured,
                           86'400U);
      }
    }
  } else if (ipsec_id && !transport_name && !tunnel_id) {
    instance += "/ipsec-transform/" + std::to_string(*ipsec_id);
    if (id == md_delete_ipsec_transform ||
        id == classic_ipsec_transform_remove) {
      changed = !ipsec_referenced(state, static_cast<std::uint16_t>(*ipsec_id)) &&
                erase(state.ipsec_transforms,
                      static_cast<std::uint16_t>(*ipsec_id));
    } else if (id == classic_ipsec_transform_create) {
      changed = !ipsec::configuration::find_ipsec(
                    state, static_cast<std::uint16_t>(*ipsec_id)) &&
                materialize<IpsecTransform>(
                    state.ipsec_transforms,
                    static_cast<std::uint16_t>(*ipsec_id),
                    profile::maximum_ipsec_transforms);
    } else {
      auto *item = md ? materialize<IpsecTransform>(
                            state.ipsec_transforms,
                            static_cast<std::uint16_t>(*ipsec_id),
                            profile::maximum_ipsec_transforms)
                      : ipsec::configuration::find_ipsec(
                            state, static_cast<std::uint16_t>(*ipsec_id));
      if (item) {
        if (id == md_ipsec_transform_auth_encryption ||
            id == classic_ipsec_transform_auth_encryption)
          changed = configure_flag(item->authentication_encryption_configured);
        else if (id == md_ipsec_transform_aes128_gcm16 ||
                 id == md_ipsec_transform_aes192_gcm16 ||
                 id == md_ipsec_transform_aes256_gcm16 ||
                 id == classic_ipsec_transform_aes128_gcm16 ||
                 id == classic_ipsec_transform_aes192_gcm16 ||
                 id == classic_ipsec_transform_aes256_gcm16)
          changed = configure(item->encryption, item->encryption_configured,
                              encryption(id));
        else if (id == md_ipsec_transform_esn_true ||
                 id == md_ipsec_transform_esn_false ||
                 id == classic_ipsec_transform_esn_true ||
                 id == classic_ipsec_transform_esn_false)
          changed = configure(item->extended_sequence_number,
                              item->extended_sequence_number_configured,
                              id == md_ipsec_transform_esn_true ||
                                  id == classic_ipsec_transform_esn_true);
        else if (id == md_ipsec_transform_lifetime ||
                 id == classic_ipsec_transform_lifetime) {
          const auto value = number(command, TokenKind::ipsec_lifetime);
          changed = value && *value >= 1'200U && *value <= 31'536'000U &&
                    configure(item->lifetime_seconds, item->lifetime_configured,
                              static_cast<std::uint32_t>(*value));
        } else if (id == md_ipsec_transform_pfs19 ||
                   id == classic_ipsec_transform_pfs19) {
          changed = !item->pfs_group_configured || !item->pfs_enabled;
          item->pfs_group = ipsec::configuration::DiffieHellmanGroup::ecp256;
          item->pfs_enabled = true;
          item->pfs_group_configured = true;
        } else if (id == md_ipsec_transform_pfs_none ||
                   id == classic_ipsec_transform_pfs_none) {
          changed = !item->pfs_group_configured || item->pfs_enabled;
          item->pfs_enabled = false;
          item->pfs_group_configured = true;
        } else if (id == md_delete_ipsec_transform_auth ||
                   id == classic_ipsec_transform_no_auth)
          changed = remove_flag(item->authentication_encryption_configured);
        else if (id == md_delete_ipsec_transform_encryption ||
                 id == classic_ipsec_transform_no_encryption)
          changed = remove(item->encryption, item->encryption_configured,
                           AesGcmKeySize::aes128);
        else if (id == md_delete_ipsec_transform_esn ||
                 id == classic_ipsec_transform_no_esn)
          changed = remove(item->extended_sequence_number,
                           item->extended_sequence_number_configured, true);
        else if (id == md_delete_ipsec_transform_lifetime ||
                 id == classic_ipsec_transform_no_lifetime)
          changed = remove(item->lifetime_seconds, item->lifetime_configured,
                           0U);
        else if (id == md_delete_ipsec_transform_pfs ||
                 id == classic_ipsec_transform_no_pfs) {
          changed = item->pfs_group_configured;
          item->pfs_group = ipsec::configuration::DiffieHellmanGroup::ecp256;
          item->pfs_enabled = false;
          item->pfs_group_configured = false;
        }
      }
    }
  } else if (policy_id && !transport_name) {
    instance += "/ike-policy/" + std::to_string(*policy_id);
    if (id == md_delete_ike_policy || id == classic_ike_policy_remove) {
      changed = erase(state.ike_policies,
                      static_cast<std::uint16_t>(*policy_id));
    } else if (id == classic_ike_policy_create) {
      changed = !ipsec::configuration::find_policy(
                    state, static_cast<std::uint16_t>(*policy_id)) &&
                materialize<IkePolicy>(state.ike_policies,
                                       static_cast<std::uint16_t>(*policy_id),
                                       profile::maximum_ike_policies);
    } else {
      auto *item = md ? materialize<IkePolicy>(
                            state.ike_policies,
                            static_cast<std::uint16_t>(*policy_id),
                            profile::maximum_ike_policies)
                      : ipsec::configuration::find_policy(
                            state, static_cast<std::uint16_t>(*policy_id));
      if (item && id == md_ike_policy_transform) {
        const auto reference = number(command, TokenKind::ike_transform_ref);
        changed = reference &&
                  ipsec::configuration::find_ike(
                      state, static_cast<std::uint16_t>(*reference)) &&
                  item->ike_transforms.size() < 4U &&
                  std::find(item->ike_transforms.begin(),
                            item->ike_transforms.end(), *reference) ==
                      item->ike_transforms.end();
        if (changed)
          item->ike_transforms.push_back(static_cast<std::uint16_t>(*reference));
      } else if (item && id == md_delete_ike_policy_transform) {
        const auto reference = number(command, TokenKind::ike_transform_ref);
        if (reference) {
          const auto found = std::find(item->ike_transforms.begin(),
                                       item->ike_transforms.end(), *reference);
          if (found != item->ike_transforms.end()) {
            item->ike_transforms.erase(found);
            changed = true;
          }
        }
      } else if (item &&
                 (id == classic_ike_policy_transform ||
                  id == classic_ike_policy_transform_2 ||
                  id == classic_ike_policy_transform_3 ||
                  id == classic_ike_policy_transform_4)) {
        const auto references = numbers(command, TokenKind::ike_transform_ref);
        bool unique = true;
        for (std::size_t left = 0U; left < references.size(); ++left)
          for (std::size_t right = left + 1U; right < references.size(); ++right)
            if (references[left] == references[right])
              unique = false;
        const bool resolved = !references.empty() && unique &&
            std::all_of(references.begin(), references.end(), [&](auto reference) {
              return ipsec::configuration::find_ike(state, reference) != nullptr;
            });
        if (resolved && item->ike_transforms != references) {
          // Classic `ike-transform` is one compound replacement command. It
          // does not append to the prior list, even when only one ID is given.
          item->ike_transforms = references;
          changed = true;
        }
      } else if (item && id == classic_ike_policy_no_transform) {
        changed = !item->ike_transforms.empty();
        item->ike_transforms.clear();
      } else if (item && (id == md_ike_policy_description ||
                          id == classic_ike_policy_description)) {
        const auto value = cli_detail::argument(command, TokenKind::description);
        changed = value && assign_description(item->description, *value);
      } else if (item && (id == md_delete_ike_policy_description ||
                          id == classic_ike_policy_no_description)) {
        changed = !item->description.empty();
        item->description.clear();
      } else if (item && (id == md_ike_policy_auth_psk ||
                          id == classic_ike_policy_auth_psk))
        changed = configure(item->peer_authentication,
                            item->peer_authentication_configured,
                            ipsec::configuration::AuthenticationMethod::psk);
      else if (item && (id == md_ike_policy_own_symmetric ||
                        id == classic_ike_policy_own_symmetric))
        changed = configure(item->own_authentication,
                            item->own_authentication_configured,
                            ipsec::configuration::AuthenticationMethod::symmetric);
      else if (item && id == classic_ike_policy_version2) {
        // IKEv2 is the only version represented by this standards module. The
        // explicit classic command still has a real intent effect: it ensures
        // a newly created policy cannot be mistaken for an IKEv1 policy.
        changed = !item->ike_version2_configured;
        item->ike_version2_configured = true;
      } else if (item && id == md_ike_policy_fragment_mtu) {
        const auto value = number(command, TokenKind::ike_fragment_mtu);
        if (value && *value >= 512U && *value <= 9'000U) {
          const bool created = !item->fragmentation_configured;
          item->fragmentation_configured = true;
          const bool leaf_changed = configure(
              item->fragmentation_mtu, item->fragmentation_mtu_configured,
              static_cast<std::uint16_t>(*value));
          changed = created || leaf_changed;
        }
      } else if (item && id == md_ike_policy_fragment_timeout) {
        const auto value = number(command, TokenKind::ike_reassembly_timeout);
        if (value && *value >= 1U && *value <= 5U) {
          const bool created = !item->fragmentation_configured;
          item->fragmentation_configured = true;
          const bool leaf_changed = configure(
              item->fragmentation_reassembly_timeout_seconds,
              item->fragmentation_reassembly_timeout_configured,
              static_cast<std::uint8_t>(*value));
          changed = created || leaf_changed;
        }
      } else if (item && id == classic_ike_policy_fragment) {
        const auto mtu = number(command, TokenKind::ike_fragment_mtu);
        const auto timeout = number(command, TokenKind::ike_reassembly_timeout);
        if (mtu && timeout && *mtu >= 512U && *mtu <= 9'000U &&
            *timeout >= 1U && *timeout <= 5U) {
          const auto previous_item = *item;
          item->fragmentation_configured = true;
          item->fragmentation_mtu = static_cast<std::uint16_t>(*mtu);
          item->fragmentation_reassembly_timeout_seconds =
              static_cast<std::uint8_t>(*timeout);
          item->fragmentation_mtu_configured = true;
          item->fragmentation_reassembly_timeout_configured = true;
          changed = *item != previous_item;
        }
      } else if (item && (id == md_delete_ike_policy_fragment ||
                          id == classic_ike_policy_no_fragment)) {
        changed = item->fragmentation_configured;
        clear_fragmentation(*item);
      } else if (item && id == md_ike_policy_dpd_interval) {
        const auto value = number(command, TokenKind::dpd_interval);
        if (value && *value >= 10U && *value <= 300U) {
          const bool created = !item->dpd_configured;
          item->dpd_configured = true;
          const bool leaf_changed = configure(
              item->dpd_interval_seconds, item->dpd_interval_configured,
              static_cast<std::uint16_t>(*value));
          changed = created || leaf_changed;
        }
      } else if (item && id == md_ike_policy_dpd_retries) {
        const auto value = number(command, TokenKind::dpd_retries);
        if (value && *value >= 2U && *value <= 5U) {
          const bool created = !item->dpd_configured;
          item->dpd_configured = true;
          const bool leaf_changed = configure(
              item->dpd_max_retries, item->dpd_max_retries_configured,
              static_cast<std::uint8_t>(*value));
          changed = created || leaf_changed;
        }
      } else if (item && id == md_ike_policy_dpd_reply_only) {
        const auto value = cli_detail::argument(command, TokenKind::boolean);
        if (value) {
          const bool created = !item->dpd_configured;
          item->dpd_configured = true;
          const bool leaf_changed = configure(
              item->dpd_reply_only, item->dpd_reply_only_configured,
              *value == "true");
          changed = created || leaf_changed;
        }
      } else if (item && id >= classic_ike_policy_dpd &&
                 id <= classic_ike_policy_dpd_all) {
        const auto interval = number(command, TokenKind::dpd_interval);
        const auto retries = number(command, TokenKind::dpd_retries);
        if ((!interval || (*interval >= 10U && *interval <= 300U)) &&
            (!retries || (*retries >= 2U && *retries <= 5U))) {
          const auto previous_item = *item;
          item->dpd_configured = true;
          item->dpd_interval_seconds = static_cast<std::uint16_t>(
              interval.value_or(30U));
          item->dpd_max_retries =
              static_cast<std::uint8_t>(retries.value_or(3U));
          item->dpd_reply_only =
              id == classic_ike_policy_dpd_reply_only ||
              id == classic_ike_policy_dpd_interval_reply_only ||
              id == classic_ike_policy_dpd_retries_reply_only ||
              id == classic_ike_policy_dpd_all;
          item->dpd_interval_configured = interval.has_value();
          item->dpd_max_retries_configured = retries.has_value();
          item->dpd_reply_only_configured = item->dpd_reply_only;
          changed = *item != previous_item;
        }
      } else if (item && (id == md_delete_ike_policy_dpd ||
                          id == classic_ike_policy_no_dpd)) {
        changed = item->dpd_configured;
        clear_dpd(*item);
      } else if (item && id == md_ike_policy_nat_force) {
        const auto value = cli_detail::argument(command, TokenKind::boolean);
        if (value) {
          const bool created = !item->nat_traversal_configured;
          item->nat_traversal_configured = true;
          const bool leaf_changed = configure(
              item->nat_force, item->nat_force_configured, *value == "true");
          changed = created || leaf_changed;
        }
      } else if (item && id == md_ike_policy_nat_keepalive_force) {
        const auto value = cli_detail::argument(command, TokenKind::boolean);
        if (value) {
          const bool created = !item->nat_traversal_configured;
          item->nat_traversal_configured = true;
          const bool leaf_changed = configure(
              item->nat_force_keepalive,
              item->nat_force_keepalive_configured, *value == "true");
          changed = created || leaf_changed;
        }
      } else if (item && id == md_ike_policy_nat_keepalive_interval) {
        const auto value = number(command, TokenKind::nat_keepalive_interval);
        if (value && *value >= 120U && *value <= 600U) {
          const bool created = !item->nat_traversal_configured;
          item->nat_traversal_configured = true;
          const bool leaf_changed = configure(
              item->nat_keepalive_interval_seconds,
              item->nat_keepalive_interval_configured,
              static_cast<std::uint16_t>(*value));
          changed = created || leaf_changed;
        }
      } else if (item && id >= classic_ike_policy_nat &&
                 id <= classic_ike_policy_nat_all) {
        const auto interval = number(command, TokenKind::nat_keepalive_interval);
        if (!interval || (*interval >= 120U && *interval <= 600U)) {
          const auto previous_item = *item;
          item->nat_traversal_configured = true;
          item->nat_force = id == classic_ike_policy_nat_force ||
                            id == classic_ike_policy_nat_force_interval ||
                            id == classic_ike_policy_nat_force_force_keepalive ||
                            id == classic_ike_policy_nat_all;
          item->nat_force_keepalive =
              id == classic_ike_policy_nat_force_keepalive ||
              id == classic_ike_policy_nat_force_force_keepalive ||
              id == classic_ike_policy_nat_interval_force_keepalive ||
              id == classic_ike_policy_nat_all;
          item->nat_keepalive_interval_seconds =
              static_cast<std::uint16_t>(interval.value_or(0U));
          item->nat_force_configured = item->nat_force;
          item->nat_force_keepalive_configured = item->nat_force_keepalive;
          item->nat_keepalive_interval_configured = interval.has_value();
          changed = *item != previous_item;
        }
      } else if (item && (id == md_delete_ike_policy_nat ||
                          id == classic_ike_policy_no_nat)) {
        changed = item->nat_traversal_configured;
        clear_nat_traversal(*item);
      } else if (item && id == md_ike_policy_lifetime) {
        const auto value = number(command, TokenKind::ipsec_lifetime);
        changed = value && *value >= 1'200U && *value <= 31'536'000U &&
                  configure(item->ipsec_lifetime_seconds,
                            item->ipsec_lifetime_configured,
                            static_cast<std::uint32_t>(*value));
      }
    }
  } else if (ts_name) {
    instance += "/ts-list/" + std::string{*ts_name};
    const bool remove_list = id == md_delete_ts_list ||
                             id == classic_ts_list_remove;
    if (remove_list) {
      const auto found = std::find_if(
          state.traffic_selector_lists.begin(),
          state.traffic_selector_lists.end(), [&](const auto &item) {
            return item.name == *ts_name;
          });
      if (found != state.traffic_selector_lists.end()) {
        state.traffic_selector_lists.erase(found);
        changed = true;
      }
    } else {
      auto *list = md ? materialize_named(
                            state.traffic_selector_lists, *ts_name,
                            profile::maximum_traffic_selector_lists)
                      : ipsec::configuration::find_traffic_selector_list(
                            state.traffic_selector_lists, *ts_name);
      if (id == classic_ts_list_create) {
        if (!list)
          list = materialize_named(state.traffic_selector_lists, *ts_name,
                                   profile::maximum_traffic_selector_lists);
        changed = list && !ipsec::configuration::find_traffic_selector_list(
                              before.traffic_selector_lists, *ts_name);
      } else if (list) {
        const auto entry_id = number(command, TokenKind::ts_entry_id);
        // The side is release grammar, not a property inferred from command
        // enum ordering. This remains correct as protocol alternatives grow
        // and cannot be confused by a list name whose text happens to be
        // `local`, because only generated literal token kinds are inspected.
        const bool local = has_literal(command, "local");
        auto &entries = local ? list->local : list->remote;
        if (entry_id && (id == md_delete_ts_local_entry ||
                         id == md_delete_ts_remote_entry ||
                         id == classic_ts_local_entry_remove ||
                         id == classic_ts_remote_entry_remove)) {
          const auto found = std::find_if(entries.begin(), entries.end(),
                                          [&](const auto &entry) {
                                            return entry.id == *entry_id;
                                          });
          if (found != entries.end()) {
            entries.erase(found);
            changed = true;
          }
        } else if (entry_id && *entry_id <= 32U) {
          auto *entry = materialize_selector(
              entries, static_cast<std::uint8_t>(*entry_id));
          if (entry && (id == classic_ts_local_entry_create ||
                        id == classic_ts_remote_entry_create)) {
            const auto &old_entries = local
                                          ? ipsec::configuration::find_traffic_selector_list(
                                                before.traffic_selector_lists,
                                                *ts_name)
                                                ->local
                                          : ipsec::configuration::find_traffic_selector_list(
                                                before.traffic_selector_lists,
                                                *ts_name)
                                                ->remote;
            changed = std::none_of(old_entries.begin(), old_entries.end(),
                                   [&](const auto &old) {
                                     return old.id == entry->id;
                                   });
          } else if (entry &&
                     (id == md_delete_ts_local_address ||
                      id == md_delete_ts_remote_address ||
                      id == classic_ts_local_no_address ||
                      id == classic_ts_remote_no_address)) {
            changed = entry->prefix.has_value() ||
                      entry->range_begin.has_value() ||
                      entry->range_end.has_value();
            entry->prefix.reset();
            entry->range_begin.reset();
            entry->range_end.reset();
          } else if (entry &&
                     cli_detail::argument(command, TokenKind::ip_prefix)) {
            const auto text =
                cli_detail::argument(command, TokenKind::ip_prefix);
            const auto value = text ? prefix(*text) : std::nullopt;
            if (value && entry->prefix != value) {
              entry->prefix = value;
              entry->range_begin.reset();
              entry->range_end.reset();
              changed = true;
            }
          } else if (entry && has_literal(command, "address") &&
                     !arguments(command, TokenKind::ip_address).empty()) {
            const auto values = arguments(command, TokenKind::ip_address);
            if (values.size() == 1U) {
              const auto value = address(values.front());
              if (value) {
                const auto before_entry = *entry;
                entry->prefix.reset();
                if (has_literal(command, "begin"))
                  entry->range_begin = *value;
                else
                  entry->range_end = *value;
                changed = *entry != before_entry;
              }
            } else if (values.size() == 2U) {
              const auto first = address(values.front());
              const auto last = address(values.back());
              if (first && last &&
                  ipsec::configuration::address_not_after(*first, *last)) {
                const auto before_entry = *entry;
                entry->prefix.reset();
                entry->range_begin = *first;
                entry->range_end = *last;
                changed = *entry != before_entry;
              }
            }
          } else if (entry &&
                     (id == md_delete_ts_local_protocol ||
                      id == md_delete_ts_remote_protocol ||
                      id == classic_ts_local_no_protocol ||
                      id == classic_ts_remote_no_protocol)) {
            changed = entry->protocol_configured;
            entry->protocol = ipsec::configuration::SelectorProtocol::any;
            entry->numeric_protocol = 0U;
            entry->ports = {};
            entry->opaque_ports = false;
            entry->protocol_configured = false;
            entry->selector_begin_configured = false;
            entry->selector_end_configured = false;
            entry->begin_icmp_type_configured = false;
            entry->begin_icmp_code_configured = false;
            entry->end_icmp_type_configured = false;
            entry->end_icmp_code_configured = false;
          } else if (entry && has_literal(command, "protocol") &&
                     has_literal(command, "any") &&
                     !has_literal(command, "port") &&
                     !has_literal(command, "protocol-id-with-any-port")) {
            const auto before_entry = *entry;
            entry->protocol = ipsec::configuration::SelectorProtocol::any;
            entry->numeric_protocol = 0U;
            entry->ports = {};
            entry->opaque_ports = false;
            entry->protocol_configured = true;
            entry->selector_begin_configured = false;
            entry->selector_end_configured = false;
            entry->begin_icmp_type_configured = false;
            entry->begin_icmp_code_configured = false;
            entry->end_icmp_type_configured = false;
            entry->end_icmp_code_configured = false;
            changed = *entry != before_entry;
          } else if (entry && has_literal(command, "protocol")) {
            const auto selected = command_selector_protocol(command);
            if (selected) {
              const auto [protocol, numeric_spelling] = *selected;
              const bool opaque = has_literal(command, "opaque");
              const bool any_port =
                  has_literal(command, "protocol-id-with-any-port") ||
                  id == classic_ts_local_protocol_any_port ||
                  id == classic_ts_remote_protocol_any_port;
              const bool supports_range =
                  protocol == ipsec::configuration::SelectorProtocol::tcp ||
                  protocol == ipsec::configuration::SelectorProtocol::udp ||
                  protocol == ipsec::configuration::SelectorProtocol::sctp ||
                  protocol == ipsec::configuration::SelectorProtocol::icmp ||
                  protocol == ipsec::configuration::SelectorProtocol::icmpv6 ||
                  protocol ==
                      ipsec::configuration::SelectorProtocol::ipv6_mobility;
              if (has_literal(command, "delete")) {
                const auto before_entry = *entry;
                // Deleting an MD leaf restores only that leaf's schema
                // default. Sibling candidate leaves remain intact, including
                // an otherwise incomplete ICMP tuple.
                if (has_literal(command, "begin")) {
                  entry->ports.first = 0U;
                  entry->selector_begin_configured = false;
                } else if (has_literal(command, "end")) {
                  entry->ports.last = 65'535U;
                  entry->selector_end_configured = false;
                } else if (has_literal(command, "begin-icmp-type")) {
                  entry->ports.first &= 0x00ffU;
                  entry->begin_icmp_type_configured = false;
                } else if (has_literal(command, "begin-icmp-code")) {
                  entry->ports.first &= 0xff00U;
                  entry->begin_icmp_code_configured = false;
                } else if (has_literal(command, "end-icmp-type")) {
                  entry->ports.last = static_cast<std::uint16_t>(
                      0xff00U | (entry->ports.last & 0x00ffU));
                  entry->end_icmp_type_configured = false;
                } else if (has_literal(command, "end-icmp-code")) {
                  entry->ports.last = static_cast<std::uint16_t>(
                      (entry->ports.last & 0xff00U) | 0x00ffU);
                  entry->end_icmp_code_configured = false;
                }
                changed = *entry != before_entry;
              } else {
              const auto classic_first = cli_detail::argument(
                  command, TokenKind::selector_port_begin);
              const auto classic_last = cli_detail::argument(
                  command, TokenKind::selector_port_end);
              const auto parsed_classic_first =
                  classic_first ? selector_bound(protocol, *classic_first)
                                : std::nullopt;
              const auto parsed_classic_last =
                  classic_last ? selector_bound(protocol, *classic_last)
                               : std::nullopt;
              const bool classic_range = parsed_classic_first &&
                                         parsed_classic_last &&
                                         *parsed_classic_first <=
                                             *parsed_classic_last;

              if (any_port || (opaque && supports_range) || classic_range ||
                  (!opaque && !any_port && supports_range && md)) {
                const auto before_entry = *entry;
                const bool protocol_changed =
                    entry->protocol != protocol ||
                    entry->numeric_protocol != numeric_spelling;
                if (protocol_changed) {
                  // A different protocol selects a different YANG choice.
                  // Removing every old child mirrors that replacement and
                  // prevents stale TCP bounds from becoming ICMP type bytes.
                  entry->ports = {};
                  entry->opaque_ports = false;
                  entry->selector_begin_configured = false;
                  entry->selector_end_configured = false;
                  entry->begin_icmp_type_configured = false;
                  entry->begin_icmp_code_configured = false;
                  entry->end_icmp_type_configured = false;
                  entry->end_icmp_code_configured = false;
                }
                entry->protocol = protocol;
                entry->numeric_protocol = numeric_spelling;
                entry->protocol_configured = true;

                if (any_port || opaque) {
                  entry->ports = {};
                  entry->opaque_ports = opaque;
                  entry->selector_begin_configured = false;
                  entry->selector_end_configured = false;
                  entry->begin_icmp_type_configured = false;
                  entry->begin_icmp_code_configured = false;
                  entry->end_icmp_type_configured = false;
                  entry->end_icmp_code_configured = false;
                } else if (classic_range) {
                // Classic CLI represents ICMP bounds as `type/code` inside the
                // same two port arguments used by TCP, UDP, SCTP and MIPv6.
                  entry->ports = {*parsed_classic_first,
                                  *parsed_classic_last};
                  entry->opaque_ports = false;
                  const bool icmp =
                      protocol ==
                          ipsec::configuration::SelectorProtocol::icmp ||
                      protocol ==
                          ipsec::configuration::SelectorProtocol::icmpv6;
                  entry->selector_begin_configured = !icmp;
                  entry->selector_end_configured = !icmp;
                  entry->begin_icmp_type_configured = icmp;
                  entry->begin_icmp_code_configured = icmp;
                  entry->end_icmp_type_configured = icmp;
                  entry->end_icmp_code_configured = icmp;
                } else if (protocol ==
                               ipsec::configuration::SelectorProtocol::icmp ||
                           protocol == ipsec::configuration::SelectorProtocol::
                                           icmpv6) {
                  // Each MD leaf updates one byte of the packed IKE selector.
                  // The untouched byte and its presence flag remain candidate
                  // state so editing order does not change the final result.
                  if (const auto value =
                          number(command, TokenKind::icmp_type_begin)) {
                    entry->ports.first = static_cast<std::uint16_t>(
                        (*value << 8U) | (entry->ports.first & 0x00ffU));
                    entry->begin_icmp_type_configured = true;
                  }
                  if (const auto value =
                          number(command, TokenKind::icmp_code_begin)) {
                    entry->ports.first = static_cast<std::uint16_t>(
                        (entry->ports.first & 0xff00U) | *value);
                    entry->begin_icmp_code_configured = true;
                  }
                  if (const auto value =
                          number(command, TokenKind::icmp_type_end)) {
                    entry->ports.last = static_cast<std::uint16_t>(
                        (*value << 8U) | (entry->ports.last & 0x00ffU));
                    entry->end_icmp_type_configured = true;
                  }
                  if (const auto value =
                          number(command, TokenKind::icmp_code_end)) {
                    entry->ports.last = static_cast<std::uint16_t>(
                        (entry->ports.last & 0xff00U) | *value);
                    entry->end_icmp_code_configured = true;
                  }
                } else {
                  const auto maximum =
                      protocol == ipsec::configuration::SelectorProtocol::
                                      ipv6_mobility
                          ? 255U
                          : 65'535U;
                  if (const auto value = number(command, TokenKind::port_begin);
                      value && *value <= maximum) {
                    entry->ports.first = static_cast<std::uint16_t>(*value);
                    entry->selector_begin_configured = true;
                  }
                  if (const auto value = number(command, TokenKind::port_end);
                      value && *value <= maximum) {
                    entry->ports.last = static_cast<std::uint16_t>(*value);
                    entry->selector_end_configured = true;
                  }
                }
                changed = *entry != before_entry;
              }
              }
            }
          }
        }
      }
    }
  } else if (transport_name) {
    instance += "/ipsec-transport-mode-profile/" +
                std::string{*transport_name};
    if (id == md_delete_transport_profile || id == classic_transport_remove) {
      const auto found = std::find_if(
          state.transport_mode_profiles.begin(),
          state.transport_mode_profiles.end(), [&](const auto &item) {
            return item.name == *transport_name;
          });
      if (found != state.transport_mode_profiles.end()) {
        state.transport_mode_profiles.erase(found);
        changed = true;
      }
    } else {
      auto *item = md ? materialize_named(
                            state.transport_mode_profiles, *transport_name,
                            state.transport_mode_profiles.max_size())
                      : ipsec::configuration::find_named(
                            state.transport_mode_profiles, *transport_name);
      if (id == classic_transport_create) {
        if (!item)
          item = materialize_named(state.transport_mode_profiles,
                                   *transport_name,
                                   state.transport_mode_profiles.max_size());
        changed = item && !ipsec::configuration::find_named(
                              before.transport_mode_profiles, *transport_name);
      } else if (item && (id == md_transport_description ||
                          id == classic_transport_description)) {
        const auto value =
            cli_detail::argument(command, TokenKind::description);
        changed = value && assign_description(item->description, *value);
      } else if (item && (id == md_delete_transport_description ||
                          id == classic_transport_no_description)) {
        changed = !item->description.empty();
        if (changed)
          item->description.clear();
      } else if (item && (id == md_transport_auto_establish ||
                          id == classic_transport_auto_establish)) {
        const auto value = id == classic_transport_auto_establish
                               ? std::optional<std::string_view>{"true"}
                               : cli_detail::argument(command,
                                                      TokenKind::boolean);
        changed = value && configure(item->dynamic.auto_establish,
                                     item->dynamic.auto_establish_configured,
                                     *value == "true");
      } else if (item && (id == md_delete_transport_auto_establish ||
                          id == classic_transport_no_auto_establish)) {
        changed = remove(item->dynamic.auto_establish,
                         item->dynamic.auto_establish_configured, false);
      } else if (item && (id == md_transport_cert_profile ||
                          id == classic_transport_cert_profile)) {
        const auto value = cli_detail::argument(
            command, TokenKind::ipsec_cert_profile_name);
        changed = value && ipsec::configuration::find_named(
                               state.certificate_profiles, *value) &&
                  item->dynamic.certificate_profile != *value;
        if (changed)
          item->dynamic.certificate_profile = *value;
      } else if (item && (id == md_delete_transport_cert_profile ||
                          id == classic_transport_no_cert_profile)) {
        changed = !item->dynamic.certificate_profile.empty();
        item->dynamic.certificate_profile.clear();
      } else if (item && (id == md_transport_cert_default_revoked ||
                          id == md_transport_cert_default_good ||
                          id == classic_transport_cert_default_revoked ||
                          id == classic_transport_cert_default_good)) {
        changed = configure(
            item->dynamic.default_revocation_result,
            item->dynamic.default_revocation_result_configured,
            id == md_transport_cert_default_good ||
                    id == classic_transport_cert_default_good
                ? ipsec::configuration::RevocationResult::good
                : ipsec::configuration::RevocationResult::revoked);
      } else if (item && (id == md_delete_transport_cert_default ||
                          id == classic_transport_cert_no_default)) {
        changed = remove(
            item->dynamic.default_revocation_result,
            item->dynamic.default_revocation_result_configured,
            ipsec::configuration::RevocationResult::revoked);
      } else if (item && (id == md_transport_cert_primary_crl ||
                          id == md_transport_cert_primary_ocsp)) {
        changed = configure(
            item->dynamic.primary_revocation_method,
            item->dynamic.primary_revocation_method_configured,
            id == md_transport_cert_primary_ocsp
                ? ipsec::configuration::RevocationMethod::ocsp
                : ipsec::configuration::RevocationMethod::crl);
      } else if (item && id == md_delete_transport_cert_primary) {
        changed = remove(item->dynamic.primary_revocation_method,
                         item->dynamic.primary_revocation_method_configured,
                         ipsec::configuration::RevocationMethod::crl);
      } else if (item && (id == md_transport_cert_secondary_none ||
                          id == md_transport_cert_secondary_crl ||
                          id == md_transport_cert_secondary_ocsp)) {
        const auto value =
            id == md_transport_cert_secondary_crl
                ? ipsec::configuration::RevocationMethod::crl
                : id == md_transport_cert_secondary_ocsp
                      ? ipsec::configuration::RevocationMethod::ocsp
                      : ipsec::configuration::RevocationMethod::none;
        changed = configure(item->dynamic.secondary_revocation_method,
                            item->dynamic.secondary_revocation_method_configured,
                            value);
      } else if (item && id == md_delete_transport_cert_secondary) {
        changed = remove(item->dynamic.secondary_revocation_method,
                         item->dynamic.secondary_revocation_method_configured,
                         ipsec::configuration::RevocationMethod::none);
      } else if (item &&
                 (id == classic_transport_cert_crl_none ||
                  id == classic_transport_cert_crl_crl ||
                  id == classic_transport_cert_crl_ocsp ||
                  id == classic_transport_cert_ocsp_none ||
                  id == classic_transport_cert_ocsp_crl ||
                  id == classic_transport_cert_ocsp_ocsp)) {
        // Classic configures the primary and secondary CSV methods in one
        // compound command. Update both values and both presence markers as a
        // single datastore edit so no observer can see a mixed method pair.
        const auto before_dynamic = item->dynamic;
        const bool primary_ocsp =
            id == classic_transport_cert_ocsp_none ||
            id == classic_transport_cert_ocsp_crl ||
            id == classic_transport_cert_ocsp_ocsp;
        item->dynamic.primary_revocation_method =
            primary_ocsp ? ipsec::configuration::RevocationMethod::ocsp
                         : ipsec::configuration::RevocationMethod::crl;
        item->dynamic.primary_revocation_method_configured = true;
        item->dynamic.secondary_revocation_method =
            id == classic_transport_cert_crl_crl ||
                    id == classic_transport_cert_ocsp_crl
                ? ipsec::configuration::RevocationMethod::crl
                : id == classic_transport_cert_crl_ocsp ||
                          id == classic_transport_cert_ocsp_ocsp
                      ? ipsec::configuration::RevocationMethod::ocsp
                      : ipsec::configuration::RevocationMethod::none;
        item->dynamic.secondary_revocation_method_configured = true;
        changed = item->dynamic != before_dynamic;
      } else if (item && (id == md_transport_trust_anchor_profile ||
                          id == classic_transport_trust_anchor_profile)) {
        const auto value = cli_detail::argument(
            command, TokenKind::ipsec_trust_anchor_profile_name);
        changed = value && ipsec::configuration::find_named(
                               state.trust_anchor_profiles, *value) &&
                  item->dynamic.trust_anchor_profile != *value;
        if (changed)
          item->dynamic.trust_anchor_profile = *value;
      } else if (item && (id == md_delete_transport_trust_anchor ||
                          id == classic_transport_no_trust_anchor_profile)) {
        changed = !item->dynamic.trust_anchor_profile.empty();
        item->dynamic.trust_anchor_profile.clear();
      } else if (item && (id == md_transport_id_fqdn ||
                          id == md_transport_id_ipv4 ||
                          id == md_transport_id_ipv6 ||
                          id == classic_transport_local_id_fqdn ||
                          id == classic_transport_local_id_ipv4 ||
                          id == classic_transport_local_id_ipv6)) {
        const bool fqdn = id == md_transport_id_fqdn ||
                          id == classic_transport_local_id_fqdn;
        const bool ipv4 = id == md_transport_id_ipv4 ||
                          id == classic_transport_local_id_ipv4;
        const auto kind = fqdn
                              ? TokenKind::ike_identity_fqdn
                              : ipv4 ? TokenKind::ipv4
                                     : TokenKind::ip_address;
        const auto value = cli_detail::argument(command, kind);
        if (value) {
          const auto before_dynamic = item->dynamic;
          item->dynamic.identity = *value;
          item->dynamic.identity_type =
              fqdn
                  ? ipsec::configuration::IdentityType::fqdn
                  : ipv4
                        ? ipsec::configuration::IdentityType::ipv4
                        : ipsec::configuration::IdentityType::ipv6;
          changed = item->dynamic != before_dynamic;
        }
      } else if (item && (id == md_delete_transport_identity ||
                          id == classic_transport_no_local_id)) {
        changed = !item->dynamic.identity.empty() ||
                  item->dynamic.identity_type !=
                      ipsec::configuration::IdentityType::automatic;
        item->dynamic.identity.clear();
        item->dynamic.identity_type =
            ipsec::configuration::IdentityType::automatic;
      } else if (item && (id == md_transport_ike_policy ||
                          id == classic_transport_ike_policy)) {
        changed = policy_id && ipsec::configuration::find_policy(
                                   state, static_cast<std::uint16_t>(*policy_id)) &&
                  item->dynamic.ike_policy != *policy_id;
        if (changed)
          item->dynamic.ike_policy = static_cast<std::uint16_t>(*policy_id);
      } else if (item && (id == md_delete_transport_ike_policy ||
                          id == classic_transport_no_ike_policy)) {
        changed = item->dynamic.ike_policy != 0U;
        item->dynamic.ike_policy = 0U;
      } else if (item && id == md_transport_ppk_list) {
        const auto name =
            cli_detail::argument(command, TokenKind::ppk_list_name);
        changed = name && ipsec::configuration::find_named(state.ppk_lists,
                                                            *name) &&
                  item->dynamic.ppk_list != *name;
        if (changed)
          item->dynamic.ppk_list.assign(*name);
      } else if (item && id == md_delete_transport_ppk_list) {
        changed = !item->dynamic.ppk_list.empty();
        if (changed) {
          item->dynamic.ppk_list.clear();
          item->dynamic.ppk_id.clear();
        }
      } else if (item && id == md_transport_ppk_id) {
        const auto value = cli_detail::argument(command, TokenKind::ppk_id);
        const auto *list = ipsec::configuration::find_named(
            state.ppk_lists, item->dynamic.ppk_list);
        changed = value && list &&
                  std::any_of(list->entries.begin(), list->entries.end(),
                              [&](const auto &entry) {
                                return entry.id == *value;
                              }) &&
                  item->dynamic.ppk_id != *value;
        if (changed)
          item->dynamic.ppk_id.assign(*value);
      } else if (item && id == md_delete_transport_ppk_id) {
        changed = !item->dynamic.ppk_id.empty();
        if (changed)
          item->dynamic.ppk_id.clear();
      } else if (item && id == classic_transport_ppk) {
        const auto list_name =
            cli_detail::argument(command, TokenKind::ppk_list_name);
        const auto entry_id = cli_detail::argument(command, TokenKind::ppk_id);
        const auto *list = list_name ? ipsec::configuration::find_named(
                                           state.ppk_lists, *list_name)
                                     : nullptr;
        const bool valid_entry =
            list && entry_id &&
            std::any_of(list->entries.begin(), list->entries.end(),
                        [&](const auto &entry) {
                          return entry.id == *entry_id;
                        });
        if (valid_entry &&
            (item->dynamic.ppk_list != *list_name ||
             item->dynamic.ppk_id != *entry_id)) {
          item->dynamic.ppk_list.assign(*list_name);
          item->dynamic.ppk_id.assign(*entry_id);
          changed = true;
        }
      } else if (item && id == classic_transport_no_ppk) {
        changed = !item->dynamic.ppk_list.empty() ||
                  !item->dynamic.ppk_id.empty();
        if (changed) {
          item->dynamic.ppk_list.clear();
          item->dynamic.ppk_id.clear();
        }
      } else if (item && (id == md_transport_pre_shared_key ||
                          id == classic_transport_pre_shared_key)) {
        const auto value = cli_detail::argument(
            command, TokenKind::ipsec_pre_shared_key);
        const auto handle = value ? seal_secret(
                                        secrets,
                                        SecretKind::ike_pre_shared_key, *value)
                                  : std::nullopt;
        changed = handle && item->dynamic.pre_shared_key_handle != *handle;
        if (changed)
          item->dynamic.pre_shared_key_handle = *handle;
      } else if (item && (id == md_delete_transport_pre_shared_key ||
                          id == classic_transport_no_pre_shared_key)) {
        changed = item->dynamic.pre_shared_key_handle != 0U;
        item->dynamic.pre_shared_key_handle = 0U;
      } else if (item && id == md_transport_ipsec_transform) {
        changed = ipsec_id &&
                  ipsec::configuration::find_ipsec(
                      state, static_cast<std::uint16_t>(*ipsec_id)) &&
                  item->dynamic.ipsec_transforms.size() < 4U &&
                  std::find(item->dynamic.ipsec_transforms.begin(),
                            item->dynamic.ipsec_transforms.end(), *ipsec_id) ==
                      item->dynamic.ipsec_transforms.end();
        if (changed)
          item->dynamic.ipsec_transforms.push_back(
              static_cast<std::uint16_t>(*ipsec_id));
      } else if (item && classic_transport_transform_command(id)) {
        const auto references = numbers(command, TokenKind::ipsec_transform_id);
        // The classic `transform` command replaces the complete ordered
        // preference list. It is not an append operation and the first ID is
        // the most preferred proposal sent by an initiator.
        changed = valid_ipsec_transform_list(state, references) &&
                  item->dynamic.ipsec_transforms != references;
        if (changed)
          item->dynamic.ipsec_transforms = references;
      } else if (item && id == classic_transport_no_transform) {
        changed = !item->dynamic.ipsec_transforms.empty();
        if (changed)
          item->dynamic.ipsec_transforms.clear();
      } else if (item && id == md_delete_transport_ipsec_transform) {
        if (ipsec_id) {
          const auto found = std::find(item->dynamic.ipsec_transforms.begin(),
                                       item->dynamic.ipsec_transforms.end(),
                                       *ipsec_id);
          if (found != item->dynamic.ipsec_transforms.end()) {
            item->dynamic.ipsec_transforms.erase(found);
            changed = true;
          }
        }
      } else if (item && (id == md_transport_history_esp ||
                          id == classic_transport_history_esp)) {
        const auto value = number(command, TokenKind::history_esp_records);
        changed = value && *value >= 1U && *value <= 48U &&
                  configure(item->maximum_esp_history_records,
                            item->maximum_esp_history_records_configured,
                            static_cast<std::uint8_t>(*value));
      } else if (item && (id == md_delete_transport_history_esp ||
                          id == classic_transport_no_history_esp)) {
        changed = remove(item->maximum_esp_history_records,
                         item->maximum_esp_history_records_configured,
                         static_cast<std::uint8_t>(0U));
      } else if (item && (id == md_transport_history_ike ||
                          id == classic_transport_history_ike)) {
        const auto value = number(command, TokenKind::history_ike_records);
        changed = value && *value >= 1U && *value <= 3U &&
                  configure(item->maximum_ike_history_records,
                            item->maximum_ike_history_records_configured,
                            static_cast<std::uint8_t>(*value));
      } else if (item && (id == md_delete_transport_history_ike ||
                          id == classic_transport_no_history_ike)) {
        changed = remove(item->maximum_ike_history_records,
                         item->maximum_ike_history_records_configured,
                         static_cast<std::uint8_t>(0U));
      } else if (item && (id == md_transport_replay_window ||
                          id == classic_transport_replay_window)) {
        const auto value = number(command, TokenKind::replay_window);
        changed = value && ipsec::configuration::valid_replay_window(
                               static_cast<std::uint16_t>(*value)) &&
                  configure(item->replay_window,
                            item->replay_window_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_transport_replay_window ||
                          id == classic_transport_no_replay_window)) {
        changed = remove(item->replay_window,
                         item->replay_window_configured,
                         static_cast<std::uint16_t>(0U));
      }
    }
  } else if (tunnel_id) {
    instance += "/tunnel-template/" + std::to_string(*tunnel_id);
    if (id == md_delete_tunnel_template || id == classic_tunnel_remove) {
      changed = erase(state.tunnel_templates,
                      static_cast<std::uint16_t>(*tunnel_id));
    } else if (id == classic_tunnel_create) {
      changed = !ipsec::configuration::find_tunnel_template(
                    state.tunnel_templates,
                    static_cast<std::uint16_t>(*tunnel_id)) &&
                materialize<ipsec::configuration::TunnelTemplate>(
                    state.tunnel_templates,
                    static_cast<std::uint16_t>(*tunnel_id),
                    profile::maximum_tunnel_templates);
    } else {
      auto *item = md ? materialize<ipsec::configuration::TunnelTemplate>(
                            state.tunnel_templates,
                            static_cast<std::uint16_t>(*tunnel_id),
                            profile::maximum_tunnel_templates)
                      : ipsec::configuration::find_tunnel_template(
                            state.tunnel_templates,
                            static_cast<std::uint16_t>(*tunnel_id));
      if (item && (id == md_tunnel_description ||
                   id == classic_tunnel_description)) {
        const auto value = cli_detail::argument(command, TokenKind::description);
        changed = value && assign_description(item->description, *value);
      } else if (item && (id == md_delete_tunnel_description ||
                          id == classic_tunnel_no_description)) {
        changed = !item->description.empty();
        if (changed)
          item->description.clear();
      } else if (item && id == md_tunnel_transform) {
        changed = ipsec_id &&
                  ipsec::configuration::find_ipsec(
                      state, static_cast<std::uint16_t>(*ipsec_id)) &&
                  item->ipsec_transforms.size() < 4U &&
                  std::find(item->ipsec_transforms.begin(),
                            item->ipsec_transforms.end(), *ipsec_id) ==
                      item->ipsec_transforms.end();
        if (changed)
          item->ipsec_transforms.push_back(
              static_cast<std::uint16_t>(*ipsec_id));
      } else if (item && classic_tunnel_transform_command(id)) {
        const auto references = numbers(command, TokenKind::ipsec_transform_id);
        changed = valid_ipsec_transform_list(state, references) &&
                  item->ipsec_transforms != references;
        if (changed)
          item->ipsec_transforms = references;
      } else if (item && id == classic_tunnel_no_transform) {
        changed = !item->ipsec_transforms.empty();
        if (changed)
          item->ipsec_transforms.clear();
      } else if (item && id == md_delete_tunnel_transform) {
        const auto found = ipsec_id
                               ? std::find(item->ipsec_transforms.begin(),
                                           item->ipsec_transforms.end(),
                                           static_cast<std::uint16_t>(*ipsec_id))
                               : item->ipsec_transforms.end();
        changed = found != item->ipsec_transforms.end();
        if (changed)
          item->ipsec_transforms.erase(found);
      } else if (item && (id == md_tunnel_replay_window ||
                          id == classic_tunnel_replay_window)) {
        const auto value = number(command, TokenKind::replay_window);
        changed = value && ipsec::configuration::valid_replay_window(
                               static_cast<std::uint16_t>(*value)) &&
                  configure(item->replay_window,
                            item->replay_window_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_replay_window ||
                          id == classic_tunnel_no_replay_window)) {
        changed = remove(item->replay_window, item->replay_window_configured,
                         static_cast<std::uint16_t>(0U));
      } else if (item && (id == md_tunnel_encapsulated_mtu ||
                          id == classic_tunnel_encapsulated_mtu)) {
        const auto value = number(command, TokenKind::mtu);
        changed = value && *value >= 512U && *value <= 9'000U &&
                  configure(item->encapsulated_ip_mtu,
                            item->encapsulated_ip_mtu_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_encapsulated_mtu ||
                          id == classic_tunnel_no_encapsulated_mtu)) {
        changed = remove(item->encapsulated_ip_mtu,
                         item->encapsulated_ip_mtu_configured,
                         static_cast<std::uint16_t>(0U));
      } else if (item && (id == md_tunnel_ip_mtu ||
                          id == classic_tunnel_ip_mtu)) {
        const auto value = number(command, TokenKind::mtu);
        changed = value && *value >= 512U && *value <= 9'000U &&
                  configure(item->ip_mtu, item->ip_mtu_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_ip_mtu ||
                          id == classic_tunnel_no_ip_mtu)) {
        changed = remove(item->ip_mtu, item->ip_mtu_configured,
                         static_cast<std::uint16_t>(0U));
      } else if (item && (id == md_tunnel_pmtu_aging ||
                          id == classic_tunnel_pmtu_aging)) {
        const auto value = number(command, TokenKind::pmtu_aging);
        changed = value && *value >= 900U && *value <= 3'600U &&
                  configure(item->pmtu_discovery_aging_seconds,
                            item->pmtu_discovery_aging_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_pmtu_aging ||
                          id == classic_tunnel_no_pmtu_aging)) {
        changed = remove(item->pmtu_discovery_aging_seconds,
                         item->pmtu_discovery_aging_configured,
                         static_cast<std::uint16_t>(900U));
      } else if (item && (id == md_tunnel_ppk_list ||
                          id == classic_tunnel_ppk_list)) {
        const auto name = cli_detail::argument(command, TokenKind::ppk_list_name);
        changed = name && ipsec::configuration::find_named(state.ppk_lists, *name) &&
                  item->ppk_list != *name;
        if (changed)
          item->ppk_list.assign(*name);
      } else if (item && (id == md_delete_tunnel_ppk_list ||
                          id == classic_tunnel_no_ppk_list)) {
        changed = !item->ppk_list.empty();
        if (changed)
          item->ppk_list.clear();
      } else if (item && (id == md_tunnel_private_mss ||
                          id == classic_tunnel_private_mss)) {
        const auto value = number(command, TokenKind::tunnel_mss);
        changed = value && *value >= 512U && *value <= 9'000U &&
                  configure(item->private_tcp_mss_adjust,
                            item->private_tcp_mss_adjust_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_private_mss ||
                          id == classic_tunnel_no_private_mss)) {
        changed = remove(item->private_tcp_mss_adjust,
                         item->private_tcp_mss_adjust_configured,
                         static_cast<std::uint16_t>(0U));
      } else if (item && (id == md_tunnel_public_mss ||
                          id == classic_tunnel_public_mss)) {
        const auto value = number(command, TokenKind::tunnel_mss);
        // The numeric and `auto` alternatives are one YANG choice. Switching
        // alternatives replaces the prior leaf atomically instead of leaving
        // an obsolete numeric value active behind an auto flag.
        changed = value && *value >= 512U && *value <= 9'000U &&
                  (!item->public_tcp_mss_adjust_configured ||
                   item->public_tcp_mss_auto ||
                   item->public_tcp_mss_adjust != *value);
        if (changed) {
          item->public_tcp_mss_adjust = static_cast<std::uint16_t>(*value);
          item->public_tcp_mss_adjust_configured = true;
          item->public_tcp_mss_auto = false;
        }
      } else if (item && (id == md_tunnel_public_mss_auto ||
                          id == classic_tunnel_public_mss_auto)) {
        changed = !item->public_tcp_mss_adjust_configured ||
                  !item->public_tcp_mss_auto;
        if (changed) {
          item->public_tcp_mss_adjust = 0U;
          item->public_tcp_mss_adjust_configured = true;
          item->public_tcp_mss_auto = true;
        }
      } else if (item && (id == md_delete_tunnel_public_mss ||
                          id == classic_tunnel_no_public_mss)) {
        changed = item->public_tcp_mss_adjust_configured;
        if (changed) {
          item->public_tcp_mss_adjust = 0U;
          item->public_tcp_mss_adjust_configured = false;
          item->public_tcp_mss_auto = false;
        }
      } else if (item && (id == md_tunnel_icmp_enable ||
                          id == md_tunnel_icmp_disable ||
                          id == classic_tunnel_frag_required)) {
        changed = configure(item->ipv4_fragmentation_required.enabled,
                            item->ipv4_fragmentation_required.enabled_configured,
                            id != md_tunnel_icmp_disable);
      } else if (item && (id == md_delete_tunnel_icmp_admin ||
                          id == classic_tunnel_no_frag_required)) {
        // In classic CLI the no form disables the containing mechanism; it
        // does not remove the MD leaf's presence. Recording an explicit false
        // preserves that observable difference when engines are switched.
        if (id == classic_tunnel_no_frag_required)
          changed = configure(item->ipv4_fragmentation_required.enabled,
                              item->ipv4_fragmentation_required.enabled_configured,
                              false);
        else
          changed = remove(item->ipv4_fragmentation_required.enabled,
                           item->ipv4_fragmentation_required.enabled_configured,
                           true);
      } else if (item && (id == md_tunnel_icmp_interval ||
                          id == classic_tunnel_frag_interval)) {
        const auto value = number(command, TokenKind::tunnel_rate_interval);
        changed = value && *value >= 1U && *value <= 60U &&
                  configure(item->ipv4_fragmentation_required.interval_seconds,
                            item->ipv4_fragmentation_required.interval_configured,
                            static_cast<std::uint8_t>(*value));
      } else if (item && (id == md_delete_tunnel_icmp_interval ||
                          id == classic_tunnel_no_frag_interval)) {
        changed = remove(item->ipv4_fragmentation_required.interval_seconds,
                         item->ipv4_fragmentation_required.interval_configured,
                         static_cast<std::uint8_t>(10U));
      } else if (item && (id == md_tunnel_icmp_count ||
                          id == classic_tunnel_frag_count)) {
        const auto value = number(command, TokenKind::tunnel_message_count);
        changed = value && *value >= 10U && *value <= 1'000U &&
                  configure(item->ipv4_fragmentation_required.message_count,
                            item->ipv4_fragmentation_required.message_count_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_icmp_count ||
                          id == classic_tunnel_no_frag_count)) {
        changed = remove(item->ipv4_fragmentation_required.message_count,
                         item->ipv4_fragmentation_required.message_count_configured,
                         static_cast<std::uint16_t>(100U));
      } else if (item && (id == md_tunnel_icmp6_enable ||
                          id == md_tunnel_icmp6_disable ||
                          id == classic_tunnel_pkt_too_big)) {
        changed = configure(item->ipv6_packet_too_big.enabled,
                            item->ipv6_packet_too_big.enabled_configured,
                            id != md_tunnel_icmp6_disable);
      } else if (item && (id == md_delete_tunnel_icmp6_admin ||
                          id == classic_tunnel_no_pkt_too_big)) {
        if (id == classic_tunnel_no_pkt_too_big)
          changed = configure(item->ipv6_packet_too_big.enabled,
                              item->ipv6_packet_too_big.enabled_configured,
                              false);
        else
          changed = remove(item->ipv6_packet_too_big.enabled,
                           item->ipv6_packet_too_big.enabled_configured, true);
      } else if (item && (id == md_tunnel_icmp6_interval ||
                          id == classic_tunnel_pkt_interval)) {
        const auto value = number(command, TokenKind::tunnel_rate_interval);
        changed = value && *value >= 1U && *value <= 60U &&
                  configure(item->ipv6_packet_too_big.interval_seconds,
                            item->ipv6_packet_too_big.interval_configured,
                            static_cast<std::uint8_t>(*value));
      } else if (item && (id == md_delete_tunnel_icmp6_interval ||
                          id == classic_tunnel_no_pkt_interval)) {
        changed = remove(item->ipv6_packet_too_big.interval_seconds,
                         item->ipv6_packet_too_big.interval_configured,
                         static_cast<std::uint8_t>(10U));
      } else if (item && (id == md_tunnel_icmp6_count ||
                          id == classic_tunnel_pkt_count)) {
        const auto value = number(command, TokenKind::tunnel_message_count);
        changed = value && *value >= 10U && *value <= 1'000U &&
                  configure(item->ipv6_packet_too_big.message_count,
                            item->ipv6_packet_too_big.message_count_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && (id == md_delete_tunnel_icmp6_count ||
                          id == classic_tunnel_no_pkt_count)) {
        changed = remove(item->ipv6_packet_too_big.message_count,
                         item->ipv6_packet_too_big.message_count_configured,
                         static_cast<std::uint16_t>(100U));
      } else if (item && id == md_tunnel_reverse_metric) {
        const auto value = number(command, TokenKind::reverse_route_metric);
        changed = value && *value <= 65'535U &&
                  configure(item->reverse_route_metric,
                            item->reverse_route_metric_configured,
                            static_cast<std::uint16_t>(*value));
      } else if (item && id == md_delete_tunnel_reverse_metric) {
        changed = remove(item->reverse_route_metric,
                         item->reverse_route_metric_configured,
                         static_cast<std::uint16_t>(0U));
      } else if (item && id == md_tunnel_reverse_preference) {
        const auto value = number(command, TokenKind::reverse_route_preference);
        changed = value && *value <= 255U &&
                  configure(item->reverse_route_preference,
                            item->reverse_route_preference_configured,
                            static_cast<std::uint8_t>(*value));
      } else if (item && id == md_delete_tunnel_reverse_preference) {
        changed = remove(item->reverse_route_preference,
                         item->reverse_route_preference_configured,
                         static_cast<std::uint8_t>(0U));
      } else if (item && (id == classic_tunnel_sp_reverse ||
                          id == classic_tunnel_sp_reverse_ignore)) {
        const auto before_item = *item;
        item->service_provider_reverse_route =
            ipsec::configuration::ServiceProviderReverseRoute::use_security_policy;
        item->service_provider_reverse_route_configured = true;
        item->ignore_default_route = id == classic_tunnel_sp_reverse_ignore;
        item->ignore_default_route_configured = true;
        changed = *item != before_item;
      } else if (item && id == classic_tunnel_no_sp_reverse) {
        const auto before_item = *item;
        item->service_provider_reverse_route =
            ipsec::configuration::ServiceProviderReverseRoute::none;
        item->service_provider_reverse_route_configured = false;
        item->ignore_default_route = false;
        item->ignore_default_route_configured = false;
        changed = *item != before_item;
      } else if (item && (id == md_tunnel_sp_reverse_none ||
                          id == md_tunnel_sp_reverse_policy)) {
        const auto value = id == md_tunnel_sp_reverse_policy
                               ? ipsec::configuration::ServiceProviderReverseRoute::use_security_policy
                               : ipsec::configuration::ServiceProviderReverseRoute::none;
        changed = configure(item->service_provider_reverse_route,
                            item->service_provider_reverse_route_configured,
                            value);
      } else if (item && id == md_delete_tunnel_sp_reverse) {
        changed = remove(item->service_provider_reverse_route,
                         item->service_provider_reverse_route_configured,
                         ipsec::configuration::ServiceProviderReverseRoute::none);
      } else if (item && (id == classic_tunnel_clear_df ||
                          id == classic_tunnel_no_clear_df)) {
        changed = configure(item->clear_df_bit, item->clear_df_bit_configured,
                            id == classic_tunnel_clear_df);
      } else if (item && (id == classic_tunnel_copy_traffic_class ||
                          id == classic_tunnel_no_copy_traffic_class)) {
        changed = configure(item->copy_traffic_class_upon_decapsulation,
                            item->copy_traffic_class_configured,
                            id == classic_tunnel_copy_traffic_class);
      } else if (item && (id == classic_tunnel_propagate_pmtu_v4 ||
                          id == classic_tunnel_no_propagate_pmtu_v4)) {
        changed = configure(item->propagate_pmtu_v4,
                            item->propagate_pmtu_v4_configured,
                            id == classic_tunnel_propagate_pmtu_v4);
      } else if (item && (id == classic_tunnel_propagate_pmtu_v6 ||
                          id == classic_tunnel_no_propagate_pmtu_v6)) {
        changed = configure(item->propagate_pmtu_v6,
                            item->propagate_pmtu_v6_configured,
                            id == classic_tunnel_propagate_pmtu_v6);
      } else if (item) {
        const auto value = cli_detail::argument(command, TokenKind::boolean);
        if (id == md_tunnel_clear_df)
          changed = value && configure(item->clear_df_bit,
                                       item->clear_df_bit_configured,
                                       *value == "true");
        else if (id == md_tunnel_copy_traffic_class)
          changed = value && configure(
                                 item->copy_traffic_class_upon_decapsulation,
                                 item->copy_traffic_class_configured,
                                 *value == "true");
        else if (id == md_tunnel_ignore_default)
          changed = value && configure(item->ignore_default_route,
                                       item->ignore_default_route_configured,
                                       *value == "true");
        else if (id == md_tunnel_propagate_pmtu_v4)
          changed = value && configure(item->propagate_pmtu_v4,
                                       item->propagate_pmtu_v4_configured,
                                       *value == "true");
        else if (id == md_tunnel_propagate_pmtu_v6)
          changed = value && configure(item->propagate_pmtu_v6,
                                       item->propagate_pmtu_v6_configured,
                                       *value == "true");
        else if (id == md_delete_tunnel_clear_df)
          changed = remove(item->clear_df_bit, item->clear_df_bit_configured,
                           false);
        else if (id == md_delete_tunnel_copy_traffic_class)
          changed = remove(item->copy_traffic_class_upon_decapsulation,
                           item->copy_traffic_class_configured, false);
        else if (id == md_delete_tunnel_ignore_default)
          changed = remove(item->ignore_default_route,
                           item->ignore_default_route_configured, false);
        else if (id == md_delete_tunnel_propagate_pmtu_v4)
          changed = remove(item->propagate_pmtu_v4,
                           item->propagate_pmtu_v4_configured, true);
        else if (id == md_delete_tunnel_propagate_pmtu_v6)
          changed = remove(item->propagate_pmtu_v6,
                           item->propagate_pmtu_v6_configured, true);
      }
    }
  }

  // Some operations materialize a parent before discovering an invalid child
  // value. Rollback makes the editor transactional and prevents empty phantom
  // list entries from appearing after a rejected terminal command.
  if (!changed)
    state = before;
  return {.recognized = true, .changed = changed, .instance = std::move(instance)};
}

} // namespace router::lab::ipsec_cli
