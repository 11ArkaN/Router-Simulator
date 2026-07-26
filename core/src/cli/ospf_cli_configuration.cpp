// Atomic implementation of the SR OS OSPF and OSPF3 instance, area and
// interface commands represented by the generated CLI schema. Both terminal
// syntaxes update one intent model while retaining their own commit semantics.

#include "ospf_cli_configuration.hpp"

#include "cli_internal.hpp"
#include "router/generated_device_catalog.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <optional>
#include <string_view>
#include <chrono>

namespace router::lab::ospf_cli {
namespace {

using cli_schema::CommandId;
using cli_schema::TokenKind;

template <typename Integer>
std::optional<Integer> decimal(std::string_view text) noexcept {
  Integer parsed{};
  const auto result =
      std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (text.empty() || result.ec != std::errc{} ||
      result.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::string_view argument_text(const cli_detail::ParsedCommand &command,
                               TokenKind kind) noexcept {
  const auto value = cli_detail::argument(command, kind);
  return value ? cli_detail::unquote(*value) : std::string_view{};
}

std::optional<std::uint32_t> ipv4(std::string_view text) noexcept {
  std::uint32_t value{};
  std::size_t offset{};
  for (std::size_t octet{}; octet < 4U; ++octet) {
    const auto end = octet == 3U ? text.size() : text.find('.', offset);
    if (end == std::string_view::npos || end == offset)
      return std::nullopt;
    const auto component = decimal<unsigned>(text.substr(offset, end - offset));
    if (!component || *component > 255U)
      return std::nullopt;
    value = value << 8U | *component;
    offset = end + 1U;
  }
  return offset == text.size() + 1U ? std::optional{value} : std::nullopt;
}

std::optional<std::uint32_t> area_id(std::string_view text) noexcept {
  // SR OS accepts both dotted-decimal and an unsigned 32-bit area number.
  // Parsing both into the wire-order integer makes equality independent of
  // which textual form the operator used.
  if (text.find('.') != std::string_view::npos)
    return ipv4(text);
  return decimal<std::uint32_t>(text);
}

std::optional<std::int64_t>
utc_timestamp(std::string_view text) noexcept {
  // MD-CLI renders ietf-yang-types date-and-time in RFC 3339 form. OSPF key
  // rollover uses UTC internally, so only `Z` and explicit +00:00 are
  // accepted here. Other offsets remain source-valid syntax but require a
  // complete offset normalizer before they can be exposed by the grammar.
  if (text.size() < 20U || text[4U] != '-' || text[7U] != '-' ||
      text[10U] != 'T' || text[13U] != ':' || text[16U] != ':')
    return std::nullopt;
  const auto year = decimal<int>(text.substr(0U, 4U));
  const auto month = decimal<unsigned>(text.substr(5U, 2U));
  const auto day = decimal<unsigned>(text.substr(8U, 2U));
  const auto hour = decimal<unsigned>(text.substr(11U, 2U));
  const auto minute = decimal<unsigned>(text.substr(14U, 2U));
  const auto second = decimal<unsigned>(text.substr(17U, 2U));
  if (!year || !month || !day || !hour || !minute || !second ||
      *year < 1970 || *month == 0U || *month > 12U || *hour > 23U ||
      *minute > 59U || *second > 59U)
    return std::nullopt;
  std::size_t zone = 19U;
  if (zone < text.size() && text[zone] == '.') {
    ++zone;
    const auto fraction_begin = zone;
    while (zone < text.size() && text[zone] >= '0' && text[zone] <= '9')
      ++zone;
    if (zone == fraction_begin)
      return std::nullopt;
  }
  if (!(text.substr(zone) == "Z" || text.substr(zone) == "+00:00"))
    return std::nullopt;
  constexpr std::array<unsigned, 12U> month_days{
      31U, 28U, 31U, 30U, 31U, 30U,
      31U, 31U, 30U, 31U, 30U, 31U};
  const bool leap = (*year % 4 == 0 && *year % 100 != 0) ||
                    *year % 400 == 0;
  const auto maximum_day =
      month_days[*month - 1U] + (*month == 2U && leap ? 1U : 0U);
  if (*day == 0U || *day > maximum_day)
    return std::nullopt;

  // Howard Hinnant's civil-date transform maps Gregorian dates to days since
  // 1970-01-01 without locale, timezone database or platform `time_t`.
  const auto adjusted_year = *year - (*month <= 2U ? 1 : 0);
  const auto era = adjusted_year / 400;
  const auto year_of_era = adjusted_year - era * 400;
  const auto adjusted_month =
      static_cast<int>(*month) + (*month > 2U ? -3 : 9);
  const auto day_of_year =
      (153 * adjusted_month + 2) / 5 + static_cast<int>(*day) - 1;
  const auto day_of_era =
      year_of_era * 365 + year_of_era / 4 - year_of_era / 100 +
      day_of_year;
  const auto days = era * 146097 + day_of_era - 719468;
  return static_cast<std::int64_t>(days) * 86400 +
         static_cast<std::int64_t>(*hour) * 3600 +
         static_cast<std::int64_t>(*minute) * 60 + *second;
}

bool version_three(CommandId id) noexcept {
  using enum CommandId;
  switch (id) {
  case md_ospf3_admin_enable:
  case md_ospf3_admin_disable:
  case md_ospf3_router_id:
  case md_ospf3_reference_bandwidth:
  case md_ospf3_preference:
  case md_ospf3_external_preference:
  case md_ospf3_export_policy:
  case md_ospf3_asbr:
  case md_delete_ospf3_asbr:
  case md_ospf3_overload:
  case md_ospf3_graceful_restart:
  case md_ospf3_loopfree_alternates:
  case md_ospf3_spf_initial_wait:
  case md_ospf3_spf_second_wait:
  case md_ospf3_spf_max_wait:
  case md_ospf3_lsa_initial_wait:
  case md_ospf3_lsa_second_wait:
  case md_ospf3_lsa_max_wait:
  case md_ospf3_area_stub:
  case md_delete_ospf3_area_stub:
  case md_ospf3_area_nssa:
  case md_delete_ospf3_area_nssa:
  case md_ospf3_area_summaries:
  case md_ospf3_area_default_metric:
  case md_ospf3_area_range_advertise:
  case md_ospf3_area_range_suppress:
  case md_delete_ospf3_area_range:
  case md_ospf3_virtual_link:
  case md_delete_ospf3_virtual_link:
  case md_ospf3_virtual_link_hello:
  case md_delete_ospf3_virtual_link_hello:
  case md_ospf3_virtual_link_dead:
  case md_delete_ospf3_virtual_link_dead:
  case md_ospf3_virtual_link_retransmit:
  case md_delete_ospf3_virtual_link_retransmit:
  case md_ospf3_virtual_link_transit_delay:
  case md_delete_ospf3_virtual_link_transit_delay:
  case md_ospf3_virtual_link_auth_bidirectional:
  case md_ospf3_virtual_link_auth_directional:
  case md_delete_ospf3_virtual_link_authentication:
  case md_ospf3_interface_type:
  case md_ospf3_interface_admin_enable:
  case md_ospf3_interface_admin_disable:
  case md_ospf3_interface_metric:
  case md_ospf3_interface_priority:
  case md_ospf3_interface_passive:
  case md_ospf3_interface_mtu_ignore:
  case md_ospf3_interface_hello:
  case md_ospf3_interface_dead:
  case md_ospf3_interface_retransmit:
  case md_ospf3_interface_transit_delay:
  case md_ospf3_interface_neighbor:
  case md_delete_ospf3_interface_neighbor:
  case md_ospf3_interface_auth_keychain:
  case md_ospf3_interface_auth_directional:
  case md_delete_ospf3_interface_authentication:
  case md_delete_ospf3_interface:
  case md_delete_ospf3_area:
  case md_delete_ospf3:
  case classic_ospf3_create:
  case classic_ospf3_create_router_id:
  case classic_no_ospf3:
  case classic_ospf3_shutdown:
  case classic_ospf3_no_shutdown:
  case classic_ospf3_reference_bandwidth:
  case classic_ospf3_preference:
  case classic_ospf3_external_preference:
  case classic_ospf3_export_policy:
  case classic_ospf3_asbr:
  case classic_ospf3_no_asbr:
  case classic_ospf3_overload:
  case classic_ospf3_no_overload:
  case classic_ospf3_graceful_restart:
  case classic_ospf3_no_graceful_restart:
  case classic_ospf3_loopfree_alternates:
  case classic_ospf3_no_loopfree_alternates:
  case classic_ospf3_spf_initial_wait:
  case classic_ospf3_spf_second_wait:
  case classic_ospf3_spf_max_wait:
  case classic_ospf3_lsa_initial_wait:
  case classic_ospf3_lsa_second_wait:
  case classic_ospf3_lsa_max_wait:
  case classic_ospf3_area_stub:
  case classic_ospf3_area_no_stub:
  case classic_ospf3_area_nssa:
  case classic_ospf3_area_no_nssa:
  case classic_ospf3_area_no_summaries:
  case classic_ospf3_area_summaries:
  case classic_ospf3_area_default_metric:
  case classic_ospf3_area_range_advertise:
  case classic_ospf3_area_range_suppress:
  case classic_ospf3_area_no_range:
  case classic_ospf3_virtual_link:
  case classic_ospf3_no_virtual_link:
  case classic_ospf3_virtual_link_hello:
  case classic_ospf3_virtual_link_no_hello:
  case classic_ospf3_virtual_link_dead:
  case classic_ospf3_virtual_link_no_dead:
  case classic_ospf3_virtual_link_retransmit:
  case classic_ospf3_virtual_link_no_retransmit:
  case classic_ospf3_virtual_link_transit_delay:
  case classic_ospf3_virtual_link_no_transit_delay:
  case classic_ospf3_virtual_link_auth_bidirectional:
  case classic_ospf3_virtual_link_auth_directional:
  case classic_ospf3_virtual_link_no_authentication:
  case classic_ospf3_interface_type:
  case classic_ospf3_interface_metric:
  case classic_ospf3_interface_priority:
  case classic_ospf3_interface_passive:
  case classic_ospf3_interface_no_passive:
  case classic_ospf3_interface_neighbor:
  case classic_ospf3_interface_no_neighbor:
  case classic_ospf3_interface_auth_keychain:
  case classic_ospf3_interface_auth_directional:
  case classic_ospf3_interface_no_authentication:
  case classic_ospf3_no_interface:
    return true;
  default:
    return false;
  }
}

ospf::AddressFamily family_for(CommandId id, std::uint8_t instance) noexcept {
  if (!version_three(id))
    return ospf::AddressFamily::ipv4;
  return instance <= device_catalog::ospf_v3_ipv6_instance_last
             ? ospf::AddressFamily::ipv6
             : ospf::AddressFamily::ipv4_over_ospfv3;
}

ospf::InstanceConfiguration *
find_instance(ospf::RouterConfiguration &configuration,
              ospf::AddressFamily family, std::uint8_t id) noexcept {
  const auto found = std::find_if(
      configuration.instances.begin(), configuration.instances.end(),
      [&](const auto &instance) {
        return instance.address_family == family && instance.instance_id == id;
      });
  return found == configuration.instances.end() ? nullptr : &*found;
}

ospf::AreaConfiguration *
find_area(ospf::InstanceConfiguration &instance, std::uint32_t id) noexcept {
  const auto found =
      std::find_if(instance.areas.begin(), instance.areas.end(),
                   [id](const auto &area) { return area.area_id == id; });
  return found == instance.areas.end() ? nullptr : &*found;
}

ospf::InterfaceConfigurationIntent *
find_interface(ospf::AreaConfiguration &area, std::string_view name) noexcept {
  const auto found = std::find_if(
      area.interfaces.begin(), area.interfaces.end(),
      [name](const auto &interface) {
        return interface.interface_name == name;
      });
  return found == area.interfaces.end() ? nullptr : &*found;
}

ospf::InterfaceConfigurationIntent
default_interface(std::string_view name) {
  // These values are release-owned generated data. An interface context is
  // therefore complete enough for canonical validation without embedding SR
  // OS defaults in parser logic.
  return {
      .interface_name = std::string{name},
      .cost = device_catalog::ospf_interface_cost,
      .hello_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_hello_interval.count()),
      .dead_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_dead_interval.count()),
      .retransmit_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_retransmit_interval.count()),
      .transmit_delay_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_transmit_delay.count()),
      .priority = device_catalog::ospf_interface_priority,
      .network_type = ospf::NetworkType::point_to_point,
      .admin_enabled = true};
}

ospf::VirtualLinkConfiguration
default_virtual_link(std::uint32_t remote_router_id,
                     std::uint32_t transit_area_id) noexcept {
  // Virtual-link timers use the same release defaults as a point-to-point
  // OSPF interface unless explicitly configured in its child context.
  return {
      .transit_area_id = transit_area_id,
      .remote_router_id = remote_router_id,
      .hello_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_hello_interval.count()),
      .dead_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_dead_interval.count()),
      .retransmit_interval_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_retransmit_interval.count()),
      .transmit_delay_seconds = static_cast<std::uint16_t>(
          device_catalog::ospf_transmit_delay.count()),
      .admin_enabled = true};
}

std::optional<ospf::NetworkType>
network_type(std::string_view text) noexcept {
  if (text == "point-to-point")
    return ospf::NetworkType::point_to_point;
  if (text == "broadcast")
    return ospf::NetworkType::broadcast;
  if (text == "non-broadcast")
    return ospf::NetworkType::non_broadcast;
  if (text == "point-to-multipoint")
    return ospf::NetworkType::point_to_multipoint;
  return std::nullopt;
}

bool boolean(std::string_view text, bool &value) noexcept {
  if (text == "true") {
    value = true;
    return true;
  }
  if (text == "false") {
    value = false;
    return true;
  }
  return false;
}

bool has_literal(const cli_schema::CommandSpec &spec,
                 std::string_view literal) noexcept {
  // Command behavior is derived from the same generated row used by parsing
  // and completion. This avoids maintaining another list whenever the release
  // profile adds the same virtual-link leaf to OSPFv2 or OSPFv3.
  return std::any_of(spec.tokens.begin(),
                     spec.tokens.begin() + spec.token_count,
                     [literal](const auto &token) {
                       return token.kind == TokenKind::literal &&
                              token.display == literal;
                     });
}

} // namespace

bool is_md_command(CommandId id) noexcept {
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [id](const auto &command) {
        const auto root = command.tokens[0].display;
        return command.id == id && (command.engine_mask & 1U) != 0U &&
               (command.source_id ==
                    "nokia.sros.26_7.ospf.configuration_model" ||
                command.source_id ==
                    "nokia.sros.26_7.ospf.virtual_link" ||
                command.source_id ==
                    "nokia.sros.26_7.ospf.keychain") &&
               (root == "configure" || root == "delete");
      });
}

bool is_classic_command(CommandId id) noexcept {
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [id](const auto &command) {
        return command.id == id && (command.engine_mask & 2U) != 0U &&
               (command.source_id ==
                    "nokia.sros.26_7.ospf.configuration_model" ||
                command.source_id ==
                    "nokia.sros.26_7.ospf.virtual_link" ||
                command.source_id ==
                    "nokia.sros.26_7.ospf.keychain") &&
               command.tokens[0].display == "configure";
      });
}

EditResult edit(ospf::RouterConfiguration &configuration,
                const cli_detail::ParsedCommand &command, CliEngine engine,
                SecretSink *secrets) {
  const auto id = command.spec->id;
  const bool recognized =
      engine == CliEngine::md ? is_md_command(id) : is_classic_command(id);
  if (!recognized)
    return {};

  if (command.spec->source_id == "nokia.sros.26_7.ospf.keychain" &&
      !cli_detail::argument(command, TokenKind::ospf_instance)) {
    const auto name =
        argument_text(command, TokenKind::ospf_keychain_name);
    const auto parsed_id =
        decimal<unsigned>(argument_text(command, TokenKind::ospf_key_id));
    if (name.empty() || name.size() > 32U)
      return {.recognized = true, .changed = false, .instance = {}};
    auto next = configuration;
    auto keychain = std::find_if(
        next.keychains.begin(), next.keychains.end(),
        [&](const auto &candidate) { return candidate.name == name; });
    const bool delete_keychain =
        id == CommandId::md_delete_keychain ||
        id == CommandId::classic_no_keychain;
    if (delete_keychain) {
      if (keychain == next.keychains.end())
        return {.recognized = true, .changed = false, .instance = {}};
      next.keychains.erase(keychain);
    } else {
      if (!parsed_id || *parsed_id > 63U)
        return {.recognized = true, .changed = false, .instance = {}};
      if (keychain == next.keychains.end()) {
        next.keychains.push_back({.name = std::string{name}});
        keychain = std::prev(next.keychains.end());
      }
      auto entry = std::find_if(
          keychain->bidirectional.begin(), keychain->bidirectional.end(),
          [&](const auto &candidate) { return candidate.id == *parsed_id; });
      const bool delete_entry =
          id == CommandId::md_delete_keychain_entry ||
          id == CommandId::classic_keychain_no_entry;
      if (delete_entry) {
        if (entry == keychain->bidirectional.end())
          return {.recognized = true, .changed = false, .instance = {}};
        keychain->bidirectional.erase(entry);
      } else {
        if (entry == keychain->bidirectional.end()) {
          keychain->bidirectional.push_back(
              {.tolerance_seconds = 300U,
               .id = static_cast<std::uint8_t>(*parsed_id)});
          entry = std::prev(keychain->bidirectional.end());
        }
        const bool password =
            id == CommandId::md_keychain_entry_password ||
            id == CommandId::classic_keychain_entry_password;
        const bool message_digest =
            id == CommandId::md_keychain_entry_message_digest ||
            id == CommandId::classic_keychain_entry_message_digest;
        const bool hmac_sha1 =
            id == CommandId::md_keychain_entry_hmac_sha1 ||
            id == CommandId::classic_keychain_entry_hmac_sha1;
        const bool hmac_sha256 =
            id == CommandId::md_keychain_entry_hmac_sha256 ||
            id == CommandId::classic_keychain_entry_hmac_sha256;
        if (password || message_digest || hmac_sha1 || hmac_sha256) {
          entry->algorithm =
              password
                  ? ospf::KeychainAlgorithm::password
              : message_digest
                  ? ospf::KeychainAlgorithm::message_digest
              : hmac_sha1 ? ospf::KeychainAlgorithm::hmac_sha1
                          : ospf::KeychainAlgorithm::hmac_sha256;
          entry->algorithm_configured = true;
        }
        const bool carries_key =
            id == CommandId::md_keychain_entry_key ||
            id == CommandId::classic_keychain_entry_password ||
            id == CommandId::classic_keychain_entry_message_digest ||
            id == CommandId::classic_keychain_entry_hmac_sha1 ||
            id == CommandId::classic_keychain_entry_hmac_sha256;
        if (carries_key) {
          const auto plaintext =
              argument_text(command, TokenKind::ospf_authentication_key);
          if (!secrets || plaintext.empty() || plaintext.size() > 128U)
            return {.recognized = true, .changed = false, .instance = {}};
          const auto handle = secrets->seal(
              std::span<const std::uint8_t>{
                  reinterpret_cast<const std::uint8_t *>(plaintext.data()),
                  plaintext.size()});
          if (!handle)
            return {.recognized = true, .changed = false, .instance = {}};
          entry->secret = *handle;
          entry->secret_configured = true;
        }
        if (id == CommandId::md_keychain_entry_begin_now ||
            id == CommandId::classic_keychain_entry_begin_now) {
          entry->begin_utc_seconds =
              std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
        } else if (id == CommandId::md_keychain_entry_begin_time) {
          const auto parsed = utc_timestamp(
              argument_text(command, TokenKind::ospf_keychain_time));
          if (!parsed)
            return {.recognized = true, .changed = false, .instance = {}};
          entry->begin_utc_seconds = *parsed;
        } else if (id == CommandId::md_keychain_entry_tolerance ||
                   id == CommandId::classic_keychain_entry_tolerance) {
          const auto tolerance = decimal<std::uint64_t>(
              argument_text(command, TokenKind::ospf_tolerance));
          if (!tolerance ||
              *tolerance >
                  std::numeric_limits<std::uint32_t>::max() - 1ULL)
            return {.recognized = true, .changed = false, .instance = {}};
          entry->tolerance_seconds =
              static_cast<std::uint32_t>(*tolerance);
        }
      }
    }
    if (ospf::validate(next, true) != ospf::ConfigurationStatus::valid)
      return {.recognized = true, .changed = false, .instance = {}};
    if (next == configuration)
      return {.recognized = true, .valid = true, .changed = false,
              .instance = {}};
    configuration = std::move(next);
    return {.recognized = true, .valid = true, .changed = true,
            .instance = {}};
  }

  const auto instance_text = argument_text(command, TokenKind::ospf_instance);
  const auto parsed_instance = decimal<unsigned>(instance_text);
  if (!parsed_instance ||
      *parsed_instance > std::numeric_limits<std::uint8_t>::max())
    return {.recognized = true, .changed = false, .instance = {}};
  const auto instance_id = static_cast<std::uint8_t>(*parsed_instance);
  const auto family = family_for(id, instance_id);

  // Apply against a value-level copy. A failed range, missing parent or
  // whole-model invariant cannot leak a partially created area or interface
  // into MD candidate or classic running state.
  auto next = configuration;
  auto *instance = find_instance(next, family, instance_id);
  const bool delete_instance =
      id == CommandId::md_delete_ospf || id == CommandId::md_delete_ospf3 ||
      id == CommandId::classic_no_ospf ||
      id == CommandId::classic_no_ospf3;
  if (delete_instance) {
    if (!instance)
      return {.recognized = true, .changed = false, .instance = {}};
    std::erase_if(next.instances, [&](const auto &candidate) {
      return candidate.address_family == family &&
             candidate.instance_id == instance_id;
    });
  } else {
    if (!instance) {
      next.instances.push_back(ospf::default_instance(family, instance_id));
      instance = &next.instances.back();
    }

    const bool create_only =
        id == CommandId::classic_ospf_create ||
        id == CommandId::classic_ospf3_create;
    const bool set_router_id =
        id == CommandId::md_ospf_router_id ||
        id == CommandId::md_ospf3_router_id ||
        id == CommandId::classic_ospf_create_router_id ||
        id == CommandId::classic_ospf3_create_router_id;
    const bool set_reference_bandwidth =
        id == CommandId::md_ospf_reference_bandwidth ||
        id == CommandId::md_ospf3_reference_bandwidth ||
        id == CommandId::classic_ospf_reference_bandwidth ||
        id == CommandId::classic_ospf3_reference_bandwidth;
    if (set_router_id) {
      const auto router_id = ipv4(argument_text(command, TokenKind::ipv4));
      if (!router_id || *router_id == 0U)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->configured_router_id = *router_id;
    } else if (set_reference_bandwidth) {
      const auto bandwidth = decimal<std::uint64_t>(
          argument_text(command, TokenKind::ospf_reference_bandwidth));
      if (!bandwidth)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->reference_bandwidth_kbps = *bandwidth;
    } else if (id == CommandId::md_ospf_admin_enable ||
               id == CommandId::md_ospf3_admin_enable ||
               id == CommandId::classic_ospf_no_shutdown ||
               id == CommandId::classic_ospf3_no_shutdown) {
      instance->admin_enabled = true;
    } else if (id == CommandId::md_ospf_admin_disable ||
               id == CommandId::md_ospf3_admin_disable ||
               id == CommandId::classic_ospf_shutdown ||
               id == CommandId::classic_ospf3_shutdown) {
      instance->admin_enabled = false;
    } else if (id == CommandId::md_ospf_preference ||
               id == CommandId::md_ospf3_preference ||
               id == CommandId::classic_ospf_preference ||
               id == CommandId::classic_ospf3_preference) {
      const auto value = decimal<std::uint32_t>(
          argument_text(command, TokenKind::ospf_preference));
      if (!value || *value < 1U || *value > 255U)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->router_preference = *value;
    } else if (id == CommandId::md_ospf_external_preference ||
               id == CommandId::md_ospf3_external_preference ||
               id == CommandId::classic_ospf_external_preference ||
               id == CommandId::classic_ospf3_external_preference) {
      const auto value = decimal<std::uint32_t>(
          argument_text(command, TokenKind::ospf_preference));
      if (!value || *value < 1U || *value > 255U)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->external_preference = *value;
    } else if (id == CommandId::md_ospf_export_policy ||
               id == CommandId::md_ospf3_export_policy ||
               id == CommandId::classic_ospf_export_policy ||
               id == CommandId::classic_ospf3_export_policy) {
      const auto name = argument_text(command, TokenKind::policy_name);
      if (name.empty() || name.size() > 64U)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->export_policy = name;
    } else if (id == CommandId::md_ospf_asbr ||
               id == CommandId::md_ospf3_asbr ||
               id == CommandId::classic_ospf_asbr ||
               id == CommandId::classic_ospf3_asbr) {
      instance->asbr = true;
    } else if (id == CommandId::md_ospf_asbr_trace_path ||
               id == CommandId::classic_ospf_asbr_trace_path) {
      const auto domain = decimal<unsigned>(
          argument_text(command, TokenKind::ospf_domain_id));
      if (!domain || *domain == 0U || *domain > 31U)
        return {.recognized = true, .changed = false, .instance = {}};
      instance->asbr = true;
      instance->asbr_trace_path_domain_id =
          static_cast<std::uint8_t>(*domain);
    } else if (id == CommandId::md_delete_ospf_asbr ||
               id == CommandId::md_delete_ospf3_asbr ||
               id == CommandId::classic_ospf_no_asbr ||
               id == CommandId::classic_ospf3_no_asbr) {
      instance->asbr = false;
      instance->asbr_trace_path_domain_id.reset();
    } else if (id == CommandId::classic_ospf_overload ||
               id == CommandId::classic_ospf3_overload) {
      instance->overload = true;
    } else if (id == CommandId::classic_ospf_no_overload ||
               id == CommandId::classic_ospf3_no_overload) {
      instance->overload = false;
    } else if (id == CommandId::md_ospf_overload ||
               id == CommandId::md_ospf3_overload) {
      if (!boolean(argument_text(command, TokenKind::boolean),
                   instance->overload))
        return {.recognized = true, .changed = false, .instance = {}};
    } else if (id == CommandId::classic_ospf_graceful_restart ||
               id == CommandId::classic_ospf3_graceful_restart) {
      instance->graceful_restart_helper = true;
    } else if (id == CommandId::classic_ospf_no_graceful_restart ||
               id == CommandId::classic_ospf3_no_graceful_restart) {
      instance->graceful_restart_helper = false;
    } else if (id == CommandId::md_ospf_graceful_restart ||
               id == CommandId::md_ospf3_graceful_restart) {
      if (!boolean(argument_text(command, TokenKind::boolean),
                   instance->graceful_restart_helper))
        return {.recognized = true, .changed = false, .instance = {}};
    } else if (id == CommandId::classic_ospf_loopfree_alternates ||
               id == CommandId::classic_ospf3_loopfree_alternates) {
      instance->loopfree_alternates = true;
    } else if (id == CommandId::classic_ospf_no_loopfree_alternates ||
               id == CommandId::classic_ospf3_no_loopfree_alternates) {
      instance->loopfree_alternates = false;
    } else if (id == CommandId::md_ospf_loopfree_alternates ||
               id == CommandId::md_ospf3_loopfree_alternates) {
      if (!boolean(argument_text(command, TokenKind::boolean),
                   instance->loopfree_alternates))
        return {.recognized = true, .changed = false, .instance = {}};
    } else if (id == CommandId::md_ospf_spf_initial_wait ||
               id == CommandId::md_ospf_spf_second_wait ||
               id == CommandId::md_ospf_spf_max_wait ||
               id == CommandId::md_ospf_lsa_initial_wait ||
               id == CommandId::md_ospf_lsa_second_wait ||
               id == CommandId::md_ospf_lsa_max_wait ||
               id == CommandId::md_ospf3_spf_initial_wait ||
               id == CommandId::md_ospf3_spf_second_wait ||
               id == CommandId::md_ospf3_spf_max_wait ||
               id == CommandId::md_ospf3_lsa_initial_wait ||
               id == CommandId::md_ospf3_lsa_second_wait ||
               id == CommandId::md_ospf3_lsa_max_wait ||
               id == CommandId::classic_ospf_spf_initial_wait ||
               id == CommandId::classic_ospf_spf_second_wait ||
               id == CommandId::classic_ospf_spf_max_wait ||
               id == CommandId::classic_ospf_lsa_initial_wait ||
               id == CommandId::classic_ospf_lsa_second_wait ||
               id == CommandId::classic_ospf_lsa_max_wait ||
               id == CommandId::classic_ospf3_spf_initial_wait ||
               id == CommandId::classic_ospf3_spf_second_wait ||
               id == CommandId::classic_ospf3_spf_max_wait ||
               id == CommandId::classic_ospf3_lsa_initial_wait ||
               id == CommandId::classic_ospf3_lsa_second_wait ||
               id == CommandId::classic_ospf3_lsa_max_wait) {
      const auto value = decimal<std::uint32_t>(
          argument_text(command, TokenKind::ospf_timer_milliseconds));
      if (!value)
        return {.recognized = true, .changed = false, .instance = {}};
      // Command IDs preserve the distinct SR OS leaves while this table maps
      // them to one canonical instance. Whole-model validation below enforces
      // the YANG ranges and initial <= second <= maximum relationships.
      auto *target =
          id == CommandId::md_ospf_spf_initial_wait ||
                  id == CommandId::md_ospf3_spf_initial_wait ||
                  id == CommandId::classic_ospf_spf_initial_wait ||
                  id == CommandId::classic_ospf3_spf_initial_wait
              ? &instance->spf_initial_wait_milliseconds
          : id == CommandId::md_ospf_spf_second_wait ||
                    id == CommandId::md_ospf3_spf_second_wait ||
                    id == CommandId::classic_ospf_spf_second_wait ||
                    id == CommandId::classic_ospf3_spf_second_wait
              ? &instance->spf_second_wait_milliseconds
          : id == CommandId::md_ospf_spf_max_wait ||
                    id == CommandId::md_ospf3_spf_max_wait ||
                    id == CommandId::classic_ospf_spf_max_wait ||
                    id == CommandId::classic_ospf3_spf_max_wait
              ? &instance->spf_maximum_wait_milliseconds
          : id == CommandId::md_ospf_lsa_initial_wait ||
                    id == CommandId::md_ospf3_lsa_initial_wait ||
                    id == CommandId::classic_ospf_lsa_initial_wait ||
                    id == CommandId::classic_ospf3_lsa_initial_wait
              ? &instance->lsa_initial_wait_milliseconds
          : id == CommandId::md_ospf_lsa_second_wait ||
                    id == CommandId::md_ospf3_lsa_second_wait ||
                    id == CommandId::classic_ospf_lsa_second_wait ||
                    id == CommandId::classic_ospf3_lsa_second_wait
              ? &instance->lsa_second_wait_milliseconds
              : &instance->lsa_maximum_wait_milliseconds;
      *target = *value;
    } else if (!create_only) {
      const auto parsed_area =
          area_id(argument_text(command, TokenKind::ospf_area_id));
      const auto interface_name =
          argument_text(command, TokenKind::interface_name);
      const bool delete_area =
          id == CommandId::md_delete_ospf_area ||
          id == CommandId::md_delete_ospf3_area;
      // Area leaves are complete operations in both CLIs. They must not be
      // rejected for lacking an interface argument, which was the former
      // source of silently unusable stub, NSSA and range configuration.
      const bool area_operation =
          id == CommandId::md_ospf_area_stub ||
          id == CommandId::md_delete_ospf_area_stub ||
          id == CommandId::md_ospf_area_nssa ||
          id == CommandId::md_delete_ospf_area_nssa ||
          id == CommandId::md_ospf_area_summaries ||
          id == CommandId::md_ospf_area_default_metric ||
          id == CommandId::md_ospf_area_range_advertise ||
          id == CommandId::md_ospf_area_range_suppress ||
          id == CommandId::md_delete_ospf_area_range ||
          id == CommandId::md_ospf_virtual_link ||
          id == CommandId::md_delete_ospf_virtual_link ||
          id == CommandId::md_ospf3_area_stub ||
          id == CommandId::md_delete_ospf3_area_stub ||
          id == CommandId::md_ospf3_area_nssa ||
          id == CommandId::md_delete_ospf3_area_nssa ||
          id == CommandId::md_ospf3_area_summaries ||
          id == CommandId::md_ospf3_area_default_metric ||
          id == CommandId::md_ospf3_area_range_advertise ||
          id == CommandId::md_ospf3_area_range_suppress ||
          id == CommandId::md_delete_ospf3_area_range ||
          id == CommandId::md_ospf3_virtual_link ||
          id == CommandId::md_delete_ospf3_virtual_link ||
          id == CommandId::md_ospf3_virtual_link_auth_bidirectional ||
          id == CommandId::md_ospf3_virtual_link_auth_directional ||
          id == CommandId::
                    md_delete_ospf3_virtual_link_authentication ||
          id == CommandId::classic_ospf_area_stub ||
          id == CommandId::classic_ospf_area_no_stub ||
          id == CommandId::classic_ospf_area_nssa ||
          id == CommandId::classic_ospf_area_no_nssa ||
          id == CommandId::classic_ospf_area_no_summaries ||
          id == CommandId::classic_ospf_area_summaries ||
          id == CommandId::classic_ospf_area_default_metric ||
          id == CommandId::classic_ospf_area_range_advertise ||
          id == CommandId::classic_ospf_area_range_suppress ||
          id == CommandId::classic_ospf_area_no_range ||
          id == CommandId::classic_ospf_virtual_link ||
          id == CommandId::classic_ospf_no_virtual_link ||
          id == CommandId::classic_ospf3_area_stub ||
          id == CommandId::classic_ospf3_area_no_stub ||
          id == CommandId::classic_ospf3_area_nssa ||
          id == CommandId::classic_ospf3_area_no_nssa ||
          id == CommandId::classic_ospf3_area_no_summaries ||
          id == CommandId::classic_ospf3_area_summaries ||
          id == CommandId::classic_ospf3_area_default_metric ||
          id == CommandId::classic_ospf3_area_range_advertise ||
          id == CommandId::classic_ospf3_area_range_suppress ||
          id == CommandId::classic_ospf3_area_no_range ||
          id == CommandId::classic_ospf3_virtual_link ||
          id == CommandId::classic_ospf3_no_virtual_link ||
          id == CommandId::
                    classic_ospf3_virtual_link_auth_bidirectional ||
          id == CommandId::
                    classic_ospf3_virtual_link_auth_directional ||
          id == CommandId::
                    classic_ospf3_virtual_link_no_authentication ||
          command.spec->source_id ==
              "nokia.sros.26_7.ospf.virtual_link";
      if (!parsed_area ||
          (!delete_area && !area_operation &&
           (interface_name.empty() || interface_name.size() > 32U)))
        return {.recognized = true, .changed = false, .instance = {}};

      auto *area = find_area(*instance, *parsed_area);
      if (delete_area) {
        if (!area)
          return {.recognized = true, .changed = false, .instance = {}};
        std::erase_if(instance->areas, [&](const auto &candidate) {
          return candidate.area_id == *parsed_area;
        });
      } else {
        if (!area) {
          instance->areas.push_back({.area_id = *parsed_area});
          area = &instance->areas.back();
        }
        if (area_operation) {
          const bool virtual_link_operation =
              has_literal(*command.spec, "virtual-link");
          if (virtual_link_operation) {
            const auto remote =
                ipv4(argument_text(command, TokenKind::ipv4));
            const auto transit = area_id(
                argument_text(command,
                              TokenKind::ospf_transit_area_id));
            if (!remote || *remote == 0U || !transit ||
                *transit == 0U || *parsed_area != 0U)
              return {.recognized = true,
                      .changed = false,
                      .instance = {}};
            const auto found = std::find_if(
                area->virtual_links.begin(),
                area->virtual_links.end(), [&](const auto &link) {
                  return link.remote_router_id == *remote &&
                         link.transit_area_id == *transit;
                });
            const bool remove =
                id == CommandId::md_delete_ospf_virtual_link ||
                id == CommandId::md_delete_ospf3_virtual_link ||
                id == CommandId::classic_ospf_no_virtual_link ||
                id == CommandId::classic_ospf3_no_virtual_link;
            if (remove) {
              if (found == area->virtual_links.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              area->virtual_links.erase(found);
            } else if (has_literal(*command.spec, "authentication")) {
              if (found == area->virtual_links.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              const bool reset =
                  command.spec->tokens[0].display == "delete" ||
                  has_literal(*command.spec, "no");
              if (reset) {
                found->authentication =
                    ospf::AuthenticationMode::none;
                found->keychain.clear();
                found->ipsec_sa_inbound.clear();
                found->ipsec_sa_outbound.clear();
              } else {
                const auto inbound =
                    argument_text(command, TokenKind::static_sa_name);
                const auto outbound =
                    id == CommandId::
                              md_ospf3_virtual_link_auth_directional ||
                            id == CommandId::
                              classic_ospf3_virtual_link_auth_directional
                        ? argument_text(
                              command,
                              TokenKind::ospf_ipsec_sa_outbound)
                        : inbound;
                if (inbound.empty() || outbound.empty() ||
                    inbound.size() > 32U || outbound.size() > 32U)
                  return {.recognized = true,
                          .changed = false,
                          .instance = {}};
                found->authentication =
                    ospf::AuthenticationMode::
                        ipsec_security_association;
                found->keychain.clear();
                found->ipsec_sa_inbound = inbound;
                found->ipsec_sa_outbound = outbound;
              }
            } else if (has_literal(*command.spec, "hello-interval") ||
                       has_literal(*command.spec, "dead-interval") ||
                       has_literal(*command.spec, "retransmit-interval") ||
                       has_literal(*command.spec, "transit-delay")) {
              if (found == area->virtual_links.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};

              // MD delete and classic no reset a leaf to the selected release
              // default. A configured value is parsed into uint16 only after
              // checking the complete decimal representation.
              const bool reset =
                  command.spec->tokens[0].display == "delete" ||
                  has_literal(*command.spec, "no");
              const auto defaults = default_virtual_link(*remote, *transit);
              const auto parsed =
                  decimal<unsigned>(argument_text(command,
                                                  TokenKind::ospf_interval));
              if (!reset &&
                  (!parsed ||
                   *parsed > std::numeric_limits<std::uint16_t>::max()))
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              const auto value = static_cast<std::uint16_t>(
                  reset ? 0U : *parsed);
              if (has_literal(*command.spec, "hello-interval"))
                found->hello_interval_seconds =
                    reset ? defaults.hello_interval_seconds : value;
              else if (has_literal(*command.spec, "dead-interval"))
                found->dead_interval_seconds =
                    reset ? defaults.dead_interval_seconds : value;
              else if (has_literal(*command.spec, "retransmit-interval"))
                found->retransmit_interval_seconds =
                    reset ? defaults.retransmit_interval_seconds : value;
              else
                found->transmit_delay_seconds =
                    reset ? defaults.transmit_delay_seconds : value;
            } else {
              if (found != area->virtual_links.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              area->virtual_links.push_back(
                  default_virtual_link(*remote, *transit));
            }
          } else {
          const bool make_stub =
              id == CommandId::md_ospf_area_stub ||
              id == CommandId::md_ospf3_area_stub ||
              id == CommandId::classic_ospf_area_stub ||
              id == CommandId::classic_ospf3_area_stub;
          const bool make_nssa =
              id == CommandId::md_ospf_area_nssa ||
              id == CommandId::md_ospf3_area_nssa ||
              id == CommandId::classic_ospf_area_nssa ||
              id == CommandId::classic_ospf3_area_nssa;
          const bool make_normal =
              id == CommandId::md_delete_ospf_area_stub ||
              id == CommandId::md_delete_ospf3_area_stub ||
              id == CommandId::md_delete_ospf_area_nssa ||
              id == CommandId::md_delete_ospf3_area_nssa ||
              id == CommandId::classic_ospf_area_no_stub ||
              id == CommandId::classic_ospf3_area_no_stub ||
              id == CommandId::classic_ospf_area_no_nssa ||
              id == CommandId::classic_ospf3_area_no_nssa;
          if (make_stub) {
            area->type = ospf::AreaType::stub;
          } else if (make_nssa) {
            area->type = ospf::AreaType::nssa;
          } else if (make_normal) {
            area->type = ospf::AreaType::normal;
          } else if (id == CommandId::md_ospf_area_summaries ||
                     id == CommandId::md_ospf3_area_summaries) {
            if (!boolean(argument_text(command, TokenKind::boolean),
                         area->summaries))
              return {.recognized = true, .changed = false, .instance = {}};
          } else if (id == CommandId::classic_ospf_area_no_summaries ||
                     id == CommandId::classic_ospf3_area_no_summaries) {
            area->summaries = false;
            if (area->type == ospf::AreaType::stub)
              area->type = ospf::AreaType::totally_stub;
          } else if (id == CommandId::classic_ospf_area_summaries ||
                     id == CommandId::classic_ospf3_area_summaries) {
            area->summaries = true;
            if (area->type == ospf::AreaType::totally_stub)
              area->type = ospf::AreaType::stub;
          } else if (id == CommandId::md_ospf_area_default_metric ||
                     id == CommandId::md_ospf3_area_default_metric ||
                     id == CommandId::classic_ospf_area_default_metric ||
                     id == CommandId::classic_ospf3_area_default_metric) {
            const auto value = decimal<std::uint32_t>(
                argument_text(command, TokenKind::ospf_metric));
            if (!value || *value < 1U ||
                *value > device_catalog::ospf_interface_metric_maximum)
              return {.recognized = true, .changed = false, .instance = {}};
            area->default_metric = *value;
          } else {
            const auto prefix =
                ip::parse_ip_prefix(argument_text(command, TokenKind::ip_prefix));
            const bool requires_ipv4 =
                family == ospf::AddressFamily::ipv4 ||
                family == ospf::AddressFamily::ipv4_over_ospfv3;
            if (!prefix ||
                prefix->network.family !=
                    (requires_ipv4 ? ip::AddressFamily::ipv4
                                   : ip::AddressFamily::ipv6))
              return {.recognized = true, .changed = false, .instance = {}};

            auto range = std::find_if(
                area->ranges.begin(), area->ranges.end(),
                [&](const auto &candidate) {
                  return candidate.prefix == *prefix;
                });
            const bool remove =
                id == CommandId::md_delete_ospf_area_range ||
                id == CommandId::md_delete_ospf3_area_range ||
                id == CommandId::classic_ospf_area_no_range ||
                id == CommandId::classic_ospf3_area_no_range;
            if (remove) {
              if (range == area->ranges.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              area->ranges.erase(range);
            } else {
              const bool advertise =
                  id == CommandId::md_ospf_area_range_advertise ||
                  id == CommandId::md_ospf3_area_range_advertise ||
                  id == CommandId::classic_ospf_area_range_advertise ||
                  id == CommandId::classic_ospf3_area_range_advertise;
              if (range == area->ranges.end()) {
                area->ranges.push_back(
                    {.prefix = *prefix, .advertise = advertise});
              } else {
                range->advertise = advertise;
              }
            }
          }
          }
        } else {
        const bool delete_interface =
            id == CommandId::md_delete_ospf_interface ||
            id == CommandId::md_delete_ospf3_interface ||
            id == CommandId::classic_ospf_no_interface ||
            id == CommandId::classic_ospf3_no_interface;
        auto *interface = find_interface(*area, interface_name);
        if (delete_interface) {
          if (!interface)
            return {.recognized = true, .changed = false, .instance = {}};
          std::erase_if(area->interfaces, [&](const auto &candidate) {
            return candidate.interface_name == interface_name;
          });
        } else {
          if (!interface) {
            area->interfaces.push_back(default_interface(interface_name));
            interface = &area->interfaces.back();
          }
          if (id == CommandId::md_ospf_interface_type ||
              id == CommandId::md_ospf3_interface_type ||
              id == CommandId::classic_ospf_interface_type ||
              id == CommandId::classic_ospf3_interface_type) {
            const auto type = network_type(
                argument_text(command, TokenKind::ospf_interface_type));
            if (!type)
              return {.recognized = true, .changed = false, .instance = {}};
            interface->network_type = *type;
          } else if (id == CommandId::md_ospf_interface_admin_enable ||
                     id == CommandId::md_ospf3_interface_admin_enable) {
            interface->admin_enabled = true;
          } else if (id == CommandId::md_ospf_interface_admin_disable ||
                     id == CommandId::md_ospf3_interface_admin_disable) {
            interface->admin_enabled = false;
          } else if (id == CommandId::md_ospf_interface_metric ||
                     id == CommandId::md_ospf3_interface_metric ||
                     id == CommandId::classic_ospf_interface_metric ||
                     id == CommandId::classic_ospf3_interface_metric) {
            const auto value = decimal<std::uint32_t>(
                argument_text(command, TokenKind::ospf_metric));
            if (!value ||
                *value > device_catalog::ospf_interface_metric_maximum)
              return {.recognized = true, .changed = false, .instance = {}};
            interface->cost = *value;
          } else if (id == CommandId::md_ospf_interface_priority ||
                     id == CommandId::md_ospf3_interface_priority ||
                     id == CommandId::classic_ospf_interface_priority ||
                     id == CommandId::classic_ospf3_interface_priority) {
            const auto value = decimal<unsigned>(
                argument_text(command, TokenKind::ospf_priority));
            if (!value || *value > 255U)
              return {.recognized = true, .changed = false, .instance = {}};
            interface->priority = static_cast<std::uint8_t>(*value);
          } else if (id == CommandId::classic_ospf_interface_passive ||
                     id == CommandId::classic_ospf3_interface_passive) {
            interface->passive = true;
          } else if (id == CommandId::classic_ospf_interface_no_passive ||
                     id == CommandId::classic_ospf3_interface_no_passive) {
            interface->passive = false;
          } else if (id == CommandId::md_ospf_interface_passive ||
                     id == CommandId::md_ospf3_interface_passive) {
            if (!boolean(argument_text(command, TokenKind::boolean),
                         interface->passive))
              return {.recognized = true, .changed = false, .instance = {}};
          } else if (id == CommandId::md_ospf_interface_mtu_ignore ||
                     id == CommandId::md_ospf3_interface_mtu_ignore) {
            if (!boolean(argument_text(command, TokenKind::boolean),
                         interface->mtu_mismatch_ignore))
              return {.recognized = true, .changed = false, .instance = {}};
          } else if (
              id == CommandId::md_ospf_interface_auth_password ||
              id == CommandId::classic_ospf_interface_auth_password) {
            interface->authentication =
                ospf::AuthenticationMode::simple_password;
            interface->keychain.clear();
            interface->ipsec_sa_inbound.clear();
            interface->ipsec_sa_outbound.clear();
          } else if (
              id == CommandId::md_ospf_interface_auth_message_digest ||
              id == CommandId::classic_ospf_interface_auth_message_digest) {
            interface->authentication =
                ospf::AuthenticationMode::message_digest;
            interface->keychain.clear();
            interface->ipsec_sa_inbound.clear();
            interface->ipsec_sa_outbound.clear();
          } else if (
              id == CommandId::md_ospf_interface_authentication_key ||
              id == CommandId::classic_ospf_interface_authentication_key ||
              id == CommandId::md_ospf_interface_message_digest_key ||
              id == CommandId::classic_ospf_interface_message_digest_key) {
            const auto plaintext =
                argument_text(command,
                              TokenKind::ospf_authentication_key);
            if (!secrets || plaintext.empty() ||
                plaintext.size() >
                    (id == CommandId::
                               md_ospf_interface_authentication_key ||
                             id == CommandId::
                               classic_ospf_interface_authentication_key
                         ? 8U
                         : 16U))
              return {.recognized = true,
                      .changed = false,
                      .instance = {}};
            const auto handle = secrets->seal(
                std::span<const std::uint8_t>{
                    reinterpret_cast<const std::uint8_t *>(
                        plaintext.data()),
                    plaintext.size()});
            if (!handle)
              return {.recognized = true,
                      .changed = false,
                      .instance = {}};
            interface->authentication_secret = *handle;
            if (id == CommandId::md_ospf_interface_message_digest_key ||
                id == CommandId::
                          classic_ospf_interface_message_digest_key) {
              const auto key_id = decimal<unsigned>(
                  argument_text(command, TokenKind::ospf_key_id));
              if (!key_id || *key_id > 255U)
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              interface->authentication_key_id =
                  static_cast<std::uint8_t>(*key_id);
            } else {
              interface->authentication_key_id = 0U;
            }
          } else if (
              id == CommandId::md_ospf_interface_auth_keychain ||
              id == CommandId::classic_ospf_interface_auth_keychain) {
            const auto name =
                argument_text(command, TokenKind::ospf_keychain_name);
            if (name.empty() || name.size() > 32U)
              return {.recognized = true,
                      .changed = false,
                      .instance = {}};
            interface->authentication =
                ospf::AuthenticationMode::keychain;
            interface->keychain = name;
            interface->ipsec_sa_inbound.clear();
            interface->ipsec_sa_outbound.clear();
            interface->authentication_secret = 0U;
            interface->authentication_key_id = 0U;
          } else if (
              id == CommandId::md_ospf3_interface_auth_keychain ||
              id == CommandId::classic_ospf3_interface_auth_keychain ||
              id == CommandId::md_ospf3_interface_auth_directional ||
              id == CommandId::classic_ospf3_interface_auth_directional) {
            // SR OS calls the referenced manual IPsec object an SA name. It is
            // not a system keychain and must not be encoded as an RFC 7166
            // Authentication Trailer. The bidirectional syntax assigns one SA
            // to both directions, while the directional syntax retains two
            // independently resolved objects.
            const auto inbound =
                argument_text(command, TokenKind::static_sa_name);
            const auto outbound =
                id == CommandId::md_ospf3_interface_auth_directional ||
                        id == CommandId::
                                  classic_ospf3_interface_auth_directional
                    ? argument_text(
                          command,
                          TokenKind::ospf_ipsec_sa_outbound)
                    : inbound;
            if (inbound.empty() || outbound.empty() ||
                inbound.size() > 32U || outbound.size() > 32U)
              return {.recognized = true,
                      .changed = false,
                      .instance = {}};
            interface->authentication =
                ospf::AuthenticationMode::ipsec_security_association;
            interface->keychain.clear();
            interface->ipsec_sa_inbound = inbound;
            interface->ipsec_sa_outbound = outbound;
            interface->authentication_secret = 0U;
            interface->authentication_key_id = 0U;
          } else if (
              id == CommandId::md_delete_ospf_interface_authentication ||
              id == CommandId::classic_ospf_interface_no_authentication ||
              id ==
                  CommandId::md_delete_ospf3_interface_authentication ||
              id ==
                  CommandId::classic_ospf3_interface_no_authentication) {
            interface->authentication = ospf::AuthenticationMode::none;
            interface->keychain.clear();
            interface->ipsec_sa_inbound.clear();
            interface->ipsec_sa_outbound.clear();
            interface->authentication_secret = 0U;
            interface->authentication_key_id = 0U;
          } else if (
              id == CommandId::md_ospf_interface_neighbor ||
              id == CommandId::md_delete_ospf_interface_neighbor ||
              id == CommandId::md_ospf3_interface_neighbor ||
              id == CommandId::md_delete_ospf3_interface_neighbor ||
              id == CommandId::classic_ospf_interface_neighbor ||
              id == CommandId::classic_ospf_interface_no_neighbor ||
              id == CommandId::classic_ospf3_interface_neighbor ||
              id == CommandId::classic_ospf3_interface_no_neighbor) {
            ip::IpAddress address;
            if (version_three(id)) {
              const auto parsed =
                  ip::parse_ipv6(argument_text(command, TokenKind::ipv6));
              if (!parsed)
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              address.family = ip::AddressFamily::ipv6;
              address.bytes = *parsed;
            } else {
              const auto parsed =
                  ipv4(argument_text(command, TokenKind::ipv4));
              if (!parsed)
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              address.family = ip::AddressFamily::ipv4;
              address.bytes[0U] =
                  static_cast<std::uint8_t>(*parsed >> 24U);
              address.bytes[1U] =
                  static_cast<std::uint8_t>(*parsed >> 16U);
              address.bytes[2U] =
                  static_cast<std::uint8_t>(*parsed >> 8U);
              address.bytes[3U] =
                  static_cast<std::uint8_t>(*parsed);
            }
            const auto found = std::find_if(
                interface->nbma_neighbors.begin(),
                interface->nbma_neighbors.end(),
                [&](const auto &neighbor) {
                  return neighbor.address == address;
                });
            const bool remove =
                id == CommandId::md_delete_ospf_interface_neighbor ||
                id == CommandId::md_delete_ospf3_interface_neighbor ||
                id == CommandId::classic_ospf_interface_no_neighbor ||
                id == CommandId::classic_ospf3_interface_no_neighbor;
            if (remove) {
              if (found == interface->nbma_neighbors.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              interface->nbma_neighbors.erase(found);
            } else {
              if (found != interface->nbma_neighbors.end())
                return {.recognized = true,
                        .changed = false,
                        .instance = {}};
              // SR OS exposes the peer as an address-only list key. Its
              // documented interface PollInterval default supplies the
              // transport retry timer; configured NBMA peers are eligible
              // discovery targets until their received Hello says otherwise.
              interface->nbma_neighbors.push_back(
                  {.address = address,
                   .priority = device_catalog::ospf_interface_priority,
                   .poll_interval_seconds =
                       static_cast<std::uint16_t>(
                           device_catalog::ospf_poll_interval.count())});
            }
          } else {
            const auto value = decimal<unsigned>(
                argument_text(command, TokenKind::ospf_interval));
            if (!value ||
                *value > std::numeric_limits<std::uint16_t>::max())
              return {.recognized = true, .changed = false, .instance = {}};
            auto *target =
                id == CommandId::md_ospf_interface_hello ||
                        id == CommandId::md_ospf3_interface_hello
                    ? &interface->hello_interval_seconds
                : id == CommandId::md_ospf_interface_dead ||
                          id == CommandId::md_ospf3_interface_dead
                    ? &interface->dead_interval_seconds
                : id == CommandId::md_ospf_interface_retransmit ||
                          id == CommandId::md_ospf3_interface_retransmit
                    ? &interface->retransmit_interval_seconds
                    : &interface->transmit_delay_seconds;
            *target = static_cast<std::uint16_t>(*value);
          }
        }
        }
      }
    }
  }

  if (ospf::validate(next, true) != ospf::ConfigurationStatus::valid)
    return {.recognized = true, .changed = false, .instance = {}};
  if (next == configuration)
    return {.recognized = true, .valid = true, .changed = false,
            .instance = std::to_string(instance_id)};
  configuration = std::move(next);
  return {.recognized = true,
          .valid = true,
          .changed = true,
          .instance = std::to_string(instance_id)};
}

} // namespace router::lab::ospf_cli
