// Token parser and context completion for the generated SR OS CLI schema.
// Source: nokia.sros.26_7.md_cli.command_completion

#include "cli_parser.hpp"

#include "router/mld_import_policy.hpp"

#include "router/generated_device_catalog.hpp"
#include "router/generated_profile.hpp"
#include "router/ies_service.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace router::cli_detail {
namespace {

struct TokenizedLine {
  // The schema generator publishes the largest legal command width. Keeping
  // token views in a fixed array makes parsing allocation-free and places an
  // explicit upper bound on work for malformed terminal input.
  std::array<std::string_view, cli_schema::maximum_tokens> tokens{};
  std::uint8_t count{};
  bool trailing_space{};
  bool valid{true};
};

struct Candidate {
  // Placeholders are useful in help output but cannot replace user input.
  // Keeping that distinction beside the text avoids guessing from angle
  // brackets in the presentation layer.
  std::string value;
  std::string description;
  bool completable{};
  bool keyword{};
  bool context{};
};

constexpr bool ascii_space(char value) noexcept {
  // SR OS command grammar is byte-oriented here. Locale-dependent whitespace
  // would make the native and WebAssembly builds tokenize differently.
  return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::string_view trim_view(std::string_view value) noexcept {
  // Views retain ownership in the terminal command for the whole synchronous
  // parse. No token is copied unless it becomes completion output.
  while (!value.empty() && ascii_space(value.front()))
    value.remove_prefix(1);
  while (!value.empty() && ascii_space(value.back()))
    value.remove_suffix(1);
  return value;
}

TokenizedLine tokenize(std::string_view input, bool completion) {
  // Completion deliberately accepts an open quote. Execution does not. This
  // permits contextual help while a description is being typed without ever
  // treating incomplete text as a valid configuration value.
  TokenizedLine result;
  result.trailing_space = !input.empty() && ascii_space(input.back());
  std::size_t cursor{};
  while (cursor < input.size()) {
    while (cursor < input.size() && ascii_space(input[cursor]))
      ++cursor;
    if (cursor == input.size())
      break;
    if (result.count == result.tokens.size()) {
      result.valid = false;
      return result;
    }

    const auto begin = cursor;
    if (input[cursor] == '"') {
      ++cursor;
      while (cursor < input.size() && input[cursor] != '"')
        ++cursor;
      if (cursor == input.size()) {
        // An unfinished quote is useful while completing but is never an
        // executable token. No temporary string or escape rewriting is used.
        result.valid = completion;
      } else {
        ++cursor;
      }
      if (!result.valid)
        return result;
    } else {
      while (cursor < input.size() && !ascii_space(input[cursor]))
        ++cursor;
    }
    result.tokens[result.count++] = input.substr(begin, cursor - begin);
    if (cursor < input.size() && !ascii_space(input[cursor])) {
      result.valid = false;
      return result;
    }
  }
  return result;
}

constexpr std::uint8_t engine_mask(CliEngine engine) noexcept {
  // Engine availability comes from the generated release schema. A compact
  // bit mask keeps the hot schema scan branch-only and avoids dynamic sets.
  return engine == CliEngine::md ? 1U : 2U;
}

bool available(const cli_schema::CommandSpec &spec,
               const CliSession &session) noexcept {
  if (!(spec.engine_mask & engine_mask(session.engine)))
    return false;
  if (session.engine != CliEngine::md)
    return true;
  const bool configuring = session.md_workflow != MdCliWorkflow::operational;
  if (spec.configuration_command)
    return configuring;
  const auto is_implicit_entry = [](cli_schema::CommandId id) {
    using enum cli_schema::CommandId;
    return id == md_configure_exclusive || id == md_configure_global ||
           id == md_configure_private || id == md_configure_read_only;
  };
  if (is_implicit_entry(spec.id))
    return !configuring;
  using enum cli_schema::CommandId;
  if (spec.id == md_edit_config_exclusive || spec.id == md_edit_config_global ||
      spec.id == md_edit_config_private ||
      spec.id == md_edit_config_read_only) {
    if (!configuring)
      return true;
    // Private candidate identity cannot transition. Exclusive, global and
    // read-only share the global candidate and Nokia permits transitions among
    // them, including an implicit session becoming explicit at the same time.
    if (session.md_workflow == MdCliWorkflow::implicit_private ||
        session.md_workflow == MdCliWorkflow::explicit_private)
      return spec.id == md_edit_config_private;
    return spec.id != md_edit_config_private;
  }
  if (spec.id == cli_schema::CommandId::md_quit_config)
    return session.md_workflow == MdCliWorkflow::explicit_exclusive ||
           session.md_workflow == MdCliWorkflow::explicit_global ||
           session.md_workflow == MdCliWorkflow::explicit_private ||
           session.md_workflow == MdCliWorkflow::explicit_read_only;
  return true;
}

bool accepts(const cli_schema::TokenSpec &token, std::string_view value) {
  // Both SR OS engines accept an unambiguous keyword abbreviation. Quoted list
  // keys and symbolic commands are values rather than abbreviable keywords.
  // Ambiguity is rejected after all complete schema rows have been scanned.
  if (token.kind != cli_schema::TokenKind::literal) {
    if (value.empty())
      return false;
    using enum cli_schema::TokenKind;
    const auto decimal_text = [](std::string_view text) {
      return !text.empty() &&
             std::all_of(text.begin(), text.end(),
                         [](char byte) { return byte >= '0' && byte <= '9'; });
    };
    const auto unquote_value = [](std::string_view text) {
      return text.size() >= 2U && text.front() == '"' && text.back() == '"'
                 ? text.substr(1U, text.size() - 2U)
                 : std::string_view{};
    };
    const auto scalar_text = [&](std::string_view text) {
      const auto unquoted = unquote_value(text);
      return unquoted.empty() ? text : unquoted;
    };
    const auto bounded_name = [&](std::string_view text, std::size_t maximum) {
      text = scalar_text(text);
      return !text.empty() && text.size() <= maximum &&
             std::any_of(text.begin(), text.end(),
                         [](char byte) { return byte != ' ' && byte != '\t'; });
    };
    const auto generated_algorithm = [&](const auto &algorithms) {
      return std::any_of(
          algorithms.begin(), algorithms.end(),
          [&](const auto &entry) { return entry.sros == value; });
    };
    const auto ipv4_text = [&](std::string_view text) {
      std::uint32_t octet{};
      std::size_t count{};
      bool digit{};
      for (const auto byte : text) {
        if (byte == '.') {
          if (!digit || octet > 255U || ++count > 3U)
            return false;
          octet = 0;
          digit = false;
        } else if (byte >= '0' && byte <= '9') {
          digit = true;
          octet = octet * 10U + static_cast<unsigned>(byte - '0');
          if (octet > 255U)
            return false;
        } else {
          return false;
        }
      }
      return digit && octet <= 255U && count == 3U;
    };
    const auto ipv4_prefix_text = [&](std::string_view text) {
      const auto slash = text.find('/');
      if (slash == std::string_view::npos ||
          !ipv4_text(text.substr(0, slash)) ||
          !decimal_text(text.substr(slash + 1U)))
        return false;
      unsigned length{};
      for (const auto byte : text.substr(slash + 1U))
        length = length * 10U + static_cast<unsigned>(byte - '0');
      return length <= 32U;
    };
    switch (token.kind) {
    case ipv4:
      return ipv4_text(value);
    case ipv4_key:
      // A typed YANG list key keeps key identity without becoming a quoted
      // string. SR OS accepts the canonical dotted address directly; retaining
      // scalar_text also permits explicit quoting where the generic MD lexer
      // allows it, while help and rendered configuration use the typed form.
      return ipv4_text(scalar_text(value));
    case ipv4_prefix:
      return ipv4_prefix_text(value);
    case ip_prefix:
      return ipv4_prefix_text(value) ||
             ip::parse_ipv6_prefix(value).has_value();
    case ip_address:
      return ipv4_text(value) || ip::parse_ipv6(value).has_value();
    case ipsec_protocol_id: {
      if (value == "icmp" || value == "tcp" || value == "udp" ||
          value == "icmp6" || value == "sctp" || value == "mipv6")
        return true;
      if (!decimal_text(value))
        return false;
      unsigned protocol{};
      for (const auto byte : value)
        protocol = protocol * 10U + static_cast<unsigned>(byte - '0');
      return protocol >= 1U && protocol <= 255U;
    }
    case selector_port_begin:
    case selector_port_end: {
      // Classic represents ICMP as type/code but TCP, UDP, SCTP and MIPv6 as
      // one decimal value. Cross-field protocol limits are checked by the
      // IPsec editor after the generated grammar has matched the command.
      const auto slash = value.find('/');
      const auto component = [&](std::string_view text, unsigned maximum) {
        if (!decimal_text(text))
          return false;
        unsigned parsed{};
        for (const auto byte : text)
          parsed = parsed * 10U + static_cast<unsigned>(byte - '0');
        return parsed <= maximum;
      };
      return slash == std::string_view::npos
                 ? component(value, 65'535U)
                 : component(value.substr(0U, slash), 255U) &&
                       component(value.substr(slash + 1U), 255U);
    }
    case ipv6:
    case ipv6_source:
    case ipv6_range_start:
    case ipv6_range_end:
    case ipv6_range_step:
      return ip::parse_ipv6(value).has_value();
    case ipv6_with_zone: {
      // SR OS renders a scoped server as address-interface. IPv6 syntax never
      // contains a hyphen, so the first hyphen is an unambiguous zone boundary
      // even when the interface name itself contains later hyphens.
      const auto separator = value.find('-');
      const auto address_text = value.substr(0U, separator);
      const auto address = ip::parse_ipv6(address_text);
      if (!address)
        return false;
      const bool has_zone = separator != std::string_view::npos;
      const auto zone =
          has_zone ? value.substr(separator + 1U) : std::string_view{};
      return ip::is_link_local(*address)
                 ? has_zone && bounded_name(
                                   zone, service::maximum_interface_name_octets)
                 : !has_zone;
    }
    case ipv6_key:
      // IPv6 static-route next hops follow the same typed-key rule as IPv4.
      // Reusing the scalar normalizer prevents the two address families from
      // diverging only because the schema node is keyed.
      return ip::parse_ipv6(scalar_text(value)).has_value();
    case ipv6_prefix:
      return ip::parse_ipv6_prefix(value).has_value();
    case ipv6_address_prefix: {
      const auto slash = value.rfind('/');
      if (slash == std::string_view::npos ||
          !ip::parse_ipv6(value.substr(0, slash)) ||
          !decimal_text(value.substr(slash + 1U)))
        return false;
      unsigned length{};
      for (const auto byte : value.substr(slash + 1U))
        length = length * 10U + static_cast<unsigned>(byte - '0');
      return length >= 1U && length <= ip::ipv6_address_bits;
    }
    case customer_name:
    case service_name:
      return bounded_name(value, service::maximum_service_name_octets);
    case service_interface_name:
      return bounded_name(value, service::maximum_interface_name_octets);
    case relay_interface_id_string:
      return bounded_name(value, service::maximum_relay_interface_id_octets);
    case ethernet_mode:
      return value == "access" || value == "network" || value == "hybrid";
    case ethernet_encapsulation:
      return value == "null" || value == "dot1q" || value == "qinq";
    case policy_name:
    case prefix_list_name:
      return bounded_name(value, mld::maximum_policy_name_octets);
    case policy_entry_number:
      return decimal_text(value) && value != "0";
    case policy_action:
      return value == "accept" || value == "drop" || value == "reject" ||
             value == "next-entry" || value == "next-policy";
    case sap_id:
      // Exact coordinate, VLAN and live inventory checks belong to the IES
      // editor because the release grammar alone cannot resolve a port.
      return !value.empty() && value.size() <= 45U;
    case prefix_length:
    case ipv6_prefix_length:
    case ipv6_primary_preference:
    case ipv6_address_tag:
    case customer_id:
    case service_id:
    case relay_lease_limit:
    case count:
    case size:
    case mtu:
    case levels:
    case seconds:
    case milliseconds:
    case hop_limit:
    case mld_version:
    case robust_count:
    case mld_limit:
    case ike_policy_id:
    case ike_transform_id:
    case ike_transform_ref:
    case ipsec_transform_id:
    case ipsec_lifetime:
    case ike_lifetime:
    case ike_fragment_mtu:
    case ike_reassembly_timeout:
    case dpd_interval:
    case dpd_retries:
    case nat_keepalive_interval:
    case ts_entry_id:
    case protocol_id:
    case port_begin:
    case port_end:
    case icmp_type_begin:
    case icmp_type_end:
    case icmp_code_begin:
    case icmp_code_end:
    case tunnel_template_id:
    case replay_window:
    case pmtu_aging:
    case tunnel_mss:
    case tunnel_rate_interval:
    case tunnel_message_count:
    case reverse_route_metric:
    case reverse_route_preference:
    case ipsec_certificate_entry_id:
    case history_esp_records:
    case history_ike_records:
    case bof_timeout_seconds:
      return decimal_text(value);
    case bof_client_id: {
      // The BOF model accepts either a quoted character string or an opaque
      // hexadecimal spelling. Family-specific limits differ, so the grammar
      // only enforces the largest transport envelope and leaves the exact
      // IPv4 or IPv6 contract to the BOF configuration owner.
      const auto identifier = scalar_text(value);
      return !identifier.empty() && identifier.size() <= 256U;
    }
    case static_sa_spi: {
      // RFC 4303 reserves ESP SPI values 0 through 255. SR OS further caps a
      // manually configured SPI at 16383, so accepting a wider decimal here
      // would make the generated grammar advertise a value the configuration
      // owner must subsequently reject.
      if (!decimal_text(value))
        return false;
      unsigned spi{};
      for (const auto byte : value)
        spi = spi * 10U + static_cast<unsigned>(byte - '0');
      return spi >= 256U && spi <= 16'383U;
    }
    case tls_certificate_entry_index:
    case tls_algorithm_index: {
      if (!decimal_text(value))
        return false;
      unsigned index{};
      for (const auto byte : value)
        index = index * 10U + static_cast<unsigned>(byte - '0');
      if (token.kind == tls_certificate_entry_index)
        return index >= 1U &&
               index <= device_catalog::tls_maximum_cert_entries_per_profile;
      return index >= device_catalog::tls_algorithm_index_minimum &&
             index <= device_catalog::tls_algorithm_index_maximum;
    }
    case tls_cipher_name:
      return generated_algorithm(device_catalog::tls13_ciphers);
    case tls_group_name:
      return generated_algorithm(device_catalog::tls13_groups);
    case tls_signature_name:
      return generated_algorithm(device_catalog::tls13_signatures);
    case tls_certificate_file:
    case tls_key_file: {
      const auto file = scalar_text(value);
      return !file.empty() &&
             file.size() <= device_catalog::tls_certificate_file_name_bytes &&
             file.find_first_of(":/") == std::string_view::npos;
    }
    case pki_file_name: {
      const auto file = scalar_text(value);
      return !file.empty() && file.size() <= 95U &&
             file.find_first_of(":/") == std::string_view::npos;
    }
    case tls_cert_profile_name:
    case tls_trust_anchor_profile_name:
    case tls_client_cipher_list_name:
    case tls_client_group_list_name:
    case tls_client_signature_list_name:
    case tls_client_profile_name:
    case tls_server_cipher_list_name:
    case tls_server_group_list_name:
    case tls_server_signature_list_name:
    case tls_server_profile_name:
    case tls_ca_profile_name:
    case tls_common_name_list_name:
      return bounded_name(value, device_catalog::tls_profile_name_bytes);
    case ts_list_name:
    case transport_profile_name:
    case ipsec_cert_profile_name:
    case ipsec_trust_anchor_profile_name:
    case ppk_list_name:
    case ca_profile_name:
      // Both SR OS list keys have their own documented 1..32 contract. Keep
      // them independent from TLS catalog constants even though the current
      // maximum happens to be equal.
      return bounded_name(value, 32U);
    case static_sa_name:
    case ospf_ipsec_sa_outbound:
      // A static-SA name is a list key, not an arbitrary description. Nokia's
      // 26.7 model permits 1..32 characters and the editor performs the same
      // check before materializing the candidate list entry.
      return bounded_name(value, 32U);
    case static_sa_key: {
      // The grammar deliberately treats the key as an opaque scalar. Clear
      // ASCII, hexadecimal and imported protected spellings have different
      // semantic checks in the IPsec owner, while all share the MD encrypted
      // leaf's documented 1..110 character transport envelope.
      const auto secret = scalar_text(value);
      return !secret.empty() && secret.size() <= 110U;
    }
    case ppk_id:
      return bounded_name(value, 64U);
    case alarm_count:
    case alarm_newer_than_days:
      return decimal_text(value) && value != "0";
    case alarm_severity:
      return value == "critical" || value == "major" || value == "minor" ||
             value == "warning";
    case dhcp_lease_state:
      return value == "offered" || value == "stable" ||
             value == "force-renew-pending" || value == "remove-pending" ||
             value == "held" || value == "internal" ||
             value == "internal-orphan" || value == "internal-offered" ||
             value == "internal-held" || value == "sticky";
    case dhcpv6_lease_state:
      return value == "advertised" || value == "stable" ||
             value == "remove-pending" || value == "held" ||
             value == "internal" || value == "internal-orphan" ||
             value == "internal-offered" || value == "internal-held";
    case dhcpv6_lease_type:
      return value == "pd" || value == "slaac" || value == "wan" ||
             value == "wan-host";
    case ppk_ascii_value:
    case ipsec_pre_shared_key: {
      // SR OS encrypted-leaf text may be clear input or an opaque protected
      // spelling ending in hash, hash2, hash3 or custom. The parser enforces
      // the documented wire-independent 1..166 character envelope. The secret
      // owner decides whether a protected spelling can be imported by this
      // release and never mistakes it for clear key bytes.
      const auto secret = scalar_text(value);
      return !secret.empty() && secret.size() <= 166U;
    }
    case ppk_hex_value: {
      const auto secret = scalar_text(value);
      if (secret.empty() || secret.size() > 166U)
        return false;
      const auto suffix = [](std::string_view text) {
        return text.ends_with(" hash") || text.ends_with(" hash2") ||
               text.ends_with(" hash3") || text.ends_with(" custom");
      };
      if (suffix(secret))
        return true;
      const auto digits = secret.starts_with("0x") ? secret.substr(2U) : secret;
      return !digits.empty() && digits.size() <= 128U &&
             digits.size() % 2U == 0U &&
             std::all_of(digits.begin(), digits.end(), [](char byte) {
               return (byte >= '0' && byte <= '9') ||
                      (byte >= 'a' && byte <= 'f') ||
                      (byte >= 'A' && byte <= 'F');
             });
    }
    case ike_identity_fqdn:
      return bounded_name(value, 255U);
    case boolean:
      return value == "true" || value == "false";
    case router_preference:
      return value == "low" || value == "medium" || value == "high";
    case literal:
      break;
    default:
      // Names, descriptions and hardware identifiers are validated by their
      // state owner because validity depends on live inventory and quoting.
      return true;
    }
  }
  if (token.display.starts_with('"') || token.display == "//")
    return value == token.display;
  return !value.empty() && token.display.starts_with(value);
}

const DeviceConfiguration &active_configuration(const DeviceState &state,
                                                CliEngine engine) noexcept {
  // MD completion follows candidate state because newly provisioned parents
  // must expose their children before commit. Classic completion follows the
  // running datastore because every accepted change is immediate.
  return engine == CliEngine::md ? state.configuration.candidate
                                 : state.configuration.running;
}

void add_candidate(std::vector<Candidate> &items, std::string value,
                   bool completable, bool keyword, std::string_view partial,
                   std::string_view description, bool context) {
  // Several schema rows can share the same next token. Deduplication is done
  // before sorting so help never repeats a keyword for each descendant row.
  if (!std::string_view(value).starts_with(partial))
    return;
  const auto duplicate =
      std::find_if(items.begin(), items.end(), [&value](const Candidate &item) {
        return item.value == value;
      });
  if (duplicate == items.end()) {
    items.push_back({std::move(value), std::string{description}, completable,
                     keyword, context});
  } else {
    // A token shared by a leaf and a branch is shown as a branch. This mirrors
    // the SR OS '+' marker and prevents generated schema order from choosing
    // presentation semantics.
    duplicate->context = duplicate->context || context;
  }
}

void parameter_candidates(const DeviceState &state, CliEngine engine,
                          const cli_schema::TokenSpec &token,
                          std::string_view partial,
                          std::vector<Candidate> &items, bool context) {
  using enum cli_schema::TokenKind;
  // Syntax is release data, while concrete identifiers come from the current
  // device model. This is the boundary that prevents canned demo commands from
  // appearing as terminal completion.
  const auto &configuration = active_configuration(state, engine);
  switch (token.kind) {
  case literal:
    add_candidate(items, std::string{token.display}, true, true, partial,
                  token.description, context);
    break;
  case card_slot:
    add_candidate(items, std::to_string(profile::line_card_slot), true, false,
                  partial, token.description, context);
    break;
  case mda_slot:
    add_candidate(items, std::to_string(profile::mda_slot), true, false,
                  partial, token.description, context);
    break;
  case card_type:
    add_candidate(items, profile::line_card_type, true, false, partial,
                  token.description, context);
    break;
  case mda_type:
    add_candidate(items, profile::modeled_mda_type, true, false, partial,
                  token.description, context);
    break;
  case port_id:
    // SR OS permits port configuration after the MDA type is provisioned even
    // if the physical module is absent. Equipment controls operational state,
    // while the configured parent controls whether port nodes exist in CLI.
    for (std::size_t index = 0;
         index < (profile_mda(configuration).type ? profile::port_count : 0U);
         ++index)
      add_candidate(items, profile::port_ids[index], true, false, partial,
                    token.description, context);
    break;
  case interface_name:
    // The placeholder documents the parameter shape. Only existing interface
    // names are marked as safe replacements for the editable command line.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    for (std::size_t index = 0; index < configuration.interface_count;
         ++index) {
      if (configuration.interfaces[index].valid)
        add_candidate(items, configuration.interfaces[index].name, true, false,
                      partial, token.description, context);
    }
    break;
  case ipv4:
    // An IP address is an unconstrained scalar, not a reference into the lab
    // topology. Exposing project host addresses here would leak UI knowledge
    // into router help and incorrectly imply that other destinations are not
    // valid.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case ipv4_key:
    // A new static next-hop key is also arbitrary. Existing project endpoints
    // are not router configuration objects and therefore are never completion
    // candidates.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case ipv4_prefix:
  case ip_address:
  case ipv6:
  case ipv6_with_zone:
  case ipv6_source:
  case ipv6_range_start:
  case ipv6_range_end:
  case ipv6_range_step:
  case ipv6_key:
  case ipv6_prefix:
  case ipv6_address_prefix:
  case ipv6_primary_preference:
  case ipv6_address_tag:
  case customer_name:
  case customer_id:
  case service_name:
  case service_id:
  case service_interface_name:
  case sap_id:
  case ethernet_mode:
  case ethernet_encapsulation:
  case ipv6_prefix_length:
  case relay_interface_id_string:
  case relay_lease_limit:
  case mac_address:
  case nd_scope:
  case nd_reachable_seconds:
  case nd_stale_seconds:
  case nd_neighbor_limit:
  case nd_threshold:
  case prefix_length:
  case arp_timeout_seconds:
  case arp_retry_deciseconds:
  case ecmp_paths:
  case global_if_index:
  case count:
  case alarm_count:
  case alarm_newer_than_days:
  case alarm_severity:
  case size:
  case mtu:
  case levels:
  case system_name:
  case description:
  case dhcp_server_name:
  case dhcp_pool_name:
  case dhcp_lease_seconds:
  case dhcp_offer_seconds:
  case dhcp_maximum_declined:
  case dhcp_lease_state:
  case dhcpv6_lease_state:
  case dhcpv6_lease_type:
  case dhcpv6_lifetime_seconds:
  case dhcpv6_timer_seconds:
  case dhcpv6_delegated_length:
  case dhcp_remote_id_ascii:
  case bof_client_id:
  case bof_timeout_seconds:
  case seconds:
  case milliseconds:
  case hop_limit:
  case boolean:
  case router_preference:
  case mld_version:
  case robust_count:
  case mld_limit:
  case policy_name:
  case prefix_list_name:
  case policy_entry_number:
  case policy_action:
  case redirect_number:
  case redirect_seconds:
  case ike_policy_id:
  case ike_transform_id:
  case ike_transform_ref:
  case ipsec_transform_id:
  case ipsec_lifetime:
  case ike_lifetime:
  case ike_fragment_mtu:
  case ike_reassembly_timeout:
  case dpd_interval:
  case dpd_retries:
  case nat_keepalive_interval:
  case ts_list_name:
  case ts_entry_id:
  case ip_prefix:
  case protocol_id:
  case selector_port_begin:
  case selector_port_end:
  case port_begin:
  case port_end:
  case icmp_type_begin:
  case icmp_type_end:
  case icmp_code_begin:
  case icmp_code_end:
  case tunnel_template_id:
  case transport_profile_name:
  case replay_window:
  case pmtu_aging:
  case ppk_list_name:
  case ppk_id:
  case ppk_ascii_value:
  case ppk_hex_value:
  case static_sa_name:
  case ospf_ipsec_sa_outbound:
  case static_sa_key:
  case static_sa_spi:
  case ospf_instance:
  case ospf_area_id:
  case ospf_transit_area_id:
  case ospf_domain_id:
  case policy_route_tag:
  case ospf_metric_type:
  case ospf_metric:
  case ospf_priority:
  case ospf_interval:
  case ospf_timer_milliseconds:
  case ospf_reference_bandwidth:
  case ospf_preference:
  case ospf_authentication_key:
  case ospf_key_id:
  case ospf_keychain_name:
  case ospf_keychain_time:
  case ospf_tolerance:
  case ipsec_pre_shared_key:
  case tunnel_mss:
  case tunnel_rate_interval:
  case tunnel_message_count:
  case reverse_route_metric:
  case reverse_route_preference:
  case ipsec_cert_profile_name:
  case ipsec_trust_anchor_profile_name:
  case ipsec_certificate_entry_id:
  case pki_file_name:
  case ca_profile_name:
  case ike_identity_fqdn:
  case history_esp_records:
  case history_ike_records:
  case tls_cert_profile_name:
  case tls_trust_anchor_profile_name:
  case tls_client_cipher_list_name:
  case tls_client_group_list_name:
  case tls_client_signature_list_name:
  case tls_client_profile_name:
  case tls_server_cipher_list_name:
  case tls_server_group_list_name:
  case tls_server_signature_list_name:
  case tls_server_profile_name:
  case tls_ca_profile_name:
  case tls_certificate_file:
  case tls_key_file:
  case tls_certificate_entry_index:
  case tls_algorithm_index:
  case tls_common_name_list_name:
    // Redirect rate leaves are user supplied scalars. Their release-specific
    // numeric ranges are enforced by the command handler because completion
    // must not manufacture a preferred rate value that SR OS does not suggest.
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case ospf_interface_type:
    // The network type is a closed SR OS enumeration. Supplying the four real
    // values makes Tab and question-mark help useful without teaching the
    // parser any command path or runtime behavior.
    for (const auto value : {"point-to-point", "broadcast", "non-broadcast",
                             "point-to-multipoint"})
      add_candidate(items, value, true, false, partial, token.description,
                    context);
    break;
  case ipsec_protocol_id:
    // Classic accepts either the documented names or a decimal protocol ID.
    // Named values are real completion candidates while the numeric shape is
    // shown only as a placeholder, matching SR OS context help semantics.
    for (const auto name : {"icmp", "tcp", "udp", "icmp6", "sctp", "mipv6"})
      add_candidate(items, name, true, false, partial, token.description,
                    context);
    add_candidate(items, std::string{token.display}, false, false, partial,
                  token.description, context);
    break;
  case tls_cipher_name:
    for (const auto &algorithm : device_catalog::tls13_ciphers)
      add_candidate(items, std::string{algorithm.sros}, true, false, partial,
                    token.description, context);
    break;
  case tls_group_name:
    for (const auto &algorithm : device_catalog::tls13_groups)
      add_candidate(items, std::string{algorithm.sros}, true, false, partial,
                    token.description, context);
    break;
  case tls_signature_name:
    for (const auto &algorithm : device_catalog::tls13_signatures)
      add_candidate(items, std::string{algorithm.sros}, true, false, partial,
                    token.description, context);
    break;
  }
}

} // namespace

std::optional<ParsedCommand> parse_command(const DeviceState &,
                                           const CliSession &session,
                                           std::string_view input) {
  return parse_command(session.engine, session.md_workflow, input);
}

std::optional<ParsedCommand> parse_command(CliEngine engine,
                                           MdCliWorkflow workflow,
                                           std::string_view input) {
  CliSession session;
  session.engine = engine;
  session.md_workflow = workflow;
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return std::nullopt;
  // Generated rows are the sole syntax catalog. Handlers receive a stable ID
  // only after every literal and parameter position has matched that catalog.
  const cli_schema::CommandSpec *match{};
  std::uint8_t match_literal_count{};
  std::uint8_t match_exact_literal_count{};
  std::uint8_t match_address_parameter_count{};
  bool ambiguous_at_best_specificity{};
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || spec.token_count != line.count)
      continue;
    bool matched = true;
    for (std::size_t index = 0; index < line.count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        matched = false;
        break;
      }
    }
    if (!matched)
      continue;

    // A reserved keyword is more specific than a value accepted in the same
    // position. For example, `show router neighbor static` is the documented
    // filter, not an interface literally named "static". Literal count is the
    // primary rank. An exact keyword then outranks a longer keyword for which
    // the same input is merely an abbreviation. This is essential for sibling
    // commands such as `icmp` and `icmp6`: the documented complete keyword
    // `icmp` cannot become ambiguous just because another keyword begins with
    // those bytes. Constrained address types break the remaining tie against
    // generic list keys. Rows equal on every rank remain genuinely ambiguous,
    // so schema order can never choose one silently.
    const auto literal_count = static_cast<std::uint8_t>(std::count_if(
        spec.tokens.begin(), spec.tokens.begin() + spec.token_count,
        [](const auto &token) {
          return token.kind == cli_schema::TokenKind::literal;
        }));
    const auto exact_literal_count = static_cast<std::uint8_t>(std::count_if(
        spec.tokens.begin(), spec.tokens.begin() + spec.token_count,
        [&](const auto &token) {
          const auto index =
              static_cast<std::size_t>(&token - spec.tokens.data());
          return token.kind == cli_schema::TokenKind::literal &&
                 token.display == line.tokens[index];
        }));
    const auto address_parameter_count =
        static_cast<std::uint8_t>(std::count_if(
            spec.tokens.begin(), spec.tokens.begin() + spec.token_count,
            [](const auto &token) {
              // A validated network scalar is narrower than a free-form list
              // key. For a documented union such as `{ip-int-name |
              // ip-address}`, dotted input therefore selects the address arm
              // even though the same bytes could also form a legal name. This
              // is a token-level grammar rule shared by every command.
              using enum cli_schema::TokenKind;
              switch (token.kind) {
              case ipv4:
              case ipv4_key:
              case ipv4_prefix:
              case ipv6:
              case ipv6_with_zone:
              case ipv6_key:
              case ipv6_prefix:
              case ipv6_address_prefix:
              case ip_address:
              case ip_prefix:
              case mac_address:
                return true;
              default:
                return false;
              }
            }));
    if (!match || literal_count > match_literal_count ||
        (literal_count == match_literal_count &&
         exact_literal_count > match_exact_literal_count) ||
        (literal_count == match_literal_count &&
         exact_literal_count == match_exact_literal_count &&
         address_parameter_count > match_address_parameter_count)) {
      match = &spec;
      match_literal_count = literal_count;
      match_exact_literal_count = exact_literal_count;
      match_address_parameter_count = address_parameter_count;
      ambiguous_at_best_specificity = false;
    } else if (literal_count == match_literal_count &&
               exact_literal_count == match_exact_literal_count &&
               address_parameter_count == match_address_parameter_count) {
      ambiguous_at_best_specificity = true;
    }
  }
  return match && !ambiguous_at_best_specificity
             ? std::optional{ParsedCommand{match, line.tokens, line.count}}
             : std::nullopt;
}

std::optional<CommandFailure>
diagnose_command_failure(CliEngine engine, MdCliWorkflow workflow,
                         std::string_view input) {
  CliSession session;
  session.engine = engine;
  session.md_workflow = workflow;
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return std::nullopt;

  // Diagnostics consume the same generated rows and token validators as
  // execution. A second hand-written command tree would inevitably drift and
  // could again blame the first relative keyword for a bad value much deeper
  // in the current context.
  std::size_t deepest{};
  bool parameter_expected{};
  bool candidate_reached{};
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session))
      continue;
    std::size_t matched{};
    const auto comparable =
        std::min<std::size_t>(line.count, spec.token_count);
    while (matched < comparable &&
           accepts(spec.tokens[matched], line.tokens[matched]))
      ++matched;

    if (!candidate_reached || matched > deepest) {
      deepest = matched;
      candidate_reached = true;
      parameter_expected =
          matched < spec.token_count &&
          spec.tokens[matched].kind != cli_schema::TokenKind::literal;
    } else if (matched == deepest && matched < spec.token_count) {
      // A typed branch at the deepest matching context means the operator
      // supplied an invalid value. Literal siblings cannot turn that scalar
      // into an unknown top-level command.
      parameter_expected =
          parameter_expected ||
          spec.tokens[matched].kind != cli_schema::TokenKind::literal;
    }
  }
  if (!candidate_reached)
    return std::nullopt;

  const auto failing = std::min<std::size_t>(deepest, line.count - 1U);
  return CommandFailure{
      parameter_expected ? CommandFailureKind::invalid_element_value
                         : CommandFailureKind::unknown_element,
      std::string{line.tokens[failing]}};
}

std::optional<std::string_view> argument(const ParsedCommand &command,
                                         cli_schema::TokenKind kind) noexcept {
  // Each current command uses a parameter kind at most once. Looking up by
  // kind keeps execution independent from token offsets in release schemas.
  for (std::size_t index = 0; index < command.token_count; ++index) {
    if (command.spec->tokens[index].kind == kind)
      return command.tokens[index];
  }
  return std::nullopt;
}

std::string complete_command(const DeviceState &state,
                             const CliSession &session, std::string_view raw,
                             CliCompletionTrigger trigger) {
  const auto engine = session.engine;
  // Completion must preserve the final separator. In SR OS, `ping<Space>` asks
  // for the next token, while `ping` still names the current partial token.
  // Execution may trim both ends, but doing so here changes completion level.
  auto input = raw;
  while (!input.empty() && ascii_space(input.front()))
    input.remove_prefix(1);
  const auto line = tokenize(input, true);
  if (!line.valid)
    return {};
  std::size_t completed_count =
      line.trailing_space ? line.count : (line.count ? line.count - 1U : 0U);
  std::string_view partial = line.trailing_space || !line.count
                                 ? std::string_view{}
                                 : line.tokens[line.count - 1U];
  if (!line.trailing_space && line.count) {
    // Tab on an already complete keyword advances to its child context. This
    // differs from an abbreviation such as "sho", which completes to "show".
    const auto exact_keyword = std::any_of(
        cli_schema::commands.begin(), cli_schema::commands.end(),
        [&](const cli_schema::CommandSpec &spec) {
          if (!available(spec, session) || spec.token_count <= line.count)
            return false;
          for (std::size_t index = 0; index < line.count; ++index) {
            if (!accepts(spec.tokens[index], line.tokens[index]))
              return false;
          }
          const auto &last = spec.tokens[line.count - 1U];
          return last.kind == cli_schema::TokenKind::literal &&
                 last.display == line.tokens[line.count - 1U];
        });
    if (exact_keyword && trigger != CliCompletionTrigger::space) {
      completed_count = line.count;
      partial = {};
    }
  }
  std::vector<Candidate> candidates;

  // Completion scans only rows for the active engine and matching prefix.
  // Schema size is fixed for a release, while candidate allocation is limited
  // to the distinct children of one context.
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || completed_count >= spec.token_count)
      continue;
    bool prefix_matches = true;
    for (std::size_t index = 0; index < completed_count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        prefix_matches = false;
        break;
      }
    }
    if (prefix_matches)
      parameter_candidates(state, engine, spec.tokens[completed_count], partial,
                           candidates, spec.token_count > completed_count + 1U);
  }
  std::sort(candidates.begin(), candidates.end(),
            [](const Candidate &left, const Candidate &right) {
              return left.value < right.value;
            });
  if (candidates.empty())
    return {};
  if (engine == CliEngine::md && trigger == CliCompletionTrigger::space &&
      std::none_of(
          candidates.begin(), candidates.end(),
          [](const Candidate &candidate) { return candidate.keyword; })) {
    // MD-CLI Space completion is keyword-only; variable keys require Tab.
    // Classic CLI documents Space and Tab for command and key completion, so
    // its concrete model values remain visible through the same candidate set.
    return {};
  }
  if (candidates.size() == 1U && candidates.front().completable &&
      trigger != CliCompletionTrigger::question &&
      (trigger == CliCompletionTrigger::tab || candidates.front().keyword)) {
    // A unique concrete choice replaces the current token. This is separate
    // from list output so the terminal model does not parse presentation text.
    std::string result;
    for (std::size_t index = 0; index < completed_count; ++index) {
      if (!result.empty())
        result += ' ';
      result += line.tokens[index];
    }
    if (!result.empty())
      result += ' ';
    result += candidates.front().value;
    return result;
  }
  std::ostringstream out;
  // Multiple choices remain display-only and leave the editable line intact.
  // Newline framing is consumed by the terminal session, not by React.
  for (std::size_t index = 0; index < candidates.size(); ++index) {
    if (index)
      out << '\n';
    if (trigger == CliCompletionTrigger::question) {
      // Online help aligns the token, then uses '+' for a context and '-' for
      // an executable leaf. This is router syntax, not decoration invented by
      // React, so it is produced alongside schema-owned descriptions.
      out << ' ' << std::left << std::setw(22) << candidates[index].value
          << (candidates[index].context ? "+ " : "- ");
      out << candidates[index].description;
    } else {
      out << candidates[index].value;
    }
  }
  // A display-only singleton gets an empty second line. This keeps the current
  // string transport unambiguous without mistaking a parameter label for text
  // that should replace the user's editable command line.
  if (candidates.size() == 1U)
    out << '\n';
  return out.str();
}

std::string incomplete_command_help(const DeviceState &state,
                                    const CliSession &session,
                                    std::string_view input) {
  // A syntactically valid prefix such as "ping" is incomplete, not unknown.
  // Requiring exact supplied literals prevents an arbitrary abbreviation from
  // being reported as a complete command context after Enter.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return {};
  const auto incomplete = std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [&](const cli_schema::CommandSpec &spec) {
        if (!available(spec, session) || spec.token_count <= line.count)
          return false;
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        return true;
      });
  if (!incomplete)
    return {};

  // Enter has already accepted every supplied token as an exact prefix of a
  // longer command. Completion must therefore inspect the following token,
  // not reinterpret the final value as a partially typed replacement. This
  // matters for compound leaves such as `address <ipv4> prefix-length <n>`:
  // the address is complete, while `prefix-length` is the missing syntax.
  // Appending one separator reuses the ordinary question-mark completion path
  // and keeps this rule common to every command family.
  auto completed_prefix = std::string{trim_view(input)};
  completed_prefix += ' ';
  return complete_command(state, session, completed_prefix,
                          CliCompletionTrigger::question);
}

bool navigable_command_prefix(const CliSession &session,
                              std::string_view input) {
  // Navigation is legal only for an exact number of supplied context tokens.
  // A literal child proves the path names a container rather than a command
  // awaiting a scalar value such as ping's destination.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return false;
  // `delete` is an edit operator, never a model container. Generated delete
  // rows necessarily share prefixes while the operator is still entering a
  // keyed target, for example `delete ... route <prefix>` before the required
  // route type. Treating that incomplete action as an ordinary grammar parent
  // moved the PWC into a fabricated `/delete ...` path and made the remaining
  // key impossible to enter. Keep every incomplete delete at the caller's PWC;
  // complete rows are executed before this predicate is consulted.
  if (line.tokens[0] == "delete")
    return false;
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [&](const cli_schema::CommandSpec &spec) {
        if (!available(spec, session) ||
            spec.token_count <= line.count + 1U ||
            spec.tokens[line.count].kind != cli_schema::TokenKind::literal)
          return false;
        // `no` is the classic deletion operator. Descendant command rows make
        // it a syntactic prefix, but Nokia never exposes it as a configuration
        // node or prompt component. Reject it before the general literal-child
        // rule so `no <object>` remains an incomplete action. The empty root
        // has no preceding token and must remain safe for completion callers.
        if (line.count > 0U &&
            spec.tokens[line.count - 1U].kind ==
                cli_schema::TokenKind::literal &&
            spec.tokens[line.count - 1U].display == "no")
          return false;
        if ((line.count > 0U &&
             spec.tokens[line.count - 1U].continues_context_key) ||
            spec.tokens[line.count + 1U].continues_context_key)
          return false;
        // A final literal after the supplied path is a value of a leaf, not a
        // child context. For example, BOF `client-type` is followed by either
        // `duid-enterprise` or `duid-link-local`; accepting the common prefix
        // as a PWC fabricated a context that the Nokia command tree does not
        // contain. A real container must have at least one token beyond its
        // immediate child. Keyed lists and route-type branches still satisfy
        // that rule because their child owns further configurable elements.
        // Compound list keys can include labeled fields such as
        // `group-range start <address> end <address>`. Schema metadata marks
        // the non-final key parameter so neither the list name nor a partial
        // key becomes a fabricated PWC.
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        // `primary address <ipv4> prefix-length <n>` is one compound MD leaf.
        // The literal after the address is required syntax, not a child node.
        // Without this distinction Enter after the address fabricated a PWC
        // ending in `primary address <ipv4>`, from which prefix-length could
        // never be executed. Other address parameters, such as an IPv6 list
        // key with configurable children, remain navigable.
        if (line.count >= 2U &&
            spec.tokens[line.count - 1U].kind ==
                cli_schema::TokenKind::ipv4 &&
            spec.tokens[line.count - 2U].kind ==
                cli_schema::TokenKind::literal &&
            spec.tokens[line.count - 2U].display == "address" &&
            spec.tokens[line.count].display == "prefix-length")
          return false;
        return true;
      });
}

bool command_prefix(const CliSession &session, std::string_view input) {
  // This is deliberately broader than context navigation. A line ending at
  // `... interface` is a valid grammar prefix even though its next token is
  // the required interface key and therefore it cannot yet name a container.
  // Keeping the match against generated rows prevents arbitrary text from
  // being mistaken for a child of a defaulted list key.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return false;
  return std::any_of(
      cli_schema::commands.begin(), cli_schema::commands.end(),
      [&](const cli_schema::CommandSpec &spec) {
        if (!available(spec, session) || spec.token_count <= line.count)
          return false;
        for (std::size_t index = 0; index < line.count; ++index) {
          if (!accepts(spec.tokens[index], line.tokens[index]))
            return false;
        }
        return true;
      });
}

std::string canonical_command_prefix(const CliSession &session,
                                     std::string_view input) {
  // Every descendant row of one real context has the same canonical tokens up
  // to that context. Prefix matching must use the same specificity ordering as
  // complete-command matching. In particular, the exact `ospf` keyword wins
  // over `ospf3`, for which the same bytes are merely an abbreviation. Without
  // this ordering a perfectly valid keyed container became ambiguous even
  // though both its help output and every executable descendant were present
  // in the generated schema.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || !line.count)
    return {};
  std::string canonical;
  bool found = false;
  std::uint8_t best_literal_count{};
  std::uint8_t best_exact_literal_count{};
  std::uint8_t best_address_parameter_count{};
  for (const auto &spec : cli_schema::commands) {
    if (!available(spec, session) || spec.token_count <= line.count)
      continue;
    bool matches = true;
    std::string candidate;
    std::uint8_t literal_count{};
    std::uint8_t exact_literal_count{};
    std::uint8_t address_parameter_count{};
    for (std::size_t index = 0; index < line.count; ++index) {
      if (!accepts(spec.tokens[index], line.tokens[index])) {
        matches = false;
        break;
      }
      if (spec.tokens[index].kind == cli_schema::TokenKind::literal) {
        ++literal_count;
        if (spec.tokens[index].display == line.tokens[index])
          ++exact_literal_count;
      } else {
        // Constrained address parameters outrank unconstrained list keys when
        // the same input shape can match both. This mirrors parse_command and
        // keeps entering a context consistent with executing its leaves.
        using enum cli_schema::TokenKind;
        switch (spec.tokens[index].kind) {
        case ipv4:
        case ipv4_key:
        case ipv4_prefix:
        case ipv6:
        case ipv6_with_zone:
        case ipv6_key:
        case ipv6_prefix:
        case ipv6_address_prefix:
        case ip_address:
        case ip_prefix:
        case mac_address:
          ++address_parameter_count;
          break;
        default:
          break;
        }
      }
      if (!candidate.empty())
        candidate += ' ';
      if (spec.tokens[index].kind == cli_schema::TokenKind::literal) {
        candidate += spec.tokens[index].display;
      } else if (session.engine == CliEngine::md &&
                 spec.tokens[index].kind ==
                     cli_schema::TokenKind::interface_name &&
                 !line.tokens[index].starts_with('"')) {
        // MD-CLI renders string list keys quoted in its two-line prompt even
        // when the user entered a simple unquoted name.
        candidate += '"';
        candidate += line.tokens[index];
        candidate += '"';
      } else {
        candidate += line.tokens[index];
      }
    }
    if (!matches)
      continue;

    const bool more_specific =
        !found || literal_count > best_literal_count ||
        (literal_count == best_literal_count &&
         exact_literal_count > best_exact_literal_count) ||
        (literal_count == best_literal_count &&
         exact_literal_count == best_exact_literal_count &&
         address_parameter_count > best_address_parameter_count);
    const bool equally_specific =
        found && literal_count == best_literal_count &&
        exact_literal_count == best_exact_literal_count &&
        address_parameter_count == best_address_parameter_count;
    if (more_specific) {
      canonical = std::move(candidate);
      best_literal_count = literal_count;
      best_exact_literal_count = exact_literal_count;
      best_address_parameter_count = address_parameter_count;
      found = true;
    } else if (equally_specific && candidate != canonical) {
      // Two different canonical paths at the same best rank are genuinely
      // ambiguous. Schema order must never decide which context owns the PWC.
      canonical.clear();
    }
  }
  return canonical;
}

std::string parent_command_prefix(const CliSession &session,
                                  std::string_view input) {
  // A context may end with a list key, for example "card 1". Removing only
  // the final token would leave an impossible "card" context. Search shorter
  // prefixes against the same generated tree and return the nearest container.
  const auto line = tokenize(trim_view(input), false);
  if (!line.valid || line.count < 2)
    return {};
  for (std::size_t count = line.count - 1; count > 0; --count) {
    std::string candidate;
    for (std::size_t index = 0; index < count; ++index) {
      if (!candidate.empty())
        candidate += ' ';
      candidate += line.tokens[index];
    }
    if (navigable_command_prefix(session, candidate))
      return canonical_command_prefix(session, candidate);
  }
  return {};
}

} // namespace router::cli_detail
