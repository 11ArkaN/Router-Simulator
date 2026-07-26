// RFC 9915 packet tests exercise ordinary and relay headers, nested identity
// associations, malformed option rejection and unknown-option preservation.

#include "router/dhcpv6_packet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

void dhcpv6_packet_tests() {
  using namespace router;
  using namespace router::packet::dhcpv6;

  std::array<std::uint8_t, 2048> bytes{};
  constexpr std::array<std::uint8_t, 2> unknown_data{0x12U, 0x34U};
  auto writer = begin_client_server(
      bytes, static_cast<std::uint8_t>(MessageType::solicit), 0xabcdefU);
  constexpr std::array<std::uint8_t, 6> duid{0U, 3U, 0U, 1U, 0xaaU, 0xbbU};
  if (!writer ||
      !writer->append(static_cast<std::uint16_t>(OptionCode::client_identifier),
                      duid) ||
      !writer->append(static_cast<std::uint16_t>(OptionCode::rapid_commit),
                      {}) ||
      !writer->append(65000U, unknown_data))
    throw std::runtime_error("DHCPv6 client message writer rejected valid options");
  const auto message = parse(writer->view());
  if (!message || message->relay ||
      message->type != static_cast<std::uint8_t>(MessageType::solicit) ||
      message->transaction_id != 0xabcdefU)
    throw std::runtime_error("DHCPv6 client header did not round trip");

  OptionCursor options{message->options};
  const auto client_id = options.next();
  const auto rapid_commit = options.next();
  const auto unknown = options.next();
  if (!client_id ||
      client_id->code !=
          static_cast<std::uint16_t>(OptionCode::client_identifier) ||
      client_id->data.size() != duid.size() || !rapid_commit ||
      !rapid_commit->data.empty() || !unknown || unknown->code != 65000U ||
      unknown->data[0] != 0x12U || options.next() || !options.valid())
    throw std::runtime_error("DHCPv6 option cursor lost known or unknown data");
  std::array<std::uint8_t, 2048> inner_message{};
  const auto inner_message_length = writer->size();
  std::copy(writer->view().begin(), writer->view().end(),
            inner_message.begin());

  // No arbitrary option-count ceiling belongs in the codec. Resource policy
  // belongs to a client or server owner, while all options that fit the legal
  // UDP message remain structurally parseable.
  auto many = begin_client_server(
      bytes, static_cast<std::uint8_t>(MessageType::information_request), 1U);
  for (std::uint16_t code = 1000U; many && code < 1100U; ++code)
    if (!many->append(code, {}))
      many.reset();
  if (!many || !parse(many->view()))
    throw std::runtime_error("DHCPv6 codec imposed an option-count shortcut");

  std::array<std::uint8_t, 2048> malformed_bytes{};
  std::copy_n(inner_message.begin(), inner_message_length,
              malformed_bytes.begin());
  malformed_bytes[6U] = 0xffU;
  malformed_bytes[7U] = 0xffU;
  if (parse(std::span<const std::uint8_t>{malformed_bytes}.first(
          inner_message_length)) ||
      begin_client_server(bytes,
                          static_cast<std::uint8_t>(MessageType::relay_forward),
                          1U) ||
      begin_client_server(bytes,
                          static_cast<std::uint8_t>(MessageType::request),
                          0x01000000U))
    throw std::runtime_error("DHCPv6 accepted malformed options or header domain");

  const auto link = ip::parse_ipv6("2001:db8:1::1");
  const auto peer = ip::parse_ipv6("fe80::abcd");
  if (!link || !peer)
    throw std::runtime_error("DHCPv6 relay fixture address parsing failed");
  auto relay = begin_relay(
      bytes, static_cast<std::uint8_t>(MessageType::relay_forward), 0U, *link,
      *peer);
  constexpr std::array<std::uint8_t, 4> interface_id{'e', 't', 'h', '0'};
  if (!relay ||
      !relay->append(static_cast<std::uint16_t>(OptionCode::interface_id),
                     interface_id) ||
      !relay->append(static_cast<std::uint16_t>(OptionCode::relay_message),
                     std::span<const std::uint8_t>{inner_message}.first(
                         inner_message_length)))
    throw std::runtime_error("DHCPv6 relay writer rejected encapsulation");
  const auto relayed = parse(relay->view());
  if (!relayed || !relayed->relay || relayed->hop_count != 0U ||
      relayed->link_address != *link || relayed->peer_address != *peer)
    throw std::runtime_error("DHCPv6 relay header did not round trip");
  OptionCursor relay_options{relayed->options};
  const auto parsed_interface = relay_options.next();
  const auto encapsulated = relay_options.next();
  if (!parsed_interface || parsed_interface->data.size() != 4U ||
      !encapsulated ||
      encapsulated->code !=
          static_cast<std::uint16_t>(OptionCode::relay_message) ||
      !parse(encapsulated->data) || relay_options.next() ||
      !relay_options.valid())
    throw std::runtime_error("DHCPv6 relay options lost the inner message");

  // IA_NA uses a 12-octet fixed body followed by ordinary nested options.
  // The nested IAADDR below carries 3600-second preferred and 7200-second
  // valid lifetimes for 2001:db8:1::100.
  std::array<std::uint8_t, 40> ia_na{};
  ia_na[3U] = 7U;
  ia_na[6U] = 0x0eU;
  ia_na[7U] = 0x10U;
  ia_na[10U] = 0x1cU;
  ia_na[11U] = 0x20U;
  ia_na[12U] = 0U;
  ia_na[13U] = static_cast<std::uint8_t>(OptionCode::ia_address);
  ia_na[14U] = 0U;
  ia_na[15U] = 24U;
  const auto lease_address = ip::parse_ipv6("2001:db8:1::100");
  if (!lease_address)
    throw std::runtime_error("DHCPv6 IA address fixture parsing failed");
  std::copy(lease_address->begin(), lease_address->end(), ia_na.begin() + 16U);
  ia_na[32U] = 0U;
  ia_na[33U] = 0U;
  ia_na[34U] = 0x0eU;
  ia_na[35U] = 0x10U;
  ia_na[36U] = 0U;
  ia_na[37U] = 0U;
  ia_na[38U] = 0x1cU;
  ia_na[39U] = 0x20U;
  const auto association = parse_ia_na_or_pd(ia_na);
  OptionCursor nested{association ? association->options
                                  : std::span<const std::uint8_t>{}};
  const auto address_option = nested.next();
  const auto address = address_option ? parse_ia_address(address_option->data)
                                      : std::nullopt;
  if (!association || association->iaid != 7U || association->t1 != 3600U ||
      association->t2 != 7200U || !address ||
      address->address != *lease_address ||
      address->preferred_lifetime != 3600U ||
      address->valid_lifetime != 7200U || nested.next() || !nested.valid())
    throw std::runtime_error("DHCPv6 IA_NA or IAADDR parsing failed");
  auto invalid_address = address_option->data;
  std::array<std::uint8_t, 24> invalid_lifetime{};
  std::copy(invalid_address.begin(), invalid_address.end(),
            invalid_lifetime.begin());
  std::fill(invalid_lifetime.begin() + 16U,
            invalid_lifetime.begin() + 24U, std::uint8_t{0});
  invalid_lifetime[19U] = 2U;
  invalid_lifetime[23U] = 1U;
  if (parse_ia_address(invalid_lifetime))
    throw std::runtime_error("DHCPv6 accepted preferred lifetime above valid");

  std::array<std::uint8_t, 25> prefix_data{};
  prefix_data[3U] = 100U;
  prefix_data[7U] = 200U;
  prefix_data[8U] = 56U;
  const auto prefix = ip::parse_ipv6("2001:db8:100::");
  if (!prefix)
    throw std::runtime_error("DHCPv6 IA_PD fixture prefix parsing failed");
  std::copy(prefix->begin(), prefix->end(), prefix_data.begin() + 9U);
  const auto delegated = parse_ia_prefix(prefix_data);
  prefix_data[8U] = 129U;
  if (!delegated || delegated->prefix != *prefix ||
      delegated->prefix_length != 56U || delegated->preferred_lifetime != 100U ||
      delegated->valid_lifetime != 200U || parse_ia_prefix(prefix_data))
    throw std::runtime_error("DHCPv6 IAPREFIX validation failed");

  // RFC 6603 section 4.2 example: five subnet-id bits extend the delegated
  // 2001:db8:dead:bee0::/59 into excluded 2001:db8:dead:beef::/64. The final
  // three bits are padding and must be zero, so 0x79 is not an alternate
  // spelling of the same option.
  const auto delegated_parent = ip::parse_ipv6("2001:db8:dead:bee0::");
  const auto excluded_child = ip::parse_ipv6("2001:db8:dead:beef::");
  constexpr std::array<std::uint8_t, 2U> exclude_body{64U, 0x78U};
  constexpr std::array<std::uint8_t, 2U> exclude_bad_padding{64U, 0x79U};
  const auto excluded = delegated_parent
                            ? parse_prefix_exclude(exclude_body,
                                                   *delegated_parent, 59U)
                            : std::nullopt;
  if (!delegated_parent || !excluded_child || !excluded ||
      excluded->excluded_prefix != *excluded_child ||
      excluded->excluded_prefix_length != 64U ||
      parse_prefix_exclude(exclude_bad_padding, *delegated_parent, 59U) ||
      parse_prefix_exclude(exclude_body, *delegated_parent, 64U))
    throw std::runtime_error("DHCPv6 Prefix Exclude validation failed");

  // Typed writers must reproduce the same nested option grammar without a
  // client or server duplicating byte offsets. Build IAADDR, wrap it as an
  // option, then place that option in IA_NA and parse every layer again.
  std::array<std::uint8_t, 128> typed_address_body{};
  const auto typed_address_length = encode_ia_address(
      typed_address_body, *lease_address, 3600U, 7200U);
  std::array<std::uint8_t, 128> typed_nested_options{};
  auto typed_nested = begin_client_server(
      typed_nested_options,
      static_cast<std::uint8_t>(MessageType::request), 1U);
  if (!typed_address_length || !typed_nested)
    throw std::runtime_error("DHCPv6 typed IAADDR setup failed");
  // Skip the four-byte message header: an IA option body contains an option
  // sequence, not another DHCPv6 client/server header.
  std::array<std::uint8_t, 128> raw_nested{};
  raw_nested[0U] = 0U;
  raw_nested[1U] = static_cast<std::uint8_t>(OptionCode::ia_address);
  raw_nested[2U] = 0U;
  raw_nested[3U] = static_cast<std::uint8_t>(*typed_address_length);
  std::copy_n(typed_address_body.begin(), *typed_address_length,
              raw_nested.begin() + 4U);
  const auto raw_nested_length = 4U + *typed_address_length;
  std::array<std::uint8_t, 160> typed_ia_body{};
  const auto typed_ia_length = encode_ia_na_or_pd(
      typed_ia_body, 42U, 1800U, 2880U,
      std::span<const std::uint8_t>{raw_nested}.first(raw_nested_length));
  const auto typed_ia = typed_ia_length
                            ? parse_ia_na_or_pd(
                                  std::span<const std::uint8_t>{typed_ia_body}
                                      .first(*typed_ia_length))
                            : std::nullopt;
  OptionCursor typed_ia_options{
      typed_ia ? typed_ia->options : std::span<const std::uint8_t>{}};
  const auto typed_ia_address_option = typed_ia_options.next();
  const auto typed_ia_address =
      typed_ia_address_option
          ? parse_ia_address(typed_ia_address_option->data)
          : std::nullopt;
  if (!typed_ia || typed_ia->iaid != 42U || typed_ia->t1 != 1800U ||
      typed_ia->t2 != 2880U || !typed_ia_address ||
      typed_ia_address->address != *lease_address ||
      encode_ia_address(typed_address_body, *lease_address, 2U, 1U) ||
      encode_ia_prefix(prefix_data, *prefix, 129U, 1U, 2U))
    throw std::runtime_error("DHCPv6 typed IA option encoding failed");

  constexpr std::array<std::uint8_t, 2> status_text{'o', 'k'};
  std::array<std::uint8_t, 8> status_body{};
  const auto status_length = encode_status_code(status_body, 0U, status_text);
  const auto status = status_length
                          ? parse_status_code(
                                std::span<const std::uint8_t>{status_body}
                                    .first(*status_length))
                          : std::nullopt;
  if (!status || status->code != 0U || status->message.size() != 2U ||
      status->message[0U] != 'o' || parse_status_code({}))
    throw std::runtime_error("DHCPv6 Status Code encoding failed");

  std::array<std::uint8_t, 32> dns_data{};
  const auto dns_first = ip::parse_ipv6("2001:db8::53");
  const auto dns_second = ip::parse_ipv6("2001:db8::54");
  if (!dns_first || !dns_second)
    throw std::runtime_error("DHCPv6 DNS option fixture parsing failed");
  std::copy(dns_first->begin(), dns_first->end(), dns_data.begin());
  std::copy(dns_second->begin(), dns_second->end(), dns_data.begin() + 16U);
  const auto dns_servers = parse_dns_recursive_name_servers(dns_data);
  if (!dns_servers || dns_servers->size() != 2U ||
      (*dns_servers)[0U] != *dns_first || (*dns_servers)[1U] != *dns_second ||
      parse_dns_recursive_name_servers(
          std::span<const std::uint8_t>{dns_data}.first(31U)) ||
      parse_dns_recursive_name_servers({}))
    throw std::runtime_error("DHCPv6 DNS server option validation failed");

  constexpr std::array<std::uint8_t, 30> domains{
      3U, 'w', 'w', 'w', 7U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
      3U, 'c', 'o', 'm', 0U,
      7U, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3U, 'n', 'e', 't', 0U};
  const auto search_list = parse_domain_search_list(domains);
  constexpr std::array<std::uint8_t, 2> compressed{0xc0U, 0U};
  constexpr std::array<std::uint8_t, 3> truncated{3U, 'b', 'a'};
  if (!search_list || search_list->size() != 2U ||
      (*search_list)[0U].octets != 17U || (*search_list)[1U].octets != 13U ||
      !parse_domain_search_list({}) || parse_domain_search_list(compressed) ||
      parse_domain_search_list(truncated))
    throw std::runtime_error("DHCPv6 domain search list validation failed");

  constexpr packet::Mac identity_mac{0x02U, 0U, 0U, 0U, 0U, 1U};
  std::array<std::uint8_t, 14> duid_llt{};
  const auto duid_length =
      encode_duid_llt_ethernet(duid_llt, identity_mac, 0x01020304U);
  if (!duid_length || *duid_length != duid_llt.size() ||
      duid_llt != std::array<std::uint8_t, 14>{
                      0U, 1U, 0U, 1U, 1U, 2U, 3U, 4U,
                      2U, 0U, 0U, 0U, 0U, 1U} ||
      !valid_duid(duid_llt) ||
      valid_duid(std::span<const std::uint8_t>{duid_llt}.first(2U)))
    throw std::runtime_error("DHCPv6 DUID-LLT generation or length failed");
  std::array<std::uint8_t, maximum_duid_octets> future_duid{};
  future_duid[1U] = 99U;
  if (!valid_duid(future_duid))
    throw std::runtime_error("DHCPv6 rejected a future opaque DUID type");
}
