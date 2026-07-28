// RFC 2131, RFC 2132 and RFC 3396 conformance tests for DHCPv4 wire parsing.
// These tests use complete UDP payloads and assert malformed input rejection
// before any semantic client, server or relay owner can observe the message.

#include "router/dhcpv4_packet.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using namespace router::packet::dhcpv4;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::vector<std::uint8_t> message_with_options(
    std::span<const std::uint8_t> options) {
  std::vector<std::uint8_t> bytes(options_offset + options.size(), 0U);
  bytes[0U] = static_cast<std::uint8_t>(Operation::boot_request);
  bytes[1U] = 1U;
  bytes[2U] = 6U;
  bytes[4U] = 0x12U;
  bytes[5U] = 0x34U;
  bytes[6U] = 0x56U;
  bytes[7U] = 0x78U;
  std::copy(magic_cookie.begin(), magic_cookie.end(),
            bytes.begin() + fixed_header_octets);
  std::copy(options.begin(), options.end(), bytes.begin() + options_offset);
  return bytes;
}

void parse_and_write_round_trip() {
  std::array<std::uint8_t, 300U> output{};
  MessageView header{.operation = Operation::boot_request,
                     .hardware_type = 1U,
                     .hardware_length = 6U,
                     .transaction_id = 0x12345678U,
                     .flags = 0x8000U};
  header.client_hardware_address[0U] = 0x02U;
  header.client_hardware_address[5U] = 0x01U;

  auto writer = begin(output, header);
  require(writer.has_value(), "DHCPv4 writer rejected a valid BOOTP header");
  const std::array type{static_cast<std::uint8_t>(MessageType::discover)};
  require(writer->append(
              static_cast<std::uint8_t>(OptionCode::message_type), type),
          "DHCPv4 writer rejected a valid message type");
  require(writer->finish(), "DHCPv4 writer could not append End");

  const auto parsed = parse(writer->view());
  require(parsed.has_value(), "DHCPv4 writer output did not parse");
  require(parsed->transaction_id == 0x12345678U,
          "DHCPv4 transaction identifier changed");
  require(parsed->flags == 0x8000U, "DHCPv4 flags changed");
  require(parsed->client_hardware_address[5U] == 0x01U,
          "DHCPv4 client hardware address changed");
  const auto parsed_type = message_type(*parsed);
  require(parsed_type == MessageType::discover,
          "DHCPv4 message type changed");
}

void concatenates_repeated_options_in_wire_order() {
  const std::array<std::uint8_t, 11U> options{
      static_cast<std::uint8_t>(OptionCode::domain_search), 2U, 1U, 2U,
      static_cast<std::uint8_t>(OptionCode::pad),
      static_cast<std::uint8_t>(OptionCode::domain_search), 3U, 3U, 4U, 5U,
      static_cast<std::uint8_t>(OptionCode::end)};
  const auto bytes = message_with_options(options);
  const auto parsed = parse(bytes);
  require(parsed.has_value(), "DHCPv4 repeated options did not parse");

  std::array<std::uint8_t, 5U> normalized{};
  const auto result = normalize_option(
      *parsed, static_cast<std::uint8_t>(OptionCode::domain_search),
      normalized);
  require(result.has_value(), "DHCPv4 repeated options did not normalize");
  require(result->occurrences == 2U && result->octets == 5U,
          "DHCPv4 repeated option metadata is wrong");
  require(normalized[0U] == 1U && normalized[4U] == 5U,
          "DHCPv4 RFC 3396 concatenation order is wrong");
}

void follows_option_overload_file_then_server_name() {
  const std::array<std::uint8_t, 7U> options{
      static_cast<std::uint8_t>(OptionCode::option_overload), 1U, 3U,
      static_cast<std::uint8_t>(OptionCode::host_name), 1U,
      static_cast<std::uint8_t>('a'),
      static_cast<std::uint8_t>(OptionCode::end)};
  auto bytes = message_with_options(options);
  bytes[108U] = static_cast<std::uint8_t>(OptionCode::host_name);
  bytes[109U] = 1U;
  bytes[110U] = static_cast<std::uint8_t>('b');
  bytes[111U] = static_cast<std::uint8_t>(OptionCode::end);
  bytes[44U] = static_cast<std::uint8_t>(OptionCode::host_name);
  bytes[45U] = 1U;
  bytes[46U] = static_cast<std::uint8_t>('c');
  bytes[47U] = static_cast<std::uint8_t>(OptionCode::end);
  const auto parsed = parse(bytes);
  require(parsed.has_value(), "DHCPv4 overloaded options did not parse");

  std::array<std::uint8_t, 3U> normalized{};
  const auto result = normalize_option(
      *parsed, static_cast<std::uint8_t>(OptionCode::host_name), normalized);
  require(result.has_value() && result->occurrences == 3U,
          "DHCPv4 overloaded options did not normalize");
  require(normalized[0U] == static_cast<std::uint8_t>('a') &&
              normalized[1U] == static_cast<std::uint8_t>('b') &&
              normalized[2U] == static_cast<std::uint8_t>('c'),
          "DHCPv4 overload concatenation order is wrong");
}

void rejects_truncated_and_ambiguous_options() {
  const std::array<std::uint8_t, 4U> truncated{
      static_cast<std::uint8_t>(OptionCode::host_name), 4U, 1U, 2U};
  require(!parse(message_with_options(truncated)).has_value(),
          "DHCPv4 truncated option was accepted");

  const std::array<std::uint8_t, 7U> duplicated_overload{
      static_cast<std::uint8_t>(OptionCode::option_overload), 1U, 1U,
      static_cast<std::uint8_t>(OptionCode::option_overload), 1U, 2U,
      static_cast<std::uint8_t>(OptionCode::end)};
  require(!parse(message_with_options(duplicated_overload)).has_value(),
          "DHCPv4 duplicate overload declaration was accepted");
}

} // namespace

void dhcpv4_packet_tests() {
  parse_and_write_round_trip();
  concatenates_repeated_options_in_wire_order();
  follows_option_overload_file_then_server_name();
  rejects_truncated_and_ambiguous_options();
}
