// Extension action tests construct complete Ethernet and IPv6 frames so error
// pointers are verified in the same coordinate system used by ICMPv6 output.

#include "router/ipv6_extension.hpp"

#include <algorithm>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Frame with_extension(router::packet::Frame frame,
                                     std::uint8_t extension_type,
                                     std::uint8_t byte2,
                                     std::uint8_t byte3) {
  const auto payload = static_cast<std::uint16_t>((frame[18] << 8U) | frame[19]);
  std::copy_backward(frame.bytes.begin() + 54U,
                     frame.bytes.begin() + 54U + payload,
                     frame.bytes.begin() + 62U + payload);
  frame.bytes[20] = extension_type;
  frame.bytes[54] = router::packet::ipv6_next_header_icmpv6;
  frame.bytes[55] = 0U;
  frame.bytes[56] = byte2;
  frame.bytes[57] = byte3;
  frame.bytes[58] = 0U;
  frame.bytes[59] = 0U;
  frame.bytes[60] = 0U;
  frame.bytes[61] = 0U;
  const auto extended = static_cast<std::uint16_t>(payload + 8U);
  frame.bytes[18] = static_cast<std::uint8_t>(extended >> 8U);
  frame.bytes[19] = static_cast<std::uint8_t>(extended);
  frame.length = static_cast<std::uint16_t>(frame.length + 8U);
  return frame;
}

} // namespace

void ipv6_extension_tests() {
  using namespace router::packet;
  const Mac first{0x02, 0, 0, 0, 0, 1};
  const Mac second{0x02, 0, 0, 0, 0, 2};
  const auto source = router::ip::parse_ipv6("2001:db8::1");
  const auto destination = router::ip::parse_ipv6("2001:db8::2");
  require(source && destination, "extension fixture address is invalid");
  const auto echo = icmpv6_echo(first, second, *source, *destination, false, 1U);

  const auto skip = with_extension(echo, 0U, 0x20U, 0U);
  const auto skip_view = parse_ipv6(skip);
  require(skip_view &&
              validate_ipv6_extensions(skip, *skip_view, true, true).action ==
                  Ipv6ExtensionAction::accept,
          "skip-action IPv6 option was not accepted");

  const auto silent = with_extension(echo, 0U, 0x40U, 0U);
  const auto silent_view = parse_ipv6(silent);
  require(silent_view &&
              validate_ipv6_extensions(silent, *silent_view, true, true).action ==
                  Ipv6ExtensionAction::silent_discard,
          "discard-action IPv6 option requested an ICMP error");

  const auto report = with_extension(echo, 0U, 0x80U, 0U);
  const auto report_view = parse_ipv6(report);
  const auto report_result =
      report_view ? validate_ipv6_extensions(report, *report_view, true, true)
                  : Ipv6ExtensionValidation{};
  require(report_view &&
              report_result.action == Ipv6ExtensionAction::parameter_problem &&
              report_result.code == icmpv6_parameter_unknown_option_code &&
              report_result.pointer == 42U,
          "report-action option produced an incorrect Parameter Problem pointer");

  // An unknown Routing Type is harmless only when Segments Left is zero.
  const auto routing = with_extension(echo, 43U, 0xfaU, 1U);
  const auto routing_view = parse_ipv6(routing);
  const auto routing_result =
      routing_view ? validate_ipv6_extensions(routing, *routing_view, true, true)
                   : Ipv6ExtensionValidation{};
  require(routing_result.action == Ipv6ExtensionAction::parameter_problem &&
              routing_result.code == icmpv6_parameter_bad_header_code &&
              routing_result.pointer == 42U,
          "unknown active Routing Type did not identify its type field");
}
