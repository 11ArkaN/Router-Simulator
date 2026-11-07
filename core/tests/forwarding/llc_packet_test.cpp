// LLC fixtures exercise Length/Type boundaries, VLAN nesting and aliased
// output. Expected bytes are specified independently of the codec writer.

#include "router/llc_packet.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
}

void llc_packet_tests() {
  using namespace router::packet;
  const LlcUiInput input{{2U, 0U, 0U, 0U, 0U, 1U},
                         {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U}, 0xfeU, 0xfeU};
  const std::array<std::uint8_t, 4U> payload{0x83U, 0x14U, 1U, 0U};
  Frame frame{};
  require(llc_ui_into(frame, input, payload) && frame.length == 60U &&
            frame.bytes[12U] == 0U && frame.bytes[13U] == 7U &&
            frame.bytes[14U] == 0xfeU && frame.bytes[15U] == 0xfeU && frame.bytes[16U] == 3U,
          "LLC ordinary Length or header fixture mismatch");
  const auto decoded = parse_llc_ui(frame.view());
  require(decoded && !decoded->extended_length && std::ranges::equal(decoded->payload, payload) &&
            decoded->ethernet.source == input.source && decoded->ethernet.destination == input.destination,
          "LLC ordinary frame included Ethernet padding in its payload");
  require(std::all_of(frame.bytes.begin() + 21U, frame.bytes.begin() + frame.length,
                       [](auto octet) { return octet == 0U; }), "LLC writer leaked uninitialized padding");
  for (std::size_t truncated = 0U; truncated < 21U; ++truncated)
    require(!parse_llc_ui(frame.view().first(truncated)), "LLC accepted a truncated declared payload");
  auto malformed = frame;
  for (const auto type : {0U, 1U, 2U, 8U, 1501U, 1535U, 1536U, 0x0800U}) {
    malformed.bytes[12U] = static_cast<std::uint8_t>(type >> 8U);
    malformed.bytes[13U] = static_cast<std::uint8_t>(type);
    // Length 8 is legal with padding available, but truncating to the actual
    // seven-octet client distinguishes it from the undefined Length/Type gap.
    require(!parse_llc_ui(malformed.view().first(21U)), "LLC accepted invalid Length/Type or truncation");
  }
  malformed = frame;
  malformed.bytes[16U] = 0x13U;
  require(!parse_llc_ui(malformed.view()), "LLC accepted an unsupported control encoding");
  const std::array<EthernetView::VlanTag, 2U> tags{{{0x88a8U, 100U, 3U, false},
                                                  {0x8100U, 200U, 5U, true}}};
  require(insert_vlan_tags(frame, tags), "LLC QinQ fixture tagging failed");
  const auto tagged = parse_llc_ui(frame.view());
  require(tagged && tagged->ethernet.vlan_tag_count == 2U &&
            tagged->ethernet.vlan_tags == tags && std::ranges::equal(tagged->payload, payload),
          "LLC QinQ changed the client Length or payload");

  std::array<std::uint8_t, maximum_frame_octets> large{};
  for (std::size_t index = 0U; index < large.size(); ++index)
    large[index] = static_cast<std::uint8_t>(index);
  for (const auto size : {1497U, 1498U, static_cast<unsigned>(maximum_frame_octets - 17U)}) {
    const auto data = std::span(large).first(size);
    require(llc_ui_into(frame, input, data), "LLC rejected a supported jumbo size");
    const auto jumbo = parse_llc_ui(frame.view());
    require(jumbo && jumbo->extended_length == (size > 1497U) &&
              std::ranges::equal(jumbo->payload, data), "LLC Length/8870 boundary mismatch");
  }
  const auto saved = frame;
  require(!llc_ui_into(frame, input, large) && frame.length == saved.length &&
            frame.bytes == saved.bytes, "LLC capacity failure modified output");
  std::copy(payload.begin(), payload.end(), frame.bytes.begin());
  require(llc_ui_into(frame, input, std::span(frame.bytes).first(payload.size())) &&
            std::ranges::equal(parse_llc_ui(frame.view())->payload, payload),
          "LLC aliased payload was overwritten by the Ethernet header");
  malformed = saved;
  malformed.length = 16U;
  require(!parse_llc_ui(malformed.view()), "LLC accepted a truncated extended header");
}
