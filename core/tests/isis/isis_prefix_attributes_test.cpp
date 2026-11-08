// Independent metadata fixtures cover RFC 5130 ordered tag widths and RFC 7794
// context-dependent flag meaning. Tests own all packet storage and no policy.

#include "router/isis_prefix_attributes.hpp"

#include <algorithm>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
void require(bool value, std::source_location location = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS prefix attribute invariant failed at " + std::to_string(location.line()));
}
}
void isis_prefix_attributes_tests() {
  using namespace router::packet::isis;
  using namespace router::ip;
  const std::array<std::uint8_t, 12U> tags32{0U, 0U, 0U, 0U, 0xffU, 0xffU, 0xffU, 0xffU, 0U, 0U, 0U, 42U};
  AdministrativeTagCursor narrow({1U, tags32});
  const auto zero = narrow.next(), maximum = narrow.next(), last = narrow.next();
  require(zero && !zero->wide && zero->value == 0U && maximum && maximum->value == 0xffffffffULL &&
      last && last->value == 42U && !narrow.next() && narrow.valid());
  const std::array<std::uint8_t, 16U> tags64{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U,
      0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU};
  AdministrativeTagCursor wide({2U, tags64});
  const auto first = wide.next(), second = wide.next();
  require(first && first->wide && first->value == 0x0102030405060708ULL && second &&
      second->value == std::numeric_limits<std::uint64_t>::max() && !wide.next() && wide.valid());
  std::array<std::uint8_t, 256U> buffer{};
  TlvWriter writer(buffer);
  const std::array<std::uint32_t, 3U> numbers32{0U, 0xffffffffU, 42U};
  const std::array<std::uint64_t, 2U> numbers64{0x0102030405060708ULL, 0xffffffffffffffffULL};
  require(encode_administrative_tags(writer, numbers32) && encode_administrative_tags(writer, numbers64));
  TlvCursor encoded(writer.bytes());
  const auto old = encoded.next(), extended = encoded.next();
  require(old && old->code == 1U && std::ranges::equal(old->value, tags32) && extended &&
      extended->code == 2U && std::ranges::equal(extended->value, tags64) && !encoded.next() && encoded.valid());
  for (const auto malformed : {TlvView{1U, {}}, TlvView{1U, std::span{tags32}.first(5U)},
      TlvView{2U, std::span{tags64}.first(4U)}, TlvView{3U, tags32}}) {
    AdministrativeTagCursor cursor(malformed);
    require(!cursor.valid() && !cursor.next());
  }
  std::array<std::uint32_t, 64U> many32{};
  std::array<std::uint64_t, 32U> many64{};
  TlvWriter counts32(buffer);
  require(!encode_administrative_tags(counts32, many32) && counts32.bytes().empty() &&
      encode_administrative_tags(counts32, std::span{many32}.first(63U)) && counts32.bytes().size() == 254U);
  TlvWriter counts64(buffer);
  require(!encode_administrative_tags(counts64, many64) && counts64.bytes().empty() &&
      encode_administrative_tags(counts64, std::span{many64}.first(31U)) && counts64.bytes().size() == 250U);
  const auto saved = buffer;
  TlvWriter short_output(std::span{buffer}.first(13U));
  require(!encode_administrative_tags(short_output, numbers32) && short_output.bytes().empty() && buffer == saved);

  IpPrefix host4;
  host4.length = 32U;
  host4.network.bytes[0U] = 192U;
  host4.network.bytes[2U] = 2U;
  host4.network.bytes[3U] = 1U;
  auto host6 = host4;
  host6.network.family = AddressFamily::ipv6;
  host6.length = 128U;
  const std::array<std::uint8_t, 2U> all_flags{0xffU, 0xffU};
  require(prefix_attribute_flags({4U, all_flags}, host4) == std::optional{PrefixAttributeFlags{true, true, true}});
  require(prefix_attribute_flags({4U, all_flags}, host6) == std::optional{PrefixAttributeFlags{false, true, true}});
  auto subnet = host4;
  subnet.length = 24U;
  require(prefix_attribute_flags({4U, all_flags}, subnet) == std::optional{PrefixAttributeFlags{true, true, false}} &&
      prefix_attribute_flags({4U, {}}, host4) == std::optional{PrefixAttributeFlags{}} &&
      !prefix_attribute_flags({3U, all_flags}, host4));
  TlvWriter flags(buffer);
  require(encode_prefix_attribute_flags(flags, host4, {true, true, true}) &&
      flags.bytes().size() == 3U && flags.bytes()[0U] == 4U && flags.bytes()[1U] == 1U && flags.bytes()[2U] == 0xe0U);
  const auto flag_bytes = buffer;
  const auto available = flags.available();
  require(!encode_prefix_attribute_flags(flags, subnet, {false, false, true}) &&
      !encode_prefix_attribute_flags(flags, host6, {true, false, false}) && flags.available() == available && buffer == flag_bytes);
  require(encode_prefix_attribute_flags(flags, host6, {false, true, true}) && flags.bytes()[5U] == 0x60U);
  auto invalid = host4;
  invalid.length = 33U;
  require(!prefix_attribute_flags({4U, all_flags}, invalid) && !encode_prefix_attribute_flags(flags, invalid, {}));

  const std::array<std::uint8_t, 4U> router4{192U, 0U, 2U, 9U};
  const std::array<std::uint8_t, 16U> router6{0x20U, 1U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 9U};
  const auto id4 = prefix_source_router_id({11U, router4}), id6 = prefix_source_router_id({12U, router6});
  require(id4 && id4->family == AddressFamily::ipv4 && std::equal(router4.begin(), router4.end(), id4->bytes.begin()) &&
      id6 && id6->family == AddressFamily::ipv6 && id6->bytes == router6 &&
      !prefix_source_router_id({11U, router6}) && !prefix_source_router_id({12U, router4}));
  TlvWriter identities(buffer);
  require(encode_prefix_source_router_id(identities, *id4) && encode_prefix_source_router_id(identities, *id6));
  TlvCursor identity_options(identities.bytes());
  require(prefix_source_router_id(*identity_options.next()) == id4 && prefix_source_router_id(*identity_options.next()) == id6);
  auto bad_id = *id4;
  bad_id.bytes[15U] = 1U;
  const auto identity_bytes = buffer;
  require(!encode_prefix_source_router_id(identities, bad_id) && buffer == identity_bytes);
  TlvWriter metadata_wire(buffer);
  require(encode_prefix_attribute_flags(metadata_wire, host4, {true, true, true}) &&
      encode_prefix_attribute_flags(metadata_wire, host4, {}) &&
      metadata_wire.append(11U, router6) && encode_prefix_source_router_id(metadata_wire, *id4) &&
      metadata_wire.append(12U, router4) && encode_prefix_source_router_id(metadata_wire, *id6) &&
      encode_administrative_tags(metadata_wire, numbers32) && encode_administrative_tags(metadata_wire, numbers64));
  const std::array<std::uint32_t, 1U> later_tag{99U};
  require(encode_administrative_tags(metadata_wire, later_tag));
  const auto metadata = prefix_metadata(host4, metadata_wire.bytes());
  require(metadata && metadata->flags == std::optional{PrefixAttributeFlags{true, true, true}} &&
      metadata->source_ipv4 == id4 && metadata->source_ipv6 == id6 && metadata->first_tag32 == 0U &&
      metadata->first_tag64 == 0x0102030405060708ULL);
  const auto v6_metadata = prefix_metadata(host6, metadata_wire.bytes());
  require(v6_metadata && v6_metadata->flags == std::optional{PrefixAttributeFlags{false, true, true}});
  const std::array<std::uint8_t, 5U> absent_flags{4U, 0U, 4U, 1U, 0x80U};
  require(prefix_metadata(host4, absent_flags)->flags == std::optional{PrefixAttributeFlags{}});
  TlvWriter invalid_tag(buffer);
  require(invalid_tag.append(1U, std::span{tags32}.first(5U)) && encode_administrative_tags(invalid_tag, later_tag) &&
      prefix_metadata(host4, invalid_tag.bytes())->first_tag32 == 99U);
  const std::array<std::uint8_t, 3U> malformed{11U, 4U, 192U};
  require(!prefix_metadata(host4, malformed) && !prefix_metadata(invalid, {}));
}
