// Wire fixtures own joined metadata and verify lossless supported attributes,
// canonical flags, multipart-sized output and atomic refusal before origination.
#include "router/isis_interlevel_attributes.hpp"
#include <algorithm>
#include <source_location>
#include <stdexcept>
namespace {
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("Interlevel attribute invariant at " + std::to_string(at.line()));
}
}
void isis_interlevel_attributes_tests() {
  using namespace router;
  using namespace packet::isis;
  using namespace isis;
  const auto host = *ip::parse_ip_prefix("192.0.2.1/32");
  std::array<std::uint8_t, 1024U> input{}, output{};
  output.fill(0xaaU);
  TlvWriter writer(input);
  const std::array<std::uint8_t,2U> flags{0xffU,0xffU};
  const std::array<std::uint8_t,1U> unknown{42U};
  const std::array<std::uint32_t,3U> tags{0U,42U,7U};
  require(writer.append(4U,flags) && writer.append(99U,unknown) &&
      encode_prefix_source_router_id(writer,*ip::parse_ip_address("192.0.2.9")) &&
      encode_prefix_source_router_id(writer,*ip::parse_ip_address("2001:db8::9")) &&
      encode_administrative_tags(writer,tags) && encode_administrative_tags(writer,tags));
  const auto result = prepare_interlevel_attributes(host,writer.bytes(),output);
  require(result.status == InterlevelAttributeStatus::applied && result.octets == 55U);
  const auto metadata = prefix_metadata(host,std::span{output}.first(result.octets));
  require(metadata && metadata->flags == PrefixAttributeFlags{true,true,true} &&
      metadata->source_ipv4 == ip::parse_ip_address("192.0.2.9") &&
      metadata->source_ipv6 == ip::parse_ip_address("2001:db8::9") && metadata->first_tag32 == 0U);
  TlvCursor cursor(std::span{output}.first(result.octets));
  const auto canonical = cursor.next();
  require(canonical && canonical->code == 4U && canonical->value.size() == 1U && canonical->value[0U] == 0xe0U);
  require(cursor.next()->code == 11U && cursor.next()->code == 12U);
  for (unsigned i{}; i < 2U; ++i) {
    const auto list = cursor.next();
    require(list && list->code == 1U && list->value.size() == 12U);
    AdministrativeTagCursor values(*list);
    for (const auto tag : tags) require(values.next()->value == tag);
  }
  require(!cursor.next() && cursor.valid());
  const auto retained = output;
  require(prepare_interlevel_attributes(host,writer.bytes(),std::span{output}.first(result.octets-1U)).status ==
      InterlevelAttributeStatus::capacity && output == retained);
  const std::array<std::uint8_t,3U> broken{1U,4U,0U};
  require(prepare_interlevel_attributes(host,broken,output).status == InterlevelAttributeStatus::invalid && output == retained);
  const auto v6 = *ip::parse_ip_prefix("2001:db8::/64");
  require(prepare_interlevel_attributes(v6,writer.bytes(),output).status == InterlevelAttributeStatus::applied);
  const auto v6flags = prefix_metadata(v6,std::span{output}.first(result.octets));
  require(v6flags && v6flags->flags == PrefixAttributeFlags{false,true,false});
  TlvWriter many(input);
  std::array<std::uint32_t,63U> long_tags{};
  long_tags[0U] = 17U; long_tags[62U] = 99U;
  require(encode_administrative_tags(many,long_tags) && encode_administrative_tags(many,long_tags));
  const auto joined = prepare_interlevel_attributes(host,many.bytes(),output);
  require(joined.status == InterlevelAttributeStatus::applied && joined.octets == 515U);
  TlvCursor parts(std::span{output}.first(joined.octets));
  require(parts.next()->code == 4U);
  for (unsigned i{}; i < 2U; ++i) {
    const auto first = parts.next(), last = parts.next();
    require(first && first->value.size() == 240U && last && last->value.size() == 12U);
    AdministrativeTagCursor head(*first), tail(*last);
    require(head.next()->value == 17U);
    require(tail.next()->value == 0U && tail.next()->value == 0U && tail.next()->value == 99U);
  }
  require(!parts.next() && parts.valid());
  InterlevelPrefixParts encoded({host,maximum_path_metric,false,false,true,
      std::span{output}.first(joined.octets)});
  require(encoded.valid());
  std::array<std::uint8_t,1024U> reassembled{};
  std::size_t octets{}, part_count{};
  while (const auto part = encoded.next()) {
    TlvCursor outer(*part);
    const auto option = outer.next();
    require(option && option->code == 135U && !outer.next() && outer.valid());
    ExtendedPrefixCursor entries(*option);
    const auto entry = entries.next();
    require(entry && entry->prefix == host && entry->metric == maximum_path_metric && !entry->down &&
        !entries.next() && entries.valid());
    std::copy(entry->sub_tlvs.begin(),entry->sub_tlvs.end(),reassembled.begin()+octets);
    octets += entry->sub_tlvs.size(); ++part_count;
  }
  require(encoded.valid() && part_count == 4U && octets == joined.octets &&
      std::equal(reassembled.begin(),reassembled.begin()+octets,output.begin()));
  InterlevelPrefixParts empty({v6,17U,false,true,false,{}});
  require(empty.valid() && empty.next() && !empty.next());
  InterlevelPrefixParts down({host,17U,true,false,false,{}});
  require(!down.valid() && !down.next());
  InterlevelPrefixParts oversized({host,17U,false,false,true,many.bytes()});
  require(!oversized.valid() && !oversized.next());
  const auto joined6 = prepare_interlevel_attributes(v6,many.bytes(),output);
  require(joined6.status == InterlevelAttributeStatus::applied);
  InterlevelPrefixParts encoded6({v6,23U,false,true,true,std::span{output}.first(joined6.octets)});
  require(encoded6.valid());
  octets = part_count = 0U;
  while (const auto part = encoded6.next()) {
    TlvCursor outer(*part);
    const auto option = outer.next();
    require(option && option->code == 236U && !outer.next() && outer.valid());
    ExtendedPrefixCursor entries(*option);
    const auto entry = entries.next();
    require(entry && entry->prefix == v6 && entry->metric == 23U && entry->external && !entry->down &&
        !entries.next() && entries.valid());
    octets += entry->sub_tlvs.size(); ++part_count;
  }
  require(part_count == 5U && octets == joined6.octets);
  InterlevelPrefixParts malformed({host,17U,false,false,true,broken});
  require(!malformed.valid() && !malformed.next());
  auto noncanonical = host;
  noncanonical.length = 24U;
  InterlevelPrefixParts invalid_prefix({noncanonical,17U,false,false,false,{}});
  require(!invalid_prefix.valid() && !invalid_prefix.next());
  InterlevelPrefixParts excessive_metric({host,maximum_path_metric+1U,false,false,false,{}});
  require(!excessive_metric.valid() && !excessive_metric.next());
  const std::array<std::uint8_t,9U> invalid_values{1U,1U,0U,11U,1U,0U,4U,1U,0U};
  const auto ignored = prepare_interlevel_attributes(host,invalid_values,output);
  require(ignored.status == InterlevelAttributeStatus::applied && ignored.octets == 3U && output[2U] == 0x40U);
}
