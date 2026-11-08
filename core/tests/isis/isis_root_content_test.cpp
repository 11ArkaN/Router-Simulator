// Root semantic preparation is checked through wire cursors and fragmentation.
// Tests own all inputs; no protocol state or topology knowledge enters packing.
#include "router/isis_root_content.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_origin_fragment_workspace.hpp"
#include "router/isis_narrow_reachability.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS root content invariant"); }
}
void isis_root_content_tests() {
  using namespace router;
  using namespace router::isis;
  namespace wire = packet::isis;
  const std::array areas{*parse_configured_area("49.0001"), *parse_configured_area("49.0002")};
  const std::array<packet::Ipv4, 2U> addresses{{{10U, 0U, 0U, 1U}, {10U, 0U, 0U, 2U}}};
  RootContentInput input;
  input.local = {1U, 2U, 3U, 4U, 5U, 6U}; input.flags = 0x7fU;
  input.ipv4 = input.ipv6 = true; input.areas = areas; input.ipv4_addresses = addresses;
  input.hostname = "R1";
  std::vector<RootPrefix> prefixes;
  for (std::uint8_t index{}; index < 20U; ++index) {
    ip::IpPrefix prefix; prefix.network.bytes[0U] = 10U; prefix.network.bytes[1U] = index;
    prefix.length = 16U;
    prefixes.push_back({prefix, 30U, std::uint8_t{30U}});
  }
  const auto ipv6 = *ip::parse_ip_prefix("2001:db8::/32");
  prefixes.push_back({ipv6, 10U, {}}); input.prefixes = prefixes;
  const auto result = prepare_root_content(input, 100U, 8U);
  require(result.status == RootContentStatus::prepared && result.records.size() > 1U);
  std::size_t area_count{}, wide4{}, wide6{}, narrow4{}, hostnames{}, protocols{}, address_count{};
  for (const auto &record : result.records) {
    require(record.options.size() <= 100U && record.id[6U] == 0U && record.active);
    require(record.flags == (record.id[7U] ? 3U : input.flags));
    wire::TlvCursor cursor(record.options);
    while (const auto option = cursor.next()) {
      if (option->code == 1U) {
        require(record.id[7U] == 0U); wire::AreaAddressCursor area(*option);
        while (area.next()) ++area_count; require(area.valid());
      } else if (option->code == 135U || option->code == 236U) {
        wire::ExtendedPrefixCursor prefix(*option);
        while (const auto value = prefix.next()) {
          require(!value->down && !value->external);
          if (option->code == 135U) { ++wide4; require(value->metric == 30U); }
          else { ++wide6; require(value->prefix == ipv6); }
        }
        require(prefix.valid());
      } else if (option->code == 128U) {
        wire::NarrowIpv4Cursor prefix(*option);
        while (const auto value = prefix.next()) { ++narrow4; require(value->metrics.metric == 30U); }
        require(prefix.valid());
      } else if (option->code == 137U) {
        ++hostnames; require(option->value.size() == 2U && option->value[0U] == 'R');
      } else if (option->code == 129U) {
        ++protocols; require(wire::supports_protocol(*option, wire::ipv4_nlpid) &&
            wire::supports_protocol(*option, wire::ipv6_nlpid));
      } else if (option->code == 132U) {
        wire::FixedAddressCursor<4U> address(*option, 132U);
        while (address.next()) ++address_count; require(address.valid());
      } else require(false);
    }
    require(cursor.valid());
  }
  require(area_count == 2U && wide4 == 20U && narrow4 == 20U && wide6 == 1U &&
      hostnames == 1U && protocols == 1U && address_count == 2U);
  require(prepare_root_content(input, 100U, 1U).status == RootContentStatus::capacity);
  auto invalid = input; invalid.level = 2U;
  require(prepare_root_content(invalid, 100U, 8U).records.empty());
  invalid = input; invalid.ipv4 = false;
  require(prepare_root_content(invalid, 100U, 8U).status == RootContentStatus::invalid);
  std::swap(prefixes[0U], prefixes[1U]);
  require(prepare_root_content(input, 100U, 8U).status == RootContentStatus::invalid);
  std::swap(prefixes[0U], prefixes[1U]); prefixes[0U].narrow = std::uint8_t{64U};
  require(prepare_root_content(input, 100U, 8U).records.empty());
  prefixes[0U].narrow = std::uint8_t{30U}; prefixes[0U].prefix.network.bytes[3U] = 1U;
  require(prepare_root_content(input, 100U, 8U).records.empty());
  prefixes[0U].prefix.network.bytes[3U] = 0U;
  std::array<packet::Ipv6, 1U> link_local{*ip::parse_ipv6("fe80::1")};
  invalid = input; invalid.ipv6_addresses = link_local;
  require(prepare_root_content(invalid, 100U, 8U).records.empty());
  const std::string non_ascii(1U, static_cast<char>(0x80U));
  invalid = input; invalid.hostname = non_ascii;
  require(prepare_root_content(invalid, 100U, 8U).status == RootContentStatus::invalid);
  const std::string too_long(256U, 'r'); invalid.hostname = too_long;
  require(prepare_root_content(invalid, 100U, 8U).records.empty());
  RootContentInput empty; empty.local = input.local;
  const auto zero = prepare_root_content(empty, 100U, 1U);
  require(zero.status == RootContentStatus::prepared && zero.records.size() == 1U && zero.records[0U].options.empty());
  std::vector<packet::Ipv4> many(64U);
  for (std::size_t index{}; index < many.size(); ++index) many[index] = {10U, 0U, 0U, static_cast<std::uint8_t>(index)};
  empty.ipv4 = true; empty.ipv4_addresses = many;
  const auto chunks = prepare_root_content(empty, 300U, 2U);
  require(chunks.status == RootContentStatus::prepared);
  std::size_t lists{};
  for (const auto &record : chunks.records) {
    wire::TlvCursor cursor(record.options);
    while (const auto option = cursor.next()) if (option->code == 132U) ++lists;
  }
  require(lists == 2U);
  invalid = empty; invalid.flags = 2U;
  require(prepare_root_content(invalid, 300U, 2U).records.empty());
  invalid.flags = 1U; invalid.level = 1U;
  require(prepare_root_content(invalid, 300U, 2U).records.empty());
  invalid.flags = 3U;
  require(prepare_root_content(invalid, 300U, 2U).status == RootContentStatus::prepared);

  // A full root must survive a smaller effective budget (for authentication
  // overhead) plus a new adjacency by relocating complete movable TLVs.
  std::array<std::uint8_t, 484U> full{};
  wire::TlvWriter full_writer(full);
  const std::array<std::span<const std::uint8_t>, 1U> one_area{areas[0U].view()};
  const std::array<std::uint8_t, 237U> metadata{};
  require(wire::encode_area_addresses(full_writer, one_area) &&
      full_writer.append(250U, metadata) && full_writer.append(251U, metadata));
  require(full_writer.bytes().size() == full.size());
  LocalLspProgram local_program; local_program.random = 123U;
  local_program.levels[0U] = LocalLspLevelProgram{1200U, 512U,
      std::chrono::seconds{1U}, std::chrono::seconds{600U}};
  wire::LspId root_id{}; std::copy(input.local.begin(), input.local.end(), root_id.begin());
  local_program.records.push_back({0U, root_id, 1U, {full.begin(), full.end()}, true});
  auto extra_id = root_id; extra_id[7U] = 1U;
  local_program.records.push_back({0U, extra_id, 1U, {}, false});
  const auto now = RuntimeClock::now();
  LocalLspSet local(input.local, 3U, {wire::InstanceFormat::standard, 0U}, local_program, now);
  OriginFragmentWorkspace workspace(4U, 2U, 485U);
  require(workspace.add_root_options(local_program, 0U));
  require(workspace.add_link({1U, 1U}, {6U, 5U, 4U, 3U, 2U, 1U, 0U}, {10U, {}}, {}));
  require(workspace.compose(local, 0U, {1U, 2U, 3U, 4U, 5U, 6U, 0U}, 1U, 2U, 460U, now) == LocalContentResult::changed);
  require(local.contains(0U, extra_id));
  const auto root_fragment = local.fragment(0U, root_id);
  const auto extra_fragment = local.fragment(0U, extra_id);
  require(root_fragment && extra_fragment);
  for (const auto &fragment : {*root_fragment, *extra_fragment}) {
    wire::TlvCursor cursor(fragment.options);
    while (const auto option = cursor.next()) if (option->code == 1U) require(fragment.number == 0U);
    require(cursor.valid());
  }
}
