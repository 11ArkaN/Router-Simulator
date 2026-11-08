// Local root semantics are staged before any protocol owner is published.
// Existing typed wire encoders validate values and the common planner assigns
// whole TLV units. Returned values own their bytes and borrow no configuration.
#include "router/isis_root_content.hpp"
#include "router/isis_fragment_plan.hpp"
#include "router/isis_narrow_reachability.hpp"
#include <algorithm>
#include <array>
#include <type_traits>
#include <tuple>
namespace router::isis {
namespace {
struct Unit { std::vector<std::uint8_t> bytes; bool root{}; };
template<class Address>
bool ordered(std::span<const Address> values) {
  return std::adjacent_find(values.begin(), values.end(),
      [](const auto &a, const auto &b) { return a >= b; }) == values.end();
}
}
RootContentResult prepare_root_content(const RootContentInput &input,
    std::size_t semantic_octets, std::size_t fragments) {
  namespace wire = packet::isis;
  const auto system_type = input.flags & 3U;
  if (input.level > 1U || (system_type != 1U && system_type != 3U) ||
      (input.level == 1U && system_type != 3U) || !fragments || fragments > 256U ||
      !semantic_octets || semantic_octets > 65535U - wire::lsp_header_octets ||
      std::all_of(input.local.begin(), input.local.end(), [](auto value) { return value == 0U; }) ||
      input.hostname.size() > 255U || std::any_of(input.hostname.begin(), input.hostname.end(),
          [](unsigned char value) { return value > 0x7fU; }) || input.areas.size() > 3U ||
      (!input.ipv4 && !input.ipv4_addresses.empty()) || (!input.ipv6 && !input.ipv6_addresses.empty()) ||
      !ordered(input.ipv4_addresses) || !ordered(input.ipv6_addresses)) return {};
  std::vector<Unit> encoded;
  // At most three metadata units plus address-list chunks and prefix pairs.
  // Each encoder stages no more than a TLV value; all larger storage is cold.
  const auto add = [&](bool root, const auto &encode) {
    std::array<std::uint8_t, 514U> bytes{};
    wire::TlvWriter writer(bytes);
    if (!encode(writer)) return false;
    encoded.push_back({{writer.bytes().begin(), writer.bytes().end()}, root});
    return true;
  };
  if (!input.areas.empty()) {
    std::array<std::span<const std::uint8_t>, 3U> areas{};
    for (std::size_t index{}; index < input.areas.size(); ++index) {
      const auto &area = input.areas[index];
      if (!area.length || area.length > area.bytes.size() ||
          std::any_of(area.bytes.begin() + area.length, area.bytes.end(), [](auto value) { return value != 0U; })) return {};
      areas[index] = area.view();
      for (std::size_t prior{}; prior < index; ++prior)
        if (input.areas[prior] == area) return {};
    }
    if (!add(true, [&](auto &writer) { return wire::encode_area_addresses(writer,
        std::span{areas}.first(input.areas.size())); })) return {};
  }
  if (input.ipv4 || input.ipv6) {
    const std::array<std::uint8_t, 2U> protocols{input.ipv4 ? wire::ipv4_nlpid : wire::ipv6_nlpid, wire::ipv6_nlpid};
    if (!add(false, [&](auto &writer) { return writer.append(129U,
        std::span{protocols}.first(input.ipv4 && input.ipv6 ? 2U : 1U)); })) return {};
  }
  if (!input.hostname.empty() && !add(false, [&](auto &writer) {
      return writer.append(137U, {reinterpret_cast<const std::uint8_t *>(input.hostname.data()), input.hostname.size()}); })) return {};
  const auto addresses = [&](const auto &values, std::uint8_t code) {
    using Address = typename std::remove_cvref_t<decltype(values)>::element_type;
    constexpr auto width = std::tuple_size_v<std::remove_const_t<Address>>;
    for (std::size_t offset{}; offset < values.size();) {
      const auto count = std::min(std::size_t{255U / width}, values.size() - offset);
      if (!add(false, [&](auto &writer) {
          return wire::encode_fixed_addresses<width>(writer, code, values.subspan(offset, count)); })) return false;
      offset += count;
    }
    return true;
  };
  if (!addresses(input.ipv4_addresses, 132U) || !addresses(input.ipv6_addresses, 232U)) return {};
  for (std::size_t index{}; index < input.prefixes.size(); ++index) {
    const auto &prefix = input.prefixes[index];
    const bool ipv6 = prefix.prefix.network.family == ip::AddressFamily::ipv6;
    if ((index && input.prefixes[index - 1U].prefix >= prefix.prefix) ||
        (ipv6 ? !input.ipv6 : !input.ipv4) || (prefix.narrow && (ipv6 || *prefix.narrow > 63U))) return {};
    if (!add(false, [&](auto &writer) {
        if (!wire::encode_extended_prefix(writer, {prefix.prefix, prefix.metric, false, false, false, {}})) return false;
        if (!prefix.narrow) return true;
        wire::NarrowIpv4 narrow;
        narrow.metrics.metric = *prefix.narrow;
        std::copy_n(prefix.prefix.network.bytes.begin(), 4U, narrow.address.begin());
        for (std::size_t bit{}; bit < prefix.prefix.length; ++bit)
          narrow.mask[bit / 8U] |= static_cast<std::uint8_t>(0x80U >> (bit % 8U));
        return wire::encode_narrow_ipv4(writer, narrow);
      })) return {};
  }
  // IPv6 LSP address TLVs must exclude link-local addresses (RFC 5308).
  for (const auto &unit : encoded) {
    wire::TlvCursor cursor(unit.bytes);
    while (const auto option = cursor.next())
      if (option->code == 232U && !wire::valid_ipv6_interface_addresses(*option, wire::PduType::lsp_l1)) return {};
  }
  std::vector<FragmentUnit> units;
  units.reserve(encoded.size());
  for (std::size_t index{}; index < encoded.size(); ++index)
    units.push_back({FragmentUnitId{index}, encoded[index].bytes, {}, encoded[index].root});
  std::vector<std::vector<std::uint8_t>> storage(fragments);
  std::vector<FragmentOptions> output; output.reserve(fragments);
  for (auto &bytes : storage) { bytes.resize(semantic_octets); output.push_back({bytes, 0U}); }
  FragmentPlanner planner(units.size());
  const auto planned = planner.compose(units, semantic_octets, false, output);
  if (planned != FragmentPlanStatus::planned)
    return {planned == FragmentPlanStatus::capacity ? RootContentStatus::capacity : RootContentStatus::invalid, {}};
  RootContentResult result{RootContentStatus::prepared, {}};
  for (std::size_t index{}; index < output.size(); ++index) {
    if (index && !output[index].size) continue;
    packet::isis::LspId id{}; std::copy(input.local.begin(), input.local.end(), id.begin());
    id[7U] = static_cast<std::uint8_t>(index);
    storage[index].resize(output[index].size);
    result.records.push_back({input.level, id, index ? static_cast<std::uint8_t>(input.flags & 3U) : input.flags,
        std::move(storage[index]), true});
  }
  return result;
}
}
