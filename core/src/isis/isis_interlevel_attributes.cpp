// Canonical interlevel attributes are preflighted before any output byte changes.
// The calling instance owns both spans and all export policy; no LSDB is borrowed.
// Source: ietf.isis.selected_interlevel_export
#include "router/isis_interlevel_attributes.hpp"
#include <algorithm>
namespace router::isis {
InterlevelAttributeResult prepare_interlevel_attributes(const ip::IpPrefix &prefix,
    std::span<const std::uint8_t> input, std::span<std::uint8_t> output) noexcept {
  using namespace packet::isis;
  const auto metadata = prefix_metadata(prefix, input);
  if (!metadata) return {};
  const auto part_capacity = 255U - (prefix.network.family == ip::AddressFamily::ipv6 ? 7U : 6U) -
      (prefix.length + 7U) / 8U;
  const auto tag_chunk = [&](const TlvView &option) {
    const std::size_t width = option.code == 1U ? 4U : 8U;
    return ((part_capacity - 2U) / width) * width;
  };
  std::size_t required = 3U + (metadata->source_ipv4 ? 6U : 0U) + (metadata->source_ipv6 ? 18U : 0U);
  TlvCursor preflight(input);
  while (const auto option = preflight.next()) {
    AdministrativeTagCursor tags(*option);
    if (tags.valid()) {
      const auto chunk = tag_chunk(*option);
      const auto octets = option->value.size() + 2U * ((option->value.size() + chunk - 1U) / chunk);
      if (octets > output.size() || required > output.size() - octets)
        return {InterlevelAttributeStatus::capacity, 0U};
      required += octets;
    }
  }
  if (required > output.size()) return {InterlevelAttributeStatus::capacity, 0U};
  auto flags = metadata->flags.value_or(PrefixAttributeFlags{});
  flags.readvertised = true;
  TlvWriter writer(output);
  if (!encode_prefix_attribute_flags(writer, prefix, flags)) std::terminate();
  if (metadata->source_ipv4 && !encode_prefix_source_router_id(writer, *metadata->source_ipv4)) std::terminate();
  if (metadata->source_ipv6 && !encode_prefix_source_router_id(writer, *metadata->source_ipv6)) std::terminate();
  TlvCursor cursor(input);
  while (const auto option = cursor.next()) {
    AdministrativeTagCursor tags(*option);
    if (!tags.valid()) continue;
    auto remaining = option->value;
    while (!remaining.empty()) {
      const auto count = std::min(remaining.size(), tag_chunk(*option));
      if (!writer.append(option->code, remaining.first(count))) std::terminate();
      remaining = remaining.subspan(count);
    }
  }
  return {InterlevelAttributeStatus::applied, writer.bytes().size()};
}
InterlevelPrefixParts::InterlevelPrefixParts(packet::isis::ExtendedPrefix prefix) noexcept
    : prefix_(prefix), remaining_(prefix.sub_tlvs) {
  using namespace packet::isis;
  TlvWriter probe(bytes_);
  auto fixed = prefix;
  fixed.sub_tlvs = {};
  fixed.sub_tlvs_present = false;
  if (prefix.down || prefix.metric > maximum_path_metric ||
      (!prefix.sub_tlvs_present && !prefix.sub_tlvs.empty()) || !encode_extended_prefix(probe,fixed)) return;
  capacity_ = 255U - (prefix.prefix.network.family == ip::AddressFamily::ipv6 ? 7U : 6U) -
      (prefix.prefix.length + 7U) / 8U;
  TlvCursor cursor(remaining_);
  while (const auto option = cursor.next()) if (option->value.size() + 2U > capacity_) return;
  valid_ = cursor.valid();
}
std::optional<std::span<const std::uint8_t>> InterlevelPrefixParts::next() noexcept {
  if (!valid_ || (!first_ && remaining_.empty())) return std::nullopt;
  first_ = false;
  std::size_t count{};
  packet::isis::TlvCursor cursor(remaining_);
  while (const auto option = cursor.next()) {
    const auto size = option->value.size() + 2U;
    if (size > capacity_ - count) break;
    count += size;
  }
  auto part = prefix_;
  part.sub_tlvs = remaining_.first(count);
  part.sub_tlvs_present = !part.sub_tlvs.empty();
  packet::isis::TlvWriter writer(bytes_);
  if (!packet::isis::encode_extended_prefix(writer,part)) std::terminate();
  remaining_ = remaining_.subspan(count);
  return writer.bytes();
}

}
