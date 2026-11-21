// The prefix decision owner joins independently valid RFC 9885 parts.
// Cold-reserved scratch borrows its own staged values only; the LSDB and last
// published generation remain immutable until the enclosing transaction commits.
#include "router/isis_prefix_set.hpp"
#include "router/isis_prefix_attributes.hpp"
#include <tuple>
namespace router::isis {
namespace {
auto object_key(const PrefixAdvertisement &value) noexcept {
  packet::isis::LanId source{};
  std::copy_n(value.origin.begin(), source.size(), source.begin());
  return std::tuple{source, value.level, value.prefix};
}
}
PrefixSetStatus ExtendedPrefixSet::merge_parts() noexcept {
  part_order_.clear(); merged_.entries.clear(); merged_.attributes.clear();
  merged_.ignored = working_.ignored;
  for (std::size_t index{}; index < working_.entries.size(); ++index)
    part_order_.push_back(static_cast<std::uint32_t>(index));
  std::sort(part_order_.begin(), part_order_.end(), [&](auto left, auto right) {
    const auto &a = working_.entries[left], &b = working_.entries[right];
    const auto ak = object_key(a), bk = object_key(b);
    if (ak != bk) return ak < bk;
    // Fragments need not have arrived in this order. Original indexes also
    // distinguish repeated empty-attribute parts in the same LSP.
    return a.origin != b.origin ? a.origin < b.origin : left < right;
  });
  for (std::size_t first{}; first < part_order_.size();) {
    const auto &selected = working_.entries[part_order_[first]];
    const auto key = object_key(selected);
    auto end = first + 1U;
    while (end < part_order_.size() && object_key(working_.entries[part_order_[end]]) == key) ++end;
    // An unusable first metric cannot be replaced by a cheaper conflicting
    // later part. The original wire remains retained in the LSDB.
    if (selected.metric <= packet::isis::maximum_path_metric) {
      auto joined = selected;
      joined.attributes_offset = static_cast<std::uint32_t>(merged_.attributes.size());
      std::size_t count{};
      for (auto part = first; part < end; ++part) {
        const auto &entry = working_.entries[part_order_[part]];
        if (entry.attributes_size > std::numeric_limits<std::uint16_t>::max() - count)
          return PrefixSetStatus::capacity;
        count += entry.attributes_size;
        const auto bytes = std::span{working_.attributes}.subspan(entry.attributes_offset, entry.attributes_size);
        merged_.attributes.insert(merged_.attributes.end(), bytes.begin(), bytes.end());
      }
      joined.attributes_size = static_cast<std::uint16_t>(count);
      const auto metadata = packet::isis::prefix_metadata(joined.prefix,
          std::span{merged_.attributes}.subspan(joined.attributes_offset, count));
      if (!metadata) return PrefixSetStatus::malformed_database;
      if (joined.prefix.network.family == ip::AddressFamily::ipv4)
        joined.external = metadata->flags && metadata->flags->external;
      merged_.entries.push_back(joined);
    }
    first = end;
  }
  std::swap(working_, merged_);
  return PrefixSetStatus::applied;
}
}
