// Last complete prefix advertisements belong to one instance decision owner.
// Unknown sub-TLV bytes retain their order; packet framing and prefix bounds
// validate before replacement within the owner's existing cold capacity.

#include "router/isis_prefix_set.hpp"

namespace router::isis {
PrefixSetCheckpoint ExtendedPrefixSet::checkpoint() const {
  if (prepared_) throw std::invalid_argument("IS-IS prefix checkpoint during prepared transaction");
  return {1U, {maximum_prefixes_, maximum_attributes_}, published_.entries, published_.attributes, published_.ignored};
}
bool ExtendedPrefixSet::restore(const PrefixSetCheckpoint &saved) noexcept {
  if (prepared_ || saved.version != 1U || saved.budget != PrefixCollectionBudget{maximum_prefixes_, maximum_attributes_} ||
      saved.entries.size() > maximum_prefixes_ || saved.attributes.size() > maximum_attributes_) return false;
  std::size_t offset{};
  for (const auto &entry : saved.entries) {
    const auto family = entry.prefix.network.family;
    if ((family != ip::AddressFamily::ipv4 && family != ip::AddressFamily::ipv6) ||
        entry.prefix.length > (family == ip::AddressFamily::ipv4 ? 32U : 128U) ||
        (family == ip::AddressFamily::ipv4 && std::any_of(entry.prefix.network.bytes.begin() + 4,
            entry.prefix.network.bytes.end(), [](std::uint8_t byte) { return byte != 0U; })) ||
        ip::mask(entry.prefix.network, entry.prefix.length) != entry.prefix.network ||
        (family == ip::AddressFamily::ipv6 && entry.external) ||
        (entry.attributes_size && entry.attributes_size > 255U -
            (family == ip::AddressFamily::ipv4 ? 5U : 6U) - (entry.prefix.length + 7U) / 8U - 1U) ||
        (family == ip::AddressFamily::ipv6 && entry.prefix.length >= 10U && ip::is_link_local(entry.prefix.network.bytes)) ||
        entry.origin[6U] || (entry.level != 1U && entry.level != 2U) ||
        entry.metric > packet::isis::maximum_path_metric || entry.attributes_offset != offset ||
        entry.attributes_size > saved.attributes.size() - offset) return false;
    packet::isis::TlvCursor attributes(std::span{saved.attributes}.subspan(offset, entry.attributes_size));
    while (attributes.next()) {}
    if (!attributes.valid()) return false;
    offset += entry.attributes_size;
  }
  if (offset != saved.attributes.size()) return false;
  published_.entries.assign(saved.entries.begin(), saved.entries.end());
  published_.attributes.assign(saved.attributes.begin(), saved.attributes.end());
  published_.ignored = saved.ignored;
  return true;
}
} // namespace router::isis
