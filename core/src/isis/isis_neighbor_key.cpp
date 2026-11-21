// Canonical local/remote link identifiers distinguish RFC 9885 neighbor parts.
// All scratch is call-local and every output byte commits after validation.
#include "router/isis_neighbor_key.hpp"
#include "router/generated_isis_tlv_registry.hpp"
#include <algorithm>
namespace router::packet::isis {
std::optional<std::size_t> normalize_neighbor_key(std::span<const std::uint8_t> attributes,
    std::span<std::uint8_t> output) noexcept {
  if (attributes.size() > maximum_neighbor_key_octets) return std::nullopt;
  if (attributes.empty()) return 0U;
  struct Identifier { std::uint8_t code{}; std::span<const std::uint8_t> value; };
  // Four-octet addresses plus framing are the shortest recognized identifiers.
  std::array<Identifier, maximum_neighbor_key_octets / 6U> identifiers{};
  std::size_t count{}, link_ids{};
  TlvCursor cursor(attributes);
  while (const auto option = cursor.next()) {
    if (option->code == 4U) ++link_ids;
    const auto width = option->code == 4U ? 8U : option->code == 6U || option->code == 8U ? 4U :
        option->code == 12U || option->code == 13U ? 16U : 0U;
    if (!width || option->value.size() != width) continue;
    if (width == 16U) {
      ip::Ipv6 address{};
      std::copy(option->value.begin(), option->value.end(), address.begin());
      if (ip::is_link_local(address)) continue;
    }
    identifiers[count++] = {option->code, option->value};
  }
  if (!cursor.valid()) return std::nullopt;
  auto end = identifiers.begin() + count;
  if (link_ids > 1U) end = std::remove_if(identifiers.begin(), end, [](const auto &entry) { return entry.code == 4U; });
  std::sort(identifiers.begin(), end, [](const auto &a, const auto &b) {
    return a.code != b.code ? a.code < b.code :
        std::lexicographical_compare(a.value.begin(), a.value.end(), b.value.begin(), b.value.end());
  });
  end = std::unique(identifiers.begin(), end, [](const auto &a, const auto &b) {
    return a.code == b.code && std::ranges::equal(a.value, b.value);
  });
  std::array<std::uint8_t, maximum_neighbor_key_octets> staged;
  std::size_t size{};
  for (auto entry = identifiers.begin(); entry != end; ++entry) {
    staged[size++] = entry->code; staged[size++] = static_cast<std::uint8_t>(entry->value.size());
    std::copy(entry->value.begin(), entry->value.end(), staged.begin() + size);
    size += entry->value.size();
  }
  if (output.size() < size) return std::nullopt;
  std::copy_n(staged.begin(), size, output.begin());
  return size;
}
static_assert(multipart_applicability(MultipartContext::neighbor, 4U) == MultipartApplicability::disallowed &&
    multipart_applicability(MultipartContext::neighbor, 6U) == MultipartApplicability::disallowed &&
    multipart_applicability(MultipartContext::neighbor, 8U) == MultipartApplicability::disallowed &&
    multipart_applicability(MultipartContext::neighbor, 12U) == MultipartApplicability::disallowed &&
    multipart_applicability(MultipartContext::neighbor, 13U) == MultipartApplicability::disallowed);
}
