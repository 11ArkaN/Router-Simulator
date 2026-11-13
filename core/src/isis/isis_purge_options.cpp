// Registry-based purge acceptance is separate from authentication verification.
// POI value parsing cannot discard the enclosing LSP. All memory is caller-owned.
// Sources: ietf.isis.purge_options, iana.isis.tlv_purge_registry

#include "router/isis_purge_options.hpp"
#include "router/generated_isis_tlv_registry.hpp"

#include <algorithm>

namespace router::isis {
PurgeValidation validate_purge_options(std::span<const std::uint8_t> options, PurgeRules rules) noexcept {
  using namespace packet::isis;
  if (rules > PurgeRules::registry_6233) return PurgeValidation::invalid_policy;
  bool prohibited{}, unknown{}, poi{};
  TlvCursor cursor(options);
  while (const auto option = cursor.next()) {
    poi = poi || option->code == 13U;
    if (rules == PurgeRules::iso_10589) continue;
    if (rules == PurgeRules::authentication_only) prohibited = prohibited || option->code != 10U;
    else {
      const auto bit = std::uint64_t{1U} << (option->code & 63U);
      const bool registered = (registered_tlv_codes[option->code >> 6U] & bit) != 0U;
      prohibited = prohibited || (registered && (purge_tlv_codes[option->code >> 6U] & bit) == 0U);
      unknown = unknown || !registered;
    }
  }
  if (!cursor.valid()) return PurgeValidation::malformed;
  if (prohibited) return PurgeValidation::prohibited_option;
  if (unknown && !poi) return PurgeValidation::unknown_without_poi;
  return PurgeValidation::accepted;
}

std::optional<PurgeOriginator> decode_purge_originator(packet::isis::TlvView option) noexcept {
  if (option.code != 13U || option.value.empty() || option.value[0U] < 1U || option.value[0U] > 2U ||
      option.value.size() != 1U + 6U * option.value[0U]) return std::nullopt;
  PurgeOriginator result;
  std::copy_n(option.value.begin() + 1U, 6U, result.originator.begin());
  if (option.value[0U] == 2U) {
    result.received_from.emplace();
    std::copy_n(option.value.begin() + 7U, 6U, result.received_from->begin());
  }
  return result;
}

bool encode_purge_originator(packet::isis::TlvWriter &writer, const PurgeOriginator &originator) noexcept {
  std::array<std::uint8_t, 13U> bytes{};
  bytes[0U] = originator.received_from ? 2U : 1U;
  std::copy(originator.originator.begin(), originator.originator.end(), bytes.begin() + 1U);
  if (originator.received_from)
    std::copy(originator.received_from->begin(), originator.received_from->end(), bytes.begin() + 7U);
  return writer.append(13U, std::span(bytes).first(1U + 6U * bytes[0U]));
}
} // namespace router::isis
