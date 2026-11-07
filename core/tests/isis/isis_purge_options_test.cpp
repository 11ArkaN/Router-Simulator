// Purge policy separates registered prohibitions from unknown extensions. POI
// codecs validate their own values without rejecting the enclosing live LSP.

#include "router/isis_purge_options.hpp"

#include <array>
#include <stdexcept>
#include <source_location>
#include <string>

void isis_purge_options_tests() {
  using namespace router;
  using namespace router::isis;
  const auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS purge options failed at " + std::to_string(location.line()));
  };
  for (const auto code : {7U, 10U, 13U, 15U, 137U}) {
    const std::array bytes{static_cast<std::uint8_t>(code), std::uint8_t{0U}};
    require(validate_purge_options(bytes, PurgeRules::registry_6233) == PurgeValidation::accepted);
    require(validate_purge_options(bytes, PurgeRules::authentication_only) ==
        (code == 10U ? PurgeValidation::accepted : PurgeValidation::prohibited_option));
  }
  for (const auto code : {0U, 1U, 8U, 22U, 28U, 42U, 66U, 133U, 211U, 242U, 251U}) {
    const std::array bytes{std::uint8_t{13U}, std::uint8_t{0U}, static_cast<std::uint8_t>(code), std::uint8_t{0U}};
    require(validate_purge_options(bytes, PurgeRules::registry_6233) == PurgeValidation::prohibited_option);
    require(validate_purge_options(bytes, PurgeRules::iso_10589) == PurgeValidation::accepted);
  }
  for (const auto code : {26U, 65U, 67U, 136U, 146U, 255U}) {
    const std::array bytes{static_cast<std::uint8_t>(code), std::uint8_t{0U}, std::uint8_t{13U}, std::uint8_t{0U}};
    require(validate_purge_options(std::span(bytes).first(2U), PurgeRules::registry_6233) ==
        PurgeValidation::unknown_without_poi);
    // RFC 8918: POI value contents are a separate semantic check. Their
    // invalidity does not erase the registered TLV's presence in this purge.
    require(validate_purge_options(bytes, PurgeRules::registry_6233) == PurgeValidation::accepted);
    require(!decode_purge_originator({13U, std::span(bytes).subspan(4U)}));
  }
  const std::array<std::uint8_t, 2U> truncated{13U, 7U};
  require(validate_purge_options(truncated, PurgeRules::registry_6233) == PurgeValidation::malformed);
  require(validate_purge_options({}, static_cast<PurgeRules>(255U)) == PurgeValidation::invalid_policy);
  PurgeOriginator poi{{1U, 2U, 3U, 4U, 5U, 6U}, std::nullopt};
  std::array<std::uint8_t, 15U> output{};
  for (const bool upstream : {false, true}) {
    if (upstream) poi.received_from = packet::isis::SystemId{6U, 5U, 4U, 3U, 2U, 1U};
    packet::isis::TlvWriter writer(output);
    require(encode_purge_originator(writer, poi));
    packet::isis::TlvCursor cursor(writer.bytes());
    const auto option = cursor.next();
    require(option && decode_purge_originator(*option) == poi && !cursor.next() && cursor.valid());
    const auto size = upstream ? 15U : 9U;
    require(writer.bytes().size() == size);
    packet::isis::TlvWriter refused(std::span(output).first(size - 1U));
    require(!encode_purge_originator(refused, poi) && refused.bytes().empty());
    require(!decode_purge_originator({13U, option->value.first(option->value.size() - 1U)}));
  }
  for (const auto count : {0U, 3U}) {
    output[0U] = static_cast<std::uint8_t>(count);
    require(!decode_purge_originator({13U, output}));
  }
}
