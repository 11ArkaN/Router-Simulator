// BOF out-of-band autoconfiguration intent for SR OS 26.7.R1. LabRuntime owns
// these candidate and running values. The management EndpointStack owns live
// DHCP, RA, ND and address state after a boot-effective publish.

#pragma once

#include "router/sha256.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace router::bof {

enum class Dhcpv6ClientType : std::uint8_t {
  duid_enterprise,
  duid_link_local
};

struct DhcpClientIntent {
  // client_id is the administrator-provided opaque value. Empty means the
  // platform-derived stable chassis identity, not an empty wire identifier.
  std::string client_id;
  // Hexadecimal input retains its 0x-prefixed lexical form so boot activation
  // can decode opaque bytes rather than sending the ASCII hex spelling.
  bool client_id_hex{};
  std::uint16_t timeout_seconds{30U};
  bool enabled{};
  bool include_user_class{};

  bool operator==(const DhcpClientIntent &) const = default;
};

struct Dhcpv6ClientIntent : DhcpClientIntent {
  Dhcpv6ClientType client_type{Dhcpv6ClientType::duid_enterprise};

  bool operator==(const Dhcpv6ClientIntent &) const = default;
};

struct AutoconfigureIntent {
  DhcpClientIntent ipv4;
  Dhcpv6ClientIntent ipv6;
  // These secrets are generated from the operating-system CSPRNG once and
  // retained with portable configuration. They are never rendered by info,
  // show, telemetry or project JSON.
  crypto::Sha256Digest ipv4_transaction_secret{};
  crypto::Sha256Digest ipv6_transaction_secret{};

  bool operator==(const AutoconfigureIntent &) const = default;
};

[[nodiscard]] inline bool valid(const AutoconfigureIntent &intent) noexcept {
  const auto present = [](const crypto::Sha256Digest &secret) {
    for (const auto byte : secret)
      if (byte != 0U)
        return true;
    return false;
  };
  const auto valid_common = [](const DhcpClientIntent &client,
                               std::size_t maximum) {
    return client.timeout_seconds >= 1U &&
           client.client_id.size() <=
               (client.client_id_hex ? maximum * 2U + 2U : maximum);
  };
  return valid_common(intent.ipv4, 127U) &&
         valid_common(intent.ipv6, 124U) &&
         (!intent.ipv4.enabled || present(intent.ipv4_transaction_secret)) &&
         (!intent.ipv6.enabled || present(intent.ipv6_transaction_secret));
}

} // namespace router::bof
