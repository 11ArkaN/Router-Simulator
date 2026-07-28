// BOF CLI tests cover externally observable configuration semantics: the BOF
// root parses without a configure prefix, family-specific identifier limits
// reject atomically, and protocol identities come only from injected entropy.

#include "cli/bof_cli_configuration.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

class CountingEntropy final : public router::lab::bof_cli::EntropySource {
public:
  bool fill(std::span<std::uint8_t> output) noexcept override {
    ++calls;
    for (auto &byte : output)
      byte = next++;
    return true;
  }

  std::size_t calls{};
  std::uint8_t next{1U};
};

router::cli_detail::ParsedCommand parse(std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      router::CliEngine::md, router::MdCliWorkflow::explicit_private, text);
  if (!parsed)
    throw std::runtime_error("generated BOF command did not parse: " +
                             std::string{text});
  return *parsed;
}

void apply(router::bof::AutoconfigureIntent &configuration,
           CountingEntropy &entropy, std::string_view text) {
  const auto result = router::lab::bof_cli::edit(configuration, parse(text),
                                                 &entropy);
  if (!result.recognized || !result.valid || !result.changed)
    throw std::runtime_error("BOF command did not change candidate: " +
                             std::string{text});
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void bof_cli_configuration_tests() {
  router::bof::AutoconfigureIntent configuration;
  CountingEntropy entropy;

  apply(configuration, entropy, "bof auto-configure ipv4 dhcp");
  apply(configuration, entropy,
        "bof auto-configure ipv4 dhcp client-id \"management-client\"");
  apply(configuration, entropy,
        "bof auto-configure ipv4 dhcp include-user-class true");
  apply(configuration, entropy, "bof auto-configure ipv4 dhcp timeout 45");
  apply(configuration, entropy, "bof auto-configure ipv6 dhcp");
  apply(configuration, entropy,
        "bof auto-configure ipv6 dhcp client-type duid-link-local");

  require(configuration.ipv4.enabled && configuration.ipv6.enabled &&
              configuration.ipv4.client_id == "management-client" &&
              configuration.ipv4.include_user_class &&
              configuration.ipv4.timeout_seconds == 45U &&
              configuration.ipv6.client_type ==
                  router::bof::Dhcpv6ClientType::duid_link_local &&
              entropy.calls == 4U && router::bof::valid(configuration),
          "BOF candidate did not retain documented DHCP leaves and identities");

  const auto before = configuration;
  const auto invalid = router::lab::bof_cli::edit(
      configuration,
      parse("bof auto-configure ipv6 dhcp timeout 0"), &entropy);
  require(invalid.recognized && !invalid.valid && configuration == before,
          "invalid BOF timeout partially modified the candidate");

  apply(configuration, entropy, "delete bof auto-configure ipv4 dhcp");
  require(!configuration.ipv4.enabled &&
              configuration.ipv4_transaction_secret ==
                  router::crypto::Sha256Digest{},
          "deleting the BOF DHCPv4 container retained live identity state");
}
