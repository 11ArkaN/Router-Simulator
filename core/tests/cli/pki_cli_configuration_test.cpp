// PKI CLI editor tests prove that generated MD and classic syntax converges
// on one valid configuration model: CA profiles, common-name lists and EST
// profiles with their distinct creation and deletion semantics.

#include "cli/pki_cli_configuration.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;

router::cli_detail::ParsedCommand parse(CliEngine engine,
                                        std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated PKI command did not parse: " +
                             std::string{text});
  return *parsed;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

void edit(router::pki::Configuration &configuration, CliEngine engine,
          std::string_view text,
          router::lab::pki_cli::SecretSink *secrets = nullptr) {
  const auto parsed = parse(engine, text);
  const auto result =
      router::lab::pki_cli::edit(configuration, parsed, engine, secrets);
  if (!result.recognized || !result.changed)
    throw std::runtime_error("PKI command did not change configuration: " +
                             std::string{text});
  if (!router::pki::validate(configuration, engine == CliEngine::md))
    throw std::runtime_error("PKI command produced invalid canonical "
                             "configuration: " +
                             std::string{text});
}

void reject(router::pki::Configuration &configuration, CliEngine engine,
            std::string_view text) {
  const auto parsed = parse(engine, text);
  const auto result =
      router::lab::pki_cli::edit(configuration, parsed, engine);
  require(result.recognized && !result.valid && !result.changed,
          "invalid PKI command was not reported explicitly");
}

class TestSecretSink final : public router::lab::pki_cli::SecretSink {
public:
  std::optional<std::uint64_t>
  seal(router::lab::pki_cli::SecretKind kind,
       std::span<const std::uint8_t> plaintext) noexcept override {
    static_cast<void>(kind);
    sealed.push_back({plaintext.begin(), plaintext.end()});
    return next_handle++;
  }

  std::uint64_t next_handle{1U};
  std::vector<std::vector<std::uint8_t>> sealed{};
};

} // namespace

void pki_cli_configuration_tests() {
  using router::pki::CommonNameType;
  using router::pki::EstServerAddressKind;
  using router::pki::RevocationCheck;

  // CA profiles carry admin-state, description, file references and the
  // revocation method. MD-CLI materializes the profile while configuring a
  // leaf; classic create and removal keep their select and rejected
  // semantics.
  router::pki::Configuration ca;
  edit(ca, CliEngine::md,
       "configure system security pki ca-profile lab-root cert-file "
       "lab-root.crt");
  edit(ca, CliEngine::md,
       "configure system security pki ca-profile lab-root crl-file "
       "lab-root.crl");
  edit(ca, CliEngine::md,
       "configure system security pki ca-profile lab-root admin-state enable");
  edit(ca, CliEngine::md,
       "configure system security pki ca-profile lab-root revocation-check "
       "crl-optional");
  require(ca.ca_profiles.size() == 1U &&
              ca.ca_profiles.front().certificate_file == "lab-root.crt" &&
              ca.ca_profiles.front().crl_file == "lab-root.crl" &&
              ca.ca_profiles.front().admin_enabled &&
              ca.ca_profiles.front().revocation_check ==
                  RevocationCheck::crl_optional,
          "MD CA profile leaves did not reach the model");
  edit(ca, CliEngine::md,
       "delete system security pki ca-profile lab-root revocation-check");
  require(ca.ca_profiles.front().revocation_check == RevocationCheck::crl &&
              !ca.ca_profiles.front().revocation_check_configured,
          "MD delete revocation-check did not restore crl");
  edit(ca, CliEngine::md,
       "delete system security pki ca-profile lab-root cert-file");
  require(ca.ca_profiles.front().certificate_file.empty(),
          "MD delete cert-file retained the reference");
  require(!router::cli_detail::parse_command(
               CliEngine::md, MdCliWorkflow::explicit_private,
               "configure system security pki ca-profile lab-root cert-file "
               "bad\\name.crt")
               .has_value(),
          "backslash PKI filename parsed");
  router::pki::Configuration classic_ca;
  edit(classic_ca, CliEngine::classic,
       "configure system security pki ca-profile lab-root create");
  {
    const auto selected = router::lab::pki_cli::edit(
        classic_ca,
        parse(CliEngine::classic,
              "configure system security pki ca-profile lab-root create"),
        CliEngine::classic);
    require(selected.recognized && selected.valid && !selected.changed,
            "classic CA create of an existing profile was not a select");
  }
  edit(classic_ca, CliEngine::classic,
       "configure system security pki ca-profile lab-root no shutdown");
  edit(classic_ca, CliEngine::classic,
       "configure system security pki ca-profile lab-root cert-file "
       "lab-root.crt");
  edit(classic_ca, CliEngine::classic,
       "configure system security pki ca-profile lab-root revocation-check "
       "crl-optional");
  require(classic_ca.ca_profiles.front().admin_enabled &&
              classic_ca.ca_profiles.front().revocation_check ==
                  RevocationCheck::crl_optional,
          "classic CA leaves did not reach the model");
  edit(classic_ca, CliEngine::classic,
       "configure system security pki no ca-profile lab-root");
  require(classic_ca.ca_profiles.empty(),
          "classic removal did not clear the CA profile");
  reject(classic_ca, CliEngine::classic,
         "configure system security pki no ca-profile lab-root");

  // Common-name lists hold indexed entries with a mandatory type and value.
  // The type and value arrive in separate MD commands, so a half-built
  // candidate entry stays valid until commit.
  router::pki::Configuration cn;
  edit(cn, CliEngine::md,
       "configure system security pki common-name-list peers common-name 1 "
       "cn-type ip-address");
  edit(cn, CliEngine::md,
       "configure system security pki common-name-list peers common-name 1 "
       "cn-value 2001:db8::/32");
  require(cn.common_name_lists.size() == 1U &&
              cn.common_name_lists.front().entries.size() == 1U &&
              cn.common_name_lists.front().entries.front().type ==
                  CommonNameType::ip_address &&
              cn.common_name_lists.front().entries.front().value ==
                  "2001:db8::/32",
          "MD common-name entry did not reach the model");
  for (const auto *text :
       {"configure system security pki common-name-list peers common-name 0 "
        "cn-type ip-address",
        "configure system security pki common-name-list peers common-name "
        "129 cn-type ip-address"}) {
    require(!router::cli_detail::parse_command(
                 CliEngine::md, MdCliWorkflow::explicit_private, text)
                 .has_value(),
            "out-of-range common-name index parsed");
  }
  edit(cn, CliEngine::md,
       "delete system security pki common-name-list peers common-name 1");
  require(cn.common_name_lists.front().entries.empty(),
          "MD delete common-name did not remove the entry");
  {
    const auto silent = router::lab::pki_cli::edit(
        cn,
        parse(CliEngine::md,
              "delete system security pki common-name-list peers common-name "
              "1"),
        CliEngine::md);
    require(silent.recognized && silent.valid && !silent.changed,
            "MD delete of an absent common-name was not silent");
  }
  router::pki::Configuration classic_cn;
  edit(classic_cn, CliEngine::classic,
       "configure system security pki common-name-list peers create");
  edit(classic_cn, CliEngine::classic,
       "configure system security pki common-name-list peers cn 2 type "
       "domain-name value vpn.example.test");
  require(classic_cn.common_name_lists.front().entries.size() == 1U &&
              classic_cn.common_name_lists.front().entries.front().index ==
                  2U &&
              classic_cn.common_name_lists.front().entries.front().type ==
                  CommonNameType::domain_name,
          "classic common-name entry did not reach the model");
  require(!router::cli_detail::parse_command(
               CliEngine::classic, MdCliWorkflow::operational,
               "configure system security pki common-name-list peers cn 2 "
               "type bogus value vpn.example.test")
               .has_value(),
          "unknown cn type parsed");
  edit(classic_cn, CliEngine::classic,
       "configure system security pki common-name-list peers no cn 2");
  require(classic_cn.common_name_lists.front().entries.empty(),
          "classic no cn retained the entry");

  // EST profiles carry server, path and HTTP authentication intent. The
  // password seals into the vault; enrollment itself has no grammar rows.
  router::pki::Configuration est;
  TestSecretSink est_vault;
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est client-tls-profile "
       "est-client");
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est server port 8443");
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est server ipv4 "
       "192.0.2.10");
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est server path "
       "cacerts /.well-known/est/cacerts");
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est http-authentication "
       "username est-user",
       &est_vault);
  edit(est, CliEngine::md,
       "configure system security pki est-profile lab-est http-authentication "
       "password est-secret",
       &est_vault);
  {
    const auto &profile = est.est_profiles.front();
    require(profile.client_tls_profile == "est-client" &&
                profile.server.port == 8443U &&
                profile.server.port_configured &&
                profile.server.address_kind ==
                    EstServerAddressKind::ipv4 &&
                profile.server.address == "192.0.2.10" &&
                profile.server.path.cacerts == "/.well-known/est/cacerts" &&
                profile.http_authentication.username == "est-user" &&
                profile.http_authentication.password_configured &&
                profile.http_authentication.password_handle != 0U,
            "EST intent did not reach the canonical model");
  }
  for (const auto *text :
       {"configure system security pki est-profile lab-est server port 0",
        "configure system security pki est-profile lab-est server path "
        "cacerts relative-path"}) {
    require(!router::cli_detail::parse_command(
                 CliEngine::md, MdCliWorkflow::explicit_private, text)
                 .has_value(),
            "out-of-domain EST server value parsed");
  }
  edit(est, CliEngine::md,
       "delete system security pki est-profile lab-est http-authentication "
       "password",
       &est_vault);
  require(!est.est_profiles.front().http_authentication.password_configured,
          "MD delete password retained the secret");
  router::pki::Configuration classic_est;
  edit(classic_est, CliEngine::classic,
       "configure system security pki est-profile lab-est create");
  edit(classic_est, CliEngine::classic,
       "configure system security pki est-profile lab-est client-tls-profile "
       "est-client");
  edit(classic_est, CliEngine::classic,
       "configure system security pki est-profile lab-est http-auth username "
       "est-user");
  require(classic_est.est_profiles.front().client_tls_profile ==
                  "est-client" &&
              classic_est.est_profiles.front().http_authentication.username ==
                  "est-user",
          "classic EST leaves did not reach the model");
  edit(classic_est, CliEngine::classic,
       "configure system security pki no est-profile lab-est");
  require(classic_est.est_profiles.empty(),
          "classic removal did not clear the EST profile");
  // MD deletes stay silent below missing objects without materializing them,
  // while classic removals keep the rejected result.
  router::pki::Configuration absent;
  for (const auto *text :
       {"delete system security pki ca-profile ghost",
        "delete system security pki common-name-list ghost",
        "delete system security pki est-profile ghost",
        "delete system security pki ca-profile ghost admin-state"}) {
    const auto before_absent = absent;
    const auto silent = router::lab::pki_cli::edit(
        absent, parse(CliEngine::md, text), CliEngine::md);
    require(silent.recognized && silent.valid && !silent.changed &&
                absent == before_absent,
            "MD delete of an absent PKI element was not silent");
  }
  for (const auto *text :
       {"configure system security pki no ca-profile ghost",
        "configure system security pki no common-name-list ghost",
        "configure system security pki no est-profile ghost"}) {
    const auto rejected = router::lab::pki_cli::edit(
        absent, parse(CliEngine::classic, text), CliEngine::classic);
    require(rejected.recognized && !rejected.valid,
            "classic removal accepted an absent PKI element");
  }
}
