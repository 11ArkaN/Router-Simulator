// PKI CLI editor tests prove that generated MD and classic syntax converges
// on one valid configuration model: CA profiles (with OCSP, CMPv2 and
// automatic CRL update subtrees), common-name lists, EST profiles,
// certificate update profiles, certificate auto-update entries and top-level
// display, import, chain-depth and expiration-warning leaves, with their
// distinct creation and deletion semantics.

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

  // Top-level leaves carry display, import, chain-depth and warning intent.
  // MD restores defaults silently; classic has no removal for format leaves
  // and rejects absent warning removals.
  router::pki::Configuration top;
  edit(top, CliEngine::md,
       "configure system security pki certificate-display-format utf8");
  edit(top, CliEngine::md,
       "configure system security pki dynamic-ca true");
  edit(top, CliEngine::md,
       "configure system security pki imported-format secure");
  edit(top, CliEngine::md,
       "configure system security pki maximum-cert-chain-depth 5");
  edit(top, CliEngine::md,
       "configure system security pki certificate-expiration-warning hours "
       "72");
  edit(top, CliEngine::md,
       "configure system security pki certificate-expiration-warning "
       "repeat-hours 24");
  edit(top, CliEngine::md,
       "configure system security pki crl-expiration-warning hours 48");
  require(top.display_format == router::pki::CertificateDisplayFormat::utf8 &&
              top.dynamic_ca && top.dynamic_ca_configured &&
              top.imported_format == router::pki::ImportedFormat::secure &&
              top.maximum_cert_chain_depth == 5U &&
              top.certificate_expiration_warning.hours == 72 &&
              top.certificate_expiration_warning.repeat_hours == 24 &&
              top.crl_expiration_warning.hours == 48,
          "MD top-level PKI leaves did not reach the model");
  for (const auto *text :
       {"configure system security pki maximum-cert-chain-depth 0",
        "configure system security pki maximum-cert-chain-depth 8",
        "configure system security pki certificate-expiration-warning hours "
        "8761"}) {
    require(!router::cli_detail::parse_command(
                 CliEngine::md, MdCliWorkflow::explicit_private, text)
                 .has_value(),
            "out-of-range top-level PKI value parsed");
  }
  edit(top, CliEngine::md,
       "delete system security pki certificate-display-format");
  edit(top, CliEngine::md, "delete system security pki dynamic-ca");
  require(top.display_format == router::pki::CertificateDisplayFormat::ascii &&
              !top.display_format_configured && !top.dynamic_ca_configured,
          "MD delete top-level leaf did not restore the default");
  router::pki::Configuration classic_top;
  edit(classic_top, CliEngine::classic,
       "configure system security pki certificate-display-format utf8");
  edit(classic_top, CliEngine::classic,
       "configure system security pki maximum-cert-chain-depth 3");
  edit(classic_top, CliEngine::classic,
       "configure system security pki certificate-expiration-warning hours "
       "100 repeat 10");
  require(classic_top.display_format ==
                  router::pki::CertificateDisplayFormat::utf8 &&
              classic_top.maximum_cert_chain_depth == 3U &&
              classic_top.certificate_expiration_warning.hours == 100 &&
              classic_top.certificate_expiration_warning.repeat_hours == 10,
          "classic top-level PKI leaves did not reach the model");
  edit(classic_top, CliEngine::classic,
       "configure system security pki no maximum-cert-chain-depth");
  require(!classic_top.maximum_cert_chain_depth_configured,
          "classic no chain-depth retained the value");

  // OCSP leaves hang under the CA profile. MD uses service-name; classic
  // selects numeric services with service <id> and names with service name.
  router::pki::Configuration ocsp;
  edit(ocsp, CliEngine::md,
       "configure system security pki ca-profile lab-ocsp ocsp responder-url "
       "http://ocsp.example.test");
  edit(ocsp, CliEngine::md,
       "configure system security pki ca-profile lab-ocsp ocsp service-name "
       "ocsp-service");
  edit(ocsp, CliEngine::md,
       "configure system security pki ca-profile lab-ocsp ocsp "
       "transmission-profile ocsp-transport");
  {
    const auto &profile = ocsp.ca_profiles.front().ocsp;
    require(profile.responder_url == "http://ocsp.example.test" &&
                profile.service_kind == router::pki::OcspServiceKind::name &&
                profile.service_name == "ocsp-service" &&
                profile.transmission_profile == "ocsp-transport",
            "MD OCSP intent did not reach the canonical model");
  }
  edit(ocsp, CliEngine::md,
       "delete system security pki ca-profile lab-ocsp ocsp responder-url");
  require(ocsp.ca_profiles.front().ocsp.responder_url.empty(),
          "MD delete responder-url retained the reference");
  router::pki::Configuration classic_ocsp;
  edit(classic_ocsp, CliEngine::classic,
       "configure system security pki ca-profile lab-ocsp create");
  edit(classic_ocsp, CliEngine::classic,
       "configure system security pki ca-profile lab-ocsp ocsp responder-url "
       "http://ocsp.example.test");
  edit(classic_ocsp, CliEngine::classic,
       "configure system security pki ca-profile lab-ocsp ocsp service 42");
  require(classic_ocsp.ca_profiles.front().ocsp.service_kind ==
                  router::pki::OcspServiceKind::id &&
              classic_ocsp.ca_profiles.front().ocsp.service_id == 42U,
          "classic OCSP numeric service did not reach the model");
  edit(classic_ocsp, CliEngine::classic,
       "configure system security pki ca-profile lab-ocsp ocsp service name "
       "ocsp-service");
  require(classic_ocsp.ca_profiles.front().ocsp.service_kind ==
                  router::pki::OcspServiceKind::name,
          "classic OCSP named service did not reach the model");
  edit(classic_ocsp, CliEngine::classic,
       "configure system security pki ca-profile lab-ocsp ocsp no service");
  require(classic_ocsp.ca_profiles.front().ocsp.service_kind ==
              router::pki::OcspServiceKind::none,
          "classic no service retained the OCSP service");

  // CMPv2 covers sender, nonce, signing, recipient, unprotected-message,
  // HTTP, URL and the sealed key list. Classic keeps its documented flat
  // spellings for the boolean flags and the url/key rows.
  router::pki::Configuration cmp;
  TestSecretSink cmp_vault;
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 "
       "always-set-sender-for-ir true");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 "
       "signing-cert-subject CN=cmp-signer");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 "
       "response-signing-use-extracert");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 use-ca-subject");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 "
       "accept-unprotected-message error-message true");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 http "
       "response-timeout 60");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 http version "
       "1.0");
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 url url-string "
       "http://cmp.example.test/cmp",
       &cmp_vault);
  edit(cmp, CliEngine::md,
       "configure system security pki ca-profile lab-cmp cmpv2 key-list key "
       "initial-key password cmp-secret",
       &cmp_vault);
  {
    const auto &profile = cmp.ca_profiles.front().cmpv2;
    require(profile.always_set_sender_for_ir &&
                profile.signing_cert_subject == "CN=cmp-signer" &&
                profile.response_signing ==
                    router::pki::CmpResponseSigningKind::use_extra_cert &&
                profile.recipient == router::pki::CmpRecipientKind::ca_subject &&
                profile.accept_unprotected_error &&
                profile.http_response_timeout_seconds == 60U &&
                profile.http_version == router::pki::HttpVersion::v10 &&
                profile.url_string == "http://cmp.example.test/cmp" &&
                profile.keys.size() == 1U &&
                profile.keys.front().password_configured &&
                profile.keys.front().password_handle != 0U,
            "MD CMPv2 intent did not reach the canonical model");
  }
  edit(cmp, CliEngine::md,
       "delete system security pki ca-profile lab-cmp cmpv2 key-list key "
       "initial-key",
       &cmp_vault);
  require(cmp.ca_profiles.front().cmpv2.keys.empty(),
          "MD delete CMPv2 key retained the entry");
  {
    const auto silent = router::lab::pki_cli::edit(
        cmp,
        parse(CliEngine::md,
              "delete system security pki ca-profile lab-cmp cmpv2 key-list "
              "key initial-key"),
        CliEngine::md);
    require(silent.recognized && silent.valid && !silent.changed,
            "MD delete of an absent CMPv2 key was not silent");
  }
  router::pki::Configuration classic_cmp;
  edit(classic_cmp, CliEngine::classic,
       "configure system security pki ca-profile lab-cmp create");
  edit(classic_cmp, CliEngine::classic,
       "configure system security pki ca-profile lab-cmp cmpv2 "
       "accept-unprotected-errormsg");
  edit(classic_cmp, CliEngine::classic,
       "configure system security pki ca-profile lab-cmp cmpv2 url "
       "http://cmp.example.test/cmp service-id 100",
       &cmp_vault);
  edit(classic_cmp, CliEngine::classic,
       "configure system security pki ca-profile lab-cmp cmpv2 key-list key "
       "cmp-secret reference initial-key",
       &cmp_vault);
  {
    const auto &profile = classic_cmp.ca_profiles.front().cmpv2;
    require(profile.accept_unprotected_error &&
                profile.url_string == "http://cmp.example.test/cmp" &&
                profile.url_transport ==
                    router::pki::CmpUrlTransportKind::service_id &&
                profile.url_service_id == 100U && profile.keys.size() == 1U &&
                profile.keys.front().reference == "initial-key",
            "classic CMPv2 intent did not reach the canonical model");
  }
  edit(classic_cmp, CliEngine::classic,
       "configure system security pki ca-profile lab-cmp cmpv2 key-list no "
       "key initial-key",
       &cmp_vault);
  require(classic_cmp.ca_profiles.front().cmpv2.keys.empty(),
          "classic no CMPv2 key retained the entry");

  // Automatic CRL update is a presence container with admin-state,
  // intervals, schedule and up to eight download URLs. MD uses seconds;
  // classic uses shutdown and days/hrs/min/sec components.
  router::pki::Configuration crl;
  edit(crl, CliEngine::md,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "admin-state enable");
  edit(crl, CliEngine::md,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "periodic-update-interval 7200");
  edit(crl, CliEngine::md,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "schedule-type periodic");
  edit(crl, CliEngine::md,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "crl-urls url-entry 1 url http://crl.example.test/lab.crl");
  {
    const auto &update = crl.ca_profiles.front().auto_crl_update;
    require(update.present && update.admin_enabled &&
                update.periodic_update_seconds == 7200U &&
                update.schedule ==
                    router::pki::AutoCrlScheduleKind::periodic &&
                update.urls.size() == 1U &&
                update.urls.front().url == "http://crl.example.test/lab.crl",
            "MD auto-CRL intent did not reach the canonical model");
  }
  for (const auto *text :
       {"configure system security pki ca-profile lab-crl auto-crl-update "
        "crl-urls url-entry 0 url http://crl.example.test/lab.crl",
        "configure system security pki ca-profile lab-crl auto-crl-update "
        "crl-urls url-entry 9 url http://crl.example.test/lab.crl"}) {
    require(!router::cli_detail::parse_command(
                 CliEngine::md, MdCliWorkflow::explicit_private, text)
                 .has_value(),
            "out-of-domain auto-CRL value parsed");
  }
  reject(crl, CliEngine::md,
         "configure system security pki ca-profile lab-crl auto-crl-update "
         "periodic-update-interval 3599");
  edit(crl, CliEngine::md,
       "delete system security pki ca-profile lab-crl auto-crl-update "
       "crl-urls url-entry 1");
  require(crl.ca_profiles.front().auto_crl_update.urls.empty(),
          "MD delete CRL URL entry retained the record");
  router::pki::Configuration classic_crl;
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl create");
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "create");
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl auto-crl-update no "
       "shutdown");
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "periodic-update-interval days 1 hrs 2");
  require(classic_crl.ca_profiles.front().auto_crl_update.present &&
              classic_crl.ca_profiles.front().auto_crl_update.admin_enabled &&
              classic_crl.ca_profiles.front().auto_crl_update
                      .periodic_update_seconds == 93600U,
          "classic auto-CRL intent did not reach the canonical model");
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "crl-urls url-entry 2 create");
  edit(classic_crl, CliEngine::classic,
       "configure system security pki ca-profile lab-crl auto-crl-update "
       "crl-urls url-entry 2 url http://crl.example.test/lab.crl");
  require(classic_crl.ca_profiles.front().auto_crl_update.urls.size() == 1U,
          "classic CRL URL entry did not reach the model");

  // Certificate update profiles select the enrollment protocol, key
  // generation and schedule. Auto-update entries bind certificates to a
  // profile with a key file.
  router::pki::Configuration update;
  edit(update, CliEngine::md,
       "configure system security pki ca-profile lab-ca cert-file lab-ca.crt");
  edit(update, CliEngine::md,
       "configure system security pki certificate-update-profile lab-update "
       "hash-algorithm sha512");
  edit(update, CliEngine::md,
       "configure system security pki certificate-update-profile lab-update "
       "cmpv2 ca-profile lab-ca");
  edit(update, CliEngine::md,
       "configure system security pki certificate-update-profile lab-update "
       "rsa key-size 4096");
  edit(update, CliEngine::md,
       "configure system security pki certificate-update-profile lab-update "
       "after-issue 1000000");
  edit(update, CliEngine::md,
       "configure system security pki certificate-auto-update lab.crt "
       "key-file-name lab.key");
  edit(update, CliEngine::md,
       "configure system security pki certificate-auto-update lab.crt profile "
       "lab-update");
  {
    const auto &profile = update.update_profiles.front();
    require(profile.hash_algorithm == router::pki::HashAlgorithm::sha512 &&
                profile.protocol == router::pki::UpdateProtocol::cmpv2 &&
                profile.protocol_profile == "lab-ca" &&
                profile.key_generation == router::pki::KeyGenerationKind::rsa &&
                profile.key_size_bits == 4096U &&
                profile.schedule ==
                    router::pki::UpdateScheduleKind::after_issue &&
                update.auto_updates.size() == 1U &&
                update.auto_updates.front().key_file == "lab.key" &&
                update.auto_updates.front().profile == "lab-update",
            "MD update/auto-update intent did not reach the model");
  }
  reject(update, CliEngine::md,
         "configure system security pki certificate-update-profile lab-update "
         "rsa key-size 256");
  router::pki::Configuration classic_update;
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-update-profile lab-update "
       "create");
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-update-profile lab-update "
       "retry-interval 120");
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-update-profile lab-update "
       "key-generation rsa 2048");
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-update-profile lab-update "
       "key-generation same-as-existing-key");
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-auto-update cert lab.crt "
       "create");
  edit(classic_update, CliEngine::classic,
       "configure system security pki certificate-auto-update cert lab.crt key "
       "lab.key");
  require(classic_update.update_profiles.front().retry_seconds == 120U &&
              classic_update.auto_updates.front().key_file == "lab.key",
          "classic update/auto-update intent did not reach the model");
  edit(classic_update, CliEngine::classic,
       "configure system security pki no certificate-update-profile "
       "lab-update");
  require(classic_update.update_profiles.empty(),
          "classic removal did not clear the update profile");
}
