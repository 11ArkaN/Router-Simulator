// Release-profile tests prove that SR OS names, list ordering, reference
// validation and PQC-only filtering are driven by generated catalog data.

#include "router/tls_profile.hpp"

#include <stdexcept>

void tls_profile_tests() {
  using namespace router::tls_profile;

  Configuration configuration;
  configuration.certificate_profiles.push_back(
      {.name = "server-cert", .admin_enabled = true, .entries = {}});
  configuration.trust_anchor_profiles.push_back(
      {.name = "project-roots", .ca_profiles = {"root-ca"}});
  configuration.client_cipher_lists.push_back(
      {.name = "client-ciphers",
       .entries = {{20U, "tls-aes128-gcm-sha256"},
                   {10U, "tls-aes256-gcm-sha384"}}});
  configuration.client_group_lists.push_back(
      {.name = "client-groups",
       .entries = {{1U, "tls-x25519"}, {2U, "tls-ml-kem1024"}}});
  configuration.client_signature_lists.push_back(
      {.name = "client-signatures",
       .entries = {{1U, "tls-ed25519"}, {2U, "tls-ml-dsa87"}}});
  configuration.client_profiles.push_back(
      {.name = "resolver-client",
       .admin_enabled = true,
       .certificate_profile = {},
       .cipher_list = "client-ciphers",
       .group_list = "client-groups",
       .signature_list = "client-signatures",
       .trust_anchor_profile = "project-roots",
       .protocol_version = ProtocolVersion::tls13,
       .status_verification = {}});

  if (validate(configuration))
    throw std::runtime_error("valid TLS profile configuration was rejected");
  auto resolved = resolve_client(configuration, "resolver-client");
  if (!resolved.policy || resolved.diagnostic ||
      resolved.policy->cipher_suites.size() != 2U ||
      resolved.policy->cipher_suites[0] != "TLS_AES_256_GCM_SHA384" ||
      resolved.policy->cipher_suites[1] != "TLS_AES_128_GCM_SHA256" ||
      !resolved.policy->require_peer_certificate)
    throw std::runtime_error("TLS profile order or trust policy was lost");

  // PQC-only keeps only the release-classified PQC entries. The non-PQC
  // entries remain in candidate configuration and can become active again if
  // the global token is disabled, matching SR OS behavior.
  configuration.use_pqc_only = true;
  resolved = resolve_client(configuration, "resolver-client");
  if (!resolved.policy || resolved.policy->cipher_suites.size() != 1U ||
      resolved.policy->cipher_suites[0] != "TLS_AES_256_GCM_SHA384" ||
      resolved.policy->groups.size() != 1U ||
      resolved.policy->groups[0] != "MLKEM1024" ||
      resolved.policy->signatures.size() != 1U ||
      resolved.policy->signatures[0] != "mldsa87")
    throw std::runtime_error("PQC-only TLS filtering is incorrect");

  auto invalid = configuration;
  invalid.client_profiles[0].group_list = "missing-list";
  const auto missing = validate(invalid);
  if (!missing || missing->error != Error::missing_reference)
    throw std::runtime_error("missing TLS leafref was accepted");

  invalid = configuration;
  invalid.client_group_lists[0].entries = {{1U, "tls-x25519"}};
  const auto non_pqc = validate(invalid);
  if (!non_pqc || non_pqc->error != Error::pqc_algorithm_required)
    throw std::runtime_error("PQC-only profile accepted a non-PQC group list");

  invalid = configuration;
  invalid.certificate_profiles[0].entries.push_back(
      {.id = 1U,
       .certificate_file = "cf3:/server.pem",
       .key_file = {},
       .send_chain_ca_profiles = {}});
  const auto path = validate(invalid);
  if (!path || path->error != Error::invalid_certificate_file)
    throw std::runtime_error("certificate profile accepted a URL as filename");
}
