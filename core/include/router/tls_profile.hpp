// SR OS TLS configuration model and release-policy resolver. The control
// shard owns Configuration. This module validates list keys, references and
// release-specific algorithms without owning certificates or TLS sessions.
// The service shard receives only a ResolvedTls13Policy value and never reads
// mutable candidate configuration.

#pragma once

#include "router/generated_device_catalog.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::tls_profile {

enum class AlgorithmFamily : std::uint8_t { cipher, group, signature };
enum class EndpointRole : std::uint8_t { client, server };
enum class ProtocolVersion : std::uint8_t { tls12, tls13, all };
enum class StatusResult : std::uint8_t { revoked, good };
enum class RevocationMethod : std::uint8_t { none, crl, ocsp };

struct IndexedAlgorithm {
  std::uint8_t index{};
  std::string name;
  bool operator==(const IndexedAlgorithm &) const = default;
};

struct AlgorithmList {
  std::string name;
  std::vector<IndexedAlgorithm> entries;
  bool operator==(const AlgorithmList &) const = default;
};

struct CertificateEntry {
  std::uint8_t id{};
  std::string certificate_file;
  std::string key_file;
  // SR OS permits up to seven CA profiles in the transmitted chain. Their
  // order is configuration order and is therefore preserved here.
  std::vector<std::string> send_chain_ca_profiles;
  bool operator==(const CertificateEntry &) const = default;
};

struct CertificateProfile {
  std::string name;
  bool admin_enabled{};
  std::vector<CertificateEntry> entries;
  // Presence is separate from the effective default. MD-CLI must be able to
  // delete an explicitly configured `disable` leaf even though its effective
  // value is identical to the absent leaf's SR OS default.
  bool admin_configured{};
  bool operator==(const CertificateProfile &) const = default;
};

struct TrustAnchorProfile {
  std::string name;
  std::vector<std::string> ca_profiles;
  bool operator==(const TrustAnchorProfile &) const = default;
};

struct StatusVerification {
  StatusResult default_result{StatusResult::revoked};
  RevocationMethod primary{RevocationMethod::crl};
  RevocationMethod secondary{RevocationMethod::none};
  bool default_result_configured{};
  bool primary_configured{};
  bool secondary_configured{};
  bool operator==(const StatusVerification &) const = default;
};

struct ClientProfile {
  std::string name;
  bool admin_enabled{};
  std::string certificate_profile;
  std::string cipher_list;
  std::string group_list;
  std::string signature_list;
  std::string trust_anchor_profile;
  ProtocolVersion protocol_version{ProtocolVersion::tls12};
  StatusVerification status_verification{};
  bool admin_configured{};
  bool protocol_version_configured{};
  bool operator==(const ClientProfile &) const = default;
};

struct ServerProfile {
  std::string name;
  bool admin_enabled{};
  std::string certificate_profile;
  std::string cipher_list;
  std::string group_list;
  std::string signature_list;
  std::string client_trust_anchor_profile;
  std::string client_common_name_list;
  ProtocolVersion protocol_version{ProtocolVersion::tls12};
  StatusVerification status_verification{};
  bool admin_configured{};
  bool protocol_version_configured{};
  bool operator==(const ServerProfile &) const = default;
};

struct Configuration {
  bool use_pqc_only{};
  std::vector<CertificateProfile> certificate_profiles;
  std::vector<TrustAnchorProfile> trust_anchor_profiles;
  std::vector<AlgorithmList> client_cipher_lists;
  std::vector<AlgorithmList> client_group_lists;
  std::vector<AlgorithmList> client_signature_lists;
  std::vector<ClientProfile> client_profiles;
  std::vector<AlgorithmList> server_cipher_lists;
  std::vector<AlgorithmList> server_group_lists;
  std::vector<AlgorithmList> server_signature_lists;
  std::vector<ServerProfile> server_profiles;
  // False is both the release default and a configurable value in MD-CLI.
  // Retaining leaf presence is required for compare, info and exact delete
  // semantics; it is not an operational feature flag.
  bool use_pqc_only_configured{};
  bool operator==(const Configuration &) const = default;
};

enum class Error : std::uint8_t {
  none,
  too_many_objects,
  invalid_name,
  duplicate_name,
  invalid_index,
  duplicate_index,
  unsupported_algorithm,
  invalid_certificate_file,
  invalid_revocation_policy,
  missing_reference,
  disabled_profile,
  incomplete_tls13_profile,
  pqc_algorithm_required
};

struct Diagnostic {
  Error error{Error::none};
  std::string object;
  std::string detail;
  std::uint16_t index{};
  explicit operator bool() const noexcept { return error != Error::none; }
};

// Structural validation is suitable for candidate commit. It checks every
// internal leafref and SR OS list constraint, but does not require operational
// files to be loaded. Disabled incomplete objects remain valid configuration,
// just as they can exist on a router before their dependencies are available.
[[nodiscard]] std::optional<Diagnostic>
validate(const Configuration &configuration) noexcept;

struct ResolvedTls13Policy {
  std::vector<std::string_view> cipher_suites;
  std::vector<std::string_view> groups;
  std::vector<std::string_view> signatures;
  std::string certificate_profile;
  std::string trust_anchor_profile;
  std::string common_name_list;
  StatusVerification status_verification{};
  bool require_peer_certificate{};
};

struct Resolution {
  std::optional<ResolvedTls13Policy> policy;
  std::optional<Diagnostic> diagnostic;
};

// Resolution is an operational action. It requires an enabled TLS 1.3
// profile and all TLS 1.3 lists. The returned string_views point only at the
// immutable generated release catalog, never at candidate-owned strings.
[[nodiscard]] Resolution resolve_client(const Configuration &configuration,
                                        std::string_view profile_name) noexcept;
[[nodiscard]] Resolution resolve_server(const Configuration &configuration,
                                        std::string_view profile_name) noexcept;

[[nodiscard]] const device_catalog::TlsAlgorithmName *
algorithm(AlgorithmFamily family, std::string_view sros_name) noexcept;

} // namespace router::tls_profile
