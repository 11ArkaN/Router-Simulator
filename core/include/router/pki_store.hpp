// Local PKIX object store. One service shard owns each Store and is the only
// writer of CA serial counters, identities and revocation state. The public
// representation contains DER certificates and authenticated encrypted key
// blobs only. OpenSSL provider pointers and plaintext private keys never cross
// this module boundary or enter a checkpoint.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace router::pki {

namespace quic_access {
class EngineAccess;
}

namespace tls_access {
class EngineAccess;
}

using ObjectId = std::uint64_t;

enum class KeyAlgorithm : std::uint8_t {
  ecdsa_p256,
  rsa_3072,
  ed25519
};

enum class CertificateUsage : std::uint8_t {
  tls_server,
  tls_client,
  tls_server_and_client
};

enum class RevocationReason : std::uint8_t {
  unspecified = 0U,
  key_compromise = 1U,
  ca_compromise = 2U,
  affiliation_changed = 3U,
  superseded = 4U,
  cessation_of_operation = 5U,
  certificate_hold = 6U,
  remove_from_crl = 8U,
  privilege_withdrawn = 9U,
  aa_compromise = 10U
};

struct DistinguishedName {
  std::string common_name;
  std::string organization;
  std::string organizational_unit;
  std::string country;
};

struct AuthorityProfile {
  DistinguishedName subject;
  KeyAlgorithm key_algorithm{KeyAlgorithm::ecdsa_p256};
  std::uint64_t not_before{};
  std::uint64_t not_after{};
  // A missing path limit allows an unconstrained number of non-self-issued
  // intermediate CA certificates below this authority, as defined by RFC
  // 5280. Zero permits only end-entity certificates below this authority.
  std::optional<std::uint32_t> path_length{0U};
};

struct IdentityProfile {
  DistinguishedName subject;
  KeyAlgorithm key_algorithm{KeyAlgorithm::ecdsa_p256};
  CertificateUsage usage{CertificateUsage::tls_server};
  std::vector<std::string> dns_names;
  std::vector<std::array<std::uint8_t, 4U>> ipv4_addresses;
  std::vector<std::array<std::uint8_t, 16U>> ipv6_addresses;
  std::uint64_t not_before{};
  std::uint64_t not_after{};
};

struct RevocationRecord {
  ObjectId identity{};
  std::vector<std::uint8_t> serial;
  std::uint64_t revoked_at{};
  RevocationReason reason{RevocationReason::unspecified};
};

struct AuthorityRecord {
  ObjectId id{};
  std::vector<std::uint8_t> certificate_der;
  std::vector<std::uint8_t> sealed_private_key;
  std::uint64_t next_serial{1U};
  std::vector<RevocationRecord> revocations;
};

struct IdentityRecord {
  ObjectId id{};
  ObjectId issuer{};
  std::vector<std::uint8_t> serial;
  // The leaf certificate is first. Issuer certificates follow toward the
  // trust anchor, matching TLS Certificate message ordering from RFC 8446.
  std::vector<std::vector<std::uint8_t>> certificate_chain_der;
  std::vector<std::uint8_t> sealed_private_key;
};

struct StoreCheckpoint {
  ObjectId next_id{1U};
  std::vector<AuthorityRecord> authorities;
  std::vector<IdentityRecord> identities;
};

enum class MutationResult : std::uint8_t {
  applied,
  not_found,
  duplicate,
  invalid_argument,
  invalid_certificate,
  key_mismatch,
  expired_issuer,
  serial_exhausted,
  resource_exhausted,
  cryptographic_failure
};

enum class ValidationStatus : std::uint8_t {
  valid,
  malformed_certificate,
  untrusted,
  expired,
  not_yet_valid,
  hostname_mismatch,
  invalid_usage,
  revoked,
  revocation_status_unknown,
  invalid_revocation_data,
  cryptographic_failure
};

struct ValidationRequest {
  std::span<const std::uint8_t> leaf_der;
  std::span<const std::vector<std::uint8_t>> intermediate_der;
  std::span<const std::vector<std::uint8_t>> trust_anchor_der;
  std::span<const std::vector<std::uint8_t>> crl_der;
  std::span<const std::uint8_t> ocsp_response_der;
  std::string hostname;
  std::optional<std::array<std::uint8_t, 4U>> ipv4_address;
  std::optional<std::array<std::uint8_t, 16U>> ipv6_address;
  CertificateUsage usage{CertificateUsage::tls_server};
  std::uint64_t wall_clock_seconds{};
  // When required, absence of a usable CRL or OCSP response is a validation
  // failure. When false, supplied revocation data is still checked and a
  // definitive revoked result still rejects the certificate.
  bool require_revocation_status{};
};

struct ValidationResult {
  ValidationStatus status{ValidationStatus::cryptographic_failure};
  int provider_error{};
  int error_depth{};
};

class OpenIdentity final {
public:
  OpenIdentity(OpenIdentity &&) noexcept;
  OpenIdentity &operator=(OpenIdentity &&) noexcept;
  OpenIdentity(const OpenIdentity &) = delete;
  OpenIdentity &operator=(const OpenIdentity &) = delete;
  ~OpenIdentity();

  [[nodiscard]] std::span<const std::vector<std::uint8_t>>
  certificate_chain_der() const noexcept;

private:
  struct Impl;
  explicit OpenIdentity(std::unique_ptr<Impl> impl) noexcept;
  [[nodiscard]] void *native_private_key() const noexcept;

  std::unique_ptr<Impl> impl_;
  friend class Store;
  friend class tls_access::EngineAccess;
  // QUIC uses OpenSSL's QUIC TLS callbacks rather than the record-oriented
  // TLS adapter, but it needs the same narrowly scoped access to an opened
  // project identity. The access class is implemented only by the socket-free
  // QUIC module and cannot export the provider key to application callers.
  friend class quic_access::EngineAccess;
};

class Store final {
public:
  // The wrapping key must be exactly 32 bytes and contain caller-provided
  // project entropy. vault_context binds every encrypted object to its project
  // and logical PKI store. The Store copies both values and cleanses them at
  // destruction.
  [[nodiscard]] static std::optional<Store>
  create(std::span<const std::uint8_t> wrapping_key,
         std::span<const std::uint8_t> vault_context) noexcept;
  [[nodiscard]] static std::optional<Store>
  restore(const StoreCheckpoint &checkpoint,
          std::span<const std::uint8_t> wrapping_key,
          std::span<const std::uint8_t> vault_context) noexcept;

  Store(Store &&other) noexcept;
  Store &operator=(Store &&other) noexcept;
  Store(const Store &) = delete;
  Store &operator=(const Store &) = delete;
  ~Store();

  // create_authority generates the key with the OpenSSL CSPRNG, creates a
  // self-signed RFC 5280 CA certificate and seals the private key before the
  // record is published. Failure leaves the store unchanged.
  [[nodiscard]] std::pair<MutationResult, ObjectId>
  create_authority(const AuthorityProfile &profile) noexcept;

  // issue_identity allocates the issuer serial exactly once after all input
  // validation and storage reservation succeed. The result contains server or
  // client EKU, digitalSignature key usage and every requested SAN.
  [[nodiscard]] std::pair<MutationResult, ObjectId>
  issue_identity(ObjectId authority, const IdentityProfile &profile) noexcept;

  // import_identity consumes PEM certificate and private-key input from the
  // caller, checks key equality and seals the imported key immediately. The
  // method never exposes a private-key export operation.
  [[nodiscard]] std::pair<MutationResult, ObjectId>
  import_identity(std::span<const std::uint8_t> certificate_chain_pem,
                  std::span<const std::uint8_t> private_key_pem,
                  std::span<const std::uint8_t> password) noexcept;

  [[nodiscard]] MutationResult revoke(ObjectId authority, ObjectId identity,
                                      std::uint64_t revoked_at,
                                      RevocationReason reason) noexcept;

  // CRL and OCSP output is DER encoded and signed by the issuing CA. Callers
  // transport those bytes through their modeled application protocol.
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  issue_crl(ObjectId authority, std::uint64_t this_update,
            std::uint64_t next_update) const noexcept;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  make_ocsp_request(ObjectId identity) const noexcept;
  [[nodiscard]] std::optional<std::vector<std::uint8_t>>
  answer_ocsp(ObjectId authority, std::span<const std::uint8_t> request_der,
              std::uint64_t this_update,
              std::uint64_t next_update) const noexcept;

  [[nodiscard]] static ValidationResult
  validate(const ValidationRequest &request) noexcept;

  // Opening an identity authenticates and decrypts its private key into a
  // short-lived RAII object. TLS is the only friend permitted to obtain the
  // provider pointer; callers can inspect only the public certificate chain.
  [[nodiscard]] std::optional<OpenIdentity>
  open_identity(ObjectId id) const noexcept;

  [[nodiscard]] const AuthorityRecord *authority(ObjectId id) const noexcept;
  [[nodiscard]] const IdentityRecord *identity(ObjectId id) const noexcept;
  [[nodiscard]] const StoreCheckpoint &checkpoint() const noexcept {
    return state_;
  }

private:
  Store(std::array<std::uint8_t, 32U> wrapping_key,
        std::vector<std::uint8_t> vault_context,
        StoreCheckpoint state) noexcept;

  [[nodiscard]] ObjectId allocate_id() noexcept;
  void cleanse_secrets() noexcept;

  std::array<std::uint8_t, 32U> wrapping_key_{};
  std::vector<std::uint8_t> vault_context_;
  StoreCheckpoint state_{};
};

} // namespace router::pki
