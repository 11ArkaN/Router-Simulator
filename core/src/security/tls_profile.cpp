// Control-shard implementation of the SR OS TLS profile model. All lookup
// tables come from the generated 26.7.R1 release catalog. This file performs
// no cryptography and cannot open sockets or mutate the PKI vault.

#include "router/tls_profile.hpp"

#include <algorithm>
#include <cstddef>
#include <cctype>
#include <limits>

namespace router::tls_profile {
namespace {

bool valid_text(std::string_view value, std::size_t maximum) noexcept {
  // YANG string-not-all-spaces permits ordinary internal spaces. Checking the
  // exact encoded byte count matches SR OS CLI limits without pretending that
  // Unicode code points have a different storage contract in the runtime.
  return !value.empty() && value.size() <= maximum &&
         std::any_of(value.begin(), value.end(), [](unsigned char character) {
           return std::isspace(character) == 0;
         });
}

bool valid_file_name(std::string_view value) noexcept {
  // The 26.7.R1 certificate-file and key-file leaves accept a filename only.
  // A colon or slash would turn the leaf into a URL or path and is explicitly
  // rejected by the Nokia YANG constraint.
  return valid_text(value, device_catalog::tls_certificate_file_name_bytes) &&
         value.find_first_of(":/") == std::string_view::npos;
}

Diagnostic problem(Error error, std::string_view object,
                   std::string_view detail = {},
                   std::uint16_t index = 0U) {
  return {.error = error,
          .object = std::string{object},
          .detail = std::string{detail},
          .index = index};
}

template <typename Item>
const Item *named(std::span<const Item> items, std::string_view name) noexcept {
  const auto found = std::find_if(items.begin(), items.end(),
                                  [name](const Item &item) {
                                    return item.name == name;
                                  });
  return found == items.end() ? nullptr : &*found;
}

template <typename Item>
std::optional<Diagnostic> validate_named_objects(std::span<const Item> items,
                                                 std::size_t maximum,
                                                 std::string_view kind) {
  if (items.size() > maximum)
    return problem(Error::too_many_objects, kind);
  for (std::size_t index = 0; index < items.size(); ++index) {
    if (!valid_text(items[index].name, device_catalog::tls_profile_name_bytes))
      return problem(Error::invalid_name, items[index].name, kind);
    for (std::size_t prior = 0; prior < index; ++prior)
      if (items[prior].name == items[index].name)
        return problem(Error::duplicate_name, items[index].name, kind);
  }
  return std::nullopt;
}

std::optional<Diagnostic>
validate_reference_names(std::span<const std::string> names,
                         std::string_view object,
                         std::string_view leaf) {
  for (std::size_t index = 0; index < names.size(); ++index) {
    if (!valid_text(names[index], device_catalog::tls_profile_name_bytes))
      return problem(Error::invalid_name, object, leaf);
    if (std::find(names.begin(), names.begin() +
                                     static_cast<std::ptrdiff_t>(index),
                  names[index]) !=
        names.begin() + static_cast<std::ptrdiff_t>(index))
      return problem(Error::duplicate_name, object, names[index]);
  }
  return std::nullopt;
}

std::optional<Diagnostic>
validate_algorithm_lists(std::span<const AlgorithmList> lists,
                         std::size_t maximum, AlgorithmFamily family,
                         std::string_view kind) {
  if (auto issue = validate_named_objects(lists, maximum, kind))
    return issue;
  for (const auto &list : lists) {
    for (std::size_t position = 0; position < list.entries.size(); ++position) {
      const auto &entry = list.entries[position];
      if (entry.index < device_catalog::tls_algorithm_index_minimum ||
          entry.index > device_catalog::tls_algorithm_index_maximum)
        return problem(Error::invalid_index, list.name, entry.name,
                       entry.index);
      if (!algorithm(family, entry.name))
        return problem(Error::unsupported_algorithm, list.name, entry.name,
                       entry.index);
      for (std::size_t prior = 0; prior < position; ++prior)
        if (list.entries[prior].index == entry.index)
          return problem(Error::duplicate_index, list.name, entry.name,
                         entry.index);
    }
  }
  return std::nullopt;
}

template <typename Profile>
std::optional<Diagnostic>
validate_profile_references(const Profile &profile,
                            const Configuration &configuration) {
  const auto has_reference = [&](std::string_view value, const auto &objects,
                                 std::string_view leaf) -> std::optional<Diagnostic> {
    if (!value.empty() && !named(std::span{objects}, value))
      return problem(Error::missing_reference, profile.name, leaf);
    return std::nullopt;
  };
  if (auto issue = has_reference(profile.certificate_profile,
                                 configuration.certificate_profiles,
                                 "cert-profile"))
    return issue;
  if constexpr (requires { profile.trust_anchor_profile; }) {
    if (auto issue = has_reference(profile.cipher_list,
                                   configuration.client_cipher_lists,
                                   "cipher-list"))
      return issue;
    if (auto issue = has_reference(profile.group_list,
                                   configuration.client_group_lists,
                                   "group-list"))
      return issue;
    if (auto issue = has_reference(profile.signature_list,
                                   configuration.client_signature_lists,
                                   "signature-list"))
      return issue;
    if (auto issue = has_reference(profile.trust_anchor_profile,
                                   configuration.trust_anchor_profiles,
                                   "trust-anchor-profile"))
      return issue;
  } else {
    if (auto issue = has_reference(profile.cipher_list,
                                   configuration.server_cipher_lists,
                                   "cipher-list"))
      return issue;
    if (auto issue = has_reference(profile.group_list,
                                   configuration.server_group_lists,
                                   "group-list"))
      return issue;
    if (auto issue = has_reference(profile.signature_list,
                                   configuration.server_signature_lists,
                                   "signature-list"))
      return issue;
    if (auto issue = has_reference(profile.client_trust_anchor_profile,
                                   configuration.trust_anchor_profiles,
                                   "authenticate-client trust-anchor-profile"))
      return issue;
  }
  if (profile.status_verification.primary == RevocationMethod::none ||
      (profile.status_verification.secondary != RevocationMethod::none &&
       profile.status_verification.secondary ==
           profile.status_verification.primary))
    return problem(Error::invalid_revocation_policy, profile.name);
  return std::nullopt;
}

bool list_has_pqc(const AlgorithmList &list,
                  AlgorithmFamily family) noexcept {
  return std::any_of(list.entries.begin(), list.entries.end(),
                     [family](const IndexedAlgorithm &entry) {
                       const auto *value = algorithm(family, entry.name);
                       return value && value->pqc;
                     });
}

template <typename Profile>
std::optional<Diagnostic>
validate_pqc_assignment(const Profile &profile,
                        const Configuration &configuration,
                        EndpointRole role) {
  if (!configuration.use_pqc_only || !profile.admin_enabled)
    return std::nullopt;
  const auto &cipher_lists = role == EndpointRole::client
                                 ? configuration.client_cipher_lists
                                 : configuration.server_cipher_lists;
  const auto &group_lists = role == EndpointRole::client
                                ? configuration.client_group_lists
                                : configuration.server_group_lists;
  const auto &signature_lists = role == EndpointRole::client
                                    ? configuration.client_signature_lists
                                    : configuration.server_signature_lists;
  const auto *ciphers = named(std::span{cipher_lists}, profile.cipher_list);
  const auto *groups = named(std::span{group_lists}, profile.group_list);
  const auto *signatures =
      named(std::span{signature_lists}, profile.signature_list);
  // Nokia rejects enabling PQC-only when any assigned list on an enabled
  // profile lacks a PQC algorithm. Missing lists are reported by operational
  // resolution, while a present non-PQC list is a commit-time conflict.
  if ((ciphers && !list_has_pqc(*ciphers, AlgorithmFamily::cipher)) ||
      (groups && !list_has_pqc(*groups, AlgorithmFamily::group)) ||
      (signatures &&
       !list_has_pqc(*signatures, AlgorithmFamily::signature)))
    return problem(Error::pqc_algorithm_required, profile.name);
  return std::nullopt;
}

template <typename Profile>
Resolution resolve(const Profile *profile, const Configuration &configuration,
                   EndpointRole role) {
  if (!profile)
    return {.policy = std::nullopt,
            .diagnostic =
                problem(Error::missing_reference, {}, "tls-profile")};
  if (!profile->admin_enabled)
    return {.policy = std::nullopt,
            .diagnostic = problem(Error::disabled_profile, profile->name)};
  if (profile->protocol_version != ProtocolVersion::tls13 &&
      profile->protocol_version != ProtocolVersion::all)
    return {.policy = std::nullopt,
            .diagnostic = problem(Error::incomplete_tls13_profile,
                                  profile->name, "protocol-version")};

  const auto &cipher_lists = role == EndpointRole::client
                                 ? configuration.client_cipher_lists
                                 : configuration.server_cipher_lists;
  const auto &group_lists = role == EndpointRole::client
                                ? configuration.client_group_lists
                                : configuration.server_group_lists;
  const auto &signature_lists = role == EndpointRole::client
                                    ? configuration.client_signature_lists
                                    : configuration.server_signature_lists;
  const auto *ciphers = named(std::span{cipher_lists}, profile->cipher_list);
  const auto *groups = named(std::span{group_lists}, profile->group_list);
  const auto *signatures =
      named(std::span{signature_lists}, profile->signature_list);
  if (!ciphers || ciphers->entries.empty() || !groups ||
      groups->entries.empty() || !signatures || signatures->entries.empty())
    return {.policy = std::nullopt,
            .diagnostic = problem(Error::incomplete_tls13_profile,
                                  profile->name, "algorithm-list")};

  ResolvedTls13Policy resolved;
  resolved.certificate_profile = profile->certificate_profile;
  resolved.status_verification = profile->status_verification;
  if constexpr (requires { profile->trust_anchor_profile; }) {
    resolved.trust_anchor_profile = profile->trust_anchor_profile;
    resolved.require_peer_certificate = !profile->trust_anchor_profile.empty();
  } else {
    // A TLS server cannot produce the mandatory Certificate and
    // CertificateVerify handshake messages without an identity profile.
    // Client certificates are optional, so this requirement is deliberately
    // confined to the server specialization.
    if (profile->certificate_profile.empty())
      return {.policy = std::nullopt,
              .diagnostic = problem(Error::incomplete_tls13_profile,
                                    profile->name, "cert-profile")};
    resolved.trust_anchor_profile = profile->client_trust_anchor_profile;
    resolved.common_name_list = profile->client_common_name_list;
    resolved.require_peer_certificate =
        !profile->client_trust_anchor_profile.empty();
  }

  const auto append = [&](const AlgorithmList &list, AlgorithmFamily family,
                          std::vector<std::string_view> &target) {
    // Configuration order is the ascending numeric key, not insertion order.
    // Sorting a small control-plane copy preserves the candidate and prevents
    // mutation of the operator's stored list while producing Hello order.
    auto ordered = list.entries;
    std::sort(ordered.begin(), ordered.end(),
              [](const auto &left, const auto &right) {
                return left.index < right.index;
              });
    for (const auto &entry : ordered) {
      const auto *mapped = algorithm(family, entry.name);
      if (mapped && (!configuration.use_pqc_only || mapped->pqc))
        target.push_back(mapped->openssl);
    }
  };
  append(*ciphers, AlgorithmFamily::cipher, resolved.cipher_suites);
  append(*groups, AlgorithmFamily::group, resolved.groups);
  append(*signatures, AlgorithmFamily::signature, resolved.signatures);
  if (resolved.cipher_suites.empty() || resolved.groups.empty() ||
      resolved.signatures.empty())
    return {.policy = std::nullopt,
            .diagnostic =
                problem(Error::pqc_algorithm_required, profile->name)};
  return {.policy = std::move(resolved), .diagnostic = std::nullopt};
}

} // namespace

const device_catalog::TlsAlgorithmName *
algorithm(AlgorithmFamily family, std::string_view sros_name) noexcept {
  const auto find = [sros_name](const auto &values)
      -> const device_catalog::TlsAlgorithmName * {
    const auto found = std::find_if(values.begin(), values.end(),
                                    [sros_name](const auto &value) {
                                      return value.sros == sros_name;
                                    });
    return found == values.end() ? nullptr : &*found;
  };
  switch (family) {
  case AlgorithmFamily::cipher:
    return find(device_catalog::tls13_ciphers);
  case AlgorithmFamily::group:
    return find(device_catalog::tls13_groups);
  case AlgorithmFamily::signature:
    return find(device_catalog::tls13_signatures);
  }
  return nullptr;
}

std::optional<Diagnostic>
validate(const Configuration &configuration) noexcept {
  if (auto issue = validate_named_objects(
          std::span{configuration.certificate_profiles},
          device_catalog::tls_maximum_cert_profiles, "cert-profile"))
    return issue;
  for (const auto &profile : configuration.certificate_profiles) {
    if (profile.entries.size() >
        device_catalog::tls_maximum_cert_entries_per_profile)
      return problem(Error::too_many_objects, profile.name, "entry");
    for (std::size_t position = 0; position < profile.entries.size();
         ++position) {
      const auto &entry = profile.entries[position];
      if (entry.id == 0U ||
          entry.id > device_catalog::tls_maximum_cert_entries_per_profile)
        return problem(Error::invalid_index, profile.name, "entry", entry.id);
      for (std::size_t prior = 0; prior < position; ++prior)
        if (profile.entries[prior].id == entry.id)
          return problem(Error::duplicate_index, profile.name, "entry",
                         entry.id);
      if ((!entry.certificate_file.empty() &&
           !valid_file_name(entry.certificate_file)) ||
          (!entry.key_file.empty() && !valid_file_name(entry.key_file)))
        return problem(Error::invalid_certificate_file, profile.name,
                       entry.certificate_file.empty() ? entry.key_file
                                                      : entry.certificate_file,
                       entry.id);
      if (entry.send_chain_ca_profiles.size() > 7U)
        return problem(Error::too_many_objects, profile.name,
                       "send-chain ca-profile", entry.id);
      if (auto issue = validate_reference_names(
              entry.send_chain_ca_profiles, profile.name,
              "send-chain ca-profile"))
        return issue;
    }
  }
  if (auto issue = validate_named_objects(
          std::span{configuration.trust_anchor_profiles},
          device_catalog::tls_maximum_trust_anchor_profiles,
          "trust-anchor-profile"))
    return issue;
  for (const auto &profile : configuration.trust_anchor_profiles)
    if (profile.ca_profiles.size() >
        device_catalog::tls_maximum_trust_anchors_per_profile)
      return problem(Error::too_many_objects, profile.name, "trust-anchor");
    else if (auto issue = validate_reference_names(
                 profile.ca_profiles, profile.name, "trust-anchor"))
      return issue;

  const auto validate_lists = [&](const auto &lists, std::size_t maximum,
                                  AlgorithmFamily family,
                                  std::string_view kind)
      -> std::optional<Diagnostic> {
    return validate_algorithm_lists(std::span{lists}, maximum, family, kind);
  };
  if (auto issue = validate_lists(configuration.client_cipher_lists,
                                  device_catalog::tls_maximum_client_cipher_lists,
                                  AlgorithmFamily::cipher,
                                  "client-cipher-list"))
    return issue;
  if (auto issue = validate_lists(configuration.client_group_lists,
                                  device_catalog::tls_maximum_client_group_lists,
                                  AlgorithmFamily::group,
                                  "client-group-list"))
    return issue;
  if (auto issue = validate_lists(
          configuration.client_signature_lists,
          device_catalog::tls_maximum_client_signature_lists,
          AlgorithmFamily::signature, "client-signature-list"))
    return issue;
  if (auto issue = validate_lists(configuration.server_cipher_lists,
                                  device_catalog::tls_maximum_server_cipher_lists,
                                  AlgorithmFamily::cipher,
                                  "server-cipher-list"))
    return issue;
  if (auto issue = validate_lists(configuration.server_group_lists,
                                  device_catalog::tls_maximum_server_group_lists,
                                  AlgorithmFamily::group,
                                  "server-group-list"))
    return issue;
  if (auto issue = validate_lists(
          configuration.server_signature_lists,
          device_catalog::tls_maximum_server_signature_lists,
          AlgorithmFamily::signature, "server-signature-list"))
    return issue;

  if (auto issue = validate_named_objects(
          std::span{configuration.client_profiles},
          device_catalog::tls_maximum_client_profiles,
          "client-tls-profile"))
    return issue;
  if (auto issue = validate_named_objects(
          std::span{configuration.server_profiles},
          device_catalog::tls_maximum_server_profiles,
          "server-tls-profile"))
    return issue;
  for (const auto &profile : configuration.client_profiles) {
    if (auto issue = validate_profile_references(profile, configuration))
      return issue;
    if (auto issue = validate_pqc_assignment(profile, configuration,
                                             EndpointRole::client))
      return issue;
  }
  for (const auto &profile : configuration.server_profiles) {
    if (auto issue = validate_profile_references(profile, configuration))
      return issue;
    if (auto issue = validate_pqc_assignment(profile, configuration,
                                             EndpointRole::server))
      return issue;
  }
  return std::nullopt;
}

Resolution resolve_client(const Configuration &configuration,
                          std::string_view profile_name) noexcept {
  if (auto issue = validate(configuration))
    return {.policy = std::nullopt, .diagnostic = std::move(issue)};
  return resolve(named(std::span{configuration.client_profiles}, profile_name),
                 configuration, EndpointRole::client);
}

Resolution resolve_server(const Configuration &configuration,
                          std::string_view profile_name) noexcept {
  if (auto issue = validate(configuration))
    return {.policy = std::nullopt, .diagnostic = std::move(issue)};
  return resolve(named(std::span{configuration.server_profiles}, profile_name),
                 configuration, EndpointRole::server);
}

} // namespace router::tls_profile
