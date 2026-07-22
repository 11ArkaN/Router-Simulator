// TLS 1.3 integration test. Client and server exchange only ciphertext copied
// between bounded memory BIOs, which is the same contract used by modeled TCP.
// Certificate generation and validation use the local encrypted PKI store.

#include "router/pki_store.hpp"
#include "router/generated_device_catalog.hpp"
#include "router/tls_engine.hpp"

#include <array>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

void transfer(router::tls::Engine &source, router::tls::Engine &destination) {
  std::array<std::uint8_t, 4096U> buffer{};
  while (source.pending_ciphertext() != 0U) {
    const auto count = source.take_ciphertext(buffer);
    if (count == 0U ||
        destination.ingest_ciphertext(
            std::span<const std::uint8_t>{buffer}.first(count)) != count)
      throw std::runtime_error("TLS ciphertext transfer was not lossless");
  }
}

} // namespace

void tls_engine_tests() {
  using namespace router;

  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(0x80U + index);
  const std::array<std::uint8_t, 8U> context{
      't', 'l', 's', '-', 't', 'e', 's', 't'};
  auto store = pki::Store::create(wrapping_key, context);
  if (!store)
    throw std::runtime_error("TLS test PKI store failed");
  constexpr std::uint64_t year_2029 = 1861920000U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2031 = 1924992000U;
  const auto [ca_result, ca_id] = store->create_authority(
      {.subject = {.common_name = "TLS Test Root",
                   .organization = {},
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = pki::KeyAlgorithm::ecdsa_p256,
       .not_before = year_2029,
       .not_after = year_2031,
       .path_length = 0U});
  const auto [server_result, server_id] = store->issue_identity(
      ca_id,
      {.subject = {.common_name = "dns.lab.example",
                   .organization = {},
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = pki::KeyAlgorithm::ecdsa_p256,
       .usage = pki::CertificateUsage::tls_server,
       .dns_names = {"dns.lab.example"},
       .ipv4_addresses = {},
       .ipv6_addresses = {},
       .not_before = year_2029,
       .not_after = year_2031});
  auto server_identity = store->open_identity(server_id);
  const auto *authority = store->authority(ca_id);
  if (ca_result != pki::MutationResult::applied ||
      server_result != pki::MutationResult::applied || !server_identity ||
      !authority)
    throw std::runtime_error("TLS test identity generation failed");
  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};
  const std::array<std::string_view, 1U> ciphers{
      "TLS_AES_256_GCM_SHA384"};
  const std::array<std::string_view, 1U> groups{"P-256"};
  const std::array<std::string_view, 1U> signatures{
      "ecdsa_secp256r1_sha256"};
  const tls::Tls13PolicyView policy{.cipher_suites = ciphers,
                                    .groups = groups,
                                    .signatures = signatures};
  const auto accepts_policy = [&](std::string_view cipher,
                                  std::string_view group,
                                  std::string_view signature) {
    const std::array<std::string_view, 1U> selected_cipher{cipher};
    const std::array<std::string_view, 1U> selected_group{group};
    const std::array<std::string_view, 1U> selected_signature{signature};
    const tls::Tls13PolicyView selected{
        .cipher_suites = selected_cipher,
        .groups = selected_group,
        .signatures = selected_signature};
    return tls::Engine::client(
        {.identity = nullptr,
         .trust_anchors_der = anchors,
         .peer = {.hostname = "dns.lab.example",
                  .ipv4_address = std::nullopt,
                  .ipv6_address = std::nullopt},
         .peer_authentication = tls::PeerAuthentication::required,
         .policy = &selected,
         .wall_clock_seconds = year_2030,
         .transport_buffer_octets = 65536U,
         .alpn_protocols = {}})
        .has_value();
  };
  // Every name published by the generated SR OS profile must be accepted by
  // the pinned OpenSSL build. This catches provider build-option drift before
  // completion advertises an algorithm that cannot reach a ClientHello.
  for (const auto &cipher : device_catalog::tls13_ciphers)
    if (!accepts_policy(cipher.openssl, groups.front(), signatures.front()))
      throw std::runtime_error("generated TLS 1.3 cipher is unavailable");
  for (const auto &group : device_catalog::tls13_groups)
    if (!accepts_policy(ciphers.front(), group.openssl, signatures.front()))
      throw std::runtime_error("generated TLS 1.3 group is unavailable");
  for (const auto &signature : device_catalog::tls13_signatures)
    if (!accepts_policy(ciphers.front(), groups.front(), signature.openssl))
      throw std::runtime_error("generated TLS 1.3 signature is unavailable");
  const std::array<std::string_view, 1U> h2_alpn{"h2"};
  auto server = tls::Engine::server(
      {.identity = &*server_identity,
       .trust_anchors_der = {},
       .policy = &policy,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .require_client_certificate = false,
       .alpn_protocols = h2_alpn});
  auto client = tls::Engine::client(
      {.identity = nullptr,
       .trust_anchors_der = anchors,
       .peer = {.hostname = "dns.lab.example",
                .ipv4_address = std::nullopt,
                .ipv6_address = std::nullopt},
       .peer_authentication = tls::PeerAuthentication::required,
       .policy = &policy,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .alpn_protocols = h2_alpn});
  if (!server || !client)
    throw std::runtime_error("TLS engine configuration failed");

  for (std::size_t turn = 0U; turn < 32U &&
                              (client->state() != tls::State::established ||
                               server->state() != tls::State::established);
       ++turn) {
    static_cast<void>(client->progress());
    transfer(*client, *server);
    static_cast<void>(server->progress());
    transfer(*server, *client);
  }
  if (client->state() != tls::State::established ||
      server->state() != tls::State::established ||
      client->negotiated_cipher() != "TLS_AES_256_GCM_SHA384" ||
      client->negotiated_alpn() != "h2" ||
      server->negotiated_alpn() != "h2" ||
      !client->peer_certificate_der())
    throw std::runtime_error("TLS 1.3 authenticated handshake failed");

  constexpr std::string_view message{"modeled TCP application bytes"};
  const auto cleartext = std::span<const std::uint8_t>{
      reinterpret_cast<const std::uint8_t *>(message.data()), message.size()};
  if (client->write_plaintext(cleartext) != cleartext.size())
    throw std::runtime_error("TLS application write was not accepted");
  transfer(*client, *server);
  std::array<std::uint8_t, 128U> received{};
  const auto read = server->read_plaintext(received);
  if (read != cleartext.size() ||
      !std::ranges::equal(cleartext,
                          std::span<const std::uint8_t>{received}.first(read)))
    throw std::runtime_error("TLS application plaintext changed in transit");

  auto wrong_name_client = tls::Engine::client(
      {.identity = nullptr,
       .trust_anchors_der = anchors,
       .peer = {.hostname = "wrong.lab.example",
                .ipv4_address = std::nullopt,
                .ipv6_address = std::nullopt},
       .peer_authentication = tls::PeerAuthentication::required,
       .policy = &policy,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .alpn_protocols = {}});
  auto second_server = tls::Engine::server(
      {.identity = &*server_identity,
       .trust_anchors_der = {},
       .policy = &policy,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .require_client_certificate = false,
       .alpn_protocols = {}});
  if (!wrong_name_client || !second_server)
    throw std::runtime_error("TLS mismatch fixture setup failed");
  for (std::size_t turn = 0U; turn < 32U &&
                              wrong_name_client->state() != tls::State::failed;
       ++turn) {
    static_cast<void>(wrong_name_client->progress());
    transfer(*wrong_name_client, *second_server);
    static_cast<void>(second_server->progress());
    transfer(*second_server, *wrong_name_client);
  }
  if (wrong_name_client->state() != tls::State::failed ||
      wrong_name_client->failure() != tls::Failure::certificate_rejected)
    throw std::runtime_error("TLS hostname mismatch was accepted");
}
