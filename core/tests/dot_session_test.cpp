// DNS-over-TLS integration test. The test generates a local CA and resolver
// identity, authenticates TLS 1.3, pipelines two DNS messages and copies every
// ciphertext octet through the same bounded interface used by modeled TCP.

#include "router/dot_session.hpp"
#include "router/pki_store.hpp"

#include <array>
#include <stdexcept>
#include <vector>

namespace {

void transfer(router::dot::Session &source, router::dot::Session &destination) {
  std::array<std::uint8_t, 127U> ciphertext{};
  while (source.pending_ciphertext() != 0U) {
    const auto count = source.take_ciphertext(ciphertext);
    if (count == 0U ||
        destination.ingest_ciphertext(
            std::span<const std::uint8_t>{ciphertext}.first(count)) != count)
      throw std::runtime_error("DoT ciphertext transfer was not lossless");
  }
}

} // namespace

void dot_session_tests() {
  using namespace router;
  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(0x31U + index);
  const std::array<std::uint8_t, 8U> context{'d', 'o', 't', '-', 't', 'e', 's',
                                             't'};
  auto store = pki::Store::create(wrapping_key, context);
  if (!store)
    throw std::runtime_error("DoT test PKI store failed");
  constexpr std::uint64_t year_2029 = 1861920000U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2031 = 1924992000U;
  const auto [ca_result, ca_id] = store->create_authority(
      {.subject = {.common_name = "DoT Test Root",
                   .organization = {},
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = pki::KeyAlgorithm::ecdsa_p256,
       .not_before = year_2029,
       .not_after = year_2031,
       .path_length = 0U});
  const auto [identity_result, identity_id] = store->issue_identity(
      ca_id,
      {.subject = {.common_name = "resolver.lab.example",
                   .organization = {},
                   .organizational_unit = {},
                   .country = {}},
       .key_algorithm = pki::KeyAlgorithm::ecdsa_p256,
       .usage = pki::CertificateUsage::tls_server,
       .dns_names = {"resolver.lab.example"},
       .ipv4_addresses = {},
       .ipv6_addresses = {},
       .not_before = year_2029,
       .not_after = year_2031});
  auto identity = store->open_identity(identity_id);
  const auto *authority = store->authority(ca_id);
  if (ca_result != pki::MutationResult::applied ||
      identity_result != pki::MutationResult::applied || !identity ||
      !authority)
    throw std::runtime_error("DoT test identity generation failed");
  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};

  auto server_tls = tls::Engine::server(
      {.identity = &*identity,
       .trust_anchors_der = {},
       .policy = nullptr,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .require_client_certificate = false,
       .alpn_protocols = {}});
  auto client_tls = tls::Engine::client(
      {.identity = nullptr,
       .trust_anchors_der = anchors,
       .peer = {.hostname = "resolver.lab.example",
                .ipv4_address = std::nullopt,
                .ipv6_address = std::nullopt},
       .peer_authentication = tls::PeerAuthentication::required,
       .policy = nullptr,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .alpn_protocols = {}});
  if (!server_tls || !client_tls)
    throw std::runtime_error("DoT TLS engine creation failed");
  const dot::Configuration limits{.max_dns_message_octets = 65535U,
                                  .max_queued_outgoing_messages = 8U,
                                  .max_queued_incoming_messages = 8U};
  auto server = dot::Session::create(std::move(*server_tls), limits);
  auto client = dot::Session::create(std::move(*client_tls), limits);
  if (!server || !client)
    throw std::runtime_error("DoT session creation failed");

  const std::array<std::uint8_t, 12U> query_one{
      0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  const std::array<std::uint8_t, 12U> query_two{
      0xabU, 0xcdU, 0x01U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  if (client->queue_message(query_one) != dot::QueueResult::queued ||
      client->queue_message(query_two) != dot::QueueResult::queued)
    throw std::runtime_error("DoT pipeline admission failed");

  for (std::size_t turn = 0U; turn < 128U; ++turn) {
    static_cast<void>(client->progress());
    transfer(*client, *server);
    static_cast<void>(server->progress());
    transfer(*server, *client);
    if (server->queued_incoming_messages() == 2U)
      break;
  }
  const auto received_one = server->take_message();
  const auto received_two = server->take_message();
  if (!received_one || !received_two ||
      *received_one !=
          std::vector<std::uint8_t>(query_one.begin(), query_one.end()) ||
      *received_two !=
          std::vector<std::uint8_t>(query_two.begin(), query_two.end()) ||
      client->state() != dot::State::established ||
      server->state() != dot::State::established)
    throw std::runtime_error("DoT did not preserve pipelined DNS messages");

  // A zero-length DNS message is invalid even though it fits the two-octet
  // transport field. Rejecting it before TLS output keeps the operation atomic.
  const std::array<std::uint8_t, 1U> invalid{0U};
  if (client->queue_message(invalid) != dot::QueueResult::invalid_message ||
      client->failure() != dot::Failure::none)
    throw std::runtime_error("DoT malformed message policy was not atomic");
}
