// End-to-end QUIC v1 module test over copied IPv6 UDP payloads. The test uses
// an independently generated local certificate chain, negotiates ALPN and
// exchanges a bidirectional stream without constructing a host socket.

#include "router/pki_store.hpp"
#include "router/quic_connection.hpp"
#include "router/doq_session.hpp"

#include <array>
#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

router::quic::TransportConfiguration transport_limits() {
  return {.connection_receive_window = 1024U * 1024U,
          .stream_receive_window = 256U * 1024U,
          .max_bidirectional_streams = 32U,
          .max_unidirectional_streams = 16U,
          .max_idle_timeout_milliseconds = 30'000U,
          .max_udp_payload_octets = 1350U,
          .max_buffered_receive_octets = 1024U * 1024U,
          .max_buffered_send_octets = 1024U * 1024U,
          .max_pending_transport_events = 4096U,
          .congestion_control = router::quic::CongestionControl::cubic,
          .allow_active_migration = false,
          .pad_stream_datagrams = true};
}

} // namespace

void quic_connection_tests() {
  using namespace router;
  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(0x21U + index);
  const std::array<std::uint8_t, 9U> vault_context{
      'q', 'u', 'i', 'c', '-', 't', 'e', 's', 't'};
  auto store = pki::Store::create(wrapping_key, vault_context);
  if (!store)
    throw std::runtime_error("QUIC test PKI store failed");
  constexpr std::uint64_t year_2029 = 1861920000U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2031 = 1924992000U;
  const auto [ca_result, ca_id] = store->create_authority(
      {.subject = {.common_name = "QUIC Test Root",
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
    throw std::runtime_error("QUIC test identity generation failed");

  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};
  const std::array<std::string_view, 1U> alpn{"doq"};
  const auto client_ip = *ip::parse_ipv6("2001:db8:1::10");
  const auto server_ip = *ip::parse_ipv6("2001:db8:1::53");
  const quic::Path client_path{
      .local = quic::EndpointAddress::ipv6(client_ip, 49152U),
      .remote = quic::EndpointAddress::ipv6(server_ip, 853U)};
  const quic::Path server_path{.local = client_path.remote,
                               .remote = client_path.local};
  const auto started = quic::RuntimeClock::now();
  auto client = quic::Connection::client(
      {.initial_path = client_path,
       .transport = transport_limits(),
       .identity = nullptr,
       .trust_anchors_der = anchors,
       .peer = {.hostname = "resolver.lab.example",
                .ipv4_address = std::nullopt,
                .ipv6_address = std::nullopt},
       .peer_authentication = tls::PeerAuthentication::required,
       .tls_policy = nullptr,
       .wall_clock_seconds = year_2030,
       .alpn_protocols = alpn},
      started);
  if (!client)
    throw std::runtime_error("QUIC client construction failed");

  std::array<std::uint8_t, 1350U> datagram{};
  quic::Path emitted_path{};
  const auto initial_size =
      client->take_datagram(datagram, emitted_path, started);
  if (initial_size < quic::minimum_initial_datagram_octets ||
      !(emitted_path == client_path))
    throw std::runtime_error("QUIC client did not emit a valid Initial");
  std::array<std::uint8_t, 32U> reset_secret{};
  for (std::size_t index = 0U; index < reset_secret.size(); ++index)
    reset_secret[index] = static_cast<std::uint8_t>(0xa0U + index);
  auto server = quic::Connection::server(
      {.initial_path = server_path,
       .transport = transport_limits(),
       .identity = &*identity,
       .trust_anchors_der = {},
       .tls_policy = nullptr,
       .wall_clock_seconds = year_2030,
       .alpn_protocols = alpn,
       .require_client_certificate = false,
       .stateless_reset_secret = reset_secret},
      std::span<const std::uint8_t>{datagram}.first(initial_size), started);
  if (!server)
    throw std::runtime_error("QUIC server rejected the client Initial");

  // Advancing the supplied monotonic timestamps represents actual arrival
  // instants in a deterministic unit test. Production obtains them only from
  // RuntimeClock and never exposes this loop as simulated-time control.
  for (std::size_t turn = 1U; turn < 512U &&
                              (client->state() != quic::State::established ||
                               server->state() != quic::State::established);
       ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    const auto server_size = server->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U &&
        client->ingest_datagram(client_path,
                                std::span<const std::uint8_t>{datagram}.first(
                                    server_size),
                                now) != quic::Failure::none)
      throw std::runtime_error("QUIC client rejected a server datagram");
    const auto client_size = client->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U &&
        server->ingest_datagram(server_path,
                                std::span<const std::uint8_t>{datagram}.first(
                                    client_size),
                                now) != quic::Failure::none)
      throw std::runtime_error("QUIC server rejected a client datagram");
  }
  if (client->state() != quic::State::established ||
      server->state() != quic::State::established ||
      client->negotiated_alpn() != "doq" ||
      server->negotiated_alpn() != "doq")
    throw std::runtime_error("QUIC handshake or ALPN negotiation failed");

  auto client_session = doq::Session::create(
      std::move(*client), {.role = doq::Role::client,
                           .max_completed_transactions = 16U,
                           .max_incomplete_streams = 16U});
  auto server_session = doq::Session::create(
      std::move(*server), {.role = doq::Role::server,
                           .max_completed_transactions = 16U,
                           .max_incomplete_streams = 16U});
  if (!client_session || !server_session)
    throw std::runtime_error("DoQ session construction failed");
  const std::array<std::uint8_t, 12U> first_query{
      0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  const std::array<std::uint8_t, 12U> second_query{
      0x00U, 0x00U, 0x01U, 0x20U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  std::int64_t first_stream{};
  std::int64_t second_stream{};
  if (client_session->submit_query(first_query, first_stream) !=
          doq::SubmitResult::applied ||
      client_session->submit_query(second_query, second_stream) !=
          doq::SubmitResult::applied ||
      first_stream != 0 || second_stream != 4)
    throw std::runtime_error("DoQ did not allocate one stream per query");
  std::optional<doq::Transaction> first_received;
  std::optional<doq::Transaction> second_received;
  for (std::size_t turn = 512U; turn < 1536U && !second_received; ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    const auto client_size =
        client_session->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U &&
        server_session->ingest_datagram(
            server_path,
            std::span<const std::uint8_t>{datagram}.first(client_size), now) !=
            quic::Failure::none)
      throw std::runtime_error("DoQ query datagram was rejected");
    static_cast<void>(server_session->progress());
    const auto server_size =
        server_session->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U)
      static_cast<void>(client_session->ingest_datagram(
          client_path,
          std::span<const std::uint8_t>{datagram}.first(server_size), now));
    static_cast<void>(client_session->progress());
    if (!first_received)
      first_received = server_session->take_transaction();
    else if (!second_received)
      second_received = server_session->take_transaction();
  }
  const auto received_matches = [&](const doq::Transaction &transaction) {
    return (transaction.stream_id == first_stream &&
            transaction.dns_message == std::vector<std::uint8_t>(
                                           first_query.begin(),
                                           first_query.end())) ||
           (transaction.stream_id == second_stream &&
            transaction.dns_message == std::vector<std::uint8_t>(
                                           second_query.begin(),
                                           second_query.end()));
  };
  if (!first_received || !second_received ||
      first_received->stream_id == second_received->stream_id ||
      !received_matches(*first_received) || !received_matches(*second_received))
    throw std::runtime_error("DoQ did not reconstruct concurrent queries");

  auto first_response = first_query;
  auto second_response = second_query;
  first_response[2U] |= 0x80U;
  second_response[2U] |= 0x80U;
  // Responding in reverse stream order verifies that QUIC multiplexing, not
  // arrival order, correlates each DNS transaction.
  if (server_session->submit_response(second_stream, second_response) !=
          doq::SubmitResult::applied ||
      server_session->submit_response(first_stream, first_response) !=
          doq::SubmitResult::applied)
    throw std::runtime_error("DoQ responses could not be queued");
  std::optional<doq::Transaction> response_one;
  std::optional<doq::Transaction> response_two;
  for (std::size_t turn = 1536U; turn < 2560U && !response_two; ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    const auto server_size =
        server_session->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U)
      static_cast<void>(client_session->ingest_datagram(
          client_path,
          std::span<const std::uint8_t>{datagram}.first(server_size), now));
    static_cast<void>(client_session->progress());
    const auto client_size =
        client_session->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U)
      static_cast<void>(server_session->ingest_datagram(
          server_path,
          std::span<const std::uint8_t>{datagram}.first(client_size), now));
    static_cast<void>(server_session->progress());
    if (!response_one)
      response_one = client_session->take_transaction();
    else if (!response_two)
      response_two = client_session->take_transaction();
  }
  const auto response_matches = [&](const doq::Transaction &transaction) {
    return (transaction.stream_id == first_stream &&
            transaction.dns_message == std::vector<std::uint8_t>(
                                           first_response.begin(),
                                           first_response.end())) ||
           (transaction.stream_id == second_stream &&
            transaction.dns_message == std::vector<std::uint8_t>(
                                           second_response.begin(),
                                           second_response.end()));
  };
  if (!response_one || !response_two ||
      response_one->stream_id == response_two->stream_id ||
      !response_matches(*response_one) || !response_matches(*response_two))
    throw std::runtime_error(
        "DoQ responses lost stream correlation: first=" +
        (response_one ? std::to_string(response_one->stream_id) : "missing") +
        ", second=" +
        (response_two ? std::to_string(response_two->stream_id) : "missing") +
        ", client-state=" +
        std::to_string(static_cast<unsigned>(client_session->state())) +
        ", client-failure=" +
        std::to_string(static_cast<unsigned>(client_session->failure())));
}
