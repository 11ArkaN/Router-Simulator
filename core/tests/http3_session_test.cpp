// End-to-end HTTP/3 module test over the emulator's socket-free QUIC owner.
// The test proves TLS authentication, ALPN, mandatory HTTP/3 unidirectional
// streams, QPACK, request framing, response framing and QUIC datagram transfer
// without bypassing the modeled UDP boundary.

#include "router/doh3_session.hpp"
#include "router/pki_store.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

router::quic::TransportConfiguration transport_limits() {
  // These are explicit test resource limits, not protocol defaults. The
  // production owner obtains the same fields from the selected resource
  // profile so a large body or stream fan-out cannot allocate without bound.
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
          .pad_stream_datagrams = false};
}

router::http3::Configuration http_limits() {
  return {.max_field_section_octets = 64U * 1024U,
          .max_body_octets = 1024U * 1024U,
          .max_completed_messages = 32U,
          .max_staged_output_octets = 64U * 1024U,
          .qpack_dynamic_table_octets = 4096U,
          .qpack_blocked_streams = 16U,
          .max_remote_bidirectional_streams = 32U};
}

} // namespace

void http3_session_tests() {
  using namespace router;

  // Generate the complete trust relationship within the project PKI owner.
  // No fixture key, certificate, trust decision or hostname is hidden inside
  // the HTTP/3 adapter.
  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(0x41U + index);
  const std::array<std::uint8_t, 10U> vault_context{
      'h', 't', 't', 'p', '3', '-', 't', 'e', 's', 't'};
  auto store = pki::Store::create(wrapping_key, vault_context);
  if (!store)
    throw std::runtime_error("HTTP/3 test PKI store failed");

  constexpr std::uint64_t year_2029 = 1861920000U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2031 = 1924992000U;
  const auto [ca_result, ca_id] = store->create_authority(
      {.subject = {.common_name = "HTTP3 Test Root",
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
    throw std::runtime_error("HTTP/3 test identity generation failed");

  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};
  const std::array<std::string_view, 1U> alpn{"h3"};
  const auto client_ip = *ip::parse_ipv6("2001:db8:3::10");
  const auto server_ip = *ip::parse_ipv6("2001:db8:3::53");
  const quic::Path client_path{
      .local = quic::EndpointAddress::ipv6(client_ip, 49153U),
      .remote = quic::EndpointAddress::ipv6(server_ip, 443U)};
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
    throw std::runtime_error("HTTP/3 QUIC client construction failed");

  std::array<std::uint8_t, 1350U> datagram{};
  quic::Path emitted_path{};
  const auto initial_size = client->take_datagram(datagram, emitted_path,
                                                   started);
  if (initial_size < quic::minimum_initial_datagram_octets ||
      !(emitted_path == client_path))
    throw std::runtime_error("HTTP/3 client did not emit a QUIC Initial");

  // The reset secret belongs to the project/server profile. Supplying it here
  // verifies the transport never substitutes a process-global constant.
  std::array<std::uint8_t, 32U> reset_secret{};
  for (std::size_t index = 0U; index < reset_secret.size(); ++index)
    reset_secret[index] = static_cast<std::uint8_t>(0xc0U + index);
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
    throw std::runtime_error("HTTP/3 server rejected the QUIC Initial");

  // Unit-test timestamps are deterministic arrival instants. Production uses
  // steady_clock and offers no public stepping or simulated-time mechanism.
  for (std::size_t turn = 1U; turn < 512U &&
                              (client->state() != quic::State::established ||
                               server->state() != quic::State::established);
       ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    const auto server_size = server->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U &&
        client->ingest_datagram(
            client_path,
            std::span<const std::uint8_t>{datagram}.first(server_size), now) !=
            quic::Failure::none)
      throw std::runtime_error("HTTP/3 client rejected a handshake datagram");
    const auto client_size = client->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U &&
        server->ingest_datagram(
            server_path,
            std::span<const std::uint8_t>{datagram}.first(client_size), now) !=
            quic::Failure::none)
      throw std::runtime_error("HTTP/3 server rejected a handshake datagram");
  }
  if (client->state() != quic::State::established ||
      server->state() != quic::State::established ||
      client->negotiated_alpn() != "h3" || server->negotiated_alpn() != "h3")
    throw std::runtime_error("HTTP/3 QUIC handshake or ALPN failed");

  auto client_http =
      http3::Session::create(std::move(*client), http3::Role::client,
                             http_limits());
  auto server_http =
      http3::Session::create(std::move(*server), http3::Role::server,
                             http_limits());
  if (!client_http || !server_http)
    throw std::runtime_error("HTTP/3 session construction failed");
  const doh3::Configuration service{.authority = "resolver.lab.example",
                                    .path = "/dns-query"};
  auto client_session =
      doh3::Session::create(std::move(*client_http), service);
  auto server_session =
      doh3::Session::create(std::move(*server_http), service);
  if (!client_session || !server_session)
    throw std::runtime_error("DoH3 service construction failed");

  const std::array<std::uint8_t, 12U> dns_query{
      0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  const auto submitted =
      client_session->submit_query(doh3::Method::post, dns_query);
  if (submitted.result != http3::SubmitResult::applied ||
      submitted.stream_id != 0)
    throw std::runtime_error("DoH3 request could not be submitted");

  std::optional<doh3::Request> received_request;
  for (std::size_t turn = 512U; turn < 2048U && !received_request; ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    static_cast<void>(client_session->progress(now));
    const auto client_size =
        client_session->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U &&
        server_session->ingest_datagram(
            server_path,
            std::span<const std::uint8_t>{datagram}.first(client_size), now) !=
            quic::Failure::none)
      throw std::runtime_error("HTTP/3 server rejected request bytes");
    static_cast<void>(server_session->progress(now));
    const auto server_size =
        server_session->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U)
      static_cast<void>(client_session->ingest_datagram(
          client_path,
          std::span<const std::uint8_t>{datagram}.first(server_size), now));
    received_request = server_session->take_request();
  }
  if (!received_request ||
      received_request->status != doh3::RequestStatus::valid ||
      received_request->method != doh3::Method::post ||
      received_request->stream_id != submitted.stream_id ||
      received_request->dns_message !=
          std::vector<std::uint8_t>(dns_query.begin(), dns_query.end()))
    throw std::runtime_error("DoH3 request was not reconstructed correctly");

  auto dns_response = dns_query;
  dns_response[2U] |= 0x80U;
  if (server_session->submit_response(submitted.stream_id, dns_response,
                                      60U) !=
      http3::SubmitResult::applied)
    throw std::runtime_error("DoH3 response could not be submitted");

  std::optional<doh3::Response> received_response;
  for (std::size_t turn = 2048U; turn < 4096U && !received_response; ++turn) {
    const auto now = started + std::chrono::milliseconds{turn};
    static_cast<void>(server_session->progress(now));
    const auto server_size =
        server_session->take_datagram(datagram, emitted_path, now);
    if (server_size != 0U &&
        client_session->ingest_datagram(
            client_path,
            std::span<const std::uint8_t>{datagram}.first(server_size), now) !=
            quic::Failure::none)
      throw std::runtime_error("HTTP/3 client rejected response bytes");
    static_cast<void>(client_session->progress(now));
    const auto client_size =
        client_session->take_datagram(datagram, emitted_path, now);
    if (client_size != 0U)
      static_cast<void>(server_session->ingest_datagram(
          server_path,
          std::span<const std::uint8_t>{datagram}.first(client_size), now));
    received_response = client_session->take_response();
  }
  if (!received_response ||
      received_response->stream_id != submitted.stream_id ||
      received_response->http_status != 200U ||
      received_response->dns_message != std::vector<std::uint8_t>(
                                            dns_response.begin(),
                                            dns_response.end()))
    throw std::runtime_error("DoH3 response was not reconstructed correctly");
}
