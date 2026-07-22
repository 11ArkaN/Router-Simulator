// DoH over HTTP/2 interoperability test. TLS authenticates the local resolver
// and negotiates h2. One GET and one POST then share the same multiplexed
// connection, while only copied TLSCiphertext crosses between owners.

#include "router/doh2_session.hpp"
#include "router/dns_packet.hpp"
#include "router/pki_store.hpp"

#include <array>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

void transfer(router::doh2::Session &source,
              router::doh2::Session &destination) {
  std::array<std::uint8_t, 211U> ciphertext{};
  while (source.pending_ciphertext() != 0U) {
    const auto count = source.take_ciphertext(ciphertext);
    if (count == 0U ||
        destination.ingest_ciphertext(
            std::span<const std::uint8_t>{ciphertext}.first(count)) != count)
      throw std::runtime_error("DoH2 ciphertext transfer was not lossless");
  }
}

} // namespace

void doh2_session_tests() {
  using namespace router;
  std::array<std::uint8_t, 32U> wrapping_key{};
  for (std::size_t index = 0U; index < wrapping_key.size(); ++index)
    wrapping_key[index] = static_cast<std::uint8_t>(0x51U + index);
  const std::array<std::uint8_t, 9U> context{
      'd', 'o', 'h', '2', '-', 't', 'e', 's', 't'};
  auto store = pki::Store::create(wrapping_key, context);
  if (!store)
    throw std::runtime_error("DoH2 test PKI store failed");
  constexpr std::uint64_t year_2029 = 1861920000U;
  constexpr std::uint64_t year_2030 = 1893456000U;
  constexpr std::uint64_t year_2031 = 1924992000U;
  const auto [ca_result, ca_id] = store->create_authority(
      {.subject = {.common_name = "DoH2 Test Root",
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
    throw std::runtime_error("DoH2 test identity generation failed");
  const std::vector<std::vector<std::uint8_t>> anchors{
      authority->certificate_der};
  const std::array<std::string_view, 1U> h2{"h2"};
  auto server_tls = tls::Engine::server(
      {.identity = &*identity,
       .trust_anchors_der = {},
       .policy = nullptr,
       .wall_clock_seconds = year_2030,
       .transport_buffer_octets = 65536U,
       .require_client_certificate = false,
       .alpn_protocols = h2});
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
       .alpn_protocols = h2});
  const http2::Configuration http_limits{
      .max_concurrent_streams = 8U,
      .max_header_octets = 16384U,
      .max_message_body_octets = packet::dns::maximum_message_octets,
      .max_buffered_output_octets = 65536U,
      .max_completed_messages = 16U,
      .accept_server_push = false};
  auto server_http = http2::Session::create(http2::Role::server, http_limits);
  auto client_http = http2::Session::create(http2::Role::client, http_limits);
  if (!server_tls || !client_tls || !server_http || !client_http)
    throw std::runtime_error("DoH2 transport construction failed");
  const doh2::Configuration service{.authority = "resolver.lab.example",
                                    .path = "/dns-query",
                                    .plaintext_staging_octets = 65536U};
  auto server = doh2::Session::create(std::move(*server_tls),
                                      std::move(*server_http), service);
  auto client = doh2::Session::create(std::move(*client_tls),
                                      std::move(*client_http), service);
  if (!server || !client)
    throw std::runtime_error("DoH2 service construction failed");

  const std::array<std::uint8_t, 12U> get_query{
      0x00U, 0x00U, 0x01U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  const std::array<std::uint8_t, 12U> post_query{
      0x00U, 0x00U, 0x01U, 0x20U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U};
  const auto get_stream = client->submit_query(doh2::Method::get, get_query);
  const auto post_stream =
      client->submit_query(doh2::Method::post, post_query);
  if (get_stream.result != http2::SubmitResult::applied ||
      post_stream.result != http2::SubmitResult::applied)
    throw std::runtime_error("DoH2 GET or POST submission failed");

  for (std::size_t turn = 0U; turn < 256U; ++turn) {
    static_cast<void>(client->progress());
    transfer(*client, *server);
    static_cast<void>(server->progress());
    transfer(*server, *client);
    if (server->state() == doh2::State::failed ||
        client->state() == doh2::State::failed)
      break;
  }
  auto first_request = server->take_request();
  auto second_request = server->take_request();
  if (!first_request || !second_request ||
      first_request->status != doh2::RequestStatus::valid ||
      second_request->status != doh2::RequestStatus::valid ||
      first_request->method != doh2::Method::get ||
      second_request->method != doh2::Method::post ||
      first_request->dns_message !=
          std::vector<std::uint8_t>(get_query.begin(), get_query.end()) ||
      second_request->dns_message !=
          std::vector<std::uint8_t>(post_query.begin(), post_query.end()))
    throw std::runtime_error("DoH2 server did not decode GET and POST");

  auto get_response = get_query;
  auto post_response = post_query;
  get_response[2U] = 0x81U;
  get_response[3U] = 0x80U;
  post_response[2U] = 0x81U;
  post_response[3U] = 0x80U;
  if (server->submit_response(first_request->stream_id, get_response, 60U) !=
          http2::SubmitResult::applied ||
      server->submit_response(second_request->stream_id, post_response, 30U) !=
          http2::SubmitResult::applied)
    throw std::runtime_error("DoH2 response submission failed");
  for (std::size_t turn = 0U; turn < 256U; ++turn) {
    static_cast<void>(server->progress());
    transfer(*server, *client);
    static_cast<void>(client->progress());
    transfer(*client, *server);
  }
  const auto first_response = client->take_response();
  const auto second_response = client->take_response();
  if (!first_response || !second_response || !first_response->complete ||
      !second_response->complete || first_response->http_status != 200U ||
      second_response->http_status != 200U ||
      first_response->dns_message !=
          std::vector<std::uint8_t>(get_response.begin(), get_response.end()) ||
      second_response->dns_message != std::vector<std::uint8_t>(
                                          post_response.begin(),
                                          post_response.end()))
    throw std::runtime_error("DoH2 client did not decode DNS responses");
}
