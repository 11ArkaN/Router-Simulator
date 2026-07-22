// HTTP/2 interoperability test between independent client and server session
// owners. Every byte crosses the public memory-stream contract in deliberately
// small chunks, exercising framing, HPACK, multiplexing and backpressure.

#include "router/http2_session.hpp"

#include <array>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using router::http2::Session;

bool transfer(Session &source, Session &destination) {
  std::array<std::uint8_t, 37U> wire{};
  bool moved{};
  while (source.wants_write()) {
    const auto produced = source.take_bytes(wire);
    if (produced == 0U)
      break;
    const auto consumed = destination.ingest_bytes(
        std::span<const std::uint8_t>{wire}.first(produced));
    if (consumed != produced)
      throw std::runtime_error("HTTP/2 transfer did not consume its prefix");
    moved = true;
  }
  return moved;
}

const router::http2::HeaderField *
find_header(const router::http2::Message &message, std::string_view name) {
  for (const auto &field : message.headers)
    if (field.name == name)
      return &field;
  return nullptr;
}

} // namespace

void http2_session_tests() {
  using namespace router::http2;
  const Configuration configuration{
      .max_concurrent_streams = 8U,
      .max_header_octets = 16384U,
      .max_message_body_octets = 1024U * 1024U,
      .max_buffered_output_octets = 65536U,
      .max_completed_messages = 16U,
      .accept_server_push = false};
  auto client = Session::create(Role::client, configuration);
  auto server = Session::create(Role::server, configuration);
  if (!client || !server)
    throw std::runtime_error("HTTP/2 session creation failed");

  const std::array<HeaderField, 5U> request_headers{
      HeaderField{":method", "POST"}, HeaderField{":scheme", "https"},
      HeaderField{":authority", "resolver.lab.example"},
      HeaderField{":path", "/dns-query"},
      HeaderField{"content-type", "application/dns-message"}};
  const std::array<std::uint8_t, 5U> first_body{0x12U, 0x34U, 0x01U, 0x00U,
                                               0x00U};
  const std::array<std::uint8_t, 3U> second_body{0xabU, 0xcdU, 0xefU};
  const auto first = client->submit_request(request_headers, first_body);
  const auto second = client->submit_request(request_headers, second_body);
  if (first.result != SubmitResult::applied ||
      second.result != SubmitResult::applied || first.stream_id <= 0 ||
      second.stream_id <= first.stream_id)
    throw std::runtime_error("HTTP/2 multiplexed request submission failed");

  // The loop has no simulated time. It merely drains work that both protocol
  // owners can perform now, exactly as their service shard would after TCP
  // delivered bytes or exposed new send credit.
  for (std::size_t turn = 0U; turn < 128U; ++turn) {
    const auto client_moved = transfer(*client, *server);
    const auto server_moved = transfer(*server, *client);
    if (!client_moved && !server_moved)
      break;
  }
  auto first_request = server->take_message();
  auto second_request = server->take_message();
  if (!first_request || !second_request || !first_request->complete ||
      !second_request->complete || !first_request->request ||
      first_request->body != std::vector<std::uint8_t>(first_body.begin(),
                                                       first_body.end()) ||
      second_request->body != std::vector<std::uint8_t>(second_body.begin(),
                                                        second_body.end()))
    throw std::runtime_error("HTTP/2 server did not reconstruct requests");
  const auto *path = find_header(*first_request, ":path");
  if (!path || path->value != "/dns-query")
    throw std::runtime_error("HTTP/2 HPACK field reconstruction failed");

  const std::array<HeaderField, 2U> response_headers{
      HeaderField{":status", "200"},
      HeaderField{"content-type", "application/dns-message"}};
  const std::array<std::uint8_t, 4U> first_response{0x12U, 0x34U, 0x81U,
                                                   0x80U};
  const std::array<std::uint8_t, 4U> second_response{0xabU, 0xcdU, 0x81U,
                                                    0x80U};
  if (server->submit_response(first_request->stream_id, response_headers,
                              first_response) != SubmitResult::applied ||
      server->submit_response(second_request->stream_id, response_headers,
                              second_response) != SubmitResult::applied)
    throw std::runtime_error("HTTP/2 response submission failed");
  for (std::size_t turn = 0U; turn < 128U; ++turn) {
    const auto server_moved = transfer(*server, *client);
    const auto client_moved = transfer(*client, *server);
    if (!server_moved && !client_moved)
      break;
  }
  auto response_one = client->take_message();
  auto response_two = client->take_message();
  if (!response_one || !response_two || !response_one->complete ||
      !response_two->complete || response_one->request ||
      response_one->body !=
          std::vector<std::uint8_t>(first_response.begin(),
                                    first_response.end()) ||
      response_two->body !=
          std::vector<std::uint8_t>(second_response.begin(),
                                    second_response.end()))
    throw std::runtime_error("HTTP/2 client did not reconstruct responses");

  // Resource limits are supplied by the platform profile and reject the
  // operation before any partial stream state appears on the wire.
  std::vector<std::uint8_t> oversized(
      configuration.max_message_body_octets + 1U, 0U);
  if (client->submit_request(request_headers, oversized).result !=
          SubmitResult::invalid_message ||
      client->state() != State::open)
    throw std::runtime_error("HTTP/2 body resource policy was not atomic");
}
