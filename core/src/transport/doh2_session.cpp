// RFC 8484 mapping of one DNS exchange to one HTTP/2 stream. TLS negotiates
// the mandatory h2 identifier through ALPN before HTTP/2 bytes are released.
// Source: ietf.doh.rfc8484
// Source: ietf.http2.rfc9113

#include "router/doh2_session.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <memory>
#include <string_view>
#include <utility>

namespace router::doh2 {
namespace {

constexpr std::string_view h2_identifier{"h2"};

const http2::HeaderField *find_header(const http2::Message &message,
                                      std::string_view name) noexcept {
  const auto found = std::find_if(
      message.headers.begin(), message.headers.end(),
      [&](const auto &field) { return field.name == name; });
  return found == message.headers.end() ? nullptr : &*found;
}

std::optional<std::uint16_t> parse_status(const http2::Message &message) {
  const auto *status = find_header(message, ":status");
  if (!status || status->value.size() != 3U)
    return std::nullopt;
  std::uint16_t result{};
  const auto parsed = std::from_chars(status->value.data(),
                                      status->value.data() + 3U, result);
  return parsed.ec == std::errc{} && parsed.ptr == status->value.data() + 3U
             ? std::optional<std::uint16_t>{result}
             : std::nullopt;
}

std::uint32_t parse_age(const http2::Message &message) noexcept {
  const auto *age = find_header(message, "age");
  if (!age)
    return 0U;
  std::uint32_t result{};
  const auto parsed = std::from_chars(
      age->value.data(), age->value.data() + age->value.size(), result);
  return parsed.ec == std::errc{} &&
                 parsed.ptr == age->value.data() + age->value.size()
             ? result
             : 0U;
}

} // namespace

struct Session::Impl {
  tls::Engine tls_engine;
  http2::Session http2_session;
  Configuration configuration;
  std::vector<std::uint8_t> inbound_plaintext;
  std::vector<std::uint8_t> outbound_plaintext;
  std::size_t inbound_offset{};
  std::size_t inbound_octets{};
  std::size_t outbound_offset{};
  std::size_t outbound_octets{};
  Failure failure{Failure::none};

  Impl(tls::Engine tls_value, http2::Session http2_value,
       Configuration value)
      : tls_engine(std::move(tls_value)),
        http2_session(std::move(http2_value)),
        configuration(std::move(value)),
        inbound_plaintext(configuration.plaintext_staging_octets),
        outbound_plaintext(configuration.plaintext_staging_octets) {}

  void fail(Failure reason) noexcept {
    if (failure == Failure::none)
      failure = reason;
  }
};

Session::Session(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Session::Session(Session &&) noexcept = default;
Session &Session::operator=(Session &&) noexcept = default;
Session::~Session() = default;

std::optional<Session>
Session::create(tls::Engine tls_engine, http2::Session http2_session,
                Configuration configuration) noexcept {
  if (configuration.authority.empty() || configuration.path.empty() ||
      configuration.path.front() != '/' ||
      configuration.path.find('?') != std::string::npos ||
      configuration.plaintext_staging_octets <
          http2::minimum_serialized_frame_octets ||
      tls_engine.state() == tls::State::failed ||
      http2_session.state() == http2::State::failed)
    return std::nullopt;
  try {
    return Session{std::make_unique<Impl>(
        std::move(tls_engine), std::move(http2_session),
        std::move(configuration))};
  } catch (...) {
    return std::nullopt;
  }
}

http2::SubmitOutcome
Session::submit_query(Method method,
                      std::span<const std::uint8_t> dns_message) noexcept {
  if (!implementation_ || implementation_->http2_session.role() !=
                              http2::Role::client ||
      !doh::valid_dns_message(dns_message))
    return {.result = http2::SubmitResult::invalid_message, .stream_id = -1};
  try {
    std::vector<http2::HeaderField> headers{
        {":method", method == Method::get ? "GET" : "POST"},
        {":scheme", "https"},
        {":authority", implementation_->configuration.authority},
        {":path", implementation_->configuration.path},
        {"accept", std::string{doh::dns_media_type}}};
    if (method == Method::get) {
      const auto encoded = doh::encode_query_parameter(dns_message);
      if (!encoded)
        return {.result = http2::SubmitResult::resource_exhausted,
                .stream_id = -1};
      headers[3U].value.append("?dns=");
      headers[3U].value.append(*encoded);
      return implementation_->http2_session.submit_request(headers, {});
    }
    headers.push_back({"content-type", std::string{doh::dns_media_type}});
    headers.push_back({"content-length", std::to_string(dns_message.size())});
    return implementation_->http2_session.submit_request(headers, dns_message);
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return {.result = http2::SubmitResult::resource_exhausted,
            .stream_id = -1};
  }
}

http2::SubmitResult
Session::submit_response(std::int32_t stream_id,
                         std::span<const std::uint8_t> dns_message,
                         std::uint32_t freshness_seconds) noexcept {
  if (!implementation_ || !doh::valid_dns_message(dns_message))
    return http2::SubmitResult::invalid_message;
  try {
    const std::array<http2::HeaderField, 4U> headers{
        http2::HeaderField{":status", "200"},
        http2::HeaderField{"content-type", std::string{doh::dns_media_type}},
        http2::HeaderField{"content-length",
                           std::to_string(dns_message.size())},
        http2::HeaderField{"cache-control",
                           "max-age=" + std::to_string(freshness_seconds)}};
    return implementation_->http2_session.submit_response(
        stream_id, headers, dns_message);
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return http2::SubmitResult::resource_exhausted;
  }
}

http2::SubmitResult Session::submit_error(std::int32_t stream_id,
                                          std::uint16_t status) noexcept {
  if (!implementation_ || status < 400U || status > 599U)
    return http2::SubmitResult::invalid_message;
  try {
    const std::array<http2::HeaderField, 2U> headers{
        http2::HeaderField{":status", std::to_string(status)},
        http2::HeaderField{"content-length", "0"}};
    return implementation_->http2_session.submit_response(stream_id, headers,
                                                           {});
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return http2::SubmitResult::resource_exhausted;
  }
}

State Session::progress() noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return State::failed;
  const auto tls_state = implementation_->tls_engine.progress();
  if (tls_state == tls::State::failed) {
    implementation_->fail(Failure::tls_failure);
    return State::failed;
  }
  if (tls_state != tls::State::established)
    return tls_state == tls::State::closed ? State::closed
                                          : State::handshaking;
  if (implementation_->tls_engine.negotiated_alpn() != h2_identifier) {
    implementation_->fail(Failure::alpn_mismatch);
    return State::failed;
  }

  // A retained suffix is retried before reading more TLS plaintext. This is
  // the byte-stream backpressure contract and prevents frame loss if nghttp2
  // ever pauses processing after consuming only a prefix.
  if (implementation_->inbound_offset < implementation_->inbound_octets) {
    const auto consumed = implementation_->http2_session.ingest_bytes(
        std::span<const std::uint8_t>{implementation_->inbound_plaintext}
            .subspan(implementation_->inbound_offset,
                     implementation_->inbound_octets -
                         implementation_->inbound_offset));
    implementation_->inbound_offset += consumed;
    if (implementation_->http2_session.state() == http2::State::failed) {
      implementation_->fail(Failure::http2_failure);
      return State::failed;
    }
  }
  if (implementation_->inbound_offset == implementation_->inbound_octets) {
    implementation_->inbound_offset = 0U;
    implementation_->inbound_octets =
        implementation_->tls_engine.read_plaintext(
            implementation_->inbound_plaintext);
    if (implementation_->inbound_octets != 0U) {
      const auto consumed = implementation_->http2_session.ingest_bytes(
          std::span<const std::uint8_t>{implementation_->inbound_plaintext}
              .first(implementation_->inbound_octets));
      implementation_->inbound_offset = consumed;
    }
  }

  if (implementation_->outbound_offset ==
      implementation_->outbound_octets) {
    implementation_->outbound_offset = 0U;
    implementation_->outbound_octets =
        implementation_->http2_session.take_bytes(
            implementation_->outbound_plaintext);
  }
  if (implementation_->outbound_offset < implementation_->outbound_octets) {
    implementation_->outbound_offset +=
        implementation_->tls_engine.write_plaintext(
            std::span<const std::uint8_t>{implementation_->outbound_plaintext}
                .subspan(implementation_->outbound_offset,
                         implementation_->outbound_octets -
                             implementation_->outbound_offset));
  }
  if (implementation_->http2_session.state() == http2::State::failed) {
    implementation_->fail(Failure::http2_failure);
    return State::failed;
  }
  return implementation_->http2_session.state() == http2::State::draining
             ? State::draining
             : State::established;
}

std::size_t
Session::ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept {
  return implementation_ && implementation_->failure == Failure::none
             ? implementation_->tls_engine.ingest_ciphertext(bytes)
             : 0U;
}

std::size_t
Session::take_ciphertext(std::span<std::uint8_t> output) noexcept {
  return implementation_ && implementation_->failure == Failure::none
             ? implementation_->tls_engine.take_ciphertext(output)
             : 0U;
}

std::size_t Session::pending_ciphertext() const noexcept {
  return implementation_ ? implementation_->tls_engine.pending_ciphertext()
                         : 0U;
}

std::optional<Request> Session::take_request() noexcept {
  if (!implementation_ || implementation_->http2_session.role() !=
                              http2::Role::server)
    return std::nullopt;
  auto message = implementation_->http2_session.take_message();
  if (!message)
    return std::nullopt;
  Request result{.stream_id = message->stream_id,
                 .status = RequestStatus::malformed_http,
                 .method = Method::post,
                 .dns_message = {}};
  if (!message->complete) {
    result.status = RequestStatus::stream_error;
    return result;
  }
  const auto *method = find_header(*message, ":method");
  const auto *scheme = find_header(*message, ":scheme");
  const auto *authority = find_header(*message, ":authority");
  const auto *path = find_header(*message, ":path");
  if (!method || !scheme || !authority || !path)
    return result;
  if (scheme->value != "https" ||
      authority->value != implementation_->configuration.authority) {
    result.status = RequestStatus::wrong_endpoint;
    return result;
  }
  if (method->value == "POST") {
    result.method = Method::post;
    const auto *content_type = find_header(*message, "content-type");
    if (!content_type || content_type->value != doh::dns_media_type) {
      result.status = RequestStatus::unsupported_media_type;
      return result;
    }
    if (path->value != implementation_->configuration.path) {
      result.status = RequestStatus::wrong_endpoint;
      return result;
    }
    result.dns_message = std::move(message->body);
  } else if (method->value == "GET") {
    result.method = Method::get;
    const auto prefix = implementation_->configuration.path + "?dns=";
    if (!path->value.starts_with(prefix)) {
      result.status = RequestStatus::wrong_endpoint;
      return result;
    }
    const auto decoded = doh::decode_query_parameter(
        std::string_view{path->value}.substr(prefix.size()));
    if (!decoded) {
      result.status = RequestStatus::malformed_dns_message;
      return result;
    }
    result.dns_message = std::move(*decoded);
  } else {
    return result;
  }
  result.status = doh::valid_dns_message(result.dns_message)
                      ? RequestStatus::valid
                      : RequestStatus::malformed_dns_message;
  return result;
}

std::optional<Response> Session::take_response() noexcept {
  if (!implementation_ || implementation_->http2_session.role() !=
                              http2::Role::client)
    return std::nullopt;
  auto message = implementation_->http2_session.take_message();
  if (!message)
    return std::nullopt;
  const auto status = parse_status(*message);
  Response result{.stream_id = message->stream_id,
                  .complete = message->complete,
                  .http_status = status.value_or(0U),
                  .age_seconds = parse_age(*message),
                  .dns_message = {}};
  if (!message->complete || !status || *status < 200U || *status >= 300U)
    return result;
  const auto *content_type = find_header(*message, "content-type");
  if (!content_type || content_type->value != doh::dns_media_type ||
      !doh::valid_dns_message(message->body)) {
    result.complete = false;
    return result;
  }
  result.dns_message = std::move(message->body);
  return result;
}

http2::Role Session::role() const noexcept {
  return implementation_ ? implementation_->http2_session.role()
                         : http2::Role::client;
}

State Session::state() const noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return State::failed;
  if (implementation_->tls_engine.state() == tls::State::handshaking)
    return State::handshaking;
  if (implementation_->tls_engine.state() == tls::State::closed)
    return State::closed;
  if (implementation_->http2_session.state() == http2::State::draining)
    return State::draining;
  return State::established;
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::resource_exhausted;
}

} // namespace router::doh2
