// RFC 8484 mapping of one DNS exchange to one HTTP/3 request stream. HTTP/3
// version independence comes from RFC 8484's normal HTTP semantics; QUIC and
// QPACK framing remain entirely inside the HTTP/3 owner.
// Source: ietf.doh.rfc8484
// Source: ietf.http3.rfc9114

#include "router/doh3_session.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <memory>
#include <string_view>
#include <utility>

namespace router::doh3 {
namespace {

const http3::HeaderField *find_header(const http3::Message &message,
                                      std::string_view name) noexcept {
  const auto found = std::find_if(
      message.headers.begin(), message.headers.end(),
      [&](const auto &field) { return field.name == name; });
  return found == message.headers.end() ? nullptr : &*found;
}

std::optional<std::uint16_t>
parse_status(const http3::Message &message) noexcept {
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

std::uint32_t parse_age(const http3::Message &message) noexcept {
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
  http3::Session http_session;
  Configuration configuration;
  Failure failure{Failure::none};

  Impl(http3::Session session, Configuration value)
      : http_session(std::move(session)), configuration(std::move(value)) {}

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
Session::create(http3::Session http_session,
                Configuration configuration) noexcept {
  if (configuration.authority.empty() || configuration.path.empty() ||
      configuration.path.front() != '/' ||
      configuration.path.find('?') != std::string::npos ||
      http_session.state() != http3::State::established)
    return std::nullopt;
  try {
    return Session{std::make_unique<Impl>(std::move(http_session),
                                          std::move(configuration))};
  } catch (...) {
    return std::nullopt;
  }
}

SubmitOutcome
Session::submit_query(Method method,
                      std::span<const std::uint8_t> dns_message) noexcept {
  if (!implementation_ || implementation_->http_session.role() !=
                              http3::Role::client ||
      !doh::valid_dns_message(dns_message))
    return {};
  try {
    std::vector<http3::HeaderField> headers{
        {":method", method == Method::get ? "GET" : "POST"},
        {":scheme", "https"},
        {":authority", implementation_->configuration.authority},
        {":path", implementation_->configuration.path},
        {"accept", std::string{doh::dns_media_type}}};
    std::span<const std::uint8_t> body{};
    if (method == Method::get) {
      const auto encoded = doh::encode_query_parameter(dns_message);
      if (!encoded) {
        implementation_->fail(Failure::resource_exhausted);
        return {.result = http3::SubmitResult::resource_exhausted,
                .stream_id = -1};
      }
      headers[3U].value.append("?dns=");
      headers[3U].value.append(*encoded);
    } else {
      headers.push_back({"content-type", std::string{doh::dns_media_type}});
      headers.push_back({"content-length", std::to_string(dns_message.size())});
      body = dns_message;
    }
    std::int64_t stream_id{-1};
    const auto result =
        implementation_->http_session.submit_request(headers, body, stream_id);
    return {.result = result, .stream_id = stream_id};
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return {.result = http3::SubmitResult::resource_exhausted,
            .stream_id = -1};
  }
}

http3::SubmitResult
Session::submit_response(std::int64_t stream_id,
                         std::span<const std::uint8_t> dns_message,
                         std::uint32_t freshness_seconds) noexcept {
  if (!implementation_ || implementation_->http_session.role() !=
                              http3::Role::server ||
      !doh::valid_dns_message(dns_message))
    return http3::SubmitResult::invalid_message;
  try {
    const std::array<http3::HeaderField, 4U> headers{
        http3::HeaderField{":status", "200"},
        http3::HeaderField{"content-type", std::string{doh::dns_media_type}},
        http3::HeaderField{"content-length",
                           std::to_string(dns_message.size())},
        http3::HeaderField{"cache-control",
                           "max-age=" + std::to_string(freshness_seconds)}};
    return implementation_->http_session.submit_response(stream_id, headers,
                                                           dns_message);
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return http3::SubmitResult::resource_exhausted;
  }
}

http3::SubmitResult Session::submit_error(std::int64_t stream_id,
                                          std::uint16_t status) noexcept {
  if (!implementation_ || implementation_->http_session.role() !=
                              http3::Role::server ||
      status < 400U || status > 599U)
    return http3::SubmitResult::invalid_message;
  try {
    const std::array<http3::HeaderField, 2U> headers{
        http3::HeaderField{":status", std::to_string(status)},
        http3::HeaderField{"content-length", "0"}};
    return implementation_->http_session.submit_response(stream_id, headers,
                                                           {});
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return http3::SubmitResult::resource_exhausted;
  }
}

http3::State Session::progress(quic::RuntimeClock::time_point now) noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return http3::State::failed;
  const auto result = implementation_->http_session.progress(now);
  if (result == http3::State::failed)
    implementation_->fail(Failure::http3_failure);
  return result;
}

std::optional<Request> Session::take_request() noexcept {
  if (!implementation_ || implementation_->http_session.role() !=
                              http3::Role::server)
    return std::nullopt;
  auto message = implementation_->http_session.take_message();
  if (!message)
    return std::nullopt;
  Request result{.stream_id = message->stream_id,
                 .status = RequestStatus::malformed_http,
                 .method = Method::post,
                 .dns_message = {}};
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
  if (!implementation_ || implementation_->http_session.role() !=
                              http3::Role::client)
    return std::nullopt;
  auto message = implementation_->http_session.take_message();
  if (!message)
    return std::nullopt;
  const auto status = parse_status(*message);
  Response result{.stream_id = message->stream_id,
                  .http_status = status.value_or(0U),
                  .age_seconds = parse_age(*message),
                  .dns_message = {}};
  if (!status || *status < 200U || *status >= 300U)
    return result;
  const auto *content_type = find_header(*message, "content-type");
  if (content_type && content_type->value == doh::dns_media_type &&
      doh::valid_dns_message(message->body))
    result.dns_message = std::move(message->body);
  return result;
}

quic::Failure Session::ingest_datagram(
    const quic::Path &path, std::span<const std::uint8_t> datagram,
    quic::RuntimeClock::time_point received_at) noexcept {
  return implementation_ ? implementation_->http_session.ingest_datagram(
                               path, datagram, received_at)
                         : quic::Failure::invalid_configuration;
}

std::size_t Session::take_datagram(std::span<std::uint8_t> output,
                                   quic::Path &path,
                                   quic::RuntimeClock::time_point now) noexcept {
  return implementation_ ? implementation_->http_session.take_datagram(
                               output, path, now)
                         : 0U;
}

std::optional<quic::RuntimeClock::time_point>
Session::next_expiry() const noexcept {
  return implementation_ ? implementation_->http_session.next_expiry()
                         : std::nullopt;
}

quic::Failure
Session::handle_expiry(quic::RuntimeClock::time_point now) noexcept {
  return implementation_ ? implementation_->http_session.handle_expiry(now)
                         : quic::Failure::invalid_configuration;
}

http3::Role Session::role() const noexcept {
  return implementation_ ? implementation_->http_session.role()
                         : http3::Role::client;
}

http3::State Session::state() const noexcept {
  return implementation_ ? implementation_->http_session.state()
                         : http3::State::failed;
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::invalid_configuration;
}

} // namespace router::doh3
