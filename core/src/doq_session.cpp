// RFC 9250 stream mapping over the socket-free QUIC owner. Each query uses a
// new client-initiated bidirectional stream, message IDs are zero, framing is
// identical to one DNS-over-TCP transaction, and both directions end in FIN.
// Source: ietf.doq.rfc9250

#include "router/doq_session.hpp"

#include "router/dns_packet.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <map>
#include <set>

namespace router::doq {
namespace {

constexpr std::size_t length_octets = 2U;

[[nodiscard]] bool valid_dns_message(
    std::span<const std::uint8_t> message, bool expect_response) noexcept {
  if (message.size() < packet::dns::header_octets ||
      message.size() > packet::dns::maximum_message_octets ||
      message[0U] != 0U || message[1U] != 0U)
    return false;
  const bool response = (message[2U] & 0x80U) != 0U;
  return response == expect_response;
}

[[nodiscard]] std::vector<std::uint8_t>
frame(std::span<const std::uint8_t> message) {
  std::vector<std::uint8_t> result(message.size() + length_octets);
  result[0U] = static_cast<std::uint8_t>(message.size() >> 8U);
  result[1U] = static_cast<std::uint8_t>(message.size());
  std::copy(message.begin(), message.end(), result.begin() + length_octets);
  return result;
}

State public_state(quic::State value) noexcept {
  switch (value) {
  case quic::State::handshaking:
    return State::handshaking;
  case quic::State::established:
    return State::established;
  case quic::State::closing:
  case quic::State::draining:
    return State::closing;
  case quic::State::closed:
    return State::closed;
  case quic::State::failed:
    return State::failed;
  }
  return State::failed;
}

} // namespace

struct Session::Impl {
  struct IncompleteStream {
    std::vector<std::uint8_t> wire;
    bool fin{};
  };

  quic::Connection connection;
  Configuration configuration;
  std::map<std::int64_t, IncompleteStream> incomplete;
  std::set<std::int64_t> outstanding_queries;
  std::set<std::int64_t> answered_queries;
  std::deque<Transaction> completed;
  Failure failure{Failure::none};

  Impl(quic::Connection value, Configuration limits)
      : connection(std::move(value)), configuration(limits) {}

  void fail(Failure reason) noexcept {
    if (failure == Failure::none)
      failure = reason;
    // Malformed DoQ is a connection-level error. Staging an application close
    // ensures the peer observes a real CONNECTION_CLOSE with code 0x2.
    static_cast<void>(connection.close_application(protocol_error));
  }

  bool finish_stream(std::int64_t stream_id,
                     IncompleteStream &stream) noexcept {
    if (!stream.fin || stream.wire.size() < length_octets)
      return false;
    const auto message_octets =
        (static_cast<std::size_t>(stream.wire[0U]) << 8U) |
        stream.wire[1U];
    if (message_octets < packet::dns::header_octets ||
        stream.wire.size() != message_octets + length_octets) {
      fail(Failure::malformed_dns_message);
      return false;
    }
    const auto message = std::span<const std::uint8_t>{stream.wire}.subspan(
        length_octets, message_octets);
    const bool expect_response = configuration.role == Role::client;
    if ((stream_id & 0x3) != 0 ||
        !valid_dns_message(message, expect_response) ||
        (expect_response && !outstanding_queries.contains(stream_id)) ||
        (!expect_response && answered_queries.contains(stream_id))) {
      fail(Failure::unexpected_stream);
      return false;
    }
    if (completed.size() >= configuration.max_completed_transactions)
      return false;
    try {
      completed.push_back(Transaction{
          .stream_id = stream_id,
          .dns_message = {message.begin(), message.end()}});
      if (expect_response)
        outstanding_queries.erase(stream_id);
      return true;
    } catch (...) {
      fail(Failure::resource_exhausted);
      return false;
    }
  }
};

Session::Session(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Session::Session(Session &&) noexcept = default;
Session &Session::operator=(Session &&) noexcept = default;
Session::~Session() = default;

std::optional<Session>
Session::create(quic::Connection connection,
                const Configuration &configuration) noexcept {
  const auto path = connection.current_path();
  if (configuration.max_completed_transactions == 0U ||
      configuration.max_incomplete_streams == 0U ||
      path.remote.port == packet::dns::server_port ||
      path.local.port == packet::dns::server_port ||
      connection.state() == quic::State::failed)
    return std::nullopt;
  try {
    return Session{
        std::make_unique<Impl>(std::move(connection), configuration)};
  } catch (...) {
    return std::nullopt;
  }
}

SubmitResult Session::submit_query(
    std::span<const std::uint8_t> dns_message,
    std::int64_t &stream_id) noexcept {
  if (!implementation_ || implementation_->configuration.role != Role::client)
    return SubmitResult::wrong_role;
  if (state() != State::established)
    return SubmitResult::not_established;
  if (!valid_dns_message(dns_message, false))
    return SubmitResult::invalid_message;
  const auto stream = implementation_->connection.open_bidirectional_stream();
  if (!stream)
    return SubmitResult::stream_limit;
  try {
    auto wire = frame(dns_message);
    if (implementation_->connection.send_stream(*stream, wire, true) !=
        quic::Failure::none)
      return SubmitResult::resource_exhausted;
    implementation_->outstanding_queries.insert(*stream);
    stream_id = *stream;
    return SubmitResult::applied;
  } catch (...) {
    static_cast<void>(implementation_->connection.reset_stream(
        *stream, excessive_load));
    return SubmitResult::resource_exhausted;
  }
}

SubmitResult Session::submit_response(
    std::int64_t stream_id,
    std::span<const std::uint8_t> dns_message) noexcept {
  if (!implementation_ || implementation_->configuration.role != Role::server)
    return SubmitResult::wrong_role;
  if (state() != State::established)
    return SubmitResult::not_established;
  if (!valid_dns_message(dns_message, true))
    return SubmitResult::invalid_message;
  if (implementation_->answered_queries.contains(stream_id))
    return SubmitResult::duplicate_response;
  try {
    auto wire = frame(dns_message);
    if (implementation_->connection.send_stream(stream_id, wire, true) !=
        quic::Failure::none)
      return SubmitResult::resource_exhausted;
    implementation_->answered_queries.insert(stream_id);
    return SubmitResult::applied;
  } catch (...) {
    static_cast<void>(implementation_->connection.reset_stream(
        stream_id, internal_error));
    return SubmitResult::resource_exhausted;
  }
}

SubmitResult Session::cancel(std::int64_t stream_id) noexcept {
  if (!implementation_ || implementation_->configuration.role != Role::client)
    return SubmitResult::wrong_role;
  if (!implementation_->outstanding_queries.contains(stream_id))
    return SubmitResult::invalid_message;
  if (implementation_->connection.stop_sending(stream_id,
                                                request_cancelled) !=
      quic::Failure::none)
    return SubmitResult::resource_exhausted;
  implementation_->outstanding_queries.erase(stream_id);
  return SubmitResult::applied;
}

State Session::progress() noexcept {
  if (!implementation_)
    return State::failed;
  if (implementation_->failure != Failure::none)
    return State::failed;
  const auto transport_state = implementation_->connection.state();
  if (transport_state == quic::State::failed) {
    implementation_->fail(Failure::quic_failure);
    return State::failed;
  }
  if (transport_state != quic::State::established)
    return public_state(transport_state);
  if (implementation_->connection.negotiated_alpn() != "doq") {
    implementation_->fail(Failure::alpn_mismatch);
    return State::failed;
  }
  auto chunk = implementation_->connection.take_received_stream();
  if (!chunk)
    return State::established;
  auto iterator = implementation_->incomplete.find(chunk->stream_id);
  if (iterator == implementation_->incomplete.end()) {
    if (implementation_->incomplete.size() >=
        implementation_->configuration.max_incomplete_streams) {
      implementation_->fail(Failure::resource_exhausted);
      return State::failed;
    }
    iterator = implementation_->incomplete.try_emplace(chunk->stream_id).first;
  }
  auto &stream = iterator->second;
  if (stream.fin || chunk->offset != stream.wire.size() ||
      chunk->bytes.size() > packet::dns::maximum_message_octets +
                                  length_octets - stream.wire.size()) {
    implementation_->fail(Failure::malformed_dns_message);
    return State::failed;
  }
  try {
    stream.wire.insert(stream.wire.end(), chunk->bytes.begin(),
                       chunk->bytes.end());
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return State::failed;
  }
  if (implementation_->connection.consume_received_stream(
          chunk->stream_id, chunk->bytes.size()) != quic::Failure::none) {
    implementation_->fail(Failure::quic_failure);
    return State::failed;
  }
  stream.fin = chunk->fin;
  if (stream.fin && implementation_->finish_stream(chunk->stream_id, stream))
    implementation_->incomplete.erase(iterator);
  return implementation_->failure == Failure::none ? State::established
                                                    : State::failed;
}

std::optional<Transaction> Session::take_transaction() noexcept {
  if (!implementation_ || implementation_->completed.empty())
    return std::nullopt;
  auto result = std::move(implementation_->completed.front());
  implementation_->completed.pop_front();
  return result;
}

quic::Failure Session::ingest_datagram(
    const quic::Path &path, std::span<const std::uint8_t> datagram,
    quic::RuntimeClock::time_point received_at) noexcept {
  return implementation_
             ? implementation_->connection.ingest_datagram(path, datagram,
                                                            received_at)
             : quic::Failure::invalid_configuration;
}

std::size_t Session::take_datagram(std::span<std::uint8_t> output,
                                   quic::Path &path,
                                   quic::RuntimeClock::time_point now) noexcept {
  return implementation_
             ? implementation_->connection.take_datagram(output, path, now)
             : 0U;
}

std::optional<quic::RuntimeClock::time_point>
Session::next_expiry() const noexcept {
  return implementation_ ? implementation_->connection.next_expiry()
                         : std::nullopt;
}

quic::Failure
Session::handle_expiry(quic::RuntimeClock::time_point now) noexcept {
  return implementation_ ? implementation_->connection.handle_expiry(now)
                         : quic::Failure::invalid_configuration;
}

State Session::state() const noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return State::failed;
  return public_state(implementation_->connection.state());
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::resource_exhausted;
}

const quic::Connection &Session::transport() const noexcept {
  return implementation_->connection;
}

} // namespace router::doq
