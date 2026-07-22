// RFC 7858 framing over the socket-free TLS 1.3 engine. The two-octet DNS
// length prefix exists inside TLS plaintext. TCP sees only TLSCiphertext.
// Source: ietf.dot.rfc7858
// Source: ietf.dot.authentication.rfc8310

#include "router/dot_session.hpp"

#include "router/dns_packet.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace router::dot {
namespace {

constexpr std::size_t length_prefix_octets = 2U;
constexpr std::size_t wire_length_maximum =
    std::numeric_limits<std::uint16_t>::max();

bool valid_configuration(const Configuration &configuration) noexcept {
  return configuration.max_dns_message_octets >= packet::dns::header_octets &&
         configuration.max_dns_message_octets <= wire_length_maximum &&
         configuration.max_queued_outgoing_messages != 0U &&
         configuration.max_queued_incoming_messages != 0U;
}

State public_state(tls::State state) noexcept {
  switch (state) {
  case tls::State::handshaking:
    return State::handshaking;
  case tls::State::established:
    return State::established;
  case tls::State::closing:
    return State::closing;
  case tls::State::closed:
    return State::closed;
  case tls::State::failed:
    return State::failed;
  }
  return State::failed;
}

} // namespace

struct Session::Impl {
  tls::Engine engine;
  Configuration configuration;
  std::deque<std::vector<std::uint8_t>> outgoing;
  std::deque<std::vector<std::uint8_t>> incoming;
  std::vector<std::uint8_t> receive_stream;
  std::size_t receive_octets{};
  std::size_t outgoing_offset{};
  Failure failure{Failure::none};

  explicit Impl(tls::Engine value, Configuration limits)
      : engine(std::move(value)), configuration(limits),
        receive_stream(limits.max_dns_message_octets + length_prefix_octets) {}

  void fail(Failure reason) noexcept {
    // Preserve the first boundary failure. A later TLS alert is a consequence
    // of rejecting malformed application plaintext, not a more useful cause.
    if (failure == Failure::none)
      failure = reason;
  }

  bool receive_one_message() noexcept {
    if (receive_octets < length_prefix_octets)
      return false;
    const auto message_octets = static_cast<std::size_t>(
        (static_cast<std::uint16_t>(receive_stream[0U]) << 8U) |
        receive_stream[1U]);
    if (message_octets < packet::dns::header_octets ||
        message_octets > configuration.max_dns_message_octets) {
      fail(Failure::malformed_dns_message);
      return false;
    }
    const auto framed_octets = message_octets + length_prefix_octets;
    if (receive_octets < framed_octets)
      return false;
    if (incoming.size() >= configuration.max_queued_incoming_messages) {
      // Backpressure is applied before consuming the complete plaintext frame.
      // Retaining it in receive_stream lets the service resume losslessly once
      // the application drains one response or query.
      return false;
    }
    try {
      incoming.emplace_back(receive_stream.begin() + length_prefix_octets,
                            receive_stream.begin() +
                                static_cast<std::ptrdiff_t>(framed_octets));
    } catch (...) {
      fail(Failure::resource_exhausted);
      return false;
    }
    const auto remaining = receive_octets - framed_octets;
    std::move(receive_stream.begin() +
                  static_cast<std::ptrdiff_t>(framed_octets),
              receive_stream.begin() +
                  static_cast<std::ptrdiff_t>(receive_octets),
              receive_stream.begin());
    receive_octets = remaining;
    return true;
  }
};

Session::Session(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Session::Session(Session &&) noexcept = default;
Session &Session::operator=(Session &&) noexcept = default;
Session::~Session() = default;

std::optional<Session>
Session::create(tls::Engine engine,
                const Configuration &configuration) noexcept {
  if (!valid_configuration(configuration) ||
      engine.state() == tls::State::failed ||
      engine.state() == tls::State::closed)
    return std::nullopt;
  try {
    return Session{
        std::make_unique<Impl>(std::move(engine), configuration)};
  } catch (...) {
    return std::nullopt;
  }
}

QueueResult
Session::queue_message(std::span<const std::uint8_t> message) noexcept {
  if (!implementation_ || implementation_->failure != Failure::none ||
      implementation_->engine.state() == tls::State::closed ||
      implementation_->engine.state() == tls::State::failed)
    return QueueResult::session_closed;
  if (message.size() < packet::dns::header_octets ||
      message.size() > implementation_->configuration.max_dns_message_octets)
    return QueueResult::invalid_message;
  if (implementation_->outgoing.size() >=
      implementation_->configuration.max_queued_outgoing_messages)
    return QueueResult::queue_full;
  try {
    std::vector<std::uint8_t> framed(message.size() + length_prefix_octets);
    framed[0U] = static_cast<std::uint8_t>(message.size() >> 8U);
    framed[1U] = static_cast<std::uint8_t>(message.size());
    std::copy(message.begin(), message.end(),
              framed.begin() + length_prefix_octets);
    implementation_->outgoing.push_back(std::move(framed));
    return QueueResult::queued;
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return QueueResult::queue_full;
  }
}

State Session::progress() noexcept {
  if (!implementation_)
    return State::failed;
  if (implementation_->failure != Failure::none)
    return State::failed;
  const auto tls_state = implementation_->engine.progress();
  if (tls_state == tls::State::failed) {
    implementation_->fail(Failure::tls_failure);
    return State::failed;
  }
  if (tls_state != tls::State::established)
    return public_state(tls_state);

  // One write per call gives the service shard a deterministic work budget.
  // A short TLS write retains the suffix and never duplicates its DNS prefix.
  if (!implementation_->outgoing.empty()) {
    auto &message = implementation_->outgoing.front();
    const auto written = implementation_->engine.write_plaintext(
        std::span<const std::uint8_t>{message}.subspan(
            implementation_->outgoing_offset));
    implementation_->outgoing_offset += written;
    if (implementation_->outgoing_offset == message.size()) {
      implementation_->outgoing.pop_front();
      implementation_->outgoing_offset = 0U;
    }
  }

  // Decode at most one already-buffered message and perform at most one TLS
  // read. Repeated service turns drain pipelined messages without allowing one
  // busy encrypted connection to monopolize its shard.
  if (implementation_->receive_one_message())
    return State::established;
  if (implementation_->failure != Failure::none ||
      implementation_->incoming.size() >=
          implementation_->configuration.max_queued_incoming_messages)
    return implementation_->failure == Failure::none ? State::established
                                                      : State::failed;
  if (implementation_->receive_octets <
      implementation_->receive_stream.size()) {
    implementation_->receive_octets += implementation_->engine.read_plaintext(
        std::span<std::uint8_t>{implementation_->receive_stream}.subspan(
            implementation_->receive_octets));
    static_cast<void>(implementation_->receive_one_message());
  }
  return implementation_->failure == Failure::none ? State::established
                                                    : State::failed;
}

std::size_t
Session::ingest_ciphertext(std::span<const std::uint8_t> bytes) noexcept {
  return implementation_ && implementation_->failure == Failure::none
             ? implementation_->engine.ingest_ciphertext(bytes)
             : 0U;
}

std::size_t
Session::take_ciphertext(std::span<std::uint8_t> output) noexcept {
  return implementation_ && implementation_->failure == Failure::none
             ? implementation_->engine.take_ciphertext(output)
             : 0U;
}

std::size_t Session::pending_ciphertext() const noexcept {
  return implementation_ ? implementation_->engine.pending_ciphertext() : 0U;
}

std::optional<std::vector<std::uint8_t>> Session::take_message() noexcept {
  if (!implementation_ || implementation_->incoming.empty())
    return std::nullopt;
  auto message = std::move(implementation_->incoming.front());
  implementation_->incoming.pop_front();
  return message;
}

std::size_t Session::queued_outgoing_messages() const noexcept {
  return implementation_ ? implementation_->outgoing.size() : 0U;
}

std::size_t Session::queued_incoming_messages() const noexcept {
  return implementation_ ? implementation_->incoming.size() : 0U;
}

State Session::state() const noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return State::failed;
  return public_state(implementation_->engine.state());
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::resource_exhausted;
}

tls::Failure Session::tls_failure() const noexcept {
  return implementation_ ? implementation_->engine.failure()
                         : tls::Failure::invalid_configuration;
}

} // namespace router::dot
