// nghttp3 1.17.0 HTTP/3 adapter over the socket-free QUIC owner. The adapter
// copies QPACK output into bounded QUIC stream storage before advancing
// nghttp3 offsets and returns receive credit only for bytes nghttp3 consumed.
// Source: ietf.http3.rfc9114
// Source: ietf.qpack.rfc9204
// Source: nghttp3.http3.1_17_0

#include "router/http3_session.hpp"

#include <nghttp3/nghttp3.h>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <deque>
#include <limits>
#include <map>

namespace router::http3 {
namespace {

[[nodiscard]] bool valid_field(const HeaderField &field) noexcept {
  if (field.name.empty() || field.name.find('\0') != std::string::npos ||
      field.value.find('\0') != std::string::npos)
    return false;
  return std::all_of(field.name.begin(), field.name.end(), [](char value) {
    const auto byte = static_cast<unsigned char>(value);
    return !(byte >= 'A' && byte <= 'Z') && byte > 0x20U && byte != 0x7fU;
  });
}

[[nodiscard]] std::size_t
field_octets(std::span<const HeaderField> fields) noexcept {
  std::size_t total{};
  for (const auto &field : fields) {
    if (!valid_field(field) ||
        field.name.size() > std::numeric_limits<std::size_t>::max() - total ||
        field.value.size() > std::numeric_limits<std::size_t>::max() - total -
                                 field.name.size())
      return std::numeric_limits<std::size_t>::max();
    total += field.name.size() + field.value.size();
  }
  return total;
}

[[nodiscard]] nghttp3_nv native_field(const HeaderField &field) noexcept {
  return {.name = reinterpret_cast<std::uint8_t *>(
              const_cast<char *>(field.name.data())),
          .value = reinterpret_cast<std::uint8_t *>(
              const_cast<char *>(field.value.data())),
          .namelen = field.name.size(),
          .valuelen = field.value.size(),
          .flags = NGHTTP3_NV_FLAG_NONE};
}

} // namespace

struct Session::Impl {
  struct StreamState {
    Message incoming;
    std::vector<std::uint8_t> outgoing_body;
    std::size_t outgoing_body_acked{};
    bool reading_trailers{};
    bool completion_queued{};
    bool body_read{};
  };

  quic::Connection connection;
  Role role;
  Configuration configuration;
  nghttp3_conn *http_connection{};
  std::map<std::int64_t, StreamState> streams;
  std::deque<std::int64_t> completed;
  Failure failure{Failure::none};

  Impl(quic::Connection value, Role session_role, Configuration limits)
      : connection(std::move(value)), role(session_role),
        configuration(limits) {}

  ~Impl() { nghttp3_conn_del(http_connection); }

  void fail(Failure reason, std::uint64_t application_error) noexcept {
    if (failure == Failure::none)
      failure = reason;
    static_cast<void>(connection.close_application(application_error));
  }

  [[nodiscard]] StreamState *stream(std::int64_t stream_id) noexcept {
    try {
      auto [iterator, inserted] = streams.try_emplace(stream_id);
      if (inserted)
        iterator->second.incoming.stream_id = stream_id;
      return &iterator->second;
    } catch (...) {
      return nullptr;
    }
  }

  static void random_bytes(std::uint8_t *destination,
                           std::size_t length) noexcept {
    // nghttp3's callback lacks user data and cannot report failure. Entropy
    // failure is process-wide cryptographic failure, so fail closed before any
    // predictable glitch-rate randomization can influence protocol behavior.
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        RAND_bytes(destination, static_cast<int>(length)) != 1)
      std::abort();
  }

  static int begin_headers(nghttp3_conn *, std::int64_t stream_id,
                           void *user_data, void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *state = self ? self->stream(stream_id) : nullptr;
    if (!state)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    state->reading_trailers = false;
    return nghttp3_conn_set_stream_user_data(self->http_connection, stream_id,
                                              state);
  }

  static int begin_trailers(nghttp3_conn *, std::int64_t stream_id,
                            void *user_data, void *stream_user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!state && self)
      state = self->stream(stream_id);
    if (!state)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    state->reading_trailers = true;
    return 0;
  }

  static int receive_header(nghttp3_conn *, std::int64_t,
                            std::int32_t, nghttp3_rcbuf *name,
                            nghttp3_rcbuf *value, std::uint8_t,
                            void *user_data, void *stream_user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!self || !state)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    const auto name_buffer = nghttp3_rcbuf_get_buf(name);
    const auto value_buffer = nghttp3_rcbuf_get_buf(value);
    auto &target = state->reading_trailers ? state->incoming.trailers
                                          : state->incoming.headers;
    std::size_t current{};
    for (const auto &field : target)
      current += field.name.size() + field.value.size();
    if (name_buffer.len > self->configuration.max_field_section_octets -
                              std::min(current, self->configuration.max_field_section_octets) ||
        value_buffer.len > self->configuration.max_field_section_octets -
                               std::min(current + name_buffer.len,
                                        self->configuration.max_field_section_octets))
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    try {
      target.push_back(
          {.name = {reinterpret_cast<const char *>(name_buffer.base),
                    name_buffer.len},
           .value = {reinterpret_cast<const char *>(value_buffer.base),
                     value_buffer.len}});
      return 0;
    } catch (...) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  static int receive_data(nghttp3_conn *, std::int64_t stream_id,
                          const std::uint8_t *data, std::size_t length,
                          void *user_data, void *stream_user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!self || !state ||
        length > self->configuration.max_body_octets -
                     std::min(state->incoming.body.size(),
                              self->configuration.max_body_octets))
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    try {
      state->incoming.body.insert(state->incoming.body.end(), data,
                                  data + length);
    } catch (...) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    return self->connection.consume_received_stream(stream_id, length) ==
                   quic::Failure::none
               ? 0
               : NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  static int deferred_consume(nghttp3_conn *, std::int64_t stream_id,
                              std::size_t length, void *user_data,
                              void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    return self && self->connection.consume_received_stream(stream_id,
                                                             length) ==
                       quic::Failure::none
               ? 0
               : NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  static int end_stream(nghttp3_conn *, std::int64_t stream_id,
                        void *user_data, void *stream_user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!self || !state || state->completion_queued ||
        self->completed.size() >= self->configuration.max_completed_messages)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    try {
      self->completed.push_back(stream_id);
      state->completion_queued = true;
      return 0;
    } catch (...) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }

  static int stop_sending(nghttp3_conn *, std::int64_t stream_id,
                          std::uint64_t error, void *user_data,
                          void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    return self && self->connection.stop_sending(stream_id, error) ==
                       quic::Failure::none
               ? 0
               : NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  static int reset_stream(nghttp3_conn *, std::int64_t stream_id,
                          std::uint64_t error, void *user_data,
                          void *) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    return self && self->connection.reset_stream(stream_id, error) ==
                       quic::Failure::none
               ? 0
               : NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  static int acknowledged_body(nghttp3_conn *, std::int64_t,
                               std::uint64_t length, void *,
                               void *stream_user_data) noexcept {
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!state || length > state->outgoing_body.size() -
                               state->outgoing_body_acked)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    state->outgoing_body_acked += static_cast<std::size_t>(length);
    if (state->outgoing_body_acked == state->outgoing_body.size()) {
      // Retain the allocation for the lifetime of the stream. Releasing it
      // from a noexcept nghttp3 callback could allocate internally and would
      // add allocator contention to the ACK path without reducing the
      // session's configured peak-memory obligation.
      state->outgoing_body.clear();
    }
    return 0;
  }

  static nghttp3_ssize read_body(nghttp3_conn *, std::int64_t,
                                 nghttp3_vec *vectors,
                                 std::size_t vector_capacity,
                                 std::uint32_t *flags, void *,
                                 void *stream_user_data) noexcept {
    auto *state = static_cast<StreamState *>(stream_user_data);
    if (!state || vector_capacity == 0U)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    if (state->body_read) {
      *flags |= NGHTTP3_DATA_FLAG_EOF;
      return 0;
    }
    vectors[0U] = {.base = state->outgoing_body.data(),
                   .len = state->outgoing_body.size()};
    state->body_read = true;
    *flags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
  }

  [[nodiscard]] bool initialize() noexcept {
    nghttp3_callbacks callbacks{};
    callbacks.acked_stream_data = acknowledged_body;
    callbacks.recv_data = receive_data;
    callbacks.deferred_consume = deferred_consume;
    callbacks.begin_headers = begin_headers;
    callbacks.recv_header = receive_header;
    callbacks.begin_trailers = begin_trailers;
    callbacks.recv_trailer = receive_header;
    callbacks.stop_sending = stop_sending;
    callbacks.end_stream = end_stream;
    callbacks.reset_stream = reset_stream;
    callbacks.rand = random_bytes;
    nghttp3_settings settings{};
    nghttp3_settings_default(&settings);
    settings.max_field_section_size = configuration.max_field_section_octets;
    settings.qpack_max_dtable_capacity =
        configuration.qpack_dynamic_table_octets;
    settings.qpack_encoder_max_dtable_capacity =
        configuration.qpack_dynamic_table_octets;
    settings.qpack_blocked_streams = configuration.qpack_blocked_streams;
    const auto create_result = role == Role::client
                                   ? nghttp3_conn_client_new(
                                         &http_connection, &callbacks,
                                         &settings, nullptr, this)
                                   : nghttp3_conn_server_new(
                                         &http_connection, &callbacks,
                                         &settings, nullptr, this);
    if (create_result != 0)
      return false;
    if (role == Role::server)
      nghttp3_conn_set_max_client_streams_bidi(
          http_connection, configuration.max_remote_bidirectional_streams);
    const auto control = connection.open_unidirectional_stream();
    const auto encoder = connection.open_unidirectional_stream();
    const auto decoder = connection.open_unidirectional_stream();
    return control && encoder && decoder &&
           nghttp3_conn_bind_control_stream(http_connection, *control) == 0 &&
           nghttp3_conn_bind_qpack_streams(http_connection, *encoder,
                                           *decoder) == 0;
  }

  [[nodiscard]] bool pump_ack() noexcept {
    auto acknowledged = connection.take_acknowledged_stream();
    return !acknowledged ||
           nghttp3_conn_add_ack_offset(http_connection,
                                       acknowledged->stream_id,
                                       acknowledged->octets) == 0;
  }

  [[nodiscard]] bool pump_input(quic::RuntimeClock::time_point now) noexcept {
    auto chunk = connection.take_received_stream();
    if (!chunk)
      return true;
    const auto consumed = nghttp3_conn_read_stream2(
        http_connection, chunk->stream_id, chunk->bytes.data(),
        chunk->bytes.size(), chunk->fin ? 1 : 0,
        static_cast<std::uint64_t>(std::chrono::duration_cast<
                                       std::chrono::nanoseconds>(
                                       now.time_since_epoch())
                                       .count()));
    if (consumed < 0)
      return false;
    return connection.consume_received_stream(
               chunk->stream_id, static_cast<std::size_t>(consumed)) ==
           quic::Failure::none;
  }

  [[nodiscard]] bool pump_output() noexcept {
    std::array<nghttp3_vec, 16U> vectors{};
    std::int64_t stream_id{-1};
    int fin{};
    const auto count = nghttp3_conn_writev_stream(
        http_connection, &stream_id, &fin, vectors.data(), vectors.size());
    if (count < 0)
      return false;
    if (stream_id < 0)
      return true;
    std::size_t total{};
    for (nghttp3_ssize index = 0; index < count; ++index) {
      const auto length = vectors[static_cast<std::size_t>(index)].len;
      if (length > configuration.max_staged_output_octets -
                       std::min(total, configuration.max_staged_output_octets))
        return false;
      total += length;
    }
    try {
      std::vector<std::uint8_t> bytes;
      bytes.reserve(total);
      for (nghttp3_ssize index = 0; index < count; ++index) {
        const auto &vector = vectors[static_cast<std::size_t>(index)];
        bytes.insert(bytes.end(), vector.base, vector.base + vector.len);
      }
      // nghttp3 may return a valid stream and FIN with no payload vectors.
      // Dropping that result leaves the peer waiting forever for the end of
      // the request or response, so even an empty byte span must reach QUIC.
      const auto result = connection.send_stream(stream_id, bytes, fin != 0);
      if (result != quic::Failure::none)
        return result == quic::Failure::flow_control_blocked;
      return nghttp3_conn_add_write_offset(http_connection, stream_id,
                                           total) == 0;
    } catch (...) {
      return false;
    }
  }
};

namespace {

[[nodiscard]] bool valid_configuration(const Configuration &value) noexcept {
  return value.max_field_section_octets != 0U &&
         value.max_body_octets != 0U && value.max_completed_messages != 0U &&
         value.max_staged_output_octets != 0U &&
         value.max_remote_bidirectional_streams != 0U;
}

[[nodiscard]] std::vector<nghttp3_nv>
native_fields(std::span<const HeaderField> fields) {
  std::vector<nghttp3_nv> result;
  result.reserve(fields.size());
  for (const auto &field : fields)
    result.push_back(native_field(field));
  return result;
}

} // namespace

Session::Session(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Session::Session(Session &&) noexcept = default;
Session &Session::operator=(Session &&) noexcept = default;
Session::~Session() = default;

std::optional<Session>
Session::create(quic::Connection connection, Role role,
                const Configuration &configuration) noexcept {
  if (!valid_configuration(configuration) ||
      connection.state() != quic::State::established ||
      connection.negotiated_alpn() != "h3")
    return std::nullopt;
  try {
    auto implementation =
        std::make_unique<Impl>(std::move(connection), role, configuration);
    if (!implementation->initialize())
      return std::nullopt;
    return Session{std::move(implementation)};
  } catch (...) {
    return std::nullopt;
  }
}

SubmitResult Session::submit_request(
    std::span<const HeaderField> headers, std::span<const std::uint8_t> body,
    std::int64_t &stream_id) noexcept {
  if (!implementation_ || implementation_->role != Role::client)
    return SubmitResult::wrong_role;
  if (state() != State::established)
    return SubmitResult::session_closed;
  if (field_octets(headers) > implementation_->configuration.max_field_section_octets ||
      body.size() > implementation_->configuration.max_body_octets)
    return SubmitResult::invalid_message;
  const auto stream = implementation_->connection.open_bidirectional_stream();
  if (!stream)
    return SubmitResult::stream_limit;
  try {
    auto *state = implementation_->stream(*stream);
    if (!state)
      return SubmitResult::resource_exhausted;
    state->outgoing_body.assign(body.begin(), body.end());
    auto native = native_fields(headers);
    const nghttp3_data_reader reader{.read_data = Impl::read_body};
    if (nghttp3_conn_submit_request(
            implementation_->http_connection, *stream, native.data(),
            native.size(), body.empty() ? nullptr : &reader, state) != 0)
      return SubmitResult::invalid_message;
    stream_id = *stream;
    return SubmitResult::applied;
  } catch (...) {
    return SubmitResult::resource_exhausted;
  }
}

SubmitResult Session::submit_response(
    std::int64_t stream_id, std::span<const HeaderField> headers,
    std::span<const std::uint8_t> body) noexcept {
  if (!implementation_ || implementation_->role != Role::server)
    return SubmitResult::wrong_role;
  if (state() != State::established)
    return SubmitResult::session_closed;
  if (field_octets(headers) > implementation_->configuration.max_field_section_octets ||
      body.size() > implementation_->configuration.max_body_octets)
    return SubmitResult::invalid_message;
  try {
    auto *state = implementation_->stream(stream_id);
    if (!state || !state->outgoing_body.empty() || state->body_read)
      return SubmitResult::invalid_message;
    state->outgoing_body.assign(body.begin(), body.end());
    auto native = native_fields(headers);
    const nghttp3_data_reader reader{.read_data = Impl::read_body};
    return nghttp3_conn_submit_response(
               implementation_->http_connection, stream_id, native.data(),
               native.size(), body.empty() ? nullptr : &reader) == 0
               ? SubmitResult::applied
               : SubmitResult::invalid_message;
  } catch (...) {
    return SubmitResult::resource_exhausted;
  }
}

State Session::progress(quic::RuntimeClock::time_point now) noexcept {
  if (!implementation_ || implementation_->failure != Failure::none)
    return State::failed;
  if (implementation_->connection.state() == quic::State::failed) {
    implementation_->fail(Failure::quic_failure, NGHTTP3_H3_INTERNAL_ERROR);
    return State::failed;
  }
  if (!implementation_->pump_ack() || !implementation_->pump_input(now) ||
      !implementation_->pump_output()) {
    implementation_->fail(Failure::protocol_error,
                          NGHTTP3_H3_GENERAL_PROTOCOL_ERROR);
    return State::failed;
  }
  return state();
}

std::optional<Message> Session::take_message() noexcept {
  if (!implementation_ || implementation_->completed.empty())
    return std::nullopt;
  const auto stream_id = implementation_->completed.front();
  implementation_->completed.pop_front();
  auto iterator = implementation_->streams.find(stream_id);
  if (iterator == implementation_->streams.end())
    return std::nullopt;
  iterator->second.completion_queued = false;
  Message result = std::move(iterator->second.incoming);
  iterator->second.incoming.stream_id = stream_id;
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
  if (!implementation_ || implementation_->failure != Failure::none ||
      implementation_->connection.state() == quic::State::failed)
    return State::failed;
  switch (implementation_->connection.state()) {
  case quic::State::closing:
  case quic::State::draining:
    return State::closing;
  case quic::State::closed:
    return State::closed;
  default:
    return State::established;
  }
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::invalid_configuration;
}

Role Session::role() const noexcept {
  return implementation_ ? implementation_->role : Role::client;
}

const quic::Connection &Session::transport() const noexcept {
  return implementation_->connection;
}

} // namespace router::http3
