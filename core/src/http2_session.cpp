// nghttp2 adapter for an emulator-owned byte stream. nghttp2 owns HTTP/2 and
// HPACK protocol state. Session owns application retention and overload policy.
// Source: ietf.http2.rfc9113
// Source: nghttp2.http2.1_69_0

#include "router/http2_session.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <utility>

namespace router::http2 {
namespace {

struct CallbackDeleter {
  void operator()(nghttp2_session_callbacks *callbacks) const noexcept {
    if (callbacks)
      nghttp2_session_callbacks_del(callbacks);
  }
};

struct OptionDeleter {
  void operator()(nghttp2_option *option) const noexcept {
    if (option)
      nghttp2_option_del(option);
  }
};

using CallbackOwner =
    std::unique_ptr<nghttp2_session_callbacks, CallbackDeleter>;
using OptionOwner = std::unique_ptr<nghttp2_option, OptionDeleter>;

struct OutgoingBody {
  std::vector<std::uint8_t> octets;
  std::size_t offset{};
};

struct StreamState {
  std::int32_t id{};
  std::vector<HeaderField> headers;
  std::vector<HeaderField> pending_headers;
  std::vector<HeaderField> trailers;
  std::vector<std::uint8_t> body;
  std::unique_ptr<OutgoingBody> outgoing_body;
  std::size_t received_header_octets{};
  bool final_headers_seen{};
  bool incoming_delivered{};
};

bool valid_configuration(const Configuration &configuration) noexcept {
  return configuration.max_concurrent_streams != 0U &&
         configuration.max_header_octets != 0U &&
         configuration.max_message_body_octets != 0U &&
         configuration.max_buffered_output_octets >=
             minimum_serialized_frame_octets &&
         configuration.max_completed_messages != 0U;
}

bool append_size(std::size_t &total, std::size_t addition,
                 std::size_t limit) noexcept {
  // Subtraction avoids wrapping size_t before the resource decision. The
  // caller can therefore distinguish protocol input from local exhaustion.
  if (total > limit || addition > limit - total)
    return false;
  total += addition;
  return true;
}

bool status_is_informational(std::span<const HeaderField> fields) noexcept {
  for (const auto &field : fields)
    if (field.name == ":status")
      return field.value.size() == 3U && field.value.front() == '1';
  return false;
}

bool contains_status(std::span<const HeaderField> fields) noexcept {
  return std::any_of(fields.begin(), fields.end(), [](const HeaderField &field) {
    return field.name == ":status";
  });
}

std::vector<nghttp2_nv>
native_headers(std::span<const HeaderField> headers) {
  std::vector<nghttp2_nv> result;
  result.reserve(headers.size());
  for (const auto &field : headers) {
    // NGHTTP2_NV_FLAG_NONE asks nghttp2 to copy the fields during submission.
    // The caller's strings therefore need to remain alive only for this call.
    result.push_back(
        {.name = reinterpret_cast<std::uint8_t *>(
             const_cast<char *>(field.name.data())),
         .value = reinterpret_cast<std::uint8_t *>(
             const_cast<char *>(field.value.data())),
         .namelen = field.name.size(),
         .valuelen = field.value.size(),
         .flags = NGHTTP2_NV_FLAG_NONE});
  }
  return result;
}

bool valid_outgoing_headers(std::span<const HeaderField> headers,
                            std::size_t limit) noexcept {
  if (headers.empty())
    return false;
  std::size_t total{};
  for (const auto &field : headers) {
    if (field.name.empty() ||
        nghttp2_check_header_name(
            reinterpret_cast<const std::uint8_t *>(field.name.data()),
            field.name.size()) == 0 ||
        nghttp2_check_header_value_rfc9113(
            reinterpret_cast<const std::uint8_t *>(field.value.data()),
            field.value.size()) == 0 ||
        !append_size(total, field.name.size(), limit) ||
        !append_size(total, field.value.size(), limit))
      return false;
  }
  return true;
}

} // namespace

struct Session::Impl {
  nghttp2_session *session{};
  Role role{Role::client};
  Configuration configuration{};
  std::map<std::int32_t, std::unique_ptr<StreamState>> streams;
  std::deque<Message> completed_messages;
  std::vector<std::uint8_t> pending_output;
  std::size_t pending_output_offset{};
  State state{State::open};
  Failure failure{Failure::none};
  int provider_error{};

  ~Impl() {
    if (session)
      nghttp2_session_del(session);
  }

  void fail(Failure reason, int error = 0) noexcept {
    // Preserve the first failure because it identifies the boundary that
    // actually broke. Later nghttp2 calls commonly return a generic callback
    // error which would otherwise hide the resource or protocol root cause.
    if (state == State::failed)
      return;
    state = State::failed;
    failure = reason;
    provider_error = error;
  }

  StreamState *find_stream(std::int32_t id) noexcept {
    const auto found = streams.find(id);
    return found == streams.end() ? nullptr : found->second.get();
  }

  StreamState *make_remote_stream(std::int32_t id) noexcept {
    if (streams.size() >= configuration.max_concurrent_streams)
      return nullptr;
    try {
      auto stream = std::make_unique<StreamState>();
      stream->id = id;
      auto *view = stream.get();
      const auto insertion = streams.emplace(id, std::move(stream));
      return insertion.second ? view : nullptr;
    } catch (...) {
      return nullptr;
    }
  }

  int emit_message(StreamState &stream, bool complete,
                   std::uint32_t error_code) noexcept {
    if (completed_messages.size() >= configuration.max_completed_messages) {
      fail(Failure::resource_exhausted);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    try {
      // Moving the assembled message makes queue publication O(1) for the body
      // and field vectors. The stream object stays alive for the opposite half
      // of the bidirectional exchange and for nghttp2 callback ownership.
      completed_messages.push_back(
          {.stream_id = stream.id,
           .request = role == Role::server,
           .complete = complete,
           .error_code = error_code,
           .headers = std::move(stream.headers),
           .body = std::move(stream.body),
           .trailers = std::move(stream.trailers)});
      stream.incoming_delivered = complete;
      return 0;
    } catch (...) {
      fail(Failure::resource_exhausted);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  int finish_header_block(const nghttp2_frame &frame) noexcept {
    auto *stream = find_stream(frame.hd.stream_id);
    if (!stream)
      return 0;
    try {
      if (role == Role::server) {
        if (frame.headers.cat == NGHTTP2_HCAT_REQUEST) {
          stream->headers = std::move(stream->pending_headers);
          stream->final_headers_seen = true;
        } else {
          stream->trailers.insert(
              stream->trailers.end(),
              std::make_move_iterator(stream->pending_headers.begin()),
              std::make_move_iterator(stream->pending_headers.end()));
          stream->pending_headers.clear();
        }
      } else if (contains_status(stream->pending_headers)) {
        // Informational responses do not replace the final response delivered
        // to the application. A later non-1xx field section becomes the final
        // header set, exactly as RFC 9113 Section 8.1 requires.
        if (!status_is_informational(stream->pending_headers)) {
          stream->headers = std::move(stream->pending_headers);
          stream->final_headers_seen = true;
        } else {
          stream->pending_headers.clear();
        }
      } else if (stream->final_headers_seen) {
        stream->trailers.insert(
            stream->trailers.end(),
            std::make_move_iterator(stream->pending_headers.begin()),
            std::make_move_iterator(stream->pending_headers.end()));
        stream->pending_headers.clear();
      }
    } catch (...) {
      fail(Failure::resource_exhausted);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if ((frame.hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U &&
        stream->final_headers_seen && !stream->incoming_delivered)
      return emit_message(*stream, true, NGHTTP2_NO_ERROR);
    return 0;
  }

  static nghttp2_ssize read_body(nghttp2_session *, std::int32_t,
                                 std::uint8_t *buffer, std::size_t length,
                                 std::uint32_t *data_flags,
                                 nghttp2_data_source *source, void *) noexcept {
    auto *body = source ? static_cast<OutgoingBody *>(source->ptr) : nullptr;
    if (!body || !data_flags)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    const auto available = body->octets.size() - body->offset;
    const auto count = std::min(length, available);
    if (count != 0U) {
      std::memcpy(buffer, body->octets.data() + body->offset, count);
      body->offset += count;
    }
    if (body->offset == body->octets.size())
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(count);
  }

  static int begin_headers(nghttp2_session *native,
                           const nghttp2_frame *frame,
                           void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self || !frame || frame->hd.type != NGHTTP2_HEADERS)
      return 0;
    auto *stream = self->find_stream(frame->hd.stream_id);
    if (!stream && self->role == Role::server &&
        frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      stream = self->make_remote_stream(frame->hd.stream_id);
      if (stream)
        static_cast<void>(nghttp2_session_set_stream_user_data(
            native, frame->hd.stream_id, stream));
    }
    if (!stream) {
      // The remote peer exceeded the configured owner capacity. Returning a
      // temporal failure resets only this stream and keeps unrelated streams
      // valid unless allocation failure already marked the connection failed.
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    stream->pending_headers.clear();
    return 0;
  }

  static int receive_header(nghttp2_session *, const nghttp2_frame *frame,
                            const std::uint8_t *name, std::size_t name_length,
                            const std::uint8_t *value,
                            std::size_t value_length, std::uint8_t,
                            void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *stream = self && frame ? self->find_stream(frame->hd.stream_id)
                                 : nullptr;
    if (!stream)
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    if (!append_size(stream->received_header_octets, name_length,
                     self->configuration.max_header_octets) ||
        !append_size(stream->received_header_octets, value_length,
                     self->configuration.max_header_octets))
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    try {
      stream->pending_headers.push_back(
          {.name = std::string(reinterpret_cast<const char *>(name),
                              name_length),
           .value = std::string(reinterpret_cast<const char *>(value),
                                value_length)});
      return 0;
    } catch (...) {
      self->fail(Failure::resource_exhausted);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int receive_data(nghttp2_session *, std::uint8_t,
                          std::int32_t stream_id, const std::uint8_t *data,
                          std::size_t length, void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    auto *stream = self ? self->find_stream(stream_id) : nullptr;
    if (!stream || stream->body.size() >
                       self->configuration.max_message_body_octets ||
        length > self->configuration.max_message_body_octets -
                     stream->body.size())
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    try {
      stream->body.insert(stream->body.end(), data, data + length);
      return 0;
    } catch (...) {
      self->fail(Failure::resource_exhausted);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  static int receive_frame(nghttp2_session *, const nghttp2_frame *frame,
                           void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self || !frame)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (frame->hd.type == NGHTTP2_HEADERS)
      return self->finish_header_block(*frame);
    if (frame->hd.type == NGHTTP2_DATA &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0U) {
      auto *stream = self->find_stream(frame->hd.stream_id);
      if (stream && stream->final_headers_seen &&
          !stream->incoming_delivered)
        return self->emit_message(*stream, true, NGHTTP2_NO_ERROR);
    }
    if (frame->hd.type == NGHTTP2_GOAWAY)
      self->state = State::draining;
    return 0;
  }

  static int close_stream(nghttp2_session *, std::int32_t stream_id,
                          std::uint32_t error_code,
                          void *user_data) noexcept {
    auto *self = static_cast<Impl *>(user_data);
    if (!self)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    auto found = self->streams.find(stream_id);
    if (found == self->streams.end())
      return 0;
    if (error_code != NGHTTP2_NO_ERROR) {
      const auto result = self->emit_message(*found->second, false, error_code);
      if (result != 0)
        return result;
    }
    self->streams.erase(found);
    return 0;
  }
};

Session::Session(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Session::Session(Session &&) noexcept = default;
Session &Session::operator=(Session &&) noexcept = default;
Session::~Session() = default;

std::optional<Session>
Session::create(Role role, const Configuration &configuration) noexcept {
  if (!valid_configuration(configuration) ||
      configuration.max_concurrent_streams >
          static_cast<std::uint32_t>(std::numeric_limits<std::int32_t>::max()))
    return std::nullopt;
  try {
    auto implementation = std::make_unique<Impl>();
    implementation->role = role;
    implementation->configuration = configuration;
    implementation->pending_output.reserve(
        configuration.max_buffered_output_octets);

    nghttp2_session_callbacks *raw_callbacks{};
    if (nghttp2_session_callbacks_new(&raw_callbacks) != 0)
      return std::nullopt;
    CallbackOwner callbacks{raw_callbacks};
    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks.get(), &Impl::begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks.get(),
                                                     &Impl::receive_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks.get(), &Impl::receive_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(),
                                                         &Impl::receive_frame);
    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks.get(), &Impl::close_stream);

    nghttp2_option *raw_option{};
    if (nghttp2_option_new(&raw_option) != 0)
      return std::nullopt;
    OptionOwner option{raw_option};
    nghttp2_option_set_peer_max_concurrent_streams(
        option.get(), configuration.max_concurrent_streams);
    nghttp2_option_set_max_send_header_block_length(
        option.get(), configuration.max_header_octets);

    const auto create_result =
        role == Role::client
            ? nghttp2_session_client_new2(&implementation->session,
                                          callbacks.get(),
                                          implementation.get(), option.get())
            : nghttp2_session_server_new2(&implementation->session,
                                          callbacks.get(),
                                          implementation.get(), option.get());
    if (create_result != 0)
      return std::nullopt;

    std::array<nghttp2_settings_entry, 2U> settings{
        nghttp2_settings_entry{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                               configuration.max_concurrent_streams},
        nghttp2_settings_entry{NGHTTP2_SETTINGS_ENABLE_PUSH,
                               configuration.accept_server_push ? 1U : 0U}};
    const auto count = role == Role::client ? settings.size() : 1U;
    if (nghttp2_submit_settings(implementation->session, NGHTTP2_FLAG_NONE,
                                settings.data(), count) != 0)
      return std::nullopt;
    return Session{std::move(implementation)};
  } catch (...) {
    return std::nullopt;
  }
}

SubmitOutcome
Session::submit_request(std::span<const HeaderField> headers,
                        std::span<const std::uint8_t> body) noexcept {
  if (!implementation_ || implementation_->role != Role::client)
    return {.result = SubmitResult::invalid_role, .stream_id = -1};
  if (implementation_->state != State::open)
    return {.result = SubmitResult::stream_unavailable, .stream_id = -1};
  if (!valid_outgoing_headers(headers,
                              implementation_->configuration.max_header_octets) ||
      body.size() >
          implementation_->configuration.max_message_body_octets)
    return {.result = SubmitResult::invalid_message, .stream_id = -1};
  if (implementation_->streams.size() >=
      implementation_->configuration.max_concurrent_streams)
    return {.result = SubmitResult::stream_unavailable, .stream_id = -1};
  try {
    auto stream = std::make_unique<StreamState>();
    auto outgoing = std::make_unique<OutgoingBody>();
    outgoing->octets.assign(body.begin(), body.end());
    nghttp2_data_provider2 provider{};
    provider.source.ptr = outgoing.get();
    provider.read_callback = &Impl::read_body;
    const auto fields = native_headers(headers);
    const auto stream_id = nghttp2_submit_request2(
        implementation_->session, nullptr, fields.data(), fields.size(),
        body.empty() ? nullptr : &provider, stream.get());
    if (stream_id < 0)
      return {.result = SubmitResult::protocol_error, .stream_id = -1};
    stream->id = stream_id;
    stream->outgoing_body = std::move(outgoing);
    implementation_->streams.emplace(stream_id, std::move(stream));
    return {.result = SubmitResult::applied, .stream_id = stream_id};
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return {.result = SubmitResult::resource_exhausted, .stream_id = -1};
  }
}

SubmitResult Session::submit_response(
    std::int32_t stream_id, std::span<const HeaderField> headers,
    std::span<const std::uint8_t> body) noexcept {
  if (!implementation_ || implementation_->role != Role::server)
    return SubmitResult::invalid_role;
  if (implementation_->state == State::failed ||
      implementation_->state == State::closed)
    return SubmitResult::stream_unavailable;
  auto *stream = implementation_->find_stream(stream_id);
  if (!stream || stream->outgoing_body)
    return SubmitResult::stream_unavailable;
  if (!valid_outgoing_headers(headers,
                              implementation_->configuration.max_header_octets) ||
      body.size() >
          implementation_->configuration.max_message_body_octets)
    return SubmitResult::invalid_message;
  try {
    auto outgoing = std::make_unique<OutgoingBody>();
    outgoing->octets.assign(body.begin(), body.end());
    nghttp2_data_provider2 provider{};
    provider.source.ptr = outgoing.get();
    provider.read_callback = &Impl::read_body;
    const auto fields = native_headers(headers);
    const auto result = nghttp2_submit_response2(
        implementation_->session, stream_id, fields.data(), fields.size(),
        body.empty() ? nullptr : &provider);
    if (result != 0)
      return SubmitResult::protocol_error;
    stream->outgoing_body = std::move(outgoing);
    return SubmitResult::applied;
  } catch (...) {
    implementation_->fail(Failure::resource_exhausted);
    return SubmitResult::resource_exhausted;
  }
}

std::size_t
Session::ingest_bytes(std::span<const std::uint8_t> bytes) noexcept {
  if (!implementation_ || implementation_->state == State::failed ||
      implementation_->state == State::closed || bytes.empty())
    return 0U;
  const auto consumed = nghttp2_session_mem_recv2(
      implementation_->session, bytes.data(), bytes.size());
  if (consumed < 0) {
    implementation_->fail(Failure::protocol_error,
                          static_cast<int>(consumed));
    return 0U;
  }
  return static_cast<std::size_t>(consumed);
}

std::size_t Session::take_bytes(std::span<std::uint8_t> output) noexcept {
  if (!implementation_ || implementation_->state == State::failed ||
      output.empty())
    return 0U;
  if (implementation_->pending_output_offset ==
      implementation_->pending_output.size()) {
    implementation_->pending_output.clear();
    implementation_->pending_output_offset = 0U;
    const std::uint8_t *serialized{};
    const auto length =
        nghttp2_session_mem_send2(implementation_->session, &serialized);
    if (length < 0) {
      implementation_->fail(Failure::protocol_error,
                            static_cast<int>(length));
      return 0U;
    }
    if (length == 0)
      return 0U;
    if (static_cast<std::size_t>(length) >
        implementation_->configuration.max_buffered_output_octets) {
      implementation_->fail(Failure::resource_exhausted);
      return 0U;
    }
    try {
      implementation_->pending_output.assign(
          serialized, serialized + static_cast<std::size_t>(length));
    } catch (...) {
      implementation_->fail(Failure::resource_exhausted);
      return 0U;
    }
  }
  const auto available = implementation_->pending_output.size() -
                         implementation_->pending_output_offset;
  const auto count = std::min(available, output.size());
  std::memcpy(output.data(),
              implementation_->pending_output.data() +
                  implementation_->pending_output_offset,
              count);
  implementation_->pending_output_offset += count;
  return count;
}

std::optional<Message> Session::take_message() noexcept {
  if (!implementation_ || implementation_->completed_messages.empty())
    return std::nullopt;
  auto result = std::move(implementation_->completed_messages.front());
  implementation_->completed_messages.pop_front();
  return result;
}

bool Session::wants_read() const noexcept {
  return implementation_ && implementation_->state != State::failed &&
         implementation_->state != State::closed &&
         nghttp2_session_want_read(implementation_->session) != 0;
}

bool Session::wants_write() const noexcept {
  return implementation_ && implementation_->state != State::failed &&
         (pending_output_octets() != 0U ||
          nghttp2_session_want_write(implementation_->session) != 0);
}

std::size_t Session::pending_output_octets() const noexcept {
  return implementation_
             ? implementation_->pending_output.size() -
                   implementation_->pending_output_offset
             : 0U;
}

std::size_t Session::active_streams() const noexcept {
  return implementation_ ? implementation_->streams.size() : 0U;
}

Role Session::role() const noexcept {
  return implementation_ ? implementation_->role : Role::client;
}

State Session::state() const noexcept {
  return implementation_ ? implementation_->state : State::failed;
}

Failure Session::failure() const noexcept {
  return implementation_ ? implementation_->failure
                         : Failure::invalid_configuration;
}

int Session::provider_error() const noexcept {
  return implementation_ ? implementation_->provider_error : 0;
}

} // namespace router::http2
