// TCP endpoint checkpoint ABI codec. Every helper mirrors one checkpoint
// value contract and uses explicit little-endian fields, so Windows native and
// Wasm builds produce identical images without serializing object layout.

#include "router/tcp_checkpoint_codec.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <type_traits>

namespace router::transport::tcp::checkpoint {
namespace {

template <typename T, bool = std::is_enum_v<T>> struct IntegerType {
  using type = T;
};
template <typename T> struct IntegerType<T, true> {
  using type = std::underlying_type_t<T>;
};

class Writer final {
public:
  template <typename T> void integer(T value) {
    using Raw = typename IntegerType<T>::type;
    using Unsigned = std::make_unsigned_t<Raw>;
    const auto raw = static_cast<Unsigned>(value);
    for (std::size_t index = 0U; index < sizeof(Unsigned); ++index)
      bytes_.push_back(static_cast<std::uint8_t>(raw >> (index * 8U)));
  }
  void boolean(bool value) { integer<std::uint8_t>(value ? 1U : 0U); }
  void octets(std::span<const std::uint8_t> value) {
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }
  [[nodiscard]] std::vector<std::uint8_t> finish() && {
    return std::move(bytes_);
  }

private:
  std::vector<std::uint8_t> bytes_;
};

class Reader final {
public:
  explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
  template <typename T> bool integer(T &value) noexcept {
    using Raw = typename IntegerType<T>::type;
    using Unsigned = std::make_unsigned_t<Raw>;
    if (remaining() < sizeof(Unsigned))
      return false;
    Unsigned raw{};
    for (std::size_t index = 0U; index < sizeof(Unsigned); ++index)
      raw |= static_cast<Unsigned>(bytes_[offset_++]) << (index * 8U);
    value = static_cast<T>(raw);
    return true;
  }
  bool boolean(bool &value) noexcept {
    std::uint8_t raw{};
    if (!integer(raw) || raw > 1U)
      return false;
    value = raw != 0U;
    return true;
  }
  bool octets(std::span<std::uint8_t> output) noexcept {
    if (remaining() < output.size())
      return false;
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                output.size(), output.begin());
    offset_ += output.size();
    return true;
  }
  [[nodiscard]] std::size_t remaining() const noexcept {
    return bytes_.size() - offset_;
  }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{};
};

template <typename T, typename Encode>
void optional(Writer &out, const std::optional<T> &value, Encode encode) {
  out.boolean(value.has_value());
  if (value)
    encode(out, *value);
}

template <typename T, typename Decode>
bool optional(Reader &in, std::optional<T> &value, Decode decode) {
  bool present{};
  if (!in.boolean(present))
    return false;
  if (!present) {
    value.reset();
    return true;
  }
  T decoded{};
  if (!decode(in, decoded))
    return false;
  value = std::move(decoded);
  return true;
}

template <std::size_t Size>
void octet_array(Writer &out, const std::array<std::uint8_t, Size> &value) {
  out.octets(value);
}

template <std::size_t Size>
bool octet_array(Reader &in, std::array<std::uint8_t, Size> &value) noexcept {
  return in.octets(value);
}

void byte_vector(Writer &out, const std::vector<std::uint8_t> &value) {
  if (value.size() > std::numeric_limits<std::uint32_t>::max())
    throw std::length_error("TCP checkpoint byte vector exceeds ABI length");
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.size()));
  out.octets(value);
}

bool byte_vector(Reader &in, std::vector<std::uint8_t> &value) {
  std::uint32_t size{};
  // The serial-arithmetic domain is also the largest legitimate socket arena.
  // Remaining input provides a tighter allocation bound for corrupt images.
  if (!in.integer(size) || size > 0x40000000U || size > in.remaining())
    return false;
  value.resize(size);
  return in.octets(value);
}

void fields(Writer &out, const packet::tcp::Fields &value) {
  out.integer(value.source_port);
  out.integer(value.destination_port);
  out.integer(value.sequence);
  out.integer(value.acknowledgment);
  out.integer(value.flags);
  out.integer(value.window);
  out.integer(value.urgent_pointer);
}

bool fields(Reader &in, packet::tcp::Fields &value) noexcept {
  return in.integer(value.source_port) &&
         in.integer(value.destination_port) && in.integer(value.sequence) &&
         in.integer(value.acknowledgment) && in.integer(value.flags) &&
         in.integer(value.window) && in.integer(value.urgent_pointer);
}

void retransmission(Writer &out, const RetransmissionCheckpoint &value) {
  out.integer(value.smoothed_rtt_nanoseconds);
  out.integer(value.rtt_variation_nanoseconds);
  out.integer(value.timeout_nanoseconds);
  out.boolean(value.measurement_present);
  out.boolean(value.syn_retransmitted);
}

bool retransmission(Reader &in, RetransmissionCheckpoint &value) noexcept {
  return in.integer(value.smoothed_rtt_nanoseconds) &&
         in.integer(value.rtt_variation_nanoseconds) &&
         in.integer(value.timeout_nanoseconds) &&
         in.boolean(value.measurement_present) &&
         in.boolean(value.syn_retransmitted);
}

void congestion(Writer &out, const CongestionCheckpoint &value) {
  out.integer(value.sender_mss);
  out.integer(value.congestion_window);
  out.integer(value.slow_start_threshold);
  out.integer(value.duplicate_acknowledgments);
  out.integer(value.recovery_inflation_limit);
  out.boolean(value.fast_recovery);
  out.boolean(value.sack_recovery);
}

bool congestion(Reader &in, CongestionCheckpoint &value) noexcept {
  return in.integer(value.sender_mss) &&
         in.integer(value.congestion_window) &&
         in.integer(value.slow_start_threshold) &&
         in.integer(value.duplicate_acknowledgments) &&
         in.integer(value.recovery_inflation_limit) &&
         in.boolean(value.fast_recovery) && in.boolean(value.sack_recovery);
}

void control(Writer &out, const ControlBlockCheckpoint &value) {
  retransmission(out, value.retransmission);
  congestion(out, value.congestion);
  fields(out, value.outstanding_control);
  out.integer(value.retransmission_remaining_nanoseconds);
  out.integer(value.time_wait_remaining_nanoseconds);
  out.integer(value.send_unacknowledged);
  out.integer(value.send_next);
  out.integer(value.send_window);
  out.integer(value.send_window_sequence);
  out.integer(value.send_window_acknowledgment);
  out.integer(value.receive_next);
  out.integer(value.receive_window);
  out.integer(value.initial_send_sequence);
  out.integer(value.initial_receive_sequence);
  out.integer(value.local_port);
  out.integer(value.remote_port);
  out.integer(value.state);
  out.boolean(value.passive_open);
  out.boolean(value.outstanding_control_present);
  out.boolean(value.local_fin_sent);
}

bool control(Reader &in, ControlBlockCheckpoint &value) noexcept {
  return retransmission(in, value.retransmission) &&
         congestion(in, value.congestion) &&
         fields(in, value.outstanding_control) &&
         in.integer(value.retransmission_remaining_nanoseconds) &&
         in.integer(value.time_wait_remaining_nanoseconds) &&
         in.integer(value.send_unacknowledged) && in.integer(value.send_next) &&
         in.integer(value.send_window) &&
         in.integer(value.send_window_sequence) &&
         in.integer(value.send_window_acknowledgment) &&
         in.integer(value.receive_next) && in.integer(value.receive_window) &&
         in.integer(value.initial_send_sequence) &&
         in.integer(value.initial_receive_sequence) &&
         in.integer(value.local_port) && in.integer(value.remote_port) &&
         in.integer(value.state) && in.boolean(value.passive_open) &&
         in.boolean(value.outstanding_control_present) &&
         in.boolean(value.local_fin_sent);
}

void syn_offer(Writer &out, const SynOptionOffer &value) {
  out.integer(value.receive_mss);
  out.integer(value.receive_window_shift);
  out.boolean(value.offer_window_scale);
  out.boolean(value.offer_timestamps);
  out.boolean(value.offer_sack);
  out.integer(value.timestamp_value);
  out.integer(value.timestamp_echo_reply);
}

bool syn_offer(Reader &in, SynOptionOffer &value) noexcept {
  return in.integer(value.receive_mss) &&
         in.integer(value.receive_window_shift) &&
         in.boolean(value.offer_window_scale) &&
         in.boolean(value.offer_timestamps) && in.boolean(value.offer_sack) &&
         in.integer(value.timestamp_value) &&
         in.integer(value.timestamp_echo_reply);
}

void typed_options(Writer &out, const TypedOptions &value) {
  optional(out, value.maximum_segment_size,
           [](Writer &writer, std::uint16_t item) { writer.integer(item); });
  optional(out, value.window_scale,
           [](Writer &writer, std::uint8_t item) { writer.integer(item); });
  optional(out, value.timestamp_value,
           [](Writer &writer, std::uint32_t item) { writer.integer(item); });
  optional(out, value.timestamp_echo_reply,
           [](Writer &writer, std::uint32_t item) { writer.integer(item); });
  out.integer(value.sack_block_count);
  for (const auto &block : value.sack_blocks) {
    out.integer(block.left_edge);
    out.integer(block.right_edge);
  }
  out.boolean(value.sack_permitted);
}

bool typed_options(Reader &in, TypedOptions &value) {
  const auto u16 = [](Reader &reader, std::uint16_t &item) {
    return reader.integer(item);
  };
  const auto u8 = [](Reader &reader, std::uint8_t &item) {
    return reader.integer(item);
  };
  const auto u32 = [](Reader &reader, std::uint32_t &item) {
    return reader.integer(item);
  };
  if (!optional(in, value.maximum_segment_size, u16) ||
      !optional(in, value.window_scale, u8) ||
      !optional(in, value.timestamp_value, u32) ||
      !optional(in, value.timestamp_echo_reply, u32) ||
      !in.integer(value.sack_block_count))
    return false;
  for (auto &block : value.sack_blocks)
    if (!in.integer(block.left_edge) || !in.integer(block.right_edge))
      return false;
  return in.boolean(value.sack_permitted);
}

void negotiated(Writer &out, const NegotiatedOptions &value) {
  out.integer(value.send_mss);
  out.integer(value.send_window_shift);
  out.integer(value.receive_window_shift);
  out.boolean(value.window_scaling);
  out.boolean(value.timestamps);
  out.boolean(value.sack);
}

bool negotiated(Reader &in, NegotiatedOptions &value) noexcept {
  return in.integer(value.send_mss) &&
         in.integer(value.send_window_shift) &&
         in.integer(value.receive_window_shift) &&
         in.boolean(value.window_scaling) && in.boolean(value.timestamps) &&
         in.boolean(value.sack);
}

void timestamp(Writer &out, const TimestampCheckpoint &value) {
  out.integer(value.recent);
  out.integer(value.last_ack_sent);
  out.integer(value.recent_age_nanoseconds);
  out.boolean(value.negotiated);
  out.boolean(value.recent_present);
}

bool timestamp(Reader &in, TimestampCheckpoint &value) noexcept {
  return in.integer(value.recent) && in.integer(value.last_ack_sent) &&
         in.integer(value.recent_age_nanoseconds) &&
         in.boolean(value.negotiated) && in.boolean(value.recent_present);
}

void send_buffer(Writer &out, const SendBufferCheckpoint &value) {
  byte_vector(out, value.storage);
  out.integer(value.send_unacknowledged);
  out.integer(value.send_next);
  out.integer(value.write_next);
  out.integer(value.head);
  out.integer(value.generation);
}

bool send_buffer(Reader &in, SendBufferCheckpoint &value) {
  return byte_vector(in, value.storage) &&
         in.integer(value.send_unacknowledged) && in.integer(value.send_next) &&
         in.integer(value.write_next) && in.integer(value.head) &&
         in.integer(value.generation);
}

void history(Writer &out, const TransmissionHistoryCheckpoint &value) {
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.records.size()));
  for (const auto &record : value.records) {
    out.integer(record.first);
    out.integer(record.end);
    out.integer(record.retransmissions);
    out.integer(record.first_age_nanoseconds);
    out.integer(record.last_age_nanoseconds);
  }
}

bool history(Reader &in, TransmissionHistoryCheckpoint &value) {
  std::uint32_t size{};
  if (!in.integer(size) || size > in.remaining() / 28U)
    return false;
  value.records.resize(size);
  for (auto &record : value.records)
    if (!in.integer(record.first) || !in.integer(record.end) ||
        !in.integer(record.retransmissions) ||
        !in.integer(record.first_age_nanoseconds) ||
        !in.integer(record.last_age_nanoseconds))
      return false;
  return true;
}

void failure(Writer &out, const FailureCheckpoint &value) {
  out.integer(value.segment_first);
  out.integer(value.segment_end);
  out.integer(value.retransmissions);
  out.integer(value.segment_age_nanoseconds);
  out.integer(value.data_r2_nanoseconds);
  out.boolean(value.active);
  out.boolean(value.syn);
  out.boolean(value.negative_advice_reported);
  out.boolean(value.data_r2_infinite);
}

bool failure(Reader &in, FailureCheckpoint &value) noexcept {
  return in.integer(value.segment_first) && in.integer(value.segment_end) &&
         in.integer(value.retransmissions) &&
         in.integer(value.segment_age_nanoseconds) &&
         in.integer(value.data_r2_nanoseconds) && in.boolean(value.active) &&
         in.boolean(value.syn) &&
         in.boolean(value.negative_advice_reported) &&
         in.boolean(value.data_r2_infinite);
}

void sack(Writer &out, const SackScoreboardCheckpoint &value) {
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.ranges.size()));
  for (const auto &range : value.ranges) {
    out.integer(range.first);
    out.integer(range.end);
  }
  out.integer(value.high_ack);
  out.integer(value.high_data_end);
  out.integer(value.high_retransmitted_end);
  out.integer(value.recovery_point);
  out.integer(value.rescue_retransmitted);
  out.integer(value.duplicate_acknowledgments);
  out.boolean(value.recovery);
  out.boolean(value.rescue_present);
  out.boolean(value.recovery_suppressed);
}

bool sack(Reader &in, SackScoreboardCheckpoint &value) {
  std::uint32_t size{};
  if (!in.integer(size) || size > in.remaining() / 8U)
    return false;
  value.ranges.resize(size);
  for (auto &range : value.ranges)
    if (!in.integer(range.first) || !in.integer(range.end))
      return false;
  return in.integer(value.high_ack) && in.integer(value.high_data_end) &&
         in.integer(value.high_retransmitted_end) &&
         in.integer(value.recovery_point) &&
         in.integer(value.rescue_retransmitted) &&
         in.integer(value.duplicate_acknowledgments) &&
         in.boolean(value.recovery) && in.boolean(value.rescue_present) &&
         in.boolean(value.recovery_suppressed);
}

void persist(Writer &out, const PersistCheckpoint &value) {
  out.integer(value.remaining_nanoseconds);
  out.integer(value.interval_nanoseconds);
  out.boolean(value.active);
}

bool persist(Reader &in, PersistCheckpoint &value) noexcept {
  return in.integer(value.remaining_nanoseconds) &&
         in.integer(value.interval_nanoseconds) && in.boolean(value.active);
}

void sender(Writer &out, const SenderCheckpoint &value) {
  send_buffer(out, value.bytes);
  history(out, value.history);
  failure(out, value.failure);
  sack(out, value.sack);
  congestion(out, value.congestion);
  retransmission(out, value.retransmission);
  persist(out, value.persist);
  out.integer(value.receiver_window);
  out.integer(value.maximum_receiver_window);
  out.integer(value.rtt_sequence_end);
  out.integer(value.retransmission_remaining_nanoseconds);
  out.integer(value.rtt_probe_age_nanoseconds);
  out.integer(value.sws_override_remaining_nanoseconds);
  out.integer(value.generation);
  out.integer(value.pending_failure_action);
  out.boolean(value.retransmission_deadline_present);
  out.boolean(value.rtt_probe_present);
  out.boolean(value.rtt_probe_retransmitted);
  out.boolean(value.fast_retransmission_pending);
  out.boolean(value.sws_override_deadline_present);
  out.boolean(value.nagle_enabled);
  out.boolean(value.sack_enabled);
}

bool sender(Reader &in, SenderCheckpoint &value) {
  return send_buffer(in, value.bytes) && history(in, value.history) &&
         failure(in, value.failure) && sack(in, value.sack) &&
         congestion(in, value.congestion) &&
         retransmission(in, value.retransmission) &&
         persist(in, value.persist) && in.integer(value.receiver_window) &&
         in.integer(value.maximum_receiver_window) &&
         in.integer(value.rtt_sequence_end) &&
         in.integer(value.retransmission_remaining_nanoseconds) &&
         in.integer(value.rtt_probe_age_nanoseconds) &&
         in.integer(value.sws_override_remaining_nanoseconds) &&
         in.integer(value.generation) &&
         in.integer(value.pending_failure_action) &&
         in.boolean(value.retransmission_deadline_present) &&
         in.boolean(value.rtt_probe_present) &&
         in.boolean(value.rtt_probe_retransmitted) &&
         in.boolean(value.fast_retransmission_pending) &&
         in.boolean(value.sws_override_deadline_present) &&
         in.boolean(value.nagle_enabled) && in.boolean(value.sack_enabled);
}

void receiver(Writer &out, const ReceiveBufferCheckpoint &value) {
  byte_vector(out, value.storage);
  byte_vector(out, value.received);
  out.integer(value.read_sequence);
  out.integer(value.receive_next);
  out.integer(value.head);
  out.integer(value.recent_sequence);
  out.boolean(value.recent_sequence_present);
}

bool receiver(Reader &in, ReceiveBufferCheckpoint &value) {
  return byte_vector(in, value.storage) && byte_vector(in, value.received) &&
         in.integer(value.read_sequence) && in.integer(value.receive_next) &&
         in.integer(value.head) && in.integer(value.recent_sequence) &&
         in.boolean(value.recent_sequence_present);
}

void receive_window(Writer &out, const ReceiveWindowCheckpoint &value) {
  out.integer(value.capacity);
  out.integer(value.effective_send_mss);
  out.integer(value.advertised);
}

bool receive_window(Reader &in, ReceiveWindowCheckpoint &value) noexcept {
  return in.integer(value.capacity) &&
         in.integer(value.effective_send_mss) &&
         in.integer(value.advertised);
}

void delayed_ack(Writer &out, const DelayedAckCheckpoint &value) {
  out.integer(value.remaining_nanoseconds);
  out.integer(value.data_segments_since_ack);
  out.boolean(value.deadline_present);
}

bool delayed_ack(Reader &in, DelayedAckCheckpoint &value) noexcept {
  return in.integer(value.remaining_nanoseconds) &&
         in.integer(value.data_segments_since_ack) &&
         in.boolean(value.deadline_present);
}

void tuple(Writer &out, const ConnectionTuple &value) {
  out.integer(value.family);
  octet_array(out, value.local_ipv4);
  octet_array(out, value.remote_ipv4);
  octet_array(out, value.local_ipv6);
  octet_array(out, value.remote_ipv6);
  out.integer(value.interface_id);
  out.integer(value.local_port);
  out.integer(value.remote_port);
}

bool tuple(Reader &in, ConnectionTuple &value) noexcept {
  return in.integer(value.family) && octet_array(in, value.local_ipv4) &&
         octet_array(in, value.remote_ipv4) &&
         octet_array(in, value.local_ipv6) &&
         octet_array(in, value.remote_ipv6) &&
         in.integer(value.interface_id) && in.integer(value.local_port) &&
         in.integer(value.remote_port);
}

void connection(Writer &out, const ConnectionCheckpoint &value) {
  tuple(out, value.tuple);
  out.integer(value.policy.maximum_transport_message);
  out.integer(value.policy.receive_capacity);
  out.integer(value.policy.timestamp_offset);
  out.boolean(value.policy.window_scaling);
  out.boolean(value.policy.timestamps);
  out.boolean(value.policy.sack);
  control(out, value.control);
  optional(out, value.local_syn_offer,
           [](Writer &writer, const SynOptionOffer &item) {
             syn_offer(writer, item);
           });
  optional(out, value.peer_syn_options,
           [](Writer &writer, const TypedOptions &item) {
             typed_options(writer, item);
           });
  optional(out, value.negotiated,
           [](Writer &writer, const NegotiatedOptions &item) {
             negotiated(writer, item);
           });
  timestamp(out, value.timestamps);
  optional(out, value.sender, [](Writer &writer, const SenderCheckpoint &item) {
    sender(writer, item);
  });
  optional(out, value.receiver,
           [](Writer &writer, const ReceiveBufferCheckpoint &item) {
             receiver(writer, item);
           });
  optional(out, value.receive_window,
           [](Writer &writer, const ReceiveWindowCheckpoint &item) {
             receive_window(writer, item);
           });
  delayed_ack(out, value.delayed_ack);
  out.integer(value.timestamp_elapsed_nanoseconds);
  out.integer(value.next_token);
  out.boolean(value.timestamp_state_present);
}

bool connection(Reader &in, ConnectionCheckpoint &value) {
  return tuple(in, value.tuple) &&
         in.integer(value.policy.maximum_transport_message) &&
         in.integer(value.policy.receive_capacity) &&
         in.integer(value.policy.timestamp_offset) &&
         in.boolean(value.policy.window_scaling) &&
         in.boolean(value.policy.timestamps) && in.boolean(value.policy.sack) &&
         control(in, value.control) &&
         optional(in, value.local_syn_offer,
                  [](Reader &reader, SynOptionOffer &item) {
                    return syn_offer(reader, item);
                  }) &&
         optional(in, value.peer_syn_options,
                  [](Reader &reader, TypedOptions &item) {
                    return typed_options(reader, item);
                  }) &&
         optional(in, value.negotiated,
                  [](Reader &reader, NegotiatedOptions &item) {
                    return negotiated(reader, item);
                  }) &&
         timestamp(in, value.timestamps) &&
         optional(in, value.sender,
                  [](Reader &reader, SenderCheckpoint &item) {
                    return sender(reader, item);
                  }) &&
         optional(in, value.receiver,
                  [](Reader &reader, ReceiveBufferCheckpoint &item) {
                    return receiver(reader, item);
                  }) &&
         optional(in, value.receive_window,
                  [](Reader &reader, ReceiveWindowCheckpoint &item) {
                    return receive_window(reader, item);
                  }) &&
         delayed_ack(in, value.delayed_ack) &&
         in.integer(value.timestamp_elapsed_nanoseconds) &&
         in.integer(value.next_token) &&
         in.boolean(value.timestamp_state_present);
}

void binding(Writer &out, const EndpointBinding &value) {
  out.integer(value.family);
  octet_array(out, value.ipv4);
  octet_array(out, value.ipv6);
  out.integer(value.interface_id);
  out.integer(value.port);
}

bool binding(Reader &in, EndpointBinding &value) noexcept {
  return in.integer(value.family) && octet_array(in, value.ipv4) &&
         octet_array(in, value.ipv6) && in.integer(value.interface_id) &&
         in.integer(value.port);
}

void resources(Writer &out, const SocketResources &value) {
  out.integer<std::uint64_t>(value.send_buffer_bytes);
  out.integer<std::uint64_t>(value.receive_buffer_bytes);
  out.integer<std::uint64_t>(value.transmission_records);
  out.integer<std::uint64_t>(value.sack_ranges);
}

bool resources(Reader &in, SocketResources &value) noexcept {
  std::uint64_t send{}, receive{}, records{}, ranges{};
  if (!in.integer(send) || !in.integer(receive) || !in.integer(records) ||
      !in.integer(ranges) || send > std::numeric_limits<std::size_t>::max() ||
      receive > std::numeric_limits<std::size_t>::max() ||
      records > std::numeric_limits<std::size_t>::max() ||
      ranges > std::numeric_limits<std::size_t>::max())
    return false;
  value = {.send_buffer_bytes = static_cast<std::size_t>(send),
           .receive_buffer_bytes = static_cast<std::size_t>(receive),
           .transmission_records = static_cast<std::size_t>(records),
           .sack_ranges = static_cast<std::size_t>(ranges)};
  return true;
}

void socket_handle(Writer &out, EndpointSocketHandle value) {
  out.integer(value.index);
  out.integer(value.generation);
}

bool socket_handle(Reader &in, EndpointSocketHandle &value) noexcept {
  return in.integer(value.index) && in.integer(value.generation);
}

void network_error(Writer &out,
                   const transport::Ipv6NetworkError &value) {
  octet_array(out, value.remote);
  out.integer(value.interface_id);
  out.integer(value.parameter);
  out.integer(value.remote_port);
  out.integer(value.type);
  out.integer(value.code);
  out.integer(value.kind);
}

bool network_error(Reader &in,
                   transport::Ipv6NetworkError &value) noexcept {
  return octet_array(in, value.remote) && in.integer(value.interface_id) &&
         in.integer(value.parameter) && in.integer(value.remote_port) &&
         in.integer(value.type) && in.integer(value.code) &&
         in.integer(value.kind) &&
         value.type < packet::icmpv6_informational_type_boundary &&
         value.kind <= transport::Ipv6NetworkErrorKind::unknown;
}

void socket(Writer &out, const EndpointSocketCheckpoint &value) {
  binding(out, value.binding);
  resources(out, value.resources);
  optional(out, value.connection,
           [](Writer &writer, const ConnectionCheckpoint &item) {
             connection(writer, item);
           });
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.accepted.size()));
  for (const auto handle : value.accepted)
    socket_handle(out, handle);
  optional(out, value.listener_index,
           [](Writer &writer, std::uint32_t item) { writer.integer(item); });
  optional(out, value.network_error,
           [](Writer &writer, const transport::Ipv6NetworkError &item) {
             network_error(writer, item);
           });
  out.integer<std::uint64_t>(value.backlog);
  out.integer(value.generation);
  out.boolean(value.occupied);
  out.boolean(value.listener);
  out.boolean(value.queued_for_accept);
}

bool socket(Reader &in, EndpointSocketCheckpoint &value) {
  std::uint32_t accepted{};
  std::uint64_t backlog{};
  if (!binding(in, value.binding) || !resources(in, value.resources) ||
      !optional(in, value.connection,
                [](Reader &reader, ConnectionCheckpoint &item) {
                  return connection(reader, item);
                }) ||
      !in.integer(accepted) ||
      accepted > in.remaining() / 8U)
    return false;
  value.accepted.resize(accepted);
  for (auto &handle : value.accepted)
    if (!socket_handle(in, handle))
      return false;
  const auto u32 = [](Reader &reader, std::uint32_t &item) {
    return reader.integer(item);
  };
  if (!optional(in, value.listener_index, u32) ||
      !optional(in, value.network_error,
                [](Reader &reader, transport::Ipv6NetworkError &item) {
                  return network_error(reader, item);
                }) ||
      !in.integer(backlog) ||
      backlog > std::numeric_limits<std::size_t>::max())
    return false;
  value.backlog = static_cast<std::size_t>(backlog);
  return in.integer(value.generation) && in.boolean(value.occupied) &&
         in.boolean(value.listener) && in.boolean(value.queued_for_accept);
}

} // namespace

std::optional<std::vector<std::uint8_t>>
encode(const EndpointCheckpoint &state) noexcept {
  try {
    if (state.sockets.size() > std::numeric_limits<std::uint32_t>::max())
      return std::nullopt;
    Writer out;
    octet_array(out, state.isn.secret);
    out.integer(state.isn.clock_quanta);
    out.integer<std::uint32_t>(static_cast<std::uint32_t>(state.sockets.size()));
    for (const auto &entry : state.sockets)
      socket(out, entry);
    out.integer(state.ephemeral_cursor);
    out.integer(state.next_endpoint_token);
    return std::move(out).finish();
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  } catch (const std::length_error &) {
    return std::nullopt;
  }
}

std::optional<EndpointCheckpoint>
decode(std::span<const std::uint8_t> bytes) noexcept {
  try {
    Reader in{bytes};
    EndpointCheckpoint state;
    std::uint32_t sockets{};
    if (!octet_array(in, state.isn.secret) ||
        !in.integer(state.isn.clock_quanta) || !in.integer(sockets) ||
        sockets > in.remaining() / 32U)
      return std::nullopt;
    state.sockets.resize(sockets);
    for (auto &entry : state.sockets)
      if (!socket(in, entry))
        return std::nullopt;
    if (!in.integer(state.ephemeral_cursor) ||
        !in.integer(state.next_endpoint_token) || in.remaining() != 0U)
      return std::nullopt;
    return state;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

} // namespace router::transport::tcp::checkpoint
