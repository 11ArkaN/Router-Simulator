// Transactional TCP wire connection for one IP four-tuple. One endpoint shard
// owns all mutable state. It stages a TCB transition, encodes a checksum-valid
// segment into caller memory, and exposes a token committed only after the IP
// and queue owner accepts those bytes. No system socket or peer object exists.

#pragma once

#include "router/tcp_control_block.hpp"
#include "router/tcp_options.hpp"
#include "router/tcp_receive_buffer.hpp"
#include "router/tcp_receive_window.hpp"
#include "router/tcp_sender.hpp"
#include "router/tcp_timers.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::transport::tcp {

struct ConnectionTuple {
  InternetFamily family{InternetFamily::ipv6};
  packet::Ipv4 local_ipv4{};
  packet::Ipv4 remote_ipv4{};
  packet::Ipv6 local_ipv6{};
  packet::Ipv6 remote_ipv6{};
  std::uint64_t interface_id{};
  std::uint16_t local_port{};
  std::uint16_t remote_port{};

  [[nodiscard]] bool operator==(const ConnectionTuple &) const noexcept = default;
};

struct ConnectionOptionPolicy {
  // maximum_transport_message is the family path's current MMS_R. The receive
  // capacity is an owner-provided arena size, so this wire layer imposes no
  // arbitrary stream-length or application-message limit.
  std::uint32_t maximum_transport_message{};
  std::uint32_t receive_capacity{};
  std::uint32_t timestamp_offset{};
  bool window_scaling{true};
  bool timestamps{true};
  bool sack{true};

  [[nodiscard]] bool
  operator==(const ConnectionOptionPolicy &) const noexcept = default;
};

struct ConnectionStorage {
  // Every span belongs to the endpoint allocator owner and outlives the
  // connection. No capacity below is a protocol message limit: it is explicit
  // socket memory, advertised through flow control and replaceable per profile.
  std::span<std::uint8_t> send_bytes;
  std::span<std::uint8_t> receive_bytes;
  std::span<std::uint8_t> receive_bitmap;
  std::span<std::uint8_t> transmit_payload_scratch;
  std::span<TransmissionRecord> transmission_history;
  std::span<SackRange> sack_ranges;
  std::span<SackRange> sack_workspace;
};

struct ConnectionCheckpoint {
  // Tuple and policy are canonical validation keys. The endpoint reconstructs
  // caller-owned arenas first, then restore rejects a checkpoint intended for
  // a different socket or resource profile before touching live byte storage.
  ConnectionTuple tuple;
  ConnectionOptionPolicy policy;
  ControlBlockCheckpoint control;
  std::optional<SynOptionOffer> local_syn_offer;
  std::optional<TypedOptions> peer_syn_options;
  std::optional<NegotiatedOptions> negotiated;
  TimestampCheckpoint timestamps;
  std::optional<SenderCheckpoint> sender;
  std::optional<ReceiveBufferCheckpoint> receiver;
  std::optional<ReceiveWindowCheckpoint> receive_window;
  DelayedAckCheckpoint delayed_ack;
  std::int64_t timestamp_elapsed_nanoseconds{};
  std::uint64_t next_token{};
  bool timestamp_state_present{};
};

enum class ConnectionPrepareStatus : std::uint8_t {
  prepared,
  no_action,
  invalid_connection,
  wrong_state,
  malformed_segment,
  missing_timestamp,
  payload_requires_stream_owner,
  output_too_small,
  pending_transmission,
};

struct PreparedConnectionSegment {
  std::uint64_t token{};
  std::size_t octets{};
  ControlEvent event{ControlEvent::none};
  bool emit{};

  [[nodiscard]] explicit operator bool() const noexcept { return token != 0U; }
};

struct ConnectionPrepareResult {
  ConnectionPrepareStatus status{ConnectionPrepareStatus::no_action};
  PreparedConnectionSegment segment{};
};

class Connection final {
public:
  using Clock = std::chrono::steady_clock;

  Connection(const ConnectionTuple &tuple,
             const ConnectionOptionPolicy &policy,
             const ConnectionStorage &storage,
             Clock::time_point timestamp_origin = Clock::now()) noexcept;

  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] const ConnectionTuple &tuple() const noexcept { return tuple_; }
  [[nodiscard]] bool transmitted(std::uint32_t sequence) const noexcept {
    return sender_ && sender_->transmitted(sequence);
  }
  // maximum_transport_message includes the TCP header but excludes the IP
  // header. Network input may lower it only after the IP owner validates an
  // ICMP quotation for this connection.
  [[nodiscard]] bool reduce_maximum_transport_message(
      std::uint32_t maximum_transport_message) noexcept;
  [[nodiscard]] bool listen() noexcept;

  [[nodiscard]] ConnectionPrepareResult prepare_active_open(
      std::uint32_t initial_sequence, std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_ingress(
      std::span<const std::uint8_t> segment,
      std::uint32_t passive_initial_sequence,
      std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_close(
      std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_deadline(
      std::span<std::uint8_t> output,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::size_t
  write(std::span<const std::uint8_t> bytes,
        Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::size_t
  read(std::span<std::uint8_t> output,
       Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_data(
      std::span<std::uint8_t> output, bool pushed,
      Clock::time_point now = Clock::now()) noexcept;

  // Commit is the only operation that publishes a staged transition. A queue
  // rejection calls discard instead, leaving sequence state, options and RTO
  // exactly as they were before preparation.
  [[nodiscard]] bool commit(
      const PreparedConnectionSegment &prepared,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool discard(const PreparedConnectionSegment &prepared) noexcept;

  [[nodiscard]] State state() const noexcept { return control_.state(); }
  [[nodiscard]] const std::optional<NegotiatedOptions> &
  negotiated_options() const noexcept {
    return negotiated_;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::optional<ConnectionCheckpoint> checkpoint(
      Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(
      const ConnectionCheckpoint &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct PendingTransition {
    ControlBlock control;
    std::optional<SynOptionOffer> local_syn_offer;
    std::optional<TypedOptions> peer_syn_options;
    std::optional<NegotiatedOptions> negotiated;
    TimestampState timestamps;
    std::optional<Sender> sender;
    PreparedTransmission sender_transmission{};
    packet::tcp::Fields emitted_fields{};
    std::uint64_t token{};
    ControlEvent event{ControlEvent::none};
    bool timestamp_state_present{};
    bool sender_transmission_present{};
    bool emitted{};
  };

  [[nodiscard]] SynOptionOffer offer(Clock::time_point now) const noexcept;
  [[nodiscard]] ConnectionPrepareResult stage(
      ControlBlock candidate, const ControlResult &result,
      std::optional<SynOptionOffer> candidate_local_offer,
      std::optional<TypedOptions> candidate_peer_options,
      std::optional<NegotiatedOptions> candidate_negotiated,
      TimestampState candidate_timestamps, bool timestamp_state_present,
      std::span<std::uint8_t> output, Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<std::size_t> encode(
      packet::tcp::Fields fields,
      const std::optional<SynOptionOffer> &local_offer,
      const std::optional<NegotiatedOptions> &negotiated,
      const TimestampState &timestamps, bool timestamp_state_present,
      std::span<const std::uint8_t> payload,
      std::span<std::uint8_t> output, Clock::time_point now) const noexcept;
  [[nodiscard]] bool tuple_valid() const noexcept;
  [[nodiscard]] bool storage_valid() const noexcept;
  void initialize_stream(Clock::time_point now) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_current_ack(
      std::span<std::uint8_t> output, Clock::time_point now) noexcept;
  [[nodiscard]] ConnectionPrepareResult prepare_sender_transmission(
      const PreparedTransmission &transmission,
      std::span<std::uint8_t> output, bool pushed,
      Clock::time_point now) noexcept;

  ConnectionTuple tuple_{};
  ConnectionOptionPolicy policy_{};
  ConnectionStorage storage_{};
  Clock::time_point timestamp_origin_{};
  ControlBlock control_;
  std::optional<SynOptionOffer> local_syn_offer_;
  std::optional<TypedOptions> peer_syn_options_;
  std::optional<NegotiatedOptions> negotiated_;
  TimestampState timestamps_{};
  std::optional<Sender> sender_;
  std::optional<ReceiveBuffer> receiver_;
  std::optional<ReceiveWindow> receive_window_;
  DelayedAcknowledger delayed_ack_{};
  std::optional<PendingTransition> pending_;
  std::uint64_t next_token_{1U};
  bool timestamp_state_present_{};
  bool valid_{};
};

} // namespace router::transport::tcp
