// Historical DHCPv4 failover draft-12 wire codec.
//
// Responsibility: preserve and validate complete failover messages exchanged
// over modeled TCP port 647. This pure module owns no socket, lease, timer or
// secret. Ordered option occurrences remain borrowed views because BNDUPD can
// carry repeated binding groups whose order has protocol meaning.

#pragma once

#include "router/dhcpv4_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace router::dhcpv4::failover {

inline constexpr std::uint16_t tcp_port = 647U;
inline constexpr std::size_t fixed_header_octets = 12U;
inline constexpr std::size_t maximum_message_octets = 2048U;
inline constexpr std::size_t maximum_client_identifier_octets = 255U;
inline constexpr std::uint8_t version_one_payload_offset = 8U;

enum class MessageType : std::uint8_t {
  pool_request = 1U,
  pool_response = 2U,
  binding_update = 3U,
  binding_ack = 4U,
  connect = 5U,
  connect_ack = 6U,
  update_request_all = 7U,
  update_done = 8U,
  update_request = 9U,
  state = 10U,
  contact = 11U,
  disconnect = 12U,
};

enum class OptionCode : std::uint16_t {
  addresses_transferred = 1U,
  assigned_ip_address = 2U,
  binding_status = 3U,
  client_identifier = 4U,
  client_hardware_address = 5U,
  client_last_transaction_time = 6U,
  client_reply_options = 7U,
  client_request_options = 8U,
  ddns = 9U,
  delayed_service_parameter = 10U,
  hash_bucket_assignment = 11U,
  ip_flags = 12U,
  lease_expiration_time = 13U,
  maximum_unacked_binding_updates = 14U,
  maximum_client_lead_time = 15U,
  message = 16U,
  message_digest = 17U,
  potential_expiration_time = 18U,
  receive_timer = 19U,
  protocol_version = 20U,
  reject_reason = 21U,
  relationship_name = 22U,
  server_flags = 23U,
  server_state = 24U,
  start_time_of_state = 25U,
  tls_reply = 26U,
  tls_request = 27U,
  vendor_class_identifier = 28U,
  vendor_specific_options = 29U,
};

enum class BindingStatus : std::uint8_t {
  free = 1U,
  active = 2U,
  expired = 3U,
  released = 4U,
  abandoned = 5U,
  reset = 6U,
  backup = 7U,
};

enum class ServerState : std::uint8_t {
  startup = 1U,
  normal = 2U,
  communications_interrupted = 3U,
  partner_down = 4U,
  potential_conflict = 5U,
  recover = 6U,
  paused = 7U,
  shutdown = 8U,
  recover_done = 9U,
  resolution_interrupted = 10U,
  conflict_done = 11U,
};

enum class TlsRequest : std::uint8_t {
  disabled = 0U,
  desired = 1U,
  required = 2U,
};

enum class DigestStatus : std::uint8_t {
  accepted,
  missing,
  not_first,
  malformed,
  unsupported_type,
  cryptographic_failure,
  mismatch,
};

struct OptionView {
  std::uint16_t code{};
  std::span<const std::uint8_t> value{};
};

struct MessageView {
  MessageType type{MessageType::contact};
  std::uint8_t payload_offset{};
  std::uint32_t sent_time{};
  std::uint32_t transaction_id{};
  std::span<const std::uint8_t> additional_header{};
  std::span<const std::uint8_t> options{};

  [[nodiscard]] std::optional<OptionView>
  first(std::uint16_t code) const noexcept;
};

enum class DecodeStatus : std::uint8_t {
  accepted,
  truncated_header,
  invalid_length,
  unknown_required_message,
  optional_message_ignored,
  invalid_payload_offset,
  invalid_transaction_id,
  malformed_option,
  too_many_options,
  duplicate_option,
  invalid_message_options,
};

struct DecodeResult {
  DecodeStatus status{DecodeStatus::truncated_header};
  MessageView message{};
  std::size_t option_count{};
};

enum class StreamStatus : std::uint8_t {
  need_more,
  message_ready,
  invalid_length,
  overflow,
};

struct StreamIngestResult {
  StreamStatus status{StreamStatus::need_more};
  std::size_t accepted_octets{};
  std::span<const std::uint8_t> message{};
};

struct StreamDecoderCheckpoint {
  std::vector<std::uint8_t> bytes;
  std::size_t expected{};
  bool ready{};
  bool failed{};
};

// Producer: one established failover TCP socket. Consumer: the relationship
// owner on the same forwarding shard. Capacity: one complete draft message,
// bounded by maximum_message_octets. Ordering: exact TCP byte order. Overflow:
// reject and close the relationship without exposing a partial message.
//
// A decoder deliberately stops after one complete message even when the input
// span also contains bytes from the next one. The caller can then dispatch the
// borrowed view, call consume(), and pass the unaccepted suffix again. This
// keeps the view valid without copying every failover message into a second
// application buffer.
class StreamDecoder final {
public:
  [[nodiscard]] StreamIngestResult
  ingest(std::span<const std::uint8_t> input) noexcept;
  // The relationship owner may borrow a writable view only while a complete
  // message is ready. HMAC-MD5 verification temporarily clears and restores
  // the digest bytes in this owned buffer, so authentication does not require
  // a second maximum-sized message allocation. The view expires at consume().
  [[nodiscard]] std::span<std::uint8_t> mutable_message() noexcept {
    return ready_ ? std::span<std::uint8_t>{storage_}.first(expected_)
                  : std::span<std::uint8_t>{};
  }
  [[nodiscard]] StreamDecoderCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const StreamDecoderCheckpoint &state) noexcept;
  void consume() noexcept;
  [[nodiscard]] std::size_t occupied() const noexcept { return occupied_; }

private:
  std::array<std::uint8_t, maximum_message_octets> storage_{};
  std::size_t occupied_{};
  std::size_t expected_{};
  bool ready_{};
  bool failed_{};
};

// The input starts at the two-octet message length and contains exactly one
// TCP-framed message. The decoder rejects trailing bytes so callers cannot
// accidentally merge adjacent stream messages into one authenticated unit.
[[nodiscard]] DecodeResult
decode(std::span<const std::uint8_t> message) noexcept;

// Draft section 11.1 requires the digest option to be first, type HMAC-MD5,
// and present in every message of a shared-secret relationship. Signing and
// verification temporarily zero only the sixteen digest octets and leave the
// ordered failover message otherwise byte-for-byte unchanged.
[[nodiscard]] DigestStatus
sign_hmac_md5(std::span<std::uint8_t> message,
              std::span<const std::uint8_t> secret) noexcept;
[[nodiscard]] DigestStatus
verify_hmac_md5(std::span<std::uint8_t> message,
                std::span<const std::uint8_t> secret) noexcept;
// Inserts the mandatory first digest TLV into caller-owned spare capacity,
// updates the inclusive draft length and signs the result. Existing options
// retain their order and no allocation is performed.
[[nodiscard]] std::optional<std::size_t>
insert_hmac_md5(std::span<std::uint8_t> storage,
                std::size_t message_octets,
                std::span<const std::uint8_t> secret) noexcept;

class Encoder final {
public:
  explicit Encoder(std::span<std::uint8_t> output) noexcept;

  // Version 1 has no additional header and therefore uses payload offset 8.
  // XIDs remain unique on one TCP connection and responses copy the request
  // XID. Zero is rejected because it weakens replay and response correlation.
  [[nodiscard]] bool begin(MessageType type, std::uint32_t sent_time,
                           std::uint32_t transaction_id) noexcept;
  [[nodiscard]] bool option(std::uint16_t code,
                            std::span<const std::uint8_t> value) noexcept;
  [[nodiscard]] std::span<const std::uint8_t> message() noexcept;

private:
  std::span<std::uint8_t> output_;
  std::size_t occupied_{};
  std::size_t option_count_{};
  bool begun_{};
  bool failed_{};
};

// The endpoint state is deliberately distinct from ServerState. Draft-12
// defines RECOVER-WAIT as a real local state but omits it from the wire
// server-state option registry. Collapsing the two domains would either lose
// the MCLT recovery interlock or invent an undocumented wire number.
enum class State : std::uint8_t {
  startup,
  normal,
  communications_interrupted,
  partner_down,
  potential_conflict,
  recover,
  recover_wait,
  recover_done,
  resolution_interrupted,
  conflict_done,
  paused,
  shutdown,
};

enum class Role : std::uint8_t { primary, secondary };

enum class Responsiveness : std::uint8_t {
  unresponsive,
  renew_responsive,
  responsive,
};

struct Configuration {
  std::string relationship_name;
  Role role{Role::primary};
  std::uint32_t maximum_client_lead_time_seconds{};
  std::uint32_t startup_seconds{};
  std::uint32_t maximum_response_delay_seconds{};
  std::optional<std::uint32_t> safe_period_seconds;
  std::uint16_t maximum_unacked_updates{};
};

enum class NegotiationStatus : std::uint8_t {
  accepted,
  wrong_message,
  missing_required_option,
  malformed_option,
  relationship_mismatch,
  protocol_version_mismatch,
  mclt_mismatch,
  unsupported_tls_request,
};

struct NegotiationParameters {
  // RFC 3074 assigns exactly 256 hash buckets. The draft carries that
  // assignment as a 32-octet bitmap, with one bit for each bucket delegated
  // to the secondary. Keeping the bitmap intact avoids inventing a second
  // representation whose bit numbering might differ from the wire format.
  std::array<std::uint8_t, 32U> secondary_hash_buckets{};
  std::string vendor_class_identifier;
  TlsRequest tls_request{TlsRequest::disabled};
};

struct NegotiatedParameters {
  std::uint32_t maximum_client_lead_time_seconds{};
  std::uint32_t receive_timer_seconds{};
  std::uint32_t maximum_unacked_updates{};
  TlsRequest tls_request{TlsRequest::disabled};
  std::array<std::uint8_t, 32U> secondary_hash_buckets{};
};

// CONNECT is sent only by the primary and includes the complete relationship
// policy. CONNECTACK omits the primary-only MCLT and HBA options. A caller
// tells this validator which direction is expected so accepting an otherwise
// well-formed CONNECTACK as a CONNECT cannot silently weaken negotiation.
[[nodiscard]] NegotiationStatus validate_negotiation(
    const MessageView &message, const Configuration &local, bool reply,
    bool secured_transport, NegotiatedParameters &negotiated) noexcept;

// The supplied vendor identifier and HBA are configuration, not built-in
// product constants. CONNECTACK callers pass reply=true and the accepted TLS
// result, while CONNECT callers pass the primary's configured request.
[[nodiscard]] std::optional<std::size_t> encode_negotiation(
    MessageType type, std::uint32_t sent_time, std::uint32_t transaction_id,
    const Configuration &configuration,
    const NegotiationParameters &parameters, bool secured_transport,
    std::span<std::uint8_t> output) noexcept;

struct StateAdvertisement {
  ServerState state{ServerState::normal};
  bool startup{};
  std::uint32_t started_at{};
};

[[nodiscard]] std::optional<std::size_t> encode_state(
    std::uint32_t sent_time, std::uint32_t transaction_id,
    const StateAdvertisement &state,
    std::span<std::uint8_t> output) noexcept;
[[nodiscard]] std::optional<StateAdvertisement>
parse_state(const MessageView &message) noexcept;

enum class BindingParseStatus : std::uint8_t {
  accepted,
  end,
  wrong_message,
  malformed,
  missing_required_option,
};

struct BindingUpdateView {
  packet::Ipv4 address{};
  BindingStatus status{BindingStatus::free};
  std::span<const std::uint8_t> client_identifier{};
  std::span<const std::uint8_t> client_hardware_address{};
  std::optional<std::uint32_t> lease_expiration_time;
  std::optional<std::uint32_t> potential_expiration_time;
  std::optional<std::uint32_t> client_last_transaction_time;
  std::optional<std::uint32_t> start_time_of_state;
  std::optional<std::uint8_t> reject_reason;
};

struct BindingParseResult {
  BindingParseStatus status{BindingParseStatus::malformed};
  BindingUpdateView update{};
  // Cursor is an offset within MessageView::options. Keeping iteration state
  // outside the borrowed view lets one BNDUPD carry multiple ordered binding
  // transactions without allocating a vector or rescanning earlier groups.
  std::size_t next_offset{};
};

[[nodiscard]] BindingParseResult
next_binding(const MessageView &message, std::size_t offset = 0U) noexcept;

struct BindingUpdate {
  packet::Ipv4 address{};
  BindingStatus status{BindingStatus::free};
  std::span<const std::uint8_t> client_identifier{};
  std::span<const std::uint8_t> client_hardware_address{};
  std::optional<std::uint32_t> lease_expiration_time;
  std::optional<std::uint32_t> potential_expiration_time;
  std::optional<std::uint32_t> client_last_transaction_time;
  std::optional<std::uint32_t> start_time_of_state;
  std::optional<std::uint8_t> reject_reason;
};

// One binding per emitted message is deliberate. The receiver accepts the
// mandatory batched form through next_binding(), while the sender keeps each
// outstanding XID and acknowledgement owner unambiguous.
[[nodiscard]] std::optional<std::size_t> encode_binding(
    MessageType type, std::uint32_t sent_time, std::uint32_t transaction_id,
    const BindingUpdate &binding,
    std::span<std::uint8_t> output) noexcept;
// BNDACK acknowledges every ordered group from one received BNDUPD with the
// same transaction ID. A single response avoids losing later acknowledgements
// when TCP applies send-buffer backpressure between maintenance turns.
[[nodiscard]] std::optional<std::size_t> encode_binding_ack(
    std::uint32_t sent_time, std::uint32_t transaction_id,
    std::span<const BindingUpdateView> bindings,
    std::span<std::uint8_t> output) noexcept;

struct Checkpoint {
  Configuration configuration;
  State state{State::startup};
  std::optional<State> partner_state;
  std::uint32_t state_started_absolute{};
  std::int64_t state_remaining_nanoseconds{-1};
  std::int64_t contact_remaining_nanoseconds{-1};
  std::uint32_t next_transaction_id{1U};
  bool communications_ok{};
  bool update_request_complete{};
};

class Endpoint final {
public:
  using Clock = std::chrono::steady_clock;

  // Preconditions: every timer and bounded update window is explicit. The
  // endpoint does not manufacture implementation-dependent draft defaults.
  // Postcondition: success starts an unresponsive STARTUP relationship whose
  // mutable state belongs exclusively to this object.
  [[nodiscard]] bool configure(Configuration configuration,
                               std::uint32_t absolute_now,
                               Clock::time_point now);
  void communication_changed(bool available, std::uint32_t absolute_now,
                             Clock::time_point now) noexcept;
  void partner_state_changed(State state, std::uint32_t absolute_now,
                             Clock::time_point now) noexcept;
  void update_request_finished(std::uint32_t absolute_now,
                               Clock::time_point now) noexcept;
  [[nodiscard]] bool request_partner_down(std::uint32_t absolute_now,
                                          Clock::time_point now) noexcept;
  void service(std::uint32_t absolute_now, Clock::time_point now) noexcept;

  [[nodiscard]] std::uint32_t allocate_transaction_id() noexcept;
  [[nodiscard]] State state() const noexcept { return state_; }
  [[nodiscard]] std::optional<State> partner_state() const noexcept {
    return partner_state_;
  }
  [[nodiscard]] Responsiveness responsiveness() const noexcept;
  [[nodiscard]] bool communications_ok() const noexcept {
    return communications_ok_;
  }
  [[nodiscard]] Checkpoint checkpoint(Clock::time_point now) const;
  [[nodiscard]] bool restore(const Checkpoint &state,
                             Clock::time_point now) noexcept;

private:
  void evaluate(std::uint32_t absolute_now, Clock::time_point now) noexcept;
  void transition(State state, std::uint32_t absolute_now,
                  Clock::time_point now,
                  std::optional<std::chrono::seconds> duration =
                      std::nullopt) noexcept;

  Configuration configuration_;
  State state_{State::startup};
  std::optional<State> partner_state_;
  Clock::time_point state_deadline_{Clock::time_point::max()};
  Clock::time_point contact_deadline_{Clock::time_point::max()};
  std::uint32_t state_started_absolute_{};
  std::uint32_t next_transaction_id_{1U};
  bool configured_{};
  bool communications_ok_{};
  bool update_request_complete_{};
};

enum class SessionPhase : std::uint8_t {
  disconnected,
  awaiting_connect,
  awaiting_connect_ack,
  synchronizing,
  established,
};

enum class SessionEventKind : std::uint8_t {
  none,
  binding_update,
  binding_ack,
  pool_request,
  pool_response,
  synchronization_requested,
  synchronization_complete,
  partner_state_changed,
  peer_disconnected,
  protocol_error,
};

struct SessionEvent {
  SessionEventKind kind{SessionEventKind::none};
  MessageView message{};
};

struct SessionCheckpoint {
  struct PendingControl {
    MessageType type{MessageType::contact};
    std::uint32_t transaction_id{};
  };

  Configuration configuration;
  NegotiationParameters negotiation;
  Checkpoint endpoint;
  std::vector<PendingControl> pending;
  std::int64_t transmit_remaining_nanoseconds{};
  std::uint32_t synchronization_transaction_id{};
  std::uint32_t send_interval_seconds{};
  SessionPhase phase{SessionPhase::disconnected};
  bool secured_transport{};
};

// Draft-12 application conversation above one modeled TCP connection. Socket
// sequence state, retransmission and routing remain in TcpEndpoint and
// RouterForwarder. This owner handles only failover framing, negotiation,
// state exchange and bounded synchronization ordering.
class Session final {
public:
  using Clock = std::chrono::steady_clock;

  [[nodiscard]] bool configure(Configuration configuration,
                               NegotiationParameters negotiation,
                               bool secured_transport,
                               std::uint32_t absolute_now,
                               Clock::time_point now);
  void transport_connected(std::uint32_t absolute_now,
                           Clock::time_point now) noexcept;
  void transport_closed(std::uint32_t absolute_now,
                        Clock::time_point now) noexcept;
  [[nodiscard]] SessionEvent receive(const MessageView &message,
                                     std::uint32_t absolute_now,
                                     Clock::time_point now) noexcept;
  void service(std::uint32_t absolute_now, Clock::time_point now) noexcept;
  [[nodiscard]] bool finish_synchronization(
      std::uint32_t request_transaction_id) noexcept;
  [[nodiscard]] std::optional<std::size_t>
  prepare_next(std::span<std::uint8_t> output,
               std::uint32_t absolute_now,
               Clock::time_point now) noexcept;

  [[nodiscard]] SessionPhase phase() const noexcept { return phase_; }
  [[nodiscard]] Endpoint &endpoint() noexcept { return endpoint_; }
  [[nodiscard]] const Endpoint &endpoint() const noexcept {
    return endpoint_;
  }
  // TCP sequence and receive queues are checkpointed by the transport owner.
  // This value captures only application framing-independent conversation
  // state, preserving pending control ordering and the keepalive deadline.
  [[nodiscard]] SessionCheckpoint checkpoint(Clock::time_point now) const;
  [[nodiscard]] bool restore(const SessionCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  struct PendingControl {
    MessageType type{MessageType::contact};
    std::uint32_t transaction_id{};
  };

  [[nodiscard]] bool enqueue(MessageType type,
                             std::uint32_t transaction_id = 0U) noexcept;
  void fail(std::uint32_t absolute_now, Clock::time_point now) noexcept;

  Configuration configuration_{};
  NegotiationParameters negotiation_{};
  Endpoint endpoint_{};
  std::array<PendingControl, 16U> pending_{};
  std::size_t pending_head_{};
  std::size_t pending_count_{};
  Clock::time_point last_transmit_{};
  std::uint32_t synchronization_transaction_id_{};
  std::uint32_t send_interval_seconds_{};
  SessionPhase phase_{SessionPhase::disconnected};
  bool configured_{};
  bool secured_transport_{};
};

} // namespace router::dhcpv4::failover
