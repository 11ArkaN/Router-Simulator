// RFC 8156 DHCPv6 failover wire codec and endpoint state owner.
//
// Responsibility: validate and encode failover messages carried by the TCP
// owner, and apply externally observed communication and administrative events
// to one relationship state machine. The module owns no socket, lease database,
// wall clock or CLI state. Callers supply absolute RFC time and steady-clock
// deadlines. Dependency direction is protocol primitives only.

#pragma once

#include "router/dhcpv6_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::dhcpv6::failover {

inline constexpr std::uint16_t tcp_port = 647U;
inline constexpr std::size_t header_octets = 8U;
inline constexpr std::size_t frame_prefix_octets = 2U;
// RFC 5460 framing uses one unsigned 16-bit body length. The implementation
// accepts that entire protocol domain instead of inventing a smaller product
// limit which could reject a valid resynchronization message.
inline constexpr std::size_t maximum_message_octets = 0xffffU;

enum class MessageType : std::uint8_t {
  binding_update = 24U,
  binding_reply = 25U,
  pool_request = 26U,
  pool_response = 27U,
  update_request = 28U,
  update_request_all = 29U,
  update_done = 30U,
  connect = 31U,
  connect_reply = 32U,
  disconnect = 33U,
  state = 34U,
  contact = 35U,
};

enum class OptionCode : std::uint16_t {
  binding_status = 114U,
  connect_flags = 115U,
  dns_removal_info = 116U,
  dns_host_name = 117U,
  dns_zone_name = 118U,
  dns_flags = 119U,
  expiration_time = 120U,
  maximum_unacked_binding_updates = 121U,
  maximum_client_lead_time = 122U,
  partner_lifetime = 123U,
  partner_lifetime_sent = 124U,
  partner_down_time = 125U,
  partner_raw_client_last_transaction_time = 126U,
  protocol_version = 127U,
  keepalive_time = 128U,
  reconfigure_data = 129U,
  relationship_name = 130U,
  server_flags = 131U,
  server_state = 132U,
  start_time_of_state = 133U,
  state_expiration_time = 134U,
};

enum class BindingStatus : std::uint8_t {
  reserved = 0U,
  active = 1U,
  expired = 2U,
  released = 3U,
  pending_free = 4U,
  free = 5U,
  free_backup = 6U,
  abandoned = 7U,
  reset = 8U,
};

struct OptionView {
  std::uint16_t code{};
  std::span<const std::uint8_t> value{};
};

struct MessageView {
  MessageType type{MessageType::contact};
  std::uint32_t transaction_id{};
  std::uint32_t sent_time{};
  std::span<const std::uint8_t> options{};

  // Returns the first occurrence. Message-specific validation separately
  // rejects singleton duplicates, so this helper never hides ambiguity.
  [[nodiscard]] std::optional<OptionView>
  first(std::uint16_t code) const noexcept;
};

enum class DecodeStatus : std::uint8_t {
  accepted,
  truncated_header,
  unknown_message_type,
  malformed_option,
  too_many_options,
  invalid_transaction_id,
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

// Producer: one established RFC 8156 TCP socket. Consumer: its relationship
// owner. Capacity: the complete 16-bit RFC 5460 message domain. Ordering:
// exact TCP byte order. Overflow: close the relationship before dispatching a
// partial message. Backpressure is supplied by TCP receive-window ownership,
// not by growing this application buffer.
class StreamDecoder final {
public:
  [[nodiscard]] StreamIngestResult
  ingest(std::span<const std::uint8_t> input) noexcept;
  [[nodiscard]] StreamDecoderCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const StreamDecoderCheckpoint &state) noexcept;
  void consume() noexcept;

private:
  std::array<std::uint8_t, maximum_message_octets> storage_{};
  std::size_t occupied_{};
  std::size_t expected_{};
  bool ready_{};
  bool failed_{};
};

// Preconditions: payload is exactly one frame body after RFC 5460 framing.
// Postcondition: accepted means every TLV boundary and message-specific
// singleton rule was checked without retaining a pointer beyond payload.
[[nodiscard]] DecodeResult
decode(std::span<const std::uint8_t> payload) noexcept;

class Encoder final {
public:
  explicit Encoder(std::span<std::uint8_t> output) noexcept;

  // begin writes the eight-octet RFC 8156 header. Initiating exchanges require
  // a nonzero unique transaction ID. Reply kinds require the ID copied from
  // the triggering request.
  [[nodiscard]] bool begin(MessageType type, std::uint32_t transaction_id,
                           std::uint32_t sent_time) noexcept;
  [[nodiscard]] bool option(std::uint16_t code,
                            std::span<const std::uint8_t> value) noexcept;
  [[nodiscard]] std::span<const std::uint8_t> message() const noexcept;

private:
  std::span<std::uint8_t> output_;
  std::size_t occupied_{};
  std::size_t option_count_{};
  bool begun_{};
  bool failed_{};
};

// Prefixes one validated message with the two-octet RFC 5460 TCP length.
[[nodiscard]] std::optional<std::size_t>
frame(std::span<const std::uint8_t> message,
      std::span<std::uint8_t> output) noexcept;

enum class Role : std::uint8_t { primary, secondary };

enum class State : std::uint8_t {
  startup = 1U,
  normal = 2U,
  communications_interrupted = 3U,
  partner_down = 4U,
  potential_conflict = 5U,
  recover = 6U,
  recover_wait = 7U,
  recover_done = 8U,
  resolution_interrupted = 9U,
  conflict_done = 10U,
};

enum class Responsiveness : std::uint8_t {
  unresponsive,
  renew_responsive,
  responsive,
};

struct Configuration {
  std::string relationship_name;
  Role role{Role::primary};
  std::uint32_t maximum_client_lead_time_seconds{};
  std::uint32_t keepalive_seconds{};
  std::uint32_t maximum_response_delay_seconds{};
  std::optional<std::uint32_t> auto_partner_down_seconds;
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
  unsupported_connect_flags,
};

struct NegotiatedParameters {
  std::uint32_t maximum_client_lead_time_seconds{};
  std::uint32_t keepalive_seconds{};
  std::uint32_t maximum_unacked_updates{};
  std::uint16_t connect_flags{};
};

// CONNECT and CONNECTREPLY use the same mandatory negotiation set. The
// secondary accepts the primary's MCLT; the primary requires CONNECTREPLY to
// echo it exactly. The relationship name is required here because this runtime
// permits several named relationships between one address pair and therefore
// cannot use RFC 8156's single-relationship omission shortcut.
[[nodiscard]] NegotiationStatus validate_negotiation(
    const MessageView &message, const Configuration &local,
    bool reply, NegotiatedParameters &negotiated) noexcept;

// The caller supplies RFC 8156 absolute time and one bounded output arena.
// connect_reply copies the CONNECT transaction ID; CONNECT obtains its ID from
// Endpoint::allocate_transaction_id().
[[nodiscard]] std::optional<std::size_t> encode_negotiation(
    MessageType type, std::uint32_t transaction_id,
    std::uint32_t sent_time, const Configuration &configuration,
    std::uint16_t connect_flags, std::span<std::uint8_t> output) noexcept;

struct StateAdvertisement {
  State state{State::startup};
  std::uint8_t flags{};
  std::uint32_t started_at{};
  std::optional<std::uint32_t> partner_down_at;
};

[[nodiscard]] std::optional<std::size_t> encode_state(
    std::uint32_t transaction_id, std::uint32_t sent_time,
    const StateAdvertisement &state,
    std::span<std::uint8_t> output) noexcept;
[[nodiscard]] std::optional<StateAdvertisement>
parse_state(const MessageView &message) noexcept;

enum class BindingParseStatus : std::uint8_t {
  accepted,
  wrong_message,
  malformed,
  missing_required_option,
  resource_exhausted,
};

enum class IdentityAssociationType : std::uint8_t {
  non_temporary,
  temporary,
  delegated_prefix,
  unassociated_prefix,
};

struct BindingUpdateView {
  // client_identifier borrows the decoded message. It is empty only for an
  // unassociated delegable prefix carried directly as OPTION_IAPREFIX.
  std::span<const std::uint8_t> client_identifier{};
  packet::Ipv6 value{};
  IdentityAssociationType association{
      IdentityAssociationType::non_temporary};
  BindingStatus status{BindingStatus::reserved};
  std::uint32_t iaid{};
  std::uint32_t t1{};
  std::uint32_t t2{};
  std::uint32_t preferred_lifetime{};
  std::uint32_t valid_lifetime{};
  std::uint32_t base_time{};
  std::uint32_t start_time_of_state{};
  std::optional<std::uint32_t> state_expiration_time;
  std::optional<std::uint32_t> client_last_transaction_time;
  std::optional<std::uint32_t> partner_lifetime;
  std::optional<std::uint32_t> partner_raw_client_last_transaction_time;
  std::optional<std::uint32_t> expiration_time;
  std::uint8_t prefix_length{128U};
};

struct BindingParseResult {
  BindingParseStatus status{BindingParseStatus::malformed};
  std::size_t bindings{};
};

// RFC 8156 permits several IAs and resources inside one CLIENT_DATA option.
// The caller supplies fixed storage so a peer cannot cause an unbounded vector
// allocation. resource_exhausted means the message is well formed so far but
// contains more resources than the configured application budget.
[[nodiscard]] BindingParseResult parse_bindings(
    const MessageView &message,
    std::span<BindingUpdateView> output) noexcept;

struct BindingUpdate {
  std::span<const std::uint8_t> client_identifier{};
  packet::Ipv6 value{};
  IdentityAssociationType association{
      IdentityAssociationType::non_temporary};
  BindingStatus status{BindingStatus::reserved};
  std::uint32_t iaid{};
  std::uint32_t t1{};
  std::uint32_t t2{};
  std::uint32_t preferred_lifetime{};
  std::uint32_t valid_lifetime{};
  std::uint32_t base_time{};
  std::uint32_t start_time_of_state{};
  std::optional<std::uint32_t> state_expiration_time;
  std::optional<std::uint32_t> client_last_transaction_time;
  std::optional<std::uint32_t> partner_lifetime;
  std::optional<std::uint32_t> partner_raw_client_last_transaction_time;
  std::optional<std::uint32_t> expiration_time;
  std::uint8_t prefix_length{128U};
};

// One resource per outbound BNDUPD keeps XID acknowledgement ownership
// unambiguous. parse_bindings still accepts every RFC-valid multi-IA peer
// message, so this sender policy does not narrow interoperability.
[[nodiscard]] std::optional<std::size_t> encode_binding(
    MessageType type, std::uint32_t transaction_id,
    std::uint32_t sent_time, const BindingUpdate &binding,
    std::span<std::uint8_t> output) noexcept;

// RFC 8156 permits one BNDUPD to carry several CLIENT_DATA or unassociated
// prefix resources. The reply echoes every accepted binding in the same
// transaction so the sender cannot mistake a partial repository commit for a
// complete acknowledgement. Input views are borrowed only for this call.
[[nodiscard]] std::optional<std::size_t> encode_binding_reply(
    std::uint32_t transaction_id, std::uint32_t sent_time,
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

  // A relationship is rejected unless every negotiated resource and timer is
  // explicit. No protocol default is invented in this module.
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
  awaiting_connect_reply,
  synchronizing,
  established,
};

enum class SessionEventKind : std::uint8_t {
  none,
  binding_update,
  binding_reply,
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
  Checkpoint endpoint;
  std::vector<PendingControl> pending;
  std::int64_t transmit_remaining_nanoseconds{};
  std::uint32_t synchronization_transaction_id{};
  std::uint16_t connect_flags{};
  SessionPhase phase{SessionPhase::disconnected};
};

// This object owns the failover application conversation above TCP. It does
// not own a socket and cannot send to another device. RouterForwarder supplies
// bytes received from its modeled TcpEndpoint and transmits each encoded result
// through the ordinary IPv6 FIB, ND, queue and link path.
class Session final {
public:
  using Clock = std::chrono::steady_clock;

  [[nodiscard]] bool configure(Configuration configuration,
                               std::uint16_t connect_flags,
                               std::uint32_t absolute_now,
                               Clock::time_point now);
  void transport_connected(std::uint32_t absolute_now,
                           Clock::time_point now) noexcept;
  void transport_closed(std::uint32_t absolute_now,
                        Clock::time_point now) noexcept;

  // message borrows the stream decoder. The returned event is valid only until
  // that decoder consumes its current frame.
  [[nodiscard]] SessionEvent receive(const MessageView &message,
                                     std::uint32_t absolute_now,
                                     Clock::time_point now) noexcept;
  void service(std::uint32_t absolute_now, Clock::time_point now) noexcept;

  // A synchronization owner calls this only after every requested binding
  // update has been acknowledged. UPDDONE then carries the original request
  // XID and cannot race ahead of the lease repository.
  [[nodiscard]] bool finish_synchronization(
      std::uint32_t request_transaction_id) noexcept;

  // Returns one unframed RFC 8156 message. The TCP adapter applies RFC 5460
  // framing exactly once before writing it to a stream.
  [[nodiscard]] std::optional<std::size_t>
  prepare_next(std::span<std::uint8_t> output,
               std::uint32_t absolute_now,
               Clock::time_point now) noexcept;

  [[nodiscard]] SessionPhase phase() const noexcept { return phase_; }
  [[nodiscard]] Endpoint &endpoint() noexcept { return endpoint_; }
  [[nodiscard]] const Endpoint &endpoint() const noexcept {
    return endpoint_;
  }
  // Socket sequence and retransmission queues have a separate transport
  // checkpoint. This captures the RFC 8156 application conversation and its
  // pending control-message order without duplicating TCP bytes.
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
  Endpoint endpoint_{};
  std::array<PendingControl, 16U> pending_{};
  std::size_t pending_head_{};
  std::size_t pending_count_{};
  Clock::time_point last_transmit_{};
  std::uint32_t synchronization_transaction_id_{};
  std::uint16_t connect_flags_{};
  SessionPhase phase_{SessionPhase::disconnected};
  bool configured_{};
};

} // namespace router::dhcpv6::failover
