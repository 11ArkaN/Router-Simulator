// RFC 6926 and RFC 7724 DHCPv4 Leasequery TCP framing. The TCP endpoint owns
// connection state and byte delivery. This codec owns only one bounded stream
// reassembly buffer and emits complete DHCPv4 message views to the service
// owner. It never opens sockets or mutates the lease repository.

#pragma once

#include "router/dhcpv4_lease.hpp"
#include "router/dhcpv4_packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv4::leasequery {

inline constexpr std::size_t frame_prefix_octets = 2U;

enum class StreamStatus : std::uint8_t {
  need_more,
  message_ready,
  malformed_length,
  receive_overflow,
};

struct StreamResult {
  StreamStatus status{StreamStatus::need_more};
  std::span<const std::uint8_t> message{};
  // Number of input octets accepted during this call. A TCP read may contain
  // several framed messages; the caller advances by this value, consumes a
  // ready message, then presents the remaining bytes again.
  std::size_t accepted_octets{};
};

struct StreamDecoderCheckpoint {
  // Only occupied TCP bytes are portable state. A fixed maximum-sized array
  // here would place roughly 64 KiB in every temporary checkpoint value and
  // can overflow a 1 MiB WebAssembly worker stack during nested serialization.
  std::vector<std::uint8_t> storage;
  std::size_t occupied{};
  std::size_t complete_octets{};
  bool malformed{};
};

// Producer: one established TCP socket. Consumer: its DHCP Leasequery session.
// Capacity: one maximum RFC 6926 message plus its two-byte prefix. Ordering:
// exact TCP byte order. Overflow: reject the connection before any query state
// mutation. Memory: one owner thread calls ingest, take and reset.
class StreamDecoder final {
public:
  // Ingest accepts any TCP segmentation, including a split length prefix and
  // multiple DHCP messages in one read. It consumes at most one frame per
  // call. The returned view remains valid until consume() or reset() is called.
  [[nodiscard]] StreamResult
  ingest(std::span<const std::uint8_t> bytes) noexcept;
  void consume() noexcept;
  void reset() noexcept;
  [[nodiscard]] StreamDecoderCheckpoint checkpoint() const;
  [[nodiscard]] bool
  restore(const StreamDecoderCheckpoint &state) noexcept;
  [[nodiscard]] std::size_t pending_octets() const noexcept {
    return occupied_;
  }

private:
  [[nodiscard]] StreamResult current() const noexcept;

  std::array<std::uint8_t,
             packet::dhcpv4::maximum_message_octets + frame_prefix_octets>
      storage_{};
  std::size_t occupied_{};
  std::size_t complete_octets_{};
  bool malformed_{};
};

// Prefixes exactly one complete DHCPv4 message with its unsigned network-order
// length. The caller supplies stream output owned by the TCP send queue.
[[nodiscard]] std::optional<std::size_t>
encode_frame(std::span<const std::uint8_t> message,
             std::span<std::uint8_t> output) noexcept;

enum class RequestKind : std::uint8_t {
  bulk,
  active,
  tls,
};

enum class SelectorKind : std::uint8_t {
  all_configured,
  hardware_address,
  client_identifier,
  remote_identifier,
  relay_identifier,
};

struct RequestView {
  RequestKind kind{RequestKind::bulk};
  SelectorKind selector{SelectorKind::all_configured};
  std::uint32_t transaction_id{};
  std::optional<std::uint32_t> query_start_time{};
  std::optional<std::uint32_t> query_end_time{};
  std::array<std::uint8_t, 255U> selector_value{};
  std::array<std::uint8_t, 255U> requested_options{};
  std::uint16_t selector_octets{};
  std::uint16_t requested_option_octets{};
  std::uint8_t hardware_type{};
};

enum class RequestParseStatus : std::uint8_t {
  accepted,
  malformed,
  not_allowed,
};

struct RequestParseResult {
  RequestParseStatus status{RequestParseStatus::malformed};
  RequestView request{};
};

// Validates the common RFC 6926 and RFC 7724 restrictions that apply before a
// query can acquire repository state. Primary query selectors remain available
// through the borrowed packet view and are evaluated by the server owner.
[[nodiscard]] RequestParseResult
parse_request_result(std::span<const std::uint8_t> message) noexcept;
[[nodiscard]] std::optional<RequestView>
parse_request(std::span<const std::uint8_t> message) noexcept;

enum class StatusCode : std::uint16_t {
  success = 0U,
  unspecified_failure = 1U,
  query_terminated = 2U,
  malformed_query = 3U,
  not_allowed = 4U,
  data_missing = 5U,
  connection_active = 6U,
  catch_up_complete = 7U,
  tls_connection_refused = 8U,
};

// These wire values are the RFC 6926 dhcp-state registry, not the internal
// repository enum. The translation remains explicit so future failover states
// cannot accidentally leak their C++ ordinal onto the network.
enum class WireBindingState : std::uint8_t {
  available = 1U,
  active = 2U,
  expired = 3U,
  released = 4U,
  abandoned = 5U,
  reset = 6U,
  remote = 7U,
  transitioning = 8U,
};

struct BindingReplyInput {
  const Lease *lease{};
  const Pool *pool{};
  packet::Ipv4 address{};
  packet::Ipv4 server_identifier{};
  std::uint32_t transaction_id{};
  std::uint32_t base_time{};
  std::span<const std::uint8_t> requested_options{};
  LeaseRepository::Clock::time_point now{};
  bool include_server_identifier{};
  bool active_query{};
};

// Encodes one RFC 6926/7724 reply message without TCP framing. lease==nullptr
// describes an address controlled by the server but currently unassigned.
[[nodiscard]] std::optional<std::size_t>
encode_binding_reply(const BindingReplyInput &input,
                     std::span<std::uint8_t> output) noexcept;

// DONE terminates Bulk Leasequery. STATUS marks Active catch-up, keepalive and
// TLS negotiation states. Text is optional status detail and is never sourced
// from untrusted packet bytes.
[[nodiscard]] std::optional<std::size_t>
encode_status_reply(RequestKind kind, std::uint32_t transaction_id,
                    StatusCode status, std::uint32_t base_time,
                    std::span<const std::uint8_t> text,
                    std::span<std::uint8_t> output) noexcept;

[[nodiscard]] bool matches(const RequestView &request, const Lease &lease,
                           std::uint32_t base_time,
                           LeaseRepository::Clock::time_point now) noexcept;

} // namespace router::dhcpv4::leasequery
