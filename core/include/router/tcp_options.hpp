// Typed TCP option negotiation and RFC 7323 timestamp state. The connection
// owner supplies path limits, receive capacity and monotonic time. This module
// owns no sockets, buffers, random generator, timer thread or packet queue.

#pragma once

#include "router/tcp_packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::transport::tcp {

enum class InternetFamily : std::uint8_t { ipv4, ipv6 };

struct SackBlock {
  std::uint32_t left_edge{};
  std::uint32_t right_edge{};

  [[nodiscard]] bool operator==(const SackBlock &) const noexcept = default;
};

struct TypedOptions {
  std::optional<std::uint16_t> maximum_segment_size;
  std::optional<std::uint8_t> window_scale;
  std::optional<std::uint32_t> timestamp_value;
  std::optional<std::uint32_t> timestamp_echo_reply;
  std::array<SackBlock, 4> sack_blocks{};
  std::uint8_t sack_block_count{};
  bool sack_permitted{};

  [[nodiscard]] bool operator==(const TypedOptions &) const noexcept = default;
};

// The parser interprets every standardized option supported by this stage and
// ignores well-formed unknown kinds as RFC 9293 requires. A null result means
// malformed bytes or an internally invalid SACK block, never an unknown kind.
[[nodiscard]] std::optional<TypedOptions>
parse_typed_options(std::span<const std::uint8_t> options) noexcept;

struct SynOptionOffer {
  std::uint16_t receive_mss{};
  std::uint8_t receive_window_shift{};
  bool offer_window_scale{};
  bool offer_timestamps{};
  bool offer_sack{};
  std::uint32_t timestamp_value{};
  // A SYN carries zero. A SYN,ACK echoes the TSval received in the initiating
  // SYN as RFC 7323 requires; keeping it in the offer prevents the wire encoder
  // from reaching into peer or connection state.
  std::uint32_t timestamp_echo_reply{};

  [[nodiscard]] bool operator==(const SynOptionOffer &) const noexcept = default;
};

// maximum_transport_message is the IP-layer MMS_R value from RFC 1122, not a
// guessed Ethernet MTU. The receive arena determines window scaling. The
// returned MSS excludes only the fixed 20-octet TCP header per RFC 9293.
[[nodiscard]] std::optional<SynOptionOffer>
make_syn_offer(std::uint32_t maximum_transport_message,
               std::uint32_t receive_capacity, bool window_scale,
               bool timestamps, bool sack,
               std::uint32_t timestamp_value) noexcept;

// Writes an unpadded SYN option sequence. The packet codec owns final 32-bit
// alignment. SYN-ACK callers must first suppress WS and TS if the initial SYN
// did not offer them, as required by RFC 7323.
[[nodiscard]] std::optional<std::size_t>
encode_syn_options(std::span<std::uint8_t> output,
                   const SynOptionOffer &offer) noexcept;

struct NegotiatedOptions {
  std::uint32_t send_mss{};
  std::uint8_t send_window_shift{};
  std::uint8_t receive_window_shift{};
  bool window_scaling{};
  bool timestamps{};
  bool sack{};

  [[nodiscard]] bool
  operator==(const NegotiatedOptions &) const noexcept = default;
};

// local_offer is what this endpoint actually placed in its SYN or SYN-ACK.
// peer_syn is the typed options received from the peer's SYN. Both offers are
// required for WS, timestamps and SACK; absent MSS selects the family default.
[[nodiscard]] NegotiatedOptions
negotiate_options(InternetFamily family, const SynOptionOffer &local_offer,
                  const TypedOptions &peer_syn) noexcept;

[[nodiscard]] constexpr std::uint32_t
default_send_mss(InternetFamily family) noexcept {
  return family == InternetFamily::ipv4 ? 536U : 1220U;
}

// Computes RFC 9293 Eff.snd.MSS for one concrete segment. TCP and IP option
// sizes are passed per packet because timestamps or extension headers can vary.
[[nodiscard]] std::uint32_t
effective_send_mss(std::uint32_t negotiated_send_mss,
                   std::uint32_t maximum_transport_message,
                   std::uint32_t tcp_header_octets,
                   std::uint32_t ip_option_octets) noexcept;

[[nodiscard]] std::uint32_t decode_peer_window(
    std::uint16_t wire_window, bool syn_segment,
    const NegotiatedOptions &options) noexcept;
[[nodiscard]] std::uint16_t encode_receive_window(
    std::uint32_t receive_window, bool syn_segment,
    const NegotiatedOptions &options) noexcept;

enum class TimestampAccept : std::uint8_t {
  accepted,
  missing_required,
  stale
};

struct TimestampCheckpoint {
  std::uint32_t recent{};
  std::uint32_t last_ack_sent{};
  std::int64_t recent_age_nanoseconds{};
  bool negotiated{};
  bool recent_present{};
};

class TimestampState final {
public:
  using Clock = std::chrono::steady_clock;

  explicit TimestampState(bool negotiated = false) noexcept
      : negotiated_(negotiated) {}

  // RST bypasses PAWS. A negotiated non-RST segment without TSopt is silently
  // rejected but does not abort the connection. sequence is SEG.SEQ.
  [[nodiscard]] TimestampAccept
  accept(bool rst, std::optional<std::uint32_t> timestamp,
         std::uint32_t sequence, Clock::time_point now) noexcept;

  // The owner calls this only after its ACK is admitted to the packet path.
  // Doing so earlier could let an unsent ACK alter later timestamp selection.
  void acknowledge_sent(std::uint32_t acknowledgment) noexcept {
    last_ack_sent_ = acknowledgment;
  }

  [[nodiscard]] std::uint32_t echo_reply() const noexcept {
    return recent_present_ ? recent_ : 0U;
  }
  [[nodiscard]] bool negotiated() const noexcept { return negotiated_; }

  [[nodiscard]] TimestampCheckpoint
  checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const TimestampCheckpoint &state,
                             Clock::time_point now) noexcept;

private:
  // RFC 7323 requires invalidation after more than 24 days of idleness so a
  // wrapped peer timestamp cannot freeze a long-lived connection forever.
  static constexpr auto maximum_recent_age = std::chrono::hours{24 * 24};

  std::uint32_t recent_{};
  std::uint32_t last_ack_sent_{};
  Clock::time_point recent_updated_at_{};
  bool negotiated_{};
  bool recent_present_{};
};

// Timestamp values use a monotonic millisecond clock plus a connection-private
// offset. The caller derives that offset from a secret PRF, never wall time.
[[nodiscard]] std::uint32_t
timestamp_value(std::chrono::steady_clock::time_point now,
                std::chrono::steady_clock::time_point origin,
                std::uint32_t connection_offset) noexcept;

[[nodiscard]] std::array<std::uint8_t, 10>
encode_timestamp_option(std::uint32_t value, std::uint32_t echo) noexcept;

// Encodes one RFC 2018 SACK option without padding. At most four blocks fit in
// the 40-octet TCP option area. The caller orders blocks by receiver priority.
[[nodiscard]] std::optional<std::size_t>
encode_sack_option(std::span<std::uint8_t> output,
                   std::span<const SackBlock> blocks) noexcept;

} // namespace router::transport::tcp
