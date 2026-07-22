// Endpoint-only IPv6 fragmentation and bounded destination reassembly. Routers
// never call the source encoder. One endpoint owner mutates each reassembly
// table, so no locks or cross-shard pointers are present in this module.

#pragma once

#include "router/packet.hpp"

#include <array>
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::packet {

struct Ipv6FragmentBatch {
  // This compatibility batch is deliberately limited to a source packet that
  // already fits one Frame. Full-size transport datagrams use the streaming
  // sink below, avoiding an array of roughly fifty-four jumbo Frame objects.
  static constexpr std::size_t minimum_fragment_payload =
      ((ipv6_minimum_link_mtu - ipv6_header_octets -
        ipv6_fragment_header_octets) /
       ipv6_fragment_offset_unit_octets) *
      ipv6_fragment_offset_unit_octets;
  static constexpr std::size_t maximum_fragment_count =
      (maximum_frame_octets + minimum_fragment_payload - 1U) /
      minimum_fragment_payload;
  std::array<Frame, maximum_fragment_count> frames{};
  std::uint8_t count{};
};

// The streaming path can fragment a complete ordinary IPv6 datagram rather
// than only a Frame-sized packet. This count sizes owner-local pointer and
// descriptor batches, never a second array of jumbo Frame values.
inline constexpr std::size_t maximum_ipv6_datagram_fragments =
    (maximum_ipv6_payload_octets +
     Ipv6FragmentBatch::minimum_fragment_payload - 1U) /
    Ipv6FragmentBatch::minimum_fragment_payload;

// Preconditions: packet is a valid, unfragmented IPv6 Ethernet frame and mtu
// is an IPv6 network-layer MTU. Returns nullopt for a packet that does not need
// fragmentation or cannot be represented without violating RFC 8200.
[[nodiscard]] std::optional<Ipv6FragmentBatch>
fragment_ipv6(const Frame &packet, std::uint16_t mtu,
              std::uint32_t identification) noexcept;

using Ipv6FragmentSink = bool (*)(void *context,
                                  const Frame &fragment) noexcept;
using Ipv6FragmentAdmission = bool (*)(void *context,
                                       std::size_t frames) noexcept;

// Computes source-fragment count without emitting bytes. A local egress owner
// uses this value to admit the complete datagram before its first fragment is
// published. nullopt has the same malformed, already-small or invalid-MTU
// meaning as fragment_ipv6_datagram.
[[nodiscard]] std::optional<std::size_t>
ipv6_fragment_count(std::span<const std::uint8_t> packet,
                    std::uint16_t mtu) noexcept;

// Streams each fragment before constructing the next one. `packet` starts at
// an Ethernet header and may contain the complete ordinary 65535-octet IPv6
// payload, even when it exceeds Frame. A false sink result stops generation so
// queue overload cannot silently discard a middle fragment and emit a suffix.
// The returned count is present only when fragmentation and every sink call
// succeeded. Transit routers must never call this source-only function. A
// router-local UDP or TCP endpoint is an originating source and uses it under
// the same whole-batch admission contract as a host.
[[nodiscard]] std::optional<std::size_t> fragment_ipv6_datagram(
    std::span<const std::uint8_t> packet, std::uint16_t mtu,
    std::uint32_t identification, void *context,
    Ipv6FragmentSink sink) noexcept;

enum class Ipv6ReassemblyStatus : std::uint8_t {
  not_fragment,
  incomplete,
  complete,
  atomic,
  malformed,
  overlap,
  resource_exhausted
};

struct Ipv6ReassemblyResult {
  Ipv6ReassemblyStatus status{Ipv6ReassemblyStatus::not_fragment};
  // The view borrows table-owned completion storage and remains valid only
  // until the next non-const operation on that same table. This keeps a legal
  // 65 KiB datagram off the Wasm stack and avoids packet-path allocation.
  std::span<const std::uint8_t> packet{};
};

struct Ipv6ReassemblyCheckpoint {
  // Both payload bytes and their acceptance bitmap are persisted. Rebuilding
  // the bitmap from only a byte count would incorrectly turn out-of-order gaps
  // into received data after restore and weaken RFC 5722 overlap detection.
  Ipv6 source{};
  Ipv6 destination{};
  Frame first_fragment{};
  // Checkpoints retain only the written prefix and a packed acceptance bitmap.
  // Runtime slots stay preallocated, while inactive persisted state costs no
  // fixed 65 KiB value and cannot overflow a caller's stack during copying.
  std::vector<std::uint8_t> fragmentable;
  std::vector<std::uint8_t> received;
  std::int64_t remaining_nanoseconds{};
  std::uint32_t identification{};
  std::uint16_t fragment_header_offset{};
  std::uint16_t previous_next_header_offset{};
  std::uint16_t final_size{};
  std::uint8_t fragment_next_header{};
  bool have_first{};
  bool have_last{};
};

class Ipv6ReassemblyTable final {
public:
  using Clock = std::chrono::steady_clock;
  // Each active slot owns a complete ordinary IPv6 payload buffer and the
  // table owns one assembled Ethernet datagram buffer. Bitmaps and vector
  // control words are inline and therefore accounted by sizeof(table).
  static constexpr std::size_t payload_arena_allocation_bytes =
      device_catalog::ipv6_reassembly_entries_per_endpoint *
          maximum_ipv6_payload_octets +
      maximum_ethernet_ipv6_datagram_octets;

  // Four profile-bounded slots and one completion buffer are allocated once at
  // owner construction. accept(), expire() and restore() never allocate.
  Ipv6ReassemblyTable();

  // Producer and consumer are one endpoint transport owner. A completed or
  // rejected datagram frees its slot in the same turn. Oldest state is never
  // evicted to hide resource exhaustion from the caller.
  [[nodiscard]] Ipv6ReassemblyResult
  accept(const Frame &fragment, Clock::time_point now = Clock::now()) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;
  void discard_all() noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::size_t active() const noexcept;
  [[nodiscard]] std::vector<Ipv6ReassemblyCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const std::vector<Ipv6ReassemblyCheckpoint> &state) noexcept;
  [[nodiscard]] bool restore(
      const std::vector<Ipv6ReassemblyCheckpoint> &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Entry {
    Ipv6 source{};
    Ipv6 destination{};
    Frame first_fragment{};
    std::vector<std::uint8_t> fragmentable;
    std::bitset<maximum_ipv6_payload_octets> received{};
    Clock::time_point expires{};
    std::uint32_t identification{};
    std::uint16_t fragment_header_offset{};
    std::uint16_t previous_next_header_offset{};
    std::uint32_t extent{};
    std::uint16_t final_size{};
    std::uint8_t fragment_next_header{};
    bool occupied{};
    bool have_first{};
    bool have_last{};
  };

  [[nodiscard]] Entry *find(const Ipv6View &view) noexcept;
  [[nodiscard]] Entry *allocate(const Ipv6View &view,
                                Clock::time_point now) noexcept;
  [[nodiscard]] std::span<const std::uint8_t>
  assemble(const Entry &entry) noexcept;
  static void clear(Entry &entry) noexcept;

  std::array<Entry, device_catalog::ipv6_reassembly_entries_per_endpoint>
      entries_{};
  std::vector<std::uint8_t> completed_;
};

} // namespace router::packet
