// Destination-owned IPv4 fragment reassembly. One endpoint shard owns each
// table, every input is an encoded Ethernet frame, and completed storage is
// borrowed only until the next non-const table operation.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <bitset>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::packet {

enum class Ipv4ReassemblyStatus : std::uint8_t {
  not_fragment,
  incomplete,
  complete,
  malformed,
  resource_exhausted
};

struct Ipv4ReassemblyResult {
  Ipv4ReassemblyStatus status{Ipv4ReassemblyStatus::not_fragment};
  // The span borrows table-owned completion storage. A caller must consume or
  // copy it before accept(), take_expired(), discard_all() or restore() is called.
  std::span<const std::uint8_t> packet{};
};

struct Ipv4ReassemblyCheckpoint {
  Ipv4 source{};
  Ipv4 destination{};
  Frame first_fragment{};
  // Only the live prefix and packed receipt bitmap are serialized. Runtime
  // arenas remain fixed and allocation-free after table construction.
  std::vector<std::uint8_t> payload;
  std::vector<std::uint8_t> received;
  std::int64_t remaining_nanoseconds{};
  std::uint16_t identification{};
  std::uint16_t final_size{};
  std::uint8_t protocol{};
  bool have_first{};
  bool have_last{};
};

class Ipv4ReassemblyTable final {
public:
  using Clock = std::chrono::steady_clock;
  static constexpr std::size_t maximum_payload_octets =
      maximum_ipv4_datagram_octets - 20U;
  // Construction allocates every payload arena once. The forwarding hot path
  // performs no heap allocation and never evicts an incomplete datagram merely
  // to hide resource exhaustion from its owner.
  Ipv4ReassemblyTable();

  // Precondition: fragment is one complete captured Ethernet frame. The table
  // validates IPv4 checksum, lengths and RFC 791 fragment alignment itself.
  // Overlapping bytes use RFC 791's later-arrival precedence. This behavior is
  // intentionally distinct from IPv6's mandatory whole-datagram rejection.
  [[nodiscard]] Ipv4ReassemblyResult
  accept(const Frame &fragment, Clock::time_point now = Clock::now()) noexcept;
  // Removes at most one expired entry. first_fragment.length is nonzero only
  // when offset zero had arrived and the endpoint must emit ICMP Time Exceeded
  // code 1. Repeating until false drains every due entry without allocation.
  [[nodiscard]] bool take_expired(
      Frame &first_fragment,
      Clock::time_point now = Clock::now()) noexcept;
  void discard_all() noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::size_t active() const noexcept;
  [[nodiscard]] std::vector<Ipv4ReassemblyCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const std::vector<Ipv4ReassemblyCheckpoint> &state) noexcept;
  [[nodiscard]] bool restore(
      const std::vector<Ipv4ReassemblyCheckpoint> &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Entry {
    Ipv4 source{};
    Ipv4 destination{};
    Frame first_fragment{};
    std::vector<std::uint8_t> payload;
    std::bitset<maximum_payload_octets> received{};
    Clock::time_point expires{};
    std::uint32_t extent{};
    std::uint16_t identification{};
    std::uint16_t final_size{};
    std::uint8_t protocol{};
    bool occupied{};
    bool have_first{};
    bool have_last{};
  };

public:
  // entries_ itself is heap-backed to keep EndpointStack small enough for
  // ordinary native and Wasm call frames. This value includes its exact object
  // allocation as well as every payload and completion vector allocation.
  static constexpr std::size_t payload_arena_allocation_bytes =
      device_catalog::ipv4_reassembly_entries_per_endpoint *
          (maximum_payload_octets + sizeof(Entry)) +
      maximum_ethernet_ipv4_datagram_octets;

private:

  [[nodiscard]] Entry *find(const Ipv4View &view) noexcept;
  [[nodiscard]] Entry *allocate(const Ipv4View &view,
                                Clock::time_point now) noexcept;
  [[nodiscard]] std::span<const std::uint8_t>
  assemble(const Entry &entry) noexcept;
  static void clear(Entry &entry) noexcept;

  std::vector<Entry> entries_;
  std::vector<std::uint8_t> completed_;
};

} // namespace router::packet
