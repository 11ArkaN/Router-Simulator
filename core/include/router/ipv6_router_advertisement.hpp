// Forwarding-owned Router Advertisement timer table. It owns only per-port
// transmit deadlines and copied RA configuration. Packet encoding remains in
// neighbor_discovery_packet, while interface intent remains control-owned.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/neighbor_discovery_packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

struct RouterAdvertisementAction {
  // The polling forwarding owner consumes this value in the same turn and
  // encodes it as an Ethernet frame. No action crosses a device boundary.
  std::uint16_t port_ordinal{};
  packet::nd::RouterAdvertisementConfig config{};
};

struct Ipv6RouterAdvertisementCheckpoint {
  packet::nd::RouterAdvertisementConfig config{};
  std::int64_t remaining_nanoseconds{};
  std::int64_t last_sent_ago_nanoseconds{};
  std::uint64_t random_state{};
  std::uint16_t port_ordinal{};
  std::uint8_t initial_advertisements_remaining{};
  bool requested_enabled{};
  bool active{};
  bool has_sent{};
};

class Ipv6RouterAdvertisementTable final {
public:
  using Clock = std::chrono::steady_clock;
  static constexpr std::size_t capacity =
      device_catalog::maximum_ports_per_router;

  // configure atomically replaces one port's complete advertisement intent.
  // It rejects SR OS interval ranges and RFC min/max relationships before any
  // deadline is installed. Disabled entries consume no timer work.
  [[nodiscard]] bool configure(
      std::uint16_t port_ordinal, bool enabled,
      const packet::nd::RouterAdvertisementConfig &config,
      Clock::time_point now = Clock::now(), bool link_ready = true) noexcept;
  void remove(std::uint16_t port_ordinal) noexcept;
  void set_link_ready(std::uint16_t port_ordinal, bool ready,
                      Clock::time_point now = Clock::now()) noexcept;

  // A validated RS schedules a response using MAX_RA_DELAY_TIME while honoring
  // MIN_DELAY_BETWEEN_RAS. Repeated solicitations coalesce into one multicast
  // response, matching the RFC permission to answer multiple hosts together.
  void observe_solicitation(std::uint16_t port_ordinal,
                            Clock::time_point now = Clock::now()) noexcept;

  // Producer and consumer are the same forwarding shard. The caller supplies
  // bounded storage, and unreturned due actions remain due for the next turn.
  [[nodiscard]] std::size_t
  poll(Clock::time_point now,
       std::span<RouterAdvertisementAction> actions) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  // Cold checkpoint operations run on the owning forwarding shard. Relative
  // durations survive process restarts without persisting a steady-clock epoch.
  [[nodiscard]] std::vector<Ipv6RouterAdvertisementCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      std::span<const Ipv6RouterAdvertisementCheckpoint> state) noexcept;
  [[nodiscard]] bool restore(
      std::span<const Ipv6RouterAdvertisementCheckpoint> state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Entry {
    packet::nd::RouterAdvertisementConfig config{};
    Clock::time_point next{};
    Clock::time_point last_sent{};
    std::uint64_t random_state{};
    std::uint16_t port_ordinal{};
    std::uint8_t initial_advertisements_remaining{};
    bool occupied{};
    bool requested_enabled{};
    bool active{};
    bool has_sent{};
  };

  [[nodiscard]] Entry *find(std::uint16_t port_ordinal) noexcept;
  [[nodiscard]] static std::chrono::nanoseconds
  random_delay(Entry &entry, std::chrono::nanoseconds maximum) noexcept;
  [[nodiscard]] static std::chrono::nanoseconds
  periodic_delay(Entry &entry) noexcept;
  [[nodiscard]] static bool valid_config(
      const packet::nd::RouterAdvertisementConfig &config) noexcept;

  std::array<Entry, capacity> entries_{};
};

} // namespace router::lab
