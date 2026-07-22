// Forwarding-owner Duplicate Address Detection state. The owner emits only
// value actions. RouterForwarder converts them to encoded NS frames and sends
// them through the ordinary egress queue and physical link.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

// Shared jitter calculation for router and host DAD owners. scope_id is a
// stable local interface identity and never identifies a remote topology node.
[[nodiscard]] std::chrono::nanoseconds ipv6_interface_initial_delay(
    std::uint64_t scope_id, const ip::Ipv6 &address,
    std::chrono::steady_clock::time_point now,
    std::chrono::nanoseconds maximum) noexcept;

enum class Ipv6DadState : std::uint8_t { tentative, preferred, duplicate };

struct Ipv6DadAction {
  std::uint64_t interface_id{};
  std::uint16_t port_ordinal{};
  ip::Ipv6 target{};
};

struct Ipv6DadSnapshot {
  std::uint64_t interface_id{};
  ip::Ipv6 address{};
  Ipv6DadState state{Ipv6DadState::tentative};
  std::uint8_t probes_sent{};
};

struct Ipv6DadCheckpoint {
  std::uint64_t interface_id{};
  std::uint16_t port_ordinal{};
  ip::Ipv6 address{};
  Ipv6DadState state{Ipv6DadState::tentative};
  std::uint8_t probes_sent{};
  std::uint8_t transmit_limit{};
  bool has_deadline{};
  std::int64_t remaining_nanoseconds{};
};

class Ipv6DadTable final {
public:
  using Clock = std::chrono::steady_clock;

  // Capacity is generated independently from a current address-per-port shape,
  // so adding secondary, SLAAC or DHCPv6 addresses does not require changing
  // the DAD state machine or hiding a multiplier in this header.
  static constexpr std::size_t capacity =
      device_catalog::ipv6_dad_entries_per_node;

  // Repeating an identical address is idempotent and does not restart DAD.
  // A changed address must be removed by the interface owner first so stale
  // conflict state cannot remain attached to the port.
  [[nodiscard]] bool configure(
      std::uint64_t interface_id, std::uint16_t port_ordinal,
      const ip::Ipv6 &address,
      std::uint8_t transmit_limit, std::chrono::nanoseconds initial_delay,
      Clock::time_point now = Clock::now()) noexcept;
  // Address-specific removal lets RFC 7217 replace one duplicate tentative
  // address without discarding independent DAD state on the same interface.
  void remove(std::uint64_t interface_id,
              const ip::Ipv6 &address) noexcept;
  void remove_interface(std::uint64_t interface_id) noexcept;
  void remove_physical_port(std::uint16_t port_ordinal) noexcept;

  // A received NS with an unspecified source or any received NA for a
  // tentative target is a DAD conflict. The caller has already validated the
  // complete ND packet before invoking this state transition.
  [[nodiscard]] bool observe_conflict(std::uint64_t interface_id,
                                      const ip::Ipv6 &target) noexcept;
  [[nodiscard]] bool preferred(std::uint64_t interface_id,
                               const ip::Ipv6 &address) const noexcept;
  [[nodiscard]] std::optional<Ipv6DadSnapshot>
  find(std::uint64_t interface_id, const ip::Ipv6 &address) const noexcept;

  // Due output is bounded by the caller. A full output span leaves the first
  // unhandled deadline due so backpressure never skips a required NS.
  [[nodiscard]] std::size_t
  poll(Clock::time_point now, std::span<Ipv6DadAction> output) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] std::vector<Ipv6DadCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      std::span<const Ipv6DadCheckpoint> state) noexcept;
  [[nodiscard]] bool restore(std::span<const Ipv6DadCheckpoint> state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  struct Entry {
    bool valid{};
    std::uint64_t interface_id{};
    std::uint16_t port_ordinal{};
    ip::Ipv6 address{};
    Ipv6DadState state{Ipv6DadState::tentative};
    std::uint8_t probes_sent{};
    std::uint8_t transmit_limit{};
    Clock::time_point deadline{Clock::time_point::max()};
  };

  [[nodiscard]] Entry *entry(std::uint64_t interface_id,
                             const ip::Ipv6 &address) noexcept;
  [[nodiscard]] const Entry *entry(std::uint64_t interface_id,
                                   const ip::Ipv6 &address) const noexcept;

  std::array<Entry, capacity> entries_{};
};

} // namespace router::lab
