// IPv4 Path MTU cache for one IP owner. The destination and stable outgoing
// interface form the path key. Only a caller that has authenticated an ICMP
// quotation may lower an entry, so this module never parses packets or reaches
// into routing, Ethernet or another device's state.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace router::ip {

enum class Ipv4PathMtuUpdate : std::uint8_t {
  decreased,
  unchanged,
  invalid_report,
  resource_exhausted
};

struct Ipv4PathMtuEntry {
  packet::Ipv4 destination{};
  std::chrono::steady_clock::time_point probe_after{};
  std::uint64_t interface_id{};
  std::uint32_t mtu{};
  // A larger value is an unconfirmed one-datagram experiment. It is never
  // returned by estimate(), so concurrent application traffic remains bound
  // by the last confirmed path value while the probe is outstanding.
  std::uint32_t probe_mtu{};
  bool occupied{};
};

struct Ipv4PathMtuCheckpoint {
  // A relative deadline avoids importing a process-local steady-clock epoch.
  // The destination and interface remain explicit because an address can use
  // a different MTU after route replacement or interface migration.
  packet::Ipv4 destination{};
  std::int64_t remaining_probe_nanoseconds{};
  std::uint64_t interface_id{};
  std::uint32_t mtu{};
  std::uint32_t probe_mtu{};
};

class Ipv4PathMtuCache final {
public:
  using Clock = std::chrono::steady_clock;

  // Returns the current per-path estimate without changing probe timers.
  // first_hop_mtu remains authoritative when no learned path entry exists.
  [[nodiscard]] std::uint32_t estimate(
      packet::Ipv4 destination, std::uint64_t interface_id,
      std::uint32_t first_hop_mtu) const noexcept;

  // Called immediately before a DF probe is emitted. Once the RFC 1191 aging
  // deadline expires, exactly one higher plateau is attempted and the shorter
  // retry interval prevents every subsequent datagram from repeating it.
  [[nodiscard]] std::uint32_t begin_probe(
      packet::Ipv4 destination, std::uint64_t interface_id,
      std::uint32_t first_hop_mtu, std::uint32_t packet_octets,
      Clock::time_point now = Clock::now()) noexcept;

  // Confirms only the currently outstanding larger experiment. The caller
  // must have associated a success response with the exact emitted packet.
  [[nodiscard]] bool confirm_probe(
      packet::Ipv4 destination, std::uint64_t interface_id,
      Clock::time_point now = Clock::now()) noexcept;

  // reported_mtu is the ICMP Next-Hop MTU field. Zero denotes an old router;
  // quoted_total_length then selects the next lower RFC 1191 plateau. The
  // caller must already have matched the quote to a locally emitted packet.
  [[nodiscard]] Ipv4PathMtuUpdate update(
      packet::Ipv4 destination, std::uint64_t interface_id,
      std::uint32_t reported_mtu, std::uint32_t quoted_total_length,
      std::uint32_t first_hop_mtu,
      Clock::time_point now = Clock::now()) noexcept;

  void remove_interface(std::uint64_t interface_id) noexcept;
  void clear() noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::vector<Ipv4PathMtuCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const std::vector<Ipv4PathMtuCheckpoint> &state) noexcept;
  [[nodiscard]] bool restore(
      const std::vector<Ipv4PathMtuCheckpoint> &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] Ipv4PathMtuEntry *find(
      packet::Ipv4 destination, std::uint64_t interface_id) noexcept;
  [[nodiscard]] const Ipv4PathMtuEntry *find(
      packet::Ipv4 destination, std::uint64_t interface_id) const noexcept;

  // The forwarding or endpoint shard that contains this object is its sole
  // writer. No atomics are needed because control and checkpoint requests are
  // serialized into that same owner.
  std::array<Ipv4PathMtuEntry,
             device_catalog::ipv4_pmtu_entries_per_endpoint>
      entries_{};
};

} // namespace router::ip
