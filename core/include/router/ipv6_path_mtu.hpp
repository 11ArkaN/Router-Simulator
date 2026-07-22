// Per-destination and per-link IPv6 Path MTU cache. The IP owner supplies
// already validated PTB information. This module never parses ICMP, sends a
// probe or raises an estimate from untrusted network input.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"
#include "router/packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router::ip {

enum class PathMtuUpdate : std::uint8_t {
  decreased,
  unchanged,
  invalid_report,
  resource_exhausted
};

struct Ipv6PathMtuEntry {
  Ipv6 destination{};
  std::chrono::steady_clock::time_point probe_after{};
  std::uint64_t interface_id{};
  std::uint32_t mtu{};
  // This candidate belongs to one emitted packet and is not visible through
  // estimate(). Only a correlated success can publish it as the path value.
  std::uint32_t probe_mtu{};
  bool occupied{};
};

struct Ipv6PathMtuCheckpoint {
  // The stable interface identifier is part of the path key. Remaining time
  // is relative so restore never imports another process's steady-clock epoch.
  Ipv6 destination{};
  std::int64_t remaining_probe_nanoseconds{};
  std::uint64_t interface_id{};
  std::uint32_t mtu{};
  // A checkpoint can be taken while a real probe is in flight. Preserving the
  // candidate avoids silently turning that probe into ordinary confirmed state.
  std::uint32_t probe_mtu{};
};

class Ipv6PathMtuCache final {
public:
  using Clock = std::chrono::steady_clock;

  // first_hop_mtu is the current routed-link MTU and remains the default when
  // no cache entry exists. A PTB can only lower the stored estimate.
  [[nodiscard]] std::uint32_t estimate(
      const Ipv6 &destination, std::uint64_t interface_id,
      std::uint32_t first_hop_mtu) const noexcept;
  // RFC 8201 section 5.3 permits a conservative larger experiment after the
  // aging interval. packet_octets is the exact packet that the caller is about
  // to emit, so a short packet cannot claim evidence for an MTU it did not use.
  [[nodiscard]] std::uint32_t begin_probe(
      const Ipv6 &destination, std::uint64_t interface_id,
      std::uint32_t first_hop_mtu, std::uint32_t packet_octets,
      Clock::time_point now = Clock::now()) noexcept;
  // The caller must first correlate a received success response with the exact
  // destination, interface and emitted probe generation.
  [[nodiscard]] bool confirm_probe(
      const Ipv6 &destination, std::uint64_t interface_id,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] PathMtuUpdate update(
      const Ipv6 &destination, std::uint64_t interface_id,
      std::uint32_t reported_mtu, std::uint32_t first_hop_mtu,
      Clock::time_point now = Clock::now()) noexcept;
  void remove_interface(std::uint64_t interface_id) noexcept;
  void clear() noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  // These methods run on the cache owner while it is quiesced. restore first
  // validates the complete image and therefore cannot partially replace live
  // path estimates when a checkpoint is malformed.
  [[nodiscard]] std::vector<Ipv6PathMtuCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const std::vector<Ipv6PathMtuCheckpoint> &state) noexcept;
  [[nodiscard]] bool restore(
      const std::vector<Ipv6PathMtuCheckpoint> &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  [[nodiscard]] Ipv6PathMtuEntry *find(const Ipv6 &destination,
                                       std::uint64_t interface_id) noexcept;
  [[nodiscard]] const Ipv6PathMtuEntry *find(
      const Ipv6 &destination, std::uint64_t interface_id) const noexcept;

  std::array<Ipv6PathMtuEntry,
             device_catalog::ipv6_pmtu_entries_per_endpoint>
      entries_{};
};

} // namespace router::ip
