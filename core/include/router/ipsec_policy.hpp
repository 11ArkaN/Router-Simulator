// IPsec Security Policy Database value contract and single-owner repository.
// One forwarding security owner mutates an Spd instance. Packet selectors flow
// from the local input, forwarding or output path into lookup(), and immutable
// policy copies flow back to that same owner. This module depends only on
// allocation-free address values and cannot transmit packets or inspect a CLI.

#pragma once

#include "router/ip_address.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router::ipsec {

using AddressFamily = ip::AddressFamily;
enum class Direction : std::uint8_t { inbound, outbound, forwarding };
enum class PolicyAction : std::uint8_t { discard, bypass, protect };
enum class SecurityProtocol : std::uint8_t { esp = 50U, ah = 51U };
enum class Mode : std::uint8_t { transport, tunnel };

// SPD, IKE traffic selectors and policy-options use the same canonical
// allocation-free dual-stack values. Aliasing the common contract prevents
// family parsing and checkpoint validation from drifting between security and
// routing features while retaining the established ipsec namespace API.
using Address = ip::IpAddress;
using Prefix = ip::IpPrefix;

struct PortRange {
  std::uint16_t first{};
  std::uint16_t last{65535U};

  [[nodiscard]] friend constexpr bool
  operator==(const PortRange &, const PortRange &) noexcept = default;
};

struct TrafficSelector {
  Prefix source{};
  Prefix destination{};
  // RFC 4301 uses zero as the wildcard upper-layer protocol selector. Port
  // selectors are meaningful only for a protocol whose selector defines them.
  std::uint8_t upper_layer_protocol{};
  PortRange source_ports{};
  PortRange destination_ports{};
  // Zero means every interface. A stable interface identifier, rather than a
  // vector index, prevents inventory changes from redirecting a policy.
  std::uint64_t interface_id{};
};

struct PacketSelector {
  Address source{};
  Address destination{};
  std::uint8_t upper_layer_protocol{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  std::uint64_t interface_id{};
};

struct Policy {
  std::uint32_t id{};
  std::uint32_t priority{};
  Direction direction{Direction::outbound};
  PolicyAction action{PolicyAction::discard};
  TrafficSelector selector{};
  // A protect policy names a validated transform or IKE proposal owned by the
  // control plane. Zero is forbidden for protect and required otherwise.
  std::uint32_t proposal_id{};
};

struct SpdCheckpoint {
  // Capacity is an owner resource property and is authenticated by the outer
  // project checkpoint. Policies remain canonical values with no indexes or
  // native pointers, so restore can rebuild lookup order deterministically.
  std::size_t capacity{};
  std::vector<Policy> policies;
};

enum class PolicyInstallResult : std::uint8_t {
  installed,
  replaced,
  invalid,
  capacity_exhausted
};

class Spd final {
public:
  // The release or platform profile supplies capacity. The repository does not
  // invent a device limit, and zero deliberately creates a disabled database.
  explicit Spd(std::size_t capacity);

  // install() is the sole mutation path. It validates selectors before changing
  // state and atomically replaces an existing ID, so a rejected configuration
  // cannot leave half of a policy active.
  [[nodiscard]] PolicyInstallResult install(const Policy &policy) noexcept;
  [[nodiscard]] bool erase(std::uint32_t id) noexcept;

  // RFC 4301 section 4.4.1 requires ordered policy processing. The smallest
  // numeric priority is evaluated first, followed by stable policy ID order.
  [[nodiscard]] std::optional<Policy>
  lookup(Direction direction, const PacketSelector &packet) const noexcept;

  // Checkpoint stores configured policy values only. Derived direction and
  // family indexes are rebuilt in a detached Spd and published only after all
  // records validate, preventing malformed persistence from changing live SPD.
  [[nodiscard]] SpdCheckpoint checkpoint() const;
  [[nodiscard]] bool restore(const SpdCheckpoint &state) noexcept;

  [[nodiscard]] std::size_t size() const noexcept { return policies_.size(); }
  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

private:
  void rebuild_indexes() noexcept;

  std::size_t capacity_{};
  std::vector<Policy> policies_;
  // Three directions times two address families. Each bucket stores positions
  // in the priority-sorted policy vector, so lookup scans only the applicable
  // class while preserving the exact configured first-match order.
  std::array<std::vector<std::size_t>, 6U> lookup_indexes_;
};

[[nodiscard]] bool valid_address(const Address &address) noexcept;
[[nodiscard]] bool valid_prefix(const Prefix &prefix) noexcept;
[[nodiscard]] bool prefix_contains(const Prefix &prefix,
                                   const Address &address) noexcept;

} // namespace router::ipsec
