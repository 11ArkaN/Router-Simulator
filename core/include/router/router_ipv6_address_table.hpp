// Forwarding-owned configured IPv6 address generation for native router
// interfaces. Control publishes a complete value generation; this table
// validates it before replacing live state and never retains control memory.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

struct RouterIpv6Address {
  // interface_id is the stable routed-interface identity. port_ordinal is the
  // physical egress coordinate used only after routing selected that owner.
  packet::Ipv6 address{};
  packet::Ipv6 network{};
  std::uint64_t interface_id{};
  std::uint32_t primary_preference{};
  std::uint32_t tag{};
  std::uint16_t port_ordinal{};
  std::uint8_t prefix_length{};
  bool duplicate_address_detection{true};
  bool tag_configured{};

  [[nodiscard]] friend bool
  operator==(const RouterIpv6Address &, const RouterIpv6Address &) = default;
};

enum class RouterIpv6AddressProgramStatus : std::uint8_t {
  accepted,
  too_many_addresses,
  invalid_record,
  duplicate_address,
  interface_limit_exceeded,
  resource_exhausted
};

class RouterIpv6AddressTable final {
public:
  RouterIpv6AddressTable() = default;
  RouterIpv6AddressTable(const RouterIpv6AddressTable &) = delete;
  RouterIpv6AddressTable &
  operator=(const RouterIpv6AddressTable &) = delete;
  RouterIpv6AddressTable(RouterIpv6AddressTable &&) noexcept = default;
  RouterIpv6AddressTable &
  operator=(RouterIpv6AddressTable &&) noexcept = default;

  // The per-router allocation is the documented per-interface ceiling times
  // the generated hardware inventory ceiling. It is fixed in forwarding
  // memory, so packet lookup and source selection never allocate or lock.
  static constexpr std::size_t capacity =
      device_catalog::maximum_ports_per_router *
      device_catalog::network_interface_ip_addresses;

  // Preconditions: records is a complete intended generation. Every network
  // is canonical and every interface and port identity is nonzero/in-range.
  // Postcondition on accepted: live records equal the canonical sorted input.
  // Any error preserves the prior generation without partial publication.
  [[nodiscard]] RouterIpv6AddressProgramStatus
  program(std::span<const RouterIpv6Address> records) noexcept;

  [[nodiscard]] std::span<const RouterIpv6Address> records() const noexcept {
    return records_;
  }

  [[nodiscard]] const RouterIpv6Address *
  find(std::uint64_t interface_id, const packet::Ipv6 &address) const noexcept;

  [[nodiscard]] const RouterIpv6Address *
  owner(const packet::Ipv6 &address) const noexcept;

  // The lowest primary-preference value wins. Address bytes are the stable
  // final tie-breaker, which makes checkpoint restore and repeated programming
  // deterministic even when configuration arrived in a different order.
  [[nodiscard]] const RouterIpv6Address *
  primary(std::uint64_t interface_id) const noexcept;

  [[nodiscard]] std::size_t
  interface_count(std::uint64_t interface_id) const noexcept;

  // Physical inventory removal is already serialized on the forwarding
  // owner. Compacting the live vector in place cannot fail and avoids a heap
  // transaction inside the noexcept hardware-removal path.
  void remove_physical_port(std::uint16_t port_ordinal) noexcept;

private:
  // Configured addresses are sparse relative to the 800-port hardware ceiling.
  // A vector keeps RouterForwarder small enough for the Wasm stack while still
  // providing contiguous, allocation-free packet-path traversal. Allocation
  // occurs only while a control-plane generation is prepared.
  std::vector<RouterIpv6Address> records_{};
};

} // namespace router::lab
