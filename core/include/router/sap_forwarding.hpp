// Forwarding-owned immutable SAP classifier for one router generation. It maps
// encoded Ethernet tag stacks on a physical ingress port to stable logical
// service-interface identities and applies the selected service envelope only
// at physical egress. It never performs routing, topology lookup or delivery.

#pragma once

#include "router/ies_service.hpp"
#include "router/ipv6_neighbor_cache.hpp"
#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::service {

struct SapAttachment {
  std::uint64_t logical_interface_id{};
  SapKey sap{};
  // TPIDs are port-level wire configuration. inner_tpid is ignored unless the
  // encapsulation is QinQ. Carrying both values here lets the packet path
  // support release-profiled TPIDs such as 0x88a8 or 0x9100 without guessing.
  std::uint16_t outer_tpid{};
  std::uint16_t inner_tpid{};

  [[nodiscard]] friend constexpr bool
  operator==(const SapAttachment &, const SapAttachment &) noexcept = default;
};

struct ServiceIpv6Interface {
  // interface_id is the RFC 4007 zone and FIB key. physical_port_ordinal is
  // only the wire attachment selected after routing and neighbor resolution.
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  std::uint16_t mtu{};
  packet::Mac mac{};
  packet::Ipv6 address{};
  packet::Ipv6 network{};
  packet::Ipv6 link_local{};
  std::uint8_t prefix_length{};
  std::uint32_t nd_reachable_time_milliseconds{};
  std::uint32_t nd_stale_time_seconds{};
  lab::Ipv6UnsolicitedLearning unsolicited_learning{
      lab::Ipv6UnsolicitedLearning::none};
  lab::Ipv6UnsolicitedLearning proactive_refresh{
      lab::Ipv6UnsolicitedLearning::none};
  std::uint32_t neighbor_limit{};
  std::uint8_t neighbor_limit_threshold_percent{};
  std::uint16_t redirect_maximum{};
  std::uint16_t redirect_interval_seconds{};
  bool neighbor_limit_configured{};
  bool neighbor_limit_log_only{};
  bool redirects_enabled{};
  bool configured{};
  bool operational{};

  [[nodiscard]] friend constexpr bool
  operator==(const ServiceIpv6Interface &,
             const ServiceIpv6Interface &) noexcept = default;
};

struct SapVlanMarking {
  std::uint8_t outer_priority_code_point{};
  bool outer_drop_eligible{};
  std::uint8_t inner_priority_code_point{};
  bool inner_drop_eligible{};
};

enum class SapProgramStatus : std::uint8_t {
  accepted,
  invalid_attachment,
  duplicate_sap,
  duplicate_logical_interface,
  inconsistent_port_encapsulation,
  invalid_interface,
  incomplete_service_generation,
  resource_exhausted
};

enum class SapIngressStatus : std::uint8_t {
  matched,
  no_match,
  malformed,
  output_too_small
};

struct SapIngressResult {
  SapIngressStatus status{SapIngressStatus::no_match};
  std::uint64_t logical_interface_id{};
  SapVlanMarking received_marking{};
};

class SapForwardingTable final {
public:
  // Replacement sorts and validates a private copy before publication. The
  // existing generation remains live after every failure, matching candidate
  // commit atomicity. Only the forwarding shard may call this method.
  [[nodiscard]] SapProgramStatus
  replace(std::span<const SapAttachment> attachments);
  // Service replacement validates and publishes SAP classifiers plus routed
  // interface projections as one generation. A packet turn cannot observe a
  // new VLAN key with old L3 state or the inverse.
  [[nodiscard]] SapProgramStatus replace(
      std::span<const SapAttachment> attachments,
      std::span<const ServiceIpv6Interface> interfaces);
  // Physical inventory removal runs inside a noexcept forwarding-owner turn.
  // Erasing in place and rebuilding the existing index capacity avoids both
  // allocation failure and a stale service attachment surviving card removal.
  void remove_physical_port(std::uint16_t physical_port_ordinal) noexcept;
  void clear() noexcept {
    attachments_.clear();
    logical_index_.clear();
    interfaces_.clear();
  }

  // ingress writes one untagged internal frame only after an exact physical
  // port, tag count, TPID and VID match. The result retains PCP and DEI for the
  // future ingress QoS owner instead of discarding observable wire metadata.
  [[nodiscard]] SapIngressResult ingress(std::uint16_t physical_port_ordinal,
                                         const packet::Frame &wire,
                                         packet::Frame &internal) const
      noexcept;

  // egress accepts only a complete untagged frame and a caller-owned marking.
  // It writes a separate wire image, so queue admission failure cannot mutate
  // a retained packet or a different service consumer's copy.
  [[nodiscard]] bool egress(std::uint64_t logical_interface_id,
                            const packet::Frame &internal,
                            const SapVlanMarking &marking,
                            packet::Frame &wire) const noexcept;

  [[nodiscard]] const SapAttachment *
  find_logical(std::uint64_t logical_interface_id) const noexcept;
  [[nodiscard]] const ServiceIpv6Interface *
  find_interface(std::uint64_t logical_interface_id) const noexcept;
  [[nodiscard]] bool
  has_physical_port(std::uint16_t physical_port_ordinal) const noexcept {
    return first_on_port(physical_port_ordinal) != nullptr;
  }
  [[nodiscard]] std::span<const SapAttachment> attachments() const noexcept {
    return attachments_;
  }
  [[nodiscard]] std::span<const ServiceIpv6Interface>
  interfaces() const noexcept { return interfaces_; }

private:
  [[nodiscard]] const SapAttachment *
  first_on_port(std::uint16_t physical_port_ordinal) const noexcept;

  // Entries are sorted by physical port and then exact wire key. A binary
  // ingress search is O(log n) and performs no allocation or string work.
  std::vector<SapAttachment> attachments_{};
  // Logical lookup stores indices into attachments_. It is rebuilt only after
  // attachments_ has reached its final sorted address and is never shared with
  // another owner.
  std::vector<std::size_t> logical_index_{};
  // Sorted independently by logical ID. Publication swaps this vector only
  // after both candidate indexes have passed cross-reference validation.
  std::vector<ServiceIpv6Interface> interfaces_{};
};

} // namespace router::service
