// Interface-owned MLD listener state. This module translates local multicast
// reception intent and received Queries into bounded report actions. It owns
// no packet buffers, links, sockets or router state. The caller encodes each
// action and sends the resulting frame through the ordinary egress queue.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/mld_packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

enum class MldFilterMode : std::uint8_t { include, exclude };

struct MldListenerAction {
  // One action deliberately carries one multicast-address record. RFC 3810
  // permits a Report to contain one record, while this shape keeps each poll
  // bounded without allocating an aggregation buffer on the forwarding path.
  packet::Ipv6 multicast_address{};
  std::array<packet::Ipv6, device_catalog::mld_sources_per_group> sources{};
  std::uint16_t source_count{};
  packet::mld::RecordType record_type{packet::mld::RecordType::mode_is_include};
  bool version_one{};
  bool done{};
};

struct MldListenerGroupCheckpoint {
  packet::Ipv6 multicast_address{};
  std::array<packet::Ipv6, device_catalog::mld_sources_per_group> sources{};
  // State-change retransmissions retain their own delta. Reusing the current
  // filter list would turn BLOCK_OLD_SOURCES into an unrelated full-state
  // record after the local source list had already changed.
  std::array<packet::Ipv6, device_catalog::mld_sources_per_group>
      retransmission_sources{};
  std::uint16_t source_count{};
  std::uint16_t retransmission_source_count{};
  std::int64_t response_remaining_nanoseconds{};
  std::int64_t retransmission_remaining_nanoseconds{};
  MldFilterMode mode{MldFilterMode::include};
  packet::mld::RecordType retransmission_type{
      packet::mld::RecordType::mode_is_include};
  std::uint8_t retransmissions_remaining{};
  bool response_pending{};
  bool occupied{};
};

struct MldListenerCheckpoint {
  std::vector<MldListenerGroupCheckpoint> groups;
  std::int64_t older_querier_remaining_nanoseconds{};
  std::uint64_t random_state{};
  bool version_one_compatibility{};
  bool link_operational{};
  bool link_local_preferred{};
};

class MldListener final {
public:
  using Clock = std::chrono::steady_clock;

  // The interface identity seeds only the RFC-required randomized response
  // delay. It is not a security secret and does not derive an IPv6 address.
  explicit MldListener(std::uint64_t interface_identity = 1U) noexcept;

  // listen is the RFC 3810 IPv6MulticastListen interface-level operation.
  // The supplied list completely replaces prior state for this group. Lists
  // above the generated platform capacity fail atomically.
  [[nodiscard]] bool listen(
      const packet::Ipv6 &group, MldFilterMode mode,
      std::span<const packet::Ipv6> sources,
      Clock::time_point now = Clock::now()) noexcept;

  // Convenience membership used by ND and SLAAC. EXCLUDE {} means receive
  // from every source. INCLUDE {} means stop listening, exactly as RFC 3810.
  [[nodiscard]] bool join(const packet::Ipv6 &group,
                          Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool leave(const packet::Ipv6 &group,
                           Clock::time_point now = Clock::now()) noexcept;

  // Query processing is separate from frame parsing so malformed packets can
  // never enter this owner. The caller passes only a validated codec view.
  void observe_query(const packet::mld::QueryView &query,
                     Clock::time_point now = Clock::now()) noexcept;
  void observe_version_one_report(const packet::Ipv6 &group) noexcept;

  // Link-local preference changes the legal report source under RFC 3590. A
  // transition to preferred schedules refreshed reports for every membership.
  void set_link_state(bool operational, bool link_local_preferred,
                      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::size_t
  poll(Clock::time_point now,
       std::span<MldListenerAction> actions) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] bool accepts(const packet::Ipv6 &group,
                             const packet::Ipv6 &source) const noexcept;
  [[nodiscard]] bool joined(const packet::Ipv6 &group) const noexcept;
  [[nodiscard]] bool version_one_compatibility() const noexcept {
    return version_one_compatibility_;
  }

  [[nodiscard]] MldListenerCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const MldListenerCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(
      const MldListenerCheckpoint &state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Group {
    packet::Ipv6 multicast_address{};
    std::array<packet::Ipv6, device_catalog::mld_sources_per_group> sources{};
    std::array<packet::Ipv6, device_catalog::mld_sources_per_group>
        retransmission_sources{};
    std::uint16_t source_count{};
    std::uint16_t retransmission_source_count{};
    Clock::time_point response_deadline{Clock::time_point::max()};
    Clock::time_point retransmission_deadline{Clock::time_point::max()};
    MldFilterMode mode{MldFilterMode::include};
    packet::mld::RecordType retransmission_type{
        packet::mld::RecordType::mode_is_include};
    std::uint8_t retransmissions_remaining{};
    bool response_pending{};
    bool occupied{};
  };

  std::array<Group, device_catalog::mld_groups_per_interface> groups_{};
  Clock::time_point older_querier_deadline_{Clock::time_point::max()};
  std::uint64_t random_state_{};
  bool version_one_compatibility_{};
  bool link_operational_{};
  bool link_local_preferred_{};

  [[nodiscard]] Group *find(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] const Group *find(const packet::Ipv6 &group) const noexcept;
  [[nodiscard]] Group *allocate(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] std::chrono::nanoseconds
  randomized_delay(std::chrono::nanoseconds maximum) noexcept;
  void schedule_state_change(Group &group, packet::mld::RecordType type,
                             std::span<const packet::Ipv6> record_sources,
                             Clock::time_point now) noexcept;
};

} // namespace router::lab
