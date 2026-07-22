// Per-interface MLD router owner. It aggregates listener Reports, performs
// querier election and emits bounded Query actions. It has no access to the
// topology graph, packet queues or another router and is active only after an
// explicit SR OS MLD interface configuration is projected by control.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/mld_listener.hpp"
#include "router/mld_packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

struct MldRouterConfiguration {
  packet::Ipv6 link_local_address{};
  std::chrono::seconds query_interval{device_catalog::mld_query_interval};
  std::chrono::milliseconds query_response_interval{
      device_catalog::mld_query_response_interval};
  std::chrono::milliseconds last_listener_query_interval{
      device_catalog::mld_last_listener_query_interval};
  std::uint16_t port_ordinal{};
  std::uint8_t robustness_variable{device_catalog::mld_robustness_variable};
  std::uint8_t version{device_catalog::mld_default_version};
  // Zero means the corresponding SR OS leaf is absent and imposes no
  // operator-configured admission limit. Runtime resource exhaustion remains
  // a separate failure reason and never changes these configuration values.
  std::uint32_t maximum_number_groups{};
  std::uint32_t maximum_number_group_sources{};
  std::uint32_t maximum_number_sources{};
  // RFC 2710 and RFC 3810 require Router Alert. SR OS exposes an explicit
  // compatibility control that may disable only this receive-side check.
  bool router_alert_check{true};
  bool enabled{};
};

struct MldSsmTranslation {
  // One configured source is one independently removable YANG list entry.
  // Ranges are inclusive and use network byte order, which makes the default
  // std::array ordering identical to numeric IPv6 address ordering.
  packet::Ipv6 start{};
  packet::Ipv6 end{};
  packet::Ipv6 source{};
  bool operator==(const MldSsmTranslation &) const = default;
};

enum class MldSsmProgramOperation : std::uint8_t { begin, add, commit, abort };

enum class MldRouterQueryKind : std::uint8_t {
  general,
  multicast_address,
  multicast_address_and_sources
};

enum class MldStaticOperation : std::uint8_t {
  create_group,
  add_starg,
  add_source,
  remove_group,
  remove_starg,
  remove_source
};

struct MldRouterAction {
  std::array<packet::Ipv6, device_catalog::mld_sources_per_group> sources{};
  packet::Ipv6 multicast_address{};
  std::chrono::milliseconds maximum_response_delay{};
  std::chrono::seconds query_interval{};
  MldRouterQueryKind kind{MldRouterQueryKind::general};
  std::uint16_t source_count{};
  std::uint8_t robustness_variable{};
  bool suppress_router_processing{};
  bool version_one{};
};

struct MldRouterSourceCheckpoint {
  packet::Ipv6 address{};
  std::int64_t remaining_nanoseconds{};
  bool timer_running{};
};

struct MldRouterPendingQueryCheckpoint {
  std::vector<packet::Ipv6> sources;
  std::int64_t remaining_nanoseconds{};
  std::uint8_t transmissions_remaining{};
  bool multicast_address_query{};
};

struct MldRouterGroupCheckpoint {
  packet::Ipv6 multicast_address{};
  std::vector<MldRouterSourceCheckpoint> sources;
  std::array<MldRouterPendingQueryCheckpoint, 2U> pending_queries{};
  std::int64_t filter_remaining_nanoseconds{};
  std::int64_t older_host_remaining_nanoseconds{};
  MldFilterMode mode{MldFilterMode::include};
  bool filter_timer_running{};
  bool older_host_present{};
};

struct MldRouterStaticGroupCheckpoint {
  // Static membership is configuration-owned and has no expiry timer. A
  // group context may be empty until its starg or source child is committed.
  packet::Ipv6 multicast_address{};
  std::vector<packet::Ipv6> sources;
  bool starg{};
};

struct MldRouterStatistics {
  // These names intentionally mirror the 26.7 `show router mld statistics`
  // fields. The forwarding shard is the sole writer, while CLI reads a
  // quiesced checkpoint projection. Plain integers are therefore sufficient
  // and avoid atomic traffic on every link-local control packet.
  std::uint64_t queries_received{};
  std::uint64_t queries_transmitted{};
  std::uint64_t reports_v1_received{};
  std::uint64_t reports_v1_transmitted{};
  std::uint64_t reports_v2_received{};
  std::uint64_t reports_v2_transmitted{};
  std::uint64_t dones_received{};
  std::uint64_t dones_transmitted{};
  std::uint64_t bad_length{};
  std::uint64_t bad_checksum{};
  std::uint64_t unknown_type{};
  std::uint64_t bad_receive_interface{};
  std::uint64_t receive_non_local{};
  std::uint64_t receive_wrong_version{};
  std::uint64_t policy_drops{};
  std::uint64_t no_router_alert{};
  std::uint64_t receive_bad_encodings{};
  std::uint64_t receive_packet_drops{};
  std::uint64_t local_scope_packets{};
  std::uint64_t reserved_scope_packets{};
  std::uint64_t mcac_policy_drops{};
};

enum class MldReceiveStatistic : std::uint8_t {
  query,
  report_v1,
  report_v2,
  done,
  bad_length,
  bad_checksum,
  unknown_type,
  bad_receive_interface,
  non_local,
  wrong_version,
  policy_drop,
  no_router_alert,
  bad_encoding,
  packet_drop,
  local_scope,
  reserved_scope,
  mcac_policy_drop
};

struct MldRouterCheckpoint {
  MldRouterConfiguration configuration{};
  std::vector<MldRouterGroupCheckpoint> groups;
  std::vector<MldRouterStaticGroupCheckpoint> static_groups;
  packet::Ipv6 querier_address{};
  MldRouterStatistics statistics{};
  std::int64_t general_query_remaining_nanoseconds{};
  std::int64_t other_querier_remaining_nanoseconds{};
  std::int64_t older_querier_remaining_nanoseconds{};
  std::uint8_t startup_queries_remaining{};
  bool querier{};
  bool other_querier_timer_running{};
  bool older_querier_present{};
};

class MldRouterInterface final {
public:
  using Clock = std::chrono::steady_clock;

  MldRouterInterface();

  // configure validates the complete timer tuple before replacing live state.
  // Enabling a new interface starts as Querier and schedules its first General
  // Query immediately, as required by RFC 3810 section 7.6.2.
  [[nodiscard]] bool configure(const MldRouterConfiguration &configuration,
                               Clock::time_point now = Clock::now()) noexcept;

  // The packet codec has already verified checksum, Hop Limit and address
  // form. Router Alert validation follows this interface's resolved SR OS
  // compatibility setting before any view reaches the protocol owner.
  void observe_query(const packet::mld::QueryView &query,
                     std::span<const packet::Ipv6> sources = {},
                     Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  observe_version_one(const packet::mld::VersionOneView &message,
                      Clock::time_point now = Clock::now()) noexcept;
  // SR OS SSM translation converts only an MLDv1 (*,G) Report. The forwarding
  // owner resolves interface override versus protocol-level rules and passes
  // their configured sources here. A Done still follows ordinary v1 handling.
  [[nodiscard]] bool observe_translated_version_one_report(
      const packet::mld::VersionOneView &message,
      std::span<const packet::Ipv6> translated_sources,
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool
  observe_record(const packet::mld::RecordView &record,
                 std::span<const packet::Ipv6> sources,
                 Clock::time_point now = Clock::now()) noexcept;

  // Static group operations implement the Nokia configuration hierarchy. A
  // group context is created separately from its mutually exclusive starg or
  // source children, allowing candidate order to match both CLI engines.
  [[nodiscard]] bool configure_static_group(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] bool configure_static_starg(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] bool
  configure_static_source(const packet::Ipv6 &group,
                          const packet::Ipv6 &source) noexcept;
  [[nodiscard]] bool remove_static_group(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] bool remove_static_starg(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] bool remove_static_source(const packet::Ipv6 &group,
                                          const packet::Ipv6 &source) noexcept;

  [[nodiscard]] std::size_t poll(Clock::time_point now,
                                 std::span<MldRouterAction> actions) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  // Forwarding suggestion follows RFC 3810 section 7.3. MLD does not create a
  // route; the multicast routing owner may use this result for an attached
  // receiver interface after its own RPF and policy decision.
  [[nodiscard]] bool listener_accepts(const packet::Ipv6 &group,
                                      const packet::Ipv6 &source,
                                      Clock::time_point now) const noexcept;
  // Operational clear is executed by this owner rather than by editing a
  // checkpoint image. An absent group is a valid clear result because SR OS
  // clear commands are idempotent operational requests, not configuration
  // deletions. Static memberships will be stored separately and therefore
  // are deliberately outside this dynamic database operation.
  void clear_database(
      const std::optional<packet::Ipv6> &group = std::nullopt) noexcept;

  // MLDv1 compatibility is learned independently for every multicast group.
  // The SR OS clear-version command removes only that learned compatibility;
  // listener filter state and configured protocol version remain intact.
  void clear_older_host_compatibility() noexcept;
  // Packet classification occurs in RouterForwarder because malformed bytes
  // cannot safely become protocol views. This narrow counter message lets
  // that owner report the outcome without exposing mutable statistics.
  void count_receive(MldReceiveStatistic statistic) noexcept;
  void clear_statistics() noexcept { statistics_ = {}; }
  [[nodiscard]] std::size_t group_count() const noexcept {
    return groups_.size();
  }
  [[nodiscard]] std::size_t static_group_count() const noexcept {
    return static_groups_.size();
  }
  [[nodiscard]] std::size_t group_source_count() const noexcept;
  [[nodiscard]] bool querier() const noexcept { return querier_; }
  [[nodiscard]] const packet::Ipv6 &querier_address() const noexcept {
    return querier_address_;
  }
  [[nodiscard]] std::uint8_t operational_version() const noexcept {
    return configuration_.version == 1U || older_querier_present_ ? 1U : 2U;
  }
  [[nodiscard]] const MldRouterConfiguration &configuration() const noexcept {
    return configuration_;
  }
  [[nodiscard]] const MldRouterStatistics &statistics() const noexcept {
    return statistics_;
  }

  [[nodiscard]] MldRouterCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool
  validate_checkpoint(const MldRouterCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(const MldRouterCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;

private:
  struct Source {
    packet::Ipv6 address{};
    Clock::time_point expires{Clock::time_point::max()};
    bool timer_running{};
  };

  struct PendingQuery {
    std::vector<packet::Ipv6> sources;
    Clock::time_point deadline{Clock::time_point::max()};
    std::uint8_t transmissions_remaining{};
    bool multicast_address_query{};
  };

  struct Group {
    packet::Ipv6 multicast_address{};
    std::vector<Source> sources;
    std::array<PendingQuery, 2U> pending_queries{};
    Clock::time_point filter_deadline{Clock::time_point::max()};
    Clock::time_point older_host_deadline{Clock::time_point::max()};
    MldFilterMode mode{MldFilterMode::include};
    bool filter_timer_running{};
    bool older_host_present{};
  };

  struct StaticGroup {
    packet::Ipv6 multicast_address{};
    std::vector<packet::Ipv6> sources;
    bool starg{};
  };

  MldRouterConfiguration configuration_{};
  std::vector<Group> groups_;
  std::vector<StaticGroup> static_groups_;
  Clock::time_point general_query_deadline_{Clock::time_point::max()};
  Clock::time_point other_querier_deadline_{Clock::time_point::max()};
  Clock::time_point older_querier_deadline_{Clock::time_point::max()};
  packet::Ipv6 querier_address_{};
  MldRouterStatistics statistics_{};
  std::uint8_t startup_queries_remaining_{};
  bool querier_{};
  bool other_querier_timer_running_{};
  bool older_querier_present_{};

  [[nodiscard]] Group *find(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] const Group *find(const packet::Ipv6 &group) const noexcept;
  [[nodiscard]] Group *ensure(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] StaticGroup *find_static(const packet::Ipv6 &group) noexcept;
  [[nodiscard]] const StaticGroup *
  find_static(const packet::Ipv6 &group) const noexcept;
  [[nodiscard]] Clock::duration multicast_address_listening_interval() const;
  [[nodiscard]] Clock::duration last_listener_query_time() const;
  void schedule_query(Group &group, bool multicast_address_query,
                      std::span<const packet::Ipv6> sources,
                      Clock::time_point now) noexcept;
  void expire(Clock::time_point now) noexcept;
};

} // namespace router::lab
