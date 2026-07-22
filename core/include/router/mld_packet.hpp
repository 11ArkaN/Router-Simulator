// Allocation-free Multicast Listener Discovery wire contracts. This module
// owns ICMPv6 MLD framing and validation only. Listener and querier state
// machines remain with their interface owners and exchange complete frames.

#pragma once

#include "router/neighbor_discovery_packet.hpp"
#include "router/packet.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::mld {

inline constexpr std::uint8_t query_type = 130U;
inline constexpr std::uint8_t version_one_report_type = 131U;
inline constexpr std::uint8_t version_one_done_type = 132U;
inline constexpr std::uint8_t version_two_report_type = 143U;

extern const Ipv6 all_mldv2_routers;

enum class RecordType : std::uint8_t {
  mode_is_include = 1,
  mode_is_exclude = 2,
  change_to_include = 3,
  change_to_exclude = 4,
  allow_new_sources = 5,
  block_old_sources = 6
};

enum class RejectionReason : std::uint8_t {
  not_mld,
  bad_length,
  bad_checksum,
  unknown_type,
  bad_receive_interface,
  non_local_source,
  no_router_alert,
  bad_encoding
};

struct QueryView {
  // Source addresses remain encoded in the caller-owned Frame. Access through
  // query_source validates an index and copies one fixed 16-octet value.
  Ipv6 source{};
  Ipv6 destination{};
  Ipv6 multicast_address{};
  std::chrono::milliseconds maximum_response_delay{};
  std::chrono::seconds query_interval{};
  std::uint16_t source_count{};
  std::uint16_t source_offset{};
  std::uint8_t robustness_variable{};
  bool suppress_router_processing{};
  bool version_two{};
};

struct VersionOneView {
  Ipv6 source{};
  Ipv6 destination{};
  Ipv6 multicast_address{};
  std::chrono::milliseconds maximum_response_delay{};
  std::uint8_t type{};
};

struct ReportView {
  Ipv6 source{};
  Ipv6 destination{};
  std::uint16_t record_count{};
  std::uint16_t records_offset{};
};

struct RecordView {
  Ipv6 multicast_address{};
  std::uint16_t source_count{};
  std::uint16_t sources_offset{};
  std::uint16_t auxiliary_offset{};
  std::uint16_t auxiliary_octets{};
  RecordType type{RecordType::mode_is_include};
};

struct ReportRecord {
  RecordType type{RecordType::mode_is_include};
  Ipv6 multicast_address{};
  std::span<const Ipv6> sources{};
};

// All decoders require Hop Limit 1, a valid ICMPv6 checksum and the source
// address rules from RFC 3590 and RFC 3810. Router Alert is required by
// default. Passing false is reserved for an interface whose documented SR OS
// router-alert-check leaf is disabled; all other extension validation remains.
[[nodiscard]] std::optional<QueryView>
parse_query(const Frame &frame, bool require_router_alert = true) noexcept;
[[nodiscard]] std::optional<VersionOneView>
parse_version_one(const Frame &frame,
                  bool require_router_alert = true) noexcept;
[[nodiscard]] std::optional<ReportView>
parse_version_two_report(const Frame &frame,
                         bool require_router_alert = true) noexcept;
// diagnose_rejection is the counter-facing companion to the strict decoders.
// It never returns an accepted view and never relaxes packet processing. Its
// only purpose is to assign one SR OS statistics bucket to rejected bytes.
[[nodiscard]] RejectionReason
diagnose_rejection(const Frame &frame,
                   bool require_router_alert = true) noexcept;
[[nodiscard]] std::optional<RecordView>
report_record(const Frame &frame, const ReportView &report,
              std::size_t index) noexcept;
[[nodiscard]] std::optional<Ipv6> query_source(const Frame &frame,
                                               const QueryView &query,
                                               std::size_t index) noexcept;
[[nodiscard]] std::optional<Ipv6> record_source(const Frame &frame,
                                                const RecordView &record,
                                                std::size_t index) noexcept;

// Encoders return a complete Ethernet frame with an eight-octet Hop-by-Hop
// Router Alert header. Oversized record sets return nullopt and never emit a
// truncated report or allocate an unbounded temporary payload.
[[nodiscard]] std::optional<Frame> version_one_message(
    Mac source_mac, Ipv6 source, std::uint8_t type,
    const Ipv6 &multicast_address,
    std::chrono::milliseconds maximum_response_delay = {}) noexcept;
[[nodiscard]] std::optional<Frame>
version_two_report(Mac source_mac, Ipv6 source,
                   std::span<const ReportRecord> records) noexcept;
[[nodiscard]] std::optional<Frame>
version_two_query(Mac source_mac, Ipv6 source, const Ipv6 &multicast_address,
                  std::chrono::milliseconds maximum_response_delay,
                  std::uint8_t robustness_variable,
                  bool suppress_router_processing,
                  std::chrono::seconds query_interval,
                  std::span<const Ipv6> sources) noexcept;

} // namespace router::packet::mld
