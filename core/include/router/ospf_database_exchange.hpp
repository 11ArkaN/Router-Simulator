// Per-neighbor OSPF database exchange lists. The neighbor owner exclusively
// mutates summary, request, retransmission and delayed-acknowledgment state.
// LSDB records are copied as headers or keys, never retained by pointer.

#pragma once

#include "router/ospf_lsdb.hpp"
#include "router/ospf_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace router::ospf {

struct RetransmissionEntry {
  LsaKey key;
  std::int32_t sequence_number{};
  std::uint16_t checksum{};

  [[nodiscard]] friend bool
  operator==(const RetransmissionEntry &,
             const RetransmissionEntry &) noexcept = default;
};

struct NeighborDatabaseExchangeCheckpoint {
  std::vector<packet::ospf::LsaHeaderView> summaries;
  std::vector<packet::ospf::LinkStateRequestEntry> requests;
  std::vector<RetransmissionEntry> retransmissions;
  std::vector<packet::ospf::LsaHeaderView> acknowledgments;
  std::uint8_t version{};
  bool permit_autonomous_system_scope{true};
};

class NeighborDatabaseExchange final {
public:
  NeighborDatabaseExchange(std::size_t maximum_summaries,
                           std::size_t maximum_requests,
                           std::size_t maximum_retransmissions,
                           std::size_t maximum_acknowledgments);

  // begin rebuilds one database summary from the caller's area and applicable
  // AS or link scope. MaxAge records are excluded from DD summaries and remain
  // subject to ordinary flooding.
  [[nodiscard]] bool
  begin(std::span<const LsaRecord> records, std::uint8_t version,
        RuntimeClock::time_point now,
        bool permit_autonomous_system_scope = true) noexcept;

  // Every advertised header is compared with the local database. Missing or
  // newer instances enter the request list exactly once. Malformed DD payload
  // rejects the complete operation without partially extending that list.
  [[nodiscard]] bool
  process_database_description(
      const packet::ospf::DatabaseDescriptionView &description,
      const LinkStateDatabase &database,
      RuntimeClock::time_point now) noexcept;

  // An installed or identical LSU satisfies its matching request. Older and
  // malformed instances do not, preventing premature LoadingDone.
  void received_lsa(const packet::ospf::LsaHeaderView &header,
                    InstallResult result) noexcept;

  [[nodiscard]] bool queue_retransmission(const LsaRecord &record,
                                          std::uint8_t version,
                                          RuntimeClock::time_point now) noexcept;
  // Explicit and implied acknowledgments remove only an exact sequence and
  // checksum instance. A delayed acknowledgment for an older generation
  // cannot clear retransmission of a newly originated LSA with the same key.
  [[nodiscard]] bool
  acknowledge(const packet::ospf::LsaHeaderView &header) noexcept;

  [[nodiscard]] bool
  queue_delayed_acknowledgment(
      const packet::ospf::LsaHeaderView &header) noexcept;
  void clear_delayed_acknowledgments() noexcept {
    acknowledgments_.clear();
  }
  void consume_delayed_acknowledgments(std::size_t count) noexcept;
  void reset() noexcept;

  [[nodiscard]] std::span<const packet::ospf::LsaHeaderView>
  summaries() const noexcept {
    return summaries_;
  }
  [[nodiscard]] std::span<const packet::ospf::LinkStateRequestEntry>
  requests() const noexcept {
    return requests_;
  }
  [[nodiscard]] std::span<const RetransmissionEntry>
  retransmissions() const noexcept {
    return retransmissions_;
  }
  // MaxAge removal asks every adjacency whether the exact LSA identity is
  // still awaiting acknowledgment. Sequence and checksum are intentionally
  // ignored here: any queued generation with the same key keeps the database
  // record alive until reliable flooding has settled.
  [[nodiscard]] bool
  retransmits(const LsaKey &key) const noexcept;
  [[nodiscard]] std::span<const packet::ospf::LsaHeaderView>
  delayed_acknowledgments() const noexcept {
    return acknowledgments_;
  }
  [[nodiscard]] NeighborDatabaseExchangeCheckpoint checkpoint() const;
  [[nodiscard]] bool
  restore(const NeighborDatabaseExchangeCheckpoint &checkpoint) noexcept;

private:
  std::vector<packet::ospf::LsaHeaderView> summaries_;
  std::vector<packet::ospf::LinkStateRequestEntry> requests_;
  std::vector<RetransmissionEntry> retransmissions_;
  std::vector<packet::ospf::LsaHeaderView> acknowledgments_;
  std::size_t maximum_summaries_{};
  std::size_t maximum_requests_{};
  std::size_t maximum_retransmissions_{};
  std::size_t maximum_acknowledgments_{};
  std::uint8_t version_{};
  // RFC 2328 section 15 and RFC 5340 section 4.7 prohibit AS-scope database
  // summaries over a virtual adjacency. The policy is captured when exchange
  // starts so every later DD packet in that exchange applies the same rule.
  bool permit_autonomous_system_scope_{true};
};

} // namespace router::ospf
