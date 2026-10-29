// Bounded encoded LSP repository for one level of one IS-IS instance. The
// dedicated control shard is its sole mutable owner. No peer, forwarding,
// runtime, UI or persistence object may access mutable records directly.

#pragma once

#include "router/isis_packet.hpp"

#include <chrono>
#include <vector>

namespace router::isis {

using RuntimeClock = std::chrono::steady_clock;
enum class LspRecency : std::uint8_t { older, identical, newer, confusion };

// Inputs carry effective lifetimes, not stale encoded install-time values.
// ISO 10589 7.3.16.4 purge processing takes precedence over checksum confusion.
// Unequal nonzero lifetimes do not refresh or rank otherwise identical LSPs.
[[nodiscard]] LspRecency compare_lsp_headers(const packet::isis::LspView &candidate,
                                             const packet::isis::LspView &current) noexcept;

struct LsdbLimits {
  std::size_t records{};
  std::size_t allocated_pdu_octets{};
};

enum class LspInstallResult : std::uint8_t {
  installed, identical, older, confusion, unknown_purge, malformed,
  invalid_checksum, excessive_lifetime, capacity_exhausted
};

struct StoredLspView {
  packet::isis::PduView pdu;
  packet::isis::LspView header;
  bool purge_installed{};
};

enum class LspDeadlineKind : std::uint8_t { finalize_expiration, retire_purge };
struct LspDeadline {
  packet::isis::LspId id{};
  RuntimeClock::time_point at{};
  LspDeadlineKind kind{};
};

class LinkStateDatabase final {
public:
  // Reserves metadata once. type must be LSP L1 or L2, otherwise throws
  // invalid_argument; allocation failure throws bad_alloc before publication.
  // PDU storage grows only when accepting a new or larger advertisement.
  explicit LinkStateDatabase(packet::isis::PduType type, LsdbLimits limits);

  // Preconditions: wire passed instance, circuit, adjacency, authentication,
  // purge-policy and self-originated fight-back checks in the process owner.
  // Validates envelope and active-LSP checksum before mutation. A zero checksum
  // has effective lifetime zero per ISO 10589 7.3.14. Unknown purges are not
  // retained; their acknowledgement remains the process owner's obligation.
  // Capacity failure preserves every record and must not be acknowledged.
  // A shorter replacement reuses its allocation even when the budget is full.
  // purge_retention is ZeroAgeLifetime for received/expired purges, or MaxAge
  // for an initiated non-expiration purge. It is a source-selected wire-sized
  // duration, not a global simulation timer. Runs only on the owning shard.
  [[nodiscard]] LspInstallResult install(std::span<const std::uint8_t> wire,
      RuntimeClock::time_point now, std::uint16_t maximum_age,
      std::chrono::seconds purge_retention) noexcept;

  // Views borrow repository bytes until the next mutation. Effective lifetime
  // is a value projection using owner-local steady time; encoded bytes remain
  // the exact accepted PDU except zero-checksum lifetime normalization.
  [[nodiscard]] std::optional<StoredLspView> find(const packet::isis::LspId &id,
                                                RuntimeClock::time_point now) const noexcept;
  [[nodiscard]] std::optional<StoredLspView> at(std::size_t index,
                                              RuntimeClock::time_point now) const noexcept;
  // Same-owner value projection, without allocation or a borrowed record.
  // Active expiration requires finalized purge construction before removal;
  // installed purges retain their selected retention deadline. Equal times
  // select the lowest LSP ID. A due item remains due until the owner handles it.
  [[nodiscard]] std::optional<LspDeadline> next_deadline() const noexcept;

  // Only an installed purge whose retention deadline passed can be removed.
  // An active LSP that merely aged to zero must first pass the process owner's
  // authenticated purge construction, flooding and replacement path.
  [[nodiscard]] bool retire_purge(const packet::isis::LspId &id,
                                  RuntimeClock::time_point now) noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return records_.size(); }
  [[nodiscard]] std::size_t allocated_octets() const noexcept { return allocated_octets_; }

private:
  struct Record {
    packet::isis::LspView header;
    std::vector<std::uint8_t> bytes;
    RuntimeClock::time_point installed_at{};
    RuntimeClock::time_point retire_at{};
    bool purge_installed{};
  };
  [[nodiscard]] StoredLspView view(const Record &record, RuntimeClock::time_point now) const noexcept;
  packet::isis::PduType type_;
  LsdbLimits limits_;
  std::vector<Record> records_;
  std::size_t allocated_octets_{};
};

} // namespace router::isis
