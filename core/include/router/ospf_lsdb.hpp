// Per-instance OSPF link-state database. The protocol control shard is the
// sole mutable owner. Records contain complete encoded LSAs so flooding,
// database exchange and capture all use the same bytes that passed validation.

#pragma once

#include "router/ospf_packet.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ospf {

using RuntimeClock = std::chrono::steady_clock;

inline constexpr std::uint16_t max_age_seconds = 3600U;
inline constexpr std::uint16_t max_age_difference_seconds = 900U;
inline constexpr std::uint16_t checksum_check_age_seconds = 300U;
inline constexpr std::int32_t initial_sequence_number =
    static_cast<std::int32_t>(0x80000001U);
inline constexpr std::int32_t maximum_sequence_number = 0x7fffffff;

enum class FloodingScope : std::uint8_t {
  link,
  area,
  autonomous_system
};

struct LsaKey {
  std::uint32_t link_state_id{};
  std::uint32_t advertising_router{};
  std::uint16_t type{};
  FloodingScope scope{FloodingScope::area};

  [[nodiscard]] friend bool operator==(const LsaKey &,
                                       const LsaKey &) noexcept = default;
};

struct LsaRecord {
  LsaKey key;
  std::vector<std::uint8_t> bytes;
  RuntimeClock::time_point installed_at{};
  std::uint16_t age_at_install{};
  std::uint16_t last_checksum_check_age{};
  // The owner sets this only after the MaxAge generation has been placed on
  // every eligible adjacency retransmission list. Aging to 3600 seconds and
  // reliable flooding are separate operations: deleting a record merely
  // because its computed age reached MaxAge can prevent a slow neighbor from
  // ever learning the flush.
  bool max_age_flooded{};

  [[nodiscard]] std::uint16_t
  age(RuntimeClock::time_point now) const noexcept;
};

struct LsaRecordCheckpoint {
  LsaKey key;
  std::vector<std::uint8_t> bytes;
  std::uint16_t effective_age{};
  std::uint16_t last_checksum_check_age{};
  bool max_age_flooded{};
};

struct LinkStateDatabaseCheckpoint {
  std::vector<LsaRecordCheckpoint> records;
};

enum class InstallResult : std::uint8_t {
  installed,
  identical,
  older,
  too_soon,
  fight_back_required,
  ignored,
  malformed,
  capacity_exhausted
};

enum class LsaRecency : std::int8_t {
  older = -1,
  identical = 0,
  newer = 1
};

// Header comparison is shared by LSDB installation, database summaries and
// acknowledgment processing. Callers must supply the current effective ages,
// not stale age-at-install values retained in encoded storage.
[[nodiscard]] LsaRecency compare_lsa_headers(
    const packet::ospf::LsaHeaderView &candidate,
    const packet::ospf::LsaHeaderView &current) noexcept;
// Identity construction is shared by packet exchange and the database owner.
// Keeping scope decoding here prevents request handling from carrying a
// second interpretation of the OSPFv2 type table or OSPFv3 S2/S1 bits.
[[nodiscard]] LsaKey
lsa_key(const packet::ospf::LsaHeaderView &header) noexcept;

// RFC 2328 section 12.1.7 uses the Fletcher checksum over the complete LSA
// except LS age. update writes the two checksum octets in caller-owned storage.
[[nodiscard]] bool verify_lsa_checksum(
    std::span<const std::uint8_t> lsa) noexcept;
[[nodiscard]] bool
update_lsa_checksum(std::span<std::uint8_t> lsa) noexcept;

class LinkStateDatabase final {
public:
  // maximum_records is supplied by the active release and hardware resource
  // profile. Construction reserves once so ordinary installation cannot move
  // existing records or allocate a new vector control block in the hot path.
  explicit LinkStateDatabase(std::size_t maximum_records);

  // received_from_neighbor distinguishes a reflected self-originated LSA from
  // local origination. A reflected LSA requests fight-back and is never allowed
  // to overwrite the owner's authoritative local instance directly.
  [[nodiscard]] InstallResult
  install(std::span<const std::uint8_t> encoded_lsa, std::uint8_t version,
          RuntimeClock::time_point now, std::uint32_t local_router_id,
          bool received_from_neighbor) noexcept;

  [[nodiscard]] const LsaRecord *find(const LsaKey &key) const noexcept;
  [[nodiscard]] LsaRecord *find(const LsaKey &key) noexcept;
  // Transitioning to MaxAge does not alter the Fletcher checksum because RFC
  // 2328 excludes the first two LS age octets from that checksum. The process
  // owner must flood the returned generation before calling
  // mark_max_age_flooded().
  [[nodiscard]] bool premature_age(const LsaKey &key,
                                   RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool mark_max_age_flooded(const LsaKey &key) noexcept;
  // RFC CheckAge verifies an otherwise immutable LSA every five minutes of
  // effective age. false reports either a missing record or detected database
  // corruption; callers must retain the last complete route generation.
  [[nodiscard]] bool verify_checksum_at(
      const LsaKey &key, RuntimeClock::time_point now) noexcept;
  [[nodiscard]] bool erase(const LsaKey &key) noexcept;
  [[nodiscard]] std::span<const LsaRecord> records() const noexcept {
    return records_;
  }
  // Checkpoint ages are sampled against one caller-provided steady-clock
  // instant. Restore rebases those ages onto the new monotonic epoch, so a
  // browser suspension or process restart never advances protocol time.
  [[nodiscard]] LinkStateDatabaseCheckpoint
  checkpoint(RuntimeClock::time_point now) const;
  [[nodiscard]] bool restore(const LinkStateDatabaseCheckpoint &checkpoint,
                             std::uint8_t version,
                             RuntimeClock::time_point now) noexcept;

private:
  std::vector<LsaRecord> records_;
  std::size_t maximum_records_{};
};

} // namespace router::ospf
