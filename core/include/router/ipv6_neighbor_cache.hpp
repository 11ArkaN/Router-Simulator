// Forwarding-owner IPv6 Neighbor Cache and RFC 4861 reachability state. One
// instance belongs to one router or host stack. It owns every mutable entry and
// emits actions for its caller to encode as ND frames through the normal port,
// queue and link path.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ip_address.hpp"
#include "router/packet.hpp"

#include <chrono>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab {

enum class Ipv6NeighborState : std::uint8_t {
  incomplete,
  reachable,
  stale,
  delay,
  probe
};

enum class Ipv6UnsolicitedLearning : std::uint8_t {
  // Standard RFC 4861 behavior does not create a cache entry from an NA when
  // no entry exists. The other values are explicit SR OS interface policy.
  none,
  global,
  link_local,
  both
};

enum class Ipv6ResolutionStatus : std::uint8_t {
  resolved,
  solicitation_required,
  pending,
  table_full
};

struct Ipv6Resolution {
  Ipv6ResolutionStatus status{Ipv6ResolutionStatus::pending};
  packet::Mac mac{};
};

enum class Ipv6NeighborActionKind : std::uint8_t {
  multicast_solicitation,
  unicast_solicitation,
  resolution_failed
};

struct Ipv6NeighborAction {
  // The owner returns a value action rather than invoking a link directly.
  // Forwarding encodes the appropriate NS frame and enqueues it after the
  // current owner turn, preserving bounded shard and link backpressure.
  Ipv6NeighborActionKind kind{Ipv6NeighborActionKind::resolution_failed};
  // RFC 4007 scopes link-local neighbors to an IP interface, not to a piece
  // of hardware. A 64-bit logical identity therefore keeps two tagged SAPs
  // on the same physical port in independent Neighbor Cache zones.
  std::uint64_t interface_id{};
  ip::Ipv6 address{};
  packet::Mac mac{};
};

struct Ipv6NeighborSnapshot {
  std::uint64_t interface_id{};
  ip::Ipv6 address{};
  packet::Mac mac{};
  Ipv6NeighborState state{Ipv6NeighborState::incomplete};
  bool is_router{};
  bool is_static{};
};

struct Ipv6NeighborCheckpoint {
  // steady_clock epochs are process-local and never serialized. A finite
  // deadline is stored as remaining time and re-anchored when the forwarding
  // owner restores this entry on its destination worker.
  std::uint64_t interface_id{};
  ip::Ipv6 address{};
  packet::Mac mac{};
  Ipv6NeighborState state{Ipv6NeighborState::incomplete};
  bool is_router{};
  bool is_static{};
  bool has_deadline{};
  std::uint8_t probes_sent{};
  std::uint64_t use_generation{};
  std::int64_t remaining_nanoseconds{};
  // These are the effective per-interface SR OS timers at the time the entry
  // was checkpointed. Retaining them lets a restored STALE entry continue the
  // same vendor aging and proactive-refresh behavior without consulting
  // control-plane state from the forwarding owner.
  std::uint32_t stale_time_seconds{
      device_catalog::nd_default_stale_time_seconds};
  bool proactive_refresh{};
};

enum class Ipv6NeighborBatchKind : std::uint8_t { learn_stale, remove_dynamic };

struct Ipv6NeighborBatchEdit {
  // Batch edits are value-only instructions owned by the caller until commit.
  // They exist for protocols such as DHCPv6 whose one Reply can atomically
  // add, replace and withdraw several Neighbor Cache mappings.
  Ipv6NeighborBatchKind kind{Ipv6NeighborBatchKind::learn_stale};
  std::uint64_t interface_id{};
  ip::Ipv6 address{};
  packet::Mac mac{};
  std::chrono::seconds stale_time{std::chrono::seconds{
      device_catalog::nd_default_stale_time_seconds}};
  bool proactive_refresh{};
};

class Ipv6NeighborCache final {
public:
  using Clock = std::chrono::steady_clock;

  Ipv6NeighborCache();

  // resolve() is called when forwarding needs a link-layer address. A new
  // entry requests exactly one initial multicast NS. The caller owns pending
  // packets and must not send them until resolved is returned later.
  [[nodiscard]] Ipv6Resolution
  resolve(std::uint64_t interface_id, const ip::Ipv6 &address,
          Clock::time_point now = Clock::now(),
          std::chrono::seconds stale_time = std::chrono::seconds{
              device_catalog::nd_default_stale_time_seconds},
          bool proactive_refresh = false) noexcept;

  // A valid received NA updates only an existing entry, matching RFC 4861
  // section 7.2.5. reachable_time is the interface's randomized reachable
  // interval, not a process-global constant.
  [[nodiscard]] bool receive_advertisement(
      std::uint64_t interface_id, const ip::Ipv6 &address,
      std::optional<packet::Mac> target_link_layer, bool solicited,
      bool override_flag, bool is_router, bool learn_unsolicited,
      std::chrono::milliseconds reachable_time,
      Clock::time_point now = Clock::now(),
      std::chrono::seconds stale_time = std::chrono::seconds{
          device_catalog::nd_default_stale_time_seconds},
      bool proactive_refresh = false) noexcept;

  // NS, RS, RA and Redirect messages with a validated link-layer option can
  // create or refresh a STALE entry. This learning path never marks a neighbor
  // reachable because receipt alone does not confirm two-way reachability.
  [[nodiscard]] bool learn_stale(std::uint64_t interface_id,
                                 const ip::Ipv6 &address, packet::Mac mac,
                                 bool is_router,
                                 Clock::time_point now = Clock::now(),
                                 std::chrono::seconds stale_time =
                                     std::chrono::seconds{
                                         device_catalog::
                                             nd_default_stale_time_seconds},
                                 bool proactive_refresh = false) noexcept;

  // The entire edit list is validated and all required vector/index capacity
  // is obtained before the first live entry changes. false therefore leaves
  // the cache unchanged. Duplicate scoped keys are rejected because their
  // ordering would otherwise become an undocumented conflict policy.
  [[nodiscard]] bool apply_batch(
      std::span<const Ipv6NeighborBatchEdit> edits,
      Clock::time_point now = Clock::now()) noexcept;

  // Static mappings are configuration intent and therefore bypass NUD while
  // still living in the same forwarding-owned lookup table. A successful
  // install replaces a dynamic entry for the same scoped address atomically.
  [[nodiscard]] bool install_static(std::uint64_t interface_id,
                                    const ip::Ipv6 &address,
                                    packet::Mac mac) noexcept;
  [[nodiscard]] bool remove_static(std::uint64_t interface_id,
                                   const ip::Ipv6 &address) noexcept;
  // Operational reset never erases configured static mappings. Optional
  // scope keys correspond to the classic clear and MD reset selectors. The
  // removed count is useful to tests and diagnostics, but an empty selection
  // remains a valid idempotent reset. It does not mean the command is an
  // unimplemented successful no-op: the real cache owner evaluated the exact
  // selector and found no dynamic operational state to erase.
  [[nodiscard]] std::size_t clear_dynamic(
      std::optional<std::uint64_t> interface_id = std::nullopt,
      std::optional<ip::Ipv6> address = std::nullopt) noexcept;

  // Positive upper-layer feedback such as acknowledged TCP data may confirm
  // reachability without sending another probe. The caller supplies the same
  // per-interface randomized duration used for a solicited NA.
  [[nodiscard]] bool confirm_reachability(
      std::uint64_t interface_id, const ip::Ipv6 &address,
      std::chrono::milliseconds reachable_time,
      Clock::time_point now = Clock::now()) noexcept;

  // poll() advances only due entries and writes bounded actions. When output is
  // full, a due entry remains due so overload cannot silently skip a probe or
  // failure notification.
  [[nodiscard]] std::size_t
  poll(Clock::time_point now, std::span<Ipv6NeighborAction> output) noexcept;

  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::optional<Ipv6NeighborSnapshot>
  find(std::uint64_t interface_id, const ip::Ipv6 &address) const noexcept;
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] std::size_t
  dynamic_size(std::uint64_t interface_id) const noexcept;
  void remove_interface(std::uint64_t interface_id) noexcept;

  // Checkpoint operations are cold forwarding-owner operations. The returned
  // vector owns its values and retains no pointers into the fixed cache arena.
  // restore validates the complete image before changing live state.
  [[nodiscard]] std::vector<Ipv6NeighborCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      std::span<const Ipv6NeighborCheckpoint> state) noexcept;
  [[nodiscard]] bool restore(
      std::span<const Ipv6NeighborCheckpoint> state,
      Clock::time_point now = Clock::now()) noexcept;

private:
  struct Entry {
    bool valid{};
    bool is_router{};
    bool is_static{};
    std::uint64_t interface_id{};
    ip::Ipv6 address{};
    packet::Mac mac{};
    Ipv6NeighborState state{Ipv6NeighborState::incomplete};
    std::uint8_t probes_sent{};
    std::uint64_t use_generation{};
    Clock::time_point deadline{Clock::time_point::max()};
    std::chrono::seconds stale_time{std::chrono::seconds{
        device_catalog::nd_default_stale_time_seconds}};
    bool proactive_refresh{};
  };

  enum class IndexState : std::uint8_t { empty, occupied, tombstone };

  struct IndexSlot {
    // The index is a derived hot-path accelerator. Entry values remain the
    // authoritative state and are the only representation serialized.
    std::uint64_t hash{};
    std::uint32_t entry_index{};
    IndexState state{IndexState::empty};
  };

  [[nodiscard]] Entry *entry(std::uint64_t interface_id,
                             const ip::Ipv6 &address) noexcept;
  [[nodiscard]] const Entry *entry(std::uint64_t interface_id,
                                   const ip::Ipv6 &address) const noexcept;
  [[nodiscard]] Entry *allocate(Clock::time_point now) noexcept;
  [[nodiscard]] static std::uint64_t key_hash(
      std::uint64_t interface_id, const ip::Ipv6 &address) noexcept;
  [[nodiscard]] std::optional<std::size_t> index_lookup(
      std::uint64_t interface_id, const ip::Ipv6 &address) const noexcept;
  [[nodiscard]] bool ensure_index_capacity(std::size_t active) noexcept;
  [[nodiscard]] bool index_insert(std::size_t entry_index) noexcept;
  void index_erase(std::uint64_t interface_id,
                   const ip::Ipv6 &address) noexcept;
  void erase_entry(Entry &entry) noexcept;
  void mark_reachable(Entry &entry, std::chrono::milliseconds reachable_time,
                      Clock::time_point now) noexcept;
  void mark_stale(Entry &entry, std::chrono::seconds stale_time,
                  bool proactive_refresh, Clock::time_point now) noexcept;
  void touch(Entry &entry) noexcept;
  void trim_unused_tail() noexcept;

  // Capacity is a release limit, not an instruction to allocate every possible
  // entry for every router. The vector grows only on a cache miss and reuses
  // holes before growth. Ordinary resolved forwarding performs no allocation,
  // while sixteen sparse routers do not consume sixteen maximum-size arenas.
  std::vector<Entry> entries_;
  // Open addressing keeps resolved lookups allocation-free and cache-local.
  // At most half of the slots are occupied, guaranteeing bounded successful
  // insertion even when tombstones from churn are present. Capacity grows
  // geometrically from a small sparse-router footprint.
  std::vector<IndexSlot> index_;
  // Per-interface admission is queried only while creating an entry. Counting
  // the sparse arena at that point avoids a second dynamically allocated map
  // and, unlike an array indexed by port ordinal, supports arbitrary stable
  // service-interface identities without imposing a guessed platform limit.
  std::size_t indexed_entries_{};
  std::uint64_t use_generation_{};
};

} // namespace router::lab
