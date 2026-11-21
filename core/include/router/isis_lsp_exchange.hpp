// Circuit-local LSP egress retains only a version projection and receipt ticket.
// The control shard borrows its level database; forwarding owns queued frames.
// Scheduling and authenticated purge construction belong to the instance owner.

#pragma once

#include "router/isis_level_database.hpp"
#include "router/isis_pdu_composition.hpp"
#include "router/protocol_transmission.hpp"
#include "router/protocol_frame_expiry.hpp"

namespace router::isis {
enum class LspEmissionStatus : std::uint8_t {
  encoded, pending, ineligible, not_requested, purge_required, capacity, ticket_exhausted, too_large
};
struct LspTransmission {
  LspEmissionStatus status{LspEmissionStatus::not_requested};
  std::uint64_t ticket{};
  protocol::FrameExpiry expiry{};
};
struct LspReceipt { bool accepted{}; bool current_version{}; };
struct LspExchangeCheckpoint {
  std::uint32_t version{1U};
  packet::isis::PduType database_type{};
  std::size_t circuit{};
  protocol::TransmissionWindowCheckpoint transmission;
  std::optional<packet::isis::LspView> pending;
};
class LspExchange final {
public:
  // Database outlives this same-shard owner. Circuit slots are stable and epoch
  // is nonzero. Invalid inputs throw before publication; no allocation occurs.
  LspExchange(LevelDatabase &database, std::size_t circuit, std::uint64_t epoch);
  // Caller selected an SRM entry using its media-specific pacing/retry rules.
  // transit_seconds is at least one per ISO 10589 7.3.16.3. Aging to zero needs
  // the instance's finalized purge first. Existing authenticated options and
  // checksum survive lifetime rewriting. Scratch/output must not alias LSDB.
  // Only encoded permits dispatch. No LSDB bytes or key lease are retained.
  // too_large clears only the oversized circuit's SRM under ISO 7.3.15; the
  // parent must emit lSPTooLargeToPropagate. capacity preserves obligations.
  [[nodiscard]] LspTransmission prepare(const packet::isis::LspId &id,
      const packet::Mac &source, const packet::Mac &destination,
      std::size_t maximum_pdu_octets, std::uint16_t transit_seconds,
      packet::Frame &output, PduScratch &scratch, RuntimeClock::time_point now) noexcept;
  // Actual egress receipt must match this reservation. Refusal leaves SRM;
  // success clears LAN SRM only for the unchanged version. P2P retains SRM
  // until peer SNP acceptance. No caller may apply effects after false.
  [[nodiscard]] LspReceipt complete(std::uint64_t epoch, std::uint64_t ticket,
      bool enqueued, RuntimeClock::time_point now) noexcept;
  // Same circuit owner; the enclosing barrier separately captures queued
  // encoded frames and receipts. Idle scratch is omitted. No allocation occurs.
  [[nodiscard]] LspExchangeCheckpoint checkpoint() const noexcept;
  // Same quiesced owner with matching level, slot and epoch. The pending LSP
  // may legitimately have been superseded or retired in the LSDB. Structural
  // validation precedes mutation; false preserves the reservation and SRM.
  [[nodiscard]] bool restore(const LspExchangeCheckpoint &checkpoint) noexcept;
  [[nodiscard]] bool pending() const noexcept { return transmission_.pending(); }
  void cancel() noexcept;
  [[nodiscard]] bool replace_epoch(std::uint64_t epoch) noexcept;
private:
  LevelDatabase &database_;
  std::size_t circuit_{};
  protocol::TransmissionWindow transmission_;
  packet::isis::LspView pending_;
};
} // namespace router::isis
