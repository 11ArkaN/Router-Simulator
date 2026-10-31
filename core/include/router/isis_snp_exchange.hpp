// One circuit-level owner coordinates SNP composition and exact egress receipts.
// It borrows the same control shard's level database and transient obligations;
// those owners outlive it. No peer state, frame queue or key lease is retained.

#pragma once

#include "router/isis_csnp_sequence.hpp"
#include "router/isis_snp_builder.hpp"
#include "router/isis_transient_acknowledgements.hpp"
#include "router/protocol_transmission.hpp"

namespace router::isis {
enum class SnpEmission : std::uint8_t { complete, partial, transient_acknowledgement };
enum class SnpExchangeStatus : std::uint8_t {
  encoded, idle, pending, ineligible, role_forbidden, invalid_configuration,
  capacity, composition_failed, ticket_exhausted, inconsistent_database
};
struct SnpTransmission {
  SnpExchangeStatus status{SnpExchangeStatus::idle};
  std::uint64_t ticket{};
  SnpBuildResult composition{SnpBuildResult::encoded};
};
struct SnpCompletion {
  bool accepted{};
  std::size_t retired{};
  std::size_t superseded{};
};
class SnpExchange final {
public:
  // All state uses this control owner's affinity. A valid stable circuit and
  // nonzero epoch are required. Entry scratch allocates before publication.
  // Capacity must cover the exact wire budget supplied during prepare().
  SnpExchange(LevelDatabase &database, TransientAcknowledgements &acknowledgements,
      std::size_t circuit, std::uint64_t epoch, std::size_t entry_capacity);
  SnpExchange(const SnpExchange &) = delete;
  SnpExchange &operator=(const SnpExchange &) = delete;
  SnpExchange(SnpExchange &&) noexcept = default;
  SnpExchange &operator=(SnpExchange &&) = delete;
  void request_complete() noexcept { complete_.request(); }
  // Parent supplies policy-accepted envelope, authentication lease and current
  // DIS role at its source-backed timer or immediate-ack trigger. Only encoded
  // permits frame dispatch. No flag, cursor or acknowledgement retires here.
  // One outstanding SNP serializes this circuit's three emission classes.
  [[nodiscard]] SnpTransmission prepare(SnpEmission emission, SnpContents contents,
      bool designated, packet::Frame &output, PduScratch &scratch,
      RuntimeClock::time_point now) noexcept;
  // Actual forwarding receipt must match both epoch and transmission ticket.
  // Stale LSP versions retain their new obligations. Refusal keeps scan cursors
  // and CSNP ranges for retry. No input packet or key view survives this call.
  [[nodiscard]] SnpCompletion complete(std::uint64_t epoch, std::uint64_t ticket,
      bool enqueued, RuntimeClock::time_point now) noexcept;
  // Role loss cancels pending output without clearing obligations or rewinding
  // tickets. A new DIS starts a fresh complete sequence through request_complete.
  void cancel() noexcept;
  // Parent completed circuit Down and revoked the old forwarding projection.
  // A strictly newer configuration epoch clears transient circuit obligations.
  [[nodiscard]] bool replace_epoch(std::uint64_t epoch) noexcept;
  [[nodiscard]] bool pending() const noexcept { return transmission_.pending(); }
private:
  LevelDatabase &database_;
  TransientAcknowledgements &acknowledgements_;
  std::size_t circuit_{};
  protocol::TransmissionWindow transmission_;
  CompleteSnpSequence complete_;
  std::optional<SnpEmission> pending_emission_;
  std::optional<packet::isis::LspId> partial_cursor_, acknowledgement_cursor_, pending_cursor_;
  std::vector<packet::isis::SnpEntry> entries_;
  std::vector<TransientAcknowledgement> acknowledgement_entries_;
  std::size_t pending_count_{};
};
} // namespace router::isis
