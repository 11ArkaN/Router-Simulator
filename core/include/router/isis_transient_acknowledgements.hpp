// One IS-IS level owner retains bounded acknowledgements for unknown purges.
// These records never enter the LSDB or acquire SRM. The circuit owner selects
// the source-backed acknowledgement PDU and supplies actual egress receipts.

#pragma once

#include "router/isis_packet.hpp"

#include <vector>

namespace router::isis {
struct TransientAcknowledgement {
  packet::isis::SnpEntry entry;
  std::uint64_t ticket{};
};
enum class AcknowledgementAdmission : std::uint8_t {
  queued, duplicate, not_purge, capacity, ticket_exhausted
};
struct AcknowledgementResult {
  AcknowledgementAdmission status{AcknowledgementAdmission::capacity};
  std::uint64_t ticket{};
};
struct AcknowledgementSelection {
  std::size_t count{};
  std::optional<packet::isis::LspId> cursor;
};
class TransientAcknowledgements final {
public:
  // Capacity is an emulator budget, not a vendor scale claim. All metadata
  // reserves before publication. first_ticket is a checkpoint high-water mark;
  // zero is invalid. Construction may throw before the owner is published.
  explicit TransientAcknowledgements(std::size_t capacity, std::uint64_t first_ticket = 1U);
  // The level already accepted the purge's source, authentication and epoch.
  // entry carries effective lifetime, including zero-checksum normalization.
  // Exact duplicates share one obligation. Distinct versions retain distinct
  // tickets, so an old receipt cannot erase a newer purge acknowledgement.
  // Refusal changes nothing and must not be acknowledged by the caller.
  [[nodiscard]] AcknowledgementResult admit(std::size_t circuit,
      const packet::isis::SnpEntry &entry) noexcept;
  // Caller owns one outstanding PDU per circuit. Selection neither reserves
  // nor removes entries. It emits one version per ID, oldest admission first,
  // with cyclic ID fairness and ascending output suitable for SNP composition.
  // The caller preserves tickets beside its pending frame until completion.
  [[nodiscard]] AcknowledgementSelection select(std::size_t circuit,
      std::optional<packet::isis::LspId> cursor,
      std::span<TransientAcknowledgement> output) const noexcept;
  // Same-owner receipt after circuit-epoch acceptance. Failure retains the
  // obligation. Unknown tickets and receipts for another circuit reject.
  [[nodiscard]] bool complete(std::size_t circuit, std::uint64_t ticket, bool enqueued) noexcept;
  // Circuit Down invalidates pending obligations before its slot is reused.
  [[nodiscard]] std::size_t clear_circuit(std::size_t circuit) noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  [[nodiscard]] std::uint64_t next_ticket() const noexcept { return next_ticket_; }
private:
  struct Record {
    std::size_t circuit{};
    TransientAcknowledgement acknowledgement;
  };
  std::vector<Record> entries_;
  std::size_t capacity_{};
  std::uint64_t next_ticket_{};
};
} // namespace router::isis
