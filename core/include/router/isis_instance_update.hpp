// One instance's update owner joins local P2P adjacency events to independent
// level databases. Peer information enters as encoded frames or synchronous
// events from this same control owner's authenticated Hello circuit.

#pragma once

#include "router/isis_level_process.hpp"
#include "router/isis_p2p_circuit.hpp"

#include <memory>

namespace router::isis {
struct UpdateLevelConfiguration {
  LsdbLimits database;
  std::size_t acknowledgement_capacity{}, snp_entry_capacity{}, receive_pdu_octets{};
  std::uint16_t maximum_age{};
  std::chrono::seconds purge_retention{}, waiting_time{};
  bool authenticate_lsp{}, authenticate_csnp{}, authenticate_psnp{};
};
struct UpdateCircuitConfiguration {
  std::uint64_t configuration_epoch{};
  Levels levels{Levels::none};
  bool physical_point_to_point{};
  packet::isis::InstanceFormat format{};
  std::uint16_t wire_instance{};
  std::array<packet::Mac, 2U> destinations{};
};
enum class UpdateStatus : std::uint8_t {
  applied, invalid_circuit, stale_configuration, invalid_event, epoch_exhausted,
  missing_observer, malformed, inactive, destination, instance, authentication,
  maximum_areas, receive_capacity, self_originated, level_refused, capacity, invalid_configuration
};
struct UpdateReceiveResult {
  UpdateStatus status{UpdateStatus::malformed};
  std::size_t level{};
  LevelLspResult lsp{};
  LevelSnpResult snp{};
  std::optional<packet::isis::LspView> local_lsp{};
};
struct UpdateOutputs {
  std::uint64_t synchronization_epoch{};
  LevelOutputs reservations;
};
struct UpdateCircuitAdmission {
  UpdateStatus status{UpdateStatus::invalid_configuration};
  LevelStatus level_status{LevelStatus::invalid_configuration};
  std::optional<std::size_t> index{};
  bool appended{};
  std::uint64_t configuration_epoch{};
  std::uint64_t ticket{};
  std::optional<UpdateCircuitConfiguration> previous_configuration{};
};
class InstanceUpdateProcess final {
public:
  // Every effective value is supplied by the configuration owner. Array index
  // zero selects L1, one L2. At least one level, nonzero configuration epochs,
  // legal level subsets and multicast destinations are mandatory. Construction
  // allocates before publication. The initial synchronization epoch must be
  // nonzero and exceed the parent-retained fence of any previous entity.
  // This contract currently admits P2P only.
  InstanceUpdateProcess(packet::isis::SystemId local, std::uint8_t maximum_areas,
      std::array<std::optional<UpdateLevelConfiguration>, 2U> levels,
      std::span<const UpdateCircuitConfiguration> circuits, std::size_t maximum_circuits = 0U,
      std::uint64_t initial_synchronization_epoch = 1U);
  InstanceUpdateProcess(const InstanceUpdateProcess &) = delete;
  InstanceUpdateProcess &operator=(const InstanceUpdateProcess &) = delete;
  // Same-owner cold admission, with no borrowed outputs outstanding. Zero
  // constructor budget fixes the initial count. Failure rolls back every level
  // and publishes no circuit; existing LSDBs and pending reservations survive.
  [[nodiscard]] UpdateCircuitAdmission admit_circuit(UpdateCircuitConfiguration configuration) noexcept;
  // Undo a successful cold admission in reverse admission order, before any
  // activation. Appended slots are removed from both levels; reused slots keep
  // their existing coordinators and fences. The token is consumed only once.
  [[nodiscard]] bool cancel_circuit_admission(UpdateCircuitAdmission &admission) noexcept;
  // Same-owner binding retirement after the authenticated circuit emitted Down.
  // Refuses live slots and stale epochs without mutation. Retains both level
  // slots, ticket counters and synchronization fences for bounded safe reuse.
  [[nodiscard]] UpdateStatus release_circuit(std::size_t circuit,
      std::uint64_t configuration_epoch) noexcept;
  // Commit-only binding replacement after release_circuit completed Down.
  // Requires a strictly newer transport epoch and prevalidated configuration.
  // No allocation or coordinator replacement; refuses before any mutation.
  [[nodiscard]] UpdateStatus rebind_circuit(std::size_t circuit,
      UpdateCircuitConfiguration configuration) noexcept;
  // Same-owner callback from PointToPointCircuit, before borrowed attributes
  // expire. The before state must match the previous event. Down cancels level
  // reservations; subsequent Up advances an independent synchronization epoch
  // without changing the transport configuration epoch. Exhaustion preserves
  // state and requires the enclosing instance to stop rather than reuse IDs.
  [[nodiscard]] UpdateStatus p2p(std::size_t circuit, std::uint64_t configuration_epoch,
      const P2pCircuitEvent &event, LevelObserver observer) noexcept;
  // Frame must be the actual ingress bytes for this circuit/configuration.
  // Performs level, destination, IID, adjacency, MRU, maximum-area and configured
  // authentication checks before LSDB mutation. Borrowed key expires on return.
  // self_originated is NOT successful processing: caller must perform local
  // fight-back/purge using local_lsp before accepting another mutation. The
  // returned header normalizes zero checksum to zero lifetime under ISO 7.3.14.
  [[nodiscard]] UpdateReceiveResult receive(std::size_t circuit,
      std::uint64_t configuration_epoch, const packet::Frame &frame,
      std::optional<AuthenticationKey> key, RuntimeClock::time_point now,
      LevelObserver observer) noexcept;
  // Local originator already selected sequence, semantic options and key. This
  // owner verifies level and local system identity before publishing the PDU.
  [[nodiscard]] LevelOriginResult originate(std::size_t level,
      std::span<const std::uint8_t> wire, RuntimeClock::time_point now,
      OriginPurgeReason purge, LevelObserver observer) noexcept;
  // Borrowed output references expire on a circuit event or owner destruction.
  // Queue receipts use this synchronization epoch and the exact reservation
  // ticket. Configuration epoch still guards the outer transport metadata.
  // Borrowers may prepare/complete/cancel output, never replace its epoch.
  [[nodiscard]] std::optional<UpdateOutputs> outputs(std::size_t circuit,
      std::size_t level) noexcept;
  [[nodiscard]] const LevelProcess *level(std::size_t index) const noexcept;
  // Same-owner value projection for entity replacement. The parent preserves
  // this fence outside the entity and starts its successor strictly above it;
  // no old reservation may match a reconstructed output owner's first ticket.
  [[nodiscard]] std::uint64_t maximum_synchronization_epoch() const noexcept;
private:
  struct Circuit {
    UpdateCircuitConfiguration configuration;
    std::array<std::uint64_t, 2U> synchronization_epochs{};
    std::array<bool, 2U> activated{};
    bool configured{true};
    bool admission_pending{};
    std::uint64_t admission_ticket{};
    Levels active{Levels::none};
    packet::Mac peer{};
  };
  packet::isis::SystemId local_{};
  std::uint8_t maximum_areas_{};
  std::array<std::optional<UpdateLevelConfiguration>, 2U> configuration_;
  std::array<std::unique_ptr<LevelProcess>, 2U> levels_;
  std::vector<Circuit> circuits_;
  std::size_t maximum_circuits_{};
  std::uint64_t initial_synchronization_epoch_{};
  std::uint64_t admission_ticket_{};
};
} // namespace router::isis
