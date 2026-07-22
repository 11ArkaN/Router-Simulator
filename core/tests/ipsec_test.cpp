// IPsec owner tests cover ordered SPD selection, RFC 4303 longest SAD lookup,
// AH and ESP structural safety, sequence exhaustion and replay behavior. They
// use explicit state and do not sleep or substitute a simulated clock.

#include "router/ipsec_forwarding_security.hpp"
#include "router/ipsec_packet.hpp"
#include "router/ipsec_policy.hpp"
#include "router/ipsec_replay.hpp"
#include "router/ipsec_sad.hpp"

#include <array>
#include <chrono>
#include <limits>
#include <optional>
#include <stdexcept>

namespace {

router::ipsec::Address ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                            std::uint8_t d) {
  router::ipsec::Address result{};
  result.family = router::ipsec::AddressFamily::ipv4;
  result.bytes[0] = a;
  result.bytes[1] = b;
  result.bytes[2] = c;
  result.bytes[3] = d;
  return result;
}

router::ipsec::Address ipv6(std::uint8_t subnet, std::uint8_t host) {
  router::ipsec::Address result{};
  result.family = router::ipsec::AddressFamily::ipv6;
  result.bytes[0] = 0x20U;
  result.bytes[1] = 0x01U;
  result.bytes[2] = 0x0dU;
  result.bytes[3] = 0xb8U;
  result.bytes[7] = subnet;
  result.bytes[15] = host;
  return result;
}

router::ipsec::Policy protect_policy(std::uint32_t id,
                                     std::uint32_t priority) {
  using namespace router::ipsec;
  Policy policy{};
  policy.id = id;
  policy.priority = priority;
  policy.direction = Direction::outbound;
  policy.action = PolicyAction::protect;
  policy.proposal_id = 9U;
  policy.selector.source = {.network = ipv4(10, 0, 0, 0), .length = 24U};
  policy.selector.destination = {
      .network = ipv4(192, 0, 2, 0), .length = 24U};
  policy.selector.upper_layer_protocol = 17U;
  policy.selector.source_ports = {.first = 1000U, .last = 2000U};
  policy.selector.destination_ports = {.first = 53U, .last = 53U};
  return policy;
}

} // namespace

void ipsec_tests() {
  using namespace router::ipsec;

  // The lower numeric priority wins even when it is installed later. A rule
  // with the wrong direction must not affect the selected outbound action.
  Spd policies{3U};
  auto broad = protect_policy(20U, 200U);
  auto preferred = protect_policy(10U, 100U);
  if (policies.install(broad) != PolicyInstallResult::installed ||
      policies.install(preferred) != PolicyInstallResult::installed)
    throw std::runtime_error("valid IPsec policies were not installed");
  PacketSelector dns_packet{.source = ipv4(10, 0, 0, 8),
                            .destination = ipv4(192, 0, 2, 53),
                            .upper_layer_protocol = 17U,
                            .source_port = 1400U,
                            .destination_port = 53U};
  const auto selected = policies.lookup(Direction::outbound, dns_packet);
  if (!selected || selected->id != preferred.id ||
      policies.lookup(Direction::inbound, dns_packet))
    throw std::runtime_error("ordered IPsec SPD lookup selected wrong policy");

  // Checkpoint restore rebuilds indexes in a detached owner. A noncanonical
  // order is rejected without replacing the existing policy set, while the
  // canonical value produces the same first-match decision after restore.
  const auto saved_spd = policies.checkpoint();
  Spd restored_policies{3U};
  if (!restored_policies.restore(saved_spd) ||
      !restored_policies.lookup(Direction::outbound, dns_packet) ||
      restored_policies.lookup(Direction::outbound, dns_packet)->id !=
          preferred.id)
    throw std::runtime_error("IPsec SPD checkpoint did not rebuild lookup order");
  auto noncanonical_spd = saved_spd;
  std::swap(noncanonical_spd.policies[0U], noncanonical_spd.policies[1U]);
  if (restored_policies.restore(noncanonical_spd) ||
      restored_policies.lookup(Direction::outbound, dns_packet)->id !=
          preferred.id)
    throw std::runtime_error("invalid SPD checkpoint partially changed state");

  // A protect rule without a proposal and a wildcard protocol with a fake port
  // restriction would both misrepresent policy semantics and must be atomic
  // validation failures.
  auto invalid = preferred;
  invalid.id = 30U;
  invalid.proposal_id = 0U;
  if (policies.install(invalid) != PolicyInstallResult::invalid)
    throw std::runtime_error("protect policy without proposal was accepted");
  invalid = preferred;
  invalid.id = 30U;
  invalid.selector.upper_layer_protocol = 0U;
  if (policies.install(invalid) != PolicyInstallResult::invalid)
    throw std::runtime_error("wildcard protocol retained a port restriction");

  // Prefix canonicalization is validated rather than silently rewriting user
  // intent. Both IPv4 tail bytes and host bits belong to this invariant.
  Prefix noncanonical{.network = ipv4(10, 0, 0, 1), .length = 24U};
  if (valid_prefix(noncanonical) ||
      !prefix_contains(Prefix{.network = ipv6(4U, 0U), .length = 64U},
                       ipv6(4U, 7U)))
    throw std::runtime_error("IPsec selector prefix validation failed");

  // Anti-replay precheck cannot change state before authentication. Once the
  // candidate is committed, duplicates are rejected and a newer sequence moves
  // the bounded window without accepting a packet outside its left edge.
  ReplayWindow replay{64U, false};
  const auto first = replay.check(1U);
  if (first.status != ReplayStatus::admissible || replay.highest() != 0U ||
      !replay.commit(first.sequence) ||
      replay.check(1U).status != ReplayStatus::duplicate ||
      !replay.commit(70U) ||
      replay.check(1U).status != ReplayStatus::too_old)
    throw std::runtime_error("IPsec replay window transition failed");

  // ESN sends only low32. At rollover, low zero reconstructs as the next
  // sequence subspace and becomes 2^32 only after authenticated commitment.
  ReplayWindow esn{64U, true};
  if (!esn.restore(0xffffffffULL, 1U))
    throw std::runtime_error("ESN checkpoint setup was rejected");
  const auto rollover = esn.check(0U);
  if (rollover.status != ReplayStatus::admissible ||
      rollover.sequence != 0x100000000ULL ||
      !esn.commit(rollover.sequence))
    throw std::runtime_error("ESN high word was reconstructed incorrectly");

  OutboundSequence short_sequence{false};
  if (!short_sequence.restore(
          std::numeric_limits<std::uint32_t>::max() - 1ULL) ||
      short_sequence.next() != std::numeric_limits<std::uint32_t>::max() ||
      short_sequence.next())
    throw std::runtime_error("32-bit IPsec sequence wrapped instead of expiring");

  // RFC 4303 requires the most specific inbound identifier. Three entries use
  // one SPI and demonstrate source+destination, destination and SPI fallback.
  Sad associations{4U};
  SecurityAssociation fallback{};
  fallback.id = 1U;
  fallback.inbound_identifier = {
      .spi = 0x10203040U,
      .protocol = SecurityProtocol::esp,
      .destination = std::nullopt,
      .source = std::nullopt};
  fallback.integrity = IntegrityAlgorithm::hmac_sha256_128;
  fallback.crypto_material_handle = 1U;
  fallback.policy_id = 1U;
  SecurityAssociation destination = fallback;
  destination.id = 2U;
  destination.inbound_identifier.destination = ipv4(192, 0, 2, 1);
  SecurityAssociation source_destination = destination;
  source_destination.id = 3U;
  source_destination.inbound_identifier.source = ipv4(198, 51, 100, 1);
  if (associations.install(fallback) != SaInstallResult::installed ||
      associations.install(destination) != SaInstallResult::installed ||
      associations.install(source_destination) != SaInstallResult::installed)
    throw std::runtime_error("valid IPsec SAs were not installed");
  const auto exact = associations.find_inbound(
      SecurityProtocol::esp, 0x10203040U, ipv4(192, 0, 2, 1),
      ipv4(198, 51, 100, 1));
  const auto destination_only = associations.find_inbound(
      SecurityProtocol::esp, 0x10203040U, ipv4(192, 0, 2, 1),
      ipv4(198, 51, 100, 2));
  if (!exact || exact->id != 3U || !destination_only ||
      destination_only->id != 2U)
    throw std::runtime_error("IPsec SAD longest identifier lookup failed");

  // Structural parsers expose only the lookup fields and opaque protected
  // bytes. Reserved AH bits, zero SPI and IPv6 misalignment are rejected before
  // an untrusted Next Header can influence local protocol dispatch.
  const std::array<std::uint8_t, 16> ah{
      58U, 2U, 0U, 0U, 0x10U, 0x20U, 0x30U, 0x40U,
      0U, 0U, 0U, 1U, 0xaaU, 0xbbU, 0xccU, 0xddU};
  const auto ah_view = parse_ah(ah, true);
  if (!ah_view || ah_view->next_header != 58U ||
      ah_view->spi != 0x10203040U || ah_view->sequence_low != 1U ||
      ah_view->icv.size() != 4U)
    throw std::runtime_error("valid aligned AH was not parsed");
  auto invalid_ah = ah;
  invalid_ah[2] = 1U;
  if (parse_ah(invalid_ah, true))
    throw std::runtime_error("AH reserved bits were accepted");

  const std::array<std::uint8_t, 12> esp{
      0x10U, 0x20U, 0x30U, 0x40U, 0U, 0U, 0U, 7U,
      0xdeU, 0xadU, 0xbeU, 0xefU};
  const auto esp_view = parse_esp(esp);
  if (!esp_view || esp_view->spi != 0x10203040U ||
      esp_view->sequence_low != 7U ||
      esp_view->protected_payload.size() != 4U)
    throw std::runtime_error("valid ESP lookup fields were not parsed");

  // A CHILD SA pair is one forwarding transaction. Replacing its inbound half
  // and then exhausting capacity on the outbound half must restore the exact
  // previous inbound metadata instead of leaving asymmetric protection.
  Sad pair_database{2U};
  SecurityAssociation pair_inbound = fallback;
  pair_inbound.id = 10U;
  SecurityAssociation pair_outbound = fallback;
  pair_outbound.id = 11U;
  pair_outbound.outbound = true;
  const auto installed_pair =
      pair_database.install_pair(pair_inbound, pair_outbound);
  if (!installed_pair.committed || pair_database.size() != 2U)
    throw std::runtime_error("IPsec CHILD SA pair was not installed atomically");
  pair_outbound.id = 12U;
  // A rekey allocates a fresh SPI. Reusing the live SPI would correctly fail
  // as an identifier conflict before the capacity branch and would not test
  // the intended atomic behavior under resource exhaustion.
  pair_outbound.inbound_identifier.spi = 0x66778899U;
  pair_outbound.created_at += std::chrono::seconds{1};
  const auto rejected_rekey = pair_database.install(pair_outbound);
  const auto *selected_outbound = pair_database.find_outbound_for_policy(
      pair_inbound.policy_id, SecurityProtocol::esp);
  if (rejected_rekey != SaInstallResult::capacity_exhausted ||
      !selected_outbound || selected_outbound->id != 11U)
    throw std::runtime_error("IPsec outbound SA policy selection changed on failed rekey");
  pair_outbound.id = 11U;
  pair_outbound.inbound_identifier.spi = 0x10203040U;
  pair_outbound.created_at -= std::chrono::seconds{1};
  auto replacement_inbound = pair_inbound;
  replacement_inbound.inbound_identifier.spi = 0x55667788U;
  auto extra_outbound = pair_outbound;
  extra_outbound.id = 12U;
  extra_outbound.inbound_identifier.spi = 0x55667788U;
  const auto rejected_pair =
      pair_database.install_pair(replacement_inbound, extra_outbound);
  const auto *restored_inbound = pair_database.find(10U);
  if (rejected_pair.committed || !restored_inbound ||
      restored_inbound->inbound_identifier.spi != 0x10203040U ||
      pair_database.find(12U))
    throw std::runtime_error("failed CHILD SA pair changed the live SAD");
  if (pair_database.erase_pair(pair_inbound.id, 999U) !=
          SaPairEraseResult::missing ||
      pair_database.size() != 2U)
    throw std::runtime_error("partial CHILD SA delete changed the SAD");
  if (pair_database.erase_pair(pair_inbound.id, pair_outbound.id) !=
          SaPairEraseResult::erased ||
      pair_database.size() != 0U)
    throw std::runtime_error("atomic CHILD SA pair deletion failed");

  if (!pair_database.install_pair(pair_inbound, pair_outbound).committed)
    throw std::runtime_error("SAD checkpoint fixture could not reinstall pair");
  auto *checkpoint_outbound = pair_database.find_outbound(pair_outbound.id);
  Address checkpoint_destination{};
  Address checkpoint_source{};
  checkpoint_destination.bytes[0U] = 192U;
  checkpoint_source.bytes[0U] = 198U;
  auto *checkpoint_inbound = pair_database.find_inbound(
      SecurityProtocol::esp, pair_inbound.inbound_identifier.spi,
      checkpoint_destination, checkpoint_source);
  if (!checkpoint_outbound || !checkpoint_inbound ||
      !checkpoint_outbound->outbound_sequence.next() ||
      !checkpoint_outbound->outbound_sequence.next())
    throw std::runtime_error("SAD checkpoint sequence fixture failed");
  const auto replay_candidate = checkpoint_inbound->replay.check(1U);
  if (replay_candidate.status != ReplayStatus::admissible ||
      !checkpoint_inbound->replay.commit(replay_candidate.sequence))
    throw std::runtime_error("SAD checkpoint replay fixture failed");
  const auto saved_sad = pair_database.checkpoint(
      std::chrono::steady_clock::time_point{std::chrono::seconds{10}});
  Sad restored_sad{2U};
  const auto restore_time =
      std::chrono::steady_clock::time_point{std::chrono::seconds{100}};
  if (!saved_sad || !restored_sad.restore(*saved_sad, restore_time) ||
      !restored_sad.find_outbound(pair_outbound.id) ||
      restored_sad.find_outbound(pair_outbound.id)
              ->outbound_sequence.current() != 2U ||
      !restored_sad.find(pair_inbound.id) ||
      restored_sad.find(pair_inbound.id)->replay.highest() != 1U)
    throw std::runtime_error("SAD sequence or replay state did not restore");
  auto corrupt_sad = *saved_sad;
  corrupt_sad.associations[1U].outbound_sequence =
      std::numeric_limits<std::uint64_t>::max();
  if (restored_sad.restore(corrupt_sad, restore_time) ||
      restored_sad.find_outbound(pair_outbound.id)
              ->outbound_sequence.current() != 2U)
    throw std::runtime_error("invalid SAD checkpoint partially changed state");

  // The composed forwarding owner must fail closed between policy commit and
  // CHILD SA installation. Once a pair is atomically present, the same packet
  // selects its outbound ESP association, and checkpoint restore preserves
  // that decision without serializing a cryptographic engine or key byte.
  ForwardingSecurity forwarding_security{4U, 4U};
  auto live_policy = protect_policy(100U, 1U);
  if (forwarding_security.install_policy(live_policy) !=
          PolicyInstallResult::installed)
    throw std::runtime_error("forwarding security rejected a valid SPD rule");
  const auto absent_decision = forwarding_security.decide(
      Direction::outbound, dns_packet);
  if (absent_decision.status !=
      PolicyDecisionStatus::required_sa_unavailable)
    throw std::runtime_error("protect policy fell back without a CHILD SA");
  auto live_inbound = fallback;
  live_inbound.id = 1000U;
  live_inbound.policy_id = live_policy.id;
  live_inbound.inbound_identifier.spi = 0x12345678U;
  live_inbound.created_at = restore_time;
  auto live_outbound = live_inbound;
  live_outbound.id = 1001U;
  live_outbound.outbound = true;
  if (!forwarding_security.install_child_pair(live_inbound, live_outbound)
           .committed)
    throw std::runtime_error("forwarding security rejected a CHILD SA pair");
  const auto live_decision = forwarding_security.decide(Direction::outbound,
                                                        dns_packet);
  if (live_decision.status != PolicyDecisionStatus::protect ||
      live_decision.outbound_sa_id != live_outbound.id ||
      live_decision.protocol != SecurityProtocol::esp)
    throw std::runtime_error("forwarding security selected the wrong CHILD SA");
  const auto forwarding_checkpoint =
      forwarding_security.checkpoint(restore_time);
  ForwardingSecurity restored_security{4U, 4U};
  if (!forwarding_checkpoint ||
      !restored_security.restore(*forwarding_checkpoint,
                                 restore_time + std::chrono::seconds{5}) ||
      restored_security.decide(Direction::outbound, dns_packet)
              .outbound_sa_id != live_outbound.id)
    throw std::runtime_error("forwarding security checkpoint lost SPD or SAD");
}
