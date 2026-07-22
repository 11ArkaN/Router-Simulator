// RFC 4301 SAD validation and RFC 4302/RFC 4303 longest inbound identifier
// lookup. This repository owns metadata only. Crypto providers and packet paths
// borrow an entry for one owner turn and never retain a mutable pointer.

#include "router/ipsec_sad.hpp"

#include <algorithm>

namespace router::ipsec {
namespace {

bool identifier_valid(const SaIdentifier &identifier) noexcept {
  if (identifier.spi == 0U ||
      (identifier.source.has_value() && !identifier.destination.has_value()))
    return false;
  if (identifier.destination && !valid_address(*identifier.destination))
    return false;
  if (identifier.source &&
      (!valid_address(*identifier.source) ||
       identifier.source->family != identifier.destination->family))
    return false;
  return true;
}

bool algorithms_valid(const SecurityAssociation &association) noexcept {
  if (association.crypto_material_handle == 0U)
    return false;
  if (association.inbound_identifier.protocol == SecurityProtocol::ah)
    return association.encryption == EncryptionAlgorithm::none &&
           association.integrity != IntegrityAlgorithm::none;
  // RFC 4303 forbids NULL encryption together with NULL integrity. AEAD suites
  // carry integrity in the encryption transform and therefore require the
  // separate integrity selector to be none.
  if (association.encryption != EncryptionAlgorithm::none)
    return association.integrity == IntegrityAlgorithm::none;
  return association.integrity != IntegrityAlgorithm::none;
}

bool tunnel_valid(const SecurityAssociation &association) noexcept {
  if (association.mode == Mode::transport)
    return !association.tunnel_source && !association.tunnel_destination;
  return association.tunnel_source && association.tunnel_destination &&
         valid_address(*association.tunnel_source) &&
         valid_address(*association.tunnel_destination) &&
         association.tunnel_source->family ==
             association.tunnel_destination->family;
}

bool exact_identifier(const SaIdentifier &left,
                      const SaIdentifier &right) noexcept {
  return left.spi == right.spi && left.protocol == right.protocol &&
         left.destination == right.destination && left.source == right.source;
}

std::uint8_t match_specificity(const SecurityAssociation &association,
                               SecurityProtocol protocol, std::uint32_t spi,
                               const Address &destination,
                               const Address &source) noexcept {
  const auto &identifier = association.inbound_identifier;
  if (association.outbound || identifier.spi != spi ||
      identifier.protocol != protocol)
    return 0U;
  if (identifier.destination && *identifier.destination != destination)
    return 0U;
  if (identifier.source && *identifier.source != source)
    return 0U;
  return identifier.source ? 3U : identifier.destination ? 2U : 1U;
}

} // namespace

Sad::Sad(std::size_t capacity) : capacity_(capacity) {
  try {
    entries_.reserve(capacity);
  } catch (...) {
  }
}

SaInstallResult Sad::install(const SecurityAssociation &association) noexcept {
  if (association.id == 0U || association.policy_id == 0U ||
      !identifier_valid(association.inbound_identifier) ||
      !algorithms_valid(association) || !tunnel_valid(association))
    return SaInstallResult::invalid;
  const auto existing =
      std::find_if(entries_.begin(), entries_.end(), [&](const auto &entry) {
        return entry.id == association.id;
      });
  const auto conflict =
      std::find_if(entries_.begin(), entries_.end(), [&](const auto &entry) {
        return entry.id != association.id &&
               entry.outbound == association.outbound &&
               exact_identifier(entry.inbound_identifier,
                                association.inbound_identifier);
      });
  if (conflict != entries_.end())
    return SaInstallResult::identifier_conflict;
  if (existing == entries_.end() && entries_.size() >= capacity_)
    return SaInstallResult::capacity_exhausted;
  try {
    if (existing != entries_.end()) {
      *existing = association;
      return SaInstallResult::replaced;
    }
    entries_.push_back(association);
    return SaInstallResult::installed;
  } catch (...) {
    return SaInstallResult::capacity_exhausted;
  }
}

SaPairInstallResult
Sad::install_pair(const SecurityAssociation &inbound,
                  const SecurityAssociation &outbound) noexcept {
  if (inbound.outbound || !outbound.outbound || inbound.id == outbound.id ||
      inbound.policy_id != outbound.policy_id ||
      inbound.mode != outbound.mode ||
      inbound.inbound_identifier.protocol !=
          outbound.inbound_identifier.protocol ||
      inbound.encryption != outbound.encryption ||
      inbound.integrity != outbound.integrity)
    return {};

  std::vector<SecurityAssociation> previous;
  try {
    // Pair installation is a cold control-plane operation. The snapshot owns
    // metadata and opaque key handles only, never key bytes or provider state.
    previous = entries_;
  } catch (...) {
    return {.inbound = SaInstallResult::capacity_exhausted,
            .outbound = SaInstallResult::capacity_exhausted,
            .committed = false};
  }
  const auto inbound_result = install(inbound);
  if (inbound_result != SaInstallResult::installed &&
      inbound_result != SaInstallResult::replaced)
    return {.inbound = inbound_result,
            .outbound = SaInstallResult::invalid,
            .committed = false};
  const auto outbound_result = install(outbound);
  if (outbound_result != SaInstallResult::installed &&
      outbound_result != SaInstallResult::replaced) {
    entries_ = std::move(previous);
    return {.inbound = inbound_result,
            .outbound = outbound_result,
            .committed = false};
  }
  return {.inbound = inbound_result,
          .outbound = outbound_result,
          .committed = true};
}

SaPairEraseResult Sad::erase_pair(std::uint64_t inbound_id,
                                  std::uint64_t outbound_id) noexcept {
  if (inbound_id == 0U || outbound_id == 0U || inbound_id == outbound_id)
    return SaPairEraseResult::invalid;
  const auto inbound = std::find_if(entries_.begin(), entries_.end(),
                                    [inbound_id](const auto &entry) {
                                      return entry.id == inbound_id;
                                    });
  const auto outbound = std::find_if(entries_.begin(), entries_.end(),
                                     [outbound_id](const auto &entry) {
                                       return entry.id == outbound_id;
                                     });
  if (inbound == entries_.end() || outbound == entries_.end())
    return SaPairEraseResult::missing;
  if (inbound->outbound || !outbound->outbound ||
      inbound->policy_id != outbound->policy_id ||
      inbound->mode != outbound->mode ||
      inbound->inbound_identifier.protocol !=
          outbound->inbound_identifier.protocol)
    return SaPairEraseResult::not_a_pair;

  // std::remove_if only moves existing metadata and cannot allocate. Erasing
  // the resulting suffix therefore cannot expose a one-directional transient
  // to another operation because this SAD has exactly one mutable owner.
  entries_.erase(
      std::remove_if(entries_.begin(), entries_.end(),
                     [inbound_id, outbound_id](const auto &entry) {
                       return entry.id == inbound_id ||
                              entry.id == outbound_id;
                     }),
      entries_.end());
  return SaPairEraseResult::erased;
}

bool Sad::erase(std::uint64_t id) noexcept {
  const auto found =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const auto &entry) { return entry.id == id; });
  if (found == entries_.end())
    return false;
  entries_.erase(found);
  return true;
}

SecurityAssociation *Sad::find_inbound(SecurityProtocol protocol,
                                       std::uint32_t spi,
                                       const Address &destination,
                                       const Address &source) noexcept {
  if (spi == 0U || !valid_address(destination) || !valid_address(source) ||
      destination.family != source.family)
    return nullptr;
  SecurityAssociation *best{};
  std::uint8_t best_specificity{};
  for (auto &entry : entries_) {
    const auto specificity =
        match_specificity(entry, protocol, spi, destination, source);
    if (specificity > best_specificity) {
      best = &entry;
      best_specificity = specificity;
    }
  }
  return best;
}

SecurityAssociation *Sad::find_outbound(std::uint64_t id) noexcept {
  const auto found = std::find_if(entries_.begin(), entries_.end(),
                                  [&](const auto &entry) {
                                    return entry.outbound && entry.id == id;
                                  });
  return found == entries_.end() ? nullptr : &*found;
}

SecurityAssociation *Sad::find_outbound_for_policy(
    std::uint32_t policy_id, SecurityProtocol protocol) noexcept {
  SecurityAssociation *selected{};
  for (auto &association : entries_) {
    if (!association.outbound || association.policy_id != policy_id ||
        association.inbound_identifier.protocol != protocol)
      continue;
    if (!selected || association.created_at > selected->created_at ||
        (association.created_at == selected->created_at &&
         association.id > selected->id))
      selected = &association;
  }
  return selected;
}

const SecurityAssociation *Sad::find(std::uint64_t id) const noexcept {
  const auto found =
      std::find_if(entries_.begin(), entries_.end(),
                   [&](const auto &entry) { return entry.id == id; });
  return found == entries_.end() ? nullptr : &*found;
}

std::optional<SadCheckpoint>
Sad::checkpoint(std::chrono::steady_clock::time_point now) const noexcept {
  SadCheckpoint state{.capacity = capacity_, .associations = {}};
  try {
    state.associations.reserve(entries_.size());
    for (const auto &entry : entries_) {
      if (entry.created_at > now)
        return std::nullopt;
      const auto age = std::chrono::duration_cast<std::chrono::nanoseconds>(
          now - entry.created_at);
      if (std::chrono::duration_cast<std::chrono::steady_clock::duration>(age) !=
          now - entry.created_at)
        return std::nullopt;
      auto metadata = entry;
      metadata.created_at = {};
      // Keeping default sequence objects inside the metadata copy avoids a
      // second almost-identical SA type. Restore ignores those defaults and
      // rebuilds both repositories from the explicit portable values.
      metadata.replay = ReplayWindow{entry.replay.width(),
                                     entry.replay.extended()};
      metadata.outbound_sequence =
          OutboundSequence{entry.outbound_sequence.extended()};
      state.associations.push_back(
          {.association = metadata,
           .created_age_nanoseconds = age.count(),
           .replay_highest = entry.replay.highest(),
           .replay_bitmap = entry.replay.bitmap(),
           .outbound_sequence = entry.outbound_sequence.current()});
    }
  } catch (...) {
    return std::nullopt;
  }
  return state;
}

bool Sad::restore(const SadCheckpoint &state,
                  std::chrono::steady_clock::time_point now) noexcept {
  if (state.capacity != capacity_ || state.associations.size() > capacity_)
    return false;
  Sad replacement{capacity_};
  for (const auto &saved : state.associations) {
    if (saved.created_age_nanoseconds < 0)
      return false;
    const auto age = std::chrono::duration_cast<
        std::chrono::steady_clock::duration>(
        std::chrono::nanoseconds{saved.created_age_nanoseconds});
    if (std::chrono::duration_cast<std::chrono::nanoseconds>(age).count() !=
            saved.created_age_nanoseconds ||
        now.time_since_epoch() < age)
      return false;
    auto association = saved.association;
    association.created_at = now - age;
    association.replay = ReplayWindow{saved.association.replay.width(),
                                      saved.association.replay.extended()};
    association.outbound_sequence = OutboundSequence{
        saved.association.outbound_sequence.extended()};
    if (!association.replay.restore(saved.replay_highest,
                                    saved.replay_bitmap) ||
        !association.outbound_sequence.restore(saved.outbound_sequence))
      return false;
    const auto installed = replacement.install(association);
    if (installed != SaInstallResult::installed)
      return false;
  }
  entries_.swap(replacement.entries_);
  return true;
}

} // namespace router::ipsec
