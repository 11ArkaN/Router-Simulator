// Atomic LSDB and flood-obligation admission for one instance level. Its
// control owner stages all new flag storage before installing received bytes.
// Dependencies point only to the local LSDB and allocation-free transitions.

#include "router/isis_level_database.hpp"

#include <algorithm>
#include <new>
#include <utility>
#include <stdexcept>

namespace router::isis {
namespace {
// One borrowed SNP traversal keeps order across repeated TLV 9 options. No
// state can be applied until a separate full traversal passed validation.
class SnpEntries final {
public:
  explicit SnpEntries(std::span<const std::uint8_t> options) noexcept : options_(options) {}
  std::optional<packet::isis::SnpEntry> next() noexcept {
    if (!valid_) return std::nullopt;
    while (remaining_.empty()) {
      const auto option = options_.next();
      if (!option) { valid_ = options_.valid(); return std::nullopt; }
      if (option->code != 9U) continue;
      if (option->value.size() % packet::isis::snp_entry_octets) {
        valid_ = false;
        return std::nullopt;
      }
      remaining_ = option->value;
    }
    const auto entry = packet::isis::snp_entry(remaining_.first(packet::isis::snp_entry_octets));
    remaining_ = remaining_.subspan(packet::isis::snp_entry_octets);
    valid_ = entry.has_value();
    return entry;
  }
  bool valid() const noexcept { return valid_; }
private:
  packet::isis::TlvCursor options_;
  std::span<const std::uint8_t> remaining_;
  bool valid_{true};
};
}

LevelDatabase::LevelDatabase(packet::isis::PduType type, LsdbLimits limits,
    std::span<const FloodCircuit> circuits, std::size_t maximum_circuits)
    : type_(type), database_(type, limits), circuits_(circuits.begin(), circuits.end()), maximum_records_(limits.records),
      maximum_circuits_(maximum_circuits ? maximum_circuits : circuits.size()) {
  if (maximum_circuits_ < circuits.size() || maximum_circuits_ > circuits_.max_size())
    throw std::invalid_argument("IS-IS circuit slot budget cannot contain its initial generation");
  records_.reserve(limits.records);
  for (auto &circuit : circuits_) circuit.srm = circuit.ssn = false;
}

std::optional<std::size_t> LevelDatabase::admit_circuit(bool broadcast) noexcept {
  if (circuits_.size() == maximum_circuits_) return std::nullopt;
  const auto index = circuits_.size();
  try {
    // Complete every possible allocation before changing a vector length.
    // Retained LSP bytes and existing SRM/SSN are never part of this mutation.
    circuits_.reserve(index + 1U);
    for (auto &record : records_) record.circuits.reserve(index + 1U);
  } catch (const std::bad_alloc &) { return std::nullopt; }
    catch (const std::length_error &) { return std::nullopt; }
  const FloodCircuit value{broadcast, false, false, false};
  circuits_.push_back(value);
  for (auto &record : records_) record.circuits.push_back(value);
  return index;
}

bool LevelDatabase::cancel_circuit_admission(std::size_t index) noexcept {
  if (index >= circuits_.size() || index + 1U != circuits_.size() || circuits_[index].eligible ||
      std::any_of(records_.begin(), records_.end(), [&](const auto &record) {
        const auto &flags = record.circuits[index];
        return flags.eligible || flags.srm || flags.ssn;
      })) return false;
  for (auto &record : records_) record.circuits.pop_back();
  circuits_.pop_back();
  return true;
}

std::size_t LevelDatabase::position(const packet::isis::LspId &id) const noexcept {
  return static_cast<std::size_t>(std::lower_bound(records_.begin(), records_.end(), id,
      [](const Record &record, const auto &key) { return record.id < key; }) - records_.begin());
}

LevelReceiveResult LevelDatabase::receive(std::span<const std::uint8_t> wire,
    std::size_t ingress, RuntimeClock::time_point now, std::uint16_t maximum_age,
    std::chrono::seconds purge_retention) noexcept {
  if (ingress >= circuits_.size() || !circuits_[ingress].eligible) return {};
  return admit(wire, ingress, now, maximum_age, purge_retention);
}

LspInstallResult LevelDatabase::originate(std::span<const std::uint8_t> wire,
    RuntimeClock::time_point now, std::uint16_t maximum_age,
    std::chrono::seconds purge_retention) noexcept {
  return admit(wire, std::nullopt, now, maximum_age, purge_retention).install;
}

LevelReceiveResult LevelDatabase::admit(std::span<const std::uint8_t> wire,
    std::optional<std::size_t> ingress, RuntimeClock::time_point now,
    std::uint16_t maximum_age, std::chrono::seconds purge_retention) noexcept {
  packet::isis::DecodeError error{};
  const auto pdu = packet::isis::parse(wire, error);
  const auto header = pdu ? packet::isis::lsp(*pdu) : std::nullopt;
  if (!header) return {};
  const auto index = position(header->id);
  const bool exists = index < records_.size() && records_[index].id == header->id;
  Record staged;
  if (!exists && header->remaining_seconds && header->checksum) {
    if (records_.size() == maximum_records_)
      return {LspInstallResult::capacity_exhausted, {false, false, true}, std::nullopt};
    try { staged = {header->id, circuits_}; }
    catch (const std::bad_alloc &) {
      return {LspInstallResult::capacity_exhausted, {false, false, true}, std::nullopt};
    }
  }
  const auto installed = database_.install(wire, now, maximum_age, purge_retention);
  if (!exists && installed == LspInstallResult::installed)
    records_.insert(records_.begin() + index, std::move(staged));
  if (installed == LspInstallResult::installed) records_[index].placeholder = false;
  auto flags = exists || installed == LspInstallResult::installed
      ? std::span(records_[index].circuits) : std::span(circuits_);
  if (ingress) {
    const auto flooding = received_lsp(flags, *ingress, installed);
    return {installed, flooding, flooding.transient_acknowledgement
        ? std::optional(packet::isis::SnpEntry{0U, header->id, header->sequence, header->checksum})
        : std::nullopt};
  }
  if (installed == LspInstallResult::installed) for (auto &circuit : flags) {
    circuit.srm = circuit.eligible;
    circuit.ssn = false;
  }
  return {installed, {}, std::nullopt};
}

bool LevelDatabase::circuit(std::size_t index, bool broadcast, bool eligible,
    bool flood_all) noexcept {
  if (index >= circuits_.size() ||
      (circuits_[index].eligible && circuits_[index].broadcast != broadcast)) return false;
  circuits_[index] = {broadcast, eligible, false, false};
  for (auto &record : records_) {
    auto &flags = record.circuits[index];
    flags = {broadcast, eligible, !record.placeholder && eligible && (flags.srm || flood_all), eligible && flags.ssn};
  }
  return true;
}

bool LevelDatabase::complete(const packet::isis::LspView &sent,
    std::size_t circuit, bool partial_snp, bool enqueued,
    RuntimeClock::time_point now) noexcept {
  const auto index = position(sent.id);
  const auto current = database_.find(sent.id, now);
  if (index == records_.size() || records_[index].id != sent.id ||
      circuit >= records_[index].circuits.size()) return false;
  if (!current) {
    if (!partial_snp || !records_[index].placeholder || sent.sequence || sent.checksum || sent.remaining_seconds)
      return false;
    psnp_transmitted(records_[index].circuits[circuit], enqueued);
    return true;
  }
  if (sent.sequence != current->header.sequence || sent.checksum != current->header.checksum ||
      (sent.remaining_seconds == 0U) != (current->header.remaining_seconds == 0U)) return false;
  auto &flags = records_[index].circuits[circuit];
  if (partial_snp) psnp_transmitted(flags, enqueued);
  else lsp_transmitted(flags, enqueued);
  return true;
}

std::optional<FloodCircuit> LevelDatabase::flags(const packet::isis::LspId &id,
    std::size_t circuit) const noexcept {
  const auto index = position(id);
  return index < records_.size() && records_[index].id == id &&
      circuit < records_[index].circuits.size()
      ? std::optional(records_[index].circuits[circuit]) : std::nullopt;
}

SnpFloodResult LevelDatabase::receive_snp_entry(const packet::isis::SnpEntry &entry,
    std::size_t circuit, RuntimeClock::time_point now) noexcept {
  if (circuit >= circuits_.size() || !circuits_[circuit].eligible) return {};
  const auto current = database_.find(entry.id, now);
  if (!current) {
    const auto decision = received_snp_entry(circuits_[circuit], entry, nullptr);
    if (!decision.request_missing) return decision;
    const auto index = position(entry.id);
    if (index == records_.size() || records_[index].id != entry.id) {
      if (records_.size() == maximum_records_) return {false, false, true};
      Record staged;
      try { staged = {entry.id, circuits_, true}; }
      catch (const std::bad_alloc &) { return {false, false, true}; }
      records_.insert(records_.begin() + index, std::move(staged));
    }
    records_[index].circuits[circuit].ssn = true;
    return decision;
  }
  const auto index = position(entry.id);
  return received_snp_entry(records_[index].circuits[circuit], entry, &current->header);
}

SnpBatchResult LevelDatabase::receive_snp(const packet::isis::PduView &pdu,
    std::size_t circuit, bool designated, RuntimeClock::time_point now) noexcept {
  using namespace packet::isis;
  const bool level1 = type_ == PduType::lsp_l1;
  const bool complete = pdu.type == (level1 ? PduType::csnp_l1 : PduType::csnp_l2);
  const bool partial = pdu.type == (level1 ? PduType::psnp_l1 : PduType::psnp_l2);
  if ((!complete && !partial) || circuit >= circuits_.size() || !circuits_[circuit].eligible ||
      (partial && circuits_[circuit].broadcast && !designated)) return {};
  const auto header = snp(pdu);
  if (!header || (complete && header->last < header->first)) return {SnpBatchStatus::malformed};
  SnpEntries validation(pdu.tlvs);
  std::optional<LspId> previous;
  while (const auto entry = validation.next()) {
    if ((previous && entry->id <= *previous) ||
        (complete && (entry->id < header->first || entry->id > header->last)))
      return {SnpBatchStatus::malformed};
    previous = entry->id;
  }
  if (!validation.valid()) return {SnpBatchStatus::malformed};
  SnpBatchResult result{SnpBatchStatus::accepted};
  SnpEntries entries(pdu.tlvs);
  while (const auto entry = entries.next()) {
    const auto applied = receive_snp_entry(*entry, circuit, now);
    result.waiting_state = result.waiting_state || applied.waiting_state;
    if (applied.confusion) ++result.confusions;
  }
  if (complete) {
    SnpEntries mentioned(pdu.tlvs);
    auto entry = mentioned.next();
    for (const auto &record : records_) {
      while (entry && entry->id < record.id) entry = mentioned.next();
      if (!entry || entry->id != record.id) omitted(record.id, circuit, header->first, header->last, now);
    }
  }
  return result;
}

std::optional<packet::isis::SnpEntry> LevelDatabase::snp_entry(
    const packet::isis::LspId &id, RuntimeClock::time_point now) const noexcept {
  const auto index = position(id);
  if (index == records_.size() || records_[index].id != id) return std::nullopt;
  if (records_[index].placeholder) return packet::isis::SnpEntry{0U, id, 0U, 0U};
  const auto current = database_.find(id, now);
  if (!current) return std::nullopt;
  return packet::isis::SnpEntry{current->header.remaining_seconds, id,
      current->header.sequence, current->header.checksum};
}

std::optional<packet::isis::SnpEntry> LevelDatabase::snp_entry_at(
    std::size_t index, RuntimeClock::time_point now) const noexcept {
  return index < records_.size() ? snp_entry(records_[index].id, now) : std::nullopt;
}

PartialSnpSelection LevelDatabase::partial_snp(std::size_t circuit,
    std::optional<packet::isis::LspId> cursor,
    std::span<packet::isis::SnpEntry> output, RuntimeClock::time_point now) const noexcept {
  PartialSnpSelection result{0U, cursor};
  if (circuit >= circuits_.size() || !circuits_[circuit].eligible || output.empty() || records_.empty())
    return result;
  std::size_t start{};
  if (cursor) {
    start = position(*cursor);
    if (start < records_.size() && records_[start].id == *cursor) ++start;
  }
  for (std::size_t offset{}; offset < records_.size(); ++offset) {
    const auto &record = records_[(start + offset) % records_.size()];
    if (!record.circuits[circuit].ssn) continue;
    const auto entry = snp_entry(record.id, now);
    if (!entry) continue;
    output[result.count++] = *entry;
    result.cursor = record.id;
    if (result.count == output.size()) break;
  }
  std::sort(output.begin(), output.begin() + result.count,
      [](const auto &left, const auto &right) { return left.id < right.id; });
  return result;
}

void LevelDatabase::omitted(const packet::isis::LspId &id, std::size_t circuit,
    const packet::isis::LspId &first, const packet::isis::LspId &last,
    RuntimeClock::time_point now) noexcept {
  if (circuit >= circuits_.size()) return;
  const auto current = database_.find(id, now);
  if (current) omitted_from_csnp(records_[position(id)].circuits[circuit], current->header, first, last);
}

bool LevelDatabase::retire_purge(const packet::isis::LspId &id,
    RuntimeClock::time_point now) noexcept {
  if (!database_.retire_purge(id, now)) return false;
  records_.erase(records_.begin() + position(id));
  return true;
}

} // namespace router::isis
