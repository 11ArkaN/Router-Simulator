// ISO 10589 7.3.15.3 and 7.3.17 require complete contiguous CSNP ranges.
// Only this circuit-level control owner advances the sequence, and only after
// its encoded batch enters the actual egress queue. There is no shared clock.

#include "router/isis_csnp_sequence.hpp"

namespace router::isis {
namespace {
constexpr packet::isis::LspId maximum_id{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU};
packet::isis::LspId predecessor(packet::isis::LspId id) noexcept {
  // A next entry follows at least one selected ID, so this cannot underflow.
  for (std::size_t index = id.size(); index > 0U; --index) {
    auto &octet = id[index - 1U];
    if (octet) { --octet; break; }
    octet = 0xffU;
  }
  return id;
}
packet::isis::LspId successor(packet::isis::LspId id) noexcept {
  // Completion handles maximum_id separately, preventing range wraparound.
  for (std::size_t index = id.size(); index > 0U; --index) {
    auto &octet = id[index - 1U];
    if (octet != 0xffU) { ++octet; break; }
    octet = 0U;
  }
  return id;
}
}

void CompleteSnpSequence::request() noexcept {
  if (active_) repeat_ = true;
  else { active_ = true; first_ = {}; }
}

CompleteSnpBatch CompleteSnpSequence::prepare(const LevelDatabase &database,
    std::span<packet::isis::SnpEntry> output, RuntimeClock::time_point now) noexcept {
  if (pending_) return {CompleteSnpStatus::pending};
  if (!active_) return {};
  CompleteSnpBatch result{CompleteSnpStatus::prepared, first_, maximum_id, 0U};
  for (std::size_t index{}; index < database.size(); ++index) {
    const auto entry = database.snp_entry_at(index, now);
    if (!entry) return {CompleteSnpStatus::inconsistent_database};
    if (entry->id < first_) continue;
    if (result.count == output.size()) {
      if (!result.count) return {CompleteSnpStatus::capacity};
      result.last = predecessor(entry->id);
      break;
    }
    output[result.count++] = *entry;
  }
  pending_last_ = result.last;
  pending_ = true;
  return result;
}

bool CompleteSnpSequence::complete(bool enqueued) noexcept {
  if (!pending_) return false;
  pending_ = false;
  if (!enqueued) return true;
  if (pending_last_ == maximum_id) {
    active_ = repeat_;
    repeat_ = false;
    first_ = {};
  } else first_ = successor(pending_last_);
  return true;
}

void CompleteSnpSequence::reset() noexcept {
  first_ = pending_last_ = {};
  active_ = pending_ = repeat_ = false;
}
} // namespace router::isis
