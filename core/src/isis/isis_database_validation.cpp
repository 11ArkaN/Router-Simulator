// ISO 10589 7.3.18 checks retained live LSP checksums independently of traffic
// and local refresh. Sorted identity traversal avoids stale index references
// during bounded scans. A detected fault remains latched until reconstruction.

#include "router/isis_database_validation.hpp"
#include "router/isis_jitter.hpp"

#include <stdexcept>

namespace router::isis {
namespace {
RuntimeClock::time_point after(RuntimeClock::time_point now, std::chrono::microseconds interval) noexcept {
  const auto duration = std::chrono::duration_cast<RuntimeClock::duration>(interval);
  return now > RuntimeClock::time_point::max() - duration ? RuntimeClock::time_point::max() : now + duration;
}
}
DatabaseValidation::DatabaseValidation(std::chrono::microseconds interval, std::uint64_t random,
    RuntimeClock::time_point now) : interval_(interval), random_(random), due_(now) {
  if (!random || interval.count() <= 0 || interval >
      std::chrono::duration_cast<std::chrono::microseconds>(RuntimeClock::duration::max()))
    throw std::invalid_argument("Invalid IS-IS database validation interval");
  due_ = after(now, *jittered_interval(interval_, random_));
}
std::optional<RuntimeClock::time_point> DatabaseValidation::deadline() const noexcept {
  return corrupted_ ? std::nullopt : std::optional{due_};
}
DatabaseValidationResult DatabaseValidation::service(const LinkStateDatabase &database,
    RuntimeClock::time_point now, std::size_t &budget) noexcept {
  if (corrupted_) return {DatabaseValidationStatus::corrupted, cursor_, 0U};
  if (!scanning_ && now < due_) return {};
  scanning_ = true;
  DatabaseValidationResult result;
  for (;;) {
    const auto record = database.next_after(cursor_, now);
    if (!record) {
      scanning_ = false;
      cursor_.reset();
      due_ = after(now, *jittered_interval(interval_, random_));
      result.status = DatabaseValidationStatus::complete;
      return result;
    }
    if (!budget) { result.status = DatabaseValidationStatus::more; return result; }
    --budget;
    ++result.checked;
    cursor_ = record->header.id;
    if (record->header.remaining_seconds && !packet::isis::valid_lsp_checksum(record->pdu)) {
      corrupted_ = true;
      result.status = DatabaseValidationStatus::corrupted;
      result.corrupted = cursor_;
      return result;
    }
  }
}
} // namespace router::isis
