// Fragment body and flood publication is one level-owner transaction. Tests
// inspect both records at the first decision notification and retain placeholders
// and old flood obligations after a second-member admission refusal.

#include "router/isis_level_process.hpp"

#include <algorithm>
#include <array>
#include <source_location>
#include <stdexcept>
#include <string>

namespace {
using namespace router::isis;
using namespace router::packet::isis;
using namespace std::chrono_literals;
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS level batch invariant at " + std::to_string(where.line()));
}
std::vector<std::uint8_t> body(std::uint8_t fragment, std::uint32_t sequence) {
  std::vector<std::uint8_t> bytes(lsp_header_octets + 3U);
  const std::array<std::uint8_t, 3U> option{250U, 1U, fragment};
  require(encode_lsp(bytes, {PduType::lsp_l1,
      {1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}, 1200U, sequence, 3U}, option).has_value());
  return bytes;
}
LspId identity(std::uint8_t fragment) { return {1U, 2U, 3U, 4U, 5U, 6U, 0U, fragment}; }
}

void isis_level_batch_tests() {
  const auto now = RuntimeClock::time_point{100s};
  const std::array circuits{FloodCircuit{true, true, false, false},
      FloodCircuit{true, true, false, false}, FloodCircuit{false, false, false, false}};
  LevelDatabase database(PduType::lsp_l1, {4U, 1024U}, circuits);
  require(database.reserve_origin_batch(2U));
  auto first = body(0U, 1U), second = body(1U, 1U);
  std::array requests{LspInstallRequest{first, 1200U, 60s}, LspInstallRequest{second, 1200U, 60s}};
  require(database.originate_batch(requests, now) == LspInstallResult::installed);
  for (std::uint8_t fragment{}; fragment < 2U; ++fragment) {
    const auto header = database.database().find(identity(fragment), now)->header;
    for (std::size_t circuit{}; circuit < 2U; ++circuit)
      require(database.flags(header.id, circuit)->srm && !database.flags(header.id, circuit)->ssn &&
          database.complete(header, circuit, false, true, now) && !database.flags(header.id, circuit)->srm);
    require(!database.flags(header.id, 2U)->srm);
  }
  auto next_first = body(0U, 2U), next_second = body(1U, 2U);
  requests[0U].wire = next_first; requests[1U].wire = std::span{next_second}.first(4U);
  require(database.originate_batch(requests, now) == LspInstallResult::malformed);
  for (std::uint8_t fragment{}; fragment < 2U; ++fragment)
    require(database.database().find(identity(fragment), now)->header.sequence == 1U &&
        !database.flags(identity(fragment), 0U)->srm && !database.flags(identity(fragment), 1U)->srm);
  requests[1U].wire = next_second;
  require(database.originate_batch(requests, now) == LspInstallResult::installed);
  for (std::uint8_t fragment{}; fragment < 2U; ++fragment)
    require(database.database().find(identity(fragment), now)->header.sequence == 2U &&
        database.flags(identity(fragment), 0U)->srm && database.flags(identity(fragment), 1U)->srm);
  // Flags for two outstanding requests occupy metadata independently of wire.
  // The first staged new flag record must disappear when the second cannot fit.
  LevelDatabase limited(PduType::lsp_l1, {3U, 1024U}, circuits);
  require(limited.reserve_origin_batch(2U));
  require(!limited.receive_snp_entry({100U, identity(8U), 3U, 77U}, 0U, now).waiting_state &&
      !limited.receive_snp_entry({100U, identity(9U), 3U, 78U}, 0U, now).waiting_state);
  require(limited.size() == 2U && !limited.database().size());
  require(limited.originate_batch(requests, now) == LspInstallResult::capacity_exhausted &&
      limited.size() == 2U && !limited.database().size() && !limited.flags(identity(0U), 0U) &&
      limited.flags(identity(8U), 0U)->ssn && limited.flags(identity(9U), 0U)->ssn);

  const std::array programs{LevelCircuitConfiguration{false, 7U}, LevelCircuitConfiguration{true, 7U}};
  LevelProcess level(PduType::lsp_l1, {4U, 1024U}, programs, 8U, 8U, 1200U, 60s, 60s);
  struct Observation {
    const LevelProcess *level;
    RuntimeClock::time_point now;
    std::array<std::uint32_t, 2U> sequence{1U, 1U};
    std::size_t events{};
    bool complete{true}, purge{};
  } observation{&level, now};
  const LevelObserver observer{&observation, +[](void *context, const LevelEvent &event) noexcept {
    if (event.kind != LevelEventKind::database_changed && event.kind != LevelEventKind::database_refreshed) return;
    auto &value = *static_cast<Observation *>(context);
    ++value.events;
    for (std::uint8_t fragment{}; fragment < 2U; ++fragment) {
      const auto &owner = value.level->database();
      const auto record = owner.database().find(identity(fragment), value.now);
      value.complete = value.complete && record && record->header.sequence == value.sequence[fragment] &&
          record->purge_installed == (fragment == 1U && value.purge);
      for (std::size_t circuit{}; circuit < 2U; ++circuit) {
        const auto flags = owner.flags(identity(fragment), circuit);
        value.complete = value.complete && flags && flags->srm && !flags->ssn;
      }
    }
  }};
  require(level.circuit(0U, 7U, false, true, false, true, observer) == LevelStatus::applied &&
      level.circuit(1U, 7U, true, true, true, true, observer) == LevelStatus::applied);
  require(level.reserve_origin_batch(2U));
  const std::array initial{LevelOriginInput{first}, LevelOriginInput{second}};
  require(level.originate_batch(initial, now, {}).status == LevelStatus::missing_observer);
  require(level.originate_batch(initial, now, observer).install == LspInstallResult::installed &&
      observation.events == 2U && observation.complete);
  auto corrupt = next_second; corrupt.back() ^= 1U;
  const std::array invalid{LevelOriginInput{next_first}, LevelOriginInput{corrupt}};
  require(level.originate_batch(invalid, now, observer).install == LspInstallResult::invalid_checksum &&
      observation.events == 2U && level.database().database().find(identity(0U), now)->header.sequence == 1U);
  auto purge = second; purge[10U] = purge[11U] = 0U;
  observation.sequence = {2U, 1U}; observation.purge = true;
  const std::array mixed{LevelOriginInput{next_first}, LevelOriginInput{purge, OriginPurgeReason::initiated}};
  require(level.originate_batch(mixed, now, observer).install == LspInstallResult::installed &&
      observation.events == 4U && observation.complete);
  const auto retirement = level.database().database().next_deadline(LspDeadlineKind::retire_purge);
  require(retirement && retirement->id == identity(1U) && retirement->at == now + 1200s);
}
