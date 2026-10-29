// Foreign expiration preserves source checksum while authenticated generation
// strips reachability. Local purges may generate a fresh valid checksum.

#include "router/isis_purge_builder.hpp"
#include "router/isis_lsdb.hpp"

#include <array>
#include <stdexcept>
#include <vector>
#include <memory>

void isis_purge_builder_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("IS-IS purge composition invariant failed");
  };
  std::vector<std::uint8_t> options(1492U), output(1492U);
  const SystemId local{1U, 2U, 3U, 4U, 5U, 1U}, source{1U, 2U, 3U, 4U, 5U, 2U};
  const std::array<std::uint8_t, 6U> area{1U, 4U, 3U, 0x49U, 0U, 1U};
  const std::array<std::uint8_t, 6U> secret{1U, 2U, 3U, 4U, 5U, 6U};
  for (const auto method : {std::optional<AuthenticationMethod>{},
      std::optional{AuthenticationMethod::password}, std::optional{AuthenticationMethod::hmac_md5},
      std::optional{AuthenticationMethod::hmac_sha1}, std::optional{AuthenticationMethod::hmac_sha256}}) {
    LspContents active;
    active.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 2U, 0U, 0U}, 1200U, 9U, 3U};
    active.options = area;
    active.maximum_pdu_octets = 1492U;
    if (method) active.authentication = AuthenticationKey{*method, 7U, secret};
    const auto live = build_lsp_pdu(active, options, output);
    DecodeError error{};
    const auto original = parse(live.bytes, error);
    require(live.status == LspBuildStatus::encoded && original && valid_lsp_checksum(*original));
    std::unique_ptr<LinkStateDatabase> full;
    const auto now = RuntimeClock::time_point{100s};
    const std::uint8_t *retained{};
    if (!method) {
      LinkStateDatabase refused(PduType::lsp_l1, {1U, 35U, 36U});
      require(refused.install(live.bytes, now, 1200U, 60s) == LspInstallResult::capacity_exhausted && !refused.size());
      full = std::make_unique<LinkStateDatabase>(PduType::lsp_l1, LsdbLimits{1U, 36U, 36U});
      require(full->install(live.bytes, now, 1200U, 60s) == LspInstallResult::installed && full->allocated_octets() == 36U);
      retained = full->at(0U, now)->pdu.bytes.data();
    }
    PurgeContents purge;
    purge.type = original->type;
    purge.original = *lsp(*original);
    purge.maximum_areas = original->maximum_area_addresses;
    purge.generator = local;
    purge.rules = PurgeRules::registry_6233;
    purge.authentication = active.authentication;
    purge.maximum_pdu_octets = 1492U;
    const auto expired = build_purge_pdu(purge, options, output);
    const auto pdu = parse(expired.bytes, error);
    require(expired.status == LspBuildStatus::encoded && pdu && !lsp(*pdu)->remaining_seconds &&
        lsp(*pdu)->id == purge.original.id && lsp(*pdu)->sequence == purge.original.sequence &&
        lsp(*pdu)->checksum == purge.original.checksum &&
        validate_purge_options(pdu->tlvs, PurgeRules::registry_6233) == PurgeValidation::accepted);
    if (full) {
      require(full->install(expired.bytes, now + 1200s, 1200U, 60s,
          {LspAdmissionOrigin::originated}) == LspInstallResult::installed);
      require(full->allocated_octets() == 36U && full->at(0U, now + 1200s)->pdu.bytes.data() == retained);
    }
    TlvCursor cursor(pdu->tlvs);
    const auto poi = cursor.next();
    require(poi && decode_purge_originator(*poi)->originator == local);
    if (method) require(cursor.next()->code == 10U &&
        verify_authentication(expired.bytes, *purge.authentication) == AuthenticationError::none);
    require(!cursor.next() && cursor.valid());
    purge.generator = source;
    const auto own = build_purge_pdu(purge, options, output);
    const auto own_pdu = parse(own.bytes, error);
    require(own.status == LspBuildStatus::encoded && own_pdu && valid_lsp_checksum(*own_pdu));
    purge.generator = local;
    purge.original.checksum = 0U;
    const auto zero = build_purge_pdu(purge, options, output);
    const auto zero_pdu = parse(zero.bytes, error);
    require(zero.status == LspBuildStatus::encoded && zero_pdu && !lsp(*zero_pdu)->checksum);
    if (method) require(verify_authentication(zero.bytes, *purge.authentication) == AuthenticationError::none);
    purge.rules = PurgeRules::authentication_only;
    purge.instance = PduInstanceOption{InstanceFormat::legacy_2009, 0U, {}};
    require(build_purge_pdu(purge, options, output).status == LspBuildStatus::options);
    purge.instance.reset();
    purge.rules = PurgeRules::unspecified;
    require(build_purge_pdu(purge, options, output).status == LspBuildStatus::options);
  }
  const auto now = RuntimeClock::time_point{100s};
  LinkStateDatabase deadlines(PduType::lsp_l1, {2U, 72U, 36U});
  LspContents active;
  active.header = {PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 2U, 0U, 0U}, 1200U, 1U, 3U};
  active.options = area;
  active.maximum_pdu_octets = 1492U;
  const auto first_id = active.header.id;
  auto live = build_lsp_pdu(active, options, output);
  require(live.status == LspBuildStatus::encoded && deadlines.install(live.bytes, now,
      1200U, 60s) == LspInstallResult::installed);
  active.header.id.back() = 1U;
  live = build_lsp_pdu(active, options, output);
  require(live.status == LspBuildStatus::encoded && deadlines.install(live.bytes, now + 1s,
      1200U, 60s) == LspInstallResult::installed);
  const std::array<LspId, 1> blocked{first_id};
  const auto unblocked = deadlines.next_deadline(std::nullopt, blocked);
  require(unblocked && unblocked->id == active.header.id && unblocked->at == now + 1201s);
  const std::array all_blocked{first_id, active.header.id};
  require(!deadlines.next_deadline(std::nullopt, all_blocked));
  const auto stored = deadlines.find(first_id, now + 1200s);
  PurgeContents purge;
  purge.type = PduType::lsp_l1;
  purge.original = stored->header;
  purge.maximum_areas = 3U;
  purge.generator = local;
  purge.rules = PurgeRules::registry_6233;
  purge.maximum_pdu_octets = 1492U;
  const auto expired = build_purge_pdu(purge, options, output);
  require(expired.status == LspBuildStatus::encoded && deadlines.install(expired.bytes,
      now + 1200s, 1200U, 60s, {LspAdmissionOrigin::originated}) == LspInstallResult::installed);
  const auto retirement = deadlines.next_deadline(std::nullopt, all_blocked);
  require(retirement && retirement->id == first_id && retirement->kind == LspDeadlineKind::retire_purge &&
      retirement->at == now + 1260s);

}
