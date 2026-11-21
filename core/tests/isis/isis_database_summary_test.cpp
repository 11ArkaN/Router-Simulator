// Real LSDB fixtures retain live and purged LSPs at independent levels. All
// databases and query results belong to this test's synchronous owner.
#include "router/isis_database_summary.hpp"
#include <array>
#include <stdexcept>
void isis_database_summary_tests() {
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace std::chrono_literals;
  const auto require=[](bool value) { if (!value) throw std::runtime_error("Database summary invariant"); };
  LinkStateDatabase l1(PduType::lsp_l1,{8U,8192U,128U}), l2(PduType::lsp_l2,{8U,8192U,128U});
  const auto start=RuntimeClock::time_point{100s};
  const LspId root{1U,2U,3U,4U,5U,6U,0U,0U};
  auto pn=root; pn[6U]=1U;
  std::array<std::uint8_t,256U> wire{};
  const auto install=[&](LinkStateDatabase &db,PduType type,LspId id,std::uint16_t lifetime) {
    const auto encoded=encode_lsp(wire,{type,id,lifetime,7U,3U},{});
    require(encoded && db.install(*encoded,start,1200U,60s,{LspAdmissionOrigin::originated})==LspInstallResult::installed);
  };
  install(l1,PduType::lsp_l1,root,1200U); install(l1,PduType::lsp_l1,pn,0U); install(l2,PduType::lsp_l2,root,600U);
  const std::array<const LinkStateDatabase *,2U> databases{&l1,&l2};
  DatabaseSummaryQuery all; all.maximum_rows=3U;
  require(collect_database_summary(databases,start+2500ms,all)==DatabaseSummaryResult::collected && all.rows.size()==3U);
  require(all.rows[0U].level==0U && all.rows[0U].header.id==root && all.rows[0U].header.remaining_seconds==1198U);
  require(all.rows[1U].header.id==pn && !all.rows[1U].header.remaining_seconds);
  require(all.rows[2U].level==1U && all.rows[2U].header.remaining_seconds==598U);
  DatabaseSummaryQuery selected; selected.maximum_rows=1U; selected.levels=2U; selected.lsp=root;
  require(collect_database_summary(databases,start,selected)==DatabaseSummaryResult::collected && selected.rows.size()==1U);
  require(collect_database_summary(databases,start,selected)==DatabaseSummaryResult::invalid && selected.rows.empty());
  DatabaseSummaryQuery wrong_level; wrong_level.maximum_rows=3U;
  require(collect_database_summary({&l2,&l1},start,wrong_level)==DatabaseSummaryResult::invalid && wrong_level.rows.empty());
  DatabaseSummaryQuery refused; refused.maximum_rows=2U;
  require(collect_database_summary(databases,start,refused)==DatabaseSummaryResult::capacity && refused.rows.empty());
  refused.maximum_rows=3U; refused.levels=4U;
  require(collect_database_summary(databases,start,refused)==DatabaseSummaryResult::invalid && refused.rows.empty());
  require(l1.retire_purge(pn,start+60s) && all.rows[1U].header.id==pn && all.rows.size()==3U);
  DatabaseSummaryQuery empty; empty.maximum_rows=1U;
  require(collect_database_summary({nullptr,nullptr},start,empty)==DatabaseSummaryResult::collected && empty.rows.empty());
  LinkStateDatabase protected_database(PduType::lsp_l1,{2U,1024U,128U});
  const std::array<std::uint8_t,9U> options{10U,4U,1U,'k','e','y',137U,1U,'a'};
  const auto protected_wire=encode_lsp(wire,{PduType::lsp_l1,root,1200U,1U,3U},options);
  require(protected_wire && protected_database.install(*protected_wire,start,1200U,60s,
      {LspAdmissionOrigin::originated})==LspInstallResult::installed);
  DatabaseSummaryQuery detail; detail.maximum_rows=1U; detail.levels=1U;
  detail.detailed=true; detail.maximum_tlv_octets=4U;
  require(collect_database_summary({&protected_database,nullptr},start,detail)==DatabaseSummaryResult::collected && detail.rows.size()==1U);
  const auto &row=detail.rows.front();
  require(row.tlvs==std::vector<std::uint8_t>{137U,1U,'a'} && row.authentication_types==std::vector<std::uint8_t>{1U} &&
      row.allocated_octets>=row.used_octets && row.used_octets==protected_wire->size() && row.version==1U && row.packet_version==1U);
  detail.rows.clear(); detail.maximum_tlv_octets=3U;
  require(collect_database_summary({&protected_database,nullptr},start,detail)==DatabaseSummaryResult::capacity && detail.rows.empty());
  auto second=root; second[7U]=1U;
  const auto second_wire=encode_lsp(wire,{PduType::lsp_l1,second,1200U,1U,3U},options);
  require(second_wire && protected_database.install(*second_wire,start,1200U,60s,
      {LspAdmissionOrigin::originated})==LspInstallResult::installed);
  detail.maximum_rows=2U; detail.maximum_tlv_octets=7U;
  require(collect_database_summary({&protected_database,nullptr},start,detail)==DatabaseSummaryResult::capacity &&
      detail.rows.empty() && protected_database.size()==2U);
}
