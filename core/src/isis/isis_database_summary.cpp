// Owner-local bounded summary collection. Only accepted header values are
// copied; there is no mutable state, peer lookup or retained borrowed view.
#include "router/isis_database_summary.hpp"
#include <algorithm>
#include <new>
#include <stdexcept>
namespace router::isis {
DatabaseSummaryResult collect_database_summary(const std::array<const LinkStateDatabase *,2U> &databases,
    RuntimeClock::time_point now,DatabaseSummaryQuery &query) noexcept {
  const auto fail=[&](DatabaseSummaryResult status) { query.rows.clear(); return status; };
  if (query.version!=1U || !query.levels || query.levels>3U || !query.maximum_rows || !query.rows.empty())
    return fail(DatabaseSummaryResult::invalid);
  const auto matches=[&](const packet::isis::LspId &id) {
    return (!query.lsp || *query.lsp==id) && (!query.system || std::equal(query.system->begin(),query.system->end(),id.begin()));
  };
  try {
    std::size_t count{};
    for (std::size_t level{}; level<databases.size(); ++level) if ((query.levels&(1U<<level)) && databases[level])
      for (std::size_t index{}; index<databases[level]->size(); ++index) {
        const auto record=databases[level]->at(index,now);
        if (!record || record->pdu.type!=(level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1))
          return fail(DatabaseSummaryResult::invalid);
        if (matches(record->header.id) && ++count>query.maximum_rows) return fail(DatabaseSummaryResult::capacity);
      }
    query.rows.reserve(count);
    for (std::size_t level{}; level<databases.size(); ++level) if ((query.levels&(1U<<level)) && databases[level])
      for (std::size_t index{}; index<databases[level]->size(); ++index) {
        const auto record=databases[level]->at(index,now);
        if (!record || record->pdu.type!=(level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1))
          return fail(DatabaseSummaryResult::invalid);
        if (matches(record->header.id)) query.rows.push_back({static_cast<std::uint8_t>(level),record->header});
      }
    return DatabaseSummaryResult::collected;
  } catch (const std::bad_alloc &) { return fail(DatabaseSummaryResult::capacity); }
    catch (const std::length_error &) { return fail(DatabaseSummaryResult::capacity); }
}
}
