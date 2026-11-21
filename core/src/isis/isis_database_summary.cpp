// Owner-local bounded summary collection. Only accepted header values are
// copied; there is no mutable state, peer lookup or retained borrowed view.
#include "router/isis_database_summary.hpp"
#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>
namespace router::isis {
DatabaseSummaryResult collect_database_summary(const std::array<const LinkStateDatabase *,2U> &databases,
    RuntimeClock::time_point now,DatabaseSummaryQuery &query) noexcept {
  const auto fail=[&](DatabaseSummaryResult status) { query.rows.clear(); return status; };
  if (query.version!=1U || !query.levels || query.levels>3U || !query.maximum_rows || !query.rows.empty() ||
      (query.detailed && !query.maximum_tlv_octets))
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
    std::size_t copied{};
    for (std::size_t level{}; level<databases.size(); ++level) if ((query.levels&(1U<<level)) && databases[level])
      for (std::size_t index{}; index<databases[level]->size(); ++index) {
        const auto record=databases[level]->at(index,now);
        if (!record || record->pdu.type!=(level ? packet::isis::PduType::lsp_l2 : packet::isis::PduType::lsp_l1))
          return fail(DatabaseSummaryResult::invalid);
        if (!matches(record->header.id)) continue;
        DatabaseSummaryRow row{static_cast<std::uint8_t>(level),record->header};
        if (query.detailed) {
          row.allocated_octets=record->allocated_octets; row.used_octets=record->pdu.bytes.size();
          row.version=record->pdu.bytes[2U]; row.packet_version=record->pdu.bytes[5U];
          row.system_id_octets=record->pdu.bytes[3U] ? record->pdu.bytes[3U] : 6U;
          row.maximum_areas=record->pdu.maximum_area_addresses;
          packet::isis::TlvCursor options(record->pdu.tlvs);
          while (const auto option=options.next()) {
            const auto size=option->code==10U ? 1U : option->value.size()+2U;
            if (size>query.maximum_tlv_octets-copied) return fail(DatabaseSummaryResult::capacity);
            if (option->code==10U) {
              if (option->value.empty()) return fail(DatabaseSummaryResult::invalid);
              row.authentication_types.push_back(option->value.front());
            } else {
              row.tlvs.push_back(option->code); row.tlvs.push_back(static_cast<std::uint8_t>(option->value.size()));
              row.tlvs.insert(row.tlvs.end(),option->value.begin(),option->value.end());
            }
            copied+=size;
          }
          if (!options.valid()) return fail(DatabaseSummaryResult::invalid);
        }
        query.rows.push_back(std::move(row));
      }
    return DatabaseSummaryResult::collected;
  } catch (const std::bad_alloc &) { return fail(DatabaseSummaryResult::capacity); }
    catch (const std::length_error &) { return fail(DatabaseSummaryResult::capacity); }
}
}
