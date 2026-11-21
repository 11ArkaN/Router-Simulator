// A cold database summary copies accepted LSP headers on their sole protocol
// owner. Wire bodies and authentication values never leave the LSDB here.
#pragma once
#include "router/isis_lsdb.hpp"
#include <array>
#include <optional>
#include <vector>
namespace router::isis {
// Pointer-free cold request. Limits bound selected headers and the independent
// name catalog; they are emulator resource budgets, not protocol capacities.
struct DatabaseRequest {
  std::uint32_t version{1U};
  std::uint8_t instance{}, levels{3U};
  std::uint32_t maximum_rows{}, maximum_names{}, maximum_name_octets{};
  std::optional<packet::isis::SystemId> system;
  std::optional<packet::isis::LspId> lsp;
  bool detailed{};
  std::uint32_t maximum_tlv_octets{};
};
struct DatabaseSummaryRow {
  DatabaseSummaryRow()=default;
  DatabaseSummaryRow(std::uint8_t selected_level,packet::isis::LspView selected_header) noexcept
      : level(selected_level),header(selected_header) {}
  std::uint8_t level{};
  packet::isis::LspView header;
  std::size_t allocated_octets{}, used_octets{};
  std::uint8_t version{}, packet_version{}, system_id_octets{}, maximum_areas{};
  // Authentication values are excluded before publication. Only the public
  // authentication type is retained; all remaining bytes are owned TLVs.
  std::vector<std::uint8_t> tlvs;
  std::vector<std::uint8_t> authentication_types;
};
struct DatabaseSummaryQuery {
  std::uint32_t version{1U};
  std::uint8_t levels{3U};
  std::size_t maximum_rows{};
  std::optional<packet::isis::SystemId> system;
  std::optional<packet::isis::LspId> lsp;
  std::vector<DatabaseSummaryRow> rows;
  bool detailed{};
  std::size_t maximum_tlv_octets{};
};
enum class DatabaseSummaryResult : std::uint8_t { collected, invalid, capacity };
// Call synchronously on the owner of both databases. Null entries mean absent
// levels. No input pointer escapes. Results own all copied values and remain
// valid after LSDB mutation. Purges remain visible with effective lifetime zero.
// Failure clears rows and preserves both databases; no partial result publishes.
[[nodiscard]] DatabaseSummaryResult collect_database_summary(
    const std::array<const LinkStateDatabase *,2U> &, RuntimeClock::time_point,
    DatabaseSummaryQuery &) noexcept;
}
