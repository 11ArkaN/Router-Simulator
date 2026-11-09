// Operational formatting follows the source-bound adjacency report columns.
// Topologies are read from accepted Hello TLVs, including explicit MT-only
// membership. No configuration or packet path depends on this renderer.
#include "cli/isis_cli_operational.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_multi_topology.hpp"
#include <iomanip>
#include <sstream>
namespace router::lab::isis_cli {
std::optional<std::string> adjacency_table(const isis::AdjacencyQuery &query,
    std::span<const InterfaceName> names) {
  if (query.version != 1U || query.instance > device_catalog::isis_instance_last) return std::nullopt;
  std::ostringstream out;
  const std::string rule(79U, '='), separator(79U, '-');
  out << rule << "\nRtr Base ISIS Instance " << unsigned(query.instance) << " Adjacency\n" << rule
      << "\nSystem ID                Usage State         Hold Interface              MT-ID\n" << separator << '\n';
  for (const auto &row : query.rows) {
    const auto name = std::find_if(names.begin(), names.end(),
        [&](const auto &entry) { return entry.identity == row.circuit.interface_id; });
    if (name == names.end() || row.circuit.device != query.device || row.circuit.instance != query.instance ||
        row.expires_in.count() < 0 || static_cast<unsigned>(row.usage) > 3U) return std::nullopt;
    std::string_view state;
    switch (row.state) {
    case isis::OperationalAdjacencyState::initializing: state = "Initializing"; break;
    case isis::OperationalAdjacencyState::up: state = "Up"; break;
    case isis::OperationalAdjacencyState::failed: state = "Failed"; break;
    case isis::OperationalAdjacencyState::down: state = "Down"; break;
    default: return std::nullopt;
    }
    std::vector<std::uint16_t> topologies;
    bool membership{};
    packet::isis::TlvCursor options(row.attributes);
    while (const auto option = options.next()) if (option->code == 229U) {
      membership = true;
      packet::isis::TopologyCursor values(*option);
      while (const auto value = values.next()) topologies.push_back(value->id);
      if (!values.valid()) return std::nullopt;
    }
    if (!options.valid()) return std::nullopt;
    if (!membership) topologies.push_back(0U);
    std::sort(topologies.begin(), topologies.end());
    topologies.erase(std::unique(topologies.begin(), topologies.end()), topologies.end());
    static constexpr std::array<std::string_view, 4U> usage{"undefined", "L1", "L2", "L1L2"};
    out << std::left << std::setw(25) << isis::format_configured_system_id(row.system)
        << std::setw(6) << usage[static_cast<std::size_t>(row.usage)] << std::setw(14) << state
        << std::setw(5) << std::chrono::duration_cast<std::chrono::seconds>(row.expires_in).count()
        << std::setw(23) << name->name;
    for (std::size_t index{}; index < topologies.size(); ++index) {
      if (index) out << ',';
      out << topologies[index];
    }
    out << '\n';
  }
  out << separator << "\nAdjacencies : " << query.rows.size() << '\n' << rule;
  return out.str();
}
}
