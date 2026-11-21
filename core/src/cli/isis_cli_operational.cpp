// Operational formatting follows source-bound adjacency, hostname and LSDB columns.
// Topologies are read from accepted Hello TLVs, including explicit MT-only
// membership. No configuration or packet path depends on this renderer.
#include "cli/isis_cli_operational.hpp"
#include "router/isis_configuration.hpp"
#include "router/isis_multi_topology.hpp"
#include "router/isis_lsp_identity.hpp"
#include <algorithm>
#include <tuple>
#include <iomanip>
#include <sstream>
namespace router::lab::isis_cli {
namespace {
bool valid_hostnames(const isis::HostnameQuery &query) noexcept {
  if (query.version!=1U || query.instance>device_catalog::isis_instance_last ||
      !query.maximum_rows || !query.maximum_name_octets || query.rows.size()>query.maximum_rows) return false;
  std::size_t octets{};
  for (std::size_t index{}; index<query.rows.size(); ++index) {
    const auto &row=query.rows[index];
    if ((index && query.rows[index-1U].system>=row.system) || row.hostname.empty() || row.hostname.size()>255U ||
        row.hostname.size()>query.maximum_name_octets-octets ||
        std::any_of(row.hostname.begin(),row.hostname.end(),[](unsigned char value) { return value>0x7fU; })) return false;
    octets+=row.hostname.size();
  }
  return true;
}
void terminal_name(std::ostream &out,std::string_view name) {
  constexpr std::string_view hex="0123456789abcdef";
  for (const unsigned char value : name) {
    if (value>=0x20U && value<=0x7eU) out << static_cast<char>(value);
    else out << "\\x" << hex[value>>4U] << hex[value&15U];
  }
}
}
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
std::optional<std::string> hostname_table(const isis::HostnameQuery &query) {
  if (!valid_hostnames(query)) return std::nullopt;
  std::ostringstream out;
  const std::string rule(73U,'='), separator(73U,'-');
  out << rule << "\nRtr Base ISIS Instance " << unsigned(query.instance) << " Hostnames\n" << rule
      << "\nSystem Id                Hostname\n" << separator << '\n';
  for (const auto &row : query.rows) {
    out << std::left << std::setw(25) << isis::format_configured_system_id(row.system);
    terminal_name(out,row.hostname);
    out << '\n';
  }
  out << rule;
  return out.str();
}
std::optional<std::string> database_table(const isis::DatabaseQuery &query) {
  const auto &request=query.request;
  const auto &summary=query.summary;
  if (request.version!=1U || request.instance>device_catalog::isis_instance_last || !request.levels || request.levels>3U ||
      summary.version!=1U || summary.levels!=request.levels || summary.maximum_rows!=request.maximum_rows ||
      !request.maximum_rows || summary.rows.size()>request.maximum_rows || summary.system!=request.system || summary.lsp!=request.lsp ||
      query.hostnames.device!=query.device || query.hostnames.instance!=request.instance ||
      query.hostnames.maximum_rows!=request.maximum_names || query.hostnames.maximum_name_octets!=request.maximum_name_octets ||
      !valid_hostnames(query.hostnames)) return std::nullopt;
  for (std::size_t index{}; index<summary.rows.size(); ++index) {
    const auto &row=summary.rows[index];
    if (row.level>1U || !(request.levels&(1U<<row.level)) ||
        (request.lsp && row.header.id!=*request.lsp) ||
        (request.system && !std::equal(request.system->begin(),request.system->end(),row.header.id.begin())) ||
        (index && std::tie(summary.rows[index-1U].level,summary.rows[index-1U].header.id)>=std::tie(row.level,row.header.id)))
      return std::nullopt;
  }
  const auto hex=[](auto value) { std::ostringstream out; out << "0x" << std::hex << value; return out.str(); };
  std::ostringstream out;
  const std::string rule(79U,'='), separator(79U,'-');
  out << rule << "\nRtr Base ISIS Instance " << unsigned(request.instance) << " Database\n" << rule
      << "\nLSP ID                                  Sequence  Checksum Lifetime Attributes\n" << separator << '\n';
  for (std::size_t level{}; level<2U; ++level) if (request.levels&(1U<<level)) {
    out << "Displaying Level " << level+1U << " database\n" << separator << '\n';
    std::size_t count{};
    for (const auto &row : summary.rows) if (row.level==level) {
      auto label=isis::format_lsp_id(row.header.id);
      packet::isis::SystemId system{}; std::copy_n(row.header.id.begin(),system.size(),system.begin());
      const auto name=std::lower_bound(query.hostnames.rows.begin(),query.hostnames.rows.end(),system,
          [](const auto &candidate,const auto &id) { return candidate.system<id; });
      if (name!=query.hostnames.rows.end() && name->system==system) {
        std::ostringstream escaped; terminal_name(escaped,name->hostname); label=escaped.str()+label.substr(14U);
      }
      constexpr std::array<std::string_view,4U> types{"","L1","L2","L1L2"};
      out << std::left << std::setw(39) << label << ' ' << std::setw(9) << hex(row.header.sequence) << ' '
          << std::setw(8) << hex(row.header.checksum) << ' ' << std::setw(8) << row.header.remaining_seconds << ' ' << types[row.header.flags&3U];
      if (row.header.flags&0x04U) out << " OV";
      if (row.header.flags&0x78U) out << " ATT";
      out << '\n'; ++count;
    }
    out << "Level (" << level+1U << ") LSP Count : " << count << '\n';
  }
  out << rule; return out.str();
}

}
