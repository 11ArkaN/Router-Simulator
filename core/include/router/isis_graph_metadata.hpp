// Immutable root metadata selects family and topology membership for local
// graph and hierarchy decisions. The instance control owner lends a current
// LSDB view; this adapter retains no bytes or mutable state.
// Source: iso.10589.2002.lsdb_link_graph
#pragma once
#include "router/isis_link_graph.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_multi_topology.hpp"
namespace router::isis {
// Same owner and current root fragment only. Flags follow ISO 10589 and RFC
// 5120; malformed optional MT TLVs are counted and ignored consistently.
struct GraphRootMetadata {
  bool supported{}, overloaded{}, attached{}, valid{true};
  std::size_t ignored{};
};
inline GraphRootMetadata graph_root_metadata(const StoredLspView &record, const LinkGraphSelection &selection) noexcept {
  GraphRootMetadata result;
  const bool pseudonode = record.header.id[6U] != 0U;
  result.overloaded = !selection.topology && (record.header.flags & 4U);
  result.attached = !selection.topology && !pseudonode && (record.header.flags & 8U);
  if (pseudonode) { result.supported = true; return result; }
  bool advertised{}, found{}, protocol = !selection.protocol;
  packet::isis::TlvCursor options(record.pdu.tlvs);
  while (const auto option = options.next()) {
    if (option->code == 129U && selection.protocol)
      protocol = protocol || packet::isis::supports_protocol(*option, *selection.protocol);
    if (option->code != 229U) continue;
    packet::isis::TopologyCursor entries(*option, true);
    bool member{}, overloaded{}, attached{};
    while (const auto entry = entries.next()) if (entry->id == selection.topology) {
      member = true;
      overloaded = overloaded || entry->overloaded;
      attached = attached || entry->attached;
    }
    if (!entries.valid()) { ++result.ignored; continue; }
    advertised = true;
    found = found || member;
    if (selection.topology) {
      result.overloaded = result.overloaded || overloaded;
      result.attached = result.attached || attached;
    }
  }
  result.valid = options.valid();
  result.supported = protocol && (found || (!advertised && !selection.topology));
  return result;
}
}
