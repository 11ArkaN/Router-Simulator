// Cold AF projections become owned, deduplicated reachability units. Only the
// instance control writer later edits availability and borrows these units for
// fragment composition. No packet ingress, clock or foreign state is read.
#include "router/isis_local_prefix_catalog.hpp"
#include "router/isis_narrow_reachability.hpp"
#include <algorithm>
#include <array>
namespace router::isis {
namespace {
bool valid_unit(const LocalPrefixCatalogUnit &unit) noexcept {
  namespace wire = packet::isis;
  wire::TlvCursor options(unit.options);
  const auto first = options.next();
  if (!first || (first->code != 135U && first->code != 236U)) return false;
  wire::ExtendedPrefixCursor prefixes(*first);
  const auto prefix = prefixes.next();
  if (!prefix || prefixes.next() || !prefixes.valid() || prefix->down || prefix->prefix != unit.prefix) return false;
  RootPrefix decoded{prefix->prefix, prefix->metric, {}, prefix->sub_tlvs, prefix->external};
  if (const auto narrow_option = options.next()) {
    wire::NarrowIpv4Cursor narrow(*narrow_option);
    const auto value = narrow.next();
    if (!value || narrow.next() || !narrow.valid()) return false;
    decoded.narrow = value->metrics.metric;
  }
  if (options.next() || !options.valid()) return false;
  std::array<std::uint8_t, 514U> bytes{};
  wire::TlvWriter writer(bytes);
  return encode_root_prefix(writer, decoded) && std::ranges::equal(writer.bytes(), unit.options);
}
}
bool valid_local_prefix_catalog(const LocalPrefixCatalogProgram &program) noexcept {
  if (program.version != 1U) return false;
  for (std::size_t index{}; index < program.interfaces.size(); ++index)
    if (!program.interfaces[index].interface_id ||
        (index && program.interfaces[index - 1U].interface_id >= program.interfaces[index].interface_id)) return false;
  for (std::size_t index{}; index < program.units.size(); ++index) {
    const auto &unit = program.units[index];
    if (unit.level > 1U || unit.owners.empty() || !valid_unit(unit)) return false;
    if (index) {
      const auto &prior = program.units[index - 1U];
      if (prior.level > unit.level || (prior.level == unit.level && prior.prefix >= unit.prefix)) return false;
    }
    for (std::size_t owner{}; owner < unit.owners.size(); ++owner) {
      const auto id = unit.owners[owner];
      if ((owner && unit.owners[owner - 1U] >= id) ||
          !std::binary_search(program.interfaces.begin(), program.interfaces.end(), LocalPrefixInterface{id, {}, false},
              [](const auto &a, const auto &b) { return a.interface_id < b.interface_id; })) return false;
    }
  }
  return true;
}
bool set_local_prefix_carrier(LocalPrefixCatalogProgram &program, std::uint16_t port, bool available) noexcept {
  bool changed{};
  for (auto &interface : program.interfaces)
    if (interface.physical_port == port && interface.available != available) {
      interface.available = available; changed = true;
    }
  return changed;
}
bool append_local_prefix_catalog(OriginFragmentWorkspace &workspace,
    const LocalPrefixCatalogProgram &program, std::size_t level, bool all_possible) noexcept {
  if (level > 1U) return false;
  for (std::size_t index{}; index < program.units.size(); ++index) {
    const auto &unit = program.units[index];
    if (unit.level != level) continue;
    const bool available = all_possible || std::any_of(unit.owners.begin(), unit.owners.end(), [&](auto id) {
      const auto source = std::lower_bound(program.interfaces.begin(), program.interfaces.end(), id,
          [](const auto &entry, auto key) { return entry.interface_id < key; });
      return source != program.interfaces.end() && source->interface_id == id && source->available;
    });
    if (available && !workspace.add_options({3U, index + 1U}, unit.options, {}, false)) return false;
  }
  return true;
}
}
