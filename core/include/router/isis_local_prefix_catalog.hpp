// The instance control shard owns local prefix availability. Cold preparation
// copies canonical AF projections into immutable semantic units; local carrier
// edits change only their interface gates. Dependencies point to semantic
// encoders and fragment scratch, never to another device or the UI.
#pragma once
#include "router/isis_root_content.hpp"
#include "router/isis_origin_fragment_workspace.hpp"
namespace router::isis {
struct LocalPrefixInterface {
  std::uint64_t interface_id{};
  // Absence denotes a logical local interface such as System. Physical carrier
  // updates cannot change that gate. The configuration owner supplies its state.
  std::optional<std::uint16_t> physical_port;
  bool available{};
  bool operator==(const LocalPrefixInterface &) const = default;
};
struct LocalPrefixCatalogUnit {
  std::uint8_t level{};
  ip::IpPrefix prefix;
  std::vector<std::uint8_t> options;
  // Sorted unique local interface IDs. A shared subnet remains advertised
  // while any eligible owner is available, without duplicate reachability.
  std::vector<std::uint64_t> owners;
  bool operator==(const LocalPrefixCatalogUnit &) const = default;
};
struct LocalPrefixCatalogProgram {
  std::uint32_t version{1U};
  // Owned storage transfers cold from the configuration owner to the sole IS-IS
  // control writer. No shared references or concurrent access. Exhaustion
  // refuses the complete admission; carrier updates allocate nothing.
  std::vector<LocalPrefixInterface> interfaces;
  std::vector<LocalPrefixCatalogUnit> units;
  bool operator==(const LocalPrefixCatalogProgram &) const = default;
};
// Same control owner, no allocation or mutation. Checks canonical, ordered
// prefix units, exact generated encoding and complete local owner references.
// Malformed checkpoint/program input returns false before any admission.
[[nodiscard]] bool valid_local_prefix_catalog(const LocalPrefixCatalogProgram &) noexcept;
// Local physical event only. Returns whether any matching gate changed. Logical
// gates and other ports remain untouched; repeated events are idempotent.
// The caller marks its root dirty and composes before ordinary LSP service.
[[nodiscard]] bool set_local_prefix_carrier(LocalPrefixCatalogProgram &,
    std::uint16_t port, bool available) noexcept;
// Requires a validated program. Adds immutable units to same-owner reserved scratch. Program storage
// outlives compose/reset. all_possible admits the worst-case cold capacity;
// ordinary composition emits each prefix once if any owner is available.
// No allocation or protocol publication. Refusal changes only workspace scratch.
[[nodiscard]] bool append_local_prefix_catalog(OriginFragmentWorkspace &,
    const LocalPrefixCatalogProgram &, std::size_t level, bool all_possible = false) noexcept;
}
