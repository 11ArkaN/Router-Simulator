// The configuration control owner prepares local-only Hello and update programs before
// admission. No adjacency, clock, live owner or peer information is accessed.
#pragma once
#include "router/isis_configuration_resolution.hpp"
#include "router/isis_control_worker.hpp"
namespace router::isis {
struct InterfaceProgramContext {
  CircuitIdentity identity;
  std::string_view interface_name;
  IdentityContext system_identity;
  std::optional<ConfiguredInterfaceType> default_type;
  packet::Mac mac{};
  CircuitDestinations destinations;
  std::uint32_t extended_circuit{};
  std::uint8_t local_circuit{}, maximum_areas{};
  std::uint64_t random{};
  std::size_t maximum_pdu_octets{}, peer_attribute_octets{}, lan_neighbors{};
  // All values are effective local interface policy. In particular, IPv6
  // Hello addresses and NLPIDs have already passed the AF configuration owner.
  std::span<const std::uint8_t> protocols;
  std::span<const packet::Ipv4> ipv4_addresses;
  std::span<const packet::Ipv6> ipv6_addresses;
  bool operational{}, loopback{}, physical_point_to_point{}, padding{}, strict_adjacency_check{};
  bool ipv6_addresses_ready{true};
};
struct InterfaceUpdateContext {
  std::uint16_t partial_seconds{}, maximum_pdu_octets{}, transit_seconds{};
  // Explicit local transport scheduling policy, not a vendor CLI default.
  std::chrono::microseconds csnp_separation{};
};
enum class InterfaceUpdateStatus : std::uint8_t { prepared, invalid_context, unresolved_media, unresolved_pacing };
struct InterfaceUpdateResult {
  InterfaceUpdateStatus status{InterfaceUpdateStatus::invalid_context};
  std::optional<UpdateTransmissionProgram> program;
};
// Pure same-owner preparation from validated effective interface values.
// Pacing uses the documented 100 ms or 1 s bucket. Zero blocks LSP output
// while retaining SNP service. Nonintegral burst counts refuse pending a
// sourced rounding rule. LAN scan spacing and CSNP separation remain distinct.
// No allocation, peer access, clock read or publication; failure returns no program.
[[nodiscard]] InterfaceUpdateResult prepare_interface_update_program(const ResolvedInterface &,
    const InterfaceUpdateContext &) noexcept;

enum class InterfaceProgramStatus : std::uint8_t {
  prepared, inactive, unresolved_identity, unresolved_media, invalid_context,
  unrepresentable_holding, unsupported_instance, unsupported_topology
};
struct InterfaceProgramResult {
  InterfaceProgramStatus status{InterfaceProgramStatus::invalid_context};
  std::optional<CircuitDefinition> circuit;
};
// Preconditions: validated instance/interface intent, effective wire limits and AF policy; context is
// the local interface owner projection, never inferred from another router.
// Cold control-shard call, may allocate/throw. Returned values own all storage;
// borrowed input spans expire on return. Failure/inactivity returns no circuit
// and changes no input. Preparation is not publication or admission. MT/IID and
// transmission policy remain separate configuration contracts. This adapter
// currently admits local instance zero only. Oversized hold products reject
// explicitly instead of inventing a platform saturation or truncation rule.
// A physically down port still prepares its configured circuit with carrier
// false. Admission reserves state without emitting until its local port is Up.
[[nodiscard]] InterfaceProgramResult prepare_interface_program(const InstanceIntent &,
    const InterfaceIntent &, const InterfaceProgramContext &);
}
