// Instance-Identifier wire formats remain distinct from RFC 5120 MT-IDs.
// Views borrow immutable packet bytes and own no instance or LSDB state.
// Dependencies point only to the IS-IS PDU value contract.

#pragma once

#include "router/isis_packet.hpp"

namespace router::packet::isis {

// The standard format follows RFC 8202. SR OS standard-multi-instance cites
// its 2016 predecessor draft; legacy_2009 remains a separate wire format.
enum class InstanceFormat : std::uint8_t { legacy_2009, standard };
enum class InstanceError : std::uint8_t {
  none, invalid_format, malformed_tlv, duplicate, conflicting_instance,
  topology_count, mixed_zero_topology, zero_instance_placement
};

struct InstanceTlvView {
  std::uint16_t instance{};
  std::span<const std::uint8_t> encoded_topologies;
  [[nodiscard]] std::size_t topology_count() const noexcept { return encoded_topologies.size() / 2U; }
  [[nodiscard]] std::optional<std::uint16_t> topology(std::size_t index) const noexcept;
};

struct InstanceSelection {
  std::uint16_t instance{};
  bool present{};
  bool topology_zero{};
};

// Decode one complete TLV 7. Legacy has exactly two octets. RFC 8202
// adds even-sized ITID lists and reserves ITID zero for sole use by an instance.
// Wrong code, lengths, zero-IID topology lists and mixed zero ITIDs fail.
[[nodiscard]] std::optional<InstanceTlvView>
decode_instance_tlv(TlvView tlv, InstanceFormat format) noexcept;

// Append one complete option. All values are network-order 16-bit identifiers,
// independent of the product configuration's narrower instance-ID range.
// Legacy forbids ITIDs. Nonzero standard instances require at least one ITID.
// Failure leaves writer unchanged; caller retains all storage, on any shard.
[[nodiscard]] bool encode_instance_tlv(TlvWriter &writer, InstanceFormat format,
    std::uint16_t instance, std::span<const std::uint16_t> topologies) noexcept;

// Requires a PDU returned by parse(). Validates all IID options together before
// returning selection. Standard Hellos union topology support across options;
// all nonzero-instance SNPs/LSPs require exactly one IID option and one ITID.
// IID zero is explicit only in standard physical-P2P Hellos. p2p_over_lan uses
// broadcast MAC isolation and therefore passes physical_point_to_point=false.
// This does not authenticate, accept an adjacency or choose a destination MAC.
[[nodiscard]] std::optional<InstanceSelection> select_instance(const PduView &pdu,
    InstanceFormat format, bool physical_point_to_point, InstanceError &error) noexcept;

} // namespace router::packet::isis
