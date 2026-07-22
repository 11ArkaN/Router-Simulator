// Exact SAP generation programming and Ethernet envelope transformation.
// Configuration-time sorting pays the comparison cost once; every packet turn
// performs bounded binary searches and one unavoidable frame copy only.

#include "router/sap_forwarding.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <utility>

namespace router::service {
namespace {

[[nodiscard]] std::uint8_t tag_count(EthernetEncapsulation value) noexcept {
  switch (value) {
  case EthernetEncapsulation::null:
    return 0U;
  case EthernetEncapsulation::dot1q:
    return 1U;
  case EthernetEncapsulation::qinq:
    return 2U;
  }
  return 0xffU;
}

[[nodiscard]] bool valid_tpid(std::uint16_t value) noexcept {
  // IEEE 802.3 reserves values below 1536 as length fields. A configured TPID
  // must be an EtherType, but it is not restricted to two globally recognized
  // values because SR OS profiles can use another provider tag EtherType.
  return value >= 0x0600U;
}

[[nodiscard]] bool valid_attachment(const SapAttachment &attachment) noexcept {
  if (attachment.logical_interface_id == 0U || attachment.sap.port.card == 0U ||
      attachment.sap.port.mda == 0U || attachment.sap.port.port == 0U)
    return false;
  const auto count = tag_count(attachment.sap.encapsulation);
  if (count == 0U)
    return !attachment.sap.outer_vlan && !attachment.sap.inner_vlan &&
           attachment.outer_tpid == 0U && attachment.inner_tpid == 0U;
  if (!attachment.sap.outer_vlan ||
      *attachment.sap.outer_vlan > maximum_vlan_identifier ||
      !valid_tpid(attachment.outer_tpid))
    return false;
  if (count == 1U)
    return !attachment.sap.inner_vlan && attachment.inner_tpid == 0U;
  return attachment.sap.inner_vlan &&
         *attachment.sap.inner_vlan <= maximum_vlan_identifier &&
         valid_tpid(attachment.inner_tpid);
}

[[nodiscard]] auto wire_key(const SapAttachment &attachment) noexcept {
  // Logical identity is intentionally excluded. Ingress learns identity from
  // the matched entry; including it would make an otherwise exact VLAN key
  // depend on whichever entry happened to describe the port contract first.
  return std::array<std::uint64_t, 6U>{
      attachment.sap.port.ordinal,
      tag_count(attachment.sap.encapsulation),
      attachment.outer_tpid,
      attachment.sap.outer_vlan.value_or(0U),
      attachment.inner_tpid,
      attachment.sap.inner_vlan.value_or(0U)};
}

[[nodiscard]] bool same_port_contract(const SapAttachment &left,
                                      const SapAttachment &right) noexcept {
  return left.sap.port == right.sap.port &&
         left.sap.encapsulation == right.sap.encapsulation &&
         left.outer_tpid == right.outer_tpid &&
         left.inner_tpid == right.inner_tpid;
}

[[nodiscard]] std::uint16_t read_u16(const packet::Frame &frame,
                                     std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(frame.bytes[offset] << 8U |
                                    frame.bytes[offset + 1U]);
}

[[nodiscard]] bool looks_like_additional_tag(std::uint16_t ether_type,
                                             const SapAttachment &contract)
    noexcept {
  // Exact tag-stack matching prevents an extra customer or provider tag from
  // falling through to a shorter SAP. Include the standard TPIDs as well as
  // this port's configured values because a mismatched tag is still a tag, not
  // an L3 EtherType for the selected SAP.
  return ether_type == packet::ethernet_type_customer_vlan ||
         ether_type == packet::ethernet_type_service_vlan ||
         ether_type == contract.outer_tpid ||
         (contract.inner_tpid != 0U && ether_type == contract.inner_tpid);
}

void strip_known_tag_count(packet::Frame &frame, std::uint8_t count) noexcept {
  if (count == 0U)
    return;
  const auto removed = static_cast<std::size_t>(count) *
                       packet::vlan_tag_octets;
  // The classifier already validated the complete envelope. Move begins at
  // the final EtherType and therefore restores the ordinary 14-octet header.
  std::move(frame.bytes.begin() + 12U + removed,
            frame.bytes.begin() + frame.length, frame.bytes.begin() + 12U);
  frame.length = static_cast<std::uint16_t>(frame.length - removed);
}

} // namespace

SapProgramStatus
SapForwardingTable::replace(std::span<const SapAttachment> attachments) {
  return replace(attachments, {});
}

SapProgramStatus SapForwardingTable::replace(
    std::span<const SapAttachment> attachments,
    std::span<const ServiceIpv6Interface> interfaces) {
  try {
    std::vector<SapAttachment> candidate{attachments.begin(),
                                         attachments.end()};
    if (!std::all_of(candidate.begin(), candidate.end(), valid_attachment))
      return SapProgramStatus::invalid_attachment;
    std::sort(candidate.begin(), candidate.end(), [](const auto &left,
                                                     const auto &right) {
      return wire_key(left) < wire_key(right);
    });
    for (std::size_t index = 1U; index < candidate.size(); ++index) {
      const auto &previous = candidate[index - 1U];
      const auto &current = candidate[index];
      if (previous.sap.port.ordinal == current.sap.port.ordinal &&
          !same_port_contract(previous, current))
        return SapProgramStatus::inconsistent_port_encapsulation;
      if (previous.sap == current.sap)
        return SapProgramStatus::duplicate_sap;
    }

    std::vector<std::size_t> logical(candidate.size());
    for (std::size_t index = 0U; index < logical.size(); ++index)
      logical[index] = index;
    std::sort(logical.begin(), logical.end(), [&](auto left, auto right) {
      return candidate[left].logical_interface_id <
             candidate[right].logical_interface_id;
    });
    for (std::size_t index = 1U; index < logical.size(); ++index)
      if (candidate[logical[index - 1U]].logical_interface_id ==
          candidate[logical[index]].logical_interface_id)
        return SapProgramStatus::duplicate_logical_interface;

    std::vector<ServiceIpv6Interface> candidate_interfaces{
        interfaces.begin(), interfaces.end()};
    std::sort(candidate_interfaces.begin(), candidate_interfaces.end(),
              [](const auto &left, const auto &right) {
                return left.interface_id < right.interface_id;
              });
    for (std::size_t index = 0U; index < candidate_interfaces.size(); ++index) {
      const auto &interface = candidate_interfaces[index];
      const bool duplicate = index != 0U &&
          candidate_interfaces[index - 1U].interface_id ==
              interface.interface_id;
      // Validate protocol values before relating them to the wire attachment.
      // MTU is L3 and RFC 8200 requires at least 1280 octets.
      const bool configured_address_valid =
          interface.configured && !ip::is_unspecified(interface.address) &&
          !ip::is_multicast(interface.address) &&
          ip::mask(interface.address, interface.prefix_length) ==
              interface.network &&
          ip::is_link_local(interface.link_local) &&
          interface.prefix_length <= 128U;
      const bool unconfigured_address_valid =
          !interface.configured && !interface.operational &&
          ip::is_unspecified(interface.address) &&
          ip::is_unspecified(interface.network) &&
          ip::is_unspecified(interface.link_local) &&
          interface.prefix_length == 0U;
      if (duplicate || interface.interface_id == 0U ||
          interface.physical_port_ordinal >=
              device_catalog::maximum_ports_per_router ||
          interface.mtu < packet::ipv6_minimum_link_mtu ||
          (!configured_address_valid && !unconfigured_address_valid) ||
          interface.unsolicited_learning >
              lab::Ipv6UnsolicitedLearning::both ||
          interface.proactive_refresh >
              lab::Ipv6UnsolicitedLearning::both ||
          interface.neighbor_limit_threshold_percent > 100U ||
          interface.redirect_interval_seconds == 0U)
        return SapProgramStatus::invalid_interface;
      const auto matching = std::find_if(
          candidate.begin(), candidate.end(), [&](const auto &value) {
            return value.logical_interface_id == interface.interface_id;
          });
      if (matching == candidate.end() ||
          matching->sap.port.ordinal != interface.physical_port_ordinal)
        return SapProgramStatus::incomplete_service_generation;
    }
    if (!candidate_interfaces.empty() &&
        candidate_interfaces.size() != candidate.size())
      return SapProgramStatus::incomplete_service_generation;

    attachments_ = std::move(candidate);
    logical_index_ = std::move(logical);
    interfaces_ = std::move(candidate_interfaces);
    return SapProgramStatus::accepted;
  } catch (const std::bad_alloc &) {
    return SapProgramStatus::resource_exhausted;
  }
}

const ServiceIpv6Interface *SapForwardingTable::find_interface(
    std::uint64_t logical_interface_id) const noexcept {
  const auto found = std::lower_bound(
      interfaces_.begin(), interfaces_.end(), logical_interface_id,
      [](const auto &entry, std::uint64_t value) {
        return entry.interface_id < value;
      });
  return found != interfaces_.end() &&
                 found->interface_id == logical_interface_id
             ? &*found
             : nullptr;
}

void SapForwardingTable::remove_physical_port(
    std::uint16_t physical_port_ordinal) noexcept {
  // attachments_ was sorted by physical ordinal during publication, so one
  // equal_range identifies the whole ownership slice without scanning or a
  // temporary vector. vector::erase moves trivially owned attachment values.
  const auto first = std::lower_bound(
      attachments_.begin(), attachments_.end(), physical_port_ordinal,
      [](const SapAttachment &entry, std::uint16_t ordinal) {
        return entry.sap.port.ordinal < ordinal;
      });
  const auto last = std::upper_bound(
      first, attachments_.end(), physical_port_ordinal,
      [](std::uint16_t ordinal, const SapAttachment &entry) {
        return ordinal < entry.sap.port.ordinal;
      });
  if (first == last)
    return;
  attachments_.erase(first, last);

  // logical_index_ previously held exactly one element per attachment and
  // therefore has sufficient capacity after the erase. Reusing it is the
  // invariant that makes this lifecycle operation genuinely noexcept.
  logical_index_.clear();
  for (std::size_t index = 0U; index < attachments_.size(); ++index)
    logical_index_.push_back(index);
  std::sort(logical_index_.begin(), logical_index_.end(), [&](auto left,
                                                              auto right) {
    return attachments_[left].logical_interface_id <
           attachments_[right].logical_interface_id;
  });
  std::erase_if(interfaces_, [&](const auto &entry) {
    return entry.physical_port_ordinal == physical_port_ordinal;
  });
}

const SapAttachment *SapForwardingTable::first_on_port(
    std::uint16_t physical_port_ordinal) const noexcept {
  const auto found = std::lower_bound(
      attachments_.begin(), attachments_.end(), physical_port_ordinal,
      [](const SapAttachment &entry, std::uint16_t ordinal) {
        return entry.sap.port.ordinal < ordinal;
      });
  return found != attachments_.end() &&
                 found->sap.port.ordinal == physical_port_ordinal
             ? &*found
             : nullptr;
}

const SapAttachment *SapForwardingTable::find_logical(
    std::uint64_t logical_interface_id) const noexcept {
  const auto found = std::lower_bound(
      logical_index_.begin(), logical_index_.end(), logical_interface_id,
      [&](std::size_t index, std::uint64_t value) {
        return attachments_[index].logical_interface_id < value;
      });
  return found != logical_index_.end() &&
                 attachments_[*found].logical_interface_id ==
                     logical_interface_id
             ? &attachments_[*found]
             : nullptr;
}

SapIngressResult SapForwardingTable::ingress(
    std::uint16_t physical_port_ordinal, const packet::Frame &wire,
    packet::Frame &internal) const noexcept {
  const auto *contract = first_on_port(physical_port_ordinal);
  if (!contract)
    return {.status = SapIngressStatus::no_match};
  const auto count = tag_count(contract->sap.encapsulation);
  const auto minimum = packet::ethernet_header_octets +
                       static_cast<std::size_t>(count) *
                           packet::vlan_tag_octets;
  if (wire.length < minimum)
    return {.status = SapIngressStatus::malformed};

  SapAttachment lookup = *contract;
  SapVlanMarking marking{};
  if (count >= 1U) {
    if (read_u16(wire, 12U) != contract->outer_tpid)
      return {.status = SapIngressStatus::no_match};
    const auto control = read_u16(wire, 14U);
    lookup.sap.outer_vlan = static_cast<std::uint16_t>(control & 0x0fffU);
    marking.outer_priority_code_point =
        static_cast<std::uint8_t>(control >> 13U);
    marking.outer_drop_eligible = (control & 0x1000U) != 0U;
  }
  if (count == 2U) {
    if (read_u16(wire, 16U) != contract->inner_tpid)
      return {.status = SapIngressStatus::no_match};
    const auto control = read_u16(wire, 18U);
    lookup.sap.inner_vlan = static_cast<std::uint16_t>(control & 0x0fffU);
    marking.inner_priority_code_point =
        static_cast<std::uint8_t>(control >> 13U);
    marking.inner_drop_eligible = (control & 0x1000U) != 0U;
  }
  if (looks_like_additional_tag(read_u16(wire, 12U + count * 4U),
                                *contract))
    return {.status = SapIngressStatus::no_match};

  const auto key = wire_key(lookup);
  const auto found = std::lower_bound(
      attachments_.begin(), attachments_.end(), key,
      [](const SapAttachment &entry, const auto &value) {
        return wire_key(entry) < value;
      });
  if (found == attachments_.end() || wire_key(*found) != key)
    return {.status = SapIngressStatus::no_match};

  internal = wire;
  strip_known_tag_count(internal, count);
  return {.status = SapIngressStatus::matched,
          .logical_interface_id = found->logical_interface_id,
          .received_marking = marking};
}

bool SapForwardingTable::egress(std::uint64_t logical_interface_id,
                                const packet::Frame &internal,
                                const SapVlanMarking &marking,
                                packet::Frame &wire) const noexcept {
  const auto *attachment = find_logical(logical_interface_id);
  const auto parsed = packet::parse_ethernet(internal);
  if (!attachment || !parsed || parsed->vlan_tag_count != 0U ||
      marking.outer_priority_code_point > 7U ||
      marking.inner_priority_code_point > 7U)
    return false;

  std::array<packet::EthernetView::VlanTag, 2U> tags{};
  const auto count = tag_count(attachment->sap.encapsulation);
  if (count >= 1U)
    tags[0] = {.tpid = attachment->outer_tpid,
               .vlan_identifier = *attachment->sap.outer_vlan,
               .priority_code_point = marking.outer_priority_code_point,
               .drop_eligible = marking.outer_drop_eligible};
  if (count == 2U)
    tags[1] = {.tpid = attachment->inner_tpid,
               .vlan_identifier = *attachment->sap.inner_vlan,
               .priority_code_point = marking.inner_priority_code_point,
               .drop_eligible = marking.inner_drop_eligible};
  wire = internal;
  return packet::insert_vlan_tags(
      wire, std::span<const packet::EthernetView::VlanTag>{tags}.first(count));
}

} // namespace router::service
