// Structured Hello-to-Ethernet composition. The protocol owner supplies all
// effective values and retains keys, neighbor lists and addresses. Scratch
// belongs to that control shard and is never shared with the forwarding owner.

#pragma once

#include "router/isis_authentication.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_ethernet.hpp"
#include "router/isis_instance_tlv.hpp"
#include "router/isis_pdu_composition.hpp"
#include "router/isis_three_way.hpp"

namespace router::isis {

using HelloInstanceOption = PduInstanceOption;

struct HelloContents {
  packet::isis::HelloInput header;
  packet::Mac source{};
  packet::Mac destination{};
  std::span<const std::span<const std::uint8_t>> areas;
  std::span<const std::uint8_t> protocols;
  std::span<const packet::Ipv4> ipv4_addresses;
  std::span<const packet::Ipv6> ipv6_addresses;
  std::span<const packet::Mac> neighbors;
  std::optional<ThreeWayOption> three_way;
  std::optional<HelloInstanceOption> instance;
  std::optional<AuthenticationKey> authentication;
  std::size_t maximum_pdu_octets{};
  bool padding{};
  bool physical_point_to_point{};
};

using HelloScratch = PduScratch;

enum class HelloBuildResult : std::uint8_t {
  encoded, invalid_header, capacity, areas, addresses, instance, three_way, authentication
};

// Requires effective configuration already accepted by its source-backed
// model, with all input/output views disjoint from scratch. Splits lists into
// complete TLVs, advertises IID first and finalizes authentication after all
// padding. P2P Hellos require this implementation's three-way option; LAN
// Hellos must not carry it. IPv6 Hello address lists must be link-local.
// The caller selects mandatory area/NLPID/address content and multicast policy.
// Failure preserves output. Input spans borrow only for this call. The caller
// owns the resulting frame until publishing it through its egress SPSC channel.
[[nodiscard]] HelloBuildResult build_hello_frame(packet::Frame &output,
    const HelloContents &contents, HelloScratch &scratch) noexcept;

} // namespace router::isis
