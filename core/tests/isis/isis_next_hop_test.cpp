// Owner-local next-hop binding uses encoded Hello addresses and copied local
// scope. Test storage supplies no remote runtime state or neighbor-cache entry.

#include "router/isis_next_hop.hpp"

#include <stdexcept>

namespace {
void require(bool value) {
  if (!value) throw std::runtime_error("IS-IS accepted-Hello next-hop binding invariant failed");
}
}
void isis_next_hop_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  std::array<std::uint8_t, 256U> storage{};
  TlvWriter writer(storage);
  const std::array protocols{ipv4_nlpid, ipv6_nlpid};
  const std::array<packet::Ipv4, 1U> v4{{{203U, 0U, 113U, 7U}}};
  const std::array<packet::Ipv6, 1U> v6{*ip::parse_ipv6("fe80::7")};
  require(writer.append(129U, protocols) && encode_fixed_addresses<4U>(writer, 132U, v4) &&
      encode_fixed_addresses<16U>(writer, 232U, v6));
  P2pSnapshot adjacency;
  adjacency.neighbor_system = {1U, 2U, 3U, 4U, 5U, 7U};
  adjacency.present = adjacency.iso_up = true;
  adjacency.usage = Levels::both;
  const NextHopInterface scope{42U, 17U, 3U};
  const auto address4 = *ip::parse_ip_address("203.0.113.7");
  const auto address6 = *ip::parse_ip_address("fe80::7");
  const auto bind = [&](auto selected, std::uint8_t level = 1U) {
    return bind_p2p_next_hop(adjacency, writer.bytes(), protocols, scope,
        static_cast<std::uint8_t>(level), selected);
  };
  const auto ipv4 = bind(address4);
  const auto ipv6 = bind(address6, 2U);
  require(ipv4 && ipv6 && ipv4->address == address4 && ipv6->address == address6 &&
      ipv4->peer == adjacency.neighbor_system && ipv6->interface == scope && ipv6->level == 2U);
  const auto other_scope = bind_p2p_next_hop(adjacency, writer.bytes(), protocols,
      {43U, 18U, 3U}, 2U, address6);
  require(other_scope && other_scope->interface.interface_id != ipv6->interface.interface_id);
  require(!bind(*ip::parse_ip_address("203.0.113.8")) && !bind(address4, 0U) && !bind(address4, 3U));
  const std::array v4_only{ipv4_nlpid};
  require(!bind_p2p_next_hop(adjacency, writer.bytes(), v4_only, scope, 1U, address6));
  for (const auto invalid : {NextHopInterface{0U, 17U, 3U}, NextHopInterface{42U, 0U, 3U},
       NextHopInterface{42U, 17U, device_catalog::maximum_ports_per_router}})
    require(!bind_p2p_next_hop(adjacency, writer.bytes(), protocols, invalid, 1U, address4));
  adjacency.usage = Levels::level1;
  require(!bind(address4, 2U));
  adjacency.iso_up = false;
  require(!bind(address4));
  adjacency.iso_up = true;
  adjacency.present = false;
  require(!bind(address4));
  adjacency.present = true;
  // A matching address at the front never hides malformed trailing framing.
  const auto length = writer.bytes().size();
  storage[length] = 250U;
  require(!bind_p2p_next_hop(adjacency, std::span(storage).first(length + 1U),
      protocols, scope, 1U, address4));
  // Family support is independent of ISO Up and address presence.
  storage[2U] = 0xeeU;
  require(!bind(address4) && bind(address6).has_value());
  storage[2U] = ipv4_nlpid;
  // Reject non-unicast candidates even when their bytes were advertised.
  for (const auto first : {0U, 127U, 224U, 240U, 255U}) {
    storage[6U] = static_cast<std::uint8_t>(first);
    auto invalid = address4;
    invalid.bytes[0U] = static_cast<std::uint8_t>(first);
    require(!bind(invalid));
  }
  storage[6U] = 203U;
  auto noncanonical = address4;
  noncanonical.bytes[15U] = 1U;
  require(!bind(noncanonical));
  // A malformed known address option invalidates the binding even for IPv4.
  const std::array bad_address{std::uint8_t{1U}};
  require(writer.append(232U, bad_address) && !bind(address4));
}
