// Serializable DNS service-owner state. These records contain stable socket
// handles and owned bytes only. Endpoint TCP and UDP internals are checkpointed
// separately by EndpointStack, so this layer never duplicates transport state.

#pragma once

#include "router/dns_resolver.hpp"
#include "router/dnssec_signed_zone_owner.hpp"
#include "router/tcp_endpoint.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace router::dns {

struct ZoneCheckpoint {
  packet::dns::Name origin;
  std::vector<ZoneRecord> records;
};

struct PendingQueryCheckpoint {
  TransactionHandle transaction{};
  PreparedQuery prepared{};
  // UDP stores the bare DNS message. TCP stores its length-prefixed write
  // image separately because a checkpoint may occur after a partial write.
  std::vector<std::uint8_t> query_message;
  std::vector<std::uint8_t> stream_wire;
  std::size_t stream_write_offset{};
  bool active{};
};

struct PendingResponseCheckpoint {
  transport::IpFamily family{transport::IpFamily::ipv6};
  packet::Ipv4 destination_ipv4{};
  packet::Ipv6 destination_ipv6{};
  std::uint16_t destination_port{};
  std::vector<std::uint8_t> message;
  bool active{};
};

struct RecursiveUdpClientCheckpoint {
  TransactionHandle transaction{};
  packet::dns::Question question;
  packet::Ipv4 destination_ipv4{};
  packet::Ipv6 destination_ipv6{};
  transport::IpFamily family{transport::IpFamily::ipv6};
  std::uint16_t destination_port{};
  std::uint16_t request_id{};
  std::uint16_t udp_payload_bytes{512U};
  bool recursion_desired{};
  bool checking_disabled{};
  bool dnssec_ok{};
  bool understands_authenticated_data{};
  bool used_edns{};
};

struct ResolverTcpConnectionCheckpoint {
  ServerAddress server;
  transport::tcp::EndpointSocketHandle socket{};
  std::vector<std::uint8_t> received_wire;
};

struct AuthoritativeTcpConnectionCheckpoint {
  transport::tcp::EndpointSocketHandle socket{};
  transport::IpFamily family{transport::IpFamily::ipv6};
  std::vector<std::uint8_t> received_wire;
  std::vector<std::uint8_t> send_wire;
  std::vector<RecursiveUdpClientCheckpoint> recursive_clients;
  std::size_t send_offset{};
};

struct EndpointServiceCheckpoint {
  std::optional<ResolverCheckpoint> resolver;
  std::optional<transport::UdpSocketHandle> resolver_ipv4_socket;
  std::optional<transport::UdpSocketHandle> resolver_ipv6_socket;
  std::vector<TransactionHandle> transactions;
  PendingQueryCheckpoint pending_query;
  std::vector<ResolverTcpConnectionCheckpoint> resolver_tcp_connections;

  std::vector<ZoneCheckpoint> zones;
  // Signed owners persist unsigned source data, encrypted provider keys,
  // operator timing and the relative next-visit deadline. Generated RRSIG
  // records are recreated after restore and are intentionally not trusted.
  std::vector<dnssec::SignedZoneOwnerCheckpoint> signed_zones;
  std::optional<transport::UdpSocketHandle> authoritative_ipv4_socket;
  std::optional<transport::UdpSocketHandle> authoritative_ipv6_socket;
  std::optional<transport::tcp::EndpointSocketHandle>
      authoritative_ipv4_listener;
  std::optional<transport::tcp::EndpointSocketHandle>
      authoritative_ipv6_listener;
  std::vector<AuthoritativeTcpConnectionCheckpoint>
      authoritative_tcp_connections;
  PendingResponseCheckpoint pending_response;
  std::vector<RecursiveUdpClientCheckpoint> recursive_udp_clients;
  bool recursive_service_enabled{};
};

} // namespace router::dns
