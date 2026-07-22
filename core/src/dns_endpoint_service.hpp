// DNS application owner attached to one EndpointStack. Resolver queries cross
// its real UDP or TCP sockets and encoded IP path. The service owns no fabric,
// route table, peer endpoint or browser state.

#pragma once

#include "network_endpoint.hpp"
#include "router/dns_authoritative.hpp"
#include "router/dns_endpoint_checkpoint.hpp"
#include "router/dns_resolver.hpp"
#include "router/dnssec_signed_zone_owner.hpp"
#ifdef __EMSCRIPTEN__
#include "router/dnssec_openssl.hpp"
#endif

#include <array>
#include <memory>
#include <optional>
#include <vector>

namespace router::network_detail {

class DnsEndpointService final {
public:
  using Clock = EndpointStack::Clock;

  ~DnsEndpointService();

  [[nodiscard]] bool
  configure_resolver(crypto::Sha256Digest identifier_secret,
                     std::vector<dns::RootHint> root_hints,
                     std::vector<dns::ZoneRecord> trust_anchors,
                     dnssec::Nsec3IterationPolicy nsec3_policy,
                     bool serve_clients, EndpointStack &endpoint);
  void remove_resolver(EndpointStack &endpoint) noexcept;
  [[nodiscard]] bool configure_authoritative(std::vector<dns::Zone> zones,
                                             EndpointStack &endpoint);
  // The wrapping key is installed on the same service shard before signed
  // configuration or restore. It is used only to seal and unseal provider
  // keys in checkpoints and is erased when this owner is destroyed.
  [[nodiscard]] bool initialize_signing_vault(
      std::span<const std::uint8_t> wrapping_key,
      std::span<const std::uint8_t> project_context) noexcept;
  [[nodiscard]] bool
  configure_signed_authoritative(std::vector<dnssec::SignedZoneOwner> zones,
                                 EndpointStack &endpoint);
  void remove_authoritative(EndpointStack &endpoint) noexcept;

  [[nodiscard]] std::optional<dns::TransactionHandle>
  resolve(const packet::dns::Question &question,
          Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<dns::ResolutionResult>
  result(dns::TransactionHandle handle) const;
  [[nodiscard]] bool release(dns::TransactionHandle handle) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  // Checkpoint copies application-owned buffers and stores deadlines relative
  // to now through ResolverCheckpoint. restore is transactional: every socket
  // generation and record set is validated before live state is replaced.
  [[nodiscard]] std::optional<dns::EndpointServiceCheckpoint>
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool
  restore(const dns::EndpointServiceCheckpoint &state, EndpointStack &endpoint,
          Clock::time_point now = Clock::now(),
          std::optional<std::uint64_t> wall_now = std::nullopt) noexcept;

  // One call performs bounded receive and one outbound action. ARP, ND,
  // fragmentation and egress admission remain EndpointStack responsibilities.
  [[nodiscard]] std::optional<Clock::time_point>
  service(EndpointStack &endpoint, void *sink_context,
          packet::Ipv4FragmentSink ipv4_sink,
          packet::Ipv4FragmentAdmission ipv4_admission,
          packet::Ipv6FragmentSink ipv6_sink,
          packet::Ipv6FragmentAdmission ipv6_admission,
          Clock::time_point now = Clock::now(),
          std::optional<std::uint64_t> wall_now = std::nullopt) noexcept;

private:
  struct PendingQuery {
    dns::TransactionHandle transaction{};
    dns::PreparedQuery prepared{};
    std::vector<std::uint8_t> stream_wire;
    std::size_t stream_write_offset{};
    bool active{};
  };
  struct PendingResponse {
    transport::IpFamily family{transport::IpFamily::ipv6};
    packet::Ipv4 destination_ipv4{};
    packet::Ipv6 destination_ipv6{};
    std::uint16_t destination_port{};
    std::size_t message_octets{};
    bool active{};
  };
  struct RecursiveUdpClient {
    dns::TransactionHandle transaction{};
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
  struct ResolverTcpConnection {
    dns::ServerAddress server;
    transport::tcp::EndpointSocketHandle socket{};
    std::vector<std::uint8_t> receive_wire;
    std::size_t received_octets{};
  };
  struct AuthoritativeTcpConnection {
    transport::tcp::EndpointSocketHandle socket{};
    transport::IpFamily family{transport::IpFamily::ipv6};
    std::vector<std::uint8_t> receive_wire;
    std::vector<std::uint8_t> send_wire;
    // RFC 7766 permits multiple outstanding queries on one connection. Each
    // transaction keeps its own DNS ID and flags; send_wire serializes only
    // the currently selected completed response into endpoint TCP bytes.
    std::vector<RecursiveUdpClient> recursive_clients;
    std::size_t received_octets{};
    std::size_t send_offset{};
  };

  [[nodiscard]] bool
  try_send_pending(EndpointStack &endpoint, void *sink_context,
                   packet::Ipv4FragmentSink ipv4_sink,
                   packet::Ipv4FragmentAdmission ipv4_admission,
                   packet::Ipv6FragmentSink ipv6_sink,
                   packet::Ipv6FragmentAdmission ipv6_admission,
                   Clock::time_point now) noexcept;
  [[nodiscard]] bool
  try_send_response(EndpointStack &endpoint, void *sink_context,
                    packet::Ipv4FragmentSink ipv4_sink,
                    packet::Ipv4FragmentAdmission ipv4_admission,
                    packet::Ipv6FragmentSink ipv6_sink,
                    packet::Ipv6FragmentAdmission ipv6_admission,
                    Clock::time_point now) noexcept;
  [[nodiscard]] std::optional<std::size_t>
  build_authoritative_response(std::span<const std::uint8_t> request,
                               std::span<std::uint8_t> output,
                               bool udp) const noexcept;
  [[nodiscard]] std::optional<std::size_t> build_recursive_response(
      const RecursiveUdpClient &client, const dns::ResolutionResult &result,
      std::span<std::uint8_t> output, bool udp) const noexcept;
  [[nodiscard]] const dns::Zone *
  authoritative_zone(const packet::dns::Name &name) const noexcept;

  std::unique_ptr<dns::IterativeResolver> resolver_;
  std::optional<transport::UdpSocketHandle> ipv4_socket_;
  std::optional<transport::UdpSocketHandle> ipv6_socket_;
  std::vector<dns::TransactionHandle> transactions_;
  std::vector<std::uint8_t> query_wire_;
  std::vector<std::uint8_t> response_wire_;
  PendingQuery pending_{};
  std::vector<ResolverTcpConnection> resolver_tcp_connections_;
  std::vector<dns::Zone> zones_;
  std::vector<dnssec::SignedZoneOwner> signed_zones_;
  std::optional<transport::UdpSocketHandle> authoritative_ipv4_socket_;
  std::optional<transport::UdpSocketHandle> authoritative_ipv6_socket_;
  std::optional<transport::tcp::EndpointSocketHandle>
      authoritative_ipv4_listener_;
  std::optional<transport::tcp::EndpointSocketHandle>
      authoritative_ipv6_listener_;
  std::vector<AuthoritativeTcpConnection> authoritative_tcp_connections_;
  std::vector<std::uint8_t> authoritative_request_wire_;
  std::vector<std::uint8_t> authoritative_response_wire_;
  PendingResponse pending_response_{};
  std::vector<RecursiveUdpClient> recursive_udp_clients_;
  bool recursive_service_enabled_{};
  std::array<std::uint8_t, 32U> signing_wrapping_key_{};
  std::vector<std::uint8_t> signing_vault_context_;
  bool signing_vault_initialized_{};
#ifdef __EMSCRIPTEN__
  // The provider performs only local DNSSEC hashing and signature work. It
  // owns no socket and cannot bypass EndpointStack packet delivery.
  dnssec::OpenSslCryptoVerifier dnssec_crypto_{};
#endif
};

} // namespace router::network_detail
