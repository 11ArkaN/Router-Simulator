// RFC 2131 DHCPv4 relay transformation owner and RFC 3046 Option 82 policy.
// The relay accepts and emits complete DHCPv4 UDP payloads only. FIB lookup,
// ARP, interface queues and link delivery remain below this module.

#pragma once

#include "router/dhcpv4_packet.hpp"
#include "router/generated_device_catalog.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace router::dhcpv4 {

enum class ExistingRelayInformationAction : std::uint8_t {
  keep,
  replace,
  drop,
};

// These values mirror the modeled SR OS `src-ip-addr` leaf. `automatic`
// selects the address chosen by the routed egress path, while `gi_address`
// deliberately uses the configured relay gateway as the IPv4 source.
enum class RelaySourceAddress : std::uint8_t {
  automatic,
  gi_address,
};

// Configuration presence is distinct from the generated sub-option bytes.
// The management owner retains the selected SR OS choice so `info` and
// checkpoints do not reverse-engineer configuration from a wire encoding.
enum class CircuitIdSource : std::uint8_t {
  none,
  ascii_tuple,
  interface_name,
  interface_index,
  port_id,
  vlan_ascii_tuple,
};

enum class RemoteIdSource : std::uint8_t {
  none,
  ascii_string,
  client_mac,
};

struct RelayServer {
  packet::Ipv4 address{};

  [[nodiscard]] friend constexpr bool
  operator==(const RelayServer &, const RelayServer &) noexcept = default;
};

struct RelayConfiguration {
  // A configured DHCP context is administratively disabled until explicitly
  // enabled by the CLI. Incomplete disabled configuration remains valid
  // candidate state, but it is never published to the packet owner.
  bool admin_enabled{};
  std::string description;
  packet::Ipv4 gateway_address{};
  bool gateway_address_configured{};
  std::vector<RelayServer> servers;
  std::vector<std::uint8_t> circuit_id;
  std::vector<std::uint8_t> remote_id;
  // SR OS 26.7.R1 defaults this choice to ascii-tuple. Keeping the default in
  // the typed model, rather than manufacturing it in the CLI renderer, makes
  // packet behavior, `info detail`, checkpoints and both CLI engines agree.
  CircuitIdSource circuit_id_source{CircuitIdSource::ascii_tuple};
  RemoteIdSource remote_id_source{RemoteIdSource::none};
  std::string remote_id_ascii;
  ExistingRelayInformationAction existing_information{
      ExistingRelayInformationAction::keep};
  RelaySourceAddress source_address{RelaySourceAddress::automatic};
  // RFC 1542 recommends a configurable threshold with default four and an
  // upper bound of sixteen. It is protocol configuration, not a queue limit.
  std::uint8_t maximum_hops{4U};
  bool trusted_ingress{};
  bool relay_plain_bootp{};
  bool release_include_gateway_address{};

  [[nodiscard]] friend bool
  operator==(const RelayConfiguration &, const RelayConfiguration &) = default;
};

// Logical and physical identity are separate because several routed service
// interfaces may share one Ethernet port. giaddr is the wire return key,
// interface_id owns L3 state, and physical_port_ordinal selects the real link.
struct RelayInterfaceConfiguration {
  std::uint64_t interface_id{};
  std::uint16_t physical_port_ordinal{};
  RelayConfiguration relay{};

  [[nodiscard]] friend bool operator==(const RelayInterfaceConfiguration &,
                                       const RelayInterfaceConfiguration &) =
      default;
};

enum class RelayStatus : std::uint8_t {
  forwarded,
  discarded,
  malformed,
  hop_limit,
  untrusted_relay_information,
  output_too_small,
  not_configured,
};

struct RelayResult {
  RelayStatus status{RelayStatus::discarded};
  std::size_t message_octets{};
  packet::Ipv4 destination{};
  // Direct client delivery is not an ARP lookup. RFC 1542 section 4.1.2
  // explicitly selects the L2 destination from htype, hlen and chaddr because
  // a client may not yet answer ARP for yiaddr. The relay returns that
  // validated Ethernet address to the IP/link owner without retaining input.
  packet::Mac client_mac{};
  bool client_broadcast{};
  bool client_direct_l2{};
};

class RelayAgent final {
public:
  [[nodiscard]] bool configure(const RelayConfiguration &configuration);

  // server_index selects an administrator-configured destination after any
  // higher-level selection policy. The index is validated, never wrapped.
  [[nodiscard]] RelayResult
  forward_client(std::span<const std::uint8_t> input,
                 std::span<std::uint8_t> output,
                 std::size_t server_index) const noexcept;
  [[nodiscard]] RelayResult
  forward_server(std::span<const std::uint8_t> input,
                 std::span<std::uint8_t> output) const noexcept;
  // Configuration is immutable between forwarding-owner command turns.
  // Exposing a const view lets that owner originate one independent wire
  // datagram per configured server without duplicating relay policy state.
  [[nodiscard]] const RelayConfiguration *configuration() const noexcept {
    return configured_ ? &configuration_ : nullptr;
  }

private:
  [[nodiscard]] RelayResult
  encode(const packet::dhcpv4::MessageView &message,
         std::span<std::uint8_t> output, bool add_information,
         bool strip_information) const noexcept;

  RelayConfiguration configuration_{};
  bool configured_{};
};

} // namespace router::dhcpv4
