// Forwarding-owned IKEv2 UDP attachment. It binds emulator sockets only and
// classifies received application payloads for the local IKE/IPsec owner. It
// cannot address another endpoint, inject a packet into a peer or call a host
// networking API. Endpoint routing remains responsible for every transmission.

#pragma once

#include "router/ipsec_nat_t.hpp"
#include "router/udp_transport.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::ikev2 {

enum class UdpInboundKind : std::uint8_t { ike, esp, nat_keepalive };

struct UdpInboundDatagram {
  transport::UdpDatagramMetadata metadata{};
  UdpInboundKind kind{UdpInboundKind::ike};
  // The view is valid only during the handler call. A consumer that needs to
  // retain the packet must copy it into its own bounded packet repository.
  std::span<const std::uint8_t> bytes;
};

using UdpInboundHandler = bool (*)(void *context,
                                   const UdpInboundDatagram &datagram);

enum class UdpServiceResult : std::uint8_t {
  empty,
  delivered,
  malformed,
  handler_rejected,
  transport_error
};

struct UdpServiceCheckpoint {
  std::array<transport::UdpSocketHandle, 4U> sockets{};
  bool configured{};
};

class UdpService final {
public:
  UdpService();

  // Configuration is transactional. If any wildcard bind conflicts, every
  // socket created by this attempt is closed and no partial listener remains.
  [[nodiscard]] bool configure(transport::UdpEndpoint &endpoint) noexcept;
  void remove(transport::UdpEndpoint &endpoint) noexcept;

  // One call consumes at most one datagram, preserving forwarding-shard work
  // budgets. Port 500 is direct IKE. Port 4500 uses RFC 3948 classification.
  [[nodiscard]] UdpServiceResult service_one(
      transport::UdpEndpoint &endpoint, void *context,
      UdpInboundHandler handler) noexcept;

  [[nodiscard]] std::optional<transport::UdpSocketHandle>
  socket(transport::IpFamily family, bool encapsulated) const noexcept;

  // The UDP endpoint owns queued bytes and socket generations. This checkpoint
  // stores only handles and validates them against the already-restored UDP
  // owner, preventing stale handle resurrection.
  [[nodiscard]] UdpServiceCheckpoint checkpoint() const noexcept;
  [[nodiscard]] static bool validate_checkpoint(
      const UdpServiceCheckpoint &state,
      const transport::UdpEndpointCheckpoint &udp_state) noexcept;
  [[nodiscard]] bool restore(const UdpServiceCheckpoint &state,
                             const transport::UdpEndpoint &endpoint) noexcept;

private:
  [[nodiscard]] static std::size_t socket_index(transport::IpFamily family,
                                                bool encapsulated) noexcept;

  std::array<transport::UdpSocketHandle, 4U> sockets_{};
  std::vector<std::uint8_t> receive_buffer_;
  bool configured_{};
};

} // namespace router::ikev2
