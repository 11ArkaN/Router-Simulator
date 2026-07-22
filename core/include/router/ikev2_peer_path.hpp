// IKE SA peer-path owner for RFC 7296 NAT traversal. It stores the observed
// local and remote UDP tuples, permits rebinding only after authenticated replay
// admission and owns a local keepalive deadline. It emits no datagram and has
// no access to routes, interfaces, host sockets or another device.

#pragma once

#include "router/udp_transport.hpp"

#include <chrono>
#include <cstdint>
#include <optional>

namespace router::ikev2 {

struct PeerEndpoint {
  transport::IpFamily family{transport::IpFamily::ipv6};
  packet::Ipv4 ipv4{};
  packet::Ipv6 ipv6{};
  std::uint16_t port{};

  [[nodiscard]] friend constexpr bool
  operator==(const PeerEndpoint &, const PeerEndpoint &) noexcept = default;
};

struct PeerPathConfiguration {
  // RFC 3948 leaves the keepalive interval to configuration. Zero disables
  // keepalives even when NAT was detected; no hidden default exists here.
  std::chrono::seconds keepalive_interval{};
};

enum class PeerPathUpdate : std::uint8_t {
  unchanged,
  updated,
  rejected_unvalidated,
  rejected_local_behind_nat,
  wrong_local_tuple,
  wrong_family,
  unavailable
};

struct PeerPathCheckpoint {
  PeerEndpoint local{};
  PeerEndpoint remote{};
  PeerPathConfiguration configuration{};
  std::int64_t keepalive_remaining_nanoseconds{};
  bool nat_traversal{};
  bool local_behind_nat{};
  bool peer_behind_nat{};
  bool keepalive_armed{};
  bool established{};
};

class PeerPath final {
public:
  using Clock = std::chrono::steady_clock;

  explicit PeerPath(PeerPathConfiguration configuration) noexcept;

  // Metadata is from the received IKE_SA_INIT packet, so source identifies the
  // peer and destination identifies this endpoint. NAT detection results come
  // from hashes already checked against that exact packet's outer tuple.
  [[nodiscard]] bool establish(
      const transport::UdpDatagramMetadata &metadata, bool local_behind_nat,
      bool peer_behind_nat, Clock::time_point now = Clock::now()) noexcept;

  // authenticated_new_message must be true only after integrity and replay or
  // Message ID admission. Old authenticated retransmissions cannot roll the
  // path back to a previous NAT mapping.
  [[nodiscard]] PeerPathUpdate observe_authenticated(
      const transport::UdpDatagramMetadata &metadata,
      bool authenticated_new_message,
      Clock::time_point now = Clock::now()) noexcept;

  // Any outbound IKE or ESP packet refreshes a local NAT mapping. poll returns
  // true once per configured idle interval and schedules from the actual send
  // decision instead of accumulating missed events after browser suspension.
  void note_outbound_activity(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool poll_keepalive(
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] std::optional<PeerPathCheckpoint>
  checkpoint(Clock::time_point now) const noexcept;
  [[nodiscard]] bool restore(const PeerPathCheckpoint &checkpoint,
                             Clock::time_point now) noexcept;

  [[nodiscard]] const PeerEndpoint &local() const noexcept { return local_; }
  [[nodiscard]] const PeerEndpoint &remote() const noexcept { return remote_; }
  [[nodiscard]] bool nat_traversal() const noexcept { return nat_traversal_; }
  [[nodiscard]] bool established() const noexcept { return established_; }

private:
  [[nodiscard]] bool arm_keepalive(Clock::time_point now) noexcept;
  [[nodiscard]] static PeerEndpoint source(
      const transport::UdpDatagramMetadata &metadata) noexcept;
  [[nodiscard]] static PeerEndpoint destination(
      const transport::UdpDatagramMetadata &metadata) noexcept;

  PeerPathConfiguration configuration_{};
  PeerEndpoint local_{};
  PeerEndpoint remote_{};
  Clock::time_point keepalive_deadline_{Clock::time_point::max()};
  bool nat_traversal_{};
  bool local_behind_nat_{};
  bool peer_behind_nat_{};
  bool keepalive_armed_{};
  bool established_{};
};

} // namespace router::ikev2
