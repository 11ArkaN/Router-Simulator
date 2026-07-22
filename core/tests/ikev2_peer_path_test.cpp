// NAT-T path tests cover mandatory port switching, authenticated-only remote
// rebinding, replay rollback rejection, local-behind-NAT protection, profiled
// keepalive deadlines and relative checkpoint restoration.

#include "router/ikev2_peer_path.hpp"

#include <chrono>
#include <stdexcept>

void ikev2_peer_path_tests() {
  using namespace router::ikev2;
  using namespace std::chrono_literals;
  namespace transport = router::transport;
  const auto now = PeerPath::Clock::time_point{10s};
  transport::UdpDatagramMetadata initial{
      .family = transport::IpFamily::ipv4,
      .source_ipv4 = {192U, 0U, 2U, 1U},
      .destination_ipv4 = {198U, 51U, 100U, 1U},
      .source_ipv6 = {},
      .destination_ipv6 = {},
      .interface_id = 7U,
      .payload_octets = 28U,
      .source_port = 500U,
      .destination_port = 500U};
  PeerPath path{{.keepalive_interval = 20s}};
  if (!path.establish(initial, false, true, now) || !path.nat_traversal() ||
      path.local().port != 4500U || path.remote().port != 4500U)
    throw std::runtime_error("IKE NAT-T path did not switch to UDP 4500");

  auto rebound = initial;
  rebound.source_ipv4 = {192U, 0U, 2U, 2U};
  rebound.source_port = 46000U;
  rebound.destination_port = 4500U;
  if (path.observe_authenticated(rebound, false, now + 1s) !=
          PeerPathUpdate::rejected_unvalidated ||
      path.observe_authenticated(rebound, true, now + 1s) !=
          PeerPathUpdate::updated ||
      path.remote().ipv4 != rebound.source_ipv4 ||
      path.remote().port != rebound.source_port)
    throw std::runtime_error("IKE authenticated NAT rebinding failed");
  if (path.poll_keepalive(now + 100s))
    throw std::runtime_error("peer-side NAT incorrectly armed keepalive");

  PeerPath local_nat{{.keepalive_interval = 20s}};
  if (!local_nat.establish(initial, true, false, now) ||
      local_nat.observe_authenticated(rebound, true, now + 1s) !=
          PeerPathUpdate::rejected_local_behind_nat ||
      local_nat.poll_keepalive(now + 19s) ||
      !local_nat.poll_keepalive(now + 20s))
    throw std::runtime_error("IKE local NAT keepalive or migration policy failed");

  const auto saved = local_nat.checkpoint(now + 22s);
  PeerPath restored{{.keepalive_interval = 1s}};
  if (!saved || !restored.restore(*saved, now + 100s) ||
      restored.poll_keepalive(now + 117s) ||
      !restored.poll_keepalive(now + 118s))
    throw std::runtime_error("IKE peer path checkpoint changed deadline");
  auto invalid = *saved;
  invalid.nat_traversal = false;
  if (restored.restore(invalid, now + 100s) || !restored.established())
    throw std::runtime_error("invalid IKE path checkpoint replaced live state");
}
