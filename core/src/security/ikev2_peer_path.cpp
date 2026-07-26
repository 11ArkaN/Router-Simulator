// NAT-T tuple state and keepalive deadlines. Tuple changes are committed only
// for a cryptographically validated new packet and are transactionally restored
// from relative monotonic time, preventing replay-driven address rollback.

#include "router/ikev2_peer_path.hpp"

#include "router/ipsec_nat_t.hpp"

#include <limits>

namespace router::ikev2 {
namespace {

bool add_interval(PeerPath::Clock::time_point now,
                  std::chrono::seconds interval,
                  PeerPath::Clock::time_point &deadline) noexcept {
  const auto duration =
      std::chrono::duration_cast<PeerPath::Clock::duration>(interval);
  if (duration <= PeerPath::Clock::duration::zero() ||
      now > PeerPath::Clock::time_point::max() - duration)
    return false;
  deadline = now + duration;
  return true;
}

bool endpoint_address_equal(const PeerEndpoint &left,
                            const PeerEndpoint &right) noexcept {
  if (left.family != right.family)
    return false;
  return left.family == transport::IpFamily::ipv4 ? left.ipv4 == right.ipv4
                                                   : left.ipv6 == right.ipv6;
}

} // namespace

PeerPath::PeerPath(PeerPathConfiguration configuration) noexcept
    : configuration_(configuration) {}

PeerEndpoint PeerPath::source(
    const transport::UdpDatagramMetadata &metadata) noexcept {
  return {.family = metadata.family,
          .ipv4 = metadata.source_ipv4,
          .ipv6 = metadata.source_ipv6,
          .port = metadata.source_port};
}

PeerEndpoint PeerPath::destination(
    const transport::UdpDatagramMetadata &metadata) noexcept {
  return {.family = metadata.family,
          .ipv4 = metadata.destination_ipv4,
          .ipv6 = metadata.destination_ipv6,
          .port = metadata.destination_port};
}

bool PeerPath::arm_keepalive(Clock::time_point now) noexcept {
  keepalive_armed_ = nat_traversal_ && local_behind_nat_ &&
                     configuration_.keepalive_interval.count() > 0;
  if (!keepalive_armed_) {
    keepalive_deadline_ = Clock::time_point::max();
    return true;
  }
  if (!add_interval(now, configuration_.keepalive_interval,
                    keepalive_deadline_)) {
    keepalive_armed_ = false;
    keepalive_deadline_ = Clock::time_point::max();
    return false;
  }
  return true;
}

bool PeerPath::establish(const transport::UdpDatagramMetadata &metadata,
                         bool local_behind_nat, bool peer_behind_nat,
                         Clock::time_point now) noexcept {
  if (established_ ||
      (metadata.destination_port != ipsec::nat_t::ike_port &&
       metadata.destination_port != ipsec::nat_t::encapsulated_port) ||
      metadata.source_port == 0U)
    return false;
  auto local = destination(metadata);
  auto remote = source(metadata);
  const bool nat = local_behind_nat || peer_behind_nat;
  if (nat) {
    // RFC 7296 requires every subsequent IKE and ESP packet to use 4500 after
    // either NAT detection mismatch, irrespective of the initial port 500.
    local.port = ipsec::nat_t::encapsulated_port;
    remote.port = ipsec::nat_t::encapsulated_port;
  }
  local_ = local;
  remote_ = remote;
  nat_traversal_ = nat;
  local_behind_nat_ = local_behind_nat;
  peer_behind_nat_ = peer_behind_nat;
  established_ = true;
  if (!arm_keepalive(now)) {
    established_ = false;
    return false;
  }
  return true;
}

PeerPathUpdate PeerPath::observe_authenticated(
    const transport::UdpDatagramMetadata &metadata,
    bool authenticated_new_message, Clock::time_point now) noexcept {
  if (!established_)
    return PeerPathUpdate::unavailable;
  const auto received_local = destination(metadata);
  const auto received_remote = source(metadata);
  if (received_local.family != local_.family ||
      received_remote.family != remote_.family)
    return PeerPathUpdate::wrong_family;
  if (!endpoint_address_equal(received_local, local_) ||
      received_local.port != local_.port || received_remote.port == 0U)
    return PeerPathUpdate::wrong_local_tuple;
  if (received_remote == remote_) {
    static_cast<void>(arm_keepalive(now));
    return PeerPathUpdate::unchanged;
  }
  if (!authenticated_new_message)
    return PeerPathUpdate::rejected_unvalidated;
  if (local_behind_nat_)
    return PeerPathUpdate::rejected_local_behind_nat;
  remote_ = received_remote;
  static_cast<void>(arm_keepalive(now));
  return PeerPathUpdate::updated;
}

void PeerPath::note_outbound_activity(Clock::time_point now) noexcept {
  if (established_)
    static_cast<void>(arm_keepalive(now));
}

bool PeerPath::poll_keepalive(Clock::time_point now) noexcept {
  if (!established_ || !keepalive_armed_ || now < keepalive_deadline_)
    return false;
  if (!arm_keepalive(now))
    return false;
  return true;
}

std::optional<PeerPathCheckpoint>
PeerPath::checkpoint(Clock::time_point now) const noexcept {
  if (!established_)
    return PeerPathCheckpoint{.configuration = configuration_};
  std::int64_t remaining{};
  if (keepalive_armed_) {
    const auto value = std::chrono::duration_cast<std::chrono::nanoseconds>(
                           keepalive_deadline_ - now)
                           .count();
    remaining = value > 0 ? value : 0;
  }
  return PeerPathCheckpoint{.local = local_,
                            .remote = remote_,
                            .configuration = configuration_,
                            .keepalive_remaining_nanoseconds = remaining,
                            .nat_traversal = nat_traversal_,
                            .local_behind_nat = local_behind_nat_,
                            .peer_behind_nat = peer_behind_nat_,
                            .keepalive_armed = keepalive_armed_,
                            .established = established_};
}

bool PeerPath::restore(const PeerPathCheckpoint &checkpoint,
                       Clock::time_point now) noexcept {
  if (checkpoint.configuration.keepalive_interval.count() < 0 ||
      checkpoint.keepalive_remaining_nanoseconds < 0 ||
      checkpoint.nat_traversal !=
          (checkpoint.local_behind_nat || checkpoint.peer_behind_nat) ||
      (!checkpoint.established &&
       (checkpoint.nat_traversal || checkpoint.local_behind_nat ||
        checkpoint.peer_behind_nat || checkpoint.keepalive_armed ||
        checkpoint.local.port != 0U || checkpoint.remote.port != 0U)) ||
      (checkpoint.established &&
       (checkpoint.local.family != checkpoint.remote.family ||
        checkpoint.local.port == 0U || checkpoint.remote.port == 0U ||
        (checkpoint.nat_traversal &&
         (checkpoint.local.port != ipsec::nat_t::encapsulated_port ||
          checkpoint.remote.port != ipsec::nat_t::encapsulated_port)))) ||
      (checkpoint.keepalive_armed &&
       (!checkpoint.established || !checkpoint.nat_traversal ||
        !checkpoint.local_behind_nat ||
        checkpoint.configuration.keepalive_interval.count() <= 0)))
    return false;
  auto deadline = Clock::time_point::max();
  if (checkpoint.keepalive_armed) {
    const auto duration = std::chrono::nanoseconds{
        checkpoint.keepalive_remaining_nanoseconds};
    if (now > Clock::time_point::max() - duration)
      return false;
    deadline = now + duration;
  }
  configuration_ = checkpoint.configuration;
  local_ = checkpoint.local;
  remote_ = checkpoint.remote;
  keepalive_deadline_ = deadline;
  nat_traversal_ = checkpoint.nat_traversal;
  local_behind_nat_ = checkpoint.local_behind_nat;
  peer_behind_nat_ = checkpoint.peer_behind_nat;
  keepalive_armed_ = checkpoint.keepalive_armed;
  established_ = checkpoint.established;
  return true;
}

} // namespace router::ikev2
