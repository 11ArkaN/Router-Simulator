// A real bounded SPSC channel exercises local AF publication under backpressure.
// Explicit DAD times prove that unsent state coalesces while accepted values
// keep their exact subscription identity and ordering across retries.
#include "router/ipv6_readiness_projection.hpp"
#include "router/spsc_ring.hpp"
#include <source_location>
#include <stdexcept>
namespace {
using namespace router;
using namespace router::lab;
using Channel = SpscRing<Ipv6ReadinessChange, 2U>;
void require(bool value, std::source_location at = std::source_location::current()) {
  if (!value) throw std::runtime_error("IPv6 AF readiness publication invariant at " + std::to_string(at.line()));
}
bool sink(void *context, const Ipv6ReadinessChange &change) noexcept {
  return static_cast<Channel *>(context)->try_push(change);
}
}
void ipv6_readiness_projection_tests() {
  const DeviceHandle device{0U, 1U};
  const Ipv6ReadinessWatch first{70'001U, 1U, *ip::parse_ipv6("fe80::1")};
  const Ipv6ReadinessWatch second{70'002U, 2U, *ip::parse_ipv6("2001:db8::2")};
  const std::array watches{second, first};
  const auto now = Ipv6DadTable::Clock::time_point{};
  Ipv6DadTable dad;
  require(dad.configure(first.interface_id, first.port_ordinal, first.address, 0U, {}, now));
  require(dad.configure(second.interface_id, second.port_ordinal, second.address, 1U, {}, now));
  Ipv6ReadinessProjection projection(device, 9U, watches, 2U);
  Channel channel;
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::blocked);
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::blocked);
  Ipv6ReadinessChange change;
  require(channel.try_pop(change) && change.version == 1U && change.device == device &&
      change.configuration_generation == 9U && change.source == first && change.preferred);
  require(!channel.try_pop(change));
  std::array<Ipv6DadAction, 1U> actions{};
  require(dad.poll(now, actions) == 1U);
  require(dad.poll(now + device_catalog::nd_retrans_timer, actions) == 0U);
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  require(channel.try_pop(change) && change.source == second && change.preferred && !channel.try_pop(change));
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::idle);
  dad.remove(first.interface_id, first.address);
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  dad.remove(second.interface_id, second.address);
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::blocked);
  require(channel.try_pop(change) && change.source == first && !change.preferred);
  require(projection.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  require(channel.try_pop(change) && change.source == second && !change.preferred && !channel.try_pop(change));
  // A new projection after detached restoration sends a complete current image,
  // even when this DAD generation has not changed since the previous publisher.
  Ipv6ReadinessProjection restored(device, 10U, watches, 2U);
  require(restored.publish(dad, &channel, nullptr) == Ipv6ReadinessPublication::blocked);
  require(restored.publish(dad, &channel, sink) == Ipv6ReadinessPublication::blocked);
  require(channel.try_pop(change) && change.configuration_generation == 10U && !change.preferred);
  require(restored.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  require(channel.try_pop(change) && change.source == second && !change.preferred);
  // A logical interface may be rebound while an old subscription is draining.
  // Its original physical key must never report readiness from the new port.
  require(dad.configure(first.interface_id, first.port_ordinal + 1U, first.address, 0U, {}, now));
  require(restored.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  require(!channel.try_pop(change));
  const std::array rebound{Ipv6ReadinessWatch{first.interface_id,
      static_cast<std::uint16_t>(first.port_ordinal + 1U), first.address}};
  Ipv6ReadinessProjection current_binding(device, 11U, rebound, 1U);
  require(current_binding.publish(dad, &channel, sink) == Ipv6ReadinessPublication::complete);
  require(channel.try_pop(change) && change.configuration_generation == 11U &&
      change.source == rebound[0U] && change.preferred && !channel.try_pop(change));
  const auto refused = [&](DeviceHandle selected, std::uint64_t epoch,
      std::span<const Ipv6ReadinessWatch> program, std::size_t maximum) {
    try { Ipv6ReadinessProjection invalid(selected, epoch, program, maximum); }
    catch (const std::invalid_argument &) { return true; }
    return false;
  };
  require(refused({}, 9U, watches, 2U) && refused(device, 0U, watches, 2U) &&
      refused(device, 9U, watches, 1U));
  auto invalid = watches; invalid[0U] = first;
  require(refused(device, 9U, invalid, 2U));
  invalid = watches; invalid[0U].address = {};
  require(refused(device, 9U, invalid, 2U));
  invalid[0U].address = *ip::parse_ipv6("ff02::1");
  require(refused(device, 9U, invalid, 2U));
  invalid = watches; invalid[0U].port_ordinal = static_cast<std::uint16_t>(device_catalog::maximum_ports_per_router);
  require(refused(device, 9U, invalid, 2U));
}
