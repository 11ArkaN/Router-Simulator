// Multi-device fabric tests verify real frame ownership, generation isolation,
// carrier drops and independent point-to-point delivery without peer calls.

#include "router/multi_device_fabric.hpp"

#include <chrono>
#include <memory>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  // Throwing integrates with the repository's compact module-test runner and
  // retains the first violated ownership contract as the test diagnostic.
  if (!condition)
    throw std::runtime_error(message);
}

struct Observation {
  std::size_t deliveries{};
  router::lab::LinkHandle link{};
  router::lab::PortHandle destination{};
  std::uint16_t frame_length{};
};

void observe(void *context,
             const router::lab::MultiDeviceFabric::Delivery &delivery) {
  // Copy only values needed after the callback. Holding delivery.frame would
  // violate the pool's borrowed-reference lifetime contract.
  auto &result = *static_cast<Observation *>(context);
  ++result.deliveries;
  result.link = delivery.link;
  result.destination = delivery.destination;
  result.frame_length = delivery.frame.length;
}

} // namespace

void multi_device_fabric_tests() {
  using namespace router;
  using namespace router::lab;
  // The fabric contains the one 64 MiB packet pool and a bounded direction
  // array, so heap allocation keeps the native test thread stack intentionally
  // small and matches RuntimeSupervisor ownership.
  auto fabric = std::make_unique<MultiDeviceFabric>();

  const DeviceHandle r1{0, 1};
  const DeviceHandle r2{1, 1};
  const DeviceHandle r3{2, 1};
  const PortHandle r1p1{node(r1), 0, 1};
  const PortHandle r2p1{node(r2), 0, 1};
  const PortHandle r2p2{node(r2), 1, 1};
  const PortHandle r3p1{node(r3), 0, 1};
  const LinkHandle first{0, 1};
  const LinkHandle second{1, 1};

  require(fabric->configure(first, r1p1, r2p1, 10'000'000'000ULL,
                            std::chrono::nanoseconds{100}),
          "fabric rejected first valid point-to-point link");
  require(fabric->configure(second, r2p2, r3p1, 10'000'000'000ULL,
                            std::chrono::nanoseconds{200}),
          "fabric rejected second valid point-to-point link");
  require(fabric->active_links() == 2,
          "fabric did not retain independent active links");

  const auto frame = packet::arp_request(
      {0x02, 0, 0, 0, 0, 1}, {192, 0, 2, 1}, {192, 0, 2, 2});
  require(fabric->enqueue(first, 0, frame) ==
              MultiDeviceFabric::DropReason::carrier_down,
          "fabric admitted traffic before carrier became operational");
  require(fabric->set_carrier(first, true),
          "fabric rejected carrier transition for a live link");

  const auto now = MultiDeviceFabric::Clock::now();
  require(fabric->enqueue(first, 0, frame) ==
              MultiDeviceFabric::DropReason::none,
          "fabric rejected a valid encoded frame");
  fabric->pump_transmit(now);
  Observation observation;
  // One microsecond exceeds minimum 10 Gb/s serialization plus configured
  // propagation, avoiding sleeps and host scheduler noise in the native test.
  fabric->pump_delivery(&observation, observe,
                        now + std::chrono::microseconds{1});
  require(observation.deliveries == 1 && observation.link == first &&
              observation.destination == r2p1 &&
              observation.frame_length == frame.length,
          "fabric delivered bytes to the wrong link endpoint");

  require(fabric->set_carrier(first, false),
          "fabric rejected carrier loss for a live link");
  require(fabric->remove(first), "fabric rejected live link removal");
  require(fabric->enqueue(first, 0, frame) ==
              MultiDeviceFabric::DropReason::stale_link,
          "fabric accepted a frame through a removed link handle");
  const LinkHandle replacement{0, 2};
  require(fabric->configure(replacement, r1p1, r2p1, 10'000'000'000ULL,
                            std::chrono::nanoseconds{0}),
          "fabric rejected a replacement link generation");
  require(!fabric->set_carrier(first, true),
          "stale link generation changed replacement carrier");

  require(fabric->set_carrier(replacement, true) &&
              fabric->enqueue(replacement, 0, frame) ==
                  MultiDeviceFabric::DropReason::none,
          "fabric could not stage a frame for checkpoint testing");
  const auto checkpoint_time = MultiDeviceFabric::Clock::now();
  fabric->pump_transmit(checkpoint_time);
  auto checkpoint = std::make_unique<MultiDeviceFabricCheckpoint>(
      fabric->checkpoint(checkpoint_time));
  require(checkpoint->links.size() == 2 &&
              checkpoint->links[0].directions[0].in_flight.size() == 1,
          "fabric checkpoint lost an encoded in-flight frame");
  // Release the first 64 MiB pool before constructing the restore target. This
  // matches atomic runtime import, which validates the heap image first and
  // then installs it into the existing single pool.
  fabric.reset();
  fabric = std::make_unique<MultiDeviceFabric>();
  require(fabric->restore(*checkpoint, checkpoint_time),
          "fabric rejected its own structural checkpoint");
  observation = {};
  fabric->pump_delivery(&observation, observe,
                        checkpoint_time + std::chrono::microseconds{1});
  require(observation.deliveries == 1 && observation.link == replacement &&
              observation.destination == r2p1,
          "restored medium did not retain delivery identity and deadline");

  auto invalid = std::make_unique<MultiDeviceFabricCheckpoint>(*checkpoint);
  invalid->links.front().directions.front().bits_per_second = 0;
  const auto links_before_invalid = fabric->active_links();
  require(!fabric->restore(*invalid, checkpoint_time) &&
              fabric->active_links() == links_before_invalid,
          "invalid fabric checkpoint partially changed live topology");
}
