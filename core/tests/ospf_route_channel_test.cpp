// Ownership and backpressure tests for the shared OSPF route-generation
// channel. Tests exchange real route records so a handle-only test cannot hide
// a missing release/acquire relationship for the large shared slot.

#include "router/ospf_route_channel.hpp"

#include <memory>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_route_channel_tests() {
  // Production owns these profile-sized route slots on the heap. Mirroring
  // that placement keeps the test stack independent of route scale and still
  // exercises the exact channel type used across pthreads.
  auto channel =
      std::make_unique<router::ospf::RouteGenerationChannel<2U>>();
  const auto first = channel->try_acquire();
  require(first.has_value(), "route channel did not provide its first slot");
  first->generation->device = {.index = 3U, .generation = 7U};
  first->generation->generation = 11U;
  first->generation->ipv4[0] = {
      .configured = true,
      .operational = true,
      .network = 0xc0000200U,
      .next_hop = 0xc6336402U,
      .port_ordinal = 4U,
      .preference = 10U,
      .metric = 20U,
      .prefix_length = 24U,
      .source = router::lab::routing::RouteSource::ospf,
      .ospf_path_type = router::lab::routing::OspfPathType::intra_area,
      .internal_metric = 20U,
      .area_id = 1U,
      .protocol_instance = 0U};
  first->generation->ipv4_count = 1U;
  require(channel->publish(first->handle),
          "route channel rejected a valid complete generation");

  const auto received = channel->try_receive();
  require(received && received->generation->device.index == 3U &&
              received->generation->generation == 11U &&
              received->generation->ipv4_count == 1U &&
              received->generation->ipv4[0].metric == 20U,
          "route channel did not preserve the immutable generation bytes");
  require(channel->release(received->handle),
          "route channel could not return its borrowed slot");

  // Producer reclaim happens on acquire. Both slots must remain reusable after
  // one full ownership cycle, while a third simultaneous acquisition observes
  // explicit backpressure instead of aliasing an in-flight generation.
  const auto second = channel->try_acquire();
  const auto third = channel->try_acquire();
  require(second && third && !channel->try_acquire(),
          "route channel capacity did not enforce bounded ownership");
  require(channel->cancel(second->handle) && channel->cancel(third->handle),
          "route channel could not cancel unpublished writable slots");
}
