// The forwarding AF owner publishes subscribed address usability as local value
// messages. One writer owns the projection and its DAD table. Dependencies point
// to AF state and registry values, never to a routing protocol or another device.
#pragma once
#include "router/ipv6_dad.hpp"
#include "router/ipv6_address_readiness.hpp"
namespace router::lab {
enum class Ipv6ReadinessPublication : std::uint8_t { idle, complete, blocked };
class Ipv6ReadinessProjection final {
public:
  // Cold admission before transfer to the forwarding writer, or on that writer.
  // Device and generation must be live local
  // values; watches require unique interface/address keys, usable physical
  // ordinals and unicast addresses. maximum_watches is the caller's reserved
  // subscription budget. Reconstruct this derived subscription when replacing
  // the DAD owner from a checkpoint. Invalid input throws; nothing is published.
  Ipv6ReadinessProjection(DeviceHandle, std::uint64_t configuration_generation,
      std::span<const Ipv6ReadinessWatch>, std::size_t maximum_watches);
  // Producer: this forwarding owner. Consumer: the local protocol coordinator
  // through its SPSC channel. A sink copies the complete value before returning
  // true. False means full channel and retains the unsent current value for
  // retry, without acknowledging it or changing the DAD owner. Calls allocate
  // nothing. Unsent changes may coalesce to the newest local readiness; sent
  // messages retain FIFO ordering in the external channel. No remote state.
  using Sink = bool (*)(void *, const Ipv6ReadinessChange &) noexcept;
  [[nodiscard]] Ipv6ReadinessPublication publish(const Ipv6DadTable &, void *, Sink) noexcept;
private:
  struct State { Ipv6ReadinessWatch source; std::optional<bool> published; bool desired{}; };
  DeviceHandle device_{};
  std::uint64_t configuration_generation_{}, observed_{};
  std::vector<State> states_;
  bool pending_{true};
};
}
