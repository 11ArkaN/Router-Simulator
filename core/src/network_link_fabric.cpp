// Physical medium implementation. It contains no ARP, IP, ICMP, FIB or CLI
// logic and cannot complete a packet operation without receiver callbacks.

#include "network_link_fabric.hpp"

namespace router::network_detail {

bool LinkFabric::enqueue(std::size_t direction,
                         const packet::Frame &frame) noexcept {
  // Pool allocation precedes TX admission. A full TX ring returns its handle so
  // every failure path preserves pool ownership exactly once.
  if (direction >= directions_.size())
    return false;
  const auto handle = pool_.allocate(frame);
  if (!handle)
    return false;
  if (!directions_[direction].tx.try_push(*handle)) {
    pool_.release(*handle);
    return false;
  }
  return true;
}

void LinkFabric::set_propagation(std::size_t endpoint,
                                 std::chrono::nanoseconds value) noexcept {
  // One physical full-duplex link applies the same propagation value to both
  // independently serialized directions.
  if (endpoint >= endpoint_count)
    return;
  directions_[to_router(endpoint)].link.set_propagation(value);
  directions_[to_endpoint(endpoint)].link.set_propagation(value);
}

void LinkFabric::pump_transmit(void *context, FrameObserver observer) noexcept {
  // Peek keeps the handle in TX until LinkDirection accepts it. A busy
  // in-flight ring therefore applies backpressure without reordering the queue.
  for (std::size_t index = 0; index < directions_.size(); ++index) {
    auto &direction = directions_[index];
    PacketHandle handle{};
    while (direction.tx.try_peek(handle)) {
      if (!direction.link.try_transmit(
              {.packet_handle = handle,
               .captured_octets = pool_.get(handle).size()}))
        break;
      static_cast<void>(direction.tx.try_pop(handle));
      if (observer)
        observer(context, index, pool_.get(handle));
    }
  }
}

void LinkFabric::pump_delivery(void *context, FrameObserver observer) noexcept {
  // Delivery copies a complete encoded frame before releasing its pool handle.
  // Receiver processing may enqueue another frame but can never retain storage
  // owned by this component.
  for (std::size_t index = 0; index < directions_.size(); ++index) {
    auto &direction = directions_[index];
    PacketHandle handle{};
    while (!direction.rx.full() && direction.link.pop_delivered(handle)) {
      static_cast<void>(direction.rx.try_push(handle));
    }
    while (direction.rx.try_pop(handle)) {
      const auto frame = pool_.get(handle);
      pool_.release(handle);
      if (observer)
        observer(context, index, frame);
    }
  }
}

std::optional<std::chrono::steady_clock::time_point>
LinkFabric::next_delivery() const noexcept {
  // Scanning read-only link-owned deadlines chooses a sleep bound only. It does
  // not execute work, advance time or become a future-event scheduler.
  std::optional<std::chrono::steady_clock::time_point> next;
  for (const auto &direction : directions_) {
    const auto candidate = direction.link.next_delivery();
    if (candidate && (!next || *candidate < *next))
      next = candidate;
  }
  return next;
}

} // namespace router::network_detail
