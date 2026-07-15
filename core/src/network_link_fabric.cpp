// Physical medium implementation. It contains no ARP, IP, ICMP, FIB or CLI
// logic and cannot complete a packet operation without receiver callbacks.

#include "network_link_fabric.hpp"

#include <vector>

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

void LinkFabric::checkpoint(NetworkCheckpointState &state,
                            std::chrono::steady_clock::time_point now) const {
  // Queue order is copied from each owner without mutation. Pool handles never
  // enter the public state because they are meaningful only in this instance.
  for (std::size_t direction_index = 0;
       direction_index < directions_.size(); ++direction_index) {
    const auto &direction = directions_[direction_index];
    PacketHandle handle{};
    for (std::size_t index = 0; index < direction.tx.size(); ++index) {
      static_cast<void>(direction.tx.copy_at(index, handle));
      state.frames.push_back(
          {.stage = NetworkFrameStage::fabric_tx,
           .direction = static_cast<std::uint8_t>(direction_index),
           .frame = pool_.get(handle)});
    }
    const auto link = direction.link.checkpoint(now);
    state.transmitter_remaining_ns[direction_index] =
        link.transmitter_remaining_ns;
    for (std::size_t index = 0; index < link.count; ++index) {
      state.frames.push_back(
          {.stage = NetworkFrameStage::fabric_in_flight,
           .direction = static_cast<std::uint8_t>(direction_index),
           .remaining_ns = link.in_flight[index].remaining_ns,
           .frame = pool_.get(link.in_flight[index].packet_handle)});
    }
    for (std::size_t index = 0; index < direction.rx.size(); ++index) {
      static_cast<void>(direction.rx.copy_at(index, handle));
      state.frames.push_back(
          {.stage = NetworkFrameStage::fabric_rx,
           .direction = static_cast<std::uint8_t>(direction_index),
           .frame = pool_.get(handle)});
    }
  }
}

void LinkFabric::clear_owned(
    std::chrono::steady_clock::time_point now) noexcept {
  // Take a handle snapshot before clearing LinkDirection because future
  // deadlines cannot be popped safely through the normal delivery method.
  for (auto &direction : directions_) {
    PacketHandle handle{};
    while (direction.tx.try_pop(handle))
      pool_.release(handle);
    const auto link = direction.link.checkpoint(now);
    for (std::size_t index = 0; index < link.count; ++index)
      pool_.release(link.in_flight[index].packet_handle);
    static_cast<void>(direction.link.restore({}, now));
    while (direction.rx.try_pop(handle))
      pool_.release(handle);
  }
}

bool LinkFabric::restore(const NetworkCheckpointState &state,
                         std::chrono::steady_clock::time_point now) noexcept {
  // Validation precedes mutation where possible. Frame sizes and direction
  // indices are untrusted checkpoint input and must not index pool or arrays.
  // One link snapshot can be tens of KiB at the generated in-flight capacity.
  // Checkpoint restore is a cold path, so heap storage prevents overflowing the
  // deliberately small Wasm pthread stack without affecting packet admission.
  std::vector<LinkDirection::State> links(direction_count);
  for (std::size_t direction = 0; direction < links.size(); ++direction)
    links[direction].transmitter_remaining_ns =
        state.transmitter_remaining_ns[direction];
  for (const auto &stored : state.frames) {
    if ((stored.stage == NetworkFrameStage::fabric_tx ||
         stored.stage == NetworkFrameStage::fabric_in_flight ||
         stored.stage == NetworkFrameStage::fabric_rx) &&
        (stored.direction >= directions_.size() || !stored.frame.length ||
         stored.frame.length > stored.frame.bytes.size()))
      return false;
    if (stored.stage == NetworkFrameStage::fabric_in_flight &&
        links[stored.direction].count ==
            links[stored.direction].in_flight.size())
      return false;
  }

  clear_owned(now);
  // In-flight handles are staged outside Direction until link.restore accepts
  // the complete ordered list. TX and RX handles are already owned by their
  // queues and clear_owned can release them. This separate list closes the one
  // rollback window where a pool handle otherwise had no owner at all.
  std::vector<std::pair<PacketHandle, std::uint8_t>> staged_in_flight;
  staged_in_flight.reserve(state.frames.size());
  for (const auto &stored : state.frames) {
    if (stored.stage != NetworkFrameStage::fabric_tx &&
        stored.stage != NetworkFrameStage::fabric_in_flight &&
        stored.stage != NetworkFrameStage::fabric_rx)
      continue;
    const auto handle = pool_.allocate(stored.frame);
    if (!handle) {
      clear_owned(now);
      return false;
    }
    auto &direction = directions_[stored.direction];
    bool accepted{};
    if (stored.stage == NetworkFrameStage::fabric_tx)
      accepted = direction.tx.try_push(*handle);
    else if (stored.stage == NetworkFrameStage::fabric_rx)
      accepted = direction.rx.try_push(*handle);
    else {
      auto &link = links[stored.direction];
      link.in_flight[link.count++] = {
          .packet_handle = *handle, .remaining_ns = stored.remaining_ns};
      staged_in_flight.emplace_back(*handle, stored.direction);
      accepted = true;
    }
    if (!accepted) {
      pool_.release(*handle);
      clear_owned(now);
      for (const auto &[staged, ignored_direction] : staged_in_flight) {
        static_cast<void>(ignored_direction);
        pool_.release(staged);
      }
      return false;
    }
  }
  for (std::size_t direction = 0; direction < directions_.size(); ++direction) {
    if (!directions_[direction].link.restore(links[direction], now)) {
      // Earlier directions transferred ownership to LinkDirection and are
      // released by clear_owned. The failed direction clears its own ring
      // without releasing handles, while later directions were never offered.
      clear_owned(now);
      for (const auto &[staged, staged_direction] : staged_in_flight) {
        if (staged_direction >= direction)
          pool_.release(staged);
      }
      return false;
    }
  }
  return true;
}

} // namespace router::network_detail
