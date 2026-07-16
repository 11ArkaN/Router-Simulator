// Link-shard implementation of the global multi-device Ethernet fabric. It
// models only physical transport and never parses ARP, IPv4, ICMP or CLI data.

#include "router/multi_device_fabric.hpp"

#include <algorithm>
#include <utility>

namespace router::lab {

MultiDeviceFabric::MultiDeviceFabric() noexcept {
  // Reverse fill makes the first allocated metadata index zero and matches the
  // packet pool's deterministic free-list behavior. Construction allocates no
  // packet-path objects after the owning supervisor has started its shards.
  for (std::size_t index = 0; index < free_in_flight_.size(); ++index) {
    free_in_flight_[index] = static_cast<std::uint32_t>(
        free_in_flight_.size() - index - 1U);
  }
}

MultiDeviceFabric::Slot *MultiDeviceFabric::find(LinkHandle link) noexcept {
  // Both fields are required. Index alone could address a new cable created in
  // a slot after a delayed forwarding message crossed a shard boundary.
  if (link.index >= slots_.size())
    return nullptr;
  auto &slot = slots_[link.index];
  return slot.active && slot.generation == link.generation ? &slot : nullptr;
}

const MultiDeviceFabric::Slot *
MultiDeviceFabric::find(LinkHandle link) const noexcept {
  // The const lookup is used only for deadline inspection. It cannot expose
  // queue mutation to a caller computing the link shard's next sleep bound.
  if (link.index >= slots_.size())
    return nullptr;
  const auto &slot = slots_[link.index];
  return slot.active && slot.generation == link.generation ? &slot : nullptr;
}

bool MultiDeviceFabric::configure(LinkHandle link, PortHandle first,
                                  PortHandle second,
                                  std::uint64_t bits_per_second,
                                  std::chrono::nanoseconds propagation,
                                  bool carrier) noexcept {
  // Zero generation, duplicate endpoints, zero rate and negative propagation
  // are invalid physical states. Reject before touching an existing medium so
  // a malformed edit cannot tear down a working link.
  if (!link || !first || !second || first == second || !bits_per_second ||
      propagation.count() < 0 || link.index >= slots_.size())
    return false;

  auto &slot = slots_[link.index];
  if (slot.active) {
    // Topology updates are serialized on the owner. Draining before replacing
    // endpoint metadata prevents a queued old frame from reaching a new port.
    drain(slot, Clock::now());
  } else {
    ++active_links_;
  }

  slot.generation = link.generation;
  slot.active = true;
  // Carrier is part of the replacement value. Publishing it here avoids a
  // second fallible control call after an old link generation was drained.
  slot.carrier = carrier;
  slot.endpoints = {first, second};
  for (auto &direction : slot.directions) {
    // Direction zero transmits first to second and direction one the reverse.
    // Both halves negotiate one rate on this point-to-point Ethernet link.
    direction.bits_per_second = bits_per_second;
    direction.propagation = propagation;
    direction.transmitter_available = {};
  }
  return true;
}

bool MultiDeviceFabric::remove(LinkHandle link) noexcept {
  auto *slot = find(link);
  if (!slot)
    return false;
  // Draining happens while the slot is still active so every owned stage can
  // be visited. Metadata is cleared only after all packet handles are returned.
  drain(*slot, Clock::now());
  slot->active = false;
  slot->carrier = false;
  slot->endpoints = {};
  --active_links_;
  return true;
}

bool MultiDeviceFabric::set_carrier(LinkHandle link, bool up) noexcept {
  auto *slot = find(link);
  if (!slot)
    return false;
  if (slot->carrier == up)
    return true;
  // A down transition discards frames at all medium stages. Retaining them and
  // delivering after recovery would invent buffering that the physical link
  // does not provide across loss of signal.
  if (!up)
    drain(*slot, Clock::now());
  slot->carrier = up;
  return true;
}

MultiDeviceFabric::DropReason
MultiDeviceFabric::enqueue(LinkHandle link, std::uint8_t endpoint,
                           const packet::Frame &frame) noexcept {
  auto *slot = find(link);
  if (!slot || endpoint > 1U) {
    ++dropped_frames_;
    return DropReason::stale_link;
  }
  if (!slot->carrier) {
    ++dropped_frames_;
    return DropReason::carrier_down;
  }

  // Pool admission occurs before queue admission. If the bounded TX queue is
  // full, ownership is rolled back immediately and existing FIFO order remains.
  const auto handle = pool_.allocate(frame);
  if (!handle) {
    ++dropped_frames_;
    return DropReason::packet_pool_full;
  }
  auto &direction = slot->directions[endpoint];
  if (!direction.tx.try_push(*handle)) {
    pool_.release(*handle);
    ++dropped_frames_;
    return DropReason::transmit_queue_full;
  }
  return DropReason::none;
}

void MultiDeviceFabric::pump_transmit(Clock::time_point now) noexcept {
  // One frame per direction per visit prevents a saturated cable from filling
  // the global medium slab before another cable gets an admission opportunity.
  std::size_t budget = device_catalog::fabric_work_budget_frames;
  for (std::size_t visited = 0; visited < slots_.size() && budget; ++visited) {
    const auto slot_index = (transmit_cursor_ + visited) % slots_.size();
    auto &slot = slots_[slot_index];
    if (!slot.active || !slot.carrier)
      continue;
    for (auto &direction : slot.directions) {
      PacketHandle handle{};
      if (budget && direction.tx.try_peek(handle)) {
        // One in-flight node is reserved before the TX handle is transferred.
        // The slab is sized to the packet pool, but allocation can still fail
        // while every existing frame happens to occupy the medium stage.
        const auto node_index = allocate_in_flight();
        if (!node_index)
          break;
        const auto &frame = pool_.get(handle);
        const auto mac_octets =
            std::max<std::uint64_t>(frame.size() + 4U, 64U);
        const auto delivery_bits = (8U + mac_octets) * 8U;
        const auto spacing_bits = (8U + mac_octets + 12U) * 8U;
        const auto start = std::max(now, direction.transmitter_available);
        direction.transmitter_available =
            start + serialization_time(spacing_bits,
                                       direction.bits_per_second);

        auto &node = in_flight_[*node_index];
        node.packet = handle;
        node.delivered =
            start + serialization_time(delivery_bits,
                                       direction.bits_per_second) +
            direction.propagation;
        node.next = no_in_flight;
        // Append to this direction only. Frames from another cable never share
        // ordering even though their metadata comes from the same free slab.
        if (direction.in_flight_tail == no_in_flight)
          direction.in_flight_head = *node_index;
        else
          in_flight_[direction.in_flight_tail].next = *node_index;
        direction.in_flight_tail = *node_index;
        static_cast<void>(direction.tx.try_pop(handle));
        --budget;
      }
    }
  }
  transmit_cursor_ = (transmit_cursor_ + 1U) % slots_.size();
}

void MultiDeviceFabric::pump_delivery(void *context, DeliveryObserver observer,
                                      Clock::time_point now) noexcept {
  std::size_t budget = device_catalog::fabric_work_budget_frames;
  for (std::size_t visited = 0; visited < slots_.size() && budget; ++visited) {
    const auto slot_index = (delivery_cursor_ + visited) % slots_.size();
    auto &slot = slots_[slot_index];
    if (!slot.active || !slot.carrier)
      continue;
    for (std::uint8_t direction_index = 0; direction_index < 2U;
         ++direction_index) {
      auto &direction = slot.directions[direction_index];
      PacketHandle handle{};
      // RX is a real bounded device queue. Move only while it has capacity so
      // a slow receiver applies backpressure to the owned in-flight list.
      if (!direction.rx.full() && direction.in_flight_head != no_in_flight) {
        const auto node_index = direction.in_flight_head;
        const auto &node = in_flight_[node_index];
        if (node.delivered <= now) {
          handle = node.packet;
          direction.in_flight_head = node.next;
          if (direction.in_flight_head == no_in_flight)
            direction.in_flight_tail = no_in_flight;
          // RX becomes the packet owner before the metadata node returns to the
          // global free list, so there is no ownerless interval during transfer.
          static_cast<void>(direction.rx.try_push(handle));
          release_in_flight(node_index);
        }
      }

      if (budget && direction.rx.try_pop(handle)) {
        // Direction index denotes the source endpoint. XOR selects the remote
        // endpoint without a branch and is safe because the bound is exactly 2.
        if (observer) {
          const Delivery delivery{
              .link = {static_cast<std::uint16_t>(slot_index), slot.generation},
              .source = slot.endpoints[direction_index],
              .destination = slot.endpoints[direction_index ^ 1U],
              .frame = pool_.get(handle)};
          observer(context, delivery);
        }
        // The callback is synchronous and borrowed. Releasing here makes the
        // exact end of pool ownership visible and prevents receiver retention.
        pool_.release(handle);
        --budget;
      }
    }
  }
  delivery_cursor_ = (delivery_cursor_ + 1U) % slots_.size();
}

std::optional<MultiDeviceFabric::Clock::time_point>
MultiDeviceFabric::next_delivery() const noexcept {
  // Remaining TX work makes the owner immediately runnable while a free
  // in-flight node exists. This schedules all serialized starts without adding
  // propagation delay between consecutive frames.
  if (free_in_flight_count_) {
    for (const auto &slot : slots_)
      if (slot.active && slot.carrier)
        for (const auto &direction : slot.directions)
          if (direction.tx.size())
            return Clock::time_point::min();
  }
  std::optional<Clock::time_point> earliest;
  for (const auto &slot : slots_) {
    if (!slot.active || !slot.carrier)
      continue;
    for (const auto &direction : slot.directions) {
      // This scan chooses only how long the owner may sleep. Work remains in
      // each direction and no central record executes a future event.
      if (direction.in_flight_head == no_in_flight)
        continue;
      const auto candidate = in_flight_[direction.in_flight_head].delivered;
      if (!earliest || candidate < *earliest)
        earliest = candidate;
    }
  }
  return earliest;
}

MultiDeviceFabricCheckpoint
MultiDeviceFabric::checkpoint(Clock::time_point now) const {
  MultiDeviceFabricCheckpoint state;
  state.links.reserve(active_links_);
  for (std::size_t slot_index = 0; slot_index < slots_.size(); ++slot_index) {
    const auto &slot = slots_[slot_index];
    if (!slot.active)
      continue;
    FabricLinkCheckpoint link;
    link.link = {static_cast<std::uint16_t>(slot_index), slot.generation};
    link.endpoints = slot.endpoints;
    link.carrier = slot.carrier;
    for (std::size_t direction_index = 0; direction_index < 2U;
         ++direction_index) {
      const auto &direction = slot.directions[direction_index];
      auto &output = link.directions[direction_index];
      output.bits_per_second = direction.bits_per_second;
      output.propagation_nanoseconds = direction.propagation.count();
      output.transmitter_remaining_nanoseconds =
          direction.transmitter_available > now
              ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                    direction.transmitter_available - now)
                    .count()
              : 0;
      output.transmit.reserve(direction.tx.size());
      for (std::size_t offset = 0; offset < direction.tx.size(); ++offset) {
        PacketHandle handle{};
        static_cast<void>(direction.tx.copy_at(offset, handle));
        output.transmit.push_back({pool_.get(handle), 0});
      }
      for (auto node_index = direction.in_flight_head;
           node_index != no_in_flight; node_index = in_flight_[node_index].next) {
        const auto &node = in_flight_[node_index];
        const auto remaining = node.delivered > now
                                   ? node.delivered - now
                                   : Clock::duration::zero();
        output.in_flight.push_back(
            {pool_.get(node.packet),
             std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                 .count()});
      }
      output.receive.reserve(direction.rx.size());
      for (std::size_t offset = 0; offset < direction.rx.size(); ++offset) {
        PacketHandle handle{};
        static_cast<void>(direction.rx.copy_at(offset, handle));
        output.receive.push_back({pool_.get(handle), 0});
      }
    }
    state.links.push_back(std::move(link));
  }
  state.dropped_frames = dropped_frames_;
  return state;
}

bool MultiDeviceFabric::validate_checkpoint(
    const MultiDeviceFabricCheckpoint &state) noexcept {
  if (state.links.size() > device_catalog::maximum_links)
    return false;
  std::array<bool, device_catalog::maximum_links> seen_links{};
  std::size_t total_frames{};
  const auto valid_frame = [](const FabricFrameCheckpoint &entry) {
    return entry.frame.size() > 0U &&
           entry.frame.size() <= entry.frame.bytes.size();
  };
  for (const auto &link : state.links) {
    if (!link.link || link.link.index >= device_catalog::maximum_links ||
        seen_links[link.link.index] || !link.endpoints[0] ||
        !link.endpoints[1] || link.endpoints[0] == link.endpoints[1])
      return false;
    seen_links[link.link.index] = true;
    for (const auto &direction : link.directions) {
      if (!direction.bits_per_second || direction.propagation_nanoseconds < 0 ||
          direction.transmitter_remaining_nanoseconds < 0 ||
          direction.transmit.size() > device_catalog::link_queue_capacity ||
          direction.receive.size() > device_catalog::link_queue_capacity)
        return false;
      std::int64_t prior_delivery{-1};
      for (const auto &entry : direction.in_flight) {
        // A direction's medium list is FIFO by delivery deadline. Accepting a
        // decreasing deadline would change delivery order after restoration.
        if (!valid_frame(entry) || entry.delivery_remaining_nanoseconds < 0 ||
            entry.delivery_remaining_nanoseconds < prior_delivery)
          return false;
        prior_delivery = entry.delivery_remaining_nanoseconds;
      }
      if (!std::all_of(direction.transmit.begin(), direction.transmit.end(),
                       valid_frame) ||
          !std::all_of(direction.receive.begin(), direction.receive.end(),
                       valid_frame))
        return false;
      total_frames += direction.transmit.size() + direction.in_flight.size() +
                      direction.receive.size();
      if (total_frames > PacketPool::capacity)
        return false;
    }
  }
  return true;
}

bool MultiDeviceFabric::restore(const MultiDeviceFabricCheckpoint &state,
                                Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;

  // Full validation above makes the installation deterministic. Draining all
  // old stages returns every handle before the first restored allocation.
  for (auto &slot : slots_)
    if (slot.active)
      drain(slot, now);
  // Reset one link slot at a time. Assigning an aggregate value to the complete
  // 64-link array can make Clang materialize the whole arena on the 64 KiB Wasm
  // worker stack even though the persistent owner itself is heap allocated.
  for (auto &slot : slots_)
    slot = {};
  transmit_cursor_ = 0;
  delivery_cursor_ = 0;
  active_links_ = 0;
  for (const auto &link : state.links) {
    auto &slot = slots_[link.link.index];
    slot.generation = link.link.generation;
    slot.active = true;
    slot.carrier = link.carrier;
    slot.endpoints = link.endpoints;
    ++active_links_;
    for (std::size_t direction_index = 0; direction_index < 2U;
         ++direction_index) {
      const auto &input = link.directions[direction_index];
      auto &direction = slot.directions[direction_index];
      direction.bits_per_second = input.bits_per_second;
      direction.propagation =
          std::chrono::nanoseconds(input.propagation_nanoseconds);
      direction.transmitter_available =
          now + std::chrono::nanoseconds(
                    input.transmitter_remaining_nanoseconds);
      for (const auto &entry : input.transmit) {
        const auto handle = pool_.allocate(entry.frame);
        if (!handle || !direction.tx.try_push(*handle))
          std::terminate();
      }
      for (const auto &entry : input.in_flight) {
        const auto handle = pool_.allocate(entry.frame);
        const auto node_index = allocate_in_flight();
        if (!handle || !node_index)
          std::terminate();
        auto &node = in_flight_[*node_index];
        node.packet = *handle;
        node.delivered = now + std::chrono::nanoseconds(
                                   entry.delivery_remaining_nanoseconds);
        node.next = no_in_flight;
        if (direction.in_flight_tail == no_in_flight)
          direction.in_flight_head = *node_index;
        else
          in_flight_[direction.in_flight_tail].next = *node_index;
        direction.in_flight_tail = *node_index;
      }
      for (const auto &entry : input.receive) {
        const auto handle = pool_.allocate(entry.frame);
        if (!handle || !direction.rx.try_push(*handle))
          std::terminate();
      }
    }
  }
  dropped_frames_ = state.dropped_frames;
  return true;
}

void MultiDeviceFabric::drain(Slot &slot, Clock::time_point now) noexcept {
  static_cast<void>(now);
  for (auto &direction : slot.directions) {
    PacketHandle handle{};
    while (direction.tx.try_pop(handle)) {
      pool_.release(handle);
      ++dropped_frames_;
    }

    // Walk only this direction's chain. A carrier failure never scans or
    // disturbs in-flight frames owned by another physical link.
    auto node_index = direction.in_flight_head;
    while (node_index != no_in_flight) {
      const auto next = in_flight_[node_index].next;
      pool_.release(in_flight_[node_index].packet);
      release_in_flight(node_index);
      ++dropped_frames_;
      node_index = next;
    }
    direction.in_flight_head = no_in_flight;
    direction.in_flight_tail = no_in_flight;
    direction.transmitter_available = {};

    while (direction.rx.try_pop(handle)) {
      pool_.release(handle);
      ++dropped_frames_;
    }
  }
}

std::optional<std::uint32_t>
MultiDeviceFabric::allocate_in_flight() noexcept {
  // This can reach zero only when every packet-pool slot is currently on a
  // medium. TX and RX frames consume packet slots but not metadata nodes, so a
  // frame admitted from TX normally guarantees a free node remains available.
  if (!free_in_flight_count_)
    return std::nullopt;
  return free_in_flight_[--free_in_flight_count_];
}

void MultiDeviceFabric::release_in_flight(std::uint32_t index) noexcept {
  // Only the link owner mutates the free list. Clearing the node makes an
  // accidental second traversal fail visibly in debug inspection instead of
  // retaining a plausible packet handle and deadline.
  in_flight_[index] = {};
  free_in_flight_[free_in_flight_count_++] = index;
}

std::chrono::nanoseconds MultiDeviceFabric::serialization_time(
    std::uint64_t bits, std::uint64_t bits_per_second) const noexcept {
  // IEEE 802.3 timing uses integer ceiling because steady_clock represents
  // whole nanoseconds. This never rounds a frame to an earlier delivery time.
  return std::chrono::nanoseconds{
      (bits * 1'000'000'000ULL + bits_per_second - 1U) / bits_per_second};
}

} // namespace router::lab
