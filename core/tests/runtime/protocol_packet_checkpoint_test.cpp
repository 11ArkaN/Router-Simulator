// Quiescent transfers preserve all four slot roles without consuming wire.
// Original channels die before saved borrowed handles and receipts resume.
// Real-thread channel tests separately exercise the live release/acquire path.

#include "router/protocol_packet_channel.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>

void protocol_packet_checkpoint_tests() {
  using Channel = router::protocol::PacketChannel<6U, true>;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("Protocol channel checkpoint invariant at " + std::to_string(where.line()));
  };
  router::SpscRing<std::uint32_t, 4U> ring;
  require(ring.try_push(1U) && ring.try_push(2U) && ring.try_push(3U));
  std::uint32_t taken{};
  require(ring.try_pop(taken) && taken == 1U && ring.try_push(4U));
  const auto wrapped = ring.checkpoint_quiescent();
  require(wrapped == std::vector<std::uint32_t>{2U, 3U, 4U});
  require(!ring.restore_quiescent(std::array<std::uint32_t, 4U>{}) && ring.checkpoint_quiescent() == wrapped);
  require(ring.restore_quiescent(wrapped));
  for (const auto expected : wrapped) require(ring.try_pop(taken) && taken == expected);
  require(ring.empty() && ring.restore_quiescent({}));
  auto source = std::make_unique<Channel>();
  auto frame = std::make_unique<router::packet::Frame>();
  frame->length = router::packet::maximum_frame_octets;
  for (unsigned iteration{}; iteration < 40U; ++iteration) {
    require(source->try_send({}, *frame));
    const auto value = source->try_receive();
    require(value && source->release(value->handle, true) && source->try_completion().has_value());
  }
  for (std::uint64_t index{}; index < 5U; ++index) {
    frame->length = index == 4U ? router::packet::maximum_frame_octets : 60U;
    std::fill_n(frame->bytes.begin(), frame->length, static_cast<std::uint8_t>(index + 1U));
    require(source->try_send({{2U, 7U}, 100U + index, 3U, 11U, index + 1U, 20U, 2U, 41U}, *frame));
  }
  const auto first = source->try_receive();
  require(first && source->release(first->handle, false));
  auto held = source->try_receive();
  require(held.has_value());
  const auto held_handle = held->handle;
  const auto held_metadata = held->metadata;
  held.reset();
  const auto third = source->try_receive();
  require(third && source->release(third->handle, true));
  const auto saved = source->checkpoint_quiescent(77U);
  require(saved.available.size() == 1U && saved.ready.size() == 2U && saved.borrowed.size() == 1U &&
      saved.returned.size() == 2U && saved.occupied.size() == 5U && Channel::valid_checkpoint(saved, 77U));
  source.reset();
  auto restored = std::make_unique<Channel>();
  require(restored->restore_quiescent(saved, 77U) && !restored->restore_quiescent(saved, 78U));
  for (unsigned invalid{}; invalid < 15U; ++invalid) {
    auto bad = saved;
    switch (invalid) {
      case 0U: ++bad.version; break;
      case 1U: bad.barrier_epoch = 0U; break;
      case 2U: ++bad.capacity; break;
      case 3U: bad.with_completions = false; break;
      case 4U: bad.ready[0U] = bad.available[0U]; break;
      case 5U: bad.ready[0U] = 6U; break;
      case 6U: bad.borrowed.clear(); break;
      case 7U: bad.returned[1U].handle = bad.returned[0U].handle; break;
      case 8U: bad.occupied.pop_back(); break;
      case 9U: bad.occupied[1U].handle = bad.occupied[0U].handle; break;
      case 10U: bad.occupied[0U].bytes.resize(router::packet::maximum_frame_octets + 1U); break;
      case 11U: bad.occupied[0U].handle = bad.available[0U]; break;
      case 12U: bad.borrowed.push_back(bad.borrowed[0U]); break;
      case 13U: bad.available.clear(); break;
      default: std::swap(bad.occupied[0U], bad.occupied[1U]); break;
    }
    require(!Channel::valid_checkpoint(bad, 77U) && !restored->restore_quiescent(bad, 77U));
    const auto unchanged = restored->checkpoint_quiescent(77U);
    require(unchanged.ready == saved.ready && unchanged.returned[0U].handle == saved.returned[0U].handle &&
        unchanged.occupied[0U].bytes == saved.occupied[0U].bytes);
  }
  bool missing_epoch{};
  try { static_cast<void>(restored->checkpoint_quiescent(0U)); }
  catch (const std::invalid_argument &) { missing_epoch = true; }
  require(missing_epoch);
  const auto refused = restored->try_completion();
  require(refused && !refused->enqueued && refused->metadata.interface_id == 100U && refused->frame->view().front() == 1U);
  const auto admitted = restored->try_completion();
  require(admitted && admitted->enqueued && admitted->metadata.interface_id == 102U && admitted->frame->view().front() == 3U);
  require(!restored->try_completion() && restored->producer_available() == 3U);
  frame->length = 60U;
  std::fill_n(frame->bytes.begin(), frame->length, std::uint8_t{9U});
  require(restored->try_send({{2U, 7U}, 200U}, *frame));
  auto wrong = held_metadata;
  ++wrong.protocol_epoch;
  require(!restored->release(held_handle, wrong, true) && restored->release(held_handle, held_metadata, true) &&
      !restored->release(held_handle, held_metadata, true));
  for (const auto id : {103U, 104U, 200U}) {
    const auto packet = restored->try_receive();
    require(packet && packet->metadata.interface_id == id);
    if (id == 104U) require(packet->frame->size() == router::packet::maximum_frame_octets &&
        packet->frame->view().back() == 5U);
    if (id == 200U) require(packet->handle == saved.returned[1U].handle && packet->frame->view().front() == 9U);
    require(restored->release(packet->handle, true));
  }
  for (const auto id : {101U, 103U, 104U, 200U}) {
    const auto receipt = restored->try_completion();
    require(receipt && receipt->metadata.interface_id == id && receipt->enqueued);
  }
  require(!restored->try_receive() && !restored->try_completion() && restored->producer_available() == 6U);
  const auto empty = restored->checkpoint_quiescent(78U);
  require(empty.occupied.empty() && empty.available.size() == 6U);

  using Ingress = router::protocol::PacketChannel<4U>;
  auto ingress = std::make_unique<Ingress>();
  for (std::uint64_t index{}; index < 3U; ++index) require(ingress->try_send({{0U, 7U}, index}, *frame));
  const auto received = ingress->try_receive();
  require(received && ingress->release(received->handle));
  const auto borrowed = ingress->try_receive();
  require(borrowed.has_value());
  const auto inbound = ingress->checkpoint_quiescent(79U);
  auto resumed_ingress = std::make_unique<Ingress>();
  require(resumed_ingress->restore_quiescent(inbound, 79U) && resumed_ingress->producer_available() == 2U);
  auto invalid_ingress = inbound;
  invalid_ingress.returned[0U].enqueued = true;
  require(!resumed_ingress->restore_quiescent(invalid_ingress, 79U));
  require(resumed_ingress->release(borrowed->handle));
  ingress.reset();
  const auto remaining = resumed_ingress->try_receive();
  require(remaining && remaining->metadata.interface_id == 2U && resumed_ingress->release(remaining->handle) &&
      resumed_ingress->producer_available() == 4U);
  // The free LIFO is semantically retained even when every slot is empty.
  require(resumed_ingress->restore_quiescent(inbound, 79U));
  auto reordered_free = empty;
  std::reverse(reordered_free.available.begin(), reordered_free.available.end());
  require(restored->restore_quiescent(reordered_free, 78U) && restored->try_send({}, *frame));
  const auto reused = restored->try_receive();
  require(reused && reused->handle == reordered_free.available.back());
}

void protocol_packet_checkpoint_barrier_tests() {
  using Channel = router::protocol::PacketChannel<6U, true>;
  using namespace std::chrono_literals;
  auto channel = std::make_unique<Channel>();
  std::atomic_bool producer_paused{}, consumer_paused{}, resume{}, failed{};
  const auto timeout = std::chrono::steady_clock::now() + 5s;
  const auto await = [&](auto predicate) {
    while (!predicate()) {
      if (failed.load(std::memory_order_acquire)) return false;
      if (std::chrono::steady_clock::now() >= timeout) {
        failed.store(true, std::memory_order_release);
        return false;
      }
      std::this_thread::yield();
    }
    return true;
  };
  std::thread producer([&] {
    auto wire = std::make_unique<router::packet::Frame>();
    wire->length = 60U;
    for (std::uint64_t id{}; id < 4U; ++id) {
      std::fill_n(wire->bytes.begin(), wire->length, static_cast<std::uint8_t>(id + 1U));
      if (!channel->try_send({{0U, 7U}, id, 1U, 9U, id + 1U, 20U, 0U, 41U}, *wire)) {
        failed.store(true, std::memory_order_release); return;
      }
    }
    producer_paused.store(true, std::memory_order_release);
    if (!await([&] { return resume.load(std::memory_order_acquire); })) return;
    auto receipt = channel->try_completion();
    if (!receipt || receipt->metadata.interface_id != 1U || receipt->enqueued) {
      failed.store(true, std::memory_order_release); return;
    }
    std::fill_n(wire->bytes.begin(), wire->length, std::uint8_t{5U});
    if (!channel->try_send({{0U, 7U}, 4U, 1U, 9U, 5U, 20U, 0U, 41U}, *wire)) {
      failed.store(true, std::memory_order_release); return;
    }
    for (const auto id : {0U, 2U, 3U, 4U}) {
      receipt.reset();
      if (!await([&] { receipt = channel->try_completion(); return receipt.has_value(); })) return;
      if (receipt->metadata.interface_id != id || !receipt->enqueued || receipt->frame->view().front() != id + 1U) {
        failed.store(true, std::memory_order_release); return;
      }
    }
  });
  std::thread consumer([&] {
    if (!await([&] { return producer_paused.load(std::memory_order_acquire); })) return;
    auto borrowed = channel->try_receive();
    if (!borrowed || borrowed->metadata.interface_id != 0U) {
      failed.store(true, std::memory_order_release); return;
    }
    const auto handle = borrowed->handle;
    const auto metadata = borrowed->metadata;
    borrowed.reset(); // No old frame view survives the restoration barrier.
    auto next = channel->try_receive();
    if (!next || next->metadata.interface_id != 1U || !channel->release(next->handle, false)) {
      failed.store(true, std::memory_order_release); return;
    }
    next.reset();
    consumer_paused.store(true, std::memory_order_release);
    if (!await([&] { return resume.load(std::memory_order_acquire); })) return;
    if (!channel->release(handle, metadata, true)) {
      failed.store(true, std::memory_order_release); return;
    }
    for (const auto id : {2U, 3U, 4U}) {
      next.reset();
      if (!await([&] { next = channel->try_receive(); return next.has_value(); })) return;
      if (next->metadata.interface_id != id || next->frame->view().front() != id + 1U ||
          !channel->release(next->handle, true)) {
        failed.store(true, std::memory_order_release); return;
      }
    }
  });
  const bool paused = await([&] { return producer_paused.load(std::memory_order_acquire) &&
      consumer_paused.load(std::memory_order_acquire); });
  try {
    if (paused) {
      // Both release acknowledgements precede cross-owned field access. Neither
      // live thread can touch a ring or slot until the coordinator releases it.
      const auto saved = channel->checkpoint_quiescent(81U);
      if (saved.ready.size() != 2U || saved.borrowed.size() != 1U || saved.returned.size() != 1U ||
          saved.available.size() != 2U || !channel->restore_quiescent(saved, 81U))
        failed.store(true, std::memory_order_release);
    }
  } catch (...) { failed.store(true, std::memory_order_release); }
  resume.store(true, std::memory_order_release);
  producer.join(); consumer.join();
  if (!paused || failed.load(std::memory_order_acquire) || channel->producer_available() != 6U)
    throw std::runtime_error("Protocol channel restore violated a real two-owner quiescence barrier");
}
