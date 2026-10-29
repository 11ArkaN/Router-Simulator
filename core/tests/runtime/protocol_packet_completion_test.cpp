// Completion-enabled channels retain producer credits until the actual egress
// result is consumed. Two real threads verify result/frame publication through
// the reverse SPSC ring without copying a second packet into that ring.

#include "router/protocol_packet_channel.hpp"

#include <algorithm>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <thread>

void protocol_packet_completion_tests() {
  using Channel = router::protocol::PacketChannel<4U, true>;
  auto channel = std::make_unique<Channel>();
  if (channel->consumer_pending())
    throw std::runtime_error("Empty protocol channel reported pending consumer work");
  router::packet::Frame frame{};
  frame.length = 60U;
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, static_cast<std::uint8_t>(index));
    if (!channel->try_send({{0U, 7U}, index, 0U, index + 100U, index + 1000U}, frame))
      throw std::runtime_error("Protocol completion channel refused a reserved slot");
  }
  if (channel->try_send({}, frame) || channel->producer_available() != 0U)
    throw std::runtime_error("Protocol completion channel exceeded its frame capacity");
  if (!channel->consumer_pending())
    throw std::runtime_error("Published protocol frames did not wake a bounded consumer");
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    const auto packet = channel->try_receive();
    if (!packet || !channel->release(packet->handle, index % 2U != 0U) || channel->release(packet->handle, true))
      throw std::runtime_error("Protocol completion channel lost a release or accepted a duplicate result");
  }
  if (channel->producer_available() != 0U || channel->try_send({}, frame))
    throw std::runtime_error("Protocol completion channel reclaimed unconsumed results");
  if (channel->consumer_pending())
    throw std::runtime_error("Borrowed frames were confused with pending consumer work");
  for (std::uint64_t index = 0U; index < 4U; ++index) {
    const auto result = channel->try_completion();
    if (!result || result->metadata.interface_id != index || result->metadata.configuration_generation != index + 100U ||
        result->metadata.transmission_id != index + 1000U || result->enqueued != (index % 2U != 0U) ||
        result->frame->view().front() != static_cast<std::uint8_t>(index))
      throw std::runtime_error("Protocol completion did not preserve its immutable frame and result");
  }
  if (channel->try_completion() || channel->producer_available() != 4U || channel->release(4U, false))
    throw std::runtime_error("Protocol completion ownership did not return exactly once");

  std::atomic_bool valid{true};
  constexpr std::uint64_t count = 1024U;
  std::thread consumer([&] {
    for (std::uint64_t index = 0U; index < count; ++index) {
      std::optional<Channel::Borrowed> packet;
      while (!(packet = channel->try_receive())) std::this_thread::yield();
      if (packet->metadata.interface_id != index || packet->metadata.configuration_generation != index + 100U ||
          packet->metadata.transmission_id != index + 1000U ||
          packet->frame->view().front() != static_cast<std::uint8_t>(index))
        valid.store(false, std::memory_order_relaxed);
      if (!channel->release(packet->handle, index % 3U != 0U)) valid.store(false, std::memory_order_relaxed);
    }
  });
  std::uint64_t completed{};
  const auto drain = [&] {
    while (const auto result = channel->try_completion()) {
      if (result->metadata.interface_id != completed || result->metadata.configuration_generation != completed + 100U ||
          result->metadata.transmission_id != completed + 1000U || result->enqueued != (completed % 3U != 0U) ||
          result->frame->size() != 60U || !std::all_of(result->frame->view().begin(), result->frame->view().end(),
              [completed](auto byte) { return byte == static_cast<std::uint8_t>(completed); }))
        valid.store(false, std::memory_order_relaxed);
      ++completed;
    }
  };
  for (std::uint64_t index = 0U; index < count; ++index) {
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, static_cast<std::uint8_t>(index));
    while (!channel->try_send({{0U, 7U}, index, 0U, index + 100U, index + 1000U}, frame)) { drain(); std::this_thread::yield(); }
    std::fill(frame.bytes.begin(), frame.bytes.begin() + frame.length, std::uint8_t{});
    drain();
  }
  while (completed != count) { drain(); std::this_thread::yield(); }
  consumer.join();
  if (!valid.load(std::memory_order_relaxed) || channel->producer_available() != 4U)
    throw std::runtime_error("Protocol completion SPSC publication violated frame/result ownership");

  using Reused = router::protocol::PacketChannel<1U, true>;
  auto reused = std::make_unique<Reused>();
  const Reused::Metadata hello{{0U, 7U}, 11U, 0U, 9U, 1U, 17U};
  auto lsp = hello;
  lsp.transmission_class = 18U;
  if (!reused->try_send(hello, frame)) throw std::runtime_error("Protocol receipt fixture admission failed");
  const auto first = reused->try_receive();
  if (!first || !reused->release(first->handle, hello, true) || !reused->try_completion() || !reused->try_send(lsp, frame))
    throw std::runtime_error("Protocol receipt fixture did not reuse one frame handle");
  const auto replacement = reused->try_receive();
  if (!replacement || replacement->handle != first->handle || reused->release(replacement->handle, hello, true) ||
      reused->producer_available() != 0U)
    throw std::runtime_error("Delayed receipt released a replacement PDU class with the same epoch and ticket");
  auto wrong_ticket = lsp;
  ++wrong_ticket.transmission_id;
  auto wrong_epoch = lsp;
  ++wrong_epoch.configuration_generation;
  if (reused->release(replacement->handle, wrong_ticket, true) || reused->release(replacement->handle, wrong_epoch, true) ||
      !reused->release(replacement->handle, lsp, false))
    throw std::runtime_error("Protocol physical receipt accepted a different pending identity");
  const auto final = reused->try_completion();
  if (!final || final->metadata != lsp || final->enqueued || reused->producer_available() != 1U)
    throw std::runtime_error("Protocol guarded receipt lost actual admission or its PDU class");
  auto first_instance = hello;
  first_instance.instance_id = 1U;
  auto second_instance = first_instance;
  second_instance.instance_id = 2U;
  if (!reused->try_send(first_instance, frame)) throw std::runtime_error("Protocol instance fixture admission failed");
  const auto old_instance = reused->try_receive();
  if (!old_instance || !reused->release(old_instance->handle, first_instance, true) ||
      !reused->try_completion() || !reused->try_send(second_instance, frame))
    throw std::runtime_error("Protocol instance fixture did not reuse its frame handle");
  const auto current_instance = reused->try_receive();
  if (!current_instance || current_instance->handle != old_instance->handle ||
      reused->release(current_instance->handle, first_instance, true) ||
      !reused->release(current_instance->handle, second_instance, true))
    throw std::runtime_error("Delayed receipt released another instance with the same epoch, PDU class and ticket");
  const auto instance_result = reused->try_completion();
  if (!instance_result || instance_result->metadata != second_instance || !instance_result->enqueued)
    throw std::runtime_error("Protocol instance receipt lost its full identity");
}
