// Real owners hand off variable-length control values through handle-only
// rings, preserving publication and rejecting duplicate credit returns.

#include "router/owned_spsc_channel.hpp"

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <thread>
#include <vector>

void owned_spsc_channel_tests() {
  using Channel = router::protocol::OwnedSpscChannel<std::vector<std::uint64_t>, 4U>;
  Channel channel;
  const auto require = [](bool value) {
    if (!value) throw std::runtime_error("Owned control SPSC handoff invariant failed");
  };
  const auto cancelled = channel.acquire();
  require(cancelled.has_value());
  cancelled->value->assign(32U, 123U);
  require(channel.cancel(cancelled->handle) && !channel.cancel(cancelled->handle));
  std::atomic_bool valid{true};
  std::thread consumer([&] {
    for (std::uint64_t index{}; index < 1024U; ++index) {
      std::optional<Channel::Lease> lease;
      while (!(lease = channel.receive())) std::this_thread::yield();
      auto value = std::move(*lease->value);
      if (value.size() != index % 31U + 1U ||
          !std::all_of(value.begin(), value.end(), [index](auto item) { return item == index; }))
        valid.store(false, std::memory_order_relaxed);
      if (!channel.release(lease->handle) || channel.release(lease->handle))
        valid.store(false, std::memory_order_relaxed);
    }
  });
  for (std::uint64_t index{}; index < 1024U; ++index) {
    std::optional<Channel::Lease> lease;
    while (!(lease = channel.acquire())) std::this_thread::yield();
    lease->value->assign(static_cast<std::size_t>(index % 31U + 1U), index);
    require(channel.publish(lease->handle) && !channel.publish(lease->handle));
  }
  consumer.join();
  require(valid.load(std::memory_order_relaxed) && channel.empty() && !channel.release(4U));
  std::array<Channel::Lease, 4U> leases{};
  for (auto &lease : leases) {
    const auto acquired = channel.acquire();
    require(acquired.has_value());
    lease = *acquired;
  }
  require(!channel.acquire());
  for (const auto &lease : leases) require(channel.cancel(lease.handle));
  using Ack = router::protocol::OwnedSpscChannel<std::array<std::uint64_t, 2U>, 1U, true>;
  Ack acknowledged;
  const auto edit = acknowledged.acquire();
  require(edit.has_value());
  (*edit->value)[0U] = 42U;
  require(acknowledged.publish(edit->handle));
  const auto borrowed = acknowledged.receive();
  require(borrowed && (*borrowed->value)[0U] == 42U);
  (*borrowed->value)[1U] = 99U;
  require(acknowledged.release(borrowed->handle) && !acknowledged.release(borrowed->handle));
  require(!acknowledged.acquire());
  const auto returned = acknowledged.completion();
  require(returned && (*returned->value)[0U] == 42U && (*returned->value)[1U] == 99U &&
      !acknowledged.completion());
  const auto reused = acknowledged.acquire();
  require(reused && *reused->value == std::array<std::uint64_t, 2U>{} &&
      acknowledged.cancel(reused->handle) && !acknowledged.cancel(reused->handle));

  struct ReplyValue { std::array<std::uint64_t, 4U> body{}; std::uint64_t reply{}; };
  using Replies = router::protocol::OwnedSpscChannel<ReplyValue, 4U, true>;
  Replies replies;
  std::thread reply_consumer([&] {
    for (std::uint64_t index{}; index < 1024U; ++index) {
      std::optional<Replies::Lease> lease;
      while (!(lease = replies.receive())) std::this_thread::yield();
      const auto &body = lease->value->body;
      if (body != std::array<std::uint64_t, 4U>{index, index + 7U, ~index, index * 3U})
        valid.store(false, std::memory_order_relaxed);
      lease->value->reply = index ^ 0x123456789abcdef0ULL;
      if (!replies.release(lease->handle)) valid.store(false, std::memory_order_relaxed);
    }
  });
  std::uint64_t completed{};
  const auto consume_reply = [&] {
    const auto result = replies.completion();
    if (!result) return false;
    if (result->value->body[0U] != completed || result->value->reply != (completed ^ 0x123456789abcdef0ULL))
      valid.store(false, std::memory_order_relaxed);
    ++completed;
    return true;
  };
  for (std::uint64_t index{}; index < 1024U; ++index) {
    std::optional<Replies::Lease> lease;
    while (!(lease = replies.acquire())) if (!consume_reply()) std::this_thread::yield();
    lease->value->body = {index, index + 7U, ~index, index * 3U};
    require(replies.publish(lease->handle));
    while (consume_reply()) {}
  }
  while (completed < 1024U) if (!consume_reply()) std::this_thread::yield();
  reply_consumer.join();
  require(valid.load(std::memory_order_relaxed) && replies.empty() && !replies.completion());

}
