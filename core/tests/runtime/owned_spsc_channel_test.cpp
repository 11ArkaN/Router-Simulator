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
}
