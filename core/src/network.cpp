// Byte-accurate endpoint, router, queue, link and adjacency processing.
// One forwarding shard owns every mutable object in this translation unit.
// Topology arrives as values and no network information bypasses encoded
// frames.

#include "router/network.hpp"

#include "network_adjacency.hpp"
#include "network_endpoint.hpp"
#include "network_link_fabric.hpp"
#include "router/bounded_queue.hpp"

#include <algorithm>
#include <chrono>
#include <optional>
#include <thread>

namespace router {
namespace {

using namespace std::chrono_literals;
using packet::Frame;
using packet::Ipv4;
using packet::Mac;

constexpr Mac no_mac{};

std::uint32_t to_u32(Ipv4 address) noexcept {
  return routing::ipv4(address[0], address[1], address[2], address[3]);
}

Ipv4 to_ipv4(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24),
          static_cast<std::uint8_t>(value >> 16),
          static_cast<std::uint8_t>(value >> 8),
          static_cast<std::uint8_t>(value)};
}

bool is_zero(Mac value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](auto byte) { return byte == 0; });
}

NetworkConfiguration default_configuration() noexcept {
  NetworkConfiguration result;
  for (std::size_t index = 0; index < result.endpoints.size(); ++index) {
    result.endpoints[index] = {
        .connected = true,
        .router_port = static_cast<std::uint8_t>(index),
        .endpoint_mac = profile::host_macs[index],
        .endpoint_address = profile::host_addresses[index],
        .endpoint_prefix_length = profile::host_prefix_lengths[index],
        .endpoint_gateway = profile::host_gateways[index],
        .router_mac = profile::router_macs[index],
        .router_address = profile::router_addresses[index],
        .propagation = profile::default_link_propagation};
  }
  return result;
}

struct PendingFrame {
  // routed distinguishes transit traffic requiring TTL processing from a
  // router-originated datagram. The next-hop key prevents unrelated ARP
  // learning on the same port from releasing the queued frame.
  Frame frame{};
  bool routed{};
  Ipv4 next_hop{};
};

} // namespace

struct LabNetwork::Impl {
  static constexpr std::size_t endpoint_count = network_endpoint_capacity;
  static constexpr std::size_t direction_count =
      network_detail::LinkFabric::direction_count;

  // Even directions carry endpoint to router traffic. Odd directions carry
  // router to endpoint traffic. Arithmetic mapping replaces topology-specific
  // enums and remains constant-time on the hot path.
  static constexpr std::size_t to_router(std::size_t endpoint) noexcept {
    return network_detail::LinkFabric::to_router(endpoint);
  }
  static constexpr std::size_t to_endpoint(std::size_t endpoint) noexcept {
    return network_detail::LinkFabric::to_endpoint(endpoint);
  }

  struct Operation {
    bool active{};
    bool terminal{};
    bool success{};
    PingOrigin origin{};
    NetworkDrop drop{NetworkDrop::none};
    std::uint8_t source_endpoint{};
    std::uint8_t destination_endpoint{};
    std::uint16_t sequence{};
    std::optional<std::chrono::steady_clock::time_point> echo_started;
    std::uint8_t reply_ttl{};
    std::uint32_t transmitted_frames{};
    std::uint32_t captured_frames{};
    std::uint32_t capture_drops{};
    std::array<std::uint64_t, profile::port_count> rx{};
    std::array<std::uint64_t, profile::port_count> tx{};
    CaptureObserver observer{};
    void *observer_context{};
  } operation;

  network_detail::LinkFabric fabric;
  std::array<network_detail::EndpointStack, endpoint_count> hosts{};
  NetworkConfiguration configuration{};
  routing::FibProgram fib{};
  network_detail::AdjacencyTable adjacencies;
  std::array<BoundedQueue<PendingFrame, 8>, profile::port_count> pending{};

  // PacketPool allocates its fixed arena during construction. Propagating
  // allocation failure is safer than promising noexcept and terminating the
  // entire runtime before it can report startup failure.
  Impl() { apply_configuration(default_configuration()); }

  [[nodiscard]] std::optional<std::size_t>
  endpoint_for_port(std::uint8_t port) const noexcept {
    for (std::size_t endpoint = 0; endpoint < configuration.endpoints.size();
         ++endpoint) {
      const auto &link = configuration.endpoints[endpoint];
      if (link.connected && link.router_port == port)
        return endpoint;
    }
    return std::nullopt;
  }

  void observe(std::uint8_t interface_id, const Frame &frame) noexcept {
    if (!operation.observer)
      return;
    const auto timestamp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    if (operation.observer(operation.observer_context, interface_id, frame,
                           static_cast<std::uint64_t>(timestamp))) {
      ++operation.captured_frames;
    } else {
      ++operation.capture_drops;
    }
  }

  bool fail(NetworkDrop reason) noexcept {
    if (operation.active && !operation.terminal) {
      operation.terminal = true;
      operation.success = false;
      operation.drop = reason;
    }
    return false;
  }

  [[nodiscard]] bool enqueue(std::size_t direction,
                             const Frame &frame) noexcept {
    if (direction >= direction_count)
      return fail(NetworkDrop::route_miss);
    if (!fabric.enqueue(direction, frame))
      return fail(NetworkDrop::queue_full);
    if ((direction & 1U) != 0U) {
      // For the starter profile these resolve to capture IDs 6 and 7, matching
      // the persisted PCAP interface table while avoiding named path constants.
      const auto endpoint = direction / 2;
      observe(static_cast<std::uint8_t>(direction_count + endpoint_count +
                                        endpoint),
              frame);
    }
    return true;
  }

  void start_echo_clock() noexcept {
    // Source ARP is excluded from RTT. Router-side resolution after launch is
    // included because it delays the already emitted IP datagram.
    if (!operation.echo_started)
      operation.echo_started = std::chrono::steady_clock::now();
  }

  void pump_transmit() noexcept {
    fabric.pump_transmit(this, [](void *context, std::size_t index,
                                  const Frame &frame) {
      auto &self = *static_cast<Impl *>(context);
      ++self.operation.transmitted_frames;
      if ((index & 1U) != 0U) {
        const auto endpoint = index / 2;
        const auto port = self.configuration.endpoints[endpoint].router_port;
        if (port < self.operation.tx.size())
          ++self.operation.tx[port];
      }
      self.observe(static_cast<std::uint8_t>(index), frame);
    });
  }

  void pump_delivery() noexcept {
    // Parsing occurs only after LinkDirection releases the handle at its real
    // steady-clock deadline. No endpoint or router receives protocol objects.
    fabric.pump_delivery(this, [](void *context, std::size_t index,
                                  const Frame &frame) {
      auto &self = *static_cast<Impl *>(context);
      const auto endpoint = static_cast<std::uint8_t>(index / 2);
      if ((index & 1U) == 0U) {
        const auto port = self.configuration.endpoints[endpoint].router_port;
        if (port < self.operation.rx.size())
          ++self.operation.rx[port];
        self.process_router(port, frame);
      } else {
        self.process_host(endpoint, frame);
      }
    });
  }

  void process_host(std::uint8_t index, const Frame &frame) noexcept {
    if (index >= hosts.size())
      return;
    const auto ip = packet::parse_ipv4(frame);
    const bool probe_source = operation.origin == PingOrigin::endpoint &&
                              index == operation.source_endpoint;
    const auto result =
        hosts[index].receive(frame, operation.sequence, probe_source);
    for (std::size_t output = 0; output < result.count; ++output) {
      static_cast<void>(enqueue(to_router(index), result.frames[output]));
    }
    if (result.start_echo_clock)
      start_echo_clock();
    if (result.echo_reply) {
      operation.reply_ttl = ip ? ip->ttl : 0;
      operation.success = true;
      operation.terminal = true;
    }
    if (result.ttl_expired)
      fail(NetworkDrop::ttl_expired);
  }

  void learn_router_arp(std::uint8_t port,
                        const packet::ArpView &arp) noexcept {
    if (port >= profile::port_count || is_zero(arp.sender_mac))
      return;
    adjacencies.learn(port, arp.sender_ip, arp.sender_mac);
  }

  void flush_pending(std::uint8_t port) noexcept {
    if (port >= pending.size())
      return;
    const auto *adjacency = adjacencies.get(port);
    if (!adjacency)
      return;
    const auto endpoint = endpoint_for_port(port);
    if (!endpoint) {
      fail(NetworkDrop::route_miss);
      return;
    }
    const auto &local = configuration.endpoints[*endpoint];
    PendingFrame item;
    const auto count = pending[port].size();
    for (std::size_t index = 0; index < count; ++index) {
      static_cast<void>(pending[port].try_pop(item));
      if (item.next_hop != adjacency->address) {
        static_cast<void>(pending[port].try_push(item));
        continue;
      }
      if (item.routed) {
        const auto routed =
            packet::route_ipv4(item.frame, local.router_mac, adjacency->mac);
        if (!routed) {
          fail(NetworkDrop::malformed);
          continue;
        }
        static_cast<void>(enqueue(to_endpoint(*endpoint), *routed));
      } else {
        packet::rewrite_ethernet(item.frame, local.router_mac, adjacency->mac);
        start_echo_clock();
        static_cast<void>(enqueue(to_endpoint(*endpoint), item.frame));
      }
    }
    adjacencies.complete_request(port);
  }

  void resolve_or_queue(std::uint8_t port, const Frame &frame, bool routed,
                        Ipv4 next_hop) noexcept {
    if (port >= pending.size()) {
      fail(NetworkDrop::route_miss);
      return;
    }
    if (adjacencies.exact(port, next_hop)) {
      if (!pending[port].try_push({frame, routed, next_hop})) {
        fail(NetworkDrop::queue_full);
        return;
      }
      flush_pending(port);
      return;
    }
    if (!pending[port].try_push({frame, routed, next_hop})) {
      fail(NetworkDrop::queue_full);
      return;
    }
    const auto endpoint = endpoint_for_port(port);
    if (!endpoint) {
      fail(NetworkDrop::route_miss);
      return;
    }
    if (!adjacencies.request_outstanding(port)) {
      adjacencies.mark_request(port);
      const auto &local = configuration.endpoints[*endpoint];
      static_cast<void>(
          enqueue(to_endpoint(*endpoint),
                  packet::arp_request(local.router_mac, local.router_address,
                                      next_hop)));
    }
  }

  void process_router(std::uint8_t ingress, const Frame &frame) noexcept {
    const auto endpoint = endpoint_for_port(ingress);
    if (!endpoint || ingress >= fib.port_operational.size()) {
      fail(NetworkDrop::ingress_down);
      return;
    }
    // Capture ingress IDs follow physical directions and remain stable for the
    // current profile even when endpoint bindings move to another router port.
    observe(static_cast<std::uint8_t>(direction_count + *endpoint), frame);
    if (!fib.port_operational[ingress]) {
      fail(NetworkDrop::ingress_down);
      return;
    }
    const auto &local = configuration.endpoints[*endpoint];
    const auto ethernet = packet::parse_ethernet(frame);
    if (!ethernet) {
      fail(NetworkDrop::malformed);
      return;
    }
    if (!packet::ethernet_for_local(ethernet->destination, local.router_mac))
      return;
    if (ethernet->ether_type == 0x0806) {
      const auto arp = packet::parse_arp(frame);
      if (!arp)
        return;
      learn_router_arp(ingress, *arp);
      if (arp->target_ip == local.router_address) {
        observe(static_cast<std::uint8_t>(direction_count * 2), frame);
      }
      if (arp->operation == 1 && arp->target_ip == local.router_address) {
        static_cast<void>(
            enqueue(to_endpoint(*endpoint),
                    packet::arp_reply(local.router_mac, local.router_address,
                                      arp->sender_mac, arp->sender_ip)));
      } else if (arp->operation == 2 &&
                 arp->target_ip == local.router_address) {
        flush_pending(ingress);
      }
      return;
    }
    if (ethernet->ether_type != 0x0800)
      return;
    const auto ip = packet::parse_ipv4(frame);
    if (!ip) {
      fail(NetworkDrop::malformed);
      return;
    }
    const auto local_destination = std::find_if(
        configuration.endpoints.begin(), configuration.endpoints.end(),
        [&ip](const auto &item) {
          return item.connected && item.router_address == ip->destination;
        });
    if (local_destination != configuration.endpoints.end()) {
      observe(static_cast<std::uint8_t>(direction_count * 2), frame);
      const auto icmp = packet::parse_icmp(frame);
      if (!icmp)
        return;
      if (icmp->type == 8) {
        const auto reply =
            packet::icmp_echo_reply(frame, local.router_mac, ethernet->source);
        if (reply)
          static_cast<void>(enqueue(to_endpoint(*endpoint), *reply));
      } else if (icmp->type == 0 && operation.origin == PingOrigin::router &&
                 icmp->sequence == operation.sequence) {
        operation.reply_ttl = ip->ttl;
        operation.success = true;
        operation.terminal = true;
      }
      return;
    }
    std::uint8_t egress{};
    std::uint32_t configured_next_hop{};
    if (!routing::lookup(fib, to_u32(ip->destination), egress,
                         &configured_next_hop) ||
        egress >= fib.port_operational.size() ||
        !fib.port_operational[egress]) {
      fail(NetworkDrop::route_miss);
      return;
    }
    if (ip->ttl <= 1) {
      const auto exceeded =
          packet::icmp_time_exceeded(frame, local.router_mac, ethernet->source,
                                     local.router_address, ip->source);
      if (exceeded)
        static_cast<void>(enqueue(to_endpoint(*endpoint), *exceeded));
      return;
    }
    const auto next_hop =
        configured_next_hop ? configured_next_hop : to_u32(ip->destination);
    resolve_or_queue(egress, frame, true, to_ipv4(next_hop));
  }

  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  next_delivery() const noexcept {
    // This is a read-only scan of link-owned deadlines, not a scheduler or
    // simulated clock. It cannot execute work or advance runtime time.
    return fabric.next_delivery();
  }

  [[nodiscard]] std::array<NetworkArpEntry, profile::port_count>
  arp_projection() const noexcept {
    return adjacencies.projection();
  }

  void apply_configuration(const NetworkConfiguration &next) noexcept {
    configuration = next;
    for (std::size_t endpoint = 0; endpoint < hosts.size(); ++endpoint) {
      const auto &item = configuration.endpoints[endpoint];
      hosts[endpoint].configure(item);
      fabric.set_propagation(endpoint, item.propagation);
    }
    // Configuration replacement is an adjacency generation boundary. Keeping
    // old MAC entries after a port move could forward to the former endpoint.
    for (std::size_t port = 0; port < profile::port_count; ++port) {
      adjacencies.invalidate(port);
      PendingFrame discarded;
      while (pending[port].try_pop(discarded)) {
      }
    }
  }

  [[nodiscard]] NetworkResult ping(PingOrigin origin, std::uint16_t sequence,
                                   CaptureObserver observer,
                                   void *context) noexcept {
    operation = {};
    operation.active = true;
    operation.origin = origin;
    operation.sequence = sequence;
    operation.source_endpoint = 0;
    operation.destination_endpoint = endpoint_count > 1 ? 1 : 0;
    operation.observer = observer;
    operation.observer_context = context;
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    const auto destination = operation.destination_endpoint;
    const auto &target_link = configuration.endpoints[destination];

    const auto target_missing =
        !target_link.connected ||
        target_link.router_port >= fib.port_operational.size();
    const auto router_egress_down =
        !target_missing && origin == PingOrigin::router &&
        !fib.port_operational[target_link.router_port];
    if (target_missing || router_egress_down) {
      fail(NetworkDrop::route_miss);
    } else if (origin == PingOrigin::endpoint) {
      const auto source = operation.source_endpoint;
      const auto &source_link = configuration.endpoints[source];
      if (!source_link.connected ||
          !fib.port_operational[source_link.router_port]) {
        fail(NetworkDrop::ingress_down);
      } else {
        const auto frames =
            hosts[source].begin_echo(hosts[destination].address(), sequence);
        for (std::size_t index = 0; index < frames.count; ++index) {
          static_cast<void>(enqueue(to_router(source), frames.frames[index]));
        }
        if (frames.start_echo_clock)
          start_echo_clock();
      }
    } else {
      const auto request = packet::icmp_echo(
          target_link.router_mac, no_mac, target_link.router_address,
          hosts[destination].address(), false, sequence);
      resolve_or_queue(target_link.router_port, request, false,
                       hosts[destination].address());
    }

    // The forwarding shard waits only for the nearest link-owned deadline.
    // No global event queue, time scaling or direct device callback exists.
    while (!operation.terminal && std::chrono::steady_clock::now() < deadline) {
      pump_transmit();
      pump_delivery();
      pump_transmit();
      if (operation.terminal)
        break;
      if (const auto next = next_delivery()) {
        std::this_thread::sleep_until(std::min(*next, deadline));
      } else if (std::chrono::steady_clock::now() < deadline) {
        fail(NetworkDrop::timeout);
      }
    }
    if (!operation.terminal)
      fail(NetworkDrop::timeout);
    NetworkResult result{.success = operation.success,
                         .drop = operation.drop,
                         .reply_ttl = operation.reply_ttl,
                         .transmitted_frames = operation.transmitted_frames,
                         .captured_frames = operation.captured_frames,
                         .capture_drops = operation.capture_drops,
                         .rx_delta = operation.rx,
                         .tx_delta = operation.tx,
                         .router_arp = arp_projection()};
    if (operation.echo_started && operation.terminal) {
      result.rtt_us = static_cast<std::uint64_t>(std::max<std::int64_t>(
          1, std::chrono::duration_cast<std::chrono::microseconds>(
                 std::chrono::steady_clock::now() - *operation.echo_started)
                 .count()));
    }
    operation.active = false;
    return result;
  }
};

LabNetwork::LabNetwork() : impl_(std::make_unique<Impl>()) {}
LabNetwork::~LabNetwork() = default;

void LabNetwork::install_fib(const routing::FibProgram &fib) noexcept {
  for (std::size_t port = 0; port < fib.port_operational.size(); ++port) {
    if (fib.port_operational[port])
      continue;
    impl_->adjacencies.invalidate(port);
    PendingFrame discarded;
    while (impl_->pending[port].try_pop(discarded)) {
    }
    if (const auto endpoint =
            impl_->endpoint_for_port(static_cast<std::uint8_t>(port))) {
      impl_->hosts[*endpoint].clear_neighbor();
    }
  }
  // Generations are monotonic. A delayed program can acknowledge completion but
  // cannot restore routes withdrawn by a newer control-plane publication.
  if (fib.generation >= impl_->fib.generation)
    impl_->fib = fib;
}

void LabNetwork::configure(const NetworkConfiguration &configuration) noexcept {
  impl_->apply_configuration(configuration);
}

void LabNetwork::restore_adjacencies(
    const std::array<NetworkArpEntry, profile::port_count> &entries) noexcept {
  impl_->adjacencies.restore(entries);
  // Endpoint neighbor caches are derived from local link bindings. Only an
  // exact port adjacency is restored, and no queue or PacketPool handle crosses
  // the checkpoint boundary.
  for (std::size_t endpoint = 0; endpoint < impl_->hosts.size(); ++endpoint) {
    const auto &link = impl_->configuration.endpoints[endpoint];
    if (link.connected && link.router_port < entries.size() &&
        entries[link.router_port].valid) {
      impl_->hosts[endpoint].restore_router_neighbor(link.router_address,
                                                     link.router_mac);
    } else {
      impl_->hosts[endpoint].clear_neighbor();
    }
  }
}

std::array<NetworkArpEntry, profile::port_count>
LabNetwork::adjacencies() const noexcept {
  return impl_->arp_projection();
}

NetworkResult LabNetwork::ping(PingOrigin origin, std::uint16_t sequence,
                               CaptureObserver observer,
                               void *observer_context) noexcept {
  return impl_->ping(origin, sequence, observer, observer_context);
}

} // namespace router
