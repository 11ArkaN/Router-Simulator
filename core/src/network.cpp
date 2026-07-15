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

using packet::Frame;
using packet::Ipv4;
using packet::Mac;

constexpr Mac no_mac{};

// Converts packet byte order to the RIB's network-order integer key.
std::uint32_t to_u32(Ipv4 address) noexcept {
  return routing::ipv4(address[0], address[1], address[2], address[3]);
}

// Converts a selected RIB next hop back into packet encoder bytes.
Ipv4 to_ipv4(std::uint32_t value) noexcept {
  return {static_cast<std::uint8_t>(value >> 24),
          static_cast<std::uint8_t>(value >> 16),
          static_cast<std::uint8_t>(value >> 8),
          static_cast<std::uint8_t>(value)};
}

// A zero MAC marks unresolved adjacency storage and is never a valid neighbor.
bool is_zero(Mac value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](auto byte) { return byte == 0; });
}

// Builds the initial endpoint projection entirely from generated profile data.
// Later project operations replace this value through configure().
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
        .router_mtu = static_cast<std::uint16_t>(
            profile::default_port_mtu - packet::ethernet_header_octets),
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
  std::array<BoundedQueue<PendingFrame, profile::adjacency_pending_capacity>,
             profile::port_count>
      pending{};

  // PacketPool allocates its fixed arena during construction. Propagating
  // allocation failure is safer than promising noexcept and terminating the
  // entire runtime before it can report startup failure.
  Impl() { apply_configuration(default_configuration()); }

  [[nodiscard]] std::optional<std::size_t>
  endpoint_for_port(std::uint8_t port) const noexcept {
    // Physical binding is project data. Scanning the small bounded endpoint
    // array avoids a second mutable reverse index that could become stale.
    for (std::size_t endpoint = 0; endpoint < configuration.endpoints.size();
         ++endpoint) {
      const auto &link = configuration.endpoints[endpoint];
      if (link.connected && link.router_port == port)
        return endpoint;
    }
    return std::nullopt;
  }

  void observe(std::uint8_t interface_id, const Frame &frame) noexcept {
    // Capture timestamps use wall-clock epoch for PCAP interoperability, while
    // delivery and protocol deadlines use steady_clock and cannot jump.
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
    // The first terminal failure wins. Later frames already in flight cannot
    // overwrite the causal drop reported to control.
    if (operation.active && !operation.terminal) {
      operation.terminal = true;
      operation.success = false;
      operation.drop = reason;
    }
    return false;
  }

  [[nodiscard]] bool enqueue(std::size_t direction,
                             const Frame &frame) noexcept {
    // Admission copies bytes into the bounded fabric-owned packet pool. A full
    // ring is an explicit modeled tail drop, never a heap allocation fallback.
    if (direction >= direction_count)
      return fail(NetworkDrop::route_miss);
    if (!fabric.enqueue(direction, frame))
      return fail(NetworkDrop::queue_full);
    if ((direction & 1U) != 0U) {
      // Capture groups are generated with the profile. Direction arithmetic
      // selects the endpoint within the egress group without naming a link.
      const auto endpoint = direction / 2;
      observe(
          static_cast<std::uint8_t>(profile::capture_egress_base + endpoint),
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
    // Link admission observes encoded bytes before propagation and increments
    // counters for the physical router port selected by project binding.
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
    // EndpointStack receives bytes only after link delivery. Returned replies
    // must re-enter the opposite physical direction through normal admission.
    if (index >= hosts.size())
      return;
    const auto ip = packet::parse_ipv4(frame);
    const bool probe_source = operation.active &&
                              operation.origin == PingOrigin::endpoint &&
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
    if (result.mtu_exceeded)
      fail(NetworkDrop::mtu_exceeded);
  }

  void learn_router_arp(std::uint8_t port,
                        const packet::ArpView &arp) noexcept {
    // Adjacency keys include the egress port, preventing the same protocol
    // address on separate links from releasing the wrong pending queue.
    if (port >= profile::port_count || is_zero(arp.sender_mac))
      return;
    adjacencies.learn(port, arp.sender_ip, arp.sender_mac);
  }

  void flush_pending(std::uint8_t port) noexcept {
    // Only frames matching the newly learned next hop are released. Others
    // retain FIFO order and wait for their own ARP transaction.
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
        const auto routed_ip = packet::parse_ipv4(*routed);
        if (!routed_ip) {
          fail(NetworkDrop::malformed);
          continue;
        }
        if (routed_ip->total_length > local.router_mtu) {
          // RFC 791 fragmentation happens after the single TTL decrement and
          // after adjacency resolution. Every resulting Ethernet frame enters
          // the same bounded egress queue and real-time link independently.
          const auto fragments = packet::fragment_ipv4(*routed, local.router_mtu);
          if (!fragments) {
            fail(NetworkDrop::malformed);
            continue;
          }
          for (std::size_t fragment = 0; fragment < fragments->count;
               ++fragment) {
            if (!enqueue(to_endpoint(*endpoint), fragments->frames[fragment]))
              break;
          }
        } else {
          static_cast<void>(enqueue(to_endpoint(*endpoint), *routed));
        }
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
    // Queue before transmitting ARP so an immediate reply cannot race ahead of
    // the frame that depends on it. One request per port is outstanding.
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
    // Processing follows Ethernet acceptance, protocol parsing, local delivery,
    // FIB lookup, TTL handling and adjacency resolution in that order.
    const auto endpoint = endpoint_for_port(ingress);
    if (!endpoint || ingress >= fib.port_operational.size()) {
      fail(NetworkDrop::ingress_down);
      return;
    }
    // Capture ingress IDs follow physical directions and remain stable for the
    // current profile even when endpoint bindings move to another router port.
    observe(
        static_cast<std::uint8_t>(profile::capture_ingress_base + *endpoint),
        frame);
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
        observe(static_cast<std::uint8_t>(profile::capture_cpm_index), frame);
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
      observe(static_cast<std::uint8_t>(profile::capture_cpm_index), frame);
      const auto icmp = packet::parse_icmp(frame);
      if (!icmp)
        return;
      if (icmp->type == 8) {
        const auto reply =
            packet::icmp_echo_reply(frame, local.router_mac, ethernet->source);
        if (reply)
          static_cast<void>(enqueue(to_endpoint(*endpoint), *reply));
      } else if (icmp->type == 0 && operation.active &&
                 operation.origin == PingOrigin::router &&
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
    const auto egress_endpoint = endpoint_for_port(egress);
    if (!egress_endpoint) {
      fail(NetworkDrop::route_miss);
      return;
    }
    const auto egress_mtu =
        configuration.endpoints[*egress_endpoint].router_mtu;
    if (ip->total_length > egress_mtu && ip->dont_fragment) {
      // RFC 1812 forbids forwarding an oversized DF datagram. RFC 1191 places
      // the limiting next-hop MTU in ICMP type 3 code 4. The error travels back
      // through the ingress link as encoded bytes, never as a direct callback.
      const auto needed = packet::icmp_fragmentation_needed(
          frame, local.router_mac, ethernet->source, local.router_address,
          ip->source, egress_mtu);
      if (needed)
        static_cast<void>(enqueue(to_endpoint(*endpoint), *needed));
      else
        fail(NetworkDrop::malformed);
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
    // Control receives a bounded value copy and cannot mutate forwarding state.
    return adjacencies.projection();
  }

  void apply_configuration(const NetworkConfiguration &next) noexcept {
    // Project replacement is atomic on this owner. Endpoint stacks and link
    // delays update before every previous adjacency generation is invalidated.
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

  [[nodiscard]] NetworkResult
  ping(PingOrigin origin, std::uint8_t source_endpoint, Ipv4 destination,
       std::uint16_t sequence, std::size_t payload_octets, bool dont_fragment,
       CaptureObserver observer, void *context,
       CancellationObserver cancelled, void *cancellation_context) noexcept {
    // One operation owns its probe bookkeeping until success, a modeled drop or
    // the real-time timeout. No other device object is called by this loop.
    operation = {};
    operation.active = true;
    operation.origin = origin;
    operation.sequence = sequence;
    operation.source_endpoint = source_endpoint;
    operation.observer = observer;
    operation.observer_context = context;
    const auto deadline =
        std::chrono::steady_clock::now() + profile::ping_timeout;

    if (origin == PingOrigin::endpoint) {
      const auto source = static_cast<std::size_t>(source_endpoint);
      if (source >= hosts.size()) {
        fail(NetworkDrop::route_miss);
      } else {
        const auto &source_link = configuration.endpoints[source];
        if (!source_link.connected ||
            !fib.port_operational[source_link.router_port]) {
          fail(NetworkDrop::ingress_down);
        } else {
          // The endpoint stack decides whether the destination is on-link or
          // requires its configured gateway. No topology index is substituted
          // for the destination supplied by the terminal or host action.
          const auto frames = hosts[source].begin_echo(
              destination, sequence, payload_octets, dont_fragment);
          for (std::size_t index = 0; index < frames.count; ++index) {
            static_cast<void>(enqueue(to_router(source), frames.frames[index]));
          }
          if (frames.start_echo_clock)
            start_echo_clock();
        }
      }
    } else {
      std::uint8_t egress{};
      std::uint32_t configured_next_hop{};
      if (!routing::lookup(fib, to_u32(destination), egress,
                           &configured_next_hop) ||
          egress >= fib.port_operational.size() ||
          !fib.port_operational[egress]) {
        fail(NetworkDrop::route_miss);
      } else if (const auto endpoint = endpoint_for_port(egress)) {
        // Router-originated traffic takes its source address and MAC from the
        // selected egress interface. This is a FIB decision, not a shortcut to
        // a known host object.
        const auto &local = configuration.endpoints[*endpoint];
        const auto request =
            packet::icmp_echo(local.router_mac, no_mac, local.router_address,
                              destination, false, sequence, 64, payload_octets,
                              dont_fragment);
        const auto next_hop =
            configured_next_hop ? to_ipv4(configured_next_hop) : destination;
        resolve_or_queue(egress, request, false, next_hop);
      } else {
        fail(NetworkDrop::route_miss);
      }
    }

    // The forwarding shard waits only for the nearest link-owned deadline.
    // No global event queue, time scaling or direct device callback exists.
    while (!operation.terminal && std::chrono::steady_clock::now() < deadline) {
      // Cancellation is read from an atomic shared control word. It never
      // mutates packet state directly; the forwarding owner terminates its own
      // operation and returns a normal result acknowledgement to control.
      if (cancelled && cancelled(cancellation_context)) {
        fail(NetworkDrop::cancelled);
        break;
      }
      pump_transmit();
      pump_delivery();
      pump_transmit();
      if (operation.terminal)
        break;
      if (const auto next = next_delivery()) {
        // Capping only the blocking interval bounds Ctrl-C latency. Link and
        // protocol deadlines remain the real due times and are never advanced.
        const auto cancellation_poll =
            std::chrono::steady_clock::now() + std::chrono::milliseconds{10};
        std::this_thread::sleep_until(
            std::min({*next, deadline, cancellation_poll}));
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

// Large packet pools and link queues live on the heap rather than the Wasm
// entry stack. Construction also installs the generated default topology.
LabNetwork::LabNetwork() : impl_(std::make_unique<Impl>()) {}
LabNetwork::~LabNetwork() = default;

// Replaces one immutable FIB generation. Ports withdrawn by the generation
// lose adjacency and endpoint neighbor state before later packets are handled.
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

// Applies a complete validated project topology on the forwarding owner.
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
  // Checkpoint and telemetry callers receive values, never mutable pointers.
  return impl_->arp_projection();
}

NetworkCheckpointState LabNetwork::checkpoint() const {
  // The caller established a forwarding barrier, so every owner below can be
  // read in one generation. Frames are copied as wire values and no pool
  // handle, clock epoch or component pointer escapes this method.
  NetworkCheckpointState state;
  state.adjacencies = impl_->arp_projection();
  state.arp_requests = impl_->adjacencies.request_projection();
  for (std::size_t endpoint = 0; endpoint < impl_->hosts.size(); ++endpoint)
    impl_->hosts[endpoint].checkpoint(
        state, static_cast<std::uint8_t>(endpoint));
  for (std::size_t port = 0; port < impl_->pending.size(); ++port) {
    PendingFrame pending;
    for (std::size_t index = 0; index < impl_->pending[port].size(); ++index) {
      static_cast<void>(impl_->pending[port].copy_at(index, pending));
      state.frames.push_back(
          {.stage = NetworkFrameStage::router_pending,
           .direction = static_cast<std::uint8_t>(port),
           .routed = pending.routed,
           .next_hop = pending.next_hop,
           .frame = pending.frame});
    }
  }
  impl_->fabric.checkpoint(state, std::chrono::steady_clock::now());
  return state;
}

bool LabNetwork::restore(const NetworkCheckpointState &state) noexcept {
  // Validate all local queue counts before mutating any forwarding owner. The
  // fabric performs its own handle-capacity validation and rolls back to empty
  // on allocation failure, never retaining a half-restored generation.
  std::array<std::size_t, profile::port_count> pending_counts{};
  std::array<std::size_t, network_endpoint_capacity> endpoint_pending{};
  std::array<std::size_t, network_endpoint_capacity> endpoint_reassembly{};
  for (const auto &stored : state.frames) {
    if (!stored.frame.length || stored.frame.length > stored.frame.bytes.size())
      return false;
    if (stored.stage == NetworkFrameStage::router_pending) {
      if (stored.direction >= pending_counts.size() ||
          ++pending_counts[stored.direction] >
              profile::adjacency_pending_capacity)
        return false;
    } else if (stored.stage == NetworkFrameStage::endpoint_pending) {
      if (stored.direction >= endpoint_pending.size() ||
          ++endpoint_pending[stored.direction] > 1U)
        return false;
    } else if (stored.stage == NetworkFrameStage::endpoint_reassembly) {
      if (stored.direction >= endpoint_reassembly.size() ||
          ++endpoint_reassembly[stored.direction] > 1U ||
          stored.frame.length < 34U ||
          stored.frame.length !=
              34U + state.endpoints[stored.direction].reassembly_payload_octets)
        return false;
    }
  }
  for (std::size_t port = 0; port < state.arp_requests.size(); ++port) {
    if (state.arp_requests[port] && !pending_counts[port])
      return false;
  }
  for (std::size_t endpoint = 0; endpoint < state.endpoints.size(); ++endpoint) {
    if (state.endpoints[endpoint].pending_next_hop_valid !=
            (endpoint_pending[endpoint] == 1U) ||
        state.endpoints[endpoint].reassembly_active !=
            (endpoint_reassembly[endpoint] == 1U))
      return false;
  }

  const auto now = std::chrono::steady_clock::now();
  if (!impl_->fabric.restore(state, now))
    return false;
  for (std::size_t endpoint = 0; endpoint < impl_->hosts.size(); ++endpoint) {
    if (!impl_->hosts[endpoint].restore(
            state, static_cast<std::uint8_t>(endpoint)))
      return false;
  }
  impl_->adjacencies.restore(state.adjacencies);
  impl_->adjacencies.restore_requests(state.arp_requests);
  for (auto &queue : impl_->pending)
    queue.clear();
  for (const auto &stored : state.frames) {
    if (stored.stage == NetworkFrameStage::router_pending &&
        !impl_->pending[stored.direction].try_push(
            {stored.frame, stored.routed, stored.next_hop}))
      return false;
  }
  return true;
}

void LabNetwork::service() noexcept {
  // A three-phase pass mirrors the active ping loop: admit queued handles,
  // release every due link frame into its receiver, then admit replies created
  // by receiver processing. No loop waits here, so mailbox latency remains
  // controlled by Runtime's condition variable.
  impl_->pump_transmit();
  impl_->pump_delivery();
  impl_->pump_transmit();
}

std::optional<std::chrono::steady_clock::time_point>
LabNetwork::next_deadline() const noexcept {
  return impl_->next_delivery();
}

// Runs one probe with explicit origin, source endpoint and destination. The
// capture observer is borrowed only until the synchronous result returns.
NetworkResult LabNetwork::ping(PingOrigin origin, std::uint8_t source_endpoint,
                               packet::Ipv4 destination, std::uint16_t sequence,
                               std::size_t payload_octets, bool dont_fragment,
                               CaptureObserver observer, void *observer_context,
                               CancellationObserver cancelled,
                               void *cancellation_context) noexcept {
  return impl_->ping(origin, source_endpoint, destination, sequence,
                     payload_octets, dont_fragment, observer, observer_context,
                     cancelled, cancellation_context);
}

} // namespace router
