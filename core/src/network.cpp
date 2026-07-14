// Byte-accurate host, router, queue, link and adjacency processing.
// One forwarding shard owns every mutable object in this translation unit.

#include "router/network.hpp"

#include "router/bounded_queue.hpp"
#include "router/generated_profile.hpp"
#include "router/link_direction.hpp"
#include "router/packet_pool.hpp"

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

constexpr auto host_a_default_mac = profile::host_macs[0];
constexpr auto host_b_default_mac = profile::host_macs[1];
constexpr auto router_mac_a = profile::router_macs[0];
constexpr auto router_mac_b = profile::router_macs[1];
constexpr auto host_a_default_ip = profile::host_addresses[0];
constexpr auto host_b_default_ip = profile::host_addresses[1];
constexpr auto router_ip_a = profile::router_addresses[0];
constexpr auto router_ip_b = profile::router_addresses[1];
constexpr Mac no_mac{};

std::uint32_t to_u32(Ipv4 address) noexcept {
  return routing::ipv4(address[0], address[1], address[2], address[3]);
}

bool is_zero(Mac value) noexcept {
  return std::all_of(value.begin(), value.end(), [](auto byte) { return byte == 0; });
}

struct PendingFrame {
  // A pending frame represents the small RFC 1812 queue held while direct
  // next-hop address resolution is in progress. routed distinguishes a transit
  // packet that still requires TTL processing from a router-originated packet.
  Frame frame{};
  bool routed{};
  Ipv4 next_hop{};
};

struct Adjacency {
  // Protocol and hardware addresses form one indivisible ARP cache entry. A
  // MAC learned for an unrelated sender cannot satisfy resolution merely
  // because it arrived on the same physical port.
  Ipv4 address{};
  Mac mac{};
};

struct Host {
  // Each host owns a one-entry neighbor cache and one pending Echo request. The
  // cache is keyed by protocol address because an on-link destination and the
  // configured gateway are not interchangeable ARP targets. The narrow
  // milestone permits one active ping per runtime, so a larger host socket
  // queue would consume memory without representing observable concurrency.
  Mac mac{};
  Ipv4 address{};
  std::uint8_t prefix_length{30};
  Ipv4 gateway{};
  std::optional<Ipv4> neighbor_address;
  std::optional<Mac> neighbor_mac;
  std::optional<Frame> pending;
  std::optional<Ipv4> pending_next_hop;
};

struct WireDirection {
  // Ownership moves pool handle TX queue -> in-flight link -> RX queue. No
  // protocol object or mutable Frame pointer crosses between modeled devices.
  // Queue admission is tail-drop and the handle is released exactly once.
  BoundedQueue<PacketHandle, 256> tx;
  LinkDirection link;
  BoundedQueue<PacketHandle, 256> rx;

  // Speed comes from the equipped port. The default propagation value seeds a
  // new project but may later be replaced on the forwarding owner by the
  // physical link configuration. Keeping the values separate prevents a long
  // circuit from incorrectly reducing transmitter throughput.
  WireDirection()
      : link(profile::port_bits_per_second, profile::default_link_propagation) {}
};

}  // namespace

struct LabNetwork::Impl {
  enum Path : std::uint8_t {
    host_a_to_router,
    router_to_host_a,
    router_to_host_b,
    host_b_to_router,
    path_count
  };

  struct Operation {
    // Operation is reset per Echo sequence. Persistent link deadlines and ARP
    // caches live outside it, which is why a second probe can avoid resolution.
    bool active{};
    bool terminal{};
    bool success{};
    PingOrigin origin{};
    NetworkDrop drop{NetworkDrop::none};
    std::uint16_t sequence{};
    std::optional<std::chrono::steady_clock::time_point> echo_started;
    std::uint8_t reply_ttl{};
    std::uint32_t transmitted_frames{};
    std::uint32_t captured_frames{};
    std::uint32_t capture_drops{};
    std::array<std::uint64_t, 2> rx{};
    std::array<std::uint64_t, 2> tx{};
    CaptureObserver observer{};
    void* observer_context{};
  } operation;

  PacketPool pool;
  // PacketPool and every path below have forwarding-thread affinity. They use
  // no atomics because no other pthread may inspect or mutate their contents.
  std::array<WireDirection, path_count> paths;
  std::array<Host, 2> hosts{{
      {.mac = host_a_default_mac,
       .address = host_a_default_ip,
       .prefix_length = 30,
       .gateway = router_ip_a,
       .neighbor_address = std::nullopt,
       .neighbor_mac = std::nullopt,
       .pending = std::nullopt,
       .pending_next_hop = std::nullopt},
      {.mac = host_b_default_mac,
       .address = host_b_default_ip,
       .prefix_length = 30,
       .gateway = router_ip_b,
       .neighbor_address = std::nullopt,
       .neighbor_mac = std::nullopt,
       .pending = std::nullopt,
       .pending_next_hop = std::nullopt},
  }};
  routing::FibProgram fib{};
  // router_arp is the authoritative forwarding adjacency table for the two
  // directly connected networks. DeviceState holds only its last projection.
  std::array<std::optional<Adjacency>, 2> router_arp;
  std::array<BoundedQueue<PendingFrame, 8>, 2> pending;
  std::array<bool, 2> arp_outstanding{};

  void observe(std::uint8_t interface_id, const Frame& frame) noexcept {
    if (!operation.observer) return;
    const auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    if (operation.observer(operation.observer_context, interface_id, frame,
                           static_cast<std::uint64_t>(timestamp))) {
      ++operation.captured_frames;
    } else {
      ++operation.capture_drops;
    }
  }

  [[nodiscard]] bool enqueue(Path path, const Frame& frame) noexcept {
    // Allocation precedes queue admission so the queue carries a stable 32-bit
    // handle. Failure returns the slot immediately and becomes an observable
    // drop instead of silently bypassing the modeled queue.
    const auto handle = pool.allocate(frame);
    if (!handle) return fail(NetworkDrop::queue_full);
    if (!paths[path].tx.try_push(*handle)) {
      pool.release(*handle);
      return fail(NetworkDrop::queue_full);
    }
    // Capture IDs 6 and 7 are the router egress pipeline before serialization.
    // IDs 0 through 3 remain the four physical medium directions observed only
    // after LinkDirection accepts the handle.
    if (path == router_to_host_a) observe(6, frame);
    if (path == router_to_host_b) observe(7, frame);
    return true;
  }

  bool fail(NetworkDrop reason) noexcept {
    if (operation.active && !operation.terminal) {
      operation.terminal = true;
      operation.success = false;
      operation.drop = reason;
    }
    return false;
  }

  void start_echo_clock() noexcept {
    // RTT begins when the Echo frame enters the source TX queue. Preparatory ARP
    // at the source is excluded, while router-side resolution after launch is
    // naturally included because it delays delivery of that same datagram.
    if (!operation.echo_started) operation.echo_started = std::chrono::steady_clock::now();
  }

  void pump_transmit() noexcept {
    // try_peek preserves FIFO ownership until LinkDirection accepts the frame.
    // This matters when 2048 propagating frames fill a direction while its TX
    // queue continues to apply bounded backpressure.
    for (std::uint8_t index = 0; index < path_count; ++index) {
      auto& path = paths[index];
      PacketHandle handle{};
      while (path.tx.try_peek(handle)) {
        const auto admitted = path.link.try_transmit(handle, pool.get(handle).size());
        if (!admitted) break;
        static_cast<void>(path.tx.try_pop(handle));
        ++operation.transmitted_frames;
        if (index == router_to_host_a) ++operation.tx[0];
        if (index == router_to_host_b) ++operation.tx[1];
        observe(index, pool.get(handle));
      }
    }
  }

  void pump_delivery() noexcept {
    // A frame is visible to the receiver only after the direction reports its
    // real steady-clock delivery deadline. Parsing before this transfer would
    // recreate the forbidden direct device-to-device shortcut.
    for (std::uint8_t index = 0; index < path_count; ++index) {
      auto& path = paths[index];
      std::uint32_t handle{};
      while (!path.rx.full() && path.link.pop_delivered(handle)) {
        static_cast<void>(path.rx.try_push(handle));
      }
      while (path.rx.try_pop(handle)) {
        const Frame frame = pool.get(handle);
        pool.release(handle);
        if (index == host_a_to_router) {
          ++operation.rx[0];
          process_router(0, frame);
        } else if (index == host_b_to_router) {
          ++operation.rx[1];
          process_router(1, frame);
        } else if (index == router_to_host_a) {
          process_host(0, frame);
        } else {
          process_host(1, frame);
        }
      }
    }
  }

  [[nodiscard]] Path host_egress(std::uint8_t host) const noexcept {
    return host ? host_b_to_router : host_a_to_router;
  }

  [[nodiscard]] Path router_egress(std::uint8_t port) const noexcept {
    return port ? router_to_host_b : router_to_host_a;
  }

  void process_host(std::uint8_t index, const Frame& frame) noexcept {
    // The endpoint derives every response from bytes dequeued from its RX ring.
    // Constants identify only its own configured addresses, never a neighbor's
    // response or future protocol state.
    const auto ethernet = packet::parse_ethernet(frame);
    if (!ethernet || !packet::ethernet_for_local(ethernet->destination, hosts[index].mac)) {
      return;
    }
    if (ethernet->ether_type == 0x0806) {
      const auto arp = packet::parse_arp(frame);
      if (!arp || arp->target_ip != hosts[index].address) return;
      // Source: ietf.arp.rfc826. The sender mapping is merged before the opcode
      // is processed, so a request also supplies a usable return adjacency.
      // The single-entry cache records both keys and values, preventing a MAC
      // learned for one IPv4 address from satisfying a different resolution.
      if (!is_zero(arp->sender_mac)) {
        hosts[index].neighbor_address = arp->sender_ip;
        hosts[index].neighbor_mac = arp->sender_mac;
      }
      if (arp->operation == 1) {
        static_cast<void>(enqueue(host_egress(index),
                                  packet::arp_reply(hosts[index].mac, hosts[index].address,
                                                    arp->sender_mac, arp->sender_ip)));
      }
      // Either an ARP Request or Reply can complete resolution because RFC 826
      // merges the sender tuple before examining the operation. Only a mapping
      // for the exact requested protocol address releases the queued datagram.
      if (hosts[index].pending && hosts[index].pending_next_hop == arp->sender_ip) {
        auto pending_frame = *hosts[index].pending;
        hosts[index].pending.reset();
        hosts[index].pending_next_hop.reset();
        packet::rewrite_ethernet(pending_frame, hosts[index].mac, arp->sender_mac);
        start_echo_clock();
        static_cast<void>(enqueue(host_egress(index), pending_frame));
      }
      return;
    }
    if (ethernet->ether_type != 0x0800) return;
    const auto ip = packet::parse_ipv4(frame);
    const auto icmp = packet::parse_icmp(frame);
    if (!ip || !icmp || ip->destination != hosts[index].address) return;
    if (icmp->type == 8 && index == 1) {
      const auto reply = packet::icmp_echo_reply(frame, hosts[index].mac, ethernet->source);
      if (reply) static_cast<void>(enqueue(host_b_to_router, *reply));
      return;
    }
    if (icmp->type == 0 && operation.origin == PingOrigin::host_a && index == 0 &&
        icmp->sequence == operation.sequence) {
      operation.reply_ttl = ip->ttl;
      operation.success = true;
      operation.terminal = true;
      return;
    }
    if (icmp->type == 11 && operation.origin == PingOrigin::host_a && index == 0) {
      fail(NetworkDrop::ttl_expired);
    }
  }

  void learn_router_arp(std::uint8_t port, const packet::ArpView& arp) noexcept {
    // The port is receiver-local information. The MAC and protocol address are
    // taken only from parsed sender fields, never from configured neighbor data.
    if (is_zero(arp.sender_mac)) return;
    router_arp[port] = Adjacency{.address = arp.sender_ip, .mac = arp.sender_mac};
  }

  void flush_pending(std::uint8_t port) noexcept {
    // ARP completion is the only path that releases unresolved IPv4 traffic.
    // Transit packets are routed here so their L2 rewrite uses the learned MAC.
    // Pending traffic on this profile always targets the configured endpoint
    // on the selected port. A different learned sender remains observable in
    // the cache but cannot release or rewrite that traffic.
    if (!router_arp[port]) return;
    PendingFrame item;
    const auto count = pending[port].size();
    for (std::size_t index = 0; index < count; ++index) {
      static_cast<void>(pending[port].try_pop(item));
      if (item.next_hop != router_arp[port]->address) {
        static_cast<void>(pending[port].try_push(item));
        continue;
      }
      if (item.routed) {
        const auto routed = packet::route_ipv4(item.frame,
                                                port ? router_mac_b : router_mac_a,
                                                router_arp[port]->mac);
        if (!routed) {
          fail(NetworkDrop::malformed);
          continue;
        }
        static_cast<void>(enqueue(router_egress(port), *routed));
      } else {
        packet::rewrite_ethernet(item.frame, port ? router_mac_b : router_mac_a,
                                 router_arp[port]->mac);
        start_echo_clock();
        static_cast<void>(enqueue(router_egress(port), item.frame));
      }
    }
    arp_outstanding[port] = false;
  }

  void resolve_or_queue(std::uint8_t port, const Frame& frame, bool routed,
                        Ipv4 next_hop) noexcept {
    // Source: ietf.arp.rfc826 and ietf.ipv4.router_requirements.rfc1812. Only
    // one request is outstanding per adjacency while up to eight packets wait.
    if (router_arp[port] && router_arp[port]->address == next_hop) {
      PendingFrame pending_frame{frame, routed, next_hop};
      if (!pending[port].try_push(pending_frame)) {
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
    if (!arp_outstanding[port]) {
      arp_outstanding[port] = true;
      static_cast<void>(enqueue(router_egress(port),
                                packet::arp_request(port ? router_mac_b : router_mac_a,
                                                    port ? router_ip_b : router_ip_a,
                                                    next_hop)));
    }
  }

  void process_router(std::uint8_t ingress, const Frame& frame) noexcept {
    // The ingress port, EtherType, header checksum, destination and FIB are all
    // derived or checked after RX delivery. The topology editor supplies none
    // of the forwarding decision as an out-of-band hint.
    observe(static_cast<std::uint8_t>(4U + ingress), frame);
    if (!fib.port_operational[ingress]) {
      fail(NetworkDrop::ingress_down);
      return;
    }
    const auto ethernet = packet::parse_ethernet(frame);
    if (!ethernet) {
      fail(NetworkDrop::malformed);
      return;
    }
    const auto local_mac = ingress ? router_mac_b : router_mac_a;
    if (!packet::ethernet_for_local(ethernet->destination, local_mac)) {
      // Ethernet filtering occurs before any L3 lookup or adjacency mutation.
      // A frame addressed to another station is not accepted merely because it
      // entered the modeled router port.
      return;
    }
    if (ethernet->ether_type == 0x0806) {
      const auto arp = packet::parse_arp(frame);
      if (!arp) return;
      learn_router_arp(ingress, *arp);
      const auto local_ip = ingress ? router_ip_b : router_ip_a;
      if (arp->target_ip == local_ip) observe(8, frame);
      if (arp->operation == 1 && arp->target_ip == local_ip) {
        static_cast<void>(enqueue(router_egress(ingress),
                                  packet::arp_reply(local_mac, local_ip, arp->sender_mac,
                                                    arp->sender_ip)));
      } else if (arp->operation == 2 && arp->target_ip == local_ip) {
        flush_pending(ingress);
      }
      return;
    }
    if (ethernet->ether_type != 0x0800) return;
    // parse_ipv4 verifies the entire header before FIB lookup. A damaged frame
    // therefore cannot consume an adjacency slot or select an egress queue.
    const auto ip = packet::parse_ipv4(frame);
    if (!ip) {
      fail(NetworkDrop::malformed);
      return;
    }
    if (ip->destination == router_ip_a || ip->destination == router_ip_b) {
      // Locally terminated IPv4 enters the CPM punt observation point before
      // ICMP dispatch. It is still the received frame, not an out-of-band
      // protocol object or a synthetic event.
      observe(8, frame);
      const auto icmp = packet::parse_icmp(frame);
      if (!icmp) return;
      if (icmp->type == 8) {
        const auto reply = packet::icmp_echo_reply(
            frame, ingress ? router_mac_b : router_mac_a, ethernet->source);
        if (reply) static_cast<void>(enqueue(router_egress(ingress), *reply));
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
    if (!routing::lookup(fib, to_u32(ip->destination), egress, &configured_next_hop) ||
        !fib.port_operational[egress]) {
      fail(NetworkDrop::route_miss);
      return;
    }
    if (ip->ttl <= 1) {
      // Time Exceeded returns through the ingress adjacency learned from the
      // sender's earlier ARP exchange. It is itself an encoded frame and crosses
      // the normal router egress link rather than completing the probe directly.
      const auto exceeded = packet::icmp_time_exceeded(
          frame, ingress ? router_mac_b : router_mac_a, ethernet->source,
          ingress ? router_ip_b : router_ip_a, ip->source);
      if (exceeded) static_cast<void>(enqueue(router_egress(ingress), *exceeded));
      return;
    }
    const auto resolved = configured_next_hop ? configured_next_hop : to_u32(ip->destination);
    resolve_or_queue(egress, frame, true,
                     {static_cast<std::uint8_t>(resolved >> 24),
                      static_cast<std::uint8_t>(resolved >> 16),
                      static_cast<std::uint8_t>(resolved >> 8),
                      static_cast<std::uint8_t>(resolved)});
  }

  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point>
  next_delivery() const noexcept {
    // This scan compares four link-owned deadlines only. It stores no event and
    // cannot execute network work, advance time, pause it, or change ordering.
    std::optional<std::chrono::steady_clock::time_point> next;
    for (const auto& path : paths) {
      const auto candidate = path.link.next_delivery();
      if (candidate && (!next || *candidate < *next)) next = candidate;
    }
    return next;
  }

  [[nodiscard]] std::array<NetworkArpEntry, 2> arp_projection() const noexcept {
    std::array<NetworkArpEntry, 2> result{};
    for (std::uint8_t port = 0; port < 2; ++port) {
      if (router_arp[port]) {
        result[port] = {.valid = true,
                        .address = router_arp[port]->address,
                        .mac = router_arp[port]->mac,
                        .port_index = port};
      }
    }
    return result;
  }

  [[nodiscard]] NetworkResult ping(PingOrigin origin, std::uint16_t sequence,
                                   CaptureObserver observer,
                                   void* context) noexcept {
    // Reset every per-probe counter without touching persistent ARP, queues or
    // physical links. Reusing neighbor state is observable on later probes.
    operation = {};
    operation.active = true;
    operation.origin = origin;
    operation.sequence = sequence;
    operation.observer = observer;
    operation.observer_context = context;
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    if (origin == PingOrigin::host_a) {
      if (!fib.port_operational[0]) {
        fail(NetworkDrop::ingress_down);
      } else {
        auto request = packet::icmp_echo(hosts[0].mac, no_mac, hosts[0].address,
                                         hosts[1].address, false, sequence);
        const auto next_hop_u32 = routing::host_next_hop(
            to_u32(hosts[0].address), hosts[0].prefix_length,
            to_u32(hosts[1].address), to_u32(hosts[0].gateway));
        const Ipv4 next_hop{static_cast<std::uint8_t>(next_hop_u32 >> 24),
                            static_cast<std::uint8_t>(next_hop_u32 >> 16),
                            static_cast<std::uint8_t>(next_hop_u32 >> 8),
                            static_cast<std::uint8_t>(next_hop_u32)};
        if (hosts[0].neighbor_address == next_hop && hosts[0].neighbor_mac) {
          packet::rewrite_ethernet(request, hosts[0].mac, *hosts[0].neighbor_mac);
          start_echo_clock();
          static_cast<void>(enqueue(host_a_to_router, request));
        } else {
          // Replacing a one-entry cache is explicit. A stale MAC for a previous
          // next hop cannot leak into this packet while ARP is outstanding.
          hosts[0].neighbor_address.reset();
          hosts[0].neighbor_mac.reset();
          hosts[0].pending = request;
          hosts[0].pending_next_hop = next_hop;
          static_cast<void>(enqueue(host_a_to_router,
                                    packet::arp_request(hosts[0].mac, hosts[0].address,
                                                        next_hop)));
        }
      }
    } else if (!fib.port_operational[1]) {
      fail(NetworkDrop::route_miss);
    } else {
      const auto request = packet::icmp_echo(router_mac_b, no_mac, router_ip_b,
                                             hosts[1].address, false, sequence);
      resolve_or_queue(1, request, false, hosts[1].address);
    }

    // Each LinkDirection owns its transmission and propagation deadlines. This
    // shard merely waits for the earliest local delivery; it is not a global
    // simulation clock and cannot advance or rewind runtime time.
    while (!operation.terminal && std::chrono::steady_clock::now() < deadline) {
      pump_transmit();
      pump_delivery();
      // RX processing can synchronously enqueue a protocol response such as an
      // ARP Reply. A second launch pass gives that new TX handle its own link
      // deadline before the shard decides whether there is work to wait for.
      // Without this pass, an empty in-flight list could be mistaken for an
      // idle network while a valid response remained in a device TX queue.
      pump_transmit();
      if (operation.terminal) break;
      if (const auto next = next_delivery()) {
        std::this_thread::sleep_until(std::min(*next, deadline));
      } else if (std::chrono::steady_clock::now() < deadline) {
        fail(NetworkDrop::timeout);
      }
    }
    if (!operation.terminal) fail(NetworkDrop::timeout);
    NetworkResult result{
        .success = operation.success,
        .drop = operation.drop,
        .reply_ttl = operation.reply_ttl,
        .transmitted_frames = operation.transmitted_frames,
        .captured_frames = operation.captured_frames,
        .capture_drops = operation.capture_drops,
        .rx_delta = operation.rx,
        .tx_delta = operation.tx,
        .router_arp = arp_projection(),
    };
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

void LabNetwork::install_fib(const routing::FibProgram& fib) noexcept {
  // Link failure invalidates only state whose dependency chain includes that
  // port. The opposite interface and its adjacency remain usable.
  for (std::uint8_t port = 0; port < 2; ++port) {
    if (!fib.port_operational[port]) {
      impl_->router_arp[port].reset();
      impl_->arp_outstanding[port] = false;
      PendingFrame discarded;
      while (impl_->pending[port].try_pop(discarded)) {}
      impl_->hosts[port].neighbor_address.reset();
      impl_->hosts[port].neighbor_mac.reset();
      impl_->hosts[port].pending.reset();
      impl_->hosts[port].pending_next_hop.reset();
    }
  }
  if (fib.generation >= impl_->fib.generation) impl_->fib = fib;
}

void LabNetwork::configure_hosts(
    const std::array<Mac, 2>& macs, const std::array<Ipv4, 2>& addresses,
    const std::array<std::uint8_t, 2>& prefix_lengths,
    const std::array<Ipv4, 2>& gateways) noexcept {
  // Control validates the complete pair before this message is published. Both
  // endpoints are replaced in one forwarding job, so swapping identities can
  // never expose a transient duplicate or half-applied project generation.
  for (std::size_t index = 0; index < impl_->hosts.size(); ++index) {
    impl_->hosts[index] = {.mac = macs[index],
                           .address = addresses[index],
                           .prefix_length = prefix_lengths[index],
                           .gateway = gateways[index],
                           .neighbor_address = std::nullopt,
                           .neighbor_mac = std::nullopt,
                           .pending = std::nullopt,
                           .pending_next_hop = std::nullopt};
    impl_->router_arp[index].reset();
  }
}

void LabNetwork::configure_links(
    const std::array<std::chrono::nanoseconds, 2>& propagation_delays) noexcept {
  // Paths 0 and 1 are the two directions of the Host A medium. Paths 2 and 3
  // are the two directions of the Host B medium. Each direction keeps its own
  // serialization deadline and queues, while a shared physical length gives
  // both directions the same propagation delay.
  impl_->paths[Impl::host_a_to_router].link.set_propagation(propagation_delays[0]);
  impl_->paths[Impl::router_to_host_a].link.set_propagation(propagation_delays[0]);
  impl_->paths[Impl::router_to_host_b].link.set_propagation(propagation_delays[1]);
  impl_->paths[Impl::host_b_to_router].link.set_propagation(propagation_delays[1]);
}

void LabNetwork::restore_adjacencies(
    const std::array<NetworkArpEntry, 2>& entries) noexcept {
  // The quiescent checkpoint contains no live queue handles. Rebuilding cache
  // values is therefore independent from PacketPool generations and cannot
  // release or duplicate a buffer owned before import.
  for (std::size_t index = 0; index < entries.size(); ++index) {
    if (entries[index].valid) {
      impl_->router_arp[index] = Adjacency{entries[index].address, entries[index].mac};
    } else {
      impl_->router_arp[index].reset();
    }
    impl_->arp_outstanding[index] = false;
    impl_->hosts[index].pending.reset();
    impl_->hosts[index].pending_next_hop.reset();
  }
  // Each host's first hop is the router interface on its own medium. Rebuilding
  // this derived adjacency avoids an unnecessary ARP exchange after restore and
  // uses only addresses already locked by the profile and project.
  impl_->hosts[0].neighbor_address = router_ip_a;
  impl_->hosts[0].neighbor_mac = router_mac_a;
  impl_->hosts[1].neighbor_address = router_ip_b;
  impl_->hosts[1].neighbor_mac = router_mac_b;
}

std::array<NetworkArpEntry, 2> LabNetwork::adjacencies() const noexcept {
  return impl_->arp_projection();
}

NetworkResult LabNetwork::ping(PingOrigin origin, std::uint16_t sequence,
                               CaptureObserver observer,
                               void* observer_context) noexcept {
  return impl_->ping(origin, sequence, observer, observer_context);
}

}  // namespace router
