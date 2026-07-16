// Per-router Ethernet, ARP and IPv4 forwarding implementation. All neighbor
// knowledge is learned from received RFC 826 bytes on one local port.

#include "router/router_forwarder.hpp"

#include <algorithm>

namespace router::lab {
namespace {

std::uint32_t to_u32(packet::Ipv4 address) noexcept {
  // Packet fields remain byte arrays in network order. The RIB uses an integer
  // only as a comparison key, so this conversion performs no host-endian load.
  return static_cast<std::uint32_t>(address[0]) << 24 |
         static_cast<std::uint32_t>(address[1]) << 16 |
         static_cast<std::uint32_t>(address[2]) << 8 | address[3];
}

packet::Ipv4 to_ipv4(std::uint32_t address) noexcept {
  // Shifts define the wire byte order explicitly and avoid aliasing a uint32_t
  // through a byte pointer on Wasm and native hosts.
  return {static_cast<std::uint8_t>(address >> 24),
          static_cast<std::uint8_t>(address >> 16),
          static_cast<std::uint8_t>(address >> 8),
          static_cast<std::uint8_t>(address)};
}

bool usable_sender_mac(packet::Mac mac) noexcept {
  // Reject group, broadcast and all-zero addresses before ARP learning. The
  // local-admin bit is valid and therefore intentionally not rejected.
  return (mac[0] & 1U) == 0U &&
         std::any_of(mac.begin(), mac.end(), [](auto byte) { return byte != 0; });
}

constexpr packet::Mac unresolved_mac{};

} // namespace

bool RouterForwarder::configure_port(const ForwardPort &input) noexcept {
  // Validation occurs before indexing the fixed arena. An invalid management
  // transaction cannot disturb the previously installed forwarding projection.
  if (input.ordinal >= ports_.size() || input.prefix_length > 32U ||
      input.mtu < device_catalog::minimum_network_mtu ||
      input.mtu > device_catalog::maximum_network_mtu || !input.speed_mbps)
    return false;
  // Network is canonicalized at the forwarding boundary. Control may keep the
  // configured host address separately, while lookup sees one unambiguous key.
  auto value = input;
  value.network &= routing::prefix_mask(value.prefix_length);
  ports_[value.ordinal] = value;
  return true;
}

void RouterForwarder::remove_port(std::uint16_t ordinal) noexcept {
  if (ordinal >= ports_.size())
    return;
  ports_[ordinal] = {};
  // Removing physical inventory invalidates local adjacencies and queued work.
  // It never rewrites another port or another router's state.
  for (auto &entry : adjacencies_)
    if (entry.valid && entry.port_ordinal == ordinal)
      entry = {};
  for (auto &entry : pending_)
    if (entry.valid && entry.port_ordinal == ordinal) {
      entry = {};
      drop(ForwardDrop::port_down);
    }
}

RouterForwarderCheckpoint
RouterForwarder::checkpoint(Clock::time_point now) const {
  RouterForwarderCheckpoint state;
  state.ports.reserve(ports_.size());
  for (const auto &port : ports_)
    if (port.configured)
      state.ports.push_back(port);
  state.fib = fib_;
  state.adjacencies.reserve(arp_entries());
  for (const auto &entry : adjacencies_) {
    if (!entry.valid)
      continue;
    const auto remaining = entry.expires > now ? entry.expires - now
                                                : Clock::duration::zero();
    state.adjacencies.push_back({
        .port_ordinal = entry.port_ordinal,
        .address = entry.address,
        .mac = entry.mac,
        .remaining_nanoseconds =
            std::chrono::duration_cast<std::chrono::nanoseconds>(remaining)
                .count()});
  }
  state.pending.reserve(pending_frames());
  for (const auto &entry : pending_)
    if (entry.valid)
      state.pending.push_back({entry.transit, entry.port_ordinal,
                               entry.next_hop, entry.frame});
  state.forwarded_frames = forwarded_frames_;
  state.dropped_frames = dropped_frames_;
  state.last_drop = last_drop_;
  state.echo_reply_sequence = echo_reply_sequence_;
  state.echo_reply_valid = echo_reply_valid_;
  return state;
}

bool RouterForwarder::validate_checkpoint(
    const RouterForwarderCheckpoint &state) noexcept {
  // Validate every index, count and frame before clearing the live arrays.
  // The second installation phase contains no allocation and cannot fail.
  if (state.ports.size() > device_catalog::maximum_ports_per_router ||
      state.adjacencies.size() > device_catalog::arp_entries_per_router ||
      state.pending.size() > device_catalog::pending_ipv4_frames_per_router ||
      state.fib.count > state.fib.routes.size() ||
      state.last_drop < ForwardDrop::none ||
      state.last_drop > ForwardDrop::mtu_exceeded)
    return false;
  std::array<bool, device_catalog::maximum_ports_per_router> seen_ports{};
  for (const auto &port : state.ports) {
    if (!port.configured || port.ordinal >= seen_ports.size() ||
        seen_ports[port.ordinal] || port.prefix_length > 32U ||
        port.mtu < device_catalog::minimum_network_mtu ||
        port.mtu > device_catalog::maximum_network_mtu || !port.speed_mbps)
      return false;
    seen_ports[port.ordinal] = true;
  }
  for (const auto &entry : state.adjacencies)
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] || !usable_sender_mac(entry.mac) ||
        entry.remaining_nanoseconds < 0)
      return false;
  for (const auto &entry : state.pending)
    if (entry.port_ordinal >= seen_ports.size() ||
        !seen_ports[entry.port_ordinal] || !entry.next_hop ||
        !entry.frame.size() || entry.frame.size() > entry.frame.bytes.size())
      return false;
  return true;
}

bool RouterForwarder::restore(const RouterForwarderCheckpoint &state,
                              Clock::time_point now) noexcept {
  if (!validate_checkpoint(state))
    return false;

  ports_.fill({});
  adjacencies_.fill({});
  pending_.fill({});
  for (const auto &port : state.ports)
    ports_[port.ordinal] = port;
  fib_ = state.fib;
  for (std::size_t index = 0; index < state.adjacencies.size(); ++index) {
    const auto &source = state.adjacencies[index];
    adjacencies_[index] = {
        .valid = true,
        .port_ordinal = source.port_ordinal,
        .address = source.address,
        .mac = source.mac,
        .expires = now + std::chrono::nanoseconds(source.remaining_nanoseconds)};
  }
  for (std::size_t index = 0; index < state.pending.size(); ++index) {
    const auto &source = state.pending[index];
    pending_[index] = {.valid = true,
                       .transit = source.transit,
                       .port_ordinal = source.port_ordinal,
                       .next_hop = source.next_hop,
                       .frame = source.frame};
  }
  forwarded_frames_ = state.forwarded_frames;
  dropped_frames_ = state.dropped_frames;
  last_drop_ = state.last_drop;
  echo_reply_sequence_ = state.echo_reply_sequence;
  echo_reply_valid_ = state.echo_reply_valid;
  return true;
}

bool RouterForwarder::program_fib(
    const routing::FibProgram &program) noexcept {
  // Equal generation is idempotent. Older generations are stale shard messages
  // and cannot replace forwarding state selected later by control.
  if (program.generation < fib_.generation ||
      program.count > program.routes.size())
    return false;
  if (program.generation == fib_.generation && fib_.generation) {
    // Reusing a generation with different bytes would make stale-message
    // ordering ambiguous. Accept only an exact idempotent replay.
    if (program.count != fib_.count ||
        !std::equal(program.routes.begin(),
                    program.routes.begin() + program.count,
                    fib_.routes.begin(), [](const auto &left, const auto &right) {
                      return left.network == right.network &&
                             left.next_hop == right.next_hop &&
                             left.port_ordinal == right.port_ordinal &&
                             left.prefix_length == right.prefix_length;
                    }))
      return false;
    return true;
  }
  fib_ = program;
  return true;
}

bool RouterForwarder::originate_echo(std::uint32_t destination,
                                     std::uint16_t sequence, void *context,
                                     EgressSink sink,
                                     Clock::time_point now,
                                     std::uint16_t payload_octets,
                                     bool dont_fragment) noexcept {
  routing::Route route;
  // Source selection follows the same local FIB used by transit packets. This
  // prevents a CLI ping from gaining an out-of-band route through the lab graph.
  if (!routing::lookup(fib_, destination, route)) {
    drop(ForwardDrop::no_route);
    return false;
  }
  const auto *egress = port(route.port_ordinal);
  if (!egress || !egress->operational) {
    drop(ForwardDrop::port_down);
    return false;
  }
  // Source address and MAC come from the locally selected egress interface.
  // The router does not ask another device or the topology graph for a source.
  auto request = packet::icmp_echo(
      egress->mac, unresolved_mac, to_ipv4(egress->address),
      to_ipv4(destination), false, sequence, 64, payload_octets,
      dont_fragment);
  echo_reply_valid_ = false;
  const auto forwarded_before = forwarded_frames_;
  send(request, destination, false, context, sink, now);
  return forwarded_frames_ != forwarded_before || pending_frames() > 0;
}

const ForwardPort *RouterForwarder::port(std::uint16_t ordinal) const noexcept {
  return ordinal < ports_.size() && ports_[ordinal].configured
             ? &ports_[ordinal]
             : nullptr;
}

ForwardPort *RouterForwarder::port(std::uint16_t ordinal) noexcept {
  return ordinal < ports_.size() && ports_[ordinal].configured
             ? &ports_[ordinal]
             : nullptr;
}

RouterForwarder::Adjacency *RouterForwarder::find_adjacency(
    std::uint16_t port_ordinal, std::uint32_t address,
    Clock::time_point now) noexcept {
  for (auto &entry : adjacencies_) {
    // Port is part of the key because equal protocol addresses on separate
    // interfaces cannot share one link-layer mapping.
    if (!entry.valid || entry.port_ordinal != port_ordinal ||
        entry.address != address)
      continue;
    if (entry.expires <= now) {
      entry = {};
      return nullptr;
    }
    return &entry;
  }
  return nullptr;
}

void RouterForwarder::learn(std::uint16_t port_ordinal, std::uint32_t address,
                            packet::Mac mac, Clock::time_point now) noexcept {
  if (!usable_sender_mac(mac))
    return;
  Adjacency *target{};
  // Prefer an exact existing key, otherwise remember the first free slot. The
  // scan never evicts an unrelated live neighbor behind the user's back.
  for (auto &entry : adjacencies_) {
    if (entry.valid && entry.port_ordinal == port_ordinal &&
        entry.address == address) {
      target = &entry;
      break;
    }
    if (!entry.valid && !target)
      target = &entry;
  }
  if (!target)
    return;
  // Source: ietf.arp.rfc826 and nokia.sros.26_7.arp.aging. A learned sender
  // mapping refreshes the release default dynamic lifetime.
  *target = {.valid = true,
             .port_ordinal = port_ordinal,
             .address = address,
             .mac = mac,
             .expires = now + device_catalog::dynamic_arp_timeout};
}

bool RouterForwarder::emit(std::uint16_t port_ordinal,
                           const packet::Frame &frame, void *context,
                           EgressSink sink) noexcept {
  // The sink is the only legal forwarding-to-link boundary. Failure is a real
  // queue drop and cannot fall back to calling the receiver directly.
  if (!sink || !sink(context, port_ordinal, frame)) {
    drop(ForwardDrop::egress_queue_full);
    return false;
  }
  ++forwarded_frames_;
  return true;
}

void RouterForwarder::send_resolved(const packet::Frame &input,
                                    const ForwardPort &egress,
                                    packet::Mac destination_mac, bool transit,
                                    void *context, EgressSink sink,
                                    Clock::time_point now) noexcept {
  packet::Frame frame;
  packet::copy_frame(frame, input);
  // Input remains the untouched received datagram for ICMP quotation. The
  // bounded working copy may change L2 bytes, TTL, checksum and fragmentation.
  if (transit) {
    // route_ipv4 decrements TTL exactly once and recalculates the IPv4 checksum.
    if (!packet::route_ipv4_into(frame, input, egress.mac, destination_mac)) {
      drop(ForwardDrop::malformed);
      return;
    }
  } else {
    packet::rewrite_ethernet(frame, egress.mac, destination_mac);
  }

  const auto ip = packet::parse_ipv4(frame);
  if (!ip) {
    drop(ForwardDrop::malformed);
    return;
  }
  // SR OS Ethernet MTU includes the 14-octet untagged MAC header. Fragmentation
  // receives the actual maximum IPv4 length for this egress port.
  const auto ip_mtu = static_cast<std::uint16_t>(egress.mtu - 14U);
  if (ip->total_length <= ip_mtu) {
    static_cast<void>(emit(egress.ordinal, frame, context, sink));
    return;
  }
  if (ip->dont_fragment) {
    drop(ForwardDrop::mtu_exceeded);
    // RFC 1191 requires code 4 and the next-hop IP MTU. Quote the received
    // datagram before TTL decrement, then route the new error independently.
    if (transit) {
      const auto original_ip = packet::parse_ipv4(input);
      if (original_ip && may_send_icmp_error(input, *original_ip))
        send_fragmentation_needed(input, *original_ip, ip_mtu, context,
                                  sink, now);
    }
    return;
  }
  const auto fragments = packet::fragment_ipv4(frame, ip_mtu);
  if (!fragments) {
    drop(ForwardDrop::mtu_exceeded);
    return;
  }
  for (std::size_t index = 0; index < fragments->count; ++index)
    // Fragments retain encoder order. Stopping after the first queue rejection
    // avoids delivering a suffix whose leading fragment was already dropped.
    if (!emit(egress.ordinal, fragments->frames[index], context, sink))
      break;
}

void RouterForwarder::send(packet::Frame frame, std::uint32_t destination,
                           bool transit, void *context, EgressSink sink,
                           Clock::time_point now) noexcept {
  routing::Route route;
  if (!routing::lookup(fib_, destination, route)) {
    drop(ForwardDrop::no_route);
    return;
  }
  const auto *egress = port(route.port_ordinal);
  if (!egress || !egress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto next_hop = route.next_hop ? route.next_hop : destination;
  // A connected route resolves the destination itself. A static route resolves
  // its configured protocol next-hop and never asks topology for a neighbor MAC.
  if (auto *adjacency = find_adjacency(route.port_ordinal, next_hop, now)) {
    send_resolved(frame, *egress, adjacency->mac, transit, context, sink, now);
    return;
  }

  bool request_in_progress{};
  Pending *free{};
  for (auto &entry : pending_) {
    if (entry.valid && entry.port_ordinal == route.port_ordinal &&
        entry.next_hop == next_hop)
      request_in_progress = true;
    if (!entry.valid && !free)
      free = &entry;
  }
  if (!free) {
    drop(ForwardDrop::arp_pending_full);
    return;
  }
  free->valid = true;
  free->transit = transit;
  free->port_ordinal = route.port_ordinal;
  free->next_hop = next_hop;
  packet::copy_frame(free->frame, frame);
  // Only the first pending frame for an exact adjacency emits a request.
  // Following frames wait in their bounded router-owned queue.
  if (!request_in_progress) {
    const auto request = packet::arp_request(
        egress->mac, to_ipv4(egress->address), to_ipv4(next_hop));
    if (!emit(egress->ordinal, request, context, sink)) {
      // No retry timer exists in this narrow milestone yet. Retaining the
      // initiating datagram after its only ARP request was rejected would make
      // originate_echo report a live operation that can never progress.
      *free = {};
    }
  }
}

void RouterForwarder::flush_pending(std::uint16_t port_ordinal,
                                    std::uint32_t address, packet::Mac mac,
                                    void *context, EgressSink sink,
                                    Clock::time_point now) noexcept {
  const auto *egress = port(port_ordinal);
  if (!egress || !egress->operational)
    return;
  for (auto &entry : pending_) {
    // Only exact port and next-hop matches are released. An ARP reply received
    // elsewhere cannot unlock traffic on another physical adjacency.
    if (!entry.valid || entry.port_ordinal != port_ordinal ||
        entry.next_hop != address)
      continue;
    // Clear ownership before egress callback. A callback-triggered failure or
    // reentrant status query cannot observe the same pending frame twice.
    const auto frame = entry.frame;
    const auto transit = entry.transit;
    entry = {};
    send_resolved(frame, *egress, mac, transit, context, sink, now);
  }
}

void RouterForwarder::send_time_exceeded(
    const packet::Frame &original, const packet::Ipv4View &ip, void *context,
    EgressSink sink, Clock::time_point now) noexcept {
  if (!may_send_icmp_error(original, ip))
    return;
  routing::Route reverse;
  // The return path is independently looked up. Symmetry is never inferred
  // from the ingress port because static routing may be asymmetric.
  if (!routing::lookup(fib_, to_u32(ip.source), reverse)) {
    drop(ForwardDrop::no_route);
    return;
  }
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto error = packet::icmp_time_exceeded(
      original, egress->mac, unresolved_mac, to_ipv4(egress->address),
      ip.source);
  if (!error) {
    drop(ForwardDrop::malformed);
    return;
  }
  send(*error, to_u32(ip.source), false, context, sink, now);
}

void RouterForwarder::send_fragmentation_needed(
    const packet::Frame &original, const packet::Ipv4View &ip,
    std::uint16_t next_hop_mtu, void *context, EgressSink sink,
    Clock::time_point now) noexcept {
  routing::Route reverse;
  if (!routing::lookup(fib_, to_u32(ip.source), reverse))
    return;
  const auto *egress = port(reverse.port_ordinal);
  if (!egress || !egress->operational)
    return;
  const auto error = packet::icmp_fragmentation_needed(
      original, egress->mac, unresolved_mac, to_ipv4(egress->address),
      ip.source, next_hop_mtu);
  if (error)
    send(*error, to_u32(ip.source), false, context, sink, now);
}

bool RouterForwarder::may_send_icmp_error(
    const packet::Frame &original, const packet::Ipv4View &ip) const noexcept {
  const auto source = to_u32(ip.source);
  const auto destination = to_u32(ip.destination);
  const auto multicast = [](std::uint32_t address) {
    return (address & 0xf0000000U) == 0xe0000000U;
  };
  // Source: ietf.ipv4.router_requirements.rfc1812. Errors are suppressed for
  // invalid sources, multicast, limited broadcast and non-initial fragments.
  if (!source || source == 0xffffffffU || multicast(source) ||
      destination == 0xffffffffU || multicast(destination) ||
      ip.fragment_offset != 0U)
    return false;
  for (const auto &candidate : ports_) {
    // Directed broadcast depends on each configured prefix, not only the
    // limited broadcast constant. /31 and /32 do not define this broadcast.
    if (!candidate.configured || candidate.prefix_length >= 31U)
      continue;
    const auto broadcast = candidate.network |
                           ~routing::prefix_mask(candidate.prefix_length);
    if (destination == broadcast)
      return false;
  }
  if (ip.protocol != 1U)
    return true;
  const auto icmp = packet::parse_icmp(original);
  if (!icmp)
    return false;
  // ICMP informational messages may receive errors. ICMP error types may not
  // recursively trigger another error and form a network feedback loop.
  return icmp->type != 3U && icmp->type != 4U && icmp->type != 5U &&
         icmp->type != 11U && icmp->type != 12U;
}

void RouterForwarder::receive(std::uint16_t ingress_port,
                              const packet::Frame &frame, void *context,
                              EgressSink sink, Clock::time_point now,
                              void *punt_context,
                              PuntObserver punt_observer) noexcept {
  const auto *ingress = port(ingress_port);
  if (!ingress || !ingress->operational) {
    drop(ForwardDrop::port_down);
    return;
  }
  const auto ethernet = packet::parse_ethernet(frame);
  if (!ethernet) {
    drop(ForwardDrop::malformed);
    return;
  }
  if (!packet::ethernet_for_local(ethernet->destination, ingress->mac)) {
    drop(ForwardDrop::not_for_router);
    return;
  }

  if (ethernet->ether_type == 0x0806) {
    const auto arp = packet::parse_arp(frame);
    if (!arp) {
      drop(ForwardDrop::malformed);
      return;
    }
    // ARP is terminated by the router adjacency process rather than forwarded
    // as IPv4. The observer receives the original encoded ingress frame and is
    // diagnostics-only, so capture failure cannot alter neighbor learning.
    if (punt_observer)
      punt_observer(punt_context, ingress_port, frame);
    const auto sender = to_u32(arp->sender_ip);
    // RFC 826 merges the sender before examining request versus reply. Pending
    // release therefore precedes the optional reply to a request for us.
    learn(ingress_port, sender, arp->sender_mac, now);
    flush_pending(ingress_port, sender, arp->sender_mac, context, sink, now);
    if (arp->operation == 1U && to_u32(arp->target_ip) == ingress->address) {
      const auto reply = packet::arp_reply(ingress->mac,
                                           to_ipv4(ingress->address),
                                           arp->sender_mac, arp->sender_ip);
      static_cast<void>(emit(ingress_port, reply, context, sink));
    }
    return;
  }
  if (ethernet->ether_type != 0x0800) {
    drop(ForwardDrop::malformed);
    return;
  }
  const auto ip = packet::parse_ipv4(frame);
  if (!ip) {
    drop(ForwardDrop::malformed);
    return;
  }

  const auto destination = to_u32(ip->destination);
  const auto local = std::find_if(ports_.begin(), ports_.end(),
                                  [destination](const auto &candidate) {
                                    return candidate.configured &&
                                           candidate.address == destination;
                                  });
  if (local != ports_.end()) {
    // Locally addressed IPv4 leaves the transit pipeline for the CPM protocol
    // stack. Capture observes bytes before an ICMP reply or session state is
    // generated, preserving the actual received packet.
    if (punt_observer)
      punt_observer(punt_context, ingress_port, frame);
    // Local delivery terminates forwarding. Only implemented local protocols
    // respond; unsupported IP protocols are consumed without a success no-op.
    const auto icmp = packet::parse_icmp(frame);
    if (icmp && icmp->type == 8U && icmp->code == 0U) {
      // The reply is locally originated with TTL 64, then routed toward the
      // remote source through this router's own FIB and ARP state.
      const auto reply = packet::icmp_echo_reply(frame, local->mac,
                                                 unresolved_mac);
      if (reply)
        send(*reply, to_u32(ip->source), false, context, sink, now);
    } else if (icmp && icmp->type == 0U && icmp->code == 0U) {
      // Echo success is derived only from a received encoded reply addressed to
      // one local interface. The asynchronous command owner polls this value.
      echo_reply_sequence_ = icmp->sequence;
      echo_reply_valid_ = true;
    }
    return;
  }

  if (ip->ttl <= 1U) {
    // TTL is evaluated before route_ipv4 can decrement it. The original header
    // is available for the required ICMP quotation.
    send_time_exceeded(frame, *ip, context, sink, now);
    return;
  }
  send(frame, destination, true, context, sink, now);
}

void RouterForwarder::expire(Clock::time_point now) noexcept {
  // Aging is local maintenance work. It does not schedule a global event or
  // advance time, and it touches no pending frame until a new resolution starts.
  for (auto &entry : adjacencies_)
    if (entry.valid && entry.expires <= now)
      entry = {};
}

void RouterForwarder::drop(ForwardDrop reason) noexcept {
  // Counters record every rejected frame while last_drop retains the most
  // recent diagnostic for an operational projection.
  ++dropped_frames_;
  last_drop_ = reason;
}

std::size_t RouterForwarder::arp_entries() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      adjacencies_.begin(), adjacencies_.end(),
      [](const auto &entry) { return entry.valid; }));
}

std::size_t RouterForwarder::pending_frames() const noexcept {
  return static_cast<std::size_t>(std::count_if(
      pending_.begin(), pending_.end(),
      [](const auto &entry) { return entry.valid; }));
}

} // namespace router::lab
