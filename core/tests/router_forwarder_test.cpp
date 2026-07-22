// Router forwarder tests drive only encoded frames through two local ports.
// They verify per-hop ARP, TTL, checksum and ICMP without topology shortcuts.

#include "router/dhcpv6_packet.hpp"
#include "router/dhcpv6_relay.hpp"
#include "router/router_forwarder.hpp"
#include "router/udp_packet.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  // The module runner retains the first packet-path contract failure.
  if (!condition)
    throw std::runtime_error(message);
}

struct Emitted {
  std::uint16_t port{};
  router::packet::Frame frame{};
};

bool collect(void *context, std::uint16_t port,
             const router::packet::Frame &frame) {
  // Test storage copies wire bytes because the sink contract does not permit a
  // caller to retain the forwarder's temporary frame reference.
  static_cast<std::vector<Emitted> *>(context)->push_back({port, frame});
  return true;
}

bool admit_all(void *, std::uint16_t, std::size_t frames) {
  // The vector sink used by this module has no finite ring. Returning true for
  // a non-empty batch exercises the same preflight contract supplied by the
  // production SPSC owner without inventing per-fragment acceptance.
  return frames != 0U;
}

router::packet::Frame udp_ipv6_payload_frame(
    const router::packet::Mac &source_mac,
    const router::packet::Mac &destination_mac,
    const router::packet::Ipv6 &source, const router::packet::Ipv6 &destination,
    std::uint16_t source_port, std::uint16_t destination_port,
    std::span<const std::uint8_t> payload) {
  // This helper still constructs a wire packet. It does not inject UDP
  // metadata or a decoded DHCP object into the router application owner.
  using namespace router;
  packet::Frame frame{};
  std::array<std::uint8_t, packet::udp::maximum_datagram_octets> udp{};
  const auto encoded = packet::udp::encode_ipv6(
      udp, source, destination, source_port, destination_port, payload);
  if (!encoded)
    throw std::runtime_error("UDP IPv6 payload fixture encoding failed");
  const auto frame_octets = packet::encode_ipv6_ethernet_datagram(
      frame.bytes, source_mac, destination_mac, source, destination,
      packet::ipv6_next_header_udp, 64U,
      std::span<const std::uint8_t>{udp}.first(*encoded));
  if (!frame_octets || *frame_octets > frame.bytes.size())
    throw std::runtime_error("UDP IPv6 payload fixture exceeds one frame");
  frame.length = static_cast<std::uint16_t>(*frame_octets);
  return frame;
}

router::packet::Frame udp_ipv6_frame(const router::packet::Mac &source_mac,
                                     const router::packet::Mac &destination_mac,
                                     const router::packet::Ipv6 &source,
                                     const router::packet::Ipv6 &destination) {
  constexpr std::array<std::uint8_t, 3> payload{0x41U, 0x42U, 0x43U};
  return udp_ipv6_payload_frame(source_mac, destination_mac, source,
                                destination, 49152U, 9999U, payload);
}

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
  // DHCPv6 option headers are network byte order. Keeping the test writer
  // explicit makes nested IA payloads pass through the production parser
  // instead of constructing decoded lease records behind the packet path.
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_dhcpv6_option(std::vector<std::uint8_t> &output,
                          router::packet::dhcpv6::OptionCode code,
                          std::span<const std::uint8_t> body) {
  if (body.size() > 0xffffU)
    throw std::runtime_error("DHCPv6 nested option fixture is too large");
  append_u16(output, static_cast<std::uint16_t>(code));
  append_u16(output, static_cast<std::uint16_t>(body.size()));
  output.insert(output.end(), body.begin(), body.end());
}

bool append_dhcpv6_association(router::packet::dhcpv6::Writer &message,
                               router::packet::dhcpv6::OptionCode code,
                               std::uint32_t iaid,
                               std::span<const std::uint8_t> nested = {}) {
  // IA_NA and IA_PD share the RFC 9915 IAID, T1 and T2 fixed header. This
  // helper is intentionally limited to those two codes so a future IA_TA
  // test cannot accidentally emit the wrong eight extra octets.
  if (code != router::packet::dhcpv6::OptionCode::ia_na &&
      code != router::packet::dhcpv6::OptionCode::ia_pd)
    return false;
  std::array<std::uint8_t, 512U> body{};
  const auto body_octets =
      router::packet::dhcpv6::encode_ia_na_or_pd(body, iaid, 30U, 50U, nested);
  return body_octets &&
         message.append(
             static_cast<std::uint16_t>(code),
             std::span<const std::uint8_t>{body}.first(*body_octets));
}

std::unique_ptr<router::lab::RouterForwarderCheckpoint>
snapshot(const router::lab::RouterForwarder &forwarder,
         router::lab::RouterForwarder::Clock::time_point now =
             router::lab::RouterForwarder::Clock::now()) {
  // Router checkpoints contain complete fixed-capacity FIB programs. Building
  // directly in heap-owned storage mirrors the runtime checkpoint arena and
  // prevents a test-only copy from consuming the bounded Wasm control stack.
  auto result = std::make_unique<router::lab::RouterForwarderCheckpoint>();
  forwarder.checkpoint(*result, now);
  return result;
}

} // namespace

void router_forwarder_local_ipv4_delivery_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;

  // This suite owns its forwarding object independently of the wider router
  // integration suite. Apart from making the behavioral boundary explicit,
  // that separation matters in WebAssembly: maximum-sized Frame fixtures are
  // short-lived packet buffers and must not inflate an unrelated test's single
  // control-stack frame for its entire two-thousand-line lifetime.
  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac router_mac{0x02, 0, 0, 0, 1, 1};
  const packet::Mac host_mac{0x02, 0, 0, 0, 0, 1};
  require(forwarder->configure_port({true, true, 0, 1514, 0x0a000001U,
                                     0x0a000000U, 10'000, 24, router_mac}),
          "local IPv4 suite could not configure its physical port");

  RouteTable rib;
  const std::array connected{ConnectedInput{true, true, 0x0a000000U, 0, 24},
                             ConnectedInput{.configured = true,
                                            .operational = true,
                                            .network = 0x0aff0001U,
                                            .prefix_length = 32U,
                                            .local_system = true}};
  require(rib.rebuild(connected, std::span<const StaticInput>{}) &&
              forwarder->program_fib(rib.compile(1U)),
          "local IPv4 suite could not program connected and system routes");

  std::vector<Emitted> emitted;
  // Learn the return adjacency from a real encoded ARP request. ICMP errors
  // below are therefore forced through the same FIB and ARP path as ordinary
  // router-originated traffic instead of using a test-only response shortcut.
  const auto reverse_arp =
      packet::arp_request(host_mac, {10, 0, 0, 2}, {10, 0, 0, 1});
  forwarder->receive(0U, reverse_arp, &emitted, collect);
  emitted.clear();

  // A router is a destination host for packets addressed to any of its own
  // interfaces. Deliver fragments out of order so parsing fragment zero as a
  // complete Echo Request cannot accidentally satisfy the test.
  const auto local_echo =
      packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1},
                        false, 43U, 64U, 200U);
  const auto fragments = packet::fragment_ipv4(local_echo, 100U);
  require(fragments && fragments->count == 3U,
          "local IPv4 reassembly fixture did not produce three fragments");
  const auto fragment_now = RouterForwarder::Clock::now();
  forwarder->receive(0U, fragments->frames[2], &emitted, collect, fragment_now);
  forwarder->receive(0U, fragments->frames[1], &emitted, collect, fragment_now);
  require(emitted.empty(),
          "incomplete local IPv4 fragments reached the ICMP dispatcher");
  forwarder->receive(0U, fragments->frames[0], &emitted, collect, fragment_now);
  const auto local_reply = emitted.empty()
                               ? std::optional<packet::IcmpView>{}
                               : packet::parse_icmp(emitted.back().frame);
  require(emitted.size() == 1U && emitted.back().port == 0U && local_reply &&
              local_reply->type == 0U && local_reply->sequence == 43U,
          "router-local IPv4 reassembly did not produce one Echo Reply");

  // Preserve an incomplete set through a checkpoint, then let the restored
  // owner expire it. Only fragment zero permits the mandatory code 1 report.
  emitted.clear();
  forwarder->receive(0U, fragments->frames[0], &emitted, collect, fragment_now);
  const auto checkpoint = snapshot(*forwarder, fragment_now);
  require(checkpoint->ipv4_reassembly.size() == 1U,
          "router checkpoint omitted local IPv4 reassembly state");
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, fragment_now),
          "router rejected valid IPv4 reassembly checkpoint state");
  restored->service_ipv4_maintenance(
      &emitted, collect,
      fragment_now + device_catalog::ipv4_reassembly_timeout);
  const auto reassembly_timeout =
      emitted.empty() ? std::optional<packet::IcmpView>{}
                      : packet::parse_icmp(emitted.back().frame);
  require(emitted.size() == 1U && reassembly_timeout &&
              reassembly_timeout->type == 11U && reassembly_timeout->code == 1U,
          "restored local IPv4 reassembly timeout omitted ICMP code 1");

  // Fragment zero is also sufficient to identify an invoking ICMP error. Its
  // checksum necessarily spans bytes that have not arrived, so the router must
  // inspect only the available type for the RFC 1812 recursion prohibition and
  // silently reclaim the timed-out entry rather than answer one error with
  // another error.
  emitted.clear();
  const auto invoking_error = packet::icmp_network_unreachable(
      local_echo, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1});
  const auto error_fragments = invoking_error
                                   ? packet::fragment_ipv4(*invoking_error, 44U)
                                   : std::nullopt;
  require(error_fragments && error_fragments->count > 1U,
          "ICMP error suppression fixture was not fragmented");
  const auto error_fragment_now = fragment_now +
                                  device_catalog::ipv4_reassembly_timeout +
                                  std::chrono::seconds{1};
  // Use the restored owner whose earlier incomplete set has already expired.
  // The original owner intentionally still contains the checkpoint source
  // set, which would independently and correctly emit its own timeout here.
  restored->receive(0U, error_fragments->frames[0], &emitted, collect,
                    error_fragment_now);
  restored->service_ipv4_maintenance(
      &emitted, collect,
      error_fragment_now + device_catalog::ipv4_reassembly_timeout);
  require(emitted.empty(),
          "IPv4 reassembly timeout replied to an invoking ICMP error");

  // UDP reaches the forwarding owner's real socket table. With no bound
  // destination port the router returns code 3. An unowned IP Protocol value
  // returns code 2. Both errors use the independently resolved reverse route.
  emitted.clear();
  std::array<std::uint8_t, 64U> udp_bytes{};
  constexpr std::array<std::uint8_t, 4U> udp_payload{1U, 2U, 3U, 4U};
  const auto udp_octets = packet::udp::encode_ipv4(
      udp_bytes, {10, 0, 0, 2}, {10, 0, 0, 1}, 40'000U, 53U, udp_payload);
  std::array<std::uint8_t, packet::maximum_frame_octets> storage{};
  const auto udp_frame_octets =
      udp_octets
          ? packet::encode_ipv4_ethernet_datagram(
                storage, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1},
                17U, 64U, 7U,
                std::span<const std::uint8_t>{udp_bytes}.first(*udp_octets),
                false)
          : std::nullopt;
  packet::Frame closed_udp_frame;
  if (udp_frame_octets) {
    std::copy_n(storage.begin(), *udp_frame_octets,
                closed_udp_frame.bytes.begin());
    closed_udp_frame.length = static_cast<std::uint16_t>(*udp_frame_octets);
  }
  forwarder->receive(0U, closed_udp_frame, &emitted, collect);
  const auto closed_port = emitted.empty()
                               ? std::optional<packet::IcmpView>{}
                               : packet::parse_icmp(emitted.back().frame);
  require(udp_frame_octets && emitted.size() == 1U && closed_port &&
              closed_port->type == 3U && closed_port->code == 3U,
          "router-local closed UDP port omitted ICMP code 3");

  // RFC 2644 disables receipt and forwarding of a subnet-directed broadcast
  // by default. It must not become a connected route that ARPs for .255, an
  // ICMP error, or an Echo response.
  emitted.clear();
  constexpr packet::Mac broadcast_mac{0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU};
  const auto broadcast_udp_octets = packet::encode_ipv4_ethernet_datagram(
      storage, host_mac, broadcast_mac, {10, 0, 0, 2}, {10, 0, 0, 255}, 17U,
      64U, 9U, std::span<const std::uint8_t>{udp_bytes}.first(*udp_octets),
      false);
  packet::Frame broadcast_udp;
  if (broadcast_udp_octets) {
    std::copy_n(storage.begin(), *broadcast_udp_octets,
                broadcast_udp.bytes.begin());
    broadcast_udp.length = static_cast<std::uint16_t>(*broadcast_udp_octets);
  }
  forwarder->receive(0U, broadcast_udp, &emitted, collect);
  const auto broadcast_echo =
      packet::icmp_echo(host_mac, broadcast_mac, {10, 0, 0, 2}, {10, 0, 0, 255},
                        false, 44U, 64U, 8U);
  forwarder->receive(0U, broadcast_echo, &emitted, collect);
  require(broadcast_udp_octets && emitted.empty(),
          "router forwarded or answered IPv4 subnet broadcast input");
  require(forwarder->last_drop() ==
              lab::ForwardDrop::directed_broadcast_disabled,
          "directed broadcast was misclassified as malformed input");

  emitted.clear();
  constexpr std::array<std::uint8_t, 8U> unknown_payload{};
  const auto unknown_octets = packet::encode_ipv4_ethernet_datagram(
      storage, host_mac, router_mac, {10, 0, 0, 2}, {10, 0, 0, 1}, 99U, 64U, 8U,
      unknown_payload, false);
  packet::Frame unknown_protocol;
  if (unknown_octets) {
    std::copy_n(storage.begin(), *unknown_octets,
                unknown_protocol.bytes.begin());
    unknown_protocol.length = static_cast<std::uint16_t>(*unknown_octets);
  }
  forwarder->receive(0U, unknown_protocol, &emitted, collect);
  const auto unsupported_protocol =
      emitted.empty() ? std::optional<packet::IcmpView>{}
                      : packet::parse_icmp(emitted.back().frame);
  require(unknown_octets && emitted.size() == 1U && unsupported_protocol &&
              unsupported_protocol->type == 3U &&
              unsupported_protocol->code == 2U,
          "router-local unknown IPv4 protocol omitted ICMP code 2");

  // Read counters only after exercising the actual packet path. This guards
  // against an attractive but incorrect implementation where show commands
  // synthesize plausible values independently of admitted wire traffic.
  const auto global_statistics = forwarder->icmpv4_global_statistics();
  const auto interface_statistics = forwarder->icmpv4_interface_statistics(0U);
  require(interface_statistics.has_value() &&
              global_statistics.received.total == 1U &&
              global_statistics.received.echo_request == 1U &&
              global_statistics.sent.total == 3U &&
              global_statistics.sent.echo_reply == 1U &&
              global_statistics.sent.destination_unreachable == 2U &&
              *interface_statistics == global_statistics,
          "local IPv4 wire traffic did not drive scoped ICMP counters");

  // The timeout was emitted by the independently restored owner. Its state
  // must contain the earlier Echo exchange from the checkpoint plus exactly
  // one code 1 Time Exceeded generated after restore.
  const auto restored_statistics = restored->icmpv4_global_statistics();
  require(restored_statistics.received.echo_request == 1U &&
              restored_statistics.sent.echo_reply == 1U &&
              restored_statistics.sent.time_exceeded == 1U &&
              restored_statistics.sent.total == 2U,
          "checkpointed ICMP counters or restored timeout accounting diverged");

  // Global, interface and all are separate operational scopes in SR OS. Clear
  // through the forwarding owner and prove that each operation leaves every
  // non-selected scope intact. An absent physical ordinal must be rejected.
  const auto before_global_clear = restored->icmpv4_interface_statistics(0U);
  restored->clear_icmpv4_global_statistics();
  require(restored->icmpv4_global_statistics() == Icmpv4Statistics{} &&
              restored->icmpv4_interface_statistics(0U) == before_global_clear,
          "global ICMP clear changed independent interface statistics");
  require(restored->clear_icmpv4_interface_statistics(0U) &&
              restored->icmpv4_interface_statistics(0U) == Icmpv4Statistics{} &&
              !restored->clear_icmpv4_interface_statistics(799U),
          "interface ICMP clear accepted an absent port or retained data");
  restored->clear_icmpv4_statistics_all();
  require(restored->icmpv4_global_statistics() == Icmpv4Statistics{} &&
              restored->icmpv4_interface_statistics(0U) == Icmpv4Statistics{},
          "all ICMP clear retained a counter scope");
}

void router_forwarder_ipv4_redirect_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;

  auto forwarder = std::make_unique<RouterForwarder>();
  constexpr packet::Mac router_mac{0x02U, 0U, 0U, 0U, 1U, 1U};
  constexpr packet::Mac host_mac{0x02U, 0U, 0U, 0U, 0U, 2U};
  constexpr packet::Mac gateway_mac{0x02U, 0U, 0U, 0U, 0U, 3U};
  ForwardPort port{.configured = true,
                   .operational = true,
                   .ordinal = 0U,
                   .mtu = 1514U,
                   .address = 0x0a000001U,
                   .network = 0x0a000000U,
                   .speed_mbps = 10'000U,
                   .prefix_length = 24U,
                   .mac = router_mac,
                   .icmp_redirect_maximum = 10U,
                   .icmp_redirect_interval_seconds = 1U};
  require(forwarder->configure_port(port),
          "IPv4 Redirect fixture rejected its interface policy");
  RouteTable rib;
  const std::array connected{ConnectedInput{true, true, 0x0a000000U, 0U, 24U}};
  const std::array statics{StaticInput{true, 0xc0000200U, 0x0a000003U, 24U}};
  require(rib.rebuild(connected, statics) &&
              forwarder->program_fib(rib.compile(1U)),
          "IPv4 Redirect fixture rejected connected and static routes");

  std::vector<Emitted> emitted;
  // Learn the better router from encoded ARP. The invoking datagram can then
  // be forwarded while the independent Redirect returns directly to the
  // source MAC observed on the ingress link.
  const auto gateway_arp =
      packet::arp_request(gateway_mac, {10, 0, 0, 3}, {10, 0, 0, 1});
  forwarder->receive(0U, gateway_arp, &emitted, collect);
  emitted.clear();
  const auto invoking = packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2},
                                          {192, 0, 2, 9}, false, 77U);
  const auto now = RouterForwarder::Clock::now();
  forwarder->receive(0U, invoking, &emitted, collect, now);
  const auto redirect =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        const auto icmp = packet::parse_icmp(candidate.frame);
        return icmp && icmp->type == 5U && icmp->code == 1U;
      });
  const auto redirect_ip = redirect == emitted.end()
                               ? std::optional<packet::Ipv4View>{}
                               : packet::parse_ipv4(redirect->frame);
  const auto redirect_ethernet = redirect == emitted.end()
                                     ? std::optional<packet::EthernetView>{}
                                     : packet::parse_ethernet(redirect->frame);
  require(redirect != emitted.end() && redirect_ip && redirect_ethernet &&
              redirect->port == 0U &&
              redirect_ip->source == packet::Ipv4{10, 0, 0, 1} &&
              redirect_ip->destination == packet::Ipv4{10, 0, 0, 2} &&
              redirect_ethernet->source == router_mac &&
              redirect_ethernet->destination == host_mac &&
              std::equal(redirect->frame.bytes.begin() + 38U,
                         redirect->frame.bytes.begin() + 42U,
                         packet::Ipv4{10, 0, 0, 3}.begin()),
          "IPv4 Host Redirect carried an incorrect gateway or return envelope");

  // The configured fixed window admits ten messages. Transit forwarding is
  // independent and therefore continues for the eleventh invoking packet.
  emitted.clear();
  for (std::uint16_t sequence = 0U; sequence < 11U; ++sequence) {
    const auto request = packet::icmp_echo(host_mac, router_mac, {10, 0, 0, 2},
                                           {192, 0, 2, 9}, false, sequence);
    forwarder->receive(0U, request, &emitted, collect,
                       now + std::chrono::milliseconds{10});
  }
  const auto redirects =
      std::count_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        const auto icmp = packet::parse_icmp(candidate.frame);
        return icmp && icmp->type == 5U;
      });
  require(redirects == 9U && emitted.size() == 20U,
          "IPv4 Redirect limiter altered transit or exceeded its window");

  const auto checkpoint =
      snapshot(*forwarder, now + std::chrono::milliseconds{10});
  require(checkpoint->ipv4_redirect_limiters.size() == 1U &&
              checkpoint->ipv4_redirect_limiters[0].sent == 10U,
          "IPv4 Redirect fixed window was absent from checkpoint state");
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, now + std::chrono::milliseconds{10}),
          "IPv4 Redirect fixed window did not restore");
  emitted.clear();
  restored->receive(0U, invoking, &emitted, collect,
                    now + std::chrono::milliseconds{20});
  require(std::none_of(emitted.begin(), emitted.end(),
                       [](const auto &candidate) {
                         const auto icmp = packet::parse_icmp(candidate.frame);
                         return icmp && icmp->type == 5U;
                       }) &&
              emitted.size() == 1U,
          "restored IPv4 Redirect limiter forgot its active allowance");

  port.icmp_redirects_enabled = false;
  require(restored->configure_port(port),
          "IPv4 Redirect disable policy was rejected");
  emitted.clear();
  restored->receive(0U, invoking, &emitted, collect,
                    now + std::chrono::seconds{2});
  require(emitted.size() == 1U,
          "disabled IPv4 Redirect policy changed ordinary forwarding");
}

void router_forwarder_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;
  {
    // Service attachment lifecycle is tested on an isolated owner so removing
    // a card port cannot perturb the routed-frame cases below. The physical
    // coordinate is deliberately different from the dense ordinal, proving
    // that user-visible SAP identity does not leak an arena index.
    // RouterForwarder owns bounded packet arenas that intentionally live on
    // the runtime heap. Keeping the test owner on the heap mirrors production
    // and avoids consuming the fixed WebAssembly control stack with arenas.
    auto service_forwarder = std::make_unique<RouterForwarder>();
    const packet::Mac service_mac{0x02, 0, 0, 0, 9, 1};
    require(service_forwarder->configure_port({true, true, 7, 1514, 0x0a070001U,
                                               0x0a070000U, 10'000, 24,
                                               service_mac}),
            "service forwarder rejected physical attachment port");
    const std::array published{service::SapAttachment{
        .logical_interface_id = 9001U,
        .sap = {.port = {.ordinal = 7U, .card = 3U, .mda = 2U, .port = 11U},
                .encapsulation = service::EthernetEncapsulation::qinq,
                .outer_vlan = std::uint16_t{101U},
                .inner_vlan = std::uint16_t{202U}},
        .outer_tpid = 0x88a8U,
        .inner_tpid = 0x8100U}};
    require(service_forwarder->program_sap_generation(published) ==
                service::SapProgramStatus::accepted,
            "forwarder rejected valid SAP generation");

    auto invalid = published;
    invalid[0].sap.port.ordinal = 6U;
    require(service_forwarder->program_sap_generation(invalid) ==
                    service::SapProgramStatus::invalid_attachment &&
                snapshot(*service_forwarder)->sap_attachments ==
                    std::vector<service::SapAttachment>{published.begin(),
                                                        published.end()},
            "invalid SAP generation changed the published classifier");

    // Checkpoint restore must rebuild both the wire-key and logical indexes.
    // A later physical removal then erases the restored attachment without a
    // fallible control-plane allocation in the noexcept hardware path.
    const auto service_checkpoint = snapshot(*service_forwarder);
    auto restored_service_forwarder = std::make_unique<RouterForwarder>();
    require(restored_service_forwarder->restore(*service_checkpoint) &&
                snapshot(*restored_service_forwarder)->sap_attachments ==
                    service_checkpoint->sap_attachments,
            "SAP generation did not survive forwarding checkpoint restore");
    restored_service_forwarder->remove_port(7U);
    require(snapshot(*restored_service_forwarder)->sap_attachments.empty(),
            "physical port removal retained a stale SAP attachment");
  }
  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac router_a{0x02, 0, 0, 0, 1, 1};
  const packet::Mac router_b{0x02, 0, 0, 0, 1, 2};
  const packet::Mac host_a{0x02, 0, 0, 0, 0, 1};
  const packet::Mac host_b{0x02, 0, 0, 0, 0, 2};
  const packet::Mac host_c{0x02, 0, 0, 0, 0, 3};
  ForwardPort first_port{true,        true,   0,  1514,    0x0a000001U,
                         0x0a000000U, 10'000, 24, router_a};
  ForwardPort second_port{true,        true,   1,  600,     0x0a000101U,
                          0x0a000100U, 10'000, 24, router_b};
  // Exercise configured values rather than merely repeating release defaults.
  // Zero aging must retain learned state indefinitely, while 25 deciseconds
  // must drive the actual encoded retry at 2.5 seconds.
  second_port.arp_timeout_seconds = 0U;
  second_port.arp_retry_deciseconds = 25U;
  require(forwarder->configure_port(first_port) &&
              forwarder->configure_port(second_port),
          "forwarder rejected valid routed ports");
  RouteTable rib;
  const std::array connected{ConnectedInput{true, true, 0x0a000000U, 0, 24},
                             ConnectedInput{true, true, 0x0a000100U, 1, 24}};
  require(rib.rebuild(connected, std::span<const StaticInput>{}) &&
              forwarder->program_fib(rib.compile(1)),
          "forwarder rejected connected FIB");

  std::vector<Emitted> emitted;
  const auto echo = packet::icmp_echo(host_a, router_a, {10, 0, 0, 2},
                                      {10, 0, 1, 2}, false, 1);
  const auto arp_start = RouterForwarder::Clock::now();
  forwarder->receive(0, echo, &emitted, collect, arp_start);
  require(emitted.size() == 1 && emitted[0].port == 1 &&
              packet::parse_arp(emitted[0].frame)->operation == 1 &&
              forwarder->pending_frames() == 1,
          "unresolved next hop did not emit one encoded ARP request");
  forwarder->service_ipv4_maintenance(&emitted, collect,
                                      arp_start +
                                          std::chrono::milliseconds{2500} -
                                          std::chrono::milliseconds{1});
  require(emitted.size() == 1U,
          "ARP retried before the configured default interval elapsed");

  // Link loss suppresses transmission, but it must not leave an overdue timer
  // that spins the forwarding worker. The unresolved packet remains owned by
  // the interface and resumes the same configured retry cadence when the link
  // becomes operational again.
  second_port.operational = false;
  require(forwarder->configure_port(second_port),
          "forwarder rejected an operational port-down transition");
  forwarder->service_ipv4_maintenance(
      &emitted, collect, arp_start + std::chrono::milliseconds{2500});
  const auto deferred_retry = forwarder->next_ipv4_deadline();
  require(emitted.size() == 1U && deferred_retry &&
              *deferred_retry == arp_start + std::chrono::milliseconds{5000},
          "down interface retained an overdue ARP retry deadline");
  second_port.operational = true;
  require(forwarder->configure_port(second_port),
          "forwarder rejected an operational port-up transition");
  forwarder->service_ipv4_maintenance(&emitted, collect,
                                      arp_start +
                                          std::chrono::milliseconds{5000} -
                                          std::chrono::milliseconds{1});
  require(emitted.size() == 1U,
          "deferred ARP retry ignored the configured interface timer");
  forwarder->service_ipv4_maintenance(
      &emitted, collect, arp_start + std::chrono::milliseconds{5000});
  require(emitted.size() == 2U && emitted.back().port == 1U &&
              packet::parse_arp(emitted.back().frame) &&
              packet::parse_arp(emitted.back().frame)->operation == 1U,
          "unresolved IPv4 next hop did not retry with an encoded ARP request");
  emitted.clear();

  const auto arp_reply =
      packet::arp_reply(host_b, {10, 0, 1, 2}, router_b, {10, 0, 1, 1});
  forwarder->receive(1, arp_reply, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 1 &&
              forwarder->pending_frames() == 0 && forwarder->arp_entries() == 1,
          "ARP reply did not release the pending transit frame");
  forwarder->service_ipv4_maintenance(
      &emitted, collect,
      RouterForwarder::Clock::time_point::max() - std::chrono::hours{1});
  require(forwarder->arp_entries() == 1U,
          "zero ARP timeout did not disable dynamic entry aging");
  const auto routed_ip = packet::parse_ipv4(emitted[0].frame);
  const auto routed_eth = packet::parse_ethernet(emitted[0].frame);
  require(routed_ip && routed_eth && routed_ip->ttl == 63 &&
              routed_eth->source == router_b &&
              routed_eth->destination == host_b,
          "transit hop did not rewrite Ethernet and decrement TTL once");

  // Learn the reverse source only through an ARP request received on port 0.
  const auto reverse_arp =
      packet::arp_request(host_a, {10, 0, 0, 2}, {10, 0, 0, 1});
  forwarder->receive(0, reverse_arp, &emitted, collect);

  // Program two equal static children and prove selection on encoded transit
  // frames, after both real ARP adjacencies have been learned. Varying only
  // the destination address exercises the default SR OS address hash inputs;
  // every packet of one source/destination flow must stay on one member.
  const std::array ecmp_statics{
      StaticInput{true, 0xcb007100U, 0x0a000002U, 24},
      StaticInput{true, 0xcb007100U, 0x0a000102U, 24}};
  require(rib.rebuild(connected, ecmp_statics, {}, 2U) &&
              forwarder->program_fib(rib.compile(2U)),
          "forwarder rejected a two-member static ECMP FIB");
  first_port.icmp_redirects_enabled = false;
  require(forwarder->configure_port(first_port),
          "ECMP fixture could not disable same-interface redirects");
  std::array<bool, 2U> selected_ports{};
  for (std::uint16_t host = 1U;
       host < 255U && !(selected_ports[0] && selected_ports[1]); ++host) {
    emitted.clear();
    const auto frame = packet::icmp_echo(
        host_a, router_a, {10, 0, 0, 2},
        {203, 0, 113, static_cast<std::uint8_t>(host)}, false, host);
    forwarder->receive(0U, frame, &emitted, collect);
    require(emitted.size() == 1U && emitted.front().port < 2U,
            "ECMP transit flow did not use a resolved member");
    selected_ports[emitted.front().port] = true;
  }
  require(selected_ports[0] && selected_ports[1],
          "address hashing did not distribute flows across ECMP members");

  const std::array with_system{ConnectedInput{true, true, 0x0a000000U, 0, 24},
                               ConnectedInput{true, true, 0x0a000100U, 1, 24},
                               ConnectedInput{.configured = true,
                                              .operational = true,
                                              .network = 0x0aff0001U,
                                              .prefix_length = 32U,
                                              .local_system = true}};
  require(rib.rebuild(with_system, std::span<const StaticInput>{}) &&
              forwarder->program_fib(rib.compile(3U)),
          "forwarder rejected system-interface local FIB route");
  emitted.clear();
  const auto system_echo = packet::icmp_echo(host_a, router_a, {10, 0, 0, 2},
                                             {10, 255, 0, 1}, false, 41U);
  forwarder->receive(0U, system_echo, &emitted, collect);
  const auto system_reply_ip = emitted.empty()
                                   ? std::optional<packet::Ipv4View>{}
                                   : packet::parse_ipv4(emitted.back().frame);
  require(emitted.size() == 1U && emitted.front().port == 0U &&
              system_reply_ip &&
              system_reply_ip->source == packet::Ipv4{10, 255, 0, 1} &&
              system_reply_ip->destination == packet::Ipv4{10, 0, 0, 2},
          "system-interface echo did not return through reverse FIB and ARP");

  emitted.clear();
  const auto global_before_local_system_ping =
      forwarder->icmpv4_global_statistics();
  const auto interface_before_local_system_ping =
      forwarder->icmpv4_interface_statistics(0U);
  require(forwarder->originate_echo(0x0aff0001U, 42U, &emitted, collect,
                                    RouterForwarder::Clock::now()) &&
              forwarder->received_echo_reply(42U) && emitted.empty(),
          "local ping to system interface used a fabricated wire path");
  const auto global_after_local_system_ping =
      forwarder->icmpv4_global_statistics();
  require(global_after_local_system_ping.sent.total ==
                  global_before_local_system_ping.sent.total + 1U &&
              global_after_local_system_ping.sent.echo_request ==
                  global_before_local_system_ping.sent.echo_request + 1U &&
              global_after_local_system_ping.received.total ==
                  global_before_local_system_ping.received.total + 1U &&
              global_after_local_system_ping.received.echo_reply ==
                  global_before_local_system_ping.received.echo_reply + 1U &&
              forwarder->icmpv4_interface_statistics(0U) ==
                  interface_before_local_system_ping,
          "local system ping did not update only the global ICMP scope");

  // Terminal polling is intentionally asynchronous, but RTT belongs to the
  // forwarding owner. A controlled two-millisecond wire exchange must retain
  // that duration instead of the later time at which management reads it.
  emitted.clear();
  const auto timed_ipv4_at = RouterForwarder::Clock::now();
  require(forwarder->originate_echo(0x0a000102U, 49U, &emitted, collect,
                                    timed_ipv4_at) &&
              emitted.size() == 1U,
          "timed IPv4 Echo probe was not emitted");
  const auto timed_ipv4_reply = packet::icmp_echo(
      host_b, router_b, {10U, 0U, 1U, 2U}, {10U, 0U, 1U, 1U}, true, 49U);
  forwarder->receive(1U, timed_ipv4_reply, &emitted, collect,
                     timed_ipv4_at + std::chrono::milliseconds{2});
  require((forwarder->echo_outcome(49U) & 0xffU) == 1U &&
              (forwarder->echo_outcome(49U) >> 8U) == 2'000'000U,
          "IPv4 Echo RTT included management polling delay");

  // A router-originated DF probe participates in RFC 1191 like host traffic.
  // The first report uses an unrelated quote and must be ignored. The second
  // quotes the exact emitted packet, lowers the per-interface path cache and
  // causes a same-size retry to fail locally without another wire frame.
  emitted.clear();
  const auto pmtu_now = RouterForwarder::Clock::now();
  require(forwarder->originate_echo(0x0a000102U, 50U, &emitted, collect,
                                    pmtu_now, 500U, true) &&
              emitted.size() == 1U && emitted.front().port == 1U,
          "router IPv4 DF probe did not use its routed egress");
  const auto unrelated_probe =
      packet::icmp_echo(router_b, host_b, {10U, 0U, 1U, 1U}, {10U, 0U, 1U, 2U},
                        false, 51U, 64U, 500U, true);
  const auto forged_pmtu = packet::icmp_fragmentation_needed(
      unrelated_probe, host_b, router_b, {10U, 0U, 1U, 2U}, {10U, 0U, 1U, 1U},
      400U);
  require(forged_pmtu.has_value(),
          "router forged PMTU fixture could not be encoded");
  forwarder->receive(1U, *forged_pmtu, &emitted, collect,
                     pmtu_now + std::chrono::seconds{1});
  require(snapshot(*forwarder, pmtu_now + std::chrono::seconds{1})
              ->ipv4_path_mtu.empty(),
          "router accepted an unrelated IPv4 PMTU quotation");
  const auto valid_pmtu = packet::icmp_fragmentation_needed(
      emitted.front().frame, host_b, router_b, {10U, 0U, 1U, 2U},
      {10U, 0U, 1U, 1U}, 400U);
  require(valid_pmtu.has_value(),
          "router valid PMTU fixture could not be encoded");
  forwarder->receive(1U, *valid_pmtu, &emitted, collect,
                     pmtu_now + std::chrono::seconds{2});
  const auto ipv4_pmtu_checkpoint =
      snapshot(*forwarder, pmtu_now + std::chrono::seconds{2});
  require(ipv4_pmtu_checkpoint->ipv4_path_mtu.size() == 1U &&
              ipv4_pmtu_checkpoint->ipv4_path_mtu.front().mtu == 400U,
          "router did not retain a validated IPv4 PMTU report");
  const auto frame_count_before_known_oversize = emitted.size();
  require(!forwarder->originate_echo(0x0a000102U, 52U, &emitted, collect,
                                     pmtu_now + std::chrono::seconds{3}, 500U,
                                     true) &&
              emitted.size() == frame_count_before_known_oversize,
          "router emitted a DF packet already known to exceed PMTU");
  emitted.clear();
  auto ttl_one = echo;
  // Mutate TTL and its header checksum to create a valid received datagram.
  ttl_one.bytes[22] = 1;
  ttl_one.bytes[24] = 0;
  ttl_one.bytes[25] = 0;
  const auto header_checksum = packet::checksum(ttl_one.view().subspan(14, 20));
  ttl_one.bytes[24] = static_cast<std::uint8_t>(header_checksum >> 8);
  ttl_one.bytes[25] = static_cast<std::uint8_t>(header_checksum);
  forwarder->receive(0, ttl_one, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "TTL expiry did not return an encoded frame on the reverse route");
  const auto error_ip = packet::parse_ipv4(emitted[0].frame);
  const auto error_icmp = packet::parse_icmp(emitted[0].frame);
  require(error_ip && error_icmp &&
              error_ip->source == packet::Ipv4{10, 0, 0, 1} &&
              error_ip->destination == packet::Ipv4{10, 0, 0, 2} &&
              error_icmp->type == 11 && error_icmp->code == 0,
          "TTL expiry did not produce a valid ICMP Time Exceeded message");

  emitted.clear();
  const auto unrouted = packet::icmp_echo(host_a, router_a, {10, 0, 0, 2},
                                          {203, 0, 113, 7}, false, 9U);
  forwarder->receive(0U, unrouted, &emitted, collect);
  const auto unreachable = emitted.empty()
                               ? std::optional<packet::IcmpView>{}
                               : packet::parse_icmp(emitted.front().frame);
  require(emitted.size() == 1U && emitted.front().port == 0U && unreachable &&
              unreachable->type == 3U && unreachable->code == 0U,
          "missing IPv4 route did not return ICMP network unreachable");

  emitted.clear();
  const auto fragmentable =
      packet::icmp_echo(host_a, router_a, {10, 0, 0, 2}, {10, 0, 1, 2}, false,
                        2, 64, 1000, false);
  forwarder->receive(0, fragmentable, &emitted, collect);
  require(emitted.size() == 2 && emitted[0].port == 1 && emitted[1].port == 1,
          "oversized non-DF datagram did not emit every IPv4 fragment");
  const auto first_fragment = packet::parse_ipv4(emitted[0].frame);
  const auto final_fragment = packet::parse_ipv4(emitted[1].frame);
  require(first_fragment && final_fragment && first_fragment->more_fragments &&
              !final_fragment->more_fragments &&
              final_fragment->fragment_offset != 0U,
          "forwarded fragments carry invalid IPv4 offset or MF fields");

  emitted.clear();
  const auto oversized = packet::icmp_echo(
      host_a, router_a, {10, 0, 0, 2}, {10, 0, 1, 2}, false, 2, 64, 1000, true);
  forwarder->receive(0, oversized, &emitted, collect);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "DF packet above egress MTU did not return an ICMP error");
  const auto mtu_error = packet::parse_icmp(emitted[0].frame);
  require(mtu_error && mtu_error->type == 3 && mtu_error->code == 4,
          "DF packet did not produce ICMP Fragmentation Needed");

  emitted.clear();
  auto nested_error = *packet::icmp_time_exceeded(echo, host_a, router_a,
                                                  {10, 0, 0, 2}, {10, 0, 1, 2});
  nested_error.bytes[22] = 1;
  nested_error.bytes[24] = 0;
  nested_error.bytes[25] = 0;
  const auto nested_checksum =
      packet::checksum(nested_error.view().subspan(14, 20));
  nested_error.bytes[24] = static_cast<std::uint8_t>(nested_checksum >> 8);
  nested_error.bytes[25] = static_cast<std::uint8_t>(nested_checksum);
  forwarder->receive(0, nested_error, &emitted, collect);
  require(emitted.empty(),
          "router generated an ICMP error in response to an ICMP error");

  // A configured mapping replaces learned state for the same key, rejects an
  // off-link key and cannot be overwritten by a later encoded ARP sender. This
  // exercises the management/data-plane ownership boundary without bypassing
  // the normal Ethernet egress path.
  const packet::Mac static_mac{0x02, 0x44, 0x55, 0x66, 0x77, 0x88};
  const packet::Mac conflicting_mac{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  require(
      forwarder->install_static_ipv4_neighbor(1U, 0x0a000163U, static_mac) &&
          !forwarder->install_static_ipv4_neighbor(1U, 0x0a000263U, static_mac),
      "static ARP accepted an off-link key or rejected an on-link key");
  const auto conflicting_arp = packet::arp_reply(
      conflicting_mac, {10, 0, 1, 99}, router_b, {10, 0, 1, 1});
  forwarder->receive(1U, conflicting_arp, &emitted, collect);
  auto static_snapshot = snapshot(*forwarder, RouterForwarder::Clock::now());
  const auto configured = std::find_if(
      static_snapshot->adjacencies.begin(), static_snapshot->adjacencies.end(),
      [](const auto &entry) {
        return entry.port_ordinal == 1U && entry.address == 0x0a000163U;
      });
  require(configured != static_snapshot->adjacencies.end() &&
              configured->configured_static && configured->aging_disabled &&
              configured->mac == static_mac,
          "dynamic ARP overwrote administrator-owned static adjacency");

  // Operational ARP clearing is executed on the forwarding owner. Exact
  // address and interface selectors remove only matching dynamic entries,
  // while a selector for a non-IPv4 port is rejected instead of acknowledged
  // as an inert success.
  require(
      forwarder->arp_entries() == 3U &&
          forwarder->clear_dynamic_ipv4_neighbors(std::nullopt, 0x0a000102U) &&
          forwarder->arp_entries() == 2U &&
          forwarder->clear_dynamic_ipv4_neighbors(0U, std::nullopt) &&
          forwarder->arp_entries() == 1U &&
          !forwarder->clear_dynamic_ipv4_neighbors(2U, std::nullopt),
      "dynamic ARP clear ignored its address or interface selector");

  const auto checkpoint_now = RouterForwarder::Clock::now();
  // Checkpoint images are cold-path heap values. Keeping three complete FIB
  // images on the deliberately small Wasm test stack would test stack size,
  // not restore semantics used by the heap-owned runtime supervisor.
  auto checkpoint = snapshot(*forwarder, checkpoint_now);
  auto restored = std::make_unique<RouterForwarder>();
  require(restored->restore(*checkpoint, checkpoint_now) &&
              restored->arp_entries() == forwarder->arp_entries() &&
              restored->forwarded_frames() == forwarder->forwarded_frames() &&
              restored->dropped_frames() == forwarder->dropped_frames(),
          "forwarder checkpoint did not restore owner-local state");
  require(restored->remove_static_ipv4_neighbor(1U, 0x0a000163U) &&
              restored->arp_entries() == 0U,
          "restored static ARP provenance did not support exact removal");
  auto invalid = std::make_unique<RouterForwarderCheckpoint>(*checkpoint);
  invalid->ports.front().ordinal =
      static_cast<std::uint16_t>(device_catalog::maximum_ports_per_router);
  const auto forwarded_before_invalid = restored->forwarded_frames();
  require(!restored->restore(*invalid, checkpoint_now) &&
              restored->forwarded_frames() == forwarded_before_invalid,
          "invalid forwarder checkpoint partially changed live state");

  // The IPv6 forwarding path uses an independent FIB and ND cache while
  // sharing physical ports and the bounded unresolved-frame arena with IPv4.
  auto forwarder6 = std::make_unique<RouterForwarder>();
  const auto address6 = [](const char *text) {
    const auto parsed = router::ip::parse_ipv6(text);
    if (!parsed)
      throw std::runtime_error("IPv6 forwarder test address is invalid");
    return *parsed;
  };
  {
    // A service interface is an independent RFC 4007 zone even though its
    // packets ultimately use one physical port. Exercise the complete wire
    // boundary here: ingress starts as an encoded dot1q frame, routing and ND
    // operate on the stripped internal frame, and egress restores the exact
    // configured TPID and VID. No decoded neighbor or topology object is
    // inserted by the test.
    auto service_ipv6 = std::make_unique<RouterForwarder>();
    constexpr std::uint64_t service_interface_id = 70'001U;
    constexpr std::uint16_t service_port_ordinal = 7U;
    constexpr std::uint16_t service_vlan = 701U;
    const packet::Mac service_router_mac{0x02U, 0U, 0U, 0U, 0x70U, 1U};
    const packet::Mac service_host_mac{0x02U, 0U, 0U, 0U, 0x70U, 2U};
    const auto service_router_address = address6("2001:db8:70::1");
    const auto service_host_address = address6("2001:db8:70::2");
    const auto service_link_local = address6("fe80::7001");
    const auto service_host_link_local = address6("fe80::7002");
    const ForwardPort service_physical{
        .configured = true,
        .operational = true,
        .ordinal = service_port_ordinal,
        // ForwardPort retains the full Ethernet frame allowance. The service
        // projection below owns the independent 1500-octet IPv6 link MTU.
        .mtu = 1518U,
        .speed_mbps = 10'000U,
        .mac = service_router_mac};
    require(service_ipv6->configure_port(service_physical),
            "service IPv6 fixture rejected its physical access port");
    const service::PhysicalPortCoordinate service_coordinate{
        .ordinal = service_port_ordinal, .card = 1U, .mda = 1U, .port = 8U};
    const std::array service_attachments{service::SapAttachment{
        .logical_interface_id = service_interface_id,
        .sap = {.port = service_coordinate,
                .encapsulation = service::EthernetEncapsulation::dot1q,
                .outer_vlan = service_vlan},
        .outer_tpid = packet::ethernet_type_customer_vlan}};
    const std::array service_interfaces{service::ServiceIpv6Interface{
        .interface_id = service_interface_id,
        .physical_port_ordinal = service_port_ordinal,
        .mtu = 1500U,
        .mac = service_router_mac,
        .address = service_router_address,
        .network = address6("2001:db8:70::"),
        .link_local = service_link_local,
        .prefix_length = 64U,
        .nd_reachable_time_milliseconds = 30'000U,
        .nd_stale_time_seconds = 14'400U,
        .neighbor_limit_threshold_percent = 90U,
        .redirect_maximum = 10U,
        .redirect_interval_seconds = 1U,
        .redirects_enabled = true,
        .configured = true,
        .operational = true}};
    require(service_ipv6->program_sap_generation(service_attachments,
                                                 service_interfaces) ==
                service::SapProgramStatus::accepted,
            "forwarder rejected the complete service IPv6 generation");
    Ipv6RouteTable service_rib;
    const std::array service_connected{
        Ipv6ConnectedInput{.configured = true,
                           .operational = true,
                           .network = address6("2001:db8:70::"),
                           .interface_id = service_interface_id,
                           .physical_port_ordinal = service_port_ordinal,
                           .prefix_length = 64U}};
    require(service_rib.rebuild(service_connected,
                                std::span<const Ipv6StaticInput>{}) &&
                service_ipv6->program_ipv6_fib(service_rib.compile(1U)),
            "forwarder rejected the service connected IPv6 route");

    std::vector<Emitted> service_emitted;
    for (std::size_t turn = 1U; turn <= 5U; ++turn)
      service_ipv6->service_ipv6_maintenance(&service_emitted, collect,
                                             checkpoint_now +
                                                 std::chrono::seconds{turn});
    service_emitted.clear();

    auto tagged_ns = packet::nd::neighbor_solicitation(
        service_host_mac, service_host_link_local, service_router_address);
    const std::array service_tag{packet::EthernetView::VlanTag{
        .tpid = packet::ethernet_type_customer_vlan,
        .vlan_identifier = service_vlan}};
    require(packet::insert_vlan_tags(tagged_ns, service_tag),
            "service NS fixture could not add its dot1q envelope");
    service_ipv6->receive(service_port_ordinal, tagged_ns, &service_emitted,
                          collect, checkpoint_now + std::chrono::seconds{6});
    require(service_emitted.size() == 1U,
            "tagged service NS did not produce one Neighbor Advertisement");
    const auto service_na_ethernet =
        packet::parse_ethernet(service_emitted.front().frame);
    require(
        service_emitted.front().port == service_port_ordinal &&
            service_na_ethernet && service_na_ethernet->vlan_tag_count == 1U &&
            service_na_ethernet->vlan_tags[0].tpid ==
                packet::ethernet_type_customer_vlan &&
            service_na_ethernet->vlan_tags[0].vlan_identifier == service_vlan,
        "service Neighbor Advertisement lost its configured SAP envelope");

    // A frame for another VID reaches the same physical port but must not
    // enter the native L3 path or learn a neighbor in the service zone.
    auto unknown_vlan_ns = tagged_ns;
    unknown_vlan_ns.bytes[15] = static_cast<std::uint8_t>(service_vlan + 1U);
    service_emitted.clear();
    service_ipv6->receive(service_port_ordinal, unknown_vlan_ns,
                          &service_emitted, collect,
                          checkpoint_now + std::chrono::seconds{7});
    require(service_emitted.empty(),
            "unknown service VLAN escaped the exact SAP classifier");

    // Restore while the service address is preferred and its neighbor is
    // learned. An Echo Request after restore proves that SAP indexes, DAD,
    // Neighbor Cache and logical FIB scope survive as one observable state.
    const auto service_state =
        snapshot(*service_ipv6, checkpoint_now + std::chrono::seconds{7});
    auto restored_service_ipv6 = std::make_unique<RouterForwarder>();
    require(restored_service_ipv6->restore(
                *service_state, checkpoint_now + std::chrono::seconds{7}),
            "active service IPv6 state was not restorable");
    auto tagged_echo = packet::icmpv6_echo(service_host_mac, service_router_mac,
                                           service_host_address,
                                           service_router_address, false, 701U);
    require(packet::insert_vlan_tags(tagged_echo, service_tag),
            "service Echo fixture could not add its dot1q envelope");
    service_emitted.clear();
    restored_service_ipv6->receive(service_port_ordinal, tagged_echo,
                                   &service_emitted, collect,
                                   checkpoint_now + std::chrono::seconds{8});
    const auto restored_echo_ethernet =
        service_emitted.empty()
            ? std::optional<packet::EthernetView>{}
            : packet::parse_ethernet(service_emitted.front().frame);
    require(service_emitted.size() == 1U && restored_echo_ethernet &&
                restored_echo_ethernet->vlan_tag_count == 1U &&
                restored_echo_ethernet->vlan_tags[0].vlan_identifier ==
                    service_vlan,
            "restored service interface did not return tagged ICMPv6");
  }
  ForwardPort port6_a{.configured = true,
                      .operational = true,
                      .ordinal = 0,
                      .mtu = 1514,
                      .speed_mbps = 10'000,
                      .mac = router_a,
                      .ipv6_configured = true,
                      .ipv6_address = address6("2001:db8:10::1"),
                      .ipv6_link_local = address6("fe80::1"),
                      .ipv6_prefix_length = 64,
                      .icmp6_redirect_maximum = 10U,
                      .icmp6_redirect_interval_seconds = 1U};
  ForwardPort port6_b{.configured = true,
                      .operational = true,
                      .ordinal = 1,
                      .mtu = 1314,
                      .speed_mbps = 10'000,
                      .mac = router_b,
                      .ipv6_configured = true,
                      .ipv6_address = address6("2001:db8:11::1"),
                      .ipv6_link_local = address6("fe80::1"),
                      .ipv6_prefix_length = 64};

  // ReachableTime belongs to an interface and is uniformly sampled from the
  // RFC 4861 0.5 through 1.5 BaseReachableTime interval. A restored owner must
  // continue the same PRNG stream rather than synchronizing to a fixed value.
  auto reachable_owner = std::make_unique<RouterForwarder>();
  require(reachable_owner->configure_port(port6_a),
          "reachable-time fixture rejected IPv6 interface");
  const auto reachable_checkpoint = snapshot(*reachable_owner, checkpoint_now);
  require(reachable_checkpoint->ipv6_reachable_times.size() == 1U &&
              reachable_checkpoint->ipv6_reachable_times[0]
                      .effective_milliseconds >=
                  port6_a.nd_reachable_time_milliseconds / 2U &&
              reachable_checkpoint->ipv6_reachable_times[0]
                      .effective_milliseconds <=
                  port6_a.nd_reachable_time_milliseconds +
                      port6_a.nd_reachable_time_milliseconds / 2U,
          "ReachableTime sample violated the RFC 4861 random interval");
  auto reachable_restored = std::make_unique<RouterForwarder>();
  require(reachable_restored->restore(*reachable_checkpoint, checkpoint_now),
          "ReachableTime checkpoint was not restorable");
  std::vector<Emitted> reachable_emitted;
  const auto refresh_time = checkpoint_now +
                            device_catalog::nd_reachable_time_recalculation +
                            std::chrono::seconds{1};
  reachable_owner->service_ipv6_maintenance(&reachable_emitted, collect,
                                            refresh_time);
  reachable_emitted.clear();
  reachable_restored->service_ipv6_maintenance(&reachable_emitted, collect,
                                               refresh_time);
  const auto reachable_after = snapshot(*reachable_owner, refresh_time);
  const auto restored_after = snapshot(*reachable_restored, refresh_time);
  require(
      reachable_after->ipv6_reachable_times[0].random_state !=
              reachable_checkpoint->ipv6_reachable_times[0].random_state &&
          reachable_after->ipv6_reachable_times[0].random_state ==
              restored_after->ipv6_reachable_times[0].random_state &&
          reachable_after->ipv6_reachable_times[0].effective_milliseconds ==
              restored_after->ipv6_reachable_times[0].effective_milliseconds,
      "ReachableTime refresh or checkpoint PRNG continuation diverged");
  require(forwarder6->configure_port(port6_a) &&
              forwarder6->configure_port(port6_b),
          "forwarder rejected valid dual-stack port projection");
  const auto secondary6 = address6("2001:db8:12::1");
  const std::array native_addresses{
      RouterIpv6Address{.address = port6_a.ipv6_address,
                        .network = address6("2001:db8:10::"),
                        .interface_id = physical_interface_id(0U),
                        .primary_preference = 10U,
                        .port_ordinal = 0U,
                        .prefix_length = 64U},
      RouterIpv6Address{.address = secondary6,
                        .network = address6("2001:db8:12::"),
                        .interface_id = physical_interface_id(0U),
                        .primary_preference = 20U,
                        .port_ordinal = 0U,
                        .prefix_length = 64U},
      RouterIpv6Address{.address = port6_b.ipv6_address,
                        .network = address6("2001:db8:11::"),
                        .interface_id = physical_interface_id(1U),
                        .primary_preference = 10U,
                        .port_ordinal = 1U,
                        .prefix_length = 64U}};
  require(
      forwarder6->program_ipv6_addresses(native_addresses, checkpoint_now) ==
          RouterIpv6AddressProgramStatus::accepted,
      "forwarder rejected a complete multi-address generation");
  Ipv6RouteTable rib6;
  const std::array connected6{
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = address6("2001:db8:10::"),
                         .interface_id = physical_interface_id(0U),
                         .physical_port_ordinal = 0,
                         .prefix_length = 64},
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = address6("2001:db8:11::"),
                         .interface_id = physical_interface_id(1U),
                         .physical_port_ordinal = 1,
                         .prefix_length = 64},
      Ipv6ConnectedInput{.configured = true,
                         .operational = true,
                         .network = address6("2001:db8:12::"),
                         .interface_id = physical_interface_id(0U),
                         .physical_port_ordinal = 0,
                         .prefix_length = 64}};
  require(rib6.rebuild(connected6, std::span<const Ipv6StaticInput>{}) &&
              forwarder6->program_ipv6_fib(rib6.compile(1)),
          "forwarder rejected connected IPv6 FIB");

  // Static addresses remain tentative until link-local DAD and then global
  // DAD each send NS and wait one complete RetransTimer interval. Advancing
  // explicit test instants exercises local deadlines without sleeping.
  for (std::size_t turn = 1; turn <= 5; ++turn)
    forwarder6->service_ipv6_maintenance(
        &emitted, collect, checkpoint_now + std::chrono::seconds{turn});
  require(forwarder6->ipv6_address_state(0, port6_a.ipv6_address) &&
              forwarder6->ipv6_address_state(0, port6_a.ipv6_address)->state ==
                  Ipv6DadState::preferred &&
              forwarder6->ipv6_address_state(1, port6_b.ipv6_address) &&
              forwarder6->ipv6_address_state(1, port6_b.ipv6_address)->state ==
                  Ipv6DadState::preferred &&
              forwarder6->ipv6_address_state(0, secondary6) &&
              forwarder6->ipv6_address_state(0, secondary6)->state ==
                  Ipv6DadState::preferred,
          "forwarder used IPv6 addresses before successful DAD");

  // A router owns every preferred unicast address configured on it, including
  // secondary addresses. RFC 4291 local delivery must not emit Ethernet or
  // perform ND, and RFC 4293 accounts the request and reply only at the global
  // ICMPv6 scope because no physical interface carried either message.
  emitted.clear();
  const auto global_before_local_ipv6_ping =
      forwarder6->icmpv6_global_statistics();
  const auto interface_before_local_ipv6_ping =
      forwarder6->icmpv6_interface_statistics(0U);
  require(forwarder6->originate_ipv6_echo(
              secondary6, 38U, &emitted, collect,
              checkpoint_now + std::chrono::seconds{5}) &&
              forwarder6->received_ipv6_echo_reply(38U) &&
              (forwarder6->ipv6_echo_outcome(38U) & 0xffU) == 1U &&
              (forwarder6->ipv6_echo_outcome(38U) >> 8U) == 0U &&
              emitted.empty(),
          "local IPv6 ping used a fabricated wire path or nonzero RTT");
  const auto global_after_local_ipv6_ping =
      forwarder6->icmpv6_global_statistics();
  require(global_after_local_ipv6_ping.sent.total ==
                  global_before_local_ipv6_ping.sent.total + 1U &&
              global_after_local_ipv6_ping.sent.echo_request ==
                  global_before_local_ipv6_ping.sent.echo_request + 1U &&
              global_after_local_ipv6_ping.received.total ==
                  global_before_local_ipv6_ping.received.total + 1U &&
              global_after_local_ipv6_ping.received.echo_reply ==
                  global_before_local_ipv6_ping.received.echo_reply + 1U &&
              forwarder6->icmpv6_interface_statistics(0U) ==
                  interface_before_local_ipv6_ping,
          "local IPv6 ping did not update only global ICMPv6 counters");

  // Secondary addresses own their solicited-node multicast groups and answer
  // Neighbor Solicitation exactly like the selected primary. This wire-level
  // assertion prevents a multi-address CLI list from becoming presentation-
  // only state that the forwarding plane cannot actually terminate.
  emitted.clear();
  const auto secondary_ns = packet::nd::neighbor_solicitation(
      host_a, address6("2001:db8:12::2"), secondary6);
  forwarder6->receive(0U, secondary_ns, &emitted, collect,
                      checkpoint_now + std::chrono::seconds{6});
  require(
      emitted.size() == 1U &&
          packet::nd::parse_neighbor_advertisement(emitted[0].frame),
      "secondary IPv6 address did not answer encoded Neighbor Solicitation");

  // Router Alert checking is not merely a CLI presentation value. Feed the
  // same checksum-valid encoded MLDv2 Report through the ingress packet path
  // before and after changing the per-interface compatibility control. The
  // default must reject it, while the explicit disabled setting may admit it
  // without bypassing Ethernet, IPv6 or ICMPv6 validation.
  const auto mld_now = checkpoint_now + std::chrono::seconds{5};
  MldRouterConfiguration mld_config{.link_local_address =
                                        port6_a.ipv6_link_local,
                                    .port_ordinal = 0U,
                                    .router_alert_check = true,
                                    .enabled = true};
  require(forwarder6->configure_mld_interface(mld_config, mld_now),
          "forwarder rejected a valid MLD interface projection");
  const auto mld_group = address6("ff3e::1234");
  const std::array mld_records{packet::mld::ReportRecord{
      .type = packet::mld::RecordType::change_to_exclude,
      .multicast_address = mld_group,
      .sources = {}}};
  auto report_without_valid_alert =
      packet::mld::version_two_report(host_a, address6("fe80::2"), mld_records);
  require(report_without_valid_alert.has_value(),
          "MLD Router Alert packet fixture could not be encoded");
  constexpr std::size_t router_alert_value_offset =
      packet::ethernet_header_octets + packet::ipv6_header_octets + 4U;
  report_without_valid_alert->bytes[router_alert_value_offset + 1U] = 1U;
  forwarder6->receive(0U, *report_without_valid_alert, &emitted, collect,
                      mld_now);
  require(forwarder6->mld_group_count(0U) == 0U,
          "default MLD interface admitted a nonzero Router Alert value");
  const auto rejected_mld_checkpoint = snapshot(*forwarder6, mld_now);
  require(rejected_mld_checkpoint->mld_interfaces.size() == 1U &&
              rejected_mld_checkpoint->mld_interfaces[0]
                      .protocol.statistics.no_router_alert == 1U,
          "forwarder did not classify a rejected MLD Router Alert");
  mld_config.router_alert_check = false;
  require(forwarder6->configure_mld_interface(mld_config, mld_now),
          "forwarder rejected disabled MLD Router Alert checking");
  forwarder6->receive(0U, *report_without_valid_alert, &emitted, collect,
                      mld_now);
  require(forwarder6->mld_group_count(0U) == 1U,
          "disabled Router Alert check did not affect the real MLD packet "
          "path");
  const auto accepted_mld_checkpoint = snapshot(*forwarder6, mld_now);
  require(accepted_mld_checkpoint->mld_interfaces[0]
                      .protocol.statistics.reports_v2_received == 1U &&
              accepted_mld_checkpoint->mld_interfaces[0]
                      .protocol.statistics.no_router_alert == 1U,
          "MLD statistics did not separate accepted and rejected reports");
  require(forwarder6->clear_mld_statistics(0U),
          "forwarder rejected an interface MLD statistics clear");
  const auto cleared_mld_checkpoint = snapshot(*forwarder6, mld_now);
  require(cleared_mld_checkpoint->mld_interfaces[0]
                      .protocol.statistics.reports_v2_received == 0U &&
              forwarder6->mld_group_count(0U) == 1U,
          "MLD statistics clear retained counters or erased listener state");

  // Program an SSM range through the same begin/add/commit transaction used
  // by the control shard. A real encoded MLDv1 (*,G) Report must become
  // INCLUDE(S,G), proving that translation is in the ingress packet path and
  // is not a CLI-only projection or a direct call between devices.
  const MldSsmTranslation ssm{.start = address6("ff3e::2000"),
                              .end = address6("ff3e::20ff"),
                              .source = address6("2001:db8:10::200")};
  require(forwarder6->program_mld_ssm_translation(
              0U, MldSsmProgramOperation::begin, {}, 1U) &&
              forwarder6->program_mld_ssm_translation(
                  0U, MldSsmProgramOperation::add, ssm) &&
              forwarder6->program_mld_ssm_translation(
                  0U, MldSsmProgramOperation::commit),
          "forwarder rejected an atomic SSM translation program");
  const auto translated_group = address6("ff3e::2001");
  const auto version_one = packet::mld::version_one_message(
      host_a, address6("fe80::2"), packet::mld::version_one_report_type,
      translated_group);
  require(version_one.has_value(), "MLDv1 SSM fixture could not be encoded");
  forwarder6->receive(0U, *version_one, &emitted, collect, mld_now);
  const auto translated_checkpoint = snapshot(*forwarder6, mld_now);
  const auto translated_interface = std::find_if(
      translated_checkpoint->mld_interfaces.begin(),
      translated_checkpoint->mld_interfaces.end(),
      [](const auto &entry) { return entry.intent.port_ordinal == 0U; });
  require(translated_interface != translated_checkpoint->mld_interfaces.end() &&
              translated_interface->ssm_translations.size() == 1U &&
              translated_interface->protocol.groups.size() == 2U,
          "forwarder checkpoint omitted committed SSM state");
  const auto translated_state = std::find_if(
      translated_interface->protocol.groups.begin(),
      translated_interface->protocol.groups.end(), [&](const auto &entry) {
        return entry.multicast_address == translated_group;
      });
  require(translated_state != translated_interface->protocol.groups.end() &&
              translated_state->mode == MldFilterMode::include &&
              translated_state->sources.size() == 1U &&
              translated_state->sources[0].address == ssm.source,
          "MLDv1 Report did not become the configured SSM source state");

  // An uncommitted generation must never leak into packet processing. Abort
  // the replacement and confirm that the checkpoint still exposes the old
  // committed tuple.
  const MldSsmTranslation replacement{.start = ssm.start,
                                      .end = ssm.end,
                                      .source = address6("2001:db8:10::201")};
  require(forwarder6->program_mld_ssm_translation(
              0U, MldSsmProgramOperation::begin, {}, 1U) &&
              forwarder6->program_mld_ssm_translation(
                  0U, MldSsmProgramOperation::add, replacement) &&
              forwarder6->program_mld_ssm_translation(
                  0U, MldSsmProgramOperation::abort),
          "forwarder could not abort staged SSM replacement");
  const auto after_abort = snapshot(*forwarder6, mld_now);
  require(after_abort->mld_interfaces[0].ssm_translations.size() == 1U &&
              after_abort->mld_interfaces[0].ssm_translations[0] == ssm,
          "aborted SSM staging replaced committed forwarding state");

  // Import policy executes on decoded wire reports before the listener DB is
  // touched. Reject one source from a two-source MLDv2 record and verify that
  // only the accepted tuple survives. This also proves checkpoint persistence
  // of the active compiled policy rather than a presentation-only CLI value.
  const auto policy_group = address6("ff3e::3001");
  const auto denied_source = address6("2001:db8:10::301");
  const auto allowed_source = address6("2001:db8:10::302");
  const std::array policy_entries{
      mld::ImportPolicyEntry{
          .number = 10U,
          .term = 0U,
          .group = ip::Ipv6Prefix{.network = address6("ff3e::3000"),
                                 .length = 120U},
          .source = ip::Ipv6Prefix{.network = denied_source, .length = 128U},
          .action = mld::ImportPolicyAction::reject,
          .protocol_mld = true},
      mld::ImportPolicyEntry{
          .number = 20U,
          .term = 0U,
          .group = ip::Ipv6Prefix{.network = address6("ff3e::3000"),
                                 .length = 120U},
          .source = std::nullopt,
          .action = mld::ImportPolicyAction::accept,
          .protocol_mld = true}};
  require(forwarder6->replace_mld_import_policy(
              0U, policy_entries, mld::ImportPolicyAction::reject),
          "forwarder rejected valid MLD import policy");
  const std::array policy_sources{denied_source, allowed_source};
  const std::array policy_records{packet::mld::ReportRecord{
      .type = packet::mld::RecordType::mode_is_include,
      .multicast_address = policy_group,
      .sources = policy_sources}};
  const auto policy_report = packet::mld::version_two_report(
      host_a, address6("fe80::2"), policy_records);
  require(policy_report.has_value(), "MLD policy fixture could not be encoded");
  forwarder6->receive(0U, *policy_report, &emitted, collect, mld_now);
  const auto policy_checkpoint = snapshot(*forwarder6, mld_now);
  const auto &policy_interface = policy_checkpoint->mld_interfaces[0];
  const auto policy_state = std::find_if(
      policy_interface.protocol.groups.begin(),
      policy_interface.protocol.groups.end(), [&](const auto &entry) {
        return entry.multicast_address == policy_group;
      });
  require(policy_state != policy_interface.protocol.groups.end() &&
              policy_state->sources.size() == 1U &&
              policy_state->sources[0].address == allowed_source &&
              policy_interface.import_policy.entries.size() == 2U,
          "MLD import policy did not filter the encoded source tuples");

  // A completely rejected source list must not be converted to an empty mode
  // transition. The policy counters must classify the drop while the listener
  // group count remains unchanged.
  const auto rejected_policy_group = address6("ff3e::4001");
  const std::array rejected_policy_records{packet::mld::ReportRecord{
      .type = packet::mld::RecordType::mode_is_include,
      .multicast_address = rejected_policy_group,
      .sources = std::span<const packet::Ipv6>{policy_sources.data(), 1U}}};
  const auto rejected_policy_report = packet::mld::version_two_report(
      host_a, address6("fe80::2"), rejected_policy_records);
  require(rejected_policy_report.has_value(),
          "rejected MLD policy fixture could not be encoded");
  const auto groups_before_policy_drop = forwarder6->mld_group_count(0U);
  forwarder6->receive(0U, *rejected_policy_report, &emitted, collect, mld_now);
  const auto dropped_policy_checkpoint = snapshot(*forwarder6, mld_now);
  require(forwarder6->mld_group_count(0U) == groups_before_policy_drop &&
              dropped_policy_checkpoint->mld_interfaces[0]
                      .protocol.statistics.policy_drops == 1U,
          "fully rejected MLD record mutated listener state or lost counters");

  const auto host6_a = address6("2001:db8:10::2");
  const auto host6_b = address6("2001:db8:11::2");
  // A configured zero is distinct from an absent neighbor limit. It blocks a
  // new dynamic entry before any pending packet or NS is created, while the
  // documented log-only variant admits the same wire flow and reports only.
  port6_b.ipv6_neighbor_limit_configured = true;
  port6_b.ipv6_neighbor_limit = 0U;
  port6_b.ipv6_neighbor_limit_log_only = false;
  require(forwarder6->configure_port(port6_b),
          "forwarder rejected zero IPv6 neighbor limit");
  emitted.clear();
  const auto limited_echo = std::make_unique<packet::Frame>(
      packet::icmpv6_echo(host_a, router_a, host6_a, host6_b, false, 30U));
  forwarder6->receive(0U, *limited_echo, &emitted, collect, checkpoint_now);
  require(emitted.empty() && forwarder6->pending_frames() == 0U &&
              forwarder6->last_drop() == ForwardDrop::neighbor_pending_full,
          "zero neighbor limit learned or queued a new neighbor");
  port6_b.ipv6_neighbor_limit_log_only = true;
  require(forwarder6->configure_port(port6_b),
          "forwarder rejected log-only IPv6 neighbor limit");
  emitted.clear();
  const auto echo6 =
      packet::icmpv6_echo(host_a, router_a, host6_a, host6_b, false, 31);
  forwarder6->receive(0, echo6, &emitted, collect, checkpoint_now);
  require(emitted.size() == 1 && emitted[0].port == 1 &&
              packet::nd::parse_neighbor_solicitation(emitted[0].frame) &&
              forwarder6->pending_frames() == 1,
          "unresolved IPv6 next hop did not emit Neighbor Solicitation");

  const auto advertisement6 = packet::nd::neighbor_advertisement(
      host_b, router_b, host6_b, port6_b.ipv6_link_local, host6_b, false, true,
      true);
  forwarder6->receive(1, advertisement6, &emitted, collect, checkpoint_now);
  // Keep the three ownership effects separate. A parser or Neighbor Cache
  // regression must not be reported as a pending-frame mismatch, and a valid
  // cache update without egress must not look like successful forwarding.
  // Earlier wire traffic legitimately learned another scoped neighbor, so a
  // global table-size assertion would reject correct multi-neighbor behavior.
  // Inspect the exact RFC 4007 scoped key completed by this advertisement.
  const auto advertisement_state = snapshot(*forwarder6, checkpoint_now);
  const auto advertised_neighbor = std::find_if(
      advertisement_state->ipv6_neighbors.begin(),
      advertisement_state->ipv6_neighbors.end(), [&](const auto &neighbor) {
        return neighbor.interface_id == physical_interface_id(1U) &&
               neighbor.address == host6_b && neighbor.mac == host_b &&
               neighbor.state == Ipv6NeighborState::reachable;
      });
  require(advertised_neighbor != advertisement_state->ipv6_neighbors.end(),
          "Neighbor Advertisement did not update its scoped cache entry");
  require(forwarder6->pending_frames() == 0,
          "Neighbor Advertisement did not release IPv6 transit ownership");
  require(emitted.size() == 2 && emitted[1].port == 1,
          "released IPv6 transit frame did not reach the selected egress");
  const auto routed6 = packet::parse_ipv6(emitted[1].frame);
  const auto routed6_ethernet = packet::parse_ethernet(emitted[1].frame);
  require(routed6 && routed6_ethernet && routed6->hop_limit == 63U &&
              routed6_ethernet->source == router_b &&
              routed6_ethernet->destination == host_b,
          "IPv6 transit did not rewrite Ethernet and Hop Limit once");

  // A received NS learns the reverse host as STALE from actual wire bytes.
  const auto reverse_ns =
      packet::nd::neighbor_solicitation(host_a, host6_a, port6_a.ipv6_address);
  forwarder6->receive(0, reverse_ns, &emitted, collect, checkpoint_now);

  // Proactive refresh is scope-selective and operates on the actual address
  // learned from the NS. At stale-time expiry maintenance must emit an encoded
  // unicast Neighbor Solicitation through the normal egress sink.
  port6_a.nd_stale_time_seconds = 60U;
  port6_a.ipv6_proactive_refresh = Ipv6UnsolicitedLearning::global;
  require(forwarder6->configure_port(port6_a),
          "forwarder rejected proactive Neighbor Discovery policy");
  const auto policy_now = checkpoint_now + std::chrono::seconds{10};
  forwarder6->receive(0U, reverse_ns, &emitted, collect, policy_now);
  emitted.clear();
  forwarder6->service_ipv6_maintenance(&emitted, collect,
                                       policy_now + std::chrono::seconds{60});
  const auto proactive_probe =
      std::find_if(emitted.begin(), emitted.end(), [&](const auto &item) {
        const auto solicitation =
            packet::nd::parse_neighbor_solicitation(item.frame);
        const auto ethernet = packet::parse_ethernet(item.frame);
        return item.port == 0U && solicitation && ethernet &&
               solicitation->target == host6_a &&
               ethernet->destination == host_a;
      });
  require(proactive_probe != emitted.end(),
          "proactive stale expiry did not emit unicast NUD");

  // Configure a regular service-interface relay on the client-facing port.
  // The only upstream is a real IPv6 neighbor behind the other routed port;
  // no server object or editor edge is passed to the forwarding owner.
  const auto client_link_local = address6("fe80::2");
  constexpr std::array<std::uint8_t, 4U> relay_interface_id{'s', 'a', 'p', '1'};
  dhcpv6::RelayInterfaceConfig relay_configuration{
      // A deliberately non-ordinal logical ID proves return routing resolves
      // the committed service identity instead of subtracting one from it.
      .interface_id = 70'001U,
      .physical_port_ordinal = 0U,
      .link_address = port6_a.ipv6_address,
      .relay_interface_id = std::vector<std::uint8_t>(
          relay_interface_id.begin(), relay_interface_id.end()),
      .server_count = 1U,
      .upstream_policy =
          dhcpv6::RelayUpstreamPolicy::explicit_servers_required};
  relay_configuration.servers[0] = {.address = host6_b};
  // Publish the untagged IES attachment before its DHCPv6 child. Receiving
  // every frame under a relay's opaque Interface-Id would incorrectly move
  // native ND into the service zone. The SAP classifier is the only owner
  // allowed to select that logical RFC 4007 scope from Ethernet ingress.
  const std::array relay_attachments{service::SapAttachment{
      .logical_interface_id = relay_configuration.interface_id,
      .sap = {.port = {.ordinal = 0U, .card = 1U, .mda = 1U, .port = 1U},
              .encapsulation = service::EthernetEncapsulation::null}}};
  const std::array relay_interfaces{service::ServiceIpv6Interface{
      .interface_id = relay_configuration.interface_id,
      .physical_port_ordinal = 0U,
      .mtu = 1500U,
      .mac = port6_a.mac,
      .address = port6_a.ipv6_address,
      // The caller-side ForwardPort fixture contains configured host bits;
      // configure_port canonicalizes only its owned copy. Supply the service
      // projection's network explicitly instead of reading stale input data.
      .network = address6("2001:db8:10::"),
      .link_local = port6_a.ipv6_link_local,
      .prefix_length = port6_a.ipv6_prefix_length,
      .nd_reachable_time_milliseconds = port6_a.nd_reachable_time_milliseconds,
      .nd_stale_time_seconds = port6_a.nd_stale_time_seconds,
      .neighbor_limit_threshold_percent =
          port6_a.ipv6_neighbor_limit_threshold_percent,
      .redirect_maximum = port6_a.icmp6_redirect_maximum,
      .redirect_interval_seconds = port6_a.icmp6_redirect_interval_seconds,
      .redirects_enabled = port6_a.icmp6_redirects_enabled,
      .configured = true,
      .operational = true}};
  require(
      forwarder6->program_sap_generation(relay_attachments, relay_interfaces) ==
          service::SapProgramStatus::accepted,
      "forwarder rejected the relay service-interface generation");
  require(forwarder6->configure_dhcpv6_relay(relay_configuration) ==
              dhcpv6::RelayConfigStatus::accepted,
          "forwarder rejected a valid SR OS DHCPv6 relay service");
  // The relay is a child of the same logical routed interface as ND and FIB.
  // Reprogramming the connected route with the service ID proves that later
  // same-link traffic and relay replies share one RFC 4007 zone even though
  // their final wire egress is the same physical port zero.
  auto relay_connected = connected6;
  relay_connected[0].interface_id = relay_configuration.interface_id;
  require(rib6.rebuild(relay_connected, std::span<const Ipv6StaticInput>{}) &&
              forwarder6->program_ipv6_fib(rib6.compile(2U)),
          "relay service interface identity did not reach the IPv6 FIB");

  // Neighbor Cache entries belong to an RFC 4007 zone and therefore cannot
  // be copied from the former native-port interface into the newly selected
  // service interface. The attached host sends an ordinary NS after that
  // control-plane change, which lets the forwarding owner learn its source
  // address and MAC from wire bytes in the correct logical scope. This is the
  // same exchange a real host performs before later router-local UDP replies.
  emitted.clear();
  forwarder6->receive(0U, reverse_ns, &emitted, collect, checkpoint_now);
  // A newly created service interface has its own RFC 4862 DAD state even
  // when the same link-local bytes were already preferred on a former native
  // interface. Drive the real initial-delay and RetransTimer transitions
  // before exercising relay return traffic.
  forwarder6->service_ipv6_maintenance(
      &emitted, collect, checkpoint_now + std::chrono::seconds{2});
  forwarder6->service_ipv6_maintenance(
      &emitted, collect, checkpoint_now + std::chrono::seconds{4});
  emitted.clear();

  std::array<std::uint8_t, 128U> solicit_storage{};
  auto solicit = packet::dhcpv6::begin_client_server(
      solicit_storage,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::solicit),
      0x123456U);
  constexpr std::array<std::uint8_t, 6U> relay_client_duid{0U, 3U,    0U,
                                                           1U, 0xaaU, 0xbbU};
  require(solicit && solicit->append(
                         static_cast<std::uint16_t>(
                             packet::dhcpv6::OptionCode::client_identifier),
                         relay_client_duid),
          "DHCPv6 relay Solicit fixture could not be encoded");
  emitted.clear();
  const auto client_solicit =
      std::make_unique<packet::Frame>(udp_ipv6_payload_frame(
          host_a,
          packet::ipv6_multicast_mac(
              packet::dhcpv6::all_relay_agents_and_servers),
          client_link_local, packet::dhcpv6::all_relay_agents_and_servers,
          packet::dhcpv6::client_port, packet::dhcpv6::server_port,
          solicit->view()));
  forwarder6->receive(0U, *client_solicit, &emitted, collect, checkpoint_now,
                      nullptr, nullptr, admit_all);
  require(emitted.size() == 1U && emitted[0].port == 1U,
          "DHCPv6 Solicit did not traverse routed relay egress");
  const auto upstream_ipv6 = packet::parse_ipv6(emitted[0].frame);
  const auto upstream_ethernet = packet::parse_ethernet(emitted[0].frame);
  require(upstream_ipv6 && upstream_ethernet &&
              upstream_ipv6->source == port6_b.ipv6_address &&
              upstream_ipv6->destination == host6_b &&
              upstream_ethernet->source == router_b &&
              upstream_ethernet->destination == host_b,
          "DHCPv6 relay bypassed FIB source selection or ND");
  const auto upstream_end = packet::ethernet_header_octets +
                            packet::ipv6_header_octets +
                            upstream_ipv6->payload_length;
  const auto upstream_udp = packet::udp::parse_ipv6(
      emitted[0].frame.view().subspan(upstream_ipv6->upper_layer_offset,
                                      upstream_end -
                                          upstream_ipv6->upper_layer_offset),
      upstream_ipv6->source, upstream_ipv6->destination);
  const auto relay_forward = upstream_udp
                                 ? packet::dhcpv6::parse(upstream_udp->payload)
                                 : std::optional<packet::dhcpv6::MessageView>{};
  require(upstream_udp &&
              upstream_udp->source_port == packet::dhcpv6::server_port &&
              upstream_udp->destination_port == packet::dhcpv6::server_port &&
              relay_forward && relay_forward->hop_count == 0U &&
              relay_forward->link_address == port6_a.ipv6_address &&
              relay_forward->peer_address == client_link_local,
          "DHCPv6 Relay-forward wire fields or UDP ports were incorrect");

  // Learn the client's link-local neighbor through a real NS before the
  // server response. Relay-reply can then cross the reverse ND path without a
  // test hook preinstalling a MAC address.
  const auto client_ns =
      std::make_unique<packet::Frame>(packet::nd::neighbor_solicitation(
          host_a, client_link_local, port6_a.ipv6_address));
  forwarder6->receive(0U, *client_ns, &emitted, collect, checkpoint_now);
  std::array<std::uint8_t, 128U> reply_message_storage{};
  auto client_reply = packet::dhcpv6::begin_client_server(
      reply_message_storage,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::reply), 0x123456U);
  require(client_reply &&
              client_reply->append(
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::client_identifier),
                  relay_client_duid),
          "DHCPv6 client Reply fixture could not be encoded");
  std::array<std::uint8_t, 512U> relay_reply_storage{};
  const auto relay_reply = dhcpv6::encapsulate_relay_reply(
      upstream_udp->payload, client_reply->view(), relay_reply_storage);
  require(relay_reply.status == dhcpv6::RelayStatus::forwarded,
          "DHCPv6 server could not reverse Relay-forward fixture");
  emitted.clear();
  const auto server_reply =
      std::make_unique<packet::Frame>(udp_ipv6_payload_frame(
          host_b, router_b, host6_b, port6_b.ipv6_address,
          packet::dhcpv6::server_port, packet::dhcpv6::server_port,
          std::span<const std::uint8_t>{relay_reply_storage}.first(
              relay_reply.message_octets)));
  forwarder6->receive(1U, *server_reply, &emitted, collect, checkpoint_now,
                      nullptr, nullptr, admit_all);
  require(emitted.size() == 1U && emitted[0].port == 0U,
          "DHCPv6 Relay-reply did not select its Interface-Id egress");
  const auto downstream_ipv6 = packet::parse_ipv6(emitted[0].frame);
  const auto downstream_end = downstream_ipv6
                                  ? packet::ethernet_header_octets +
                                        packet::ipv6_header_octets +
                                        downstream_ipv6->payload_length
                                  : 0U;
  const auto downstream_udp =
      downstream_ipv6
          ? packet::udp::parse_ipv6(
                emitted[0].frame.view().subspan(
                    downstream_ipv6->upper_layer_offset,
                    downstream_end - downstream_ipv6->upper_layer_offset),
                downstream_ipv6->source, downstream_ipv6->destination)
          : std::optional<packet::udp::View>{};
  require(
      downstream_ipv6 && downstream_ipv6->source == port6_a.ipv6_link_local &&
          downstream_ipv6->destination == client_link_local && downstream_udp &&
          downstream_udp->source_port == packet::dhcpv6::server_port &&
          downstream_udp->destination_port == packet::dhcpv6::client_port &&
          std::equal(downstream_udp->payload.begin(),
                     downstream_udp->payload.end(),
                     client_reply->view().begin(), client_reply->view().end()),
      "DHCPv6 Relay-reply changed client bytes, scope or UDP ports");

  // Enable the complete SR OS lease-populate policy on the already live
  // relay. The client subnet is derived from its service-interface address in
  // production; this isolated forwarding-owner test supplies the same
  // canonical prefix directly because no control shard exists in this module.
  const auto relay_client_prefix = ip::parse_ipv6_prefix("2001:db8:10::/64");
  require(relay_client_prefix.has_value(),
          "DHCPv6 relay client prefix fixture is invalid");
  relay_configuration.client_prefix = *relay_client_prefix;
  relay_configuration.lease_population_limit = 2U;
  relay_configuration.neighbor_resolution = true;
  relay_configuration.route_non_temporary = true;
  relay_configuration.route_delegated_prefix = true;
  relay_configuration.route_prefix_exclude = true;
  require(forwarder6->configure_dhcpv6_relay(relay_configuration) ==
              dhcpv6::RelayConfigStatus::accepted,
          "forwarder rejected sourced DHCPv6 population policy");

  // Correlation must come from a new encoded client request containing the
  // exact IAIDs later returned by the server. The source MAC is deliberately
  // available only in this Ethernet frame, proving the implementation does
  // not infer it from the opaque DUID-LL bytes.
  constexpr std::uint32_t binding_transaction = 0x234567U;
  std::array<std::uint8_t, 256U> binding_solicit_storage{};
  auto binding_solicit = packet::dhcpv6::begin_client_server(
      binding_solicit_storage,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::solicit),
      binding_transaction);
  require(binding_solicit &&
              binding_solicit->append(
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::client_identifier),
                  relay_client_duid) &&
              append_dhcpv6_association(
                  *binding_solicit, packet::dhcpv6::OptionCode::ia_na, 11U) &&
              append_dhcpv6_association(*binding_solicit,
                                        packet::dhcpv6::OptionCode::ia_pd, 12U),
          "DHCPv6 lease-populate Solicit fixture could not be encoded");
  emitted.clear();
  const auto binding_client_frame =
      std::make_unique<packet::Frame>(udp_ipv6_payload_frame(
          host_a,
          packet::ipv6_multicast_mac(
              packet::dhcpv6::all_relay_agents_and_servers),
          client_link_local, packet::dhcpv6::all_relay_agents_and_servers,
          packet::dhcpv6::client_port, packet::dhcpv6::server_port,
          binding_solicit->view()));
  forwarder6->receive(0U, *binding_client_frame, &emitted, collect,
                      checkpoint_now, nullptr, nullptr, admit_all);
  require(emitted.size() == 1U && emitted[0].port == 1U,
          "DHCPv6 population Solicit did not reach the configured server");
  const auto binding_upstream_ipv6 = packet::parse_ipv6(emitted[0].frame);
  const auto binding_upstream_end =
      binding_upstream_ipv6
          ? packet::ethernet_header_octets + packet::ipv6_header_octets +
                binding_upstream_ipv6->payload_length
          : 0U;
  const auto binding_upstream_udp =
      binding_upstream_ipv6
          ? packet::udp::parse_ipv6(
                emitted[0].frame.view().subspan(
                    binding_upstream_ipv6->upper_layer_offset,
                    binding_upstream_end -
                        binding_upstream_ipv6->upper_layer_offset),
                binding_upstream_ipv6->source,
                binding_upstream_ipv6->destination)
          : std::optional<packet::udp::View>{};
  require(binding_upstream_udp.has_value(),
          "DHCPv6 population Relay-forward UDP could not be decoded");

  const auto leased_address = address6("2001:db8:10::100");
  const auto delegated_prefix = address6("2001:db8:dead:bee0::");
  const auto excluded_prefix = address6("2001:db8:dead:beef::");
  std::array<std::uint8_t, 64U> address_body{};
  const auto address_body_octets = packet::dhcpv6::encode_ia_address(
      address_body, leased_address, 600U, 1200U);
  std::vector<std::uint8_t> na_options;
  require(address_body_octets.has_value(),
          "DHCPv6 IAADDR fixture could not be encoded");
  append_dhcpv6_option(
      na_options, packet::dhcpv6::OptionCode::ia_address,
      std::span<const std::uint8_t>{address_body}.first(*address_body_octets));

  // RFC 6603 represents 2001:db8:dead:beef::/64 inside the delegated
  // 2001:db8:dead:bee0::/59 as five subnet-id bits 01111 followed by three
  // zero padding bits. The wire value is nested inside its IAPREFIX.
  constexpr std::array<std::uint8_t, 2U> prefix_exclude{64U, 0x78U};
  std::vector<std::uint8_t> prefix_children;
  append_dhcpv6_option(prefix_children,
                       packet::dhcpv6::OptionCode::prefix_exclude,
                       prefix_exclude);
  std::array<std::uint8_t, 128U> prefix_body{};
  const auto prefix_body_octets = packet::dhcpv6::encode_ia_prefix(
      prefix_body, delegated_prefix, 59U, 600U, 1200U, prefix_children);
  std::vector<std::uint8_t> pd_options;
  require(prefix_body_octets.has_value(),
          "DHCPv6 IAPREFIX fixture could not be encoded");
  append_dhcpv6_option(
      pd_options, packet::dhcpv6::OptionCode::ia_prefix,
      std::span<const std::uint8_t>{prefix_body}.first(*prefix_body_octets));

  std::array<std::uint8_t, 1024U> binding_reply_storage{};
  constexpr std::array<std::uint8_t, 8U> relay_server_duid{0U, 3U, 0U, 1U,
                                                           2U, 0U, 0U, 0xfeU};
  auto binding_reply = packet::dhcpv6::begin_client_server(
      binding_reply_storage,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::reply),
      binding_transaction);
  require(binding_reply &&
              binding_reply->append(
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::client_identifier),
                  relay_client_duid) &&
              binding_reply->append(
                  static_cast<std::uint16_t>(
                      packet::dhcpv6::OptionCode::server_identifier),
                  relay_server_duid) &&
              append_dhcpv6_association(*binding_reply,
                                        packet::dhcpv6::OptionCode::ia_na, 11U,
                                        na_options) &&
              append_dhcpv6_association(*binding_reply,
                                        packet::dhcpv6::OptionCode::ia_pd, 12U,
                                        pd_options),
          "DHCPv6 populated Reply fixture could not be encoded");
  std::array<std::uint8_t, 1536U> binding_relay_reply_storage{};
  const auto binding_relay_reply = dhcpv6::encapsulate_relay_reply(
      binding_upstream_udp->payload, binding_reply->view(),
      binding_relay_reply_storage);
  require(binding_relay_reply.status == dhcpv6::RelayStatus::forwarded,
          "DHCPv6 server could not wrap populated Reply fixture");
  emitted.clear();
  const auto binding_server_frame =
      std::make_unique<packet::Frame>(udp_ipv6_payload_frame(
          host_b, router_b, host6_b, port6_b.ipv6_address,
          packet::dhcpv6::server_port, packet::dhcpv6::server_port,
          std::span<const std::uint8_t>{binding_relay_reply_storage}.first(
              binding_relay_reply.message_octets)));
  forwarder6->receive(1U, *binding_server_frame, &emitted, collect,
                      checkpoint_now, nullptr, nullptr, admit_all);
  const auto populated_checkpoint = snapshot(*forwarder6, checkpoint_now);
  const auto populated_neighbor = std::find_if(
      populated_checkpoint->ipv6_neighbors.begin(),
      populated_checkpoint->ipv6_neighbors.end(), [&](const auto &neighbor) {
        return neighbor.interface_id == relay_configuration.interface_id &&
               neighbor.address == leased_address && neighbor.mac == host_a &&
               !neighbor.is_static;
      });
  const auto populated_na_route = std::find_if(
      populated_checkpoint->dhcpv6_relay_routes.begin(),
      populated_checkpoint->dhcpv6_relay_routes.end(), [&](const auto &route) {
        return route.network == leased_address && route.prefix_length == 128U &&
               route.next_hop == client_link_local && !route.blackhole;
      });
  const auto populated_pd_route = std::find_if(
      populated_checkpoint->dhcpv6_relay_routes.begin(),
      populated_checkpoint->dhcpv6_relay_routes.end(), [&](const auto &route) {
        return route.network == delegated_prefix &&
               route.prefix_length == 59U &&
               route.next_hop == client_link_local && !route.blackhole;
      });
  const auto populated_exclude = std::find_if(
      populated_checkpoint->dhcpv6_relay_routes.begin(),
      populated_checkpoint->dhcpv6_relay_routes.end(), [&](const auto &route) {
        return route.network == excluded_prefix && route.prefix_length == 64U &&
               route.blackhole;
      });
  require(
      emitted.size() == 1U && emitted[0].port == 0U &&
          populated_checkpoint->dhcpv6_relay_leases.size() == 2U &&
          populated_checkpoint->dhcpv6_relay_routes.size() == 3U &&
          populated_neighbor != populated_checkpoint->ipv6_neighbors.end() &&
          populated_na_route !=
              populated_checkpoint->dhcpv6_relay_routes.end() &&
          populated_pd_route !=
              populated_checkpoint->dhcpv6_relay_routes.end() &&
          populated_exclude != populated_checkpoint->dhcpv6_relay_routes.end(),
      "DHCPv6 Reply did not atomically populate lease, neighbor and routes");

  // A client datagram that fits the ingress MTU may grow past the independent
  // server-facing PMTU after relay encapsulation. The router is the source of
  // the outer packet and must emit a complete RFC 8200 fragment batch instead
  // of imposing the link MTU as a DHCPv6 or UDP payload limit.
  std::array<std::uint8_t, 1400U> large_solicit_storage{};
  auto large_solicit = packet::dhcpv6::begin_client_server(
      large_solicit_storage,
      static_cast<std::uint8_t>(packet::dhcpv6::MessageType::solicit),
      0x654321U);
  std::array<std::uint8_t, 1220U> vendor_data{};
  for (std::size_t index = 0; index < vendor_data.size(); ++index)
    vendor_data[index] = static_cast<std::uint8_t>(index);
  require(large_solicit && large_solicit->append(
                               static_cast<std::uint16_t>(
                                   packet::dhcpv6::OptionCode::vendor_options),
                               vendor_data),
          "large DHCPv6 Solicit fixture could not be encoded");
  emitted.clear();
  const auto large_client_solicit =
      std::make_unique<packet::Frame>(udp_ipv6_payload_frame(
          host_a,
          packet::ipv6_multicast_mac(
              packet::dhcpv6::all_relay_agents_and_servers),
          client_link_local, packet::dhcpv6::all_relay_agents_and_servers,
          packet::dhcpv6::client_port, packet::dhcpv6::server_port,
          large_solicit->view()));
  forwarder6->receive(0U, *large_client_solicit, &emitted, collect,
                      checkpoint_now, nullptr, nullptr, admit_all);
  require(emitted.size() > 1U &&
              std::all_of(emitted.begin(), emitted.end(),
                          [](const auto &item) {
                            const auto parsed = packet::parse_ipv6(item.frame);
                            return item.port == 1U && parsed &&
                                   parsed->fragment;
                          }),
          "large DHCPv6 relay payload was limited or partially fragmented");
  auto relay_reassembly = std::make_unique<packet::Ipv6ReassemblyTable>();
  packet::Ipv6ReassemblyResult reassembled_relay;
  for (const auto &fragment : emitted)
    reassembled_relay =
        relay_reassembly->accept(fragment.frame, checkpoint_now);
  const auto reassembled_ipv6 = packet::parse_ipv6(reassembled_relay.packet);
  const auto reassembled_end = reassembled_ipv6
                                   ? packet::ethernet_header_octets +
                                         packet::ipv6_header_octets +
                                         reassembled_ipv6->payload_length
                                   : 0U;
  const auto reassembled_udp =
      reassembled_ipv6
          ? packet::udp::parse_ipv6(
                reassembled_relay.packet.subspan(
                    reassembled_ipv6->upper_layer_offset,
                    reassembled_end - reassembled_ipv6->upper_layer_offset),
                reassembled_ipv6->source, reassembled_ipv6->destination)
          : std::optional<packet::udp::View>{};
  require(reassembled_relay.status == packet::Ipv6ReassemblyStatus::complete &&
              reassembled_udp &&
              packet::dhcpv6::parse(reassembled_udp->payload),
          "large DHCPv6 fragment batch did not reconstruct one UDP datagram");

  const auto relay_checkpoint = snapshot(*forwarder6, checkpoint_now);
  auto relay_restored = std::make_unique<RouterForwarder>();
  const bool relay_restore_accepted =
      relay_restored->restore(*relay_checkpoint, checkpoint_now);
  const auto restored_relay_checkpoint =
      relay_restore_accepted ? snapshot(*relay_restored, checkpoint_now)
                             : std::unique_ptr<RouterForwarderCheckpoint>{};
  require(relay_checkpoint->dhcpv6_relay_interfaces.size() == 1U &&
              relay_checkpoint->dhcpv6_relay_leases.size() == 2U &&
              relay_checkpoint->dhcpv6_relay_routes.size() == 3U &&
              relay_checkpoint->dhcpv6_relay_socket.has_value() &&
              restored_relay_checkpoint &&
              restored_relay_checkpoint->dhcpv6_relay_interfaces.size() == 1U &&
              restored_relay_checkpoint->dhcpv6_relay_leases.size() == 2U &&
              restored_relay_checkpoint->dhcpv6_relay_routes.size() == 3U,
          "DHCPv6 relay socket, return path or population did not survive "
          "checkpoint");

  // Nokia suppresses the on-behalf Release when fewer than five minutes of
  // valid lifetime remain, even without the explicit no-dhcp-release keyword.
  // Restore a separate owner so this threshold test cannot consume the rows
  // used by the encoded Release test below.
  auto threshold_relay = std::make_unique<RouterForwarder>();
  require(threshold_relay->restore(*relay_checkpoint, checkpoint_now),
          "DHCPv6 threshold-clear fixture restore failed");
  emitted.clear();
  require(threshold_relay->clear_dhcpv6_relay_leases(
              {.interface_id = relay_configuration.interface_id,
               .prefix = {.network = delegated_prefix, .length = 59U},
               .prefix_specific = true},
              false, &emitted, collect, admit_all,
              checkpoint_now + std::chrono::seconds{901}),
          "DHCPv6 below-threshold clear command was rejected");
  require(emitted.empty(),
          "DHCPv6 clear sent Release with under five minutes remaining");

  // The no-dhcp-release form must withdraw the selected IA_NA, its populated
  // /128 route and derived Neighbor Cache row without emitting any packet.
  // The exact address/length selector must leave the unrelated IA_PD and
  // OPTION_PD_EXCLUDE blackhole intact.
  emitted.clear();
  require(relay_restored->clear_dhcpv6_relay_leases(
              {.interface_id = relay_configuration.interface_id,
               .prefix = {.network = leased_address, .length = 128U},
               .prefix_specific = true},
              true, &emitted, collect, admit_all, checkpoint_now),
          "DHCPv6 no-release clear command was rejected");
  const auto after_no_release = snapshot(*relay_restored, checkpoint_now);
  require(emitted.empty() &&
              after_no_release->dhcpv6_relay_leases.size() == 1U &&
              after_no_release->dhcpv6_relay_leases.front().value ==
                  delegated_prefix &&
              after_no_release->dhcpv6_relay_routes.size() == 2U &&
              std::none_of(after_no_release->ipv6_neighbors.begin(),
                           after_no_release->ipv6_neighbors.end(),
                           [&](const auto &neighbor) {
                             return neighbor.interface_id ==
                                        relay_configuration.interface_id &&
                                    neighbor.address == leased_address;
                           }),
          "DHCPv6 no-release clear removed the wrong operational state");

  // More than five minutes remain on an infinite or sufficiently long lease,
  // so the ordinary clear form sends Release on behalf of the client. The
  // packet is decoded from Ethernet through UDP and Relay-forward before its
  // mandatory identifiers, Elapsed Time and selected IA_PD are checked.
  emitted.clear();
  require(relay_restored->clear_dhcpv6_relay_leases(
              {.interface_id = relay_configuration.interface_id,
               .prefix = {.network = delegated_prefix, .length = 59U},
               .prefix_specific = true},
              false, &emitted, collect, admit_all, checkpoint_now),
          "DHCPv6 release-generating clear command was rejected");
  const auto cleared_state = snapshot(*relay_restored, checkpoint_now);
  require(emitted.size() == 1U && emitted.front().port == 1U &&
              cleared_state->dhcpv6_relay_leases.empty() &&
              cleared_state->dhcpv6_relay_routes.empty(),
          "DHCPv6 clear did not withdraw state and emit one Release");
  const auto release_ipv6 = packet::parse_ipv6(emitted.front().frame);
  const auto release_end = release_ipv6 ? packet::ethernet_header_octets +
                                              packet::ipv6_header_octets +
                                              release_ipv6->payload_length
                                        : 0U;
  const auto release_udp =
      release_ipv6 ? packet::udp::parse_ipv6(
                         emitted.front().frame.view().subspan(
                             release_ipv6->upper_layer_offset,
                             release_end - release_ipv6->upper_layer_offset),
                         release_ipv6->source, release_ipv6->destination)
                   : std::optional<packet::udp::View>{};
  const auto release_relay = release_udp
                                 ? packet::dhcpv6::parse(release_udp->payload)
                                 : std::optional<packet::dhcpv6::MessageView>{};
  std::span<const std::uint8_t> release_inner_bytes;
  if (release_relay) {
    packet::dhcpv6::OptionCursor relay_options{release_relay->options};
    while (const auto option = relay_options.next())
      if (option->code ==
          static_cast<std::uint16_t>(packet::dhcpv6::OptionCode::relay_message))
        release_inner_bytes = option->data;
  }
  const auto release_inner = packet::dhcpv6::parse(release_inner_bytes);
  bool release_client{};
  bool release_server{};
  bool release_elapsed{};
  bool release_pd{};
  if (release_inner) {
    packet::dhcpv6::OptionCursor options{release_inner->options};
    while (const auto option = options.next()) {
      release_client |=
          option->code == static_cast<std::uint16_t>(
                              packet::dhcpv6::OptionCode::client_identifier) &&
          std::equal(option->data.begin(), option->data.end(),
                     relay_client_duid.begin(), relay_client_duid.end());
      release_server |=
          option->code == static_cast<std::uint16_t>(
                              packet::dhcpv6::OptionCode::server_identifier) &&
          std::equal(option->data.begin(), option->data.end(),
                     relay_server_duid.begin(), relay_server_duid.end());
      release_elapsed |=
          option->code == static_cast<std::uint16_t>(
                              packet::dhcpv6::OptionCode::elapsed_time) &&
          option->data.size() == 2U && option->data[0] == 0U &&
          option->data[1] == 0U;
      if (option->code ==
          static_cast<std::uint16_t>(packet::dhcpv6::OptionCode::ia_pd)) {
        const auto association =
            packet::dhcpv6::parse_ia_na_or_pd(option->data);
        packet::dhcpv6::OptionCursor resources{
            association ? association->options
                        : std::span<const std::uint8_t>{}};
        while (const auto resource = resources.next()) {
          if (resource->code !=
              static_cast<std::uint16_t>(packet::dhcpv6::OptionCode::ia_prefix))
            continue;
          const auto prefix = packet::dhcpv6::parse_ia_prefix(resource->data);
          release_pd = association && association->iaid == 12U && prefix &&
                       prefix->prefix == delegated_prefix &&
                       prefix->prefix_length == 59U;
        }
      }
    }
  }
  require(
      release_ipv6 && release_ipv6->destination == host6_b && release_udp &&
          release_udp->source_port == packet::dhcpv6::server_port &&
          release_udp->destination_port == packet::dhcpv6::server_port &&
          release_relay && release_relay->relay && release_inner &&
          release_inner->type ==
              static_cast<std::uint8_t>(packet::dhcpv6::MessageType::release) &&
          release_client && release_server && release_elapsed && release_pd,
      "DHCPv6 clear emitted a malformed or misrouted Release");

  // The remaining forwarding cases exercise the native router interface on
  // this same physical port. Withdraw the relay child before its parent SAP,
  // then restore the original connected-route scope. This mirrors service
  // dependency ordering and prevents an obsolete logical ID from classifying
  // unrelated untagged ND or Redirect traffic later in the test.
  require(forwarder6->remove_dhcpv6_relay(relay_configuration.interface_id) &&
              forwarder6->program_sap_generation({}, {}) ==
                  service::SapProgramStatus::accepted &&
              rib6.rebuild(connected6, std::span<const Ipv6StaticInput>{}) &&
              forwarder6->program_ipv6_fib(rib6.compile(3U)),
          "relay service teardown did not restore native IPv6 scope");

  // A host that sends same-link traffic through the router receives a real
  // ICMPv6 Redirect after the transit packet enters ordinary ND processing.
  // Eleven accepted packets in one one-second SR OS window must yield exactly
  // the configured ten Redirects, with no special test-only delivery path.
  emitted.clear();
  const auto host6_c = address6("2001:db8:10::3");
  const auto redirect_now = checkpoint_now + std::chrono::seconds{6};
  for (std::uint16_t sequence = 0U; sequence < 11U; ++sequence) {
    const auto same_link = packet::icmpv6_echo(host_a, router_a, host6_a,
                                               host6_c, false, sequence);
    forwarder6->receive(0U, same_link, &emitted, collect, redirect_now);
  }
  const auto redirect_count = static_cast<std::size_t>(
      std::count_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        return packet::nd::parse_redirect(candidate.frame).has_value();
      }));
  const auto first_redirect =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        return packet::nd::parse_redirect(candidate.frame).has_value();
      });
  const auto parsed_redirect =
      first_redirect == emitted.end()
          ? std::optional<packet::nd::RedirectView>{}
          : packet::nd::parse_redirect(first_redirect->frame);
  require(redirect_count == 10U && parsed_redirect &&
              first_redirect->port == 0U &&
              parsed_redirect->source == port6_a.ipv6_link_local &&
              parsed_redirect->receiver == host6_a &&
              parsed_redirect->target == host6_c &&
              parsed_redirect->destination == host6_c,
          "same-link forwarding did not emit rate-limited IPv6 Redirects");
  auto redirect_checkpoint = snapshot(*forwarder6, redirect_now);
  require(redirect_checkpoint->ipv6_redirect_limiters.size() == 1U &&
              redirect_checkpoint->ipv6_redirect_limiters[0].sent == 10U,
          "active Redirect rate window was not checkpointed");
  {
    auto redirect_restored = std::make_unique<RouterForwarder>();
    require(redirect_restored->restore(*redirect_checkpoint, redirect_now),
            "Redirect forwarding-owner checkpoint was rejected");
    auto restored_redirect_checkpoint =
        snapshot(*redirect_restored, redirect_now);
    require(restored_redirect_checkpoint->ipv6_redirect_limiters.size() == 1U &&
                restored_redirect_checkpoint->ipv6_redirect_limiters[0].sent ==
                    10U,
            "Redirect rate window did not survive forwarding-owner restore");
  }

  // Resolve the real same-link target through NA so queued transit packets
  // leave the bounded arena and the next Redirect may include its known TLLA.
  const auto host_c_na = packet::nd::neighbor_advertisement(
      host_c, router_a, host6_c, port6_a.ipv6_link_local, host6_c, false, true,
      true);
  forwarder6->receive(0U, host_c_na, &emitted, collect,
                      redirect_now + std::chrono::milliseconds{100});
  require(forwarder6->pending_frames() == 0U,
          "same-link NA did not release Redirect test transit packets");

  // A new interval permits another Redirect. Disabling the configured leaf on
  // the same address generation must suppress it without restarting DAD.
  emitted.clear();
  const auto later_same_link =
      packet::icmpv6_echo(host_a, router_a, host6_a, host6_c, false, 20U);
  forwarder6->receive(0U, later_same_link, &emitted, collect,
                      redirect_now + std::chrono::seconds{2});
  const auto later_redirect =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        return packet::nd::parse_redirect(candidate.frame).has_value();
      });
  const auto later_redirect_view =
      later_redirect == emitted.end()
          ? std::optional<packet::nd::RedirectView>{}
          : packet::nd::parse_redirect(later_redirect->frame);
  require(
      later_redirect_view && later_redirect_view->target_link_layer == host_c,
      "new Redirect window omitted the target's learned link-layer address");
  auto redirects_disabled = port6_a;
  redirects_disabled.icmp6_redirects_enabled = false;
  require(
      forwarder6->configure_port(redirects_disabled) &&
          forwarder6->ipv6_address_state(0U,
                                         redirects_disabled.ipv6_link_local) &&
          forwarder6->ipv6_address_state(0U, redirects_disabled.ipv6_link_local)
                  ->state == Ipv6DadState::preferred,
      "Redirect leaf update restarted an unchanged IPv6 DAD generation");
  emitted.clear();
  forwarder6->receive(0U, later_same_link, &emitted, collect,
                      redirect_now + std::chrono::seconds{3});
  require(std::none_of(
              emitted.begin(), emitted.end(),
              [](const auto &candidate) {
                return packet::nd::parse_redirect(candidate.frame).has_value();
              }),
          "disabled interface continued to emit IPv6 Redirects");

  // UDP is a recognized IPv6 upper-layer protocol even before a router-local
  // application binds the destination tuple. RFC 4443 requires code 4 for a
  // valid closed port, while an invalid mandatory checksum is discarded.
  emitted.clear();
  const auto closed_udp =
      udp_ipv6_frame(host_a, router_a, host6_a, port6_a.ipv6_address);
  const auto closed_udp_ipv6 = packet::parse_ipv6(closed_udp);
  const auto closed_udp_ethernet = packet::parse_ethernet(closed_udp);
  const auto closed_udp_wire =
      closed_udp_ipv6
          ? packet::udp::parse_ipv6(
                closed_udp.view().subspan(closed_udp_ipv6->upper_layer_offset),
                closed_udp_ipv6->source, closed_udp_ipv6->destination)
          : std::optional<packet::udp::View>{};
  require(closed_udp_wire.has_value(),
          "closed-port fixture was not a valid IPv6 UDP datagram");
  require(closed_udp_ethernet && closed_udp_ethernet->destination == router_a,
          "closed-port fixture did not target the configured router MAC");
  forwarder6->receive(0U, closed_udp, &emitted, collect, checkpoint_now);
  const auto closed_port_error =
      emitted.empty() ? std::optional<packet::Icmpv6View>{}
                      : packet::parse_icmpv6(emitted.back().frame);
  if (emitted.size() != 1U || !closed_port_error ||
      closed_port_error->type != packet::icmpv6_destination_unreachable_type ||
      closed_port_error->code !=
          packet::icmpv6_destination_port_unreachable_code)
    throw std::runtime_error(
        "closed router UDP port did not return ICMPv6 code 4: frames=" +
        std::to_string(emitted.size()) + " type=" +
        std::to_string(closed_port_error ? closed_port_error->type : 255U) +
        " code=" +
        std::to_string(closed_port_error ? closed_port_error->code : 255U) +
        " drop=" +
        std::to_string(static_cast<unsigned>(forwarder6->last_drop())));
  emitted.clear();
  auto corrupt_udp = closed_udp;
  corrupt_udp.bytes[corrupt_udp.length - 1U] ^= 0xffU;
  forwarder6->receive(0U, corrupt_udp, &emitted, collect, checkpoint_now);
  require(emitted.empty(),
          "invalid IPv6 UDP checksum produced an ICMP amplification response");

  emitted.clear();
  auto unknown_next = packet::icmpv6_echo(host_a, router_a, host6_a,
                                          port6_a.ipv6_address, false, 39U);
  constexpr std::uint8_t experimental_next_header = 253U;
  unknown_next.bytes[20] = experimental_next_header;
  forwarder6->receive(0, unknown_next, &emitted, collect, checkpoint_now);
  const auto next_header_error =
      emitted.empty() ? std::optional<packet::Icmpv6View>{}
                      : packet::parse_icmpv6(emitted.back().frame);
  require(emitted.size() == 1U && emitted[0].port == 0U && next_header_error &&
              next_header_error->type ==
                  packet::icmpv6_parameter_problem_type &&
              next_header_error->code ==
                  packet::icmpv6_parameter_unknown_next_header_code &&
              next_header_error->parameter == 6U,
          "unknown local IPv6 Next Header did not return its field pointer");
  emitted.clear();
  auto hop_one6 = echo6;
  hop_one6.bytes[21] = 1;
  forwarder6->receive(0, hop_one6, &emitted, collect, checkpoint_now);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "IPv6 Hop Limit expiry did not use the reverse route");
  const auto hop_error6 = packet::parse_icmpv6(emitted[0].frame);
  require(hop_error6 && hop_error6->type == 3U && hop_error6->code == 0U,
          "IPv6 Hop Limit expiry did not produce Time Exceeded");

  emitted.clear();
  const auto oversized6 = packet::icmpv6_echo(host_a, router_a, host6_a,
                                              host6_b, false, 32, 64, 1300);
  forwarder6->receive(0, oversized6, &emitted, collect, checkpoint_now);
  require(emitted.size() == 1 && emitted[0].port == 0,
          "oversized IPv6 packet did not return Packet Too Big");
  const auto mtu_error6 = packet::parse_icmpv6(emitted[0].frame);
  require(mtu_error6 && mtu_error6->type == 2U &&
              mtu_error6->parameter == 1300U,
          "IPv6 Packet Too Big carried an incorrect next-hop MTU");

  // Locally originated IPv6 must honor the first-hop MTU before transmission.
  // The already learned port-1 neighbor makes every collected frame an actual
  // link emission rather than an unresolved packet hidden in ND state.
  emitted.clear();
  require(forwarder6->originate_ipv6_echo(host6_b, 40U, &emitted, collect,
                                          checkpoint_now, 1'300U),
          "large local IPv6 Echo could not enter the source packetizer");
  require(emitted.size() == 2U &&
              packet::parse_ipv6(emitted[0].frame)->fragment.has_value() &&
              packet::parse_ipv6(emitted[1].frame)->fragment.has_value(),
          "IPv6 source did not fragment at its first-hop MTU");

  // A checksum-valid PTB that quotes other traffic must not poison this path.
  const auto unrelated = packet::icmpv6_echo(
      router_b, host_b, port6_b.ipv6_address, host6_b, false, 99U,
      device_catalog::default_ip_hop_limit, 1'300U);
  const auto forged_ptb = packet::icmpv6_packet_too_big(
      unrelated, host_b, router_b, host6_b, port6_b.ipv6_address, 1'280U);
  require(forged_ptb.has_value(), "forged PTB fixture could not be encoded");
  forwarder6->receive(1U, *forged_ptb, &emitted, collect, checkpoint_now);
  require(snapshot(*forwarder6, checkpoint_now)->ipv6_path_mtu.empty(),
          "unrelated PTB quote changed local Path MTU state");

  const auto valid_ptb =
      packet::icmpv6_packet_too_big(emitted[0].frame, host_b, router_b, host6_b,
                                    port6_b.ipv6_address, 1'280U);
  require(valid_ptb.has_value(), "valid PTB fixture could not be encoded");
  forwarder6->receive(1U, *valid_ptb, &emitted, collect, checkpoint_now);
  const auto pmtu_checkpoint = snapshot(*forwarder6, checkpoint_now);
  const auto ptb_outcome = forwarder6->ipv6_echo_outcome(40U);
  require(pmtu_checkpoint->ipv6_path_mtu.size() == 1U &&
              pmtu_checkpoint->ipv6_path_mtu[0].mtu == 1'280U &&
              pmtu_checkpoint->ipv6_probe_packets.empty() &&
              pmtu_checkpoint->ipv6_echo_error_valid &&
              pmtu_checkpoint->ipv6_echo_error_sequence == 40U &&
              (ptb_outcome & 0xffU) == 2U &&
              static_cast<std::uint8_t>(ptb_outcome >> 8U) ==
                  packet::icmpv6_packet_too_big_type &&
              static_cast<std::uint32_t>(ptb_outcome >> 24U) == 1'280U,
          "validated PTB did not reduce checkpointed Path MTU");

  emitted.clear();
  require(forwarder6->originate_ipv6_echo(host6_b, 41U, &emitted, collect,
                                          checkpoint_now, 1'300U) &&
              emitted.size() == 2U,
          "cached Path MTU prevented a valid fragmented retransmission");
  for (const auto &candidate : emitted) {
    const auto parsed = packet::parse_ipv6(candidate.frame);
    require(parsed &&
                packet::ipv6_header_octets + parsed->payload_length <= 1'280U,
            "source fragment exceeded the validated Path MTU");
  }

  // RFC 8201 allows a conservative upward experiment after ten minutes. The
  // 1,252-byte Echo payload makes the complete IPv6 packet exactly 1,300
  // octets, so a successful unfragmented exchange is evidence for that value.
  // A reply with another sequence from the same host must not promote it.
  const auto upward_probe_at =
      checkpoint_now + device_catalog::ipv6_pmtu_probe_interval;
  emitted.clear();
  require(forwarder6->originate_ipv6_echo(host6_b, 42U, &emitted, collect,
                                          upward_probe_at, 1'252U) &&
              emitted.size() == 1U &&
              !packet::parse_ipv6(emitted.front().frame)->fragment,
          "due IPv6 PMTU experiment was not emitted as one larger packet");
  const auto wrong_sequence_reply = packet::icmpv6_echo(
      host_b, router_b, host6_b, port6_b.ipv6_address, true, 43U,
      device_catalog::default_ip_hop_limit, 1'252U);
  forwarder6->receive(1U, wrong_sequence_reply, &emitted, collect,
                      upward_probe_at + std::chrono::milliseconds{1});
  require(snapshot(*forwarder6,
                   upward_probe_at + std::chrono::milliseconds{1})
                  ->ipv6_path_mtu.front()
                  .mtu == 1'280U,
          "an unrelated Echo generation raised IPv6 Path MTU");

  // Re-emit at the next permitted interval because the unrelated reply closes
  // the previous CLI generation without proving the candidate. The exact
  // response then publishes the new estimate and clears its candidate state.
  const auto retry_probe_at =
      upward_probe_at + device_catalog::ipv6_pmtu_probe_interval;
  emitted.clear();
  require(forwarder6->originate_ipv6_echo(host6_b, 44U, &emitted, collect,
                                          retry_probe_at, 1'252U) &&
              emitted.size() == 1U,
          "IPv6 PMTU experiment could not retry after its safe interval");
  const auto successful_reply = packet::icmpv6_echo(
      host_b, router_b, host6_b, port6_b.ipv6_address, true, 44U,
      device_catalog::default_ip_hop_limit, 1'252U);
  forwarder6->receive(1U, successful_reply, &emitted, collect,
                      retry_probe_at + std::chrono::milliseconds{1});
  const auto raised_pmtu = snapshot(
      *forwarder6, retry_probe_at + std::chrono::milliseconds{1});
  const auto successful_outcome = forwarder6->ipv6_echo_outcome(44U);
  require(raised_pmtu->ipv6_path_mtu.front().mtu == 1'300U &&
              raised_pmtu->ipv6_path_mtu.front().probe_mtu == 0U &&
              (successful_outcome & 0xffU) == 1U &&
              (successful_outcome >> 8U) == 1'000'000U &&
              raised_pmtu->ipv6_echo_reply_rtt_nanoseconds == 1'000'000U,
          "matching IPv6 Echo success did not confirm the larger Path MTU");

  // RA is configured only after link-local DAD completes. Timer expiry emits a
  // complete multicast frame, and a received RS influences only this port's
  // local deadline rather than invoking a host or topology object directly.
  packet::nd::RouterAdvertisementConfig ra_config{.router_lifetime_seconds =
                                                      1'800U,
                                                  .advertised_mtu = 1'500U,
                                                  .prefix_count = 1U};
  ra_config.prefixes[0] = {
      .prefix = {.network = address6("2001:db8:10::"), .length = 64U},
      .valid_lifetime_seconds = 86'400U,
      .preferred_lifetime_seconds = 14'400U,
      .on_link = true,
      .autonomous = true};
  const auto ra_configured_at = checkpoint_now + std::chrono::seconds{5};
  require(forwarder6->configure_router_advertisement(0U, true, ra_config,
                                                     ra_configured_at),
          "forwarder rejected valid RA configuration");
  emitted.clear();
  forwarder6->service_ipv6_maintenance(
      &emitted, collect,
      ra_configured_at + device_catalog::ra_max_initial_advertisement_interval);
  const auto timed_ra =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        return candidate.port == 0U &&
               packet::nd::parse_router_advertisement(candidate.frame)
                   .has_value();
      });
  require(timed_ra != emitted.end(),
          "RA timer did not emit a valid multicast advertisement");

  emitted.clear();
  const auto rs = packet::nd::router_solicitation(host_a, host6_a);
  const auto rs_received_at =
      ra_configured_at + device_catalog::ra_max_initial_advertisement_interval;
  forwarder6->receive(0U, rs, &emitted, collect, rs_received_at);
  require(emitted.empty(),
          "RS response bypassed the required randomized delay");
  forwarder6->service_ipv6_maintenance(
      &emitted, collect,
      rs_received_at + device_catalog::ra_min_delay_between_advertisements +
          device_catalog::ra_max_response_delay);
  const auto solicited_ra =
      std::find_if(emitted.begin(), emitted.end(), [](const auto &candidate) {
        return candidate.port == 0U &&
               packet::nd::parse_router_advertisement(candidate.frame)
                   .has_value();
      });
  require(solicited_ra != emitted.end(),
          "RS did not schedule an encoded RA response");

  const auto local_large_echo = packet::icmpv6_echo(
      host_a, router_a, host6_a, port6_a.ipv6_address, false, 52U,
      device_catalog::default_ip_hop_limit, 3'000U);
  const auto local_fragments = packet::fragment_ipv6(
      local_large_echo, packet::ipv6_minimum_link_mtu, 0x3456789aU);
  require(local_fragments && local_fragments->count == 3U,
          "local reassembly fixture did not produce three fragments");
  emitted.clear();
  forwarder6->receive(0U, local_fragments->frames[2], &emitted, collect,
                      checkpoint_now);
  require(emitted.empty() &&
              snapshot(*forwarder6, checkpoint_now)->ipv6_reassembly.size() ==
                  1U,
          "local IPv6 endpoint delivered an incomplete fragment set");

  require(forwarder6->configure_ike_udp() &&
              forwarder6->ike_udp_socket(transport::IpFamily::ipv4, false) &&
              forwarder6->ike_udp_socket(transport::IpFamily::ipv6, true),
          "router forwarding owner did not bind IKE UDP listeners");
  auto checkpoint6 = snapshot(*forwarder6, checkpoint_now);
  auto restored6 = std::make_unique<RouterForwarder>();
  require(!checkpoint6->ipv6_router_advertisements.empty() &&
              !checkpoint6->ipv6_path_mtu.empty() &&
              checkpoint6->ipv6_reassembly.size() == 1U &&
              !checkpoint6->ipv6_probe_valid &&
              checkpoint6->ike_udp.configured &&
              restored6->restore(*checkpoint6, checkpoint_now) &&
              restored6->program_ipv6_fib(checkpoint6->ipv6_fib) &&
              restored6->ipv6_neighbor_entries() ==
                  forwarder6->ipv6_neighbor_entries() &&
              restored6->ike_udp_socket(transport::IpFamily::ipv4, true) &&
              restored6->ike_udp_socket(transport::IpFamily::ipv6, false) &&
              restored6->next_ipv6_deadline().has_value(),
          "IPv6 FIB, Neighbor Cache or RA timer did not survive checkpoint");

  emitted.clear();
  restored6->receive(0U, local_fragments->frames[1], &emitted, collect,
                     checkpoint_now);
  restored6->receive(0U, local_fragments->frames[0], &emitted, collect,
                     checkpoint_now);
  require(snapshot(*restored6, checkpoint_now)->ipv6_reassembly.empty(),
          "restored local IPv6 fragment set remained incomplete");
  const auto contains_restored_reply = [&]() {
    packet::Ipv6ReassemblyTable host_reassembly;
    for (const auto &candidate : emitted) {
      const auto ipv6_packet = packet::parse_ipv6(candidate.frame);
      if (!ipv6_packet || ipv6_packet->destination != host6_a)
        continue;
      if (!ipv6_packet->fragment) {
        const auto icmp = packet::parse_icmpv6(candidate.frame);
        if (icmp && icmp->type == packet::icmpv6_echo_reply_type &&
            icmp->sequence == 52U)
          return true;
        continue;
      }
      const auto result =
          host_reassembly.accept(candidate.frame, checkpoint_now);
      if (!result.packet.empty()) {
        const auto icmp = packet::parse_icmpv6(result.packet);
        if (icmp && icmp->type == packet::icmpv6_echo_reply_type &&
            icmp->sequence == 52U)
          return true;
      }
    }
    return false;
  };
  if (!contains_restored_reply()) {
    const auto relearn = packet::nd::neighbor_advertisement(
        host_a, router_a, host6_a, port6_a.ipv6_link_local, host6_a, false,
        true, true);
    restored6->receive(0U, relearn, &emitted, collect, checkpoint_now);
  }
  require(contains_restored_reply(),
          "restored local IPv6 fragments did not produce one Echo Reply");

  // Operational ICMPv6 counters are driven by the same received and generated
  // frames used above. Eleven admitted Redirects and one rate rejection give
  // stable assertions without injecting counter state through a test hook.
  const auto statistics_checkpoint = snapshot(*forwarder6, checkpoint_now);
  const auto port_zero_statistics =
      std::find_if(statistics_checkpoint->icmpv6_interface_statistics.begin(),
                   statistics_checkpoint->icmpv6_interface_statistics.end(),
                   [](const auto &entry) { return entry.port_ordinal == 0U; });
  require(port_zero_statistics !=
                  statistics_checkpoint->icmpv6_interface_statistics.end() &&
              port_zero_statistics->statistics.sent.redirects == 11U &&
              port_zero_statistics->statistics.sent.discarded == 1U &&
              statistics_checkpoint->icmpv6_global_statistics.sent.redirects ==
                  11U &&
              statistics_checkpoint->icmpv6_global_statistics.sent.discarded ==
                  1U,
          "real Redirect traffic did not update ICMPv6 operational counters");

  auto statistics_restored = std::make_unique<RouterForwarder>();
  require(
      statistics_restored->restore(*statistics_checkpoint, checkpoint_now) &&
          statistics_restored->icmpv6_global_statistics() ==
              statistics_checkpoint->icmpv6_global_statistics,
      "ICMPv6 operational counters did not survive checkpoint restore");
  const auto restored_ra_statistics =
      statistics_restored->icmpv6_interface_statistics(0U);
  require(restored_ra_statistics.has_value(),
          "RA counter fixture lost its configured interface");
  statistics_restored->clear_router_advertisement_statistics_all();
  const auto after_ra_clear =
      statistics_restored->icmpv6_interface_statistics(0U);
  const auto after_ra_checkpoint =
      snapshot(*statistics_restored, checkpoint_now);
  const auto after_ra_times =
      std::find_if(after_ra_checkpoint->icmpv6_interface_statistics.begin(),
                   after_ra_checkpoint->icmpv6_interface_statistics.end(),
                   [](const auto &entry) { return entry.port_ordinal == 0U; });
  require(
      after_ra_clear.has_value() &&
          after_ra_clear->sent.router_advertisement == 0U &&
          after_ra_clear->sent.neighbor_solicitation == 0U &&
          after_ra_clear->sent.neighbor_advertisement == 0U &&
          after_ra_clear->sent.redirects ==
              restored_ra_statistics->sent.redirects &&
          after_ra_times !=
              after_ra_checkpoint->icmpv6_interface_statistics.end() &&
          after_ra_times->router_advertisement_last_sent_ago_nanoseconds ==
              -1 &&
          after_ra_times->neighbor_solicitation_last_sent_ago_nanoseconds ==
              -1 &&
          after_ra_times->neighbor_advertisement_last_sent_ago_nanoseconds ==
              -1,
      "RA clear erased unrelated ICMPv6 counters or retained send ages");
  const auto interface_before_global_clear =
      statistics_restored->icmpv6_interface_statistics(0U);
  statistics_restored->clear_icmpv6_global_statistics();
  require(statistics_restored->icmpv6_global_statistics() ==
                  Icmpv6Statistics{} &&
              statistics_restored->icmpv6_interface_statistics(0U) ==
                  interface_before_global_clear,
          "global ICMPv6 clear changed independent interface statistics");
  require(
      statistics_restored->clear_icmpv6_interface_statistics(0U) &&
          statistics_restored->icmpv6_interface_statistics(0U) ==
              Icmpv6Statistics{} &&
          !statistics_restored->clear_icmpv6_interface_statistics(799U),
      "interface ICMPv6 clear accepted an absent interface or retained data");
  statistics_restored->clear_icmpv6_statistics_all();
  require(statistics_restored->icmpv6_interface_statistics(1U) ==
              Icmpv6Statistics{},
          "all ICMPv6 clear retained another interface scope");

  // A removed RA must disappear from the owner's checkpoint, not survive as a
  // disabled entry that could be resurrected when the ordinal is reused.
  require(forwarder6->remove_router_advertisement(0U) &&
              snapshot(*forwarder6, checkpoint_now)
                  ->ipv6_router_advertisements.empty(),
          "explicit RA removal retained forwarding-owned timer state");
}
