// Forwarding accepts IS-IS only through port-local LLC/multicast projection.
// Fixtures contain real encoded PDUs and an interface with neither IP family.

#include "router/isis_ethernet.hpp"
#include "router/router_forwarder.hpp"

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
struct Observed {
  std::vector<router::packet::Frame> emitted;
  unsigned punts{};
};
bool collect(void *opaque, std::uint16_t port, const router::packet::Frame &frame) {
  require(port == 0U, "IS-IS changed the physical egress port");
  static_cast<Observed *>(opaque)->emitted.push_back(frame);
  return true;
}
void punt(void *opaque, std::uint16_t port, const router::packet::Frame &) {
  require(port == 0U, "IS-IS changed the physical ingress port");
  ++static_cast<Observed *>(opaque)->punts;
}
}

void router_forwarder_isis_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::packet::isis;
  auto forwarder = std::make_unique<RouterForwarder>();
  const packet::Mac group{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  const packet::Mac local{2U, 0U, 0U, 0U, 0U, 1U};
  const packet::Mac peer{2U, 0U, 0U, 0U, 0U, 2U};
  ForwardPort port;
  port.configured = true;
  port.operational = true;
  port.ordinal = 0U;
  port.mtu = 1514U;
  port.speed_mbps = 1000U;
  port.mac = local;
  port.ipv4_configured = false;
  require(forwarder->configure_port(port), "IS-IS forwarding port setup failed");
  std::array<std::uint8_t, 2048U> bytes{};
  const HelloInput input{PduType::point_to_point_hello, {1U, 2U, 3U, 4U, 5U, 6U}, 30U, 3U, 1U};
  const auto hello = encode_hello(bytes, input, {});
  packet::Frame frame{};
  require(hello && ethernet_pdu_into(frame, peer, group, *hello), "IS-IS forwarding Hello fixture failed");
  Observed observed;
  const auto now = RouterForwarder::Clock::now();
  const auto receive = [&](const packet::Frame &wire) {
    forwarder->receive(0U, wire, &observed, collect, now, &observed, punt);
  };
  receive(frame);
  require(observed.punts == 0U && !forwarder->originate_isis(0U, frame, &observed, collect),
          "IS-IS entered an unprogrammed interface");
  const std::array<packet::Mac, 2U> groups{group, group};
  require(forwarder->configure_isis_punt(0U, groups), "IS-IS multicast projection failed");
  receive(frame);
  require(observed.punts == 1U && observed.emitted.empty(), "IS-IS failed to punt without IP addressing");
  const std::array<packet::Mac, 1U> invalid{peer};
  require(!forwarder->configure_isis_punt(0U, invalid) && !forwarder->configure_isis_punt(1U, groups),
          "IS-IS accepted unicast or an unconfigured physical port");
  receive(frame);
  require(observed.punts == 2U, "IS-IS rejected projection destroyed previous membership");
  auto malformed = frame;
  malformed.bytes[17U] = 0x81U;
  receive(malformed);
  malformed = frame;
  malformed.bytes[15U] = 0xffU;
  receive(malformed);
  require(observed.punts == 2U, "IS-IS punt accepted a different NLPID or SAP");
  malformed = frame;
  malformed.bytes[18U] = 1U;
  receive(malformed);
  require(observed.punts == 3U, "IS-IS malformed PDU could not reach protocol error accounting");
  require(!forwarder->originate_isis(0U, malformed, &observed, collect),
          "IS-IS transmitted a malformed locally generated PDU");
  require(!forwarder->originate_isis(0U, frame, &observed, collect) && observed.emitted.empty(),
          "IS-IS forwarding repaired an obsolete or incorrect local MAC projection");
  packet::Frame outbound;
  require(ethernet_pdu_into(outbound, local, group, *hello) &&
            forwarder->originate_isis(0U, outbound, &observed, collect) && observed.emitted.size() == 1U &&
            std::equal(outbound.view().begin(), outbound.view().end(), observed.emitted.front().view().begin(),
                observed.emitted.front().view().end()),
          "IS-IS forwarding changed the protocol owner's encoded frame");
  const auto refuse = +[](void *, std::uint16_t, const packet::Frame &) { return false; };
  require(!forwarder->originate_isis(0U, outbound, nullptr, refuse), "IS-IS bypassed outbound queue refusal");
  std::array<std::uint8_t, 1600U> padding{};
  TlvWriter writer(padding);
  require(writer.pad_to(padding.size()), "IS-IS oversized fixture padding failed");
  const auto large = encode_hello(bytes, input, writer.bytes());
  packet::Frame jumbo{};
  require(large && ethernet_pdu_into(jumbo, local, group, *large) &&
            !forwarder->originate_isis(0U, jumbo, &observed, collect) && observed.emitted.size() == 1U,
          "IS-IS oversized PDU bypassed the physical port MTU");
  require(forwarder->configure_isis_punt(0U, {}), "IS-IS membership removal failed");
  receive(frame);
  require(observed.punts == 3U, "IS-IS disabled membership still punted frames");
  require(forwarder->configure_isis_punt(0U, groups), "IS-IS membership restoration failed");
  forwarder->remove_port(0U);
  require(forwarder->configure_port(port), "IS-IS replacement physical port failed");
  receive(frame);
  require(observed.punts == 3U, "IS-IS replacement port inherited a stale multicast generation");
  require(forwarder->configure_isis_punt(0U, groups), "IS-IS replacement membership failed");
  port.operational = false;
  require(forwarder->configure_port(port), "IS-IS carrier-loss projection failed");
  receive(frame);
  require(observed.punts == 3U && !forwarder->originate_isis(0U, frame, &observed, collect),
          "IS-IS bypassed a nonoperational physical interface");
  port.operational = true;
  require(forwarder->configure_port(port), "IS-IS exchange fixture port recovery failed");
  std::vector<packet::Mac> empty;
  require(forwarder->exchange_isis_punt(0U, empty) && empty == std::vector<packet::Mac>{group},
      "IS-IS projection exchange did not return previous ownership");
  receive(frame);
  require(observed.punts == 3U && forwarder->exchange_isis_punt(0U, empty) && empty.empty(),
      "IS-IS projection rollback lost ownership or retained disabled membership");
  receive(frame);
  require(observed.punts == 4U, "IS-IS projection rollback did not restore packet acceptance");
  std::vector<packet::Mac> duplicate{group, group};
  auto unicast = std::vector<packet::Mac>{peer};
  auto other_group = group;
  ++other_group.back();
  std::vector<packet::Mac> unsorted{other_group, group};
  auto invalid_port = std::vector<packet::Mac>{group};
  require(!forwarder->exchange_isis_punt(0U, duplicate) && duplicate.size() == 2U &&
      !forwarder->exchange_isis_punt(0U, unicast) && unicast.front() == peer &&
      !forwarder->exchange_isis_punt(0U, unsorted) && unsorted.front() == other_group &&
      !forwarder->exchange_isis_punt(1U, invalid_port) && invalid_port.front() == group,
      "IS-IS rejected projection exchange consumed the caller's staged values");
  receive(frame);
  require(observed.punts == 5U, "IS-IS rejected exchange changed the active projection");
}
