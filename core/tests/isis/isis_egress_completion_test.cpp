// A saturated physical link refuses frames after the protocol SPSC accepted
// them. Reverse results keep LAN SRM and PSNP SSN set until the forwarding
// owner admits the corresponding encoded packet to that real port queue.

#include "router/isis_flooding.hpp"
#include "router/isis_basic_tlvs.hpp"
#include "router/isis_snp_builder.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/protocol_packet_channel.hpp"
#include "router/router_forwarder.hpp"

#include <array>
#include <memory>
#include <stdexcept>

namespace {
void require(bool condition, const char *message) {
  if (!condition) throw std::runtime_error(message);
}
struct Medium {
  router::lab::MultiDeviceFabric &fabric;
  router::lab::LinkHandle link;
  unsigned delivered{};
  bool correct_port{true};
};
bool enqueue(void *opaque, std::uint16_t port, const router::packet::Frame &frame) {
  auto &medium = *static_cast<Medium *>(opaque);
  medium.correct_port = medium.correct_port && port == 0U;
  return medium.fabric.enqueue(medium.link, 0U, frame) == router::lab::MultiDeviceFabric::DropReason::none;
}
void delivered(void *opaque, const router::lab::MultiDeviceFabric::Delivery &delivery) {
  auto &medium = *static_cast<Medium *>(opaque);
  medium.correct_port = medium.correct_port && delivery.destination.node.index == 1U;
  ++medium.delivered;
}
}

void isis_egress_completion_tests() {
  using namespace router;
  using namespace router::isis;
  using namespace router::packet::isis;
  using namespace router::lab;
  using namespace std::chrono_literals;
  using Channel = protocol::PacketChannel<2U, true>;
  auto channel = std::make_unique<Channel>();
  auto fabric = std::make_unique<MultiDeviceFabric>();
  auto forwarder = std::make_unique<RouterForwarder>();
  const LinkHandle link{0U, 1U};
  require(fabric->configure(link, {node(DeviceHandle{0U, 1U}), 0U, 1U},
      {node(DeviceHandle{1U, 1U}), 0U, 1U}, 1'000'000'000U, 100ns, true),
      "IS-IS completion physical link setup failed");
  const packet::Mac local{2U, 0U, 0U, 0U, 0U, 1U};
  const packet::Mac group{1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  ForwardPort port;
  port.configured = true;
  port.operational = true;
  port.ordinal = 0U;
  port.mtu = 1514U;
  port.speed_mbps = 1000U;
  port.mac = local;
  const std::array<packet::Mac, 1U> groups{group};
  require(forwarder->configure_port(port) && forwarder->configure_isis_punt(0U, groups),
          "IS-IS completion physical port programming failed");
  Medium medium{*fabric, link};
  auto now = MultiDeviceFabric::Clock::time_point{100s};
  const auto drain = [&](std::size_t turns) {
    for (std::size_t index = 0U; index < turns; ++index) {
      fabric->pump_transmit(now);
      now += 1ms;
      fabric->pump_delivery(&medium, delivered, now);
    }
    require(fabric->available_packets() == PacketPool::capacity,
            "IS-IS completion fixture retained a physical queue or in-flight frame");
  };
  std::array<std::uint8_t, 256U> options{};
  TlvWriter option_writer(options);
  const std::array<std::uint8_t, 3U> area{0x49U, 0U, 1U};
  const std::array<std::span<const std::uint8_t>, 1U> areas{area};
  require(encode_area_addresses(option_writer, areas), "IS-IS completion area fixture failed");
  std::array<std::uint8_t, 512U> bytes{};
  const LspInput input{PduType::lsp_l1, {1U, 2U, 3U, 4U, 5U, 6U, 0U, 0U}, 1200U, 1U, 3U};
  const auto lsp_wire = encode_lsp(bytes, input, option_writer.bytes());
  packet::Frame frame{};
  require(lsp_wire && ethernet_pdu_into(frame, local, group, *lsp_wire), "IS-IS completion LSP fixture failed");
  FloodCircuit flags{true, true, true, false};
  const auto fill = [&] {
    std::size_t admitted{};
    while (admitted < PacketPool::capacity && fabric->enqueue(link, 0U, frame) == MultiDeviceFabric::DropReason::none)
      ++admitted;
    require(admitted < PacketPool::capacity, "IS-IS completion fixture did not reach a bounded physical queue");
    return admitted;
  };
  std::uint64_t operation{};
  const auto attempt = [&](PduType expected) {
    const auto old_srm = flags.srm;
    const auto old_ssn = flags.ssn;
    require(channel->try_send({{0U, 1U}, ++operation, 0U}, frame), "IS-IS completion protocol queue refused output");
    require(flags.srm == old_srm && flags.ssn == old_ssn, "IS-IS cleared flood flags on control-channel publication");
    const auto borrowed = channel->try_receive();
    require(borrowed.has_value(), "IS-IS forwarding owner could not borrow output");
    const bool enqueued = forwarder->originate_isis(borrowed->metadata.physical_port_ordinal,
        *borrowed->frame, &medium, enqueue);
    require(channel->release(borrowed->handle, enqueued) && channel->producer_available() == 1U,
            "IS-IS completion result was lost or reclaimed before protocol consumption");
    const auto completion = channel->try_completion();
    EthernetDecodeError error{};
    const auto completed_frame = completion ? parse_ethernet_pdu(completion->frame->view(), error) : std::nullopt;
    require(completion && completion->metadata.interface_id == operation && completion->enqueued == enqueued &&
              completed_frame && completed_frame->pdu.type == expected,
            "IS-IS completion did not identify the original encoded packet");
    if (expected == PduType::lsp_l1) lsp_transmitted(flags, completion->enqueued);
    else psnp_transmitted(flags, completion->enqueued);
    return enqueued;
  };
  const auto full = fill();
  require(full != 0U && !attempt(PduType::lsp_l1) && flags.srm,
          "IS-IS LAN cleared SRM after a saturated physical queue refused the LSP");
  drain(full + 4U);
  require(attempt(PduType::lsp_l1) && !flags.srm,
          "IS-IS LAN did not commit SRM after actual port-queue admission");

  DecodeError decode{};
  const auto lsp_header = lsp(*parse(*lsp_wire, decode));
  const std::array<SnpEntry, 1U> acknowledgements{{{lsp_header->remaining_seconds,
      lsp_header->id, lsp_header->sequence, lsp_header->checksum}}};
  auto scratch = std::make_unique<PduScratch>();
  SnpContents snp;
  snp.header.type = PduType::psnp_l1;
  snp.header.source = {1U, 2U, 3U, 4U, 5U, 6U};
  snp.source = local;
  snp.destination = group;
  snp.entries = acknowledgements;
  snp.maximum_pdu_octets = 1492U;
  require(build_snp_frame(frame, snp, *scratch) == SnpBuildResult::encoded, "IS-IS completion PSNP fixture failed");
  flags.ssn = true;
  const auto full_again = fill();
  require(!attempt(PduType::psnp_l1) && flags.ssn,
          "IS-IS cleared SSN after the port queue refused a PSNP batch");
  drain(full_again + 4U);
  require(attempt(PduType::psnp_l1) && !flags.ssn, "IS-IS failed to commit a physically enqueued PSNP acknowledgement");
  drain(4U);
  require(medium.correct_port && medium.delivered >= full + full_again + 2U && channel->producer_available() == 2U,
          "IS-IS completion path bypassed physical delivery or leaked channel credits");
}
