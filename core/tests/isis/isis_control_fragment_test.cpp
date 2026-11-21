// Two real protocol owners fragment their own accepted parallel P2P links.
// Encoded Hellos/LSPs/SNPs cross port queues and physical fabric; the test
// owns forwarding only and observes value projections from the control owner.
#include "router/isis_control_worker.hpp"
#include "router/isis_lsp_builder.hpp"
#include "router/multi_device_fabric.hpp"
#include <array>
#include <memory>
#include <source_location>
#include <stdexcept>
#include <string>
namespace {
using namespace router;
using namespace router::isis;
using namespace std::chrono_literals;
constexpr std::uint16_t ports{18U};
constexpr std::uint16_t originating_mtu{512U};
void require(bool value, std::source_location where = std::source_location::current()) {
  if (!value) throw std::runtime_error("IS-IS physical fragment invariant at " + std::to_string(where.line()));
}
P2pCircuitConfiguration hello(std::uint8_t node, std::uint8_t port) {
  P2pCircuitConfiguration result;
  result.local = {{1U, 2U, 3U, 4U, 5U, node}, static_cast<std::uint32_t>(port) + 1U, static_cast<std::uint8_t>(port + 1U), Levels::level1, true};
  result.mac = {2U, 0U, 0U, 0U, node, port};
  result.hello_destination = {1U, 0x80U, 0xc2U, 0U, 0U, 0x14U};
  NeighborArea area; area.bytes = {0x49U, 0U, 1U}; area.length = 3U;
  result.areas.push_back(area);
  result.protocols.push_back(packet::isis::ipv4_nlpid);
  result.ipv4_addresses.push_back({192U, 0U, 2U, node});
  result.maximum_area_addresses = 3U;
  result.holding_seconds = 3U;
  result.hello_interval = 1s;
  result.maximum_pdu_octets = 1492U;
  result.peer_attribute_octets = 512U;
  return result;
}
}
void isis_control_fragment_tests() {
  auto channels = std::make_unique<ControlChannels>();
  auto worker = std::make_unique<ControlWorker>(*channels, 1U, 2U * ports);
  auto fabric = std::make_unique<lab::MultiDeviceFabric>();
  std::uint64_t next{};
  const auto command = [&](ControlCommand value) {
    value.id = ++next;
    const auto deadline = RuntimeClock::now() + 3s;
    while (!worker->submit(std::move(value))) { require(RuntimeClock::now() < deadline); std::this_thread::yield(); }
    ControlResult result;
    while (!worker->read(result)) { require(RuntimeClock::now() < deadline); std::this_thread::yield(); }
    require(result.id == next);
    return result;
  };
  std::array<std::array<CircuitIdentity, ports>, 2U> identities{};
  for (std::uint16_t node{}; node < 2U; ++node) {
    ControlCommand registration;
    registration.kind = ControlCommandKind::register_device;
    registration.identity.device = {node, 1U};
    require(command(std::move(registration)).error == ControlError::none);
    const UpdateLevelConfiguration level{{64U, 65536U}, 32U, 128U, 1492U, 1200U, 60s, 60s,
        false, false, false, PurgeRules::iso_10589};
    UpdateInstanceProgram program{hello(static_cast<std::uint8_t>(node + 1U), 0U).local.system,
        3U, {level, std::nullopt}, ports, {1U, 1U, 10U, 1s, 10U, 1492U, 1U}};
    program.origination.emplace();
    program.origination->resource_retry = 100ms;
    program.origination->neighbors.emplace();
    auto &local = program.origination->content;
    local.random = node + 17U;
    local.levels[0U] = LocalLspLevelProgram{1200U, originating_mtu, 1s, 40s};
    packet::isis::LspId root{};
    std::copy(program.local.begin(), program.local.end(), root.begin());
    local.records.push_back({0U, root, 1U, {1U, 4U, 3U, 0x49U, 0U, 1U}});
    for (std::uint16_t port{}; port < ports; ++port)
      program.origination->neighbors->push_back({port + 1U, {P2pOriginMetric{10U, std::uint8_t{10U}}, std::nullopt}});
    ControlCommand add_instance;
    add_instance.kind = ControlCommandKind::add_update_instance;
    add_instance.identity.device = {node, 1U};
    add_instance.update.emplace(std::move(program));
    require(command(std::move(add_instance)).error == ControlError::none);
    for (std::uint16_t port{}; port < ports; ++port) {
      identities[node][port] = {{node, 1U}, port + 1U, 7U, port, 0U};
      ControlCommand add;
      add.kind = ControlCommandKind::add_p2p_circuit;
      add.identity = identities[node][port];
      add.configuration = hello(static_cast<std::uint8_t>(node + 1U), static_cast<std::uint8_t>(port));
      add.random_state = 17U + node * 4U + port;
      require(command(std::move(add)).error == ControlError::none);
    }
  }
  for (std::uint16_t port{}; port < ports; ++port)
    require(fabric->configure({port, 1U}, {lab::node(identities[0U][port].device), port, 1U},
        {lab::node(identities[1U][port].device), port, 1U}, 1'000'000'000U, 100ns, true));
  struct Delivery {
    ControlChannels &channels;
    ControlWorker &worker;
    std::array<bool, 2U> nonzero{};
    bool large_snp{};
    std::array<unsigned, 33U> transit_received{}, transit_refused{};
  } delivery{*channels, *worker};
  const auto receive = +[](void *opaque, const lab::MultiDeviceFabric::Delivery &frame) {
    auto &context = *static_cast<Delivery *>(opaque);
    packet::isis::EthernetDecodeError error{};
    const auto decoded = packet::isis::parse_ethernet_pdu(frame.frame.view(), error);
    require(decoded.has_value());
    const auto type = decoded->pdu.type;
    if (type == packet::isis::PduType::csnp_l1 || type == packet::isis::PduType::csnp_l2 ||
        type == packet::isis::PduType::psnp_l1 || type == packet::isis::PduType::psnp_l2) {
      require(decoded->pdu.bytes.size() <= originating_mtu);
      context.large_snp = context.large_snp || decoded->pdu.bytes.size() >= 450U;
    }

    if (const auto header = packet::isis::lsp(decoded->pdu); header && header->remaining_seconds) {
      require(decoded->pdu.bytes.size() <= originating_mtu && packet::isis::valid_lsp_checksum(decoded->pdu));
      if (header->id[7U]) context.nonzero[frame.destination.node.index] = true;
      packet::isis::TlvCursor options(decoded->pdu.tlvs);
      while (const auto option = options.next()) if (option->code == 1U) require(!header->id[6U] && !header->id[7U]);
    }
    const auto port = frame.destination.ordinal;
    const bool admitted = context.channels.ingress[0U].try_send(
        {{frame.destination.node.index, 1U}, port + 1U, port, 7U}, frame.frame);
    if (const auto lsp = packet::isis::lsp(decoded->pdu); lsp && lsp->id[4U] == 0xa5U &&
        lsp->id[5U] < context.transit_received.size() && frame.destination.node.index == 1U) {
      ++context.transit_received[lsp->id[5U]];
      if (!admitted) ++context.transit_refused[lsp->id[5U]];
    }
    context.worker.notify();
  };
  const auto pump = [&] {
    while (const auto frame = channels->egress[0U].try_receive()) {
      const auto port = frame->metadata.physical_port_ordinal;
      require(port < ports);
      const bool accepted = fabric->enqueue({port, 1U}, static_cast<std::uint8_t>(frame->metadata.device.index),
          *frame->frame) == lab::MultiDeviceFabric::DropReason::none;
      require(channels->egress[0U].release(frame->handle, accepted));
      worker->notify();
    }
    fabric->pump_transmit();
    fabric->pump_delivery(&delivery, receive);
  };
  const auto selected = [&](std::uint16_t device, std::uint8_t fragment) {
    ControlCommand query;
    query.kind = ControlCommandKind::query_update_instance;
    query.identity.device = {device, 1U};
    query.selected_lsp = packet::isis::LspId{1U, 2U, 3U, 4U, 5U, static_cast<std::uint8_t>(2U - device), 0U, fragment};
    return command(std::move(query));
  };
  auto deadline = RuntimeClock::now() + 8s;
  for (;;) {
    pump();
    bool complete{true};
    for (std::uint16_t node{}; node < 2U; ++node) {
      const auto root = selected(node, 0U), fragment = selected(node, 1U);
      complete = complete && root.selected_lsp && fragment.selected_lsp && root.selected_lsp_links && fragment.selected_lsp_links &&
          root.selected_lsp->remaining_seconds && fragment.selected_lsp->remaining_seconds &&
          root.selected_lsp_links->narrow + fragment.selected_lsp_links->narrow == ports &&
          root.selected_lsp_links->wide + fragment.selected_lsp_links->wide == ports && delivery.nonzero[node];
    }
    if (complete) break;
    require(RuntimeClock::now() < deadline);
    std::this_thread::yield();
  }
  // Real carrier loss stops one port queue. The neighbors expire through their
  // own holding timers; higher fragments are then purged over surviving links.
  require(fabric->configure({ports - 1U, 1U}, {lab::node(identities[0U][ports - 1U].device), ports - 1U, 1U},
      {lab::node(identities[1U][ports - 1U].device), ports - 1U, 1U}, 1'000'000'000U, 100ns, false));
  deadline = RuntimeClock::now() + 8s;
  for (;;) {
    pump();
    bool complete{true};
    for (std::uint16_t node{}; node < 2U; ++node) {
      const auto root = selected(node, 0U), fragment = selected(node, 1U);
      complete = complete && root.selected_lsp_links == std::optional{LspLinkCounts{ports - 1U, ports - 1U}} &&
          fragment.selected_lsp && !fragment.selected_lsp->remaining_seconds;
    }
    if (complete) break;
    require(RuntimeClock::now() < deadline);
    std::this_thread::yield();
  }
  // Transit advertisements need no direct adjacency to their originating IS.
  // Each encoded root enters over an actual Up peer link and is observed only
  // through the receiving owner's query interface. The resulting complete SNP
  // set exceeds one 512-byte PDU and must use multiple bounded ranges.
  auto scratch = std::make_unique<PduScratch>();
  auto frame = std::make_unique<packet::Frame>();
  const std::array<std::uint8_t, 9U> options{1U, 4U, 3U, 0x49U, 0U, 1U, 129U, 1U, packet::isis::ipv4_nlpid};
  for (std::uint8_t origin{1U}; origin <= 32U; ++origin) {
    LspContents contents;
    contents.header = {packet::isis::PduType::lsp_l1, {1U, 2U, 3U, 4U, 0xa5U, origin, 0U, 0U}, 1200U, 1U, 1U};
    contents.options = options;
    contents.maximum_pdu_octets = originating_mtu;
    const auto built = build_lsp_pdu(contents, scratch->options, scratch->pdu);
    require(built.status == LspBuildStatus::encoded && packet::isis::ethernet_pdu_into(*frame,
        hello(1U, 0U).mac, hello(1U, 0U).hello_destination, built.bytes));
    require(fabric->enqueue({0U, 1U}, 0U, *frame) == lab::MultiDeviceFabric::DropReason::none);
    deadline = RuntimeClock::now() + 3s;
    // This external transit source has no local LSDB owner in the fixture.
    // Repeat its unchanged encoded LSP at the configured retransmit interval:
    // a full physical ingress queue may drop the first frame legitimately.
    // Every attempt still crosses the same port queue and physical link.
    auto retransmit_at = RuntimeClock::now() + 1s;
    for (;;) {
      pump();
      const auto now = RuntimeClock::now();
      if (now >= retransmit_at) {
        require(fabric->enqueue({0U, 1U}, 0U, *frame) == lab::MultiDeviceFabric::DropReason::none);
        retransmit_at = now + 1s;
      }
      ControlCommand query;
      query.kind = ControlCommandKind::query_update_instance;
      query.identity.device = {1U, 1U};
      query.selected_lsp = contents.header.id;
      const auto received = command(std::move(query));
      if (received.selected_lsp) break;
      if (RuntimeClock::now() >= deadline) {
        ControlCommand circuit_query;
        circuit_query.kind = ControlCommandKind::query_circuit;
        circuit_query.identity = identities[1U][0U];
        const auto circuit = command(std::move(circuit_query));
        throw std::runtime_error("IS-IS transit fragment missing: origin=" + std::to_string(origin) +
            " instance=" + std::to_string(static_cast<unsigned>(received.update_status)) +
            " receive=" + std::to_string(static_cast<unsigned>(circuit.counters.last_update)) +
            " discarded=" + std::to_string(circuit.counters.update_discarded) +
            " delivered=" + std::to_string(delivery.transit_received[origin]) +
            " refused=" + std::to_string(delivery.transit_refused[origin]));
      }
      std::this_thread::yield();
    }
  }
  deadline = RuntimeClock::now() + 12s;
  while (!delivery.large_snp) {
    pump();
    require(RuntimeClock::now() < deadline);
    std::this_thread::yield();
  }
  worker->stop();
}
