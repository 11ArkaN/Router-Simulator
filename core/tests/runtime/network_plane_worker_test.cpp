// Worker tests verify real thread startup, SPSC overflow and ordered results.

#include "router/network_plane_worker.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

namespace {

void require(bool condition, const char *message) {
  // The first cross-thread contract failure is preserved by the shared runner.
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void network_plane_worker_tests() {
  using namespace router::lab;
  {
    auto idle_channels = std::make_unique<NetworkPlaneChannels>();
    // NetworkPlaneWorker owns the complete multi-router forwarding arena.
    // Production creates that long-lived owner on the heap, and the Wasm test
    // must exercise the same lifetime instead of placing the arena inside the
    // deliberately small entry-thread stack frame.
    auto idle = std::make_unique<NetworkPlaneWorker>(*idle_channels);
    idle->start();
    const auto startup_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (!idle->running() &&
           std::chrono::steady_clock::now() < startup_deadline)
      std::this_thread::yield();
    const auto before = idle->owner_turns();
    std::this_thread::sleep_for(std::chrono::milliseconds{35});
    const auto after = idle->owner_turns();
    // One spurious condition-variable wake is tolerated. A 10 ms poll would
    // produce at least three turns in this interval and fails this contract.
    if (!idle->running() || after - before > 1U)
      throw std::runtime_error("idle network owner is polling without work");
    idle->stop();
  }

  {
    // DNSSEC wrapping material has a separate two-slot SPSC channel because a
    // consumed generic NetworkCommand slot intentionally retains ordinary
    // bytes for reuse. This test crosses the real pthread boundary and proves
    // exact retry is idempotent while a later key substitution is rejected.
    auto vault_channels = std::make_unique<NetworkPlaneChannels>();
    auto vault_worker = std::make_unique<NetworkPlaneWorker>(*vault_channels);
    vault_worker->start();
    NetworkCommand vault_command{
        .kind = NetworkCommandKind::initialize_signing_vault};
    NetworkSigningVaultInitialize vault_payload;
    std::fill(vault_payload.wrapping_key.begin(),
              vault_payload.wrapping_key.end(), 0x6aU);
    std::fill(vault_payload.project_context_digest.begin(),
              vault_payload.project_context_digest.end(), 0x3cU);
    const auto send_vault = [&](std::uint64_t id) {
      vault_command.id = id;
      require(vault_worker->submit_signing_vault(vault_command, vault_payload),
              "DNSSEC vault command was not admitted");
      const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::seconds{2};
      NetworkResult result;
      while (std::chrono::steady_clock::now() < deadline) {
        if (vault_worker->read(result)) {
          require(result.id == id && result.kind == vault_command.kind,
                  "DNSSEC vault result lost command identity");
          return result.success;
        }
        std::this_thread::yield();
      }
      throw std::runtime_error("DNSSEC vault command timed out");
    };
    require(send_vault(1U),
            "network owner rejected initial DNSSEC vault material");
    require(vault_channels->signing_vault.empty(),
            "network owner retained a consumed DNSSEC secret slot");
    require(send_vault(2U),
            "network owner rejected an exact idempotent vault retry");
    vault_payload.wrapping_key.front() ^= 0xffU;
    require(!send_vault(3U),
            "network owner accepted replacement DNSSEC vault material");
    router::spsc_secure_clear(vault_payload);
    vault_worker->stop();
  }

  // A command can carry a complete, generation-stamped FIB replacement. The
  // ring is consequently a persistent shared-memory arena, not call-local
  // scratch storage. Heap ownership in this test mirrors production and keeps
  // the fixed arena away from WebAssembly's intentionally small call stack.
  auto channels = std::make_unique<NetworkPlaneChannels>();
  auto worker = std::make_unique<NetworkPlaneWorker>(*channels);
  auto command = std::make_unique<NetworkCommand>();
  // Capacity eight deliberately exposes seven usable SPSC entries. Filling it
  // before worker startup makes overflow deterministic and
  // scheduler-independent.
  constexpr auto usable =
      router::device_catalog::network_command_ring_entries - 1U;
  for (std::uint16_t index = 0; index < usable; ++index) {
    command->id = index + 1U;
    command->kind = NetworkCommandKind::add_router;
    command->device = {index, 1};
    if (!worker->submit(*command))
      throw std::runtime_error(
          "network command ring rejected an in-bound entry");
  }
  command->id = router::device_catalog::network_command_ring_entries;
  command->kind = NetworkCommandKind::add_router;
  command->device = {static_cast<std::uint16_t>(usable), 1};
  if (worker->submit(*command))
    throw std::runtime_error("network command ring hid bounded overflow");

  worker->start();
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds{2};
  std::uint64_t expected = 1;
  while (expected <= usable && std::chrono::steady_clock::now() < deadline) {
    NetworkResult result;
    if (!worker->read(result)) {
      std::this_thread::yield();
      continue;
    }
    if (!result.success || result.id != expected++)
      throw std::runtime_error(
          "network worker reordered or rejected a command");
  }
  if (expected != router::device_catalog::network_command_ring_entries ||
      !worker->running())
    throw std::runtime_error(
        "network worker did not execute on its owner thread");
  worker->stop();

  // Relay programming traverses the public control-to-network SPSC channel
  // and the private network-to-forwarding SPSC channel. A separate live worker
  // proves neither boundary relies on vector pointers or a single-thread test
  // shortcut.
  auto relay_channels = std::make_unique<NetworkPlaneChannels>();
  auto relay_worker = std::make_unique<NetworkPlaneWorker>(*relay_channels);
  relay_worker->start();
  std::uint64_t relay_command_id{};
  // Reuse one heap-resident command image for the whole transaction. SPSC
  // publication copies the complete value before send() returns, so later
  // field changes cannot affect an admitted slot.
  auto relay_command = std::make_unique<NetworkCommand>();
  const auto send = [&] {
    relay_command->id = ++relay_command_id;
    if (!relay_worker->submit(*relay_command))
      throw std::runtime_error("relay control command was not admitted");
    const auto result_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{2};
    NetworkResult result;
    while (std::chrono::steady_clock::now() < result_deadline) {
      if (relay_worker->read(result)) {
        if (result.id != relay_command->id ||
            result.kind != relay_command->kind)
          throw std::runtime_error("relay control result lost FIFO identity");
        return result.success;
      }
      std::this_thread::yield();
    }
    throw std::runtime_error("relay control command timed out");
  };
  const DeviceHandle relay_router{0U, 1U};
  const auto parse_ipv6 = [](const char *text) {
    const auto parsed = router::ip::parse_ipv6(text);
    if (!parsed)
      throw std::runtime_error("relay worker fixture address is invalid");
    return *parsed;
  };
  relay_command->kind = NetworkCommandKind::add_router;
  relay_command->device = relay_router;
  require(send(), "relay worker could not create its router owner");
  ForwardPort relay_port{.configured = true,
                         .operational = true,
                         .ordinal = 0U,
                         .mtu = 1'500U,
                         .speed_mbps = 10'000U,
                         .mac = {0x02, 0, 0, 0, 0x71, 1},
                         .ipv6_configured = true,
                         .ipv6_address = parse_ipv6("2001:db8:71::1"),
                         .ipv6_link_local = parse_ipv6("fe80::71:1"),
                         .ipv6_prefix_length = 64U};
  relay_command->kind = NetworkCommandKind::configure_port;
  relay_command->port = relay_port;
  require(send(), "relay worker could not configure its IPv6 ingress");
  // An interface-address generation is streamed because a complete router can
  // own thousands of addresses while the SPSC slot must remain small and
  // bounded. Begin reserves the exact cold-path storage, Add copies one value
  // per owner turn, and Commit is the only operation allowed to publish the
  // generation to forwarding. The checkpoint assertion below proves that the
  // secondary address crossed both pthread boundaries and was not reduced to
  // the primary cache retained in ForwardPort.
  const RouterIpv6Address primary_address{
      .address = parse_ipv6("2001:db8:71::1"),
      .network = parse_ipv6("2001:db8:71::"),
      .interface_id = physical_interface_id(0U),
      .primary_preference = 10U,
      .port_ordinal = 0U,
      .prefix_length = 64U};
  const RouterIpv6Address secondary_address{
      .address = parse_ipv6("2001:db8:72::1"),
      .network = parse_ipv6("2001:db8:72::"),
      .interface_id = physical_interface_id(0U),
      .primary_preference = 20U,
      .tag = 71U,
      .port_ordinal = 0U,
      .prefix_length = 64U,
      .duplicate_address_detection = false,
      .tag_configured = true};
  relay_command->kind = NetworkCommandKind::begin_ipv6_address_generation;
  relay_command->fib = Ipv6AddressGenerationBegin{.expected_addresses = 2U};
  const bool address_begin = send();
  relay_command->kind = NetworkCommandKind::add_ipv6_interface_address;
  relay_command->fib = primary_address;
  const bool primary_add = send();
  relay_command->fib = secondary_address;
  const bool secondary_add = send();
  relay_command->kind = NetworkCommandKind::commit_ipv6_address_generation;
  const bool address_commit = send();
  require(address_begin && primary_add && secondary_add && address_commit,
          "worker did not publish the complete IPv6 address generation");
  const router::service::SapAttachment worker_sap{
      .logical_interface_id = 71'001U,
      .sap = {.port = {.ordinal = 0U, .card = 1U, .mda = 1U, .port = 1U},
              .encapsulation = router::service::EthernetEncapsulation::qinq,
              .outer_vlan = 710U,
              .inner_vlan = 711U},
      .outer_tpid = 0x88a8U,
      .inner_tpid = 0x8100U};
  relay_command->kind = NetworkCommandKind::begin_sap_generation;
  relay_command->fib = SapGenerationBegin{.expected_attachments = 1U};
  const bool sap_begin = send();
  relay_command->kind = NetworkCommandKind::add_sap_attachment;
  relay_command->fib = worker_sap;
  const bool sap_add = send();
  relay_command->kind = NetworkCommandKind::commit_sap_generation;
  const bool sap_commit = send();
  require(sap_begin && sap_add && sap_commit,
          "worker did not publish SAP generation through both SPSC boundaries");
  // Program a configured neighbor through both production SPSC boundaries.
  // The checkpoint readback proves this did not mutate a test-only cache or
  // retain a pointer into the control thread's command scratch value.
  const auto configured_neighbor = parse_ipv6("2001:db8:71::2");
  const router::packet::Mac configured_neighbor_mac{0x02U, 0U,    0U,
                                                    0U,    0x71U, 0x02U};
  relay_command->kind = NetworkCommandKind::install_static_ipv6_neighbor;
  relay_command->fib = StaticIpv6NeighborProgram{.device = relay_router,
                                                 .address = configured_neighbor,
                                                 .mac = configured_neighbor_mac,
                                                 .port_ordinal = 0U};
  require(send(), "worker rejected a valid configured IPv6 neighbor");
  constexpr std::uint32_t interface_id_octets =
      static_cast<std::uint32_t>(dhcpv6_relay_program_chunk_octets * 2U + 17U);
  relay_command->kind = NetworkCommandKind::begin_dhcpv6_relay;
  relay_command->fib = Dhcpv6RelayBegin{
      .interface_id = 71'002U,
      .link_address = parse_ipv6("2001:db8:71::1"),
      .expected_interface_id_octets = interface_id_octets,
      .expected_servers = 1U,
      .upstream_policy =
          router::dhcpv6::RelayUpstreamPolicy::explicit_servers_required};
  require(send(), "relay worker rejected a protocol-valid Begin record");
  std::uint32_t streamed{};
  while (streamed < interface_id_octets) {
    Dhcpv6RelayInterfaceIdChunk chunk;
    chunk.size = static_cast<std::uint16_t>(std::min<std::uint32_t>(
        chunk.octets.size(), interface_id_octets - streamed));
    for (std::uint16_t index = 0; index < chunk.size; ++index)
      chunk.octets[index] =
          static_cast<std::uint8_t>((streamed + index) & 0xffU);
    relay_command->kind = NetworkCommandKind::add_dhcpv6_relay_interface_id;
    relay_command->fib = chunk;
    require(send(), "relay worker rejected an in-range Interface-Id chunk");
    streamed += chunk.size;
  }
  relay_command->kind = NetworkCommandKind::add_dhcpv6_relay_server;
  relay_command->fib = router::dhcpv6::RelayDestination{
      .address = parse_ipv6("2001:db8:72::53")};
  const bool relay_server = send();
  relay_command->kind = NetworkCommandKind::commit_dhcpv6_relay;
  const bool relay_commit = send();
  // Operational clear is a forwarding-owner command even when the selected
  // table is empty. Exercising that idempotent case here proves the complete
  // filter crosses both production SPSC boundaries as a value. In particular,
  // it must not retain a pointer to CLI-owned selector storage or be handled
  // directly by the control worker.
  relay_command->kind = NetworkCommandKind::clear_dhcpv6_relay_leases;
  relay_command->fib = Dhcpv6RelayLeaseClearProgram{
      .filter = {.interface_id = 71'002U}, .no_dhcp_release = false};
  const bool relay_clear = send();
  // The logical interface is part of the owner key. An otherwise valid empty
  // clear against an unknown identity cannot report success because that
  // would hide a stale service-to-forwarding program after reconfiguration.
  relay_command->fib = Dhcpv6RelayLeaseClearProgram{
      .filter = {.interface_id = 71'003U}, .no_dhcp_release = true};
  const bool foreign_relay_clear = send();
  relay_command->kind = NetworkCommandKind::prepare_router_checkpoint;
  const bool checkpoint_prepare = send();
  require(relay_server && relay_commit && relay_clear && !foreign_relay_clear &&
              checkpoint_prepare,
          "relay worker did not preserve clear-command interface ownership");
  const auto *relay_checkpoint = relay_worker->prepared_router_checkpoint();
  require(relay_checkpoint &&
              relay_checkpoint->native_ipv6_addresses.size() == 2U &&
              std::find(relay_checkpoint->native_ipv6_addresses.begin(),
                        relay_checkpoint->native_ipv6_addresses.end(),
                        secondary_address) !=
                  relay_checkpoint->native_ipv6_addresses.end() &&
              relay_checkpoint->dhcpv6_relay_interfaces.size() == 1U &&
              relay_checkpoint->sap_attachments.size() == 1U &&
              relay_checkpoint->sap_attachments.front() == worker_sap &&
              relay_checkpoint->dhcpv6_relay_interfaces[0]
                      .relay_interface_id.size() == interface_id_octets &&
              relay_checkpoint->ipv6_neighbors.size() == 1U &&
              relay_checkpoint->ipv6_neighbors.front().is_static &&
              relay_checkpoint->ipv6_neighbors.front().address ==
                  configured_neighbor &&
              relay_checkpoint->ipv6_neighbors.front().mac ==
                  configured_neighbor_mac,
          "programmed state did not survive both pthread ownership boundaries");
  relay_command->kind = NetworkCommandKind::remove_static_ipv6_neighbor;
  relay_command->port.ordinal = 0U;
  relay_command->ipv6_destination = configured_neighbor;
  const bool neighbor_remove = send();
  relay_command->kind = NetworkCommandKind::prepare_router_checkpoint;
  const bool checkpoint_refresh = send();
  require(
      neighbor_remove && checkpoint_refresh &&
          relay_worker->prepared_router_checkpoint()->ipv6_neighbors.empty(),
      "worker did not remove the configured neighbor from its owner");
  relay_worker->stop();
}
