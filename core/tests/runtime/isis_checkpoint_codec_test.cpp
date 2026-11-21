// Protected codec tests retain cross-platform integer values, signed relative
// times, orphan recovery and both route families. Authenticated malformed lengths
// must fail before allocation or owner publication, independently of tag failures.

#include "router/isis_checkpoint_codec.hpp"

#include <algorithm>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>

void isis_checkpoint_codec_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace std::chrono_literals;
  const auto require = [](bool value, std::source_location where = std::source_location::current()) {
    if (!value) throw std::runtime_error("IS-IS checkpoint codec invariant at " + std::to_string(where.line()));
  };
  auto channels = std::make_unique<isis::ControlChannels>();
  auto saved = std::make_unique<IsisRuntimeCheckpoint>();
  saved->control.barrier_epoch = 19U;
  saved->control.forwarding_shards = 1U;
  saved->control.maximum_circuits = 2U;
  saved->control.devices.reserve(2U);
  auto &device = saved->control.devices.emplace_back();
  device.handle = {0U, 7U};
  device.configuration_epoch = UINT64_MAX;
  device.retired_epoch_floor = std::numeric_limits<std::uint64_t>::max();
  device.update_fences[127U] = std::numeric_limits<std::uint64_t>::max();
  device.route_generation = device.route_pending = 3U;
  device.route_installed = 2U;
  device.route_retry_at = {isis::checkpoint_time::DeadlineKind::relative, -123456789};
  device.route_retry = 37ms;
  std::array<std::optional<isis::SequenceLevelLifetime>, 2U> levels;
  levels[1U] = isis::SequenceLevelLifetime{1200U, 60U};
  isis::SequenceRecovery recovery(levels, 37ms);
  const auto now = isis::RuntimeClock::time_point{100s};
  require(recovery.begin(now));
  device.gates.push_back({127U, recovery.checkpoint(now + 3s)});
  const auto route = channels->routes->try_acquire();
  require(route.has_value());
  route->generation->device = device.handle;
  route->generation->generation = device.route_pending;
  route->generation->ipv4_count = route->generation->ipv6_count = 1U;
  auto &ipv4 = route->generation->ipv4[0U];
  ipv4.configured = ipv4.operational = true;
  ipv4.network = 0xc0000200U; ipv4.next_hop = 0xc0000201U;
  ipv4.prefix_length = 24U; ipv4.preference = 15U;
  ipv4.source = lab::routing::RouteSource::isis;
  ipv4.interface_id = 99U; ipv4.interface_generation = 7U;
  ipv4.protocol_instance = 127U;
  auto &ipv6 = route->generation->ipv6[0U];
  ipv6.configured = ipv6.operational = true;
  ipv6.network[0U] = 0x20U; ipv6.network[1U] = 1U;
  ipv6.next_hop[0U] = 0xfeU; ipv6.next_hop[1U] = 0x80U; ipv6.next_hop[15U] = 9U;
  ipv6.prefix_length = 64U; ipv6.preference = 15U;
  ipv6.source = lab::routing::RouteSource::isis;
  ipv6.interface_id = 99U; ipv6.interface_generation = 7U;
  ipv6.protocol_instance = 127U;
  require(channels->routes->publish(route->handle));
  const auto selection = channels->selections->acquire();
  require(selection.has_value());
  selection->value->identity = {{device.handle.index,6U},2U,UINT64_MAX - 1U,UINT64_MAX};
  selection->value->counts = {1U,0U};
  selection->value->selected[0U][0U] = 1U;
  require(channels->selections->publish(selection->handle));
  saved->selection_first_device = device_catalog::maximum_routers - 1U;
  saved->ingress.push_back(channels->ingress[0U].checkpoint_quiescent(19U));
  saved->egress.push_back(channels->egress[0U].checkpoint_quiescent(19U));
  saved->routes = channels->routes->checkpoint_quiescent(19U);
  saved->selections = channels->selections->checkpoint_quiescent(19U);
  saved->installed.push_back({device.handle, 2U, {}, {}});
  auto &export_owner = saved->control.devices.emplace_back();
  export_owner.handle = {1U,9U}; export_owner.configuration_epoch = 1U;
  isis::InterlevelExportState export_bank(export_owner.handle,{8U,512U,16U});
  export_owner.interlevel = export_bank.checkpoint();
  ::router::routing::IsisSelectionProducer producer(export_owner.handle,device_catalog::maximum_dynamic_routes_per_router);
  saved->selection_producers.push_back(producer.checkpoint());
  std::array<std::uint8_t, 32U> key{}, binding{};
  key.fill(0x63U); binding.fill(0x91U);
  auto vault = vault::SecretVault::create(key, std::array<std::uint8_t, 3U>{'l', 'a', 'b'}, 1U);
  require(vault.has_value() && valid_isis_runtime_links(*saved));
  const auto producers = saved->selection_producers;
  saved->selection_producers.clear();
  require(!valid_isis_runtime_links(*saved));
  saved->selection_producers = producers;
  const auto stale_identity = saved->selections.occupied[0U].value.identity;
  saved->selections.occupied[0U].value.identity.device = export_owner.handle;
  require(!valid_isis_runtime_links(*saved));
  saved->selections.occupied[0U].value.identity = stale_identity;
  // A network-owner installation can precede enabling the protocol publisher.
  // Preserve its accepted high water without inventing a producer receipt.
  device.route_generation = device.route_pending = device.route_installed = 0U;
  require(valid_isis_runtime_links(*saved));
  device.route_generation = device.route_pending = 3U;
  device.route_installed = 2U;
  const auto selection_image = saved->selections;
  saved->selections.occupied[0U].value.selected[0U][0U] = 2U;
  require(!valid_isis_runtime_links(*saved));
  saved->selections = selection_image;
  saved->selections.ready.clear(); saved->selections.borrowed.push_back(selection->handle);
  require(!valid_isis_runtime_links(*saved));
  saved->selections = selection_image;
  saved->selection_first_device = device_catalog::maximum_routers;
  require(!valid_isis_runtime_links(*saved));
  saved->selection_first_device = device_catalog::maximum_routers - 1U;
  const auto encoded = isis_checkpoint::encode(*saved, *vault, binding);
  require(encoded && encoded->size() < 65536U); // Unused fixed route capacity is absent.
  auto restored = isis_checkpoint::decode(*encoded, *vault, binding);
  require(restored && restored->control.devices.size() == 2U && restored->routes.occupied.size() == 1U);
  require(restored->selections.occupied.size() == 1U && restored->selections.ready.size() == 1U &&
      restored->selections.occupied[0U].value == selection_image.occupied[0U].value &&
      restored->selection_first_device == device_catalog::maximum_routers - 1U);
  require(restored->control.devices[1U].interlevel && restored->selection_producers.size() == 1U &&
      restored->selection_producers[0U].device == export_owner.handle &&
      restored->selection_producers[0U].capacity == device_catalog::maximum_dynamic_routes_per_router &&
      !restored->selection_producers[0U].publication);
  const auto &copy = restored->control.devices[0U];
  require(copy.configuration_epoch == UINT64_MAX);
  const auto &routes = restored->routes.occupied[0U].value.routes;
  require(copy.retired_epoch_floor == std::numeric_limits<std::uint64_t>::max() &&
      copy.update_fences[127U] == std::numeric_limits<std::uint64_t>::max() &&
      restored->installed.size() == 1U && restored->installed[0U].generation == 2U &&
      copy.route_retry_at.nanoseconds == -123456789 && copy.route_retry == 37ms &&
      copy.gates.size() == 1U && copy.gates[0U].state.due_nanoseconds == device.gates[0U].state.due_nanoseconds &&
      routes.ipv4_count == 1U && routes.ipv6_count == 1U && routes.ipv4[0U].network == ipv4.network &&
      routes.ipv4[0U].interface_generation == 7U && routes.ipv6[0U].next_hop == ipv6.next_hop &&
      routes.ipv6[0U].protocol_instance == 127U);
  auto gate = isis::SequenceRecovery::restore_checkpoint(copy.gates[0U].state, now + 1h);
  require(gate && gate->disabled() && !gate->ready(now + 1h));
  const auto [open_status, plaintext] = vault->open_isis_checkpoint(*encoded, binding);
  require(open_status == vault::Result::applied && plaintext);
  const auto refuses_plaintext = [&](auto corrupt) {
    std::vector<std::uint8_t> malformed(plaintext->bytes().begin(), plaintext->bytes().end());
    corrupt(malformed);
    const auto [status, sealed] = vault->seal_isis_checkpoint(malformed, binding);
    require(status == vault::Result::applied && !isis_checkpoint::decode(sealed, *vault, binding));
  };
  // The codec has an eight-octet magic and fixed 64-bit scalar/count fields.
  // These are authenticated format errors, not merely damaged GCM tags.
  refuses_plaintext([](auto &bytes) { bytes[0U] ^= 1U; });
  refuses_plaintext([](auto &bytes) { bytes[8U] = 9U; });
  refuses_plaintext([](auto &bytes) { std::fill_n(bytes.begin() + 64U, 8U, std::uint8_t{0xffU}); });
  refuses_plaintext([](auto &bytes) { std::fill_n(bytes.begin() + 72U, 8U, std::uint8_t{0xffU}); });
  refuses_plaintext([](auto &bytes) { bytes[88U] = 2U; });
  refuses_plaintext([](auto &bytes) { bytes.push_back(0U); });
  auto damaged = *encoded;
  damaged.back() ^= 1U;
  require(!isis_checkpoint::decode(damaged, *vault, binding));
  binding[0U] ^= 1U;
  require(!isis_checkpoint::decode(*encoded, *vault, binding));
  saved->control.barrier_epoch = 0U;
  require(!isis_checkpoint::encode(*saved, *vault, binding) && vault->checkpoint().records.empty());
}
