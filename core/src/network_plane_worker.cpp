// Network owner pthread implementation. No command handler touches control
// registries or returns pointers across the SPSC boundary.

#include "router/network_plane_worker.hpp"

#include <chrono>
#include <functional>
#include <limits>
#include <new>
#include <optional>
#include <utility>

namespace router::lab {

NetworkPlaneWorker::NetworkPlaneWorker(NetworkPlaneChannels &channels)
    : channels_(channels),
      command_scratch_(std::make_unique<NetworkCommand>()) {
  // Forwarding owners publish egress into SPSC transfer rings. Their callback
  // wakes this link owner if it is sleeping without a physical deadline.
  plane_.set_link_wakeup(this, wake_link_owner);
}

NetworkPlaneWorker::~NetworkPlaneWorker() { stop(); }

void NetworkPlaneWorker::wake_link_owner(void *context) noexcept {
  auto &worker = *static_cast<NetworkPlaneWorker *>(context);
  // The release store is the durable predicate required by a condition
  // variable. A bare notify can be lost when it occurs after the link owner
  // checks its command rings but before that owner actually begins waiting.
  worker.forwarding_egress_pending_.store(true, std::memory_order_release);
  {
    std::lock_guard lock(worker.wait_mutex_);
  }
  worker.wait_condition_.notify_one();
}

void NetworkPlaneWorker::start() {
  // A worker instance has one physical lifetime. Restarting would retain plane
  // state while changing thread affinity, so a joined worker is not reusable.
  if (thread_.joinable() || running_.load(std::memory_order_acquire))
    return;
  stop_requested_.store(false, std::memory_order_release);
  thread_ = std::thread([this] { run(); });
}

void NetworkPlaneWorker::stop() noexcept {
  stop_requested_.store(true, std::memory_order_release);
  // The producer-side lock closes the condition-variable handoff window. The
  // worker releases this mutex atomically when it begins waiting.
  {
    std::lock_guard lock(wait_mutex_);
  }
  wait_condition_.notify_one();
  if (thread_.joinable())
    thread_.join();
}

bool NetworkPlaneWorker::submit(const NetworkCommand &command) noexcept {
  // Version mismatch is rejected before consuming shared ring capacity. The
  // network thread never has to infer the layout of an unknown command.
  if (command.version != network_plane_message_version ||
      !channels_.commands.try_push(command))
    return false;
  {
    std::lock_guard lock(wait_mutex_);
  }
  wait_condition_.notify_one();
  return true;
}

bool NetworkPlaneWorker::submit_signing_vault(
    const NetworkCommand &command,
    const NetworkSigningVaultInitialize &payload) noexcept {
  if (command.version != network_plane_message_version ||
      command.kind != NetworkCommandKind::initialize_signing_vault ||
      channels_.commands.full() || channels_.signing_vault.full())
    return false;
  if (!channels_.signing_vault.try_push(payload))
    return false;
  // Only this control owner writes both rings. Once preflight succeeds, the
  // network consumer can only increase command availability, so this push
  // cannot fail without an internal ring invariant violation.
  if (!channels_.commands.try_push(command))
    return false;
  {
    std::lock_guard lock(wait_mutex_);
  }
  wait_condition_.notify_one();
  return true;
}

bool NetworkPlaneWorker::read(NetworkResult &result) noexcept {
  // Control is the only consumer. Acquire ordering makes the complete result
  // visible before the caller matches its monotonically assigned command ID.
  if (!channels_.results.try_pop(result))
    return false;
  // A consumed result can release a worker blocked by response backpressure.
  {
    std::lock_guard lock(wait_mutex_);
  }
  wait_condition_.notify_one();
  return true;
}

bool NetworkPlaneWorker::stage_restore(NetworkPlaneCheckpoint state) {
  // Synchronous supervisor dispatch permits one pending restore. Allocating and
  // copying happen on control before release-publishing the command.
  if (pending_restore_)
    return false;
  try {
    pending_restore_ =
        std::make_unique<NetworkPlaneCheckpoint>(std::move(state));
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

NetworkResult
NetworkPlaneWorker::apply(const NetworkCommand &command) noexcept {
  NetworkResult result{.version = network_plane_message_version,
                       .id = command.id,
                       .kind = command.kind};
  if (command.version != network_plane_message_version)
    return result;
  switch (command.kind) {
  case NetworkCommandKind::initialize_signing_vault: {
    NetworkSigningVaultInitialize secret;
    if (channels_.signing_vault.try_pop_and_clear(secret))
      result.success = plane_.initialize_signing_vault(
          secret.wrapping_key, secret.project_context_digest);
    spsc_secure_clear(secret);
    break;
  }
  case NetworkCommandKind::add_router:
    result.success = plane_.add_router(command.device);
    if (result.success &&
        command.device.index < sap_generation_staging_.size()) {
      sap_generation_staging_[command.device.index].reset();
      ipv6_address_generation_staging_[command.device.index].reset();
    }
    break;
  case NetworkCommandKind::remove_router:
    result.success = plane_.remove_router(command.device);
    if (result.success &&
        command.device.index < sap_generation_staging_.size()) {
      sap_generation_staging_[command.device.index].reset();
      ipv6_address_generation_staging_[command.device.index].reset();
    }
    break;
  case NetworkCommandKind::add_host:
    result.success = plane_.add_host(command.host);
    break;
  case NetworkCommandKind::remove_host:
    result.success = plane_.remove_host(command.host);
    break;
  case NetworkCommandKind::configure_port:
    result.success = plane_.configure_port(command.device, command.port);
    break;
  case NetworkCommandKind::remove_port:
    result.success = plane_.remove_port(command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::program_fib:
    if (const auto *fib = std::get_if<routing::FibProgram>(&command.fib))
      result.success = plane_.program_fib(command.device, *fib);
    break;
  case NetworkCommandKind::program_ipv6_fib:
    if (const auto *fib = std::get_if<routing::Ipv6FibProgram>(&command.fib))
      result.success = plane_.program_ipv6_fib(command.device, *fib);
    break;
  case NetworkCommandKind::begin_ipv6_address_generation:
    if (command.device &&
        command.device.index < ipv6_address_generation_staging_.size())
      if (const auto *begin =
              std::get_if<Ipv6AddressGenerationBegin>(&command.fib);
          begin &&
          begin->expected_addresses <= RouterIpv6AddressTable::capacity) {
        try {
          Ipv6AddressGenerationStaging staged;
          staged.addresses.reserve(begin->expected_addresses);
          staged.expected_addresses = begin->expected_addresses;
          ipv6_address_generation_staging_[command.device.index] =
              std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // No lower owner has observed this transaction, so live addresses
          // remain unchanged when staging cannot reserve its declared size.
        }
      }
    break;
  case NetworkCommandKind::add_ipv6_interface_address:
    if (command.device.index < ipv6_address_generation_staging_.size())
      if (auto &staged = ipv6_address_generation_staging_[command.device.index];
          staged)
        if (const auto *address = std::get_if<RouterIpv6Address>(&command.fib);
            address && staged->addresses.size() < staged->expected_addresses) {
          try {
            staged->addresses.push_back(*address);
            result.success = true;
          } catch (const std::bad_alloc &) {
            // Begin pre-reserved this exact count; retaining the guard makes
            // failure behavior explicit for unusual allocator contracts.
          }
        }
    break;
  case NetworkCommandKind::commit_ipv6_address_generation:
    if (command.device.index < ipv6_address_generation_staging_.size()) {
      auto &staged = ipv6_address_generation_staging_[command.device.index];
      if (staged && staged->addresses.size() == staged->expected_addresses)
        result.success = plane_.program_ipv6_address_generation(
            command.device, staged->addresses);
      staged.reset();
    }
    break;
  case NetworkCommandKind::abort_ipv6_address_generation:
    if (command.device.index < ipv6_address_generation_staging_.size()) {
      ipv6_address_generation_staging_[command.device.index].reset();
      result.success = true;
    }
    break;
  case NetworkCommandKind::begin_sap_generation:
    if (command.device && command.device.index < sap_generation_staging_.size())
      if (const auto *begin = std::get_if<SapGenerationBegin>(&command.fib)) {
        try {
          SapGenerationStaging staged;
          staged.attachments.reserve(begin->expected_attachments);
          staged.interfaces.reserve(begin->expected_interfaces);
          staged.expected_attachments = begin->expected_attachments;
          staged.expected_interfaces = begin->expected_interfaces;
          sap_generation_staging_[command.device.index] = std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // No command has reached NetworkPlane, so its published SAP table
          // remains untouched when control-owner staging cannot be allocated.
        }
      }
    break;
  case NetworkCommandKind::add_sap_attachment:
    if (command.device.index < sap_generation_staging_.size())
      if (auto &staged = sap_generation_staging_[command.device.index]; staged)
        if (const auto *attachment =
                std::get_if<service::SapAttachment>(&command.fib)) {
          if (staged->attachments.size() >= staged->expected_attachments)
            break;
          try {
            staged->attachments.push_back(*attachment);
            result.success = true;
          } catch (const std::bad_alloc &) {
            // Begin pre-reserved this exact count. The catch documents the
            // transaction's failure behavior for unusual allocator contracts.
          }
        }
    break;
  case NetworkCommandKind::add_service_ipv6_interface:
    if (command.device.index < sap_generation_staging_.size())
      if (auto &staged = sap_generation_staging_[command.device.index]; staged)
        if (const auto *interface =
                std::get_if<service::ServiceIpv6Interface>(&command.fib)) {
          if (staged->interfaces.size() >= staged->expected_interfaces)
            break;
          try {
            staged->interfaces.push_back(*interface);
            result.success = true;
          } catch (const std::bad_alloc &) {
            // The live generation remains untouched until Commit.
          }
        }
    break;
  case NetworkCommandKind::commit_sap_generation:
    if (command.device.index < sap_generation_staging_.size()) {
      auto &staged = sap_generation_staging_[command.device.index];
      if (staged &&
          staged->attachments.size() == staged->expected_attachments &&
          staged->interfaces.size() == staged->expected_interfaces)
        result.success = plane_.program_sap_generation(
            command.device, staged->attachments, staged->interfaces);
      staged.reset();
    }
    break;
  case NetworkCommandKind::abort_sap_generation:
    if (command.device.index < sap_generation_staging_.size()) {
      sap_generation_staging_[command.device.index].reset();
      result.success = true;
    }
    break;
  case NetworkCommandKind::install_static_ipv6_neighbor:
    if (const auto *program =
            std::get_if<StaticIpv6NeighborProgram>(&command.fib))
      result.success = plane_.install_static_ipv6_neighbor(*program);
    break;
  case NetworkCommandKind::remove_static_ipv6_neighbor:
    result.success = plane_.remove_static_ipv6_neighbor(
        command.device, command.port.ordinal, command.ipv6_destination);
    break;
  case NetworkCommandKind::install_static_ipv4_neighbor:
    if (const auto *program =
            std::get_if<StaticIpv4NeighborProgram>(&command.fib))
      result.success = plane_.install_static_ipv4_neighbor(*program);
    break;
  case NetworkCommandKind::remove_static_ipv4_neighbor:
    result.success = plane_.remove_static_ipv4_neighbor(
        command.device, command.port.ordinal, command.destination);
    break;
  case NetworkCommandKind::clear_dynamic_ipv4_neighbors:
    result.success = plane_.clear_dynamic_ipv4_neighbors(
        command.device,
        command.ipv4_neighbor_interface_specific
            ? std::optional<std::uint16_t>{command.port.ordinal}
            : std::nullopt,
        command.destination == 0U
            ? std::nullopt
            : std::optional<std::uint32_t>{command.destination});
    break;
  case NetworkCommandKind::clear_dynamic_ipv6_neighbors:
    result.success = plane_.clear_dynamic_ipv6_neighbors(
        command.device,
        command.ipv6_neighbor_interface_specific
            ? std::optional<std::uint16_t>{command.port.ordinal}
            : std::nullopt,
        ip::is_unspecified(command.ipv6_destination)
            ? std::nullopt
            : std::optional<packet::Ipv6>{command.ipv6_destination});
    break;
  case NetworkCommandKind::configure_router_advertisement:
    if (const auto *program =
            std::get_if<RouterAdvertisementProgram>(&command.fib))
      result.success = plane_.configure_router_advertisement(*program);
    break;
  case NetworkCommandKind::remove_router_advertisement:
    result.success = plane_.remove_router_advertisement(command.device,
                                                        command.port.ordinal);
    break;
  case NetworkCommandKind::configure_mld_interface:
    if (const auto *program = std::get_if<MldInterfaceProgram>(&command.fib))
      result.success = plane_.configure_mld_interface(*program);
    break;
  case NetworkCommandKind::remove_mld_interface:
    result.success =
        plane_.remove_mld_interface(command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::begin_dhcpv6_relay:
    if (command.device && command.device.index < dhcpv6_relay_staging_.size())
      if (const auto *begin = std::get_if<Dhcpv6RelayBegin>(&command.fib)) {
        if (begin->interface_id == 0U ||
            begin->physical_port_ordinal >=
                device_catalog::maximum_ports_per_router ||
            begin->expected_interface_id_octets >
                std::numeric_limits<std::uint16_t>::max() ||
            begin->expected_servers >
                device_catalog::dhcpv6_relay_servers_per_interface)
          break;
        try {
          Dhcpv6RelayStaging staged;
          staged.configuration.interface_id = begin->interface_id;
          staged.configuration.physical_port_ordinal =
              begin->physical_port_ordinal;
          staged.configuration.link_address = begin->link_address;
          staged.configuration.source_address = begin->source_address;
          staged.configuration.client_prefix = begin->client_prefix;
          staged.configuration.lease_population_limit =
              begin->lease_population_limit;
          staged.configuration.has_source_address = begin->has_source_address;
          staged.configuration.neighbor_resolution = begin->neighbor_resolution;
          staged.configuration.route_non_temporary = begin->route_non_temporary;
          staged.configuration.route_temporary = begin->route_temporary;
          staged.configuration.route_delegated_prefix =
              begin->route_delegated_prefix;
          staged.configuration.route_prefix_exclude =
              begin->route_prefix_exclude;
          staged.configuration.upstream_policy = begin->upstream_policy;
          staged.configuration.relay_interface_id.reserve(
              begin->expected_interface_id_octets);
          staged.expected_interface_id_octets =
              begin->expected_interface_id_octets;
          staged.expected_servers = begin->expected_servers;
          dhcpv6_relay_staging_[command.device.index] = std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // The owner has not touched NetworkPlane, so allocation failure
          // cannot disturb the currently active forwarding policy.
        }
      }
    break;
  case NetworkCommandKind::add_dhcpv6_relay_interface_id:
    if (command.device.index < dhcpv6_relay_staging_.size())
      if (auto &staged = dhcpv6_relay_staging_[command.device.index]; staged)
        if (const auto *chunk =
                std::get_if<Dhcpv6RelayInterfaceIdChunk>(&command.fib)) {
          const auto current = staged->configuration.relay_interface_id.size();
          if (chunk->size == 0U || chunk->size > chunk->octets.size() ||
              current > staged->expected_interface_id_octets ||
              chunk->size > staged->expected_interface_id_octets - current)
            break;
          try {
            staged->configuration.relay_interface_id.insert(
                staged->configuration.relay_interface_id.end(),
                chunk->octets.begin(), chunk->octets.begin() + chunk->size);
            result.success = true;
          } catch (const std::bad_alloc &) {
          }
        }
    break;
  case NetworkCommandKind::add_dhcpv6_relay_server:
    if (command.device.index < dhcpv6_relay_staging_.size())
      if (auto &staged = dhcpv6_relay_staging_[command.device.index]; staged)
        if (const auto *server =
                std::get_if<dhcpv6::RelayDestination>(&command.fib)) {
          if (staged->configuration.server_count >= staged->expected_servers)
            break;
          staged->configuration.servers[staged->configuration.server_count++] =
              *server;
          result.success = true;
        }
    break;
  case NetworkCommandKind::commit_dhcpv6_relay:
    if (command.device.index < dhcpv6_relay_staging_.size()) {
      auto &staged = dhcpv6_relay_staging_[command.device.index];
      if (staged &&
          staged->configuration.relay_interface_id.size() ==
              staged->expected_interface_id_octets &&
          staged->configuration.server_count == staged->expected_servers)
        result.success = plane_.configure_dhcpv6_relay(command.device,
                                                       staged->configuration);
      // The command result is the only commit acknowledgement. Retaining a
      // rejected value here could let an unrelated later command resurrect it.
      staged.reset();
    }
    break;
  case NetworkCommandKind::abort_dhcpv6_relay:
    if (command.device.index < dhcpv6_relay_staging_.size()) {
      dhcpv6_relay_staging_[command.device.index].reset();
      result.success = true;
    }
    break;
  case NetworkCommandKind::remove_dhcpv6_relay:
    result.success = plane_.remove_dhcpv6_relay(command.device,
                                                command.logical_interface_id);
    break;
  case NetworkCommandKind::clear_dhcpv6_relay_leases:
    if (const auto *program =
            std::get_if<Dhcpv6RelayLeaseClearProgram>(&command.fib))
      result.success =
          plane_.clear_dhcpv6_relay_leases(command.device, *program);
    break;
  case NetworkCommandKind::clear_mld_database:
    result.success = plane_.clear_mld_database(
        command.device, command.port.ordinal,
        command.mld_group_specific
            ? std::optional<packet::Ipv6>{command.ipv6_destination}
            : std::nullopt);
    break;
  case NetworkCommandKind::clear_mld_database_all:
    result.success = plane_.clear_mld_database_all(command.device);
    break;
  case NetworkCommandKind::clear_mld_version:
    result.success =
        plane_.clear_mld_version(command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::clear_mld_statistics:
    result.success =
        plane_.clear_mld_statistics(command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::clear_mld_statistics_all:
    result.success = plane_.clear_mld_statistics_all(command.device);
    break;
  case NetworkCommandKind::edit_mld_static:
    result.success = plane_.edit_mld_static(
        command.device, command.port.ordinal, command.mld_static_operation,
        command.ipv6_destination, command.ipv6_source);
    break;
  case NetworkCommandKind::program_mld_ssm_translation:
    result.success = plane_.program_mld_ssm_translation(
        command.device, command.port.ordinal, command.mld_ssm_operation,
        command.mld_ssm_translation, command.mld_ssm_expected_entries);
    break;
  case NetworkCommandKind::program_mld_import_policy:
    result.success = plane_.program_mld_import_policy(
        command.device, command.port.ordinal,
        command.mld_import_policy_operation, command.mld_import_policy_entry,
        command.mld_import_policy_default_action,
        command.mld_import_policy_expected_entries);
    break;
  case NetworkCommandKind::clear_icmpv4_statistics_all:
    result.success = plane_.clear_icmpv4_statistics_all(command.device);
    break;
  case NetworkCommandKind::clear_icmpv4_global_statistics:
    result.success = plane_.clear_icmpv4_global_statistics(command.device);
    break;
  case NetworkCommandKind::clear_icmpv4_interface_statistics:
    result.success = plane_.clear_icmpv4_interface_statistics(
        command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::clear_icmpv6_statistics_all:
    result.success = plane_.clear_icmpv6_statistics_all(command.device);
    break;
  case NetworkCommandKind::clear_icmpv6_global_statistics:
    result.success = plane_.clear_icmpv6_global_statistics(command.device);
    break;
  case NetworkCommandKind::clear_icmpv6_interface_statistics:
    result.success = plane_.clear_icmpv6_interface_statistics(
        command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::clear_router_advertisement_statistics_all:
    result.success =
        plane_.clear_router_advertisement_statistics_all(command.device);
    break;
  case NetworkCommandKind::clear_router_advertisement_interface_statistics:
    result.success = plane_.clear_router_advertisement_interface_statistics(
        command.device, command.port.ordinal);
    break;
  case NetworkCommandKind::configure_host:
    result.success = plane_.configure_host(command.host_program);
    break;
  case NetworkCommandKind::begin_host_dhcpv6_client:
    if (command.host.index < dhcpv6_client_staging_.size())
      if (const auto *begin =
              std::get_if<NetworkDhcpv6ClientBegin>(&command.fib)) {
        try {
          HostDhcpv6ClientProgram staged{.host = command.host,
                                         .configuration = {},
                                         .information_only =
                                             begin->information_only};
          staged.configuration.duid = begin->duid;
          staged.configuration.duid_octets = begin->duid_octets;
          staged.configuration.transaction_secret = begin->transaction_secret;
          staged.configuration.rapid_commit = begin->rapid_commit;
          staged.configuration.identity_associations.reserve(
              begin->expected_associations);
          staged.configuration.requested_options.reserve(
              begin->expected_options);
          dhcpv6_client_staging_[command.host.index] = std::move(staged);
          dhcpv6_client_expected_[command.host.index] = {
              begin->expected_associations, begin->expected_options};
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::add_host_dhcpv6_client_ia:
    if (command.host.index < dhcpv6_client_staging_.size())
      if (auto &staged = dhcpv6_client_staging_[command.host.index]; staged)
        if (const auto *association =
                std::get_if<NetworkDhcpv6ClientAssociation>(&command.fib)) {
          // The Begin message is the admission decision for this streamed
          // transaction. Refusing an extra element here prevents a malformed
          // producer from growing owner-local vectors beyond the capacity it
          // declared before any allocation was attempted.
          const auto expected = dhcpv6_client_expected_[command.host.index];
          if (staged->configuration.identity_associations.size() >=
              expected[0U])
            break;
          try {
            staged->configuration.identity_associations.push_back(
                {association->iaid, association->kind});
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::add_host_dhcpv6_client_option:
    if (command.host.index < dhcpv6_client_staging_.size())
      if (auto &staged = dhcpv6_client_staging_[command.host.index]; staged) {
        const auto expected = dhcpv6_client_expected_[command.host.index];
        if (staged->configuration.requested_options.size() >= expected[1U])
          break;
        try {
          staged->configuration.requested_options.push_back(
              command.dhcpv6_option_code);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::commit_host_dhcpv6_client:
    if (command.host.index < dhcpv6_client_staging_.size()) {
      auto &staged = dhcpv6_client_staging_[command.host.index];
      const auto expected = dhcpv6_client_expected_[command.host.index];
      if (staged &&
          staged->configuration.identity_associations.size() == expected[0U] &&
          staged->configuration.requested_options.size() == expected[1U]) {
        result.success = plane_.configure_host_dhcpv6_client(*staged);
      }
      staged.reset();
      dhcpv6_client_expected_[command.host.index] = {};
    }
    break;
  case NetworkCommandKind::abort_host_dhcpv6_client:
    if (command.host.index < dhcpv6_client_staging_.size()) {
      dhcpv6_client_staging_[command.host.index].reset();
      dhcpv6_client_expected_[command.host.index] = {};
      result.success = true;
    }
    break;
  case NetworkCommandKind::remove_host_dhcpv6_client:
    result.success = plane_.remove_host_dhcpv6_client(command.host);
    break;
  case NetworkCommandKind::begin_host_dhcpv6_server:
    if (command.host.index < dhcpv6_server_staging_.size())
      if (const auto *begin =
              std::get_if<NetworkDhcpv6ServerBegin>(&command.fib)) {
        try {
          HostDhcpv6ServerProgram staged{
              .host = command.host,
              .configuration = {},
              .address_pools = {},
              .prefix_pools = {},
              .decline_hold_time =
                  std::chrono::seconds{begin->decline_hold_seconds}};
          auto &configuration = staged.configuration;
          configuration.duid = begin->duid;
          configuration.duid_octets = begin->duid_octets;
          configuration.preference = begin->preference;
          configuration.address_pool_index = begin->address_pool_index;
          configuration.prefix_pool_index = begin->prefix_pool_index;
          configuration.information_refresh_time_seconds =
              begin->information_refresh_time_seconds;
          configuration.rapid_commit = begin->rapid_commit;
          if (begin->has_solicit_maximum_retransmission)
            configuration.solicit_maximum_retransmission_seconds =
                begin->solicit_maximum_retransmission_seconds;
          if (begin->has_information_maximum_retransmission)
            configuration.information_maximum_retransmission_seconds =
                begin->information_maximum_retransmission_seconds;
          configuration.dns_recursive_servers.reserve(
              begin->expected_dns_servers);
          staged.address_pools.reserve(begin->expected_address_pools);
          staged.prefix_pools.reserve(begin->expected_prefix_pools);
          dhcpv6_server_staging_[command.host.index] = std::move(staged);
          dhcpv6_server_expected_[command.host.index] = {
              begin->expected_dns_servers, begin->expected_address_pools,
              begin->expected_prefix_pools};
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::add_host_dhcpv6_server_dns:
    if (command.host.index < dhcpv6_server_staging_.size())
      if (auto &staged = dhcpv6_server_staging_[command.host.index]; staged) {
        const auto expected = dhcpv6_server_expected_[command.host.index];
        if (staged->configuration.dns_recursive_servers.size() >= expected[0U])
          break;
        try {
          staged->configuration.dns_recursive_servers.push_back(
              command.ipv6_destination);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::add_host_dhcpv6_server_address_pool:
  case NetworkCommandKind::add_host_dhcpv6_server_prefix_pool:
    if (command.host.index < dhcpv6_server_staging_.size())
      if (auto &staged = dhcpv6_server_staging_[command.host.index]; staged)
        if (const auto *pool = std::get_if<dhcpv6::LeasePool>(&command.fib)) {
          try {
            const auto expected = dhcpv6_server_expected_[command.host.index];
            auto &target =
                command.kind ==
                        NetworkCommandKind::add_host_dhcpv6_server_address_pool
                    ? staged->address_pools
                    : staged->prefix_pools;
            const auto admitted =
                command.kind ==
                        NetworkCommandKind::add_host_dhcpv6_server_address_pool
                    ? expected[1U]
                    : expected[2U];
            if (target.size() >= admitted)
              break;
            target.push_back(*pool);
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dhcpv6_server:
    if (command.host.index < dhcpv6_server_staging_.size()) {
      auto &staged = dhcpv6_server_staging_[command.host.index];
      const auto expected = dhcpv6_server_expected_[command.host.index];
      if (staged &&
          staged->configuration.dns_recursive_servers.size() == expected[0U] &&
          staged->address_pools.size() == expected[1U] &&
          staged->prefix_pools.size() == expected[2U]) {
        result.success = plane_.configure_host_dhcpv6_server(*staged);
      }
      staged.reset();
      dhcpv6_server_expected_[command.host.index] = {};
    }
    break;
  case NetworkCommandKind::abort_host_dhcpv6_server:
    if (command.host.index < dhcpv6_server_staging_.size()) {
      dhcpv6_server_staging_[command.host.index].reset();
      dhcpv6_server_expected_[command.host.index] = {};
      result.success = true;
    }
    break;
  case NetworkCommandKind::remove_host_dhcpv6_server:
    result.success = plane_.remove_host_dhcpv6_server(command.host);
    break;
  case NetworkCommandKind::host_dhcpv6_client_status: {
    const auto leases = plane_.host_dhcpv6_client_lease_count(command.host);
    result.success = leases.has_value();
    result.value = leases.value_or(0U);
    break;
  }
  case NetworkCommandKind::begin_host_dns_resolver:
    if (command.host.index < dns_resolver_staging_.size())
      if (const auto *begin =
              std::get_if<NetworkDnsResolverBegin>(&command.fib)) {
        try {
          DnsResolverStaging staged;
          staged.program.host = command.host;
          staged.program.identifier_secret = begin->identifier_secret;
          staged.program.nsec3_policy.maximum = begin->maximum_nsec3_iterations;
          staged.program.serve_clients = begin->serve_clients;
          staged.program.root_hints.reserve(begin->expected_root_hints);
          staged.program.trust_anchors.reserve(begin->expected_trust_anchors);
          staged.expected_roots = begin->expected_root_hints;
          staged.expected_anchors = begin->expected_trust_anchors;
          dns_resolver_staging_[command.host.index] = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::begin_host_dns_root_hint:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (const auto *begin =
                std::get_if<NetworkDnsRootHintBegin>(&command.fib)) {
          if (staged->root_active || staged->anchor_active ||
              staged->program.root_hints.size() >= staged->expected_roots ||
              begin->expected_addresses == 0U)
            break;
          try {
            staged->current_root = {.server_name = begin->server_name,
                                    .addresses = {}};
            staged->current_root.addresses.reserve(begin->expected_addresses);
            staged->expected_current_addresses = begin->expected_addresses;
            staged->root_active = true;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::add_host_dns_root_address:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (const auto *address =
                std::get_if<dns::ServerAddress>(&command.fib)) {
          if (!staged->root_active || staged->anchor_active ||
              staged->current_root.addresses.size() >=
                  staged->expected_current_addresses)
            break;
          try {
            staged->current_root.addresses.push_back(*address);
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dns_root_hint:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (staged->root_active && !staged->anchor_active &&
            staged->current_root.addresses.size() ==
                staged->expected_current_addresses) {
          try {
            staged->program.root_hints.push_back(
                std::move(staged->current_root));
            staged->current_root = {};
            staged->expected_current_addresses = 0U;
            staged->root_active = false;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::begin_host_dns_trust_anchor:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (const auto *begin =
                std::get_if<NetworkDnsTrustAnchorBegin>(&command.fib)) {
          if (staged->root_active || staged->anchor_active ||
              staged->program.trust_anchors.size() >=
                  staged->expected_anchors ||
              begin->expected_rdata_octets == 0U)
            break;
          try {
            staged->current_anchor = {.owner = begin->owner,
                                      .type = packet::dns::type_dnskey,
                                      .record_class = begin->record_class,
                                      .ttl = begin->ttl,
                                      .rdata = {}};
            staged->current_anchor.rdata.reserve(begin->expected_rdata_octets);
            staged->expected_current_rdata = begin->expected_rdata_octets;
            staged->anchor_active = true;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::add_host_dns_trust_anchor_rdata:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (const auto *chunk =
                std::get_if<NetworkDnsRdataChunk>(&command.fib)) {
          const auto current = staged->current_anchor.rdata.size();
          if (!staged->anchor_active || staged->root_active ||
              chunk->size == 0U || chunk->size > chunk->octets.size() ||
              current > staged->expected_current_rdata ||
              chunk->size > staged->expected_current_rdata - current)
            break;
          try {
            staged->current_anchor.rdata.insert(
                staged->current_anchor.rdata.end(), chunk->octets.begin(),
                chunk->octets.begin() + chunk->size);
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dns_trust_anchor:
    if (command.host.index < dns_resolver_staging_.size())
      if (auto &staged = dns_resolver_staging_[command.host.index]; staged)
        if (staged->anchor_active && !staged->root_active &&
            staged->current_anchor.rdata.size() ==
                staged->expected_current_rdata) {
          try {
            staged->program.trust_anchors.push_back(
                std::move(staged->current_anchor));
            staged->current_anchor = {};
            staged->expected_current_rdata = 0U;
            staged->anchor_active = false;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dns_resolver:
    if (command.host.index < dns_resolver_staging_.size()) {
      auto &staged = dns_resolver_staging_[command.host.index];
      if (staged && !staged->root_active && !staged->anchor_active &&
          staged->program.root_hints.size() == staged->expected_roots &&
          staged->program.trust_anchors.size() == staged->expected_anchors)
        result.success = plane_.configure_host_dns_resolver(staged->program);
      staged.reset();
    }
    break;
  case NetworkCommandKind::abort_host_dns_resolver:
    if (command.host.index < dns_resolver_staging_.size()) {
      dns_resolver_staging_[command.host.index].reset();
      result.success = true;
    }
    break;
  case NetworkCommandKind::remove_host_dns_resolver:
    result.success = plane_.remove_host_dns_resolver(command.host);
    if (command.host.index < dns_resolver_staging_.size())
      dns_resolver_staging_[command.host.index].reset();
    break;
  case NetworkCommandKind::begin_host_dns_authoritative:
    if (command.host.index < dns_authoritative_staging_.size())
      if (const auto *begin =
              std::get_if<NetworkDnsAuthoritativeBegin>(&command.fib)) {
        if (!begin->expected_zones ||
            (begin->managed_signing && !begin->wall_now))
          break;
        try {
          DnsAuthoritativeStaging staged;
          staged.managed_signing = begin->managed_signing;
          staged.expected_zones = begin->expected_zones;
          if (begin->managed_signing) {
            staged.signed_program.host = command.host;
            staged.signed_program.wall_now = begin->wall_now;
            staged.signed_program.zones.reserve(begin->expected_zones);
          } else {
            staged.plain.host = command.host;
            staged.plain.zones.reserve(begin->expected_zones);
          }
          dns_authoritative_staging_[command.host.index] = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case NetworkCommandKind::begin_host_dns_zone:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index]; staged)
        if (const auto *begin =
                std::get_if<NetworkDnsZoneBegin>(&command.fib)) {
          const auto completed = staged->managed_signing
                                     ? staged->signed_program.zones.size()
                                     : staged->plain.zones.size();
          if (staged->zone_active || staged->record_active ||
              completed >= staged->expected_zones || !begin->expected_records ||
              (staged->managed_signing &&
               (!begin->expected_keys ||
                !dnssec::valid_managed_zone_policy(begin->policy))) ||
              (!staged->managed_signing && begin->expected_keys))
            break;
          try {
            if (staged->managed_signing) {
              staged->current_signed_zone = {
                  .zone = {.origin = begin->origin, .records = {}},
                  .keys = {},
                  .policy = begin->policy};
              staged->current_signed_zone.zone.records.reserve(
                  begin->expected_records);
              staged->current_signed_zone.keys.reserve(begin->expected_keys);
            } else {
              staged->current_zone = {.origin = begin->origin, .records = {}};
              staged->current_zone.records.reserve(begin->expected_records);
            }
            staged->expected_current_records = begin->expected_records;
            staged->expected_current_keys = begin->expected_keys;
            staged->zone_active = true;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::add_host_dns_signing_key:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index]; staged)
        if (const auto *key =
                std::get_if<NetworkDnsSigningKeyDefinition>(&command.fib)) {
          if (!staged->managed_signing || !staged->zone_active ||
              staged->record_active ||
              staged->current_signed_zone.keys.size() >=
                  staged->expected_current_keys ||
              !key->algorithm || !dnssec::valid_schedule(key->schedule))
            break;
          try {
            staged->current_signed_zone.keys.push_back(
                {.schedule = key->schedule,
                 .generation = key->generation,
                 .role = key->role,
                 .algorithm = key->algorithm});
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::begin_host_dns_record:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index]; staged)
        if (const auto *begin =
                std::get_if<NetworkDnsRecordBegin>(&command.fib)) {
          auto &records = staged->managed_signing
                              ? staged->current_signed_zone.zone.records
                              : staged->current_zone.records;
          if (!staged->zone_active || staged->record_active ||
              records.size() >= staged->expected_current_records ||
              begin->expected_rdata_octets >
                  std::numeric_limits<std::uint16_t>::max())
            break;
          try {
            staged->current_record = {.owner = begin->owner,
                                      .type = begin->type,
                                      .record_class = begin->record_class,
                                      .ttl = begin->ttl,
                                      .rdata = {}};
            staged->current_record.rdata.reserve(begin->expected_rdata_octets);
            staged->expected_current_rdata = begin->expected_rdata_octets;
            staged->record_active = true;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::add_host_dns_rdata:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index]; staged)
        if (const auto *chunk =
                std::get_if<NetworkDnsRdataChunk>(&command.fib)) {
          const auto current = staged->current_record.rdata.size();
          if (!staged->record_active || chunk->size == 0U ||
              chunk->size > chunk->octets.size() ||
              current > staged->expected_current_rdata ||
              chunk->size > staged->expected_current_rdata - current)
            break;
          try {
            staged->current_record.rdata.insert(
                staged->current_record.rdata.end(), chunk->octets.begin(),
                chunk->octets.begin() + chunk->size);
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dns_record:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index]; staged)
        if (staged->zone_active && staged->record_active &&
            staged->current_record.rdata.size() ==
                staged->expected_current_rdata) {
          try {
            auto &records = staged->managed_signing
                                ? staged->current_signed_zone.zone.records
                                : staged->current_zone.records;
            records.push_back(std::move(staged->current_record));
            staged->current_record = {};
            staged->expected_current_rdata = 0U;
            staged->record_active = false;
            result.success = true;
          } catch (...) {
          }
        }
    break;
  case NetworkCommandKind::commit_host_dns_zone:
    if (command.host.index < dns_authoritative_staging_.size())
      if (auto &staged = dns_authoritative_staging_[command.host.index];
          staged) {
        const auto &records = staged->managed_signing
                                  ? staged->current_signed_zone.zone.records
                                  : staged->current_zone.records;
        const bool keys_complete = !staged->managed_signing ||
                                   staged->current_signed_zone.keys.size() ==
                                       staged->expected_current_keys;
        if (staged->zone_active && !staged->record_active && keys_complete &&
            records.size() == staged->expected_current_records) {
          try {
            if (staged->managed_signing)
              staged->signed_program.zones.push_back(
                  std::move(staged->current_signed_zone));
            else
              staged->plain.zones.push_back(std::move(staged->current_zone));
            staged->current_zone = {};
            staged->current_signed_zone = {};
            staged->expected_current_records = 0U;
            staged->expected_current_keys = 0U;
            staged->zone_active = false;
            result.success = true;
          } catch (...) {
          }
        }
      }
    break;
  case NetworkCommandKind::commit_host_dns_authoritative:
    if (command.host.index < dns_authoritative_staging_.size()) {
      auto &staged = dns_authoritative_staging_[command.host.index];
      if (staged && !staged->zone_active && !staged->record_active) {
        if (staged->managed_signing &&
            staged->signed_program.zones.size() == staged->expected_zones)
          result.success = plane_.configure_host_dns_signed_authoritative(
              staged->signed_program);
        else if (!staged->managed_signing &&
                 staged->plain.zones.size() == staged->expected_zones)
          result.success =
              plane_.configure_host_dns_authoritative(staged->plain);
      }
      staged.reset();
    }
    break;
  case NetworkCommandKind::abort_host_dns_authoritative:
    if (command.host.index < dns_authoritative_staging_.size()) {
      dns_authoritative_staging_[command.host.index].reset();
      result.success = true;
    }
    break;
  case NetworkCommandKind::remove_host_dns_authoritative:
    result.success = plane_.remove_host_dns_authoritative(command.host);
    if (command.host.index < dns_authoritative_staging_.size())
      dns_authoritative_staging_[command.host.index].reset();
    break;
  case NetworkCommandKind::configure_link:
    result.success = plane_.configure_link(command.link_program);
    break;
  case NetworkCommandKind::remove_link:
    result.success = plane_.remove_link(command.link);
    break;
  case NetworkCommandKind::router_ping:
    result.success =
        plane_.start_router_ping(command.device, command.destination,
                                 command.sequence, NetworkPlane::Clock::now(),
                                 command.payload_octets, command.dont_fragment);
    break;
  case NetworkCommandKind::router_ipv6_ping:
    result.success = plane_.start_router_ipv6_ping(
        command.device, command.ipv6_destination, command.sequence,
        NetworkPlane::Clock::now(), command.payload_octets);
    break;
  case NetworkCommandKind::host_ping:
    result.success = plane_.start_host_ping(
        command.host, command.host_destination, command.sequence);
    break;
  case NetworkCommandKind::router_ping_status:
    // Control validates the handle in DeviceRegistry before issuing the query.
    // The payload therefore reports completion without exposing a forwarding
    // pointer or copying the router's adjacency state across the shard.
    result.success = true;
    result.value = plane_.router_ping_outcome(command.device, command.sequence);
    break;
  case NetworkCommandKind::router_ipv6_ping_status:
    result.success = true;
    result.value =
        plane_.router_ipv6_ping_outcome(command.device, command.sequence);
    break;
  case NetworkCommandKind::host_ping_status:
    result.success = true;
    result.value = plane_.host_ping_reply(command.host, command.sequence);
    break;
  case NetworkCommandKind::active_link_count:
    result.success = true;
    result.value = plane_.active_links();
    break;
  case NetworkCommandKind::configure_capture_point:
    result.success = plane_.configure_capture_point(command.capture_program);
    break;
  case NetworkCommandKind::prepare_capture:
    plane_.prepare_capture();
    result.success = true;
    result.value = plane_.prepared_capture().size();
    break;
  case NetworkCommandKind::capture_frame_count:
    result.success = true;
    result.value = plane_.captured_frames();
    break;
  case NetworkCommandKind::capture_drop_count:
    result.success = true;
    result.value = plane_.capture_dropped();
    break;
  case NetworkCommandKind::packet_drop_count:
    result.success = true;
    result.value = plane_.dropped_packets();
    break;
  case NetworkCommandKind::prepare_router_checkpoint:
    try {
      const auto state =
          plane_.router_checkpoint(command.device, NetworkPlane::Clock::now());
      if (state) {
        prepared_router_checkpoint_ =
            std::make_unique<RouterForwarderCheckpoint>(*state);
        result.success = true;
      } else {
        prepared_router_checkpoint_.reset();
      }
    } catch (const std::bad_alloc &) {
      prepared_router_checkpoint_.reset();
    }
    break;
  case NetworkCommandKind::prepare_checkpoint:
    try {
      auto checkpoint = plane_.checkpoint(NetworkPlane::Clock::now());
      if (checkpoint) {
        prepared_checkpoint_ =
            std::make_unique<NetworkPlaneCheckpoint>(std::move(*checkpoint));
        result.success = true;
      } else {
        prepared_checkpoint_.reset();
      }
    } catch (const std::bad_alloc &) {
      prepared_checkpoint_.reset();
    }
    break;
  case NetworkCommandKind::restore_checkpoint:
    result.success =
        pending_restore_ &&
        plane_.restore(*pending_restore_, NetworkPlane::Clock::now());
    pending_restore_.reset();
    break;
  case NetworkCommandKind::shutdown:
    // Shutdown acknowledgment is published before the run loop observes the
    // stop word, allowing control to distinguish clean stop from worker loss.
    result.success = true;
    stop_requested_.store(true, std::memory_order_release);
    break;
  }
  return result;
}

void NetworkPlaneWorker::run() noexcept {
  // std::thread::id is process-local and never enters a checkpoint. Hashing it
  // produces the opaque nonzero health token already used by telemetry ABI 6.
  auto owner = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  if (!owner)
    owner = 1U;
  owner_thread_id_.store(owner, std::memory_order_release);
  running_.store(true, std::memory_order_release);
  std::optional<NetworkResult> pending_result;
  while (!stop_requested_.load(std::memory_order_acquire)) {
    // Every forwarding ring is scanned by the following pump. Clearing before
    // the scan cannot lose work: a concurrent publication sets the bit again,
    // while an earlier publication is already visible to the SPSC consumer.
    forwarding_egress_pending_.exchange(false, std::memory_order_acquire);
    owner_turns_.fetch_add(1U, std::memory_order_relaxed);
    // A result owns its command completion until control accepts it. No later
    // command executes while the bounded response path is applying
    // backpressure.
    if (pending_result && channels_.results.try_push(*pending_result))
      pending_result.reset();

    // The generated budget is independent from queue capacity. A profile may
    // tune fairness without silently changing shared-ring memory layout.
    std::size_t budget = device_catalog::network_command_work_budget;
    // The command payload may hold an entire FIB generation. Reuse the
    // worker-owned heap buffer so increasing a hardware route profile cannot
    // silently consume the fixed Wasm pthread stack.
    auto &command = *command_scratch_;
    while (!pending_result && budget-- && channels_.commands.try_pop(command)) {
      auto result = apply(command);
      if (!channels_.results.try_push(result))
        pending_result = result;
      if (stop_requested_.load(std::memory_order_acquire))
        break;
    }

    const auto now = NetworkPlane::Clock::now();
    plane_.pump(now);
    if (stop_requested_.load(std::memory_order_acquire))
      break;
    const auto medium = plane_.next_deadline();
    std::unique_lock lock(wait_mutex_);
    const auto ready = [&] {
      return stop_requested_.load(std::memory_order_acquire) ||
             !channels_.commands.empty() ||
             forwarding_egress_pending_.load(std::memory_order_acquire) ||
             (pending_result && !channels_.results.full());
    };
    // The predicate closes the notify-before-wait race using the ring's
    // release/acquire publication. Without an in-flight frame there is no
    // periodic maintenance task, so an idle laboratory sleeps indefinitely.
    // At 10G, a minimum Ethernet frame completes serialization in tens of
    // nanoseconds. The deadline commonly becomes due while this worker scans
    // the fabric and acquires the wait mutex. Passing an already due instant
    // to a WebAssembly condition variable can yield the pthread for an entire
    // browser scheduling quantum. Re-entering the pump instead preserves the
    // real steady-clock deadline and avoids inventing millisecond link delay.
    if (medium) {
      const auto sampled_now = NetworkPlane::Clock::now();
      if (*medium <= sampled_now)
        continue;
      // Browser condition variables cannot reliably sleep for Ethernet wire
      // intervals measured in nanoseconds. Entering one here inflated a direct
      // 10 Gb/s Echo round trip by roughly 27 ms. The generated horizon equals
      // one maximum-size frame at the slowest supported port speed. Remaining
      // runnable until that real steady-clock deadline preserves serialization
      // and short propagation precisely without creating periodic idle polling.
      if (*medium - sampled_now <= device_catalog::immediate_link_deadline)
        continue;
    }
    if (medium)
      static_cast<void>(wait_condition_.wait_until(lock, *medium, ready));
    else
      wait_condition_.wait(lock, ready);
  }
  running_.store(false, std::memory_order_release);
  owner_thread_id_.store(0U, std::memory_order_release);
}

} // namespace router::lab
