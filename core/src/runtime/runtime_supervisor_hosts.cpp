// Control-shard host, DNS, capture and operational queries. RuntimeSupervisor owns
// host intent and delegates packet state through the network command boundary.

#include "runtime_supervisor_internal.hpp"

namespace router::lab {

bool RuntimeSupervisor::configure_router_bof_management(
    const RouterBofManagementProgram &program) noexcept {
  const auto *inventory = hardware(program.device);
  const auto *profile = inventory ? inventory->profile() : nullptr;
  const auto &endpoint = program.endpoint;
  const bool secret_present =
      std::ranges::any_of(endpoint.transport_secret,
                          [](std::uint8_t value) { return value != 0U; });
  if (!profile || !profile->bof_autoconfigure || endpoint.host ||
      endpoint.prefix_length > 32U ||
      endpoint.mtu < packet::ipv6_minimum_link_mtu ||
      endpoint.mtu > device_catalog::maximum_network_mtu ||
      !endpoint.interface_id || !secret_present)
    return false;
  auto &command =
      prepare(NetworkCommandKind::configure_router_bof_management);
  command.device = program.device;
  command.host_program = endpoint;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_router_bof_dhcpv4_client(
    const RouterBofDhcpv4ClientProgram &program) noexcept {
  const auto *inventory = hardware(program.device);
  const auto *profile = inventory ? inventory->profile() : nullptr;
  if (!profile || !profile->bof_autoconfigure ||
      program.bootstrap_timeout <= std::chrono::seconds::zero() ||
      program.configuration.client_identifier.size() > 255U ||
      program.configuration.parameter_request_list.size() > 255U ||
      program.configuration.user_class.size() > 254U)
    return false;
  NetworkDhcpv4ClientBegin begin{
      .hardware_address = program.configuration.hardware_address,
      .transaction_secret = program.configuration.transaction_secret,
      .client_identifier_octets = static_cast<std::uint16_t>(
          program.configuration.client_identifier.size()),
      .parameter_request_list_octets = static_cast<std::uint16_t>(
          program.configuration.parameter_request_list.size()),
      .user_class_octets = static_cast<std::uint16_t>(
          program.configuration.user_class.size()),
      .maximum_message_size = program.configuration.maximum_message_size,
      .bootstrap_timeout_seconds = static_cast<std::uint32_t>(
          program.bootstrap_timeout.count()),
      .broadcast = program.configuration.broadcast};
  std::ranges::copy(program.configuration.client_identifier,
                    begin.client_identifier.begin());
  std::ranges::copy(program.configuration.parameter_request_list,
                    begin.parameter_request_list.begin());
  std::ranges::copy(program.configuration.user_class,
                    begin.user_class.begin());
  auto &start =
      prepare(NetworkCommandKind::begin_router_bof_dhcpv4_client);
  start.device = program.device;
  start.fib = begin;
  auto result = dispatch(start);
  if (!result || !result->success)
    return false;
  auto &commit =
      prepare(NetworkCommandKind::commit_router_bof_dhcpv4_client);
  commit.device = program.device;
  result = dispatch(commit);
  if (result && result->success)
    return true;
  auto &abort =
      prepare(NetworkCommandKind::abort_router_bof_dhcpv4_client);
  abort.device = program.device;
  static_cast<void>(dispatch(abort));
  return false;
}

bool RuntimeSupervisor::remove_router_bof_dhcpv4_client(
    DeviceHandle device) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || !inventory->profile()->bof_autoconfigure)
    return false;
  auto &command =
      prepare(NetworkCommandKind::remove_router_bof_dhcpv4_client);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_router_bof_dhcpv6_client(
    const RouterBofDhcpv6ClientProgram &program) noexcept {
  const auto *inventory = hardware(program.device);
  const auto *profile = inventory ? inventory->profile() : nullptr;
  if (!profile || !profile->bof_autoconfigure ||
      program.bootstrap_timeout <= std::chrono::seconds::zero() ||
      program.configuration.user_class.size() > 255U)
    return false;
  auto &start =
      prepare(NetworkCommandKind::begin_router_bof_dhcpv6_client);
  start.device = program.device;
  start.fib = NetworkDhcpv6ClientBegin{
      .duid = program.configuration.duid,
      .transaction_secret = program.configuration.transaction_secret,
      .expected_associations = static_cast<std::uint32_t>(
          program.configuration.identity_associations.size()),
      .expected_options = static_cast<std::uint32_t>(
          program.configuration.requested_options.size()),
      .duid_octets = program.configuration.duid_octets,
      .user_class_octets = static_cast<std::uint16_t>(
          program.configuration.user_class.size()),
      .bootstrap_timeout_seconds = static_cast<std::uint32_t>(
          program.bootstrap_timeout.count()),
      .rapid_commit = program.configuration.rapid_commit,
      .information_only = program.information_only};
  std::ranges::copy(program.configuration.user_class,
                    std::get<NetworkDhcpv6ClientBegin>(start.fib)
                        .user_class.begin());
  auto result = dispatch(start);
  if (!result || !result->success)
    return false;
  for (const auto &association : program.configuration.identity_associations) {
    auto &add =
        prepare(NetworkCommandKind::add_router_bof_dhcpv6_client_ia);
    add.device = program.device;
    add.fib = NetworkDhcpv6ClientAssociation{
        .iaid = association.iaid, .kind = association.kind};
    result = dispatch(add);
    if (!result || !result->success)
      goto abort_bof_dhcpv6;
  }
  for (const auto option : program.configuration.requested_options) {
    auto &add =
        prepare(NetworkCommandKind::add_router_bof_dhcpv6_client_option);
    add.device = program.device;
    add.dhcpv6_option_code = option;
    result = dispatch(add);
    if (!result || !result->success)
      goto abort_bof_dhcpv6;
  }
  {
    auto &commit =
        prepare(NetworkCommandKind::commit_router_bof_dhcpv6_client);
    commit.device = program.device;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_bof_dhcpv6:
  {
    auto &abort =
        prepare(NetworkCommandKind::abort_router_bof_dhcpv6_client);
    abort.device = program.device;
    static_cast<void>(dispatch(abort));
  }
  return false;
}

bool RuntimeSupervisor::remove_router_bof_dhcpv6_client(
    DeviceHandle device) noexcept {
  const auto *inventory = hardware(device);
  if (!inventory || !inventory->profile()->bof_autoconfigure)
    return false;
  auto &command =
      prepare(NetworkCommandKind::remove_router_bof_dhcpv6_client);
  command.device = device;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host(
    HostHandle host, packet::Mac mac, packet::Ipv4 address,
    std::uint8_t prefix_length, packet::Ipv4 gateway, std::uint16_t mtu,
    std::uint64_t interface_id, bool ipv6_autoconfiguration,
    const host::Ipv6InterfaceIdentifierConfiguration &ipv6_identifier,
    crypto::Sha256Digest transport_secret) noexcept {
  const bool transport_secret_present =
      std::any_of(transport_secret.begin(), transport_secret.end(),
                  [](std::uint8_t value) { return value != 0U; });
  if (!hosts_.get(host) || prefix_length > 32U ||
      mtu < device_catalog::minimum_host_ipv4_mtu ||
      mtu > device_catalog::maximum_network_mtu || !transport_secret_present ||
      (ipv6_autoconfiguration &&
       (!interface_id || mtu < packet::ipv6_minimum_link_mtu)))
    return false;
  // HostNetworkProgram crosses the same value boundary as router port and FIB
  // projections. Control never receives a pointer to endpoint ARP state.
  auto &command = prepare(NetworkCommandKind::configure_host);
  command.host_program = {host,
                          mac,
                          address,
                          gateway,
                          prefix_length,
                          mtu,
                          interface_id,
                          ipv6_autoconfiguration,
                          ipv6_identifier,
                          transport_secret};
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dhcpv4_client(
    const HostDhcpv4ClientProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.configuration.client_identifier.size() > 255U ||
      program.configuration.parameter_request_list.size() > 255U ||
      program.configuration.user_class.size() > 254U)
    return false;
  NetworkDhcpv4ClientBegin begin{
      .hardware_address = program.configuration.hardware_address,
      .transaction_secret = program.configuration.transaction_secret,
      .client_identifier_octets = static_cast<std::uint16_t>(
          program.configuration.client_identifier.size()),
      .parameter_request_list_octets = static_cast<std::uint16_t>(
          program.configuration.parameter_request_list.size()),
      .user_class_octets = static_cast<std::uint16_t>(
          program.configuration.user_class.size()),
      .maximum_message_size = program.configuration.maximum_message_size,
      .broadcast = program.configuration.broadcast};
  std::ranges::copy(program.configuration.client_identifier,
                    begin.client_identifier.begin());
  std::ranges::copy(program.configuration.parameter_request_list,
                    begin.parameter_request_list.begin());
  std::ranges::copy(program.configuration.user_class,
                    begin.user_class.begin());
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv4_client);
  begin_command.host = program.host;
  begin_command.fib = begin;
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  auto &commit = prepare(NetworkCommandKind::commit_host_dhcpv4_client);
  commit.host = program.host;
  result = dispatch(commit);
  if (result && result->success)
    return true;
  auto &abort = prepare(NetworkCommandKind::abort_host_dhcpv4_client);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv4_client(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv4_client);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dhcpv4_server(
    const HostDhcpv4ServerProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.configuration.offer_hold <= std::chrono::seconds::zero() ||
      program.configuration.decline_hold <= std::chrono::seconds::zero() ||
      program.configuration.domain_name_servers.size() >
          packet::dhcpv4::maximum_ipv4_addresses_per_option ||
      program.pools.size() > device_catalog::dhcpv4_pools_per_server ||
      program.reservations.size() >
          device_catalog::dhcpv4_leases_per_server ||
      program.exclusions.size() >
          device_catalog::dhcpv4_leases_per_server)
    return false;
  const auto &configuration = program.configuration;
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv4_server);
  begin_command.host = program.host;
  begin_command.fib = NetworkDhcpv4ServerBegin{
      .server_identifier = configuration.server_identifier,
      .offer_hold_seconds =
          static_cast<std::uint64_t>(configuration.offer_hold.count()),
      .decline_hold_seconds =
          static_cast<std::uint64_t>(configuration.decline_hold.count()),
      .server_instance = configuration.server_instance,
      .routing_context = configuration.routing_context,
      .expected_dns_servers = static_cast<std::uint32_t>(
          configuration.domain_name_servers.size()),
      .expected_pools = static_cast<std::uint32_t>(program.pools.size()),
      .expected_reservations =
          static_cast<std::uint32_t>(program.reservations.size()),
      .expected_exclusions =
          static_cast<std::uint32_t>(program.exclusions.size()),
      .authoritative = configuration.authoritative,
      .force_renews = configuration.force_renews};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  for (const auto &dns : configuration.domain_name_servers) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv4_server_dns);
    command.host = program.host;
    command.fib = dns;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_dhcpv4_server;
  }
  for (const auto &pool : program.pools) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv4_server_pool);
    command.host = program.host;
    command.fib = pool;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_dhcpv4_server;
  }
  for (const auto &reservation : program.reservations) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv4_server_reservation);
    command.host = program.host;
    command.fib = reservation;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_dhcpv4_server;
  }
  // Exclusions are streamed as part of the same transaction as pools. The
  // forwarding owner does not publish the new server until it has received
  // every declared item, so a full command ring cannot expose a partially
  // excluded address range to clients.
  for (const auto &excluded : program.exclusions) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv4_server_exclusion);
    command.host = program.host;
    command.fib = excluded;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_dhcpv4_server;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_host_dhcpv4_server);
    command.host = program.host;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }
abort_dhcpv4_server: {
  auto &command = prepare(NetworkCommandKind::abort_host_dhcpv4_server);
  command.host = program.host;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv4_server(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv4_server);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

std::optional<std::size_t>
RuntimeSupervisor::host_dhcpv4_client_lease_count(HostHandle host) noexcept {
  const auto status = host_dhcpv4_client_status(host);
  return status ? std::optional<std::size_t>{
                      status->lease_present ? 1U : 0U}
                : std::nullopt;
}

std::optional<dhcpv4::ClientStatus>
RuntimeSupervisor::host_dhcpv4_client_status(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::host_dhcpv4_client_status);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success
             ? std::optional{result->dhcpv4_client}
             : std::nullopt;
}

bool RuntimeSupervisor::configure_host_dhcpv6_client(
    const HostDhcpv6ClientProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.configuration.identity_associations.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.requested_options.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.user_class.size() > 255U)
    return false;
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv6_client);
  begin_command.host = program.host;
  begin_command.fib = NetworkDhcpv6ClientBegin{
      .duid = program.configuration.duid,
      .transaction_secret = program.configuration.transaction_secret,
      .expected_associations = static_cast<std::uint32_t>(
          program.configuration.identity_associations.size()),
      .expected_options = static_cast<std::uint32_t>(
          program.configuration.requested_options.size()),
      .duid_octets = program.configuration.duid_octets,
      .user_class_octets = static_cast<std::uint16_t>(
          program.configuration.user_class.size()),
      .rapid_commit = program.configuration.rapid_commit,
      .information_only = program.information_only};
  std::ranges::copy(
      program.configuration.user_class,
      std::get<NetworkDhcpv6ClientBegin>(begin_command.fib)
          .user_class.begin());
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  for (const auto &association : program.configuration.identity_associations) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_client_ia);
    command.host = program.host;
    command.fib =
        NetworkDhcpv6ClientAssociation{association.iaid, association.kind};
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_client;
  }
  for (const auto option : program.configuration.requested_options) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_client_option);
    command.host = program.host;
    command.dhcpv6_option_code = option;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_client;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_host_dhcpv6_client);
    command.host = program.host;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }
abort_client: {
  auto &command = prepare(NetworkCommandKind::abort_host_dhcpv6_client);
  command.host = program.host;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv6_client(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv6_client);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dhcpv6_server(
    const HostDhcpv6ServerProgram &program) noexcept {
  if (!hosts_.get(program.host) ||
      program.decline_hold_time < std::chrono::seconds::zero() ||
      program.configuration.dns_recursive_servers.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.address_pools.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.prefix_pools.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto &configuration = program.configuration;
  auto &begin_command = prepare(NetworkCommandKind::begin_host_dhcpv6_server);
  begin_command.host = program.host;
  begin_command.fib = NetworkDhcpv6ServerBegin{
      .duid = configuration.duid,
      .decline_hold_seconds =
          static_cast<std::uint64_t>(program.decline_hold_time.count()),
      .expected_dns_servers = static_cast<std::uint32_t>(
          configuration.dns_recursive_servers.size()),
      .expected_address_pools =
          static_cast<std::uint32_t>(program.address_pools.size()),
      .expected_prefix_pools =
          static_cast<std::uint32_t>(program.prefix_pools.size()),
      .information_refresh_time_seconds =
          configuration.information_refresh_time_seconds,
      .solicit_maximum_retransmission_seconds =
          configuration.solicit_maximum_retransmission_seconds.value_or(0U),
      .information_maximum_retransmission_seconds =
          configuration.information_maximum_retransmission_seconds.value_or(0U),
      .duid_octets = configuration.duid_octets,
      .preference = configuration.preference,
      .address_pool_index = configuration.address_pool_index,
      .prefix_pool_index = configuration.prefix_pool_index,
      .rapid_commit = configuration.rapid_commit,
      .lease_query = configuration.lease_query,
      .has_solicit_maximum_retransmission =
          configuration.solicit_maximum_retransmission_seconds.has_value(),
      .has_information_maximum_retransmission =
          configuration.information_maximum_retransmission_seconds.has_value()};
  auto result = dispatch(begin_command);
  if (!result || !result->success)
    return false;
  for (const auto &dns : configuration.dns_recursive_servers) {
    auto &command = prepare(NetworkCommandKind::add_host_dhcpv6_server_dns);
    command.host = program.host;
    command.ipv6_destination = dns;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  for (const auto &pool : program.address_pools) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv6_server_address_pool);
    command.host = program.host;
    command.fib = pool;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  for (const auto &pool : program.prefix_pools) {
    auto &command =
        prepare(NetworkCommandKind::add_host_dhcpv6_server_prefix_pool);
    command.host = program.host;
    command.fib = pool;
    result = dispatch(command);
    if (!result || !result->success)
      goto abort_server;
  }
  {
    auto &command = prepare(NetworkCommandKind::commit_host_dhcpv6_server);
    command.host = program.host;
    result = dispatch(command);
    if (result && result->success)
      return true;
  }
abort_server: {
  auto &command = prepare(NetworkCommandKind::abort_host_dhcpv6_server);
  command.host = program.host;
  static_cast<void>(dispatch(command));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dhcpv6_server(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dhcpv6_server);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

std::optional<std::size_t>
RuntimeSupervisor::host_dhcpv6_client_lease_count(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::host_dhcpv6_client_status);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success ? std::optional<std::size_t>{result->value}
                                   : std::nullopt;
}

bool RuntimeSupervisor::configure_host_dns_resolver(
    const HostDnsResolverProgram &program) noexcept {
  if (!hosts_.get(program.host) || program.root_hints.empty() ||
      program.root_hints.size() > std::numeric_limits<std::uint32_t>::max() ||
      program.trust_anchors.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_resolver);
  begin.host = program.host;
  begin.fib = NetworkDnsResolverBegin{
      .identifier_secret = program.identifier_secret,
      .expected_root_hints =
          static_cast<std::uint32_t>(program.root_hints.size()),
      .expected_trust_anchors =
          static_cast<std::uint32_t>(program.trust_anchors.size()),
      .maximum_nsec3_iterations = program.nsec3_policy.maximum,
      .serve_clients = program.serve_clients};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &hint : program.root_hints) {
    if (hint.addresses.empty() ||
        hint.addresses.size() > std::numeric_limits<std::uint32_t>::max())
      goto abort_resolver;
    auto &root = prepare(NetworkCommandKind::begin_host_dns_root_hint);
    root.host = program.host;
    root.fib = NetworkDnsRootHintBegin{
        .server_name = hint.server_name,
        .expected_addresses =
            static_cast<std::uint32_t>(hint.addresses.size())};
    result = dispatch(root);
    if (!result || !result->success)
      goto abort_resolver;
    for (const auto &address : hint.addresses) {
      auto &add = prepare(NetworkCommandKind::add_host_dns_root_address);
      add.host = program.host;
      add.fib = address;
      result = dispatch(add);
      if (!result || !result->success)
        goto abort_resolver;
    }
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_root_hint);
    commit.host = program.host;
    result = dispatch(commit);
    if (!result || !result->success)
      goto abort_resolver;
  }
  for (const auto &anchor : program.trust_anchors) {
    if (anchor.type != packet::dns::type_dnskey || !anchor.record_class ||
        anchor.rdata.empty() ||
        anchor.rdata.size() > std::numeric_limits<std::uint16_t>::max())
      goto abort_resolver;
    auto &anchor_begin =
        prepare(NetworkCommandKind::begin_host_dns_trust_anchor);
    anchor_begin.host = program.host;
    anchor_begin.fib = NetworkDnsTrustAnchorBegin{
        .owner = anchor.owner,
        .ttl = anchor.ttl,
        .expected_rdata_octets =
            static_cast<std::uint32_t>(anchor.rdata.size()),
        .record_class = anchor.record_class};
    result = dispatch(anchor_begin);
    if (!result || !result->success)
      goto abort_resolver;
    for (std::size_t offset{}; offset < anchor.rdata.size();
         offset += network_dns_chunk_octets) {
      NetworkDnsRdataChunk chunk;
      chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
          chunk.octets.size(), anchor.rdata.size() - offset));
      std::copy_n(anchor.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                  chunk.size, chunk.octets.begin());
      auto &add = prepare(NetworkCommandKind::add_host_dns_trust_anchor_rdata);
      add.host = program.host;
      add.fib = chunk;
      result = dispatch(add);
      if (!result || !result->success)
        goto abort_resolver;
    }
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_trust_anchor);
    commit.host = program.host;
    result = dispatch(commit);
    if (!result || !result->success)
      goto abort_resolver;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_resolver);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_resolver: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_resolver);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dns_resolver(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dns_resolver);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::configure_host_dns_authoritative(
    const HostDnsAuthoritativeProgram &program) noexcept {
  if (!hosts_.get(program.host) || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_authoritative);
  begin.host = program.host;
  begin.fib = NetworkDnsAuthoritativeBegin{
      .wall_now = 0U,
      .expected_zones = static_cast<std::uint32_t>(program.zones.size()),
      .managed_signing = false};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &zone : program.zones) {
    if (zone.records.empty() ||
        zone.records.size() > std::numeric_limits<std::uint32_t>::max())
      goto abort_authoritative;
    auto &zone_begin = prepare(NetworkCommandKind::begin_host_dns_zone);
    zone_begin.host = program.host;
    zone_begin.fib = NetworkDnsZoneBegin{
        .origin = zone.origin,
        .policy = {},
        .expected_records = static_cast<std::uint32_t>(zone.records.size()),
        .expected_keys = 0U};
    result = dispatch(zone_begin);
    if (!result || !result->success)
      goto abort_authoritative;
    for (const auto &record : zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        goto abort_authoritative;
      auto &record_begin = prepare(NetworkCommandKind::begin_host_dns_record);
      record_begin.host = program.host;
      record_begin.fib = NetworkDnsRecordBegin{
          .owner = record.owner,
          .ttl = record.ttl,
          .expected_rdata_octets =
              static_cast<std::uint32_t>(record.rdata.size()),
          .type = record.type,
          .record_class = record.record_class};
      result = dispatch(record_begin);
      if (!result || !result->success)
        goto abort_authoritative;
      for (std::size_t offset{}; offset < record.rdata.size();
           offset += network_dns_chunk_octets) {
        NetworkDnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        auto &add = prepare(NetworkCommandKind::add_host_dns_rdata);
        add.host = program.host;
        add.fib = chunk;
        result = dispatch(add);
        if (!result || !result->success)
          goto abort_authoritative;
      }
      auto &commit = prepare(NetworkCommandKind::commit_host_dns_record);
      commit.host = program.host;
      result = dispatch(commit);
      if (!result || !result->success)
        goto abort_authoritative;
    }
    auto &zone_commit = prepare(NetworkCommandKind::commit_host_dns_zone);
    zone_commit.host = program.host;
    result = dispatch(zone_commit);
    if (!result || !result->success)
      goto abort_authoritative;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_authoritative);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_authoritative: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_authoritative);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::configure_host_dns_signed_authoritative(
    const HostDnsSignedAuthoritativeProgram &program) noexcept {
  if (!hosts_.get(program.host) || !program.wall_now || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  auto &begin = prepare(NetworkCommandKind::begin_host_dns_authoritative);
  begin.host = program.host;
  begin.fib = NetworkDnsAuthoritativeBegin{
      .wall_now = program.wall_now,
      .expected_zones = static_cast<std::uint32_t>(program.zones.size()),
      .managed_signing = true};
  auto result = dispatch(begin);
  if (!result || !result->success)
    return false;
  for (const auto &zone : program.zones) {
    if (zone.zone.records.empty() || zone.keys.empty() ||
        zone.zone.records.size() > std::numeric_limits<std::uint32_t>::max() ||
        zone.keys.size() > std::numeric_limits<std::uint32_t>::max() ||
        !dnssec::valid_managed_zone_policy(zone.policy))
      goto abort_signed;
    auto &zone_begin = prepare(NetworkCommandKind::begin_host_dns_zone);
    zone_begin.host = program.host;
    zone_begin.fib = NetworkDnsZoneBegin{
        .origin = zone.zone.origin,
        .policy = zone.policy,
        .expected_records =
            static_cast<std::uint32_t>(zone.zone.records.size()),
        .expected_keys = static_cast<std::uint32_t>(zone.keys.size())};
    result = dispatch(zone_begin);
    if (!result || !result->success)
      goto abort_signed;
    for (const auto &key : zone.keys) {
      auto &add_key = prepare(NetworkCommandKind::add_host_dns_signing_key);
      add_key.host = program.host;
      add_key.fib = NetworkDnsSigningKeyDefinition{.schedule = key.schedule,
                                                   .generation = key.generation,
                                                   .role = key.role,
                                                   .algorithm = key.algorithm};
      result = dispatch(add_key);
      if (!result || !result->success)
        goto abort_signed;
    }
    for (const auto &record : zone.zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
        goto abort_signed;
      auto &record_begin = prepare(NetworkCommandKind::begin_host_dns_record);
      record_begin.host = program.host;
      record_begin.fib = NetworkDnsRecordBegin{
          .owner = record.owner,
          .ttl = record.ttl,
          .expected_rdata_octets =
              static_cast<std::uint32_t>(record.rdata.size()),
          .type = record.type,
          .record_class = record.record_class};
      result = dispatch(record_begin);
      if (!result || !result->success)
        goto abort_signed;
      for (std::size_t offset{}; offset < record.rdata.size();
           offset += network_dns_chunk_octets) {
        NetworkDnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        auto &add = prepare(NetworkCommandKind::add_host_dns_rdata);
        add.host = program.host;
        add.fib = chunk;
        result = dispatch(add);
        if (!result || !result->success)
          goto abort_signed;
      }
      auto &record_commit = prepare(NetworkCommandKind::commit_host_dns_record);
      record_commit.host = program.host;
      result = dispatch(record_commit);
      if (!result || !result->success)
        goto abort_signed;
    }
    auto &zone_commit = prepare(NetworkCommandKind::commit_host_dns_zone);
    zone_commit.host = program.host;
    result = dispatch(zone_commit);
    if (!result || !result->success)
      goto abort_signed;
  }
  {
    auto &commit = prepare(NetworkCommandKind::commit_host_dns_authoritative);
    commit.host = program.host;
    result = dispatch(commit);
    if (result && result->success)
      return true;
  }
abort_signed: {
  auto &abort = prepare(NetworkCommandKind::abort_host_dns_authoritative);
  abort.host = program.host;
  static_cast<void>(dispatch(abort));
}
  return false;
}

bool RuntimeSupervisor::remove_host_dns_authoritative(
    HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::remove_host_dns_authoritative);
  command.host = host;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::start_host_ping(HostHandle host,
                                        packet::Ipv4 destination,
                                        std::uint16_t sequence) noexcept {
  if (!hosts_.get(host))
    return false;
  auto &command = prepare(NetworkCommandKind::host_ping);
  command.host = host;
  command.host_destination = destination;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success;
}

bool RuntimeSupervisor::host_ping_reply(HostHandle host,
                                        std::uint16_t sequence) noexcept {
  return (host_ping_outcome(host, sequence) & 0xffU) == 1U;
}

std::uint64_t
RuntimeSupervisor::host_ping_outcome(HostHandle host,
                                     std::uint16_t sequence) noexcept {
  if (!hosts_.get(host))
    return 0U;
  auto &command = prepare(NetworkCommandKind::host_ping_status);
  command.host = host;
  command.sequence = sequence;
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0U;
}

bool RuntimeSupervisor::delete_router(DeviceHandle device) noexcept {
  auto *record = devices_.get(device);
  if (!record)
    return false;
  // Quiescing is visible before dependent deletion. New session work can be
  // rejected while already accepted work follows the explicit drain policy.
  record->quiescing = true;
  const auto links = topology_.attached(node(device));
  static_cast<void>(session_workflows_.close_device(device));
  for (std::size_t index = 0; index < links.count; ++index)
    // delete_link drains fabric ownership and clears both endpoint signals
    // before TopologyRegistry invalidates the handle generation.
    static_cast<void>(delete_link(links.handles[index]));
  // Network-owned queues and protocol state are destroyed before the control
  // generation is advanced, so no live packet can target a released handle.
  auto &remove = prepare(NetworkCommandKind::remove_router);
  remove.device = device;
  const auto removed = dispatch(remove);
  if (!removed || !removed->success)
    return false;
  hardware_[device.index].reset();
  router_network_[device.index].reset();
  return devices_.erase(device);
}

bool RuntimeSupervisor::delete_host(HostHandle host) noexcept {
  if (!hosts_.get(host))
    return false;
  const auto links = topology_.attached(node(host));
  for (std::size_t index = 0; index < links.count; ++index)
    static_cast<void>(delete_link(links.handles[index]));
  auto &remove = prepare(NetworkCommandKind::remove_host);
  remove.host = host;
  const auto removed = dispatch(remove);
  if (!removed || !removed->success)
    return false;
  return hosts_.erase(host);
}

bool RuntimeSupervisor::delete_switch(SwitchHandle handle) noexcept {
  if (!switches_.get(handle))
    return false;
  const auto links = topology_.attached(node(handle));
  for (std::size_t index{}; index < links.count; ++index)
    static_cast<void>(delete_link(links.handles[index]));
  auto &remove = prepare(NetworkCommandKind::remove_switch);
  remove.ethernet_switch = handle;
  const auto removed = dispatch(remove);
  return removed && removed->success && switches_.erase(handle);
}

std::size_t RuntimeSupervisor::active_links() noexcept {
  auto &query = prepare(NetworkCommandKind::active_link_count);
  const auto result = dispatch(query);
  // A failed health query cannot safely invent a stale physical link count.
  return result && result->success ? static_cast<std::size_t>(result->value)
                                   : 0;
}

bool RuntimeSupervisor::configure_capture_point(
    const CapturePointProgram &program) noexcept {
  auto &command = prepare(NetworkCommandKind::configure_capture_point);
  command.capture_program = program;
  const auto result = dispatch(command);
  return result && result->success;
}

std::span<const std::uint8_t> RuntimeSupervisor::prepare_capture() noexcept {
  auto &command = prepare(NetworkCommandKind::prepare_capture);
  const auto result = dispatch(command);
  if (!result || !result->success ||
      result->value != network_worker_->prepared_capture().size())
    return {};
  // Response-ring acquire ordering publishes the completed byte vector. The
  // bridge must copy it before issuing another prepare command.
  return network_worker_->prepared_capture();
}

bool RuntimeSupervisor::clear_capture() noexcept {
  auto &command = prepare(NetworkCommandKind::clear_capture);
  const auto result = dispatch(command);
  return result && result->success;
}

std::size_t RuntimeSupervisor::captured_frames() noexcept {
  auto &command = prepare(NetworkCommandKind::capture_frame_count);
  const auto result = dispatch(command);
  return result && result->success ? static_cast<std::size_t>(result->value)
                                   : 0;
}

std::uint64_t RuntimeSupervisor::capture_dropped() noexcept {
  auto &command = prepare(NetworkCommandKind::capture_drop_count);
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0;
}

std::uint64_t RuntimeSupervisor::dropped_packets() noexcept {
  // The link owner combines its medium and cross-shard counters. Control reads
  // one scalar response and never samples forwarding-owned atomics directly.
  auto &command = prepare(NetworkCommandKind::packet_drop_count);
  const auto result = dispatch(command);
  return result && result->success ? result->value : 0;
}

std::optional<RouterForwarderCheckpoint>
RuntimeSupervisor::router_operational_state(DeviceHandle device) noexcept {
  if (!devices_.get(device))
    return std::nullopt;
  auto &command = prepare(NetworkCommandKind::prepare_router_checkpoint);
  command.device = device;
  const auto result = dispatch(command);
  const auto *prepared = network_worker_->prepared_router_checkpoint();
  if (!result || !result->success || !prepared)
    return std::nullopt;
  // Acquire on the result ring publishes the immutable prepared value. Copying
  // now releases the worker-owned buffer for the next show request without
  // exposing forwarding pointers or serializing unrelated capture metadata.
  try {
    return *prepared;
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

} // namespace router::lab
