// Network-plane owner implementation. Router and host stacks communicate only
// through encoded frames admitted to MultiDeviceFabric.

#include "router/network_plane.hpp"

#include "dhcpv4/dhcpv4_endpoint_service.hpp"
#include "dhcpv6/dhcpv6_endpoint_service.hpp"
#include "dns/dns_endpoint_service.hpp"
#include "forwarding/network_endpoint.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/ospf_control_worker.hpp"
#include "router/shard_policy.hpp"
#include "router/spsc_ring.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <limits>
#include <mutex>
#include <new>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>

namespace router::lab {

namespace {

template <typename Clock>
[[nodiscard]] std::int64_t
relative_runtime_deadline(typename Clock::time_point deadline,
                          typename Clock::time_point now) noexcept {
  if (deadline == Clock::time_point::max())
    return -1;
  return std::max<std::int64_t>(
      0, std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
             .count());
}

template <typename Clock>
[[nodiscard]] typename Clock::time_point
restore_runtime_deadline(std::int64_t remaining,
                         typename Clock::time_point now) noexcept {
  return remaining < 0
             ? Clock::time_point::max()
             : now + std::chrono::nanoseconds{remaining};
}

[[nodiscard]] bool empty_unconfigured_host_checkpoint(
    const NetworkCheckpointState &state) noexcept {
  const auto zero_octets = [](const auto &value) {
    return std::all_of(value.begin(), value.end(),
                       [](const auto octet) { return octet == 0U; });
  };
  const auto &endpoint = state.endpoint;
  const auto &ipv6 = state.ipv6;
  const auto &autoconfiguration = ipv6.autoconfiguration;
  const auto &mld = ipv6.mld;

  // A host object may be connected before it has an IP configuration. Its
  // physical link signal belongs to HostSlot, while all protocol owners remain
  // absent. Accepting any hidden socket, packet, neighbor or lifetime here
  // would let a later configuration inherit state created under no identity.
  return !endpoint.neighbor_valid && zero_octets(endpoint.neighbor_address) &&
         zero_octets(endpoint.neighbor_mac) &&
         !endpoint.pending_next_hop_valid &&
         zero_octets(endpoint.pending_next_hop) &&
         endpoint.next_ipv4_identification == 1U &&
         !endpoint.ipv4_probe_valid &&
         zero_octets(endpoint.ipv4_probe_destination) &&
         endpoint.ipv4_probe_packet.length == 0U &&
         state.ipv4_reassembly.empty() && state.ipv4_path_mtu.empty() &&
         state.ipv6_reassembly.empty() && state.frames.empty() && !state.tcp &&
         state.udp.sockets.empty() &&
         state.udp.ephemeral_cursor ==
             device_catalog::udp_ephemeral_port_first &&
         !state.ike_udp.configured &&
         std::all_of(state.ike_udp.sockets.begin(), state.ike_udp.sockets.end(),
                     [](const auto &socket) {
                       return socket == transport::UdpSocketHandle{};
                     }) &&
         autoconfiguration.default_routers.empty() &&
         autoconfiguration.on_link_prefixes.empty() &&
         autoconfiguration.addresses.empty() &&
         autoconfiguration.rdnss.empty() &&
         zero_octets(autoconfiguration.interface_identifier) &&
         zero_octets(autoconfiguration.stable_secret) &&
         autoconfiguration.network_id.empty() &&
         autoconfiguration.interface_id == 0U &&
         autoconfiguration.next_rdnss_order == 0U &&
         autoconfiguration.link_mtu == 0U &&
         autoconfiguration.effective_mtu == 0U &&
         autoconfiguration.current_hop_limit == 0U &&
         autoconfiguration.reachable_time_milliseconds == 0U &&
         autoconfiguration.retrans_timer_milliseconds == 0U &&
         !autoconfiguration.managed_configuration &&
         !autoconfiguration.other_configuration && ipv6.dad.empty() &&
         ipv6.neighbors.empty() && ipv6.destinations.empty() &&
         ipv6.path_mtu.empty() && mld.groups.empty() &&
         mld.older_querier_remaining_nanoseconds == 0 &&
         mld.random_state == 0U && !mld.version_one_compatibility &&
         !mld.link_operational && !mld.link_local_preferred &&
         ipv6.link_local_dad_counter == 0U &&
         ipv6.next_fragment_identification == 1U &&
         !ipv6.link_local_generation_exhausted &&
         ipv6.router_solicitation_remaining_nanoseconds == 0 &&
         ipv6.router_solicitations_sent == 0U &&
         !ipv6.router_solicitation_active;
}

enum class ForwardCommandKind : std::uint8_t {
  add_router,
  remove_router,
  configure_router_bof_management,
  begin_router_bof_dhcpv4_client,
  commit_router_bof_dhcpv4_client,
  abort_router_bof_dhcpv4_client,
  remove_router_bof_dhcpv4_client,
  begin_router_bof_dhcpv6_client,
  add_router_bof_dhcpv6_client_ia,
  add_router_bof_dhcpv6_client_option,
  commit_router_bof_dhcpv6_client,
  abort_router_bof_dhcpv6_client,
  remove_router_bof_dhcpv6_client,
  add_host,
  remove_host,
  configure_port,
  remove_port,
  configure_ospf_punt,
  program_fib,
  program_ipv6_fib,
  begin_ipv6_address_generation,
  add_ipv6_interface_address,
  commit_ipv6_address_generation,
  abort_ipv6_address_generation,
  begin_sap_generation,
  add_sap_attachment,
  add_service_ipv6_interface,
  commit_sap_generation,
  abort_sap_generation,
  install_static_ipv6_neighbor,
  remove_static_ipv6_neighbor,
  install_static_ipv4_neighbor,
  remove_static_ipv4_neighbor,
  clear_dynamic_ipv4_neighbors,
  clear_dynamic_ipv6_neighbors,
  configure_router_advertisement,
  remove_router_advertisement,
  configure_mld_interface,
  remove_mld_interface,
  configure_dhcpv4_relay,
  remove_dhcpv4_relay,
  begin_router_dhcpv4_server,
  add_router_dhcpv4_server_dns,
  add_router_dhcpv4_server_pool,
  add_router_dhcpv4_server_reservation,
  add_router_dhcpv4_server_exclusion,
  commit_router_dhcpv4_server,
  abort_router_dhcpv4_server,
  remove_router_dhcpv4_server,
  clear_router_dhcpv4_server_statistics,
  clear_router_dhcpv4_server_leases,
  send_router_dhcpv4_force_renew,
  begin_dhcpv6_relay,
  add_dhcpv6_relay_interface_id,
  add_dhcpv6_relay_server,
  commit_dhcpv6_relay,
  abort_dhcpv6_relay,
  remove_dhcpv6_relay,
  clear_dhcpv6_relay_leases,
  begin_router_dhcpv6_server,
  add_router_dhcpv6_server_dns,
  add_router_dhcpv6_server_address_pool,
  add_router_dhcpv6_server_prefix_pool,
  commit_router_dhcpv6_server,
  abort_router_dhcpv6_server,
  remove_router_dhcpv6_server,
  clear_router_dhcpv6_server_leases,
  clear_router_dhcpv6_server_statistics,
  clear_mld_database,
  clear_mld_database_all,
  clear_mld_version,
  clear_mld_statistics,
  clear_mld_statistics_all,
  edit_mld_static,
  program_mld_ssm_translation,
  program_mld_import_policy,
  clear_icmpv4_statistics_all,
  clear_icmpv4_global_statistics,
  clear_icmpv4_interface_statistics,
  clear_icmpv6_statistics_all,
  clear_icmpv6_global_statistics,
  clear_icmpv6_interface_statistics,
  clear_router_advertisement_statistics_all,
  clear_router_advertisement_interface_statistics,
  configure_host,
  begin_host_dhcpv4_client,
  commit_host_dhcpv4_client,
  abort_host_dhcpv4_client,
  remove_host_dhcpv4_client,
  begin_host_dhcpv4_server,
  add_host_dhcpv4_server_dns,
  add_host_dhcpv4_server_pool,
  add_host_dhcpv4_server_reservation,
  add_host_dhcpv4_server_exclusion,
  commit_host_dhcpv4_server,
  abort_host_dhcpv4_server,
  remove_host_dhcpv4_server,
  host_dhcpv4_client_status,
  begin_host_dhcpv6_client,
  add_host_dhcpv6_client_ia,
  add_host_dhcpv6_client_option,
  commit_host_dhcpv6_client,
  abort_host_dhcpv6_client,
  remove_host_dhcpv6_client,
  begin_host_dhcpv6_server,
  add_host_dhcpv6_server_dns,
  add_host_dhcpv6_server_address_pool,
  add_host_dhcpv6_server_prefix_pool,
  commit_host_dhcpv6_server,
  abort_host_dhcpv6_server,
  remove_host_dhcpv6_server,
  host_dhcpv6_client_status,
  begin_host_dns_resolver,
  begin_host_dns_root_hint,
  add_host_dns_root_address,
  commit_host_dns_root_hint,
  begin_host_dns_trust_anchor,
  add_host_dns_trust_anchor_rdata,
  commit_host_dns_trust_anchor,
  commit_host_dns_resolver,
  abort_host_dns_resolver,
  remove_host_dns_resolver,
  begin_host_dns_authoritative,
  begin_host_dns_signed_authoritative,
  begin_host_dns_zone,
  begin_host_dns_signed_zone,
  add_host_dns_signing_key,
  begin_host_dns_record,
  add_host_dns_rdata,
  commit_host_dns_record,
  commit_host_dns_zone,
  commit_host_dns_authoritative,
  abort_host_dns_authoritative,
  remove_host_dns_authoritative,
  start_host_dns_query,
  release_host_dns_query,
  set_host_link,
  host_link_status,
  set_router_bof_link,
  router_bof_link_status,
  router_ping,
  router_ipv6_ping,
  host_ping,
  router_ping_status,
  router_ipv6_ping_status,
  host_ping_status,
  pause,
  shutdown
};

struct Dhcpv6ClientBegin {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  crypto::Sha256Digest transaction_secret{};
  std::array<std::uint8_t, 255U> user_class{};
  std::uint32_t expected_associations{};
  std::uint32_t expected_options{};
  std::uint16_t duid_octets{};
  std::uint16_t user_class_octets{};
  std::uint32_t bootstrap_timeout_seconds{};
  bool rapid_commit{};
  bool information_only{};
};

struct Dhcpv4ClientBegin {
  packet::Mac hardware_address{};
  std::array<std::uint8_t, 255U> client_identifier{};
  std::array<std::uint8_t, 255U> parameter_request_list{};
  std::array<std::uint8_t, 254U> user_class{};
  crypto::Sha256Digest transaction_secret{};
  std::uint16_t client_identifier_octets{};
  std::uint16_t parameter_request_list_octets{};
  std::uint16_t user_class_octets{};
  std::uint16_t maximum_message_size{};
  std::uint32_t bootstrap_timeout_seconds{};
  bool broadcast{};
};

struct Dhcpv4ServerBegin {
  std::array<char, 32U> name{};
  packet::Ipv4 server_identifier{};
  std::uint64_t offer_hold_seconds{};
  std::uint64_t decline_hold_seconds{};
  std::uint32_t server_instance{};
  std::uint32_t routing_context{};
  std::uint32_t expected_dns_servers{};
  std::uint32_t expected_pools{};
  std::uint32_t expected_reservations{};
  std::uint32_t expected_exclusions{};
  std::uint8_t name_octets{};
  bool authoritative{};
  bool force_renews{};
};

struct Dhcpv6ClientAssociation {
  std::uint32_t iaid{};
  dhcpv6::LeaseKind kind{dhcpv6::LeaseKind::non_temporary};
};

struct Dhcpv6ClientOption {
  std::uint16_t code{};
};

struct Dhcpv6ServerBegin {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> duid{};
  std::array<char, 32U> name{};
  std::uint64_t decline_hold_seconds{};
  std::uint32_t expected_dns_servers{};
  std::uint32_t expected_address_pools{};
  std::uint32_t expected_prefix_pools{};
  std::uint32_t information_refresh_time_seconds{};
  std::uint32_t solicit_maximum_retransmission_seconds{};
  std::uint32_t information_maximum_retransmission_seconds{};
  std::uint16_t duid_octets{};
  std::uint8_t name_octets{};
  std::uint8_t preference{};
  std::uint8_t address_pool_index{};
  std::uint8_t prefix_pool_index{};
  bool rapid_commit{};
  // This value crosses the second SPSC boundary and becomes owned by the
  // server instance when the staged program commits atomically.
  bool lease_query{};
  bool has_solicit_maximum_retransmission{};
  bool has_information_maximum_retransmission{};
};

inline constexpr std::size_t dns_program_chunk_octets = 256U;

struct DnsResolverBegin {
  crypto::Sha256Digest identifier_secret{};
  std::uint32_t expected_root_hints{};
  std::uint32_t expected_trust_anchors{};
  std::uint16_t maximum_nsec3_iterations{};
  bool serve_clients{};
};

struct DnsRootHintBegin {
  packet::dns::Name server_name;
  std::uint32_t expected_addresses{};
};

struct DnsTrustAnchorBegin {
  packet::dns::Name owner;
  std::uint32_t ttl{};
  std::uint32_t expected_rdata_octets{};
  std::uint16_t record_class{packet::dns::internet_class};
};

struct DnsAuthoritativeBegin {
  std::uint32_t expected_zones{};
  std::uint64_t wall_now{};
};

struct DnsZoneBegin {
  packet::dns::Name origin;
  std::uint32_t expected_records{};
};

struct DnsSignedZoneBegin {
  packet::dns::Name origin;
  dnssec::ManagedZoneSigningPolicy policy{};
  std::uint32_t expected_records{};
  std::uint32_t expected_keys{};
};

struct DnsSigningKeyDefinition {
  dnssec::KeySchedule schedule{};
  dnssec::SigningKeyGeneration generation{};
  dnssec::KeyRole role{dnssec::KeyRole::zone_signing};
  std::uint8_t algorithm{};
};

struct DnsRecordBegin {
  packet::dns::Name owner;
  std::uint32_t ttl{};
  std::uint32_t expected_rdata_octets{};
  std::uint16_t type{};
  std::uint16_t record_class{packet::dns::internet_class};
};

struct DnsRdataChunk {
  std::array<std::uint8_t, dns_program_chunk_octets> octets{};
  std::uint16_t size{};
};

struct DnsTransactionCommand {
  packet::dns::Question question;
  dns::TransactionHandle transaction{};
};

using ForwardProgram = std::variant<
    routing::FibProgram, routing::Ipv6FibProgram, Ipv6AddressGenerationBegin,
    RouterIpv6Address, StaticIpv6NeighborProgram, StaticIpv4NeighborProgram,
    RouterAdvertisementProgram, MldInterfaceProgram, SapGenerationBegin,
    service::SapAttachment, service::ServiceIpv6Interface, Dhcpv4RelayBegin,
    Dhcpv6RelayBegin,
    Dhcpv6RelayInterfaceIdChunk, dhcpv6::RelayDestination,
    Dhcpv6RelayLeaseClearProgram, Dhcpv4ClientBegin, Dhcpv4ServerBegin,
    packet::Ipv4, dhcpv4::Pool, dhcpv4::Reservation,
    dhcpv4::ExcludedRange, RouterDhcpv4ServerOperation, Dhcpv6ClientBegin,
    Dhcpv6ClientAssociation,
    Dhcpv6ClientOption, Dhcpv6ServerBegin, packet::Ipv6, dhcpv6::LeasePool,
    RouterDhcpv6ServerOperation,
    DnsResolverBegin, DnsRootHintBegin, dns::ServerAddress, DnsTrustAnchorBegin,
    DnsAuthoritativeBegin, DnsZoneBegin, DnsSignedZoneBegin,
    DnsSigningKeyDefinition, DnsRecordBegin, DnsRdataChunk,
    DnsTransactionCommand>;

struct ForwardCommand {
  // Producer: link owner. Consumer: exactly one forwarding shard selected by
  // stable node index. Every field is a value, never a registry pointer.
  std::uint64_t id{};
  std::uint64_t logical_interface_id{};
  ForwardCommandKind kind{};
  DeviceHandle device{};
  crypto::Sha256Digest router_transport_secret{};
  bool transit_forwarding_enabled{true};
  HostHandle host{};
  ForwardPort port{};
  // One programming command carries one FIB or one RA projection. Keeping
  // alternatives in-place avoids summing unrelated maximum-size payloads in
  // every SPSC slot while retaining value ownership across the shard boundary.
  ForwardProgram fib{};
  HostNetworkProgram host_program{};
  std::uint32_t destination{};
  packet::Ipv6 ipv6_destination{};
  packet::Ipv6 ipv6_source{};
  packet::Ipv4 host_destination{};
  std::uint16_t sequence{};
  std::uint16_t payload_octets{56};
  std::chrono::steady_clock::time_point operation_now{};
  bool flag{};
  bool ospf_version_two{};
  bool ospf_version_three{};
  // Only clear_mld_database reads this discriminator. Keeping it explicit
  // prevents an unspecified IPv6 address from being confused with the valid
  // multicast group value ::, which the protocol owner must reject itself.
  bool mld_group_specific{};
  // Dynamic neighbor clear needs a presence discriminator because ordinal zero
  // is a valid interface. Family-specific bits keep the internal command ABI
  // explicit and prevent one command kind from accidentally reading another
  // family's selector state.
  bool ipv4_neighbor_interface_specific{};
  bool ipv6_neighbor_interface_specific{};
  MldStaticOperation mld_static_operation{};
  MldSsmProgramOperation mld_ssm_operation{};
  MldSsmTranslation mld_ssm_translation{};
  std::uint32_t mld_ssm_expected_entries{};
  mld::ImportPolicyProgramOperation mld_import_policy_operation{};
  mld::ImportPolicyEntry mld_import_policy_entry{};
  mld::ImportPolicyAction mld_import_policy_default_action{
      mld::ImportPolicyAction::accept};
  std::uint32_t mld_import_policy_expected_entries{};
};

struct ForwardResult {
  // Producer: one forwarding shard. Consumer: link owner. A result remains in
  // the bounded ring until consumed; a command is never acknowledged early.
  std::uint64_t id{};
  bool success{};
  std::uint64_t value{};
  dhcpv4::ClientStatus dhcpv4_client{};
};

struct ForwardIngress {
  // Producer: link owner after physical delivery. Consumer: destination
  // forwarding shard. Full ring means an explicit ingress queue tail drop.
  PortHandle destination{};
  packet::Frame frame{};
};

enum class ForwardEgressKind : std::uint8_t { transmit, cpm_punt };

struct ForwardEgress {
  // Producer: one forwarding shard. Consumer: link owner. CPM observations use
  // the same ordered path so capture never reads forwarding-owned objects.
  ForwardEgressKind kind{};
  NodeHandle source{};
  std::uint16_t ordinal{};
  packet::Frame frame{};
};

void spsc_copy(ForwardIngress &destination,
               const ForwardIngress &source) noexcept {
  destination.destination = source.destination;
  packet::copy_frame(destination.frame, source.frame);
}

void spsc_copy(ForwardEgress &destination,
               const ForwardEgress &source) noexcept {
  destination.kind = source.kind;
  destination.source = source.source;
  destination.ordinal = source.ordinal;
  packet::copy_frame(destination.frame, source.frame);
}

static_assert(std::is_trivially_copyable_v<ForwardCommand>);
static_assert(std::is_trivially_copyable_v<ForwardResult>);
static_assert(std::is_trivially_copyable_v<ForwardIngress>);
static_assert(std::is_trivially_copyable_v<ForwardEgress>);

class ForwardingShardWorker final {
public:
  using CommandHandler = ForwardResult (*)(void *, std::size_t,
                                           const ForwardCommand &) noexcept;
  using IngressHandler = void (*)(void *, std::size_t,
                                  const ForwardIngress &) noexcept;
  using MaintenanceHandler =
      std::optional<std::chrono::steady_clock::time_point> (*)(
          void *, std::size_t, std::chrono::steady_clock::time_point) noexcept;

  ForwardingShardWorker(std::size_t index, void *owner,
                        CommandHandler command_handler,
                        IngressHandler ingress_handler,
                        MaintenanceHandler maintenance_handler)
      : index_(index), owner_(owner), command_handler_(command_handler),
        ingress_handler_(ingress_handler),
        maintenance_handler_(maintenance_handler) {}

  ~ForwardingShardWorker() { stop(); }
  ForwardingShardWorker(const ForwardingShardWorker &) = delete;
  ForwardingShardWorker &operator=(const ForwardingShardWorker &) = delete;

  void start() {
    if (thread_.joinable())
      return;
    stop_requested_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
  }

  void stop() noexcept {
    if (!thread_.joinable())
      return;
    // Destruction follows the outer link-owner join, so no new ingress can be
    // published. Setting the stop word also releases a paused checkpoint
    // barrier without requiring another command result consumer.
    stop_requested_.store(true, std::memory_order_release);
    resume_requested_.store(true, std::memory_order_release);
    notify();
    thread_.join();
  }

  [[nodiscard]] bool submit(const ForwardCommand &command) noexcept {
    if (!commands_.try_push(command))
      return false;
    notify();
    return true;
  }

  [[nodiscard]] bool result(ForwardResult &value) noexcept {
    const bool consumed = results_.try_pop(value);
    if (consumed)
      notify();
    return consumed;
  }

  [[nodiscard]] bool deliver(const ForwardIngress &value) noexcept {
    if (!ingress_.try_push(value))
      return false;
    notify();
    return true;
  }

  [[nodiscard]] bool take_egress(ForwardEgress &value) noexcept {
    const bool consumed = egress_.try_pop(value);
    if (consumed)
      notify();
    return consumed;
  }

  [[nodiscard]] bool emit(const ForwardEgress &value) noexcept {
    if (!egress_.try_push(value))
      return false;
    if (link_wakeup_)
      link_wakeup_(link_context_);
    return true;
  }

  [[nodiscard]] bool can_emit(std::size_t frames) const noexcept {
    // ForwardingShardWorker is the sole producer of its egress ring. The link
    // owner can only release slots between this check and publication, so a
    // complete fragment batch admitted here cannot become partially full.
    return frames <= egress_.producer_available();
  }

  void set_link_wakeup(void *context, void (*wakeup)(void *)) noexcept {
    link_context_ = context;
    link_wakeup_ = wakeup;
  }

  void resume() noexcept {
    resume_requested_.store(true, std::memory_order_release);
    notify();
  }

  [[nodiscard]] std::uint64_t thread_id() const noexcept {
    return thread_id_.load(std::memory_order_acquire);
  }

  [[nodiscard]] std::uint64_t turns() const noexcept {
    return turns_.load(std::memory_order_acquire);
  }

private:
  void notify() noexcept {
    // Taking the same mutex as wait closes notify-before-sleep without making
    // ring bytes mutex-owned. SPSC release and acquire remain authoritative.
    {
      std::lock_guard lock(wait_mutex_);
    }
    wait_condition_.notify_one();
  }

  void run() noexcept {
    auto identity = static_cast<std::uint64_t>(
        std::hash<std::thread::id>{}(std::this_thread::get_id()));
    thread_id_.store(identity ? identity : 1U, std::memory_order_release);
    std::optional<ForwardCommand> pending_command;
    while (!stop_requested_.load(std::memory_order_acquire)) {
      turns_.fetch_add(1U, std::memory_order_relaxed);

      // A pending pause is ordered after every already delivered ingress
      // frame. The link owner stops producing ingress while awaiting the
      // barrier and drains egress, leaving no cross-shard frame outside the
      // fabric checkpoint when the pause result is observed.
      std::size_t ingress_budget = device_catalog::fabric_work_budget_frames;
      ForwardIngress ingress;
      while (ingress_budget-- && ingress_.try_pop(ingress))
        ingress_handler_(owner_, index_, ingress);

      if (!pending_command) {
        // ForwardCommand contains the largest generated FIB alternative.
        // Constructing a ring destination and then copying it into the pending
        // optional used two additional command-sized Wasm stack frames. Pop
        // directly into the persistent pending slot so the bounded command
        // remains value-owned without multiplying its cold-path stack cost.
        pending_command.emplace();
        if (!commands_.try_pop(*pending_command))
          pending_command.reset();
      }
      if (pending_command &&
          (pending_command->kind != ForwardCommandKind::pause ||
           ingress_.empty())) {
        // Keep the payload in the optional until its handler returns. Copying
        // it to a block local previously overlapped the handler's own staging
        // frame and could exhaust the fixed pthread stack during a large
        // transactional commit.
        const auto command_kind = pending_command->kind;
        const auto command_id = pending_command->id;
        auto result = command_kind == ForwardCommandKind::pause
                          ? ForwardResult{command_id, true, 0}
                          : command_handler_(owner_, index_, *pending_command);
        pending_command.reset();
        while (!results_.try_push(result) &&
               !stop_requested_.load(std::memory_order_acquire)) {
          std::unique_lock lock(wait_mutex_);
          wait_condition_.wait(lock, [&] {
            return stop_requested_.load(std::memory_order_acquire) ||
                   !results_.full();
          });
        }
        if (command_kind == ForwardCommandKind::shutdown) {
          stop_requested_.store(true, std::memory_order_release);
          break;
        }
        if (command_kind == ForwardCommandKind::pause) {
          resume_requested_.store(false, std::memory_order_release);
          std::unique_lock lock(wait_mutex_);
          wait_condition_.wait(lock, [&] {
            return stop_requested_.load(std::memory_order_acquire) ||
                   resume_requested_.load(std::memory_order_acquire);
          });
        }
      }

      // Neighbor timers are forwarding-owner deadlines. Running maintenance
      // here avoids a polling command from the link owner and wakes this shard
      // at the exact local deadline even when the physical medium is idle.
      const auto now = std::chrono::steady_clock::now();
      const auto maintenance_deadline =
          maintenance_handler_ ? maintenance_handler_(owner_, index_, now)
                               : std::nullopt;
      std::unique_lock lock(wait_mutex_);
      const auto ready = [&] {
        return stop_requested_.load(std::memory_order_acquire) ||
               pending_command.has_value() || !commands_.empty() ||
               !ingress_.empty();
      };
      if (!ready()) {
        if (maintenance_deadline)
          static_cast<void>(
              wait_condition_.wait_until(lock, *maintenance_deadline, ready));
        else
          wait_condition_.wait(lock, ready);
      }
    }
    thread_id_.store(0U, std::memory_order_release);
  }

  std::size_t index_{};
  void *owner_{};
  CommandHandler command_handler_{};
  IngressHandler ingress_handler_{};
  MaintenanceHandler maintenance_handler_{};
  SpscRing<ForwardCommand, device_catalog::network_command_ring_entries>
      commands_;
  SpscRing<ForwardResult, device_catalog::network_result_ring_entries> results_;
  SpscRing<ForwardIngress, device_catalog::forwarding_ring_frames> ingress_;
  SpscRing<ForwardEgress, device_catalog::forwarding_ring_frames> egress_;
  std::thread thread_;
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool resume_requested_{};
  std::atomic_uint64_t thread_id_{};
  std::atomic_uint64_t turns_{};
  void *link_context_{};
  void (*link_wakeup_)(void *){};
};

} // namespace

struct NetworkPlane::Impl {
  struct RouterSlot {
    std::uint16_t generation{};
    std::unique_ptr<RouterForwarder> forwarder;
    // The management endpoint is a separate protocol host attached to the
    // chassis OOB port. It never enters RouterForwarder's Base FIB and cannot
    // forward transit packets between management and data-plane interfaces.
    // EndpointStack carries bounded reassembly, neighbor and transport arenas.
    // Allocate it only for a platform whose BOF is configured so the fixed
    // 16-router registry does not reserve unused OOB packet state.
    std::unique_ptr<network_detail::EndpointStack> management_stack;
    bool management_configured{};
    bool management_link_signal{};
    struct BofDhcpv4ClientStaging {
      dhcpv4::ClientConfiguration configuration;
      std::chrono::seconds bootstrap_timeout{};
      bool active{};
    } bof_dhcpv4_client_staging;
    std::unique_ptr<network_detail::Dhcpv4EndpointService> bof_dhcpv4;
    Clock::time_point bof_dhcpv4_timeout{Clock::time_point::max()};
    struct BofDhcpv6ClientStaging {
      dhcpv6::ClientConfiguration configuration;
      std::uint32_t expected_associations{};
      std::uint32_t expected_options{};
      std::chrono::seconds bootstrap_timeout{};
      bool information_only{};
      bool active{};
    } bof_dhcpv6_client_staging;
    std::unique_ptr<network_detail::Dhcpv6EndpointService> bof_dhcpv6;
    Clock::time_point bof_dhcpv6_timeout{Clock::time_point::max()};
    struct RelayStaging {
      // This object has exactly one writer: the RouterSlot's forwarding
      // shard. expected_* values make Begin the only allocation admission
      // point and prevent malformed Add messages from growing either buffer.
      dhcpv6::RelayInterfaceConfig configuration;
      std::uint32_t expected_interface_id_octets{};
      std::uint16_t expected_servers{};
      bool active{};
    } dhcpv6_relay_staging;
    struct SapStaging {
      // The selected forwarding shard is the only writer. Begin performs the
      // sole reserve, Add accepts no surplus, and Commit transfers a complete
      // span into RouterForwarder's independently validated candidate table.
      std::vector<service::SapAttachment> attachments;
      std::vector<service::ServiceIpv6Interface> interfaces;
      std::uint32_t expected_attachments{};
      std::uint32_t expected_interfaces{};
      bool active{};
    } sap_staging;
    struct Ipv6AddressStaging {
      // One forwarding shard owns this cold-path vector. Begin reserves the
      // declared generation, Add cannot exceed it and Commit validates before
      // RouterForwarder swaps any live packet-path state.
      std::vector<RouterIpv6Address> addresses;
      std::uint32_t expected_addresses{};
      bool active{};
    } ipv6_address_staging;
    struct Dhcpv4ServerStaging {
      // Begin reserves all variable policy on this one forwarding owner. Add
      // messages cannot exceed declared counts and Commit is the sole point
      // at which RouterForwarder may replace a live named instance.
      std::string name;
      dhcpv4::ServerConfiguration configuration;
      std::vector<dhcpv4::Pool> pools;
      std::vector<dhcpv4::Reservation> reservations;
      std::vector<dhcpv4::ExcludedRange> exclusions;
      std::uint32_t expected_dns_servers{};
      std::uint32_t expected_pools{};
      std::uint32_t expected_reservations{};
      std::uint32_t expected_exclusions{};
      bool active{};
    } dhcpv4_server_staging;
    struct Dhcpv6ServerStaging {
      // Two fixed-message transactions assemble one replacement on the
      // network owner and then on the forwarding owner. No vector pointer or
      // CLI-owned string crosses either SPSC boundary.
      std::string name;
      dhcpv6::ServerConfiguration configuration;
      std::vector<dhcpv6::LeasePool> address_pools;
      std::vector<dhcpv6::LeasePool> prefix_pools;
      std::chrono::seconds decline_hold_time{};
      std::uint32_t expected_dns_servers{};
      std::uint32_t expected_address_pools{};
      std::uint32_t expected_prefix_pools{};
      bool active{};
    } dhcpv6_server_staging;
  };

  struct HostSlot {
    std::uint16_t generation{};
    network_detail::EndpointStack stack;
    std::uint16_t expected_sequence{};
    bool configured{};
    bool link_signal{};
    bool ping_pending{};
    bool ping_reply{};
    // Only the forwarding owner reads or writes these timestamps. The clock
    // starts when the encoded Echo Request, rather than a preceding ARP
    // request, is admitted to the fabric.
    bool ping_clock_started{};
    Clock::time_point ping_sent_at{};
    std::chrono::nanoseconds ping_reply_rtt{};
    std::uint8_t ping_reply_ttl{};
    struct Dhcpv4ClientStaging {
      dhcpv4::ClientConfiguration configuration;
      bool active{};
    } dhcpv4_client_staging;
    struct Dhcpv4ServerStaging {
      dhcpv4::ServerConfiguration configuration;
      std::vector<dhcpv4::Pool> pools;
      std::vector<dhcpv4::Reservation> reservations;
      std::vector<dhcpv4::ExcludedRange> exclusions;
      std::uint32_t expected_dns_servers{};
      std::uint32_t expected_pools{};
      std::uint32_t expected_reservations{};
      std::uint32_t expected_exclusions{};
      bool active{};
    } dhcpv4_server_staging;
    // One application owner holds both roles because UDP 67 and UDP 68 share
    // endpoint transport state and dynamic address ownership. The roles may
    // coexist, but neither can mutate the other's repository.
    std::unique_ptr<network_detail::Dhcpv4EndpointService> dhcpv4;
    struct ClientStaging {
      dhcpv6::ClientConfiguration configuration;
      std::uint32_t expected_associations{};
      std::uint32_t expected_options{};
      bool information_only{};
      bool active{};
    } dhcpv6_client_staging;
    struct ServerStaging {
      dhcpv6::ServerConfiguration configuration;
      std::vector<dhcpv6::LeasePool> address_pools;
      std::vector<dhcpv6::LeasePool> prefix_pools;
      std::chrono::seconds decline_hold_time{};
      std::uint32_t expected_dns_servers{};
      std::uint32_t expected_address_pools{};
      std::uint32_t expected_prefix_pools{};
      bool active{};
    } dhcpv6_server_staging;
    std::unique_ptr<network_detail::Dhcpv6EndpointService> dhcpv6;
    struct DnsResolverStaging {
      crypto::Sha256Digest identifier_secret{};
      std::vector<dns::RootHint> root_hints;
      std::vector<dns::ZoneRecord> trust_anchors;
      dns::ZoneRecord current_trust_anchor;
      dnssec::Nsec3IterationPolicy nsec3_policy{};
      std::uint32_t expected_root_hints{};
      std::uint32_t expected_current_addresses{};
      std::uint32_t expected_trust_anchors{};
      std::uint32_t expected_trust_anchor_rdata_octets{};
      bool root_active{};
      bool trust_anchor_active{};
      bool serve_clients{};
      bool active{};
    } dns_resolver_staging;
    struct DnsAuthoritativeStaging {
      struct SignedZone {
        dns::ZoneCheckpoint source;
        std::vector<DnsSigningKeyDefinition> keys;
        dnssec::ManagedZoneSigningPolicy policy{};
        std::uint32_t expected_keys{};
      };
      std::vector<dns::ZoneCheckpoint> zones;
      std::vector<SignedZone> signed_zones;
      dns::ZoneRecord current_record;
      std::uint64_t wall_now{};
      std::uint32_t expected_zones{};
      std::uint32_t expected_current_records{};
      std::uint32_t expected_rdata_octets{};
      bool zone_active{};
      bool record_active{};
      bool managed_signing{};
      bool active{};

      [[nodiscard]] dns::ZoneCheckpoint *current_zone() noexcept {
        if (managed_signing)
          return signed_zones.empty() ? nullptr : &signed_zones.back().source;
        return zones.empty() ? nullptr : &zones.back();
      }
    } dns_authoritative_staging;
    std::unique_ptr<network_detail::DnsEndpointService> dns;
  };

  struct SwitchSlot {
    // Link shard is the sole writer of all fields. The generated profile is
    // immutable process-lifetime storage, while forwarding contains the FDB,
    // port queues and aging deadlines for exactly this handle generation.
    std::uint16_t generation{};
    std::uint16_t profile_index{};
    const device_catalog::EthernetSwitchProfile *profile{};
    std::unique_ptr<EthernetSwitch> forwarding;
    // Each bounded owner turn resumes at the following physical port. A busy
    // low-numbered port therefore cannot starve another port on the switch.
    std::uint16_t egress_cursor{};
  };

  struct EgressContext {
    Impl *owner{};
    NodeHandle source{};
    ForwardingShardWorker *shard{};
  };

  struct PortBinding {
    // A live binding is owned by this network shard. Keeping the complete port
    // generation prevents a reinserted MDA from inheriting queued egress that
    // targeted the previous physical port instance.
    PortHandle port{};
    LinkHandle link{};
    std::uint8_t endpoint{};
  };

  struct CaptureBinding {
    // active separates CapturePointId zero from an unused location. The owner
    // handle prevents a removed and recreated router or link from inheriting a
    // diagnostic tap that belonged to an older generation.
    bool active{};
    CapturePointId id{};
    NodeHandle node{};
    LinkHandle link{};
  };

  std::array<RouterSlot, device_catalog::maximum_routers> routers{};
  std::array<HostSlot, device_catalog::maximum_hosts> hosts{};
  std::array<SwitchSlot, device_catalog::maximum_switches> switches{};
  // Link-owner generation mirrors validate capture and physical delivery
  // targets without reading forwarding-owned slot state across pthreads.
  std::array<std::uint16_t, device_catalog::maximum_routers>
      router_generations{};
  std::array<std::uint16_t, device_catalog::maximum_hosts> host_generations{};
  std::array<std::uint16_t, device_catalog::maximum_switches>
      switch_generations{};
  std::array<std::optional<LinkHandle>, device_catalog::maximum_links> links{};
  std::array<std::array<PortHandle, 2>, device_catalog::maximum_links>
      endpoints{};
  // Router and host indexes occupy separate registries, so separate tables
  // avoid adding a kind dimension to every packet-path lookup. The arenas are
  // allocated once inside Impl and never grow while frames are flowing.
  std::array<std::array<PortBinding, device_catalog::maximum_ports_per_router>,
             device_catalog::maximum_routers>
      router_bindings{};
  std::array<PortBinding, device_catalog::maximum_hosts> host_bindings{};
  std::array<std::array<PortBinding, device_catalog::maximum_switch_ports>,
             device_catalog::maximum_switches>
      switch_bindings{};
  std::array<std::array<CaptureBinding, 2>, device_catalog::maximum_links>
      link_captures{};
  std::array<
      std::array<CaptureBinding, device_catalog::maximum_ports_per_router>,
      device_catalog::maximum_routers>
      ingress_captures{};
  std::array<
      std::array<CaptureBinding, device_catalog::maximum_ports_per_router>,
      device_catalog::maximum_routers>
      egress_captures{};
  std::array<CaptureBinding, device_catalog::maximum_routers> cpm_captures{};
  std::unique_ptr<CaptureStore> capture{std::make_unique<CaptureStore>()};
  std::uint64_t capture_dropped{};
  // ingress and missing-binding loss have one link-owner writer. Egress loss
  // has up to three forwarding writers, so it alone requires an atomic. All
  // counters are monotonic and relaxed ordering is sufficient because frame
  // ownership is synchronized independently by the corresponding SPSC ring.
  std::uint64_t ingress_ring_dropped{};
  std::atomic_uint64_t egress_ring_dropped{};
  std::atomic_uint64_t ospf_ingress_dropped{};
  std::uint64_t missing_binding_dropped{};
  std::size_t switch_egress_cursor{};
  std::unique_ptr<MultiDeviceFabric> fabric{
      std::make_unique<MultiDeviceFabric>()};
  Clock::time_point now{};
  ShardPolicy policy{};
  std::size_t separate_forwarding_shards{};
  std::array<std::unique_ptr<ForwardingShardWorker>,
             device_catalog::high_forwarding_shards>
      forwarding_shards{};
  // Channels outlive the worker and every forwarding owner. Destruction first
  // joins the OSPF consumer, then forwarding producers, before releasing slot
  // storage.
  ospf::ControlChannels ospf_channels{};
  std::unique_ptr<ospf::ControlWorker> ospf_worker;
  std::uint64_t next_forward_command_id{1};
  std::uint64_t next_ospf_command_id{1};
  struct RouteManagerState {
    // This network-owner state is the sole place where connected, static and
    // protocol candidates meet. OSPF never writes a forwarding table and the
    // forwarding shards never inspect protocol-owned LSDB memory.
    RoutePolicyProgram policy{};
    routing::FibProgram base_ipv4{};
    routing::Ipv6FibProgram base_ipv6{};
    routing::RouteTable ipv4_rib{};
    routing::Ipv6RouteTable ipv6_rib{};
    std::vector<routing::DynamicInput> ospf_ipv4{};
    std::vector<routing::Ipv6DynamicInput> ospf_ipv6{};
    // Configured rows retain policy-accepted intent even while their source
    // route is absent from the selected RIB. Active rows are the last complete
    // transaction published to the OSPF owner. Separating both is what lets a
    // port failure withdraw an external LSA and a later recovery re-originate
    // it without rebuilding neighbors or guessing from topology state.
    std::vector<OspfExternalRouteProgram> configured_external_routes{};
    std::vector<OspfExternalRouteProgram> active_external_routes{};
    std::uint64_t ospf_generation{};
    std::uint64_t installed_ipv4_generation{};
    std::uint64_t installed_ipv6_generation{};
    bool policy_configured{};
    bool base_ipv4_configured{};
    bool base_ipv6_configured{};

    RouteManagerState() {
      // Active generations reserve the generated route ceiling at device
      // admission. After a borrowed channel generation has been selected and
      // programmed, retaining it therefore cannot fail due to vector growth.
      ospf_ipv4.reserve(device_catalog::maximum_dynamic_routes_per_router);
      ospf_ipv6.reserve(device_catalog::maximum_dynamic_routes_per_router);
    }
  };
  // Route tables contain profile-sized fixed arrays and are therefore
  // allocated only for admitted routers, not eagerly for every registry slot.
  std::array<std::unique_ptr<RouteManagerState>,
             device_catalog::maximum_routers>
      route_managers{};
  // NetworkPlane owns the complete forwarding projection derived from the
  // active OSPF generation. Bit zero represents OSPFv2 and bit one OSPFv3.
  // These are internal presence bits, not protocol or vendor numeric values.
  std::array<
      std::array<std::uint8_t, device_catalog::maximum_ports_per_router>,
      device_catalog::maximum_routers>
      ospf_punt_masks{};
  void *link_wakeup_context{};
  void (*link_wakeup)(void *){};
  std::array<std::uint8_t, 32U> signing_wrapping_key{};
  crypto::Sha256Digest signing_context_digest{};
  bool signing_vault_initialized{};

  explicit Impl(std::size_t logical_cpus)
      : policy(select_shard_policy(logical_cpus)),
        separate_forwarding_shards(
            policy.combined_forwarding_link() ? 0U : policy.forwarding) {
    // All host slots exist eagerly so worker ownership never races a heap
    // insertion. Their UDP and reassembly byte arenas are the only large
    // allocations not included directly in sizeof(Impl). Proving both costs
    // against the generated control reserve prevents a new protocol arena from
    // silently consuming the generated baseline assumed by runtime startup.
    constexpr auto endpoint_heap_arenas =
        device_catalog::maximum_hosts *
        (transport::UdpEndpoint::payload_arena_allocation_bytes +
         packet::Ipv4ReassemblyTable::payload_arena_allocation_bytes +
         packet::Ipv6ReassemblyTable::payload_arena_allocation_bytes +
         network_detail::EndpointStack::outbound_scratch_allocation_bytes);
    static_assert(sizeof(Impl) + endpoint_heap_arenas <=
                      device_catalog::runtime_control_reserve_bytes,
                  "network plane and host protocol arenas exceed the generated "
                  "control reserve");
    // Combined mode retains the direct owner path below. Medium and high host
    // policies allocate only the generated number of persistent actors.
    for (std::size_t index = 0; index < separate_forwarding_shards; ++index) {
      forwarding_shards[index] = std::make_unique<ForwardingShardWorker>(
          index, this, apply_forward_command, apply_forward_ingress,
          service_forwarding);
      forwarding_shards[index]->start();
    }
    // Protocol state has a permanent owner from runtime startup. Emscripten
    // uses a fixed pthread pool, so constructing this actor on the first OSPF
    // CLI command can block forever once generated pool entries already own
    // forwarding work. Startup allocation also makes admission atomic: the
    // lab either owns a usable protocol shard or fails before opening.
    ospf_worker = std::make_unique<ospf::ControlWorker>(
        ospf_channels,
        std::max<std::size_t>(1U, separate_forwarding_shards));
  }

  ~Impl() {
    ospf_worker.reset();
    // Joining forwarding owners before fabric and capture destruction prevents
    // a late egress callback from observing released link-owner state.
    for (std::size_t index = 0; index < separate_forwarding_shards; ++index)
      forwarding_shards[index]->stop();
    volatile std::uint8_t *key = signing_wrapping_key.data();
    for (std::size_t index{}; index < signing_wrapping_key.size(); ++index)
      key[index] = 0U;
  }

  [[nodiscard]] bool parallel() const noexcept {
    return separate_forwarding_shards != 0;
  }

  [[nodiscard]] bool install_ipv4_fib(
      DeviceHandle device, const routing::FibProgram &fib) noexcept;
  [[nodiscard]] bool install_ipv6_fib(
      DeviceHandle device, const routing::Ipv6FibProgram &fib) noexcept;
  [[nodiscard]] bool rebuild_managed_routes(
      DeviceHandle device, RouteManagerState &state,
      std::span<const routing::DynamicInput> ipv4_dynamic,
      std::span<const routing::Ipv6DynamicInput> ipv6_dynamic) noexcept;
  [[nodiscard]] bool reconcile_external_routes(
      DeviceHandle device, RouteManagerState &state) noexcept;
  void drain_ospf_routes() noexcept;

  [[nodiscard]] bool live(DeviceHandle handle) const noexcept {
    return handle && handle.index < router_generations.size() &&
           router_generations[handle.index] == handle.generation;
  }

  [[nodiscard]] bool live(HostHandle handle) const noexcept {
    return handle && handle.index < host_generations.size() &&
           host_generations[handle.index] == handle.generation;
  }

  [[nodiscard]] bool live(SwitchHandle handle) const noexcept {
    return handle && handle.index < switch_generations.size() &&
           switch_generations[handle.index] == handle.generation;
  }

  [[nodiscard]] ForwardingShardWorker &shard(NodeHandle handle) noexcept {
    // Stable handle indexes do not change during device lifetime. Modulo
    // placement is deterministic and no live device migrates between owners.
    return *forwarding_shards[handle.index % separate_forwarding_shards];
  }

  static ForwardResult
  apply_forward_command(void *context, std::size_t shard_index,
                        const ForwardCommand &command) noexcept;
  static void apply_forward_ingress(void *context, std::size_t shard_index,
                                    const ForwardIngress &ingress) noexcept;
  static std::optional<Clock::time_point>
  service_forwarding(void *context, std::size_t shard_index,
                     Clock::time_point now) noexcept;
  [[nodiscard]] ForwardResult
  execute_forward(const ForwardCommand &command) noexcept;
  [[nodiscard]] ospf::ControlResult
  execute_ospf(ospf::ControlCommand command) noexcept;
  [[nodiscard]] bool queue_egress(ForwardingShardWorker *shard,
                                  NodeHandle source, std::uint16_t ordinal,
                                  const packet::Frame &frame) noexcept;
  void drain_forwarding_egress() noexcept;
  void drain_ospf_egress(std::size_t shard_index,
                         ForwardingShardWorker *worker,
                         Clock::time_point current) noexcept;
  [[nodiscard]] bool pause_forwarding() noexcept;
  void resume_forwarding() noexcept;

  [[nodiscard]] RouterForwarder *router(DeviceHandle handle) noexcept {
    // Both compact index and generation participate. A delayed FIB program for
    // a deleted router cannot reach the replacement forwarder.
    if (handle.index >= routers.size())
      return nullptr;
    auto &slot = routers[handle.index];
    return slot.generation == handle.generation ? slot.forwarder.get()
                                                : nullptr;
  }

  [[nodiscard]] const RouterForwarder *
  router(DeviceHandle handle) const noexcept {
    if (handle.index >= routers.size())
      return nullptr;
    const auto &slot = routers[handle.index];
    return slot.generation == handle.generation ? slot.forwarder.get()
                                                : nullptr;
  }

  [[nodiscard]] HostSlot *host(HostHandle handle) noexcept {
    if (handle.index >= hosts.size())
      return nullptr;
    auto &slot = hosts[handle.index];
    return slot.generation == handle.generation ? &slot : nullptr;
  }

  [[nodiscard]] const HostSlot *host(HostHandle handle) const noexcept {
    if (handle.index >= hosts.size())
      return nullptr;
    const auto &slot = hosts[handle.index];
    return slot.generation == handle.generation ? &slot : nullptr;
  }

  [[nodiscard]] SwitchSlot *ethernet_switch(SwitchHandle handle) noexcept {
    if (handle.index >= switches.size())
      return nullptr;
    auto &slot = switches[handle.index];
    return slot.generation == handle.generation && slot.forwarding ? &slot
                                                                   : nullptr;
  }

  [[nodiscard]] const SwitchSlot *
  ethernet_switch(SwitchHandle handle) const noexcept {
    if (handle.index >= switches.size())
      return nullptr;
    const auto &slot = switches[handle.index];
    return slot.generation == handle.generation && slot.forwarding ? &slot
                                                                   : nullptr;
  }

  [[nodiscard]] PortBinding *binding(PortHandle port) noexcept {
    // Port ordinals are validated before indexing. Hosts expose only eth0 at
    // ordinal zero, while routers use hardware-generated stable ordinals.
    if (port.node.kind == NodeKind::host)
      return port.ordinal == 0 && port.node.index < host_bindings.size()
                 ? &host_bindings[port.node.index]
                 : nullptr;
    if (port.node.kind == NodeKind::ethernet_switch)
      return port.node.index < switch_bindings.size() &&
                     port.ordinal < switch_bindings[port.node.index].size()
                 ? &switch_bindings[port.node.index][port.ordinal]
                 : nullptr;
    return port.node.kind == NodeKind::router &&
                   port.node.index < router_bindings.size() &&
                   port.ordinal < router_bindings[port.node.index].size()
               ? &router_bindings[port.node.index][port.ordinal]
               : nullptr;
  }

  [[nodiscard]] const PortBinding *
  binding(NodeHandle node_handle, std::uint16_t ordinal) const noexcept {
    if (node_handle.kind == NodeKind::host)
      return ordinal == 0 && node_handle.index < host_bindings.size()
                 ? &host_bindings[node_handle.index]
                 : nullptr;
    if (node_handle.kind == NodeKind::ethernet_switch)
      return node_handle.index < switch_bindings.size() &&
                     ordinal < switch_bindings[node_handle.index].size()
                 ? &switch_bindings[node_handle.index][ordinal]
                 : nullptr;
    return node_handle.kind == NodeKind::router &&
                   node_handle.index < router_bindings.size() &&
                   ordinal < router_bindings[node_handle.index].size()
               ? &router_bindings[node_handle.index][ordinal]
               : nullptr;
  }

  void clear_binding(PortHandle port, LinkHandle link) noexcept {
    auto *current = binding(port);
    // A stale remove must not clear a newer cable on the same physical port.
    // Both link and full port generation therefore participate in ownership.
    if (current && current->link == link && current->port == port)
      *current = {};
  }

  void clear_capture_id(CapturePointId id) noexcept {
    // Rebinding one stable identity is a control operation. Scanning bounded
    // metadata here keeps packet observation a direct indexed lookup.
    for (auto &link : link_captures)
      for (auto &binding : link)
        if (binding.active && binding.id == id)
          binding = {};
    for (auto *table : {&ingress_captures, &egress_captures})
      for (auto &router : *table)
        for (auto &binding : router)
          if (binding.active && binding.id == id)
            binding = {};
    for (auto &binding : cpm_captures)
      if (binding.active && binding.id == id)
        binding = {};
  }

  void deactivate_capture(CaptureBinding &binding) noexcept {
    if (!binding.active)
      return;
    static_cast<void>(capture->deactivate_point(binding.id));
    binding = {};
  }

  void observe(const CaptureBinding &binding, NodeHandle expected,
               const packet::Frame &frame) noexcept {
    if (!binding.active || binding.node != expected)
      return;
    const auto timestamp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    // Capture uses wall time only as PCAP metadata. No protocol deadline or
    // packet delivery decision reads this clock.
    if (!capture->record(binding.id, frame,
                         static_cast<std::uint64_t>(timestamp)))
      ++capture_dropped;
  }

  void observe(const CaptureBinding &binding, LinkHandle expected,
               const packet::Frame &frame) noexcept {
    if (!binding.active || binding.link != expected)
      return;
    const auto timestamp =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    if (!capture->record(binding.id, frame,
                         static_cast<std::uint64_t>(timestamp)))
      ++capture_dropped;
  }

  [[nodiscard]] bool
  send(NodeHandle source, std::uint16_t ordinal, const packet::Frame &frame,
       ForwardingShardWorker *source_shard = nullptr) noexcept {
    if (parallel())
      return queue_egress(source_shard, source, ordinal, frame);
    const auto *current = binding(source, ordinal);
    // The binding includes the complete source generation. Index and ordinal
    // alone could send a delayed frame from a deleted router through a cable
    // now owned by its replacement.
    if (!current || current->port.node != source || !current->link) {
      ++missing_binding_dropped;
      return false;
    }
    // Router egress precedes medium admission. A frame rejected by the link
    // queue was still emitted by the router and belongs in the port egress tap,
    // but must not appear at the link-direction observation point.
    if (source.kind == NodeKind::router &&
        source.index < egress_captures.size() &&
        ordinal < egress_captures[source.index].size())
      observe(egress_captures[source.index][ordinal], source, frame);
    if (fabric->enqueue(current->link, current->endpoint, frame) !=
        MultiDeviceFabric::DropReason::none)
      return false;
    observe(link_captures[current->link.index][current->endpoint],
            current->link, frame);
    return true;
  }

  void drain_switch_egress() noexcept {
    // The link owner performs a bounded round-robin transfer from bridge port
    // queues to physical TX queues. A frame remains in the switch queue while
    // the corresponding medium queue is full, which models egress
    // backpressure rather than turning temporary congestion into an immediate
    // software drop.
    std::size_t budget = device_catalog::fabric_work_budget_frames;
    for (std::size_t visited_switches{};
         visited_switches < switches.size() && budget; ++visited_switches) {
      const auto switch_index =
          (switch_egress_cursor + visited_switches) % switches.size();
      auto &slot = switches[switch_index];
      if (!slot.forwarding || !slot.profile)
        continue;
      for (std::size_t visited_ports{};
           visited_ports < slot.profile->port_count && budget;
           ++visited_ports) {
        const auto port = static_cast<std::uint16_t>(
            (slot.egress_cursor + visited_ports) % slot.profile->port_count);
        const auto owner = node(SwitchHandle{
            static_cast<std::uint16_t>(switch_index), slot.generation});
        const auto *current = binding(owner, port);
        if (!current || current->port.node != owner || !current->link ||
            !fabric->can_enqueue(current->link, current->endpoint, 1U))
          continue;
        const auto queued = slot.forwarding->dequeue(port);
        if (!queued)
          continue;
        // Fabric retains the same immutable pool record before the switch
        // releases its queue reference. Broadcast fanout therefore performs no
        // frame-sized copy at this ownership boundary.
        const auto admitted =
            fabric->enqueue_shared(current->link, current->endpoint,
                                   queued->handle) ==
            MultiDeviceFabric::DropReason::none;
        if (admitted)
          observe(link_captures[current->link.index][current->endpoint],
                  current->link, *queued->frame);
        slot.forwarding->release(queued->handle);
        if (!admitted)
          ++missing_binding_dropped;
        --budget;
      }
      slot.egress_cursor = static_cast<std::uint16_t>(
          (slot.egress_cursor + 1U) % slot.profile->port_count);
    }
    switch_egress_cursor = (switch_egress_cursor + 1U) % switches.size();
  }

  static bool egress(void *context, std::uint16_t ordinal,
                     const packet::Frame &frame) noexcept {
    auto &value = *static_cast<EgressContext *>(context);
    // The callback writes only to the owner-local fabric admission queue. It
    // never discovers or invokes the destination device directly.
    return value.owner->send(value.source, ordinal, frame, value.shard);
  }

  static bool host_fragment_egress(void *context,
                                   const packet::Frame &frame) noexcept {
    // EndpointStack has one physical attachment at ordinal zero. Adapting the
    // fragment sink here keeps that topology fact out of the reusable DHCP
    // service and still routes every fragment through normal shard egress.
    return egress(context, 0U, frame);
  }

  static bool host_fragment_admission(void *context,
                                      std::size_t frames) noexcept {
    auto &value = *static_cast<EgressContext *>(context);
    if (!frames)
      return false;
    if (value.owner->parallel())
      return value.shard && value.shard->can_emit(frames);
    const auto *binding = value.owner->binding(value.source, 0U);
    return binding && binding->port.node == value.source && binding->link &&
           value.owner->fabric->can_enqueue(binding->link, binding->endpoint,
                                            frames);
  }

  static bool management_fragment_egress(
      void *context, const packet::Frame &frame) noexcept {
    // BOF DHCP shares EndpointStack with ordinary hosts but is physically
    // attached to the catalog management ordinal, never host ordinal zero.
    return egress(context, device_catalog::management_port_ordinal, frame);
  }

  static bool management_fragment_admission(void *context,
                                            std::size_t frames) noexcept {
    auto &value = *static_cast<EgressContext *>(context);
    if (!frames)
      return false;
    if (value.owner->parallel())
      return value.shard && value.shard->can_emit(frames);
    const auto *binding = value.owner->binding(
        value.source, device_catalog::management_port_ordinal);
    return binding && binding->port.node == value.source && binding->link &&
           value.owner->fabric->can_enqueue(binding->link, binding->endpoint,
                                            frames);
  }

  static bool router_fragment_admission(void *context, std::uint16_t ordinal,
                                        std::size_t frames) noexcept {
    auto &value = *static_cast<EgressContext *>(context);
    if (!frames)
      return false;
    if (value.owner->parallel())
      return value.shard && value.shard->can_emit(frames);
    const auto *binding = value.owner->binding(value.source, ordinal);
    return binding && binding->port.node == value.source && binding->link &&
           value.owner->fabric->can_enqueue(binding->link, binding->endpoint,
                                            frames);
  }

  static void deliver(void *context,
                      const MultiDeviceFabric::Delivery &delivery) {
    auto &owner = *static_cast<Impl *>(context);
    if (delivery.destination.node.kind == NodeKind::ethernet_switch) {
      const SwitchHandle handle{delivery.destination.node.index,
                                delivery.destination.node.generation};
      auto *slot = owner.ethernet_switch(handle);
      if (!slot ||
          delivery.destination.ordinal >= slot->profile->port_count)
        return;
      static_cast<void>(slot->forwarding->ingress(
          delivery.destination.ordinal, delivery.frame, owner.now));
      owner.drain_switch_egress();
      return;
    }
    if (owner.parallel()) {
      if (delivery.destination.node.kind == NodeKind::router &&
          delivery.destination.node.index < owner.ingress_captures.size() &&
          delivery.destination.ordinal <
              owner.ingress_captures[delivery.destination.node.index].size())
        owner.observe(owner.ingress_captures[delivery.destination.node.index]
                                            [delivery.destination.ordinal],
                      delivery.destination.node, delivery.frame);
      ForwardIngress ingress;
      ingress.destination = delivery.destination;
      packet::copy_frame(ingress.frame, delivery.frame);
      // Delivery has left the physical medium. A full forwarding ingress ring
      // is an explicit modeled tail drop, never a direct call into the router.
      if (!owner.shard(delivery.destination.node).deliver(ingress))
        ++owner.ingress_ring_dropped;
      return;
    }
    if (delivery.destination.node.kind == NodeKind::router) {
      const DeviceHandle handle{delivery.destination.node.index,
                                delivery.destination.node.generation};
      if (delivery.destination.ordinal ==
              device_catalog::management_port_ordinal &&
          handle.index < owner.routers.size()) {
        auto &slot = owner.routers[handle.index];
        if (!owner.router(handle) || !slot.management_configured)
          return;
        const auto result =
            slot.management_stack->receive(delivery.frame, 0U, false,
                                          owner.now);
        for (std::size_t index = 0; index < result.count; ++index)
          static_cast<void>(owner.send(
              node(handle), device_catalog::management_port_ordinal,
              result.frames[index]));
        return;
      }
      auto *forwarder = owner.router(handle);
      if (!forwarder)
        return;
      if (delivery.destination.node.index < owner.ingress_captures.size() &&
          delivery.destination.ordinal <
              owner.ingress_captures[delivery.destination.node.index].size())
        owner.observe(owner.ingress_captures[delivery.destination.node.index]
                                            [delivery.destination.ordinal],
                      delivery.destination.node, delivery.frame);
      EgressContext egress_context{&owner, delivery.destination.node, nullptr};
      owner.punt_node = delivery.destination.node;
      forwarder->receive(delivery.destination.ordinal, delivery.frame,
                         &egress_context, egress, owner.now, &egress_context,
                         punt, router_fragment_admission);
      // The callback is synchronous. Clearing the transient identity prevents
      // any later non-delivery code from attributing a packet to this router.
      owner.punt_node = {};
      return;
    }

    const HostHandle handle{delivery.destination.node.index,
                            delivery.destination.node.generation};
    auto *endpoint = owner.host(handle);
    if (!endpoint || !endpoint->configured)
      return;
    const auto result =
        endpoint->stack.receive(delivery.frame, endpoint->expected_sequence,
                                endpoint->ping_pending, owner.now);
    // ARP may release a retained Echo Request into the synchronous fabric.
    // Install the timestamp before sending those frames because a zero-delay
    // link can deliver the reply reentrantly from owner.send().
    if (result.start_echo_clock) {
      endpoint->ping_clock_started = true;
      endpoint->ping_sent_at = owner.now;
    }
    for (std::size_t index = 0; index < result.count; ++index)
      static_cast<void>(owner.send(node(handle), 0, result.frames[index]));
    if (result.echo_reply) {
      endpoint->ping_reply = true;
      endpoint->ping_pending = false;
      endpoint->ping_reply_ttl = result.echo_reply_ttl;
      endpoint->ping_reply_rtt =
          endpoint->ping_clock_started && owner.now >= endpoint->ping_sent_at
              ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                    owner.now - endpoint->ping_sent_at)
              : std::chrono::nanoseconds::zero();
      endpoint->ping_clock_started = false;
    }
  }

  static void punt(void *context, std::uint16_t ingress_port,
                   const packet::Frame &frame) noexcept {
    auto &egress_context = *static_cast<EgressContext *>(context);
    auto &owner = *egress_context.owner;
    const auto ipv4 = packet::parse_ipv4(frame);
    const auto ipv6 = packet::parse_ipv6(frame);
    const bool ospf_packet =
        (ipv4 && ipv4->protocol == packet::ospf::ip_protocol) ||
        (ipv6 &&
         ipv6->upper_layer_protocol == packet::ospf::ip_protocol);
    if (ospf_packet && owner.ospf_worker &&
        egress_context.source.kind == NodeKind::router) {
      const auto shard =
          egress_context.source.index %
          std::max<std::size_t>(1U, owner.separate_forwarding_shards);
      const DeviceHandle device{egress_context.source.index,
                                egress_context.source.generation};
      if (!owner.ospf_channels.ingress[shard].try_send(
              {.device = device,
               .interface_id = 0U,
               .physical_port_ordinal = ingress_port},
              frame))
        owner.ospf_ingress_dropped.fetch_add(1U,
                                             std::memory_order_relaxed);
      else
        owner.ospf_worker->notify();
    }
    if (owner.parallel()) {
      ForwardEgress observation;
      observation.kind = ForwardEgressKind::cpm_punt;
      observation.source = egress_context.source;
      observation.ordinal = 0xffffU;
      packet::copy_frame(observation.frame, frame);
      if (!egress_context.shard || !egress_context.shard->emit(observation))
        owner.egress_ring_dropped.fetch_add(1U, std::memory_order_relaxed);
      return;
    }
    // receive invokes this callback while deliver still identifies the router
    // in the current owner turn. The active delivery destination is retained
    // in punt_node only for that synchronous call.
    if (owner.punt_node.kind != NodeKind::router ||
        owner.punt_node.index >= owner.cpm_captures.size())
      return;
    owner.observe(owner.cpm_captures[owner.punt_node.index], owner.punt_node,
                  frame);
  }

  NodeHandle punt_node{};
};

ForwardResult NetworkPlane::Impl::apply_forward_command(
    void *context, std::size_t shard_index,
    const ForwardCommand &command) noexcept {
  auto &owner = *static_cast<Impl *>(context);
  ForwardResult result{.id = command.id};
  const NodeHandle target =
      command.device ? node(command.device) : node(command.host);
  if (!target.generation ||
      (owner.parallel() &&
       target.index % owner.separate_forwarding_shards != shard_index))
    return result;

  switch (command.kind) {
  case ForwardCommandKind::add_router: {
    if (command.device.index >= owner.routers.size())
      break;
    auto &slot = owner.routers[command.device.index];
    if (slot.forwarder)
      break;
    try {
      slot.forwarder = std::make_unique<RouterForwarder>(
          command.router_transport_secret);
      // Apply the role policy before the generation becomes visible. A server
      // therefore never has a transient interval in which it routes foreign
      // packets between two otherwise valid local interfaces.
      slot.forwarder->set_transit_forwarding(
          command.transit_forwarding_enabled);
      slot.generation = command.device.generation;
      result.success = true;
    } catch (const std::bad_alloc &) {
    }
    break;
  }
  case ForwardCommandKind::remove_router: {
    if (!owner.router(command.device))
      break;
    owner.routers[command.device.index] = {};
    result.success = true;
    break;
  }
  case ForwardCommandKind::configure_router_bof_management:
    if (command.device.index < owner.routers.size()) {
      auto &slot = owner.routers[command.device.index];
      if (!owner.router(command.device) ||
          command.host_program.prefix_length > 32U ||
          command.host_program.mtu <
              device_catalog::minimum_host_ipv4_mtu ||
          command.host_program.mtu > device_catalog::maximum_network_mtu)
        break;
      std::unique_ptr<network_detail::EndpointStack> replacement;
      try {
        replacement = std::make_unique<network_detail::EndpointStack>();
      } catch (const std::bad_alloc &) {
        break;
      }
      const bool configured = replacement->configure(
          {.endpoint_mac = command.host_program.mac,
           .endpoint_address = command.host_program.address,
           .endpoint_prefix_length = command.host_program.prefix_length,
           .endpoint_gateway = command.host_program.gateway,
           .endpoint_mtu = command.host_program.mtu,
           .endpoint_interface_id = command.host_program.interface_id,
           .endpoint_ipv6_autoconfiguration =
               command.host_program.ipv6_autoconfiguration,
           .endpoint_ipv6_identifier = command.host_program.ipv6_identifier,
           .endpoint_transport_secret =
               command.host_program.transport_secret});
      if (!configured)
        break;
      replacement->set_link_state(slot.management_link_signal);
      slot.management_stack = std::move(replacement);
      slot.management_configured = true;
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_router_bof_dhcpv4_client:
    if (command.device.index < owner.routers.size()) {
      auto &slot = owner.routers[command.device.index];
      const auto *begin = std::get_if<Dhcpv4ClientBegin>(&command.fib);
      if (!owner.router(command.device) || !slot.management_configured ||
          !begin ||
          begin->client_identifier_octets > begin->client_identifier.size() ||
          begin->parameter_request_list_octets >
              begin->parameter_request_list.size() ||
          begin->user_class_octets > begin->user_class.size() ||
          begin->bootstrap_timeout_seconds == 0U)
        break;
      try {
        RouterSlot::BofDhcpv4ClientStaging staged;
        staged.configuration.hardware_address = begin->hardware_address;
        staged.configuration.client_identifier.assign(
            begin->client_identifier.begin(),
            begin->client_identifier.begin() +
                begin->client_identifier_octets);
        staged.configuration.parameter_request_list.assign(
            begin->parameter_request_list.begin(),
            begin->parameter_request_list.begin() +
                begin->parameter_request_list_octets);
        staged.configuration.user_class.assign(
            begin->user_class.begin(),
            begin->user_class.begin() + begin->user_class_octets);
        staged.configuration.transaction_secret = begin->transaction_secret;
        staged.configuration.maximum_message_size =
            begin->maximum_message_size;
        staged.configuration.broadcast = begin->broadcast;
        staged.bootstrap_timeout =
            std::chrono::seconds{begin->bootstrap_timeout_seconds};
        staged.active = true;
        slot.bof_dhcpv4_client_staging = std::move(staged);
        result.success = true;
      } catch (...) {
      }
    }
    break;
  case ForwardCommandKind::commit_router_bof_dhcpv4_client:
    if (command.device.index < owner.routers.size()) {
      auto &slot = owner.routers[command.device.index];
      auto &staged = slot.bof_dhcpv4_client_staging;
      if (!owner.router(command.device) || !staged.active)
        break;
      try {
        if (!slot.bof_dhcpv4)
          slot.bof_dhcpv4 =
              std::make_unique<network_detail::Dhcpv4EndpointService>();
        const auto now = Clock::now();
        result.success = slot.bof_dhcpv4->configure_client(
            staged.configuration, *slot.management_stack, now);
        if (result.success)
          slot.bof_dhcpv4_timeout = now + staged.bootstrap_timeout;
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_router_bof_dhcpv4_client:
    if (command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      owner.routers[command.device.index].bof_dhcpv4_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_router_bof_dhcpv4_client:
    if (command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      auto &slot = owner.routers[command.device.index];
      if (slot.bof_dhcpv4)
        slot.bof_dhcpv4->remove_client(*slot.management_stack);
      slot.bof_dhcpv4_timeout = Clock::time_point::max();
      slot.bof_dhcpv4_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_router_bof_dhcpv6_client:
    if (command.device.index < owner.routers.size()) {
      auto &slot = owner.routers[command.device.index];
      const auto *begin = std::get_if<Dhcpv6ClientBegin>(&command.fib);
      if (!owner.router(command.device) || !slot.management_configured ||
          !begin || begin->user_class_octets > begin->user_class.size() ||
          begin->bootstrap_timeout_seconds == 0U)
        break;
      try {
        RouterSlot::BofDhcpv6ClientStaging staged;
        staged.configuration.duid = begin->duid;
        staged.configuration.duid_octets = begin->duid_octets;
        staged.configuration.transaction_secret = begin->transaction_secret;
        staged.configuration.user_class.assign(
            begin->user_class.begin(),
            begin->user_class.begin() + begin->user_class_octets);
        staged.configuration.rapid_commit = begin->rapid_commit;
        staged.configuration.identity_associations.reserve(
            begin->expected_associations);
        staged.configuration.requested_options.reserve(
            begin->expected_options);
        staged.expected_associations = begin->expected_associations;
        staged.expected_options = begin->expected_options;
        staged.bootstrap_timeout =
            std::chrono::seconds{begin->bootstrap_timeout_seconds};
        staged.information_only = begin->information_only;
        staged.active = true;
        slot.bof_dhcpv6_client_staging = std::move(staged);
        result.success = true;
      } catch (...) {
      }
    }
    break;
  case ForwardCommandKind::add_router_bof_dhcpv6_client_ia:
    if (command.device.index < owner.routers.size()) {
      auto &staged =
          owner.routers[command.device.index].bof_dhcpv6_client_staging;
      const auto *association =
          std::get_if<Dhcpv6ClientAssociation>(&command.fib);
      if (owner.router(command.device) && staged.active && association &&
          staged.configuration.identity_associations.size() <
              staged.expected_associations) {
        try {
          staged.configuration.identity_associations.push_back(
              {.iaid = association->iaid, .kind = association->kind});
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_router_bof_dhcpv6_client_option:
    if (command.device.index < owner.routers.size()) {
      auto &staged =
          owner.routers[command.device.index].bof_dhcpv6_client_staging;
      const auto *option = std::get_if<Dhcpv6ClientOption>(&command.fib);
      if (owner.router(command.device) && staged.active && option &&
          staged.configuration.requested_options.size() <
              staged.expected_options) {
        try {
          staged.configuration.requested_options.push_back(option->code);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_router_bof_dhcpv6_client:
    if (command.device.index < owner.routers.size()) {
      auto &slot = owner.routers[command.device.index];
      auto &staged = slot.bof_dhcpv6_client_staging;
      if (!owner.router(command.device) || !staged.active ||
          staged.configuration.identity_associations.size() !=
              staged.expected_associations ||
          staged.configuration.requested_options.size() !=
              staged.expected_options)
        break;
      try {
        if (!slot.bof_dhcpv6)
          slot.bof_dhcpv6 =
              std::make_unique<network_detail::Dhcpv6EndpointService>();
        const auto now = Clock::now();
        result.success = slot.bof_dhcpv6->configure_client(
            staged.configuration, staged.information_only,
            *slot.management_stack, now);
        if (result.success)
          slot.bof_dhcpv6_timeout = now + staged.bootstrap_timeout;
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_router_bof_dhcpv6_client:
    if (command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      owner.routers[command.device.index].bof_dhcpv6_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_router_bof_dhcpv6_client:
    if (command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      auto &slot = owner.routers[command.device.index];
      if (slot.bof_dhcpv6)
        slot.bof_dhcpv6->remove_client(*slot.management_stack);
      slot.bof_dhcpv6_timeout = Clock::time_point::max();
      slot.bof_dhcpv6_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::add_host:
    if (command.host.index < owner.hosts.size() &&
        !owner.hosts[command.host.index].generation) {
      owner.hosts[command.host.index].generation = command.host.generation;
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host:
    if (owner.host(command.host)) {
      owner.hosts[command.host.index] = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::configure_port:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->configure_port(command.port);
    break;
  case ForwardCommandKind::remove_port:
    if (auto *forwarder = owner.router(command.device);
        forwarder &&
        command.port.ordinal < device_catalog::maximum_ports_per_router) {
      forwarder->remove_port(command.port.ordinal);
      result.success = true;
    }
    break;
  case ForwardCommandKind::configure_ospf_punt:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->configure_ospf_punt(
          command.port.ordinal, command.ospf_version_two,
          command.ospf_version_three);
    break;
  case ForwardCommandKind::program_fib:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *fib = std::get_if<routing::FibProgram>(&command.fib))
        result.success = forwarder->program_fib(*fib);
    break;
  case ForwardCommandKind::program_ipv6_fib:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *fib = std::get_if<routing::Ipv6FibProgram>(&command.fib))
        result.success = forwarder->program_ipv6_fib(*fib);
    break;
  case ForwardCommandKind::begin_ipv6_address_generation:
    if (owner.router(command.device))
      if (const auto *begin =
              std::get_if<Ipv6AddressGenerationBegin>(&command.fib);
          begin &&
          begin->expected_addresses <= RouterIpv6AddressTable::capacity) {
        try {
          RouterSlot::Ipv6AddressStaging staged;
          staged.addresses.reserve(begin->expected_addresses);
          staged.expected_addresses = begin->expected_addresses;
          staged.active = true;
          owner.routers[command.device.index].ipv6_address_staging =
              std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // Publication has not started. The existing table and DAD generation
          // therefore remain intact when the cold-path reserve fails.
        }
      }
    break;
  case ForwardCommandKind::add_ipv6_interface_address:
    if (owner.router(command.device))
      if (const auto *address = std::get_if<RouterIpv6Address>(&command.fib)) {
        auto &staged = owner.routers[command.device.index].ipv6_address_staging;
        if (!staged.active ||
            staged.addresses.size() >= staged.expected_addresses)
          break;
        try {
          staged.addresses.push_back(*address);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // Begin owns allocation admission; a failed Add never changes live
          // state and Commit will reject the incomplete generation.
        }
      }
    break;
  case ForwardCommandKind::commit_ipv6_address_generation:
    if (auto *forwarder = owner.router(command.device); forwarder) {
      auto &staged = owner.routers[command.device.index].ipv6_address_staging;
      if (staged.active &&
          staged.addresses.size() == staged.expected_addresses) {
        const auto status = forwarder->program_ipv6_addresses(
            staged.addresses, command.operation_now);
        result.value = static_cast<std::uint64_t>(status);
        result.success = status == RouterIpv6AddressProgramStatus::accepted;
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_ipv6_address_generation:
    if (owner.router(command.device)) {
      owner.routers[command.device.index].ipv6_address_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_sap_generation:
    if (owner.router(command.device))
      if (const auto *begin = std::get_if<SapGenerationBegin>(&command.fib)) {
        try {
          RouterSlot::SapStaging staged;
          staged.attachments.reserve(begin->expected_attachments);
          staged.interfaces.reserve(begin->expected_interfaces);
          staged.expected_attachments = begin->expected_attachments;
          staged.expected_interfaces = begin->expected_interfaces;
          staged.active = true;
          owner.routers[command.device.index].sap_staging = std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // Live classification is unchanged because publication occurs only
          // in Commit after this private staging allocation succeeds.
        }
      }
    break;
  case ForwardCommandKind::add_sap_attachment:
    if (owner.router(command.device))
      if (const auto *attachment =
              std::get_if<service::SapAttachment>(&command.fib)) {
        auto &staged = owner.routers[command.device.index].sap_staging;
        if (!staged.active ||
            staged.attachments.size() >= staged.expected_attachments)
          break;
        try {
          staged.attachments.push_back(*attachment);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // Begin reserved the declared count, but retaining the guard keeps
          // the owner safe with a non-standard allocator implementation.
        }
      }
    break;
  case ForwardCommandKind::add_service_ipv6_interface:
    if (owner.router(command.device))
      if (const auto *interface =
              std::get_if<service::ServiceIpv6Interface>(&command.fib)) {
        auto &staged = owner.routers[command.device.index].sap_staging;
        if (!staged.active ||
            staged.interfaces.size() >= staged.expected_interfaces)
          break;
        try {
          staged.interfaces.push_back(*interface);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // Begin reserved the exact set. Allocation failure terminates this
          // record without exposing a partial live generation.
        }
      }
    break;
  case ForwardCommandKind::commit_sap_generation:
    if (auto *forwarder = owner.router(command.device); forwarder) {
      auto &staged = owner.routers[command.device.index].sap_staging;
      if (staged.active &&
          staged.attachments.size() == staged.expected_attachments &&
          staged.interfaces.size() == staged.expected_interfaces) {
        const auto status = forwarder->program_sap_generation(
            staged.attachments, staged.interfaces);
        result.value = static_cast<std::uint64_t>(status);
        result.success = status == service::SapProgramStatus::accepted;
      }
      // Commit is terminal even on validation failure. No later transaction
      // may accidentally append to or publish this rejected generation.
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_sap_generation:
    if (owner.router(command.device)) {
      owner.routers[command.device.index].sap_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::install_static_ipv6_neighbor:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *program =
              std::get_if<StaticIpv6NeighborProgram>(&command.fib))
        result.success = forwarder->install_static_ipv6_neighbor(
            program->port_ordinal, program->address, program->mac);
    break;
  case ForwardCommandKind::remove_static_ipv6_neighbor:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->remove_static_ipv6_neighbor(
          command.port.ordinal, command.ipv6_destination);
    break;
  case ForwardCommandKind::install_static_ipv4_neighbor:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *program =
              std::get_if<StaticIpv4NeighborProgram>(&command.fib))
        result.success = forwarder->install_static_ipv4_neighbor(
            program->port_ordinal, program->address, program->mac);
    break;
  case ForwardCommandKind::remove_static_ipv4_neighbor:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->remove_static_ipv4_neighbor(
          command.port.ordinal, command.destination);
    break;
  case ForwardCommandKind::clear_dynamic_ipv4_neighbors:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->clear_dynamic_ipv4_neighbors(
          command.ipv4_neighbor_interface_specific
              ? std::optional<std::uint16_t>{command.port.ordinal}
              : std::nullopt,
          command.destination == 0U
              ? std::nullopt
              : std::optional<std::uint32_t>{command.destination});
    break;
  case ForwardCommandKind::clear_dynamic_ipv6_neighbors:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->clear_dynamic_ipv6_neighbors(
          command.ipv6_neighbor_interface_specific
              ? std::optional<std::uint16_t>{command.port.ordinal}
              : std::nullopt,
          ip::is_unspecified(command.ipv6_destination)
              ? std::nullopt
              : std::optional<packet::Ipv6>{command.ipv6_destination});
    break;
  case ForwardCommandKind::configure_router_advertisement:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *program =
              std::get_if<RouterAdvertisementProgram>(&command.fib))
        result.success = forwarder->configure_router_advertisement(
            program->port_ordinal, program->enabled, program->config);
    break;
  case ForwardCommandKind::remove_router_advertisement:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->remove_router_advertisement(command.port.ordinal);
    break;
  case ForwardCommandKind::configure_mld_interface:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *program = std::get_if<MldInterfaceProgram>(&command.fib))
        result.success =
            forwarder->configure_mld_interface(program->configuration);
    break;
  case ForwardCommandKind::remove_mld_interface:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->remove_mld_interface(command.port.ordinal);
    break;
  case ForwardCommandKind::configure_dhcpv4_relay:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *begin = std::get_if<Dhcpv4RelayBegin>(&command.fib);
          begin && begin->circuit_id_octets <= begin->circuit_id.size() &&
          begin->remote_id_octets <= begin->remote_id.size() &&
          begin->server_count <= begin->servers.size()) {
        try {
          dhcpv4::RelayInterfaceConfiguration configuration{
              .interface_id = begin->interface_id,
              .physical_port_ordinal = begin->physical_port_ordinal,
              .relay = {}};
          configuration.relay.admin_enabled = true;
          configuration.relay.gateway_address = begin->gateway_address;
          configuration.relay.gateway_address_configured = true;
          configuration.relay.existing_information =
              begin->existing_information;
          configuration.relay.source_address = begin->source_address;
          configuration.relay.maximum_hops = begin->maximum_hops;
          configuration.relay.trusted_ingress = begin->trusted_ingress;
          configuration.relay.relay_plain_bootp = begin->relay_plain_bootp;
          configuration.relay.release_include_gateway_address =
              begin->release_include_gateway_address;
          configuration.relay.circuit_id.assign(
              begin->circuit_id.begin(),
              begin->circuit_id.begin() + begin->circuit_id_octets);
          configuration.relay.remote_id.assign(
              begin->remote_id.begin(),
              begin->remote_id.begin() + begin->remote_id_octets);
          configuration.relay.servers.reserve(begin->server_count);
          for (std::size_t index{}; index < begin->server_count; ++index)
            configuration.relay.servers.push_back(
                {.address = begin->servers[index]});
          result.success =
              forwarder->configure_dhcpv4_relay(std::move(configuration));
        } catch (const std::bad_alloc &) {
          result.success = false;
        }
      }
    break;
  case ForwardCommandKind::remove_dhcpv4_relay:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->remove_dhcpv4_relay(command.logical_interface_id);
    break;
  case ForwardCommandKind::begin_router_dhcpv4_server:
    if (owner.router(command.device))
      if (const auto *begin = std::get_if<Dhcpv4ServerBegin>(&command.fib);
          begin && begin->name_octets > 0U &&
          begin->name_octets <= begin->name.size() &&
          begin->expected_dns_servers <=
              packet::dhcpv4::maximum_ipv4_addresses_per_option &&
          begin->expected_pools <=
              device_catalog::dhcpv4_pools_per_server &&
          begin->expected_reservations <=
              device_catalog::dhcpv4_leases_per_server &&
          begin->expected_exclusions <=
              device_catalog::dhcpv4_leases_per_server) {
        try {
          RouterSlot::Dhcpv4ServerStaging staged;
          staged.name.assign(begin->name.data(), begin->name_octets);
          staged.configuration.server_identifier = begin->server_identifier;
          staged.configuration.offer_hold =
              std::chrono::seconds{begin->offer_hold_seconds};
          staged.configuration.decline_hold =
              std::chrono::seconds{begin->decline_hold_seconds};
          staged.configuration.server_instance = begin->server_instance;
          staged.configuration.routing_context = begin->routing_context;
          staged.configuration.authoritative = begin->authoritative;
          staged.configuration.force_renews = begin->force_renews;
          staged.configuration.domain_name_servers.reserve(
              begin->expected_dns_servers);
          staged.pools.reserve(begin->expected_pools);
          staged.reservations.reserve(begin->expected_reservations);
          staged.exclusions.reserve(begin->expected_exclusions);
          staged.expected_dns_servers = begin->expected_dns_servers;
          staged.expected_pools = begin->expected_pools;
          staged.expected_reservations = begin->expected_reservations;
          staged.expected_exclusions = begin->expected_exclusions;
          staged.active = true;
          owner.routers[command.device.index].dhcpv4_server_staging =
              std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    break;
  case ForwardCommandKind::add_router_dhcpv4_server_dns:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv4_server_staging;
      if (const auto *address = std::get_if<packet::Ipv4>(&command.fib);
          staged.active && address &&
          staged.configuration.domain_name_servers.size() <
              staged.expected_dns_servers) {
        try {
          staged.configuration.domain_name_servers.push_back(*address);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_router_dhcpv4_server_pool:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv4_server_staging;
      if (const auto *pool = std::get_if<dhcpv4::Pool>(&command.fib);
          staged.active && pool &&
          staged.pools.size() < staged.expected_pools) {
        try {
          staged.pools.push_back(*pool);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_router_dhcpv4_server_reservation:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv4_server_staging;
      if (const auto *reservation =
              std::get_if<dhcpv4::Reservation>(&command.fib);
          staged.active && reservation &&
          staged.reservations.size() < staged.expected_reservations) {
        try {
          staged.reservations.push_back(*reservation);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_router_dhcpv4_server_exclusion:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv4_server_staging;
      if (const auto *excluded =
              std::get_if<dhcpv4::ExcludedRange>(&command.fib);
          staged.active && excluded &&
          staged.exclusions.size() < staged.expected_exclusions) {
        try {
          staged.exclusions.push_back(*excluded);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_router_dhcpv4_server:
    if (auto *forwarder = owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv4_server_staging;
      if (staged.active &&
          staged.configuration.domain_name_servers.size() ==
              staged.expected_dns_servers &&
          staged.pools.size() == staged.expected_pools &&
          staged.reservations.size() == staged.expected_reservations &&
          staged.exclusions.size() == staged.expected_exclusions)
        result.success = forwarder->configure_dhcpv4_server(
            std::move(staged.name), staged.configuration, staged.pools,
            staged.reservations, staged.exclusions);
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_router_dhcpv4_server:
    if (owner.router(command.device)) {
      owner.routers[command.device.index].dhcpv4_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_router_dhcpv4_server:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *begin = std::get_if<Dhcpv4ServerBegin>(&command.fib);
          begin && begin->name_octets > 0U &&
          begin->name_octets <= begin->name.size())
        result.success = forwarder->remove_dhcpv4_server(
            std::string_view{begin->name.data(), begin->name_octets});
    break;
  case ForwardCommandKind::clear_router_dhcpv4_server_statistics:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *operation =
              std::get_if<RouterDhcpv4ServerOperation>(&command.fib);
          operation && operation->name_octets > 0U &&
          operation->name_octets <= operation->name.size())
        result.success = forwarder->clear_dhcpv4_server_statistics(
            std::string_view{operation->name.data(), operation->name_octets});
    break;
  case ForwardCommandKind::clear_router_dhcpv4_server_leases:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *operation =
              std::get_if<RouterDhcpv4ServerOperation>(&command.fib);
          operation && operation->name_octets > 0U &&
          operation->name_octets <= operation->name.size())
        result.success = forwarder->clear_dhcpv4_server_leases(
            std::string_view{operation->name.data(), operation->name_octets},
            operation->lease_filter, Clock::now());
    break;
  case ForwardCommandKind::send_router_dhcpv4_force_renew:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *operation =
              std::get_if<RouterDhcpv4ServerOperation>(&command.fib);
          operation && operation->name_octets > 0U &&
          operation->name_octets <= operation->name.size()) {
        auto *worker = owner.parallel()
                           ? owner.forwarding_shards[shard_index].get()
                           : nullptr;
        EgressContext egress_context{&owner, node(command.device), worker};
        const auto status = forwarder->send_dhcpv4_force_renew(
            std::string_view{operation->name.data(), operation->name_octets},
            operation->address, &egress_context, egress,
            router_fragment_admission, Clock::now());
        result.value = static_cast<std::uint64_t>(status);
        result.success = status == dhcpv4::ForceRenewStatus::encoded;
      }
    break;
  case ForwardCommandKind::clear_router_dhcpv6_server_leases:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *operation =
              std::get_if<RouterDhcpv6ServerOperation>(&command.fib);
          operation && operation->name_octets > 0U &&
          operation->name_octets <= operation->name.size())
        result.success = forwarder->clear_dhcpv6_server_leases(
            std::string_view{operation->name.data(), operation->name_octets},
            operation->lease_filter, Clock::now());
    break;
  case ForwardCommandKind::clear_router_dhcpv6_server_statistics:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *operation =
              std::get_if<RouterDhcpv6ServerOperation>(&command.fib);
          operation && operation->name_octets > 0U &&
          operation->name_octets <= operation->name.size())
        result.success = forwarder->clear_dhcpv6_server_statistics(
            std::string_view{operation->name.data(), operation->name_octets});
    break;
  case ForwardCommandKind::begin_dhcpv6_relay:
    if (auto *forwarder = owner.router(command.device); forwarder)
      if (const auto *begin = std::get_if<Dhcpv6RelayBegin>(&command.fib)) {
        // DHCPv6 option lengths are unsigned 16-bit wire values. Rejecting a
        // larger declaration here is protocol validation, while the 256-byte
        // message chunk remains only an internal transport granularity.
        if (begin->interface_id == 0U ||
            begin->physical_port_ordinal >=
                device_catalog::maximum_ports_per_router ||
            begin->expected_interface_id_octets >
                std::numeric_limits<std::uint16_t>::max() ||
            begin->expected_servers >
                device_catalog::dhcpv6_relay_servers_per_interface)
          break;
        try {
          RouterSlot::RelayStaging staged;
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
          staged.active = true;
          owner.routers[command.device.index].dhcpv6_relay_staging =
              std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // The live relay remains untouched. A later Begin may retry after
          // the caller reports resource exhaustion to configuration control.
        }
      }
    break;
  case ForwardCommandKind::add_dhcpv6_relay_interface_id:
    if (owner.router(command.device))
      if (const auto *chunk =
              std::get_if<Dhcpv6RelayInterfaceIdChunk>(&command.fib)) {
        auto &staged = owner.routers[command.device.index].dhcpv6_relay_staging;
        const auto current = staged.configuration.relay_interface_id.size();
        if (!staged.active || chunk->size == 0U ||
            chunk->size > chunk->octets.size() ||
            current > staged.expected_interface_id_octets ||
            chunk->size > staged.expected_interface_id_octets - current)
          break;
        try {
          staged.configuration.relay_interface_id.insert(
              staged.configuration.relay_interface_id.end(),
              chunk->octets.begin(), chunk->octets.begin() + chunk->size);
          result.success = true;
        } catch (const std::bad_alloc &) {
          // reserve() at Begin should make this path allocation-free. The
          // catch still protects native allocators with unusual guarantees.
        }
      }
    break;
  case ForwardCommandKind::add_dhcpv6_relay_server:
    if (owner.router(command.device))
      if (const auto *server =
              std::get_if<dhcpv6::RelayDestination>(&command.fib)) {
        auto &staged = owner.routers[command.device.index].dhcpv6_relay_staging;
        if (!staged.active ||
            staged.configuration.server_count >= staged.expected_servers)
          break;
        staged.configuration.servers[staged.configuration.server_count++] =
            *server;
        result.success = true;
      }
    break;
  case ForwardCommandKind::commit_dhcpv6_relay:
    if (auto *forwarder = owner.router(command.device); forwarder) {
      auto &staged = owner.routers[command.device.index].dhcpv6_relay_staging;
      if (staged.active &&
          staged.configuration.relay_interface_id.size() ==
              staged.expected_interface_id_octets &&
          staged.configuration.server_count == staged.expected_servers) {
        const auto status =
            forwarder->configure_dhcpv6_relay(std::move(staged.configuration));
        result.value = static_cast<std::uint64_t>(status);
        result.success = status == dhcpv6::RelayConfigStatus::accepted;
      }
      // Commit is terminal even when validation rejects the replacement. No
      // partially assembled policy remains available to a later transaction.
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_dhcpv6_relay:
    if (owner.router(command.device)) {
      owner.routers[command.device.index].dhcpv6_relay_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_dhcpv6_relay:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->remove_dhcpv6_relay(command.logical_interface_id);
    break;
  case ForwardCommandKind::clear_dhcpv6_relay_leases:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *program =
              std::get_if<Dhcpv6RelayLeaseClearProgram>(&command.fib)) {
        auto *worker = owner.parallel()
                           ? owner.forwarding_shards[shard_index].get()
                           : nullptr;
        EgressContext egress_context{&owner, node(command.device), worker};
        // Release packets use the same bounded forwarding-to-link path as
        // data traffic. The command callback never calls a server or another
        // device directly, even though the operation originated in CLI.
        result.success = forwarder->clear_dhcpv6_relay_leases(
            program->filter, program->no_dhcp_release, &egress_context, egress,
            router_fragment_admission, Clock::now());
      }
    break;
  case ForwardCommandKind::begin_router_dhcpv6_server:
    if (owner.router(command.device))
      if (const auto *begin = std::get_if<Dhcpv6ServerBegin>(&command.fib);
          begin && begin->name_octets > 0U &&
          begin->name_octets <= begin->name.size()) {
        try {
          RouterSlot::Dhcpv6ServerStaging staged;
          staged.name.assign(begin->name.data(), begin->name_octets);
          staged.configuration.duid = begin->duid;
          staged.configuration.duid_octets = begin->duid_octets;
          staged.configuration.preference = begin->preference;
          staged.configuration.address_pool_index = begin->address_pool_index;
          staged.configuration.prefix_pool_index = begin->prefix_pool_index;
          staged.configuration.information_refresh_time_seconds =
              begin->information_refresh_time_seconds;
          staged.configuration.rapid_commit = begin->rapid_commit;
          staged.configuration.lease_query = begin->lease_query;
          if (begin->has_solicit_maximum_retransmission)
            staged.configuration.solicit_maximum_retransmission_seconds =
                begin->solicit_maximum_retransmission_seconds;
          if (begin->has_information_maximum_retransmission)
            staged.configuration.information_maximum_retransmission_seconds =
                begin->information_maximum_retransmission_seconds;
          staged.configuration.dns_recursive_servers.reserve(
              begin->expected_dns_servers);
          staged.address_pools.reserve(begin->expected_address_pools);
          staged.prefix_pools.reserve(begin->expected_prefix_pools);
          staged.decline_hold_time =
              std::chrono::seconds{begin->decline_hold_seconds};
          staged.expected_dns_servers = begin->expected_dns_servers;
          staged.expected_address_pools = begin->expected_address_pools;
          staged.expected_prefix_pools = begin->expected_prefix_pools;
          staged.active = true;
          owner.routers[command.device.index].dhcpv6_server_staging =
              std::move(staged);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    break;
  case ForwardCommandKind::add_router_dhcpv6_server_dns:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv6_server_staging;
      if (const auto *address =
              std::get_if<packet::Ipv6>(&command.fib);
          staged.active && address &&
          staged.configuration.dns_recursive_servers.size() <
              staged.expected_dns_servers) {
        try {
          staged.configuration.dns_recursive_servers.push_back(*address);
          result.success = true;
        } catch (const std::bad_alloc &) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_router_dhcpv6_server_address_pool:
  case ForwardCommandKind::add_router_dhcpv6_server_prefix_pool:
    if (owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv6_server_staging;
      if (const auto *pool = std::get_if<dhcpv6::LeasePool>(&command.fib);
          staged.active && pool) {
        auto &target =
            command.kind ==
                    ForwardCommandKind::add_router_dhcpv6_server_address_pool
                ? staged.address_pools
                : staged.prefix_pools;
        const auto expected =
            command.kind ==
                    ForwardCommandKind::add_router_dhcpv6_server_address_pool
                ? staged.expected_address_pools
                : staged.expected_prefix_pools;
        if (target.size() < expected)
          try {
            target.push_back(*pool);
            result.success = true;
          } catch (const std::bad_alloc &) {
          }
      }
    }
    break;
  case ForwardCommandKind::commit_router_dhcpv6_server:
    if (auto *forwarder = owner.router(command.device)) {
      auto &staged =
          owner.routers[command.device.index].dhcpv6_server_staging;
      if (staged.active &&
          staged.configuration.dns_recursive_servers.size() ==
              staged.expected_dns_servers &&
          staged.address_pools.size() == staged.expected_address_pools &&
          staged.prefix_pools.size() == staged.expected_prefix_pools)
        result.success = forwarder->configure_dhcpv6_server(
            std::move(staged.name), staged.configuration,
            staged.address_pools, staged.prefix_pools,
            staged.decline_hold_time);
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_router_dhcpv6_server:
    if (owner.router(command.device)) {
      owner.routers[command.device.index].dhcpv6_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_router_dhcpv6_server:
    if (auto *forwarder = owner.router(command.device))
      if (const auto *begin = std::get_if<Dhcpv6ServerBegin>(&command.fib);
          begin && begin->name_octets > 0U &&
          begin->name_octets <= begin->name.size())
        result.success = forwarder->remove_dhcpv6_server(
            std::string_view{begin->name.data(), begin->name_octets});
    break;
  case ForwardCommandKind::clear_mld_database:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->clear_mld_database(
          command.port.ordinal,
          command.mld_group_specific
              ? std::optional<packet::Ipv6>{command.ipv6_destination}
              : std::nullopt);
    break;
  case ForwardCommandKind::clear_mld_database_all:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_mld_database_all();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_mld_version:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->clear_mld_version(command.port.ordinal);
    break;
  case ForwardCommandKind::clear_mld_statistics:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->clear_mld_statistics(command.port.ordinal);
    break;
  case ForwardCommandKind::clear_mld_statistics_all:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_mld_statistics_all();
      result.success = true;
    }
    break;
  case ForwardCommandKind::edit_mld_static:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->edit_mld_static(
          command.port.ordinal, command.mld_static_operation,
          command.ipv6_destination, command.ipv6_source);
    break;
  case ForwardCommandKind::program_mld_ssm_translation:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->program_mld_ssm_translation(
          command.port.ordinal, command.mld_ssm_operation,
          command.mld_ssm_translation, command.mld_ssm_expected_entries);
    break;
  case ForwardCommandKind::program_mld_import_policy:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->program_mld_import_policy(
          command.port.ordinal, command.mld_import_policy_operation,
          command.mld_import_policy_entry,
          command.mld_import_policy_default_action,
          command.mld_import_policy_expected_entries);
    break;
  case ForwardCommandKind::clear_icmpv4_statistics_all:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_icmpv4_statistics_all();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_icmpv4_global_statistics:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_icmpv4_global_statistics();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_icmpv4_interface_statistics:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->clear_icmpv4_interface_statistics(command.port.ordinal);
    break;
  case ForwardCommandKind::clear_icmpv6_statistics_all:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_icmpv6_statistics_all();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_icmpv6_global_statistics:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_icmpv6_global_statistics();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_icmpv6_interface_statistics:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->clear_icmpv6_interface_statistics(command.port.ordinal);
    break;
  case ForwardCommandKind::clear_router_advertisement_statistics_all:
    if (auto *forwarder = owner.router(command.device)) {
      forwarder->clear_router_advertisement_statistics_all();
      result.success = true;
    }
    break;
  case ForwardCommandKind::clear_router_advertisement_interface_statistics:
    if (auto *forwarder = owner.router(command.device))
      result.success =
          forwarder->clear_router_advertisement_interface_statistics(
              command.port.ordinal);
    break;
  case ForwardCommandKind::configure_host:
    if (auto *endpoint = owner.host(command.host_program.host);
        endpoint && command.host_program.prefix_length <= 32U &&
        command.host_program.mtu >= device_catalog::minimum_host_ipv4_mtu &&
        command.host_program.mtu <= device_catalog::maximum_network_mtu) {
      const bool configured = endpoint->stack.configure(
          {.endpoint_mac = command.host_program.mac,
           .endpoint_address = command.host_program.address,
           .endpoint_prefix_length = command.host_program.prefix_length,
           .endpoint_gateway = command.host_program.gateway,
           .endpoint_mtu = command.host_program.mtu,
           .endpoint_interface_id = command.host_program.interface_id,
           .endpoint_ipv6_autoconfiguration =
               command.host_program.ipv6_autoconfiguration,
           .endpoint_ipv6_identifier = command.host_program.ipv6_identifier,
           .endpoint_transport_secret = command.host_program.transport_secret});
      if (!configured)
        break;
      endpoint->stack.set_link_state(endpoint->link_signal);
      endpoint->configured = true;
      endpoint->ping_pending = false;
      endpoint->ping_reply = false;
      // Reconfiguration invalidates observations tied to the previous source
      // address and interface identity. Clearing the complete observation,
      // rather than only its two legacy flags, keeps checkpoint state atomic.
      endpoint->ping_clock_started = false;
      endpoint->ping_reply_rtt = std::chrono::nanoseconds::zero();
      endpoint->ping_reply_ttl = 0U;
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_host_dhcpv4_client:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured)
      if (const auto *begin = std::get_if<Dhcpv4ClientBegin>(&command.fib);
          begin &&
          begin->client_identifier_octets <= begin->client_identifier.size() &&
          begin->parameter_request_list_octets <=
              begin->parameter_request_list.size() &&
          begin->user_class_octets <= begin->user_class.size()) {
        try {
          HostSlot::Dhcpv4ClientStaging staged;
          staged.configuration.hardware_address = begin->hardware_address;
          staged.configuration.client_identifier.assign(
              begin->client_identifier.begin(),
              begin->client_identifier.begin() +
                  begin->client_identifier_octets);
          staged.configuration.parameter_request_list.assign(
              begin->parameter_request_list.begin(),
              begin->parameter_request_list.begin() +
                  begin->parameter_request_list_octets);
          staged.configuration.user_class.assign(
              begin->user_class.begin(),
              begin->user_class.begin() + begin->user_class_octets);
          staged.configuration.transaction_secret =
              begin->transaction_secret;
          staged.configuration.maximum_message_size =
              begin->maximum_message_size;
          staged.configuration.broadcast = begin->broadcast;
          staged.active = true;
          endpoint->dhcpv4_client_staging = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::commit_host_dhcpv4_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_client_staging;
      if (!staged.active)
        break;
      try {
        if (!endpoint->dhcpv4)
          endpoint->dhcpv4 =
              std::make_unique<network_detail::Dhcpv4EndpointService>();
        result.success = endpoint->dhcpv4->configure_client(
            staged.configuration, endpoint->stack, Clock::now());
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dhcpv4_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dhcpv4_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dhcpv4_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dhcpv4)
        endpoint->dhcpv4->remove_client(endpoint->stack);
      endpoint->dhcpv4_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_host_dhcpv4_server:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured)
      if (const auto *begin = std::get_if<Dhcpv4ServerBegin>(&command.fib);
          begin &&
          begin->expected_dns_servers <=
              packet::dhcpv4::maximum_ipv4_addresses_per_option &&
          begin->expected_pools <=
              device_catalog::dhcpv4_pools_per_server &&
          begin->expected_reservations <=
              device_catalog::dhcpv4_leases_per_server) {
        try {
          HostSlot::Dhcpv4ServerStaging staged;
          staged.configuration.server_instance = begin->server_instance;
          staged.configuration.routing_context = begin->routing_context;
          staged.configuration.server_identifier =
              begin->server_identifier;
          staged.configuration.offer_hold =
              std::chrono::seconds{begin->offer_hold_seconds};
          staged.configuration.decline_hold =
              std::chrono::seconds{begin->decline_hold_seconds};
          staged.configuration.authoritative = begin->authoritative;
          staged.configuration.force_renews = begin->force_renews;
          staged.configuration.domain_name_servers.reserve(
              begin->expected_dns_servers);
          staged.pools.reserve(begin->expected_pools);
          staged.reservations.reserve(begin->expected_reservations);
          staged.exclusions.reserve(begin->expected_exclusions);
          staged.expected_dns_servers = begin->expected_dns_servers;
          staged.expected_pools = begin->expected_pools;
          staged.expected_reservations = begin->expected_reservations;
          staged.expected_exclusions = begin->expected_exclusions;
          staged.active = true;
          endpoint->dhcpv4_server_staging = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dhcpv4_server_dns:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_server_staging;
      if (const auto *address = std::get_if<packet::Ipv4>(&command.fib);
          staged.active && address &&
          staged.configuration.domain_name_servers.size() <
              staged.expected_dns_servers) {
        try {
          staged.configuration.domain_name_servers.push_back(*address);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_host_dhcpv4_server_pool:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_server_staging;
      if (const auto *pool = std::get_if<dhcpv4::Pool>(&command.fib);
          staged.active && pool &&
          staged.pools.size() < staged.expected_pools) {
        try {
          staged.pools.push_back(*pool);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_host_dhcpv4_server_reservation:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_server_staging;
      if (const auto *reservation =
              std::get_if<dhcpv4::Reservation>(&command.fib);
          staged.active && reservation &&
          staged.reservations.size() < staged.expected_reservations) {
        try {
          staged.reservations.push_back(*reservation);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_host_dhcpv4_server_exclusion:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_server_staging;
      if (const auto *excluded =
              std::get_if<dhcpv4::ExcludedRange>(&command.fib);
          staged.active && excluded &&
          staged.exclusions.size() < staged.expected_exclusions) {
        try {
          staged.exclusions.push_back(*excluded);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_host_dhcpv4_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv4_server_staging;
      if (!staged.active ||
          staged.configuration.domain_name_servers.size() !=
              staged.expected_dns_servers ||
          staged.pools.size() != staged.expected_pools ||
          staged.reservations.size() != staged.expected_reservations ||
          staged.exclusions.size() != staged.expected_exclusions)
        break;
      try {
        if (!endpoint->dhcpv4)
          endpoint->dhcpv4 =
              std::make_unique<network_detail::Dhcpv4EndpointService>();
        result.success = endpoint->dhcpv4->configure_server(
            staged.configuration, staged.pools, staged.reservations,
            staged.exclusions, endpoint->stack);
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dhcpv4_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dhcpv4_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dhcpv4_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dhcpv4)
        endpoint->dhcpv4->remove_server(endpoint->stack);
      endpoint->dhcpv4_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::host_dhcpv4_client_status:
    if (const auto *endpoint = owner.host(command.host);
        endpoint && endpoint->dhcpv4 &&
        endpoint->dhcpv4->client_configured()) {
      result.success = true;
      result.dhcpv4_client = *endpoint->dhcpv4->client_status();
      result.value = result.dhcpv4_client.lease_present ? 1U : 0U;
    }
    break;
  case ForwardCommandKind::begin_host_dhcpv6_client:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured)
      if (const auto *begin = std::get_if<Dhcpv6ClientBegin>(&command.fib)) {
        if (begin->user_class_octets > begin->user_class.size())
          break;
        try {
          HostSlot::ClientStaging staged;
          staged.configuration.duid = begin->duid;
          staged.configuration.duid_octets = begin->duid_octets;
          staged.configuration.transaction_secret = begin->transaction_secret;
          staged.configuration.user_class.assign(
              begin->user_class.begin(),
              begin->user_class.begin() + begin->user_class_octets);
          staged.configuration.rapid_commit = begin->rapid_commit;
          staged.configuration.identity_associations.reserve(
              begin->expected_associations);
          staged.configuration.requested_options.reserve(
              begin->expected_options);
          staged.expected_associations = begin->expected_associations;
          staged.expected_options = begin->expected_options;
          staged.information_only = begin->information_only;
          staged.active = true;
          endpoint->dhcpv6_client_staging = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dhcpv6_client_ia:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_client_staging;
      if (const auto *association =
              std::get_if<Dhcpv6ClientAssociation>(&command.fib);
          staged.active && association &&
          staged.configuration.identity_associations.size() <
              staged.expected_associations) {
        try {
          staged.configuration.identity_associations.push_back(
              {.iaid = association->iaid, .kind = association->kind});
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_host_dhcpv6_client_option:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_client_staging;
      if (const auto *option = std::get_if<Dhcpv6ClientOption>(&command.fib);
          staged.active && option &&
          staged.configuration.requested_options.size() <
              staged.expected_options) {
        try {
          staged.configuration.requested_options.push_back(option->code);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_host_dhcpv6_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_client_staging;
      if (!staged.active ||
          staged.configuration.identity_associations.size() !=
              staged.expected_associations ||
          staged.configuration.requested_options.size() !=
              staged.expected_options)
        break;
      try {
        if (!endpoint->dhcpv6)
          endpoint->dhcpv6 =
              std::make_unique<network_detail::Dhcpv6EndpointService>();
        result.success = endpoint->dhcpv6->configure_client(
            staged.configuration, staged.information_only, endpoint->stack,
            Clock::now());
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dhcpv6_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dhcpv6_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dhcpv6_client:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dhcpv6)
        endpoint->dhcpv6->remove_client(endpoint->stack);
      endpoint->dhcpv6_client_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_host_dhcpv6_server:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured)
      if (const auto *begin = std::get_if<Dhcpv6ServerBegin>(&command.fib)) {
        try {
          HostSlot::ServerStaging staged;
          staged.configuration.duid = begin->duid;
          staged.configuration.duid_octets = begin->duid_octets;
          staged.configuration.preference = begin->preference;
          staged.configuration.address_pool_index = begin->address_pool_index;
          staged.configuration.prefix_pool_index = begin->prefix_pool_index;
          staged.configuration.information_refresh_time_seconds =
              begin->information_refresh_time_seconds;
          staged.configuration.rapid_commit = begin->rapid_commit;
          staged.configuration.lease_query = begin->lease_query;
          if (begin->has_solicit_maximum_retransmission)
            staged.configuration.solicit_maximum_retransmission_seconds =
                begin->solicit_maximum_retransmission_seconds;
          if (begin->has_information_maximum_retransmission)
            staged.configuration.information_maximum_retransmission_seconds =
                begin->information_maximum_retransmission_seconds;
          staged.configuration.dns_recursive_servers.reserve(
              begin->expected_dns_servers);
          staged.address_pools.reserve(begin->expected_address_pools);
          staged.prefix_pools.reserve(begin->expected_prefix_pools);
          staged.decline_hold_time =
              std::chrono::seconds{begin->decline_hold_seconds};
          staged.expected_dns_servers = begin->expected_dns_servers;
          staged.expected_address_pools = begin->expected_address_pools;
          staged.expected_prefix_pools = begin->expected_prefix_pools;
          staged.active = true;
          endpoint->dhcpv6_server_staging = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dhcpv6_server_dns:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_server_staging;
      if (const auto *address = std::get_if<packet::Ipv6>(&command.fib);
          staged.active && address &&
          staged.configuration.dns_recursive_servers.size() <
              staged.expected_dns_servers) {
        try {
          staged.configuration.dns_recursive_servers.push_back(*address);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::add_host_dhcpv6_server_address_pool:
  case ForwardCommandKind::add_host_dhcpv6_server_prefix_pool:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_server_staging;
      const auto *pool = std::get_if<dhcpv6::LeasePool>(&command.fib);
      auto &target_pools =
          command.kind ==
                  ForwardCommandKind::add_host_dhcpv6_server_address_pool
              ? staged.address_pools
              : staged.prefix_pools;
      const auto expected =
          command.kind ==
                  ForwardCommandKind::add_host_dhcpv6_server_address_pool
              ? staged.expected_address_pools
              : staged.expected_prefix_pools;
      if (staged.active && pool && target_pools.size() < expected) {
        try {
          target_pools.push_back(*pool);
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_host_dhcpv6_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dhcpv6_server_staging;
      if (!staged.active ||
          staged.configuration.dns_recursive_servers.size() !=
              staged.expected_dns_servers ||
          staged.address_pools.size() != staged.expected_address_pools ||
          staged.prefix_pools.size() != staged.expected_prefix_pools)
        break;
      try {
        if (!endpoint->dhcpv6)
          endpoint->dhcpv6 =
              std::make_unique<network_detail::Dhcpv6EndpointService>();
        result.success = endpoint->dhcpv6->configure_server(
            staged.configuration, staged.address_pools, staged.prefix_pools,
            staged.decline_hold_time, endpoint->stack, Clock::now());
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dhcpv6_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dhcpv6_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dhcpv6_server:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dhcpv6)
        endpoint->dhcpv6->remove_server(endpoint->stack, Clock::now());
      endpoint->dhcpv6_server_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::host_dhcpv6_client_status:
    if (const auto *endpoint = owner.host(command.host);
        endpoint && endpoint->dhcpv6 && endpoint->dhcpv6->client_configured()) {
      result.success = true;
      result.value = endpoint->dhcpv6->client_lease_count();
    }
    break;
  case ForwardCommandKind::begin_host_dns_resolver:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsResolverBegin>(&command.fib)) {
        try {
          HostSlot::DnsResolverStaging staged;
          staged.identifier_secret = begin->identifier_secret;
          staged.root_hints.reserve(begin->expected_root_hints);
          staged.trust_anchors.reserve(begin->expected_trust_anchors);
          staged.expected_root_hints = begin->expected_root_hints;
          staged.expected_trust_anchors = begin->expected_trust_anchors;
          staged.nsec3_policy.maximum = begin->maximum_nsec3_iterations;
          staged.serve_clients = begin->serve_clients;
          staged.active = true;
          endpoint->dns_resolver_staging = std::move(staged);
          result.success = true;
        } catch (...) {
          // Begin is the allocation admission point. Existing resolver state
          // remains live when the requested configuration cannot be staged.
        }
      }
    break;
  case ForwardCommandKind::begin_host_dns_root_hint:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsRootHintBegin>(&command.fib)) {
        auto &staged = endpoint->dns_resolver_staging;
        if (!staged.active || staged.root_active ||
            staged.root_hints.size() >= staged.expected_root_hints ||
            begin->expected_addresses == 0U)
          break;
        try {
          dns::RootHint hint{.server_name = begin->server_name,
                             .addresses = {}};
          hint.addresses.reserve(begin->expected_addresses);
          staged.root_hints.push_back(std::move(hint));
          staged.expected_current_addresses = begin->expected_addresses;
          staged.root_active = true;
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dns_root_address:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *address = std::get_if<dns::ServerAddress>(&command.fib)) {
        auto &staged = endpoint->dns_resolver_staging;
        if (!staged.active || !staged.root_active ||
            staged.root_hints.empty() ||
            staged.root_hints.back().addresses.size() >=
                staged.expected_current_addresses)
          break;
        try {
          staged.root_hints.back().addresses.push_back(*address);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::commit_host_dns_root_hint:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_resolver_staging;
      if (staged.active && staged.root_active && !staged.root_hints.empty() &&
          staged.root_hints.back().addresses.size() ==
              staged.expected_current_addresses) {
        staged.root_active = false;
        staged.expected_current_addresses = 0U;
        result.success = true;
      }
    }
    break;
  case ForwardCommandKind::begin_host_dns_trust_anchor:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsTrustAnchorBegin>(&command.fib)) {
        auto &staged = endpoint->dns_resolver_staging;
        if (!staged.active || staged.root_active ||
            staged.trust_anchor_active ||
            staged.trust_anchors.size() >= staged.expected_trust_anchors ||
            begin->expected_rdata_octets == 0U ||
            begin->expected_rdata_octets >
                std::numeric_limits<std::uint16_t>::max())
          break;
        try {
          staged.current_trust_anchor = {.owner = begin->owner,
                                         .type = packet::dns::type_dnskey,
                                         .record_class = begin->record_class,
                                         .ttl = begin->ttl,
                                         .rdata = {}};
          staged.current_trust_anchor.rdata.reserve(
              begin->expected_rdata_octets);
          staged.expected_trust_anchor_rdata_octets =
              begin->expected_rdata_octets;
          staged.trust_anchor_active = true;
          result.success = true;
        } catch (...) {
          staged.current_trust_anchor = {};
          staged.expected_trust_anchor_rdata_octets = 0U;
          staged.trust_anchor_active = false;
        }
      }
    break;
  case ForwardCommandKind::add_host_dns_trust_anchor_rdata:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *chunk = std::get_if<DnsRdataChunk>(&command.fib)) {
        auto &staged = endpoint->dns_resolver_staging;
        const auto current = staged.current_trust_anchor.rdata.size();
        if (!staged.active || !staged.trust_anchor_active ||
            chunk->size == 0U || chunk->size > chunk->octets.size() ||
            current > staged.expected_trust_anchor_rdata_octets ||
            chunk->size > staged.expected_trust_anchor_rdata_octets - current)
          break;
        try {
          staged.current_trust_anchor.rdata.insert(
              staged.current_trust_anchor.rdata.end(), chunk->octets.begin(),
              chunk->octets.begin() + chunk->size);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::commit_host_dns_trust_anchor:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_resolver_staging;
      if (!staged.active || !staged.trust_anchor_active ||
          staged.current_trust_anchor.rdata.size() !=
              staged.expected_trust_anchor_rdata_octets)
        break;
      try {
        staged.trust_anchors.push_back(std::move(staged.current_trust_anchor));
        staged.current_trust_anchor = {};
        staged.expected_trust_anchor_rdata_octets = 0U;
        staged.trust_anchor_active = false;
        result.success = true;
      } catch (...) {
      }
    }
    break;
  case ForwardCommandKind::commit_host_dns_resolver:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_resolver_staging;
      if (!endpoint->configured || !staged.active || staged.root_active ||
          staged.trust_anchor_active ||
          staged.root_hints.size() != staged.expected_root_hints ||
          staged.trust_anchors.size() != staged.expected_trust_anchors)
        break;
      try {
        if (!endpoint->dns)
          endpoint->dns =
              std::make_unique<network_detail::DnsEndpointService>();
        result.success = endpoint->dns->configure_resolver(
            staged.identifier_secret, std::move(staged.root_hints),
            std::move(staged.trust_anchors), staged.nsec3_policy,
            staged.serve_clients, endpoint->stack);
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dns_resolver:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dns_resolver_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dns_resolver:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dns)
        endpoint->dns->remove_resolver(endpoint->stack);
      endpoint->dns_resolver_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::begin_host_dns_authoritative:
  case ForwardCommandKind::begin_host_dns_signed_authoritative:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin =
              std::get_if<DnsAuthoritativeBegin>(&command.fib)) {
        const bool managed =
            command.kind ==
            ForwardCommandKind::begin_host_dns_signed_authoritative;
        if (begin->expected_zones == 0U || (managed && !begin->wall_now) ||
            (managed && !owner.signing_vault_initialized))
          break;
        try {
          HostSlot::DnsAuthoritativeStaging staged;
          if (managed)
            staged.signed_zones.reserve(begin->expected_zones);
          else
            staged.zones.reserve(begin->expected_zones);
          staged.wall_now = begin->wall_now;
          staged.expected_zones = begin->expected_zones;
          staged.managed_signing = managed;
          staged.active = true;
          endpoint->dns_authoritative_staging = std::move(staged);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::begin_host_dns_zone:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsZoneBegin>(&command.fib)) {
        auto &staged = endpoint->dns_authoritative_staging;
        if (!staged.active || staged.managed_signing || staged.zone_active ||
            staged.record_active ||
            staged.zones.size() >= staged.expected_zones ||
            begin->expected_records == 0U)
          break;
        try {
          dns::ZoneCheckpoint zone{.origin = begin->origin, .records = {}};
          zone.records.reserve(begin->expected_records);
          staged.zones.push_back(std::move(zone));
          staged.expected_current_records = begin->expected_records;
          staged.zone_active = true;
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::begin_host_dns_signed_zone:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsSignedZoneBegin>(&command.fib)) {
        auto &staged = endpoint->dns_authoritative_staging;
        if (!staged.active || !staged.managed_signing || staged.zone_active ||
            staged.record_active ||
            staged.signed_zones.size() >= staged.expected_zones ||
            begin->expected_records == 0U || begin->expected_keys == 0U ||
            !dnssec::valid_managed_zone_policy(begin->policy))
          break;
        try {
          HostSlot::DnsAuthoritativeStaging::SignedZone zone{
              .source = {.origin = begin->origin, .records = {}},
              .keys = {},
              .policy = begin->policy,
              .expected_keys = begin->expected_keys};
          zone.source.records.reserve(begin->expected_records);
          zone.keys.reserve(begin->expected_keys);
          staged.signed_zones.push_back(std::move(zone));
          staged.expected_current_records = begin->expected_records;
          staged.zone_active = true;
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dns_signing_key:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *key =
              std::get_if<DnsSigningKeyDefinition>(&command.fib)) {
        auto &staged = endpoint->dns_authoritative_staging;
        if (!staged.active || !staged.managed_signing || !staged.zone_active ||
            staged.record_active || staged.signed_zones.empty() ||
            staged.signed_zones.back().keys.size() >=
                staged.signed_zones.back().expected_keys ||
            !dnssec::valid_schedule(key->schedule) || !key->algorithm)
          break;
        try {
          staged.signed_zones.back().keys.push_back(*key);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::begin_host_dns_record:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *begin = std::get_if<DnsRecordBegin>(&command.fib)) {
        auto &staged = endpoint->dns_authoritative_staging;
        const auto *zone = staged.current_zone();
        if (!staged.active || !staged.zone_active || staged.record_active ||
            !zone || zone->records.size() >= staged.expected_current_records ||
            begin->expected_rdata_octets >
                std::numeric_limits<std::uint16_t>::max())
          break;
        try {
          staged.current_record = {.owner = begin->owner,
                                   .type = begin->type,
                                   .record_class = begin->record_class,
                                   .ttl = begin->ttl,
                                   .rdata = {}};
          staged.current_record.rdata.reserve(begin->expected_rdata_octets);
          staged.expected_rdata_octets = begin->expected_rdata_octets;
          staged.record_active = true;
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::add_host_dns_rdata:
    if (auto *endpoint = owner.host(command.host); endpoint)
      if (const auto *chunk = std::get_if<DnsRdataChunk>(&command.fib)) {
        auto &staged = endpoint->dns_authoritative_staging;
        const auto current = staged.current_record.rdata.size();
        if (!staged.active || !staged.record_active || chunk->size == 0U ||
            chunk->size > chunk->octets.size() ||
            current > staged.expected_rdata_octets ||
            chunk->size > staged.expected_rdata_octets - current)
          break;
        try {
          staged.current_record.rdata.insert(
              staged.current_record.rdata.end(), chunk->octets.begin(),
              chunk->octets.begin() + chunk->size);
          result.success = true;
        } catch (...) {
        }
      }
    break;
  case ForwardCommandKind::commit_host_dns_record:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_authoritative_staging;
      if (staged.active && staged.zone_active && staged.record_active &&
          staged.current_record.rdata.size() == staged.expected_rdata_octets) {
        try {
          auto *zone = staged.current_zone();
          if (!zone)
            break;
          zone->records.push_back(std::move(staged.current_record));
          staged.current_record = {};
          staged.expected_rdata_octets = 0U;
          staged.record_active = false;
          result.success = true;
        } catch (...) {
        }
      }
    }
    break;
  case ForwardCommandKind::commit_host_dns_zone:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_authoritative_staging;
      const auto *zone = staged.current_zone();
      const bool keys_complete = !staged.managed_signing ||
                                 (!staged.signed_zones.empty() &&
                                  staged.signed_zones.back().keys.size() ==
                                      staged.signed_zones.back().expected_keys);
      if (staged.active && staged.zone_active && !staged.record_active &&
          zone && zone->records.size() == staged.expected_current_records &&
          keys_complete) {
        staged.zone_active = false;
        staged.expected_current_records = 0U;
        result.success = true;
      }
    }
    break;
  case ForwardCommandKind::commit_host_dns_authoritative:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      auto &staged = endpoint->dns_authoritative_staging;
      const auto completed_zones = staged.managed_signing
                                       ? staged.signed_zones.size()
                                       : staged.zones.size();
      if (!endpoint->configured || !staged.active || staged.zone_active ||
          staged.record_active || completed_zones != staged.expected_zones)
        break;
      try {
        if (staged.managed_signing) {
          std::vector<dnssec::SignedZoneOwner> signed_zones;
          signed_zones.reserve(staged.signed_zones.size());
          for (auto &saved : staged.signed_zones) {
            dnssec::ZoneKeyStore key_store;
            bool keys_valid = saved.keys.size() == saved.expected_keys;
            for (const auto &definition : saved.keys) {
              auto provider = dnssec::generate_signing_key(
                  definition.algorithm, definition.generation);
              auto key = dnssec::ManagedKey::create(
                  definition.role, definition.schedule, std::move(provider));
              if (!key || key_store.add(std::move(*key)).first !=
                              dnssec::ZoneKeyMutation::applied) {
                keys_valid = false;
                break;
              }
            }
            if (!keys_valid)
              break;
            auto zone = dnssec::SignedZoneOwner::create(
                saved.source.origin, std::move(saved.source.records),
                std::move(key_store), saved.policy, staged.wall_now,
                command.operation_now);
            if (!zone)
              break;
            signed_zones.push_back(std::move(*zone));
          }
          if (signed_zones.size() == staged.expected_zones) {
            if (!endpoint->dns)
              endpoint->dns =
                  std::make_unique<network_detail::DnsEndpointService>();
            if (endpoint->dns->initialize_signing_vault(
                    owner.signing_wrapping_key, owner.signing_context_digest))
              result.success = endpoint->dns->configure_signed_authoritative(
                  std::move(signed_zones), endpoint->stack);
          }
        } else {
          std::vector<dns::Zone> zones;
          zones.reserve(staged.zones.size());
          for (auto &saved : staged.zones) {
            dns::Zone zone{saved.origin};
            if (!zone.replace(std::move(saved.records))) {
              zones.clear();
              break;
            }
            zones.push_back(std::move(zone));
          }
          if (zones.size() == staged.expected_zones) {
            if (!endpoint->dns)
              endpoint->dns =
                  std::make_unique<network_detail::DnsEndpointService>();
            result.success = endpoint->dns->configure_authoritative(
                std::move(zones), endpoint->stack);
          }
        }
      } catch (...) {
      }
      staged = {};
    }
    break;
  case ForwardCommandKind::abort_host_dns_authoritative:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      endpoint->dns_authoritative_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::remove_host_dns_authoritative:
    if (auto *endpoint = owner.host(command.host); endpoint) {
      if (endpoint->dns)
        endpoint->dns->remove_authoritative(endpoint->stack);
      endpoint->dns_authoritative_staging = {};
      result.success = true;
    }
    break;
  case ForwardCommandKind::start_host_dns_query:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->dns && endpoint->configured)
      if (const auto *query = std::get_if<DnsTransactionCommand>(&command.fib))
        if (const auto handle = endpoint->dns->resolve(query->question,
                                                       command.operation_now)) {
          result.success = true;
          result.value =
              (static_cast<std::uint64_t>(handle->generation) << 32U) |
              handle->index;
        }
    break;
  case ForwardCommandKind::release_host_dns_query:
    if (auto *endpoint = owner.host(command.host); endpoint && endpoint->dns)
      if (const auto *query = std::get_if<DnsTransactionCommand>(&command.fib))
        result.success = endpoint->dns->release(query->transaction);
    break;
  case ForwardCommandKind::set_host_link:
    if (auto *endpoint = owner.host(command.host)) {
      endpoint->link_signal = command.flag;
      endpoint->stack.set_link_state(command.flag);
      result.success = true;
    }
    break;
  case ForwardCommandKind::host_link_status:
    if (const auto *endpoint = owner.host(command.host)) {
      result.success = true;
      result.value = endpoint->link_signal;
    }
    break;
  case ForwardCommandKind::set_router_bof_link:
    if (command.port.ordinal == device_catalog::management_port_ordinal &&
        command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      auto &slot = owner.routers[command.device.index];
      slot.management_link_signal = command.flag;
      if (slot.management_stack)
        slot.management_stack->set_link_state(command.flag);
      result.success = true;
    }
    break;
  case ForwardCommandKind::router_bof_link_status:
    if (command.port.ordinal == device_catalog::management_port_ordinal &&
        command.device.index < owner.routers.size() &&
        owner.router(command.device)) {
      result.success = true;
      result.value =
          owner.routers[command.device.index].management_link_signal;
    }
    break;
  case ForwardCommandKind::router_ping:
    if (auto *forwarder = owner.router(command.device)) {
      auto &worker = *owner.forwarding_shards[shard_index];
      EgressContext egress_context{&owner, node(command.device), &worker};
      result.success = forwarder->originate_echo(
          command.destination, command.sequence, &egress_context, egress,
          Clock::now(), command.payload_octets, command.flag);
    }
    break;
  case ForwardCommandKind::router_ipv6_ping:
    if (auto *forwarder = owner.router(command.device)) {
      auto &worker = *owner.forwarding_shards[shard_index];
      EgressContext egress_context{&owner, node(command.device), &worker};
      result.success = forwarder->originate_ipv6_echo(
          command.ipv6_destination, command.sequence, &egress_context, egress,
          Clock::now(), command.payload_octets);
    }
    break;
  case ForwardCommandKind::host_ping:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured && endpoint->link_signal) {
      endpoint->expected_sequence = command.sequence;
      endpoint->ping_pending = true;
      endpoint->ping_reply = false;
      endpoint->ping_clock_started = false;
      endpoint->ping_reply_rtt = std::chrono::nanoseconds::zero();
      endpoint->ping_reply_ttl = 0U;
      const auto started_at = Clock::now();
      const auto frames = endpoint->stack.begin_echo(
          command.host_destination, command.sequence,
          device_catalog::default_ping_payload_octets, false, started_at);
      bool accepted = frames.count > 0;
      auto &worker = *owner.forwarding_shards[shard_index];
      for (std::size_t index = 0; index < frames.count; ++index)
        accepted = owner.queue_egress(&worker, node(command.host), 0,
                                      frames.frames[index]) &&
                   accepted;
      if (!accepted)
        endpoint->ping_pending = false;
      else if (frames.start_echo_clock) {
        endpoint->ping_clock_started = true;
        endpoint->ping_sent_at = started_at;
      }
      result.success = accepted;
    }
    break;
  case ForwardCommandKind::router_ping_status:
    if (const auto *forwarder = owner.router(command.device)) {
      result.success = true;
      result.value = forwarder->echo_outcome(command.sequence);
    }
    break;
  case ForwardCommandKind::router_ipv6_ping_status:
    if (const auto *forwarder = owner.router(command.device)) {
      result.success = true;
      result.value = forwarder->ipv6_echo_outcome(command.sequence);
    }
    break;
  case ForwardCommandKind::host_ping_status:
    if (const auto *endpoint = owner.host(command.host)) {
      result.success = true;
      if (endpoint->ping_reply &&
          endpoint->expected_sequence == command.sequence) {
        constexpr auto maximum_elapsed = (std::uint64_t{1} << 48U) - 1U;
        const auto elapsed = static_cast<std::uint64_t>(
            std::max<std::int64_t>(0, endpoint->ping_reply_rtt.count()));
        result.value =
            1U | static_cast<std::uint64_t>(endpoint->ping_reply_ttl) << 8U |
            std::min(elapsed, maximum_elapsed) << 16U;
      }
    }
    break;
  case ForwardCommandKind::pause:
  case ForwardCommandKind::shutdown:
    // Worker lifecycle commands are consumed by ForwardingShardWorker itself.
    result.success = true;
    break;
  }
  return result;
}

void NetworkPlane::Impl::apply_forward_ingress(
    void *context, std::size_t shard_index,
    const ForwardIngress &ingress) noexcept {
  auto &owner = *static_cast<Impl *>(context);
  if (!ingress.destination ||
      ingress.destination.node.index % owner.separate_forwarding_shards !=
          shard_index)
    return;
  auto &worker = *owner.forwarding_shards[shard_index];
  if (ingress.destination.node.kind == NodeKind::router) {
    const DeviceHandle handle{ingress.destination.node.index,
                              ingress.destination.node.generation};
    if (ingress.destination.ordinal ==
            device_catalog::management_port_ordinal &&
        handle.index < owner.routers.size()) {
      auto &slot = owner.routers[handle.index];
      if (!owner.router(handle) || !slot.management_configured)
        return;
      // The OOB endpoint consumes Ethernet locally. It is never passed to the
      // Base forwarding engine, which enforces ip-forwarding=false between
      // management and routed interfaces.
      const auto frames =
          slot.management_stack->receive(ingress.frame, 0U, false,
                                        Clock::now());
      for (std::size_t index = 0; index < frames.count; ++index)
        static_cast<void>(owner.queue_egress(
            &worker, node(handle), device_catalog::management_port_ordinal,
            frames.frames[index]));
      return;
    }
    auto *forwarder = owner.router(handle);
    if (!forwarder)
      return;
    EgressContext egress_context{&owner, ingress.destination.node, &worker};
    forwarder->receive(ingress.destination.ordinal, ingress.frame,
                       &egress_context, egress, Clock::now(), &egress_context,
                       punt, router_fragment_admission);
    return;
  }

  const HostHandle handle{ingress.destination.node.index,
                          ingress.destination.node.generation};
  auto *endpoint = owner.host(handle);
  if (!endpoint || !endpoint->configured)
    return;
  const auto received_at = Clock::now();
  const auto frames =
      endpoint->stack.receive(ingress.frame, endpoint->expected_sequence,
                              endpoint->ping_pending, received_at);
  // Queue-based forwarding is not reentrant, but publishing the clock before
  // egress also keeps both execution layouts under one ordering invariant.
  if (frames.start_echo_clock) {
    endpoint->ping_clock_started = true;
    endpoint->ping_sent_at = received_at;
  }
  for (std::size_t index = 0; index < frames.count; ++index)
    static_cast<void>(
        owner.queue_egress(&worker, node(handle), 0, frames.frames[index]));
  if (frames.echo_reply) {
    endpoint->ping_reply = true;
    endpoint->ping_pending = false;
    endpoint->ping_reply_ttl = frames.echo_reply_ttl;
    endpoint->ping_reply_rtt =
        endpoint->ping_clock_started && received_at >= endpoint->ping_sent_at
            ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                  received_at - endpoint->ping_sent_at)
            : std::chrono::nanoseconds::zero();
    endpoint->ping_clock_started = false;
  }
}

std::optional<NetworkPlane::Clock::time_point>
NetworkPlane::Impl::service_forwarding(void *context, std::size_t shard_index,
                                       Clock::time_point now) noexcept {
  auto &owner = *static_cast<Impl *>(context);
  std::optional<Clock::time_point> next;
  auto &worker = *owner.forwarding_shards[shard_index];
  owner.drain_ospf_egress(shard_index, &worker, now);
  for (std::size_t index = shard_index; index < owner.routers.size();
       index += owner.separate_forwarding_shards) {
    auto &slot = owner.routers[index];
    if (!slot.forwarder || !slot.generation)
      continue;
    const DeviceHandle handle{static_cast<std::uint16_t>(index),
                              slot.generation};
    EgressContext egress_context{&owner, node(handle), &worker};
    // IPv4 ARP aging and retries belong to the forwarding owner. Supplying the
    // ordinary egress callback guarantees every retry crosses the same bounded
    // inter-shard and physical-link queues as its initiating request.
    slot.forwarder->service_ipv4_maintenance(&egress_context, egress, now);
    slot.forwarder->service_ipv6_maintenance(&egress_context, egress, now);
    if (slot.management_configured) {
      const auto frames = slot.management_stack->service_maintenance(now);
      for (std::size_t frame = 0; frame < frames.count; ++frame)
        static_cast<void>(owner.queue_egress(
            &worker, node(handle), device_catalog::management_port_ordinal,
            frames.frames[frame]));
      if (slot.bof_dhcpv4) {
        const auto deadline = slot.bof_dhcpv4->service(
            *slot.management_stack, &egress_context,
            management_fragment_egress, management_fragment_admission, now);
        if (deadline && (!next || *deadline < *next))
          next = deadline;
        if (slot.bof_dhcpv4->client_bootstrap_complete()) {
          slot.bof_dhcpv4_timeout = Clock::time_point::max();
        } else if (now >= slot.bof_dhcpv4_timeout) {
          slot.bof_dhcpv4->remove_client(*slot.management_stack);
          slot.bof_dhcpv4_timeout = Clock::time_point::max();
        } else if (slot.bof_dhcpv4_timeout != Clock::time_point::max() &&
                   (!next || slot.bof_dhcpv4_timeout < *next)) {
          next = slot.bof_dhcpv4_timeout;
        }
      }
      if (slot.bof_dhcpv6) {
        const auto deadline = slot.bof_dhcpv6->service(
            *slot.management_stack, &egress_context,
            management_fragment_egress, management_fragment_admission, now);
        if (deadline && (!next || *deadline < *next))
          next = deadline;
        if (slot.bof_dhcpv6->client_bootstrap_complete()) {
          slot.bof_dhcpv6_timeout = Clock::time_point::max();
        } else if (now >= slot.bof_dhcpv6_timeout) {
          slot.bof_dhcpv6->remove_client(*slot.management_stack);
          slot.bof_dhcpv6_timeout = Clock::time_point::max();
        } else if (slot.bof_dhcpv6_timeout != Clock::time_point::max() &&
                   (!next || slot.bof_dhcpv6_timeout < *next)) {
          next = slot.bof_dhcpv6_timeout;
        }
      }
      const auto deadline =
          slot.management_stack->next_maintenance_deadline();
      if (deadline && (!next || *deadline < *next))
        next = deadline;
    }
    for (const auto deadline : {slot.forwarder->next_ipv4_deadline(),
                                slot.forwarder->next_ipv6_deadline()})
      if (deadline && (!next || *deadline < *next))
        next = deadline;
  }
  for (std::size_t index = shard_index; index < owner.hosts.size();
       index += owner.separate_forwarding_shards) {
    auto &slot = owner.hosts[index];
    if (!slot.generation || !slot.configured)
      continue;
    const HostHandle handle{static_cast<std::uint16_t>(index), slot.generation};
    const auto frames = slot.stack.service_maintenance(now);
    for (std::size_t frame = 0; frame < frames.count; ++frame)
      static_cast<void>(
          owner.queue_egress(&worker, node(handle), 0U, frames.frames[frame]));
    EgressContext egress_context{&owner, node(handle), &worker};
    if (slot.dhcpv4) {
      const auto service_deadline = slot.dhcpv4->service(
          slot.stack, &egress_context, host_fragment_egress,
          host_fragment_admission, now);
      if (service_deadline && (!next || *service_deadline < *next))
        next = service_deadline;
    }
    if (slot.dhcpv6) {
      const auto service_deadline = slot.dhcpv6->service(
          slot.stack, &egress_context, host_fragment_egress,
          host_fragment_admission, now);
      if (service_deadline && (!next || *service_deadline < *next))
        next = service_deadline;
    }
    if (slot.dns) {
      const auto service_deadline =
          slot.dns->service(slot.stack, &egress_context, host_fragment_egress,
                            host_fragment_admission, host_fragment_egress,
                            host_fragment_admission, now);
      if (service_deadline && (!next || *service_deadline < *next))
        next = service_deadline;
    }
    const auto deadline = slot.stack.next_maintenance_deadline();
    if (deadline && (!next || *deadline < *next))
      next = deadline;
  }
  return next;
}

void NetworkPlane::Impl::drain_ospf_egress(
    std::size_t shard_index, ForwardingShardWorker *worker,
    Clock::time_point current) noexcept {
  if (!ospf_worker ||
      shard_index >= std::max<std::size_t>(
                         1U, separate_forwarding_shards))
    return;
  std::size_t budget = device_catalog::ospf_work_budget_packets;
  while (budget--) {
    const auto packet = ospf_channels.egress[shard_index].try_receive();
    if (!packet)
      break;
    auto *forwarder = router(packet->metadata.device);
    if (forwarder) {
      EgressContext context{this, node(packet->metadata.device), worker};
      static_cast<void>(forwarder->originate_ospf(
          packet->metadata.physical_port_ordinal, *packet->frame, &context,
          egress, current));
    }
    static_cast<void>(
        ospf_channels.egress[shard_index].release(packet->handle));
    // Returning a slot can unblock the sole OSPF producer. Wake after release
    // so its acquire observes the reclaimed handle.
    ospf_worker->notify();
  }
}

ForwardResult
NetworkPlane::Impl::execute_forward(const ForwardCommand &source) noexcept {
  ForwardCommand command = source;
  command.id = next_forward_command_id++;
  const NodeHandle target =
      command.device ? node(command.device) : node(command.host);
  if (!target.generation)
    return {.id = command.id};
  auto &worker = shard(target);
  if (!worker.submit(command))
    return {.id = command.id};
  ForwardResult result;
  while (!worker.result(result)) {
    // Egress can be produced by the submitted operation itself. Draining it
    // while awaiting the command result prevents a full transfer ring from
    // turning synchronous control into a deadlock.
    drain_forwarding_egress();
    std::this_thread::yield();
  }
  return result.id == command.id ? result : ForwardResult{.id = command.id};
}

ospf::ControlResult
NetworkPlane::Impl::execute_ospf(ospf::ControlCommand command) noexcept {
  // Construction guarantees the owner. Retain the guard so teardown or a
  // future explicitly failed startup cannot turn a control request into a
  // null dereference, but never create a pthread on this command path.
  if (!ospf_worker) {
    if (command.kind == ospf::ControlCommandKind::stage_authentication)
      spsc_secure_clear(command);
    return {.id = command.id};
  }
  command.id = next_ospf_command_id++;
  const auto id = command.id;
  const auto sensitive =
      command.kind == ospf::ControlCommandKind::stage_authentication;
  if (!ospf_worker->submit(command)) {
    if (sensitive)
      spsc_secure_clear(command);
    return {.id = id};
  }
  if (sensitive)
    spsc_secure_clear(command);
  ospf::ControlResult result;
  while (!ospf_worker->read(result))
    std::this_thread::yield();
  return result.id == id ? result : ospf::ControlResult{.id = id};
}

bool NetworkPlane::Impl::install_ipv4_fib(
    DeviceHandle device, const routing::FibProgram &fib) noexcept {
  if (parallel())
    return execute_forward({.kind = ForwardCommandKind::program_fib,
                            .device = device,
                            .fib = fib})
        .success;
  auto *forwarder = router(device);
  return forwarder && forwarder->program_fib(fib);
}

bool NetworkPlane::Impl::install_ipv6_fib(
    DeviceHandle device, const routing::Ipv6FibProgram &fib) noexcept {
  if (parallel())
    return execute_forward({.kind = ForwardCommandKind::program_ipv6_fib,
                            .device = device,
                            .fib = fib})
        .success;
  auto *forwarder = router(device);
  return forwarder && forwarder->program_ipv6_fib(fib);
}

bool NetworkPlane::Impl::reconcile_external_routes(
    DeviceHandle device, RouteManagerState &state) noexcept {
  std::vector<OspfExternalRouteProgram> active;
  try {
    active.reserve(state.configured_external_routes.size());
    for (const auto &external : state.configured_external_routes) {
      const auto &source = external.source;
      const bool installed =
          source.destination.ipv6
              ? std::any_of(
                    state.ipv6_rib.routes().begin(),
                    state.ipv6_rib.routes().end(),
                    [&](const auto &route) {
                      return route.network ==
                                 source.destination.ipv6_network &&
                             route.prefix_length ==
                                 source.destination.length &&
                             route.source == source.source;
                    })
              : std::any_of(
                    state.ipv4_rib.routes().begin(),
                    state.ipv4_rib.routes().end(),
                    [&](const auto &route) {
                      return route.network ==
                                 source.destination.ipv4_network &&
                             route.prefix_length ==
                                 source.destination.length &&
                             route.source == source.source;
                    });
      if (installed)
        active.push_back(external);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  const auto same = [](const OspfExternalRouteProgram &left,
                       const OspfExternalRouteProgram &right) {
    return left.process.device == right.process.device &&
           left.process.area_id == right.process.area_id &&
           left.process.version == right.process.version &&
           left.process.instance_id == right.process.instance_id &&
           left.source == right.source &&
           left.advertisement == right.advertisement;
  };
  if (active.size() == state.active_external_routes.size() &&
      std::equal(active.begin(), active.end(),
                 state.active_external_routes.begin(), same))
    return true;

  // RIB activity is a separate input generation from OSPF configuration.
  // Replacing only external advertisements preserves every live adjacency and
  // lets InstanceProcess perform normal sequence, MaxAge and flooding rules
  // for additions, changes and withdrawals.
  const ospf::ProcessIdentity identity{.device = device};
  auto result = execute_ospf(
      {.process = identity,
       .expected_external_routes =
           static_cast<std::uint32_t>(active.size()),
       .kind = ospf::ControlCommandKind::begin_external_generation});
  const auto abort = [&] {
    static_cast<void>(execute_ospf(
        {.process = identity,
         .kind = ospf::ControlCommandKind::abort_external_generation}));
  };
  if (!result.success)
    return false;
  for (const auto &external : active) {
    result = execute_ospf(
        {.external_route = external.advertisement,
         .process =
             {.device = device,
              .area_id = external.process.area_id,
              .version = external.process.version,
              .instance_id = external.process.instance_id},
         .kind = ospf::ControlCommandKind::stage_external_route});
    if (!result.success) {
      abort();
      return false;
    }
  }
  result = execute_ospf(
      {.process = identity,
       .kind = ospf::ControlCommandKind::commit_external_generation});
  if (!result.success) {
    abort();
    return false;
  }
  state.active_external_routes.swap(active);
  return true;
}

bool NetworkPlane::Impl::rebuild_managed_routes(
    DeviceHandle device, RouteManagerState &state,
    std::span<const routing::DynamicInput> ipv4_dynamic,
    std::span<const routing::Ipv6DynamicInput> ipv6_dynamic) noexcept {
  if (!live(device) || !state.policy_configured)
    return false;

  if (state.base_ipv4_configured) {
    std::vector<routing::ConnectedInput> connected;
    try {
      connected.reserve(state.base_ipv4.count);
      for (std::size_t index{}; index < state.base_ipv4.count; ++index) {
        const auto &route = state.base_ipv4.routes[index];
        if (route.source != routing::RouteSource::connected)
          continue;
        // The base FIB was compiled by the control-owned configuration model.
        // Converting only connected selections preserves the interface and
        // hardware oper state while unresolved static intent comes separately
        // from RoutePolicyProgram.
        connected.push_back({.configured = true,
                             .operational = true,
                             .network = route.network,
                             .port_ordinal = route.port_ordinal,
                             .prefix_length = route.prefix_length,
                             .local_system = route.local_system});
      }
    } catch (const std::bad_alloc &) {
      return false;
    }

    const bool changed = state.ipv4_rib.rebuild(
        connected, state.policy.ipv4_statics, ipv4_dynamic,
        state.policy.maximum_ecmp_paths);
    if (!state.ipv4_rib.last_rebuild_valid())
      return false;
    if (changed || state.installed_ipv4_generation == 0U) {
      if (++state.installed_ipv4_generation == 0U)
        ++state.installed_ipv4_generation;
      if (!install_ipv4_fib(
              device,
              state.ipv4_rib.compile(state.installed_ipv4_generation)))
        return false;
    }
  }

  if (state.base_ipv6_configured) {
    std::vector<routing::Ipv6ConnectedInput> connected;
    try {
      connected.reserve(state.base_ipv6.count);
      for (std::size_t index{}; index < state.base_ipv6.count; ++index) {
        const auto &route = state.base_ipv6.routes[index];
        if (route.source != routing::RouteSource::connected)
          continue;
        connected.push_back(
            {.configured = true,
             .operational = true,
             .network = route.network,
             .interface_id = route.interface_id,
             .physical_port_ordinal = route.physical_port_ordinal,
             .prefix_length = route.prefix_length});
      }
    } catch (const std::bad_alloc &) {
      return false;
    }

    const bool changed = state.ipv6_rib.rebuild(
        connected, state.policy.ipv6_statics, {}, ipv6_dynamic,
        state.policy.maximum_ecmp_paths);
    if (!state.ipv6_rib.last_rebuild_valid())
      return false;
    if (changed || state.installed_ipv6_generation == 0U) {
      if (++state.installed_ipv6_generation == 0U)
        ++state.installed_ipv6_generation;
      if (!install_ipv6_fib(
              device,
              state.ipv6_rib.compile(state.installed_ipv6_generation)))
        return false;
    }
  }
  return reconcile_external_routes(device, state);
}

void NetworkPlane::Impl::drain_ospf_routes() noexcept {
  while (const auto borrowed = ospf_channels.routes->try_receive()) {
    const auto &published = *borrowed->generation;
    if (live(published.device) &&
        published.device.index < route_managers.size()) {
      auto &manager = route_managers[published.device.index];
      if (!manager) {
        try {
          manager = std::make_unique<RouteManagerState>();
        } catch (const std::bad_alloc &) {
        }
      }
      if (manager && published.generation > manager->ospf_generation &&
          published.ipv4_count <= published.ipv4.size() &&
          published.ipv6_count <= published.ipv6.size()) {
        const auto ipv4 = std::span<const routing::DynamicInput>{
            published.ipv4}.first(published.ipv4_count);
        const auto ipv6 = std::span<const routing::Ipv6DynamicInput>{
            published.ipv6}.first(published.ipv6_count);

        // The borrowed route slot remains immutable until release below. Build
        // and program from those bytes first, then retain the accepted values
        // in capacity-reserved active vectors without a second large staging
        // allocation per router.
        if (manager->policy_configured &&
            !rebuild_managed_routes(published.device, *manager, ipv4, ipv6)) {
          static_cast<void>(
              rebuild_managed_routes(published.device, *manager,
                                     manager->ospf_ipv4,
                                     manager->ospf_ipv6));
        } else {
          manager->ospf_ipv4.assign(ipv4.begin(), ipv4.end());
          manager->ospf_ipv6.assign(ipv6.begin(), ipv6.end());
          manager->ospf_generation = published.generation;
        }
      }
    }
    static_cast<void>(ospf_channels.routes->release(borrowed->handle));
  }
}

bool NetworkPlane::Impl::queue_egress(ForwardingShardWorker *source_shard,
                                      NodeHandle source, std::uint16_t ordinal,
                                      const packet::Frame &frame) noexcept {
  ForwardEgress transfer;
  transfer.kind = ForwardEgressKind::transmit;
  transfer.source = source;
  transfer.ordinal = ordinal;
  packet::copy_frame(transfer.frame, frame);
  const bool accepted = source_shard && source_shard->emit(transfer);
  if (!accepted)
    egress_ring_dropped.fetch_add(1U, std::memory_order_relaxed);
  return accepted;
}

void NetworkPlane::Impl::drain_forwarding_egress() noexcept {
  for (std::size_t shard_index = 0; shard_index < separate_forwarding_shards;
       ++shard_index) {
    auto &worker = *forwarding_shards[shard_index];
    std::size_t budget = device_catalog::fabric_work_budget_frames;
    ForwardEgress egress_frame;
    while (budget-- && worker.take_egress(egress_frame)) {
      if (egress_frame.kind == ForwardEgressKind::cpm_punt) {
        if (egress_frame.source.kind == NodeKind::router &&
            egress_frame.source.index < cpm_captures.size())
          observe(cpm_captures[egress_frame.source.index], egress_frame.source,
                  egress_frame.frame);
        continue;
      }
      const auto *current = binding(egress_frame.source, egress_frame.ordinal);
      if (!current || current->port.node != egress_frame.source ||
          !current->link) {
        ++missing_binding_dropped;
        continue;
      }
      if (egress_frame.source.kind == NodeKind::router &&
          egress_frame.source.index < egress_captures.size() &&
          egress_frame.ordinal <
              egress_captures[egress_frame.source.index].size())
        observe(
            egress_captures[egress_frame.source.index][egress_frame.ordinal],
            egress_frame.source, egress_frame.frame);
      if (fabric->enqueue(current->link, current->endpoint,
                          egress_frame.frame) !=
          MultiDeviceFabric::DropReason::none)
        continue;
      observe(link_captures[current->link.index][current->endpoint],
              current->link, egress_frame.frame);
    }
  }
}

bool NetworkPlane::Impl::pause_forwarding() noexcept {
  if (!parallel())
    return true;
  std::array<std::uint64_t, device_catalog::high_forwarding_shards> ids{};
  for (std::size_t index = 0; index < separate_forwarding_shards; ++index) {
    ids[index] = next_forward_command_id++;
    while (!forwarding_shards[index]->submit(
        {.id = ids[index], .kind = ForwardCommandKind::pause}))
      std::this_thread::yield();
  }
  for (std::size_t index = 0; index < separate_forwarding_shards; ++index) {
    ForwardResult result;
    while (!forwarding_shards[index]->result(result)) {
      drain_forwarding_egress();
      std::this_thread::yield();
    }
    if (result.id != ids[index] || !result.success)
      return false;
  }
  drain_forwarding_egress();
  return true;
}

void NetworkPlane::Impl::resume_forwarding() noexcept {
  for (std::size_t index = 0; index < separate_forwarding_shards; ++index)
    forwarding_shards[index]->resume();
}

NetworkPlane::NetworkPlane(std::size_t logical_cpus)
    : impl_(std::make_unique<Impl>(logical_cpus)) {
  // Impl is intentionally private, so this member is the only scope that can
  // prove concrete metadata and maximum forwarding transfer rings fit their
  // 24 MiB share of runtime_control_reserve_bytes. The remaining 8 MiB covers
  // registries, workflow vectors and standard-library allocation headers.
  static_assert(sizeof(Impl) + device_catalog::high_forwarding_shards *
                                   sizeof(ForwardingShardWorker) <=
                    24U * 1024U * 1024U,
                "network shard metadata exceeds its fixed Wasm reserve");
}
NetworkPlane::~NetworkPlane() = default;

bool NetworkPlane::add_router(
    DeviceHandle device,
    const crypto::Sha256Digest &transport_secret,
    bool transit_forwarding_enabled) noexcept {
  if (!device || device.index >= impl_->routers.size())
    return false;
  if (std::ranges::all_of(transport_secret,
                          [](std::uint8_t octet) { return octet == 0U; }))
    return false;
  std::unique_ptr<Impl::RouteManagerState> route_manager;
  try {
    route_manager = std::make_unique<Impl::RouteManagerState>();
  } catch (const std::bad_alloc &) {
    // Route capacity is part of router admission. Starting a device that could
    // later acknowledge but not retain a complete OSPF generation would
    // violate withdrawal and best-path correctness.
    return false;
  }
  if (impl_->parallel()) {
    if (impl_->router_generations[device.index] ||
        impl_->route_managers[device.index])
      return false;
    const bool added =
        impl_
            ->execute_forward({.kind = ForwardCommandKind::add_router,
                               .device = device,
                               .router_transport_secret = transport_secret,
                               .transit_forwarding_enabled =
                                   transit_forwarding_enabled})
            .success;
    if (added) {
      impl_->router_generations[device.index] = device.generation;
      impl_->route_managers[device.index] = std::move(route_manager);
    }
    return added;
  }
  auto &slot = impl_->routers[device.index];
  if (slot.forwarder || impl_->route_managers[device.index])
    return false;
  // Allocate the device arena once on lifecycle admission, never on packet
  // receipt. Generation is published only after allocation succeeded.
  try {
    slot.forwarder =
        std::make_unique<RouterForwarder>(transport_secret);
    slot.forwarder->set_transit_forwarding(transit_forwarding_enabled);
  } catch (const std::bad_alloc &) {
    return false;
  }
  slot.generation = device.generation;
  impl_->router_generations[device.index] = device.generation;
  impl_->route_managers[device.index] = std::move(route_manager);
  return true;
}

bool NetworkPlane::remove_router(DeviceHandle device) noexcept {
  if (!impl_->live(device))
    return false;
  // Withdraw the protocol generation while physical ports still exist. This
  // lets the transaction clear every derived punt bit and prevents a reused
  // router slot from inheriting an old daemon generation.
  if (impl_->ospf_worker &&
      !replace_ospf_generation(device, {}, {}, {}, {}, {}, {}))
    return false;
  for (std::size_t index = 0; index < impl_->links.size(); ++index) {
    if (!impl_->links[index])
      continue;
    if (impl_->endpoints[index][0].node == node(device) ||
        impl_->endpoints[index][1].node == node(device))
      static_cast<void>(remove_link(*impl_->links[index]));
  }
  for (auto *table : {&impl_->ingress_captures, &impl_->egress_captures})
    for (auto &binding : (*table)[device.index])
      if (binding.active && binding.node == node(device))
        impl_->deactivate_capture(binding);
  if (impl_->cpm_captures[device.index].active &&
      impl_->cpm_captures[device.index].node == node(device))
    impl_->deactivate_capture(impl_->cpm_captures[device.index]);
  if (impl_->parallel()) {
    const bool removed =
        impl_
            ->execute_forward(
                {.kind = ForwardCommandKind::remove_router, .device = device})
            .success;
    if (removed) {
      impl_->router_generations[device.index] = 0;
      impl_->route_managers[device.index].reset();
    }
    return removed;
  }
  impl_->routers[device.index] = {};
  impl_->router_generations[device.index] = 0;
  impl_->route_managers[device.index].reset();
  return true;
}

bool NetworkPlane::add_host(HostHandle host) noexcept {
  if (!host || host.index >= impl_->hosts.size() ||
      impl_->host_generations[host.index])
    return false;
  if (impl_->parallel()) {
    const bool added =
        impl_
            ->execute_forward(
                {.kind = ForwardCommandKind::add_host, .host = host})
            .success;
    if (added)
      impl_->host_generations[host.index] = host.generation;
    return added;
  }
  impl_->hosts[host.index].generation = host.generation;
  impl_->host_generations[host.index] = host.generation;
  return true;
}

bool NetworkPlane::remove_host(HostHandle host) noexcept {
  if (!impl_->live(host))
    return false;
  for (std::size_t index = 0; index < impl_->links.size(); ++index) {
    if (impl_->links[index] && (impl_->endpoints[index][0].node == node(host) ||
                                impl_->endpoints[index][1].node == node(host)))
      static_cast<void>(remove_link(*impl_->links[index]));
  }
  if (impl_->parallel()) {
    const bool removed =
        impl_
            ->execute_forward(
                {.kind = ForwardCommandKind::remove_host, .host = host})
            .success;
    if (removed)
      impl_->host_generations[host.index] = 0;
    return removed;
  }
  impl_->hosts[host.index] = {};
  impl_->host_generations[host.index] = 0;
  return true;
}

bool NetworkPlane::add_switch(SwitchHandle handle,
                              std::uint16_t profile_index) noexcept {
  if (!handle || handle.index >= impl_->switches.size() ||
      impl_->switch_generations[handle.index])
    return false;
  const auto *profile =
      device_catalog::ethernet_switch_profile(profile_index);
  if (!profile ||
      profile->port_count > device_catalog::maximum_switch_ports)
    return false;
  try {
    auto forwarding =
        std::make_unique<EthernetSwitch>(*profile,
                                         impl_->fabric->packet_pool());
    // Every initial port property comes from the selected generated hardware
    // profile. Cable creation is not allowed to synthesize speed, MTU or
    // administrative state.
    for (std::uint16_t port{}; port < profile->port_count; ++port) {
      if (!forwarding->configure_port(
              port,
              {.speed_mbps = profile->default_speed_mbps,
               .mtu = profile->default_mtu,
               .admin_enabled = profile->default_admin_enabled,
               .carrier = false}))
        return false;
    }
    auto &slot = impl_->switches[handle.index];
    slot.generation = handle.generation;
    slot.profile_index = profile_index;
    slot.profile = profile;
    slot.forwarding = std::move(forwarding);
    impl_->switch_generations[handle.index] = handle.generation;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool NetworkPlane::remove_switch(SwitchHandle handle) noexcept {
  if (!impl_->live(handle))
    return false;
  for (std::size_t index{}; index < impl_->links.size(); ++index) {
    if (impl_->links[index] &&
        (impl_->endpoints[index][0].node == node(handle) ||
         impl_->endpoints[index][1].node == node(handle)))
      static_cast<void>(remove_link(*impl_->links[index]));
  }
  impl_->switches[handle.index] = {};
  impl_->switch_generations[handle.index] = 0U;
  return true;
}

bool NetworkPlane::configure_switch_port(
    SwitchHandle handle, std::uint16_t port,
    const SwitchPortConfiguration &configuration) noexcept {
  auto *slot = impl_->ethernet_switch(handle);
  if (!slot || port >= slot->profile->port_count)
    return false;
  // Operational carrier is owned by the physical link. A control edit may
  // change admin, MTU or rate but cannot claim or withdraw physical signal.
  const auto current = slot->forwarding->port_configuration(port);
  if (!current)
    return false;
  auto value = configuration;
  value.carrier = current->carrier;
  return slot->forwarding->configure_port(port, value);
}

bool NetworkPlane::configure_port(DeviceHandle device,
                                  const ForwardPort &port) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::configure_port,
                           .device = device,
                           .port = port})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->configure_port(port);
}

bool NetworkPlane::remove_port(DeviceHandle device,
                               std::uint16_t ordinal) noexcept {
  if (impl_->parallel()) {
    ForwardPort port;
    port.ordinal = ordinal;
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::remove_port,
                           .device = device,
                           .port = port})
        .success;
  }
  auto *forwarder = impl_->router(device);
  if (!forwarder || ordinal >= device_catalog::maximum_ports_per_router)
    return false;
  // RouterForwarder owns adjacencies and pending frames associated with this
  // interface. Delegating removal to that owner ensures a deleted interface
  // cannot leave a usable next-hop entry behind.
  forwarder->remove_port(ordinal);
  return true;
}

bool NetworkPlane::add_ospf_process(
    const OspfProcessProgram &program) noexcept {
  if (!impl_->live(program.device))
    return false;
  return impl_->execute_ospf(
      {.process =
           {.device = program.device,
            .area_id = program.area_id,
            .version = program.version,
            .instance_id = program.instance_id},
       .router_id = program.router_id,
       .initial_dd_sequence = program.initial_dd_sequence,
       .maximum_interfaces = program.maximum_interfaces,
       .default_metric = program.default_metric,
       .router_preference = program.router_preference,
       .external_preference = program.external_preference,
       .spf_initial_wait_milliseconds =
           program.spf_initial_wait_milliseconds,
       .spf_second_wait_milliseconds =
           program.spf_second_wait_milliseconds,
       .spf_maximum_wait_milliseconds =
           program.spf_maximum_wait_milliseconds,
       .lsa_initial_wait_milliseconds =
           program.lsa_initial_wait_milliseconds,
       .lsa_second_wait_milliseconds =
           program.lsa_second_wait_milliseconds,
       .lsa_maximum_wait_milliseconds =
           program.lsa_maximum_wait_milliseconds,
       .area_type = program.area_type,
       .kind = ospf::ControlCommandKind::add_process,
       .summaries = program.summaries,
       .nssa_translate_always = program.nssa_translate_always,
       .asbr = program.asbr,
       .graceful_restart_helper = program.graceful_restart_helper,
       .loopfree_alternates = program.loopfree_alternates,
       .overload = program.overload})
      .success;
}

bool NetworkPlane::remove_ospf_process(
    const OspfProcessProgram &program) noexcept {
  return impl_->execute_ospf(
      {.process =
           {.device = program.device,
            .area_id = program.area_id,
            .version = program.version,
            .instance_id = program.instance_id},
       .kind = ospf::ControlCommandKind::remove_process})
      .success;
}

bool NetworkPlane::add_ospf_interface(
    const OspfInterfaceProgram &program) noexcept {
  if (!impl_->live(program.process.device))
    return false;
  const ForwardCommand punt{
      .kind = ForwardCommandKind::configure_ospf_punt,
      .device = program.process.device,
      .port = ForwardPort{
          .ordinal = program.interface.physical_port_ordinal},
      .ospf_version_two =
          program.process.version == packet::ospf::version_two,
      .ospf_version_three =
          program.process.version == packet::ospf::version_three};
  if (impl_->parallel() && !impl_->execute_forward(punt).success)
    return false;
  if (!impl_->parallel()) {
    auto *forwarder = impl_->router(program.process.device);
    if (!forwarder ||
        !forwarder->configure_ospf_punt(
            program.interface.physical_port_ordinal,
            program.process.version == packet::ospf::version_two,
            program.process.version == packet::ospf::version_three))
      return false;
  }
  const auto result = impl_->execute_ospf(
      {.interface = program.interface,
       .process =
           {.device = program.process.device,
            .area_id = program.process.area_id,
            .version = program.process.version,
            .instance_id = program.process.instance_id},
       .kind = ospf::ControlCommandKind::add_interface});
  return result.success;
}

bool NetworkPlane::remove_ospf_interface(
    const OspfInterfaceProgram &program) noexcept {
  const auto result = impl_->execute_ospf(
      {.process =
           {.device = program.process.device,
            .area_id = program.process.area_id,
            .version = program.process.version,
            .instance_id = program.process.instance_id},
       .interface_id = program.interface.protocol.interface_id,
       .kind = ospf::ControlCommandKind::remove_interface});
  return result.success;
}

bool NetworkPlane::replace_ospf_generation(
    DeviceHandle device, std::span<const OspfProcessProgram> processes,
    std::span<const OspfInterfaceProgram> interfaces,
    std::span<const OspfAuthenticationProgram> authentications,
    std::span<const OspfNbmaNeighborProgram> nbma_neighbors,
    std::span<const OspfVirtualLinkProgram> virtual_links,
    std::span<const OspfAreaRangeProgram> ranges,
    std::span<const OspfExternalRouteProgram> external_routes) noexcept {
  if (!impl_->live(device) ||
      processes.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max() ||
      authentications.size() > std::numeric_limits<std::uint32_t>::max() ||
      nbma_neighbors.size() > std::numeric_limits<std::uint32_t>::max() ||
      virtual_links.size() > std::numeric_limits<std::uint32_t>::max() ||
      ranges.size() > std::numeric_limits<std::uint32_t>::max() ||
      external_routes.size() >
          device_catalog::maximum_dynamic_routes_per_router)
    return false;

  std::vector<OspfExternalRouteProgram> configured_external_routes;
  std::vector<OspfExternalRouteProgram> active_external_routes;
  try {
    configured_external_routes.assign(external_routes.begin(),
                                      external_routes.end());
    active_external_routes.reserve(external_routes.size());
    const auto *manager =
        device.index < impl_->route_managers.size()
            ? impl_->route_managers[device.index].get()
            : nullptr;
    for (const auto &external : external_routes) {
      if (!manager)
        continue;
      const auto &source = external.source;
      const bool installed =
          source.destination.ipv6
              ? std::any_of(
                    manager->ipv6_rib.routes().begin(),
                    manager->ipv6_rib.routes().end(),
                    [&](const auto &route) {
                      return route.network ==
                                 source.destination.ipv6_network &&
                             route.prefix_length ==
                                 source.destination.length &&
                             route.source == source.source;
                    })
              : std::any_of(
                    manager->ipv4_rib.routes().begin(),
                    manager->ipv4_rib.routes().end(),
                    [&](const auto &route) {
                      return route.network ==
                                 source.destination.ipv4_network &&
                             route.prefix_length ==
                                 source.destination.length &&
                             route.source == source.source;
                    });
      if (installed)
        active_external_routes.push_back(external);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  // The stage commands carry exact counts and value records. The OSPF owner
  // allocates and validates an unpublished candidate, while the active
  // generation continues to process packets and deadlines.
  const ospf::ProcessIdentity generation_identity{.device = device};
  auto result = impl_->execute_ospf(
      {.process = generation_identity,
       .expected_processes = static_cast<std::uint32_t>(processes.size()),
       .expected_interfaces =
           static_cast<std::uint32_t>(interfaces.size()),
       .expected_authentications =
           static_cast<std::uint32_t>(authentications.size()),
       .expected_nbma_neighbors =
           static_cast<std::uint32_t>(nbma_neighbors.size()),
       .expected_virtual_links =
           static_cast<std::uint32_t>(virtual_links.size()),
       .expected_ranges = static_cast<std::uint32_t>(ranges.size()),
       .expected_external_routes =
           static_cast<std::uint32_t>(active_external_routes.size()),
       .kind = ospf::ControlCommandKind::begin_generation});
  if (!result.success)
    return false;

  const auto abort = [&] {
    static_cast<void>(impl_->execute_ospf(
        {.process = generation_identity,
         .kind = ospf::ControlCommandKind::abort_generation}));
  };
  for (const auto &process : processes) {
    if (process.device != device) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .router_id = process.router_id,
         .initial_dd_sequence = process.initial_dd_sequence,
         .maximum_interfaces = process.maximum_interfaces,
         .default_metric = process.default_metric,
         .router_preference = process.router_preference,
         .external_preference = process.external_preference,
         .spf_initial_wait_milliseconds =
             process.spf_initial_wait_milliseconds,
         .spf_second_wait_milliseconds =
             process.spf_second_wait_milliseconds,
         .spf_maximum_wait_milliseconds =
             process.spf_maximum_wait_milliseconds,
         .lsa_initial_wait_milliseconds =
             process.lsa_initial_wait_milliseconds,
         .lsa_second_wait_milliseconds =
             process.lsa_second_wait_milliseconds,
         .lsa_maximum_wait_milliseconds =
             process.lsa_maximum_wait_milliseconds,
         .area_type = process.area_type,
         .kind = ospf::ControlCommandKind::stage_process,
         .summaries = process.summaries,
         .nssa_translate_always = process.nssa_translate_always,
         .asbr = process.asbr,
         .graceful_restart_helper = process.graceful_restart_helper,
         .loopfree_alternates = process.loopfree_alternates,
         .overload = process.overload});
    if (!result.success) {
      abort();
      return false;
    }
  }

  std::array<std::uint8_t, device_catalog::maximum_ports_per_router>
      next_masks{};
  for (const auto &interface : interfaces) {
    const auto &process = interface.process;
    const auto ordinal = interface.interface.physical_port_ordinal;
    const bool passive_without_port =
        interface.interface.protocol.passive &&
        ordinal == ospf::no_physical_port;
    if (process.device != device ||
        (!passive_without_port && ordinal >= next_masks.size()) ||
        (process.version != packet::ospf::version_two &&
         process.version != packet::ospf::version_three)) {
      abort();
      return false;
    }
    // A port may participate in both address families or in multiple areas
    // only where configuration validation permits it. The forwarding mask is
    // a union, so adding one protocol cannot clear the other protocol's punt.
    constexpr std::uint8_t version_two_presence = 1U << 0U;
    constexpr std::uint8_t version_three_presence = 1U << 1U;
    if (!passive_without_port)
      next_masks[ordinal] |=
          process.version == packet::ospf::version_two
              ? version_two_presence
              : version_three_presence;
    result = impl_->execute_ospf(
        {.interface = interface.interface,
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .kind = ospf::ControlCommandKind::stage_interface});
    if (!result.success) {
      abort();
      return false;
    }
  }
  for (const auto &authentication : authentications) {
    const auto &process = authentication.process;
    if (process.device != device) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.authentication = authentication.authentication,
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .interface_id = authentication.interface_id,
         .kind = ospf::ControlCommandKind::stage_authentication,
         .authentication_receive = authentication.receive,
         .authentication_send = authentication.send});
    if (!result.success) {
      abort();
      return false;
    }
  }
  for (const auto &neighbor : nbma_neighbors) {
    const auto &process = neighbor.process;
    if (process.device != device) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.nbma_neighbor = neighbor.neighbor,
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .interface_id = neighbor.interface_id,
         .kind = ospf::ControlCommandKind::stage_nbma_neighbor});
    if (!result.success) {
      abort();
      return false;
    }
  }
  for (const auto &virtual_link : virtual_links) {
    const auto &process = virtual_link.process;
    if (process.device != device || process.area_id != 0U) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.virtual_link = virtual_link.link,
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .kind = ospf::ControlCommandKind::stage_virtual_link});
    if (!result.success) {
      abort();
      return false;
    }
  }
  for (const auto &range : ranges) {
    const auto &process = range.process;
    if (process.device != device ||
        range.prefix.length >
            ip::address_bits(range.prefix.network.family)) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.range =
             {.prefix = range.prefix,
              .advertised_metric =
                  range.has_advertised_metric
                      ? std::optional<std::uint32_t>{
                            range.advertised_metric}
                      : std::nullopt,
              .advertise = range.advertise},
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .kind = ospf::ControlCommandKind::stage_range});
    if (!result.success) {
      abort();
      return false;
    }
  }
  for (const auto &external : active_external_routes) {
    const auto &process = external.process;
    if (process.device != device) {
      abort();
      return false;
    }
    result = impl_->execute_ospf(
        {.external_route = external.advertisement,
         .process =
             {.device = device,
              .area_id = process.area_id,
              .version = process.version,
              .instance_id = process.instance_id},
         .kind = ospf::ControlCommandKind::stage_external_route});
    if (!result.success) {
      abort();
      return false;
    }
  }

  // Quiescing forwarding closes the only observation window between protocol
  // generation publication and its derived multicast punt projection. In
  // combined mode pause_forwarding is a no-op because this method already runs
  // on the sole network owner.
  if (!impl_->pause_forwarding()) {
    abort();
    return false;
  }
  auto &current_masks = impl_->ospf_punt_masks[device.index];
  bool programmed = true;
  for (std::size_t ordinal{}; ordinal < next_masks.size() && programmed;
       ++ordinal) {
    if (current_masks[ordinal] == next_masks[ordinal])
      continue;
    constexpr std::uint8_t version_two_presence = 1U << 0U;
    constexpr std::uint8_t version_three_presence = 1U << 1U;
    const ForwardCommand punt{
        .kind = ForwardCommandKind::configure_ospf_punt,
        .device = device,
        .port = ForwardPort{.ordinal = static_cast<std::uint16_t>(ordinal)},
        .ospf_version_two =
            (next_masks[ordinal] & version_two_presence) != 0U,
        .ospf_version_three =
            (next_masks[ordinal] & version_three_presence) != 0U};
    // Forwarding owners are quiesced, so the network owner may apply this
    // short projection directly without queueing a command to a sleeping
    // shard. No packet path can concurrently read the mask.
    if (auto *forwarder = impl_->router(device))
      programmed = forwarder->configure_ospf_punt(
          punt.port.ordinal, punt.ospf_version_two, punt.ospf_version_three);
    else
      programmed = false;
  }

  if (programmed)
    result = impl_->execute_ospf(
        {.process = generation_identity,
         .kind = ospf::ControlCommandKind::commit_generation});
  if (!programmed || !result.success) {
    // Restore every port from the previously published projection before
    // forwarding resumes. A failed generation is therefore invisible both to
    // protocol packet acceptance and to the daemon owner.
    for (std::size_t ordinal{}; ordinal < next_masks.size(); ++ordinal) {
      if (current_masks[ordinal] == next_masks[ordinal])
        continue;
      constexpr std::uint8_t version_two_presence = 1U << 0U;
      constexpr std::uint8_t version_three_presence = 1U << 1U;
      const ForwardCommand restore{
          .kind = ForwardCommandKind::configure_ospf_punt,
          .device = device,
          .port = ForwardPort{.ordinal =
                                  static_cast<std::uint16_t>(ordinal)},
          .ospf_version_two =
              (current_masks[ordinal] & version_two_presence) != 0U,
          .ospf_version_three =
              (current_masks[ordinal] & version_three_presence) != 0U};
      if (auto *forwarder = impl_->router(device))
        static_cast<void>(forwarder->configure_ospf_punt(
            restore.port.ordinal, restore.ospf_version_two,
            restore.ospf_version_three));
    }
    abort();
    impl_->resume_forwarding();
    return false;
  }

  current_masks = next_masks;
  // Both vectors were completely allocated before the owner transaction
  // started. Swapping after commit is non-throwing and retains the exact
  // configured set needed for future RIB-driven withdrawal and recovery.
  auto &manager = impl_->route_managers[device.index];
  if (manager) {
    manager->configured_external_routes.swap(configured_external_routes);
    manager->active_external_routes.swap(active_external_routes);
  }
  impl_->resume_forwarding();
  return true;
}

bool NetworkPlane::program_fib(DeviceHandle device,
                               const routing::FibProgram &fib) noexcept {
  if (!impl_->live(device) ||
      device.index >= impl_->route_managers.size())
    return false;
  auto &manager = impl_->route_managers[device.index];
  // Low-level NetworkPlane tests may deliberately program an already selected
  // FIB without a control RIB. Preserve that narrow API contract. Production
  // RuntimeSupervisor always publishes RoutePolicyProgram first.
  if (!manager || !manager->policy_configured)
    return impl_->install_ipv4_fib(device, fib);
  if (!manager->base_ipv4_configured) {
    // A restored forwarding owner may already hold this control generation.
    // Rebuild the manager at the same generation when no learned route changes
    // its bytes, which RouterForwarder accepts as an exact idempotent replay.
    // If OSPF converged first, advance beyond the restored base generation
    // because the composed bytes are intentionally different.
    const auto configuration_floor =
        manager->ospf_ipv4.empty() && fib.generation
            ? fib.generation - 1U
            : fib.generation;
    // A restored forwarding owner may already hold a generation advanced by
    // earlier OSPF convergence. The newly reconstructed route manager starts
    // with an empty RIB, but it must retain that forwarding high-water mark.
    // Reusing the smaller configuration generation would make the forwarder
    // correctly reject the reconstructed FIB as stale, leaving a full LSDB
    // and zero visible OSPF routes after browser reload.
    manager->installed_ipv4_generation =
        std::max(manager->installed_ipv4_generation, configuration_floor);
  }
  manager->base_ipv4 = fib;
  manager->base_ipv4_configured = true;
  return impl_->rebuild_managed_routes(device, *manager, manager->ospf_ipv4,
                                       manager->ospf_ipv6);
}

bool NetworkPlane::program_ipv6_fib(
    DeviceHandle device, const routing::Ipv6FibProgram &fib) noexcept {
  if (!impl_->live(device) ||
      device.index >= impl_->route_managers.size())
    return false;
  auto &manager = impl_->route_managers[device.index];
  if (!manager || !manager->policy_configured)
    return impl_->install_ipv6_fib(device, fib);
  if (!manager->base_ipv6_configured) {
    const auto configuration_floor =
        manager->ospf_ipv6.empty() && fib.generation
            ? fib.generation - 1U
            : fib.generation;
    manager->installed_ipv6_generation =
        std::max(manager->installed_ipv6_generation, configuration_floor);
  }
  manager->base_ipv6 = fib;
  manager->base_ipv6_configured = true;
  return impl_->rebuild_managed_routes(device, *manager, manager->ospf_ipv4,
                                       manager->ospf_ipv6);
}

bool NetworkPlane::program_route_policy(
    DeviceHandle device, const RoutePolicyProgram &policy) noexcept {
  if (!impl_->live(device) ||
      device.index >= impl_->route_managers.size() ||
      policy.maximum_ecmp_paths == 0U)
    return false;
  auto &manager = impl_->route_managers[device.index];
  if (!manager)
    return false;
  const auto same_ipv4 = [](const auto &left, const auto &right) {
    return left.configured == right.configured &&
           left.network == right.network &&
           left.next_hop == right.next_hop &&
           left.prefix_length == right.prefix_length &&
           left.indirect == right.indirect;
  };
  const auto same_ipv6 = [](const auto &left, const auto &right) {
    return left.configured == right.configured &&
           left.indirect == right.indirect &&
           left.outgoing_interface_set == right.outgoing_interface_set &&
           left.network == right.network &&
           left.next_hop == right.next_hop &&
           left.outgoing_interface_id == right.outgoing_interface_id &&
           left.prefix_length == right.prefix_length;
  };
  const bool unchanged =
      manager->policy_configured &&
      manager->policy.maximum_ecmp_paths == policy.maximum_ecmp_paths &&
      std::equal(manager->policy.ipv4_statics.begin(),
                 manager->policy.ipv4_statics.end(),
                 policy.ipv4_statics.begin(), same_ipv4) &&
      std::equal(manager->policy.ipv6_statics.begin(),
                 manager->policy.ipv6_statics.end(),
                 policy.ipv6_statics.begin(), same_ipv6);
  // Reconciliation republishes policy before computing whether connected
  // state changed. An identical generation is a successful no-op and must not
  // consume another FIB generation or block the subsequent base update.
  if (unchanged)
    return true;
  manager->policy = policy;
  manager->policy_configured = true;
  // The first policy arrives before base FIB publication. Later ECMP or static
  // edits must immediately reselect from the retained connected and OSPF
  // generations instead of waiting for unrelated protocol activity.
  if (!manager->base_ipv4_configured && !manager->base_ipv6_configured)
    return true;
  return impl_->rebuild_managed_routes(device, *manager, manager->ospf_ipv4,
                                       manager->ospf_ipv6);
}

std::optional<OspfRouteDiagnostics>
NetworkPlane::ospf_route_diagnostics(DeviceHandle device) const noexcept {
  if (!impl_->live(device) ||
      device.index >= impl_->route_managers.size())
    return std::nullopt;
  const auto &manager = impl_->route_managers[device.index];
  if (!manager)
    return std::nullopt;
  return OspfRouteDiagnostics{
      .generation = manager->ospf_generation,
      .ipv4_candidates =
          static_cast<std::uint32_t>(manager->ospf_ipv4.size()),
      .ipv6_candidates =
          static_cast<std::uint32_t>(manager->ospf_ipv6.size())};
}

std::optional<ospf::ControlResult>
NetworkPlane::query_ospf(DeviceHandle device,
                         const OspfOperationalQuery &query) noexcept {
  if (!impl_->live(device) ||
      (query.kind != ospf::ControlCommandKind::query_process &&
       query.kind != ospf::ControlCommandKind::query_interface &&
       query.kind != ospf::ControlCommandKind::query_neighbor &&
       query.kind != ospf::ControlCommandKind::query_lsa &&
       query.kind != ospf::ControlCommandKind::reset_neighbors &&
       query.kind != ospf::ControlCommandKind::reset_database))
    return std::nullopt;
  const auto result = impl_->execute_ospf(
      {.process = {.device = device,
                   .version = query.version,
                   .instance_id = query.instance_id},
       .interface_id = query.interface_id,
       .process_ordinal = query.process_ordinal,
       .interface_ordinal = query.interface_ordinal,
       .row_ordinal = query.row_ordinal,
       .neighbor_router_id = query.neighbor_router_id,
       .kind = query.kind});
  return result.success ? std::optional{result} : std::nullopt;
}

bool NetworkPlane::program_ipv6_address_generation(
    DeviceHandle device,
    std::span<const RouterIpv6Address> addresses) noexcept {
  if (!device || addresses.size() > RouterIpv6AddressTable::capacity)
    return false;
  const auto operation_now = Clock::now();
  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = device;
    command.operation_now = operation_now;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  if (!execute({.kind = ForwardCommandKind::begin_ipv6_address_generation,
                .fib = Ipv6AddressGenerationBegin{
                    static_cast<std::uint32_t>(addresses.size())}}))
    return false;
  for (const auto &address : addresses)
    if (!execute({.kind = ForwardCommandKind::add_ipv6_interface_address,
                  .fib = address})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_ipv6_address_generation}));
      return false;
    }
  if (execute({.kind = ForwardCommandKind::commit_ipv6_address_generation}))
    return true;
  // Commit is terminal in the forwarding owner, while Abort is deliberately
  // idempotent so both sequential and parallel execution leave no staging.
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_ipv6_address_generation}));
  return false;
}

bool NetworkPlane::program_sap_generation(
    DeviceHandle device, std::span<const service::SapAttachment> attachments,
    std::span<const service::ServiceIpv6Interface> interfaces) noexcept {
  if (!device ||
      attachments.size() > std::numeric_limits<std::uint32_t>::max() ||
      interfaces.size() > std::numeric_limits<std::uint32_t>::max())
    return false;

  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  if (!execute({.kind = ForwardCommandKind::begin_sap_generation,
                .fib = SapGenerationBegin{
                    static_cast<std::uint32_t>(attachments.size()),
                    static_cast<std::uint32_t>(interfaces.size())}}))
    return false;

  // One self-contained attachment per acknowledged value command keeps both
  // SPSC slots trivially copyable and bounds partial transaction memory by the
  // Begin declaration rather than a hidden fixed SAP limit.
  for (const auto &attachment : attachments)
    if (!execute({.kind = ForwardCommandKind::add_sap_attachment,
                  .fib = attachment})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_sap_generation}));
      return false;
    }
  for (const auto &interface : interfaces)
    if (!execute({.kind = ForwardCommandKind::add_service_ipv6_interface,
                  .fib = interface})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_sap_generation}));
      return false;
    }
  if (execute({.kind = ForwardCommandKind::commit_sap_generation}))
    return true;
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_sap_generation}));
  return false;
}

bool NetworkPlane::install_static_ipv6_neighbor(
    const StaticIpv6NeighborProgram &program) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::install_static_ipv6_neighbor,
             .device = program.device,
             .fib = program})
        .success;
  auto *forwarder = impl_->router(program.device);
  return forwarder && forwarder->install_static_ipv6_neighbor(
                          program.port_ordinal, program.address, program.mac);
}

bool NetworkPlane::remove_static_ipv6_neighbor(
    DeviceHandle device, std::uint16_t port_ordinal,
    const packet::Ipv6 &address) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::remove_static_ipv6_neighbor,
             .device = device,
             .port = {.ordinal = port_ordinal},
             .ipv6_destination = address})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->remove_static_ipv6_neighbor(port_ordinal, address);
}

bool NetworkPlane::install_static_ipv4_neighbor(
    const StaticIpv4NeighborProgram &program) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::install_static_ipv4_neighbor,
             .device = program.device,
             .fib = program})
        .success;
  auto *forwarder = impl_->router(program.device);
  return forwarder && forwarder->install_static_ipv4_neighbor(
                          program.port_ordinal, program.address, program.mac);
}

bool NetworkPlane::remove_static_ipv4_neighbor(DeviceHandle device,
                                               std::uint16_t port_ordinal,
                                               std::uint32_t address) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::remove_static_ipv4_neighbor,
             .device = device,
             .port = {.ordinal = port_ordinal},
             .destination = address})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->remove_static_ipv4_neighbor(port_ordinal, address);
}

bool NetworkPlane::clear_dynamic_ipv6_neighbors(
    DeviceHandle device, std::optional<std::uint16_t> port_ordinal,
    std::optional<packet::Ipv6> address) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_dynamic_ipv6_neighbors,
             .device = device,
             .port = {.ordinal = port_ordinal.value_or(0U)},
             .ipv6_destination = address.value_or(packet::Ipv6{}),
             .ipv6_neighbor_interface_specific = port_ordinal.has_value()})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->clear_dynamic_ipv6_neighbors(port_ordinal, address);
}

bool NetworkPlane::clear_dynamic_ipv4_neighbors(
    DeviceHandle device, std::optional<std::uint16_t> port_ordinal,
    std::optional<std::uint32_t> address) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_dynamic_ipv4_neighbors,
             .device = device,
             .port = {.ordinal = port_ordinal.value_or(0U)},
             .destination = address.value_or(0U),
             .ipv4_neighbor_interface_specific = port_ordinal.has_value()})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->clear_dynamic_ipv4_neighbors(port_ordinal, address);
}

bool NetworkPlane::configure_router_advertisement(
    const RouterAdvertisementProgram &program) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::configure_router_advertisement,
             .device = program.device,
             .fib = program})
        .success;
  auto *forwarder = impl_->router(program.device);
  return forwarder &&
         forwarder->configure_router_advertisement(
             program.port_ordinal, program.enabled, program.config);
}

bool NetworkPlane::remove_router_advertisement(
    DeviceHandle device, std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::remove_router_advertisement,
             .device = device,
             .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->remove_router_advertisement(port_ordinal);
}

bool NetworkPlane::configure_mld_interface(
    const MldInterfaceProgram &program) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::configure_mld_interface,
                           .device = program.device,
                           .fib = program})
        .success;
  auto *forwarder = impl_->router(program.device);
  return forwarder && forwarder->configure_mld_interface(program.configuration);
}

bool NetworkPlane::remove_mld_interface(DeviceHandle device,
                                        std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::remove_mld_interface,
                           .device = device,
                           .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->remove_mld_interface(port_ordinal);
}

bool NetworkPlane::configure_dhcpv4_relay(
    DeviceHandle device,
    const dhcpv4::RelayInterfaceConfiguration &configuration) noexcept {
  if (!device || configuration.interface_id == 0U ||
      configuration.relay.circuit_id.size() > 255U ||
      configuration.relay.remote_id.size() > 255U ||
      configuration.relay.servers.size() >
          device_catalog::dhcpv4_relay_servers_per_interface)
    return false;
  Dhcpv4RelayBegin begin{
      .interface_id = configuration.interface_id,
      .physical_port_ordinal = configuration.physical_port_ordinal,
      .gateway_address = configuration.relay.gateway_address,
      .circuit_id_octets = static_cast<std::uint16_t>(
          configuration.relay.circuit_id.size()),
      .remote_id_octets = static_cast<std::uint16_t>(
          configuration.relay.remote_id.size()),
      .server_count =
          static_cast<std::uint16_t>(configuration.relay.servers.size()),
      .existing_information = configuration.relay.existing_information,
      .source_address = configuration.relay.source_address,
      .maximum_hops = configuration.relay.maximum_hops,
      .trusted_ingress = configuration.relay.trusted_ingress,
      .relay_plain_bootp = configuration.relay.relay_plain_bootp,
      .release_include_gateway_address =
          configuration.relay.release_include_gateway_address};
  std::copy(configuration.relay.circuit_id.begin(),
            configuration.relay.circuit_id.end(), begin.circuit_id.begin());
  std::copy(configuration.relay.remote_id.begin(),
            configuration.relay.remote_id.end(), begin.remote_id.begin());
  for (std::size_t index{}; index < configuration.relay.servers.size();
       ++index)
    begin.servers[index] = configuration.relay.servers[index].address;
  const ForwardCommand command{.kind =
                                   ForwardCommandKind::configure_dhcpv4_relay,
                               .device = device,
                               .fib = begin};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

bool NetworkPlane::remove_dhcpv4_relay(
    DeviceHandle device, std::uint64_t logical_interface_id) noexcept {
  if (!device || logical_interface_id == 0U)
    return false;
  const ForwardCommand command{
      .logical_interface_id = logical_interface_id,
      .kind = ForwardCommandKind::remove_dhcpv4_relay,
      .device = device};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

bool NetworkPlane::configure_router_dhcpv4_server(
    const RouterDhcpv4ServerProgram &program) noexcept {
  if (!program.device || program.name.empty() || program.name.size() > 32U ||
      program.configuration.offer_hold <= std::chrono::seconds::zero() ||
      program.configuration.decline_hold < std::chrono::seconds::zero() ||
      program.configuration.domain_name_servers.size() >
          packet::dhcpv4::maximum_ipv4_addresses_per_option ||
      program.pools.size() > device_catalog::dhcpv4_pools_per_server ||
      program.reservations.size() >
          device_catalog::dhcpv4_leases_per_server ||
      program.exclusions.size() >
          device_catalog::dhcpv4_leases_per_server)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = program.device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  const auto &configuration = program.configuration;
  Dhcpv4ServerBegin begin{
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
      .name_octets = static_cast<std::uint8_t>(program.name.size()),
      .authoritative = configuration.authoritative,
      .force_renews = configuration.force_renews};
  std::copy(program.name.begin(), program.name.end(), begin.name.begin());
  if (!execute({.kind = ForwardCommandKind::begin_router_dhcpv4_server,
                .fib = begin}))
    return false;
  for (const auto &dns : configuration.domain_name_servers)
    if (!execute({.kind = ForwardCommandKind::add_router_dhcpv4_server_dns,
                  .fib = dns}))
      goto abort_router_dhcpv4_server;
  for (const auto &pool : program.pools)
    if (!execute({.kind = ForwardCommandKind::add_router_dhcpv4_server_pool,
                  .fib = pool}))
      goto abort_router_dhcpv4_server;
  for (const auto &reservation : program.reservations)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_router_dhcpv4_server_reservation,
             .fib = reservation}))
      goto abort_router_dhcpv4_server;
  for (const auto &excluded : program.exclusions)
    if (!execute(
            {.kind = ForwardCommandKind::add_router_dhcpv4_server_exclusion,
             .fib = excluded}))
      goto abort_router_dhcpv4_server;
  if (execute({.kind = ForwardCommandKind::commit_router_dhcpv4_server}))
    return true;
abort_router_dhcpv4_server:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_router_dhcpv4_server}));
  return false;
}

bool NetworkPlane::remove_router_dhcpv4_server(
    DeviceHandle device, std::string_view name) noexcept {
  if (!device || name.empty() || name.size() > 32U)
    return false;
  Dhcpv4ServerBegin begin{
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), begin.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_router_dhcpv4_server,
      .device = device,
      .fib = begin};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

bool NetworkPlane::clear_router_dhcpv4_server_statistics(
    DeviceHandle device, std::string_view name) noexcept {
  if (!device || name.empty() || name.size() > 32U)
    return false;
  RouterDhcpv4ServerOperation operation{
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), operation.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::clear_router_dhcpv4_server_statistics,
      .device = device,
      .fib = operation};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

bool NetworkPlane::clear_router_dhcpv4_server_leases(
    DeviceHandle device, std::string_view name,
    const dhcpv4::LeaseClearFilter &filter) noexcept {
  if (!device || name.empty() || name.size() > 32U ||
      filter.prefix_length > 32U)
    return false;
  RouterDhcpv4ServerOperation operation{
      .lease_filter = filter,
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), operation.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::clear_router_dhcpv4_server_leases,
      .device = device,
      .fib = operation};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

dhcpv4::ForceRenewStatus NetworkPlane::send_router_dhcpv4_force_renew(
    DeviceHandle device, std::string_view name, packet::Ipv4 address) noexcept {
  if (!device || name.empty() || name.size() > 32U ||
      address == packet::Ipv4{})
    return dhcpv4::ForceRenewStatus::not_configured;
  RouterDhcpv4ServerOperation operation{
      .address = address,
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), operation.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::send_router_dhcpv4_force_renew,
      .device = device,
      .fib = operation};
  const auto result =
      impl_->parallel()
          ? impl_->execute_forward(command)
          : Impl::apply_forward_command(impl_.get(), 0U, command);
  return static_cast<dhcpv4::ForceRenewStatus>(result.value);
}

bool NetworkPlane::configure_dhcpv6_relay(
    DeviceHandle device,
    const dhcpv6::RelayInterfaceConfig &configuration) noexcept {
  if (!device ||
      configuration.relay_interface_id.size() >
          std::numeric_limits<std::uint16_t>::max() ||
      configuration.server_count > configuration.servers.size())
    return false;

  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  const Dhcpv6RelayBegin begin{
      .interface_id = configuration.interface_id,
      .physical_port_ordinal = configuration.physical_port_ordinal,
      .link_address = configuration.link_address,
      .source_address = configuration.source_address,
      .client_prefix = configuration.client_prefix,
      .expected_interface_id_octets =
          static_cast<std::uint32_t>(configuration.relay_interface_id.size()),
      .expected_servers =
          static_cast<std::uint16_t>(configuration.server_count),
      .lease_population_limit = configuration.lease_population_limit,
      .has_source_address = configuration.has_source_address,
      .neighbor_resolution = configuration.neighbor_resolution,
      .route_non_temporary = configuration.route_non_temporary,
      .route_temporary = configuration.route_temporary,
      .route_delegated_prefix = configuration.route_delegated_prefix,
      .route_prefix_exclude = configuration.route_prefix_exclude,
      .upstream_policy = configuration.upstream_policy};
  if (!execute({.kind = ForwardCommandKind::begin_dhcpv6_relay, .fib = begin}))
    return false;

  // Each command is synchronously acknowledged before the next one is
  // submitted. An Interface-Id can therefore occupy the complete 16-bit DHCP
  // option domain without requiring a 64 KiB shared ring slot or an unbounded
  // number of simultaneously queued messages.
  for (std::size_t offset = 0; offset < configuration.relay_interface_id.size();
       offset += dhcpv6_relay_program_chunk_octets) {
    Dhcpv6RelayInterfaceIdChunk chunk;
    chunk.size = static_cast<std::uint16_t>(
        std::min(dhcpv6_relay_program_chunk_octets,
                 configuration.relay_interface_id.size() - offset));
    std::copy_n(configuration.relay_interface_id.begin() + offset, chunk.size,
                chunk.octets.begin());
    if (execute({.kind = ForwardCommandKind::add_dhcpv6_relay_interface_id,
                 .fib = chunk}))
      continue;
    static_cast<void>(
        execute({.kind = ForwardCommandKind::abort_dhcpv6_relay}));
    return false;
  }
  for (std::size_t index = 0; index < configuration.server_count; ++index)
    if (!execute({.kind = ForwardCommandKind::add_dhcpv6_relay_server,
                  .fib = configuration.servers[index]})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_dhcpv6_relay}));
      return false;
    }
  if (execute({.kind = ForwardCommandKind::commit_dhcpv6_relay}))
    return true;
  // Commit already discards its staging object. Abort remains idempotent for
  // the transport transaction and also covers future commit implementations
  // that may preserve a rejected candidate for diagnostics.
  static_cast<void>(execute({.kind = ForwardCommandKind::abort_dhcpv6_relay}));
  return false;
}

bool NetworkPlane::remove_dhcpv6_relay(
    DeviceHandle device, std::uint64_t logical_interface_id) noexcept {
  if (!device || logical_interface_id == 0U)
    return false;
  if (impl_->parallel())
    return impl_
        ->execute_forward({
            .logical_interface_id = logical_interface_id,
            .kind = ForwardCommandKind::remove_dhcpv6_relay,
            .device = device,
        })
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->remove_dhcpv6_relay(logical_interface_id);
}

bool NetworkPlane::clear_dhcpv6_relay_leases(
    DeviceHandle device, const Dhcpv6RelayLeaseClearProgram &program) noexcept {
  if (!device || program.filter.interface_id == 0U)
    return false;
  const ForwardCommand command{
      .kind = ForwardCommandKind::clear_dhcpv6_relay_leases,
      .device = device,
      .fib = program};
  return (impl_->parallel()
              ? impl_->execute_forward(command)
              : Impl::apply_forward_command(impl_.get(), 0U, command))
      .success;
}

bool NetworkPlane::clear_mld_database(
    DeviceHandle device, std::uint16_t port_ordinal,
    const std::optional<packet::Ipv6> &group) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::clear_mld_database,
                           .device = device,
                           .port = {.ordinal = port_ordinal},
                           .ipv6_destination = group.value_or(packet::Ipv6{}),
                           .mld_group_specific = group.has_value()})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->clear_mld_database(port_ordinal, group);
}

bool NetworkPlane::clear_mld_database_all(DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::clear_mld_database_all,
                           .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_mld_database_all();
  return true;
}

bool NetworkPlane::clear_mld_version(DeviceHandle device,
                                     std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::clear_mld_version,
                           .device = device,
                           .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->clear_mld_version(port_ordinal);
}

bool NetworkPlane::clear_mld_statistics(DeviceHandle device,
                                        std::uint16_t port_ordinal) noexcept {
  // The forwarding owner performs this as one mutation. The parallel and
  // native test paths deliberately share the same typed operation.
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::clear_mld_statistics,
                           .device = device,
                           .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->clear_mld_statistics(port_ordinal);
}

bool NetworkPlane::clear_mld_statistics_all(DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::clear_mld_statistics_all,
                           .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_mld_statistics_all();
  return true;
}

bool NetworkPlane::clear_icmpv4_statistics_all(DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv4_statistics_all,
             .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_icmpv4_statistics_all();
  return true;
}

bool NetworkPlane::clear_icmpv4_global_statistics(
    DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv4_global_statistics,
             .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_icmpv4_global_statistics();
  return true;
}

bool NetworkPlane::clear_icmpv4_interface_statistics(
    DeviceHandle device, std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv4_interface_statistics,
             .device = device,
             .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->clear_icmpv4_interface_statistics(port_ordinal);
}

bool NetworkPlane::clear_icmpv6_statistics_all(DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv6_statistics_all,
             .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_icmpv6_statistics_all();
  return true;
}

bool NetworkPlane::clear_icmpv6_global_statistics(
    DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv6_global_statistics,
             .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_icmpv6_global_statistics();
  return true;
}

bool NetworkPlane::clear_icmpv6_interface_statistics(
    DeviceHandle device, std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::clear_icmpv6_interface_statistics,
             .device = device,
             .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->clear_icmpv6_interface_statistics(port_ordinal);
}

bool NetworkPlane::clear_router_advertisement_statistics_all(
    DeviceHandle device) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind =
                 ForwardCommandKind::clear_router_advertisement_statistics_all,
             .device = device})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  forwarder->clear_router_advertisement_statistics_all();
  return true;
}

bool NetworkPlane::clear_router_advertisement_interface_statistics(
    DeviceHandle device, std::uint16_t port_ordinal) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::
                               clear_router_advertisement_interface_statistics,
                           .device = device,
                           .port = {.ordinal = port_ordinal}})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->clear_router_advertisement_interface_statistics(
             port_ordinal);
}

bool NetworkPlane::edit_mld_static(DeviceHandle device,
                                   std::uint16_t port_ordinal,
                                   MldStaticOperation operation,
                                   const packet::Ipv6 &group,
                                   const packet::Ipv6 &source) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::edit_mld_static,
                           .device = device,
                           .port = {.ordinal = port_ordinal},
                           .ipv6_destination = group,
                           .ipv6_source = source,
                           .mld_static_operation = operation})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->edit_mld_static(port_ordinal, operation, group, source);
}

bool NetworkPlane::program_mld_ssm_translation(
    DeviceHandle device, std::uint16_t port_ordinal,
    MldSsmProgramOperation operation, const MldSsmTranslation &translation,
    std::uint32_t expected_entries) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::program_mld_ssm_translation,
             .device = device,
             .port = {.ordinal = port_ordinal},
             .mld_ssm_operation = operation,
             .mld_ssm_translation = translation,
             .mld_ssm_expected_entries = expected_entries})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->program_mld_ssm_translation(port_ordinal, operation,
                                                translation, expected_entries);
}

bool NetworkPlane::program_mld_import_policy(
    DeviceHandle device, std::uint16_t port_ordinal,
    mld::ImportPolicyProgramOperation operation,
    const mld::ImportPolicyEntry &entry, mld::ImportPolicyAction default_action,
    std::uint32_t expected_entries) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward(
            {.kind = ForwardCommandKind::program_mld_import_policy,
             .device = device,
             .port = {.ordinal = port_ordinal},
             .mld_import_policy_operation = operation,
             .mld_import_policy_entry = entry,
             .mld_import_policy_default_action = default_action,
             .mld_import_policy_expected_entries = expected_entries})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder &&
         forwarder->program_mld_import_policy(port_ordinal, operation, entry,
                                              default_action, expected_entries);
}

bool NetworkPlane::initialize_signing_vault(
    std::span<const std::uint8_t> wrapping_key,
    const crypto::Sha256Digest &project_context_digest) noexcept {
  if (wrapping_key.size() != impl_->signing_wrapping_key.size() ||
      std::ranges::none_of(wrapping_key,
                           [](const auto byte) { return byte != 0U; }))
    return false;
  if (impl_->signing_vault_initialized)
    return std::ranges::equal(impl_->signing_wrapping_key, wrapping_key) &&
           impl_->signing_context_digest == project_context_digest;
  std::ranges::copy(wrapping_key, impl_->signing_wrapping_key.begin());
  impl_->signing_context_digest = project_context_digest;
  impl_->signing_vault_initialized = true;
  return true;
}

bool NetworkPlane::configure_router_bof_management(
    const RouterBofManagementProgram &program) noexcept {
  if (!program.device || program.endpoint.host)
    return false;
  auto endpoint = program.endpoint;
  const ForwardCommand command{
      .kind = ForwardCommandKind::configure_router_bof_management,
      .device = program.device,
      .host_program = endpoint};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_router_bof_dhcpv4_client(
    const RouterBofDhcpv4ClientProgram &program) noexcept {
  if (!program.device ||
      program.bootstrap_timeout <= std::chrono::seconds::zero() ||
      program.configuration.client_identifier.size() > 255U ||
      program.configuration.parameter_request_list.size() > 255U)
    return false;
  if (program.configuration.user_class.size() > 254U)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = program.device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  Dhcpv4ClientBegin begin{
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
  if (!execute({.kind =
                    ForwardCommandKind::begin_router_bof_dhcpv4_client,
                .fib = begin}))
    return false;
  if (execute(
          {.kind = ForwardCommandKind::commit_router_bof_dhcpv4_client}))
    return true;
  static_cast<void>(execute(
      {.kind = ForwardCommandKind::abort_router_bof_dhcpv4_client}));
  return false;
}

bool NetworkPlane::remove_router_bof_dhcpv4_client(
    DeviceHandle device) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_router_bof_dhcpv4_client,
      .device = device};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_router_bof_dhcpv6_client(
    const RouterBofDhcpv6ClientProgram &program) noexcept {
  if (!program.device ||
      program.bootstrap_timeout <= std::chrono::seconds::zero() ||
      program.configuration.identity_associations.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.requested_options.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.user_class.size() > 255U)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = program.device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  Dhcpv6ClientBegin begin{
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
                    begin.user_class.begin());
  if (!execute({.kind =
                    ForwardCommandKind::begin_router_bof_dhcpv6_client,
                .fib = begin}))
    return false;
  for (const auto &association : program.configuration.identity_associations)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_router_bof_dhcpv6_client_ia,
             .fib = Dhcpv6ClientAssociation{association.iaid,
                                            association.kind}}))
      goto abort_bof_dhcpv6;
  for (const auto option : program.configuration.requested_options)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_router_bof_dhcpv6_client_option,
             .fib = Dhcpv6ClientOption{option}}))
      goto abort_bof_dhcpv6;
  if (execute(
          {.kind = ForwardCommandKind::commit_router_bof_dhcpv6_client}))
    return true;
abort_bof_dhcpv6:
  static_cast<void>(execute(
      {.kind = ForwardCommandKind::abort_router_bof_dhcpv6_client}));
  return false;
}

bool NetworkPlane::remove_router_bof_dhcpv6_client(
    DeviceHandle device) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_router_bof_dhcpv6_client,
      .device = device};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_host(const HostNetworkProgram &program) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::configure_host,
                           .host = program.host,
                           .host_program = program})
        .success;
  auto *host = impl_->host(program.host);
  if (!host || program.prefix_length > 32U ||
      program.mtu < device_catalog::minimum_host_ipv4_mtu ||
      program.mtu > device_catalog::maximum_network_mtu)
    return false;
  if (!host->stack.configure(
          {.endpoint_mac = program.mac,
           .endpoint_address = program.address,
           .endpoint_prefix_length = program.prefix_length,
           .endpoint_gateway = program.gateway,
           .endpoint_mtu = program.mtu,
           .endpoint_interface_id = program.interface_id,
           .endpoint_ipv6_autoconfiguration = program.ipv6_autoconfiguration,
           .endpoint_ipv6_identifier = program.ipv6_identifier,
           .endpoint_transport_secret = program.transport_secret}))
    return false;
  host->stack.set_link_state(host->link_signal);
  host->configured = true;
  // Address replacement is a protocol operation and must not overwrite the
  // independently owned physical carrier established by configure_link.
  host->ping_pending = false;
  host->ping_reply = false;
  host->ping_clock_started = false;
  host->ping_reply_rtt = std::chrono::nanoseconds::zero();
  host->ping_reply_ttl = 0U;
  return true;
}

bool NetworkPlane::configure_host_dhcpv4_client(
    const HostDhcpv4ClientProgram &program) noexcept {
  if (!program.host ||
      program.configuration.client_identifier.size() > 255U ||
      program.configuration.parameter_request_list.size() > 255U)
    return false;
  if (program.configuration.user_class.size() > 254U)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };

  Dhcpv4ClientBegin begin{
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
  if (!execute(
          {.kind = ForwardCommandKind::begin_host_dhcpv4_client, .fib = begin}))
    return false;
  if (execute({.kind = ForwardCommandKind::commit_host_dhcpv4_client}))
    return true;
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dhcpv4_client}));
  return false;
}

bool NetworkPlane::remove_host_dhcpv4_client(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dhcpv4_client, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_host_dhcpv4_server(
    const HostDhcpv4ServerProgram &program) noexcept {
  if (!program.host ||
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
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  const auto &configuration = program.configuration;
  const Dhcpv4ServerBegin begin{
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
  if (!execute(
          {.kind = ForwardCommandKind::begin_host_dhcpv4_server, .fib = begin}))
    return false;
  for (const auto &dns : configuration.domain_name_servers)
    if (!execute({.kind = ForwardCommandKind::add_host_dhcpv4_server_dns,
                  .fib = dns}))
      goto abort_dhcpv4_server;
  for (const auto &pool : program.pools)
    if (!execute({.kind = ForwardCommandKind::add_host_dhcpv4_server_pool,
                  .fib = pool}))
      goto abort_dhcpv4_server;
  for (const auto &reservation : program.reservations)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_host_dhcpv4_server_reservation,
             .fib = reservation}))
      goto abort_dhcpv4_server;
  for (const auto &excluded : program.exclusions)
    if (!execute(
            {.kind = ForwardCommandKind::add_host_dhcpv4_server_exclusion,
             .fib = excluded}))
      goto abort_dhcpv4_server;
  if (execute({.kind = ForwardCommandKind::commit_host_dhcpv4_server}))
    return true;
abort_dhcpv4_server:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dhcpv4_server}));
  return false;
}

bool NetworkPlane::remove_host_dhcpv4_server(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dhcpv4_server, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

std::optional<std::size_t>
NetworkPlane::host_dhcpv4_client_lease_count(HostHandle host) noexcept {
  const auto status = host_dhcpv4_client_status(host);
  return status ? std::optional<std::size_t>{
                      status->lease_present ? 1U : 0U}
                : std::nullopt;
}

std::optional<dhcpv4::ClientStatus>
NetworkPlane::host_dhcpv4_client_status(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::host_dhcpv4_client_status, .host = host};
  const auto result =
      impl_->parallel() ? impl_->execute_forward(command)
                        : Impl::apply_forward_command(impl_.get(), 0U, command);
  return result.success ? std::optional{result.dhcpv4_client} : std::nullopt;
}

bool NetworkPlane::configure_host_dhcpv6_client(
    const HostDhcpv6ClientProgram &program) noexcept {
  if (!program.host ||
      program.configuration.identity_associations.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.requested_options.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.configuration.user_class.size() > 255U)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  Dhcpv6ClientBegin begin{
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
  std::ranges::copy(program.configuration.user_class,
                    begin.user_class.begin());
  if (!execute(
          {.kind = ForwardCommandKind::begin_host_dhcpv6_client, .fib = begin}))
    return false;
  for (const auto &association : program.configuration.identity_associations)
    if (!execute({.kind = ForwardCommandKind::add_host_dhcpv6_client_ia,
                  .fib = Dhcpv6ClientAssociation{association.iaid,
                                                 association.kind}})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_host_dhcpv6_client}));
      return false;
    }
  for (const auto option : program.configuration.requested_options)
    if (!execute({.kind = ForwardCommandKind::add_host_dhcpv6_client_option,
                  .fib = Dhcpv6ClientOption{option}})) {
      static_cast<void>(
          execute({.kind = ForwardCommandKind::abort_host_dhcpv6_client}));
      return false;
    }
  if (execute({.kind = ForwardCommandKind::commit_host_dhcpv6_client}))
    return true;
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dhcpv6_client}));
  return false;
}

bool NetworkPlane::remove_host_dhcpv6_client(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dhcpv6_client, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_host_dhcpv6_server(
    const HostDhcpv6ServerProgram &program) noexcept {
  if (!program.host ||
      program.decline_hold_time < std::chrono::seconds::zero() ||
      program.configuration.dns_recursive_servers.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.address_pools.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.prefix_pools.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  const auto &configuration = program.configuration;
  Dhcpv6ServerBegin begin{
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
  if (!execute(
          {.kind = ForwardCommandKind::begin_host_dhcpv6_server, .fib = begin}))
    return false;
  for (const auto &dns : configuration.dns_recursive_servers)
    if (!execute({.kind = ForwardCommandKind::add_host_dhcpv6_server_dns,
                  .fib = dns}))
      goto abort_server;
  for (const auto &pool : program.address_pools)
    if (!execute(
            {.kind = ForwardCommandKind::add_host_dhcpv6_server_address_pool,
             .fib = pool}))
      goto abort_server;
  for (const auto &pool : program.prefix_pools)
    if (!execute(
            {.kind = ForwardCommandKind::add_host_dhcpv6_server_prefix_pool,
             .fib = pool}))
      goto abort_server;
  if (execute({.kind = ForwardCommandKind::commit_host_dhcpv6_server}))
    return true;
abort_server:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dhcpv6_server}));
  return false;
}

bool NetworkPlane::remove_host_dhcpv6_server(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dhcpv6_server, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_router_dhcpv6_server(
    const RouterDhcpv6ServerProgram &program) noexcept {
  // RFC 9915 defines Decline but not a mandatory quarantine duration. The
  // protocol repository therefore uses zero as the documented indefinite
  // retention sentinel. Reject negative durations while preserving that
  // sentinel across this intermediate owner boundary.
  if (!program.device || program.name.empty() || program.name.size() > 32U ||
      program.decline_hold_time < std::chrono::seconds::zero() ||
      program.configuration.dns_recursive_servers.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.address_pools.size() >
          std::numeric_limits<std::uint32_t>::max() ||
      program.prefix_pools.size() >
          std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.device = program.device;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  const auto &configuration = program.configuration;
  Dhcpv6ServerBegin begin{
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
      .name_octets = static_cast<std::uint8_t>(program.name.size()),
      .preference = configuration.preference,
      .address_pool_index = configuration.address_pool_index,
      .prefix_pool_index = configuration.prefix_pool_index,
      .rapid_commit = configuration.rapid_commit,
      .lease_query = configuration.lease_query,
      .has_solicit_maximum_retransmission =
          configuration.solicit_maximum_retransmission_seconds.has_value(),
      .has_information_maximum_retransmission =
          configuration.information_maximum_retransmission_seconds.has_value()};
  std::copy(program.name.begin(), program.name.end(), begin.name.begin());
  if (!execute({.kind = ForwardCommandKind::begin_router_dhcpv6_server,
                .fib = begin}))
    return false;
  for (const auto &dns : configuration.dns_recursive_servers)
    if (!execute({.kind = ForwardCommandKind::add_router_dhcpv6_server_dns,
                  .fib = dns}))
      goto abort_router_server;
  for (const auto &pool : program.address_pools)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_router_dhcpv6_server_address_pool,
             .fib = pool}))
      goto abort_router_server;
  for (const auto &pool : program.prefix_pools)
    if (!execute(
            {.kind =
                 ForwardCommandKind::add_router_dhcpv6_server_prefix_pool,
             .fib = pool}))
      goto abort_router_server;
  if (execute({.kind = ForwardCommandKind::commit_router_dhcpv6_server}))
    return true;
abort_router_server:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_router_dhcpv6_server}));
  return false;
}

bool NetworkPlane::remove_router_dhcpv6_server(
    DeviceHandle device, std::string_view name) noexcept {
  if (!device || name.empty() || name.size() > 32U)
    return false;
  Dhcpv6ServerBegin begin{
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), begin.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_router_dhcpv6_server,
      .device = device,
      .fib = begin};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::clear_router_dhcpv6_server_leases(
    DeviceHandle device, std::string_view name,
    const dhcpv6::LeaseClearFilter &filter) noexcept {
  if (!device || name.empty() || name.size() > 32U ||
      filter.prefix_length > 128U)
    return false;
  RouterDhcpv6ServerOperation operation{
      .lease_filter = filter,
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), operation.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::clear_router_dhcpv6_server_leases,
      .device = device,
      .fib = operation};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::clear_router_dhcpv6_server_statistics(
    DeviceHandle device, std::string_view name) noexcept {
  if (!device || name.empty() || name.size() > 32U)
    return false;
  RouterDhcpv6ServerOperation operation{
      .name_octets = static_cast<std::uint8_t>(name.size())};
  std::copy(name.begin(), name.end(), operation.name.begin());
  const ForwardCommand command{
      .kind = ForwardCommandKind::clear_router_dhcpv6_server_statistics,
      .device = device,
      .fib = operation};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

std::optional<std::size_t>
NetworkPlane::host_dhcpv6_client_lease_count(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::host_dhcpv6_client_status, .host = host};
  const auto result =
      impl_->parallel() ? impl_->execute_forward(command)
                        : Impl::apply_forward_command(impl_.get(), 0U, command);
  return result.success ? std::optional<std::size_t>{result.value}
                        : std::nullopt;
}

bool NetworkPlane::configure_host_dns_resolver(
    const HostDnsResolverProgram &program) noexcept {
  if (!program.host || program.root_hints.empty() ||
      program.root_hints.size() > std::numeric_limits<std::uint32_t>::max() ||
      program.trust_anchors.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  if (!execute({.kind = ForwardCommandKind::begin_host_dns_resolver,
                .fib = DnsResolverBegin{
                    .identifier_secret = program.identifier_secret,
                    .expected_root_hints =
                        static_cast<std::uint32_t>(program.root_hints.size()),
                    .expected_trust_anchors = static_cast<std::uint32_t>(
                        program.trust_anchors.size()),
                    .maximum_nsec3_iterations = program.nsec3_policy.maximum,
                    .serve_clients = program.serve_clients}}))
    return false;
  for (const auto &hint : program.root_hints) {
    if (hint.addresses.empty() ||
        hint.addresses.size() > std::numeric_limits<std::uint32_t>::max() ||
        !execute({.kind = ForwardCommandKind::begin_host_dns_root_hint,
                  .fib = DnsRootHintBegin{
                      .server_name = hint.server_name,
                      .expected_addresses =
                          static_cast<std::uint32_t>(hint.addresses.size())}}))
      goto abort_resolver;
    for (const auto &address : hint.addresses)
      if (!execute({.kind = ForwardCommandKind::add_host_dns_root_address,
                    .fib = address}))
        goto abort_resolver;
    if (!execute({.kind = ForwardCommandKind::commit_host_dns_root_hint}))
      goto abort_resolver;
  }
  for (const auto &anchor : program.trust_anchors) {
    if (anchor.type != packet::dns::type_dnskey || anchor.record_class == 0U ||
        anchor.rdata.empty() ||
        anchor.rdata.size() > std::numeric_limits<std::uint16_t>::max() ||
        !execute({.kind = ForwardCommandKind::begin_host_dns_trust_anchor,
                  .fib = DnsTrustAnchorBegin{
                      .owner = anchor.owner,
                      .ttl = anchor.ttl,
                      .expected_rdata_octets =
                          static_cast<std::uint32_t>(anchor.rdata.size()),
                      .record_class = anchor.record_class}}))
      goto abort_resolver;
    std::size_t offset{};
    while (offset < anchor.rdata.size()) {
      DnsRdataChunk chunk;
      chunk.size = static_cast<std::uint16_t>(
          std::min(chunk.octets.size(), anchor.rdata.size() - offset));
      std::copy_n(anchor.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                  chunk.size, chunk.octets.begin());
      if (!execute({.kind = ForwardCommandKind::add_host_dns_trust_anchor_rdata,
                    .fib = chunk}))
        goto abort_resolver;
      offset += chunk.size;
    }
    if (!execute({.kind = ForwardCommandKind::commit_host_dns_trust_anchor}))
      goto abort_resolver;
  }
  if (execute({.kind = ForwardCommandKind::commit_host_dns_resolver}))
    return true;
abort_resolver:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dns_resolver}));
  return false;
}

bool NetworkPlane::remove_host_dns_resolver(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dns_resolver, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_host_dns_authoritative(
    const HostDnsAuthoritativeProgram &program) noexcept {
  if (!program.host || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max())
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  if (!execute({.kind = ForwardCommandKind::begin_host_dns_authoritative,
                .fib = DnsAuthoritativeBegin{
                    .expected_zones =
                        static_cast<std::uint32_t>(program.zones.size())}}))
    return false;
  for (const auto &zone : program.zones) {
    if (zone.records.empty() ||
        zone.records.size() > std::numeric_limits<std::uint32_t>::max() ||
        !execute(
            {.kind = ForwardCommandKind::begin_host_dns_zone,
             .fib = DnsZoneBegin{.origin = zone.origin,
                                 .expected_records = static_cast<std::uint32_t>(
                                     zone.records.size())}}))
      goto abort_authoritative;
    for (const auto &record : zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max() ||
          !execute({.kind = ForwardCommandKind::begin_host_dns_record,
                    .fib = DnsRecordBegin{
                        .owner = record.owner,
                        .ttl = record.ttl,
                        .expected_rdata_octets =
                            static_cast<std::uint32_t>(record.rdata.size()),
                        .type = record.type,
                        .record_class = record.record_class}}))
        goto abort_authoritative;
      for (std::size_t offset = 0U; offset < record.rdata.size();
           offset += dns_program_chunk_octets) {
        DnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        if (!execute(
                {.kind = ForwardCommandKind::add_host_dns_rdata, .fib = chunk}))
          goto abort_authoritative;
      }
      if (!execute({.kind = ForwardCommandKind::commit_host_dns_record}))
        goto abort_authoritative;
    }
    if (!execute({.kind = ForwardCommandKind::commit_host_dns_zone}))
      goto abort_authoritative;
  }
  if (execute({.kind = ForwardCommandKind::commit_host_dns_authoritative}))
    return true;
abort_authoritative:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dns_authoritative}));
  return false;
}

bool NetworkPlane::configure_host_dns_signed_authoritative(
    const HostDnsSignedAuthoritativeProgram &program) noexcept {
  if (!program.host || !program.wall_now || program.zones.empty() ||
      program.zones.size() > std::numeric_limits<std::uint32_t>::max() ||
      !impl_->signing_vault_initialized)
    return false;
  const auto execute = [&](ForwardCommand command) noexcept {
    command.host = program.host;
    command.operation_now = Clock::now();
    return impl_->parallel()
               ? impl_->execute_forward(command).success
               : Impl::apply_forward_command(impl_.get(), 0U, command).success;
  };
  if (!execute({.kind = ForwardCommandKind::begin_host_dns_signed_authoritative,
                .fib = DnsAuthoritativeBegin{
                    .expected_zones =
                        static_cast<std::uint32_t>(program.zones.size()),
                    .wall_now = program.wall_now}}))
    return false;
  for (const auto &zone : program.zones) {
    if (zone.zone.records.empty() || zone.keys.empty() ||
        zone.zone.records.size() > std::numeric_limits<std::uint32_t>::max() ||
        zone.keys.size() > std::numeric_limits<std::uint32_t>::max() ||
        !dnssec::valid_managed_zone_policy(zone.policy) ||
        !execute({.kind = ForwardCommandKind::begin_host_dns_signed_zone,
                  .fib = DnsSignedZoneBegin{
                      .origin = zone.zone.origin,
                      .policy = zone.policy,
                      .expected_records =
                          static_cast<std::uint32_t>(zone.zone.records.size()),
                      .expected_keys =
                          static_cast<std::uint32_t>(zone.keys.size())}}))
      goto abort_signed_authoritative;
    for (const auto &key : zone.keys) {
      if (!dnssec::valid_schedule(key.schedule) || !key.algorithm ||
          !execute(
              {.kind = ForwardCommandKind::add_host_dns_signing_key,
               .fib = DnsSigningKeyDefinition{.schedule = key.schedule,
                                              .generation = key.generation,
                                              .role = key.role,
                                              .algorithm = key.algorithm}}))
        goto abort_signed_authoritative;
    }
    for (const auto &record : zone.zone.records) {
      if (record.rdata.size() > std::numeric_limits<std::uint16_t>::max() ||
          !execute({.kind = ForwardCommandKind::begin_host_dns_record,
                    .fib = DnsRecordBegin{
                        .owner = record.owner,
                        .ttl = record.ttl,
                        .expected_rdata_octets =
                            static_cast<std::uint32_t>(record.rdata.size()),
                        .type = record.type,
                        .record_class = record.record_class}}))
        goto abort_signed_authoritative;
      for (std::size_t offset = 0U; offset < record.rdata.size();
           offset += dns_program_chunk_octets) {
        DnsRdataChunk chunk;
        chunk.size = static_cast<std::uint16_t>(std::min<std::size_t>(
            chunk.octets.size(), record.rdata.size() - offset));
        std::copy_n(record.rdata.begin() + static_cast<std::ptrdiff_t>(offset),
                    chunk.size, chunk.octets.begin());
        if (!execute(
                {.kind = ForwardCommandKind::add_host_dns_rdata, .fib = chunk}))
          goto abort_signed_authoritative;
      }
      if (!execute({.kind = ForwardCommandKind::commit_host_dns_record}))
        goto abort_signed_authoritative;
    }
    if (!execute({.kind = ForwardCommandKind::commit_host_dns_zone}))
      goto abort_signed_authoritative;
  }
  if (execute({.kind = ForwardCommandKind::commit_host_dns_authoritative}))
    return true;
abort_signed_authoritative:
  static_cast<void>(
      execute({.kind = ForwardCommandKind::abort_host_dns_authoritative}));
  return false;
}

bool NetworkPlane::remove_host_dns_authoritative(HostHandle host) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::remove_host_dns_authoritative, .host = host};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

std::optional<dns::TransactionHandle>
NetworkPlane::start_host_dns_query(HostHandle host,
                                   const packet::dns::Question &question,
                                   Clock::time_point now) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::start_host_dns_query,
      .host = host,
      .fib = DnsTransactionCommand{.question = question, .transaction = {}},
      .operation_now = now};
  const auto result =
      impl_->parallel() ? impl_->execute_forward(command)
                        : Impl::apply_forward_command(impl_.get(), 0U, command);
  return result.success
             ? std::optional<dns::TransactionHandle>{dns::TransactionHandle{
                   .index = static_cast<std::uint32_t>(result.value),
                   .generation =
                       static_cast<std::uint32_t>(result.value >> 32U)}}
             : std::nullopt;
}

std::optional<dns::ResolutionResult>
NetworkPlane::host_dns_result(HostHandle host,
                              dns::TransactionHandle transaction) {
  if (!impl_->pause_forwarding())
    return std::nullopt;
  struct Resume final {
    Impl *owner;
    ~Resume() { owner->resume_forwarding(); }
  } resume{impl_.get()};
  const auto *slot = impl_->host(host);
  return slot && slot->dns ? slot->dns->result(transaction) : std::nullopt;
}

bool NetworkPlane::release_host_dns_query(
    HostHandle host, dns::TransactionHandle transaction) noexcept {
  const ForwardCommand command{
      .kind = ForwardCommandKind::release_host_dns_query,
      .host = host,
      .fib = DnsTransactionCommand{.question = {}, .transaction = transaction}};
  return impl_->parallel()
             ? impl_->execute_forward(command).success
             : Impl::apply_forward_command(impl_.get(), 0U, command).success;
}

bool NetworkPlane::configure_link(const NetworkLinkProgram &program) noexcept {
  if (!program.link || !program.first || !program.second ||
      program.first == program.second ||
      program.link.index >= impl_->links.size())
    return false;
  const auto live_node = [&](NodeHandle value) {
    switch (value.kind) {
    case NodeKind::router:
      return impl_->live(DeviceHandle{value.index, value.generation});
    case NodeKind::host:
      return impl_->live(HostHandle{value.index, value.generation});
    case NodeKind::ethernet_switch:
      return impl_->live(SwitchHandle{value.index, value.generation});
    }
    return false;
  };
  if (!live_node(program.first.node) || !live_node(program.second.node))
    return false;
  auto *first_binding = impl_->binding(program.first);
  auto *second_binding = impl_->binding(program.second);
  if (!first_binding || !second_binding)
    return false;
  // A physical port belongs to one point-to-point link. Accepting the current
  // link permits an atomic property update, but a different live link is an
  // ownership conflict and must be rejected before the fabric is touched.
  if ((first_binding->link && first_binding->link != program.link) ||
      (second_binding->link && second_binding->link != program.link))
    return false;
  if (impl_->links[program.link.index] == program.link &&
      impl_->endpoints[program.link.index] !=
          std::array<PortHandle, 2>{program.first, program.second})
    return false;

  struct SwitchSignalChange {
    SwitchHandle handle{};
    std::uint16_t port{};
    SwitchPortConfiguration previous{};
    bool applied{};
  };
  std::array<SwitchSignalChange, 2> switch_changes{};
  std::size_t switch_change_count{};
  for (const auto endpoint : {program.first, program.second}) {
    if (endpoint.node.kind != NodeKind::ethernet_switch)
      continue;
    const SwitchHandle handle{endpoint.node.index, endpoint.node.generation};
    auto *slot = impl_->ethernet_switch(handle);
    if (!slot || endpoint.ordinal >= slot->profile->port_count)
      return false;
    const auto configuration =
        slot->forwarding->port_configuration(endpoint.ordinal);
    // Full-duplex link serialization and bridge port transmission must use
    // one physical rate. Rejecting disagreement here prevents a control bug
    // from creating two contradictory clocks for the same cable.
    if (!configuration ||
        static_cast<std::uint64_t>(configuration->speed_mbps) * 1'000'000ULL !=
            program.bits_per_second)
      return false;
    switch_changes[switch_change_count++] = {
        handle, endpoint.ordinal, *configuration, false};
  }

  struct HostSignalChange {
    HostHandle host{};
    bool previous{};
    bool applied{};
  };
  std::array<HostSignalChange, 2> host_changes{};
  std::size_t host_change_count{};
  struct ManagementSignalChange {
    DeviceHandle device{};
    bool previous{};
    bool applied{};
  };
  std::array<ManagementSignalChange, 2> management_changes{};
  std::size_t management_change_count{};
  const auto set_local_host_signal = [&](HostHandle handle, bool value) {
    auto *host = impl_->host(handle);
    if (!host)
      return false;
    host->link_signal = value;
    host->stack.set_link_state(value);
    return true;
  };
  for (const auto endpoint : {program.first, program.second}) {
    if (endpoint.node.kind != NodeKind::host)
      continue;
    auto &change = host_changes[host_change_count++];
    change.host = {endpoint.node.index, endpoint.node.generation};
    if (impl_->parallel()) {
      const auto status = impl_->execute_forward(
          {.kind = ForwardCommandKind::host_link_status, .host = change.host});
      if (!status.success)
        return false;
      change.previous = status.value != 0;
    } else {
      const auto *host = impl_->host(change.host);
      if (!host)
        return false;
      change.previous = host->link_signal;
    }
  }
  for (const auto endpoint : {program.first, program.second}) {
    if (endpoint.node.kind != NodeKind::router ||
        endpoint.ordinal != device_catalog::management_port_ordinal)
      continue;
    auto &change = management_changes[management_change_count++];
    change.device = {endpoint.node.index, endpoint.node.generation};
    if (impl_->parallel()) {
      const auto status = impl_->execute_forward(
          {.kind = ForwardCommandKind::router_bof_link_status,
           .device = change.device,
           .port = {.ordinal = device_catalog::management_port_ordinal}});
      if (!status.success)
        return false;
      change.previous = status.value != 0U;
    } else {
      const auto *router = impl_->router(change.device);
      if (!router)
        return false;
      change.previous =
          impl_->routers[change.device.index].management_link_signal;
    }
  }
  const auto rollback_host_signals = [&] {
    // Reverse order mirrors a small transaction log. Each target was validated
    // before the first mutation, so rollback cannot address a stale handle.
    for (std::size_t index = host_change_count; index > 0; --index) {
      const auto &change = host_changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(
            impl_->execute_forward({.kind = ForwardCommandKind::set_host_link,
                                    .host = change.host,
                                    .flag = change.previous}));
      else
        static_cast<void>(set_local_host_signal(change.host, change.previous));
    }
  };
  const auto rollback_management_signals = [&] {
    for (std::size_t index = management_change_count; index > 0U; --index) {
      const auto &change = management_changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(impl_->execute_forward(
            {.kind = ForwardCommandKind::set_router_bof_link,
             .device = change.device,
             .port = {.ordinal = device_catalog::management_port_ordinal},
             .flag = change.previous}));
      else {
        auto &slot = impl_->routers[change.device.index];
        slot.management_link_signal = change.previous;
        if (slot.management_stack)
          slot.management_stack->set_link_state(change.previous);
      }
    }
  };
  const auto rollback_switch_signals = [&] {
    for (std::size_t index = switch_change_count; index > 0; --index) {
      const auto &change = switch_changes[index - 1U];
      if (!change.applied)
        continue;
      if (auto *slot = impl_->ethernet_switch(change.handle))
        static_cast<void>(slot->forwarding->configure_port(
            change.port, change.previous));
    }
  };
  for (std::size_t index = 0; index < host_change_count; ++index) {
    auto &change = host_changes[index];
    const bool changed =
        impl_->parallel()
            ? impl_
                  ->execute_forward({.kind = ForwardCommandKind::set_host_link,
                                     .host = change.host,
                                     .flag = program.carrier})
                  .success
            : set_local_host_signal(change.host, program.carrier);
    if (!changed) {
      rollback_host_signals();
      return false;
    }
    change.applied = true;
  }
  for (std::size_t index = 0; index < management_change_count; ++index) {
    auto &change = management_changes[index];
    bool changed{};
    if (impl_->parallel())
      changed =
          impl_
              ->execute_forward(
                  {.kind = ForwardCommandKind::set_router_bof_link,
                   .device = change.device,
                   .port = {
                       .ordinal = device_catalog::management_port_ordinal},
                   .flag = program.carrier})
              .success;
    else {
      auto &slot = impl_->routers[change.device.index];
      slot.management_link_signal = program.carrier;
      if (slot.management_stack)
        slot.management_stack->set_link_state(program.carrier);
      changed = true;
    }
    if (!changed) {
      rollback_management_signals();
      rollback_host_signals();
      return false;
    }
    change.applied = true;
  }
  for (std::size_t index{}; index < switch_change_count; ++index) {
    auto &change = switch_changes[index];
    auto *slot = impl_->ethernet_switch(change.handle);
    auto configured = change.previous;
    configured.carrier = program.carrier;
    if (!slot ||
        !slot->forwarding->configure_port(change.port, configured)) {
      rollback_switch_signals();
      rollback_management_signals();
      rollback_host_signals();
      return false;
    }
    change.applied = true;
  }

  // Reconfiguration drains the old generation inside the fabric before new
  // endpoint bindings become visible to packet-path lookup.
  if (!impl_->fabric->configure(program.link, program.first, program.second,
                                program.bits_per_second, program.propagation,
                                program.carrier)) {
    rollback_switch_signals();
    rollback_management_signals();
    rollback_host_signals();
    return false;
  }
  if (impl_->links[program.link.index] == program.link)
    for (const auto old_endpoint : impl_->endpoints[program.link.index])
      impl_->clear_binding(old_endpoint, program.link);
  impl_->links[program.link.index] = program.link;
  impl_->endpoints[program.link.index] = {program.first, program.second};
  *first_binding = {program.first, program.link, 0};
  *second_binding = {program.second, program.link, 1};
  return true;
}

bool NetworkPlane::remove_link(LinkHandle link) noexcept {
  if (!link || link.index >= impl_->links.size() ||
      impl_->links[link.index] != link)
    return false;
  struct HostSignalChange {
    HostHandle host{};
    bool previous{};
    bool applied{};
  };
  std::array<HostSignalChange, 2> changes{};
  std::size_t change_count{};
  struct ManagementSignalChange {
    DeviceHandle device{};
    bool previous{};
    bool applied{};
  };
  std::array<ManagementSignalChange, 2> management_changes{};
  std::size_t management_change_count{};
  struct SwitchSignalChange {
    SwitchHandle handle{};
    std::uint16_t port{};
    SwitchPortConfiguration previous{};
    bool applied{};
  };
  std::array<SwitchSignalChange, 2> switch_changes{};
  std::size_t switch_change_count{};
  const auto set_local_host_signal = [&](HostHandle handle, bool value) {
    auto *host = impl_->host(handle);
    if (!host)
      return false;
    host->link_signal = value;
    host->stack.set_link_state(value);
    return true;
  };
  for (const auto endpoint : impl_->endpoints[link.index]) {
    if (endpoint.node.kind != NodeKind::host)
      continue;
    auto &change = changes[change_count++];
    change.host = {endpoint.node.index, endpoint.node.generation};
    if (impl_->parallel()) {
      const auto status = impl_->execute_forward(
          {.kind = ForwardCommandKind::host_link_status, .host = change.host});
      if (!status.success)
        return false;
      change.previous = status.value != 0;
    } else {
      const auto *host = impl_->host(change.host);
      if (!host)
        return false;
      change.previous = host->link_signal;
    }
  }
  for (const auto endpoint : impl_->endpoints[link.index]) {
    if (endpoint.node.kind != NodeKind::router ||
        endpoint.ordinal != device_catalog::management_port_ordinal)
      continue;
    auto &change = management_changes[management_change_count++];
    change.device = {endpoint.node.index, endpoint.node.generation};
    if (impl_->parallel()) {
      const auto status = impl_->execute_forward(
          {.kind = ForwardCommandKind::router_bof_link_status,
           .device = change.device,
           .port = {.ordinal = device_catalog::management_port_ordinal}});
      if (!status.success)
        return false;
      change.previous = status.value != 0U;
    } else {
      if (!impl_->router(change.device))
        return false;
      change.previous =
          impl_->routers[change.device.index].management_link_signal;
    }
  }
  for (const auto endpoint : impl_->endpoints[link.index]) {
    if (endpoint.node.kind != NodeKind::ethernet_switch)
      continue;
    const SwitchHandle handle{endpoint.node.index, endpoint.node.generation};
    auto *slot = impl_->ethernet_switch(handle);
    const auto configuration =
        slot ? slot->forwarding->port_configuration(endpoint.ordinal)
             : std::nullopt;
    if (!configuration)
      return false;
    switch_changes[switch_change_count++] = {
        handle, endpoint.ordinal, *configuration, false};
  }
  const auto rollback = [&] {
    for (std::size_t index = switch_change_count; index > 0; --index) {
      const auto &change = switch_changes[index - 1U];
      if (!change.applied)
        continue;
      if (auto *slot = impl_->ethernet_switch(change.handle))
        static_cast<void>(slot->forwarding->configure_port(
            change.port, change.previous));
    }
    for (std::size_t index = change_count; index > 0; --index) {
      const auto &change = changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(
            impl_->execute_forward({.kind = ForwardCommandKind::set_host_link,
                                    .host = change.host,
                                    .flag = change.previous}));
      else
        static_cast<void>(set_local_host_signal(change.host, change.previous));
    }
    for (std::size_t index = management_change_count; index > 0U; --index) {
      const auto &change = management_changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(impl_->execute_forward(
            {.kind = ForwardCommandKind::set_router_bof_link,
             .device = change.device,
             .port = {.ordinal = device_catalog::management_port_ordinal},
             .flag = change.previous}));
      else {
        auto &slot = impl_->routers[change.device.index];
        slot.management_link_signal = change.previous;
        if (slot.management_stack)
          slot.management_stack->set_link_state(change.previous);
      }
    }
  };
  for (std::size_t index = 0; index < change_count; ++index) {
    auto &change = changes[index];
    const bool cleared =
        impl_->parallel()
            ? impl_
                  ->execute_forward({.kind = ForwardCommandKind::set_host_link,
                                     .host = change.host,
                                     .flag = false})
                  .success
            : set_local_host_signal(change.host, false);
    if (!cleared) {
      rollback();
      return false;
    }
    change.applied = true;
  }
  for (std::size_t index = 0; index < management_change_count; ++index) {
    auto &change = management_changes[index];
    bool cleared{};
    if (impl_->parallel())
      cleared =
          impl_
              ->execute_forward(
                  {.kind = ForwardCommandKind::set_router_bof_link,
                   .device = change.device,
                   .port = {
                       .ordinal = device_catalog::management_port_ordinal},
                   .flag = false})
              .success;
    else {
      auto &slot = impl_->routers[change.device.index];
      slot.management_link_signal = false;
      if (slot.management_stack)
        slot.management_stack->set_link_state(false);
      cleared = true;
    }
    if (!cleared) {
      rollback();
      return false;
    }
    change.applied = true;
  }
  for (std::size_t index{}; index < switch_change_count; ++index) {
    auto &change = switch_changes[index];
    auto *slot = impl_->ethernet_switch(change.handle);
    auto configured = change.previous;
    configured.carrier = false;
    if (!slot ||
        !slot->forwarding->configure_port(change.port, configured)) {
      rollback();
      return false;
    }
    change.applied = true;
  }
  if (!impl_->fabric->remove(link)) {
    rollback();
    return false;
  }
  // No fallible operation remains after medium removal. Clearing constant-time
  // lookup and capture bindings completes the owner-local transaction.
  for (const auto endpoint : impl_->endpoints[link.index])
    impl_->clear_binding(endpoint, link);
  for (auto &binding : impl_->link_captures[link.index])
    if (binding.active && binding.link == link)
      impl_->deactivate_capture(binding);
  impl_->links[link.index].reset();
  impl_->endpoints[link.index] = {};
  return true;
}

bool NetworkPlane::configure_capture_point(
    const CapturePointProgram &program) noexcept {
  if (program.kind < CapturePointKind::link_direction ||
      program.kind > CapturePointKind::cpm_punt)
    return false;
  if (!program.selected) {
    // Encoded historic blocks remain self-describing in the byte stream, while
    // live point metadata is retired with the packet-path binding. Repeating
    // removal of an unknown point is not success.
    const auto removed = impl_->capture->deactivate_point(program.id);
    impl_->clear_capture_id(program.id);
    return removed;
  }
  if (!program.name_size || program.name_size > program.name.size())
    return false;

  Impl::CaptureBinding *target{};
  if (program.kind == CapturePointKind::link_direction) {
    if (!program.link || program.link.index >= impl_->links.size() ||
        impl_->links[program.link.index] != program.link ||
        program.link_endpoint > 1U)
      return false;
    target = &impl_->link_captures[program.link.index][program.link_endpoint];
  } else {
    if (program.node.kind != NodeKind::router ||
        !impl_->live(DeviceHandle{program.node.index, program.node.generation}))
      return false;
    if (program.kind == CapturePointKind::cpm_punt) {
      target = &impl_->cpm_captures[program.node.index];
    } else {
      if (program.port_ordinal >= device_catalog::maximum_ports_per_router)
        return false;
      target = program.kind == CapturePointKind::router_ingress
                   ? &impl_->ingress_captures[program.node.index]
                                             [program.port_ordinal]
                   : &impl_->egress_captures[program.node.index]
                                            [program.port_ordinal];
    }
  }

  const std::string_view name{program.name.data(), program.name_size};
  if (!impl_->capture->configure_point(program.id, name))
    return false;
  // One stable capture identity observes one location at a time. Moving it is
  // atomic on this owner and does not remove older records carrying the ID.
  impl_->clear_capture_id(program.id);
  if (target->active && target->id != program.id)
    impl_->deactivate_capture(*target);
  *target = {.active = true,
             .id = program.id,
             .node = program.node,
             .link = program.link};
  return true;
}

void NetworkPlane::prepare_capture() { impl_->capture->encode(); }

bool NetworkPlane::clear_capture() noexcept {
  // The same forwarding owner that records packets rotates the section. No
  // packet can interleave between reset and the new Section Header Block.
  if (!impl_->capture->clear_session())
    return false;
  impl_->capture_dropped = 0;
  return true;
}

std::span<const std::uint8_t> NetworkPlane::prepared_capture() const noexcept {
  return impl_->capture->prepared();
}

std::size_t NetworkPlane::captured_frames() const noexcept {
  return impl_->capture->size();
}

std::uint64_t NetworkPlane::capture_dropped() const noexcept {
  return impl_->capture_dropped;
}

std::optional<NetworkPlaneCheckpoint>
NetworkPlane::checkpoint(Clock::time_point now) {
  if (!impl_->pause_forwarding())
    return std::nullopt;
  struct Resume final {
    Impl *owner;
    ~Resume() { owner->resume_forwarding(); }
  } resume{impl_.get()};
  NetworkPlaneCheckpoint state;
  const auto ospf_result = impl_->execute_ospf(
      {.checkpoint_transfer =
           reinterpret_cast<std::uintptr_t>(&state.ospf),
       .operation_now_nanoseconds =
           std::chrono::duration_cast<std::chrono::nanoseconds>(
               now.time_since_epoch())
               .count(),
               .kind = ospf::ControlCommandKind::checkpoint});
  if (!ospf_result.success)
    return std::nullopt;
  for (std::size_t index = 0; index < impl_->routers.size(); ++index) {
    const auto &slot = impl_->routers[index];
    if (!slot.forwarder)
      continue;
    NetworkRouterCheckpoint router;
    router.device = {static_cast<std::uint16_t>(index), slot.generation};
    router.forwarding = slot.forwarder->checkpoint(now);
    router.management_configured = slot.management_configured;
    router.management_link_signal = slot.management_link_signal;
    if (slot.management_stack) {
      router.management_endpoint.emplace();
      slot.management_stack->checkpoint(*router.management_endpoint, now);
      router.management_mac = slot.management_stack->mac();
      router.management_address = slot.management_stack->address();
      router.management_gateway = slot.management_stack->gateway();
      router.management_prefix_length =
          slot.management_stack->prefix_length();
      router.management_mtu = slot.management_stack->mtu();
      router.management_interface_id =
          slot.management_stack->interface_id();
      router.management_ipv6_autoconfiguration =
          slot.management_stack->ipv6_enabled();
    }
    if (slot.bof_dhcpv4)
      router.bof_dhcpv4 = slot.bof_dhcpv4->checkpoint(now);
    if (slot.bof_dhcpv6)
      router.bof_dhcpv6 = slot.bof_dhcpv6->checkpoint(now);
    router.bof_dhcpv4_timeout_remaining_nanoseconds =
        relative_runtime_deadline<Clock>(slot.bof_dhcpv4_timeout, now);
    router.bof_dhcpv6_timeout_remaining_nanoseconds =
        relative_runtime_deadline<Clock>(slot.bof_dhcpv6_timeout, now);
    state.routers.push_back(std::move(router));
  }
  for (std::size_t index = 0; index < impl_->hosts.size(); ++index) {
    const auto &slot = impl_->hosts[index];
    if (!slot.generation)
      continue;
    NetworkHostCheckpoint host;
    host.host = {static_cast<std::uint16_t>(index), slot.generation};
    // An unconfigured host owns no transport entropy or protocol state. Its
    // HostSlot identity and link signal are sufficient for a later user
    // configuration, and serializing the deliberately invalid all-zero TCP
    // bootstrap key would create an unrestorable checkpoint.
    if (slot.configured)
      slot.stack.checkpoint(host.endpoint, now);
    host.mac = slot.stack.mac();
    host.address = slot.stack.address();
    host.gateway = slot.stack.gateway();
    host.prefix_length = slot.stack.prefix_length();
    host.mtu = slot.stack.mtu();
    host.interface_id = slot.stack.interface_id();
    host.expected_sequence = slot.expected_sequence;
    host.configured = slot.configured;
    host.link_signal = slot.link_signal;
    host.ping_pending = slot.ping_pending;
    host.ping_reply = slot.ping_reply;
    host.ping_sent_elapsed_nanoseconds =
        slot.ping_clock_started && now >= slot.ping_sent_at
            ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                  now - slot.ping_sent_at)
                  .count()
            : -1;
    host.ping_reply_rtt_nanoseconds = static_cast<std::uint64_t>(
        std::max<std::int64_t>(0, slot.ping_reply_rtt.count()));
    host.ping_reply_ttl = slot.ping_reply_ttl;
    host.ipv6_autoconfiguration = slot.stack.ipv6_enabled();
    if (slot.dhcpv4)
      host.dhcpv4 = slot.dhcpv4->checkpoint(now);
    if (slot.dhcpv6)
      host.dhcpv6 = slot.dhcpv6->checkpoint(now);
    if (slot.dns) {
      auto dns = slot.dns->checkpoint(now);
      if (!dns)
        return std::nullopt;
      host.dns = std::move(*dns);
    }
    state.hosts.push_back(std::move(host));
  }
  for (std::size_t index{}; index < impl_->switches.size(); ++index) {
    const auto &slot = impl_->switches[index];
    if (!slot.forwarding)
      continue;
    state.switches.push_back(
        {.handle = {static_cast<std::uint16_t>(index), slot.generation},
         .profile_index = slot.profile_index,
         .forwarding = slot.forwarding->checkpoint(now)});
  }
  state.fabric = impl_->fabric->checkpoint(now);
  state.capture = impl_->capture->checkpoint();
  const auto append_capture = [&](const Impl::CaptureBinding &binding,
                                  CapturePointKind kind, LinkHandle link,
                                  NodeHandle node_handle, std::uint16_t ordinal,
                                  std::uint8_t endpoint) {
    if (!binding.active)
      return;
    const auto point = std::find_if(
        state.capture.points.begin(), state.capture.points.end(),
        [&](const auto &candidate) { return candidate.id == binding.id; });
    if (point == state.capture.points.end())
      return;
    CapturePointProgram program;
    program.id = binding.id;
    program.kind = kind;
    program.link = link;
    program.node = node_handle;
    program.port_ordinal = ordinal;
    program.link_endpoint = endpoint;
    program.selected = true;
    program.name_size = static_cast<std::uint16_t>(point->name.size());
    std::copy(point->name.begin(), point->name.end(), program.name.begin());
    state.capture_points.push_back(program);
  };
  for (std::size_t link = 0; link < impl_->link_captures.size(); ++link)
    for (std::uint8_t endpoint = 0; endpoint < 2U; ++endpoint)
      append_capture(impl_->link_captures[link][endpoint],
                     CapturePointKind::link_direction,
                     impl_->links[link].value_or(LinkHandle{}), {}, 0xffffU,
                     endpoint);
  for (std::size_t router = 0; router < impl_->routers.size(); ++router) {
    const NodeHandle owner{NodeKind::router, static_cast<std::uint16_t>(router),
                           impl_->routers[router].generation};
    for (std::size_t port = 0; port < impl_->ingress_captures[router].size();
         ++port) {
      append_capture(impl_->ingress_captures[router][port],
                     CapturePointKind::router_ingress, {}, owner,
                     static_cast<std::uint16_t>(port), 0);
      append_capture(impl_->egress_captures[router][port],
                     CapturePointKind::router_egress, {}, owner,
                     static_cast<std::uint16_t>(port), 0);
    }
    append_capture(impl_->cpm_captures[router], CapturePointKind::cpm_punt, {},
                   owner, 0xffffU, 0);
  }
  state.capture_dropped = impl_->capture_dropped;
  state.ingress_ring_dropped = impl_->ingress_ring_dropped;
  state.egress_ring_dropped =
      impl_->egress_ring_dropped.load(std::memory_order_relaxed);
  state.missing_binding_dropped = impl_->missing_binding_dropped;
  return state;
}

std::optional<RouterForwarderCheckpoint>
NetworkPlane::router_checkpoint(DeviceHandle device, Clock::time_point now) {
  if (!impl_->pause_forwarding())
    return std::nullopt;
  struct Resume final {
    Impl *owner;
    ~Resume() { owner->resume_forwarding(); }
  } resume{impl_.get()};
  // The generation check lives in Impl::router, exactly like packet delivery.
  // A show command for a deleted router cannot sample a replacement that later
  // reused its compact slot.
  const auto *forwarder = impl_->router(device);
  if (!forwarder)
    return std::nullopt;
  return forwarder->checkpoint(now);
}

bool NetworkPlane::restore(const NetworkPlaneCheckpoint &state,
                           Clock::time_point now) {
  if (state.routers.size() > device_catalog::maximum_routers ||
      state.hosts.size() > device_catalog::maximum_hosts ||
      state.switches.size() > device_catalog::maximum_switches ||
      state.capture_points.size() >
          device_catalog::maximum_active_capture_points ||
      !MultiDeviceFabric::validate_checkpoint(state.fabric) ||
      !CaptureStore::validate_checkpoint(state.capture))
    return false;
  if (!impl_->pause_forwarding())
    return false;
  struct Resume final {
    Impl *owner;
    ~Resume() { owner->resume_forwarding(); }
  } resume{impl_.get()};
  std::array<bool, device_catalog::maximum_routers> router_seen{};
  std::array<bool, device_catalog::maximum_hosts> host_seen{};
  std::array<bool, device_catalog::maximum_switches> switch_seen{};
  std::vector<CapturePointId> capture_seen;
  capture_seen.reserve(state.capture_points.size());
  try {
    auto staged_routers = std::make_unique<decltype(impl_->routers)>();
    auto staged_route_managers =
        std::make_unique<decltype(impl_->route_managers)>();
    auto staged_hosts = std::make_unique<decltype(impl_->hosts)>();
    auto staged_switches = std::make_unique<decltype(impl_->switches)>();
    for (const auto &router : state.routers) {
      if (!router.device || router.device.index >= router_seen.size() ||
          router_seen[router.device.index] ||
          !RouterForwarder::validate_checkpoint(router.forwarding))
        return false;
      router_seen[router.device.index] = true;
      // RouterForwarder restore must begin with the exact persisted TCP ISN
      // identity. A default or shared secret would make sequence numbers
      // repeat across routers after restoring the same lab.
      if (!router.forwarding.tcp)
        return false;
      auto forwarder = std::make_unique<RouterForwarder>(
          router.forwarding.tcp->isn.secret, now);
      if (!forwarder->restore(router.forwarding, now))
        return false;
      // The RIB owner is reconstructed empty and receives canonical connected,
      // static and OSPF generations from RuntimeSupervisor immediately after
      // this forwarding checkpoint commits. Allocating its full route capacity
      // in staging keeps restore atomic on memory exhaustion.
      auto route_manager = std::make_unique<Impl::RouteManagerState>();
      // Forwarding generations are monotonic owner state. Although connected,
      // static and protocol RIB inputs are rebuilt by RuntimeSupervisor, their
      // next compiled generation must advance beyond the exact FIB restored
      // above. Persisting only this high-water mark avoids duplicating RIB
      // ownership in the checkpoint while preventing a valid reconstructed
      // program from being rejected as stale.
      route_manager->installed_ipv4_generation =
          router.forwarding.fib.generation;
      route_manager->installed_ipv6_generation =
          router.forwarding.ipv6_fib.generation;
      (*staged_route_managers)[router.device.index] =
          std::move(route_manager);
      auto &target = (*staged_routers)[router.device.index];
      target.generation = router.device.generation;
      target.forwarder = std::move(forwarder);
      if (router.management_configured !=
              router.management_endpoint.has_value() ||
          (!router.management_configured &&
           (router.bof_dhcpv4 || router.bof_dhcpv6 ||
            router.management_link_signal)))
        return false;
      if (router.management_configured) {
        if (router.management_prefix_length > 32U ||
            router.management_mtu < device_catalog::minimum_host_ipv4_mtu ||
            router.management_mtu > device_catalog::maximum_network_mtu ||
            !router.management_interface_id ||
            (router.management_ipv6_autoconfiguration &&
             router.management_mtu < packet::ipv6_minimum_link_mtu))
          return false;
        const auto &endpoint = *router.management_endpoint;
        const auto &saved_identifier = endpoint.ipv6.autoconfiguration;
        if (saved_identifier.network_id.size() >
            device_catalog::ipv6_stable_iid_network_id_octets)
          return false;
        host::Ipv6InterfaceIdentifierConfiguration identifier{
            .modified_eui64 = saved_identifier.interface_identifier,
            .stable_secret = saved_identifier.stable_secret,
            .network_id_octets =
                static_cast<std::uint8_t>(saved_identifier.network_id.size()),
            .mode = saved_identifier.interface_identifier_mode};
        std::copy(saved_identifier.network_id.begin(),
                  saved_identifier.network_id.end(),
                  identifier.network_id.begin());
        target.management_stack =
            std::make_unique<network_detail::EndpointStack>();
        if (!target.management_stack->configure(
                {.endpoint_mac = router.management_mac,
                 .endpoint_address = router.management_address,
                 .endpoint_prefix_length = router.management_prefix_length,
                 .endpoint_gateway = router.management_gateway,
                 .endpoint_mtu = router.management_mtu,
                 .endpoint_interface_id = router.management_interface_id,
                 .endpoint_ipv6_autoconfiguration =
                     router.management_ipv6_autoconfiguration,
                 .endpoint_ipv6_identifier = identifier,
                 .endpoint_transport_secret =
                     endpoint.tcp ? endpoint.tcp->isn.secret
                                  : crypto::Sha256Digest{}}))
          return false;
        target.management_stack->set_link_state(
            router.management_link_signal, now);
        if (!target.management_stack->restore(endpoint, now))
          return false;
        if (router.bof_dhcpv4) {
          target.bof_dhcpv4 =
              std::make_unique<network_detail::Dhcpv4EndpointService>();
          if (!target.bof_dhcpv4->restore(
                  *router.bof_dhcpv4, *target.management_stack, now))
            return false;
          if (router.bof_dhcpv4_timeout_remaining_nanoseconds < -1)
            return false;
          target.bof_dhcpv4_timeout = restore_runtime_deadline<Clock>(
              router.bof_dhcpv4_timeout_remaining_nanoseconds, now);
        }
        if (router.bof_dhcpv6) {
          target.bof_dhcpv6 =
              std::make_unique<network_detail::Dhcpv6EndpointService>();
          if (!target.bof_dhcpv6->restore(
                  *router.bof_dhcpv6, *target.management_stack, now))
            return false;
          if (router.bof_dhcpv6_timeout_remaining_nanoseconds < -1)
            return false;
          target.bof_dhcpv6_timeout = restore_runtime_deadline<Clock>(
              router.bof_dhcpv6_timeout_remaining_nanoseconds, now);
        }
        target.management_configured = true;
        target.management_link_signal = router.management_link_signal;
      }
      // Staging values represent incomplete external transactions and are
      // intentionally discarded. Only committed endpoint and DHCP owners are
      // restored, so a checkpoint can never replay half of a configuration.
    }
    for (const auto &host : state.hosts) {
      if (!host.host || host.host.index >= host_seen.size() ||
          host_seen[host.host.index])
        return false;
      host_seen[host.host.index] = true;
      auto &target = (*staged_hosts)[host.host.index];
      target.generation = host.host.generation;
      if (host.prefix_length > 32U ||
          host.mtu < device_catalog::minimum_host_ipv4_mtu ||
          host.mtu > device_catalog::maximum_network_mtu ||
          (host.ipv6_autoconfiguration &&
           (!host.interface_id || host.mtu < packet::ipv6_minimum_link_mtu)))
        return false;
      if (host.configured) {
        const auto &saved_identifier = host.endpoint.ipv6.autoconfiguration;
        if (saved_identifier.network_id.size() >
            device_catalog::ipv6_stable_iid_network_id_octets)
          return false;
        host::Ipv6InterfaceIdentifierConfiguration identifier{
            .modified_eui64 = saved_identifier.interface_identifier,
            .stable_secret = saved_identifier.stable_secret,
            .network_id_octets =
                static_cast<std::uint8_t>(saved_identifier.network_id.size()),
            .mode = saved_identifier.interface_identifier_mode};
        std::copy(saved_identifier.network_id.begin(),
                  saved_identifier.network_id.end(),
                  identifier.network_id.begin());
        if (!target.stack.configure(
                {.endpoint_mac = host.mac,
                 .endpoint_address = host.address,
                 .endpoint_prefix_length = host.prefix_length,
                 .endpoint_gateway = host.gateway,
                 .endpoint_mtu = host.mtu,
                 .endpoint_interface_id = host.interface_id,
                 .endpoint_ipv6_autoconfiguration = host.ipv6_autoconfiguration,
                 .endpoint_ipv6_identifier = identifier,
                 .endpoint_transport_secret =
                     host.endpoint.tcp ? host.endpoint.tcp->isn.secret
                                       : crypto::Sha256Digest{}}))
          return false;
        target.stack.set_link_state(host.link_signal, now);
        if (!target.stack.restore(host.endpoint, now))
          return false;
      } else {
        // Link carrier is retained below in HostSlot but is not delivered to
        // an endpoint without a configured MAC/IP identity. The exact empty
        // checkpoint check prevents a crafted project from hiding live
        // protocol state behind configured=false.
        if (!empty_unconfigured_host_checkpoint(host.endpoint) ||
            !std::all_of(host.mac.begin(), host.mac.end(),
                         [](const auto octet) { return octet == 0U; }) ||
            !std::all_of(host.address.begin(), host.address.end(),
                         [](const auto octet) { return octet == 0U; }) ||
            !std::all_of(host.gateway.begin(), host.gateway.end(),
                         [](const auto octet) { return octet == 0U; }) ||
            host.prefix_length != 0U ||
            host.mtu != device_catalog::default_host_ipv4_mtu ||
            host.interface_id != 0U || host.ipv6_autoconfiguration ||
            host.dhcpv4 || host.dhcpv6 || host.dns || host.ping_pending ||
            host.ping_reply || host.ping_sent_elapsed_nanoseconds != -1 ||
            host.ping_reply_rtt_nanoseconds != 0U ||
            host.ping_reply_ttl != 0U)
          return false;
      }
      if (host.dhcpv4) {
        if (!host.configured)
          return false;
        target.dhcpv4 =
            std::make_unique<network_detail::Dhcpv4EndpointService>();
        if (!target.dhcpv4->restore(*host.dhcpv4, target.stack, now))
          return false;
      }
      if (host.dhcpv6) {
        if (!host.configured)
          return false;
        target.dhcpv6 =
            std::make_unique<network_detail::Dhcpv6EndpointService>();
        if (!target.dhcpv6->restore(*host.dhcpv6, target.stack, now))
          return false;
      }
      if (host.dns) {
        if (!host.configured)
          return false;
        target.dns = std::make_unique<network_detail::DnsEndpointService>();
        if (!host.dns->signed_zones.empty() &&
            (!impl_->signing_vault_initialized ||
             !target.dns->initialize_signing_vault(
                 impl_->signing_wrapping_key, impl_->signing_context_digest)))
          return false;
        if (!target.dns->restore(*host.dns, target.stack, now))
          return false;
      }
      target.expected_sequence = host.expected_sequence;
      target.configured = host.configured;
      target.link_signal = host.link_signal;
      target.ping_pending = host.ping_pending;
      target.ping_reply = host.ping_reply;
      if (host.ping_sent_elapsed_nanoseconds < -1 ||
          host.ping_sent_elapsed_nanoseconds >
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  device_catalog::checkpoint_max_relative_deadline)
                  .count() ||
          host.ping_reply_rtt_nanoseconds >
              static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(
                      device_catalog::checkpoint_max_relative_deadline)
                      .count()) ||
          (host.ping_reply && host.ping_reply_ttl == 0U) ||
          (!host.ping_reply &&
           (host.ping_reply_rtt_nanoseconds != 0U ||
            host.ping_reply_ttl != 0U)) ||
          (!host.ping_pending && host.ping_sent_elapsed_nanoseconds >= 0))
        return false;
      target.ping_clock_started =
          host.ping_sent_elapsed_nanoseconds >= 0;
      if (target.ping_clock_started)
        target.ping_sent_at =
            now - std::chrono::nanoseconds{
                      host.ping_sent_elapsed_nanoseconds};
      target.ping_reply_rtt =
          std::chrono::nanoseconds{static_cast<std::int64_t>(
              host.ping_reply_rtt_nanoseconds)};
      target.ping_reply_ttl = host.ping_reply_ttl;
    }
    std::size_t switch_queued_frames{};
    for (const auto &saved : state.switches) {
      const auto *profile =
          device_catalog::ethernet_switch_profile(saved.profile_index);
      if (!saved.handle || saved.handle.index >= switch_seen.size() ||
          switch_seen[saved.handle.index] || !profile ||
          !EthernetSwitch::validate_checkpoint(*profile, saved.forwarding))
        return false;
      switch_seen[saved.handle.index] = true;
      switch_queued_frames += saved.forwarding.egress.size();
      auto &target = (*staged_switches)[saved.handle.index];
      target.generation = saved.handle.generation;
      target.profile_index = saved.profile_index;
      target.profile = profile;
      target.forwarding =
          std::make_unique<EthernetSwitch>(*profile,
                                           impl_->fabric->packet_pool());
    }
    std::size_t fabric_frames{};
    for (const auto &link : state.fabric.links)
      for (const auto &direction : link.directions)
        fabric_frames += direction.transmit.size() +
                         direction.in_flight.size() +
                         direction.receive.size();
    // Fabric and bridge queues share one generated packet arena. Independent
    // validation is insufficient because two individually valid domains could
    // exceed that common owner budget when restored together.
    if (fabric_frames + switch_queued_frames > PacketPool::capacity)
      return false;
    std::array<std::array<bool, device_catalog::maximum_ports_per_router>,
               device_catalog::maximum_routers>
        router_ports{};
    std::array<bool, device_catalog::maximum_hosts> host_ports{};
    std::array<std::array<bool, device_catalog::maximum_switch_ports>,
               device_catalog::maximum_switches>
        switch_ports{};
    for (const auto &link : state.fabric.links) {
      for (const auto port : link.endpoints) {
        if (port.node.kind == NodeKind::router) {
          if (port.node.index >= router_seen.size() ||
              !router_seen[port.node.index] ||
              (*staged_routers)[port.node.index].generation !=
                  port.node.generation ||
              port.ordinal >= device_catalog::maximum_ports_per_router ||
              router_ports[port.node.index][port.ordinal])
            return false;
          router_ports[port.node.index][port.ordinal] = true;
        } else if (port.node.kind == NodeKind::host) {
          if (port.node.index >= host_seen.size() ||
              !host_seen[port.node.index] ||
              (*staged_hosts)[port.node.index].generation !=
                  port.node.generation ||
              port.ordinal != 0U || host_ports[port.node.index])
            return false;
          host_ports[port.node.index] = true;
        } else if (port.node.kind == NodeKind::ethernet_switch) {
          if (port.node.index >= switch_seen.size() ||
              !switch_seen[port.node.index] ||
              (*staged_switches)[port.node.index].generation !=
                  port.node.generation ||
              port.ordinal >=
                  (*staged_switches)[port.node.index].profile->port_count ||
              switch_ports[port.node.index][port.ordinal])
            return false;
          const auto &saved =
              *std::find_if(state.switches.begin(), state.switches.end(),
                            [&](const auto &entry) {
                              return entry.handle.index == port.node.index;
                            });
          const auto &configuration =
              saved.forwarding.ports[port.ordinal].configuration;
          const auto &link_direction = link.directions[0];
          if (!saved.forwarding.ports[port.ordinal].configured ||
              configuration.carrier != link.carrier ||
              static_cast<std::uint64_t>(configuration.speed_mbps) *
                      1'000'000ULL !=
                  link_direction.bits_per_second)
            return false;
          switch_ports[port.node.index][port.ordinal] = true;
        } else {
          return false;
        }
      }
    }
    for (const auto &program : state.capture_points) {
      if (!program.selected ||
          std::find(capture_seen.begin(), capture_seen.end(), program.id) !=
              capture_seen.end() || !program.name_size ||
          program.name_size > program.name.size() ||
          program.kind < CapturePointKind::link_direction ||
          program.kind > CapturePointKind::cpm_punt)
        return false;
      capture_seen.push_back(program.id);
      const auto point = std::find_if(
          state.capture.points.begin(), state.capture.points.end(),
          [&](const auto &candidate) { return candidate.id == program.id; });
      if (point == state.capture.points.end() || !point->active ||
          point->name !=
              std::string_view(program.name.data(), program.name_size))
        return false;
      if (program.kind == CapturePointKind::link_direction) {
        if (!program.link ||
            program.link.index >= device_catalog::maximum_links ||
            program.link_endpoint > 1U ||
            std::none_of(
                state.fabric.links.begin(), state.fabric.links.end(),
                [&](const auto &link) { return link.link == program.link; }))
          return false;
      } else if (program.node.kind != NodeKind::router ||
                 program.node.index >= router_seen.size() ||
                 !router_seen[program.node.index] ||
                 (*staged_routers)[program.node.index].generation !=
                     program.node.generation ||
                 (program.kind != CapturePointKind::cpm_punt &&
                  program.port_ordinal >=
                      device_catalog::maximum_ports_per_router)) {
        return false;
      }
    }

    // The multicast-punt table is a forwarding projection of authoritative
    // OSPF interface configuration. It is intentionally absent from the
    // checkpoint because serializing the same fact under two owners would let
    // a project contain a protocol interface that its forwarding owner never
    // delivers, or a stale punt with no receiving protocol process. Rebuild
    // the projection while every replacement forwarder is still staged and
    // before any restored OSPF timer can emit its first Hello.
    //
    // Keep this generated-size table off the WebAssembly stack. A maximum-size
    // lab has one row per router and one byte per physical port; heap staging
    // also lets allocation failure preserve the currently running lab.
    auto restored_ospf_punt_masks =
        std::make_unique<decltype(impl_->ospf_punt_masks)>();
    constexpr std::uint8_t ospf_v2_presence = 1U << 0U;
    constexpr std::uint8_t ospf_v3_presence = 1U << 1U;
    for (const auto &saved_process : state.ospf.processes) {
      const auto device = saved_process.definition.process.device;
      const auto version = saved_process.definition.process.version;
      if (!device || device.index >= router_seen.size() ||
          !router_seen[device.index] ||
          (*staged_routers)[device.index].generation != device.generation ||
          (version != packet::ospf::version_two &&
           version != packet::ospf::version_three))
        return false;
      for (const auto &saved_interface : saved_process.process.interfaces) {
        const auto ordinal =
            saved_interface.configuration.physical_port_ordinal;
        const bool passive_without_port =
            saved_interface.configuration.protocol.passive &&
            ordinal == ospf::no_physical_port;
        if (passive_without_port)
          continue;
        if (ordinal >= device_catalog::maximum_ports_per_router)
          return false;
        // Multiple areas and both address families may refer to one physical
        // port. A bitwise union matches live generation programming and
        // prevents restoring one process from disabling another.
        (*restored_ospf_punt_masks)[device.index][ordinal] |=
            version == packet::ospf::version_two ? ospf_v2_presence
                                                 : ospf_v3_presence;
      }
    }

    // CaptureStore performs its own replacement-object staging and swaps only
    // after all allocations succeed. Fabric validation proves its fixed-pool
    // installation cannot fail, so no fallible operation follows that swap.
    // Keeping this ordering provides atomic failure without temporarily
    // allocating a second 64 MiB packet pool inside the shared Wasm budget.
    if (!impl_->capture->restore(state.capture))
      return false;
    // Destroy old bridge queues before fabric replacement so every reference
    // in the shared packet arena is returned exactly once.
    for (auto &slot : impl_->switches)
      slot = {};
    if (!impl_->fabric->restore(state.fabric, now))
      std::terminate();
    for (std::size_t index = 0; index < impl_->routers.size(); ++index)
      impl_->routers[index] = std::move((*staged_routers)[index]);
    for (std::size_t index = 0; index < impl_->route_managers.size(); ++index)
      impl_->route_managers[index] =
          std::move((*staged_route_managers)[index]);
    for (std::size_t index = 0; index < impl_->hosts.size(); ++index)
      impl_->hosts[index] = std::move((*staged_hosts)[index]);
    for (std::size_t index{}; index < impl_->switches.size(); ++index)
      impl_->switches[index] = std::move((*staged_switches)[index]);
    for (const auto &saved : state.switches)
      if (!impl_->switches[saved.handle.index].forwarding->restore(
              saved.forwarding, now))
        std::terminate();
    impl_->router_generations.fill(0);
    impl_->host_generations.fill(0);
    impl_->switch_generations.fill(0);
    for (const auto &router : state.routers)
      impl_->router_generations[router.device.index] = router.device.generation;
    for (const auto &host : state.hosts)
      impl_->host_generations[host.host.index] = host.host.generation;
    for (const auto &saved : state.switches)
      impl_->switch_generations[saved.handle.index] =
          saved.handle.generation;

    for (auto &link : impl_->links)
      link.reset();
    for (auto &endpoints : impl_->endpoints)
      endpoints = {};
    for (auto &router : impl_->router_bindings)
      for (auto &binding : router)
        binding = {};
    for (auto &binding : impl_->host_bindings)
      binding = {};
    for (auto &device : impl_->switch_bindings)
      for (auto &binding : device)
        binding = {};
    for (const auto &link : state.fabric.links) {
      impl_->links[link.link.index] = link.link;
      impl_->endpoints[link.link.index] = link.endpoints;
      for (std::uint8_t endpoint = 0; endpoint < 2U; ++endpoint) {
        auto *binding = impl_->binding(link.endpoints[endpoint]);
        if (!binding)
          return false;
        *binding = {link.endpoints[endpoint], link.link, endpoint};
      }
    }
    for (auto &link : impl_->link_captures)
      for (auto &binding : link)
        binding = {};
    for (auto *table : {&impl_->ingress_captures, &impl_->egress_captures})
      for (auto &router : *table)
        for (auto &binding : router)
          binding = {};
    for (auto &binding : impl_->cpm_captures)
      binding = {};
    for (const auto &program : state.capture_points) {
      Impl::CaptureBinding value{true, program.id, program.node, program.link};
      if (program.kind == CapturePointKind::link_direction)
        impl_->link_captures[program.link.index][program.link_endpoint] = value;
      else if (program.kind == CapturePointKind::router_ingress)
        impl_->ingress_captures[program.node.index][program.port_ordinal] =
            value;
      else if (program.kind == CapturePointKind::router_egress)
        impl_->egress_captures[program.node.index][program.port_ordinal] =
            value;
      else
        impl_->cpm_captures[program.node.index] = value;
    }
    impl_->capture_dropped = state.capture_dropped;
    impl_->ingress_ring_dropped = state.ingress_ring_dropped;
    impl_->egress_ring_dropped.store(state.egress_ring_dropped,
                                     std::memory_order_relaxed);
    impl_->missing_binding_dropped = state.missing_binding_dropped;
    impl_->now = now;
    // Fresh RouterForwarders deliberately restore only their owned packet
    // state, so their derived OSPF punt bits start clear. Forwarding remains
    // quiesced here. Program every non-empty projection directly before the
    // protocol worker is restored, ensuring even an immediately due Hello is
    // accepted by its peer instead of disappearing between owners.
    for (std::size_t device_index{};
         device_index < restored_ospf_punt_masks->size(); ++device_index) {
      auto *forwarder =
          impl_->routers[device_index].forwarder.get();
      for (std::size_t ordinal{};
           forwarder &&
           ordinal < (*restored_ospf_punt_masks)[device_index].size();
           ++ordinal) {
        const auto mask =
            (*restored_ospf_punt_masks)[device_index][ordinal];
        if (mask != 0U &&
            !forwarder->configure_ospf_punt(
                static_cast<std::uint16_t>(ordinal),
                (mask & ospf_v2_presence) != 0U,
                (mask & ospf_v3_presence) != 0U))
          std::terminate();
      }
    }
    impl_->ospf_punt_masks = std::move(*restored_ospf_punt_masks);

    // OSPF restoration is the final owner commit. Every forwarding, fabric,
    // capture and multicast-punt value has already passed validation, while
    // the protocol command reconstructs derived routes from its restored LSDB
    // before publishing success.
    const auto ospf_restore = impl_->execute_ospf(
        {.checkpoint_transfer = reinterpret_cast<std::uintptr_t>(
             const_cast<ospf::ControlWorkerCheckpoint *>(&state.ospf)),
         .operation_now_nanoseconds =
             std::chrono::duration_cast<std::chrono::nanoseconds>(
                 now.time_since_epoch())
                 .count(),
                 .kind = ospf::ControlCommandKind::restore_checkpoint});
    if (!ospf_restore.success)
      std::terminate();
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool NetworkPlane::start_router_ping(DeviceHandle device,
                                     std::uint32_t destination,
                                     std::uint16_t sequence,
                                     Clock::time_point now,
                                     std::uint16_t payload_octets,
                                     bool dont_fragment) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::router_ping,
                           .device = device,
                           .destination = destination,
                           .sequence = sequence,
                           .payload_octets = payload_octets,
                           .flag = dont_fragment})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  Impl::EgressContext context{impl_.get(), node(device), nullptr};
  return forwarder->originate_echo(destination, sequence, &context,
                                   Impl::egress, now, payload_octets,
                                   dont_fragment);
}

bool NetworkPlane::start_host_ping(HostHandle handle, packet::Ipv4 destination,
                                   std::uint16_t sequence) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::host_ping,
                           .host = handle,
                           .host_destination = destination,
                           .sequence = sequence})
        .success;
  auto *host = impl_->host(handle);
  if (!host || !host->configured || !host->link_signal)
    return false;
  host->expected_sequence = sequence;
  host->ping_pending = true;
  host->ping_reply = false;
  host->ping_clock_started = false;
  host->ping_reply_rtt = std::chrono::nanoseconds::zero();
  host->ping_reply_ttl = 0U;
  const auto started_at = Clock::now();
  const auto frames = host->stack.begin_echo(
      destination, sequence, device_catalog::default_ping_payload_octets,
      false, started_at);
  bool accepted = frames.count > 0;
  for (std::size_t index = 0; index < frames.count; ++index)
    accepted = impl_->send(node(handle), 0, frames.frames[index]) && accepted;
  if (!accepted)
    host->ping_pending = false;
  else if (frames.start_echo_clock) {
    host->ping_clock_started = true;
    host->ping_sent_at = started_at;
  }
  return accepted;
}

bool NetworkPlane::start_router_ipv6_ping(
    DeviceHandle device, const packet::Ipv6 &destination,
    std::uint16_t sequence, Clock::time_point now,
    std::uint16_t payload_octets) noexcept {
  if (impl_->parallel())
    return impl_
        ->execute_forward({.kind = ForwardCommandKind::router_ipv6_ping,
                           .device = device,
                           .ipv6_destination = destination,
                           .sequence = sequence,
                           .payload_octets = payload_octets})
        .success;
  auto *forwarder = impl_->router(device);
  if (!forwarder)
    return false;
  Impl::EgressContext context{impl_.get(), node(device), nullptr};
  return forwarder->originate_ipv6_echo(destination, sequence, &context,
                                        Impl::egress, now, payload_octets);
}

bool NetworkPlane::router_ping_reply(DeviceHandle device,
                                     std::uint16_t sequence) noexcept {
  return (router_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
NetworkPlane::router_ping_outcome(DeviceHandle device,
                                  std::uint16_t sequence) noexcept {
  if (impl_->parallel()) {
    const auto result =
        impl_->execute_forward({.kind = ForwardCommandKind::router_ping_status,
                                .device = device,
                                .sequence = sequence});
    return result.success ? result.value : 0U;
  }
  const auto *forwarder = impl_->router(device);
  return forwarder ? forwarder->echo_outcome(sequence) : 0U;
}

bool NetworkPlane::host_ping_reply(HostHandle handle,
                                   std::uint16_t sequence) noexcept {
  return (host_ping_outcome(handle, sequence) & 0xffU) == 1U;
}

std::uint64_t
NetworkPlane::host_ping_outcome(HostHandle handle,
                                std::uint16_t sequence) noexcept {
  if (impl_->parallel()) {
    const auto result =
        impl_->execute_forward({.kind = ForwardCommandKind::host_ping_status,
                                .host = handle,
                                .sequence = sequence});
    return result.success ? result.value : 0U;
  }
  const auto *host = impl_->host(handle);
  if (!host || !host->ping_reply || host->expected_sequence != sequence)
    return 0U;
  constexpr auto maximum_elapsed = (std::uint64_t{1} << 48U) - 1U;
  const auto elapsed = static_cast<std::uint64_t>(
      std::max<std::int64_t>(0, host->ping_reply_rtt.count()));
  return 1U | static_cast<std::uint64_t>(host->ping_reply_ttl) << 8U |
         std::min(elapsed, maximum_elapsed) << 16U;
}

bool NetworkPlane::router_ipv6_ping_reply(DeviceHandle device,
                                          std::uint16_t sequence) noexcept {
  return (router_ipv6_ping_outcome(device, sequence) & 0xffU) == 1U;
}

std::uint64_t
NetworkPlane::router_ipv6_ping_outcome(DeviceHandle device,
                                       std::uint16_t sequence) noexcept {
  if (impl_->parallel()) {
    const auto result = impl_->execute_forward(
        {.kind = ForwardCommandKind::router_ipv6_ping_status,
         .device = device,
         .sequence = sequence});
    return result.success ? result.value : 0U;
  }
  const auto *forwarder = impl_->router(device);
  return forwarder ? forwarder->ipv6_echo_outcome(sequence) : 0U;
}

void NetworkPlane::pump(Clock::time_point now) noexcept {
  impl_->now = now;
  // OSPF route generations are consumed by the link-thread route manager, not
  // by a forwarding shard. Drain them before packet work so a just-converged
  // next hop can be installed before subsequent data frames are forwarded.
  impl_->drain_ospf_routes();
  if (impl_->parallel()) {
    impl_->drain_forwarding_egress();
  } else {
    // Low-CPU policy co-locates forwarding and link ownership on this thread.
    // Service each router's local ND deadlines before medium delivery without
    // introducing a global timer queue or a synthetic periodic event.
    impl_->drain_ospf_egress(0U, nullptr, now);
    for (std::size_t index = 0; index < impl_->routers.size(); ++index) {
      auto &slot = impl_->routers[index];
      if (!slot.forwarder || !slot.generation)
        continue;
      const DeviceHandle handle{static_cast<std::uint16_t>(index),
                                slot.generation};
      Impl::EgressContext context{impl_.get(), node(handle), nullptr};
      slot.forwarder->service_ipv4_maintenance(&context, Impl::egress, now);
      slot.forwarder->service_ipv6_maintenance(&context, Impl::egress, now);
      if (slot.management_configured) {
        const auto frames = slot.management_stack->service_maintenance(now);
        for (std::size_t frame = 0; frame < frames.count; ++frame)
          static_cast<void>(impl_->send(
              node(handle), device_catalog::management_port_ordinal,
              frames.frames[frame]));
        if (slot.bof_dhcpv4) {
          static_cast<void>(slot.bof_dhcpv4->service(
              *slot.management_stack, &context,
              Impl::management_fragment_egress,
              Impl::management_fragment_admission, now));
          if (slot.bof_dhcpv4->client_bootstrap_complete()) {
            slot.bof_dhcpv4_timeout = Clock::time_point::max();
          } else if (now >= slot.bof_dhcpv4_timeout) {
            slot.bof_dhcpv4->remove_client(*slot.management_stack);
            slot.bof_dhcpv4_timeout = Clock::time_point::max();
          }
        }
        if (slot.bof_dhcpv6) {
          static_cast<void>(slot.bof_dhcpv6->service(
              *slot.management_stack, &context,
              Impl::management_fragment_egress,
              Impl::management_fragment_admission, now));
          if (slot.bof_dhcpv6->client_bootstrap_complete()) {
            slot.bof_dhcpv6_timeout = Clock::time_point::max();
          } else if (now >= slot.bof_dhcpv6_timeout) {
            slot.bof_dhcpv6->remove_client(*slot.management_stack);
            slot.bof_dhcpv6_timeout = Clock::time_point::max();
          }
        }
      }
    }
    for (std::size_t index = 0; index < impl_->hosts.size(); ++index) {
      auto &slot = impl_->hosts[index];
      if (!slot.generation || !slot.configured)
        continue;
      const HostHandle handle{static_cast<std::uint16_t>(index),
                              slot.generation};
      const auto frames = slot.stack.service_maintenance(now);
      for (std::size_t frame = 0; frame < frames.count; ++frame)
        static_cast<void>(impl_->send(node(handle), 0U, frames.frames[frame]));
      if (slot.dhcpv4) {
        Impl::EgressContext context{impl_.get(), node(handle), nullptr};
        static_cast<void>(slot.dhcpv4->service(
            slot.stack, &context, Impl::host_fragment_egress,
            Impl::host_fragment_admission, now));
      }
      if (slot.dhcpv6) {
        Impl::EgressContext context{impl_.get(), node(handle), nullptr};
        static_cast<void>(slot.dhcpv6->service(
            slot.stack, &context, Impl::host_fragment_egress,
            Impl::host_fragment_admission, now));
      }
      if (slot.dns) {
        Impl::EgressContext context{impl_.get(), node(handle), nullptr};
        static_cast<void>(slot.dns->service(
            slot.stack, &context, Impl::host_fragment_egress,
            Impl::host_fragment_admission, Impl::host_fragment_egress,
            Impl::host_fragment_admission, now));
      }
    }
  }
  // FDB aging and bridge egress belong to this link-shard turn regardless of
  // whether router forwarding has separate pthread owners.
  for (auto &slot : impl_->switches)
    if (slot.forwarding)
      slot.forwarding->age(now);
  impl_->drain_switch_egress();
  impl_->fabric->pump_transmit(now);
  // Transmission scheduling above has real execution cost. Reusing the time
  // sampled before that work would force every Ethernet frame, including a
  // 51.2 ns minimum frame at 10 Gb/s, through a condition-variable sleep even
  // when its wire deadline elapsed while the owner scanned the fabric. Sample
  // the monotonic host clock again at the receive boundary. This neither skips
  // serialization nor propagation: pump_delivery still compares the physical
  // deadline recorded by MultiDeviceFabric, but it can complete work that is
  // genuinely due now instead of adding the browser's millisecond wake-up
  // quantum to a nanosecond link operation.
  // Native unit tests are permitted to inject a monotonic test clock. Keep a
  // caller-supplied later instant authoritative while production, which passes
  // the host clock, benefits from the fresh sample taken after TX scheduling.
  // Choosing the later monotonic value can only make already elapsed physical
  // deadlines runnable; it never moves a delivery ahead of either clock.
  const auto delivery_now = std::max(now, Clock::now());
  impl_->fabric->pump_delivery(impl_.get(), Impl::deliver, delivery_now);
  if (impl_->parallel())
    impl_->drain_forwarding_egress();
  impl_->drain_switch_egress();
  impl_->fabric->pump_transmit(Clock::now());
}

std::optional<NetworkPlane::Clock::time_point>
NetworkPlane::next_deadline() const noexcept {
  // The fabric scans direction-local heads only to select a worker wait bound.
  auto next = impl_->fabric->next_delivery();
  for (const auto &slot : impl_->switches) {
    if (!slot.forwarding)
      continue;
    const auto candidate = slot.forwarding->next_deadline();
    if (candidate && (!next || *candidate < *next))
      next = candidate;
  }
  if (!impl_->parallel()) {
    for (const auto &slot : impl_->routers) {
      if (!slot.forwarder)
        continue;
      const auto candidate = slot.forwarder->next_ipv6_deadline();
      if (candidate && (!next || *candidate < *next))
        next = candidate;
    }
    for (const auto &slot : impl_->hosts) {
      if (!slot.generation || !slot.configured)
        continue;
      const auto candidate = slot.stack.next_maintenance_deadline();
      if (candidate && (!next || *candidate < *next))
        next = candidate;
      if (slot.dhcpv4) {
        const auto service = slot.dhcpv4->next_deadline();
        if (service && (!next || *service < *next))
          next = service;
      }
      if (slot.dhcpv6) {
        const auto service = slot.dhcpv6->next_deadline();
        if (service && (!next || *service < *next))
          next = service;
      }
      if (slot.dns) {
        const auto service = slot.dns->next_deadline();
        if (service && (!next || *service < *next))
          next = service;
      }
    }
  }
  return next;
}

std::size_t NetworkPlane::active_links() const noexcept {
  // This low-frequency owner query is used for lifecycle verification and
  // telemetry projection. Packet processing never depends on the value.
  return impl_->fabric->active_links();
}

std::uint64_t NetworkPlane::dropped_packets() const noexcept {
  // Fabric owns carrier, packet-pool and TX-queue drops. The remaining values
  // account for the only three ways a frame can be lost between physical
  // runtime owners before or after medium admission.
  return impl_->fabric->dropped_frames() + impl_->ingress_ring_dropped +
         impl_->egress_ring_dropped.load(std::memory_order_relaxed) +
         impl_->missing_binding_dropped;
}

void NetworkPlane::set_link_wakeup(void *context,
                                   void (*wakeup)(void *)) noexcept {
  impl_->link_wakeup_context = context;
  impl_->link_wakeup = wakeup;
  // These callbacks are installed before any OSPF process can create the
  // dedicated protocol pthread, so the worker reads immutable pointers. Route
  // generations and encoded egress frames use distinct SPSC rings but wake
  // the same network owner after release-publication.
  impl_->ospf_channels.egress_wakeup_context = context;
  impl_->ospf_channels.egress_wakeup = wakeup;
  impl_->ospf_channels.route_wakeup_context = context;
  impl_->ospf_channels.route_wakeup = wakeup;
  for (std::size_t index = 0; index < impl_->separate_forwarding_shards;
       ++index)
    impl_->forwarding_shards[index]->set_link_wakeup(context, wakeup);
}

std::size_t NetworkPlane::forwarding_owner_count() const noexcept {
  // Combined mode has no additional pthread. The outer network worker itself
  // is the one forwarding owner reported by telemetry.
  return impl_->separate_forwarding_shards;
}

std::uint64_t
NetworkPlane::forwarding_owner_thread_id(std::size_t index) const noexcept {
  return index < impl_->separate_forwarding_shards
             ? impl_->forwarding_shards[index]->thread_id()
             : 0U;
}

std::uint64_t
NetworkPlane::forwarding_owner_turns(std::size_t index) const noexcept {
  return index < impl_->separate_forwarding_shards
             ? impl_->forwarding_shards[index]->turns()
             : 0U;
}

std::uint64_t NetworkPlane::ospf_owner_thread_id() const noexcept {
  return impl_->ospf_worker ? impl_->ospf_worker->thread_id() : 0U;
}

} // namespace router::lab
