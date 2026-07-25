// Dedicated network owner thread. It drains bounded control commands, pumps
// ready packet work against steady_clock and sleeps on notification or the next
// direction-local delivery deadline.

#pragma once

#include "router/network_plane_messages.hpp"

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <utility>

namespace router::lab {

class NetworkPlaneWorker final {
public:
  explicit NetworkPlaneWorker(NetworkPlaneChannels &channels);
  ~NetworkPlaneWorker();
  NetworkPlaneWorker(const NetworkPlaneWorker &) = delete;
  NetworkPlaneWorker &operator=(const NetworkPlaneWorker &) = delete;

  void start();
  void stop() noexcept;
  // submit has exactly one caller on the control owner. false means bounded
  // backpressure and the command was not accepted or partially executed.
  [[nodiscard]] bool submit(const NetworkCommand &command) noexcept;
  // The command and secret payload use separate SPSC rings. Capacity is
  // preflighted before either publication, and the consumer securely clears
  // the secret slot before acknowledging the nonsecret command identity.
  [[nodiscard]] bool
  submit_signing_vault(const NetworkCommand &command,
                       const NetworkSigningVaultInitialize &payload) noexcept;
  [[nodiscard]] bool read(NetworkResult &result) noexcept;
  // Control may borrow the immutable export only after a prepare_capture result
  // has crossed the release/acquire response ring. The next prepare invalidates
  // the span and must not overlap its consumer.
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_capture() const noexcept {
    return plane_.prepared_capture();
  }
  // Prepared image is immutable after the matching result crosses the response
  // ring. Restore staging is written by control before the command release and
  // consumed exactly once by the network owner.
  [[nodiscard]] const NetworkPlaneCheckpoint *
  prepared_checkpoint() const noexcept {
    return prepared_checkpoint_.get();
  }
  [[nodiscard]] std::unique_ptr<NetworkPlaneCheckpoint>
  take_prepared_checkpoint() noexcept {
    return std::move(prepared_checkpoint_);
  }
  [[nodiscard]] const RouterForwarderCheckpoint *
  prepared_router_checkpoint() const noexcept {
    return prepared_router_checkpoint_.get();
  }
  [[nodiscard]] bool stage_restore(NetworkPlaneCheckpoint state);
  void cancel_staged_restore() noexcept { pending_restore_.reset(); }
  [[nodiscard]] bool running() const noexcept {
    return running_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t owner_thread_id() const noexcept {
    // Zero is reserved for a worker that has not entered its run loop. The
    // telemetry smoke gate can therefore distinguish startup from failure.
    return owner_thread_id_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::uint64_t owner_turns() const noexcept {
    // The monotonic diagnostic counter lets tests and telemetry distinguish a
    // sleeping owner from a hidden periodic poll loop. It has no network-time
    // meaning and is never persisted in a checkpoint.
    return owner_turns_.load(std::memory_order_acquire);
  }
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept {
    return plane_.forwarding_owner_count();
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept {
    return plane_.forwarding_owner_thread_id(index);
  }
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept {
    return plane_.forwarding_owner_turns(index);
  }
  [[nodiscard]] std::uint64_t ospf_owner_thread_id() const noexcept {
    return plane_.ospf_owner_thread_id();
  }

private:
  static void wake_link_owner(void *context) noexcept;
  void run() noexcept;
  [[nodiscard]] NetworkResult apply(const NetworkCommand &command) noexcept;

  NetworkPlaneChannels &channels_;
  std::unique_ptr<NetworkPlaneCheckpoint> prepared_checkpoint_;
  std::unique_ptr<RouterForwarderCheckpoint> prepared_router_checkpoint_;
  std::unique_ptr<NetworkPlaneCheckpoint> pending_restore_;
  // NetworkCommand contains the largest fixed FIB generation supported by the
  // selected hardware profile. Keeping one owner-local scratch object on the
  // heap makes the pthread stack independent from route scale and performs no
  // allocation inside the command loop. Only run() mutates this object.
  std::unique_ptr<NetworkCommand> command_scratch_;
  std::thread thread_;
  std::atomic_bool stop_requested_{};
  std::atomic_bool running_{};
  // Producer: any forwarding shard after release-publishing an egress frame.
  // Consumer: the sole link owner. The bit is the condition-variable
  // predicate that survives notify-before-wait; clearing it before a pump is
  // safe because that pump scans every forwarding-to-link SPSC ring.
  std::atomic_bool forwarding_egress_pending_{};
  std::atomic_uint64_t owner_thread_id_{};
  std::atomic_uint64_t owner_turns_{};
  // The mutex protects only sleeping and notification. Queue bytes and owner
  // state remain synchronized exclusively by SpscRing acquire and release.
  std::mutex wait_mutex_;
  std::condition_variable wait_condition_;
  // Variable service policy is assembled only on the network owner. Each
  // control message contains one value item, so shared SPSC slots remain
  // trivially copyable and never carry vector pointers across pthreads.
  std::array<std::optional<HostDhcpv6ClientProgram>,
             device_catalog::maximum_hosts>
      dhcpv6_client_staging_{};
  std::array<std::array<std::uint32_t, 2U>, device_catalog::maximum_hosts>
      dhcpv6_client_expected_{};
  std::array<std::optional<HostDhcpv6ServerProgram>,
             device_catalog::maximum_hosts>
      dhcpv6_server_staging_{};
  std::array<std::array<std::uint32_t, 3U>, device_catalog::maximum_hosts>
      dhcpv6_server_expected_{};
  struct DnsResolverStaging {
    // One network owner assembles variable resolver policy before asking the
    // forwarding owner to perform its own value-only transaction. current_*
    // objects are unpublished until their declared counts match exactly.
    HostDnsResolverProgram program;
    dns::RootHint current_root;
    dns::ZoneRecord current_anchor;
    std::uint32_t expected_roots{};
    std::uint32_t expected_anchors{};
    std::uint32_t expected_current_addresses{};
    std::uint32_t expected_current_rdata{};
    bool root_active{};
    bool anchor_active{};
  };
  std::array<std::optional<DnsResolverStaging>, device_catalog::maximum_hosts>
      dns_resolver_staging_{};
  struct DnsAuthoritativeStaging {
    // Plain and managed-signed programs are mutually exclusive generations.
    // Private keys are absent here: only generation requests cross control,
    // while the forwarding DNS owner creates and retains provider handles.
    HostDnsAuthoritativeProgram plain;
    HostDnsSignedAuthoritativeProgram signed_program;
    dns::ZoneCheckpoint current_zone;
    HostDnsSignedZoneProgram current_signed_zone;
    dns::ZoneRecord current_record;
    std::uint32_t expected_zones{};
    std::uint32_t expected_current_records{};
    std::uint32_t expected_current_keys{};
    std::uint32_t expected_current_rdata{};
    bool managed_signing{};
    bool zone_active{};
    bool record_active{};
  };
  std::array<std::optional<DnsAuthoritativeStaging>,
             device_catalog::maximum_hosts>
      dns_authoritative_staging_{};
  struct Dhcpv6RelayStaging {
    // Network owner assembles the portable control transaction before asking
    // NetworkPlane to perform its own forwarding-shard transaction. This
    // second boundary is required because both pthread handoffs use value-only
    // SPSC slots and neither owner may borrow the other's vector allocation.
    dhcpv6::RelayInterfaceConfig configuration;
    std::uint32_t expected_interface_id_octets{};
    std::uint16_t expected_servers{};
  };
  std::array<std::optional<Dhcpv6RelayStaging>, device_catalog::maximum_routers>
      dhcpv6_relay_staging_{};
  struct SapGenerationStaging {
    // Only the network owner mutates this vector. The following NetworkPlane
    // commit copies values through its separate forwarding SPSC transaction,
    // so no allocation pointer crosses either pthread boundary.
    std::vector<service::SapAttachment> attachments;
    std::vector<service::ServiceIpv6Interface> interfaces;
    std::uint32_t expected_attachments{};
    std::uint32_t expected_interfaces{};
  };
  std::array<std::optional<SapGenerationStaging>,
             device_catalog::maximum_routers>
      sap_generation_staging_{};
  struct Ipv6AddressGenerationStaging {
    // The network owner receives one trivially copyable record per SPSC turn.
    // reserve happens only at Begin and Commit is the sole publication point.
    std::vector<RouterIpv6Address> addresses;
    std::uint32_t expected_addresses{};
  };
  std::array<std::optional<Ipv6AddressGenerationStaging>,
             device_catalog::maximum_routers>
      ipv6_address_generation_staging_{};
  struct OspfGenerationStaging {
    // Variable configuration is assembled only on the network owner. The
    // eventual NetworkPlane call performs a second atomic publication to the
    // dedicated OSPF owner and its forwarding punt projection.
    std::vector<OspfProcessProgram> processes;
    std::vector<OspfInterfaceProgram> interfaces;
    std::vector<OspfAuthenticationProgram> authentications;
    std::vector<OspfNbmaNeighborProgram> nbma_neighbors;
    std::vector<OspfVirtualLinkProgram> virtual_links;
    std::vector<OspfAreaRangeProgram> ranges;
    std::vector<OspfExternalRouteProgram> external_routes;
    std::uint32_t expected_processes{};
    std::uint32_t expected_interfaces{};
    std::uint32_t expected_authentications{};
    std::uint32_t expected_nbma_neighbors{};
    std::uint32_t expected_virtual_links{};
    std::uint32_t expected_ranges{};
    std::uint32_t expected_external_routes{};

    OspfGenerationStaging() = default;
    OspfGenerationStaging(const OspfGenerationStaging &) = delete;
    OspfGenerationStaging &
    operator=(const OspfGenerationStaging &) = delete;
    OspfGenerationStaging(OspfGenerationStaging &&) noexcept = default;
    OspfGenerationStaging &
    operator=(OspfGenerationStaging &&) noexcept = default;
    ~OspfGenerationStaging();
  };
  std::array<std::optional<OspfGenerationStaging>,
             device_catalog::maximum_routers>
      ospf_generation_staging_{};
  // Declared last so it is destroyed first. Its forwarding pthreads may use
  // the wake callback and therefore must join while the mutex and condition
  // variable above are still alive.
  NetworkPlane plane_;
};

} // namespace router::lab
