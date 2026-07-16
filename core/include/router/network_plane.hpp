// Forwarding and link-shard aggregate for the multi-device runtime. Control
// submits complete value commands. This owner never reads configuration,
// hardware inventory, CLI sessions, project strings or the topology registry.

#pragma once

#include "router/capture_store.hpp"
#include "router/lab_registry.hpp"
#include "router/multi_device_routing.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/endpoint_protocol.hpp"
#include "router/packet.hpp"
#include "router/router_forwarder.hpp"

#include <chrono>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <thread>
#include <vector>

namespace router::lab {

struct NetworkLinkProgram {
  // Control resolves textual topology and hardware compatibility before this
  // value crosses the shard boundary. NetworkPlane receives compact live ports.
  LinkHandle link;
  PortHandle first;
  PortHandle second;
  std::uint64_t bits_per_second{};
  std::chrono::nanoseconds propagation{};
  bool carrier{};
};

struct HostNetworkProgram {
  HostHandle host;
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
};

enum class CapturePointKind : std::uint8_t {
  link_direction,
  router_ingress,
  router_egress,
  cpm_punt
};

struct CapturePointProgram {
  CapturePointId id{};
  CapturePointKind kind{};
  LinkHandle link{};
  NodeHandle node{};
  std::uint16_t port_ordinal{0xffffU};
  std::uint8_t link_endpoint{};
  bool selected{};
  std::uint16_t name_size{};
  std::array<char, device_catalog::capture_point_name_bytes> name{};
};

struct NetworkRouterCheckpoint {
  DeviceHandle device{};
  RouterForwarderCheckpoint forwarding;
};

struct NetworkHostCheckpoint {
  HostHandle host{};
  NetworkCheckpointState endpoint;
  packet::Mac mac{};
  packet::Ipv4 address{};
  packet::Ipv4 gateway{};
  std::uint8_t prefix_length{};
  std::uint16_t mtu{device_catalog::default_host_ipv4_mtu};
  std::uint16_t expected_sequence{};
  bool configured{};
  bool link_signal{};
  bool ping_pending{};
  bool ping_reply{};
};

struct NetworkPlaneCheckpoint {
  // Sparse vectors contain only live generations. Fabric and capture values
  // retain queue bytes and selected diagnostic locations independently.
  std::vector<NetworkRouterCheckpoint> routers;
  std::vector<NetworkHostCheckpoint> hosts;
  MultiDeviceFabricCheckpoint fabric;
  CaptureStoreCheckpoint capture;
  std::vector<CapturePointProgram> capture_points;
  std::uint64_t capture_dropped{};
  // Transfer rings exist only between physical runtime owners. Their loss
  // counters are persisted so checkpoint restore cannot make overload vanish
  // from operational telemetry.
  std::uint64_t ingress_ring_dropped{};
  std::uint64_t egress_ring_dropped{};
  std::uint64_t missing_binding_dropped{};
};

class NetworkPlane final {
public:
  using Clock = std::chrono::steady_clock;

  explicit NetworkPlane(
      std::size_t logical_cpus = std::thread::hardware_concurrency());
  ~NetworkPlane();
  NetworkPlane(const NetworkPlane &) = delete;
  NetworkPlane &operator=(const NetworkPlane &) = delete;

  // Device lifecycle commands are generation-checked. Removing an old handle
  // cannot erase a forwarding instance created later in the same bounded slot.
  [[nodiscard]] bool add_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool remove_router(DeviceHandle device) noexcept;
  [[nodiscard]] bool add_host(HostHandle host) noexcept;
  [[nodiscard]] bool remove_host(HostHandle host) noexcept;

  // Port and FIB programs replace complete owner-local projections. Neither
  // method retains a control pointer after the call or future mailbox turn.
  [[nodiscard]] bool configure_port(DeviceHandle device,
                                    const ForwardPort &port) noexcept;
  [[nodiscard]] bool remove_port(DeviceHandle device,
                                 std::uint16_t ordinal) noexcept;
  [[nodiscard]] bool program_fib(DeviceHandle device,
                                 const routing::FibProgram &fib) noexcept;
  [[nodiscard]] bool configure_host(const HostNetworkProgram &program) noexcept;

  // A link program is atomic for both directions. Failure leaves the prior
  // generation untouched, so control can report the rejected transaction.
  [[nodiscard]] bool configure_link(const NetworkLinkProgram &program) noexcept;
  [[nodiscard]] bool remove_link(LinkHandle link) noexcept;
  [[nodiscard]] bool
  configure_capture_point(const CapturePointProgram &program) noexcept;
  void prepare_capture();
  [[nodiscard]] std::span<const std::uint8_t>
  prepared_capture() const noexcept;
  [[nodiscard]] std::size_t captured_frames() const noexcept;
  [[nodiscard]] std::uint64_t capture_dropped() const noexcept;
  // Includes medium queue loss and all explicit cross-shard transfer losses.
  // It excludes capture loss because observation must not affect network
  // forwarding counters.
  [[nodiscard]] std::uint64_t dropped_packets() const noexcept;
  [[nodiscard]] NetworkPlaneCheckpoint
  checkpoint(Clock::time_point now = Clock::now());
  [[nodiscard]] std::optional<RouterForwarderCheckpoint>
  router_checkpoint(DeviceHandle device,
                    Clock::time_point now = Clock::now());
  [[nodiscard]] bool restore(const NetworkPlaneCheckpoint &state,
                             Clock::time_point now = Clock::now());

  // Ping starts an asynchronous protocol operation. Completion becomes true
  // only after an encoded reply returns through the physical packet path.
  [[nodiscard]] bool start_router_ping(DeviceHandle device,
                                       std::uint32_t destination,
                                       std::uint16_t sequence,
                                       Clock::time_point now,
                                       std::uint16_t payload_octets = 56,
                                       bool dont_fragment = false) noexcept;
  [[nodiscard]] bool start_host_ping(HostHandle host, packet::Ipv4 destination,
                                     std::uint16_t sequence) noexcept;
  [[nodiscard]] bool router_ping_reply(DeviceHandle device,
                                       std::uint16_t sequence) noexcept;
  [[nodiscard]] bool host_ping_reply(HostHandle host,
                                     std::uint16_t sequence) noexcept;

  // pump runs one bounded forwarding and medium turn at steady-clock now. It
  // never advances a virtual clock and never executes work from a global heap.
  void pump(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] std::size_t active_links() const noexcept;

  // The outer link worker installs a wake callback so forwarding egress can
  // interrupt its deadline wait without polling. Callback lifetime is bounded
  // by NetworkPlaneWorker, which clears it only after all forwarding owners
  // have joined during NetworkPlane destruction.
  void set_link_wakeup(void *context, void (*wakeup)(void *)) noexcept;
  [[nodiscard]] std::size_t forwarding_owner_count() const noexcept;
  [[nodiscard]] std::uint64_t
  forwarding_owner_thread_id(std::size_t index) const noexcept;
  [[nodiscard]] std::uint64_t
  forwarding_owner_turns(std::size_t index) const noexcept;

private:
  // PIMPL keeps the large fixed arenas and internal endpoint stack out of every
  // control translation unit. The object is still allocated once at startup.
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace router::lab
