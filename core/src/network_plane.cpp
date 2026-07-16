// Network-plane owner implementation. Router and host stacks communicate only
// through encoded frames admitted to MultiDeviceFabric.

#include "router/network_plane.hpp"

#include "network_endpoint.hpp"
#include "router/multi_device_fabric.hpp"
#include "router/shard_policy.hpp"
#include "router/spsc_ring.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <new>
#include <thread>
#include <string_view>
#include <utility>

namespace router::lab {

namespace {

enum class ForwardCommandKind : std::uint8_t {
  add_router,
  remove_router,
  add_host,
  remove_host,
  configure_port,
  remove_port,
  program_fib,
  configure_host,
  set_host_link,
  host_link_status,
  router_ping,
  host_ping,
  router_ping_status,
  host_ping_status,
  pause,
  shutdown
};

struct ForwardCommand {
  // Producer: link owner. Consumer: exactly one forwarding shard selected by
  // stable node index. Every field is a value, never a registry pointer.
  std::uint64_t id{};
  ForwardCommandKind kind{};
  DeviceHandle device{};
  HostHandle host{};
  ForwardPort port{};
  routing::FibProgram fib{};
  HostNetworkProgram host_program{};
  std::uint32_t destination{};
  packet::Ipv4 host_destination{};
  std::uint16_t sequence{};
  std::uint16_t payload_octets{56};
  bool flag{};
};

struct ForwardResult {
  // Producer: one forwarding shard. Consumer: link owner. A result remains in
  // the bounded ring until consumed; a command is never acknowledged early.
  std::uint64_t id{};
  bool success{};
  std::uint64_t value{};
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

  ForwardingShardWorker(std::size_t index, void *owner,
                        CommandHandler command_handler,
                        IngressHandler ingress_handler)
      : index_(index), owner_(owner), command_handler_(command_handler),
        ingress_handler_(ingress_handler) {}

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
    { std::lock_guard lock(wait_mutex_); }
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
        ForwardCommand command;
        if (commands_.try_pop(command))
          pending_command = command;
      }
      if (pending_command &&
          (pending_command->kind != ForwardCommandKind::pause ||
           ingress_.empty())) {
        const auto command = *pending_command;
        pending_command.reset();
        auto result = command.kind == ForwardCommandKind::pause
                          ? ForwardResult{command.id, true, 0}
                          : command_handler_(owner_, index_, command);
        while (!results_.try_push(result) &&
               !stop_requested_.load(std::memory_order_acquire)) {
          std::unique_lock lock(wait_mutex_);
          wait_condition_.wait(lock, [&] {
            return stop_requested_.load(std::memory_order_acquire) ||
                   !results_.full();
          });
        }
        if (command.kind == ForwardCommandKind::shutdown) {
          stop_requested_.store(true, std::memory_order_release);
          break;
        }
        if (command.kind == ForwardCommandKind::pause) {
          resume_requested_.store(false, std::memory_order_release);
          std::unique_lock lock(wait_mutex_);
          wait_condition_.wait(lock, [&] {
            return stop_requested_.load(std::memory_order_acquire) ||
                   resume_requested_.load(std::memory_order_acquire);
          });
        }
      }

      std::unique_lock lock(wait_mutex_);
      const auto ready = [&] {
        return stop_requested_.load(std::memory_order_acquire) ||
               pending_command.has_value() || !commands_.empty() ||
               !ingress_.empty();
      };
      if (!ready())
        wait_condition_.wait(lock, ready);
    }
    thread_id_.store(0U, std::memory_order_release);
  }

  std::size_t index_{};
  void *owner_{};
  CommandHandler command_handler_{};
  IngressHandler ingress_handler_{};
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
  };

  struct HostSlot {
    std::uint16_t generation{};
    network_detail::EndpointStack stack;
    std::uint16_t expected_sequence{};
    bool configured{};
    bool link_signal{};
    bool ping_pending{};
    bool ping_reply{};
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
  // Link-owner generation mirrors validate capture and physical delivery
  // targets without reading forwarding-owned slot state across pthreads.
  std::array<std::uint16_t, device_catalog::maximum_routers>
      router_generations{};
  std::array<std::uint16_t, device_catalog::maximum_hosts> host_generations{};
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
  std::array<std::array<CaptureBinding, 2>,
             device_catalog::maximum_links>
      link_captures{};
  std::array<std::array<CaptureBinding,
                        device_catalog::maximum_ports_per_router>,
             device_catalog::maximum_routers>
      ingress_captures{};
  std::array<std::array<CaptureBinding,
                        device_catalog::maximum_ports_per_router>,
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
  std::uint64_t missing_binding_dropped{};
  std::unique_ptr<MultiDeviceFabric> fabric{
      std::make_unique<MultiDeviceFabric>()};
  Clock::time_point now{};
  ShardPolicy policy{};
  std::size_t separate_forwarding_shards{};
  std::array<std::unique_ptr<ForwardingShardWorker>,
             device_catalog::high_forwarding_shards>
      forwarding_shards{};
  std::uint64_t next_forward_command_id{1};
  void *link_wakeup_context{};
  void (*link_wakeup)(void *){};

  explicit Impl(std::size_t logical_cpus)
      : policy(select_shard_policy(logical_cpus)),
        separate_forwarding_shards(policy.combined_forwarding_link()
                                       ? 0U
                                       : policy.forwarding) {
    // Combined mode retains the direct owner path below. Medium and high host
    // policies allocate only the generated number of persistent actors.
    for (std::size_t index = 0; index < separate_forwarding_shards; ++index) {
      forwarding_shards[index] = std::make_unique<ForwardingShardWorker>(
          index, this, apply_forward_command, apply_forward_ingress);
      forwarding_shards[index]->start();
    }
  }

  ~Impl() {
    // Joining forwarding owners before fabric and capture destruction prevents
    // a late egress callback from observing released link-owner state.
    for (std::size_t index = 0; index < separate_forwarding_shards; ++index)
      forwarding_shards[index]->stop();
  }

  [[nodiscard]] bool parallel() const noexcept {
    return separate_forwarding_shards != 0;
  }

  [[nodiscard]] bool live(DeviceHandle handle) const noexcept {
    return handle && handle.index < router_generations.size() &&
           router_generations[handle.index] == handle.generation;
  }

  [[nodiscard]] bool live(HostHandle handle) const noexcept {
    return handle && handle.index < host_generations.size() &&
           host_generations[handle.index] == handle.generation;
  }

  [[nodiscard]] ForwardingShardWorker &shard(NodeHandle handle) noexcept {
    // Stable handle indexes do not change during device lifetime. Modulo
    // placement is deterministic and no live device migrates between owners.
    return *forwarding_shards[handle.index % separate_forwarding_shards];
  }

  static ForwardResult apply_forward_command(
      void *context, std::size_t shard_index,
      const ForwardCommand &command) noexcept;
  static void apply_forward_ingress(void *context, std::size_t shard_index,
                                    const ForwardIngress &ingress) noexcept;
  [[nodiscard]] ForwardResult execute_forward(
      const ForwardCommand &command) noexcept;
  [[nodiscard]] bool queue_egress(ForwardingShardWorker *shard,
                                  NodeHandle source,
                                  std::uint16_t ordinal,
                                  const packet::Frame &frame) noexcept;
  void drain_forwarding_egress() noexcept;
  [[nodiscard]] bool pause_forwarding() noexcept;
  void resume_forwarding() noexcept;

  [[nodiscard]] RouterForwarder *router(DeviceHandle handle) noexcept {
    // Both compact index and generation participate. A delayed FIB program for
    // a deleted router cannot reach the replacement forwarder.
    if (handle.index >= routers.size())
      return nullptr;
    auto &slot = routers[handle.index];
    return slot.generation == handle.generation ? slot.forwarder.get() : nullptr;
  }

  [[nodiscard]] const RouterForwarder *
  router(DeviceHandle handle) const noexcept {
    if (handle.index >= routers.size())
      return nullptr;
    const auto &slot = routers[handle.index];
    return slot.generation == handle.generation ? slot.forwarder.get() : nullptr;
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

  [[nodiscard]] PortBinding *binding(PortHandle port) noexcept {
    // Port ordinals are validated before indexing. Hosts expose only eth0 at
    // ordinal zero, while routers use hardware-generated stable ordinals.
    if (port.node.kind == NodeKind::host)
      return port.ordinal == 0 && port.node.index < host_bindings.size()
                 ? &host_bindings[port.node.index]
                 : nullptr;
    return port.node.index < router_bindings.size() &&
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
    return node_handle.index < router_bindings.size() &&
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
    const auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                               std::chrono::system_clock::now()
                                   .time_since_epoch())
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
    const auto timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                               std::chrono::system_clock::now()
                                   .time_since_epoch())
                               .count();
    if (!capture->record(binding.id, frame,
                         static_cast<std::uint64_t>(timestamp)))
      ++capture_dropped;
  }

  [[nodiscard]] bool send(NodeHandle source, std::uint16_t ordinal,
                          const packet::Frame &frame,
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
    if (fabric->enqueue(current->link, current->endpoint, frame) !=
        MultiDeviceFabric::DropReason::none)
      return false;
    // Observation happens only after successful queue admission. A dropped
    // frame is counted by the queue owner and is not invented in the capture.
    observe(link_captures[current->link.index][current->endpoint],
            current->link, frame);
    if (source.kind == NodeKind::router &&
        source.index < egress_captures.size() &&
        ordinal < egress_captures[source.index].size())
      observe(egress_captures[source.index][ordinal], source, frame);
    return true;
  }

  static bool egress(void *context, std::uint16_t ordinal,
                     const packet::Frame &frame) noexcept {
    auto &value = *static_cast<EgressContext *>(context);
    // The callback writes only to the owner-local fabric admission queue. It
    // never discovers or invokes the destination device directly.
    return value.owner->send(value.source, ordinal, frame, value.shard);
  }

  static void deliver(void *context,
                      const MultiDeviceFabric::Delivery &delivery) {
    auto &owner = *static_cast<Impl *>(context);
    if (owner.parallel()) {
      if (delivery.destination.node.kind == NodeKind::router &&
          delivery.destination.node.index < owner.ingress_captures.size() &&
          delivery.destination.ordinal <
              owner.ingress_captures[delivery.destination.node.index].size())
        owner.observe(
            owner.ingress_captures[delivery.destination.node.index]
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
      auto *forwarder = owner.router(handle);
      if (!forwarder)
        return;
      if (delivery.destination.node.index < owner.ingress_captures.size() &&
          delivery.destination.ordinal <
              owner.ingress_captures[delivery.destination.node.index].size())
        owner.observe(
            owner.ingress_captures[delivery.destination.node.index]
                                  [delivery.destination.ordinal],
            delivery.destination.node, delivery.frame);
      EgressContext egress_context{&owner, delivery.destination.node, nullptr};
      owner.punt_node = delivery.destination.node;
      forwarder->receive(delivery.destination.ordinal, delivery.frame,
                         &egress_context, egress, owner.now, &egress_context,
                         punt);
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
    const auto result = endpoint->stack.receive(
        delivery.frame, endpoint->expected_sequence, endpoint->ping_pending);
    for (std::size_t index = 0; index < result.count; ++index)
      static_cast<void>(owner.send(node(handle), 0, result.frames[index]));
    if (result.echo_reply) {
      endpoint->ping_reply = true;
      endpoint->ping_pending = false;
    }
  }

  static void punt(void *context, std::uint16_t,
                   const packet::Frame &frame) noexcept {
    auto &egress_context = *static_cast<EgressContext *>(context);
    auto &owner = *egress_context.owner;
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
  const NodeHandle target = command.device ? node(command.device)
                                           : node(command.host);
  if (!target.generation ||
      target.index % owner.separate_forwarding_shards != shard_index)
    return result;

  switch (command.kind) {
  case ForwardCommandKind::add_router: {
    if (command.device.index >= owner.routers.size())
      break;
    auto &slot = owner.routers[command.device.index];
    if (slot.forwarder)
      break;
    try {
      slot.forwarder = std::make_unique<RouterForwarder>();
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
  case ForwardCommandKind::program_fib:
    if (auto *forwarder = owner.router(command.device))
      result.success = forwarder->program_fib(command.fib);
    break;
  case ForwardCommandKind::configure_host:
    if (auto *endpoint = owner.host(command.host_program.host);
        endpoint && command.host_program.prefix_length <= 32U &&
        command.host_program.mtu >= device_catalog::minimum_host_ipv4_mtu &&
        command.host_program.mtu <= device_catalog::maximum_network_mtu) {
      endpoint->stack.configure(
          {.endpoint_mac = command.host_program.mac,
           .endpoint_address = command.host_program.address,
           .endpoint_prefix_length = command.host_program.prefix_length,
           .endpoint_gateway = command.host_program.gateway,
           .endpoint_mtu = command.host_program.mtu});
      endpoint->configured = true;
      endpoint->ping_pending = false;
      endpoint->ping_reply = false;
      result.success = true;
    }
    break;
  case ForwardCommandKind::set_host_link:
    if (auto *endpoint = owner.host(command.host)) {
      endpoint->link_signal = command.flag;
      result.success = true;
    }
    break;
  case ForwardCommandKind::host_link_status:
    if (const auto *endpoint = owner.host(command.host)) {
      result.success = true;
      result.value = endpoint->link_signal;
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
  case ForwardCommandKind::host_ping:
    if (auto *endpoint = owner.host(command.host);
        endpoint && endpoint->configured && endpoint->link_signal) {
      endpoint->expected_sequence = command.sequence;
      endpoint->ping_pending = true;
      endpoint->ping_reply = false;
      const auto frames =
          endpoint->stack.begin_echo(command.host_destination, command.sequence);
      bool accepted = frames.count > 0;
      auto &worker = *owner.forwarding_shards[shard_index];
      for (std::size_t index = 0; index < frames.count; ++index)
        accepted = owner.queue_egress(&worker, node(command.host), 0,
                                      frames.frames[index]) && accepted;
      if (!accepted)
        endpoint->ping_pending = false;
      result.success = accepted;
    }
    break;
  case ForwardCommandKind::router_ping_status:
    if (const auto *forwarder = owner.router(command.device)) {
      result.success = true;
      result.value = forwarder->received_echo_reply(command.sequence);
    }
    break;
  case ForwardCommandKind::host_ping_status:
    if (const auto *endpoint = owner.host(command.host)) {
      result.success = true;
      result.value = endpoint->ping_reply &&
                     endpoint->expected_sequence == command.sequence;
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
    auto *forwarder = owner.router(handle);
    if (!forwarder)
      return;
    EgressContext egress_context{&owner, ingress.destination.node, &worker};
    forwarder->receive(ingress.destination.ordinal, ingress.frame,
                       &egress_context, egress, Clock::now(), &egress_context,
                       punt);
    return;
  }

  const HostHandle handle{ingress.destination.node.index,
                          ingress.destination.node.generation};
  auto *endpoint = owner.host(handle);
  if (!endpoint || !endpoint->configured)
    return;
  const auto frames = endpoint->stack.receive(
      ingress.frame, endpoint->expected_sequence, endpoint->ping_pending);
  for (std::size_t index = 0; index < frames.count; ++index)
    static_cast<void>(owner.queue_egress(&worker, node(handle), 0,
                                         frames.frames[index]));
  if (frames.echo_reply) {
    endpoint->ping_reply = true;
    endpoint->ping_pending = false;
  }
}

ForwardResult NetworkPlane::Impl::execute_forward(
    const ForwardCommand &source) noexcept {
  ForwardCommand command = source;
  command.id = next_forward_command_id++;
  const NodeHandle target = command.device ? node(command.device)
                                           : node(command.host);
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

bool NetworkPlane::Impl::queue_egress(ForwardingShardWorker *source_shard,
                                      NodeHandle source,
                                      std::uint16_t ordinal,
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
  for (std::size_t shard_index = 0;
       shard_index < separate_forwarding_shards; ++shard_index) {
    auto &worker = *forwarding_shards[shard_index];
    std::size_t budget = device_catalog::fabric_work_budget_frames;
    ForwardEgress egress_frame;
    while (budget-- && worker.take_egress(egress_frame)) {
      if (egress_frame.kind == ForwardEgressKind::cpm_punt) {
        if (egress_frame.source.kind == NodeKind::router &&
            egress_frame.source.index < cpm_captures.size())
          observe(cpm_captures[egress_frame.source.index],
                  egress_frame.source, egress_frame.frame);
        continue;
      }
      const auto *current = binding(egress_frame.source,
                                    egress_frame.ordinal);
      if (!current || current->port.node != egress_frame.source ||
          !current->link) {
        ++missing_binding_dropped;
        continue;
      }
      if (fabric->enqueue(current->link, current->endpoint,
                          egress_frame.frame) !=
          MultiDeviceFabric::DropReason::none)
        continue;
      observe(link_captures[current->link.index][current->endpoint],
              current->link, egress_frame.frame);
      if (egress_frame.source.kind == NodeKind::router &&
          egress_frame.source.index < egress_captures.size() &&
          egress_frame.ordinal <
              egress_captures[egress_frame.source.index].size())
        observe(egress_captures[egress_frame.source.index]
                               [egress_frame.ordinal],
                egress_frame.source, egress_frame.frame);
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

bool NetworkPlane::add_router(DeviceHandle device) noexcept {
  if (!device || device.index >= impl_->routers.size())
    return false;
  if (impl_->parallel()) {
    if (impl_->router_generations[device.index])
      return false;
    const bool added = impl_->execute_forward(
        {.kind = ForwardCommandKind::add_router, .device = device})
        .success;
    if (added)
      impl_->router_generations[device.index] = device.generation;
    return added;
  }
  auto &slot = impl_->routers[device.index];
  if (slot.forwarder)
    return false;
  // Allocate the device arena once on lifecycle admission, never on packet
  // receipt. Generation is published only after allocation succeeded.
  slot.forwarder = std::make_unique<RouterForwarder>();
  slot.generation = device.generation;
  impl_->router_generations[device.index] = device.generation;
  return true;
}

bool NetworkPlane::remove_router(DeviceHandle device) noexcept {
  if (!impl_->live(device))
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
    const bool removed = impl_->execute_forward(
        {.kind = ForwardCommandKind::remove_router, .device = device})
        .success;
    if (removed)
      impl_->router_generations[device.index] = 0;
    return removed;
  }
  impl_->routers[device.index] = {};
  impl_->router_generations[device.index] = 0;
  return true;
}

bool NetworkPlane::add_host(HostHandle host) noexcept {
  if (!host || host.index >= impl_->hosts.size() ||
      impl_->host_generations[host.index])
    return false;
  if (impl_->parallel()) {
    const bool added = impl_->execute_forward(
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
    if (impl_->links[index] &&
        (impl_->endpoints[index][0].node == node(host) ||
         impl_->endpoints[index][1].node == node(host)))
      static_cast<void>(remove_link(*impl_->links[index]));
  }
  if (impl_->parallel()) {
    const bool removed = impl_->execute_forward(
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

bool NetworkPlane::configure_port(DeviceHandle device,
                                  const ForwardPort &port) noexcept {
  if (impl_->parallel())
    return impl_->execute_forward({.kind = ForwardCommandKind::configure_port,
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
    return impl_->execute_forward({.kind = ForwardCommandKind::remove_port,
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

bool NetworkPlane::program_fib(DeviceHandle device,
                               const routing::FibProgram &fib) noexcept {
  if (impl_->parallel())
    return impl_->execute_forward({.kind = ForwardCommandKind::program_fib,
                                   .device = device,
                                   .fib = fib})
        .success;
  auto *forwarder = impl_->router(device);
  return forwarder && forwarder->program_fib(fib);
}

bool NetworkPlane::configure_host(const HostNetworkProgram &program) noexcept {
  if (impl_->parallel())
    return impl_->execute_forward(
        {.kind = ForwardCommandKind::configure_host,
         .host = program.host,
         .host_program = program})
        .success;
  auto *host = impl_->host(program.host);
  if (!host || program.prefix_length > 32U ||
      program.mtu < device_catalog::minimum_host_ipv4_mtu ||
      program.mtu > device_catalog::maximum_network_mtu)
    return false;
  host->stack.configure({.endpoint_mac = program.mac,
                         .endpoint_address = program.address,
                         .endpoint_prefix_length = program.prefix_length,
                         .endpoint_gateway = program.gateway,
                         .endpoint_mtu = program.mtu});
  host->configured = true;
  // Address replacement is a protocol operation and must not overwrite the
  // independently owned physical carrier established by configure_link.
  host->ping_pending = false;
  host->ping_reply = false;
  return true;
}

bool NetworkPlane::configure_link(const NetworkLinkProgram &program) noexcept {
  if (!program.link || !program.first || !program.second ||
      program.first == program.second ||
      program.link.index >= impl_->links.size())
    return false;
  const auto live_node = [&](NodeHandle value) {
    return value.kind == NodeKind::router
               ? impl_->live(DeviceHandle{value.index, value.generation})
               : impl_->live(HostHandle{value.index, value.generation});
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

  struct HostSignalChange {
    HostHandle host{};
    bool previous{};
    bool applied{};
  };
  std::array<HostSignalChange, 2> host_changes{};
  std::size_t host_change_count{};
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
  const auto rollback_host_signals = [&] {
    // Reverse order mirrors a small transaction log. Each target was validated
    // before the first mutation, so rollback cannot address a stale handle.
    for (std::size_t index = host_change_count; index > 0; --index) {
      const auto &change = host_changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(impl_->execute_forward(
            {.kind = ForwardCommandKind::set_host_link,
             .host = change.host,
             .flag = change.previous}));
      else
        impl_->hosts[change.host.index].link_signal = change.previous;
    }
  };
  for (std::size_t index = 0; index < host_change_count; ++index) {
    auto &change = host_changes[index];
    const bool changed = impl_->parallel()
                             ? impl_->execute_forward(
                                   {.kind = ForwardCommandKind::set_host_link,
                                    .host = change.host,
                                    .flag = program.carrier})
                                   .success
                             : (impl_->hosts[change.host.index].link_signal =
                                    program.carrier,
                                true);
    if (!changed) {
      rollback_host_signals();
      return false;
    }
    change.applied = true;
  }

  // Reconfiguration drains the old generation inside the fabric before new
  // endpoint bindings become visible to packet-path lookup.
  if (!impl_->fabric->configure(program.link, program.first, program.second,
                                program.bits_per_second,
                                program.propagation, program.carrier)) {
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
  const auto rollback = [&] {
    for (std::size_t index = change_count; index > 0; --index) {
      const auto &change = changes[index - 1U];
      if (!change.applied)
        continue;
      if (impl_->parallel())
        static_cast<void>(impl_->execute_forward(
            {.kind = ForwardCommandKind::set_host_link,
             .host = change.host,
             .flag = change.previous}));
      else
        impl_->hosts[change.host.index].link_signal = change.previous;
    }
  };
  for (std::size_t index = 0; index < change_count; ++index) {
    auto &change = changes[index];
    const bool cleared = impl_->parallel()
                             ? impl_->execute_forward(
                                   {.kind = ForwardCommandKind::set_host_link,
                                    .host = change.host,
                                    .flag = false})
                                   .success
                             : (impl_->hosts[change.host.index].link_signal =
                                    false,
                                true);
    if (!cleared) {
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
  if (program.id >= device_catalog::selected_capture_points)
    return false;
  if (program.kind < CapturePointKind::link_direction ||
      program.kind > CapturePointKind::cpm_punt)
    return false;
  if (!program.selected) {
    // CaptureStore retains the name and records while the indexed packet-path
    // binding is removed. Repeating removal of an unknown point is not success.
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
    target = &impl_->link_captures[program.link.index]
                                  [program.link_endpoint];
  } else {
    if (program.node.kind != NodeKind::router ||
        !impl_->live(DeviceHandle{program.node.index,
                                  program.node.generation}))
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

std::span<const std::uint8_t>
NetworkPlane::prepared_capture() const noexcept {
  return impl_->capture->prepared();
}

std::size_t NetworkPlane::captured_frames() const noexcept {
  return impl_->capture->size();
}

std::uint64_t NetworkPlane::capture_dropped() const noexcept {
  return impl_->capture_dropped;
}

NetworkPlaneCheckpoint NetworkPlane::checkpoint(Clock::time_point now) {
  if (!impl_->pause_forwarding())
    return {};
  struct Resume final {
    Impl *owner;
    ~Resume() { owner->resume_forwarding(); }
  } resume{impl_.get()};
  NetworkPlaneCheckpoint state;
  for (std::size_t index = 0; index < impl_->routers.size(); ++index) {
    const auto &slot = impl_->routers[index];
    if (slot.forwarder)
      state.routers.push_back(
          {{static_cast<std::uint16_t>(index), slot.generation},
           slot.forwarder->checkpoint(now)});
  }
  for (std::size_t index = 0; index < impl_->hosts.size(); ++index) {
    const auto &slot = impl_->hosts[index];
    if (!slot.generation)
      continue;
    NetworkHostCheckpoint host;
    host.host = {static_cast<std::uint16_t>(index), slot.generation};
    slot.stack.checkpoint(host.endpoint);
    host.mac = slot.stack.mac();
    host.address = slot.stack.address();
    host.gateway = slot.stack.gateway();
    host.prefix_length = slot.stack.prefix_length();
    host.mtu = slot.stack.mtu();
    host.expected_sequence = slot.expected_sequence;
    host.configured = slot.configured;
    host.link_signal = slot.link_signal;
    host.ping_pending = slot.ping_pending;
    host.ping_reply = slot.ping_reply;
    state.hosts.push_back(std::move(host));
  }
  state.fabric = impl_->fabric->checkpoint(now);
  state.capture = impl_->capture->checkpoint();
  const auto append_capture = [&](const Impl::CaptureBinding &binding,
                                  CapturePointKind kind, LinkHandle link,
                                  NodeHandle node_handle,
                                  std::uint16_t ordinal,
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
    append_capture(impl_->cpm_captures[router], CapturePointKind::cpm_punt,
                   {}, owner, 0xffffU, 0);
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
      state.capture_points.size() > device_catalog::selected_capture_points ||
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
  std::array<bool, device_catalog::selected_capture_points> capture_seen{};
  try {
    auto staged_routers = std::make_unique<decltype(impl_->routers)>();
    auto staged_hosts = std::make_unique<decltype(impl_->hosts)>();
    for (const auto &router : state.routers) {
      if (!router.device || router.device.index >= router_seen.size() ||
          router_seen[router.device.index] ||
          !RouterForwarder::validate_checkpoint(router.forwarding))
        return false;
      router_seen[router.device.index] = true;
      auto forwarder = std::make_unique<RouterForwarder>();
      if (!forwarder->restore(router.forwarding, now))
        return false;
      (*staged_routers)[router.device.index] =
          {router.device.generation, std::move(forwarder)};
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
          host.mtu > device_catalog::maximum_network_mtu)
        return false;
      if (host.configured)
        target.stack.configure({.endpoint_mac = host.mac,
                                .endpoint_address = host.address,
                                .endpoint_prefix_length = host.prefix_length,
                                .endpoint_gateway = host.gateway,
                                .endpoint_mtu = host.mtu});
      if (!target.stack.restore(host.endpoint))
        return false;
      target.expected_sequence = host.expected_sequence;
      target.configured = host.configured;
      target.link_signal = host.link_signal;
      target.ping_pending = host.ping_pending;
      target.ping_reply = host.ping_reply;
    }
    std::array<std::array<bool, device_catalog::maximum_ports_per_router>,
               device_catalog::maximum_routers>
        router_ports{};
    std::array<bool, device_catalog::maximum_hosts> host_ports{};
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
        } else {
          if (port.node.index >= host_seen.size() ||
              !host_seen[port.node.index] ||
              (*staged_hosts)[port.node.index].generation !=
                  port.node.generation ||
              port.ordinal != 0U || host_ports[port.node.index])
            return false;
          host_ports[port.node.index] = true;
        }
      }
    }
    for (const auto &program : state.capture_points) {
      if (!program.selected ||
          program.id >= device_catalog::selected_capture_points ||
          capture_seen[program.id] || !program.name_size ||
          program.name_size > program.name.size() ||
          program.kind < CapturePointKind::link_direction ||
          program.kind > CapturePointKind::cpm_punt)
        return false;
      capture_seen[program.id] = true;
      const auto point = std::find_if(
          state.capture.points.begin(), state.capture.points.end(),
          [&](const auto &candidate) { return candidate.id == program.id; });
      if (point == state.capture.points.end() || !point->active ||
          point->name != std::string_view(program.name.data(),
                                          program.name_size))
        return false;
      if (program.kind == CapturePointKind::link_direction) {
        if (!program.link || program.link.index >= device_catalog::maximum_links ||
            program.link_endpoint > 1U ||
            std::none_of(state.fabric.links.begin(), state.fabric.links.end(),
                         [&](const auto &link) {
                           return link.link == program.link;
                         }))
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

    // CaptureStore performs its own replacement-object staging and swaps only
    // after all allocations succeed. Fabric validation proves its fixed-pool
    // installation cannot fail, so no fallible operation follows that swap.
    // Keeping this ordering provides atomic failure without temporarily
    // allocating a second 64 MiB packet pool inside the 256 MiB Wasm budget.
    if (!impl_->capture->restore(state.capture))
      return false;
    if (!impl_->fabric->restore(state.fabric, now))
      std::terminate();
    for (std::size_t index = 0; index < impl_->routers.size(); ++index)
      impl_->routers[index] = std::move((*staged_routers)[index]);
    for (std::size_t index = 0; index < impl_->hosts.size(); ++index)
      impl_->hosts[index] = std::move((*staged_hosts)[index]);
    impl_->router_generations.fill(0);
    impl_->host_generations.fill(0);
    for (const auto &router : state.routers)
      impl_->router_generations[router.device.index] = router.device.generation;
    for (const auto &host : state.hosts)
      impl_->host_generations[host.host.index] = host.host.generation;

    for (auto &link : impl_->links)
      link.reset();
    for (auto &endpoints : impl_->endpoints)
      endpoints = {};
    for (auto &router : impl_->router_bindings)
      for (auto &binding : router)
        binding = {};
    for (auto &binding : impl_->host_bindings)
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
        impl_->ingress_captures[program.node.index][program.port_ordinal] = value;
      else if (program.kind == CapturePointKind::router_egress)
        impl_->egress_captures[program.node.index][program.port_ordinal] = value;
      else
        impl_->cpm_captures[program.node.index] = value;
    }
    impl_->capture_dropped = state.capture_dropped;
    impl_->ingress_ring_dropped = state.ingress_ring_dropped;
    impl_->egress_ring_dropped.store(state.egress_ring_dropped,
                                     std::memory_order_relaxed);
    impl_->missing_binding_dropped = state.missing_binding_dropped;
    impl_->now = now;
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
    return impl_->execute_forward({.kind = ForwardCommandKind::router_ping,
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

bool NetworkPlane::start_host_ping(HostHandle handle,
                                   packet::Ipv4 destination,
                                   std::uint16_t sequence) noexcept {
  if (impl_->parallel())
    return impl_->execute_forward({.kind = ForwardCommandKind::host_ping,
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
  const auto frames = host->stack.begin_echo(destination, sequence);
  bool accepted = frames.count > 0;
  for (std::size_t index = 0; index < frames.count; ++index)
    accepted = impl_->send(node(handle), 0, frames.frames[index]) && accepted;
  if (!accepted)
    host->ping_pending = false;
  return accepted;
}

bool NetworkPlane::router_ping_reply(DeviceHandle device,
                                     std::uint16_t sequence) noexcept {
  if (impl_->parallel()) {
    const auto result = impl_->execute_forward(
        {.kind = ForwardCommandKind::router_ping_status,
         .device = device,
         .sequence = sequence});
    return result.success && result.value;
  }
  const auto *forwarder = impl_->router(device);
  return forwarder && forwarder->received_echo_reply(sequence);
}

bool NetworkPlane::host_ping_reply(HostHandle handle,
                                   std::uint16_t sequence) noexcept {
  if (impl_->parallel()) {
    const auto result = impl_->execute_forward(
        {.kind = ForwardCommandKind::host_ping_status,
         .host = handle,
         .sequence = sequence});
    return result.success && result.value;
  }
  const auto *host = impl_->host(handle);
  return host && host->ping_reply && host->expected_sequence == sequence;
}

void NetworkPlane::pump(Clock::time_point now) noexcept {
  impl_->now = now;
  if (impl_->parallel())
    impl_->drain_forwarding_egress();
  impl_->fabric->pump_transmit(now);
  impl_->fabric->pump_delivery(impl_.get(), Impl::deliver, now);
  if (impl_->parallel())
    impl_->drain_forwarding_egress();
  impl_->fabric->pump_transmit(now);
}

std::optional<NetworkPlane::Clock::time_point>
NetworkPlane::next_deadline() const noexcept {
  // The fabric scans direction-local heads only to select a worker wait bound.
  return impl_->fabric->next_delivery();
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

} // namespace router::lab
