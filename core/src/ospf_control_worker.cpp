// OSPF worker scheduling and Ethernet/IP envelope transfer. The implementation
// never reads the editor topology or another router's state. It learns only
// from frames released by forwarding and emits frames back through the paired
// bounded channel.

#include "router/ospf_control_worker.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <new>

#include <openssl/crypto.h>

namespace router::ospf {

namespace {

void cleanse_authentication_commands(
    std::vector<ControlCommand> &commands) noexcept {
  for (auto &command : commands)
    OPENSSL_cleanse(command.authentication.key.data(),
                    command.authentication.key.size());
}

} // namespace

ControlWorker::OwnedProcess::~OwnedProcess() {
  cleanse_authentication_commands(authentications);
}

ControlWorker::GenerationStaging::~GenerationStaging() {
  cleanse_authentication_commands(authentications);
}

ControlWorker::ControlWorker(ControlChannels &channels,
                             std::size_t forwarding_shards)
    : channels_(channels),
      forwarding_shards_(std::clamp<std::size_t>(
          forwarding_shards, 1U,
          device_catalog::high_forwarding_shards)),
      output_scratch_(device_catalog::ospf_work_budget_packets),
      thread_([this] { run(); }) {}

ControlWorker::~ControlWorker() {
  stop_requested_.store(true, std::memory_order_release);
  notify();
  if (thread_.joinable())
    thread_.join();
}

bool ControlWorker::submit(const ControlCommand &command) noexcept {
  if (!commands_.try_push(command))
    return false;
  notify();
  return true;
}

bool ControlWorker::read(ControlResult &result) noexcept {
  const bool consumed = results_.try_pop(result);
  if (consumed)
    notify();
  return consumed;
}

void ControlWorker::notify() noexcept {
  work_pending_.store(true, std::memory_order_release);
  {
    std::lock_guard lock(wait_mutex_);
  }
  wait_condition_.notify_one();
}

ControlResult ControlWorker::apply(const ControlCommand &command) noexcept {
  ControlResult result{.id = command.id};
  // Shutdown is worker-scoped and intentionally carries no router identity.
  // Handle it before validating commands that mutate one router generation.
  if (command.kind == ControlCommandKind::shutdown) {
    result.success = true;
    stop_requested_.store(true, std::memory_order_release);
    return result;
  }
  if (command.kind == ControlCommandKind::checkpoint) {
    auto *destination = reinterpret_cast<ControlWorkerCheckpoint *>(
        command.checkpoint_transfer);
    if (!destination)
      return result;
    try {
      ControlWorkerCheckpoint staged;
      const auto now = RuntimeClock::time_point{
          std::chrono::nanoseconds{command.operation_now_nanoseconds}};
      for (const auto &device : processes_)
        for (const auto &owned : device)
          staged.processes.push_back(
              {.definition = owned.definition,
               .process = owned.process.checkpoint(now),
               .ranges = owned.ranges,
               .virtual_links = owned.virtual_links,
               .authentications = owned.authentications,
               .external_routes = owned.external_routes,
               .published_route_generation =
                   owned.published_route_generation,
               .coordinated_route_generation =
                   owned.coordinated_route_generation});
      for (auto &process : staged.processes)
        for (auto &authentication : process.authentications)
          authentication.authentication.key.fill(0U);
      staged.next_route_generation = next_route_generation_;
      staged.active_devices = active_devices_;
      staged.route_publication_pending =
          route_publication_pending_;
      staged.route_coordination_pending =
          route_coordination_pending_;
      *destination = std::move(staged);
      result.success = true;
    } catch (const std::bad_alloc &) {
    }
    return result;
  }
  if (command.kind == ControlCommandKind::restore_checkpoint) {
    auto *source =
        reinterpret_cast<ControlWorkerCheckpoint *>(
            command.checkpoint_transfer);
    if (!source)
      return result;
    try {
      std::array<std::vector<OwnedProcess>,
                 device_catalog::maximum_routers>
          replacement;
      const auto now = RuntimeClock::time_point{
          std::chrono::nanoseconds{command.operation_now_nanoseconds}};
      for (const auto &saved : source->processes) {
        const auto &definition = saved.definition;
        if (!definition.process.device ||
            definition.process.device.index >= replacement.size() ||
            definition.router_id == 0U ||
            definition.maximum_interfaces == 0U ||
            (definition.process.version != packet::ospf::version_two &&
             definition.process.version !=
                 packet::ospf::version_three))
          return result;
        auto &device = replacement[definition.process.device.index];
        if (std::any_of(device.begin(), device.end(),
                        [&](const auto &candidate) {
                          return candidate.identity ==
                                 definition.process;
                        }))
          return result;
        device.emplace_back(definition);
        auto &owned = device.back();
        if (!owned.process.restore(saved.process, now))
          return result;
        owned.ranges = saved.ranges;
        owned.virtual_links = saved.virtual_links;
        owned.authentications = saved.authentications;
        owned.external_routes = saved.external_routes;
        owned.published_route_generation =
            saved.published_route_generation;
        owned.coordinated_route_generation =
            saved.coordinated_route_generation;
      }
      // The replacement processes now own their copied key material. Erase
      // the detached checkpoint copies before committing so destruction of a
      // moved RuntimeSupervisorCheckpoint never leaves plaintext in freed
      // WebAssembly heap pages.
      for (auto &saved : source->processes) {
        for (auto &interface : saved.process.interfaces) {
          if (interface.send_authentication)
            interface.send_authentication->key.fill(0U);
          for (auto &authentication :
               interface.receive_authentications)
            authentication.key.fill(0U);
        }
        for (auto &authentication : saved.authentications)
          authentication.authentication.key.fill(0U);
      }
      processes_.swap(replacement);
      next_route_generation_ = source->next_route_generation;
      active_devices_ = source->active_devices;
      route_publication_pending_ =
          source->route_publication_pending;
      route_coordination_pending_ =
          source->route_coordination_pending;
      // NetworkPlane deliberately rebuilds its route-manager owners empty.
      // Every restored router with a protocol process must therefore publish
      // the complete route generation reconstructed from its LSDB, even when
      // that same generation had already been consumed before checkpoint.
      for (std::size_t index{}; index < processes_.size(); ++index)
        if (!processes_[index].empty()) {
          route_publication_pending_[index] = true;
          route_coordination_pending_[index] = true;
        }
      for (auto &staging : generation_staging_)
        staging.reset();
      for (auto &staging : external_staging_)
        staging.reset();
      result.success = true;
    } catch (const std::bad_alloc &) {
    }
    return result;
  }
  if (!command.process.device ||
      command.process.device.index >= processes_.size())
    return result;
  auto &device_processes = processes_[command.process.device.index];
  const auto found = std::find_if(
      device_processes.begin(), device_processes.end(),
      [&](const auto &candidate) {
        return candidate.identity == command.process;
      });
  switch (command.kind) {
  case ControlCommandKind::add_process:
    if (found != device_processes.end() || command.router_id == 0U ||
        command.maximum_interfaces == 0U ||
        (command.process.version != packet::ospf::version_two &&
         command.process.version != packet::ospf::version_three))
      return result;
    try {
      device_processes.emplace_back(command);
      active_devices_[command.process.device.index] = command.process.device;
      route_publication_pending_[command.process.device.index] = true;
      route_coordination_pending_[command.process.device.index] = true;
      result.success = true;
    } catch (const std::bad_alloc &) {
    }
    return result;
  case ControlCommandKind::remove_process:
    if (found == device_processes.end())
      return result;
    device_processes.erase(found);
    route_publication_pending_[command.process.device.index] = true;
    route_coordination_pending_[command.process.device.index] = true;
    result.success = true;
    return result;
  case ControlCommandKind::add_interface:
    if (found != device_processes.end())
      result.success = found->process.add_interface(
          command.interface, RuntimeClock::now());
    return result;
  case ControlCommandKind::add_nbma_neighbor:
    if (found != device_processes.end())
      result.success = found->process.add_nbma_neighbor(
          command.interface_id, command.nbma_neighbor, RuntimeClock::now());
    return result;
  case ControlCommandKind::remove_interface:
    if (found != device_processes.end())
      result.success =
          found->process.remove_interface(command.interface_id,
                                          RuntimeClock::now());
    return result;
  case ControlCommandKind::begin_generation: {
    // A second Begin discards only unpublished staging. The currently running
    // generation is deliberately untouched until a later successful Commit.
    try {
      GenerationStaging staged;
      staged.processes.reserve(command.expected_processes);
      staged.interfaces.reserve(command.expected_interfaces);
      staged.authentications.reserve(command.expected_authentications);
      staged.nbma_neighbors.reserve(command.expected_nbma_neighbors);
      staged.virtual_links.reserve(command.expected_virtual_links);
      staged.ranges.reserve(command.expected_ranges);
      staged.external_routes.reserve(command.expected_external_routes);
      staged.expected_processes = command.expected_processes;
      staged.expected_interfaces = command.expected_interfaces;
      staged.expected_authentications =
          command.expected_authentications;
      staged.expected_nbma_neighbors = command.expected_nbma_neighbors;
      staged.expected_virtual_links = command.expected_virtual_links;
      staged.expected_ranges = command.expected_ranges;
      staged.expected_external_routes = command.expected_external_routes;
      generation_staging_[command.process.device.index].reset();
      generation_staging_[command.process.device.index] = std::move(staged);
      result.success = true;
    } catch (const std::bad_alloc &) {
      generation_staging_[command.process.device.index].reset();
    }
    return result;
  }
  case ControlCommandKind::stage_process:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged && staged->processes.size() < staged->expected_processes) {
      try {
        staged->processes.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_interface:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged && staged->interfaces.size() < staged->expected_interfaces) {
      try {
        staged->interfaces.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_authentication:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged &&
        staged->authentications.size() <
            staged->expected_authentications) {
      try {
        staged->authentications.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_nbma_neighbor:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged &&
        staged->nbma_neighbors.size() < staged->expected_nbma_neighbors) {
      try {
        staged->nbma_neighbors.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_virtual_link:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged &&
        staged->virtual_links.size() < staged->expected_virtual_links) {
      try {
        staged->virtual_links.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_range:
    if (auto &staged =
            generation_staging_[command.process.device.index];
        staged && staged->ranges.size() < staged->expected_ranges) {
      try {
        staged->ranges.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::stage_external_route:
    if (auto &external =
            external_staging_[command.process.device.index];
        external &&
        external->size() <
            expected_external_staging_[command.process.device.index]) {
      try {
        external->push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    } else if (auto &staged =
                   generation_staging_[command.process.device.index];
               staged &&
               staged->external_routes.size() <
                   staged->expected_external_routes) {
      try {
        staged->external_routes.push_back(command);
        result.success = true;
      } catch (const std::bad_alloc &) {
      }
    }
    return result;
  case ControlCommandKind::begin_external_generation: {
    try {
      std::vector<ControlCommand> external;
      external.reserve(command.expected_external_routes);
      external_staging_[command.process.device.index] = std::move(external);
      expected_external_staging_[command.process.device.index] =
          command.expected_external_routes;
      result.success = true;
    } catch (const std::bad_alloc &) {
      external_staging_[command.process.device.index].reset();
    }
    return result;
  }
  case ControlCommandKind::commit_external_generation: {
    auto &staged = external_staging_[command.process.device.index];
    if (!staged ||
        staged->size() !=
            expected_external_staging_[command.process.device.index])
      return result;
    try {
      std::vector<std::vector<CoordinatorAdvertisement>> replacement(
          device_processes.size());
      for (const auto &external : *staged) {
        const auto owner = std::find_if(
            device_processes.begin(), device_processes.end(),
            [&](const auto &candidate) {
              return candidate.identity == external.process;
            });
        if (owner == device_processes.end()) {
          staged.reset();
          return result;
        }
        replacement[static_cast<std::size_t>(
                        std::distance(device_processes.begin(), owner))]
            .push_back(external.external_route);
      }
      for (std::size_t index{}; index < device_processes.size(); ++index)
        device_processes[index].external_routes.swap(replacement[index]);
      route_coordination_pending_[command.process.device.index] = true;
      staged.reset();
      result.success = true;
    } catch (const std::bad_alloc &) {
      // Live advertisements remain untouched until every replacement vector
      // has been built. The next RIB generation retries the exact transaction.
      staged.reset();
    }
    return result;
  }
  case ControlCommandKind::abort_external_generation:
    external_staging_[command.process.device.index].reset();
    result.success = true;
    return result;
  case ControlCommandKind::commit_generation: {
    auto &staged = generation_staging_[command.process.device.index];
    if (!staged ||
        staged->processes.size() != staged->expected_processes ||
        staged->interfaces.size() != staged->expected_interfaces ||
        staged->authentications.size() !=
            staged->expected_authentications ||
        staged->nbma_neighbors.size() != staged->expected_nbma_neighbors ||
        staged->virtual_links.size() != staged->expected_virtual_links ||
        staged->ranges.size() != staged->expected_ranges ||
        staged->external_routes.size() !=
            staged->expected_external_routes)
      return result;

    try {
      // Build every process and attach every interface in an unpublished
      // vector. Any duplicate identity, invalid interface or allocation
      // failure rejects the transaction without disturbing the live vector.
      std::vector<OwnedProcess> replacement;
      replacement.reserve(staged->processes.size());
      for (const auto &process : staged->processes) {
        if (process.process.device != command.process.device ||
            process.router_id == 0U || process.maximum_interfaces == 0U ||
            (process.process.version != packet::ospf::version_two &&
             process.process.version != packet::ospf::version_three) ||
            std::any_of(replacement.begin(), replacement.end(),
                        [&](const auto &candidate) {
                          return candidate.identity == process.process;
                        })) {
          staged.reset();
          return result;
        }
        replacement.emplace_back(process);
      }
      const auto now = RuntimeClock::now();
      for (const auto &interface : staged->interfaces) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(), [&](const auto &candidate) {
              return candidate.identity == interface.process;
            });
        if (owner == replacement.end() ||
            !owner->process.add_interface(interface.interface, now)) {
          staged.reset();
          return result;
        }
      }
      for (const auto &authentication : staged->authentications) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == authentication.process;
            });
        if (owner == replacement.end()) {
          staged.reset();
          return result;
        }
        owner->authentications.push_back(authentication);
      }
      // Authentication records are grouped only after every interface exists
      // in the unpublished replacement. This preserves atomicity and lets a
      // rollover publish multiple receive keys with exactly one send key.
      for (const auto &interface : staged->interfaces) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == interface.process;
            });
        if (owner == replacement.end()) {
          staged.reset();
          return result;
        }
        std::vector<ProcessAuthentication> receive;
        std::optional<ProcessAuthentication> send;
        try {
          for (const auto &authentication : owner->authentications) {
            if (authentication.process != interface.process ||
                authentication.interface_id !=
                    interface.interface.protocol.interface_id)
              continue;
            if (authentication.authentication_receive)
              receive.push_back(authentication.authentication);
            if (authentication.authentication_send) {
              if (send) {
                staged.reset();
                return result;
              }
              send = authentication.authentication;
            }
          }
        } catch (const std::bad_alloc &) {
          staged.reset();
          return result;
        }
        if (!receive.empty() &&
            !owner->process.set_interface_authentication(
                interface.interface.protocol.interface_id, send, receive)) {
          staged.reset();
          return result;
        }
      }
      // Neighbors depend on their interface owner, so they are attached only
      // after every interface in the unpublished generation has validated.
      // A bad address or duplicate rejects the whole replacement before swap.
      for (const auto &neighbor : staged->nbma_neighbors) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == neighbor.process;
            });
        if (owner == replacement.end() ||
            !owner->process.add_nbma_neighbor(
                neighbor.interface_id, neighbor.nbma_neighbor, now)) {
          staged.reset();
          return result;
        }
      }
      for (const auto &virtual_link : staged->virtual_links) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == virtual_link.process;
            });
        if (owner == replacement.end() ||
            owner->identity.area_id != 0U ||
            virtual_link.virtual_link.interface_id == 0U ||
            virtual_link.virtual_link.transit_area_id == 0U ||
            virtual_link.virtual_link.remote_router_id == 0U ||
            !virtual_link.virtual_link.admin_enabled ||
            std::any_of(owner->virtual_links.begin(),
                        owner->virtual_links.end(),
                        [&](const auto &candidate) {
                          return candidate.interface_id ==
                                     virtual_link.virtual_link.interface_id ||
                                 (candidate.transit_area_id ==
                                      virtual_link.virtual_link
                                          .transit_area_id &&
                                  candidate.remote_router_id ==
                                      virtual_link.virtual_link
                                          .remote_router_id);
                        })) {
          staged.reset();
          return result;
        }
        owner->virtual_links.push_back(virtual_link.virtual_link);
      }
      for (const auto &range : staged->ranges) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == range.process;
            });
        if (owner == replacement.end()) {
          staged.reset();
          return result;
        }
        owner->ranges.push_back(range.range);
      }
      for (const auto &external : staged->external_routes) {
        const auto owner = std::find_if(
            replacement.begin(), replacement.end(),
            [&](const auto &candidate) {
              return candidate.identity == external.process;
            });
        if (owner == replacement.end()) {
          staged.reset();
          return result;
        }
        owner->external_routes.push_back(external.external_route);
      }
      device_processes.swap(replacement);
      active_devices_[command.process.device.index] = command.process.device;
      // The replacement is a complete configuration generation. Publishing
      // even an empty route set is required to withdraw routes left by the
      // prior generation when its final OSPF process was removed.
      route_publication_pending_[command.process.device.index] = true;
      route_coordination_pending_[command.process.device.index] = true;
      staged.reset();
      result.success = true;
    } catch (const std::bad_alloc &) {
      // All allocations occur before swap, so live protocol state remains the
      // exact prior generation on memory exhaustion.
      staged.reset();
    }
    return result;
  }
  case ControlCommandKind::abort_generation:
    generation_staging_[command.process.device.index].reset();
    result.success = true;
    return result;
  case ControlCommandKind::query_process: {
    result.success = true;
    result.process_count =
        static_cast<std::uint32_t>(device_processes.size());
    if (command.process_ordinal >= device_processes.size())
      return result;
    const auto &owned = device_processes[command.process_ordinal];
    result.present = true;
    result.process = owned.identity;
    result.router_id = owned.process.router_id();
    result.interface_count =
        static_cast<std::uint32_t>(owned.process.interface_count());
    result.lsa_count =
        static_cast<std::uint32_t>(owned.process.database().records().size());
    result.route_count =
        static_cast<std::uint32_t>(owned.process.routes().size());
    result.route_generation = owned.process.route_generation();
    result.route_status = owned.process.route_recalculation_status();
    result.run_status = owned.process.run_ready_status();
    result.origination_status = owned.process.local_origination_status();
    return result;
  }
  case ControlCommandKind::query_interface: {
    result.success = true;
    if (command.process_ordinal >= device_processes.size())
      return result;
    const auto &owned = device_processes[command.process_ordinal];
    const auto snapshot =
        owned.process.interface_snapshot(command.interface_ordinal);
    if (!snapshot)
      return result;
    result.present = true;
    result.process = owned.identity;
    result.interface = *snapshot;
    return result;
  }
  case ControlCommandKind::query_neighbor: {
    result.success = true;
    if (command.process_ordinal >= device_processes.size())
      return result;
    const auto &owned = device_processes[command.process_ordinal];
    const auto snapshot = owned.process.neighbor_snapshot(
        command.interface_ordinal, command.row_ordinal);
    if (!snapshot)
      return result;
    result.present = true;
    result.process = owned.identity;
    result.neighbor = *snapshot;
    return result;
  }
  case ControlCommandKind::query_lsa: {
    result.success = true;
    if (command.process_ordinal >= device_processes.size())
      return result;
    const auto &owned = device_processes[command.process_ordinal];
    const auto records = owned.process.database().records();
    if (command.row_ordinal >= records.size())
      return result;
    const auto &record = records[command.row_ordinal];
    const auto header =
        packet::ospf::lsa_header(record.bytes, owned.identity.version);
    if (!header)
      return result;
    result.present = true;
    result.process = owned.identity;
    result.lsa = *header;
    result.effective_lsa_age = record.age(RuntimeClock::now());
    return result;
  }
  case ControlCommandKind::reset_neighbors:
  case ControlCommandKind::reset_database: {
    result.success = true;
    const auto now = RuntimeClock::now();
    for (auto &owned : device_processes) {
      if ((command.process.version != 0U &&
           owned.identity.version != command.process.version) ||
          owned.identity.instance_id != command.process.instance_id)
        continue;
      if (command.kind == ControlCommandKind::reset_database) {
        if (!owned.process.reset_database(now)) {
          result.success = false;
          return result;
        }
        ++result.reset_count;
      } else {
        result.reset_count += static_cast<std::uint32_t>(
            owned.process.reset_neighbors(
                command.interface_id, command.neighbor_router_id, now));
      }
    }
    return result;
  }
  case ControlCommandKind::shutdown:
  case ControlCommandKind::checkpoint:
  case ControlCommandKind::restore_checkpoint:
    // Handled before router identity validation above.
    return result;
  }
  return result;
}

void ControlWorker::receive_frame(
    const ProtocolPacketChannel::Borrowed &incoming,
    RuntimeClock::time_point now) noexcept {
  const auto ipv4 = packet::parse_ipv4(*incoming.frame);
  if (ipv4 && ipv4->protocol == packet::ospf::ip_protocol) {
    const auto offset = static_cast<std::size_t>(
        packet::ethernet_header_octets + ipv4->header_length);
    if (ipv4->total_length < ipv4->header_length ||
        offset > incoming.frame->view().size())
      return;
    const auto size = static_cast<std::size_t>(
        ipv4->total_length - ipv4->header_length);
    if (size > incoming.frame->view().size() - offset)
      return;
    const auto bytes = incoming.frame->view().subspan(offset, size);
    const auto header = packet::ospf::parse_packet(bytes);
    if (!header)
      return;
    if (incoming.metadata.device.index >= processes_.size())
      return;
    auto &device_processes = processes_[incoming.metadata.device.index];
    const auto process = std::find_if(
        device_processes.begin(), device_processes.end(),
        [&](const auto &candidate) {
          return candidate.identity.device == incoming.metadata.device &&
                 candidate.identity.version == header->version &&
                 candidate.identity.area_id == header->area_id;
        });
    if (process != device_processes.end()) {
      const auto interface_id = process->process.interface_id_for_packet(
          incoming.metadata.physical_port_ordinal, header->router_id);
      if (!interface_id)
        return;
      // RFC 2328 section 7.2 requires only the DR and BDR to receive
      // AllDRouters traffic. Ethernet multicast reaches the port before the
      // control owner can apply this OSPF membership rule, so reject it here
      // without presenting an impossible packet to a DROther neighbor FSM.
      if (ipv4->destination == packet::ospf::all_dr_routers_v4) {
        const auto state = process->process.interface_state(*interface_id);
        if (!state ||
            (*state != InterfaceState::designated &&
             *state != InterfaceState::backup))
          return;
      }
      static_cast<void>(process->process.receive_ipv4_packet(
          *interface_id, bytes, ipv4->source, ipv4->destination, now));
    }
    return;
  }

  const auto ipv6 = packet::parse_ipv6(*incoming.frame);
  if (!ipv6 ||
      ipv6->upper_layer_protocol != packet::ospf::ip_protocol)
    return;
  const auto end = static_cast<std::size_t>(
      packet::ethernet_header_octets + packet::ipv6_header_octets +
      ipv6->payload_length);
  if (ipv6->upper_layer_offset > end ||
      end > incoming.frame->view().size())
    return;
  const auto bytes = incoming.frame->view().subspan(
      ipv6->upper_layer_offset, end - ipv6->upper_layer_offset);
  const auto header = packet::ospf::parse_packet(bytes);
  if (!header)
    return;
  if (incoming.metadata.device.index >= processes_.size())
    return;
  auto &device_processes = processes_[incoming.metadata.device.index];
  const auto process = std::find_if(
      device_processes.begin(), device_processes.end(),
      [&](const auto &candidate) {
        return candidate.identity.device == incoming.metadata.device &&
               candidate.identity.version == header->version &&
               candidate.identity.instance_id == header->instance_id &&
               candidate.identity.area_id == header->area_id;
      });
  if (process != device_processes.end()) {
    const auto interface_id = process->process.interface_id_for_packet(
        incoming.metadata.physical_port_ordinal, header->router_id);
    if (!interface_id)
      return;
    // OSPFv3 keeps the same DR/BDR multicast membership semantics as OSPFv2.
    // Filtering at the process boundary preserves a shared Ethernet medium
    // while preventing ff02::6 from reaching DROther state machines.
    if (ipv6->destination == packet::ospf::all_dr_routers_v6) {
      const auto state = process->process.interface_state(*interface_id);
      if (!state ||
          (*state != InterfaceState::designated &&
           *state != InterfaceState::backup))
        return;
    }
    if (ipv6->authentication_header_present) {
      const auto layer_three = incoming.frame->view().subspan(
          packet::ethernet_header_octets,
          end - packet::ethernet_header_octets);
      static_cast<void>(process->process.receive_ipv6_ipsec_packet(
          *interface_id, layer_three, now));
    } else {
      static_cast<void>(process->process.receive_packet(
          *interface_id, bytes, ipv6->source, ipv6->destination, now));
    }
  }
}

bool ControlWorker::publish(OwnedProcess &owner,
                            const ProcessOutput &output) noexcept {
  const auto &identity = owner.identity;
  const auto shard = identity.device.index % forwarding_shards_;
  packet::Mac destination_mac{};
  if (output.destination == PacketDestination::all_spf_routers) {
    destination_mac =
        output.version == packet::ospf::version_two
            ? packet::ospf::all_spf_routers_mac_v4
            : packet::ospf::all_spf_routers_mac_v6;
  } else if (output.destination == PacketDestination::all_dr_routers) {
    destination_mac =
        output.version == packet::ospf::version_two
            ? packet::ospf::all_dr_routers_mac_v4
            : packet::ospf::all_dr_routers_mac_v6;
  }

  packet::Frame frame;
  std::optional<std::size_t> size;
  const auto payload =
      std::span<const std::uint8_t>{output.bytes}.first(output.size);
  if (output.version == packet::ospf::version_two) {
    // RFC 6864 permits Identification zero for an atomic datagram. OSPF
    // packet sizing avoids fragmentation and DF makes that contract explicit.
    size = packet::encode_ipv4_ethernet_datagram(
        frame.bytes, output.source_mac, destination_mac, output.ipv4_source,
        output.ipv4_destination, packet::ospf::ip_protocol, output.hop_limit,
        0U, payload, true);
  } else {
    if (owner.process.ipsec_authentication_configured(
            output.interface_id)) {
      const auto protected_packet =
          owner.process.protect_ipv6_ipsec_packet(
              output.interface_id, output.ipv6_source,
              output.ipv6_destination, output.hop_limit, payload,
              std::span<std::uint8_t>{frame.bytes}.subspan(
                  packet::ethernet_header_octets));
      if (!protected_packet)
        return false;
      std::copy(destination_mac.begin(), destination_mac.end(),
                frame.bytes.begin());
      std::copy(output.source_mac.begin(), output.source_mac.end(),
                frame.bytes.begin() + 6U);
      frame.bytes[12U] =
          static_cast<std::uint8_t>(packet::ethernet_type_ipv6 >> 8U);
      frame.bytes[13U] =
          static_cast<std::uint8_t>(packet::ethernet_type_ipv6);
      size = packet::ethernet_header_octets +
             protected_packet->size();
    } else {
      size = packet::encode_ipv6_ethernet_datagram(
          frame.bytes, output.source_mac, destination_mac,
          output.ipv6_source, output.ipv6_destination,
          packet::ospf::ip_protocol, output.hop_limit, payload);
    }
  }
  if (!size || *size > packet::maximum_frame_octets)
    return false;
  frame.length = static_cast<std::uint16_t>(*size);
  const bool published = channels_.egress[shard].try_send(
      {.device = identity.device,
       .interface_id = output.interface_id,
       .physical_port_ordinal = output.physical_port_ordinal},
      frame);
  if (published && channels_.egress_wakeup)
    channels_.egress_wakeup(channels_.egress_wakeup_context);
  return published;
}

bool ControlWorker::publish_routes(
    lab::DeviceHandle device,
    std::span<OwnedProcess> processes) noexcept {
  if (!device || device.index >= route_publication_pending_.size())
    return false;

  const bool process_changed =
      std::any_of(processes.begin(), processes.end(), [](const auto &owned) {
        return owned.process.route_generation() !=
               owned.published_route_generation;
      });
  if (!process_changed && !route_publication_pending_[device.index])
    return true;

  const auto writable = channels_.routes->try_acquire();
  if (!writable)
    return false;

  auto &generation = *writable->generation;
  generation.device = device;
  // Zero identifies an uninitialized generation throughout the forwarding
  // boundary. Skip it on integer wrap instead of making a valid replacement
  // indistinguishable from startup state.
  auto &next = next_route_generation_[device.index];
  if (++next == 0U)
    ++next;
  generation.generation = next;

  for (const auto &owned : processes) {
    const auto ipv4 = owned.process.ipv4_route_inputs();
    const auto ipv6 = owned.process.ipv6_route_inputs();
    if (ipv4.size() > generation.ipv4.size() - generation.ipv4_count ||
        ipv6.size() > generation.ipv6.size() - generation.ipv6_count) {
      // Capacity is generated from the supported route scale. Reject the
      // complete generation instead of publishing a truncated RIB candidate
      // set whose withdrawals and best paths would be observably incorrect.
      static_cast<void>(channels_.routes->cancel(writable->handle));
      return false;
    }
    std::copy(ipv4.begin(), ipv4.end(),
              generation.ipv4.begin() + generation.ipv4_count);
    std::copy(ipv6.begin(), ipv6.end(),
              generation.ipv6.begin() + generation.ipv6_count);
    generation.ipv4_count += static_cast<std::uint32_t>(ipv4.size());
    generation.ipv6_count += static_cast<std::uint32_t>(ipv6.size());
  }

  if (!channels_.routes->publish(writable->handle)) {
    static_cast<void>(channels_.routes->cancel(writable->handle));
    return false;
  }

  // Acknowledge process generations only after the complete aggregate crosses
  // the release edge. If publication was backpressured, the mismatch remains
  // and the next owner turn retries without losing a withdrawal.
  for (auto &owned : processes)
    owned.published_route_generation = owned.process.route_generation();
  route_publication_pending_[device.index] = false;
  if (channels_.route_wakeup)
    channels_.route_wakeup(channels_.route_wakeup_context);
  return true;
}

bool ControlWorker::coordinate_routes(
    std::span<OwnedProcess> processes,
    RuntimeClock::time_point now) noexcept {
  if (processes.empty())
    return true;
  try {
    std::vector<bool> visited(processes.size());
    for (std::size_t root{}; root < processes.size(); ++root) {
      if (visited[root])
        continue;
      std::vector<std::size_t> group;
      std::vector<AreaCoordinationView> views;
      for (std::size_t index{}; index < processes.size(); ++index) {
        const auto &candidate = processes[index];
        if (candidate.identity.version !=
                processes[root].identity.version ||
            candidate.identity.instance_id !=
                processes[root].identity.instance_id)
          continue;
        visited[index] = true;
        group.push_back(index);
        views.push_back(
            {.routes = candidate.process.routes(),
             .database = candidate.process.database().records(),
             .ranges = candidate.ranges,
             .area_id = candidate.identity.area_id,
             .default_metric = candidate.default_metric,
             .type = candidate.area_type,
             .summaries = candidate.summaries,
             .nssa_translate_always =
                 candidate.nssa_translate_always});
      }
      const bool ipv4_af =
          processes[root].identity.version ==
              packet::ospf::version_three &&
          processes[root].identity.instance_id >=
              device_catalog::ospf_v3_ipv4_instance_first;
      const auto coordinated =
          coordinate_areas(views, processes[root].process.router_id(),
                           processes[root].identity.version, ipv4_af);
      if (!coordinated ||
          coordinated->advertisements.size() != group.size())
        return false;

      // Virtual links are configured on the backbone process but derive their
      // transport, cost and viability from a non-backbone process in this same
      // version and instance group. Every lookup below reads only that local
      // transit LSDB and SPF result. Packets still traverse the selected
      // physical port, ordinary FIB, ARP or ND, link queue and remote ingress.
      std::vector<std::vector<ip::Ipv6>> endpoint_addresses(group.size());
      std::vector<bool> virtual_endpoint(group.size());
      for (std::size_t backbone_ordinal{}; backbone_ordinal < group.size();
           ++backbone_ordinal) {
        auto &backbone = processes[group[backbone_ordinal]];
        if (backbone.identity.area_id != 0U)
          continue;
        for (const auto &link : backbone.virtual_links) {
          const auto transit_ordinal = std::find_if(
              group.begin(), group.end(), [&](std::size_t index) {
                return processes[index].identity.area_id ==
                       link.transit_area_id;
              });
          if (transit_ordinal == group.end()) {
            if (!backbone.process.remove_virtual_interface(
                    link.interface_id, now))
              return false;
            continue;
          }
          const auto position = static_cast<std::size_t>(
              std::distance(group.begin(), transit_ordinal));
          auto &transit = processes[*transit_ordinal];
          const auto resolution =
              transit.process.resolve_virtual_link(
                  link.remote_router_id);
          if (!resolution) {
            if (!backbone.process.remove_virtual_interface(
                    link.interface_id, now))
              return false;
            continue;
          }
          if (backbone.identity.version ==
              packet::ospf::version_three)
            endpoint_addresses[position].push_back(
                resolution->local_address.bytes);
          if (!resolution->remote_address_known ||
              resolution->cost >
                  std::numeric_limits<std::uint16_t>::max()) {
            if (!backbone.process.remove_virtual_interface(
                    link.interface_id, now))
              return false;
            continue;
          }

          ProcessInterfaceConfiguration interface;
          interface.protocol = {
              .router_id = backbone.process.router_id(),
              .area_id = 0U,
              .interface_id = link.interface_id,
              .network_mask = 0U,
              .local_election_identity = 0U,
              .options = link.options,
              .hello_interval_seconds =
                  link.hello_interval_seconds,
              .dead_interval_seconds =
                  link.dead_interval_seconds,
              .interface_mtu = resolution->interface_mtu,
              .router_priority = 0U,
              .version = backbone.identity.version,
              .instance_id = backbone.identity.instance_id,
              .network_type = NetworkType::virtual_link,
              .passive = false,
              .enabled = link.admin_enabled};
          interface.source_mac = resolution->source_mac;
          interface.physical_port_ordinal =
              resolution->physical_port_ordinal;
          interface.metric =
              static_cast<std::uint16_t>(resolution->cost);
          interface.retransmit_interval_seconds =
              link.retransmit_interval_seconds;
          interface.transmit_delay_seconds =
              link.transmit_delay_seconds;
          interface.prefix_length =
              backbone.identity.version ==
                      packet::ospf::version_two
                  ? 32U
                  : 128U;
          interface.virtual_neighbor_router_id =
              link.remote_router_id;
          interface.virtual_neighbor_address =
              resolution->remote_address;
          if (backbone.identity.version ==
              packet::ospf::version_two) {
            std::copy_n(resolution->local_address.bytes.begin(),
                        interface.ipv4_source.size(),
                        interface.ipv4_source.begin());
          } else {
            interface.ipv6_source =
                resolution->local_address.bytes;
            interface.ipv6_prefix =
                resolution->local_address.bytes;
          }
          if (!backbone.process.replace_virtual_interface(interface,
                                                           now))
            return false;
          std::vector<ProcessAuthentication> receive;
          std::optional<ProcessAuthentication> send;
          try {
            receive.reserve(backbone.authentications.size());
            for (const auto &authentication :
                 backbone.authentications) {
              if (authentication.interface_id != link.interface_id)
                continue;
              if (authentication.authentication_receive)
                receive.push_back(authentication.authentication);
              if (authentication.authentication_send) {
                if (send)
                  return false;
                send = authentication.authentication;
              }
            }
          } catch (const std::bad_alloc &) {
            return false;
          }
          if (!receive.empty() &&
              !backbone.process.set_interface_authentication(
                  link.interface_id, send, receive))
            return false;
          virtual_endpoint[position] =
              virtual_endpoint[position] ||
              backbone.process.neighbor_state(
                  link.interface_id, link.remote_router_id) ==
                  NeighborState::full;
        }
      }
      if (processes[root].identity.version ==
          packet::ospf::version_three)
        for (std::size_t ordinal{}; ordinal < group.size(); ++ordinal)
          if (!processes[group[ordinal]]
                   .process.set_virtual_endpoint_addresses(
                       endpoint_addresses[ordinal], now))
            return false;

      for (std::size_t ordinal{}; ordinal < group.size(); ++ordinal) {
        auto &owned = processes[group[ordinal]];
        auto advertisements =
            std::move(coordinated->advertisements[ordinal]);
        advertisements.insert(advertisements.end(),
                              owned.external_routes.begin(),
                              owned.external_routes.end());
        owned.process.set_router_roles(
            coordinated->area_border_router,
            owned.asbr, virtual_endpoint[ordinal],
            owned.overload, now);
        if (!owned.process.reconcile_coordinator_advertisements(
                advertisements, now))
          return false;
        owned.coordinated_route_generation =
            owned.process.route_generation();
      }
    }
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void ControlWorker::run() noexcept {
  auto identity = static_cast<std::uint64_t>(
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  thread_id_.store(identity ? identity : 1U, std::memory_order_release);
  while (!stop_requested_.load(std::memory_order_acquire)) {
    work_pending_.store(false, std::memory_order_release);
    std::size_t command_budget =
        device_catalog::network_command_work_budget;
    ControlCommand command;
    while (command_budget-- &&
           commands_.try_pop_and_clear(command)) {
      const auto result = apply(command);
      if (command.kind == ControlCommandKind::stage_authentication)
        spsc_secure_clear(command);
      while (!results_.try_push(result) &&
             !stop_requested_.load(std::memory_order_acquire)) {
        std::unique_lock lock(wait_mutex_);
        wait_condition_.wait(lock, [&] {
          return stop_requested_.load(std::memory_order_acquire) ||
                 !results_.full();
        });
      }
    }

    auto now = RuntimeClock::now();
    std::size_t receive_budget =
        device_catalog::ospf_work_budget_packets;
    for (std::size_t shard{}; shard < forwarding_shards_ && receive_budget;
         ++shard) {
      while (receive_budget) {
        const auto packet = channels_.ingress[shard].try_receive();
        if (!packet)
          break;
        receive_frame(*packet, now);
        static_cast<void>(
            channels_.ingress[shard].release(packet->handle));
        --receive_budget;
      }
    }

    std::optional<RuntimeClock::time_point> deadline;
    for (auto &device_processes : processes_)
      for (auto &owned : device_processes) {
        const auto shard = owned.identity.device.index % forwarding_shards_;
        const auto available =
            channels_.egress[shard].producer_available();
        if (available != 0U) {
          std::size_t written{};
          const auto capacity =
              std::min(available, output_scratch_.size());
          static_cast<void>(owned.process.run_ready(
              now, std::span<ProcessOutput>{output_scratch_}.first(capacity),
              written));
          for (std::size_t index{}; index < written; ++index)
            if (!publish(owned, output_scratch_[index]))
              break;
        }
        const auto candidate = owned.process.next_deadline();
        if (candidate && (!deadline || *candidate < *deadline))
          deadline = candidate;
      }
    // Route publication is performed once per router after every local process
    // has completed this turn. The consumer consequently sees one coherent
    // device generation rather than area-by-area transient best paths.
    for (std::size_t index{}; index < processes_.size(); ++index) {
      auto &device_processes = processes_[index];
      if (!device_processes.empty()) {
        if (std::any_of(
                device_processes.begin(), device_processes.end(),
                [](const auto &owned) {
                  return owned.process.route_generation() !=
                         owned.coordinated_route_generation;
                }))
          route_coordination_pending_[index] = true;
        if (route_coordination_pending_[index] &&
            coordinate_routes(device_processes, now))
          route_coordination_pending_[index] = false;
        static_cast<void>(publish_routes(device_processes.front().identity.device,
                                         device_processes));
      } else if (route_publication_pending_[index]) {
        // A removed final process has no remaining identity object. The slot
        // generation comes from the last accepted configuration command, not
        // from a guessed registry generation derived from the slot index.
        static_cast<void>(
            publish_routes(active_devices_[index], device_processes));
      }
    }

    std::unique_lock lock(wait_mutex_);
    const auto ready = [&] {
      return stop_requested_.load(std::memory_order_acquire) ||
             work_pending_.load(std::memory_order_acquire) ||
             !commands_.empty();
    };
    if (!ready()) {
      if (deadline)
        static_cast<void>(
            wait_condition_.wait_until(lock, *deadline, ready));
      else
        wait_condition_.wait(lock, ready);
    }
  }
  thread_id_.store(0U, std::memory_order_release);
}

} // namespace router::ospf
