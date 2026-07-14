// Runtime coordinator for two ownership shards, SPSC mailboxes and real-time
// hardware deadlines. Serialization, project parsing, capture and projections
// are implemented by independent modules and called only at ownership
// boundaries.

#include "router/runtime.hpp"

#include "router/project_configuration.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace router {
namespace {

template <std::size_t N>
bool copy_text(std::array<char, N> &destination, const std::string &source) {
  const auto length = std::min(source.size(), N - 1);
  std::memcpy(destination.data(), source.data(), length);
  destination[length] = '\0';
  return length == source.size();
}

std::string ipv4_text(packet::Ipv4 address) {
  std::ostringstream out;
  out << static_cast<unsigned>(address[0]) << '.'
      << static_cast<unsigned>(address[1]) << '.'
      << static_cast<unsigned>(address[2]) << '.'
      << static_cast<unsigned>(address[3]);
  return out.str();
}

const char *drop_name(NetworkDrop reason) noexcept {
  switch (reason) {
  case NetworkDrop::ingress_down:
    return "interface-down";
  case NetworkDrop::route_miss:
    return "route-miss";
  case NetworkDrop::queue_full:
    return "queue-full";
  case NetworkDrop::ttl_expired:
    return "ttl-expired";
  case NetworkDrop::timeout:
    return "timeout";
  case NetworkDrop::malformed:
    return "malformed-packet";
  case NetworkDrop::none:
    return "none";
  }
  return "unknown";
}

} // namespace

Runtime::Runtime() : started_(std::chrono::steady_clock::now()) {
  // Construction occurs in the browser Worker. Both pthread owners exist
  // before the first command can observe a ready state.
  control_thread_ = std::thread(&Runtime::control_loop, this);
  forwarding_thread_ = std::thread(&Runtime::forwarding_loop, this);
}

Runtime::~Runtime() { stop(); }

std::span<const std::uint8_t> Runtime::export_checkpoint() {
  return command("checkpoint:prepare") == "checkpoint ready"
             ? prepared_checkpoint_
             : std::span<const std::uint8_t>{};
}

bool Runtime::import_checkpoint(std::span<const std::uint8_t> bytes) {
  {
    std::scoped_lock lock(checkpoint_mutex_);
    pending_checkpoint_import_.assign(bytes.begin(), bytes.end());
  }
  return command("checkpoint:import") == "checkpoint imported";
}

void Runtime::stop() {
  // Joining remains mandatory when a worker already published stopping_. A
  // joinable std::thread destructor would otherwise terminate the process.
  stopping_.store(true, std::memory_order_release);
  command_epoch_.fetch_add(1, std::memory_order_release);
  forward_epoch_.fetch_add(1, std::memory_order_release);
  result_epoch_.fetch_add(1, std::memory_order_release);
  response_epoch_.fetch_add(1, std::memory_order_release);
  wake_control_.notify_all();
  wake_forward_.notify_all();
  wake_response_.notify_all();
  if (control_thread_.joinable())
    control_thread_.join();
  if (forwarding_thread_.joinable())
    forwarding_thread_.join();
}

std::string Runtime::command(const std::string &text) {
  // submit_mutex_ preserves the single-producer ring contract for public API
  // callers. Epoch predicates close the empty-check to wait lost-wakeup gap.
  std::scoped_lock submit_lock(submit_mutex_);
  CommandMessage message{.id =
                             next_id_.fetch_add(1, std::memory_order_relaxed)};
  if (!copy_text(message.text, text))
    return "ERROR: command exceeds control mailbox limit";
  if (!commands_.try_push(message))
    return "ERROR: control mailbox full";
  command_epoch_.fetch_add(1, std::memory_order_release);
  wake_control_.notify_one();

  ResponseMessage response;
  while (!stopping_.load(std::memory_order_acquire)) {
    if (responses_.try_pop(response))
      return response.text.data();
    const auto observed = response_epoch_.load(std::memory_order_acquire);
    if (responses_.try_pop(response))
      return response.text.data();
    std::unique_lock lock(wake_mutex_);
    wake_response_.wait(lock, [this, observed] {
      return stopping_.load(std::memory_order_acquire) ||
             response_epoch_.load(std::memory_order_acquire) != observed;
    });
  }
  return "ERROR: runtime stopped";
}

void Runtime::control_loop() {
  control_thread_id_.store(
      static_cast<std::uint64_t>(
          std::hash<std::thread::id>{}(std::this_thread::get_id())),
      std::memory_order_release);
  while (!stopping_.load(std::memory_order_acquire)) {
    CommandMessage request;
    if (!commands_.try_pop(request)) {
      const auto observed = command_epoch_.load(std::memory_order_acquire);
      if (!commands_.try_pop(request)) {
        std::unique_lock lock(wake_mutex_);
        const auto ready = [this, observed] {
          return stopping_.load(std::memory_order_acquire) ||
                 command_epoch_.load(std::memory_order_acquire) != observed;
        };
        if (hardware_deadline_) {
          if (!wake_control_.wait_until(lock, *hardware_deadline_, ready)) {
            lock.unlock();
            const auto now = std::chrono::steady_clock::now();
            const auto lag =
                now > *hardware_deadline_
                    ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                          now - *hardware_deadline_)
                          .count()
                    : 0;
            auto previous =
                max_scheduling_lag_ns_.load(std::memory_order_relaxed);
            while (static_cast<std::uint64_t>(lag) > previous &&
                   !max_scheduling_lag_ns_.compare_exchange_weak(
                       previous, static_cast<std::uint64_t>(lag),
                       std::memory_order_relaxed)) {
            }
            const auto result =
                hardware::reconcile(state_.configuration.running,
                                    state_.hardware, state_.operational, now);
            hardware_deadline_ = result.next_deadline;
            if (result.operational_change)
              reconcile_fib();
            publish_telemetry();
          }
        } else {
          wake_control_.wait(lock, ready);
        }
        control_wakeups_.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
    }
    ResponseMessage response{.id = request.id};
    const auto output = dispatch(request.text.data());
    if (!copy_text(response.text, output)) {
      copy_text(response.text, "ERROR: response exceeds control mailbox limit");
    }
    if (!responses_.try_push(response)) {
      // A full response ring violates the one-response-per-command contract.
      // Stop and wake every domain so no thread remains parked indefinitely.
      stopping_.store(true, std::memory_order_release);
      wake_control_.notify_all();
      wake_forward_.notify_all();
      wake_response_.notify_all();
      continue;
    }
    response_epoch_.fetch_add(1, std::memory_order_release);
    wake_response_.notify_one();
  }
}

std::string Runtime::dispatch(const std::string &text) {
  const auto reconcile = [this] {
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return snapshot();
  };
  if (text == "snapshot") {
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    if (result.operational_change)
      reconcile_fib();
    return snapshot();
  }
  if (text == "hardware:insert-card") {
    state_.hardware.card.present = true;
    state_.hardware.card.lifecycle =
        EquipmentLifecycle::waiting_for_provisioning;
    return reconcile();
  }
  if (text == "hardware:remove-card") {
    state_.hardware.card.present = false;
    state_.hardware.mda.present = false;
    state_.operational.arp = {};
    return reconcile();
  }
  if (text == "hardware:insert-mda:me10-10gb-sfp+" ||
      text == "hardware:insert-mda:me1-100gb-cfp2") {
    if (!state_.hardware.card.present)
      return "ERROR: equip card 1 before MDA 1/1";
    state_.hardware.mda.present = true;
    state_.hardware.mda.compatible = text.ends_with("me10-10gb-sfp+");
    state_.hardware.mda.lifecycle =
        state_.hardware.mda.compatible
            ? EquipmentLifecycle::waiting_for_provisioning
            : EquipmentLifecycle::mismatch;
    if (!state_.hardware.mda.compatible)
      state_.operational.arp = {};
    return reconcile();
  }
  if (text == "hardware:remove-mda") {
    state_.hardware.mda.present = false;
    state_.operational.arp = {};
    return reconcile();
  }
  for (const auto up : {false, true}) {
    const std::string_view prefix = up ? "link:up:" : "link:down:";
    if (!std::string_view(text).starts_with(prefix))
      continue;
    const auto id = std::string_view(text).substr(prefix.size());
    const auto port =
        std::find(profile::port_ids.begin(), profile::port_ids.end(), id);
    if (port == profile::port_ids.end())
      return "ERROR: unknown physical port";
    const auto index =
        static_cast<std::size_t>(port - profile::port_ids.begin());
    state_.hardware.link_signal[index] = up;
    if (!up)
      state_.operational.arp[index] = {};
    return reconcile();
  }
  constexpr std::string_view provisioning = "project:provisioning|";
  if (std::string_view(text).starts_with(provisioning)) {
    const auto values = std::string_view(text).substr(provisioning.size());
    const auto separator = values.find('|');
    if (separator == std::string_view::npos)
      return "ERROR: invalid provisioning state";
    const auto card = values.substr(0, separator);
    const auto mda = values.substr(separator + 1);
    if ((card != "absent" && card != "iom4-e") ||
        (mda != "absent" && mda != "me10-10gb-sfp+") ||
        (card == "absent" && mda != "absent")) {
      return "ERROR: unsupported provisioning state";
    }
    auto &running = state_.configuration.running;
    running.card_provisioned = card == "iom4-e";
    running.mda_provisioned = mda == "me10-10gb-sfp+";
    state_.configuration.candidate = running;
    session_.candidate_dirty = false;
    session_.candidate_outdated = false;
    return reconcile();
  }
  if (std::string_view(text).starts_with("project:hosts|"))
    return configure_hosts(text);
  if (std::string_view(text).starts_with("project:links|"))
    return configure_links(text);
  if (std::string_view(text).starts_with("project:running|"))
    return configure_running(text);
  if (text == "capture:prepare")
    return prepare_capture();
  if (text == "checkpoint:prepare") {
    return encode_checkpoint_on_control().empty()
               ? "ERROR: checkpoint barrier failed"
               : "checkpoint ready";
  }
  if (text == "checkpoint:import") {
    std::vector<std::uint8_t> bytes;
    {
      std::scoped_lock lock(checkpoint_mutex_);
      bytes = pending_checkpoint_import_;
      pending_checkpoint_import_.clear();
    }
    return decode_checkpoint_on_control(bytes)
               ? "checkpoint imported"
               : "ERROR: incompatible checkpoint";
  }
  if (text == "capture:start" || text == "capture:stop") {
    const bool active = text == "capture:start";
    capture_active_.store(active, std::memory_order_relaxed);
    return active ? "capture started" : "capture stopped";
  }
  constexpr std::string_view completion = "terminal:complete:";
  if (std::string_view(text).starts_with(completion)) {
    return complete_cli(state_, session_, text.substr(completion.size()));
  }
  constexpr std::string_view terminal = "terminal:";
  if (std::string_view(text).starts_with(terminal)) {
    auto output =
        execute_cli(state_, session_, text.substr(terminal.size()),
                    [this](std::uint32_t count) {
                      return run_ping(ForwardJobKind::router_ping, count);
                    });
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return output;
  }
  if (text == "host:ping:host-a:host-b") {
    return run_ping(ForwardJobKind::endpoint_ping, 1);
  }
  return "ERROR: unsupported runtime command";
}

std::string Runtime::run_ping(ForwardJobKind kind, std::uint32_t count) {
  count = std::clamp<std::uint32_t>(count, 1, 100);
  const auto destination = ipv4_text(state_.project.hosts.back().address);
  std::ostringstream out;
  out << "PING " << destination << " 56 data bytes\n";
  std::uint32_t received = 0;
  for (std::uint32_t sequence = 1; sequence <= count; ++sequence) {
    const auto result = submit_forward(
        {.id = next_id_.fetch_add(1, std::memory_order_relaxed), .kind = kind});
    state_.operational.capture_count += result.captured_frames;
    state_.operational.capture_dropped += result.capture_drops;
    state_.operational.arp = {};
    for (std::size_t index = 0; index < result.arp.size(); ++index) {
      const auto &entry = result.arp[index];
      if (entry.valid) {
        state_.operational.arp[index] = {.valid = true,
                                         .address = entry.address,
                                         .mac = entry.mac,
                                         .port_index = entry.port_index};
      }
      state_.operational.port_counters[index].rx_packets +=
          result.rx_delta[index];
      state_.operational.port_counters[index].tx_packets +=
          result.tx_delta[index];
    }
    if (!result.success) {
      ++state_.operational.dropped_packets;
      state_.operational.last_drop_reason = drop_name(result.drop_reason);
      out << "Request timeout for icmp_seq " << sequence << '\n';
      continue;
    }
    ++received;
    state_.operational.last_drop_reason = nullptr;
    out << "64 bytes from " << destination << ": icmp_seq=" << sequence
        << " ttl=" << static_cast<unsigned>(result.reply_ttl) << " time=";
    if (result.rtt_us < 1000)
      out << "<1 ms\n";
    else
      // RTT is bounded by the two-second operation deadline, so conversion to
      // double is exact here. Spell it out to keep unit conversion auditable.
      out << std::fixed << std::setprecision(3)
          << static_cast<double>(result.rtt_us) / 1000.0 << " ms\n";
  }
  out << "--- " << destination << " ping statistics ---\n"
      << count << " packets transmitted, " << received << " packets received, "
      << std::fixed << std::setprecision(1)
      << (100.0 * static_cast<double>(count - received) / count)
      << "% packet loss";
  return out.str();
}

ForwardResult Runtime::submit_forward(ForwardJob job) {
  if (!forward_jobs_.try_push(job))
    return {};
  forward_epoch_.fetch_add(1, std::memory_order_release);
  wake_forward_.notify_one();
  ForwardResult result;
  while (!stopping_.load(std::memory_order_acquire)) {
    if (forward_results_.try_pop(result))
      return result;
    const auto observed = result_epoch_.load(std::memory_order_acquire);
    if (forward_results_.try_pop(result))
      return result;
    std::unique_lock lock(wake_mutex_);
    wake_control_.wait(lock, [this, observed] {
      return stopping_.load(std::memory_order_acquire) ||
             result_epoch_.load(std::memory_order_acquire) != observed;
    });
  }
  return {};
}

std::string Runtime::prepare_capture() {
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::export_capture});
  return result.success
             ? "capture ready: " + std::to_string(capture_store_.size())
             : "ERROR: capture export failed";
}

void Runtime::reconcile_fib(bool force) {
  if (!rib_.rebuild(make_rib_input(state_)) && fib_generation_ && !force)
    return;
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::program_fib,
                      .fib = rib_.compile(++fib_generation_)});
  if (!result.success)
    state_.operational.last_drop_reason = "fib-programming-failed";
}

void Runtime::forwarding_loop() {
  LabNetwork network;
  forwarding_thread_id_.store(
      static_cast<std::uint64_t>(
          std::hash<std::thread::id>{}(std::this_thread::get_id())),
      std::memory_order_release);
  const auto publish = [this](const ForwardResult &result) {
    while (!forward_results_.try_push(result) &&
           !stopping_.load(std::memory_order_acquire))
      std::this_thread::yield();
    result_epoch_.fetch_add(1, std::memory_order_release);
    wake_control_.notify_one();
  };
  const auto capture = [](void *context, std::uint8_t interface_id,
                          const packet::Frame &frame,
                          std::uint64_t timestamp_us) {
    return static_cast<Runtime *>(context)->record_capture(interface_id, frame,
                                                           timestamp_us);
  };
  while (!stopping_.load(std::memory_order_acquire)) {
    ForwardJob job;
    if (!forward_jobs_.try_pop(job)) {
      const auto observed = forward_epoch_.load(std::memory_order_acquire);
      if (!forward_jobs_.try_pop(job)) {
        std::unique_lock lock(wake_mutex_);
        wake_forward_.wait(lock, [this, observed] {
          return stopping_.load(std::memory_order_acquire) ||
                 forward_epoch_.load(std::memory_order_acquire) != observed;
        });
        forwarding_wakeups_.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
    }
    ForwardResult result{.id = job.id};
    switch (job.kind) {
    case ForwardJobKind::program_fib:
      network.install_fib(job.fib);
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::configure_network:
      network.configure(job.network);
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::export_capture:
      capture_store_.encode();
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::checkpoint_barrier:
      result.arp = network.adjacencies();
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::restore_adjacencies:
      network.restore_adjacencies(job.restored_arp);
      result.arp = network.adjacencies();
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::router_ping:
    case ForwardJobKind::endpoint_ping:
      break;
    }
    const auto outcome = network.ping(
        job.kind == ForwardJobKind::endpoint_ping ? PingOrigin::endpoint
                                                  : PingOrigin::router,
        static_cast<std::uint16_t>(job.id),
        capture_active_.load(std::memory_order_relaxed) ? capture : nullptr,
        this);
    result.success = outcome.success;
    result.reply_ttl = outcome.reply_ttl;
    result.rtt_us = outcome.rtt_us;
    result.captured_frames = outcome.captured_frames;
    result.capture_drops = outcome.capture_drops;
    result.rx_delta = outcome.rx_delta;
    result.tx_delta = outcome.tx_delta;
    result.arp = outcome.router_arp;
    result.drop_reason = outcome.drop;
    publish(result);
  }
}

bool Runtime::record_capture(std::uint8_t interface_id,
                             const packet::Frame &frame,
                             std::uint64_t timestamp_us) {
  return capture_store_.record(interface_id, frame, timestamp_us);
}

} // namespace router
