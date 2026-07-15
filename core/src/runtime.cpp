// Runtime coordinator for two ownership shards, SPSC mailboxes and real-time
// hardware deadlines. Serialization, project parsing, capture and projections
// are implemented by independent modules and called only at ownership
// boundaries.

#include "router/runtime.hpp"

#include "router/generated_runtime_protocol.hpp"
#include "router/project_configuration.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>
#include <thread>

namespace router {
namespace {

template <std::size_t N>
// Copies one bridge response into bounded mailbox storage. False means the
// caller must publish an explicit overflow error instead of truncating text.
bool copy_text(std::array<char, N> &destination, const std::string &source) {
  const auto length = std::min(source.size(), N - 1);
  std::memcpy(destination.data(), source.data(), length);
  destination[length] = '\0';
  return length == source.size();
}

// Formats packet-layer IPv4 bytes without locale or platform socket helpers.
// Runtime output uses this only after forwarding has accepted the address.
std::string ipv4_text(packet::Ipv4 address) {
  std::ostringstream out;
  out << static_cast<unsigned>(address[0]) << '.'
      << static_cast<unsigned>(address[1]) << '.'
      << static_cast<unsigned>(address[2]) << '.'
      << static_cast<unsigned>(address[3]);
  return out.str();
}

// Maps forwarding failures to stable operational projection values. The
// terminal may format its own message, while telemetry keeps this short code.
const char *drop_name(NetworkDrop reason) noexcept {
  switch (reason) {
  case NetworkDrop::ingress_down:
    return "interface-down";
  case NetworkDrop::route_miss:
    return "route-miss";
  case NetworkDrop::queue_full:
    return "queue-full";
  case NetworkDrop::mtu_exceeded:
    return "mtu-exceeded";
  case NetworkDrop::ttl_expired:
    return "ttl-expired";
  case NetworkDrop::timeout:
    return "timeout";
  case NetworkDrop::cancelled:
    return "cancelled";
  case NetworkDrop::malformed:
    return "malformed-packet";
  case NetworkDrop::none:
    return "none";
  }
  return "unknown";
}

// Converts an external one-based chassis slot to internal zero-based storage.
// Parsing rejects signs, suffixes and zero so array arithmetic stays bounded.
std::optional<std::size_t> parse_slot(std::string_view text) noexcept {
  std::size_t slot{};
  const auto parsed =
      std::from_chars(text.data(), text.data() + text.size(), slot);
  if (text.empty() || parsed.ec != std::errc{} ||
      parsed.ptr != text.data() + text.size() || slot == 0)
    return std::nullopt;
  return slot - 1U;
}

// Serializes the router-owned terminal engine, history region, banner and
// prompt as netstrings. UI rendering therefore never predicts prompt markers,
// workflow boundaries or system names.
std::string terminal_state(const DeviceState &state,
                           const CliSession &session) {
  // Netstrings preserve spaces and control characters in the prompt without
  // teaching the browser how a specific CLI engine renders it.
  const auto field = [](std::string_view value) {
    return std::to_string(value.size()) + ":" + std::string{value} + ",";
  };
  const auto engine = session.engine == CliEngine::md ? "md" : "classic";
  // MD-CLI intentionally separates operational and configuration histories.
  // This small semantic projection lets the byte editor select the correct
  // bounded history without exposing or duplicating the candidate workflow.
  const auto history_region =
      session.engine == CliEngine::classic                ? "classic"
      : session.md_workflow == MdCliWorkflow::operational ? "md-operational"
                                                          : "md-configuration";
  const auto banner = std::string{"SR OS "} + profile::release;
  return field(engine) + field(history_region) + field(banner) +
         field(cli_prompt(state, session));
}

} // namespace

Runtime::Runtime() : started_(std::chrono::steady_clock::now()) {
  // Construction occurs in the browser Worker. Both pthread owners exist
  // before the first command can observe a ready state.
  control_thread_ = std::thread(&Runtime::control_loop, this);
  forwarding_thread_ = std::thread(&Runtime::forwarding_loop, this);
}

Runtime::~Runtime() { stop(); }

// Freezes the latest control-owned state after a forwarding barrier. The span
// remains owned by Runtime and is invalidated by the next export.
std::span<const std::uint8_t> Runtime::export_checkpoint() {
  return command(runtime_protocol::checkpoint_prepare) == "checkpoint ready"
             ? prepared_checkpoint_
             : std::span<const std::uint8_t>{};
}

// Stages borrowed import bytes under a mutex, then asks the control owner to
// validate and apply them atomically. Live state is unchanged on failure.
bool Runtime::import_checkpoint(std::span<const std::uint8_t> bytes) {
  {
    std::scoped_lock lock(checkpoint_mutex_);
    pending_checkpoint_import_.assign(bytes.begin(), bytes.end());
  }
  return command(runtime_protocol::checkpoint_import) == "checkpoint imported";
}

// Stops both owners by publishing the release-ordered flag, advancing every
// wait epoch and joining each thread before member storage is destroyed.
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

// Submits one management request to the control owner. submit_mutex preserves
// the SPSC producer contract even if several host API calls arrive together.
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
  std::string output;
  output.reserve(profile::response_message_bytes);
  while (!stopping_.load(std::memory_order_acquire)) {
    if (responses_.try_pop(response)) {
      if (response.id != message.id)
        return "ERROR: control response ordering violation";
      output.append(response.text.data());
      if (!response.more)
        return output;
      continue;
    }
    const auto observed = response_epoch_.load(std::memory_order_acquire);
    if (responses_.try_pop(response)) {
      if (response.id != message.id)
        return "ERROR: control response ordering violation";
      output.append(response.text.data());
      if (!response.more)
        return output;
      continue;
    }
    std::unique_lock lock(wake_mutex_);
    wake_response_.wait(lock, [this, observed] {
      return stopping_.load(std::memory_order_acquire) ||
             response_epoch_.load(std::memory_order_acquire) != observed;
    });
  }
  return "ERROR: runtime stopped";
}

// Owns configuration, hardware lifecycle, RIB, CLI session and projections.
// It sleeps on mailbox epochs or the nearest hardware deadline, never on a
// global event queue and never advances an artificial clock.
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
    auto output = dispatch(request.text.data());
    if (output.size() > profile::cli_output_queue_bytes)
      output = "ERROR: response exceeds CLI output queue limit";

    // Chunking prevents a large show result from inflating every response-ring
    // slot. The browser bridge drains concurrently; if all slots are occupied,
    // control yields until the sole consumer returns capacity. Accepted bytes
    // are therefore never overwritten or silently truncated.
    std::size_t offset{};
    do {
      ResponseMessage response{.id = request.id};
      const auto remaining = output.size() - offset;
      const auto count = std::min(remaining, response.text.size() - 1U);
      std::memcpy(response.text.data(), output.data() + offset, count);
      response.text[count] = '\0';
      offset += count;
      response.more = offset < output.size();
      while (!responses_.try_push(response) &&
             !stopping_.load(std::memory_order_acquire))
        std::this_thread::yield();
      response_epoch_.fetch_add(1, std::memory_order_release);
      wake_response_.notify_one();
    } while (offset < output.size() &&
             !stopping_.load(std::memory_order_acquire));
  }
}

std::string Runtime::dispatch(const std::string &text) {
  // Every mutating hardware path ends through the same reconciliation closure.
  // This guarantees alarms, deadlines and FIB withdrawal are published before
  // a successful command returns its snapshot.
  const auto reconcile = [this] {
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return snapshot();
  };
  if (text == runtime_protocol::snapshot) {
    // Snapshot is observational, but overdue real-time hardware deadlines must
    // be reconciled before rendering so the projection cannot remain stale.
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    if (result.operational_change)
      reconcile_fib();
    return snapshot();
  }
  const auto input = std::string_view{text};
  if (input.starts_with(runtime_protocol::hardware_insert_card)) {
    // Physical insertion accepts an explicit profile slot and inventory type.
    // It does not provision configuration or manufacture child inventory.
    const auto fields = input.substr(
        std::string_view{runtime_protocol::hardware_insert_card}.size());
    const auto separator = fields.find(':');
    const auto slot = parse_slot(fields.substr(0, separator));
    const auto type = separator == std::string_view::npos
                          ? std::string_view{}
                          : fields.substr(separator + 1U);
    if (!slot || *slot >= state_.hardware.cards.size() ||
        *slot != profile::line_card_index || type != profile::line_card_type)
      return "ERROR: unsupported card or slot";
    auto &card = state_.hardware.cards[*slot];
    card.type = profile::line_card_type;
    card.compatible = true;
    card.equipment.lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    return reconcile();
  }
  if (input.starts_with(runtime_protocol::hardware_remove_card)) {
    // Removing a parent atomically removes its physical children and clears
    // learned adjacencies whose egress inventory no longer exists.
    const auto slot = parse_slot(input.substr(
        std::string_view{runtime_protocol::hardware_remove_card}.size()));
    if (!slot || *slot >= state_.hardware.cards.size())
      return "ERROR: unknown card slot";
    state_.hardware.cards[*slot] = {};
    state_.operational.arp = {};
    return reconcile();
  }
  if (input.starts_with(runtime_protocol::hardware_insert_mda)) {
    // Inventory can contain a sourced but incompatible MDA type. Keeping that
    // value lets reconciliation expose mismatch rather than rejecting reality.
    auto fields = input.substr(
        std::string_view{runtime_protocol::hardware_insert_mda}.size());
    const auto first = fields.find(':');
    const auto card_slot = parse_slot(fields.substr(0, first));
    if (first == std::string_view::npos)
      return "ERROR: invalid MDA location";
    fields.remove_prefix(first + 1U);
    const auto second = fields.find(':');
    const auto mda_slot = parse_slot(fields.substr(0, second));
    const auto type = second == std::string_view::npos
                          ? std::string_view{}
                          : fields.substr(second + 1U);
    const auto supported = std::find(profile::supported_mda_types.begin(),
                                     profile::supported_mda_types.end(), type);
    if (!card_slot || !mda_slot || *card_slot >= state_.hardware.cards.size() ||
        *mda_slot >= profile::mda_slots_per_card ||
        supported == profile::supported_mda_types.end())
      return "ERROR: unsupported MDA or slot";
    auto &card = state_.hardware.cards[*card_slot];
    if (!card.type)
      return "ERROR: equip the parent card before its MDA";
    auto &mda = card.mdas[*mda_slot];
    mda.type = *supported;
    mda.compatible = type == profile::modeled_mda_type;
    mda.equipment.lifecycle = mda.compatible
                                  ? EquipmentLifecycle::waiting_for_provisioning
                                  : EquipmentLifecycle::mismatch;
    if (!mda.compatible)
      state_.operational.arp = {};
    return reconcile();
  }
  if (input.starts_with(runtime_protocol::hardware_remove_mda)) {
    // MDA removal preserves running provisioning, matching a physical pull.
    // The next insertion can therefore recover without replaying CLI config.
    auto fields = input.substr(
        std::string_view{runtime_protocol::hardware_remove_mda}.size());
    const auto separator = fields.find(':');
    const auto card_slot = parse_slot(fields.substr(0, separator));
    const auto mda_slot = separator == std::string_view::npos
                              ? std::optional<std::size_t>{}
                              : parse_slot(fields.substr(separator + 1U));
    if (!card_slot || !mda_slot || *card_slot >= state_.hardware.cards.size() ||
        *mda_slot >= profile::mda_slots_per_card)
      return "ERROR: unknown MDA slot";
    state_.hardware.cards[*card_slot].mdas[*mda_slot] = {};
    state_.operational.arp = {};
    return reconcile();
  }
  for (const auto up : {false, true}) {
    // Carrier transitions address generated physical port IDs. Clearing only
    // the affected ARP slot avoids withdrawing unrelated link adjacencies.
    const std::string_view prefix =
        up ? runtime_protocol::link_up : runtime_protocol::link_down;
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
  const std::string_view provisioning = runtime_protocol::project_provisioning;
  if (std::string_view(text).starts_with(provisioning)) {
    // Project restore changes the canonical running provisioning as one pair.
    // Parent-child validation happens before either field is written.
    const auto values = std::string_view(text).substr(provisioning.size());
    const auto separator = values.find('|');
    if (separator == std::string_view::npos)
      return "ERROR: invalid provisioning state";
    const auto card = values.substr(0, separator);
    const auto mda = values.substr(separator + 1);
    if ((card != runtime_protocol::provisioning_absent &&
         card != profile::line_card_type) ||
        (mda != runtime_protocol::provisioning_absent &&
         mda != profile::modeled_mda_type) ||
        (card == runtime_protocol::provisioning_absent &&
         mda != runtime_protocol::provisioning_absent)) {
      return "ERROR: unsupported provisioning state";
    }
    auto &running = state_.configuration.running;
    auto &configured_card = profile_card(running);
    auto &configured_mda = profile_mda(running);
    configured_card.type = card == runtime_protocol::provisioning_absent
                               ? nullptr
                               : profile::line_card_type;
    configured_mda.type = mda == runtime_protocol::provisioning_absent
                              ? nullptr
                              : profile::modeled_mda_type;
    state_.configuration.candidate = running;
    session_.candidate_dirty = false;
    session_.candidate_outdated = false;
    return reconcile();
  }
  if (input.starts_with(runtime_protocol::project_hosts))
    return configure_hosts(text);
  if (input.starts_with(runtime_protocol::project_links))
    return configure_links(text);
  if (input.starts_with(runtime_protocol::project_running))
    return configure_running(text);
  if (text == runtime_protocol::capture_prepare)
    return prepare_capture();
  if (text == runtime_protocol::checkpoint_prepare) {
    return encode_checkpoint_on_control().empty()
               ? "ERROR: checkpoint barrier failed"
               : "checkpoint ready";
  }
  if (text == runtime_protocol::checkpoint_import) {
    // Move staged bytes out while holding the bridge mutex, then perform the
    // expensive structural decode without blocking another producer copy.
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
  if (text == runtime_protocol::capture_start ||
      text == runtime_protocol::capture_stop) {
    // Relaxed ordering is sufficient because this diagnostic flag publishes
    // no packet data. Forwarding reads it only to decide whether to call the
    // already thread-safe capture observer for later frames.
    const bool active = text == runtime_protocol::capture_start;
    capture_active_.store(active, std::memory_order_relaxed);
    return active ? "capture started" : "capture stopped";
  }
  const std::string_view completion = runtime_protocol::terminal_complete;
  if (std::string_view(text).starts_with(completion)) {
    auto request = std::string_view{text}.substr(completion.size());
    auto trigger = CliCompletionTrigger::tab;
    if (request.starts_with("question|")) {
      trigger = CliCompletionTrigger::question;
      request.remove_prefix(9U);
    } else if (request.starts_with("space|")) {
      trigger = CliCompletionTrigger::space;
      request.remove_prefix(6U);
    } else if (request.starts_with("tab|")) {
      request.remove_prefix(4U);
    }
    return complete_cli(state_, session_, std::string{request}, trigger);
  }
  if (text == runtime_protocol::terminal_state)
    return terminal_state(state_, session_);
  const std::string_view terminal = runtime_protocol::terminal_execute;
  if (input.starts_with(terminal)) {
    // CLI execution stays on control. Ping is dependency-injected and crosses
    // the forwarding ring, so a command cannot call another device directly.
    auto output = execute_cli(
        state_, session_, text.substr(terminal.size()),
        [this](packet::Ipv4 destination, std::uint32_t count,
               std::uint16_t payload_octets, bool dont_fragment) {
          return run_ping(ForwardJobKind::router_ping, destination, 0, count,
                          payload_octets, dont_fragment);
        });
    const auto result = hardware::reconcile(state_.configuration.running,
                                            state_.hardware, state_.operational,
                                            std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return output;
  }
  if (input.starts_with(runtime_protocol::host_ping)) {
    // Host IDs are resolved through generated topology arrays. The selected
    // destination address and source endpoint then enter normal packet flow.
    const auto fields =
        input.substr(std::string_view{runtime_protocol::host_ping}.size());
    const auto separator = fields.find(':');
    if (separator == std::string_view::npos)
      return "ERROR: invalid host ping request";
    const auto source_id = fields.substr(0, separator);
    const auto destination_id = fields.substr(separator + 1U);
    const auto source = std::find(profile::host_ids.begin(),
                                  profile::host_ids.end(), source_id);
    const auto destination = std::find(profile::host_ids.begin(),
                                       profile::host_ids.end(), destination_id);
    if (source == profile::host_ids.end() ||
        destination == profile::host_ids.end())
      return "ERROR: unknown host";
    return run_ping(
        ForwardJobKind::endpoint_ping,
        state_.project
            .hosts[static_cast<std::size_t>(destination -
                                            profile::host_ids.begin())]
            .address,
        static_cast<std::uint8_t>(source - profile::host_ids.begin()), 1);
  }
  return "ERROR: unsupported runtime command";
}

std::string Runtime::run_ping(ForwardJobKind kind, packet::Ipv4 destination_ip,
                              std::uint8_t source_endpoint,
                              std::uint32_t count,
                              std::uint16_t payload_octets,
                              bool dont_fragment) {
  // The CLI schema bounds count, but this internal boundary clamps again for
  // typed host operations and future ABI callers that do not use CLI parsing.
  count = std::clamp<std::uint32_t>(count, 1, profile::maximum_ping_count);
  std::atomic_ref<std::uint32_t>{telemetry_.cli_cancel_requested}.store(
      0U, std::memory_order_release);
  const auto destination = ipv4_text(destination_ip);
  std::ostringstream out;
  out << "PING " << destination << ' ' << payload_octets << " data bytes\n";
  std::uint32_t received = 0;
  std::uint32_t transmitted = 0;
  std::uint64_t minimum_rtt = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t maximum_rtt{};
  double rtt_sum{};
  double rtt_square_sum{};
  auto next_probe = std::chrono::steady_clock::now();
  for (std::uint32_t sequence = 1; sequence <= count; ++sequence) {
    // SR OS defaults to one second between consecutive requests. Waiting on
    // the host monotonic clock preserves real-time behavior and deliberately
    // avoids a simulated event queue or accelerated test clock.
    if (sequence > 1) {
      next_probe += std::chrono::seconds{1};
      // A local monotonic deadline preserves the one-second interval. Short
      // sleeps only provide a bounded observation point for an atomic Ctrl-C
      // request and do not advance or reschedule network time.
      while (!cli_cancelled() &&
             std::chrono::steady_clock::now() < next_probe) {
        std::this_thread::sleep_until(
            std::min(next_probe, std::chrono::steady_clock::now() +
                                     std::chrono::milliseconds{10}));
      }
      if (cli_cancelled())
        break;
    }
    // Each probe is a distinct forwarding job and receives real ARP, queue and
    // link processing. Results return only value projections to control.
    const auto result =
        submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                        .kind = kind,
                        .destination = destination_ip,
                        .source_endpoint = source_endpoint,
                        .payload_octets = payload_octets,
                        .dont_fragment = dont_fragment});
    if (result.drop_reason == NetworkDrop::cancelled)
      break;
    ++transmitted;
    state_.operational.capture_count += result.captured_frames;
    state_.operational.capture_dropped += result.capture_drops;
    state_.operational.arp = {};
    const auto arp_projection_time = std::chrono::steady_clock::now();
    for (std::size_t index = 0; index < result.arp.size(); ++index) {
      const auto &entry = result.arp[index];
      if (entry.valid) {
        state_.operational.arp[index] = {
            .valid = true,
            .address = entry.address,
            .mac = entry.mac,
            .port_index = entry.port_index,
            .expires_at = arp_projection_time +
                          std::chrono::seconds{entry.remaining_seconds}};
      }
      state_.operational.port_counters[index].rx_packets +=
          result.rx_delta[index];
      state_.operational.port_counters[index].tx_packets +=
          result.tx_delta[index];
    }
    if (!result.success) {
      ++state_.operational.dropped_packets;
      state_.operational.last_drop_reason = drop_name(result.drop_reason);
      if (result.drop_reason == NetworkDrop::mtu_exceeded)
        out << "Packet too big for icmp_seq " << sequence << '\n';
      else
        out << "Request timeout for icmp_seq " << sequence << '\n';
      continue;
    }
    ++received;
    state_.operational.last_drop_reason = nullptr;
    minimum_rtt = std::min(minimum_rtt, result.rtt_us);
    maximum_rtt = std::max(maximum_rtt, result.rtt_us);
    rtt_sum += static_cast<double>(result.rtt_us);
    rtt_square_sum += static_cast<double>(result.rtt_us) * result.rtt_us;
    out << "64 bytes from " << destination << ": icmp_seq=" << sequence
        << " ttl=" << static_cast<unsigned>(result.reply_ttl) << " time=";
    // SR OS writes the unit without an intervening space and terminates each
    // reply line with a period. Microseconds provide stable three-decimal
    // millisecond precision without inventing sub-clock measurements.
    out << std::fixed << std::setprecision(3)
        << static_cast<double>(result.rtt_us) / 1000.0 << "ms.\n";
  }
  out << "\n---- " << destination << " PING Statistics ----\n"
      << transmitted
      << (transmitted == 1 ? " packet transmitted, " : " packets transmitted, ")
      << received
      << (received == 1 ? " packet received, " : " packets received, ")
      << std::fixed << std::setprecision(2)
      << (transmitted ? 100.0 * static_cast<double>(transmitted - received) /
                            transmitted
                      : 0.0)
      << "% packet loss";
  if (received) {
    const auto average = rtt_sum / received;
    const auto variance =
        std::max(0.0, rtt_square_sum / received - average * average);
    out << "\nround-trip min = " << std::fixed << std::setprecision(3)
        << static_cast<double>(minimum_rtt) / 1000.0
        << "ms, avg = " << average / 1000.0
        << "ms, max = " << static_cast<double>(maximum_rtt) / 1000.0
        << "ms, stddev = " << std::sqrt(variance) / 1000.0 << "ms";
  }
  return out.str();
}

bool Runtime::cli_cancelled() noexcept {
  // atomic_ref matches JavaScript Atomics on the same aligned Wasm word. The
  // acquire pairs with Atomics.store and makes cancellation visible to both
  // runtime shards without routing a second command through the blocked owner.
  return std::atomic_ref<std::uint32_t>{telemetry_.cli_cancel_requested}.load(
             std::memory_order_acquire) != 0U;
}

ForwardResult Runtime::submit_forward(ForwardJob job) {
  // Control is the sole producer and forwarding the sole consumer. Epochs
  // close the empty-check-to-sleep race without locking ring contents.
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
  // Encoding runs on forwarding after all earlier jobs, producing a stable
  // immutable buffer for the Wasm C ABI to borrow.
  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::export_capture});
  return result.success
             ? "capture ready: " + std::to_string(capture_store_.size())
             : "ERROR: capture export failed";
}

void Runtime::reconcile_fib(bool force) {
  // RIB rebuild owns route selection. Forwarding receives a complete new
  // generation and acknowledges installation before control returns.
  if (!rib_.rebuild(make_rib_input(state_)) && fib_generation_ && !force)
    return;

  // SR OS route tables report the age of the selected route, not a constant
  // placeholder. These clocks belong to control because route selection also
  // belongs here. A route keeps its original clock across unrelated rebuilds
  // and receives a new clock only after withdrawal followed by reactivation.
  std::array<bool, profile::port_count> connected_active{};
  std::array<bool, profile::static_route_capacity> static_active{};
  for (const auto &selected : rib_.entries()) {
    if (selected.next_hop == 0) {
      for (std::size_t index = 0;
           index < state_.configuration.running.interface_count; ++index) {
        const auto &interface = state_.configuration.running.interfaces[index];
        if (interface.valid && interface.network == selected.network &&
            interface.prefix_length == selected.prefix_length &&
            interface.port_index == selected.port_index) {
          connected_active[index] = true;
          break;
        }
      }
      continue;
    }
    for (std::size_t index = 0;
         index < state_.configuration.running.static_routes.size(); ++index) {
      const auto &route = state_.configuration.running.static_routes[index];
      if (route.valid && route.network == selected.network &&
          route.prefix_length == selected.prefix_length &&
          route.next_hop == selected.next_hop) {
        static_active[index] = true;
        break;
      }
    }
  }
  const auto now = std::chrono::steady_clock::now();
  const auto retain_or_reset =
      [now](bool active, std::chrono::steady_clock::time_point &since) {
        if (active && since == std::chrono::steady_clock::time_point{})
          since = now;
        else if (!active)
          since = {};
      };
  for (std::size_t index = 0; index < connected_active.size(); ++index)
    retain_or_reset(connected_active[index],
                    state_.operational.connected_route_since[index]);
  for (std::size_t index = 0; index < static_active.size(); ++index)
    retain_or_reset(static_active[index],
                    state_.operational.static_route_since[index]);

  const auto result =
      submit_forward({.id = next_id_.fetch_add(1, std::memory_order_relaxed),
                      .kind = ForwardJobKind::program_fib,
                      .fib = rib_.compile(++fib_generation_)});
  if (!result.success) {
    state_.operational.last_drop_reason = "fib-programming-failed";
    return;
  }
  // FIB installation also invalidates adjacency and pending packets on every
  // withdrawn port. Publish the post-install table immediately so CLI and UI
  // cannot display a stale MAC until the next unrelated ping result arrives.
  state_.operational.arp = {};
  const auto arp_projection_time = std::chrono::steady_clock::now();
  for (const auto &entry : result.arp) {
    if (entry.valid)
      state_.operational.arp[entry.port_index] = {
          .valid = true,
          .address = entry.address,
          .mac = entry.mac,
          .port_index = entry.port_index,
          .expires_at = arp_projection_time +
                        std::chrono::seconds{entry.remaining_seconds}};
  }
}

void Runtime::forwarding_loop() {
  // This thread exclusively owns LabNetwork and every mutable packet-path
  // queue, adjacency and link deadline. Control can only exchange bounded jobs.
  LabNetwork network;
  forwarding_thread_id_.store(
      static_cast<std::uint64_t>(
          std::hash<std::thread::id>{}(std::this_thread::get_id())),
      std::memory_order_release);
  const auto publish = [this](const ForwardResult &result) {
    // Accepted jobs require one result. If the return ring is temporarily full,
    // yielding preserves delivery instead of dropping control-plane state.
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
    // Progress restored or previously admitted frames even when no operation
    // currently waits for a reply. The call is nonblocking and remains on the
    // sole forwarding owner.
    network.service();
    // A failed pop is paired with an epoch snapshot and a second pop before
    // sleep, preventing a notification between the first check and wait.
    ForwardJob job;
    if (!forward_jobs_.try_pop(job)) {
      const auto observed = forward_epoch_.load(std::memory_order_acquire);
      if (!forward_jobs_.try_pop(job)) {
        std::unique_lock lock(wake_mutex_);
        const auto ready = [this, observed] {
          return stopping_.load(std::memory_order_acquire) ||
                 forward_epoch_.load(std::memory_order_acquire) != observed;
        };
        // Link deadlines are local physical-medium state. Waiting for the
        // nearest one does not create a global scheduler and a newly published
        // mailbox epoch always interrupts the sleep.
        if (const auto deadline = network.next_deadline())
          static_cast<void>(wake_forward_.wait_until(lock, *deadline, ready));
        else
          wake_forward_.wait(lock, ready);
        forwarding_wakeups_.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
    }
    ForwardResult result{.id = job.id};
    switch (job.kind) {
    case ForwardJobKind::program_fib:
      network.install_fib(job.fib);
      result.arp = network.adjacencies();
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
      // A release on the result ring publishes the complete structural value
      // to control. No handle or mutable network pointer crosses this handoff.
      forwarding_checkpoint_ = network.checkpoint();
      result.arp = forwarding_checkpoint_.adjacencies;
      result.success = true;
      publish(result);
      continue;
    case ForwardJobKind::restore_checkpoint:
      result.success = network.restore(forwarding_checkpoint_);
      result.arp = network.adjacencies();
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
        job.source_endpoint, job.destination,
        static_cast<std::uint16_t>(job.id), job.payload_octets,
        job.dont_fragment,
        capture_active_.load(std::memory_order_relaxed) ? capture : nullptr,
        this,
        [](void *context) noexcept {
          return static_cast<Runtime *>(context)->cli_cancelled();
        },
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
  // CaptureStore owns its bounded arena. The boolean reports tail drop to the
  // forwarding operation without throwing or allocating on packet flow.
  return capture_store_.record(interface_id, frame, timestamp_us);
}

} // namespace router
