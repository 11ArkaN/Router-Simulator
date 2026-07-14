// Runtime ownership, mailbox waits, lifecycle deadlines and stable projections.
// This translation unit is the only coordinator of control and forwarding jobs.

#include "router/runtime.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace router {
namespace {

template <std::size_t N>
bool copy_text(std::array<char, N>& destination, const std::string& source) {
  const auto length = std::min(source.size(), N - 1);
  std::memcpy(destination.data(), source.data(), length);
  destination[length] = '\0';
  return length == source.size();
}

std::optional<packet::Ipv4> parse_ipv4_text(std::string_view text) {
  // Project input is untrusted persisted data. Parsing fails closed before any
  // value reaches the forwarding owner and never falls back to profile values.
  packet::Ipv4 result{};
  for (std::size_t index = 0; index < result.size(); ++index) {
    const auto separator = text.find('.');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || value > 255) {
      return std::nullopt;
    }
    result[index] = static_cast<std::uint8_t>(value);
    if (index + 1 == result.size()) {
      if (separator != std::string_view::npos) return std::nullopt;
    } else {
      if (separator == std::string_view::npos) return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

std::optional<packet::Mac> parse_mac_text(std::string_view text) {
  // Exactly two hexadecimal digits per octet avoids accepting ambiguous short
  // forms that the project exporter can never reproduce canonically.
  packet::Mac result{};
  for (std::size_t index = 0; index < result.size(); ++index) {
    const auto separator = text.find(':');
    const auto token = text.substr(0, separator);
    unsigned value{};
    const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, 16);
    if (token.size() != 2 || parsed.ec != std::errc{} ||
        parsed.ptr != token.data() + token.size() || value > 255) {
      return std::nullopt;
    }
    result[index] = static_cast<std::uint8_t>(value);
    if (index + 1 == result.size()) {
      if (separator != std::string_view::npos) return std::nullopt;
    } else {
      if (separator == std::string_view::npos) return std::nullopt;
      text.remove_prefix(separator + 1);
    }
  }
  return result;
}

std::string ipv4_text(packet::Ipv4 address) {
  std::ostringstream out;
  out << static_cast<unsigned>(address[0]) << '.' << static_cast<unsigned>(address[1])
      << '.' << static_cast<unsigned>(address[2]) << '.' << static_cast<unsigned>(address[3]);
  return out.str();
}

std::string ipv4_text(std::uint32_t address) {
  return ipv4_text({static_cast<std::uint8_t>(address >> 24),
                    static_cast<std::uint8_t>(address >> 16),
                    static_cast<std::uint8_t>(address >> 8),
                    static_cast<std::uint8_t>(address)});
}

std::string mac_text(packet::Mac address) {
  std::ostringstream out;
  out << std::uppercase << std::hex << std::setfill('0');
  for (std::size_t index = 0; index < address.size(); ++index) {
    if (index) out << ':';
    out << std::setw(2) << static_cast<unsigned>(address[index]);
  }
  return out.str();
}

std::string json_text(std::string_view value) {
  // CLI descriptions are user-controlled. Escaping at the projection boundary
  // keeps the telemetry document valid without constraining the canonical
  // configuration to a JSON-specific character subset.
  std::string result;
  result.reserve(value.size());
  for (const unsigned char byte : value) {
    switch (byte) {
      case '"': result += "\\\""; break;
      case '\\': result += "\\\\"; break;
      case '\b': result += "\\b"; break;
      case '\f': result += "\\f"; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      default:
        if (byte >= 0x20) result.push_back(static_cast<char>(byte));
    }
  }
  return result;
}

constexpr std::uint64_t checkpoint_build_hash = 0x202607140003ULL;
constexpr std::uint64_t checkpoint_profile_hash = 0x775000070004ULL;

class BinaryWriter {
 public:
  template <typename Integer>
  void integer(Integer value) {
    using Unsigned = std::make_unsigned_t<Integer>;
    auto bits = static_cast<Unsigned>(value);
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes.push_back(static_cast<std::uint8_t>(bits >> (index * 8U)));
    }
  }
  template <std::size_t N>
  void fixed(const std::array<char, N>& value) {
    bytes.insert(bytes.end(), reinterpret_cast<const std::uint8_t*>(value.data()),
                 reinterpret_cast<const std::uint8_t*>(value.data() + value.size()));
  }
  void raw(std::span<const std::uint8_t> value) {
    bytes.insert(bytes.end(), value.begin(), value.end());
  }
  std::vector<std::uint8_t> bytes;
};

class BinaryReader {
 public:
  explicit BinaryReader(std::span<const std::uint8_t> input) : bytes(input) {}
  template <typename Integer>
  bool integer(Integer& value) {
    if (offset + sizeof(Integer) > bytes.size()) return false;
    using Unsigned = std::make_unsigned_t<Integer>;
    Unsigned result{};
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      result |= static_cast<Unsigned>(bytes[offset++]) << (index * 8U);
    }
    value = static_cast<Integer>(result);
    return true;
  }
  template <std::size_t N>
  bool fixed(std::array<char, N>& value) {
    if (offset + N > bytes.size()) return false;
    std::memcpy(value.data(), bytes.data() + offset, N);
    offset += N;
    // Every fixed string must contain a terminator. This rejects a malicious
    // checkpoint before any unterminated text reaches CLI or JSON formatting.
    return std::find(value.begin(), value.end(), '\0') != value.end();
  }
  bool raw(std::span<std::uint8_t> value) {
    if (offset + value.size() > bytes.size()) return false;
    std::memcpy(value.data(), bytes.data() + offset, value.size());
    offset += value.size();
    return true;
  }
  [[nodiscard]] bool complete() const noexcept { return offset == bytes.size(); }
 private:
  std::span<const std::uint8_t> bytes;
  std::size_t offset{};
};

}  // namespace

Runtime::Runtime() : started_(std::chrono::steady_clock::now()) {
  // Construction occurs inside the browser Worker. These pthreads establish
  // independent control and forwarding ownership domains before UI commands
  // can observe a ready snapshot.
  captures_.reserve(capture_capacity);
  control_thread_ = std::thread(&Runtime::control_loop, this);
  forwarding_thread_ = std::thread(&Runtime::forwarding_loop, this);
}

Runtime::~Runtime() { stop(); }

std::span<const std::uint8_t> Runtime::export_checkpoint() {
  const auto result = command("checkpoint:prepare");
  return result == "checkpoint ready" ? prepared_checkpoint_
                                       : std::span<const std::uint8_t>{};
}

bool Runtime::import_checkpoint(std::span<const std::uint8_t> bytes) {
  {
    std::scoped_lock lock(checkpoint_mutex_);
    pending_checkpoint_import_.assign(bytes.begin(), bytes.end());
  }
  return command("checkpoint:import") == "checkpoint imported";
}

std::span<const std::uint8_t> Runtime::encode_checkpoint_on_control() {
  // The FIFO barrier proves that no forwarding job or link-owned operation is
  // still running. The first stage exposes synchronous lab operations, so all
  // bounded packet queues are empty at this boundary. Their structural count is
  // encoded as zero rather than copying PacketPool slots or pthread memory.
  const auto barrier = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::checkpoint_barrier,
  });
  if (!barrier.success) return {};
  state_.arp = {};
  for (std::size_t index = 0; index < barrier.arp.size(); ++index) {
    if (barrier.arp[index].valid) {
      state_.arp[index] = {.valid = true,
                           .address = barrier.arp[index].address,
                           .mac = barrier.arp[index].mac,
                           .port_index = barrier.arp[index].port_index};
    }
  }

  BinaryWriter out;
  out.integer<std::uint32_t>(0x50435352U);
  out.integer<std::uint16_t>(1U);
  out.integer<std::uint16_t>(3U);
  out.integer(checkpoint_build_hash);
  out.integer(checkpoint_profile_hash);
  const auto now = std::chrono::steady_clock::now();
  const auto remaining = [now](auto lifecycle, auto deadline) {
    return lifecycle == EquipmentLifecycle::initializing && deadline > now
               ? static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                deadline - now).count())
               : 0ULL;
  };
  out.integer(remaining(state_.card_lifecycle, state_.card_deadline));
  out.integer(remaining(state_.mda_lifecycle, state_.mda_deadline));
  out.integer<std::uint8_t>(state_.card_provisioned);
  out.integer<std::uint8_t>(state_.mda_provisioned);
  out.integer<std::uint8_t>(state_.card_present);
  out.integer<std::uint8_t>(state_.mda_present);
  out.integer<std::uint8_t>(state_.mda_compatible);
  out.integer<std::uint8_t>(state_.card_admin_enabled);
  out.integer<std::uint8_t>(state_.mda_admin_enabled);
  out.integer<std::uint8_t>(static_cast<std::uint8_t>(state_.card_lifecycle));
  out.integer<std::uint8_t>(static_cast<std::uint8_t>(state_.mda_lifecycle));
  out.integer<std::uint8_t>(state_.candidate_card);
  out.integer<std::uint8_t>(state_.candidate_mda);
  out.integer<std::uint8_t>(static_cast<std::uint8_t>(session_.engine));
  out.integer<std::uint8_t>(session_.candidate_dirty);
  out.integer<std::uint8_t>(session_.candidate_outdated);
  out.fixed(state_.system_name);
  out.fixed(state_.candidate_system_name);
  for (const auto& port : state_.ports) {
    out.integer<std::uint8_t>(port.admin_enabled);
    out.integer<std::uint8_t>(port.link_signal);
    out.integer<std::uint8_t>(port.candidate_admin_enabled);
    out.integer(port.mtu);
    out.integer(port.candidate_mtu);
    out.fixed(port.description);
    out.fixed(port.candidate_description);
    out.integer(port.rx_packets);
    out.integer(port.tx_packets);
  }
  for (const auto& interface : state_.interfaces) {
    out.integer<std::uint8_t>(interface.admin_enabled);
    out.integer<std::uint8_t>(interface.candidate_admin_enabled);
  }
  for (const auto& route : state_.static_routes) {
    out.integer<std::uint8_t>(route.valid);
    out.integer<std::uint8_t>(route.candidate_valid);
    out.integer(route.network);
    out.integer(route.candidate_network);
    out.integer(route.next_hop);
    out.integer(route.candidate_next_hop);
    out.integer(route.prefix_length);
    out.integer(route.candidate_prefix_length);
  }
  for (const auto& entry : state_.arp) {
    out.integer<std::uint8_t>(entry.valid);
    out.raw(entry.address);
    out.raw(entry.mac);
    out.integer(entry.port_index);
  }
  out.integer(state_.capture_count);
  out.integer(state_.capture_dropped);
  out.integer(state_.dropped_packets);
  out.integer(fib_generation_);
  out.integer<std::uint32_t>(0U);  // quiescent packet descriptor count
  prepared_checkpoint_ = std::move(out.bytes);
  return prepared_checkpoint_;
}

bool Runtime::decode_checkpoint_on_control(std::span<const std::uint8_t> bytes) {
  // Parse into independent temporary state. No partial or incompatible input
  // can alter the live lab. The header binds structure to ABI, build and profile
  // before any value is trusted.
  BinaryReader in(bytes);
  std::uint32_t magic{};
  std::uint16_t format{};
  std::uint16_t abi{};
  std::uint64_t build{};
  std::uint64_t profile_hash{};
  std::uint64_t card_remaining{};
  std::uint64_t mda_remaining{};
  if (!in.integer(magic) || !in.integer(format) || !in.integer(abi) ||
      !in.integer(build) || !in.integer(profile_hash) ||
      magic != 0x50435352U || format != 1 || abi != 3 ||
      build != checkpoint_build_hash || profile_hash != checkpoint_profile_hash ||
      !in.integer(card_remaining) || !in.integer(mda_remaining)) {
    return false;
  }
  DeviceState restored;
  CliSession restored_session;
  auto boolean = [&in](bool& value) {
    std::uint8_t encoded{};
    if (!in.integer(encoded) || encoded > 1) return false;
    value = encoded != 0;
    return true;
  };
  std::uint8_t card_lifecycle{};
  std::uint8_t mda_lifecycle{};
  std::uint8_t engine{};
  if (!boolean(restored.card_provisioned) || !boolean(restored.mda_provisioned) ||
      !boolean(restored.card_present) || !boolean(restored.mda_present) ||
      !boolean(restored.mda_compatible) || !boolean(restored.card_admin_enabled) ||
      !boolean(restored.mda_admin_enabled) || !in.integer(card_lifecycle) ||
      !in.integer(mda_lifecycle) || card_lifecycle > 5 || mda_lifecycle > 5 ||
      !boolean(restored.candidate_card) || !boolean(restored.candidate_mda) ||
      !in.integer(engine) || engine > 1 || !boolean(restored_session.candidate_dirty) ||
      !boolean(restored_session.candidate_outdated) || !in.fixed(restored.system_name) ||
      !in.fixed(restored.candidate_system_name)) {
    return false;
  }
  restored.card_lifecycle = static_cast<EquipmentLifecycle>(card_lifecycle);
  restored.mda_lifecycle = static_cast<EquipmentLifecycle>(mda_lifecycle);
  restored_session.engine = static_cast<CliEngine>(engine);
  for (auto& port : restored.ports) {
    if (!boolean(port.admin_enabled) || !boolean(port.link_signal) ||
        !boolean(port.candidate_admin_enabled) || !in.integer(port.mtu) ||
        !in.integer(port.candidate_mtu) || port.mtu < 576 || port.mtu > 1500 ||
        port.candidate_mtu < 576 || port.candidate_mtu > 1500 ||
        !in.fixed(port.description) || !in.fixed(port.candidate_description) ||
        !in.integer(port.rx_packets) || !in.integer(port.tx_packets)) {
      return false;
    }
  }
  for (auto& interface : restored.interfaces) {
    if (!boolean(interface.admin_enabled) || !boolean(interface.candidate_admin_enabled)) {
      return false;
    }
  }
  for (auto& route : restored.static_routes) {
    if (!boolean(route.valid) || !boolean(route.candidate_valid) ||
        !in.integer(route.network) || !in.integer(route.candidate_network) ||
        !in.integer(route.next_hop) || !in.integer(route.candidate_next_hop) ||
        !in.integer(route.prefix_length) || !in.integer(route.candidate_prefix_length) ||
        route.prefix_length > 32 || route.candidate_prefix_length > 32) {
      return false;
    }
  }
  for (auto& entry : restored.arp) {
    if (!boolean(entry.valid) || !in.raw(entry.address) || !in.raw(entry.mac) ||
        !in.integer(entry.port_index) || entry.port_index >= 2) {
      return false;
    }
  }
  std::uint64_t restored_generation{};
  std::uint32_t packet_descriptors{};
  if (!in.integer(restored.capture_count) || !in.integer(restored.capture_dropped) ||
      !in.integer(restored.dropped_packets) || !in.integer(restored_generation) ||
      !in.integer(packet_descriptors) || packet_descriptors != 0 || !in.complete()) {
    return false;
  }
  const auto now = std::chrono::steady_clock::now();
  if (restored.card_lifecycle == EquipmentLifecycle::initializing) {
    restored.card_deadline = now + std::chrono::nanoseconds(card_remaining);
  }
  if (restored.mda_lifecycle == EquipmentLifecycle::initializing) {
    restored.mda_deadline = now + std::chrono::nanoseconds(mda_remaining);
  }
  state_ = restored;
  session_ = restored_session;
  fib_generation_ = restored_generation;
  hardware_deadline_ = hardware::reconcile(state_, now).next_deadline;
  reconcile_fib();
  std::array<NetworkArpEntry, 2> arp{};
  for (std::size_t index = 0; index < arp.size(); ++index) {
    arp[index] = {.valid = state_.arp[index].valid,
                  .address = state_.arp[index].address,
                  .mac = state_.arp[index].mac,
                  .port_index = state_.arp[index].port_index};
  }
  const auto result = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::restore_adjacencies,
      .restored_arp = arp,
  });
  publish_telemetry();
  return result.success;
}

void Runtime::stop() {
  // Joining is required even if a worker already raised the stop flag after a
  // fatal mailbox condition. Returning solely because the flag was true would
  // leave joinable std::thread members and make their destructors terminate the
  // process. Repeated stop calls remain safe because joinable() is idempotent.
  stopping_.store(true, std::memory_order_release);
  command_epoch_.fetch_add(1, std::memory_order_release);
  forward_epoch_.fetch_add(1, std::memory_order_release);
  result_epoch_.fetch_add(1, std::memory_order_release);
  response_epoch_.fetch_add(1, std::memory_order_release);
  wake_control_.notify_all();
  wake_forward_.notify_all();
  wake_response_.notify_all();
  if (control_thread_.joinable()) control_thread_.join();
  if (forwarding_thread_.joinable()) forwarding_thread_.join();
}

std::string Runtime::command(const std::string& text) {
  // The JavaScript bridge serializes calls through submit_mutex_, preserving
  // the one-producer contract of commands_. Epoch predicates prevent a notify
  // between the empty check and wait from being lost.
  std::scoped_lock submit_lock(submit_mutex_);
  CommandMessage message{.id = next_id_.fetch_add(1, std::memory_order_relaxed)};
  if (!copy_text(message.text, text)) return "ERROR: command exceeds control mailbox limit";
  if (!commands_.try_push(message)) return "ERROR: control mailbox full";
  command_epoch_.fetch_add(1, std::memory_order_release);
  wake_control_.notify_one();

  ResponseMessage response;
  while (!stopping_) {
    if (responses_.try_pop(response)) return response.text.data();
    const auto observed = response_epoch_.load(std::memory_order_acquire);
    if (responses_.try_pop(response)) return response.text.data();
    std::unique_lock lock(wake_mutex_);
    wake_response_.wait(lock, [this, observed] {
      return stopping_.load(std::memory_order_acquire) ||
             response_epoch_.load(std::memory_order_acquire) != observed;
    });
  }
  return "ERROR: runtime stopped";
}

void Runtime::control_loop() {
  // DeviceState, CliSession and ConnectedRib have exclusive control-thread
  // affinity. Forwarding returns bounded value deltas through forward_results_.
  control_thread_id_.store(
      static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
      std::memory_order_release);
  while (!stopping_) {
    CommandMessage request;
    if (!commands_.try_pop(request)) {
      const auto observed = command_epoch_.load(std::memory_order_acquire);
      if (commands_.try_pop(request)) {
        // Work arrived between the first empty check and epoch observation.
      } else {
        std::unique_lock lock(wake_mutex_);
        const auto ready = [this, observed] {
          return stopping_.load(std::memory_order_acquire) ||
                 command_epoch_.load(std::memory_order_acquire) != observed;
        };
        if (hardware_deadline_) {
          if (!wake_control_.wait_until(lock, *hardware_deadline_, ready)) {
            // The steady-clock deadline belongs to the control-owned hardware
            // reconciler. Finishing a lifecycle phase can add or withdraw all
            // dependent ports and therefore must publish a fresh FIB program.
            lock.unlock();
            const auto now = std::chrono::steady_clock::now();
            const auto lag = now > *hardware_deadline_
                                 ? std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       now - *hardware_deadline_).count()
                                 : 0;
            auto previous = max_scheduling_lag_ns_.load(std::memory_order_relaxed);
            while (static_cast<std::uint64_t>(lag) > previous &&
                   !max_scheduling_lag_ns_.compare_exchange_weak(
                       previous, static_cast<std::uint64_t>(lag),
                       std::memory_order_relaxed)) {
            }
            const auto result = hardware::reconcile(state_, std::chrono::steady_clock::now());
            hardware_deadline_ = result.next_deadline;
            if (result.operational_change) reconcile_fib();
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
      // A full response ring is a fatal ownership-contract violation. Wake all
      // three wait domains so no caller remains parked after the stop flag is
      // published. Runtime::stop will still join both threads later.
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

std::string Runtime::dispatch(const std::string& text) {
  // Internal commands are deliberately namespaced. None is exposed as an SR OS
  // command, and terminal input can reach only the terminal: branch below.
  if (text == "snapshot") {
    const auto result = hardware::reconcile(state_, std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    if (result.operational_change) reconcile_fib();
    return snapshot();
  }
  const auto state_changed = [this] {
    const auto result = hardware::reconcile(state_, std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return snapshot();
  };
  if (text == "hardware:insert-card") {
    state_.card_present = true;
    state_.card_lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    return state_changed();
  }
  if (text == "hardware:remove-card") {
    // Parent removal also removes physically equipped child state. Provisioned
    // configuration remains, allowing the same hardware to become operational
    // again after reinsertion without an invented CLI transaction.
    state_.card_present = false;
    state_.mda_present = false;
    state_.arp = {};
    return state_changed();
  }
  if (text == "hardware:insert-mda:me10-10gb-sfp+") {
    if (!state_.card_present) return "ERROR: equip card 1 before MDA 1/1";
    state_.mda_present = true;
    state_.mda_compatible = true;
    state_.mda_lifecycle = EquipmentLifecycle::waiting_for_provisioning;
    return state_changed();
  }
  if (text == "hardware:insert-mda:me1-100gb-cfp2") {
    if (!state_.card_present) return "ERROR: equip card 1 before MDA 1/1";
    state_.mda_present = true;
    state_.mda_compatible = false;
    state_.mda_lifecycle = EquipmentLifecycle::mismatch;
    state_.arp = {};
    return state_changed();
  }
  if (text == "hardware:remove-mda") {
    state_.mda_present = false;
    state_.arp = {};
    return state_changed();
  }
  if (text == "link:down:1/1/1" || text == "link:down:1/1/2") {
    // Control clears only the affected operational projection. install_fib then
    // tells forwarding to invalidate its matching ARP cache and pending queue.
    const auto index = text.back() == '1' ? 0U : 1U;
    state_.ports[index].link_signal = false;
    state_.arp[index] = {};
    return state_changed();
  }
  if (text == "link:up:1/1/1" || text == "link:up:1/1/2") {
    const auto index = text.back() == '1' ? 0U : 1U;
    state_.ports[index].link_signal = true;
    return state_changed();
  }
  if (text.rfind("project:provisioning|", 0) == 0) {
    // Persisted provisioning is restored independently from equipment. This is
    // an internal project protocol and cannot be confused with either CLI
    // engine's configuration semantics.
    const auto values = text.substr(std::string_view{"project:provisioning|"}.size());
    const auto separator = values.find('|');
    if (separator == std::string::npos) return "ERROR: invalid provisioning state";
    const auto card = values.substr(0, separator);
    const auto mda = values.substr(separator + 1);
    if ((card != "absent" && card != "iom4-e") ||
        (mda != "absent" && mda != "me10-10gb-sfp+") ||
        (card == "absent" && mda != "absent")) {
      return "ERROR: unsupported provisioning state";
    }
    state_.card_provisioned = card == "iom4-e";
    state_.mda_provisioned = mda == "me10-10gb-sfp+";
    state_.candidate_card = state_.card_provisioned;
    state_.candidate_mda = state_.mda_provisioned;
    session_.candidate_dirty = false;
    session_.candidate_outdated = false;
    return state_changed();
  }
  if (text.rfind("project:hosts|", 0) == 0) return configure_hosts(text);
  if (text.rfind("project:links|", 0) == 0) return configure_links(text);
  if (text == "capture:prepare") return prepare_capture();
  if (text == "checkpoint:prepare") {
    return encode_checkpoint_on_control().empty() ? "ERROR: checkpoint barrier failed"
                                                   : "checkpoint ready";
  }
  if (text == "checkpoint:import") {
    std::vector<std::uint8_t> bytes;
    {
      std::scoped_lock lock(checkpoint_mutex_);
      bytes = pending_checkpoint_import_;
      pending_checkpoint_import_.clear();
    }
    return decode_checkpoint_on_control(bytes) ? "checkpoint imported"
                                                : "ERROR: incompatible checkpoint";
  }
  if (text == "capture:start") {
    capture_active_.store(true, std::memory_order_relaxed);
    return "capture started";
  }
  if (text == "capture:stop") {
    capture_active_.store(false, std::memory_order_relaxed);
    return "capture stopped";
  }
  constexpr std::string_view completion_prefix = "terminal:complete:";
  if (text.rfind(completion_prefix, 0) == 0) {
    // Completion is handled by the active engine in the same session as
    // execution. The UI never maintains a second command schema.
    return complete_cli(state_, session_, text.substr(completion_prefix.size()));
  }
  constexpr std::string_view prefix = "terminal:";
  if (text.rfind(prefix, 0) == 0) {
    auto output = execute_cli(state_, session_, text.substr(prefix.size()),
                              [this](std::uint32_t count) {
                                return run_ping(ForwardJob::Kind::router_to_host_b, count);
                              });
    const auto result = hardware::reconcile(state_, std::chrono::steady_clock::now());
    hardware_deadline_ = result.next_deadline;
    reconcile_fib();
    return output;
  }
  if (text == "host:ping:host-a:host-b") {
    return run_ping(ForwardJob::Kind::host_a_to_host_b, 1);
  }
  return "ERROR: unsupported runtime command";
}

std::string Runtime::configure_hosts(const std::string& text) {
  // The pipe-separated worker protocol avoids a JSON parser in the C++ runtime.
  // Both endpoints occupy one message so syntax, identity and subnet checks
  // succeed completely before either control or forwarding state is mutated.
  std::array<std::string_view, 7> fields{};
  std::string_view remaining{text};
  for (auto& field : fields) {
    const auto separator = remaining.find('|');
    field = remaining.substr(0, separator);
    if (separator == std::string_view::npos) {
      remaining = {};
    } else {
      remaining.remove_prefix(separator + 1);
    }
  }
  if (!remaining.empty() || fields[0] != "project:hosts") {
    return "ERROR: invalid atomic host configuration command";
  }

  std::array<packet::Mac, 2> macs{};
  std::array<packet::Ipv4, 2> addresses{};
  std::array<packet::Ipv4, 2> gateways{};
  std::array<std::uint8_t, 2> prefixes{};
  const auto valid_unicast = [](const packet::Ipv4& candidate) {
    return candidate != packet::Ipv4{} && candidate[0] != 0 && candidate[0] != 127 &&
           candidate[0] < 224;
  };

  for (std::size_t index = 0; index < 2; ++index) {
    const auto base = 1U + index * 3U;
    const auto mac = parse_mac_text(fields[base]);
    const auto slash = fields[base + 1].find('/');
    if (slash == std::string_view::npos) {
      return "ERROR: host address requires a prefix length";
    }
    const auto address = parse_ipv4_text(fields[base + 1].substr(0, slash));
    const auto gateway = parse_ipv4_text(fields[base + 2]);
    unsigned prefix{};
    const auto prefix_text = fields[base + 1].substr(slash + 1);
    const auto prefix_result = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (!mac || !address || !gateway || prefix_result.ec != std::errc{} ||
        prefix_result.ptr != prefix_text.data() + prefix_text.size() || prefix > 32) {
      return "ERROR: invalid host MAC, IPv4 address, prefix, or gateway";
    }
    const auto mask = routing::prefix_mask(static_cast<std::uint8_t>(prefix));
    const auto address_u32 = routing::ipv4((*address)[0], (*address)[1], (*address)[2], (*address)[3]);
    const auto gateway_u32 = routing::ipv4((*gateway)[0], (*gateway)[1], (*gateway)[2], (*gateway)[3]);
    const auto host_bits = ~mask;
    const auto address_host = address_u32 & host_bits;
    const auto gateway_host = gateway_u32 & host_bits;
    const auto invalid_mac = std::all_of(mac->begin(), mac->end(),
                                         [](auto byte) { return byte == 0; }) ||
                             ((*mac)[0] & 1U);
    // Source: ietf.host_requirements.rfc1122 and
    // ieee.802_3.ethernet_frame_timing. Runtime repeats semantic checks so a
    // caller bypassing TypeScript cannot install group, network, broadcast or
    // router-owned identities into endpoint and ARP state.
    if ((address_u32 & mask) != (gateway_u32 & mask) || *address == *gateway ||
        !valid_unicast(*address) || !valid_unicast(*gateway) || invalid_mac ||
        (prefix <= 30 && (address_host == 0 || address_host == host_bits ||
                          gateway_host == 0 || gateway_host == host_bits)) ||
        std::find(profile::router_macs.begin(), profile::router_macs.end(), *mac) !=
            profile::router_macs.end() ||
        std::find(profile::router_addresses.begin(), profile::router_addresses.end(), *address) !=
            profile::router_addresses.end()) {
      return "ERROR: invalid or conflicting host identity, prefix, or gateway";
    }
    macs[index] = *mac;
    addresses[index] = *address;
    gateways[index] = *gateway;
    prefixes[index] = static_cast<std::uint8_t>(prefix);
  }
  if (macs[0] == macs[1] || addresses[0] == addresses[1]) {
    return "ERROR: host endpoint identities must be unique";
  }

  const auto result = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::configure_hosts,
      .host_macs = macs,
      .host_addresses = addresses,
      .host_gateways = gateways,
      .host_prefix_lengths = prefixes,
  });
  if (!result.success) return "ERROR: atomic host configuration was rejected";
  for (std::size_t index = 0; index < 2; ++index) {
    state_.lab_hosts[index] = {.mac = macs[index],
                               .address = addresses[index],
                               .prefix_length = prefixes[index],
                               .gateway = gateways[index]};
  }
  return snapshot();
}

std::string Runtime::configure_links(const std::string& text) {
  // Link timing is a control message, not a shared mutable property. Parsing
  // both values first ensures the forwarding owner never observes a project
  // with only one of its physical links updated.
  std::array<std::string_view, 3> fields{};
  std::string_view remaining{text};
  for (auto& field : fields) {
    const auto separator = remaining.find('|');
    field = remaining.substr(0, separator);
    if (separator == std::string_view::npos) {
      remaining = {};
    } else {
      remaining.remove_prefix(separator + 1);
    }
  }
  if (!remaining.empty() || fields[0] != "project:links") {
    return "ERROR: invalid atomic link configuration command";
  }

  std::array<std::uint64_t, 2> delays{};
  for (std::size_t index = 0; index < delays.size(); ++index) {
    const auto parsed = std::from_chars(fields[index + 1].data(),
                                        fields[index + 1].data() + fields[index + 1].size(),
                                        delays[index]);
    // Source: ecma.number.max_safe_integer. The upper bound is the largest
    // integer JSON and JavaScript can carry exactly, not a guessed circuit or
    // platform limit. This second check is mandatory because callers can reach
    // the runtime without TypeScript.
    if (fields[index + 1].empty() || parsed.ec != std::errc{} ||
        parsed.ptr != fields[index + 1].data() + fields[index + 1].size() ||
        delays[index] > 9007199254740991ULL) {
      return "ERROR: link propagation must be an exact non-negative integer in ns";
    }
  }

  const auto result = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::configure_links,
      .propagation_delay_ns = delays,
  });
  if (!result.success) return "ERROR: atomic link configuration was rejected";
  return snapshot();
}

std::string Runtime::run_ping(ForwardJob::Kind kind, std::uint32_t count) {
  const auto drop_name = [](ForwardResult::DropReason reason) {
    switch (reason) {
      case ForwardResult::DropReason::ingress_down: return "interface-down";
      case ForwardResult::DropReason::route_miss: return "route-miss";
      case ForwardResult::DropReason::queue_full: return "queue-full";
      case ForwardResult::DropReason::ttl_expired: return "ttl-expired";
      case ForwardResult::DropReason::timeout: return "timeout";
      case ForwardResult::DropReason::malformed: return "malformed-packet";
      case ForwardResult::DropReason::none: return "none";
    }
    return "unknown";
  };
  count = std::clamp<std::uint32_t>(count, 1, 100);
  const auto destination = ipv4_text(state_.lab_hosts[1].address);
  std::ostringstream out;
  out << "PING " << destination << " 56 data bytes\n";
  std::uint32_t received = 0;
  for (std::uint32_t sequence = 1; sequence <= count; ++sequence) {
    // Every sequence is a separate network operation. Repeated probes reuse
    // learned ARP exactly as real endpoints do, so later sequences transmit
    // fewer frames without a special fast path.
    const auto result = submit_forward({
        .id = next_id_.fetch_add(1, std::memory_order_relaxed),
        .kind = kind,
    });
    state_.capture_count += result.captured_frames;
    state_.capture_dropped += result.capture_drops;
    state_.arp = {};
    for (std::size_t index = 0; index < result.arp.size(); ++index) {
      const auto& entry = result.arp[index];
      if (entry.valid) {
        state_.arp[index] = {.valid = true,
                             .address = entry.address,
                             .mac = entry.mac,
                             .port_index = entry.port_index};
      }
      state_.ports[index].rx_packets += result.rx_delta[index];
      state_.ports[index].tx_packets += result.tx_delta[index];
    }
    if (!result.success) {
      // A timeout line belongs to this probe only. Aggregate loss percentage is
      // calculated after all requested probes, matching CLI count semantics.
      ++state_.dropped_packets;
      state_.last_drop_reason = drop_name(result.drop_reason);
      out << "Request timeout for icmp_seq " << sequence << '\n';
      continue;
    }
    ++received;
    state_.last_drop_reason = nullptr;
    out << "64 bytes from " << destination << ": icmp_seq=" << sequence
        << " ttl=" << static_cast<unsigned>(result.reply_ttl) << " time=";
    if (result.rtt_us < 1000) {
      out << "<1 ms\n";
    } else {
      out << std::fixed << std::setprecision(3) << result.rtt_us / 1000.0 << " ms\n";
    }
  }
  out << "--- " << destination << " ping statistics ---\n" << count
      << " packets transmitted, " << received << " packets received, "
      << std::fixed << std::setprecision(1)
      << (100.0 * static_cast<double>(count - received) / count) << "% packet loss";
  return out.str();
}

Runtime::ForwardResult Runtime::submit_forward(ForwardJob job) {
  // A FIB or configuration change is acknowledged before control publishes a
  // snapshot. This keeps running configuration and installed data plane in the
  // same observable generation without sharing mutable pointers.
  if (!forward_jobs_.try_push(job)) return {};
  forward_epoch_.fetch_add(1, std::memory_order_release);
  wake_forward_.notify_one();
  ForwardResult result;
  while (!stopping_) {
    if (forward_results_.try_pop(result)) return result;
    const auto observed = result_epoch_.load(std::memory_order_acquire);
    if (forward_results_.try_pop(result)) return result;
    std::unique_lock lock(wake_mutex_);
    wake_control_.wait(lock, [this, observed] {
      return stopping_.load(std::memory_order_acquire) ||
             result_epoch_.load(std::memory_order_acquire) != observed;
    });
  }
  return {};
}

std::string Runtime::prepare_capture() {
  const auto result = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::export_capture,
  });
  return result.success ? "capture ready: " + std::to_string(captures_.size())
                        : "ERROR: capture export failed";
}

void Runtime::reconcile_fib() {
  // Initial programming occurs even for an empty RIB so LabNetwork learns that
  // both ports are down before the first ping. Later identical rebuilds skip the
  // cross-thread round trip.
  if (!rib_.rebuild(state_) && fib_generation_) return;
  const auto result = submit_forward({
      .id = next_id_.fetch_add(1, std::memory_order_relaxed),
      .kind = ForwardJob::Kind::program_fib,
      .fib = rib_.compile(++fib_generation_),
  });
  if (!result.success) state_.last_drop_reason = "fib-programming-failed";
}

void Runtime::forwarding_loop() {
  // LabNetwork and capture storage are created and mutated only on this shard.
  // The observer is a plain function pointer to avoid allocating std::function
  // state for every transmitted frame.
  LabNetwork network;
  forwarding_thread_id_.store(
      static_cast<std::uint64_t>(std::hash<std::thread::id>{}(std::this_thread::get_id())),
      std::memory_order_release);
  const auto publish = [this](const ForwardResult& result) {
    while (!forward_results_.try_push(result) && !stopping_) std::this_thread::yield();
    result_epoch_.fetch_add(1, std::memory_order_release);
    wake_control_.notify_one();
  };
  const auto capture = [](void* context, std::uint8_t interface_id,
                          const packet::Frame& frame, std::uint64_t timestamp_us) {
    return static_cast<Runtime*>(context)->record_capture(interface_id, frame, timestamp_us);
  };
  while (!stopping_) {
    ForwardJob job;
    if (!forward_jobs_.try_pop(job)) {
      const auto observed = forward_epoch_.load(std::memory_order_acquire);
      if (forward_jobs_.try_pop(job)) {
        // Work arrived before the wait predicate was installed.
      } else {
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
    if (job.kind == ForwardJob::Kind::program_fib) {
      network.install_fib(job.fib);
      result.success = true;
      publish(result);
      continue;
    }
    if (job.kind == ForwardJob::Kind::configure_hosts) {
      network.configure_hosts(job.host_macs, job.host_addresses,
                              job.host_prefix_lengths, job.host_gateways);
      result.success = true;
      publish(result);
      continue;
    }
    if (job.kind == ForwardJob::Kind::configure_links) {
      network.configure_links({
          std::chrono::nanoseconds(job.propagation_delay_ns[0]),
          std::chrono::nanoseconds(job.propagation_delay_ns[1]),
      });
      result.success = true;
      publish(result);
      continue;
    }
    if (job.kind == ForwardJob::Kind::export_capture) {
      encode_capture();
      result.success = true;
      publish(result);
      continue;
    }
    if (job.kind == ForwardJob::Kind::checkpoint_barrier) {
      // SPSC FIFO order makes this acknowledgement a quiescence barrier for
      // every earlier forwarding job. ping itself returns only after all link
      // queues for that operation are drained or failed, so no packet handle is
      // hidden behind this barrier in the first-stage synchronous API.
      result.arp = network.adjacencies();
      result.success = true;
      publish(result);
      continue;
    }
    if (job.kind == ForwardJob::Kind::restore_adjacencies) {
      network.restore_adjacencies(job.restored_arp);
      result.arp = network.adjacencies();
      result.success = true;
      publish(result);
      continue;
    }
    const auto outcome = network.ping(
        job.kind == ForwardJob::Kind::host_a_to_host_b ? PingOrigin::host_a
                                                        : PingOrigin::router,
        static_cast<std::uint16_t>(job.id),
        capture_active_.load(std::memory_order_relaxed) ? capture : nullptr, this);
    result.success = outcome.success;
    result.reply_ttl = outcome.reply_ttl;
    result.rtt_us = outcome.rtt_us;
    result.captured_frames = outcome.captured_frames;
    result.capture_drops = outcome.capture_drops;
    result.rx_delta = outcome.rx_delta;
    result.tx_delta = outcome.tx_delta;
    result.arp = outcome.router_arp;
    switch (outcome.drop) {
      case NetworkDrop::none: result.drop_reason = ForwardResult::DropReason::none; break;
      case NetworkDrop::ingress_down: result.drop_reason = ForwardResult::DropReason::ingress_down; break;
      case NetworkDrop::route_miss: result.drop_reason = ForwardResult::DropReason::route_miss; break;
      case NetworkDrop::queue_full: result.drop_reason = ForwardResult::DropReason::queue_full; break;
      case NetworkDrop::ttl_expired: result.drop_reason = ForwardResult::DropReason::ttl_expired; break;
      case NetworkDrop::timeout: result.drop_reason = ForwardResult::DropReason::timeout; break;
      case NetworkDrop::malformed: result.drop_reason = ForwardResult::DropReason::malformed; break;
    }
    publish(result);
  }
}

bool Runtime::record_capture(std::uint8_t interface_id, const packet::Frame& frame,
                             std::uint64_t timestamp_us) {
  // Capture exhaustion never blocks or drops live traffic. Returning false
  // increments a dedicated diagnostic counter so loss is never silent.
  if (captures_.size() == capture_capacity) return false;
  captures_.push_back({.timestamp_us = timestamp_us,
                       .interface_id = interface_id,
                       .frame = frame});
  return true;
}

void Runtime::encode_capture() {
  // Source: ietf.pcapng.draft_ietf_opsawg_05. Each modeled capture point owns
  // an IDB. EPB interface IDs therefore preserve the physical direction.
  std::size_t size = 28U;
  for (const auto* name : profile::capture_interface_names) {
    const auto name_length = std::char_traits<char>::length(name);
    size += 28U + ((name_length + 3U) & ~std::size_t{3U});
  }
  for (const auto& capture : captures_) {
    size += 32U + ((capture.frame.size() + 3U) & ~std::size_t{3U});
  }
  prepared_capture_.clear();
  prepared_capture_.reserve(size);
  const auto put16 = [this](std::uint16_t value) {
    prepared_capture_.push_back(static_cast<std::uint8_t>(value));
    prepared_capture_.push_back(static_cast<std::uint8_t>(value >> 8));
  };
  const auto put32 = [this](std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
      prepared_capture_.push_back(static_cast<std::uint8_t>(value >> shift));
    }
  };
  put32(0x0a0d0d0aU);
  // Section length is unknown because captures append during runtime. PCAPNG
  // represents that value with all one bits in both 32-bit halves.
  put32(28);
  put32(0x1a2b3c4dU);
  put16(1);
  put16(0);
  put32(0xffffffffU);
  put32(0xffffffffU);
  put32(28);
  for (const auto* name : profile::capture_interface_names) {
    // if_name option makes the otherwise numeric Interface ID self-describing
    // in Wireshark. Padding bytes belong to the option and are not name data.
    const auto name_length = std::char_traits<char>::length(name);
    const auto padded_name = (name_length + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(28U + padded_name);
    put32(1);
    put32(total);
    put16(1);
    put16(0);
    put32(1514);
    put16(2);
    put16(static_cast<std::uint16_t>(name_length));
    prepared_capture_.insert(prepared_capture_.end(), name, name + name_length);
    prepared_capture_.resize(prepared_capture_.size() + padded_name - name_length, 0);
    put16(0);
    put16(0);
    put32(total);
  }
  for (const auto& capture : captures_) {
    // Captured and original lengths are equal because this milestone does not
    // truncate frames. FCS is absent at every software egress capture point.
    const auto padded = (capture.frame.size() + 3U) & ~std::size_t{3U};
    const auto total = static_cast<std::uint32_t>(32U + padded);
    put32(6);
    put32(total);
    put32(capture.interface_id);
    put32(static_cast<std::uint32_t>(capture.timestamp_us >> 32));
    put32(static_cast<std::uint32_t>(capture.timestamp_us));
    put32(capture.frame.length);
    put32(capture.frame.length);
    prepared_capture_.insert(prepared_capture_.end(), capture.frame.view().begin(),
                             capture.frame.view().end());
    prepared_capture_.resize(prepared_capture_.size() + padded - capture.frame.size(), 0);
    put32(total);
  }
}

void Runtime::publish_telemetry() noexcept {
  // UI reads this cache line directly from SharedArrayBuffer. The writer is the
  // control shard, so a seqlock avoids a mutex and keeps sampling independent
  // of packet throughput. No packet bytes or mutable class layout are exposed.
  std::atomic_ref<std::uint32_t> sequence(telemetry_.sequence);
  auto generation = sequence.load(std::memory_order_relaxed);
  if (generation & 1U) ++generation;
  sequence.store(generation + 1U, std::memory_order_release);
  telemetry_.abi_version = 3;
  telemetry_.byte_size = sizeof(TelemetryPageV1);
  telemetry_.status = stopping_.load(std::memory_order_acquire) ? 3U : 1U;
  telemetry_.worker_count = 2;
  telemetry_.inventory_ports = static_cast<std::uint32_t>(state_.inventory_port_count());
  telemetry_.operational_ports = 0;
  telemetry_.port_oper_bitmap = 0;
  for (std::size_t index = 0; index < state_.inventory_port_count(); ++index) {
    if (state_.port_operational(index)) {
      ++telemetry_.operational_ports;
      telemetry_.port_oper_bitmap |= 1U << index;
    }
  }
  telemetry_.fib_generation = static_cast<std::uint32_t>(fib_generation_);
  telemetry_.control_thread_id = control_thread_id_.load(std::memory_order_acquire);
  telemetry_.forwarding_thread_id = forwarding_thread_id_.load(std::memory_order_acquire);
  telemetry_.control_wakeups = control_wakeups_.load(std::memory_order_relaxed);
  telemetry_.forwarding_wakeups = forwarding_wakeups_.load(std::memory_order_relaxed);
  telemetry_.max_scheduling_lag_ns = max_scheduling_lag_ns_.load(std::memory_order_relaxed);
  telemetry_.captured_frames = state_.capture_count;
  telemetry_.capture_dropped = state_.capture_dropped;
  telemetry_.dropped_packets = state_.dropped_packets;
  sequence.store(generation + 2U, std::memory_order_release);
}

std::string Runtime::snapshot() {
  // JSON is constructed on demand at 2 Hz rather than maintained after every
  // packet. All values are copied while control owns the state, so React never
  // observes half-applied counters, routes, hardware or adjacency data.
  publish_telemetry();
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - started_)
                           .count();
  std::ostringstream out;
  out << "{\"abiVersion\":3,\"status\":\"ready\",\"nowMs\":" << elapsed
      << ",\"hardware\":{\"chassis\":\"" << profile::chassis
      << "\",\"cpmA\":\"active-ready\""
      << ",\"card1Provisioned\":\"" << (state_.card_provisioned ? "iom4-e" : "absent")
      << "\",\"mda11Provisioned\":\"" << (state_.mda_provisioned ? "me10-10gb-sfp+" : "absent")
      << "\",\"card1\":\"" << (state_.card_present ? "iom4-e" : "absent")
      << "\",\"mda11\":\""
      << (state_.mda_present ? (state_.mda_compatible ? "me10-10gb-sfp+" : "me1-100gb-cfp2") : "absent")
      << "\",\"cardLifecycle\":\"" << hardware::lifecycle_name(state_.card_lifecycle)
      << "\",\"mdaLifecycle\":\"" << hardware::lifecycle_name(state_.mda_lifecycle)
      << "\",\"cardReason\":\"" << state_.card_reason
      << "\",\"mdaReason\":\"" << state_.mda_reason
      << "\"},\"ports\":[";
  for (std::size_t index = 0; index < state_.inventory_port_count(); ++index) {
    if (index) out << ',';
    const auto& port = state_.ports[index];
    out << "{\"id\":\"" << port.id << "\",\"admin\":\""
        << (port.admin_enabled ? "up" : "down") << "\",\"oper\":\""
        << (state_.port_operational(index) ? "up" : "down")
        << "\",\"speedMbps\":" << profile::port_speed_mbps
        << ",\"mtu\":" << port.mtu
        << ",\"description\":\"" << json_text(port.description.data()) << "\""
        << ",\"rxPackets\":" << port.rx_packets
        << ",\"txPackets\":" << port.tx_packets << '}';
  }
  out << "],\"arp\":[";
  bool first = true;
  for (const auto& entry : state_.arp) {
    if (!entry.valid) continue;
    if (!first) out << ',';
    first = false;
    out << "{\"address\":\"" << ipv4_text(entry.address) << "\",\"mac\":\""
        << mac_text(entry.mac) << "\",\"port\":\"" << state_.ports[entry.port_index].id
        << "\"}";
  }
  out << "],\"routes\":[";
  first = true;
  for (const auto& route : rib_.entries()) {
    if (!first) out << ',';
    first = false;
    const auto index = route.port_index;
    out << "{\"prefix\":\"";
    if (route.next_hop) {
      out << ipv4_text(route.network) << '/' << static_cast<unsigned>(route.prefix_length);
    } else {
      out << state_.interfaces[index].prefix;
    }
    out << "\",\"nextHop\":\"" << (route.next_hop ? ipv4_text(route.next_hop) : "")
        << "\",\"port\":\"" << state_.ports[index].id
        << "\",\"source\":\"" << (route.next_hop ? "static" : "local") << "\"}";
  }
  out << "],\"alarms\":[";
  for (std::size_t index = 0; index < state_.alarm_count; ++index) {
    if (index) out << ',';
    const auto& alarm = state_.alarms[index];
    out << "{\"id\":\"" << alarm.id << "\",\"severity\":\"" << alarm.severity
        << "\",\"reason\":\"" << alarm.reason << "\"}";
  }
  out << "],\"runningConfig\":{\"systemName\":\"" << json_text(state_.system_name.data())
      << "\",\"ports\":[";
  for (std::size_t index = 0; index < state_.ports.size(); ++index) {
    if (index) out << ',';
    const auto& port = state_.ports[index];
    out << "{\"id\":\"" << port.id << "\",\"admin\":\""
        << (port.admin_enabled ? "up" : "down") << "\",\"mtu\":" << port.mtu
        << ",\"description\":\"" << json_text(port.description.data()) << "\"}";
  }
  out << "],\"interfaces\":[";
  for (std::size_t index = 0; index < state_.interfaces.size(); ++index) {
    if (index) out << ',';
    out << "{\"name\":\"" << state_.interfaces[index].name << "\",\"admin\":\""
        << (state_.interfaces[index].admin_enabled ? "up" : "down") << "\"}";
  }
  out << "],\"staticRoutes\":[";
  first = true;
  for (const auto& route : state_.static_routes) {
    if (!route.valid) continue;
    if (!first) out << ',';
    first = false;
    out << "{\"prefix\":\"" << ipv4_text(route.network) << '/'
        << static_cast<unsigned>(route.prefix_length) << "\",\"nextHop\":\""
        << ipv4_text(route.next_hop) << "\"}";
  }
  out << "]},\"captureCount\":" << state_.capture_count
      << ",\"captureDropped\":" << state_.capture_dropped
      << ",\"droppedPackets\":" << state_.dropped_packets;
  if (state_.last_drop_reason) out << ",\"lastDropReason\":\"" << state_.last_drop_reason << '\"';
  out << '}';
  return out.str();
}

}  // namespace router
