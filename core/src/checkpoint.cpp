// Versioned little-endian checkpoint implementation. Validation completes into
// a private Image before the runtime replaces any live control-owned state.

#include "router/checkpoint.hpp"
#include "router/routing.hpp"

#include <algorithm>
#include <cstring>
#include <type_traits>

namespace router::checkpoint {
namespace {

// The magic identifies the checkpoint family only. Format evolution is carried
// by the generated version and schema hash fields, not a duplicated digit in
// the byte signature.
constexpr std::array<std::uint8_t, 8> magic{'R', 'S', 'I', 'M', 'C', 'P', 0, 0};

// Encodes null as zero and supported inventory types as stable profile-order
// codes. Unknown pointers are rejected by emitting an impossible marker.
std::uint8_t mda_type_code(const char *type) noexcept {
  if (!type)
    return 0;
  for (std::size_t index = 0; index < profile::supported_mda_types.size();
       ++index) {
    if (std::strcmp(type, profile::supported_mda_types[index]) == 0)
      return static_cast<std::uint8_t>(index + 1U);
  }
  return 0xffU;
}

class Writer {
public:
  // Emits every integer least-significant byte first. Fixed byte order makes
  // checkpoint files portable across native and WebAssembly hosts.
  template <typename Integer> void integer(Integer value) {
    using Unsigned = std::make_unsigned_t<Integer>;
    const auto bits = static_cast<Unsigned>(value);
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes.push_back(static_cast<std::uint8_t>(bits >> (index * 8U)));
    }
  }
  template <typename Type, std::size_t N>
  void fixed(const std::array<Type, N> &value) {
    // Fixed arrays contain byte-like or trivially copyable scalar fields only;
    // no pointer or padding-bearing device object is serialized wholesale.
    const auto *first = reinterpret_cast<const std::uint8_t *>(value.data());
    bytes.insert(bytes.end(), first, first + sizeof(Type) * N);
  }
  void frame(const packet::Frame &value) {
    // Only initialized wire bytes are emitted. Serializing the entire fixed
    // capacity would leak irrelevant stack contents and inflate sparse queues.
    integer(value.length);
    bytes.insert(bytes.end(), value.bytes.begin(),
                 value.bytes.begin() + value.length);
  }
  std::vector<std::uint8_t> bytes;
};

class Reader {
public:
  // Reader borrows immutable input for one decode call and never retains it in
  // the returned Image.
  explicit Reader(std::span<const std::uint8_t> input) : bytes_(input) {}

  template <typename Integer> bool integer(Integer &value) {
    // Bounds are checked before any output mutation. Truncated input therefore
    // fails without an out-of-range read or partially assembled live state.
    if (offset_ + sizeof(Integer) > bytes_.size())
      return false;
    using Unsigned = std::make_unsigned_t<Integer>;
    Unsigned result{};
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      result |= static_cast<Unsigned>(bytes_[offset_++]) << (index * 8U);
    }
    value = static_cast<Integer>(result);
    return true;
  }

  template <typename Type, std::size_t N>
  bool fixed(std::array<Type, N> &value) {
    // Exact-size copies preserve embedded zero bytes in MAC and IP addresses.
    const auto size = sizeof(Type) * N;
    if (offset_ + size > bytes_.size())
      return false;
    std::memcpy(value.data(), bytes_.data() + offset_, size);
    offset_ += size;
    return true;
  }

  bool frame(packet::Frame &value) {
    std::uint16_t length{};
    if (!integer(length) || !length || length > value.bytes.size() ||
        offset_ + length > bytes_.size())
      return false;
    value.length = length;
    std::memcpy(value.bytes.data(), bytes_.data() + offset_, length);
    offset_ += length;
    return true;
  }

  // Successful decoding requires consumption of the complete byte stream so
  // appended unknown data cannot be accepted under an older schema.
  [[nodiscard]] bool complete() const noexcept {
    return offset_ == bytes_.size();
  }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{};
};

// Serializes one canonical datastore using generated chassis and resource
// capacities. Physical presence is deliberately excluded from this function.
void configuration(Writer &out, const DeviceConfiguration &value) {
  for (const auto &card : value.cards) {
    out.integer<std::uint8_t>(card.type ? 1U : 0U);
    out.integer<std::uint8_t>(card.admin_enabled);
    for (const auto &mda : card.mdas) {
      out.integer(mda_type_code(mda.type));
      out.integer<std::uint8_t>(mda.admin_enabled);
    }
  }
  out.fixed(value.system_name);
  for (const auto &port : value.ports) {
    out.integer<std::uint8_t>(port.admin_enabled);
    out.integer(port.mtu);
    out.fixed(port.description);
  }
  out.integer(value.interface_count);
  for (const auto &interface : value.interfaces) {
    out.integer<std::uint8_t>(interface.valid);
    out.integer<std::uint8_t>(interface.admin_enabled);
    out.integer(interface.port_index);
    out.fixed(interface.ipv4);
    out.integer(interface.network);
    out.integer(interface.prefix_length);
  }
  for (const auto &route : value.static_routes) {
    out.integer<std::uint8_t>(route.valid);
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
  }
}

// Reads the canonical one-byte boolean form. Other values are malformed rather
// than treated as truthy, keeping files deterministic across implementations.
bool boolean(Reader &in, bool &value) {
  std::uint8_t raw{};
  if (!in.integer(raw) || raw > 1)
    return false;
  value = raw != 0;
  return true;
}

constexpr std::size_t maximum_stored_frames =
    profile::link_direction_count *
        (profile::link_queue_capacity * 2U +
         profile::link_inflight_capacity) +
    profile::port_count * profile::adjacency_pending_capacity +
    network_endpoint_capacity * 2U;

void forwarding(Writer &out, const NetworkCheckpointState &value) {
  // Forwarding records use bounded generated dimensions. Vector length is
  // written once, then each frame carries its queue stage and exact wire bytes.
  for (const auto &entry : value.adjacencies) {
    out.integer<std::uint8_t>(entry.valid);
    out.fixed(entry.address);
    out.fixed(entry.mac);
    out.integer(entry.port_index);
    out.integer(entry.remaining_seconds);
  }
  for (const auto request : value.arp_requests)
    out.integer<std::uint8_t>(request);
  for (const auto &endpoint : value.endpoints) {
    out.integer<std::uint8_t>(endpoint.neighbor_valid);
    out.fixed(endpoint.neighbor_address);
    out.fixed(endpoint.neighbor_mac);
    out.integer<std::uint8_t>(endpoint.pending_next_hop_valid);
    out.fixed(endpoint.pending_next_hop);
    out.integer<std::uint8_t>(endpoint.reassembly_active);
    out.fixed(endpoint.reassembly_source);
    out.fixed(endpoint.reassembly_destination);
    out.integer(endpoint.reassembly_identification);
    out.integer(endpoint.reassembly_payload_octets);
  }
  for (const auto remaining : value.transmitter_remaining_ns)
    out.integer(remaining);
  out.integer(static_cast<std::uint32_t>(value.frames.size()));
  for (const auto &stored : value.frames) {
    out.integer(static_cast<std::uint8_t>(stored.stage));
    out.integer(stored.direction);
    out.integer<std::uint8_t>(stored.routed);
    out.fixed(stored.next_hop);
    out.integer(stored.remaining_ns);
    out.frame(stored.frame);
  }
}

bool forwarding(Reader &in, NetworkCheckpointState &value) {
  for (auto &entry : value.adjacencies) {
    if (!boolean(in, entry.valid) || !in.fixed(entry.address) ||
        !in.fixed(entry.mac) || !in.integer(entry.port_index) ||
        entry.port_index >= profile::port_count ||
        !in.integer(entry.remaining_seconds))
      return false;
  }
  for (auto &request : value.arp_requests) {
    if (!boolean(in, request))
      return false;
  }
  for (auto &endpoint : value.endpoints) {
    if (!boolean(in, endpoint.neighbor_valid) ||
        !in.fixed(endpoint.neighbor_address) ||
        !in.fixed(endpoint.neighbor_mac) ||
        !boolean(in, endpoint.pending_next_hop_valid) ||
        !in.fixed(endpoint.pending_next_hop) ||
        !boolean(in, endpoint.reassembly_active) ||
        !in.fixed(endpoint.reassembly_source) ||
        !in.fixed(endpoint.reassembly_destination) ||
        !in.integer(endpoint.reassembly_identification) ||
        !in.integer(endpoint.reassembly_payload_octets) ||
        endpoint.reassembly_payload_octets >
            packet::maximum_frame_octets - 34U)
      return false;
  }
  for (auto &remaining : value.transmitter_remaining_ns) {
    if (!in.integer(remaining))
      return false;
  }
  std::uint32_t frame_count{};
  if (!in.integer(frame_count) || frame_count > maximum_stored_frames)
    return false;
  value.frames.resize(frame_count);
  for (auto &stored : value.frames) {
    std::uint8_t stage{};
    if (!in.integer(stage) ||
        stage > static_cast<std::uint8_t>(
                    NetworkFrameStage::endpoint_reassembly) ||
        !in.integer(stored.direction) || !boolean(in, stored.routed) ||
        !in.fixed(stored.next_hop) || !in.integer(stored.remaining_ns) ||
        !in.frame(stored.frame))
      return false;
    stored.stage = static_cast<NetworkFrameStage>(stage);
  }
  return true;
}

// Decodes a datastore into private Image storage and validates every profile
// identity, string terminator, slot index, MTU and route prefix bound.
bool configuration(Reader &in, DeviceConfiguration &value) {
  for (std::size_t card_index = 0; card_index < value.cards.size();
       ++card_index) {
    auto &card = value.cards[card_index];
    bool provisioned{};
    if (!boolean(in, provisioned) || !boolean(in, card.admin_enabled))
      return false;
    if (provisioned && card_index != profile::line_card_index)
      return false;
    card.type = provisioned ? profile::line_card_type : nullptr;
    for (auto &mda : card.mdas) {
      std::uint8_t type{};
      if (!in.integer(type) || type > profile::supported_mda_types.size() ||
          !boolean(in, mda.admin_enabled))
        return false;
      // Provisioning supports only the MDA modeled by this release profile.
      // Other supported inventory values are valid in HardwareState solely to
      // represent and diagnose a physical mismatch.
      if (type && (card_index != profile::line_card_index ||
                   std::strcmp(profile::supported_mda_types[type - 1U],
                               profile::modeled_mda_type) != 0))
        return false;
      mda.type = type ? profile::supported_mda_types[type - 1U] : nullptr;
    }
  }
  if (!in.fixed(value.system_name) ||
      std::find(value.system_name.begin(), value.system_name.end(), '\0') ==
          value.system_name.end())
    return false;
  for (auto &port : value.ports) {
    if (!boolean(in, port.admin_enabled) || !in.integer(port.mtu) ||
        port.mtu < profile::minimum_port_mtu ||
        port.mtu > profile::maximum_port_mtu || !in.fixed(port.description) ||
        std::find(port.description.begin(), port.description.end(), '\0') ==
            port.description.end())
      return false;
  }
  if (!in.integer(value.interface_count) ||
      value.interface_count > value.interfaces.size()) {
    return false;
  }
  for (auto &interface : value.interfaces) {
    if (!boolean(in, interface.valid) ||
        !boolean(in, interface.admin_enabled) ||
        !in.integer(interface.port_index) ||
        interface.port_index >= profile::port_count ||
        !in.fixed(interface.ipv4) || !in.integer(interface.network) ||
        !in.integer(interface.prefix_length) || interface.prefix_length > 32U ||
        interface.network !=
            (routing::ipv4(interface.ipv4[0], interface.ipv4[1],
                           interface.ipv4[2], interface.ipv4[3]) &
             routing::prefix_mask(interface.prefix_length))) {
      return false;
    }
  }
  for (auto &route : value.static_routes) {
    if (!boolean(in, route.valid) || !in.integer(route.network) ||
        !in.integer(route.next_hop) || !in.integer(route.prefix_length) ||
        route.prefix_length > 32)
      return false;
  }
  return true;
}

// Converts the runtime's stable drop strings to a compact checkpoint field.
// Zero represents no last failure and unknown text is not persisted as valid.
std::uint8_t drop_reason_code(const char *reason) noexcept {
  if (!reason)
    return 0;
  if (std::strcmp(reason, "interface-down") == 0)
    return 1;
  if (std::strcmp(reason, "route-miss") == 0)
    return 2;
  if (std::strcmp(reason, "queue-full") == 0)
    return 3;
  if (std::strcmp(reason, "mtu-exceeded") == 0)
    return 4;
  if (std::strcmp(reason, "ttl-expired") == 0)
    return 5;
  if (std::strcmp(reason, "timeout") == 0)
    return 6;
  if (std::strcmp(reason, "cancelled") == 0)
    return 7;
  if (std::strcmp(reason, "malformed-packet") == 0)
    return 8;
  return 0;
}

// Reconstructs only drop names known by this checkpoint schema version.
const char *drop_reason(std::uint8_t code) noexcept {
  switch (code) {
  case 1:
    return "interface-down";
  case 2:
    return "route-miss";
  case 3:
    return "queue-full";
  case 4:
    return "mtu-exceeded";
  case 5:
    return "ttl-expired";
  case 6:
    return "timeout";
  case 7:
    return "cancelled";
  case 8:
    return "malformed-packet";
  default:
    return nullptr;
  }
}

} // namespace

std::vector<std::uint8_t> encode(const DeviceState &device,
                                 const CliSession &session,
                                 std::uint64_t fib_generation,
                                 const NetworkCheckpointState &forwarding_state,
                                 std::chrono::steady_clock::time_point now) {
  // Header compatibility fields are generated from the active profile and
  // schema contents. No build date or manually maintained version is trusted.
  Writer out;
  out.fixed(magic);
  out.integer(profile::checkpoint_abi);
  out.integer(profile::checkpoint_schema_hash);
  out.integer(profile::profile_hash);
  out.integer(profile::build_hash);
  const auto remaining = [now](const EquipmentState &equipment) {
    // Absolute steady-clock points are process-local. Only remaining duration
    // is portable, and expired initialization restores as immediately due.
    if (equipment.lifecycle != EquipmentLifecycle::initializing ||
        equipment.deadline <= now)
      return std::uint64_t{};
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            equipment.deadline - now)
            .count());
  };
  const auto deadline_remaining = [now](auto deadline) {
    if (deadline == decltype(deadline){} || deadline <= now)
      return std::uint64_t{};
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
            .count());
  };
  const auto elapsed_since = [now](auto since) {
    // Zero marks an inactive route. One is added to active elapsed durations
    // so a route selected at the checkpoint instant remains distinguishable.
    if (since == decltype(since){})
      return std::uint64_t{};
    const auto elapsed = since < now ? now - since : decltype(now - since){};
    return static_cast<std::uint64_t>(
               std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed)
                   .count()) +
           1U;
  };
  for (const auto &card : device.hardware.cards) {
    // Hardware inventory stores type, compatibility and lifecycle separately
    // from provisioning so a restored mismatch remains observable.
    out.integer(remaining(card.equipment));
    for (const auto &mda : card.mdas)
      out.integer(remaining(mda.equipment));
  }
  configuration(out, device.configuration.running);
  configuration(out, device.configuration.candidate);
  out.integer<std::uint8_t>(device.configuration.running_unsaved);
  for (const auto &card : device.hardware.cards) {
    out.integer<std::uint8_t>(card.type ? 1U : 0U);
    out.integer<std::uint8_t>(card.compatible);
    out.integer(static_cast<std::uint8_t>(card.equipment.lifecycle));
    for (const auto &mda : card.mdas) {
      out.integer(mda_type_code(mda.type));
      out.integer<std::uint8_t>(mda.compatible);
      out.integer(static_cast<std::uint8_t>(mda.equipment.lifecycle));
    }
  }
  for (const auto signal : device.hardware.link_signal)
    out.integer<std::uint8_t>(signal);
  for (const auto &host : device.project.hosts) {
    out.fixed(host.mac);
    out.fixed(host.address);
    out.integer(host.prefix_length);
    out.fixed(host.gateway);
  }
  for (const auto &link : device.project.links) {
    out.integer<std::uint8_t>(link.connected);
    out.integer(link.router_port);
    out.integer(static_cast<std::uint64_t>(link.propagation.count()));
  }
  for (const auto &counters : device.operational.port_counters) {
    out.integer(counters.rx_packets);
    out.integer(counters.tx_packets);
  }
  out.integer(device.operational.capture_count);
  out.integer(device.operational.dropped_packets);
  out.integer(device.operational.capture_dropped);
  out.integer(drop_reason_code(device.operational.last_drop_reason));
  for (const auto &entry : device.operational.arp) {
    out.integer<std::uint8_t>(entry.valid);
    out.fixed(entry.address);
    out.fixed(entry.mac);
    out.integer(entry.port_index);
    // Only the remaining interval is portable across process-local monotonic
    // clock epochs.
    out.integer(deadline_remaining(entry.expires_at));
  }
  // Route activation time is wall-clock presentation state. Persisting it
  // prevents every restored route from falsely appearing newly installed.
  for (const auto since : device.operational.connected_route_since)
    out.integer(elapsed_since(since));
  for (const auto since : device.operational.static_route_since)
    out.integer(elapsed_since(since));
  for (const auto seen : device.operational.port_seen_operational)
    out.integer<std::uint8_t>(seen);
  for (const auto active : device.operational.port_link_alarm_active)
    out.integer<std::uint8_t>(active);
  out.integer(static_cast<std::uint8_t>(session.engine));
  out.integer(static_cast<std::uint8_t>(session.md_workflow));
  out.fixed(session.md_path);
  out.fixed(session.classic_path);
  out.fixed(session.md_previous_path);
  out.fixed(session.classic_previous_path);
  out.integer<std::uint8_t>(session.md_exit_confirmation);
  out.integer<std::uint8_t>(session.candidate_dirty);
  out.integer<std::uint8_t>(session.candidate_outdated);
  out.integer<std::uint8_t>(session.classic_unsaved);
  out.integer(fib_generation);
  forwarding(out, forwarding_state);
  return std::move(out.bytes);
}

std::optional<Image> decode(std::span<const std::uint8_t> bytes,
                            std::chrono::steady_clock::time_point now) {
  // All work targets a local Image. The runtime does not receive it unless the
  // header, every field and complete-consumption check all succeed.
  Reader in(bytes);
  std::array<std::uint8_t, magic.size()> input_magic{};
  std::uint32_t input_version{};
  std::uint64_t input_schema{};
  std::uint64_t input_profile{};
  std::uint64_t input_build{};
  Image image;
  if (!in.fixed(input_magic) || input_magic != magic ||
      !in.integer(input_version) || input_version != profile::checkpoint_abi ||
      !in.integer(input_schema) ||
      input_schema != profile::checkpoint_schema_hash ||
      !in.integer(input_profile) || input_profile != profile::profile_hash ||
      !in.integer(input_build) || input_build != profile::build_hash)
    return std::nullopt;
  for (std::size_t card_index = 0;
       card_index < image.device.hardware.cards.size(); ++card_index) {
    if (!in.integer(image.card_remaining_ns[card_index]))
      return std::nullopt;
    for (std::size_t mda_index = 0;
         mda_index < image.device.hardware.cards[card_index].mdas.size();
         ++mda_index) {
      const auto flat = card_index * profile::mda_slots_per_card + mda_index;
      if (!in.integer(image.mda_remaining_ns[flat]))
        return std::nullopt;
    }
  }
  if (!configuration(in, image.device.configuration.running) ||
      !configuration(in, image.device.configuration.candidate) ||
      !boolean(in, image.device.configuration.running_unsaved))
    return std::nullopt;
  for (std::size_t card_index = 0;
       card_index < image.device.hardware.cards.size(); ++card_index) {
    auto &card = image.device.hardware.cards[card_index];
    bool present{};
    std::uint8_t lifecycle{};
    if (!boolean(in, present) || !boolean(in, card.compatible) ||
        !in.integer(lifecycle) ||
        lifecycle > static_cast<std::uint8_t>(EquipmentLifecycle::mismatch) ||
        (present && card_index != profile::line_card_index))
      return std::nullopt;
    card.type = present ? profile::line_card_type : nullptr;
    card.equipment.lifecycle = static_cast<EquipmentLifecycle>(lifecycle);
    for (auto &mda : card.mdas) {
      std::uint8_t type{};
      if (!in.integer(type) || type > profile::supported_mda_types.size() ||
          !boolean(in, mda.compatible) || !in.integer(lifecycle) ||
          lifecycle > static_cast<std::uint8_t>(EquipmentLifecycle::mismatch))
        return std::nullopt;
      mda.type = type ? profile::supported_mda_types[type - 1U] : nullptr;
      mda.equipment.lifecycle = static_cast<EquipmentLifecycle>(lifecycle);
    }
  }
  for (auto &signal : image.device.hardware.link_signal) {
    if (!boolean(in, signal))
      return std::nullopt;
  }
  for (auto &host : image.device.project.hosts) {
    if (!in.fixed(host.mac) || !in.fixed(host.address) ||
        !in.integer(host.prefix_length) || host.prefix_length > 32 ||
        !in.fixed(host.gateway))
      return std::nullopt;
  }
  for (auto &link : image.device.project.links) {
    // Project delays are limited to JavaScript's exact integer range because
    // the same values must survive a browser project round trip unchanged.
    std::uint64_t propagation{};
    if (!boolean(in, link.connected) || !in.integer(link.router_port) ||
        link.router_port >= profile::port_count || !in.integer(propagation) ||
        propagation > 9007199254740991ULL)
      return std::nullopt;
    link.propagation = std::chrono::nanoseconds(propagation);
  }
  for (auto &counters : image.device.operational.port_counters) {
    if (!in.integer(counters.rx_packets) || !in.integer(counters.tx_packets))
      return std::nullopt;
  }
  std::uint8_t reason{};
  if (!in.integer(image.device.operational.capture_count) ||
      !in.integer(image.device.operational.dropped_packets) ||
      !in.integer(image.device.operational.capture_dropped) ||
      !in.integer(reason) || reason > 8) {
    return std::nullopt;
  }
  image.device.operational.last_drop_reason = drop_reason(reason);
  for (auto &entry : image.device.operational.arp) {
    std::uint64_t remaining_ns{};
    if (!boolean(in, entry.valid) || !in.fixed(entry.address) ||
        !in.fixed(entry.mac) || !in.integer(entry.port_index) ||
        !in.integer(remaining_ns) || entry.port_index >= profile::port_count) {
      return std::nullopt;
    }
    entry.valid = entry.valid && remaining_ns != 0;
    entry.expires_at = entry.valid
                           ? now + std::chrono::nanoseconds{remaining_ns}
                           : std::chrono::steady_clock::time_point{};
  }
  for (auto &since : image.device.operational.connected_route_since) {
    std::uint64_t elapsed_plus_one{};
    if (!in.integer(elapsed_plus_one))
      return std::nullopt;
    since = elapsed_plus_one
                ? now - std::chrono::nanoseconds{elapsed_plus_one - 1U}
                : std::chrono::steady_clock::time_point{};
  }
  for (auto &since : image.device.operational.static_route_since) {
    std::uint64_t elapsed_plus_one{};
    if (!in.integer(elapsed_plus_one))
      return std::nullopt;
    since = elapsed_plus_one
                ? now - std::chrono::nanoseconds{elapsed_plus_one - 1U}
                : std::chrono::steady_clock::time_point{};
  }
  for (auto &seen : image.device.operational.port_seen_operational) {
    if (!boolean(in, seen))
      return std::nullopt;
  }
  for (auto &active : image.device.operational.port_link_alarm_active) {
    if (!boolean(in, active))
      return std::nullopt;
  }
  std::uint8_t engine{};
  std::uint8_t workflow{};
  // Session engine and candidate flags are last so truncated terminal state
  // cannot produce an otherwise accepted device checkpoint.
  if (!in.integer(engine) ||
      engine > static_cast<std::uint8_t>(CliEngine::classic) ||
      !in.integer(workflow) ||
      workflow > static_cast<std::uint8_t>(MdCliWorkflow::explicit_exclusive) ||
      !in.fixed(image.session.md_path) ||
      !in.fixed(image.session.classic_path) ||
      !in.fixed(image.session.md_previous_path) ||
      !in.fixed(image.session.classic_previous_path) ||
      image.session.md_path.back() != '\0' ||
      image.session.classic_path.back() != '\0' ||
      image.session.md_previous_path.back() != '\0' ||
      image.session.classic_previous_path.back() != '\0' ||
      !boolean(in, image.session.md_exit_confirmation) ||
      !boolean(in, image.session.candidate_dirty) ||
      !boolean(in, image.session.candidate_outdated) ||
      !boolean(in, image.session.classic_unsaved) ||
      !in.integer(image.fib_generation) ||
      !forwarding(in, image.forwarding) || !in.complete())
    return std::nullopt;
  image.session.engine = static_cast<CliEngine>(engine);
  image.session.md_workflow = static_cast<MdCliWorkflow>(workflow);
  return image;
}

} // namespace router::checkpoint
