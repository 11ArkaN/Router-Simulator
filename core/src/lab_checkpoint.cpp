// ABI 5 codec implementation. Decoding creates a detached value graph. The
// supervisor performs cross-owner validation and atomic commit only afterwards.

#include "router/lab_checkpoint.hpp"

#include "router/generated_device_catalog.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace router::lab::checkpoint_v5 {
namespace {

inline constexpr std::array<std::uint8_t, 8> magic{
    'R', 'S', 'L', 'A', 'B', '0', '5', 0};
inline constexpr std::size_t maximum_checkpoint_bytes =
    device_catalog::wasm_initial_memory_bytes;

template <typename T, bool = std::is_enum_v<T>> struct IntegerRaw {
  using type = T;
};
template <typename T> struct IntegerRaw<T, true> {
  using type = std::underlying_type_t<T>;
};

class Writer final {
public:
  template <typename T> void integer(T value) {
    static_assert(std::is_integral_v<T> || std::is_enum_v<T>);
    using Raw = typename IntegerRaw<T>::type;
    using Unsigned = std::make_unsigned_t<Raw>;
    const auto raw = static_cast<Unsigned>(value);
    for (std::size_t byte = 0; byte < sizeof(Unsigned); ++byte)
      bytes_.push_back(static_cast<std::uint8_t>(raw >> (byte * 8U)));
  }

  void boolean(bool value) { integer<std::uint8_t>(value ? 1U : 0U); }

  void string(std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max())
      throw std::length_error("checkpoint string exceeds ABI bound");
    integer<std::uint16_t>(static_cast<std::uint16_t>(value.size()));
    bytes_.insert(bytes_.end(), value.begin(), value.end());
  }

  void frame(const packet::Frame &value) {
    integer<std::uint16_t>(value.length);
    bytes_.insert(bytes_.end(), value.bytes.begin(),
                  value.bytes.begin() + value.length);
  }

  [[nodiscard]] std::vector<std::uint8_t> finish() && {
    if (bytes_.size() > maximum_checkpoint_bytes)
      throw std::length_error("checkpoint exceeds fixed Wasm memory budget");
    return std::move(bytes_);
  }

private:
  std::vector<std::uint8_t> bytes_;
};

class Reader final {
public:
  explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

  template <typename T> bool integer(T &value) noexcept {
    static_assert(std::is_integral_v<T> || std::is_enum_v<T>);
    using Raw = typename IntegerRaw<T>::type;
    using Unsigned = std::make_unsigned_t<Raw>;
    if (remaining() < sizeof(Unsigned))
      return false;
    Unsigned raw{};
    for (std::size_t byte = 0; byte < sizeof(Unsigned); ++byte)
      raw |= static_cast<Unsigned>(bytes_[offset_++]) << (byte * 8U);
    value = static_cast<T>(raw);
    return true;
  }

  bool boolean(bool &value) noexcept {
    std::uint8_t raw{};
    if (!integer(raw) || raw > 1U)
      return false;
    value = raw != 0;
    return true;
  }

  bool string(std::string &value, std::size_t maximum) {
    std::uint16_t size{};
    if (!integer(size) || size > maximum || remaining() < size)
      return false;
    value.assign(reinterpret_cast<const char *>(bytes_.data() + offset_), size);
    offset_ += size;
    return true;
  }

  bool frame(packet::Frame &value) noexcept {
    std::uint16_t size{};
    if (!integer(size) || !size || size > value.bytes.size() ||
        remaining() < size)
      return false;
    value.length = size;
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_), size,
                value.bytes.begin());
    offset_ += size;
    return true;
  }

  bool exact(std::span<const std::uint8_t> expected) noexcept {
    if (remaining() < expected.size() ||
        !std::equal(expected.begin(), expected.end(),
                    bytes_.begin() + static_cast<std::ptrdiff_t>(offset_)))
      return false;
    offset_ += expected.size();
    return true;
  }

  [[nodiscard]] std::size_t remaining() const noexcept {
    return bytes_.size() - offset_;
  }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{};
};

template <typename Tag>
void handle(Writer &out, Handle<Tag> value) {
  out.integer(value.index);
  out.integer(value.generation);
}

template <typename Tag>
bool handle(Reader &in, Handle<Tag> &value) noexcept {
  return in.integer(value.index) && in.integer(value.generation);
}

void node(Writer &out, NodeHandle value) {
  out.integer(value.kind);
  out.integer(value.index);
  out.integer(value.generation);
}

bool node(Reader &in, NodeHandle &value) noexcept {
  return in.integer(value.kind) && value.kind <= NodeKind::host &&
         in.integer(value.index) && in.integer(value.generation);
}

void port_handle(Writer &out, PortHandle value) {
  node(out, value.node);
  out.integer(value.ordinal);
  out.integer(value.generation);
}

bool port_handle(Reader &in, PortHandle &value) noexcept {
  return node(in, value.node) && in.integer(value.ordinal) &&
         in.integer(value.generation);
}

void mac(Writer &out, packet::Mac value) {
  for (const auto byte : value)
    out.integer(byte);
}

bool mac(Reader &in, packet::Mac &value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [&](auto &byte) { return in.integer(byte); });
}

void ipv4(Writer &out, packet::Ipv4 value) {
  for (const auto byte : value)
    out.integer(byte);
}

bool ipv4(Reader &in, packet::Ipv4 &value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [&](auto &byte) { return in.integer(byte); });
}

void forward_port(Writer &out, const ForwardPort &value) {
  out.boolean(value.configured);
  out.boolean(value.operational);
  out.integer(value.ordinal);
  out.integer(value.mtu);
  out.integer(value.address);
  out.integer(value.network);
  out.integer(value.speed_mbps);
  out.integer(value.prefix_length);
  mac(out, value.mac);
}

bool forward_port(Reader &in, ForwardPort &value) noexcept {
  return in.boolean(value.configured) && in.boolean(value.operational) &&
         in.integer(value.ordinal) && in.integer(value.mtu) &&
         in.integer(value.address) && in.integer(value.network) &&
         in.integer(value.speed_mbps) && in.integer(value.prefix_length) &&
         mac(in, value.mac);
}

void route(Writer &out, const routing::Route &value) {
  out.integer(value.network);
  out.integer(value.next_hop);
  out.integer(value.port_ordinal);
  out.integer(value.prefix_length);
}

bool route(Reader &in, routing::Route &value) noexcept {
  return in.integer(value.network) && in.integer(value.next_hop) &&
         in.integer(value.port_ordinal) && in.integer(value.prefix_length);
}

void fib(Writer &out, const routing::FibProgram &value) {
  out.integer(value.generation);
  out.integer(value.count);
  for (std::size_t index = 0; index < value.count; ++index)
    route(out, value.routes[index]);
}

bool fib(Reader &in, routing::FibProgram &value) noexcept {
  if (!in.integer(value.generation) || !in.integer(value.count) ||
      value.count > value.routes.size())
    return false;
  for (std::size_t index = 0; index < value.count; ++index)
    if (!route(in, value.routes[index]))
      return false;
  return true;
}

template <typename T>
void count(Writer &out, const std::vector<T> &values) {
  if (values.size() > std::numeric_limits<std::uint32_t>::max())
    throw std::length_error("checkpoint vector exceeds ABI bound");
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(values.size()));
}

bool count(Reader &in, std::uint32_t &value, std::size_t maximum) noexcept {
  return in.integer(value) && value <= maximum;
}

template <std::size_t Size>
void generations(Writer &out, const std::array<std::uint16_t, Size> &values) {
  for (const auto value : values)
    out.integer(value);
}

template <std::size_t Size>
bool generations(Reader &in, std::array<std::uint16_t, Size> &values) noexcept {
  for (auto &value : values)
    if (!in.integer(value) || !value)
      return false;
  return true;
}

void device_registry(Writer &out, const DeviceRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    out.string(entry.node_id);
    out.string(entry.system_name);
    out.string(entry.profile_id);
    out.boolean(entry.quiescing);
  }
}

bool device_registry(Reader &in, DeviceRegistryCheckpoint &state) {
  std::uint32_t size{};
  if (!generations(in, state.generations) ||
      !count(in, size, device_catalog::maximum_routers))
    return false;
  state.entries.resize(size);
  for (auto &entry : state.entries)
    if (!handle(in, entry.handle) || !in.string(entry.node_id, 64) ||
        !in.string(entry.system_name, 64) ||
        !in.string(entry.profile_id, 64) || !in.boolean(entry.quiescing))
      return false;
  return true;
}

void host_registry(Writer &out, const HostRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    out.string(entry.node_id);
    out.string(entry.name);
  }
}

bool host_registry(Reader &in, HostRegistryCheckpoint &state) {
  std::uint32_t size{};
  if (!generations(in, state.generations) ||
      !count(in, size, device_catalog::maximum_hosts))
    return false;
  state.entries.resize(size);
  for (auto &entry : state.entries)
    if (!handle(in, entry.handle) || !in.string(entry.node_id, 64) ||
        !in.string(entry.name, 64))
      return false;
  return true;
}

void link_endpoint(Writer &out, const LinkEndpoint &value) {
  node(out, value.node);
  out.string(value.port_id);
}

bool link_endpoint(Reader &in, LinkEndpoint &value) {
  return node(in, value.node) && in.string(value.port_id, 32);
}

void topology_registry(Writer &out,
                       const TopologyRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    out.string(entry.record.link_id);
    link_endpoint(out, entry.record.endpoints[0]);
    link_endpoint(out, entry.record.endpoints[1]);
    out.boolean(entry.record.admin_enabled);
    out.boolean(entry.record.carrier);
    out.integer(entry.record.speed_mbps);
    out.integer(entry.record.propagation_ns);
  }
}

bool topology_registry(Reader &in, TopologyRegistryCheckpoint &state) {
  std::uint32_t size{};
  if (!generations(in, state.generations) ||
      !count(in, size, device_catalog::maximum_links))
    return false;
  state.entries.resize(size);
  for (auto &entry : state.entries)
    if (!handle(in, entry.handle) ||
        !in.string(entry.record.link_id, 64) ||
        !link_endpoint(in, entry.record.endpoints[0]) ||
        !link_endpoint(in, entry.record.endpoints[1]) ||
        !in.boolean(entry.record.admin_enabled) ||
        !in.boolean(entry.record.carrier) ||
        !in.integer(entry.record.speed_mbps) ||
        !in.integer(entry.record.propagation_ns))
      return false;
  return true;
}

void session_registry(Writer &out, const SessionRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    handle(out, entry.record.device);
    out.string(entry.record.session_id);
    out.integer(entry.record.mode);
    out.integer(entry.record.base_generation);
    out.integer(entry.record.cli.engine);
    out.integer(entry.record.cli.md_workflow);
    out.string(entry.record.cli.md_path.data());
    out.string(entry.record.cli.classic_path.data());
    out.string(entry.record.cli.md_previous_path.data());
    out.string(entry.record.cli.classic_previous_path.data());
    out.boolean(entry.record.cli.md_exit_confirmation);
    out.integer(entry.record.cli.md_confirmation_target);
    out.boolean(entry.record.cli.candidate_dirty);
    out.boolean(entry.record.cli.candidate_outdated);
    out.boolean(entry.record.cli.classic_unsaved);
    out.boolean(entry.record.closing);
  }
}

bool session_registry(Reader &in, SessionRegistryCheckpoint &state) {
  std::uint32_t size{};
  if (!generations(in, state.generations) ||
      !count(in, size, SessionRegistryCheckpoint::capacity))
    return false;
  state.entries.resize(size);
  for (auto &entry : state.entries) {
    std::string md_path;
    std::string classic_path;
    std::string md_previous;
    std::string classic_previous;
    if (!handle(in, entry.handle) || !handle(in, entry.record.device) ||
        !in.string(entry.record.session_id, 64) ||
        !in.integer(entry.record.mode) ||
        entry.record.mode > CandidateMode::read_only ||
        !in.integer(entry.record.base_generation) ||
        !in.integer(entry.record.cli.engine) ||
        entry.record.cli.engine > CliEngine::classic ||
        !in.integer(entry.record.cli.md_workflow) ||
        entry.record.cli.md_workflow > MdCliWorkflow::explicit_read_only ||
        !in.string(md_path, entry.record.cli.md_path.size() - 1U) ||
        !in.string(classic_path,
                   entry.record.cli.classic_path.size() - 1U) ||
        !in.string(md_previous,
                   entry.record.cli.md_previous_path.size() - 1U) ||
        !in.string(classic_previous,
                   entry.record.cli.classic_previous_path.size() - 1U) ||
        !in.boolean(entry.record.cli.md_exit_confirmation) ||
        !in.integer(entry.record.cli.md_confirmation_target) ||
        entry.record.cli.md_confirmation_target >
            MdCliWorkflow::explicit_read_only ||
        !in.boolean(entry.record.cli.candidate_dirty) ||
        !in.boolean(entry.record.cli.candidate_outdated) ||
        !in.boolean(entry.record.cli.classic_unsaved) ||
        !in.boolean(entry.record.closing))
      return false;
    // Reader bounds guarantee room for the terminator. Filling first prevents
    // stale bytes from a reused decode object from becoming part of a path.
    entry.record.cli.md_path.fill('\0');
    entry.record.cli.classic_path.fill('\0');
    entry.record.cli.md_previous_path.fill('\0');
    entry.record.cli.classic_previous_path.fill('\0');
    std::copy(md_path.begin(), md_path.end(),
              entry.record.cli.md_path.begin());
    std::copy(classic_path.begin(), classic_path.end(),
              entry.record.cli.classic_path.begin());
    std::copy(md_previous.begin(), md_previous.end(),
              entry.record.cli.md_previous_path.begin());
    std::copy(classic_previous.begin(), classic_previous.end(),
              entry.record.cli.classic_previous_path.begin());
  }
  return true;
}

void hardware_port(Writer &out, const RouterPortState &value) {
  out.boolean(value.present);
  out.boolean(value.configuration_compatible);
  out.boolean(value.hierarchy_enabled);
  out.boolean(value.admin_enabled);
  out.boolean(value.link_signal);
  out.integer(value.generation);
  out.integer(value.card_slot);
  out.integer(value.mda_slot);
  out.integer(value.port_number);
  out.integer(value.mtu);
  out.integer(value.speed_mbps);
}

bool hardware_port(Reader &in, RouterPortState &value) noexcept {
  return in.boolean(value.present) &&
         in.boolean(value.configuration_compatible) &&
         in.boolean(value.hierarchy_enabled) &&
         in.boolean(value.admin_enabled) &&
         in.boolean(value.link_signal) && in.integer(value.generation) &&
         in.integer(value.card_slot) && in.integer(value.mda_slot) &&
         in.integer(value.port_number) && in.integer(value.mtu) &&
         in.integer(value.speed_mbps);
}

void hardware_state(Writer &out, const RouterHardwareCheckpoint &state) {
  handle(out, state.device);
  out.string(state.profile_id);
  for (const auto &card : state.cards) {
    out.string(card.provisioned);
    out.string(card.equipped);
    out.boolean(card.admin_enabled);
    for (const auto &mda : card.mdas) {
      out.string(mda.provisioned);
      out.string(mda.equipped);
      out.boolean(mda.admin_enabled);
    }
  }
  for (const auto &port : state.ports)
    hardware_port(out, port);
}

bool hardware_state(Reader &in, RouterHardwareCheckpoint &state) {
  if (!handle(in, state.device) || !in.string(state.profile_id, 64))
    return false;
  for (auto &card : state.cards) {
    if (!in.string(card.provisioned, 64) || !in.string(card.equipped, 64) ||
        !in.boolean(card.admin_enabled))
      return false;
    for (auto &mda : card.mdas)
      if (!in.string(mda.provisioned, 64) ||
          !in.string(mda.equipped, 64) || !in.boolean(mda.admin_enabled))
        return false;
  }
  for (auto &port : state.ports)
    if (!hardware_port(in, port))
      return false;
  return true;
}

void connected(Writer &out, const routing::ConnectedInput &value) {
  out.boolean(value.configured);
  out.boolean(value.operational);
  out.integer(value.network);
  out.integer(value.port_ordinal);
  out.integer(value.prefix_length);
}

bool connected(Reader &in, routing::ConnectedInput &value) noexcept {
  return in.boolean(value.configured) && in.boolean(value.operational) &&
         in.integer(value.network) && in.integer(value.port_ordinal) &&
         in.integer(value.prefix_length);
}

void static_route(Writer &out, const routing::StaticInput &value) {
  out.boolean(value.configured);
  out.integer(value.network);
  out.integer(value.next_hop);
  out.integer(value.prefix_length);
}

bool static_route(Reader &in, routing::StaticInput &value) noexcept {
  return in.boolean(value.configured) && in.integer(value.network) &&
         in.integer(value.next_hop) && in.integer(value.prefix_length);
}

void control_state(Writer &out, const RouterControlCheckpoint &state) {
  handle(out, state.device);
  for (const auto &value : state.connected)
    connected(out, value);
  for (const auto &value : state.statics)
    static_route(out, value);
  for (const auto &value : state.ports)
    forward_port(out, value);
  for (const auto value : state.interface_admin)
    out.boolean(value);
  fib(out, state.selected_rib);
  out.integer(state.fib_generation);
}

bool control_state(Reader &in, RouterControlCheckpoint &state) noexcept {
  if (!handle(in, state.device))
    return false;
  for (auto &value : state.connected)
    if (!connected(in, value))
      return false;
  for (auto &value : state.statics)
    if (!static_route(in, value))
      return false;
  for (auto &value : state.ports)
    if (!forward_port(in, value))
      return false;
  for (auto &value : state.interface_admin)
    if (!in.boolean(value))
      return false;
  return fib(in, state.selected_rib) &&
         in.integer(state.fib_generation);
}

void workflows(Writer &out, const SessionWorkflowsCheckpoint &state) {
  count(out, state.routers);
  for (const auto &router : state.routers) {
    handle(out, router.device);
    out.integer(router.running_generation);
    out.integer(router.global_baseline);
    count(out, router.global_keys);
    for (const auto key : router.global_keys)
      out.integer(key);
    count(out, router.revisions);
    for (const auto &revision : router.revisions) {
      out.integer(revision.key);
      out.integer(revision.generation);
    }
  }
  count(out, state.sessions);
  for (const auto &session : state.sessions) {
    handle(out, session.session);
    handle(out, session.device);
    count(out, session.keys);
    for (const auto key : session.keys)
      out.integer(key);
  }
}

bool workflows(Reader &in, SessionWorkflowsCheckpoint &state) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::maximum_routers))
    return false;
  state.routers.resize(size);
  for (auto &router : state.routers) {
    std::uint32_t keys{};
    std::uint32_t revisions{};
    if (!handle(in, router.device) ||
        !in.integer(router.running_generation) ||
        !in.integer(router.global_baseline) ||
        !count(in, keys, device_catalog::candidate_keys_per_router))
      return false;
    router.global_keys.resize(keys);
    for (auto &key : router.global_keys)
      if (!in.integer(key))
        return false;
    if (!count(in, revisions, device_catalog::candidate_keys_per_router))
      return false;
    router.revisions.resize(revisions);
    for (auto &revision : router.revisions)
      if (!in.integer(revision.key) || !in.integer(revision.generation))
        return false;
  }
  if (!count(in, size, SessionRegistryCheckpoint::capacity))
    return false;
  state.sessions.resize(size);
  for (auto &session : state.sessions) {
    std::uint32_t keys{};
    if (!handle(in, session.session) || !handle(in, session.device) ||
        !count(in, keys, device_catalog::candidate_keys_per_session))
      return false;
    session.keys.resize(keys);
    for (auto &key : session.keys)
      if (!in.integer(key))
        return false;
  }
  return true;
}

void forwarder_state(Writer &out, const RouterForwarderCheckpoint &state) {
  count(out, state.ports);
  for (const auto &value : state.ports)
    forward_port(out, value);
  fib(out, state.fib);
  count(out, state.adjacencies);
  for (const auto &entry : state.adjacencies) {
    out.integer(entry.port_ordinal);
    out.integer(entry.address);
    mac(out, entry.mac);
    out.integer(entry.remaining_nanoseconds);
  }
  count(out, state.pending);
  for (const auto &entry : state.pending) {
    out.boolean(entry.transit);
    out.integer(entry.port_ordinal);
    out.integer(entry.next_hop);
    out.frame(entry.frame);
  }
  out.integer(state.forwarded_frames);
  out.integer(state.dropped_frames);
  out.integer(state.last_drop);
  out.integer(state.echo_reply_sequence);
  out.boolean(state.echo_reply_valid);
}

bool forwarder_state(Reader &in, RouterForwarderCheckpoint &state) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ports.resize(size);
  for (auto &value : state.ports)
    if (!forward_port(in, value))
      return false;
  if (!fib(in, state.fib) ||
      !count(in, size, device_catalog::arp_entries_per_router))
    return false;
  state.adjacencies.resize(size);
  for (auto &entry : state.adjacencies)
    if (!in.integer(entry.port_ordinal) || !in.integer(entry.address) ||
        !mac(in, entry.mac) || !in.integer(entry.remaining_nanoseconds))
      return false;
  if (!count(in, size, device_catalog::pending_ipv4_frames_per_router))
    return false;
  state.pending.resize(size);
  for (auto &entry : state.pending)
    if (!in.boolean(entry.transit) || !in.integer(entry.port_ordinal) ||
        !in.integer(entry.next_hop) || !in.frame(entry.frame))
      return false;
  return in.integer(state.forwarded_frames) &&
         in.integer(state.dropped_frames) && in.integer(state.last_drop) &&
         state.last_drop <= ForwardDrop::mtu_exceeded &&
         in.integer(state.echo_reply_sequence) &&
         in.boolean(state.echo_reply_valid);
}

void network_stored_frame(Writer &out, const NetworkStoredFrame &value) {
  out.integer(value.stage);
  out.integer(value.direction);
  out.boolean(value.routed);
  ipv4(out, value.next_hop);
  out.integer(value.remaining_ns);
  out.frame(value.frame);
}

bool network_stored_frame(Reader &in, NetworkStoredFrame &value) noexcept {
  return in.integer(value.stage) &&
         value.stage <= NetworkFrameStage::endpoint_reassembly &&
         in.integer(value.direction) && in.boolean(value.routed) &&
         ipv4(in, value.next_hop) && in.integer(value.remaining_ns) &&
         in.frame(value.frame);
}

void endpoint_state(Writer &out, const NetworkCheckpointState &state) {
  const auto &endpoint = state.endpoint;
  out.boolean(endpoint.neighbor_valid);
  ipv4(out, endpoint.neighbor_address);
  mac(out, endpoint.neighbor_mac);
  out.boolean(endpoint.pending_next_hop_valid);
  ipv4(out, endpoint.pending_next_hop);
  out.boolean(endpoint.reassembly_active);
  ipv4(out, endpoint.reassembly_source);
  ipv4(out, endpoint.reassembly_destination);
  out.integer(endpoint.reassembly_identification);
  out.integer(endpoint.reassembly_payload_octets);
  count(out, state.frames);
  for (const auto &frame : state.frames)
    network_stored_frame(out, frame);
}

bool endpoint_state(Reader &in, NetworkCheckpointState &state) {
  auto &endpoint = state.endpoint;
  if (!in.boolean(endpoint.neighbor_valid) ||
      !ipv4(in, endpoint.neighbor_address) ||
      !mac(in, endpoint.neighbor_mac) ||
      !in.boolean(endpoint.pending_next_hop_valid) ||
      !ipv4(in, endpoint.pending_next_hop) ||
      !in.boolean(endpoint.reassembly_active) ||
      !ipv4(in, endpoint.reassembly_source) ||
      !ipv4(in, endpoint.reassembly_destination) ||
      !in.integer(endpoint.reassembly_identification) ||
      !in.integer(endpoint.reassembly_payload_octets))
    return false;
  std::uint32_t size{};
  if (!count(in, size, 4U))
    return false;
  state.frames.resize(size);
  for (auto &frame : state.frames)
    if (!network_stored_frame(in, frame))
      return false;
  return true;
}

void host_state(Writer &out, const NetworkHostCheckpoint &state) {
  handle(out, state.host);
  endpoint_state(out, state.endpoint);
  mac(out, state.mac);
  ipv4(out, state.address);
  ipv4(out, state.gateway);
  out.integer(state.prefix_length);
  out.integer(state.mtu);
  out.integer(state.expected_sequence);
  out.boolean(state.configured);
  out.boolean(state.link_signal);
  out.boolean(state.ping_pending);
  out.boolean(state.ping_reply);
}

bool host_state(Reader &in, NetworkHostCheckpoint &state) {
  return handle(in, state.host) && endpoint_state(in, state.endpoint) &&
         mac(in, state.mac) && ipv4(in, state.address) &&
         ipv4(in, state.gateway) && in.integer(state.prefix_length) &&
         in.integer(state.mtu) &&
         in.integer(state.expected_sequence) && in.boolean(state.configured) &&
         in.boolean(state.link_signal) && in.boolean(state.ping_pending) &&
         in.boolean(state.ping_reply);
}

void fabric_frame(Writer &out, const FabricFrameCheckpoint &value) {
  out.frame(value.frame);
  out.integer(value.delivery_remaining_nanoseconds);
}

bool fabric_frame(Reader &in, FabricFrameCheckpoint &value) noexcept {
  return in.frame(value.frame) &&
         in.integer(value.delivery_remaining_nanoseconds);
}

void fabric_direction(Writer &out,
                      const FabricDirectionCheckpoint &value) {
  out.integer(value.bits_per_second);
  out.integer(value.propagation_nanoseconds);
  out.integer(value.transmitter_remaining_nanoseconds);
  for (const auto *frames : {&value.transmit, &value.in_flight,
                             &value.receive}) {
    count(out, *frames);
    for (const auto &frame : *frames)
      fabric_frame(out, frame);
  }
}

bool fabric_direction(Reader &in, FabricDirectionCheckpoint &value) {
  if (!in.integer(value.bits_per_second) ||
      !in.integer(value.propagation_nanoseconds) ||
      !in.integer(value.transmitter_remaining_nanoseconds))
    return false;
  std::array<std::vector<FabricFrameCheckpoint> *, 3> stages{
      &value.transmit, &value.in_flight, &value.receive};
  for (std::size_t index = 0; index < stages.size(); ++index) {
    std::uint32_t size{};
    const auto maximum = index == 1U ? PacketPool::capacity
                                     : device_catalog::link_queue_capacity;
    if (!count(in, size, maximum))
      return false;
    stages[index]->resize(size);
    for (auto &frame : *stages[index])
      if (!fabric_frame(in, frame))
        return false;
  }
  return true;
}

void fabric_state(Writer &out, const MultiDeviceFabricCheckpoint &state) {
  count(out, state.links);
  for (const auto &link : state.links) {
    handle(out, link.link);
    port_handle(out, link.endpoints[0]);
    port_handle(out, link.endpoints[1]);
    out.boolean(link.carrier);
    fabric_direction(out, link.directions[0]);
    fabric_direction(out, link.directions[1]);
  }
  out.integer(state.dropped_frames);
}

bool fabric_state(Reader &in, MultiDeviceFabricCheckpoint &state) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::maximum_links))
    return false;
  state.links.resize(size);
  for (auto &link : state.links)
    if (!handle(in, link.link) || !port_handle(in, link.endpoints[0]) ||
        !port_handle(in, link.endpoints[1]) ||
        !in.boolean(link.carrier) ||
        !fabric_direction(in, link.directions[0]) ||
        !fabric_direction(in, link.directions[1]))
      return false;
  return in.integer(state.dropped_frames);
}

void capture_state(Writer &out, const CaptureStoreCheckpoint &state) {
  count(out, state.points);
  for (const auto &point : state.points) {
    out.integer(point.id);
    out.string(point.name);
    out.boolean(point.active);
  }
  count(out, state.records);
  for (const auto &record : state.records) {
    out.integer(record.timestamp_us);
    out.integer(record.capture_point);
    out.frame(record.frame);
  }
}

bool capture_state(Reader &in, CaptureStoreCheckpoint &state) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::selected_capture_points))
    return false;
  state.points.resize(size);
  for (auto &point : state.points)
    if (!in.integer(point.id) ||
        !in.string(point.name, device_catalog::capture_point_name_bytes) ||
        !in.boolean(point.active))
      return false;
  constexpr auto maximum_records =
      device_catalog::capture_store_bytes / sizeof(CaptureRecordCheckpoint);
  if (!count(in, size, maximum_records))
    return false;
  state.records.resize(size);
  for (auto &record : state.records)
    if (!in.integer(record.timestamp_us) ||
        !in.integer(record.capture_point) || !in.frame(record.frame))
      return false;
  return true;
}

void capture_program(Writer &out, const CapturePointProgram &value) {
  out.integer(value.id);
  out.integer(value.kind);
  handle(out, value.link);
  node(out, value.node);
  out.integer(value.port_ordinal);
  out.integer(value.link_endpoint);
  out.boolean(value.selected);
  out.integer(value.name_size);
  for (std::size_t index = 0; index < value.name_size; ++index)
    out.integer<std::uint8_t>(static_cast<std::uint8_t>(value.name[index]));
}

bool capture_program(Reader &in, CapturePointProgram &value) noexcept {
  if (!in.integer(value.id) || !in.integer(value.kind) ||
      value.kind > CapturePointKind::cpm_punt || !handle(in, value.link) ||
      !node(in, value.node) || !in.integer(value.port_ordinal) ||
      !in.integer(value.link_endpoint) || !in.boolean(value.selected) ||
      !in.integer(value.name_size) || value.name_size > value.name.size())
    return false;
  for (std::size_t index = 0; index < value.name_size; ++index) {
    std::uint8_t byte{};
    if (!in.integer(byte))
      return false;
    value.name[index] = static_cast<char>(byte);
  }
  return true;
}

void network_state(Writer &out, const NetworkPlaneCheckpoint &state) {
  count(out, state.routers);
  for (const auto &router : state.routers) {
    handle(out, router.device);
    forwarder_state(out, router.forwarding);
  }
  count(out, state.hosts);
  for (const auto &host : state.hosts)
    host_state(out, host);
  fabric_state(out, state.fabric);
  capture_state(out, state.capture);
  count(out, state.capture_points);
  for (const auto &program : state.capture_points)
    capture_program(out, program);
  out.integer(state.capture_dropped);
  out.integer(state.ingress_ring_dropped);
  out.integer(state.egress_ring_dropped);
  out.integer(state.missing_binding_dropped);
}

bool network_state(Reader &in, NetworkPlaneCheckpoint &state) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::maximum_routers))
    return false;
  state.routers.resize(size);
  for (auto &router : state.routers)
    if (!handle(in, router.device) ||
        !forwarder_state(in, router.forwarding))
      return false;
  if (!count(in, size, device_catalog::maximum_hosts))
    return false;
  state.hosts.resize(size);
  for (auto &host : state.hosts)
    if (!host_state(in, host))
      return false;
  if (!fabric_state(in, state.fabric) || !capture_state(in, state.capture) ||
      !count(in, size, device_catalog::selected_capture_points))
    return false;
  state.capture_points.resize(size);
  for (auto &program : state.capture_points)
    if (!capture_program(in, program))
      return false;
  return in.integer(state.capture_dropped) &&
         in.integer(state.ingress_ring_dropped) &&
         in.integer(state.egress_ring_dropped) &&
         in.integer(state.missing_binding_dropped);
}

void portable_configuration(Writer &out,
                            const PortableConfigurationCheckpoint &state);
bool portable_configuration(Reader &in,
                            PortableConfigurationCheckpoint &state);

void portable_router(Writer &out,
                     const PortableRouterIntentCheckpoint &state) {
  // Names and descriptions are management-plane configuration. They are
  // written after forwarding state so restoring a bare checkpoint never has
  // to guess them from a currently open project in the browser.
  handle(out, state.device);
  count(out, state.ports);
  for (const auto &port : state.ports) {
    out.string(port.id);
    out.boolean(port.admin_enabled);
    out.integer(port.mtu);
    out.integer(port.speed_mbps);
    out.string(port.description);
  }
  count(out, state.interfaces);
  for (const auto &interface : state.interfaces) {
    out.string(interface.name);
    out.string(interface.port_id);
    mac(out, interface.mac);
    out.integer(interface.address);
    out.integer(interface.prefix_length);
    out.boolean(interface.admin_enabled);
    out.boolean(interface.port_configured);
    out.boolean(interface.address_configured);
  }
  count(out, state.routes);
  for (const auto &route : state.routes) {
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
  }
  out.boolean(state.global_candidate_initialized);
  if (state.global_candidate_initialized)
    portable_configuration(out, state.global_candidate);
}

bool portable_router(Reader &in, PortableRouterIntentCheckpoint &state) {
  std::uint32_t size{};
  if (!handle(in, state.device) ||
      !count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ports.resize(size);
  for (auto &port : state.ports) {
    if (!in.string(port.id, 32) || port.id.empty() ||
        !in.boolean(port.admin_enabled) || !in.integer(port.mtu) ||
        port.mtu < device_catalog::minimum_network_mtu ||
        port.mtu > device_catalog::maximum_network_mtu ||
        !in.integer(port.speed_mbps) || !port.speed_mbps ||
        !in.string(port.description, 80))
      return false;
  }
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.interfaces.resize(size);
  for (auto &interface : state.interfaces) {
    if (!in.string(interface.name, 64) || interface.name.empty() ||
        !in.string(interface.port_id, 32) ||
        !mac(in, interface.mac) || !in.integer(interface.address) ||
        !in.integer(interface.prefix_length) || interface.prefix_length > 32U ||
        !in.boolean(interface.admin_enabled) ||
        !in.boolean(interface.port_configured) ||
        !in.boolean(interface.address_configured) ||
        (interface.port_configured != !interface.port_id.empty()) ||
        (!interface.address_configured &&
         (interface.address || interface.prefix_length)))
      return false;
  }
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.routes.resize(size);
  for (auto &route : state.routes) {
    if (!in.integer(route.network) || !in.integer(route.next_hop) ||
        !route.next_hop || !in.integer(route.prefix_length) ||
        route.prefix_length > 32U ||
        route.network !=
            (route.network & routing::prefix_mask(route.prefix_length)))
      return false;
  }
  if (!in.boolean(state.global_candidate_initialized))
    return false;
  return !state.global_candidate_initialized ||
         portable_configuration(in, state.global_candidate);
}

void portable_configuration(Writer &out,
                            const PortableConfigurationCheckpoint &state) {
  out.string(state.system_name);
  for (const auto &card : state.cards) {
    out.string(card.provisioned);
    out.boolean(card.admin_enabled);
    for (const auto &mda : card.mdas) {
      out.string(mda.provisioned);
      out.boolean(mda.admin_enabled);
    }
  }
  count(out, state.ports);
  for (const auto &port : state.ports) {
    out.string(port.id);
    out.boolean(port.admin_enabled);
    out.integer(port.mtu);
    out.integer(port.speed_mbps);
    out.string(port.description);
  }
  count(out, state.interfaces);
  for (const auto &interface : state.interfaces) {
    out.string(interface.name);
    out.string(interface.port_id);
    mac(out, interface.mac);
    out.integer(interface.address);
    out.integer(interface.prefix_length);
    out.boolean(interface.admin_enabled);
    out.boolean(interface.port_configured);
    out.boolean(interface.address_configured);
  }
  count(out, state.routes);
  for (const auto &route : state.routes) {
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
  }
}

bool portable_configuration(Reader &in,
                            PortableConfigurationCheckpoint &state) {
  if (!in.string(state.system_name, 64) || state.system_name.empty())
    return false;
  for (auto &card : state.cards) {
    if (!in.string(card.provisioned, 64) ||
        !in.boolean(card.admin_enabled))
      return false;
    for (auto &mda : card.mdas)
      if (!in.string(mda.provisioned, 64) ||
          !in.boolean(mda.admin_enabled))
        return false;
  }
  std::uint32_t size{};
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ports.resize(size);
  for (auto &port : state.ports)
    if (!in.string(port.id, 32) || port.id.empty() ||
        !in.boolean(port.admin_enabled) || !in.integer(port.mtu) ||
        port.mtu < device_catalog::minimum_network_mtu ||
        port.mtu > device_catalog::maximum_network_mtu ||
        !in.integer(port.speed_mbps) || !port.speed_mbps ||
        !in.string(port.description, 80))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.interfaces.resize(size);
  for (auto &interface : state.interfaces)
    if (!in.string(interface.name, 64) || interface.name.empty() ||
        !in.string(interface.port_id, 32) || !mac(in, interface.mac) ||
        !in.integer(interface.address) ||
        !in.integer(interface.prefix_length) || interface.prefix_length > 32U ||
        !in.boolean(interface.admin_enabled) ||
        !in.boolean(interface.port_configured) ||
        !in.boolean(interface.address_configured) ||
        (interface.port_configured != !interface.port_id.empty()) ||
        (!interface.address_configured &&
         (interface.address || interface.prefix_length)))
      return false;
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.routes.resize(size);
  for (auto &route : state.routes)
    if (!in.integer(route.network) || !in.integer(route.next_hop) ||
        !route.next_hop || !in.integer(route.prefix_length) ||
        route.prefix_length > 32U ||
        route.network !=
            (route.network & routing::prefix_mask(route.prefix_length)))
      return false;
  return true;
}

void portable_host(Writer &out, const PortableHostIntentCheckpoint &state) {
  handle(out, state.host);
  mac(out, state.mac);
  ipv4(out, state.address);
  ipv4(out, state.gateway);
  out.integer(state.prefix_length);
  out.integer(state.mtu);
  out.boolean(state.configured);
}

bool portable_host(Reader &in, PortableHostIntentCheckpoint &state) noexcept {
  if (!handle(in, state.host) || !mac(in, state.mac) ||
      !ipv4(in, state.address) || !ipv4(in, state.gateway) ||
      !in.integer(state.prefix_length) || state.prefix_length > 32U ||
      !in.integer(state.mtu) || !in.boolean(state.configured))
    return false;
  // An unconfigured host has no user-selected MTU yet. Configured hosts must
  // satisfy the IPv4 minimum accepted by the live host operation.
  return !state.configured ||
         (state.mtu >= device_catalog::minimum_host_ipv4_mtu &&
          state.mtu <= device_catalog::maximum_network_mtu);
}

void portable_capture(Writer &out,
                      const PortableCaptureIntentCheckpoint &state) {
  out.integer(state.id);
  out.integer(state.kind);
  out.string(state.object_id);
  out.string(state.port_id);
  out.integer(state.direction);
  out.boolean(state.selected);
}

bool portable_capture(Reader &in,
                      PortableCaptureIntentCheckpoint &state) {
  return in.integer(state.id) &&
         state.id < device_catalog::selected_capture_points &&
         in.integer(state.kind) && state.kind <= CapturePointKind::cpm_punt &&
         in.string(state.object_id, 64) && !state.object_id.empty() &&
         in.string(state.port_id, 32) && in.integer(state.direction) &&
         state.direction <= 1U && in.boolean(state.selected);
}

} // namespace

std::vector<std::uint8_t>
encode(const RuntimeSupervisorCheckpoint &state) {
  Writer out;
  for (const auto byte : magic)
    out.integer(byte);
  out.integer(abi);
  out.integer(schema_hash);
  out.integer(device_catalog::catalog_hash);
  out.integer(device_catalog::build_hash);
  device_registry(out, state.devices);
  host_registry(out, state.hosts);
  topology_registry(out, state.topology);
  session_registry(out, state.sessions);
  count(out, state.hardware);
  for (const auto &value : state.hardware)
    hardware_state(out, value);
  count(out, state.control);
  for (const auto &value : state.control)
    control_state(out, value);
  workflows(out, state.workflows);
  network_state(out, state.network);
  out.integer(state.next_network_command_id);
  count(out, state.portable_routers);
  for (const auto &value : state.portable_routers)
    portable_router(out, value);
  count(out, state.portable_session_candidates);
  for (const auto &value : state.portable_session_candidates) {
    handle(out, value.session);
    out.boolean(value.initialized);
    if (value.initialized)
      portable_configuration(out, value.candidate);
    out.integer(value.ping_destination);
    out.integer(value.ping_sequence);
    out.integer(value.ping_payload_octets);
    out.integer(value.ping_requested);
    out.integer(value.ping_sent);
    out.integer(value.ping_received);
    out.integer(value.ping_next_send_ns);
    out.integer(value.ping_reply_deadline_ns);
    out.boolean(value.ping_dont_fragment);
    out.boolean(value.ping_waiting);
    out.boolean(value.ping_active);
    out.boolean(value.ping_cancel_requested);
  }
  count(out, state.portable_hosts);
  for (const auto &value : state.portable_hosts)
    portable_host(out, value);
  count(out, state.portable_capture_points);
  for (const auto &value : state.portable_capture_points)
    portable_capture(out, value);
  return std::move(out).finish();
}

std::unique_ptr<RuntimeSupervisorCheckpoint>
decode(std::span<const std::uint8_t> bytes) {
  if (bytes.empty() || bytes.size() > maximum_checkpoint_bytes)
    return nullptr;
  try {
    Reader in{bytes};
    std::uint32_t input_abi{};
    std::uint64_t input_schema{};
    std::uint64_t input_profile{};
    std::uint64_t input_build{};
    if (!in.exact(magic) || !in.integer(input_abi) || input_abi != abi ||
        !in.integer(input_schema) || input_schema != schema_hash ||
        !in.integer(input_profile) ||
        input_profile != device_catalog::catalog_hash ||
        !in.integer(input_build) ||
        input_build != device_catalog::build_hash)
      return nullptr;
    auto state = std::make_unique<RuntimeSupervisorCheckpoint>();
    if (!device_registry(in, state->devices) ||
        !host_registry(in, state->hosts) ||
        !topology_registry(in, state->topology) ||
        !session_registry(in, state->sessions))
      return nullptr;
    std::uint32_t size{};
    if (!count(in, size, device_catalog::maximum_routers))
      return nullptr;
    state->hardware.resize(size);
    for (auto &value : state->hardware)
      if (!hardware_state(in, value))
        return nullptr;
    if (!count(in, size, device_catalog::maximum_routers))
      return nullptr;
    state->control.resize(size);
    for (auto &value : state->control)
      if (!control_state(in, value))
        return nullptr;
    if (!workflows(in, state->workflows) ||
        !network_state(in, state->network) ||
        !in.integer(state->next_network_command_id) ||
        !count(in, size, device_catalog::maximum_routers))
      return nullptr;
    state->portable_routers.resize(size);
    for (auto &value : state->portable_routers)
      if (!portable_router(in, value))
        return nullptr;
    if (!count(in, size, device_catalog::maximum_routers *
                             device_catalog::maximum_sessions_per_router))
      return nullptr;
    state->portable_session_candidates.resize(size);
    for (auto &value : state->portable_session_candidates) {
      if (!handle(in, value.session) || !in.boolean(value.initialized) ||
          (value.initialized &&
           !portable_configuration(in, value.candidate)) ||
          !in.integer(value.ping_destination) ||
          !in.integer(value.ping_sequence) ||
          !in.integer(value.ping_payload_octets) ||
          value.ping_payload_octets <
              device_catalog::minimum_ping_payload_octets ||
          value.ping_payload_octets >
              device_catalog::maximum_ping_payload_octets ||
          !in.integer(value.ping_requested) ||
          value.ping_requested > device_catalog::maximum_ping_count ||
          !in.integer(value.ping_sent) ||
          !in.integer(value.ping_received) ||
          value.ping_received > value.ping_sent ||
          value.ping_sent > value.ping_requested ||
          !in.integer(value.ping_next_send_ns) ||
          value.ping_next_send_ns > 86'400'000'000'000ULL ||
          !in.integer(value.ping_reply_deadline_ns) ||
          value.ping_reply_deadline_ns > 86'400'000'000'000ULL ||
          !in.boolean(value.ping_dont_fragment) ||
          !in.boolean(value.ping_waiting) ||
          !in.boolean(value.ping_active) ||
          !in.boolean(value.ping_cancel_requested) ||
          (value.ping_waiting && !value.ping_active) ||
          (value.ping_active && !value.ping_requested))
        return nullptr;
    }
    if (!count(in, size, device_catalog::maximum_hosts))
      return nullptr;
    state->portable_hosts.resize(size);
    for (auto &value : state->portable_hosts)
      if (!portable_host(in, value))
        return nullptr;
    if (!count(in, size, device_catalog::selected_capture_points))
      return nullptr;
    state->portable_capture_points.resize(size);
    for (auto &value : state->portable_capture_points)
      if (!portable_capture(in, value))
        return nullptr;
    if (in.remaining() != 0)
      return nullptr;
    return state;
  } catch (const std::bad_alloc &) {
    return nullptr;
  } catch (const std::length_error &) {
    return nullptr;
  }
}

} // namespace router::lab::checkpoint_v5
