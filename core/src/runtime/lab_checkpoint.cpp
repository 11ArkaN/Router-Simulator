// ABI 7 codec implementation. Decoding creates a detached value graph. The
// supervisor performs cross-owner validation and atomic commit only afterwards.

#include "router/lab_checkpoint.hpp"

#include "router/generated_device_catalog.hpp"
#include "router/tcp_checkpoint_codec.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>

namespace router::lab::checkpoint_v7 {
namespace {

inline constexpr std::array<std::uint8_t, 8> magic{'R', 'S', 'L', 'A',
                                                   'B', '0', '7', 0};
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

  // Callers write a length first for variable protocol state. This primitive
  // copies only the supplied bytes and intentionally owns no implicit bound.
  void octets(std::span<const std::uint8_t> value) {
    bytes_.insert(bytes_.end(), value.begin(), value.end());
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

  bool octets(std::span<std::uint8_t> value) noexcept {
    if (remaining() < value.size())
      return false;
    std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                value.size(), value.begin());
    offset_ += value.size();
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

  // Length-delimited sub-codecs borrow the immutable checkpoint image. The
  // returned span is valid for this Reader's lifetime and advances the parent
  // cursor exactly once, avoiding a second allocation during decode.
  std::optional<std::span<const std::uint8_t>> view(std::size_t size) noexcept {
    if (remaining() < size)
      return std::nullopt;
    const auto result = bytes_.subspan(offset_, size);
    offset_ += size;
    return result;
  }

  [[nodiscard]] std::size_t remaining() const noexcept {
    return bytes_.size() - offset_;
  }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{};
};

template <typename Tag> void handle(Writer &out, Handle<Tag> value) {
  out.integer(value.index);
  out.integer(value.generation);
}

template <typename Tag> bool handle(Reader &in, Handle<Tag> &value) noexcept {
  return in.integer(value.index) && in.integer(value.generation);
}

void node(Writer &out, NodeHandle value) {
  out.integer(value.kind);
  out.integer(value.index);
  out.integer(value.generation);
}

bool node(Reader &in, NodeHandle &value) noexcept {
  // The serialized discriminant is validated before any index is consumed.
  // This prevents corrupt project bytes from manufacturing a fourth endpoint
  // class that downstream router/host/switch ownership code cannot handle.
  return in.integer(value.kind) &&
         value.kind <= NodeKind::ethernet_switch &&
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

void ipv6(Writer &out, const packet::Ipv6 &value) {
  for (const auto byte : value)
    out.integer(byte);
}

bool ipv6(Reader &in, packet::Ipv6 &value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [&](auto &byte) { return in.integer(byte); });
}

void ip_address(Writer &out, const ip::IpAddress &value) {
  out.integer(value.family);
  // The full fixed representation is serialized for both families. This
  // keeps checkpoint records independent of native unions and lets decode
  // verify the required zero tail for IPv4 before publishing any state.
  for (const auto byte : value.bytes)
    out.integer(byte);
}

bool ip_address(Reader &in, ip::IpAddress &value) noexcept {
  if (!in.integer(value.family) ||
      (value.family != ip::AddressFamily::ipv4 &&
       value.family != ip::AddressFamily::ipv6) ||
      !std::all_of(value.bytes.begin(), value.bytes.end(),
                   [&](auto &byte) { return in.integer(byte); }))
    return false;
  return value.family == ip::AddressFamily::ipv6 ||
         std::all_of(value.bytes.begin() + 4, value.bytes.end(),
                     [](auto byte) { return byte == 0U; });
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
  out.integer(value.arp_timeout_seconds);
  out.integer(value.arp_retry_deciseconds);
  out.integer(value.icmp_redirect_maximum);
  out.integer(value.icmp_redirect_interval_seconds);
  out.boolean(value.icmp_redirects_enabled);
  out.boolean(value.ipv6_configured);
  ipv6(out, value.ipv6_address);
  ipv6(out, value.ipv6_network);
  ipv6(out, value.ipv6_link_local);
  out.integer(value.ipv6_prefix_length);
  out.integer(value.nd_reachable_time_milliseconds);
  out.integer(value.nd_stale_time_seconds);
  out.integer(value.ipv6_unsolicited_learning);
  out.integer(value.ipv6_proactive_refresh);
  out.integer(value.ipv6_neighbor_limit);
  out.integer(value.ipv6_neighbor_limit_threshold_percent);
  out.boolean(value.ipv6_neighbor_limit_configured);
  out.boolean(value.ipv6_neighbor_limit_log_only);
  out.integer(value.icmp6_redirect_maximum);
  out.integer(value.icmp6_redirect_interval_seconds);
  out.boolean(value.icmp6_redirects_enabled);
  out.boolean(value.ipv4_configured);
}

bool forward_port(Reader &in, ForwardPort &value) noexcept {
  return in.boolean(value.configured) && in.boolean(value.operational) &&
         in.integer(value.ordinal) && in.integer(value.mtu) &&
         in.integer(value.address) && in.integer(value.network) &&
         in.integer(value.speed_mbps) && in.integer(value.prefix_length) &&
         mac(in, value.mac) && in.integer(value.arp_timeout_seconds) &&
         in.integer(value.arp_retry_deciseconds) &&
         in.integer(value.icmp_redirect_maximum) &&
         in.integer(value.icmp_redirect_interval_seconds) &&
         in.boolean(value.icmp_redirects_enabled) &&
         in.boolean(value.ipv6_configured) && ipv6(in, value.ipv6_address) &&
         ipv6(in, value.ipv6_network) && ipv6(in, value.ipv6_link_local) &&
         in.integer(value.ipv6_prefix_length) &&
         in.integer(value.nd_reachable_time_milliseconds) &&
         in.integer(value.nd_stale_time_seconds) &&
         in.integer(value.ipv6_unsolicited_learning) &&
         value.ipv6_unsolicited_learning <= Ipv6UnsolicitedLearning::both &&
         in.integer(value.ipv6_proactive_refresh) &&
         value.ipv6_proactive_refresh <= Ipv6UnsolicitedLearning::both &&
         in.integer(value.ipv6_neighbor_limit) &&
         in.integer(value.ipv6_neighbor_limit_threshold_percent) &&
         in.boolean(value.ipv6_neighbor_limit_configured) &&
         in.boolean(value.ipv6_neighbor_limit_log_only) &&
         in.integer(value.icmp6_redirect_maximum) &&
         in.integer(value.icmp6_redirect_interval_seconds) &&
         in.boolean(value.icmp6_redirects_enabled) &&
         in.boolean(value.ipv4_configured);
}

void route(Writer &out, const routing::Route &value) {
  out.integer(value.network);
  out.integer(value.next_hop);
  out.integer(value.port_ordinal);
  out.integer(value.prefix_length);
  out.integer(value.preference);
  out.integer(value.metric);
  out.integer(value.source);
  out.boolean(value.local_system);
  // OSPF route provenance is part of forwarding continuity. Omitting it would
  // restore a byte-valid FIB whose later RIB comparisons and show output no
  // longer describe the protocol generation that produced it.
  out.integer(value.ospf_path_type);
  out.integer(value.protocol_instance);
}

bool route(Reader &in, routing::Route &value) noexcept {
  return in.integer(value.network) && in.integer(value.next_hop) &&
         in.integer(value.port_ordinal) && in.integer(value.prefix_length) &&
         in.integer(value.preference) && in.integer(value.metric) &&
         in.integer(value.source) &&
         value.source <= routing::RouteSource::ospf3 &&
         in.boolean(value.local_system) && in.integer(value.ospf_path_type) &&
         value.ospf_path_type <= routing::OspfPathType::nssa_type_2 &&
         in.integer(value.protocol_instance);
}

void fib(Writer &out, const routing::FibProgram &value) {
  out.integer(value.generation);
  out.integer(value.count);
  for (std::size_t index = 0; index < value.count; ++index)
    route(out, value.routes[index]);
  out.integer(value.loop_free_alternate_count);
  for (std::size_t index{}; index < value.loop_free_alternate_count; ++index)
    route(out, value.routes[value.count + index]);
}

bool fib(Reader &in, routing::FibProgram &value) noexcept {
  if (!in.integer(value.generation) || !in.integer(value.count) ||
      value.count > value.routes.size())
    return false;
  for (std::size_t index = 0; index < value.count; ++index)
    if (!route(in, value.routes[index]))
      return false;
  if (!in.integer(value.loop_free_alternate_count) ||
      value.count + value.loop_free_alternate_count > value.routes.size())
    return false;
  for (std::size_t index{}; index < value.loop_free_alternate_count; ++index)
    if (!route(in, value.routes[value.count + index]))
      return false;
  return true;
}

void ipv6_route(Writer &out, const routing::Ipv6Route &value) {
  ipv6(out, value.network);
  ipv6(out, value.next_hop);
  out.integer(value.interface_id);
  out.integer(value.physical_port_ordinal);
  out.integer(value.prefix_length);
  out.integer(value.preference);
  out.integer(value.metric);
  out.integer(value.source);
  out.integer(value.ospf_path_type);
  out.integer(value.protocol_instance);
}

bool ipv6_route(Reader &in, routing::Ipv6Route &value) noexcept {
  return ipv6(in, value.network) && ipv6(in, value.next_hop) &&
         in.integer(value.interface_id) &&
         in.integer(value.physical_port_ordinal) &&
         in.integer(value.prefix_length) && in.integer(value.preference) &&
         in.integer(value.metric) && in.integer(value.source) &&
         value.source <= routing::RouteSource::ospf3 &&
         in.integer(value.ospf_path_type) &&
         value.ospf_path_type <= routing::OspfPathType::nssa_type_2 &&
         in.integer(value.protocol_instance);
}

void ipv6_fib(Writer &out, const routing::Ipv6FibProgram &value) {
  out.integer(value.generation);
  out.integer(value.count);
  for (std::size_t index = 0; index < value.count; ++index)
    ipv6_route(out, value.routes[index]);
  out.integer(value.loop_free_alternate_count);
  for (std::size_t index{}; index < value.loop_free_alternate_count; ++index)
    ipv6_route(out, value.routes[value.count + index]);
}

bool ipv6_fib(Reader &in, routing::Ipv6FibProgram &value) noexcept {
  if (!in.integer(value.generation) || !in.integer(value.count) ||
      value.count > value.routes.size())
    return false;
  for (std::size_t index = 0; index < value.count; ++index)
    if (!ipv6_route(in, value.routes[index]))
      return false;
  if (!in.integer(value.loop_free_alternate_count) ||
      value.count + value.loop_free_alternate_count > value.routes.size())
    return false;
  for (std::size_t index{}; index < value.loop_free_alternate_count; ++index)
    if (!ipv6_route(in, value.routes[value.count + index]))
      return false;
  return true;
}

template <typename T> void count(Writer &out, const std::vector<T> &values) {
  if (values.size() > std::numeric_limits<std::uint32_t>::max())
    throw std::length_error("checkpoint vector exceeds ABI bound");
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(values.size()));
}

bool count(Reader &in, std::uint32_t &value, std::size_t maximum) noexcept {
  return in.integer(value) && value <= maximum;
}

void ipv6_reassembly_entries(
    Writer &out, const std::vector<packet::Ipv6ReassemblyCheckpoint> &value);
bool ipv6_reassembly_entries(
    Reader &in, std::vector<packet::Ipv6ReassemblyCheckpoint> &value);
void ipv4_reassembly_entries(
    Writer &out, const std::vector<packet::Ipv4ReassemblyCheckpoint> &value);
bool ipv4_reassembly_entries(
    Reader &in, std::vector<packet::Ipv4ReassemblyCheckpoint> &value);
// Router and host DHCPv4 services share one wire representation. Declaring
// these helpers before the router codec prevents a second, subtly divergent
// encoding for the same RFC 2131 state machine.
void dhcpv4_server_checkpoint(Writer &out,
                              const dhcpv4::ServerCheckpoint &value);
bool dhcpv4_server_checkpoint(Reader &in,
                              dhcpv4::ServerCheckpoint &value);
// The router and dedicated endpoint also share one DHCPv6 checkpoint codec.
// Its definition follows the client codec, but the router forwarding payload
// is serialized earlier in this translation unit.
void dhcpv6_server_checkpoint(Writer &out,
                              const dhcpv6::ServerCheckpoint &value);
bool dhcpv6_server_checkpoint(Reader &in,
                              dhcpv6::ServerCheckpoint &value);

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
        !in.string(entry.system_name, 64) || !in.string(entry.profile_id, 64) ||
        !in.boolean(entry.quiescing))
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

void switch_registry(Writer &out, const SwitchRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    out.string(entry.node_id);
    out.string(entry.name);
    out.string(entry.profile_id);
    count(out, entry.ports);
    for (const auto &port : entry.ports) {
      out.integer(port.speed_mbps);
      out.integer(port.mtu);
      out.boolean(port.admin_enabled);
    }
  }
}

bool switch_registry(Reader &in, SwitchRegistryCheckpoint &state) {
  std::uint32_t size{};
  if (!generations(in, state.generations) ||
      !count(in, size, device_catalog::maximum_switches))
    return false;
  state.entries.resize(size);
  for (auto &entry : state.entries) {
    if (!handle(in, entry.handle) || !in.string(entry.node_id, 64) ||
        !in.string(entry.name, 64) || !in.string(entry.profile_id, 64))
      return false;
    const auto *profile =
        device_catalog::find_ethernet_switch_profile(entry.profile_id);
    if (!profile || !count(in, size, profile->port_count))
      return false;
    entry.ports.resize(size);
    for (auto &port : entry.ports)
      if (!in.integer(port.speed_mbps) || !in.integer(port.mtu) ||
          !in.boolean(port.admin_enabled))
        return false;
  }
  return true;
}

void link_endpoint(Writer &out, const LinkEndpoint &value) {
  node(out, value.node);
  out.string(value.port_id);
}

bool link_endpoint(Reader &in, LinkEndpoint &value) {
  return node(in, value.node) && in.string(value.port_id, 32);
}

void topology_registry(Writer &out, const TopologyRegistryCheckpoint &state) {
  generations(out, state.generations);
  count(out, state.entries);
  for (const auto &entry : state.entries) {
    handle(out, entry.handle);
    out.string(entry.record.link_id);
    link_endpoint(out, entry.record.endpoints[0]);
    link_endpoint(out, entry.record.endpoints[1]);
    out.boolean(entry.record.admin_enabled);
    out.integer(entry.record.configured_speed_mbps);
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
    if (!handle(in, entry.handle) || !in.string(entry.record.link_id, 64) ||
        !link_endpoint(in, entry.record.endpoints[0]) ||
        !link_endpoint(in, entry.record.endpoints[1]) ||
        !in.boolean(entry.record.admin_enabled) ||
        !in.integer(entry.record.configured_speed_mbps) ||
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
        !in.string(classic_path, entry.record.cli.classic_path.size() - 1U) ||
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
    std::copy(md_path.begin(), md_path.end(), entry.record.cli.md_path.begin());
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
         in.boolean(value.admin_enabled) && in.boolean(value.link_signal) &&
         in.integer(value.generation) && in.integer(value.card_slot) &&
         in.integer(value.mda_slot) && in.integer(value.port_number) &&
         in.integer(value.mtu) && in.integer(value.speed_mbps);
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
      if (!in.string(mda.provisioned, 64) || !in.string(mda.equipped, 64) ||
          !in.boolean(mda.admin_enabled))
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
  out.boolean(value.local_system);
}

bool connected(Reader &in, routing::ConnectedInput &value) noexcept {
  return in.boolean(value.configured) && in.boolean(value.operational) &&
         in.integer(value.network) && in.integer(value.port_ordinal) &&
         in.integer(value.prefix_length) && in.boolean(value.local_system);
}

void static_route(Writer &out, const routing::StaticInput &value) {
  out.boolean(value.configured);
  out.integer(value.network);
  out.integer(value.next_hop);
  out.integer(value.prefix_length);
  out.boolean(value.indirect);
}

void ipv6_connected(Writer &out, const routing::Ipv6ConnectedInput &value) {
  out.boolean(value.configured);
  out.boolean(value.operational);
  ipv6(out, value.network);
  out.integer(value.interface_id);
  out.integer(value.physical_port_ordinal);
  out.integer(value.prefix_length);
}

bool ipv6_connected(Reader &in, routing::Ipv6ConnectedInput &value) noexcept {
  return in.boolean(value.configured) && in.boolean(value.operational) &&
         ipv6(in, value.network) && in.integer(value.interface_id) &&
         in.integer(value.physical_port_ordinal) &&
         in.integer(value.prefix_length);
}

void ipv6_static_route(Writer &out, const routing::Ipv6StaticInput &value) {
  out.boolean(value.configured);
  out.boolean(value.outgoing_interface_set);
  ipv6(out, value.network);
  ipv6(out, value.next_hop);
  out.integer(value.outgoing_interface_id);
  out.integer(value.prefix_length);
  out.boolean(value.indirect);
}

bool ipv6_static_route(Reader &in, routing::Ipv6StaticInput &value) noexcept {
  return in.boolean(value.configured) &&
         in.boolean(value.outgoing_interface_set) && ipv6(in, value.network) &&
         ipv6(in, value.next_hop) && in.integer(value.outgoing_interface_id) &&
         in.integer(value.prefix_length) && in.boolean(value.indirect);
}

bool static_route(Reader &in, routing::StaticInput &value) noexcept {
  return in.boolean(value.configured) && in.integer(value.network) &&
         in.integer(value.next_hop) && in.integer(value.prefix_length) &&
         in.boolean(value.indirect);
}

void rdnss_information(Writer &out, const packet::nd::RdnssInformation &rdnss) {
  out.integer(rdnss.count);
  for (std::size_t index = 0; index < rdnss.count; ++index) {
    ipv6(out, rdnss.servers[index].address);
    out.integer(rdnss.servers[index].lifetime_seconds);
  }
}

bool rdnss_information(Reader &in,
                       packet::nd::RdnssInformation &rdnss) noexcept {
  if (!in.integer(rdnss.count) || rdnss.count > rdnss.servers.size())
    return false;
  for (std::size_t index = 0; index < rdnss.count; ++index)
    if (!ipv6(in, rdnss.servers[index].address) ||
        !in.integer(rdnss.servers[index].lifetime_seconds))
      return false;
  return true;
}

bool valid_rdnss_information(const packet::nd::RdnssInformation &rdnss,
                             std::uint32_t lifetime_seconds) noexcept {
  if (lifetime_seconds != device_catalog::ra_infinite_lifetime &&
      (lifetime_seconds < device_catalog::ra_minimum_rdnss_lifetime ||
       lifetime_seconds > device_catalog::ra_maximum_rdnss_lifetime))
    return false;
  for (std::size_t index = 0; index < rdnss.count; ++index)
    if (ip::is_unspecified(rdnss.servers[index].address) ||
        ip::is_multicast(rdnss.servers[index].address) ||
        rdnss.servers[index].lifetime_seconds != lifetime_seconds)
      return false;
  return true;
}

void router_advertisement_config(
    Writer &out, const packet::nd::RouterAdvertisementConfig &config);
bool router_advertisement_config(
    Reader &in, packet::nd::RouterAdvertisementConfig &config) noexcept;
void mld_router_configuration(Writer &out, const MldRouterConfiguration &value);
bool mld_router_configuration(Reader &in,
                              MldRouterConfiguration &value) noexcept;

// SSM translation is configuration owned by control and a resolved program
// owned by forwarding. Keeping one wire representation for both checkpoints
// prevents the two owners from silently accepting different range semantics.
void mld_ssm_translations(Writer &out,
                          const std::vector<MldSsmTranslation> &translations) {
  count(out, translations);
  for (const auto &translation : translations) {
    ipv6(out, translation.start);
    ipv6(out, translation.end);
    ipv6(out, translation.source);
  }
}

bool mld_ssm_translations(
    Reader &in, std::vector<MldSsmTranslation> &translations) noexcept {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::mld_router_group_sources_per_interface))
    return false;
  try {
    translations.resize(size);
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (auto &translation : translations)
    if (!ipv6(in, translation.start) || !ipv6(in, translation.end) ||
        !ipv6(in, translation.source))
      return false;
  return true;
}

void mld_import_policy(Writer &out, const mld::ImportPolicyCheckpoint &policy) {
  count(out, policy.entries);
  out.integer(policy.default_action);
  for (const auto &entry : policy.entries) {
    out.integer(entry.number);
    out.integer(entry.term);
    out.boolean(entry.group.has_value());
    if (entry.group) {
      ipv6(out, entry.group->network);
      out.integer(entry.group->length);
    }
    out.boolean(entry.source.has_value());
    if (entry.source) {
      ipv6(out, entry.source->network);
      out.integer(entry.source->length);
    }
    out.integer(entry.action);
    out.boolean(entry.protocol_mld);
  }
}

bool mld_import_policy(Reader &in,
                       mld::ImportPolicyCheckpoint &policy) noexcept {
  std::uint32_t size{};
  // Every encoded entry consumes at least the numeric key, two presence bits,
  // action and protocol bit. This checkpoint-size-derived bound prevents an
  // untrusted count from requesting memory that the remaining byte stream
  // could never fill, without inventing a platform policy limit.
  if (!count(in, size, maximum_checkpoint_bytes / 8U) ||
      !in.integer(policy.default_action) ||
      policy.default_action > mld::ImportPolicyAction::next_policy)
    return false;
  try {
    policy.entries.resize(size);
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (auto &entry : policy.entries) {
    bool group_present{};
    bool source_present{};
    if (!in.integer(entry.number) || !in.integer(entry.term) ||
        !in.boolean(group_present))
      return false;
    if (group_present) {
      entry.group.emplace();
      if (!ipv6(in, entry.group->network) || !in.integer(entry.group->length))
        return false;
    } else {
      entry.group.reset();
    }
    if (!in.boolean(source_present))
      return false;
    if (source_present) {
      entry.source.emplace();
      if (!ipv6(in, entry.source->network) || !in.integer(entry.source->length))
        return false;
    } else {
      entry.source.reset();
    }
    if (!in.integer(entry.action) ||
        entry.action > mld::ImportPolicyAction::next_policy ||
        !in.boolean(entry.protocol_mld))
      return false;
  }
  // The policy compiler is the single semantic validator for canonical
  // prefixes, ordering and terminal action. Checkpoint decode delegates to it
  // instead of maintaining a subtly different acceptance grammar here.
  mld::ImportPolicyProgram validator;
  return validator.restore(policy);
}

void mld_policy_prefix_lists(
    Writer &out, const std::vector<MldPolicyPrefixListIntent> &lists) {
  count(out, lists);
  for (const auto &list : lists) {
    out.string(list.name);
    count(out, list.prefixes);
    for (const auto &prefix : list.prefixes) {
      ip_address(out, prefix.network);
      out.integer(prefix.length);
    }
  }
}

bool mld_policy_prefix_lists(
    Reader &in, std::vector<MldPolicyPrefixListIntent> &lists) noexcept {
  std::uint32_t size{};
  if (!count(in, size, maximum_checkpoint_bytes / 8U))
    return false;
  try {
    lists.resize(size);
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (auto &list : lists) {
    if (!in.string(list.name, mld::maximum_policy_name_octets) ||
        list.name.empty() || !count(in, size, maximum_checkpoint_bytes / 17U))
      return false;
    try {
      list.prefixes.resize(size);
    } catch (const std::bad_alloc &) {
      return false;
    }
    for (auto &prefix : list.prefixes)
      if (!ip_address(in, prefix.network) || !in.integer(prefix.length) ||
          prefix.length > ip::address_bits(prefix.network.family) ||
          ip::mask(prefix.network, prefix.length) != prefix.network)
        return false;
    std::sort(list.prefixes.begin(), list.prefixes.end(),
              [](const auto &left, const auto &right) {
                return left.length < right.length ||
                       (left.length == right.length &&
                        left.network < right.network);
              });
    if (std::adjacent_find(list.prefixes.begin(), list.prefixes.end()) !=
        list.prefixes.end())
      return false;
  }
  std::sort(lists.begin(), lists.end(),
            [](const auto &left, const auto &right) {
              return left.name < right.name;
            });
  return std::adjacent_find(lists.begin(), lists.end(),
                            [](const auto &left, const auto &right) {
                              return left.name == right.name;
                            }) == lists.end();
}

void named_mld_import_policies(
    Writer &out, const std::vector<MldNamedImportPolicyIntent> &policies) {
  count(out, policies);
  for (const auto &policy : policies) {
    out.string(policy.name);
    count(out, policy.entries);
    for (const auto &entry : policy.entries) {
      out.integer(entry.number);
      out.string(entry.group_prefix_list);
      out.boolean(entry.source_address.has_value());
      if (entry.source_address)
        ipv6(out, *entry.source_address);
      out.string(entry.source_prefix_list);
      out.integer(entry.action);
      out.boolean(entry.action_configured);
      out.boolean(entry.protocol_mld);
      out.string(entry.route_prefix_list);
      out.boolean(entry.route_source.has_value());
      if (entry.route_source)
        out.integer(*entry.route_source);
      out.boolean(entry.protocol_instance.has_value());
      if (entry.protocol_instance)
        out.integer(*entry.protocol_instance);
      out.boolean(entry.route_tag.has_value());
      if (entry.route_tag)
        out.integer(*entry.route_tag);
      out.boolean(entry.set_metric.has_value());
      if (entry.set_metric)
        out.integer(*entry.set_metric);
      out.boolean(entry.set_metric_type.has_value());
      if (entry.set_metric_type)
        out.integer(*entry.set_metric_type);
      out.boolean(entry.set_route_tag.has_value());
      if (entry.set_route_tag)
        out.integer(*entry.set_route_tag);
    }
    out.integer(policy.default_action);
    out.boolean(policy.default_action_configured);
  }
}

bool named_mld_import_policies(
    Reader &in, std::vector<MldNamedImportPolicyIntent> &policies) noexcept {
  std::uint32_t size{};
  if (!count(in, size, maximum_checkpoint_bytes / 10U))
    return false;
  try {
    policies.resize(size);
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (auto &policy : policies) {
    if (!in.string(policy.name, mld::maximum_policy_name_octets) ||
        policy.name.empty() || !count(in, size, maximum_checkpoint_bytes / 12U))
      return false;
    try {
      policy.entries.resize(size);
    } catch (const std::bad_alloc &) {
      return false;
    }
    for (auto &entry : policy.entries) {
      bool source_present{};
      bool route_source_present{};
      bool protocol_instance_present{};
      bool route_tag_present{};
      bool metric_present{};
      bool metric_type_present{};
      bool set_route_tag_present{};
      if (!in.integer(entry.number) || !entry.number ||
          !in.string(entry.group_prefix_list,
                     mld::maximum_policy_name_octets) ||
          !in.boolean(source_present))
        return false;
      if (source_present) {
        entry.source_address.emplace();
        if (!ipv6(in, *entry.source_address) ||
            ip::is_unspecified(*entry.source_address) ||
            ip::is_multicast(*entry.source_address))
          return false;
      } else {
        entry.source_address.reset();
      }
      if (!in.string(entry.source_prefix_list,
                     mld::maximum_policy_name_octets) ||
          (entry.source_address && !entry.source_prefix_list.empty()) ||
          !in.integer(entry.action) ||
          entry.action > mld::ImportPolicyAction::next_policy ||
          !in.boolean(entry.action_configured) ||
          (!entry.action_configured &&
           entry.action != mld::ImportPolicyAction::next_entry) ||
          !in.boolean(entry.protocol_mld) ||
          !in.string(entry.route_prefix_list,
                     mld::maximum_policy_name_octets) ||
          !in.boolean(route_source_present))
        return false;
      if (route_source_present) {
        entry.route_source.emplace();
        if (!in.integer(*entry.route_source) ||
            *entry.route_source > routing::RouteSource::ospf3)
          return false;
      } else {
        entry.route_source.reset();
      }
      if (!in.boolean(protocol_instance_present))
        return false;
      if (protocol_instance_present) {
        entry.protocol_instance.emplace();
        if (!in.integer(*entry.protocol_instance))
          return false;
      } else {
        entry.protocol_instance.reset();
      }
      if (!in.boolean(route_tag_present))
        return false;
      if (route_tag_present) {
        entry.route_tag.emplace();
        if (!in.integer(*entry.route_tag))
          return false;
      } else {
        entry.route_tag.reset();
      }
      if (!in.boolean(metric_present))
        return false;
      if (metric_present) {
        entry.set_metric.emplace();
        if (!in.integer(*entry.set_metric))
          return false;
      } else {
        entry.set_metric.reset();
      }
      if (!in.boolean(metric_type_present))
        return false;
      if (metric_type_present) {
        entry.set_metric_type.emplace();
        if (!in.integer(*entry.set_metric_type) ||
            (*entry.set_metric_type !=
                 routing::OspfPathType::external_type_1 &&
             *entry.set_metric_type !=
                 routing::OspfPathType::external_type_2))
          return false;
      } else {
        entry.set_metric_type.reset();
      }
      if (!in.boolean(set_route_tag_present))
        return false;
      if (set_route_tag_present) {
        entry.set_route_tag.emplace();
        if (!in.integer(*entry.set_route_tag))
          return false;
      } else {
        entry.set_route_tag.reset();
      }
    }
    std::sort(policy.entries.begin(), policy.entries.end(),
              [](const auto &left, const auto &right) {
                return left.number < right.number;
              });
    if (std::adjacent_find(policy.entries.begin(), policy.entries.end(),
                           [](const auto &left, const auto &right) {
                             return left.number == right.number;
                           }) != policy.entries.end() ||
        !in.integer(policy.default_action) ||
        policy.default_action > mld::ImportPolicyAction::next_policy ||
        !in.boolean(policy.default_action_configured) ||
        (!policy.default_action_configured &&
         policy.default_action != mld::ImportPolicyAction::accept))
      return false;
  }
  std::sort(policies.begin(), policies.end(),
            [](const auto &left, const auto &right) {
              return left.name < right.name;
            });
  // Policy names are datastore keys. Duplicate keys make reference resolution
  // ambiguous and therefore invalidate the entire detached checkpoint before
  // any router owner is replaced.
  return std::adjacent_find(policies.begin(), policies.end(),
                            [](const auto &left, const auto &right) {
                              return left.name == right.name;
                            }) == policies.end();
}

// Control checkpoint encoding precedes the forwarding checkpoint helpers in
// this translation unit. Forward declarations keep one canonical relay wire
// representation for both owners instead of duplicating a subtly different
// variable-length codec.
void dhcpv4_relay_configuration(
    Writer &out, const dhcpv4::RelayInterfaceConfiguration &value);
bool dhcpv4_relay_configuration(
    Reader &in, dhcpv4::RelayInterfaceConfiguration &value);
void dhcpv6_relay_configuration(Writer &out,
                                const dhcpv6::RelayInterfaceConfig &value);
bool dhcpv6_relay_configuration(Reader &in,
                                dhcpv6::RelayInterfaceConfig &value);
void sap_attachment(Writer &out, const service::SapAttachment &value);
bool sap_attachment(Reader &in, service::SapAttachment &value) noexcept;
void service_ipv6_interface(Writer &out,
                            const service::ServiceIpv6Interface &value);
bool service_ipv6_interface(Reader &in,
                            service::ServiceIpv6Interface &value) noexcept;

void ies_configuration(Writer &out, const service::Configuration &value) {
  out.string(value.access_node_identifier);
  count(out, value.ports);
  for (const auto &port : value.ports) {
    out.integer(port.coordinate.ordinal);
    out.integer(port.coordinate.card);
    out.integer(port.coordinate.mda);
    out.integer(port.coordinate.port);
    out.integer(port.mode);
    out.integer(port.encapsulation);
    out.integer(port.outer_tpid);
  }
  count(out, value.customers);
  for (const auto &customer : value.customers) {
    out.string(customer.name);
    out.integer(customer.customer_id);
    out.string(customer.description);
  }
  count(out, value.ies_services);
  for (const auto &ies : value.ies_services) {
    out.integer(ies.service_id);
    out.integer(ies.customer_id);
    out.string(ies.name);
    out.string(ies.description);
    out.boolean(ies.admin_enabled);
    count(out, ies.interfaces);
    for (const auto &interface : ies.interfaces) {
      out.integer(interface.logical_id);
      out.string(interface.name);
      out.string(interface.description);
      // Reuse the SAP codec through a temporary attachment so physical and
      // VLAN identity cannot acquire a second checkpoint representation.
      sap_attachment(out, {.logical_interface_id = interface.logical_id,
                           .sap = interface.sap});
      mac(out, interface.mac);
      ipv6(out, interface.address);
      ipv6(out, interface.link_local);
      out.integer(interface.prefix_length);
      out.integer(interface.ip_mtu);
      out.boolean(interface.address_configured);
      out.boolean(interface.admin_enabled);
      const auto &relay = interface.dhcpv6_relay;
      out.boolean(relay.configured);
      out.boolean(relay.admin_enabled);
      out.boolean(relay.neighbor_resolution);
      out.boolean(relay.link_address.has_value());
      if (relay.link_address)
        ipv6(out, *relay.link_address);
      out.boolean(relay.source_address.has_value());
      if (relay.source_address)
        ipv6(out, *relay.source_address);
      count(out, relay.servers);
      for (const auto &server : relay.servers) {
        ipv6(out, server.address);
        out.integer(server.scope_interface_id);
      }
      out.integer(relay.interface_id_kind);
      out.string(relay.interface_id_string);
      out.integer(relay.lease_population_limit);
      out.boolean(relay.route_populate_na);
      out.boolean(relay.route_populate_pd);
      out.boolean(relay.route_populate_ta);
      out.boolean(relay.route_populate_pd_exclude);
    }
  }
}

bool ies_configuration(Reader &in, service::Configuration &value,
                       bool allow_incomplete = false) noexcept {
  try {
    std::uint32_t size{};
    if (!in.string(value.access_node_identifier,
                   service::maximum_service_name_octets) ||
        !count(in, size, device_catalog::maximum_ports_per_router))
      return false;
    value.ports.resize(size);
    for (auto &port : value.ports)
      if (!in.integer(port.coordinate.ordinal) ||
          !in.integer(port.coordinate.card) ||
          !in.integer(port.coordinate.mda) ||
          !in.integer(port.coordinate.port) || !in.integer(port.mode) ||
          port.mode > service::EthernetPortMode::hybrid ||
          !in.integer(port.encapsulation) ||
          port.encapsulation > service::EthernetEncapsulation::qinq ||
          !in.integer(port.outer_tpid))
        return false;
    if (!count(in, size, maximum_checkpoint_bytes / 8U))
      return false;
    value.customers.resize(size);
    for (auto &customer : value.customers)
      if (!in.string(customer.name, service::maximum_service_name_octets) ||
          !in.integer(customer.customer_id) ||
          !in.string(customer.description, service::maximum_description_octets))
        return false;
    if (!count(in, size, maximum_checkpoint_bytes / 16U))
      return false;
    value.ies_services.resize(size);
    for (auto &ies : value.ies_services) {
      std::uint32_t interface_count{};
      if (!in.integer(ies.service_id) || !in.integer(ies.customer_id) ||
          !in.string(ies.name, service::maximum_service_name_octets) ||
          !in.string(ies.description, service::maximum_description_octets) ||
          !in.boolean(ies.admin_enabled) ||
          !count(in, interface_count, maximum_checkpoint_bytes / 64U))
        return false;
      ies.interfaces.resize(interface_count);
      for (auto &interface : ies.interfaces) {
        service::SapAttachment encoded_sap{};
        bool link_present{};
        bool source_present{};
        std::uint32_t server_count{};
        if (!in.integer(interface.logical_id) ||
            !in.string(interface.name,
                       service::maximum_interface_name_octets) ||
            !in.string(interface.description,
                       service::maximum_description_octets) ||
            !sap_attachment(in, encoded_sap) ||
            encoded_sap.logical_interface_id != interface.logical_id ||
            !mac(in, interface.mac) || !ipv6(in, interface.address) ||
            !ipv6(in, interface.link_local) ||
            !in.integer(interface.prefix_length) ||
            !in.integer(interface.ip_mtu) ||
            !in.boolean(interface.address_configured) ||
            !in.boolean(interface.admin_enabled) ||
            !in.boolean(interface.dhcpv6_relay.configured) ||
            !in.boolean(interface.dhcpv6_relay.admin_enabled) ||
            !in.boolean(interface.dhcpv6_relay.neighbor_resolution) ||
            !in.boolean(link_present))
          return false;
        interface.sap = encoded_sap.sap;
        if (link_present) {
          packet::Ipv6 link{};
          if (!ipv6(in, link))
            return false;
          interface.dhcpv6_relay.link_address = link;
        } else {
          interface.dhcpv6_relay.link_address.reset();
        }
        if (!in.boolean(source_present))
          return false;
        if (source_present) {
          packet::Ipv6 source{};
          if (!ipv6(in, source))
            return false;
          interface.dhcpv6_relay.source_address = source;
        } else {
          interface.dhcpv6_relay.source_address.reset();
        }
        if (!count(in, server_count,
                   device_catalog::dhcpv6_relay_servers_per_interface))
          return false;
        interface.dhcpv6_relay.servers.resize(server_count);
        for (auto &server : interface.dhcpv6_relay.servers)
          if (!ipv6(in, server.address) ||
              !in.integer(server.scope_interface_id))
            return false;
        auto &relay = interface.dhcpv6_relay;
        if (!in.integer(relay.interface_id_kind) ||
            relay.interface_id_kind > service::RelayInterfaceIdKind::string ||
            !in.string(relay.interface_id_string,
                       service::maximum_relay_interface_id_octets) ||
            !in.integer(relay.lease_population_limit) ||
            !in.boolean(relay.route_populate_na) ||
            !in.boolean(relay.route_populate_pd) ||
            !in.boolean(relay.route_populate_ta) ||
            !in.boolean(relay.route_populate_pd_exclude))
          return false;
      }
    }
    return (allow_incomplete
                ? service::validate_candidate(value)
                : service::validate(value)) == service::ValidationError::none;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void control_state(Writer &out, const RouterControlCheckpoint &state) {
  handle(out, state.device);
  // ECMP width is control-owned policy. Persist it before route inputs so the
  // restored RIB uses the same path cap as the live router.
  out.integer(state.maximum_ecmp_paths);
  for (const auto &value : state.connected)
    connected(out, value);
  for (const auto &value : state.statics)
    static_route(out, value);
  for (const auto &value : state.ipv6_connected)
    ipv6_connected(out, value);
  count(out, state.native_ipv6_addresses);
  for (const auto &address : state.native_ipv6_addresses) {
    ipv6(out, address.address);
    ipv6(out, address.network);
    out.integer(address.interface_id);
    out.integer(address.primary_preference);
    out.integer(address.tag);
    out.integer(address.port_ordinal);
    out.integer(address.prefix_length);
    out.boolean(address.duplicate_address_detection);
    out.boolean(address.tag_configured);
  }
  count(out, state.native_ipv6_connected);
  for (const auto &value : state.native_ipv6_connected)
    ipv6_connected(out, value);
  for (const auto &value : state.ipv6_statics)
    ipv6_static_route(out, value);
  for (const auto &value : state.ports)
    forward_port(out, value);
  for (const auto value : state.interface_admin)
    out.boolean(value);
  // This bit is not derivable from ForwardPort alone because a physical port
  // may simultaneously carry native IP and one or more SAPs. Persisting the
  // owner explicitly lets removal of either tree preserve the other after a
  // restore.
  for (const auto value : state.ies_port_owned)
    out.boolean(value);
  for (const auto &advertisement : state.router_advertisements) {
    router_advertisement_config(out, advertisement.config);
    out.boolean(advertisement.configured);
    out.boolean(advertisement.enabled);
  }
  for (const auto &mld : state.mld_interfaces) {
    mld_router_configuration(out, mld.configuration);
    mld_ssm_translations(out, mld.ssm_translations);
    mld_import_policy(out, mld.import_policy);
    out.boolean(mld.configured);
  }
  count(out, state.dhcpv4_relays);
  for (const auto &relay : state.dhcpv4_relays)
    dhcpv4_relay_configuration(out, relay);
  count(out, state.dhcpv6_relays);
  for (const auto &relay : state.dhcpv6_relays)
    dhcpv6_relay_configuration(out, relay);
  ies_configuration(out, state.ies_configuration);
  count(out, state.ies_sap_attachments);
  for (const auto &attachment : state.ies_sap_attachments)
    sap_attachment(out, attachment);
  count(out, state.ies_ipv6_interfaces);
  for (const auto &interface : state.ies_ipv6_interfaces)
    service_ipv6_interface(out, interface);
  count(out, state.ies_ipv6_connected);
  for (const auto &connected : state.ies_ipv6_connected)
    ipv6_connected(out, connected);
  count(out, state.ies_dhcpv6_relays);
  for (const auto &relay : state.ies_dhcpv6_relays)
    dhcpv6_relay_configuration(out, relay);
  fib(out, state.selected_rib);
  out.integer(state.fib_generation);
  ipv6_fib(out, state.selected_ipv6_rib);
  out.integer(state.ipv6_fib_generation);
}

bool control_state(Reader &in, RouterControlCheckpoint &state) noexcept {
  if (!handle(in, state.device) ||
      !in.integer(state.maximum_ecmp_paths) ||
      state.maximum_ecmp_paths == 0U ||
      state.maximum_ecmp_paths > device_catalog::maximum_ecmp_paths)
    return false;
  for (auto &value : state.connected)
    if (!connected(in, value))
      return false;
  for (auto &value : state.statics)
    if (!static_route(in, value))
      return false;
  for (auto &value : state.ipv6_connected)
    if (!ipv6_connected(in, value))
      return false;
  std::uint32_t native_size{};
  if (!count(in, native_size, RouterIpv6AddressTable::capacity))
    return false;
  state.native_ipv6_addresses.resize(native_size);
  for (auto &address : state.native_ipv6_addresses)
    if (!ipv6(in, address.address) || !ipv6(in, address.network) ||
        !in.integer(address.interface_id) ||
        !in.integer(address.primary_preference) || !in.integer(address.tag) ||
        !in.integer(address.port_ordinal) ||
        !in.integer(address.prefix_length) ||
        !in.boolean(address.duplicate_address_detection) ||
        !in.boolean(address.tag_configured))
      return false;
  if (!count(in, native_size, RouterIpv6AddressTable::capacity))
    return false;
  state.native_ipv6_connected.resize(native_size);
  for (auto &value : state.native_ipv6_connected)
    if (!ipv6_connected(in, value))
      return false;
  for (auto &value : state.ipv6_statics)
    if (!ipv6_static_route(in, value))
      return false;
  for (auto &value : state.ports)
    if (!forward_port(in, value))
      return false;
  for (auto &value : state.interface_admin)
    if (!in.boolean(value))
      return false;
  for (auto &value : state.ies_port_owned)
    if (!in.boolean(value))
      return false;
  for (auto &advertisement : state.router_advertisements)
    if (!router_advertisement_config(in, advertisement.config) ||
        !in.boolean(advertisement.configured) ||
        !in.boolean(advertisement.enabled))
      return false;
  for (auto &mld : state.mld_interfaces)
    if (!mld_router_configuration(in, mld.configuration) ||
        !mld_ssm_translations(in, mld.ssm_translations) ||
        !mld_import_policy(in, mld.import_policy) ||
        !in.boolean(mld.configured))
      return false;
  std::uint32_t relay_count{};
  if (!count(in, relay_count, device_catalog::maximum_ports_per_router))
    return false;
  state.dhcpv4_relays.resize(relay_count);
  for (auto &relay : state.dhcpv4_relays)
    if (!dhcpv4_relay_configuration(in, relay))
      return false;
  if (!count(in, relay_count, device_catalog::maximum_ports_per_router))
    return false;
  state.dhcpv6_relays.resize(relay_count);
  for (auto &relay : state.dhcpv6_relays)
    if (!dhcpv6_relay_configuration(in, relay))
      return false;
  std::uint32_t size{};
  if (!ies_configuration(in, state.ies_configuration) ||
      !count(in, size, maximum_checkpoint_bytes / 23U))
    return false;
  state.ies_sap_attachments.resize(size);
  for (auto &attachment : state.ies_sap_attachments)
    if (!sap_attachment(in, attachment))
      return false;
  if (!count(in, size, maximum_checkpoint_bytes / 80U))
    return false;
  state.ies_ipv6_interfaces.resize(size);
  for (auto &interface : state.ies_ipv6_interfaces)
    if (!service_ipv6_interface(in, interface))
      return false;
  if (!count(in, size, device_catalog::maximum_fib_routes_per_router))
    return false;
  state.ies_ipv6_connected.resize(size);
  for (auto &connected : state.ies_ipv6_connected)
    if (!ipv6_connected(in, connected))
      return false;
  if (!count(in, size, maximum_checkpoint_bytes / 64U))
    return false;
  state.ies_dhcpv6_relays.resize(size);
  for (auto &relay : state.ies_dhcpv6_relays)
    if (!dhcpv6_relay_configuration(in, relay))
      return false;
  return fib(in, state.selected_rib) && in.integer(state.fib_generation) &&
         ipv6_fib(in, state.selected_ipv6_rib) &&
         in.integer(state.ipv6_fib_generation);
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
    if (!handle(in, router.device) || !in.integer(router.running_generation) ||
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

void router_advertisement_config(
    Writer &out, const packet::nd::RouterAdvertisementConfig &config) {
  // Only active option records are serialized. Array tail bytes are capacity,
  // not protocol state, and including them would bloat every checkpoint.
  out.integer(config.prefix_count);
  for (std::size_t index = 0; index < config.prefix_count; ++index) {
    const auto &prefix = config.prefixes[index];
    ipv6(out, prefix.prefix.network);
    out.integer(prefix.prefix.length);
    out.integer(prefix.valid_lifetime_seconds);
    out.integer(prefix.preferred_lifetime_seconds);
    out.boolean(prefix.on_link);
    out.boolean(prefix.autonomous);
  }
  rdnss_information(out, config.rdnss);
  out.integer(config.rdnss_lifetime_seconds);
  out.integer(config.reachable_time_milliseconds);
  out.integer(config.retrans_timer_milliseconds);
  out.integer(config.max_advertisement_interval_seconds);
  out.integer(config.min_advertisement_interval_seconds);
  out.integer(config.router_lifetime_seconds);
  out.integer(config.advertised_mtu);
  out.integer(config.current_hop_limit);
  out.integer(config.preference);
  out.boolean(config.managed_configuration);
  out.boolean(config.other_configuration);
  out.boolean(config.include_source_link_layer);
}

bool router_advertisement_config(
    Reader &in, packet::nd::RouterAdvertisementConfig &config) noexcept {
  if (!in.integer(config.prefix_count) ||
      config.prefix_count > config.prefixes.size())
    return false;
  for (std::size_t index = 0; index < config.prefix_count; ++index) {
    auto &prefix = config.prefixes[index];
    if (!ipv6(in, prefix.prefix.network) || !in.integer(prefix.prefix.length) ||
        !in.integer(prefix.valid_lifetime_seconds) ||
        !in.integer(prefix.preferred_lifetime_seconds) ||
        !in.boolean(prefix.on_link) || !in.boolean(prefix.autonomous))
      return false;
  }
  return rdnss_information(in, config.rdnss) &&
         in.integer(config.rdnss_lifetime_seconds) &&
         in.integer(config.reachable_time_milliseconds) &&
         in.integer(config.retrans_timer_milliseconds) &&
         in.integer(config.max_advertisement_interval_seconds) &&
         in.integer(config.min_advertisement_interval_seconds) &&
         in.integer(config.router_lifetime_seconds) &&
         in.integer(config.advertised_mtu) &&
         in.integer(config.current_hop_limit) &&
         in.integer(config.preference) &&
         config.preference <= packet::nd::RouterPreference::high &&
         in.boolean(config.managed_configuration) &&
         in.boolean(config.other_configuration) &&
         in.boolean(config.include_source_link_layer);
}

void mld_router_configuration(Writer &out,
                              const MldRouterConfiguration &value) {
  ipv6(out, value.link_local_address);
  out.integer(value.query_interval.count());
  out.integer(value.query_response_interval.count());
  out.integer(value.last_listener_query_interval.count());
  out.integer(value.port_ordinal);
  out.integer(value.robustness_variable);
  out.integer(value.version);
  out.integer(value.maximum_number_groups);
  out.integer(value.maximum_number_group_sources);
  out.integer(value.maximum_number_sources);
  out.boolean(value.router_alert_check);
  out.boolean(value.enabled);
}

bool mld_router_configuration(Reader &in,
                              MldRouterConfiguration &value) noexcept {
  std::int64_t query_interval{};
  std::int64_t response_interval{};
  std::int64_t last_listener_interval{};
  if (!ipv6(in, value.link_local_address) || !in.integer(query_interval) ||
      !in.integer(response_interval) || !in.integer(last_listener_interval) ||
      !in.integer(value.port_ordinal) ||
      !in.integer(value.robustness_variable) || !in.integer(value.version) ||
      !in.integer(value.maximum_number_groups) ||
      !in.integer(value.maximum_number_group_sources) ||
      !in.integer(value.maximum_number_sources) ||
      !in.boolean(value.router_alert_check) || !in.boolean(value.enabled))
    return false;
  value.query_interval = std::chrono::seconds{query_interval};
  value.query_response_interval = std::chrono::milliseconds{response_interval};
  value.last_listener_query_interval =
      std::chrono::milliseconds{last_listener_interval};
  return true;
}

void mld_router_checkpoint(Writer &out, const MldRouterCheckpoint &value) {
  mld_router_configuration(out, value.configuration);
  count(out, value.groups);
  for (const auto &group : value.groups) {
    ipv6(out, group.multicast_address);
    count(out, group.sources);
    for (const auto &source : group.sources) {
      ipv6(out, source.address);
      out.integer(source.remaining_nanoseconds);
      out.boolean(source.timer_running);
    }
    for (const auto &query : group.pending_queries) {
      count(out, query.sources);
      for (const auto &source : query.sources)
        ipv6(out, source);
      out.integer(query.remaining_nanoseconds);
      out.integer(query.transmissions_remaining);
      out.boolean(query.multicast_address_query);
    }
    out.integer(group.filter_remaining_nanoseconds);
    out.integer(group.older_host_remaining_nanoseconds);
    out.integer(group.mode);
    out.boolean(group.filter_timer_running);
    out.boolean(group.older_host_present);
  }
  count(out, value.static_groups);
  for (const auto &group : value.static_groups) {
    ipv6(out, group.multicast_address);
    count(out, group.sources);
    for (const auto &source : group.sources)
      ipv6(out, source);
    out.boolean(group.starg);
  }
  ipv6(out, value.querier_address);
  const auto &statistics = value.statistics;
  out.integer(statistics.queries_received);
  out.integer(statistics.queries_transmitted);
  out.integer(statistics.reports_v1_received);
  out.integer(statistics.reports_v1_transmitted);
  out.integer(statistics.reports_v2_received);
  out.integer(statistics.reports_v2_transmitted);
  out.integer(statistics.dones_received);
  out.integer(statistics.dones_transmitted);
  out.integer(statistics.bad_length);
  out.integer(statistics.bad_checksum);
  out.integer(statistics.unknown_type);
  out.integer(statistics.bad_receive_interface);
  out.integer(statistics.receive_non_local);
  out.integer(statistics.receive_wrong_version);
  out.integer(statistics.policy_drops);
  out.integer(statistics.no_router_alert);
  out.integer(statistics.receive_bad_encodings);
  out.integer(statistics.receive_packet_drops);
  out.integer(statistics.local_scope_packets);
  out.integer(statistics.reserved_scope_packets);
  out.integer(statistics.mcac_policy_drops);
  out.integer(value.general_query_remaining_nanoseconds);
  out.integer(value.other_querier_remaining_nanoseconds);
  out.integer(value.older_querier_remaining_nanoseconds);
  out.integer(value.startup_queries_remaining);
  out.boolean(value.querier);
  out.boolean(value.other_querier_timer_running);
  out.boolean(value.older_querier_present);
}

bool mld_router_checkpoint(Reader &in, MldRouterCheckpoint &value) noexcept {
  std::uint32_t size{};
  if (!mld_router_configuration(in, value.configuration) ||
      !count(in, size, device_catalog::mld_router_groups_per_interface))
    return false;
  value.groups.resize(size);
  for (auto &group : value.groups) {
    if (!ipv6(in, group.multicast_address) ||
        !count(in, size, device_catalog::mld_router_sources_per_group))
      return false;
    group.sources.resize(size);
    for (auto &source : group.sources)
      if (!ipv6(in, source.address) ||
          !in.integer(source.remaining_nanoseconds) ||
          !in.boolean(source.timer_running))
        return false;
    for (auto &query : group.pending_queries) {
      if (!count(in, size, device_catalog::mld_sources_per_group))
        return false;
      query.sources.resize(size);
      for (auto &source : query.sources)
        if (!ipv6(in, source))
          return false;
      if (!in.integer(query.remaining_nanoseconds) ||
          !in.integer(query.transmissions_remaining) ||
          !in.boolean(query.multicast_address_query))
        return false;
    }
    if (!in.integer(group.filter_remaining_nanoseconds) ||
        !in.integer(group.older_host_remaining_nanoseconds) ||
        !in.integer(group.mode) || group.mode > MldFilterMode::exclude ||
        !in.boolean(group.filter_timer_running) ||
        !in.boolean(group.older_host_present))
      return false;
  }
  if (!count(in, size, device_catalog::mld_router_groups_per_interface))
    return false;
  value.static_groups.resize(size);
  for (auto &group : value.static_groups) {
    if (!ipv6(in, group.multicast_address) ||
        !count(in, size, device_catalog::mld_router_sources_per_group))
      return false;
    group.sources.resize(size);
    for (auto &source : group.sources)
      if (!ipv6(in, source))
        return false;
    if (!in.boolean(group.starg))
      return false;
  }
  auto &statistics = value.statistics;
  return ipv6(in, value.querier_address) &&
         in.integer(statistics.queries_received) &&
         in.integer(statistics.queries_transmitted) &&
         in.integer(statistics.reports_v1_received) &&
         in.integer(statistics.reports_v1_transmitted) &&
         in.integer(statistics.reports_v2_received) &&
         in.integer(statistics.reports_v2_transmitted) &&
         in.integer(statistics.dones_received) &&
         in.integer(statistics.dones_transmitted) &&
         in.integer(statistics.bad_length) &&
         in.integer(statistics.bad_checksum) &&
         in.integer(statistics.unknown_type) &&
         in.integer(statistics.bad_receive_interface) &&
         in.integer(statistics.receive_non_local) &&
         in.integer(statistics.receive_wrong_version) &&
         in.integer(statistics.policy_drops) &&
         in.integer(statistics.no_router_alert) &&
         in.integer(statistics.receive_bad_encodings) &&
         in.integer(statistics.receive_packet_drops) &&
         in.integer(statistics.local_scope_packets) &&
         in.integer(statistics.reserved_scope_packets) &&
         in.integer(statistics.mcac_policy_drops) &&
         in.integer(value.general_query_remaining_nanoseconds) &&
         in.integer(value.other_querier_remaining_nanoseconds) &&
         in.integer(value.older_querier_remaining_nanoseconds) &&
         in.integer(value.startup_queries_remaining) &&
         in.boolean(value.querier) &&
         in.boolean(value.other_querier_timer_running) &&
         in.boolean(value.older_querier_present);
}

void icmpv4_direction(Writer &out, const Icmpv4DirectionStatistics &value) {
  // Field order follows the sourced SR OS Received and Sent presentation and
  // is protected by checkpoint ABI 6. Both directions use the exact layout.
  out.integer(value.total);
  out.integer(value.errors);
  out.integer(value.destination_unreachable);
  out.integer(value.redirects);
  out.integer(value.echo_request);
  out.integer(value.echo_reply);
  out.integer(value.time_exceeded);
  out.integer(value.source_quench);
  out.integer(value.timestamp_request);
  out.integer(value.timestamp_reply);
  out.integer(value.address_mask_request);
  out.integer(value.address_mask_reply);
  out.integer(value.parameter_problem);
}

bool icmpv4_direction(Reader &in, Icmpv4DirectionStatistics &value) noexcept {
  return in.integer(value.total) && in.integer(value.errors) &&
         in.integer(value.destination_unreachable) &&
         in.integer(value.redirects) && in.integer(value.echo_request) &&
         in.integer(value.echo_reply) && in.integer(value.time_exceeded) &&
         in.integer(value.source_quench) &&
         in.integer(value.timestamp_request) &&
         in.integer(value.timestamp_reply) &&
         in.integer(value.address_mask_request) &&
         in.integer(value.address_mask_reply) &&
         in.integer(value.parameter_problem);
}

void icmpv4_statistics(Writer &out, const Icmpv4Statistics &value) {
  icmpv4_direction(out, value.received);
  icmpv4_direction(out, value.sent);
}

bool icmpv4_statistics(Reader &in, Icmpv4Statistics &value) noexcept {
  return icmpv4_direction(in, value.received) &&
         icmpv4_direction(in, value.sent);
}

void icmpv6_direction(Writer &out, const Icmpv6DirectionStatistics &value) {
  // Keep the wire order aligned with Nokia's operational display. The schema
  // version protects readers from interpreting an older, shorter sequence.
  out.integer(value.total);
  out.integer(value.errors);
  out.integer(value.destination_unreachable);
  out.integer(value.redirects);
  out.integer(value.time_exceeded);
  out.integer(value.packet_too_big);
  out.integer(value.echo_request);
  out.integer(value.echo_reply);
  out.integer(value.router_solicitation);
  out.integer(value.router_advertisement);
  out.integer(value.neighbor_solicitation);
  out.integer(value.neighbor_advertisement);
  out.integer(value.parameter_problem);
  out.integer(value.discarded);
}

bool icmpv6_direction(Reader &in, Icmpv6DirectionStatistics &value) noexcept {
  return in.integer(value.total) && in.integer(value.errors) &&
         in.integer(value.destination_unreachable) &&
         in.integer(value.redirects) && in.integer(value.time_exceeded) &&
         in.integer(value.packet_too_big) && in.integer(value.echo_request) &&
         in.integer(value.echo_reply) &&
         in.integer(value.router_solicitation) &&
         in.integer(value.router_advertisement) &&
         in.integer(value.neighbor_solicitation) &&
         in.integer(value.neighbor_advertisement) &&
         in.integer(value.parameter_problem) && in.integer(value.discarded);
}

void icmpv6_statistics(Writer &out, const Icmpv6Statistics &value) {
  icmpv6_direction(out, value.received);
  icmpv6_direction(out, value.sent);
}

bool icmpv6_statistics(Reader &in, Icmpv6Statistics &value) noexcept {
  return icmpv6_direction(in, value.received) &&
         icmpv6_direction(in, value.sent);
}

// UDP serialization is shared with host checkpoints below. Forward
// declarations let router state reuse the exact same wire representation
// without a second transport codec that could drift on socket generations.
void udp_endpoint(Writer &out, const transport::UdpEndpointCheckpoint &value);
bool udp_endpoint(Reader &in, transport::UdpEndpointCheckpoint &value);
void ike_udp_service(Writer &out, const ikev2::UdpServiceCheckpoint &value);
bool ike_udp_service(Reader &in, ikev2::UdpServiceCheckpoint &value) noexcept;

void dhcpv4_relay_policy(Writer &out,
                         const dhcpv4::RelayConfiguration &value) {
  out.boolean(value.admin_enabled);
  out.string(value.description);
  ipv4(out, value.gateway_address);
  out.boolean(value.gateway_address_configured);
  out.integer(value.existing_information);
  out.integer(value.source_address);
  out.integer(value.maximum_hops);
  out.boolean(value.trusted_ingress);
  out.boolean(value.relay_plain_bootp);
  out.boolean(value.release_include_gateway_address);
  out.integer(value.circuit_id_source);
  out.integer(value.remote_id_source);
  out.string(value.remote_id_ascii);
  count(out, value.servers);
  for (const auto &server : value.servers)
    ipv4(out, server.address);
  count(out, value.circuit_id);
  out.octets(value.circuit_id);
  count(out, value.remote_id);
  out.octets(value.remote_id);
}

bool dhcpv4_relay_policy(Reader &in, dhcpv4::RelayConfiguration &value) {
  std::uint32_t size{};
  if (!in.boolean(value.admin_enabled) ||
      !in.string(value.description, 80U) ||
      !ipv4(in, value.gateway_address) ||
      !in.boolean(value.gateway_address_configured) ||
      !in.integer(value.existing_information) ||
      value.existing_information >
          dhcpv4::ExistingRelayInformationAction::drop ||
      !in.integer(value.source_address) ||
      value.source_address > dhcpv4::RelaySourceAddress::gi_address ||
      !in.integer(value.maximum_hops) ||
      !in.boolean(value.trusted_ingress) ||
      !in.boolean(value.relay_plain_bootp) ||
      !in.boolean(value.release_include_gateway_address) ||
      !in.integer(value.circuit_id_source) ||
      value.circuit_id_source > dhcpv4::CircuitIdSource::vlan_ascii_tuple ||
      !in.integer(value.remote_id_source) ||
      value.remote_id_source > dhcpv4::RemoteIdSource::client_mac ||
      !in.string(value.remote_id_ascii, 32U) ||
      !count(in, size,
             device_catalog::dhcpv4_relay_servers_per_interface))
    return false;
  value.servers.resize(size);
  for (auto &server : value.servers)
    if (!ipv4(in, server.address))
      return false;
  if (!count(in, size, 255U))
    return false;
  value.circuit_id.resize(size);
  if (!in.octets(value.circuit_id) || !count(in, size, 255U))
    return false;
  value.remote_id.resize(size);
  return in.octets(value.remote_id);
}

void dhcpv4_relay_configuration(
    Writer &out, const dhcpv4::RelayInterfaceConfiguration &value) {
  out.integer(value.interface_id);
  out.integer(value.physical_port_ordinal);
  dhcpv4_relay_policy(out, value.relay);
}

bool dhcpv4_relay_configuration(
    Reader &in, dhcpv4::RelayInterfaceConfiguration &value) {
  return in.integer(value.interface_id) &&
         in.integer(value.physical_port_ordinal) &&
         value.physical_port_ordinal <
             device_catalog::maximum_ports_per_router &&
         dhcpv4_relay_policy(in, value.relay);
}

void dhcpv6_relay_configuration(Writer &out,
                                const dhcpv6::RelayInterfaceConfig &value) {
  out.integer(value.interface_id);
  out.integer(value.physical_port_ordinal);
  ipv6(out, value.link_address);
  ipv6(out, value.source_address);
  out.boolean(value.has_source_address);
  ipv6(out, value.client_prefix.network);
  out.integer(value.client_prefix.length);
  out.integer(value.lease_population_limit);
  out.boolean(value.neighbor_resolution);
  out.boolean(value.route_non_temporary);
  out.boolean(value.route_temporary);
  out.boolean(value.route_delegated_prefix);
  out.boolean(value.route_prefix_exclude);
  count(out, value.relay_interface_id);
  out.octets(value.relay_interface_id);
  out.integer(value.server_count);
  for (std::size_t index = 0; index < value.server_count; ++index) {
    ipv6(out, value.servers[index].address);
    out.integer(value.servers[index].scope_interface_id);
  }
  out.integer(value.upstream_policy);
}

bool dhcpv6_relay_configuration(Reader &in,
                                dhcpv6::RelayInterfaceConfig &value) {
  std::uint32_t size{};
  if (!in.integer(value.interface_id) ||
      !in.integer(value.physical_port_ordinal) ||
      value.physical_port_ordinal >= device_catalog::maximum_ports_per_router ||
      !ipv6(in, value.link_address) || !ipv6(in, value.source_address) ||
      !in.boolean(value.has_source_address) ||
      !ipv6(in, value.client_prefix.network) ||
      !in.integer(value.client_prefix.length) ||
      value.client_prefix.length > ip::ipv6_address_bits ||
      !in.integer(value.lease_population_limit) ||
      !in.boolean(value.neighbor_resolution) ||
      !in.boolean(value.route_non_temporary) ||
      !in.boolean(value.route_temporary) ||
      !in.boolean(value.route_delegated_prefix) ||
      !in.boolean(value.route_prefix_exclude) ||
      !count(in, size, std::numeric_limits<std::uint16_t>::max()))
    return false;
  value.relay_interface_id.resize(size);
  if (!in.octets(value.relay_interface_id) || !in.integer(value.server_count) ||
      value.server_count > value.servers.size())
    return false;
  for (std::size_t index = 0; index < value.server_count; ++index)
    if (!ipv6(in, value.servers[index].address) ||
        !in.integer(value.servers[index].scope_interface_id))
      return false;
  return in.integer(value.upstream_policy) &&
         value.upstream_policy <=
             dhcpv6::RelayUpstreamPolicy::explicit_servers_required;
}

void dhcpv6_relay_lease(Writer &out,
                        const dhcpv6::RelayLeaseCheckpoint &value) {
  // DUID remains opaque and length-delimited. Persisting only the meaningful
  // prefix of the fixed storage prevents uninitialized tail bytes from
  // becoming part of the checkpoint format or client identity.
  out.integer(value.client.duid_octets);
  out.octets(std::span<const std::uint8_t>{value.client.duid}.first(
      value.client.duid_octets));
  out.octets(value.client.link_identity);
  out.integer(value.client.iaid);
  out.integer(value.client.kind);
  // Server Identifier is the opaque RFC 9915 DUID selected by the server.
  // Keeping it with the lease is required to construct a protocol-valid
  // Release after an operator clears lease state.
  out.integer(value.server.duid_octets);
  out.octets(std::span<const std::uint8_t>{value.server.duid}.first(
      value.server.duid_octets));
  ipv6(out, value.value);
  ipv6(out, value.peer_address);
  ipv6(out, value.server_address);
  mac(out, value.client_mac);
  ipv6(out, value.excluded_prefix);
  out.integer(value.interface_id);
  out.integer(value.server_scope_interface_id);
  out.integer(value.preferred_remaining_nanoseconds);
  out.integer(value.valid_remaining_nanoseconds);
  out.integer(value.physical_port_ordinal);
  out.integer(value.prefix_length);
  out.integer(value.excluded_prefix_length);
  out.integer(value.protocol);
  out.boolean(value.has_client_mac);
  out.boolean(value.has_excluded_prefix);
}

bool dhcpv6_relay_lease(Reader &in,
                        dhcpv6::RelayLeaseCheckpoint &value) noexcept {
  return in.integer(value.client.duid_octets) &&
         value.client.duid_octets <= value.client.duid.size() &&
         in.octets(std::span<std::uint8_t>{value.client.duid}.first(
             value.client.duid_octets)) &&
         in.octets(value.client.link_identity) &&
         in.integer(value.client.iaid) && in.integer(value.client.kind) &&
         value.client.kind <= dhcpv6::LeaseKind::prefix &&
         in.integer(value.server.duid_octets) &&
         value.server.duid_octets <= value.server.duid.size() &&
         in.octets(std::span<std::uint8_t>{value.server.duid}.first(
             value.server.duid_octets)) &&
         ipv6(in, value.value) && ipv6(in, value.peer_address) &&
         ipv6(in, value.server_address) && mac(in, value.client_mac) &&
         ipv6(in, value.excluded_prefix) && in.integer(value.interface_id) &&
         in.integer(value.server_scope_interface_id) &&
         in.integer(value.preferred_remaining_nanoseconds) &&
         in.integer(value.valid_remaining_nanoseconds) &&
         in.integer(value.physical_port_ordinal) &&
         in.integer(value.prefix_length) &&
         in.integer(value.excluded_prefix_length) &&
         in.integer(value.protocol) &&
         value.protocol <= dhcpv6::RelayLeaseProtocol::delegated_prefix &&
         in.boolean(value.has_client_mac) &&
         in.boolean(value.has_excluded_prefix);
}

void dhcpv6_relay_route(Writer &out,
                        const dhcpv6::RelayRouteCheckpoint &value) {
  ipv6(out, value.network);
  ipv6(out, value.next_hop);
  out.integer(value.interface_id);
  out.integer(value.physical_port_ordinal);
  out.integer(value.prefix_length);
  out.integer(value.protocol);
  out.boolean(value.blackhole);
}

bool dhcpv6_relay_route(Reader &in,
                        dhcpv6::RelayRouteCheckpoint &value) noexcept {
  return ipv6(in, value.network) && ipv6(in, value.next_hop) &&
         in.integer(value.interface_id) &&
         in.integer(value.physical_port_ordinal) &&
         in.integer(value.prefix_length) && value.prefix_length <= 128U &&
         in.integer(value.protocol) &&
         value.protocol <=
             dhcpv6::RelayRouteProtocol::delegated_prefix_exclude &&
         in.boolean(value.blackhole);
}

void sap_attachment(Writer &out, const service::SapAttachment &value) {
  out.integer(value.logical_interface_id);
  out.integer(value.sap.port.ordinal);
  out.integer(value.sap.port.card);
  out.integer(value.sap.port.mda);
  out.integer(value.sap.port.port);
  out.integer(value.sap.encapsulation);
  out.boolean(value.sap.outer_vlan.has_value());
  if (value.sap.outer_vlan)
    out.integer(*value.sap.outer_vlan);
  out.boolean(value.sap.inner_vlan.has_value());
  if (value.sap.inner_vlan)
    out.integer(*value.sap.inner_vlan);
  out.integer(value.outer_tpid);
  out.integer(value.inner_tpid);
}

bool sap_attachment(Reader &in, service::SapAttachment &value) noexcept {
  bool outer_present{};
  bool inner_present{};
  if (!in.integer(value.logical_interface_id) ||
      !in.integer(value.sap.port.ordinal) || !in.integer(value.sap.port.card) ||
      !in.integer(value.sap.port.mda) || !in.integer(value.sap.port.port) ||
      !in.integer(value.sap.encapsulation) ||
      value.sap.encapsulation > service::EthernetEncapsulation::qinq ||
      !in.boolean(outer_present))
    return false;
  if (outer_present) {
    std::uint16_t vlan{};
    if (!in.integer(vlan))
      return false;
    value.sap.outer_vlan = vlan;
  } else {
    value.sap.outer_vlan.reset();
  }
  if (!in.boolean(inner_present))
    return false;
  if (inner_present) {
    std::uint16_t vlan{};
    if (!in.integer(vlan))
      return false;
    value.sap.inner_vlan = vlan;
  } else {
    value.sap.inner_vlan.reset();
  }
  return in.integer(value.outer_tpid) && in.integer(value.inner_tpid);
}

void service_ipv6_interface(Writer &out,
                            const service::ServiceIpv6Interface &interface) {
  out.integer(interface.interface_id);
  out.integer(interface.physical_port_ordinal);
  out.integer(interface.mtu);
  mac(out, interface.mac);
  ipv6(out, interface.address);
  ipv6(out, interface.network);
  ipv6(out, interface.link_local);
  out.integer(interface.prefix_length);
  out.integer(interface.nd_reachable_time_milliseconds);
  out.integer(interface.nd_stale_time_seconds);
  out.integer(interface.unsolicited_learning);
  out.integer(interface.proactive_refresh);
  out.integer(interface.neighbor_limit);
  out.integer(interface.neighbor_limit_threshold_percent);
  out.integer(interface.redirect_maximum);
  out.integer(interface.redirect_interval_seconds);
  out.boolean(interface.neighbor_limit_configured);
  out.boolean(interface.neighbor_limit_log_only);
  out.boolean(interface.redirects_enabled);
  out.boolean(interface.configured);
  out.boolean(interface.operational);
}

bool service_ipv6_interface(Reader &in,
                            service::ServiceIpv6Interface &interface) noexcept {
  return in.integer(interface.interface_id) &&
         in.integer(interface.physical_port_ordinal) &&
         in.integer(interface.mtu) && mac(in, interface.mac) &&
         ipv6(in, interface.address) && ipv6(in, interface.network) &&
         ipv6(in, interface.link_local) &&
         in.integer(interface.prefix_length) &&
         in.integer(interface.nd_reachable_time_milliseconds) &&
         in.integer(interface.nd_stale_time_seconds) &&
         in.integer(interface.unsolicited_learning) &&
         interface.unsolicited_learning <= Ipv6UnsolicitedLearning::both &&
         in.integer(interface.proactive_refresh) &&
         interface.proactive_refresh <= Ipv6UnsolicitedLearning::both &&
         in.integer(interface.neighbor_limit) &&
         in.integer(interface.neighbor_limit_threshold_percent) &&
         in.integer(interface.redirect_maximum) &&
         in.integer(interface.redirect_interval_seconds) &&
         in.boolean(interface.neighbor_limit_configured) &&
         in.boolean(interface.neighbor_limit_log_only) &&
         in.boolean(interface.redirects_enabled) &&
         in.boolean(interface.configured) && in.boolean(interface.operational);
}

void dhcpv4_leasequery_request(
    Writer &out, const dhcpv4::leasequery::RequestView &request) {
  out.integer(request.kind);
  out.integer(request.selector);
  out.integer(request.transaction_id);
  out.boolean(request.query_start_time.has_value());
  if (request.query_start_time)
    out.integer(*request.query_start_time);
  out.boolean(request.query_end_time.has_value());
  if (request.query_end_time)
    out.integer(*request.query_end_time);
  out.integer(request.selector_octets);
  out.octets(std::span<const std::uint8_t>{request.selector_value}.first(
      request.selector_octets));
  out.integer(request.requested_option_octets);
  out.octets(std::span<const std::uint8_t>{request.requested_options}.first(
      request.requested_option_octets));
  out.integer(request.hardware_type);
}

bool dhcpv4_leasequery_request(
    Reader &in, dhcpv4::leasequery::RequestView &request) noexcept {
  bool start_present{};
  bool end_present{};
  if (!in.integer(request.kind) ||
      request.kind > dhcpv4::leasequery::RequestKind::tls ||
      !in.integer(request.selector) ||
      request.selector >
          dhcpv4::leasequery::SelectorKind::relay_identifier ||
      !in.integer(request.transaction_id) ||
      !in.boolean(start_present))
    return false;
  if (start_present) {
    std::uint32_t value{};
    if (!in.integer(value))
      return false;
    request.query_start_time = value;
  } else {
    request.query_start_time.reset();
  }
  if (!in.boolean(end_present))
    return false;
  if (end_present) {
    std::uint32_t value{};
    if (!in.integer(value))
      return false;
    request.query_end_time = value;
  } else {
    request.query_end_time.reset();
  }
  if (!in.integer(request.selector_octets) ||
      request.selector_octets > request.selector_value.size())
    return false;
  const auto selector = in.view(request.selector_octets);
  if (!selector)
    return false;
  std::copy(selector->begin(), selector->end(),
            request.selector_value.begin());
  if (!in.integer(request.requested_option_octets) ||
      request.requested_option_octets > request.requested_options.size())
    return false;
  const auto requested = in.view(request.requested_option_octets);
  if (!requested || !in.integer(request.hardware_type))
    return false;
  std::copy(requested->begin(), requested->end(),
            request.requested_options.begin());
  return true;
}

void dhcpv4_leasequery_session(
    Writer &out,
    const RouterForwarderCheckpoint::Dhcpv4LeasequerySession &session) {
  out.integer(session.socket.index);
  out.integer(session.socket.generation);
  out.integer(session.decoder.occupied);
  out.octets(std::span<const std::uint8_t>{session.decoder.storage}.first(
      session.decoder.occupied));
  out.integer(session.decoder.complete_octets);
  out.boolean(session.decoder.malformed);
  out.boolean(session.request.has_value());
  if (session.request)
    dhcpv4_leasequery_request(out, *session.request);
  ipv4(out, session.local);
  ipv4(out, session.remote);
  out.string(session.server_name);
  out.integer(session.lease_cursor);
  out.integer(session.pool_cursor);
  out.integer(session.address_cursor);
  out.integer(session.revision_cursor);
  out.integer(session.scan_revision_target);
  out.integer(session.data_remaining_nanoseconds);
  out.integer(session.keepalive_remaining_nanoseconds);
  out.boolean(session.first_reply);
  out.boolean(session.catch_up_complete);
  out.boolean(session.done);
}

bool dhcpv4_leasequery_session(
    Reader &in,
    RouterForwarderCheckpoint::Dhcpv4LeasequerySession &session) {
  bool request_present{};
  if (!in.integer(session.socket.index) ||
      !in.integer(session.socket.generation) ||
      !in.integer(session.decoder.occupied) ||
      session.decoder.occupied >
          packet::dhcpv4::maximum_message_octets +
              dhcpv4::leasequery::frame_prefix_octets)
    return false;
  const auto decoder = in.view(session.decoder.occupied);
  if (!decoder)
    return false;
  session.decoder.storage.assign(decoder->begin(), decoder->end());
  if (!in.integer(session.decoder.complete_octets) ||
      !in.boolean(session.decoder.malformed) ||
      !in.boolean(request_present))
    return false;
  if (request_present) {
    session.request.emplace();
    if (!dhcpv4_leasequery_request(in, *session.request))
      return false;
  } else {
    session.request.reset();
  }
  return ipv4(in, session.local) && ipv4(in, session.remote) &&
         in.string(session.server_name,
                   device_catalog::dhcpv4_server_name_bytes) &&
         in.integer(session.lease_cursor) &&
         in.integer(session.pool_cursor) &&
         in.integer(session.address_cursor) &&
         in.integer(session.revision_cursor) &&
         in.integer(session.scan_revision_target) &&
         in.integer(session.data_remaining_nanoseconds) &&
         in.integer(session.keepalive_remaining_nanoseconds) &&
         in.boolean(session.first_reply) &&
         in.boolean(session.catch_up_complete) && in.boolean(session.done);
}

void forwarder_state(Writer &out, const RouterForwarderCheckpoint &state) {
  out.boolean(state.transit_forwarding_enabled);
  count(out, state.ports);
  for (const auto &value : state.ports)
    forward_port(out, value);
  count(out, state.native_ipv6_addresses);
  for (const auto &address : state.native_ipv6_addresses) {
    // Address intent is a forwarding value generation. DAD deadlines are
    // serialized by their distinct owner below and are never duplicated here.
    ipv6(out, address.address);
    ipv6(out, address.network);
    out.integer(address.interface_id);
    out.integer(address.primary_preference);
    out.integer(address.tag);
    out.integer(address.port_ordinal);
    out.integer(address.prefix_length);
    out.boolean(address.duplicate_address_detection);
    out.boolean(address.tag_configured);
  }
  count(out, state.sap_attachments);
  for (const auto &attachment : state.sap_attachments)
    sap_attachment(out, attachment);
  count(out, state.service_ipv6_interfaces);
  for (const auto &interface : state.service_ipv6_interfaces)
    service_ipv6_interface(out, interface);
  fib(out, state.fib);
  ipv6_fib(out, state.ipv6_fib);
  count(out, state.ipv4_route_ages_seconds);
  for (const auto value : state.ipv4_route_ages_seconds)
    out.integer(value);
  count(out, state.ipv6_route_ages_seconds);
  for (const auto value : state.ipv6_route_ages_seconds)
    out.integer(value);
  count(out, state.adjacencies);
  for (const auto &entry : state.adjacencies) {
    out.integer(entry.port_ordinal);
    out.integer(entry.address);
    mac(out, entry.mac);
    out.integer(entry.remaining_nanoseconds);
    out.boolean(entry.aging_disabled);
    out.boolean(entry.configured_static);
  }
  count(out, state.ipv6_neighbors);
  for (const auto &entry : state.ipv6_neighbors) {
    // Neighbor scope is the stable IP interface identity. Serializing the
    // physical ordinal here would merge tagged IES interfaces after restore.
    out.integer(entry.interface_id);
    ipv6(out, entry.address);
    mac(out, entry.mac);
    out.integer(entry.state);
    out.boolean(entry.is_router);
    out.boolean(entry.is_static);
    out.boolean(entry.has_deadline);
    out.integer(entry.probes_sent);
    out.integer(entry.use_generation);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.stale_time_seconds);
    out.boolean(entry.proactive_refresh);
  }
  count(out, state.ipv6_dad);
  for (const auto &entry : state.ipv6_dad) {
    out.integer(entry.interface_id);
    out.integer(entry.port_ordinal);
    ipv6(out, entry.address);
    out.integer(entry.state);
    out.integer(entry.probes_sent);
    out.integer(entry.transmit_limit);
    out.boolean(entry.has_deadline);
    out.integer(entry.remaining_nanoseconds);
  }
  count(out, state.ipv6_router_advertisements);
  for (const auto &entry : state.ipv6_router_advertisements) {
    router_advertisement_config(out, entry.config);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.last_sent_ago_nanoseconds);
    out.integer(entry.random_state);
    out.integer(entry.port_ordinal);
    out.integer(entry.initial_advertisements_remaining);
    out.boolean(entry.requested_enabled);
    out.boolean(entry.active);
    out.boolean(entry.has_sent);
  }
  count(out, state.ipv6_path_mtu);
  for (const auto &entry : state.ipv6_path_mtu) {
    ipv6(out, entry.destination);
    out.integer(entry.remaining_probe_nanoseconds);
    out.integer(entry.interface_id);
    out.integer(entry.mtu);
    out.integer(entry.probe_mtu);
  }
  count(out, state.ipv4_path_mtu);
  for (const auto &entry : state.ipv4_path_mtu) {
    ipv4(out, entry.destination);
    out.integer(entry.remaining_probe_nanoseconds);
    out.integer(entry.interface_id);
    out.integer(entry.mtu);
    out.integer(entry.probe_mtu);
  }
  // Family-specific local reassembly tables are independent forwarding-owner
  // state. IPv4 precedes IPv6 in ABI 6 and both store relative deadlines.
  ipv4_reassembly_entries(out, state.ipv4_reassembly);
  ipv6_reassembly_entries(out, state.ipv6_reassembly);
  udp_endpoint(out, state.udp);
  ike_udp_service(out, state.ike_udp);
  out.boolean(state.tcp.has_value());
  if (state.tcp) {
    // Reuse the transport-owned codec so the runtime checkpoint does not
    // duplicate TCP invariants or silently omit future socket fields.
    const auto encoded = transport::tcp::checkpoint::encode(*state.tcp);
    if (!encoded || encoded->size() > std::numeric_limits<std::uint32_t>::max())
      throw std::length_error("router TCP endpoint checkpoint cannot be encoded");
    out.integer<std::uint32_t>(static_cast<std::uint32_t>(encoded->size()));
    out.octets(*encoded);
  }
  out.boolean(state.dhcpv4_leasequery_listener.has_value());
  if (state.dhcpv4_leasequery_listener) {
    out.integer(state.dhcpv4_leasequery_listener->index);
    out.integer(state.dhcpv4_leasequery_listener->generation);
  }
  count(out, state.dhcpv4_leasequery_sessions);
  for (const auto &session : state.dhcpv4_leasequery_sessions)
    dhcpv4_leasequery_session(out, session);
  count(out, state.dhcpv4_relay_interfaces);
  for (const auto &configuration : state.dhcpv4_relay_interfaces)
    dhcpv4_relay_configuration(out, configuration);
  count(out, state.dhcpv4_servers);
  for (const auto &server : state.dhcpv4_servers) {
    out.string(server.name);
    dhcpv4_server_checkpoint(out, server.protocol);
  }
  out.boolean(state.dhcpv4_relay_socket.has_value());
  if (state.dhcpv4_relay_socket) {
    out.integer(state.dhcpv4_relay_socket->index);
    out.integer(state.dhcpv4_relay_socket->generation);
  }
  count(out, state.dhcpv6_relay_interfaces);
  for (const auto &configuration : state.dhcpv6_relay_interfaces)
    dhcpv6_relay_configuration(out, configuration);
  count(out, state.dhcpv6_servers);
  for (const auto &server : state.dhcpv6_servers) {
    out.string(server.name);
    dhcpv6_server_checkpoint(out, server.protocol);
  }
  count(out, state.dhcpv6_relay_leases);
  for (const auto &lease : state.dhcpv6_relay_leases)
    dhcpv6_relay_lease(out, lease);
  count(out, state.dhcpv6_relay_routes);
  for (const auto &route : state.dhcpv6_relay_routes)
    dhcpv6_relay_route(out, route);
  out.boolean(state.dhcpv6_relay_socket.has_value());
  if (state.dhcpv6_relay_socket) {
    out.integer(state.dhcpv6_relay_socket->index);
    out.integer(state.dhcpv6_relay_socket->generation);
  }
  count(out, state.mld_interfaces);
  for (const auto &entry : state.mld_interfaces) {
    mld_router_configuration(out, entry.intent);
    mld_router_checkpoint(out, entry.protocol);
    count(out, entry.ssm_translations);
    for (const auto &translation : entry.ssm_translations) {
      ipv6(out, translation.start);
      ipv6(out, translation.end);
      ipv6(out, translation.source);
    }
    mld_import_policy(out, entry.import_policy);
    out.boolean(entry.running);
  }
  count(out, state.ipv6_redirect_limiters);
  for (const auto &entry : state.ipv6_redirect_limiters) {
    out.integer(entry.port_ordinal);
    out.integer(entry.sent);
    out.integer(entry.remaining_nanoseconds);
  }
  count(out, state.ipv4_redirect_limiters);
  for (const auto &entry : state.ipv4_redirect_limiters) {
    out.integer(entry.port_ordinal);
    out.integer(entry.sent);
    out.integer(entry.remaining_nanoseconds);
  }
  count(out, state.ipv6_reachable_times);
  for (const auto &entry : state.ipv6_reachable_times) {
    out.integer(entry.port_ordinal);
    out.integer(entry.base_milliseconds);
    out.integer(entry.effective_milliseconds);
    out.integer(entry.random_state);
    out.integer(entry.remaining_refresh_nanoseconds);
  }
  icmpv4_statistics(out, state.icmpv4_global_statistics);
  count(out, state.icmpv4_interface_statistics);
  for (const auto &entry : state.icmpv4_interface_statistics) {
    out.integer(entry.port_ordinal);
    icmpv4_statistics(out, entry.statistics);
  }
  icmpv6_statistics(out, state.icmpv6_global_statistics);
  count(out, state.icmpv6_interface_statistics);
  for (const auto &entry : state.icmpv6_interface_statistics) {
    out.integer(entry.port_ordinal);
    icmpv6_statistics(out, entry.statistics);
    out.integer(entry.router_advertisement_last_sent_ago_nanoseconds);
    out.integer(entry.neighbor_solicitation_last_sent_ago_nanoseconds);
    out.integer(entry.neighbor_advertisement_last_sent_ago_nanoseconds);
  }
  count(out, state.interface_traffic_statistics);
  for (const auto &entry : state.interface_traffic_statistics) {
    out.integer(entry.ingress_packets);
    out.integer(entry.ingress_octets);
    out.integer(entry.egress_packets);
    out.integer(entry.egress_octets);
  }
  count(out, state.ipv6_probe_packets);
  for (const auto &frame : state.ipv6_probe_packets)
    out.frame(frame);
  out.boolean(state.ipv4_probe_valid);
  if (state.ipv4_probe_valid) {
    out.frame(state.ipv4_probe_packet);
    ipv4(out, state.ipv4_probe_destination);
    out.integer(state.ipv4_probe_interface_id);
    out.integer(state.ipv4_probe_port_ordinal);
  }
  count(out, state.pending);
  for (const auto &entry : state.pending) {
    out.boolean(entry.transit);
    out.boolean(entry.ipv6);
    out.integer(entry.interface_id);
    out.integer(entry.port_ordinal);
    out.integer(entry.next_hop);
    ipv6(out, entry.next_hop_ipv6);
    out.frame(entry.frame);
    out.integer(entry.ipv6_source_mtu);
    out.integer(entry.arp_retry_remaining_nanoseconds);
  }
  out.integer(state.forwarded_frames);
  out.integer(state.dropped_frames);
  out.integer(state.last_drop);
  out.integer(state.echo_reply_sequence);
  out.boolean(state.echo_reply_valid);
  ipv4(out, state.echo_request_destination);
  out.integer(state.echo_request_age_nanoseconds);
  out.integer(state.echo_reply_rtt_nanoseconds);
  out.integer(state.echo_reply_ttl);
  out.integer(state.echo_request_sequence);
  out.boolean(state.echo_request_valid);
  out.integer(state.ipv6_echo_reply_sequence);
  out.boolean(state.ipv6_echo_reply_valid);
  out.integer(state.ipv6_probe_age_nanoseconds);
  out.integer(state.ipv6_echo_reply_rtt_nanoseconds);
  out.integer(state.ipv6_echo_reply_hop_limit);
  out.integer(state.ipv6_echo_error_parameter);
  out.integer(state.ipv6_echo_error_sequence);
  out.integer(state.ipv6_echo_error_type);
  out.integer(state.ipv6_echo_error_code);
  out.boolean(state.ipv6_echo_error_valid);
  ipv6(out, state.ipv6_probe_destination);
  out.integer(state.ipv6_fragment_identification);
  out.integer(state.ipv6_probe_interface_id);
  out.integer(state.ipv6_probe_port_ordinal);
  out.integer(state.ipv6_probe_sequence);
  out.integer(state.mld_service_cursor);
  out.boolean(state.ipv6_probe_valid);
}

bool forwarder_state(Reader &in, RouterForwarderCheckpoint &state) {
  std::uint32_t size{};
  if (!in.boolean(state.transit_forwarding_enabled) ||
      !count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ports.resize(size);
  for (auto &value : state.ports)
    if (!forward_port(in, value))
      return false;
  if (!count(in, size, RouterIpv6AddressTable::capacity))
    return false;
  state.native_ipv6_addresses.resize(size);
  for (auto &address : state.native_ipv6_addresses)
    if (!ipv6(in, address.address) || !ipv6(in, address.network) ||
        !in.integer(address.interface_id) ||
        !in.integer(address.primary_preference) || !in.integer(address.tag) ||
        !in.integer(address.port_ordinal) ||
        !in.integer(address.prefix_length) ||
        !in.boolean(address.duplicate_address_detection) ||
        !in.boolean(address.tag_configured))
      return false;
  // The bound follows from the 256 MiB checkpoint envelope and the 23-byte
  // minimum encoded attachment, not from an invented SR OS service limit.
  // A truncated or hostile count is rejected before vector allocation.
  if (!count(in, size, maximum_checkpoint_bytes / 23U))
    return false;
  state.sap_attachments.resize(size);
  for (auto &attachment : state.sap_attachments)
    if (!sap_attachment(in, attachment))
      return false;
  if (!count(in, size, maximum_checkpoint_bytes / 80U))
    return false;
  state.service_ipv6_interfaces.resize(size);
  for (auto &interface : state.service_ipv6_interfaces)
    if (!service_ipv6_interface(in, interface))
      return false;
  if (!fib(in, state.fib) || !ipv6_fib(in, state.ipv6_fib))
    return false;
  if (!count(in, size, device_catalog::maximum_fib_routes_per_router))
    return false;
  state.ipv4_route_ages_seconds.resize(size);
  for (auto &value : state.ipv4_route_ages_seconds)
    if (!in.integer(value))
      return false;
  if (!count(in, size, device_catalog::maximum_fib_routes_per_router))
    return false;
  state.ipv6_route_ages_seconds.resize(size);
  for (auto &value : state.ipv6_route_ages_seconds)
    if (!in.integer(value))
      return false;
  if (!count(in, size, device_catalog::arp_entries_per_router))
    return false;
  state.adjacencies.resize(size);
  for (auto &entry : state.adjacencies)
    if (!in.integer(entry.port_ordinal) || !in.integer(entry.address) ||
        !mac(in, entry.mac) || !in.integer(entry.remaining_nanoseconds) ||
        !in.boolean(entry.aging_disabled) ||
        !in.boolean(entry.configured_static))
      return false;
  if (!count(in, size, device_catalog::ipv6_neighbor_entries_per_router))
    return false;
  state.ipv6_neighbors.resize(size);
  for (auto &entry : state.ipv6_neighbors)
    if (!in.integer(entry.interface_id) || !ipv6(in, entry.address) ||
        !mac(in, entry.mac) || !in.integer(entry.state) ||
        entry.state > Ipv6NeighborState::probe ||
        !in.boolean(entry.is_router) || !in.boolean(entry.is_static) ||
        !in.boolean(entry.has_deadline) || !in.integer(entry.probes_sent) ||
        !in.integer(entry.use_generation) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.stale_time_seconds) ||
        !in.boolean(entry.proactive_refresh))
      return false;
  if (!count(in, size, Ipv6DadTable::capacity))
    return false;
  state.ipv6_dad.resize(size);
  for (auto &entry : state.ipv6_dad)
    if (!in.integer(entry.interface_id) || !in.integer(entry.port_ordinal) ||
        !ipv6(in, entry.address) || !in.integer(entry.state) ||
        entry.state > Ipv6DadState::duplicate ||
        !in.integer(entry.probes_sent) || !in.integer(entry.transmit_limit) ||
        !in.boolean(entry.has_deadline) ||
        !in.integer(entry.remaining_nanoseconds))
      return false;
  if (!count(in, size, Ipv6RouterAdvertisementTable::capacity))
    return false;
  state.ipv6_router_advertisements.resize(size);
  for (auto &entry : state.ipv6_router_advertisements)
    if (!router_advertisement_config(in, entry.config) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.last_sent_ago_nanoseconds) ||
        !in.integer(entry.random_state) || !in.integer(entry.port_ordinal) ||
        !in.integer(entry.initial_advertisements_remaining) ||
        !in.boolean(entry.requested_enabled) || !in.boolean(entry.active) ||
        !in.boolean(entry.has_sent))
      return false;
  if (!count(in, size, device_catalog::ipv6_pmtu_entries_per_endpoint))
    return false;
  state.ipv6_path_mtu.resize(size);
  for (auto &entry : state.ipv6_path_mtu)
    if (!ipv6(in, entry.destination) ||
        !in.integer(entry.remaining_probe_nanoseconds) ||
        !in.integer(entry.interface_id) || !in.integer(entry.mtu) ||
        !in.integer(entry.probe_mtu))
      return false;
  if (!count(in, size, device_catalog::ipv4_pmtu_entries_per_endpoint))
    return false;
  state.ipv4_path_mtu.resize(size);
  for (auto &entry : state.ipv4_path_mtu)
    if (!ipv4(in, entry.destination) ||
        !in.integer(entry.remaining_probe_nanoseconds) ||
        !in.integer(entry.interface_id) || !in.integer(entry.mtu) ||
        !in.integer(entry.probe_mtu))
      return false;
  if (!ipv4_reassembly_entries(in, state.ipv4_reassembly) ||
      !ipv6_reassembly_entries(in, state.ipv6_reassembly))
    return false;
  if (!udp_endpoint(in, state.udp) || !ike_udp_service(in, state.ike_udp))
    return false;
  bool tcp_present{};
  if (!in.boolean(tcp_present))
    return false;
  if (tcp_present) {
    std::uint32_t tcp_octets{};
    if (!in.integer(tcp_octets))
      return false;
    const auto encoded = in.view(tcp_octets);
    if (!encoded)
      return false;
    state.tcp = transport::tcp::checkpoint::decode(*encoded);
    if (!state.tcp)
      return false;
  } else {
    state.tcp.reset();
  }
  bool leasequery_listener_present{};
  if (!in.boolean(leasequery_listener_present))
    return false;
  if (leasequery_listener_present) {
    transport::tcp::EndpointSocketHandle listener;
    if (!in.integer(listener.index) ||
        !in.integer(listener.generation))
      return false;
    state.dhcpv4_leasequery_listener = listener;
  } else {
    state.dhcpv4_leasequery_listener.reset();
  }
  if (!count(
          in, size,
          device_catalog::dhcpv4_leasequery_connections_per_server))
    return false;
  state.dhcpv4_leasequery_sessions.resize(size);
  for (auto &session : state.dhcpv4_leasequery_sessions)
    if (!dhcpv4_leasequery_session(in, session))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.dhcpv4_relay_interfaces.resize(size);
  for (auto &configuration : state.dhcpv4_relay_interfaces)
    if (!dhcpv4_relay_configuration(in, configuration))
      return false;
  // The checkpoint envelope is the resource bound for server instances. Pool
  // and lease counts are validated separately by the protocol decoder.
  if (!count(in, size, maximum_checkpoint_bytes / 64U))
    return false;
  state.dhcpv4_servers.resize(size);
  for (auto &server : state.dhcpv4_servers)
    if (!in.string(server.name, 32U) ||
        !dhcpv4_server_checkpoint(in, server.protocol))
      return false;
  bool dhcpv4_relay_socket_present{};
  if (!in.boolean(dhcpv4_relay_socket_present))
    return false;
  if (dhcpv4_relay_socket_present) {
    transport::UdpSocketHandle socket;
    if (!in.integer(socket.index) || !in.integer(socket.generation))
      return false;
    state.dhcpv4_relay_socket = socket;
  } else {
    state.dhcpv4_relay_socket.reset();
  }
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.dhcpv6_relay_interfaces.resize(size);
  for (auto &configuration : state.dhcpv6_relay_interfaces)
    if (!dhcpv6_relay_configuration(in, configuration))
      return false;
  if (!count(in, size, maximum_checkpoint_bytes / 64U))
    return false;
  state.dhcpv6_servers.resize(size);
  for (auto &server : state.dhcpv6_servers)
    if (!in.string(server.name, 32U) ||
        !dhcpv6_server_checkpoint(in, server.protocol))
      return false;
  // The byte-envelope bound is deliberately independent from one current
  // Nokia platform limit. The repository validator later applies each
  // configured interface limit and rejects surplus state before publication.
  if (!count(in, size, maximum_checkpoint_bytes / 96U))
    return false;
  state.dhcpv6_relay_leases.resize(size);
  for (auto &lease : state.dhcpv6_relay_leases)
    if (!dhcpv6_relay_lease(in, lease))
      return false;
  if (!count(in, size, maximum_checkpoint_bytes / 48U))
    return false;
  state.dhcpv6_relay_routes.resize(size);
  for (auto &route : state.dhcpv6_relay_routes)
    if (!dhcpv6_relay_route(in, route))
      return false;
  bool relay_socket_present{};
  if (!in.boolean(relay_socket_present))
    return false;
  if (relay_socket_present) {
    transport::UdpSocketHandle socket;
    if (!in.integer(socket.index) || !in.integer(socket.generation))
      return false;
    state.dhcpv6_relay_socket = socket;
  } else {
    state.dhcpv6_relay_socket.reset();
  }
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.mld_interfaces.resize(size);
  for (auto &entry : state.mld_interfaces) {
    if (!mld_router_configuration(in, entry.intent) ||
        !mld_router_checkpoint(in, entry.protocol) ||
        !count(in, size,
               device_catalog::mld_router_group_sources_per_interface))
      return false;
    entry.ssm_translations.resize(size);
    for (auto &translation : entry.ssm_translations)
      if (!ipv6(in, translation.start) || !ipv6(in, translation.end) ||
          !ipv6(in, translation.source))
        return false;
    if (!mld_import_policy(in, entry.import_policy))
      return false;
    if (!in.boolean(entry.running))
      return false;
  }
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ipv6_redirect_limiters.resize(size);
  for (auto &entry : state.ipv6_redirect_limiters)
    if (!in.integer(entry.port_ordinal) || !in.integer(entry.sent) ||
        !in.integer(entry.remaining_nanoseconds))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ipv4_redirect_limiters.resize(size);
  for (auto &entry : state.ipv4_redirect_limiters)
    if (!in.integer(entry.port_ordinal) || !in.integer(entry.sent) ||
        !in.integer(entry.remaining_nanoseconds))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.ipv6_reachable_times.resize(size);
  for (auto &entry : state.ipv6_reachable_times)
    if (!in.integer(entry.port_ordinal) ||
        !in.integer(entry.base_milliseconds) ||
        !in.integer(entry.effective_milliseconds) ||
        !in.integer(entry.random_state) ||
        !in.integer(entry.remaining_refresh_nanoseconds))
      return false;
  if (!icmpv4_statistics(in, state.icmpv4_global_statistics))
    return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.icmpv4_interface_statistics.resize(size);
  for (auto &entry : state.icmpv4_interface_statistics)
    if (!in.integer(entry.port_ordinal) ||
        !icmpv4_statistics(in, entry.statistics))
      return false;
  if (!icmpv6_statistics(in, state.icmpv6_global_statistics))
    return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.icmpv6_interface_statistics.resize(size);
  for (auto &entry : state.icmpv6_interface_statistics)
    if (!in.integer(entry.port_ordinal) ||
        !icmpv6_statistics(in, entry.statistics) ||
        !in.integer(entry.router_advertisement_last_sent_ago_nanoseconds) ||
        !in.integer(entry.neighbor_solicitation_last_sent_ago_nanoseconds) ||
        !in.integer(entry.neighbor_advertisement_last_sent_ago_nanoseconds))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router))
    return false;
  state.interface_traffic_statistics.resize(size);
  for (auto &entry : state.interface_traffic_statistics)
    if (!in.integer(entry.ingress_packets) ||
        !in.integer(entry.ingress_octets) ||
        !in.integer(entry.egress_packets) ||
        !in.integer(entry.egress_octets))
      return false;
  if (!count(in, size, packet::Ipv6FragmentBatch::maximum_fragment_count))
    return false;
  state.ipv6_probe_packets.resize(size);
  for (auto &frame : state.ipv6_probe_packets)
    if (!in.frame(frame))
      return false;
  if (!in.boolean(state.ipv4_probe_valid))
    return false;
  if (state.ipv4_probe_valid && (!in.frame(state.ipv4_probe_packet) ||
                                 !ipv4(in, state.ipv4_probe_destination) ||
                                 !in.integer(state.ipv4_probe_interface_id) ||
                                 !in.integer(state.ipv4_probe_port_ordinal)))
    return false;
  if (!count(in, size, device_catalog::pending_l3_frames_per_router))
    return false;
  state.pending.resize(size);
  for (auto &entry : state.pending)
    if (!in.boolean(entry.transit) || !in.boolean(entry.ipv6) ||
        !in.integer(entry.interface_id) || !in.integer(entry.port_ordinal) ||
        !in.integer(entry.next_hop) || !ipv6(in, entry.next_hop_ipv6) ||
        !in.frame(entry.frame) || !in.integer(entry.ipv6_source_mtu) ||
        !in.integer(entry.arp_retry_remaining_nanoseconds))
      return false;
  return in.integer(state.forwarded_frames) &&
         in.integer(state.dropped_frames) && in.integer(state.last_drop) &&
         state.last_drop <= ForwardDrop::blackhole &&
         in.integer(state.echo_reply_sequence) &&
         in.boolean(state.echo_reply_valid) &&
         ipv4(in, state.echo_request_destination) &&
         in.integer(state.echo_request_age_nanoseconds) &&
         in.integer(state.echo_reply_rtt_nanoseconds) &&
         in.integer(state.echo_reply_ttl) &&
         in.integer(state.echo_request_sequence) &&
         in.boolean(state.echo_request_valid) &&
         in.integer(state.ipv6_echo_reply_sequence) &&
         in.boolean(state.ipv6_echo_reply_valid) &&
         in.integer(state.ipv6_probe_age_nanoseconds) &&
         in.integer(state.ipv6_echo_reply_rtt_nanoseconds) &&
         in.integer(state.ipv6_echo_reply_hop_limit) &&
         state.echo_request_age_nanoseconds <=
             static_cast<std::uint64_t>(
                 std::chrono::duration_cast<std::chrono::nanoseconds>(
                     device_catalog::checkpoint_max_relative_deadline)
                     .count()) &&
         state.echo_reply_rtt_nanoseconds <=
             static_cast<std::uint64_t>(
                 std::chrono::duration_cast<std::chrono::nanoseconds>(
                     device_catalog::checkpoint_max_relative_deadline)
                     .count()) &&
         state.ipv6_probe_age_nanoseconds <=
             static_cast<std::uint64_t>(
                 std::chrono::duration_cast<std::chrono::nanoseconds>(
                     device_catalog::checkpoint_max_relative_deadline)
                     .count()) &&
         state.ipv6_echo_reply_rtt_nanoseconds <=
             static_cast<std::uint64_t>(
                 std::chrono::duration_cast<std::chrono::nanoseconds>(
                     device_catalog::checkpoint_max_relative_deadline)
                     .count()) &&
         in.integer(state.ipv6_echo_error_parameter) &&
         in.integer(state.ipv6_echo_error_sequence) &&
         in.integer(state.ipv6_echo_error_type) &&
         in.integer(state.ipv6_echo_error_code) &&
         in.boolean(state.ipv6_echo_error_valid) &&
         (!state.ipv6_echo_error_valid ||
          state.ipv6_echo_error_type <
              packet::icmpv6_informational_type_boundary) &&
         ipv6(in, state.ipv6_probe_destination) &&
         in.integer(state.ipv6_fragment_identification) &&
         in.integer(state.ipv6_probe_interface_id) &&
         in.integer(state.ipv6_probe_port_ordinal) &&
         in.integer(state.ipv6_probe_sequence) &&
         in.integer(state.mld_service_cursor) &&
         in.boolean(state.ipv6_probe_valid);
}

void network_stored_frame(Writer &out, const NetworkStoredFrame &value) {
  ipv4(out, value.next_hop);
  out.frame(value.frame);
}

bool network_stored_frame(Reader &in, NetworkStoredFrame &value) noexcept {
  return ipv4(in, value.next_hop) && in.frame(value.frame);
}

void udp_binding(Writer &out, const transport::UdpBinding &value) {
  out.integer(value.family);
  ipv4(out, value.ipv4);
  ipv6(out, value.ipv6);
  out.integer(value.interface_id);
  out.integer(value.port);
  out.boolean(value.ipv4_broadcast);
  out.boolean(value.ipv4_unconfigured_unicast);
}

bool udp_binding(Reader &in, transport::UdpBinding &value) noexcept {
  return in.integer(value.family) &&
         value.family <= transport::IpFamily::ipv6 && ipv4(in, value.ipv4) &&
         ipv6(in, value.ipv6) && in.integer(value.interface_id) &&
         in.integer(value.port) && in.boolean(value.ipv4_broadcast) &&
         in.boolean(value.ipv4_unconfigured_unicast);
}

void udp_metadata(Writer &out, const transport::UdpDatagramMetadata &value) {
  out.integer(value.family);
  ipv4(out, value.source_ipv4);
  ipv4(out, value.destination_ipv4);
  ipv6(out, value.source_ipv6);
  ipv6(out, value.destination_ipv6);
  mac(out, value.source_mac);
  out.integer(value.interface_id);
  out.integer(value.payload_octets);
  out.integer(value.source_port);
  out.integer(value.destination_port);
}

bool udp_metadata(Reader &in, transport::UdpDatagramMetadata &value) noexcept {
  return in.integer(value.family) &&
         value.family <= transport::IpFamily::ipv6 &&
         ipv4(in, value.source_ipv4) && ipv4(in, value.destination_ipv4) &&
         ipv6(in, value.source_ipv6) && ipv6(in, value.destination_ipv6) &&
         mac(in, value.source_mac) && in.integer(value.interface_id) &&
         in.integer(value.payload_octets) && in.integer(value.source_port) &&
         in.integer(value.destination_port);
}

void udp_ipv6_transmission(Writer &out,
                           const transport::UdpIpv6Transmission &value) {
  ipv6(out, value.local);
  ipv6(out, value.remote);
  out.integer(value.interface_id);
  out.integer(value.remote_port);
}

bool udp_ipv6_transmission(Reader &in,
                           transport::UdpIpv6Transmission &value) noexcept {
  return ipv6(in, value.local) && ipv6(in, value.remote) &&
         in.integer(value.interface_id) && in.integer(value.remote_port);
}

void ipv6_network_error(Writer &out, const transport::Ipv6NetworkError &value) {
  ipv6(out, value.remote);
  out.integer(value.interface_id);
  out.integer(value.parameter);
  out.integer(value.remote_port);
  out.integer(value.type);
  out.integer(value.code);
  out.integer(value.kind);
}

bool ipv6_network_error(Reader &in,
                        transport::Ipv6NetworkError &value) noexcept {
  return ipv6(in, value.remote) && in.integer(value.interface_id) &&
         in.integer(value.parameter) && in.integer(value.remote_port) &&
         in.integer(value.type) && in.integer(value.code) &&
         in.integer(value.kind) &&
         value.type < packet::icmpv6_informational_type_boundary &&
         value.kind <= transport::Ipv6NetworkErrorKind::unknown;
}

void udp_endpoint(Writer &out, const transport::UdpEndpointCheckpoint &value) {
  out.integer(value.ephemeral_cursor);
  count(out, value.sockets);
  for (const auto &socket : value.sockets) {
    out.integer(socket.generation);
    out.boolean(socket.occupied);
    if (!socket.occupied)
      continue;
    udp_binding(out, socket.binding);
    out.boolean(socket.last_ipv6_transmission.has_value());
    if (socket.last_ipv6_transmission)
      udp_ipv6_transmission(out, *socket.last_ipv6_transmission);
    out.boolean(socket.network_error.has_value());
    if (socket.network_error)
      ipv6_network_error(out, *socket.network_error);
    count(out, socket.datagrams);
    for (const auto &datagram : socket.datagrams) {
      udp_metadata(out, datagram.metadata);
      count(out, datagram.payload);
      out.octets(datagram.payload);
    }
  }
}

bool udp_endpoint(Reader &in, transport::UdpEndpointCheckpoint &value) {
  if (!in.integer(value.ephemeral_cursor))
    return false;
  std::uint32_t size{};
  // At least generation and occupancy are required for every socket record.
  // Bounding by the complete checkpoint byte budget prevents hostile length
  // fields from turning the dynamic socket table into an unbounded allocation.
  if (!count(in, size, maximum_checkpoint_bytes / 5U))
    return false;
  value.sockets.resize(size);
  for (auto &socket : value.sockets) {
    if (!in.integer(socket.generation) || !in.boolean(socket.occupied))
      return false;
    socket.datagrams.clear();
    socket.last_ipv6_transmission.reset();
    socket.network_error.reset();
    if (!socket.occupied)
      continue;
    bool has_transmission{}, has_error{};
    if (!udp_binding(in, socket.binding) || !in.boolean(has_transmission))
      return false;
    if (has_transmission) {
      socket.last_ipv6_transmission.emplace();
      if (!udp_ipv6_transmission(in, *socket.last_ipv6_transmission))
        return false;
    }
    if (!in.boolean(has_error))
      return false;
    if (has_error) {
      socket.network_error.emplace();
      if (!ipv6_network_error(in, *socket.network_error))
        return false;
    }
    if (!count(in, size, device_catalog::udp_datagrams_per_socket))
      return false;
    socket.datagrams.resize(size);
    for (auto &datagram : socket.datagrams) {
      if (!udp_metadata(in, datagram.metadata) ||
          !count(in, size, packet::udp::maximum_payload_octets))
        return false;
      datagram.payload.resize(size);
      if (!in.octets(datagram.payload))
        return false;
    }
  }
  return true;
}

void ike_udp_service(Writer &out, const ikev2::UdpServiceCheckpoint &value) {
  out.boolean(value.configured);
  // Fixed cardinality is part of the checkpoint ABI: IPv4/500, IPv4/4500,
  // IPv6/500 and IPv6/4500. Handles still carry generations from UDP owner.
  for (const auto handle : value.sockets) {
    out.integer(handle.index);
    out.integer(handle.generation);
  }
}

bool ike_udp_service(Reader &in, ikev2::UdpServiceCheckpoint &value) noexcept {
  if (!in.boolean(value.configured))
    return false;
  for (auto &handle : value.sockets)
    if (!in.integer(handle.index) || !in.integer(handle.generation))
      return false;
  return true;
}

void ipv6_reassembly_entries(
    Writer &out, const std::vector<packet::Ipv6ReassemblyCheckpoint> &value) {
  count(out, value);
  for (const auto &entry : value) {
    ipv6(out, entry.source);
    ipv6(out, entry.destination);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.identification);
    out.integer(entry.fragment_header_offset);
    out.integer(entry.previous_next_header_offset);
    out.integer(entry.final_size);
    out.integer(entry.fragment_next_header);
    out.boolean(entry.have_first);
    out.boolean(entry.have_last);
    if (entry.have_first)
      out.frame(entry.first_fragment);
    count(out, entry.fragmentable);
    out.octets(entry.fragmentable);
    count(out, entry.received);
    out.octets(entry.received);
  }
}

bool ipv6_reassembly_entries(
    Reader &in, std::vector<packet::Ipv6ReassemblyCheckpoint> &value) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::ipv6_reassembly_entries_per_endpoint))
    return false;
  value.resize(size);
  for (auto &entry : value) {
    if (!ipv6(in, entry.source) || !ipv6(in, entry.destination) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.identification) ||
        !in.integer(entry.fragment_header_offset) ||
        !in.integer(entry.previous_next_header_offset) ||
        !in.integer(entry.final_size) ||
        !in.integer(entry.fragment_next_header) ||
        !in.boolean(entry.have_first) || !in.boolean(entry.have_last) ||
        (entry.have_first && !in.frame(entry.first_fragment)) ||
        !count(in, size, packet::maximum_ipv6_payload_octets))
      return false;
    entry.fragmentable.resize(size);
    if (!in.octets(entry.fragmentable) ||
        !count(in, size, (packet::maximum_ipv6_payload_octets + 7U) / 8U))
      return false;
    entry.received.resize(size);
    if (!in.octets(entry.received))
      return false;
  }
  return true;
}

void ipv4_reassembly_entries(
    Writer &out, const std::vector<packet::Ipv4ReassemblyCheckpoint> &value) {
  count(out, value);
  for (const auto &entry : value) {
    ipv4(out, entry.source);
    ipv4(out, entry.destination);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.identification);
    out.integer(entry.final_size);
    out.integer(entry.protocol);
    out.boolean(entry.have_first);
    out.boolean(entry.have_last);
    if (entry.have_first)
      out.frame(entry.first_fragment);
    count(out, entry.payload);
    out.octets(entry.payload);
    count(out, entry.received);
    out.octets(entry.received);
  }
}

bool ipv4_reassembly_entries(
    Reader &in, std::vector<packet::Ipv4ReassemblyCheckpoint> &value) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::ipv4_reassembly_entries_per_endpoint))
    return false;
  value.resize(size);
  for (auto &entry : value) {
    if (!ipv4(in, entry.source) || !ipv4(in, entry.destination) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.identification) || !in.integer(entry.final_size) ||
        !in.integer(entry.protocol) || !in.boolean(entry.have_first) ||
        !in.boolean(entry.have_last) ||
        (entry.have_first && !in.frame(entry.first_fragment)) ||
        !count(in, size, packet::Ipv4ReassemblyTable::maximum_payload_octets))
      return false;
    entry.payload.resize(size);
    if (!in.octets(entry.payload) ||
        !count(in, size,
               (packet::Ipv4ReassemblyTable::maximum_payload_octets + 7U) / 8U))
      return false;
    entry.received.resize(size);
    if (!in.octets(entry.received))
      return false;
  }
  return true;
}

void endpoint_state(Writer &out, const NetworkCheckpointState &state) {
  const auto &endpoint = state.endpoint;
  out.boolean(endpoint.neighbor_valid);
  ipv4(out, endpoint.neighbor_address);
  mac(out, endpoint.neighbor_mac);
  out.boolean(endpoint.pending_next_hop_valid);
  ipv4(out, endpoint.pending_next_hop);
  out.integer(endpoint.next_ipv4_identification);
  out.boolean(endpoint.ipv4_probe_valid);
  ipv4(out, endpoint.ipv4_probe_destination);
  if (endpoint.ipv4_probe_valid)
    out.frame(endpoint.ipv4_probe_packet);
  ipv4_reassembly_entries(out, state.ipv4_reassembly);
  // IPv4 and IPv6 PMTU have different minimums and legacy-report behavior,
  // but both use stable interface keys and relative deadlines on disk.
  count(out, state.ipv4_path_mtu);
  for (const auto &entry : state.ipv4_path_mtu) {
    ipv4(out, entry.destination);
    out.integer(entry.remaining_probe_nanoseconds);
    out.integer(entry.interface_id);
    out.integer(entry.mtu);
    out.integer(entry.probe_mtu);
  }
  count(out, state.frames);
  for (const auto &frame : state.frames)
    network_stored_frame(out, frame);

  const auto lifetime = [&](const host::RelativeIpv6Lifetime &value) {
    out.integer(value.remaining_nanoseconds);
    out.boolean(value.infinite);
  };
  const auto &ipv6_state = state.ipv6;
  const auto &autoconfiguration = ipv6_state.autoconfiguration;
  count(out, autoconfiguration.default_routers);
  for (const auto &entry : autoconfiguration.default_routers) {
    ipv6(out, entry.address);
    lifetime(entry.lifetime);
    out.integer(entry.preference);
  }
  count(out, autoconfiguration.on_link_prefixes);
  for (const auto &entry : autoconfiguration.on_link_prefixes) {
    ipv6(out, entry.prefix.network);
    out.integer(entry.prefix.length);
    lifetime(entry.lifetime);
  }
  count(out, autoconfiguration.addresses);
  for (const auto &entry : autoconfiguration.addresses) {
    ipv6(out, entry.address);
    ipv6(out, entry.prefix.network);
    out.integer(entry.prefix.length);
    lifetime(entry.preferred_lifetime);
    lifetime(entry.valid_lifetime);
    out.integer(entry.state);
    out.integer(entry.dad_counter);
  }
  count(out, autoconfiguration.rdnss);
  for (const auto &entry : autoconfiguration.rdnss) {
    ipv6(out, entry.address);
    lifetime(entry.lifetime);
    out.integer(entry.interface_id);
    out.integer(entry.order);
  }
  out.octets(autoconfiguration.interface_identifier);
  out.octets(autoconfiguration.stable_secret);
  count(out, autoconfiguration.network_id);
  out.octets(autoconfiguration.network_id);
  out.integer(autoconfiguration.interface_id);
  out.integer(autoconfiguration.next_rdnss_order);
  out.integer(autoconfiguration.link_mtu);
  out.integer(autoconfiguration.effective_mtu);
  out.integer(autoconfiguration.current_hop_limit);
  out.integer(autoconfiguration.reachable_time_milliseconds);
  out.integer(autoconfiguration.retrans_timer_milliseconds);
  out.boolean(autoconfiguration.managed_configuration);
  out.boolean(autoconfiguration.other_configuration);
  out.integer(autoconfiguration.interface_identifier_mode);
  count(out, ipv6_state.dad);
  for (const auto &entry : ipv6_state.dad) {
    out.integer(entry.interface_id);
    out.integer(entry.port_ordinal);
    ipv6(out, entry.address);
    out.integer(entry.state);
    out.integer(entry.probes_sent);
    out.integer(entry.transmit_limit);
    out.boolean(entry.has_deadline);
    out.integer(entry.remaining_nanoseconds);
  }
  // Neighbor and Destination caches are separate RFC 4861 repositories. The
  // Neighbor Cache uses stable logical interface scope; the host destination
  // cache retains its single physical attachment coordinate independently.
  count(out, ipv6_state.neighbors);
  for (const auto &entry : ipv6_state.neighbors) {
    out.integer(entry.interface_id);
    ipv6(out, entry.address);
    mac(out, entry.mac);
    out.integer(entry.state);
    out.boolean(entry.is_router);
    out.boolean(entry.is_static);
    out.boolean(entry.has_deadline);
    out.integer(entry.probes_sent);
    out.integer(entry.use_generation);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.stale_time_seconds);
    out.boolean(entry.proactive_refresh);
  }
  count(out, ipv6_state.destinations);
  for (const auto &entry : ipv6_state.destinations) {
    ipv6(out, entry.destination);
    ipv6(out, entry.next_hop);
    ipv6(out, entry.route_first_hop);
    out.integer(entry.port_ordinal);
    out.integer(entry.use_generation);
  }
  // PMTU entries are keyed by the stable interface identity, not the current
  // host slot. Relative probe deadlines preserve the RFC 8201 aging decision
  // without importing a steady-clock epoch from another process.
  count(out, ipv6_state.path_mtu);
  for (const auto &entry : ipv6_state.path_mtu) {
    ipv6(out, entry.destination);
    out.integer(entry.remaining_probe_nanoseconds);
    out.integer(entry.interface_id);
    out.integer(entry.mtu);
    out.integer(entry.probe_mtu);
  }
  // MLD keeps protocol deadlines relative to this checkpoint's single time
  // sample. Source filters and retransmission deltas are distinct because a
  // state-change Report may describe addresses no longer in the live filter.
  const auto &mld = ipv6_state.mld;
  count(out, mld.groups);
  for (const auto &group : mld.groups) {
    ipv6(out, group.multicast_address);
    out.integer(group.source_count);
    for (std::size_t index = 0; index < group.source_count; ++index)
      ipv6(out, group.sources[index]);
    out.integer(group.retransmission_source_count);
    for (std::size_t index = 0; index < group.retransmission_source_count;
         ++index)
      ipv6(out, group.retransmission_sources[index]);
    out.integer(group.response_remaining_nanoseconds);
    out.integer(group.retransmission_remaining_nanoseconds);
    out.integer(group.mode);
    out.integer(group.retransmission_type);
    out.integer(group.retransmissions_remaining);
    out.boolean(group.response_pending);
    out.boolean(group.occupied);
  }
  out.integer(mld.older_querier_remaining_nanoseconds);
  out.integer(mld.random_state);
  out.boolean(mld.version_one_compatibility);
  out.boolean(mld.link_operational);
  out.boolean(mld.link_local_preferred);
  out.integer(ipv6_state.link_local_dad_counter);
  out.integer(ipv6_state.next_fragment_identification);
  out.boolean(ipv6_state.link_local_generation_exhausted);
  out.integer(ipv6_state.router_solicitation_remaining_nanoseconds);
  out.integer(ipv6_state.router_solicitations_sent);
  out.boolean(ipv6_state.router_solicitation_active);
  ipv6_reassembly_entries(out, state.ipv6_reassembly);
  udp_endpoint(out, state.udp);
  ike_udp_service(out, state.ike_udp);
  out.boolean(state.tcp.has_value());
  if (state.tcp) {
    const auto encoded = transport::tcp::checkpoint::encode(*state.tcp);
    if (!encoded || encoded->size() > std::numeric_limits<std::uint32_t>::max())
      throw std::length_error("TCP endpoint checkpoint cannot be encoded");
    out.integer<std::uint32_t>(static_cast<std::uint32_t>(encoded->size()));
    out.octets(*encoded);
  }
}

bool endpoint_state(Reader &in, NetworkCheckpointState &state) {
  auto &endpoint = state.endpoint;
  if (!in.boolean(endpoint.neighbor_valid) ||
      !ipv4(in, endpoint.neighbor_address) || !mac(in, endpoint.neighbor_mac) ||
      !in.boolean(endpoint.pending_next_hop_valid) ||
      !ipv4(in, endpoint.pending_next_hop) ||
      !in.integer(endpoint.next_ipv4_identification) ||
      !in.boolean(endpoint.ipv4_probe_valid) ||
      !ipv4(in, endpoint.ipv4_probe_destination) ||
      (endpoint.ipv4_probe_valid && !in.frame(endpoint.ipv4_probe_packet)) ||
      !ipv4_reassembly_entries(in, state.ipv4_reassembly))
    return false;
  std::uint32_t size{};
  if (!count(in, size, device_catalog::ipv4_pmtu_entries_per_endpoint))
    return false;
  state.ipv4_path_mtu.resize(size);
  for (auto &entry : state.ipv4_path_mtu)
    if (!ipv4(in, entry.destination) ||
        !in.integer(entry.remaining_probe_nanoseconds) ||
        !in.integer(entry.interface_id) || !in.integer(entry.mtu) ||
        !in.integer(entry.probe_mtu))
      return false;
  if (!count(in, size, maximum_endpoint_pending_ipv4_fragments))
    return false;
  state.frames.resize(size);
  for (auto &frame : state.frames)
    if (!network_stored_frame(in, frame))
      return false;

  const auto lifetime = [&](host::RelativeIpv6Lifetime &value) {
    return in.integer(value.remaining_nanoseconds) &&
           in.boolean(value.infinite);
  };
  auto &ipv6_state = state.ipv6;
  auto &autoconfiguration = ipv6_state.autoconfiguration;
  if (!count(in, size, device_catalog::ipv6_default_routers_per_host_interface))
    return false;
  autoconfiguration.default_routers.resize(size);
  for (auto &entry : autoconfiguration.default_routers)
    if (!ipv6(in, entry.address) || !lifetime(entry.lifetime) ||
        !in.integer(entry.preference) ||
        entry.preference > packet::nd::RouterPreference::high)
      return false;
  if (!count(in, size,
             device_catalog::ipv6_on_link_prefixes_per_host_interface))
    return false;
  autoconfiguration.on_link_prefixes.resize(size);
  for (auto &entry : autoconfiguration.on_link_prefixes)
    if (!ipv6(in, entry.prefix.network) || !in.integer(entry.prefix.length) ||
        !lifetime(entry.lifetime))
      return false;
  if (!count(in, size, device_catalog::ipv6_slaac_addresses_per_host_interface))
    return false;
  autoconfiguration.addresses.resize(size);
  for (auto &entry : autoconfiguration.addresses)
    if (!ipv6(in, entry.address) || !ipv6(in, entry.prefix.network) ||
        !in.integer(entry.prefix.length) ||
        !lifetime(entry.preferred_lifetime) ||
        !lifetime(entry.valid_lifetime) || !in.integer(entry.state) ||
        !in.integer(entry.dad_counter) ||
        entry.state > host::AutoconfigAddressState::deprecated)
      return false;
  if (!count(in, size, device_catalog::ipv6_rdnss_entries_per_host_interface))
    return false;
  autoconfiguration.rdnss.resize(size);
  for (auto &entry : autoconfiguration.rdnss)
    if (!ipv6(in, entry.address) || !lifetime(entry.lifetime) ||
        !in.integer(entry.interface_id) || !in.integer(entry.order))
      return false;
  if (!in.octets(autoconfiguration.interface_identifier) ||
      !in.octets(autoconfiguration.stable_secret) ||
      !count(in, size, device_catalog::ipv6_stable_iid_network_id_octets))
    return false;
  autoconfiguration.network_id.resize(size);
  if (!in.octets(autoconfiguration.network_id) ||
      !in.integer(autoconfiguration.interface_id) ||
      !in.integer(autoconfiguration.next_rdnss_order) ||
      !in.integer(autoconfiguration.link_mtu) ||
      !in.integer(autoconfiguration.effective_mtu) ||
      !in.integer(autoconfiguration.current_hop_limit) ||
      !in.integer(autoconfiguration.reachable_time_milliseconds) ||
      !in.integer(autoconfiguration.retrans_timer_milliseconds) ||
      !in.boolean(autoconfiguration.managed_configuration) ||
      !in.boolean(autoconfiguration.other_configuration) ||
      !in.integer(autoconfiguration.interface_identifier_mode) ||
      autoconfiguration.interface_identifier_mode >
          host::InterfaceIdentifierMode::stable_opaque ||
      !count(in, size, Ipv6DadTable::capacity))
    return false;
  ipv6_state.dad.resize(size);
  for (auto &entry : ipv6_state.dad)
    if (!in.integer(entry.interface_id) || !in.integer(entry.port_ordinal) ||
        !ipv6(in, entry.address) || !in.integer(entry.state) ||
        entry.state > Ipv6DadState::duplicate ||
        !in.integer(entry.probes_sent) || !in.integer(entry.transmit_limit) ||
        !in.boolean(entry.has_deadline) ||
        !in.integer(entry.remaining_nanoseconds))
      return false;
  if (!count(in, size, device_catalog::ipv6_neighbor_entries_per_router))
    return false;
  ipv6_state.neighbors.resize(size);
  for (auto &entry : ipv6_state.neighbors)
    if (!in.integer(entry.interface_id) || !ipv6(in, entry.address) ||
        !mac(in, entry.mac) || !in.integer(entry.state) ||
        entry.state > Ipv6NeighborState::probe ||
        !in.boolean(entry.is_router) || !in.boolean(entry.is_static) ||
        !in.boolean(entry.has_deadline) || !in.integer(entry.probes_sent) ||
        !in.integer(entry.use_generation) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.stale_time_seconds) ||
        !in.boolean(entry.proactive_refresh))
      return false;
  if (!count(in, size, device_catalog::ipv6_destination_entries_per_endpoint))
    return false;
  ipv6_state.destinations.resize(size);
  for (auto &entry : ipv6_state.destinations)
    if (!ipv6(in, entry.destination) || !ipv6(in, entry.next_hop) ||
        !ipv6(in, entry.route_first_hop) || !in.integer(entry.port_ordinal) ||
        !in.integer(entry.use_generation))
      return false;
  if (!count(in, size, device_catalog::ipv6_pmtu_entries_per_endpoint))
    return false;
  ipv6_state.path_mtu.resize(size);
  for (auto &entry : ipv6_state.path_mtu)
    if (!ipv6(in, entry.destination) ||
        !in.integer(entry.remaining_probe_nanoseconds) ||
        !in.integer(entry.interface_id) || !in.integer(entry.mtu) ||
        !in.integer(entry.probe_mtu))
      return false;
  auto &mld = ipv6_state.mld;
  if (!count(in, size, device_catalog::mld_groups_per_interface))
    return false;
  mld.groups.resize(size);
  for (auto &group : mld.groups) {
    if (!ipv6(in, group.multicast_address) || !in.integer(group.source_count) ||
        group.source_count > device_catalog::mld_sources_per_group)
      return false;
    for (std::size_t index = 0; index < group.source_count; ++index)
      if (!ipv6(in, group.sources[index]))
        return false;
    if (!in.integer(group.retransmission_source_count) ||
        group.retransmission_source_count >
            device_catalog::mld_sources_per_group)
      return false;
    for (std::size_t index = 0; index < group.retransmission_source_count;
         ++index)
      if (!ipv6(in, group.retransmission_sources[index]))
        return false;
    if (!in.integer(group.response_remaining_nanoseconds) ||
        !in.integer(group.retransmission_remaining_nanoseconds) ||
        !in.integer(group.mode) || group.mode > MldFilterMode::exclude ||
        !in.integer(group.retransmission_type) ||
        group.retransmission_type >
            packet::mld::RecordType::block_old_sources ||
        !in.integer(group.retransmissions_remaining) ||
        !in.boolean(group.response_pending) || !in.boolean(group.occupied))
      return false;
  }
  if (!in.integer(mld.older_querier_remaining_nanoseconds) ||
      !in.integer(mld.random_state) ||
      !in.boolean(mld.version_one_compatibility) ||
      !in.boolean(mld.link_operational) ||
      !in.boolean(mld.link_local_preferred) ||
      !in.integer(ipv6_state.link_local_dad_counter) ||
      !in.integer(ipv6_state.next_fragment_identification) ||
      !in.boolean(ipv6_state.link_local_generation_exhausted))
    return false;
  if (!in.integer(ipv6_state.router_solicitation_remaining_nanoseconds) ||
      !in.integer(ipv6_state.router_solicitations_sent) ||
      !in.boolean(ipv6_state.router_solicitation_active) ||
      !ipv6_reassembly_entries(in, state.ipv6_reassembly) ||
      !udp_endpoint(in, state.udp) || !ike_udp_service(in, state.ike_udp))
    return false;
  bool tcp_present{};
  if (!in.boolean(tcp_present))
    return false;
  if (!tcp_present) {
    state.tcp.reset();
    return true;
  }
  std::uint32_t tcp_octets{};
  if (!in.integer(tcp_octets))
    return false;
  const auto encoded = in.view(tcp_octets);
  if (!encoded)
    return false;
  state.tcp = transport::tcp::checkpoint::decode(*encoded);
  return state.tcp.has_value();
}

void dhcpv6_pool(Writer &out, const dhcpv6::LeasePool &value) {
  ipv6(out, value.prefix.network);
  out.integer(value.prefix.length);
  out.octets(value.allocation_secret);
  out.octets(value.link_identity);
  out.integer(value.preferred_lifetime_seconds);
  out.integer(value.valid_lifetime_seconds);
  out.integer(value.t1_seconds);
  out.integer(value.t2_seconds);
  out.integer(value.delegated_length);
  out.boolean(value.link_scoped);
}

bool dhcpv6_pool(Reader &in, dhcpv6::LeasePool &value) noexcept {
  return ipv6(in, value.prefix.network) && in.integer(value.prefix.length) &&
         in.octets(value.allocation_secret) &&
         in.octets(value.link_identity) &&
         in.integer(value.preferred_lifetime_seconds) &&
         in.integer(value.valid_lifetime_seconds) &&
         in.integer(value.t1_seconds) && in.integer(value.t2_seconds) &&
         in.integer(value.delegated_length) && in.boolean(value.link_scoped);
}

void dhcpv6_client_configuration(Writer &out,
                                 const dhcpv6::ClientConfiguration &value) {
  out.integer(value.duid_octets);
  out.octets(
      std::span<const std::uint8_t>{value.duid}.first(value.duid_octets));
  out.octets(value.transaction_secret);
  count(out, value.identity_associations);
  for (const auto &association : value.identity_associations) {
    out.integer(association.iaid);
    out.integer(association.kind);
  }
  count(out, value.requested_options);
  for (const auto option : value.requested_options)
    out.integer(option);
  count(out, value.user_class);
  out.octets(value.user_class);
  out.boolean(value.rapid_commit);
}

bool dhcpv6_client_configuration(Reader &in,
                                 dhcpv6::ClientConfiguration &value) {
  std::uint32_t size{};
  if (!in.integer(value.duid_octets) || value.duid_octets > value.duid.size() ||
      !in.octets(
          std::span<std::uint8_t>{value.duid}.first(value.duid_octets)) ||
      !in.octets(value.transaction_secret) ||
      !count(in, size, packet::dhcpv6::maximum_message_octets / 4U))
    return false;
  value.identity_associations.resize(size);
  for (auto &association : value.identity_associations)
    if (!in.integer(association.iaid) || !in.integer(association.kind) ||
        association.kind > dhcpv6::LeaseKind::prefix)
      return false;
  if (!count(in, size, packet::dhcpv6::maximum_message_octets / 2U))
    return false;
  value.requested_options.resize(size);
  for (auto &option : value.requested_options)
    if (!in.integer(option))
      return false;
  if (!count(in, size, packet::dhcpv6::maximum_message_octets - 2U))
    return false;
  value.user_class.resize(size);
  if (!in.octets(value.user_class))
    return false;
  return in.boolean(value.rapid_commit);
}

void dhcpv6_retransmission(Writer &out,
                           const dhcpv6::RetransmissionCheckpoint &value) {
  out.integer(value.next_deadline_remaining_nanoseconds);
  out.integer(value.first_transmission_ago_nanoseconds);
  out.integer(value.previous_timeout_nanoseconds);
  out.integer(value.maximum_retransmission_override_nanoseconds);
  out.integer(value.transaction_id);
  out.integer(value.random_state);
  out.integer(value.transmissions);
  out.integer(value.kind);
  out.boolean(value.active);
  out.boolean(value.transmitted);
}

bool dhcpv6_retransmission(Reader &in,
                           dhcpv6::RetransmissionCheckpoint &value) noexcept {
  return in.integer(value.next_deadline_remaining_nanoseconds) &&
         in.integer(value.first_transmission_ago_nanoseconds) &&
         in.integer(value.previous_timeout_nanoseconds) &&
         in.integer(value.maximum_retransmission_override_nanoseconds) &&
         in.integer(value.transaction_id) && in.integer(value.random_state) &&
         in.integer(value.transmissions) && in.integer(value.kind) &&
         value.kind <= dhcpv6::ExchangeKind::decline &&
         in.boolean(value.active) && in.boolean(value.transmitted);
}

void dhcpv6_client_lease(Writer &out,
                         const dhcpv6::ClientLeaseCheckpoint &value) {
  ipv6(out, value.value);
  out.integer(value.preferred_remaining_nanoseconds);
  out.integer(value.valid_remaining_nanoseconds);
  out.integer(value.renew_remaining_nanoseconds);
  out.integer(value.rebind_remaining_nanoseconds);
  out.integer(value.iaid);
  out.integer(value.prefix_length);
  out.integer(value.kind);
}

bool dhcpv6_client_lease(Reader &in,
                         dhcpv6::ClientLeaseCheckpoint &value) noexcept {
  return ipv6(in, value.value) &&
         in.integer(value.preferred_remaining_nanoseconds) &&
         in.integer(value.valid_remaining_nanoseconds) &&
         in.integer(value.renew_remaining_nanoseconds) &&
         in.integer(value.rebind_remaining_nanoseconds) &&
         in.integer(value.iaid) && in.integer(value.prefix_length) &&
         in.integer(value.kind) && value.kind <= dhcpv6::LeaseKind::prefix;
}

void dhcpv6_client_leases(
    Writer &out, const std::vector<dhcpv6::ClientLeaseCheckpoint> &values) {
  count(out, values);
  for (const auto &value : values)
    dhcpv6_client_lease(out, value);
}

bool dhcpv6_client_leases(Reader &in,
                          std::vector<dhcpv6::ClientLeaseCheckpoint> &values) {
  std::uint32_t size{};
  if (!count(in, size, packet::dhcpv6::maximum_message_octets / 4U))
    return false;
  values.resize(size);
  for (auto &value : values)
    if (!dhcpv6_client_lease(in, value))
      return false;
  return true;
}

void dhcpv6_client_checkpoint(Writer &out,
                              const dhcpv6::ClientCheckpoint &value) {
  dhcpv6_client_configuration(out, value.configuration);
  dhcpv6_retransmission(out, value.retransmission);
  out.integer(value.offer.server_octets);
  out.octets(std::span<const std::uint8_t>{value.offer.server}.first(
      value.offer.server_octets));
  out.integer(value.offer.preference);
  dhcpv6_client_leases(out, value.offer.leases);
  out.boolean(value.offer.present);
  dhcpv6_client_leases(out, value.leases);
  dhcpv6_client_leases(out, value.operation_leases);
  count(out, value.dns_servers);
  for (const auto &address : value.dns_servers)
    ipv6(out, address);
  out.integer(value.server_octets);
  out.octets(
      std::span<const std::uint8_t>{value.server}.first(value.server_octets));
  out.integer(value.random_state);
  out.integer(value.transaction_counter);
  out.integer(value.solicit_maximum_retransmission_seconds);
  out.integer(value.information_maximum_retransmission_seconds);
  out.integer(value.advertise_solicit_maximum_seconds);
  out.integer(value.advertise_information_maximum_seconds);
  out.integer(value.rate_limit_tokens_scaled);
  out.integer(value.information_refresh_remaining_nanoseconds);
  out.integer(value.state);
  out.boolean(value.confirm_not_on_link_received);
  out.boolean(value.rate_limit_initialized);
  out.boolean(value.advertise_solicit_maximum_seen);
  out.boolean(value.advertise_solicit_maximum_conflict);
  out.boolean(value.advertise_information_maximum_seen);
  out.boolean(value.advertise_information_maximum_conflict);
}

bool dhcpv6_client_checkpoint(Reader &in, dhcpv6::ClientCheckpoint &value) {
  std::uint32_t size{};
  if (!dhcpv6_client_configuration(in, value.configuration) ||
      !dhcpv6_retransmission(in, value.retransmission) ||
      !in.integer(value.offer.server_octets) ||
      value.offer.server_octets > value.offer.server.size() ||
      !in.octets(std::span<std::uint8_t>{value.offer.server}.first(
          value.offer.server_octets)) ||
      !in.integer(value.offer.preference) ||
      !dhcpv6_client_leases(in, value.offer.leases) ||
      !in.boolean(value.offer.present) ||
      !dhcpv6_client_leases(in, value.leases) ||
      !dhcpv6_client_leases(in, value.operation_leases) ||
      !count(in, size, packet::dhcpv6::maximum_message_octets / 16U))
    return false;
  value.dns_servers.resize(size);
  for (auto &address : value.dns_servers)
    if (!ipv6(in, address))
      return false;
  return in.integer(value.server_octets) &&
         value.server_octets <= value.server.size() &&
         in.octets(std::span<std::uint8_t>{value.server}.first(
             value.server_octets)) &&
         in.integer(value.random_state) &&
         in.integer(value.transaction_counter) &&
         in.integer(value.solicit_maximum_retransmission_seconds) &&
         in.integer(value.information_maximum_retransmission_seconds) &&
         in.integer(value.advertise_solicit_maximum_seconds) &&
         in.integer(value.advertise_information_maximum_seconds) &&
         in.integer(value.rate_limit_tokens_scaled) &&
         in.integer(value.information_refresh_remaining_nanoseconds) &&
         in.integer(value.state) &&
         value.state <= dhcpv6::ClientState::failed &&
         in.boolean(value.confirm_not_on_link_received) &&
         in.boolean(value.rate_limit_initialized) &&
         in.boolean(value.advertise_solicit_maximum_seen) &&
         in.boolean(value.advertise_solicit_maximum_conflict) &&
         in.boolean(value.advertise_information_maximum_seen) &&
         in.boolean(value.advertise_information_maximum_conflict);
}

void dhcpv6_server_configuration(Writer &out,
                                 const dhcpv6::ServerConfiguration &value) {
  out.integer(value.duid_octets);
  out.octets(
      std::span<const std::uint8_t>{value.duid}.first(value.duid_octets));
  out.integer(value.preference);
  out.integer(value.address_pool_index);
  out.integer(value.prefix_pool_index);
  out.integer(value.information_refresh_time_seconds);
  out.boolean(value.rapid_commit);
  out.boolean(value.lease_query);
  count(out, value.dns_recursive_servers);
  for (const auto &address : value.dns_recursive_servers)
    ipv6(out, address);
  out.boolean(value.solicit_maximum_retransmission_seconds.has_value());
  if (value.solicit_maximum_retransmission_seconds)
    out.integer(*value.solicit_maximum_retransmission_seconds);
  out.boolean(value.information_maximum_retransmission_seconds.has_value());
  if (value.information_maximum_retransmission_seconds)
    out.integer(*value.information_maximum_retransmission_seconds);
}

bool dhcpv6_server_configuration(Reader &in,
                                 dhcpv6::ServerConfiguration &value) {
  std::uint32_t size{};
  bool present{};
  if (!in.integer(value.duid_octets) || value.duid_octets > value.duid.size() ||
      !in.octets(
          std::span<std::uint8_t>{value.duid}.first(value.duid_octets)) ||
      !in.integer(value.preference) || !in.integer(value.address_pool_index) ||
      !in.integer(value.prefix_pool_index) ||
      !in.integer(value.information_refresh_time_seconds) ||
      !in.boolean(value.rapid_commit) ||
      !in.boolean(value.lease_query) ||
      !count(in, size, packet::dhcpv6::maximum_message_octets / 16U))
    return false;
  value.dns_recursive_servers.resize(size);
  for (auto &address : value.dns_recursive_servers)
    if (!ipv6(in, address))
      return false;
  if (!in.boolean(present))
    return false;
  if (present) {
    std::uint32_t seconds{};
    if (!in.integer(seconds))
      return false;
    value.solicit_maximum_retransmission_seconds = seconds;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    std::uint32_t seconds{};
    if (!in.integer(seconds))
      return false;
    value.information_maximum_retransmission_seconds = seconds;
  }
  return true;
}

void dhcpv6_server_checkpoint(Writer &out,
                              const dhcpv6::ServerCheckpoint &value) {
  dhcpv6_server_configuration(out, value.configuration);
  for (const auto *pools : {&value.address_pools, &value.prefix_pools}) {
    count(out, *pools);
    for (const auto &pool : *pools)
      dhcpv6_pool(out, pool);
  }
  count(out, value.leases);
  for (const auto &lease : value.leases) {
    out.integer(lease.client.duid_octets);
    out.octets(std::span<const std::uint8_t>{lease.client.duid}.first(
        lease.client.duid_octets));
    out.octets(lease.client.link_identity);
    out.integer(lease.client.iaid);
    out.integer(lease.client.kind);
    ipv6(out, lease.value);
    ipv6(out, lease.last_client_address);
    out.integer(lease.preferred_remaining_nanoseconds);
    out.integer(lease.valid_remaining_nanoseconds);
    out.integer(lease.declined_remaining_nanoseconds);
    out.integer(lease.last_client_transaction_ago_nanoseconds);
    out.integer(lease.pool_index);
    out.integer(lease.prefix_length);
    out.boolean(lease.declined);
  }
  count(out, value.failover_bindings);
  for (const auto &binding : value.failover_bindings) {
    ipv6(out, binding.value);
    out.integer(binding.association);
    out.integer(binding.status);
    out.integer(binding.state_started_absolute);
    out.integer(binding.prefix_length);
    out.boolean(binding.occupied);
  }
  // Message counters are part of operational continuity. Restoring a
  // checkpoint must not make the server appear freshly started while its
  // leases and transaction history remain live.
  out.integer(value.statistics.rx_solicit);
  out.integer(value.statistics.rx_request);
  out.integer(value.statistics.rx_confirm);
  out.integer(value.statistics.rx_renew);
  out.integer(value.statistics.rx_rebind);
  out.integer(value.statistics.rx_release);
  out.integer(value.statistics.rx_decline);
  out.integer(value.statistics.rx_information_request);
  out.integer(value.statistics.rx_relay_forward);
  out.integer(value.statistics.rx_leasequery);
  out.integer(value.statistics.tx_advertise);
  out.integer(value.statistics.tx_reply);
  out.integer(value.statistics.tx_reconfigure);
  out.integer(value.statistics.tx_relay_reply);
  out.integer(value.statistics.tx_leasequery_reply);
  out.integer(value.statistics.dropped_bad_packet);
  out.integer(value.statistics.dropped_not_allowed);
  out.integer(value.statistics.dropped_resource_exhausted);
  out.integer(value.decline_hold_seconds);
  out.boolean(value.configured);
}

bool dhcpv6_server_checkpoint(Reader &in, dhcpv6::ServerCheckpoint &value) {
  if (!dhcpv6_server_configuration(in, value.configuration))
    return false;
  std::uint32_t size{};
  // Address and delegated-prefix pools are independently generated resources.
  // Reading both with the address ceiling would make a future profile change
  // either reject valid prefix state or admit more prefix pools than the
  // server owner can represent.
  if (!count(in, size, device_catalog::dhcpv6_address_pools_per_server))
    return false;
  value.address_pools.resize(size);
  for (auto &pool : value.address_pools)
    if (!dhcpv6_pool(in, pool))
      return false;
  if (!count(in, size, device_catalog::dhcpv6_prefix_pools_per_server))
    return false;
  value.prefix_pools.resize(size);
  for (auto &pool : value.prefix_pools)
    if (!dhcpv6_pool(in, pool))
      return false;
  if (!count(in, size, device_catalog::dhcpv6_leases_per_server))
    return false;
  value.leases.resize(size);
  for (auto &lease : value.leases)
    if (!in.integer(lease.client.duid_octets) ||
        lease.client.duid_octets > lease.client.duid.size() ||
        !in.octets(std::span<std::uint8_t>{lease.client.duid}.first(
            lease.client.duid_octets)) ||
        !in.octets(lease.client.link_identity) ||
        !in.integer(lease.client.iaid) || !in.integer(lease.client.kind) ||
        lease.client.kind > dhcpv6::LeaseKind::prefix ||
        !ipv6(in, lease.value) || !ipv6(in, lease.last_client_address) ||
        !in.integer(lease.preferred_remaining_nanoseconds) ||
        !in.integer(lease.valid_remaining_nanoseconds) ||
        !in.integer(lease.declined_remaining_nanoseconds) ||
        !in.integer(lease.last_client_transaction_ago_nanoseconds) ||
        !in.integer(lease.pool_index) || !in.integer(lease.prefix_length) ||
        !in.boolean(lease.declined))
      return false;
  if (!count(in, size, device_catalog::dhcpv6_leases_per_server))
    return false;
  value.failover_bindings.resize(size);
  for (auto &binding : value.failover_bindings)
    if (!ipv6(in, binding.value) ||
        !in.integer(binding.association) ||
        binding.association >
            dhcpv6::failover::IdentityAssociationType::unassociated_prefix ||
        !in.integer(binding.status) ||
        binding.status > dhcpv6::failover::BindingStatus::reset ||
        !in.integer(binding.state_started_absolute) ||
        !in.integer(binding.prefix_length) ||
        !in.boolean(binding.occupied))
      return false;
  return in.integer(value.statistics.rx_solicit) &&
         in.integer(value.statistics.rx_request) &&
         in.integer(value.statistics.rx_confirm) &&
         in.integer(value.statistics.rx_renew) &&
         in.integer(value.statistics.rx_rebind) &&
         in.integer(value.statistics.rx_release) &&
         in.integer(value.statistics.rx_decline) &&
         in.integer(value.statistics.rx_information_request) &&
         in.integer(value.statistics.rx_relay_forward) &&
         in.integer(value.statistics.rx_leasequery) &&
         in.integer(value.statistics.tx_advertise) &&
         in.integer(value.statistics.tx_reply) &&
         in.integer(value.statistics.tx_reconfigure) &&
         in.integer(value.statistics.tx_relay_reply) &&
         in.integer(value.statistics.tx_leasequery_reply) &&
         in.integer(value.statistics.dropped_bad_packet) &&
         in.integer(value.statistics.dropped_not_allowed) &&
         in.integer(value.statistics.dropped_resource_exhausted) &&
         in.integer(value.decline_hold_seconds) &&
         in.boolean(value.configured);
}

void dhcpv4_scope(Writer &out, const dhcpv4::AllocationScope &value) {
  out.integer(value.server_instance);
  out.integer(value.routing_context);
  out.integer(value.link_identity);
}

bool dhcpv4_scope(Reader &in, dhcpv4::AllocationScope &value) {
  return in.integer(value.server_instance) &&
         in.integer(value.routing_context) &&
         in.integer(value.link_identity);
}

void dhcpv4_client_key(Writer &out, const dhcpv4::ClientKey &value) {
  out.integer(value.octets);
  out.octets(std::span<const std::uint8_t>{value.bytes}.first(value.octets));
  out.boolean(value.option_61);
}

bool dhcpv4_client_key(Reader &in, dhcpv4::ClientKey &value) {
  return in.integer(value.octets) && value.octets != 0U &&
         value.octets <= value.bytes.size() &&
         in.octets(std::span<std::uint8_t>{value.bytes}.first(value.octets)) &&
         in.boolean(value.option_61);
}

void dhcpv4_pool(Writer &out, const dhcpv4::Pool &value) {
  out.integer(value.id);
  dhcpv4_scope(out, value.scope);
  ipv4(out, value.first);
  ipv4(out, value.last);
  ipv4(out, value.subnet_mask);
  ipv4(out, value.router);
  out.integer(value.lease_seconds);
  out.integer(value.minimum_lease_seconds);
  out.integer(value.maximum_lease_seconds);
  out.integer(value.offer_seconds);
  out.integer(value.maximum_declined);
  out.integer(value.renewal_seconds);
  out.integer(value.rebinding_seconds);
  out.boolean(value.enabled);
}

bool dhcpv4_pool(Reader &in, dhcpv4::Pool &value) {
  return in.integer(value.id) && dhcpv4_scope(in, value.scope) &&
         ipv4(in, value.first) && ipv4(in, value.last) &&
         ipv4(in, value.subnet_mask) && ipv4(in, value.router) &&
         in.integer(value.lease_seconds) &&
         in.integer(value.minimum_lease_seconds) &&
         in.integer(value.maximum_lease_seconds) &&
         in.integer(value.offer_seconds) &&
         in.integer(value.maximum_declined) &&
         in.integer(value.renewal_seconds) &&
         in.integer(value.rebinding_seconds) && in.boolean(value.enabled);
}

void dhcpv4_reservation(Writer &out,
                        const dhcpv4::Reservation &value) {
  dhcpv4_scope(out, value.scope);
  dhcpv4_client_key(out, value.client);
  ipv4(out, value.address);
}

bool dhcpv4_reservation(Reader &in, dhcpv4::Reservation &value) {
  return dhcpv4_scope(in, value.scope) &&
         dhcpv4_client_key(in, value.client) && ipv4(in, value.address);
}

void dhcpv4_repository(Writer &out,
                       const dhcpv4::LeaseRepositoryCheckpoint &value) {
  count(out, value.pools);
  for (const auto &pool : value.pools)
    dhcpv4_pool(out, pool);
  count(out, value.reservations);
  for (const auto &reservation : value.reservations)
    dhcpv4_reservation(out, reservation);
  count(out, value.exclusions);
  for (const auto &excluded : value.exclusions) {
    dhcpv4_scope(out, excluded.scope);
    ipv4(out, excluded.first);
    ipv4(out, excluded.last);
  }
  count(out, value.leases);
  for (const auto &lease : value.leases) {
    dhcpv4_scope(out, lease.scope);
    dhcpv4_client_key(out, lease.client);
    out.octets(lease.hardware.address);
    out.integer(lease.hardware.type);
    out.integer(lease.hardware.length);
    out.octets(lease.relay_agent_information);
    out.integer(lease.relay_agent_information_octets);
    ipv4(out, lease.address);
    out.integer(lease.transaction_id);
    out.integer(lease.offer_remaining_nanoseconds);
    out.integer(lease.active_remaining_nanoseconds);
    out.integer(lease.last_client_transaction_elapsed_nanoseconds);
    out.integer(lease.last_state_change_elapsed_nanoseconds);
    out.integer(lease.lease_seconds);
    out.integer(lease.decline_sequence);
    out.integer(lease.revision);
    out.integer(lease.failover_state_started_absolute);
    out.integer(lease.failover_partner_expiration_absolute);
    out.integer(lease.failover_status);
    out.integer(lease.state);
    out.boolean(lease.sticky);
    out.boolean(lease.failover_managed);
  }
  out.integer(value.offer_hold_nanoseconds);
  out.integer(value.decline_hold_nanoseconds);
  out.integer(value.next_decline_sequence);
  out.integer(value.next_revision);
}

bool dhcpv4_repository(Reader &in,
                       dhcpv4::LeaseRepositoryCheckpoint &value) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::dhcpv4_pools_per_server))
    return false;
  value.pools.resize(size);
  for (auto &pool : value.pools)
    if (!dhcpv4_pool(in, pool))
      return false;
  if (!count(in, size, device_catalog::dhcpv4_leases_per_server))
    return false;
  value.reservations.resize(size);
  for (auto &reservation : value.reservations)
    if (!dhcpv4_reservation(in, reservation))
      return false;
  if (!count(in, size, device_catalog::dhcpv4_leases_per_server))
    return false;
  value.exclusions.resize(size);
  for (auto &excluded : value.exclusions)
    if (!dhcpv4_scope(in, excluded.scope) ||
        !ipv4(in, excluded.first) || !ipv4(in, excluded.last))
      return false;
  if (!count(in, size, device_catalog::dhcpv4_leases_per_server))
    return false;
  value.leases.resize(size);
  for (auto &lease : value.leases)
    if (!dhcpv4_scope(in, lease.scope) ||
        !dhcpv4_client_key(in, lease.client) ||
        !in.octets(lease.hardware.address) ||
        !in.integer(lease.hardware.type) ||
        !in.integer(lease.hardware.length) ||
        !in.octets(lease.relay_agent_information) ||
        !in.integer(lease.relay_agent_information_octets) ||
        !ipv4(in, lease.address) || !in.integer(lease.transaction_id) ||
        !in.integer(lease.offer_remaining_nanoseconds) ||
        !in.integer(lease.active_remaining_nanoseconds) ||
        !in.integer(lease.last_client_transaction_elapsed_nanoseconds) ||
        !in.integer(lease.last_state_change_elapsed_nanoseconds) ||
        !in.integer(lease.lease_seconds) ||
        !in.integer(lease.decline_sequence) ||
        !in.integer(lease.revision) ||
        !in.integer(lease.failover_state_started_absolute) ||
        !in.integer(lease.failover_partner_expiration_absolute) ||
        !in.integer(lease.failover_status) ||
        lease.failover_status > dhcpv4::failover::BindingStatus::backup ||
        !in.integer(lease.state) ||
        lease.state > dhcpv4::BindingState::reserved ||
        !in.boolean(lease.sticky) ||
        !in.boolean(lease.failover_managed))
      return false;
  return in.integer(value.offer_hold_nanoseconds) &&
         in.integer(value.decline_hold_nanoseconds) &&
         in.integer(value.next_decline_sequence) &&
         in.integer(value.next_revision);
}

void dhcpv4_client_configuration(
    Writer &out, const dhcpv4::ClientConfiguration &value) {
  mac(out, value.hardware_address);
  count(out, value.client_identifier);
  out.octets(value.client_identifier);
  count(out, value.parameter_request_list);
  out.octets(value.parameter_request_list);
  count(out, value.user_class);
  out.octets(value.user_class);
  out.octets(value.transaction_secret);
  out.integer(value.maximum_message_size);
  out.boolean(value.broadcast);
}

bool dhcpv4_client_configuration(
    Reader &in, dhcpv4::ClientConfiguration &value) {
  std::uint32_t size{};
  if (!mac(in, value.hardware_address) || !count(in, size, 255U))
    return false;
  value.client_identifier.resize(size);
  if (!in.octets(value.client_identifier) || !count(in, size, 255U))
    return false;
  value.parameter_request_list.resize(size);
  if (!in.octets(value.parameter_request_list) || !count(in, size, 254U))
    return false;
  value.user_class.resize(size);
  return in.octets(value.user_class) &&
         in.octets(value.transaction_secret) &&
         in.integer(value.maximum_message_size) &&
         in.boolean(value.broadcast);
}

void dhcpv4_client_lease(Writer &out,
                         const dhcpv4::ClientLeaseCheckpoint &value) {
  ipv4(out, value.address);
  ipv4(out, value.subnet_mask);
  ipv4(out, value.router);
  ipv4(out, value.server_identifier);
  count(out, value.domain_name_servers);
  for (const auto &server : value.domain_name_servers)
    ipv4(out, server);
  out.integer(value.renew_remaining_nanoseconds);
  out.integer(value.rebind_remaining_nanoseconds);
  out.integer(value.valid_remaining_nanoseconds);
}

bool dhcpv4_client_lease(Reader &in,
                         dhcpv4::ClientLeaseCheckpoint &value) {
  std::uint32_t size{};
  if (!ipv4(in, value.address) || !ipv4(in, value.subnet_mask) ||
      !ipv4(in, value.router) || !ipv4(in, value.server_identifier) ||
      !count(in, size,
             packet::dhcpv4::maximum_ipv4_addresses_per_option))
    return false;
  value.domain_name_servers.resize(size);
  for (auto &server : value.domain_name_servers)
    if (!ipv4(in, server))
      return false;
  return in.integer(value.renew_remaining_nanoseconds) &&
         in.integer(value.rebind_remaining_nanoseconds) &&
         in.integer(value.valid_remaining_nanoseconds);
}

void dhcpv4_client_checkpoint(Writer &out,
                              const dhcpv4::ClientCheckpoint &value) {
  dhcpv4_client_configuration(out, value.configuration);
  out.boolean(value.lease.has_value());
  if (value.lease)
    dhcpv4_client_lease(out, *value.lease);
  out.boolean(value.offered.has_value());
  if (value.offered)
    dhcpv4_client_lease(out, *value.offered);
  out.boolean(value.pending.has_value());
  if (value.pending)
    dhcpv4_client_lease(out, *value.pending);
  ipv4(out, value.inform_address);
  out.integer(value.transaction_counter);
  out.integer(value.transaction_id);
  out.integer(value.random_state);
  out.integer(value.attempts);
  out.integer(value.timeout_nanoseconds);
  out.integer(value.next_action_remaining_nanoseconds);
  out.integer(value.exchange_elapsed_nanoseconds);
  out.integer(value.state);
  out.boolean(value.configured);
}

bool dhcpv4_client_checkpoint(Reader &in,
                              dhcpv4::ClientCheckpoint &value) {
  bool present{};
  if (!dhcpv4_client_configuration(in, value.configuration) ||
      !in.boolean(present))
    return false;
  if (present) {
    value.lease.emplace();
    if (!dhcpv4_client_lease(in, *value.lease))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    value.offered.emplace();
    if (!dhcpv4_client_lease(in, *value.offered))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    value.pending.emplace();
    if (!dhcpv4_client_lease(in, *value.pending))
      return false;
  }
  if (!ipv4(in, value.inform_address))
    return false;
  return in.integer(value.transaction_counter) &&
         in.integer(value.transaction_id) &&
         in.integer(value.random_state) && in.integer(value.attempts) &&
         in.integer(value.timeout_nanoseconds) &&
         in.integer(value.next_action_remaining_nanoseconds) &&
         in.integer(value.exchange_elapsed_nanoseconds) &&
         in.integer(value.state) && value.state <= dhcpv4::ClientState::failed &&
         in.boolean(value.configured);
}

void dhcpv4_server_configuration(
    Writer &out, const dhcpv4::ServerConfiguration &value) {
  out.integer(value.server_instance);
  out.integer(value.routing_context);
  ipv4(out, value.server_identifier);
  count(out, value.domain_name_servers);
  for (const auto &server : value.domain_name_servers)
    ipv4(out, server);
  out.integer(value.offer_hold.count());
  out.integer(value.decline_hold.count());
  out.boolean(value.authoritative);
  out.boolean(value.force_renews);
}

bool dhcpv4_server_configuration(
    Reader &in, dhcpv4::ServerConfiguration &value) {
  std::uint32_t size{};
  std::int64_t offer_seconds{};
  std::int64_t decline_seconds{};
  if (!in.integer(value.server_instance) ||
      !in.integer(value.routing_context) ||
      !ipv4(in, value.server_identifier) ||
      !count(in, size,
             packet::dhcpv4::maximum_ipv4_addresses_per_option))
    return false;
  value.domain_name_servers.resize(size);
  for (auto &server : value.domain_name_servers)
    if (!ipv4(in, server))
      return false;
  if (!in.integer(offer_seconds) || !in.integer(decline_seconds) ||
      offer_seconds <= 0 || decline_seconds <= 0 ||
      !in.boolean(value.authoritative) ||
      !in.boolean(value.force_renews))
    return false;
  value.offer_hold = std::chrono::seconds{offer_seconds};
  value.decline_hold = std::chrono::seconds{decline_seconds};
  return true;
}

void dhcpv4_server_checkpoint(Writer &out,
                              const dhcpv4::ServerCheckpoint &value) {
  dhcpv4_server_configuration(out, value.configuration);
  dhcpv4_repository(out, value.leases);
  out.integer(value.statistics.rx_discover);
  out.integer(value.statistics.rx_request);
  out.integer(value.statistics.rx_release);
  out.integer(value.statistics.rx_decline);
  out.integer(value.statistics.rx_inform);
  out.integer(value.statistics.rx_lease_query);
  out.integer(value.statistics.tx_offer);
  out.integer(value.statistics.tx_acknowledgement);
  out.integer(value.statistics.tx_negative_acknowledgement);
  out.integer(value.statistics.tx_force_renew);
  out.integer(value.statistics.tx_lease_active);
  out.integer(value.statistics.tx_lease_unassigned);
  out.integer(value.statistics.tx_lease_unknown);
  out.integer(value.statistics.dropped_bad_packet);
  out.integer(value.statistics.dropped_unknown_scope);
  out.integer(value.statistics.dropped_address_unavailable);
  out.integer(value.statistics.dropped_resource_exhausted);
  out.boolean(value.configured);
}

bool dhcpv4_server_checkpoint(Reader &in,
                              dhcpv4::ServerCheckpoint &value) {
  return dhcpv4_server_configuration(in, value.configuration) &&
         dhcpv4_repository(in, value.leases) &&
         in.integer(value.statistics.rx_discover) &&
         in.integer(value.statistics.rx_request) &&
         in.integer(value.statistics.rx_release) &&
         in.integer(value.statistics.rx_decline) &&
         in.integer(value.statistics.rx_inform) &&
         in.integer(value.statistics.rx_lease_query) &&
         in.integer(value.statistics.tx_offer) &&
         in.integer(value.statistics.tx_acknowledgement) &&
         in.integer(value.statistics.tx_negative_acknowledgement) &&
         in.integer(value.statistics.tx_force_renew) &&
         in.integer(value.statistics.tx_lease_active) &&
         in.integer(value.statistics.tx_lease_unassigned) &&
         in.integer(value.statistics.tx_lease_unknown) &&
         in.integer(value.statistics.dropped_bad_packet) &&
         in.integer(value.statistics.dropped_unknown_scope) &&
         in.integer(value.statistics.dropped_address_unavailable) &&
         in.integer(value.statistics.dropped_resource_exhausted) &&
         in.boolean(value.configured);
}

void dhcpv4_pending(Writer &out,
                    const HostDhcpv4PendingCheckpoint &value) {
  ipv4(out, value.destination);
  mac(out, value.destination_mac);
  out.integer(value.destination_port);
  out.integer(value.delivery);
  out.boolean(value.active);
  count(out, value.payload);
  out.octets(value.payload);
}

bool dhcpv4_pending(Reader &in,
                    HostDhcpv4PendingCheckpoint &value) {
  std::uint32_t size{};
  if (!ipv4(in, value.destination) || !mac(in, value.destination_mac) ||
      !in.integer(value.destination_port) || !in.integer(value.delivery) ||
      !in.boolean(value.active) ||
      !count(in, size, packet::dhcpv4::maximum_message_octets))
    return false;
  value.payload.resize(size);
  return in.octets(value.payload);
}

void dhcpv4_service(Writer &out,
                    const HostDhcpv4ServiceCheckpoint &value) {
  out.boolean(value.client.has_value());
  if (value.client)
    dhcpv4_client_checkpoint(out, *value.client);
  out.boolean(value.server.has_value());
  if (value.server)
    dhcpv4_server_checkpoint(out, *value.server);
  for (const auto &socket : {value.client_socket, value.server_socket}) {
    out.boolean(socket.has_value());
    if (socket) {
      out.integer(socket->index);
      out.integer(socket->generation);
    }
  }
  dhcpv4_pending(out, value.client_pending);
  dhcpv4_pending(out, value.server_pending);
  ipv4(out, value.probe.candidate);
  out.integer(value.probe.next_action_remaining_nanoseconds);
  out.integer(value.probe.probes_sent);
  out.boolean(value.probe.active);
  ipv4(out, value.installed_address);
}

bool dhcpv4_service(Reader &in,
                    HostDhcpv4ServiceCheckpoint &value) {
  bool present{};
  if (!in.boolean(present))
    return false;
  if (present) {
    value.client.emplace();
    if (!dhcpv4_client_checkpoint(in, *value.client))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    value.server.emplace();
    if (!dhcpv4_server_checkpoint(in, *value.server))
      return false;
  }
  for (auto *socket : {&value.client_socket, &value.server_socket}) {
    if (!in.boolean(present))
      return false;
    if (present) {
      transport::UdpSocketHandle handle{};
      if (!in.integer(handle.index) || !in.integer(handle.generation))
        return false;
      *socket = handle;
    }
  }
  return dhcpv4_pending(in, value.client_pending) &&
         dhcpv4_pending(in, value.server_pending) &&
         ipv4(in, value.probe.candidate) &&
         in.integer(value.probe.next_action_remaining_nanoseconds) &&
         in.integer(value.probe.probes_sent) &&
         in.boolean(value.probe.active) &&
         ipv4(in, value.installed_address);
}

void dhcpv6_pending(Writer &out, const HostDhcpv6PendingCheckpoint &value) {
  ipv6(out, value.destination);
  out.integer(value.destination_port);
  out.boolean(value.active);
  count(out, value.payload);
  out.octets(value.payload);
}

bool dhcpv6_pending(Reader &in, HostDhcpv6PendingCheckpoint &value) {
  std::uint32_t size{};
  if (!ipv6(in, value.destination) || !in.integer(value.destination_port) ||
      !in.boolean(value.active) ||
      !count(in, size, packet::dhcpv6::maximum_message_octets))
    return false;
  value.payload.resize(size);
  return in.octets(value.payload);
}

void dhcpv6_service(Writer &out, const HostDhcpv6ServiceCheckpoint &value) {
  out.boolean(value.client.has_value());
  if (value.client)
    dhcpv6_client_checkpoint(out, *value.client);
  out.boolean(value.server.has_value());
  if (value.server)
    dhcpv6_server_checkpoint(out, *value.server);
  for (const auto &socket : {value.client_socket, value.server_socket}) {
    out.boolean(socket.has_value());
    if (socket) {
      out.integer(socket->index);
      out.integer(socket->generation);
    }
  }
  dhcpv6_pending(out, value.client_pending);
  dhcpv6_pending(out, value.server_pending);
}

bool dhcpv6_service(Reader &in, HostDhcpv6ServiceCheckpoint &value) {
  bool present{};
  if (!in.boolean(present))
    return false;
  if (present) {
    value.client.emplace();
    if (!dhcpv6_client_checkpoint(in, *value.client))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    value.server.emplace();
    if (!dhcpv6_server_checkpoint(in, *value.server))
      return false;
  }
  for (auto *socket : {&value.client_socket, &value.server_socket}) {
    if (!in.boolean(present))
      return false;
    if (present) {
      transport::UdpSocketHandle handle{};
      if (!in.integer(handle.index) || !in.integer(handle.generation))
        return false;
      *socket = handle;
    }
  }
  return dhcpv6_pending(in, value.client_pending) &&
         dhcpv6_pending(in, value.server_pending);
}

// DNS vectors have no product record-count ceiling. Decode admission is tied
// to the maximum checkpoint image instead, while each wire RDATA keeps the
// protocol's unsigned 16-bit RDLENGTH boundary.
inline constexpr std::size_t maximum_dns_checkpoint_entries =
    maximum_checkpoint_bytes / 16U;

void dns_name(Writer &out, const packet::dns::Name &value) {
  out.integer(value.octets);
  out.octets(value.view());
}

bool dns_name(Reader &in, packet::dns::Name &value) {
  if (!in.integer(value.octets) || value.octets == 0U ||
      value.octets > value.wire.size() ||
      !in.octets(std::span<std::uint8_t>{value.wire}.first(value.octets)))
    return false;
  packet::dns::Name parsed;
  const auto consumed = packet::dns::parse_name(value.view(), 0U, parsed);
  return consumed && *consumed == value.octets;
}

void dns_optional_name(Writer &out, const packet::dns::Name &value) {
  out.boolean(value.octets != 0U);
  if (value.octets != 0U)
    dns_name(out, value);
}

bool dns_optional_name(Reader &in, packet::dns::Name &value) {
  bool present{};
  if (!in.boolean(present))
    return false;
  if (!present) {
    value = {};
    return true;
  }
  return dns_name(in, value);
}

void dns_question(Writer &out, const packet::dns::Question &value) {
  dns_name(out, value.name);
  out.integer(value.type);
  out.integer(value.record_class);
}

bool dns_question(Reader &in, packet::dns::Question &value) {
  return dns_name(in, value.name) && in.integer(value.type) &&
         in.integer(value.record_class);
}

void dns_zone_record(Writer &out, const dns::ZoneRecord &value) {
  dns_name(out, value.owner);
  out.integer(value.type);
  out.integer(value.record_class);
  out.integer(value.ttl);
  count(out, value.rdata);
  out.octets(value.rdata);
}

bool dns_zone_record(Reader &in, dns::ZoneRecord &value) {
  std::uint32_t size{};
  if (!dns_name(in, value.owner) || !in.integer(value.type) ||
      !in.integer(value.record_class) || !in.integer(value.ttl) ||
      !count(in, size, std::numeric_limits<std::uint16_t>::max()))
    return false;
  value.rdata.resize(size);
  return in.octets(value.rdata);
}

void dns_server(Writer &out, const dns::ServerAddress &value) {
  out.integer(value.family);
  ipv4(out, value.ipv4);
  ipv6(out, value.ipv6);
  out.integer(value.interface_id);
}

bool dns_server(Reader &in, dns::ServerAddress &value) {
  return in.integer(value.family) &&
         value.family <= transport::IpFamily::ipv6 && ipv4(in, value.ipv4) &&
         ipv6(in, value.ipv6) && in.integer(value.interface_id);
}

void dns_root_hint(Writer &out, const dns::RootHint &value) {
  dns_name(out, value.server_name);
  count(out, value.addresses);
  for (const auto &address : value.addresses)
    dns_server(out, address);
}

bool dns_root_hint(Reader &in, dns::RootHint &value) {
  std::uint32_t size{};
  if (!dns_name(in, value.server_name) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.addresses.resize(size);
  return std::all_of(value.addresses.begin(), value.addresses.end(),
                     [&](auto &address) { return dns_server(in, address); });
}

void dns_cache_record(Writer &out, const dns::CacheRecordCheckpoint &value) {
  dns_name(out, value.owner);
  count(out, value.rdata);
  out.octets(value.rdata);
  out.integer(value.remaining_nanoseconds);
  out.integer(value.use_generation);
  out.integer(value.type);
  out.integer(value.record_class);
  out.integer(value.original_ttl);
  out.integer(value.security);
}

bool dns_cache_record(Reader &in, dns::CacheRecordCheckpoint &value) {
  std::uint32_t size{};
  if (!dns_name(in, value.owner) ||
      !count(in, size, std::numeric_limits<std::uint16_t>::max()))
    return false;
  value.rdata.resize(size);
  return in.octets(value.rdata) && in.integer(value.remaining_nanoseconds) &&
         in.integer(value.use_generation) && in.integer(value.type) &&
         in.integer(value.record_class) && in.integer(value.original_ttl) &&
         in.integer(value.security) &&
         value.security <= dns::CacheSecurity::secure;
}

void dns_cache(Writer &out, const dns::CacheCheckpoint &value) {
  count(out, value.records);
  for (const auto &record : value.records)
    dns_cache_record(out, record);
  count(out, value.negative);
  for (const auto &negative : value.negative) {
    dns_name(out, negative.name);
    dns_cache_record(out, negative.soa);
    out.integer(negative.remaining_nanoseconds);
    out.integer(negative.use_generation);
    out.integer(negative.type);
    out.integer(negative.record_class);
    out.integer(negative.kind);
    out.integer(negative.security);
  }
  out.integer(value.next_use_generation);
  out.integer(value.capacity_bytes);
}

bool dns_cache(Reader &in, dns::CacheCheckpoint &value) {
  std::uint32_t size{};
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.records.resize(size);
  for (auto &record : value.records)
    if (!dns_cache_record(in, record))
      return false;
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.negative.resize(size);
  for (auto &negative : value.negative)
    if (!dns_name(in, negative.name) || !dns_cache_record(in, negative.soa) ||
        !in.integer(negative.remaining_nanoseconds) ||
        !in.integer(negative.use_generation) || !in.integer(negative.type) ||
        !in.integer(negative.record_class) || !in.integer(negative.kind) ||
        !in.integer(negative.security) ||
        negative.kind > dns::NegativeKind::no_data ||
        negative.security > dns::CacheSecurity::secure)
      return false;
  return in.integer(value.next_use_generation) &&
         in.integer(value.capacity_bytes);
}

void dns_name_vector(Writer &out,
                     const std::vector<packet::dns::Name> &values) {
  count(out, values);
  for (const auto &value : values)
    dns_name(out, value);
}

bool dns_name_vector(Reader &in, std::vector<packet::dns::Name> &values) {
  std::uint32_t size{};
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  values.resize(size);
  return std::all_of(values.begin(), values.end(),
                     [&](auto &value) { return dns_name(in, value); });
}

void dns_server_vector(Writer &out,
                       const std::vector<dns::ServerAddress> &values) {
  count(out, values);
  for (const auto &value : values)
    dns_server(out, value);
}

bool dns_server_vector(Reader &in, std::vector<dns::ServerAddress> &values) {
  std::uint32_t size{};
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  values.resize(size);
  return std::all_of(values.begin(), values.end(),
                     [&](auto &value) { return dns_server(in, value); });
}

void dns_zone_record_vector(Writer &out,
                            const std::vector<dns::ZoneRecord> &values) {
  count(out, values);
  for (const auto &value : values)
    dns_zone_record(out, value);
}

bool dns_zone_record_vector(Reader &in, std::vector<dns::ZoneRecord> &values) {
  std::uint32_t size{};
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  values.resize(size);
  return std::all_of(values.begin(), values.end(),
                     [&](auto &value) { return dns_zone_record(in, value); });
}

void dns_resolution(Writer &out, const dns::ResolutionResult &value) {
  dns_question(out, value.original_question);
  dns_zone_record_vector(out, value.answers);
  dns_zone_record_vector(out, value.authorities);
  out.integer(value.status);
  out.integer(value.security);
}

bool dns_resolution(Reader &in, dns::ResolutionResult &value) {
  return dns_question(in, value.original_question) &&
         dns_zone_record_vector(in, value.answers) &&
         dns_zone_record_vector(in, value.authorities) &&
         in.integer(value.status) &&
         value.status <= dns::ResolutionStatus::resource_exhausted &&
         in.integer(value.security) &&
         value.security <= dns::CacheSecurity::secure;
}

void dns_referral(Writer &out, const dns::ReferralResumeCheckpoint &value) {
  dns_question(out, value.original);
  dns_name_vector(out, value.plan);
  dns_name_vector(out, value.visited_aliases);
  dns_name_vector(out, value.nameservers);
  dns_server_vector(out, value.resolved_addresses);
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.stage));
  out.integer<std::uint32_t>(
      static_cast<std::uint32_t>(value.nameserver_index));
  out.boolean(value.resolving_ipv6);
  dns_optional_name(out, value.current_zone);
  dns_zone_record_vector(out, value.current_dnskeys);
  out.integer(value.current_dnskeys_valid_until);
  dns_optional_name(out, value.pending_zone);
  dns_zone_record_vector(out, value.pending_ds);
  out.integer(value.chain_security);
  out.integer(value.dnssec_phase);
  out.boolean(value.validation_failure_seen);
  out.boolean(value.checking_disabled);
  out.boolean(value.cache_allowed);
}

bool dns_referral(Reader &in, dns::ReferralResumeCheckpoint &value) {
  std::uint32_t stage{};
  std::uint32_t nameserver_index{};
  if (!dns_question(in, value.original) || !dns_name_vector(in, value.plan) ||
      !dns_name_vector(in, value.visited_aliases) ||
      !dns_name_vector(in, value.nameservers) ||
      !dns_server_vector(in, value.resolved_addresses) || !in.integer(stage) ||
      !in.integer(nameserver_index) || !in.boolean(value.resolving_ipv6) ||
      !dns_optional_name(in, value.current_zone) ||
      !dns_zone_record_vector(in, value.current_dnskeys) ||
      !in.integer(value.current_dnskeys_valid_until) ||
      !dns_optional_name(in, value.pending_zone) ||
      !dns_zone_record_vector(in, value.pending_ds) ||
      !in.integer(value.chain_security) ||
      value.chain_security > dns::CacheSecurity::secure ||
      !in.integer(value.dnssec_phase) ||
      value.dnssec_phase > dns::DnssecPhase::child_dnskey ||
      !in.boolean(value.validation_failure_seen) ||
      !in.boolean(value.checking_disabled) || !in.boolean(value.cache_allowed))
    return false;
  value.stage = stage;
  value.nameserver_index = nameserver_index;
  return true;
}

void dns_transaction(Writer &out,
                     const dns::ResolverTransactionCheckpoint &value) {
  dns_question(out, value.original);
  dns_question(out, value.active_question);
  dns_name_vector(out, value.plan);
  dns_server_vector(out, value.servers);
  dns_name_vector(out, value.visited_aliases);
  count(out, value.referral_stack);
  for (const auto &referral : value.referral_stack)
    dns_referral(out, referral);
  dns_resolution(out, value.result);
  out.integer(value.deadline_remaining_nanoseconds);
  dns_server(out, value.active_server);
  out.integer(value.active_transport);
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.stage));
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.server_index));
  out.integer(value.attempts);
  out.integer(value.prepared_token);
  out.integer(value.active_id);
  out.boolean(value.awaiting);
  out.boolean(value.force_tcp);
  // These fields make a checkpoint resume at the same authenticated zone cut
  // instead of silently restarting as an unchecked resolver.
  dns_optional_name(out, value.current_zone);
  dns_zone_record_vector(out, value.current_dnskeys);
  out.integer(value.current_dnskeys_valid_until);
  dns_optional_name(out, value.pending_zone);
  dns_zone_record_vector(out, value.pending_ds);
  out.integer(value.chain_security);
  out.integer(value.dnssec_phase);
  out.boolean(value.validation_failure_seen);
  out.boolean(value.checking_disabled);
  out.boolean(value.cache_allowed);
}

bool dns_transaction(Reader &in, dns::ResolverTransactionCheckpoint &value) {
  std::uint32_t size{};
  std::uint32_t stage{};
  std::uint32_t server_index{};
  if (!dns_question(in, value.original) ||
      !dns_question(in, value.active_question) ||
      !dns_name_vector(in, value.plan) ||
      !dns_server_vector(in, value.servers) ||
      !dns_name_vector(in, value.visited_aliases) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.referral_stack.resize(size);
  for (auto &referral : value.referral_stack)
    if (!dns_referral(in, referral))
      return false;
  if (!dns_resolution(in, value.result) ||
      !in.integer(value.deadline_remaining_nanoseconds) ||
      !dns_server(in, value.active_server) ||
      !in.integer(value.active_transport) ||
      value.active_transport > dns::QueryTransport::tcp || !in.integer(stage) ||
      !in.integer(server_index) || !in.integer(value.attempts) ||
      !in.integer(value.prepared_token) || !in.integer(value.active_id) ||
      !in.boolean(value.awaiting) || !in.boolean(value.force_tcp) ||
      !dns_optional_name(in, value.current_zone) ||
      !dns_zone_record_vector(in, value.current_dnskeys) ||
      !in.integer(value.current_dnskeys_valid_until) ||
      !dns_optional_name(in, value.pending_zone) ||
      !dns_zone_record_vector(in, value.pending_ds) ||
      !in.integer(value.chain_security) ||
      value.chain_security > dns::CacheSecurity::secure ||
      !in.integer(value.dnssec_phase) ||
      value.dnssec_phase > dns::DnssecPhase::child_dnskey ||
      !in.boolean(value.validation_failure_seen) ||
      !in.boolean(value.checking_disabled) || !in.boolean(value.cache_allowed))
    return false;
  value.stage = stage;
  value.server_index = server_index;
  return true;
}

void dns_resolver(Writer &out, const dns::ResolverCheckpoint &value) {
  out.octets(value.identifier_secret);
  count(out, value.root_hints);
  for (const auto &hint : value.root_hints)
    dns_root_hint(out, hint);
  out.integer(value.policy.retry_interval.count());
  out.integer(value.policy.advertised_udp_payload_bytes);
  out.integer(value.policy.attempts_per_server);
  out.integer(value.policy.maximum_minimise_count);
  out.integer(value.policy.minimise_one_label_count);
  out.integer(value.policy.maximum_alias_hops);
  dns_cache(out, value.cache);
  count(out, value.transactions);
  for (const auto &transaction : value.transactions) {
    out.boolean(transaction.has_value());
    if (transaction)
      dns_transaction(out, *transaction);
  }
  count(out, value.generations);
  for (const auto generation : value.generations)
    out.integer(generation);
  out.integer(value.identifier_counter);
  out.integer(value.preparation_counter);
  dns_zone_record_vector(out, value.trust_anchors);
  out.integer(value.nsec3_policy.maximum);
  out.boolean(value.dnssec_enabled);
}

bool dns_resolver(Reader &in, dns::ResolverCheckpoint &value) {
  std::uint32_t size{};
  std::chrono::milliseconds::rep retry{};
  if (!in.octets(value.identifier_secret) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.root_hints.resize(size);
  for (auto &hint : value.root_hints)
    if (!dns_root_hint(in, hint))
      return false;
  if (!in.integer(retry) ||
      !in.integer(value.policy.advertised_udp_payload_bytes) ||
      !in.integer(value.policy.attempts_per_server) ||
      !in.integer(value.policy.maximum_minimise_count) ||
      !in.integer(value.policy.minimise_one_label_count) ||
      !in.integer(value.policy.maximum_alias_hops) ||
      !dns_cache(in, value.cache) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.policy.retry_interval = std::chrono::milliseconds{retry};
  value.transactions.resize(size);
  for (auto &transaction : value.transactions) {
    bool present{};
    if (!in.boolean(present))
      return false;
    if (present) {
      transaction.emplace();
      if (!dns_transaction(in, *transaction))
        return false;
    }
  }
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.generations.resize(size);
  for (auto &generation : value.generations)
    if (!in.integer(generation))
      return false;
  return in.integer(value.identifier_counter) &&
         in.integer(value.preparation_counter) &&
         dns_zone_record_vector(in, value.trust_anchors) &&
         in.integer(value.nsec3_policy.maximum) &&
         in.boolean(value.dnssec_enabled);
}

template <typename Handle>
void optional_socket(Writer &out, const std::optional<Handle> &value) {
  out.boolean(value.has_value());
  if (value) {
    out.integer(value->index);
    out.integer(value->generation);
  }
}

template <typename Handle>
bool optional_socket(Reader &in, std::optional<Handle> &value) {
  bool present{};
  if (!in.boolean(present))
    return false;
  if (!present) {
    value.reset();
    return true;
  }
  Handle handle{};
  if (!in.integer(handle.index) || !in.integer(handle.generation))
    return false;
  value = handle;
  return true;
}

void dns_transaction_handle(Writer &out, dns::TransactionHandle value) {
  out.integer(value.index);
  out.integer(value.generation);
}

bool dns_transaction_handle(Reader &in, dns::TransactionHandle &value) {
  return in.integer(value.index) && in.integer(value.generation);
}

void dns_prepared_query(Writer &out, const dns::PreparedQuery &value) {
  dns_server(out, value.server);
  dns_question(out, value.question);
  out.integer(value.transport);
  out.integer(value.preparation_token);
  out.integer<std::uint32_t>(static_cast<std::uint32_t>(value.message_octets));
  out.integer(value.id);
}

bool dns_prepared_query(Reader &in, dns::PreparedQuery &value) {
  std::uint32_t message_octets{};
  if (!dns_server(in, value.server) || !dns_question(in, value.question) ||
      !in.integer(value.transport) ||
      value.transport > dns::QueryTransport::tcp ||
      !in.integer(value.preparation_token) || !in.integer(message_octets) ||
      message_octets > packet::dns::maximum_message_octets ||
      !in.integer(value.id))
    return false;
  value.message_octets = message_octets;
  return true;
}

void dns_octets(Writer &out, const std::vector<std::uint8_t> &value) {
  count(out, value);
  out.octets(value);
}

bool dns_octets(Reader &in, std::vector<std::uint8_t> &value,
                std::size_t maximum) {
  std::uint32_t size{};
  if (!count(in, size, maximum))
    return false;
  value.resize(size);
  return in.octets(value);
}

void dnssec_key_schedule(Writer &out, const dnssec::KeySchedule &value) {
  out.integer(value.publish_at);
  out.integer(value.ready_at);
  out.integer(value.activate_at);
  out.integer(value.retire_at);
  out.integer(value.dead_at);
  out.integer(value.remove_at);
}

bool dnssec_key_schedule(Reader &in, dnssec::KeySchedule &value) {
  return in.integer(value.publish_at) && in.integer(value.ready_at) &&
         in.integer(value.activate_at) && in.integer(value.retire_at) &&
         in.integer(value.dead_at) && in.integer(value.remove_at) &&
         dnssec::valid_schedule(value);
}

void dnssec_signed_zone(Writer &out,
                        const dnssec::SignedZoneOwnerCheckpoint &value) {
  dns_name(out, value.origin);
  dns_zone_record_vector(out, value.unsigned_records);
  out.integer(value.keys.next_id);
  count(out, value.keys.keys);
  for (const auto &key : value.keys.keys) {
    out.integer(key.id);
    out.integer(key.role);
    dnssec_key_schedule(out, key.schedule);
    out.integer(key.algorithm);
    dns_octets(out, key.public_key);
    dns_octets(out, key.sealed_private_key);
  }
  out.integer(value.policy.dnskey_ttl);
  out.integer(value.policy.denial_ttl);
  out.integer(value.policy.denial_mode);
  out.integer(value.policy.timing.validity_seconds);
  out.integer(value.policy.timing.refresh_seconds);
  out.integer(value.policy.timing.resign_seconds);
  out.integer(value.policy.timing.inception_offset_seconds);
  out.integer(value.statistics.generation);
  out.integer(value.statistics.successful_refreshes);
  out.integer(value.statistics.failed_refreshes);
  out.integer(value.statistics.last_success_wall_seconds);
  out.integer(value.statistics.signature_expiration_wall_seconds);
  out.integer(value.next_visit_remaining_nanoseconds);
}

bool dnssec_signed_zone(Reader &in, dnssec::SignedZoneOwnerCheckpoint &value) {
  std::uint32_t size{};
  if (!dns_name(in, value.origin) ||
      !dns_zone_record_vector(in, value.unsigned_records) ||
      !in.integer(value.keys.next_id) || value.keys.next_id == 0U ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.keys.keys.resize(size);
  for (auto &key : value.keys.keys)
    if (!in.integer(key.id) || key.id == 0U || !in.integer(key.role) ||
        key.role > dnssec::KeyRole::key_signing ||
        !dnssec_key_schedule(in, key.schedule) || !in.integer(key.algorithm) ||
        key.algorithm == 0U ||
        !dns_octets(in, key.public_key, packet::dns::maximum_message_octets) ||
        key.public_key.empty() ||
        !dns_octets(in, key.sealed_private_key,
                    packet::dns::maximum_message_octets) ||
        key.sealed_private_key.empty())
      return false;
  return in.integer(value.policy.dnskey_ttl) &&
         in.integer(value.policy.denial_ttl) &&
         in.integer(value.policy.denial_mode) &&
         value.policy.denial_mode <= dnssec::DenialMode::nsec3_opt_out &&
         in.integer(value.policy.timing.validity_seconds) &&
         in.integer(value.policy.timing.refresh_seconds) &&
         in.integer(value.policy.timing.resign_seconds) &&
         in.integer(value.policy.timing.inception_offset_seconds) &&
         dnssec::valid_managed_zone_policy(value.policy) &&
         in.integer(value.statistics.generation) &&
         value.statistics.generation != 0U &&
         in.integer(value.statistics.successful_refreshes) &&
         in.integer(value.statistics.failed_refreshes) &&
         in.integer(value.statistics.last_success_wall_seconds) &&
         in.integer(value.statistics.signature_expiration_wall_seconds) &&
         in.integer(value.next_visit_remaining_nanoseconds) &&
         value.next_visit_remaining_nanoseconds >= 0;
}

void dns_recursive_client(Writer &out,
                          const dns::RecursiveUdpClientCheckpoint &client) {
  dns_transaction_handle(out, client.transaction);
  dns_question(out, client.question);
  ipv4(out, client.destination_ipv4);
  ipv6(out, client.destination_ipv6);
  out.integer(client.family);
  out.integer(client.destination_port);
  out.integer(client.request_id);
  out.integer(client.udp_payload_bytes);
  out.boolean(client.recursion_desired);
  out.boolean(client.checking_disabled);
  out.boolean(client.dnssec_ok);
  out.boolean(client.understands_authenticated_data);
  out.boolean(client.used_edns);
}

bool dns_recursive_client(Reader &in,
                          dns::RecursiveUdpClientCheckpoint &client) {
  return dns_transaction_handle(in, client.transaction) &&
         dns_question(in, client.question) &&
         ipv4(in, client.destination_ipv4) &&
         ipv6(in, client.destination_ipv6) && in.integer(client.family) &&
         client.family <= transport::IpFamily::ipv6 &&
         in.integer(client.destination_port) && in.integer(client.request_id) &&
         in.integer(client.udp_payload_bytes) &&
         in.boolean(client.recursion_desired) &&
         in.boolean(client.checking_disabled) && in.boolean(client.dnssec_ok) &&
         in.boolean(client.understands_authenticated_data) &&
         in.boolean(client.used_edns);
}

void dns_service(Writer &out, const dns::EndpointServiceCheckpoint &value) {
  out.boolean(value.resolver.has_value());
  if (value.resolver)
    dns_resolver(out, *value.resolver);
  optional_socket(out, value.resolver_ipv4_socket);
  optional_socket(out, value.resolver_ipv6_socket);
  count(out, value.transactions);
  for (const auto transaction : value.transactions)
    dns_transaction_handle(out, transaction);
  dns_transaction_handle(out, value.pending_query.transaction);
  dns_prepared_query(out, value.pending_query.prepared);
  dns_octets(out, value.pending_query.query_message);
  dns_octets(out, value.pending_query.stream_wire);
  out.integer<std::uint32_t>(
      static_cast<std::uint32_t>(value.pending_query.stream_write_offset));
  out.boolean(value.pending_query.active);
  count(out, value.resolver_tcp_connections);
  for (const auto &connection : value.resolver_tcp_connections) {
    dns_server(out, connection.server);
    out.integer(connection.socket.index);
    out.integer(connection.socket.generation);
    dns_octets(out, connection.received_wire);
  }
  count(out, value.zones);
  for (const auto &zone : value.zones) {
    dns_name(out, zone.origin);
    dns_zone_record_vector(out, zone.records);
  }
  count(out, value.signed_zones);
  for (const auto &zone : value.signed_zones)
    dnssec_signed_zone(out, zone);
  optional_socket(out, value.authoritative_ipv4_socket);
  optional_socket(out, value.authoritative_ipv6_socket);
  optional_socket(out, value.authoritative_ipv4_listener);
  optional_socket(out, value.authoritative_ipv6_listener);
  count(out, value.authoritative_tcp_connections);
  for (const auto &connection : value.authoritative_tcp_connections) {
    out.integer(connection.socket.index);
    out.integer(connection.socket.generation);
    out.integer(connection.family);
    dns_octets(out, connection.received_wire);
    dns_octets(out, connection.send_wire);
    count(out, connection.recursive_clients);
    for (const auto &client : connection.recursive_clients)
      dns_recursive_client(out, client);
    out.integer<std::uint32_t>(
        static_cast<std::uint32_t>(connection.send_offset));
  }
  out.integer(value.pending_response.family);
  ipv4(out, value.pending_response.destination_ipv4);
  ipv6(out, value.pending_response.destination_ipv6);
  out.integer(value.pending_response.destination_port);
  dns_octets(out, value.pending_response.message);
  out.boolean(value.pending_response.active);
  count(out, value.recursive_udp_clients);
  for (const auto &client : value.recursive_udp_clients)
    dns_recursive_client(out, client);
  out.boolean(value.recursive_service_enabled);
}

bool dns_service(Reader &in, dns::EndpointServiceCheckpoint &value) {
  bool present{};
  std::uint32_t size{};
  if (!in.boolean(present))
    return false;
  if (present) {
    value.resolver.emplace();
    if (!dns_resolver(in, *value.resolver))
      return false;
  }
  if (!optional_socket(in, value.resolver_ipv4_socket) ||
      !optional_socket(in, value.resolver_ipv6_socket) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.transactions.resize(size);
  for (auto &transaction : value.transactions)
    if (!dns_transaction_handle(in, transaction))
      return false;
  std::uint32_t offset{};
  if (!dns_transaction_handle(in, value.pending_query.transaction) ||
      !dns_prepared_query(in, value.pending_query.prepared) ||
      !dns_octets(in, value.pending_query.query_message,
                  packet::dns::maximum_message_octets) ||
      !dns_octets(in, value.pending_query.stream_wire,
                  packet::dns::maximum_message_octets + 2U) ||
      !in.integer(offset) || !in.boolean(value.pending_query.active) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.pending_query.stream_write_offset = offset;
  value.resolver_tcp_connections.resize(size);
  for (auto &connection : value.resolver_tcp_connections)
    if (!dns_server(in, connection.server) ||
        !in.integer(connection.socket.index) ||
        !in.integer(connection.socket.generation) ||
        !dns_octets(in, connection.received_wire,
                    packet::dns::maximum_message_octets + 2U))
      return false;
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.zones.resize(size);
  for (auto &zone : value.zones)
    if (!dns_name(in, zone.origin) || !dns_zone_record_vector(in, zone.records))
      return false;
  if (!count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.signed_zones.resize(size);
  for (auto &zone : value.signed_zones)
    if (!dnssec_signed_zone(in, zone))
      return false;
  if (!optional_socket(in, value.authoritative_ipv4_socket) ||
      !optional_socket(in, value.authoritative_ipv6_socket) ||
      !optional_socket(in, value.authoritative_ipv4_listener) ||
      !optional_socket(in, value.authoritative_ipv6_listener) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.authoritative_tcp_connections.resize(size);
  for (auto &connection : value.authoritative_tcp_connections) {
    if (!in.integer(connection.socket.index) ||
        !in.integer(connection.socket.generation) ||
        !in.integer(connection.family) ||
        connection.family > transport::IpFamily::ipv6 ||
        !dns_octets(in, connection.received_wire,
                    packet::dns::maximum_message_octets + 2U) ||
        !dns_octets(in, connection.send_wire,
                    packet::dns::maximum_message_octets + 2U) ||
        !count(in, size, maximum_dns_checkpoint_entries))
      return false;
    connection.recursive_clients.resize(size);
    for (auto &client : connection.recursive_clients)
      if (!dns_recursive_client(in, client))
        return false;
    if (!in.integer(offset))
      return false;
    connection.send_offset = offset;
  }
  if (!in.integer(value.pending_response.family) ||
      value.pending_response.family > transport::IpFamily::ipv6 ||
      !ipv4(in, value.pending_response.destination_ipv4) ||
      !ipv6(in, value.pending_response.destination_ipv6) ||
      !in.integer(value.pending_response.destination_port) ||
      !dns_octets(in, value.pending_response.message,
                  packet::dns::maximum_message_octets) ||
      !in.boolean(value.pending_response.active) ||
      !count(in, size, maximum_dns_checkpoint_entries))
    return false;
  value.recursive_udp_clients.resize(size);
  for (auto &client : value.recursive_udp_clients)
    if (!dns_recursive_client(in, client))
      return false;
  return in.boolean(value.recursive_service_enabled);
}

void host_state(Writer &out, const NetworkHostCheckpoint &state) {
  handle(out, state.host);
  endpoint_state(out, state.endpoint);
  mac(out, state.mac);
  ipv4(out, state.address);
  ipv4(out, state.gateway);
  out.integer(state.prefix_length);
  out.integer(state.mtu);
  // The interface identity is an opaque project-owned value used to seed
  // per-interface IPv6 state. Persisting it is mandatory: substituting a slot
  // index during restore would change DAD and solicitation timing and would
  // silently attach learned IPv6 state to a different logical interface.
  out.integer(state.interface_id);
  out.integer(state.expected_sequence);
  out.boolean(state.configured);
  out.boolean(state.link_signal);
  out.boolean(state.ping_pending);
  out.boolean(state.ping_reply);
  out.integer(state.ping_sent_elapsed_nanoseconds);
  out.integer(state.ping_reply_rtt_nanoseconds);
  out.integer(state.ping_reply_ttl);
  out.boolean(state.ipv6_autoconfiguration);
  out.boolean(state.dhcpv4.has_value());
  if (state.dhcpv4)
    dhcpv4_service(out, *state.dhcpv4);
  out.boolean(state.dhcpv6.has_value());
  if (state.dhcpv6)
    dhcpv6_service(out, *state.dhcpv6);
  out.boolean(state.dns.has_value());
  if (state.dns)
    dns_service(out, *state.dns);
}

bool host_state(Reader &in, NetworkHostCheckpoint &state) {
  return handle(in, state.host) && endpoint_state(in, state.endpoint) &&
         mac(in, state.mac) && ipv4(in, state.address) &&
         ipv4(in, state.gateway) && in.integer(state.prefix_length) &&
         in.integer(state.mtu) && in.integer(state.interface_id) &&
         in.integer(state.expected_sequence) && in.boolean(state.configured) &&
         in.boolean(state.link_signal) && in.boolean(state.ping_pending) &&
         in.boolean(state.ping_reply) &&
         in.integer(state.ping_sent_elapsed_nanoseconds) &&
         in.integer(state.ping_reply_rtt_nanoseconds) &&
         in.integer(state.ping_reply_ttl) &&
         in.boolean(state.ipv6_autoconfiguration) && ([&] {
           bool present{};
           if (!in.boolean(present))
             return false;
           if (!present)
             return true;
           state.dhcpv4.emplace();
           return dhcpv4_service(in, *state.dhcpv4);
         })() &&
         ([&] {
           bool present{};
           if (!in.boolean(present))
             return false;
           if (!present)
             return true;
           state.dhcpv6.emplace();
           return dhcpv6_service(in, *state.dhcpv6);
         })() &&
         ([&] {
           bool present{};
           if (!in.boolean(present))
             return false;
           if (!present)
             return true;
           state.dns.emplace();
           return dns_service(in, *state.dns);
         })();
}

void switch_state(Writer &out,
                  const NetworkPlaneCheckpoint::Switch &state) {
  handle(out, state.handle);
  out.integer(state.profile_index);
  count(out, state.forwarding.ports);
  for (const auto &port : state.forwarding.ports) {
    out.integer(port.configuration.speed_mbps);
    out.integer(port.configuration.mtu);
    out.boolean(port.configuration.admin_enabled);
    out.boolean(port.configuration.carrier);
    out.boolean(port.configured);
  }
  count(out, state.forwarding.fdb);
  for (const auto &entry : state.forwarding.fdb) {
    mac(out, entry.address);
    out.integer(entry.remaining_nanoseconds);
    out.integer(entry.port);
  }
  count(out, state.forwarding.egress);
  for (const auto &entry : state.forwarding.egress) {
    out.frame(entry.frame);
    out.integer(entry.port);
  }
}

bool switch_state(Reader &in, NetworkPlaneCheckpoint::Switch &state) {
  if (!handle(in, state.handle) || !in.integer(state.profile_index))
    return false;
  const auto *profile =
      device_catalog::ethernet_switch_profile(state.profile_index);
  std::uint32_t size{};
  if (!profile || !count(in, size, profile->port_count))
    return false;
  state.forwarding.ports.resize(size);
  for (auto &port : state.forwarding.ports)
    if (!in.integer(port.configuration.speed_mbps) ||
        !in.integer(port.configuration.mtu) ||
        !in.boolean(port.configuration.admin_enabled) ||
        !in.boolean(port.configuration.carrier) ||
        !in.boolean(port.configured))
      return false;
  if (!count(in, size, profile->fdb_entries))
    return false;
  state.forwarding.fdb.resize(size);
  for (auto &entry : state.forwarding.fdb)
    if (!mac(in, entry.address) ||
        !in.integer(entry.remaining_nanoseconds) ||
        !in.integer(entry.port))
      return false;
  const auto maximum_queued =
      static_cast<std::size_t>(profile->port_count) *
      profile->queue_frames_per_port;
  if (!count(in, size, maximum_queued))
    return false;
  state.forwarding.egress.resize(size);
  for (auto &entry : state.forwarding.egress)
    if (!in.frame(entry.frame) || !in.integer(entry.port))
      return false;
  return true;
}

void fabric_frame(Writer &out, const FabricFrameCheckpoint &value) {
  out.frame(value.frame);
  out.integer(value.delivery_remaining_nanoseconds);
}

bool fabric_frame(Reader &in, FabricFrameCheckpoint &value) noexcept {
  return in.frame(value.frame) &&
         in.integer(value.delivery_remaining_nanoseconds);
}

void fabric_direction(Writer &out, const FabricDirectionCheckpoint &value) {
  out.integer(value.bits_per_second);
  out.integer(value.propagation_nanoseconds);
  out.integer(value.transmitter_remaining_nanoseconds);
  for (const auto *frames :
       {&value.transmit, &value.in_flight, &value.receive}) {
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
        !port_handle(in, link.endpoints[1]) || !in.boolean(link.carrier) ||
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
    out.integer(point.received);
    out.integer(point.dropped);
  }
  // ABI 6 reserved this count for packet records. Keep the zero field so the
  // surrounding checkpoint layout remains stable, but packet bytes now live
  // exclusively in the independently persisted PCAPNG artifact.
  out.integer<std::uint32_t>(0U);
}

bool capture_state(Reader &in, CaptureStoreCheckpoint &state) {
  std::uint32_t size{};
  // Only live capture points enter new checkpoints. The serialized file size
  // is already bounded by the checkpoint envelope, so decoding does not impose
  // the obsolete lifetime total of 256 selections.
  if (!count(in, size, device_catalog::maximum_active_capture_points))
    return false;
  state.points.resize(size);
  for (auto &point : state.points)
    if (!in.integer(point.id) ||
        !in.string(point.name, device_catalog::capture_point_name_bytes) ||
        !in.boolean(point.active) || !in.integer(point.received) ||
        !in.integer(point.dropped))
      return false;
  return in.integer(size) && size == 0U;
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

void ospf_duration(Writer &out, std::chrono::milliseconds value) {
  out.integer(value.count());
}

bool ospf_duration(Reader &in, std::chrono::milliseconds &value) noexcept {
  std::int64_t count_value{};
  if (!in.integer(count_value) || count_value < 0 ||
      std::chrono::milliseconds{count_value} >
          device_catalog::checkpoint_max_relative_deadline)
    return false;
  value = std::chrono::milliseconds{count_value};
  return true;
}

void ospf_lsa_key(Writer &out, const ospf::LsaKey &value) {
  out.integer(value.link_state_id);
  out.integer(value.advertising_router);
  out.integer(value.type);
  out.integer(value.scope);
}

bool ospf_lsa_key(Reader &in, ospf::LsaKey &value) noexcept {
  return in.integer(value.link_state_id) &&
         in.integer(value.advertising_router) &&
         in.integer(value.type) && in.integer(value.scope) &&
         value.scope <= ospf::FloodingScope::autonomous_system;
}

void ospf_lsa_header(Writer &out,
                     const packet::ospf::LsaHeaderView &value) {
  out.integer(value.link_state_id);
  out.integer(value.advertising_router);
  out.integer(value.sequence_number);
  out.integer(value.age_seconds);
  out.integer(value.type);
  out.integer(value.checksum);
  out.integer(value.length);
  out.integer(value.options);
  out.integer(value.version);
}

bool ospf_lsa_header(Reader &in,
                     packet::ospf::LsaHeaderView &value) noexcept {
  return in.integer(value.link_state_id) &&
         in.integer(value.advertising_router) &&
         in.integer(value.sequence_number) &&
         in.integer(value.age_seconds) &&
         value.age_seconds <= ospf::max_age_seconds &&
         in.integer(value.type) && in.integer(value.checksum) &&
         in.integer(value.length) && in.integer(value.options) &&
         in.integer(value.version) &&
         (value.version == packet::ospf::version_two ||
          value.version == packet::ospf::version_three);
}

void ospf_process_identity(Writer &out,
                           const ospf::ProcessIdentity &value) {
  handle(out, value.device);
  out.integer(value.area_id);
  out.integer(value.version);
  out.integer(value.instance_id);
}

bool ospf_process_identity(Reader &in,
                           ospf::ProcessIdentity &value) noexcept {
  return handle(in, value.device) && in.integer(value.area_id) &&
         in.integer(value.version) &&
         (value.version == packet::ospf::version_two ||
          value.version == packet::ospf::version_three) &&
         in.integer(value.instance_id);
}

void ospf_interface_configuration(
    Writer &out, const ospf::InterfaceConfiguration &value) {
  out.integer(value.router_id);
  out.integer(value.area_id);
  out.integer(value.interface_id);
  out.integer(value.network_mask);
  out.integer(value.local_election_identity);
  out.integer(value.options);
  out.integer(value.hello_interval_seconds);
  out.integer(value.dead_interval_seconds);
  out.integer(value.interface_mtu);
  out.integer(value.router_priority);
  out.integer(value.version);
  out.integer(value.instance_id);
  out.integer(value.network_type);
  out.boolean(value.passive);
  out.boolean(value.enabled);
}

bool ospf_interface_configuration(
    Reader &in, ospf::InterfaceConfiguration &value) noexcept {
  if (!in.integer(value.router_id) || value.router_id == 0U)
    return false;
  if (!in.integer(value.area_id))
    return false;
  if (!in.integer(value.interface_id))
    return false;
  if (!in.integer(value.network_mask))
    return false;
  if (!in.integer(value.local_election_identity))
    return false;
  if (!in.integer(value.options))
    return false;
  if (!in.integer(value.hello_interval_seconds))
    return false;
  if (!in.integer(value.dead_interval_seconds))
    return false;
  if (!in.integer(value.interface_mtu))
    return false;
  if (!in.integer(value.router_priority))
    return false;
  if (!in.integer(value.version))
    return false;
  if (!in.integer(value.instance_id))
    return false;
  if (!in.integer(value.network_type) ||
      value.network_type > ospf::NetworkType::virtual_link)
    return false;
  if (!in.boolean(value.passive))
    return false;
  if (!in.boolean(value.enabled))
    return false;
  if (value.interface_id == 0U && !value.passive)
    return false;
  if (!ospf::InterfaceRuntime::validate_configuration(value))
    return false;
  return true;
  // A physical OSPF owner always has a stable Interface ID. The passive
  // system interface is different: it contributes a stub prefix but owns no
  // port and never emits a Hello, so zero is its deliberate internal absence
  // marker. Reject zero on every active owner to keep corrupt checkpoints
  // from creating an unaddressable packet-producing interface.
}

void ospf_process_interface_configuration(
    Writer &out, const ospf::ProcessInterfaceConfiguration &value) {
  ospf_interface_configuration(out, value.protocol);
  ipv4(out, value.ipv4_source);
  ipv6(out, value.ipv6_source);
  ipv6(out, value.ipv6_prefix);
  mac(out, value.source_mac);
  out.integer(value.physical_port_ordinal);
  out.integer(value.metric);
  out.integer(value.retransmit_interval_seconds);
  out.integer(value.transmit_delay_seconds);
  out.integer(value.prefix_length);
  out.integer(value.virtual_neighbor_router_id);
  ip_address(out, value.virtual_neighbor_address);
}

bool ospf_process_interface_configuration(
    Reader &in, ospf::ProcessInterfaceConfiguration &value) noexcept {
  return ospf_interface_configuration(in, value.protocol) &&
         ipv4(in, value.ipv4_source) && ipv6(in, value.ipv6_source) &&
         ipv6(in, value.ipv6_prefix) && mac(in, value.source_mac) &&
         in.integer(value.physical_port_ordinal) &&
         in.integer(value.metric) &&
         in.integer(value.retransmit_interval_seconds) &&
         in.integer(value.transmit_delay_seconds) &&
         in.integer(value.prefix_length) && value.prefix_length <= 128U &&
         in.integer(value.virtual_neighbor_router_id) &&
         ip_address(in, value.virtual_neighbor_address);
}

void ospf_authentication(Writer &out,
                         const ospf::ProcessAuthentication &value) {
  out.integer(value.key_size);
  out.integer(value.initial_sequence);
  out.integer(value.secret_handle);
  out.integer(value.key_id);
  out.integer(value.algorithm);
  out.integer(value.secret_kind);
  out.boolean(value.ipsec_ah);
  out.integer(value.begin_utc_seconds);
  out.boolean(value.end_utc_seconds.has_value());
  if (value.end_utc_seconds)
    out.integer(*value.end_utc_seconds);
  out.integer(value.tolerance_seconds);
  out.boolean(value.timed);
}

bool ospf_authentication(Reader &in,
                         ospf::ProcessAuthentication &value) noexcept {
  bool has_end{};
  std::int64_t end{};
  if (!in.integer(value.key_size) || value.key_size > value.key.size() ||
      !in.integer(value.initial_sequence) ||
      !in.integer(value.secret_handle) || value.secret_handle == 0U ||
      !in.integer(value.key_id) ||
      !in.integer(value.algorithm) ||
      value.algorithm > ospf::KeychainAlgorithm::hmac_sha256 ||
      !in.integer(value.secret_kind) ||
      value.secret_kind >
          static_cast<std::uint8_t>(
              vault::SecretKind::ospf_authentication_key) ||
      value.secret_kind == 0U ||
      !in.boolean(value.ipsec_ah) ||
      !in.integer(value.begin_utc_seconds) || !in.boolean(has_end) ||
      (has_end && !in.integer(end)) ||
      !in.integer(value.tolerance_seconds) || !in.boolean(value.timed))
    return false;
  value.end_utc_seconds =
      has_end ? std::optional<std::int64_t>{end} : std::nullopt;
  value.key.fill(0U);
  return value.key_size != 0U;
}

void ospf_interface_runtime(
    Writer &out, const ospf::InterfaceRuntimeCheckpoint &value) {
  ospf_interface_configuration(out, value.configuration);
  count(out, value.neighbors);
  for (const auto &neighbor : value.neighbors) {
    out.integer(neighbor.router_id);
    out.integer(neighbor.election_identity);
    out.integer(neighbor.interface_id);
    out.integer(neighbor.designated_router);
    out.integer(neighbor.backup_designated_router);
    out.integer(neighbor.options);
    ospf_duration(
        out, std::chrono::duration_cast<std::chrono::milliseconds>(
                 neighbor.inactivity_deadline.time_since_epoch()));
    ospf_duration(
        out, std::chrono::duration_cast<std::chrono::milliseconds>(
                 neighbor.state_since.time_since_epoch()));
    ospf_duration(
        out, std::chrono::duration_cast<std::chrono::milliseconds>(
                 neighbor.last_event_at.time_since_epoch()));
    ospf_duration(
        out, std::chrono::duration_cast<std::chrono::milliseconds>(
                 neighbor.last_restart_at.time_since_epoch()));
    out.integer(neighbor.state);
    out.integer(neighbor.event_count);
    out.integer(neighbor.restart_count);
    out.integer(neighbor.bad_neighbor_states);
    out.integer(neighbor.bad_sequence_numbers);
    out.integer(neighbor.bad_link_state_requests);
    out.integer(neighbor.priority);
  }
  ospf_duration(out, value.hello_remaining);
  ospf_duration(out, value.wait_remaining);
  out.integer(value.state);
  out.integer(value.designated_router);
  out.integer(value.backup_designated_router);
}

bool ospf_interface_runtime(
    Reader &in, ospf::InterfaceRuntimeCheckpoint &value) {
  std::uint32_t size{};
  if (!ospf_interface_configuration(in, value.configuration) ||
      !count(in, size, device_catalog::ospf_neighbors_per_interface))
    return false;
  value.neighbors.resize(size);
  for (auto &neighbor : value.neighbors) {
    std::chrono::milliseconds remaining{};
    std::chrono::milliseconds state_elapsed{};
    std::chrono::milliseconds event_elapsed{};
    std::chrono::milliseconds restart_elapsed{};
    if (!in.integer(neighbor.router_id) || neighbor.router_id == 0U ||
        !in.integer(neighbor.election_identity) ||
        !in.integer(neighbor.interface_id) ||
        !in.integer(neighbor.designated_router) ||
        !in.integer(neighbor.backup_designated_router) ||
        !in.integer(neighbor.options) ||
        !ospf_duration(in, remaining) ||
        !ospf_duration(in, state_elapsed) ||
        !ospf_duration(in, event_elapsed) ||
        !ospf_duration(in, restart_elapsed) ||
        !in.integer(neighbor.state) ||
        neighbor.state > ospf::NeighborState::full ||
        !in.integer(neighbor.event_count) ||
        !in.integer(neighbor.restart_count) ||
        !in.integer(neighbor.bad_neighbor_states) ||
        !in.integer(neighbor.bad_sequence_numbers) ||
        !in.integer(neighbor.bad_link_state_requests) ||
        !in.integer(neighbor.priority))
      return false;
    neighbor.inactivity_deadline =
        ospf::RuntimeClock::time_point{remaining};
    neighbor.state_since = ospf::RuntimeClock::time_point{state_elapsed};
    neighbor.last_event_at = ospf::RuntimeClock::time_point{event_elapsed};
    neighbor.last_restart_at =
        ospf::RuntimeClock::time_point{restart_elapsed};
  }
  return ospf_duration(in, value.hello_remaining) &&
         ospf_duration(in, value.wait_remaining) &&
         in.integer(value.state) &&
         // Broadcast Ethernet interfaces legitimately restore in DR Other,
         // Backup or Designated Router after RFC 2328 section 9.3 election.
         // Point-to-Point is not the maximum enum value and using it as the
         // decoder bound rejected every converged broadcast checkpoint.
         value.state <= ospf::InterfaceState::designated &&
         in.integer(value.designated_router) &&
         in.integer(value.backup_designated_router);
}

void ospf_database_exchange(
    Writer &out,
    const ospf::NeighborDatabaseExchangeCheckpoint &value) {
  count(out, value.summaries);
  for (const auto &entry : value.summaries)
    ospf_lsa_header(out, entry);
  count(out, value.requests);
  for (const auto &entry : value.requests) {
    out.integer(entry.link_state_type);
    out.integer(entry.link_state_id);
    out.integer(entry.advertising_router);
  }
  count(out, value.retransmissions);
  for (const auto &entry : value.retransmissions) {
    ospf_lsa_key(out, entry.key);
    out.integer(entry.sequence_number);
    out.integer(entry.checksum);
  }
  count(out, value.acknowledgments);
  for (const auto &entry : value.acknowledgments)
    ospf_lsa_header(out, entry);
  out.integer(value.version);
  out.boolean(value.permit_autonomous_system_scope);
}

bool ospf_database_exchange(
    Reader &in, ospf::NeighborDatabaseExchangeCheckpoint &value) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.summaries.resize(size);
  for (auto &entry : value.summaries)
    if (!ospf_lsa_header(in, entry))
      return false;
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.requests.resize(size);
  for (auto &entry : value.requests)
    if (!in.integer(entry.link_state_type) ||
        !in.integer(entry.link_state_id) ||
        !in.integer(entry.advertising_router))
      return false;
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.retransmissions.resize(size);
  for (auto &entry : value.retransmissions)
    if (!ospf_lsa_key(in, entry.key) ||
        !in.integer(entry.sequence_number) ||
        !in.integer(entry.checksum))
      return false;
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.acknowledgments.resize(size);
  for (auto &entry : value.acknowledgments)
    if (!ospf_lsa_header(in, entry))
      return false;
  return in.integer(value.version) &&
         (value.version == 0U ||
          value.version == packet::ospf::version_two ||
          value.version == packet::ospf::version_three) &&
         in.boolean(value.permit_autonomous_system_scope);
}

void ospf_lsa_database(
    Writer &out, const ospf::LinkStateDatabaseCheckpoint &value) {
  count(out, value.records);
  for (const auto &record : value.records) {
    ospf_lsa_key(out, record.key);
    count(out, record.bytes);
    out.octets(record.bytes);
    out.integer(record.effective_age);
    out.integer(record.last_checksum_check_age);
    out.boolean(record.max_age_flooded);
  }
}

bool ospf_lsa_database(
    Reader &in, ospf::LinkStateDatabaseCheckpoint &value) {
  std::uint32_t size{};
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.records.resize(size);
  for (auto &record : value.records) {
    std::uint32_t byte_count{};
    if (!ospf_lsa_key(in, record.key) ||
        !count(in, byte_count, packet::maximum_frame_octets) ||
        byte_count < packet::ospf::lsa_header_octets ||
        !(record.bytes.resize(byte_count), in.octets(record.bytes)) ||
        !in.integer(record.effective_age) ||
        record.effective_age > ospf::max_age_seconds ||
        !in.integer(record.last_checksum_check_age) ||
        record.last_checksum_check_age > record.effective_age ||
        !in.boolean(record.max_age_flooded))
      return false;
  }
  return true;
}

void ospf_coordinator_advertisement(
    Writer &out, const ospf::CoordinatorAdvertisement &value) {
  ip_address(out, value.prefix.network);
  out.integer(value.prefix.length);
  out.integer(value.destination_router_id);
  out.integer(value.metric);
  out.integer(value.internal_metric);
  out.integer(value.forwarding_address_v4);
  ipv6(out, value.forwarding_address_v6);
  out.integer(value.tag);
  out.integer(value.source_link_state_id);
  out.integer(value.kind);
  out.boolean(value.type_two);
  out.boolean(value.ipv4_forwarding_address);
}

bool ospf_coordinator_advertisement(
    Reader &in, ospf::CoordinatorAdvertisement &value) noexcept {
  return ip_address(in, value.prefix.network) &&
         in.integer(value.prefix.length) &&
         value.prefix.length <= ip::address_bits(value.prefix.network.family) &&
         in.integer(value.destination_router_id) &&
         in.integer(value.metric) && in.integer(value.internal_metric) &&
         in.integer(value.forwarding_address_v4) &&
         ipv6(in, value.forwarding_address_v6) && in.integer(value.tag) &&
         in.integer(value.source_link_state_id) &&
         in.integer(value.kind) &&
         value.kind <= ospf::CoordinatorAdvertisementKind::nssa_external &&
         in.boolean(value.type_two) &&
         in.boolean(value.ipv4_forwarding_address);
}

void ospf_process_checkpoint(
    Writer &out, const ospf::InstanceProcessCheckpoint &value) {
  ospf_lsa_database(out, value.database);
  count(out, value.interfaces);
  for (const auto &interface : value.interfaces) {
    ospf_process_interface_configuration(out, interface.configuration);
    ospf_interface_runtime(out, interface.runtime);
    count(out, interface.exchanges);
    for (const auto &exchange : interface.exchanges) {
      ospf_database_exchange(out, exchange.database);
      out.integer(exchange.router_id);
      out.integer(exchange.dd_sequence);
      out.integer(static_cast<std::uint32_t>(exchange.summary_cursor));
      out.integer(static_cast<std::uint32_t>(exchange.request_cursor));
      out.integer(static_cast<std::uint32_t>(exchange.update_cursor));
      ospf_duration(out, exchange.dd_retransmit_remaining);
      ospf_duration(out, exchange.request_retransmit_remaining);
      ospf_duration(out, exchange.update_retransmit_remaining);
      ipv4(out, exchange.ipv4_address);
      ipv6(out, exchange.ipv6_address);
      for (const auto sequence : exchange.authentication_sequences)
        out.integer(sequence);
      for (const auto seen : exchange.authentication_sequence_seen)
        out.boolean(seen);
      ospf_duration(out, exchange.helper_remaining);
      ospf_duration(out, exchange.helper_elapsed);
      out.boolean(exchange.local_master);
      out.boolean(exchange.negotiation_complete);
      out.boolean(exchange.pending_database_description);
      out.boolean(exchange.pending_request);
      out.boolean(exchange.pending_update);
      out.boolean(exchange.pending_acknowledgment);
      out.boolean(exchange.peer_more);
      out.boolean(exchange.sent_more);
      out.boolean(exchange.complete_after_reply);
      out.boolean(exchange.helper_active);
      out.boolean(exchange.helper_was_designated_router);
    }
    count(out, interface.nbma_peers);
    for (const auto &peer : interface.nbma_peers) {
      ip_address(out, peer.configuration.address);
      out.integer(peer.configuration.poll_interval_seconds);
      out.integer(peer.configuration.priority);
      ospf_duration(out, peer.hello_remaining);
      out.integer(peer.router_id);
    }
    out.boolean(interface.send_authentication.has_value());
    if (interface.send_authentication)
      ospf_authentication(out, *interface.send_authentication);
    count(out, interface.receive_authentications);
    for (const auto &authentication : interface.receive_authentications)
      ospf_authentication(out, authentication);
    out.integer(interface.authentication_sequence);
    out.integer(interface.authentication_send_key_id);
    out.integer(interface.ipsec_replay_sequence);
    out.integer(interface.network_lsa_sequence);
    out.integer(interface.network_prefix_lsa_sequence);
    out.integer(interface.link_lsa_sequence);
    out.boolean(interface.authentication_required);
    out.boolean(interface.ipsec_replay_sequence_seen);
    out.boolean(interface.network_lsa_originated);
    out.boolean(interface.network_sequence_at_max);
    out.boolean(interface.network_prefix_sequence_at_max);
    out.boolean(interface.link_sequence_at_max);
    out.boolean(interface.network_sequence_wrap_pending);
    out.boolean(interface.network_prefix_sequence_wrap_pending);
    out.boolean(interface.link_sequence_wrap_pending);
  }
  count(out, value.pending_fight_backs);
  for (const auto &entry : value.pending_fight_backs) {
    ospf_lsa_key(out, entry.key);
    count(out, entry.bytes);
    out.octets(entry.bytes);
  }
  count(out, value.pending_sequence_wraps);
  for (const auto &entry : value.pending_sequence_wraps)
    ospf_lsa_key(out, entry);
  count(out, value.coordinator_lsas);
  for (const auto &entry : value.coordinator_lsas) {
    ospf_coordinator_advertisement(out, entry.advertisement);
    ospf_lsa_key(out, entry.key);
    out.integer(entry.sequence);
    out.boolean(entry.withdrawing);
    out.boolean(entry.sequence_at_max);
    out.boolean(entry.sequence_wrap_pending);
  }
  count(out, value.virtual_endpoint_addresses);
  for (const auto &address : value.virtual_endpoint_addresses)
    ipv6(out, address);
  count(out, value.pending_coordinator_advertisements);
  for (const auto &entry : value.pending_coordinator_advertisements)
    ospf_coordinator_advertisement(out, entry);
  ospf_duration(out, value.last_local_origination_age);
  ospf_duration(out, value.local_origination_remaining);
  ospf_duration(out, value.spf_remaining);
  ospf_duration(out, value.last_spf_started_age);
  ospf_duration(out, value.current_lsa_delay);
  ospf_duration(out, value.current_spf_delay);
  out.integer(value.route_generation);
  out.integer(value.next_dd_sequence);
  out.integer(value.next_coordinator_link_state_id);
  out.integer(value.router_lsa_sequence);
  out.integer(value.prefix_lsa_sequence);
  out.integer(value.router_information_lsa_sequence);
  out.integer(value.route_recalculation_status);
  out.integer(value.run_ready_status);
  out.integer(value.local_origination_status);
  out.integer(value.local_origination_install_result);
  out.boolean(value.coordinator_reconcile_pending);
  out.boolean(value.router_sequence_at_max);
  out.boolean(value.prefix_sequence_at_max);
  out.boolean(value.router_information_sequence_at_max);
  out.boolean(value.router_sequence_wrap_pending);
  out.boolean(value.prefix_sequence_wrap_pending);
  out.boolean(value.router_information_sequence_wrap_pending);
  out.boolean(value.area_border_router);
  out.boolean(value.autonomous_system_boundary_router);
  out.boolean(value.virtual_link_endpoint);
  out.boolean(value.overload);
  out.boolean(value.graceful_restart_helper);
  out.boolean(value.loop_free_alternates);
}

bool ospf_process_checkpoint(
    Reader &in, ospf::InstanceProcessCheckpoint &value) {
  std::uint32_t size{};
  if (!ospf_lsa_database(in, value.database) ||
      !count(in, size, device_catalog::maximum_ports_per_router + 1U))
    return false;
  value.interfaces.resize(size);
  for (auto &interface : value.interfaces) {
    if (!ospf_process_interface_configuration(
            in, interface.configuration))
      return false;
    if (!ospf_interface_runtime(in, interface.runtime))
      return false;
    if (!count(in, size,
               device_catalog::ospf_neighbors_per_interface))
      return false;
    interface.exchanges.resize(size);
    for (auto &exchange : interface.exchanges) {
      std::uint32_t summary_cursor{};
      std::uint32_t request_cursor{};
      std::uint32_t update_cursor{};
      if (!ospf_database_exchange(in, exchange.database) ||
          !in.integer(exchange.router_id) ||
          exchange.router_id == 0U ||
          !in.integer(exchange.dd_sequence) ||
          !in.integer(summary_cursor) ||
          !in.integer(request_cursor) ||
          !in.integer(update_cursor) ||
          !ospf_duration(in, exchange.dd_retransmit_remaining) ||
          !ospf_duration(in, exchange.request_retransmit_remaining) ||
          !ospf_duration(in, exchange.update_retransmit_remaining) ||
          !ipv4(in, exchange.ipv4_address) ||
          !ipv6(in, exchange.ipv6_address))
        return false;
      exchange.summary_cursor = summary_cursor;
      exchange.request_cursor = request_cursor;
      exchange.update_cursor = update_cursor;
      for (auto &sequence : exchange.authentication_sequences)
        if (!in.integer(sequence))
          return false;
      for (auto &seen : exchange.authentication_sequence_seen)
        if (!in.boolean(seen))
          return false;
      if (!ospf_duration(in, exchange.helper_remaining) ||
          !ospf_duration(in, exchange.helper_elapsed) ||
          !in.boolean(exchange.local_master) ||
          !in.boolean(exchange.negotiation_complete) ||
          !in.boolean(exchange.pending_database_description) ||
          !in.boolean(exchange.pending_request) ||
          !in.boolean(exchange.pending_update) ||
          !in.boolean(exchange.pending_acknowledgment) ||
          !in.boolean(exchange.peer_more) ||
          !in.boolean(exchange.sent_more) ||
          !in.boolean(exchange.complete_after_reply) ||
          !in.boolean(exchange.helper_active) ||
          !in.boolean(exchange.helper_was_designated_router))
        return false;
    }
    if (!count(in, size,
               device_catalog::ospf_neighbors_per_interface))
      return false;
    interface.nbma_peers.resize(size);
    for (auto &peer : interface.nbma_peers)
      if (!ip_address(in, peer.configuration.address) ||
          !in.integer(peer.configuration.poll_interval_seconds) ||
          !in.integer(peer.configuration.priority) ||
          !ospf_duration(in, peer.hello_remaining) ||
          !in.integer(peer.router_id))
        return false;
    bool has_send{};
    if (!in.boolean(has_send))
      return false;
    if (has_send) {
      interface.send_authentication.emplace();
      if (!ospf_authentication(in, *interface.send_authentication))
        return false;
    }
    if (!count(in, size, 64U))
      return false;
    interface.receive_authentications.resize(size);
    for (auto &authentication : interface.receive_authentications)
      if (!ospf_authentication(in, authentication))
        return false;
    if (!in.integer(interface.authentication_sequence) ||
        !in.integer(interface.authentication_send_key_id) ||
        !in.integer(interface.ipsec_replay_sequence) ||
        !in.integer(interface.network_lsa_sequence) ||
        !in.integer(interface.network_prefix_lsa_sequence) ||
        !in.integer(interface.link_lsa_sequence) ||
        !in.boolean(interface.authentication_required) ||
        !in.boolean(interface.ipsec_replay_sequence_seen) ||
        !in.boolean(interface.network_lsa_originated) ||
        !in.boolean(interface.network_sequence_at_max) ||
        !in.boolean(interface.network_prefix_sequence_at_max) ||
        !in.boolean(interface.link_sequence_at_max) ||
        !in.boolean(interface.network_sequence_wrap_pending) ||
        !in.boolean(interface.network_prefix_sequence_wrap_pending) ||
        !in.boolean(interface.link_sequence_wrap_pending))
      return false;
  }
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.pending_fight_backs.resize(size);
  for (auto &entry : value.pending_fight_backs) {
    std::uint32_t bytes{};
    if (!ospf_lsa_key(in, entry.key) ||
        !count(in, bytes, packet::maximum_frame_octets) ||
        bytes < packet::ospf::lsa_header_octets)
      return false;
    entry.bytes.resize(bytes);
    if (!in.octets(entry.bytes))
      return false;
  }
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.pending_sequence_wraps.resize(size);
  for (auto &entry : value.pending_sequence_wraps)
    if (!ospf_lsa_key(in, entry))
      return false;
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.coordinator_lsas.resize(size);
  for (auto &entry : value.coordinator_lsas)
    if (!ospf_coordinator_advertisement(in, entry.advertisement) ||
        !ospf_lsa_key(in, entry.key) || !in.integer(entry.sequence) ||
        !in.boolean(entry.withdrawing) ||
        !in.boolean(entry.sequence_at_max) ||
        !in.boolean(entry.sequence_wrap_pending))
      return false;
  if (!count(in, size, device_catalog::maximum_ports_per_router + 1U))
    return false;
  value.virtual_endpoint_addresses.resize(size);
  for (auto &address : value.virtual_endpoint_addresses)
    if (!ipv6(in, address))
      return false;
  if (!count(in, size, device_catalog::ospf_lsas_per_instance))
    return false;
  value.pending_coordinator_advertisements.resize(size);
  for (auto &entry : value.pending_coordinator_advertisements)
    if (!ospf_coordinator_advertisement(in, entry))
      return false;
  return ospf_duration(in, value.last_local_origination_age) &&
         ospf_duration(in, value.local_origination_remaining) &&
         ospf_duration(in, value.spf_remaining) &&
         ospf_duration(in, value.last_spf_started_age) &&
         ospf_duration(in, value.current_lsa_delay) &&
         ospf_duration(in, value.current_spf_delay) &&
         in.integer(value.route_generation) &&
         in.integer(value.next_dd_sequence) &&
         in.integer(value.next_coordinator_link_state_id) &&
         in.integer(value.router_lsa_sequence) &&
         in.integer(value.prefix_lsa_sequence) &&
         in.integer(value.router_information_lsa_sequence) &&
         in.integer(value.route_recalculation_status) &&
         value.route_recalculation_status <=
             ospf::RouteRecalculationStatus::allocation_failed &&
         in.integer(value.run_ready_status) &&
         value.run_ready_status <=
             ospf::RunReadyStatus::request_encoding_rejected &&
         in.integer(value.local_origination_status) &&
         value.local_origination_status <=
             ospf::LocalOriginationStatus::allocation_failed &&
         in.integer(value.local_origination_install_result) &&
         value.local_origination_install_result <=
             ospf::InstallResult::capacity_exhausted &&
         in.boolean(value.coordinator_reconcile_pending) &&
         in.boolean(value.router_sequence_at_max) &&
         in.boolean(value.prefix_sequence_at_max) &&
         in.boolean(value.router_information_sequence_at_max) &&
         in.boolean(value.router_sequence_wrap_pending) &&
         in.boolean(value.prefix_sequence_wrap_pending) &&
         in.boolean(value.router_information_sequence_wrap_pending) &&
         in.boolean(value.area_border_router) &&
         in.boolean(value.autonomous_system_boundary_router) &&
         in.boolean(value.virtual_link_endpoint) &&
         in.boolean(value.overload) &&
         in.boolean(value.graceful_restart_helper) &&
         in.boolean(value.loop_free_alternates);
}

void ospf_process_definition(Writer &out,
                             const ospf::ControlCommand &value) {
  ospf_process_identity(out, value.process);
  out.integer(value.router_id);
  out.integer(value.initial_dd_sequence);
  out.integer(value.maximum_interfaces);
  out.integer(value.default_metric);
  out.integer(value.router_preference);
  out.integer(value.external_preference);
  out.integer(value.spf_initial_wait_milliseconds);
  out.integer(value.spf_second_wait_milliseconds);
  out.integer(value.spf_maximum_wait_milliseconds);
  out.integer(value.lsa_initial_wait_milliseconds);
  out.integer(value.lsa_second_wait_milliseconds);
  out.integer(value.lsa_maximum_wait_milliseconds);
  out.integer(value.area_type);
  out.boolean(value.summaries);
  out.boolean(value.nssa_translate_always);
  out.boolean(value.asbr);
  out.boolean(value.graceful_restart_helper);
  out.boolean(value.loopfree_alternates);
  out.boolean(value.overload);
}

bool ospf_process_definition(Reader &in,
                             ospf::ControlCommand &value) noexcept {
  value.kind = ospf::ControlCommandKind::stage_process;
  return ospf_process_identity(in, value.process) &&
         in.integer(value.router_id) && value.router_id != 0U &&
         in.integer(value.initial_dd_sequence) &&
         in.integer(value.maximum_interfaces) &&
         value.maximum_interfaces != 0U &&
         value.maximum_interfaces <=
             device_catalog::maximum_ports_per_router + 1U &&
         in.integer(value.default_metric) &&
         in.integer(value.router_preference) &&
         in.integer(value.external_preference) &&
         in.integer(value.spf_initial_wait_milliseconds) &&
         in.integer(value.spf_second_wait_milliseconds) &&
         in.integer(value.spf_maximum_wait_milliseconds) &&
         in.integer(value.lsa_initial_wait_milliseconds) &&
         in.integer(value.lsa_second_wait_milliseconds) &&
         in.integer(value.lsa_maximum_wait_milliseconds) &&
         in.integer(value.area_type) &&
         value.area_type <= ospf::AreaType::nssa &&
         in.boolean(value.summaries) &&
         in.boolean(value.nssa_translate_always) &&
         in.boolean(value.asbr) &&
         in.boolean(value.graceful_restart_helper) &&
         in.boolean(value.loopfree_alternates) &&
         in.boolean(value.overload);
}

void ospf_range(Writer &out,
                const ospf::AreaRangeConfiguration &value) {
  ip_address(out, value.prefix.network);
  out.integer(value.prefix.length);
  out.boolean(value.advertised_metric.has_value());
  if (value.advertised_metric)
    out.integer(*value.advertised_metric);
  out.boolean(value.advertise);
}

bool ospf_range(Reader &in,
                ospf::AreaRangeConfiguration &value) noexcept {
  bool has_metric{};
  std::uint32_t metric{};
  if (!ip_address(in, value.prefix.network) ||
      !in.integer(value.prefix.length) ||
      value.prefix.length > ip::address_bits(value.prefix.network.family) ||
      !in.boolean(has_metric) ||
      (has_metric && !in.integer(metric)) ||
      !in.boolean(value.advertise))
    return false;
  value.advertised_metric =
      has_metric ? std::optional<std::uint32_t>{metric} : std::nullopt;
  return true;
}

void ospf_virtual_link(
    Writer &out, const ospf::ProcessVirtualLinkConfiguration &value) {
  out.integer(value.interface_id);
  out.integer(value.transit_area_id);
  out.integer(value.remote_router_id);
  out.integer(value.hello_interval_seconds);
  out.integer(value.dead_interval_seconds);
  out.integer(value.retransmit_interval_seconds);
  out.integer(value.transmit_delay_seconds);
  out.integer(value.options);
  out.integer(value.authentication);
  out.boolean(value.admin_enabled);
}

bool ospf_virtual_link(
    Reader &in, ospf::ProcessVirtualLinkConfiguration &value) noexcept {
  return in.integer(value.interface_id) && value.interface_id != 0U &&
         in.integer(value.transit_area_id) &&
         value.transit_area_id != 0U &&
         in.integer(value.remote_router_id) &&
         value.remote_router_id != 0U &&
         in.integer(value.hello_interval_seconds) &&
         in.integer(value.dead_interval_seconds) &&
         in.integer(value.retransmit_interval_seconds) &&
         in.integer(value.transmit_delay_seconds) &&
         in.integer(value.options) &&
         in.integer(value.authentication) &&
         value.authentication <=
             ospf::AuthenticationMode::ipsec_security_association &&
         in.boolean(value.admin_enabled);
}

void ospf_control_checkpoint(
    Writer &out, const ospf::ControlWorkerCheckpoint &value) {
  count(out, value.processes);
  for (const auto &process : value.processes) {
    ospf_process_definition(out, process.definition);
    ospf_process_checkpoint(out, process.process);
    count(out, process.ranges);
    for (const auto &range : process.ranges)
      ospf_range(out, range);
    count(out, process.virtual_links);
    for (const auto &link : process.virtual_links)
      ospf_virtual_link(out, link);
    count(out, process.authentications);
    for (const auto &authentication : process.authentications) {
      ospf_process_identity(out, authentication.process);
      out.integer(authentication.interface_id);
      ospf_authentication(out, authentication.authentication);
      out.boolean(authentication.authentication_receive);
      out.boolean(authentication.authentication_send);
    }
    count(out, process.external_routes);
    for (const auto &route : process.external_routes)
      ospf_coordinator_advertisement(out, route);
    out.integer(process.published_route_generation);
    out.integer(process.coordinated_route_generation);
  }
  for (const auto generation : value.next_route_generation)
    out.integer(generation);
  for (const auto device : value.active_devices)
    handle(out, device);
  for (const auto pending : value.route_publication_pending)
    out.boolean(pending);
  for (const auto pending : value.route_coordination_pending)
    out.boolean(pending);
}

bool ospf_control_checkpoint(
    Reader &in, ospf::ControlWorkerCheckpoint &value) {
  std::uint32_t size{};
  const auto maximum_processes =
      device_catalog::maximum_routers *
      (device_catalog::ospf_v2_instances_per_router +
       device_catalog::ospf_v3_instances_per_router);
  if (!count(in, size, maximum_processes))
    return false;
  value.processes.resize(size);
  for (auto &process : value.processes) {
    if (!ospf_process_definition(in, process.definition))
      return false;
    if (!ospf_process_checkpoint(in, process.process))
      return false;
    if (!count(in, size, device_catalog::ospf_lsas_per_instance))
      return false;
    process.ranges.resize(size);
    for (auto &range : process.ranges)
      if (!ospf_range(in, range))
        return false;
    if (!count(in, size, device_catalog::ospf_lsas_per_instance))
      return false;
    process.virtual_links.resize(size);
    for (auto &link : process.virtual_links)
      if (!ospf_virtual_link(in, link))
        return false;
    if (!count(in, size,
               (device_catalog::maximum_ports_per_router + 1U) * 64U))
      return false;
    process.authentications.resize(size);
    for (auto &authentication : process.authentications) {
      authentication.kind =
          ospf::ControlCommandKind::stage_authentication;
      if (!ospf_process_identity(in, authentication.process) ||
          !in.integer(authentication.interface_id) ||
          !ospf_authentication(in, authentication.authentication) ||
          !in.boolean(authentication.authentication_receive) ||
          !in.boolean(authentication.authentication_send))
        return false;
    }
    if (!count(in, size, device_catalog::ospf_lsas_per_instance))
      return false;
    process.external_routes.resize(size);
    for (auto &route : process.external_routes)
      if (!ospf_coordinator_advertisement(in, route))
        return false;
    if (!in.integer(process.published_route_generation) ||
        !in.integer(process.coordinated_route_generation))
      return false;
  }
  for (auto &generation : value.next_route_generation)
    if (!in.integer(generation))
      return false;
  for (auto &device : value.active_devices)
    if (!handle(in, device))
      return false;
  for (auto &pending : value.route_publication_pending)
    if (!in.boolean(pending))
      return false;
  for (auto &pending : value.route_coordination_pending)
    if (!in.boolean(pending))
      return false;
  return true;
}

void network_state(Writer &out, const NetworkPlaneCheckpoint &state) {
  count(out, state.routers);
  for (const auto &router : state.routers) {
    handle(out, router.device);
    forwarder_state(out, router.forwarding);
    out.boolean(router.management_endpoint.has_value());
    if (router.management_endpoint)
      endpoint_state(out, *router.management_endpoint);
    mac(out, router.management_mac);
    ipv4(out, router.management_address);
    ipv4(out, router.management_gateway);
    out.integer(router.management_prefix_length);
    out.integer(router.management_mtu);
    out.integer(router.management_interface_id);
    out.boolean(router.management_ipv6_autoconfiguration);
    out.boolean(router.management_configured);
    out.boolean(router.management_link_signal);
    out.boolean(router.bof_dhcpv4.has_value());
    if (router.bof_dhcpv4)
      dhcpv4_service(out, *router.bof_dhcpv4);
    out.boolean(router.bof_dhcpv6.has_value());
    if (router.bof_dhcpv6)
      dhcpv6_service(out, *router.bof_dhcpv6);
    out.integer(router.bof_dhcpv4_timeout_remaining_nanoseconds);
    out.integer(router.bof_dhcpv6_timeout_remaining_nanoseconds);
  }
  count(out, state.hosts);
  for (const auto &host : state.hosts)
    host_state(out, host);
  count(out, state.switches);
  for (const auto &ethernet_switch : state.switches)
    switch_state(out, ethernet_switch);
  fabric_state(out, state.fabric);
  capture_state(out, state.capture);
  ospf_control_checkpoint(out, state.ospf);
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
  for (auto &router : state.routers) {
    bool present{};
    if (!handle(in, router.device) || !forwarder_state(in, router.forwarding) ||
        !in.boolean(present))
      return false;
    if (present) {
      router.management_endpoint.emplace();
      if (!endpoint_state(in, *router.management_endpoint))
        return false;
    }
    if (!mac(in, router.management_mac) ||
        !ipv4(in, router.management_address) ||
        !ipv4(in, router.management_gateway) ||
        !in.integer(router.management_prefix_length) ||
        !in.integer(router.management_mtu) ||
        !in.integer(router.management_interface_id) ||
        !in.boolean(router.management_ipv6_autoconfiguration) ||
        !in.boolean(router.management_configured) ||
        !in.boolean(router.management_link_signal) ||
        !in.boolean(present))
      return false;
    if (present) {
      router.bof_dhcpv4.emplace();
      if (!dhcpv4_service(in, *router.bof_dhcpv4))
        return false;
    }
    if (!in.boolean(present))
      return false;
    if (present) {
      router.bof_dhcpv6.emplace();
      if (!dhcpv6_service(in, *router.bof_dhcpv6))
        return false;
    }
    if (!in.integer(router.bof_dhcpv4_timeout_remaining_nanoseconds) ||
        !in.integer(router.bof_dhcpv6_timeout_remaining_nanoseconds))
      return false;
  }
  if (!count(in, size, device_catalog::maximum_hosts))
    return false;
  state.hosts.resize(size);
  for (auto &host : state.hosts)
    if (!host_state(in, host))
      return false;
  if (!count(in, size, device_catalog::maximum_switches))
    return false;
  state.switches.resize(size);
  for (auto &ethernet_switch : state.switches)
    if (!switch_state(in, ethernet_switch))
      return false;
  if (!fabric_state(in, state.fabric))
    return false;
  if (!capture_state(in, state.capture))
    return false;
  if (!ospf_control_checkpoint(in, state.ospf))
    return false;
  if (!count(in, size, device_catalog::maximum_active_capture_points))
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
bool portable_configuration(Reader &in, PortableConfigurationCheckpoint &state);

void mld_global_intent(Writer &out, const MldGlobalIntent &value) {
  out.integer(value.query_interval.count());
  out.integer(value.query_response_interval.count());
  out.integer(value.last_listener_query_interval.count());
  out.integer(value.robustness_variable);
  mld_ssm_translations(out, value.ssm_translations);
  out.boolean(value.configured);
  out.boolean(value.enabled);
  out.boolean(value.query_interval_configured);
  out.boolean(value.query_response_interval_configured);
  out.boolean(value.last_listener_query_interval_configured);
  out.boolean(value.robustness_variable_configured);
}

bool mld_global_intent(Reader &in, MldGlobalIntent &value) noexcept {
  std::int64_t query_seconds{};
  std::int64_t response_milliseconds{};
  std::int64_t last_listener_milliseconds{};
  if (!in.integer(query_seconds) || !in.integer(response_milliseconds) ||
      !in.integer(last_listener_milliseconds) ||
      !in.integer(value.robustness_variable) ||
      !mld_ssm_translations(in, value.ssm_translations) ||
      !in.boolean(value.configured) || !in.boolean(value.enabled) ||
      !in.boolean(value.query_interval_configured) ||
      !in.boolean(value.query_response_interval_configured) ||
      !in.boolean(value.last_listener_query_interval_configured) ||
      !in.boolean(value.robustness_variable_configured))
    return false;
  value.query_interval = std::chrono::seconds{query_seconds};
  value.query_response_interval =
      std::chrono::milliseconds{response_milliseconds};
  value.last_listener_query_interval =
      std::chrono::milliseconds{last_listener_milliseconds};
  if (!value.valid() || (!value.configured && !value.ssm_translations.empty()))
    return false;
  for (std::size_t index = 0; index < value.ssm_translations.size(); ++index) {
    const auto &translation = value.ssm_translations[index];
    if (!ip::is_multicast(translation.start) ||
        !ip::is_multicast(translation.end) ||
        translation.end < translation.start ||
        ip::is_unspecified(translation.source) ||
        ip::is_multicast(translation.source) ||
        std::find(value.ssm_translations.begin(),
                  value.ssm_translations.begin() +
                      static_cast<std::ptrdiff_t>(index),
                  translation) !=
            value.ssm_translations.begin() + static_cast<std::ptrdiff_t>(index))
      return false;
  }
  return true;
}

bool valid_mld_interface_intent(
    const PortableInterfaceIntentCheckpoint &interface,
    const MldGlobalIntent &global) noexcept {
  if (!interface.mld_configured)
    return !interface.mld_enabled && !interface.mld_version_configured &&
           interface.mld_version == device_catalog::mld_default_version &&
           interface.mld_query_interval == std::chrono::seconds::zero() &&
           interface.mld_query_response_interval ==
               std::chrono::milliseconds::zero() &&
           interface.mld_last_listener_query_interval ==
               std::chrono::milliseconds::zero() &&
           interface.mld_robustness_variable == 0U &&
           interface.mld_maximum_number_groups == 0U &&
           interface.mld_maximum_number_group_sources == 0U &&
           interface.mld_maximum_number_sources == 0U &&
           interface.mld_router_alert_check &&
           !interface.mld_query_interval_configured &&
           !interface.mld_query_response_interval_configured &&
           !interface.mld_last_listener_query_interval_configured &&
           !interface.mld_robustness_variable_configured &&
           !interface.mld_maximum_number_groups_configured &&
           !interface.mld_maximum_number_group_sources_configured &&
           !interface.mld_maximum_number_sources_configured &&
           !interface.mld_router_alert_check_configured &&
           interface.mld_import_policy.empty() &&
           interface.mld_ssm_translations.empty() &&
           interface.mld_static_groups.empty();
  if ((!interface.mld_query_interval_configured &&
       interface.mld_query_interval != std::chrono::seconds::zero()) ||
      (!interface.mld_query_response_interval_configured &&
       interface.mld_query_response_interval !=
           std::chrono::milliseconds::zero()) ||
      (!interface.mld_last_listener_query_interval_configured &&
       interface.mld_last_listener_query_interval !=
           std::chrono::milliseconds::zero()) ||
      (!interface.mld_robustness_variable_configured &&
       interface.mld_robustness_variable != 0U) ||
      (!interface.mld_maximum_number_groups_configured &&
       interface.mld_maximum_number_groups != 0U) ||
      (!interface.mld_maximum_number_group_sources_configured &&
       interface.mld_maximum_number_group_sources != 0U) ||
      (!interface.mld_maximum_number_sources_configured &&
       interface.mld_maximum_number_sources != 0U) ||
      (interface.mld_maximum_number_groups_configured !=
       (interface.mld_maximum_number_groups != 0U)) ||
      (interface.mld_maximum_number_group_sources_configured !=
       (interface.mld_maximum_number_group_sources != 0U)) ||
      (interface.mld_maximum_number_sources_configured !=
       (interface.mld_maximum_number_sources != 0U)) ||
      (!interface.mld_router_alert_check_configured &&
       !interface.mld_router_alert_check) ||
      interface.mld_maximum_number_groups >
          device_catalog::mld_maximum_number_groups ||
      interface.mld_maximum_number_group_sources >
          device_catalog::mld_maximum_number_group_sources ||
      interface.mld_maximum_number_sources >
          device_catalog::mld_maximum_number_sources ||
      interface.mld_ssm_translations.size() >
          device_catalog::mld_router_group_sources_per_interface)
    return false;
  for (std::size_t index = 0; index < interface.mld_ssm_translations.size();
       ++index) {
    const auto &translation = interface.mld_ssm_translations[index];
    if (!ip::is_multicast(translation.start) ||
        !ip::is_multicast(translation.end) ||
        translation.end < translation.start ||
        ip::is_unspecified(translation.source) ||
        ip::is_multicast(translation.source) ||
        std::find(interface.mld_ssm_translations.begin(),
                  interface.mld_ssm_translations.begin() +
                      static_cast<std::ptrdiff_t>(index),
                  translation) != interface.mld_ssm_translations.begin() +
                                      static_cast<std::ptrdiff_t>(index))
      return false;
  }
  if (!interface.mld_version_configured &&
      interface.mld_version != device_catalog::mld_default_version)
    return false;
  if (interface.mld_static_groups.size() >
      device_catalog::mld_router_groups_per_interface)
    return false;
  for (std::size_t index = 0; index < interface.mld_static_groups.size();
       ++index) {
    const auto &group = interface.mld_static_groups[index];
    if (!ip::is_multicast(group.multicast_address) ||
        (group.range && (!ip::is_multicast(group.range_end) ||
                         ip::is_unspecified(group.range_step) ||
                         group.range_end < group.multicast_address)) ||
        (!group.range && (group.range_end != packet::Ipv6{} ||
                          group.range_step != packet::Ipv6{})) ||
        group.sources.size() > device_catalog::mld_router_sources_per_group ||
        (group.starg && !group.sources.empty()) ||
        std::any_of(
            group.sources.begin(), group.sources.end(), [](const auto &source) {
              return ip::is_unspecified(source) || ip::is_multicast(source);
            }))
      return false;
    for (std::size_t other = 0; other < index; ++other)
      if (interface.mld_static_groups[other].multicast_address ==
          group.multicast_address)
        return false;
    for (std::size_t source = 0; source < group.sources.size(); ++source)
      if (std::find(group.sources.begin(), group.sources.begin() + source,
                    group.sources[source]) != group.sources.begin() + source)
        return false;
  }
  auto effective = global;
  effective.configured = true;
  effective.enabled = false;
  if (interface.mld_query_interval_configured)
    effective.query_interval = interface.mld_query_interval;
  if (interface.mld_query_response_interval_configured)
    effective.query_response_interval = interface.mld_query_response_interval;
  if (interface.mld_last_listener_query_interval_configured)
    effective.last_listener_query_interval =
        interface.mld_last_listener_query_interval;
  if (interface.mld_robustness_variable_configured)
    effective.robustness_variable = interface.mld_robustness_variable;
  return global.configured && effective.valid();
}

bool valid_ipv6_neighbor_intents(
    std::span<const PortableInterfaceIntentCheckpoint> interfaces) noexcept {
  std::size_t total{};
  std::size_t static_arp_total{};
  for (const auto &interface : interfaces) {
    if (interface.ipv6_unsolicited_learning > Ipv6UnsolicitedLearning::both ||
        interface.ipv6_proactive_refresh > Ipv6UnsolicitedLearning::both ||
        (!interface.ipv6_unsolicited_learning_configured &&
         interface.ipv6_unsolicited_learning !=
             Ipv6UnsolicitedLearning::none) ||
        (!interface.ipv6_proactive_refresh_configured &&
         interface.ipv6_proactive_refresh != Ipv6UnsolicitedLearning::none) ||
        (interface.ipv6_nd_reachable_time_configured !=
         (interface.ipv6_nd_reachable_time_seconds != 0U)) ||
        (interface.ipv6_nd_stale_time_configured !=
         (interface.ipv6_nd_stale_time_seconds != 0U)) ||
        (interface.ipv6_nd_reachable_time_configured &&
         (interface.ipv6_nd_reachable_time_seconds <
              device_catalog::nd_minimum_reachable_time_seconds ||
          interface.ipv6_nd_reachable_time_seconds >
              device_catalog::nd_maximum_reachable_time_seconds)) ||
        (interface.ipv6_nd_stale_time_configured &&
         (interface.ipv6_nd_stale_time_seconds <
              device_catalog::nd_minimum_stale_time_seconds ||
          interface.ipv6_nd_stale_time_seconds >
              device_catalog::nd_maximum_stale_time_seconds)) ||
        interface.ipv6_neighbor_limit >
            device_catalog::nd_maximum_neighbor_limit ||
        interface.ipv6_neighbor_limit_threshold_percent > 100U ||
        (!interface.ipv6_neighbor_limit_configured &&
         interface.ipv6_neighbor_limit != 0U) ||
        (!interface.ipv6_neighbor_limit_log_only_configured &&
         interface.ipv6_neighbor_limit_log_only) ||
        (!interface.ipv6_neighbor_limit_threshold_configured &&
         interface.ipv6_neighbor_limit_threshold_percent !=
             device_catalog::nd_default_neighbor_limit_threshold_percent) ||
        (!interface.ipv6_address_configured &&
         (!interface.static_ipv6_neighbors.empty() ||
          interface.ipv6_unsolicited_learning_configured ||
          interface.ipv6_proactive_refresh_configured ||
          interface.ipv6_nd_reachable_time_configured ||
          interface.ipv6_nd_stale_time_configured ||
          interface.ipv6_neighbor_limit_configured ||
          interface.ipv6_neighbor_limit_log_only_configured ||
          interface.ipv6_neighbor_limit_threshold_configured)) ||
        interface.static_ipv6_neighbors.size() >
            device_catalog::ipv6_neighbor_entries_per_router - total)
      return false;
    if ((!interface.address_configured &&
         !interface.static_ipv4_neighbors.empty()) ||
        interface.static_ipv4_neighbors.size() >
            device_catalog::static_arp_entries_per_router - static_arp_total)
      return false;
    static_arp_total += interface.static_ipv4_neighbors.size();
    const auto mask = interface.prefix_length == 0U
                          ? 0U
                          : std::numeric_limits<std::uint32_t>::max()
                                << (32U - interface.prefix_length);
    const auto network = interface.address & mask;
    const auto broadcast = network | ~mask;
    const bool has_broadcast_addresses = interface.prefix_length <= 30U;
    for (std::size_t index = 0; index < interface.static_ipv4_neighbors.size();
         ++index) {
      const auto &neighbor = interface.static_ipv4_neighbors[index];
      const bool usable_mac =
          (neighbor.mac[0U] & 1U) == 0U &&
          std::any_of(neighbor.mac.begin(), neighbor.mac.end(),
                      [](auto byte) { return byte != 0U; });
      if (!usable_mac || neighbor.address == 0U ||
          neighbor.address == 0xffffffffU ||
          (neighbor.address & mask) != network ||
          neighbor.address == interface.address ||
          (has_broadcast_addresses &&
           (neighbor.address == network || neighbor.address == broadcast)) ||
          std::any_of(interface.static_ipv4_neighbors.begin(),
                      interface.static_ipv4_neighbors.begin() +
                          static_cast<std::ptrdiff_t>(index),
                      [&](const auto &prior) {
                        return prior.address == neighbor.address;
                      }))
        return false;
    }
    total += interface.static_ipv6_neighbors.size();
    for (std::size_t index = 0; index < interface.static_ipv6_neighbors.size();
         ++index) {
      const auto &neighbor = interface.static_ipv6_neighbors[index];
      const bool usable_mac =
          (neighbor.mac[0U] & 1U) == 0U &&
          std::any_of(neighbor.mac.begin(), neighbor.mac.end(),
                      [](auto byte) { return byte != 0U; });
      if (!usable_mac || ip::is_unspecified(neighbor.address) ||
          ip::is_multicast(neighbor.address) ||
          (!ip::is_link_local(neighbor.address) &&
           ip::mask(neighbor.address, interface.ipv6_prefix_length) !=
               ip::mask(interface.ipv6_address,
                        interface.ipv6_prefix_length)) ||
          std::any_of(interface.static_ipv6_neighbors.begin(),
                      interface.static_ipv6_neighbors.begin() +
                          static_cast<std::ptrdiff_t>(index),
                      [&](const auto &prior) {
                        return prior.address == neighbor.address;
                      }))
        return false;
    }
  }
  return true;
}

bool valid_ipv6_neighbor_defaults(std::uint32_t reachable, std::uint32_t stale,
                                  bool reachable_configured,
                                  bool stale_configured) noexcept {
  // Portable candidates preserve explicit presence. An absent leaf must carry
  // its release default so later equality, delete and inheritance decisions do
  // not depend on untrusted dormant bytes from a checkpoint.
  return reachable >= device_catalog::nd_minimum_reachable_time_seconds &&
         reachable <= device_catalog::nd_maximum_reachable_time_seconds &&
         stale >= device_catalog::nd_minimum_stale_time_seconds &&
         stale <= device_catalog::nd_maximum_stale_time_seconds &&
         (reachable_configured ||
          reachable == device_catalog::nd_default_reachable_time_seconds) &&
         (stale_configured ||
          stale == device_catalog::nd_default_stale_time_seconds);
}

bool valid_mld_policy_references(
    const std::vector<MldPolicyPrefixListIntent> &prefix_lists,
    const std::vector<MldNamedImportPolicyIntent> &policies,
    const std::vector<PortableInterfaceIntentCheckpoint> &interfaces) noexcept {
  const auto list_exists = [&](std::string_view name) {
    return name.empty() ||
           std::any_of(prefix_lists.begin(), prefix_lists.end(),
                       [&](const auto &list) { return list.name == name; });
  };
  if (std::any_of(policies.begin(), policies.end(), [&](const auto &policy) {
        return std::any_of(policy.entries.begin(), policy.entries.end(),
                           [&](const auto &entry) {
                             return !list_exists(entry.group_prefix_list) ||
                                    !list_exists(entry.source_prefix_list);
                           });
      }))
    return false;
  return std::none_of(
      interfaces.begin(), interfaces.end(), [&](const auto &interface) {
        if (interface.mld_import_policy.empty())
          return false;
        return std::none_of(policies.begin(), policies.end(),
                            [&](const auto &policy) {
                              return policy.name == interface.mld_import_policy;
                            });
      });
}

void portable_interface(Writer &out,
                        const PortableInterfaceIntentCheckpoint &interface) {
  out.string(interface.name);
  out.string(interface.port_id);
  mac(out, interface.mac);
  out.integer(interface.address);
  out.integer(interface.prefix_length);
  out.integer(interface.arp_timeout_seconds);
  out.integer(interface.arp_retry_deciseconds);
  out.boolean(interface.arp_timeout_configured);
  out.boolean(interface.arp_retry_configured);
  out.integer(interface.icmp_redirect_maximum);
  out.integer(interface.icmp_redirect_interval_seconds);
  out.boolean(interface.icmp_redirects_enabled);
  out.boolean(interface.icmp_redirect_admin_configured);
  out.boolean(interface.icmp_redirect_maximum_configured);
  out.boolean(interface.icmp_redirect_interval_configured);
  out.boolean(interface.admin_enabled);
  out.boolean(interface.port_configured);
  out.boolean(interface.address_configured);
  count(out, interface.static_ipv4_neighbors);
  for (const auto &neighbor : interface.static_ipv4_neighbors) {
    out.integer(neighbor.address);
    mac(out, neighbor.mac);
  }
  out.boolean(interface.ipv6_address_configured);
  if (interface.ipv6_address_configured) {
    ipv6(out, interface.ipv6_address);
    ipv6(out, interface.ipv6_link_local);
    out.integer(interface.ipv6_prefix_length);
  }
  count(out, interface.ipv6_addresses);
  for (const auto &address : interface.ipv6_addresses) {
    ipv6(out, address.address);
    out.integer(address.primary_preference);
    out.integer(address.tag);
    out.integer(address.prefix_length);
    out.boolean(address.duplicate_address_detection);
    out.boolean(address.eui64);
    mac(out, address.eui64_source_mac);
    out.boolean(address.tag_configured);
  }
  out.integer(interface.ipv6_unsolicited_learning);
  out.boolean(interface.ipv6_unsolicited_learning_configured);
  out.integer(interface.ipv6_nd_reachable_time_seconds);
  out.integer(interface.ipv6_nd_stale_time_seconds);
  out.integer(interface.ipv6_proactive_refresh);
  out.integer(interface.ipv6_neighbor_limit);
  out.integer(interface.ipv6_neighbor_limit_threshold_percent);
  out.boolean(interface.ipv6_nd_reachable_time_configured);
  out.boolean(interface.ipv6_nd_stale_time_configured);
  out.boolean(interface.ipv6_proactive_refresh_configured);
  out.boolean(interface.ipv6_neighbor_limit_configured);
  out.boolean(interface.ipv6_neighbor_limit_log_only);
  out.boolean(interface.ipv6_neighbor_limit_log_only_configured);
  out.boolean(interface.ipv6_neighbor_limit_threshold_configured);
  count(out, interface.static_ipv6_neighbors);
  for (const auto &neighbor : interface.static_ipv6_neighbors) {
    ipv6(out, neighbor.address);
    mac(out, neighbor.mac);
  }
  out.boolean(interface.router_advertisement_configured);
  out.boolean(interface.router_advertisement_enabled);
  out.integer(interface.router_advertisement_leaf_presence);
  for (const auto presence :
       interface.router_advertisement_prefix_leaf_presence)
    out.integer(presence);
  out.boolean(interface.router_advertisement_rdnss_lifetime_configured);
  out.boolean(interface.router_advertisement_include_dns);
  out.boolean(interface.router_advertisement_include_dns_configured);
  if (interface.router_advertisement_configured)
    router_advertisement_config(out, interface.router_advertisement);
  out.integer(interface.icmp6_redirect_maximum);
  out.integer(interface.icmp6_redirect_interval_seconds);
  out.boolean(interface.icmp6_redirects_enabled);
  out.boolean(interface.icmp6_redirect_admin_configured);
  out.boolean(interface.icmp6_redirect_maximum_configured);
  out.boolean(interface.icmp6_redirect_interval_configured);
  out.integer(interface.mld_version);
  out.integer(interface.mld_query_interval.count());
  out.integer(interface.mld_query_response_interval.count());
  out.integer(interface.mld_last_listener_query_interval.count());
  out.integer(interface.mld_robustness_variable);
  out.integer(interface.mld_maximum_number_groups);
  out.integer(interface.mld_maximum_number_group_sources);
  out.integer(interface.mld_maximum_number_sources);
  out.boolean(interface.mld_router_alert_check);
  out.boolean(interface.mld_configured);
  out.boolean(interface.mld_enabled);
  out.boolean(interface.mld_version_configured);
  out.boolean(interface.mld_query_interval_configured);
  out.boolean(interface.mld_query_response_interval_configured);
  out.boolean(interface.mld_last_listener_query_interval_configured);
  out.boolean(interface.mld_robustness_variable_configured);
  out.boolean(interface.mld_maximum_number_groups_configured);
  out.boolean(interface.mld_maximum_number_group_sources_configured);
  out.boolean(interface.mld_maximum_number_sources_configured);
  out.boolean(interface.mld_router_alert_check_configured);
  out.string(interface.mld_import_policy);
  mld_ssm_translations(out, interface.mld_ssm_translations);
  count(out, interface.mld_static_groups);
  for (const auto &group : interface.mld_static_groups) {
    ipv6(out, group.multicast_address);
    ipv6(out, group.range_end);
    ipv6(out, group.range_step);
    count(out, group.sources);
    for (const auto &source : group.sources)
      ipv6(out, source);
    out.boolean(group.starg);
    out.boolean(group.range);
  }
  out.boolean(interface.dhcpv4_relay.has_value());
  if (interface.dhcpv4_relay)
    dhcpv4_relay_policy(out, *interface.dhcpv4_relay);
  out.string(interface.dhcpv6_local_server);
}

bool portable_interface(Reader &in,
                        PortableInterfaceIntentCheckpoint &interface,
                        bool candidate = false) {
  if (!in.string(interface.name, 64) || interface.name.empty() ||
      !in.string(interface.port_id, 32) || !mac(in, interface.mac) ||
      !in.integer(interface.address) || !in.integer(interface.prefix_length) ||
      interface.prefix_length > 32U ||
      !in.integer(interface.arp_timeout_seconds) ||
      interface.arp_timeout_seconds >
          device_catalog::arp_timeout_maximum_seconds ||
      !in.integer(interface.arp_retry_deciseconds) ||
      interface.arp_retry_deciseconds <
          device_catalog::arp_retry_minimum_deciseconds ||
      interface.arp_retry_deciseconds >
          device_catalog::arp_retry_maximum_deciseconds ||
      !in.boolean(interface.arp_timeout_configured) ||
      !in.boolean(interface.arp_retry_configured) ||
      (!interface.arp_timeout_configured &&
       interface.arp_timeout_seconds !=
           device_catalog::dynamic_arp_timeout.count()) ||
      (!interface.arp_retry_configured &&
       interface.arp_retry_deciseconds !=
           device_catalog::dynamic_arp_retry_deciseconds) ||
      !in.integer(interface.icmp_redirect_maximum) ||
      !in.integer(interface.icmp_redirect_interval_seconds) ||
      !in.boolean(interface.icmp_redirects_enabled) ||
      !in.boolean(interface.icmp_redirect_admin_configured) ||
      !in.boolean(interface.icmp_redirect_maximum_configured) ||
      !in.boolean(interface.icmp_redirect_interval_configured) ||
      !in.boolean(interface.admin_enabled) ||
      !in.boolean(interface.port_configured) ||
      !in.boolean(interface.address_configured))
    return false;
  std::uint32_t static_ipv4_neighbor_count{};
  if (!count(in, static_ipv4_neighbor_count,
             device_catalog::static_arp_entries_per_router))
    return false;
  interface.static_ipv4_neighbors.resize(static_ipv4_neighbor_count);
  for (auto &neighbor : interface.static_ipv4_neighbors)
    if (!in.integer(neighbor.address) || !mac(in, neighbor.mac))
      return false;
  if (!in.boolean(interface.ipv6_address_configured))
    return false;
  if (interface.ipv6_address_configured &&
      (!ipv6(in, interface.ipv6_address) ||
       !ipv6(in, interface.ipv6_link_local) ||
       !in.integer(interface.ipv6_prefix_length)))
    return false;
  std::uint32_t ipv6_address_count{};
  if (!count(in, ipv6_address_count,
             device_catalog::network_interface_ip_addresses))
    return false;
  interface.ipv6_addresses.resize(ipv6_address_count);
  for (std::size_t index = 0; index < interface.ipv6_addresses.size();
       ++index) {
    auto &address = interface.ipv6_addresses[index];
    if (!ipv6(in, address.address) || !in.integer(address.primary_preference) ||
        !in.integer(address.tag) || !in.integer(address.prefix_length) ||
        address.prefix_length > ip::ipv6_address_bits ||
        !in.boolean(address.duplicate_address_detection) ||
        !in.boolean(address.eui64) || !mac(in, address.eui64_source_mac) ||
        !in.boolean(address.tag_configured) ||
        ip::is_unspecified(address.address) ||
        ip::is_multicast(address.address) ||
        ip::is_link_local(address.address) ||
        (address.eui64 &&
         (address.prefix_length != 64U ||
          ip::mask(address.address, 64U) != address.address ||
          std::none_of(address.eui64_source_mac.begin(),
                       address.eui64_source_mac.end(),
                       [](auto byte) { return byte != 0U; }))) ||
        (!address.eui64 && std::any_of(address.eui64_source_mac.begin(),
                                       address.eui64_source_mac.end(),
                                       [](auto byte) { return byte != 0U; })) ||
        std::any_of(interface.ipv6_addresses.begin(),
                    interface.ipv6_addresses.begin() +
                        static_cast<std::ptrdiff_t>(index),
                    [&](const auto &prior) {
                      return prior.address == address.address;
                    }))
      return false;
  }
  if (!in.integer(interface.ipv6_unsolicited_learning) ||
      interface.ipv6_unsolicited_learning > Ipv6UnsolicitedLearning::both ||
      !in.boolean(interface.ipv6_unsolicited_learning_configured) ||
      !in.integer(interface.ipv6_nd_reachable_time_seconds) ||
      !in.integer(interface.ipv6_nd_stale_time_seconds) ||
      !in.integer(interface.ipv6_proactive_refresh) ||
      interface.ipv6_proactive_refresh > Ipv6UnsolicitedLearning::both ||
      !in.integer(interface.ipv6_neighbor_limit) ||
      !in.integer(interface.ipv6_neighbor_limit_threshold_percent) ||
      !in.boolean(interface.ipv6_nd_reachable_time_configured) ||
      !in.boolean(interface.ipv6_nd_stale_time_configured) ||
      !in.boolean(interface.ipv6_proactive_refresh_configured) ||
      !in.boolean(interface.ipv6_neighbor_limit_configured) ||
      !in.boolean(interface.ipv6_neighbor_limit_log_only) ||
      !in.boolean(interface.ipv6_neighbor_limit_log_only_configured) ||
      !in.boolean(interface.ipv6_neighbor_limit_threshold_configured))
    return false;
  std::uint32_t static_neighbor_count{};
  if (!count(in, static_neighbor_count,
             device_catalog::ipv6_neighbor_entries_per_router))
    return false;
  interface.static_ipv6_neighbors.resize(static_neighbor_count);
  for (auto &neighbor : interface.static_ipv6_neighbors)
    if (!ipv6(in, neighbor.address) || !mac(in, neighbor.mac))
      return false;
  if (!in.boolean(interface.router_advertisement_configured) ||
      !in.boolean(interface.router_advertisement_enabled) ||
      !in.integer(interface.router_advertisement_leaf_presence))
    return false;
  for (auto &presence : interface.router_advertisement_prefix_leaf_presence)
    if (!in.integer(presence))
      return false;
  if (!in.boolean(interface.router_advertisement_rdnss_lifetime_configured) ||
      !in.boolean(interface.router_advertisement_include_dns) ||
      !in.boolean(interface.router_advertisement_include_dns_configured) ||
      (interface.router_advertisement_configured &&
       !router_advertisement_config(in, interface.router_advertisement)) ||
      !in.integer(interface.icmp6_redirect_maximum) ||
      !in.integer(interface.icmp6_redirect_interval_seconds) ||
      !in.boolean(interface.icmp6_redirects_enabled) ||
      !in.boolean(interface.icmp6_redirect_admin_configured) ||
      !in.boolean(interface.icmp6_redirect_maximum_configured) ||
      !in.boolean(interface.icmp6_redirect_interval_configured) ||
      !in.integer(interface.mld_version))
    return false;
  std::int64_t mld_query_seconds{};
  std::int64_t mld_response_milliseconds{};
  std::int64_t mld_last_listener_milliseconds{};
  if (!in.integer(mld_query_seconds) ||
      !in.integer(mld_response_milliseconds) ||
      !in.integer(mld_last_listener_milliseconds) ||
      !in.integer(interface.mld_robustness_variable) ||
      !in.integer(interface.mld_maximum_number_groups) ||
      !in.integer(interface.mld_maximum_number_group_sources) ||
      !in.integer(interface.mld_maximum_number_sources) ||
      !in.boolean(interface.mld_router_alert_check) ||
      !in.boolean(interface.mld_configured) ||
      !in.boolean(interface.mld_enabled) ||
      !in.boolean(interface.mld_version_configured) ||
      !in.boolean(interface.mld_query_interval_configured) ||
      !in.boolean(interface.mld_query_response_interval_configured) ||
      !in.boolean(interface.mld_last_listener_query_interval_configured) ||
      !in.boolean(interface.mld_robustness_variable_configured) ||
      !in.boolean(interface.mld_maximum_number_groups_configured) ||
      !in.boolean(interface.mld_maximum_number_group_sources_configured) ||
      !in.boolean(interface.mld_maximum_number_sources_configured) ||
      !in.boolean(interface.mld_router_alert_check_configured) ||
      !in.string(interface.mld_import_policy,
                 mld::maximum_policy_name_octets) ||
      !mld_ssm_translations(in, interface.mld_ssm_translations))
    return false;
  std::uint32_t static_group_count{};
  if (!count(in, static_group_count,
             device_catalog::mld_router_groups_per_interface))
    return false;
  interface.mld_static_groups.resize(static_group_count);
  for (auto &group : interface.mld_static_groups) {
    std::uint32_t source_count{};
    if (!ipv6(in, group.multicast_address) || !ipv6(in, group.range_end) ||
        !ipv6(in, group.range_step) ||
        !count(in, source_count, device_catalog::mld_router_sources_per_group))
      return false;
    group.sources.resize(source_count);
    for (auto &source : group.sources)
      if (!ipv6(in, source))
        return false;
    if (!in.boolean(group.starg) || !in.boolean(group.range))
      return false;
  }
  bool dhcpv4_relay_present{};
  if (!in.boolean(dhcpv4_relay_present))
    return false;
  if (dhcpv4_relay_present) {
    interface.dhcpv4_relay.emplace();
    if (!dhcpv4_relay_policy(in, *interface.dhcpv4_relay))
      return false;
    if (interface.dhcpv4_relay->admin_enabled) {
      // Disabled candidate contexts may be incomplete. An enabled context must
      // be publishable after deriving the default giaddr from its IPv4 parent.
      // Validate a copy so the checkpoint preserves whether gi-address was
      // explicitly configured for `info` and delete semantics.
      auto effective = *interface.dhcpv4_relay;
      if (!effective.gateway_address_configured)
        effective.gateway_address = packet::Ipv4{
            static_cast<std::uint8_t>(interface.address >> 24U),
            static_cast<std::uint8_t>(interface.address >> 16U),
            static_cast<std::uint8_t>(interface.address >> 8U),
            static_cast<std::uint8_t>(interface.address)};
      dhcpv4::RelayAgent validation;
      if (!validation.configure(effective))
        return false;
    }
  } else {
    interface.dhcpv4_relay.reset();
  }
  if (!in.string(interface.dhcpv6_local_server, 32U))
    return false;
  interface.mld_query_interval = std::chrono::seconds{mld_query_seconds};
  interface.mld_query_response_interval =
      std::chrono::milliseconds{mld_response_milliseconds};
  interface.mld_last_listener_query_interval =
      std::chrono::milliseconds{mld_last_listener_milliseconds};
  if (!interface.ipv6_addresses.empty()) {
    const auto primary = std::min_element(
        interface.ipv6_addresses.begin(), interface.ipv6_addresses.end(),
        [](const auto &left, const auto &right) {
          return left.primary_preference < right.primary_preference ||
                 (left.primary_preference == right.primary_preference &&
                  left.address < right.address);
        });
    if (!interface.ipv6_address_configured ||
        primary->address != interface.ipv6_address ||
        primary->prefix_length != interface.ipv6_prefix_length ||
        interface.ipv6_addresses.size() +
                (interface.address_configured ? 1U : 0U) >
            device_catalog::network_interface_ip_addresses)
      return false;
  }
  const bool system = interface.name == "system";
  // The system interface is a portless routed loopback, not an IPv4-only
  // special case. Its /32 and /128 host addresses are legitimate routing
  // inputs and therefore belong in a portable checkpoint. Only children that
  // require an attached data-link medium remain prohibited here. This mirrors
  // LabRuntime::validate_portable_configuration so encode and decode enforce
  // one contract instead of accepting a configuration that cannot be restored.
  const bool unsupported_system_children =
      !interface.static_ipv4_neighbors.empty() ||
      !interface.static_ipv6_neighbors.empty() ||
      interface.router_advertisement_configured || interface.mld_configured ||
      interface.ipv6_unsolicited_learning_configured ||
      interface.ipv6_proactive_refresh_configured ||
      interface.ipv6_nd_reachable_time_configured ||
      interface.ipv6_nd_stale_time_configured ||
      interface.ipv6_neighbor_limit_configured ||
      interface.ipv6_neighbor_limit_log_only_configured ||
      interface.ipv6_neighbor_limit_threshold_configured ||
      interface.arp_timeout_configured || interface.arp_retry_configured ||
      interface.icmp_redirect_admin_configured ||
      interface.icmp_redirect_maximum_configured ||
      interface.icmp_redirect_interval_configured ||
      interface.dhcpv4_relay.has_value() ||
      !interface.dhcpv6_local_server.empty();
  const auto scalar_present = [&](RouterAdvertisementLeaf leaf) noexcept {
    return (interface.router_advertisement_leaf_presence &
            static_cast<std::uint16_t>(leaf)) != 0U;
  };
  const auto defaults = packet::nd::RouterAdvertisementConfig{};
  bool valid_ra_presence =
      (interface.router_advertisement_leaf_presence &
       ~router_advertisement_leaf_presence_mask) == 0U &&
      (interface.router_advertisement_configured ||
       interface.router_advertisement_leaf_presence == 0U) &&
      (scalar_present(RouterAdvertisementLeaf::admin_state) ||
       !interface.router_advertisement_enabled) &&
      (scalar_present(RouterAdvertisementLeaf::current_hop_limit) ||
       interface.router_advertisement.current_hop_limit ==
           defaults.current_hop_limit) &&
      (scalar_present(RouterAdvertisementLeaf::managed_configuration) ||
       interface.router_advertisement.managed_configuration ==
           defaults.managed_configuration) &&
      (scalar_present(RouterAdvertisementLeaf::other_configuration) ||
       interface.router_advertisement.other_configuration ==
           defaults.other_configuration) &&
      (scalar_present(RouterAdvertisementLeaf::maximum_interval) ||
       interface.router_advertisement.max_advertisement_interval_seconds ==
           defaults.max_advertisement_interval_seconds) &&
      (scalar_present(RouterAdvertisementLeaf::minimum_interval) ||
       interface.router_advertisement.min_advertisement_interval_seconds ==
           defaults.min_advertisement_interval_seconds) &&
      (scalar_present(RouterAdvertisementLeaf::mtu) ||
       interface.router_advertisement.advertised_mtu ==
           defaults.advertised_mtu) &&
      (scalar_present(RouterAdvertisementLeaf::preference) ||
       interface.router_advertisement.preference == defaults.preference) &&
      (scalar_present(RouterAdvertisementLeaf::reachable_time) ||
       interface.router_advertisement.reachable_time_milliseconds ==
           defaults.reachable_time_milliseconds) &&
      (scalar_present(RouterAdvertisementLeaf::retransmit_time) ||
       interface.router_advertisement.retrans_timer_milliseconds ==
           defaults.retrans_timer_milliseconds) &&
      (scalar_present(RouterAdvertisementLeaf::router_lifetime) ||
       interface.router_advertisement.router_lifetime_seconds ==
           defaults.router_lifetime_seconds);
  for (std::size_t index = 0;
       valid_ra_presence &&
       index < interface.router_advertisement_prefix_leaf_presence.size();
       ++index) {
    const auto presence =
        interface.router_advertisement_prefix_leaf_presence[index];
    valid_ra_presence =
        (presence & ~router_advertisement_prefix_leaf_presence_mask) == 0U &&
        (index < interface.router_advertisement.prefix_count || presence == 0U);
    if (!valid_ra_presence ||
        index >= interface.router_advertisement.prefix_count)
      continue;
    const auto &prefix = interface.router_advertisement.prefixes[index];
    const auto prefix_present = [&](RouterAdvertisementPrefixLeaf leaf) {
      return (presence & static_cast<std::uint8_t>(leaf)) != 0U;
    };
    valid_ra_presence =
        (prefix_present(RouterAdvertisementPrefixLeaf::autonomous) ||
         prefix.autonomous) &&
        (prefix_present(RouterAdvertisementPrefixLeaf::on_link) ||
         prefix.on_link) &&
        (prefix_present(RouterAdvertisementPrefixLeaf::preferred_lifetime) ||
         prefix.preferred_lifetime_seconds ==
             device_catalog::ra_default_prefix_preferred_lifetime) &&
        (prefix_present(RouterAdvertisementPrefixLeaf::valid_lifetime) ||
         prefix.valid_lifetime_seconds ==
             device_catalog::ra_default_prefix_valid_lifetime);
  }
  // Keep family invariants separate. Besides making this untrusted-input
  // boundary auditable, the grouping prevents a new protocol leaf from being
  // accidentally hidden inside one large boolean expression.
  const bool valid_system =
      !system ||
      (!interface.port_configured && interface.port_id.empty() &&
       (!interface.address_configured || interface.prefix_length == 32U) &&
       !unsupported_system_children);
  const bool valid_binding =
      interface.port_configured == !interface.port_id.empty();
  const bool valid_ipv4 =
      (interface.address_configured || interface.address == 0U) &&
      (interface.address_configured || interface.prefix_length == 0U) &&
      (!interface.dhcpv4_relay ||
       (interface.address_configured &&
        (!interface.dhcpv4_relay->gateway_address_configured ||
         interface.dhcpv4_relay->gateway_address ==
            packet::Ipv4{
                static_cast<std::uint8_t>(interface.address >> 24U),
                static_cast<std::uint8_t>(interface.address >> 16U),
                static_cast<std::uint8_t>(interface.address >> 8U),
                static_cast<std::uint8_t>(interface.address)})));
  const bool valid_icmp4 =
      interface.icmp_redirect_maximum >=
          device_catalog::icmp_redirect_minimum_maximum &&
      interface.icmp_redirect_maximum <=
          device_catalog::icmp_redirect_maximum_maximum &&
      interface.icmp_redirect_interval_seconds >=
          device_catalog::icmp_redirect_minimum_interval.count() &&
      interface.icmp_redirect_interval_seconds <=
          device_catalog::icmp_redirect_maximum_interval.count() &&
      (interface.address_configured ||
       (!interface.icmp_redirect_admin_configured &&
        !interface.icmp_redirect_maximum_configured &&
        !interface.icmp_redirect_interval_configured &&
        interface.icmp_redirects_enabled &&
        interface.icmp_redirect_maximum ==
            device_catalog::icmp_redirect_default_maximum &&
        interface.icmp_redirect_interval_seconds ==
            device_catalog::icmp_redirect_default_interval.count()));
  // An uncommitted candidate can acquire its first IPv6 address before the
  // effective EUI-64 link-local address is materialized by apply_configuration.
  // Running checkpoints must always carry the derived address, while candidate
  // checkpoints preserve the unspecified sentinel so a restore does not turn
  // derived operational state into an explicit configuration leaf.
  const bool valid_link_local =
      system ? ip::is_unspecified(interface.ipv6_link_local)
             : ip::is_link_local(interface.ipv6_link_local) ||
                   (candidate && ip::is_unspecified(interface.ipv6_link_local));
  const bool valid_ipv6 =
      !interface.ipv6_address_configured ||
      (interface.ipv6_prefix_length <= ip::ipv6_address_bits &&
       !ip::is_unspecified(interface.ipv6_address) &&
       !ip::is_multicast(interface.ipv6_address) && valid_link_local);
  const bool valid_ra =
      valid_ra_presence &&
      (!interface.router_advertisement_configured ||
       interface.ipv6_address_configured) &&
      (!interface.router_advertisement_configured ||
       valid_rdnss_information(
           interface.router_advertisement.rdnss,
           interface.router_advertisement.rdnss_lifetime_seconds)) &&
      (!interface.router_advertisement_enabled ||
       interface.router_advertisement_configured) &&
      (!interface.router_advertisement_rdnss_lifetime_configured ||
       interface.router_advertisement_configured) &&
      (!interface.router_advertisement_include_dns_configured ||
       interface.router_advertisement_configured) &&
      (interface.router_advertisement_include_dns_configured ||
       interface.router_advertisement_include_dns) &&
      (interface.router_advertisement_rdnss_lifetime_configured ||
       interface.router_advertisement.rdnss_lifetime_seconds ==
           device_catalog::ra_infinite_lifetime);
  const bool valid_icmp6 =
      interface.icmp6_redirect_maximum >=
          device_catalog::icmp6_redirect_minimum_maximum &&
      interface.icmp6_redirect_maximum <=
          device_catalog::icmp6_redirect_maximum_maximum &&
      interface.icmp6_redirect_interval_seconds >=
          device_catalog::icmp6_redirect_minimum_interval.count() &&
      interface.icmp6_redirect_interval_seconds <=
          device_catalog::icmp6_redirect_maximum_interval.count() &&
      (interface.ipv6_address_configured ||
       (!interface.icmp6_redirect_admin_configured &&
        !interface.icmp6_redirect_maximum_configured &&
        !interface.icmp6_redirect_interval_configured));
  const bool valid_mld =
      interface.mld_version >= device_catalog::mld_minimum_version &&
      interface.mld_version <= device_catalog::mld_maximum_version &&
      (!interface.mld_configured || interface.ipv6_address_configured) &&
      (!interface.mld_enabled || interface.mld_configured);
  if (!valid_system) {
    return false;
  }
  if (!valid_binding) {
    return false;
  }
  if (!valid_ipv4) {
    return false;
  }
  if (!valid_icmp4) {
    return false;
  }
  if (!valid_ipv6) {
    return false;
  }
  if (!valid_ra) {
    return false;
  }
  if (!valid_icmp6) {
    return false;
  }
  if (!valid_mld) {
    return false;
  }
  return true;
}

void portable_ipv6_route(Writer &out,
                         const PortableIpv6StaticRouteIntentCheckpoint &route) {
  // The persisted interface key is the RFC 4007 zone for a link-local next
  // hop. Global next hops deliberately store an empty key, avoiding a stale
  // dependency on an unrelated physical port after inventory changes.
  ipv6(out, route.network);
  ipv6(out, route.next_hop);
  out.string(route.outgoing_port_id);
  out.integer(route.prefix_length);
  out.boolean(route.indirect);
  out.boolean(route.admin_enabled);
  out.boolean(route.admin_state_configured);
}

bool portable_ipv6_route(Reader &in,
                         PortableIpv6StaticRouteIntentCheckpoint &route) {
  if (!ipv6(in, route.network) || !ipv6(in, route.next_hop) ||
      !in.string(route.outgoing_port_id, 32) ||
      !in.integer(route.prefix_length) || !in.boolean(route.indirect) ||
      !in.boolean(route.admin_enabled) ||
      !in.boolean(route.admin_state_configured) ||
      route.prefix_length > ip::ipv6_address_bits ||
      ip::is_unspecified(route.next_hop) || ip::is_multicast(route.next_hop) ||
      route.network != ip::mask(route.network, route.prefix_length))
    return false;
  // RFC 4007 requires a zone for a link-local next hop. Conversely, retaining
  // a zone on a global next hop would make configuration equality depend on a
  // field that has no routing meaning and is therefore rejected.
  return ip::is_link_local(route.next_hop) ? !route.outgoing_port_id.empty()
                                           : route.outgoing_port_id.empty();
}

void tls_status_verification(Writer &out,
                             const tls_profile::StatusVerification &state) {
  out.integer(state.default_result);
  out.integer(state.primary);
  out.integer(state.secondary);
  out.boolean(state.default_result_configured);
  out.boolean(state.primary_configured);
  out.boolean(state.secondary_configured);
}

bool tls_status_verification(Reader &in,
                             tls_profile::StatusVerification &state) noexcept {
  if (!in.integer(state.default_result) || !in.integer(state.primary) ||
      !in.integer(state.secondary) ||
      !in.boolean(state.default_result_configured) ||
      !in.boolean(state.primary_configured) ||
      !in.boolean(state.secondary_configured))
    return false;
  return state.default_result <= tls_profile::StatusResult::good &&
         state.primary <= tls_profile::RevocationMethod::ocsp &&
         state.secondary <= tls_profile::RevocationMethod::ocsp;
}

void tls_algorithm_lists(Writer &out,
                         const std::vector<tls_profile::AlgorithmList> &lists) {
  count(out, lists);
  for (const auto &list : lists) {
    out.string(list.name);
    count(out, list.entries);
    for (const auto &entry : list.entries) {
      out.integer(entry.index);
      out.string(entry.name);
    }
  }
}

bool tls_algorithm_lists(Reader &in,
                         std::vector<tls_profile::AlgorithmList> &lists,
                         std::size_t maximum_lists) {
  std::uint32_t list_count{};
  if (!count(in, list_count, maximum_lists))
    return false;
  lists.resize(list_count);
  for (auto &list : lists) {
    std::uint32_t entry_count{};
    if (!in.string(list.name, device_catalog::tls_profile_name_bytes) ||
        !count(in, entry_count, device_catalog::tls_algorithm_index_maximum))
      return false;
    list.entries.resize(entry_count);
    for (auto &entry : list.entries)
      if (!in.integer(entry.index) || !in.string(entry.name, 64U))
        return false;
  }
  return true;
}

void tls_configuration(Writer &out, const tls_profile::Configuration &state) {
  // Checkpoint order mirrors the SR OS configuration tree. It contains only
  // filenames and leafrefs. Private key ciphertext belongs to the PKI owner
  // and is serialized by that owner, never duplicated into candidate state.
  out.boolean(state.use_pqc_only);
  out.boolean(state.use_pqc_only_configured);
  count(out, state.certificate_profiles);
  for (const auto &profile : state.certificate_profiles) {
    out.string(profile.name);
    out.boolean(profile.admin_enabled);
    out.boolean(profile.admin_configured);
    count(out, profile.entries);
    for (const auto &entry : profile.entries) {
      out.integer(entry.id);
      out.string(entry.certificate_file);
      out.string(entry.key_file);
      count(out, entry.send_chain_ca_profiles);
      for (const auto &name : entry.send_chain_ca_profiles)
        out.string(name);
    }
  }
  count(out, state.trust_anchor_profiles);
  for (const auto &profile : state.trust_anchor_profiles) {
    out.string(profile.name);
    count(out, profile.ca_profiles);
    for (const auto &name : profile.ca_profiles)
      out.string(name);
  }
  tls_algorithm_lists(out, state.client_cipher_lists);
  tls_algorithm_lists(out, state.client_group_lists);
  tls_algorithm_lists(out, state.client_signature_lists);
  count(out, state.client_profiles);
  for (const auto &profile : state.client_profiles) {
    out.string(profile.name);
    out.boolean(profile.admin_enabled);
    out.boolean(profile.admin_configured);
    out.string(profile.certificate_profile);
    out.string(profile.cipher_list);
    out.string(profile.group_list);
    out.string(profile.signature_list);
    out.string(profile.trust_anchor_profile);
    out.integer(profile.protocol_version);
    out.boolean(profile.protocol_version_configured);
    tls_status_verification(out, profile.status_verification);
  }
  tls_algorithm_lists(out, state.server_cipher_lists);
  tls_algorithm_lists(out, state.server_group_lists);
  tls_algorithm_lists(out, state.server_signature_lists);
  count(out, state.server_profiles);
  for (const auto &profile : state.server_profiles) {
    out.string(profile.name);
    out.boolean(profile.admin_enabled);
    out.boolean(profile.admin_configured);
    out.string(profile.certificate_profile);
    out.string(profile.cipher_list);
    out.string(profile.group_list);
    out.string(profile.signature_list);
    out.string(profile.client_trust_anchor_profile);
    out.string(profile.client_common_name_list);
    out.integer(profile.protocol_version);
    out.boolean(profile.protocol_version_configured);
    tls_status_verification(out, profile.status_verification);
  }
}

bool tls_configuration(Reader &in, tls_profile::Configuration &state) {
  std::uint32_t size{};
  if (!in.boolean(state.use_pqc_only) ||
      !in.boolean(state.use_pqc_only_configured) ||
      !count(in, size, device_catalog::tls_maximum_cert_profiles))
    return false;
  state.certificate_profiles.resize(size);
  for (auto &profile : state.certificate_profiles) {
    std::uint32_t entry_count{};
    if (!in.string(profile.name, device_catalog::tls_profile_name_bytes) ||
        !in.boolean(profile.admin_enabled) ||
        !in.boolean(profile.admin_configured) ||
        !count(in, entry_count,
               device_catalog::tls_maximum_cert_entries_per_profile))
      return false;
    profile.entries.resize(entry_count);
    for (auto &entry : profile.entries) {
      std::uint32_t chain_count{};
      if (!in.integer(entry.id) ||
          !in.string(entry.certificate_file,
                     device_catalog::tls_certificate_file_name_bytes) ||
          !in.string(entry.key_file,
                     device_catalog::tls_certificate_file_name_bytes) ||
          !count(in, chain_count, 7U))
        return false;
      entry.send_chain_ca_profiles.resize(chain_count);
      for (auto &name : entry.send_chain_ca_profiles)
        if (!in.string(name, device_catalog::tls_profile_name_bytes))
          return false;
    }
  }
  if (!count(in, size, device_catalog::tls_maximum_trust_anchor_profiles))
    return false;
  state.trust_anchor_profiles.resize(size);
  for (auto &profile : state.trust_anchor_profiles) {
    std::uint32_t anchor_count{};
    if (!in.string(profile.name, device_catalog::tls_profile_name_bytes) ||
        !count(in, anchor_count,
               device_catalog::tls_maximum_trust_anchors_per_profile))
      return false;
    profile.ca_profiles.resize(anchor_count);
    for (auto &name : profile.ca_profiles)
      if (!in.string(name, device_catalog::tls_profile_name_bytes))
        return false;
  }
  if (!tls_algorithm_lists(in, state.client_cipher_lists,
                           device_catalog::tls_maximum_client_cipher_lists) ||
      !tls_algorithm_lists(in, state.client_group_lists,
                           device_catalog::tls_maximum_client_group_lists) ||
      !tls_algorithm_lists(
          in, state.client_signature_lists,
          device_catalog::tls_maximum_client_signature_lists) ||
      !count(in, size, device_catalog::tls_maximum_client_profiles))
    return false;
  state.client_profiles.resize(size);
  for (auto &profile : state.client_profiles) {
    if (!in.string(profile.name, device_catalog::tls_profile_name_bytes) ||
        !in.boolean(profile.admin_enabled) ||
        !in.boolean(profile.admin_configured) ||
        !in.string(profile.certificate_profile,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.cipher_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.group_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.signature_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.trust_anchor_profile,
                   device_catalog::tls_profile_name_bytes) ||
        !in.integer(profile.protocol_version) ||
        !in.boolean(profile.protocol_version_configured) ||
        profile.protocol_version > tls_profile::ProtocolVersion::all ||
        !tls_status_verification(in, profile.status_verification))
      return false;
  }
  if (!tls_algorithm_lists(in, state.server_cipher_lists,
                           device_catalog::tls_maximum_server_cipher_lists) ||
      !tls_algorithm_lists(in, state.server_group_lists,
                           device_catalog::tls_maximum_server_group_lists) ||
      !tls_algorithm_lists(
          in, state.server_signature_lists,
          device_catalog::tls_maximum_server_signature_lists) ||
      !count(in, size, device_catalog::tls_maximum_server_profiles))
    return false;
  state.server_profiles.resize(size);
  for (auto &profile : state.server_profiles) {
    if (!in.string(profile.name, device_catalog::tls_profile_name_bytes) ||
        !in.boolean(profile.admin_enabled) ||
        !in.boolean(profile.admin_configured) ||
        !in.string(profile.certificate_profile,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.cipher_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.group_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.signature_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.client_trust_anchor_profile,
                   device_catalog::tls_profile_name_bytes) ||
        !in.string(profile.client_common_name_list,
                   device_catalog::tls_profile_name_bytes) ||
        !in.integer(profile.protocol_version) ||
        !in.boolean(profile.protocol_version_configured) ||
        profile.protocol_version > tls_profile::ProtocolVersion::all ||
        !tls_status_verification(in, profile.status_verification))
      return false;
  }
  // The same validator protects live candidate commits. Running it after all
  // bytes are staged prevents malformed leafrefs or duplicate list keys from
  // reaching the active control owner during atomic restore.
  return !tls_profile::validate(state).has_value();
}

void ipsec_selector_entry(
    Writer &out, const ipsec::configuration::TrafficSelectorEntry &entry) {
  out.integer(entry.id);
  out.boolean(entry.prefix.has_value());
  if (entry.prefix) {
    out.integer(entry.prefix->network.family);
    out.octets(entry.prefix->network.bytes);
    out.integer(entry.prefix->length);
  }
  out.boolean(entry.range_begin.has_value());
  if (entry.range_begin) {
    out.integer(entry.range_begin->family);
    out.octets(entry.range_begin->bytes);
  }
  out.boolean(entry.range_end.has_value());
  if (entry.range_end) {
    out.integer(entry.range_end->family);
    out.octets(entry.range_end->bytes);
  }
  out.integer(entry.protocol);
  out.integer(entry.numeric_protocol);
  out.integer(entry.ports.first);
  out.integer(entry.ports.last);
  out.boolean(entry.opaque_ports);
  out.boolean(entry.protocol_configured);
  out.boolean(entry.selector_begin_configured);
  out.boolean(entry.selector_end_configured);
  out.boolean(entry.begin_icmp_type_configured);
  out.boolean(entry.begin_icmp_code_configured);
  out.boolean(entry.end_icmp_type_configured);
  out.boolean(entry.end_icmp_code_configured);
}

bool ipsec_selector_entry(Reader &in,
                          ipsec::configuration::TrafficSelectorEntry &entry,
                          bool allow_incomplete) {
  bool present{};
  if (!in.integer(entry.id) || !in.boolean(present))
    return false;
  if (present) {
    entry.prefix.emplace();
    if (!in.integer(entry.prefix->network.family) ||
        !in.octets(entry.prefix->network.bytes) ||
        !in.integer(entry.prefix->length))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    entry.range_begin.emplace();
    if (!in.integer(entry.range_begin->family) ||
        !in.octets(entry.range_begin->bytes))
      return false;
  }
  if (!in.boolean(present))
    return false;
  if (present) {
    entry.range_end.emplace();
    if (!in.integer(entry.range_end->family) ||
        !in.octets(entry.range_end->bytes))
      return false;
  }
  return in.integer(entry.protocol) && in.integer(entry.numeric_protocol) &&
         in.integer(entry.ports.first) && in.integer(entry.ports.last) &&
         in.boolean(entry.opaque_ports) &&
         in.boolean(entry.protocol_configured) &&
         in.boolean(entry.selector_begin_configured) &&
         in.boolean(entry.selector_end_configured) &&
         in.boolean(entry.begin_icmp_type_configured) &&
         in.boolean(entry.begin_icmp_code_configured) &&
         in.boolean(entry.end_icmp_type_configured) &&
         in.boolean(entry.end_icmp_code_configured) &&
         ipsec::configuration::validate_traffic_selector_entry(
             entry, allow_incomplete);
}

void ipsec_transport_profile(
    Writer &out, const ipsec::configuration::TransportModeProfile &profile) {
  out.string(profile.name);
  out.string(profile.description);
  const auto &dynamic = profile.dynamic;
  out.integer(dynamic.ike_policy);
  count(out, dynamic.ipsec_transforms);
  for (const auto reference : dynamic.ipsec_transforms)
    out.integer(reference);
  out.string(dynamic.certificate_profile);
  out.string(dynamic.trust_anchor_profile);
  out.string(dynamic.ppk_list);
  out.string(dynamic.ppk_id);
  out.integer(dynamic.pre_shared_key_handle);
  out.string(dynamic.identity);
  out.integer(dynamic.identity_type);
  out.integer(dynamic.default_revocation_result);
  out.integer(dynamic.primary_revocation_method);
  out.integer(dynamic.secondary_revocation_method);
  out.boolean(dynamic.auto_establish);
  out.boolean(dynamic.auto_establish_configured);
  out.boolean(dynamic.default_revocation_result_configured);
  out.boolean(dynamic.primary_revocation_method_configured);
  out.boolean(dynamic.secondary_revocation_method_configured);
  out.integer(profile.replay_window);
  out.integer(profile.maximum_esp_history_records);
  out.integer(profile.maximum_ike_history_records);
  out.boolean(profile.replay_window_configured);
  out.boolean(profile.maximum_esp_history_records_configured);
  out.boolean(profile.maximum_ike_history_records_configured);
}

bool ipsec_transport_profile(
    Reader &in, ipsec::configuration::TransportModeProfile &profile) {
  auto &dynamic = profile.dynamic;
  std::uint32_t reference_count{};
  if (!in.string(profile.name, 32U) || !in.string(profile.description, 80U) ||
      !in.integer(dynamic.ike_policy) || !count(in, reference_count, 4U))
    return false;
  dynamic.ipsec_transforms.resize(reference_count);
  for (auto &reference : dynamic.ipsec_transforms)
    if (!in.integer(reference))
      return false;
  return in.string(dynamic.certificate_profile, 32U) &&
         in.string(dynamic.trust_anchor_profile, 32U) &&
         in.string(dynamic.ppk_list, 32U) && in.string(dynamic.ppk_id, 64U) &&
         in.integer(dynamic.pre_shared_key_handle) &&
         in.string(dynamic.identity, 255U) &&
         in.integer(dynamic.identity_type) &&
         in.integer(dynamic.default_revocation_result) &&
         in.integer(dynamic.primary_revocation_method) &&
         in.integer(dynamic.secondary_revocation_method) &&
         in.boolean(dynamic.auto_establish) &&
         in.boolean(dynamic.auto_establish_configured) &&
         in.boolean(dynamic.default_revocation_result_configured) &&
         in.boolean(dynamic.primary_revocation_method_configured) &&
         in.boolean(dynamic.secondary_revocation_method_configured) &&
         in.integer(profile.replay_window) &&
         in.integer(profile.maximum_esp_history_records) &&
         in.integer(profile.maximum_ike_history_records) &&
         in.boolean(profile.replay_window_configured) &&
         in.boolean(profile.maximum_esp_history_records_configured) &&
         in.boolean(profile.maximum_ike_history_records_configured);
}

void ipsec_rate_limit(Writer &out,
                      const ipsec::configuration::RateLimit &rate) {
  out.integer(rate.interval_seconds);
  out.integer(rate.message_count);
  out.boolean(rate.enabled);
  out.boolean(rate.enabled_configured);
  out.boolean(rate.interval_configured);
  out.boolean(rate.message_count_configured);
}

bool ipsec_rate_limit(Reader &in, ipsec::configuration::RateLimit &rate) {
  return in.integer(rate.interval_seconds) && in.integer(rate.message_count) &&
         in.boolean(rate.enabled) && in.boolean(rate.enabled_configured) &&
         in.boolean(rate.interval_configured) &&
         in.boolean(rate.message_count_configured) &&
         ipsec::configuration::validate_rate_limit(rate);
}

void ipsec_tunnel_template(Writer &out,
                           const ipsec::configuration::TunnelTemplate &item) {
  out.integer(item.id);
  out.string(item.description);
  count(out, item.ipsec_transforms);
  for (const auto reference : item.ipsec_transforms)
    out.integer(reference);
  out.string(item.ppk_list);
  out.integer(item.encapsulated_ip_mtu);
  out.integer(item.ip_mtu);
  out.integer(item.replay_window);
  out.integer(item.pmtu_discovery_aging_seconds);
  out.integer(item.private_tcp_mss_adjust);
  out.integer(item.public_tcp_mss_adjust);
  out.integer(item.reverse_route_metric);
  out.integer(item.reverse_route_preference);
  out.integer(item.service_provider_reverse_route);
  ipsec_rate_limit(out, item.ipv4_fragmentation_required);
  ipsec_rate_limit(out, item.ipv6_packet_too_big);
  out.boolean(item.clear_df_bit);
  out.boolean(item.clear_df_bit_configured);
  out.boolean(item.copy_traffic_class_upon_decapsulation);
  out.boolean(item.copy_traffic_class_configured);
  out.boolean(item.ignore_default_route);
  out.boolean(item.ignore_default_route_configured);
  out.boolean(item.encapsulated_ip_mtu_configured);
  out.boolean(item.ip_mtu_configured);
  out.boolean(item.replay_window_configured);
  out.boolean(item.pmtu_discovery_aging_configured);
  out.boolean(item.private_tcp_mss_adjust_configured);
  out.boolean(item.propagate_pmtu_v4);
  out.boolean(item.propagate_pmtu_v4_configured);
  out.boolean(item.propagate_pmtu_v6);
  out.boolean(item.propagate_pmtu_v6_configured);
  out.boolean(item.public_tcp_mss_adjust_configured);
  out.boolean(item.public_tcp_mss_auto);
  out.boolean(item.reverse_route_metric_configured);
  out.boolean(item.reverse_route_preference_configured);
  out.boolean(item.service_provider_reverse_route_configured);
}

bool ipsec_tunnel_template(Reader &in,
                           ipsec::configuration::TunnelTemplate &item) {
  std::uint32_t reference_count{};
  if (!in.integer(item.id) || !in.string(item.description, 80U) ||
      !count(in, reference_count, 4U))
    return false;
  item.ipsec_transforms.resize(reference_count);
  for (auto &reference : item.ipsec_transforms)
    if (!in.integer(reference))
      return false;
  return in.string(item.ppk_list, 32U) &&
         in.integer(item.encapsulated_ip_mtu) && in.integer(item.ip_mtu) &&
         in.integer(item.replay_window) &&
         in.integer(item.pmtu_discovery_aging_seconds) &&
         in.integer(item.private_tcp_mss_adjust) &&
         in.integer(item.public_tcp_mss_adjust) &&
         in.integer(item.reverse_route_metric) &&
         in.integer(item.reverse_route_preference) &&
         in.integer(item.service_provider_reverse_route) &&
         ipsec_rate_limit(in, item.ipv4_fragmentation_required) &&
         ipsec_rate_limit(in, item.ipv6_packet_too_big) &&
         in.boolean(item.clear_df_bit) &&
         in.boolean(item.clear_df_bit_configured) &&
         in.boolean(item.copy_traffic_class_upon_decapsulation) &&
         in.boolean(item.copy_traffic_class_configured) &&
         in.boolean(item.ignore_default_route) &&
         in.boolean(item.ignore_default_route_configured) &&
         in.boolean(item.encapsulated_ip_mtu_configured) &&
         in.boolean(item.ip_mtu_configured) &&
         in.boolean(item.replay_window_configured) &&
         in.boolean(item.pmtu_discovery_aging_configured) &&
         in.boolean(item.private_tcp_mss_adjust_configured) &&
         in.boolean(item.propagate_pmtu_v4) &&
         in.boolean(item.propagate_pmtu_v4_configured) &&
         in.boolean(item.propagate_pmtu_v6) &&
         in.boolean(item.propagate_pmtu_v6_configured) &&
         in.boolean(item.public_tcp_mss_adjust_configured) &&
         in.boolean(item.public_tcp_mss_auto) &&
         in.boolean(item.reverse_route_metric_configured) &&
         in.boolean(item.reverse_route_preference_configured) &&
         in.boolean(item.service_provider_reverse_route_configured);
}

void ipsec_certificate_profile(
    Writer &out, const ipsec::configuration::CertificateProfile &profile) {
  out.string(profile.name);
  out.boolean(profile.enabled);
  out.boolean(profile.admin_state_configured);
  count(out, profile.entries);
  for (const auto &entry : profile.entries) {
    out.integer(entry.id);
    out.string(entry.certificate_file);
    out.string(entry.private_key_file);
    out.string(entry.compare_chain_include);
    out.integer(entry.rsa_signature);
    out.boolean(entry.rsa_signature_configured);
    count(out, entry.send_chain_ca_profiles);
    for (const auto &ca_profile : entry.send_chain_ca_profiles)
      out.string(ca_profile);
  }
}

bool ipsec_certificate_profile(
    Reader &in, ipsec::configuration::CertificateProfile &profile) {
  std::uint32_t entry_count{};
  if (!in.string(profile.name, 32U) || !in.boolean(profile.enabled) ||
      !in.boolean(profile.admin_state_configured) ||
      !count(in, entry_count,
             ipsec::configuration::maximum_certificate_entries))
    return false;
  profile.entries.resize(entry_count);
  for (auto &entry : profile.entries) {
    std::uint32_t ca_count{};
    if (!in.integer(entry.id) || !in.string(entry.certificate_file, 95U) ||
        !in.string(entry.private_key_file, 95U) ||
        !in.string(entry.compare_chain_include, 32U) ||
        !in.integer(entry.rsa_signature) ||
        !in.boolean(entry.rsa_signature_configured) ||
        !count(in, ca_count, ipsec::configuration::maximum_send_chain_profiles))
      return false;
    entry.send_chain_ca_profiles.resize(ca_count);
    for (auto &ca_profile : entry.send_chain_ca_profiles)
      if (!in.string(ca_profile, 32U))
        return false;
  }
  return true;
}

void ipsec_trust_anchor_profile(
    Writer &out, const ipsec::configuration::TrustAnchorProfile &profile) {
  out.string(profile.name);
  count(out, profile.ca_profiles);
  for (const auto &ca_profile : profile.ca_profiles)
    out.string(ca_profile);
}

bool ipsec_trust_anchor_profile(
    Reader &in, ipsec::configuration::TrustAnchorProfile &profile) {
  std::uint32_t count_value{};
  if (!in.string(profile.name, 32U) ||
      !count(in, count_value, ipsec::configuration::maximum_trust_anchors))
    return false;
  profile.ca_profiles.resize(count_value);
  for (auto &ca_profile : profile.ca_profiles)
    if (!in.string(ca_profile, 32U))
      return false;
  return true;
}

void ipsec_ppk_list(Writer &out, const ipsec::configuration::PpkList &list) {
  out.string(list.name);
  count(out, list.entries);
  for (const auto &entry : list.entries) {
    out.string(entry.id);
    out.integer(entry.secret_handle);
    out.integer(entry.format);
  }
}

bool ipsec_ppk_list(Reader &in, ipsec::configuration::PpkList &list) {
  std::uint32_t entry_count{};
  if (!in.string(list.name, 32U) ||
      !count(in, entry_count, ipsec::configuration::maximum_ppks_per_list))
    return false;
  list.entries.resize(entry_count);
  for (auto &entry : list.entries)
    if (!in.string(entry.id, 64U) || !in.integer(entry.secret_handle) ||
        !in.integer(entry.format))
      return false;
  return true;
}

void ipsec_configuration(Writer &out,
                         const ipsec::configuration::Configuration &state) {
  // This is configuration intent only. Live SPIs, replay windows and keying
  // material are serialized by their owning IKE and SAD components so a
  // candidate datastore can never duplicate or accidentally expose secrets.
  count(out, state.ike_transforms);
  for (const auto &transform : state.ike_transforms) {
    out.integer(transform.id);
    out.integer(transform.dh_group);
    out.integer(transform.encryption);
    out.integer(transform.lifetime_seconds);
    out.boolean(transform.dh_group_configured);
    out.boolean(transform.authentication_encryption_configured);
    out.boolean(transform.encryption_configured);
    out.boolean(transform.prf_sha256_configured);
    out.boolean(transform.lifetime_configured);
  }
  count(out, state.ipsec_transforms);
  for (const auto &transform : state.ipsec_transforms) {
    out.integer(transform.id);
    out.integer(transform.encryption);
    out.integer(transform.pfs_group);
    out.integer(transform.lifetime_seconds);
    out.boolean(transform.authentication_encryption_configured);
    out.boolean(transform.encryption_configured);
    out.boolean(transform.extended_sequence_number);
    out.boolean(transform.extended_sequence_number_configured);
    out.boolean(transform.lifetime_configured);
    out.boolean(transform.pfs_enabled);
    out.boolean(transform.pfs_group_configured);
  }
  count(out, state.ike_policies);
  for (const auto &policy : state.ike_policies) {
    out.integer(policy.id);
    out.string(policy.description);
    count(out, policy.ike_transforms);
    for (const auto transform : policy.ike_transforms)
      out.integer(transform);
    out.integer(policy.peer_authentication);
    out.integer(policy.own_authentication);
    out.integer(policy.ipsec_lifetime_seconds);
    out.integer(policy.fragmentation_mtu);
    out.integer(policy.fragmentation_reassembly_timeout_seconds);
    out.integer(policy.dpd_interval_seconds);
    out.integer(policy.dpd_max_retries);
    out.integer(policy.nat_keepalive_interval_seconds);
    out.boolean(policy.fragmentation_configured);
    out.boolean(policy.dpd_configured);
    out.boolean(policy.nat_traversal_configured);
    out.boolean(policy.ike_version2_configured);
    out.boolean(policy.peer_authentication_configured);
    out.boolean(policy.own_authentication_configured);
    out.boolean(policy.ipsec_lifetime_configured);
    out.boolean(policy.fragmentation_mtu_configured);
    out.boolean(policy.fragmentation_reassembly_timeout_configured);
    out.boolean(policy.dpd_interval_configured);
    out.boolean(policy.dpd_max_retries_configured);
    out.boolean(policy.dpd_reply_only);
    out.boolean(policy.dpd_reply_only_configured);
    out.boolean(policy.nat_force);
    out.boolean(policy.nat_force_configured);
    out.boolean(policy.nat_force_keepalive);
    out.boolean(policy.nat_force_keepalive_configured);
    out.boolean(policy.nat_keepalive_interval_configured);
  }
  count(out, state.static_sas);
  for (const auto &association : state.static_sas) {
    out.string(association.name);
    out.string(association.description);
    out.integer(association.authentication);
    out.integer(association.authentication_key_format);
    out.integer(association.direction);
    out.integer(association.protocol);
    out.integer(association.authentication_key_handle);
    out.integer(association.spi);
    out.boolean(association.authentication_container_configured);
    out.boolean(association.authentication_configured);
    out.boolean(association.direction_configured);
    out.boolean(association.protocol_configured);
    out.boolean(association.spi_configured);
  }
  count(out, state.certificate_profiles);
  for (const auto &profile : state.certificate_profiles)
    ipsec_certificate_profile(out, profile);
  count(out, state.trust_anchor_profiles);
  for (const auto &profile : state.trust_anchor_profiles)
    ipsec_trust_anchor_profile(out, profile);
  count(out, state.ppk_lists);
  for (const auto &list : state.ppk_lists)
    ipsec_ppk_list(out, list);
  count(out, state.traffic_selector_lists);
  for (const auto &list : state.traffic_selector_lists) {
    out.string(list.name);
    count(out, list.local);
    for (const auto &entry : list.local)
      ipsec_selector_entry(out, entry);
    count(out, list.remote);
    for (const auto &entry : list.remote)
      ipsec_selector_entry(out, entry);
  }
  count(out, state.transport_mode_profiles);
  for (const auto &profile : state.transport_mode_profiles)
    ipsec_transport_profile(out, profile);
  count(out, state.tunnel_templates);
  for (const auto &item : state.tunnel_templates)
    ipsec_tunnel_template(out, item);
}

bool ipsec_configuration(Reader &in, ipsec::configuration::Configuration &state,
                         bool allow_incomplete = false) {
  std::uint32_t size{};
  if (!count(in, size, profile::maximum_ike_transforms))
    return false;
  state.ike_transforms.resize(size);
  for (auto &transform : state.ike_transforms)
    if (!in.integer(transform.id) || !in.integer(transform.dh_group) ||
        !in.integer(transform.encryption) ||
        !in.integer(transform.lifetime_seconds) ||
        !in.boolean(transform.dh_group_configured) ||
        !in.boolean(transform.authentication_encryption_configured) ||
        !in.boolean(transform.encryption_configured) ||
        !in.boolean(transform.prf_sha256_configured) ||
        !in.boolean(transform.lifetime_configured))
      return false;
  if (!count(in, size, profile::maximum_ipsec_transforms))
    return false;
  state.ipsec_transforms.resize(size);
  for (auto &transform : state.ipsec_transforms)
    if (!in.integer(transform.id) || !in.integer(transform.encryption) ||
        !in.integer(transform.pfs_group) ||
        !in.integer(transform.lifetime_seconds) ||
        !in.boolean(transform.authentication_encryption_configured) ||
        !in.boolean(transform.encryption_configured) ||
        !in.boolean(transform.extended_sequence_number) ||
        !in.boolean(transform.extended_sequence_number_configured) ||
        !in.boolean(transform.lifetime_configured) ||
        !in.boolean(transform.pfs_enabled) ||
        !in.boolean(transform.pfs_group_configured))
      return false;
  if (!count(in, size, profile::maximum_ike_policies))
    return false;
  state.ike_policies.resize(size);
  for (auto &policy : state.ike_policies) {
    std::uint32_t reference_count{};
    if (!in.integer(policy.id) || !in.string(policy.description, 80U) ||
        !count(in, reference_count, 4U))
      return false;
    policy.ike_transforms.resize(reference_count);
    for (auto &transform : policy.ike_transforms)
      if (!in.integer(transform))
        return false;
    if (!in.integer(policy.peer_authentication) ||
        !in.integer(policy.own_authentication) ||
        !in.integer(policy.ipsec_lifetime_seconds) ||
        !in.integer(policy.fragmentation_mtu) ||
        !in.integer(policy.fragmentation_reassembly_timeout_seconds) ||
        !in.integer(policy.dpd_interval_seconds) ||
        !in.integer(policy.dpd_max_retries) ||
        !in.integer(policy.nat_keepalive_interval_seconds) ||
        !in.boolean(policy.fragmentation_configured) ||
        !in.boolean(policy.dpd_configured) ||
        !in.boolean(policy.nat_traversal_configured) ||
        !in.boolean(policy.ike_version2_configured) ||
        !in.boolean(policy.peer_authentication_configured) ||
        !in.boolean(policy.own_authentication_configured) ||
        !in.boolean(policy.ipsec_lifetime_configured) ||
        !in.boolean(policy.fragmentation_mtu_configured) ||
        !in.boolean(policy.fragmentation_reassembly_timeout_configured) ||
        !in.boolean(policy.dpd_interval_configured) ||
        !in.boolean(policy.dpd_max_retries_configured) ||
        !in.boolean(policy.dpd_reply_only) ||
        !in.boolean(policy.dpd_reply_only_configured) ||
        !in.boolean(policy.nat_force) ||
        !in.boolean(policy.nat_force_configured) ||
        !in.boolean(policy.nat_force_keepalive) ||
        !in.boolean(policy.nat_force_keepalive_configured) ||
        !in.boolean(policy.nat_keepalive_interval_configured))
      return false;
  }
  if (!count(in, size, profile::maximum_static_sas))
    return false;
  state.static_sas.resize(size);
  for (auto &association : state.static_sas)
    if (!in.string(association.name, 32U) ||
        !in.string(association.description, 32U) ||
        !in.integer(association.authentication) ||
        association.authentication >
            ipsec::configuration::StaticSaAuthentication::sha1 ||
        !in.integer(association.authentication_key_format) ||
        association.authentication_key_format >
            ipsec::configuration::StaticSaKeyFormat::hexadecimal ||
        !in.integer(association.direction) ||
        association.direction >
            ipsec::configuration::StaticSaDirection::bidirectional ||
        !in.integer(association.protocol) ||
        association.protocol > ipsec::SecurityProtocol::ah ||
        !in.integer(association.authentication_key_handle) ||
        !in.integer(association.spi) ||
        !in.boolean(association.authentication_container_configured) ||
        !in.boolean(association.authentication_configured) ||
        !in.boolean(association.direction_configured) ||
        !in.boolean(association.protocol_configured) ||
        !in.boolean(association.spi_configured))
      return false;
  if (!count(in, size, ipsec::configuration::maximum_certificate_profiles))
    return false;
  state.certificate_profiles.resize(size);
  for (auto &profile : state.certificate_profiles)
    if (!ipsec_certificate_profile(in, profile))
      return false;
  if (!count(in, size, ipsec::configuration::maximum_trust_anchor_profiles))
    return false;
  state.trust_anchor_profiles.resize(size);
  for (auto &profile : state.trust_anchor_profiles)
    if (!ipsec_trust_anchor_profile(in, profile))
      return false;
  if (!count(in, size, ipsec::configuration::maximum_ppk_lists))
    return false;
  state.ppk_lists.resize(size);
  for (auto &list : state.ppk_lists)
    if (!ipsec_ppk_list(in, list))
      return false;
  if (!count(in, size, profile::maximum_traffic_selector_lists))
    return false;
  state.traffic_selector_lists.resize(size);
  for (auto &list : state.traffic_selector_lists) {
    std::uint32_t entry_count{};
    if (!in.string(list.name, 32U) ||
        !count(in, entry_count, profile::maximum_traffic_selectors_per_list))
      return false;
    list.local.resize(entry_count);
    for (auto &entry : list.local)
      if (!ipsec_selector_entry(in, entry, allow_incomplete))
        return false;
    if (!count(in, entry_count, profile::maximum_traffic_selectors_per_list))
      return false;
    list.remote.resize(entry_count);
    for (auto &entry : list.remote)
      if (!ipsec_selector_entry(in, entry, allow_incomplete))
        return false;
  }
  // The command reference does not publish a separate transport-profile
  // instance ceiling. Decode is still bounded by the checkpoint byte count;
  // the traffic-selector ceiling supplies a conservative structural maximum
  // without inventing a smaller platform capability.
  if (!count(in, size, profile::maximum_traffic_selector_lists))
    return false;
  state.transport_mode_profiles.resize(size);
  for (auto &transport : state.transport_mode_profiles)
    if (!ipsec_transport_profile(in, transport))
      return false;
  if (!count(in, size, profile::maximum_tunnel_templates))
    return false;
  state.tunnel_templates.resize(size);
  for (auto &item : state.tunnel_templates)
    if (!ipsec_tunnel_template(in, item))
      return false;
  // Validation rejects invalid enum values, duplicate IDs, out-of-range
  // timers and dangling leafrefs before restored intent reaches the owner.
  return ipsec::configuration::validate(state, allow_incomplete);
}

void dhcpv4_router_configuration(
    Writer &out, const dhcpv4::configuration::RouterConfiguration &state) {
  count(out, state.servers);
  for (const auto &server : state.servers) {
    out.integer(server.instance_id);
    out.string(server.name);
    out.string(server.description);
    out.boolean(server.force_renews);
    out.boolean(server.admin_enabled);
    count(out, server.pools);
    for (const auto &pool : server.pools) {
      out.string(pool.name);
      out.string(pool.description);
      out.integer(pool.minimum_lease_seconds);
      out.integer(pool.maximum_lease_seconds);
      out.integer(pool.offer_seconds);
      out.boolean(pool.nak_non_matching_subnet);
      count(out, pool.options);
      for (const auto &option : pool.options) {
        out.integer(option.code);
        out.integer(option.kind);
        count(out, option.value);
        out.octets(option.value);
      }
      count(out, pool.subnets);
      for (const auto &subnet : pool.subnets) {
        out.integer(subnet.allocation_scope_id);
        ipv4(out, subnet.network);
        out.integer(subnet.prefix_length);
        out.integer(subnet.maximum_declined);
        out.boolean(subnet.drain);
        count(out, subnet.address_ranges);
        for (const auto &range : subnet.address_ranges) {
          ipv4(out, range.first);
          ipv4(out, range.last);
          out.integer(range.failover_control);
        }
        count(out, subnet.excluded_ranges);
        for (const auto &excluded : subnet.excluded_ranges) {
          ipv4(out, excluded.first);
          ipv4(out, excluded.last);
        }
        count(out, subnet.options);
        for (const auto &option : subnet.options) {
          out.integer(option.code);
          out.integer(option.kind);
          count(out, option.value);
          out.octets(option.value);
        }
      }
    }
  }
}

bool dhcpv4_option(Reader &in,
                   dhcpv4::configuration::Option &option) noexcept {
  std::uint32_t octets{};
  if (!in.integer(option.code) || !in.integer(option.kind) ||
      option.kind > dhcpv4::configuration::OptionValueKind::netbios_node_type ||
      !count(in, octets, 255U))
    return false;
  option.value.resize(octets);
  return in.octets(option.value);
}

bool dhcpv4_router_configuration(
    Reader &in, dhcpv4::configuration::RouterConfiguration &state) {
  std::uint32_t server_count{};
  if (!count(in, server_count, device_catalog::dhcpv4_servers_per_router))
    return false;
  state.servers.resize(server_count);
  for (auto &server : state.servers) {
    std::uint32_t pool_count{};
    if (!in.integer(server.instance_id) ||
        !in.string(server.name, device_catalog::dhcpv4_server_name_bytes) ||
        !in.string(server.description,
                   device_catalog::dhcpv4_description_bytes) ||
        !in.boolean(server.force_renews) ||
        !in.boolean(server.admin_enabled) ||
        !count(in, pool_count, device_catalog::dhcpv4_pools_per_server))
      return false;
    server.pools.resize(pool_count);
    for (auto &pool : server.pools) {
      std::uint32_t option_count{};
      std::uint32_t subnet_count{};
      if (!in.string(pool.name, device_catalog::dhcpv4_server_name_bytes) ||
          !in.string(pool.description,
                     device_catalog::dhcpv4_description_bytes) ||
          !in.integer(pool.minimum_lease_seconds) ||
          !in.integer(pool.maximum_lease_seconds) ||
          !in.integer(pool.offer_seconds) ||
          !in.boolean(pool.nak_non_matching_subnet) ||
          !count(in, option_count,
                 device_catalog::dhcpv4_option_occurrences_per_message))
        return false;
      pool.options.resize(option_count);
      for (auto &option : pool.options)
        if (!dhcpv4_option(in, option))
          return false;
      if (!count(in, subnet_count,
                 device_catalog::dhcpv4_leases_per_server))
        return false;
      pool.subnets.resize(subnet_count);
      for (auto &subnet : pool.subnets) {
        std::uint32_t range_count{};
        std::uint32_t excluded_count{};
        if (!in.integer(subnet.allocation_scope_id) ||
            !ipv4(in, subnet.network) ||
            !in.integer(subnet.prefix_length) ||
            !in.integer(subnet.maximum_declined) ||
            !in.boolean(subnet.drain) ||
            !count(in, range_count,
                   device_catalog::dhcpv4_leases_per_server))
          return false;
        subnet.address_ranges.resize(range_count);
        for (auto &range : subnet.address_ranges)
          if (!ipv4(in, range.first) || !ipv4(in, range.last) ||
              !in.integer(range.failover_control) ||
              range.failover_control >
                  dhcpv4::configuration::FailoverControlType::remote)
            return false;
        if (!count(in, excluded_count,
                   device_catalog::dhcpv4_leases_per_server))
          return false;
        subnet.excluded_ranges.resize(excluded_count);
        for (auto &excluded : subnet.excluded_ranges)
          if (!ipv4(in, excluded.first) || !ipv4(in, excluded.last))
            return false;
        if (!count(in, option_count,
                   device_catalog::dhcpv4_option_occurrences_per_message))
          return false;
        subnet.options.resize(option_count);
        for (auto &option : subnet.options)
          if (!dhcpv4_option(in, option))
            return false;
      }
    }
  }
  return dhcpv4::configuration::validate(state, true) ==
         dhcpv4::configuration::Status::valid;
}

void bof_autoconfigure(Writer &out,
                       const bof::AutoconfigureIntent &state) {
  const auto common = [&](const bof::DhcpClientIntent &client) {
    out.string(client.client_id);
    out.boolean(client.client_id_hex);
    out.integer(client.timeout_seconds);
    out.boolean(client.enabled);
    out.boolean(client.include_user_class);
  };
  common(state.ipv4);
  common(state.ipv6);
  out.integer(state.ipv6.client_type);
  out.octets(state.ipv4_transaction_secret);
  out.octets(state.ipv6_transaction_secret);
}

bool bof_autoconfigure(Reader &in,
                       bof::AutoconfigureIntent &state) noexcept {
  const auto common = [&](bof::DhcpClientIntent &client,
                          std::size_t maximum) {
    return in.string(client.client_id, maximum * 2U + 2U) &&
           in.boolean(client.client_id_hex) &&
           in.integer(client.timeout_seconds) &&
           in.boolean(client.enabled) &&
           in.boolean(client.include_user_class);
  };
  if (!common(state.ipv4, 127U) || !common(state.ipv6, 124U) ||
      !in.integer(state.ipv6.client_type) ||
      state.ipv6.client_type > bof::Dhcpv6ClientType::duid_link_local ||
      !in.octets(state.ipv4_transaction_secret) ||
      !in.octets(state.ipv6_transaction_secret))
    return false;
  return bof::valid(state);
}

void dhcpv6_router_configuration(
    Writer &out, const dhcpv6::configuration::RouterConfiguration &state) {
  // DUIDs and allocation secrets are persistent protocol identities, not
  // derived cache. Writing their exact octets ensures a restored router does
  // not present a new server identity or remap every existing IA.
  count(out, state.servers);
  for (const auto &server : state.servers) {
    out.integer(server.instance_id);
    out.octets(server.duid);
    out.integer(server.duid_octets);
    out.string(server.name);
    out.string(server.description);
    count(out, server.dns_recursive_servers);
    for (const auto &address : server.dns_recursive_servers)
      ipv6(out, address);
    out.integer(server.default_preferred_lifetime_seconds);
    out.integer(server.default_valid_lifetime_seconds);
    out.integer(server.default_renewal_time_seconds);
    out.integer(server.default_rebinding_time_seconds);
    out.boolean(server.default_preferred_lifetime_configured);
    out.boolean(server.default_valid_lifetime_configured);
    out.boolean(server.default_renewal_time_configured);
    out.boolean(server.default_rebinding_time_configured);
    out.integer(server.information_refresh_time_seconds);
    out.integer(server.preference);
    out.boolean(server.rapid_commit);
    out.boolean(server.lease_query);
    out.boolean(server.admin_enabled);
    out.boolean(server.rapid_commit_configured);
    out.boolean(server.lease_query_configured);
    out.boolean(server.admin_state_configured);
    count(out, server.pools);
    for (const auto &pool : server.pools) {
      out.string(pool.name);
      out.string(pool.description);
      out.integer(pool.delegated_length);
      out.integer(pool.minimum_delegated_length);
      out.integer(pool.maximum_delegated_length);
      out.boolean(pool.delegated_length_configured);
      out.boolean(pool.minimum_delegated_length_configured);
      out.boolean(pool.maximum_delegated_length_configured);
      count(out, pool.prefixes);
      for (const auto &prefix : pool.prefixes) {
        out.integer(prefix.allocation_scope_id);
        ipv6(out, prefix.aggregate.network);
        out.integer(prefix.aggregate.length);
        out.octets(prefix.allocation_secret);
        out.integer(prefix.preferred_lifetime_seconds);
        out.integer(prefix.valid_lifetime_seconds);
        out.integer(prefix.renewal_time_seconds);
        out.integer(prefix.rebinding_time_seconds);
        out.boolean(prefix.preferred_lifetime_configured);
        out.boolean(prefix.valid_lifetime_configured);
        out.boolean(prefix.renewal_time_configured);
        out.boolean(prefix.rebinding_time_configured);
        out.boolean(prefix.wan_host);
        out.boolean(prefix.delegated_prefix);
        out.boolean(prefix.drain);
        out.boolean(prefix.drain_configured);
        out.boolean(prefix.wan_host_configured);
        out.boolean(prefix.delegated_prefix_configured);
      }
    }
  }
}

bool dhcpv6_router_configuration(
    Reader &in, dhcpv6::configuration::RouterConfiguration &state,
    bool allow_incomplete = false) {
  std::uint32_t server_count{};
  if (!count(in, server_count, device_catalog::dhcpv6_servers_per_router))
    return false;
  state.servers.resize(server_count);
  for (auto &server : state.servers) {
    std::uint32_t dns_count{};
    std::uint32_t pool_count{};
    if (!in.integer(server.instance_id) || !in.octets(server.duid) ||
        !in.integer(server.duid_octets) ||
        !in.string(server.name, 32U) ||
        !in.string(server.description, 80U) ||
        !count(in, dns_count,
               packet::dhcpv6::maximum_message_octets /
                   packet::Ipv6{}.size()))
      return false;
    server.dns_recursive_servers.resize(dns_count);
    for (auto &address : server.dns_recursive_servers)
      if (!ipv6(in, address))
        return false;
    if (!in.integer(server.default_preferred_lifetime_seconds) ||
        !in.integer(server.default_valid_lifetime_seconds) ||
        !in.integer(server.default_renewal_time_seconds) ||
        !in.integer(server.default_rebinding_time_seconds) ||
        !in.boolean(server.default_preferred_lifetime_configured) ||
        !in.boolean(server.default_valid_lifetime_configured) ||
        !in.boolean(server.default_renewal_time_configured) ||
        !in.boolean(server.default_rebinding_time_configured) ||
        !in.integer(server.information_refresh_time_seconds) ||
        !in.integer(server.preference) ||
        !in.boolean(server.rapid_commit) ||
        !in.boolean(server.lease_query) ||
        !in.boolean(server.admin_enabled) ||
        !in.boolean(server.rapid_commit_configured) ||
        !in.boolean(server.lease_query_configured) ||
        !in.boolean(server.admin_state_configured) ||
        !count(in, pool_count,
               device_catalog::dhcpv6_address_pools_per_server +
                   device_catalog::dhcpv6_prefix_pools_per_server))
      return false;
    server.pools.resize(pool_count);
    for (auto &pool : server.pools) {
      std::uint32_t prefix_count{};
      if (!in.string(pool.name, 32U) ||
          !in.string(pool.description, 80U) ||
          !in.integer(pool.delegated_length) ||
          !in.integer(pool.minimum_delegated_length) ||
          !in.integer(pool.maximum_delegated_length) ||
          !in.boolean(pool.delegated_length_configured) ||
          !in.boolean(pool.minimum_delegated_length_configured) ||
          !in.boolean(pool.maximum_delegated_length_configured) ||
          !count(in, prefix_count,
                 device_catalog::dhcpv6_address_pools_per_server +
                     device_catalog::dhcpv6_prefix_pools_per_server))
        return false;
      pool.prefixes.resize(prefix_count);
      for (auto &prefix : pool.prefixes) {
        if (!in.integer(prefix.allocation_scope_id) ||
            !ipv6(in, prefix.aggregate.network) ||
            !in.integer(prefix.aggregate.length) ||
            !in.octets(prefix.allocation_secret) ||
            !in.integer(prefix.preferred_lifetime_seconds) ||
            !in.integer(prefix.valid_lifetime_seconds) ||
            !in.integer(prefix.renewal_time_seconds) ||
            !in.integer(prefix.rebinding_time_seconds) ||
            !in.boolean(prefix.preferred_lifetime_configured) ||
            !in.boolean(prefix.valid_lifetime_configured) ||
            !in.boolean(prefix.renewal_time_configured) ||
            !in.boolean(prefix.rebinding_time_configured) ||
            !in.boolean(prefix.wan_host) ||
            !in.boolean(prefix.delegated_prefix) ||
            !in.boolean(prefix.drain) ||
            !in.boolean(prefix.drain_configured) ||
            !in.boolean(prefix.wan_host_configured) ||
            !in.boolean(prefix.delegated_prefix_configured))
          return false;
      }
    }
  }
  return dhcpv6::configuration::validate(state, allow_incomplete) ==
         dhcpv6::configuration::Status::valid;
}

void ospf_configuration(Writer &out,
                        const ospf::RouterConfiguration &state) {
  // Keychains precede consumers so a hostile checkpoint cannot create an
  // interface leafref before its bounded secret metadata has been decoded.
  // Only opaque vault handles enter the checkpoint. Clear key material never
  // crosses this persistence boundary.
  count(out, state.keychains);
  for (const auto &keychain : state.keychains) {
    out.string(keychain.name);
    out.boolean(keychain.admin_enabled);
    count(out, keychain.bidirectional);
    for (const auto &entry : keychain.bidirectional) {
      out.integer(entry.secret);
      out.integer(entry.begin_utc_seconds);
      out.boolean(entry.end_utc_seconds.has_value());
      if (entry.end_utc_seconds)
        out.integer(*entry.end_utc_seconds);
      out.integer(entry.tolerance_seconds);
      out.integer(entry.id);
      out.integer(entry.algorithm);
      out.boolean(entry.admin_enabled);
      out.boolean(entry.algorithm_configured);
      out.boolean(entry.secret_configured);
    }
  }
  count(out, state.instances);
  for (const auto &instance : state.instances) {
    out.string(instance.export_policy);
    out.boolean(instance.configured_router_id.has_value());
    if (instance.configured_router_id)
      out.integer(*instance.configured_router_id);
    out.boolean(instance.asbr_trace_path_domain_id.has_value());
    if (instance.asbr_trace_path_domain_id)
      out.integer(*instance.asbr_trace_path_domain_id);
    out.integer(instance.reference_bandwidth_kbps);
    out.integer(instance.router_preference);
    out.integer(instance.external_preference);
    out.integer(instance.spf_initial_wait_milliseconds);
    out.integer(instance.spf_second_wait_milliseconds);
    out.integer(instance.spf_maximum_wait_milliseconds);
    out.integer(instance.lsa_initial_wait_milliseconds);
    out.integer(instance.lsa_second_wait_milliseconds);
    out.integer(instance.lsa_maximum_wait_milliseconds);
    out.integer(instance.instance_id);
    out.integer(instance.address_family);
    out.boolean(instance.asbr);
    out.boolean(instance.graceful_restart_helper);
    out.boolean(instance.loopfree_alternates);
    out.boolean(instance.overload);
    out.boolean(instance.admin_enabled);
    count(out, instance.areas);
    for (const auto &area : instance.areas) {
      out.integer(area.area_id);
      out.integer(area.type);
      out.integer(area.default_metric);
      out.boolean(area.summaries);
      out.boolean(area.nssa_translate_always);
      count(out, area.ranges);
      for (const auto &range : area.ranges) {
        ip_address(out, range.prefix.network);
        out.integer(range.prefix.length);
        out.boolean(range.advertised_metric.has_value());
        if (range.advertised_metric)
          out.integer(*range.advertised_metric);
        out.boolean(range.advertise);
      }
      count(out, area.interfaces);
      for (const auto &interface : area.interfaces) {
        out.string(interface.interface_name);
        out.string(interface.keychain);
        out.string(interface.ipsec_sa_inbound);
        out.string(interface.ipsec_sa_outbound);
        out.integer(interface.authentication_secret);
        out.integer(interface.authentication_key_id);
        out.integer(interface.cost);
        out.integer(interface.hello_interval_seconds);
        out.integer(interface.dead_interval_seconds);
        out.integer(interface.retransmit_interval_seconds);
        out.integer(interface.transmit_delay_seconds);
        out.integer(interface.priority);
        out.integer(interface.network_type);
        out.integer(interface.authentication);
        out.boolean(interface.passive);
        out.boolean(interface.mtu_mismatch_ignore);
        out.boolean(interface.admin_enabled);
        count(out, interface.nbma_neighbors);
        for (const auto &neighbor : interface.nbma_neighbors) {
          ip_address(out, neighbor.address);
          out.integer(neighbor.priority);
          out.integer(neighbor.poll_interval_seconds);
        }
      }
      count(out, area.virtual_links);
      for (const auto &link : area.virtual_links) {
        out.integer(link.transit_area_id);
        out.integer(link.remote_router_id);
        out.integer(link.hello_interval_seconds);
        out.integer(link.dead_interval_seconds);
        out.integer(link.retransmit_interval_seconds);
        out.integer(link.transmit_delay_seconds);
        out.integer(link.authentication);
        out.string(link.keychain);
        out.string(link.ipsec_sa_inbound);
        out.string(link.ipsec_sa_outbound);
        out.integer(link.authentication_secret);
        out.integer(link.authentication_key_id);
        out.boolean(link.admin_enabled);
      }
    }
  }
}

bool ospf_configuration(Reader &in,
                        ospf::RouterConfiguration &state) {
  std::uint32_t keychain_count{};
  // The platform documents 64 entries per keychain. The same bound on the
  // number of named chains is a persistence allocation guard, not a claim
  // that SR OS restricts the global namespace to this count.
  if (!count(in, keychain_count, 64U))
    return false;
  state.keychains.resize(keychain_count);
  for (auto &keychain : state.keychains) {
    std::uint32_t entry_count{};
    if (!in.string(keychain.name, 32U) ||
        !in.boolean(keychain.admin_enabled) ||
        !count(in, entry_count, 64U))
      return false;
    keychain.bidirectional.resize(entry_count);
    for (auto &entry : keychain.bidirectional) {
      bool has_end{};
      std::int64_t end{};
      if (!in.integer(entry.secret) || entry.secret == 0U ||
          !in.integer(entry.begin_utc_seconds) ||
          !in.boolean(has_end) ||
          (has_end && !in.integer(end)) ||
          !in.integer(entry.tolerance_seconds) ||
          !in.integer(entry.id) || entry.id > 63U ||
          !in.integer(entry.algorithm) ||
          entry.algorithm > ospf::KeychainAlgorithm::hmac_sha256 ||
          !in.boolean(entry.admin_enabled) ||
          !in.boolean(entry.algorithm_configured) ||
          !in.boolean(entry.secret_configured))
        return false;
      entry.end_utc_seconds =
          has_end ? std::optional<std::int64_t>{end} : std::nullopt;
    }
    if (ospf::validate(keychain) != ospf::KeychainStatus::valid)
      return false;
  }
  std::uint32_t instance_count{};
  constexpr auto maximum_instances =
      device_catalog::ospf_v2_instances_per_router +
      device_catalog::ospf_v3_instances_per_router;
  if (!count(in, instance_count, maximum_instances))
    return false;
  state.instances.resize(instance_count);
  for (auto &instance : state.instances) {
    bool has_router_id{};
    std::uint32_t router_id{};
    bool has_asbr_domain_id{};
    std::uint8_t asbr_domain_id{};
    if (!in.string(instance.export_policy, 64U) ||
        !in.boolean(has_router_id) ||
        (has_router_id && !in.integer(router_id)) ||
        (has_router_id && router_id == 0U) ||
        !in.boolean(has_asbr_domain_id) ||
        (has_asbr_domain_id && !in.integer(asbr_domain_id)) ||
        (has_asbr_domain_id && asbr_domain_id > 31U) ||
        !in.integer(instance.reference_bandwidth_kbps) ||
        !in.integer(instance.router_preference) ||
        !in.integer(instance.external_preference) ||
        !in.integer(instance.spf_initial_wait_milliseconds) ||
        !in.integer(instance.spf_second_wait_milliseconds) ||
        !in.integer(instance.spf_maximum_wait_milliseconds) ||
        !in.integer(instance.lsa_initial_wait_milliseconds) ||
        !in.integer(instance.lsa_second_wait_milliseconds) ||
        !in.integer(instance.lsa_maximum_wait_milliseconds) ||
        !in.integer(instance.instance_id) ||
        !in.integer(instance.address_family) ||
        instance.address_family > ospf::AddressFamily::ipv4_over_ospfv3 ||
        !in.boolean(instance.asbr) ||
        !in.boolean(instance.graceful_restart_helper) ||
        !in.boolean(instance.loopfree_alternates) ||
        !in.boolean(instance.overload) ||
        !in.boolean(instance.admin_enabled))
      return false;
    instance.configured_router_id =
        has_router_id ? std::optional<std::uint32_t>{router_id}
                      : std::nullopt;
    instance.asbr_trace_path_domain_id =
        has_asbr_domain_id
            ? std::optional<std::uint8_t>{asbr_domain_id}
            : std::nullopt;

    std::uint32_t area_count{};
    // This is a hostile-checkpoint allocation guard tied to the generated
    // per-instance LSA arena. It is not exposed as an SR OS area scale claim.
    if (!count(in, area_count, device_catalog::ospf_lsas_per_instance))
      return false;
    instance.areas.resize(area_count);
    for (auto &area : instance.areas) {
      if (!in.integer(area.area_id) || !in.integer(area.type) ||
          area.type > ospf::AreaType::nssa ||
          !in.integer(area.default_metric) ||
          !in.boolean(area.summaries) ||
          !in.boolean(area.nssa_translate_always))
        return false;
      std::uint32_t item_count{};
      if (!count(in, item_count, device_catalog::ospf_lsas_per_instance))
        return false;
      area.ranges.resize(item_count);
      for (auto &range : area.ranges) {
        bool has_metric{};
        std::uint32_t metric{};
        if (!ip_address(in, range.prefix.network) ||
            !in.integer(range.prefix.length) ||
            range.prefix.length >
                ip::address_bits(range.prefix.network.family) ||
            !in.boolean(has_metric) ||
            (has_metric && !in.integer(metric)) ||
            !in.boolean(range.advertise))
          return false;
        range.advertised_metric =
            has_metric ? std::optional<std::uint32_t>{metric}
                       : std::nullopt;
      }
      if (!count(in, item_count,
                 device_catalog::maximum_ports_per_router + 1U))
        return false;
      area.interfaces.resize(item_count);
      for (auto &interface : area.interfaces) {
        if (!in.string(interface.interface_name, 64U) ||
            !in.string(interface.keychain, 64U) ||
            !in.string(interface.ipsec_sa_inbound, 64U) ||
            !in.string(interface.ipsec_sa_outbound, 64U) ||
            !in.integer(interface.authentication_secret) ||
            !in.integer(interface.authentication_key_id) ||
            !in.integer(interface.cost) ||
            !in.integer(interface.hello_interval_seconds) ||
            !in.integer(interface.dead_interval_seconds) ||
            !in.integer(interface.retransmit_interval_seconds) ||
            !in.integer(interface.transmit_delay_seconds) ||
            !in.integer(interface.priority) ||
            !in.integer(interface.network_type) ||
            interface.network_type > ospf::NetworkType::virtual_link ||
            !in.integer(interface.authentication) ||
            interface.authentication >
                ospf::AuthenticationMode::ipsec_security_association ||
            !in.boolean(interface.passive) ||
            !in.boolean(interface.mtu_mismatch_ignore) ||
            !in.boolean(interface.admin_enabled))
          return false;
        std::uint32_t neighbor_count{};
        if (!count(in, neighbor_count,
                   device_catalog::ospf_neighbors_per_interface))
          return false;
        interface.nbma_neighbors.resize(neighbor_count);
        for (auto &neighbor : interface.nbma_neighbors)
          if (!ip_address(in, neighbor.address) ||
              !in.integer(neighbor.priority) ||
              !in.integer(neighbor.poll_interval_seconds))
            return false;
      }
      if (!count(in, item_count, device_catalog::ospf_lsas_per_instance))
        return false;
      area.virtual_links.resize(item_count);
      for (auto &link : area.virtual_links)
        if (!in.integer(link.transit_area_id) ||
            !in.integer(link.remote_router_id) ||
            !in.integer(link.hello_interval_seconds) ||
            !in.integer(link.dead_interval_seconds) ||
            !in.integer(link.retransmit_interval_seconds) ||
            !in.integer(link.transmit_delay_seconds) ||
            !in.integer(link.authentication) ||
            link.authentication >
                ospf::AuthenticationMode::ipsec_security_association ||
            !in.string(link.keychain, 64U) ||
            !in.string(link.ipsec_sa_inbound, 64U) ||
            !in.string(link.ipsec_sa_outbound, 64U) ||
            !in.integer(link.authentication_secret) ||
            !in.integer(link.authentication_key_id) ||
            !in.boolean(link.admin_enabled))
          return false;
    }
  }
  return ospf::validate(state) == ospf::ConfigurationStatus::valid;
}

bool valid_facility_alarm_severity(std::string_view value) noexcept {
  return value == "critical" || value == "major" || value == "minor" ||
         value == "warning";
}

void facility_alarm(Writer &out,
                    const PortableFacilityAlarmCheckpoint &state) {
  // Facility alarm indexes and civil timestamps are management presentation
  // state. Persisting them here keeps `show system alarms` stable after
  // checkpoint restore without teaching the hardware owner about CLI rows.
  out.string(state.key);
  out.string(state.code);
  out.string(state.severity);
  out.string(state.resource);
  out.string(state.detail);
  out.integer(state.index);
  out.integer(state.raised_at_epoch_ms);
  out.integer(state.cleared_at_epoch_ms);
  out.boolean(state.masked);
}

bool facility_alarm(Reader &in,
                    PortableFacilityAlarmCheckpoint &state) noexcept {
  return in.string(state.key, 96U) && !state.key.empty() &&
         in.string(state.code, 32U) && !state.code.empty() &&
         in.string(state.severity, 16U) &&
         valid_facility_alarm_severity(state.severity) &&
         in.string(state.resource, 128U) && !state.resource.empty() &&
         in.string(state.detail, 256U) && !state.detail.empty() &&
         in.integer(state.index) && state.index != 0U &&
         in.integer(state.raised_at_epoch_ms) &&
         state.raised_at_epoch_ms != 0U &&
         in.integer(state.cleared_at_epoch_ms) &&
         in.boolean(state.masked);
}

void portable_router(Writer &out, const PortableRouterIntentCheckpoint &state) {
  // Names and descriptions are management-plane configuration. They are
  // written after forwarding state so restoring a bare checkpoint never has
  // to guess them from a currently open project in the browser.
  handle(out, state.device);
  out.integer(state.maximum_ecmp_paths);
  mld_global_intent(out, state.mld);
  mld_policy_prefix_lists(out, state.mld_prefix_lists);
  named_mld_import_policies(out, state.mld_import_policies);
  rdnss_information(out, state.router_advertisement_rdnss);
  out.integer(state.router_advertisement_rdnss_lifetime_seconds);
  out.boolean(state.router_advertisement_rdnss_lifetime_configured);
  out.integer(state.ipv6_nd_reachable_time_seconds);
  out.integer(state.ipv6_nd_stale_time_seconds);
  out.boolean(state.ipv6_nd_reachable_time_configured);
  out.boolean(state.ipv6_nd_stale_time_configured);
  tls_configuration(out, state.tls);
  ipsec_configuration(out, state.ipsec);
  ies_configuration(out, state.ies);
  bof_autoconfigure(out, state.bof_autoconfigure);
  dhcpv4_router_configuration(out, state.dhcpv4_servers);
  dhcpv6_router_configuration(out, state.dhcpv6_servers);
  ospf_configuration(out, state.ospf);
  count(out, state.ports);
  for (const auto &port : state.ports) {
    out.string(port.id);
    out.boolean(port.admin_enabled);
    out.integer(port.mtu);
    out.integer(port.speed_mbps);
    out.string(port.description);
  }
  count(out, state.interfaces);
  for (const auto &interface : state.interfaces)
    portable_interface(out, interface);
  count(out, state.routes);
  for (const auto &route : state.routes) {
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
    out.boolean(route.indirect);
    out.boolean(route.admin_enabled);
    out.boolean(route.admin_state_configured);
  }
  count(out, state.ipv6_routes);
  for (const auto &route : state.ipv6_routes)
    portable_ipv6_route(out, route);
  out.boolean(state.global_candidate_initialized);
  if (state.global_candidate_initialized)
    portable_configuration(out, state.global_candidate);
  for (const auto seen : state.port_seen_operational)
    out.boolean(seen);
  count(out, state.active_facility_alarms);
  for (const auto &alarm : state.active_facility_alarms)
    facility_alarm(out, alarm);
  count(out, state.cleared_facility_alarms);
  for (const auto &alarm : state.cleared_facility_alarms)
    facility_alarm(out, alarm);
  out.integer(state.next_facility_alarm_index);
  out.boolean(state.cleared_facility_alarms_wrapped);
}

bool portable_router(Reader &in, PortableRouterIntentCheckpoint &state) {
  std::uint32_t size{};
  if (!handle(in, state.device) ||
      !in.integer(state.maximum_ecmp_paths) ||
      state.maximum_ecmp_paths == 0U ||
      state.maximum_ecmp_paths > device_catalog::maximum_ecmp_paths ||
      !mld_global_intent(in, state.mld) ||
      !mld_policy_prefix_lists(in, state.mld_prefix_lists) ||
      !named_mld_import_policies(in, state.mld_import_policies) ||
      !rdnss_information(in, state.router_advertisement_rdnss) ||
      !in.integer(state.router_advertisement_rdnss_lifetime_seconds) ||
      !in.boolean(state.router_advertisement_rdnss_lifetime_configured) ||
      !valid_rdnss_information(
          state.router_advertisement_rdnss,
          state.router_advertisement_rdnss_lifetime_seconds) ||
      (!state.router_advertisement_rdnss_lifetime_configured &&
       state.router_advertisement_rdnss_lifetime_seconds !=
           device_catalog::ra_infinite_lifetime) ||
      !in.integer(state.ipv6_nd_reachable_time_seconds) ||
      !in.integer(state.ipv6_nd_stale_time_seconds) ||
      !in.boolean(state.ipv6_nd_reachable_time_configured) ||
      !in.boolean(state.ipv6_nd_stale_time_configured) ||
      !valid_ipv6_neighbor_defaults(state.ipv6_nd_reachable_time_seconds,
                                    state.ipv6_nd_stale_time_seconds,
                                    state.ipv6_nd_reachable_time_configured,
                                    state.ipv6_nd_stale_time_configured) ||
      !tls_configuration(in, state.tls) ||
      !ipsec_configuration(in, state.ipsec) ||
      !ies_configuration(in, state.ies) ||
      !bof_autoconfigure(in, state.bof_autoconfigure) ||
      !dhcpv4_router_configuration(in, state.dhcpv4_servers) ||
      !dhcpv6_router_configuration(in, state.dhcpv6_servers) ||
      !ospf_configuration(in, state.ospf) ||
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
  // The physical port vector above is bounded by inventory. Interface intent
  // additionally admits the one reserved, portless system loopback.
  if (!count(in, size, routing::maximum_ipv4_connected_inputs))
    return false;
  state.interfaces.resize(size);
  for (auto &interface : state.interfaces)
    if (!portable_interface(in, interface))
      return false;
  if (std::any_of(state.interfaces.begin(), state.interfaces.end(),
                  [&](const auto &interface) {
                    return !valid_mld_interface_intent(interface, state.mld);
                  }) ||
      !valid_ipv6_neighbor_intents(state.interfaces) ||
      !valid_mld_policy_references(state.mld_prefix_lists,
                                   state.mld_import_policies, state.interfaces))
    return false;
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.routes.resize(size);
  for (auto &route : state.routes) {
    if (!in.integer(route.network) || !in.integer(route.next_hop) ||
        !route.next_hop || !in.integer(route.prefix_length) ||
        !in.boolean(route.indirect) || !in.boolean(route.admin_enabled) ||
        !in.boolean(route.admin_state_configured) ||
        route.prefix_length > 32U ||
        route.network !=
            (route.network & routing::prefix_mask(route.prefix_length)))
      return false;
  }
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.ipv6_routes.resize(size);
  for (auto &route : state.ipv6_routes)
    if (!portable_ipv6_route(in, route))
      return false;
  if (!in.boolean(state.global_candidate_initialized))
    return false;
  if (state.global_candidate_initialized &&
      !portable_configuration(in, state.global_candidate))
    return false;
  for (auto &seen : state.port_seen_operational)
    if (!in.boolean(seen))
      return false;
  constexpr auto maximum_active_facility_alarms =
      device_catalog::maximum_ports_per_router +
      device_catalog::maximum_card_slots *
          (1U + device_catalog::maximum_mda_slots_per_card);
  if (!count(in, size, maximum_active_facility_alarms))
    return false;
  state.active_facility_alarms.resize(size);
  for (auto &alarm : state.active_facility_alarms)
    if (!facility_alarm(in, alarm) || alarm.cleared_at_epoch_ms != 0U)
      return false;
  if (!count(in, size, device_catalog::facility_alarm_cleared_history_size))
    return false;
  state.cleared_facility_alarms.resize(size);
  for (auto &alarm : state.cleared_facility_alarms)
    if (!facility_alarm(in, alarm) || alarm.cleared_at_epoch_ms == 0U)
      return false;
  if (!in.integer(state.next_facility_alarm_index) ||
      state.next_facility_alarm_index == 0U ||
      !in.boolean(state.cleared_facility_alarms_wrapped))
    return false;
  return true;
}

void portable_configuration(Writer &out,
                            const PortableConfigurationCheckpoint &state) {
  out.string(state.system_name);
  out.integer(state.maximum_ecmp_paths);
  mld_global_intent(out, state.mld);
  mld_policy_prefix_lists(out, state.mld_prefix_lists);
  named_mld_import_policies(out, state.mld_import_policies);
  rdnss_information(out, state.router_advertisement_rdnss);
  out.integer(state.router_advertisement_rdnss_lifetime_seconds);
  out.boolean(state.router_advertisement_rdnss_lifetime_configured);
  out.integer(state.ipv6_nd_reachable_time_seconds);
  out.integer(state.ipv6_nd_stale_time_seconds);
  out.boolean(state.ipv6_nd_reachable_time_configured);
  out.boolean(state.ipv6_nd_stale_time_configured);
  tls_configuration(out, state.tls);
  ipsec_configuration(out, state.ipsec);
  ies_configuration(out, state.ies);
  bof_autoconfigure(out, state.bof_autoconfigure);
  dhcpv4_router_configuration(out, state.dhcpv4_servers);
  dhcpv6_router_configuration(out, state.dhcpv6_servers);
  ospf_configuration(out, state.ospf);
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
  for (const auto &interface : state.interfaces)
    portable_interface(out, interface);
  count(out, state.routes);
  for (const auto &route : state.routes) {
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
    out.boolean(route.indirect);
    out.boolean(route.admin_enabled);
    out.boolean(route.admin_state_configured);
  }
  count(out, state.ipv6_routes);
  for (const auto &route : state.ipv6_routes)
    portable_ipv6_route(out, route);
}

bool portable_configuration(Reader &in,
                            PortableConfigurationCheckpoint &state) {
  if (!in.string(state.system_name, 64) || state.system_name.empty() ||
      !in.integer(state.maximum_ecmp_paths) ||
      state.maximum_ecmp_paths == 0U ||
      state.maximum_ecmp_paths > device_catalog::maximum_ecmp_paths ||
      !mld_global_intent(in, state.mld) ||
      !mld_policy_prefix_lists(in, state.mld_prefix_lists) ||
      !named_mld_import_policies(in, state.mld_import_policies) ||
      !rdnss_information(in, state.router_advertisement_rdnss) ||
      !in.integer(state.router_advertisement_rdnss_lifetime_seconds) ||
      !in.boolean(state.router_advertisement_rdnss_lifetime_configured) ||
      !valid_rdnss_information(
          state.router_advertisement_rdnss,
          state.router_advertisement_rdnss_lifetime_seconds) ||
      (!state.router_advertisement_rdnss_lifetime_configured &&
       state.router_advertisement_rdnss_lifetime_seconds !=
           device_catalog::ra_infinite_lifetime) ||
      !in.integer(state.ipv6_nd_reachable_time_seconds) ||
      !in.integer(state.ipv6_nd_stale_time_seconds) ||
      !in.boolean(state.ipv6_nd_reachable_time_configured) ||
      !in.boolean(state.ipv6_nd_stale_time_configured) ||
      !valid_ipv6_neighbor_defaults(state.ipv6_nd_reachable_time_seconds,
                                    state.ipv6_nd_stale_time_seconds,
                                    state.ipv6_nd_reachable_time_configured,
                                    state.ipv6_nd_stale_time_configured) ||
      !tls_configuration(in, state.tls) ||
      !ipsec_configuration(in, state.ipsec, true) ||
      !ies_configuration(in, state.ies, true) ||
      !bof_autoconfigure(in, state.bof_autoconfigure) ||
      !dhcpv4_router_configuration(in, state.dhcpv4_servers) ||
      !dhcpv6_router_configuration(in, state.dhcpv6_servers, true) ||
      !ospf_configuration(in, state.ospf))
    return false;
  for (auto &card : state.cards) {
    if (!in.string(card.provisioned, 64) || !in.boolean(card.admin_enabled))
      return false;
    for (auto &mda : card.mdas)
      if (!in.string(mda.provisioned, 64) || !in.boolean(mda.admin_enabled))
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
  // Candidate configuration uses the same logical capacity as running state:
  // every physical routed port plus the portless system interface.
  if (!count(in, size, routing::maximum_ipv4_connected_inputs))
    return false;
  state.interfaces.resize(size);
  for (auto &interface : state.interfaces)
    if (!portable_interface(in, interface, true))
      return false;
  if (std::any_of(state.interfaces.begin(), state.interfaces.end(),
                  [&](const auto &interface) {
                    return !valid_mld_interface_intent(interface, state.mld);
                  }) ||
      !valid_ipv6_neighbor_intents(state.interfaces) ||
      !valid_mld_policy_references(state.mld_prefix_lists,
                                   state.mld_import_policies, state.interfaces))
    return false;
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.routes.resize(size);
  for (auto &route : state.routes)
    if (!in.integer(route.network) || !in.integer(route.next_hop) ||
        !route.next_hop || !in.integer(route.prefix_length) ||
        !in.boolean(route.indirect) || !in.boolean(route.admin_enabled) ||
        !in.boolean(route.admin_state_configured) ||
        route.prefix_length > 32U ||
        route.network !=
            (route.network & routing::prefix_mask(route.prefix_length)))
      return false;
  if (!count(in, size, device_catalog::maximum_static_routes_per_router))
    return false;
  state.ipv6_routes.resize(size);
  for (auto &route : state.ipv6_routes)
    if (!portable_ipv6_route(in, route))
      return false;
  return true;
}

void interface_identifier(
    Writer &out, const host::Ipv6InterfaceIdentifierConfiguration &state) {
  out.octets(state.modified_eui64);
  out.octets(state.stable_secret);
  out.integer(state.network_id_octets);
  out.octets(std::span<const std::uint8_t>{state.network_id}.first(
      state.network_id_octets));
  out.integer(state.mode);
}

bool interface_identifier(
    Reader &in, host::Ipv6InterfaceIdentifierConfiguration &state) noexcept {
  if (!in.octets(state.modified_eui64) || !in.octets(state.stable_secret) ||
      !in.integer(state.network_id_octets) ||
      state.network_id_octets > state.network_id.size())
    return false;
  state.network_id.fill(0U);
  if (!in.octets(std::span<std::uint8_t>{state.network_id}.first(
          state.network_id_octets)) ||
      !in.integer(state.mode) ||
      state.mode > host::InterfaceIdentifierMode::stable_opaque)
    return false;
  return state.mode != host::InterfaceIdentifierMode::stable_opaque ||
         std::any_of(state.stable_secret.begin(), state.stable_secret.end(),
                     [](std::uint8_t value) { return value != 0U; });
}

void portable_host(Writer &out, const PortableHostIntentCheckpoint &state) {
  handle(out, state.host);
  mac(out, state.mac);
  ipv4(out, state.address);
  ipv4(out, state.gateway);
  out.integer(state.prefix_length);
  out.integer(state.mtu);
  out.integer(state.interface_id);
  out.boolean(state.configured);
  out.boolean(state.ipv6_autoconfiguration);
  interface_identifier(out, state.ipv6_identifier);
  out.octets(state.transport_secret);
}

bool portable_host(Reader &in, PortableHostIntentCheckpoint &state) noexcept {
  if (!handle(in, state.host) || !mac(in, state.mac) ||
      !ipv4(in, state.address) || !ipv4(in, state.gateway) ||
      !in.integer(state.prefix_length) || state.prefix_length > 32U ||
      !in.integer(state.mtu) || !in.integer(state.interface_id) ||
      !in.boolean(state.configured) ||
      !in.boolean(state.ipv6_autoconfiguration) ||
      !interface_identifier(in, state.ipv6_identifier) ||
      !in.octets(state.transport_secret) ||
      (state.configured &&
       std::all_of(state.transport_secret.begin(), state.transport_secret.end(),
                   [](std::uint8_t value) { return value == 0U; })))
    return false;
  // An unconfigured host has no user-selected MTU yet. Configured hosts must
  // satisfy the IPv4 minimum accepted by the live host operation.
  return !state.configured ||
         (state.mtu >= device_catalog::minimum_host_ipv4_mtu &&
          state.mtu <= device_catalog::maximum_network_mtu &&
          (!state.ipv6_autoconfiguration ||
           (state.interface_id && state.mtu >= packet::ipv6_minimum_link_mtu)));
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

bool portable_capture(Reader &in, PortableCaptureIntentCheckpoint &state) {
  return in.integer(state.id) &&
         state.id != std::numeric_limits<CapturePointId>::max() &&
         in.integer(state.kind) && state.kind <= CapturePointKind::cpm_punt &&
         in.string(state.object_id, 64) && !state.object_id.empty() &&
         in.string(state.port_id, 32) && in.integer(state.direction) &&
         state.direction <= 1U && in.boolean(state.selected);
}

void secret_vault(Writer &out, const vault::Checkpoint &state) {
  out.integer(state.next_handle);
  count(out, state.records);
  for (const auto &record : state.records) {
    out.integer(record.handle);
    out.integer(record.kind);
    if (record.sealed.size() > std::numeric_limits<std::uint32_t>::max())
      throw std::length_error("sealed secret exceeds checkpoint ABI bound");
    out.integer(static_cast<std::uint32_t>(record.sealed.size()));
    out.octets(record.sealed);
  }
}

bool secret_vault(Reader &in, vault::Checkpoint &state) {
  constexpr std::size_t maximum_sealed_secret_octets =
      64U * 1024U + 4U + 1U + 12U + 4U + 16U;
  std::uint32_t size{};
  if (!in.integer(state.next_handle) || !state.next_handle ||
      !count(in, size, profile::maximum_project_secret_records))
    return false;
  state.records.resize(size);
  vault::SecretHandle previous{};
  for (auto &record : state.records) {
    std::uint32_t sealed_size{};
    if (!in.integer(record.handle) || !record.handle ||
        record.handle <= previous || record.handle >= state.next_handle ||
        !in.integer(record.kind) ||
        record.kind < vault::SecretKind::ipsec_ppk_ascii ||
        record.kind > vault::SecretKind::ospf_authentication_key ||
        !in.integer(sealed_size) || !sealed_size ||
        sealed_size > maximum_sealed_secret_octets)
      return false;
    const auto bytes = in.view(sealed_size);
    if (!bytes)
      return false;
    record.sealed.assign(bytes->begin(), bytes->end());
    previous = record.handle;
  }
  return true;
}

} // namespace

std::vector<std::uint8_t> encode(const RuntimeSupervisorCheckpoint &state) {
  Writer out;
  for (const auto byte : magic)
    out.integer(byte);
  out.integer(abi);
  out.integer(schema_hash);
  out.integer(device_catalog::catalog_hash);
  out.integer(device_catalog::build_hash);
  device_registry(out, state.devices);
  host_registry(out, state.hosts);
  switch_registry(out, state.switches);
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
    out.boolean(value.classic_policy_edit_active);
    if (value.classic_policy_edit_active)
      portable_configuration(out, value.classic_policy_candidate);
    out.integer(value.ping_destination);
    ipv6(out, value.ping_destination_ipv6);
    out.integer(value.ping_sequence);
    out.integer(value.ping_payload_octets);
    out.integer(value.ping_requested);
    out.integer(value.ping_sent);
    out.integer(value.ping_received);
    out.integer(value.ping_rtt_min_microseconds);
    out.integer(value.ping_rtt_max_microseconds);
    out.integer(value.ping_rtt_sum_microseconds);
    out.integer(value.ping_rtt_squared_sum_microseconds);
    out.integer(value.ping_next_send_ns);
    out.integer(value.ping_reply_deadline_ns);
    out.boolean(value.ping_dont_fragment);
    out.boolean(value.ping_ipv6);
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
  secret_vault(out, state.secret_vault);
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
        !in.integer(input_build) || input_build != device_catalog::build_hash)
      return nullptr;
    auto state = std::make_unique<RuntimeSupervisorCheckpoint>();
    if (!device_registry(in, state->devices) ||
        !host_registry(in, state->hosts) ||
        !switch_registry(in, state->switches) ||
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
    if (!workflows(in, state->workflows))
      return nullptr;
    if (!network_state(in, state->network) ||
        !in.integer(state->next_network_command_id) ||
        !count(in, size, device_catalog::maximum_routers))
      return nullptr;
    state->portable_routers.resize(size);
    for (auto &value : state->portable_routers)
      if (!portable_router(in, value))
        return nullptr;
    if (!count(in, size,
               device_catalog::maximum_routers *
                   device_catalog::maximum_sessions_per_router))
      return nullptr;
    state->portable_session_candidates.resize(size);
    for (auto &value : state->portable_session_candidates) {
      if (!handle(in, value.session) || !in.boolean(value.initialized) ||
          (value.initialized && !portable_configuration(in, value.candidate)) ||
          !in.boolean(value.classic_policy_edit_active) ||
          (value.classic_policy_edit_active &&
           !portable_configuration(in, value.classic_policy_candidate)) ||
          !in.integer(value.ping_destination) ||
          !ipv6(in, value.ping_destination_ipv6) ||
          !in.integer(value.ping_sequence) ||
          !in.integer(value.ping_payload_octets) ||
          value.ping_payload_octets <
              device_catalog::minimum_ping_payload_octets ||
          value.ping_payload_octets >
              device_catalog::maximum_ping_payload_octets ||
          !in.integer(value.ping_requested) ||
          value.ping_requested > device_catalog::maximum_ping_count ||
          !in.integer(value.ping_sent) || !in.integer(value.ping_received) ||
          value.ping_received > value.ping_sent ||
          value.ping_sent > value.ping_requested ||
          !in.integer(value.ping_rtt_min_microseconds) ||
          !in.integer(value.ping_rtt_max_microseconds) ||
          !in.integer(value.ping_rtt_sum_microseconds) ||
          !in.integer(value.ping_rtt_squared_sum_microseconds) ||
          (value.ping_received == 0U &&
           (value.ping_rtt_min_microseconds != 0U ||
            value.ping_rtt_max_microseconds != 0U ||
            value.ping_rtt_sum_microseconds != 0U ||
            value.ping_rtt_squared_sum_microseconds != 0U)) ||
          (value.ping_received != 0U &&
           (value.ping_rtt_min_microseconds >
                value.ping_rtt_max_microseconds ||
            value.ping_rtt_min_microseconds >
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        device_catalog::ping_timeout)
                        .count()) ||
            value.ping_rtt_max_microseconds >
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        device_catalog::ping_timeout)
                        .count()))) ||
          !in.integer(value.ping_next_send_ns) ||
          value.ping_next_send_ns >
              static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(
                      device_catalog::checkpoint_max_relative_deadline)
                      .count()) ||
          !in.integer(value.ping_reply_deadline_ns) ||
          value.ping_reply_deadline_ns >
              static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(
                      device_catalog::checkpoint_max_relative_deadline)
                      .count()) ||
          !in.boolean(value.ping_dont_fragment) ||
          !in.boolean(value.ping_ipv6) || !in.boolean(value.ping_waiting) ||
          !in.boolean(value.ping_active) ||
          !in.boolean(value.ping_cancel_requested) ||
          (value.ping_waiting && !value.ping_active) ||
          (value.ping_active && !value.ping_requested) ||
          (value.ping_active && value.ping_ipv6 &&
           (ip::is_unspecified(value.ping_destination_ipv6) ||
            ip::is_multicast(value.ping_destination_ipv6))))
        return nullptr;
    }
    if (!count(in, size, device_catalog::maximum_hosts))
      return nullptr;
    state->portable_hosts.resize(size);
    for (auto &value : state->portable_hosts)
      if (!portable_host(in, value))
        return nullptr;
    if (!count(in, size, device_catalog::maximum_active_capture_points))
      return nullptr;
    state->portable_capture_points.resize(size);
    for (auto &value : state->portable_capture_points)
      if (!portable_capture(in, value))
        return nullptr;
    if (!secret_vault(in, state->secret_vault))
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

} // namespace router::lab::checkpoint_v7
