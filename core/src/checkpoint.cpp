// Versioned little-endian checkpoint implementation. Validation completes into
// a private Image before the runtime replaces any live control-owned state.

#include "router/checkpoint.hpp"

#include <algorithm>
#include <cstring>
#include <type_traits>

namespace router::checkpoint {
namespace {

constexpr std::array<std::uint8_t, 8> magic{'R', 'S', 'I', 'M',
                                            'C', 'P', '2', 0};
constexpr std::uint32_t version = 2;
constexpr std::uint64_t build_hash = 0x202607140004ULL;
constexpr std::uint64_t profile_hash = 0x775000070004ULL;

class Writer {
public:
  template <typename Integer> void integer(Integer value) {
    using Unsigned = std::make_unsigned_t<Integer>;
    const auto bits = static_cast<Unsigned>(value);
    for (std::size_t index = 0; index < sizeof(Integer); ++index) {
      bytes.push_back(static_cast<std::uint8_t>(bits >> (index * 8U)));
    }
  }
  template <typename Type, std::size_t N>
  void fixed(const std::array<Type, N> &value) {
    const auto *first = reinterpret_cast<const std::uint8_t *>(value.data());
    bytes.insert(bytes.end(), first, first + sizeof(Type) * N);
  }
  std::vector<std::uint8_t> bytes;
};

class Reader {
public:
  explicit Reader(std::span<const std::uint8_t> input) : bytes_(input) {}

  template <typename Integer> bool integer(Integer &value) {
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
    const auto size = sizeof(Type) * N;
    if (offset_ + size > bytes_.size())
      return false;
    std::memcpy(value.data(), bytes_.data() + offset_, size);
    offset_ += size;
    return true;
  }

  [[nodiscard]] bool complete() const noexcept {
    return offset_ == bytes_.size();
  }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{};
};

void configuration(Writer &out, const DeviceConfiguration &value) {
  out.integer<std::uint8_t>(value.card_provisioned);
  out.integer<std::uint8_t>(value.mda_provisioned);
  out.integer<std::uint8_t>(value.card_admin_enabled);
  out.integer<std::uint8_t>(value.mda_admin_enabled);
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
  }
  for (const auto &route : value.static_routes) {
    out.integer<std::uint8_t>(route.valid);
    out.integer(route.network);
    out.integer(route.next_hop);
    out.integer(route.prefix_length);
  }
}

bool boolean(Reader &in, bool &value) {
  std::uint8_t raw{};
  if (!in.integer(raw) || raw > 1)
    return false;
  value = raw != 0;
  return true;
}

bool configuration(Reader &in, DeviceConfiguration &value) {
  if (!boolean(in, value.card_provisioned) ||
      !boolean(in, value.mda_provisioned) ||
      !boolean(in, value.card_admin_enabled) ||
      !boolean(in, value.mda_admin_enabled) || !in.fixed(value.system_name) ||
      std::find(value.system_name.begin(), value.system_name.end(), '\0') ==
          value.system_name.end())
    return false;
  for (auto &port : value.ports) {
    if (!boolean(in, port.admin_enabled) || !in.integer(port.mtu) ||
        port.mtu < 576 || port.mtu > 1500 || !in.fixed(port.description) ||
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
        interface.port_index >= profile::port_count) {
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

std::uint8_t drop_reason_code(const char *reason) noexcept {
  if (!reason)
    return 0;
  if (std::strcmp(reason, "ingress-down") == 0)
    return 1;
  if (std::strcmp(reason, "route-miss") == 0)
    return 2;
  if (std::strcmp(reason, "queue-full") == 0)
    return 3;
  if (std::strcmp(reason, "ttl-expired") == 0)
    return 4;
  if (std::strcmp(reason, "timeout") == 0)
    return 5;
  if (std::strcmp(reason, "malformed") == 0)
    return 6;
  return 0;
}

const char *drop_reason(std::uint8_t code) noexcept {
  switch (code) {
  case 1:
    return "ingress-down";
  case 2:
    return "route-miss";
  case 3:
    return "queue-full";
  case 4:
    return "ttl-expired";
  case 5:
    return "timeout";
  case 6:
    return "malformed";
  default:
    return nullptr;
  }
}

} // namespace

std::vector<std::uint8_t> encode(const DeviceState &device,
                                 const CliSession &session,
                                 std::uint64_t fib_generation,
                                 std::chrono::steady_clock::time_point now) {
  Writer out;
  out.fixed(magic);
  out.integer(version);
  out.integer(build_hash);
  out.integer(profile_hash);
  const auto remaining = [now](const EquipmentState &equipment) {
    if (equipment.lifecycle != EquipmentLifecycle::initializing ||
        equipment.deadline <= now)
      return std::uint64_t{};
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            equipment.deadline - now)
            .count());
  };
  out.integer(remaining(device.hardware.card));
  out.integer(remaining(device.hardware.mda));
  configuration(out, device.configuration.running);
  configuration(out, device.configuration.candidate);
  for (const auto *equipment : {&device.hardware.card, &device.hardware.mda}) {
    out.integer<std::uint8_t>(equipment->present);
    out.integer<std::uint8_t>(equipment->compatible);
    out.integer(static_cast<std::uint8_t>(equipment->lifecycle));
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
  }
  out.integer(static_cast<std::uint8_t>(session.engine));
  out.integer<std::uint8_t>(session.candidate_dirty);
  out.integer<std::uint8_t>(session.candidate_outdated);
  out.integer(fib_generation);
  return std::move(out.bytes);
}

std::optional<Image> decode(std::span<const std::uint8_t> bytes) {
  Reader in(bytes);
  std::array<std::uint8_t, magic.size()> input_magic{};
  std::uint32_t input_version{};
  std::uint64_t input_build{};
  std::uint64_t input_profile{};
  Image image;
  if (!in.fixed(input_magic) || input_magic != magic ||
      !in.integer(input_version) || input_version != version ||
      !in.integer(input_build) || input_build != build_hash ||
      !in.integer(input_profile) || input_profile != profile_hash ||
      !in.integer(image.card_remaining_ns) ||
      !in.integer(image.mda_remaining_ns) ||
      !configuration(in, image.device.configuration.running) ||
      !configuration(in, image.device.configuration.candidate))
    return std::nullopt;
  for (auto *equipment :
       {&image.device.hardware.card, &image.device.hardware.mda}) {
    std::uint8_t lifecycle{};
    if (!boolean(in, equipment->present) ||
        !boolean(in, equipment->compatible) || !in.integer(lifecycle) ||
        lifecycle > static_cast<std::uint8_t>(EquipmentLifecycle::mismatch))
      return std::nullopt;
    equipment->lifecycle = static_cast<EquipmentLifecycle>(lifecycle);
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
      !in.integer(reason) || reason > 6) {
    return std::nullopt;
  }
  image.device.operational.last_drop_reason = drop_reason(reason);
  for (auto &entry : image.device.operational.arp) {
    if (!boolean(in, entry.valid) || !in.fixed(entry.address) ||
        !in.fixed(entry.mac) || !in.integer(entry.port_index) ||
        entry.port_index >= profile::port_count) {
      return std::nullopt;
    }
  }
  std::uint8_t engine{};
  if (!in.integer(engine) ||
      engine > static_cast<std::uint8_t>(CliEngine::classic) ||
      !boolean(in, image.session.candidate_dirty) ||
      !boolean(in, image.session.candidate_outdated) ||
      !in.integer(image.fib_generation) || !in.complete())
    return std::nullopt;
  image.session.engine = static_cast<CliEngine>(engine);
  return image;
}

} // namespace router::checkpoint
