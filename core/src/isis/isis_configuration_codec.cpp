// Versioned intent codec with bounded detached allocation. Configuration and
// persistence owners publish values only after this module returns success.
#include "router/isis_configuration_codec.hpp"
#include <limits>
#include <tuple>
#include <type_traits>
namespace router::isis::configuration_codec {
namespace {
template<class T> struct Optional : std::false_type {};
template<class T> struct Optional<std::optional<T>> : std::true_type {};
template<class T> struct Vector : std::false_type {};
template<class T> struct Vector<std::vector<T>> : std::true_type {};
template<class T> struct Array : std::false_type {};
template<class T, std::size_t N> struct Array<std::array<T, N>> : std::true_type {};
template<class T> requires std::is_same_v<std::remove_const_t<T>, InterfaceLevelIntent>
auto fields(T &v) { [[maybe_unused]] auto &[present, metric, hello_interval_seconds, hello_multiplier, priority, passive] = v;
  return std::tie(v.present, v.metric, v.hello_interval_seconds, v.hello_multiplier, v.priority, v.passive); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, InstanceLevelIntent>
auto fields(T &v) { [[maybe_unused]] auto &[present, default_metric, lsp_mtu_octets, preference, external_preference, wide_metrics_only] = v;
  return std::tie(v.present, v.default_metric, v.lsp_mtu_octets, v.preference, v.external_preference, v.wide_metrics_only); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, InterfaceIntent>
auto fields(T &v) { [[maybe_unused]] auto &[name, type, levels, admin_enabled, passive, csnp_interval_seconds, retransmit_interval_seconds, lsp_pacing_interval_milliseconds, level] = v;
  return std::tie(v.name, v.type, v.levels, v.admin_enabled, v.passive, v.csnp_interval_seconds, v.retransmit_interval_seconds, v.lsp_pacing_interval_milliseconds, v.level); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, InstanceIntent>
auto fields(T &v) { [[maybe_unused]] auto &[instance, admin_enabled, ipv4_routing, ipv6_routing, levels, system_id, router_id, lsp_lifetime_seconds, lsp_mtu_octets, level, areas, interfaces, spf_wait, lsp_wait] = v;
  return std::tie(v.instance, v.admin_enabled, v.ipv4_routing, v.ipv6_routing, v.levels, v.system_id, v.router_id, v.lsp_lifetime_seconds, v.lsp_mtu_octets, v.level, v.areas, v.interfaces, v.spf_wait, v.lsp_wait); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, WaitTimerIntent>
auto fields(T &v) { [[maybe_unused]] auto &[maximum, initial, second] = v; return std::tie(v.maximum, v.initial, v.second); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, NeighborArea>
auto fields(T &v) { [[maybe_unused]] auto &[bytes, length] = v; return std::tie(v.bytes, v.length); }
template<class T> requires std::is_same_v<std::remove_const_t<T>, RouterConfiguration>
auto fields(T &v) { [[maybe_unused]] auto &[instances] = v; return std::tie(v.instances); }
class Writer {
public:
  explicit Writer(std::size_t maximum) : maximum_(maximum) {}
  template<class... T> bool operator()(const T &...value) { return (one(value) && ...); }
  std::vector<std::uint8_t> bytes;
private:
  bool byte(std::uint8_t value) { if (bytes.size() == maximum_) return false; bytes.push_back(value); return true; }
  template<class T> bool one(const T &value) {
    if constexpr (std::is_same_v<T, bool>) return byte(static_cast<std::uint8_t>(value));
    else if constexpr (std::is_enum_v<T>) return one(static_cast<std::underlying_type_t<T>>(value));
    else if constexpr (std::is_integral_v<T>) {
      static_assert(std::is_unsigned_v<T>);
      for (std::size_t index{}; index < sizeof(T); ++index)
        if (!byte(static_cast<std::uint8_t>(value >> (index * 8U)))) return false;
      return true;
    } else if constexpr (Optional<T>::value) return one(value.has_value()) && (!value || one(*value));
    else if constexpr (std::is_same_v<T, std::string>) {
      if (value.size() > std::numeric_limits<std::uint16_t>::max() || !one(static_cast<std::uint16_t>(value.size()))) return false;
      for (const auto character : value) if (!byte(static_cast<std::uint8_t>(character))) return false;
      return true;
    } else if constexpr (Vector<T>::value || Array<T>::value) {
      if constexpr (Vector<T>::value)
        if (value.size() > std::numeric_limits<std::uint32_t>::max() || !one(static_cast<std::uint32_t>(value.size()))) return false;
      for (const auto &entry : value) if (!one(entry)) return false;
      return true;
    } else return std::apply([&](const auto &...member) { return (*this)(member...); }, fields(value));
  }
  std::size_t maximum_;
};
class Reader {
public:
  Reader(std::span<const std::uint8_t> bytes, std::size_t budget, std::uint8_t version) : bytes_(bytes), budget_(budget), version_(version) {}
  template<class... T> bool operator()(T &...value) { return (one(value) && ...); }
  bool finished() const noexcept { return offset_ == bytes_.size(); }
private:
  std::size_t remaining() const noexcept { return bytes_.size() - offset_; }
  template<class T> bool one(T &value) {
    if constexpr (std::is_same_v<T, bool>) {
      if (!remaining() || bytes_[offset_] > 1U) return false;
      value = bytes_[offset_++] != 0U; return true;
    } else if constexpr (std::is_enum_v<T>) {
      std::underlying_type_t<T> raw{};
      if (!one(raw)) return false;
      value = static_cast<T>(raw); return true;
    } else if constexpr (std::is_integral_v<T>) {
      static_assert(std::is_unsigned_v<T>);
      if (remaining() < sizeof(T)) return false;
      std::uint64_t raw{};
      for (std::size_t index{}; index < sizeof(T); ++index) raw |= std::uint64_t{bytes_[offset_++]} << (index * 8U);
      value = static_cast<T>(raw); return true;
    } else if constexpr (Optional<T>::value) {
      bool present{};
      if (!one(present)) return false;
      if (!present) { value.reset(); return true; }
      return one(value.emplace());
    } else if constexpr (std::is_same_v<T, std::string>) {
      std::uint16_t size{};
      // The sole string is a 32-scalar interface name, at most 128 UTF-8 bytes.
      if (!one(size) || size > 128U || size > remaining() || size > budget_) return false;
      budget_ -= size;
      value.assign(reinterpret_cast<const char *>(bytes_.data() + offset_), size);
      offset_ += size; return true;
    } else if constexpr (Vector<T>::value) {
      std::uint32_t count{};
      using Element = typename T::value_type;
      if (!one(count) || count > remaining() || count > budget_ / sizeof(Element)) return false;
      budget_ -= std::size_t{count} * sizeof(Element);
      value.clear(); value.reserve(count);
      for (std::uint32_t index{}; index < count; ++index) if (!one(value.emplace_back())) return false;
      return true;
    } else if constexpr (Array<T>::value) {
      for (auto &entry : value) if (!one(entry)) return false;
      return true;
    } else if constexpr (std::is_same_v<T, InstanceIntent>) {
      if (version_ == 1U) return (*this)(value.instance, value.admin_enabled, value.ipv4_routing,
          value.ipv6_routing, value.levels, value.system_id, value.router_id, value.lsp_lifetime_seconds,
          value.lsp_mtu_octets, value.level, value.areas, value.interfaces);
      return std::apply([&](auto &...member) { return (*this)(member...); }, fields(value));
    } else return std::apply([&](auto &...member) { return (*this)(member...); }, fields(value));
  }
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{}, budget_{};
  std::uint8_t version_{};
};
}
std::optional<std::vector<std::uint8_t>> encode(const RouterConfiguration &value, std::size_t maximum) noexcept {
  if (validate_configuration(value) != ConfigurationError::none) return {};
  try { Writer writer{maximum}; if (!writer(std::uint8_t{2U}, value)) return {}; return std::move(writer.bytes); }
  catch (...) { return {}; }
}
std::unique_ptr<RouterConfiguration> decode(std::span<const std::uint8_t> bytes, std::size_t maximum) noexcept {
  if (maximum < sizeof(RouterConfiguration)) return {};
  try {
    auto value = std::make_unique<RouterConfiguration>();
    if (bytes.empty() || (bytes.front() != 1U && bytes.front() != 2U)) return {};
    Reader reader{bytes.subspan(1U), maximum - sizeof(RouterConfiguration), bytes.front()};
    if (!reader(*value) || !reader.finished() ||
        validate_configuration(*value) != ConfigurationError::none) return {};
    return value;
  } catch (...) { return {}; }
}
}
