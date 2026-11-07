// The persistence coordinator serializes an explicit detached graph and seals
// it under the project checkpoint purpose. Decoding authenticates before bounded
// construction. Neither direction can mutate a router, queue or credential store.

#include "router/isis_checkpoint_codec.hpp"
#include "isis_checkpoint_fields.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <bit>
#include <limits>

namespace router::lab::isis_checkpoint {
namespace {
constexpr std::array<std::uint8_t, 8U> magic{'R', 'S', 'I', 'S', 'I', 'S', '0', '1'};
constexpr auto maximum = device_catalog::wasm_initial_memory_bytes;
template <typename> struct Vector : std::false_type {};
template <typename T, typename A> struct Vector<std::vector<T, A>> : std::true_type {};
template <typename> struct Array : std::false_type {};
template <typename T, std::size_t N> struct Array<std::array<T, N>> : std::true_type {};
template <typename> struct Optional : std::false_type {};
template <typename T> struct Optional<std::optional<T>> : std::true_type {};
template <typename> struct Variant : std::false_type {};
template <typename... T> struct Variant<std::variant<T...>> : std::true_type {};
template <typename> struct Duration : std::false_type {};
template <typename R, typename P> struct Duration<std::chrono::duration<R, P>> : std::true_type {};

template <typename Archive, typename T> bool object(Archive &archive, T &value) {
  if constexpr (std::is_same_v<std::remove_const_t<T>, ::router::routing::RouteGeneration>) {
    [[maybe_unused]] auto &[device, generation, ipv4, ipv6, ipv4_count, ipv6_count] = value;
    // Unused route capacity is neither owned intent nor wire state. Counts are
    // bounded before traversal, preserving queued inadmissible routes for their
    // ordinary RIB refusal without serializing thousands of empty entries.
    return archive(value.device, value.generation, value.ipv4_count, value.ipv6_count) &&
        archive.prefix(value.ipv4, value.ipv4_count) && archive.prefix(value.ipv6, value.ipv6_count);
  } else return std::apply([&](auto &...field) { return archive(field...); }, detail::members(value));
}
// Erase every released allocation, including vector growth buffers. Cleansing
// only the final vector would leave earlier serialized wire copies in the heap.
template <typename T> struct CleansingAllocator {
  using value_type = T;
  CleansingAllocator() = default;
  template <typename U> CleansingAllocator(const CleansingAllocator<U> &) noexcept {}
  [[nodiscard]] T *allocate(std::size_t count) { return std::allocator<T>{}.allocate(count); }
  void deallocate(T *value, std::size_t count) noexcept {
    if (value) OPENSSL_cleanse(value, count * sizeof(T));
    std::allocator<T>{}.deallocate(value, count);
  }
  template <typename U> bool operator==(const CleansingAllocator<U> &) const noexcept { return true; }
};
class Writer final {
public:
  Writer() = default;
  Writer(const Writer &) = delete;
  Writer &operator=(const Writer &) = delete;
  template <typename... T> bool operator()(const T &...value) { return (one(value) && ...); }
  template <typename T, std::size_t N> bool prefix(const std::array<T, N> &value, std::size_t count) {
    if (count > N) return false;
    for (std::size_t index{}; index < count; ++index) if (!one(value[index])) return false;
    return true;
  }
  [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept { return bytes_; }
private:
  bool append(std::span<const std::uint8_t> value) {
    if (value.size() > maximum - bytes_.size()) return false;
    bytes_.insert(bytes_.end(), value.begin(), value.end());
    return true;
  }
  bool integer(std::uint64_t value) {
    if (bytes_.size() > maximum - 8U) return false;
    for (unsigned byte{}; byte < 8U; ++byte) bytes_.push_back(static_cast<std::uint8_t>(value >> (8U * byte)));
    return true;
  }
  template <typename T> bool one(const T &value) {
    if constexpr (std::is_same_v<T, bool>) {
      const std::array<std::uint8_t, 1U> byte{static_cast<std::uint8_t>(value)};
      return append(byte);
    } else if constexpr (std::is_integral_v<T> || std::is_enum_v<T>) return integer(static_cast<std::uint64_t>(value));
    else if constexpr (Duration<T>::value) return one(value.count());
    else if constexpr (Optional<T>::value) return one(value.has_value()) && (!value || one(*value));
    else if constexpr (Variant<T>::value) return one(value.index()) && std::visit([&](const auto &entry) { return one(entry); }, value);
    else if constexpr (Vector<T>::value || Array<T>::value) {
      if constexpr (Vector<T>::value) if (!integer(value.size())) return false;
      if constexpr (std::is_same_v<typename T::value_type, std::uint8_t>) return append(value);
      else { for (const auto &entry : value) if (!one(entry)) return false; return true; }
    } else return object(*this, value);
  }
  std::vector<std::uint8_t, CleansingAllocator<std::uint8_t>> bytes_;
};
class Reader final {
public:
  explicit Reader(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
  template <typename... T> bool operator()(T &...value) { return (one(value) && ...); }
  template <typename T, std::size_t N> bool prefix(std::array<T, N> &value, std::size_t count) {
    if (count > N) return false;
    for (std::size_t index{}; index < count; ++index) if (!one(value[index])) return false;
    return true;
  }
  [[nodiscard]] bool finished() const noexcept { return offset_ == bytes_.size(); }
private:
  bool integer(std::uint64_t &value) noexcept {
    if (remaining() < 8U) return false;
    value = 0U;
    for (unsigned byte{}; byte < 8U; ++byte) value |= std::uint64_t{bytes_[offset_++]} << (8U * byte);
    return true;
  }
  [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - offset_; }
  template <std::size_t Index = 0U, typename T> bool variant(T &value, std::uint64_t index) {
    if constexpr (Index == std::variant_size_v<T>) return false;
    else {
      if (index == Index) return one(value.template emplace<Index>());
      return variant<Index + 1U>(value, index);
    }
  }
  template <typename T> bool one(T &value) {
    if constexpr (std::is_same_v<T, bool>) {
      if (!remaining() || bytes_[offset_] > 1U) return false;
      value = bytes_[offset_++] != 0U;
      return true;
    } else if constexpr (std::is_integral_v<T>) {
      std::uint64_t raw{};
      if (!integer(raw)) return false;
      if constexpr (std::is_signed_v<T>) {
        const auto signed_value = std::bit_cast<std::int64_t>(raw);
        if (signed_value < std::numeric_limits<T>::min() || signed_value > std::numeric_limits<T>::max()) return false;
        value = static_cast<T>(signed_value);
      } else {
        if (raw > std::numeric_limits<T>::max()) return false;
        value = static_cast<T>(raw);
      }
      return true;
    } else if constexpr (std::is_enum_v<T>) {
      std::underlying_type_t<T> raw{};
      if (!one(raw)) return false;
      value = static_cast<T>(raw);
      return true;
    } else if constexpr (Duration<T>::value) {
      typename T::rep count{};
      if (!one(count)) return false;
      value = T{count};
      return true;
    } else if constexpr (Optional<T>::value) {
      bool present{};
      if (!one(present)) return false;
      if (!present) { value.reset(); return true; }
      return one(value.emplace());
    } else if constexpr (Variant<T>::value) {
      std::uint64_t index{};
      return integer(index) && variant(value, index);
    } else if constexpr (Vector<T>::value) {
      using Element = typename T::value_type;
      std::uint64_t count{};
      if (!integer(count) || count > remaining() || count > value.max_size() || count > budget_ / sizeof(Element)) return false;
      budget_ -= static_cast<std::size_t>(count) * sizeof(Element);
      if constexpr (std::is_same_v<Element, std::uint8_t>) {
        const auto data = bytes_.subspan(offset_, static_cast<std::size_t>(count));
        value.assign(data.begin(), data.end());
        offset_ += static_cast<std::size_t>(count);
      } else {
        value.clear();
        value.reserve(static_cast<std::size_t>(count));
        for (std::uint64_t index{}; index < count; ++index) if (!one(value.emplace_back())) return false;
      }
      return true;
    } else if constexpr (Array<T>::value) {
      if constexpr (std::is_same_v<typename T::value_type, std::uint8_t>) {
        if (value.size() > remaining()) return false;
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_), value.size(), value.begin());
        offset_ += value.size();
      } else for (auto &entry : value) if (!one(entry)) return false;
      return true;
    } else return object(*this, value);
  }
  std::span<const std::uint8_t> bytes_;
  std::size_t offset_{}, budget_{maximum - sizeof(IsisRuntimeCheckpoint)};
};
}
std::optional<std::vector<std::uint8_t>> encode(const IsisRuntimeCheckpoint &state,
    const vault::SecretVault &vault, std::span<const std::uint8_t> binding) noexcept {
  if (!valid_isis_runtime_links(state)) return std::nullopt;
  try {
    Writer writer;
    if (!writer(magic, state)) return std::nullopt;
    auto [status, sealed] = vault.seal_isis_checkpoint(writer.bytes(), binding);
    return status == vault::Result::applied ? std::optional{std::move(sealed)} : std::nullopt;
  } catch (...) { return std::nullopt; }
}
std::unique_ptr<IsisRuntimeCheckpoint> decode(std::span<const std::uint8_t> sealed,
    const vault::SecretVault &vault, std::span<const std::uint8_t> binding) noexcept {
  try {
    auto [status, opened] = vault.open_isis_checkpoint(sealed, binding);
    if (status != vault::Result::applied || !opened) return nullptr;
    Reader reader(opened->bytes());
    std::array<std::uint8_t, magic.size()> header{};
    auto result = std::make_unique<IsisRuntimeCheckpoint>();
    if (!reader(header, *result) || header != magic || !reader.finished() || !valid_isis_runtime_links(*result)) return nullptr;
    return result;
  } catch (...) { return nullptr; }
}
} // namespace router::lab::isis_checkpoint
