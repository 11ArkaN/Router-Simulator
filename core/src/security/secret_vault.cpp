// AES-256-GCM implementation of the project secret owner. A 96-bit random
// nonce and 128-bit tag follow NIST SP 800-38D. Record identity, purpose,
// version and project context are authenticated as additional data.
// Source: nist.project_key_vault.aes_gcm

#include "router/secret_vault.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <ranges>
#include <utility>

namespace router::vault {
namespace {

constexpr std::array<std::uint8_t, 4U> magic{'R', 'S', 'V', '1'};
constexpr std::uint8_t format_version = 1U;
constexpr std::size_t nonce_octets = 12U;
constexpr std::size_t tag_octets = 16U;
constexpr std::size_t length_octets = 4U;
constexpr std::size_t header_octets =
    magic.size() + 1U + nonce_octets + length_octets;
constexpr std::size_t maximum_secret_octets = 64U * 1024U;
constexpr std::size_t maximum_context_octets = 512U;

struct CipherDeleter {
  void operator()(EVP_CIPHER_CTX *value) const noexcept {
    if (value)
      EVP_CIPHER_CTX_free(value);
  }
};
using CipherOwner = std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter>;

struct SensitiveBytes {
  std::vector<std::uint8_t> value;
  SensitiveBytes() = default;
  explicit SensitiveBytes(std::vector<std::uint8_t> bytes)
      : value(std::move(bytes)) {}
  SensitiveBytes(SensitiveBytes &&other) noexcept
      : value(std::move(other.value)) {
    other.value.clear();
  }
  SensitiveBytes &operator=(SensitiveBytes &&other) noexcept {
    if (this != &other) {
      if (!value.empty())
        OPENSSL_cleanse(value.data(), value.size());
      value = std::move(other.value);
      other.value.clear();
    }
    return *this;
  }
  SensitiveBytes(const SensitiveBytes &) = delete;
  SensitiveBytes &operator=(const SensitiveBytes &) = delete;
  ~SensitiveBytes() {
    if (!value.empty())
      OPENSSL_cleanse(value.data(), value.size());
  }
};

struct SensitiveKey {
  std::array<std::uint8_t, 32U> value{};

  SensitiveKey() = default;
  SensitiveKey(const SensitiveKey &) = delete;
  SensitiveKey &operator=(const SensitiveKey &) = delete;

  // Rewrapping has several authenticated failure exits. Keeping the candidate
  // key in an erasing owner prevents any one of those exits from leaving key
  // bytes in the worker stack until that stack storage is reused.
  ~SensitiveKey() { OPENSSL_cleanse(value.data(), value.size()); }
};

bool valid_key(std::span<const std::uint8_t> key) noexcept {
  // Rejecting the all-zero value catches uninitialized project material. Key
  // quality beyond that is supplied by the browser CSPRNG and cannot be
  // estimated from a single 256-bit sample without introducing false claims.
  return key.size() == 32U &&
         std::ranges::any_of(key, [](std::uint8_t byte) { return byte != 0U; });
}

bool valid_kind(SecretKind kind) noexcept {
  const auto value = static_cast<std::uint8_t>(kind);
  return value >= static_cast<std::uint8_t>(SecretKind::ipsec_ppk_ascii) &&
         value <= static_cast<std::uint8_t>(
                      SecretKind::ospf_authentication_key);
}

void write_u32(std::span<std::uint8_t> output, std::size_t offset,
               std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(input[offset]) << 24U) |
         (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
         static_cast<std::uint32_t>(input[offset + 3U]);
}

void append_u64(std::vector<std::uint8_t> &output,
                std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8)
    output.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::vector<std::uint8_t>
additional_data(std::span<const std::uint8_t> header,
                std::span<const std::uint8_t> context,
                SecretHandle handle, SecretKind kind) {
  // Length-prefixing the context makes the concatenation unambiguous if a
  // future format appends another variable field. Header bytes are included
  // verbatim, binding nonce and ciphertext length to the authentication tag.
  std::vector<std::uint8_t> aad;
  aad.reserve(header.size() + 4U + context.size() + 8U + 1U);
  aad.insert(aad.end(), header.begin(), header.end());
  const auto context_size = static_cast<std::uint32_t>(context.size());
  aad.push_back(static_cast<std::uint8_t>(context_size >> 24U));
  aad.push_back(static_cast<std::uint8_t>(context_size >> 16U));
  aad.push_back(static_cast<std::uint8_t>(context_size >> 8U));
  aad.push_back(static_cast<std::uint8_t>(context_size));
  aad.insert(aad.end(), context.begin(), context.end());
  append_u64(aad, handle);
  aad.push_back(static_cast<std::uint8_t>(kind));
  return aad;
}

bool cipher_aad(EVP_CIPHER_CTX *cipher, std::span<const std::uint8_t> aad,
                bool encrypt) noexcept {
  if (aad.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;
  int ignored{};
  return (encrypt ? EVP_EncryptUpdate(cipher, nullptr, &ignored, aad.data(),
                                      static_cast<int>(aad.size()))
                  : EVP_DecryptUpdate(cipher, nullptr, &ignored, aad.data(),
                                      static_cast<int>(aad.size()))) == 1;
}

bool seal_record(std::span<const std::uint8_t> key,
                 std::span<const std::uint8_t> context, SecretHandle handle,
                 SecretKind kind, std::span<const std::uint8_t> plaintext,
                 std::vector<std::uint8_t> &output) {
  if (!valid_key(key) || !handle || !valid_kind(kind) || plaintext.empty() ||
      plaintext.size() > maximum_secret_octets ||
      plaintext.size() >
          static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return false;

  std::array<std::uint8_t, nonce_octets> nonce{};
  // RAND_priv_bytes uses OpenSSL's private DRBG class. GCM requires nonce
  // uniqueness under one key, and a fresh 96-bit random value per write gives
  // the NIST-recommended construction for this bounded local store.
  if (RAND_priv_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1)
    return false;

  std::vector<std::uint8_t> staged(header_octets + plaintext.size() +
                                   tag_octets);
  std::copy(magic.begin(), magic.end(), staged.begin());
  staged[magic.size()] = format_version;
  std::copy(nonce.begin(), nonce.end(), staged.begin() + magic.size() + 1U);
  write_u32(staged, header_octets - length_octets,
            static_cast<std::uint32_t>(plaintext.size()));
  const auto aad = additional_data(
      std::span<const std::uint8_t>{staged}.first(header_octets), context,
      handle, kind);

  CipherOwner cipher{EVP_CIPHER_CTX_new()};
  if (!cipher ||
      EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_EncryptInit_ex(cipher.get(), nullptr, nullptr, key.data(),
                         nonce.data()) != 1 ||
      !cipher_aad(cipher.get(), aad, true))
    return false;

  auto *ciphertext = staged.data() + header_octets;
  int written{};
  int final_written{};
  if (EVP_EncryptUpdate(cipher.get(), ciphertext, &written, plaintext.data(),
                        static_cast<int>(plaintext.size())) != 1 ||
      EVP_EncryptFinal_ex(cipher.get(), ciphertext + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) != plaintext.size() ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG,
                          static_cast<int>(tag_octets),
                          staged.data() + header_octets + plaintext.size()) !=
          1)
    return false;
  output = std::move(staged);
  return true;
}

std::pair<Result, std::optional<SensitiveBytes>>
open_record(std::span<const std::uint8_t> key,
            std::span<const std::uint8_t> context, const SealedRecord &record) {
  const auto sealed = std::span<const std::uint8_t>{record.sealed};
  if (!valid_key(key) || !record.handle || !valid_kind(record.kind) ||
      sealed.size() < header_octets + tag_octets ||
      !std::ranges::equal(sealed.first(magic.size()), magic) ||
      sealed[magic.size()] != format_version)
    return {Result::authentication_failed, std::nullopt};
  const auto size = read_u32(sealed, header_octets - length_octets);
  if (!size || size > maximum_secret_octets ||
      size > static_cast<std::uint32_t>(std::numeric_limits<int>::max()) ||
      sealed.size() != header_octets + size + tag_octets)
    return {Result::authentication_failed, std::nullopt};

  const auto nonce = sealed.subspan(magic.size() + 1U, nonce_octets);
  const auto ciphertext = sealed.subspan(header_octets, size);
  const auto tag = sealed.last(tag_octets);
  const auto aad = additional_data(sealed.first(header_octets), context,
                                   record.handle, record.kind);
  SensitiveBytes plaintext{std::vector<std::uint8_t>(size)};
  CipherOwner cipher{EVP_CIPHER_CTX_new()};
  if (!cipher ||
      EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_IVLEN,
                          static_cast<int>(nonce.size()), nullptr) != 1 ||
      EVP_DecryptInit_ex(cipher.get(), nullptr, nullptr, key.data(),
                         nonce.data()) != 1 ||
      !cipher_aad(cipher.get(), aad, false))
    return {Result::cryptographic_failure, std::nullopt};

  int written{};
  int final_written{};
  if (EVP_DecryptUpdate(cipher.get(), plaintext.value.data(), &written,
                        ciphertext.data(), static_cast<int>(size)) != 1 ||
      EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG,
                          static_cast<int>(tag.size()),
                          const_cast<std::uint8_t *>(tag.data())) != 1 ||
      EVP_DecryptFinal_ex(cipher.get(), plaintext.value.data() + written,
                          &final_written) != 1 ||
      static_cast<std::size_t>(written + final_written) != size)
    return {Result::authentication_failed, std::nullopt};

  // Transfer only after tag verification. SensitiveBytes becomes empty, so
  // exactly one RAII owner remains responsible for cleansing the plaintext.
  return {Result::applied, std::move(plaintext)};
}

} // namespace

OpenedSecret::OpenedSecret(std::vector<std::uint8_t> plaintext) noexcept
    : plaintext_(std::move(plaintext)) {}

OpenedSecret::OpenedSecret(OpenedSecret &&other) noexcept
    : plaintext_(std::move(other.plaintext_)) {
  other.plaintext_.clear();
}

OpenedSecret &OpenedSecret::operator=(OpenedSecret &&other) noexcept {
  if (this != &other) {
    cleanse();
    plaintext_ = std::move(other.plaintext_);
    other.plaintext_.clear();
  }
  return *this;
}

OpenedSecret::~OpenedSecret() { cleanse(); }

void OpenedSecret::cleanse() noexcept {
  if (!plaintext_.empty())
    OPENSSL_cleanse(plaintext_.data(), plaintext_.size());
  plaintext_.clear();
}

SecretVault::SecretVault(std::array<std::uint8_t, 32U> wrapping_key,
                         std::vector<std::uint8_t> context,
                         std::size_t capacity, Checkpoint state) noexcept
    : wrapping_key_(wrapping_key), context_(std::move(context)),
      capacity_(capacity), state_(std::move(state)) {}

std::optional<SecretVault>
SecretVault::create(std::span<const std::uint8_t> wrapping_key,
                    std::span<const std::uint8_t> context,
                    std::size_t capacity) noexcept {
  if (!valid_key(wrapping_key) || context.empty() ||
      context.size() > maximum_context_octets || !capacity)
    return std::nullopt;
  try {
    std::array<std::uint8_t, 32U> key{};
    std::copy(wrapping_key.begin(), wrapping_key.end(), key.begin());
    Checkpoint state;
    state.records.reserve(capacity);
    return SecretVault{key, {context.begin(), context.end()}, capacity,
                       std::move(state)};
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<SecretVault>
SecretVault::restore(const Checkpoint &checkpoint,
                     std::span<const std::uint8_t> wrapping_key,
                     std::span<const std::uint8_t> context,
                     std::size_t capacity) noexcept {
  auto candidate = create(wrapping_key, context, capacity);
  if (!candidate || checkpoint.records.size() > capacity ||
      checkpoint.next_handle == 0U)
    return std::nullopt;
  try {
    SecretHandle previous{};
    candidate->state_.records.reserve(capacity);
    for (const auto &record : checkpoint.records) {
      // Strict ordering makes duplicate handles impossible and gives lookup a
      // deterministic binary-search contract after untrusted checkpoint input.
      if (!record.handle || record.handle <= previous ||
          record.handle >= checkpoint.next_handle || !valid_kind(record.kind))
        return std::nullopt;
      const auto [result, plaintext] = open_record(
          candidate->wrapping_key_, candidate->context_, record);
      if (result != Result::applied || !plaintext)
        return std::nullopt;
      previous = record.handle;
      candidate->state_.records.push_back(record);
    }
    candidate->state_.next_handle = checkpoint.next_handle;
    return candidate;
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<SecretVault>
SecretVault::stage_restore(const Checkpoint &checkpoint) const noexcept {
  return restore(checkpoint, wrapping_key_, context_, capacity_);
}

SecretVault::SecretVault(SecretVault &&other) noexcept
    : wrapping_key_(other.wrapping_key_), context_(std::move(other.context_)),
      capacity_(other.capacity_), state_(std::move(other.state_)) {
  other.cleanse_key();
  other.capacity_ = 0U;
}

SecretVault &SecretVault::operator=(SecretVault &&other) noexcept {
  if (this != &other) {
    cleanse_key();
    wrapping_key_ = other.wrapping_key_;
    context_ = std::move(other.context_);
    capacity_ = other.capacity_;
    state_ = std::move(other.state_);
    other.cleanse_key();
    other.capacity_ = 0U;
  }
  return *this;
}

SecretVault::~SecretVault() { cleanse_key(); }

void SecretVault::cleanse_key() noexcept {
  OPENSSL_cleanse(wrapping_key_.data(), wrapping_key_.size());
  if (!context_.empty())
    OPENSSL_cleanse(context_.data(), context_.size());
  context_.clear();
}

std::pair<Result, SecretHandle>
SecretVault::seal(SecretKind kind,
                  std::span<const std::uint8_t> plaintext) noexcept {
  if (!valid_kind(kind) || plaintext.empty() ||
      plaintext.size() > maximum_secret_octets)
    return {Result::invalid_argument, 0U};
  try {
    // Configuration commands frequently repeat the current value. Opening
    // same-kind records avoids allocating a new stable identity for that
    // semantic no-op. Constant-time equality prevents a timing shortcut from
    // revealing the first differing secret byte inside this owner.
    for (const auto &record : state_.records) {
      if (record.kind != kind)
        continue;
      auto [result, opened] = open_record(wrapping_key_, context_, record);
      if (result != Result::applied || !opened)
        return {result, 0U};
      if (opened->value.size() == plaintext.size() &&
          CRYPTO_memcmp(opened->value.data(), plaintext.data(),
                        plaintext.size()) == 0)
        return {Result::applied, record.handle};
    }
    if (state_.records.size() >= capacity_ ||
        state_.next_handle == std::numeric_limits<SecretHandle>::max())
      return {Result::resource_exhausted, 0U};
    SealedRecord staged{.handle = state_.next_handle,
                        .kind = kind,
                        .sealed = {}};
    if (!seal_record(wrapping_key_, context_, staged.handle, staged.kind,
                     plaintext, staged.sealed))
      return {Result::cryptographic_failure, 0U};
    state_.records.push_back(std::move(staged));
    return {Result::applied, state_.next_handle++};
  } catch (...) {
    return {Result::resource_exhausted, 0U};
  }
}

std::pair<Result, std::optional<OpenedSecret>>
SecretVault::open(SecretHandle handle,
                  SecretKind expected_kind) const noexcept {
  const auto found = std::lower_bound(
      state_.records.begin(), state_.records.end(), handle,
      [](const SealedRecord &record, SecretHandle wanted) {
        return record.handle < wanted;
      });
  if (found == state_.records.end() || found->handle != handle)
    return {Result::not_found, std::nullopt};
  if (found->kind != expected_kind)
    return {Result::wrong_kind, std::nullopt};
  try {
    auto [result, plaintext] = open_record(wrapping_key_, context_, *found);
    if (result != Result::applied || !plaintext)
      return {result, std::nullopt};
    return {Result::applied,
            OpenedSecret{std::exchange(plaintext->value, {})}};
  } catch (...) {
    return {Result::resource_exhausted, std::nullopt};
  }
}

Result SecretVault::erase(SecretHandle handle) noexcept {
  const auto found = std::lower_bound(
      state_.records.begin(), state_.records.end(), handle,
      [](const SealedRecord &record, SecretHandle wanted) {
        return record.handle < wanted;
      });
  if (found == state_.records.end() || found->handle != handle)
    return Result::not_found;
  if (!found->sealed.empty())
    OPENSSL_cleanse(found->sealed.data(), found->sealed.size());
  state_.records.erase(found);
  return Result::applied;
}

void SecretVault::prune(std::span<const SecretHandle> live_handles) noexcept {
  // Capacity is bounded, so a linear live-set lookup keeps this path compact.
  // Pruning is a control operation, never a packet-path lookup.
  for (auto iterator = state_.records.begin();
       iterator != state_.records.end();) {
    if (std::ranges::find(live_handles, iterator->handle) !=
        live_handles.end()) {
      ++iterator;
      continue;
    }
    if (!iterator->sealed.empty())
      OPENSSL_cleanse(iterator->sealed.data(), iterator->sealed.size());
    iterator = state_.records.erase(iterator);
  }
}

Result SecretVault::rewrap(std::span<const std::uint8_t> wrapping_key,
                           std::span<const std::uint8_t> context) noexcept {
  if (!valid_key(wrapping_key) || context.empty() ||
      context.size() > maximum_context_octets)
    return Result::invalid_argument;
  try {
    SensitiveKey next_key;
    std::copy(wrapping_key.begin(), wrapping_key.end(), next_key.value.begin());
    std::vector<std::uint8_t> next_context{context.begin(), context.end()};
    Checkpoint staged{.next_handle = state_.next_handle, .records = {}};
    staged.records.reserve(capacity_);
    for (const auto &record : state_.records) {
      auto [result, opened] = open_record(wrapping_key_, context_, record);
      if (result != Result::applied || !opened)
        return result;
      SealedRecord replacement{.handle = record.handle,
                               .kind = record.kind,
                               .sealed = {}};
      if (!seal_record(next_key.value, next_context, replacement.handle,
                       replacement.kind, opened->value,
                       replacement.sealed))
        return Result::cryptographic_failure;
      staged.records.push_back(std::move(replacement));
    }
    cleanse_key();
    wrapping_key_ = next_key.value;
    context_ = std::move(next_context);
    state_ = std::move(staged);
    return Result::applied;
  } catch (...) {
    return Result::resource_exhausted;
  }
}

bool SecretVault::contains(SecretHandle handle, SecretKind kind) const noexcept {
  const auto found = std::lower_bound(
      state_.records.begin(), state_.records.end(), handle,
      [](const SealedRecord &record, SecretHandle wanted) {
        return record.handle < wanted;
      });
  return found != state_.records.end() && found->handle == handle &&
         found->kind == kind;
}

} // namespace router::vault
