// RFC 7583 DNSSEC key lifecycle. ManagedKey owns one provider private key and
// an explicit operator schedule. Callers supply wall-clock seconds and own the
// zone refresh loop. No global scheduler, background thread or inferred timing
// exists in this module.

#pragma once

#include "router/dnssec_signer.hpp"
#include "router/dnssec_zone_signer.hpp"

#include <cstdint>
#include <memory>
#include <optional>

namespace router::dnssec {

enum class KeyLifecycleState : std::uint8_t {
  generated,
  published,
  ready,
  active,
  retired,
  dead,
  removed
};

struct KeySchedule {
  std::uint64_t publish_at{};
  std::uint64_t ready_at{};
  std::uint64_t activate_at{};
  std::uint64_t retire_at{};
  std::uint64_t dead_at{};
  std::uint64_t remove_at{};
};

[[nodiscard]] bool valid_schedule(const KeySchedule &schedule) noexcept;

class ManagedKey final {
public:
  // create takes ownership only when the complete schedule is monotonic.
  // Equality between adjacent events is legal for initial publication or an
  // operator-directed emergency transition.
  [[nodiscard]] static std::optional<ManagedKey>
  create(KeyRole role, KeySchedule schedule,
         std::unique_ptr<SigningKey> key) noexcept;

  ManagedKey(ManagedKey &&) noexcept = default;
  ManagedKey &operator=(ManagedKey &&) noexcept = default;
  ManagedKey(const ManagedKey &) = delete;
  ManagedKey &operator=(const ManagedKey &) = delete;

  [[nodiscard]] KeyLifecycleState state(std::uint64_t now) const noexcept;
  [[nodiscard]] bool published(std::uint64_t now) const noexcept;
  [[nodiscard]] bool signs(std::uint64_t now) const noexcept;
  [[nodiscard]] KeyRole role() const noexcept { return role_; }
  [[nodiscard]] const KeySchedule &schedule() const noexcept {
    return schedule_;
  }
  [[nodiscard]] const SigningKey &key() const noexcept { return *key_; }

private:
  ManagedKey(KeyRole role, KeySchedule schedule,
             std::unique_ptr<SigningKey> key) noexcept
      : role_(role), schedule_(schedule), key_(std::move(key)) {}

  KeyRole role_{KeyRole::zone_signing};
  KeySchedule schedule_{};
  std::unique_ptr<SigningKey> key_;
};

} // namespace router::dnssec
