// OSPF view of the SR OS system keychain. The configuration owner stores only
// encrypted-vault handles. This module selects send and receive entries from
// absolute UTC validity windows and never opens, copies or displays a secret.

#pragma once

#include "router/secret_vault.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace router::ospf {

enum class KeychainAlgorithm : std::uint8_t {
  password,
  message_digest,
  hmac_sha1,
  hmac_sha256
};

struct KeychainEntry {
  vault::SecretHandle secret{};
  // Epoch seconds preserve configured wall-clock activation across a runtime
  // restart. Protocol deadlines still use steady_clock after selection.
  std::int64_t begin_utc_seconds{};
  std::optional<std::int64_t> end_utc_seconds{};
  std::uint32_t tolerance_seconds{};
  std::uint8_t id{};
  KeychainAlgorithm algorithm{KeychainAlgorithm::password};
  bool admin_enabled{true};
  // MD-CLI candidate edits may create the list entry before its mandatory
  // leaves. Presence is retained separately from effective enum and handle
  // values so commit validation can reject an incomplete candidate without
  // inventing defaults.
  bool algorithm_configured{};
  bool secret_configured{};
  bool operator==(const KeychainEntry &) const = default;
};

struct KeychainConfiguration {
  std::string name{};
  std::vector<KeychainEntry> bidirectional{};
  bool admin_enabled{true};
  bool operator==(const KeychainConfiguration &) const = default;
};

enum class KeychainStatus : std::uint8_t {
  valid,
  invalid_name,
  invalid_entry,
  duplicate_entry,
  invalid_window
};

[[nodiscard]] KeychainStatus
validate(const KeychainConfiguration &keychain,
         bool allow_incomplete = false) noexcept;

// SR OS uses the youngest valid send key. Receive selection is by the wire
// Key ID and permits the configured post-end tolerance used during rollover.
[[nodiscard]] const KeychainEntry *
select_send_key(const KeychainConfiguration &keychain,
                std::int64_t now_utc_seconds) noexcept;
[[nodiscard]] const KeychainEntry *
select_receive_key(const KeychainConfiguration &keychain, std::uint8_t key_id,
                   std::int64_t now_utc_seconds) noexcept;

} // namespace router::ospf
