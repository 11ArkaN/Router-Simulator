// IPsec CLI candidate editor. It translates generated SR OS command IDs into
// atomic edits of the control-owned IPsec configuration value. It never owns
// live SAs, key bytes or packet-processing state and cannot call forwarding.

#pragma once

#include "cli_parser.hpp"
#include "router/ipsec_configuration.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace router::lab::ipsec_cli {

struct EditResult {
  bool recognized{};
  bool changed{};
  std::string instance;
};

enum class SecretKind : std::uint8_t {
  ppk_ascii,
  ppk_hexadecimal,
  ike_pre_shared_key,
  static_authentication_key
};

class SecretSink {
public:
  virtual ~SecretSink() = default;

  // The caller owns `plaintext` and may cleanse it immediately after return.
  // A successful result names authenticated encrypted storage owned outside
  // candidate configuration. Zero is never a valid handle. Implementations
  // must fail without changing existing records when capacity or entropy is
  // unavailable.
  [[nodiscard]] virtual std::optional<std::uint64_t>
  seal(SecretKind kind, std::span<const std::uint8_t> plaintext) noexcept = 0;
};

// Preconditions: command was accepted by the generated release grammar and
// state belongs to the calling control shard. A failed edit restores the exact
// input value. Successful results always change intent and contain a stable
// schema instance path for candidate conflict tracking.
[[nodiscard]] EditResult
edit(ipsec::configuration::Configuration &state,
     const cli_detail::ParsedCommand &command, CliEngine engine,
     SecretSink *secrets = nullptr);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_show_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::ipsec_cli
