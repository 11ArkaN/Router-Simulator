// PKI CLI candidate editor. It translates generated SR OS command IDs into
// atomic edits of the control-owned PKI configuration value: CA profiles
// (with OCSP, CMPv2 and automatic CRL update subtrees), common-name lists,
// EST profiles, certificate update profiles, certificate auto-update entries
// and top-level display, import, chain-depth and expiration-warning leaves.
// It never owns live enrollment state, private keys or packet-processing
// state and cannot call forwarding. EST and CMP enrollment operations have no
// grammar rows and stay explicit errors.

#pragma once

#include "cli_parser.hpp"
#include "router/pki_configuration.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace router::lab::pki_cli {

struct EditResult {
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance;
};

enum class SecretKind : std::uint8_t { est_http_password, cmp_key_password };

class SecretSink {
public:
  virtual ~SecretSink() = default;

  // The caller owns `plaintext` and may cleanse it immediately after return.
  // A successful result names authenticated encrypted storage owned outside
  // candidate configuration. Zero is never a valid handle.
  [[nodiscard]] virtual std::optional<std::uint64_t>
  seal(SecretKind kind, std::span<const std::uint8_t> plaintext) noexcept = 0;
};

// Preconditions: command was accepted by the generated release grammar and the
// caller exclusively owns configuration for this control turn. On failure the
// supplied configuration is restored to its exact prior value.
[[nodiscard]] EditResult
edit(pki::Configuration &configuration,
     const cli_detail::ParsedCommand &command, CliEngine engine,
     SecretSink *secrets = nullptr);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;
[[nodiscard]] bool is_classic_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::pki_cli
