// Internal CLI parsing primitives shared by two terminal engines. This header
// exposes no public router API and cannot access hardware or operational state.

#pragma once

#include "cli_parser.hpp"
#include "router/device.hpp"

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace router::cli_detail {

struct ParsedStaticRoute {
  std::uint32_t network{};
  std::uint8_t prefix{};
  std::uint32_t next_hop{};
};

struct ParsedInterfaceAddress {
  // Network-order numeric storage matches RIB keys and removes text lifetime
  // from candidate copies. The packet form is retained for wire encoders.
  packet::Ipv4 address{};
  std::uint32_t network{};
  std::uint8_t prefix{};
};

[[nodiscard]] std::string trim(std::string_view value);
[[nodiscard]] std::optional<std::size_t> port_index(std::string_view text);
[[nodiscard]] std::optional<ParsedStaticRoute>
parse_static_route(std::string_view prefix, std::string_view next_hop);
[[nodiscard]] bool install_static(DeviceConfiguration &configuration,
                                  ParsedStaticRoute route);
[[nodiscard]] bool remove_static(DeviceConfiguration &configuration,
                                 std::string_view prefix);
[[nodiscard]] std::optional<ParsedInterfaceAddress>
parse_interface_address(std::string_view address,
                        std::string_view prefix_length = {});
[[nodiscard]] bool set_interface_address(DeviceConfiguration &configuration,
                                         std::size_t interface_index,
                                         ParsedInterfaceAddress address);
[[nodiscard]] bool set_interface_port(DeviceConfiguration &configuration,
                                      std::size_t interface_index,
                                      std::size_t port_index);
[[nodiscard]] std::string_view unquote(std::string_view value) noexcept;
[[nodiscard]] bool valid_cli_string(std::string_view value) noexcept;

// Resolves a line against the active engine's working context without parsing
// or mutating router configuration. The multi-router facade uses this narrow
// helper so relative commands retain the exact same MD-CLI and classic CLI
// path semantics as the fully tested terminal engine.
[[nodiscard]] std::string resolve_session_input(const CliSession &session,
                                                std::string_view input);

// Applies MD-CLI default list keys to an already absolute command line without
// resolving it against the session's present working context. The helper is
// read-only and is used by schema-driven completion before token matching.
[[nodiscard]] std::string
apply_md_command_defaults(const CliSession &session, std::string_view input);

// Removes only the internally supplied Base key from a completed absolute
// command before the text is returned to the operator's editable line.
[[nodiscard]] std::string
hide_md_default_router_key(std::string_view input);
// Stores a validated classic present-working-context after the runtime facade
// has successfully applied a command that both creates and enters a list
// instance. This narrow session-only operation cannot mutate configuration.
// Preconditions: control-shard affinity and a canonical resolved command path.
// Postcondition: the classic path and reversible previous path are updated
// together, or neither changes when the bounded session storage is exceeded.
[[nodiscard]] bool enter_classic_context(CliSession &session,
                                         std::string_view path) noexcept;
// Stores a validated MD-CLI present-working-context after the runtime facade
// has successfully applied a command that is both a presence-container edit
// and the parent of additional leaves. The generated grammar decides whether
// a command has that dual role; this helper only owns the session transition.
// Preconditions: control-shard affinity, MD-CLI engine, canonical command path.
// Postcondition: current and reversible previous paths change atomically, or
// neither changes when the bounded session path cannot contain the new value.
[[nodiscard]] bool enter_md_context(CliSession &session,
                                    std::string_view path) noexcept;

template <std::size_t N>
bool copy_config_text(std::array<char, N> &destination,
                      std::string_view value) {
  // Fixed storage keeps datastore copies bounded and prevents allocator
  // ownership from leaking into checkpoints or cross-shard projections.
  if (value.size() >= N)
    return false;
  std::memcpy(destination.data(), value.data(), value.size());
  destination[value.size()] = '\0';
  return true;
}

void synchronize_candidate(ConfigurationState &configuration,
                           CliSession &session, bool running_changed) noexcept;
[[nodiscard]] std::string execute_md(ConfigurationState &configuration,
                                     CliSession &session,
                                     const ParsedCommand &command);
[[nodiscard]] std::string execute_classic(ConfigurationState &configuration,
                                          CliSession &session,
                                          const ParsedCommand &command);
// The prompt is rendered from the running system name on every response. The
// terminal therefore cannot retain a stale frontend copy after configuration
// changes or checkpoint restore.
[[nodiscard]] std::string prompt(const DeviceConfiguration &configuration,
                                 const CliSession &session);

} // namespace router::cli_detail
