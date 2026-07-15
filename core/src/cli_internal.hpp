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
