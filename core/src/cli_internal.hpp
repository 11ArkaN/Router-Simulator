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

[[nodiscard]] std::string trim(std::string_view value);
[[nodiscard]] std::optional<std::size_t> port_index(std::string_view text);
[[nodiscard]] std::optional<ParsedStaticRoute>
parse_static_route(std::string_view prefix, std::string_view next_hop);
[[nodiscard]] bool install_static(DeviceConfiguration &configuration,
                                  ParsedStaticRoute route);
[[nodiscard]] std::string_view unquote(std::string_view value) noexcept;

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
[[nodiscard]] std::string prompt(const CliSession &session);

} // namespace router::cli_detail
