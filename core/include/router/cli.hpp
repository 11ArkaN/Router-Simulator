// CLI execution boundary for two engines in one router-owned terminal session.
// Handlers mutate only control-owned candidate or running configuration.

#pragma once

#include "router/device.hpp"

#include <functional>
#include <string>

namespace router {

// Operational commands share device state, while engine-specific configuration
// semantics remain inside separate MD and classic dispatchers. ping is injected
// so the CLI cannot bypass the forwarding shard with a direct device call.
std::string execute_cli(DeviceState& state, CliSession& session, const std::string& input,
                        const std::function<std::string(std::uint32_t)>& ping);
std::string complete_cli(const DeviceState& state, const CliSession& session,
                         const std::string& input);

}  // namespace router
