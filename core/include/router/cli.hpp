// CLI execution boundary for two engines in one router-owned terminal session.
// Handlers mutate only control-owned candidate or running configuration.

#pragma once

#include "router/device.hpp"

#include <functional>
#include <string>

namespace router {

using CliPing = std::function<std::string(packet::Ipv4, std::uint32_t)>;

// Operational commands share device state, while engine-specific configuration
// semantics remain inside separate MD and classic dispatchers. ping is injected
// so the CLI cannot bypass the forwarding shard with a direct device call.
// Preconditions: control-shard affinity and a router-owned session. Successful
// configuration commands update only the datastore selected by that engine.
// Parser and capability errors are returned as terminal text, not exceptions.
std::string execute_cli(DeviceState &state, CliSession &session,
                        const std::string &input, const CliPing &ping);
// Completion is read-only. It consults the same generated grammar as execution
// and never exposes schema-only or unsupported command transcripts.
std::string complete_cli(const DeviceState &state, const CliSession &session,
                         const std::string &input);
// Returns the router-owned prompt for terminal redraws. The frontend must not
// reconstruct engine markers or the configured system name.
std::string cli_prompt(const DeviceState &state, const CliSession &session);

} // namespace router
