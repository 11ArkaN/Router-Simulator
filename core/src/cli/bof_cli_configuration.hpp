// Atomic BOF autoconfiguration editor for the model-driven CLI. LabRuntime
// owns the candidate object. This module owns no mutable state and depends
// only on the generated command schema, BOF intent and injected entropy.

#pragma once

#include "cli_parser.hpp"
#include "router/bof_autoconfigure.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace router::lab::bof_cli {

class EntropySource {
public:
  virtual ~EntropySource() = default;

  // Preconditions: output names writable memory for its entire extent.
  // Postcondition: success means every byte was supplied by the platform
  // CSPRNG. Failure requires the caller to discard its staged edit.
  [[nodiscard]] virtual bool
  fill(std::span<std::uint8_t> output) noexcept = 0;
};

struct EditResult {
  bool recognized{};
  bool valid{};
  bool changed{};
  std::string instance{};
};

// Applies one generated BOF command to a staged copy, validates the complete
// intent, then atomically replaces configuration. Protocol identity secrets
// are generated on first enable and are never derived from CLI text.
[[nodiscard]] EditResult
edit(bof::AutoconfigureIntent &configuration,
     const cli_detail::ParsedCommand &command, EntropySource *entropy);

[[nodiscard]] bool is_md_command(cli_schema::CommandId id) noexcept;

} // namespace router::lab::bof_cli
