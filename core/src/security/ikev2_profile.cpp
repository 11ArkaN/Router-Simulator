// Generated profile projection for IKEv2. Keeping conversion in one cold-path
// module prevents packet and state-machine code from knowing generator layouts.

#include "router/ikev2_profile.hpp"

#include "router/generated_profile.hpp"

namespace router::ikev2 {

TransformProfileResult load_implemented_transform_profile(
    std::span<TransformDefinition> output) noexcept {
  std::size_t required{};
  std::size_t written{};
  for (const auto &entry : profile::ipsec_transforms) {
    if (!entry.implemented)
      continue;
    if (written < output.size()) {
      output[written] = {
          .type = static_cast<TransformType>(
              static_cast<std::uint8_t>(entry.type)),
          .id = entry.id,
          .key_bits = entry.key_bits,
          .key_length_attribute_required =
              entry.key_length_attribute_required,
          .authenticated_encryption = entry.authenticated_encryption};
      ++written;
    }
    ++required;
  }
  return {.written = written, .required = required};
}

} // namespace router::ikev2
