// Release-profile tests ensure every visible transform passes through the
// generated adapter and an undersized consumer learns the required capacity.

#include "router/ikev2_profile.hpp"

#include <array>
#include <stdexcept>

void ikev2_profile_tests() {
  using namespace router::ikev2;
  std::array<TransformDefinition, 16U> transforms{};
  const auto loaded = load_implemented_transform_profile(transforms);
  if (loaded.required == 0U || loaded.written != loaded.required)
    throw std::runtime_error("generated IKEv2 transform profile is empty");
  std::array<TransformDefinition, 1U> short_output{};
  const auto short_result = load_implemented_transform_profile(short_output);
  if (short_result.written != 1U || short_result.required != loaded.required)
    throw std::runtime_error("IKEv2 transform capacity reporting failed");
  bool found_aead{};
  bool found_prf{};
  bool found_dh{};
  for (const auto &entry : std::span{transforms}.first(loaded.written)) {
    found_aead = found_aead ||
                 (entry.type == TransformType::encryption &&
                  entry.authenticated_encryption);
    found_prf = found_prf || entry.type == TransformType::prf;
    found_dh = found_dh || entry.type == TransformType::diffie_hellman;
  }
  if (!found_aead || !found_prf || !found_dh)
    throw std::runtime_error("generated IKEv2 profile lacks a usable IKE suite");
}
