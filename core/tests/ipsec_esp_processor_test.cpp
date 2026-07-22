// ESP processor tests compose real SAD entries, sequence allocation, AES-GCM,
// replay commit, selector validation and lifetime accounting in packet order.

#include "router/ipsec_esp_processor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>

namespace {

router::ipsec::esp_gcm::Engine *lookup_engine(void *context,
                                              std::uint64_t handle) noexcept {
  return handle == 1U
             ? static_cast<router::ipsec::esp_gcm::Engine *>(context)
             : nullptr;
}

bool accept_selector(void *, std::uint32_t policy_id, std::uint8_t next_header,
                     std::span<const std::uint8_t> plaintext) noexcept {
  return policy_id == 7U && next_header == 17U && !plaintext.empty();
}

} // namespace

void ipsec_esp_processor_tests() {
  using namespace router::ipsec;
  esp_gcm::KeyMaterial material{};
  material.key_octets = 16U;
  material.key[0U] = 1U;
  material.salt = {2U, 3U, 4U, 5U};
  auto engine = esp_gcm::Engine::create(material);
  if (!engine)
    throw std::runtime_error("ESP processor provider setup failed");

  Sad sad{4U};
  SecurityAssociation outbound{};
  outbound.id = 1U;
  outbound.inbound_identifier.spi = 0x10203040U;
  outbound.inbound_identifier.protocol = SecurityProtocol::esp;
  outbound.encryption = EncryptionAlgorithm::aes_gcm_16_128;
  outbound.crypto_material_handle = 1U;
  outbound.policy_id = 7U;
  outbound.created_at = std::chrono::steady_clock::time_point{};
  outbound.outbound = true;
  auto inbound = outbound;
  inbound.id = 2U;
  inbound.outbound = false;
  if (sad.install(outbound) != SaInstallResult::installed ||
      sad.install(inbound) != SaInstallResult::installed)
    throw std::runtime_error("ESP processor SAD setup failed");

  const EspProcessorDependencies dependencies{
      .engine_context = engine.get(),
      .find_engine = lookup_engine,
      .selector_context = nullptr,
      .validate_inbound_selector = accept_selector};
  const std::array<std::uint8_t, 5U> plaintext{1U, 2U, 3U, 4U, 5U};
  std::array<std::uint8_t, 64U> packet{};
  const auto now = std::chrono::steady_clock::time_point{};
  const auto protected_result =
      protect_esp(sad, 1U, dependencies, 17U, plaintext, now, packet);
  if (protected_result.status != EspProcessStatus::ok)
    throw std::runtime_error("ESP processor outbound protection failed");

  Address destination{};
  Address source{};
  destination.bytes[0U] = 10U;
  source.bytes[0U] = 10U;
  std::array<std::uint8_t, 32U> recovered{};
  const auto packet_view =
      std::span{packet}.first(protected_result.packet_octets);
  const auto unprotected = unprotect_esp(sad, destination, source, dependencies,
                                        packet_view, now, recovered);
  if (unprotected.status != EspProcessStatus::ok ||
      unprotected.plaintext_octets != plaintext.size() ||
      unprotected.next_header != 17U ||
      !std::equal(plaintext.begin(), plaintext.end(), recovered.begin()))
    throw std::runtime_error("ESP processor inbound protection failed");
  if (unprotect_esp(sad, destination, source, dependencies, packet_view, now,
                    recovered)
          .status != EspProcessStatus::replay_rejected)
    throw std::runtime_error("ESP processor accepted a replay");

  const auto second =
      protect_esp(sad, 1U, dependencies, 17U, plaintext, now, packet);
  if (second.status != EspProcessStatus::ok)
    throw std::runtime_error("ESP processor second protection failed");
  packet[second.packet_octets - 1U] ^= 1U;
  if (unprotect_esp(sad, destination, source, dependencies,
                    std::span{packet}.first(second.packet_octets), now,
                    recovered)
          .status != EspProcessStatus::authentication_failed)
    throw std::runtime_error("ESP processor accepted a modified tag");
  packet[second.packet_octets - 1U] ^= 1U;
  if (unprotect_esp(sad, destination, source, dependencies,
                    std::span{packet}.first(second.packet_octets), now,
                    recovered)
          .status != EspProcessStatus::ok)
    throw std::runtime_error("ESP replay state advanced before authentication");
}
