// RFC 4301 and RFC 4303 ESP processing order. Replay admission is checked
// before cryptography but committed only after authentication. Authenticated
// plaintext is cleansed if its inner selectors do not match the protecting SA.

#include "router/ipsec_esp_processor.hpp"

#include "router/ipsec_lifetime.hpp"
#include "router/ipsec_packet.hpp"

#include <openssl/crypto.h>

#include <limits>

namespace router::ipsec {
namespace {

std::size_t protected_octets(std::size_t plaintext_octets) noexcept {
  // AES-GCM ESP aligns Pad Length and Next Header to four octets. Expansion is
  // SPI+Seq(8), IV(8), trailer(2+0..3) and ICV(16).
  const auto padding = (4U - ((plaintext_octets + 2U) % 4U)) % 4U;
  return plaintext_octets + padding + 34U;
}

EspProcessStatus map_crypto(esp_gcm::Status status) noexcept {
  switch (status) {
  case esp_gcm::Status::output_too_small:
    return EspProcessStatus::output_too_small;
  case esp_gcm::Status::authentication_failed:
  case esp_gcm::Status::invalid_padding:
    return EspProcessStatus::authentication_failed;
  default:
    return EspProcessStatus::crypto_failure;
  }
}

bool accepted(LifetimeUseStatus status) noexcept {
  return status == LifetimeUseStatus::accepted ||
         status == LifetimeUseStatus::accepted_soft_limit ||
         status == LifetimeUseStatus::accepted_hard_limit;
}

void increment_drop(std::uint64_t &counter) noexcept {
  if (counter != std::numeric_limits<std::uint64_t>::max())
    ++counter;
}

} // namespace

EspProtectResult protect_esp(
    Sad &sad, std::uint64_t outbound_sa_id,
    const EspProcessorDependencies &dependencies, std::uint8_t next_header,
    std::span<const std::uint8_t> plaintext,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> output) noexcept {
  if (!dependencies.find_engine)
    return {.status = EspProcessStatus::invalid_argument};
  auto *association = sad.find_outbound(outbound_sa_id);
  if (!association)
    return {.status = EspProcessStatus::unknown_sa};
  if (!association->outbound || association->inbound_identifier.protocol !=
                                    SecurityProtocol::esp)
    return {.status = EspProcessStatus::wrong_sa_direction};
  if (plaintext.size() > std::numeric_limits<std::size_t>::max() - 37U ||
      output.size() < protected_octets(plaintext.size()))
    return {.status = EspProcessStatus::output_too_small};
  auto *engine = dependencies.find_engine(
      dependencies.engine_context, association->crypto_material_handle);
  if (!engine)
    return {.status = EspProcessStatus::crypto_failure};
  const auto lifetime = assess_sa_use(*association, plaintext.size(), now);
  if (!accepted(lifetime.status))
    return {.status = EspProcessStatus::lifetime_expired};
  const auto sequence = association->outbound_sequence.next();
  if (!sequence.has_value())
    return {.status = EspProcessStatus::sequence_exhausted};
  const auto protected_result = engine->protect(
      association->inbound_identifier.spi, *sequence,
      association->outbound_sequence.extended(),
      next_header, plaintext, output);
  if (protected_result.status != esp_gcm::Status::ok)
    return {.status = map_crypto(protected_result.status)};
  commit_sa_use(*association, lifetime);
  return {.status = EspProcessStatus::ok,
          .packet_octets = protected_result.packet_octets,
          .soft_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_soft_limit,
          .hard_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_hard_limit};
}

EspUnprotectResult unprotect_esp(
    Sad &sad, const Address &outer_destination, const Address &outer_source,
    const EspProcessorDependencies &dependencies,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> plaintext_output) noexcept {
  if (!dependencies.find_engine || !dependencies.validate_inbound_selector)
    return {.status = EspProcessStatus::invalid_argument};
  const auto parsed = parse_esp(packet);
  if (!parsed.has_value())
    return {.status = EspProcessStatus::invalid_argument};
  const auto &view = *parsed;
  auto *association = sad.find_inbound(SecurityProtocol::esp, view.spi,
                                       outer_destination, outer_source);
  if (!association)
    return {.status = EspProcessStatus::unknown_sa};
  const auto replay = association->replay.check(view.sequence_low);
  if (replay.status != ReplayStatus::admissible) {
    increment_drop(association->counters.replay_drops);
    return {.status = EspProcessStatus::replay_rejected};
  }
  auto *engine = dependencies.find_engine(
      dependencies.engine_context, association->crypto_material_handle);
  if (!engine)
    return {.status = EspProcessStatus::crypto_failure};
  const auto unprotected = engine->unprotect(
      replay.sequence, association->replay.extended(), packet,
      plaintext_output);
  if (unprotected.status != esp_gcm::Status::ok) {
    if (unprotected.status == esp_gcm::Status::authentication_failed ||
        unprotected.status == esp_gcm::Status::invalid_padding)
      increment_drop(association->counters.integrity_drops);
    return {.status = map_crypto(unprotected.status)};
  }
  if (!association->replay.commit(replay.sequence)) {
    OPENSSL_cleanse(plaintext_output.data(), unprotected.plaintext_octets);
    return {.status = EspProcessStatus::replay_rejected};
  }
  const auto authenticated_plaintext =
      plaintext_output.first(unprotected.plaintext_octets);
  if (!dependencies.validate_inbound_selector(
          dependencies.selector_context, association->policy_id,
          unprotected.next_header, authenticated_plaintext)) {
    increment_drop(association->counters.selector_drops);
    OPENSSL_cleanse(plaintext_output.data(), unprotected.plaintext_octets);
    return {.status = EspProcessStatus::selector_mismatch};
  }
  const auto lifetime =
      assess_sa_use(*association, unprotected.plaintext_octets, now);
  if (!accepted(lifetime.status)) {
    OPENSSL_cleanse(plaintext_output.data(), unprotected.plaintext_octets);
    return {.status = EspProcessStatus::lifetime_expired};
  }
  commit_sa_use(*association, lifetime);
  return {.status = EspProcessStatus::ok,
          .plaintext_octets = unprotected.plaintext_octets,
          .next_header = unprotected.next_header,
          .soft_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_soft_limit,
          .hard_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_hard_limit};
}

} // namespace router::ipsec
