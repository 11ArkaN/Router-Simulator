// RFC 4302 inbound and outbound processing order for the executable base-header
// profile. Replay is checked before HMAC but committed only after successful
// authentication. Selector validation happens before payload release.

#include "router/ipsec_ah_processor.hpp"

#include "router/ipsec_ah_canonical.hpp"
#include "router/ipsec_lifetime.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::ipsec {
namespace {

std::size_t ah_offset(bool ipv6) noexcept { return ipv6 ? 40U : 20U; }

void write_u32(std::span<std::uint8_t> output, std::size_t offset,
               std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::array<std::uint8_t, 4U> esn_high(std::uint64_t sequence) noexcept {
  const auto high = static_cast<std::uint32_t>(sequence >> 32U);
  return {static_cast<std::uint8_t>(high >> 24U),
          static_cast<std::uint8_t>(high >> 16U),
          static_cast<std::uint8_t>(high >> 8U),
          static_cast<std::uint8_t>(high)};
}

ah::CanonicalResult canonicalize(bool ipv6,
                                 std::span<const std::uint8_t> packet,
                                 std::span<std::uint8_t> output) noexcept {
  return ipv6 ? ah::canonicalize_ipv6(packet, output)
              : ah::canonicalize_ipv4(packet, output);
}

AhProcessStatus map_canonical(ah::CanonicalStatus status) noexcept {
  if (status == ah::CanonicalStatus::output_too_small)
    return AhProcessStatus::output_too_small;
  if (status == ah::CanonicalStatus::unsupported_header_chain)
    return AhProcessStatus::unsupported_header_chain;
  return AhProcessStatus::invalid_argument;
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

AhProtectResult protect_ah(
    Sad &sad, std::uint64_t outbound_sa_id,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet_template,
    std::chrono::steady_clock::time_point now, std::span<std::uint8_t> output,
    std::span<std::uint8_t> canonical_scratch) noexcept {
  if (!dependencies.find_engine)
    return {.status = AhProcessStatus::invalid_argument};
  auto *association = sad.find_outbound(outbound_sa_id);
  if (!association)
    return {.status = AhProcessStatus::unknown_sa};
  if (!association->outbound || association->inbound_identifier.protocol !=
                                    SecurityProtocol::ah ||
      association->integrity != IntegrityAlgorithm::hmac_sha256_128)
    return {.status = AhProcessStatus::wrong_sa_direction};
  if (output.size() < packet_template.size() ||
      canonical_scratch.size() < packet_template.size())
    return {.status = AhProcessStatus::output_too_small};
  auto *engine = dependencies.find_engine(
      dependencies.engine_context, association->crypto_material_handle);
  if (!engine)
    return {.status = AhProcessStatus::crypto_failure};
  std::copy(packet_template.begin(), packet_template.end(), output.begin());
  const auto offset = ah_offset(ipv6);
  if (output.size() < offset + 12U)
    return {.status = AhProcessStatus::invalid_argument};
  write_u32(output, offset + 4U, association->inbound_identifier.spi);
  // Validate the complete caller template before consuming a non-reusable AH
  // sequence number. Sequence zero is safe only in this local scratch pass and
  // is replaced before any packet or authenticator can leave the owner.
  write_u32(output, offset + 8U, 0U);
  auto canonical = canonicalize(
      ipv6, std::span<const std::uint8_t>{output}.first(packet_template.size()),
      canonical_scratch);
  if (canonical.status != ah::CanonicalStatus::ok)
    return {.status = map_canonical(canonical.status)};
  const auto payload_octets =
      packet_template.size() - (offset + canonical.ah.header_length);
  const auto lifetime = assess_sa_use(*association, payload_octets, now);
  if (!accepted(lifetime.status))
    return {.status = AhProcessStatus::lifetime_expired};
  const auto sequence = association->outbound_sequence.next();
  if (!sequence)
    return {.status = AhProcessStatus::sequence_exhausted};
  write_u32(output, offset + 8U, static_cast<std::uint32_t>(*sequence));
  canonical = canonicalize(
      ipv6, std::span<const std::uint8_t>{output}.first(packet_template.size()),
      canonical_scratch);
  if (canonical.status != ah::CanonicalStatus::ok)
    return {.status = map_canonical(canonical.status)};
  const auto high = esn_high(*sequence);
  const std::array segments{
      std::span<const std::uint8_t>{canonical_scratch}.first(
          canonical.packet_octets),
      association->outbound_sequence.extended()
          ? std::span<const std::uint8_t>{high}
          : std::span<const std::uint8_t>{}};
  auto transmitted_icv = output.subspan(
      offset + 12U, integrity::hmac_sha256_128_icv_octets);
  if (engine->compute(segments, transmitted_icv) != integrity::Status::ok)
    return {.status = AhProcessStatus::crypto_failure};
  // IPv6 alignment padding is transmitted as zero and is itself covered by
  // the canonical packet. IPv4 has no padding for this 128-bit ICV.
  const auto full_icv_region = canonical.ah.icv.size();
  if (full_icv_region > transmitted_icv.size())
    std::fill(output.begin() + static_cast<std::ptrdiff_t>(offset + 12U +
                                                           transmitted_icv.size()),
              output.begin() + static_cast<std::ptrdiff_t>(offset + 12U +
                                                           full_icv_region),
              std::uint8_t{0});
  commit_sa_use(*association, lifetime);
  return {.status = AhProcessStatus::ok,
          .packet_octets = packet_template.size(),
          .soft_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_soft_limit,
          .hard_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_hard_limit};
}

AhVerifyResult verify_ah(
    Sad &sad, const Address &outer_destination, const Address &outer_source,
    const AhProcessorDependencies &dependencies, bool ipv6,
    std::span<const std::uint8_t> packet,
    std::chrono::steady_clock::time_point now,
    std::span<std::uint8_t> canonical_scratch) noexcept {
  if (!dependencies.find_engine || !dependencies.validate_inbound_selector)
    return {.status = AhProcessStatus::invalid_argument};
  const auto canonical = canonicalize(ipv6, packet, canonical_scratch);
  if (canonical.status != ah::CanonicalStatus::ok)
    return {.status = map_canonical(canonical.status)};
  const auto offset = ah_offset(ipv6);
  const auto received_icv = packet.subspan(
      offset + 12U, integrity::hmac_sha256_128_icv_octets);
  if (canonical.ah.icv.size() > received_icv.size() &&
      std::any_of(packet.begin() + static_cast<std::ptrdiff_t>(
                                   offset + 12U + received_icv.size()),
                  packet.begin() + static_cast<std::ptrdiff_t>(
                                   offset + 12U + canonical.ah.icv.size()),
                  [](auto byte) { return byte != 0U; }))
    return {.status = AhProcessStatus::authentication_failed};
  auto *association = sad.find_inbound(SecurityProtocol::ah, canonical.ah.spi,
                                       outer_destination, outer_source);
  if (!association)
    return {.status = AhProcessStatus::unknown_sa};
  if (association->integrity != IntegrityAlgorithm::hmac_sha256_128)
    return {.status = AhProcessStatus::wrong_sa_direction};
  const auto replay = association->replay.check(canonical.ah.sequence_low);
  if (replay.status != ReplayStatus::admissible) {
    increment_drop(association->counters.replay_drops);
    return {.status = AhProcessStatus::replay_rejected};
  }
  auto *engine = dependencies.find_engine(
      dependencies.engine_context, association->crypto_material_handle);
  if (!engine)
    return {.status = AhProcessStatus::crypto_failure};
  const auto high = esn_high(replay.sequence);
  const std::array segments{
      std::span<const std::uint8_t>{canonical_scratch}.first(
          canonical.packet_octets),
      association->replay.extended()
          ? std::span<const std::uint8_t>{high}
          : std::span<const std::uint8_t>{}};
  if (engine->verify(segments, received_icv) != integrity::Status::ok) {
    increment_drop(association->counters.integrity_drops);
    return {.status = AhProcessStatus::authentication_failed};
  }
  if (!association->replay.commit(replay.sequence))
    return {.status = AhProcessStatus::replay_rejected};
  const auto payload_offset = offset + canonical.ah.header_length;
  const auto payload = packet.subspan(payload_offset);
  if (!dependencies.validate_inbound_selector(
          dependencies.selector_context, association->policy_id,
          canonical.ah.next_header, payload)) {
    increment_drop(association->counters.selector_drops);
    return {.status = AhProcessStatus::selector_mismatch};
  }
  const auto lifetime = assess_sa_use(*association, payload.size(), now);
  if (!accepted(lifetime.status))
    return {.status = AhProcessStatus::lifetime_expired};
  commit_sa_use(*association, lifetime);
  return {.status = AhProcessStatus::ok,
          .payload_offset = payload_offset,
          .payload_octets = payload.size(),
          .next_header = canonical.ah.next_header,
          .soft_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_soft_limit,
          .hard_lifetime_reached =
              lifetime.status == LifetimeUseStatus::accepted_hard_limit};
}

} // namespace router::ipsec
