// AH processor tests compose SAD sequence ownership, RFC 4302 canonicalization,
// RFC 4868 HMAC, replay commit, selector validation and lifetime accounting.

#include "router/ipsec_ah_processor.hpp"
#include "router/ipsec_packet.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <stdexcept>

namespace {

router::ipsec::integrity::HmacSha256128Engine *
lookup_ah_engine(void *context, std::uint64_t handle) noexcept {
  return handle == 1U
             ? static_cast<router::ipsec::integrity::HmacSha256128Engine *>(
                   context)
             : nullptr;
}

bool accept_ah_selector(void *, std::uint32_t policy_id,
                        std::uint8_t next_header,
                        std::span<const std::uint8_t> payload) noexcept {
  return policy_id == 7U && next_header == 17U && payload.size() == 4U;
}

} // namespace

void ipsec_ah_processor_tests() {
  using namespace router::ipsec;
  std::array<std::uint8_t, integrity::hmac_sha256_key_octets> key{};
  key.fill(0x3cU);
  auto engine = integrity::HmacSha256128Engine::create(key);
  if (!engine)
    throw std::runtime_error("AH processor key owner setup failed");

  Sad sad{4U};
  SecurityAssociation outbound{};
  outbound.id = 1U;
  outbound.inbound_identifier.spi = 0x10203040U;
  outbound.inbound_identifier.protocol = SecurityProtocol::ah;
  outbound.integrity = IntegrityAlgorithm::hmac_sha256_128;
  outbound.crypto_material_handle = 1U;
  outbound.policy_id = 7U;
  outbound.created_at = std::chrono::steady_clock::time_point{};
  outbound.outbound = true;
  auto inbound = outbound;
  inbound.id = 2U;
  inbound.outbound = false;
  if (sad.install(outbound) != SaInstallResult::installed ||
      sad.install(inbound) != SaInstallResult::installed)
    throw std::runtime_error("AH processor SAD setup failed");

  const AhProcessorDependencies dependencies{
      .engine_context = engine.get(),
      .find_engine = lookup_ah_engine,
      .selector_context = nullptr,
      .validate_inbound_selector = accept_ah_selector};
  std::array<std::uint8_t, 52U> packet_template{};
  packet_template[0U] = 0x45U;
  packet_template[2U] = 0U;
  packet_template[3U] = static_cast<std::uint8_t>(packet_template.size());
  packet_template[8U] = 64U;
  packet_template[9U] = ip_protocol_ah;
  packet_template[12U] = 192U;
  packet_template[15U] = 1U;
  packet_template[16U] = 192U;
  packet_template[19U] = 2U;
  packet_template[20U] = 17U;
  packet_template[21U] = 5U;
  packet_template[48U] = 1U;
  packet_template[49U] = 2U;
  packet_template[50U] = 3U;
  packet_template[51U] = 4U;
  std::array<std::uint8_t, 52U> packet{};
  std::array<std::uint8_t, 52U> scratch{};
  const auto now = std::chrono::steady_clock::time_point{};
  const auto protected_result = protect_ah(
      sad, outbound.id, dependencies, false, packet_template, now, packet,
      scratch);
  if (protected_result.status != AhProcessStatus::ok ||
      protected_result.packet_octets != packet.size())
    throw std::runtime_error("AH outbound protection failed");

  Address destination{};
  Address source{};
  destination.bytes[0U] = 192U;
  source.bytes[0U] = 192U;
  // TTL is mutable and must not invalidate the authenticator in transit.
  packet[8U] = 31U;
  const auto verified = verify_ah(sad, destination, source, dependencies, false,
                                  packet, now, scratch);
  if (verified.status != AhProcessStatus::ok ||
      verified.next_header != 17U || verified.payload_offset != 48U ||
      verified.payload_octets != 4U)
    throw std::runtime_error("AH inbound verification failed");
  if (verify_ah(sad, destination, source, dependencies, false, packet, now,
                scratch)
          .status != AhProcessStatus::replay_rejected)
    throw std::runtime_error("AH processor accepted a replay");

  const auto second = protect_ah(sad, outbound.id, dependencies, false,
                                 packet_template, now, packet, scratch);
  if (second.status != AhProcessStatus::ok)
    throw std::runtime_error("AH second outbound protection failed");
  packet.back() ^= 1U;
  if (verify_ah(sad, destination, source, dependencies, false, packet, now,
                scratch)
          .status != AhProcessStatus::authentication_failed)
    throw std::runtime_error("AH accepted modified immutable payload");
  packet.back() ^= 1U;
  if (verify_ah(sad, destination, source, dependencies, false, packet, now,
                scratch)
          .status != AhProcessStatus::ok)
    throw std::runtime_error("AH replay state advanced before authentication");

  // The IPv6 form carries four explicit zero padding octets after the same
  // 128-bit ICV so AH remains aligned to eight octets.
  std::array<std::uint8_t, 76U> ipv6_template{};
  ipv6_template[0U] = 0x6aU;
  ipv6_template[5U] = 36U;
  ipv6_template[6U] = ip_protocol_ah;
  ipv6_template[7U] = 64U;
  ipv6_template[8U] = 0x20U;
  ipv6_template[24U] = 0x20U;
  ipv6_template[40U] = 17U;
  ipv6_template[41U] = 6U;
  ipv6_template[72U] = 1U;
  ipv6_template[73U] = 2U;
  ipv6_template[74U] = 3U;
  ipv6_template[75U] = 4U;
  std::array<std::uint8_t, 76U> ipv6_packet{};
  std::array<std::uint8_t, 76U> ipv6_scratch{};
  const auto protected_v6 = protect_ah(sad, outbound.id, dependencies, true,
                                       ipv6_template, now, ipv6_packet,
                                       ipv6_scratch);
  Address destination_v6{.family = AddressFamily::ipv6};
  Address source_v6{.family = AddressFamily::ipv6};
  destination_v6.bytes[0U] = 0x20U;
  source_v6.bytes[0U] = 0x20U;
  if (protected_v6.status != AhProcessStatus::ok ||
      std::any_of(ipv6_packet.begin() + 68, ipv6_packet.begin() + 72,
                  [](auto byte) { return byte != 0U; }) ||
      verify_ah(sad, destination_v6, source_v6, dependencies, true,
                ipv6_packet, now, ipv6_scratch)
              .status != AhProcessStatus::ok)
    throw std::runtime_error("IPv6 AH protection or explicit padding failed");
}
