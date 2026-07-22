// Group 19 tests create independent peers, exchange RFC 5903 X|Y values and
// require identical 32-octet ECDH secrets without exporting either private key.

#include "router/ikev2_dh.hpp"

#include <array>
#include <stdexcept>

void ikev2_dh_tests() {
  using namespace router::ikev2::dh;
  auto initiator = EphemeralKey::generate_group_19();
  auto responder = EphemeralKey::generate_group_19();
  if (!initiator || !responder)
    throw std::runtime_error("IKEv2 group 19 key generation failed");
  std::array<std::uint8_t, group_19_public_octets> initiator_public{};
  std::array<std::uint8_t, group_19_public_octets> responder_public{};
  if (initiator->public_value(initiator_public) != Status::ok ||
      responder->public_value(responder_public) != Status::ok)
    throw std::runtime_error("IKEv2 group 19 public export failed");
  std::array<std::uint8_t, group_19_secret_octets> initiator_secret{};
  std::array<std::uint8_t, group_19_secret_octets> responder_secret{};
  if (initiator->derive(responder_public, initiator_secret) != Status::ok ||
      responder->derive(initiator_public, responder_secret) != Status::ok ||
      initiator_secret != responder_secret)
    throw std::runtime_error("IKEv2 group 19 ECDH mismatch");
  std::array<std::uint8_t, group_19_public_octets> invalid_public{};
  if (initiator->derive(invalid_public, initiator_secret) !=
      Status::invalid_peer_value)
    throw std::runtime_error("invalid IKEv2 group 19 point was accepted");
}
