// IS-IS authentication TLV construction and digest checks. The caller owns
// keys and packet bytes; key selection, rollover, counters, purge acceptance
// and adjacency state belong to the protocol process, never this codec.

#pragma once

#include "router/isis_packet.hpp"

namespace router::isis {

enum class AuthenticationMethod : std::uint8_t { password, hmac_md5, hmac_sha1, hmac_sha256 };
enum class AuthenticationError : std::uint8_t {
  none, malformed_pdu, missing, duplicate, wrong_type, wrong_length, wrong_key_id,
  checksum_tlv, mismatch, provider_failure, originator_mismatch, invalid_method
};

struct AuthenticationKey {
  AuthenticationMethod method{};
  std::uint16_t id{}; // RFC 5310 only; password and RFC 5304 do not carry an ID.
  std::span<const std::uint8_t> bytes;
};
// Configuration owner resolves transmit policy independently of receive checks.
// A required missing lease must block transmission, never select unsigned output.
// Key bytes remain borrowed for the synchronous composition/publication call.
struct TransmitAuthentication {
  bool required{};
  std::optional<AuthenticationKey> key;
};

// Appends cleartext or a digest placeholder with its exact type/length/key-ID.
// Caller completes all other TLVs and Hello padding before finalization.
// Invalid method, excessive password length or capacity failure leaves writer
// unchanged. Input key bytes are borrowed only for this call, on any shard.
[[nodiscard]] bool append_authentication(packet::isis::TlvWriter &writer,
                                         const AuthenticationKey &key) noexcept;

// Requires an already encoded complete PDU and exactly one matching auth TLV.
// Originator must equal its source ID; LSP checksum uses this immutable seed.
// Success changes digest/checksum bytes only, preserving Remaining Lifetime.
// Every failure leaves output unchanged. No packet concatenation or retention.
[[nodiscard]] AuthenticationError finalize_authentication(
    std::span<std::uint8_t> pdu, const AuthenticationKey &key,
    const packet::isis::SystemId &originator) noexcept;

// Authenticates bytes only, without changing the packet or accepting a purge,
// sequence number or adjacency. LSP lifetime/checksum are excluded from HMAC.
// Comparison is constant-time. Unknown types, duplicate TLVs and optional
// checksum TLVs forbidden with cryptographic Hello/SNP authentication fail.
[[nodiscard]] AuthenticationError verify_authentication(
    std::span<const std::uint8_t> pdu, const AuthenticationKey &key) noexcept;

} // namespace router::isis
