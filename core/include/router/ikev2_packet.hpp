// Allocation-free IKEv2 message and generic payload-chain codec. It validates
// untrusted UDP payloads but owns no IKE SA, keys, timers or sockets. A service
// shard supplies bounded output storage and decides how known payload bodies are
// interpreted after this structural layer succeeds.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace router::ikev2 {

inline constexpr std::size_t header_octets = 28U;
inline constexpr std::size_t generic_payload_header_octets = 4U;

enum class ExchangeType : std::uint8_t {
  ike_sa_init = 34U,
  ike_auth = 35U,
  create_child_sa = 36U,
  informational = 37U
};

enum class PayloadType : std::uint8_t {
  none = 0U,
  security_association = 33U,
  key_exchange = 34U,
  identification_initiator = 35U,
  identification_responder = 36U,
  certificate = 37U,
  certificate_request = 38U,
  authentication = 39U,
  nonce = 40U,
  notify = 41U,
  delete_payload = 42U,
  vendor_id = 43U,
  traffic_selector_initiator = 44U,
  traffic_selector_responder = 45U,
  encrypted = 46U,
  configuration = 47U,
  extensible_authentication = 48U,
  encrypted_fragment = 53U
};

struct Header {
  std::uint64_t initiator_spi{};
  std::uint64_t responder_spi{};
  std::uint8_t first_payload{};
  std::uint8_t major_version{};
  std::uint8_t minor_version{};
  std::uint8_t exchange_type{};
  bool initiator{};
  bool higher_version_supported{};
  bool response{};
  std::uint32_t message_id{};
  std::uint32_t length{};
};

struct PayloadView {
  std::uint8_t type{};
  std::uint8_t next_payload{};
  bool critical{};
  std::span<const std::uint8_t> body;
  std::size_t offset{};
};

enum class ParseStatus : std::uint8_t {
  ok,
  truncated_header,
  invalid_length,
  invalid_version,
  invalid_flags,
  invalid_spi,
  truncated_payload,
  invalid_payload_length,
  payload_capacity_exhausted,
  trailing_payload_type
};

struct ParseResult {
  ParseStatus status{ParseStatus::truncated_header};
  Header header{};
  std::size_t payload_count{};
};

struct PayloadChainParseResult {
  ParseStatus status{ParseStatus::truncated_payload};
  std::size_t payload_count{};
};

// payloads receives views in transmitted chain order. If capacity is exhausted,
// parsing fails without truncating the logical message and the caller may emit
// TEMPORARY_FAILURE or apply its bounded overload policy.
[[nodiscard]] ParseResult
parse(std::span<const std::uint8_t> datagram,
      std::span<PayloadView> payloads) noexcept;

// Decrypted SK plaintext contains only a generic payload chain, not another
// IKE header. Offsets returned here are relative to encoded_payloads. An SK or
// SKF payload terminates its visible chain because its Next Payload field
// names protected content rather than another outer payload.
[[nodiscard]] PayloadChainParseResult parse_payload_chain(
    std::uint8_t first_payload,
    std::span<const std::uint8_t> encoded_payloads,
    std::span<PayloadView> payloads) noexcept;

// encode_header writes exactly 28 octets. total_length must already include all
// payloads and be representable by the supplied output span.
[[nodiscard]] bool encode_header(const Header &header,
                                 std::span<std::uint8_t> output) noexcept;

// encode_payload writes one generic header and body. The caller chains payload
// types explicitly so encrypted and fragmented payload ownership stays visible.
[[nodiscard]] std::size_t
encode_payload(std::uint8_t next_payload, bool critical,
               std::span<const std::uint8_t> body,
               std::span<std::uint8_t> output) noexcept;

// Packet owners that fill a body in place, such as AEAD engines, reserve the
// generic header before the body exists. This writes only the four header
// octets and validates the complete payload length.
[[nodiscard]] bool encode_payload_header(std::uint8_t next_payload,
                                         bool critical,
                                         std::size_t payload_octets,
                                         std::span<std::uint8_t> output) noexcept;

} // namespace router::ikev2
