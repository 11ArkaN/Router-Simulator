// ISO 10589 IS-IS PDU envelopes for the SR OS six-octet system-ID profile.
// Codecs own no protocol state. Views borrow immutable caller bytes; writers
// use caller-owned bounded storage. Dependencies point only to value helpers.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::isis {

using SystemId = std::array<std::uint8_t, 6U>;
using LanId = std::array<std::uint8_t, 7U>;
using LspId = std::array<std::uint8_t, 8U>;

// Source: iso.10589.2002.protocol. Clauses 9.5 through 9.13 define the wire
// values and fixed-header lengths for a six-octet system identifier.
enum class PduType : std::uint8_t {
  lan_hello_l1 = 15U,
  lan_hello_l2 = 16U,
  point_to_point_hello = 17U,
  lsp_l1 = 18U,
  lsp_l2 = 20U,
  csnp_l1 = 24U,
  csnp_l2 = 25U,
  psnp_l1 = 26U,
  psnp_l2 = 27U
};

inline constexpr std::uint8_t discriminator = 0x83U;
inline constexpr std::size_t common_header_octets = 8U;
inline constexpr std::size_t lan_hello_header_octets = 27U;
inline constexpr std::size_t point_to_point_hello_header_octets = 20U;
inline constexpr std::size_t lsp_header_octets = 27U;
inline constexpr std::size_t csnp_header_octets = 33U;
inline constexpr std::size_t psnp_header_octets = 17U;
inline constexpr std::size_t lsp_protected_offset = 12U;
inline constexpr std::size_t lsp_checksum_offset = 24U;

enum class DecodeError : std::uint8_t {
  none,
  truncated,
  discriminator,
  version,
  pdu_type,
  invalid_id_length,
  unsupported_id_length,
  header_length,
  pdu_length,
  tlv_length
};

struct TlvView {
  std::uint8_t code{};
  std::span<const std::uint8_t> value;
};

class TlvCursor final {
public:
  explicit TlvCursor(std::span<const std::uint8_t> bytes) noexcept : remaining_(bytes) {}

  // Returns one bounded borrowed TLV. End-of-input leaves valid() true;
  // truncation consumes the remaining input and permanently sets it false.
  [[nodiscard]] std::optional<TlvView> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }

private:
  std::span<const std::uint8_t> remaining_;
  bool valid_{true};
};

class TlvWriter final {
public:
  explicit TlvWriter(std::span<std::uint8_t> output) noexcept : output_(output) {}

  // Appends one complete TLV or returns false without changing bytes/cursor.
  // Value may overlap output. The caller owns both writer state and storage.
  [[nodiscard]] bool append(std::uint8_t code, std::span<const std::uint8_t> value) noexcept;
  // Adds ISO padding TLVs to reach at least target octets. A one-octet gap
  // needs a two-octet zero-length TLV. Capacity is preflighted before mutation.
  [[nodiscard]] bool pad_to(std::size_t target) noexcept;
  [[nodiscard]] std::span<const std::uint8_t> bytes() const noexcept {
    return output_.first(length_);
  }

private:
  std::span<std::uint8_t> output_;
  std::size_t length_{};
};

struct SnpEntry {
  std::uint16_t remaining_seconds{};
  LspId id{};
  std::uint32_t sequence{};
  std::uint16_t checksum{};
  bool operator==(const SnpEntry &) const = default;
};

inline constexpr std::size_t snp_entry_octets = 16U;

// ISO 10589 9.10 through 9.13 entry value, without its outer TLV header.
// Reader requires exactly one entry. Writer preflights capacity and changes
// only the first 16 octets. Ordering across entries belongs to the SNP owner.
[[nodiscard]] std::optional<SnpEntry>
snp_entry(std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] bool encode_snp_entry(std::span<std::uint8_t> output,
                                   const SnpEntry &entry) noexcept;

struct PduView {
  PduType type{};
  std::uint8_t maximum_area_addresses{};
  std::span<const std::uint8_t> bytes;
  std::span<const std::uint8_t> tlvs;
};

// Validates the entire envelope and TLV lengths before returning a view.
// Reserved receive bits are ignored. Trailing link padding is excluded using
// PDU Length. ID lengths legal in ISO but outside this profile have a distinct
// error. Checksum, authentication and individual TLV semantics remain explicit
// higher-level checks. No allocation, mutation, retention or shard affinity.
[[nodiscard]] std::optional<PduView>
parse(std::span<const std::uint8_t> bytes, DecodeError &error) noexcept;

struct HelloInput {
  PduType type{};
  SystemId source{};
  std::uint16_t holding_seconds{};
  std::uint8_t circuit_type{};
  std::uint8_t local_circuit_id{};
  std::uint8_t priority{};
  LanId designated_id{};
  std::uint8_t maximum_area_addresses{3U};
};

struct LspInput {
  PduType type{};
  LspId id{};
  std::uint16_t remaining_seconds{};
  std::uint32_t sequence{};
  std::uint8_t flags{};
  std::uint8_t maximum_area_addresses{3U};
};

struct SnpInput {
  PduType type{};
  SystemId source{};
  LspId first{};
  LspId last{};
  std::uint8_t maximum_area_addresses{3U};
};

struct HelloView {
  SystemId source{};
  std::uint16_t holding_seconds{};
  std::uint8_t circuit_type{};
  std::uint8_t local_circuit_id{};
  std::uint8_t priority{};
  LanId designated_id{};
};

struct LspView {
  LspId id{};
  std::uint16_t remaining_seconds{};
  std::uint32_t sequence{};
  std::uint16_t checksum{};
  std::uint8_t flags{};
};

struct SnpView {
  SystemId source{};
  std::uint8_t source_circuit_id{};
  LspId first{};
  LspId last{};
};

// Body projections require a PduView returned by parse and reject another
// family's type. Returned identifiers are value copies; TLVs remain in PduView.
// Reserved circuit-type and priority bits are masked on receipt as required by
// ISO 10589 9.1. Circuit/level compatibility is checked by the adjacency owner.
[[nodiscard]] std::optional<HelloView> hello(const PduView &pdu) noexcept;
[[nodiscard]] std::optional<LspView> lsp(const PduView &pdu) noexcept;
[[nodiscard]] std::optional<SnpView> snp(const PduView &pdu) noexcept;

// Writers validate type, total length and complete TLV framing before mutation.
// Success returns only the written PDU; failure returns nullopt and leaves
// output unchanged. tlvs may overlap output. LSP checksum is generated using
// a seed from the input system ID. Buffers remain owned by the caller, on any
// shard; authentication TLV finalization is a separate protocol-owner operation.
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_hello(std::span<std::uint8_t> output, const HelloInput &input,
             std::span<const std::uint8_t> tlvs) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_lsp(std::span<std::uint8_t> output, const LspInput &input,
           std::span<const std::uint8_t> tlvs) noexcept;
[[nodiscard]] std::optional<std::span<const std::uint8_t>>
encode_snp(std::span<std::uint8_t> output, const SnpInput &input,
           std::span<const std::uint8_t> tlvs) noexcept;

// Applies only mathematical checksum verification to an already validated LSP.
// A zero checksum has a separate ISO 10589 7.3.14 receive rule and must not be
// confused with a malformed header or silently accepted as a valid checksum.
[[nodiscard]] bool valid_lsp_checksum(const PduView &pdu) noexcept;

} // namespace router::packet::isis
