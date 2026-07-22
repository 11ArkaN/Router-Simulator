// Allocation-free DNS wire parser and base encoder. The caller owns section
// storage and the received message bytes. Parsed RDATA remains a borrowed view,
// while expanded owner names are copied into bounded RFC 1035 wire form.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace router::packet::dns {

inline constexpr std::size_t header_octets = 12U;
inline constexpr std::size_t maximum_message_octets = 65535U;
inline constexpr std::uint16_t server_port = 53U;
inline constexpr std::size_t maximum_name_octets = 255U;
inline constexpr std::size_t maximum_label_octets = 63U;
inline constexpr std::uint16_t internet_class = 1U;
inline constexpr std::uint16_t type_a = 1U;
inline constexpr std::uint16_t type_ns = 2U;
inline constexpr std::uint16_t type_md = 3U;
inline constexpr std::uint16_t type_mf = 4U;
inline constexpr std::uint16_t type_cname = 5U;
inline constexpr std::uint16_t type_soa = 6U;
inline constexpr std::uint16_t type_mb = 7U;
inline constexpr std::uint16_t type_mg = 8U;
inline constexpr std::uint16_t type_mr = 9U;
inline constexpr std::uint16_t type_null = 10U;
inline constexpr std::uint16_t type_wks = 11U;
inline constexpr std::uint16_t type_ptr = 12U;
inline constexpr std::uint16_t type_hinfo = 13U;
inline constexpr std::uint16_t type_minfo = 14U;
inline constexpr std::uint16_t type_mx = 15U;
inline constexpr std::uint16_t type_txt = 16U;
inline constexpr std::uint16_t type_aaaa = 28U;
inline constexpr std::uint16_t type_srv = 33U;
inline constexpr std::uint16_t type_dname = 39U;
inline constexpr std::uint16_t type_ds = 43U;
inline constexpr std::uint16_t type_rrsig = 46U;
inline constexpr std::uint16_t type_nsec = 47U;
inline constexpr std::uint16_t type_dnskey = 48U;
inline constexpr std::uint16_t type_nsec3 = 50U;
inline constexpr std::uint16_t type_nsec3param = 51U;
inline constexpr std::uint16_t type_tlsa = 52U;
inline constexpr std::uint16_t type_caa = 257U;
inline constexpr std::uint16_t type_svcb = 64U;
inline constexpr std::uint16_t type_https = 65U;
inline constexpr std::uint16_t type_opt = 41U;

enum class Rcode : std::uint8_t {
  no_error = 0U,
  format_error = 1U,
  server_failure = 2U,
  name_error = 3U,
  not_implemented = 4U,
  refused = 5U,
  yx_domain = 6U
};

struct Name {
  // The expanded value uses ordinary label-length octets and one root octet.
  // It never contains compression pointers, native strings or hidden storage.
  std::array<std::uint8_t, maximum_name_octets> wire{};
  std::uint16_t octets{1U};

  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return std::span<const std::uint8_t>{wire}.first(octets);
  }
};

struct Header {
  std::uint16_t id{};
  std::uint16_t question_count{};
  std::uint16_t answer_count{};
  std::uint16_t authority_count{};
  std::uint16_t additional_count{};
  std::uint8_t opcode{};
  Rcode rcode{Rcode::no_error};
  bool response{};
  bool authoritative{};
  bool truncated{};
  bool recursion_desired{};
  bool recursion_available{};
  bool authentic_data{};
  bool checking_disabled{};
};

struct Question {
  Name name;
  std::uint16_t type{};
  std::uint16_t record_class{};
};

struct ResourceRecord {
  Name owner;
  std::uint16_t type{};
  std::uint16_t record_class{};
  std::uint32_t ttl{};
  // This view borrows the input packet and deliberately preserves unknown RR
  // formats. It is invalid after the caller releases that packet buffer.
  std::span<const std::uint8_t> rdata;
  std::size_t rdata_message_offset{};
};

struct RecordData {
  Name owner;
  std::uint16_t type{};
  std::uint16_t record_class{};
  std::uint32_t ttl{};
  // Canonical RDATA is caller-owned. Domain names inside it use ordinary
  // uncompressed DNS wire names, which are valid for every supported RR type.
  std::span<const std::uint8_t> rdata;
};

struct ResponseConfiguration {
  Rcode rcode{Rcode::no_error};
  bool authoritative{};
  bool recursion_desired{};
  bool recursion_available{};
  bool authentic_data{};
  bool checking_disabled{};
  std::optional<std::uint16_t> edns_udp_payload_size;
  std::uint8_t edns_extended_rcode{};
  std::uint8_t edns_version{};
  bool dnssec_ok{};
};

struct MessageStorage {
  std::span<Question> questions;
  std::span<ResourceRecord> answers;
  std::span<ResourceRecord> authorities;
  std::span<ResourceRecord> additionals;
};

struct MessageView {
  Header header;
  std::span<const Question> questions;
  std::span<const ResourceRecord> answers;
  std::span<const ResourceRecord> authorities;
  std::span<const ResourceRecord> additionals;
};

// parse_name expands labels at message_offset and returns the number of octets
// consumed at that original position. Compression pointers may terminate the
// original name, so consumed and expanded length are intentionally distinct.
[[nodiscard]] std::optional<std::size_t>
parse_name(std::span<const std::uint8_t> message, std::size_t message_offset,
           Name &output) noexcept;

// Parses one complete RFC 1035 wire name without compression. The returned
// count covers only that name, so callers can walk concatenated name lists.
// On failure output is unchanged. This boundary is shared by DNS RDATA and
// DHCPv6 options whose wire formats explicitly prohibit compression.
[[nodiscard]] std::optional<std::size_t>
parse_uncompressed_name(std::span<const std::uint8_t> bytes,
                        Name &output) noexcept;

// The parser rejects insufficient caller storage before publishing any spans.
// It also rejects trailing bytes, malformed counts, reserved label forms and
// RDATA which extends beyond the UDP or TCP DNS message boundary.
[[nodiscard]] std::optional<MessageView>
parse(std::span<const std::uint8_t> message,
      const MessageStorage &storage) noexcept;

// Presentation parsing accepts an absolute name with an optional final dot.
// The root is ".". Empty interior labels, labels over 63 octets and expanded
// names over 255 octets are rejected without partial publication.
[[nodiscard]] std::optional<Name>
name_from_text(std::string_view text) noexcept;
[[nodiscard]] bool equal_case_insensitive(const Name &left,
                                          const Name &right) noexcept;

// Converts one parsed RDATA field to checkpoint-safe canonical bytes. Embedded
// names are expanded against the complete message and all other bytes remain
// exact. The output is replaced only after complete validation succeeds.
[[nodiscard]] bool
canonicalize_rdata(std::span<const std::uint8_t> message,
                   const ResourceRecord &record,
                   std::vector<std::uint8_t> &output) noexcept;

// DNS over TCP prepends an unsigned two-octet message length. A zero length is
// invalid. decode_stream_message returns nullopt until a whole frame is
// present and reports the exact consumed prefix plus message span, allowing a
// connection owner to retain any following frames without extra packet rules.
struct StreamMessage {
  std::span<const std::uint8_t> message;
  std::size_t consumed_octets{};
};
[[nodiscard]] std::optional<std::size_t>
encode_stream_message(std::span<std::uint8_t> output,
                      std::span<const std::uint8_t> message) noexcept;
[[nodiscard]] std::optional<StreamMessage>
decode_stream_message(std::span<const std::uint8_t> input) noexcept;

// Encodes a standard one-question query without compression. EDNS is emitted
// only when udp_payload_size is present. Values below 512 are represented as
// 512 as RFC 6891 requires; the caller chooses any higher resource policy.
[[nodiscard]] std::optional<std::size_t>
encode_query(std::span<std::uint8_t> output, std::uint16_t id,
             const Question &question, bool recursion_desired,
             std::optional<std::uint16_t> udp_payload_size = std::nullopt,
             bool dnssec_ok = false, bool authentic_data = false,
             bool checking_disabled = false) noexcept;

// Builds the header-only error form used when a server cannot safely echo a
// malformed question. Preconditions: output holds at least the 12-octet DNS
// header and opcode fits the four-bit field. No borrowed storage survives the
// call. The function has no shard affinity and performs no allocation.
[[nodiscard]] std::optional<std::size_t>
encode_error_response(std::span<std::uint8_t> output, std::uint16_t id,
                      std::uint8_t opcode, Rcode rcode, bool recursion_desired,
                      bool checking_disabled,
                      bool recursion_available = false) noexcept;

// Response encoding retains whole consecutive RRsets. If the caller's UDP or
// stream message budget cannot hold the next complete set, the encoder stops
// before it and sets TC. Owner names equal to QNAME use a backward pointer;
// all RDATA is copied canonically and remains interoperable without
// compression.
[[nodiscard]] std::optional<std::size_t>
encode_response(std::span<std::uint8_t> output, std::uint16_t id,
                const Question &question, std::span<const RecordData> answers,
                std::span<const RecordData> authorities,
                std::span<const RecordData> additionals,
                const ResponseConfiguration &configuration) noexcept;

} // namespace router::packet::dns
