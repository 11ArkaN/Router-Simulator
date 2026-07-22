// RFC 1035 and RFC 6891 DNS message codec. Compression traversal requires
// every pointer to target an earlier message offset. This both follows the
// original compression contract and makes pointer loops impossible without a
// heap bitmap or recursion on untrusted input.

#include "router/dns_packet.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <new>

namespace router::packet::dns {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
}

void write_u16(std::span<std::uint8_t> bytes, std::size_t offset,
               std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

bool parse_question(std::span<const std::uint8_t> message, std::size_t &offset,
                    Question &question) noexcept {
  const auto consumed = parse_name(message, offset, question.name);
  if (!consumed || *consumed > message.size() - offset)
    return false;
  offset += *consumed;
  if (message.size() - offset < 4U)
    return false;
  question.type = read_u16(message, offset);
  question.record_class = read_u16(message, offset + 2U);
  offset += 4U;
  return true;
}

bool parse_record(std::span<const std::uint8_t> message, std::size_t &offset,
                  ResourceRecord &record) noexcept {
  const auto consumed = parse_name(message, offset, record.owner);
  if (!consumed || *consumed > message.size() - offset)
    return false;
  offset += *consumed;
  if (message.size() - offset < 10U)
    return false;
  record.type = read_u16(message, offset);
  record.record_class = read_u16(message, offset + 2U);
  record.ttl = read_u32(message, offset + 4U);
  const auto rdata_octets = read_u16(message, offset + 8U);
  offset += 10U;
  if (rdata_octets > message.size() - offset)
    return false;
  record.rdata_message_offset = offset;
  record.rdata = message.subspan(offset, rdata_octets);
  offset += rdata_octets;
  return true;
}

template <typename Value, typename ParseOne>
bool parse_section(std::span<const std::uint8_t> message, std::size_t &offset,
                   std::span<Value> storage, std::uint16_t count,
                   ParseOne parse_one) noexcept {
  if (count > storage.size())
    return false;
  for (std::size_t index = 0U; index < count; ++index)
    if (!parse_one(message, offset, storage[index]))
      return false;
  return true;
}

} // namespace

std::optional<std::size_t> parse_name(std::span<const std::uint8_t> message,
                                      std::size_t message_offset,
                                      Name &output) noexcept {
  if (message_offset >= message.size())
    return std::nullopt;
  Name staged;
  staged.octets = 0U;
  std::size_t cursor = message_offset;
  std::size_t consumed{};
  bool jumped{};

  while (cursor < message.size()) {
    const auto length = message[cursor];
    if ((length & 0xc0U) == 0xc0U) {
      if (cursor + 1U >= message.size())
        return std::nullopt;
      const auto pointer = static_cast<std::size_t>(
          (static_cast<std::uint16_t>(length & 0x3fU) << 8U) |
          message[cursor + 1U]);
      // RFC 1035 compression points to a prior occurrence. Enforcing that
      // direction also rejects self-pointers, forward-pointer chains and every
      // possible loop before following untrusted offsets.
      if (pointer >= cursor)
        return std::nullopt;
      if (!jumped)
        consumed = cursor + 2U - message_offset;
      jumped = true;
      cursor = pointer;
      continue;
    }
    if ((length & 0xc0U) != 0U || length > maximum_label_octets)
      return std::nullopt;
    ++cursor;
    if (length == 0U) {
      if (staged.octets >= staged.wire.size())
        return std::nullopt;
      staged.wire[staged.octets++] = 0U;
      if (!jumped)
        consumed = cursor - message_offset;
      output = staged;
      return consumed;
    }
    if (cursor + length > message.size() ||
        staged.octets + 1U + length >= staged.wire.size())
      return std::nullopt;
    staged.wire[staged.octets++] = length;
    std::copy_n(message.begin() + static_cast<std::ptrdiff_t>(cursor), length,
                staged.wire.begin() + staged.octets);
    staged.octets = static_cast<std::uint16_t>(staged.octets + length);
    cursor += length;
  }
  return std::nullopt;
}

std::optional<std::size_t>
parse_uncompressed_name(std::span<const std::uint8_t> bytes,
                        Name &output) noexcept {
  Name staged;
  staged.octets = 0U;
  std::size_t offset{};
  while (offset < bytes.size()) {
    const auto length = bytes[offset++];
    // The high bits identify either a compression pointer or a reserved DNS
    // label form. Both are invalid at an explicitly uncompressed boundary.
    if ((length & 0xc0U) != 0U || length > maximum_label_octets ||
        staged.octets >= staged.wire.size())
      return std::nullopt;
    staged.wire[staged.octets++] = length;
    if (length == 0U) {
      output = staged;
      return offset;
    }
    if (length > bytes.size() - offset ||
        length > staged.wire.size() - staged.octets)
      return std::nullopt;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), length,
                staged.wire.begin() + staged.octets);
    staged.octets = static_cast<std::uint16_t>(staged.octets + length);
    offset += length;
  }
  return std::nullopt;
}

std::optional<MessageView> parse(std::span<const std::uint8_t> message,
                                 const MessageStorage &storage) noexcept {
  if (message.size() < header_octets)
    return std::nullopt;
  const auto flags = read_u16(message, 2U);
  Header header{.id = read_u16(message, 0U),
                .question_count = read_u16(message, 4U),
                .answer_count = read_u16(message, 6U),
                .authority_count = read_u16(message, 8U),
                .additional_count = read_u16(message, 10U),
                .opcode = static_cast<std::uint8_t>((flags >> 11U) & 0x0fU),
                .rcode = static_cast<Rcode>(flags & 0x0fU),
                .response = (flags & 0x8000U) != 0U,
                .authoritative = (flags & 0x0400U) != 0U,
                .truncated = (flags & 0x0200U) != 0U,
                .recursion_desired = (flags & 0x0100U) != 0U,
                .recursion_available = (flags & 0x0080U) != 0U,
                .authentic_data = (flags & 0x0020U) != 0U,
                .checking_disabled = (flags & 0x0010U) != 0U};
  std::size_t offset = header_octets;
  if (!parse_section(message, offset, storage.questions, header.question_count,
                     parse_question) ||
      !parse_section(message, offset, storage.answers, header.answer_count,
                     parse_record) ||
      !parse_section(message, offset, storage.authorities,
                     header.authority_count, parse_record) ||
      !parse_section(message, offset, storage.additionals,
                     header.additional_count, parse_record) ||
      offset != message.size())
    return std::nullopt;
  return MessageView{
      .header = header,
      .questions = storage.questions.first(header.question_count),
      .answers = storage.answers.first(header.answer_count),
      .authorities = storage.authorities.first(header.authority_count),
      .additionals = storage.additionals.first(header.additional_count)};
}

std::optional<Name> name_from_text(std::string_view text) noexcept {
  Name result;
  result.octets = 0U;
  if (text == "." || text.empty()) {
    result.wire[0U] = 0U;
    result.octets = 1U;
    return result;
  }
  if (text.back() == '.')
    text.remove_suffix(1U);
  std::size_t begin{};
  while (begin < text.size()) {
    const auto dot = text.find('.', begin);
    const auto end = dot == std::string_view::npos ? text.size() : dot;
    const auto length = end - begin;
    if (length == 0U || length > maximum_label_octets ||
        result.octets + 1U + length >= result.wire.size())
      return std::nullopt;
    result.wire[result.octets++] = static_cast<std::uint8_t>(length);
    std::copy_n(text.begin() + static_cast<std::ptrdiff_t>(begin), length,
                result.wire.begin() + result.octets);
    result.octets = static_cast<std::uint16_t>(result.octets + length);
    if (dot == std::string_view::npos)
      break;
    begin = dot + 1U;
  }
  result.wire[result.octets++] = 0U;
  return result;
}

bool equal_case_insensitive(const Name &left, const Name &right) noexcept {
  if (left.octets != right.octets)
    return false;
  for (std::size_t index = 0U; index < left.octets; ++index) {
    const auto lhs = left.wire[index];
    const auto rhs = right.wire[index];
    if (lhs == rhs)
      continue;
    // Length and root octets are below ASCII alphabetic values, so folding
    // them is harmless and keeps comparison allocation-free.
    if (std::tolower(static_cast<unsigned char>(lhs)) !=
        std::tolower(static_cast<unsigned char>(rhs)))
      return false;
  }
  return true;
}

bool canonicalize_rdata(std::span<const std::uint8_t> message,
                        const ResourceRecord &record,
                        std::vector<std::uint8_t> &output) noexcept {
  try {
    std::vector<std::uint8_t> staged;
    staged.reserve(record.rdata.size());
    const auto append_name = [&](std::size_t message_offset,
                                 std::size_t available,
                                 std::size_t &consumed) -> bool {
      Name expanded;
      const auto parsed = parse_name(message, message_offset, expanded);
      if (!parsed || *parsed > available)
        return false;
      staged.insert(staged.end(), expanded.wire.begin(),
                    expanded.wire.begin() + expanded.octets);
      consumed = *parsed;
      return true;
    };

    std::size_t first{};
    switch (record.type) {
    case type_ns:
    case type_md:
    case type_mf:
    case type_cname:
    case type_mb:
    case type_mg:
    case type_mr:
    case type_ptr:
    case type_dname:
      if (!append_name(record.rdata_message_offset, record.rdata.size(),
                       first) ||
          first != record.rdata.size())
        return false;
      break;
    case type_minfo: {
      std::size_t second{};
      if (!append_name(record.rdata_message_offset, record.rdata.size(),
                       first) ||
          first > record.rdata.size() ||
          !append_name(record.rdata_message_offset + first,
                       record.rdata.size() - first, second) ||
          first + second != record.rdata.size())
        return false;
      break;
    }
    case type_mx:
      if (record.rdata.size() < 3U)
        return false;
      staged.insert(staged.end(), record.rdata.begin(),
                    record.rdata.begin() + 2U);
      if (!append_name(record.rdata_message_offset + 2U,
                       record.rdata.size() - 2U, first) ||
          first != record.rdata.size() - 2U)
        return false;
      break;
    case type_srv:
      if (record.rdata.size() < 7U)
        return false;
      staged.insert(staged.end(), record.rdata.begin(),
                    record.rdata.begin() + 6U);
      if (!append_name(record.rdata_message_offset + 6U,
                       record.rdata.size() - 6U, first) ||
          first != record.rdata.size() - 6U)
        return false;
      break;
    case type_soa: {
      std::size_t second{};
      if (!append_name(record.rdata_message_offset, record.rdata.size(),
                       first) ||
          first > record.rdata.size() ||
          !append_name(record.rdata_message_offset + first,
                       record.rdata.size() - first, second) ||
          first + second + 20U != record.rdata.size())
        return false;
      staged.insert(staged.end(), record.rdata.end() - 20, record.rdata.end());
      break;
    }
    default:
      staged.assign(record.rdata.begin(), record.rdata.end());
      break;
    }
    output = std::move(staged);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

std::optional<std::size_t>
encode_stream_message(std::span<std::uint8_t> output,
                      std::span<const std::uint8_t> message) noexcept {
  if (message.empty() ||
      message.size() > std::numeric_limits<std::uint16_t>::max() ||
      output.size() < message.size() + 2U)
    return std::nullopt;
  const auto length = static_cast<std::uint16_t>(message.size());
  output[0] = static_cast<std::uint8_t>(length >> 8U);
  output[1] = static_cast<std::uint8_t>(length);
  std::copy(message.begin(), message.end(), output.begin() + 2U);
  return message.size() + 2U;
}

std::optional<StreamMessage>
decode_stream_message(std::span<const std::uint8_t> input) noexcept {
  if (input.size() < 2U)
    return std::nullopt;
  const auto length = static_cast<std::size_t>(
      (static_cast<std::uint16_t>(input[0]) << 8U) | input[1]);
  if (length == 0U || input.size() < length + 2U)
    return std::nullopt;
  return StreamMessage{.message = input.subspan(2U, length),
                       .consumed_octets = length + 2U};
}

namespace {

bool same_rrset(const RecordData &left, const RecordData &right) noexcept {
  return left.type == right.type && left.record_class == right.record_class &&
         equal_case_insensitive(left.owner, right.owner);
}

std::size_t encoded_owner_octets(const RecordData &record,
                                 const Question &question) noexcept {
  return equal_case_insensitive(record.owner, question.name)
             ? 2U
             : record.owner.octets;
}

bool valid_record(const RecordData &record) noexcept {
  if (record.owner.octets == 0U || record.owner.octets > maximum_name_octets ||
      record.type == 0U ||
      record.rdata.size() > std::numeric_limits<std::uint16_t>::max())
    return false;
  Name validated;
  const auto consumed = parse_name(record.owner.view(), 0U, validated);
  return consumed && *consumed == record.owner.octets;
}

void write_record(std::span<std::uint8_t> output, std::size_t &offset,
                  const RecordData &record, const Question &question) noexcept {
  if (equal_case_insensitive(record.owner, question.name)) {
    // QNAME always begins immediately after the fixed header in responses
    // generated by this encoder, making 0xC00C a stable backward pointer.
    output[offset++] = 0xc0U;
    output[offset++] = 0x0cU;
  } else {
    std::copy_n(record.owner.wire.begin(), record.owner.octets,
                output.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += record.owner.octets;
  }
  write_u16(output, offset, record.type);
  write_u16(output, offset + 2U, record.record_class);
  output[offset + 4U] = static_cast<std::uint8_t>(record.ttl >> 24U);
  output[offset + 5U] = static_cast<std::uint8_t>(record.ttl >> 16U);
  output[offset + 6U] = static_cast<std::uint8_t>(record.ttl >> 8U);
  output[offset + 7U] = static_cast<std::uint8_t>(record.ttl);
  write_u16(output, offset + 8U,
            static_cast<std::uint16_t>(record.rdata.size()));
  offset += 10U;
  std::copy(record.rdata.begin(), record.rdata.end(),
            output.begin() + static_cast<std::ptrdiff_t>(offset));
  offset += record.rdata.size();
}

bool encode_section(std::span<std::uint8_t> output, std::size_t &offset,
                    const Question &question,
                    std::span<const RecordData> records,
                    std::uint16_t &encoded_count, bool &truncated) noexcept {
  for (std::size_t begin = 0U; begin < records.size();) {
    std::size_t end = begin + 1U;
    while (end < records.size() && same_rrset(records[begin], records[end]))
      ++end;
    std::size_t required{};
    for (std::size_t index = begin; index < end; ++index) {
      if (!valid_record(records[index]))
        return false;
      required += encoded_owner_octets(records[index], question) + 10U +
                  records[index].rdata.size();
    }
    // Integer promotion turns uint16_t subtraction into signed int on GCC.
    // Convert the non-negative remaining count to the container size type so
    // the limit check is warning-free without weakening -Werror or changing
    // the DNS header's normative 16-bit section-count bound.
    const auto remaining_count = static_cast<std::size_t>(
        std::numeric_limits<std::uint16_t>::max() - encoded_count);
    if (required > output.size() - offset ||
        end - begin > remaining_count) {
      truncated = true;
      return true;
    }
    for (std::size_t index = begin; index < end; ++index) {
      write_record(output, offset, records[index], question);
      ++encoded_count;
    }
    begin = end;
  }
  return true;
}

} // namespace

std::optional<std::size_t>
encode_query(std::span<std::uint8_t> output, std::uint16_t id,
             const Question &question, bool recursion_desired,
             std::optional<std::uint16_t> udp_payload_size, bool dnssec_ok,
             bool authentic_data, bool checking_disabled) noexcept {
  if (question.name.octets == 0U ||
      question.name.octets > maximum_name_octets ||
      question.name.wire[question.name.octets - 1U] != 0U ||
      question.type == 0U || question.record_class == 0U ||
      (dnssec_ok && !udp_payload_size))
    return std::nullopt;
  Name validated_name;
  const auto consumed = parse_name(question.name.view(), 0U, validated_name);
  if (!consumed || *consumed != question.name.octets)
    return std::nullopt;
  const auto additional = udp_payload_size ? 1U : 0U;
  const auto required =
      header_octets + question.name.octets + 4U + (additional ? 11U : 0U);
  if (output.size() < required)
    return std::nullopt;
  std::fill_n(output.begin(), required, std::uint8_t{0});
  write_u16(output, 0U, id);
  std::uint16_t flags = recursion_desired ? 0x0100U : 0U;
  if (authentic_data)
    flags |= 0x0020U;
  if (checking_disabled)
    flags |= 0x0010U;
  write_u16(output, 2U, flags);
  write_u16(output, 4U, 1U);
  write_u16(output, 10U, static_cast<std::uint16_t>(additional));
  std::size_t offset = header_octets;
  std::copy_n(question.name.wire.begin(), question.name.octets,
              output.begin() + static_cast<std::ptrdiff_t>(offset));
  offset += question.name.octets;
  write_u16(output, offset, question.type);
  write_u16(output, offset + 2U, question.record_class);
  offset += 4U;
  if (additional) {
    output[offset++] = 0U;
    write_u16(output, offset, type_opt);
    const auto advertised = std::max<std::uint16_t>(*udp_payload_size, 512U);
    write_u16(output, offset + 2U, advertised);
    // OPT TTL carries extended RCODE, version and flags. DO is bit 15 of the
    // lower flags word; option RDLEN remains zero for this base query.
    if (dnssec_ok)
      output[offset + 6U] = 0x80U;
    offset += 10U;
  }
  return offset;
}

std::optional<std::size_t>
encode_error_response(std::span<std::uint8_t> output, std::uint16_t id,
                      std::uint8_t opcode, Rcode rcode, bool recursion_desired,
                      bool checking_disabled,
                      bool recursion_available) noexcept {
  if (output.size() < header_octets || opcode > 0x0fU)
    return std::nullopt;

  // RFC 1035 permits the question count to be zero when a format error makes
  // the question unparseable. Clearing the entire fixed header also guarantees
  // that no caller-owned stale section count is accidentally exposed.
  std::fill_n(output.begin(), header_octets, std::uint8_t{0});
  std::uint16_t flags = 0x8000U | (static_cast<std::uint16_t>(opcode) << 11U) |
                        static_cast<std::uint16_t>(rcode);
  if (recursion_desired)
    flags |= 0x0100U;
  if (recursion_available)
    flags |= 0x0080U;
  if (checking_disabled)
    flags |= 0x0010U;
  write_u16(output, 0U, id);
  write_u16(output, 2U, flags);
  return header_octets;
}

std::optional<std::size_t>
encode_response(std::span<std::uint8_t> output, std::uint16_t id,
                const Question &question, std::span<const RecordData> answers,
                std::span<const RecordData> authorities,
                std::span<const RecordData> additionals,
                const ResponseConfiguration &configuration) noexcept {
  Name validated;
  const auto question_name = parse_name(question.name.view(), 0U, validated);
  const auto question_octets = question.name.octets + 4U;
  const auto opt_octets = configuration.edns_udp_payload_size ? 11U : 0U;
  if (!question_name || *question_name != question.name.octets ||
      question.type == 0U || question.record_class == 0U ||
      output.size() < header_octets + question_octets + opt_octets)
    return std::nullopt;

  // Only the fixed prefix needs clearing. Every record octet is subsequently
  // written, so clearing a caller's entire 65,535-byte TCP buffer would add
  // work unrelated to the encoded message length.
  std::fill_n(output.begin(), header_octets + question_octets, std::uint8_t{0});
  std::size_t offset = header_octets;
  std::copy_n(question.name.wire.begin(), question.name.octets,
              output.begin() + static_cast<std::ptrdiff_t>(offset));
  offset += question.name.octets;
  write_u16(output, offset, question.type);
  write_u16(output, offset + 2U, question.record_class);
  offset += 4U;

  std::uint16_t answer_count{};
  std::uint16_t authority_count{};
  std::uint16_t additional_count{};
  bool truncated{};
  const auto record_output =
      output.first(output.size() - static_cast<std::size_t>(opt_octets));
  if (!encode_section(record_output, offset, question, answers, answer_count,
                      truncated))
    return std::nullopt;
  if (!truncated && !encode_section(record_output, offset, question,
                                    authorities, authority_count, truncated))
    return std::nullopt;
  if (!truncated && !encode_section(record_output, offset, question,
                                    additionals, additional_count, truncated))
    return std::nullopt;
  if (configuration.edns_udp_payload_size) {
    output[offset++] = 0U;
    write_u16(output, offset, type_opt);
    write_u16(
        output, offset + 2U,
        std::max<std::uint16_t>(*configuration.edns_udp_payload_size, 512U));
    output[offset + 4U] = configuration.edns_extended_rcode;
    output[offset + 5U] = configuration.edns_version;
    output[offset + 6U] = configuration.dnssec_ok ? 0x80U : 0U;
    output[offset + 7U] = 0U;
    write_u16(output, offset + 8U, 0U);
    offset += 10U;
    ++additional_count;
  }

  std::uint16_t flags = 0x8000U;
  if (configuration.authoritative)
    flags |= 0x0400U;
  if (truncated)
    flags |= 0x0200U;
  if (configuration.recursion_desired)
    flags |= 0x0100U;
  if (configuration.recursion_available)
    flags |= 0x0080U;
  if (configuration.authentic_data)
    flags |= 0x0020U;
  if (configuration.checking_disabled)
    flags |= 0x0010U;
  flags |= static_cast<std::uint16_t>(configuration.rcode);
  write_u16(output, 0U, id);
  write_u16(output, 2U, flags);
  write_u16(output, 4U, 1U);
  write_u16(output, 6U, answer_count);
  write_u16(output, 8U, authority_count);
  write_u16(output, 10U, additional_count);
  return offset;
}

} // namespace router::packet::dns
