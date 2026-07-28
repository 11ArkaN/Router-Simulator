// DHCPv4 structural parsing and serialization. Semantic owners consume these
// bounded views only after the complete BOOTP header, cookie and every visible
// option field have passed validation.

#include "router/dhcpv4_packet.hpp"

#include <algorithm>
#include <limits>

namespace router::packet::dhcpv4 {
namespace {

[[nodiscard]] std::uint16_t read16(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
      bytes[offset + 1U]);
}

[[nodiscard]] std::uint32_t read32(std::span<const std::uint8_t> bytes,
                                   std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
         (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
         bytes[offset + 3U];
}

void write16(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint16_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset,
             std::uint32_t value) noexcept {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
  bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] Ipv4 read_ipv4(std::span<const std::uint8_t> bytes,
                             std::size_t offset) noexcept {
  Ipv4 value{};
  std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
              value.size(), value.begin());
  return value;
}

void write_ipv4(std::span<std::uint8_t> bytes, std::size_t offset,
                const Ipv4 &value) noexcept {
  std::copy(value.begin(), value.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(offset));
}

} // namespace

std::optional<MessageView> parse(
    std::span<const std::uint8_t> bytes) noexcept {
  // BOOTP packets without the DHCP cookie are not interpreted as DHCP. This
  // prevents arbitrary bytes in the vendor area from becoming trusted TLVs.
  if (bytes.size() < options_offset ||
      !std::equal(magic_cookie.begin(), magic_cookie.end(),
                  bytes.begin() + fixed_header_octets))
    return std::nullopt;

  if (bytes[0U] != static_cast<std::uint8_t>(Operation::boot_request) &&
      bytes[0U] != static_cast<std::uint8_t>(Operation::boot_reply))
    return std::nullopt;

  // RFC 2131 permits a hardware address length up to the sixteen-octet chaddr
  // field. A longer value would make client identity parsing read into sname.
  if (bytes[2U] > 16U)
    return std::nullopt;

  MessageView result{
      .operation = static_cast<Operation>(bytes[0U]),
      .hardware_type = bytes[1U],
      .hardware_length = bytes[2U],
      .hops = bytes[3U],
      .transaction_id = read32(bytes, 4U),
      .seconds = read16(bytes, 8U),
      .flags = read16(bytes, 10U),
      .client_address = read_ipv4(bytes, 12U),
      .your_address = read_ipv4(bytes, 16U),
      .server_address = read_ipv4(bytes, 20U),
      .gateway_address = read_ipv4(bytes, 24U),
      .server_name = bytes.subspan(44U, 64U),
      .file = bytes.subspan(108U, 128U),
      .options = bytes.subspan(options_offset),
  };
  std::copy_n(bytes.begin() + 28U, result.client_hardware_address.size(),
              result.client_hardware_address.begin());

  // Validation consumes all selected option fields once. Returning a view
  // only after this pass gives every semantic caller the same atomic rejection
  // behavior for malformed options.
  RawOptionCursor cursor{result};
  while (cursor.next()) {
  }
  if (!cursor.valid())
    return std::nullopt;
  return result;
}

RawOptionCursor::RawOptionCursor(const MessageView &message) noexcept
    : message_(&message), remaining_(message.options) {}

std::optional<OptionOccurrence> RawOptionCursor::next_in_field() noexcept {
  while (!remaining_.empty()) {
    const auto code = remaining_.front();
    remaining_ = remaining_.subspan(1U);
    if (code == static_cast<std::uint8_t>(OptionCode::pad))
      continue;
    if (code == static_cast<std::uint8_t>(OptionCode::end)) {
      remaining_ = {};
      return std::nullopt;
    }
    if (remaining_.empty()) {
      valid_ = false;
      return std::nullopt;
    }
    const auto length = remaining_.front();
    remaining_ = remaining_.subspan(1U);
    if (remaining_.size() < length) {
      valid_ = false;
      return std::nullopt;
    }
    const auto data = remaining_.first(length);
    remaining_ = remaining_.subspan(length);

    if (field_ == OptionField::options &&
        code == static_cast<std::uint8_t>(OptionCode::option_overload)) {
      // RFC 2132 defines one one-octet overload declaration. Treating two
      // declarations as a union would hide an ambiguous parsing boundary.
      if (overload_seen_ || data.size() != 1U || data.front() < 1U ||
          data.front() > 3U) {
        valid_ = false;
        return std::nullopt;
      }
      overload_seen_ = true;
      overload_ = data.front();
    }
    return OptionOccurrence{.code = code, .field = field_, .data = data};
  }
  return std::nullopt;
}

bool RawOptionCursor::advance_field() noexcept {
  if (field_ == OptionField::options) {
    // RFC 2132 section 9.3 orders the overloaded file field before sname when
    // both bits are present. This is also the RFC 3396 concatenation order.
    if ((overload_ & 1U) != 0U) {
      field_ = OptionField::file;
      remaining_ = message_->file;
      return true;
    }
    if ((overload_ & 2U) != 0U) {
      field_ = OptionField::server_name;
      remaining_ = message_->server_name;
      return true;
    }
    return false;
  }
  if (field_ == OptionField::file && (overload_ & 2U) != 0U) {
    field_ = OptionField::server_name;
    remaining_ = message_->server_name;
    return true;
  }
  return false;
}

std::optional<OptionOccurrence> RawOptionCursor::next() noexcept {
  if (!valid_)
    return std::nullopt;
  while (true) {
    if (const auto value = next_in_field())
      return value;
    if (!valid_ || !advance_field())
      return std::nullopt;
  }
}

std::optional<NormalizedOption>
normalize_option(const MessageView &message, std::uint8_t code,
                 std::span<std::uint8_t> output) noexcept {
  if (code == static_cast<std::uint8_t>(OptionCode::pad) ||
      code == static_cast<std::uint8_t>(OptionCode::end))
    return std::nullopt;

  std::size_t octets = 0U;
  std::size_t occurrences = 0U;
  RawOptionCursor cursor{message};
  while (const auto option = cursor.next()) {
    if (option->code != code)
      continue;
    if (output.size() - octets < option->data.size())
      return std::nullopt;
    std::copy(option->data.begin(), option->data.end(),
              output.begin() + static_cast<std::ptrdiff_t>(octets));
    octets += option->data.size();
    ++occurrences;
  }
  if (!cursor.valid())
    return std::nullopt;
  return NormalizedOption{.octets = octets, .occurrences = occurrences};
}

std::optional<MessageType>
message_type(const MessageView &message) noexcept {
  std::array<std::uint8_t, 1U> data{};
  const auto normalized = normalize_option(
      message, static_cast<std::uint8_t>(OptionCode::message_type), data);
  if (!normalized || normalized->occurrences != 1U ||
      normalized->octets != 1U || data.front() < 1U || data.front() > 18U)
    return std::nullopt;
  return static_cast<MessageType>(data.front());
}

std::optional<Writer>
begin(std::span<std::uint8_t> output, const MessageView &header) noexcept {
  if (output.size() < options_offset || header.hardware_length > 16U)
    return std::nullopt;

  output[0U] = static_cast<std::uint8_t>(header.operation);
  output[1U] = header.hardware_type;
  output[2U] = header.hardware_length;
  output[3U] = header.hops;
  write32(output, 4U, header.transaction_id);
  write16(output, 8U, header.seconds);
  write16(output, 10U, header.flags);
  write_ipv4(output, 12U, header.client_address);
  write_ipv4(output, 16U, header.your_address);
  write_ipv4(output, 20U, header.server_address);
  write_ipv4(output, 24U, header.gateway_address);
  std::copy(header.client_hardware_address.begin(),
            header.client_hardware_address.end(), output.begin() + 28U);
  if ((!header.server_name.empty() && header.server_name.size() != 64U) ||
      (!header.file.empty() && header.file.size() != 128U))
    return std::nullopt;
  if (header.server_name.empty())
    std::fill(output.begin() + 44U, output.begin() + 108U, 0U);
  else
    std::copy(header.server_name.begin(), header.server_name.end(),
              output.begin() + 44U);
  if (header.file.empty())
    std::fill(output.begin() + 108U, output.begin() + 236U, 0U);
  else
    std::copy(header.file.begin(), header.file.end(), output.begin() + 108U);
  std::copy(magic_cookie.begin(), magic_cookie.end(),
            output.begin() + fixed_header_octets);
  return Writer{output, options_offset};
}

bool Writer::append(std::uint8_t code,
                    std::span<const std::uint8_t> data) noexcept {
  if (finished_ || code == static_cast<std::uint8_t>(OptionCode::pad) ||
      code == static_cast<std::uint8_t>(OptionCode::end) ||
      data.size() > std::numeric_limits<std::uint8_t>::max() ||
      output_.size() - position_ < 2U ||
      output_.size() - position_ - 2U < data.size())
    return false;
  output_[position_++] = code;
  output_[position_++] = static_cast<std::uint8_t>(data.size());
  std::copy(data.begin(), data.end(),
            output_.begin() + static_cast<std::ptrdiff_t>(position_));
  position_ += data.size();
  return true;
}

bool Writer::finish() noexcept {
  if (finished_ || position_ == output_.size())
    return false;
  output_[position_++] = static_cast<std::uint8_t>(OptionCode::end);
  finished_ = true;
  return true;
}

} // namespace router::packet::dhcpv4
