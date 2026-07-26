// RFC 9460 SVCB wire validation. Scheme-specific requirements such as the
// DNS mapping's mandatory ALPN and dohpath relationship belong to the caller.
// Source: ietf.svcb.rfc9460

#include "router/dns_svcb.hpp"

#include <limits>

namespace router::packet::dns::svcb {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

bool valid_mandatory(std::span<const std::uint8_t> value) noexcept {
  if (value.empty() || value.size() % 2U != 0U)
    return false;
  std::uint16_t previous{};
  bool first{true};
  for (std::size_t offset = 0U; offset < value.size(); offset += 2U) {
    const auto key = read_u16(value, offset);
    if (key == key_mandatory || (!first && key <= previous))
      return false;
    first = false;
    previous = key;
  }
  return true;
}

bool valid_alpn(std::span<const std::uint8_t> value) noexcept {
  return visit_alpn(value, [](std::span<const std::uint8_t>) { return true; });
}

bool valid_known_value(std::uint16_t key,
                       std::span<const std::uint8_t> value) noexcept {
  switch (key) {
  case key_mandatory:
    return valid_mandatory(value);
  case key_alpn:
    return valid_alpn(value);
  case key_no_default_alpn:
    return value.empty();
  case key_port:
    return value.size() == 2U;
  case key_ipv4hint:
    return !value.empty() && value.size() % 4U == 0U;
  case key_ipv6hint:
    return !value.empty() && value.size() % 16U == 0U;
  default:
    // Unknown keys and ECH are opaque at this layer. Their registering
    // protocol, not the base SVCB decoder, owns semantic validation.
    return true;
  }
}

} // namespace

std::optional<RecordView>
parse(std::span<const std::uint8_t> rdata,
      std::span<Parameter> parameter_storage) noexcept {
  if (rdata.size() < 3U)
    return std::nullopt;
  Name target;
  const auto name_octets = parse_uncompressed_name(rdata.subspan(2U), target);
  if (!name_octets)
    return std::nullopt;
  std::size_t offset = 2U + *name_octets;
  std::size_t count{};
  std::uint16_t previous{};
  bool first{true};
  while (offset < rdata.size()) {
    if (rdata.size() - offset < 4U || count >= parameter_storage.size())
      return std::nullopt;
    const auto key = read_u16(rdata, offset);
    const auto length = static_cast<std::size_t>(read_u16(rdata, offset + 2U));
    offset += 4U;
    if ((!first && key <= previous) || length > rdata.size() - offset)
      return std::nullopt;
    const auto value = rdata.subspan(offset, length);
    if (!valid_known_value(key, value))
      return std::nullopt;
    parameter_storage[count++] = {.key = key, .value = value};
    first = false;
    previous = key;
    offset += length;
  }
  return RecordView{.priority = read_u16(rdata, 0U),
                    .target = target,
                    .parameters = parameter_storage.first(count)};
}

const Parameter *find(const RecordView &record, std::uint16_t key) noexcept {
  for (const auto &parameter : record.parameters) {
    if (parameter.key == key)
      return &parameter;
    if (parameter.key > key)
      break;
  }
  return nullptr;
}

} // namespace router::packet::dns::svcb
