// Private OSPF process helpers shared only by InstanceProcess implementation
// units. InstanceProcess owns protocol state; dependencies remain in primitives.

#pragma once

#include "router/ospf_process.hpp"
#include "router/interface_identity.hpp"
#include "router/ospf_authentication.hpp"

#include <algorithm>
#include <new>
#include <openssl/crypto.h>

namespace router::ospf {

namespace {

[[maybe_unused, nodiscard]] bool external_advertisement(
    CoordinatorAdvertisementKind kind) noexcept {
  return kind == CoordinatorAdvertisementKind::translated_external ||
         kind == CoordinatorAdvertisementKind::nssa_external;
}

[[maybe_unused]] void write16(std::span<std::uint8_t> output,
                              std::size_t offset,
                              std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

[[maybe_unused]] void write32(std::span<std::uint8_t> output,
                              std::size_t offset,
                              std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

[[maybe_unused]] void
write_lsa_header(std::span<std::uint8_t> output,
                 const packet::ospf::LsaHeaderView &header,
                 std::uint8_t version) noexcept {
  // DD and LSAck use the same twenty-octet header representation. Keeping one
  // writer prevents version 3's two-octet LS Type from drifting from version
  // 2's Options and one-octet type layout.
  write16(output, 0U, header.age_seconds);
  if (version == packet::ospf::version_two) {
    output[2U] = static_cast<std::uint8_t>(header.options);
    output[3U] = static_cast<std::uint8_t>(header.type);
  } else {
    write16(output, 2U, header.type);
  }
  write32(output, 4U, header.link_state_id);
  write32(output, 8U, header.advertising_router);
  write32(output, 12U,
          static_cast<std::uint32_t>(header.sequence_number));
  write16(output, 16U, header.checksum);
  write16(output, 18U, header.length);
}

[[maybe_unused]] bool
constant_time_equal(std::span<const std::uint8_t> left,
                    std::span<const std::uint8_t> right) noexcept {
  if (left.size() != right.size())
    return false;
  std::uint8_t difference{};
  for (std::size_t index{}; index < left.size(); ++index)
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  return difference == 0U;
}

[[maybe_unused, nodiscard]] std::int64_t wall_clock_seconds() noexcept {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

[[maybe_unused, nodiscard]] bool receive_key_valid(
    const ProcessAuthentication &candidate,
    std::span<const ProcessAuthentication> all,
    std::int64_t now) noexcept {
  if (!candidate.timed)
    return true;
  const auto tolerance =
      static_cast<std::int64_t>(candidate.tolerance_seconds);
  const auto earliest =
      candidate.begin_utc_seconds <
              std::numeric_limits<std::int64_t>::min() + tolerance
          ? std::numeric_limits<std::int64_t>::min()
          : candidate.begin_utc_seconds - tolerance;
  if (now < earliest)
    return false;

  // SR OS receive tolerance for a retiring entry is measured from the next
  // entry's begin-time. OSPF retains the last valid entry indefinitely, so no
  // locally configured end-time can create an unauthenticated fallback.
  std::optional<std::int64_t> next_begin;
  for (const auto &entry : all) {
    if (!entry.timed ||
        entry.begin_utc_seconds <= candidate.begin_utc_seconds)
      continue;
    if (!next_begin || entry.begin_utc_seconds < *next_begin)
      next_begin = entry.begin_utc_seconds;
  }
  if (!next_begin)
    return true;
  const auto latest =
      *next_begin > std::numeric_limits<std::int64_t>::max() - tolerance
          ? std::numeric_limits<std::int64_t>::max()
          : *next_begin + tolerance;
  return now <= latest;
}

} // namespace

} // namespace router::ospf
