// RFC 1035 master-file import and RFC 3597 transparent export. Parsing builds
// detached ZoneRecord storage; the caller publishes it through Zone::replace
// only after this complete operation succeeds.

#pragma once

#include "router/dns_authoritative.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace router::dns {

enum class MasterFileErrorCode : std::uint8_t {
  none,
  malformed_token,
  unterminated_quote,
  unmatched_parenthesis,
  missing_origin,
  missing_owner,
  missing_ttl,
  unsupported_directive,
  invalid_owner,
  invalid_class,
  invalid_type,
  invalid_ttl,
  invalid_rdata,
  include_unavailable,
  include_cycle,
  resource_exhausted
};

struct MasterFileError {
  MasterFileErrorCode code{MasterFileErrorCode::none};
  // Included-file diagnostics name the resolver's canonical source. The root
  // may remain empty when the caller imported an anonymous text buffer.
  std::string source;
  std::size_t line{};
  std::size_t token{};
};

struct MasterFileResult {
  std::vector<ZoneRecord> records;
  MasterFileError error{};

  [[nodiscard]] explicit operator bool() const noexcept {
    return error.code == MasterFileErrorCode::none;
  }
};

struct MasterFileInclude {
  // canonical_name is an owner-defined stable identity used only to detect an
  // active include cycle. contents is detached from browser or filesystem
  // storage before the protocol parser sees it.
  std::string canonical_name;
  std::string contents;
};

// The project or CLI import owner resolves names. Passing the referring source
// lets that owner implement relative paths without granting the core ambient
// filesystem access. nullopt means that the requested source does not exist or
// cannot be read. The callback may allocate because master-file import is a
// control-plane transaction, never packet-path work.
using MasterFileIncludeResolver =
    std::function<std::optional<MasterFileInclude>(
        std::string_view referring_source, std::string_view requested_source)>;

// Preconditions: initial_origin, when present, is an uncompressed DNS wire
// name. Postcondition: success returns every parsed record in detached storage;
// failure returns no records, so a caller can never publish a partial zone.
// The operation owns all returned bytes and has no shard affinity.
//
// $INCLUDE is accepted only when include_resolver is supplied. source_identity
// names the root input to that resolver and participates in cycle detection.
// An empty identity is valid for a detached root but an included result must
// return a nonempty canonical identity so aliases cannot evade cycle checks.
[[nodiscard]] MasterFileResult import_master_file(
    std::string_view text,
    std::optional<packet::dns::Name> initial_origin = std::nullopt,
    std::optional<std::uint32_t> initial_ttl = std::nullopt,
    const MasterFileIncludeResolver *include_resolver = nullptr,
    std::string_view source_identity = {}) noexcept;

// Preconditions: origin and every record owner are complete, uncompressed DNS
// names; every RDATA value fits the DNS RDLENGTH field. The returned string is
// caller-owned and independent of the zone. nullopt means validation or memory
// allocation failed and no partial file is exposed.
//
// Export uses the generic RFC 3597 RDATA representation for every type. It is
// standards-compliant, exactly preserves unknown bytes and round-trips through
// import without type-specific presentation ambiguities.
[[nodiscard]] std::optional<std::string>
export_master_file(const packet::dns::Name &origin,
                   std::span<const ZoneRecord> records) noexcept;

} // namespace router::dns
