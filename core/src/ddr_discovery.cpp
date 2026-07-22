// RFC 9462 DDR candidate selection over RFC 9460 and RFC 9461 SVCB records.
// The module accepts canonical DNS records only and delegates every connection
// attempt to the normal TLS, QUIC, UDP and TCP owners.
// Source: ietf.ddr.rfc9462
// Source: ietf.dns_svcb.rfc9461
// Source: ietf.svcb.rfc9460

#include "router/ddr_discovery.hpp"

#include "router/dns_svcb.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace router::ddr {
namespace {

using packet::dns::Name;
using packet::dns::RecordData;
namespace svcb = packet::dns::svcb;

bool valid_name(const Name &name) noexcept {
  if (name.octets == 0U || name.octets > name.wire.size())
    return false;
  Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

bool root_name(const Name &name) noexcept {
  return name.octets == 1U && name.wire[0U] == 0U;
}

std::optional<Name> prefixed_dns_name(const Name &suffix) noexcept {
  if (!valid_name(suffix) || suffix.octets + 5U > suffix.wire.size())
    return std::nullopt;
  Name result;
  result.octets = static_cast<std::uint16_t>(suffix.octets + 5U);
  result.wire[0U] = 4U;
  result.wire[1U] = '_';
  result.wire[2U] = 'd';
  result.wire[3U] = 'n';
  result.wire[4U] = 's';
  std::copy_n(suffix.wire.begin(), suffix.octets, result.wire.begin() + 5U);
  return result;
}

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool same_address_family_bytes(const Address &left,
                               const Address &right) noexcept {
  return left == right;
}

bool local_or_private(const Address &address) noexcept {
  if (address.family == AddressFamily::ipv4) {
    const auto &b = address.bytes;
    return b[0U] == 10U || b[0U] == 127U ||
           (b[0U] == 172U && (b[1U] & 0xf0U) == 16U) ||
           (b[0U] == 192U && b[1U] == 168U) ||
           (b[0U] == 169U && b[1U] == 254U);
  }
  ip::Ipv6 value{};
  std::copy_n(address.bytes.begin(), value.size(), value.begin());
  return (value[0U] & 0xfeU) == 0xfcU || ip::is_link_local(value) ||
         ip::is_loopback(value);
}

bool usable_resolver_address(const Address &address) noexcept {
  if (address.family == AddressFamily::ipv4) {
    const bool unspecified = address.bytes[0U] == 0U &&
                             address.bytes[1U] == 0U &&
                             address.bytes[2U] == 0U &&
                             address.bytes[3U] == 0U;
    return !unspecified && address.bytes[0U] < 224U;
  }
  ip::Ipv6 value{};
  std::copy_n(address.bytes.begin(), value.size(), value.begin());
  return !ip::is_unspecified(value) && !ip::is_multicast(value);
}

std::uint16_t read_u16(std::span<const std::uint8_t> value) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(value[0U]) << 8U) | value[1U]);
}

bool supported_mandatory_key(std::uint16_t key) noexcept {
  switch (key) {
  case svcb::key_alpn:
  case svcb::key_port:
  case svcb::key_ipv4hint:
  case svcb::key_ipv6hint:
  case svcb::key_dohpath:
    return true;
  default:
    return false;
  }
}

bool mandatory_compatible(const svcb::RecordView &record) noexcept {
  const auto *mandatory = svcb::find(record, svcb::key_mandatory);
  if (!mandatory)
    return true;
  for (std::size_t offset = 0U; offset < mandatory->value.size();
       offset += 2U) {
    const auto key = read_u16(mandatory->value.subspan(offset, 2U));
    if (!supported_mandatory_key(key) || !svcb::find(record, key))
      return false;
  }
  return true;
}

bool valid_utf8(std::span<const std::uint8_t> value) noexcept {
  std::size_t offset{};
  while (offset < value.size()) {
    const auto first = value[offset++];
    if (first <= 0x7fU)
      continue;
    std::size_t continuation{};
    std::uint32_t scalar{};
    if ((first & 0xe0U) == 0xc0U) {
      continuation = 1U;
      scalar = first & 0x1fU;
      if (scalar < 2U)
        return false;
    } else if ((first & 0xf0U) == 0xe0U) {
      continuation = 2U;
      scalar = first & 0x0fU;
    } else if ((first & 0xf8U) == 0xf0U) {
      continuation = 3U;
      scalar = first & 0x07U;
    } else {
      return false;
    }
    if (continuation > value.size() - offset)
      return false;
    for (std::size_t index = 0U; index < continuation; ++index) {
      const auto next = value[offset++];
      if ((next & 0xc0U) != 0x80U)
        return false;
      scalar = (scalar << 6U) | (next & 0x3fU);
    }
    if ((continuation == 2U && scalar < 0x800U) ||
        (continuation == 3U && scalar < 0x10000U) || scalar > 0x10ffffU ||
        (scalar >= 0xd800U && scalar <= 0xdfffU))
      return false;
  }
  return true;
}

bool valid_doh_template(std::span<const std::uint8_t> value) noexcept {
  if (value.empty() || value.front() != '/' || !valid_utf8(value))
    return false;
  const std::string_view text{reinterpret_cast<const char *>(value.data()),
                              value.size()};
  // RFC 9461 requires a relative URI Template containing the dns variable.
  // Reject authority and fragment forms because neither can be a valid HTTP
  // request :path after expansion.
  return !text.starts_with("//") && text.find('#') == std::string_view::npos &&
         (text.find("{?dns}") != std::string_view::npos ||
          text.find("{&dns}") != std::string_view::npos);
}

void append_parameter_addresses(const svcb::RecordView &record,
                                std::vector<Address> &output,
                                std::size_t limit) {
  const auto append = [&](const svcb::Parameter *parameter,
                          std::size_t width, AddressFamily family) {
    if (!parameter)
      return;
    for (std::size_t offset = 0U;
         offset < parameter->value.size() && output.size() < limit;
         offset += width) {
      Address address{.family = family, .bytes = {}};
      std::copy_n(parameter->value.begin() +
                      static_cast<std::ptrdiff_t>(offset),
                  width, address.bytes.begin());
      output.push_back(address);
    }
  };
  append(svcb::find(record, svcb::key_ipv4hint), 4U, AddressFamily::ipv4);
  append(svcb::find(record, svcb::key_ipv6hint), 16U, AddressFamily::ipv6);
}

void append_additional_addresses(const Name &target,
                                 std::span<const RecordData> additionals,
                                 std::vector<Address> &output,
                                 std::size_t limit) {
  for (const auto &record : additionals) {
    if (output.size() >= limit || record.record_class != packet::dns::internet_class ||
        !same_name(record.owner, target))
      continue;
    if (record.type == packet::dns::type_a && record.rdata.size() == 4U) {
      Address address{.family = AddressFamily::ipv4, .bytes = {}};
      std::copy_n(record.rdata.begin(), 4U, address.bytes.begin());
      output.push_back(address);
    } else if (record.type == packet::dns::type_aaaa &&
               record.rdata.size() == 16U) {
      Address address{.family = AddressFamily::ipv6, .bytes = {}};
      std::copy_n(record.rdata.begin(), 16U, address.bytes.begin());
      output.push_back(address);
    }
  }
}

std::uint64_t mix(std::uint64_t value) noexcept {
  value ^= value >> 30U;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27U;
  value *= 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

std::uint64_t name_hash(const Name &name) noexcept {
  std::uint64_t value = 1469598103934665603ULL;
  for (const auto byte : name.view()) {
    value ^= byte;
    value *= 1099511628211ULL;
  }
  return value;
}

} // namespace

Address Address::ipv4(const ip::Ipv4 &value) noexcept {
  Address result{.family = AddressFamily::ipv4, .bytes = {}};
  std::copy_n(value.begin(), value.size(), result.bytes.begin());
  return result;
}

Address Address::ipv6(const ip::Ipv6 &value) noexcept {
  Address result{.family = AddressFamily::ipv6, .bytes = {}};
  std::copy_n(value.begin(), value.size(), result.bytes.begin());
  return result;
}

struct Discovery::Impl {
  Configuration configuration;
  Name current_query;
  std::vector<Name> visited_aliases;
  std::vector<Endpoint> endpoints;

  Impl(Configuration value, Name query)
      : configuration(std::move(value)), current_query(query) {}
};

Discovery::Discovery(std::unique_ptr<Impl> implementation) noexcept
    : implementation_(std::move(implementation)) {}
Discovery::Discovery(Discovery &&) noexcept = default;
Discovery &Discovery::operator=(Discovery &&) noexcept = default;
Discovery::~Discovery() = default;

std::optional<Discovery>
Discovery::create(Configuration configuration) noexcept {
  if (configuration.max_alias_depth == 0U ||
      configuration.max_candidates == 0U ||
      configuration.max_addresses_per_candidate == 0U ||
      configuration.max_parameters_per_record == 0U ||
      (configuration.mode == DiscoveryMode::resolver_address &&
       !usable_resolver_address(configuration.unencrypted_resolver)) ||
      (configuration.mode == DiscoveryMode::resolver_name &&
       !valid_name(configuration.known_resolver_name)))
    return std::nullopt;
  const auto resolver_arpa = packet::dns::name_from_text("resolver.arpa.");
  std::optional<Name> query;
  if (configuration.mode == DiscoveryMode::resolver_address) {
    query = packet::dns::name_from_text("_dns.resolver.arpa.");
  } else {
    query = prefixed_dns_name(configuration.known_resolver_name);
  }
  if (!resolver_arpa || !query)
    return std::nullopt;
  try {
    return Discovery{std::make_unique<Impl>(std::move(configuration), *query)};
  } catch (...) {
    return std::nullopt;
  }
}

const Name &Discovery::query_name() const noexcept {
  return implementation_->current_query;
}

IngestResult
Discovery::ingest(std::span<const RecordData> answers,
                  std::span<const RecordData> additionals) noexcept {
  if (!implementation_)
    return IngestResult::resource_exhausted;
  try {
    std::vector<Endpoint> staged;
    staged.reserve(std::min(implementation_->configuration.max_candidates,
                            answers.size() * 4U));
    std::vector<Name> aliases;
    const auto resolver_arpa = *packet::dns::name_from_text("resolver.arpa.");

    for (const auto &answer : answers) {
      if (answer.type != packet::dns::type_svcb ||
          answer.record_class != packet::dns::internet_class ||
          !same_name(answer.owner, implementation_->current_query))
        continue;
      // Parameter capacity is a resource-profile input. The parser rejects a
      // larger record rather than interpreting only a prefix and accidentally
      // missing a mandatory or security-relevant parameter at the end.
      std::vector<svcb::Parameter> parameters(
          implementation_->configuration.max_parameters_per_record);
      const auto parsed = svcb::parse(answer.rdata, parameters);
      if (!parsed) {
        implementation_->endpoints.clear();
        return IngestResult::malformed_rrset;
      }
      if (parsed->alias_mode()) {
        if (!root_name(parsed->target))
          aliases.push_back(parsed->target);
        continue;
      }
      if (!aliases.empty())
        continue;
      Name effective_target = parsed->target;
      if (root_name(effective_target))
        effective_target = answer.owner;
      if (implementation_->configuration.mode ==
              DiscoveryMode::resolver_address &&
          (root_name(parsed->target) || same_name(effective_target, resolver_arpa)))
        continue;
      if (!mandatory_compatible(*parsed) ||
          svcb::find(*parsed, svcb::key_no_default_alpn))
        continue;
      const auto *alpn = svcb::find(*parsed, svcb::key_alpn);
      if (!alpn)
        continue;
      const auto *port_parameter = svcb::find(*parsed, svcb::key_port);
      const auto explicit_port =
          port_parameter ? std::optional<std::uint16_t>{
                               read_u16(port_parameter->value)}
                         : std::nullopt;
      const auto *path_parameter = svcb::find(*parsed, svcb::key_dohpath);
      const auto http_path_valid =
          path_parameter && valid_doh_template(path_parameter->value);
      std::vector<Address> addresses;
      append_additional_addresses(
          effective_target, additionals, addresses,
          implementation_->configuration.max_addresses_per_candidate);
      if (addresses.empty())
        append_parameter_addresses(
            *parsed, addresses,
            implementation_->configuration.max_addresses_per_candidate);

      const auto append_protocol = [&](Protocol protocol,
                                       std::uint16_t default_port) {
        if (staged.size() >= implementation_->configuration.max_candidates)
          return;
        Endpoint endpoint{.priority = parsed->priority,
                          .target = effective_target,
                          .protocol = protocol,
                          .port = explicit_port.value_or(default_port),
                          .doh_uri_template = {},
                          .addresses = addresses,
                          .usable = false};
        if (protocol == Protocol::doh2 || protocol == Protocol::doh3) {
          if (!http_path_valid)
            return;
          endpoint.doh_uri_template.assign(
              reinterpret_cast<const char *>(path_parameter->value.data()),
              path_parameter->value.size());
        }
        staged.push_back(std::move(endpoint));
      };
      if (!svcb::visit_alpn(
              alpn->value, [&](std::span<const std::uint8_t> identifier) {
                const std::string_view name{
                    reinterpret_cast<const char *>(identifier.data()),
                    identifier.size()};
                if (name == "dot")
                  append_protocol(Protocol::dot, 853U);
                else if (name == "doq")
                  append_protocol(Protocol::doq, 853U);
                else if (name == "h2")
                  append_protocol(Protocol::doh2, 443U);
                else if (name == "h3")
                  append_protocol(Protocol::doh3, 443U);
                return true;
              })) {
        implementation_->endpoints.clear();
        return IngestResult::malformed_rrset;
      }
    }

    if (!aliases.empty()) {
      if (implementation_->visited_aliases.size() >=
          implementation_->configuration.max_alias_depth)
        return IngestResult::alias_limit;
      const auto selected = static_cast<std::size_t>(
          mix(implementation_->configuration.selection_nonce ^
              implementation_->visited_aliases.size()) % aliases.size());
      const auto &target = aliases[selected];
      if (same_name(implementation_->current_query, target))
        return IngestResult::alias_limit;
      for (const auto &visited : implementation_->visited_aliases)
        if (same_name(visited, target))
          return IngestResult::alias_limit;
      implementation_->visited_aliases.push_back(
          implementation_->current_query);
      implementation_->current_query = target;
      implementation_->endpoints.clear();
      return IngestResult::alias_followup_required;
    }

    // Preserve priority ordering while using a persisted per-discovery nonce
    // as a stable tie breaker. This meets RFC 9460 load distribution without
    // a process-global random owner or nondeterministic checkpoints.
    std::stable_sort(staged.begin(), staged.end(), [&](const Endpoint &left,
                                                        const Endpoint &right) {
      if (left.priority != right.priority)
        return left.priority < right.priority;
      const auto left_key = mix(implementation_->configuration.selection_nonce ^
                                static_cast<std::uint64_t>(left.protocol) ^
                                left.port ^ name_hash(left.target));
      const auto right_key = mix(implementation_->configuration.selection_nonce ^
                                 static_cast<std::uint64_t>(right.protocol) ^
                                 right.port ^ name_hash(right.target));
      return left_key < right_key;
    });
    implementation_->endpoints = std::move(staged);
    return implementation_->endpoints.empty()
               ? IngestResult::no_designated_resolver
               : IngestResult::candidates_available;
  } catch (...) {
    implementation_->endpoints.clear();
    return IngestResult::resource_exhausted;
  }
}

ConfirmationResult
Discovery::confirm(std::size_t candidate_index,
                   const AuthenticationEvidence &evidence) noexcept {
  if (!implementation_ || candidate_index >= implementation_->endpoints.size())
    return ConfirmationResult::invalid_candidate;
  auto &endpoint = implementation_->endpoints[candidate_index];
  if (implementation_->configuration.automatic_policy ==
      AutomaticPolicy::manual_only) {
    if (!evidence.manual_approval)
      return ConfirmationResult::rejected_policy;
    endpoint.usable = true;
    return ConfirmationResult::usable;
  }
  const auto verified =
      evidence.certificate_chain_valid &&
      ((implementation_->configuration.mode ==
            DiscoveryMode::resolver_address &&
        evidence.original_resolver_ip_in_subject_alt_name) ||
       (implementation_->configuration.mode == DiscoveryMode::resolver_name &&
        evidence.known_resolver_name_in_subject_alt_name));
  if (verified) {
    endpoint.usable = true;
    return ConfirmationResult::usable;
  }
  if (implementation_->configuration.automatic_policy ==
          AutomaticPolicy::verified_or_local_opportunistic &&
      implementation_->configuration.mode ==
          DiscoveryMode::resolver_address &&
      local_or_private(implementation_->configuration.unencrypted_resolver) &&
      same_address_family_bytes(
          evidence.connected_address,
          implementation_->configuration.unencrypted_resolver)) {
    endpoint.usable = true;
    return ConfirmationResult::usable;
  }
  return ConfirmationResult::rejected_authentication;
}

std::span<const Endpoint> Discovery::candidates() const noexcept {
  return implementation_ ? std::span<const Endpoint>{implementation_->endpoints}
                         : std::span<const Endpoint>{};
}

std::uint64_t Discovery::network_identity() const noexcept {
  return implementation_ ? implementation_->configuration.network_identity
                         : 0U;
}

} // namespace router::ddr
