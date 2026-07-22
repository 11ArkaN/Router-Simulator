// DDR tests cover resolver-scoped discovery, SVCB compatibility, IPv6
// additional addresses, authentication binding and explicitly permitted local
// opportunistic use. No test bypasses the policy owner by marking a candidate
// usable directly.

#include "router/ddr_discovery.hpp"
#include "router/dns_svcb.hpp"

#include <array>
#include <stdexcept>
#include <vector>

namespace {

void append_u16(std::vector<std::uint8_t> &output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
  output.push_back(static_cast<std::uint8_t>(value));
}

void append_parameter(std::vector<std::uint8_t> &output, std::uint16_t key,
                      std::span<const std::uint8_t> value) {
  append_u16(output, key);
  append_u16(output, static_cast<std::uint16_t>(value.size()));
  output.insert(output.end(), value.begin(), value.end());
}

std::vector<std::uint8_t>
service_rdata(const router::packet::dns::Name &target,
              bool unknown_mandatory = false) {
  using namespace router::packet::dns;
  namespace svcb = router::packet::dns::svcb;
  std::vector<std::uint8_t> result;
  append_u16(result, 1U);
  result.insert(result.end(), target.view().begin(), target.view().end());
  const std::array<std::uint8_t, 4U> required{
      0x00U, 0x01U, 0x00U,
      static_cast<std::uint8_t>(unknown_mandatory ? 99U : 7U)};
  append_parameter(result, svcb::key_mandatory, required);
  const std::array<std::uint8_t, 6U> alpns{0x02U, 'h', '2',
                                           0x02U, 'h', '3'};
  append_parameter(result, svcb::key_alpn, alpns);
  const std::array<std::uint8_t, 16U> path{
      '/', 'd', 'n', 's', '-', 'q', 'u', 'e',
      'r', 'y', '{', '?', 'd', 'n', 's', '}'};
  append_parameter(result, svcb::key_dohpath, path);
  return result;
}

} // namespace

void ddr_discovery_tests() {
  using namespace router;
  using namespace router::packet::dns;

  const auto owner = name_from_text("_dns.resolver.arpa.");
  const auto target = name_from_text("resolver.example.");
  const auto source_ipv6 = ip::parse_ipv6("fd00::53");
  const auto endpoint_ipv6 = ip::parse_ipv6("fd00::853");
  if (!owner || !target || !source_ipv6 || !endpoint_ipv6)
    throw std::runtime_error("DDR test fixture addresses are invalid");

  auto rdata = service_rdata(*target);
  std::array<std::uint8_t, 16U> endpoint_bytes = *endpoint_ipv6;
  const RecordData answer{.owner = *owner,
                          .type = type_svcb,
                          .record_class = internet_class,
                          .ttl = 7200U,
                          .rdata = rdata};
  const RecordData additional{.owner = *target,
                              .type = type_aaaa,
                              .record_class = internet_class,
                              .ttl = 300U,
                              .rdata = endpoint_bytes};
  auto discovery = ddr::Discovery::create(
      {.mode = ddr::DiscoveryMode::resolver_address,
       .unencrypted_resolver = ddr::Address::ipv6(*source_ipv6),
       .known_resolver_name = {},
       .network_identity = 91U,
       .automatic_policy =
           ddr::AutomaticPolicy::verified_or_local_opportunistic,
       .selection_nonce = 0x123456789abcdef0ULL,
       .max_alias_depth = 8U,
       .max_candidates = 16U,
       .max_addresses_per_candidate = 8U,
       .max_parameters_per_record = 16U});
  if (!discovery || !equal_case_insensitive(discovery->query_name(), *owner))
    throw std::runtime_error("DDR resolver-address query name is wrong");

  if (discovery->ingest(std::span<const RecordData>{&answer, 1U},
                        std::span<const RecordData>{&additional, 1U}) !=
          ddr::IngestResult::candidates_available ||
      discovery->candidates().size() != 2U)
    throw std::runtime_error("DDR did not create h2 and h3 candidates");
  for (const auto &candidate : discovery->candidates()) {
    if (candidate.port != 443U ||
        candidate.doh_uri_template != "/dns-query{?dns}" ||
        candidate.addresses.size() != 1U ||
        candidate.addresses.front() != ddr::Address::ipv6(*endpoint_ipv6))
      throw std::runtime_error("DDR candidate lost SVCB endpoint data");
  }

  // Verified Discovery binds the certificate to the original unencrypted
  // resolver IP, not the attacker-controlled SVCB TargetName.
  if (discovery->confirm(
          0U, {.certificate_chain_valid = true,
               .original_resolver_ip_in_subject_alt_name = true,
               .known_resolver_name_in_subject_alt_name = false,
               .connected_address = ddr::Address::ipv6(*endpoint_ipv6),
               .manual_approval = false}) !=
          ddr::ConfirmationResult::usable ||
      !discovery->candidates()[0U].usable)
    throw std::runtime_error("DDR rejected valid IP-bound authentication");

  // Opportunistic Discovery is permitted only for a private or local source
  // and only when the encrypted connection uses that same source address.
  if (discovery->confirm(
          1U, {.certificate_chain_valid = false,
               .original_resolver_ip_in_subject_alt_name = false,
               .known_resolver_name_in_subject_alt_name = false,
               .connected_address = ddr::Address::ipv6(*source_ipv6),
               .manual_approval = false}) !=
          ddr::ConfirmationResult::usable ||
      !discovery->candidates()[1U].usable)
    throw std::runtime_error("DDR local opportunistic policy was not applied");

  auto incompatible_rdata = service_rdata(*target, true);
  const RecordData incompatible{.owner = *owner,
                                .type = type_svcb,
                                .record_class = internet_class,
                                .ttl = 7200U,
                                .rdata = incompatible_rdata};
  if (discovery->ingest(std::span<const RecordData>{&incompatible, 1U}, {}) !=
          ddr::IngestResult::no_designated_resolver ||
      !discovery->candidates().empty())
    throw std::runtime_error("DDR used an unknown mandatory SVCB parameter");

  auto malformed_rdata = service_rdata(*target);
  // The dohpath key follows ALPN. Replacing its key with ALPN creates a
  // duplicate and proves malformed RRsets are rejected transactionally.
  const auto key_offset = malformed_rdata.size() - 20U;
  malformed_rdata[key_offset] = 0U;
  malformed_rdata[key_offset + 1U] = 1U;
  const RecordData malformed{.owner = *owner,
                             .type = type_svcb,
                             .record_class = internet_class,
                             .ttl = 7200U,
                             .rdata = malformed_rdata};
  if (discovery->ingest(std::span<const RecordData>{&malformed, 1U}, {}) !=
      ddr::IngestResult::malformed_rrset)
    throw std::runtime_error("DDR accepted a malformed SVCB RRset");
}
