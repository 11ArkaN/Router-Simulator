// NSEC tests cover canonical ordering, NODATA, NXDOMAIN's two required names,
// insecure-delegation proof and the authenticated-data construction boundary.

#include "router/dnssec_denial.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>

namespace {

router::packet::dns::Name name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("NSEC fixture name is malformed");
  return *parsed;
}

router::dns::ZoneRecord nsec_record(const char *owner, const char *next,
                                    std::vector<std::uint16_t> types) {
  router::dnssec::Nsec value{.next_domain = name(next),
                             .types = std::move(types)};
  std::vector<std::uint8_t> wire;
  if (!router::dnssec::encode_nsec(value, wire))
    throw std::runtime_error("NSEC fixture encoding failed");
  return {.owner = name(owner),
          .type = router::packet::dns::type_nsec,
          .record_class = router::packet::dns::internet_class,
          .ttl = 300U,
          .rdata = std::move(wire)};
}

router::dnssec::AuthenticatedNsec authenticated(
    const router::dns::ZoneRecord &record) {
  const auto value = router::dnssec::authenticate_nsec(
      record, {.state = router::dnssec::ValidationState::secure,
               .failure = router::dnssec::ValidationFailure::none});
  if (!value)
    throw std::runtime_error("Secure NSEC fixture was not authenticated");
  return *value;
}

std::string base32hex(std::span<const std::uint8_t> input) {
  static constexpr char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  std::string output;
  output.reserve((input.size() * 8U + 4U) / 5U);
  std::uint32_t bits{};
  unsigned count{};
  for (const auto octet : input) {
    bits = (bits << 8U) | octet;
    count += 8U;
    while (count >= 5U) {
      count -= 5U;
      output.push_back(alphabet[(bits >> count) & 0x1fU]);
      bits &= count == 0U ? 0U : (1U << count) - 1U;
    }
  }
  if (count != 0U)
    output.push_back(alphabet[(bits << (5U - count)) & 0x1fU]);
  return output;
}

router::dnssec::AuthenticatedNsec3 nsec3_record(
    std::uint8_t owner_hash, std::uint8_t next_hash, std::uint8_t flags,
    std::uint16_t iterations, std::vector<std::uint16_t> types) {
  const std::array<std::uint8_t, 20U> owner_bytes = [&] {
    std::array<std::uint8_t, 20U> value{};
    value.fill(owner_hash);
    return value;
  }();
  router::dnssec::Nsec3 value{.hash_algorithm = 1U,
                              .flags = flags,
                              .iterations = iterations,
                              .salt = {},
                              .next_hashed_owner =
                                  std::vector<std::uint8_t>(20U, next_hash),
                              .types = std::move(types)};
  std::vector<std::uint8_t> wire;
  if (!router::dnssec::encode_nsec3(value, wire))
    throw std::runtime_error("NSEC3 fixture encoding failed");
  const auto owner = base32hex(owner_bytes) + ".example.";
  const router::dns::ZoneRecord record{
      .owner = name(owner.c_str()),
      .type = router::packet::dns::type_nsec3,
      .record_class = router::packet::dns::internet_class,
      .ttl = 300U,
      .rdata = std::move(wire)};
  const auto authenticated = router::dnssec::authenticate_nsec3(
      record, {.state = router::dnssec::ValidationState::secure,
               .failure = router::dnssec::ValidationFailure::none});
  if (!authenticated)
    throw std::runtime_error("Secure NSEC3 fixture was not authenticated");
  return *authenticated;
}

class NameDigest final : public router::dnssec::DigestCalculator {
public:
  bool supports_digest(std::uint8_t type) const noexcept override {
    return type == 1U;
  }
  bool calculate_digest(std::uint8_t type,
                        std::span<const std::uint8_t> input,
                        std::vector<std::uint8_t> &output) const noexcept override {
    if (type != 1U)
      return false;
    const std::array mappings{
        std::pair{name("example."), 0x20U},
        std::pair{name("child.example."), 0x40U},
        std::pair{name("missing.example."), 0x50U},
        std::pair{name("*.example."), 0x60U}};
    try {
      for (const auto &[candidate, byte] : mappings)
        if (std::ranges::equal(input, candidate.view())) {
          output.assign(20U, static_cast<std::uint8_t>(byte));
          return true;
        }
    } catch (...) {
      return false;
    }
    return false;
  }
};

} // namespace

void dnssec_denial_tests() {
  using namespace router;

  const auto root = name(".");
  const auto example = name("Example.");
  const auto child = name("a.example.");
  const auto longer_label = name("aa.example.");
  if (dnssec::canonical_name_compare(root, example) != -1 ||
      dnssec::canonical_name_compare(name("A.Example."), child) != 0 ||
      dnssec::canonical_name_compare(child, longer_label) != -1)
    throw std::runtime_error("DNSSEC canonical name ordering is wrong");

  const auto child_record = nsec_record(
      "child.example.", "next.example.",
      {packet::dns::type_ns, packet::dns::type_nsec,
       packet::dns::type_rrsig});
  const std::vector child_proof{authenticated(child_record)};
  if (!dnssec::prove_nsec_nodata(name("CHILD.example."),
                                 packet::dns::type_aaaa, child_proof) ||
      dnssec::prove_nsec_nodata(name("child.example."),
                                packet::dns::type_ns, child_proof) ||
      !dnssec::prove_nsec_no_ds(name("child.example."), child_proof))
    throw std::runtime_error("NSEC NODATA or no-DS proof is wrong");

  const auto cname_record = nsec_record(
      "alias.example.", "next.example.",
      {packet::dns::type_cname, packet::dns::type_nsec,
       packet::dns::type_rrsig});
  const std::vector cname_proof{authenticated(cname_record)};
  if (dnssec::prove_nsec_nodata(name("alias.example."),
                                packet::dns::type_aaaa, cname_proof))
    throw std::runtime_error("NSEC treated a CNAME owner as NODATA");

  // example. -> z.example. covers both a.example. and *.example. while the
  // exact owner proves example. is the closest encloser.
  const auto range_record = nsec_record(
      "example.", "z.example.",
      {packet::dns::type_soa, packet::dns::type_ns, packet::dns::type_nsec,
       packet::dns::type_rrsig});
  const std::vector range_proof{authenticated(range_record)};
  if (!dnssec::prove_nsec_name_error(name("a.example."), range_proof) ||
      dnssec::prove_nsec_name_error(name("example."), range_proof))
    throw std::runtime_error("NSEC NXDOMAIN closest-encloser proof is wrong");

  const auto wildcard_closest = nsec_record(
      "example.", "*.example.",
      {packet::dns::type_soa, packet::dns::type_ns, packet::dns::type_nsec,
       packet::dns::type_rrsig});
  const auto wildcard_owner = nsec_record(
      "*.example.", "z.example.",
      {packet::dns::type_mx, packet::dns::type_nsec,
       packet::dns::type_rrsig});
  const std::vector wildcard_proof{authenticated(wildcard_closest),
                                   authenticated(wildcard_owner)};
  if (!dnssec::prove_nsec_wildcard_nodata(
          name("missing.example."), packet::dns::type_aaaa, wildcard_proof) ||
      dnssec::prove_nsec_wildcard_nodata(
          name("missing.example."), packet::dns::type_mx, wildcard_proof) ||
      !dnssec::prove_nsec_wildcard_expansion(name("missing.example."), 1U,
                                             range_proof) ||
      dnssec::prove_nsec_wildcard_expansion(name("example."), 1U,
                                            range_proof))
    throw std::runtime_error("NSEC wildcard NODATA proof is wrong");

  if (dnssec::authenticate_nsec(
          range_record,
          {.state = dnssec::ValidationState::bogus,
           .failure = dnssec::ValidationFailure::invalid_signature}))
    throw std::runtime_error("Bogus NSEC crossed authentication boundary");

  NameDigest name_digest;
  const auto nsec3_exact = nsec3_record(
      0x40U, 0x70U, 0U, 0U,
      {packet::dns::type_ns, packet::dns::type_nsec3,
       packet::dns::type_rrsig});
  const std::vector exact_nsec3{nsec3_exact};
  if (dnssec::prove_nsec3_nodata(
          name("child.example."), packet::dns::type_aaaa, name("example."),
          exact_nsec3, {}, name_digest) != dnssec::Nsec3ProofState::proved ||
      dnssec::prove_nsec3_no_ds(name("child.example."), name("example."),
                                exact_nsec3, {}, name_digest) !=
          dnssec::Nsec3ProofState::proved)
    throw std::runtime_error("NSEC3 exact NODATA or no-DS proof is wrong");

  const auto nsec3_range = nsec3_record(
      0x20U, 0x70U, 0U, 0U,
      {packet::dns::type_soa, packet::dns::type_ns,
       packet::dns::type_nsec3, packet::dns::type_rrsig});
  const std::vector range_nsec3{nsec3_range};
  if (dnssec::prove_nsec3_name_error(
          name("missing.example."), name("example."), range_nsec3, {},
          name_digest) != dnssec::Nsec3ProofState::proved)
    throw std::runtime_error("NSEC3 closest-encloser NXDOMAIN proof is wrong");
  const std::vector delegated_closest{nsec3_record(
      0x20U, 0x70U, 0U, 0U,
      {packet::dns::type_ns, packet::dns::type_nsec3,
       packet::dns::type_rrsig})};
  if (dnssec::prove_nsec3_name_error(
          name("missing.example."), name("example."), delegated_closest, {},
          name_digest) != dnssec::Nsec3ProofState::not_proved)
    throw std::runtime_error("delegation was accepted as closest encloser");

  const auto nsec3_wildcard_closest = nsec3_record(
      0x20U, 0x60U, 0U, 0U,
      {packet::dns::type_soa, packet::dns::type_ns,
       packet::dns::type_nsec3, packet::dns::type_rrsig});
  const auto nsec3_wildcard_owner = nsec3_record(
      0x60U, 0x70U, 0U, 0U,
      {packet::dns::type_mx, packet::dns::type_nsec3,
       packet::dns::type_rrsig});
  const std::vector wildcard_nsec3{nsec3_wildcard_closest,
                                   nsec3_wildcard_owner};
  if (dnssec::prove_nsec3_wildcard_nodata(
          name("missing.example."), packet::dns::type_aaaa, name("example."),
          wildcard_nsec3, {}, name_digest) != dnssec::Nsec3ProofState::proved ||
      dnssec::prove_nsec3_wildcard_nodata(
          name("missing.example."), packet::dns::type_mx, name("example."),
          wildcard_nsec3, {}, name_digest) !=
          dnssec::Nsec3ProofState::not_proved ||
      dnssec::prove_nsec3_wildcard_expansion(
          name("missing.example."), 1U, name("example."), range_nsec3, {},
          name_digest) != dnssec::Nsec3ProofState::proved)
    throw std::runtime_error("NSEC3 wildcard NODATA proof is wrong");

  const auto nsec3_optout = nsec3_record(
      0x20U, 0x70U, 1U, 0U,
      {packet::dns::type_soa, packet::dns::type_ns,
       packet::dns::type_nsec3, packet::dns::type_rrsig});
  const std::vector optout_nsec3{nsec3_optout};
  if (dnssec::prove_nsec3_no_ds(name("child.example."), name("example."),
                                optout_nsec3, {}, name_digest) !=
      dnssec::Nsec3ProofState::proved)
    throw std::runtime_error("NSEC3 Opt-Out delegation proof is wrong");

  const auto excessive = nsec3_record(
      0x40U, 0x70U, 0U, 1U, {packet::dns::type_rrsig});
  const std::vector excessive_nsec3{excessive};
  if (dnssec::prove_nsec3_nodata(
          name("child.example."), packet::dns::type_aaaa, name("example."),
          excessive_nsec3, {}, name_digest) !=
      dnssec::Nsec3ProofState::unsupported_iterations)
    throw std::runtime_error("NSEC3 iteration policy was not enforced");
}
