// Iterative resolver tests exchange complete DNS messages through prepared
// actions. The fixture models root, TLD and authoritative hops without direct
// access to another zone or topology object.

#include "router/dns_resolver.hpp"
#include "router/dnssec_record.hpp"

#include <array>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace {

router::packet::dns::Name resolver_name(const char *text) {
  const auto value = router::packet::dns::name_from_text(text);
  if (!value)
    throw std::runtime_error("resolver fixture name is invalid");
  return *value;
}

std::vector<std::uint8_t> resolver_name_data(const char *text) {
  const auto value = resolver_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

std::vector<std::uint8_t> response(
    const router::dns::PreparedQuery &query,
    std::span<const router::packet::dns::RecordData> answers,
    std::span<const router::packet::dns::RecordData> authorities,
    std::span<const router::packet::dns::RecordData> additionals,
    bool authoritative = false) {
  std::vector<std::uint8_t> bytes(2048U);
  const auto octets = router::packet::dns::encode_response(
      bytes, query.id, query.question, answers, authorities, additionals,
      {.authoritative = authoritative,
       .edns_udp_payload_size = std::nullopt,
       .edns_extended_rcode = 0U,
       .edns_version = 0U,
       .dnssec_ok = false});
  if (!octets)
    throw std::runtime_error("resolver fixture response did not encode");
  bytes.resize(*octets);
  return bytes;
}

class ResolverAcceptingCrypto final : public router::dnssec::CryptoVerifier {
public:
  bool supports(std::uint8_t algorithm) const noexcept override {
    return algorithm == 13U;
  }

  bool verify(std::uint8_t algorithm,
              std::span<const std::uint8_t> public_key,
              std::span<const std::uint8_t> signed_data,
              std::span<const std::uint8_t> signature) const noexcept override {
    // Canonical RRset construction is still exercised before this narrow test
    // provider is called. A fixed signature isolates resolver state-machine
    // failures from OpenSSL, whose real algorithms have independent vectors.
    return algorithm == 13U && !public_key.empty() && !signed_data.empty() &&
           signature.size() == 2U && signature[0] == 0xaaU &&
           signature[1] == 0x55U;
  }
};

class ResolverDeterministicDigests final
    : public router::dnssec::DigestCalculator {
public:
  bool supports_digest(std::uint8_t digest_type) const noexcept override {
    return digest_type == 2U;
  }

  bool calculate_digest(std::uint8_t digest_type,
                        std::span<const std::uint8_t> input,
                        std::vector<std::uint8_t> &output) const noexcept override {
    if (digest_type != 2U || input.empty())
      return false;
    try {
      output = {0xd5U, static_cast<std::uint8_t>(input.size() & 0xffU)};
      return true;
    } catch (...) {
      return false;
    }
  }
};

std::uint32_t resolver_wall_clock(void *context) noexcept {
  return *static_cast<const std::uint32_t *>(context);
}

router::dns::ZoneRecord dnskey_record(const char *owner_text,
                                      std::uint8_t key_octet) {
  router::dnssec::Dnskey key{
      .flags = static_cast<std::uint16_t>(
          router::dnssec::dnskey_zone_flag |
          router::dnssec::dnskey_secure_entry_point_flag),
      .protocol = router::dnssec::dnskey_protocol,
      .algorithm = 13U,
      .public_key = {key_octet, static_cast<std::uint8_t>(key_octet + 1U)}};
  std::vector<std::uint8_t> wire;
  if (!router::dnssec::encode_dnskey(key, wire))
    throw std::runtime_error("resolver DNSKEY fixture did not encode");
  return {.owner = resolver_name(owner_text),
          .type = router::packet::dns::type_dnskey,
          .record_class = router::packet::dns::internet_class,
          .ttl = 3600U,
          .rdata = std::move(wire)};
}

router::dns::ZoneRecord signature_record(
    const char *owner_text, std::uint16_t covered_type, std::uint8_t labels,
    const char *signer_text, const router::dns::ZoneRecord &key) {
  router::dnssec::Rrsig signature{
      .type_covered = covered_type,
      .algorithm = 13U,
      .labels = labels,
      .original_ttl = 3600U,
      .signature_expiration = 2000U,
      .signature_inception = 1000U,
      .key_tag = router::dnssec::key_tag(key.rdata),
      .signer_name = resolver_name(signer_text),
      .signature = {0xaaU, 0x55U}};
  std::vector<std::uint8_t> wire;
  if (!router::dnssec::encode_rrsig(signature, wire))
    throw std::runtime_error("resolver RRSIG fixture did not encode");
  return {.owner = resolver_name(owner_text),
          .type = router::packet::dns::type_rrsig,
          .record_class = router::packet::dns::internet_class,
          .ttl = 3600U,
          .rdata = std::move(wire)};
}

router::packet::dns::RecordData record_view(
    const router::dns::ZoneRecord &record) noexcept {
  return {.owner = record.owner,
          .type = record.type,
          .record_class = record.record_class,
          .ttl = record.ttl,
          .rdata = record.rdata};
}

router::dns::PreparedQuery prepare_and_commit(
    router::dns::IterativeResolver &resolver,
    router::dns::TransactionHandle handle,
    router::dns::IterativeResolver::Clock::time_point now) {
  std::array<std::uint8_t, 2048U> bytes{};
  const auto prepared = resolver.prepare(handle, bytes, now);
  if (prepared.status != router::dns::PrepareQueryStatus::prepared)
    throw std::runtime_error("resolver did not admit a prepared query");

  // RFC 6840 section 5.9 requires a validating resolver to set CD on every
  // upstream query so an upstream validator cannot suppress bogus data that
  // this resolver must evaluate itself. DO requests the DNSSEC records needed
  // for that evaluation, while AD advertises that the requester understands
  // authenticated-data semantics. Check the emitted wire message here rather
  // than trusting fields in PreparedQuery, because only the bytes cross the
  // transport boundary.
  std::array<router::packet::dns::Question, 1U> questions{};
  std::array<router::packet::dns::ResourceRecord, 1U> additionals{};
  const auto message = router::packet::dns::parse(
      std::span<const std::uint8_t>{bytes}.first(prepared.query.message_octets),
      {.questions = questions,
       .answers = {},
       .authorities = {},
       .additionals = additionals});
  if (!message || !message->header.authentic_data ||
      !message->header.checking_disabled || message->additionals.size() != 1U ||
      message->additionals.front().type != router::packet::dns::type_opt ||
      (message->additionals.front().ttl & 0x8000U) == 0U)
    throw std::runtime_error("resolver upstream DNSSEC flags are wrong");

  if (!resolver.commit(handle, prepared.query, now))
    throw std::runtime_error("resolver did not commit a prepared query");
  return prepared.query;
}

} // namespace

void dns_resolver_tests() {
  using namespace std::chrono_literals;
  using namespace router;
  using namespace router::packet::dns;

  crypto::Sha256Digest secret{};
  secret[0] = 0x42U;
  dns::ServerAddress root_address{.family = transport::IpFamily::ipv6,
                                  .ipv6 = {0x20U, 0x01U, 0x0dU, 0xb8U,
                                           0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                           0U, 0U, 0U, 0U, 0x53U}};
  dns::IterativeResolver resolver{
      secret,
      {{.server_name = resolver_name("a.root.test."),
        .addresses = {root_address}}}};
  const auto epoch = dns::IterativeResolver::Clock::time_point{10s};
  const Question original{.name = resolver_name("www.example.test."),
                          .type = type_a,
                          .record_class = internet_class};
  const auto handle = resolver.begin(original, epoch);
  if (!handle)
    throw std::runtime_error("iterative resolver transaction did not start");

  const auto root_query = prepare_and_commit(resolver, *handle, epoch);
  if (!equal_case_insensitive(root_query.question.name,
                              resolver_name("test.")) ||
      root_query.question.type != type_a ||
      root_query.transport != dns::QueryTransport::udp)
    throw std::runtime_error("QNAME minimisation exposed too many labels");

  const auto test_ns = resolver_name_data("ns.test.");
  const std::array<std::uint8_t, 4U> test_glue{192U, 0U, 2U, 53U};
  const std::array<RecordData, 1U> root_authority{
      RecordData{.owner = resolver_name("test."),
                 .type = type_ns,
                 .record_class = internet_class,
                 .ttl = 3600U,
                 .rdata = test_ns}};
  const std::array<RecordData, 1U> root_additional{
      RecordData{.owner = resolver_name("ns.test."),
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 3600U,
                 .rdata = test_glue}};
  const auto root_reply =
      response(root_query, {}, root_authority, root_additional);
  if (resolver.receive(*handle, root_address, dns::QueryTransport::udp,
                       root_reply, epoch + 1ms) !=
      dns::ResponseStatus::accepted)
    throw std::runtime_error("root referral was not accepted");

  const dns::ServerAddress tld_address{.family = transport::IpFamily::ipv4,
                                      .ipv4 = test_glue};
  const auto tld_query = prepare_and_commit(resolver, *handle, epoch + 2ms);
  if (tld_query.server != tld_address ||
      !equal_case_insensitive(tld_query.question.name,
                              resolver_name("example.test.")))
    throw std::runtime_error("resolver did not follow root glue");

  const auto authoritative_ns = resolver_name_data("nameserver.");
  const std::array<std::uint8_t, 16U> authoritative_glue{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U, 0U, 0U, 0U, 0U, 0U, 0x53U, 0x53U};
  const std::array<RecordData, 1U> tld_authority{
      RecordData{.owner = resolver_name("example.test."),
                 .type = type_ns,
                 .record_class = internet_class,
                 .ttl = 1800U,
                 .rdata = authoritative_ns}};
  const auto tld_reply = response(tld_query, {}, tld_authority, {});
  if (resolver.receive(*handle, tld_address, dns::QueryTransport::udp,
                       tld_reply, epoch + 3ms) !=
      dns::ResponseStatus::accepted)
    throw std::runtime_error("TLD referral was not accepted");

  // The NS target is out of bailiwick, so the referral intentionally carries
  // no usable glue. The resolver performs ordinary AAAA and A subqueries from
  // root hints instead of trusting unrelated additional data.
  const auto ns_aaaa_query =
      prepare_and_commit(resolver, *handle, epoch + 4ms);
  if (ns_aaaa_query.server != root_address ||
      ns_aaaa_query.question.type != type_aaaa ||
      !equal_case_insensitive(ns_aaaa_query.question.name,
                              resolver_name("nameserver.")))
    throw std::runtime_error("out-of-bailiwick NS AAAA lookup was not started");
  const std::array<RecordData, 1U> ns_aaaa_answer{
      RecordData{.owner = resolver_name("nameserver."),
                 .type = type_aaaa,
                 .record_class = internet_class,
                 .ttl = 1800U,
                 .rdata = authoritative_glue}};
  const auto ns_aaaa_reply =
      response(ns_aaaa_query, ns_aaaa_answer, {}, {}, true);
  if (resolver.receive(*handle, root_address, dns::QueryTransport::udp,
                       ns_aaaa_reply, epoch + 5ms) !=
      dns::ResponseStatus::accepted)
    throw std::runtime_error("NS AAAA address subquery did not complete");

  const auto ns_a_query = prepare_and_commit(resolver, *handle, epoch + 6ms);
  if (ns_a_query.question.type != type_a ||
      !equal_case_insensitive(ns_a_query.question.name,
                              resolver_name("nameserver.")))
    throw std::runtime_error("out-of-bailiwick NS A lookup was not started");
  const std::array<std::uint8_t, 4U> authoritative_ipv4{203U, 0U, 113U, 53U};
  const std::array<RecordData, 1U> ns_a_answer{
      RecordData{.owner = resolver_name("nameserver."),
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 1800U,
                 .rdata = authoritative_ipv4}};
  const auto ns_a_reply = response(ns_a_query, ns_a_answer, {}, {}, true);
  if (resolver.receive(*handle, root_address, dns::QueryTransport::udp,
                       ns_a_reply, epoch + 7ms) !=
      dns::ResponseStatus::accepted)
    throw std::runtime_error("NS A address subquery did not complete");

  const dns::ServerAddress authoritative_address{
      .family = transport::IpFamily::ipv6, .ipv6 = authoritative_glue};
  const auto final_query = prepare_and_commit(resolver, *handle, epoch + 8ms);
  if (final_query.server != authoritative_address ||
      !equal_case_insensitive(final_query.question.name, original.name) ||
      final_query.question.type != original.type)
    throw std::runtime_error("resolver did not issue the original final query");

  const std::array<std::uint8_t, 4U> final_address{198U, 51U, 100U, 80U};
  const std::array<RecordData, 1U> final_answers{
      RecordData{.owner = original.name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 300U,
                 .rdata = final_address}};
  const auto final_reply = response(final_query, final_answers, {}, {}, true);
  if (resolver.receive(*handle, authoritative_address,
                       dns::QueryTransport::udp, final_reply,
                       epoch + 9ms) != dns::ResponseStatus::complete)
    throw std::runtime_error("authoritative DNS answer did not complete");
  const auto result = resolver.result(*handle);
  if (!result || result->status != dns::ResolutionStatus::success ||
      result->answers.size() != 1U ||
      result->answers.front().rdata !=
          std::vector<std::uint8_t>{final_address.begin(), final_address.end()})
    throw std::runtime_error("iterative resolution result changed answer data");

  // A second lookup completes directly from cache and emits no network action.
  const auto cached_handle = resolver.begin(original, epoch + 1s);
  std::array<std::uint8_t, 512U> unused_query_storage{};
  if (!cached_handle || !resolver.result(*cached_handle) ||
      resolver.prepare(*cached_handle, unused_query_storage,
                       epoch + 1s)
              .status != dns::PrepareQueryStatus::complete)
    throw std::runtime_error("iterative resolver did not use positive cache");

  // TC on UDP retries the same question and server using DNS over TCP. This
  // does not impose a 1232-octet protocol ceiling: TCP accepts the full DNS
  // message up to its two-octet length field.
  const Question root_question{.name = resolver_name("test."),
                               .type = type_a,
                               .record_class = internet_class};
  const auto tcp_handle = resolver.begin(root_question, epoch + 2s);
  const auto udp_query = prepare_and_commit(resolver, *tcp_handle, epoch + 2s);
  std::array<RecordData, 2U> large_rrset{
      RecordData{.owner = root_question.name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 60U,
                 .rdata = final_address},
      RecordData{.owner = root_question.name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 60U,
                 .rdata = test_glue}};
  std::array<std::uint8_t, 40U> truncated_storage{};
  const auto truncated_octets = encode_response(
      truncated_storage, udp_query.id, udp_query.question, large_rrset, {}, {},
      {.authoritative = true,
       .edns_udp_payload_size = std::nullopt,
       .edns_extended_rcode = 0U,
       .edns_version = 0U,
       .dnssec_ok = false});
  if (!truncated_octets ||
      resolver.receive(
          *tcp_handle, root_address, dns::QueryTransport::udp,
          std::span<const std::uint8_t>{truncated_storage}.first(*truncated_octets),
          epoch + 2001ms) != dns::ResponseStatus::accepted)
    throw std::runtime_error("truncated UDP response was not accepted");
  const auto tcp_query =
      prepare_and_commit(resolver, *tcp_handle, epoch + 2002ms);
  if (tcp_query.transport != dns::QueryTransport::tcp ||
      tcp_query.server != root_address ||
      !equal_case_insensitive(tcp_query.question.name, udp_query.question.name))
    throw std::runtime_error("truncated DNS query did not retry over TCP");

  dns::IterativeResolver guarded{
      secret,
      {{.server_name = resolver_name("a.root.test."),
        .addresses = {root_address}}}};
  const auto guarded_handle = guarded.begin(root_question, epoch + 3s);
  const auto guarded_query =
      prepare_and_commit(guarded, *guarded_handle, epoch + 3s);
  std::array<std::uint8_t, header_octets> impossible_counts{};
  impossible_counts[0] = static_cast<std::uint8_t>(guarded_query.id >> 8U);
  impossible_counts[1] = static_cast<std::uint8_t>(guarded_query.id);
  impossible_counts[2] = 0x80U;
  impossible_counts[4] = 0xffU;
  impossible_counts[5] = 0xffU;
  if (guarded.receive(*guarded_handle, root_address,
                      dns::QueryTransport::udp, impossible_counts,
                      epoch + 3001ms) != dns::ResponseStatus::malformed)
    throw std::runtime_error("DNS response counts bypassed size admission");

  const std::array<RecordData, 1U> unrelated_answer{
      RecordData{.owner = resolver_name("unrelated.test."),
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 60U,
                 .rdata = final_address}};
  const auto poisoned =
      response(guarded_query, unrelated_answer, {}, {}, true);
  if (guarded.receive(*guarded_handle, root_address,
                      dns::QueryTransport::udp, poisoned,
                      epoch + 3002ms) != dns::ResponseStatus::malformed ||
      !guarded.cache()
           .lookup(resolver_name("unrelated.test."), type_a, internet_class,
                   epoch + 3002ms)
           .records.empty())
    throw std::runtime_error("unrelated DNS answer polluted resolver cache");

  dns::IterativeResolver checkpoint_source{
      secret,
      {{.server_name = resolver_name("a.root.test."),
        .addresses = {root_address}}}};
  const auto checkpoint_handle =
      checkpoint_source.begin(root_question, epoch + 4s);
  const auto checkpoint_query = prepare_and_commit(
      checkpoint_source, *checkpoint_handle, epoch + 4s);
  const auto checkpoint = checkpoint_source.checkpoint(epoch + 4100ms);
  dns::IterativeResolver checkpoint_restored{secret, {}};
  if (!checkpoint_restored.restore(checkpoint, epoch + 20s))
    throw std::runtime_error("active DNS resolver checkpoint did not restore");
  const auto restored_deadline = checkpoint_restored.next_deadline();
  if (!restored_deadline ||
      *restored_deadline != epoch + 20s + 900ms)
    throw std::runtime_error("DNS checkpoint changed retry remaining time");
  const std::array<RecordData, 1U> checkpoint_answers{
      RecordData{.owner = root_question.name,
                 .type = type_a,
                 .record_class = internet_class,
                 .ttl = 60U,
                 .rdata = final_address}};
  const auto checkpoint_reply =
      response(checkpoint_query, checkpoint_answers, {}, {}, true);
  if (checkpoint_restored.receive(
          *checkpoint_handle, root_address, dns::QueryTransport::udp,
          checkpoint_reply, epoch + 20100ms) !=
          dns::ResponseStatus::complete ||
      !checkpoint_restored.result(*checkpoint_handle))
    throw std::runtime_error("restored DNS transaction did not accept reply");
  auto corrupt_checkpoint = checkpoint;
  corrupt_checkpoint.generations.front() = 0U;
  if (checkpoint_restored.restore(corrupt_checkpoint, epoch + 30s) ||
      !checkpoint_restored.result(*checkpoint_handle))
    throw std::runtime_error("corrupt DNS checkpoint changed live resolver");

  // The validating path establishes a root anchor, authenticates a DS at the
  // zone cut, fetches the child's DNSKEY over the selected glue address and
  // only then admits the signed answer to the secure cache. No test fixture
  // passes a key or answer directly between the modeled servers.
  ResolverAcceptingCrypto dnssec_crypto;
  ResolverDeterministicDigests dnssec_digests;
  std::uint32_t wall_time = 1500U;
  const auto root_key = dnskey_record(".", 1U);
  const auto child_key = dnskey_record("secure.", 3U);
  dnssec::TrustAnchorStore anchors;
  if (anchors.add(root_key) != dnssec::AnchorMutation::applied)
    throw std::runtime_error("resolver trust anchor fixture was rejected");
  dns::IterativeResolver validating{
      secret,
      {{.server_name = resolver_name("a.root.test."),
        .addresses = {root_address}}}};
  if (!validating.enable_dnssec(
          {.crypto = &dnssec_crypto,
           .digests = &dnssec_digests,
           .wall_clock_seconds = resolver_wall_clock,
           .wall_clock_context = &wall_time,
           .trust_anchors = anchors}))
    throw std::runtime_error("resolver DNSSEC policy was not enabled");
  const Question secure_question{
      .name = resolver_name("www.secure."),
      .type = type_aaaa,
      .record_class = internet_class};
  const auto secure_handle = validating.begin(secure_question, epoch + 40s);
  if (!secure_handle)
    throw std::runtime_error("validating resolver transaction did not start");

  const auto root_key_query =
      prepare_and_commit(validating, *secure_handle, epoch + 40s);
  if (root_key_query.question.type != type_dnskey ||
      !equal_case_insensitive(root_key_query.question.name,
                              resolver_name(".")))
    throw std::runtime_error("validating resolver did not fetch root DNSKEY");
  const auto root_key_signature =
      signature_record(".", type_dnskey, 0U, ".", root_key);
  const std::array root_key_answers{record_view(root_key),
                                    record_view(root_key_signature)};
  if (validating.receive(
          *secure_handle, root_address, dns::QueryTransport::udp,
          response(root_key_query, root_key_answers, {}, {}, true),
          epoch + 40001ms) != dns::ResponseStatus::accepted)
    throw std::runtime_error("root trust anchor did not validate");

  // Checkpointing after anchor validation must retain the authenticated root
  // key and injected policy, not downgrade the resumed transaction.
  const auto secure_checkpoint = validating.checkpoint(epoch + 40002ms);
  dns::IterativeResolver resumed_validating{secret, {}};
  dnssec::TrustAnchorStore resume_anchors;
  if (resume_anchors.add(root_key) != dnssec::AnchorMutation::applied ||
      !resumed_validating.enable_dnssec(
          {.crypto = &dnssec_crypto,
           .digests = &dnssec_digests,
           .wall_clock_seconds = resolver_wall_clock,
           .wall_clock_context = &wall_time,
           .trust_anchors = std::move(resume_anchors)}) ||
      !resumed_validating.restore(secure_checkpoint, epoch + 50s))
    throw std::runtime_error("validated resolver checkpoint did not restore");

  const auto delegation_query =
      prepare_and_commit(resumed_validating, *secure_handle, epoch + 50001ms);
  if (!equal_case_insensitive(delegation_query.question.name,
                              resolver_name("secure.")))
    throw std::runtime_error("resolver minimisation did not reach zone cut");
  std::vector<std::uint8_t> child_digest;
  std::vector<std::uint8_t> digest_input(
      child_key.owner.view().begin(), child_key.owner.view().end());
  digest_input.insert(digest_input.end(), child_key.rdata.begin(),
                      child_key.rdata.end());
  if (!dnssec_digests.calculate_digest(2U, digest_input, child_digest))
    throw std::runtime_error("resolver DS fixture digest failed");
  dnssec::Ds child_ds{.key_tag = dnssec::key_tag(child_key.rdata),
                      .algorithm = 13U,
                      .digest_type = 2U,
                      .digest = child_digest};
  std::vector<std::uint8_t> child_ds_wire;
  if (!dnssec::encode_ds(child_ds, child_ds_wire))
    throw std::runtime_error("resolver DS fixture did not encode");
  const dns::ZoneRecord child_ds_record{
      .owner = resolver_name("secure."),
      .type = type_ds,
      .record_class = internet_class,
      .ttl = 3600U,
      .rdata = std::move(child_ds_wire)};
  const auto child_ds_signature =
      signature_record("secure.", type_ds, 1U, ".", root_key);
  const auto child_ns_wire = resolver_name_data("ns.secure.");
  const std::array<std::uint8_t, 16U> child_server_ipv6{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x54U};
  const std::array<RecordData, 3U> delegation_authority{
      RecordData{.owner = resolver_name("secure."),
                 .type = type_ns,
                 .record_class = internet_class,
                 .ttl = 3600U,
                 .rdata = child_ns_wire},
      record_view(child_ds_record), record_view(child_ds_signature)};
  const std::array<RecordData, 1U> delegation_glue{
      RecordData{.owner = resolver_name("ns.secure."),
                 .type = type_aaaa,
                 .record_class = internet_class,
                 .ttl = 3600U,
                 .rdata = child_server_ipv6}};
  if (resumed_validating.receive(
          *secure_handle, root_address, dns::QueryTransport::udp,
          response(delegation_query, {}, delegation_authority,
                   delegation_glue),
          epoch + 50002ms) != dns::ResponseStatus::accepted)
    throw std::runtime_error("secure delegation was not accepted");

  const dns::ServerAddress child_server{
      .family = transport::IpFamily::ipv6, .ipv6 = child_server_ipv6};
  const auto child_key_query = prepare_and_commit(
      resumed_validating, *secure_handle, epoch + 50003ms);
  if (child_key_query.server != child_server ||
      child_key_query.question.type != type_dnskey)
    throw std::runtime_error("child DNSKEY was not fetched through glue");
  const auto child_key_signature =
      signature_record("secure.", type_dnskey, 1U, "secure.", child_key);
  const std::array child_key_answers{record_view(child_key),
                                     record_view(child_key_signature)};
  if (resumed_validating.receive(
          *secure_handle, child_server, dns::QueryTransport::udp,
          response(child_key_query, child_key_answers, {}, {}, true),
          epoch + 50004ms) != dns::ResponseStatus::accepted)
    throw std::runtime_error("child DNSKEY did not validate against DS");

  const auto secure_answer_query = prepare_and_commit(
      resumed_validating, *secure_handle, epoch + 50005ms);
  const std::array<std::uint8_t, 16U> secure_ipv6{
      0x20U, 0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U,
      0U, 0U, 0U, 0U, 0U, 0U, 0x80U, 0x80U};
  const dns::ZoneRecord secure_aaaa{
      .owner = secure_question.name,
      .type = type_aaaa,
      .record_class = internet_class,
      .ttl = 300U,
      .rdata = {secure_ipv6.begin(), secure_ipv6.end()}};
  const auto secure_aaaa_signature = signature_record(
      "www.secure.", type_aaaa, 2U, "secure.", child_key);
  const std::array secure_answers{record_view(secure_aaaa),
                                  record_view(secure_aaaa_signature)};
  if (resumed_validating.receive(
          *secure_handle, child_server, dns::QueryTransport::udp,
          response(secure_answer_query, secure_answers, {}, {}, true),
          epoch + 50006ms) != dns::ResponseStatus::complete)
    throw std::runtime_error("signed IPv6 answer did not complete");
  const auto secure_result = resumed_validating.result(*secure_handle);
  if (!secure_result ||
      secure_result->security != dns::CacheSecurity::secure ||
      secure_result->status != dns::ResolutionStatus::success)
    throw std::runtime_error("validated IPv6 answer was not marked secure");

  // CD belongs to the individual client transaction, not to global resolver
  // mode. The unchecked answer is returned with indeterminate security and is
  // deliberately excluded from the shared cache so a later validating query
  // cannot mistake it for authenticated data.
  const Question unchecked_question{
      .name = resolver_name("unchecked."),
      .type = type_aaaa,
      .record_class = internet_class};
  const auto unchecked_handle = resumed_validating.begin(
      unchecked_question, epoch + 51s, true);
  const auto unchecked_query = prepare_and_commit(
      resumed_validating, *unchecked_handle, epoch + 51s);
  if (unchecked_query.question.type != type_aaaa)
    throw std::runtime_error("CD query unexpectedly fetched DNSKEY");
  const dns::ZoneRecord unchecked_aaaa{
      .owner = unchecked_question.name,
      .type = type_aaaa,
      .record_class = internet_class,
      .ttl = 60U,
      .rdata = {secure_ipv6.begin(), secure_ipv6.end()}};
  const std::array unchecked_answers{record_view(unchecked_aaaa)};
  if (resumed_validating.receive(
          *unchecked_handle, root_address, dns::QueryTransport::udp,
          response(unchecked_query, unchecked_answers, {}, {}, true),
          epoch + 51001ms) != dns::ResponseStatus::complete)
    throw std::runtime_error("CD query did not return unchecked data");
  const auto unchecked_result = resumed_validating.result(*unchecked_handle);
  if (!unchecked_result ||
      unchecked_result->security != dns::CacheSecurity::indeterminate ||
      !resumed_validating.cache()
           .lookup(unchecked_question.name, type_aaaa, internet_class,
                   epoch + 51002ms)
           .records.empty())
    throw std::runtime_error("CD data entered validating resolver cache");
  const auto rechecked_handle = resumed_validating.begin(
      unchecked_question, epoch + 51003ms, false);
  const auto rechecked_query = prepare_and_commit(
      resumed_validating, *rechecked_handle, epoch + 51003ms);
  if (rechecked_query.question.type != type_dnskey)
    throw std::runtime_error("validated query reused unchecked cache data");
}
