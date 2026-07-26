// RFC 1034 iterative resolution with RFC 9156 QNAME minimisation, RFC 2308
// negative caching and RFC 7766 TCP retry. All network work is represented by
// prepared actions and becomes live only after the packet owner admits bytes.

#include "router/dns_resolver.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <stdexcept>

namespace router::dns {
namespace {

using packet::dns::Name;
using packet::dns::RecordData;
using packet::dns::ResourceRecord;

bool same_name(const Name &left, const Name &right) noexcept {
  return packet::dns::equal_case_insensitive(left, right);
}

bool valid_question(const packet::dns::Question &question) noexcept {
  Name parsed;
  const auto consumed =
      packet::dns::parse_name(question.name.view(), 0U, parsed);
  return consumed && *consumed == question.name.octets &&
         question.type != 0U && question.record_class != 0U;
}

bool subdomain(const Name &name, const Name &ancestor) noexcept {
  std::size_t offset{};
  while (offset < name.octets) {
    Name suffix;
    suffix.octets = static_cast<std::uint16_t>(name.octets - offset);
    std::copy_n(name.wire.begin() + static_cast<std::ptrdiff_t>(offset),
                suffix.octets, suffix.wire.begin());
    if (same_name(suffix, ancestor))
      return true;
    if (name.wire[offset] == 0U)
      break;
    offset += 1U + name.wire[offset];
  }
  return false;
}

std::uint16_t read_u16(std::span<const std::uint8_t> bytes,
                       std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
}

std::optional<Name> canonical_name(std::span<const std::uint8_t> message,
                                   const ResourceRecord &record) noexcept {
  std::vector<std::uint8_t> bytes;
  if (!packet::dns::canonicalize_rdata(message, record, bytes))
    return std::nullopt;
  Name result;
  const auto consumed = packet::dns::parse_name(bytes, 0U, result);
  return consumed && *consumed == bytes.size() ? std::optional<Name>{result}
                                               : std::nullopt;
}

ZoneRecord own_record(std::span<const std::uint8_t> message,
                      const ResourceRecord &record, bool &valid) {
  ZoneRecord owned{.owner = record.owner,
                   .type = record.type,
                   .record_class = record.record_class,
                   .ttl = record.ttl,
                   .rdata = {}};
  valid = packet::dns::canonicalize_rdata(message, record, owned.rdata);
  return owned;
}

std::vector<RecordData> views(const std::vector<ZoneRecord> &records) {
  std::vector<RecordData> result;
  result.reserve(records.size());
  for (const auto &record : records)
    result.push_back({.owner = record.owner,
                      .type = record.type,
                      .record_class = record.record_class,
                      .ttl = record.ttl,
                      .rdata = record.rdata});
  return result;
}

std::uint32_t negative_ttl(const ZoneRecord &soa) noexcept {
  if (soa.type != packet::dns::type_soa || soa.rdata.size() < 22U)
    return 0U;
  Name value;
  const auto first = packet::dns::parse_name(soa.rdata, 0U, value);
  if (!first)
    return 0U;
  const auto second = packet::dns::parse_name(soa.rdata, *first, value);
  if (!second || *first + *second + 20U != soa.rdata.size())
    return 0U;
  const auto offset = soa.rdata.size() - 4U;
  const auto minimum =
      (static_cast<std::uint32_t>(soa.rdata[offset]) << 24U) |
      (static_cast<std::uint32_t>(soa.rdata[offset + 1U]) << 16U) |
      (static_cast<std::uint32_t>(soa.rdata[offset + 2U]) << 8U) |
      soa.rdata[offset + 3U];
  return std::min(soa.ttl, minimum);
}

std::vector<Name> filter_relevant_answers(std::vector<ZoneRecord> &records,
                                          const Name &qname) {
  std::vector<Name> reachable{qname};
  std::vector<bool> admitted(records.size(), false);
  bool changed{true};
  while (changed) {
    changed = false;
    for (std::size_t index = 0U; index < records.size(); ++index) {
      if (admitted[index])
        continue;
      const auto &record = records[index];
      const bool exact_owner = std::any_of(
          reachable.begin(), reachable.end(), [&](const auto &name) {
            return same_name(name, record.owner);
          });
      const bool dname_ancestor = record.type == packet::dns::type_dname &&
                                  std::any_of(
                                      reachable.begin(), reachable.end(),
                                      [&](const auto &name) {
                                        return subdomain(name, record.owner) &&
                                               !same_name(name, record.owner);
                                      });
      if (!exact_owner && !dname_ancestor)
        continue;
      admitted[index] = true;
      changed = true;
      if (record.type != packet::dns::type_cname)
        continue;
      Name target;
      const auto consumed = packet::dns::parse_name(record.rdata, 0U, target);
      if (!consumed || *consumed != record.rdata.size())
        continue;
      if (std::none_of(reachable.begin(), reachable.end(),
                       [&](const auto &name) {
                         return same_name(name, target);
                       }))
        reachable.push_back(target);
    }
  }
  for (std::size_t index = records.size(); index-- > 0U;)
    if (!admitted[index])
      records.erase(records.begin() + static_cast<std::ptrdiff_t>(index));
  return reachable;
}

bool valid_server(const ServerAddress &server) noexcept {
  if (server.family == transport::IpFamily::ipv4)
    return server.ipv4 != ip::Ipv4{};
  return !ip::is_unspecified(server.ipv6) && !ip::is_multicast(server.ipv6) &&
         (!ip::is_link_local(server.ipv6) || server.interface_id != 0U);
}

bool valid_name(const Name &name) noexcept {
  Name parsed;
  const auto consumed = packet::dns::parse_name(name.view(), 0U, parsed);
  return consumed && *consumed == name.octets;
}

bool valid_owned_record(const ZoneRecord &record) noexcept {
  return valid_name(record.owner) && record.type != 0U &&
         record.record_class != 0U &&
         record.rdata.size() <=
             static_cast<std::size_t>(
                 std::numeric_limits<std::uint16_t>::max());
}

bool dnssec_time_before(std::uint32_t left, std::uint32_t right) noexcept {
  return left != right && static_cast<std::uint32_t>(right - left) <
                              0x80000000U;
}

} // namespace

struct IterativeResolver::Transaction {
  struct ReferralResume {
    packet::dns::Question original;
    std::vector<Name> plan;
    std::vector<Name> visited_aliases;
    std::vector<Name> nameservers;
    std::vector<ServerAddress> resolved_addresses;
    std::size_t stage{};
    std::size_t nameserver_index{};
    bool resolving_ipv6{true};
    // Resolving an out-of-bailiwick NS target temporarily reuses this
    // transaction. The parent validation chain must therefore be stacked with
    // the ordinary query state and restored atomically afterwards.
    Name current_zone;
    std::vector<ZoneRecord> current_dnskeys;
    std::uint32_t current_dnskeys_valid_until{};
    Name pending_zone;
    std::vector<ZoneRecord> pending_ds;
    CacheSecurity chain_security{CacheSecurity::indeterminate};
    DnssecPhase dnssec_phase{DnssecPhase::disabled};
    bool validation_failure_seen{};
    bool checking_disabled{};
    bool cache_allowed{true};
  };

  packet::dns::Question original;
  packet::dns::Question active_question;
  std::vector<Name> plan;
  std::vector<ServerAddress> servers;
  std::vector<Name> visited_aliases;
  std::vector<ReferralResume> referral_stack;
  ResolutionResult result;
  Clock::time_point deadline{};
  ServerAddress active_server{};
  QueryTransport active_transport{QueryTransport::udp};
  std::size_t stage{};
  std::size_t server_index{};
  std::uint32_t attempts{};
  std::uint64_t prepared_token{};
  std::uint16_t active_id{};
  bool occupied{};
  bool awaiting{};
  bool force_tcp{};
  Name current_zone;
  std::vector<ZoneRecord> current_dnskeys;
  std::uint32_t current_dnskeys_valid_until{};
  Name pending_zone;
  std::vector<ZoneRecord> pending_ds;
  CacheSecurity chain_security{CacheSecurity::indeterminate};
  DnssecPhase dnssec_phase{DnssecPhase::disabled};
  bool validation_failure_seen{};
  bool checking_disabled{};
  bool cache_allowed{true};
};

std::vector<Name> build_minimisation_plan(const Name &qname,
                                          const ResolverPolicy &policy) {
  std::vector<std::size_t> label_offsets;
  std::size_t offset{};
  while (offset < qname.octets && qname.wire[offset] != 0U) {
    label_offsets.push_back(offset);
    offset += 1U + qname.wire[offset];
  }
  if (offset >= qname.octets)
    return {};

  const auto labels = label_offsets.size();
  if (labels == 0U)
    return {qname};
  const auto maximum = std::max<std::size_t>(1U, policy.maximum_minimise_count);
  const auto iterations = std::min(labels, maximum);
  const auto must_group = labels > iterations;
  const auto single_slots = must_group ? iterations - 1U : iterations;
  const auto singles = std::min(
      {labels, single_slots,
       static_cast<std::size_t>(policy.minimise_one_label_count)});
  std::vector<std::size_t> increments(singles, 1U);
  const auto remaining_labels = labels - singles;
  const auto remaining_slots = iterations - singles;
  if (remaining_slots != 0U) {
    const auto base = remaining_labels / remaining_slots;
    const auto remainder = remaining_labels % remaining_slots;
    for (std::size_t slot = 0U; slot < remaining_slots; ++slot) {
      // RFC 9156 places the uneven remainder in later iterations so early
      // queries disclose the fewest possible labels.
      const auto extra = slot >= remaining_slots - remainder ? 1U : 0U;
      increments.push_back(base + extra);
    }
  }

  std::vector<Name> result;
  result.reserve(increments.size());
  std::size_t exposed{};
  for (const auto increment : increments) {
    exposed += increment;
    const auto suffix = label_offsets[labels - exposed];
    Name value;
    value.octets = static_cast<std::uint16_t>(qname.octets - suffix);
    std::copy_n(qname.wire.begin() + static_cast<std::ptrdiff_t>(suffix),
                value.octets, value.wire.begin());
    result.push_back(value);
  }
  return result;
}

IterativeResolver::IterativeResolver(crypto::Sha256Digest identifier_secret,
                                     std::vector<RootHint> root_hints,
                                     ResolverPolicy policy)
    : identifier_secret_(identifier_secret),
      root_hints_(std::move(root_hints)), policy_(policy) {
  if (std::none_of(identifier_secret_.begin(), identifier_secret_.end(),
                   [](const auto byte) { return byte != 0U; }))
    throw std::invalid_argument("DNS identifier secret must contain entropy");
  for (std::size_t index = 0U; index < root_hints_.size(); ++index) {
    const auto &hint = root_hints_[index];
    if (!valid_name(hint.server_name) || hint.addresses.empty() ||
        std::any_of(hint.addresses.begin(), hint.addresses.end(),
                    [](const auto &server) {
                      return !valid_server(server);
                    }))
      throw std::invalid_argument("DNS root hint is invalid");
    for (std::size_t previous = 0U; previous < index; ++previous)
      if (same_name(root_hints_[previous].server_name, hint.server_name))
        throw std::invalid_argument("DNS root hint owner is duplicated");
  }
  // Zero retry or attempt values would create a busy loop rather than a useful
  // operational policy. Normalization changes local resource policy only and
  // never changes DNS wire limits or accepted UDP datagram sizes.
  policy_.retry_interval = std::max(policy_.retry_interval,
                                    std::chrono::milliseconds{1});
  policy_.attempts_per_server = std::max(1U, policy_.attempts_per_server);
  policy_.maximum_minimise_count =
      std::max(1U, policy_.maximum_minimise_count);
  policy_.maximum_alias_hops = std::max(1U, policy_.maximum_alias_hops);
  policy_.advertised_udp_payload_bytes =
      std::max<std::uint16_t>(512U, policy_.advertised_udp_payload_bytes);
}

IterativeResolver::~IterativeResolver() = default;

bool IterativeResolver::enable_dnssec(
    ResolverDnssecConfiguration configuration) noexcept {
  if (!transactions_.empty() || cache_.used_bytes() != 0U ||
      !configuration.crypto || !configuration.digests ||
      !configuration.wall_clock_seconds ||
      configuration.trust_anchors.records().empty())
    return false;
  dnssec_crypto_ = configuration.crypto;
  dnssec_digests_ = configuration.digests;
  wall_clock_seconds_ = configuration.wall_clock_seconds;
  wall_clock_context_ = configuration.wall_clock_context;
  trust_anchors_ = std::move(configuration.trust_anchors);
  nsec3_policy_ = configuration.nsec3_policy;
  return true;
}

IterativeResolver::Transaction *
IterativeResolver::find(TransactionHandle handle) noexcept {
  if (handle.index >= transactions_.size() ||
      handle.index >= generations_.size() ||
      generations_[handle.index] != handle.generation ||
      !transactions_[handle.index])
    return nullptr;
  return &*transactions_[handle.index];
}

const IterativeResolver::Transaction *
IterativeResolver::find(TransactionHandle handle) const noexcept {
  if (handle.index >= transactions_.size() ||
      handle.index >= generations_.size() ||
      generations_[handle.index] != handle.generation ||
      !transactions_[handle.index])
    return nullptr;
  return &*transactions_[handle.index];
}

bool IterativeResolver::reset_to_roots(Transaction &transaction) noexcept {
  try {
    transaction.servers.clear();
    for (const auto &hint : root_hints_)
      transaction.servers.insert(transaction.servers.end(),
                                 hint.addresses.begin(), hint.addresses.end());
    transaction.server_index = 0U;
    transaction.attempts = 0U;
    transaction.awaiting = false;
    transaction.force_tcp = false;
    return !transaction.servers.empty();
  } catch (const std::bad_alloc &) {
    transaction.result.status = ResolutionStatus::resource_exhausted;
    return false;
  }
}

bool IterativeResolver::restart_validation_from_root(
    Transaction &transaction) noexcept {
  if (!dnssec_crypto_ || transaction.checking_disabled) {
    transaction.current_zone = {};
    transaction.current_dnskeys.clear();
    transaction.current_dnskeys_valid_until = 0U;
    transaction.pending_zone = {};
    transaction.pending_ds.clear();
    transaction.chain_security = CacheSecurity::indeterminate;
    transaction.dnssec_phase = DnssecPhase::disabled;
    transaction.validation_failure_seen = false;
    return true;
  }
  const auto root = packet::dns::name_from_text(".");
  if (!root) {
    transaction.result.status = ResolutionStatus::resource_exhausted;
    return false;
  }
  // A fresh recursive walk authenticates the root DNSKEY before exposing any
  // child label. This is also used after a CNAME crosses zones and for nested
  // NS address lookups, preventing an authenticated key from one zone from
  // being applied to an unrelated response.
  transaction.current_zone = *root;
  transaction.current_dnskeys.clear();
  transaction.current_dnskeys_valid_until = 0U;
  transaction.pending_zone = {};
  transaction.pending_ds.clear();
  transaction.chain_security = CacheSecurity::indeterminate;
  transaction.dnssec_phase = DnssecPhase::root_dnskey;
  transaction.validation_failure_seen = false;
  transaction.active_question = {
      .name = *root,
      .type = packet::dns::type_dnskey,
      .record_class = transaction.original.record_class};
  return true;
}

std::optional<TransactionHandle>
IterativeResolver::begin(const packet::dns::Question &question,
                         Clock::time_point now,
                         bool checking_disabled) noexcept {
  if (!valid_question(question))
    return std::nullopt;
  try {
    Transaction transaction{.original = question,
                            .active_question = question,
                            .plan = build_minimisation_plan(question.name,
                                                            policy_),
                            .servers = {},
                            .visited_aliases = {question.name},
                            .referral_stack = {},
                            .result = {.original_question = question,
                                       .answers = {},
                                       .authorities = {},
                                       .status = ResolutionStatus::pending,
                                       .security =
                                           CacheSecurity::indeterminate},
                            .occupied = true,
                            .current_zone = {},
                            .current_dnskeys = {},
                            .current_dnskeys_valid_until = 0U,
                            .pending_zone = {},
                            .pending_ds = {},
                            .chain_security = CacheSecurity::indeterminate,
                            .dnssec_phase = DnssecPhase::disabled,
                            .validation_failure_seen = false,
                            .checking_disabled = checking_disabled,
                            .cache_allowed =
                                !dnssec_crypto_ || !checking_disabled};
    const auto cached =
        cache_.lookup(question.name, question.type, question.record_class, now);
    const auto cache_acceptable =
        !dnssec_crypto_ || checking_disabled ||
        cached.security != CacheSecurity::indeterminate;
    if (!cached.records.empty() && cache_acceptable) {
      for (const auto &record : cached.records)
        transaction.result.answers.push_back(
            {.owner = record.owner,
             .type = record.type,
             .record_class = record.record_class,
             .ttl = record.ttl,
             .rdata = {record.rdata.begin(), record.rdata.end()}});
      transaction.result.status = ResolutionStatus::success;
      transaction.result.security = cached.security;
    } else if (cached.negative != NegativeKind::none && cache_acceptable) {
      for (const auto &record : cached.authorities)
        transaction.result.authorities.push_back(
            {.owner = record.owner,
             .type = record.type,
             .record_class = record.record_class,
             .ttl = record.ttl,
             .rdata = {record.rdata.begin(), record.rdata.end()}});
      transaction.result.status = cached.negative == NegativeKind::name_error
                                      ? ResolutionStatus::name_error
                                      : ResolutionStatus::no_data;
      transaction.result.security = cached.security;
    } else if (!reset_to_roots(transaction)) {
      if (transaction.result.status == ResolutionStatus::pending)
        transaction.result.status = ResolutionStatus::no_reachable_server;
    } else if (!restart_validation_from_root(transaction))
      return std::nullopt;

    std::size_t index{};
    for (; index < transactions_.size(); ++index)
      if (!transactions_[index])
        break;
    if (index == transactions_.size()) {
      transactions_.emplace_back();
      generations_.push_back(1U);
    }
    transactions_[index] = std::move(transaction);
    return TransactionHandle{.index = static_cast<std::uint32_t>(index),
                             .generation = generations_[index]};
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

std::uint16_t
IterativeResolver::next_identifier(const Transaction &transaction,
                                   const ServerAddress &server) noexcept {
  std::array<std::uint8_t, 8U> counter{};
  auto value = identifier_counter_++;
  for (std::size_t index = 0U; index < counter.size(); ++index) {
    counter[counter.size() - 1U - index] = static_cast<std::uint8_t>(value);
    value >>= 8U;
  }
  const std::span<const std::uint8_t> address =
      server.family == transport::IpFamily::ipv4
          ? std::span<const std::uint8_t>{server.ipv4}
          : std::span<const std::uint8_t>{server.ipv6};
  const std::array<std::span<const std::uint8_t>, 3U> parts{
      std::span<const std::uint8_t>{counter}, transaction.active_question.name.view(),
      address};
  const auto digest = crypto::hmac_sha256(identifier_secret_, parts);
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(digest[0]) << 8U) | digest[1]);
}

PrepareQueryResult
IterativeResolver::prepare(TransactionHandle handle,
                           std::span<std::uint8_t> output,
                           Clock::time_point now) noexcept {
  auto *transaction = find(handle);
  if (!transaction)
    return {.status = PrepareQueryStatus::invalid_transaction};
  if (transaction->result.status != ResolutionStatus::pending)
    return {.status = PrepareQueryStatus::complete};
  if (transaction->awaiting || transaction->prepared_token != 0U)
    return {.status = PrepareQueryStatus::awaiting_response};
  if (transaction->server_index >= transaction->servers.size())
    return {.status = PrepareQueryStatus::no_reachable_server};
  if (transaction->plan.empty() || transaction->stage >= transaction->plan.size())
    return {.status = PrepareQueryStatus::resource_exhausted};

  const bool key_phase =
      transaction->dnssec_phase == DnssecPhase::root_dnskey ||
      transaction->dnssec_phase == DnssecPhase::child_dnskey;
  try {
    while (!key_phase &&
           transaction->stage + 1U < transaction->plan.size()) {
      const auto cached = cache_.lookup(
          transaction->plan[transaction->stage], packet::dns::type_a,
          transaction->original.record_class, now);
      if (cached.negative == NegativeKind::name_error) {
        transaction->result.status = ResolutionStatus::name_error;
        return {.status = PrepareQueryStatus::complete};
      }
      if (cached.records.empty() &&
          cached.negative == NegativeKind::none)
        break;
      // Any cached NOERROR result, including NODATA, proves that this child
      // name exists and RFC 9156 iteration may expose the next label without
      // repeating the upstream query.
      ++transaction->stage;
    }
  } catch (const std::bad_alloc &) {
    transaction->result.status = ResolutionStatus::resource_exhausted;
    return {.status = PrepareQueryStatus::resource_exhausted};
  }

  if (!key_phase)
    transaction->active_question = {
        .name = transaction->plan[transaction->stage],
        .type = transaction->stage + 1U == transaction->plan.size()
                    ? transaction->original.type
                    : packet::dns::type_a,
        .record_class = transaction->original.record_class};
  const auto &server = transaction->servers[transaction->server_index];
  const auto id = next_identifier(*transaction, server);
  const auto octets = packet::dns::encode_query(
      output, id, transaction->active_question, false,
      std::optional<std::uint16_t>{policy_.advertised_udp_payload_bytes},
      true, true, true);
  if (!octets)
    return {.status = PrepareQueryStatus::buffer_too_small};
  transaction->prepared_token = preparation_counter_++;
  if (transaction->prepared_token == 0U)
    transaction->prepared_token = preparation_counter_++;
  return {.status = PrepareQueryStatus::prepared,
          .query = {.server = server,
                    .question = transaction->active_question,
                    .transport = transaction->force_tcp ? QueryTransport::tcp
                                                        : QueryTransport::udp,
                    .preparation_token = transaction->prepared_token,
                    .message_octets = *octets,
                    .id = id}};
}

bool IterativeResolver::commit(TransactionHandle handle,
                               const PreparedQuery &query,
                               Clock::time_point now) noexcept {
  auto *transaction = find(handle);
  if (!transaction || transaction->prepared_token == 0U ||
      transaction->prepared_token != query.preparation_token ||
      transaction->awaiting)
    return false;
  transaction->prepared_token = 0U;
  transaction->active_server = query.server;
  transaction->active_transport = query.transport;
  transaction->active_id = query.id;
  transaction->deadline = now + policy_.retry_interval;
  transaction->awaiting = true;
  ++transaction->attempts;
  return true;
}

bool IterativeResolver::discard(TransactionHandle handle,
                                const PreparedQuery &query) noexcept {
  auto *transaction = find(handle);
  if (!transaction || transaction->prepared_token != query.preparation_token)
    return false;
  transaction->prepared_token = 0U;
  return true;
}

void IterativeResolver::advance_server(Transaction &transaction) noexcept {
  transaction.awaiting = false;
  transaction.prepared_token = 0U;
  transaction.force_tcp = false;
  transaction.attempts = 0U;
  ++transaction.server_index;
  if (transaction.server_index >= transaction.servers.size()) {
    if (!transaction.referral_stack.empty())
      finish_nameserver_address_lookup(transaction, {});
    else
      transaction.result.status = transaction.validation_failure_seen
                                      ? ResolutionStatus::server_failure
                                      : ResolutionStatus::no_reachable_server;
  }
}

bool IterativeResolver::start_nameserver_address_lookup(
    Transaction &transaction) noexcept {
  if (transaction.referral_stack.empty())
    return false;
  auto &resume = transaction.referral_stack.back();
  if (resume.nameserver_index >= resume.nameservers.size())
    return false;
  const auto target = resume.nameservers[resume.nameserver_index];
  transaction.original = {
      .name = target,
      .type = resume.resolving_ipv6 ? packet::dns::type_aaaa
                                    : packet::dns::type_a,
      .record_class = resume.original.record_class};
  transaction.plan = build_minimisation_plan(target, policy_);
  // Reuse the transaction-owned allocation and copy one complete Name object
  // directly. GCC 13 lowers initializer-list assignment to a one-past
  // memmove and reports a false array-bounds diagnostic under -O2 -Werror.
  transaction.visited_aliases.clear();
  transaction.visited_aliases.push_back(target);
  transaction.stage = 0U;
  if (!reset_to_roots(transaction))
    return false;
  // A nameserver address is a separate recursive lookup and therefore cannot
  // borrow the suspended outer query's validation chain.
  return restart_validation_from_root(transaction);
}

void IterativeResolver::finish_nameserver_address_lookup(
    Transaction &transaction,
    std::span<const ServerAddress> discovered) noexcept {
  try {
    while (!transaction.referral_stack.empty()) {
      auto &resume = transaction.referral_stack.back();
      resume.validation_failure_seen =
          resume.validation_failure_seen || transaction.validation_failure_seen;
      for (const auto &address : discovered)
        if (std::find(resume.resolved_addresses.begin(),
                      resume.resolved_addresses.end(), address) ==
            resume.resolved_addresses.end())
          resume.resolved_addresses.push_back(address);

      if (resume.resolving_ipv6) {
        resume.resolving_ipv6 = false;
        if (start_nameserver_address_lookup(transaction))
          return;
      } else {
        resume.resolving_ipv6 = true;
        ++resume.nameserver_index;
        if (resume.nameserver_index < resume.nameservers.size() &&
            start_nameserver_address_lookup(transaction))
          return;
      }

      auto addresses = std::move(resume.resolved_addresses);
      auto original = resume.original;
      auto plan = std::move(resume.plan);
      auto aliases = std::move(resume.visited_aliases);
      const auto saved_stage = resume.stage;
      auto current_zone = resume.current_zone;
      auto current_dnskeys = std::move(resume.current_dnskeys);
      const auto current_dnskeys_valid_until =
          resume.current_dnskeys_valid_until;
      auto pending_zone = resume.pending_zone;
      auto pending_ds = std::move(resume.pending_ds);
      const auto chain_security = resume.chain_security;
      const auto dnssec_phase = resume.dnssec_phase;
      const auto validation_failure_seen = resume.validation_failure_seen;
      transaction.referral_stack.pop_back();
      transaction.original = original;
      transaction.plan = std::move(plan);
      transaction.visited_aliases = std::move(aliases);
      transaction.stage = saved_stage;
      transaction.servers = std::move(addresses);
      transaction.server_index = 0U;
      transaction.attempts = 0U;
      transaction.awaiting = false;
      transaction.force_tcp = false;
      transaction.current_zone = current_zone;
      transaction.current_dnskeys = std::move(current_dnskeys);
      transaction.current_dnskeys_valid_until =
          current_dnskeys_valid_until;
      transaction.pending_zone = pending_zone;
      transaction.pending_ds = std::move(pending_ds);
      transaction.chain_security = chain_security;
      transaction.dnssec_phase = dnssec_phase;
      transaction.validation_failure_seen = validation_failure_seen;
      if (!transaction.servers.empty()) {
        // The outer referral has now acquired real addresses through normal
        // DNS packets. A secure delegation still has to authenticate the
        // child's DNSKEY before minimisation can cross the zone cut.
        if (!transaction.pending_ds.empty()) {
          transaction.active_question = {
              .name = transaction.pending_zone,
              .type = packet::dns::type_dnskey,
              .record_class = transaction.original.record_class};
          transaction.dnssec_phase = DnssecPhase::child_dnskey;
        } else if (transaction.stage + 1U < transaction.plan.size()) {
          ++transaction.stage;
        }
        return;
      }

      // A failed nested address lookup is itself just an empty address result
      // for the next outer delegation. Continue unwinding until another NS
      // target can be tried or the client query genuinely has no server.
      discovered = {};
    }
    transaction.result.status = ResolutionStatus::no_reachable_server;
  } catch (const std::bad_alloc &) {
    transaction.result.status = ResolutionStatus::resource_exhausted;
  }
}

ResponseStatus IterativeResolver::receive(
    TransactionHandle handle, const ServerAddress &source,
    QueryTransport transport, std::span<const std::uint8_t> message,
    Clock::time_point now) noexcept {
  auto *transaction = find(handle);
  if (!transaction)
    return ResponseStatus::invalid_transaction;
  if (!transaction->awaiting || source != transaction->active_server)
    return ResponseStatus::ignored_source;
  if (transport != transaction->active_transport)
    return ResponseStatus::ignored_transport;
  if (message.size() < packet::dns::header_octets)
    return ResponseStatus::malformed;
  if (read_u16(message, 0U) != transaction->active_id)
    return ResponseStatus::ignored_identifier;

  try {
    const auto question_count = read_u16(message, 4U);
    const auto answer_count = read_u16(message, 6U);
    const auto authority_count = read_u16(message, 8U);
    const auto additional_count = read_u16(message, 10U);
    const auto minimum_question_octets =
        static_cast<std::size_t>(question_count) * 5U;
    const auto record_count = static_cast<std::size_t>(answer_count) +
                              authority_count + additional_count;
    const auto minimum_record_octets = record_count * 11U;
    if (minimum_question_octets + minimum_record_octets >
        message.size() - packet::dns::header_octets)
      return ResponseStatus::malformed;
    std::vector<packet::dns::Question> questions(question_count);
    std::vector<ResourceRecord> answers(answer_count);
    std::vector<ResourceRecord> authorities(authority_count);
    std::vector<ResourceRecord> additionals(additional_count);
    const auto parsed = packet::dns::parse(
        message, {.questions = questions,
                  .answers = answers,
                  .authorities = authorities,
                  .additionals = additionals});
    if (!parsed || !parsed->header.response || parsed->header.opcode != 0U)
      return ResponseStatus::malformed;
    if (parsed->questions.size() != 1U ||
        !same_name(parsed->questions.front().name,
                   transaction->active_question.name) ||
        parsed->questions.front().type != transaction->active_question.type ||
        parsed->questions.front().record_class !=
            transaction->active_question.record_class)
      return ResponseStatus::mismatched_question;

    transaction->awaiting = false;
    if (parsed->header.truncated && transport == QueryTransport::udp) {
      transaction->force_tcp = true;
      transaction->attempts = 0U;
      return ResponseStatus::accepted;
    }
    if (parsed->header.rcode == packet::dns::Rcode::server_failure ||
        parsed->header.rcode == packet::dns::Rcode::refused) {
      advance_server(*transaction);
      return transaction->result.status == ResolutionStatus::pending
                 ? ResponseStatus::accepted
                 : ResponseStatus::complete;
    }

    std::vector<ZoneRecord> owned_answers;
    std::vector<ZoneRecord> owned_authorities;
    owned_answers.reserve(parsed->answers.size());
    owned_authorities.reserve(parsed->authorities.size());
    for (const auto &record : parsed->answers) {
      bool valid{};
      auto owned = own_record(message, record, valid);
      if (!valid)
        return ResponseStatus::malformed;
      owned_answers.push_back(std::move(owned));
    }
    for (const auto &record : parsed->authorities) {
      bool valid{};
      auto owned = own_record(message, record, valid);
      if (!valid)
        return ResponseStatus::malformed;
      owned_authorities.push_back(std::move(owned));
    }

    if (transaction->dnssec_phase == DnssecPhase::root_dnskey ||
        transaction->dnssec_phase == DnssecPhase::child_dnskey) {
      const auto &expected_zone =
          transaction->dnssec_phase == DnssecPhase::root_dnskey
              ? transaction->current_zone
              : transaction->pending_zone;
      if (!parsed->header.authoritative ||
          parsed->header.rcode != packet::dns::Rcode::no_error ||
          !same_name(transaction->active_question.name, expected_zone)) {
        advance_server(*transaction);
        return transaction->result.status == ResolutionStatus::pending
                   ? ResponseStatus::accepted
                   : ResponseStatus::complete;
      }
      std::vector<ZoneRecord> dnskeys;
      std::vector<ZoneRecord> signatures;
      for (const auto &record : owned_answers) {
        if (!same_name(record.owner, expected_zone)) {
          advance_server(*transaction);
          return transaction->result.status == ResolutionStatus::pending
                     ? ResponseStatus::accepted
                     : ResponseStatus::complete;
        }
        if (record.type == packet::dns::type_dnskey)
          dnskeys.push_back(record);
        if (record.type == packet::dns::type_rrsig) {
          const auto signature = dnssec::decode_rrsig(record.rdata);
          if (signature &&
              signature->type_covered == packet::dns::type_dnskey)
            signatures.push_back(record);
        }
      }
      const auto wall_now = wall_clock_seconds_(wall_clock_context_);
      const auto chain = transaction->dnssec_phase == DnssecPhase::root_dnskey
                             ? dnssec::validate_from_trust_anchor(
                                   dnskeys, signatures, trust_anchors_,
                                   wall_now,
                                   *dnssec_crypto_)
                             : dnssec::validate_dnskey_delegation(
                                   dnskeys, signatures, transaction->pending_ds,
                                   wall_now,
                                   *dnssec_crypto_, *dnssec_digests_);
      if (chain.state != dnssec::ChainState::secure) {
        transaction->validation_failure_seen = true;
        advance_server(*transaction);
        return transaction->result.status == ResolutionStatus::pending
                   ? ResponseStatus::accepted
                   : ResponseStatus::complete;
      }
      transaction->current_dnskeys = std::move(dnskeys);
      transaction->current_dnskeys_valid_until = chain.valid_until;
      if (transaction->dnssec_phase == DnssecPhase::child_dnskey) {
        transaction->current_zone = transaction->pending_zone;
        transaction->pending_ds.clear();
        transaction->pending_zone = {};
        if (transaction->stage + 1U < transaction->plan.size())
          ++transaction->stage;
      }
      transaction->chain_security = CacheSecurity::secure;
      transaction->dnssec_phase = DnssecPhase::ordinary;
      transaction->server_index = 0U;
      transaction->attempts = 0U;
      transaction->force_tcp = false;
      return ResponseStatus::accepted;
    }

    CacheSecurity response_security = transaction->chain_security;
    std::optional<dnssec::ResponseValidationResult> dnssec_validation;
    if (transaction->dnssec_phase == DnssecPhase::ordinary &&
        transaction->chain_security == CacheSecurity::secure) {
      const auto wall_now = wall_clock_seconds_(wall_clock_context_);
      if (dnssec_time_before(transaction->current_dnskeys_valid_until,
                             wall_now)) {
        if (!reset_to_roots(*transaction) ||
            !restart_validation_from_root(*transaction))
          return ResponseStatus::complete;
        return ResponseStatus::accepted;
      }
      dnssec_validation = dnssec::validate_secure_zone_response(
          transaction->active_question, parsed->header.rcode, owned_answers,
          owned_authorities, transaction->current_zone,
          transaction->current_dnskeys, wall_now, *dnssec_crypto_,
          *dnssec_digests_, nsec3_policy_);
      if (dnssec_validation->security == dnssec::ResponseSecurity::bogus ||
          dnssec_validation->security ==
              dnssec::ResponseSecurity::indeterminate) {
        transaction->validation_failure_seen = true;
        advance_server(*transaction);
        return transaction->result.status == ResolutionStatus::pending
                   ? ResponseStatus::accepted
                   : ResponseStatus::complete;
      }
      response_security =
          dnssec_validation->security ==
                  dnssec::ResponseSecurity::insecure_delegation
              ? CacheSecurity::insecure
              : CacheSecurity::secure;
    }

    const ResourceRecord *delegation{};
    for (const auto &record : parsed->authorities)
      if (record.type == packet::dns::type_ns &&
          subdomain(transaction->active_question.name, record.owner) &&
          (!delegation || record.owner.octets > delegation->owner.octets))
        delegation = &record;
    if (delegation && !parsed->header.authoritative) {
      std::vector<Name> nameservers;
      std::vector<ZoneRecord> referral_records;
      for (const auto &record : parsed->authorities) {
        if (record.type != packet::dns::type_ns ||
            !same_name(record.owner, delegation->owner))
          continue;
        const auto target = canonical_name(message, record);
        bool valid{};
        auto owned = own_record(message, record, valid);
        if (!target || !valid)
          return ResponseStatus::invalid_referral;
        nameservers.push_back(*target);
        referral_records.push_back(std::move(owned));
      }

      std::vector<ServerAddress> next_servers;
      std::vector<ZoneRecord> glue_records;
      for (const auto &record : parsed->additionals) {
        const bool address_type = record.type == packet::dns::type_a ||
                                  record.type == packet::dns::type_aaaa;
        const bool named_server = std::any_of(
            nameservers.begin(), nameservers.end(), [&](const auto &name) {
              return same_name(name, record.owner);
            });
        // Glue is usable only for an NS target inside the delegated zone. An
        // unrelated additional address is never promoted to a query target.
        if (!address_type || !named_server ||
            !subdomain(record.owner, delegation->owner))
          continue;
        bool valid{};
        auto owned = own_record(message, record, valid);
        if (!valid || (record.type == packet::dns::type_a &&
                       record.rdata.size() != 4U) ||
            (record.type == packet::dns::type_aaaa &&
             record.rdata.size() != 16U))
          return ResponseStatus::invalid_referral;
        ServerAddress server;
        if (record.type == packet::dns::type_a) {
          server.family = transport::IpFamily::ipv4;
          std::copy_n(record.rdata.begin(), 4U, server.ipv4.begin());
        } else {
          server.family = transport::IpFamily::ipv6;
          std::copy_n(record.rdata.begin(), 16U, server.ipv6.begin());
        }
        if (std::find(next_servers.begin(), next_servers.end(), server) ==
            next_servers.end())
          next_servers.push_back(server);
        glue_records.push_back(std::move(owned));
      }

      if (dnssec_validation) {
        transaction->pending_zone = delegation->owner;
        transaction->pending_ds.clear();
        for (const auto &record : owned_authorities)
          if (record.type == packet::dns::type_ds &&
              same_name(record.owner, delegation->owner))
            transaction->pending_ds.push_back(record);
        if (dnssec_validation->security ==
            dnssec::ResponseSecurity::insecure_delegation) {
          transaction->current_zone = delegation->owner;
          transaction->current_dnskeys.clear();
          transaction->current_dnskeys_valid_until = 0U;
          transaction->pending_ds.clear();
          transaction->chain_security = CacheSecurity::insecure;
        } else if (transaction->pending_ds.empty()) {
          // A secure referral without DS and without an authenticated no-DS
          // result is internally inconsistent and must not advance the chain.
          advance_server(*transaction);
          return transaction->result.status == ResolutionStatus::pending
                     ? ResponseStatus::accepted
                     : ResponseStatus::complete;
        }
      }
      if (next_servers.empty())
      {
        const auto referral_views = views(referral_records);
        if (transaction->cache_allowed &&
            !cache_.insert_positive(referral_views, now,
                                    CacheSecurity::indeterminate))
          return ResponseStatus::resource_exhausted;
        Transaction::ReferralResume resume{
            .original = transaction->original,
            .plan = transaction->plan,
            .visited_aliases = transaction->visited_aliases,
            .nameservers = std::move(nameservers),
            .resolved_addresses = {},
            .stage = transaction->stage,
            .nameserver_index = 0U,
            .resolving_ipv6 = true,
            .current_zone = transaction->current_zone,
            .current_dnskeys = transaction->current_dnskeys,
            .current_dnskeys_valid_until =
                transaction->current_dnskeys_valid_until,
            .pending_zone = transaction->pending_zone,
            .pending_ds = transaction->pending_ds,
            .chain_security = transaction->chain_security,
            .dnssec_phase = transaction->dnssec_phase,
            .validation_failure_seen =
                transaction->validation_failure_seen,
            .checking_disabled = transaction->checking_disabled,
            .cache_allowed = transaction->cache_allowed};
        transaction->referral_stack.push_back(std::move(resume));
        if (!start_nameserver_address_lookup(*transaction))
          return transaction->result.status == ResolutionStatus::pending
                     ? ResponseStatus::invalid_referral
                     : ResponseStatus::complete;
        return ResponseStatus::accepted;
      }
      const auto referral_views = views(referral_records);
      const auto glue_views = views(glue_records);
      if (transaction->cache_allowed &&
          (!cache_.insert_positive(referral_views, now,
                                   CacheSecurity::indeterminate) ||
           !cache_.insert_positive(glue_views, now,
                                   CacheSecurity::indeterminate)))
        return ResponseStatus::resource_exhausted;
      transaction->servers = std::move(next_servers);
      transaction->server_index = 0U;
      transaction->attempts = 0U;
      transaction->force_tcp = false;
      if (!transaction->pending_ds.empty()) {
        transaction->active_question = {
            .name = transaction->pending_zone,
            .type = packet::dns::type_dnskey,
            .record_class = transaction->original.record_class};
        transaction->dnssec_phase = DnssecPhase::child_dnskey;
      } else if (transaction->stage + 1U < transaction->plan.size()) {
        ++transaction->stage;
      }
      return ResponseStatus::accepted;
    }

    const auto received_answer_count = owned_answers.size();
    const auto reachable_names = filter_relevant_answers(
        owned_answers, transaction->active_question.name);
    if (received_answer_count != 0U && owned_answers.empty())
      return ResponseStatus::malformed;
    const auto answer_views = views(owned_answers);
    if (transaction->cache_allowed && !answer_views.empty() &&
        !cache_.insert_positive(answer_views, now, response_security))
      return ResponseStatus::resource_exhausted;

    const auto soa = std::find_if(
        owned_authorities.begin(), owned_authorities.end(),
        [](const auto &record) { return record.type == packet::dns::type_soa; });
    if (parsed->header.rcode == packet::dns::Rcode::name_error) {
      if (soa != owned_authorities.end()) {
        const auto ttl = negative_ttl(*soa);
        const RecordData soa_view{.owner = soa->owner,
                                  .type = soa->type,
                                  .record_class = soa->record_class,
                                  .ttl = ttl,
                                  .rdata = soa->rdata};
        // A zero negative TTL is a valid instruction not to cache. It does not
        // turn an otherwise valid NXDOMAIN response into resource exhaustion.
        if (transaction->cache_allowed && ttl != 0U &&
            !cache_.insert_negative(transaction->active_question.name,
                                    transaction->active_question.type,
                                    transaction->active_question.record_class,
                                    NegativeKind::name_error, soa_view, now,
                                    response_security))
          return ResponseStatus::resource_exhausted;
      }
      if (!transaction->referral_stack.empty()) {
        finish_nameserver_address_lookup(*transaction, {});
        return transaction->result.status == ResolutionStatus::pending
                   ? ResponseStatus::accepted
                   : ResponseStatus::complete;
      }
      transaction->result.authorities = std::move(owned_authorities);
      transaction->result.status = ResolutionStatus::name_error;
      transaction->result.security = response_security;
      return ResponseStatus::complete;
    }
    if (parsed->header.rcode != packet::dns::Rcode::no_error) {
      advance_server(*transaction);
      return transaction->result.status == ResolutionStatus::pending
                 ? ResponseStatus::accepted
                 : ResponseStatus::complete;
    }

    if (transaction->stage + 1U < transaction->plan.size()) {
      ++transaction->stage;
      transaction->attempts = 0U;
      transaction->force_tcp = false;
      return ResponseStatus::accepted;
    }

    const auto direct = std::find_if(
        owned_answers.begin(), owned_answers.end(), [&](const auto &record) {
          return record.type == transaction->original.type &&
                 std::any_of(reachable_names.begin(), reachable_names.end(),
                             [&](const auto &name) {
                               return same_name(record.owner, name);
                             });
        });
    if (direct != owned_answers.end()) {
      if (!transaction->referral_stack.empty() &&
          (transaction->original.type == packet::dns::type_a ||
           transaction->original.type == packet::dns::type_aaaa)) {
        std::vector<ServerAddress> discovered;
        for (const auto &record : owned_answers) {
          if (record.type != transaction->original.type ||
              std::none_of(reachable_names.begin(), reachable_names.end(),
                           [&](const auto &name) {
                             return same_name(record.owner, name);
                           }))
            continue;
          ServerAddress address;
          if (record.type == packet::dns::type_a && record.rdata.size() == 4U) {
            address.family = transport::IpFamily::ipv4;
            std::copy_n(record.rdata.begin(), 4U, address.ipv4.begin());
          } else if (record.type == packet::dns::type_aaaa &&
                     record.rdata.size() == 16U) {
            address.family = transport::IpFamily::ipv6;
            std::copy_n(record.rdata.begin(), 16U, address.ipv6.begin());
          } else {
            continue;
          }
          discovered.push_back(address);
        }
        finish_nameserver_address_lookup(*transaction, discovered);
        return transaction->result.status == ResolutionStatus::pending
                   ? ResponseStatus::accepted
                   : ResponseStatus::complete;
      }
      transaction->result.answers.insert(
          transaction->result.answers.end(),
          std::make_move_iterator(owned_answers.begin()),
          std::make_move_iterator(owned_answers.end()));
      transaction->result.status = ResolutionStatus::success;
      transaction->result.security = response_security;
      return ResponseStatus::complete;
    }

    const auto alias = std::find_if(
        owned_answers.begin(), owned_answers.end(), [&](const auto &record) {
          return record.type == packet::dns::type_cname &&
                 same_name(record.owner, transaction->active_question.name);
        });
    if (alias != owned_answers.end()) {
      Name target;
      const auto consumed = packet::dns::parse_name(alias->rdata, 0U, target);
      const bool loop = !consumed || *consumed != alias->rdata.size() ||
                        std::any_of(transaction->visited_aliases.begin(),
                                    transaction->visited_aliases.end(),
                                    [&](const auto &seen) {
                                      return same_name(seen, target);
                                    });
      if (loop || transaction->visited_aliases.size() >=
                      policy_.maximum_alias_hops) {
        transaction->result.status = ResolutionStatus::alias_loop;
        return ResponseStatus::complete;
      }
      if (transaction->referral_stack.empty())
        transaction->result.answers.insert(
            transaction->result.answers.end(),
            std::make_move_iterator(owned_answers.begin()),
            std::make_move_iterator(owned_answers.end()));
      transaction->visited_aliases.push_back(target);
      transaction->original.name = target;
      transaction->plan = build_minimisation_plan(target, policy_);
      transaction->stage = 0U;
      if (!reset_to_roots(*transaction))
        return ResponseStatus::complete;
      if (!restart_validation_from_root(*transaction))
        return ResponseStatus::complete;
      return ResponseStatus::accepted;
    }

    if (soa != owned_authorities.end()) {
      const auto ttl = negative_ttl(*soa);
      const RecordData soa_view{.owner = soa->owner,
                                .type = soa->type,
                                .record_class = soa->record_class,
                                .ttl = ttl,
                                .rdata = soa->rdata};
      if (transaction->cache_allowed && ttl != 0U &&
          !cache_.insert_negative(transaction->active_question.name,
                                  transaction->active_question.type,
                                  transaction->active_question.record_class,
                                  NegativeKind::no_data, soa_view, now,
                                  response_security))
        return ResponseStatus::resource_exhausted;
    }
    if (!transaction->referral_stack.empty()) {
      finish_nameserver_address_lookup(*transaction, {});
      return transaction->result.status == ResolutionStatus::pending
                 ? ResponseStatus::accepted
                 : ResponseStatus::complete;
    }
    transaction->result.authorities = std::move(owned_authorities);
    transaction->result.status = ResolutionStatus::no_data;
    transaction->result.security = response_security;
    return ResponseStatus::complete;
  } catch (const std::bad_alloc &) {
    transaction->result.status = ResolutionStatus::resource_exhausted;
    transaction->awaiting = false;
    return ResponseStatus::resource_exhausted;
  }
}

void IterativeResolver::service(Clock::time_point now) noexcept {
  for (auto &slot : transactions_) {
    if (!slot || !slot->awaiting || slot->deadline > now)
      continue;
    slot->awaiting = false;
    if (slot->attempts >= policy_.attempts_per_server)
      advance_server(*slot);
  }
  cache_.expire(now);
}

std::optional<IterativeResolver::Clock::time_point>
IterativeResolver::next_deadline() const noexcept {
  std::optional<Clock::time_point> result;
  for (const auto &slot : transactions_)
    if (slot && slot->awaiting &&
        (!result || slot->deadline < *result))
      result = slot->deadline;
  return result;
}

std::optional<ResolutionResult>
IterativeResolver::result(TransactionHandle handle) const {
  const auto *transaction = find(handle);
  if (!transaction || transaction->result.status == ResolutionStatus::pending)
    return std::nullopt;
  return transaction->result;
}

bool IterativeResolver::release(TransactionHandle handle) noexcept {
  if (!find(handle))
    return false;
  transactions_[handle.index].reset();
  auto &generation = generations_[handle.index];
  if (++generation == 0U)
    generation = 1U;
  return true;
}

ResolverCheckpoint
IterativeResolver::checkpoint(Clock::time_point now) const {
  ResolverCheckpoint state{.identifier_secret = identifier_secret_,
                           .root_hints = root_hints_,
                           .policy = policy_,
                           .cache = cache_.checkpoint(now),
                           .transactions = {},
                           .generations = generations_,
                           .identifier_counter = identifier_counter_,
                           .preparation_counter = preparation_counter_,
                           .trust_anchors = {trust_anchors_.records().begin(),
                                             trust_anchors_.records().end()},
                           .nsec3_policy = nsec3_policy_,
                           .dnssec_enabled = dnssec_crypto_ != nullptr};
  state.transactions.reserve(transactions_.size());
  for (const auto &slot : transactions_) {
    if (!slot) {
      state.transactions.emplace_back();
      continue;
    }
    ResolverTransactionCheckpoint saved{
        .original = slot->original,
        .active_question = slot->active_question,
        .plan = slot->plan,
        .servers = slot->servers,
        .visited_aliases = slot->visited_aliases,
        .referral_stack = {},
        .result = slot->result,
        .deadline_remaining_nanoseconds =
            slot->awaiting
                ? std::max<std::int64_t>(
                      0,
                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                          slot->deadline - now)
                          .count())
                : 0,
        .active_server = slot->active_server,
        .active_transport = slot->active_transport,
        .stage = slot->stage,
        .server_index = slot->server_index,
        .attempts = slot->attempts,
        .prepared_token = slot->prepared_token,
        .active_id = slot->active_id,
        .awaiting = slot->awaiting,
        .force_tcp = slot->force_tcp,
        .current_zone = slot->current_zone,
        .current_dnskeys = slot->current_dnskeys,
        .current_dnskeys_valid_until =
            slot->current_dnskeys_valid_until,
        .pending_zone = slot->pending_zone,
        .pending_ds = slot->pending_ds,
        .chain_security = slot->chain_security,
        .dnssec_phase = slot->dnssec_phase,
        .validation_failure_seen = slot->validation_failure_seen,
        .checking_disabled = slot->checking_disabled,
        .cache_allowed = slot->cache_allowed};
    saved.referral_stack.reserve(slot->referral_stack.size());
    for (const auto &resume : slot->referral_stack)
      saved.referral_stack.push_back(
          {.original = resume.original,
           .plan = resume.plan,
           .visited_aliases = resume.visited_aliases,
           .nameservers = resume.nameservers,
           .resolved_addresses = resume.resolved_addresses,
           .stage = resume.stage,
           .nameserver_index = resume.nameserver_index,
           .resolving_ipv6 = resume.resolving_ipv6,
           .current_zone = resume.current_zone,
           .current_dnskeys = resume.current_dnskeys,
           .current_dnskeys_valid_until =
               resume.current_dnskeys_valid_until,
           .pending_zone = resume.pending_zone,
           .pending_ds = resume.pending_ds,
           .chain_security = resume.chain_security,
           .dnssec_phase = resume.dnssec_phase,
           .validation_failure_seen = resume.validation_failure_seen,
           .checking_disabled = resume.checking_disabled,
           .cache_allowed = resume.cache_allowed});
    state.transactions.emplace_back(std::move(saved));
  }
  return state;
}

bool IterativeResolver::restore(const ResolverCheckpoint &state,
                                Clock::time_point now) noexcept {
  const auto valid_policy =
      state.policy.retry_interval.count() > 0 &&
      state.policy.attempts_per_server != 0U &&
      state.policy.maximum_minimise_count != 0U &&
      state.policy.maximum_alias_hops != 0U &&
      state.policy.advertised_udp_payload_bytes >= 512U;
  if (!valid_policy || state.identifier_counter == 0U ||
      state.preparation_counter == 0U ||
      state.transactions.size() != state.generations.size() ||
      state.transactions.size() >
          static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    return false;
  const auto valid_security = [](CacheSecurity security) noexcept {
    return static_cast<std::uint8_t>(security) <=
           static_cast<std::uint8_t>(CacheSecurity::secure);
  };
  const auto valid_phase = [](DnssecPhase phase) noexcept {
    return static_cast<std::uint8_t>(phase) <=
           static_cast<std::uint8_t>(DnssecPhase::child_dnskey);
  };
  if ((state.dnssec_enabled &&
       (state.trust_anchors.empty() || !dnssec_crypto_ || !dnssec_digests_ ||
        !wall_clock_seconds_)) ||
      (!state.dnssec_enabled && !state.trust_anchors.empty()) ||
      std::any_of(state.trust_anchors.begin(), state.trust_anchors.end(),
                  [](const auto &record) {
                    return !valid_owned_record(record) ||
                           record.type != packet::dns::type_dnskey;
                  }))
    return false;
  for (const auto &hint : state.root_hints) {
    if (!valid_name(hint.server_name) || hint.addresses.empty() ||
        std::any_of(hint.addresses.begin(), hint.addresses.end(),
                    [](const auto &address) {
                      return !valid_server(address);
                    }))
      return false;
  }
  try {
    IterativeResolver candidate{state.identifier_secret, state.root_hints,
                                state.policy};
    if (state.dnssec_enabled) {
      dnssec::TrustAnchorStore anchors;
      for (const auto &anchor : state.trust_anchors)
        if (anchors.add(anchor) != dnssec::AnchorMutation::applied)
          return false;
      if (!candidate.enable_dnssec(
              {.crypto = dnssec_crypto_,
               .digests = dnssec_digests_,
               .wall_clock_seconds = wall_clock_seconds_,
               .wall_clock_context = wall_clock_context_,
               .trust_anchors = std::move(anchors),
               .nsec3_policy = state.nsec3_policy}))
        return false;
    }
    if (!candidate.cache_.restore(state.cache, now))
      return false;
    candidate.generations_ = state.generations;
    candidate.transactions_.resize(state.transactions.size());
    candidate.identifier_counter_ = state.identifier_counter;
    candidate.preparation_counter_ = state.preparation_counter;
    for (std::size_t index = 0U; index < state.transactions.size(); ++index) {
      if (state.generations[index] == 0U)
        return false;
      if (!state.transactions[index])
        continue;
      const auto &saved = *state.transactions[index];
      if (!valid_question(saved.original) ||
          !valid_question(saved.active_question) || saved.plan.empty() ||
          saved.stage >= saved.plan.size() ||
          saved.server_index > saved.servers.size() ||
          !valid_question(saved.result.original_question) ||
          static_cast<std::uint8_t>(saved.result.status) >
              static_cast<std::uint8_t>(
                  ResolutionStatus::resource_exhausted) ||
          !valid_security(saved.result.security) ||
          !valid_security(saved.chain_security) ||
          !valid_phase(saved.dnssec_phase) ||
          (!state.dnssec_enabled &&
           saved.dnssec_phase != DnssecPhase::disabled) ||
          (state.dnssec_enabled &&
           saved.result.status == ResolutionStatus::pending &&
           saved.dnssec_phase == DnssecPhase::disabled &&
           !saved.checking_disabled) ||
          (saved.dnssec_phase != DnssecPhase::disabled &&
           !valid_name(saved.current_zone)) ||
          ((saved.dnssec_phase == DnssecPhase::ordinary ||
            saved.dnssec_phase == DnssecPhase::child_dnskey) &&
           saved.chain_security == CacheSecurity::secure &&
           (saved.current_dnskeys.empty() ||
            saved.current_dnskeys_valid_until == 0U)) ||
          (saved.dnssec_phase == DnssecPhase::child_dnskey &&
           (!valid_name(saved.pending_zone) || saved.pending_ds.empty())) ||
          std::any_of(saved.current_dnskeys.begin(),
                      saved.current_dnskeys.end(), [](const auto &record) {
                        return !valid_owned_record(record) ||
                               record.type != packet::dns::type_dnskey;
                      }) ||
          std::any_of(saved.pending_ds.begin(), saved.pending_ds.end(),
                      [](const auto &record) {
                        return !valid_owned_record(record) ||
                               record.type != packet::dns::type_ds;
                      }) ||
          std::any_of(saved.result.answers.begin(),
                      saved.result.answers.end(), [](const auto &record) {
                        return !valid_owned_record(record);
                      }) ||
          std::any_of(saved.result.authorities.begin(),
                      saved.result.authorities.end(), [](const auto &record) {
                        return !valid_owned_record(record);
                      }) ||
          std::any_of(saved.plan.begin(), saved.plan.end(),
                      [](const auto &name) { return !valid_name(name); }) ||
          std::any_of(saved.servers.begin(), saved.servers.end(),
                      [](const auto &server) {
                        return !valid_server(server);
                      }) ||
          saved.visited_aliases.empty() ||
          saved.visited_aliases.size() >
              state.policy.maximum_alias_hops ||
          std::any_of(saved.visited_aliases.begin(),
                      saved.visited_aliases.end(),
                      [](const auto &name) { return !valid_name(name); }) ||
          (saved.awaiting && saved.prepared_token != 0U) ||
          (saved.awaiting && !valid_server(saved.active_server)) ||
          (saved.checking_disabled && saved.cache_allowed &&
           state.dnssec_enabled) ||
          static_cast<std::uint8_t>(saved.active_transport) >
              static_cast<std::uint8_t>(QueryTransport::tcp) ||
          saved.attempts > state.policy.attempts_per_server ||
          saved.deadline_remaining_nanoseconds < 0 ||
          (saved.result.status == ResolutionStatus::pending &&
           (saved.servers.empty() ||
            saved.server_index >= saved.servers.size())))
        return false;

      Transaction restored{
          .original = saved.original,
          .active_question = saved.active_question,
          .plan = saved.plan,
          .servers = saved.servers,
          .visited_aliases = saved.visited_aliases,
          .referral_stack = {},
          .result = saved.result,
          .deadline = saved.awaiting
                          ? now + std::chrono::nanoseconds{
                                      saved.deadline_remaining_nanoseconds}
                          : Clock::time_point{},
          .active_server = saved.active_server,
          .active_transport = saved.active_transport,
          .stage = saved.stage,
          .server_index = saved.server_index,
          .attempts = saved.attempts,
          .prepared_token = saved.prepared_token,
          .active_id = saved.active_id,
          .occupied = true,
          .awaiting = saved.awaiting,
          .force_tcp = saved.force_tcp,
          .current_zone = saved.current_zone,
          .current_dnskeys = saved.current_dnskeys,
          .current_dnskeys_valid_until =
              saved.current_dnskeys_valid_until,
          .pending_zone = saved.pending_zone,
          .pending_ds = saved.pending_ds,
          .chain_security = saved.chain_security,
          .dnssec_phase = saved.dnssec_phase,
          .validation_failure_seen = saved.validation_failure_seen,
          .checking_disabled = saved.checking_disabled,
          .cache_allowed = saved.cache_allowed};
      restored.referral_stack.reserve(saved.referral_stack.size());
      for (const auto &resume : saved.referral_stack) {
        if (!valid_question(resume.original) || resume.plan.empty() ||
            resume.stage >= resume.plan.size() || resume.nameservers.empty() ||
            resume.nameserver_index >= resume.nameservers.size() ||
            std::any_of(resume.plan.begin(), resume.plan.end(),
                        [](const auto &name) { return !valid_name(name); }) ||
            std::any_of(resume.visited_aliases.begin(),
                        resume.visited_aliases.end(),
                        [](const auto &name) { return !valid_name(name); }) ||
            std::any_of(resume.nameservers.begin(), resume.nameservers.end(),
                        [](const auto &name) { return !valid_name(name); }) ||
            std::any_of(resume.resolved_addresses.begin(),
                        resume.resolved_addresses.end(),
                        [](const auto &server) {
                          return !valid_server(server);
                        }) ||
            !valid_security(resume.chain_security) ||
            !valid_phase(resume.dnssec_phase) ||
            (!state.dnssec_enabled &&
             resume.dnssec_phase != DnssecPhase::disabled) ||
            (state.dnssec_enabled &&
             resume.dnssec_phase == DnssecPhase::disabled &&
             !resume.checking_disabled) ||
            resume.checking_disabled != saved.checking_disabled ||
            resume.cache_allowed != saved.cache_allowed ||
            (resume.dnssec_phase != DnssecPhase::disabled &&
             !valid_name(resume.current_zone)) ||
            ((resume.dnssec_phase == DnssecPhase::ordinary ||
              resume.dnssec_phase == DnssecPhase::child_dnskey) &&
             resume.chain_security == CacheSecurity::secure &&
             (resume.current_dnskeys.empty() ||
              resume.current_dnskeys_valid_until == 0U)) ||
            (resume.dnssec_phase == DnssecPhase::child_dnskey &&
             (!valid_name(resume.pending_zone) || resume.pending_ds.empty())) ||
            std::any_of(resume.current_dnskeys.begin(),
                        resume.current_dnskeys.end(), [](const auto &record) {
                          return !valid_owned_record(record) ||
                                 record.type != packet::dns::type_dnskey;
                        }) ||
            std::any_of(resume.pending_ds.begin(), resume.pending_ds.end(),
                        [](const auto &record) {
                          return !valid_owned_record(record) ||
                                 record.type != packet::dns::type_ds;
                        }))
          return false;
        restored.referral_stack.push_back(
            {.original = resume.original,
             .plan = resume.plan,
             .visited_aliases = resume.visited_aliases,
             .nameservers = resume.nameservers,
             .resolved_addresses = resume.resolved_addresses,
             .stage = resume.stage,
             .nameserver_index = resume.nameserver_index,
             .resolving_ipv6 = resume.resolving_ipv6,
             .current_zone = resume.current_zone,
             .current_dnskeys = resume.current_dnskeys,
             .current_dnskeys_valid_until =
                 resume.current_dnskeys_valid_until,
             .pending_zone = resume.pending_zone,
             .pending_ds = resume.pending_ds,
             .chain_security = resume.chain_security,
             .dnssec_phase = resume.dnssec_phase,
             .validation_failure_seen = resume.validation_failure_seen,
             .checking_disabled = resume.checking_disabled,
             .cache_allowed = resume.cache_allowed});
      }
      candidate.transactions_[index] = std::move(restored);
    }
    identifier_secret_ = candidate.identifier_secret_;
    root_hints_ = std::move(candidate.root_hints_);
    policy_ = candidate.policy_;
    cache_ = std::move(candidate.cache_);
    transactions_ = std::move(candidate.transactions_);
    generations_ = std::move(candidate.generations_);
    identifier_counter_ = candidate.identifier_counter_;
    preparation_counter_ = candidate.preparation_counter_;
    dnssec_crypto_ = candidate.dnssec_crypto_;
    dnssec_digests_ = candidate.dnssec_digests_;
    wall_clock_seconds_ = candidate.wall_clock_seconds_;
    wall_clock_context_ = candidate.wall_clock_context_;
    trust_anchors_ = std::move(candidate.trust_anchors_);
    nsec3_policy_ = candidate.nsec3_policy_;
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::dns
