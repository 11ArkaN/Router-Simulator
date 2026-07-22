// Action-driven iterative DNS resolver. One service shard owns transactions,
// cache and server-selection state. It emits encoded query intents but cannot
// access UDP, TCP, routing, topology or another endpoint directly.

#pragma once

#include "router/dns_cache.hpp"
#include "router/dns_authoritative.hpp"
#include "router/dnssec_chain.hpp"
#include "router/dnssec_response_validation.hpp"
#include "router/ip_address.hpp"
#include "router/sha256.hpp"
#include "router/udp_transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dns {

enum class QueryTransport : std::uint8_t { udp, tcp };

enum class DnssecPhase : std::uint8_t {
  disabled,
  root_dnskey,
  ordinary,
  child_dnskey
};

struct ResolverDnssecConfiguration {
  using WallClockSeconds = std::uint32_t (*)(void *context) noexcept;

  const dnssec::CryptoVerifier *crypto{};
  const dnssec::DigestCalculator *digests{};
  // DNSSEC signature inception and expiration are expressed as POSIX seconds,
  // while resolver retransmission timers use steady_clock. Keeping the wall
  // clock behind an injected callback prevents tests and checkpoint restore
  // from silently depending on the machine clock.
  WallClockSeconds wall_clock_seconds{};
  void *wall_clock_context{};
  dnssec::TrustAnchorStore trust_anchors;
  dnssec::Nsec3IterationPolicy nsec3_policy{};
};

struct ServerAddress {
  transport::IpFamily family{transport::IpFamily::ipv6};
  ip::Ipv4 ipv4{};
  ip::Ipv6 ipv6{};
  // Link-local servers require a stable interface zone. Global addresses and
  // IPv4 use zero unless policy pins them to one outgoing interface.
  std::uint64_t interface_id{};

  [[nodiscard]] bool operator==(const ServerAddress &) const noexcept = default;
};

struct RootHint {
  packet::dns::Name server_name;
  std::vector<ServerAddress> addresses;
};

struct ResolverPolicy {
  std::chrono::milliseconds retry_interval{
      device_catalog::dns_resolver_retry_milliseconds};
  std::uint16_t advertised_udp_payload_bytes{
      device_catalog::dns_resolver_advertised_udp_payload_bytes};
  std::uint32_t attempts_per_server{
      device_catalog::dns_resolver_attempts_per_server};
  std::uint32_t maximum_minimise_count{
      device_catalog::dns_resolver_max_minimise_count};
  std::uint32_t minimise_one_label_count{
      device_catalog::dns_resolver_minimise_one_label_count};
  std::uint32_t maximum_alias_hops{
      device_catalog::dns_resolver_max_alias_hops};
};

struct TransactionHandle {
  std::uint32_t index{};
  std::uint32_t generation{};
  [[nodiscard]] bool operator==(const TransactionHandle &) const noexcept =
      default;
};

struct PreparedQuery {
  ServerAddress server;
  packet::dns::Question question;
  QueryTransport transport{QueryTransport::udp};
  std::uint64_t preparation_token{};
  std::size_t message_octets{};
  std::uint16_t id{};

  [[nodiscard]] explicit operator bool() const noexcept {
    return preparation_token != 0U;
  }
};

enum class PrepareQueryStatus : std::uint8_t {
  prepared,
  awaiting_response,
  complete,
  invalid_transaction,
  buffer_too_small,
  no_reachable_server,
  resource_exhausted
};

struct PrepareQueryResult {
  PrepareQueryStatus status{PrepareQueryStatus::invalid_transaction};
  PreparedQuery query{};
};

enum class ResponseStatus : std::uint8_t {
  accepted,
  complete,
  ignored_source,
  ignored_transport,
  ignored_identifier,
  malformed,
  mismatched_question,
  invalid_referral,
  resource_exhausted,
  invalid_transaction
};

enum class ResolutionStatus : std::uint8_t {
  pending,
  success,
  name_error,
  no_data,
  server_failure,
  alias_loop,
  no_reachable_server,
  resource_exhausted
};

struct ResolutionResult {
  packet::dns::Question original_question;
  std::vector<ZoneRecord> answers;
  std::vector<ZoneRecord> authorities;
  ResolutionStatus status{ResolutionStatus::pending};
  // Security is meaningful only after status leaves pending. The resolver
  // never maps bogus validation to success; it returns server_failure unless
  // a checking-disabled client explicitly requested unchecked data.
  CacheSecurity security{CacheSecurity::indeterminate};
};

struct ReferralResumeCheckpoint {
  packet::dns::Question original;
  std::vector<packet::dns::Name> plan;
  std::vector<packet::dns::Name> visited_aliases;
  std::vector<packet::dns::Name> nameservers;
  std::vector<ServerAddress> resolved_addresses;
  std::size_t stage{};
  std::size_t nameserver_index{};
  bool resolving_ipv6{true};
  packet::dns::Name current_zone;
  std::vector<ZoneRecord> current_dnskeys;
  std::uint32_t current_dnskeys_valid_until{};
  packet::dns::Name pending_zone;
  std::vector<ZoneRecord> pending_ds;
  CacheSecurity chain_security{CacheSecurity::indeterminate};
  DnssecPhase dnssec_phase{DnssecPhase::disabled};
  bool validation_failure_seen{};
  bool checking_disabled{};
  bool cache_allowed{true};
};

struct ResolverTransactionCheckpoint {
  packet::dns::Question original;
  packet::dns::Question active_question;
  std::vector<packet::dns::Name> plan;
  std::vector<ServerAddress> servers;
  std::vector<packet::dns::Name> visited_aliases;
  std::vector<ReferralResumeCheckpoint> referral_stack;
  ResolutionResult result;
  std::int64_t deadline_remaining_nanoseconds{};
  ServerAddress active_server{};
  QueryTransport active_transport{QueryTransport::udp};
  std::size_t stage{};
  std::size_t server_index{};
  std::uint32_t attempts{};
  std::uint64_t prepared_token{};
  std::uint16_t active_id{};
  bool awaiting{};
  bool force_tcp{};
  packet::dns::Name current_zone;
  std::vector<ZoneRecord> current_dnskeys;
  std::uint32_t current_dnskeys_valid_until{};
  packet::dns::Name pending_zone;
  std::vector<ZoneRecord> pending_ds;
  CacheSecurity chain_security{CacheSecurity::indeterminate};
  DnssecPhase dnssec_phase{DnssecPhase::disabled};
  bool validation_failure_seen{};
  bool checking_disabled{};
  bool cache_allowed{true};
};

struct ResolverCheckpoint {
  crypto::Sha256Digest identifier_secret{};
  std::vector<RootHint> root_hints;
  ResolverPolicy policy{};
  CacheCheckpoint cache;
  std::vector<std::optional<ResolverTransactionCheckpoint>> transactions;
  std::vector<std::uint32_t> generations;
  std::uint64_t identifier_counter{1U};
  std::uint64_t preparation_counter{1U};
  std::vector<ZoneRecord> trust_anchors;
  dnssec::Nsec3IterationPolicy nsec3_policy{};
  bool dnssec_enabled{};
};

class IterativeResolver final {
public:
  using Clock = std::chrono::steady_clock;

  IterativeResolver(crypto::Sha256Digest identifier_secret,
                    std::vector<RootHint> root_hints,
                    ResolverPolicy policy = {});
  ~IterativeResolver();
  IterativeResolver(const IterativeResolver &) = delete;
  IterativeResolver &operator=(const IterativeResolver &) = delete;

  // Providers remain externally owned because they are process-wide crypto
  // adapters, not resolver state. Anchors are copied into the resolver. The
  // call is allowed only before the first transaction so a validation policy
  // cannot change under active queries or cached security classifications.
  [[nodiscard]] bool
  enable_dnssec(ResolverDnssecConfiguration configuration) noexcept;

  // begin first consults the positive and negative cache. Otherwise it creates
  // an owner-affine transaction with root-hint addresses copied into SLIST.
  [[nodiscard]] std::optional<TransactionHandle>
  begin(const packet::dns::Question &question,
        Clock::time_point now = Clock::now(),
        bool checking_disabled = false) noexcept;

  // prepare writes a DNS message but does not start any timer. The forwarding
  // owner must call commit only after the UDP datagram or TCP stream bytes are
  // admitted to its queue. discard leaves retry and query state unchanged.
  [[nodiscard]] PrepareQueryResult
  prepare(TransactionHandle handle, std::span<std::uint8_t> output,
          Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool commit(TransactionHandle handle,
                            const PreparedQuery &query,
                            Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool discard(TransactionHandle handle,
                             const PreparedQuery &query) noexcept;

  [[nodiscard]] ResponseStatus
  receive(TransactionHandle handle, const ServerAddress &source,
          QueryTransport transport, std::span<const std::uint8_t> message,
          Clock::time_point now = Clock::now()) noexcept;
  void service(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  [[nodiscard]] std::optional<ResolutionResult>
  result(TransactionHandle handle) const;
  [[nodiscard]] bool release(TransactionHandle handle) noexcept;
  [[nodiscard]] ResolverCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(const ResolverCheckpoint &state,
                             Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] ResolverCache &cache() noexcept { return cache_; }
  [[nodiscard]] const ResolverCache &cache() const noexcept { return cache_; }

private:
  struct Transaction;
  [[nodiscard]] Transaction *find(TransactionHandle handle) noexcept;
  [[nodiscard]] const Transaction *find(TransactionHandle handle) const noexcept;
  [[nodiscard]] std::uint16_t next_identifier(const Transaction &transaction,
                                              const ServerAddress &server) noexcept;
  [[nodiscard]] bool reset_to_roots(Transaction &transaction) noexcept;
  [[nodiscard]] bool restart_validation_from_root(
      Transaction &transaction) noexcept;
  void advance_server(Transaction &transaction) noexcept;
  [[nodiscard]] bool start_nameserver_address_lookup(
      Transaction &transaction) noexcept;
  void finish_nameserver_address_lookup(
      Transaction &transaction,
      std::span<const ServerAddress> discovered) noexcept;

  crypto::Sha256Digest identifier_secret_{};
  std::vector<RootHint> root_hints_;
  ResolverPolicy policy_{};
  ResolverCache cache_{};
  std::vector<std::optional<Transaction>> transactions_;
  std::vector<std::uint32_t> generations_;
  std::uint64_t identifier_counter_{1U};
  std::uint64_t preparation_counter_{1U};
  const dnssec::CryptoVerifier *dnssec_crypto_{};
  const dnssec::DigestCalculator *dnssec_digests_{};
  ResolverDnssecConfiguration::WallClockSeconds wall_clock_seconds_{};
  void *wall_clock_context_{};
  dnssec::TrustAnchorStore trust_anchors_{};
  dnssec::Nsec3IterationPolicy nsec3_policy_{};
};

// Exposed for deterministic tests and operational inspection. The returned
// names progress from one label below the known root to the original QNAME;
// generated policy bounds work, not the legal DNS name length.
[[nodiscard]] std::vector<packet::dns::Name>
build_minimisation_plan(const packet::dns::Name &qname,
                        const ResolverPolicy &policy);

} // namespace router::dns
