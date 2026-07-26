// DHCPv6 relay lease-state tests cover wire-derived client correlation,
// atomic admission limits, status handling, PD Exclude, expiry and restart.
// They deliberately use encoded messages instead of inserting repository
// records so the same option grammar used on a live relay is exercised.

#include "router/dhcpv6_relay_lease.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace {

using router::packet::dhcpv6::OptionCode;

void put_u16(std::vector<std::uint8_t> &bytes, std::uint16_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_option(std::vector<std::uint8_t> &bytes, OptionCode code,
                   std::span<const std::uint8_t> body) {
  // Tests use the same four-octet TLV header as the production cursor. Keep
  // this tiny fixture writer independent from the message Writer because IA
  // bodies contain a raw option stream without a DHCP message header.
  if (body.size() > 0xffffU)
    throw std::runtime_error("DHCPv6 relay test option is too large");
  put_u16(bytes, static_cast<std::uint16_t>(code));
  put_u16(bytes, static_cast<std::uint16_t>(body.size()));
  bytes.insert(bytes.end(), body.begin(), body.end());
}

std::vector<std::uint8_t> client_message(
    router::packet::dhcpv6::MessageType type, std::uint32_t transaction_id,
    OptionCode association_code, std::uint32_t iaid,
    std::span<const std::uint8_t> association_options = {}) {
  using namespace router::packet::dhcpv6;
  constexpr std::array<std::uint8_t, 8U> duid{0U, 3U, 0U, 1U,
                                               2U, 0U, 0U, 1U};
  constexpr std::array<std::uint8_t, 8U> server_duid{
      0U, 3U, 0U, 1U, 2U, 0U, 0U, 0xfeU};
  std::array<std::uint8_t, 512U> association_body{};
  const auto association_size =
      association_code == OptionCode::ia_ta
          ? encode_ia_ta(association_body, iaid, association_options)
          : encode_ia_na_or_pd(association_body, iaid, 30U, 50U,
                               association_options);
  std::array<std::uint8_t, 1024U> message_storage{};
  auto writer = begin_client_server(message_storage,
                                    static_cast<std::uint8_t>(type),
                                    transaction_id);
  if (!association_size || !writer ||
      !writer->append(static_cast<std::uint16_t>(
                          OptionCode::client_identifier),
                      duid))
    throw std::runtime_error("DHCPv6 relay test message encoding failed");
  // RFC 9915 requires Reply to carry Server Identifier while Solicit normally
  // does not. Keeping that distinction in fixtures catches accidental parser
  // coupling between client observation and server-bound lease creation.
  if (type == MessageType::reply &&
      !writer->append(static_cast<std::uint16_t>(
                          OptionCode::server_identifier),
                      server_duid))
    throw std::runtime_error("DHCPv6 relay Server DUID encoding failed");
  if (!writer->append(static_cast<std::uint16_t>(association_code),
                      std::span<const std::uint8_t>{association_body}.first(
                          *association_size)))
    throw std::runtime_error("DHCPv6 relay IA encoding failed");
  return {writer->view().begin(), writer->view().end()};
}

std::vector<std::uint8_t>
address_options(router::packet::Ipv6 address, std::uint32_t preferred,
                std::uint32_t valid) {
  std::array<std::uint8_t, 64U> body{};
  const auto body_size = router::packet::dhcpv6::encode_ia_address(
      body, address, preferred, valid);
  if (!body_size)
    throw std::runtime_error("DHCPv6 relay test IAADDR encoding failed");
  std::vector<std::uint8_t> result;
  append_option(result, OptionCode::ia_address,
                std::span<const std::uint8_t>{body}.first(*body_size));
  return result;
}

std::vector<std::uint8_t> prefix_options(router::packet::Ipv6 prefix,
                                         std::uint8_t prefix_length,
                                         std::uint32_t preferred,
                                         std::uint32_t valid) {
  // RFC 6603's /59 to /64 example encodes five subnet-id bits as 01111 and
  // leaves three zero padding bits. OPTION_PD_EXCLUDE is nested in IAPREFIX,
  // never beside it in IA_PD.
  constexpr std::array<std::uint8_t, 2U> excluded{64U, 0x78U};
  std::vector<std::uint8_t> prefix_children;
  append_option(prefix_children, OptionCode::prefix_exclude, excluded);
  std::array<std::uint8_t, 128U> body{};
  const auto body_size = router::packet::dhcpv6::encode_ia_prefix(
      body, prefix, prefix_length, preferred, valid, prefix_children);
  if (!body_size)
    throw std::runtime_error("DHCPv6 relay test IAPREFIX encoding failed");
  std::vector<std::uint8_t> result;
  append_option(result, OptionCode::ia_prefix,
                std::span<const std::uint8_t>{body}.first(*body_size));
  return result;
}

} // namespace

void dhcpv6_relay_lease_tests() {
  using namespace router;
  using namespace router::dhcpv6;
  using namespace router::packet::dhcpv6;

  const auto client_prefix = ip::parse_ipv6_prefix("2001:db8:1::/64");
  const auto peer = ip::parse_ipv6("fe80::100");
  const auto address = ip::parse_ipv6("2001:db8:1::100");
  const auto second_address = ip::parse_ipv6("2001:db8:1::101");
  const auto delegated = ip::parse_ipv6("2001:db8:dead:bee0::");
  const auto excluded = ip::parse_ipv6("2001:db8:dead:beef::");
  const auto server_address = ip::parse_ipv6("2001:db8:ffff::1");
  if (!client_prefix || !peer || !address || !second_address || !delegated ||
      !excluded || !server_address)
    throw std::runtime_error("DHCPv6 relay lease fixture address is invalid");

  constexpr std::uint64_t interface_id = 71U;
  constexpr std::uint32_t transaction_id = 0x123456U;
  constexpr packet::Mac client_mac{0x02U, 0U, 0U, 0U, 0U, 7U};
  const RelayLeasePolicy policy{
      .interface_id = interface_id,
      .physical_port_ordinal = 3U,
      .client_prefix = *client_prefix,
      .maximum_leases = 1U,
      .neighbor_resolution = true,
      .route_non_temporary = true,
      .route_temporary = true,
      .route_delegated_prefix = true,
      .route_prefix_exclude = true};
  RelayLeaseRepository repository;
  if (!repository.configure(std::span{&policy, 1U}))
    throw std::runtime_error("DHCPv6 relay lease policy was rejected");

  const auto start = RelayLeaseRepository::Clock::time_point{} +
                     std::chrono::seconds{1000};
  const auto solicit = client_message(MessageType::solicit, transaction_id,
                                      OptionCode::ia_na, 9U);
  if (!repository.observe_client(interface_id, *peer, client_mac, solicit,
                                 start))
    throw std::runtime_error("DHCPv6 relay did not correlate a direct client");

  const auto first_reply = client_message(
      MessageType::reply, transaction_id, OptionCode::ia_na, 9U,
      address_options(*address, 60U, 120U));
  const auto first_plan =
      repository.prepare_reply(interface_id, *peer, *server_address, 0U,
                               first_reply, start);
  if (first_plan.status != RelayLeaseReplyStatus::accepted ||
      first_plan.mutations.size() != 1U ||
      first_plan.mutations.front().kind != RelayLeaseMutationKind::install ||
      first_plan.mutations.front().record.value != *address ||
      !first_plan.mutations.front().record.has_client_mac ||
      first_plan.mutations.front().record.client_mac != client_mac ||
      !repository.commit_prepared() || repository.leases().size() != 1U)
    throw std::runtime_error("DHCPv6 relay did not atomically install IA_NA");

  // Nokia lease-populate discards the whole Reply after the configured maximum
  // is reached. The existing binding must remain unchanged, with no partial
  // second lease visible to route or adjacency owners.
  const auto overflow_reply = client_message(
      MessageType::reply, transaction_id, OptionCode::ia_na, 9U,
      address_options(*second_address, 60U, 120U));
  const auto overflow =
      repository.prepare_reply(interface_id, *peer, *server_address, 0U,
                               overflow_reply, start);
  if (overflow.status != RelayLeaseReplyStatus::lease_limit_exceeded ||
      !overflow.mutations.empty() || repository.leases().size() != 1U)
    throw std::runtime_error("DHCPv6 relay partially admitted a full lease table");

  // A zero valid lifetime withdraws the same binding. That frees capacity in
  // the final projected state and is committed only after the caller publishes
  // the corresponding route and Neighbor Cache removals.
  const auto withdraw_reply = client_message(
      MessageType::reply, transaction_id, OptionCode::ia_na, 9U,
      address_options(*address, 0U, 0U));
  const auto withdrawal =
      repository.prepare_reply(interface_id, *peer, *server_address, 0U,
                               withdraw_reply, start);
  if (withdrawal.status != RelayLeaseReplyStatus::accepted ||
      withdrawal.mutations.size() != 1U ||
      withdrawal.mutations.front().kind != RelayLeaseMutationKind::remove ||
      !repository.commit_prepared() || !repository.leases().empty())
    throw std::runtime_error("DHCPv6 relay failed to withdraw a zero lease");

  // A failed IA is protocol success at the message level but owns no lease.
  // A duplicate status is malformed, preventing ambiguous status precedence.
  std::array<std::uint8_t, 4U> failure_body{0U, 2U, 'n', 'o'};
  std::vector<std::uint8_t> failed_options;
  append_option(failed_options, OptionCode::status_code, failure_body);
  const auto failed_reply = client_message(MessageType::reply, transaction_id,
                                           OptionCode::ia_na, 9U,
                                           failed_options);
  const auto failed =
      repository.prepare_reply(interface_id, *peer, *server_address, 0U,
                               failed_reply, start);
  if (failed.status != RelayLeaseReplyStatus::accepted ||
      !failed.mutations.empty())
    throw std::runtime_error("DHCPv6 relay created state for a failed IA");
  append_option(failed_options, OptionCode::status_code, failure_body);
  const auto malformed_reply = client_message(
      MessageType::reply, transaction_id, OptionCode::ia_na, 9U,
      failed_options);
  if (repository
          .prepare_reply(interface_id, *peer, *server_address, 0U,
                         malformed_reply, start)
          .status != RelayLeaseReplyStatus::malformed)
    throw std::runtime_error("DHCPv6 relay accepted duplicate IA status");

  RelayLeasePolicy pd_policy = policy;
  pd_policy.maximum_leases = 2U;
  if (!repository.configure(std::span{&pd_policy, 1U}))
    throw std::runtime_error("DHCPv6 relay PD policy was rejected");
  const auto pd_solicit = client_message(MessageType::solicit, transaction_id,
                                         OptionCode::ia_pd, 10U);
  if (!repository.observe_client(interface_id, *peer, client_mac, pd_solicit,
                                 start))
    throw std::runtime_error("DHCPv6 relay did not correlate IA_PD");
  const auto pd_reply = client_message(
      MessageType::reply, transaction_id, OptionCode::ia_pd, 10U,
      prefix_options(*delegated, 59U, 60U, 120U));
  const auto pd_plan =
      repository.prepare_reply(interface_id, *peer, *server_address, 0U,
                               pd_reply, start);
  if (pd_plan.status != RelayLeaseReplyStatus::accepted ||
      pd_plan.mutations.size() != 1U ||
      !pd_plan.mutations.front().record.has_excluded_prefix ||
      pd_plan.mutations.front().record.excluded_prefix != *excluded ||
      !repository.commit_prepared())
    throw std::runtime_error("DHCPv6 relay lost the delegated excluded prefix");

  const auto saved = repository.checkpoint(start + std::chrono::seconds{10});
  RelayLeaseRepository restored;
  if (!restored.restore(std::span{&pd_policy, 1U}, saved,
                        start + std::chrono::seconds{100}) ||
      restored.leases().size() != 1U ||
      restored.leases().front().server_address != *server_address ||
      restored.leases().front().server.duid_octets != 8U ||
      restored.next_deadline() !=
          start + std::chrono::seconds{210})
    throw std::runtime_error("DHCPv6 relay lease restart changed lifetime");
  const auto expiry =
      restored.prepare_expiry(start + std::chrono::seconds{210});
  if (expiry.size() != 1U ||
      expiry.front().kind != RelayLeaseMutationKind::remove ||
      !restored.commit_prepared() || !restored.leases().empty())
    throw std::runtime_error("DHCPv6 relay lease did not expire atomically");

  // Removing a configured service uses the same two-phase contract as timer
  // expiry, so routes and neighbors cannot outlive their lease policy.
  const auto remove_plan = repository.prepare_remove_interface(interface_id);
  if (remove_plan.size() != 1U ||
      remove_plan.front().kind != RelayLeaseMutationKind::remove) {
    throw std::runtime_error("DHCPv6 relay removal did not prepare withdrawal");
  }
  repository.discard_prepared();
}
