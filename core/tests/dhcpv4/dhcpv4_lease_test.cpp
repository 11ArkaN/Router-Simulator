// DHCPv4 lease tests cover the owner-serialized address policy, pending offer
// exclusion and state transitions. They deliberately use two clients with
// simultaneous transactions to detect double allocation.

#include "router/dhcpv4_lease.hpp"

#include <array>
#include <chrono>
#include <stdexcept>

namespace {

using namespace router;
using namespace router::dhcpv4;

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

ClientKey key(std::uint8_t suffix) {
  ClientKey value{.octets = 7U};
  value.bytes[0U] = 1U;
  value.bytes[1U] = 0x02U;
  value.bytes[6U] = suffix;
  return value;
}

Pool pool() {
  return Pool{.id = 1U,
              .scope = {.server_instance = 1U,
                        .routing_context = 1U,
                        .link_identity = 7U},
              .first = {192U, 0U, 2U, 10U},
              .last = {192U, 0U, 2U, 12U},
              .subnet_mask = {255U, 255U, 255U, 0U},
              .router = {192U, 0U, 2U, 1U},
              .lease_seconds = 3600U,
              .renewal_seconds = 1800U,
              .rebinding_seconds = 3150U,
              .enabled = true};
}

void pending_offer_prevents_double_allocation() {
  LeaseRepository leases;
  const auto configured_pool = pool();
  require(leases.configure(std::span{&configured_pool, 1U}, {},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 lease repository rejected a valid pool");
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  const auto first = leases.offer(configured_pool.scope, key(1U), 1U,
                                  std::nullopt, now);
  const auto second = leases.offer(configured_pool.scope, key(2U), 2U,
                                   std::nullopt, now);
  require(first.status == AllocateStatus::offered &&
              second.status == AllocateStatus::offered,
          "DHCPv4 repository did not create valid offers");
  require(first.address != second.address,
          "DHCPv4 repository offered one address to two clients");
}

void reservation_and_requested_address_precedence() {
  LeaseRepository leases;
  const auto configured_pool = pool();
  const auto reserved_client = key(9U);
  const Reservation fixed{.scope = configured_pool.scope,
                          .client = reserved_client,
                          .address = {192U, 0U, 2U, 12U}};
  require(leases.configure(std::span{&configured_pool, 1U},
                           std::span{&fixed, 1U},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 repository rejected a valid reservation");
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  const auto reserved = leases.offer(
      configured_pool.scope, reserved_client, 1U,
      packet::Ipv4{192U, 0U, 2U, 10U}, now);
  require(reserved.address == fixed.address,
          "DHCPv4 requested address bypassed a reservation");

  const auto requested = packet::Ipv4{192U, 0U, 2U, 11U};
  const auto ordinary =
      leases.offer(configured_pool.scope, key(2U), 2U, requested, now);
  require(ordinary.address == requested,
          "DHCPv4 available requested address was ignored");
}

void commit_release_and_decline_transitions() {
  LeaseRepository leases;
  const auto configured_pool = pool();
  require(leases.configure(std::span{&configured_pool, 1U}, {},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 repository rejected transition test pool");
  const auto client = key(1U);
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  const auto offered =
      leases.offer(configured_pool.scope, client, 77U, std::nullopt, now);
  require(leases.commit(configured_pool.scope, client, 77U,
                        offered.address, now),
          "DHCPv4 matching REQUEST did not commit its offer");
  require(!leases.commit(configured_pool.scope, client, 78U,
                         packet::Ipv4{192U, 0U, 2U, 12U}, now),
          "DHCPv4 mismatched REQUEST changed a binding");
  require(leases.release(configured_pool.scope, client, offered.address, now),
          "DHCPv4 RELEASE did not release an active lease");

  const auto offered_again =
      leases.offer(configured_pool.scope, client, 79U, std::nullopt, now);
  require(leases.decline(configured_pool.scope, client,
                         offered_again.address, now),
          "DHCPv4 DECLINE did not hold the offered address");
  const auto other =
      leases.offer(configured_pool.scope, key(2U), 80U, std::nullopt, now);
  require(other.address != offered_again.address,
          "DHCPv4 declined address returned before hold-down expiry");
}

void multiple_pools_use_identity_order_not_storage_order() {
  LeaseRepository leases;
  auto higher = pool();
  higher.id = 9U;
  higher.first = {192U, 0U, 2U, 20U};
  higher.last = {192U, 0U, 2U, 20U};
  auto lower = pool();
  lower.id = 3U;
  lower.first = {192U, 0U, 2U, 30U};
  lower.last = {192U, 0U, 2U, 30U};
  // Deliberately serialize the larger ID first. Allocation order is a
  // configuration contract and must not change when a project serializer
  // reorders otherwise equivalent collection elements.
  const std::array configured{higher, lower};
  require(leases.configure(configured, {}, std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 repository rejected disjoint pools on one link");
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  const auto first =
      leases.offer(lower.scope, key(1U), 1U, std::nullopt, now);
  const auto second =
      leases.offer(lower.scope, key(2U), 2U, std::nullopt, now);
  require(first.pool_id == lower.id && first.address == lower.first,
          "DHCPv4 allocation depended on serialized pool order");
  require(second.pool_id == higher.id && second.address == higher.first,
          "DHCPv4 allocation did not continue into the next pool");
}

void excluded_ranges_are_never_allocated() {
  LeaseRepository leases;
  const auto configured_pool = pool();
  const ExcludedRange excluded{.scope = configured_pool.scope,
                               .first = {192U, 0U, 2U, 10U},
                               .last = {192U, 0U, 2U, 11U}};
  require(leases.configure(std::span{&configured_pool, 1U}, {},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600},
                           std::span{&excluded, 1U}),
          "DHCPv4 repository rejected an in-pool exclusion");
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};

  // This assertion exercises both allocation branches. The requested address
  // path must reject an excluded address, then deterministic first-free must
  // skip the complete excluded interval rather than only its first element.
  const auto offered =
      leases.offer(configured_pool.scope, key(1U), 1U, excluded.first, now);
  require(offered.status == AllocateStatus::offered &&
              offered.address == configured_pool.last,
          "DHCPv4 allocator returned an excluded address");
}

void operational_clear_filters_address_and_binding_state() {
  LeaseRepository leases;
  const auto configured_pool = pool();
  require(leases.configure(std::span{&configured_pool, 1U}, {},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 repository rejected operational-clear pool");
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};

  const auto active_offer =
      leases.offer(configured_pool.scope, key(1U), 1U, std::nullopt, now);
  require(leases.commit(configured_pool.scope, key(1U), 1U,
                        active_offer.address, now),
          "DHCPv4 clear test could not create an active lease");
  const auto pending_offer =
      leases.offer(configured_pool.scope, key(2U), 2U, std::nullopt, now);
  require(pending_offer.status == AllocateStatus::offered,
          "DHCPv4 clear test could not create a pending offer");

  // A state filter must be applied by the repository owner in the same erase
  // pass as the mutation. Filtering a copied management projection first
  // would race with lease transitions on the control-plane shard.
  const LeaseClearFilter offered_filter{
      .state = OperationalLeaseState::offered};
  require(leases.clear(offered_filter, now) == 1U &&
              leases.leases().size() == 1U &&
              leases.leases().front().address == active_offer.address,
          "DHCPv4 offered-state clear removed the wrong binding");

  const LeaseClearFilter active_address_filter{
      .address = active_offer.address,
      .prefix_length = 32U,
      .state = OperationalLeaseState::stable,
      .address_specific = true};
  require(leases.clear(active_address_filter, now) == 1U &&
              leases.leases().empty(),
          "DHCPv4 address-specific stable clear did not remove its lease");
}

void partner_binding_update_commits_before_acknowledgement() {
  LeaseRepository leases;
  auto configured_pool = pool();
  // A range controlled by the remote endpoint is unavailable to the local
  // allocator, but it remains a valid repository scope for received BNDUPD.
  configured_pool.enabled = false;
  require(leases.configure(std::span{&configured_pool, 1U}, {},
                           std::chrono::seconds{60},
                           std::chrono::seconds{600}),
          "DHCPv4 repository rejected a remote failover range");
  constexpr std::array hardware{std::uint8_t{1U}, std::uint8_t{0x02U},
                                std::uint8_t{0U}, std::uint8_t{0U},
                                std::uint8_t{0U}, std::uint8_t{0U},
                                std::uint8_t{9U}};
  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  const failover::BindingUpdateView update{
      .address = configured_pool.first,
      .status = failover::BindingStatus::active,
      .client_hardware_address = hardware,
      .lease_expiration_time = 4600U,
      .potential_expiration_time = 4700U,
      .client_last_transaction_time = 995U,
      .start_time_of_state = 990U,
      .reject_reason = std::nullopt};
  require(leases.apply_partner_update(update, 1000U, now) ==
              PartnerUpdateStatus::applied &&
              leases.leases().size() == 1U &&
              leases.leases().front().state == BindingState::active,
          "DHCPv4 partner update did not commit an active binding");
  require(leases.apply_partner_update(update, 1000U, now) ==
              PartnerUpdateStatus::duplicate &&
              leases.leases().size() == 1U,
          "DHCPv4 duplicate partner update mutated the repository");

  const auto saved = leases.checkpoint(now);
  LeaseRepository restored;
  require(restored.configure(std::span{&configured_pool, 1U}, {},
                             std::chrono::seconds{60},
                             std::chrono::seconds{600}) &&
              restored.restore(saved, now) &&
              restored.leases().front().failover_managed,
          "DHCPv4 failover metadata did not survive repository restore");
}

} // namespace

void dhcpv4_lease_tests() {
  pending_offer_prevents_double_allocation();
  reservation_and_requested_address_precedence();
  commit_release_and_decline_transitions();
  multiple_pools_use_identity_order_not_storage_order();
  excluded_ranges_are_never_allocated();
  operational_clear_filters_address_and_binding_state();
  partner_binding_update_commits_before_acknowledgement();
}
