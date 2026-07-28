// DHCPv6 lease tests exercise stable opaque assignment, IA namespace
// separation, renew, release, decline quarantine, exhaustion and IA_PD.

#include "router/dhcpv6_lease.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::dhcpv6::ClientIdentity client(std::uint8_t identity,
                                      std::uint32_t iaid,
                                      router::dhcpv6::LeaseKind kind) {
  router::dhcpv6::ClientIdentity result{.iaid = iaid, .kind = kind};
  constexpr std::array<std::uint8_t, 4U> prefix{0U, 3U, 0U, 1U};
  std::copy(prefix.begin(), prefix.end(), result.duid.begin());
  result.duid[4U] = identity;
  result.duid_octets = 5U;
  return result;
}

router::dhcpv6::LeasePool pool(const char *text,
                                std::uint8_t delegated = 0U) {
  const auto prefix = router::ip::parse_ipv6_prefix(text);
  if (!prefix)
    throw std::runtime_error("DHCPv6 lease fixture prefix is invalid");
  router::dhcpv6::LeasePool result{
      .prefix = *prefix,
      .preferred_lifetime_seconds = 3600U,
      .valid_lifetime_seconds = 7200U,
      .t1_seconds = 1800U,
      .t2_seconds = 2880U,
      .delegated_length = delegated};
  for (std::size_t index = 0; index < result.allocation_secret.size(); ++index)
    result.allocation_secret[index] = static_cast<std::uint8_t>(index + 1U);
  return result;
}

} // namespace

void dhcpv6_lease_tests() {
  using namespace router;
  using namespace router::dhcpv6;
  using namespace std::chrono_literals;

  LeaseRepository repository;
  const auto address_pool = pool("2001:db8:10::/64");
  const auto prefix_pool = pool("2001:db8:100::/48", 56U);
  require(repository.configure(
              std::span<const LeasePool>{&address_pool, 1U},
              std::span<const LeasePool>{&prefix_pool, 1U}, 30min),
          "DHCPv6 lease repository rejected valid pools");
  const auto now = LeaseRepository::Clock::now();
  const auto first_client = client(1U, 7U, LeaseKind::non_temporary);
  const auto second_client = client(2U, 7U, LeaseKind::non_temporary);
  const auto offered = repository.preview(first_client, 0U, now);
  require(offered.status == LeaseStatus::assigned &&
              repository.active_leases() == 0U,
          "DHCPv6 Advertise preview committed repository state");
  const auto first = repository.assign(first_client, 0U, now);
  const auto second = repository.assign(second_client, 0U, now);
  require(first.status == LeaseStatus::assigned && first.value == offered.value &&
              second.status == LeaseStatus::assigned &&
              first.value != second.value &&
              ip::contains(address_pool.prefix, first.value) &&
              ip::contains(address_pool.prefix, second.value) &&
              first.preferred_lifetime_seconds == 3600U &&
              first.valid_lifetime_seconds == 7200U &&
              first.t1_seconds == 1800U && first.t2_seconds == 2880U,
          "DHCPv6 address assignment collided or lost lease timers");

  const auto renewed = repository.renew(first_client, now + 100s);
  require(renewed.status == LeaseStatus::renewed &&
              renewed.value == first.value &&
              renewed.valid_lifetime_seconds == 7200U,
          "DHCPv6 Renew changed an active client binding");

  const auto temporary_client = client(1U, 7U, LeaseKind::temporary);
  const auto temporary = repository.assign(temporary_client, 0U, now);
  require(temporary.status == LeaseStatus::assigned &&
              temporary.value != first.value,
          "DHCPv6 IA_TA did not use its independent IAID namespace");

  const auto delegated_client = client(1U, 9U, LeaseKind::prefix);
  const auto delegated = repository.assign(delegated_client, 0U, now);
  require(delegated.status == LeaseStatus::assigned &&
              delegated.prefix_length == 56U &&
              ip::contains(prefix_pool.prefix, delegated.value) &&
              ip::mask(delegated.value, 56U) == delegated.value,
          "DHCPv6 IA_PD did not allocate a canonical child prefix");

  require(repository.decline(first_client, now + 200s) ==
              LeaseStatus::declined &&
              repository.active_leases() == 3U &&
              repository.declined_values() == 1U,
          "DHCPv6 Decline did not quarantine the assigned address");
  const auto replacement = repository.assign(first_client, 0U, now + 201s);
  require(replacement.status == LeaseStatus::assigned &&
              replacement.value != first.value,
          "DHCPv6 reassigned a value while its decline hold was active");
  const auto observed_client = ip::parse_ipv6("fe80::1");
  require(observed_client &&
              repository.note_client_address(first_client, *observed_client),
          "DHCPv6 repository rejected a real client source address");
  const auto lease_checkpoint = repository.checkpoint(now + 202s);
  const auto observed_binding = std::find_if(
      lease_checkpoint.begin(), lease_checkpoint.end(),
      [&](const auto &lease) {
        return lease.client == first_client && !lease.declined;
      });
  require(observed_binding != lease_checkpoint.end() &&
              observed_binding->last_client_address == *observed_client,
          "DHCPv6 checkpoint lost the observed client endpoint");
  LeaseRepository restored;
  require(restored.configure(
              std::span<const LeasePool>{&address_pool, 1U},
              std::span<const LeasePool>{&prefix_pool, 1U}, 30min) &&
              restored.validate_checkpoint(lease_checkpoint) &&
              restored.restore(lease_checkpoint, now + 500s) &&
              restored.active_leases() == repository.active_leases() &&
              restored.declined_values() == repository.declined_values() &&
              restored.renew(temporary_client, now + 501s).value ==
                  temporary.value,
          "DHCPv6 checkpoint changed active or declined bindings");
  auto invalid_checkpoint = lease_checkpoint;
  const auto invalid_live = std::find_if(
      invalid_checkpoint.begin(), invalid_checkpoint.end(),
      [](const auto &lease) { return !lease.declined; });
  if (invalid_live == invalid_checkpoint.end())
    throw std::runtime_error("DHCPv6 checkpoint fixture lost live bindings");
  invalid_live->valid_remaining_nanoseconds = 0;
  require(!restored.validate_checkpoint(invalid_checkpoint) &&
              !restored.restore(invalid_checkpoint, now + 500s),
          "DHCPv6 checkpoint admitted an expired live binding");

  repository.expire(now + 34min);
  require(repository.declined_values() == 0U,
          "DHCPv6 decline hold did not expire");
  require(repository.release(second_client) == LeaseStatus::released &&
              repository.release(second_client) == LeaseStatus::no_binding,
          "DHCPv6 Release did not remove exactly one binding");

  LeaseClearFilter pd_only;
  pd_only.type = LeaseClearFilter::Type::pd;
  require(repository.clear(pd_only, now + 34min) == 1U &&
              repository.renew(delegated_client, now + 34min).status ==
                  LeaseStatus::no_binding,
          "DHCPv6 operational type filter removed the wrong binding");

  auto invalid_pool = address_pool;
  invalid_pool.t1_seconds = 4000U;
  invalid_pool.t2_seconds = 3000U;
  require(!repository.configure(
              std::span<const LeasePool>{&invalid_pool, 1U}, {}, 1s),
          "DHCPv6 pool accepted T1 above T2");

  // A /128 contains one exact value. Once allocated, another DUID must receive
  // NoAddrsAvail rather than an address outside administrator intent.
  const auto single = pool("2001:db8::1234/128");
  require(repository.configure(std::span<const LeasePool>{&single, 1U}, {},
                               10min),
          "DHCPv6 /128 pool was rejected");
  const auto only = repository.assign(first_client, 0U, now);
  const auto exhausted = repository.assign(second_client, 0U, now);
  require(only.status == LeaseStatus::assigned && only.value == single.prefix.network &&
              exhausted.status == LeaseStatus::no_addresses_available,
          "DHCPv6 finite pool exhaustion escaped its configured prefix");

  auto infinite = pool("2001:db8:ffff::/64");
  infinite.preferred_lifetime_seconds =
      std::numeric_limits<std::uint32_t>::max();
  infinite.valid_lifetime_seconds =
      std::numeric_limits<std::uint32_t>::max();
  infinite.t1_seconds = 0U;
  infinite.t2_seconds = 0U;
  require(repository.configure(std::span<const LeasePool>{&infinite, 1U}, {},
                               10min),
          "DHCPv6 infinite-lifetime pool was rejected");
  const auto forever = repository.assign(first_client, 0U, now);
  const auto forever_checkpoint = repository.checkpoint(now + 100s);
  require(forever.preferred_lifetime_seconds ==
              std::numeric_limits<std::uint32_t>::max() &&
              forever.valid_lifetime_seconds ==
                  std::numeric_limits<std::uint32_t>::max() &&
              forever_checkpoint.front().preferred_remaining_nanoseconds ==
                  -1 &&
              forever_checkpoint.front().valid_remaining_nanoseconds == -1,
          "DHCPv6 infinity became a large finite lease");
}
