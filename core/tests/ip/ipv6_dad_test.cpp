// DAD tests use explicit monotonic times and validate actions rather than a
// sleeping thread. They cover the mandatory quiet interval after the last NS.

#include "router/ipv6_dad.hpp"

#include <array>
#include <stdexcept>

void ipv6_dad_tests() {
  using namespace router::lab;
  const auto address = router::ip::parse_ipv6("2001:db8::1");
  if (!address)
    throw std::runtime_error("DAD fixture address is invalid");
  const auto start = Ipv6DadTable::Clock::time_point{};
  constexpr std::uint64_t interface_id = 70'007U;
  constexpr std::uint16_t physical_port = 7U;
  Ipv6DadTable table;
  if (!table.configure(interface_id, physical_port, *address, 1,
                       std::chrono::milliseconds{12}, start) ||
      table.preferred(interface_id, *address))
    throw std::runtime_error("DAD did not create a tentative address");
  std::array<Ipv6DadAction, 1> action{};
  if (table.poll(start + std::chrono::milliseconds{11}, action) != 0 ||
      table.poll(start + std::chrono::milliseconds{12}, action) != 1 ||
      action[0].interface_id != interface_id ||
      action[0].port_ordinal != physical_port ||
      action[0].target != *address ||
      table.preferred(interface_id, *address))
    throw std::runtime_error("DAD initial delay or solicitation was incorrect");
  if (table.poll(start + std::chrono::milliseconds{12} +
                     router::device_catalog::nd_retrans_timer,
                 action) != 0 ||
      !table.preferred(interface_id, *address))
    throw std::runtime_error("DAD skipped the post-solicitation quiet interval");

  const auto duplicate = router::ip::parse_ipv6("fe80::7");
  if (!duplicate ||
      !table.configure(interface_id, physical_port, *duplicate, 1,
                       std::chrono::nanoseconds{0}, start) ||
      !table.observe_conflict(interface_id, *duplicate) ||
      !table.find(interface_id, *duplicate) ||
      table.find(interface_id, *duplicate)->state != Ipv6DadState::duplicate)
    throw std::runtime_error("validated ND conflict did not fail DAD");

  const auto checkpoint = table.checkpoint(start);
  Ipv6DadTable restored;
  if (!restored.restore(checkpoint, start + std::chrono::hours{1}) ||
      !restored.preferred(interface_id, *address) ||
      restored.find(interface_id, *duplicate)->state !=
          Ipv6DadState::duplicate)
    throw std::runtime_error("DAD checkpoint lost address lifecycle state");
  restored.remove(interface_id, *duplicate);
  if (restored.find(interface_id, *duplicate) ||
      !restored.preferred(interface_id, *address))
    throw std::runtime_error(
        "address-specific DAD removal erased unrelated interface state");

  // An AF subscriber caches usable addresses until the same owner's readiness
  // revision changes. Cold candidate preparation must not invalidate live data.
  auto observed = restored.readiness_revision();
  if (restored.readiness_changed(observed) ||
      !restored.configure(interface_id, physical_port, *address, 1,
                          std::chrono::nanoseconds{0}, start) ||
      restored.readiness_changed(observed))
    throw std::runtime_error("idempotent DAD configuration invalidated AF readiness");
  auto candidate = restored;
  if (!candidate.configure(interface_id, physical_port, *duplicate, 1,
                           std::chrono::nanoseconds{0}, start) ||
      restored.readiness_changed(observed) || !candidate.readiness_changed(observed))
    throw std::runtime_error("cold DAD preparation leaked a live readiness change");
  restored = candidate;
  if (!restored.readiness_changed(observed))
    throw std::runtime_error("committed DAD generation did not invalidate AF readiness");
  observed = restored.readiness_revision();
  if (restored.poll(start, action) != 1U || restored.readiness_changed(observed))
    throw std::runtime_error("a tentative probe changed AF address usability");
  if (restored.poll(start + router::device_catalog::nd_retrans_timer, action) != 0U ||
      !restored.preferred(interface_id, *duplicate) || !restored.readiness_changed(observed))
    throw std::runtime_error("DAD completion did not invalidate AF readiness");
  observed = restored.readiness_revision();
  restored.remove_interface(interface_id + 1U);
  restored.remove_physical_port(physical_port + 1U);
  if (restored.readiness_changed(observed))
    throw std::runtime_error("absent DAD removal invalidated an unrelated AF projection");
  auto invalid = restored.checkpoint(start);
  invalid.front().interface_id = 0U;
  if (restored.restore(invalid, start) || restored.readiness_changed(observed))
    throw std::runtime_error("refused DAD restoration changed AF readiness");
  const auto valid = restored.checkpoint(start);
  if (!restored.restore(valid, start) || !restored.readiness_changed(observed))
    throw std::runtime_error("DAD restoration failed to invalidate derived AF state");
  observed = restored.readiness_revision();
  restored.remove_physical_port(physical_port);
  if (!restored.readiness_changed(observed) || restored.find(interface_id, *address))
    throw std::runtime_error("physical removal retained a published IPv6 address");
  if (!restored.configure(interface_id, physical_port, *duplicate, 1,
                          std::chrono::nanoseconds{0}, start))
    throw std::runtime_error("DAD conflict fixture admission failed");
  observed = restored.readiness_revision();
  if (!restored.observe_conflict(interface_id, *duplicate) || !restored.readiness_changed(observed))
    throw std::runtime_error("DAD conflict did not invalidate derived AF state");
  observed = restored.readiness_revision();
  if (restored.observe_conflict(interface_id, *duplicate) || restored.readiness_changed(observed))
    throw std::runtime_error("duplicate conflict changed an already failed AF generation");
  restored.remove_interface(interface_id);
  if (!restored.readiness_changed(observed) || restored.find(interface_id, *duplicate))
    throw std::runtime_error("interface removal retained failed AF state");
}
