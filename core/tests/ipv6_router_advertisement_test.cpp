// RA timer tests exercise local steady-clock scheduling, solicitation
// coalescing and profile validation without introducing a virtual time source.

#include "router/ipv6_router_advertisement.hpp"

#include <array>
#include <chrono>
#include <memory>
#include <stdexcept>

void ipv6_router_advertisement_tests() {
  using namespace std::chrono_literals;
  using router::lab::Ipv6RouterAdvertisementTable;
  using router::lab::RouterAdvertisementAction;
  namespace nd = router::packet::nd;

  // The production owner is heap-resident. Tests mirror that placement because
  // a full maximum-port RA table is intentionally larger than the Wasm stack.
  auto table = std::make_unique<Ipv6RouterAdvertisementTable>();
  const auto start = Ipv6RouterAdvertisementTable::Clock::time_point{};
  nd::RouterAdvertisementConfig config{
      .router_lifetime_seconds = 1'800U};
  if (!table->configure(7U, true, config, start) || !table->next_deadline() ||
      *table->next_deadline() < start ||
      *table->next_deadline() >
          start + router::device_catalog::ra_max_initial_advertisement_interval)
    throw std::runtime_error("RA initial deadline is outside RFC bounds");

  std::array<RouterAdvertisementAction, 1> actions{};
  if (table->poll(start, actions) != 0U)
    throw std::runtime_error("RA fired before its randomized deadline");
  const auto first_deadline = *table->next_deadline();
  if (table->poll(first_deadline, actions) != 1U ||
      actions[0].port_ordinal != 7U ||
      actions[0].config.router_lifetime_seconds != 1'800U)
    throw std::runtime_error("RA deadline did not emit copied configuration");

  // A solicitation immediately after transmission must not bypass the three
  // second minimum. The action remains owner-local until poll reaches it.
  table->observe_solicitation(7U, first_deadline);
  const auto response_deadline = *table->next_deadline();
  if (response_deadline < first_deadline + 3s ||
      table->poll(response_deadline - 1ns, actions) != 0U ||
      table->poll(response_deadline, actions) != 1U)
    throw std::runtime_error("Solicited RA violated minimum spacing");

  auto invalid = config;
  invalid.min_advertisement_interval_seconds = 201U;
  invalid.max_advertisement_interval_seconds = 200U;
  if (table->configure(8U, true, invalid, start))
    throw std::runtime_error("Invalid RA interval relationship was accepted");

  const auto saved = table->checkpoint(response_deadline);
  auto restored = std::make_unique<Ipv6RouterAdvertisementTable>();
  if (!Ipv6RouterAdvertisementTable::validate_checkpoint(saved) ||
      !restored->restore(saved, response_deadline) ||
      restored->next_deadline() != table->next_deadline())
    throw std::runtime_error("RA relative deadline did not survive checkpoint");
  auto corrupt = saved;
  corrupt[0].random_state = 0U;
  if (restored->restore(corrupt, response_deadline))
    throw std::runtime_error("Invalid RA checkpoint replaced live state");

  table->remove(7U);
  if (table->next_deadline())
    throw std::runtime_error("Removed RA interface retained a deadline");
}
