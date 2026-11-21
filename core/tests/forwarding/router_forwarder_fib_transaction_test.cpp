// The forwarding owner preflights both address families before one command
// turn can replace either FIB. Tests retain and reuse heap-owned generations;
// no protocol stack stores profile-sized transfer values.

#include "router_forwarder_test_support.hpp"

void router_forwarder_fib_transaction_tests() {
  using namespace router;
  using namespace router::lab;
  using namespace router::lab::routing;
  auto forwarder = std::make_unique<RouterForwarder>();
  auto ipv4 = std::make_unique<FibProgram>();
  auto ipv6 = std::make_unique<Ipv6FibProgram>();
  ipv4->generation = ipv6->generation = 1U;
  ipv4->count = ipv6->count = 1U;
  ipv4->routes[0U] = {.network = 0xc0000200U, .port_ordinal = 1U,
      .prefix_length = 24U, .metric = 10U};
  ipv6->routes[0U] = {.network = *ip::parse_ipv6("2001:db8:1::"),
      .interface_id = 2U, .physical_port_ordinal = 2U, .prefix_length = 64U, .metric = 20U};
  require(forwarder->program_fibs(ipv4.get(), ipv6.get()), "initial dual-family commit failed");
  const auto unchanged = [&] {
    const auto state = snapshot(*forwarder);
    require(state->fib.generation == 1U && state->fib.routes[0U].metric == 10U &&
        state->ipv6_fib.generation == 1U && state->ipv6_fib.routes[0U].metric == 20U,
        "refused dual-family transaction changed one FIB");
  };
  ipv4->generation = 2U;
  ipv4->routes[0U].metric = 11U;
  ipv6->generation = 0U;
  require(!forwarder->program_fibs(ipv4.get(), ipv6.get()), "stale IPv6 generation accepted");
  unchanged();
  ipv6->generation = 2U;
  ipv6->count = static_cast<std::uint16_t>(ipv6->routes.size() + 1U);
  require(!forwarder->program_fibs(ipv4.get(), ipv6.get()), "invalid IPv6 count accepted");
  unchanged();
  ipv6->count = 1U;
  ipv4->generation = 1U;
  require(!forwarder->program_fibs(ipv4.get(), ipv6.get()), "changed equal-generation IPv4 accepted");
  unchanged();
  ipv4->generation = 2U;
  ipv6->routes[0U].metric = 21U;
  require(forwarder->program_fibs(ipv4.get(), ipv6.get()) &&
      forwarder->program_fibs(ipv4.get(), ipv6.get()), "valid/idempotent dual-family commit failed");
  auto state = snapshot(*forwarder);
  require(state->fib.generation == 2U && state->fib.routes[0U].metric == 11U &&
      state->ipv6_fib.generation == 2U && state->ipv6_fib.routes[0U].metric == 21U,
      "dual-family commit did not install both generations");
  require(!forwarder->program_fibs(nullptr, nullptr), "empty FIB operation accepted");
  ipv4->generation = 3U;
  ipv4->count = 0U;
  require(forwarder->program_fibs(ipv4.get(), nullptr), "single-family withdrawal failed");
  state = snapshot(*forwarder);
  require(!state->fib.count && state->fib.generation == 3U && state->ipv6_fib.generation == 2U,
      "null family was mistaken for a withdrawal");

  auto rib4 = std::make_unique<RouteTable>();
  auto rib6 = std::make_unique<Ipv6RouteTable>();
  const std::array connected4{ConnectedInput{true, true, 0xc0000200U, 1U, 24U}};
  const std::array connected6{Ipv6ConnectedInput{true, true, *ip::parse_ipv6("2001:db8:1::"), 2U, 2U, 64U}};
  require(rib4->rebuild(connected4, {}) && rib6->rebuild(connected6, {}), "RIB setup failed");
  rib4->compile_into(*ipv4, 4U);
  rib6->compile_into(*ipv6, 4U);
  require(forwarder->program_fibs(ipv4.get(), ipv6.get()), "compiled transfer arena rejected");
  require(rib4->rebuild({}, {}) && rib6->rebuild({}, {}), "RIB withdrawal failed");
  rib4->compile_into(*ipv4, 5U);
  rib6->compile_into(*ipv6, 5U);
  require(!ipv4->count && !ipv6->count &&
      std::all_of(ipv4->routes.begin(), ipv4->routes.end(), [](const auto &route) { return route == Route{}; }) &&
      std::all_of(ipv6->routes.begin(), ipv6->routes.end(), [](const auto &route) { return route == Ipv6Route{}; }) &&
      forwarder->program_fibs(ipv4.get(), ipv6.get()), "reused arena retained withdrawn route values");
}
