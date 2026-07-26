// Destination Cache tests cover state-dependent Redirect validation, next-hop
// replacement, route-change invalidation and checkpoint reconstruction.

#include "router/ipv6_destination_cache.hpp"

#include "router/ip_address.hpp"

#include <stdexcept>

void ipv6_destination_cache_tests() {
  using namespace router;
  using namespace router::lab;
  const auto address = [](const char *text) {
    const auto result = ip::parse_ipv6(text);
    if (!result)
      throw std::runtime_error("Destination Cache address setup failed");
    return *result;
  };
  const auto router_a = address("fe80::1");
  const auto router_b = address("fe80::2");
  const auto destination = address("2001:db8:20::20");
  const auto mac = packet::Mac{0x02U, 0U, 0U, 0U, 0U, 2U};
  packet::nd::RedirectView redirect{.source = router_a,
                                    .receiver = address("2001:db8:10::10"),
                                    .target = router_b,
                                    .destination = destination,
                                    .target_link_layer = mac,
                                    .redirected_header_present = true};
  Ipv6DestinationCache cache;
  if (!cache.accept_redirect(0U, redirect, router_a, router_a) ||
      cache.size() != 1U ||
      cache.current_next_hop(0U, destination, router_a) != router_b)
    throw std::runtime_error("valid Redirect did not update Destination Cache");
  if (cache.current_next_hop(0U, destination, address("fe80::3")) !=
      address("fe80::3"))
    throw std::runtime_error("stale Redirect overrode a changed first hop");
  auto invalid = redirect;
  invalid.source = router_b;
  if (cache.accept_redirect(0U, invalid, router_a, router_a))
    throw std::runtime_error("Redirect from a non-current router was accepted");

  const auto checkpoint = cache.checkpoint();
  Ipv6DestinationCache restored;
  if (!restored.restore(checkpoint) || restored.size() != 1U ||
      restored.current_next_hop(0U, destination, router_a) != router_b)
    throw std::runtime_error("Destination Cache checkpoint did not restore");
  cache.remove_port(0U);
  if (cache.size() != 0U)
    throw std::runtime_error("Destination Cache retained removed interface");
}
