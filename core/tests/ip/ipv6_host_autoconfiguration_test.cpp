// Host Router Discovery tests cover independent lifetimes, tentative SLAAC,
// the RFC 4862 two-hour defense and RFC 8106 immediate RDNSS withdrawal.

#include "router/ipv6_host_autoconfiguration.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::packet::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("host autoconfiguration fixture is invalid");
  return *parsed;
}

template <typename Range> std::size_t occupied(const Range &range) {
  return static_cast<std::size_t>(std::count_if(
      range.begin(), range.end(), [](const auto &entry) {
        return entry.occupied;
      }));
}

} // namespace

void ipv6_host_autoconfiguration_tests() {
  using namespace router;
  using namespace router::host;
  const auto now = Ipv6HostAutoconfiguration::Clock::now();
  const std::array<std::uint8_t,
                   Ipv6HostAutoconfiguration::
                       ethernet_interface_identifier_octets>
      iid{0x02U, 0U, 0U, 0U, 0U, 0U, 0U, 1U};
  Ipv6HostAutoconfiguration state;
  const Ipv6InterfaceIdentifierConfiguration identifier{
      .modified_eui64 = iid,
      .mode = InterfaceIdentifierMode::modified_eui64};
  require(!state.configure(1U, identifier,
                           packet::ipv6_minimum_link_mtu - 1U) &&
              state.configure(7U, identifier, 1'500U),
          "host accepted an invalid IPv6 link MTU or rejected a valid one");

  packet::nd::RouterAdvertisementView advertisement{
      .source = address("fe80::1"),
      .destination = packet::nd::all_nodes_multicast,
      .advertised_mtu = 1'400U,
      .reachable_time_milliseconds = 40'000U,
      .retrans_timer_milliseconds = 2'000U,
      .router_lifetime_seconds = 1'800U,
      .prefix_count = 1U,
      .current_hop_limit = 48U,
      .preference = packet::nd::RouterPreference::high,
      .managed_configuration = true,
      .other_configuration = true};
  advertisement.prefixes[0] = {
      .prefix = {.network = address("2001:db8:1::"), .length = 64U},
      .valid_lifetime_seconds = 86'400U,
      .preferred_lifetime_seconds = 3'600U,
      .on_link = true,
      .autonomous = true};
  advertisement.rdnss.count = 1U;
  advertisement.rdnss.servers[0] = {
      .address = address("2001:db8:1::53"), .lifetime_seconds = 600U};

  require(state.process(advertisement, false, now) ==
              RouterAdvertisementApply::applied &&
              occupied(state.default_routers()) == 1U &&
              occupied(state.on_link_prefixes()) == 1U &&
              occupied(state.addresses()) == 1U &&
              occupied(state.rdnss()) == 1U && state.effective_mtu() == 1'400U &&
              state.current_hop_limit() == 48U &&
              state.reachable_time_milliseconds() == 40'000U &&
              state.retrans_timer_milliseconds() == 2'000U &&
              state.managed_configuration() && state.other_configuration(),
          "valid RA did not update every independent host repository");
  const auto slaac = std::find_if(
      state.addresses().begin(), state.addresses().end(),
      [](const auto &entry) { return entry.occupied; });
  require(slaac != state.addresses().end() &&
              slaac->address == address("2001:db8:1:0:200::1") &&
              slaac->state == AutoconfigAddressState::tentative &&
              state.confirm_dad(slaac->address, false, now) &&
              slaac->state == AutoconfigAddressState::preferred,
          "SLAAC did not compose an Ethernet IID or wait for DAD");

  // steady_clock has no process-independent epoch. A later restore therefore
  // preserves each remaining lifetime relative to one new timestamp rather
  // than copying implementation-specific time_point representation bytes.
  const auto checkpoint = state.checkpoint(now);
  const auto restored_at = now + std::chrono::seconds{100};
  Ipv6HostAutoconfiguration restored;
  require(Ipv6HostAutoconfiguration::validate_checkpoint(checkpoint) &&
              restored.restore(checkpoint, restored_at) &&
              occupied(restored.default_routers()) == 1U &&
              occupied(restored.on_link_prefixes()) == 1U &&
              occupied(restored.addresses()) == 1U &&
              occupied(restored.rdnss()) == 1U &&
              restored.default_routers()[0].expires ==
                  restored_at + std::chrono::seconds{1'800} &&
              restored.addresses()[0].valid_until ==
                  restored_at + std::chrono::seconds{86'400},
          "host IPv6 checkpoint did not preserve repositories and lifetimes");
  auto invalid_checkpoint = checkpoint;
  invalid_checkpoint.addresses[0].address = address("2001:db8:ffff::1");
  require(!Ipv6HostAutoconfiguration::validate_checkpoint(
              invalid_checkpoint) &&
              !restored.restore(invalid_checkpoint, restored_at) &&
              occupied(restored.addresses()) == 1U,
          "invalid SLAAC checkpoint changed live owner state");

  // RFC 7217 mode derives the IID from the advertised prefix rather than the
  // MAC-based modified EUI-64 value. Secret and network identity survive the
  // owner checkpoint so a later RA for the same tuple remains stable after a
  // runtime replacement.
  Ipv6InterfaceIdentifierConfiguration opaque_identifier{
      .modified_eui64 = iid,
      .network_id_octets = 10U,
      .mode = InterfaceIdentifierMode::stable_opaque};
  for (std::size_t index = 0; index < opaque_identifier.stable_secret.size();
       ++index)
    opaque_identifier.stable_secret[index] =
        static_cast<std::uint8_t>(index + 1U);
  constexpr std::array<std::uint8_t, 10U> stable_network{
      'l', 'a', 'b', '-', 'l', 'i', 'n', 'k', '-', '7'};
  std::copy(stable_network.begin(), stable_network.end(),
            opaque_identifier.network_id.begin());
  Ipv6HostAutoconfiguration opaque;
  require(opaque.configure(7U, opaque_identifier, 1'500U) &&
              opaque.process(advertisement, false, now) ==
                  RouterAdvertisementApply::applied,
          "valid stable opaque host identity was rejected");
  const auto opaque_entry = std::find_if(
      opaque.addresses().begin(), opaque.addresses().end(),
      [](const auto &entry) { return entry.occupied; });
  require(opaque_entry != opaque.addresses().end() &&
              opaque_entry->address != address("2001:db8:1:0:200::1") &&
              opaque_entry->dad_counter == 0U,
          "SLAAC ignored the RFC 7217 interface identifier mode");
  const auto opaque_checkpoint = opaque.checkpoint(now);
  Ipv6HostAutoconfiguration opaque_restored;
  require(opaque_restored.restore(opaque_checkpoint, restored_at) &&
              opaque_restored.checkpoint(restored_at).stable_secret ==
                  opaque_identifier.stable_secret &&
              opaque_restored.addresses()[0].address == opaque_entry->address,
          "stable IID secret or derived address was lost on owner restore");
  auto previous_opaque_address = opaque_entry->address;
  for (std::uint32_t counter = 1U;
       counter <= device_catalog::ipv6_stable_iid_dad_retries; ++counter) {
    require(opaque.confirm_dad(previous_opaque_address, true, now) &&
                opaque_entry->occupied &&
                opaque_entry->dad_counter == counter &&
                opaque_entry->address != previous_opaque_address &&
                opaque_entry->state == AutoconfigAddressState::tentative,
            "RFC 7217 DAD conflict did not derive a bounded replacement IID");
    previous_opaque_address = opaque_entry->address;
  }
  require(opaque.confirm_dad(previous_opaque_address, true, now) &&
              !opaque_entry->occupied,
          "stable IID exceeded the RFC 7217 retry limit");

  // An unauthenticated short lifetime first clamps a long-lived address to two
  // hours. A second short advertisement cannot reduce the already protected
  // remaining lifetime, while an authenticated RA may do so.
  advertisement.prefixes[0].valid_lifetime_seconds = 60U;
  advertisement.prefixes[0].preferred_lifetime_seconds = 0U;
  require(state.process(advertisement, false, now) ==
              RouterAdvertisementApply::applied,
          "short-lifetime RA was not processed");
  const auto protected_until = slaac->valid_until;
  require(protected_until == now + std::chrono::hours{2},
          "RFC 4862 two-hour lifetime defense was not applied");
  advertisement.prefixes[0].valid_lifetime_seconds = 30U;
  require(state.process(advertisement, false, now) ==
              RouterAdvertisementApply::applied &&
              slaac->valid_until == protected_until,
          "second unauthenticated RA bypassed the two-hour defense");
  require(state.process(advertisement, true, now) ==
              RouterAdvertisementApply::applied &&
              slaac->valid_until == now + std::chrono::seconds{30},
          "authenticated RA could not set its advertised valid lifetime");

  // Router, prefix and RDNSS lifetimes are deliberately independent. A zero
  // router lifetime does not erase DNS, while zero in each own option does.
  advertisement.router_lifetime_seconds = 0U;
  advertisement.prefixes[0].valid_lifetime_seconds = 0U;
  advertisement.rdnss.servers[0].lifetime_seconds = 600U;
  require(state.process(advertisement, false, now) ==
              RouterAdvertisementApply::applied &&
              occupied(state.default_routers()) == 0U &&
              occupied(state.on_link_prefixes()) == 0U &&
              occupied(state.rdnss()) == 1U,
          "router withdrawal incorrectly controlled another RA lifetime");
  advertisement.rdnss.servers[0].lifetime_seconds = 0U;
  require(state.process(advertisement, false, now) ==
              RouterAdvertisementApply::applied &&
              occupied(state.rdnss()) == 0U,
          "zero RDNSS lifetime did not remove the resolver immediately");

  state.expire(now + std::chrono::seconds{31});
  require(occupied(state.addresses()) == 0U,
          "SLAAC address remained assigned after valid lifetime expiry");
}
