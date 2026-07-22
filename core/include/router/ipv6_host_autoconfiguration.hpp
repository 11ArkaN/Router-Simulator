// Host-interface owner for Router Discovery, on-link prefixes, SLAAC address
// lifetimes and RDNSS. It consumes only a validated RA wire view and never
// reads router configuration, the editor graph or another device's state.

#pragma once

#include "router/generated_device_catalog.hpp"
#include "router/ipv6_stable_iid.hpp"
#include "router/neighbor_discovery_packet.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::host {

// Ethernet uses a 64-bit interface identifier for the SLAAC /64 address form.
// Naming this link-layer contract once prevents packet and lifetime owners
// from embedding independent byte counts in array declarations.
inline constexpr std::size_t ethernet_interface_identifier_octets = 8U;

enum class AutoconfigAddressState : std::uint8_t {
  tentative,
  preferred,
  deprecated
};

struct DefaultRouterEntry {
  packet::Ipv6 address{};
  std::chrono::steady_clock::time_point expires{};
  packet::nd::RouterPreference preference{
      packet::nd::RouterPreference::medium};
  bool occupied{};
};

struct OnLinkPrefixEntry {
  ip::Ipv6Prefix prefix{};
  std::chrono::steady_clock::time_point expires{};
  bool occupied{};
};

struct SlaacAddressEntry {
  packet::Ipv6 address{};
  ip::Ipv6Prefix prefix{};
  std::chrono::steady_clock::time_point preferred_until{};
  std::chrono::steady_clock::time_point valid_until{};
  AutoconfigAddressState state{AutoconfigAddressState::tentative};
  // RFC 7217 increments this value only after a DAD conflict for the same
  // prefix and interface identity. Modified EUI-64 entries retain zero.
  std::uint32_t dad_counter{};
  bool occupied{};
};

struct Ipv6InterfaceIdentifierConfiguration {
  // modified_eui64 is derived by the attachment owner from its configured
  // MAC. stable_secret and network_id are ignored in that mode but retained
  // in one value contract so changing modes is an atomic reconfiguration.
  std::array<std::uint8_t, ethernet_interface_identifier_octets>
      modified_eui64{};
  StableIidSecret stable_secret{};
  std::array<std::uint8_t,
             device_catalog::ipv6_stable_iid_network_id_octets>
      network_id{};
  std::uint8_t network_id_octets{};
  InterfaceIdentifierMode mode{InterfaceIdentifierMode::modified_eui64};
};

struct RdnssEntry {
  // Link-local DNS servers retain the receiving interface as their RFC 4007
  // zone. Global servers keep the same field because repository keys include
  // the source interface even when textual formatting does not show a zone.
  packet::Ipv6 address{};
  std::chrono::steady_clock::time_point expires{};
  std::uint64_t interface_id{};
  std::uint64_t order{};
  bool occupied{};
};

enum class RouterAdvertisementApply : std::uint8_t {
  applied,
  applied_with_resource_drop,
  invalid_interface
};

struct RelativeIpv6Lifetime {
  // RFC 4862 and RFC 8106 use all-one-bits as an infinite lifetime. A separate
  // flag preserves that meaning without selecting an arbitrary far-future
  // date that could expire after checkpoint restore or overflow Clock.
  std::int64_t remaining_nanoseconds{};
  bool infinite{};
};

struct DefaultRouterCheckpoint {
  packet::Ipv6 address{};
  RelativeIpv6Lifetime lifetime{};
  packet::nd::RouterPreference preference{
      packet::nd::RouterPreference::medium};
};

struct OnLinkPrefixCheckpoint {
  ip::Ipv6Prefix prefix{};
  RelativeIpv6Lifetime lifetime{};
};

struct SlaacAddressCheckpoint {
  packet::Ipv6 address{};
  ip::Ipv6Prefix prefix{};
  RelativeIpv6Lifetime preferred_lifetime{};
  RelativeIpv6Lifetime valid_lifetime{};
  AutoconfigAddressState state{AutoconfigAddressState::tentative};
  std::uint32_t dad_counter{};
};

struct RdnssCheckpoint {
  packet::Ipv6 address{};
  RelativeIpv6Lifetime lifetime{};
  std::uint64_t interface_id{};
  std::uint64_t order{};
};

struct Ipv6HostAutoconfigurationCheckpoint {
  // Vectors contain occupied repository entries only. Their upper bounds are
  // generated from the release profile and are validated before live state is
  // touched, so a malformed file cannot force unbounded owner allocations.
  std::vector<DefaultRouterCheckpoint> default_routers;
  std::vector<OnLinkPrefixCheckpoint> on_link_prefixes;
  std::vector<SlaacAddressCheckpoint> addresses;
  std::vector<RdnssCheckpoint> rdnss;
  std::array<std::uint8_t, ethernet_interface_identifier_octets>
      interface_identifier{};
  StableIidSecret stable_secret{};
  std::vector<std::uint8_t> network_id;
  std::uint64_t interface_id{};
  std::uint64_t next_rdnss_order{};
  std::uint32_t link_mtu{};
  std::uint32_t effective_mtu{};
  std::uint32_t current_hop_limit{};
  std::uint32_t reachable_time_milliseconds{};
  std::uint32_t retrans_timer_milliseconds{};
  bool managed_configuration{};
  bool other_configuration{};
  InterfaceIdentifierMode interface_identifier_mode{
      InterfaceIdentifierMode::modified_eui64};
};

class Ipv6HostAutoconfiguration final {
public:
  using Clock = std::chrono::steady_clock;
  static constexpr std::size_t ethernet_interface_identifier_octets =
      host::ethernet_interface_identifier_octets;

  // configure replaces one physical attachment. The caller supplies the IID
  // selected by a separate RFC 7217 or modified EUI-64 identity owner, so this
  // lifetime module neither guesses nor weakens that cryptographic decision.
  [[nodiscard]] bool configure(
      std::uint64_t interface_id,
      const Ipv6InterfaceIdentifierConfiguration &identifier,
      std::uint32_t link_mtu) noexcept;

  // Preconditions: advertisement was accepted by the strict RFC 4861 packet
  // decoder on this interface. Postcondition: each repository is updated from
  // its own advertised lifetime. No router lifetime controls PIO or RDNSS data.
  [[nodiscard]] RouterAdvertisementApply process(
      const packet::nd::RouterAdvertisementView &advertisement,
      bool authenticated = false,
      Clock::time_point now = Clock::now()) noexcept;

  // DAD completion is delivered by the interface's DAD owner. A duplicate
  // removes only the matching tentative SLAAC address and leaves other prefixes
  // and static user intent untouched.
  [[nodiscard]] bool confirm_dad(const packet::Ipv6 &address,
                                 bool duplicate,
                                 Clock::time_point now = Clock::now()) noexcept;
  void expire(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;

  // Checkpoint uses relative lifetimes because steady_clock has no portable
  // epoch. restore validates the complete image and changes this owner only
  // after every prefix, address, repository count and timer is accepted.
  [[nodiscard]] Ipv6HostAutoconfigurationCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] static bool validate_checkpoint(
      const Ipv6HostAutoconfigurationCheckpoint &state) noexcept;
  [[nodiscard]] bool restore(
      const Ipv6HostAutoconfigurationCheckpoint &state,
      Clock::time_point now = Clock::now()) noexcept;

  [[nodiscard]] const auto &default_routers() const noexcept {
    return default_routers_;
  }
  [[nodiscard]] const auto &on_link_prefixes() const noexcept {
    return on_link_prefixes_;
  }
  [[nodiscard]] const auto &addresses() const noexcept { return addresses_; }
  [[nodiscard]] const auto &rdnss() const noexcept { return rdnss_; }
  [[nodiscard]] std::uint32_t current_hop_limit() const noexcept {
    return current_hop_limit_;
  }
  [[nodiscard]] std::uint32_t reachable_time_milliseconds() const noexcept {
    return reachable_time_milliseconds_;
  }
  [[nodiscard]] std::uint32_t retrans_timer_milliseconds() const noexcept {
    return retrans_timer_milliseconds_;
  }
  [[nodiscard]] std::uint32_t effective_mtu() const noexcept {
    return effective_mtu_;
  }
  [[nodiscard]] bool managed_configuration() const noexcept {
    return managed_configuration_;
  }
  [[nodiscard]] bool other_configuration() const noexcept {
    return other_configuration_;
  }

private:
  std::array<DefaultRouterEntry,
             device_catalog::ipv6_default_routers_per_host_interface>
      default_routers_{};
  std::array<OnLinkPrefixEntry,
             device_catalog::ipv6_on_link_prefixes_per_host_interface>
      on_link_prefixes_{};
  std::array<SlaacAddressEntry,
             device_catalog::ipv6_slaac_addresses_per_host_interface>
      addresses_{};
  std::array<RdnssEntry,
             device_catalog::ipv6_rdnss_entries_per_host_interface>
      rdnss_{};
  std::array<std::uint8_t, ethernet_interface_identifier_octets>
      interface_identifier_{};
  StableIidSecret stable_secret_{};
  std::array<std::uint8_t,
             device_catalog::ipv6_stable_iid_network_id_octets>
      network_id_{};
  std::uint8_t network_id_octets_{};
  std::uint64_t interface_id_{};
  std::uint64_t next_rdnss_order_{1U};
  std::uint32_t link_mtu_{};
  std::uint32_t effective_mtu_{};
  std::uint32_t current_hop_limit_{device_catalog::default_ip_hop_limit};
  std::uint32_t reachable_time_milliseconds_{
      static_cast<std::uint32_t>(
          device_catalog::nd_base_reachable_time.count())};
  std::uint32_t retrans_timer_milliseconds_{
      static_cast<std::uint32_t>(device_catalog::nd_retrans_timer.count())};
  bool managed_configuration_{};
  bool other_configuration_{};
  InterfaceIdentifierMode interface_identifier_mode_{
      InterfaceIdentifierMode::modified_eui64};
};

} // namespace router::host
