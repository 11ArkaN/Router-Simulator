// Release-backed OSPF configuration defaults and whole-generation validation.
// Validation is pure and leaves the caller's candidate unchanged on failure.

#include "router/ospf_configuration.hpp"

#include "router/generated_device_catalog.hpp"

#include <algorithm>

namespace router::ospf {

InstanceConfiguration default_instance(AddressFamily family,
                                       std::uint8_t instance_id) {
  return {
      .reference_bandwidth_kbps =
          device_catalog::ospf_reference_bandwidth_kbps,
      .router_preference = device_catalog::ospf_router_preference,
      .external_preference = device_catalog::ospf_external_preference,
      .spf_initial_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_spf_initial_wait.count()),
      .spf_second_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_spf_second_wait.count()),
      .spf_maximum_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_spf_maximum_wait.count()),
      .lsa_initial_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_lsa_initial_wait.count()),
      .lsa_second_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_lsa_second_wait.count()),
      .lsa_maximum_wait_milliseconds = static_cast<std::uint32_t>(
          device_catalog::ospf_lsa_maximum_wait.count()),
      .instance_id = instance_id,
      .address_family = family,
      // Nokia creates OSPF and OSPF3 instances shutdown. A terminal command
      // must explicitly enable the process after its required configuration.
      .admin_enabled = false};
}

ConfigurationStatus
validate(const RouterConfiguration &configuration,
         bool allow_incomplete) noexcept {
  for (std::size_t index{}; index < configuration.keychains.size(); ++index) {
    if (validate(configuration.keychains[index], allow_incomplete) !=
        KeychainStatus::valid)
      return ConfigurationStatus::invalid_reference;
    for (std::size_t prior{}; prior < index; ++prior)
      if (configuration.keychains[prior].name ==
          configuration.keychains[index].name)
        return ConfigurationStatus::invalid_reference;
  }
  for (std::size_t instance_index{};
       instance_index < configuration.instances.size(); ++instance_index) {
    const auto &instance = configuration.instances[instance_index];
    const bool v2 = instance.address_family == AddressFamily::ipv4;
    const bool valid_id =
        v2 ? instance.instance_id >=
                     device_catalog::ospf_v2_instance_first &&
                 instance.instance_id <=
                     device_catalog::ospf_v2_instance_last
           : (instance.address_family == AddressFamily::ipv6
                  ? instance.instance_id >=
                            device_catalog::ospf_v3_ipv6_instance_first &&
                        instance.instance_id <=
                            device_catalog::ospf_v3_ipv6_instance_last
                  : instance.instance_id >=
                            device_catalog::ospf_v3_ipv4_instance_first &&
                        instance.instance_id <=
                            device_catalog::ospf_v3_ipv4_instance_last);
    if (!valid_id || instance.reference_bandwidth_kbps == 0U ||
        instance.router_preference > 255U ||
        instance.external_preference > 255U ||
        instance.spf_initial_wait_milliseconds < 10U ||
        instance.spf_initial_wait_milliseconds > 100000U ||
        instance.spf_second_wait_milliseconds < 10U ||
        instance.spf_second_wait_milliseconds > 100000U ||
        instance.spf_maximum_wait_milliseconds < 10U ||
        instance.spf_maximum_wait_milliseconds > 120000U ||
        instance.spf_initial_wait_milliseconds >
            instance.spf_second_wait_milliseconds ||
        instance.spf_second_wait_milliseconds >
            instance.spf_maximum_wait_milliseconds ||
        instance.lsa_initial_wait_milliseconds < 10U ||
        instance.lsa_initial_wait_milliseconds > 600000U ||
        instance.lsa_second_wait_milliseconds < 10U ||
        instance.lsa_second_wait_milliseconds > 600000U ||
        instance.lsa_maximum_wait_milliseconds < 10U ||
        instance.lsa_maximum_wait_milliseconds > 600000U ||
        instance.lsa_initial_wait_milliseconds >
            instance.lsa_second_wait_milliseconds ||
        instance.lsa_second_wait_milliseconds >
            instance.lsa_maximum_wait_milliseconds ||
        (instance.asbr_trace_path_domain_id &&
         (!v2 || !instance.asbr ||
          *instance.asbr_trace_path_domain_id == 0U ||
          *instance.asbr_trace_path_domain_id > 31U)))
      return ConfigurationStatus::invalid_instance;
    for (std::size_t previous{}; previous < instance_index; ++previous)
      if (configuration.instances[previous].instance_id ==
              instance.instance_id &&
          configuration.instances[previous].address_family ==
              instance.address_family)
        return ConfigurationStatus::duplicate_instance;

    for (std::size_t area_index{}; area_index < instance.areas.size();
         ++area_index) {
      const auto &area = instance.areas[area_index];
      for (std::size_t previous{}; previous < area_index; ++previous)
        if (instance.areas[previous].area_id == area.area_id)
          return ConfigurationStatus::duplicate_area;
      if (area.nssa_translate_always && area.type != AreaType::nssa)
        return ConfigurationStatus::invalid_area;
      // RFC 5838 section 2.8 prohibits virtual links for every OSPFv3
      // address family other than base IPv6 unicast. Their transport is a
      // routed global IPv6 packet, and an IPv4-AF instance cannot derive that
      // path from its own AF LSDB. Rejecting the candidate here prevents the
      // process owner from later inventing cross-instance reachability.
      if (!area.virtual_links.empty() &&
          (area.area_id != 0U ||
           instance.address_family == AddressFamily::ipv4_over_ospfv3))
        return ConfigurationStatus::invalid_area;
      for (std::size_t link_index{}; link_index < area.virtual_links.size();
           ++link_index) {
        const auto &link = area.virtual_links[link_index];
        if (link.transit_area_id == 0U || link.remote_router_id == 0U ||
            link.hello_interval_seconds <
                device_catalog::ospf_hello_interval_minimum.count() ||
            link.hello_interval_seconds >
                device_catalog::ospf_hello_interval_maximum.count() ||
            link.dead_interval_seconds <
                device_catalog::ospf_dead_interval_minimum.count() ||
            link.dead_interval_seconds >
                device_catalog::ospf_dead_interval_maximum.count() ||
            link.dead_interval_seconds <
                2U * static_cast<std::uint32_t>(
                         link.hello_interval_seconds) ||
            link.retransmit_interval_seconds <
                device_catalog::ospf_retransmit_interval_minimum.count() ||
            link.retransmit_interval_seconds >
                device_catalog::ospf_retransmit_interval_maximum.count() ||
            link.transmit_delay_seconds <
                device_catalog::ospf_transmit_delay_minimum.count() ||
            link.transmit_delay_seconds >
                device_catalog::ospf_transmit_delay_maximum.count() ||
            ((link.authentication == AuthenticationMode::keychain ||
              link.authentication ==
                  AuthenticationMode::authentication_trailer) &&
             link.keychain.empty()) ||
            (link.authentication != AuthenticationMode::keychain &&
             link.authentication !=
                 AuthenticationMode::authentication_trailer &&
             !link.keychain.empty()) ||
            (link.authentication ==
                 AuthenticationMode::ipsec_security_association &&
             (link.ipsec_sa_inbound.empty() ||
              link.ipsec_sa_outbound.empty())) ||
            (link.authentication !=
                 AuthenticationMode::ipsec_security_association &&
             (!link.ipsec_sa_inbound.empty() ||
              !link.ipsec_sa_outbound.empty())) ||
            (!allow_incomplete &&
             ((link.authentication == AuthenticationMode::simple_password ||
               link.authentication == AuthenticationMode::message_digest) !=
              (link.authentication_secret != 0U))) ||
            (!v2 &&
             (link.authentication == AuthenticationMode::simple_password ||
              link.authentication == AuthenticationMode::message_digest)) ||
            (v2 &&
             (link.authentication ==
                  AuthenticationMode::authentication_trailer ||
              link.authentication ==
                  AuthenticationMode::ipsec_security_association)))
          return ConfigurationStatus::invalid_area;
        if ((link.authentication == AuthenticationMode::keychain ||
             link.authentication ==
                 AuthenticationMode::authentication_trailer) &&
            std::none_of(configuration.keychains.begin(),
                         configuration.keychains.end(),
                         [&](const auto &keychain) {
                           return keychain.name == link.keychain;
                         }))
          return ConfigurationStatus::invalid_reference;
        const auto transit = std::find_if(
            instance.areas.begin(), instance.areas.end(),
            [&](const auto &candidate) {
              return candidate.area_id == link.transit_area_id;
            });
        // Both RFC 2328 section 15 and SR OS 26.7 prohibit a stub or NSSA
        // transit area. The reference must resolve in this protocol instance
        // so runtime never searches another instance or fabricates a path.
        if (transit == instance.areas.end() ||
            transit->type != AreaType::normal)
          return ConfigurationStatus::invalid_area;
        for (std::size_t previous{}; previous < link_index; ++previous)
          if (area.virtual_links[previous].transit_area_id ==
                  link.transit_area_id &&
              area.virtual_links[previous].remote_router_id ==
                  link.remote_router_id)
            return ConfigurationStatus::invalid_area;
      }
      for (std::size_t interface_index{};
           interface_index < area.interfaces.size(); ++interface_index) {
        const auto &interface = area.interfaces[interface_index];
        if (interface.interface_name.empty() ||
            interface.cost >
                device_catalog::ospf_interface_metric_maximum ||
            interface.hello_interval_seconds <
                device_catalog::ospf_hello_interval_minimum.count() ||
            interface.hello_interval_seconds >
                device_catalog::ospf_hello_interval_maximum.count() ||
            interface.dead_interval_seconds <
                device_catalog::ospf_dead_interval_minimum.count() ||
            interface.dead_interval_seconds >
                device_catalog::ospf_dead_interval_maximum.count() ||
            interface.dead_interval_seconds <
                2U * static_cast<std::uint32_t>(
                         interface.hello_interval_seconds) ||
            interface.retransmit_interval_seconds <
                device_catalog::ospf_retransmit_interval_minimum.count() ||
            interface.retransmit_interval_seconds >
                device_catalog::ospf_retransmit_interval_maximum.count() ||
            interface.transmit_delay_seconds <
                device_catalog::ospf_transmit_delay_minimum.count() ||
            interface.transmit_delay_seconds >
                device_catalog::ospf_transmit_delay_maximum.count())
          return ConfigurationStatus::invalid_timer;
        for (std::size_t prior_area{}; prior_area <= area_index;
             ++prior_area) {
          const auto &other_area = instance.areas[prior_area];
          const auto end =
              prior_area == area_index ? interface_index
                                       : other_area.interfaces.size();
          for (std::size_t prior_interface{};
               prior_interface < end; ++prior_interface)
            if (other_area.interfaces[prior_interface].interface_name ==
                interface.interface_name)
              return ConfigurationStatus::duplicate_interface;
        }
        if (interface.network_type != NetworkType::non_broadcast &&
            !interface.nbma_neighbors.empty())
          return ConfigurationStatus::invalid_reference;
        if (((interface.authentication == AuthenticationMode::keychain ||
              interface.authentication ==
                  AuthenticationMode::authentication_trailer) &&
             interface.keychain.empty()) ||
            (interface.authentication != AuthenticationMode::keychain &&
             interface.authentication !=
                 AuthenticationMode::authentication_trailer &&
             !interface.keychain.empty()) ||
            (interface.authentication ==
                 AuthenticationMode::ipsec_security_association &&
             (interface.ipsec_sa_inbound.empty() ||
              interface.ipsec_sa_outbound.empty())) ||
            (interface.authentication !=
                 AuthenticationMode::ipsec_security_association &&
             (!interface.ipsec_sa_inbound.empty() ||
              !interface.ipsec_sa_outbound.empty())) ||
            (!allow_incomplete &&
             ((interface.authentication ==
                   AuthenticationMode::simple_password ||
               interface.authentication ==
                   AuthenticationMode::message_digest) !=
              (interface.authentication_secret != 0U))) ||
            (!v2 &&
             (interface.authentication ==
                  AuthenticationMode::simple_password ||
              interface.authentication ==
                  AuthenticationMode::message_digest)) ||
            (v2 &&
             (interface.authentication ==
                  AuthenticationMode::authentication_trailer ||
              interface.authentication ==
                  AuthenticationMode::ipsec_security_association)))
          return ConfigurationStatus::invalid_reference;
        if ((interface.authentication == AuthenticationMode::keychain ||
             interface.authentication ==
                 AuthenticationMode::authentication_trailer) &&
            std::none_of(configuration.keychains.begin(),
                         configuration.keychains.end(),
                         [&](const auto &keychain) {
                           return keychain.name == interface.keychain;
                         }))
          return ConfigurationStatus::invalid_reference;
        for (std::size_t neighbor_index{};
             neighbor_index < interface.nbma_neighbors.size();
             ++neighbor_index) {
          const auto &neighbor =
              interface.nbma_neighbors[neighbor_index];
          if (neighbor.address.family !=
                  (v2 ? ip::AddressFamily::ipv4
                      : ip::AddressFamily::ipv6) ||
              neighbor.poll_interval_seconds == 0U)
            return ConfigurationStatus::invalid_reference;
          for (std::size_t previous{}; previous < neighbor_index; ++previous)
            if (interface.nbma_neighbors[previous].address ==
                neighbor.address)
              return ConfigurationStatus::invalid_reference;
        }
      }
    }
  }
  return ConfigurationStatus::valid;
}

} // namespace router::ospf
