// OSPF CLI editor tests prove that generated MD and classic syntax converges
// on one valid configuration model and that rejected timer edits are atomic.

#include "../src/ospf_cli_configuration.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;

router::cli_detail::ParsedCommand parse(CliEngine engine,
                                        std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated OSPF command did not parse: " +
                             std::string{text});
  return *parsed;
}

void edit(router::ospf::RouterConfiguration &configuration, CliEngine engine,
          std::string_view text) {
  const auto parsed = parse(engine, text);
  const auto result =
      router::lab::ospf_cli::edit(configuration, parsed, engine);
  if (!result.recognized || !result.changed)
    throw std::runtime_error("OSPF command did not change configuration: " +
                             std::string{text});
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void ospf_cli_configuration_tests() {
  router::ospf::RouterConfiguration classic;
  edit(classic, CliEngine::classic,
       "configure router ospf 0 10.255.0.1");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 interface core "
       "interface-type broadcast");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 interface core metric 25");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 reference-bandwidth 400000000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 preference 15");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 external-preference 160");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 export redistribute-connected");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 asbr trace-path 7");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 overload");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 graceful-restart helper");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 loopfree-alternates");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers spf-wait spf-max-wait 12000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers spf-wait spf-second-wait 2000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers spf-wait spf-initial-wait 500");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers lsa-generate max-lsa-wait 7000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers lsa-generate lsa-second-wait 6000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 timers lsa-generate lsa-initial-wait 4000");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.1 stub");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.1 no summaries");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.1 default-metric 17");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.1 area-range "
       "192.0.2.0/24 advertise");
  edit(classic, CliEngine::classic,
       "configure router ospf 0 no shutdown");
  {
    // SR OS accepts assignment of the already effective leaf value. The
    // datastore revision remains unchanged, but the command is not a value
    // error. This distinction prevents a default-enabled interface from
    // rejecting an explicit `admin-state enable`.
    const auto repeated = parse(
        CliEngine::classic, "configure router ospf 0 no shutdown");
    const auto result =
        router::lab::ospf_cli::edit(classic, repeated, CliEngine::classic);
    require(result.recognized && result.valid && !result.changed,
            "idempotent OSPF assignment was reported as invalid");
  }
  require(router::ospf::validate(classic) ==
              router::ospf::ConfigurationStatus::valid,
          "classic OSPF commands produced invalid running intent");
  require(classic.instances.size() == 1U &&
              classic.instances[0].areas.size() == 2U &&
              classic.instances[0].areas[0].interfaces[0].cost == 25U &&
              classic.instances[0].reference_bandwidth_kbps == 400000000U &&
              classic.instances[0].areas[0].interfaces[0].network_type ==
                  router::ospf::NetworkType::broadcast &&
              classic.instances[0].router_preference == 15U &&
              classic.instances[0].external_preference == 160U &&
              classic.instances[0].export_policy ==
                  "redistribute-connected" &&
              classic.instances[0].asbr &&
              classic.instances[0].asbr_trace_path_domain_id ==
                  std::optional<std::uint8_t>{7U} &&
              classic.instances[0].overload &&
              classic.instances[0].graceful_restart_helper &&
              classic.instances[0].loopfree_alternates &&
              classic.instances[0].spf_initial_wait_milliseconds == 500U &&
              classic.instances[0].spf_second_wait_milliseconds == 2000U &&
              classic.instances[0].spf_maximum_wait_milliseconds == 12000U &&
              classic.instances[0].lsa_initial_wait_milliseconds == 4000U &&
              classic.instances[0].lsa_second_wait_milliseconds == 6000U &&
              classic.instances[0].lsa_maximum_wait_milliseconds == 7000U &&
              classic.instances[0].areas[1].type ==
                  router::ospf::AreaType::totally_stub &&
              classic.instances[0].areas[1].default_metric == 17U &&
              classic.instances[0].areas[1].ranges.size() == 1U &&
              classic.instances[0].admin_enabled,
          "classic OSPF leaves did not reach the canonical model");

  router::ospf::RouterConfiguration md;
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 router-id 10.255.0.2");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
       "interface-type point-to-point");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
       "hello-interval 5");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
       "dead-interval 20");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 admin-state enable");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 1 nssa");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 1 area-range "
       "2001:db8:100::/48 not-advertise");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 loopfree-alternates true");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 asbr");
  require(router::ospf::validate(md) ==
              router::ospf::ConfigurationStatus::valid &&
              md.instances[0].address_family ==
                  router::ospf::AddressFamily::ipv6 &&
              md.instances[0].loopfree_alternates &&
              md.instances[0].asbr &&
              !md.instances[0].asbr_trace_path_domain_id &&
              md.instances[0].areas[1].type ==
                  router::ospf::AreaType::nssa &&
              !md.instances[0].areas[1].ranges[0].advertise,
          "MD OSPF3 commands produced the wrong address-family intent");

  // OSPFv3 manual protection names IPsec SAs, not OSPF keychains.  Preserve
  // the two directions independently because SR OS permits key rollover by
  // receiving under one SA while transmitting under another.
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
       "authentication bidirectional sa-name ospf3-core");
  const auto md_ipsec = [&]() -> const auto & {
    return md.instances[0].areas[0].interfaces[0];
  };
  require(md_ipsec().authentication ==
              router::ospf::AuthenticationMode::
                  ipsec_security_association &&
              md_ipsec().ipsec_sa_inbound == "ospf3-core" &&
              md_ipsec().ipsec_sa_outbound == "ospf3-core" &&
              md_ipsec().keychain.empty(),
          "MD bidirectional OSPF3 authentication was not stored as an IPsec SA");
  edit(md, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
       "authentication inbound ospf3-old outbound ospf3-new");
  require(md_ipsec().ipsec_sa_inbound == "ospf3-old" &&
              md_ipsec().ipsec_sa_outbound == "ospf3-new",
          "MD directional OSPF3 authentication collapsed the two SAs");
  edit(md, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 interface core-v6 "
       "authentication");
  require(md_ipsec().authentication ==
              router::ospf::AuthenticationMode::none &&
              md_ipsec().ipsec_sa_inbound.empty() &&
              md_ipsec().ipsec_sa_outbound.empty(),
          "MD delete retained OSPF3 interface IPsec state");

  const auto before = md;
  const auto invalid = parse(
      CliEngine::md,
      "configure router \"Base\" ospf3 0 area 0 interface core-v6 "
      "dead-interval 5");
  const auto rejected =
      router::lab::ospf_cli::edit(md, invalid, CliEngine::md);
  require(rejected.recognized && !rejected.changed && md == before,
          "invalid OSPF timer edit was not rolled back atomically");

  // SR OS exposes NBMA peers as address-keyed list entries below an interface.
  // Both terminal engines must create the same canonical transport record,
  // including the sourced 120-second inactive-neighbor PollInterval.
  router::ospf::RouterConfiguration classic_nbma;
  edit(classic_nbma, CliEngine::classic,
       "configure router ospf 0 area 0 interface wan "
       "interface-type non-broadcast");
  edit(classic_nbma, CliEngine::classic,
       "configure router ospf 0 area 0 interface wan neighbor 192.0.2.2");
  require(classic_nbma.instances[0].areas[0].interfaces[0]
                      .nbma_neighbors.size() == 1U &&
              classic_nbma.instances[0].areas[0].interfaces[0]
                      .nbma_neighbors[0]
                      .poll_interval_seconds ==
                  router::device_catalog::ospf_poll_interval.count(),
          "classic NBMA neighbor did not use the release-owned PollInterval");
  edit(classic_nbma, CliEngine::classic,
       "configure router ospf 0 area 0 interface wan no neighbor 192.0.2.2");
  require(classic_nbma.instances[0].areas[0].interfaces[0]
              .nbma_neighbors.empty(),
          "classic no neighbor retained the NBMA peer");

  router::ospf::RouterConfiguration md_nbma;
  edit(md_nbma, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface wan-v6 "
       "interface-type non-broadcast");
  edit(md_nbma, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 interface wan-v6 "
       "neighbor fe80::2");
  require(md_nbma.instances[0].areas[0].interfaces[0]
                      .nbma_neighbors.size() == 1U &&
              md_nbma.instances[0].areas[0].interfaces[0]
                      .nbma_neighbors[0]
                      .address.family ==
                  router::ip::AddressFamily::ipv6,
          "MD OSPF3 neighbor did not preserve its IPv6 transport address");
  edit(md_nbma, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 interface wan-v6 "
       "neighbor fe80::2");
  require(md_nbma.instances[0].areas[0].interfaces[0]
              .nbma_neighbors.empty(),
          "MD delete neighbor retained the OSPF3 NBMA peer");

  // A virtual link is keyed by the remote ABR and transit area under area 0.
  // The transit area is created first because the canonical model enforces the
  // same non-stub, non-NSSA reference required by SR OS and the RFCs.
  router::ospf::RouterConfiguration classic_virtual;
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.1 interface transit "
       "interface-type point-to-point");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1");
  require(classic_virtual.instances[0].areas[1].virtual_links.size() == 1U &&
              classic_virtual.instances[0].areas[1].virtual_links[0]
                      .remote_router_id == 0x02020202U &&
              classic_virtual.instances[0].areas[1].virtual_links[0]
                      .transit_area_id == 1U,
          "classic virtual-link did not preserve both list keys");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1 dead-interval 60");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1 hello-interval 20");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1 retransmit-interval 9");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1 transit-delay 3");
  const auto &classic_timers =
      classic_virtual.instances[0].areas[1].virtual_links[0];
  require(classic_timers.hello_interval_seconds == 20U &&
              classic_timers.dead_interval_seconds == 60U &&
              classic_timers.retransmit_interval_seconds == 9U &&
              classic_timers.transmit_delay_seconds == 3U,
          "classic virtual-link timer leaves did not update canonical intent");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1 no hello-interval");
  require(classic_virtual.instances[0].areas[1].virtual_links[0]
                  .hello_interval_seconds ==
              router::device_catalog::ospf_hello_interval.count(),
          "classic no hello-interval did not restore the release default");
  edit(classic_virtual, CliEngine::classic,
       "configure router ospf 0 area 0.0.0.0 no virtual-link 2.2.2.2 "
       "transit-area 0.0.0.1");
  require(classic_virtual.instances[0].areas[1].virtual_links.empty(),
          "classic no virtual-link retained the configured endpoint");

  // Classic CLI reaches the same canonical directional state even though its
  // surface syntax omits MD-CLI's explicit `sa-name` keyword.
  router::ospf::RouterConfiguration classic_ipsec;
  edit(classic_ipsec, CliEngine::classic,
       "configure router ospf3 0 area 0 interface core-v6 "
       "authentication bidirectional ospf3-core");
  const auto classic_ipsec_interface = [&]() -> const auto & {
    return classic_ipsec.instances[0].areas[0].interfaces[0];
  };
  require(classic_ipsec_interface().authentication ==
              router::ospf::AuthenticationMode::
                  ipsec_security_association &&
              classic_ipsec_interface().ipsec_sa_inbound == "ospf3-core" &&
              classic_ipsec_interface().ipsec_sa_outbound == "ospf3-core",
          "classic bidirectional OSPF3 authentication lost its SA name");
  edit(classic_ipsec, CliEngine::classic,
       "configure router ospf3 0 area 0 interface core-v6 "
       "authentication inbound ospf3-old outbound ospf3-new");
  require(classic_ipsec_interface().ipsec_sa_inbound == "ospf3-old" &&
              classic_ipsec_interface().ipsec_sa_outbound == "ospf3-new",
          "classic directional OSPF3 authentication collapsed the two SAs");
  edit(classic_ipsec, CliEngine::classic,
       "configure router ospf3 0 area 0 interface core-v6 "
       "no authentication");
  require(classic_ipsec_interface().authentication ==
              router::ospf::AuthenticationMode::none,
          "classic no authentication retained OSPF3 IPsec state");

  router::ospf::RouterConfiguration md_virtual;
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 1 interface transit-v6 "
       "interface-type point-to-point");
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1");
  require(md_virtual.instances[0].areas[1].virtual_links.size() == 1U &&
              md_virtual.instances[0].areas[1].virtual_links[0]
                      .remote_router_id == 0x03030303U,
          "MD OSPF3 virtual-link did not reach canonical intent");
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 dead-interval 80");
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 hello-interval 30");
  require(md_virtual.instances[0].areas[1].virtual_links[0]
                      .hello_interval_seconds == 30U &&
              md_virtual.instances[0].areas[1].virtual_links[0]
                      .dead_interval_seconds == 80U,
          "MD OSPF3 virtual-link timers did not reach canonical intent");
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 authentication bidirectional sa-name vl-shared");
  const auto md_virtual_auth = [&]() -> const auto & {
    return md_virtual.instances[0].areas[1].virtual_links[0];
  };
  require(md_virtual_auth().authentication ==
              router::ospf::AuthenticationMode::
                  ipsec_security_association &&
              md_virtual_auth().ipsec_sa_inbound == "vl-shared" &&
              md_virtual_auth().ipsec_sa_outbound == "vl-shared",
          "MD OSPF3 virtual-link did not preserve its bidirectional SA");
  edit(md_virtual, CliEngine::md,
       "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 authentication inbound vl-old outbound vl-new");
  require(md_virtual_auth().ipsec_sa_inbound == "vl-old" &&
              md_virtual_auth().ipsec_sa_outbound == "vl-new",
          "MD OSPF3 virtual-link collapsed directional SA names");
  edit(md_virtual, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 authentication");
  require(md_virtual_auth().authentication ==
              router::ospf::AuthenticationMode::none,
          "MD delete retained virtual-link authentication");
  const auto rejected_command = parse(
      CliEngine::md,
      "configure router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
      "transit-area 1 hello-interval 50");
  const auto rejected_virtual_timer = router::lab::ospf_cli::edit(
      md_virtual, rejected_command, CliEngine::md);
  require(rejected_virtual_timer.recognized &&
              !rejected_virtual_timer.changed &&
              md_virtual.instances[0].areas[1].virtual_links[0]
                      .hello_interval_seconds == 30U,
          "invalid virtual-link dead-to-hello ratio mutated canonical intent");
  edit(md_virtual, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 hello-interval");
  edit(md_virtual, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1 dead-interval");
  require(md_virtual.instances[0].areas[1].virtual_links[0]
                  .dead_interval_seconds ==
              router::device_catalog::ospf_dead_interval.count(),
          "MD delete dead-interval did not restore the release default");
  edit(md_virtual, CliEngine::md,
       "delete router \"Base\" ospf3 0 area 0 virtual-link 3.3.3.3 "
       "transit-area 1");
  require(md_virtual.instances[0].areas[1].virtual_links.empty(),
          "MD delete virtual-link retained the configured endpoint");
}
