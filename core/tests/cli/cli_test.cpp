// CLI contract tests exercise generated syntax, router-owned session state and
// datastore semantics without bypassing the injected forwarding boundary.

#include "router/cli.hpp"
#include "router/hardware.hpp"

#include <chrono>
#include <stdexcept>
#include <string_view>

namespace {

void require(bool condition, const char *message) {
  // Keeping assertions local produces one readable failure reason in both the
  // native and WebAssembly test executables without introducing a framework.
  if (!condition)
    throw std::runtime_error(message);
}

bool contains(std::string_view text, std::string_view fragment) {
  return text.find(fragment) != std::string_view::npos;
}

} // namespace

void cli_tests() {
  router::DeviceState state;
  router::CliSession session;
  const auto no_ping = [](router::packet::Ipv4, std::uint32_t, std::uint16_t,
                          bool) {
    return std::string{};
  };

  // A new MD-CLI session starts at operational root. It does not silently own
  // an exclusive candidate, and a read-only route report is available there.
  require(router::cli_prompt(state, session) == "\n[/]\nA:admin@R1# ",
          "MD-CLI did not start in operational root");
  require(state.configuration.running.ports[0].admin_enabled &&
              state.configuration.running.ports[1].admin_enabled &&
              !state.configuration.running.ports[2].admin_enabled,
          "Starter project did not distinguish explicit port enablement from "
          "defaults");
  const auto empty_routes =
      router::execute_cli(state, session, "show router route-table", no_ping);
  require(contains(empty_routes, "Route Table (Router: Base)") &&
              contains(empty_routes, "No. of Routes: 0"),
          "Empty route table did not use the Nokia report layout");
  const auto incomplete_ping =
      router::execute_cli(state, session, "ping", no_ping);
  require(contains(incomplete_ping, "<ip-address>") &&
              !contains(incomplete_ping, "Unknown element"),
          "Incomplete ping did not display contextual argument help");

  // The implicit exclusive workflow uses Nokia's two information messages and
  // enters /configure. Successful leaves are silent; only the prompt marker
  // reveals a candidate difference.
  const auto entered =
      router::execute_cli(state, session, "configure exclusive", no_ping);
  require(contains(entered,
                   "INFO: CLI #2060: Entering exclusive configuration mode") &&
              contains(entered,
                       "INFO: CLI #2061: Uncommitted changes are discarded") &&
              contains(entered, "[ex:/configure]"),
          "Implicit exclusive workflow did not match SR OS");
  const auto card_edit =
      router::execute_cli(state, session, "card 1 card-type iom4-e", no_ping);
  require(!contains(card_edit, "configured") &&
              contains(card_edit, "*[ex:/configure]"),
          "MD card edit was not silent or did not mark the candidate");
  router::execute_cli(state, session, "card 1 mda 1 mda-type me10-10gb-sfp+",
                      no_ping);
  const auto maximum_description = std::string(80, 'x');
  router::execute_cli(state, session,
                      "port 1/1/1 description \"" + maximum_description + "\"",
                      no_ping);
  require(state.configuration.candidate.ports[0].description[79] == 'x',
          "MD port description rejected the documented 80-character limit");
  const auto oversized_description = router::execute_cli(
      state, session, "port 1/1/1 description \"" + std::string(81, 'x') + "\"",
      no_ping);
  require(contains(oversized_description, "MINOR: MGMT_CORE #2301"),
          "MD port description accepted more than 80 characters");
  router::execute_cli(state, session, "delete port 1/1/1 description", no_ping);
  require(state.configuration.candidate.ports[0].description[0] == '\0',
          "MD delete did not remove the port description leaf");
  router::execute_cli(state, session, "commit", no_ping);
  require(router::profile_card(state.configuration.running).type &&
              router::profile_mda(state.configuration.running).type &&
              state.configuration.running_unsaved,
          "MD commit did not atomically publish hardware provisioning");

  // show is rooted in MD-CLI. A relative show from configuration context is an
  // unknown child, while /show executes at operational root and returns to the
  // saved configuration context afterward.
  const auto relative_show =
      router::execute_cli(state, session, "show card", no_ping);
  require(contains(relative_show, "Unknown element - 'show'") &&
              contains(relative_show, "[ex:/configure]"),
          "Relative MD show escaped its configuration context");
  const auto absolute_show =
      router::execute_cli(state, session, "/show card", no_ping);
  require(contains(absolute_show, "Card Summary") &&
              contains(absolute_show, "iom4-e") &&
              contains(absolute_show, "[ex:/configure]"),
          "Absolute MD show did not preserve working context");
  require(router::complete_cli(state, session, "/sho",
                               router::CliCompletionTrigger::tab) == "/show",
          "MD completion removed the absolute-path slash");
  const auto forbidden_navigation =
      router::execute_cli(state, session, "/show", no_ping);
  require(contains(forbidden_navigation,
                   "cannot navigate out of configuration region") &&
              contains(forbidden_navigation, "[ex:/configure]"),
          "Implicit workflow navigated outside the configuration region");

  // Configuration statements entered before a candidate workflow receive the
  // documented CLI #2069 response. Switching an existing implicit exclusive
  // session to explicit retains its dirty candidate and working context.
  router::DeviceState workflow_state;
  router::CliSession workflow_session;
  const auto forbidden_edit =
      router::execute_cli(workflow_state, workflow_session,
                          "configure card 1 card-type iom4-e", no_ping);
  require(contains(forbidden_edit, "MINOR: CLI #2069") &&
              contains(forbidden_edit, "currently in operational mode"),
          "Operational MD-CLI did not reject a configuration statement");
  router::execute_cli(workflow_state, workflow_session, "configure exclusive",
                      no_ping);
  router::execute_cli(workflow_state, workflow_session,
                      "system name workflow-test", no_ping);
  const auto explicit_transition = router::execute_cli(
      workflow_state, workflow_session, "edit-config exclusive", no_ping);
  require(workflow_session.candidate_dirty &&
              workflow_session.md_workflow ==
                  router::MdCliWorkflow::explicit_exclusive &&
              contains(explicit_transition, "*(ex)[/configure]") &&
              !contains(explicit_transition, "Entering exclusive"),
          "Implicit-to-explicit transition discarded or re-created candidate");

  // OSPF configuration contains three successive keyed containers: protocol
  // instance, area and router interface. Each key is a parameter token rather
  // than a literal, so this path catches context traversal defects that simple
  // hardware branches such as `card 1` cannot expose. The read-only workflow
  // is intentional: navigation and reports remain legal there while writes
  // must be rejected by the datastore owner, exactly as on SR OS.
  router::DeviceState ospf_context_state;
  router::CliSession ospf_context_session;
  router::execute_cli(ospf_context_state, ospf_context_session,
                      "edit-config read-only", no_ping);
  // The Base router key is a defaulted MD-CLI list key, not text an operator
  // must enter. Exercise the complete absolute navigation form before testing
  // relative traversal so a parser regression cannot be hidden by first
  // entering the canonical `router "Base"` context.
  require(
      contains(router::execute_cli(ospf_context_state, ospf_context_session,
                                   "configure router interface "
                                   "\"implicit-base\"",
                                   no_ping),
               "(ro)[/configure router \"Base\" interface "
               "\"implicit-base\"]"),
      "MD absolute router path required the defaulted Base key");
  router::execute_cli(ospf_context_state, ospf_context_session, "exit all",
                      no_ping);
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "configure",
                                       no_ping),
                   "(ro)[/configure]"),
          "MD read-only workflow could not enter configure context");
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "router \"Base\"",
                                       no_ping),
                   "(ro)[/configure router \"Base\"]"),
          "MD context could not enter the Base router container");
  const auto ospf_process_context = router::execute_cli(
      ospf_context_state, ospf_context_session, "ospf 0", no_ping);
  if (!contains(ospf_process_context,
                "(ro)[/configure router \"Base\" ospf 0]"))
    throw std::runtime_error(
        "MD context could not enter a keyed OSPF process: " +
        ospf_process_context + " help=" +
        router::complete_cli(ospf_context_state, ospf_context_session, "ospf ",
                             router::CliCompletionTrigger::question));
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "area 1", no_ping),
                   "(ro)[/configure router \"Base\" ospf 0 area 1]"),
          "MD context could not enter a keyed OSPF area");
  require(
      contains(router::execute_cli(ospf_context_state, ospf_context_session,
                                   "interface \"edge\"", no_ping),
               "(ro)[/configure router \"Base\" ospf 0 area 1 interface "
               "\"edge\"]"),
      "MD context could not enter a keyed OSPF interface");
  const auto invalid_ospf_child = router::execute_cli(
      ospf_context_state, ospf_context_session, "not-a-child", no_ping);
  require(contains(invalid_ospf_child, "Unknown element - 'not-a-child'") &&
              contains(invalid_ospf_child,
                       "(ro)[/configure router \"Base\" ospf 0 area 1 "
                       "interface \"edge\"]"),
          "Invalid OSPF child changed or escaped the current context");
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "back 2", no_ping),
                   "(ro)[/configure router \"Base\" ospf 0]"),
          "MD back did not traverse both keyed OSPF child contexts");
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "ospf3 0", no_ping),
                   "Unknown element - 'ospf3'"),
          "MD incorrectly treated sibling OSPF3 as a child of OSPF");
  router::execute_cli(ospf_context_state, ospf_context_session, "back",
                      no_ping);
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "ospf3 0", no_ping),
                   "(ro)[/configure router \"Base\" ospf3 0]"),
          "MD context could not enter a keyed OSPF3 process");
  require(contains(router::execute_cli(ospf_context_state,
                                       ospf_context_session, "area 2", no_ping),
                   "(ro)[/configure router \"Base\" ospf3 0 area 2]"),
          "MD context could not enter an OSPF3 non-backbone area");

  // Configuration strings follow the shared SR OS 7-bit printable rule. The
  // parser must reject UTF-8 bytes instead of accepting a value that a real
  // router cannot store and later emitting it through a different encoding.
  router::DeviceState string_state;
  router::CliSession string_session;
  router::execute_cli(string_state, string_session, "configure exclusive",
                      no_ping);
  const auto non_ascii_name = router::execute_cli(
      string_state, string_session, "system name \"\xC3\xB3\"", no_ping);
  require(contains(non_ascii_name, "MINOR: MGMT_CORE #2301") &&
              std::string_view{
                  string_state.configuration.candidate.system_name.data()} ==
                  router::profile::default_system_name,
          "Configuration accepted a non-ASCII SR OS string");

  router::DeviceState back_state;
  router::CliSession back_session;
  router::execute_cli(back_state, back_session, "configure exclusive", no_ping);
  router::execute_cli(back_state, back_session, "system name dirty", no_ping);
  const auto dirty_back =
      router::execute_cli(back_state, back_session, "back", no_ping);
  require(contains(dirty_back, "Discard uncommitted changes? [y,n]") &&
              contains(dirty_back, "*[ex:/configure]") &&
              back_session.md_exit_confirmation,
          "Dirty back navigation left the implicit region before confirmation");
  const auto canceled_back =
      router::execute_cli(back_state, back_session, "n", no_ping);
  require(contains(canceled_back, "INFO: CLI #2065") &&
              contains(canceled_back, "*[ex:/configure]"),
          "Canceled implicit exit did not restore its working context");

  // MD static routes are keyed by prefix and route type, and next-hop is a
  // typed address key. The former shortened syntax must not mutate candidate.
  const auto old_route =
      router::execute_cli(state, session,
                          "router \"Base\" static-routes route 203.0.113.0/24 "
                          "next-hop 198.51.100.2",
                          no_ping);
  require(contains(old_route, "Unknown element"),
          "Obsolete shortened MD static-route syntax remained executable");
  router::execute_cli(
      state, session,
      "router \"Base\" static-routes route 203.0.113.0/24 route-type unicast "
      "next-hop 198.51.100.2",
      no_ping);
  const auto route_compare =
      router::execute_cli(state, session, "compare", no_ping);
  require(contains(route_compare,
                   "+           route 203.0.113.0/24 route-type unicast {") &&
              contains(route_compare,
                       "+               next-hop 198.51.100.2 {") &&
              !contains(route_compare,
                        "route 203.0.113.0/24 next-hop 198.51.100.2"),
          "MD compare did not emit copyable static-route hierarchy");
  router::execute_cli(state, session, "commit", no_ping);
  require(state.configuration.running.static_routes[0].valid,
          "Documented MD static-route syntax did not install the candidate");
  router::execute_cli(state, session,
                      "delete router \"Base\" static-routes route "
                      "203.0.113.0/24 route-type unicast",
                      no_ping);
  router::execute_cli(state, session, "commit", no_ping);
  require(!state.configuration.running.static_routes[0].valid,
          "MD delete did not remove the keyed static-route entry");

  // System reports consume modeled state rather than fixed demo text. Uptime,
  // pinned image identity and the unsaved configuration indicator must exist.
  const auto information =
      router::execute_cli(state, session, "/show system information", no_ping);
  require(
      contains(information, "System Version         : C-26.7.R1") &&
          contains(information, "Configuration Mode Cfg : mixed") &&
          contains(information, "System Up Time (64-bit):") &&
          contains(information, "Changes Since Last Save: Yes"),
      "System information was not derived from the device profile and state");

  // A configuration-shaped path must never move an operational MD session
  // into a fake configuration context. SR OS requires `configure [mode]` or
  // `edit-config [mode]` to acquire a candidate first. Keeping both workflow
  // and PWC unchanged makes the error recoverable and prevents later leaf
  // commands from appearing to succeed against no datastore.
  router::CliSession operational_navigation{};
  const auto forbidden_configuration_path = router::execute_cli(
      state, operational_navigation,
      "configure router \"Base\" interface \"system\"", no_ping);
  require(contains(forbidden_configuration_path,
                   "Operation not allowed - currently in operational mode") &&
              operational_navigation.md_workflow ==
                  router::MdCliWorkflow::operational &&
              router::cli_prompt(state, operational_navigation) ==
                  "\n[/]\nA:admin@R1# ",
          "Operational MD navigation entered a configuration-looking context");
  // `edit-config` is a workflow command prefix, not a YANG context. Enter on
  // the incomplete command must leave the operational PWC untouched. After a
  // mode is supplied, `configure` becomes ordinary navigation into the
  // configure region of that explicit candidate.
  const auto incomplete_edit = router::execute_cli(
      state, operational_navigation, "edit-config", no_ping);
  require(!contains(incomplete_edit, "[/edit-config]") &&
              operational_navigation.md_workflow ==
                  router::MdCliWorkflow::operational &&
              router::cli_prompt(state, operational_navigation) ==
                  "\n[/]\nA:admin@R1# ",
          "Incomplete edit-config fabricated a configuration context");
  router::execute_cli(state, operational_navigation, "edit-config exclusive",
                      no_ping);
  const auto explicit_configure = router::execute_cli(
      state, operational_navigation, "configure", no_ping);
  require(contains(explicit_configure, "(ex)[/configure]") &&
              operational_navigation.md_workflow ==
                  router::MdCliWorkflow::explicit_exclusive,
          "Explicit workflow could not navigate into configure region");
  router::execute_cli(state, operational_navigation, "exit all", no_ping);
  router::execute_cli(state, operational_navigation, "quit-config", no_ping);
  const auto alarms = [&] {
    // The report test needs one explicit control-plane reconciliation so
    // that active alarms reflect the deliberately absent card and MDA.
    const auto reconciliation = router::hardware::reconcile(
        state.configuration.running, state.hardware, state.operational,
        std::chrono::steady_clock::now());
    (void)reconciliation;
    return router::execute_cli(state, session, "/show system alarms", no_ping);
  }();
  require(contains(alarms, "Alarms [Critical:0 Major:2") &&
              contains(alarms, "7-2003-1") && contains(alarms, "MDA 1/1"),
          "Active facility alarm did not use the Nokia alarm report");

  // The spaces in classic operational reports are observable terminal
  // behavior. These assertions protect the documented SR OS column layout so
  // later UI work cannot quietly replace it with browser-owned formatting.
  const auto interfaces =
      router::execute_cli(state, session, "/show router interface", no_ping);
  const auto first_address_row =
      std::string{"\n   "} + router::profile::interface_addresses.front();
  require(
      contains(interfaces, "   IP-Address                                      "
                           "            PfxState") &&
          contains(interfaces, first_address_row),
      "Router interface report did not preserve SR OS child-row indentation");
  state.operational.arp[0] = {
      .valid = true,
      .address = {198, 51, 100, 2},
      .mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
      .port_index = 0,
      .expires_at = std::chrono::steady_clock::now() + std::chrono::hours{4},
  };
  const auto arp =
      router::execute_cli(state, session, "/show router arp", no_ping);
  require(contains(arp, "02:00:00:00:00:02 04h00m00s Dyn[I] to-host-a"),
          "ARP report columns differed from the documented SR OS layout");
  auto &equipped_card = router::profile_card(state.hardware);
  auto &equipped_mda = router::profile_mda(state.hardware);
  equipped_card.type = router::profile::line_card_type;
  equipped_card.compatible = true;
  equipped_card.equipment.lifecycle = router::EquipmentLifecycle::ready;
  equipped_mda.type = router::profile::modeled_mda_type;
  equipped_mda.compatible = true;
  equipped_mda.equipment.lifecycle = router::EquipmentLifecycle::ready;
  const auto ports = router::execute_cli(state, session, "/show port", no_ping);
  require(
      contains(
          ports,
          "1/1/1         Up    Yes  Up      9212 9212    - netw null xgige"),
      "Port report columns differed from the documented SR OS layout");

  // quit-config belongs to the operational root of an explicit candidate
  // workflow. It must not escape an arbitrary MD configuration context.
  const auto misplaced_quit =
      router::execute_cli(state, session, "quit-config", no_ping);
  require(contains(misplaced_quit, "Unknown element") &&
              session.md_workflow == router::MdCliWorkflow::implicit_exclusive,
          "quit-config ignored its documented workflow context");

  // MD navigation accepts both the closing-brace shortcut and a bounded level
  // count. Crossing above /configure leaves an implicit workflow, as do slash,
  // exit all and Ctrl-Z on hardware.
  router::execute_cli(state, session, "card 1 mda 1", no_ping);
  router::execute_cli(state, session, "}", no_ping);
  require(contains(router::cli_prompt(state, session), "/configure card 1]"),
          "Closing brace did not move to the MD parent context");
  router::execute_cli(state, session, "back 2", no_ping);
  require(session.md_workflow == router::MdCliWorkflow::operational &&
              router::cli_prompt(state, session) == "\n[/]\nA:admin@R1# ",
          "MD back level count did not leave implicit configuration mode");
  router::execute_cli(state, session, "configure exclusive", no_ping);

  // Engine switching retains independent contexts. The switch messages and
  // classic prompt are generated by the router session, never by React.
  const auto switched = router::execute_cli(state, session, "//", no_ping);
  require(contains(switched,
                   "INFO: CLI #2051: Switching to the classic CLI engine") &&
              contains(switched, "A:R1#"),
          "MD to classic engine switch was not Nokia-compatible");
  router::execute_cli(state, session, "configure card 1", no_ping);
  require(contains(router::cli_prompt(state, session), ">config>card#"),
          "Classic card context prompt was not retained");
  router::execute_cli(state, session, "exit", no_ping);
  require(contains(router::cli_prompt(state, session), ">config#"),
          "Classic exit did not move to the higher context");
  router::execute_cli(state, session, "back", no_ping);
  require(router::cli_prompt(state, session) == "\n*A:R1# ",
          "Classic back did not reach operational root");
  router::execute_cli(state, session,
                      "configure port 1/1/1 description \"edge uplink\"",
                      no_ping);
  router::execute_cli(state, session, "configure port 1/1/1 no description",
                      no_ping);
  require(state.configuration.running.ports[0].description[0] == '\0',
          "Classic no description did not remove the port description");
  router::execute_cli(state, session,
                      "configure router static-route-entry 203.0.113.0/24 "
                      "next-hop 198.51.100.2",
                      no_ping);
  router::execute_cli(state, session,
                      "configure router no static-route-entry 203.0.113.0/24",
                      no_ping);
  require(!state.configuration.running.static_routes[0].valid,
          "Classic no static-route-entry did not remove the route");
  const auto classic_help =
      router::execute_cli(state, session, "help edit", no_ping);
  require(contains(classic_help, "Delete current character") &&
              contains(classic_help, "Ctrl-z"),
          "Classic help edit did not expose the documented key bindings");
  router::execute_cli(state, session, "configure card 1", no_ping);
  const auto backslash_show =
      router::execute_cli(state, session, "\\show card", no_ping);
  require(contains(backslash_show, "Card Summary") &&
              contains(router::cli_prompt(state, session), ">config>card#"),
          "Classic backslash absolute path changed the working context");
  router::execute_cli(state, session, "\\", no_ping);
  require(router::cli_prompt(state, session) == "\n*A:R1# ",
          "Classic standalone backslash did not return to root");

  // A command prefixed with // runs as an absolute command in the other engine
  // and immediately restores the originating engine and context.
  const auto foreign =
      router::execute_cli(state, session, "//show mda", no_ping);
  require(
      contains(foreign, "INFO: CLI #2052: Switching to the MD-CLI engine") &&
          contains(foreign, "MDA Summary") &&
          contains(foreign,
                   "\nINFO: CLI #2051: Switching to the classic CLI engine") &&
          session.engine == router::CliEngine::classic,
      "Inline other-engine command did not delimit or restore the classic "
      "session");

  // Classic provisioning starts shut down. Administrative intent is legal on
  // a child while its parent is down, but operational state still depends on
  // the complete parent chain. Immediate writes retain the unsaved prompt.
  router::DeviceState classic_state;
  router::CliSession classic_session;
  router::execute_cli(classic_state, classic_session, "//", no_ping);
  router::execute_cli(classic_state, classic_session,
                      "configure card 1 card-type iom4-e", no_ping);
  require(
      !router::profile_card(classic_state.configuration.running).admin_enabled,
      "Classic card provisioning incorrectly enabled the card");
  router::execute_cli(classic_state, classic_session,
                      "configure card 1 mda 1 mda-type me10-10gb-sfp+",
                      no_ping);
  require(
      !router::profile_mda(classic_state.configuration.running).admin_enabled,
      "Classic MDA provisioning incorrectly enabled the MDA");
  const auto early_mda =
      router::execute_cli(classic_state, classic_session,
                          "configure card 1 mda 1 no shutdown", no_ping);
  require(!contains(early_mda, "Error: Bad command.") &&
              router::profile_mda(classic_state.configuration.running)
                  .admin_enabled &&
              !router::profile_card(classic_state.configuration.running)
                   .admin_enabled,
          "Classic CLI did not preserve independent MDA administrative intent");
  router::execute_cli(classic_state, classic_session,
                      "configure card 1 no shutdown", no_ping);
  require(
      router::profile_card(classic_state.configuration.running).admin_enabled &&
          router::profile_mda(classic_state.configuration.running)
              .admin_enabled &&
          contains(router::cli_prompt(classic_state, classic_session), "*A:"),
      "Classic no shutdown or unsaved prompt behavior failed");
  const auto remove_parent_with_child = router::execute_cli(
      classic_state, classic_session, "configure card 1 no card-type", no_ping);
  require(contains(remove_parent_with_child, "Error: Bad command.") &&
              router::profile_card(classic_state.configuration.running).type &&
              router::profile_mda(classic_state.configuration.running).type,
          "Classic card removal bypassed the provisioned MDA dependency");

  // Ping defaults and count bounds are release data. The injected callback
  // proves that CLI syntax reaches forwarding without a direct device call.
  std::uint32_t requested_count{};
  std::uint16_t requested_size{};
  bool requested_df{};
  const auto counted_ping = [&](router::packet::Ipv4 destination,
                                std::uint32_t count, std::uint16_t size,
                                bool dont_fragment) {
    requested_count = count;
    requested_size = size;
    requested_df = dont_fragment;
    require(destination == router::packet::Ipv4{198, 51, 100, 2},
            "Ping destination changed before forwarding");
    return std::string{"ping-result"};
  };
  router::execute_cli(classic_state, classic_session, "ping 198.51.100.2",
                      counted_ping);
  require(requested_count == 5, "Default ping count was not five");
  require(requested_size == router::profile::default_ping_payload_octets &&
              !requested_df,
          "Default ping size or DF state was not release-compatible");
  router::execute_cli(classic_state, classic_session,
                      "ping 198.51.100.2 count 2", counted_ping);
  require(requested_count == 2, "Explicit ping count was ignored");
  router::execute_cli(
      classic_state, classic_session,
      "ping 198.51.100.2 count 2 size 1000 do-not-fragment", counted_ping);
  require(requested_count == 2 && requested_size == 1000 && requested_df,
          "Explicit ping size or DF option was lost before forwarding");
  const auto invalid_count =
      router::execute_cli(classic_state, classic_session,
                          "ping 198.51.100.2 count 100001", counted_ping);
  require(contains(invalid_count, "Invalid element value"),
          "Ping count range was not enforced");

  // Completion has engine-specific trigger semantics. MD Space completes only
  // keywords, classic Space may list keys, and Tab completes live model data.
  router::CliSession completion_session;
  router::execute_cli(classic_state, completion_session,
                      "edit-config read-only", no_ping);
  const auto default_router_help = router::complete_cli(
      classic_state, completion_session, "configure router ",
      router::CliCompletionTrigger::question);
  require(contains(default_router_help, "interface") &&
              !contains(default_router_help, "\"Base\""),
          "MD help exposed the default Base key instead of router children");
  const auto default_router_completion = router::complete_cli(
      classic_state, completion_session, "configure router inter",
      router::CliCompletionTrigger::tab);
  if (default_router_completion != "configure router interface")
    throw std::runtime_error(
        "MD completion required or exposed the default Base key: " +
        default_router_completion);
  router::execute_cli(classic_state, completion_session, "quit-config",
                      no_ping);
  require(router::complete_cli(classic_state, completion_session, "sho",
                               router::CliCompletionTrigger::space) == "show",
          "Space did not complete a unique keyword");
  require(router::complete_cli(classic_state, completion_session, "show por",
                               router::CliCompletionTrigger::space) ==
              "show port",
          "Enter/Space completion could not expand the final MD keyword");
  require(router::complete_cli(classic_state, completion_session, "//",
                               router::CliCompletionTrigger::space) == "//",
          "Enter completion changed the exact terminal-engine command");
  require(router::complete_cli(classic_state, completion_session, "ping ",
                               router::CliCompletionTrigger::space)
              .empty(),
          "Space incorrectly completed a variable value");
  router::CliSession classic_completion;
  classic_completion.engine = router::CliEngine::classic;
  const auto classic_address_help =
      router::complete_cli(classic_state, classic_completion, "ping ",
                           router::CliCompletionTrigger::space);
  require(contains(classic_address_help, "<ip-address>") &&
              !contains(classic_address_help, "198.51.100.2"),
          "Classic help leaked project endpoints as router address choices");
  require(router::complete_cli(
              classic_state, completion_session, "show router ar",
              router::CliCompletionTrigger::tab) == "show router arp",
          "Tab did not complete the unique ARP keyword");
  const auto question =
      router::complete_cli(classic_state, completion_session, "show router ",
                           router::CliCompletionTrigger::question);
  const bool question_help_valid =
      contains(question, "arp") && contains(question, "fib") &&
          contains(question, "Display the ARP table") &&
          contains(question, "Display forwarding information base entries") &&
          // `show router arp` remains executable, but its documented address,
          // interface and type selectors also make it a navigable context.
          // SR OS online help therefore marks this child with `+`. FIB also
          // owns destination and interface selectors, so it is a context too.
          // Interface is executable as a summary and now also owns the
          // documented name and detail selectors, so it carries the same
          // context marker.
          contains(question, "arp                   + ") &&
          contains(question, "fib                   + ") &&
          contains(question, "interface             + ") &&
          !contains(question, "show router arp");
  if (!question_help_valid)
    throw std::runtime_error(
        "Question-mark help lacked descriptions or leaked complete commands:\n" +
        question);

  const auto unknown =
      router::execute_cli(classic_state, classic_session, "jjj", no_ping);
  require(contains(unknown, "Error: Bad command.") &&
              !contains(unknown, "milestone") && !contains(unknown, "profile"),
          "Classic error leaked emulator implementation details");
}
