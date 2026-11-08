// Normal info must replay through the generated parser into identical intent.
// Detail output shows immutable defaults without mutating the original model.
#include "cli/isis_cli_info.hpp"
#include "cli/isis_cli_configuration.hpp"
#include <sstream>
#include <stdexcept>
namespace {
void require(bool value) { if (!value) throw std::runtime_error("IS-IS info invariant"); }
void apply_command(router::isis::RouterConfiguration &value, std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(router::CliEngine::md,
      router::MdCliWorkflow::explicit_private, text);
  require(parsed.has_value());
  require(router::lab::isis_cli::edit(value, *parsed, router::CliEngine::md).valid);
}
}
void isis_cli_info_tests() {
  using namespace router::lab::isis_cli;
  router::isis::RouterConfiguration original;
  for (const auto text : {
      "configure router \"Base\" isis 127 area-address[49.0001 49.0002]",
      "configure router \"Base\" isis 127 admin-state disable",
      "configure router \"Base\" isis 127 advertise-passive-only true",
      "configure router \"Base\" isis 127 ipv6-routing native",
      "configure router \"Base\" isis 127 level-capability 1/2",
      "configure router \"Base\" isis 127 system-id 0000.0000.0127",
      "configure router \"Base\" isis 127 router-id 10.0.0.127",
      "configure router \"Base\" isis 127 timers spf-wait spf-max-wait 550",
      "configure router \"Base\" isis 127 timers lsp-wait lsp-initial-wait 99",
      "configure router \"Base\" isis 127 level 1 default-metric 20",
      "configure router \"Base\" isis 127 level 2",
      "configure router \"Base\" isis 127 interface \"edge one\" level 1 metric 30",
      "configure router \"Base\" isis 127 interface \"edge one\" level 2",
      "configure router \"Base\" isis 127 interface \"edge one\" passive false"}) apply_command(original, text);
  const auto tree = md_tree(original, false);
  std::istringstream lines{tree};
  std::vector<std::string> contexts;
  router::isis::RouterConfiguration replay;
  for (std::string line; std::getline(lines, line);) {
    const auto first = line.find_first_not_of(' ');
    if (first == std::string::npos) continue;
    auto value = line.substr(first);
    if (value == "}") { require(!contexts.empty()); contexts.pop_back(); continue; }
    const bool context = value.ends_with(" {");
    if (context) value.resize(value.size() - 2U);
    std::string command = "configure router \"Base\"";
    for (const auto &parent : contexts) command += ' ' + parent;
    command += ' ' + value;
    apply_command(replay, command);
    if (context) contexts.push_back(value);
  }
  require(contexts.empty() && original == replay);
  const auto before = original;
  const auto detail = md_tree(original, true);
  require(original == before && detail.find("hello-interval 9") != std::string::npos &&
      detail.find("lsp-mtu-size 1492") != std::string::npos);
  require(classic_leaf("advertise-passive-only true") == "advertise-passive-only" &&
      classic_leaf("advertise-passive-only false") == "no advertise-passive-only");
  require(classic_leaf("area-address 49.0001") == "area-id 49.0001");
  require(classic_leaf("level-capability 1/2") == "level-capability level-1/2");
  require(classic_leaf("ipv4-routing false") == "no ipv4-routing");
  require(classic_leaf("ipv6-routing false") == "no ipv6-routing");
  require(classic_leaf("wide-metrics-only false") == "no wide-metrics-only");
  const std::array<std::string, 4U> timer_body{"  spf-max-wait 550", "  spf-initial-wait 10", "}", "next-sibling"};
  const auto classic_timer = classic_timer_block("spf-wait", timer_body);
  require(classic_timer && classic_timer->lines == 3U &&
      classic_timer->command == "spf-wait 550 spf-initial-wait 10 spf-second-wait 1000");
  require(!classic_timer_block("other", timer_body));
  require(!classic_timer_block("spf-wait", std::span{timer_body}.first(2U)));
  for (const auto &invalid : {std::array<std::string, 3U>{"spf-max-wait 550", "spf-max-wait 600", "}"},
      std::array<std::string, 3U>{"spf-max-wait 550", "lsp-initial-wait 10", "}"},
      std::array<std::string, 3U>{"spf-max-wait 550", "spf-initial-wait 9", "}"}})
    require(!classic_timer_block("spf-wait", invalid));
  require(tree.find("spf-max-wait 550") != std::string::npos && tree.find("lsp-initial-wait 99") != std::string::npos);
  auto edited = original;
  edited.instances[0U].interfaces[0U].level[0U].metric = 40U;
  auto delta = md_compare(original, edited);
  require(delta.find("router \"Base\" {") != std::string::npos &&
      delta.find("isis 127 {") != std::string::npos && delta.find("interface \"edge one\" {") != std::string::npos &&
      delta.find("-                metric 30") != std::string::npos &&
      delta.find("+                metric 40") != std::string::npos && delta.find("system-id") == std::string::npos);
  require(md_compare(original, original).empty());
  edited = original; edited.instances[0U].areas.pop_back();
  delta = md_compare(original, edited);
  require(delta.find("-        area-address 49.0002") != std::string::npos &&
      delta.find("area-address 49.0001") == std::string::npos);
  edited = original; edited.instances[0U].interfaces.clear();
  delta = md_compare(original, edited);
  require(delta.find("-        interface \"edge one\" {") != std::string::npos);
  require(md_compare({}, original).find("+    isis 127 {") != std::string::npos);
  require(md_compare(original, {}).find("-    isis 127 {") != std::string::npos);

}
