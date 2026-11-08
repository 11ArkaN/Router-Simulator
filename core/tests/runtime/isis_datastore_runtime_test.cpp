// Public protocol operations exercise IS-IS candidates, both terminal engines
// and fresh-owner persistence. No private datastore pointer is inspected.
#include "router/lab_runtime.hpp"
#include "router/lab_checkpoint.hpp"
#include "router/generated_lab_runtime_protocol.hpp"
#include <memory>
#include <stdexcept>
namespace {
using namespace router::lab;
namespace lab_runtime_protocol = router::lab_runtime_protocol;
std::string message(std::string_view operation, std::initializer_list<std::string_view> fields = {}) {
  std::string result;
  const auto append = [&](std::string_view value) { result += std::to_string(value.size()) + ':'; result += value; result += ','; };
  append(operation); for (const auto field : fields) append(field); return result;
}
void require(bool value, const char *reason) { if (!value) throw std::runtime_error(reason); }
}
void isis_datastore_runtime_tests() {
  auto runtime = std::make_unique<LabRuntime>();
  const std::array<std::uint8_t, 32U> key{0x42U};
  const std::array<std::uint8_t, 4U> context{'i', 's', 'i', 's'};
  require(runtime->initialize_secret_vault(key, context), "IS-IS datastore vault failed");
  require(!runtime->command(message(lab_runtime_protocol::router_create, {"isis-r1", "7750-sr-1", "R1"})).starts_with("ERROR:"), "IS-IS datastore router creation failed");
  require(!runtime->command(message(lab_runtime_protocol::session_create, {"isis-console", "isis-r1", "operational"})).starts_with("ERROR:"), "IS-IS datastore session creation failed");
  const auto execute = [&](std::string_view command) {
    const auto output = std::string{runtime->command(message(lab_runtime_protocol::session_execute, {"isis-console", command}))};
    if (output.starts_with("ERROR:") || output.find("MINOR:") != std::string::npos || output.find("MAJOR:") != std::string::npos || output.find("Error:") != std::string::npos)
      throw std::runtime_error("IS-IS public CLI rejected " + std::string{command} + ": " + output);
    return output;
  };
  execute("edit-config private");
  execute("/configure router interface \"edge\"");
  execute("/configure router interface \"edge one\"");
  execute("commit");
  execute("/configure router \"Base\" isis 0");

  execute("area-address[49.0001]");
  const auto complete = [&](std::string_view input, std::string_view trigger) {
    return std::string{runtime->command(message(lab_runtime_protocol::session_complete,
        {"isis-console", input, trigger}))};
  };
  require(complete("level ", "question").find("1") != std::string::npos &&
          complete("level ", "question").find("2") != std::string::npos,
      "IS-IS product completion lost generated level values");
  require(complete("level-capability ", "question").find("1/2") != std::string::npos,
      "IS-IS product completion lost generated level capability");
  const auto absolute_completion = complete("/configure router \"Base\" isis 0 interface edge passive", "space");
  require(absolute_completion == "/configure router isis 0 interface edge passive",
      ("absolute MD completion stripped the saved ISIS context prefix: " + absolute_completion).c_str());
  execute("/configure router isis 0 interface \"edge one\" level 1");
  require(complete("hello-int", "tab") == "hello-interval",
      "MD completion split a quoted interface context");
  execute("/configure router isis 0");
  execute("level 1");
  execute("default-metric 30");
  const auto scoped = execute("info");
  require(scoped.find("default-metric 30") != std::string::npos && scoped.find("area-address") == std::string::npos,
      "IS-IS MD info escaped its level context");
  execute("/configure router isis 0 timers spf-wait");
  require(execute("info").find("spf-max-wait") == std::string::npos,
      "empty non-presence SPF context invented explicit values");
  require(execute("info detail").find("spf-max-wait 10000") != std::string::npos,
      "SPF detail lost its YANG default");
  execute("spf-max-wait 550"); execute("spf-initial-wait 10"); execute("spf-second-wait 100000");
  execute("/configure router isis 0 timers lsp-wait"); execute("lsp-initial-wait 99");
  require(execute("info").find("lsp-initial-wait 99") != std::string::npos,
      "LSP intent was replaced with its rounded effective delay");
  execute("/configure router isis 0 level 1");
  execute("/configure router isis 0 admin-state enable");
  const auto compared = execute("compare");
  require(compared.find("isis 0 {") != std::string::npos &&
          compared.find("default-metric 30") != std::string::npos && compared.find('+') != std::string::npos,
      "IS-IS candidate changes were omitted from hierarchical compare");
  const auto image = runtime->export_checkpoint();
  require(!image.empty(), "IS-IS private candidate checkpoint failed");
  const std::vector<std::uint8_t> saved{image.begin(), image.end()};
  auto inconsistent = checkpoint_v12::decode(saved);
  require(inconsistent && !inconsistent->portable_routers.empty(),
      "IS-IS datastore checkpoint could not be inspected");
  router::isis::InstanceIntent enabled;
  enabled.admin_enabled = true;
  inconsistent->portable_routers.front().isis.instances.push_back(enabled);
  const auto inconsistent_image = checkpoint_v12::encode(*inconsistent);
  require(!inconsistent_image.empty() && !runtime->import_checkpoint(inconsistent_image),
      "IS-IS running activation without a protocol owner was restored");
  inconsistent->portable_routers.front().isis.instances.front().admin_enabled = false;
  inconsistent->portable_routers.front().isis.instances.front().interfaces.push_back({});
  inconsistent->portable_routers.front().isis.instances.front().interfaces.back().name = "missing-base-interface";
  const auto dangling_image = checkpoint_v12::encode(*inconsistent);
  require(!dangling_image.empty() && !runtime->import_checkpoint(dangling_image),
      "IS-IS running interface without its Base interface was restored");
  require(execute("info").find("default-metric 30") != std::string::npos,
      "refused IS-IS restoration changed the live candidate");
  runtime.reset();
  runtime = std::make_unique<LabRuntime>();
  require(runtime->initialize_secret_vault(key, context) && runtime->import_checkpoint(saved), "IS-IS candidate fresh-owner restoration failed");
  require(execute("info").find("default-metric 30") != std::string::npos, "IS-IS private candidate leaf was lost");
  execute("/configure router isis 0");
  require(execute("info").find("admin-state enable") != std::string::npos,
      "IS-IS uncommitted candidate activation was lost on restore");
  const auto restored_timers = execute("info");
  require(restored_timers.find("spf-max-wait 550") != std::string::npos &&
      restored_timers.find("lsp-initial-wait 99") != std::string::npos,
      "wait timer intent was lost on candidate checkpoint restore");
  execute("admin-state disable"); execute("level 1");
  const auto before = runtime->command(message(lab_runtime_protocol::snapshot));
  require(before.find("\"isis\":{\"instances\":[]}") != std::string_view::npos, "IS-IS candidate leaked into running");
  execute("commit");
  require(runtime->command(message(lab_runtime_protocol::snapshot)).find("\"defaultMetric\":30") != std::string_view::npos,
      "IS-IS candidate did not reach running");
  execute("exit all"); execute("quit-config");
  execute("edit-config read-only");
  execute("/configure router isis 0");
  execute("level 1");
  require(execute("info").find("default-metric 30") != std::string::npos,
      "read-only IS-IS selection lost its existing level");
  execute("/configure router isis 0 interface \"edge one\" level 1");
  execute("/configure router isis 0 timers spf-wait");
  require(execute("info").find("spf-max-wait 550") != std::string::npos,
      "read-only IS-IS timer context is not navigable");
  for (const std::string_view forbidden : {"spf-max-wait 550", "/delete router isis 0 timers",
      "/configure router isis 127", "/configure router isis 0 interface missing"}) {
    const auto refusal = runtime->command(message(lab_runtime_protocol::session_execute,
        {"isis-console", forbidden}));
    require(refusal.find("#2069") != std::string_view::npos,
        "read-only IS-IS navigation allowed a write or created a missing list");
  }
  require(execute("info").find("spf-max-wait 550") != std::string::npos &&
      runtime->command(message(lab_runtime_protocol::snapshot)).find("\"instance\":127") == std::string_view::npos,
      "rejected read-only IS-IS command changed context or running state");
  execute("exit all"); execute("quit-config"); execute("//");
  require(execute("configure router isis 0").find(">isis#") != std::string::npos,
      "classic explicit IS-IS key leaked into the prompt");
  execute("configure router isis");
  require(execute("level 1").find(">isis>level#") != std::string::npos,
      "classic IS-IS level key leaked into the prompt");
  require(complete("\\configure router isis 0 interface edge passive", "space") ==
          "\\configure router isis 0 interface edge passive",
      "absolute classic completion stripped the saved ISIS context prefix");
  require(execute("info").find("default-metric 30") != std::string::npos, "classic IS-IS info lost the shared level");
  execute("default-metric 40");
  require(runtime->command(message(lab_runtime_protocol::snapshot)).find("\"defaultMetric\":40") != std::string_view::npos,
      "classic IS-IS edit was not immediate");
  execute("no default-metric");
  require(execute("info detail").find("default-metric 10") != std::string::npos, "classic IS-IS removal did not restore its default");
  execute("exit");
  const auto quoted_prompt = execute("configure router isis 0 interface \"edge one\"");
  require(quoted_prompt.find(">isis>if#") != std::string::npos,
      ("classic quoted IS-IS interface key leaked into the prompt: " + quoted_prompt).c_str());
  execute("level 1");
  require(complete("hello-int", "tab") == "hello-interval",
      "classic completion split a quoted interface context");
  execute("configure router isis 0");
  require(execute("info").find("area-id 49.0001") != std::string::npos, "classic IS-IS area spelling is not sourced");
  execute("configure router isis 0 timers");
  const auto classic_timers = execute("info");
  require(classic_timers.find("spf-wait 550 spf-initial-wait 10 spf-second-wait 100000") != std::string::npos &&
      classic_timers.find("lsp-wait 5000 lsp-initial-wait 99 lsp-second-wait 1000") != std::string::npos &&
      classic_timers.find("spf-max-wait") == std::string::npos,
      "classic timer info leaked the MD leaf hierarchy");
  execute("lsp-wait 5000 lsp-initial-wait 109 lsp-second-wait 1000");
  require(execute("info").find("lsp-initial-wait 109") != std::string::npos,
      "classic compound timer did not retain the raw initial delay");
  execute("no lsp-wait"); execute("no spf-wait");
  require(execute("info").find("spf-wait") == std::string::npos &&
      execute("info detail").find("spf-wait 10000 spf-initial-wait 1000 spf-second-wait 1000") != std::string::npos,
      "classic timer reset did not restore whole-group defaults");
  execute("configure router no isis 0");
  require(runtime->command(message(lab_runtime_protocol::snapshot)).find("\"isis\":{\"instances\":[]}") != std::string_view::npos,
      "classic IS-IS subtree removal retained intent");
  execute("configure router isis 1 no ipv4-routing");
  const auto inverse = runtime->command(message(lab_runtime_protocol::snapshot));
  require(inverse.find("\"instance\":1") != std::string_view::npos && inverse.find("\"ipv4Routing\":false") != std::string_view::npos,
      "classic full-path inverse did not create its required instance");
}
