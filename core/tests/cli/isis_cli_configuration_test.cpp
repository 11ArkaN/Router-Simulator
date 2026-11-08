// Both generated CLI engines must converge on one intent and reject edits
// atomically. These tests enter through the production parser, not synthetic IDs.
#include "cli/isis_cli_configuration.hpp"
#include <stdexcept>
#include <string>
namespace {
using router::CliEngine;
void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
router::lab::isis_cli::EditResult apply(router::isis::RouterConfiguration &config,
    CliEngine engine, std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(engine,
      engine == CliEngine::md ? router::MdCliWorkflow::explicit_private : router::MdCliWorkflow::operational, text);
  require(parsed.has_value(), "IS-IS command failed to parse");
  return router::lab::isis_cli::edit(config, *parsed, engine);
}
}
void isis_cli_configuration_tests() {
  std::size_t checked{};
  for (const auto &spec : router::cli_schema::commands) {
    if (spec.source_id != "nokia.sros.26_7.isis.basic_cli") continue;
    const auto engine = (spec.engine_mask & 1U) ? CliEngine::md : CliEngine::classic;
    std::string text;
    for (std::size_t index{}; index < spec.token_count; ++index) {
      const auto &token = spec.tokens[index];
      std::string value;
      using enum router::cli_schema::TokenKind;
      switch (token.kind) {
      case literal: value = token.display; break;
      case interface_name: value = "edge"; break;
      case ipv4: value = "10.0.0.1"; break;
      case isis_system_id: case isis_classic_system_id: value = "0000.0000.0001"; break;
      case isis_area_address: value = "49.0001"; break;
      default: {
        const auto keywords = router::cli_schema::parameter_values(token.kind);
        const auto range = router::cli_schema::parameter_integer_range(token.kind);
        if (!keywords.empty()) value = keywords.front();
        else if (range.constrained) value = std::to_string(range.minimum);
        else throw std::runtime_error("uncovered IS-IS test parameter");
      }
      }
      if (!text.empty()) text += ' ';
      text += value;
    }
    router::isis::RouterConfiguration configuration;
    const auto seed = engine == CliEngine::md ?
        "configure router \"Base\" isis 0 interface edge level 1 metric 20" :
        "configure router isis 0 interface edge level 1 metric 20";
    require(apply(configuration, engine, seed).valid, "surface seed rejected");
    const auto edited = apply(configuration, engine, text);
    if (!edited.recognized || !edited.valid)
      throw std::runtime_error("IS-IS surface editor rejected: " + text);
    ++checked;
  }
  require(checked == 191U, "IS-IS surface coverage changed without test review");
  router::isis::RouterConfiguration inverse;
  const auto disabled_ipv4 = apply(inverse, CliEngine::classic, "configure router isis 1 no ipv4-routing");
  require(disabled_ipv4.valid && disabled_ipv4.changed && inverse.instances.size() == 1U &&
      inverse.instances[0U].ipv4_routing == false, "classic inverse lost an absent parent context");
  const auto enabled = apply(inverse, CliEngine::classic, "configure router isis 2 no shutdown");
  require(enabled.valid && enabled.changed && inverse.instances[1U].admin_enabled == true, "classic no shutdown became an absent-parent no-op");
  require(apply(inverse, CliEngine::classic, "configure router isis 3 interface edge level 1 no metric").valid &&
      inverse.instances[2U].interfaces[0U].level[0U].present, "classic default restoration did not retain entered contexts");
  router::isis::RouterConfiguration md, classic;
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 area-address[49.0002 49.0001]").valid, "compact leaf-list rejected");
  require(apply(classic, CliEngine::classic, "configure router isis area-id 49.0001").valid, "classic implicit instance rejected");
  require(apply(classic, CliEngine::classic, "configure router isis 0 area-id 49.0002").valid, "classic explicit instance rejected");
  require(md == classic, "area order or engine intent differs");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 level-capability 1/2").valid, "MD level union rejected");
  require(apply(classic, CliEngine::classic, "configure router isis level-capability level-1/2").valid, "classic enum mapping rejected");
  require(md == classic, "classic enum did not map to YANG");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 interface \"edge[1]\" level 2 metric 16777215").valid, "quoted brackets or maximum metric rejected");
  require(apply(classic, CliEngine::classic, "configure router isis interface edge[1] level 2 metric 16777215").valid, "classic brackets changed tokenization");
  require(md == classic, "interface level intent differs");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 interface \"edge[1]\" interface-type point").valid, "unique enum abbreviation rejected");
  require(apply(classic, CliEngine::classic, "configure router isis interface edge[1] interface-type point-to-point").valid && md == classic, "abbreviated enum changed intent");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 admin-state enable").valid, "MD enable rejected");
  require(apply(classic, CliEngine::classic, "configure router isis no shutdown").valid && md == classic, "classic inverse shutdown differs");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 interface \"edge[1]\" level 2 passive true").valid, "MD passive rejected");
  require(apply(classic, CliEngine::classic, "configure router isis interface edge[1] level 2 passive").valid && md == classic, "classic passive differs");
  require(apply(md, CliEngine::md, "delete router \"Base\" isis 0 interface \"edge[1]\" level 2 passive").valid &&
      !md.instances[0].interfaces[0].level[1].passive.has_value(), "MD removal retained explicit leaf default");
  require(apply(classic, CliEngine::classic, "configure router isis interface edge[1] level 2 no passive").valid &&
      classic.instances[0].interfaces[0].level[1].passive == false, "classic inverse did not disable passive");
  require(apply(md, CliEngine::md, "configure router \"Base\" isis 0 interface \"edge[1]\" level 2 passive false").valid && md == classic, "classic inverse does not match explicit MD false");
  const auto before = md;
  require(!apply(md, CliEngine::md, "configure router \"Base\" isis 0 area-address[49.0003 49.0004]").valid && md == before, "area overflow partially changed intent");
  require(apply(md, CliEngine::md, "delete router \"Base\" isis 0 interface \"edge[1]\" level 2 metric").valid, "metric removal rejected");
  require(apply(classic, CliEngine::classic, "configure router isis interface edge[1] level 2 no metric").valid, "classic metric removal rejected");
  require(md == classic && md.instances[0].interfaces[0].level[1].present, "leaf removal deleted level context");
  require(apply(md, CliEngine::md, "delete router \"Base\" isis 0 area-address[*]").valid && md.instances[0].areas.empty(), "wildcard removal failed");
  const auto unchanged = md;
  require(apply(md, CliEngine::md, "delete router \"Base\" isis 127 interface missing").valid && md == unchanged, "absent removal created parents");
  for (const auto text : {"configure router \"Base\" isis 128", "configure router \"Base\" isis 0 level-capability 3", "configure router \"Base\" isis 0 interface x level 1 metric 16777216"})
    require(!router::cli_detail::parse_command(CliEngine::md, router::MdCliWorkflow::explicit_private, text), "out-of-range command parsed");
}
