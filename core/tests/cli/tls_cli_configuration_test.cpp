// TLS CLI editor tests prove the documented MD-CLI delete semantics: deletes
// of absent or already-default elements succeed silently without creating
// configuration, out-of-range entry keys stay rejected, and classic no forms
// keep the rejected result for absent elements.

#include "cli/tls_cli_configuration.hpp"

#include <stdexcept>
#include <string>
#include <string_view>

namespace {

router::cli_detail::ParsedCommand parse(router::CliEngine engine,
                                        std::string_view text) {
  const auto parsed = router::cli_detail::parse_command(
      engine, engine == router::CliEngine::md
                  ? router::MdCliWorkflow::explicit_private
                  : router::MdCliWorkflow::operational,
      text);
  if (!parsed)
    throw std::runtime_error("generated TLS command did not parse: " +
                             std::string{text});
  return *parsed;
}

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void tls_cli_configuration_tests() {
  router::tls_profile::Configuration configuration;

  // An MD delete of an absent element is the documented silent no-op: valid,
  // without a datastore change and without materializing the named profile.
  const auto md_delete_absent = [&](std::string_view text) {
    const auto before = configuration;
    const auto result =
        router::lab::tls_cli::edit(configuration,
                                   parse(router::CliEngine::md, text),
                                   router::CliEngine::md);
    require(result.recognized, "MD delete was not recognized");
    require(result.valid, "MD delete of an absent element was not silent");
    require(!result.changed, "MD delete of an absent element changed state");
    require(configuration == before,
            "MD delete of an absent element persisted state");
  };
  md_delete_absent("delete system security tls cert-profile missing");
  md_delete_absent("delete system security tls use-pqc-only");
  md_delete_absent(
      "delete system security tls cert-profile missing entry 1 "
      "certificate-file");

  // An entry index outside the documented 1..8 profile range is rejected by
  // the generated grammar itself, before any editor runs, in both engines.
  const auto parse_rejected = [&](router::CliEngine engine,
                                  std::string_view text) {
    const auto parsed = router::cli_detail::parse_command(
        engine, engine == router::CliEngine::md
                    ? router::MdCliWorkflow::explicit_private
                    : router::MdCliWorkflow::operational,
        text);
    require(!parsed.has_value(), "out-of-range entry key was not rejected");
  };
  parse_rejected(router::CliEngine::md,
                 "delete system security tls cert-profile missing entry 9 "
                 "certificate-file");
  parse_rejected(router::CliEngine::md,
                 "configure system security tls cert-profile missing entry 9 "
                 "certificate-file missing.pem");

  // Classic no forms keep the rejected result for absent elements.
  const auto reject = [&](router::CliEngine engine, std::string_view text) {
    const auto before = configuration;
    const auto result = router::lab::tls_cli::edit(
        configuration, parse(engine, text), engine);
    require(result.recognized, "command was not recognized");
    require(!result.valid, "classic absent-element no was not rejected");
    require(!result.changed, "rejected classic no changed configuration");
    require(configuration == before, "rejected classic no persisted state");
  };
  reject(router::CliEngine::classic,
         "configure system security tls no cert-profile missing");

  // A delete that removes configured state stays a real change, and a second
  // delete of the now-default leaf becomes the silent no-op.
  const auto configured = parse(
      router::CliEngine::md,
      "configure system security tls use-pqc-only true");
  const auto first = router::lab::tls_cli::edit(
      configuration, configured, router::CliEngine::md);
  require(first.valid && first.changed,
          "use-pqc-only true did not configure the leaf");
  const auto remove = parse(
      router::CliEngine::md, "delete system security tls use-pqc-only");
  const auto second = router::lab::tls_cli::edit(
      configuration, remove, router::CliEngine::md);
  require(second.valid && second.changed,
          "MD delete of a configured leaf did not remove it");
  const auto third = router::lab::tls_cli::edit(
      configuration, remove, router::CliEngine::md);
  require(third.valid && !third.changed,
          "MD delete of an already-default leaf was not silent");
}
