// MLD import-policy tests cover ordered first-match behavior, next-entry,
// source-less reports, canonical prefix validation and atomic replacement.

#include "router/mld_import_policy.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

router::ip::Ipv6 address(const char *text) {
  const auto parsed = router::ip::parse_ipv6(text);
  if (!parsed)
    throw std::runtime_error("MLD policy fixture address is invalid");
  return *parsed;
}

router::ip::Ipv6Prefix prefix(const char *text) {
  const auto parsed = router::ip::parse_ipv6_prefix(text);
  if (!parsed)
    throw std::runtime_error("MLD policy fixture prefix is invalid");
  return *parsed;
}

} // namespace

void mld_import_policy_tests() {
  using router::mld::ImportPolicyAction;
  using router::mld::ImportPolicyEntry;
  using router::mld::ImportPolicyProgram;

  ImportPolicyProgram program;
  const std::array entries{
      ImportPolicyEntry{.number = 10U,
                        .term = 0U,
                        .group = prefix("ff3e:100::/32"),
                        .source = prefix("2001:db8:10::/48"),
                        .action = ImportPolicyAction::reject,
                        .protocol_mld = true},
      ImportPolicyEntry{.number = 20U,
                        .term = 0U,
                        .group = prefix("ff3e:100::/32"),
                        .source = std::nullopt,
                        .action = ImportPolicyAction::accept,
                        .protocol_mld = true}};
  require(program.replace(entries, ImportPolicyAction::reject),
          "valid MLD policy generation was rejected");
  require(program.evaluate(address("ff3e:100::1"),
                           address("2001:db8:10::1")) ==
              ImportPolicyAction::reject,
          "source-specific reject did not win in numeric order");
  require(program.evaluate(address("ff3e:100::1"),
                           address("2001:db8:20::1")) ==
              ImportPolicyAction::accept,
          "group accept did not admit a different source");
  require(program.evaluate(address("ff3e:100::1")) ==
              ImportPolicyAction::accept,
          "source-less report incorrectly matched a source criterion");
  require(program.evaluate(address("ff3e:200::1")) ==
              ImportPolicyAction::reject,
          "policy default action was not applied after no match");

  const auto before = program.checkpoint();
  auto invalid = entries;
  invalid[1].number = invalid[0].number;
  require(!program.replace(invalid, ImportPolicyAction::accept) &&
              program.checkpoint().entries == before.entries,
          "invalid duplicate entry partially replaced active MLD policy");
  require(!program.replace(entries, ImportPolicyAction::next_entry),
          "policy accepted next-entry as a terminal default action");

  // One route-policy entry can compile to several ordered terms when a named
  // group list and source list are expanded. The term ordinal is therefore
  // part of ordering and duplicate detection, while the entry number remains
  // the operator-visible key.
  const std::array expanded_entries{
      ImportPolicyEntry{.number = 10U,
                        .term = 0U,
                        .group = prefix("ff3e:300::/40"),
                        .source = prefix("2001:db8:30::/48"),
                        .action = ImportPolicyAction::next_entry,
                        .protocol_mld = true},
      ImportPolicyEntry{.number = 10U,
                        .term = 1U,
                        .group = prefix("ff3e:300::/40"),
                        .source = std::nullopt,
                        .action = ImportPolicyAction::drop,
                        .protocol_mld = true}};
  require(program.replace(expanded_entries, ImportPolicyAction::next_policy),
          "expanded policy terms or next-policy default were rejected");
  require(program.evaluate(address("ff3e:300::1"),
                           address("2001:db8:30::1")) ==
              ImportPolicyAction::drop,
          "next-entry did not continue to the following expanded term");
  require(program.evaluate(address("ff3e:400::1")) ==
              ImportPolicyAction::next_policy,
          "next-policy identity was lost before the MLD consumer boundary");

  ImportPolicyProgram restored;
  require(restored.restore(before) &&
              restored.evaluate(address("ff3e:100::1"),
                                address("2001:db8:10::1")) ==
                  ImportPolicyAction::reject,
          "MLD import policy checkpoint changed evaluation behavior");
}
