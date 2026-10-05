// Route-policy tests protect ordered matching, family-safe prefix matching,
// explicit default rejection and mutation without changing the source route.

#include "router/route_policy.hpp"

#include <array>
#include <stdexcept>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

} // namespace

void route_policy_tests() {
  using namespace router::lab::routing;

  const PolicyPrefix connected_range{
      .ipv4_network = ipv4(10U, 0U, 0U, 0U), .length = 8U};
  std::array<PolicyEntry, 2U> entries{};
  entries[0].number = 10U;
  entries[0].destination = connected_range;
  entries[0].source = RouteSource::connected;
  entries[0].decision = PolicyDecision::next_entry;
  entries[0].set_metric = 25U;
  entries[0].set_metric_type = OspfPathType::external_type_1;
  entries[0].set_tag = 65001U;
  entries[1].number = 20U;
  entries[1].tag = 65001U;
  entries[1].decision = PolicyDecision::accept;

  RoutePolicyProgram program;
  require(program.replace(entries, PolicyDecision::reject),
          "valid ordered route policy was rejected");
  const PolicyCandidate source{
      .destination =
          PolicyPrefix{.ipv4_network = ipv4(10U, 2U, 0U, 0U), .length = 16U},
      .source = RouteSource::connected};
  const auto accepted = program.evaluate(source);
  require(accepted.decision == PolicyDecision::accept &&
              accepted.candidate.metric == 25U &&
              accepted.candidate.ospf_path_type ==
                  OspfPathType::external_type_1 &&
              accepted.candidate.tag == 65001U && source.metric == 0U &&
              source.tag == 0U,
          "ordered policy did not mutate and accept a value copy");

  const PolicyCandidate outside{
      .destination =
          PolicyPrefix{.ipv4_network = ipv4(192U, 0U, 2U, 0U), .length = 24U},
      .source = RouteSource::static_route};
  require(program.evaluate(outside).decision == PolicyDecision::reject,
          "unmatched route bypassed the explicit default reject");

  std::array<PolicyEntry, 2U> duplicate{};
  duplicate[0].number = 10U;
  duplicate[0].decision = PolicyDecision::accept;
  duplicate[1].number = 10U;
  duplicate[1].decision = PolicyDecision::reject;
  require(!program.replace(duplicate, PolicyDecision::reject) &&
              program.evaluate(source).decision == PolicyDecision::accept,
          "invalid replacement erased the active route policy");

  std::array<PolicyEntry, 2U> expanded{};
  expanded[0].number = 30U;
  expanded[0].term = 0U;
  expanded[0].destination =
      PolicyPrefix{.ipv4_network = ipv4(198U, 51U, 100U, 0U), .length = 24U};
  expanded[0].decision = PolicyDecision::accept;
  expanded[1].number = 30U;
  expanded[1].term = 1U;
  expanded[1].destination =
      PolicyPrefix{.ipv4_network = ipv4(203U, 0U, 113U, 0U), .length = 24U};
  expanded[1].decision = PolicyDecision::accept;
  require(program.replace(expanded, PolicyDecision::reject) &&
              program
                      .evaluate(PolicyCandidate{
                          .destination =
                              PolicyPrefix{.ipv4_network =
                                               ipv4(203U, 0U, 113U, 0U),
                                           .length = 25U},
                          .source = RouteSource::static_route})
                      .decision == PolicyDecision::accept,
          "one policy entry did not preserve every expanded prefix-list term");

  // next-policy exits the program with the mutated candidate so a chain can
  // continue in the next policy. It is a legal default; next-entry is not.
  std::array<PolicyEntry, 1U> handoff{};
  handoff[0].number = 10U;
  handoff[0].destination = connected_range;
  handoff[0].decision = PolicyDecision::next_policy;
  handoff[0].set_metric = 50U;
  RoutePolicyProgram first;
  require(first.replace(handoff, PolicyDecision::next_policy),
          "next-policy default was rejected");
  const auto handed = first.evaluate(source);
  require(handed.decision == PolicyDecision::next_policy &&
              handed.candidate.metric == 50U,
          "next-policy did not exit with the mutated candidate");
  RoutePolicyProgram invalid_default;
  require(!invalid_default.replace(handoff, PolicyDecision::next_entry),
          "next-entry default was accepted");

  // The chain applies in order and the first match wins. The first program
  // hands a static route off with a metric mutation, the second accepts only
  // mutated metrics, and an exhausted chain rejects.
  std::array<PolicyEntry, 1U> acceptor{};
  acceptor[0].number = 10U;
  acceptor[0].decision = PolicyDecision::accept;
  RoutePolicyProgram second;
  require(second.replace(acceptor, PolicyDecision::reject),
          "chain acceptor was rejected");
  const std::array<RoutePolicyProgram, 2U> chain{first, second};
  const PolicyCandidate static_source{
      .destination =
          PolicyPrefix{.ipv4_network = ipv4(10U, 2U, 0U, 0U), .length = 16U},
      .source = RouteSource::connected};
  const auto chained = evaluate_policy_chain(chain, static_source);
  require(chained.decision == PolicyDecision::accept &&
              chained.candidate.metric == 50U,
          "policy chain did not thread the handoff into the next policy");
  const std::array<RoutePolicyProgram, 1U> exhausted{first};
  require(evaluate_policy_chain(exhausted, static_source).decision ==
                  PolicyDecision::reject,
          "exhausted policy chain did not reject");
  require(evaluate_policy_chain({}, static_source).decision ==
                  PolicyDecision::reject,
          "empty policy chain did not reject");

  // A reject in the first program terminates the chain before the acceptor.
  std::array<PolicyEntry, 1U> denier{};
  denier[0].number = 10U;
  denier[0].destination = connected_range;
  denier[0].decision = PolicyDecision::reject;
  RoutePolicyProgram stopper;
  require(stopper.replace(denier, PolicyDecision::reject),
          "chain stopper was rejected");
  const std::array<RoutePolicyProgram, 2U> stopped{stopper, second};
  require(evaluate_policy_chain(stopped, static_source).decision ==
                  PolicyDecision::reject,
          "policy chain did not stop at the first match");
}
