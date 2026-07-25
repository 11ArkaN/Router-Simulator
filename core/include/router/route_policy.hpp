// Address-family-independent route-policy evaluation for control-plane route
// import and export. A protocol owner evaluates an immutable program against a
// value copy of one candidate. The program never owns RIB, LSDB or CLI state.

#pragma once

#include "router/ip_address.hpp"
#include "router/multi_device_routing.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::lab::routing {

enum class PolicyDecision : std::uint8_t {
  next_entry,
  accept,
  reject
};

struct PolicyPrefix {
  // Exactly one address family is active. IPv4 is stored in network byte order
  // in the low-level routing representation used by the existing RIB.
  bool ipv6{};
  std::uint32_t ipv4_network{};
  ip::Ipv6 ipv6_network{};
  std::uint8_t length{};

  [[nodiscard]] friend bool operator==(const PolicyPrefix &,
                                       const PolicyPrefix &) noexcept = default;
};

struct PolicyCandidate {
  PolicyPrefix destination;
  RouteSource source{};
  OspfPathType ospf_path_type{OspfPathType::none};
  std::uint32_t metric{};
  std::uint32_t tag{};
  std::uint8_t protocol_instance{};

  [[nodiscard]] friend bool
  operator==(const PolicyCandidate &,
             const PolicyCandidate &) noexcept = default;
};

struct PolicyEntry {
  // Entries are evaluated by ascending number, matching SR OS policy-options
  // semantics. A generated term expands one referenced prefix-list member
  // without inventing a visible policy entry number. The pair is therefore
  // the stable internal ordering key and lets every prefix in one operator
  // entry retain the same actions.
  std::uint32_t number{};
  std::uint32_t term{};
  std::optional<PolicyPrefix> destination;
  std::optional<RouteSource> source;
  std::optional<std::uint8_t> protocol_instance;
  std::optional<std::uint32_t> tag;
  PolicyDecision decision{PolicyDecision::next_entry};
  std::optional<std::uint32_t> set_metric;
  std::optional<OspfPathType> set_metric_type;
  std::optional<std::uint32_t> set_tag;

  [[nodiscard]] friend bool operator==(const PolicyEntry &,
                                       const PolicyEntry &) noexcept = default;
};

struct PolicyResult {
  PolicyDecision decision{PolicyDecision::reject};
  PolicyCandidate candidate;
};

class RoutePolicyProgram final {
public:
  // replace constructs and validates a complete generation before publication.
  // Failure leaves the previous generation active, preserving MD commit and
  // classic immediate-apply atomicity at the protocol-owner boundary.
  [[nodiscard]] bool replace(std::span<const PolicyEntry> entries,
                             PolicyDecision default_decision) noexcept;

  // Evaluation is allocation-free. Mutation actions apply to the returned
  // candidate only, so the originating connected or static RIB row remains
  // owned and unchanged by its source protocol.
  [[nodiscard]] PolicyResult
  evaluate(const PolicyCandidate &candidate) const noexcept;

  [[nodiscard]] const std::vector<PolicyEntry> &entries() const noexcept {
    return entries_;
  }
  [[nodiscard]] PolicyDecision default_decision() const noexcept {
    return default_decision_;
  }

private:
  [[nodiscard]] static bool
  valid(std::span<const PolicyEntry> entries,
        PolicyDecision default_decision) noexcept;

  std::vector<PolicyEntry> entries_;
  PolicyDecision default_decision_{PolicyDecision::reject};
};

} // namespace router::lab::routing
