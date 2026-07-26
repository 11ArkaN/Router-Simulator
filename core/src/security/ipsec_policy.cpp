// RFC 4301 ordered SPD validation and selection. The implementation performs no
// cryptography and owns no SA state. This separation lets policy configuration
// be tested without creating keys and prevents an SA lookup from mutating the
// configured rule order.

#include "router/ipsec_policy.hpp"

#include <algorithm>

namespace router::ipsec {
namespace {

bool valid_range(const PortRange &range) noexcept {
  return range.first <= range.last;
}

bool port_matches(const PortRange &range, std::uint16_t port) noexcept {
  return port >= range.first && port <= range.last;
}

bool selector_valid(const TrafficSelector &selector) noexcept {
  if (!valid_prefix(selector.source) || !valid_prefix(selector.destination) ||
      selector.source.network.family != selector.destination.network.family ||
      !valid_range(selector.source_ports) ||
      !valid_range(selector.destination_ports))
    return false;

  // A wildcard protocol has no defined port namespace. Requiring full ranges
  // prevents a configuration from appearing to narrow traffic when it cannot.
  if (selector.upper_layer_protocol == 0U &&
      (selector.source_ports.first != 0U ||
       selector.source_ports.last != 65535U ||
       selector.destination_ports.first != 0U ||
       selector.destination_ports.last != 65535U))
    return false;
  return true;
}

bool policy_valid(const Policy &policy) noexcept {
  if (policy.id == 0U || !selector_valid(policy.selector) ||
      static_cast<std::uint8_t>(policy.direction) >
          static_cast<std::uint8_t>(Direction::forwarding) ||
      static_cast<std::uint8_t>(policy.action) >
          static_cast<std::uint8_t>(PolicyAction::protect))
    return false;
  return policy.action == PolicyAction::protect ? policy.proposal_id != 0U
                                                 : policy.proposal_id == 0U;
}

bool matches(const TrafficSelector &selector,
             const PacketSelector &packet) noexcept {
  if (selector.source.network.family != packet.source.family ||
      packet.source.family != packet.destination.family ||
      !prefix_contains(selector.source, packet.source) ||
      !prefix_contains(selector.destination, packet.destination) ||
      (selector.interface_id != 0U &&
       selector.interface_id != packet.interface_id) ||
      (selector.upper_layer_protocol != 0U &&
       selector.upper_layer_protocol != packet.upper_layer_protocol))
    return false;

  // For wildcard protocol selectors the validated ranges are necessarily full,
  // so this common comparison remains correct without a packet-path branch.
  return port_matches(selector.source_ports, packet.source_port) &&
         port_matches(selector.destination_ports, packet.destination_port);
}

std::size_t lookup_bucket(Direction direction, AddressFamily family) noexcept {
  const auto direction_index = static_cast<std::size_t>(direction);
  const auto family_index = family == AddressFamily::ipv6 ? 1U : 0U;
  return direction_index * 2U + family_index;
}

} // namespace

bool valid_address(const Address &address) noexcept {
  if (address.family == AddressFamily::ipv6)
    return true;
  if (address.family != AddressFamily::ipv4)
    return false;
  return std::all_of(address.bytes.begin() + 4, address.bytes.end(),
                     [](std::uint8_t byte) { return byte == 0U; });
}

bool valid_prefix(const Prefix &prefix) noexcept {
  if (!valid_address(prefix.network) ||
      prefix.length > ip::address_bits(prefix.network.family))
    return false;

  // Canonical network storage is part of the public contract. Validate every
  // host bit rather than silently masking it and changing user intent.
  const auto used_bytes = static_cast<std::size_t>(
      prefix.network.family == AddressFamily::ipv4 ? 4U : 16U);
  const auto complete = static_cast<std::size_t>(prefix.length / 8U);
  const auto remainder = static_cast<std::uint8_t>(prefix.length % 8U);
  if (remainder != 0U) {
    const auto host_mask = static_cast<std::uint8_t>((1U << (8U - remainder)) - 1U);
    if ((prefix.network.bytes[complete] & host_mask) != 0U)
      return false;
  }
  const auto first_host = complete + (remainder == 0U ? 0U : 1U);
  return std::all_of(prefix.network.bytes.begin() +
                         static_cast<std::ptrdiff_t>(first_host),
                     prefix.network.bytes.begin() +
                         static_cast<std::ptrdiff_t>(used_bytes),
                     [](std::uint8_t byte) { return byte == 0U; });
}

bool prefix_contains(const Prefix &prefix, const Address &address) noexcept {
  if (!valid_prefix(prefix) || !valid_address(address) ||
      prefix.network.family != address.family)
    return false;
  const auto complete = static_cast<std::size_t>(prefix.length / 8U);
  if (!std::equal(prefix.network.bytes.begin(),
                  prefix.network.bytes.begin() +
                      static_cast<std::ptrdiff_t>(complete),
                  address.bytes.begin()))
    return false;
  const auto remainder = static_cast<std::uint8_t>(prefix.length % 8U);
  if (remainder == 0U)
    return true;
  const auto mask = static_cast<std::uint8_t>(0xffU << (8U - remainder));
  return (prefix.network.bytes[complete] & mask) ==
         (address.bytes[complete] & mask);
}

Spd::Spd(std::size_t capacity) : capacity_(capacity) {
  // reserve is a cold configuration operation. Failure leaves an empty but
  // valid database; install() translates later allocation failure into an
  // explicit capacity result without corrupting existing rules.
  try {
    policies_.reserve(capacity);
    for (auto &index : lookup_indexes_)
      index.reserve(capacity);
  } catch (...) {
    // A partially reserved index cannot uphold the allocation-free packet-path
    // contract. Disable installation rather than falling back to hidden heap
    // allocation during a later configuration change.
    capacity_ = 0U;
  }
}

void Spd::rebuild_indexes() noexcept {
  for (auto &index : lookup_indexes_)
    index.clear();
  for (std::size_t position = 0U; position < policies_.size(); ++position) {
    const auto &policy = policies_[position];
    lookup_indexes_[lookup_bucket(policy.direction,
                                  policy.selector.source.network.family)]
        .push_back(position);
  }
}

PolicyInstallResult Spd::install(const Policy &policy) noexcept {
  if (!policy_valid(policy))
    return PolicyInstallResult::invalid;
  const auto existing =
      std::find_if(policies_.begin(), policies_.end(), [&](const Policy &item) {
        return item.id == policy.id;
      });
  const auto replaced = existing != policies_.end();
  if (!replaced && policies_.size() >= capacity_)
    return PolicyInstallResult::capacity_exhausted;

  try {
    if (replaced)
      *existing = policy;
    else
      policies_.push_back(policy);
    std::sort(policies_.begin(), policies_.end(),
              [](const Policy &left, const Policy &right) {
                if (left.priority != right.priority)
                  return left.priority < right.priority;
                return left.id < right.id;
              });
    rebuild_indexes();
    return replaced ? PolicyInstallResult::replaced
                    : PolicyInstallResult::installed;
  } catch (...) {
    // Replacement cannot allocate. push_back provides the strong guarantee, so
    // an allocation failure leaves the previous policy set unchanged.
    return PolicyInstallResult::capacity_exhausted;
  }
}

bool Spd::erase(std::uint32_t id) noexcept {
  const auto found =
      std::find_if(policies_.begin(), policies_.end(), [&](const Policy &item) {
        return item.id == id;
      });
  if (found == policies_.end())
    return false;
  policies_.erase(found);
  rebuild_indexes();
  return true;
}

std::optional<Policy>
Spd::lookup(Direction direction, const PacketSelector &packet) const noexcept {
  if (!valid_address(packet.source) || !valid_address(packet.destination) ||
      packet.source.family != packet.destination.family ||
      static_cast<std::uint8_t>(direction) >
          static_cast<std::uint8_t>(Direction::forwarding))
    return std::nullopt;
  const auto &index =
      lookup_indexes_[lookup_bucket(direction, packet.source.family)];
  const auto found = std::find_if(index.begin(), index.end(),
                                  [&](std::size_t position) {
                                    return matches(policies_[position].selector,
                                                   packet);
                                  });
  return found == index.end() ? std::nullopt
                              : std::optional<Policy>{policies_[*found]};
}

SpdCheckpoint Spd::checkpoint() const {
  // The policy vector is already in canonical priority and ID order. Copying
  // it avoids persisting derived indexes whose vector positions are an
  // implementation detail and would create a fragile checkpoint ABI.
  return {.capacity = capacity_, .policies = policies_};
}

bool Spd::restore(const SpdCheckpoint &state) noexcept {
  if (state.capacity != capacity_ || state.policies.size() > capacity_)
    return false;
  try {
    Spd staged{capacity_};
    if (staged.capacity() != capacity_)
      return false;
    for (const auto &policy : state.policies) {
      const auto result = staged.install(policy);
      if (result != PolicyInstallResult::installed)
        return false;
    }
    // Duplicate IDs are rejected as replacements above. Require the encoded
    // order to be canonical as well so two byte-distinct checkpoints cannot
    // represent the same SPD and complicate authenticated persistence tests.
    for (std::size_t index = 0; index < state.policies.size(); ++index)
      if (staged.policies_[index].priority != state.policies[index].priority ||
          staged.policies_[index].id != state.policies[index].id)
        return false;
    policies_ = std::move(staged.policies_);
    lookup_indexes_ = std::move(staged.lookup_indexes_);
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::ipsec
