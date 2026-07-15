// Adjacency value owner. Bounds checks make malformed port handles harmless and
// prevent a route programming defect from indexing unrelated forwarding state.

#include "network_adjacency.hpp"

namespace router::network_detail {

void AdjacencyTable::learn(std::uint8_t port, packet::Ipv4 address,
                           packet::Mac mac) noexcept {
  // A complete address and MAC value replaces one forwarding-owned slot.
  if (port < entries_.size())
    entries_[port] = Adjacency{address, mac};
}

void AdjacencyTable::invalidate(std::size_t port) noexcept {
  // Clear learned identity and transient request state for this port
  // generation.
  if (port >= entries_.size())
    return;
  entries_[port].reset();
  requests_[port] = false;
}

const Adjacency *AdjacencyTable::exact(std::size_t port,
                                       packet::Ipv4 address) const noexcept {
  // Pending traffic can be released only by its requested protocol address.
  const auto *value = get(port);
  return value && value->address == address ? value : nullptr;
}

const Adjacency *AdjacencyTable::get(std::size_t port) const noexcept {
  // Bounds and optional validity collapse to a null non-owning result.
  if (port >= entries_.size() || !entries_[port])
    return nullptr;
  return &*entries_[port];
}

bool AdjacencyTable::request_outstanding(std::size_t port) const noexcept {
  // One flag per port suppresses duplicate ARP requests during bursts.
  return port < requests_.size() && requests_[port];
}

void AdjacencyTable::mark_request(std::size_t port) noexcept {
  // The caller queues dependent traffic before marking and sending ARP.
  if (port < requests_.size())
    requests_[port] = true;
}

void AdjacencyTable::complete_request(std::size_t port) noexcept {
  // Completion permits a later next hop on the same port to request ARP.
  if (port < requests_.size())
    requests_[port] = false;
}

void AdjacencyTable::restore(
    const std::array<NetworkArpEntry, profile::port_count> &entries) noexcept {
  // Transient requests are never restored from a structural checkpoint.
  for (std::size_t port = 0; port < entries.size(); ++port) {
    if (entries[port].valid) {
      entries_[port] = Adjacency{entries[port].address, entries[port].mac};
    } else {
      entries_[port].reset();
    }
    requests_[port] = false;
  }
}

std::array<NetworkArpEntry, profile::port_count>
AdjacencyTable::projection() const noexcept {
  // Return values only so control cannot mutate forwarding-owned optionals.
  std::array<NetworkArpEntry, profile::port_count> result{};
  for (std::size_t port = 0; port < entries_.size(); ++port) {
    // Use the checked accessor once. Besides proving optional validity to the
    // analyzer, this keeps projection bounds identical to lookup bounds.
    const auto *entry = get(port);
    if (!entry)
      continue;
    result[port] = {.valid = true,
                    .address = entry->address,
                    .mac = entry->mac,
                    .port_index = static_cast<std::uint8_t>(port)};
  }
  return result;
}

} // namespace router::network_detail
