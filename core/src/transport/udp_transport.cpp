// Bounded UDP demultiplexing and block-pool queue implementation. All mutable
// values are endpoint-owner local, so queue links need neither atomics nor
// locks. Cross-shard movement remains encoded IP and Ethernet packet bytes.

#include "router/udp_transport.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <utility>

namespace router::transport {
namespace {

[[nodiscard]] bool unspecified(packet::Ipv4 value) noexcept {
  return std::all_of(value.begin(), value.end(),
                     [](auto octet) { return octet == 0U; });
}

[[nodiscard]] bool binding_address_equal(const UdpBinding &left,
                                         const UdpBinding &right) noexcept {
  return left.family == IpFamily::ipv4 ? left.ipv4 == right.ipv4
                                       : left.ipv6 == right.ipv6;
}

[[nodiscard]] bool binding_address_wildcard(const UdpBinding &value) noexcept {
  return value.family == IpFamily::ipv4 ? unspecified(value.ipv4)
                                        : ip::is_unspecified(value.ipv6);
}

} // namespace

UdpEndpoint::UdpEndpoint() : blocks_(block_count) {
  static_assert(block_count > 0U &&
                block_count < std::numeric_limits<std::uint16_t>::max());
  static_assert(device_catalog::udp_queued_datagrams_per_endpoint <
                std::numeric_limits<std::uint16_t>::max());
  // Intrusive free lists make every ingest operation allocation-free. Indices
  // are stable across vector storage and are never exposed outside this owner.
  for (std::size_t index = 0; index < datagrams_.size(); ++index)
    datagrams_[index].next =
        index + 1U < datagrams_.size()
            ? static_cast<std::uint16_t>(index + 1U)
            : invalid_index;
  free_datagram_head_ = datagrams_.empty() ? invalid_index : 0U;
  for (std::size_t index = 0; index < blocks_.size(); ++index)
    blocks_[index].next =
        index + 1U < blocks_.size() ? static_cast<std::uint16_t>(index + 1U)
                                    : invalid_index;
  free_block_head_ = blocks_.empty() ? invalid_index : 0U;
  free_blocks_ = static_cast<std::uint16_t>(blocks_.size());
}

UdpEndpoint::Socket *UdpEndpoint::socket(UdpSocketHandle handle) noexcept {
  if (handle.index >= sockets_.size())
    return nullptr;
  auto &candidate = sockets_[handle.index];
  return candidate.occupied && candidate.generation == handle.generation
             ? &candidate
             : nullptr;
}

const UdpEndpoint::Socket *
UdpEndpoint::socket(UdpSocketHandle handle) const noexcept {
  if (handle.index >= sockets_.size())
    return nullptr;
  const auto &candidate = sockets_[handle.index];
  return candidate.occupied && candidate.generation == handle.generation
             ? &candidate
             : nullptr;
}

std::optional<std::uint16_t>
UdpEndpoint::ephemeral_port(IpFamily family, std::uint64_t interface_id,
                            packet::Ipv4 ipv4, packet::Ipv6 ipv6) noexcept {
  const auto span = static_cast<std::uint32_t>(
      device_catalog::udp_ephemeral_port_last -
      device_catalog::udp_ephemeral_port_first) +
                    1U;
  for (std::uint32_t attempt = 0; attempt < span; ++attempt) {
    const auto candidate = ephemeral_cursor_;
    ephemeral_cursor_ =
        candidate == device_catalog::udp_ephemeral_port_last
            ? device_catalog::udp_ephemeral_port_first
            : static_cast<std::uint16_t>(candidate + 1U);
    UdpBinding proposed{.family = family,
                        .ipv4 = ipv4,
                        .ipv6 = ipv6,
                        .interface_id = interface_id,
                        .port = candidate};
    const bool conflict = std::any_of(sockets_.begin(), sockets_.end(),
                                      [&](const auto &entry) {
      if (!entry.occupied || entry.binding.family != family ||
          entry.binding.port != candidate)
        return false;
      const bool interface_overlap = entry.binding.interface_id == 0U ||
                                     interface_id == 0U ||
                                     entry.binding.interface_id == interface_id;
      const bool address_overlap = binding_address_wildcard(entry.binding) ||
                                   binding_address_wildcard(proposed) ||
                                   binding_address_equal(entry.binding,
                                                         proposed);
      return interface_overlap && address_overlap;
    });
    if (!conflict)
      return candidate;
  }
  return std::nullopt;
}

std::optional<UdpSocketHandle>
UdpEndpoint::bind(const UdpBinding &input) noexcept {
  if (input.family == IpFamily::ipv6 &&
      (input.ipv4_broadcast ||
       (ip::is_link_local(input.ipv6) && input.interface_id == 0U)))
    return std::nullopt;
  auto binding = input;
  if (binding.port == 0U) {
    const auto allocated = ephemeral_port(binding.family, binding.interface_id,
                                          binding.ipv4, binding.ipv6);
    if (!allocated)
      return std::nullopt;
    binding.port = *allocated;
  }
  for (const auto &entry : sockets_) {
    if (!entry.occupied || entry.binding.family != binding.family ||
        entry.binding.port != binding.port)
      continue;
    const bool interface_overlap = entry.binding.interface_id == 0U ||
                                   binding.interface_id == 0U ||
                                   entry.binding.interface_id ==
                                       binding.interface_id;
    const bool address_overlap = binding_address_wildcard(entry.binding) ||
                                 binding_address_wildcard(binding) ||
                                 binding_address_equal(entry.binding, binding);
    if (interface_overlap && address_overlap)
      return std::nullopt;
  }
  for (std::size_t index = 0; index < sockets_.size(); ++index) {
    auto &entry = sockets_[index];
    if (entry.occupied)
      continue;
    entry.binding = binding;
    entry.queue_head = invalid_index;
    entry.queue_tail = invalid_index;
    entry.queued = 0U;
    // A recycled descriptor represents a new socket lifetime. Retaining an
    // old peer tuple or unread ICMP error would let unrelated future traffic
    // inherit network state from the previous generation.
    entry.last_ipv6_transmission.reset();
    entry.network_error.reset();
    entry.occupied = true;
    return UdpSocketHandle{.index = static_cast<std::uint32_t>(index),
                           .generation = entry.generation};
  }
  // Growing the slot repository is control-path work performed by bind, never
  // packet ingress. Existing handles contain indices and remain stable across
  // vector relocation. Allocation failure is ordinary resource exhaustion.
  try {
    if (sockets_.size() >= std::numeric_limits<std::uint32_t>::max())
      return std::nullopt;
    sockets_.push_back({.binding = binding,
                        .queue_head = invalid_index,
                        .queue_tail = invalid_index,
                        .queued = 0U,
                        .last_ipv6_transmission = std::nullopt,
                        .network_error = std::nullopt,
                        .generation = 1U,
                        .occupied = true});
    return UdpSocketHandle{
        .index = static_cast<std::uint32_t>(sockets_.size() - 1U),
        .generation = 1U};
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

void UdpEndpoint::release_datagram(std::uint16_t index) noexcept {
  auto &datagram = datagrams_[index];
  auto block = datagram.first_block;
  while (block != invalid_index) {
    const auto next = blocks_[block].next;
    blocks_[block].next = free_block_head_;
    free_block_head_ = block;
    ++free_blocks_;
    block = next;
  }
  datagram = {};
  datagram.first_block = invalid_index;
  datagram.next = free_datagram_head_;
  free_datagram_head_ = index;
}

bool UdpEndpoint::close(UdpSocketHandle handle) noexcept {
  auto *entry = socket(handle);
  if (!entry)
    return false;
  auto datagram = entry->queue_head;
  while (datagram != invalid_index) {
    const auto next = datagrams_[datagram].next;
    release_datagram(datagram);
    datagram = next;
  }
  entry->occupied = false;
  entry->queue_head = invalid_index;
  entry->queue_tail = invalid_index;
  entry->queued = 0U;
  entry->last_ipv6_transmission.reset();
  entry->network_error.reset();
  ++entry->generation;
  if (!entry->generation)
    entry->generation = 1U;
  return true;
}

std::optional<std::uint16_t>
UdpEndpoint::local_port(UdpSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry ? std::optional{entry->binding.port} : std::nullopt;
}

std::optional<UdpBinding>
UdpEndpoint::local_binding(UdpSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry ? std::optional{entry->binding} : std::nullopt;
}

UdpEndpoint::Socket *UdpEndpoint::select(
    IpFamily family, packet::Ipv4 destination_ipv4,
    packet::Ipv6 destination_ipv6, std::uint16_t destination_port,
    std::uint64_t interface_id) noexcept {
  Socket *wildcard{};
  for (auto &entry : sockets_) {
    if (!entry.occupied || entry.binding.family != family ||
        entry.binding.port != destination_port ||
        (entry.binding.interface_id != 0U &&
         entry.binding.interface_id != interface_id))
      continue;
    const bool any = binding_address_wildcard(entry.binding);
    const bool exact = family == IpFamily::ipv4
                           ? entry.binding.ipv4 == destination_ipv4
                           : entry.binding.ipv6 == destination_ipv6;
    if (exact && !any)
      return &entry;
    if (any)
      wildcard = &entry;
  }
  return wildcard;
}

UdpIngressStatus UdpEndpoint::enqueue(
    Socket &entry, const UdpDatagramMetadata &metadata,
    std::span<const std::uint8_t> payload) noexcept {
  const auto required_blocks =
      (payload.size() + device_catalog::udp_receive_block_bytes - 1U) /
      device_catalog::udp_receive_block_bytes;
  if (entry.queued >= device_catalog::udp_datagrams_per_socket ||
      free_datagram_head_ == invalid_index || required_blocks > free_blocks_)
    return UdpIngressStatus::queue_full;

  const auto descriptor_index = free_datagram_head_;
  auto &descriptor = datagrams_[descriptor_index];
  free_datagram_head_ = descriptor.next;
  descriptor = {.metadata = metadata,
                .first_block = invalid_index,
                .next = invalid_index,
                .block_count = static_cast<std::uint16_t>(required_blocks),
                .occupied = true};
  std::uint16_t last_block = invalid_index;
  std::size_t copied{};
  for (std::size_t count = 0; count < required_blocks; ++count) {
    const auto block_index = free_block_head_;
    auto &block = blocks_[block_index];
    free_block_head_ = block.next;
    --free_blocks_;
    block.next = invalid_index;
    if (last_block == invalid_index)
      descriptor.first_block = block_index;
    else
      blocks_[last_block].next = block_index;
    const auto amount = std::min(device_catalog::udp_receive_block_bytes,
                                 payload.size() - copied);
    std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(copied), amount,
                block.bytes.begin());
    copied += amount;
    last_block = block_index;
  }
  if (entry.queue_tail == invalid_index)
    entry.queue_head = descriptor_index;
  else
    datagrams_[entry.queue_tail].next = descriptor_index;
  entry.queue_tail = descriptor_index;
  ++entry.queued;
  return UdpIngressStatus::delivered;
}

UdpIngressStatus UdpEndpoint::ingest_ipv4(
    std::span<const std::uint8_t> datagram, packet::Ipv4 source,
    packet::Ipv4 destination, std::uint64_t interface_id) noexcept {
  const auto parsed = packet::udp::parse_ipv4(datagram, source, destination);
  if (!parsed)
    return UdpIngressStatus::malformed;
  auto *entry = select(IpFamily::ipv4, destination, {},
                       parsed->destination_port, interface_id);
  if (!entry)
    return UdpIngressStatus::no_socket;
  return enqueue(*entry,
                 {.family = IpFamily::ipv4,
                  .source_ipv4 = source,
                  .destination_ipv4 = destination,
                  .interface_id = interface_id,
                  .payload_octets =
                      static_cast<std::uint32_t>(parsed->payload.size()),
                  .source_port = parsed->source_port,
                  .destination_port = parsed->destination_port},
                 parsed->payload);
}

UdpIngressStatus UdpEndpoint::ingest_ipv6(
    std::span<const std::uint8_t> datagram, packet::Ipv6 source,
    packet::Ipv6 destination, std::uint64_t interface_id,
    packet::Mac source_mac) noexcept {
  const auto parsed = packet::udp::parse_ipv6(datagram, source, destination);
  if (!parsed)
    return UdpIngressStatus::malformed;
  auto *entry = select(IpFamily::ipv6, {}, destination,
                       parsed->destination_port, interface_id);
  if (!entry)
    return UdpIngressStatus::no_socket;
  return enqueue(*entry,
                 {.family = IpFamily::ipv6,
                  .source_ipv6 = source,
                  .destination_ipv6 = destination,
                  .source_mac = source_mac,
                  .interface_id = interface_id,
                  .payload_octets =
                      static_cast<std::uint32_t>(parsed->payload.size()),
                  .source_port = parsed->source_port,
                  .destination_port = parsed->destination_port},
                 parsed->payload);
}

UdpReceiveResult UdpEndpoint::receive(UdpSocketHandle handle,
                                      std::span<std::uint8_t> output) noexcept {
  auto *entry = socket(handle);
  if (!entry)
    return {.status = UdpReceiveStatus::invalid_socket};
  if (entry->queue_head == invalid_index)
    return {.status = UdpReceiveStatus::empty};
  const auto descriptor_index = entry->queue_head;
  auto &descriptor = datagrams_[descriptor_index];
  if (output.size() < descriptor.metadata.payload_octets)
    return {.status = UdpReceiveStatus::buffer_too_small,
            .metadata = descriptor.metadata};
  std::size_t copied{};
  auto block = descriptor.first_block;
  while (block != invalid_index) {
    const auto amount = std::min<std::size_t>(
        device_catalog::udp_receive_block_bytes,
        descriptor.metadata.payload_octets - copied);
    std::copy_n(blocks_[block].bytes.begin(), amount,
                output.begin() + static_cast<std::ptrdiff_t>(copied));
    copied += amount;
    block = blocks_[block].next;
  }
  const auto metadata = descriptor.metadata;
  entry->queue_head = descriptor.next;
  if (entry->queue_head == invalid_index)
    entry->queue_tail = invalid_index;
  --entry->queued;
  release_datagram(descriptor_index);
  return {.status = UdpReceiveStatus::delivered, .metadata = metadata};
}

UdpSendResult UdpEndpoint::encode_ipv6(
    UdpSocketHandle handle, packet::Ipv6 source, packet::Ipv6 destination,
    std::uint64_t interface_id, std::uint16_t destination_port,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t> output) noexcept {
  auto *entry = socket(handle);
  if (!entry)
    return {.status = UdpSendStatus::invalid_socket};
  if (entry->binding.family != IpFamily::ipv6)
    return {.status = UdpSendStatus::wrong_family};
  // An IPv6 source must identify one assigned unicast interface address.
  // UDP does not inspect DAD or address lifetimes because those belong to the
  // IP owner, but it must reject shapes that cannot legally be selected.
  if (ip::is_unspecified(source) || ip::is_multicast(source))
    return {.status = UdpSendStatus::invalid_source};
  if (ip::is_unspecified(destination) || destination_port == 0U)
    return {.status = UdpSendStatus::invalid_destination};
  if (entry->binding.interface_id != 0U &&
      entry->binding.interface_id != interface_id)
    return {.status = UdpSendStatus::interface_mismatch};
  if (!binding_address_wildcard(entry->binding) &&
      entry->binding.ipv6 != source)
    return {.status = UdpSendStatus::address_not_available};
  if (payload.size() > packet::udp::maximum_payload_octets)
    return {.status = UdpSendStatus::message_too_large};
  const auto length = packet::udp::encode_ipv6(
      output, source, destination, entry->binding.port, destination_port,
      payload);
  if (!length)
    return {.status = UdpSendStatus::buffer_too_small};
  // Publication occurs only after the complete UDP datagram has been encoded.
  // Lower-layer admission may still fail, but accepting a later matching ICMP
  // error is harmless because it describes bytes this socket attempted to send.
  entry->last_ipv6_transmission = UdpIpv6Transmission{
      .local = source,
      .remote = destination,
      .interface_id = interface_id,
      .remote_port = destination_port};
  return {.status = UdpSendStatus::encoded, .datagram_octets = *length};
}

UdpSendResult UdpEndpoint::encode_ipv4(
    UdpSocketHandle handle, packet::Ipv4 source, packet::Ipv4 destination,
    std::uint64_t interface_id, std::uint16_t destination_port,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t> output, bool checksum_enabled) const noexcept {
  const auto *entry = socket(handle);
  if (!entry)
    return {.status = UdpSendStatus::invalid_socket};
  if (entry->binding.family != IpFamily::ipv4)
    return {.status = UdpSendStatus::wrong_family};
  // Source 0.0.0.0 remains valid for address-acquisition protocols such as
  // DHCPv4. The IP owner, not UDP, decides whether that special source is
  // allowed for a particular route and interface state.
  if (unspecified(destination) || destination_port == 0U ||
      (destination == packet::Ipv4{255U, 255U, 255U, 255U} &&
       !entry->binding.ipv4_broadcast))
    return {.status = UdpSendStatus::invalid_destination};
  if (entry->binding.interface_id != 0U &&
      entry->binding.interface_id != interface_id)
    return {.status = UdpSendStatus::interface_mismatch};
  if (!binding_address_wildcard(entry->binding) &&
      entry->binding.ipv4 != source)
    return {.status = UdpSendStatus::address_not_available};
  if (payload.size() > packet::udp::maximum_ipv4_payload_octets)
    return {.status = UdpSendStatus::message_too_large};
  const auto length = packet::udp::encode_ipv4(
      output, source, destination, entry->binding.port, destination_port,
      payload, checksum_enabled);
  if (!length)
    return {.status = UdpSendStatus::buffer_too_small};
  return {.status = UdpSendStatus::encoded, .datagram_octets = *length};
}

std::size_t UdpEndpoint::queued(UdpSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry ? entry->queued : 0U;
}

bool UdpEndpoint::report_ipv6_error(
    packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    Ipv6NetworkErrorKind kind, std::uint8_t type, std::uint8_t code,
    std::uint32_t parameter) noexcept {
  if (!ipv6_network_error_kind_matches(kind, type))
    return false;
  for (auto &entry : sockets_) {
    if (!entry.occupied || entry.binding.family != IpFamily::ipv6 ||
        entry.binding.port != local_port ||
        (entry.binding.interface_id != 0U &&
         entry.binding.interface_id != interface_id) ||
        (!binding_address_wildcard(entry.binding) &&
         entry.binding.ipv6 != local) ||
        !entry.last_ipv6_transmission)
      continue;
    const auto &sent = *entry.last_ipv6_transmission;
    if (sent.local != local || sent.remote != remote ||
        sent.interface_id != interface_id || sent.remote_port != remote_port)
      continue;
    // A single owner-local error slot mirrors SO_ERROR semantics. New evidence
    // replaces stale unread evidence; no network input can allocate storage.
    entry.network_error = Ipv6NetworkError{.remote = remote,
                                           .interface_id = interface_id,
                                           .parameter = parameter,
                                           .remote_port = remote_port,
                                           .type = type,
                                           .code = code,
                                           .kind = kind};
    return true;
  }
  return false;
}

std::optional<Ipv6NetworkError>
UdpEndpoint::take_network_error(UdpSocketHandle handle) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->network_error)
    return std::nullopt;
  auto result = entry->network_error;
  entry->network_error.reset();
  return result;
}

std::size_t UdpEndpoint::free_payload_octets() const noexcept {
  return static_cast<std::size_t>(free_blocks_) *
         device_catalog::udp_receive_block_bytes;
}

UdpEndpointCheckpoint UdpEndpoint::checkpoint() const {
  UdpEndpointCheckpoint state;
  state.sockets.resize(sockets_.size());
  state.ephemeral_cursor = ephemeral_cursor_;
  for (std::size_t index = 0; index < sockets_.size(); ++index) {
    const auto &socket = sockets_[index];
    auto &saved = state.sockets[index];
    saved.binding = socket.binding;
    saved.generation = socket.generation;
    saved.occupied = socket.occupied;
    if (!socket.occupied)
      continue;
    saved.last_ipv6_transmission = socket.last_ipv6_transmission;
    saved.network_error = socket.network_error;
    saved.datagrams.reserve(socket.queued);
    auto descriptor_index = socket.queue_head;
    while (descriptor_index != invalid_index) {
      const auto &descriptor = datagrams_[descriptor_index];
      UdpQueuedDatagramCheckpoint datagram{
          .metadata = descriptor.metadata,
          .payload = std::vector<std::uint8_t>(
              descriptor.metadata.payload_octets)};
      std::size_t copied{};
      auto block_index = descriptor.first_block;
      while (block_index != invalid_index) {
        const auto amount = std::min<std::size_t>(
            device_catalog::udp_receive_block_bytes,
            datagram.payload.size() - copied);
        std::copy_n(blocks_[block_index].bytes.begin(), amount,
                    datagram.payload.begin() +
                        static_cast<std::ptrdiff_t>(copied));
        copied += amount;
        block_index = blocks_[block_index].next;
      }
      saved.datagrams.push_back(std::move(datagram));
      descriptor_index = descriptor.next;
    }
  }
  return state;
}

bool UdpEndpoint::validate_checkpoint(
    const UdpEndpointCheckpoint &state) noexcept {
  if (state.ephemeral_cursor < device_catalog::udp_ephemeral_port_first ||
      state.ephemeral_cursor > device_catalog::udp_ephemeral_port_last)
    return false;
  std::size_t datagram_count{};
  std::size_t required_blocks{};
  for (std::size_t index = 0; index < state.sockets.size(); ++index) {
    const auto &socket = state.sockets[index];
    if (!socket.generation ||
        (!socket.occupied && !socket.datagrams.empty()) ||
        (socket.occupied && socket.binding.port == 0U) ||
        (socket.occupied && socket.binding.family == IpFamily::ipv6 &&
         socket.binding.ipv4_broadcast) ||
        (!socket.occupied &&
         (socket.last_ipv6_transmission || socket.network_error)) ||
        (socket.last_ipv6_transmission &&
         (socket.binding.family != IpFamily::ipv6 ||
          ip::is_unspecified(socket.last_ipv6_transmission->local) ||
          ip::is_unspecified(socket.last_ipv6_transmission->remote) ||
          !socket.last_ipv6_transmission->interface_id ||
          !socket.last_ipv6_transmission->remote_port)) ||
        (socket.network_error &&
         (socket.binding.family != IpFamily::ipv6 ||
          socket.network_error->kind >
              Ipv6NetworkErrorKind::unknown ||
          socket.network_error->type >=
              packet::icmpv6_informational_type_boundary ||
          !ipv6_network_error_kind_matches(socket.network_error->kind,
                                           socket.network_error->type) ||
          ip::is_unspecified(socket.network_error->remote) ||
          !socket.network_error->interface_id ||
          !socket.network_error->remote_port)) ||
        socket.datagrams.size() > device_catalog::udp_datagrams_per_socket ||
        (socket.occupied && socket.binding.family == IpFamily::ipv6 &&
         ip::is_link_local(socket.binding.ipv6) &&
         socket.binding.interface_id == 0U))
      return false;
    // An unread advisory error is meaningful only while the exact encoded
    // transmission that justified accepting it is also retained. This closes
    // a checkpoint injection path which could otherwise manufacture SO_ERROR.
    if (socket.network_error &&
        (!socket.last_ipv6_transmission ||
         socket.network_error->remote !=
             socket.last_ipv6_transmission->remote ||
         socket.network_error->interface_id !=
             socket.last_ipv6_transmission->interface_id ||
         socket.network_error->remote_port !=
             socket.last_ipv6_transmission->remote_port))
      return false;
    datagram_count += socket.datagrams.size();
    for (const auto &datagram : socket.datagrams) {
      if (datagram.payload.size() > packet::udp::maximum_payload_octets ||
          datagram.metadata.payload_octets != datagram.payload.size() ||
          datagram.metadata.family != socket.binding.family ||
          datagram.metadata.destination_port != socket.binding.port ||
          (socket.binding.interface_id != 0U &&
           socket.binding.interface_id != datagram.metadata.interface_id))
        return false;
      const bool destination_matches =
          binding_address_wildcard(socket.binding) ||
          (socket.binding.family == IpFamily::ipv4
               ? socket.binding.ipv4 == datagram.metadata.destination_ipv4
               : socket.binding.ipv6 == datagram.metadata.destination_ipv6);
      if (!destination_matches)
        return false;
      required_blocks +=
          (datagram.payload.size() + device_catalog::udp_receive_block_bytes -
           1U) /
          device_catalog::udp_receive_block_bytes;
    }
    if (!socket.occupied)
      continue;
    // Restore must not create a binding set that bind() itself would reject.
    for (std::size_t previous = 0; previous < index; ++previous) {
      const auto &other = state.sockets[previous];
      if (!other.occupied || other.binding.family != socket.binding.family ||
          other.binding.port != socket.binding.port)
        continue;
      const bool interface_overlap = other.binding.interface_id == 0U ||
                                     socket.binding.interface_id == 0U ||
                                     other.binding.interface_id ==
                                         socket.binding.interface_id;
      const bool address_overlap = binding_address_wildcard(other.binding) ||
                                   binding_address_wildcard(socket.binding) ||
                                   binding_address_equal(other.binding,
                                                         socket.binding);
      if (interface_overlap && address_overlap)
        return false;
    }
  }
  return datagram_count <=
             device_catalog::udp_queued_datagrams_per_endpoint &&
         required_blocks <= block_count;
}

bool UdpEndpoint::restore(const UdpEndpointCheckpoint &state) noexcept {
  if (!validate_checkpoint(state))
    return false;
  UdpEndpoint replacement;
  try {
    replacement.sockets_.resize(state.sockets.size());
  } catch (const std::bad_alloc &) {
    return false;
  }
  replacement.ephemeral_cursor_ = state.ephemeral_cursor;
  for (std::size_t index = 0; index < state.sockets.size(); ++index) {
    const auto &saved = state.sockets[index];
    auto &socket = replacement.sockets_[index];
    socket.generation = saved.generation;
    if (!saved.occupied)
      continue;
    socket.binding = saved.binding;
    socket.last_ipv6_transmission = saved.last_ipv6_transmission;
    socket.network_error = saved.network_error;
    socket.occupied = true;
    for (const auto &datagram : saved.datagrams)
      if (replacement.enqueue(socket, datagram.metadata, datagram.payload) !=
          UdpIngressStatus::delivered)
        return false;
  }
  *this = std::move(replacement);
  return true;
}

} // namespace router::transport
