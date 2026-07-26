// Dynamic TCP socket table implementation. Endpoint-shard ownership keeps
// lookup and socket queues lock-free. Packet admission remains two-phase, and
// all cross-device communication is represented by encoded TCP segment bytes.

#include "router/tcp_endpoint.hpp"

#include "router/ip_address.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <new>
#include <utility>

namespace router::transport::tcp {
namespace {

[[nodiscard]] bool zero(packet::Ipv4 address) noexcept {
  return std::all_of(address.begin(), address.end(),
                     [](std::uint8_t value) { return value == 0U; });
}

[[nodiscard]] bool wildcard(const EndpointBinding &binding) noexcept {
  return binding.family == transport::IpFamily::ipv4
             ? zero(binding.ipv4)
             : ip::is_unspecified(binding.ipv6);
}

[[nodiscard]] bool address_equal(const EndpointBinding &left,
                                 const EndpointBinding &right) noexcept {
  return left.family == transport::IpFamily::ipv4
             ? left.ipv4 == right.ipv4
             : left.ipv6 == right.ipv6;
}

[[nodiscard]] InternetFamily family(transport::IpFamily value) noexcept {
  return value == transport::IpFamily::ipv4 ? InternetFamily::ipv4
                                             : InternetFamily::ipv6;
}

[[nodiscard]] bool has(std::uint8_t flags,
                       packet::tcp::Flag flag) noexcept {
  return (flags & static_cast<std::uint8_t>(flag)) != 0U;
}

[[nodiscard]] std::uint32_t segment_length(
    const packet::tcp::View &segment) noexcept {
  return static_cast<std::uint32_t>(segment.payload.size()) +
         (has(segment.flags, packet::tcp::syn) ? 1U : 0U) +
         (has(segment.flags, packet::tcp::fin) ? 1U : 0U);
}

[[nodiscard]] std::uint32_t timestamp_offset(
    const crypto::Sha256Digest &secret, const ConnectionTuple &tuple) noexcept {
  // Domain separation prevents observable timestamp values from revealing the
  // HMAC word used by the ISN generator even though both use endpoint entropy.
  constexpr std::array<std::uint8_t, 13> domain{
      't', 'c', 'p', '-', 't', 'i', 'm', 'e', 's', 't', 'a', 'm', 'p'};
  const std::array<std::uint8_t, 2> local_port{
      static_cast<std::uint8_t>(tuple.local_port >> 8U),
      static_cast<std::uint8_t>(tuple.local_port)};
  const std::array<std::uint8_t, 2> remote_port{
      static_cast<std::uint8_t>(tuple.remote_port >> 8U),
      static_cast<std::uint8_t>(tuple.remote_port)};
  const std::array<std::uint8_t, 1> family_tag{
      tuple.family == InternetFamily::ipv4 ? std::uint8_t{4U}
                                           : std::uint8_t{6U}};
  const auto local = tuple.family == InternetFamily::ipv4
                         ? std::span<const std::uint8_t>{tuple.local_ipv4}
                         : std::span<const std::uint8_t>{tuple.local_ipv6};
  const auto remote = tuple.family == InternetFamily::ipv4
                          ? std::span<const std::uint8_t>{tuple.remote_ipv4}
                          : std::span<const std::uint8_t>{tuple.remote_ipv6};
  const std::array<std::span<const std::uint8_t>, 6> input{
      domain, family_tag, local, local_port, remote, remote_port};
  const auto digest = crypto::hmac_sha256(secret, input);
  return (static_cast<std::uint32_t>(digest[0]) << 24U) |
         (static_cast<std::uint32_t>(digest[1]) << 16U) |
         (static_cast<std::uint32_t>(digest[2]) << 8U) | digest[3];
}

} // namespace

struct TcpEndpoint::OwnedConnection {
  std::vector<std::uint8_t> send;
  std::vector<std::uint8_t> receive;
  std::vector<std::uint8_t> bitmap;
  std::vector<std::uint8_t> scratch;
  std::vector<TransmissionRecord> history;
  std::vector<SackRange> sack;
  std::vector<SackRange> workspace;
  Connection connection;

  OwnedConnection(const ConnectionTuple &tuple,
                  const SocketResources &resources,
                  std::uint32_t maximum_transport_message,
                  std::uint32_t offset, Clock::time_point now)
      : send(resources.send_buffer_bytes),
        receive(resources.receive_buffer_bytes),
        bitmap((resources.receive_buffer_bytes + 7U) / 8U),
        scratch(maximum_transport_message),
        history(resources.transmission_records), sack(resources.sack_ranges),
        workspace(resources.sack_ranges),
        connection(tuple,
                   {.maximum_transport_message = maximum_transport_message,
                    .receive_capacity = static_cast<std::uint32_t>(
                        resources.receive_buffer_bytes),
                    .timestamp_offset = offset},
                   {.send_bytes = send,
                    .receive_bytes = receive,
                    .receive_bitmap = bitmap,
                    .transmit_payload_scratch = scratch,
                    .transmission_history = history,
                    .sack_ranges = sack,
                    .sack_workspace = workspace},
                   now) {}
};

struct TcpEndpoint::Socket {
  EndpointBinding binding{};
  SocketResources resources{};
  std::unique_ptr<OwnedConnection> owned;
  std::vector<EndpointSocketHandle> accepted;
  std::optional<std::uint32_t> listener_index;
  std::optional<transport::Ipv6NetworkError> network_error;
  PreparedConnectionSegment pending_connection{};
  std::size_t backlog{};
  std::uint64_t pending_endpoint_token{};
  std::uint32_t generation{1U};
  bool occupied{};
  bool listener{};
  bool pending_new{};
  bool queued_for_accept{};
};

TcpEndpoint::TcpEndpoint(crypto::Sha256Digest secret,
                         Clock::time_point now) noexcept
    : secret_(secret), isn_(secret, now) {}

TcpEndpoint::~TcpEndpoint() = default;

bool TcpEndpoint::valid() const noexcept { return isn_.valid(); }

TcpEndpoint::Socket *
TcpEndpoint::socket(EndpointSocketHandle handle) noexcept {
  if (handle.index >= sockets_.size() || !sockets_[handle.index])
    return nullptr;
  auto &candidate = *sockets_[handle.index];
  return candidate.occupied && candidate.generation == handle.generation
             ? &candidate
             : nullptr;
}

const TcpEndpoint::Socket *
TcpEndpoint::socket(EndpointSocketHandle handle) const noexcept {
  if (handle.index >= sockets_.size() || !sockets_[handle.index])
    return nullptr;
  const auto &candidate = *sockets_[handle.index];
  return candidate.occupied && candidate.generation == handle.generation
             ? &candidate
             : nullptr;
}

bool TcpEndpoint::binding_valid(const EndpointBinding &binding,
                                bool listener) const noexcept {
  if (binding.family == transport::IpFamily::ipv4)
    return listener || !zero(binding.ipv4);
  if ((!listener && ip::is_unspecified(binding.ipv6)) ||
      ip::is_multicast(binding.ipv6))
    return false;
  return !ip::is_link_local(binding.ipv6) || binding.interface_id != 0U;
}

bool TcpEndpoint::resources_valid(
    const SocketResources &resources) const noexcept {
  constexpr auto serial_limit = std::size_t{0x40000000U};
  return resources.send_buffer_bytes != 0U &&
         resources.send_buffer_bytes <= serial_limit &&
         resources.receive_buffer_bytes != 0U &&
         resources.receive_buffer_bytes <= serial_limit &&
         resources.transmission_records != 0U && resources.sack_ranges != 0U;
}

std::optional<std::uint16_t>
TcpEndpoint::ephemeral_port(const EndpointBinding &binding) noexcept {
  const auto count = static_cast<std::uint32_t>(
                         device_catalog::tcp_ephemeral_port_last -
                         device_catalog::tcp_ephemeral_port_first) +
                     1U;
  for (std::uint32_t attempt = 0U; attempt < count; ++attempt) {
    const auto candidate = ephemeral_cursor_;
    ephemeral_cursor_ = candidate == device_catalog::tcp_ephemeral_port_last
                            ? device_catalog::tcp_ephemeral_port_first
                            : static_cast<std::uint16_t>(candidate + 1U);
    const bool conflict = std::any_of(
        sockets_.begin(), sockets_.end(), [&](const auto &slot) {
          if (!slot || !slot->occupied ||
              slot->binding.family != binding.family ||
              slot->binding.port != candidate)
            return false;
          const bool interface_overlap =
              slot->binding.interface_id == 0U || binding.interface_id == 0U ||
              slot->binding.interface_id == binding.interface_id;
          return interface_overlap &&
                 (wildcard(slot->binding) || wildcard(binding) ||
                  address_equal(slot->binding, binding));
        });
    if (!conflict)
      return candidate;
  }
  return std::nullopt;
}

std::optional<EndpointSocketHandle> TcpEndpoint::listen(
    EndpointBinding binding, std::size_t backlog,
    SocketResources resources) noexcept {
  if (!valid() || backlog == 0U || !binding_valid(binding, true) ||
      !resources_valid(resources))
    return std::nullopt;
  if (binding.port == 0U) {
    const auto allocated = ephemeral_port(binding);
    if (!allocated)
      return std::nullopt;
    binding.port = *allocated;
  }
  for (const auto &slot : sockets_) {
    if (!slot || !slot->occupied || !slot->listener ||
        slot->binding.family != binding.family ||
        slot->binding.port != binding.port)
      continue;
    const bool interface_overlap = slot->binding.interface_id == 0U ||
                                   binding.interface_id == 0U ||
                                   slot->binding.interface_id ==
                                       binding.interface_id;
    if (interface_overlap &&
        (wildcard(slot->binding) || wildcard(binding) ||
         address_equal(slot->binding, binding)))
      return std::nullopt;
  }

  try {
    std::size_t index{};
    for (; index < sockets_.size(); ++index)
      if (sockets_[index] && !sockets_[index]->occupied)
        break;
    if (index == sockets_.size())
      sockets_.push_back(std::make_unique<Socket>());
    auto &slot = *sockets_[index];
    const auto generation = slot.generation;
    slot = Socket{};
    slot.generation = generation;
    slot.binding = binding;
    slot.resources = resources;
    slot.backlog = backlog;
    // Reserving the complete application backlog makes SYN admission
    // allocation-free after listen succeeds. A memory failure is reported at
    // listen time instead of terminating a noexcept packet-path operation.
    slot.accepted.reserve(backlog);
    slot.listener = true;
    slot.occupied = true;
    return EndpointSocketHandle{.index = static_cast<std::uint32_t>(index),
                                .generation = generation};
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

std::optional<EndpointSocketHandle> TcpEndpoint::allocate_connection(
    const ConnectionTuple &tuple, const EndpointBinding &binding,
    const SocketResources &resources,
    std::uint32_t maximum_transport_message,
    std::optional<std::uint32_t> listener_index,
    Clock::time_point now) noexcept {
  if (!resources_valid(resources) ||
      maximum_transport_message <= packet::tcp::minimum_header_octets)
    return std::nullopt;
  try {
    std::size_t index{};
    for (; index < sockets_.size(); ++index)
      if (sockets_[index] && !sockets_[index]->occupied)
        break;
    if (index == sockets_.size())
      sockets_.push_back(std::make_unique<Socket>());
    auto &slot = *sockets_[index];
    const auto generation = slot.generation;
    slot = Socket{};
    slot.generation = generation;
    slot.binding = binding;
    slot.resources = resources;
    slot.listener_index = listener_index;
    slot.owned = std::make_unique<OwnedConnection>(
        tuple, resources, maximum_transport_message,
        timestamp_offset(secret_, tuple), now);
    if (!slot.owned->connection.valid()) {
      slot.owned.reset();
      return std::nullopt;
    }
    slot.occupied = true;
    return EndpointSocketHandle{.index = static_cast<std::uint32_t>(index),
                                .generation = generation};
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

void TcpEndpoint::release(std::uint32_t index) noexcept {
  if (index >= sockets_.size() || !sockets_[index])
    return;
  auto &slot = *sockets_[index];
  if (slot.listener_index && *slot.listener_index < sockets_.size() &&
      sockets_[*slot.listener_index] &&
      sockets_[*slot.listener_index]->occupied) {
    auto &queue = sockets_[*slot.listener_index]->accepted;
    std::erase_if(queue, [&](EndpointSocketHandle handle) {
      return handle.index == index && handle.generation == slot.generation;
    });
  }
  slot.owned.reset();
  slot.accepted.clear();
  slot.network_error.reset();
  slot.occupied = false;
  slot.listener = false;
  slot.pending_endpoint_token = 0U;
  ++slot.generation;
  if (slot.generation == 0U)
    slot.generation = 1U;
}

EndpointPrepareResult TcpEndpoint::stage(
    EndpointSocketHandle handle, const ConnectionPrepareResult &prepared,
    bool newly_created) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return {.status = EndpointPrepareStatus::invalid_socket};
  if (!prepared.segment)
    return {.status = prepared.status == ConnectionPrepareStatus::no_action
                          ? EndpointPrepareStatus::no_action
                          : EndpointPrepareStatus::connection_error};
  auto token = next_endpoint_token_++;
  if (token == 0U)
    token = next_endpoint_token_++;
  entry->pending_endpoint_token = token;
  entry->pending_connection = prepared.segment;
  entry->pending_new = newly_created;
  return {.status = EndpointPrepareStatus::prepared,
          .segment = {.socket = handle,
                      .endpoint_token = token,
                      .octets = prepared.segment.octets,
                      .event = prepared.segment.event,
                      .emit = prepared.segment.emit}};
}

void TcpEndpoint::enqueue_accepted(Socket &child) noexcept {
  if (!child.listener_index || !child.queued_for_accept || !child.owned ||
      child.owned->connection.state() != State::established)
    return;
  // The child handle entered the pre-reserved backlog before SYN,ACK was
  // prepared. Establishment therefore only changes connection state and never
  // allocates or mutates queue order on this hot receive path.
}

EndpointPrepareResult TcpEndpoint::prepare_for_socket(
    EndpointSocketHandle handle, const ConnectionPrepareResult &prepared,
    bool newly_created, Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return {.status = EndpointPrepareStatus::invalid_socket};
  if (prepared.segment && !prepared.segment.emit) {
    if (!entry->owned->connection.commit(prepared.segment, now)) {
      if (newly_created)
        release(handle.index);
      return {.status = EndpointPrepareStatus::connection_error};
    }
    enqueue_accepted(*entry);
    return {.status = EndpointPrepareStatus::state_changed};
  }
  if (!prepared.segment) {
    if (prepared.status == ConnectionPrepareStatus::no_action) {
      enqueue_accepted(*entry);
      return {.status = EndpointPrepareStatus::no_action};
    }
    if (newly_created)
      release(handle.index);
  }
  return stage(handle, prepared, newly_created);
}

EndpointPrepareResult TcpEndpoint::prepare_connect(
    EndpointBinding binding, EndpointRemote remote,
    std::uint32_t maximum_transport_message, std::span<std::uint8_t> output,
    SocketResources resources, Clock::time_point now) noexcept {
  if (!valid() || !binding_valid(binding, false) || remote.port == 0U ||
      (binding.family == transport::IpFamily::ipv4
           ? zero(remote.ipv4)
           : ip::is_unspecified(remote.ipv6) || ip::is_multicast(remote.ipv6)))
    return {.status = EndpointPrepareStatus::invalid_binding};
  if (binding.port == 0U) {
    const auto allocated = ephemeral_port(binding);
    if (!allocated)
      return {.status = EndpointPrepareStatus::resource_exhausted};
    binding.port = *allocated;
  }
  ConnectionTuple tuple{.family = family(binding.family),
                        .local_ipv4 = binding.ipv4,
                        .remote_ipv4 = remote.ipv4,
                        .local_ipv6 = binding.ipv6,
                        .remote_ipv6 = remote.ipv6,
                        .interface_id = binding.interface_id,
                        .local_port = binding.port,
                        .remote_port = remote.port};
  for (const auto &slot : sockets_) {
    if (!slot || !slot->occupied || !slot->owned)
      continue;
    if (slot->owned->connection.tuple() == tuple)
      return {.status = EndpointPrepareStatus::tuple_conflict};
  }
  const auto handle = allocate_connection(tuple, binding, resources,
                                           maximum_transport_message,
                                           std::nullopt, now);
  if (!handle)
    return {.status = EndpointPrepareStatus::resource_exhausted};
  auto &connection = socket(*handle)->owned->connection;
  const auto initial = binding.family == transport::IpFamily::ipv4
                           ? isn_.generate(binding.ipv4, binding.port,
                                           remote.ipv4, remote.port, now)
                           : isn_.generate(binding.ipv6, binding.port,
                                           remote.ipv6, remote.port, now);
  return prepare_for_socket(
      *handle, connection.prepare_active_open(initial, output, now), true, now);
}

EndpointPrepareResult TcpEndpoint::ingest_ipv4(
    std::span<const std::uint8_t> segment, packet::Ipv4 source,
    packet::Ipv4 destination, std::uint64_t interface_id,
    std::uint32_t maximum_transport_message, std::span<std::uint8_t> output,
    Clock::time_point now) noexcept {
  return ingest(transport::IpFamily::ipv4, segment, source, destination, {}, {},
                interface_id, maximum_transport_message, output, now);
}

EndpointPrepareResult TcpEndpoint::ingest_ipv6(
    std::span<const std::uint8_t> segment, packet::Ipv6 source,
    packet::Ipv6 destination, std::uint64_t interface_id,
    std::uint32_t maximum_transport_message, std::span<std::uint8_t> output,
    Clock::time_point now) noexcept {
  return ingest(transport::IpFamily::ipv6, segment, {}, {}, source, destination,
                interface_id, maximum_transport_message, output, now);
}

EndpointPrepareResult TcpEndpoint::ingest(
    transport::IpFamily ip_family, std::span<const std::uint8_t> segment,
    packet::Ipv4 source_ipv4, packet::Ipv4 destination_ipv4,
    packet::Ipv6 source_ipv6, packet::Ipv6 destination_ipv6,
    std::uint64_t interface_id, std::uint32_t maximum_transport_message,
    std::span<std::uint8_t> output, Clock::time_point now) noexcept {
  const auto parsed = ip_family == transport::IpFamily::ipv4
                          ? packet::tcp::parse_ipv4(segment, source_ipv4,
                                                    destination_ipv4)
                          : packet::tcp::parse_ipv6(segment, source_ipv6,
                                                    destination_ipv6);
  if (!parsed)
    return {.status = EndpointPrepareStatus::malformed_segment};

  EndpointSocketHandle exact{};
  Socket *listener{};
  std::uint32_t listener_index{};
  for (std::size_t index = 0U; index < sockets_.size(); ++index) {
    auto &slot = sockets_[index];
    if (!slot || !slot->occupied || slot->binding.family != ip_family ||
        slot->binding.port != parsed->destination_port ||
        (slot->binding.interface_id != 0U &&
         slot->binding.interface_id != interface_id))
      continue;
    const bool local_match = wildcard(slot->binding) ||
                             (ip_family == transport::IpFamily::ipv4
                                  ? slot->binding.ipv4 == destination_ipv4
                                  : slot->binding.ipv6 == destination_ipv6);
    if (!local_match)
      continue;
    if (slot->listener) {
      listener = slot.get();
      listener_index = static_cast<std::uint32_t>(index);
      continue;
    }
    if (!slot->owned)
      continue;
    const auto &tuple = slot->owned->connection.tuple();
    const bool remote_match = tuple.remote_port == parsed->source_port &&
        (ip_family == transport::IpFamily::ipv4
             ? tuple.remote_ipv4 == source_ipv4
             : tuple.remote_ipv6 == source_ipv6);
    if (remote_match) {
      exact = {.index = static_cast<std::uint32_t>(index),
               .generation = slot->generation};
      break;
    }
  }

  if (socket(exact)) {
    auto &connection = socket(exact)->owned->connection;
    return prepare_for_socket(
        exact, connection.prepare_ingress(segment, 0U, output, now), false,
        now);
  }

  const bool initial_syn = has(parsed->flags, packet::tcp::syn) &&
                           !has(parsed->flags, packet::tcp::ack) &&
                           !has(parsed->flags, packet::tcp::rst);
  if (listener && initial_syn) {
    std::erase_if(listener->accepted, [&](EndpointSocketHandle handle) {
      const auto *child = socket(handle);
      return !child || child->listener_index != listener_index;
    });
    if (listener->accepted.size() >= listener->backlog)
      return {.status = EndpointPrepareStatus::backlog_full};
    EndpointBinding child_binding = listener->binding;
    if (wildcard(child_binding)) {
      child_binding.ipv4 = destination_ipv4;
      child_binding.ipv6 = destination_ipv6;
      child_binding.interface_id = interface_id;
    }
    ConnectionTuple tuple{.family = family(ip_family),
                          .local_ipv4 = destination_ipv4,
                          .remote_ipv4 = source_ipv4,
                          .local_ipv6 = destination_ipv6,
                          .remote_ipv6 = source_ipv6,
                          .interface_id = interface_id,
                          .local_port = parsed->destination_port,
                          .remote_port = parsed->source_port};
    const auto child = allocate_connection(
        tuple, child_binding, listener->resources, maximum_transport_message,
        listener_index, now);
    if (!child)
      return {.status = EndpointPrepareStatus::resource_exhausted};
    auto *child_socket = socket(*child);
    listener->accepted.push_back(*child);
    child_socket->queued_for_accept = true;
    auto &connection = child_socket->owned->connection;
    if (!connection.listen()) {
      release(child->index);
      return {.status = EndpointPrepareStatus::connection_error};
    }
    const auto initial = ip_family == transport::IpFamily::ipv4
                             ? isn_.generate(destination_ipv4,
                                             parsed->destination_port,
                                             source_ipv4, parsed->source_port,
                                             now)
                             : isn_.generate(destination_ipv6,
                                             parsed->destination_port,
                                             source_ipv6, parsed->source_port,
                                             now);
    return prepare_for_socket(
        *child, connection.prepare_ingress(segment, initial, output, now), true,
        now);
  }

  // RFC 9293 reset generation for a nonexistent connection has no mutable
  // state to commit. An incoming RST is silently discarded. ACK segments use
  // SEG.ACK as RST sequence; all others acknowledge their complete sequence
  // length, including SYN and FIN.
  if (has(parsed->flags, packet::tcp::rst))
    return {.status = EndpointPrepareStatus::no_socket};
  packet::tcp::Fields reset{.source_port = parsed->destination_port,
                            .destination_port = parsed->source_port};
  if (has(parsed->flags, packet::tcp::ack)) {
    reset.sequence = parsed->acknowledgment;
    reset.flags = packet::tcp::rst;
  } else {
    reset.acknowledgment = parsed->sequence + segment_length(*parsed);
    reset.flags = static_cast<std::uint8_t>(packet::tcp::rst |
                                            packet::tcp::ack);
  }
  const auto encoded = ip_family == transport::IpFamily::ipv4
                           ? packet::tcp::encode_ipv4(
                                 output, destination_ipv4, source_ipv4, reset,
                                 {}, {})
                           : packet::tcp::encode_ipv6(
                                 output, destination_ipv6, source_ipv6, reset,
                                 {}, {});
  return encoded
             ? EndpointPrepareResult{
                   .status = EndpointPrepareStatus::stateless_response,
                   .segment = {.octets = *encoded, .emit = true}}
             : EndpointPrepareResult{
                   .status = EndpointPrepareStatus::resource_exhausted};
}

std::optional<EndpointSocketHandle>
TcpEndpoint::accept(EndpointSocketHandle handle) noexcept {
  auto *listener = socket(handle);
  if (!listener || !listener->listener)
    return std::nullopt;
  for (auto candidate = listener->accepted.begin();
       candidate != listener->accepted.end();) {
    const auto child_handle = *candidate;
    auto *child = socket(child_handle);
    if (!child || !child->queued_for_accept) {
      candidate = listener->accepted.erase(candidate);
      continue;
    }
    if (!child->owned || child->owned->connection.state() != State::established) {
      ++candidate;
      continue;
    }
    listener->accepted.erase(candidate);
    child->queued_for_accept = false;
    child->listener_index.reset();
    return child_handle;
  }
  return std::nullopt;
}

std::size_t TcpEndpoint::write(EndpointSocketHandle handle,
                               std::span<const std::uint8_t> bytes,
                               Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  return entry && entry->owned ? entry->owned->connection.write(bytes, now)
                               : 0U;
}

std::size_t TcpEndpoint::read(EndpointSocketHandle handle,
                              std::span<std::uint8_t> output,
                              Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  return entry && entry->owned ? entry->owned->connection.read(output, now)
                               : 0U;
}

EndpointPrepareResult TcpEndpoint::prepare_data(
    EndpointSocketHandle handle, std::span<std::uint8_t> output, bool pushed,
    Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return {.status = EndpointPrepareStatus::invalid_socket};
  return prepare_for_socket(
      handle, entry->owned->connection.prepare_data(output, pushed, now), false,
      now);
}

EndpointPrepareResult TcpEndpoint::prepare_close(
    EndpointSocketHandle handle, std::span<std::uint8_t> output,
    Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return {.status = EndpointPrepareStatus::invalid_socket};
  return prepare_for_socket(
      handle, entry->owned->connection.prepare_close(output, now), false, now);
}

EndpointPrepareResult TcpEndpoint::prepare_deadline(
    EndpointSocketHandle handle, std::span<std::uint8_t> output,
    Clock::time_point now) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return {.status = EndpointPrepareStatus::invalid_socket};
  return prepare_for_socket(
      handle, entry->owned->connection.prepare_deadline(output, now), false,
      now);
}

bool TcpEndpoint::commit(const PreparedEndpointSegment &prepared,
                         Clock::time_point now) noexcept {
  auto *entry = socket(prepared.socket);
  if (!entry || !entry->owned || !prepared ||
      entry->pending_endpoint_token != prepared.endpoint_token ||
      entry->pending_connection.emit != prepared.emit)
    return false;
  if (!entry->owned->connection.commit(entry->pending_connection, now))
    return false;
  entry->pending_endpoint_token = 0U;
  entry->pending_connection = {};
  entry->pending_new = false;
  enqueue_accepted(*entry);
  return true;
}

bool TcpEndpoint::discard(const PreparedEndpointSegment &prepared) noexcept {
  auto *entry = socket(prepared.socket);
  if (!entry || !entry->owned || !prepared ||
      entry->pending_endpoint_token != prepared.endpoint_token ||
      !entry->owned->connection.discard(entry->pending_connection))
    return false;
  const bool remove = entry->pending_new;
  entry->pending_endpoint_token = 0U;
  entry->pending_connection = {};
  entry->pending_new = false;
  if (remove)
    release(prepared.socket.index);
  return true;
}

bool TcpEndpoint::close(EndpointSocketHandle handle) noexcept {
  auto *entry = socket(handle);
  if (!entry)
    return false;
  if (entry->pending_endpoint_token != 0U && entry->owned)
    static_cast<void>(entry->owned->connection.discard(
        entry->pending_connection));
  if (entry->listener) {
    // Accepted children are independent sockets. Only embryonic or established
    // children still queued on this listener are aborted with the listen owner.
    for (std::size_t index = 0U; index < sockets_.size(); ++index) {
      if (!sockets_[index] || !sockets_[index]->occupied ||
          sockets_[index]->listener_index != handle.index)
        continue;
      release(static_cast<std::uint32_t>(index));
    }
  }
  release(handle.index);
  return true;
}

std::optional<State>
TcpEndpoint::state(EndpointSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry && entry->owned
             ? std::optional{entry->owned->connection.state()}
             : std::nullopt;
}

std::optional<TcpEndpoint::Clock::time_point>
TcpEndpoint::next_deadline(EndpointSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry && entry->owned ? entry->owned->connection.next_deadline()
                               : std::nullopt;
}

std::optional<EndpointSocketHandle>
TcpEndpoint::earliest_deadline_socket() const noexcept {
  std::optional<EndpointSocketHandle> selected;
  Clock::time_point deadline = Clock::time_point::max();
  for (std::size_t index = 0U; index < sockets_.size(); ++index) {
    const auto &entry = sockets_[index];
    if (!entry || !entry->occupied || !entry->owned)
      continue;
    const auto candidate = entry->owned->connection.next_deadline();
    if (!candidate || *candidate >= deadline)
      continue;
    deadline = *candidate;
    selected = EndpointSocketHandle{
        .index = static_cast<std::uint32_t>(index),
        .generation = entry->generation};
  }
  return selected;
}

std::optional<EndpointBinding>
TcpEndpoint::local_binding(EndpointSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  return entry ? std::optional{entry->binding} : std::nullopt;
}

std::optional<EndpointRemote>
TcpEndpoint::remote_endpoint(EndpointSocketHandle handle) const noexcept {
  const auto *entry = socket(handle);
  if (!entry || !entry->owned)
    return std::nullopt;
  const auto &tuple = entry->owned->connection.tuple();
  return EndpointRemote{.ipv4 = tuple.remote_ipv4,
                        .ipv6 = tuple.remote_ipv6,
                        .port = tuple.remote_port};
}

bool TcpEndpoint::recognizes_ipv4_transmission(
    packet::Ipv4 local, packet::Ipv4 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    std::uint32_t sequence) const noexcept {
  return std::any_of(sockets_.begin(), sockets_.end(),
                     [&](const auto &candidate) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      return false;
    const auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    return tuple.family == InternetFamily::ipv4 &&
           tuple.local_ipv4 == local && tuple.remote_ipv4 == remote &&
           (tuple.interface_id == 0U || tuple.interface_id == interface_id) &&
           tuple.local_port == local_port && tuple.remote_port == remote_port &&
           connection.transmitted(sequence);
  });
}

bool TcpEndpoint::reduce_ipv4_path_mtu(
    packet::Ipv4 local, packet::Ipv4 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    std::uint32_t sequence,
    std::uint32_t maximum_transport_message) noexcept {
  for (auto &candidate : sockets_) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      continue;
    auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    if (tuple.family == InternetFamily::ipv4 && tuple.local_ipv4 == local &&
        tuple.remote_ipv4 == remote &&
        (tuple.interface_id == 0U || tuple.interface_id == interface_id) &&
        tuple.local_port == local_port && tuple.remote_port == remote_port &&
        connection.transmitted(sequence))
      return connection.reduce_maximum_transport_message(
          maximum_transport_message);
  }
  return false;
}

bool TcpEndpoint::recognizes_ipv6_transmission(
    packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    std::uint32_t sequence) const noexcept {
  return std::any_of(sockets_.begin(), sockets_.end(),
                     [&](const auto &candidate) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      return false;
    const auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    return tuple.family == InternetFamily::ipv6 &&
           tuple.local_ipv6 == local && tuple.remote_ipv6 == remote &&
           (tuple.interface_id == 0U || tuple.interface_id == interface_id) &&
           tuple.local_port == local_port &&
           tuple.remote_port == remote_port && connection.transmitted(sequence);
  });
}

bool TcpEndpoint::reduce_ipv6_path_mtu(
    packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    std::uint32_t sequence,
    std::uint32_t maximum_transport_message) noexcept {
  for (auto &candidate : sockets_) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      continue;
    auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    if (tuple.family == InternetFamily::ipv6 &&
        tuple.local_ipv6 == local && tuple.remote_ipv6 == remote &&
        (tuple.interface_id == 0U || tuple.interface_id == interface_id) &&
        tuple.local_port == local_port &&
        tuple.remote_port == remote_port && connection.transmitted(sequence))
      return connection.reduce_maximum_transport_message(
          maximum_transport_message);
  }
  return false;
}

std::size_t TcpEndpoint::reduce_ipv6_path_mtu_for_path(
    packet::Ipv6 remote, std::uint64_t interface_id,
    std::uint32_t maximum_transport_message) noexcept {
  std::size_t changed{};
  for (auto &candidate : sockets_) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      continue;
    auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    if (tuple.family != InternetFamily::ipv6 || tuple.remote_ipv6 != remote ||
        (tuple.interface_id != 0U && tuple.interface_id != interface_id))
      continue;
    if (connection.reduce_maximum_transport_message(
            maximum_transport_message))
      ++changed;
  }
  return changed;
}

bool TcpEndpoint::report_ipv6_error(
    packet::Ipv6 local, packet::Ipv6 remote, std::uint64_t interface_id,
    std::uint16_t local_port, std::uint16_t remote_port,
    std::uint32_t sequence, transport::Ipv6NetworkErrorKind kind,
    std::uint8_t type, std::uint8_t code,
    std::uint32_t parameter) noexcept {
  if (!transport::ipv6_network_error_kind_matches(kind, type))
    return false;
  for (auto &candidate : sockets_) {
    if (!candidate || !candidate->occupied || !candidate->owned)
      continue;
    const auto &connection = candidate->owned->connection;
    const auto &tuple = connection.tuple();
    if (tuple.family != InternetFamily::ipv6 || tuple.local_ipv6 != local ||
        tuple.remote_ipv6 != remote ||
        (tuple.interface_id != 0U && tuple.interface_id != interface_id) ||
        tuple.local_port != local_port || tuple.remote_port != remote_port ||
        !connection.transmitted(sequence))
      continue;
    // Replacement, instead of a queue, matches SO_ERROR consumption and keeps
    // packet input allocation-free under an ICMP flood.
    candidate->network_error = transport::Ipv6NetworkError{
        .remote = remote,
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

std::optional<transport::Ipv6NetworkError>
TcpEndpoint::take_network_error(EndpointSocketHandle handle) noexcept {
  auto *entry = socket(handle);
  if (!entry || !entry->network_error)
    return std::nullopt;
  auto result = entry->network_error;
  entry->network_error.reset();
  return result;
}

std::optional<EndpointCheckpoint>
TcpEndpoint::checkpoint(Clock::time_point now) const noexcept {
  // Sampling a copy keeps this observational API const while retaining the
  // exact four-microsecond M value that restore must continue from.
  auto sampled_isn = isn_;
  EndpointCheckpoint state{.isn = sampled_isn.checkpoint(now),
                           .sockets = {},
                           .ephemeral_cursor = ephemeral_cursor_,
                           .next_endpoint_token = next_endpoint_token_};
  try {
    state.sockets.reserve(sockets_.size());
    for (const auto &slot : sockets_) {
      if (!slot) {
        state.sockets.emplace_back();
        continue;
      }
      // A staged segment has no real packet-path admission result. Persisting
      // it would either manufacture a send or lose its rollback contract.
      if (slot->pending_endpoint_token != 0U)
        return std::nullopt;
      std::optional<ConnectionCheckpoint> connection;
      if (slot->occupied && slot->owned) {
        connection = slot->owned->connection.checkpoint(now);
        if (!connection)
          return std::nullopt;
      }
      state.sockets.push_back(
          {.binding = slot->binding,
           .resources = slot->resources,
           .connection = std::move(connection),
           .accepted = slot->accepted,
           .listener_index = slot->listener_index,
           .network_error = slot->network_error,
           .backlog = slot->backlog,
           .generation = slot->generation,
           .occupied = slot->occupied,
           .listener = slot->listener,
           .queued_for_accept = slot->queued_for_accept});
    }
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
  return state;
}

bool TcpEndpoint::restore(const EndpointCheckpoint &state,
                          Clock::time_point now) noexcept {
  if (!InitialSequenceGenerator::validate_checkpoint(state.isn) ||
      state.next_endpoint_token == 0U ||
      state.ephemeral_cursor < device_catalog::tcp_ephemeral_port_first ||
      state.ephemeral_cursor > device_catalog::tcp_ephemeral_port_last ||
      state.sockets.size() >
          static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()))
    return false;

  try {
    std::vector<std::unique_ptr<Socket>> candidate;
    candidate.reserve(state.sockets.size());
    for (std::size_t index = 0U; index < state.sockets.size(); ++index) {
      const auto &saved = state.sockets[index];
      if (saved.generation == 0U ||
          (!saved.occupied &&
           (saved.listener || saved.connection || saved.listener_index ||
            saved.queued_for_accept || !saved.accepted.empty() ||
            saved.network_error)) ||
          (saved.occupied &&
           saved.listener == saved.connection.has_value()) ||
          (saved.listener &&
           (saved.backlog == 0U || saved.accepted.size() > saved.backlog ||
            !binding_valid(saved.binding, true) ||
            !resources_valid(saved.resources))) ||
          (!saved.listener && saved.occupied &&
           (!binding_valid(saved.binding, false) ||
            !resources_valid(saved.resources))) ||
          (saved.network_error &&
           (saved.listener || !saved.connection ||
            saved.connection->tuple.family != InternetFamily::ipv6 ||
            saved.network_error->kind >
                transport::Ipv6NetworkErrorKind::unknown ||
            saved.network_error->type >=
                packet::icmpv6_informational_type_boundary ||
            !transport::ipv6_network_error_kind_matches(
                saved.network_error->kind, saved.network_error->type) ||
            saved.network_error->remote !=
                saved.connection->tuple.remote_ipv6 ||
            (saved.connection->tuple.interface_id != 0U &&
             saved.network_error->interface_id !=
                 saved.connection->tuple.interface_id) ||
            saved.network_error->remote_port !=
                saved.connection->tuple.remote_port)))
        return false;

      auto slot = std::make_unique<Socket>();
      slot->binding = saved.binding;
      slot->resources = saved.resources;
      slot->listener_index = saved.listener_index;
      slot->backlog = saved.backlog;
      slot->generation = saved.generation;
      slot->occupied = saved.occupied;
      slot->listener = saved.listener;
      slot->queued_for_accept = saved.queued_for_accept;
      slot->network_error = saved.network_error;
      if (saved.listener) {
        slot->accepted.reserve(saved.backlog);
        slot->accepted = saved.accepted;
      } else if (saved.occupied) {
        const auto &connection = *saved.connection;
        if (connection.policy.receive_capacity !=
                saved.resources.receive_buffer_bytes ||
            connection.tuple.local_port != saved.binding.port)
          return false;
        slot->owned = std::make_unique<OwnedConnection>(
            connection.tuple, saved.resources,
            connection.policy.maximum_transport_message,
            connection.policy.timestamp_offset, now);
        if (!slot->owned->connection.restore(connection, now))
          return false;
      }
      candidate.push_back(std::move(slot));
    }

    // Backlog references form a bidirectional relation. Validate both sides so
    // a corrupt project cannot make one child acceptable through two listeners
    // or strand a queued child outside its owner's reserved backlog.
    std::vector<std::uint8_t> queue_references(candidate.size(), 0U);
    for (std::size_t listener_index = 0U; listener_index < candidate.size();
         ++listener_index) {
      const auto &listener = candidate[listener_index];
      if (!listener->occupied || !listener->listener)
        continue;
      for (const auto handle : listener->accepted) {
        if (handle.index >= candidate.size())
          return false;
        const auto &child = candidate[handle.index];
        if (!child->occupied || child->listener ||
            child->generation != handle.generation ||
            child->listener_index != listener_index ||
            !child->queued_for_accept ||
            queue_references[handle.index] != 0U)
          return false;
        queue_references[handle.index] = 1U;
      }
    }
    for (std::size_t index = 0U; index < candidate.size(); ++index) {
      const auto &slot = candidate[index];
      if (slot->queued_for_accept != (queue_references[index] != 0U) ||
          (slot->listener_index.has_value() != slot->queued_for_accept))
        return false;
    }

    InitialSequenceGenerator restored_isn{state.isn.secret, now};
    if (!restored_isn.restore(state.isn, now))
      return false;
    // All allocations and cross-record validation completed on owner-private
    // candidates. Publication is now a constant-time replacement.
    secret_ = state.isn.secret;
    isn_ = std::move(restored_isn);
    sockets_ = std::move(candidate);
    ephemeral_cursor_ = state.ephemeral_cursor;
    next_endpoint_token_ = state.next_endpoint_token;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::transport::tcp
