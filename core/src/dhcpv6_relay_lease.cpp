// DHCPv6 relay lease-state implementation. Parsing is intentionally repeated
// in small bounded passes where needed: a complete Reply is proved valid and
// resource-admissible before one live lease is changed. This costs cold CPM
// work but avoids rollback allocation and partial operational state.

#include "router/dhcpv6_relay_lease.hpp"

#include <algorithm>
#include <limits>
#include <new>

namespace router::dhcpv6 {
namespace {

using packet::dhcpv6::MessageType;
using packet::dhcpv6::OptionCode;

constexpr std::uint16_t code(OptionCode value) noexcept {
  return static_cast<std::uint16_t>(value);
}

bool usable_client_mac(const packet::Mac &mac) noexcept {
  // Ethernet source addresses are individual and nonzero. A group address or
  // the all-zero placeholder cannot become a DHCP-derived Neighbor Cache key.
  return std::any_of(mac.begin(), mac.end(),
                     [](std::uint8_t octet) { return octet != 0U; }) &&
         (mac.front() & 1U) == 0U;
}

RelayLeaseRepository::Clock::time_point
lease_deadline(RelayLeaseRepository::Clock::time_point now,
               std::uint32_t lifetime) noexcept {
  // RFC 9915 section 7.7 assigns 0xffffffff to infinity. Keeping max() avoids
  // overflowing steady_clock and gives checkpoint code one unambiguous form.
  return lifetime == std::numeric_limits<std::uint32_t>::max()
             ? RelayLeaseRepository::Clock::time_point::max()
             : now + std::chrono::seconds{lifetime};
}

std::int64_t remaining_nanoseconds(
    RelayLeaseRepository::Clock::time_point deadline,
    RelayLeaseRepository::Clock::time_point now) noexcept {
  if (deadline == RelayLeaseRepository::Clock::time_point::max())
    return std::numeric_limits<std::int64_t>::max();
  if (deadline <= now)
    return 0;
  const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(
      deadline - now);
  return remaining.count() < 0 ? 0 : remaining.count();
}

RelayLeaseRepository::Clock::time_point restore_deadline(
    RelayLeaseRepository::Clock::time_point now,
    std::int64_t remaining) noexcept {
  return remaining == std::numeric_limits<std::int64_t>::max()
             ? RelayLeaseRepository::Clock::time_point::max()
             : now + std::chrono::nanoseconds{remaining};
}

struct MessageIdentity {
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> client{};
  std::array<std::uint8_t, packet::dhcpv6::maximum_duid_octets> server{};
  std::uint16_t client_octets{};
  std::uint16_t server_octets{};
  std::uint16_t status{};
  bool has_status{};
  bool has_server{};
};

std::optional<MessageIdentity>
message_identity(const packet::dhcpv6::MessageView &message) noexcept {
  MessageIdentity result;
  bool has_client{};
  bool has_server{};
  packet::dhcpv6::OptionCursor cursor{message.options};
  while (const auto option = cursor.next()) {
    if (option->code == code(OptionCode::client_identifier)) {
      if (has_client || !packet::dhcpv6::valid_duid(option->data) ||
          option->data.size() > result.client.size())
        return std::nullopt;
      std::copy(option->data.begin(), option->data.end(), result.client.begin());
      result.client_octets = static_cast<std::uint16_t>(option->data.size());
      has_client = true;
    } else if (option->code == code(OptionCode::server_identifier)) {
      if (has_server || !packet::dhcpv6::valid_duid(option->data) ||
          option->data.size() > result.server.size())
        return std::nullopt;
      std::copy(option->data.begin(), option->data.end(), result.server.begin());
      result.server_octets = static_cast<std::uint16_t>(option->data.size());
      has_server = true;
      result.has_server = true;
    } else if (option->code == code(OptionCode::status_code)) {
      const auto status = packet::dhcpv6::parse_status_code(option->data);
      if (result.has_status || !status)
        return std::nullopt;
      result.status = status->code;
      result.has_status = true;
    }
  }
  // Client messages observed on the access side normally do not carry a
  // Server Identifier. Parsing therefore requires only the Client Identifier;
  // prepare_reply separately enforces the Server Identifier required in a
  // Reply. Sharing one parser must not accidentally reject valid Solicits.
  return cursor.valid() && has_client ? std::optional{result} : std::nullopt;
}

enum class IaStatus : std::uint8_t { success, failure, malformed };

IaStatus ia_status(std::span<const std::uint8_t> options) noexcept {
  bool have_status{};
  std::uint16_t status{};
  packet::dhcpv6::OptionCursor cursor{options};
  while (const auto option = cursor.next()) {
    if (option->code != code(OptionCode::status_code))
      continue;
    const auto parsed = packet::dhcpv6::parse_status_code(option->data);
    if (have_status || !parsed)
      return IaStatus::malformed;
    have_status = true;
    status = parsed->code;
  }
  // A malformed option sequence cannot be treated as an absent success code.
  if (!cursor.valid())
    return IaStatus::malformed;
  return !have_status || status == 0U ? IaStatus::success
                                      : IaStatus::failure;
}

} // namespace

bool RelayLeaseRepository::same_client(const ClientIdentity &left,
                                       const ClientIdentity &right) noexcept {
  return left.iaid == right.iaid && left.kind == right.kind &&
         left.duid_octets == right.duid_octets &&
         std::equal(left.duid.begin(),
                    left.duid.begin() + left.duid_octets,
                    right.duid.begin());
}

bool RelayLeaseRepository::same_lease_key(
    const RelayLeaseRecord &left, const RelayLeaseRecord &right) noexcept {
  return left.interface_id == right.interface_id &&
         left.protocol == right.protocol &&
         left.prefix_length == right.prefix_length &&
         left.value == right.value && same_client(left.client, right.client);
}

const RelayLeasePolicy *
RelayLeaseRepository::policy(std::uint64_t interface_id) const noexcept {
  const auto found = std::find_if(
      policies_.begin(), policies_.end(), [&](const auto &candidate) {
        return candidate.interface_id == interface_id;
      });
  return found == policies_.end() ? nullptr : &*found;
}

std::size_t
RelayLeaseRepository::lease_count(std::uint64_t interface_id) const noexcept {
  return static_cast<std::size_t>(std::count_if(
      leases_.begin(), leases_.end(), [&](const auto &lease) {
        return lease.interface_id == interface_id;
      }));
}

bool RelayLeaseRepository::configure(
    std::span<const RelayLeasePolicy> policies) noexcept {
  std::size_t total_capacity{};
  for (std::size_t index = 0; index < policies.size(); ++index) {
    const auto &candidate = policies[index];
    if (candidate.interface_id == 0U ||
        candidate.client_prefix.length > ip::ipv6_address_bits ||
        ip::mask(candidate.client_prefix.network,
                 candidate.client_prefix.length) !=
            candidate.client_prefix.network ||
        (candidate.route_prefix_exclude &&
         !candidate.route_delegated_prefix))
      return false;
    if (std::any_of(policies.begin(), policies.begin() + index,
                    [&](const auto &previous) {
                      return previous.interface_id == candidate.interface_id;
                    }))
      return false;
    if (total_capacity >
        std::numeric_limits<std::size_t>::max() - candidate.maximum_leases)
      return false;
    total_capacity += candidate.maximum_leases;
    if (lease_count(candidate.interface_id) > candidate.maximum_leases)
      return false;
  }
  // Every retained lease must still have a corresponding policy. Configuration
  // removal first drains that interface so no route withdrawal is lost here.
  if (std::any_of(leases_.begin(), leases_.end(), [&](const auto &lease) {
        return std::none_of(policies.begin(), policies.end(),
                            [&](const auto &candidate) {
                              return candidate.interface_id ==
                                     lease.interface_id;
                            });
      }))
    return false;

  try {
    std::vector<RelayLeasePolicy> next_policies{policies.begin(),
                                                policies.end()};
    std::vector<RelayClientObservation> next_observations;
    std::vector<RelayLeaseRecord> next_leases;
    std::vector<RelayLeaseMutation> next_prepared;
    next_observations.reserve(total_capacity);
    next_leases.reserve(total_capacity);
    // One legal Reply can withdraw every old binding with zero lifetimes and
    // install the same number of different resources while the final count
    // still equals the limit. Reserve both halves on the configuration path.
    if (total_capacity > std::numeric_limits<std::size_t>::max() / 2U)
      return false;
    next_prepared.reserve(total_capacity * 2U);
    // Retained values are copied only after every allocation succeeded. A
    // failed Wasm growth request cannot leave a half-reconfigured repository.
    next_leases.insert(next_leases.end(), leases_.begin(), leases_.end());
    for (const auto &observation : observations_)
      if (std::any_of(next_policies.begin(), next_policies.end(),
                      [&](const auto &candidate) {
                        return candidate.interface_id ==
                               observation.interface_id;
                      }) &&
          next_observations.size() < next_observations.capacity())
        next_observations.push_back(observation);
    policies_.swap(next_policies);
    observations_.swap(next_observations);
    leases_.swap(next_leases);
    prepared_.swap(next_prepared);
    prepared_kind_ = PreparedKind::none;
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void RelayLeaseRepository::remove_expired_observations(
    Clock::time_point now) noexcept {
  observations_.erase(
      std::remove_if(observations_.begin(), observations_.end(),
                     [&](const auto &item) { return item.expires_at <= now; }),
      observations_.end());
}

bool RelayLeaseRepository::observe_client(
    std::uint64_t interface_id, packet::Ipv6 peer_address,
    packet::Mac source_mac, std::span<const std::uint8_t> message,
    Clock::time_point now) noexcept {
  discard_prepared();
  const auto *configured = policy(interface_id);
  if (!configured || configured->maximum_leases == 0U ||
      !usable_client_mac(source_mac) || ip::is_unspecified(peer_address) ||
      ip::is_multicast(peer_address))
    return false;
  const auto parsed = packet::dhcpv6::parse(message);
  if (!parsed || parsed->relay ||
      parsed->type == static_cast<std::uint8_t>(MessageType::advertise) ||
      parsed->type == static_cast<std::uint8_t>(MessageType::reply) ||
      parsed->type == static_cast<std::uint8_t>(MessageType::reconfigure))
    return false;
  const auto identity = message_identity(*parsed);
  if (!identity)
    return false;

  remove_expired_observations(now);
  bool observed{};
  packet::dhcpv6::OptionCursor cursor{parsed->options};
  while (const auto option = cursor.next()) {
    LeaseKind kind{};
    std::uint32_t iaid{};
    if (option->code == code(OptionCode::ia_na) ||
        option->code == code(OptionCode::ia_pd)) {
      const auto association =
          packet::dhcpv6::parse_ia_na_or_pd(option->data);
      if (!association)
        return false;
      iaid = association->iaid;
      kind = option->code == code(OptionCode::ia_pd)
                 ? LeaseKind::prefix
                 : LeaseKind::non_temporary;
    } else if (option->code == code(OptionCode::ia_ta)) {
      const auto association = packet::dhcpv6::parse_ia_ta(option->data);
      if (!association)
        return false;
      iaid = association->iaid;
      kind = LeaseKind::temporary;
    } else {
      continue;
    }
    ClientIdentity client{.duid = identity->client,
                          .duid_octets = identity->client_octets,
                          .iaid = iaid,
                          .kind = kind};
    const auto existing = std::find_if(
        observations_.begin(), observations_.end(), [&](const auto &item) {
          return item.interface_id == interface_id &&
                 item.transaction_id == parsed->transaction_id &&
                 same_client(item.client, client);
        });
    const RelayClientObservation value{
        .client = client,
        .peer_address = peer_address,
        .source_mac = source_mac,
        .interface_id = interface_id,
        .transaction_id = parsed->transaction_id,
        // RFC 9915's default maximum retransmission duration is one hour. An
        // older correlation cannot belong to a live client transaction.
        .expires_at = now + std::chrono::seconds{
                                packet::dhcpv6::
                                    maximum_retransmission_default_seconds}};
    if (existing != observations_.end())
      *existing = value;
    else {
      if (observations_.size() == observations_.capacity())
        return false;
      observations_.push_back(value);
    }
    observed = true;
  }
  return cursor.valid() && observed;
}

const RelayClientObservation *RelayLeaseRepository::observation(
    std::uint64_t interface_id, std::uint32_t transaction_id,
    const ClientIdentity &client, packet::Ipv6 peer_address,
    Clock::time_point now) const noexcept {
  const auto found = std::find_if(
      observations_.begin(), observations_.end(), [&](const auto &item) {
        return item.interface_id == interface_id &&
               item.transaction_id == transaction_id &&
               item.peer_address == peer_address && item.expires_at > now &&
               same_client(item.client, client);
      });
  return found == observations_.end() ? nullptr : &*found;
}

RelayLeaseReplyPlan RelayLeaseRepository::prepare_reply(
    std::uint64_t interface_id, packet::Ipv6 peer_address,
    packet::Ipv6 server_address,
    std::uint64_t server_scope_interface_id,
    std::span<const std::uint8_t> message, Clock::time_point now) noexcept {
  discard_prepared();
  remove_expired_observations(now);
  const auto *configured = policy(interface_id);
  if (!configured || configured->maximum_leases == 0U)
    return {.status = RelayLeaseReplyStatus::disabled};
  const auto parsed = packet::dhcpv6::parse(message);
  if (!parsed || ip::is_unspecified(peer_address) ||
      ip::is_multicast(peer_address) || ip::is_unspecified(server_address) ||
      ip::is_multicast(server_address) ||
      (ip::is_link_local(server_address) && server_scope_interface_id == 0U))
    return {.status = RelayLeaseReplyStatus::malformed};
  if (parsed->relay || parsed->type !=
                           static_cast<std::uint8_t>(MessageType::reply))
    return {.status = RelayLeaseReplyStatus::wrong_message_type};
  const auto identity = message_identity(*parsed);
  if (!identity || !identity->has_server)
    return {.status = RelayLeaseReplyStatus::malformed};
  // A non-success top-level status carries no successful bindings. It is a
  // valid Reply and must still reach the client without changing lease state.
  if (identity->has_status && identity->status != 0U)
    return {.status = RelayLeaseReplyStatus::accepted};

  // Capacity is evaluated against the final atomic state, not merely against
  // the number of new values. A Reply may legitimately withdraw one binding
  // and assign another while the interface is already at its configured
  // limit. Counting that replacement as an additional lease would discard a
  // valid Reply even though the committed state still fits.
  std::size_t projected_leases = lease_count(interface_id);
  auto stage = [&](RelayLeaseRecord record, std::uint32_t valid_lifetime,
                   std::uint32_t preferred_lifetime) {
    const auto already_staged = std::find_if(
        prepared_.begin(), prepared_.end(), [&](const auto &mutation) {
          return same_lease_key(mutation.record, record) ||
                 (mutation.record.interface_id == record.interface_id &&
                  mutation.record.prefix_length == record.prefix_length &&
                  mutation.record.value == record.value);
        });
    if (already_staged != prepared_.end())
      return false;
    const auto live = std::find_if(
        leases_.begin(), leases_.end(), [&](const auto &lease) {
          return same_lease_key(lease, record);
        });
    const auto conflicting_live = std::find_if(
        leases_.begin(), leases_.end(), [&](const auto &lease) {
          return lease.interface_id == record.interface_id &&
                 lease.prefix_length == record.prefix_length &&
                 lease.value == record.value &&
                 !same_lease_key(lease, record);
        });
    if (conflicting_live != leases_.end())
      return false;
    if (valid_lifetime == 0U) {
      if (live != leases_.end()) {
        prepared_.push_back(
            {.kind = RelayLeaseMutationKind::remove, .record = *live});
        --projected_leases;
      }
      return true;
    }
    if (live == leases_.end())
      ++projected_leases;
    record.preferred_until = lease_deadline(now, preferred_lifetime);
    record.valid_until = lease_deadline(now, valid_lifetime);
    prepared_.push_back(
        {.kind = RelayLeaseMutationKind::install, .record = record});
    return true;
  };

  try {
    packet::dhcpv6::OptionCursor outer{parsed->options};
    while (const auto option = outer.next()) {
      const bool na = option->code == code(OptionCode::ia_na);
      const bool pd = option->code == code(OptionCode::ia_pd);
      const bool ta = option->code == code(OptionCode::ia_ta);
      if (!na && !pd && !ta)
        continue;

      std::uint32_t iaid{};
      std::span<const std::uint8_t> resources;
      LeaseKind lease_kind{};
      RelayLeaseProtocol protocol{};
      if (ta) {
        const auto association = packet::dhcpv6::parse_ia_ta(option->data);
        if (!association)
          return {.status = RelayLeaseReplyStatus::malformed};
        iaid = association->iaid;
        resources = association->options;
        lease_kind = LeaseKind::temporary;
        protocol = RelayLeaseProtocol::temporary;
      } else {
        const auto association =
            packet::dhcpv6::parse_ia_na_or_pd(option->data);
        if (!association)
          return {.status = RelayLeaseReplyStatus::malformed};
        iaid = association->iaid;
        resources = association->options;
        lease_kind = pd ? LeaseKind::prefix : LeaseKind::non_temporary;
        protocol = pd ? RelayLeaseProtocol::delegated_prefix
                      : RelayLeaseProtocol::non_temporary;
      }
      const auto association_status = ia_status(resources);
      if (association_status == IaStatus::malformed)
        return {.status = RelayLeaseReplyStatus::malformed};
      if (association_status == IaStatus::failure)
        continue;
      ClientIdentity client{.duid = identity->client,
                            .duid_octets = identity->client_octets,
                            .iaid = iaid,
                            .kind = lease_kind};
      const RelayServerIdentity server{
          .duid = identity->server,
          .duid_octets = identity->server_octets};
      const auto *seen = observation(interface_id, parsed->transaction_id,
                                     client, peer_address, now);

      packet::dhcpv6::OptionCursor nested{resources};
      while (const auto resource = nested.next()) {
        if (!pd && resource->code == code(OptionCode::ia_address)) {
          const auto address =
              packet::dhcpv6::parse_ia_address(resource->data);
          if (!address || ip::is_unspecified(address->address) ||
              ip::is_multicast(address->address) ||
              ip::is_link_local(address->address))
            return {.status = RelayLeaseReplyStatus::malformed};
          RelayLeaseRecord record{
              .client = client,
              .server = server,
              .value = address->address,
              .peer_address = peer_address,
              .server_address = server_address,
              .client_mac = seen ? seen->source_mac : packet::Mac{},
              .interface_id = interface_id,
              .server_scope_interface_id = server_scope_interface_id,
              .physical_port_ordinal = configured->physical_port_ordinal,
              .prefix_length = 128U,
              .protocol = protocol,
              .has_client_mac = seen != nullptr};
          if (!stage(record, address->valid_lifetime,
                     address->preferred_lifetime))
            return {.status = RelayLeaseReplyStatus::malformed};
        } else if (pd &&
                   resource->code == code(OptionCode::ia_prefix)) {
          const auto prefix =
              packet::dhcpv6::parse_ia_prefix(resource->data);
          if (!prefix || ip::mask(prefix->prefix, prefix->prefix_length) !=
                             prefix->prefix)
            return {.status = RelayLeaseReplyStatus::malformed};
          RelayLeaseRecord record{
              .client = client,
              .server = server,
              .value = prefix->prefix,
              .peer_address = peer_address,
              .server_address = server_address,
              .client_mac = seen ? seen->source_mac : packet::Mac{},
              .interface_id = interface_id,
              .server_scope_interface_id = server_scope_interface_id,
              .physical_port_ordinal = configured->physical_port_ordinal,
              .prefix_length = prefix->prefix_length,
              .protocol = protocol,
              .has_client_mac = seen != nullptr};
          bool exclude_seen{};
          packet::dhcpv6::OptionCursor prefix_options{prefix->options};
          while (const auto child = prefix_options.next()) {
            if (child->code != code(OptionCode::prefix_exclude))
              continue;
            if (exclude_seen)
              return {.status = RelayLeaseReplyStatus::malformed};
            const auto excluded = packet::dhcpv6::parse_prefix_exclude(
                child->data, prefix->prefix, prefix->prefix_length);
            if (!excluded)
              return {.status = RelayLeaseReplyStatus::malformed};
            record.excluded_prefix = excluded->excluded_prefix;
            record.excluded_prefix_length =
                excluded->excluded_prefix_length;
            record.has_excluded_prefix = true;
            exclude_seen = true;
          }
          if (!prefix_options.valid() ||
              !stage(record, prefix->valid_lifetime,
                     prefix->preferred_lifetime))
            return {.status = RelayLeaseReplyStatus::malformed};
        }
      }
      if (!nested.valid())
        return {.status = RelayLeaseReplyStatus::malformed};
    }
    if (!outer.valid())
      return {.status = RelayLeaseReplyStatus::malformed};
  } catch (const std::bad_alloc &) {
    prepared_.clear();
    return {.status = RelayLeaseReplyStatus::resource_exhausted};
  }

  if (projected_leases > configured->maximum_leases) {
    prepared_.clear();
    return {.status = RelayLeaseReplyStatus::lease_limit_exceeded};
  }
  prepared_kind_ = PreparedKind::reply;
  return {.status = RelayLeaseReplyStatus::accepted,
          .mutations = prepared_};
}

bool RelayLeaseRepository::commit_prepared() noexcept {
  if (prepared_kind_ == PreparedKind::none)
    return false;
  // prepare_reply and prepare_expiry proved that every install has either an
  // existing slot or reserved vector capacity. This loop therefore cannot
  // allocate and cannot fail halfway through normal operation.
  for (const auto &mutation : prepared_) {
    const auto found = std::find_if(
        leases_.begin(), leases_.end(), [&](const auto &lease) {
          return same_lease_key(lease, mutation.record);
        });
    if (mutation.kind == RelayLeaseMutationKind::remove) {
      if (found != leases_.end())
        leases_.erase(found);
      continue;
    }
    if (found != leases_.end())
      *found = mutation.record;
    else if (leases_.size() < leases_.capacity())
      leases_.push_back(mutation.record);
    else {
      // This branch indicates an internal broken preflight invariant. Keep the
      // prepared batch for diagnostics rather than claiming a full commit.
      return false;
    }
  }
  prepared_.clear();
  prepared_kind_ = PreparedKind::none;
  return true;
}

void RelayLeaseRepository::discard_prepared() noexcept {
  prepared_.clear();
  prepared_kind_ = PreparedKind::none;
}

std::span<const RelayLeaseMutation>
RelayLeaseRepository::prepare_expiry(Clock::time_point now) noexcept {
  discard_prepared();
  for (const auto &lease : leases_)
    if (lease.valid_until != Clock::time_point::max() &&
        lease.valid_until <= now)
      prepared_.push_back(
          {.kind = RelayLeaseMutationKind::remove, .record = lease});
  if (!prepared_.empty())
    prepared_kind_ = PreparedKind::expiry;
  return prepared_;
}

std::span<const RelayLeaseMutation>
RelayLeaseRepository::prepare_remove_interface(
    std::uint64_t interface_id) noexcept {
  discard_prepared();
  if (!policy(interface_id))
    return prepared_;
  // prepared_ was reserved for the sum of all interface limits during
  // configure(). At most leases_.size() records can match, so push_back stays
  // allocation-free on this noexcept forwarding-owner path.
  for (const auto &lease : leases_)
    if (lease.interface_id == interface_id)
      prepared_.push_back(
          {.kind = RelayLeaseMutationKind::remove, .record = lease});
  if (!prepared_.empty())
    prepared_kind_ = PreparedKind::expiry;
  return prepared_;
}

std::span<const RelayLeaseMutation>
RelayLeaseRepository::prepare_clear(
    const RelayLeaseClearFilter &filter) noexcept {
  discard_prepared();
  if (!policy(filter.interface_id) ||
      (filter.prefix_specific &&
       (filter.prefix.length == 0U || filter.prefix.length > 128U ||
        ip::is_unspecified(filter.prefix.network) ||
        ip::is_multicast(filter.prefix.network))) ||
      (filter.mac_specific && !usable_client_mac(filter.mac)))
    return prepared_;

  // The repository scratch was reserved for every admitted lease. Selecting
  // rows therefore performs no allocation on the forwarding-owner command
  // path and can publish one all-or-nothing withdrawal batch downstream.
  for (const auto &lease : leases_) {
    if (lease.interface_id != filter.interface_id)
      continue;
    if (filter.prefix_specific &&
        (lease.value != filter.prefix.network ||
         lease.prefix_length != filter.prefix.length))
      continue;
    if (filter.mac_specific &&
        (!lease.has_client_mac || lease.client_mac != filter.mac))
      continue;
    prepared_.push_back(
        {.kind = RelayLeaseMutationKind::remove, .record = lease});
  }
  if (!prepared_.empty())
    prepared_kind_ = PreparedKind::operator_clear;
  return prepared_;
}

std::optional<RelayLeaseRepository::Clock::time_point>
RelayLeaseRepository::next_deadline() const noexcept {
  std::optional<Clock::time_point> next;
  for (const auto &lease : leases_)
    if (lease.valid_until != Clock::time_point::max() &&
        (!next || lease.valid_until < *next))
      next = lease.valid_until;
  for (const auto &item : observations_)
    if (!next || item.expires_at < *next)
      next = item.expires_at;
  return next;
}

std::vector<RelayLeaseCheckpoint>
RelayLeaseRepository::checkpoint(Clock::time_point now) const {
  std::vector<RelayLeaseCheckpoint> result;
  result.reserve(leases_.size());
  for (const auto &lease : leases_)
    result.push_back({
        .client = lease.client,
        .server = lease.server,
        .value = lease.value,
        .peer_address = lease.peer_address,
        .server_address = lease.server_address,
        .client_mac = lease.client_mac,
        .excluded_prefix = lease.excluded_prefix,
        .interface_id = lease.interface_id,
        .server_scope_interface_id = lease.server_scope_interface_id,
        .preferred_remaining_nanoseconds =
            remaining_nanoseconds(lease.preferred_until, now),
        .valid_remaining_nanoseconds =
            remaining_nanoseconds(lease.valid_until, now),
        .physical_port_ordinal = lease.physical_port_ordinal,
        .prefix_length = lease.prefix_length,
        .excluded_prefix_length = lease.excluded_prefix_length,
        .protocol = lease.protocol,
        .has_client_mac = lease.has_client_mac,
        .has_excluded_prefix = lease.has_excluded_prefix});
  return result;
}

bool RelayLeaseRepository::restore(
    std::span<const RelayLeasePolicy> policies,
    std::span<const RelayLeaseCheckpoint> state,
    Clock::time_point now) noexcept {
  RelayLeaseRepository replacement;
  if (!replacement.configure(policies))
    return false;
  try {
    for (const auto &saved : state) {
      const auto *configured = replacement.policy(saved.interface_id);
      const bool valid_client =
          saved.client.duid_octets >= 3U &&
          saved.client.duid_octets <= saved.client.duid.size() &&
          packet::dhcpv6::valid_duid(
              std::span<const std::uint8_t>{saved.client.duid}.first(
                  saved.client.duid_octets));
      const bool valid_server =
          saved.server.duid_octets >= 3U &&
          saved.server.duid_octets <= saved.server.duid.size() &&
          packet::dhcpv6::valid_duid(
              std::span<const std::uint8_t>{saved.server.duid}.first(
                  saved.server.duid_octets));
      if (!configured || !valid_client || !valid_server ||
          ip::is_unspecified(saved.server_address) ||
          ip::is_multicast(saved.server_address) ||
          (ip::is_link_local(saved.server_address) &&
           saved.server_scope_interface_id == 0U) ||
          replacement.lease_count(saved.interface_id) >=
              configured->maximum_leases ||
          saved.prefix_length > 128U ||
          ip::mask(saved.value, saved.prefix_length) != saved.value ||
          saved.valid_remaining_nanoseconds <= 0 ||
          saved.preferred_remaining_nanoseconds < 0 ||
          (saved.preferred_remaining_nanoseconds !=
               std::numeric_limits<std::int64_t>::max() &&
           saved.valid_remaining_nanoseconds !=
               std::numeric_limits<std::int64_t>::max() &&
           saved.preferred_remaining_nanoseconds >
               saved.valid_remaining_nanoseconds) ||
          (saved.has_excluded_prefix &&
           (saved.protocol != RelayLeaseProtocol::delegated_prefix ||
            saved.excluded_prefix_length <= saved.prefix_length ||
            saved.excluded_prefix_length > 128U ||
            ip::mask(saved.excluded_prefix,
                     saved.excluded_prefix_length) !=
                saved.excluded_prefix)) ||
          (!saved.has_excluded_prefix &&
           (saved.excluded_prefix_length != 0U ||
            !ip::is_unspecified(saved.excluded_prefix))))
        return false;
      RelayLeaseRecord lease{
          .client = saved.client,
          .server = saved.server,
          .value = saved.value,
          .peer_address = saved.peer_address,
          .server_address = saved.server_address,
          .client_mac = saved.client_mac,
          .excluded_prefix = saved.excluded_prefix,
          .interface_id = saved.interface_id,
          .server_scope_interface_id = saved.server_scope_interface_id,
          .physical_port_ordinal = saved.physical_port_ordinal,
          .prefix_length = saved.prefix_length,
          .excluded_prefix_length = saved.excluded_prefix_length,
          .protocol = saved.protocol,
          .preferred_until = restore_deadline(
              now, saved.preferred_remaining_nanoseconds),
          .valid_until = restore_deadline(now,
                                          saved.valid_remaining_nanoseconds),
          .has_client_mac = saved.has_client_mac,
          .has_excluded_prefix = saved.has_excluded_prefix};
      if (std::any_of(replacement.leases_.begin(),
                      replacement.leases_.end(), [&](const auto &existing) {
                        return same_lease_key(existing, lease);
                      }))
        return false;
      replacement.leases_.push_back(lease);
    }
  } catch (const std::bad_alloc &) {
    return false;
  }
  *this = std::move(replacement);
  return true;
}

} // namespace router::dhcpv6
