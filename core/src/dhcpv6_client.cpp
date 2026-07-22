// DHCPv6 client state machine and wire-message builder. All timers use the
// host monotonic runtime clock through Retransmission. A packet is rebuilt for
// every transmission so Elapsed Time and remaining lease lifetimes are never
// stale copies of a cached message.

#include "router/dhcpv6_client.hpp"

#include "router/ip_address.hpp"
#include "router/generated_device_catalog.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <utility>

namespace router::dhcpv6 {
namespace {

using packet::dhcpv6::MessageType;
using packet::dhcpv6::OptionCode;

constexpr std::uint16_t code(OptionCode value) noexcept {
  return static_cast<std::uint16_t>(value);
}

constexpr std::uint8_t type(MessageType value) noexcept {
  return static_cast<std::uint8_t>(value);
}

void write16(std::span<std::uint8_t> output, std::size_t offset,
             std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> output, std::size_t offset,
             std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint32_t read32(std::span<const std::uint8_t> input) noexcept {
  return (static_cast<std::uint32_t>(input[0U]) << 24U) |
         (static_cast<std::uint32_t>(input[1U]) << 16U) |
         (static_cast<std::uint32_t>(input[2U]) << 8U) | input[3U];
}

struct ReplyOptions {
  std::span<const std::uint8_t> client{};
  std::span<const std::uint8_t> server{};
  std::span<const std::uint8_t> dns{};
  std::uint16_t top_status{};
  std::uint32_t information_refresh_seconds{
      packet::dhcpv6::information_refresh_default_seconds};
  std::uint32_t solicit_maximum_retransmission_seconds{};
  std::uint32_t information_maximum_retransmission_seconds{};
  std::uint8_t preference{};
  bool have_status{};
  bool have_preference{};
  bool rapid{};
  bool have_information_refresh{};
  bool have_solicit_maximum_retransmission{};
  bool have_information_maximum_retransmission{};
  bool valid{true};
};

ReplyOptions scan_reply(std::span<const std::uint8_t> bytes) noexcept {
  ReplyOptions result;
  packet::dhcpv6::OptionCursor cursor{bytes};
  while (const auto option = cursor.next()) {
    if (option->code == code(OptionCode::client_identifier)) {
      if (!result.client.empty() || !packet::dhcpv6::valid_duid(option->data))
        result.valid = false;
      else
        result.client = option->data;
    } else if (option->code == code(OptionCode::server_identifier)) {
      if (!result.server.empty() || !packet::dhcpv6::valid_duid(option->data))
        result.valid = false;
      else
        result.server = option->data;
    } else if (option->code == code(OptionCode::preference)) {
      if (result.have_preference || option->data.size() != 1U)
        result.valid = false;
      else {
        result.preference = option->data.front();
        result.have_preference = true;
      }
    } else if (option->code == code(OptionCode::rapid_commit)) {
      if (result.rapid || !option->data.empty())
        result.valid = false;
      result.rapid = true;
    } else if (option->code == code(OptionCode::status_code)) {
      const auto status = packet::dhcpv6::parse_status_code(option->data);
      if (result.have_status || !status)
        result.valid = false;
      else {
        result.top_status = status->code;
        result.have_status = true;
      }
    } else if (option->code == code(OptionCode::dns_recursive_name_server)) {
      if (!result.dns.empty() ||
          !packet::dhcpv6::parse_dns_recursive_name_servers(option->data))
        result.valid = false;
      else
        result.dns = option->data;
    } else if (option->code == code(OptionCode::information_refresh_time)) {
      if (result.have_information_refresh || option->data.size() != 4U)
        result.valid = false;
      else {
        result.information_refresh_seconds = read32(option->data);
        result.have_information_refresh = true;
      }
    } else if (option->code ==
               code(OptionCode::solicit_maximum_retransmission_time)) {
      if (result.have_solicit_maximum_retransmission ||
          option->data.size() != 4U)
        result.valid = false;
      else {
        result.solicit_maximum_retransmission_seconds = read32(option->data);
        result.have_solicit_maximum_retransmission = true;
      }
    } else if (option->code ==
               code(OptionCode::information_maximum_retransmission_time)) {
      if (result.have_information_maximum_retransmission ||
          option->data.size() != 4U)
        result.valid = false;
      else {
        result.information_maximum_retransmission_seconds =
            read32(option->data);
        result.have_information_maximum_retransmission = true;
      }
    }
  }
  result.valid = result.valid && cursor.valid();
  return result;
}

bool same_duid(std::span<const std::uint8_t> received,
               std::span<const std::uint8_t> expected) noexcept {
  return received.size() == expected.size() &&
         std::equal(received.begin(), received.end(), expected.begin());
}

std::chrono::seconds remaining(Client::Clock::time_point deadline,
                               Client::Clock::time_point now) noexcept {
  if (deadline == Client::Clock::time_point::max())
    return std::chrono::seconds{
        std::numeric_limits<std::uint32_t>::max()};
  if (deadline <= now)
    return std::chrono::seconds::zero();
  return std::chrono::duration_cast<std::chrono::seconds>(deadline - now);
}

Client::Clock::time_point deadline(Client::Clock::time_point now,
                                   std::uint32_t lifetime) noexcept {
  return lifetime == std::numeric_limits<std::uint32_t>::max()
             ? Client::Clock::time_point::max()
             : now + std::chrono::seconds{lifetime};
}

// Parse every usable resource under every IA. Unknown IA suboptions remain
// ignored, while malformed option framing invalidates the complete response.
bool parse_leases(std::span<const std::uint8_t> options,
                  Client::Clock::time_point now,
                  std::vector<ClientLease> &leases) {
  std::vector<ClientLease> staged;
  packet::dhcpv6::OptionCursor outer{options};
  while (const auto option = outer.next()) {
    const bool na = option->code == code(OptionCode::ia_na);
    const bool pd = option->code == code(OptionCode::ia_pd);
    // IA_TA is obsolete in RFC 9915 section 21.5. An updated client ignores
    // the option instead of turning legacy traffic into a malformed Reply.
    if (!(na || pd))
      continue;
    const auto association = packet::dhcpv6::parse_ia_na_or_pd(option->data);
    if (!association)
      return false;
    const auto iaid = association->iaid;
    const auto t1 = association->t1;
    const auto t2 = association->t2;
    packet::dhcpv6::OptionCursor resources{association->options};
    while (const auto resource = resources.next()) {
      if (!pd && resource->code == code(OptionCode::ia_address)) {
        const auto address = packet::dhcpv6::parse_ia_address(resource->data);
        if (!address ||
            address->preferred_lifetime > address->valid_lifetime ||
            ip::is_unspecified(address->address) ||
            ip::is_multicast(address->address))
          return false;
        if (address->valid_lifetime == 0U)
          continue;
        // Zero T1/T2 are deliberately not converted into an immediate
        // exchange. The release profile owns the fallback percentages so a
        // different platform policy does not leak into this protocol owner.
        const auto renew_seconds =
            t1 != 0U
                ? t1
                : std::max(
                      1U, static_cast<std::uint32_t>(
                              static_cast<std::uint64_t>(
                                  address->preferred_lifetime) *
                              device_catalog::
                                  dhcpv6_zero_t1_percent_of_preferred /
                              100U));
        const auto rebind_seconds =
            t2 != 0U
                ? t2
                : std::max(
                      renew_seconds,
                      static_cast<std::uint32_t>(
                          static_cast<std::uint64_t>(
                              address->preferred_lifetime) *
                          device_catalog::
                              dhcpv6_zero_t2_percent_of_preferred /
                          100U));
        if (renew_seconds > rebind_seconds ||
            rebind_seconds > address->valid_lifetime)
          return false;
        staged.push_back({
            .value = address->address,
            .preferred_until = deadline(now, address->preferred_lifetime),
            .valid_until = deadline(now, address->valid_lifetime),
            // RFC 9915 section 7.7 assigns 0xffffffff the special meaning
            // "infinity". Using the common deadline helper is important here:
            // adding 136 years to steady_clock can overflow on some hosts and
            // would also schedule an exchange that the protocol forbids.
            .renew_at = deadline(now, renew_seconds),
            .rebind_at = deadline(now, rebind_seconds),
            .iaid = iaid,
            .kind = LeaseKind::non_temporary});
      } else if (pd && resource->code == code(OptionCode::ia_prefix)) {
        const auto prefix = packet::dhcpv6::parse_ia_prefix(resource->data);
        if (!prefix || prefix->preferred_lifetime > prefix->valid_lifetime ||
            prefix->prefix_length > 128U ||
            ip::mask(prefix->prefix, prefix->prefix_length) != prefix->prefix)
          return false;
        if (prefix->valid_lifetime == 0U)
          continue;
        const auto renew_seconds =
            t1 != 0U
                ? t1
                : std::max(
                      1U, static_cast<std::uint32_t>(
                              static_cast<std::uint64_t>(
                                  prefix->preferred_lifetime) *
                              device_catalog::
                                  dhcpv6_zero_t1_percent_of_preferred /
                              100U));
        const auto rebind_seconds =
            t2 != 0U
                ? t2
                : std::max(
                      renew_seconds,
                      static_cast<std::uint32_t>(
                          static_cast<std::uint64_t>(
                              prefix->preferred_lifetime) *
                          device_catalog::
                              dhcpv6_zero_t2_percent_of_preferred /
                          100U));
        if (renew_seconds > rebind_seconds ||
            rebind_seconds > prefix->valid_lifetime)
          return false;
        staged.push_back({
            .value = prefix->prefix,
            .preferred_until = deadline(now, prefix->preferred_lifetime),
            .valid_until = deadline(now, prefix->valid_lifetime),
            .renew_at = deadline(now, renew_seconds),
            .rebind_at = deadline(now, rebind_seconds),
            .iaid = iaid,
            .prefix_length = prefix->prefix_length,
            .kind = LeaseKind::prefix});
      }
    }
    if (!resources.valid())
      return false;
  }
  if (!outer.valid())
    return false;
  leases = std::move(staged);
  return true;
}

bool append_nested(std::span<std::uint8_t> output, std::size_t &position,
                   OptionCode option_code,
                   std::span<const std::uint8_t> data) noexcept {
  if (data.size() > std::numeric_limits<std::uint16_t>::max() ||
      output.size() - std::min(output.size(), position) < data.size() + 4U)
    return false;
  write16(output, position, code(option_code));
  write16(output, position + 2U, static_cast<std::uint16_t>(data.size()));
  std::copy(data.begin(), data.end(), output.begin() + position + 4U);
  position += data.size() + 4U;
  return true;
}

std::int64_t relative_deadline(Client::Clock::time_point value,
                               Client::Clock::time_point now) noexcept {
  if (value == Client::Clock::time_point::max())
    return -1;
  if (value <= now)
    return 0;
  return std::chrono::duration_cast<std::chrono::nanoseconds>(value - now)
      .count();
}

Client::Clock::time_point restore_deadline(std::int64_t remaining,
                                           Client::Clock::time_point now) {
  return remaining == -1
             ? Client::Clock::time_point::max()
             : now + std::chrono::nanoseconds{remaining};
}

ClientLeaseCheckpoint save_lease(const ClientLease &lease,
                                 Client::Clock::time_point now) noexcept {
  return {.value = lease.value,
          .preferred_remaining_nanoseconds =
              relative_deadline(lease.preferred_until, now),
          .valid_remaining_nanoseconds =
              relative_deadline(lease.valid_until, now),
          .renew_remaining_nanoseconds =
              relative_deadline(lease.renew_at, now),
          .rebind_remaining_nanoseconds =
              relative_deadline(lease.rebind_at, now),
          .iaid = lease.iaid,
          .prefix_length = lease.prefix_length,
          .kind = lease.kind};
}

ClientLease restore_lease(const ClientLeaseCheckpoint &lease,
                          Client::Clock::time_point now) {
  return {.value = lease.value,
          .preferred_until =
              restore_deadline(lease.preferred_remaining_nanoseconds, now),
          .valid_until =
              restore_deadline(lease.valid_remaining_nanoseconds, now),
          .renew_at =
              restore_deadline(lease.renew_remaining_nanoseconds, now),
          .rebind_at =
              restore_deadline(lease.rebind_remaining_nanoseconds, now),
          .iaid = lease.iaid,
          .prefix_length = lease.prefix_length,
          .kind = lease.kind};
}

bool ordered_remaining(std::int64_t earlier, std::int64_t later) noexcept {
  if (later == -1)
    return true;
  return earlier != -1 && earlier <= later;
}

} // namespace

Client::Client()
    : ia_scratch_(packet::dhcpv6::maximum_message_octets) {}

bool Client::configure(const ClientConfiguration &configuration) {
  if (state_ != ClientState::stopped ||
      configuration.duid_octets > configuration.duid.size() ||
      !packet::dhcpv6::valid_duid(
          std::span<const std::uint8_t>{configuration.duid}.first(
              configuration.duid_octets)) ||
      std::none_of(configuration.transaction_secret.begin(),
                   configuration.transaction_secret.end(),
                   [](std::uint8_t octet) { return octet != 0U; }))
    return false;
  for (std::size_t index = 0;
       index < configuration.identity_associations.size(); ++index) {
    // RFC 9915 obsoletes IA_TA. Rejecting obsolete local intent prevents the
    // client from silently substituting IA_NA under an administrator-visible
    // temporary association. A short-lived IA_NA remains fully supported.
    if (configuration.identity_associations[index].kind ==
        LeaseKind::temporary)
      return false;
    for (std::size_t previous = 0; previous < index; ++previous)
      if (configuration.identity_associations[index].iaid ==
              configuration.identity_associations[previous].iaid &&
          configuration.identity_associations[index].kind ==
              configuration.identity_associations[previous].kind)
        return false;
  }

  ClientConfiguration staged = configuration;
  // SOL_MAX_RT is mandatory in every stateful ORO. Preserve administrator
  // order for other options while removing duplicates that have no semantic
  // value and waste finite wire space.
  // Exchange-control options have message-specific legality. Strip them from
  // administrator interest before constructing separate stateful and
  // Information-request OROs below.
  std::erase_if(staged.requested_options, [](std::uint16_t requested) {
    return requested == code(OptionCode::solicit_maximum_retransmission_time) ||
           requested ==
               code(OptionCode::information_maximum_retransmission_time) ||
           requested == code(OptionCode::information_refresh_time);
  });
  std::vector<std::uint16_t> unique;
  unique.reserve(staged.requested_options.size());
  for (const auto requested : staged.requested_options)
    if (std::find(unique.begin(), unique.end(), requested) == unique.end())
      unique.push_back(requested);
  staged.requested_options = std::move(unique);
  std::vector<std::uint16_t> stateful_options{
      code(OptionCode::solicit_maximum_retransmission_time)};
  stateful_options.insert(stateful_options.end(),
                          staged.requested_options.begin(),
                          staged.requested_options.end());
  std::vector<std::uint16_t> information_options{
      code(OptionCode::information_maximum_retransmission_time),
      code(OptionCode::information_refresh_time)};
  information_options.insert(information_options.end(),
                             staged.requested_options.begin(),
                             staged.requested_options.end());
  std::vector<std::uint8_t> oro(stateful_options.size() * 2U);
  for (std::size_t index = 0; index < stateful_options.size(); ++index)
    write16(oro, index * 2U, stateful_options[index]);
  std::vector<std::uint8_t> information_oro(information_options.size() * 2U);
  for (std::size_t index = 0; index < information_options.size(); ++index)
    write16(information_oro, index * 2U, information_options[index]);
  configuration_ = std::move(staged);
  oro_bytes_ = std::move(oro);
  information_oro_bytes_ = std::move(information_oro);
  return true;
}

bool Client::start(std::uint32_t transaction_id, std::uint32_t seed,
                   Clock::time_point now) noexcept {
  if (state_ != ClientState::stopped || transaction_id > 0xffffffU ||
      seed == 0U || configuration_.duid_octets == 0U ||
      configuration_.identity_associations.empty())
    return false;
  random_state_ = seed;
  leases_.clear();
  dns_servers_.clear();
  offer_ = {};
  server_octets_ = 0U;
  if (!retransmission_.begin(
          ExchangeKind::solicit, transaction_id, seed, now,
          std::chrono::seconds{solicit_maximum_retransmission_seconds_}))
    return false;
  advertise_solicit_maximum_seconds_ = 0U;
  advertise_information_maximum_seconds_ = 0U;
  advertise_solicit_maximum_seen_ = false;
  advertise_solicit_maximum_conflict_ = false;
  advertise_information_maximum_seen_ = false;
  advertise_information_maximum_conflict_ = false;
  state_ = ClientState::soliciting;
  return true;
}

bool Client::start(Clock::time_point now) noexcept {
  if (state_ != ClientState::stopped || configuration_.duid_octets == 0U ||
      configuration_.identity_associations.empty())
    return false;
  leases_.clear();
  dns_servers_.clear();
  offer_ = {};
  server_octets_ = 0U;
  return begin_exchange(ExchangeKind::solicit, ClientState::soliciting, now);
}

bool Client::start_information_request(std::uint32_t transaction_id,
                                       std::uint32_t seed,
                                       Clock::time_point now) noexcept {
  if (state_ != ClientState::stopped || transaction_id > 0xffffffU ||
      seed == 0U || configuration_.duid_octets == 0U)
    return false;
  random_state_ = seed;
  leases_.clear();
  dns_servers_.clear();
  offer_ = {};
  server_octets_ = 0U;
  if (!retransmission_.begin(
          ExchangeKind::information_request, transaction_id, seed, now,
          std::chrono::seconds{
              information_maximum_retransmission_seconds_}))
    return false;
  state_ = ClientState::information_requesting;
  return true;
}

bool Client::start_information_request(Clock::time_point now) noexcept {
  if (state_ != ClientState::stopped || configuration_.duid_octets == 0U)
    return false;
  leases_.clear();
  dns_servers_.clear();
  offer_ = {};
  server_octets_ = 0U;
  return begin_exchange(ExchangeKind::information_request,
                        ClientState::information_requesting, now);
}

std::optional<Client::Clock::time_point> Client::next_deadline() const noexcept {
  if (state_ == ClientState::information_bound)
    return information_refresh_at_ == Clock::time_point::max()
               ? std::nullopt
               : std::optional{information_refresh_at_};
  if (state_ == ClientState::bound && !leases_.empty()) {
    auto result = Clock::time_point::max();
    for (const auto &lease : leases_)
      result = std::min(result, std::min(lease.renew_at, lease.rebind_at));
    return result == Clock::time_point::max() ? std::nullopt
                                              : std::optional{result};
  }
  return retransmission_.next_deadline();
}

bool Client::start_confirm(Clock::time_point now) {
  if (state_ != ClientState::bound || leases_.empty() ||
      std::any_of(leases_.begin(), leases_.end(), [](const ClientLease &lease) {
        return lease.kind == LeaseKind::prefix;
      }))
    return false;
  operation_leases_ = leases_;
  confirm_not_on_link_received_ = false;
  if (!begin_exchange(ExchangeKind::confirm, ClientState::confirming, now)) {
    operation_leases_.clear();
    return false;
  }
  return true;
}

bool Client::start_release(std::span<const packet::Ipv6> values,
                           Clock::time_point now) {
  if (state_ != ClientState::bound || values.empty() || server_octets_ == 0U)
    return false;

  // Stage both vectors before changing protocol state. Allocation failure can
  // then propagate to the control owner without partially removing an address
  // from the live interface state.
  std::vector<ClientLease> selected;
  std::vector<ClientLease> retained;
  selected.reserve(values.size());
  retained.reserve(leases_.size());
  for (const auto &lease : leases_) {
    const auto matches = std::count(values.begin(), values.end(), lease.value);
    if (matches > 1)
      return false;
    (matches == 1 ? selected : retained).push_back(lease);
  }
  if (selected.size() != values.size())
    return false;
  if (!begin_exchange(ExchangeKind::release, ClientState::releasing, now))
    return false;
  operation_leases_ = std::move(selected);
  leases_ = std::move(retained);
  return true;
}

bool Client::start_decline(std::span<const packet::Ipv6> addresses,
                           Clock::time_point now) {
  if (state_ != ClientState::bound || addresses.empty() ||
      server_octets_ == 0U)
    return false;

  std::vector<ClientLease> selected;
  std::vector<ClientLease> retained;
  selected.reserve(addresses.size());
  retained.reserve(leases_.size());
  for (const auto &lease : leases_) {
    const auto matches =
        std::count(addresses.begin(), addresses.end(), lease.value);
    if (matches > 1 || (matches == 1 && lease.kind == LeaseKind::prefix))
      return false;
    (matches == 1 ? selected : retained).push_back(lease);
  }
  if (selected.size() != addresses.size())
    return false;
  if (!begin_exchange(ExchangeKind::decline, ClientState::declining, now))
    return false;
  operation_leases_ = std::move(selected);
  leases_ = std::move(retained);
  return true;
}

void Client::stop() noexcept {
  retransmission_.complete();
  offer_ = {};
  leases_.clear();
  operation_leases_.clear();
  dns_servers_.clear();
  server_octets_ = 0U;
  information_refresh_at_ = {};
  confirm_not_on_link_received_ = false;
  state_ = ClientState::stopped;
}

std::uint32_t Client::next_transaction_id() noexcept {
  std::array<std::uint8_t, 8U> counter{};
  const auto value_counter = ++transaction_counter_;
  for (std::size_t index = 0; index < counter.size(); ++index)
    counter[index] = static_cast<std::uint8_t>(
        value_counter >> ((counter.size() - 1U - index) * 8U));
  const std::array<std::span<const std::uint8_t>, 1U> message{counter};
  const auto digest = crypto::hmac_sha256(
      configuration_.transaction_secret, message);
  const auto value = (static_cast<std::uint32_t>(digest[0U]) << 16U) |
                     (static_cast<std::uint32_t>(digest[1U]) << 8U) |
                     static_cast<std::uint32_t>(digest[2U]);
  // Jitter uses a separate slice of the digest. It does not need a
  // cryptographic generator, but each exchange should see a distinct stream.
  random_state_ = (static_cast<std::uint32_t>(digest[3U]) << 24U) |
                  (static_cast<std::uint32_t>(digest[4U]) << 16U) |
                  (static_cast<std::uint32_t>(digest[5U]) << 8U) |
                  static_cast<std::uint32_t>(digest[6U]);
  if (random_state_ == 0U)
    random_state_ = 1U;
  return value == 0U ? 1U : value;
}

bool Client::begin_exchange(ExchangeKind kind, ClientState state,
                            Clock::time_point now) noexcept {
  const auto transaction = next_transaction_id();
  const auto maximum =
      kind == ExchangeKind::solicit
          ? std::chrono::seconds{solicit_maximum_retransmission_seconds_}
      : kind == ExchangeKind::information_request
          ? std::chrono::seconds{
                information_maximum_retransmission_seconds_}
          : std::chrono::seconds::zero();
  if (!retransmission_.begin(kind, transaction, random_state_, now, maximum))
    return false;
  if (kind == ExchangeKind::solicit) {
    // Each discovery process builds a new agreement set. Interface-scoped
    // values retained from an earlier exchange remain active until a valid new
    // Advertise supplies a value or conflicting servers require the default.
    advertise_solicit_maximum_seconds_ = 0U;
    advertise_information_maximum_seconds_ = 0U;
    advertise_solicit_maximum_seen_ = false;
    advertise_solicit_maximum_conflict_ = false;
    advertise_information_maximum_seen_ = false;
    advertise_information_maximum_conflict_ = false;
  }
  state_ = state;
  return true;
}

std::uint64_t Client::rate_tokens_at(Clock::time_point now) const noexcept {
  constexpr auto capacity =
      static_cast<std::uint64_t>(
          device_catalog::dhcpv6_client_rate_limit_packets);
  constexpr auto interval = std::chrono::duration_cast<
      std::chrono::nanoseconds>(std::chrono::seconds{
      device_catalog::dhcpv6_client_rate_limit_interval_seconds});
  constexpr auto clock_interval =
      std::chrono::duration_cast<Clock::duration>(interval);
  constexpr auto full = capacity * static_cast<std::uint64_t>(interval.count());
  if (!rate_limit_initialized_)
    return full;
  const auto elapsed = now > rate_limit_refilled_at_
                           ? std::min(now - rate_limit_refilled_at_,
                                      clock_interval)
                           : Clock::duration::zero();
  const auto elapsed_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
  return std::min(full, rate_limit_tokens_scaled_ +
                            static_cast<std::uint64_t>(elapsed_nanoseconds) *
                                capacity);
}

bool Client::consume_rate_token(Clock::time_point now) noexcept {
  constexpr auto interval = std::chrono::duration_cast<
      std::chrono::nanoseconds>(std::chrono::seconds{
      device_catalog::dhcpv6_client_rate_limit_interval_seconds});
  const auto available = rate_tokens_at(now);
  if (available < static_cast<std::uint64_t>(interval.count()))
    return false;
  rate_limit_tokens_scaled_ =
      available - static_cast<std::uint64_t>(interval.count());
  rate_limit_refilled_at_ = now;
  rate_limit_initialized_ = true;
  return true;
}

bool Client::select_offer(Clock::time_point now) noexcept {
  if (!offer_.present)
    return false;
  std::copy_n(offer_.server.begin(), offer_.server_octets, server_.begin());
  server_octets_ = offer_.server_octets;
  return begin_exchange(ExchangeKind::request, ClientState::requesting, now);
}

ClientPollResult Client::poll(std::span<std::uint8_t> output,
                              Clock::time_point now) noexcept {
  output = output.first(
      std::min(output.size(), packet::dhcpv6::maximum_message_octets));
  if (state_ == ClientState::stopped || state_ == ClientState::failed)
    return {.status = ClientPollStatus::idle};

  leases_.erase(std::remove_if(leases_.begin(), leases_.end(),
                               [&](const ClientLease &lease) {
                                 return lease.valid_until <= now;
                               }),
                leases_.end());
  if (state_ == ClientState::information_bound) {
    if (information_refresh_at_ == Clock::time_point::max() ||
        information_refresh_at_ > now)
      return {.status = ClientPollStatus::idle};
    if (!begin_exchange(ExchangeKind::information_request,
                        ClientState::information_requesting, now))
      return {.status = ClientPollStatus::failed};
  }
  if (state_ == ClientState::bound) {
    if (leases_.empty()) {
      offer_ = {};
      if (!begin_exchange(ExchangeKind::solicit, ClientState::soliciting,
                          now))
        return {.status = ClientPollStatus::failed};
    } else {
      const auto earliest_renew =
          std::min_element(leases_.begin(), leases_.end(),
                           [](const auto &left, const auto &right) {
                             return left.renew_at < right.renew_at;
                           });
      const auto earliest_rebind =
          std::min_element(leases_.begin(), leases_.end(),
                           [](const auto &left, const auto &right) {
                             return left.rebind_at < right.rebind_at;
                           });
      if (earliest_rebind->rebind_at <= now) {
        if (!begin_exchange(ExchangeKind::rebind, ClientState::rebinding, now))
          return {.status = ClientPollStatus::failed};
      } else if (earliest_renew->renew_at <= now) {
        if (!begin_exchange(ExchangeKind::renew, ClientState::renewing, now))
          return {.status = ClientPollStatus::failed};
      } else {
        return {.status = ClientPollStatus::idle};
      }
    }
  }

  // Preference 255 selects immediately. Lower preferences remain collected
  // until the first Solicit RT expires, at which point poll would otherwise
  // schedule the second Solicit transmission.
  if (state_ == ClientState::soliciting && offer_.present &&
      offer_.preference == 255U && !select_offer(now))
    return {.status = ClientPollStatus::failed};

  // Reliability timers decide when a message is due. The independent token
  // bucket decides whether it may actually enter UDP now. An overdue exchange
  // remains due and is retried as soon as a token refills.
  const auto due = retransmission_.next_deadline();
  if (due && *due <= now && !consume_rate_token(now))
    return {.status = ClientPollStatus::idle};
  auto action = retransmission_.poll(now);
  if (state_ == ClientState::soliciting && offer_.present &&
      action == ExchangeAction::transmit && retransmission_.transmissions() > 1U) {
    if (!select_offer(now))
      return {.status = ClientPollStatus::failed};
    action = retransmission_.poll(now);
  }
  if (state_ == ClientState::renewing && !leases_.empty()) {
    const auto earliest_rebind =
        std::min_element(leases_.begin(), leases_.end(),
                         [](const auto &left, const auto &right) {
                           return left.rebind_at < right.rebind_at;
                         });
    if (earliest_rebind->rebind_at <= now) {
      if (!begin_exchange(ExchangeKind::rebind, ClientState::rebinding, now))
        return {.status = ClientPollStatus::failed};
      action = retransmission_.poll(now);
    }
  }
  if (action == ExchangeAction::none)
    return {.status = ClientPollStatus::idle};
  if (action == ExchangeAction::failed) {
    // Confirm timeout is not loss of the binding. Release and Decline are
    // locally complete after their bounded retry count because the addresses
    // were already removed before transmission. Only ordinary configuration
    // exchanges surface a terminal failure.
    if (state_ == ClientState::confirming) {
      operation_leases_.clear();
      if (confirm_not_on_link_received_) {
        leases_.clear();
        offer_ = {};
        if (!begin_exchange(ExchangeKind::solicit, ClientState::soliciting,
                            now))
          return {.status = ClientPollStatus::failed};
      } else {
        state_ = ClientState::bound;
      }
      confirm_not_on_link_received_ = false;
      return {.status = ClientPollStatus::idle};
    }
    if (state_ == ClientState::releasing) {
      operation_leases_.clear();
      state_ = leases_.empty() ? ClientState::stopped : ClientState::bound;
      return {.status = ClientPollStatus::idle};
    }
    if (state_ == ClientState::declining) {
      operation_leases_.clear();
      offer_ = {};
      if (!begin_exchange(ExchangeKind::solicit, ClientState::soliciting,
                          now))
        return {.status = ClientPollStatus::failed};
      return {.status = ClientPollStatus::idle};
    }
    state_ = ClientState::failed;
    return {.status = ClientPollStatus::failed};
  }
  return build(output, now);
}

ClientPollResult Client::build(std::span<std::uint8_t> output,
                               Clock::time_point now) noexcept {
  MessageType message_type;
  switch (state_) {
  case ClientState::soliciting:
    message_type = MessageType::solicit;
    break;
  case ClientState::requesting:
    message_type = MessageType::request;
    break;
  case ClientState::renewing:
    message_type = MessageType::renew;
    break;
  case ClientState::rebinding:
    message_type = MessageType::rebind;
    break;
  case ClientState::confirming:
    message_type = MessageType::confirm;
    break;
  case ClientState::releasing:
    message_type = MessageType::release;
    break;
  case ClientState::declining:
    message_type = MessageType::decline;
    break;
  case ClientState::information_requesting:
    message_type = MessageType::information_request;
    break;
  default:
    return {.status = ClientPollStatus::idle};
  }
  auto writer = packet::dhcpv6::begin_client_server(
      output, type(message_type), retransmission_.transaction_id());
  if (!writer)
    return {.status = ClientPollStatus::output_too_small};
  const auto client_duid =
      std::span<const std::uint8_t>{configuration_.duid}.first(
          configuration_.duid_octets);
  if (!writer->append(code(OptionCode::client_identifier), client_duid) ||
      ((state_ == ClientState::requesting ||
        state_ == ClientState::renewing ||
        state_ == ClientState::releasing ||
        state_ == ClientState::declining) &&
       !writer->append(
           code(OptionCode::server_identifier),
           std::span<const std::uint8_t>{server_}.first(server_octets_))))
    return {.status = ClientPollStatus::output_too_small};
  const auto elapsed = retransmission_.elapsed_centiseconds(now);
  const std::array<std::uint8_t, 2U> elapsed_bytes{
      static_cast<std::uint8_t>(elapsed >> 8U),
      static_cast<std::uint8_t>(elapsed)};
  if (!writer->append(code(OptionCode::elapsed_time), elapsed_bytes))
    return {.status = ClientPollStatus::output_too_small};

  const bool information = state_ == ClientState::information_requesting;
  const bool requests_options =
      information || state_ == ClientState::soliciting ||
      state_ == ClientState::requesting || state_ == ClientState::renewing ||
      state_ == ClientState::rebinding;
  const auto &oro = information ? information_oro_bytes_ : oro_bytes_;
  if ((requests_options &&
       !writer->append(code(OptionCode::option_request), oro)) ||
      (state_ == ClientState::soliciting && configuration_.rapid_commit &&
       !writer->append(code(OptionCode::rapid_commit), {})))
    return {.status = ClientPollStatus::output_too_small};

  if (information)
    return {.status = ClientPollStatus::transmit,
            .message_octets = writer->size()};

  const bool operation = state_ == ClientState::confirming ||
                         state_ == ClientState::releasing ||
                         state_ == ClientState::declining;
  const auto *hints = operation ? &operation_leases_
                      : state_ == ClientState::requesting ? &offer_.leases
                                                          : &leases_;
  for (const auto &requested : configuration_.identity_associations) {
    if (operation &&
        std::none_of(hints->begin(), hints->end(), [&](const auto &lease) {
          return lease.iaid == requested.iaid &&
                 lease.kind == requested.kind;
        }))
      continue;
    constexpr std::size_t header = 12U;
    if (ia_scratch_.size() < header)
      return {.status = ClientPollStatus::output_too_small};
    std::fill_n(ia_scratch_.begin(), header, std::uint8_t{0});
    write32(ia_scratch_, 0U, requested.iaid);
    std::size_t position = header;
    if (state_ != ClientState::soliciting) {
      for (const auto &lease : *hints) {
        if (lease.iaid != requested.iaid || lease.kind != requested.kind ||
            lease.valid_until <= now)
          continue;
        std::array<std::uint8_t, 32U> resource{};
        std::optional<std::size_t> encoded;
        OptionCode resource_code;
        // Confirm fields are explicitly zero because a server ignores their
        // old values. Release and Decline retain remaining values, preserving
        // the exact lease description while the server keys on the IA value.
        const auto preferred = state_ == ClientState::confirming
                                   ? 0
                                   : remaining(lease.preferred_until, now)
                                         .count();
        const auto valid = state_ == ClientState::confirming
                               ? 0
                               : remaining(lease.valid_until, now).count();
        if (requested.kind == LeaseKind::prefix) {
          resource_code = OptionCode::ia_prefix;
          encoded = packet::dhcpv6::encode_ia_prefix(
              resource, lease.value, lease.prefix_length,
              static_cast<std::uint32_t>(preferred),
              static_cast<std::uint32_t>(valid));
        } else {
          resource_code = OptionCode::ia_address;
          encoded = packet::dhcpv6::encode_ia_address(
              resource, lease.value, static_cast<std::uint32_t>(preferred),
              static_cast<std::uint32_t>(valid));
        }
        if (!encoded ||
            !append_nested(ia_scratch_, position, resource_code,
                           std::span<const std::uint8_t>{resource}.first(
                               *encoded)))
          return {.status = ClientPollStatus::output_too_small};
      }
    }
    const auto ia_code = requested.kind == LeaseKind::prefix
                             ? OptionCode::ia_pd
                             : OptionCode::ia_na;
    if (!writer->append(code(ia_code),
                        std::span<const std::uint8_t>{ia_scratch_}.first(
                            position)))
      return {.status = ClientPollStatus::output_too_small};
  }
  return {.status = ClientPollStatus::transmit,
          .message_octets = writer->size()};
}

ClientIngestStatus Client::ingest(std::span<const std::uint8_t> input,
                                  Clock::time_point now) noexcept {
  const auto message = packet::dhcpv6::parse(input);
  if (!message || message->relay)
    return ClientIngestStatus::malformed;
  if (!retransmission_.active() ||
      message->transaction_id != retransmission_.transaction_id())
    return ClientIngestStatus::transaction_mismatch;
  const auto options = scan_reply(message->options);
  if (!options.valid || options.server.empty())
    return ClientIngestStatus::malformed;
  const auto client_duid =
      std::span<const std::uint8_t>{configuration_.duid}.first(
          configuration_.duid_octets);
  if (options.client.empty() || !same_duid(options.client, client_duid))
    return ClientIngestStatus::identity_mismatch;

  try {
    std::vector<ClientLease> received;
    if (!parse_leases(message->options, now, received))
      return ClientIngestStatus::malformed;
    // A server may omit requested IAs, but it cannot cause the client to
    // create an unrequested IA owner. Accepting one would bypass persistent
    // interface intent and make subsequent Renew messages ambiguous.
    if (std::any_of(received.begin(), received.end(), [&](const auto &lease) {
          return std::none_of(
              configuration_.identity_associations.begin(),
              configuration_.identity_associations.end(),
              [&](const auto &requested) {
                return requested.iaid == lease.iaid &&
                       requested.kind == lease.kind;
              });
        }))
      return ClientIngestStatus::malformed;
    // Options 82 and 83 are interface-scoped control data. Values outside the
    // normative one-minute to one-day domain are ignored without invalidating
    // the rest of an otherwise valid message.
    const auto valid_maximum = [](std::uint32_t value) noexcept {
      return value >=
                 packet::dhcpv6::maximum_retransmission_minimum_seconds &&
             value <= packet::dhcpv6::maximum_retransmission_limit_seconds;
    };
    const auto apply_solicit_maximum = [&](std::uint32_t value) {
      solicit_maximum_retransmission_seconds_ = value;
      if (state_ == ClientState::soliciting)
        retransmission_.set_maximum_retransmission_time(
            std::chrono::seconds{value});
    };
    const auto apply_information_maximum = [&](std::uint32_t value) {
      information_maximum_retransmission_seconds_ = value;
      if (state_ == ClientState::information_requesting)
        retransmission_.set_maximum_retransmission_time(
            std::chrono::seconds{value});
    };
    const auto advertise_consensus = [&](bool supplied, std::uint32_t value,
                                         bool &seen, bool &conflict,
                                         std::uint32_t &candidate,
                                         const auto &apply) {
      if (!supplied || !valid_maximum(value))
        return;
      if (!seen) {
        seen = true;
        candidate = value;
        apply(value);
        return;
      }
      if (candidate != value)
        conflict = true;
      // Once any two servers disagree, later agreement cannot erase the
      // conflict. RFC 9915 section 18.2.9 recommends the default for the whole
      // received Advertise set, not whichever message arrived last.
      apply(conflict
                ? packet::dhcpv6::maximum_retransmission_default_seconds
                : candidate);
    };
    if (message->type == type(MessageType::advertise) &&
        state_ == ClientState::soliciting) {
      advertise_consensus(
          options.have_solicit_maximum_retransmission,
          options.solicit_maximum_retransmission_seconds,
          advertise_solicit_maximum_seen_,
          advertise_solicit_maximum_conflict_,
          advertise_solicit_maximum_seconds_, apply_solicit_maximum);
      advertise_consensus(
          options.have_information_maximum_retransmission,
          options.information_maximum_retransmission_seconds,
          advertise_information_maximum_seen_,
          advertise_information_maximum_conflict_,
          advertise_information_maximum_seconds_, apply_information_maximum);
      // Advertise without a usable resource is ignored only after its valid
      // retransmission-limit options have participated in interface consensus.
      if (received.empty())
        return ClientIngestStatus::ignored;
      if (!offer_.present || options.preference > offer_.preference) {
        std::copy(options.server.begin(), options.server.end(),
                  offer_.server.begin());
        offer_.server_octets =
            static_cast<std::uint16_t>(options.server.size());
        offer_.preference = options.preference;
        offer_.leases = std::move(received);
        offer_.present = true;
      }
      return ClientIngestStatus::accepted;
    }
    if (message->type != type(MessageType::reply))
      return ClientIngestStatus::ignored;
    const bool rapid_reply = state_ == ClientState::soliciting &&
                             configuration_.rapid_commit && options.rapid;
    if (!(rapid_reply || state_ == ClientState::requesting ||
          state_ == ClientState::renewing ||
          state_ == ClientState::rebinding ||
          state_ == ClientState::confirming ||
          state_ == ClientState::releasing ||
          state_ == ClientState::declining ||
          state_ == ClientState::information_requesting))
      return ClientIngestStatus::ignored;
    if (!rapid_reply && state_ != ClientState::rebinding &&
        state_ != ClientState::confirming &&
        state_ != ClientState::information_requesting &&
        !same_duid(options.server,
                   std::span<const std::uint8_t>{server_}.first(
                       server_octets_)))
      return ClientIngestStatus::identity_mismatch;
    // Reply does not participate in the multi-server Advertise consensus.
    // RFC 9915 sections 18.2.10 and 21.24 through 21.25 require each valid
    // Reply override to take effect immediately.
    if (options.have_solicit_maximum_retransmission &&
        valid_maximum(options.solicit_maximum_retransmission_seconds))
      apply_solicit_maximum(
          options.solicit_maximum_retransmission_seconds);
    if (options.have_information_maximum_retransmission &&
        valid_maximum(options.information_maximum_retransmission_seconds))
      apply_information_maximum(
          options.information_maximum_retransmission_seconds);
    if (state_ == ClientState::confirming) {
      // RFC 9915 section 18.2.10.3 lets any Success win over a previously
      // observed NotOnLink. Therefore NotOnLink is remembered until CNF_MAX_RD
      // rather than immediately destroying addresses that another server can
      // still confirm on this link.
      constexpr std::uint16_t success_status = 0U;
      constexpr std::uint16_t not_on_link_status = 4U;
      if (!options.have_status || options.top_status == success_status) {
        retransmission_.complete();
        operation_leases_.clear();
        confirm_not_on_link_received_ = false;
        state_ = ClientState::bound;
        return ClientIngestStatus::accepted;
      }
      if (options.top_status == not_on_link_status) {
        confirm_not_on_link_received_ = true;
        return ClientIngestStatus::accepted;
      }
      return ClientIngestStatus::ignored;
    }
    if (state_ == ClientState::releasing ||
        state_ == ClientState::declining) {
      // A syntactically and identity-valid Reply completes either operation
      // regardless of Status Code, including NoBinding after a lost first
      // Reply. The client had already stopped using these leases.
      const bool declined = state_ == ClientState::declining;
      retransmission_.complete();
      operation_leases_.clear();
      if (declined) {
        offer_ = {};
        if (!begin_exchange(ExchangeKind::solicit, ClientState::soliciting,
                            now)) {
          state_ = ClientState::failed;
          return ClientIngestStatus::ignored;
        }
      } else {
        state_ = leases_.empty() ? ClientState::stopped : ClientState::bound;
      }
      return ClientIngestStatus::accepted;
    }
    if (options.have_status && options.top_status != 0U)
      return ClientIngestStatus::ignored;
    if (state_ != ClientState::information_requesting && received.empty())
      return ClientIngestStatus::ignored;

    std::vector<packet::Ipv6> dns;
    if (!options.dns.empty()) {
      const auto sequence =
          packet::dhcpv6::parse_dns_recursive_name_servers(options.dns);
      if (!sequence)
        return ClientIngestStatus::malformed;
      dns.reserve(sequence->size());
      for (std::size_t index = 0; index < sequence->size(); ++index)
        dns.push_back((*sequence)[index]);
    }
    std::copy(options.server.begin(), options.server.end(), server_.begin());
    server_octets_ = static_cast<std::uint16_t>(options.server.size());
    if (state_ == ClientState::information_requesting) {
      const auto refresh = std::max(
          options.information_refresh_seconds,
          packet::dhcpv6::information_refresh_minimum_seconds);
      information_refresh_at_ = deadline(now, refresh);
      leases_.clear();
      state_ = ClientState::information_bound;
    } else {
      leases_ = std::move(received);
      information_refresh_at_ = {};
      state_ = ClientState::bound;
    }
    dns_servers_ = std::move(dns);
    retransmission_.complete();
    offer_ = {};
    return ClientIngestStatus::accepted;
  } catch (...) {
    // Ingest is on a packet owner and cannot let allocation failure unwind
    // across the shard boundary. Existing client state remains unchanged.
    return ClientIngestStatus::ignored;
  }
}

ClientCheckpoint Client::checkpoint(Clock::time_point now) const {
  ClientCheckpoint saved{.configuration = configuration_,
                         .retransmission = retransmission_.checkpoint(now),
                         .offer = {},
                         .leases = {},
                         .operation_leases = {},
                         .dns_servers = dns_servers_,
                         .server = server_,
                         .server_octets = server_octets_,
                         .random_state = random_state_,
                         .transaction_counter = transaction_counter_,
                         .solicit_maximum_retransmission_seconds =
                             solicit_maximum_retransmission_seconds_,
                         .information_maximum_retransmission_seconds =
                             information_maximum_retransmission_seconds_,
                         .advertise_solicit_maximum_seconds =
                             advertise_solicit_maximum_seconds_,
                         .advertise_information_maximum_seconds =
                             advertise_information_maximum_seconds_,
                         .rate_limit_tokens_scaled = rate_tokens_at(now),
                         .information_refresh_remaining_nanoseconds =
                             relative_deadline(information_refresh_at_, now),
                         .state = state_,
                         .confirm_not_on_link_received =
                             confirm_not_on_link_received_,
                         .rate_limit_initialized = rate_limit_initialized_,
                         .advertise_solicit_maximum_seen =
                             advertise_solicit_maximum_seen_,
                         .advertise_solicit_maximum_conflict =
                             advertise_solicit_maximum_conflict_,
                         .advertise_information_maximum_seen =
                             advertise_information_maximum_seen_,
                         .advertise_information_maximum_conflict =
                             advertise_information_maximum_conflict_};
  saved.leases.reserve(leases_.size());
  for (const auto &lease : leases_)
    saved.leases.push_back(save_lease(lease, now));
  saved.operation_leases.reserve(operation_leases_.size());
  for (const auto &lease : operation_leases_)
    saved.operation_leases.push_back(save_lease(lease, now));
  saved.offer.server = offer_.server;
  saved.offer.server_octets = offer_.server_octets;
  saved.offer.preference = offer_.preference;
  saved.offer.present = offer_.present;
  saved.offer.leases.reserve(offer_.leases.size());
  for (const auto &lease : offer_.leases)
    saved.offer.leases.push_back(save_lease(lease, now));
  return saved;
}

bool Client::validate_checkpoint(const ClientCheckpoint &saved) {
  Client configuration_validator;
  if (!configuration_validator.configure(saved.configuration) ||
      !Retransmission::validate_checkpoint(saved.retransmission) ||
      saved.server_octets > saved.server.size() ||
      saved.offer.server_octets > saved.offer.server.size())
    return false;
  const bool exchanging = saved.state == ClientState::soliciting ||
                          saved.state == ClientState::requesting ||
                          saved.state == ClientState::renewing ||
                          saved.state == ClientState::rebinding ||
                          saved.state == ClientState::confirming ||
                          saved.state == ClientState::releasing ||
                          saved.state == ClientState::declining ||
                          saved.state == ClientState::information_requesting;
  const bool lease_operation = saved.state == ClientState::confirming ||
                               saved.state == ClientState::releasing ||
                               saved.state == ClientState::declining;
  const auto valid_maximum = [](std::uint32_t value) noexcept {
    return value >=
               packet::dhcpv6::maximum_retransmission_minimum_seconds &&
           value <= packet::dhcpv6::maximum_retransmission_limit_seconds;
  };
  constexpr auto rate_interval = std::chrono::duration_cast<
      std::chrono::nanoseconds>(std::chrono::seconds{
      device_catalog::dhcpv6_client_rate_limit_interval_seconds});
  constexpr auto maximum_rate_tokens =
      static_cast<std::uint64_t>(
          device_catalog::dhcpv6_client_rate_limit_packets) *
      static_cast<std::uint64_t>(rate_interval.count());
  if (!valid_maximum(saved.solicit_maximum_retransmission_seconds) ||
      !valid_maximum(saved.information_maximum_retransmission_seconds) ||
      (saved.advertise_solicit_maximum_seen !=
       (saved.advertise_solicit_maximum_seconds != 0U)) ||
      (saved.advertise_information_maximum_seen !=
       (saved.advertise_information_maximum_seconds != 0U)) ||
      (saved.advertise_solicit_maximum_seen &&
       !valid_maximum(saved.advertise_solicit_maximum_seconds)) ||
      (saved.advertise_information_maximum_seen &&
       !valid_maximum(saved.advertise_information_maximum_seconds)) ||
      (saved.advertise_solicit_maximum_conflict &&
       !saved.advertise_solicit_maximum_seen) ||
      (saved.advertise_information_maximum_conflict &&
       !saved.advertise_information_maximum_seen) ||
      saved.rate_limit_tokens_scaled > maximum_rate_tokens ||
      (!saved.rate_limit_initialized &&
       saved.rate_limit_tokens_scaled != maximum_rate_tokens) ||
      saved.retransmission.active != exchanging ||
      (saved.state != ClientState::stopped && saved.random_state == 0U) ||
      (saved.offer.present && saved.state != ClientState::soliciting) ||
      (!saved.offer.present && !saved.offer.leases.empty()) ||
      ((saved.state == ClientState::requesting ||
        saved.state == ClientState::bound ||
        saved.state == ClientState::renewing ||
        saved.state == ClientState::rebinding ||
        saved.state == ClientState::releasing ||
        saved.state == ClientState::declining) &&
       (saved.server_octets == 0U ||
        !packet::dhcpv6::valid_duid(
            std::span<const std::uint8_t>{saved.server}.first(
                saved.server_octets)))) ||
      (saved.state == ClientState::information_bound &&
       saved.information_refresh_remaining_nanoseconds < -1) ||
      (saved.state != ClientState::information_bound &&
       saved.information_refresh_remaining_nanoseconds != 0) ||
      (saved.offer.present &&
       (saved.offer.server_octets == 0U ||
        !packet::dhcpv6::valid_duid(
            std::span<const std::uint8_t>{saved.offer.server}.first(
                saved.offer.server_octets)))) ||
      (lease_operation != !saved.operation_leases.empty()) ||
      (!lease_operation && saved.confirm_not_on_link_received) ||
      (saved.confirm_not_on_link_received &&
       saved.state != ClientState::confirming))
    return false;

  const auto valid_lease = [&](const ClientLeaseCheckpoint &lease) {
    const bool requested = std::any_of(
        saved.configuration.identity_associations.begin(),
        saved.configuration.identity_associations.end(),
        [&](const auto &association) {
          return association.iaid == lease.iaid &&
                 association.kind == lease.kind;
        });
    const bool value =
        lease.kind == LeaseKind::prefix
            ? lease.prefix_length <= 128U &&
                  ip::mask(lease.value, lease.prefix_length) == lease.value
            : lease.prefix_length == 128U &&
                  !ip::is_unspecified(lease.value) &&
                  !ip::is_multicast(lease.value);
    const bool deadlines =
        lease.preferred_remaining_nanoseconds >= -1 &&
        lease.valid_remaining_nanoseconds >= -1 &&
        lease.renew_remaining_nanoseconds >= -1 &&
        lease.rebind_remaining_nanoseconds >= -1 &&
        lease.valid_remaining_nanoseconds != 0 &&
        ordered_remaining(lease.preferred_remaining_nanoseconds,
                          lease.valid_remaining_nanoseconds) &&
        ordered_remaining(lease.renew_remaining_nanoseconds,
                          lease.rebind_remaining_nanoseconds) &&
        ordered_remaining(lease.rebind_remaining_nanoseconds,
                          lease.valid_remaining_nanoseconds);
    return requested && value && deadlines;
  };
  if (!std::all_of(saved.leases.begin(), saved.leases.end(), valid_lease) ||
      !std::all_of(saved.offer.leases.begin(), saved.offer.leases.end(),
                   valid_lease) ||
      !std::all_of(saved.operation_leases.begin(),
                   saved.operation_leases.end(), valid_lease) ||
      (saved.offer.present && saved.offer.leases.empty()) ||
      (saved.state == ClientState::bound && saved.leases.empty()) ||
      std::any_of(saved.dns_servers.begin(), saved.dns_servers.end(),
                  [](const auto &address) {
                    return ip::is_unspecified(address) ||
                           ip::is_multicast(address);
                  }))
    return false;
  return true;
}

bool Client::restore(const ClientCheckpoint &saved, Clock::time_point now) {
  if (!validate_checkpoint(saved))
    return false;
  try {
    Client staged;
    if (!staged.configure(saved.configuration) ||
        !staged.retransmission_.restore(saved.retransmission, now))
      return false;
    staged.leases_.reserve(saved.leases.size());
    for (const auto &lease : saved.leases)
      staged.leases_.push_back(restore_lease(lease, now));
    staged.operation_leases_.reserve(saved.operation_leases.size());
    for (const auto &lease : saved.operation_leases)
      staged.operation_leases_.push_back(restore_lease(lease, now));
    staged.offer_.server = saved.offer.server;
    staged.offer_.server_octets = saved.offer.server_octets;
    staged.offer_.preference = saved.offer.preference;
    staged.offer_.present = saved.offer.present;
    staged.offer_.leases.reserve(saved.offer.leases.size());
    for (const auto &lease : saved.offer.leases)
      staged.offer_.leases.push_back(restore_lease(lease, now));
    staged.dns_servers_ = saved.dns_servers;
    staged.server_ = saved.server;
    staged.server_octets_ = saved.server_octets;
    staged.random_state_ = saved.random_state;
    staged.transaction_counter_ = saved.transaction_counter;
    staged.solicit_maximum_retransmission_seconds_ =
        saved.solicit_maximum_retransmission_seconds;
    staged.information_maximum_retransmission_seconds_ =
        saved.information_maximum_retransmission_seconds;
    staged.advertise_solicit_maximum_seconds_ =
        saved.advertise_solicit_maximum_seconds;
    staged.advertise_information_maximum_seconds_ =
        saved.advertise_information_maximum_seconds;
    staged.rate_limit_tokens_scaled_ = saved.rate_limit_tokens_scaled;
    staged.rate_limit_refilled_at_ = now;
    staged.rate_limit_initialized_ = saved.rate_limit_initialized;
    staged.advertise_solicit_maximum_seen_ =
        saved.advertise_solicit_maximum_seen;
    staged.advertise_solicit_maximum_conflict_ =
        saved.advertise_solicit_maximum_conflict;
    staged.advertise_information_maximum_seen_ =
        saved.advertise_information_maximum_seen;
    staged.advertise_information_maximum_conflict_ =
        saved.advertise_information_maximum_conflict;
    staged.information_refresh_at_ = restore_deadline(
        saved.information_refresh_remaining_nanoseconds, now);
    staged.state_ = saved.state;
    staged.confirm_not_on_link_received_ =
        saved.confirm_not_on_link_received;
    *this = std::move(staged);
    return true;
  } catch (...) {
    return false;
  }
}

} // namespace router::dhcpv6
