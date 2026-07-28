// DHCPv4 client state transitions and wire-message generation. Every deadline
// uses steady_clock local to this owner. No global scheduler or simulated time
// participates in retransmission or lease expiration.

#include "router/dhcpv4_client.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace router::dhcpv4 {
namespace {

[[nodiscard]] bool zero(std::span<const std::uint8_t> bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(),
                     [](std::uint8_t octet) { return octet == 0U; });
}

[[nodiscard]] std::uint32_t read32(
    std::span<const std::uint8_t> bytes) noexcept {
  return (static_cast<std::uint32_t>(bytes[0U]) << 24U) |
         (static_cast<std::uint32_t>(bytes[1U]) << 16U) |
         (static_cast<std::uint32_t>(bytes[2U]) << 8U) | bytes[3U];
}

[[nodiscard]] std::optional<std::array<std::uint8_t, 4U>>
single_option(const packet::dhcpv4::MessageView &message,
              packet::dhcpv4::OptionCode code) noexcept {
  std::array<std::uint8_t, 4U> data{};
  const auto result = packet::dhcpv4::normalize_option(
      message, static_cast<std::uint8_t>(code), data);
  if (!result || result->occurrences != 1U ||
      result->octets != data.size())
    return std::nullopt;
  return data;
}

[[nodiscard]] packet::Ipv4 ipv4(
    const std::array<std::uint8_t, 4U> &data) noexcept {
  return {data[0U], data[1U], data[2U], data[3U]};
}

[[nodiscard]] bool equal_option(
    const packet::dhcpv4::MessageView &message,
    packet::dhcpv4::OptionCode code,
    std::span<const std::uint8_t> expected) noexcept {
  std::array<std::uint8_t, 255U> data{};
  const auto result = packet::dhcpv4::normalize_option(
      message, static_cast<std::uint8_t>(code), data);
  return result && result->occurrences == 1U &&
         result->octets == expected.size() &&
         std::equal(expected.begin(), expected.end(), data.begin());
}

[[nodiscard]] std::optional<std::vector<packet::Ipv4>>
ipv4_list_option(const packet::dhcpv4::MessageView &message,
                 packet::dhcpv4::OptionCode code) {
  std::array<std::uint8_t, 252U> data{};
  const auto normalized = packet::dhcpv4::normalize_option(
      message, static_cast<std::uint8_t>(code), data);
  if (!normalized)
    return std::nullopt;
  if (normalized->occurrences == 0U)
    return std::vector<packet::Ipv4>{};
  if (normalized->octets == 0U || normalized->octets % 4U != 0U)
    return std::nullopt;
  std::vector<packet::Ipv4> result;
  try {
    result.reserve(normalized->octets / 4U);
    for (std::size_t offset = 0U; offset < normalized->octets; offset += 4U)
      result.push_back(
          {data[offset], data[offset + 1U], data[offset + 2U],
           data[offset + 3U]});
  } catch (...) {
    return std::nullopt;
  }
  return result;
}

[[nodiscard]] std::int64_t
remaining_nanoseconds(Client::Clock::time_point deadline,
                      Client::Clock::time_point now) noexcept {
  return std::max<std::int64_t>(
      0, std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now)
             .count());
}

[[nodiscard]] ClientLeaseCheckpoint
lease_checkpoint(const ClientLease &lease,
                 Client::Clock::time_point now) {
  return {.address = lease.address,
          .subnet_mask = lease.subnet_mask,
          .router = lease.router,
          .server_identifier = lease.server_identifier,
          .domain_name_servers = lease.domain_name_servers,
          .renew_remaining_nanoseconds =
              remaining_nanoseconds(lease.renew_at, now),
          .rebind_remaining_nanoseconds =
              remaining_nanoseconds(lease.rebind_at, now),
          .valid_remaining_nanoseconds =
              remaining_nanoseconds(lease.valid_until, now)};
}

[[nodiscard]] std::optional<ClientLease>
restore_lease(const ClientLeaseCheckpoint &saved,
              Client::Clock::time_point now,
              bool lifetimes_required) {
  if (saved.domain_name_servers.size() >
          packet::dhcpv4::maximum_ipv4_addresses_per_option ||
      saved.renew_remaining_nanoseconds < 0 ||
      saved.rebind_remaining_nanoseconds < 0 ||
      saved.valid_remaining_nanoseconds < 0)
    return std::nullopt;
  if (lifetimes_required &&
      (saved.renew_remaining_nanoseconds >=
           saved.rebind_remaining_nanoseconds ||
       saved.rebind_remaining_nanoseconds >=
           saved.valid_remaining_nanoseconds ||
       saved.valid_remaining_nanoseconds == 0))
    return std::nullopt;
  try {
    return ClientLease{
        .address = saved.address,
        .subnet_mask = saved.subnet_mask,
        .router = saved.router,
        .server_identifier = saved.server_identifier,
        .domain_name_servers = saved.domain_name_servers,
        .renew_at =
            now + std::chrono::nanoseconds{
                      saved.renew_remaining_nanoseconds},
        .rebind_at =
            now + std::chrono::nanoseconds{
                      saved.rebind_remaining_nanoseconds},
        .valid_until =
            now + std::chrono::nanoseconds{
                      saved.valid_remaining_nanoseconds}};
  } catch (...) {
    return std::nullopt;
  }
}

} // namespace

bool Client::configure(const ClientConfiguration &configuration) {
  if (state_ != ClientState::stopped ||
      zero(configuration.hardware_address) ||
      configuration.client_identifier.size() > 255U ||
      configuration.parameter_request_list.size() > 255U ||
      configuration.user_class.size() > 254U ||
      configuration.maximum_message_size < 576U ||
      zero(configuration.transaction_secret))
    return false;
  try {
    configuration_ = configuration;
  } catch (...) {
    return false;
  }
  configured_ = true;
  return true;
}

std::uint32_t Client::next_transaction_id() noexcept {
  std::array<std::uint8_t, 8U> counter{};
  auto value = ++transaction_counter_;
  for (std::size_t index = 0U; index < counter.size(); ++index) {
    counter[counter.size() - 1U - index] = static_cast<std::uint8_t>(value);
    value >>= 8U;
  }
  const std::array<std::span<const std::uint8_t>, 1U> parts{counter};
  const auto digest = crypto::hmac_sha256(configuration_.transaction_secret,
                                          parts);
  auto result = read32(std::span{digest.data(), 4U});
  // XID has no reserved value. The separate random seed uses the next digest
  // word and is forced nonzero only because xorshift32 has a zero lock state.
  random_state_ = read32(std::span{digest.data() + 4U, 4U});
  if (random_state_ == 0U)
    random_state_ = 0x6d2b79f5U;
  return result;
}

std::uint32_t Client::random() noexcept {
  auto value = random_state_;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  random_state_ = value;
  return value;
}

std::chrono::milliseconds Client::next_timeout() noexcept {
  // RFC 2131 section 4.1 starts at four seconds with a random value from -1
  // through +1, then doubles to a sixty-four second ceiling. Keeping the
  // adjusted duration in milliseconds prevents correlated clients from
  // collapsing back onto whole-second retransmission boundaries.
  const auto base =
      timeout_.count() == 0 ? std::chrono::milliseconds{4000}
                            : std::min(timeout_ * 2,
                                       std::chrono::milliseconds{64000});
  const auto slots = static_cast<std::uint64_t>(2001U);
  const auto offset_milliseconds =
      static_cast<std::int64_t>(
          (static_cast<std::uint64_t>(random()) * slots) >> 32U) -
      1000;
  const auto adjusted =
      base + std::chrono::milliseconds{offset_milliseconds};
  // Retain the actual randomized interval. RFC 2131 doubles the preceding
  // retransmission interval, including its random component, before applying
  // the next random component.
  timeout_ = adjusted;
  return std::max(adjusted, std::chrono::milliseconds{1});
}

void Client::begin_exchange(ClientState state,
                            Clock::time_point now) noexcept {
  transaction_id_ = next_transaction_id();
  attempts_ = 0U;
  timeout_ = {};
  exchange_started_ = now;
  next_action_ = now;
  state_ = state;
}

bool Client::start(Clock::time_point now) noexcept {
  if (!configured_ || state_ != ClientState::stopped)
    return false;
  lease_.reset();
  offered_.reset();
  pending_.reset();
  inform_address_ = {};
  state_ = ClientState::init;
  begin_exchange(ClientState::selecting, now);
  return true;
}

bool Client::start_init_reboot(const ClientLease &retained,
                               Clock::time_point now) {
  if (!configured_ || state_ != ClientState::stopped ||
      zero(retained.address))
    return false;
  lease_ = retained;
  offered_.reset();
  pending_.reset();
  state_ = ClientState::init_reboot;
  begin_exchange(ClientState::rebooting, now);
  return true;
}

bool Client::release(Clock::time_point now) noexcept {
  if (!configured_ || !lease_ ||
      (state_ != ClientState::bound && state_ != ClientState::renewing &&
       state_ != ClientState::rebinding))
    return false;
  offered_.reset();
  pending_.reset();
  begin_exchange(ClientState::releasing, now);
  return true;
}

bool Client::inform(packet::Ipv4 address, Clock::time_point now) noexcept {
  if (!configured_ || state_ != ClientState::stopped || zero(address))
    return false;
  lease_.reset();
  offered_.reset();
  pending_.reset();
  inform_address_ = address;
  begin_exchange(ClientState::informing, now);
  return true;
}

bool Client::address_probe_succeeded(Clock::time_point now) noexcept {
  if (state_ != ClientState::checking || !pending_)
    return false;
  lease_ = std::move(pending_);
  pending_.reset();
  offered_.reset();
  state_ = ClientState::bound;
  next_action_ = lease_->renew_at;
  exchange_started_ = now;
  return true;
}

bool Client::address_probe_conflicted(Clock::time_point now) noexcept {
  if (state_ != ClientState::checking || !pending_)
    return false;
  // DHCPDECLINE identifies both the rejected address and the server whose ACK
  // granted it. The pending lease remains intact only until build() encodes
  // that exact information.
  begin_exchange(ClientState::declining, now);
  return true;
}

std::chrono::milliseconds Client::address_probe_initial_delay() noexcept {
  // RFC 5227 PROBE_WAIT is one second. Multiplication followed by a high-word
  // reduction gives a uniform integer in [0, 1000] without modulo bias.
  const auto slot = (static_cast<std::uint64_t>(random()) * 1001U) >> 32U;
  return std::chrono::milliseconds{slot};
}

std::chrono::milliseconds Client::address_probe_interval() noexcept {
  // RFC 5227 PROBE_MIN and PROBE_MAX are one and two seconds. Selecting one
  // of 1001 millisecond slots preserves both inclusive bounds.
  const auto slot = (static_cast<std::uint64_t>(random()) * 1001U) >> 32U;
  return std::chrono::milliseconds{1000 + slot};
}

void Client::stop() noexcept {
  lease_.reset();
  offered_.reset();
  pending_.reset();
  inform_address_ = {};
  state_ = ClientState::stopped;
  next_action_ = Clock::time_point::max();
}

void Client::schedule_retry(Clock::time_point now) noexcept {
  if (attempts_ != std::numeric_limits<std::uint16_t>::max())
    ++attempts_;
  next_action_ = now + next_timeout();
}

ClientPollResult Client::build(std::span<std::uint8_t> output,
                               Clock::time_point now) {
  packet::dhcpv4::MessageView header{
      .operation = packet::dhcpv4::Operation::boot_request,
      .hardware_type = 1U,
      .hardware_length =
          static_cast<std::uint8_t>(configuration_.hardware_address.size()),
      .transaction_id = transaction_id_,
      .seconds = static_cast<std::uint16_t>(std::min<std::int64_t>(
          std::chrono::duration_cast<std::chrono::seconds>(
              now - exchange_started_)
              .count(),
          std::numeric_limits<std::uint16_t>::max())),
      .flags = static_cast<std::uint16_t>(
          configuration_.broadcast ? 0x8000U : 0U),
  };
  std::copy(configuration_.hardware_address.begin(),
            configuration_.hardware_address.end(),
            header.client_hardware_address.begin());

  packet::dhcpv4::MessageType type{};
  if (state_ == ClientState::selecting) {
    type = packet::dhcpv4::MessageType::discover;
  } else if (state_ == ClientState::requesting ||
             state_ == ClientState::rebooting ||
             state_ == ClientState::renewing ||
             state_ == ClientState::rebinding) {
    type = packet::dhcpv4::MessageType::request;
    if ((state_ == ClientState::renewing ||
         state_ == ClientState::rebinding) &&
        lease_)
      header.client_address = lease_->address;
  } else if (state_ == ClientState::declining && pending_) {
    type = packet::dhcpv4::MessageType::decline;
  } else if (state_ == ClientState::releasing && lease_) {
    type = packet::dhcpv4::MessageType::release;
    header.client_address = lease_->address;
  } else if (state_ == ClientState::informing) {
    type = packet::dhcpv4::MessageType::inform;
    header.client_address = inform_address_;
  } else {
    return {};
  }

  auto writer = packet::dhcpv4::begin(output, header);
  const std::array type_data{static_cast<std::uint8_t>(type)};
  if (!writer ||
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::message_type),
                      type_data))
    return {.status = ClientPollStatus::output_too_small};

  if (!configuration_.client_identifier.empty() &&
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::client_identifier),
                      configuration_.client_identifier))
    return {.status = ClientPollStatus::output_too_small};
  if (!configuration_.parameter_request_list.empty() &&
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::parameter_request_list),
                      configuration_.parameter_request_list))
    return {.status = ClientPollStatus::output_too_small};
  if (!configuration_.user_class.empty()) {
    std::array<std::uint8_t, 255U> encoded{};
    encoded[0U] =
        static_cast<std::uint8_t>(configuration_.user_class.size());
    std::ranges::copy(configuration_.user_class, encoded.begin() + 1U);
    if (!writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::user_class),
            std::span{encoded}.first(configuration_.user_class.size() + 1U)))
      return {.status = ClientPollStatus::output_too_small};
  }

  const std::array maximum_size{
      static_cast<std::uint8_t>(configuration_.maximum_message_size >> 8U),
      static_cast<std::uint8_t>(configuration_.maximum_message_size)};
  if (!writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::maximum_message_size),
                      maximum_size))
    return {.status = ClientPollStatus::output_too_small};

  if ((state_ == ClientState::requesting && offered_) ||
      (state_ == ClientState::rebooting && lease_)) {
    const auto &selected =
        state_ == ClientState::requesting ? *offered_ : *lease_;
    if (!writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::requested_address),
                        selected.address) ||
        (state_ == ClientState::requesting &&
         !writer->append(static_cast<std::uint8_t>(
                             packet::dhcpv4::OptionCode::server_identifier),
                         selected.server_identifier)))
      return {.status = ClientPollStatus::output_too_small};
  }
  if (state_ == ClientState::declining && pending_) {
    if (!writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::requested_address),
                        pending_->address) ||
        !writer->append(static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::server_identifier),
                        pending_->server_identifier))
      return {.status = ClientPollStatus::output_too_small};
  }
  if (state_ == ClientState::releasing && lease_ &&
      !writer->append(static_cast<std::uint8_t>(
                          packet::dhcpv4::OptionCode::server_identifier),
                      lease_->server_identifier))
    return {.status = ClientPollStatus::output_too_small};
  if (!writer->finish())
    return {.status = ClientPollStatus::output_too_small};

  // DECLINE and RELEASE are one-shot notifications. RFC 2131 requires the
  // client to wait ten seconds after a conflict before restarting discovery.
  // The endpoint retains the encoded datagram under link backpressure, so the
  // protocol owner can safely leave these transient states after encoding.
  if (state_ == ClientState::declining) {
    pending_.reset();
    lease_.reset();
    offered_.reset();
    state_ = ClientState::init;
    next_action_ = now + std::chrono::seconds{10};
    return {.status = ClientPollStatus::transmit_limited_broadcast,
            .message_octets = writer->view().size()};
  }
  if (state_ == ClientState::releasing) {
    const auto destination = lease_->server_identifier;
    lease_.reset();
    state_ = ClientState::stopped;
    next_action_ = Clock::time_point::max();
    return {.status = ClientPollStatus::transmit_unicast,
            .message_octets = writer->view().size(),
            .destination = destination};
  }
  schedule_retry(now);

  if (state_ == ClientState::renewing && lease_)
    return {.status = ClientPollStatus::transmit_unicast,
            .message_octets = writer->view().size(),
            .destination = lease_->server_identifier};
  return {.status = ClientPollStatus::transmit_limited_broadcast,
          .message_octets = writer->view().size()};
}

ClientPollResult Client::poll(std::span<std::uint8_t> output,
                              Clock::time_point now) {
  if (state_ == ClientState::stopped || state_ == ClientState::failed)
    return {};

  if (state_ == ClientState::checking)
    return {};
  if (state_ == ClientState::init && now >= next_action_)
    begin_exchange(ClientState::selecting, now);

  if (state_ == ClientState::bound && lease_) {
    if (now >= lease_->valid_until) {
      lease_.reset();
      begin_exchange(ClientState::selecting, now);
    } else if (now >= lease_->rebind_at) {
      begin_exchange(ClientState::rebinding, now);
    } else if (now >= lease_->renew_at) {
      begin_exchange(ClientState::renewing, now);
    } else {
      return {};
    }
  }
  if (state_ == ClientState::renewing && lease_ &&
      now >= lease_->rebind_at)
    begin_exchange(ClientState::rebinding, now);
  if (state_ == ClientState::rebinding && lease_ &&
      now >= lease_->valid_until) {
    lease_.reset();
    begin_exchange(ClientState::selecting, now);
  }
  if (now < next_action_)
    return {};
  return build(output, now);
}

ClientIngestStatus Client::ingest(
    std::span<const std::uint8_t> input, Clock::time_point now) {
  const auto message = packet::dhcpv4::parse(input);
  if (!message ||
      message->operation != packet::dhcpv4::Operation::boot_reply)
    return ClientIngestStatus::malformed;
  if (!std::equal(configuration_.hardware_address.begin(),
                  configuration_.hardware_address.end(),
                  message->client_hardware_address.begin()))
    return ClientIngestStatus::identity_mismatch;
  if (!configuration_.client_identifier.empty() &&
      !equal_option(*message, packet::dhcpv4::OptionCode::client_identifier,
                    configuration_.client_identifier))
    return ClientIngestStatus::identity_mismatch;

  const auto type = packet::dhcpv4::message_type(*message);
  if (!type)
    return ClientIngestStatus::malformed;

  // RFC 3203 FORCERENEW is not part of the client's current transaction.
  // Accept it only for the address and server that own the live lease. The
  // resulting RENEW exchange receives its own fresh XID.
  if (*type == packet::dhcpv4::MessageType::force_renew) {
    const auto server = single_option(
        *message, packet::dhcpv4::OptionCode::server_identifier);
    if (!lease_ || state_ != ClientState::bound || !server ||
        ipv4(*server) != lease_->server_identifier ||
        message->client_address != lease_->address)
      return ClientIngestStatus::ignored;
    begin_exchange(ClientState::renewing, now);
    return ClientIngestStatus::accepted;
  }
  if (message->transaction_id != transaction_id_)
    return ClientIngestStatus::transaction_mismatch;
  const auto server_data = single_option(
      *message, packet::dhcpv4::OptionCode::server_identifier);
  if (!server_data)
    return ClientIngestStatus::malformed;

  if (state_ == ClientState::selecting &&
      *type == packet::dhcpv4::MessageType::offer) {
    const auto lease_data =
        single_option(*message, packet::dhcpv4::OptionCode::lease_time);
    if (zero(message->your_address) || !lease_data)
      return ClientIngestStatus::malformed;
    ClientLease offer{.address = message->your_address,
                      .subnet_mask = {},
                      .router = {},
                      .server_identifier = ipv4(*server_data),
                      .domain_name_servers = {}};
    if (const auto mask = single_option(
            *message, packet::dhcpv4::OptionCode::subnet_mask))
      offer.subnet_mask = ipv4(*mask);
    if (const auto router = single_option(
            *message, packet::dhcpv4::OptionCode::router))
      offer.router = ipv4(*router);
    offered_ = std::move(offer);
    // REQUEST uses a new transaction in RFC 2131 only when a new acquisition
    // starts. Selecting and Requesting are one acquisition and retain XID.
    attempts_ = 0U;
    timeout_ = {};
    next_action_ = now;
    state_ = ClientState::requesting;
    return ClientIngestStatus::accepted;
  }

  if ((state_ == ClientState::requesting ||
       state_ == ClientState::rebooting ||
       state_ == ClientState::renewing ||
       state_ == ClientState::rebinding) &&
      *type == packet::dhcpv4::MessageType::negative_acknowledgement) {
    lease_.reset();
    offered_.reset();
    begin_exchange(ClientState::selecting, now);
    return ClientIngestStatus::accepted;
  }

  if ((state_ == ClientState::requesting ||
       state_ == ClientState::rebooting ||
       state_ == ClientState::renewing ||
       state_ == ClientState::rebinding) &&
      *type == packet::dhcpv4::MessageType::acknowledgement) {
    const auto acknowledgement_state = state_;
    const auto lease_data =
        single_option(*message, packet::dhcpv4::OptionCode::lease_time);
    if (!lease_data)
      return ClientIngestStatus::malformed;
    const auto lease_seconds = read32(*lease_data);
    if (lease_seconds == 0U)
      return ClientIngestStatus::malformed;

    ClientLease accepted =
        offered_.value_or(lease_.value_or(ClientLease{}));
    if (!zero(message->your_address))
      accepted.address = message->your_address;
    accepted.server_identifier = ipv4(*server_data);
    if (const auto mask = single_option(
            *message, packet::dhcpv4::OptionCode::subnet_mask))
      accepted.subnet_mask = ipv4(*mask);
    if (const auto router = single_option(
            *message, packet::dhcpv4::OptionCode::router))
      accepted.router = ipv4(*router);
    const auto dns = ipv4_list_option(
        *message, packet::dhcpv4::OptionCode::domain_name_server);
    if (!dns)
      return ClientIngestStatus::malformed;
    if (!dns->empty())
      accepted.domain_name_servers = *dns;

    const auto renewal_data = single_option(
        *message, packet::dhcpv4::OptionCode::renewal_time);
    const auto rebinding_data = single_option(
        *message, packet::dhcpv4::OptionCode::rebinding_time);
    const auto renewal_seconds =
        renewal_data ? read32(*renewal_data) : lease_seconds / 2U;
    const auto rebinding_seconds =
        rebinding_data ? read32(*rebinding_data)
                       : static_cast<std::uint32_t>(
                             (static_cast<std::uint64_t>(lease_seconds) * 7U) /
                             8U);
    if (renewal_seconds >= rebinding_seconds ||
        rebinding_seconds >= lease_seconds)
      return ClientIngestStatus::malformed;
    accepted.renew_at = now + std::chrono::seconds{renewal_seconds};
    accepted.rebind_at = now + std::chrono::seconds{rebinding_seconds};
    accepted.valid_until = now + std::chrono::seconds{lease_seconds};
    offered_.reset();
    if ((acknowledgement_state == ClientState::renewing ||
         acknowledgement_state == ClientState::rebinding) &&
        lease_ && accepted.address == lease_->address) {
      // Renewal retains an address already checked on this unchanged link.
      // Repeating ACD at every T1 would create avoidable ARP traffic and a
      // temporary outage that RFC 5227 explicitly warns against.
      lease_ = std::move(accepted);
      state_ = ClientState::bound;
      next_action_ = lease_->renew_at;
    } else {
      // A newly allocated or reboot-validated address is not usable yet. RFC
      // 2131 4.4.1 and RFC 5227 require conflict detection before ownership.
      pending_ = std::move(accepted);
      state_ = ClientState::checking;
      next_action_ = Clock::time_point::max();
    }
    return ClientIngestStatus::accepted;
  }
  if (state_ == ClientState::informing &&
      *type == packet::dhcpv4::MessageType::acknowledgement) {
    // INFORM updates no address lease. The endpoint may expose returned
    // parameters separately later, but the transaction itself is complete.
    state_ = ClientState::stopped;
    next_action_ = Clock::time_point::max();
    return ClientIngestStatus::accepted;
  }
  return ClientIngestStatus::ignored;
}

std::optional<Client::Clock::time_point>
Client::next_deadline() const noexcept {
  if (state_ == ClientState::stopped || state_ == ClientState::failed)
    return std::nullopt;
  if (state_ == ClientState::bound && lease_)
    return std::min({lease_->renew_at, lease_->rebind_at,
                     lease_->valid_until});
  return state_ == ClientState::checking ? std::nullopt
                                         : std::optional{next_action_};
}

ClientCheckpoint Client::checkpoint(Clock::time_point now) const {
  ClientCheckpoint result{
      .configuration = configuration_,
      .lease = std::nullopt,
      .offered = std::nullopt,
      .pending = std::nullopt,
      .inform_address = inform_address_,
      .transaction_counter = transaction_counter_,
      .transaction_id = transaction_id_,
      .random_state = random_state_,
      .attempts = attempts_,
      .timeout_nanoseconds =
          std::chrono::duration_cast<std::chrono::nanoseconds>(timeout_)
              .count(),
      .next_action_remaining_nanoseconds =
          state_ == ClientState::stopped
              ? 0
              : remaining_nanoseconds(next_action_, now),
      .exchange_elapsed_nanoseconds =
          std::max<std::int64_t>(
              0, std::chrono::duration_cast<std::chrono::nanoseconds>(
                     now - exchange_started_)
                     .count()),
      .state = state_,
      .configured = configured_};
  if (lease_)
    result.lease = lease_checkpoint(*lease_, now);
  if (offered_)
    result.offered = lease_checkpoint(*offered_, now);
  if (pending_)
    result.pending = lease_checkpoint(*pending_, now);
  return result;
}

bool Client::restore(const ClientCheckpoint &saved,
                     Clock::time_point now) {
  if (!saved.configured || saved.state == ClientState::init ||
      saved.state > ClientState::failed || saved.timeout_nanoseconds < 0 ||
      saved.next_action_remaining_nanoseconds < 0 ||
      saved.exchange_elapsed_nanoseconds < 0)
    return false;
  Client staged;
  if (!staged.configure(saved.configuration))
    return false;
  const bool lease_lifetimes_required =
      saved.state == ClientState::bound ||
      saved.state == ClientState::renewing ||
      saved.state == ClientState::rebinding;
  if (saved.lease) {
    auto lease = restore_lease(*saved.lease, now, lease_lifetimes_required);
    if (!lease)
      return false;
    staged.lease_ = std::move(*lease);
  }
  if (saved.offered) {
    auto offered = restore_lease(*saved.offered, now, false);
    if (!offered)
      return false;
    staged.offered_ = std::move(*offered);
  }
  if (saved.pending) {
    auto pending = restore_lease(*saved.pending, now, true);
    if (!pending)
      return false;
    staged.pending_ = std::move(*pending);
  }
  if ((lease_lifetimes_required && !staged.lease_) ||
      (saved.state == ClientState::requesting && !staged.offered_) ||
      (saved.state == ClientState::selecting && staged.offered_) ||
      (saved.state == ClientState::checking && !staged.pending_) ||
      (saved.state == ClientState::declining && !staged.pending_) ||
      (saved.state == ClientState::informing &&
       saved.inform_address == packet::Ipv4{}) ||
      (saved.state != ClientState::informing &&
       saved.inform_address != packet::Ipv4{}))
    return false;
  staged.inform_address_ = saved.inform_address;
  staged.transaction_counter_ = saved.transaction_counter;
  staged.transaction_id_ = saved.transaction_id;
  staged.random_state_ = saved.random_state;
  staged.attempts_ = saved.attempts;
  staged.timeout_ = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::nanoseconds{saved.timeout_nanoseconds});
  staged.next_action_ =
      now + std::chrono::nanoseconds{
                saved.next_action_remaining_nanoseconds};
  staged.exchange_started_ =
      now - std::chrono::nanoseconds{saved.exchange_elapsed_nanoseconds};
  staged.state_ = saved.state;
  *this = std::move(staged);
  return true;
}

ClientStatus Client::status(Clock::time_point now) const noexcept {
  ClientStatus result{.state = state_};
  if (!lease_)
    return result;
  result.address = lease_->address;
  result.subnet_mask = lease_->subnet_mask;
  result.router = lease_->router;
  result.server_identifier = lease_->server_identifier;
  result.renew_remaining_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          lease_->renew_at - now).count();
  result.rebind_remaining_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          lease_->rebind_at - now).count();
  result.valid_remaining_nanoseconds =
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          lease_->valid_until - now).count();
  result.lease_present = true;
  return result;
}

} // namespace router::dhcpv4
