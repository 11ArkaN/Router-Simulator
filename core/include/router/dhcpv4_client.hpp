// RFC 2131 DHCPv4 client state owner. One endpoint control shard mutates one
// instance. The client emits and consumes only UDP payload bytes, while the
// endpoint owner performs broadcast, direct L2, ARP and routed transmission.

#pragma once

#include "router/dhcpv4_packet.hpp"
#include "router/sha256.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace router::dhcpv4 {

enum class ClientState : std::uint8_t {
  stopped,
  init,
  selecting,
  requesting,
  checking,
  declining,
  bound,
  renewing,
  rebinding,
  init_reboot,
  rebooting,
  releasing,
  informing,
  failed,
};

struct ClientConfiguration {
  packet::Mac hardware_address{};
  std::vector<std::uint8_t> client_identifier;
  std::vector<std::uint8_t> parameter_request_list;
  // RFC 3004 encodes one or more length-prefixed class values in Option 77.
  // This vector is one class value; the packet owner adds the length octet.
  std::vector<std::uint8_t> user_class;
  crypto::Sha256Digest transaction_secret{};
  std::uint16_t maximum_message_size{576U};
  bool broadcast{};
};

struct ClientLease {
  packet::Ipv4 address{};
  packet::Ipv4 subnet_mask{};
  packet::Ipv4 router{};
  packet::Ipv4 server_identifier{};
  std::vector<packet::Ipv4> domain_name_servers;
  std::chrono::steady_clock::time_point renew_at{};
  std::chrono::steady_clock::time_point rebind_at{};
  std::chrono::steady_clock::time_point valid_until{};
};

struct ClientLeaseCheckpoint {
  packet::Ipv4 address{};
  packet::Ipv4 subnet_mask{};
  packet::Ipv4 router{};
  packet::Ipv4 server_identifier{};
  std::vector<packet::Ipv4> domain_name_servers;
  std::int64_t renew_remaining_nanoseconds{};
  std::int64_t rebind_remaining_nanoseconds{};
  std::int64_t valid_remaining_nanoseconds{};
};

struct ClientStatus {
  // This fixed, pointer-free projection may cross the forwarding-to-control
  // SPSC boundary. The client remains the sole owner of the transaction and
  // lease objects; UI snapshots receive only a value sampled in one owner
  // turn.
  ClientState state{ClientState::stopped};
  packet::Ipv4 address{};
  packet::Ipv4 subnet_mask{};
  packet::Ipv4 router{};
  packet::Ipv4 server_identifier{};
  std::int64_t renew_remaining_nanoseconds{};
  std::int64_t rebind_remaining_nanoseconds{};
  std::int64_t valid_remaining_nanoseconds{};
  bool lease_present{};
};

struct ClientCheckpoint {
  ClientConfiguration configuration;
  std::optional<ClientLeaseCheckpoint> lease;
  std::optional<ClientLeaseCheckpoint> offered;
  std::optional<ClientLeaseCheckpoint> pending;
  packet::Ipv4 inform_address{};
  std::uint64_t transaction_counter{};
  std::uint32_t transaction_id{};
  std::uint32_t random_state{};
  std::uint16_t attempts{};
  std::int64_t timeout_nanoseconds{};
  std::int64_t next_action_remaining_nanoseconds{};
  std::int64_t exchange_elapsed_nanoseconds{};
  ClientState state{ClientState::stopped};
  bool configured{};
};

enum class ClientPollStatus : std::uint8_t {
  idle,
  transmit_limited_broadcast,
  transmit_unicast,
  output_too_small,
  failed,
};

struct ClientPollResult {
  ClientPollStatus status{ClientPollStatus::idle};
  std::size_t message_octets{};
  packet::Ipv4 destination{};
};

enum class ClientIngestStatus : std::uint8_t {
  accepted,
  ignored,
  malformed,
  transaction_mismatch,
  identity_mismatch,
};

class Client final {
public:
  using Clock = std::chrono::steady_clock;

  [[nodiscard]] bool configure(const ClientConfiguration &configuration);
  [[nodiscard]] bool start(Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool start_init_reboot(const ClientLease &retained,
                                       Clock::time_point now = Clock::now());
  // RELEASE is an explicit client operation. It retains the accepted binding
  // until poll() has encoded the one required packet, then locally relinquishes
  // the address even if the datagram is lost, as required by RFC 2131 4.4.4.
  [[nodiscard]] bool release(Clock::time_point now = Clock::now()) noexcept;
  // INFORM obtains parameters for an address configured by another owner. It
  // never creates a DHCP lease or transfers address ownership to this client.
  [[nodiscard]] bool inform(packet::Ipv4 address,
                            Clock::time_point now = Clock::now()) noexcept;
  // The endpoint performs RFC 5227 probing because it owns Ethernet input.
  // These callbacks are the only transitions out of the CHECKING state.
  [[nodiscard]] bool address_probe_succeeded(
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] bool address_probe_conflicted(
      Clock::time_point now = Clock::now()) noexcept;
  [[nodiscard]] std::chrono::milliseconds
  address_probe_initial_delay() noexcept;
  [[nodiscard]] std::chrono::milliseconds
  address_probe_interval() noexcept;
  void stop() noexcept;

  [[nodiscard]] ClientPollResult
  poll(std::span<std::uint8_t> output,
       Clock::time_point now = Clock::now());
  [[nodiscard]] ClientIngestStatus
  ingest(std::span<const std::uint8_t> input,
         Clock::time_point now = Clock::now());

  [[nodiscard]] ClientState state() const noexcept { return state_; }
  [[nodiscard]] const std::optional<ClientLease> &lease() const noexcept {
    return lease_;
  }
  [[nodiscard]] const std::optional<ClientLease> &
  pending_lease() const noexcept {
    return pending_;
  }
  [[nodiscard]] std::optional<Clock::time_point> next_deadline() const noexcept;
  [[nodiscard]] ClientStatus
  status(Clock::time_point now = Clock::now()) const noexcept;
  [[nodiscard]] ClientCheckpoint
  checkpoint(Clock::time_point now = Clock::now()) const;
  [[nodiscard]] bool restore(const ClientCheckpoint &state,
                             Clock::time_point now = Clock::now());

private:
  [[nodiscard]] std::uint32_t next_transaction_id() noexcept;
  [[nodiscard]] std::uint32_t random() noexcept;
  [[nodiscard]] std::chrono::milliseconds next_timeout() noexcept;
  [[nodiscard]] ClientPollResult
  build(std::span<std::uint8_t> output, Clock::time_point now);
  void begin_exchange(ClientState state, Clock::time_point now) noexcept;
  void schedule_retry(Clock::time_point now) noexcept;

  ClientConfiguration configuration_{};
  std::optional<ClientLease> lease_;
  std::optional<ClientLease> offered_;
  // ACKed parameters remain pending until RFC 5227 proves that the offered
  // address is unused. Keeping them separate prevents any packet path from
  // treating an unverified address as local.
  std::optional<ClientLease> pending_;
  packet::Ipv4 inform_address_{};
  std::uint64_t transaction_counter_{};
  std::uint32_t transaction_id_{};
  std::uint32_t random_state_{};
  std::uint16_t attempts_{};
  // RFC 2131 section 4.1 adds a sub-second random offset to retransmissions.
  // Milliseconds are retained in the owner so the wire behavior does not
  // silently quantize the required jitter to whole seconds.
  std::chrono::milliseconds timeout_{};
  Clock::time_point next_action_{};
  Clock::time_point exchange_started_{};
  ClientState state_{ClientState::stopped};
  bool configured_{};
};

} // namespace router::dhcpv4
