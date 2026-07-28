// DHCPv4 and BOOTP wire codec. The caller owns the UDP payload and every
// returned view borrows that storage. This module owns no transaction state,
// performs no routing and may be used only below control-plane DHCP semantics.

#pragma once

#include "router/packet.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::dhcpv4 {

inline constexpr std::uint16_t server_port = 67U;
inline constexpr std::uint16_t client_port = 68U;
inline constexpr std::size_t fixed_header_octets = 236U;
inline constexpr std::size_t magic_cookie_octets = 4U;
inline constexpr std::size_t options_offset =
    fixed_header_octets + magic_cookie_octets;
inline constexpr std::size_t maximum_message_octets = 65507U;
// A DHCP option has a one-octet length. An option containing only IPv4
// addresses can therefore hold at most floor(255 / 4) complete values.
inline constexpr std::size_t maximum_ipv4_addresses_per_option = 63U;
inline constexpr std::array<std::uint8_t, magic_cookie_octets> magic_cookie{
    99U, 130U, 83U, 99U};

enum class Operation : std::uint8_t {
  boot_request = 1U,
  boot_reply = 2U,
};

enum class MessageType : std::uint8_t {
  discover = 1U,
  offer = 2U,
  request = 3U,
  decline = 4U,
  acknowledgement = 5U,
  negative_acknowledgement = 6U,
  release = 7U,
  inform = 8U,
  force_renew = 9U,
  lease_query = 10U,
  lease_unassigned = 11U,
  lease_unknown = 12U,
  lease_active = 13U,
  bulk_lease_query = 14U,
  lease_query_done = 15U,
  active_lease_query = 16U,
  lease_query_status = 17U,
  tls = 18U,
};

enum class OptionCode : std::uint8_t {
  pad = 0U,
  subnet_mask = 1U,
  router = 3U,
  domain_name_server = 6U,
  host_name = 12U,
  domain_name = 15U,
  interface_mtu = 26U,
  broadcast_address = 28U,
  requested_address = 50U,
  lease_time = 51U,
  option_overload = 52U,
  message_type = 53U,
  server_identifier = 54U,
  parameter_request_list = 55U,
  message = 56U,
  maximum_message_size = 57U,
  renewal_time = 58U,
  rebinding_time = 59U,
  client_identifier = 61U,
  user_class = 77U,
  relay_agent_information = 82U,
  client_last_transaction_time = 91U,
  associated_ip = 92U,
  client_system_architecture = 93U,
  client_network_interface = 94U,
  client_machine_identifier = 97U,
  domain_search = 119U,
  classless_static_route = 121U,
  // RFC 6926 Bulk Leasequery options. Keeping the registry values in the
  // packet codec lets the UDP and TCP services share one option parser.
  status_code = 151U,
  base_time = 152U,
  start_time_of_state = 153U,
  query_start_time = 154U,
  query_end_time = 155U,
  dhcp_state = 156U,
  data_source = 157U,
  end = 255U,
};

enum class OptionField : std::uint8_t {
  options,
  file,
  server_name,
};

struct MessageView {
  Operation operation{Operation::boot_request};
  std::uint8_t hardware_type{};
  std::uint8_t hardware_length{};
  std::uint8_t hops{};
  std::uint32_t transaction_id{};
  std::uint16_t seconds{};
  std::uint16_t flags{};
  Ipv4 client_address{};
  Ipv4 your_address{};
  Ipv4 server_address{};
  Ipv4 gateway_address{};
  std::array<std::uint8_t, 16U> client_hardware_address{};
  std::span<const std::uint8_t> server_name{};
  std::span<const std::uint8_t> file{};
  std::span<const std::uint8_t> options{};
};

struct OptionOccurrence {
  std::uint8_t code{};
  OptionField field{OptionField::options};
  std::span<const std::uint8_t> data{};
};

// RawOptionCursor walks the main option field and the RFC 2132 overloaded
// fields in their required concatenation order. Padding and End markers are
// structural bytes and are skipped. Unknown option codes remain visible.
class RawOptionCursor final {
public:
  explicit RawOptionCursor(const MessageView &message) noexcept;

  // A missing result with valid()==true is clean end. A missing result with
  // valid()==false means a truncated TLV, duplicate overload declaration or
  // invalid overload value. Callers must reject the whole datagram.
  [[nodiscard]] std::optional<OptionOccurrence> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }

private:
  [[nodiscard]] std::optional<OptionOccurrence> next_in_field() noexcept;
  [[nodiscard]] bool advance_field() noexcept;

  const MessageView *message_{};
  std::span<const std::uint8_t> remaining_{};
  OptionField field_{OptionField::options};
  std::uint8_t overload_{};
  bool overload_seen_{};
  bool valid_{true};
};

[[nodiscard]] std::optional<MessageView>
parse(std::span<const std::uint8_t> bytes) noexcept;

// Concatenates every occurrence of one option according to RFC 3396. The
// caller supplies bounded output storage, so an attacker cannot cause an
// allocation proportional to duplicated option fragments.
struct NormalizedOption {
  std::size_t octets{};
  std::size_t occurrences{};
};

[[nodiscard]] std::optional<NormalizedOption>
normalize_option(const MessageView &message, std::uint8_t code,
                 std::span<std::uint8_t> output) noexcept;

[[nodiscard]] std::optional<MessageType>
message_type(const MessageView &message) noexcept;

class Writer final {
public:
  Writer() = default;

  // append rejects Pad and End because their encodings do not have a length
  // octet. finish writes the single End marker. The caller may add padding
  // after finish when a selected link-layer profile requires it.
  [[nodiscard]] bool append(std::uint8_t code,
                            std::span<const std::uint8_t> data) noexcept;
  [[nodiscard]] bool finish() noexcept;
  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return output_.first(position_);
  }

private:
  friend std::optional<Writer> begin(std::span<std::uint8_t>,
                                     const MessageView &) noexcept;
  explicit Writer(std::span<std::uint8_t> output,
                  std::size_t position) noexcept
      : output_(output), position_(position) {}

  std::span<std::uint8_t> output_{};
  std::size_t position_{};
  bool finished_{};
};

// begin serializes a BOOTP header and the DHCP magic cookie. Variable fields
// are copied from MessageView, while options are supplied through Writer.
[[nodiscard]] std::optional<Writer>
begin(std::span<std::uint8_t> output, const MessageView &header) noexcept;

} // namespace router::packet::dhcpv4
