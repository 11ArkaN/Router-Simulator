// Allocation-free RFC 9915 DHCPv6 message and option codec. The caller owns
// UDP storage and protocol state. This module preserves unknown options and
// never communicates a decoded object between devices in place of wire bytes.

#pragma once

#include "router/dns_packet.hpp"
#include "router/packet.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace router::packet::dhcpv6 {

inline constexpr std::uint16_t client_port = 546U;
inline constexpr std::uint16_t server_port = 547U;
inline constexpr Ipv6 all_relay_agents_and_servers{
    {0xffU, 0x02U, 0U, 0U, 0U, 0U, 0U, 0U,
     0U, 0U, 0U, 0U, 0U, 1U, 0U, 2U}};
// RFC 9915 assigns ff05::1:3 to All_DHCP_Servers. Relay agents use this
// site-scoped group as the protocol default when no upstream destination was
// explicitly configured. SR OS service interfaces apply a stricter profile
// policy and remain inactive until at least one server is configured.
inline constexpr Ipv6 all_servers{
    {0xffU, 0x05U, 0U, 0U, 0U, 0U, 0U, 0U,
     0U, 0U, 0U, 0U, 0U, 1U, 0U, 3U}};
inline constexpr std::uint8_t relay_multicast_hop_limit = 8U;
// The 16-bit UDP Length includes its eight-octet header. Without IPv6
// jumbograms, one DHCPv6 message can therefore occupy 65527 octets. This is a
// wire-format bound, not an implementation policy or link-MTU shortcut.
inline constexpr std::size_t maximum_message_octets = 65527U;
inline constexpr std::uint32_t information_refresh_default_seconds = 86400U;
inline constexpr std::uint32_t information_refresh_minimum_seconds = 600U;
inline constexpr std::uint32_t maximum_retransmission_default_seconds =
    3600U;
inline constexpr std::uint32_t maximum_retransmission_minimum_seconds = 60U;
inline constexpr std::uint32_t maximum_retransmission_limit_seconds = 86400U;
// RFC 9915 Table 1 retains the normative relay forwarding limit of eight.
// A relay discards an incoming Relay-forward whose hop count is already at
// this limit before it allocates or encapsulates another message.
inline constexpr std::uint8_t hop_count_limit = 8U;
inline constexpr std::size_t client_server_header_octets = 4U;
inline constexpr std::size_t relay_header_octets = 34U;
inline constexpr std::size_t maximum_duid_identifier_octets = 128U;
inline constexpr std::size_t maximum_duid_octets =
    2U + maximum_duid_identifier_octets;

enum class MessageType : std::uint8_t {
  solicit = 1,
  advertise = 2,
  request = 3,
  confirm = 4,
  renew = 5,
  rebind = 6,
  reply = 7,
  release = 8,
  decline = 9,
  reconfigure = 10,
  information_request = 11,
  relay_forward = 12,
  relay_reply = 13,
  // RFC 5007 adds the on-demand Leasequery exchange. Bulk Leasequery uses
  // later message codes and a TCP transport, so it must not be conflated with
  // these two UDP messages.
  leasequery = 14,
  leasequery_reply = 15
};

enum class OptionCode : std::uint16_t {
  client_identifier = 1,
  server_identifier = 2,
  ia_na = 3,
  ia_ta = 4,
  ia_address = 5,
  option_request = 6,
  preference = 7,
  elapsed_time = 8,
  relay_message = 9,
  authentication = 11,
  server_unicast = 12,
  status_code = 13,
  rapid_commit = 14,
  user_class = 15,
  vendor_class = 16,
  vendor_options = 17,
  interface_id = 18,
  reconfigure_message = 19,
  reconfigure_accept = 20,
  dns_recursive_name_server = 23,
  domain_search_list = 24,
  ia_pd = 25,
  ia_prefix = 26,
  information_refresh_time = 32,
  // RFC 5007 options are kept in the common wire codec even though the
  // release profile accepts only QUERY_BY_CLIENTID. Unsupported query types
  // still need to be decoded in order to return the mandated status code.
  leasequery_query = 44,
  client_data = 45,
  client_last_transaction_time = 46,
  leasequery_relay_data = 47,
  leasequery_client_link = 48,
  // RFC 7653 moved the common Active/Bulk Leasequery base timestamp into the
  // IANA DHCPv6 option registry at code 100. RFC 8156 reuses that exact option
  // inside failover CLIENT_DATA and unassociated IAPREFIX bindings.
  leasequery_base_time = 100,
  // RFC 6603 assigns option 67 to the excluded child prefix carried inside
  // an IA Prefix option. It remains a nested wire option and is never inferred
  // from the delegated aggregate by local policy.
  prefix_exclude = 67,
  solicit_maximum_retransmission_time = 82,
  information_maximum_retransmission_time = 83
};

struct OptionView {
  std::uint16_t code{};
  // data borrows the received message. Unknown codes remain accessible so a
  // relay can encapsulate the original message without reserializing options.
  std::span<const std::uint8_t> data{};
};

class OptionCursor final {
public:
  explicit OptionCursor(std::span<const std::uint8_t> bytes) noexcept
      : remaining_(bytes) {}

  // nullopt with valid()==true means clean end. nullopt with valid()==false
  // means a truncated option header or value and invalidates the whole message.
  [[nodiscard]] std::optional<OptionView> next() noexcept;
  [[nodiscard]] bool valid() const noexcept { return valid_; }
  [[nodiscard]] bool empty() const noexcept { return remaining_.empty(); }

private:
  std::span<const std::uint8_t> remaining_{};
  bool valid_{true};
};

struct MessageView {
  std::uint8_t type{};
  std::uint32_t transaction_id{};
  std::uint8_t hop_count{};
  Ipv6 link_address{};
  Ipv6 peer_address{};
  std::span<const std::uint8_t> options{};
  bool relay{};
};

[[nodiscard]] std::optional<MessageView>
parse(std::span<const std::uint8_t> bytes) noexcept;

class Writer final {
public:
  Writer() = default;

  // Options are written in caller-selected order. RFC 9915 permits options to
  // appear in any order unless an individual option specification says more.
  [[nodiscard]] bool append(std::uint16_t code,
                            std::span<const std::uint8_t> data) noexcept;
  [[nodiscard]] std::size_t size() const noexcept { return position_; }
  [[nodiscard]] std::span<const std::uint8_t> view() const noexcept {
    return output_.first(position_);
  }

private:
  friend std::optional<Writer>
  begin_client_server(std::span<std::uint8_t>, std::uint8_t,
                      std::uint32_t) noexcept;
  friend std::optional<Writer>
  begin_relay(std::span<std::uint8_t>, std::uint8_t, std::uint8_t, Ipv6,
              Ipv6) noexcept;

  explicit Writer(std::span<std::uint8_t> output,
                  std::size_t position) noexcept
      : output_(output), position_(position) {}

  std::span<std::uint8_t> output_{};
  std::size_t position_{};
};

[[nodiscard]] std::optional<Writer>
begin_client_server(std::span<std::uint8_t> output, std::uint8_t type,
                    std::uint32_t transaction_id) noexcept;
[[nodiscard]] std::optional<Writer>
begin_relay(std::span<std::uint8_t> output, std::uint8_t type,
            std::uint8_t hop_count, Ipv6 link_address,
            Ipv6 peer_address) noexcept;

struct IdentityAssociationView {
  std::uint32_t iaid{};
  std::uint32_t t1{};
  std::uint32_t t2{};
  std::span<const std::uint8_t> options{};
};

struct TemporaryIdentityAssociationView {
  std::uint32_t iaid{};
  std::span<const std::uint8_t> options{};
};

struct IaAddressView {
  Ipv6 address{};
  std::uint32_t preferred_lifetime{};
  std::uint32_t valid_lifetime{};
  std::span<const std::uint8_t> options{};
};

struct IaPrefixView {
  Ipv6 prefix{};
  std::uint32_t preferred_lifetime{};
  std::uint32_t valid_lifetime{};
  std::uint8_t prefix_length{};
  std::span<const std::uint8_t> options{};
};

struct PrefixExcludeView {
  // excluded_prefix is the canonical child prefix reconstructed by
  // concatenating the delegated prefix with the option's subnet-id bits.
  Ipv6 excluded_prefix{};
  std::uint8_t excluded_prefix_length{};
};

[[nodiscard]] std::optional<IdentityAssociationView>
parse_ia_na_or_pd(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::optional<TemporaryIdentityAssociationView>
parse_ia_ta(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::optional<IaAddressView>
parse_ia_address(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::optional<IaPrefixView>
parse_ia_prefix(std::span<const std::uint8_t> data) noexcept;
// RFC 6603 section 4 requires this option to be nested in one IAPREFIX. The
// delegated parent is supplied by the already validated enclosing option.
// Non-canonical padding, a non-child length or a malformed body is rejected.
[[nodiscard]] std::optional<PrefixExcludeView> parse_prefix_exclude(
    std::span<const std::uint8_t> data, const Ipv6 &delegated_prefix,
    std::uint8_t delegated_prefix_length) noexcept;

// Typed option-body encoders centralize every network-order field. They write
// only the option data, allowing Writer::append() to add the outer code and
// length while nested IA suboptions use the same representation recursively.
[[nodiscard]] std::optional<std::size_t> encode_ia_na_or_pd(
    std::span<std::uint8_t> output, std::uint32_t iaid, std::uint32_t t1,
    std::uint32_t t2, std::span<const std::uint8_t> options) noexcept;
[[nodiscard]] std::optional<std::size_t> encode_ia_ta(
    std::span<std::uint8_t> output, std::uint32_t iaid,
    std::span<const std::uint8_t> options) noexcept;
[[nodiscard]] std::optional<std::size_t> encode_ia_address(
    std::span<std::uint8_t> output, Ipv6 address,
    std::uint32_t preferred_lifetime, std::uint32_t valid_lifetime,
    std::span<const std::uint8_t> options = {}) noexcept;
[[nodiscard]] std::optional<std::size_t> encode_ia_prefix(
    std::span<std::uint8_t> output, Ipv6 prefix, std::uint8_t prefix_length,
    std::uint32_t preferred_lifetime, std::uint32_t valid_lifetime,
    std::span<const std::uint8_t> options = {}) noexcept;

struct StatusCodeView {
  std::uint16_t code{};
  // The UTF-8 status text is opaque diagnostic data. The protocol does not
  // require the transport owner to normalize or terminate it.
  std::span<const std::uint8_t> message{};
};

[[nodiscard]] std::optional<StatusCodeView>
parse_status_code(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] std::optional<std::size_t> encode_status_code(
    std::span<std::uint8_t> output, std::uint16_t code,
    std::span<const std::uint8_t> message = {}) noexcept;

class Ipv6AddressSequenceView final {
public:
  explicit Ipv6AddressSequenceView(
      std::span<const std::uint8_t> bytes) noexcept
      : bytes_(bytes) {}
  [[nodiscard]] std::size_t size() const noexcept {
    return bytes_.size() / Ipv6{}.size();
  }
  [[nodiscard]] Ipv6 operator[](std::size_t index) const noexcept;

private:
  std::span<const std::uint8_t> bytes_{};
};

// RFC 3646 requires one or more complete 16-octet addresses in preference
// order. The view has no implementation-defined server-count ceiling.
[[nodiscard]] std::optional<Ipv6AddressSequenceView>
parse_dns_recursive_name_servers(
    std::span<const std::uint8_t> data) noexcept;

class DomainSearchListView final {
public:
  explicit DomainSearchListView(std::span<const std::uint8_t> bytes) noexcept
      : bytes_(bytes) {}

  // Construction is restricted to parse_domain_search_list, so both methods
  // may walk borrowed bytes without repeating malformed-input branches. No
  // count ceiling exists below the DHCP option's ordinary wire length.
  [[nodiscard]] std::size_t size() const noexcept;
  [[nodiscard]] dns::Name operator[](std::size_t index) const noexcept;

private:
  std::span<const std::uint8_t> bytes_{};
};

// RFC 3646 and RFC 3315 section 8 encode adjacent ordinary DNS names and
// explicitly prohibit compression. An empty list is structurally valid
// because RFC 3646 defines no nonzero option-length requirement.
[[nodiscard]] std::optional<DomainSearchListView>
parse_domain_search_list(std::span<const std::uint8_t> data) noexcept;

// DUIDs remain opaque everywhere after creation. RFC 9915 explicitly forbids
// clients and servers from restricting them to currently known types or
// extracting link-layer identity. Validation therefore enforces length only.
[[nodiscard]] bool valid_duid(std::span<const std::uint8_t> data) noexcept;

// The browser project provides and persists generation time. The core never
// substitutes steady_clock for the RFC epoch or regenerates a DUID after a MAC
// change. Ethernet hardware type 1 and canonical MAC order follow RFC 9915.
[[nodiscard]] std::optional<std::size_t>
encode_duid_llt_ethernet(std::span<std::uint8_t> output, Mac address,
                         std::uint32_t seconds_since_2000) noexcept;

} // namespace router::packet::dhcpv6
