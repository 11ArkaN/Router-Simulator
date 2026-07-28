// DHCPv4 relay packet transformation. Modified packets are encoded into a
// canonical main option field, as allowed by RFC 3396, while unknown option
// bodies and their occurrence order remain intact.

#include "router/dhcpv4_relay.hpp"

#include <algorithm>
#include <array>

namespace router::dhcpv4 {
namespace {

[[nodiscard]] bool zero(packet::Ipv4 address) noexcept {
  return std::all_of(address.begin(), address.end(),
                     [](std::uint8_t octet) { return octet == 0U; });
}

[[nodiscard]] bool has_relay_information(
    const packet::dhcpv4::MessageView &message) noexcept {
  packet::dhcpv4::RawOptionCursor cursor{message};
  while (const auto option = cursor.next())
    if (option->code == static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::
                                relay_agent_information))
      return true;
  return false;
}

} // namespace

bool RelayAgent::configure(const RelayConfiguration &configuration) {
  // The enclosing Relay Agent Information option has its own one-octet
  // length. Validating the combined sub-option payload here makes an invalid
  // policy fail atomically at configuration time instead of surfacing later
  // as a misleading packet-buffer exhaustion error.
  const auto relay_information_octets =
      (configuration.circuit_id.empty()
           ? 0U
           : configuration.circuit_id.size() + 2U) +
      (configuration.remote_id.empty()
           ? 0U
           : configuration.remote_id.size() + 2U);
  if (!configuration.admin_enabled ||
      configuration.description.size() > 80U ||
      zero(configuration.gateway_address) ||
      configuration.servers.empty() ||
      configuration.servers.size() >
          device_catalog::dhcpv4_relay_servers_per_interface ||
      configuration.circuit_id.size() > 255U ||
      configuration.remote_id.size() > 255U ||
      configuration.remote_id_ascii.size() > 32U ||
      relay_information_octets > 255U ||
      configuration.maximum_hops == 0U ||
      configuration.maximum_hops > 16U)
    return false;
  for (const auto &server : configuration.servers)
    if (zero(server.address))
      return false;
  try {
    configuration_ = configuration;
  } catch (...) {
    return false;
  }
  configured_ = true;
  return true;
}

RelayResult RelayAgent::encode(
    const packet::dhcpv4::MessageView &message,
    std::span<std::uint8_t> output, bool add_information,
    bool strip_information) const noexcept {
  auto header = message;
  // Flattening overloaded fields requires clearing the original bytes and
  // omitting Option Overload. Every semantic occurrence is re-emitted below.
  header.server_name = {};
  header.file = {};
  auto writer = packet::dhcpv4::begin(output, header);
  if (!writer)
    return {.status = RelayStatus::output_too_small};

  packet::dhcpv4::RawOptionCursor cursor{message};
  while (const auto option = cursor.next()) {
    if (option->code == static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::option_overload))
      continue;
    if (option->code == static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::
                                relay_agent_information) &&
        strip_information)
      continue;
    if (option->code == static_cast<std::uint8_t>(
                            packet::dhcpv4::OptionCode::
                                relay_agent_information) &&
        add_information &&
        configuration_.existing_information ==
            ExistingRelayInformationAction::replace)
      continue;
    if (!writer->append(option->code, option->data))
      return {.status = RelayStatus::output_too_small};
  }
  if (!cursor.valid())
    return {.status = RelayStatus::malformed};

  if (add_information &&
      (!has_relay_information(message) ||
       configuration_.existing_information ==
           ExistingRelayInformationAction::replace)) {
    // RFC 3046 sub-options use one-octet code and length fields. Circuit ID is
    // sub-option 1 and Remote ID is sub-option 2.
    std::array<std::uint8_t, 514U> information{};
    std::size_t position = 0U;
    if (!configuration_.circuit_id.empty()) {
      information[position++] = 1U;
      information[position++] =
          static_cast<std::uint8_t>(configuration_.circuit_id.size());
      std::copy(configuration_.circuit_id.begin(),
                configuration_.circuit_id.end(),
                information.begin() +
                    static_cast<std::ptrdiff_t>(position));
      position += configuration_.circuit_id.size();
    }
    // `remote-id mac` identifies the client-facing endpoint. It therefore
    // cannot be precomputed when configuration is committed: each request may
    // carry a different RFC 2131 chaddr. SR OS documents this choice as the
    // client MAC, while RFC 3046 keeps the sub-option value opaque.
    std::span<const std::uint8_t> remote_id{configuration_.remote_id};
    if (configuration_.remote_id_source == RemoteIdSource::client_mac) {
      if (message.hardware_type != 1U ||
          message.hardware_length != packet::Mac{}.size())
        return {.status = RelayStatus::malformed};
      remote_id = std::span{message.client_hardware_address.data(),
                            packet::Mac{}.size()};
    }
    if (!remote_id.empty()) {
      information[position++] = 2U;
      information[position++] =
          static_cast<std::uint8_t>(remote_id.size());
      std::copy(remote_id.begin(), remote_id.end(),
                information.begin() +
                    static_cast<std::ptrdiff_t>(position));
      position += remote_id.size();
    }
    // The enclosing DHCP option length is one octet, so a combined payload
    // larger than 255 is invalid even if each sub-option fits independently.
    if (position > 255U ||
        !writer->append(
            static_cast<std::uint8_t>(
                packet::dhcpv4::OptionCode::relay_agent_information),
            std::span{information.data(), position}))
      return {.status = RelayStatus::output_too_small};
  }
  if (!writer->finish())
    return {.status = RelayStatus::output_too_small};
  return {.status = RelayStatus::forwarded,
          .message_octets = writer->view().size()};
}

RelayResult RelayAgent::forward_client(
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output,
    std::size_t server_index) const noexcept {
  if (!configured_)
    return {.status = RelayStatus::not_configured};
  if (server_index >= configuration_.servers.size())
    return {.status = RelayStatus::discarded};
  const auto message = packet::dhcpv4::parse(input);
  if (!message ||
      message->operation != packet::dhcpv4::Operation::boot_request)
    return {.status = RelayStatus::malformed};
  const auto type = packet::dhcpv4::message_type(*message);
  // A packet without DHCP Message Type is plain BOOTP. SR OS drops it by
  // default and relays it only when `relay-plain-bootp` is configured. A
  // malformed Message Type is deliberately treated the same at this layer:
  // neither case is valid DHCP input and neither may mutate relay state.
  if (!type && !configuration_.relay_plain_bootp)
    return {.status = RelayStatus::malformed};
  if (message->hops >= configuration_.maximum_hops)
    return {.status = RelayStatus::hop_limit};

  const auto existing = has_relay_information(*message);
  if (existing && zero(message->gateway_address) &&
      !configuration_.trusted_ingress)
    return {.status = RelayStatus::untrusted_relay_information};
  if (existing &&
      configuration_.existing_information ==
          ExistingRelayInformationAction::drop)
    return {.status = RelayStatus::discarded};

  auto forwarded = *message;
  ++forwarded.hops;
  // SR OS leaves giaddr out of a DHCPRELEASE unless the corresponding leaf is
  // enabled. Other initial client messages need giaddr so the server can
  // select the client link and the reply can return to this relay.
  const bool omit_release_gateway =
      type && *type == packet::dhcpv4::MessageType::release &&
      !configuration_.release_include_gateway_address;
  if (zero(forwarded.gateway_address) && !omit_release_gateway)
    forwarded.gateway_address = configuration_.gateway_address;
  auto result = encode(
      forwarded, output, true,
      configuration_.existing_information ==
          ExistingRelayInformationAction::replace);
  result.destination = configuration_.servers[server_index].address;
  return result;
}

RelayResult RelayAgent::forward_server(
    std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) const noexcept {
  if (!configured_)
    return {.status = RelayStatus::not_configured};
  const auto message = packet::dhcpv4::parse(input);
  if (!message ||
      message->operation != packet::dhcpv4::Operation::boot_reply ||
      message->gateway_address != configuration_.gateway_address)
    return {.status = RelayStatus::malformed};
  // This implementation is an Ethernet relay. RFC 1542 permits direct L2
  // delivery only when the BOOTP hardware tuple names an IEEE 802 address.
  // Rejecting another htype or an invalid length is safer than truncating an
  // opaque address into the six-octet Ethernet destination.
  if (message->hardware_type != 1U ||
      message->hardware_length != packet::Mac{}.size())
    return {.status = RelayStatus::malformed};

  auto result = encode(*message, output, false, true);
  std::copy_n(message->client_hardware_address.begin(),
              result.client_mac.size(), result.client_mac.begin());
  const auto broadcast = (message->flags & 0x8000U) != 0U;
  result.client_broadcast = broadcast;
  result.client_direct_l2 = !broadcast;
  result.destination = message->your_address;
  return result;
}

} // namespace router::dhcpv4
