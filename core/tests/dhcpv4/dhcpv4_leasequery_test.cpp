// RFC 6926 and RFC 7724 framing tests. These exercise TCP segmentation and
// coalescing at the codec boundary without replacing the real TCP endpoint
// used by runtime integration.

#include "router/dhcpv4_leasequery.hpp"

#include <array>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

std::vector<std::uint8_t>
query(router::packet::dhcpv4::MessageType type,
      bool hardware_identity = false) {
  using namespace router::packet::dhcpv4;
  std::vector<std::uint8_t> bytes(512U);
  MessageView header{
      .operation = Operation::boot_request,
      .hardware_type = static_cast<std::uint8_t>(hardware_identity ? 1U : 0U),
      .hardware_length =
          static_cast<std::uint8_t>(hardware_identity ? 6U : 0U),
      .transaction_id = 0x10203040U};
  auto writer = begin(bytes, header);
  const std::array message_type{static_cast<std::uint8_t>(type)};
  const std::array<std::uint8_t, 4U> query_start{0x65U, 0x43U, 0x21U, 0x10U};
  if (!writer ||
      !writer->append(static_cast<std::uint8_t>(OptionCode::message_type),
                      message_type) ||
      !writer->append(static_cast<std::uint8_t>(OptionCode::query_start_time),
                      query_start) ||
      !writer->finish())
    throw std::runtime_error("DHCPv4 Leasequery fixture encoding failed");
  bytes.resize(writer->view().size());
  return bytes;
}

} // namespace

void dhcpv4_leasequery_tests() {
  using namespace router::dhcpv4::leasequery;
  using namespace router::dhcpv4;
  using router::packet::dhcpv4::MessageType;

  const auto message = query(MessageType::bulk_lease_query);
  std::vector<std::uint8_t> framed(message.size() + frame_prefix_octets);
  const auto framed_size = encode_frame(message, framed);
  require(framed_size && *framed_size == framed.size(),
          "Bulk Leasequery TCP framing rejected a legal message");

  StreamDecoder stream;
  auto result = stream.ingest(std::span<const std::uint8_t>{framed}.first(1U));
  require(result.status == StreamStatus::need_more &&
              result.accepted_octets == 1U,
          "Leasequery stream did not retain a split length prefix");
  result = stream.ingest(
      std::span<const std::uint8_t>{framed}.subspan(1U, 17U));
  require(result.status == StreamStatus::need_more &&
              result.accepted_octets == 17U,
          "Leasequery stream did not retain a split DHCP payload");
  // A runtime checkpoint may occur between arbitrary TCP segments. Restoring
  // the decoder must preserve the exact prefix and payload fragment rather
  // than forcing the peer to restart a query on an already established TCB.
  const auto decoder_checkpoint = stream.checkpoint();
  StreamDecoder restored_stream;
  require(restored_stream.restore(decoder_checkpoint),
          "Leasequery stream rejected its own partial checkpoint");
  result =
      restored_stream.ingest(
          std::span<const std::uint8_t>{framed}.subspan(18U));
  require(result.status == StreamStatus::message_ready &&
              result.message.size() == message.size() &&
              std::ranges::equal(result.message, message),
          "restored Leasequery stream did not reconstruct exact TCP bytes");
  const auto parsed = parse_request(result.message);
  require(parsed && parsed->kind == RequestKind::bulk &&
              parsed->transaction_id == 0x10203040U &&
              parsed->query_start_time == 0x65432110U,
          "Bulk Leasequery request validation lost query identity or time");

  stream = {};
  std::vector<std::uint8_t> coalesced;
  coalesced.insert(coalesced.end(), framed.begin(), framed.end());
  coalesced.insert(coalesced.end(), framed.begin(), framed.end());
  result = stream.ingest(coalesced);
  require(result.status == StreamStatus::message_ready &&
              result.accepted_octets == framed.size(),
          "Leasequery stream consumed bytes belonging to the next frame");
  stream.consume();
  result = stream.ingest(
      std::span<const std::uint8_t>{coalesced}.subspan(framed.size()));
  require(result.status == StreamStatus::message_ready,
          "Leasequery stream could not drain a coalesced second frame");

  const auto invalid_active =
      query(MessageType::active_lease_query, true);
  require(!parse_request(invalid_active),
          "Active Leasequery accepted the forbidden hardware selector");

  const std::array<std::uint8_t, 2U> zero_length{};
  stream.reset();
  result = stream.ingest(zero_length);
  require(result.status == StreamStatus::malformed_length,
          "Leasequery stream accepted an impossible zero-length frame");

  const auto now = LeaseRepository::Clock::time_point{
      std::chrono::seconds{1000}};
  LeaseRepository repository;
  const Pool pool{
      .id = 1U,
      .scope = {.server_instance = 1U,
                .routing_context = 0U,
                .link_identity = 7U},
      .first = {192U, 0U, 2U, 10U},
      .last = {192U, 0U, 2U, 20U},
      .subnet_mask = {255U, 255U, 255U, 0U},
      .router = {192U, 0U, 2U, 1U},
      .lease_seconds = 3600U,
      .enabled = true};
  require(repository.configure(std::span{&pool, 1U}, {},
                               std::chrono::seconds{60},
                               std::chrono::seconds{3600}),
          "Leasequery repository fixture rejected its pool");
  ClientKey client{.bytes = {1U, 2U, 3U, 4U},
                   .octets = 4U,
                   .option_61 = true};
  const auto offered = repository.offer(
      pool.scope, client, 0x11223344U, std::nullopt, now);
  require(offered.status == AllocateStatus::offered &&
              repository.commit(pool.scope, client, 0x11223344U,
                                offered.address, now),
          "Leasequery fixture could not create an active binding");
  const auto *lease = repository.lease_for(pool.scope, client);
  require(lease && lease->revision != 0U &&
              repository.current_revision() == lease->revision,
          "Active Leasequery revision did not follow binding commit");

  RequestView all_request{
      .kind = RequestKind::bulk,
      .selector = SelectorKind::all_configured,
      .transaction_id = 0x55667788U,
      .requested_options = {
          static_cast<std::uint8_t>(
              router::packet::dhcpv4::OptionCode::base_time),
          static_cast<std::uint8_t>(
              router::packet::dhcpv4::OptionCode::start_time_of_state),
          static_cast<std::uint8_t>(
              router::packet::dhcpv4::OptionCode::dhcp_state)},
      .requested_option_octets = 3U};
  require(matches(all_request, *lease, 1700000000U, now),
          "Bulk Leasequery all-address selector rejected a binding");

  std::array<std::uint8_t, 1024U> response{};
  const auto response_size = encode_binding_reply(
      {.lease = lease,
       .pool = &pool,
       .address = lease->address,
       .server_identifier = {192U, 0U, 2U, 1U},
       .transaction_id = all_request.transaction_id,
       .base_time = 1700000000U,
       .requested_options =
           std::span{all_request.requested_options}.first(
               all_request.requested_option_octets),
       .now = now,
       .include_server_identifier = true,
       .active_query = false},
      response);
  const auto reply =
      response_size
          ? router::packet::dhcpv4::parse(
                std::span{response}.first(*response_size))
          : std::nullopt;
  require(reply && reply->client_address == lease->address &&
              router::packet::dhcpv4::message_type(*reply) ==
                  MessageType::lease_active,
          "Bulk Leasequery binding reply lost its address or message type");

  const auto revision_before_expiry = repository.current_revision();
  repository.expire(now + std::chrono::seconds{3601});
  lease = repository.lease_for(pool.scope, client);
  require(lease && lease->state == BindingState::expired &&
              lease->revision > revision_before_expiry,
          "Lease expiry did not create an Active Leasequery update");
}
