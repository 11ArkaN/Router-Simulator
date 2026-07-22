// DNS endpoint integration test. A resolver and authoritative fixture exchange
// an actual UDP query and response after ARP, using only encoded Ethernet
// frames and endpoint socket queues.

#include "../src/dns_endpoint_service.hpp"

#include <array>
#include <memory>
#include <stdexcept>
#include <vector>

namespace {

router::crypto::Sha256Digest dns_secret(std::uint8_t seed) {
  router::crypto::Sha256Digest result{};
  for (std::size_t index = 0U; index < result.size(); ++index)
    result[index] = static_cast<std::uint8_t>(seed + index);
  return result;
}

router::packet::dns::Name dns_name(const char *text) {
  const auto value = router::packet::dns::name_from_text(text);
  if (!value)
    throw std::runtime_error("DNS endpoint fixture name is invalid");
  return *value;
}

std::vector<std::uint8_t> dns_name_data(const char *text) {
  const auto value = dns_name(text);
  return {value.wire.begin(), value.wire.begin() + value.octets};
}

void append_dns_u32(std::vector<std::uint8_t> &bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
  bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
  bytes.push_back(static_cast<std::uint8_t>(value));
}

struct DnsEgress {
  std::vector<router::packet::Frame> frames;
  std::size_t available{256U};
};

bool collect_dns_frame(void *context,
                       const router::packet::Frame &frame) noexcept {
  static_cast<DnsEgress *>(context)->frames.push_back(frame);
  return true;
}

bool admit_dns_frames(void *context, std::size_t count) noexcept {
  return count <= static_cast<DnsEgress *>(context)->available;
}

router::dns::EndpointServiceCheckpoint dns_checkpoint(
    const router::network_detail::DnsEndpointService &service,
    router::network_detail::DnsEndpointService::Clock::time_point now) {
  auto saved = service.checkpoint(now);
  if (!saved)
    throw std::runtime_error("DNS endpoint checkpoint export failed");
  return std::move(*saved);
}

} // namespace

void dns_endpoint_service_tests() {
  using namespace router;
  using namespace router::network_detail;
  using namespace router::packet::dns;

  const NetworkEndpointConfiguration client_configuration{
      .endpoint_mac = {0x02U, 0U, 0U, 0U, 0x53U, 1U},
      .endpoint_address = {192U, 0U, 2U, 10U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 5301U,
      .endpoint_transport_secret = dns_secret(1U)};
  const NetworkEndpointConfiguration server_configuration{
      .endpoint_mac = {0x02U, 0U, 0U, 0U, 0x53U, 2U},
      .endpoint_address = {192U, 0U, 2U, 53U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 5302U,
      .endpoint_transport_secret = dns_secret(2U)};
  auto client = std::make_unique<EndpointStack>();
  auto server = std::make_unique<EndpointStack>();
  if (!client->configure(client_configuration) ||
      !server->configure(server_configuration))
    throw std::runtime_error("DNS endpoint hosts did not configure");
  const auto now = EndpointStack::Clock::now();
  client->set_link_state(true, now);
  server->set_link_state(true, now);

  DnsEndpointService service;
  dns::ServerAddress server_address{.family = transport::IpFamily::ipv4,
                                    .ipv4 =
                                        server_configuration.endpoint_address};
  if (!service.configure_resolver(dns_secret(3U),
                                  {{.server_name = dns_name("root.test."),
                                    .addresses = {server_address}}},
                                  {}, {}, false, *client))
    throw std::runtime_error("DNS resolver endpoint service did not configure");
  auto soa = dns_name_data("ns.test.");
  const auto mailbox = dns_name_data("hostmaster.test.");
  soa.insert(soa.end(), mailbox.begin(), mailbox.end());
  append_dns_u32(soa, 1U);
  append_dns_u32(soa, 3600U);
  append_dns_u32(soa, 600U);
  append_dns_u32(soa, 86400U);
  append_dns_u32(soa, 60U);
  const std::array<std::uint8_t, 4U> answer_address{198U, 51U, 100U, 10U};
  dns::Zone zone{dns_name("test.")};
  std::vector<dns::ZoneRecord> zone_records{
      {.owner = dns_name("test."), .type = type_soa, .ttl = 300U, .rdata = soa},
      {.owner = dns_name("test."),
       .type = type_ns,
       .ttl = 300U,
       .rdata = dns_name_data("ns.test.")},
      {.owner = dns_name("ns.test."),
       .type = type_a,
       .ttl = 300U,
       .rdata = {192U, 0U, 2U, 53U}},
      {.owner = dns_name("test."),
       .type = type_a,
       .ttl = 300U,
       .rdata = {answer_address.begin(), answer_address.end()}}};
  for (std::uint8_t record_index = 0U; record_index < 2U; ++record_index) {
    std::vector<std::uint8_t> text;
    for (std::size_t string_index = 0U; string_index < 3U; ++string_index) {
      text.push_back(200U);
      text.insert(text.end(), 200U,
                  static_cast<std::uint8_t>('a' + record_index + string_index));
    }
    zone_records.push_back({.owner = dns_name("large.test."),
                            .type = type_txt,
                            .ttl = 300U,
                            .rdata = std::move(text)});
  }
  if (!zone.replace(std::move(zone_records)))
    throw std::runtime_error("DNS authoritative fixture zone was rejected");
  DnsEndpointService authoritative;
  std::vector<dns::Zone> zones;
  zones.push_back(std::move(zone));
  if (!authoritative.configure_authoritative(std::move(zones), *server))
    throw std::runtime_error("DNS authoritative endpoint did not configure");
  const auto authoritative_checkpoint = dns_checkpoint(authoritative, now);
  if (!authoritative.restore(authoritative_checkpoint, *server, now))
    throw std::runtime_error("authoritative DNS service checkpoint failed");
  const Question question{.name = dns_name("test."),
                          .type = type_a,
                          .record_class = internet_class};
  const auto transaction = service.resolve(question, now);
  if (!transaction)
    throw std::runtime_error("DNS resolver query was rejected");

  DnsEgress egress;
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U || !packet::parse_arp(egress.frames.front()))
    throw std::runtime_error("DNS query bypassed IPv4 ARP resolution");
  const auto pending_checkpoint = dns_checkpoint(service, now);
  if (!pending_checkpoint.pending_query.active ||
      pending_checkpoint.pending_query.query_message.empty() ||
      !service.restore(pending_checkpoint, *client, now))
    throw std::runtime_error("pending DNS query did not survive checkpoint");
  auto corrupt_checkpoint = pending_checkpoint;
  corrupt_checkpoint.pending_query.stream_write_offset =
      corrupt_checkpoint.pending_query.stream_wire.size() + 1U;
  if (service.restore(corrupt_checkpoint, *client, now))
    throw std::runtime_error("corrupt DNS service checkpoint was accepted");
  const auto arp_reply = server->receive(egress.frames.front(), 0U, false, now);
  if (arp_reply.count != 1U)
    throw std::runtime_error("DNS server did not answer client ARP");
  static_cast<void>(client->receive(arp_reply.frames.front(), 0U, false, now));

  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U || !packet::parse_ipv4(egress.frames.front()))
    throw std::runtime_error(
        "DNS UDP query did not enter Ethernet packet path");
  static_cast<void>(server->receive(egress.frames.front(), 0U, false, now));
  DnsEgress response_egress;
  static_cast<void>(authoritative.service(
      *server, &response_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now));
  if (response_egress.frames.size() != 1U)
    throw std::runtime_error("DNS authoritative UDP response did not send");
  static_cast<void>(
      client->receive(response_egress.frames.front(), 0U, false, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  const auto result = service.result(*transaction);
  if (!result || result->status != dns::ResolutionStatus::success ||
      result->answers.size() != 1U ||
      result->answers.front().rdata !=
          std::vector<std::uint8_t>{answer_address.begin(),
                                    answer_address.end()})
    throw std::runtime_error("DNS frame exchange did not resolve answer");

  // A 1,206-octet TXT RRset plus DNS metadata exceeds the resolver's 1,232
  // byte advertised UDP response after the complete RRset rule is applied.
  // The authoritative server sets TC and both services continue over a real
  // TCP handshake and length-prefixed stream without changing the question.
  const Question large_question{.name = dns_name("large.test."),
                                .type = type_txt,
                                .record_class = internet_class};
  const auto large_transaction = service.resolve(large_question, now);
  if (!large_transaction)
    throw std::runtime_error("large DNS transaction did not start");
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U)
    throw std::runtime_error("large DNS UDP query was not emitted");
  static_cast<void>(server->receive(egress.frames.front(), 0U, false, now));
  response_egress.frames.clear();
  static_cast<void>(authoritative.service(
      *server, &response_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now));
  if (response_egress.frames.size() != 1U)
    throw std::runtime_error(
        "truncated authoritative response was not emitted");
  static_cast<void>(
      client->receive(response_egress.frames.front(), 0U, false, now));

  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U)
    throw std::runtime_error("DNS TCP fallback did not emit SYN");
  const auto syn_ip = packet::parse_ipv4(egress.frames.front());
  const auto syn =
      syn_ip ? packet::tcp::parse_ipv4(
                   egress.frames.front().view().subspan(
                       packet::ethernet_header_octets + syn_ip->header_length,
                       syn_ip->total_length - syn_ip->header_length),
                   syn_ip->source, syn_ip->destination)
             : std::nullopt;
  if (!syn || (syn->flags & packet::tcp::syn) == 0U)
    throw std::runtime_error("DNS TCP fallback emitted a non-SYN frame");
  const auto syn_ack = server->receive(egress.frames.front(), 0U, false, now);
  if (syn_ack.count != 1U)
    throw std::runtime_error("authoritative DNS TCP listener omitted SYN-ACK");
  const auto final_ack =
      client->receive(syn_ack.frames.front(), 0U, false, now);
  if (final_ack.count != 1U)
    throw std::runtime_error("DNS TCP client omitted handshake ACK");
  static_cast<void>(server->receive(final_ack.frames.front(), 0U, false, now));

  response_egress.frames.clear();
  static_cast<void>(authoritative.service(
      *server, &response_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U)
    throw std::runtime_error("DNS TCP query bytes did not enter packet path");
  const auto query_ack = server->receive(egress.frames.front(), 0U, false, now);
  for (std::size_t index = 0U; index < query_ack.count; ++index)
    static_cast<void>(client->receive(query_ack.frames[index], 0U, false, now));

  response_egress.frames.clear();
  static_cast<void>(authoritative.service(
      *server, &response_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now));
  if (response_egress.frames.size() != 1U)
    throw std::runtime_error("DNS TCP authoritative answer was not emitted");
  const auto data_ack =
      client->receive(response_egress.frames.front(), 0U, false, now);
  for (std::size_t index = 0U; index < data_ack.count; ++index)
    static_cast<void>(server->receive(data_ack.frames[index], 0U, false, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  const auto large_result = service.result(*large_transaction);
  if (!large_result || large_result->status != dns::ResolutionStatus::success ||
      large_result->answers.size() != 2U)
    throw std::runtime_error("DNS TCP fallback did not return complete RRset");

  // Reconfigure the first host as a recursive server and drive a separate stub
  // through port 53. The stub request, iterative upstream query and recursive
  // reply each cross ARP, IPv4, UDP and Ethernet rather than a service call.
  if (!service.configure_resolver(dns_secret(4U),
                                  {{.server_name = dns_name("root.test."),
                                    .addresses = {server_address}}},
                                  {}, {}, true, *client))
    throw std::runtime_error("recursive DNS listener did not configure");
  const auto recursive_checkpoint = dns_checkpoint(service, now);
  if (!recursive_checkpoint.recursive_service_enabled ||
      !recursive_checkpoint.authoritative_ipv4_socket ||
      !service.restore(recursive_checkpoint, *client, now))
    throw std::runtime_error("recursive DNS listener checkpoint failed");

  const NetworkEndpointConfiguration stub_configuration{
      .endpoint_mac = {0x02U, 0U, 0U, 0U, 0x53U, 3U},
      .endpoint_address = {192U, 0U, 2U, 11U},
      .endpoint_prefix_length = 24U,
      .endpoint_gateway = {},
      .endpoint_mtu = 1500U,
      .endpoint_interface_id = 5303U,
      .endpoint_transport_secret = dns_secret(5U)};
  auto stub = std::make_unique<EndpointStack>();
  if (!stub->configure(stub_configuration))
    throw std::runtime_error("recursive DNS stub did not configure");
  stub->set_link_state(true, now);
  const auto stub_socket = stub->bind_udp({.family = transport::IpFamily::ipv4,
                                           .interface_id = stub->interface_id(),
                                           .port = 0U});
  if (!stub_socket)
    throw std::runtime_error("recursive DNS stub socket did not bind");
  std::array<std::uint8_t, 512U> stub_query_wire{};
  const auto stub_query_octets = encode_query(
      stub_query_wire, 0x5353U, question, true,
      std::optional<std::uint16_t>{std::uint16_t{1232U}}, false, true, false);
  if (!stub_query_octets)
    throw std::runtime_error("recursive DNS stub query did not encode");
  DnsEgress stub_egress;
  const auto send_stub_query = [&] {
    return stub->send_udp_ipv4(
        *stub_socket, client_configuration.endpoint_address, server_port,
        std::span<const std::uint8_t>{stub_query_wire}.first(
            *stub_query_octets),
        &stub_egress, collect_dns_frame, admit_dns_frames);
  };
  if (send_stub_query().status !=
          EndpointUdpSendStatus::neighbor_resolution_started ||
      stub_egress.frames.size() != 1U)
    throw std::runtime_error("recursive DNS stub omitted ARP");
  const auto recursive_arp =
      client->receive(stub_egress.frames.front(), 0U, false, now);
  if (recursive_arp.count != 1U)
    throw std::runtime_error("recursive server omitted stub ARP reply");
  static_cast<void>(
      stub->receive(recursive_arp.frames.front(), 0U, false, now));
  stub_egress.frames.clear();
  if (send_stub_query().status != EndpointUdpSendStatus::sent ||
      stub_egress.frames.size() != 1U)
    throw std::runtime_error("recursive DNS query did not enter UDP path");
  static_cast<void>(
      client->receive(stub_egress.frames.front(), 0U, false, now));

  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.size() != 1U)
    throw std::runtime_error("recursive server did not emit iterative query");
  if (packet::parse_arp(egress.frames.front())) {
    const auto upstream_arp =
        server->receive(egress.frames.front(), 0U, false, now);
    if (upstream_arp.count != 1U)
      throw std::runtime_error("recursive upstream omitted ARP reply");
    static_cast<void>(
        client->receive(upstream_arp.frames.front(), 0U, false, now));
    egress.frames.clear();
    static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                      admit_dns_frames, collect_dns_frame,
                                      admit_dns_frames, now));
  }
  if (egress.frames.size() != 1U || !packet::parse_ipv4(egress.frames.front()))
    throw std::runtime_error("recursive iterative query was not IPv4 UDP");
  const auto pending_recursive_checkpoint = dns_checkpoint(service, now);
  if (pending_recursive_checkpoint.recursive_udp_clients.size() != 1U ||
      !service.restore(pending_recursive_checkpoint, *client, now))
    throw std::runtime_error(
        "active recursive client did not survive checkpoint");
  static_cast<void>(server->receive(egress.frames.front(), 0U, false, now));
  response_egress.frames.clear();
  static_cast<void>(authoritative.service(
      *server, &response_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now));
  if (response_egress.frames.size() != 1U)
    throw std::runtime_error("recursive upstream did not answer");
  static_cast<void>(
      client->receive(response_egress.frames.front(), 0U, false, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.empty())
    static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                      admit_dns_frames, collect_dns_frame,
                                      admit_dns_frames, now));
  // The first recursive reply attempt needs the reverse neighbor entry only
  // if the request's ARP entry was not retained; either path remains encoded.
  if (!egress.frames.empty() && packet::parse_arp(egress.frames.front())) {
    const auto stub_arp_reply =
        stub->receive(egress.frames.front(), 0U, false, now);
    if (stub_arp_reply.count != 1U)
      throw std::runtime_error("stub omitted recursive reply ARP answer");
    static_cast<void>(
        client->receive(stub_arp_reply.frames.front(), 0U, false, now));
    egress.frames.clear();
    static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                      admit_dns_frames, collect_dns_frame,
                                      admit_dns_frames, now));
  }
  if (egress.frames.size() != 1U)
    throw std::runtime_error("recursive UDP answer was not emitted");
  static_cast<void>(stub->receive(egress.frames.front(), 0U, false, now));
  std::array<std::uint8_t, 2048U> stub_response_wire{};
  const auto stub_response =
      stub->receive_udp(*stub_socket, stub_response_wire);
  if (stub_response.status != transport::UdpReceiveStatus::delivered)
    throw std::runtime_error("stub did not receive recursive DNS response");
  std::array<Question, 1U> recursive_questions{};
  std::array<ResourceRecord, 2U> recursive_answers{};
  std::array<ResourceRecord, 1U> recursive_additionals{};
  const auto recursive_message =
      parse(std::span<const std::uint8_t>{stub_response_wire}.first(
                stub_response.metadata.payload_octets),
            {.questions = recursive_questions,
             .answers = recursive_answers,
             .authorities = {},
             .additionals = recursive_additionals});
  if (!recursive_message || recursive_message->header.id != 0x5353U ||
      !recursive_message->header.recursion_desired ||
      !recursive_message->header.recursion_available ||
      recursive_message->header.authentic_data ||
      recursive_message->answers.size() != 1U)
    throw std::runtime_error("recursive response flags or answer are wrong");

  // The same recursive role also accepts DNS over TCP on port 53. This query
  // is served from the recursive cache, but its handshake, stream length,
  // request bytes and response bytes still traverse modeled TCP frames.
  transport::tcp::EndpointBinding stub_tcp_binding{
      .family = transport::IpFamily::ipv4,
      .ipv4 = {},
      .ipv6 = {},
      .interface_id = stub->interface_id(),
      .port = 0U};
  transport::tcp::EndpointRemote recursive_remote{
      .ipv4 = client_configuration.endpoint_address,
      .ipv6 = {},
      .port = server_port};
  const auto opened =
      stub->connect_tcp(stub_tcp_binding, recursive_remote, {}, now);
  if (!opened.socket || !opened.emitted)
    throw std::runtime_error("recursive TCP stub did not emit SYN");
  const auto recursive_syn_ack = client->receive(opened.frame, 0U, false, now);
  if (recursive_syn_ack.count != 1U)
    throw std::runtime_error("recursive TCP listener omitted SYN-ACK");
  const auto recursive_final_ack =
      stub->receive(recursive_syn_ack.frames.front(), 0U, false, now);
  if (recursive_final_ack.count != 1U)
    throw std::runtime_error("recursive TCP stub omitted final ACK");
  static_cast<void>(
      client->receive(recursive_final_ack.frames.front(), 0U, false, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));

  std::array<std::uint8_t, 512U> tcp_query_message{};
  const auto tcp_query_octets =
      encode_query(tcp_query_message, 0x5454U, question, true, std::nullopt,
                   false, true, false);
  std::array<std::uint8_t, 514U> tcp_query_stream{};
  const auto tcp_stream_octets =
      tcp_query_octets
          ? encode_stream_message(
                tcp_query_stream,
                std::span<const std::uint8_t>{tcp_query_message}.first(
                    *tcp_query_octets))
          : std::nullopt;
  if (!tcp_stream_octets ||
      stub->write_tcp(*opened.socket,
                      std::span<const std::uint8_t>{tcp_query_stream}.first(
                          *tcp_stream_octets),
                      now) != *tcp_stream_octets)
    throw std::runtime_error("recursive TCP query stream was not buffered");
  const auto tcp_query_frame = stub->send_tcp(*opened.socket, true, now);
  if (!tcp_query_frame.emitted)
    throw std::runtime_error("recursive TCP query bytes were not emitted");
  const auto recursive_query_ack =
      client->receive(tcp_query_frame.frame, 0U, false, now);
  for (std::size_t index = 0U; index < recursive_query_ack.count; ++index)
    static_cast<void>(
        stub->receive(recursive_query_ack.frames[index], 0U, false, now));
  egress.frames.clear();
  static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                    admit_dns_frames, collect_dns_frame,
                                    admit_dns_frames, now));
  if (egress.frames.empty())
    static_cast<void>(service.service(*client, &egress, collect_dns_frame,
                                      admit_dns_frames, collect_dns_frame,
                                      admit_dns_frames, now));
  if (egress.frames.size() != 1U)
    throw std::runtime_error("recursive TCP response was not emitted");
  const auto recursive_response_ack =
      stub->receive(egress.frames.front(), 0U, false, now);
  for (std::size_t index = 0U; index < recursive_response_ack.count; ++index)
    static_cast<void>(
        client->receive(recursive_response_ack.frames[index], 0U, false, now));
  std::array<std::uint8_t, 1024U> tcp_response_stream{};
  const auto tcp_response_octets =
      stub->read_tcp(*opened.socket, tcp_response_stream, now);
  const auto tcp_response = decode_stream_message(
      std::span<const std::uint8_t>{tcp_response_stream}.first(
          tcp_response_octets));
  std::array<Question, 1U> tcp_response_questions{};
  std::array<ResourceRecord, 2U> tcp_response_answers{};
  const auto tcp_message =
      tcp_response
          ? parse(tcp_response->message, {.questions = tcp_response_questions,
                                          .answers = tcp_response_answers,
                                          .authorities = {},
                                          .additionals = {}})
          : std::nullopt;
  if (!tcp_message || tcp_message->header.id != 0x5454U ||
      !tcp_message->header.recursion_available ||
      tcp_message->answers.size() != 1U)
    throw std::runtime_error("recursive DNS over TCP response is wrong");

  // Adding or replacing authoritative zones on a process that also serves
  // recursion must not destroy a port-53 TCP session owned by the shared DNS
  // listener. Rebuild the zone from its serialized records so this assertion
  // also avoids relying on copyability of the authoritative zone owner.
  std::vector<dns::Zone> shared_role_zones;
  for (const auto &saved : authoritative_checkpoint.zones) {
    dns::Zone shared_role_zone{saved.origin};
    if (!shared_role_zone.replace(saved.records))
      throw std::runtime_error("shared-role DNS zone failed validation");
    shared_role_zones.push_back(std::move(shared_role_zone));
  }
  if (!service.configure_authoritative(std::move(shared_role_zones), *client) ||
      dns_checkpoint(service, now).authoritative_tcp_connections.size() != 1U)
    throw std::runtime_error(
        "authoritative reconfiguration destroyed recursive TCP state");
  service.remove_authoritative(*client);
  if (dns_checkpoint(service, now).authoritative_tcp_connections.size() != 1U)
    throw std::runtime_error(
        "authoritative removal destroyed recursive TCP state");

  // Removing an authoritative role must release both UDP bindings and TCP
  // listeners. A fresh service can immediately bind port 53 on the same host;
  // otherwise a listener generation leaked outside its application owner.
  const auto saved_authoritative = dns_checkpoint(authoritative, now);
  authoritative.remove_authoritative(*server);
  std::vector<dns::Zone> rebound_zones;
  for (const auto &saved : saved_authoritative.zones) {
    dns::Zone rebound{saved.origin};
    if (!rebound.replace(saved.records))
      throw std::runtime_error("saved DNS zone failed rebound validation");
    rebound_zones.push_back(std::move(rebound));
  }
  if (!authoritative.configure_authoritative(std::move(rebound_zones), *server))
    throw std::runtime_error("DNS service removal leaked port 53 bindings");

  // Managed signing remains on the DNS service owner. The test supplies wall
  // time explicitly, while steady time controls only the visit deadline. The
  // checkpoint contains sealed keys and unsigned source records, then restore
  // creates a fresh generation before reusing the live port-53 sockets.
  std::array<std::uint8_t, 32U> signing_key{};
  signing_key.fill(0x5aU);
  const std::array<std::uint8_t, 11U> signing_context{
      'd', 'n', 's', '/', 'p', 'r', 'o', 'j', 'e', 'c', 't'};
  if (!authoritative.initialize_signing_vault(signing_key, signing_context))
    throw std::runtime_error("DNS service rejected project signing vault");
  const dnssec::KeySchedule signing_schedule{.publish_at = 900U,
                                             .ready_at = 900U,
                                             .activate_at = 900U,
                                             .retire_at = 5000U,
                                             .dead_at = 5100U,
                                             .remove_at = 5200U};
  dnssec::ZoneKeyStore signing_keys;
  auto ksk =
      dnssec::ManagedKey::create(dnssec::KeyRole::key_signing, signing_schedule,
                                 dnssec::generate_signing_key(15U));
  auto zsk = dnssec::ManagedKey::create(dnssec::KeyRole::zone_signing,
                                        signing_schedule,
                                        dnssec::generate_signing_key(15U));
  if (!ksk || !zsk ||
      signing_keys.add(std::move(*ksk)).first !=
          dnssec::ZoneKeyMutation::applied ||
      signing_keys.add(std::move(*zsk)).first !=
          dnssec::ZoneKeyMutation::applied)
    throw std::runtime_error("DNS service signing keys were not created");
  const auto signed_origin = dns_name("signed.test.");
  std::vector<std::uint8_t> signed_soa = dns_name_data("ns.signed.test.");
  const auto signed_mailbox = dns_name_data("hostmaster.signed.test.");
  signed_soa.insert(signed_soa.end(), signed_mailbox.begin(),
                    signed_mailbox.end());
  signed_soa.resize(signed_soa.size() + 20U, 0U);
  std::vector<dns::ZoneRecord> signed_source{
      {.owner = signed_origin,
       .type = type_soa,
       .record_class = internet_class,
       .ttl = 60U,
       .rdata = std::move(signed_soa)},
      {.owner = signed_origin,
       .type = type_ns,
       .record_class = internet_class,
       .ttl = 60U,
       .rdata = dns_name_data("ns.signed.test.")},
      {.owner = dns_name("www.signed.test."),
       .type = type_a,
       .record_class = internet_class,
       .ttl = 30U,
       .rdata = {192U, 0U, 2U, 80U}}};
  auto signed_owner = dnssec::SignedZoneOwner::create(
      signed_origin, std::move(signed_source), std::move(signing_keys),
      {.dnskey_ttl = 60U,
       .denial_ttl = 30U,
       .denial_mode = dnssec::DenialMode::nsec,
       .timing = {.validity_seconds = 100U,
                  .refresh_seconds = 30U,
                  .resign_seconds = 10U,
                  .inception_offset_seconds = 5U}},
      1000U, now);
  std::vector<dnssec::SignedZoneOwner> managed_zones;
  if (signed_owner)
    managed_zones.push_back(std::move(*signed_owner));
  if (managed_zones.empty() || !authoritative.configure_signed_authoritative(
                                   std::move(managed_zones), *server))
    throw std::runtime_error("managed DNSSEC zone did not configure");
  const auto signed_checkpoint = dns_checkpoint(authoritative, now);
  if (signed_checkpoint.signed_zones.size() != 1U ||
      !signed_checkpoint.zones.empty() ||
      signed_checkpoint.signed_zones[0].statistics.generation != 1U)
    throw std::runtime_error("managed DNSSEC checkpoint omitted owner state");

  DnsEgress signed_egress;
  static_cast<void>(authoritative.service(
      *server, &signed_egress, collect_dns_frame, admit_dns_frames,
      collect_dns_frame, admit_dns_frames, now + std::chrono::seconds{10},
      1070U));
  const auto refreshed =
      dns_checkpoint(authoritative, now + std::chrono::seconds{10});
  if (refreshed.signed_zones[0].statistics.generation != 2U ||
      !authoritative.restore(refreshed, *server, now + std::chrono::seconds{20},
                             1071U))
    throw std::runtime_error("managed DNSSEC refresh or restore failed");
  const auto restored_signed =
      dns_checkpoint(authoritative, now + std::chrono::seconds{20});
  if (restored_signed.signed_zones[0].statistics.generation != 3U)
    throw std::runtime_error("DNSSEC restore trusted an old RRSIG generation");
}
