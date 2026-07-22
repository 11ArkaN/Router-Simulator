// DNS resolver transport integration. The resolver first prepares an
// application message; this owner commits its timeout only after EndpointStack
// admits the complete UDP datagram. Neighbor discovery retries therefore do
// not consume DNS attempts or invent a packet that never entered the link.

#include "dns_endpoint_service.hpp"

#include "router/dnssec_authoritative_response.hpp"

#include <algorithm>
#include <limits>

namespace router::network_detail {
namespace {

constexpr std::uint16_t dns_port = packet::dns::server_port;
constexpr std::size_t maximum_dns_message_octets =
    packet::dns::maximum_message_octets;

std::uint64_t dnssec_wall_clock_unix_seconds() noexcept {
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
  // A host clock before the Unix epoch is not a valid DNSSEC signing input.
  // Returning zero makes signed-zone poll fail safely through its inception
  // offset validation rather than converting a negative count to a huge time.
  return seconds < 0 ? 0U : static_cast<std::uint64_t>(seconds);
}

std::uint32_t dnssec_wall_clock_seconds(void *) noexcept {
  // DNSSEC uses serial arithmetic over the low 32 bits of POSIX time. The
  // callback is separate from steady-clock retransmission deadlines so a host
  // clock adjustment cannot expire transport attempts or move packet time.
  return static_cast<std::uint32_t>(dnssec_wall_clock_unix_seconds());
}

void erase_bytes(std::span<std::uint8_t> bytes) noexcept {
  // Volatile stores prevent dead-store elimination for the project wrapping
  // key without adding a second crypto-provider dependency to this owner.
  volatile std::uint8_t *cursor = bytes.data();
  for (std::size_t index{}; index < bytes.size(); ++index)
    cursor[index] = 0U;
}

dns::ServerAddress
source_address(const transport::UdpDatagramMetadata &metadata) noexcept {
  return {.family = metadata.family,
          .ipv4 = metadata.source_ipv4,
          .ipv6 = metadata.source_ipv6,
          .interface_id = metadata.family == transport::IpFamily::ipv6
                              ? metadata.interface_id
                              : 0U};
}

struct DecodedClientQuery {
  packet::dns::Question question;
  std::uint16_t id{};
  std::uint16_t udp_payload_bytes{512U};
  bool recursion_desired{};
  bool checking_disabled{};
  bool dnssec_ok{};
  bool understands_authenticated_data{};
  bool used_edns{};
};

std::optional<DecodedClientQuery>
decode_client_query(std::span<const std::uint8_t> request) {
  if (request.size() < packet::dns::header_octets)
    return std::nullopt;
  const auto read_count = [&](std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(request[offset]) << 8U) |
        request[offset + 1U]);
  };
  const auto questions_count = read_count(4U);
  const auto answers_count = read_count(6U);
  const auto authorities_count = read_count(8U);
  const auto additionals_count = read_count(10U);
  const auto flags = read_count(2U);
  if ((flags & 0x8000U) != 0U || questions_count != 1U)
    return std::nullopt;
  const auto minimum = static_cast<std::size_t>(questions_count) * 5U +
                       (static_cast<std::size_t>(answers_count) +
                        authorities_count + additionals_count) *
                           11U;
  if (minimum > request.size() - packet::dns::header_octets)
    return std::nullopt;
  std::vector<packet::dns::Question> questions(questions_count);
  std::vector<packet::dns::ResourceRecord> answers(answers_count);
  std::vector<packet::dns::ResourceRecord> authorities(authorities_count);
  std::vector<packet::dns::ResourceRecord> additionals(additionals_count);
  const auto parsed = packet::dns::parse(request, {.questions = questions,
                                                   .answers = answers,
                                                   .authorities = authorities,
                                                   .additionals = additionals});
  if (!parsed || parsed->header.opcode != 0U)
    return std::nullopt;
  const packet::dns::ResourceRecord *opt{};
  for (const auto &additional : parsed->additionals)
    if (additional.type == packet::dns::type_opt) {
      if (opt)
        return std::nullopt;
      opt = &additional;
    }
  if (opt && ((opt->ttl >> 16U) & 0xffU) != 0U)
    return std::nullopt;
  return DecodedClientQuery{
      .question = parsed->questions.front(),
      .id = parsed->header.id,
      .udp_payload_bytes = static_cast<std::uint16_t>(
          opt ? std::max<std::uint16_t>(512U, opt->record_class) : 512U),
      .recursion_desired = parsed->header.recursion_desired,
      .checking_disabled = parsed->header.checking_disabled,
      .dnssec_ok = opt && (opt->ttl & 0x8000U) != 0U,
      .understands_authenticated_data =
          parsed->header.authentic_data || (opt && (opt->ttl & 0x8000U) != 0U),
      .used_edns = opt != nullptr};
}

bool dnssec_meta_type(std::uint16_t type) noexcept {
  switch (type) {
  case packet::dns::type_ds:
  case packet::dns::type_dnskey:
  case packet::dns::type_rrsig:
  case packet::dns::type_nsec:
  case packet::dns::type_nsec3:
  case packet::dns::type_nsec3param:
    return true;
  default:
    return false;
  }
}

std::optional<std::size_t>
encode_recursive_admission_failure(const DecodedClientQuery &query,
                                   std::span<std::uint8_t> output) noexcept {
  // RFC 1035 assigns SERVFAIL to a server that cannot complete an otherwise
  // valid request. Exhausting the bounded resolver transaction table is a
  // local server failure, not a policy refusal and not permission to drop a
  // well-formed UDP request silently. Copying RD and CD lets the client match
  // the response semantics to its request, while RA states that recursion is
  // normally available even though this particular request was not admitted.
  return packet::dns::encode_error_response(
      output, query.id, 0U, packet::dns::Rcode::server_failure,
      query.recursion_desired, query.checking_disabled, true);
}

} // namespace

DnsEndpointService::~DnsEndpointService() {
  erase_bytes(signing_wrapping_key_);
}

bool DnsEndpointService::configure_resolver(
    crypto::Sha256Digest identifier_secret,
    std::vector<dns::RootHint> root_hints,
    std::vector<dns::ZoneRecord> trust_anchors,
    dnssec::Nsec3IterationPolicy nsec3_policy, bool serve_clients,
    EndpointStack &endpoint) {
  try {
    const auto was_serving_clients = recursive_service_enabled_;
    auto staged = std::make_unique<dns::IterativeResolver>(
        identifier_secret, std::move(root_hints));
    if (!trust_anchors.empty()) {
#ifdef __EMSCRIPTEN__
      dnssec::TrustAnchorStore anchors;
      for (const auto &anchor : trust_anchors)
        if (anchors.add(anchor) != dnssec::AnchorMutation::applied)
          return false;
      if (!staged->enable_dnssec(
              {.crypto = &dnssec_crypto_,
               .digests = &dnssec_crypto_,
               .wall_clock_seconds = dnssec_wall_clock_seconds,
               .wall_clock_context = nullptr,
               .trust_anchors = std::move(anchors),
               .nsec3_policy = nsec3_policy}))
        return false;
#else
      // Native builds intentionally lack a second ambient crypto stack. Tests
      // inject deterministic providers directly into IterativeResolver.
      // The policy is consumed by the Wasm crypto branch above. Explicitly
      // mark that configuration value observed here so warning-as-error native
      // builds do not mistake the intentional platform boundary for dead API.
      static_cast<void>(nsec3_policy);
      return false;
#endif
    }
    // All allocations are admitted before binding a socket. A later failure
    // can therefore roll back only endpoint handles and never leak a newly
    // bound port because a vector resize threw after the bind.
    std::vector<std::uint8_t> query(maximum_dns_message_octets);
    std::vector<std::uint8_t> response(maximum_dns_message_octets);
    std::vector<std::uint8_t> server_request = authoritative_request_wire_;
    std::vector<std::uint8_t> server_response = authoritative_response_wire_;
    if (serve_clients && server_request.empty()) {
      server_request.resize(maximum_dns_message_octets);
      server_response.resize(maximum_dns_message_octets);
    }
    auto ipv4_socket = ipv4_socket_;
    auto ipv6_socket = ipv6_socket_;
    if (!ipv4_socket)
      ipv4_socket = endpoint.bind_udp({.family = transport::IpFamily::ipv4,
                                       .interface_id = endpoint.interface_id(),
                                       .port = 0U});
    if (!ipv6_socket)
      ipv6_socket = endpoint.bind_udp({.family = transport::IpFamily::ipv6,
                                       .interface_id = endpoint.interface_id(),
                                       .port = 0U});
    if (!ipv4_socket || !ipv6_socket) {
      if (!ipv4_socket_ && ipv4_socket)
        static_cast<void>(endpoint.close_udp(*ipv4_socket));
      if (!ipv6_socket_ && ipv6_socket)
        static_cast<void>(endpoint.close_udp(*ipv6_socket));
      return false;
    }
    auto server_ipv4_socket = authoritative_ipv4_socket_;
    auto server_ipv6_socket = authoritative_ipv6_socket_;
    auto server_ipv4_listener = authoritative_ipv4_listener_;
    auto server_ipv6_listener = authoritative_ipv6_listener_;
    if (serve_clients) {
      if (!server_ipv4_socket)
        server_ipv4_socket =
            endpoint.bind_udp({.family = transport::IpFamily::ipv4,
                               .interface_id = endpoint.interface_id(),
                               .port = dns_port});
      if (!server_ipv6_socket)
        server_ipv6_socket =
            endpoint.bind_udp({.family = transport::IpFamily::ipv6,
                               .interface_id = endpoint.interface_id(),
                               .port = dns_port});
      if (!server_ipv4_listener)
        server_ipv4_listener =
            endpoint.listen_tcp({.family = transport::IpFamily::ipv4,
                                 .interface_id = endpoint.interface_id(),
                                 .port = dns_port});
      if (!server_ipv6_listener)
        server_ipv6_listener =
            endpoint.listen_tcp({.family = transport::IpFamily::ipv6,
                                 .interface_id = endpoint.interface_id(),
                                 .port = dns_port});
      if (!server_ipv4_socket || !server_ipv6_socket || !server_ipv4_listener ||
          !server_ipv6_listener) {
        if (!authoritative_ipv4_socket_ && server_ipv4_socket)
          static_cast<void>(endpoint.close_udp(*server_ipv4_socket));
        if (!authoritative_ipv6_socket_ && server_ipv6_socket)
          static_cast<void>(endpoint.close_udp(*server_ipv6_socket));
        if (!authoritative_ipv4_listener_ && server_ipv4_listener)
          static_cast<void>(endpoint.destroy_tcp(*server_ipv4_listener));
        if (!authoritative_ipv6_listener_ && server_ipv6_listener)
          static_cast<void>(endpoint.destroy_tcp(*server_ipv6_listener));
        if (!ipv4_socket_ && ipv4_socket)
          static_cast<void>(endpoint.close_udp(*ipv4_socket));
        if (!ipv6_socket_ && ipv6_socket)
          static_cast<void>(endpoint.close_udp(*ipv6_socket));
        return false;
      }
    }
    for (const auto &connection : resolver_tcp_connections_)
      static_cast<void>(endpoint.destroy_tcp(connection.socket));
    resolver_ = std::move(staged);
    ipv4_socket_ = ipv4_socket;
    ipv6_socket_ = ipv6_socket;
    transactions_.clear();
    resolver_tcp_connections_.clear();
    query_wire_ = std::move(query);
    response_wire_ = std::move(response);
    pending_ = {};
    recursive_udp_clients_.clear();
    recursive_service_enabled_ = serve_clients;
    if (serve_clients) {
      authoritative_ipv4_socket_ = server_ipv4_socket;
      authoritative_ipv6_socket_ = server_ipv6_socket;
      authoritative_ipv4_listener_ = server_ipv4_listener;
      authoritative_ipv6_listener_ = server_ipv6_listener;
      authoritative_request_wire_ = std::move(server_request);
      authoritative_response_wire_ = std::move(server_response);
    } else if (was_serving_clients && zones_.empty() && signed_zones_.empty()) {
      if (authoritative_ipv4_socket_)
        static_cast<void>(endpoint.close_udp(*authoritative_ipv4_socket_));
      if (authoritative_ipv6_socket_)
        static_cast<void>(endpoint.close_udp(*authoritative_ipv6_socket_));
      if (authoritative_ipv4_listener_)
        static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv4_listener_));
      if (authoritative_ipv6_listener_)
        static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv6_listener_));
      for (const auto &connection : authoritative_tcp_connections_)
        static_cast<void>(endpoint.destroy_tcp(connection.socket));
      authoritative_ipv4_socket_.reset();
      authoritative_ipv6_socket_.reset();
      authoritative_ipv4_listener_.reset();
      authoritative_ipv6_listener_.reset();
      authoritative_tcp_connections_.clear();
      authoritative_request_wire_.clear();
      authoritative_response_wire_.clear();
      pending_response_ = {};
    }
    return true;
  } catch (...) {
    return false;
  }
}

void DnsEndpointService::remove_resolver(EndpointStack &endpoint) noexcept {
  const auto close_server_endpoints =
      recursive_service_enabled_ && zones_.empty() && signed_zones_.empty();
  if (ipv4_socket_)
    static_cast<void>(endpoint.close_udp(*ipv4_socket_));
  if (ipv6_socket_)
    static_cast<void>(endpoint.close_udp(*ipv6_socket_));
  ipv4_socket_.reset();
  ipv6_socket_.reset();
  resolver_.reset();
  transactions_.clear();
  for (const auto &connection : resolver_tcp_connections_)
    static_cast<void>(endpoint.destroy_tcp(connection.socket));
  resolver_tcp_connections_.clear();
  std::vector<std::uint8_t>{}.swap(query_wire_);
  std::vector<std::uint8_t>{}.swap(response_wire_);
  pending_ = {};
  recursive_udp_clients_.clear();
  recursive_service_enabled_ = false;
  if (close_server_endpoints) {
    if (authoritative_ipv4_socket_)
      static_cast<void>(endpoint.close_udp(*authoritative_ipv4_socket_));
    if (authoritative_ipv6_socket_)
      static_cast<void>(endpoint.close_udp(*authoritative_ipv6_socket_));
    for (const auto &connection : authoritative_tcp_connections_)
      static_cast<void>(endpoint.destroy_tcp(connection.socket));
    if (authoritative_ipv4_listener_)
      static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv4_listener_));
    if (authoritative_ipv6_listener_)
      static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv6_listener_));
    authoritative_ipv4_socket_.reset();
    authoritative_ipv6_socket_.reset();
    authoritative_ipv4_listener_.reset();
    authoritative_ipv6_listener_.reset();
    authoritative_tcp_connections_.clear();
    authoritative_request_wire_.clear();
    authoritative_response_wire_.clear();
    pending_response_ = {};
  }
}

bool DnsEndpointService::configure_authoritative(std::vector<dns::Zone> zones,
                                                 EndpointStack &endpoint) {
  if (zones.empty() ||
      std::any_of(zones.begin(), zones.end(),
                  [](const auto &zone) { return zone.records().empty(); }))
    return false;
  for (std::size_t index = 0U; index < zones.size(); ++index)
    for (std::size_t previous = 0U; previous < index; ++previous)
      if (packet::dns::equal_case_insensitive(zones[index].origin(),
                                              zones[previous].origin()))
        return false;
  try {
    auto ipv4_socket = authoritative_ipv4_socket_;
    auto ipv6_socket = authoritative_ipv6_socket_;
    auto ipv4_listener = authoritative_ipv4_listener_;
    auto ipv6_listener = authoritative_ipv6_listener_;
    if (!ipv4_socket)
      ipv4_socket = endpoint.bind_udp({.family = transport::IpFamily::ipv4,
                                       .interface_id = endpoint.interface_id(),
                                       .port = dns_port});
    if (!ipv6_socket)
      ipv6_socket = endpoint.bind_udp({.family = transport::IpFamily::ipv6,
                                       .interface_id = endpoint.interface_id(),
                                       .port = dns_port});
    if (!ipv4_listener)
      ipv4_listener =
          endpoint.listen_tcp({.family = transport::IpFamily::ipv4,
                               .interface_id = endpoint.interface_id(),
                               .port = dns_port});
    if (!ipv6_listener)
      ipv6_listener =
          endpoint.listen_tcp({.family = transport::IpFamily::ipv6,
                               .interface_id = endpoint.interface_id(),
                               .port = dns_port});
    if (!ipv4_socket || !ipv6_socket || !ipv4_listener || !ipv6_listener) {
      if (!authoritative_ipv4_socket_ && ipv4_socket)
        static_cast<void>(endpoint.close_udp(*ipv4_socket));
      if (!authoritative_ipv6_socket_ && ipv6_socket)
        static_cast<void>(endpoint.close_udp(*ipv6_socket));
      if (!authoritative_ipv4_listener_ && ipv4_listener)
        static_cast<void>(endpoint.close_tcp(*ipv4_listener));
      if (!authoritative_ipv6_listener_ && ipv6_listener)
        static_cast<void>(endpoint.close_tcp(*ipv6_listener));
      return false;
    }
    std::vector<std::uint8_t> request(maximum_dns_message_octets);
    std::vector<std::uint8_t> response(maximum_dns_message_octets);
    // TCP port 53 is shared by the authoritative and recursive roles. Existing
    // connections own framed requests and possibly active recursive resolver
    // transactions. A zone replacement changes only future authoritative
    // lookups, so destroying this collection here would also tear down an
    // unrelated recursive session and violate the role boundary.
    zones_ = std::move(zones);
    // Plain and managed-signed zone generations are mutually exclusive
    // configuration forms for one endpoint. A successful replacement clears
    // the previous owner set only after all sockets and buffers are admitted.
    signed_zones_.clear();
    authoritative_ipv4_socket_ = ipv4_socket;
    authoritative_ipv6_socket_ = ipv6_socket;
    authoritative_ipv4_listener_ = ipv4_listener;
    authoritative_ipv6_listener_ = ipv6_listener;
    authoritative_request_wire_ = std::move(request);
    authoritative_response_wire_ = std::move(response);
    pending_response_ = {};
    return true;
  } catch (...) {
    return false;
  }
}

bool DnsEndpointService::initialize_signing_vault(
    std::span<const std::uint8_t> wrapping_key,
    std::span<const std::uint8_t> project_context) noexcept {
  if (wrapping_key.size() != signing_wrapping_key_.size() ||
      project_context.empty() ||
      std::ranges::none_of(wrapping_key,
                           [](const auto byte) { return byte != 0U; }))
    return false;
  try {
    if (signing_vault_initialized_) {
      // Replacing entropy while live provider keys exist would make the next
      // checkpoint unrestorable. Key rotation needs a separate transactional
      // rewrap operation and is therefore rejected by this initializer.
      return std::ranges::equal(signing_wrapping_key_, wrapping_key) &&
             std::ranges::equal(signing_vault_context_, project_context);
    }
    std::vector<std::uint8_t> context{project_context.begin(),
                                      project_context.end()};
    std::ranges::copy(wrapping_key, signing_wrapping_key_.begin());
    signing_vault_context_ = std::move(context);
    signing_vault_initialized_ = true;
    return true;
  } catch (...) {
    erase_bytes(signing_wrapping_key_);
    signing_vault_context_.clear();
    signing_vault_initialized_ = false;
    return false;
  }
}

bool DnsEndpointService::configure_signed_authoritative(
    std::vector<dnssec::SignedZoneOwner> zones, EndpointStack &endpoint) {
  if (!signing_vault_initialized_ || zones.empty())
    return false;
  try {
    std::vector<dns::Zone> validation;
    validation.reserve(zones.size());
    for (std::size_t index{}; index < zones.size(); ++index) {
      for (std::size_t previous{}; previous < index; ++previous)
        if (packet::dns::equal_case_insensitive(zones[index].origin(),
                                                zones[previous].origin()))
          return false;
      dns::Zone candidate{zones[index].origin()};
      if (!candidate.replace(std::vector<dns::ZoneRecord>(
              zones[index].records().begin(), zones[index].records().end())))
        return false;
      validation.push_back(std::move(candidate));
    }
    // Reuse the existing all-or-nothing socket admission. Its successful
    // plain generation is immediately replaced by the already validated
    // move-only owners before this shard can process another mailbox turn.
    if (!configure_authoritative(std::move(validation), endpoint))
      return false;
    zones_.clear();
    signed_zones_ = std::move(zones);
    return true;
  } catch (...) {
    return false;
  }
}

void DnsEndpointService::remove_authoritative(
    EndpointStack &endpoint) noexcept {
  zones_.clear();
  signed_zones_.clear();
  if (recursive_service_enabled_)
    return;
  if (authoritative_ipv4_socket_)
    static_cast<void>(endpoint.close_udp(*authoritative_ipv4_socket_));
  if (authoritative_ipv6_socket_)
    static_cast<void>(endpoint.close_udp(*authoritative_ipv6_socket_));
  authoritative_ipv4_socket_.reset();
  authoritative_ipv6_socket_.reset();
  for (const auto &connection : authoritative_tcp_connections_)
    static_cast<void>(endpoint.destroy_tcp(connection.socket));
  authoritative_tcp_connections_.clear();
  if (authoritative_ipv4_listener_)
    static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv4_listener_));
  if (authoritative_ipv6_listener_)
    static_cast<void>(endpoint.destroy_tcp(*authoritative_ipv6_listener_));
  authoritative_ipv4_listener_.reset();
  authoritative_ipv6_listener_.reset();
  std::vector<std::uint8_t>{}.swap(authoritative_request_wire_);
  std::vector<std::uint8_t>{}.swap(authoritative_response_wire_);
  pending_response_ = {};
}

const dns::Zone *DnsEndpointService::authoritative_zone(
    const packet::dns::Name &name) const noexcept {
  const dns::Zone *selected{};
  const auto consider = [&](const dns::Zone &candidate) noexcept {
    if (dns::is_subdomain(name, candidate.origin()) &&
        (!selected || candidate.origin().octets > selected->origin().octets))
      selected = &candidate;
  };
  for (const auto &candidate : zones_)
    consider(candidate);
  for (const auto &candidate : signed_zones_)
    consider(candidate.zone());
  return selected;
}

std::optional<std::size_t> DnsEndpointService::build_authoritative_response(
    std::span<const std::uint8_t> request, std::span<std::uint8_t> output,
    bool udp) const noexcept {
  if (request.size() < packet::dns::header_octets || output.empty())
    return std::nullopt;
  try {
    const auto read_count = [&](std::size_t offset) noexcept {
      return static_cast<std::uint16_t>(
          (static_cast<std::uint16_t>(request[offset]) << 8U) |
          request[offset + 1U]);
    };
    const auto question_count = read_count(4U);
    const auto answer_count = read_count(6U);
    const auto authority_count = read_count(8U);
    const auto additional_count = read_count(10U);
    const auto request_id = read_count(0U);
    const auto request_flags = read_count(2U);
    const auto request_is_response = (request_flags & 0x8000U) != 0U;
    const auto request_opcode =
        static_cast<std::uint8_t>((request_flags >> 11U) & 0x0fU);
    const auto error_response = [&](packet::dns::Rcode code) noexcept {
      // Servers do not answer packets already marked as responses. This avoids
      // a response loop if two port-53 services receive each other's traffic.
      return request_is_response ? std::optional<std::size_t>{}
                                 : packet::dns::encode_error_response(
                                       output, request_id, request_opcode, code,
                                       (request_flags & 0x0100U) != 0U,
                                       (request_flags & 0x0010U) != 0U,
                                       recursive_service_enabled_);
    };
    const auto minimum = static_cast<std::size_t>(question_count) * 5U +
                         (static_cast<std::size_t>(answer_count) +
                          authority_count + additional_count) *
                             11U;
    if (minimum > request.size() - packet::dns::header_octets)
      return error_response(packet::dns::Rcode::format_error);
    std::vector<packet::dns::Question> questions(question_count);
    std::vector<packet::dns::ResourceRecord> answers(answer_count);
    std::vector<packet::dns::ResourceRecord> authorities(authority_count);
    std::vector<packet::dns::ResourceRecord> additionals(additional_count);
    const auto parsed =
        packet::dns::parse(request, {.questions = questions,
                                     .answers = answers,
                                     .authorities = authorities,
                                     .additionals = additionals});
    if (!parsed)
      return error_response(packet::dns::Rcode::format_error);
    if (parsed->header.response)
      return std::nullopt;
    if (parsed->header.opcode != 0U)
      return error_response(packet::dns::Rcode::not_implemented);
    if (parsed->questions.size() != 1U)
      return error_response(packet::dns::Rcode::format_error);

    const auto &question = parsed->questions.front();
    const packet::dns::ResourceRecord *request_opt{};
    for (const auto &additional : parsed->additionals)
      if (additional.type == packet::dns::type_opt) {
        if (request_opt)
          return error_response(packet::dns::Rcode::format_error);
        request_opt = &additional;
      }
    const auto *zone = authoritative_zone(question.name);
    const auto unsupported_edns_version =
        request_opt && ((request_opt->ttl >> 16U) & 0xffU) != 0U;
    const auto dnssec_ok = request_opt && (request_opt->ttl & 0x8000U) != 0U;
    auto answer =
        unsupported_edns_version
            ? dns::AuthoritativeAnswer{.rcode = packet::dns::Rcode::no_error,
                                       .answers = {},
                                       .authorities = {},
                                       .additionals = {},
                                       .synthesized_rdata = {},
                                       .authoritative = false,
                                       .referral = false}
        : zone ? zone->answer(question)
               : dns::AuthoritativeAnswer{.rcode = packet::dns::Rcode::refused,
                                          .answers = {},
                                          .authorities = {},
                                          .additionals = {},
                                          .synthesized_rdata = {},
                                          .authoritative = false,
                                          .referral = false};
    if (zone && dnssec_ok && !unsupported_edns_version &&
        !dnssec::augment_authoritative_answer(*zone, question, answer,
#ifdef __EMSCRIPTEN__
                                              &dnssec_crypto_
#else
                                              nullptr
#endif
                                              ))
      return error_response(packet::dns::Rcode::server_failure);
    auto budget = output.size();
    if (udp) {
      budget = std::min<std::size_t>(512U, budget);
      if (request_opt) {
        budget = std::min<std::size_t>(
            output.size(),
            std::max<std::size_t>(512U, request_opt->record_class));
      }
    }
    return packet::dns::encode_response(
        output.first(budget), parsed->header.id, question, answer.answers,
        answer.authorities, answer.additionals,
        {.rcode = answer.rcode,
         .authoritative = answer.authoritative,
         .recursion_desired = parsed->header.recursion_desired,
         .recursion_available = recursive_service_enabled_,
         .checking_disabled = parsed->header.checking_disabled,
         .edns_udp_payload_size =
             request_opt
                 ? std::optional<
                       std::
                           uint16_t>{device_catalog::
                                         dns_resolver_advertised_udp_payload_bytes}
                 : std::nullopt,
         .edns_extended_rcode =
             static_cast<std::uint8_t>(unsupported_edns_version ? 1U : 0U),
         .edns_version = 0U,
         .dnssec_ok = dnssec_ok});
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<std::size_t> DnsEndpointService::build_recursive_response(
    const RecursiveUdpClient &client, const dns::ResolutionResult &result,
    std::span<std::uint8_t> output, bool udp) const noexcept {
  try {
    std::vector<packet::dns::RecordData> answers;
    std::vector<packet::dns::RecordData> authorities;
    const auto append_visible = [&](const auto &source, auto &destination) {
      destination.reserve(source.size());
      for (const auto &record : source) {
        // RFC 3225 removes DNSSEC metadata when the initiating request did not
        // set DO. An explicit query for that RR type still receives its answer.
        if (!client.dnssec_ok && dnssec_meta_type(record.type) &&
            record.type != client.question.type)
          continue;
        destination.push_back({.owner = record.owner,
                               .type = record.type,
                               .record_class = record.record_class,
                               .ttl = record.ttl,
                               .rdata = record.rdata});
      }
    };
    append_visible(result.answers, answers);
    append_visible(result.authorities, authorities);

    packet::dns::Rcode rcode = packet::dns::Rcode::server_failure;
    switch (result.status) {
    case dns::ResolutionStatus::success:
    case dns::ResolutionStatus::no_data:
      rcode = packet::dns::Rcode::no_error;
      break;
    case dns::ResolutionStatus::name_error:
      rcode = packet::dns::Rcode::name_error;
      break;
    case dns::ResolutionStatus::pending:
      return std::nullopt;
    case dns::ResolutionStatus::server_failure:
    case dns::ResolutionStatus::alias_loop:
    case dns::ResolutionStatus::no_reachable_server:
    case dns::ResolutionStatus::resource_exhausted:
      rcode = packet::dns::Rcode::server_failure;
      answers.clear();
      authorities.clear();
      break;
    }
    const auto budget =
        udp ? std::min<std::size_t>(output.size(),
                                    client.used_edns ? client.udp_payload_bytes
                                                     : 512U)
            : output.size();
    return packet::dns::encode_response(
        output.first(budget), client.request_id, client.question, answers,
        authorities, {},
        {.rcode = rcode,
         .authoritative = false,
         .recursion_desired = client.recursion_desired,
         .recursion_available = true,
         .authentic_data = result.security == dns::CacheSecurity::secure &&
                           client.understands_authenticated_data,
         .checking_disabled = client.checking_disabled,
         .edns_udp_payload_size =
             client.used_edns
                 ? std::optional<
                       std::
                           uint16_t>{device_catalog::
                                         dns_resolver_advertised_udp_payload_bytes}
                 : std::nullopt,
         .edns_extended_rcode = 0U,
         .edns_version = 0U,
         .dnssec_ok = client.dnssec_ok});
  } catch (...) {
    return std::nullopt;
  }
}

std::optional<dns::TransactionHandle>
DnsEndpointService::resolve(const packet::dns::Question &question,
                            Clock::time_point now) noexcept {
  if (!resolver_)
    return std::nullopt;
  const auto handle = resolver_->begin(question, now);
  if (!handle)
    return std::nullopt;
  try {
    transactions_.push_back(*handle);
    return handle;
  } catch (...) {
    static_cast<void>(resolver_->release(*handle));
    return std::nullopt;
  }
}

std::optional<dns::ResolutionResult>
DnsEndpointService::result(dns::TransactionHandle handle) const {
  return resolver_ ? resolver_->result(handle) : std::nullopt;
}

bool DnsEndpointService::release(dns::TransactionHandle handle) noexcept {
  if (!resolver_ || !resolver_->release(handle))
    return false;
  std::erase(transactions_, handle);
  if (pending_.active && pending_.transaction == handle)
    pending_ = {};
  return true;
}

std::optional<DnsEndpointService::Clock::time_point>
DnsEndpointService::next_deadline() const noexcept {
  // TCP, ARP, ND and reassembly deadlines are owned by EndpointStack. This
  // projection contains resolver retries and local signed-zone visits owned
  // by this service, never deadlines from another endpoint or global queue.
  auto next = resolver_ ? resolver_->next_deadline() : std::nullopt;
  for (const auto &zone : signed_zones_)
    if (!next || zone.next_deadline() < *next)
      next = zone.next_deadline();
  return next;
}

std::optional<dns::EndpointServiceCheckpoint>
DnsEndpointService::checkpoint(Clock::time_point now) const {
  try {
    dns::EndpointServiceCheckpoint state{
        .resolver = resolver_ ? std::optional{resolver_->checkpoint(now)}
                              : std::nullopt,
        .resolver_ipv4_socket = ipv4_socket_,
        .resolver_ipv6_socket = ipv6_socket_,
        .transactions = transactions_,
        .pending_query = {},
        .resolver_tcp_connections = {},
        .zones = {},
        .signed_zones = {},
        .authoritative_ipv4_socket = authoritative_ipv4_socket_,
        .authoritative_ipv6_socket = authoritative_ipv6_socket_,
        .authoritative_ipv4_listener = authoritative_ipv4_listener_,
        .authoritative_ipv6_listener = authoritative_ipv6_listener_,
        .authoritative_tcp_connections = {},
        .pending_response = {},
        .recursive_udp_clients = {},
        .recursive_service_enabled = recursive_service_enabled_};

    state.pending_query = {
        .transaction = pending_.transaction,
        .prepared = pending_.prepared,
        .query_message = pending_.active
                             ? std::vector<std::uint8_t>(
                                   query_wire_.begin(),
                                   query_wire_.begin() +
                                       static_cast<std::ptrdiff_t>(
                                           pending_.prepared.message_octets))
                             : std::vector<std::uint8_t>{},
        .stream_wire = pending_.stream_wire,
        .stream_write_offset = pending_.stream_write_offset,
        .active = pending_.active};
    state.resolver_tcp_connections.reserve(resolver_tcp_connections_.size());
    for (const auto &connection : resolver_tcp_connections_)
      state.resolver_tcp_connections.push_back(
          {.server = connection.server,
           .socket = connection.socket,
           .received_wire = std::vector<std::uint8_t>(
               connection.receive_wire.begin(),
               connection.receive_wire.begin() +
                   static_cast<std::ptrdiff_t>(connection.received_octets))});

    state.zones.reserve(zones_.size());
    for (const auto &zone : zones_)
      state.zones.push_back(
          {.origin = zone.origin(), .records = zone.records()});
    state.authoritative_tcp_connections.reserve(
        authoritative_tcp_connections_.size());
    for (const auto &connection : authoritative_tcp_connections_) {
      dns::AuthoritativeTcpConnectionCheckpoint saved{
          .socket = connection.socket,
          .family = connection.family,
          .received_wire = std::vector<std::uint8_t>(
              connection.receive_wire.begin(),
              connection.receive_wire.begin() +
                  static_cast<std::ptrdiff_t>(connection.received_octets)),
          .send_wire = connection.send_wire,
          .recursive_clients = {},
          .send_offset = connection.send_offset};
      saved.recursive_clients.reserve(connection.recursive_clients.size());
      for (const auto &client : connection.recursive_clients)
        saved.recursive_clients.push_back(
            {.transaction = client.transaction,
             .question = client.question,
             .destination_ipv4 = client.destination_ipv4,
             .destination_ipv6 = client.destination_ipv6,
             .family = client.family,
             .destination_port = client.destination_port,
             .request_id = client.request_id,
             .udp_payload_bytes = client.udp_payload_bytes,
             .recursion_desired = client.recursion_desired,
             .checking_disabled = client.checking_disabled,
             .dnssec_ok = client.dnssec_ok,
             .understands_authenticated_data =
                 client.understands_authenticated_data,
             .used_edns = client.used_edns});
      state.authoritative_tcp_connections.push_back(std::move(saved));
    }
    state.pending_response = {
        .family = pending_response_.family,
        .destination_ipv4 = pending_response_.destination_ipv4,
        .destination_ipv6 = pending_response_.destination_ipv6,
        .destination_port = pending_response_.destination_port,
        .message = pending_response_.active
                       ? std::vector<std::uint8_t>(
                             authoritative_response_wire_.begin(),
                             authoritative_response_wire_.begin() +
                                 static_cast<std::ptrdiff_t>(
                                     pending_response_.message_octets))
                       : std::vector<std::uint8_t>{},
        .active = pending_response_.active};
    state.recursive_udp_clients.reserve(recursive_udp_clients_.size());
    for (const auto &client : recursive_udp_clients_)
      state.recursive_udp_clients.push_back(
          {.transaction = client.transaction,
           .question = client.question,
           .destination_ipv4 = client.destination_ipv4,
           .destination_ipv6 = client.destination_ipv6,
           .family = client.family,
           .destination_port = client.destination_port,
           .request_id = client.request_id,
           .udp_payload_bytes = client.udp_payload_bytes,
           .recursion_desired = client.recursion_desired,
           .checking_disabled = client.checking_disabled,
           .dnssec_ok = client.dnssec_ok,
           .understands_authenticated_data =
               client.understands_authenticated_data,
           .used_edns = client.used_edns});
    if (!signed_zones_.empty() && !signing_vault_initialized_)
      return std::nullopt;
    state.signed_zones.reserve(signed_zones_.size());
    for (const auto &zone : signed_zones_) {
      auto saved =
          zone.checkpoint(signing_wrapping_key_, signing_vault_context_, now);
      if (!saved)
        return std::nullopt;
      state.signed_zones.push_back(std::move(*saved));
    }
    return state;
  } catch (...) {
    return std::nullopt;
  }
}

bool DnsEndpointService::restore(
    const dns::EndpointServiceCheckpoint &state, EndpointStack &endpoint,
    Clock::time_point now, std::optional<std::uint64_t> wall_now) noexcept {
  try {
    const auto valid_udp = [&](const auto &socket) noexcept {
      return !socket || endpoint.valid_udp(*socket);
    };
    const auto valid_tcp = [&](const auto &socket) noexcept {
      return !socket || endpoint.valid_tcp(*socket);
    };
    if (!valid_udp(state.resolver_ipv4_socket) ||
        !valid_udp(state.resolver_ipv6_socket) ||
        !valid_udp(state.authoritative_ipv4_socket) ||
        !valid_udp(state.authoritative_ipv6_socket) ||
        !valid_tcp(state.authoritative_ipv4_listener) ||
        !valid_tcp(state.authoritative_ipv6_listener))
      return false;
    if ((state.resolver &&
         (!state.resolver_ipv4_socket || !state.resolver_ipv6_socket)) ||
        ((!state.zones.empty() || !state.signed_zones.empty()) &&
         (!state.authoritative_ipv4_socket ||
          !state.authoritative_ipv6_socket ||
          !state.authoritative_ipv4_listener ||
          !state.authoritative_ipv6_listener)) ||
        (!state.zones.empty() && !state.signed_zones.empty()) ||
        (!state.signed_zones.empty() && !signing_vault_initialized_))
      return false;

    // DNS message sizes are protocol fields, not product ceilings. The two
    // extra TCP octets are the RFC 7766 stream length prefix.
    if ((state.pending_query.active &&
         (state.pending_query.query_message.size() !=
              state.pending_query.prepared.message_octets ||
          state.pending_query.query_message.size() >
              maximum_dns_message_octets)) ||
        state.pending_query.stream_wire.size() >
            maximum_dns_message_octets + 2U ||
        state.pending_query.stream_write_offset >
            state.pending_query.stream_wire.size() ||
        (state.pending_response.active &&
         (state.pending_response.message.empty() ||
          state.pending_response.message.size() > maximum_dns_message_octets)))
      return false;

    std::unique_ptr<dns::IterativeResolver> restored_resolver;
    const auto saved_handle_exists = [&](dns::TransactionHandle handle) {
      return state.resolver &&
             handle.index < state.resolver->transactions.size() &&
             state.resolver->transactions[handle.index].has_value() &&
             state.resolver->generations[handle.index] == handle.generation;
    };
    const auto valid_recursive_client = [&](const auto &saved,
                                            bool udp) noexcept {
      packet::dns::Name parsed_name;
      const auto consumed =
          packet::dns::parse_name(saved.question.name.view(), 0U, parsed_name);
      return state.recursive_service_enabled &&
             saved_handle_exists(saved.transaction) && consumed &&
             *consumed == saved.question.name.octets &&
             saved.question.type != 0U && saved.question.record_class != 0U &&
             (!udp || saved.destination_port != 0U) &&
             saved.udp_payload_bytes >= 512U &&
             static_cast<std::uint8_t>(saved.family) <=
                 static_cast<std::uint8_t>(transport::IpFamily::ipv6);
    };
    if (state.resolver) {
      restored_resolver = std::make_unique<dns::IterativeResolver>(
          state.resolver->identifier_secret, state.resolver->root_hints,
          state.resolver->policy);
      if (state.resolver->dnssec_enabled) {
#ifdef __EMSCRIPTEN__
        dnssec::TrustAnchorStore anchors;
        for (const auto &anchor : state.resolver->trust_anchors)
          if (anchors.add(anchor) != dnssec::AnchorMutation::applied)
            return false;
        if (!restored_resolver->enable_dnssec(
                {.crypto = &dnssec_crypto_,
                 .digests = &dnssec_crypto_,
                 .wall_clock_seconds = dnssec_wall_clock_seconds,
                 .wall_clock_context = nullptr,
                 .trust_anchors = std::move(anchors),
                 .nsec3_policy = state.resolver->nsec3_policy}))
          return false;
#else
        return false;
#endif
      }
      if (!restored_resolver->restore(*state.resolver, now))
        return false;
      for (const auto handle : state.transactions)
        if (!saved_handle_exists(handle))
          return false;
      if (state.pending_query.active &&
          !saved_handle_exists(state.pending_query.transaction))
        return false;
    } else if (!state.transactions.empty() || state.pending_query.active ||
               state.resolver_ipv4_socket || state.resolver_ipv6_socket ||
               !state.resolver_tcp_connections.empty()) {
      return false;
    }

    std::vector<dns::Zone> restored_zones;
    restored_zones.reserve(state.zones.size());
    for (const auto &saved : state.zones) {
      dns::Zone zone{saved.origin};
      if (!zone.replace(saved.records))
        return false;
      restored_zones.push_back(std::move(zone));
    }
    std::vector<dnssec::SignedZoneOwner> restored_signed_zones;
    restored_signed_zones.reserve(state.signed_zones.size());
    const auto signing_wall =
        wall_now.value_or(dnssec_wall_clock_unix_seconds());
    for (const auto &saved : state.signed_zones) {
      auto zone = dnssec::SignedZoneOwner::restore(saved, signing_wrapping_key_,
                                                   signing_vault_context_,
                                                   signing_wall, now,
#ifdef __EMSCRIPTEN__
                                                   &dnssec_crypto_
#else
                                                   nullptr
#endif
      );
      if (!zone ||
          std::ranges::any_of(restored_signed_zones, [&](const auto &existing) {
            return packet::dns::equal_case_insensitive(existing.origin(),
                                                       zone->origin());
          }))
        return false;
      restored_signed_zones.push_back(std::move(*zone));
    }
    if (restored_zones.empty() && restored_signed_zones.empty() &&
        !state.recursive_service_enabled &&
        (state.authoritative_ipv4_socket || state.authoritative_ipv6_socket ||
         state.authoritative_ipv4_listener ||
         state.authoritative_ipv6_listener ||
         !state.authoritative_tcp_connections.empty() ||
         state.pending_response.active))
      return false;
    if (state.recursive_service_enabled &&
        (!state.resolver || !state.authoritative_ipv4_socket ||
         !state.authoritative_ipv6_socket ||
         !state.authoritative_ipv4_listener ||
         !state.authoritative_ipv6_listener))
      return false;

    std::vector<ResolverTcpConnection> restored_resolver_connections;
    restored_resolver_connections.reserve(
        state.resolver_tcp_connections.size());
    for (const auto &saved : state.resolver_tcp_connections) {
      if (!endpoint.tcp_state(saved.socket) ||
          saved.received_wire.size() > maximum_dns_message_octets + 2U)
        return false;
      ResolverTcpConnection connection{
          .server = saved.server,
          .socket = saved.socket,
          .receive_wire =
              std::vector<std::uint8_t>(maximum_dns_message_octets + 2U),
          .received_octets = saved.received_wire.size()};
      std::copy(saved.received_wire.begin(), saved.received_wire.end(),
                connection.receive_wire.begin());
      restored_resolver_connections.push_back(std::move(connection));
    }

    std::vector<RecursiveUdpClient> restored_recursive_clients;
    restored_recursive_clients.reserve(state.recursive_udp_clients.size());
    for (const auto &saved : state.recursive_udp_clients) {
      if (!valid_recursive_client(saved, true))
        return false;
      restored_recursive_clients.push_back(
          {.transaction = saved.transaction,
           .question = saved.question,
           .destination_ipv4 = saved.destination_ipv4,
           .destination_ipv6 = saved.destination_ipv6,
           .family = saved.family,
           .destination_port = saved.destination_port,
           .request_id = saved.request_id,
           .udp_payload_bytes = saved.udp_payload_bytes,
           .recursion_desired = saved.recursion_desired,
           .checking_disabled = saved.checking_disabled,
           .dnssec_ok = saved.dnssec_ok,
           .understands_authenticated_data =
               saved.understands_authenticated_data,
           .used_edns = saved.used_edns});
    }

    std::vector<AuthoritativeTcpConnection> restored_auth_connections;
    restored_auth_connections.reserve(
        state.authoritative_tcp_connections.size());
    for (const auto &saved : state.authoritative_tcp_connections) {
      if (!endpoint.tcp_state(saved.socket) ||
          saved.received_wire.size() > maximum_dns_message_octets + 2U ||
          saved.send_wire.size() > maximum_dns_message_octets + 2U ||
          saved.send_offset > saved.send_wire.size())
        return false;
      AuthoritativeTcpConnection connection{
          .socket = saved.socket,
          .family = saved.family,
          .receive_wire =
              std::vector<std::uint8_t>(maximum_dns_message_octets + 2U),
          .send_wire = saved.send_wire,
          .recursive_clients = {},
          .received_octets = saved.received_wire.size(),
          .send_offset = saved.send_offset};
      connection.recursive_clients.reserve(saved.recursive_clients.size());
      for (const auto &client : saved.recursive_clients) {
        if (!valid_recursive_client(client, false))
          return false;
        connection.recursive_clients.push_back(
            {.transaction = client.transaction,
             .question = client.question,
             .destination_ipv4 = client.destination_ipv4,
             .destination_ipv6 = client.destination_ipv6,
             .family = client.family,
             .destination_port = client.destination_port,
             .request_id = client.request_id,
             .udp_payload_bytes = client.udp_payload_bytes,
             .recursion_desired = client.recursion_desired,
             .checking_disabled = client.checking_disabled,
             .dnssec_ok = client.dnssec_ok,
             .understands_authenticated_data =
                 client.understands_authenticated_data,
             .used_edns = client.used_edns});
      }
      std::copy(saved.received_wire.begin(), saved.received_wire.end(),
                connection.receive_wire.begin());
      restored_auth_connections.push_back(std::move(connection));
    }

    std::vector<std::uint8_t> query(maximum_dns_message_octets);
    std::copy(state.pending_query.query_message.begin(),
              state.pending_query.query_message.end(), query.begin());
    std::vector<std::uint8_t> response(maximum_dns_message_octets);
    std::vector<std::uint8_t> auth_request(maximum_dns_message_octets);
    std::vector<std::uint8_t> auth_response(maximum_dns_message_octets);
    std::copy(state.pending_response.message.begin(),
              state.pending_response.message.end(), auth_response.begin());

    // Publish only after every allocation, handle check and protocol invariant
    // succeeded. The old service remains untouched on all earlier returns.
    resolver_ = std::move(restored_resolver);
    ipv4_socket_ = state.resolver_ipv4_socket;
    ipv6_socket_ = state.resolver_ipv6_socket;
    transactions_ = state.transactions;
    query_wire_ = std::move(query);
    response_wire_ = std::move(response);
    pending_ = {.transaction = state.pending_query.transaction,
                .prepared = state.pending_query.prepared,
                .stream_wire = state.pending_query.stream_wire,
                .stream_write_offset = state.pending_query.stream_write_offset,
                .active = state.pending_query.active};
    resolver_tcp_connections_ = std::move(restored_resolver_connections);
    zones_ = std::move(restored_zones);
    signed_zones_ = std::move(restored_signed_zones);
    authoritative_ipv4_socket_ = state.authoritative_ipv4_socket;
    authoritative_ipv6_socket_ = state.authoritative_ipv6_socket;
    authoritative_ipv4_listener_ = state.authoritative_ipv4_listener;
    authoritative_ipv6_listener_ = state.authoritative_ipv6_listener;
    authoritative_tcp_connections_ = std::move(restored_auth_connections);
    authoritative_request_wire_ = std::move(auth_request);
    authoritative_response_wire_ = std::move(auth_response);
    pending_response_ = {
        .family = state.pending_response.family,
        .destination_ipv4 = state.pending_response.destination_ipv4,
        .destination_ipv6 = state.pending_response.destination_ipv6,
        .destination_port = state.pending_response.destination_port,
        .message_octets = state.pending_response.message.size(),
        .active = state.pending_response.active};
    recursive_udp_clients_ = std::move(restored_recursive_clients);
    recursive_service_enabled_ = state.recursive_service_enabled;
    return true;
  } catch (...) {
    return false;
  }
}

bool DnsEndpointService::try_send_pending(
    EndpointStack &endpoint, void *sink_context,
    packet::Ipv4FragmentSink ipv4_sink,
    packet::Ipv4FragmentAdmission ipv4_admission,
    packet::Ipv6FragmentSink ipv6_sink,
    packet::Ipv6FragmentAdmission ipv6_admission,
    Clock::time_point now) noexcept {
  if (!pending_.active)
    return true;
  if (pending_.prepared.transport == dns::QueryTransport::tcp) {
    try {
      auto connection = std::find_if(
          resolver_tcp_connections_.begin(), resolver_tcp_connections_.end(),
          [&](const auto &candidate) {
            return candidate.server == pending_.prepared.server;
          });
      if (connection == resolver_tcp_connections_.end()) {
        const bool admitted =
            pending_.prepared.server.family == transport::IpFamily::ipv4
                ? ipv4_admission(sink_context, 1U)
                : ipv6_admission(sink_context, 1U);
        if (!admitted)
          return false;
        transport::tcp::EndpointBinding binding{
            .family = pending_.prepared.server.family,
            .interface_id = endpoint.interface_id()};
        transport::tcp::EndpointRemote remote{.port = dns_port};
        remote.ipv4 = pending_.prepared.server.ipv4;
        remote.ipv6 = pending_.prepared.server.ipv6;
        const auto opened = endpoint.connect_tcp(binding, remote, {}, now);
        if (opened.emitted) {
          const auto delivered =
              pending_.prepared.server.family == transport::IpFamily::ipv4
                  ? ipv4_sink(sink_context, opened.frame)
                  : ipv6_sink(sink_context, opened.frame);
          if (!delivered)
            return false;
        }
        if (opened.status == EndpointTcpSendStatus::sent && opened.socket) {
          resolver_tcp_connections_.push_back(
              {.server = pending_.prepared.server,
               .socket = *opened.socket,
               .receive_wire =
                   std::vector<std::uint8_t>(maximum_dns_message_octets + 2U),
               .received_octets = 0U});
        }
        return false;
      }

      const auto state = endpoint.tcp_state(connection->socket);
      if (!state || *state != transport::tcp::State::established)
        return false;
      if (pending_.stream_wire.empty()) {
        pending_.stream_wire.resize(pending_.prepared.message_octets + 2U);
        const auto framed = packet::dns::encode_stream_message(
            pending_.stream_wire,
            std::span<const std::uint8_t>{query_wire_}.first(
                pending_.prepared.message_octets));
        if (!framed)
          return false;
        pending_.stream_wire.resize(*framed);
      }
      while (pending_.stream_write_offset < pending_.stream_wire.size()) {
        const auto accepted = endpoint.write_tcp(
            connection->socket,
            std::span<const std::uint8_t>{pending_.stream_wire}.subspan(
                pending_.stream_write_offset),
            now);
        if (accepted == 0U)
          return false;
        pending_.stream_write_offset += accepted;
      }

      // Reserve one egress frame before asking TCP to commit a prepared data
      // segment. The sink contract guarantees the subsequent push after a
      // successful reservation, preserving transport state and wire order.
      const bool admitted =
          pending_.prepared.server.family == transport::IpFamily::ipv4
              ? ipv4_admission(sink_context, 1U)
              : ipv6_admission(sink_context, 1U);
      if (admitted) {
        const auto sent = endpoint.send_tcp(connection->socket, true, now);
        if (sent.emitted) {
          const auto delivered =
              pending_.prepared.server.family == transport::IpFamily::ipv4
                  ? ipv4_sink(sink_context, sent.frame)
                  : ipv6_sink(sink_context, sent.frame);
          if (!delivered)
            return false;
        }
      }
      const auto committed =
          resolver_->commit(pending_.transaction, pending_.prepared, now);
      pending_ = {};
      return committed;
    } catch (...) {
      return false;
    }
  }

  EndpointUdpSendResult sent;
  const auto payload = std::span<const std::uint8_t>{query_wire_}.first(
      pending_.prepared.message_octets);
  if (pending_.prepared.server.family == transport::IpFamily::ipv4) {
    if (!ipv4_socket_)
      return false;
    sent = endpoint.send_udp_ipv4(*ipv4_socket_, pending_.prepared.server.ipv4,
                                  dns_port, payload, sink_context, ipv4_sink,
                                  ipv4_admission);
  } else {
    if (!ipv6_socket_)
      return false;
    sent = endpoint.send_udp_ipv6(*ipv6_socket_, pending_.prepared.server.ipv6,
                                  dns_port, payload, sink_context, ipv6_sink,
                                  now, ipv6_admission);
  }
  if (sent.status == EndpointUdpSendStatus::sent) {
    const auto committed =
        resolver_->commit(pending_.transaction, pending_.prepared, now);
    pending_ = {};
    return committed;
  }
  if (sent.status == EndpointUdpSendStatus::neighbor_resolution_started ||
      sent.status == EndpointUdpSendStatus::neighbor_resolution_pending ||
      sent.status == EndpointUdpSendStatus::output_backpressure)
    return false;

  // A permanent local send error cannot consume an upstream retry. Discarding
  // the preparation lets a later routing/configuration repair try the same
  // DNS action without a fabricated timeout.
  static_cast<void>(
      resolver_->discard(pending_.transaction, pending_.prepared));
  pending_ = {};
  return false;
}

bool DnsEndpointService::try_send_response(
    EndpointStack &endpoint, void *sink_context,
    packet::Ipv4FragmentSink ipv4_sink,
    packet::Ipv4FragmentAdmission ipv4_admission,
    packet::Ipv6FragmentSink ipv6_sink,
    packet::Ipv6FragmentAdmission ipv6_admission,
    Clock::time_point now) noexcept {
  if (!pending_response_.active)
    return true;
  const auto payload =
      std::span<const std::uint8_t>{authoritative_response_wire_}.first(
          pending_response_.message_octets);
  EndpointUdpSendResult sent;
  if (pending_response_.family == transport::IpFamily::ipv4) {
    if (!authoritative_ipv4_socket_)
      return false;
    sent = endpoint.send_udp_ipv4(*authoritative_ipv4_socket_,
                                  pending_response_.destination_ipv4,
                                  pending_response_.destination_port, payload,
                                  sink_context, ipv4_sink, ipv4_admission);
  } else {
    if (!authoritative_ipv6_socket_)
      return false;
    sent = endpoint.send_udp_ipv6(*authoritative_ipv6_socket_,
                                  pending_response_.destination_ipv6,
                                  pending_response_.destination_port, payload,
                                  sink_context, ipv6_sink, now, ipv6_admission);
  }
  if (sent.status == EndpointUdpSendStatus::sent) {
    pending_response_ = {};
    return true;
  }
  if (sent.status == EndpointUdpSendStatus::neighbor_resolution_started ||
      sent.status == EndpointUdpSendStatus::neighbor_resolution_pending ||
      sent.status == EndpointUdpSendStatus::output_backpressure)
    return false;
  // A permanent local route or socket failure drops only this response. The
  // requester will retry according to its own resolver policy.
  pending_response_ = {};
  return false;
}

std::optional<DnsEndpointService::Clock::time_point>
DnsEndpointService::service(EndpointStack &endpoint, void *sink_context,
                            packet::Ipv4FragmentSink ipv4_sink,
                            packet::Ipv4FragmentAdmission ipv4_admission,
                            packet::Ipv6FragmentSink ipv6_sink,
                            packet::Ipv6FragmentAdmission ipv6_admission,
                            Clock::time_point now,
                            std::optional<std::uint64_t> wall_now) noexcept {
  // These callbacks are the sole permitted path from the endpoint owner into
  // its link queue. Calling through a missing callback would be undefined
  // behavior, so configuration remains intact and service simply reports no
  // deadline until the forwarding owner supplies a complete sink contract.
  if (!ipv4_sink || !ipv4_admission || !ipv6_sink || !ipv6_admission)
    return std::nullopt;
  if (!resolver_ && zones_.empty() && signed_zones_.empty())
    return std::nullopt;
  if (!signed_zones_.empty()) {
    const auto signing_wall =
        wall_now.value_or(dnssec_wall_clock_unix_seconds());
    for (auto &zone : signed_zones_)
      if (now >= zone.next_deadline())
        static_cast<void>(zone.poll(signing_wall, now,
#ifdef __EMSCRIPTEN__
                                    &dnssec_crypto_
#else
                                    nullptr
#endif
                                    ));
  }
  if (resolver_)
    resolver_->service(now);

  if (pending_response_.active)
    static_cast<void>(try_send_response(endpoint, sink_context, ipv4_sink,
                                        ipv4_admission, ipv6_sink,
                                        ipv6_admission, now));

  if (!zones_.empty() || !signed_zones_.empty() || recursive_service_enabled_) {
    try {
      const std::array listeners{
          std::pair{authoritative_ipv4_listener_, transport::IpFamily::ipv4},
          std::pair{authoritative_ipv6_listener_, transport::IpFamily::ipv6}};
      for (const auto &[listener, family] : listeners) {
        if (!listener)
          continue;
        const auto accepted = endpoint.accept_tcp(*listener);
        if (!accepted)
          continue;
        authoritative_tcp_connections_.push_back(
            {.socket = *accepted,
             .family = family,
             .receive_wire =
                 std::vector<std::uint8_t>(maximum_dns_message_octets + 2U),
             .send_wire = {},
             .recursive_clients = {},
             .received_octets = 0U,
             .send_offset = 0U});
      }

      for (auto &connection : authoritative_tcp_connections_) {
        const auto state = endpoint.tcp_state(connection.socket);
        const bool readable =
            state && (*state == transport::tcp::State::established ||
                      *state == transport::tcp::State::close_wait);
        if (!readable)
          continue;

        if (connection.send_wire.empty() && resolver_) {
          for (std::size_t index = 0U;
               index < connection.recursive_clients.size(); ++index) {
            const auto completed = resolver_->result(
                connection.recursive_clients[index].transaction);
            if (!completed)
              continue;
            const auto client = connection.recursive_clients[index];
            const auto response = build_recursive_response(
                client, *completed, authoritative_response_wire_, false);
            static_cast<void>(release(client.transaction));
            connection.recursive_clients.erase(
                connection.recursive_clients.begin() +
                static_cast<std::ptrdiff_t>(index));
            if (!response)
              break;
            connection.send_wire.resize(*response + 2U);
            const auto stream = packet::dns::encode_stream_message(
                connection.send_wire,
                std::span<const std::uint8_t>{authoritative_response_wire_}
                    .first(*response));
            if (!stream)
              connection.send_wire.clear();
            else
              connection.send_wire.resize(*stream);
            break;
          }
        }
        if (connection.received_octets < connection.receive_wire.size())
          connection.received_octets += endpoint.read_tcp(
              connection.socket,
              std::span<std::uint8_t>{connection.receive_wire}.subspan(
                  connection.received_octets),
              now);

        if (connection.send_wire.empty() && connection.received_octets != 0U) {
          const auto framed = packet::dns::decode_stream_message(
              std::span<const std::uint8_t>{connection.receive_wire}.first(
                  connection.received_octets));
          if (framed) {
            const auto decoded = decode_client_query(framed->message);
            const auto *zone =
                decoded ? authoritative_zone(decoded->question.name) : nullptr;
            bool recursive_started{};
            bool recursive_admission_failed{};
            if (decoded && !zone && recursive_service_enabled_ &&
                decoded->recursion_desired && resolver_) {
              const auto transaction = resolver_->begin(
                  decoded->question, now, decoded->checking_disabled);
              if (transaction) {
                try {
                  transactions_.push_back(*transaction);
                  connection.recursive_clients.push_back(
                      {.transaction = *transaction,
                       .question = decoded->question,
                       .destination_ipv4 = {},
                       .destination_ipv6 = {},
                       .family = connection.family,
                       .destination_port = 0U,
                       .request_id = decoded->id,
                       .udp_payload_bytes = decoded->udp_payload_bytes,
                       .recursion_desired = decoded->recursion_desired,
                       .checking_disabled = decoded->checking_disabled,
                       .dnssec_ok = decoded->dnssec_ok,
                       .understands_authenticated_data =
                           decoded->understands_authenticated_data,
                       .used_edns = decoded->used_edns});
                  recursive_started = true;
                } catch (...) {
                  std::erase(transactions_, *transaction);
                  static_cast<void>(resolver_->release(*transaction));
                  recursive_admission_failed = true;
                }
              } else
                recursive_admission_failed = true;
            }
            // Once a request selected recursion, failing admission is a server
            // resource error. Falling through to the authoritative path would
            // incorrectly turn it into REFUSED merely because no local zone
            // owns the name.
            const auto response =
                recursive_started ? std::optional<std::size_t>{}
                : recursive_admission_failed
                    ? encode_recursive_admission_failure(
                          *decoded, authoritative_response_wire_)
                    : build_authoritative_response(
                          framed->message, authoritative_response_wire_, false);
            if (response) {
              connection.send_wire.resize(*response + 2U);
              const auto stream = packet::dns::encode_stream_message(
                  connection.send_wire,
                  std::span<const std::uint8_t>{authoritative_response_wire_}
                      .first(*response));
              if (!stream)
                connection.send_wire.clear();
              else
                connection.send_wire.resize(*stream);
            }
            const auto remaining =
                connection.received_octets - framed->consumed_octets;
            std::move(
                connection.receive_wire.begin() +
                    static_cast<std::ptrdiff_t>(framed->consumed_octets),
                connection.receive_wire.begin() +
                    static_cast<std::ptrdiff_t>(connection.received_octets),
                connection.receive_wire.begin());
            connection.received_octets = remaining;
          }
        }

        while (connection.send_offset < connection.send_wire.size()) {
          const auto accepted = endpoint.write_tcp(
              connection.socket,
              std::span<const std::uint8_t>{connection.send_wire}.subspan(
                  connection.send_offset),
              now);
          if (accepted == 0U)
            break;
          connection.send_offset += accepted;
        }
        if (connection.send_wire.empty() ||
            connection.send_offset != connection.send_wire.size())
          continue;
        const auto admitted = connection.family == transport::IpFamily::ipv4
                                  ? ipv4_admission(sink_context, 1U)
                                  : ipv6_admission(sink_context, 1U);
        if (!admitted)
          continue;
        const auto sent = endpoint.send_tcp(connection.socket, true, now);
        if (sent.emitted) {
          const auto delivered = connection.family == transport::IpFamily::ipv4
                                     ? ipv4_sink(sink_context, sent.frame)
                                     : ipv6_sink(sink_context, sent.frame);
          if (!delivered)
            continue;
        }
        if (sent.status == EndpointTcpSendStatus::sent ||
            sent.status == EndpointTcpSendStatus::state_changed ||
            sent.status == EndpointTcpSendStatus::no_action) {
          connection.send_wire.clear();
          connection.send_offset = 0U;
        }
      }
      std::erase_if(authoritative_tcp_connections_,
                    [&](const auto &connection) {
                      const auto state = endpoint.tcp_state(connection.socket);
                      // Endpoint generations disappear after terminal cleanup.
                      // Keeping such an application entry would retain buffers
                      // with no possible peer.
                      const auto terminal =
                          !state || *state == transport::tcp::State::closed ||
                          *state == transport::tcp::State::time_wait;
                      if (terminal)
                        for (const auto &client : connection.recursive_clients)
                          static_cast<void>(release(client.transaction));
                      return terminal;
                    });
    } catch (...) {
      // Existing TCP connections and their endpoint-owned byte streams remain
      // valid. Allocation pressure delays accept or response construction and
      // the client retry policy handles the unanswered request.
    }
  }

  // Completed recursive work is converted back into the original client's
  // message ID and transport metadata only here, on the endpoint owner. The
  // resolver itself never knows another host or bypasses the UDP socket.
  if (!pending_response_.active && resolver_) {
    for (std::size_t index = 0U; index < recursive_udp_clients_.size();
         ++index) {
      const auto completed =
          resolver_->result(recursive_udp_clients_[index].transaction);
      if (!completed)
        continue;
      const auto client = recursive_udp_clients_[index];
      const auto encoded = build_recursive_response(
          client, *completed, authoritative_response_wire_, true);
      static_cast<void>(release(client.transaction));
      recursive_udp_clients_.erase(recursive_udp_clients_.begin() +
                                   static_cast<std::ptrdiff_t>(index));
      if (!encoded)
        break;
      pending_response_ = {.family = client.family,
                           .destination_ipv4 = client.destination_ipv4,
                           .destination_ipv6 = client.destination_ipv6,
                           .destination_port = client.destination_port,
                           .message_octets = *encoded,
                           .active = true};
      static_cast<void>(try_send_response(endpoint, sink_context, ipv4_sink,
                                          ipv4_admission, ipv6_sink,
                                          ipv6_admission, now));
      break;
    }
  }

  if (!pending_response_.active && (!zones_.empty() || !signed_zones_.empty() ||
                                    recursive_service_enabled_)) {
    try {
      const std::array sockets{authoritative_ipv4_socket_,
                               authoritative_ipv6_socket_};
      for (const auto socket : sockets) {
        if (!socket)
          continue;
        const auto received =
            endpoint.receive_udp(*socket, authoritative_request_wire_);
        if (received.status != transport::UdpReceiveStatus::delivered)
          continue;
        const auto request =
            std::span<const std::uint8_t>{authoritative_request_wire_}.first(
                received.metadata.payload_octets);
        const auto decoded = decode_client_query(request);
        const auto *zone =
            decoded ? authoritative_zone(decoded->question.name) : nullptr;
        if (decoded && !zone && recursive_service_enabled_ &&
            decoded->recursion_desired) {
          const auto duplicate = std::find_if(
              recursive_udp_clients_.begin(), recursive_udp_clients_.end(),
              [&](const auto &client) {
                return client.family == received.metadata.family &&
                       client.destination_ipv4 ==
                           received.metadata.source_ipv4 &&
                       client.destination_ipv6 ==
                           received.metadata.source_ipv6 &&
                       client.destination_port ==
                           received.metadata.source_port &&
                       client.request_id == decoded->id &&
                       packet::dns::equal_case_insensitive(
                           client.question.name, decoded->question.name) &&
                       client.question.type == decoded->question.type &&
                       client.question.record_class ==
                           decoded->question.record_class;
              });
          if (duplicate != recursive_udp_clients_.end())
            continue;
          const auto transaction = resolver_->begin(decoded->question, now,
                                                    decoded->checking_disabled);
          bool admitted{};
          try {
            if (transaction) {
              transactions_.push_back(*transaction);
              recursive_udp_clients_.push_back(
                  {.transaction = *transaction,
                   .question = decoded->question,
                   .destination_ipv4 = received.metadata.source_ipv4,
                   .destination_ipv6 = received.metadata.source_ipv6,
                   .family = received.metadata.family,
                   .destination_port = received.metadata.source_port,
                   .request_id = decoded->id,
                   .udp_payload_bytes = decoded->udp_payload_bytes,
                   .recursion_desired = decoded->recursion_desired,
                   .checking_disabled = decoded->checking_disabled,
                   .dnssec_ok = decoded->dnssec_ok,
                   .understands_authenticated_data =
                       decoded->understands_authenticated_data,
                   .used_edns = decoded->used_edns});
              admitted = true;
            }
          } catch (...) {
            std::erase(transactions_, *transaction);
            static_cast<void>(resolver_->release(*transaction));
          }
          if (admitted)
            continue;

          const auto failed = encode_recursive_admission_failure(
              *decoded, authoritative_response_wire_);
          if (!failed)
            continue;
          pending_response_ = {
              .family = received.metadata.family,
              .destination_ipv4 = received.metadata.source_ipv4,
              .destination_ipv6 = received.metadata.source_ipv6,
              .destination_port = received.metadata.source_port,
              .message_octets = *failed,
              .active = true};
          static_cast<void>(try_send_response(endpoint, sink_context, ipv4_sink,
                                              ipv4_admission, ipv6_sink,
                                              ipv6_admission, now));
          break;
        }
        const auto encoded = build_authoritative_response(
            request, authoritative_response_wire_, true);
        if (!encoded)
          continue;
        pending_response_ = {.family = received.metadata.family,
                             .destination_ipv4 = received.metadata.source_ipv4,
                             .destination_ipv6 = received.metadata.source_ipv6,
                             .destination_port = received.metadata.source_port,
                             .message_octets = *encoded,
                             .active = true};
        static_cast<void>(try_send_response(endpoint, sink_context, ipv4_sink,
                                            ipv4_admission, ipv6_sink,
                                            ipv6_admission, now));
        break;
      }
    } catch (...) {
      // The UDP request has already left the bounded socket queue. If response
      // construction cannot allocate its temporary section views, dropping
      // this datagram is safer than terminating the forwarding shard; normal
      // resolver retry provides recovery once memory pressure subsides.
    }
  }

  // Socket queues are already bounded resources. Draining one message from
  // each family per turn prevents DNS from monopolizing the forwarding owner.
  const std::array resolver_sockets{ipv4_socket_, ipv6_socket_};
  for (const auto socket : resolver_sockets) {
    if (!resolver_)
      break;
    if (!socket)
      continue;
    const auto received = endpoint.receive_udp(*socket, response_wire_);
    if (received.status != transport::UdpReceiveStatus::delivered ||
        received.metadata.source_port != dns_port)
      continue;
    const auto source = source_address(received.metadata);
    const auto message = std::span<const std::uint8_t>{response_wire_}.first(
        received.metadata.payload_octets);
    for (const auto transaction : transactions_) {
      const auto status = resolver_->receive(
          transaction, source, dns::QueryTransport::udp, message, now);
      if (status != dns::ResponseStatus::ignored_identifier &&
          status != dns::ResponseStatus::ignored_source &&
          status != dns::ResponseStatus::ignored_transport &&
          status != dns::ResponseStatus::invalid_transaction)
        break;
    }
  }

  if (resolver_) {
    for (auto &connection : resolver_tcp_connections_) {
      const auto state = endpoint.tcp_state(connection.socket);
      if (!state || *state != transport::tcp::State::established)
        continue;
      if (connection.received_octets < connection.receive_wire.size())
        connection.received_octets += endpoint.read_tcp(
            connection.socket,
            std::span<std::uint8_t>{connection.receive_wire}.subspan(
                connection.received_octets),
            now);
      while (connection.received_octets != 0U) {
        const auto framed = packet::dns::decode_stream_message(
            std::span<const std::uint8_t>{connection.receive_wire}.first(
                connection.received_octets));
        if (!framed)
          break;
        for (const auto transaction : transactions_) {
          const auto status = resolver_->receive(transaction, connection.server,
                                                 dns::QueryTransport::tcp,
                                                 framed->message, now);
          if (status != dns::ResponseStatus::ignored_identifier &&
              status != dns::ResponseStatus::ignored_source &&
              status != dns::ResponseStatus::ignored_transport &&
              status != dns::ResponseStatus::invalid_transaction)
            break;
        }
        const auto remaining =
            connection.received_octets - framed->consumed_octets;
        std::move(connection.receive_wire.begin() +
                      static_cast<std::ptrdiff_t>(framed->consumed_octets),
                  connection.receive_wire.begin() +
                      static_cast<std::ptrdiff_t>(connection.received_octets),
                  connection.receive_wire.begin());
        connection.received_octets = remaining;
      }
    }
    std::erase_if(resolver_tcp_connections_, [&](const auto &connection) {
      const auto state = endpoint.tcp_state(connection.socket);
      // A future resolver action to the same server must create a new active
      // open instead of waiting forever on an entry whose TCP state is
      // terminal.
      return !state || *state == transport::tcp::State::closed ||
             *state == transport::tcp::State::time_wait;
    });
  }

  if (resolver_ && pending_.active) {
    static_cast<void>(try_send_pending(endpoint, sink_context, ipv4_sink,
                                       ipv4_admission, ipv6_sink,
                                       ipv6_admission, now));
  } else if (resolver_) {
    for (const auto transaction : transactions_) {
      const auto prepared = resolver_->prepare(transaction, query_wire_, now);
      if (prepared.status != dns::PrepareQueryStatus::prepared)
        continue;
      pending_ = {.transaction = transaction,
                  .prepared = prepared.query,
                  .stream_wire = {},
                  .stream_write_offset = 0U,
                  .active = true};
      static_cast<void>(try_send_pending(endpoint, sink_context, ipv4_sink,
                                         ipv4_admission, ipv6_sink,
                                         ipv6_admission, now));
      break;
    }
  }
  return resolver_ ? resolver_->next_deadline() : std::nullopt;
}

} // namespace router::network_detail
