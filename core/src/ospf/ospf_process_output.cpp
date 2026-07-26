// OSPF packet encoding, adjacency actions and scheduled process turns.
// InstanceProcess owns scheduling while forwarding owns physical transmission.

#include "ospf_process_internal.hpp"

namespace router::ospf {

bool InstanceProcess::encode_output(
    InterfaceOwner &owner, NeighborExchange *neighbor,
    packet::ospf::PacketType type, std::span<const std::uint8_t> body,
    ProcessOutput &output,
    const ip::IpAddress *explicit_unicast) noexcept {
  const auto network_type = owner.configuration.protocol.network_type;
  const bool hello = type == packet::ospf::PacketType::hello;
  const bool flooding =
      type == packet::ospf::PacketType::link_state_update ||
      type == packet::ospf::PacketType::link_state_acknowledgment;

  // RFC 2328 section A.1 sends every packet on a physical point-to-point
  // network to AllSPFRouters. Broadcast flooding uses AllSPFRouters for the
  // DR/BDR and AllDRouters for DROther; other adjacency packets are unicast.
  PacketDestination destination = PacketDestination::neighbor_unicast;
  if ((hello && !explicit_unicast) ||
      network_type == NetworkType::point_to_point)
    destination = PacketDestination::all_spf_routers;
  else if (flooding && network_type == NetworkType::broadcast)
    destination =
        owner.runtime.state() == InterfaceState::designated ||
                owner.runtime.state() == InterfaceState::backup
            ? PacketDestination::all_spf_routers
            : PacketDestination::all_dr_routers;
  if (destination == PacketDestination::neighbor_unicast && !neighbor &&
      !explicit_unicast)
    return false;

  const auto explicit_v4 = [&]() {
    ip::Ipv4 result{};
    if (explicit_unicast &&
        explicit_unicast->family == ip::AddressFamily::ipv4)
      std::copy_n(explicit_unicast->bytes.begin(), result.size(),
                  result.begin());
    return result;
  }();
  const auto destination_v4 =
      destination == PacketDestination::all_spf_routers
          ? packet::ospf::all_spf_routers_v4
          : destination == PacketDestination::all_dr_routers
                ? packet::ospf::all_dr_routers_v4
                : explicit_unicast ? explicit_v4
                                   : neighbor->ipv4_address;
  const auto destination_v6 =
      destination == PacketDestination::all_spf_routers
          ? packet::ospf::all_spf_routers_v6
          : destination == PacketDestination::all_dr_routers
                ? packet::ospf::all_dr_routers_v6
                : explicit_unicast
                      ? explicit_unicast->bytes
                      : neighbor->ipv6_address;

  // Direct keys retain the singular programmed send record. A keychain keeps
  // every entry on the protocol owner and selects the most recent entry whose
  // begin-time has arrived. SR OS OSPF retains its last valid key after the
  // configured lifetime, so end-time does not force an unauthenticated packet.
  const ProcessAuthentication *send_authentication =
      owner.send_authentication ? &*owner.send_authentication : nullptr;
  if (!send_authentication && owner.authentication_required) {
    const auto now_utc = wall_clock_seconds();
    for (const auto &candidate : owner.receive_authentications) {
      if (!candidate.timed || candidate.begin_utc_seconds > now_utc)
        continue;
      if (!send_authentication ||
          candidate.begin_utc_seconds >
              send_authentication->begin_utc_seconds)
        send_authentication = &candidate;
    }
    // A configured keychain whose first begin-time is still in the future is
    // fail-closed. Sending a null-authentication Hello here could form an
    // adjacency that the operator explicitly required to be protected.
    if (!send_authentication)
      return false;
  }
  if (send_authentication &&
      owner.authentication_send_key_id != send_authentication->key_id) {
    owner.authentication_send_key_id = send_authentication->key_id;
    owner.authentication_sequence =
        send_authentication->initial_sequence;
  }

  std::optional<std::span<const std::uint8_t>> encoded;
  if (version_ == packet::ospf::version_two) {
    if (!send_authentication) {
      constexpr std::array<std::uint8_t, 8U> null_authentication{};
      encoded = packet::ospf::encode_version_two(
          output.bytes, type, router_id_, area_id_,
          packet::ospf::AuthenticationType::none, null_authentication, body);
    } else if (send_authentication->algorithm ==
               KeychainAlgorithm::password) {
      std::array<std::uint8_t, 8U> password{};
      std::copy_n(send_authentication->key.begin(),
                  std::min<std::size_t>(
                      send_authentication->key_size, password.size()),
                  password.begin());
      encoded = packet::ospf::encode_version_two(
          output.bytes, type, router_id_, area_id_,
          packet::ospf::AuthenticationType::simple_password, password, body);
    } else {
      const auto algorithm =
          send_authentication->algorithm ==
                  KeychainAlgorithm::message_digest
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::
                        message_digest_md5}
          : send_authentication->algorithm ==
                    KeychainAlgorithm::hmac_sha1
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::hmac_sha1}
          : send_authentication->algorithm ==
                    KeychainAlgorithm::hmac_sha256
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::hmac_sha256}
              : std::optional<
                    authentication::V2CryptographicAlgorithm>{};
      if (!algorithm)
        return false;
      if (owner.authentication_sequence ==
          std::numeric_limits<std::uint32_t>::max())
        return false;
      encoded = authentication::encode_v2_cryptographic(
          output.bytes, type, router_id_, area_id_,
          static_cast<std::uint8_t>(send_authentication->key_id),
          static_cast<std::uint32_t>(++owner.authentication_sequence),
          *algorithm,
          std::span<const std::uint8_t>{
              send_authentication->key.data(),
              send_authentication->key_size},
          body);
    }
    output.ipv4_destination = destination_v4;
  } else {
    if (!send_authentication || send_authentication->ipsec_ah) {
      // IPsec AH protects the IPv6 envelope, not the OSPF packet body. The
      // control worker calls protect_ipv6_ipsec_packet after this checksum is
      // calculated over the ordinary OSPFv3 pseudo-header.
      encoded = packet::ospf::encode_version_three(
          output.bytes, type, router_id_, area_id_, instance_id_,
          owner.configuration.ipv6_source, destination_v6, body);
    } else {
      if (owner.authentication_sequence ==
          std::numeric_limits<std::uint64_t>::max())
        return false;
      const auto algorithm =
          send_authentication->algorithm ==
                  KeychainAlgorithm::hmac_sha1
              ? authentication::V3CryptographicAlgorithm::hmac_sha1
              : authentication::V3CryptographicAlgorithm::hmac_sha256;
      encoded = authentication::encode_v3_authentication_trailer(
          output.bytes, type, router_id_, area_id_, instance_id_,
          owner.configuration.ipv6_source,
          send_authentication->key_id,
          ++owner.authentication_sequence, algorithm,
          std::span<const std::uint8_t>{
              send_authentication->key.data(),
              send_authentication->key_size},
          body);
    }
    output.ipv6_destination = destination_v6;
  }
  if (!encoded)
    return false;
  output.interface_id = owner.configuration.protocol.interface_id;
  output.physical_port_ordinal =
      owner.configuration.physical_port_ordinal;
  // A multicast packet is one transmission on the attached data link, even
  // though reliable flooding keeps an independent retransmission list for
  // every adjacent neighbor. Publishing a neighbor ID on multicast output
  // would let downstream code accidentally turn one physical frame into
  // private per-neighbor delivery, which is not how OSPF operates.
  output.neighbor_router_id =
      destination == PacketDestination::neighbor_unicast && neighbor
          ? neighbor->router_id
          : 0U;
  output.ipv4_source = owner.configuration.ipv4_source;
  output.ipv6_source = owner.configuration.ipv6_source;
  output.source_mac = owner.configuration.source_mac;
  output.version = version_;
  output.destination = destination;
  output.hop_limit =
      network_type == NetworkType::virtual_link
          ? device_catalog::default_ip_hop_limit
          : 1U;
  output.size = static_cast<std::uint16_t>(encoded->size());
  return true;
}

bool InstanceProcess::apply_neighbor_actions(
    InterfaceOwner &owner, std::uint32_t router_id, NeighborAction actions,
    RuntimeClock::time_point now) noexcept {
  auto *neighbor = exchange(owner, router_id, true);
  if (!neighbor)
    return false;
  if (has_action(actions, NeighborAction::clear_adjacency)) {
    neighbor->database.reset();
    neighbor->pending_database_description = false;
    neighbor->pending_request = false;
    neighbor->pending_update = false;
    neighbor->pending_acknowledgment = false;
    neighbor->dd_retransmit_deadline = {};
    neighbor->request_retransmit_deadline = {};
    neighbor->update_retransmit_deadline = {};
    schedule_local_origination(now);
  }
  if (has_action(actions, NeighborAction::delete_neighbor)) {
    // The FSM row and exchange row form one owner-local identity. Erase both
    // in the same turn so operational queries can never observe a deleted
    // neighbor with stale transport addresses or retransmission state.
    const auto exchange_row = std::find_if(
        owner.exchanges.begin(), owner.exchanges.end(),
        [router_id](const auto &candidate) {
          return candidate.router_id == router_id;
        });
    if (exchange_row != owner.exchanges.end())
      owner.exchanges.erase(exchange_row);
    return owner.runtime.erase_neighbor(router_id);
  }
  if (!has_action(actions, NeighborAction::begin_database_exchange))
    return true;
  if (!neighbor->database.begin(
          database_.records(), version_, now,
          owner.configuration.protocol.network_type !=
              NetworkType::virtual_link))
    return false;

  // RFC 2328 section 10.8 chooses the larger Router ID as master. A fresh DD
  // sequence is consumed for every new exchange, including a DR/BDR election
  // that promotes an existing 2-Way neighbor into ExStart.
  neighbor->local_master = router_id_ > neighbor->router_id;
  neighbor->dd_sequence = ++next_dd_sequence_;
  neighbor->summary_cursor = 0U;
  neighbor->request_cursor = 0U;
  neighbor->update_cursor = 0U;
  neighbor->negotiation_complete = false;
  neighbor->pending_database_description = true;
  neighbor->pending_request = false;
  neighbor->pending_update = false;
  neighbor->pending_acknowledgment = false;
  neighbor->peer_more = true;
  neighbor->sent_more = true;
  neighbor->complete_after_reply = false;
  neighbor->dd_retransmit_deadline = now;
  neighbor->request_retransmit_deadline = {};
  neighbor->update_retransmit_deadline = {};
  return true;
}

bool InstanceProcess::reconcile_interface_adjacencies(
    InterfaceOwner &owner, InterfaceAction actions,
    RuntimeClock::time_point now) noexcept {
  if (has_action(actions, InterfaceAction::originate_router_lsa) ||
      has_action(actions, InterfaceAction::originate_network_lsa))
    schedule_local_origination(now);
  if (!has_action(actions, InterfaceAction::elect_dr_bdr))
    return true;

  std::size_t written{};
  if (!owner.runtime.reconcile_adjacencies(owner.reconciliation, written))
    return false;
  for (std::size_t index{}; index < written; ++index)
    if (!apply_neighbor_actions(owner,
                                owner.reconciliation[index].router_id,
                                owner.reconciliation[index].actions, now))
      return false;
  return true;
}

bool InstanceProcess::emit_hello(InterfaceOwner &owner,
                                 ProcessOutput &output) noexcept {
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  const auto body = owner.runtime.encode_hello_payload(payload);
  if (!body)
    return false;
  const auto *virtual_peer =
      owner.configuration.protocol.network_type ==
              NetworkType::virtual_link
          ? &owner.configuration.virtual_neighbor_address
          : nullptr;
  return encode_output(owner, nullptr, packet::ospf::PacketType::hello,
                       *body, output, virtual_peer);
}

bool InstanceProcess::emit_nbma_hello(
    InterfaceOwner &owner, const InterfaceOwner::NbmaPeer &peer,
    ProcessOutput &output) noexcept {
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  const auto body = owner.runtime.encode_hello_payload(payload);
  if (!body)
    return false;
  return encode_output(owner, nullptr, packet::ospf::PacketType::hello,
                       *body, output, &peer.configuration.address);
}

bool InstanceProcess::emit_database_description(
    InterfaceOwner &owner, NeighborExchange &neighbor,
    ProcessOutput &output, RuntimeClock::time_point now) noexcept {
  const auto summaries = neighbor.database.summaries();
  const auto ospf_header =
      version_ == packet::ospf::version_two
          ? packet::ospf::version_two_header_octets
          : packet::ospf::version_three_header_octets;
  const auto ip_header =
      version_ == packet::ospf::version_two
          ? packet::ipv4_minimum_header_octets
          : packet::ipv6_header_octets;
  const auto dd_fixed =
      version_ == packet::ospf::version_two ? 8U : 12U;
  const auto mtu = owner.configuration.protocol.interface_mtu;
  if (mtu <= ip_header + ospf_header + dd_fixed)
    return false;
  const auto header_capacity =
      (mtu - ip_header - ospf_header - dd_fixed) /
      packet::ospf::lsa_header_octets;
  const bool initial = !neighbor.negotiation_complete;
  std::array<std::uint8_t, packet::maximum_frame_octets> headers{};
  const auto remaining = summaries.size() - neighbor.summary_cursor;
  // RFC 2328 section 10.6 requires the initial I/M/MS negotiation packet to
  // contain no LSA headers. Summaries begin only after master/slave roles and
  // the DD sequence have been agreed. An empty LSDB hid this distinction.
  const auto count =
      initial ? std::size_t{0U} : std::min(remaining, header_capacity);
  for (std::size_t index{}; index < count; ++index) {
    const auto &header = summaries[neighbor.summary_cursor + index];
    const auto offset = index * packet::ospf::lsa_header_octets;
    write_lsa_header(std::span<std::uint8_t>{headers}.subspan(
                         offset, packet::ospf::lsa_header_octets),
                     header, version_);
  }

  const bool more = initial || neighbor.summary_cursor + count <
                                   summaries.size();
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  const auto body = packet::ospf::encode_database_description_payload(
      payload, version_, mtu, owner.configuration.protocol.options,
      neighbor.dd_sequence, initial, more,
      initial || neighbor.local_master,
      std::span<const std::uint8_t>{headers}.first(
          count * packet::ospf::lsa_header_octets));
  if (!body)
    return false;
  if (!encode_output(owner, &neighbor,
                     packet::ospf::PacketType::database_description,
                     *body, output))
    return false;
  if (!initial)
    neighbor.summary_cursor += count;
  neighbor.sent_more = more;
  neighbor.pending_database_description = false;
  neighbor.dd_retransmit_deadline =
      now +
      std::chrono::seconds{
          owner.configuration.retransmit_interval_seconds};
  if (!initial && !neighbor.local_master && neighbor.complete_after_reply &&
      !more) {
    const auto transition = owner.runtime.apply_neighbor_event(
        neighbor.router_id, NeighborEvent::exchange_done,
        !neighbor.database.requests().empty());
    if (!transition)
      return false;
    neighbor.complete_after_reply = false;
    neighbor.dd_retransmit_deadline = {};
    neighbor.pending_request = transition->state == NeighborState::loading;
    if (neighbor.pending_request)
      neighbor.request_retransmit_deadline = now;
    if (transition->state == NeighborState::full)
      schedule_local_origination(now);
  }
  return true;
}

bool InstanceProcess::emit_link_state_request(
    InterfaceOwner &owner, NeighborExchange &neighbor,
    ProcessOutput &output, RuntimeClock::time_point now) noexcept {
  const auto requests = neighbor.database.requests();
  if (requests.empty()) {
    neighbor.pending_request = false;
    neighbor.request_retransmit_deadline = {};
    return false;
  }
  const auto ospf_header =
      version_ == packet::ospf::version_two
          ? packet::ospf::version_two_header_octets
          : packet::ospf::version_three_header_octets;
  const auto ip_header =
      version_ == packet::ospf::version_two
          ? packet::ipv4_minimum_header_octets
          : packet::ipv6_header_octets;
  constexpr std::size_t request_entry_octets = 12U;
  const auto mtu = owner.configuration.protocol.interface_mtu;
  if (mtu <= ip_header + ospf_header)
    return false;
  const auto capacity =
      (mtu - ip_header - ospf_header) / request_entry_octets;
  if (capacity == 0U)
    return false;
  if (neighbor.request_cursor >= requests.size())
    neighbor.request_cursor = 0U;
  const auto count =
      std::min(capacity, requests.size() - neighbor.request_cursor);
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  const auto body = packet::ospf::encode_link_state_request_payload(
      payload, version_, requests.subspan(neighbor.request_cursor, count));
  if (!body ||
      !encode_output(owner, &neighbor,
                     packet::ospf::PacketType::link_state_request,
                     *body, output))
    return false;
  neighbor.request_cursor += count;
  if (neighbor.request_cursor == requests.size()) {
    neighbor.request_cursor = 0U;
    neighbor.pending_request = false;
    neighbor.request_retransmit_deadline =
        now + std::chrono::seconds{
                  owner.configuration.retransmit_interval_seconds};
  }
  return true;
}

bool InstanceProcess::emit_link_state_update(
    InterfaceOwner &owner, NeighborExchange &neighbor,
    ProcessOutput &output, RuntimeClock::time_point now) noexcept {
  const auto retransmissions = neighbor.database.retransmissions();
  if (retransmissions.empty()) {
    neighbor.pending_update = false;
    neighbor.update_retransmit_deadline = {};
    neighbor.update_cursor = 0U;
    return false;
  }
  if (neighbor.update_cursor >= retransmissions.size())
    neighbor.update_cursor = 0U;
  const auto ospf_header =
      version_ == packet::ospf::version_two
          ? packet::ospf::version_two_header_octets
          : packet::ospf::version_three_header_octets;
  const auto ip_header =
      version_ == packet::ospf::version_two
          ? packet::ipv4_minimum_header_octets
          : packet::ipv6_header_octets;
  const auto mtu = owner.configuration.protocol.interface_mtu;
  constexpr std::size_t update_count_octets = 4U;
  if (mtu <= ip_header + ospf_header + update_count_octets)
    return false;
  const auto body_capacity =
      mtu - ip_header - ospf_header;
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  std::size_t written = update_count_octets;
  std::uint32_t count{};
  while (neighbor.update_cursor + count < retransmissions.size() &&
         count < device_catalog::ospf_work_budget_packets) {
    const auto &entry = retransmissions[neighbor.update_cursor + count];
    const auto *record = database_.find(entry.key);
    if (!record)
      return false;
    if (record->bytes.size() > body_capacity - written)
      break;
    std::copy(record->bytes.begin(), record->bytes.end(),
              payload.begin() + static_cast<std::ptrdiff_t>(written));
    const auto transmit_age = std::min<std::uint32_t>(
        max_age_seconds,
        static_cast<std::uint32_t>(record->age(now)) +
            owner.configuration.transmit_delay_seconds);
    write16(payload, written, static_cast<std::uint16_t>(transmit_age));
    written += record->bytes.size();
    ++count;
  }
  if (count == 0U)
    return false;
  write32(payload, 0U, count);
  if (!encode_output(owner, &neighbor,
                     packet::ospf::PacketType::link_state_update,
                     std::span<const std::uint8_t>{payload}.first(written),
                     output))
    return false;
  neighbor.update_cursor += count;
  if (neighbor.update_cursor == retransmissions.size()) {
    neighbor.update_cursor = 0U;
    neighbor.pending_update = false;
    neighbor.update_retransmit_deadline =
        now + std::chrono::seconds{
                  owner.configuration.retransmit_interval_seconds};
  }
  return true;
}

bool InstanceProcess::emit_link_state_acknowledgment(
    InterfaceOwner &owner, NeighborExchange &neighbor,
    ProcessOutput &output) noexcept {
  const auto acknowledgments =
      neighbor.database.delayed_acknowledgments();
  if (acknowledgments.empty()) {
    neighbor.pending_acknowledgment = false;
    return false;
  }
  const auto ospf_header =
      version_ == packet::ospf::version_two
          ? packet::ospf::version_two_header_octets
          : packet::ospf::version_three_header_octets;
  const auto ip_header =
      version_ == packet::ospf::version_two
          ? packet::ipv4_minimum_header_octets
          : packet::ipv6_header_octets;
  const auto mtu = owner.configuration.protocol.interface_mtu;
  if (mtu <= ip_header + ospf_header)
    return false;
  const auto capacity = (mtu - ip_header - ospf_header) /
                        packet::ospf::lsa_header_octets;
  const auto count = std::min(capacity, acknowledgments.size());
  if (count == 0U)
    return false;
  std::array<std::uint8_t, packet::maximum_frame_octets> headers{};
  for (std::size_t index{}; index < count; ++index)
    write_lsa_header(
        std::span<std::uint8_t>{headers}.subspan(
            index * packet::ospf::lsa_header_octets,
            packet::ospf::lsa_header_octets),
        acknowledgments[index], version_);
  std::array<std::uint8_t, packet::maximum_frame_octets> payload{};
  const auto body = packet::ospf::encode_link_state_acknowledgment_payload(
      payload, version_,
      std::span<const std::uint8_t>{headers}.first(
          count * packet::ospf::lsa_header_octets));
  if (!body ||
      !encode_output(owner, &neighbor,
                     packet::ospf::PacketType::link_state_acknowledgment,
                     *body, output))
    return false;
  neighbor.database.consume_delayed_acknowledgments(count);
  neighbor.pending_acknowledgment =
      !neighbor.database.delayed_acknowledgments().empty();
  return true;
}

bool InstanceProcess::run_ready(RuntimeClock::time_point now,
                                std::span<ProcessOutput> output,
                                std::size_t &written) noexcept {
  written = 0U;
  run_ready_status_ = RunReadyStatus::succeeded;
  const auto retain_encoded_output = [&]() noexcept {
    const auto &candidate = output[written];
    if (candidate.destination == PacketDestination::neighbor_unicast) {
      ++written;
      return;
    }
    // Reliable flooding and acknowledgment state belongs to each adjacency,
    // but a byte-identical multicast packet is transmitted only once on a
    // shared data link. Compare only the already retained output prefix. The
    // fixed caller-owned span makes this allocation-free and bounds work by
    // the shard's packet budget.
    const bool duplicate = std::any_of(
        output.begin(),
        output.begin() + static_cast<std::ptrdiff_t>(written),
        [&](const ProcessOutput &existing) {
          return existing.destination == candidate.destination &&
                 existing.interface_id == candidate.interface_id &&
                 existing.version == candidate.version &&
                 existing.size == candidate.size &&
                 existing.ipv4_destination == candidate.ipv4_destination &&
                 existing.ipv6_destination == candidate.ipv6_destination &&
                 std::equal(existing.bytes.begin(),
                            existing.bytes.begin() + existing.size,
                            candidate.bytes.begin());
        });
    if (!duplicate)
      ++written;
  };
  // Aging precedes origination so a record reaching LSRefreshTime in this
  // turn can schedule and publish its replacement immediately. It also makes
  // a naturally expired remote LSA enter reliable MaxAge flooding before SPF
  // can use stale topology.
  if (!maintain_database(now)) {
    run_ready_status_ = RunReadyStatus::local_origination_rejected;
    return false;
  }
  // Self-originated LSAs enter the same LSDB and retransmission machinery as
  // received advertisements. Run origination before packet emission so a Full
  // adjacency can send the new generation in this owner turn.
  if (pending_sequence_wraps_.empty() &&
      local_origination_deadline_ != RuntimeClock::time_point{} &&
      local_origination_deadline_ <= now &&
      !originate_local_lsas(now)) {
    run_ready_status_ = RunReadyStatus::local_origination_rejected;
    return false;
  }
  if (spf_deadline_ != RuntimeClock::time_point{} &&
      spf_deadline_ <= now && !recalculate_routes(now)) {
    run_ready_status_ = RunReadyStatus::route_recalculation_rejected;
    return false;
  }
  for (auto &owner : interfaces_) {
    for (auto &neighbor : owner.exchanges) {
      if (!neighbor.helper_active)
        continue;
      if (neighbor.helper_deadline <= now) {
        neighbor.helper_active = false;
        neighbor.helper_deadline = {};
        neighbor.helper_was_designated_router = false;
        schedule_local_origination(now);
      } else {
        static_cast<void>(owner.runtime.defer_inactivity(
            neighbor.router_id, neighbor.helper_deadline));
      }
    }
    std::array<ExpiredNeighbor,
               device_catalog::ospf_work_budget_packets> expired{};
    std::size_t expired_count{};
    // The fixed batch is only a work budget. false requests another immediate
    // owner turn and never discards an expired neighbor.
    const bool all_expired =
        owner.runtime.process_deadlines(now, expired, expired_count);
    for (std::size_t index{}; index < expired_count; ++index) {
      if (!apply_neighbor_actions(owner, expired[index].router_id,
                                  expired[index].actions, now)) {
        run_ready_status_ = RunReadyStatus::local_origination_rejected;
        return false;
      }
      if (has_action(expired[index].actions,
                     NeighborAction::notify_interface)) {
        const auto neighbor_actions = owner.runtime.neighbor_change(false);
        if (!reconcile_interface_adjacencies(owner, neighbor_actions, now)) {
          run_ready_status_ = RunReadyStatus::local_origination_rejected;
          return false;
        }
      }
    }
    const auto interface_actions =
        owner.runtime.process_interface_deadline(now);
    if (!reconcile_interface_adjacencies(owner, interface_actions, now)) {
      run_ready_status_ = RunReadyStatus::local_origination_rejected;
      return false;
    }
    if (owner.runtime.hello_due(now)) {
      if (written == output.size()) {
        run_ready_status_ = RunReadyStatus::output_budget_exhausted;
        return false;
      }
      if (!emit_hello(owner, output[written])) {
        run_ready_status_ = RunReadyStatus::hello_encoding_rejected;
        return false;
      }
      ++written;
      owner.runtime.hello_sent(now);
    }
    if (owner.configuration.protocol.network_type ==
        NetworkType::non_broadcast) {
      for (auto &peer : owner.nbma_peers) {
        if (peer.hello_deadline > now)
          continue;

        const auto state = peer.router_id == 0U
                               ? NeighborState::down
                               : neighbor_state(
                                     owner.configuration.protocol.interface_id,
                                     peer.router_id)
                                     .value_or(NeighborState::down);
        const bool local_eligible =
            owner.configuration.protocol.router_priority != 0U;
        const bool local_dr_or_bdr =
            owner.runtime.state() == InterfaceState::designated ||
            owner.runtime.state() == InterfaceState::backup;
        const auto peer_election_identity =
            version_ == packet::ospf::version_two
                ? static_cast<std::uint32_t>(
                      peer.configuration.address.bytes[0U])
                          << 24U |
                      static_cast<std::uint32_t>(
                          peer.configuration.address.bytes[1U])
                          << 16U |
                      static_cast<std::uint32_t>(
                          peer.configuration.address.bytes[2U])
                          << 8U |
                      peer.configuration.address.bytes[3U]
                : peer.router_id;
        const bool peer_is_dr_or_bdr =
            peer_election_identity != 0U &&
            (peer_election_identity == owner.runtime.designated_router() ||
             peer_election_identity ==
                 owner.runtime.backup_designated_router());
        const bool qualified =
            (local_eligible && peer.configuration.priority != 0U) ||
            local_dr_or_bdr || (!local_eligible && peer_is_dr_or_bdr);

        if (qualified) {
          if (written == output.size()) {
            run_ready_status_ = RunReadyStatus::output_budget_exhausted;
            return false;
          }
          if (!emit_nbma_hello(owner, peer, output[written])) {
            run_ready_status_ = RunReadyStatus::hello_encoding_rejected;
            return false;
          }
          ++written;
        }
        // RFC 2328 section 9.5.1 uses PollInterval only for a Down peer.
        // Every other state receives periodic Hellos at HelloInterval.
        peer.hello_deadline =
            now + std::chrono::seconds{
                      state == NeighborState::down
                          ? peer.configuration.poll_interval_seconds
                          : owner.configuration.protocol
                                .hello_interval_seconds};
      }
    }
    for (auto &neighbor : owner.exchanges) {
      if (!neighbor.pending_database_description &&
          neighbor.dd_retransmit_deadline != RuntimeClock::time_point{} &&
          neighbor.dd_retransmit_deadline <= now)
        neighbor.pending_database_description = true;
      if (!neighbor.pending_request &&
          neighbor.request_retransmit_deadline !=
              RuntimeClock::time_point{} &&
          neighbor.request_retransmit_deadline <= now &&
          !neighbor.database.requests().empty())
        neighbor.pending_request = true;
      if (!neighbor.pending_update &&
          neighbor.update_retransmit_deadline !=
              RuntimeClock::time_point{} &&
          neighbor.update_retransmit_deadline <= now &&
          !neighbor.database.retransmissions().empty())
        neighbor.pending_update = true;

      // Direct acknowledgments are sent before retransmissions and requests.
      // This reduces needless peer retransmission without changing protocol
      // ordering because every packet still traverses the same egress ring.
      if (neighbor.pending_acknowledgment) {
        if (written == output.size()) {
          run_ready_status_ = RunReadyStatus::output_budget_exhausted;
          return false;
        }
        if (!emit_link_state_acknowledgment(
                owner, neighbor, output[written])) {
          run_ready_status_ =
              RunReadyStatus::acknowledgment_encoding_rejected;
          return false;
        }
        retain_encoded_output();
      }
      if (neighbor.pending_database_description) {
        if (written == output.size()) {
          run_ready_status_ = RunReadyStatus::output_budget_exhausted;
          return false;
        }
        if (!emit_database_description(owner, neighbor, output[written], now)) {
          run_ready_status_ =
              RunReadyStatus::database_description_encoding_rejected;
          return false;
        }
        ++written;
      }
      if (neighbor.pending_update) {
        if (written == output.size()) {
          run_ready_status_ = RunReadyStatus::output_budget_exhausted;
          return false;
        }
        if (!emit_link_state_update(owner, neighbor, output[written], now)) {
          run_ready_status_ = RunReadyStatus::update_encoding_rejected;
          return false;
        }
        retain_encoded_output();
      }
      if (neighbor.pending_request) {
        if (written == output.size()) {
          run_ready_status_ = RunReadyStatus::output_budget_exhausted;
          return false;
        }
        if (!emit_link_state_request(owner, neighbor, output[written], now)) {
          run_ready_status_ = RunReadyStatus::request_encoding_rejected;
          return false;
        }
        ++written;
      }
    }
    if (!all_expired) {
      run_ready_status_ = RunReadyStatus::deadline_budget_exhausted;
      return false;
    }
  }
  return true;
}

std::optional<RuntimeClock::time_point>
InstanceProcess::next_deadline() const noexcept {
  std::optional<RuntimeClock::time_point> result;
  if (const auto database = database_deadline())
    result = database;
  if (pending_sequence_wraps_.empty() &&
      local_origination_deadline_ != RuntimeClock::time_point{})
    if (!result || local_origination_deadline_ < *result)
      result = local_origination_deadline_;
  if (spf_deadline_ != RuntimeClock::time_point{} &&
      (!result || spf_deadline_ < *result))
    result = spf_deadline_;
  for (const auto &owner : interfaces_) {
    const auto candidate = owner.runtime.next_deadline();
    if (candidate && (!result || *candidate < *result))
      result = candidate;
    for (const auto &peer : owner.nbma_peers)
      if (peer.hello_deadline != RuntimeClock::time_point{} &&
          (!result || peer.hello_deadline < *result))
        result = peer.hello_deadline;
    for (const auto &neighbor : owner.exchanges) {
      if (neighbor.helper_active &&
          neighbor.helper_deadline != RuntimeClock::time_point{} &&
          (!result || neighbor.helper_deadline < *result))
        result = neighbor.helper_deadline;
      if (neighbor.dd_retransmit_deadline != RuntimeClock::time_point{} &&
          (!result || neighbor.dd_retransmit_deadline < *result))
        result = neighbor.dd_retransmit_deadline;
      if (neighbor.request_retransmit_deadline !=
              RuntimeClock::time_point{} &&
          (!result || neighbor.request_retransmit_deadline < *result))
        result = neighbor.request_retransmit_deadline;
      if (neighbor.update_retransmit_deadline !=
              RuntimeClock::time_point{} &&
          (!result || neighbor.update_retransmit_deadline < *result))
        result = neighbor.update_retransmit_deadline;
    }
  }
  return result;
}

} // namespace router::ospf
