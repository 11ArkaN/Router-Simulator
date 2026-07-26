// OSPF process lifecycle, interface configuration and neighbor inspection.
// InstanceProcess owns protocol state and exchanges only encoded packets.

#include "ospf_process_internal.hpp"

namespace router::ospf {

InstanceProcess::InstanceProcess(
    std::uint32_t router_id, std::uint32_t area_id, std::uint8_t version,
    std::uint8_t instance_id, std::uint32_t initial_dd_sequence,
    std::size_t maximum_interfaces,
    std::size_t maximum_neighbors_per_interface, std::size_t maximum_lsas,
    std::chrono::milliseconds lsa_initial_wait,
    std::chrono::milliseconds lsa_second_wait,
    std::chrono::milliseconds lsa_maximum_wait,
    std::chrono::milliseconds spf_initial_wait,
    std::chrono::milliseconds spf_second_wait,
    std::chrono::milliseconds spf_maximum_wait)
    : database_(maximum_lsas),
      topology_(device_catalog::ospf_vertices_per_area,
                device_catalog::ospf_edges_per_area),
      spf_(device_catalog::ospf_vertices_per_area,
           device_catalog::ospf_edges_per_area),
      route_calculator_(device_catalog::maximum_dynamic_routes_per_router,
                        device_catalog::maximum_ecmp_paths),
      router_id_(router_id), area_id_(area_id),
      next_dd_sequence_(initial_dd_sequence),
      current_lsa_delay_(lsa_initial_wait),
      current_spf_delay_(spf_initial_wait),
      lsa_initial_wait_(lsa_initial_wait),
      lsa_second_wait_(lsa_second_wait),
      lsa_maximum_wait_(lsa_maximum_wait),
      spf_initial_wait_(spf_initial_wait),
      spf_second_wait_(spf_second_wait),
      spf_maximum_wait_(spf_maximum_wait),
      maximum_interfaces_(maximum_interfaces),
      maximum_neighbors_per_interface_(maximum_neighbors_per_interface),
      maximum_lsas_(maximum_lsas), version_(version),
      instance_id_(instance_id) {
  interfaces_.reserve(maximum_interfaces_);
  // Self-originated collisions are bounded by LSDB capacity. Reserving the
  // small control records up front prevents a normal fight-back burst from
  // reallocating the owner vectors; encoded payload storage remains allocated
  // only for collisions that actually arrive.
  pending_fight_backs_.reserve(maximum_lsas_);
  pending_sequence_wraps_.reserve(maximum_lsas_);
  coordinator_lsas_.reserve(maximum_lsas_);
  pending_coordinator_advertisements_.reserve(maximum_lsas_);
  virtual_endpoint_addresses_.reserve(maximum_interfaces_);
}

InstanceProcess::~InstanceProcess() {
  // Authentication material is intentionally absent from snapshots. Cleanse
  // the private owner copy with a provider barrier before vector storage is
  // released or reused.
  for (auto &owner : interfaces_) {
    if (owner.send_authentication)
      OPENSSL_cleanse(owner.send_authentication->key.data(),
                      owner.send_authentication->key.size());
    for (auto &authentication : owner.receive_authentications)
      OPENSSL_cleanse(authentication.key.data(),
                      authentication.key.size());
  }
}

bool InstanceProcess::reconcile_coordinator_advertisements(
    std::span<const CoordinatorAdvertisement> advertisements,
    RuntimeClock::time_point now) noexcept {
  // Copy one complete desired generation before scheduling it. If allocation
  // fails, the last published coordinator generation and LSDB remain intact.
  try {
    std::vector<CoordinatorAdvertisement> replacement;
    replacement.reserve(advertisements.size());
    for (const auto &advertisement : advertisements) {
      if (advertisement.metric > 0x00ffffffU ||
          advertisement.prefix.length >
              ip::address_bits(advertisement.prefix.network.family))
        return false;
      replacement.push_back(advertisement);
    }
    if (replacement == pending_coordinator_advertisements_ &&
        coordinator_reconcile_pending_)
      return true;
    pending_coordinator_advertisements_.swap(replacement);
    coordinator_reconcile_pending_ = true;
    schedule_local_origination(now);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

void InstanceProcess::set_router_roles(
    bool area_border_router, bool autonomous_system_boundary_router,
    bool virtual_link_endpoint, bool overload,
    RuntimeClock::time_point now) noexcept {
  if (area_border_router_ == area_border_router &&
      autonomous_system_boundary_router_ ==
          autonomous_system_boundary_router &&
      virtual_link_endpoint_ == virtual_link_endpoint &&
      overload_ == overload)
    return;
  area_border_router_ = area_border_router;
  autonomous_system_boundary_router_ =
      autonomous_system_boundary_router;
  virtual_link_endpoint_ = virtual_link_endpoint;
  overload_ = overload;
  schedule_local_origination(now);
}

void InstanceProcess::set_route_preferences(
    std::uint32_t router_preference,
    std::uint32_t external_preference) noexcept {
  // The duplicated boundary check protects the protocol owner if a malformed
  // shared-memory command bypasses canonical configuration validation.
  if (router_preference < 1U || router_preference > 255U ||
      external_preference < 1U || external_preference > 255U)
    return;
  router_preference_ = router_preference;
  external_preference_ = external_preference;
}

void InstanceProcess::set_loop_free_alternates(
    bool enabled, RuntimeClock::time_point now) noexcept {
  if (loop_free_alternates_ == enabled)
    return;
  loop_free_alternates_ = enabled;
  // The existing LSDB is sufficient to calculate or withdraw local repairs.
  // Scheduling the normal throttled SPF path preserves generation atomicity
  // and avoids publishing a primary route set from one calculation with LFA
  // rows from another.
  schedule_spf(now);
}

std::uint32_t InstanceProcess::allocate_coordinator_link_state_id(
    const CoordinatorAdvertisement &advertisement) noexcept {
  // OSPFv2 defines the Link State ID for Type 3, Type 4 and Type 5 LSAs.
  // OSPFv3 decouples prefix identity from the Link State ID, so a monotonically
  // allocated local value is retained in CoordinatorLsaState for the lifetime
  // of that advertisement. Zero is skipped because operational tooling and
  // malformed-record checks commonly use it as an absent identity.
  if (version_ == packet::ospf::version_two) {
    if (advertisement.kind ==
        CoordinatorAdvertisementKind::inter_area_router)
      return advertisement.destination_router_id;
    return static_cast<std::uint32_t>(
               advertisement.prefix.network.bytes[0U])
               << 24U |
           static_cast<std::uint32_t>(
               advertisement.prefix.network.bytes[1U])
               << 16U |
           static_cast<std::uint32_t>(
               advertisement.prefix.network.bytes[2U])
               << 8U |
           advertisement.prefix.network.bytes[3U];
  }
  if (external_advertisement(advertisement.kind) &&
      advertisement.source_link_state_id != 0U)
    return advertisement.source_link_state_id;
  auto candidate = next_coordinator_link_state_id_++;
  if (candidate == 0U)
    candidate = next_coordinator_link_state_id_++;
  return candidate;
}

std::optional<std::vector<std::uint8_t>>
InstanceProcess::encode_coordinator_lsa(
    const CoordinatorLsaState &state, std::uint16_t age) const noexcept {
  using namespace packet::ospf::lsa;
  try {
    std::array<std::uint8_t, packet::maximum_frame_octets> buffer{};
    std::optional<std::span<const std::uint8_t>> encoded;
    const auto &advertisement = state.advertisement;
    const auto type =
        version_ == packet::ospf::version_two
            ? advertisement.kind ==
                      CoordinatorAdvertisementKind::inter_area_prefix
                  ? version_two_summary_network_type
                  : advertisement.kind ==
                            CoordinatorAdvertisementKind::inter_area_router
                        ? version_two_summary_asbr_type
                        : advertisement.kind ==
                                  CoordinatorAdvertisementKind::nssa_external
                              ? version_two_nssa_type
                              : version_two_external_type
            : advertisement.kind ==
                      CoordinatorAdvertisementKind::inter_area_prefix
                  ? version_three_inter_area_prefix_type
                  : advertisement.kind ==
                            CoordinatorAdvertisementKind::inter_area_router
                        ? version_three_inter_area_router_type
                        : advertisement.kind ==
                                  CoordinatorAdvertisementKind::nssa_external
                              ? version_three_nssa_type
                              : version_three_external_type;
    const OriginationHeader header{
        .link_state_id = state.key.link_state_id,
        .advertising_router = router_id_,
        .sequence_number = state.sequence,
        .age_seconds = age,
        .type = type,
        .options =
            version_ == packet::ospf::version_two
                ? advertisement.kind ==
                          CoordinatorAdvertisementKind::nssa_external
                      // RFC 3101 uses the Type 7 P-bit to request translation
                      // by an elected NSSA border router.
                      ? packet::ospf::option_nssa_capability
                      : packet::ospf::option_external_routing_capability
                : 0U,
        .version = version_};

    if (version_ == packet::ospf::version_two) {
      const auto length = advertisement.prefix.length;
      const auto mask =
          length == 0U ? 0U : 0xffffffffU << (32U - length);
      if (external_advertisement(advertisement.kind)) {
        encoded = encode_version_two_external_lsa(
            buffer, header, mask, advertisement.metric,
            advertisement.type_two,
            advertisement.forwarding_address_v4, advertisement.tag);
      } else {
        encoded = encode_version_two_summary_lsa(
            buffer, header,
            advertisement.kind ==
                    CoordinatorAdvertisementKind::inter_area_router
                ? 0U
                : mask,
            advertisement.metric);
      }
    } else {
      PrefixInput prefix{
          .network = advertisement.prefix.network.bytes,
          .length = advertisement.prefix.length,
          // OSPFv3 carries the NSSA P-bit in PrefixOptions rather than the LSA
          // header options octet used by OSPFv2.
          .options =
              advertisement.kind ==
                      CoordinatorAdvertisementKind::nssa_external
                  ? std::uint8_t{0x08U}
                  : std::uint8_t{0U}};
      if (advertisement.kind ==
          CoordinatorAdvertisementKind::inter_area_prefix) {
        encoded = encode_version_three_inter_area_prefix_lsa(
            buffer, header, advertisement.metric, prefix);
      } else if (advertisement.kind ==
                 CoordinatorAdvertisementKind::inter_area_router) {
        encoded = encode_version_three_inter_area_router_lsa(
            buffer, header, 0U, advertisement.metric,
            advertisement.destination_router_id);
      } else {
        const bool has_forwarding =
            !ip::is_unspecified(advertisement.forwarding_address_v6);
        const auto forwarding_octets =
            advertisement.ipv4_forwarding_address ? 4U : 16U;
        encoded = encode_version_three_external_lsa(
            buffer, header, advertisement.metric, advertisement.type_two,
            prefix,
            has_forwarding
                ? std::span<const std::uint8_t>{
                      advertisement.forwarding_address_v6}
                      .first(forwarding_octets)
                : std::span<const std::uint8_t>{},
            std::optional<std::uint32_t>{advertisement.tag}, 0U,
            std::nullopt);
      }
    }
    if (!encoded)
      return std::nullopt;
    return std::vector<std::uint8_t>(encoded->begin(), encoded->end());
  } catch (const std::bad_alloc &) {
    return std::nullopt;
  }
}

bool InstanceProcess::apply_coordinator_advertisements(
    RuntimeClock::time_point now) noexcept {
  if (!coordinator_reconcile_pending_)
    return true;

  const auto same_identity = [](const CoordinatorAdvertisement &left,
                                const CoordinatorAdvertisement &right) {
    return left.kind == right.kind && left.prefix == right.prefix &&
           left.destination_router_id == right.destination_router_id &&
           left.source_link_state_id == right.source_link_state_id;
  };

  bool sequence_wrap_requested{};
  try {
    // Add or replace desired records first. This ordering avoids a transient
    // withdrawal when only a metric or external tag changed.
    for (const auto &desired : pending_coordinator_advertisements_) {
      auto state = std::find_if(
          coordinator_lsas_.begin(), coordinator_lsas_.end(),
          [&](const auto &current) {
            return same_identity(current.advertisement, desired);
          });
      if (state == coordinator_lsas_.end()) {
        if (coordinator_lsas_.size() == maximum_lsas_)
          return false;
        CoordinatorLsaState created{
            .advertisement = desired,
            .key =
                {.link_state_id =
                     allocate_coordinator_link_state_id(desired),
                 .advertising_router = router_id_,
                 .type =
                     version_ == packet::ospf::version_two
                         ? desired.kind ==
                                   CoordinatorAdvertisementKind::
                                       inter_area_prefix
                               ? packet::ospf::lsa::
                                     version_two_summary_network_type
                               : desired.kind ==
                                         CoordinatorAdvertisementKind::
                                             inter_area_router
                                     ? packet::ospf::lsa::
                                           version_two_summary_asbr_type
                                     : desired.kind ==
                                               CoordinatorAdvertisementKind::
                                                   nssa_external
                                           ? packet::ospf::lsa::
                                                 version_two_nssa_type
                                           : packet::ospf::lsa::
                                                 version_two_external_type
                         : desired.kind ==
                                   CoordinatorAdvertisementKind::
                                       inter_area_prefix
                               ? packet::ospf::lsa::
                                     version_three_inter_area_prefix_type
                               : desired.kind ==
                                         CoordinatorAdvertisementKind::
                                             inter_area_router
                                     ? packet::ospf::lsa::
                                           version_three_inter_area_router_type
                                     : desired.kind ==
                                               CoordinatorAdvertisementKind::
                                                   nssa_external
                                           ? packet::ospf::lsa::
                                                 version_three_nssa_type
                                           : packet::ospf::lsa::
                                                 version_three_external_type,
                 .scope =
                     desired.kind ==
                             CoordinatorAdvertisementKind::
                                 translated_external
                         ? FloodingScope::autonomous_system
                         : FloodingScope::area}};
        coordinator_lsas_.push_back(std::move(created));
        state = std::prev(coordinator_lsas_.end());
      } else if (state->advertisement != desired ||
                 state->withdrawing) {
        if (state->sequence == maximum_sequence_number) {
          // The desired semantics are retained while RFC 2328 sequence wrap
          // flushes the old generation. No lower sequence may be installed
          // until reliable MaxAge removal completes.
          state->advertisement = desired;
          state->withdrawing = false;
          state->sequence_at_max = true;
          sequence_wrap_requested = true;
          continue;
        }
        ++state->sequence;
        state->advertisement = desired;
        state->withdrawing = false;
      } else {
        continue;
      }

      const auto bytes = encode_coordinator_lsa(*state, 0U);
      if (!bytes)
        return false;
      const auto installed =
          database_.install(*bytes, version_, now, router_id_, false);
      if (installed != InstallResult::installed &&
          installed != InstallResult::identical)
        return false;
      const auto *record = database_.find(state->key);
      if (!record || !flood_record(*record, now))
        return false;
    }

    // Withdraw every previously originated record absent from the desired
    // generation. MaxAge remains in the LSDB until reliable flooding and all
    // retransmission acknowledgments make removal safe.
    for (auto &state : coordinator_lsas_) {
      const bool desired = std::any_of(
          pending_coordinator_advertisements_.begin(),
          pending_coordinator_advertisements_.end(),
          [&](const auto &candidate) {
            return same_identity(state.advertisement, candidate);
          });
      if (desired || state.withdrawing)
        continue;
      if (state.sequence == maximum_sequence_number) {
        // Withdrawal reuses the current sequence at MaxAge. Unlike a changed
        // still-desired LSA, it has no replacement generation to restart.
        state.withdrawing = true;
      } else {
        ++state.sequence;
        state.withdrawing = true;
      }
      const auto bytes =
          encode_coordinator_lsa(state, max_age_seconds);
      if (!bytes)
        return false;
      const auto installed =
          database_.install(*bytes, version_, now, router_id_, false);
      if (installed != InstallResult::installed &&
          installed != InstallResult::identical)
        return false;
      const auto *record = database_.find(state.key);
      if (!record || !flood_record(*record, now) ||
          !database_.mark_max_age_flooded(state.key))
        return false;
    }
  } catch (const std::bad_alloc &) {
    return false;
  }

  coordinator_reconcile_pending_ = sequence_wrap_requested;
  schedule_spf(now);
  return true;
}

bool InstanceProcess::add_interface(
    const ProcessInterfaceConfiguration &configuration,
    RuntimeClock::time_point now) noexcept {
  auto normalized = configuration;
  if (normalized.protocol.version == packet::ospf::version_two) {
    // The packet-facing configuration keeps the address as four wire octets.
    // Normalize it once at the process ownership boundary so the interface FSM
    // can compare OSPFv2 DR/BDR declarations without repeatedly decoding it or
    // borrowing state from forwarding.
    normalized.protocol.local_election_identity =
        static_cast<std::uint32_t>(normalized.ipv4_source[0U]) << 24U |
        static_cast<std::uint32_t>(normalized.ipv4_source[1U]) << 16U |
        static_cast<std::uint32_t>(normalized.ipv4_source[2U]) << 8U |
        normalized.ipv4_source[3U];
  }
  if (interfaces_.size() == maximum_interfaces_ ||
      !InterfaceRuntime::validate_configuration(normalized.protocol) ||
      normalized.protocol.router_id != router_id_ ||
      normalized.protocol.area_id != area_id_ ||
      normalized.protocol.version != version_ ||
      normalized.protocol.instance_id != instance_id_ ||
      normalized.retransmit_interval_seconds == 0U ||
      normalized.transmit_delay_seconds == 0U ||
      interface(normalized.protocol.interface_id))
    return false;
  if (normalized.protocol.network_type == NetworkType::virtual_link) {
    const auto expected =
        version_ == packet::ospf::version_two
            ? ip::AddressFamily::ipv4
            : ip::AddressFamily::ipv6;
    if (normalized.virtual_neighbor_router_id == 0U ||
        normalized.virtual_neighbor_router_id == router_id_ ||
        normalized.virtual_neighbor_address.family != expected ||
        std::all_of(normalized.virtual_neighbor_address.bytes.begin(),
                    normalized.virtual_neighbor_address.bytes.end(),
                    [](std::uint8_t octet) { return octet == 0U; }) ||
        normalized.physical_port_ordinal == no_physical_port)
      return false;
  } else if (normalized.virtual_neighbor_router_id != 0U) {
    return false;
  }
  try {
    interfaces_.emplace_back(normalized,
                             maximum_neighbors_per_interface_, now);
    // An enabled interface changes the locally originated Router-LSA even
    // before it has a neighbor because its attached prefix is reachable.
    schedule_local_origination(now);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::set_interface_authentication(
    std::uint32_t interface_id,
    const std::optional<ProcessAuthentication> &send_authentication,
    std::span<const ProcessAuthentication> receive_authentications) noexcept {
  auto *owner = interface(interface_id);
  if (!owner)
    return false;
  const auto valid = [&](const ProcessAuthentication &authentication) {
    return authentication.key_size != 0U &&
           authentication.key_size <= authentication.key.size() &&
           (version_ != packet::ospf::version_two ||
            authentication.key_id <=
                std::numeric_limits<std::uint8_t>::max()) &&
           (version_ != packet::ospf::version_three ||
            (authentication.ipsec_ah
                 ? authentication.algorithm ==
                           KeychainAlgorithm::message_digest ||
                       authentication.algorithm ==
                           KeychainAlgorithm::hmac_sha1
                 : authentication.algorithm ==
                           KeychainAlgorithm::hmac_sha1 ||
                       authentication.algorithm ==
                           KeychainAlgorithm::hmac_sha256));
  };
  if ((send_authentication && !valid(*send_authentication)) ||
      receive_authentications.size() > 64U ||
      std::any_of(receive_authentications.begin(),
                  receive_authentications.end(),
                  [&](const auto &authentication) {
                    return !valid(authentication);
                  }) ||
      [&] {
        for (std::size_t index{}; index < receive_authentications.size();
             ++index)
          for (std::size_t prior{}; prior < index; ++prior)
            if (receive_authentications[prior].key_id ==
                receive_authentications[index].key_id)
              return true;
        return false;
      }())
    return false;

  std::vector<ProcessAuthentication> staged;
  try {
    staged.assign(receive_authentications.begin(),
                  receive_authentications.end());
    // A direct interface key has one bidirectional lifetime. Keychains pass
    // their complete receive set explicitly so overlapping rollover entries
    // remain acceptable after the send key advances.
    if (staged.empty() && send_authentication)
      staged.push_back(*send_authentication);
  } catch (const std::bad_alloc &) {
    return false;
  }
  if (owner->send_authentication == send_authentication &&
      owner->receive_authentications == staged)
    return true;
  if (owner->send_authentication)
    OPENSSL_cleanse(owner->send_authentication->key.data(),
                    owner->send_authentication->key.size());
  for (auto &authentication : owner->receive_authentications)
    OPENSSL_cleanse(authentication.key.data(), authentication.key.size());
  owner->send_authentication = send_authentication;
  owner->receive_authentications = std::move(staged);
  owner->authentication_sequence =
      send_authentication ? send_authentication->initial_sequence : 0U;
  owner->authentication_send_key_id =
      send_authentication ? send_authentication->key_id : 0U;
  owner->authentication_required =
      send_authentication.has_value() ||
      !owner->receive_authentications.empty();
  owner->ipsec_replay_sequence = 0U;
  owner->ipsec_replay_sequence_seen = false;
  return true;
}

bool InstanceProcess::replace_virtual_interface(
    const ProcessInterfaceConfiguration &configuration,
    RuntimeClock::time_point now) noexcept {
  if (configuration.protocol.network_type !=
      NetworkType::virtual_link)
    return false;
  auto normalized = configuration;
  if (normalized.protocol.version == packet::ospf::version_two) {
    // add_interface stores the OSPFv2 election identity in canonical host
    // order. The ABR coordinator deliberately supplies only packet-facing
    // address octets, so compare the same canonical representation here.
    // Comparing raw input with the stored normalized record made every stable
    // route-coordination pass look like a transport change and destroyed the
    // virtual neighbor FSM before its second Hello could establish two-way
    // communication.
    normalized.protocol.local_election_identity =
        static_cast<std::uint32_t>(normalized.ipv4_source[0U]) << 24U |
        static_cast<std::uint32_t>(normalized.ipv4_source[1U]) << 16U |
        static_cast<std::uint32_t>(normalized.ipv4_source[2U]) << 8U |
        normalized.ipv4_source[3U];
  }
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return owner.configuration.protocol.interface_id ==
               normalized.protocol.interface_id;
      });
  if (found != interfaces_.end()) {
    if (found->configuration == normalized)
      return true;
    if (found->configuration.protocol.network_type !=
        NetworkType::virtual_link)
      return false;
    interfaces_.erase(found);
  }
  return add_interface(normalized, now);
}

bool InstanceProcess::remove_virtual_interface(
    std::uint32_t interface_id,
    RuntimeClock::time_point now) noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return owner.configuration.protocol.interface_id == interface_id;
      });
  if (found == interfaces_.end())
    return true;
  if (found->configuration.protocol.network_type !=
      NetworkType::virtual_link)
    return false;
  interfaces_.erase(found);
  schedule_local_origination(now);
  return true;
}

bool InstanceProcess::add_nbma_neighbor(
    std::uint32_t interface_id,
    const ProcessNbmaNeighborConfiguration &configuration,
    RuntimeClock::time_point now) noexcept {
  auto *owner = interface(interface_id);
  if (!owner ||
      owner->configuration.protocol.network_type !=
          NetworkType::non_broadcast ||
      configuration.poll_interval_seconds == 0U ||
      configuration.address.family !=
          (version_ == packet::ospf::version_two
               ? ip::AddressFamily::ipv4
               : ip::AddressFamily::ipv6) ||
      std::all_of(configuration.address.bytes.begin(),
                  configuration.address.bytes.end(),
                  [](std::uint8_t octet) { return octet == 0U; }) ||
      owner->nbma_peers.size() == maximum_neighbors_per_interface_ ||
      std::any_of(owner->nbma_peers.begin(), owner->nbma_peers.end(),
                  [&](const auto &peer) {
                    return peer.configuration.address ==
                           configuration.address;
                  }))
    return false;
  try {
    // RFC 2328 section C.5 starts discovery when an eligible NBMA interface
    // comes up. Qualification is checked at the owner turn because DR/BDR
    // state can change without changing this static transport record.
    owner->nbma_peers.push_back(
        {.configuration = configuration, .hello_deadline = now});
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::remove_interface(
    std::uint32_t interface_id, RuntimeClock::time_point now) noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return owner.configuration.protocol.interface_id == interface_id;
      });
  if (found == interfaces_.end())
    return false;
  interfaces_.erase(found);
  // Withdrawal is represented by a newer self-originated LSA that omits the
  // removed link. It follows the same MinLSInterval rule as an addition.
  schedule_local_origination(now);
  return true;
}

std::size_t InstanceProcess::reset_neighbors(
    std::uint32_t interface_id, std::uint32_t neighbor_router_id,
    RuntimeClock::time_point now) noexcept {
  std::size_t reset{};
  for (auto &owner : interfaces_) {
    if (interface_id != 0U &&
        owner.configuration.protocol.interface_id != interface_id)
      continue;
    // KillNbr deletes the row after its cleanup actions run. Copy only the
    // bounded router identities first so vector compaction cannot invalidate
    // iteration. Allocation failure leaves every neighbor unchanged.
    std::vector<std::uint32_t> router_ids;
    try {
      router_ids.reserve(owner.runtime.neighbors().size());
      for (const auto &neighbor : owner.runtime.neighbors())
        router_ids.push_back(neighbor.router_id);
    } catch (const std::bad_alloc &) {
      return reset;
    }
    for (const auto router_id : router_ids) {
      if (neighbor_router_id != 0U &&
          router_id != neighbor_router_id)
        continue;
      const auto transition = owner.runtime.apply_neighbor_event(
          router_id, NeighborEvent::kill_neighbor, false);
      if (!transition ||
          !apply_neighbor_actions(owner, router_id,
                                  transition->actions, now))
        continue;
      if (has_action(transition->actions,
                     NeighborAction::notify_interface)) {
        const auto interface_actions =
            owner.runtime.neighbor_change(false);
        if (!reconcile_interface_adjacencies(owner, interface_actions, now))
          continue;
      }
      ++reset;
    }
  }
  return reset;
}

bool InstanceProcess::reset_database(
    RuntimeClock::time_point now) noexcept {
  // SR OS reset database discards received LSAs, regresses established
  // adjacencies to one-way processing and refreshes every self-originated LSA.
  // Collect keys first because LinkStateDatabase::erase compacts storage.
  std::vector<LsaKey> received;
  try {
    received.reserve(database_.records().size());
    for (const auto &record : database_.records())
      if (record.key.advertising_router != router_id_)
        received.push_back(record.key);
  } catch (const std::bad_alloc &) {
    return false;
  }
  for (const auto &key : received)
    if (!database_.erase(key))
      return false;

  for (auto &owner : interfaces_)
    for (std::size_t index{}; index < owner.runtime.neighbors().size();
         ++index) {
      const auto router_id = owner.runtime.neighbors()[index].router_id;
      const auto state = owner.runtime.neighbors()[index].state;
      if (state <= NeighborState::two_way)
        continue;
      const auto transition = owner.runtime.apply_neighbor_event(
          router_id, NeighborEvent::one_way_received, false);
      if (!transition ||
          !apply_neighbor_actions(owner, router_id,
                                  transition->actions, now))
        return false;
    }
  schedule_local_origination(now);
  schedule_spf(now);
  return true;
}

InstanceProcess::InterfaceOwner *
InstanceProcess::interface(std::uint32_t interface_id) noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](auto &owner) {
        return owner.configuration.protocol.interface_id == interface_id;
      });
  return found == interfaces_.end() ? nullptr : &*found;
}

std::optional<NeighborState> InstanceProcess::neighbor_state(
    std::uint32_t interface_id,
    std::uint32_t neighbor_router_id) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.configuration.protocol.interface_id == interface_id;
      });
  if (owner == interfaces_.end())
    return std::nullopt;
  const auto neighbor = std::find_if(
      owner->runtime.neighbors().begin(), owner->runtime.neighbors().end(),
      [&](const auto &candidate) {
        return candidate.router_id == neighbor_router_id;
      });
  return neighbor == owner->runtime.neighbors().end()
             ? std::nullopt
             : std::optional<NeighborState>{neighbor->state};
}

std::optional<InterfaceState>
InstanceProcess::interface_state(std::uint32_t interface_id) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.configuration.protocol.interface_id == interface_id;
      });
  return owner == interfaces_.end()
             ? std::nullopt
             : std::optional<InterfaceState>{owner->runtime.state()};
}

std::optional<std::uint32_t>
InstanceProcess::designated_router(
    std::uint32_t interface_id) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.configuration.protocol.interface_id == interface_id;
      });
  return owner == interfaces_.end()
             ? std::nullopt
             : std::optional<std::uint32_t>{
                   owner->runtime.designated_router()};
}

std::optional<std::uint32_t> InstanceProcess::interface_id_for_port(
    std::uint16_t physical_port_ordinal) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.configuration.physical_port_ordinal ==
               physical_port_ordinal;
      });
  return owner == interfaces_.end()
             ? std::nullopt
             : std::optional<std::uint32_t>{
                   owner->configuration.protocol.interface_id};
}

std::optional<std::uint32_t> InstanceProcess::interface_id_for_packet(
    std::uint16_t physical_port_ordinal,
    std::uint32_t source_router_id) const noexcept {
  // A virtual packet is received through an ordinary transit-area port, but
  // belongs to the backbone interface configured for its source Router ID.
  // Search that exact tuple before the physical interface fallback because a
  // backbone process can also have a real area-0 interface on the same port.
  const auto virtual_owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &candidate) {
        return candidate.configuration.protocol.network_type ==
                   NetworkType::virtual_link &&
               candidate.configuration.physical_port_ordinal ==
                   physical_port_ordinal &&
               candidate.configuration.virtual_neighbor_router_id ==
                   source_router_id;
      });
  if (virtual_owner != interfaces_.end())
    return virtual_owner->configuration.protocol.interface_id;
  return interface_id_for_port(physical_port_ordinal);
}

std::optional<VirtualLinkResolution>
InstanceProcess::resolve_virtual_link(
    std::uint32_t remote_router_id) const noexcept {
  if (remote_router_id == 0U || remote_router_id == router_id_)
    return std::nullopt;
  const auto graph = topology_.graph();
  const auto remote = std::find_if(
      graph.keys.begin(), graph.keys.end(), [&](const auto &key) {
        return key.kind == TopologyVertexKind::router &&
               key.id == remote_router_id;
      });
  if (remote == graph.keys.end())
    return std::nullopt;
  const auto remote_vertex =
      static_cast<std::size_t>(std::distance(graph.keys.begin(), remote));
  const auto cost = spf_.cost(remote_vertex);
  if (!cost || *cost == 0U || *cost > ls_infinity ||
      spf_.first_hop_count(remote_vertex) == 0U)
    return std::nullopt;
  const auto hop_token = spf_.first_hop(remote_vertex, 0U);
  if (!hop_token || *hop_token >= graph.first_hops.size())
    return std::nullopt;
  const auto &hop = graph.first_hops[*hop_token];
  const auto local = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        if (owner.configuration.protocol.network_type ==
            NetworkType::virtual_link)
          return false;
        if (version_ == packet::ospf::version_two) {
          const auto address =
              static_cast<std::uint32_t>(
                  owner.configuration.ipv4_source[0U])
                  << 24U |
              static_cast<std::uint32_t>(
                  owner.configuration.ipv4_source[1U])
                  << 16U |
              static_cast<std::uint32_t>(
                  owner.configuration.ipv4_source[2U])
                  << 8U |
              owner.configuration.ipv4_source[3U];
          return address == hop.local_interface;
        }
        return owner.configuration.protocol.interface_id ==
               hop.local_interface;
      });
  if (local == interfaces_.end() ||
      local->configuration.physical_port_ordinal == no_physical_port)
    return std::nullopt;

  VirtualLinkResolution result{
      .source_mac = local->configuration.source_mac,
      .local_physical_interface_id =
          local->configuration.protocol.interface_id,
      .remote_router_id = remote_router_id,
      .cost = *cost,
      .physical_port_ordinal =
          local->configuration.physical_port_ordinal,
      .interface_mtu =
          local->configuration.protocol.interface_mtu};
  result.local_address.family =
      version_ == packet::ospf::version_two
          ? ip::AddressFamily::ipv4
          : ip::AddressFamily::ipv6;
  result.remote_address.family = result.local_address.family;

  if (version_ == packet::ospf::version_two) {
    std::copy(local->configuration.ipv4_source.begin(),
              local->configuration.ipv4_source.end(),
              result.local_address.bytes.begin());

    // RFC 2328 section 16.1 derives the virtual neighbor address from the
    // remote Router-LSA link that points back toward the SPF root. Find a
    // deterministic shortest-path predecessor and then read that exact
    // link_data value rather than using the editor or a subnet heuristic.
    std::optional<std::size_t> predecessor;
    for (std::size_t vertex{}; vertex < graph.vertices.size(); ++vertex) {
      const auto predecessor_cost = spf_.cost(vertex);
      if (!predecessor_cost)
        continue;
      const auto &description = graph.vertices[vertex];
      for (std::size_t edge{}; edge < description.edge_count; ++edge) {
        const auto &candidate =
            graph.edges[description.first_edge + edge];
        if (candidate.target_vertex == remote_vertex &&
            *predecessor_cost + candidate.cost == *cost) {
          predecessor = vertex;
          break;
        }
      }
      if (predecessor)
        break;
    }
    if (!predecessor)
      return std::nullopt;
    const auto record = std::find_if(
        database_.records().begin(), database_.records().end(),
        [&](const auto &candidate) {
          const auto header =
              packet::ospf::lsa_header(candidate.bytes, version_);
          return header && header->type == 1U &&
                 header->advertising_router == remote_router_id;
        });
    if (record == database_.records().end())
      return std::nullopt;
    const auto router =
        packet::ospf::lsa::parse_version_two_router(record->bytes);
    if (!router)
      return std::nullopt;
    const auto &predecessor_key = graph.keys[*predecessor];
    std::size_t offset{};
    for (std::size_t index{}; index < router->link_count; ++index) {
      const auto link =
          packet::ospf::lsa::version_two_router_link(*router, offset);
      if (!link)
        return std::nullopt;
      offset = link->next_offset;
      const bool matches =
          predecessor_key.kind == TopologyVertexKind::router
              ? ((link->type ==
                      packet::ospf::lsa::RouterLinkType::point_to_point ||
                  link->type ==
                      packet::ospf::lsa::RouterLinkType::virtual_link) &&
                 link->link_id == predecessor_key.id)
              : (link->type ==
                     packet::ospf::lsa::RouterLinkType::transit_network &&
                 link->link_id == predecessor_key.id);
      if (!matches)
        continue;
      result.remote_address.bytes[0U] =
          static_cast<std::uint8_t>(link->link_data >> 24U);
      result.remote_address.bytes[1U] =
          static_cast<std::uint8_t>(link->link_data >> 16U);
      result.remote_address.bytes[2U] =
          static_cast<std::uint8_t>(link->link_data >> 8U);
      result.remote_address.bytes[3U] =
          static_cast<std::uint8_t>(link->link_data);
      result.remote_address_known = link->link_data != 0U;
      return result.remote_address_known
                 ? std::optional<VirtualLinkResolution>{result}
                 : std::nullopt;
    }
    return std::nullopt;
  }

  // RFC 5340 sections 4.7 and 4.8.1 require global-scope source and peer
  // addresses. The local source is the selected transit egress address. The
  // remote address is the first LA-bit /128 originated by that router.
  result.local_address.bytes = local->configuration.ipv6_prefix;
  if (ip::is_unspecified(result.local_address.bytes) ||
      ip::is_link_local(result.local_address.bytes) ||
      ip::is_multicast(result.local_address.bytes))
    return std::nullopt;
  for (const auto &record : database_.records()) {
    const auto header =
        packet::ospf::lsa_header(record.bytes, version_);
    if (!header ||
        (header->type & 0x1fffU) != 9U ||
        header->advertising_router != remote_router_id)
      continue;
    const auto prefixes =
        packet::ospf::lsa::parse_version_three_intra_area_prefix(
            record.bytes);
    if (!prefixes)
      return std::nullopt;
    std::size_t offset{};
    for (std::size_t index{}; index < prefixes->prefix_count; ++index) {
      const auto prefix = packet::ospf::lsa::version_three_prefix(
          prefixes->prefixes, offset, true);
      if (!prefix)
        return std::nullopt;
      offset = prefix->next_offset;
      // LA is bit 1 in PrefixOptions. RFC 5340 section 4.4.3.9 mandates
      // PrefixLength 128 and Metric 0 for virtual-link address discovery.
      if ((prefix->options & 0x02U) == 0U ||
          prefix->length != 128U || prefix->metric != 0U)
        continue;
      const auto address =
          packet::ospf::lsa::expand_prefix(*prefix);
      if (!address || ip::is_unspecified(*address) ||
          ip::is_link_local(*address) || ip::is_multicast(*address))
        continue;
      result.remote_address.bytes = *address;
      result.remote_address_known = true;
      return result;
    }
  }
  return result;
}

bool InstanceProcess::set_virtual_endpoint_addresses(
    std::span<const ip::Ipv6> addresses,
    RuntimeClock::time_point now) noexcept {
  if (version_ != packet::ospf::version_three && !addresses.empty())
    return false;
  try {
    std::vector<ip::Ipv6> replacement;
    replacement.reserve(addresses.size());
    for (const auto &address : addresses) {
      if (ip::is_unspecified(address) || ip::is_link_local(address) ||
          ip::is_multicast(address))
        return false;
      if (std::find(replacement.begin(), replacement.end(), address) ==
          replacement.end())
        replacement.push_back(address);
    }
    std::sort(replacement.begin(), replacement.end());
    if (replacement == virtual_endpoint_addresses_)
      return true;
    virtual_endpoint_addresses_.swap(replacement);
    schedule_local_origination(now);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

std::optional<ProcessInterfaceSnapshot>
InstanceProcess::interface_snapshot(std::size_t index) const noexcept {
  if (index >= interfaces_.size())
    return std::nullopt;
  const auto &owner = interfaces_[index];
  return ProcessInterfaceSnapshot{
      .configuration = owner.configuration,
      .state = owner.runtime.state(),
      .designated_router = owner.runtime.designated_router(),
      .backup_designated_router =
          owner.runtime.backup_designated_router(),
      .neighbor_count =
          static_cast<std::uint32_t>(owner.runtime.neighbors().size())};
}

std::optional<ProcessNeighborSnapshot>
InstanceProcess::neighbor_snapshot(std::size_t interface_index,
                                   std::size_t neighbor_index) const noexcept {
  if (interface_index >= interfaces_.size())
    return std::nullopt;
  const auto &owner = interfaces_[interface_index];
  const auto neighbors = owner.runtime.neighbors();
  if (neighbor_index >= neighbors.size())
    return std::nullopt;
  const auto &runtime = neighbors[neighbor_index];
  const auto exchange = std::find_if(
      owner.exchanges.begin(), owner.exchanges.end(), [&](const auto &entry) {
        return entry.router_id == runtime.router_id;
      });
  // A Hello creates the exchange record in the same owner turn as the FSM
  // neighbor. Treat a missing correlation as an unavailable snapshot instead
  // of inventing an all-zero transport address.
  if (exchange == owner.exchanges.end())
    return std::nullopt;
  const auto now = RuntimeClock::now();
  const auto elapsed_seconds =
      [now](RuntimeClock::time_point point) noexcept -> std::uint32_t {
    if (point == RuntimeClock::time_point{} || point >= now)
      return 0U;
    const auto value = std::chrono::duration_cast<std::chrono::seconds>(
                           now - point)
                           .count();
    return value > std::numeric_limits<std::uint32_t>::max()
               ? std::numeric_limits<std::uint32_t>::max()
               : static_cast<std::uint32_t>(value);
  };
  const auto remaining_seconds =
      [now](RuntimeClock::time_point point) noexcept -> std::uint32_t {
    if (point == RuntimeClock::time_point{} || point <= now)
      return 0U;
    const auto value = std::chrono::duration_cast<std::chrono::seconds>(
                           point - now)
                           .count();
    return value > std::numeric_limits<std::uint32_t>::max()
               ? std::numeric_limits<std::uint32_t>::max()
               : static_cast<std::uint32_t>(value);
  };
  return ProcessNeighborSnapshot{
      .runtime = runtime,
      .ipv4_address = exchange->ipv4_address,
      .ipv6_address = exchange->ipv6_address,
      .dd_sequence = exchange->dd_sequence,
      .local_interface_id = owner.configuration.protocol.interface_id,
      .retransmission_queue_length = static_cast<std::uint32_t>(
          std::min<std::size_t>(
              exchange->database.retransmissions().size(),
              std::numeric_limits<std::uint32_t>::max())),
      .request_queue_length = static_cast<std::uint32_t>(
          std::min<std::size_t>(
              exchange->database.requests().size(),
              std::numeric_limits<std::uint32_t>::max())),
      .up_time_seconds = elapsed_seconds(runtime.state_since),
      .time_before_dead_seconds =
          remaining_seconds(runtime.inactivity_deadline),
      .last_event_seconds_ago = elapsed_seconds(runtime.last_event_at),
      .last_restart_seconds_ago = elapsed_seconds(runtime.last_restart_at),
      .graceful_restart_helper_age_seconds =
          elapsed_seconds(exchange->helper_started_at),
      .negotiation_complete = exchange->negotiation_complete,
      .database_description_pending =
          exchange->pending_database_description,
      .local_master = exchange->local_master,
      .graceful_restart_helper =
          exchange->helper_active && exchange->helper_deadline > now};
}

} // namespace router::ospf
