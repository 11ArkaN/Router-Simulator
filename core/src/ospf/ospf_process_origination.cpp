// OSPF LSA origination and validated packet reception.
// InstanceProcess owns protocol mutations and consumes only decoded wire input.

#include "ospf_process_internal.hpp"

namespace router::ospf {

bool InstanceProcess::originate_local_lsas(
    RuntimeClock::time_point now) noexcept {
  using namespace packet::ospf::lsa;
  local_origination_status_ = LocalOriginationStatus::succeeded;
  local_origination_install_result_ = InstallResult::installed;
  try {
    if (!apply_coordinator_advertisements(now)) {
      local_origination_status_ =
          LocalOriginationStatus::router_install_rejected;
      return false;
    }
    bool wrap_started{};
    if (!apply_pending_fight_backs(now, wrap_started)) {
      local_origination_status_ =
          LocalOriginationStatus::router_install_rejected;
      return false;
    }
    if (!wrap_started &&
        !flush_exhausted_sequences(now, wrap_started)) {
      local_origination_status_ =
          LocalOriginationStatus::router_flood_rejected;
      return false;
    }
    if (wrap_started) {
      // A MaxSequenceNumber flush and its InitialSequenceNumber replacement
      // cannot coexist in one LSDB generation. ACK or neighbor-state input
      // will wake maintenance, which removes the safe MaxAge record and
      // schedules the restart.
      last_local_origination_ = now;
      local_origination_deadline_ = {};
      schedule_spf(now);
      return true;
    }
    std::array<std::uint8_t, packet::maximum_frame_octets> encoded{};
    std::optional<std::span<const std::uint8_t>> router_lsa;

    if (version_ == packet::ospf::version_two) {
      std::vector<VersionTwoRouterLinkInput> links;
      for (auto &owner : interfaces_) {
        const auto &configuration = owner.configuration;
        if (!configuration.protocol.enabled)
          continue;
        const auto local = static_cast<std::uint32_t>(
                               configuration.ipv4_source[0U])
                               << 24U |
                           static_cast<std::uint32_t>(
                               configuration.ipv4_source[1U])
                               << 16U |
                           static_cast<std::uint32_t>(
                               configuration.ipv4_source[2U])
                               << 8U |
                           configuration.ipv4_source[3U];
        const auto mask =
            configuration.prefix_length == 0U
                ? 0U
                : std::numeric_limits<std::uint32_t>::max()
                      << (32U - configuration.prefix_length);

        const bool multi_access =
            configuration.protocol.network_type == NetworkType::broadcast ||
            configuration.protocol.network_type ==
                NetworkType::non_broadcast;
        const bool virtual_link =
            configuration.protocol.network_type ==
            NetworkType::virtual_link;
        const bool has_full_neighbor = std::any_of(
            owner.runtime.neighbors().begin(),
            owner.runtime.neighbors().end(), [&](const auto &neighbor) {
              return advertised_full(owner, neighbor.router_id, now);
            });
        auto effective_designated = owner.runtime.designated_router();
        for (const auto &neighbor : owner.exchanges)
          if (neighbor.helper_active &&
              neighbor.helper_deadline > now &&
              neighbor.helper_was_designated_router)
            effective_designated =
                static_cast<std::uint32_t>(
                    neighbor.ipv4_address[0U]) << 24U |
                static_cast<std::uint32_t>(
                    neighbor.ipv4_address[1U]) << 16U |
                static_cast<std::uint32_t>(
                    neighbor.ipv4_address[2U]) << 8U |
                neighbor.ipv4_address[3U];
        const bool transit =
            multi_access && has_full_neighbor &&
            effective_designated != 0U;

        if (virtual_link) {
          // RFC 2328 section 12.4.1 represents an operational virtual
          // adjacency as Type 4 only. It has no attached stub network and its
          // cost is the transit-area SPF cost supplied by the coordinator.
          for (const auto &neighbor : owner.runtime.neighbors())
            if (advertised_full(owner, neighbor.router_id, now))
              links.push_back(
                  {.link_id = neighbor.router_id,
                   .link_data = local,
                   .metric = configuration.metric,
                   .type = RouterLinkType::virtual_link});
          continue;
        } else if (transit) {
          // RFC 2328 section 12.4.1.2 identifies a transit network with the
          // DR's interface IPv4 address. link_data remains this router's own
          // interface address and is later used as the scoped first-hop token.
          links.push_back(
              {.link_id = effective_designated,
               .link_data = local,
               // RFC 6987 keeps directly attached stub reachability intact
               // while making every transit-capable OSPFv2 link unattractive.
               .metric = overload_
                             ? std::numeric_limits<std::uint16_t>::max()
                             : configuration.metric,
               .type = RouterLinkType::transit_network});
        } else {
          // A broadcast segment without a Full adjacency is represented as a
          // stub. Once it becomes transit, the Network-LSA supplies the prefix
          // and this duplicate stub link must disappear.
          links.push_back({.link_id = local & mask,
                           .link_data = mask,
                           .metric = configuration.metric,
                           .type = RouterLinkType::stub_network});
        }
        if (configuration.protocol.passive || multi_access)
          continue;
        for (const auto &neighbor : owner.runtime.neighbors())
          if (advertised_full(owner, neighbor.router_id, now))
            links.push_back(
                {.link_id = neighbor.router_id,
                 .link_data = local,
                 .metric = overload_
                               ? std::numeric_limits<std::uint16_t>::max()
                               : configuration.metric,
                 .type = RouterLinkType::point_to_point});
      }
      router_lsa = encode_version_two_router_lsa(
          encoded,
          {.link_state_id = router_id_,
           .advertising_router = router_id_,
           .sequence_number = router_lsa_sequence_,
           .age_seconds = 0U,
           .type = version_two_router_type,
           .options =
               packet::ospf::option_external_routing_capability |
               packet::ospf::option_opaque_capability,
           .version = version_},
          links, area_border_router_,
          autonomous_system_boundary_router_,
          virtual_link_endpoint_);
    } else {
      std::vector<VersionThreeRouterLinkInput> links;
      for (auto &owner : interfaces_) {
        const auto &configuration = owner.configuration;
        if (!configuration.protocol.enabled ||
            configuration.protocol.passive)
          continue;
        const bool multi_access =
            configuration.protocol.network_type == NetworkType::broadcast ||
            configuration.protocol.network_type ==
                NetworkType::non_broadcast;
        const bool virtual_link =
            configuration.protocol.network_type ==
            NetworkType::virtual_link;
        if (multi_access) {
          auto designated = owner.runtime.designated_router();
          for (const auto &neighbor : owner.exchanges)
            if (neighbor.helper_active &&
                neighbor.helper_deadline > now &&
                neighbor.helper_was_designated_router)
              designated = neighbor.router_id;
          const auto dr = std::find_if(
              owner.runtime.neighbors().begin(),
              owner.runtime.neighbors().end(), [&](const auto &neighbor) {
                return neighbor.router_id == designated &&
                       advertised_full(owner, neighbor.router_id, now);
              });
          const bool helping_remote_dr =
              std::any_of(owner.exchanges.begin(),
                          owner.exchanges.end(),
                          [&](const auto &neighbor) {
                            return neighbor.helper_active &&
                                   neighbor.helper_deadline > now &&
                                   neighbor
                                       .helper_was_designated_router;
                          });
          const bool local_dr =
              !helping_remote_dr &&
              owner.runtime.state() == InterfaceState::designated &&
              std::any_of(owner.runtime.neighbors().begin(),
                          owner.runtime.neighbors().end(),
                          [&](const auto &neighbor) {
                            return advertised_full(
                                owner, neighbor.router_id, now);
                          });
          if (local_dr || dr != owner.runtime.neighbors().end())
            links.push_back(
                {.interface_id = configuration.protocol.interface_id,
                 .neighbor_interface_id =
                     local_dr ? configuration.protocol.interface_id
                              : dr->interface_id,
                 .neighbor_router_id =
                     local_dr ? router_id_ : dr->router_id,
                 .metric = configuration.metric,
                 .type = RouterLinkType::transit_network});
          continue;
        }
        for (const auto &neighbor : owner.runtime.neighbors())
          if (advertised_full(owner, neighbor.router_id, now))
            links.push_back(
                {.interface_id = configuration.protocol.interface_id,
                 // The neighbor's Interface ID came from its accepted Hello.
                 // It is remote-owned and cannot be inferred locally.
                .neighbor_interface_id = neighbor.interface_id,
                .neighbor_router_id = neighbor.router_id,
                .metric = configuration.metric,
                 .type = virtual_link
                             ? RouterLinkType::virtual_link
                             : RouterLinkType::point_to_point});
      }
      const bool ipv4_address_family =
          instance_id_ >= device_catalog::ospf_v3_ipv4_instance_first;
      const auto family_options =
          ipv4_address_family
              ? packet::ospf::option_address_family
              : packet::ospf::option_ipv6_forwarding;
      router_lsa = encode_version_three_router_lsa(
          encoded,
          {.link_state_id = 0U,
           .advertising_router = router_id_,
           .sequence_number = router_lsa_sequence_,
           .age_seconds = 0U,
           .type = version_three_router_type,
           .options = packet::ospf::option_external_routing_capability |
                      family_options |
                      (overload_ ? 0U
                                 : packet::ospf::option_ospfv3_router),
           .version = version_},
          links,
          static_cast<std::uint8_t>(
              (area_border_router_ ? 0x01U : 0U) |
              (autonomous_system_boundary_router_ ? 0x02U : 0U) |
              (virtual_link_endpoint_ ? 0x04U : 0U)),
          packet::ospf::option_external_routing_capability |
              family_options |
              (overload_ ? 0U : packet::ospf::option_ospfv3_router));
    }
    if (!router_lsa) {
      local_origination_status_ =
          LocalOriginationStatus::router_encoding_rejected;
      return false;
    }
    const auto router_result =
        database_.install(*router_lsa, version_, now, router_id_, false);
    if (router_result != InstallResult::installed &&
        router_result != InstallResult::identical) {
      local_origination_status_ =
          LocalOriginationStatus::router_install_rejected;
      local_origination_install_result_ = router_result;
      return false;
    }
    const auto router_header =
        packet::ospf::lsa_header(*router_lsa, version_);
    const auto *router_record =
        router_header ? database_.find(lsa_key(*router_header)) : nullptr;
    if (!router_record || !flood_record(*router_record, now)) {
      local_origination_status_ =
          LocalOriginationStatus::router_flood_rejected;
      return false;
    }
    schedule_spf(now);

    // RFC 7770 Instance 0 advertises only capabilities that are actually
    // operational in this process. Bit 2 is valid because RFC 6987 overload
    // behavior is implemented for both versions. Bit 1 follows the configured
    // helper policy. Bit 0 deliberately remains clear because this release
    // milestone does not invent restarting-router behavior.
    const auto informational_capabilities =
        std::uint32_t{0x20000000U} |
        (graceful_restart_helper_ ? std::uint32_t{0x40000000U}
                                  : std::uint32_t{0U});
    const auto router_information_lsa =
        encode_router_information_lsa(
            encoded,
            {.link_state_id =
                 version_ == packet::ospf::version_two
                     ? static_cast<std::uint32_t>(
                           version_two_router_information_opaque_type)
                           << 24U
                     : 0U,
             .advertising_router = router_id_,
             .sequence_number =
                 router_information_lsa_sequence_,
             .age_seconds = 0U,
             .type =
                 version_ == packet::ospf::version_two
                     ? version_two_area_opaque_type
                     : version_three_router_information_type,
             .options =
                 version_ == packet::ospf::version_two
                     ? packet::ospf::option_opaque_capability
                     : 0U,
             .version = version_},
            informational_capabilities);
    if (!router_information_lsa) {
      local_origination_status_ =
          LocalOriginationStatus::
              router_information_encoding_rejected;
      return false;
    }
    const auto router_information_result = database_.install(
        *router_information_lsa, version_, now, router_id_, false);
    if (router_information_result != InstallResult::installed &&
        router_information_result != InstallResult::identical) {
      local_origination_status_ =
          LocalOriginationStatus::
              router_information_install_rejected;
      local_origination_install_result_ =
          router_information_result;
      return false;
    }
    const auto router_information_header =
        packet::ospf::lsa_header(*router_information_lsa, version_);
    const auto *router_information_record =
        router_information_header
            ? database_.find(lsa_key(*router_information_header))
            : nullptr;
    if (!router_information_record ||
        !flood_record(*router_information_record, now)) {
      local_origination_status_ =
          LocalOriginationStatus::
              router_information_flood_rejected;
      return false;
    }

    // A Network-LSA exists only while this router is DR and has at least one
    // Full adjacency on the segment. Each interface owns an independent
    // sequence space because the LSA key contains the DR interface identity.
    // Losing DR role originates a newer MaxAge instance instead of silently
    // leaving stale transit topology in the area LSDB.
    for (auto &owner : interfaces_) {
      const auto &configuration = owner.configuration;
      const bool multi_access =
          configuration.protocol.network_type == NetworkType::broadcast ||
          configuration.protocol.network_type == NetworkType::non_broadcast;
      if (!configuration.protocol.enabled ||
          configuration.protocol.passive || !multi_access)
        continue;

      std::vector<std::uint32_t> attached{router_id_};
      for (const auto &neighbor : owner.runtime.neighbors())
        if (advertised_full(owner, neighbor.router_id, now))
          attached.push_back(neighbor.router_id);
      std::sort(attached.begin(), attached.end());
      attached.erase(std::unique(attached.begin(), attached.end()),
                     attached.end());
      const bool helping_remote_dr =
          std::any_of(owner.exchanges.begin(), owner.exchanges.end(),
                      [&](const auto &neighbor) {
                        return neighbor.helper_active &&
                               neighbor.helper_deadline > now &&
                               neighbor.helper_was_designated_router;
                      });
      const bool originate =
          !helping_remote_dr &&
          owner.runtime.state() == InterfaceState::designated &&
          attached.size() > 1U;
      if (!originate && !owner.network_lsa_originated)
        continue;
      const auto age = originate ? std::uint16_t{0U} : max_age_seconds;
      std::optional<std::span<const std::uint8_t>> network_lsa;
      if (version_ == packet::ospf::version_two) {
        const auto mask =
            configuration.prefix_length == 0U
                ? 0U
                : std::numeric_limits<std::uint32_t>::max()
                      << (32U - configuration.prefix_length);
        network_lsa = encode_version_two_network_lsa(
            encoded,
            {.link_state_id = configuration.protocol.local_election_identity,
             .advertising_router = router_id_,
             .sequence_number = owner.network_lsa_sequence,
             .age_seconds = age,
             .type = version_two_network_type,
             .options =
                 packet::ospf::option_external_routing_capability |
                 packet::ospf::option_opaque_capability,
             .version = version_},
            mask, attached);
      } else {
        network_lsa = encode_version_three_network_lsa(
            encoded,
            {.link_state_id = configuration.protocol.interface_id,
             .advertising_router = router_id_,
             .sequence_number = owner.network_lsa_sequence,
             .age_seconds = age,
             .type = version_three_network_type,
             .options = 0U,
             .version = version_},
            configuration.protocol.options, attached);
      }
      if (!network_lsa) {
        local_origination_status_ =
            LocalOriginationStatus::network_encoding_rejected;
        return false;
      }
      const auto network_result =
          database_.install(*network_lsa, version_, now, router_id_, false);
      if (network_result != InstallResult::installed &&
          network_result != InstallResult::identical) {
        local_origination_status_ =
            LocalOriginationStatus::network_install_rejected;
        local_origination_install_result_ = network_result;
        return false;
      }
      const auto network_header =
          packet::ospf::lsa_header(*network_lsa, version_);
      const auto *network_record =
          network_header ? database_.find(lsa_key(*network_header)) : nullptr;
      if (!network_record || !flood_record(*network_record, now)) {
        local_origination_status_ =
            LocalOriginationStatus::network_flood_rejected;
        return false;
      }
      if (owner.network_lsa_sequence == maximum_sequence_number)
        owner.network_sequence_at_max = true;
      else
        ++owner.network_lsa_sequence;
      owner.network_lsa_originated = originate;
      schedule_spf(now);

      if (version_ != packet::ospf::version_three)
        continue;
      ip::Ipv6 network{};
      if (instance_id_ >=
          device_catalog::ospf_v3_ipv4_instance_first)
        std::copy(configuration.ipv4_source.begin(),
                  configuration.ipv4_source.end(), network.begin());
      else
        network = configuration.ipv6_prefix;
      network = ip::mask(network, configuration.prefix_length);
      const std::array<PrefixInput, 1U> network_prefix{{
          {.network = network,
           .metric = 0U,
           .length = configuration.prefix_length,
           .options = 0U},
      }};
      const auto prefix_lsa = encode_version_three_intra_area_prefix_lsa(
          encoded,
          {.link_state_id = configuration.protocol.interface_id,
           .advertising_router = router_id_,
           .sequence_number = owner.network_prefix_lsa_sequence,
           .age_seconds = age,
           .type = version_three_intra_area_prefix_type,
           .options = 0U,
           .version = version_},
          version_three_network_type, configuration.protocol.interface_id,
          router_id_, network_prefix);
      if (!prefix_lsa) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_encoding_rejected;
        return false;
      }
      const auto prefix_result =
          database_.install(*prefix_lsa, version_, now, router_id_, false);
      if (prefix_result != InstallResult::installed &&
          prefix_result != InstallResult::identical) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_install_rejected;
        local_origination_install_result_ = prefix_result;
        return false;
      }
      const auto prefix_header =
          packet::ospf::lsa_header(*prefix_lsa, version_);
      const auto *prefix_record =
          prefix_header ? database_.find(lsa_key(*prefix_header)) : nullptr;
      if (!prefix_record || !flood_record(*prefix_record, now)) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_flood_rejected;
        return false;
      }
      if (owner.network_prefix_lsa_sequence ==
          maximum_sequence_number)
        owner.network_prefix_sequence_at_max = true;
      else
        ++owner.network_prefix_lsa_sequence;
      schedule_spf(now);
    }

    if (version_ == packet::ospf::version_three) {
      std::vector<PrefixInput> prefixes;
      for (const auto &owner : interfaces_) {
        const auto &configuration = owner.configuration;
        if (!configuration.protocol.enabled ||
            configuration.protocol.network_type ==
                NetworkType::virtual_link)
          continue;
        const bool multi_access =
            configuration.protocol.network_type == NetworkType::broadcast ||
            configuration.protocol.network_type ==
                NetworkType::non_broadcast;
        const bool transit =
            multi_access && owner.runtime.designated_router() != 0U &&
            std::any_of(owner.runtime.neighbors().begin(),
                        owner.runtime.neighbors().end(),
                        [&](const auto &neighbor) {
                          return advertised_full(
                              owner, neighbor.router_id, now);
                        });
        if (transit)
          continue;
        ip::Ipv6 network{};
        std::uint8_t length{};
        if (instance_id_ >= device_catalog::ospf_v3_ipv4_instance_first) {
          std::copy(configuration.ipv4_source.begin(),
                    configuration.ipv4_source.end(), network.begin());
          length = configuration.prefix_length;
        } else {
          network = configuration.ipv6_prefix;
          length = configuration.prefix_length;
        }
        network = ip::mask(network, length);
        prefixes.push_back({.network = network,
                            .metric = configuration.metric,
                            .length = length,
                            .options = 0U});
      }
      for (const auto &address : virtual_endpoint_addresses_)
        prefixes.push_back(
            {.network = address,
             .metric = 0U,
             .length = 128U,
             // RFC 5340 section 4.4.3.9 defines PrefixOptions LA as bit 1.
             // It identifies an address, not merely a reachable prefix.
             .options = 0x02U});
      const auto prefix_lsa = encode_version_three_intra_area_prefix_lsa(
          encoded,
          {.link_state_id = 0U,
           .advertising_router = router_id_,
           .sequence_number = prefix_lsa_sequence_,
           .age_seconds = 0U,
           .type = version_three_intra_area_prefix_type,
           .options = 0U,
           .version = version_},
          version_three_router_type, 0U, router_id_, prefixes);
      if (!prefix_lsa) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_encoding_rejected;
        return false;
      }
      const auto prefix_result =
          database_.install(*prefix_lsa, version_, now, router_id_, false);
      if (prefix_result != InstallResult::installed &&
          prefix_result != InstallResult::identical) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_install_rejected;
        local_origination_install_result_ = prefix_result;
        return false;
      }
      const auto prefix_header =
          packet::ospf::lsa_header(*prefix_lsa, version_);
      const auto *prefix_record =
          prefix_header ? database_.find(lsa_key(*prefix_header)) : nullptr;
      if (!prefix_record || !flood_record(*prefix_record, now)) {
        local_origination_status_ =
            LocalOriginationStatus::prefix_flood_rejected;
        return false;
      }
      schedule_spf(now);
      if (prefix_lsa_sequence_ == maximum_sequence_number)
        prefix_sequence_at_max_ = true;
      else
        ++prefix_lsa_sequence_;

      // RFC 5340 section 4.4.3.8 makes the Link-LSA interface-scoped. It
      // supplies the link-local next hop needed to turn SPF first-hop tuples
      // into scoped forwarding entries.
      for (auto &owner : interfaces_) {
        const auto &configuration = owner.configuration;
        if (!configuration.protocol.enabled ||
            configuration.protocol.passive)
          continue;
        std::vector<PrefixInput> link_prefixes;
        if (instance_id_ < device_catalog::ospf_v3_ipv4_instance_first) {
          link_prefixes.push_back(
              {.network = ip::mask(configuration.ipv6_prefix,
                                   configuration.prefix_length),
               .metric = 0U,
               .length = configuration.prefix_length,
               .options = 0U});
        }
        auto direct_interface_address = configuration.ipv6_source;
        if (instance_id_ >=
            device_catalog::ospf_v3_ipv4_instance_first) {
          // RFC 5838 section 2.5 defines this field as an IPv4 Direct
          // Interface Address for an IPv4 AF instance. The encoder remains a
          // byte-level OSPFv3 codec, while this process owner selects the
          // address-family-specific meaning and zeroes the unused 96 bits.
          direct_interface_address = {};
          std::copy(configuration.ipv4_source.begin(),
                    configuration.ipv4_source.end(),
                    direct_interface_address.begin());
        }
        const auto link_lsa = encode_version_three_link_lsa(
            encoded,
            {.link_state_id = configuration.protocol.interface_id,
             .advertising_router = router_id_,
             .sequence_number = owner.link_lsa_sequence,
             .age_seconds = 0U,
             .type = version_three_link_type,
             .options = 0U,
             .version = version_},
            configuration.protocol.router_priority,
            configuration.protocol.options, direct_interface_address,
            link_prefixes);
        if (!link_lsa) {
          local_origination_status_ =
              LocalOriginationStatus::link_encoding_rejected;
          return false;
        }
        const auto link_result =
            database_.install(*link_lsa, version_, now, router_id_, false);
        if (link_result != InstallResult::installed &&
            link_result != InstallResult::identical) {
          local_origination_status_ =
              LocalOriginationStatus::link_install_rejected;
          local_origination_install_result_ = link_result;
          return false;
        }
        const auto link_header =
            packet::ospf::lsa_header(*link_lsa, version_);
        const auto *link_record =
            link_header ? database_.find(lsa_key(*link_header)) : nullptr;
        if (!link_record ||
            !flood_record(*link_record, now,
                          configuration.protocol.interface_id)) {
          local_origination_status_ =
              LocalOriginationStatus::link_flood_rejected;
          return false;
        }
        if (owner.link_lsa_sequence == maximum_sequence_number)
          owner.link_sequence_at_max = true;
        else
          ++owner.link_lsa_sequence;
      }
    }
    if (router_lsa_sequence_ == maximum_sequence_number)
      router_sequence_at_max_ = true;
    else
      ++router_lsa_sequence_;
    if (router_information_lsa_sequence_ ==
        maximum_sequence_number)
      router_information_sequence_at_max_ = true;
    else
      ++router_information_lsa_sequence_;
    last_local_origination_ = now;
    local_origination_deadline_ = {};
    return true;
  } catch (const std::bad_alloc &) {
    local_origination_status_ =
        LocalOriginationStatus::allocation_failed;
    return false;
  }
}

ReceiveStatus InstanceProcess::receive_packet(
    std::uint32_t interface_id, std::span<const std::uint8_t> ospf_packet,
    const ip::Ipv6 &ipv6_source, const ip::Ipv6 &ipv6_destination,
    RuntimeClock::time_point now) noexcept {
  auto *owner = interface(interface_id);
  if (!owner)
    return ReceiveStatus::interface_not_found;
  const auto decoded = packet::ospf::parse_packet(ospf_packet);
  if (!decoded)
    return ReceiveStatus::malformed;
  if (decoded->version != version_ ||
      decoded->version != packet::ospf::version_three)
    return ReceiveStatus::version_mismatch;
  if (!packet::ospf::verify_version_three_checksum(
          *decoded, ipv6_source, ipv6_destination))
    return ReceiveStatus::checksum_failure;
  return receive_validated(*owner, *decoded, {}, ipv6_source, now, false);
}

std::optional<std::span<const std::uint8_t>>
InstanceProcess::protect_ipv6_ipsec_packet(
    std::uint32_t interface_id, const ip::Ipv6 &source,
    const ip::Ipv6 &destination, std::uint8_t hop_limit,
    std::span<const std::uint8_t> ospf_packet,
    std::span<std::uint8_t> output) noexcept {
  auto *owner = interface(interface_id);
  if (!owner || !owner->send_authentication ||
      !owner->send_authentication->ipsec_ah)
    return std::nullopt;
  auto &authentication = *owner->send_authentication;
  if (owner->authentication_sequence >=
      std::numeric_limits<std::uint32_t>::max())
    return std::nullopt;
  const auto algorithm =
      authentication.algorithm == KeychainAlgorithm::message_digest
          ? authentication::IpsecAhAlgorithm::hmac_md5_96
          : authentication::IpsecAhAlgorithm::hmac_sha1_96;
  const auto next_sequence =
      static_cast<std::uint32_t>(owner->authentication_sequence + 1U);
  const auto protected_packet = authentication::encode_ipv6_ipsec_ah(
      output, source, destination, hop_limit, authentication.key_id,
      next_sequence, algorithm,
      std::span<const std::uint8_t>{authentication.key.data(),
                                    authentication.key_size},
      ospf_packet);
  // Sequence state advances only after the complete authenticated packet was
  // produced. A temporary output-capacity failure therefore cannot consume a
  // number without putting its packet on the egress channel.
  if (protected_packet)
    owner->authentication_sequence = next_sequence;
  return protected_packet;
}

bool InstanceProcess::ipsec_authentication_configured(
    std::uint32_t interface_id) const noexcept {
  const auto found = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return owner.configuration.protocol.interface_id == interface_id;
      });
  return found != interfaces_.end() && found->send_authentication &&
         found->send_authentication->ipsec_ah;
}

ReceiveStatus InstanceProcess::receive_ipv6_ipsec_packet(
    std::uint32_t interface_id,
    std::span<const std::uint8_t> ipv6_packet,
    RuntimeClock::time_point now) noexcept {
  auto *owner = interface(interface_id);
  if (!owner)
    return ReceiveStatus::interface_not_found;
  if (ipv6_packet.size() < packet::ipv6_header_octets)
    return ReceiveStatus::malformed;

  ip::Ipv6 source{};
  ip::Ipv6 destination{};
  std::copy_n(ipv6_packet.begin() + 8U, source.size(), source.begin());
  std::copy_n(ipv6_packet.begin() + 24U, destination.size(),
              destination.begin());

  // The SPI selects the inbound manual SA, but an ICV must authenticate before
  // replay state changes. Try only configured inbound AH records and retain no
  // failure detail that could become a key-selection oracle in CLI output.
  for (const auto &candidate : owner->receive_authentications) {
    if (!candidate.ipsec_ah)
      continue;
    const auto algorithm =
        candidate.algorithm == KeychainAlgorithm::message_digest
            ? authentication::IpsecAhAlgorithm::hmac_md5_96
            : authentication::IpsecAhAlgorithm::hmac_sha1_96;
    const auto verified = authentication::verify_ipv6_ipsec_ah(
        ipv6_packet, algorithm,
        std::span<const std::uint8_t>{candidate.key.data(),
                                      candidate.key_size});
    if (!verified || verified->spi != candidate.key_id)
      continue;
    if (owner->ipsec_replay_sequence_seen &&
        verified->sequence_number <= owner->ipsec_replay_sequence)
      return ReceiveStatus::authentication_failure;
    const auto decoded =
        packet::ospf::parse_packet(verified->ospf_packet);
    if (!decoded)
      return ReceiveStatus::malformed;
    if (decoded->version != version_ ||
        decoded->version != packet::ospf::version_three)
      return ReceiveStatus::version_mismatch;
    if (!packet::ospf::verify_version_three_checksum(
            *decoded, source, destination))
      return ReceiveStatus::checksum_failure;
    owner->ipsec_replay_sequence = verified->sequence_number;
    owner->ipsec_replay_sequence_seen = true;
    return receive_validated(*owner, *decoded, {}, source, now, true);
  }
  return ReceiveStatus::authentication_failure;
}

ReceiveStatus InstanceProcess::receive_ipv4_packet(
    std::uint32_t interface_id, std::span<const std::uint8_t> ospf_packet,
    const ip::Ipv4 &ipv4_source, const ip::Ipv4 &,
    RuntimeClock::time_point now) noexcept {
  auto *owner = interface(interface_id);
  if (!owner)
    return ReceiveStatus::interface_not_found;
  const auto decoded = packet::ospf::parse_packet(ospf_packet);
  if (!decoded)
    return ReceiveStatus::malformed;
  if (decoded->version != version_ ||
      decoded->version != packet::ospf::version_two)
    return ReceiveStatus::version_mismatch;
  if (!packet::ospf::verify_version_two_checksum(*decoded))
    return ReceiveStatus::checksum_failure;
  return receive_validated(*owner, *decoded, ipv4_source, {}, now, false);
}

ReceiveStatus InstanceProcess::receive_validated(
    InterfaceOwner &owner, const packet::ospf::PacketView &decoded,
    const ip::Ipv4 &ipv4_source, const ip::Ipv6 &ipv6_source,
    RuntimeClock::time_point now, bool outer_ipsec_verified) noexcept {
  std::optional<std::uint64_t> received_sequence;
  const auto now_utc = wall_clock_seconds();
  if (version_ == packet::ospf::version_two) {
    if (!owner.authentication_required) {
      if (decoded.authentication_type != static_cast<std::uint16_t>(
              packet::ospf::AuthenticationType::none))
        return ReceiveStatus::authentication_failure;
    } else if (const auto password = std::find_if(
                   owner.receive_authentications.begin(),
                   owner.receive_authentications.end(),
                   [&](const auto &candidate) {
                     return candidate.algorithm ==
                                KeychainAlgorithm::password &&
                            receive_key_valid(
                                candidate,
                                owner.receive_authentications, now_utc);
                   });
               password != owner.receive_authentications.end()) {
      const auto &authentication = *password;
      if (decoded.authentication_type != static_cast<std::uint16_t>(
              packet::ospf::AuthenticationType::simple_password))
        return ReceiveStatus::authentication_failure;
      std::array<std::uint8_t, 8U> expected{};
      const auto copied = std::min<std::size_t>(
          authentication.key_size, expected.size());
      std::copy_n(authentication.key.begin(), copied,
                  expected.begin());
      if (!constant_time_equal(decoded.authentication, expected))
        return ReceiveStatus::authentication_failure;
    } else {
      const auto key_id = authentication::v2_key_id(decoded);
      const auto selected = std::find_if(
          owner.receive_authentications.begin(),
          owner.receive_authentications.end(),
          [&](const auto &authentication) {
            return authentication.key_id == key_id &&
                   receive_key_valid(authentication,
                                     owner.receive_authentications,
                                     now_utc);
          });
      const auto algorithm =
          selected == owner.receive_authentications.end()
              ? std::optional<
                    authentication::V2CryptographicAlgorithm>{}
          : selected->algorithm == KeychainAlgorithm::message_digest
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::
                        message_digest_md5}
          : selected->algorithm == KeychainAlgorithm::hmac_sha1
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::hmac_sha1}
          : selected->algorithm == KeychainAlgorithm::hmac_sha256
              ? std::optional{
                    authentication::V2CryptographicAlgorithm::hmac_sha256}
              : std::optional<
                    authentication::V2CryptographicAlgorithm>{};
      if (!algorithm ||
          !authentication::verify_v2_cryptographic(
              decoded,
              *algorithm,
              std::span<const std::uint8_t>{
                  selected->key.data(), selected->key_size}))
        return ReceiveStatus::authentication_failure;
      received_sequence =
          authentication::v2_sequence_number(decoded);
      if (auto *known = exchange(owner, decoded.router_id, false)) {
        const auto index =
            static_cast<std::size_t>(decoded.type) - 1U;
        if (known->authentication_sequence_seen[index] &&
            *received_sequence <= known->authentication_sequences[index])
          return ReceiveStatus::authentication_failure;
        // RFC 5709 commits replay state after authentication succeeds, before
        // packet-type semantic processing. A malformed DD cannot therefore be
        // replayed repeatedly to reuse an already authenticated sequence.
        known->authentication_sequences[index] = *received_sequence;
        known->authentication_sequence_seen[index] = true;
      }
    }
  } else {
    // RFC 7166 requires every protected packet to carry a valid trailer and
    // forbids silently accepting authenticated traffic on an unprotected
    // interface. Selection by the 16-bit SA ID permits overlapping receive
    // keys during a rollover without consulting mutable management state.
    const bool ipsec_required =
        std::any_of(owner.receive_authentications.begin(),
                    owner.receive_authentications.end(),
                    [](const auto &candidate) {
                      return candidate.ipsec_ah;
                    });
    if (ipsec_required) {
      if (!outer_ipsec_verified ||
          !decoded.authentication_trailer.empty())
        return ReceiveStatus::authentication_failure;
    } else if (!owner.authentication_required) {
      if (!decoded.authentication_trailer.empty())
        return ReceiveStatus::authentication_failure;
    } else {
      const auto security_association_id =
          authentication::v3_security_association_id(decoded);
      const auto selected = std::find_if(
          owner.receive_authentications.begin(),
          owner.receive_authentications.end(),
          [&](const auto &candidate) {
            return candidate.key_id == security_association_id &&
                   receive_key_valid(candidate,
                                     owner.receive_authentications,
                                     now_utc);
          });
      if (selected == owner.receive_authentications.end())
        return ReceiveStatus::authentication_failure;
      const auto algorithm =
          selected->algorithm == KeychainAlgorithm::hmac_sha1
              ? authentication::V3CryptographicAlgorithm::hmac_sha1
              : authentication::V3CryptographicAlgorithm::hmac_sha256;
      if (!authentication::verify_v3_authentication_trailer(
              decoded, ipv6_source, algorithm,
              std::span<const std::uint8_t>{
                  selected->key.data(), selected->key_size}))
        return ReceiveStatus::authentication_failure;
      received_sequence =
          authentication::v3_sequence_number(decoded);
      if (auto *known = exchange(owner, decoded.router_id, false)) {
        const auto index =
            static_cast<std::size_t>(decoded.type) - 1U;
        if (known->authentication_sequence_seen[index] &&
            *received_sequence <= known->authentication_sequences[index])
          return ReceiveStatus::authentication_failure;
        known->authentication_sequences[index] = *received_sequence;
        known->authentication_sequence_seen[index] = true;
      }
    }
  }

  InterfaceOwner::NbmaPeer *nbma_peer{};
  if (owner.configuration.protocol.network_type ==
      NetworkType::virtual_link) {
    ip::IpAddress source{
        .family = version_ == packet::ospf::version_two
                      ? ip::AddressFamily::ipv4
                      : ip::AddressFamily::ipv6};
    if (version_ == packet::ospf::version_two)
      std::copy(ipv4_source.begin(), ipv4_source.end(),
                source.bytes.begin());
    else
      source.bytes = ipv6_source;
    // A virtual interface is configured for one remote ABR. Both the Router
    // ID and the SPF-discovered unicast address must agree before any Hello
    // can create neighbor state.
    if (decoded.router_id !=
            owner.configuration.virtual_neighbor_router_id ||
        source != owner.configuration.virtual_neighbor_address)
      return ReceiveStatus::neighbor_not_found;
  }
  if (owner.configuration.protocol.network_type ==
      NetworkType::non_broadcast) {
    ip::IpAddress source{
        .family = version_ == packet::ospf::version_two
                      ? ip::AddressFamily::ipv4
                      : ip::AddressFamily::ipv6};
    if (version_ == packet::ospf::version_two)
      std::copy(ipv4_source.begin(), ipv4_source.end(),
                source.bytes.begin());
    else
      source.bytes = ipv6_source;
    const auto found = std::find_if(
        owner.nbma_peers.begin(), owner.nbma_peers.end(),
        [&](const auto &peer) {
          return peer.configuration.address == source;
        });
    // NBMA has no dynamic discovery. A packet from an address absent from the
    // configured peer set cannot create protocol state even if its OSPF
    // envelope is otherwise valid.
    if (found == owner.nbma_peers.end())
      return ReceiveStatus::neighbor_not_found;
    nbma_peer = &*found;
  }

  if (decoded.type == packet::ospf::PacketType::hello) {
    const auto neighbor_election_identity =
        version_ == packet::ospf::version_two
            ? (static_cast<std::uint32_t>(ipv4_source[0U]) << 24U |
               static_cast<std::uint32_t>(ipv4_source[1U]) << 16U |
               static_cast<std::uint32_t>(ipv4_source[2U]) << 8U |
               ipv4_source[3U])
            : decoded.router_id;
    const auto result = owner.runtime.receive_hello(
        decoded, neighbor_election_identity, now);
    if (result.disposition != HelloDisposition::accepted)
      return ReceiveStatus::rejected_hello;
    auto *neighbor = exchange(owner, result.neighbor_router_id, true);
    if (!neighbor)
      return ReceiveStatus::resource_exhausted;
    neighbor->ipv4_address = ipv4_source;
    neighbor->ipv6_address = ipv6_source;
    if (received_sequence) {
      const auto index = static_cast<std::size_t>(decoded.type) - 1U;
      neighbor->authentication_sequences[index] = *received_sequence;
      neighbor->authentication_sequence_seen[index] = true;
    }
    if (nbma_peer) {
      nbma_peer->router_id = result.neighbor_router_id;
      // A received Hello leaves Down/Attempt and restores the ordinary
      // HelloInterval. The inactivity path below returns it to PollInterval.
      nbma_peer->hello_deadline =
          now + std::chrono::seconds{
                    owner.configuration.protocol.hello_interval_seconds};
    }
    if (!apply_neighbor_actions(owner, result.neighbor_router_id,
                                result.actions, now))
      return ReceiveStatus::resource_exhausted;
    if (has_action(result.actions, NeighborAction::notify_interface)) {
      // The completed Hello transition is already stored in the interface
      // neighbor repository. Election therefore sees the current 2-Way state,
      // priority and declarations from this exact wire generation.
      const auto interface_actions =
          owner.runtime.neighbor_change(result.backup_seen);
      if (!reconcile_interface_adjacencies(owner, interface_actions, now))
        return ReceiveStatus::resource_exhausted;
    }
    if (nbma_peer &&
        owner.configuration.protocol.router_priority == 0U) {
      const auto learned = std::find_if(
          owner.runtime.neighbors().begin(),
          owner.runtime.neighbors().end(),
          [&](const auto &candidate) {
            return candidate.router_id == result.neighbor_router_id;
          });
      const bool current_dr_or_bdr =
          learned != owner.runtime.neighbors().end() &&
          (learned->election_identity ==
               owner.runtime.designated_router() ||
           learned->election_identity ==
               owner.runtime.backup_designated_router());
      if (learned != owner.runtime.neighbors().end() &&
          learned->priority != 0U && !current_dr_or_bdr) {
        // RFC 2328 section 9.5.1 requires an ineligible router to answer an
        // eligible non-DR/BDR peer immediately. Scheduling the peer at the
        // current monotonic instant lets the normal bounded owner turn encode
        // that reply without sending from inside packet reception.
        nbma_peer->hello_deadline = now;
      }
    }
    return ReceiveStatus::accepted;
  }
  auto *neighbor = exchange(owner, decoded.router_id, false);
  if (!neighbor)
    return ReceiveStatus::neighbor_not_found;

  const auto neighbor_state = std::find_if(
      owner.runtime.neighbors().begin(), owner.runtime.neighbors().end(),
      [&](const auto &candidate) {
        return candidate.router_id == decoded.router_id;
      });
  if (neighbor_state == owner.runtime.neighbors().end())
    return ReceiveStatus::neighbor_not_found;

  if (decoded.type == packet::ospf::PacketType::database_description) {
    // RFC 2328 section 10.6 discards DD packets until the neighbor reaches
    // ExStart. A peer can legitimately get here first because the two-way
    // indication is carried by periodic Hello packets.
    if (neighbor_state->state < NeighborState::exstart)
      return ReceiveStatus::ignored;
    const auto description =
        packet::ospf::parse_database_description(decoded);
    if (!description)
      return ReceiveStatus::malformed;
    if (description->interface_mtu >
        owner.configuration.protocol.interface_mtu)
      return ReceiveStatus::invalid_neighbor_state;
    if (neighbor_state->state == NeighborState::loading ||
        neighbor_state->state == NeighborState::full) {
      const bool duplicate =
          !description->init &&
          description->master == !neighbor->local_master &&
          description->sequence_number == neighbor->dd_sequence;
      if (duplicate) {
        // RFC 2328 section 10.6 treats the last DD received in Loading or
        // Full as a duplicate. A master discards the slave's repeated
        // acknowledgement. The slave's response retransmission is already
        // retained by its DD retransmit deadline until exchange completion,
        // so accepting the duplicate must not tear down a healthy adjacency.
        return ReceiveStatus::accepted;
      }

      // A restarted peer has lost its neighbor state and begins a fresh
      // ExStart exchange while this owner can still be Full. RFC 2328 calls
      // this SeqNumberMismatch: the established side must also return to
      // ExStart and negotiate a new DD sequence. Merely rejecting the packet
      // leaves the two legitimate state machines permanently asymmetric.
      const auto transition = owner.runtime.apply_neighbor_event(
          decoded.router_id, NeighborEvent::sequence_number_mismatch, false);
      if (!transition ||
          !apply_neighbor_actions(owner, decoded.router_id,
                                  transition->actions, now))
        return ReceiveStatus::resource_exhausted;
      return ReceiveStatus::accepted;
    }
    if (neighbor_state->state == NeighborState::exstart) {
      const bool become_slave =
          description->init && description->more && description->master &&
          description->lsa_headers.empty() &&
          decoded.router_id > router_id_;
      const bool remain_master =
          !description->init && !description->master &&
          description->sequence_number == neighbor->dd_sequence &&
          decoded.router_id < router_id_;
      // During simultaneous ExStart both routers initially assert master.
      // RFC 2328 section 10.6 has the larger Router ID discard the smaller
      // router's initial proposal and continue sending its own sequence.
      const bool discard_smaller_initial =
          description->init && description->more && description->master &&
          description->lsa_headers.empty() &&
          decoded.router_id < router_id_;
      if (discard_smaller_initial)
        return ReceiveStatus::accepted;
      if (!become_slave && !remain_master)
        return ReceiveStatus::invalid_neighbor_state;
      neighbor->local_master = remain_master;
      if (become_slave)
        neighbor->dd_sequence = description->sequence_number;
      neighbor->negotiation_complete = true;
      neighbor->peer_more = description->more;
      const auto transition = owner.runtime.apply_neighbor_event(
          decoded.router_id, NeighborEvent::negotiation_done, false);
      if (!transition || transition->state != NeighborState::exchange)
        return ReceiveStatus::invalid_neighbor_state;
      if (!neighbor->database.process_database_description(
              *description, database_, now))
        return ReceiveStatus::resource_exhausted;
      // A master advances the sequence only after its previous packet was
      // acknowledged by the slave. A slave echoes the master's sequence.
      if (remain_master)
        ++neighbor->dd_sequence;
      neighbor->pending_database_description = true;
      neighbor->dd_retransmit_deadline = now;
      return ReceiveStatus::accepted;
    }
    if (neighbor_state->state != NeighborState::exchange)
      return ReceiveStatus::invalid_neighbor_state;
    if (description->init ||
        description->master != !neighbor->local_master ||
        (neighbor->local_master
             ? description->sequence_number != neighbor->dd_sequence
             : description->sequence_number < neighbor->dd_sequence)) {
      // The same RFC event applies during Exchange. Resetting both the FSM
      // and the bounded exchange repositories prevents requests or
      // retransmissions from the superseded sequence space from leaking into
      // the new negotiation.
      const auto transition = owner.runtime.apply_neighbor_event(
          decoded.router_id, NeighborEvent::sequence_number_mismatch, false);
      if (!transition ||
          !apply_neighbor_actions(owner, decoded.router_id,
                                  transition->actions, now))
        return ReceiveStatus::resource_exhausted;
      return ReceiveStatus::accepted;
    }
    if (!neighbor->database.process_database_description(
            *description, database_, now))
      return ReceiveStatus::resource_exhausted;
    neighbor->peer_more = description->more;
    if (neighbor->local_master) {
      if (!neighbor->sent_more && !neighbor->peer_more) {
        const auto transition = owner.runtime.apply_neighbor_event(
            decoded.router_id, NeighborEvent::exchange_done,
            !neighbor->database.requests().empty());
        if (!transition)
          return ReceiveStatus::invalid_neighbor_state;
        neighbor->pending_database_description = false;
        neighbor->pending_request =
            transition->state == NeighborState::loading;
        neighbor->request_retransmit_deadline = now;
        if (transition->state == NeighborState::full)
          schedule_local_origination(now);
      } else {
        ++neighbor->dd_sequence;
        neighbor->pending_database_description = true;
      }
    } else {
      neighbor->dd_sequence = description->sequence_number;
      neighbor->pending_database_description = true;
      // The slave can declare ExchangeDone only after its response has
      // actually entered the output queue.
      neighbor->complete_after_reply = !description->more;
    }
    neighbor->dd_retransmit_deadline =
        neighbor->pending_database_description ? now
                                               : RuntimeClock::time_point{};
    return ReceiveStatus::accepted;
  }

  if (neighbor_state->state < NeighborState::exchange)
    return ReceiveStatus::invalid_neighbor_state;

  if (decoded.type == packet::ospf::PacketType::link_state_request) {
    const auto request = packet::ospf::parse_link_state_request(decoded);
    if (!request)
      return ReceiveStatus::malformed;
    for (std::size_t index{}; index < request->entries.size() / 12U; ++index) {
      const auto entry = packet::ospf::request_entry(*request, index);
      if (!entry)
        return ReceiveStatus::malformed;
      const packet::ospf::LsaHeaderView identity{
          .link_state_id = entry->link_state_id,
          .advertising_router = entry->advertising_router,
          .type = static_cast<std::uint16_t>(entry->link_state_type),
          .version = version_};
      const auto *record = database_.find(lsa_key(identity));
      if (!record) {
        const auto transition = owner.runtime.apply_neighbor_event(
            decoded.router_id, NeighborEvent::bad_link_state_request, false);
        if (transition &&
            has_action(transition->actions,
                       NeighborAction::begin_database_exchange))
          neighbor->pending_database_description = true;
        return ReceiveStatus::invalid_neighbor_state;
      }
      if (!neighbor->database.queue_retransmission(*record, version_, now))
        return ReceiveStatus::resource_exhausted;
    }
    neighbor->pending_update = true;
    neighbor->update_retransmit_deadline = now;
    return ReceiveStatus::accepted;
  }

  if (decoded.type == packet::ospf::PacketType::link_state_update) {
    const auto update = packet::ospf::parse_link_state_update(decoded);
    if (!update)
      return ReceiveStatus::malformed;
    for (std::size_t index{}; index < update->advertisement_count; ++index) {
      const auto encoded = packet::ospf::update_lsa(*update, index);
      if (!encoded)
        return ReceiveStatus::malformed;
      const auto header = packet::ospf::lsa_header(*encoded, version_);
      if (!header)
        return ReceiveStatus::malformed;
      const bool grace_identity =
          version_ == packet::ospf::version_two
              ? header->type ==
                        packet::ospf::lsa::
                            version_two_link_opaque_type &&
                    (header->link_state_id >> 24U) ==
                        packet::ospf::lsa::
                            version_two_grace_opaque_type
              : header->type ==
                    packet::ospf::lsa::version_three_grace_type;
      if (grace_identity) {
        const auto grace =
            packet::ospf::lsa::parse_grace_lsa(*encoded, version_);
        if (!grace || header->advertising_router != decoded.router_id)
          return ReceiveStatus::malformed;
        if (header->age_seconds >= grace->grace_period_seconds ||
            header->age_seconds == max_age_seconds) {
          if (neighbor->helper_active) {
            neighbor->helper_active = false;
            neighbor->helper_deadline = {};
            neighbor->helper_was_designated_router = false;
            schedule_local_origination(now);
          }
        } else if (graceful_restart_helper_) {
          const auto network_type =
              owner.configuration.protocol.network_type;
          const bool address_required =
              version_ == packet::ospf::version_two &&
              (network_type == NetworkType::broadcast ||
               network_type == NetworkType::non_broadcast ||
               network_type == NetworkType::point_to_multipoint);
          const auto source_address =
              static_cast<std::uint32_t>(ipv4_source[0U]) << 24U |
              static_cast<std::uint32_t>(ipv4_source[1U]) << 16U |
              static_cast<std::uint32_t>(ipv4_source[2U]) << 8U |
              ipv4_source[3U];
          const auto runtime_neighbor = std::find_if(
              owner.runtime.neighbors().begin(),
              owner.runtime.neighbors().end(),
              [&](const auto &candidate) {
                return candidate.router_id == decoded.router_id;
              });
          const bool already_helping =
              neighbor->helper_active &&
              neighbor->helper_deadline > now;
          const bool full =
              runtime_neighbor != owner.runtime.neighbors().end() &&
              runtime_neighbor->state == NeighborState::full;
          const bool may_help =
              (already_helping || full) &&
              (!address_required ||
               (grace->interface_address &&
                *grace->interface_address == source_address)) &&
              (version_ != packet::ospf::version_three ||
               !grace->interface_address);
          if (may_help) {
            const auto remaining =
                grace->grace_period_seconds - header->age_seconds;
            if (!already_helping)
              neighbor->helper_started_at = now;
            neighbor->helper_active = true;
            neighbor->helper_deadline =
                now + std::chrono::seconds{remaining};
            const auto election_identity =
                version_ == packet::ospf::version_two
                    ? source_address
                    : decoded.router_id;
            neighbor->helper_was_designated_router =
                owner.runtime.designated_router() ==
                election_identity;
            // Refusing helper mode does not discard the LSA. RFC 3623 section
            // 3.2 still requires ordinary reception, acknowledgment and
            // link-local flooding, while only the adjacency-preservation
            // behavior depends on the helper admission checks above.
            static_cast<void>(owner.runtime.defer_inactivity(
                decoded.router_id, neighbor->helper_deadline));
          }
        }
      }
      // A conforming peer never sends an AS-scope LSA over a virtual
      // adjacency. Silently ignore such an instance rather than importing
      // forbidden state into the backbone LSDB and potentially reflooding it.
      if (owner.configuration.protocol.network_type ==
              NetworkType::virtual_link &&
          lsa_key(*header).scope == FloodingScope::autonomous_system)
        continue;
      const auto existing = database_.find(lsa_key(*header));
      const bool body_changed =
          !existing || existing->bytes.size() != encoded->size() ||
          !std::equal(existing->bytes.begin() +
                          std::min<std::size_t>(
                              packet::ospf::lsa_header_octets,
                              existing->bytes.size()),
                      existing->bytes.end(),
                      encoded->begin() +
                          std::min<std::size_t>(
                              packet::ospf::lsa_header_octets,
                              encoded->size()));
      const auto result = database_.install(*encoded, version_, now,
                                            router_id_, true);
      if (result == InstallResult::malformed ||
          result == InstallResult::capacity_exhausted)
        return result == InstallResult::capacity_exhausted
                   ? ReceiveStatus::resource_exhausted
                   : ReceiveStatus::malformed;
      if (result == InstallResult::ignored)
        continue;
      if (result == InstallResult::fight_back_required &&
          !queue_fight_back(*encoded, *header, now))
        return ReceiveStatus::resource_exhausted;
      neighbor->database.received_lsa(*header, result);
      const bool implied_acknowledgment =
          result == InstallResult::identical &&
          neighbor->database.acknowledge(*header);
      if (!implied_acknowledgment) {
        if (!neighbor->database.queue_delayed_acknowledgment(*header))
          return ReceiveStatus::resource_exhausted;
        neighbor->pending_acknowledgment = true;
      } else if (neighbor->database.retransmissions().empty()) {
        // Hearing the identical generation from the peer proves delivery of
        // our flood. Cancel its timer exactly as an explicit LSAck would;
        // sending another acknowledgment here would create an ACK ping-pong.
        neighbor->pending_update = false;
        neighbor->update_retransmit_deadline = {};
      }

      // A newly installed instance is flooded to eligible adjacent neighbors
      // from this owner's LSDB. Link-scoped LSAs remain on the receiving
      // interface; area and AS scope can cross other interfaces in this
      // instance, subject to later area policy filtering.
      if (result == InstallResult::installed) {
        const auto function =
            version_ == packet::ospf::version_two
                ? header->type
                : header->type & 0x1fffU;
        const bool topology_lsa =
            !grace_identity &&
            (version_ == packet::ospf::version_two
                 ? (function >= 1U && function <= 5U) ||
                       function == 7U
                 : function >= 1U && function <= 9U);
        if (topology_lsa && body_changed)
          terminate_grace_helpers(now);
        const auto *record = database_.find(lsa_key(*header));
        if (!record)
          return ReceiveStatus::malformed;
        for (auto &candidate_owner : interfaces_) {
          if (record->key.scope == FloodingScope::link &&
              &candidate_owner != &owner)
            continue;
          if (record->key.scope == FloodingScope::autonomous_system &&
              candidate_owner.configuration.protocol.network_type ==
                  NetworkType::virtual_link)
            continue;
          for (auto &candidate : candidate_owner.exchanges) {
            if (&candidate == neighbor)
              continue;
            const auto state = std::find_if(
                candidate_owner.runtime.neighbors().begin(),
                candidate_owner.runtime.neighbors().end(),
                [&](const auto &item) {
                  return item.router_id == candidate.router_id;
                });
            if (state == candidate_owner.runtime.neighbors().end() ||
                state->state < NeighborState::exchange)
              continue;
            if (!candidate.database.queue_retransmission(
                    *record, version_, now))
              return ReceiveStatus::resource_exhausted;
            candidate.pending_update = true;
            candidate.update_retransmit_deadline = now;
          }
        }
        schedule_spf(now);
      }
    }
    if (neighbor_state->state == NeighborState::loading &&
        neighbor->database.requests().empty()) {
      const auto transition = owner.runtime.apply_neighbor_event(
          decoded.router_id, NeighborEvent::loading_done, false);
      if (!transition || transition->state != NeighborState::full)
        return ReceiveStatus::invalid_neighbor_state;
      neighbor->pending_request = false;
      schedule_local_origination(now);
    }
    return ReceiveStatus::accepted;
  }

  if (decoded.type == packet::ospf::PacketType::link_state_acknowledgment) {
    const auto acknowledgment =
        packet::ospf::parse_link_state_acknowledgment(decoded);
    if (!acknowledgment)
      return ReceiveStatus::malformed;
    for (std::size_t index{};
         index < acknowledgment->lsa_headers.size() /
                     packet::ospf::lsa_header_octets;
         ++index) {
      const auto header =
          packet::ospf::acknowledgment_header(*acknowledgment, index);
      if (!header)
        return ReceiveStatus::malformed;
      static_cast<void>(neighbor->database.acknowledge(*header));
    }
    if (neighbor->database.retransmissions().empty()) {
      neighbor->pending_update = false;
      neighbor->update_retransmit_deadline = {};
    }
    return ReceiveStatus::accepted;
  }
  return ReceiveStatus::malformed;
}

} // namespace router::ospf
