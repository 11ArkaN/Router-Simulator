// OSPF instance scheduling and packet ownership. The implementation performs
// no link lookup and cannot inspect another router. Every received byte comes
// from forwarding, and every emitted packet returns to forwarding for actual
// network transmission.

#include "router/ospf_process.hpp"
#include "router/interface_identity.hpp"
#include "router/ospf_authentication.hpp"

#include <algorithm>
#include <new>
#include <openssl/crypto.h>

namespace router::ospf {
namespace {

[[nodiscard]] bool external_advertisement(
    CoordinatorAdvertisementKind kind) noexcept {
  return kind == CoordinatorAdvertisementKind::translated_external ||
         kind == CoordinatorAdvertisementKind::nssa_external;
}

void write16(std::span<std::uint8_t> output, std::size_t offset,
             std::uint16_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write32(std::span<std::uint8_t> output, std::size_t offset,
             std::uint32_t value) noexcept {
  output[offset] = static_cast<std::uint8_t>(value >> 24U);
  output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
  output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
  output[offset + 3U] = static_cast<std::uint8_t>(value);
}

void write_lsa_header(std::span<std::uint8_t> output,
                      const packet::ospf::LsaHeaderView &header,
                      std::uint8_t version) noexcept {
  // DD and LSAck use the same twenty-octet header representation. Keeping one
  // writer prevents version 3's two-octet LS Type from drifting from version
  // 2's Options and one-octet type layout.
  write16(output, 0U, header.age_seconds);
  if (version == packet::ospf::version_two) {
    output[2U] = static_cast<std::uint8_t>(header.options);
    output[3U] = static_cast<std::uint8_t>(header.type);
  } else {
    write16(output, 2U, header.type);
  }
  write32(output, 4U, header.link_state_id);
  write32(output, 8U, header.advertising_router);
  write32(output, 12U,
          static_cast<std::uint32_t>(header.sequence_number));
  write16(output, 16U, header.checksum);
  write16(output, 18U, header.length);
}

bool constant_time_equal(std::span<const std::uint8_t> left,
                         std::span<const std::uint8_t> right) noexcept {
  if (left.size() != right.size())
    return false;
  std::uint8_t difference{};
  for (std::size_t index{}; index < left.size(); ++index)
    difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
  return difference == 0U;
}

[[nodiscard]] std::int64_t wall_clock_seconds() noexcept {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

[[nodiscard]] bool receive_key_valid(
    const ProcessAuthentication &candidate,
    std::span<const ProcessAuthentication> all,
    std::int64_t now) noexcept {
  if (!candidate.timed)
    return true;
  const auto tolerance =
      static_cast<std::int64_t>(candidate.tolerance_seconds);
  const auto earliest =
      candidate.begin_utc_seconds <
              std::numeric_limits<std::int64_t>::min() + tolerance
          ? std::numeric_limits<std::int64_t>::min()
          : candidate.begin_utc_seconds - tolerance;
  if (now < earliest)
    return false;

  // SR OS receive tolerance for a retiring entry is measured from the next
  // entry's begin-time. OSPF retains the last valid entry indefinitely, so no
  // locally configured end-time can create an unauthenticated fallback.
  std::optional<std::int64_t> next_begin;
  for (const auto &entry : all) {
    if (!entry.timed ||
        entry.begin_utc_seconds <= candidate.begin_utc_seconds)
      continue;
    if (!next_begin || entry.begin_utc_seconds < *next_begin)
      next_begin = entry.begin_utc_seconds;
  }
  if (!next_begin)
    return true;
  const auto latest =
      *next_begin > std::numeric_limits<std::int64_t>::max() - tolerance
          ? std::numeric_limits<std::int64_t>::max()
          : *next_begin + tolerance;
  return now <= latest;
}

} // namespace

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
  return ProcessNeighborSnapshot{
      .runtime = runtime,
      .ipv4_address = exchange->ipv4_address,
      .ipv6_address = exchange->ipv6_address,
      .dd_sequence = exchange->dd_sequence,
      .local_interface_id = owner.configuration.protocol.interface_id,
      .negotiation_complete = exchange->negotiation_complete,
      .database_description_pending =
          exchange->pending_database_description,
      .local_master = exchange->local_master};
}

InstanceProcess::NeighborExchange *
InstanceProcess::exchange(InterfaceOwner &owner, std::uint32_t router_id,
                          bool create) noexcept {
  const auto found = std::find_if(
      owner.exchanges.begin(), owner.exchanges.end(),
      [&](const auto &candidate) { return candidate.router_id == router_id; });
  if (found != owner.exchanges.end())
    return &*found;
  if (!create ||
      owner.exchanges.size() == maximum_neighbors_per_interface_)
    return nullptr;
  try {
    owner.exchanges.emplace_back(router_id, maximum_lsas_);
    return &owner.exchanges.back();
  } catch (const std::bad_alloc &) {
    return nullptr;
  }
}

bool InstanceProcess::advertised_full(
    const InterfaceOwner &owner, std::uint32_t router_id,
    RuntimeClock::time_point now) const noexcept {
  const auto runtime = std::find_if(
      owner.runtime.neighbors().begin(),
      owner.runtime.neighbors().end(),
      [router_id](const auto &neighbor) {
        return neighbor.router_id == router_id;
      });
  if (runtime != owner.runtime.neighbors().end() &&
      runtime->state == NeighborState::full)
    return true;
  const auto control = std::find_if(
      owner.exchanges.begin(), owner.exchanges.end(),
      [router_id](const auto &neighbor) {
        return neighbor.router_id == router_id;
      });
  return control != owner.exchanges.end() && control->helper_active &&
         control->helper_deadline > now;
}

void InstanceProcess::terminate_grace_helpers(
    RuntimeClock::time_point now) noexcept {
  bool changed{};
  for (auto &owner : interfaces_)
    for (auto &neighbor : owner.exchanges)
      if (neighbor.helper_active) {
        neighbor.helper_active = false;
        neighbor.helper_deadline = {};
        neighbor.helper_was_designated_router = false;
        changed = true;
      }
  // RFC 3623 section 3.2 requires the router and, when applicable, network LSA
  // to be reoriginated after strict topology checking terminates helper mode.
  if (changed)
    schedule_local_origination(now);
}

void InstanceProcess::schedule_local_origination(
    RuntimeClock::time_point now) noexcept {
  // RFC 2328 MinLSInterval is the absolute lower bound. SR OS additionally
  // applies its sourced lsa-generate initial, second and doubling waits.
  // Startup has no previous generation and can originate immediately.
  auto requested = now;
  if (last_local_origination_ != RuntimeClock::time_point{}) {
    const auto minimum =
        last_local_origination_ +
        device_catalog::ospf_min_lsa_interval;
    if (now - last_local_origination_ >= current_lsa_delay_) {
      // A quiet interval resets the adaptive hold-down and permits the
      // topology change to use only the RFC minimum that has already elapsed.
      current_lsa_delay_ = lsa_initial_wait_;
      requested = std::max(now, minimum);
    } else {
      requested = std::max(
          minimum, last_local_origination_ + current_lsa_delay_);
      current_lsa_delay_ =
          current_lsa_delay_ == lsa_initial_wait_
              ? lsa_second_wait_
              : std::min(current_lsa_delay_ * 2,
                         lsa_maximum_wait_);
    }
  }
  if (local_origination_deadline_ == RuntimeClock::time_point{} ||
      requested < local_origination_deadline_)
    local_origination_deadline_ = requested;
}

void InstanceProcess::schedule_spf(RuntimeClock::time_point now) noexcept {
  // SR OS exposes initial, second and maximum SPF waits. After the second
  // calculation, each failure inside the active hold-down doubles the
  // previous wait. Adding a constant here would converge increasingly slowly
  // and contradict the release command reference.
  if (last_spf_started_ == RuntimeClock::time_point{} ||
      now - last_spf_started_ >= spf_maximum_wait_)
    current_spf_delay_ = spf_initial_wait_;
  else
    current_spf_delay_ =
        current_spf_delay_ == spf_initial_wait_
            ? spf_second_wait_
            : std::min(current_spf_delay_ * 2,
                       spf_maximum_wait_);
  const auto requested = now + current_spf_delay_;
  if (spf_deadline_ == RuntimeClock::time_point{} ||
      requested < spf_deadline_)
    spf_deadline_ = requested;
}

bool InstanceProcess::self_sequence_supported(
    const LsaKey &key) const noexcept {
  using namespace packet::ospf::lsa;
  if (key.advertising_router != router_id_)
    return false;
  const auto router_type =
      version_ == packet::ospf::version_two
          ? version_two_router_type
          : version_three_router_type;
  if (key.type == router_type)
    return true;
  const auto router_information_type =
      version_ == packet::ospf::version_two
          ? version_two_area_opaque_type
          : version_three_router_information_type;
  const auto router_information_id =
      version_ == packet::ospf::version_two
          ? static_cast<std::uint32_t>(
                version_two_router_information_opaque_type)
                << 24U
          : 0U;
  if (key.type == router_information_type &&
      key.link_state_id == router_information_id)
    return true;
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_intra_area_prefix_type) {
    if (key.link_state_id == 0U)
      return true;
    return std::any_of(
        interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
          return owner.configuration.protocol.interface_id ==
                 key.link_state_id;
        });
  }
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_link_type)
    return std::any_of(
        interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
          return owner.configuration.protocol.interface_id ==
                 key.link_state_id;
        });
  if (std::any_of(coordinator_lsas_.begin(), coordinator_lsas_.end(),
                  [&](const auto &state) { return state.key == key; }))
    return true;
  if (key.type != version_two_network_type &&
      key.type != version_three_network_type)
    return false;
  return std::any_of(
      interfaces_.begin(), interfaces_.end(), [&](const auto &owner) {
        return version_ == packet::ospf::version_two
                   ? owner.configuration.protocol.local_election_identity ==
                         key.link_state_id
                   : owner.configuration.protocol.interface_id ==
                         key.link_state_id;
      });
}

bool InstanceProcess::set_self_sequence(
    const LsaKey &key, std::int32_t sequence,
    bool wrap_pending) noexcept {
  using namespace packet::ospf::lsa;
  auto update = [&](std::int32_t &value, bool &at_max,
                    bool &pending) {
    // A completed wrap is the only legal sequence reset. Ordinary fight-back
    // can only raise the next generation, never move it backwards.
    value = pending && !wrap_pending ? sequence
                                    : std::max(value, sequence);
    at_max = false;
    pending = wrap_pending;
    return true;
  };
  const auto router_type =
      version_ == packet::ospf::version_two
          ? version_two_router_type
          : version_three_router_type;
  if (key.type == router_type)
    return update(router_lsa_sequence_, router_sequence_at_max_,
                  router_sequence_wrap_pending_);
  const auto router_information_type =
      version_ == packet::ospf::version_two
          ? version_two_area_opaque_type
          : version_three_router_information_type;
  const auto router_information_id =
      version_ == packet::ospf::version_two
          ? static_cast<std::uint32_t>(
                version_two_router_information_opaque_type)
                << 24U
          : 0U;
  if (key.type == router_information_type &&
      key.link_state_id == router_information_id)
    return update(router_information_lsa_sequence_,
                  router_information_sequence_at_max_,
                  router_information_sequence_wrap_pending_);
  if (version_ == packet::ospf::version_three &&
      key.type == version_three_intra_area_prefix_type &&
      key.link_state_id == 0U)
    return update(prefix_lsa_sequence_, prefix_sequence_at_max_,
                  prefix_sequence_wrap_pending_);
  for (auto &owner : interfaces_) {
    const auto interface_identity =
        version_ == packet::ospf::version_two
            ? owner.configuration.protocol.local_election_identity
            : owner.configuration.protocol.interface_id;
    if (key.type == (version_ == packet::ospf::version_two
                         ? version_two_network_type
                         : version_three_network_type) &&
        key.link_state_id == interface_identity)
      return update(owner.network_lsa_sequence,
                    owner.network_sequence_at_max,
                    owner.network_sequence_wrap_pending);
    if (version_ == packet::ospf::version_three &&
        key.type == version_three_intra_area_prefix_type &&
        key.link_state_id ==
            owner.configuration.protocol.interface_id)
      return update(owner.network_prefix_lsa_sequence,
                    owner.network_prefix_sequence_at_max,
                    owner.network_prefix_sequence_wrap_pending);
    if (version_ == packet::ospf::version_three &&
        key.type == version_three_link_type &&
        key.link_state_id ==
            owner.configuration.protocol.interface_id)
      return update(owner.link_lsa_sequence,
                    owner.link_sequence_at_max,
                    owner.link_sequence_wrap_pending);
  }
  const auto coordinator = std::find_if(
      coordinator_lsas_.begin(), coordinator_lsas_.end(),
      [&](const auto &state) { return state.key == key; });
  if (coordinator != coordinator_lsas_.end())
    return update(coordinator->sequence,
                  coordinator->sequence_at_max,
                  coordinator->sequence_wrap_pending);
  return false;
}

bool InstanceProcess::queue_fight_back(
    std::span<const std::uint8_t> encoded_lsa,
    const packet::ospf::LsaHeaderView &header,
    RuntimeClock::time_point now) noexcept {
  const auto key = lsa_key(header);
  const auto found = std::find_if(
      pending_fight_backs_.begin(), pending_fight_backs_.end(),
      [&](const auto &pending) { return pending.key == key; });
  try {
    if (found != pending_fight_backs_.end()) {
      const auto queued =
          packet::ospf::lsa_header(found->bytes, version_);
      if (queued &&
          compare_lsa_headers(header, *queued) != LsaRecency::newer)
        return true;
      found->bytes.assign(encoded_lsa.begin(), encoded_lsa.end());
    } else {
      if (pending_fight_backs_.size() == maximum_lsas_)
        return false;
      PendingFightBack pending{.key = key, .bytes = {}};
      pending.bytes.assign(encoded_lsa.begin(), encoded_lsa.end());
      pending_fight_backs_.push_back(std::move(pending));
    }
    // Fight-back is a self-origination and therefore shares MinLSInterval
    // with topology-driven local LSA changes. The pending wire image remains
    // owner-local until that deadline.
    schedule_local_origination(now);
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::apply_pending_fight_backs(
    RuntimeClock::time_point now, bool &wrap_started) noexcept {
  wrap_started = false;
  for (auto &pending : pending_fight_backs_) {
    auto header = packet::ospf::lsa_header(pending.bytes, version_);
    if (!header)
      return false;
    const auto *current = database_.find(pending.key);
    if (current) {
      auto current_header =
          packet::ospf::lsa_header(current->bytes, version_);
      if (!current_header)
        return false;
      current_header->age_seconds = current->age(now);
      if (compare_lsa_headers(*header, *current_header) !=
          LsaRecency::newer)
        continue;
    }

    const bool supported = self_sequence_supported(pending.key);
    if (supported &&
        header->sequence_number != maximum_sequence_number) {
      if (!set_self_sequence(pending.key,
                             header->sequence_number + 1, false))
        return false;
      continue;
    }

    // An unsupported self-originated LSA describes state this router no
    // longer originates and is flushed at the received sequence. A supported
    // MaxSequenceNumber collision follows the same flush, then waits for
    // reliable removal before restarting at InitialSequenceNumber.
    pending.bytes[0U] =
        static_cast<std::uint8_t>(max_age_seconds >> 8U);
    pending.bytes[1U] = static_cast<std::uint8_t>(max_age_seconds);
    const auto installed = database_.install(
        pending.bytes, version_, now, router_id_, false);
    if (installed != InstallResult::installed &&
        installed != InstallResult::identical)
      return false;
    if (!database_.premature_age(pending.key, now))
      return false;
    const auto *flush = database_.find(pending.key);
    if (!flush || !flood_record(*flush, now))
      return false;

    if (!supported)
      continue;
    if (!set_self_sequence(pending.key, initial_sequence_number,
                           true))
      return false;
    if (std::find(pending_sequence_wraps_.begin(),
                  pending_sequence_wraps_.end(),
                  pending.key) == pending_sequence_wraps_.end())
      pending_sequence_wraps_.push_back(pending.key);
    wrap_started = true;
  }
  pending_fight_backs_.clear();
  return true;
}

void InstanceProcess::complete_sequence_wrap(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  const auto pending = std::find(pending_sequence_wraps_.begin(),
                                 pending_sequence_wraps_.end(), key);
  if (pending == pending_sequence_wraps_.end())
    return;
  if (set_self_sequence(key, initial_sequence_number, false)) {
    pending_sequence_wraps_.erase(pending);
    // Restart only after the MaxAge generation is absent from this LSDB and
    // every adjacency retransmission list. This is the sequence-wrap ordering
    // required by RFC 2328 sections 12.1.6 and 14.1.
    schedule_local_origination(now);
  }
}

bool InstanceProcess::start_sequence_wrap(
    const LsaKey &key, RuntimeClock::time_point now) noexcept {
  if (!database_.premature_age(key, now))
    return false;
  const auto *flush = database_.find(key);
  if (!flush || !flood_record(*flush, now) ||
      !set_self_sequence(key, initial_sequence_number, true))
    return false;
  if (std::find(pending_sequence_wraps_.begin(),
                pending_sequence_wraps_.end(),
                key) == pending_sequence_wraps_.end())
    pending_sequence_wraps_.push_back(key);
  return true;
}

bool InstanceProcess::flush_exhausted_sequences(
    RuntimeClock::time_point now, bool &wrap_started) noexcept {
  using namespace packet::ospf::lsa;
  wrap_started = false;
  if (router_sequence_at_max_) {
    const LsaKey key{
        .link_state_id =
            version_ == packet::ospf::version_two ? router_id_ : 0U,
        .advertising_router = router_id_,
        .type = version_ == packet::ospf::version_two
                    ? version_two_router_type
                    : version_three_router_type,
        .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  if (version_ == packet::ospf::version_three &&
      prefix_sequence_at_max_) {
    const LsaKey key{.link_state_id = 0U,
                     .advertising_router = router_id_,
                     .type = version_three_intra_area_prefix_type,
                     .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  if (router_information_sequence_at_max_) {
    const LsaKey key{
        .link_state_id =
            version_ == packet::ospf::version_two
                ? static_cast<std::uint32_t>(
                      version_two_router_information_opaque_type)
                      << 24U
                : 0U,
        .advertising_router = router_id_,
        .type = version_ == packet::ospf::version_two
                    ? version_two_area_opaque_type
                    : version_three_router_information_type,
        .scope = FloodingScope::area};
    if (!start_sequence_wrap(key, now))
      return false;
    wrap_started = true;
  }
  for (auto &owner : interfaces_) {
    const auto interface_id =
        owner.configuration.protocol.interface_id;
    const auto network_id =
        version_ == packet::ospf::version_two
            ? owner.configuration.protocol.local_election_identity
            : interface_id;
    if (owner.network_sequence_at_max) {
      const LsaKey key{
          .link_state_id = network_id,
          .advertising_router = router_id_,
          .type = version_ == packet::ospf::version_two
                      ? version_two_network_type
                      : version_three_network_type,
          .scope = FloodingScope::area};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
    if (version_ == packet::ospf::version_three &&
        owner.network_prefix_sequence_at_max) {
      const LsaKey key{.link_state_id = interface_id,
                       .advertising_router = router_id_,
                       .type = version_three_intra_area_prefix_type,
                       .scope = FloodingScope::area};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
    if (version_ == packet::ospf::version_three &&
        owner.link_sequence_at_max) {
      const LsaKey key{.link_state_id = interface_id,
                       .advertising_router = router_id_,
                       .type = version_three_link_type,
                       .scope = FloodingScope::link};
      if (!start_sequence_wrap(key, now))
        return false;
      wrap_started = true;
    }
  }
  for (auto &state : coordinator_lsas_) {
    if (!state.sequence_at_max)
      continue;
    if (!start_sequence_wrap(state.key, now))
      return false;
    wrap_started = true;
  }
  return true;
}

bool InstanceProcess::flood_record(const LsaRecord &record,
                                   RuntimeClock::time_point now,
                                   std::optional<std::uint32_t>
                                       link_interface) noexcept {
  // Every eligible Full adjacency receives the same immutable LSDB instance.
  // Queueing a key and generation does not copy or synthesize a neighbor LSA.
  for (auto &owner : interfaces_) {
    if (link_interface &&
        owner.configuration.protocol.interface_id != *link_interface)
      continue;
    for (auto &candidate : owner.exchanges) {
      // RFC 2328 section 15 and RFC 5340 section 4.7 forbid AS-scope
      // flooding over virtual adjacencies. The filter lives beside reliable
      // queueing so originations, refreshes and MaxAge flushes all obey it.
      if (owner.configuration.protocol.network_type ==
              NetworkType::virtual_link &&
          record.key.scope == FloodingScope::autonomous_system)
        continue;
      const auto neighbor = std::find_if(
          owner.runtime.neighbors().begin(), owner.runtime.neighbors().end(),
          [&](const auto &item) {
            return item.router_id == candidate.router_id;
          });
      if (neighbor == owner.runtime.neighbors().end() ||
          !advertised_full(owner, candidate.router_id, now))
        continue;
      if (!candidate.database.queue_retransmission(record, version_, now))
        return false;
      candidate.pending_update = true;
      candidate.update_retransmit_deadline = now;
    }
  }
  if (record.age(now) == max_age_seconds &&
      !database_.mark_max_age_flooded(record.key))
    return false;
  return true;
}

bool InstanceProcess::max_age_removal_safe(
    const LsaKey &key) const noexcept {
  for (const auto &owner : interfaces_) {
    // RFC 2328 section 14 keeps every MaxAge LSA while any neighbor is still
    // synchronizing its database. Such a neighbor may need the flush even if
    // this particular key is not yet visible on its retransmission list.
    if (std::any_of(owner.runtime.neighbors().begin(),
                    owner.runtime.neighbors().end(),
                    [](const auto &neighbor) {
                      return neighbor.state == NeighborState::exchange ||
                             neighbor.state == NeighborState::loading;
                    }))
      return false;
    if (std::any_of(owner.exchanges.begin(), owner.exchanges.end(),
                    [&](const auto &neighbor) {
                      return neighbor.database.retransmits(key);
                    }))
      return false;
  }
  return true;
}

bool InstanceProcess::maintain_database(
    RuntimeClock::time_point now) noexcept {
  bool topology_changed{};
  std::size_t index{};
  while (index < database_.records().size()) {
    const auto &sample = database_.records()[index];
    const auto key = sample.key;
    const auto age = sample.age(now);
    const bool self_originated =
        key.advertising_router == router_id_;
    const auto next_checksum_age = static_cast<std::uint16_t>(
        (sample.last_checksum_check_age /
             checksum_check_age_seconds +
         1U) *
        checksum_check_age_seconds);
    if (age < max_age_seconds &&
        next_checksum_age <= max_age_seconds &&
        age >= next_checksum_age &&
        !database_.verify_checksum_at(key, now))
      return false;

    // RFC 2328 section 12.4 refreshes reachable self-originated LSAs at
    // LSRefreshTime. The existing MinLSInterval scheduler collapses records
    // that became due in the same owner turn into one coherent local
    // generation without bypassing the five-second origination guard.
    if (self_originated &&
        age >= device_catalog::ospf_lsa_refresh.count() &&
        age < max_age_seconds)
      schedule_local_origination(now);

    if (age == max_age_seconds && !sample.max_age_flooded) {
      // Freeze the encoded record at MaxAge before queueing it. LSU emission
      // still adds interface transmit delay with a MaxAge clamp, while the
      // LSDB checksum remains valid because LS age is excluded.
      if (!database_.premature_age(key, now))
        return false;
      const auto *flush = database_.find(key);
      if (!flush || !flood_record(*flush, now))
        return false;
      topology_changed = true;
    }

    const auto *current = database_.find(key);
    if (current && current->age(now) == max_age_seconds &&
        current->max_age_flooded && max_age_removal_safe(key)) {
      // erase() compacts the bounded vector, so retain the same index and
      // inspect the record that moved into this slot. No iterator or pointer
      // survives the mutation.
      if (!database_.erase(key))
        return false;
      complete_sequence_wrap(key, now);
      const auto coordinator = std::find_if(
          coordinator_lsas_.begin(), coordinator_lsas_.end(),
          [&](const auto &state) { return state.key == key; });
      if (coordinator != coordinator_lsas_.end() &&
          coordinator->withdrawing &&
          !coordinator->sequence_wrap_pending)
        coordinator_lsas_.erase(coordinator);
      topology_changed = true;
      continue;
    }
    ++index;
  }
  if (topology_changed)
    schedule_spf(now);
  return true;
}

std::optional<RuntimeClock::time_point>
InstanceProcess::database_deadline() const noexcept {
  std::optional<RuntimeClock::time_point> earliest;
  const auto retain_earlier = [&](RuntimeClock::time_point candidate) {
    if (!earliest || candidate < *earliest)
      earliest = candidate;
  };
  for (const auto &record : database_.records()) {
    if (record.age_at_install == max_age_seconds) {
      // An unflooded MaxAge record is immediately ready. A flooded one wakes
      // on an ACK or neighbor-state event instead of spinning continuously.
      if (!record.max_age_flooded)
        retain_earlier(record.installed_at);
      continue;
    }
    const auto next_checksum_age = static_cast<std::uint16_t>(
        (record.last_checksum_check_age /
             checksum_check_age_seconds +
         1U) *
        checksum_check_age_seconds);
    if (next_checksum_age <= max_age_seconds)
      retain_earlier(
          record.installed_at +
          std::chrono::seconds{
              next_checksum_age - record.age_at_install});
    if (record.key.advertising_router == router_id_ &&
        record.age_at_install <
            device_catalog::ospf_lsa_refresh.count())
      retain_earlier(
          record.installed_at +
          (device_catalog::ospf_lsa_refresh -
           std::chrono::seconds{record.age_at_install}));
    retain_earlier(
        record.installed_at +
        (device_catalog::ospf_lsa_max_age -
         std::chrono::seconds{record.age_at_install}));
  }
  return earliest;
}

bool InstanceProcess::append_route_input(
    const CalculatedRoute &route, const CalculatedNextHop &next_hop,
    bool loop_free_alternate,
    std::vector<lab::routing::DynamicInput> &ipv4,
    std::vector<lab::routing::Ipv6DynamicInput> &ipv6) const noexcept {
  const auto owner = std::find_if(
      interfaces_.begin(), interfaces_.end(), [&](const auto &item) {
        if (route.version_three)
          return item.configuration.protocol.interface_id ==
                 next_hop.topology.local_interface;
        const auto &address = item.configuration.ipv4_source;
        const auto encoded =
            static_cast<std::uint32_t>(address[0U]) << 24U |
            static_cast<std::uint32_t>(address[1U]) << 16U |
            static_cast<std::uint32_t>(address[2U]) << 8U | address[3U];
        return encoded == next_hop.topology.local_interface;
      });
  if (owner == interfaces_.end() ||
      owner->configuration.physical_port_ordinal == no_physical_port)
    return false;

  const bool external =
      route.path_type == lab::routing::OspfPathType::external_type_1 ||
      route.path_type == lab::routing::OspfPathType::external_type_2 ||
      route.path_type == lab::routing::OspfPathType::nssa_type_1 ||
      route.path_type == lab::routing::OspfPathType::nssa_type_2;
  const auto preference = static_cast<std::uint16_t>(
      external ? external_preference_ : router_preference_);
  try {
    if (!route.version_three) {
      ipv4.push_back(
          {.configured = true,
           .operational = true,
           .network = route.version_two_network,
           .next_hop = next_hop.topology.version_two_next_hop,
           .port_ordinal = owner->configuration.physical_port_ordinal,
           .preference = preference,
           .metric = route.metric,
           .prefix_length = route.prefix_length,
           .source = lab::routing::RouteSource::ospf,
           .ospf_path_type = route.path_type,
           .internal_metric = route.internal_metric,
           .area_id = route.area_id,
           .tag = route.tag,
           .protocol_instance = instance_id_,
           .loop_free_alternate = loop_free_alternate});
      return true;
    }
    if (!route.ipv4_address_family) {
      // The OSPFv3 Interface ID is a 32-bit router-local value carried on the
      // wire by RFC 5340. It is not the forwarding interface identity. Native
      // IPv6 RIB, ND, PMTU and source-address selection share the disjoint
      // 64-bit identity defined by interface_identity.hpp. Publishing the wire
      // ID here made the route visible in OSPF show output while the FIB could
      // not associate its link-local next hop with the physical interface.
      ipv6.push_back(
          {.configured = true,
           .operational = true,
           .network = route.version_three_network,
           .next_hop = next_hop.version_three_link_local,
           .interface_id = lab::physical_interface_id(
               owner->configuration.physical_port_ordinal),
           .physical_port_ordinal =
               owner->configuration.physical_port_ordinal,
           .preference = preference,
           .metric = route.metric,
           .prefix_length = route.prefix_length,
           .source = lab::routing::RouteSource::ospf3,
           .ospf_path_type = route.path_type,
           .internal_metric = route.internal_metric,
           .area_id = route.area_id,
           .tag = route.tag,
           .protocol_instance = instance_id_,
           .loop_free_alternate = loop_free_alternate});
      return true;
    }

    // RFC 5838 section 2.5 places the IPv4 Direct Interface Address in the
    // first 32 bits of the Link-LSA address field and requires the remaining
    // 96 bits to be zero. The parser has already enforced that representation.
    const auto &encoded = next_hop.version_three_link_local;
    const auto network =
        static_cast<std::uint32_t>(route.version_three_network[0U]) << 24U |
        static_cast<std::uint32_t>(route.version_three_network[1U]) << 16U |
        static_cast<std::uint32_t>(route.version_three_network[2U]) << 8U |
        route.version_three_network[3U];
    const auto forwarding =
        static_cast<std::uint32_t>(encoded[0U]) << 24U |
        static_cast<std::uint32_t>(encoded[1U]) << 16U |
        static_cast<std::uint32_t>(encoded[2U]) << 8U | encoded[3U];
    ipv4.push_back(
        {.configured = true,
         .operational = true,
         .network = network,
         .next_hop = forwarding,
         .port_ordinal = owner->configuration.physical_port_ordinal,
         .preference = preference,
         .metric = route.metric,
         .prefix_length = route.prefix_length,
         .source = lab::routing::RouteSource::ospf3,
         .ospf_path_type = route.path_type,
         .internal_metric = route.internal_metric,
         .area_id = route.area_id,
         .tag = route.tag,
         .protocol_instance = instance_id_,
         .loop_free_alternate = loop_free_alternate});
    return true;
  } catch (const std::bad_alloc &) {
    return false;
  }
}

bool InstanceProcess::recalculate_routes(
    RuntimeClock::time_point now) noexcept {
  if (!topology_.build(database_.records(), version_, router_id_)) {
    route_recalculation_status_ =
        RouteRecalculationStatus::topology_rejected;
    return false;
  }
  const auto graph = topology_.graph();
  if (!spf_.calculate(graph.root_vertex, graph.vertices, graph.edges,
                      static_cast<std::uint16_t>(graph.first_hops.size()))) {
    route_recalculation_status_ = RouteRecalculationStatus::spf_rejected;
    return false;
  }
  const bool ipv4_address_family =
      version_ == packet::ospf::version_three &&
      instance_id_ >= device_catalog::ospf_v3_ipv4_instance_first;
  if (!route_calculator_.recalculate(database_.records(), version_, area_id_,
                                     ipv4_address_family, graph, spf_,
                                     loop_free_alternates_)) {
    route_recalculation_status_ =
        RouteRecalculationStatus::route_derivation_rejected;
    return false;
  }

  try {
    std::vector<lab::routing::DynamicInput> ipv4;
    std::vector<lab::routing::Ipv6DynamicInput> ipv6;
    for (const auto &route : route_calculator_.routes()) {
      // Connected prefixes are already authoritative RIB inputs. OSPF
      // publishes only routes that have a real first hop; retaining the local
      // zero-hop copies would create duplicate protocol ownership.
      for (const auto &next_hop : route.next_hops)
        if (!append_route_input(route, next_hop, false, ipv4, ipv6)) {
          route_recalculation_status_ =
              RouteRecalculationStatus::egress_interface_missing;
          return false;
        }
      for (const auto &next_hop : route.loop_free_alternates)
        if (!append_route_input(route, next_hop, true, ipv4, ipv6)) {
          route_recalculation_status_ =
              RouteRecalculationStatus::egress_interface_missing;
          return false;
        }
    }
    ipv4_route_inputs_.swap(ipv4);
    ipv6_route_inputs_.swap(ipv6);
  } catch (const std::bad_alloc &) {
    route_recalculation_status_ =
        RouteRecalculationStatus::allocation_failed;
    return false;
  }
  ++route_generation_;
  last_spf_started_ = now;
  spf_deadline_ = {};
  route_recalculation_status_ = RouteRecalculationStatus::succeeded;
  return true;
}

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

InstanceProcessCheckpoint
InstanceProcess::checkpoint(RuntimeClock::time_point now) const {
  const auto remaining = [now](RuntimeClock::time_point deadline) {
    if (deadline == RuntimeClock::time_point{} || deadline <= now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
  };
  const auto age = [now](RuntimeClock::time_point started) {
    if (started == RuntimeClock::time_point{} || started >= now)
      return std::chrono::milliseconds{};
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now - started);
  };

  InstanceProcessCheckpoint result{
      .database = database_.checkpoint(now),
      .interfaces = {},
      .pending_fight_backs = {},
      .pending_sequence_wraps = pending_sequence_wraps_,
      .coordinator_lsas = {},
      .virtual_endpoint_addresses = virtual_endpoint_addresses_,
      .pending_coordinator_advertisements =
          pending_coordinator_advertisements_,
      .last_local_origination_age = age(last_local_origination_),
      .local_origination_remaining =
          remaining(local_origination_deadline_),
      .spf_remaining = remaining(spf_deadline_),
      .last_spf_started_age = age(last_spf_started_),
      .current_lsa_delay = current_lsa_delay_,
      .current_spf_delay = current_spf_delay_,
      .route_generation = route_generation_,
      .next_dd_sequence = next_dd_sequence_,
      .next_coordinator_link_state_id =
          next_coordinator_link_state_id_,
      .router_lsa_sequence = router_lsa_sequence_,
      .prefix_lsa_sequence = prefix_lsa_sequence_,
      .router_information_lsa_sequence =
          router_information_lsa_sequence_,
      .route_recalculation_status = route_recalculation_status_,
      .run_ready_status = run_ready_status_,
      .local_origination_status = local_origination_status_,
      .local_origination_install_result =
          local_origination_install_result_,
      .coordinator_reconcile_pending =
          coordinator_reconcile_pending_,
      .router_sequence_at_max = router_sequence_at_max_,
      .prefix_sequence_at_max = prefix_sequence_at_max_,
      .router_information_sequence_at_max =
          router_information_sequence_at_max_,
      .router_sequence_wrap_pending =
          router_sequence_wrap_pending_,
      .prefix_sequence_wrap_pending =
          prefix_sequence_wrap_pending_,
      .router_information_sequence_wrap_pending =
          router_information_sequence_wrap_pending_,
      .area_border_router = area_border_router_,
      .autonomous_system_boundary_router =
          autonomous_system_boundary_router_,
      .virtual_link_endpoint = virtual_link_endpoint_,
      .overload = overload_,
      .graceful_restart_helper = graceful_restart_helper_,
      .loop_free_alternates = loop_free_alternates_};
  result.interfaces.reserve(interfaces_.size());
  for (const auto &owner : interfaces_) {
    ProcessInterfaceCheckpoint saved{
        .configuration = owner.configuration,
        .runtime = owner.runtime.checkpoint(now),
        .exchanges = {},
        .nbma_peers = {},
        .send_authentication = owner.send_authentication,
        .receive_authentications = owner.receive_authentications,
        .authentication_sequence = owner.authentication_sequence,
        .authentication_send_key_id =
            owner.authentication_send_key_id,
        .ipsec_replay_sequence = owner.ipsec_replay_sequence,
        .network_lsa_sequence = owner.network_lsa_sequence,
        .network_prefix_lsa_sequence =
            owner.network_prefix_lsa_sequence,
        .link_lsa_sequence = owner.link_lsa_sequence,
        .authentication_required = owner.authentication_required,
        .ipsec_replay_sequence_seen =
            owner.ipsec_replay_sequence_seen,
        .network_lsa_originated = owner.network_lsa_originated,
        .network_sequence_at_max = owner.network_sequence_at_max,
        .network_prefix_sequence_at_max =
            owner.network_prefix_sequence_at_max,
        .link_sequence_at_max = owner.link_sequence_at_max,
        .network_sequence_wrap_pending =
            owner.network_sequence_wrap_pending,
        .network_prefix_sequence_wrap_pending =
            owner.network_prefix_sequence_wrap_pending,
        .link_sequence_wrap_pending =
            owner.link_sequence_wrap_pending};
    if (saved.send_authentication)
      saved.send_authentication->key.fill(0U);
    for (auto &authentication : saved.receive_authentications)
      authentication.key.fill(0U);
    saved.nbma_peers.reserve(owner.nbma_peers.size());
    for (const auto &peer : owner.nbma_peers)
      saved.nbma_peers.push_back(
          {.configuration = peer.configuration,
           .hello_remaining = remaining(peer.hello_deadline),
           .router_id = peer.router_id});
    saved.exchanges.reserve(owner.exchanges.size());
    for (const auto &neighbor : owner.exchanges)
      saved.exchanges.push_back(
          {.database = neighbor.database.checkpoint(),
           .router_id = neighbor.router_id,
           .dd_sequence = neighbor.dd_sequence,
           .summary_cursor = neighbor.summary_cursor,
           .request_cursor = neighbor.request_cursor,
           .update_cursor = neighbor.update_cursor,
           .dd_retransmit_remaining =
               remaining(neighbor.dd_retransmit_deadline),
           .request_retransmit_remaining =
               remaining(neighbor.request_retransmit_deadline),
           .update_retransmit_remaining =
               remaining(neighbor.update_retransmit_deadline),
           .ipv4_address = neighbor.ipv4_address,
           .ipv6_address = neighbor.ipv6_address,
           .authentication_sequences =
               neighbor.authentication_sequences,
           .authentication_sequence_seen =
               neighbor.authentication_sequence_seen,
           .helper_remaining = remaining(neighbor.helper_deadline),
           .local_master = neighbor.local_master,
           .negotiation_complete = neighbor.negotiation_complete,
           .pending_database_description =
               neighbor.pending_database_description,
           .pending_request = neighbor.pending_request,
           .pending_update = neighbor.pending_update,
           .pending_acknowledgment =
               neighbor.pending_acknowledgment,
           .peer_more = neighbor.peer_more,
           .sent_more = neighbor.sent_more,
           .complete_after_reply = neighbor.complete_after_reply,
           .helper_active = neighbor.helper_active,
           .helper_was_designated_router =
               neighbor.helper_was_designated_router});
    result.interfaces.push_back(std::move(saved));
  }
  result.pending_fight_backs.reserve(pending_fight_backs_.size());
  for (const auto &entry : pending_fight_backs_)
    result.pending_fight_backs.push_back(
        {.key = entry.key, .bytes = entry.bytes});
  result.coordinator_lsas.reserve(coordinator_lsas_.size());
  for (const auto &entry : coordinator_lsas_)
    result.coordinator_lsas.push_back(
        {.advertisement = entry.advertisement,
         .key = entry.key,
         .sequence = entry.sequence,
         .withdrawing = entry.withdrawing,
         .sequence_at_max = entry.sequence_at_max,
         .sequence_wrap_pending = entry.sequence_wrap_pending});
  return result;
}

bool InstanceProcess::restore(
    const InstanceProcessCheckpoint &checkpoint,
    RuntimeClock::time_point now) noexcept {
  if (checkpoint.interfaces.size() > maximum_interfaces_ ||
      checkpoint.database.records.size() > maximum_lsas_ ||
      checkpoint.current_lsa_delay < std::chrono::milliseconds{} ||
      checkpoint.current_spf_delay < std::chrono::milliseconds{})
    return false;
  const auto deadline = [now](std::chrono::milliseconds remaining) {
    return remaining == std::chrono::milliseconds{}
               ? RuntimeClock::time_point{}
               : now + remaining;
  };
  try {
    if (!database_.restore(checkpoint.database, version_, now))
      return false;
    interfaces_.clear();
    for (const auto &saved : checkpoint.interfaces) {
      if (saved.configuration.protocol.version != version_ ||
          saved.configuration.protocol.area_id != area_id_ ||
          saved.runtime.configuration != saved.configuration.protocol ||
          saved.exchanges.size() > maximum_neighbors_per_interface_ ||
          saved.nbma_peers.size() > maximum_neighbors_per_interface_ ||
          saved.receive_authentications.size() > 64U)
        return false;
      InterfaceOwner owner{saved.configuration,
                           maximum_neighbors_per_interface_, now};
      if (!owner.runtime.restore(saved.runtime, now))
        return false;
      owner.send_authentication = saved.send_authentication;
      owner.receive_authentications = saved.receive_authentications;
      owner.authentication_sequence = saved.authentication_sequence;
      owner.authentication_send_key_id =
          saved.authentication_send_key_id;
      owner.authentication_required = saved.authentication_required;
      owner.ipsec_replay_sequence = saved.ipsec_replay_sequence;
      owner.ipsec_replay_sequence_seen =
          saved.ipsec_replay_sequence_seen;
      owner.network_lsa_sequence = saved.network_lsa_sequence;
      owner.network_prefix_lsa_sequence =
          saved.network_prefix_lsa_sequence;
      owner.link_lsa_sequence = saved.link_lsa_sequence;
      owner.network_lsa_originated = saved.network_lsa_originated;
      owner.network_sequence_at_max = saved.network_sequence_at_max;
      owner.network_prefix_sequence_at_max =
          saved.network_prefix_sequence_at_max;
      owner.link_sequence_at_max = saved.link_sequence_at_max;
      owner.network_sequence_wrap_pending =
          saved.network_sequence_wrap_pending;
      owner.network_prefix_sequence_wrap_pending =
          saved.network_prefix_sequence_wrap_pending;
      owner.link_sequence_wrap_pending =
          saved.link_sequence_wrap_pending;
      for (const auto &peer : saved.nbma_peers)
        owner.nbma_peers.push_back(
            {.configuration = peer.configuration,
             .hello_deadline = deadline(peer.hello_remaining),
             .router_id = peer.router_id});
      for (const auto &saved_neighbor : saved.exchanges) {
        if (saved_neighbor.router_id == 0U ||
            saved_neighbor.summary_cursor >
                saved_neighbor.database.summaries.size() ||
            saved_neighbor.request_cursor >
                saved_neighbor.database.requests.size() ||
            saved_neighbor.update_cursor >
                saved_neighbor.database.retransmissions.size())
          return false;
        NeighborExchange neighbor{saved_neighbor.router_id,
                                  maximum_lsas_};
        if (!neighbor.database.restore(saved_neighbor.database))
          return false;
        neighbor.dd_sequence = saved_neighbor.dd_sequence;
        neighbor.summary_cursor = saved_neighbor.summary_cursor;
        neighbor.request_cursor = saved_neighbor.request_cursor;
        neighbor.update_cursor = saved_neighbor.update_cursor;
        neighbor.dd_retransmit_deadline =
            deadline(saved_neighbor.dd_retransmit_remaining);
        neighbor.request_retransmit_deadline =
            deadline(saved_neighbor.request_retransmit_remaining);
        neighbor.update_retransmit_deadline =
            deadline(saved_neighbor.update_retransmit_remaining);
        neighbor.ipv4_address = saved_neighbor.ipv4_address;
        neighbor.ipv6_address = saved_neighbor.ipv6_address;
        neighbor.authentication_sequences =
            saved_neighbor.authentication_sequences;
        neighbor.authentication_sequence_seen =
            saved_neighbor.authentication_sequence_seen;
        neighbor.local_master = saved_neighbor.local_master;
        neighbor.negotiation_complete =
            saved_neighbor.negotiation_complete;
        neighbor.pending_database_description =
            saved_neighbor.pending_database_description;
        neighbor.pending_request = saved_neighbor.pending_request;
        neighbor.pending_update = saved_neighbor.pending_update;
        neighbor.pending_acknowledgment =
            saved_neighbor.pending_acknowledgment;
        neighbor.peer_more = saved_neighbor.peer_more;
        neighbor.sent_more = saved_neighbor.sent_more;
        neighbor.complete_after_reply =
            saved_neighbor.complete_after_reply;
        neighbor.helper_deadline =
            deadline(saved_neighbor.helper_remaining);
        neighbor.helper_active = saved_neighbor.helper_active;
        neighbor.helper_was_designated_router =
            saved_neighbor.helper_was_designated_router;
        owner.exchanges.push_back(std::move(neighbor));
      }
      interfaces_.push_back(std::move(owner));
    }
    pending_fight_backs_.clear();
    for (const auto &entry : checkpoint.pending_fight_backs)
      pending_fight_backs_.push_back(
          {.key = entry.key, .bytes = entry.bytes});
    pending_sequence_wraps_ = checkpoint.pending_sequence_wraps;
    coordinator_lsas_.clear();
    for (const auto &entry : checkpoint.coordinator_lsas)
      coordinator_lsas_.push_back(
          {.advertisement = entry.advertisement,
           .key = entry.key,
           .sequence = entry.sequence,
           .withdrawing = entry.withdrawing,
           .sequence_at_max = entry.sequence_at_max,
           .sequence_wrap_pending = entry.sequence_wrap_pending});
    virtual_endpoint_addresses_ =
        checkpoint.virtual_endpoint_addresses;
    pending_coordinator_advertisements_ =
        checkpoint.pending_coordinator_advertisements;
    coordinator_reconcile_pending_ =
        checkpoint.coordinator_reconcile_pending;
    next_dd_sequence_ = checkpoint.next_dd_sequence;
    next_coordinator_link_state_id_ =
        checkpoint.next_coordinator_link_state_id;
    router_lsa_sequence_ = checkpoint.router_lsa_sequence;
    prefix_lsa_sequence_ = checkpoint.prefix_lsa_sequence;
    router_information_lsa_sequence_ =
        checkpoint.router_information_lsa_sequence;
    router_sequence_at_max_ = checkpoint.router_sequence_at_max;
    prefix_sequence_at_max_ = checkpoint.prefix_sequence_at_max;
    router_information_sequence_at_max_ =
        checkpoint.router_information_sequence_at_max;
    router_sequence_wrap_pending_ =
        checkpoint.router_sequence_wrap_pending;
    prefix_sequence_wrap_pending_ =
        checkpoint.prefix_sequence_wrap_pending;
    router_information_sequence_wrap_pending_ =
        checkpoint.router_information_sequence_wrap_pending;
    area_border_router_ = checkpoint.area_border_router;
    autonomous_system_boundary_router_ =
        checkpoint.autonomous_system_boundary_router;
    virtual_link_endpoint_ = checkpoint.virtual_link_endpoint;
    overload_ = checkpoint.overload;
    graceful_restart_helper_ = checkpoint.graceful_restart_helper;
    loop_free_alternates_ = checkpoint.loop_free_alternates;
    last_local_origination_ =
        checkpoint.last_local_origination_age ==
                std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now - checkpoint.last_local_origination_age;
    local_origination_deadline_ =
        deadline(checkpoint.local_origination_remaining);
    spf_deadline_ = deadline(checkpoint.spf_remaining);
    last_spf_started_ =
        checkpoint.last_spf_started_age == std::chrono::milliseconds{}
            ? RuntimeClock::time_point{}
            : now - checkpoint.last_spf_started_age;
    current_lsa_delay_ = checkpoint.current_lsa_delay;
    current_spf_delay_ = checkpoint.current_spf_delay;
    route_generation_ = checkpoint.route_generation;
    route_recalculation_status_ =
        checkpoint.route_recalculation_status;
    run_ready_status_ = checkpoint.run_ready_status;
    local_origination_status_ =
        checkpoint.local_origination_status;
    local_origination_install_result_ =
        checkpoint.local_origination_install_result;
    // Derived SPF, route inputs and FIB candidates are never trusted from a
    // checkpoint. Rebuild them solely from the restored LSDB and configured
    // local egress identities before ControlWorker can publish this process.
    return recalculate_routes(now);
  } catch (const std::bad_alloc &) {
    return false;
  }
}

} // namespace router::ospf
