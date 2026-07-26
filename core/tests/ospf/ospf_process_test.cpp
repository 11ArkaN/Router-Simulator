// OSPF process authentication, NBMA and LSA refresh cases. Each fixture
// owns its process state and uses only encoded protocol packets.

#include "ospf_process_test_support.hpp"

void ospf_process_authentication_tests() {
  using namespace router::ospf;
  const auto now = RuntimeClock::time_point{std::chrono::seconds{100U}};

  // Authentication is verified at the protocol owner before Hello semantics
  // can allocate neighbor state. These process-level cases complement the
  // byte-level RFC 5709 fixture by proving that an encoded packet traverses
  // the same receive gate used by every real adjacency.
  const auto authentication = [](KeychainAlgorithm algorithm,
                                 std::uint8_t key_id,
                                 std::string_view secret) {
    ProcessAuthentication result{
        .initial_sequence = 100U,
        .secret_handle = 1U,
        .key_id = key_id,
        .algorithm = algorithm,
        .secret_kind = static_cast<std::uint8_t>(
            router::vault::SecretKind::ospf_authentication_key),
        .begin_utc_seconds = 0,
        .end_utc_seconds = std::nullopt,
        .tolerance_seconds = 0U,
        .timed = false};
    result.key_size = static_cast<std::uint8_t>(secret.size());
    std::copy(secret.begin(), secret.end(), result.key.begin());
    return result;
  };
  const auto authenticated_hello =
      [&](KeychainAlgorithm algorithm, std::uint8_t key_id,
          std::string_view transmit_secret,
          std::string_view receive_secret) {
        InstanceProcess transmitter{
            0x11111111U, 0U, router::packet::ospf::version_two, 0U,
            0x10101010U, 1U,
            router::device_catalog::ospf_neighbors_per_interface,
            router::device_catalog::ospf_lsas_per_instance};
        InstanceProcess receiver{
            0x22222222U, 0U, router::packet::ospf::version_two, 0U,
            0x20202020U, 1U,
            router::device_catalog::ospf_neighbors_per_interface,
            router::device_catalog::ospf_lsas_per_instance};
        require(
            transmitter.add_interface(
                interface_configuration(0x11111111U, 0xc0000201U, 0U), now) &&
                receiver.add_interface(
                    interface_configuration(0x22222222U, 0xc0000202U, 0U),
                    now),
            "authenticated OSPF peers rejected their interfaces");
        const auto transmit =
            authentication(algorithm, key_id, transmit_secret);
        const auto receive =
            authentication(algorithm, key_id, receive_secret);
        require(transmitter.set_interface_authentication(1U, transmit) &&
                    receiver.set_interface_authentication(1U, receive),
                "authenticated OSPF peers rejected valid key material");
        std::array<ProcessOutput, 2U> packets{};
        std::size_t written{};
        require(transmitter.run_ready(now, packets, written) &&
                    written == 1U,
                "authenticated OSPF owner did not emit its initial Hello");
        const auto bytes =
            std::span<const std::uint8_t>{packets[0].bytes}.first(
                packets[0].size);
        const auto status = receiver.receive_ipv4_packet(
            1U, bytes, {{192U, 0U, 2U, 1U}},
            packets[0].ipv4_destination, now);
        return std::pair{status,
                         receiver.receive_ipv4_packet(
                             1U, bytes, {{192U, 0U, 2U, 1U}},
                             packets[0].ipv4_destination, now)};
      };
  const auto password_ok =
      authenticated_hello(KeychainAlgorithm::password, 0U,
                          "wirepass", "wirepass");
  require(password_ok.first == ReceiveStatus::accepted,
          "matching OSPFv2 simple passwords did not authenticate");
  const auto password_bad =
      authenticated_hello(KeychainAlgorithm::password, 0U,
                          "wirepass", "wrong");
  require(password_bad.first == ReceiveStatus::authentication_failure,
          "mismatched OSPFv2 simple passwords changed protocol state");
  const auto hmac_ok =
      authenticated_hello(KeychainAlgorithm::hmac_sha256, 17U,
                          "rfc5709-shared-key", "rfc5709-shared-key");
  require(hmac_ok.first == ReceiveStatus::accepted &&
              hmac_ok.second == ReceiveStatus::authentication_failure,
          "OSPFv2 HMAC-SHA-256 acceptance or replay protection failed");
  const auto hmac_bad =
      authenticated_hello(KeychainAlgorithm::hmac_sha256, 17U,
                          "rfc5709-shared-key", "different-key");
  require(hmac_bad.first == ReceiveStatus::authentication_failure,
          "OSPFv2 HMAC-SHA-256 accepted a mismatched key");
  require(authenticated_hello(KeychainAlgorithm::message_digest, 9U,
                              "md5-key", "md5-key")
                  .first == ReceiveStatus::accepted &&
              authenticated_hello(KeychainAlgorithm::hmac_sha1, 11U,
                                  "sha1-keychain-key",
                                  "sha1-keychain-key")
                      .first == ReceiveStatus::accepted,
          "release-supported OSPFv2 keyed algorithms did not reach Hello");

  // OSPFv3 manual-SA authentication is a transport-mode AH envelope, not an
  // OSPF Authentication Trailer. The process owns both the outgoing sequence
  // and inbound anti-replay value, so replaying the same authentic packet must
  // fail before the Hello refreshes neighbor inactivity state.
  InstanceProcess ah_transmitter{
      0x11111111U, 0U, router::packet::ospf::version_three, 0U,
      0x31313131U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess ah_receiver{
      0x22222222U, 0U, router::packet::ospf::version_three, 0U,
      0x32323232U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  const auto ah_tx_interface = ipv6_interface_configuration(
      0x11111111U,
      {{0x20U, 1U, 0x0dU, 0xb8U, 0U, 1U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U}},
      1U, 0U);
  const auto ah_rx_interface = ipv6_interface_configuration(
      0x22222222U,
      {{0x20U, 1U, 0x0dU, 0xb8U, 0U, 1U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 2U}},
      2U, 0U);
  require(ah_transmitter.add_interface(ah_tx_interface, now) &&
              ah_receiver.add_interface(ah_rx_interface, now),
          "OSPFv3 AH fixture rejected its interfaces");
  ProcessAuthentication ah_key{
      .initial_sequence = 0U,
      .secret_handle = 1U,
      .key_size = 20U,
      .key_id = 4096U,
      .algorithm = KeychainAlgorithm::hmac_sha1,
      .secret_kind = static_cast<std::uint8_t>(
          router::vault::SecretKind::ipsec_static_authentication_key),
      .ipsec_ah = true,
      .begin_utc_seconds = 0,
      .end_utc_seconds = std::nullopt,
      .tolerance_seconds = 0U,
      .timed = false};
  constexpr std::string_view ah_secret = "01234567890123456789";
  std::copy(ah_secret.begin(), ah_secret.end(), ah_key.key.begin());
  require(ah_transmitter.set_interface_authentication(1U, ah_key) &&
              ah_receiver.set_interface_authentication(1U, ah_key),
          "OSPFv3 AH fixture rejected its manual SA");
  std::array<ProcessOutput, 1U> ah_outputs{};
  std::size_t ah_written{};
  require(ah_transmitter.run_ready(now, ah_outputs, ah_written) &&
              ah_written == 1U,
          "OSPFv3 AH fixture did not create an OSPF Hello");
  std::array<std::uint8_t, router::packet::maximum_frame_octets>
      ah_ipv6{};
  const auto ah_packet = ah_transmitter.protect_ipv6_ipsec_packet(
      1U, ah_outputs[0].ipv6_source,
      ah_outputs[0].ipv6_destination, ah_outputs[0].hop_limit,
      std::span<const std::uint8_t>{ah_outputs[0].bytes}.first(
          ah_outputs[0].size),
      ah_ipv6);
  require(ah_packet &&
              ah_receiver.receive_ipv6_ipsec_packet(
                  1U, *ah_packet, now) == ReceiveStatus::accepted &&
              ah_receiver.receive_ipv6_ipsec_packet(
                  1U, *ah_packet, now) ==
                  ReceiveStatus::authentication_failure,
          "OSPFv3 AH acceptance or anti-replay behavior failed");

  // Key rollover is evaluated by the protocol owner from real UTC at packet
  // creation time. Two already-active entries prove that the newest begin-time
  // wins without a configuration republish or a management polling loop.
  InstanceProcess rollover{
      0x33333333U, 0U, router::packet::ospf::version_two, 0U,
      0x30303030U, 1U,
      router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  require(rollover.add_interface(
              interface_configuration(0x33333333U, 0xc0000203U, 0U), now),
          "rollover fixture rejected its physical interface");
  const auto utc_now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now()
                               .time_since_epoch())
                           .count();
  auto old_key = authentication(KeychainAlgorithm::hmac_sha256, 12U,
                                "old-keychain-key");
  old_key.timed = true;
  old_key.begin_utc_seconds = utc_now - 20;
  old_key.tolerance_seconds = 300U;
  auto new_key = authentication(KeychainAlgorithm::hmac_sha256, 13U,
                                "new-keychain-key");
  new_key.timed = true;
  new_key.begin_utc_seconds = utc_now - 10;
  new_key.tolerance_seconds = 300U;
  const std::array rollover_keys{old_key, new_key};
  require(rollover.set_interface_authentication(1U, std::nullopt,
                                                rollover_keys),
          "rollover fixture rejected its complete keychain");
  std::array<ProcessOutput, 1U> rollover_packets{};
  std::size_t rollover_written{};
  require(rollover.run_ready(now, rollover_packets, rollover_written) &&
              rollover_written == 1U,
          "keychain rollover did not emit a protected Hello");
  const auto rollover_packet = router::packet::ospf::parse_packet(
      std::span<const std::uint8_t>{rollover_packets[0].bytes}.first(
          rollover_packets[0].size));
  require(rollover_packet &&
              router::ospf::authentication::v2_key_id(*rollover_packet) ==
                  new_key.key_id,
          "keychain rollover did not select the newest active send entry");

  // RFC 2328 sections 9.5.1 and C.5 require NBMA discovery to use the
  // configured neighbor table and unicast Hellos. A packet received from any
  // other transport address must not create a neighbor dynamically.
  InstanceProcess nbma_first{
      0x11111111U, 0U, router::packet::ospf::version_two, 0U,
      0x10101010U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  InstanceProcess nbma_second{
      0x22222222U, 0U, router::packet::ospf::version_two, 0U,
      0x20202020U, 1U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto nbma_first_interface =
      interface_configuration(0x11111111U, 0xc0000201U, 0U);
  auto nbma_second_interface =
      interface_configuration(0x22222222U, 0xc0000202U, 0U);
  nbma_first_interface.protocol.network_type = NetworkType::non_broadcast;
  nbma_second_interface.protocol.network_type = NetworkType::non_broadcast;
  router::ip::IpAddress first_peer{
      .family = router::ip::AddressFamily::ipv4};
  first_peer.bytes[0U] = 192U;
  first_peer.bytes[1U] = 0U;
  first_peer.bytes[2U] = 2U;
  first_peer.bytes[3U] = 2U;
  router::ip::IpAddress second_peer{
      .family = router::ip::AddressFamily::ipv4};
  second_peer.bytes[0U] = 192U;
  second_peer.bytes[1U] = 0U;
  second_peer.bytes[2U] = 2U;
  second_peer.bytes[3U] = 1U;
  require(nbma_first.add_interface(nbma_first_interface, now) &&
              nbma_second.add_interface(nbma_second_interface, now) &&
              nbma_first.add_nbma_neighbor(
                  1U, {.address = first_peer,
                       .poll_interval_seconds = 120U,
                       .priority = 1U},
                  now) &&
              nbma_second.add_nbma_neighbor(
                  1U, {.address = second_peer,
                       .poll_interval_seconds = 120U,
                       .priority = 1U},
                  now),
          "NBMA owner rejected a valid configured peer set");
  std::array<ProcessOutput,
             router::device_catalog::ospf_work_budget_packets>
      nbma_output{};
  std::size_t nbma_written{};
  require(nbma_first.run_ready(now, nbma_output, nbma_written),
          "NBMA owner rejected its initial PollInterval turn");
  const auto nbma_hello = std::find_if(
      nbma_output.begin(), nbma_output.begin() + nbma_written,
      [&](const auto &packet) {
        return packet.destination == PacketDestination::neighbor_unicast &&
               packet.ipv4_destination ==
                   router::ip::Ipv4{192U, 0U, 2U, 2U};
      });
  require(nbma_hello != nbma_output.begin() + nbma_written,
          "NBMA Hello was not unicasted to its configured transport peer");
  require(nbma_second.receive_ipv4_packet(
              1U,
              std::span<const std::uint8_t>{nbma_hello->bytes}.first(
                  nbma_hello->size),
              router::ip::Ipv4{192U, 0U, 2U, 1U},
              nbma_hello->ipv4_destination,
              now) == ReceiveStatus::accepted &&
              nbma_second.receive_ipv4_packet(
                  1U,
                  std::span<const std::uint8_t>{nbma_hello->bytes}.first(
                      nbma_hello->size),
                  router::ip::Ipv4{192U, 0U, 2U, 99U},
                  nbma_hello->ipv4_destination, now) ==
                  ReceiveStatus::neighbor_not_found,
          "NBMA receive path did not enforce the configured neighbor table");

  // LSRefreshTime is a local steady-clock deadline, not a global simulation
  // event. An isolated passive interface is sufficient to originate one
  // Router-LSA, then prove that the same owner refreshes it with a newer
  // sequence after the sourced 1800-second interval.
  InstanceProcess refresh_owner{
      0x11111111U, 0U, router::packet::ospf::version_two, 0U,
      0x01020304U, 2U, router::device_catalog::ospf_neighbors_per_interface,
      router::device_catalog::ospf_lsas_per_instance};
  auto refresh_interface =
      interface_configuration(0x11111111U, 0xcb007101U, 0U);
  refresh_interface.protocol.passive = true;
  refresh_interface.physical_port_ordinal = no_physical_port;
  refresh_interface.prefix_length = 32U;
  std::array<ProcessOutput, 2U> refresh_output{};
  std::size_t refresh_written{};
  require(refresh_owner.add_interface(refresh_interface, now) &&
              refresh_owner.run_ready(now, refresh_output,
                                      refresh_written),
          "isolated OSPF owner could not originate its initial LSDB");
  const auto initial_refresh_header =
      router::packet::ospf::lsa_header(
          refresh_owner.database().records().front().bytes,
          router::packet::ospf::version_two);
  require(initial_refresh_header &&
              initial_refresh_header->sequence_number ==
                  initial_sequence_number,
          "initial self-originated Router-LSA used the wrong sequence");
  const auto refresh_now = now + router::device_catalog::ospf_lsa_refresh;
  require(refresh_owner.next_deadline() &&
              *refresh_owner.next_deadline() <= refresh_now &&
              refresh_owner.run_ready(refresh_now, refresh_output,
                                      refresh_written),
          "LSRefreshTime did not wake the owning process");
  const auto refreshed_header =
      router::packet::ospf::lsa_header(
          refresh_owner.database().records().front().bytes,
          router::packet::ospf::version_two);
  require(refreshed_header &&
              refreshed_header->sequence_number ==
                  initial_sequence_number + 1 &&
              refresh_owner.database().records().front().age(refresh_now) ==
                  0U,
          "LSRefreshTime did not publish a younger Router-LSA generation");

}
