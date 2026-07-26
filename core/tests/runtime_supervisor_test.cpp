// Supervisor tests verify empty startup, cross-kind identity, hardware-derived
// carrier, retained absent-port links and isolated router deletion.

#include "router/lab_checkpoint.hpp"
#include "router/runtime_supervisor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

std::uint32_t capture_u32(std::span<const std::uint8_t> bytes,
                          std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U |
         static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U |
         static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U;
}

void require(bool condition, const char *message) {
  // The shared runner preserves the first focused lifecycle diagnostic.
  if (!condition)
    throw std::runtime_error(message);
}

router::crypto::Sha256Digest transport_secret(std::uint8_t seed) {
  router::crypto::Sha256Digest result{};
  for (std::size_t index = 0U; index < result.size(); ++index)
    result[index] = static_cast<std::uint8_t>(seed + index);
  return result;
}

router::packet::dns::Name dns_name(const char *text) {
  const auto parsed = router::packet::dns::name_from_text(text);
  if (!parsed)
    throw std::runtime_error("checkpoint DNS fixture name is invalid");
  return *parsed;
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

router::tls_profile::Configuration checkpoint_tls_configuration() {
  using namespace router::tls_profile;

  // Use every TLS configuration collection in one fixture. A sparse fixture
  // could prove that the ABI carries a boolean while still losing a leafref,
  // numeric list key, status policy or certificate-chain ordering. The names
  // below are configuration identifiers, not filesystem paths or executable
  // behavior, and deliberately differ between client and server collections.
  Configuration configuration{
      .use_pqc_only = false,
      .certificate_profiles =
          {{.name = "server-cert",
            .admin_enabled = true,
            .entries = {{.id = 1U,
                         .certificate_file = "server.pem",
                         .key_file = "server-key.pem",
                         .send_chain_ca_profiles = {"intermediate-ca",
                                                    "root-ca"}}}}},
      .trust_anchor_profiles = {{.name = "project-roots",
                                 .ca_profiles = {"root-ca", "backup-ca"}}},
      .client_cipher_lists = {{.name = "client-ciphers",
                               .entries = {{20U, "tls-aes128-gcm-sha256"},
                                           {10U, "tls-aes256-gcm-sha384"}}}},
      .client_group_lists = {{.name = "client-groups",
                              .entries = {{1U, "tls-x25519"},
                                          {2U, "tls-ml-kem1024"}}}},
      .client_signature_lists = {{.name = "client-signatures",
                                  .entries = {{1U, "tls-ed25519"},
                                              {2U, "tls-ml-dsa87"}}}},
      .client_profiles =
          {{.name = "resolver-client",
            .admin_enabled = true,
            .certificate_profile = {},
            .cipher_list = "client-ciphers",
            .group_list = "client-groups",
            .signature_list = "client-signatures",
            .trust_anchor_profile = "project-roots",
            .protocol_version = ProtocolVersion::tls13,
            .status_verification = {.default_result = StatusResult::good,
                                    .primary = RevocationMethod::ocsp,
                                    .secondary = RevocationMethod::crl}}},
      .server_cipher_lists = {{.name = "server-ciphers",
                               .entries = {{1U,
                                            "tls-chacha20-poly1305-sha256"}}}},
      .server_group_lists = {{.name = "server-groups",
                              .entries = {{1U, "tls-ecdhe-384"}}}},
      .server_signature_lists = {{.name = "server-signatures",
                                  .entries = {{1U,
                                               "tls-ecdsa-secp384r1-sha384"}}}},
      .server_profiles = {
          {.name = "dns-server",
           .admin_enabled = true,
           .certificate_profile = "server-cert",
           .cipher_list = "server-ciphers",
           .group_list = "server-groups",
           .signature_list = "server-signatures",
           .client_trust_anchor_profile = "project-roots",
           .client_common_name_list = "dns-clients",
           .protocol_version = ProtocolVersion::tls13,
           .status_verification = {.default_result = StatusResult::revoked,
                                   .primary = RevocationMethod::crl,
                                   .secondary = RevocationMethod::none}}}};
  if (validate(configuration))
    throw std::runtime_error("checkpoint TLS fixture is invalid");
  return configuration;
}

router::ipsec::configuration::Configuration checkpoint_ipsec_configuration() {
  using namespace router::ipsec;
  using namespace router::ipsec::configuration;

  // This fixture intentionally touches every currently serializable IPsec
  // collection and its presence metadata. Empty vectors would only prove that
  // collection lengths survive ABI 6, not that selector address families,
  // transform references, tunnel PMTU policy or transport identity state do.
  Prefix local_prefix;
  local_prefix.network.family = AddressFamily::ipv6;
  local_prefix.network.bytes = {0x20U, 0x01U, 0x0dU, 0xb8U, 0x00U, 0x01U,
                                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                                0x00U, 0x00U, 0x00U, 0x00U};
  local_prefix.length = 64U;
  Prefix remote_prefix = local_prefix;
  remote_prefix.network.bytes[5] = 0x02U;

  Configuration configuration{
      .ike_transforms = {{.id = 19U,
                          .dh_group = DiffieHellmanGroup::ecp256,
                          .encryption = AesGcmKeySize::aes256,
                          .lifetime_seconds = 7'200U,
                          .dh_group_configured = true,
                          .authentication_encryption_configured = true,
                          .encryption_configured = true,
                          .prf_sha256_configured = true,
                          .lifetime_configured = true}},
      .ipsec_transforms = {{.id = 7U,
                            .encryption = AesGcmKeySize::aes192,
                            .pfs_group = DiffieHellmanGroup::ecp256,
                            .lifetime_seconds = 3'600U,
                            .authentication_encryption_configured = true,
                            .encryption_configured = true,
                            .extended_sequence_number = true,
                            .extended_sequence_number_configured = true,
                            .lifetime_configured = true,
                            .pfs_enabled = true,
                            .pfs_group_configured = true}},
      .ike_policies = {{.id = 4U,
                        .description = "checkpoint IKEv2 policy",
                        .ike_transforms = {19U},
                        .peer_authentication = AuthenticationMethod::psk,
                        .own_authentication = AuthenticationMethod::symmetric,
                        .ipsec_lifetime_seconds = 3'600U,
                        .fragmentation_mtu = 1'280U,
                        .fragmentation_reassembly_timeout_seconds = 3U,
                        .dpd_interval_seconds = 45U,
                        .dpd_max_retries = 4U,
                        .nat_keepalive_interval_seconds = 180U,
                        .fragmentation_configured = true,
                        .dpd_configured = true,
                        .nat_traversal_configured = true,
                        .ike_version2_configured = true,
                        .peer_authentication_configured = true,
                        .own_authentication_configured = true,
                        .ipsec_lifetime_configured = true,
                        .fragmentation_mtu_configured = true,
                        .fragmentation_reassembly_timeout_configured = true,
                        .dpd_interval_configured = true,
                        .dpd_max_retries_configured = true,
                        .dpd_reply_only = true,
                        .dpd_reply_only_configured = true,
                        .nat_force = true,
                        .nat_force_configured = true,
                        .nat_force_keepalive = true,
                        .nat_force_keepalive_configured = true,
                        .nat_keepalive_interval_configured = true}},
      // A nonzero opaque handle is sufficient for this codec fixture. The
      // LabRuntime vault tests separately prove that externally supplied or
      // tampered handles cannot be resolved into key bytes after restore.
      .static_sas = {{.name = "checkpoint-static-sa",
                      .description = "ABI 6 manual SA",
                      .authentication = StaticSaAuthentication::sha1,
                      .authentication_key_format = StaticSaKeyFormat::ascii,
                      .direction = StaticSaDirection::bidirectional,
                      .protocol = SecurityProtocol::ah,
                      .authentication_key_handle = 0x7722U,
                      .spi = 4'096U,
                      .authentication_container_configured = true,
                      .authentication_configured = true,
                      .direction_configured = true,
                      .protocol_configured = true,
                      .spi_configured = true}},
      .certificate_profiles =
          {{.name = "router-certificate",
            .entries = {{.id = 1U,
                         .certificate_file = "router-a.crt",
                         .private_key_file = "router-a.key",
                         .compare_chain_include = "cross-root",
                         .send_chain_ca_profiles = {"issuing-ca"},
                         .rsa_signature = RsaSignature::pss,
                         .rsa_signature_configured = true}},
            .enabled = true,
            .admin_state_configured = true}},
      .trust_anchor_profiles = {{.name = "lab-roots",
                                 .ca_profiles = {"root-ca"}}},
      .ppk_lists = {{.name = "post-quantum-keys",
                     .entries = {{.id = "site-a",
                                  .secret_handle = 0x7711U,
                                  .format = PpkValueFormat::hexadecimal}}}},
      .traffic_selector_lists =
          {{.name = "checkpoint-v6",
            .local = {{.id = 1U,
                       .prefix = local_prefix,
                       .range_begin = std::nullopt,
                       .range_end = std::nullopt,
                       .protocol = SelectorProtocol::tcp,
                       .numeric_protocol = 0U,
                       .ports = {.first = 443U, .last = 443U},
                       .opaque_ports = false,
                       .protocol_configured = true,
                       .selector_begin_configured = true,
                       .selector_end_configured = true}},
            .remote = {{.id = 1U,
                        .prefix = remote_prefix,
                        .range_begin = std::nullopt,
                        .range_end = std::nullopt,
                        .protocol = SelectorProtocol::udp,
                        .numeric_protocol = 0U,
                        .ports = {.first = 5'000U, .last = 5'100U},
                        .opaque_ports = false,
                        .protocol_configured = true,
                        .selector_begin_configured = true,
                        .selector_end_configured = true}}}},
      .transport_mode_profiles =
          {{.name = "checkpoint-transport",
            .description = "ABI 6 transport state",
            .dynamic = {.ike_policy = 4U,
                        .ipsec_transforms = {7U},
                        .certificate_profile = "router-certificate",
                        .trust_anchor_profile = "lab-roots",
                        .ppk_list = "post-quantum-keys",
                        .ppk_id = "site-a",
                        .pre_shared_key_handle = 0x4172U,
                        .identity = "router-a.example.test",
                        .identity_type = IdentityType::fqdn,
                        .default_revocation_result = RevocationResult::good,
                        .primary_revocation_method = RevocationMethod::ocsp,
                        .secondary_revocation_method = RevocationMethod::crl,
                        .auto_establish = true,
                        .auto_establish_configured = true,
                        .default_revocation_result_configured = true,
                        .primary_revocation_method_configured = true,
                        .secondary_revocation_method_configured = true},
            .replay_window = 256U,
            .maximum_esp_history_records = 48U,
            .maximum_ike_history_records = 3U,
            .replay_window_configured = true,
            .maximum_esp_history_records_configured = true,
            .maximum_ike_history_records_configured = true}},
      .tunnel_templates = {
          {.id = 10U,
           .description = "ABI 6 tunnel state",
           .ipsec_transforms = {7U},
           .ppk_list = "post-quantum-keys",
           .encapsulated_ip_mtu = 1'360U,
           .ip_mtu = 1'400U,
           .replay_window = 512U,
           .pmtu_discovery_aging_seconds = 1'800U,
           .private_tcp_mss_adjust = 1'320U,
           .public_tcp_mss_adjust = 1'300U,
           .reverse_route_metric = 20U,
           .reverse_route_preference = 10U,
           .ipv4_fragmentation_required = {.interval_seconds = 20U,
                                           .message_count = 50U,
                                           .enabled = true,
                                           .enabled_configured = true,
                                           .interval_configured = true,
                                           .message_count_configured = true},
           .ipv6_packet_too_big = {.interval_seconds = 30U,
                                   .message_count = 60U,
                                   .enabled = false,
                                   .enabled_configured = true,
                                   .interval_configured = true,
                                   .message_count_configured = true},
           .clear_df_bit = true,
           .clear_df_bit_configured = true,
           .copy_traffic_class_upon_decapsulation = true,
           .copy_traffic_class_configured = true,
           .ignore_default_route = true,
           .ignore_default_route_configured = true,
           .encapsulated_ip_mtu_configured = true,
           .ip_mtu_configured = true,
           .replay_window_configured = true,
           .pmtu_discovery_aging_configured = true,
           .private_tcp_mss_adjust_configured = true,
           .propagate_pmtu_v4 = true,
           .propagate_pmtu_v4_configured = true,
           .propagate_pmtu_v6 = true,
           .propagate_pmtu_v6_configured = true,
           .public_tcp_mss_adjust_configured = true,
           .reverse_route_metric_configured = true,
           .reverse_route_preference_configured = true}}};
  if (!validate(configuration))
    throw std::runtime_error("checkpoint IPsec fixture is invalid");
  return configuration;
}

} // namespace

void runtime_supervisor_tests() {
  using namespace router::lab;
  const auto wait_for = [](auto predicate,
                           std::chrono::steady_clock::duration timeout) {
    // Wasm pthreads share a finite Node worker pool. A wall-clock deadline
    // measures the runtime contract without making success depend on how many
    // one-millisecond sleeps the host scheduler coalesces under compile load.
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!predicate() && std::chrono::steady_clock::now() < deadline)
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
    return predicate();
  };
  // The global packet pool belongs on the heap, matching the production
  // supervisor lifetime instead of consuming a Wasm pthread stack.
  auto runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->devices().size() == 0 && runtime->hosts().size() == 0 &&
              runtime->topology().size() == 0,
          "new supervisor did not start empty");

  const auto r1 = runtime->create_router("r1", "7750-sr-1", "R1");
  const auto r2 = runtime->create_router("r2", "7750-sr-7", "R2");
  const auto h1 = runtime->create_host("h1", "Host 1");
  require(r1 && r2 && h1, "supervisor rejected valid mixed nodes");
  require(!runtime->create_host("r1", "Duplicate"),
          "supervisor accepted cross-kind duplicate identity");

  const auto router_link =
      runtime->create_link("r1-r2", {node(*r1), "1/1/1"}, {node(*r2), "1/1/1"},
                           std::chrono::nanoseconds{100});
  // Empty modular hardware retains topology but cannot create physical signal.
  require(router_link && runtime->topology().size() == 1 &&
              runtime->active_links() == 0,
          "absent hardware did not retain carrier-down link intent");
  require(runtime->set_card(*r2, 1, "iom4-e", "iom4-e") ==
                  HardwareEditResult::applied &&
              runtime->set_mda(*r2, 1, 1, "me10-10gb-sfp+", "me10-10gb-sfp+") ==
                  HardwareEditResult::applied,
          "supervisor rejected compatible R2 inventory");
  // R1 is 100 Gb/s and R2 is 10 Gb/s. A name-matched cable cannot hide that
  // selected rate mismatch.
  require(runtime->active_links() == 0,
          "speed mismatch produced magic carrier");

  const auto host_link =
      runtime->create_link("r1-h1", {node(*r1), "1/1/2"}, {node(*h1), "eth0"},
                           std::chrono::nanoseconds{50});
  require(host_link && runtime->active_links() == 1,
          "router-host physical link did not activate");
  require(runtime->set_link_properties(*host_link, false,
                                       std::chrono::nanoseconds{250}) &&
              runtime->topology().get(*host_link)->propagation_ns == 250U &&
              runtime->active_links() == 1,
          "link property edit deleted the object or lost propagation");
  require(runtime->delete_router(*r1) && runtime->devices().size() == 1 &&
              runtime->topology().size() == 0 && runtime->active_links() == 0,
          "router deletion retained links or changed unrelated router");

  const auto h2 = runtime->create_host("h2", "Host 2");
  const auto bridge = runtime->create_switch(
      "bridge", "generic-ethernet-24", "Broadcast domain");
  require(h2 && bridge &&
              !runtime->create_router("bridge", "7750-sr-1", "duplicate"),
          "supervisor rejected switch lifecycle or cross-kind identity");
  const auto h1_bridge = runtime->create_link(
      "h1-bridge", {node(*h1), "eth0"}, {node(*bridge), "1"},
      std::chrono::nanoseconds{100});
  const auto h2_bridge = runtime->create_link(
      "h2-bridge", {node(*h2), "eth0"}, {node(*bridge), "2"},
      std::chrono::nanoseconds{100});
  require(h1_bridge && h2_bridge && runtime->active_links() == 2U,
          "profile-backed switch links did not reach carrier");
  auto bridge_state = runtime->checkpoint();
  require(bridge_state && bridge_state->switches.entries.size() == 1U &&
              bridge_state->network.switches.size() == 1U,
          "supervisor checkpoint omitted switch control or forwarding state");
  const auto bridge_two = runtime->create_switch(
      "bridge-two", "generic-ethernet-24", "Broadcast domain 2");
  const auto bridge_three = runtime->create_switch(
      "bridge-three", "generic-ethernet-24", "Broadcast domain 3");
  require(bridge_two && bridge_three &&
              runtime->create_link(
                  "bridge-chain-1", {node(*bridge), "3"},
                  {node(*bridge_two), "1"}, std::chrono::nanoseconds{100}) &&
              runtime->create_link(
                  "bridge-chain-2", {node(*bridge_two), "2"},
                  {node(*bridge_three), "1"}, std::chrono::nanoseconds{100}) &&
              !runtime->create_link(
                  "bridge-loop", {node(*bridge_three), "2"},
                  {node(*bridge), "4"}, std::chrono::nanoseconds{100}),
          "supervisor accepted a physical bridge cycle without STP");
  require(runtime->delete_switch(*bridge_two) &&
              runtime->delete_switch(*bridge_three),
          "bridge loop fixture did not clean up");
  require(runtime->delete_switch(*bridge) && runtime->switches().size() == 0U &&
              runtime->topology().size() == 0U &&
              runtime->active_links() == 0U,
          "switch deletion retained incident links or forwarding state");

  // Release the first shared packet pool before constructing the four-router
  // reference path inside the generated Wasm memory budget.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  const auto a = runtime->create_router("a", "7750-sr-1", "A");
  const auto b = runtime->create_router("b", "7750-sr-1", "B");
  const auto c = runtime->create_router("c", "7750-sr-1", "C");
  const auto d = runtime->create_router("d", "7750-sr-1", "D");
  require(a && b && c && d, "four-router runtime creation failed");

  for (const auto device : {*a, *b, *c, *d}) {
    // Every used physical port is explicitly enabled. Fixed inventory alone
    // does not make a router interface operational.
    require(
        runtime->configure_port(device, "1/1/1", true,
                                router::device_catalog::default_network_mtu,
                                100'000) == HardwareEditResult::applied &&
            runtime->configure_port(device, "1/1/2", true,
                                    router::device_catalog::default_network_mtu,
                                    100'000) == HardwareEditResult::applied,
        "four-router port provisioning failed");
  }
  const auto ab =
      runtime->create_link("a-b", {node(*a), "1/1/1"}, {node(*b), "1/1/1"},
                           std::chrono::nanoseconds{100});
  const auto bc =
      runtime->create_link("b-c", {node(*b), "1/1/2"}, {node(*c), "1/1/1"},
                           std::chrono::nanoseconds{100});
  const auto cd =
      runtime->create_link("c-d", {node(*c), "1/1/2"}, {node(*d), "1/1/1"},
                           std::chrono::nanoseconds{100});
  require(ab && bc && cd, "four-router physical chain creation failed");

  const auto select_wire = [&](router::CapturePointId id, LinkHandle link,
                               std::string_view name) {
    CapturePointProgram program;
    program.id = id;
    program.kind = CapturePointKind::link_direction;
    program.link = link;
    program.link_endpoint = 0;
    program.selected = true;
    program.name_size = static_cast<std::uint16_t>(name.size());
    std::copy(name.begin(), name.end(), program.name.begin());
    return runtime->configure_capture_point(program);
  };
  require(select_wire(0, *ab, "a-b/from-a") &&
              select_wire(1, *bc, "b-c/from-b") &&
              select_wire(2, *cd, "c-d/from-c"),
          "four-router wire capture selection failed");

  const router::packet::Mac mac_a{0x02, 0, 0, 0, 0x0a, 1};
  const router::packet::Mac mac_b1{0x02, 0, 0, 0, 0x0b, 1};
  const router::packet::Mac mac_b2{0x02, 0, 0, 0, 0x0b, 2};
  const router::packet::Mac mac_c1{0x02, 0, 0, 0, 0x0c, 1};
  const router::packet::Mac mac_c2{0x02, 0, 0, 0, 0x0c, 2};
  const router::packet::Mac mac_d{0x02, 0, 0, 0, 0x0d, 1};
  require(
      runtime->configure_interface(*a, "1/1/1", mac_a, 0x0a000c01U, 30, true) &&
          runtime->configure_interface(*b, "1/1/1", mac_b1, 0x0a000c02U, 30,
                                       true) &&
          runtime->configure_interface(*b, "1/1/2", mac_b2, 0x0a001701U, 30,
                                       true) &&
          runtime->configure_interface(*c, "1/1/1", mac_c1, 0x0a001702U, 30,
                                       true) &&
          runtime->configure_interface(*c, "1/1/2", mac_c2, 0x0a002201U, 30,
                                       true) &&
          runtime->configure_interface(*d, "1/1/1", mac_d, 0x0a002202U, 30,
                                       true),
      "four-router interface configuration failed");
  require(runtime->configure_system_interface(*a, 0x0aff0001U, true),
          "supervisor rejected a valid IPv4 system interface");
  const auto system_route_present = [&] {
    const auto state = runtime->router_operational_state(*a);
    return state && std::any_of(state->fib.routes.begin(),
                                state->fib.routes.begin() + state->fib.count,
                                [](const auto &route) {
                                  return route.local_system &&
                                         route.network == 0x0aff0001U &&
                                         route.prefix_length == 32U;
                                });
  };
  require(system_route_present(),
          "supervisor omitted the local system route from operational FIB");
  require(runtime->add_static_route(*a, 0x0a002200U, 30, 0x0a000c02U) &&
              runtime->add_static_route(*b, 0x0a002200U, 30, 0x0a001702U) &&
              runtime->add_static_route(*c, 0x0a000c00U, 30, 0x0a001701U) &&
              runtime->add_static_route(*d, 0x0a000c00U, 30, 0x0a002201U),
          "four-router static route configuration failed");

  require(runtime->start_router_ping(*a, 0x0a002202U, 77),
          "asynchronous four-router ping did not start");
  // The network pthread owns steady_clock and all delivery deadlines. Polling
  // observes completion only and never advances a hidden test timeline.
  require(wait_for([&] { return runtime->router_ping_reply(*a, 77); },
                   std::chrono::seconds{2}),
          "four-router ping did not traverse encoded hop-by-hop forwarding");
  const auto ipv4_ping_outcome = runtime->router_ping_outcome(*a, 77);
  require((ipv4_ping_outcome & 0xffU) == 1U &&
              ((ipv4_ping_outcome >> 8U) & 0xffU) != 0U &&
              (ipv4_ping_outcome >> 16U) <
                  static_cast<std::uint64_t>(
                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::milliseconds{50})
                          .count()),
          "IPv4 forwarding-to-link wake-up added scheduler-scale RTT");

  const auto ipv6 = [](const char *text) {
    const auto value = router::ip::parse_ipv6(text);
    if (!value)
      throw std::runtime_error("runtime IPv6 fixture address is invalid");
    return *value;
  };
  // The same physical interfaces carry both families. Configuring IPv6 must
  // preserve the already working IPv4 addresses, port state and learned ARP.
  require(runtime->configure_ipv6_interface(*a, "1/1/1", mac_a,
                                            ipv6("2001:db8:ab::"), 127,
                                            ipv6("fe80::a1"), true) &&
              runtime->configure_ipv6_interface(*b, "1/1/1", mac_b1,
                                                ipv6("2001:db8:ab::1"), 127,
                                                ipv6("fe80::b1"), true) &&
              runtime->configure_ipv6_interface(*b, "1/1/2", mac_b2,
                                                ipv6("2001:db8:bc::"), 127,
                                                ipv6("fe80::b2"), true) &&
              runtime->configure_ipv6_interface(*c, "1/1/1", mac_c1,
                                                ipv6("2001:db8:bc::1"), 127,
                                                ipv6("fe80::c1"), true) &&
              runtime->configure_ipv6_interface(*c, "1/1/2", mac_c2,
                                                ipv6("2001:db8:cd::"), 127,
                                                ipv6("fe80::c2"), true) &&
              runtime->configure_ipv6_interface(*d, "1/1/1", mac_d,
                                                ipv6("2001:db8:cd::1"), 127,
                                                ipv6("fe80::d1"), true),
          "four-router IPv6 interface configuration failed");
  const auto secondary_a = ipv6("2001:db8:aa::1");
  require(runtime->configure_ipv6_address(*a, "1/1/1", secondary_a, 64U, 20U,
                                          true, 42U),
          "supervisor rejected a secondary IPv6 address transaction");
  require(runtime->add_ipv6_static_route(*a, ipv6("2001:db8:cd::"), 127,
                                         ipv6("2001:db8:ab::1")) &&
              runtime->add_ipv6_static_route(*b, ipv6("2001:db8:cd::"), 127,
                                             ipv6("2001:db8:bc::1")) &&
              runtime->add_ipv6_static_route(*c, ipv6("2001:db8:ab::"), 127,
                                             ipv6("2001:db8:bc::")) &&
              runtime->add_ipv6_static_route(*d, ipv6("2001:db8:ab::"), 127,
                                             ipv6("2001:db8:cd::")),
          "four-router IPv6 static route configuration failed");
  const std::array configured_global_addresses{
      std::pair{*a, ipv6("2001:db8:ab::")},
      std::pair{*b, ipv6("2001:db8:ab::1")},
      std::pair{*b, ipv6("2001:db8:bc::")},
      std::pair{*c, ipv6("2001:db8:bc::1")},
      std::pair{*c, ipv6("2001:db8:cd::")},
      std::pair{*d, ipv6("2001:db8:cd::1")},
      std::pair{*a, secondary_a}};
  // Every interface chooses an independent RFC 4862 initial delay before its
  // link-local and global DAD exchanges. Readiness of A therefore says nothing
  // about D: D may still be tentative and correctly ignore A's first two NS
  // packets. This test is about hop-by-hop ND forwarding, so it waits for the
  // precondition on every participant instead of racing the third one-second
  // multicast solicitation against an unrelated two-second assertion timeout.
  const auto all_global_addresses_preferred = [&] {
    for (const auto &[device, address] : configured_global_addresses) {
      const auto state = runtime->router_operational_state(device);
      if (!state)
        return false;
      const auto found =
          std::find_if(state->ipv6_dad.begin(), state->ipv6_dad.end(),
                       [&](const auto &entry) {
                         return entry.address == address &&
                                entry.state == Ipv6DadState::preferred;
                       });
      if (found == state->ipv6_dad.end())
        return false;
    }
    return true;
  };
  require(wait_for(all_global_addresses_preferred, std::chrono::seconds{5}),
          "four-router IPv6 interfaces did not complete DAD");
  router::packet::nd::RouterAdvertisementConfig ra_config{
      .advertised_mtu = static_cast<std::uint16_t>(
          router::device_catalog::default_network_mtu -
          router::packet::ethernet_header_octets)};
  require(runtime->configure_router_advertisement(*a, "1/1/1", true, ra_config),
          "control-to-forwarding RA configuration failed");
  MldRouterConfiguration mld_configuration;
  mld_configuration.enabled = true;
  // Deliberately supply invalid derived identity. RuntimeSupervisor must bind
  // the protocol to the selected inventory port and its configured link-local
  // address instead of trusting caller-owned values.
  mld_configuration.port_ordinal = 7U;
  mld_configuration.link_local_address = ipv6("fe80::dead");
  require(runtime->configure_mld_interface(*a, "1/1/1", mld_configuration),
          "control-to-forwarding MLD configuration failed");
  const std::array mld_ssm{
      MldSsmTranslation{.start = ipv6("ff3e::100"),
                        .end = ipv6("ff3e::1ff"),
                        .source = ipv6("2001:db8:ab::100")}};
  require(runtime->replace_mld_ssm_translations(*a, "1/1/1", mld_ssm),
          "control-to-forwarding SSM transaction failed");
  router::dhcpv6::RelayInterfaceConfig relay_configuration;
  // Logical service identity is deliberately unrelated to physical ordinal
  // zero. RuntimeSupervisor resolves and stores the physical attachment as a
  // separate field while preserving this stable return-path key.
  relay_configuration.interface_id = 81'001U;
  relay_configuration.link_address = ipv6("2001:db8:ab::");
  relay_configuration.relay_interface_id.assign(600U, 0x5aU);
  relay_configuration.servers[0] = {.address = ipv6("2001:db8:cd::1"),
                                    .scope_interface_id = 0U};
  relay_configuration.server_count = 1U;
  relay_configuration.upstream_policy =
      router::dhcpv6::RelayUpstreamPolicy::explicit_servers_required;
  require(runtime->configure_dhcpv6_relay(*a, "1/1/1", relay_configuration) &&
              !runtime->configure_dhcpv6_relay(*a, "1/1/1",
                                               [&] {
                                                 auto invalid =
                                                     relay_configuration;
                                                 invalid.interface_id = 0U;
                                                 return invalid;
                                               }()),
          "control-to-forwarding DHCPv6 relay transaction was not exact");
  // The public supervisor must resolve the device and active relay identity
  // before publishing an operational clear. The selected table is empty in
  // this topology, which makes the expected operation idempotent without
  // weakening ownership: a different logical interface must still fail.
  require(
      runtime->clear_dhcpv6_relay_leases(
          *a, {.filter = {.interface_id = 81'001U}, .no_dhcp_release = true}) &&
          !runtime->clear_dhcpv6_relay_leases(
              *a,
              {.filter = {.interface_id = 81'002U}, .no_dhcp_release = true}),
      "supervisor accepted a DHCPv6 lease clear for the wrong owner");
  // Creating the service interface starts independent RFC 4862 DAD for its
  // link-local source. A real router rejects local origination while that
  // address is tentative, so retry only until the owner completes the initial
  // delay and post-NS RetransTimer instead of granting instant readiness.
  require(wait_for(
              [&] {
                return runtime->start_router_ipv6_ping(
                    *a, ipv6("2001:db8:cd::1"), 78);
              },
              std::chrono::seconds{3}),
          "asynchronous four-router IPv6 ping did not start after DAD");
  const bool ipv6_ping_replied =
      wait_for([&] { return runtime->router_ipv6_ping_reply(*a, 78); },
               std::chrono::seconds{2});
  if (!ipv6_ping_replied) {
    // Preserve owner-local evidence on failure. Aggregate table size alone is
    // ambiguous in a multi-router path, while pending ownership, last drop and
    // per-router progress identify the exact hop without adding a test hook to
    // the live forwarding API.
    std::string diagnostic =
        "four-router IPv6 ping did not traverse ND on every physical hop";
    if (const auto failed = runtime->checkpoint())
      for (const auto &router : failed->network.routers) {
        diagnostic +=
            " [router=" + std::to_string(router.device.index) +
            ",pending=" + std::to_string(router.forwarding.pending.size()) +
            ",neighbors=" +
            std::to_string(router.forwarding.ipv6_neighbors.size()) +
            ",forwarded=" + std::to_string(router.forwarding.forwarded_frames) +
            ",dropped=" + std::to_string(router.forwarding.dropped_frames) +
            ",last-drop=" +
            std::to_string(static_cast<unsigned>(router.forwarding.last_drop)) +
            ",reply=" +
            std::to_string(router.forwarding.ipv6_echo_reply_valid) + ']';
      }
    throw std::runtime_error(diagnostic);
  }
  const auto ipv6_ping_outcome = runtime->router_ipv6_ping_outcome(*a, 78);
  require((ipv6_ping_outcome & 0xffU) == 1U &&
              ((ipv6_ping_outcome >> 8U) & 0xffU) != 0U &&
              (ipv6_ping_outcome >> 16U) <
                  static_cast<std::uint64_t>(
                      std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::milliseconds{50})
                          .count()),
          "IPv6 forwarding-to-link wake-up added scheduler-scale RTT");

  // Packet bytes are drained to the independent PCAPNG artifact rather than
  // duplicated in recovery checkpoints. Inspect the public capture projection
  // before taking the structural checkpoint to retain the TTL wire assertion.
  const auto path_capture_view = runtime->prepare_capture();
  const std::vector<std::uint8_t> path_capture(path_capture_view.begin(),
                                               path_capture_view.end());
  auto path_checkpoint = runtime->checkpoint();
  require(path_checkpoint && path_checkpoint->network.routers.size() == 4,
          "four-router forwarding checkpoint was unavailable");
  const auto control_a = std::find_if(
      path_checkpoint->control.begin(), path_checkpoint->control.end(),
      [&](const auto &entry) { return entry.device == *a; });
  const auto forwarding_a =
      std::find_if(path_checkpoint->network.routers.begin(),
                   path_checkpoint->network.routers.end(),
                   [&](const auto &entry) { return entry.device == *a; });
  require(
      control_a != path_checkpoint->control.end() &&
          control_a->native_ipv6_addresses.size() == 2U &&
          std::any_of(control_a->native_ipv6_addresses.begin(),
                      control_a->native_ipv6_addresses.end(),
                      [&](const auto &entry) {
                        return entry.address == secondary_a &&
                               entry.primary_preference == 20U &&
                               entry.tag_configured && entry.tag == 42U;
                      }) &&
          control_a->router_advertisements[0].configured &&
          control_a->router_advertisements[0].enabled &&
          control_a->mld_interfaces[0].configured &&
          control_a->mld_interfaces[0].configuration.port_ordinal == 0U &&
          control_a->mld_interfaces[0].configuration.link_local_address ==
              ipv6("fe80::a1") &&
          control_a->mld_interfaces[0].ssm_translations.size() == 1U &&
          control_a->mld_interfaces[0].ssm_translations[0] == mld_ssm[0] &&
          forwarding_a != path_checkpoint->network.routers.end() &&
          forwarding_a->forwarding.native_ipv6_addresses ==
              control_a->native_ipv6_addresses &&
          !forwarding_a->forwarding.ipv6_router_advertisements.empty() &&
          forwarding_a->forwarding.mld_interfaces.size() == 1U &&
          forwarding_a->forwarding.mld_interfaces[0].ssm_translations.size() ==
              1U &&
          forwarding_a->forwarding.mld_interfaces[0].ssm_translations[0] ==
              mld_ssm[0] &&
          forwarding_a->forwarding.dhcpv6_relay_interfaces.size() == 1U &&
          forwarding_a->forwarding.dhcpv6_relay_interfaces[0] ==
              relay_configuration &&
          forwarding_a->forwarding.dhcpv6_relay_socket.has_value(),
      "RA, MLD or DHCPv6 relay state was omitted from checkpoint");
  require(runtime->clear_mld_database(*a, "1/1/1") &&
              runtime->clear_mld_database_all(*a) &&
              runtime->clear_mld_version(*a, "1/1/1") &&
              !runtime->clear_mld_database(*a, "1/1/1", ipv6("2001:db8::1")),
          "MLD operational clear did not honor owner or multicast scope");
  for (const auto &router : path_checkpoint->network.routers)
    require(!router.forwarding.adjacencies.empty() &&
                !router.forwarding.ipv6_neighbors.empty(),
            "a physical hop completed without ARP or IPv6 ND state");
  std::array<bool, 3> observed_ttl{};
  for (std::size_t offset = 0; offset + 12U <= path_capture.size();) {
    const auto block_length = capture_u32(path_capture, offset + 4U);
    require(block_length >= 12U && offset + block_length <= path_capture.size(),
            "four-router capture contains an invalid PCAPNG block");
    if (capture_u32(path_capture, offset) == 6U) {
      const auto interface_id = capture_u32(path_capture, offset + 8U);
      const auto captured_length = capture_u32(path_capture, offset + 20U);
      if (interface_id < observed_ttl.size() && captured_length &&
          offset + 28U + captured_length <= path_capture.size()) {
        router::packet::Frame captured;
        captured.length = static_cast<std::uint16_t>(captured_length);
        std::copy_n(path_capture.begin() +
                        static_cast<std::ptrdiff_t>(offset + 28U),
                    captured_length, captured.bytes.begin());
        const auto ipv4 = router::packet::parse_ipv4(captured);
        const auto icmp = router::packet::parse_icmp(captured);
        if (ipv4 && icmp && icmp->type == 8U && icmp->sequence == 77U)
          observed_ttl[interface_id] =
              ipv4->ttl == static_cast<std::uint8_t>(64U - interface_id);
      }
    }
    offset += block_length;
  }
  require(std::all_of(observed_ttl.begin(), observed_ttl.end(),
                      [](bool value) { return value; }),
          "encoded IPv4 TTL was not decremented exactly once per physical hop");

  require(runtime->remove_ipv6_interface(*a, "1/1/1"),
          "IPv6 interface removal rejected configured RA child state");
  const auto removed_ra_checkpoint = runtime->checkpoint();
  const auto removed_control_a =
      std::find_if(removed_ra_checkpoint->control.begin(),
                   removed_ra_checkpoint->control.end(),
                   [&](const auto &entry) { return entry.device == *a; });
  const auto removed_forwarding_a =
      std::find_if(removed_ra_checkpoint->network.routers.begin(),
                   removed_ra_checkpoint->network.routers.end(),
                   [&](const auto &entry) { return entry.device == *a; });
  require(
      removed_control_a != removed_ra_checkpoint->control.end() &&
          !removed_control_a->router_advertisements[0].configured &&
          !removed_control_a->mld_interfaces[0].configured &&
          removed_forwarding_a !=
              removed_ra_checkpoint->network.routers.end() &&
          removed_forwarding_a->forwarding.ipv6_router_advertisements.empty() &&
          removed_forwarding_a->forwarding.mld_interfaces.empty() &&
          removed_forwarding_a->forwarding.dhcpv6_relay_interfaces.empty() &&
          !removed_forwarding_a->forwarding.dhcpv6_relay_socket,
      "IPv6 interface removal retained RA, MLD or DHCPv6 relay child state");

  // A connected/static RIB cannot regenerate an OSPF-owned row without
  // advancing protocol state. Validate the exact subset rule separately from
  // the unmodified whole-lab checkpoint restored below.
  auto base_fib = control_a->selected_rib;
  auto protocol_fib = base_fib;
  require(
      base_fib.count > 0U && base_fib.count < base_fib.routes.size(),
      "dynamic-route restore fixture has no FIB capacity");
  auto protocol_route = base_fib.routes[base_fib.count - 1U];
  protocol_route.network = 0xcb007100U;
  protocol_route.prefix_length = 24U;
  protocol_route.preference = 10U;
  protocol_route.metric = 20U;
  protocol_route.source = routing::RouteSource::ospf;
  protocol_fib.routes[protocol_fib.count++] = protocol_route;
  require(checkpoint_validation::base_fib_preserved(base_fib, protocol_fib),
          "checkpoint validation rejected an OSPF-owned FIB extension");
  protocol_fib.routes[protocol_fib.count - 1U].source =
      routing::RouteSource::static_route;
  require(!checkpoint_validation::base_fib_preserved(base_fib, protocol_fib),
          "checkpoint validation accepted an unexplained static FIB row");

  // Configuration presentation retains address insertion order, while the
  // forwarding table sorts by interface and primary preference. A checkpoint
  // is valid when those owners contain the same generation even if their
  // vector orders differ. Reverse the control copy without touching the
  // network-owned canonical copy to reproduce a real multi-interface browser
  // checkpoint that previously failed restore.
  std::reverse(control_a->native_ipv6_addresses.begin(),
               control_a->native_ipv6_addresses.end());

  // Restore the semantically unchanged pre-removal image so the remainder of
  // this integration fixture continues from the validated four-router path.
  require(runtime->restore(std::move(*path_checkpoint)),
          "pre-removal checkpoint did not restore the validated path");

  const auto host_a = runtime->create_host("host-a", "Host A");
  const auto host_b = runtime->create_host("host-b", "Host B");
  require(host_a && host_b, "reference path host creation failed");
  require(runtime->create_link("host-a-a", {node(*host_a), "eth0"},
                               {node(*a), "1/1/2"},
                               std::chrono::nanoseconds{100}) &&
              runtime->create_link("d-host-b", {node(*d), "1/1/2"},
                                   {node(*host_b), "eth0"},
                                   std::chrono::nanoseconds{100}),
          "reference path host links failed");
  const router::packet::Mac edge_a{0x02, 0, 0, 0, 0x0a, 2};
  const router::packet::Mac edge_d{0x02, 0, 0, 0, 0x0d, 2};
  const router::packet::Mac endpoint_a{0x02, 0, 0, 0, 0xaa, 1};
  const router::packet::Mac endpoint_b{0x02, 0, 0, 0, 0xbb, 1};
  require(runtime->configure_interface(*a, "1/1/2", edge_a, 0xc0000201U, 30,
                                       true) &&
              runtime->configure_interface(*d, "1/1/2", edge_d, 0xc6336401U, 30,
                                           true) &&
              runtime->configure_host(*host_a, endpoint_a, {192, 0, 2, 2}, 30,
                                      {192, 0, 2, 1}, 1500, 0, false, {},
                                      transport_secret(1U)) &&
              runtime->configure_host(*host_b, endpoint_b, {198, 51, 100, 2},
                                      30, {198, 51, 100, 1}, 1500, 0, false, {},
                                      transport_secret(2U)),
          "reference path edge configuration failed");
  require(runtime->add_static_route(*a, 0xc6336400U, 30, 0x0a000c02U) &&
              runtime->add_static_route(*b, 0xc0000200U, 30, 0x0a000c01U) &&
              runtime->add_static_route(*b, 0xc6336400U, 30, 0x0a001702U) &&
              runtime->add_static_route(*c, 0xc0000200U, 30, 0x0a001701U) &&
              runtime->add_static_route(*c, 0xc6336400U, 30, 0x0a002202U) &&
              runtime->add_static_route(*d, 0xc0000200U, 30, 0x0a002201U),
          "reference path host routes failed");

  require(runtime->start_host_ping(*host_a, {198, 51, 100, 2}, 88),
          "Host A asynchronous ping did not start");
  for (std::size_t turn = 0;
       turn < 500 && !runtime->host_ping_reply(*host_a, 88); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->host_ping_reply(*host_a, 88),
          "Host A to four routers to Host B ping did not complete");

  const auto session = runtime->create_session(*a, "a-console-1");
  require(session &&
              runtime->enter_session_mode(*session,
                                          CandidateMode::private_candidate) ==
                  SessionWorkflowResult::applied &&
              runtime->record_session_edit(*session, 0xabcU) ==
                  SessionWorkflowResult::applied,
          "supervisor checkpoint fixture could not stage a private session");
  auto checkpoint = runtime->checkpoint();
  require(checkpoint && checkpoint->devices.entries.size() == 4 &&
              checkpoint->hosts.entries.size() == 2 &&
              checkpoint->topology.entries.size() == 5 &&
              checkpoint->network.fabric.links.size() == 5,
          "supervisor barrier omitted part of the laboratory graph");

  // Exercise the binary ABI with a genuinely incomplete IPv4 datagram rather
  // than only an empty reassembly vector. The receipt bitmap contains a hole,
  // proving payload bytes and arrival state remain independent during encode
  // and decode. Fragment zero has not arrived, so no synthetic frame is stored.
  router::packet::Ipv4ReassemblyCheckpoint incomplete4{
      .source = {203U, 0U, 113U, 9U},
      .destination = {198U, 51U, 100U, 2U},
      .payload = {0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U,
                  0x19U, 0x1aU, 0x1bU},
      .received = {0x0fU, 0x05U},
      .remaining_nanoseconds = 1'500'000'000LL,
      .identification = 0x4a31U,
      .final_size = 0U,
      .protocol = router::packet::ipv6_next_header_udp,
      .have_first = false,
      .have_last = false};
  checkpoint->network.hosts.front().endpoint.ipv4_reassembly.push_back(
      incomplete4);
  // Exercise the variable DNS graph independently of service configuration.
  // The intentionally socketless fixture is removed after decoding because it
  // is a codec value, not a valid live authoritative endpoint.
  checkpoint->network.hosts.front()
      .dns = router::dns::EndpointServiceCheckpoint{
      .resolver = std::nullopt,
      .resolver_ipv4_socket = std::nullopt,
      .resolver_ipv6_socket = std::nullopt,
      .transactions = {},
      .pending_query = {},
      .resolver_tcp_connections = {},
      .zones = {{.origin = dns_name("checkpoint.test."),
                 .records = {{.owner = dns_name("checkpoint.test."),
                              .type = router::packet::dns::type_a,
                              .record_class =
                                  router::packet::dns::internet_class,
                              .ttl = 60U,
                              .rdata = {192U, 0U, 2U, 9U}}}}},
      .signed_zones =
          {{.origin = dns_name("signed.checkpoint.test."),
            .unsigned_records = {{.owner = dns_name("signed.checkpoint.test."),
                                  .type = router::packet::dns::type_a,
                                  .record_class =
                                      router::packet::dns::internet_class,
                                  .ttl = 60U,
                                  .rdata = {192U, 0U, 2U, 10U}}},
            .keys = {.next_id = 2U,
                     .keys = {{.id = 1U,
                               .role = router::dnssec::KeyRole::zone_signing,
                               .schedule = {.publish_at = 100U,
                                            .ready_at = 100U,
                                            .activate_at = 100U,
                                            .retire_at = 200U,
                                            .dead_at = 300U,
                                            .remove_at = 400U},
                               .algorithm = 15U,
                               .public_key = {1U},
                               .sealed_private_key = {2U}}}},
            .policy = {.dnskey_ttl = 60U,
                       .denial_ttl = 60U,
                       .denial_mode = router::dnssec::DenialMode::nsec,
                       .timing = {.validity_seconds = 100U,
                                  .refresh_seconds = 30U,
                                  .resign_seconds = 10U,
                                  .inception_offset_seconds = 5U}},
            .statistics = {.generation = 7U,
                           .successful_refreshes = 7U,
                           .failed_refreshes = 1U,
                           .last_success_wall_seconds = 120U,
                           .signature_expiration_wall_seconds = 220U},
            .next_visit_remaining_nanoseconds = 1000}},
      .authoritative_ipv4_socket = std::nullopt,
      .authoritative_ipv6_socket = std::nullopt,
      .authoritative_ipv4_listener = std::nullopt,
      .authoritative_ipv6_listener = std::nullopt,
      .authoritative_tcp_connections = {},
      .pending_response = {},
      .recursive_udp_clients = {},
      .recursive_service_enabled = false};
  const auto tls_fixture = checkpoint_tls_configuration();
  const auto ipsec_fixture = checkpoint_ipsec_configuration();
  // Running intent, shared candidate and private candidate are independent
  // owners. RuntimeSupervisor alone does not own their portable management
  // projections, so this codec test adds the same value records that
  // LabRuntime contributes at its barrier. This exercises all three wire
  // locations without inventing a second management owner in the supervisor.
  PortableConfigurationCheckpoint global_candidate;
  global_candidate.system_name = "tls-global";
  global_candidate.tls = tls_fixture;
  global_candidate.ipsec = ipsec_fixture;
  checkpoint->portable_routers.push_back(
      {.device = *a,
       .ports = {},
       .interfaces = {},
       .routes = {},
       .ipv6_routes = {},
       .mld = {},
       .mld_prefix_lists = {},
       .mld_import_policies = {},
       .tls = tls_fixture,
       .ipsec = ipsec_fixture,
       .ies = {},
       .ospf = {},
       .global_candidate = std::move(global_candidate),
       .global_candidate_initialized = true,
       .port_seen_operational = {},
       .active_facility_alarms = {},
       .cleared_facility_alarms = {},
       .next_facility_alarm_index = 1U,
       .cleared_facility_alarms_wrapped = false});
  PortableConfigurationCheckpoint private_candidate;
  private_candidate.system_name = "tls-private";
  private_candidate.tls = tls_fixture;
  auto partial_ipsec_fixture = ipsec_fixture;
  // An MD candidate may contain the first mandatory leaf of a range while the
  // operator is still entering the second. ABI 6 must preserve that exact
  // candidate, although the same value is correctly rejected as running
  // intent by the commit validator.
  auto &partial_selector =
      partial_ipsec_fixture.traffic_selector_lists[0].local[0];
  partial_selector.range_begin = partial_selector.prefix->network;
  partial_selector.range_end.reset();
  partial_selector.prefix.reset();
  require(router::ipsec::configuration::validate(partial_ipsec_fixture, true) &&
              !router::ipsec::configuration::validate(partial_ipsec_fixture),
          "partial traffic selector did not distinguish candidate validation");
  private_candidate.ipsec = partial_ipsec_fixture;
  PortableConfigurationCheckpoint classic_policy_candidate;
  classic_policy_candidate.system_name = "router";
  const auto checkpoint_policy_prefix =
      router::ip::parse_ip_prefix("203.0.113.0/24");
  require(checkpoint_policy_prefix.has_value(),
          "classic policy checkpoint fixture prefix was invalid");
  classic_policy_candidate.mld_prefix_lists.push_back(
      {.name = "CLASSIC-CHECKPOINT", .prefixes = {*checkpoint_policy_prefix}});
  classic_policy_candidate.mld_import_policies.push_back(
      {.name = "CLASSIC-CHECKPOINT-POLICY",
       .entries = {{.number = 10U,
                    .group_prefix_list = "CLASSIC-CHECKPOINT",
                    .source_address = std::nullopt,
                    .source_prefix_list = {},
                    .action = router::mld::ImportPolicyAction::drop,
                    .action_configured = true,
                    .protocol_mld = true,
                    .route_prefix_list = {},
                    .route_source = std::nullopt,
                    .protocol_instance = std::nullopt,
                    .route_tag = std::nullopt,
                    .set_metric = std::nullopt,
                    .set_metric_type = std::nullopt,
                    .set_route_tag = std::nullopt}},
       .default_action = router::mld::ImportPolicyAction::accept,
       .default_action_configured = true});
  checkpoint->portable_session_candidates.push_back(
      {.session = *session,
       .candidate = std::move(private_candidate),
       .initialized = true,
       // Classic policy editing is an independent transaction. Keeping a
       // nonempty edit active proves that restart does not silently publish,
       // abort or replace it with the ordinary private MD candidate.
       .classic_policy_candidate = classic_policy_candidate,
       .classic_policy_edit_active = true});
  const auto bytes = checkpoint_v7::encode(*checkpoint);
  auto decoded = checkpoint_v7::decode(bytes);
  require(decoded && bytes.size() > 64 &&
              decoded->network.hosts.front().endpoint.ipv4_reassembly.size() ==
                  1U &&
              decoded->network.hosts.front()
                      .endpoint.ipv4_reassembly.front()
                      .payload == incomplete4.payload &&
              decoded->network.hosts.front()
                      .endpoint.ipv4_reassembly.front()
                      .received == incomplete4.received &&
              decoded->network.hosts.front()
                      .endpoint.ipv4_reassembly.front()
                      .identification == incomplete4.identification &&
              decoded->network.hosts.front().dns &&
              decoded->network.hosts.front().dns->zones.size() == 1U &&
              decoded->network.hosts.front().dns->signed_zones.size() == 1U &&
              decoded->network.hosts.front()
                      .dns->signed_zones.front()
                      .statistics.generation == 7U &&
              decoded->network.hosts.front()
                      .dns->zones.front()
                      .records.front()
                      .rdata == std::vector<std::uint8_t>({192U, 0U, 2U, 9U}) &&
              std::find_if(decoded->portable_routers.begin(),
                           decoded->portable_routers.end(),
                           [&](const auto &entry) {
                             return entry.device == *a &&
                                    entry.tls == tls_fixture &&
                                    entry.ipsec == ipsec_fixture &&
                                    entry.global_candidate.tls == tls_fixture &&
                                    entry.global_candidate.ipsec ==
                                        ipsec_fixture;
                           }) != decoded->portable_routers.end() &&
              std::find_if(
                  decoded->portable_session_candidates.begin(),
                  decoded->portable_session_candidates.end(),
                  [&](const auto &entry) {
                    return entry.session == *session &&
                           entry.candidate.tls == tls_fixture &&
                           entry.candidate.ipsec == partial_ipsec_fixture &&
                           entry.classic_policy_edit_active &&
                           entry.classic_policy_candidate.mld_prefix_lists ==
                               classic_policy_candidate.mld_prefix_lists &&
                           entry.classic_policy_candidate.mld_import_policies ==
                               classic_policy_candidate.mld_import_policies;
                  }) != decoded->portable_session_candidates.end(),
          "checkpoint ABI 6 did not round-trip the value graph");
  auto corrupted = bytes;
  corrupted[0] ^= 0x5aU;
  require(!checkpoint_v7::decode(corrupted),
          "checkpoint ABI 6 accepted corrupted family magic");
  decoded->network.hosts.front().dns.reset();
  // The two portable entries above belong to LabRuntime in production. Remove
  // the codec-only projection before asking the lower-level supervisor to
  // restore its own state graph.
  decoded->portable_routers.clear();
  decoded->portable_session_candidates.clear();

  // Destroying releases the only packet and capture arenas. The checkpoint
  // owns encoded values, not references into those arenas.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->restore(std::move(*decoded)) && runtime->devices().get(*a) &&
              runtime->hosts().get(*host_a) &&
              runtime->topology().size() == 5 &&
              runtime->session_status(*session)->candidate_dirty,
          "whole-lab checkpoint did not restore identities and owner state");
  require(runtime->start_host_ping(*host_a, {198, 51, 100, 2}, 89),
          "restored whole lab could not start endpoint traffic");
  for (std::size_t turn = 0;
       turn < 500 && !runtime->host_ping_reply(*host_a, 89); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->host_ping_reply(*host_a, 89),
          "restored whole lab did not preserve multi-hop forwarding state");
  require(runtime->start_router_ipv6_ping(*a, ipv6("2001:db8:cd::1"), 79),
          "restored whole lab could not start IPv6 traffic");
  for (std::size_t turn = 0;
       turn < 500 && !runtime->router_ipv6_ping_reply(*a, 79); ++turn)
    std::this_thread::sleep_for(std::chrono::milliseconds{1});
  require(runtime->router_ipv6_ping_reply(*a, 79),
          "checkpoint lost IPv6 RIB, FIB or Neighbor Cache state");

  // Removal is a real control-to-forwarding transaction. Repeating it must
  // fail explicitly instead of acknowledging an already absent route or
  // interface as a successful no-op.
  require(runtime->remove_static_route(*a, 0xc6336400U, 30) &&
              !runtime->remove_static_route(*a, 0xc6336400U, 30) &&
              runtime->remove_interface(*a, "1/1/1") &&
              !runtime->remove_interface(*a, "1/1/1"),
          "route or interface removal was not exact and idempotence-safe");

  auto invalid = runtime->checkpoint();
  require(static_cast<bool>(invalid),
          "supervisor could not prepare invalid-import fixture");
  invalid->devices.generations[a->index] = 0;
  require(!runtime->restore(std::move(*invalid)) &&
              runtime->devices().get(*a) && runtime->active_links() == 5,
          "failed whole-lab import partially changed the active laboratory");

  const auto before_failure = runtime->checkpoint();
  require(static_cast<bool>(before_failure),
          "failure-isolation baseline checkpoint was unavailable");
  const auto fib_generation = [](const RuntimeSupervisorCheckpoint &state,
                                 DeviceHandle device) {
    const auto found = std::find_if(
        state.network.routers.begin(), state.network.routers.end(),
        [&](const auto &router) { return router.device == device; });
    return found == state.network.routers.end()
               ? std::uint64_t{}
               : found->forwarding.fib.generation;
  };
  const auto a_before = fib_generation(*before_failure, *a);
  const auto b_before = fib_generation(*before_failure, *b);
  const auto c_before = fib_generation(*before_failure, *c);
  const auto d_before = fib_generation(*before_failure, *d);
  require(runtime->delete_link(*bc),
          "middle-link failure transaction was rejected");
  const auto after_failure = runtime->checkpoint();
  require(after_failure && fib_generation(*after_failure, *a) == a_before &&
              fib_generation(*after_failure, *d) == d_before &&
              fib_generation(*after_failure, *b) > b_before &&
              fib_generation(*after_failure, *c) > c_before,
          "middle-link failure rebuilt an unrelated router FIB");

  // Exercise the complete control-owned IES graph on a separate runtime. A
  // null SAP uses the ordinary untagged access wire, but still has a logical
  // interface identity distinct from physical ordinal zero. The lower-level
  // forwarder test covers dot1q wire insertion and exact VID rejection.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  const auto service_router =
      runtime->create_router("ies-router", "7750-sr-1", "IES-R1");
  const auto service_host = runtime->create_host("ies-host", "IES host");
  require(service_router && service_host,
          "IES runtime fixture could not create its endpoints");
  require(
      runtime->configure_port(*service_router, "1/1/1", true,
                              router::device_catalog::default_network_mtu,
                              100'000U) == HardwareEditResult::applied &&
          static_cast<bool>(runtime->create_link(
              "ies-access", {node(*service_router), "1/1/1"},
              {node(*service_host), "eth0"}, std::chrono::nanoseconds{100})) &&
          runtime->active_links() == 1U,
      "IES runtime fixture could not establish physical carrier");

  router::service::Configuration ies_configuration;
  ies_configuration.access_node_identifier = "ies-router";
  const router::service::PhysicalPortCoordinate ies_coordinate{
      .ordinal = 0U, .card = 1U, .mda = 1U, .port = 1U};
  ies_configuration.ports.push_back(
      {.coordinate = ies_coordinate,
       .mode = router::service::EthernetPortMode::access,
       .encapsulation = router::service::EthernetEncapsulation::null,
       .outer_tpid = 0U});
  ies_configuration.customers.push_back(
      {.name = "1",
       .customer_id = 1U,
       .description = "IES checkpoint customer"});
  router::service::IesInterfaceConfiguration ies_interface;
  ies_interface.logical_id = 60'001U;
  ies_interface.name = "access-v6";
  ies_interface.description = "Untagged IPv6 access";
  ies_interface.sap = {.port = ies_coordinate,
                       .encapsulation =
                           router::service::EthernetEncapsulation::null};
  ies_interface.mac = {0x02U, 0U, 0U, 0U, 0x60U, 1U};
  ies_interface.address = ipv6("2001:db8:60::1");
  ies_interface.link_local = ipv6("fe80::6001");
  ies_interface.prefix_length = 64U;
  ies_interface.ip_mtu = 1500U;
  ies_interface.address_configured = true;
  ies_interface.admin_enabled = true;
  ies_interface.dhcpv6_relay.configured = true;
  ies_interface.dhcpv6_relay.admin_enabled = true;
  ies_interface.dhcpv6_relay.neighbor_resolution = true;
  ies_interface.dhcpv6_relay.source_address = ies_interface.address;
  ies_interface.dhcpv6_relay.servers.push_back(
      {.address = ipv6("2001:db8:ffff::53")});
  ies_interface.dhcpv6_relay.interface_id_kind =
      router::service::RelayInterfaceIdKind::ascii_tuple;
  router::service::IesConfiguration ies_service{.service_id = 60U,
                                                .customer_id = 1U,
                                                .name = "internet-v6",
                                                .description =
                                                    "IPv6 IES runtime fixture",
                                                .admin_enabled = true};
  ies_service.interfaces.push_back(std::move(ies_interface));
  ies_configuration.ies_services.push_back(std::move(ies_service));
  require(runtime->configure_ies_services(*service_router, ies_configuration),
          "RuntimeSupervisor rejected a valid complete IES generation");
  const auto published_ies = runtime->router_operational_state(*service_router);
  require(published_ies && published_ies->sap_attachments.size() == 1U &&
              published_ies->service_ipv6_interfaces.size() == 1U,
          "IES runtime did not publish its atomic SAP and IPv6 interface");
  require(published_ies->dhcpv6_relay_interfaces.size() == 1U,
          "IES runtime did not publish its DHCPv6 relay child");
  require(wait_for(
              [&] {
                const auto state =
                    runtime->router_operational_state(*service_router);
                return state &&
                       std::any_of(
                           state->ipv6_dad.begin(), state->ipv6_dad.end(),
                           [&](const auto &dad) {
                             return dad.interface_id == 60'001U &&
                                    dad.address == ipv6("2001:db8:60::1") &&
                                    dad.state == Ipv6DadState::preferred;
                           });
              },
              std::chrono::seconds{5}),
          "IES runtime service address did not complete DAD");
  auto ies_checkpoint = runtime->checkpoint();
  require(static_cast<bool>(ies_checkpoint),
          "IES runtime checkpoint was unavailable");
  const auto ies_checkpoint_bytes = checkpoint_v7::encode(*ies_checkpoint);
  auto decoded_ies_checkpoint = checkpoint_v7::decode(ies_checkpoint_bytes);
  require(static_cast<bool>(decoded_ies_checkpoint),
          "IES control graph did not survive checkpoint ABI 6 encoding");
  require(decoded_ies_checkpoint->control.size() == 1U &&
              decoded_ies_checkpoint->control.front().ies_port_owned[0U],
          "IES physical-port ownership did not survive checkpoint ABI 6");
  require(decoded_ies_checkpoint->network.routers.size() == 1U &&
              RouterForwarder::validate_checkpoint(
                  decoded_ies_checkpoint->network.routers.front().forwarding),
          "IES forwarding image is not independently restorable");
  // RouterForwarder contains fixed packet arenas sized for production and is
  // intentionally heap-resident in Wasm. Keeping this probe on the heap also
  // verifies restore without exceeding the one MiB worker stack.
  auto restored_ies_forwarder_probe = std::make_unique<RouterForwarder>();
  require(restored_ies_forwarder_probe->restore(
              decoded_ies_checkpoint->network.routers.front().forwarding,
              RouterForwarder::Clock::now()),
          "IES forwarding owner rejected its validated checkpoint image");
  // Free the active supervisor's worker pair before starting a standalone
  // NetworkPlane probe. Browser Wasm uses a fixed pthread pool, so overlapping
  // owners would test worker-pool exhaustion rather than checkpoint validity.
  runtime.reset();
  auto restored_ies_network_probe = std::make_unique<NetworkPlane>(2U);
  require(decoded_ies_checkpoint->network.hosts.size() == 1U,
          "IES network checkpoint lost its access host");
  auto router_only_network = std::make_unique<NetworkPlaneCheckpoint>();
  router_only_network->routers = decoded_ies_checkpoint->network.routers;
  require(restored_ies_network_probe->restore(*router_only_network,
                                              NetworkPlane::Clock::now()),
          "IES router cannot be restored inside NetworkPlane");
  auto host_only_network = std::make_unique<NetworkPlaneCheckpoint>();
  host_only_network->hosts = decoded_ies_checkpoint->network.hosts;
  require(restored_ies_network_probe->restore(*host_only_network,
                                              NetworkPlane::Clock::now()),
          "IES access host cannot be restored inside NetworkPlane");
  require(restored_ies_network_probe->restore(decoded_ies_checkpoint->network,
                                              NetworkPlane::Clock::now()),
          "IES network plane rejected its validated forwarding image");
  restored_ies_network_probe.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->restore(std::move(*decoded_ies_checkpoint)),
          "portable restore rejected the active IES generation");
  const auto restored_ies = runtime->router_operational_state(*service_router);
  require(restored_ies && restored_ies->sap_attachments.size() == 1U &&
              restored_ies->service_ipv6_interfaces.size() == 1U &&
              restored_ies->dhcpv6_relay_interfaces.size() == 1U,
          "portable restore lost IES, SAP or DHCPv6 relay ownership");

  // Exercise the public control-plane bridge separately from the deterministic
  // NetworkPlane test. The supervisor serializes every vector element through
  // fixed SPSC messages, while its forwarding worker owns the reconstructed
  // service program. Real steady-clock waiting below permits link-local DAD,
  // Solicit delay and all four DHCPv6 messages to run on their normal threads.
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  const auto dhcp_client_host =
      runtime->create_host("dhcp-client", "DHCPv6 client");
  const auto dhcp_server_host =
      runtime->create_host("dhcp-server", "DHCPv6 server");
  require(dhcp_client_host && dhcp_server_host,
          "DHCPv6 supervisor fixture could not create hosts");
  require(static_cast<bool>(runtime->create_link(
              "dhcp-wire", {node(*dhcp_client_host), "eth0"},
              {node(*dhcp_server_host), "eth0"}, std::chrono::nanoseconds{100},
              true, 10'000U)),
          "DHCPv6 supervisor fixture could not create a physical link");
  require(runtime->active_links() == 1U,
          "DHCPv6 supervisor fixture link has no physical carrier");

  const router::packet::Mac dhcp_client_mac{0x02, 0, 0, 0, 0xdc, 1};
  const router::packet::Mac dhcp_server_mac{0x02, 0, 0, 0, 0xdc, 2};
  require(runtime->configure_host(*dhcp_client_host, dhcp_client_mac,
                                  {203, 0, 113, 1}, 30, {203, 0, 113, 2}, 1500,
                                  301U, true, {}, transport_secret(3U)) &&
              runtime->configure_host(
                  *dhcp_server_host, dhcp_server_mac, {203, 0, 113, 2}, 30,
                  {203, 0, 113, 1}, 1500, 302U, true, {}, transport_secret(4U)),
          "DHCPv6 supervisor fixture rejected dual-stack host interfaces");

  // Production DHCP starts after the interface has a usable link-local
  // address. Waiting for both DAD owners here mirrors an operating system
  // service dependency and makes a failure distinguish protocol exchange from
  // IPv6 interface initialization. No synthetic time is injected.
  bool both_link_locals_ready{};
  for (std::size_t turn = 0; turn < 120U && !both_link_locals_ready; ++turn) {
    std::this_thread::sleep_for(std::chrono::milliseconds{50});
    const auto state = runtime->checkpoint();
    if (!state)
      continue;
    both_link_locals_ready =
        state->network.hosts.size() == 2U &&
        std::all_of(state->network.hosts.begin(), state->network.hosts.end(),
                    [](const auto &host) {
                      return std::any_of(
                          host.endpoint.ipv6.dad.begin(),
                          host.endpoint.ipv6.dad.end(), [](const auto &dad) {
                            return dad.state == Ipv6DadState::preferred;
                          });
                    });
  }
  require(both_link_locals_ready,
          "DHCPv6 supervisor fixture did not complete link-local DAD");

  HostDhcpv6ServerProgram server_program{.host = *dhcp_server_host,
                                         .configuration = {},
                                         .address_pools = {},
                                         .prefix_pools = {},
                                         .decline_hold_time =
                                             std::chrono::hours{1}};
  constexpr std::array<std::uint8_t, 7U> supervisor_server_duid{
      0U, 3U, 0U, 1U, 0xdcU, 2U, 1U};
  std::copy(supervisor_server_duid.begin(), supervisor_server_duid.end(),
            server_program.configuration.duid.begin());
  server_program.configuration.duid_octets = supervisor_server_duid.size();
  const auto supervisor_pool =
      router::ip::parse_ipv6_prefix("2001:db8:dc::/64");
  require(supervisor_pool.has_value(),
          "DHCPv6 supervisor fixture pool is invalid");
  server_program.address_pools.push_back({.prefix = *supervisor_pool,
                                          .preferred_lifetime_seconds = 3600U,
                                          .valid_lifetime_seconds = 7200U,
                                          .t1_seconds = 1800U,
                                          .t2_seconds = 2880U});
  for (std::size_t index = 0;
       index < server_program.address_pools.front().allocation_secret.size();
       ++index) {
    // A stable nonzero pool secret is configuration state, not protocol data.
    // It makes address allocation deterministic across checkpoint restore
    // without assigning the client a hardcoded address.
    server_program.address_pools.front().allocation_secret[index] =
        static_cast<std::uint8_t>(index + 11U);
  }

  HostDhcpv6ClientProgram client_program{.host = *dhcp_client_host,
                                         .configuration = {},
                                         .information_only = false};
  constexpr std::array<std::uint8_t, 7U> supervisor_client_duid{
      0U, 3U, 0U, 1U, 0xdcU, 1U, 1U};
  std::copy(supervisor_client_duid.begin(), supervisor_client_duid.end(),
            client_program.configuration.duid.begin());
  client_program.configuration.duid_octets = supervisor_client_duid.size();
  client_program.configuration.identity_associations.push_back(
      {.iaid = 0xdc010001U, .kind = router::dhcpv6::LeaseKind::non_temporary});
  for (std::size_t index = 0;
       index < client_program.configuration.transaction_secret.size();
       ++index) {
    client_program.configuration.transaction_secret[index] =
        static_cast<std::uint8_t>(0x80U + index);
  }

  require(runtime->configure_host_dhcpv6_server(server_program) &&
              runtime->configure_host_dhcpv6_client(client_program),
          "RuntimeSupervisor rejected streamed DHCPv6 service programs");
  for (std::size_t turn = 0;
       turn < 700U && runtime->host_dhcpv6_client_lease_count(*dhcp_client_host)
                              .value_or(0U) == 0U;
       ++turn) {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  require(
      runtime->host_dhcpv6_client_lease_count(*dhcp_client_host).value_or(0U) ==
          1U,
      "threaded DHCPv6 exchange did not cross the encoded fabric path");

  // The public supervisor path adds another pthread boundary above
  // NetworkPlane. Configure a managed zone here so a passing module-only DNS
  // test cannot conceal a missing production command or an unsealed restore.
  std::array<std::uint8_t, 32U> supervisor_dnssec_key{};
  supervisor_dnssec_key.fill(0x7bU);
  const auto supervisor_dnssec_context = transport_secret(0x52U);
  require(runtime->initialize_signing_vault(supervisor_dnssec_key,
                                            supervisor_dnssec_context),
          "RuntimeSupervisor rejected DNSSEC project vault material");
  const auto dnssec_wall_now = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
  const router::dnssec::KeySchedule supervisor_dnssec_schedule{
      .publish_at = dnssec_wall_now - 60U,
      .ready_at = dnssec_wall_now - 60U,
      .activate_at = dnssec_wall_now - 60U,
      .retire_at = dnssec_wall_now + 3600U,
      .dead_at = dnssec_wall_now + 3660U,
      .remove_at = dnssec_wall_now + 3720U};
  auto supervisor_soa = dns_name_data("ns.supervisor.test.");
  const auto supervisor_mailbox = dns_name_data("hostmaster.supervisor.test.");
  supervisor_soa.insert(supervisor_soa.end(), supervisor_mailbox.begin(),
                        supervisor_mailbox.end());
  append_dns_u32(supervisor_soa, 1U);
  append_dns_u32(supervisor_soa, 3600U);
  append_dns_u32(supervisor_soa, 600U);
  append_dns_u32(supervisor_soa, 86400U);
  append_dns_u32(supervisor_soa, 60U);
  HostDnsSignedAuthoritativeProgram supervisor_signed_dns{
      .host = *dhcp_server_host,
      .zones = {{.zone =
                     {.origin = dns_name("supervisor.test."),
                      .records = {{.owner = dns_name("supervisor.test."),
                                   .type = router::packet::dns::type_soa,
                                   .record_class =
                                       router::packet::dns::internet_class,
                                   .ttl = 300U,
                                   .rdata = supervisor_soa},
                                  {.owner = dns_name("supervisor.test."),
                                   .type = router::packet::dns::type_ns,
                                   .record_class =
                                       router::packet::dns::internet_class,
                                   .ttl = 300U,
                                   .rdata =
                                       dns_name_data("ns.supervisor.test.")},
                                  {.owner = dns_name("ns.supervisor.test."),
                                   .type = router::packet::dns::type_aaaa,
                                   .record_class = router::packet::dns::internet_class,
                                   .ttl = 300U,
                                   .rdata = {0x20U,
                                             0x01U, 0x0dU, 0xb8U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x53U}}}},
                 .keys = {{.schedule = supervisor_dnssec_schedule,
                           .generation = {},
                           .role = router::dnssec::KeyRole::key_signing,
                           .algorithm = 15U},
                          {.schedule = supervisor_dnssec_schedule,
                           .generation = {},
                           .role = router::dnssec::KeyRole::zone_signing,
                           .algorithm = 15U}},
                 .policy = {.dnskey_ttl = 300U,
                            .denial_ttl = 60U,
                            .denial_mode = router::dnssec::DenialMode::nsec,
                            .timing = {.validity_seconds = 3600U,
                                       .refresh_seconds = 1200U,
                                       .resign_seconds = 600U,
                                       .inception_offset_seconds = 60U}}}},
      .wall_now = dnssec_wall_now};
  require(
      runtime->configure_host_dns_signed_authoritative(supervisor_signed_dns),
      "RuntimeSupervisor rejected streamed managed DNSSEC zone");
  require(
      runtime->configure_host_dns_resolver(
          {.host = *dhcp_client_host,
           .identifier_secret = transport_secret(0x62U),
           .root_hints = {{.server_name = dns_name("ns.supervisor.test."),
                           .addresses = {{.family =
                                              router::transport::IpFamily::ipv4,
                                          .ipv4 = {203U, 0U, 113U, 2U}}}}},
           .trust_anchors = {},
           .nsec3_policy = {},
           .serve_clients = false}),
      "RuntimeSupervisor rejected streamed recursive DNS program");

  // Encoding the whole runtime is essential here. An in-memory checkpoint can
  // accidentally hide a missing field in the portable checkpoint ABI.
  auto dhcp_checkpoint = runtime->checkpoint();
  require(static_cast<bool>(dhcp_checkpoint),
          "threaded DHCPv6 checkpoint was unavailable");
  const auto dhcp_checkpoint_bytes = checkpoint_v7::encode(*dhcp_checkpoint);
  auto decoded_dhcp_checkpoint = checkpoint_v7::decode(dhcp_checkpoint_bytes);
  require(static_cast<bool>(decoded_dhcp_checkpoint),
          "DHCPv6 state did not survive checkpoint ABI 6 encoding");
  runtime.reset();
  runtime = std::make_unique<RuntimeSupervisor>();
  require(runtime->initialize_signing_vault(supervisor_dnssec_key,
                                            supervisor_dnssec_context) &&
              runtime->restore(std::move(*decoded_dhcp_checkpoint)) &&
              runtime->host_dhcpv6_client_lease_count(*dhcp_client_host)
                      .value_or(0U) == 1U,
          "portable restore lost DHCPv6 or managed DNSSEC owner state");
}
