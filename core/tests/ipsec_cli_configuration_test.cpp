// IPsec CLI editor tests exercise the generated MD-CLI and classic syntax
// against one shared configuration model. The editor owns no live SA state;
// these tests therefore verify atomic intent, leafrefs, defaults and deletion
// constraints without creating forwarding or browser dependencies.

#include "../src/ipsec_cli_configuration.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using router::CliEngine;
using router::MdCliWorkflow;
using router::cli_detail::ParsedCommand;
using router::ipsec::configuration::Configuration;

class TestSecretSink final : public router::lab::ipsec_cli::SecretSink {
public:
  struct Record {
    router::lab::ipsec_cli::SecretKind kind{};
    std::vector<std::uint8_t> bytes;
  };

  std::optional<std::uint64_t>
  seal(router::lab::ipsec_cli::SecretKind kind,
       std::span<const std::uint8_t> plaintext) noexcept override {
    // Test storage intentionally remains local to this unit test. Production
    // supplies the authenticated-encryption vault owner and never exposes its
    // record bytes through configuration or telemetry.
    records.push_back({kind, {plaintext.begin(), plaintext.end()}});
    return next_handle++;
  }

  std::uint64_t next_handle{1U};
  std::vector<Record> records;
};

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

ParsedCommand parse(CliEngine engine, std::string_view text) {
  // MD edits require a candidate workflow. Classic ignores that workflow and
  // applies the same parsed intent immediately in the live runtime.
  const auto command = router::cli_detail::parse_command(
      engine, engine == CliEngine::md ? MdCliWorkflow::explicit_private
                                      : MdCliWorkflow::operational,
      text);
  require(command.has_value(), "generated IPsec command did not parse");
  return *command;
}

void edit(Configuration &state, CliEngine engine, std::string_view text,
          router::lab::ipsec_cli::SecretSink *secrets = nullptr) {
  const auto command = parse(engine, text);
  const auto result =
      router::lab::ipsec_cli::edit(state, command, engine, secrets);
  if (!result.recognized || !result.changed)
    throw std::runtime_error("parsed IPsec command did not change: " +
                             std::string{text});
  require(router::ipsec::configuration::validate(
              state, engine == CliEngine::md),
          "IPsec command produced invalid canonical configuration");
}

} // namespace

void ipsec_cli_configuration_tests() {
  using namespace router;
  using namespace router::ipsec::configuration;

  Configuration state;
  TestSecretSink vault;
  edit(state, CliEngine::md,
       "configure ipsec ike-transform 19 dh-group group-19");
  edit(state, CliEngine::md,
       "configure ipsec ike-transform 19 ike-auth-algorithm auth-encryption");
  edit(state, CliEngine::md,
       "configure ipsec ike-transform 19 ike-encryption-algorithm "
       "aes256-gcm16");
  edit(state, CliEngine::md,
       "configure ipsec ike-transform 19 ike-prf-algorithm sha-256");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transform 7 esp-auth-algorithm "
       "auth-encryption");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transform 7 esp-encryption-algorithm "
       "aes192-gcm16");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate admin-state enable");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate entry 1 cert "
       "router-a.crt");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate entry 1 key "
       "router-a.key");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate entry 1 "
       "compare-chain-include cross-root");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate entry 1 "
       "rsa-signature pss");
  edit(state, CliEngine::md,
       "configure ipsec cert-profile router-certificate entry 1 send-chain "
       "ca-profile issuing-ca");
  edit(state, CliEngine::md,
       "configure ipsec trust-anchor-profile lab-roots trust-anchor root-ca");
  edit(state, CliEngine::md,
       "configure ipsec ppk-list post-quantum-keys ppk branch-a value ascii "
       "quantum-resistant-secret",
       &vault);
  edit(state, CliEngine::md,
       "configure ipsec ike-policy 4 ike-transform 19");
  edit(state, CliEngine::md,
       "configure ipsec ike-policy 4 dpd interval 45");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 1 address prefix "
       "2001:db8:1::/64");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 1 protocol id tcp "
       "port-range begin 443");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 1 protocol id tcp "
       "port-range end 443");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 address range "
       "begin 2001:db8:10::1");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 address range "
       "end 2001:db8:10::ffff");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range begin-icmp-type 128");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range begin-icmp-code 0");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range end-icmp-type 129");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range end-icmp-code 255");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 3 address prefix "
       "2001:db8:30::/64");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 3 protocol id udp "
       "opaque");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 4 address prefix "
       "2001:db8:40::/64");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 4 protocol id "
       "protocol-id-with-any-port 253");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 remote entry 1 address prefix "
       "2001:db8:2::/64");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic ike-policy 4");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic ipsec-transform 7");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic cert cert-profile router-certificate");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic cert status-verify default-result good");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic cert status-verify primary ocsp");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic cert status-verify secondary crl");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic cert trust-anchor-profile lab-roots");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic id fqdn router-a.example.test");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic ppk list post-quantum-keys");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic ppk id branch-a");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "key-exchange dynamic pre-shared-key transport-secret",
       &vault);
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "max-history-key-records esp 24");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "max-history-key-records ike 3");
  edit(state, CliEngine::md,
       "configure ipsec ipsec-transport-mode-profile gre-protected "
       "replay-window 128");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 ipsec-transform 7");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 description protected-branch");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 ppk-list post-quantum-keys");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 ip-mtu 1400");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 encapsulated-ip-mtu 1360");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 replay-window 512");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 pmtu-discovery-aging 1800");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 private-tcp-mss-adjust 1320");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 public-tcp-mss-adjust auto");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 icmp-generation frag-required "
       "admin-state disable");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 icmp-generation frag-required "
       "interval 20");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 icmp-generation frag-required "
       "message-count 50");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 icmp6-generation pkt-too-big "
       "interval 30");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 icmp6-generation pkt-too-big "
       "message-count 60");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 reverse-route metric 20");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 reverse-route preference 10");
  edit(state, CliEngine::md,
       "configure ipsec tunnel-template 10 sp-reverse-route "
       "use-security-policy");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth description control-plane");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth direction bidirectional");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth protocol ah");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth spi 4096");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth authentication algorithm sha1");
  edit(state, CliEngine::md,
       "configure ipsec static-sa ospf3-auth authentication key "
       "protected-manual-sa hash2",
       &vault);

  const auto *ike = find_ike(state, 19U);
  const auto *esp = find_ipsec(state, 7U);
  const auto *policy = find_policy(state, 4U);
  require(ike && esp && policy &&
              ike->encryption == AesGcmKeySize::aes256 &&
              esp->encryption == AesGcmKeySize::aes192 &&
              policy->ike_transforms == std::vector<std::uint16_t>{19U} &&
              policy->dpd_interval_seconds == 45U &&
              state.traffic_selector_lists.size() == 1U &&
              state.traffic_selector_lists[0].local.size() == 4U &&
              state.traffic_selector_lists[0].local[1].range_begin &&
              state.traffic_selector_lists[0].local[1].range_end &&
              state.traffic_selector_lists[0].local[1].protocol ==
                  SelectorProtocol::icmpv6 &&
              state.traffic_selector_lists[0].local[1].ports.first ==
                  0x8000U &&
              state.traffic_selector_lists[0].local[1].ports.last ==
                  0x81ffU &&
              state.traffic_selector_lists[0].local[2].opaque_ports &&
              state.traffic_selector_lists[0].local[3].protocol ==
                  SelectorProtocol::numeric &&
              state.traffic_selector_lists[0].local[3].numeric_protocol ==
                  253U &&
              state.transport_mode_profiles.size() == 1U &&
              state.certificate_profiles.size() == 1U &&
              state.certificate_profiles[0].enabled &&
              state.certificate_profiles[0].entries[0].rsa_signature ==
                  RsaSignature::pss &&
              state.trust_anchor_profiles.size() == 1U &&
              state.transport_mode_profiles[0].dynamic.certificate_profile ==
                  "router-certificate" &&
              state.transport_mode_profiles[0]
                      .dynamic.trust_anchor_profile == "lab-roots" &&
              state.transport_mode_profiles[0].dynamic.identity_type ==
                  IdentityType::fqdn &&
              state.transport_mode_profiles[0].dynamic.ppk_list ==
                  "post-quantum-keys" &&
              state.transport_mode_profiles[0].dynamic.ppk_id == "branch-a" &&
              state.transport_mode_profiles[0]
                      .dynamic.pre_shared_key_handle != 0U &&
              state.ppk_lists[0].entries[0].secret_handle != 0U &&
              state.static_sas.size() == 1U &&
              state.static_sas[0].spi == 4'096U &&
              state.static_sas[0].protocol ==
                  router::ipsec::SecurityProtocol::ah &&
              state.static_sas[0].authentication ==
                  StaticSaAuthentication::sha1 &&
              state.static_sas[0].authentication_key_handle != 0U &&
              vault.records.size() == 3U &&
              state.transport_mode_profiles[0].maximum_esp_history_records ==
                  24U &&
              state.transport_mode_profiles[0].maximum_ike_history_records ==
                  3U &&
              state.transport_mode_profiles[0].replay_window == 128U &&
              state.tunnel_templates.size() == 1U &&
              state.tunnel_templates[0].description == "protected-branch" &&
              state.tunnel_templates[0].ppk_list == "post-quantum-keys" &&
              state.tunnel_templates[0].ip_mtu == 1'400U &&
              state.tunnel_templates[0].encapsulated_ip_mtu == 1'360U &&
              state.tunnel_templates[0].replay_window == 512U &&
              state.tunnel_templates[0].private_tcp_mss_adjust == 1'320U &&
              state.tunnel_templates[0].public_tcp_mss_auto &&
              !state.tunnel_templates[0].ipv4_fragmentation_required.enabled &&
              state.tunnel_templates[0]
                      .ipv4_fragmentation_required.interval_seconds == 20U &&
              state.tunnel_templates[0]
                      .ipv6_packet_too_big.interval_seconds == 30U &&
              state.tunnel_templates[0].reverse_route_metric == 20U &&
              state.tunnel_templates[0].reverse_route_preference == 10U &&
              state.tunnel_templates[0].service_provider_reverse_route ==
                  ServiceProviderReverseRoute::use_security_policy,
          "MD IPsec edits lost transform or policy values");
  require(validate(state),
          "complete MD IPsec candidate did not satisfy running constraints");

  edit(state, CliEngine::md,
       "delete ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range end-icmp-code");
  require(!state.traffic_selector_lists[0]
               .local[1]
               .end_icmp_code_configured &&
              validate(state, true) && !validate(state),
          "MD leaf deletion did not retain an incomplete private candidate");
  edit(state, CliEngine::md,
       "configure ipsec ts-list protected-v6 local entry 2 protocol id icmp6 "
       "port-range end-icmp-code 255");

  const auto before = state;
  const auto invalid_reference = parse(
      CliEngine::md, "configure ipsec ike-policy 4 ike-transform 20");
  const auto rejected = router::lab::ipsec_cli::edit(
      state, invalid_reference, CliEngine::md);
  require(rejected.recognized && !rejected.changed && state == before,
          "missing IKE transform leafref was not rejected atomically");

  const auto delete_referenced =
      parse(CliEngine::md, "delete ipsec ike-transform 19");
  const auto protected_result = router::lab::ipsec_cli::edit(
      state, delete_referenced, CliEngine::md);
  require(protected_result.recognized && !protected_result.changed &&
              find_ike(state, 19U),
          "referenced IKE transform was deleted");

  Configuration classic;
  TestSecretSink classic_vault;
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 1 dh-group group-19");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 1 ike-prf-algorithm sha256");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 2 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 2 dh-group group-19");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-transform 2 ike-prf-algorithm sha256");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 ike-version 2");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 ike-transform 1 2");
  require(find_policy(classic, 1U)->ike_transforms ==
              std::vector<std::uint16_t>{1U, 2U},
          "classic compound IKE transform list lost its source order");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 ike-transform 2");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 description branch-policy");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 ikev2-fragment mtu 1280 "
       "reassembly-timeout 4");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 dpd interval 45 max-retries 4 "
       "reply-only");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 nat-traversal force "
       "keep-alive-interval 180 force-keep-alive");
  require(find_policy(classic, 1U)->ike_transforms ==
              std::vector<std::uint16_t>{2U},
          "classic IKE transform command appended instead of replacing");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 no ike-transform");
  require(find_policy(classic, 1U)->ike_transforms.empty(),
          "classic no ike-transform did not clear the whole reference list");
  edit(classic, CliEngine::classic,
       "configure ipsec ike-policy 1 ike-transform 2");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transform 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transform 1 esp-auth-algorithm "
       "auth-encryption");
  edit(classic, CliEngine::classic,
       "configure ipsec static-sa classic-manual create");
  edit(classic, CliEngine::classic,
       "configure ipsec static-sa classic-manual direction inbound");
  edit(classic, CliEngine::classic,
       "configure ipsec static-sa classic-manual protocol ah");
  edit(classic, CliEngine::classic,
       "configure ipsec static-sa classic-manual spi 8192");
  edit(classic, CliEngine::classic,
       "configure ipsec static-sa classic-manual authentication md5 "
       "ascii-key 0123456789abcdef",
       &classic_vault);
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate create");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate entry 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate entry 1 cert "
       "classic.crt");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate entry 1 key "
       "classic.key");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate entry 1 "
       "rsa-signature pss");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate entry 1 "
       "send-chain ca-profile issuing-ca");
  edit(classic, CliEngine::classic,
       "configure ipsec cert-profile classic-certificate no shutdown");
  edit(classic, CliEngine::classic,
       "configure ipsec trust-anchor-profile classic-roots create");
  edit(classic, CliEngine::classic,
       "configure ipsec trust-anchor-profile classic-roots trust-anchor "
       "root-ca");
  edit(classic, CliEngine::classic,
       "configure ipsec ppk-list classic-post-quantum create");
  edit(classic, CliEngine::classic,
       "configure ipsec ppk-list classic-post-quantum ppk-id branch-b value "
       "5155414e54554d format hex",
       &classic_vault);
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors create");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 1 address "
       "192.0.2.0/24");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 1 protocol "
       "udp port from 500 to 500");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 2 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 2 address "
       "from 2001:db8:20::1 to 2001:db8:20::ffff");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors local entry 2 protocol "
       "icmp6 port from 128/0 to 129/255");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors remote entry 2 create");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors remote entry 2 address "
       "2001:db8:50::/64");
  edit(classic, CliEngine::classic,
       "configure ipsec ts-list classic-selectors remote entry 2 protocol "
       "253 port any");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre create");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying ike-policy 1");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying transform 1");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre description "
       "classic-transport");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying auto-establish");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying cert cert-profile classic-certificate");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying cert status-verify default-result good");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying cert status-verify primary ocsp secondary crl");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying cert trust-anchor-profile classic-roots");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying local-id fqdn value classic.example.test");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying ppk list classic-post-quantum id branch-b");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "dynamic-keying pre-shared-key classic-transport-secret",
       &classic_vault);
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "max-history-esp-key-records 12");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "max-history-ike-key-records 2");
  edit(classic, CliEngine::classic,
       "configure ipsec ipsec-transport-mode-profile classic-gre "
       "replay-window 256");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 create");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 transform 1");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 description classic-branch");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 ppk-list classic-post-quantum");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 private-tcp-mss-adjust 1320");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 public-tcp-mss-adjust auto");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 clear-df-bit");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 copy-traffic-class-upon-decapsulation");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 no propagate-pmtu-v4");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp-generation frag-required");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp-generation frag-required "
       "interval 20");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp-generation frag-required "
       "message-count 50");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp6-generation pkt-too-big");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp6-generation pkt-too-big "
       "interval 30");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 icmp6-generation pkt-too-big "
       "message-count 60");
  edit(classic, CliEngine::classic,
       "configure ipsec tunnel-template 1 sp-reverse-route "
       "ignore-default-route");
  require(find_policy(classic, 1U)->ike_version2_configured,
          "classic IKEv2 selection was stored as a no-op");
  const auto *classic_policy = find_policy(classic, 1U);
  require(classic_policy && classic_policy->description == "branch-policy" &&
              classic_policy->fragmentation_configured &&
              classic_policy->fragmentation_mtu == 1'280U &&
              classic_policy->fragmentation_reassembly_timeout_seconds == 4U &&
              classic_policy->dpd_configured &&
              classic_policy->dpd_interval_seconds == 45U &&
              classic_policy->dpd_max_retries == 4U &&
              classic_policy->dpd_reply_only &&
              classic_policy->nat_traversal_configured &&
              classic_policy->nat_force &&
              classic_policy->nat_keepalive_interval_seconds == 180U &&
              classic_policy->nat_force_keepalive,
          "classic compound policy options were not applied atomically");
  require(classic.traffic_selector_lists[0].local[1].protocol ==
                  SelectorProtocol::icmpv6 &&
              classic.traffic_selector_lists[0].local[1].ports.first ==
                  0x8000U &&
              classic.traffic_selector_lists[0].local[1].ports.last ==
                  0x81ffU &&
              classic.traffic_selector_lists[0].remote[0].protocol ==
                  SelectorProtocol::numeric &&
              classic.traffic_selector_lists[0].remote[0].numeric_protocol ==
                  253U &&
              classic.certificate_profiles[0].enabled &&
              classic.certificate_profiles[0].entries[0].rsa_signature ==
                  RsaSignature::pss &&
              classic.transport_mode_profiles[0].description ==
                  "classic-transport" &&
              classic.transport_mode_profiles[0].dynamic.auto_establish &&
              classic.transport_mode_profiles[0]
                      .dynamic.default_revocation_result ==
                  RevocationResult::good &&
              classic.transport_mode_profiles[0]
                      .dynamic.primary_revocation_method ==
                  RevocationMethod::ocsp &&
              classic.transport_mode_profiles[0]
                      .dynamic.secondary_revocation_method ==
                  RevocationMethod::crl &&
              classic.transport_mode_profiles[0].dynamic.ppk_id ==
                  "branch-b" &&
              classic.transport_mode_profiles[0]
                      .dynamic.pre_shared_key_handle != 0U &&
              classic.transport_mode_profiles[0]
                      .maximum_esp_history_records == 12U &&
              classic.transport_mode_profiles[0]
                      .maximum_ike_history_records == 2U &&
              classic.transport_mode_profiles[0].replay_window == 256U &&
              classic.static_sas.size() == 1U &&
              classic.static_sas[0].spi == 8'192U &&
              classic.static_sas[0].direction ==
                  StaticSaDirection::inbound &&
              classic.static_sas[0].authentication_key_format ==
                  StaticSaKeyFormat::ascii &&
              classic_vault.records.size() == 3U &&
              classic.tunnel_templates[0].description ==
                              "classic-branch" &&
              classic.tunnel_templates[0].ppk_list ==
                  "classic-post-quantum" &&
              classic.tunnel_templates[0].public_tcp_mss_auto &&
              classic.tunnel_templates[0].clear_df_bit &&
              classic.tunnel_templates[0]
                  .copy_traffic_class_upon_decapsulation &&
              !classic.tunnel_templates[0].propagate_pmtu_v4 &&
              classic.tunnel_templates[0]
                      .ipv4_fragmentation_required.interval_seconds == 20U &&
              classic.tunnel_templates[0]
                      .ipv6_packet_too_big.interval_seconds == 30U &&
              classic.tunnel_templates[0].ignore_default_route &&
              classic.tunnel_templates[0].service_provider_reverse_route ==
                  ServiceProviderReverseRoute::use_security_policy,
          "classic selector address or protocol grammar lost wire values");
}
