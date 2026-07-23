#pragma once

// Generated release hardware catalog. The records contain only immutable
// profile metadata. Device registries own all selected and operational state.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace router::device_catalog {

struct TlsAlgorithmName {
  std::string_view sros;
  std::string_view openssl;
  bool pqc{};
};

// One release owns this entire generated catalog. Runtime capability output
// consumes this value instead of repeating the release pin in hand-written C++.
inline constexpr std::string_view release{"26.7.R1"};
inline constexpr std::uint64_t catalog_hash = 0x922379034b3dcf54ULL;
inline constexpr std::uint64_t checkpoint_schema_hash = 0xc14824cbb3c71b17ULL;
inline constexpr std::uint64_t runtime_protocol_hash = 0x0e4f799b5b5d2714ULL;
inline constexpr std::uint64_t build_hash = 0x7f8a23c2daaecae3ULL;

inline constexpr std::size_t maximum_routers = 16;
inline constexpr std::size_t maximum_hosts = 16;
inline constexpr std::size_t maximum_links = 64;
inline constexpr std::size_t maximum_sessions_per_router = 4;
inline constexpr std::size_t maximum_ports_per_router = 800;
inline constexpr std::size_t maximum_card_slots = 10;
inline constexpr std::size_t maximum_mda_slots_per_card = 2;
inline constexpr std::size_t maximum_ports_per_mda = 40;
inline constexpr std::size_t maximum_static_routes_per_router = 64;
inline constexpr std::uint16_t maximum_ecmp_paths = 128;
inline constexpr std::size_t maximum_fib_routes_per_router =
    maximum_ports_per_router + maximum_static_routes_per_router;
inline constexpr std::size_t wasm_initial_memory_bytes = 335544320U;
inline constexpr std::size_t wasm_maximum_memory_bytes = 1073741824U;
inline constexpr std::size_t wasm_growth_step_bytes = 67108864U;
inline constexpr std::size_t wasm_stack_bytes = 1048576U;
inline constexpr std::size_t packet_pool_bytes = 67108864U;
inline constexpr std::size_t terminal_output_arena_bytes = 16777216U;
inline constexpr std::size_t terminal_result_bytes = 1048576U;
inline constexpr std::size_t runtime_control_reserve_bytes = 41943040U;
inline constexpr std::size_t low_cpu_max = 4;
inline constexpr std::size_t medium_cpu_max = 8;
inline constexpr std::size_t low_control_shards = 1;
inline constexpr std::size_t medium_control_shards = 1;
inline constexpr std::size_t high_control_shards = 2;
inline constexpr std::size_t low_forwarding_shards = 1;
inline constexpr std::size_t medium_forwarding_shards = 2;
inline constexpr std::size_t high_forwarding_shards = 3;
inline constexpr std::size_t low_link_shards = 0;
inline constexpr std::size_t medium_link_shards = 1;
inline constexpr std::size_t high_link_shards = 1;
inline constexpr std::size_t maximum_worker_domains = 6;
inline constexpr std::size_t worker_startup_attempts = 200;
inline constexpr std::chrono::milliseconds worker_startup_poll{
    10};
inline constexpr std::chrono::milliseconds telemetry_publish_interval{
    250};
inline constexpr std::chrono::milliseconds recovery_checkpoint_interval{
    2000};
inline constexpr std::chrono::milliseconds continuity_loss_threshold{
    5000};
inline constexpr std::size_t link_queue_capacity = 256;
inline constexpr std::size_t fabric_work_budget_frames = 64;
inline constexpr std::chrono::nanoseconds immediate_link_deadline{
    74000};
inline constexpr std::size_t arp_entries_per_router = 4096;
inline constexpr std::size_t static_arp_entries_per_router = 1000;
inline constexpr std::size_t pending_ipv4_frames_per_router = 512;
inline constexpr std::size_t ipv6_neighbor_entries_per_router = 102400;
inline constexpr std::size_t ipv6_destination_entries_per_endpoint = 4096;
inline constexpr std::uint16_t icmp6_redirect_default_maximum = 100;
inline constexpr std::chrono::seconds icmp6_redirect_default_interval{10};
inline constexpr std::uint16_t icmp6_redirect_minimum_maximum = 10;
inline constexpr std::uint16_t icmp6_redirect_maximum_maximum = 1000;
inline constexpr std::chrono::seconds icmp6_redirect_minimum_interval{1};
inline constexpr std::chrono::seconds icmp6_redirect_maximum_interval{60};
inline constexpr std::uint16_t icmp_redirect_default_maximum = 100;
inline constexpr std::chrono::seconds icmp_redirect_default_interval{10};
inline constexpr std::uint16_t icmp_redirect_minimum_maximum = 10;
inline constexpr std::uint16_t icmp_redirect_maximum_maximum = 1000;
inline constexpr std::chrono::seconds icmp_redirect_minimum_interval{1};
inline constexpr std::chrono::seconds icmp_redirect_maximum_interval{60};
inline constexpr std::size_t ipv6_dad_entries_per_node = 512;
inline constexpr std::size_t network_interface_ip_addresses = 16;
inline constexpr std::size_t pending_ipv6_frames_per_router = 512;
inline constexpr std::size_t ipv4_reassembly_entries_per_endpoint = 4;
inline constexpr std::chrono::seconds ipv4_reassembly_timeout{60};
inline constexpr std::size_t ipv6_reassembly_entries_per_endpoint = 4;
inline constexpr std::chrono::seconds ipv6_reassembly_timeout{60};
inline constexpr std::size_t ipv4_pmtu_entries_per_endpoint = 64;
inline constexpr std::chrono::seconds ipv4_pmtu_probe_interval{600};
inline constexpr std::chrono::seconds ipv4_pmtu_probe_retry_interval{120};
inline constexpr std::size_t ipv6_pmtu_entries_per_endpoint = 64;
inline constexpr std::chrono::seconds ipv6_pmtu_probe_interval{600};
inline constexpr std::size_t udp_queued_datagrams_per_endpoint = 128;
inline constexpr std::size_t udp_datagrams_per_socket = 64;
inline constexpr std::size_t udp_receive_buffer_bytes_per_endpoint = 1048576;
inline constexpr std::size_t udp_receive_block_bytes = 2048;
inline constexpr std::uint16_t udp_ephemeral_port_first = 49152;
inline constexpr std::uint16_t udp_ephemeral_port_last = 65535;
inline constexpr std::size_t tcp_send_buffer_default_bytes = 262144;
inline constexpr std::size_t tcp_receive_buffer_default_bytes = 262144;
inline constexpr std::size_t tcp_transmission_records_default = 512;
inline constexpr std::size_t tcp_sack_ranges_default = 256;
inline constexpr std::size_t tcp_listen_backlog_default = 128;
inline constexpr std::uint16_t tcp_ephemeral_port_first = 49152;
inline constexpr std::uint16_t tcp_ephemeral_port_last = 65535;
inline constexpr std::size_t dns_cache_default_bytes = 8388608;
inline constexpr std::uint16_t dns_resolver_advertised_udp_payload_bytes = 1232;
inline constexpr std::uint32_t dns_resolver_retry_milliseconds = 1000;
inline constexpr std::uint32_t dns_resolver_attempts_per_server = 2;
inline constexpr std::uint32_t dns_resolver_max_minimise_count = 10;
inline constexpr std::uint32_t dns_resolver_minimise_one_label_count = 4;
inline constexpr std::uint32_t dns_resolver_max_alias_hops = 16;
inline constexpr std::size_t dhcpv6_address_pools_per_server = 8;
inline constexpr std::size_t dhcpv6_prefix_pools_per_server = 8;
inline constexpr std::size_t dhcpv6_leases_per_server = 1024;
inline constexpr std::size_t dhcpv6_relay_servers_per_interface = 8;
inline constexpr std::uint32_t dhcpv6_zero_t1_percent_of_preferred = 50;
inline constexpr std::uint32_t dhcpv6_zero_t2_percent_of_preferred = 80;
inline constexpr std::uint32_t dhcpv6_client_rate_limit_packets = 20;
inline constexpr std::uint32_t dhcpv6_client_rate_limit_interval_seconds = 20;
inline constexpr std::size_t pending_l3_frames_per_router = 512;
inline constexpr std::size_t nd_work_budget_actions = 64;
inline constexpr std::size_t ipv6_ra_prefixes_per_interface = 16;
inline constexpr std::size_t ipv6_rdnss_servers_per_interface = 4;
inline constexpr std::size_t ipv6_default_routers_per_host_interface = 8;
inline constexpr std::size_t ipv6_on_link_prefixes_per_host_interface = 16;
inline constexpr std::size_t ipv6_slaac_addresses_per_host_interface = 16;
inline constexpr std::size_t ipv6_rdnss_entries_per_host_interface = 8;
inline constexpr std::size_t ipv6_stable_iid_network_id_octets = 64;
inline constexpr std::size_t host_ipv6_work_budget_actions = 8;
inline constexpr std::size_t mld_groups_per_interface = 64;
inline constexpr std::size_t mld_sources_per_group = 64;
inline constexpr std::size_t mld_records_per_report = 64;
inline constexpr std::size_t mld_work_budget_actions = 64;
inline constexpr std::size_t mld_router_groups_per_interface = 16000;
inline constexpr std::size_t mld_router_sources_per_group = 1000;
inline constexpr std::size_t mld_router_group_sources_per_interface = 32000;
inline constexpr std::size_t network_command_ring_entries = 8;
inline constexpr std::size_t network_result_ring_entries = 32;
inline constexpr std::size_t network_command_work_budget = 64;
inline constexpr std::size_t forwarding_ring_frames = 64;
inline constexpr std::size_t candidate_keys_per_router = 16384;
inline constexpr std::size_t candidate_keys_per_session = 128;
inline constexpr std::size_t maximum_active_capture_points = 25744;
inline constexpr std::size_t capture_point_name_bytes = 512;
inline constexpr std::uint16_t default_network_mtu = 9212;
inline constexpr std::uint16_t minimum_network_mtu = 512;
inline constexpr std::uint16_t maximum_network_mtu = 9212;
inline constexpr std::uint16_t minimum_host_ipv4_mtu = 68;
inline constexpr std::uint16_t minimum_host_ipv6_mtu = 1280;
inline constexpr std::uint16_t default_host_ipv4_mtu = 1500;
inline constexpr std::size_t tls_maximum_cert_profiles = 16;
inline constexpr std::size_t tls_maximum_client_cipher_lists = 16;
inline constexpr std::size_t tls_maximum_client_group_lists = 16;
inline constexpr std::size_t tls_maximum_client_signature_lists = 16;
inline constexpr std::size_t tls_maximum_client_profiles = 16;
inline constexpr std::size_t tls_maximum_server_cipher_lists = 16;
inline constexpr std::size_t tls_maximum_server_group_lists = 16;
inline constexpr std::size_t tls_maximum_server_signature_lists = 16;
inline constexpr std::size_t tls_maximum_server_profiles = 16;
inline constexpr std::size_t tls_maximum_trust_anchor_profiles = 16;
inline constexpr std::size_t tls_maximum_cert_entries_per_profile = 8;
inline constexpr std::size_t tls_maximum_trust_anchors_per_profile = 8;
inline constexpr std::size_t tls_profile_name_bytes = 32;
inline constexpr std::size_t tls_certificate_file_name_bytes = 95;
inline constexpr std::uint8_t tls_algorithm_index_minimum = 1;
inline constexpr std::uint8_t tls_algorithm_index_maximum = 255;
inline constexpr std::array<TlsAlgorithmName, 5> tls13_ciphers{{
    {"tls-aes128-gcm-sha256", "TLS_AES_128_GCM_SHA256", false},
    {"tls-aes256-gcm-sha384", "TLS_AES_256_GCM_SHA384", true},
    {"tls-chacha20-poly1305-sha256", "TLS_CHACHA20_POLY1305_SHA256", false},
    {"tls-aes128-ccm-sha256", "TLS_AES_128_CCM_SHA256", false},
    {"tls-aes128-ccm8-sha256", "TLS_AES_128_CCM_8_SHA256", false}
}};
inline constexpr std::array<TlsAlgorithmName, 6> tls13_groups{{
    {"tls-ecdhe-256", "P-256", false},
    {"tls-ecdhe-384", "P-384", false},
    {"tls-ecdhe-521", "P-521", false},
    {"tls-x25519", "X25519", false},
    {"tls-x448", "X448", false},
    {"tls-ml-kem1024", "MLKEM1024", true}
}};
inline constexpr std::array<TlsAlgorithmName, 15> tls13_signatures{{
    {"tls-rsa-pkcs1-sha256", "rsa_pkcs1_sha256", false},
    {"tls-rsa-pkcs1-sha384", "rsa_pkcs1_sha384", false},
    {"tls-rsa-pkcs1-sha512", "rsa_pkcs1_sha512", false},
    {"tls-ecdsa-secp256r1-sha256", "ecdsa_secp256r1_sha256", false},
    {"tls-ecdsa-secp384r1-sha384", "ecdsa_secp384r1_sha384", false},
    {"tls-ecdsa-secp521r1-sha512", "ecdsa_secp521r1_sha512", false},
    {"tls-rsa-pss-rsae-sha256", "rsa_pss_rsae_sha256", false},
    {"tls-rsa-pss-rsae-sha384", "rsa_pss_rsae_sha384", false},
    {"tls-rsa-pss-rsae-sha512", "rsa_pss_rsae_sha512", false},
    {"tls-rsa-pss-pss-sha256", "rsa_pss_pss_sha256", false},
    {"tls-rsa-pss-pss-sha384", "rsa_pss_pss_sha384", false},
    {"tls-rsa-pss-pss-sha512", "rsa_pss_pss_sha512", false},
    {"tls-ed25519", "ed25519", false},
    {"tls-ed448", "ed448", false},
    {"tls-ml-dsa87", "mldsa87", true}
}};
inline constexpr std::chrono::seconds dynamic_arp_timeout{
    14400};
inline constexpr std::uint32_t arp_timeout_minimum_seconds =
    0U;
inline constexpr std::uint32_t arp_timeout_maximum_seconds =
    65535U;
inline constexpr std::chrono::milliseconds dynamic_arp_retry{
    5000};
inline constexpr std::uint16_t dynamic_arp_retry_deciseconds =
    50U;
inline constexpr std::uint16_t arp_retry_minimum_deciseconds =
    1U;
inline constexpr std::uint16_t arp_retry_maximum_deciseconds =
    300U;
inline constexpr std::chrono::milliseconds tcp_rto_initial{
    1000};
inline constexpr std::chrono::milliseconds tcp_rto_minimum{
    1000};
inline constexpr std::chrono::milliseconds tcp_rto_maximum{
    60000};
inline constexpr std::chrono::milliseconds tcp_rto_clock_granularity{
    1};
inline constexpr std::chrono::milliseconds tcp_rto_after_syn_retransmission{
    3000};
inline constexpr std::chrono::milliseconds tcp_delayed_ack{
    200};
inline constexpr std::chrono::milliseconds tcp_sws_override{
    200};
inline constexpr std::chrono::milliseconds tcp_persist_maximum{
    60000};
inline constexpr std::uint32_t tcp_failure_r1_retransmissions =
    3U;
inline constexpr std::chrono::seconds tcp_failure_data_r2{
    100};
inline constexpr std::chrono::seconds tcp_failure_syn_r2{
    180};
inline constexpr std::chrono::seconds tcp_maximum_segment_lifetime{
    120};
inline constexpr std::chrono::milliseconds nd_base_reachable_time{
    30000};
inline constexpr std::uint32_t nd_default_reachable_time_seconds =
    30U;
inline constexpr std::uint32_t nd_minimum_reachable_time_seconds =
    30U;
inline constexpr std::uint32_t nd_maximum_reachable_time_seconds =
    3600U;
inline constexpr std::uint32_t nd_default_stale_time_seconds =
    14400U;
inline constexpr std::uint32_t nd_minimum_stale_time_seconds =
    60U;
inline constexpr std::uint32_t nd_maximum_stale_time_seconds =
    65535U;
inline constexpr std::uint32_t nd_maximum_neighbor_limit =
    102400U;
inline constexpr std::uint8_t nd_default_neighbor_limit_threshold_percent =
    90U;
inline constexpr std::chrono::seconds nd_reachable_time_recalculation{
    10800};
inline constexpr std::chrono::milliseconds nd_retrans_timer{
    1000};
inline constexpr std::chrono::milliseconds nd_delay_first_probe{
    5000};
inline constexpr std::uint8_t nd_max_multicast_solicit =
    3;
inline constexpr std::uint8_t nd_max_unicast_solicit =
    3;
inline constexpr std::uint8_t ipv6_dad_transmits =
    1;
inline constexpr std::chrono::milliseconds ipv6_dad_max_initial_delay{
    1000};
inline constexpr std::uint8_t ipv6_stable_iid_dad_retries =
    3;
inline constexpr std::chrono::milliseconds ipv6_stable_iid_dad_retry_delay{
    1000};
inline constexpr std::uint8_t ipv6_rs_max_solicitations =
    3;
inline constexpr std::chrono::seconds ipv6_rs_interval{
    4};
inline constexpr std::chrono::milliseconds ipv6_rs_max_initial_delay{
    1000};
inline constexpr std::uint8_t mld_robustness_variable =
    2;
inline constexpr std::chrono::seconds mld_query_interval{
    125};
inline constexpr std::chrono::milliseconds mld_query_response_interval{
    10000};
inline constexpr std::chrono::milliseconds mld_last_listener_query_interval{
    1000};
inline constexpr std::chrono::milliseconds mld_unsolicited_report_interval{
    1000};
inline constexpr std::uint16_t mld_minimum_query_interval_seconds =
    2;
inline constexpr std::uint16_t mld_maximum_query_interval_seconds =
    1024;
inline constexpr std::uint16_t mld_minimum_query_response_interval_seconds =
    1;
inline constexpr std::uint16_t mld_maximum_query_response_interval_seconds =
    1023;
inline constexpr std::uint16_t
    mld_minimum_last_listener_query_interval_seconds =
        1;
inline constexpr std::uint16_t
    mld_maximum_last_listener_query_interval_seconds =
        1023;
inline constexpr std::uint8_t mld_minimum_robustness_variable =
    2;
inline constexpr std::uint8_t mld_maximum_robustness_variable =
    10;
inline constexpr std::uint8_t mld_minimum_version =
    1;
inline constexpr std::uint8_t mld_maximum_version =
    2;
inline constexpr std::uint8_t mld_default_version =
    2;
inline constexpr std::uint32_t mld_maximum_number_groups =
    16000;
inline constexpr std::uint32_t mld_maximum_number_group_sources =
    32000;
inline constexpr std::uint32_t mld_maximum_number_sources =
    1000;
inline constexpr std::uint8_t default_ip_hop_limit =
    64;
inline constexpr std::chrono::seconds ra_max_advertisement_interval{
    600};
inline constexpr std::chrono::seconds ra_min_advertisement_interval{
    200};
inline constexpr std::chrono::seconds ra_router_lifetime{
    1800};
inline constexpr std::chrono::seconds ra_minimum_max_advertisement_interval{
    4};
inline constexpr std::chrono::seconds ra_maximum_max_advertisement_interval{
    1800};
inline constexpr std::chrono::seconds ra_minimum_min_advertisement_interval{
    3};
inline constexpr std::chrono::seconds ra_maximum_min_advertisement_interval{
    1350};
inline constexpr std::chrono::seconds ra_minimum_nonzero_router_lifetime{
    4};
inline constexpr std::chrono::seconds ra_maximum_router_lifetime{
    9000};
inline constexpr std::chrono::milliseconds ra_maximum_reachable_time{
    3600000};
inline constexpr std::chrono::milliseconds ra_maximum_retransmit_time{
    1800000};
inline constexpr std::uint16_t ra_minimum_advertised_mtu =
    1280;
inline constexpr std::uint16_t ra_maximum_advertised_mtu =
    9800;
inline constexpr std::uint32_t ra_default_prefix_preferred_lifetime =
    604800U;
inline constexpr std::uint32_t ra_default_prefix_valid_lifetime =
    2592000U;
inline constexpr std::uint32_t ra_minimum_rdnss_lifetime =
    4U;
inline constexpr std::uint32_t ra_maximum_rdnss_lifetime =
    3600U;
inline constexpr std::uint32_t ra_infinite_lifetime =
    4294967295U;
inline constexpr std::chrono::milliseconds ra_max_response_delay{
    500};
inline constexpr std::chrono::seconds ra_min_delay_between_advertisements{
    3};
inline constexpr std::chrono::seconds ra_max_initial_advertisement_interval{
    16};
inline constexpr std::uint8_t ra_max_initial_advertisements =
    3;
inline constexpr std::size_t default_ping_payload_octets =
    56;
inline constexpr std::size_t minimum_ping_payload_octets =
    12;
inline constexpr std::size_t maximum_ping_payload_octets =
    1472;
inline constexpr std::uint32_t maximum_ping_count =
    100000U;
inline constexpr std::chrono::milliseconds ping_interval{
    1000};
inline constexpr std::chrono::milliseconds ping_timeout{
    5000};
inline constexpr std::chrono::seconds checkpoint_max_relative_deadline{
    86400};

struct PortGroup {
  std::uint8_t count{};
  std::array<std::uint32_t, 2> speeds_mbps{};
};

struct MdaProfile {
  std::string_view type;
  bool ethernet{};
  std::uint8_t port_count{};
  std::uint8_t group_count{};
  std::array<PortGroup, 2> groups{};
};

struct CardProfile {
  std::string_view device_profile;
  std::string_view type;
  bool fixed{};
  std::uint8_t mda_slots{};
  std::uint16_t first_mda{};
  std::uint16_t mda_count{};
};

struct DeviceProfile {
  std::string_view id;
  std::string_view chassis;
  std::string_view release;
  bool fixed{};
  std::uint8_t card_slots{};
  std::uint16_t first_card{};
  std::uint16_t card_count{};
  std::string_view control_slot;
  std::string_view control_type;
  std::string_view default_card;
  std::array<std::string_view, 2> default_mdas{};
  std::uint16_t maximum_ports{};
};

inline constexpr std::array<MdaProfile, 27> mdas{{
    {"isa2-aa", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"isa2-bb", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"isa2-tunnel", false, 0, 0, {{{0, {{0U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p10-10g-sfp", true, 10, 1, {{{10, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p1-100g-cfp", true, 1, 1, {{{1, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p6-10g-sfp", true, 6, 1, {{{6, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"p20-1gb-sfp", true, 20, 1, {{{20, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"imm24-1gb-xp-sfp", true, 24, 1, {{{24, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me10-10gb-sfp+", true, 10, 1, {{{10, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me1-100gb-cfp2", true, 1, 1, {{{1, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me12-10/1gb-sfp+", true, 12, 1, {{{12, {{1000U, 10000U}}}, {0, {{0U, 0U}}}}}},
    {"me2-100gb-ms-qsfp28", true, 2, 1, {{{2, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me2-100gb-qsfp28", true, 2, 1, {{{2, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me40-1gb-csfp", true, 40, 1, {{{40, {{1000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me6-10gb-sfp+", true, 6, 1, {{{6, {{10000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me8-10/25gb-sfp28", true, 8, 1, {{{8, {{10000U, 25000U}}}, {0, {{0U, 0U}}}}}},
    {"me12-100gb-qsfp28", true, 12, 1, {{{12, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me3-200gb-cfp2-dco", true, 3, 1, {{{3, {{100000U, 200000U}}}, {0, {{0U, 0U}}}}}},
    {"me6-100gb-qsfp28", true, 6, 1, {{{6, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me6-400gb-qsfpdd", true, 6, 1, {{{6, {{400000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me16-25gb-sfp28+2-100gb-qsfp28", true, 18, 2, {{{16, {{10000U, 25000U}}}, {2, {{100000U, 0U}}}}}},
    {"me3-400gb-qsfpdd", true, 3, 1, {{{3, {{400000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"me16-25gb-sfp28+2-100gb-qsfp-b", true, 18, 2, {{{16, {{10000U, 25000U}}}, {2, {{100000U, 0U}}}}}},
    {"m5e2-100g-qsfp28+2-800g-qdd", true, 4, 2, {{{2, {{100000U, 0U}}}, {2, {{800000U, 0U}}}}}},
    {"m5e8-100g-sfp112+2-800g-qdd", true, 10, 2, {{{8, {{100000U, 0U}}}, {2, {{800000U, 0U}}}}}},
    {"m5e10-100g-qsfp28", true, 10, 1, {{{10, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}},
    {"m5e16-100g-sfp112", true, 16, 1, {{{16, {{100000U, 0U}}}, {0, {{0U, 0U}}}}}}
}};

inline constexpr std::array<std::uint16_t, 95> card_mdas{{
    16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U, 25U, 26U, 0U, 1U, 2U, 3U, 4U, 7U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 17U, 18U, 20U, 21U, 22U, 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 0U, 1U, 2U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U, 17U, 18U, 20U, 21U, 22U
}};

inline constexpr std::array<CardProfile, 13> cards{{
    {"7750-sr-1", "cpm-1", true, 2, 0, 11},
    {"7750-sr-7", "imm-2pac-fp3", false, 2, 11, 5},
    {"7750-sr-7", "imm48-1gb-sfp-c", false, 1, 16, 1},
    {"7750-sr-7", "iom4-e", false, 2, 17, 11},
    {"7750-sr-7", "iom4-e-b", false, 2, 28, 11},
    {"7750-sr-7", "iom4-e-hs", false, 2, 39, 8},
    {"7750-sr-7", "iom5-e", false, 2, 47, 5},
    {"7750-sr-12", "imm-2pac-fp3", false, 2, 52, 7},
    {"7750-sr-12", "imm48-1gb-sfp-c", false, 1, 59, 1},
    {"7750-sr-12", "iom4-e", false, 2, 60, 11},
    {"7750-sr-12", "iom4-e-b", false, 2, 71, 11},
    {"7750-sr-12", "iom4-e-hs", false, 2, 82, 8},
    {"7750-sr-12", "iom5-e", false, 2, 90, 5}
}};

inline constexpr std::array<DeviceProfile, 3> profiles{{
    {"7750-sr-1", "7750 SR-1", "26.7.R1", true, 0, 0, 1, "A", "cpm-1", "cpm-1", {"me6-100gb-qsfp28", "me12-100gb-qsfp28"}, 36},
    {"7750-sr-7", "7750 SR-7", "26.7.R1", false, 5, 1, 6, "A", "cpm5", "iom5-e", {"me6-100gb-qsfp28", ""}, 400},
    {"7750-sr-12", "7750 SR-12", "26.7.R1", false, 10, 7, 6, "A", "cpm5", "iom5-e", {"me6-100gb-qsfp28", ""}, 800}
}};

[[nodiscard]] constexpr const DeviceProfile *find_profile(std::string_view id) noexcept {
  // Bounded generated records are cheaper and easier to validate than a mutable
  // hash index. The returned pointer targets immutable process-lifetime data.
  for (const auto &profile : profiles)
    if (profile.id == id)
      return &profile;
  return nullptr;
}

[[nodiscard]] constexpr const MdaProfile *find_mda(std::string_view type) noexcept {
  // Hardware edits run on the control shard, so a bounded catalog scan keeps
  // the generated representation compact without affecting packet throughput.
  for (const auto &mda : mdas)
    if (mda.type == type)
      return &mda;
  return nullptr;
}

[[nodiscard]] constexpr const CardProfile *
find_card(const DeviceProfile &profile, std::string_view type) noexcept {
  // Cards for a profile occupy one contiguous generated range. Restricting the
  // scan to that range prevents a same-named card from another chassis profile
  // from becoming compatible accidentally.
  for (std::size_t offset = 0; offset < profile.card_count; ++offset) {
    const auto &card = cards[profile.first_card + offset];
    if (card.type == type)
      return &card;
  }
  return nullptr;
}

[[nodiscard]] constexpr bool card_supports_mda(
    const CardProfile &card, std::string_view type) noexcept {
  // card_mdas stores indexes into immutable MDA records. The compact relation
  // is evaluated on hardware edits, never per forwarded packet.
  for (std::size_t offset = 0; offset < card.mda_count; ++offset)
    if (mdas[card_mdas[card.first_mda + offset]].type == type)
      return true;
  return false;
}

} // namespace router::device_catalog
