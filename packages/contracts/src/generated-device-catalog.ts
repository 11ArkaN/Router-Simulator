// Generated from profiles/catalog/26.7.R1.yaml. Do not edit.
// Runtime and UI code use this catalog instead of chassis-specific branches.

export const PROFILE_CATALOG = {
  "release": "26.7.R1",
  "limits": {
    "routers": 16,
    "hosts": 16,
    "links": 64,
    "sessions_per_router": 4
  },
  "runtime": {
    "wasm_initial_memory_bytes": 335544320,
    "wasm_maximum_memory_bytes": 1073741824,
    "wasm_growth_step_bytes": 67108864,
    "wasm_stack_bytes": 1048576,
    "packet_pool_bytes": 67108864,
    "capture_store_bytes": 33554432,
    "terminal_output_arena_bytes": 16777216,
    "terminal_result_bytes": 1048576,
    "runtime_control_reserve_bytes": 41943040,
    "low_cpu_max": 4,
    "medium_cpu_max": 8,
    "low_control_shards": 1,
    "medium_control_shards": 1,
    "high_control_shards": 2,
    "low_forwarding_shards": 1,
    "medium_forwarding_shards": 2,
    "high_forwarding_shards": 3,
    "low_link_shards": 0,
    "medium_link_shards": 1,
    "high_link_shards": 1,
    "pthread_pool_low": 1,
    "pthread_pool_medium": 3,
    "pthread_pool_high": 5,
    "maximum_worker_domains": 6,
    "worker_startup_attempts": 200,
    "worker_startup_poll_milliseconds": 10,
    "telemetry_publish_interval_milliseconds": 250,
    "recovery_checkpoint_interval_milliseconds": 2000,
    "continuity_loss_threshold_milliseconds": 5000,
    "link_queue_frames": 256,
    "fabric_work_budget_frames": 64,
    "immediate_link_deadline_nanoseconds": 74000,
    "static_routes_per_router": 64,
    "arp_entries_per_router": 4096,
    "static_arp_entries_per_router": 1000,
    "pending_ipv4_frames_per_router": 512,
    "ipv6_neighbor_entries_per_router": 102400,
    "ipv6_destination_entries_per_endpoint": 4096,
    "icmp6_redirect_default_maximum": 100,
    "icmp6_redirect_default_interval_seconds": 10,
    "icmp6_redirect_minimum_maximum": 10,
    "icmp6_redirect_maximum_maximum": 1000,
    "icmp6_redirect_minimum_interval_seconds": 1,
    "icmp6_redirect_maximum_interval_seconds": 60,
    "icmp_redirect_default_maximum": 100,
    "icmp_redirect_default_interval_seconds": 10,
    "icmp_redirect_minimum_maximum": 10,
    "icmp_redirect_maximum_maximum": 1000,
    "icmp_redirect_minimum_interval_seconds": 1,
    "icmp_redirect_maximum_interval_seconds": 60,
    "ipv6_dad_entries_per_node": 512,
    "network_interface_ip_addresses": 16,
    "pending_ipv6_frames_per_router": 512,
    "ipv4_reassembly_entries_per_endpoint": 4,
    "ipv4_reassembly_timeout_seconds": 60,
    "ipv4_pmtu_entries_per_endpoint": 64,
    "ipv4_pmtu_probe_interval_seconds": 600,
    "ipv4_pmtu_probe_retry_interval_seconds": 120,
    "ipv6_reassembly_entries_per_endpoint": 4,
    "ipv6_reassembly_timeout_seconds": 60,
    "ipv6_pmtu_entries_per_endpoint": 64,
    "ipv6_pmtu_probe_interval_seconds": 600,
    "udp_queued_datagrams_per_endpoint": 128,
    "udp_datagrams_per_socket": 64,
    "udp_receive_buffer_bytes_per_endpoint": 1048576,
    "udp_receive_block_bytes": 2048,
    "udp_ephemeral_port_first": 49152,
    "udp_ephemeral_port_last": 65535,
    "tcp_send_buffer_default_bytes": 262144,
    "tcp_receive_buffer_default_bytes": 262144,
    "tcp_transmission_records_default": 512,
    "tcp_sack_ranges_default": 256,
    "tcp_listen_backlog_default": 128,
    "tcp_ephemeral_port_first": 49152,
    "tcp_ephemeral_port_last": 65535,
    "dns_cache_default_bytes": 8388608,
    "dns_resolver_advertised_udp_payload_bytes": 1232,
    "dns_resolver_retry_milliseconds": 1000,
    "dns_resolver_attempts_per_server": 2,
    "dns_resolver_max_minimise_count": 10,
    "dns_resolver_minimise_one_label_count": 4,
    "dns_resolver_max_alias_hops": 16,
    "dhcpv6_address_pools_per_server": 8,
    "dhcpv6_prefix_pools_per_server": 8,
    "dhcpv6_leases_per_server": 1024,
    "dhcpv6_relay_servers_per_interface": 8,
    "dhcpv6_zero_t1_percent_of_preferred": 50,
    "dhcpv6_zero_t2_percent_of_preferred": 80,
    "dhcpv6_client_rate_limit_packets": 20,
    "dhcpv6_client_rate_limit_interval_seconds": 20,
    "ipv6_ra_prefixes_per_interface": 16,
    "ipv6_rdnss_servers_per_interface": 4,
    "ipv6_default_routers_per_host_interface": 8,
    "ipv6_on_link_prefixes_per_host_interface": 16,
    "ipv6_slaac_addresses_per_host_interface": 16,
    "ipv6_rdnss_entries_per_host_interface": 8,
    "ipv6_stable_iid_network_id_octets": 64,
    "host_ipv6_work_budget_actions": 8,
    "mld_groups_per_interface": 64,
    "mld_sources_per_group": 64,
    "mld_records_per_report": 64,
    "mld_work_budget_actions": 64,
    "mld_router_groups_per_interface": 16000,
    "mld_router_sources_per_group": 1000,
    "mld_router_group_sources_per_interface": 32000,
    "pending_l3_frames_per_router": 512,
    "nd_work_budget_actions": 64,
    "network_command_ring_entries": 8,
    "network_result_ring_entries": 32,
    "network_command_work_budget": 64,
    "forwarding_ring_frames": 64,
    "candidate_keys_per_router": 16384,
    "candidate_keys_per_session": 128,
    "selected_capture_points": 256,
    "capture_point_name_bytes": 512
  },
  "ethernet": {
    "default_network_mtu": 9212,
    "minimum_network_mtu": 512,
    "maximum_network_mtu": 9212,
    "minimum_host_ipv4_mtu": 68,
    "minimum_host_ipv6_mtu": 1280,
    "default_host_ipv4_mtu": 1500
  },
  "ipsec": {
    "maximum_ike_policies": 2048,
    "maximum_ike_transforms": 4096,
    "maximum_ipsec_transforms": 2048,
    "maximum_static_sas": 1000,
    "maximum_tunnel_templates": 2048,
    "maximum_traffic_selector_lists": 32768,
    "maximum_traffic_selectors_per_list": 32,
    "maximum_ppk_lists": 128,
    "maximum_ppks_per_list": 128,
    "maximum_certificate_profiles": 10200,
    "maximum_certificate_entries_per_profile": 8,
    "maximum_trust_anchor_profiles": 10128,
    "maximum_trust_anchors_per_profile": 8,
    "maximum_project_secret_records": 131072,
    "ike_fragment_mtu_minimum": 512,
    "ike_fragment_mtu_maximum": 9000,
    "ike_fragment_mtu_default": 1500,
    "ike_reassembly_timeout_minimum_seconds": 1,
    "ike_reassembly_timeout_maximum_seconds": 5,
    "ike_reassembly_timeout_default_seconds": 2,
    "transforms": [
      {
        "type": "encryption",
        "id": 20,
        "key_bits": 128,
        "key_length_attribute_required": true,
        "authenticated_encryption": true,
        "implemented": true
      },
      {
        "type": "encryption",
        "id": 20,
        "key_bits": 192,
        "key_length_attribute_required": true,
        "authenticated_encryption": true,
        "implemented": true
      },
      {
        "type": "encryption",
        "id": 20,
        "key_bits": 256,
        "key_length_attribute_required": true,
        "authenticated_encryption": true,
        "implemented": true
      },
      {
        "type": "prf",
        "id": 5,
        "key_bits": 256,
        "key_length_attribute_required": false,
        "authenticated_encryption": false,
        "implemented": true
      },
      {
        "type": "integrity",
        "id": 12,
        "key_bits": 256,
        "key_length_attribute_required": false,
        "authenticated_encryption": false,
        "implemented": true
      },
      {
        "type": "diffie_hellman",
        "id": 19,
        "key_bits": 256,
        "key_length_attribute_required": false,
        "authenticated_encryption": false,
        "implemented": true
      },
      {
        "type": "extended_sequence_numbers",
        "id": 0,
        "key_bits": 0,
        "key_length_attribute_required": false,
        "authenticated_encryption": false,
        "implemented": true
      },
      {
        "type": "extended_sequence_numbers",
        "id": 1,
        "key_bits": 0,
        "key_length_attribute_required": false,
        "authenticated_encryption": false,
        "implemented": true
      }
    ]
  },
  "tls": {
    "maximum_cert_profiles": 16,
    "maximum_client_cipher_lists": 16,
    "maximum_client_group_lists": 16,
    "maximum_client_signature_lists": 16,
    "maximum_client_tls_profiles": 16,
    "maximum_server_cipher_lists": 16,
    "maximum_server_group_lists": 16,
    "maximum_server_signature_lists": 16,
    "maximum_server_tls_profiles": 16,
    "maximum_trust_anchor_profiles": 16,
    "maximum_cert_entries_per_profile": 8,
    "maximum_trust_anchors_per_profile": 8,
    "profile_name_bytes": 32,
    "certificate_file_name_bytes": 95,
    "algorithm_index_minimum": 1,
    "algorithm_index_maximum": 255,
    "default_admin_state": "disable",
    "default_protocol_version": "tls-version-12",
    "default_status_result": "revoked",
    "default_revocation_primary": "crl",
    "default_revocation_secondary": "none",
    "tls13_ciphers": [
      {
        "sros": "tls-aes128-gcm-sha256",
        "openssl": "TLS_AES_128_GCM_SHA256",
        "pqc": false
      },
      {
        "sros": "tls-aes256-gcm-sha384",
        "openssl": "TLS_AES_256_GCM_SHA384",
        "pqc": true
      },
      {
        "sros": "tls-chacha20-poly1305-sha256",
        "openssl": "TLS_CHACHA20_POLY1305_SHA256",
        "pqc": false
      },
      {
        "sros": "tls-aes128-ccm-sha256",
        "openssl": "TLS_AES_128_CCM_SHA256",
        "pqc": false
      },
      {
        "sros": "tls-aes128-ccm8-sha256",
        "openssl": "TLS_AES_128_CCM_8_SHA256",
        "pqc": false
      }
    ],
    "tls13_groups": [
      {
        "sros": "tls-ecdhe-256",
        "openssl": "P-256",
        "pqc": false
      },
      {
        "sros": "tls-ecdhe-384",
        "openssl": "P-384",
        "pqc": false
      },
      {
        "sros": "tls-ecdhe-521",
        "openssl": "P-521",
        "pqc": false
      },
      {
        "sros": "tls-x25519",
        "openssl": "X25519",
        "pqc": false
      },
      {
        "sros": "tls-x448",
        "openssl": "X448",
        "pqc": false
      },
      {
        "sros": "tls-ml-kem1024",
        "openssl": "MLKEM1024",
        "pqc": true
      }
    ],
    "tls13_signatures": [
      {
        "sros": "tls-rsa-pkcs1-sha256",
        "openssl": "rsa_pkcs1_sha256",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pkcs1-sha384",
        "openssl": "rsa_pkcs1_sha384",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pkcs1-sha512",
        "openssl": "rsa_pkcs1_sha512",
        "pqc": false
      },
      {
        "sros": "tls-ecdsa-secp256r1-sha256",
        "openssl": "ecdsa_secp256r1_sha256",
        "pqc": false
      },
      {
        "sros": "tls-ecdsa-secp384r1-sha384",
        "openssl": "ecdsa_secp384r1_sha384",
        "pqc": false
      },
      {
        "sros": "tls-ecdsa-secp521r1-sha512",
        "openssl": "ecdsa_secp521r1_sha512",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-rsae-sha256",
        "openssl": "rsa_pss_rsae_sha256",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-rsae-sha384",
        "openssl": "rsa_pss_rsae_sha384",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-rsae-sha512",
        "openssl": "rsa_pss_rsae_sha512",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-pss-sha256",
        "openssl": "rsa_pss_pss_sha256",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-pss-sha384",
        "openssl": "rsa_pss_pss_sha384",
        "pqc": false
      },
      {
        "sros": "tls-rsa-pss-pss-sha512",
        "openssl": "rsa_pss_pss_sha512",
        "pqc": false
      },
      {
        "sros": "tls-ed25519",
        "openssl": "ed25519",
        "pqc": false
      },
      {
        "sros": "tls-ed448",
        "openssl": "ed448",
        "pqc": false
      },
      {
        "sros": "tls-ml-dsa87",
        "openssl": "mldsa87",
        "pqc": true
      }
    ]
  },
  "protocol_defaults": {
    "arp_timeout_minimum_seconds": 0,
    "arp_timeout_maximum_seconds": 65535,
    "dynamic_arp_timeout_seconds": 14400,
    "arp_retry_minimum_deciseconds": 1,
    "arp_retry_maximum_deciseconds": 300,
    "dynamic_arp_retry_deciseconds": 50,
    "tcp_rto_initial_milliseconds": 1000,
    "tcp_rto_minimum_milliseconds": 1000,
    "tcp_rto_maximum_milliseconds": 60000,
    "tcp_rto_clock_granularity_milliseconds": 1,
    "tcp_rto_after_syn_retransmission_milliseconds": 3000,
    "tcp_delayed_ack_milliseconds": 200,
    "tcp_sws_override_milliseconds": 200,
    "tcp_persist_maximum_milliseconds": 60000,
    "tcp_failure_r1_retransmissions": 3,
    "tcp_failure_data_r2_seconds": 100,
    "tcp_failure_syn_r2_seconds": 180,
    "tcp_maximum_segment_lifetime_seconds": 120,
    "nd_reachable_time_milliseconds": 30000,
    "nd_default_reachable_time_seconds": 30,
    "nd_minimum_reachable_time_seconds": 30,
    "nd_maximum_reachable_time_seconds": 3600,
    "nd_default_stale_time_seconds": 14400,
    "nd_minimum_stale_time_seconds": 60,
    "nd_maximum_stale_time_seconds": 65535,
    "nd_maximum_neighbor_limit": 102400,
    "nd_default_neighbor_limit_threshold_percent": 90,
    "nd_reachable_time_recalculation_seconds": 10800,
    "nd_retrans_timer_milliseconds": 1000,
    "nd_delay_first_probe_milliseconds": 5000,
    "mld_robustness_variable": 2,
    "mld_query_interval_seconds": 125,
    "mld_query_response_interval_milliseconds": 10000,
    "mld_last_listener_query_interval_milliseconds": 1000,
    "mld_unsolicited_report_interval_milliseconds": 1000,
    "mld_minimum_query_interval_seconds": 2,
    "mld_maximum_query_interval_seconds": 1024,
    "mld_minimum_query_response_interval_seconds": 1,
    "mld_maximum_query_response_interval_seconds": 1023,
    "mld_minimum_last_listener_query_interval_seconds": 1,
    "mld_maximum_last_listener_query_interval_seconds": 1023,
    "mld_minimum_robustness_variable": 2,
    "mld_maximum_robustness_variable": 10,
    "mld_minimum_version": 1,
    "mld_maximum_version": 2,
    "mld_default_version": 2,
    "mld_maximum_number_groups": 16000,
    "mld_maximum_number_group_sources": 32000,
    "mld_maximum_number_sources": 1000,
    "nd_max_multicast_solicit": 3,
    "nd_max_unicast_solicit": 3,
    "ipv6_dad_transmits": 1,
    "ipv6_dad_max_initial_delay_milliseconds": 1000,
    "ipv6_stable_iid_dad_retries": 3,
    "ipv6_stable_iid_dad_retry_delay_milliseconds": 1000,
    "ipv6_rs_max_solicitations": 3,
    "ipv6_rs_interval_seconds": 4,
    "ipv6_rs_max_initial_delay_milliseconds": 1000,
    "default_ip_hop_limit": 64,
    "ra_max_advertisement_interval_seconds": 600,
    "ra_min_advertisement_interval_seconds": 200,
    "ra_router_lifetime_seconds": 1800,
    "ra_minimum_max_advertisement_interval_seconds": 4,
    "ra_maximum_max_advertisement_interval_seconds": 1800,
    "ra_minimum_min_advertisement_interval_seconds": 3,
    "ra_maximum_min_advertisement_interval_seconds": 1350,
    "ra_minimum_nonzero_router_lifetime_seconds": 4,
    "ra_maximum_router_lifetime_seconds": 9000,
    "ra_maximum_reachable_time_milliseconds": 3600000,
    "ra_maximum_retransmit_time_milliseconds": 1800000,
    "ra_minimum_advertised_mtu": 1280,
    "ra_maximum_advertised_mtu": 9800,
    "ra_default_prefix_preferred_lifetime_seconds": 604800,
    "ra_default_prefix_valid_lifetime_seconds": 2592000,
    "ra_minimum_rdnss_lifetime_seconds": 4,
    "ra_maximum_rdnss_lifetime_seconds": 3600,
    "ra_infinite_lifetime_seconds": 4294967295,
    "ra_max_response_delay_milliseconds": 500,
    "ra_min_delay_between_advertisements_seconds": 3,
    "ra_max_initial_advertisement_interval_seconds": 16,
    "ra_max_initial_advertisements": 3,
    "ping_payload_octets": 56,
    "ping_minimum_payload_octets": 12,
    "ping_maximum_payload_octets": 1472,
    "ping_maximum_count": 100000,
    "ping_interval_milliseconds": 1000,
    "ping_timeout_milliseconds": 5000,
    "checkpoint_max_relative_deadline_seconds": 86400
  },
  "profiles": [
    {
      "id": "7750-sr-1",
      "chassis": "7750 SR-1",
      "fixed": true,
      "card_slots": 0,
      "control": {
        "slot": "A",
        "types": [
          "cpm-1"
        ]
      },
      "cards": [
        {
          "type": "cpm-1",
          "fixed": true,
          "mda_slots": 2,
          "mdas": [
            "me12-100gb-qsfp28",
            "me3-200gb-cfp2-dco",
            "me6-100gb-qsfp28",
            "me6-400gb-qsfpdd",
            "me16-25gb-sfp28+2-100gb-qsfp28",
            "me3-400gb-qsfpdd",
            "me16-25gb-sfp28+2-100gb-qsfp-b",
            "m5e2-100g-qsfp28+2-800g-qdd",
            "m5e8-100g-sfp112+2-800g-qdd",
            "m5e10-100g-qsfp28",
            "m5e16-100g-sfp112"
          ]
        }
      ],
      "default_hardware": {
        "card": "cpm-1",
        "mdas": [
          "me6-100gb-qsfp28",
          "me12-100gb-qsfp28"
        ]
      }
    },
    {
      "id": "7750-sr-7",
      "chassis": "7750 SR-7",
      "fixed": false,
      "card_slots": 5,
      "control": {
        "slot": "A",
        "types": [
          "cpm5"
        ]
      },
      "cards": [
        {
          "type": "imm-2pac-fp3",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "p10-10g-sfp",
            "p1-100g-cfp"
          ]
        },
        {
          "type": "imm48-1gb-sfp-c",
          "fixed": false,
          "mda_slots": 1,
          "mdas": [
            "imm24-1gb-xp-sfp"
          ]
        },
        {
          "type": "iom4-e",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom4-e-b",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom4-e-hs",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom5-e",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "me3-200gb-cfp2-dco",
            "me6-100gb-qsfp28",
            "me16-25gb-sfp28+2-100gb-qsfp28",
            "me3-400gb-qsfpdd",
            "me16-25gb-sfp28+2-100gb-qsfp-b"
          ]
        }
      ],
      "default_hardware": {
        "card": "iom5-e",
        "mdas": [
          "me6-100gb-qsfp28"
        ]
      }
    },
    {
      "id": "7750-sr-12",
      "chassis": "7750 SR-12",
      "fixed": false,
      "card_slots": 10,
      "control": {
        "slot": "A",
        "types": [
          "cpm5"
        ]
      },
      "cards": [
        {
          "type": "imm-2pac-fp3",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "p10-10g-sfp",
            "p1-100g-cfp",
            "p6-10g-sfp",
            "p20-1gb-sfp"
          ]
        },
        {
          "type": "imm48-1gb-sfp-c",
          "fixed": false,
          "mda_slots": 1,
          "mdas": [
            "imm24-1gb-xp-sfp"
          ]
        },
        {
          "type": "iom4-e",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom4-e-b",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "isa2-aa",
            "isa2-bb",
            "isa2-tunnel",
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom4-e-hs",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "me10-10gb-sfp+",
            "me1-100gb-cfp2",
            "me12-10/1gb-sfp+",
            "me2-100gb-ms-qsfp28",
            "me2-100gb-qsfp28",
            "me40-1gb-csfp",
            "me6-10gb-sfp+",
            "me8-10/25gb-sfp28"
          ]
        },
        {
          "type": "iom5-e",
          "fixed": false,
          "mda_slots": 2,
          "mdas": [
            "me3-200gb-cfp2-dco",
            "me6-100gb-qsfp28",
            "me16-25gb-sfp28+2-100gb-qsfp28",
            "me3-400gb-qsfpdd",
            "me16-25gb-sfp28+2-100gb-qsfp-b"
          ]
        }
      ],
      "default_hardware": {
        "card": "iom5-e",
        "mdas": [
          "me6-100gb-qsfp28"
        ]
      }
    }
  ],
  "mdas": {
    "isa2-aa": {
      "ethernet": false,
      "ports": []
    },
    "isa2-bb": {
      "ethernet": false,
      "ports": []
    },
    "isa2-tunnel": {
      "ethernet": false,
      "ports": []
    },
    "p10-10g-sfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 10,
          "speeds_mbps": [
            10000
          ]
        }
      ]
    },
    "p1-100g-cfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 1,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "p6-10g-sfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 6,
          "speeds_mbps": [
            10000
          ]
        }
      ]
    },
    "p20-1gb-sfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 20,
          "speeds_mbps": [
            1000
          ]
        }
      ]
    },
    "imm24-1gb-xp-sfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 24,
          "speeds_mbps": [
            1000
          ]
        }
      ]
    },
    "me10-10gb-sfp+": {
      "ethernet": true,
      "ports": [
        {
          "count": 10,
          "speeds_mbps": [
            10000
          ]
        }
      ]
    },
    "me1-100gb-cfp2": {
      "ethernet": true,
      "ports": [
        {
          "count": 1,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me12-10/1gb-sfp+": {
      "ethernet": true,
      "ports": [
        {
          "count": 12,
          "speeds_mbps": [
            1000,
            10000
          ]
        }
      ]
    },
    "me2-100gb-ms-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 2,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me2-100gb-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 2,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me40-1gb-csfp": {
      "ethernet": true,
      "ports": [
        {
          "count": 40,
          "speeds_mbps": [
            1000
          ]
        }
      ]
    },
    "me6-10gb-sfp+": {
      "ethernet": true,
      "ports": [
        {
          "count": 6,
          "speeds_mbps": [
            10000
          ]
        }
      ]
    },
    "me8-10/25gb-sfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 8,
          "speeds_mbps": [
            10000,
            25000
          ]
        }
      ]
    },
    "me12-100gb-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 12,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me3-200gb-cfp2-dco": {
      "ethernet": true,
      "ports": [
        {
          "count": 3,
          "speeds_mbps": [
            100000,
            200000
          ]
        }
      ]
    },
    "me6-100gb-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 6,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me6-400gb-qsfpdd": {
      "ethernet": true,
      "ports": [
        {
          "count": 6,
          "speeds_mbps": [
            400000
          ]
        }
      ]
    },
    "me16-25gb-sfp28+2-100gb-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 16,
          "speeds_mbps": [
            10000,
            25000
          ]
        },
        {
          "count": 2,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "me3-400gb-qsfpdd": {
      "ethernet": true,
      "ports": [
        {
          "count": 3,
          "speeds_mbps": [
            400000
          ]
        }
      ]
    },
    "me16-25gb-sfp28+2-100gb-qsfp-b": {
      "ethernet": true,
      "ports": [
        {
          "count": 16,
          "speeds_mbps": [
            10000,
            25000
          ]
        },
        {
          "count": 2,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "m5e2-100g-qsfp28+2-800g-qdd": {
      "ethernet": true,
      "ports": [
        {
          "count": 2,
          "speeds_mbps": [
            100000
          ]
        },
        {
          "count": 2,
          "speeds_mbps": [
            800000
          ]
        }
      ]
    },
    "m5e8-100g-sfp112+2-800g-qdd": {
      "ethernet": true,
      "ports": [
        {
          "count": 8,
          "speeds_mbps": [
            100000
          ]
        },
        {
          "count": 2,
          "speeds_mbps": [
            800000
          ]
        }
      ]
    },
    "m5e10-100g-qsfp28": {
      "ethernet": true,
      "ports": [
        {
          "count": 10,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    },
    "m5e16-100g-sfp112": {
      "ethernet": true,
      "ports": [
        {
          "count": 16,
          "speeds_mbps": [
            100000
          ]
        }
      ]
    }
  }
} as const;
export const PROFILE_CATALOG_COMPILED = {
  "maximumPortsPerRouter": 800,
  "maximumCardSlots": 10,
  "maximumMdaSlotsPerCard": 2,
  "maximumPortsPerMda": 40
} as const;
export const PROFILE_CATALOG_HASH = "01daa898ad67b5b7" as const;
export const LAB_BUILD_HASH = "e13c92da55c396f9" as const;
