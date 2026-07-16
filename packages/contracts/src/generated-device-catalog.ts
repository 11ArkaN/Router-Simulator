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
    "wasm_initial_memory_bytes": 268435456,
    "wasm_stack_bytes": 1048576,
    "packet_pool_bytes": 67108864,
    "capture_store_bytes": 33554432,
    "terminal_output_arena_bytes": 16777216,
    "terminal_result_bytes": 1048576,
    "runtime_control_reserve_bytes": 33554432,
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
    "link_queue_frames": 256,
    "fabric_work_budget_frames": 64,
    "static_routes_per_router": 64,
    "arp_entries_per_router": 4096,
    "pending_ipv4_frames_per_router": 512,
    "network_command_ring_entries": 8,
    "network_result_ring_entries": 32,
    "forwarding_ring_frames": 64,
    "candidate_keys_per_router": 256,
    "candidate_keys_per_session": 128,
    "selected_capture_points": 256,
    "capture_point_name_bytes": 512
  },
  "ethernet": {
    "default_network_mtu": 9212,
    "minimum_network_mtu": 512,
    "maximum_network_mtu": 9212,
    "minimum_host_ipv4_mtu": 68,
    "default_host_ipv4_mtu": 1500
  },
  "protocol_defaults": {
    "dynamic_arp_timeout_seconds": 14400,
    "ping_payload_octets": 56,
    "ping_minimum_payload_octets": 12,
    "ping_maximum_payload_octets": 1472,
    "ping_maximum_count": 100000,
    "ping_interval_milliseconds": 1000,
    "ping_timeout_milliseconds": 5000
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
export const PROFILE_CATALOG_HASH = "0fae1ef668260ff9" as const;
export const LAB_BUILD_HASH = "28923cb2f23d9285" as const;
