// Generated browser projection of the active release profile. UI, storage
// and Worker code consume these values instead of reconstructing hardware.

export const GENERATED_PROFILE = {
  id: "7750-sr-7-iom4-e",
  release: "26.7.R1",
  chassis: "7750 SR-7",
  chassisSlots: 5,
  defaultSystemName: "R1",
  control: {"slot":"A","card":"cpm5","initial_state":"active-ready"},
  lineCard: {"slot":1,"type":"iom4-e","initializationMs":2000,"timingStatus":"experimental"},
  mda: {"slot":1,"slotsPerCard":1,"modeledType":"me10-10gb-sfp+","supportedTypes":["me10-10gb-sfp+","me1-100gb-cfp2"],"initializationMs":1000,"timingStatus":"experimental"},
  ports: {"ids":["1/1/1","1/1/2","1/1/3","1/1/4","1/1/5","1/1/6","1/1/7","1/1/8","1/1/9","1/1/10"],"count":10,"speedMbps":10000,"defaultMtu":9212,"minimumMtu":512,"maximumMtu":9212},
  defaultPropagationDelayNs: 100,
  routerInterfaces: [{"name":"to-host-a","port":"1/1/1","admin_state":"enable","mac":"02:00:00:00:01:01","address":"192.0.2.1/30","network":"192.0.2.0/30"},{"name":"to-host-b","port":"1/1/2","admin_state":"enable","mac":"02:00:00:00:01:02","address":"198.51.100.1/30","network":"198.51.100.0/30"}],
  hosts: [{"id":"host-a","name":"Host A","mac":"02:00:00:00:00:0A","address":"192.0.2.2/30","gateway":"192.0.2.1"},{"id":"host-b","name":"Host B","mac":"02:00:00:00:00:0B","address":"198.51.100.2/30","gateway":"198.51.100.1"}],
  links: [{"id":"host-a-r1","host":"host-a","router_port":"1/1/1"},{"id":"r1-host-b","host":"host-b","router_port":"1/1/2"}],
  captureInterfaces: ["link-host-a-to-router","link-router-to-host-a","link-host-b-to-router","link-router-to-host-b","router-1/1/1-ingress","router-1/1/2-ingress","router-1/1/1-egress","router-1/1/2-egress","cpm-punt"],
  resources: {"runtime_worker_count":2,"command_message_bytes":1024,"response_message_bytes":16384,"static_route_capacity":8,"fib_route_capacity":18,"packet_pool_bytes":67108864,"capture_memory_bytes":33554432,"link_queue_frames":256,"link_inflight_frames":2048,"adjacency_pending_frames":8,"command_ring_capacity":64,"response_ring_capacity":8,"forwarding_ring_capacity":16,"cli_input_queue_bytes":65536,"wasm_initial_memory_bytes":268435456},
  timing: {"ping_timeout_milliseconds":2000,"arp_timeout_seconds":14400,"telemetry_interval_milliseconds":250,"equipment_poll_milliseconds":250,"worker_shutdown_milliseconds":250,"worker_startup_poll_milliseconds":10,"worker_startup_attempts":200,"telemetry_read_attempts":4,"autosave_debounce_milliseconds":400},
  limits: {"system_name_bytes":64,"port_description_bytes":80,"host_name_bytes":64,"project_name_bytes":128},
  cliDefaults: {"ping_count":5,"ping_max_count":100000,"history_entries":50},
  abi: {"runtime_snapshot":3,"telemetry":4,"runtime_messages":2,"checkpoint":3},
  uiDefaults: {"router_id":"r1","inspector_width":324,"terminal_height":240,"nodes":{"host-a":{"x":72,"y":170},"r1":{"x":410,"y":170},"host-b":{"x":748,"y":170}}},
  profileHash: "bf930a8c47c9a9e8"
} as const;
