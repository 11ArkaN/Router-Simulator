// Typed projection of the canonical 7750 SR-7 profile. Full-output
// comparison in CI prevents browser defaults from drifting away from the YAML.

export const GENERATED_PROFILE = {
  id: "7750-sr-7-iom4-e",
  release: "26.7.R1",
  chassis: "7750 SR-7",
  chassisSlots: 5,
  portCount: 10,
  portSpeedMbps: 10000,
  cardInitializationMs: 2000,
  mdaInitializationMs: 1000,
  defaultPropagationDelayNs: 100,
  routerInterfaces: [
    { mac: "02:00:00:00:01:01", address: "192.0.2.1/30" },
    { mac: "02:00:00:00:01:02", address: "198.51.100.1/30" }
  ],
  hosts: [
    { id: "host-a", name: "Host A", mac: "02:00:00:00:00:0A", address: "192.0.2.2/30", gateway: "192.0.2.1" },
    { id: "host-b", name: "Host B", mac: "02:00:00:00:00:0B", address: "198.51.100.2/30", gateway: "198.51.100.1" }
  ]
} as const;
