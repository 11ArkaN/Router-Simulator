// Built-in demo laboratory factories. This module owns portable project
// construction only, keeps every runtime transition outside contracts and
// depends only on the versioned project boundary.

import { createEmptyProjectV4, createRouterProjectV4, equippedRouterPorts,
  hostInterfaceId, parseLabProjectV4, PROFILE_CATALOG,
  type HostProjectV4, type LabProjectV4, type LinkProjectV4,
  type RouterProjectV4 } from "./lab-project-v4";

type InterfaceIntent = {
  name: string;
  portId: string;
  address: string;
  ospf?: {
    cost: number;
    passive: boolean;
    networkType: "point-to-point" | "broadcast";
  };
};

function port(router: RouterProjectV4, ordinal: number): string {
  const selected = router.running.ports[ordinal];
  if (!selected) throw new Error(`${router.id} has no port at ordinal ${ordinal}`);
  return selected.id;
}

function link(id: string, firstNode: string, firstPort: string,
  secondNode: string, secondPort: string): LinkProjectV4 {
  return { id, endpoints: [{ nodeId: firstNode, portId: firstPort },
    { nodeId: secondNode, portId: secondPort }], admin: "up",
    configuredSpeedMbps: null, propagationDelayNs: 100 };
}

function host(id: string, name: string, macSuffix: string,
  address: string, gateway: string): HostProjectV4 {
  return { id, kind: "host", name, eth0: {
    mac: `02:00:00:00:10:${macSuffix}`, address, gateway,
    mtu: PROFILE_CATALOG.ethernet.default_host_ipv4_mtu,
    mode: "ethernet",
    transportSecretHex: macSuffix.repeat(32),
    dns: { resolver: null, authoritative: null },
    ipv6: { autoconfiguration: true, interfaceId: hostInterfaceId(id),
      interfaceIdentifierMode: "modified-eui64", stableIidSecret: null,
      networkId: "", dhcpv6: { client: null, server: null } }
  } };
}

function configureRouter(router: RouterProjectV4,
  interfaces: readonly InterfaceIntent[],
  staticRoutes: readonly { prefix: string; nextHop: string }[]): void {
  const used = new Set(interfaces.map((item) => item.portId)
    .filter((value) => value.length > 0));
  router.running.ports = equippedRouterPorts(router).map((item) =>
    used.has(item.id) ? { ...item, admin: "up" } : item);
  router.running.interfaces = interfaces.map((item) => ({
    name: item.name,
    portId: item.portId,
    address: item.address,
    arpTimeoutSeconds: null,
    arpRetryTimerDeciseconds: null,
    ipv6Addresses: [],
    admin: "up"
  }));
  router.running.staticRoutes = staticRoutes.map((route) => ({
    ...route, indirect: false
  }));
  router.running.ipv6StaticRoutes = [];
}

function ospfInstance(routerId: string,
  interfaces: readonly InterfaceIntent[]):
  RouterProjectV4["running"]["ospf"]["instances"][number] {
  const defaults = PROFILE_CATALOG.protocol_defaults;
  return {
    instanceId: 0,
    addressFamily: "ipv4",
    routerId,
    exportPolicy: "",
    asbr: false,
    asbrTracePathDomainId: null,
    referenceBandwidthKbps: defaults.ospf_reference_bandwidth_kbps,
    routerPreference: defaults.ospf_router_preference,
    externalPreference: defaults.ospf_external_preference,
    spfTimersMilliseconds: {
      initial: defaults.ospf_spf_initial_wait_milliseconds,
      second: defaults.ospf_spf_second_wait_milliseconds,
      maximum: defaults.ospf_spf_maximum_wait_milliseconds
    },
    lsaTimersMilliseconds: {
      initial: defaults.ospf_lsa_initial_wait_milliseconds,
      second: defaults.ospf_lsa_second_wait_milliseconds,
      maximum: defaults.ospf_lsa_maximum_wait_milliseconds
    },
    gracefulRestartHelper: false,
    loopfreeAlternates: false,
    overload: false,
    admin: "up",
    areas: [{
      areaId: "0.0.0.0",
      type: "normal",
      defaultMetric: 1,
      summaries: true,
      nssaTranslateAlways: false,
      ranges: [],
      interfaces: interfaces.filter((item) => item.ospf).map((item) => ({
        interfaceName: item.name,
        cost: item.ospf!.cost,
        helloIntervalSeconds: defaults.ospf_hello_interval_seconds,
        deadIntervalSeconds: defaults.ospf_dead_interval_seconds,
        retransmitIntervalSeconds: defaults.ospf_retransmit_interval_seconds,
        transmitDelaySeconds: defaults.ospf_transmit_delay_seconds,
        priority: defaults.ospf_interface_priority,
        networkType: item.ospf!.networkType,
        authentication: "none",
        keychain: "",
        ipsecSaInbound: "",
        ipsecSaOutbound: "",
        passive: item.ospf!.passive,
        mtuMismatchIgnore: false,
        admin: "up",
        nbmaNeighbors: []
      })),
      virtualLinks: []
    }]
  };
}

// Preconditions: the generated SR-1 profile must expose at least two Ethernet
// ports. Postconditions: the returned project is format 4, has a fresh project
// identity and validates through parseLabProjectV4 before it crosses packages.
export function createStaticIpv4DemoLabV5(now = new Date()): LabProjectV4 {
  const project = createEmptyProjectV4(now);
  project.name = "Static IPv4 two-router demo";
  const r1 = createRouterProjectV4("r1", "7750-sr-1", "R1");
  const r2 = createRouterProjectV4("r2", "7750-sr-1", "R2");

  configureRouter(r1, [
    { name: "to-h1", portId: port(r1, 0), address: "192.0.2.1/30" },
    { name: "to-r2", portId: port(r1, 1), address: "10.0.12.1/30" }
  ], [{ prefix: "192.0.2.4/30", nextHop: "10.0.12.2" }]);
  configureRouter(r2, [
    { name: "to-r1", portId: port(r2, 0), address: "10.0.12.2/30" },
    { name: "to-h2", portId: port(r2, 1), address: "192.0.2.5/30" }
  ], [{ prefix: "192.0.2.0/30", nextHop: "10.0.12.1" }]);

  project.routers = [r1, r2];
  project.hosts = [
    host("h1", "Host A", "01", "192.0.2.2/30", "192.0.2.1"),
    host("h2", "Host B", "02", "192.0.2.6/30", "192.0.2.5")
  ];
  project.links = [
    link("h1-r1", "h1", "eth0", "r1", port(r1, 0)),
    link("r1-r2", "r1", port(r1, 1), "r2", port(r2, 0)),
    link("r2-h2", "r2", port(r2, 1), "h2", "eth0")
  ];
  project.layout.nodes = {
    h1: { x: 80, y: 250 },
    r1: { x: 300, y: 250 },
    r2: { x: 560, y: 250 },
    h2: { x: 780, y: 250 }
  };
  return parseLabProjectV4(project);
}

// Preconditions: the generated SR-1 profile must expose at least three
// Ethernet ports. Postconditions: the returned project is format 4, has a
// fresh project identity and validates through parseLabProjectV4 before it
// crosses packages.
export function createOspfTriangleDemoLabV5(now = new Date()): LabProjectV4 {
  const project = createEmptyProjectV4(now);
  project.name = "OSPF triangle failover demo";
  const r1 = createRouterProjectV4("r1", "7750-sr-1", "R1");
  const r2 = createRouterProjectV4("r2", "7750-sr-1", "R2");
  const r3 = createRouterProjectV4("r3", "7750-sr-1", "R3");

  const r1Interfaces: InterfaceIntent[] = [
    { name: "to-h1", portId: port(r1, 0), address: "198.51.100.1/30",
      ospf: { cost: 10, passive: true, networkType: "broadcast" } },
    { name: "to-r2", portId: port(r1, 1), address: "10.0.12.1/30",
      ospf: { cost: 10, passive: false, networkType: "point-to-point" } },
    { name: "to-r3-backup", portId: port(r1, 2), address: "10.0.13.1/30",
      ospf: { cost: 40, passive: false, networkType: "point-to-point" } }
  ];
  const r2Interfaces: InterfaceIntent[] = [
    { name: "to-r1", portId: port(r2, 0), address: "10.0.12.2/30",
      ospf: { cost: 10, passive: false, networkType: "point-to-point" } },
    { name: "to-r3", portId: port(r2, 1), address: "10.0.23.1/30",
      ospf: { cost: 10, passive: false, networkType: "point-to-point" } }
  ];
  const r3Interfaces: InterfaceIntent[] = [
    { name: "to-r2", portId: port(r3, 0), address: "10.0.23.2/30",
      ospf: { cost: 10, passive: false, networkType: "point-to-point" } },
    { name: "to-h2", portId: port(r3, 1), address: "198.51.100.9/30",
      ospf: { cost: 10, passive: true, networkType: "broadcast" } },
    { name: "to-r1-backup", portId: port(r3, 2), address: "10.0.13.2/30",
      ospf: { cost: 40, passive: false, networkType: "point-to-point" } }
  ];
  configureRouter(r1, r1Interfaces, []);
  configureRouter(r2, r2Interfaces, []);
  configureRouter(r3, r3Interfaces, []);
  r1.running.ospf.instances = [ospfInstance("10.255.0.1", r1Interfaces)];
  r2.running.ospf.instances = [ospfInstance("10.255.0.2", r2Interfaces)];
  r3.running.ospf.instances = [ospfInstance("10.255.0.3", r3Interfaces)];

  project.routers = [r1, r2, r3];
  project.hosts = [
    host("h1", "Branch host", "11", "198.51.100.2/30", "198.51.100.1"),
    host("h2", "Data center host", "12", "198.51.100.10/30", "198.51.100.9")
  ];
  project.links = [
    link("h1-r1", "h1", "eth0", "r1", port(r1, 0)),
    link("r1-r2", "r1", port(r1, 1), "r2", port(r2, 0)),
    link("r2-r3", "r2", port(r2, 1), "r3", port(r3, 0)),
    link("r3-h2", "r3", port(r3, 1), "h2", "eth0"),
    link("r1-r3-backup", "r1", port(r1, 2), "r3", port(r3, 2))
  ];
  project.layout.nodes = {
    h1: { x: 60, y: 320 },
    r1: { x: 260, y: 320 },
    r2: { x: 520, y: 170 },
    r3: { x: 780, y: 320 },
    h2: { x: 980, y: 320 }
  };
  return parseLabProjectV4(project);
}
