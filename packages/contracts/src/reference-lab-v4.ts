// This module constructs the portable four-router conformance laboratory.
// It owns no live state and depends only on the public project contract. The
// runtime must treat the returned graph exactly like a user-created project.

import { createEmptyProjectV4, createRouterProjectV4, equippedRouterPorts,
  hostInterfaceId, parseLabProjectV4, PROFILE_CATALOG, type HostProjectV4, type LabProjectV4,
  type RouterProjectV4 } from "./lab-project-v4";

function equipEthernetCard(router: RouterProjectV4): void {
  // Each modular reference router needs three ordinary Ethernet ports.
  // Provisioned and physically equipped identities are both set because the
  // runtime correctly withholds port inventory while either side is absent.
  const profile = PROFILE_CATALOG.profiles.find(
    (candidate) => candidate.id === router.profileId);
  if (!profile || profile.fixed) return;
  const cardProfile = profile.cards.find((card) => card.mdas.some((type) => {
    const mda = PROFILE_CATALOG.mdas[type];
    return mda.ethernet && mda.ports.reduce((sum, group) => sum + group.count, 0) >= 3;
  }));
  const mdaType = cardProfile?.mdas.find((type) => {
    const mda = PROFILE_CATALOG.mdas[type];
    return mda.ethernet && mda.ports.reduce((sum, group) => sum + group.count, 0) >= 3;
  });
  if (!cardProfile || !mdaType) throw new Error("Reference router has no three-port Ethernet option");
  const card = router.hardware.cards[0];
  card.admin = "up";
  card.provisionedType = cardProfile.type;
  card.equippedType = cardProfile.type;
  card.mdas[0] = { slot: 1, admin: "up",
    provisionedType: mdaType, equippedType: mdaType };
  router.running.ports = equippedRouterPorts(router);
}

function port(router: RouterProjectV4, ordinal: number): string {
  // Physical identities are selected from generated inventory. The reference
  // topology therefore follows a catalog change instead of carrying a hidden
  // second list of slot, MDA and port numbers.
  const selected = router.running.ports[ordinal];
  if (!selected) throw new Error("Reference router has insufficient Ethernet ports");
  return selected.id;
}

function configureRouter(router: RouterProjectV4,
  interfaces: Array<{ name: string; portId: string; address: string }>,
  staticRoutes: Array<{ prefix: string; nextHop: string }>): void {
  // Port administration is independent from routed-interface administration.
  // Every used physical port is therefore enabled explicitly before creating
  // the IP interface that references it.
  const used = new Set(interfaces.map((item) => item.portId));
  router.running.ports = router.running.ports.map((port) => used.has(port.id)
    ? { ...port, admin: "up" } : port);
  router.running.interfaces = interfaces.map((item) => ({ ...item,
    arpTimeoutSeconds: null, arpRetryTimerDeciseconds: null,
    ipv6Addresses: [], admin: "up" }));
  router.running.staticRoutes = staticRoutes.map((route) => ({ ...route }));
  router.running.ipv6StaticRoutes = [];
}

function host(id: string, name: string, macSuffix: string,
  address: string, gateway: string): HostProjectV4 {
  // Locally administered unicast MAC addresses avoid claiming vendor OUIs.
  // Each /30 contains exactly its host and the attached router interface.
  return { id, kind: "host", name, eth0: {
    mac: `02:00:00:00:00:${macSuffix}`, address, gateway,
    mtu: PROFILE_CATALOG.ethernet.default_host_ipv4_mtu,
    mode: "ethernet", transportSecretHex: macSuffix.repeat(32),
    dns: { resolver: null, authoritative: null },
    ipv6: { autoconfiguration: true, interfaceId: hostInterfaceId(id),
      interfaceIdentifierMode: "modified-eui64", stableIidSecret: null,
      networkId: "", dhcpv6: { client: null, server: null } }
  } };
}

export function createFourRouterReferenceLabV4(): LabProjectV4 {
  const project = createEmptyProjectV4(new Date("2026-07-16T00:00:00.000Z"));
  project.projectId = "four-router-reference";
  project.name = "Four router reference lab";

  const fixedProfile = PROFILE_CATALOG.profiles.find((profile) => profile.fixed);
  const modularProfiles = [...PROFILE_CATALOG.profiles]
    .filter((profile) => !profile.fixed)
    .sort((left, right) => left.card_slots - right.card_slots);
  const compactModular = modularProfiles[0];
  const largestModular = modularProfiles.at(-1);
  if (!fixedProfile || !compactModular || !largestModular)
    throw new Error("Reference topology requires fixed and modular router profiles");
  const r1 = createRouterProjectV4("r1", fixedProfile.id, "R1");
  const r2 = createRouterProjectV4("r2", compactModular.id, "R2");
  const r3 = createRouterProjectV4("r3", largestModular.id, "R3");
  const r4 = createRouterProjectV4("r4", compactModular.id, "R4");
  for (const router of [r1, r2, r3, r4]) equipEthernetCard(router);

  configureRouter(r1, [
    { name: "to-h1", portId: port(r1, 0), address: "192.0.2.1/30" },
    { name: "to-r2", portId: port(r1, 1), address: "10.0.12.1/30" },
    { name: "to-r4", portId: port(r1, 2), address: "10.0.14.1/30" }
  ], [
    { prefix: "192.0.2.4/30", nextHop: "10.0.12.2" },
    { prefix: "192.0.2.8/30", nextHop: "10.0.12.2" },
    { prefix: "192.0.2.12/30", nextHop: "10.0.14.2" }
  ]);
  configureRouter(r2, [
    { name: "to-r1", portId: port(r2, 0), address: "10.0.12.2/30" },
    { name: "to-r3", portId: port(r2, 1), address: "10.0.23.1/30" },
    { name: "to-h2", portId: port(r2, 2), address: "192.0.2.5/30" }
  ], [
    { prefix: "192.0.2.0/30", nextHop: "10.0.12.1" },
    { prefix: "192.0.2.8/30", nextHop: "10.0.23.2" },
    { prefix: "192.0.2.12/30", nextHop: "10.0.23.2" }
  ]);
  configureRouter(r3, [
    { name: "to-r2", portId: port(r3, 0), address: "10.0.23.2/30" },
    { name: "to-r4", portId: port(r3, 1), address: "10.0.34.1/30" },
    { name: "to-h3", portId: port(r3, 2), address: "192.0.2.9/30" }
  ], [
    { prefix: "192.0.2.0/30", nextHop: "10.0.23.1" },
    { prefix: "192.0.2.4/30", nextHop: "10.0.23.1" },
    { prefix: "192.0.2.12/30", nextHop: "10.0.34.2" }
  ]);
  configureRouter(r4, [
    { name: "to-r3", portId: port(r4, 0), address: "10.0.34.2/30" },
    { name: "to-r1", portId: port(r4, 1), address: "10.0.14.2/30" },
    { name: "to-h4", portId: port(r4, 2), address: "192.0.2.13/30" }
  ], [
    { prefix: "192.0.2.0/30", nextHop: "10.0.14.1" },
    { prefix: "192.0.2.4/30", nextHop: "10.0.34.1" },
    { prefix: "192.0.2.8/30", nextHop: "10.0.34.1" }
  ]);

  project.routers = [r1, r2, r3, r4];
  project.hosts = [
    host("h1", "Host 1", "01", "192.0.2.2/30", "192.0.2.1"),
    host("h2", "Host 2", "02", "192.0.2.6/30", "192.0.2.5"),
    host("h3", "Host 3", "03", "192.0.2.10/30", "192.0.2.9"),
    host("h4", "Host 4", "04", "192.0.2.14/30", "192.0.2.13")
  ];

  // Eight independent cables create the four-router chain, four access links
  // and the direct R1-to-R4 path. Link delay is real monotonic propagation
  // time and is deliberately distinct from serialization time.
  project.links = [
    { id: "h1-r1", endpoints: [{ nodeId: "h1", portId: "eth0" },
      { nodeId: "r1", portId: port(r1, 0) }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r1-r2", endpoints: [{ nodeId: "r1", portId: port(r1, 1) },
      { nodeId: "r2", portId: port(r2, 0) }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r2-h2", endpoints: [{ nodeId: "r2", portId: port(r2, 2) },
      { nodeId: "h2", portId: "eth0" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r2-r3", endpoints: [{ nodeId: "r2", portId: port(r2, 1) },
      { nodeId: "r3", portId: port(r3, 0) }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r3-h3", endpoints: [{ nodeId: "r3", portId: port(r3, 2) },
      { nodeId: "h3", portId: "eth0" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r3-r4", endpoints: [{ nodeId: "r3", portId: port(r3, 1) },
      { nodeId: "r4", portId: port(r4, 0) }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r4-h4", endpoints: [{ nodeId: "r4", portId: port(r4, 2) },
      { nodeId: "h4", portId: "eth0" }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 },
    { id: "r1-r4", endpoints: [{ nodeId: "r1", portId: port(r1, 2) },
      { nodeId: "r4", portId: port(r4, 1) }], admin: "up", configuredSpeedMbps: null, propagationDelayNs: 100 }
  ];
  project.layout.nodes = {
    h1: { x: 40, y: 310 }, r1: { x: 220, y: 310 },
    r2: { x: 480, y: 180 }, h2: { x: 480, y: 20 },
    r3: { x: 740, y: 180 }, h3: { x: 740, y: 20 },
    r4: { x: 1000, y: 310 }, h4: { x: 1180, y: 310 }
  };
  return parseLabProjectV4(project);
}
