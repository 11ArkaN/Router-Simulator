// Versioned browser contracts for projects, runtime projections and netsim
// manifests. Parsers reject incompatible or partial external data before use.

import { GENERATED_PROFILE } from "./generated-profile";

export { GENERATED_PROFILE };

export const ABI_VERSION = 3 as const;
export const PROJECT_VERSION = 1 as const;

// Runtime ABI and persisted project format evolve independently. A compatible
// project import must not imply compatibility with an in-memory Wasm snapshot.

export type CliEngine = "md" | "classic";
export type RuntimeStatus = "booting" | "ready" | "blocked" | "stopped";
export type OperState = "up" | "down" | "absent";

export interface HostConfig {
  id: "host-a" | "host-b";
  name: string;
  mac: string;
  address: string;
  gateway: string;
}

export interface LinkConfig {
  // Propagation delay describes one physical medium in both full-duplex
  // directions. Ethernet serialization remains derived from the port speed.
  id: "host-a-r1" | "r1-host-b";
  propagationDelayNs: number;
}

export interface HardwareState {
  chassis: typeof GENERATED_PROFILE.chassis;
  cpmA: "active-ready";
  card1Provisioned: "absent" | "iom4-e";
  mda11Provisioned: "absent" | "me10-10gb-sfp+";
  card1: "absent" | "iom4-e";
  mda11: "absent" | "me10-10gb-sfp+" | "me1-100gb-cfp2";
  cardLifecycle?: "absent" | "waiting-provisioning" | "waiting-parent" | "initializing" | "ready" | "mismatch";
  mdaLifecycle?: "absent" | "waiting-provisioning" | "waiting-parent" | "initializing" | "ready" | "mismatch";
  cardReason?: string;
  mdaReason?: string;
}

export interface PortState {
  // Ports are a hardware inventory projection. The union cannot be fixed to
  // the two links in the starter topology because an equipped me10 MDA owns ten
  // physical ports even when only two are wired.
  id: string;
  admin: "up" | "down";
  oper: OperState;
  speedMbps: number;
  mtu: number;
  description: string;
  rxPackets: number;
  txPackets: number;
}

export interface RuntimeSnapshot {
  // This interface is an immutable operational projection consumed by UI at a
  // bounded rate. Canonical counters, routes, and adjacency state stay in C++.
  abiVersion: typeof ABI_VERSION;
  status: RuntimeStatus;
  nowMs: number;
  hardware: HardwareState;
  ports: PortState[];
  arp: Array<{ address: string; mac: string; port: string }>;
  routes: Array<{ prefix: string; nextHop: string; port: string; source: "local" | "static" }>;
  captureCount: number;
  captureDropped: number;
  droppedPackets: number;
  lastDropReason?: string;
  alarms: Array<{ id: string; severity: "minor" | "major" | "critical"; reason: string }>;
  runningConfig: RunningConfig;
}

export interface RunningConfig {
  systemName: string;
  ports: Array<{ id: string; admin: "up" | "down"; mtu: number; description: string }>;
  interfaces: Array<{ name: "to-host-a" | "to-host-b"; admin: "up" | "down" }>;
  staticRoutes: Array<{ prefix: string; nextHop: string }>;
}

export interface UiLayout {
  nodes: Record<"host-a" | "r1" | "host-b", { x: number; y: number }>;
  inspectorWidth: number;
  terminalHeight: number;
}

export interface ProjectManifestV1 {
  mode: "project" | "checkpoint";
  formatVersion: 1;
  profileLock: { id: typeof GENERATED_PROFILE.id; release: typeof GENERATED_PROFILE.release };
  project: LabProject;
  captureBase64?: string;
  checkpointBase64?: string;
}

export interface CheckpointHeaderV1 {
  format: 1;
  abiVersion: typeof ABI_VERSION;
  buildHash: string;
  profile: typeof GENERATED_PROFILE.id;
}

function isHardwareState(input: unknown): input is HardwareState {
  if (!input || typeof input !== "object") return false;
  const hardware = input as Partial<HardwareState>;
  return hardware.chassis === GENERATED_PROFILE.chassis &&
    hardware.cpmA === "active-ready" &&
    ["absent", "iom4-e"].includes(hardware.card1 ?? "") &&
    ["absent", "me10-10gb-sfp+", "me1-100gb-cfp2"].includes(hardware.mda11 ?? "") &&
    ["absent", "iom4-e"].includes(hardware.card1Provisioned ?? "") &&
    ["absent", "me10-10gb-sfp+"].includes(hardware.mda11Provisioned ?? "") &&
    !(hardware.card1Provisioned === "absent" && hardware.mda11Provisioned !== "absent") &&
    !(hardware.card1 === "absent" && hardware.mda11 !== "absent");
}

export function parseRuntimeSnapshot(input: unknown): RuntimeSnapshot {
  // A TypeScript assertion does not validate data crossing Wasm memory and the
  // Worker message boundary. Rejecting the wrong ABI before rendering prevents
  // a newer C++ layout from being interpreted with stale UI semantics.
  if (!input || typeof input !== "object") throw new Error("Runtime snapshot must be an object");
  const value = input as Partial<RuntimeSnapshot>;
  const finiteCounter = (candidate: unknown) => typeof candidate === "number" &&
    Number.isFinite(candidate) && candidate >= 0;
  if (value.abiVersion !== ABI_VERSION ||
      !["booting", "ready", "blocked", "stopped"].includes(value.status ?? "") ||
      !finiteCounter(value.nowMs) || !isHardwareState(value.hardware) ||
      !Array.isArray(value.ports) || value.ports.length > GENERATED_PROFILE.portCount ||
      !Array.isArray(value.arp) || !Array.isArray(value.routes) || !Array.isArray(value.alarms) ||
      !value.runningConfig || typeof value.runningConfig.systemName !== "string" ||
      !Array.isArray(value.runningConfig.ports) || !Array.isArray(value.runningConfig.interfaces) ||
      !Array.isArray(value.runningConfig.staticRoutes) ||
      !finiteCounter(value.captureCount) || !finiteCounter(value.captureDropped) ||
      !finiteCounter(value.droppedPackets)) {
    throw new Error("Runtime snapshot has an incompatible ABI or shape");
  }
  const portIds = new Set<string>();
  if (value.ports.some((port) => !port || !/^1\/1\/(?:[1-9]|10)$/.test(port.id) ||
      portIds.has(port.id) || !portIds.add(port.id) ||
      !["up", "down"].includes(port.admin) ||
      !["up", "down", "absent"].includes(port.oper) ||
      !finiteCounter(port.speedMbps) || !finiteCounter(port.mtu) ||
      typeof port.description !== "string" || !finiteCounter(port.rxPackets) ||
      !finiteCounter(port.txPackets)) ||
      value.arp.some((entry) => !entry || typeof entry.address !== "string" ||
        typeof entry.mac !== "string" || typeof entry.port !== "string") ||
      value.routes.some((route) => !route || typeof route.prefix !== "string" ||
        typeof route.nextHop !== "string" || typeof route.port !== "string" ||
        !["local", "static"].includes(route.source)) ||
      (value.lastDropReason !== undefined && typeof value.lastDropReason !== "string")) {
    throw new Error("Runtime snapshot contains invalid operational data");
  }
  return value as RuntimeSnapshot;
}

export interface LabProject {
  // Release and hardware profile are explicit compatibility keys. Mixing
  // defaults from other SR OS releases is rejected during import.
  format: "router-simulator-project";
  version: typeof PROJECT_VERSION;
  release: typeof GENERATED_PROFILE.release;
  profile: typeof GENERATED_PROFILE.id;
  name: string;
  hosts: [HostConfig, HostConfig];
  links: [LinkConfig, LinkConfig];
  hardware: HardwareState;
  runningConfig: RunningConfig;
  layout: UiLayout;
  updatedAt: string;
}

export const DEFAULT_PROJECT: LabProject = {
  // Documentation address ranges and locally administered MAC addresses make
  // the default lab deterministic without colliding with real infrastructure.
  format: "router-simulator-project",
  version: PROJECT_VERSION,
  release: GENERATED_PROFILE.release,
  profile: GENERATED_PROFILE.id,
  name: "SR-7 routed path",
  hosts: [{ ...GENERATED_PROFILE.hosts[0] }, { ...GENERATED_PROFILE.hosts[1] }],
  links: [
    { id: "host-a-r1", propagationDelayNs: GENERATED_PROFILE.defaultPropagationDelayNs },
    { id: "r1-host-b", propagationDelayNs: GENERATED_PROFILE.defaultPropagationDelayNs }
  ],
  hardware: {
    chassis: GENERATED_PROFILE.chassis,
    cpmA: "active-ready",
    card1Provisioned: "absent",
    mda11Provisioned: "absent",
    card1: "absent",
    mda11: "absent"
  },
  runningConfig: {
    systemName: "R1",
    ports: Array.from({ length: GENERATED_PROFILE.portCount }, (_, index) => ({
      id: `1/1/${index + 1}`, admin: "up" as const, mtu: 1500, description: ""
    })),
    interfaces: [
      { name: "to-host-a", admin: "up" },
      { name: "to-host-b", admin: "up" }
    ],
    staticRoutes: []
  },
  layout: {
    nodes: { "host-a": { x: 72, y: 170 }, r1: { x: 410, y: 170 }, "host-b": { x: 748, y: 170 } },
    inspectorWidth: 324,
    terminalHeight: 240
  },
  updatedAt: "2026-07-14T00:00:00.000Z"
};

export function parseProject(input: unknown): LabProject {
  // Validation fails closed before persisted data reaches the runtime. The
  // narrow first format can be extended with version-specific migrations later.
  if (!input || typeof input !== "object") throw new Error("Project must be an object");
  const value = input as Partial<LabProject>;
  if (value.format !== "router-simulator-project" || value.version !== PROJECT_VERSION) {
    throw new Error("Unsupported project format or version");
  }
  if (value.release !== GENERATED_PROFILE.release || value.profile !== GENERATED_PROFILE.id) {
    throw new Error("Unsupported release or hardware profile");
  }
  if (!Array.isArray(value.hosts) || value.hosts.length !== 2 || !value.hardware) {
    throw new Error("Project is missing required topology state");
  }
  // Projects saved before per-link timing existed had one implicit profile
  // delay. Normalize only that absent field. Malformed or partial arrays are
  // rejected instead of silently replacing user data.
  const links = value.links === undefined
    ? structuredClone(DEFAULT_PROJECT.links)
    : value.links;
  const runningConfig = value.runningConfig ?? structuredClone(DEFAULT_PROJECT.runningConfig);
  const layout = value.layout ?? structuredClone(DEFAULT_PROJECT.layout);
  // Source: ecma.number.max_safe_integer. Number.isSafeInteger rejects values
  // that JSON could already have rounded to a neighboring nanosecond.
  if (!Array.isArray(links) || links.length !== 2 ||
      links[0]?.id !== "host-a-r1" || links[1]?.id !== "r1-host-b" ||
      links.some((link) => !Number.isSafeInteger(link?.propagationDelayNs) ||
        link.propagationDelayNs < 0)) {
    throw new Error("Project contains invalid link propagation");
  }
  // Persisted and imported projects are untrusted input. Exact endpoint IDs,
  // MAC syntax and CIDR syntax are validated here, then C++ repeats semantic
  // subnet checks before committing values to the forwarding owner.
  const mac = /^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
  const cidr = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12]\d|3[0-2])$/;
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const octets = (address: string) => address.split(/[./]/).slice(0, 4).map(Number);
  const validOctets = (address: string) => octets(address)
    .every((octet) => octet >= 0 && octet <= 255);
  const ipv4Number = (address: string) => octets(address)
    .reduce((result, octet) => ((result * 256) + octet) >>> 0, 0);

  // Tuple order is part of the topology contract. Accepting the two IDs in a
  // reversed order would pass structural validation but connect UI labels and
  // edits to the wrong physical link after restoration.
  if (value.hosts[0]?.id !== "host-a" || value.hosts[1]?.id !== "host-b" ||
      value.hosts.some((host) =>
    !host || typeof host.name !== "string" || !host.name.trim() || host.name.length > 64 ||
    !mac.test(host.mac) ||
    !cidr.test(host.address) || !ipv4.test(host.gateway) ||
    !validOctets(host.address) || !validOctets(host.gateway))) {
    throw new Error("Project contains an invalid host configuration");
  }

  for (const host of value.hosts) {
    // Source: ietf.host_requirements.rfc1122. A host first determines whether
    // the destination or gateway is on its directly connected network. Keeping
    // address and gateway in different prefixes would make the configured
    // first hop unreachable without an undocumented recursive route.
    const prefix = Number(host.address.split("/")[1]);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const address = ipv4Number(host.address);
    const gateway = ipv4Number(host.gateway);
    const hostBits = (~mask) >>> 0;
    const addressHost = address & hostBits;
    const gatewayHost = gateway & hostBits;
    // Source: ietf.host_requirements.rfc1122. This Ethernet endpoint accepts
    // unicast interface and first-hop addresses only. For traditional prefixes
    // through /30, all-zero and all-one host portions are network and directed
    // broadcast addresses. /31 remains available for point-to-point profiles.
    const validUnicast = (candidate: number) => {
      const first = candidate >>> 24;
      return candidate !== 0 && candidate !== 0xffffffff && first !== 0 &&
        first !== 127 && first < 224;
    };
    if ((address & mask) !== (gateway & mask) || address === gateway ||
        !validUnicast(address) || !validUnicast(gateway) ||
        (prefix <= 30 && (addressHost === 0 || addressHost === hostBits ||
                          gatewayHost === 0 || gatewayHost === hostBits))) {
      throw new Error("Host gateway must be a different address in the local prefix");
    }
  }

  // Duplicate endpoint identities are rejected before they can make ARP
  // learning depend on packet order. Case folding is required because MAC text
  // is case-insensitive even though the persisted spelling is preserved.
  // Source: ieee.802_3.ethernet_frame_timing. An individual endpoint source
  // address cannot be the all-zero value, broadcast, or any group address.
  const hostMacs = value.hosts.map((host) => host.mac.toLowerCase());
  const routerMacs = GENERATED_PROFILE.routerInterfaces.map((item) => item.mac.toLowerCase());
  const invalidMac = (address: string) => address === "00:00:00:00:00:00" ||
    (Number.parseInt(address.slice(0, 2), 16) & 1) !== 0;
  const routerAddresses = GENERATED_PROFILE.routerInterfaces.map((item) => ipv4Number(item.address));
  if (hostMacs[0] === hostMacs[1] || hostMacs.some((address) =>
        invalidMac(address) || routerMacs.includes(address)) ||
      ipv4Number(value.hosts[0].address) === ipv4Number(value.hosts[1].address) ||
      value.hosts.some((host) => routerAddresses.includes(ipv4Number(host.address)))) {
    throw new Error("Project contains invalid or duplicate endpoint identity");
  }
  if (typeof value.name !== "string" || !value.name.trim() || value.name.length > 128 ||
      typeof value.updatedAt !== "string" || Number.isNaN(Date.parse(value.updatedAt))) {
    throw new Error("Project contains invalid metadata");
  }
  if (!isHardwareState(value.hardware)) {
    throw new Error("Project contains unsupported hardware state");
  }
  if (typeof runningConfig.systemName !== "string" || !runningConfig.systemName.trim() ||
      runningConfig.systemName.length > 64 || runningConfig.ports.length !== GENERATED_PROFILE.portCount ||
      runningConfig.ports.some((port, index) => port.id !== `1/1/${index + 1}` ||
        !["up", "down"].includes(port.admin) || !Number.isInteger(port.mtu) ||
        port.mtu < 576 || port.mtu > 1500 || typeof port.description !== "string" ||
        port.description.length > 64 || /["\r\n]/.test(port.description)) || runningConfig.interfaces.length !== 2 ||
      runningConfig.interfaces.some((item, index) => item.name !== ["to-host-a", "to-host-b"][index] ||
        !["up", "down"].includes(item.admin)) || runningConfig.staticRoutes.length > 8 ||
      runningConfig.staticRoutes.some((route) => !route || !cidr.test(route.prefix) ||
        !ipv4.test(route.nextHop) || !validOctets(route.prefix) || !validOctets(route.nextHop))) {
    throw new Error("Project contains invalid running configuration");
  }
  const staticPrefixes = new Set<string>();
  for (const route of runningConfig.staticRoutes) {
    // A route key represents a network, not an arbitrary address plus mask.
    // Rejecting host bits keeps project restore identical to the C++ CLI
    // validator and prevents two spellings of the same prefix entering RIB.
    const [addressText, prefixText] = route.prefix.split("/");
    const prefix = Number(prefixText);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const address = ipv4Number(addressText);
    if ((address & mask) !== address || staticPrefixes.has(route.prefix)) {
      throw new Error("Static route prefixes must be canonical and unique");
    }
    staticPrefixes.add(route.prefix);
  }
  const finitePosition = (point: { x?: unknown; y?: unknown } | undefined) => point &&
    typeof point.x === "number" && Number.isFinite(point.x) &&
    typeof point.y === "number" && Number.isFinite(point.y);
  if (!layout.nodes || !finitePosition(layout.nodes["host-a"]) || !finitePosition(layout.nodes.r1) ||
      !finitePosition(layout.nodes["host-b"]) || !Number.isFinite(layout.inspectorWidth) ||
      !Number.isFinite(layout.terminalHeight)) {
    throw new Error("Project contains invalid UI layout");
  }
  // Returning a fresh object makes legacy normalization observable to the
  // persistence layer without mutating the untrusted input supplied by caller.
  return { ...value, links, runningConfig, layout } as LabProject;
}
