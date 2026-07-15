// Versioned browser contracts for projects, runtime projections and netsim
// manifests. All profile-dependent identities come from generated data.

import { GENERATED_PROFILE } from "./generated-profile";
export { GENERATED_PROFILE };
export { RUNTIME_PROTOCOL } from "./generated-runtime-protocol";

export const ABI_VERSION = GENERATED_PROFILE.abi.runtime_snapshot;
export const PROJECT_VERSION = 1 as const;

export type CliEngine = "md" | "classic";
export type RuntimeStatus = "booting" | "ready" | "blocked" | "stopped";
export type OperState = "up" | "down" | "absent";
export type EquipmentLifecycle = "absent" | "waiting-provisioning" |
  "waiting-parent" | "initializing" | "ready" | "mismatch";

export interface HostConfig {
  id: string;
  name: string;
  mac: string;
  address: string;
  gateway: string;
}

export interface LinkConfig {
  id: string;
  host: string;
  routerPort: string;
  propagationDelayNs: number;
}

export interface MdaState {
  slot: number;
  provisionedType: string | null;
  equippedType: string | null;
  compatible: boolean;
  lifecycle: EquipmentLifecycle;
  reason: string;
}

export interface CardState {
  slot: number;
  provisionedType: string | null;
  equippedType: string | null;
  compatible: boolean;
  lifecycle: EquipmentLifecycle;
  reason: string;
  mdas: MdaState[];
}

export interface HardwareState {
  chassis: string;
  control: { slot: string; type: string; state: string };
  cards: CardState[];
}

// Projects store user intent only. Compatibility, lifecycle and reason are
// live reconciler outputs and cannot be replayed as desired hardware state.
export interface ProjectMdaHardware {
  slot: number;
  provisionedType: string | null;
  equippedType: string | null;
}

export interface ProjectCardHardware {
  slot: number;
  provisionedType: string | null;
  equippedType: string | null;
  mdas: ProjectMdaHardware[];
}

export interface ProjectHardware {
  cards: ProjectCardHardware[];
}

export interface PortState {
  id: string;
  admin: "up" | "down";
  oper: OperState;
  speedMbps: number;
  mtu: number;
  description: string;
  rxPackets: number;
  txPackets: number;
}

export interface RunningConfig {
  systemName: string;
  ports: Array<{ id: string; admin: "up" | "down"; mtu: number; description: string }>;
  interfaces: Array<{ name: string; admin: "up" | "down" }>;
  staticRoutes: Array<{ prefix: string; nextHop: string }>;
}

export interface RuntimeSnapshot {
  // C++ owns this immutable operational projection. The browser validates the
  // generated ABI before any values can reach rendering or persistence.
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

export interface UiLayout {
  nodes: Record<string, { x: number; y: number }>;
  inspectorWidth: number;
  terminalHeight: number;
}

export interface LabProject {
  format: "router-simulator-project";
  version: typeof PROJECT_VERSION;
  release: typeof GENERATED_PROFILE.release;
  profile: typeof GENERATED_PROFILE.id;
  name: string;
  hosts: HostConfig[];
  links: LinkConfig[];
  hardware: ProjectHardware;
  runningConfig: RunningConfig;
  layout: UiLayout;
  updatedAt: string;
}

export interface ProjectManifestV1 {
  mode: "project" | "checkpoint";
  formatVersion: 1;
  profileLock: { id: typeof GENERATED_PROFILE.id; release: typeof GENERATED_PROFILE.release };
  project: LabProject;
  captureBase64?: string;
  checkpointBase64?: string;
}

const lifecycleValues = new Set<EquipmentLifecycle>([
  "absent", "waiting-provisioning", "waiting-parent", "initializing", "ready", "mismatch"
]);
const knownPorts = new Set<string>(GENERATED_PROFILE.ports.ids);
const knownHosts = new Set<string>(GENERATED_PROFILE.hosts.map((host) => host.id));
// Counters cross JSON and shared memory as Numbers. They must be finite and
// non-negative before arithmetic or display.
const finiteCounter = (candidate: unknown): candidate is number =>
  typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0;

// Validates one card or MDA record against generated slot identity and type
// capabilities. Provisioning and equipped inventory intentionally use distinct
// allowed sets because mismatch inventory must remain representable.
function isEquipment(input: unknown, cardSlot: number, mda = false): input is CardState | MdaState {
  if (!input || typeof input !== "object") return false;
  const value = input as Partial<CardState>;
  const allowedProvisioned: Array<string | null> = mda
    ? [null, GENERATED_PROFILE.mda.modeledType]
    : [null, GENERATED_PROFILE.lineCard.type];
  const allowedEquipped: Array<string | null> = mda
    ? [null, ...GENERATED_PROFILE.mda.supportedTypes]
    : [null, GENERATED_PROFILE.lineCard.type];
  return value.slot === cardSlot && allowedProvisioned.includes(value.provisionedType ?? null) &&
    allowedEquipped.includes(value.equippedType ?? null) && typeof value.compatible === "boolean" &&
    lifecycleValues.has(value.lifecycle as EquipmentLifecycle) && typeof value.reason === "string";
}

// Project equipment validation accepts only desired provisioned and equipped
// types. Rejecting extra operational fields prevents imported files from
// pretending to own hardware lifecycle, compatibility or alarm reasons.
function isProjectEquipment(input: unknown, slot: number, mda = false):
  input is ProjectCardHardware | ProjectMdaHardware {
  if (!input || typeof input !== "object") return false;
  const value = input as Partial<ProjectCardHardware>;
  const keys = Object.keys(value);
  const expectedKeys = mda
    ? ["slot", "provisionedType", "equippedType"]
    : ["slot", "provisionedType", "equippedType", "mdas"];
  if (keys.length !== expectedKeys.length || keys.some((key) => !expectedKeys.includes(key))) return false;
  const allowedProvisioned: Array<string | null> = mda
    ? [null, GENERATED_PROFILE.mda.modeledType]
    : [null, GENERATED_PROFILE.lineCard.type];
  const allowedEquipped: Array<string | null> = mda
    ? [null, ...GENERATED_PROFILE.mda.supportedTypes]
    : [null, GENERATED_PROFILE.lineCard.type];
  return value.slot === slot && allowedProvisioned.includes(value.provisionedType ?? null) &&
    allowedEquipped.includes(value.equippedType ?? null);
}

// The project chassis keeps every generated slot explicit, but only the
// profile-modeled slot may contain equipment in the current capability set.
function isProjectHardware(input: unknown): input is ProjectHardware {
  if (!input || typeof input !== "object" || !("cards" in input) ||
      !Array.isArray(input.cards) || input.cards.length !== GENERATED_PROFILE.chassisSlots) return false;
  return input.cards.every((card, cardIndex) => {
    if (!isProjectEquipment(card, cardIndex + 1)) return false;
    // The false branch above proves the outer record is the card variant. The
    // shared validator intentionally also serves child records to keep type and
    // slot rules in one place, so narrow the parent before inspecting mdas.
    const projectCard = card as ProjectCardHardware;
    if (!Array.isArray(projectCard.mdas) ||
        projectCard.mdas.length !== GENERATED_PROFILE.mda.slotsPerCard) return false;
    const modeled = projectCard.slot === GENERATED_PROFILE.lineCard.slot;
    if (!modeled && (projectCard.provisionedType !== null || projectCard.equippedType !== null)) return false;
    if ((projectCard.provisionedType === null && projectCard.mdas.some((item) => item.provisionedType !== null)) ||
        (projectCard.equippedType === null && projectCard.mdas.some((item) => item.equippedType !== null))) return false;
    return projectCard.mdas.every((item, mdaIndex) => isProjectEquipment(item, mdaIndex + 1, true));
  });
}

// Validates the complete bounded chassis tree including parent-child presence.
// Slots outside the modeled line-card position must remain explicitly empty.
function isHardwareState(input: unknown): input is HardwareState {
  if (!input || typeof input !== "object") return false;
  const hardware = input as Partial<HardwareState>;
  if (hardware.chassis !== GENERATED_PROFILE.chassis || !hardware.control ||
      hardware.control.slot !== GENERATED_PROFILE.control.slot ||
      hardware.control.type !== GENERATED_PROFILE.control.card ||
      hardware.control.state !== GENERATED_PROFILE.control.initial_state ||
      !Array.isArray(hardware.cards) || hardware.cards.length !== GENERATED_PROFILE.chassisSlots) return false;
  return hardware.cards.every((card, cardIndex) => {
    if (!isEquipment(card, cardIndex + 1) || !Array.isArray(card.mdas) ||
        card.mdas.length !== GENERATED_PROFILE.mda.slotsPerCard) return false;
    const isModeledSlot = card.slot === GENERATED_PROFILE.lineCard.slot;
    if (!isModeledSlot && (card.provisionedType !== null || card.equippedType !== null)) return false;
    if ((card.provisionedType === null && card.mdas.some((mda) => mda.provisionedType !== null)) ||
        (card.equippedType === null && card.mdas.some((mda) => mda.equippedType !== null))) return false;
    return card.mdas.every((mda, mdaIndex) => isEquipment(mda, mdaIndex + 1, true));
  });
}

// Constructs portable desired hardware state without borrowing runtime objects.
// Operational lifecycle will be reconciled again after project restoration.
function emptyHardware(): ProjectHardware {
  return {
    cards: Array.from({ length: GENERATED_PROFILE.chassisSlots }, (_, cardIndex) => ({
      slot: cardIndex + 1,
      provisionedType: null,
      equippedType: null,
      mdas: Array.from({ length: GENERATED_PROFILE.mda.slotsPerCard }, (_, mdaIndex) => ({
        slot: mdaIndex + 1,
        provisionedType: null,
        equippedType: null
      }))
    }))
  };
}

// Creates a fresh project from generated profile data. Injectable time makes
// deterministic tests possible while real projects receive their creation time.
export function createDefaultProject(now = new Date()): LabProject {
  return {
    format: "router-simulator-project",
    version: PROJECT_VERSION,
    release: GENERATED_PROFILE.release,
    profile: GENERATED_PROFILE.id,
    name: `${GENERATED_PROFILE.chassis} routed path`,
    hosts: GENERATED_PROFILE.hosts.map((host) => ({ ...host })),
    links: GENERATED_PROFILE.links.map((link) => ({
      id: link.id,
      host: link.host,
      routerPort: link.router_port,
      propagationDelayNs: GENERATED_PROFILE.defaultPropagationDelayNs
    })),
    hardware: emptyHardware(),
    runningConfig: {
      systemName: GENERATED_PROFILE.defaultSystemName,
      ports: GENERATED_PROFILE.ports.ids.map((id) => ({
        id, admin: "up" as const, mtu: GENERATED_PROFILE.ports.defaultMtu, description: ""
      })),
      interfaces: GENERATED_PROFILE.routerInterfaces.map((item) => ({ name: item.name, admin: "up" as const })),
      staticRoutes: []
    },
    layout: {
      nodes: structuredClone(GENERATED_PROFILE.uiDefaults.nodes),
      inspectorWidth: GENERATED_PROFILE.uiDefaults.inspector_width,
      terminalHeight: GENERATED_PROFILE.uiDefaults.terminal_height
    },
    updatedAt: now.toISOString()
  };
}

export const DEFAULT_PROJECT = createDefaultProject();

// Checks untrusted Wasm JSON before React can render it. ABI, bounded arrays,
// generated identities and numeric ranges all fail closed on mismatch.
export function parseRuntimeSnapshot(input: unknown): RuntimeSnapshot {
  if (!input || typeof input !== "object") throw new Error("Runtime snapshot must be an object");
  const value = input as Partial<RuntimeSnapshot>;
  if (value.abiVersion !== ABI_VERSION ||
      !["booting", "ready", "blocked", "stopped"].includes(value.status ?? "") ||
      !finiteCounter(value.nowMs) || !isHardwareState(value.hardware) ||
      !Array.isArray(value.ports) || value.ports.length > GENERATED_PROFILE.ports.count ||
      !Array.isArray(value.arp) || !Array.isArray(value.routes) || !Array.isArray(value.alarms) ||
      !value.runningConfig || typeof value.runningConfig.systemName !== "string" ||
      !Array.isArray(value.runningConfig.ports) || !Array.isArray(value.runningConfig.interfaces) ||
      !Array.isArray(value.runningConfig.staticRoutes) || !finiteCounter(value.captureCount) ||
      !finiteCounter(value.captureDropped) || !finiteCounter(value.droppedPackets)) {
    throw new Error("Runtime snapshot has an incompatible ABI or shape");
  }
  const seenPorts = new Set<string>();
  if (value.ports.some((port) => !port || !knownPorts.has(port.id) || seenPorts.has(port.id) ||
      !seenPorts.add(port.id) || !["up", "down"].includes(port.admin) ||
      !["up", "down", "absent"].includes(port.oper) ||
      port.speedMbps !== GENERATED_PROFILE.ports.speedMbps ||
      !Number.isInteger(port.mtu) || port.mtu < GENERATED_PROFILE.ports.minimumMtu ||
      port.mtu > GENERATED_PROFILE.ports.maximumMtu || typeof port.description !== "string" ||
      !finiteCounter(port.rxPackets) || !finiteCounter(port.txPackets)) ||
      value.arp.some((entry) => !entry || typeof entry.address !== "string" ||
        typeof entry.mac !== "string" || !knownPorts.has(entry.port)) ||
      value.routes.some((route) => !route || typeof route.prefix !== "string" ||
        typeof route.nextHop !== "string" || !knownPorts.has(route.port) ||
        !["local", "static"].includes(route.source)) ||
      (value.lastDropReason !== undefined && typeof value.lastDropReason !== "string")) {
    throw new Error("Runtime snapshot contains invalid operational data");
  }
  return value as RuntimeSnapshot;
}

// Validates imported or persisted project data before any runtime mutation.
// Optional fields from the first project format are normalized from generated
// defaults, while malformed present values are never replaced silently.
export function parseProject(input: unknown): LabProject {
  if (!input || typeof input !== "object") throw new Error("Project must be an object");
  const value = input as Partial<LabProject>;
  if (value.format !== "router-simulator-project" || value.version !== PROJECT_VERSION ||
      value.release !== GENERATED_PROFILE.release || value.profile !== GENERATED_PROFILE.id) {
    throw new Error("Unsupported project format, release or profile");
  }
  const links = value.links ?? structuredClone(DEFAULT_PROJECT.links);
  const running = value.runningConfig ?? structuredClone(DEFAULT_PROJECT.runningConfig);
  const layout = value.layout ?? structuredClone(DEFAULT_PROJECT.layout);
  if (!Array.isArray(value.hosts) || value.hosts.length !== GENERATED_PROFILE.hosts.length ||
      !Array.isArray(links) || links.length !== GENERATED_PROFILE.links.length || !value.hardware) {
    throw new Error("Project is missing required topology state");
  }
  const macPattern = /^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
  const cidrPattern = /^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12]\d|3[0-2])$/;
  const ipv4Pattern = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const octets = (address: string) => address.split(/[./]/).slice(0, 4).map(Number);
  // Text syntax alone accepts octets above 255, so semantic range validation is
  // performed before addresses are reduced to an integer.
  const validOctets = (address: string) => octets(address).every((octet) => octet >= 0 && octet <= 255);
  // Network-order arithmetic avoids platform parsing differences and is exact
  // for four validated octets under JavaScript Number semantics.
  const ipv4Number = (address: string) => octets(address)
    .reduce((result, octet) => ((result * 256) + octet) >>> 0, 0);
  if (value.hosts.some((host, index) => !host || host.id !== GENERATED_PROFILE.hosts[index]?.id ||
      typeof host.name !== "string" || !host.name.trim() ||
      host.name.length > GENERATED_PROFILE.limits.host_name_bytes ||
      !macPattern.test(host.mac) || !cidrPattern.test(host.address) || !ipv4Pattern.test(host.gateway) ||
      !validOctets(host.address) || !validOctets(host.gateway))) {
    throw new Error("Project contains an invalid host configuration");
  }
  for (const host of value.hosts) {
    // RFC 1122 requires the configured first hop to be reachable on the local
    // network. Network and broadcast addresses remain invalid through /30.
    const prefix = Number(host.address.split("/")[1]);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const address = ipv4Number(host.address);
    const gateway = ipv4Number(host.gateway);
    const hostBits = (~mask) >>> 0;
    const validUnicast = (candidate: number) => {
      // Reject unspecified, broadcast, loopback and multicast ranges because
      // this milestone models ordinary unicast Ethernet endpoints only.
      const first = candidate >>> 24;
      return candidate !== 0 && candidate !== 0xffffffff && first !== 0 && first !== 127 && first < 224;
    };
    if ((address & mask) !== (gateway & mask) || address === gateway ||
        !validUnicast(address) || !validUnicast(gateway) ||
        (prefix <= 30 && ([address, gateway].some((candidate) =>
          (candidate & hostBits) === 0 || (candidate & hostBits) === hostBits)))) {
      throw new Error("Host gateway must be a different unicast address in the local prefix");
    }
  }
  const hostMacs = value.hosts.map((host) => host.mac.toLowerCase());
  const hostIps = value.hosts.map((host) => ipv4Number(host.address));
  const routerMacs = new Set(GENERATED_PROFILE.routerInterfaces.map((item) => item.mac.toLowerCase()));
  const routerIps = new Set(GENERATED_PROFILE.routerInterfaces.map((item) => ipv4Number(item.address)));
  // Ethernet source identities cannot be zero or have the group bit set.
  const invalidMac = (address: string) => address === "00:00:00:00:00:00" ||
    (Number.parseInt(address.slice(0, 2), 16) & 1) !== 0;
  if (new Set(hostMacs).size !== hostMacs.length || new Set(hostIps).size !== hostIps.length ||
      hostMacs.some((address) => invalidMac(address) || routerMacs.has(address)) ||
      hostIps.some((address) => routerIps.has(address))) {
    throw new Error("Project contains invalid or duplicate endpoint identity");
  }
  if (links.some((link, index) => !link || link.id !== GENERATED_PROFILE.links[index]?.id ||
      link.host !== GENERATED_PROFILE.links[index]?.host ||
      link.routerPort !== GENERATED_PROFILE.links[index]?.router_port ||
      !knownHosts.has(link.host) || !knownPorts.has(link.routerPort) ||
      !Number.isSafeInteger(link.propagationDelayNs) || link.propagationDelayNs < 0)) {
    throw new Error("Project contains invalid link configuration");
  }
  if (typeof value.name !== "string" || !value.name.trim() ||
      value.name.length > GENERATED_PROFILE.limits.project_name_bytes ||
      typeof value.updatedAt !== "string" || Number.isNaN(Date.parse(value.updatedAt)) ||
      !isProjectHardware(value.hardware)) {
    throw new Error("Project contains invalid metadata or hardware state");
  }
  const interfaceNames = new Set<string>(GENERATED_PROFILE.routerInterfaces.map((item) => item.name));
  if (typeof running.systemName !== "string" || !running.systemName.trim() ||
      running.systemName.length > GENERATED_PROFILE.limits.system_name_bytes ||
      running.ports.length !== GENERATED_PROFILE.ports.count ||
      running.ports.some((port, index) => port.id !== GENERATED_PROFILE.ports.ids[index] ||
        !["up", "down"].includes(port.admin) || !Number.isInteger(port.mtu) ||
        port.mtu < GENERATED_PROFILE.ports.minimumMtu || port.mtu > GENERATED_PROFILE.ports.maximumMtu ||
        typeof port.description !== "string" ||
        port.description.length > GENERATED_PROFILE.limits.port_description_bytes ||
        /["\r\n]/.test(port.description)) ||
      running.interfaces.length !== interfaceNames.size ||
      running.interfaces.some((item) => !interfaceNames.has(item.name) || !["up", "down"].includes(item.admin)) ||
      running.staticRoutes.length > GENERATED_PROFILE.resources.static_route_capacity ||
      running.staticRoutes.some((route) => !route || !cidrPattern.test(route.prefix) ||
        !ipv4Pattern.test(route.nextHop) || !validOctets(route.prefix) || !validOctets(route.nextHop))) {
    throw new Error("Project contains invalid running configuration");
  }
  const prefixes = new Set<string>();
  for (const route of running.staticRoutes) {
    const [addressText, prefixText] = route.prefix.split("/");
    const prefix = Number(prefixText);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((ipv4Number(addressText) & mask) !== ipv4Number(addressText) || prefixes.has(route.prefix)) {
      throw new Error("Static route prefixes must be canonical and unique");
    }
    prefixes.add(route.prefix);
  }
  const requiredNodeIds = [...GENERATED_PROFILE.hosts.map((host) => host.id), GENERATED_PROFILE.uiDefaults.router_id];
  // Layout positions must remain finite so React Flow never receives NaN or
  // infinity from a hand-edited project file.
  const validPoint = (point: { x?: unknown; y?: unknown } | undefined) => point &&
    typeof point.x === "number" && Number.isFinite(point.x) &&
    typeof point.y === "number" && Number.isFinite(point.y);
  if (!layout.nodes || requiredNodeIds.some((id) => !validPoint(layout.nodes[id])) ||
      !Number.isFinite(layout.inspectorWidth) || !Number.isFinite(layout.terminalHeight)) {
    throw new Error("Project contains invalid UI layout");
  }
  return { ...value, hosts: value.hosts, links, runningConfig: running, layout } as LabProject;
}
